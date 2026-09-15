using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;
using Ensou.Dsh.Contracts;
using Ensou.Dsh.UpdateEngine;

namespace Ensou.Dsh.Launcher;

/// <summary>
/// Strict, compiled-development-only dependencies for the installed Launcher live-update
/// acceptance. Production construction never creates this context.
/// </summary>
internal sealed class PersonalDevelopmentLiveUpdateContext
{
    private const string ServerName = "updates.example.test";
    private const string ArtifactOrigin = "https://updates.example.test/";
    private const int MinimumLoopbackPort = 49152;
    private const long MaximumSafeInteger = 9_007_199_254_740_991L;
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

    private readonly byte[] _expectedTlsCertificateDerSha256;

    private PersonalDevelopmentLiveUpdateContext(
        PersonalDevelopmentLiveUpdateArguments arguments,
        PersonalDevelopmentE2ELayoutArguments layoutArguments,
        LiveUpdateConfiguration configuration)
    {
        Arguments = arguments;
        Layout = layoutArguments.Layout;
        LayoutArguments = layoutArguments.ToArguments().ToArray();
        RunId = configuration.RunId;
        ManifestUri = configuration.ManifestUri;
        LoopbackPort = configuration.LoopbackPort;
        RuntimePort = configuration.RuntimePort;
        TrustedPolicy = configuration.TrustedPolicy;
        ObserverRoot = configuration.ObserverRoot;
        InitialSequence = configuration.InitialSequence;
        TargetSequence = configuration.TargetSequence;
        FailFirstReceiverBeforeReady = configuration.FailFirstReceiverBeforeReady;
        ObserveFailureRecovery = configuration.ObserveFailureRecovery;
        _expectedTlsCertificateDerSha256 = Convert.FromHexString(
            configuration.ExpectedTlsCertificateDerSha256);
    }

    internal PersonalDevelopmentLiveUpdateArguments Arguments { get; }

    internal PersonalInstallationLayout Layout { get; }

    internal IReadOnlyList<string> LayoutArguments { get; }

    internal string RunId { get; }

    internal Uri ManifestUri { get; }

    internal int LoopbackPort { get; }

    internal int RuntimePort { get; }

    internal PersonalReleaseTrustPolicy TrustedPolicy { get; }

    internal string ObserverRoot { get; }

    internal long InitialSequence { get; }

    internal long TargetSequence { get; }

    internal bool FailFirstReceiverBeforeReady { get; }

    internal bool ObserveFailureRecovery { get; }

    internal string SingleInstanceMutexName =>
        $"Local\\Ensou.Dsh.Launcher.DevE2E.{RunId}.SingleInstance";

    internal string ActivationEventName =>
        $"Local\\Ensou.Dsh.Launcher.DevE2E.{RunId}.Activate";

    internal static PersonalDevelopmentLiveUpdateContext Create(
        PersonalDevelopmentLiveUpdateArguments arguments,
        PersonalDevelopmentE2ELayoutArguments layoutArguments)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        ArgumentNullException.ThrowIfNull(layoutArguments);
        var bytes = arguments.ReadPinnedConfigurationBytes();
        using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions
        {
            AllowTrailingCommas = false,
            CommentHandling = JsonCommentHandling.Disallow,
            MaxDepth = 32,
        });
        RequireNoDuplicateProperties(document.RootElement);
        var configuration = document.RootElement.Deserialize<LiveUpdateConfiguration>(JsonOptions)
            ?? throw new InvalidDataException(
                "Personal development live-update configuration is empty.");
        if (configuration.SchemaVersion != 1)
        {
            throw new InvalidDataException(
                "Personal development live-update configuration version is invalid.");
        }

        var layout = layoutArguments.Layout;
        RequireExactPath(configuration.ManagedRoot, layout.ManagedRoot, "managed root");
        RequireExactPath(configuration.HarnessHome, layout.HarnessHome, "Harness home");
        RequireExactPath(
            configuration.UpdateSecurityWitnessPath,
            layout.UpdateSecurityWitnessPath,
            "update-security witness");

        RequireLowerHex(configuration.RunId, 32, "run id");
        RequireLowerHex(
            configuration.ExpectedTlsCertificateDerSha256,
            64,
            "TLS certificate hash");
        if (configuration.LoopbackPort is < MinimumLoopbackPort or > ushort.MaxValue
            || configuration.RuntimePort is < MinimumLoopbackPort or > ushort.MaxValue
            || configuration.RuntimePort == configuration.LoopbackPort)
        {
            throw new InvalidDataException(
                "Personal development live-update ports must be distinct high loopback ports.");
        }
        if (configuration.InitialSequence is <= 0 or > MaximumSafeInteger
            || configuration.TargetSequence is <= 0 or > MaximumSafeInteger
            || configuration.TargetSequence <= configuration.InitialSequence)
        {
            throw new InvalidDataException(
                "Personal development live-update sequences must be positive, safe, and monotonic.");
        }

        configuration.TrustedPolicy.Validate();
        if (!string.Equals(
                configuration.TrustedPolicy.Product,
                PersonalReleaseSetContract.Product,
                StringComparison.Ordinal)
            || !string.Equals(
                configuration.TrustedPolicy.Environment,
                PersonalReleaseSetContract.ProductionEnvironment,
                StringComparison.Ordinal)
            || !string.Equals(
                configuration.TrustedPolicy.ArtifactOrigin.AbsoluteUri,
                ArtifactOrigin,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Personal development live-update trust policy scope is invalid.");
        }
        RequireManifestUri(configuration.ManifestUri, configuration.TrustedPolicy.Channel);

        var configurationPath = RequireCanonicalLocalPath(
            arguments.ConfigurationPath,
            "configuration file",
            directory: false);
        var isolationRoot = RequireCanonicalLocalPath(
            Path.GetDirectoryName(configurationPath)
                ?? throw new InvalidDataException(
                    "Personal development live-update configuration has no parent."),
            "isolation root",
            directory: true);
        var managedRoot = RequireStrictChild(
            isolationRoot, layout.ManagedRoot, "managed root", directory: true);
        var harnessHome = RequireStrictChild(
            isolationRoot, layout.HarnessHome, "Harness home", directory: true);
        var witnessPath = RequireStrictChild(
            isolationRoot,
            layout.UpdateSecurityWitnessPath,
            "update-security witness",
            directory: false);
        var observerRoot = RequireStrictChild(
            isolationRoot,
            configuration.ObserverRoot,
            "observer root",
            directory: true);
        RequireDisjoint(managedRoot, harnessHome, "managed root", "Harness home");
        RequireDisjoint(managedRoot, witnessPath, "managed root", "update-security witness");
        RequireDisjoint(harnessHome, witnessPath, "Harness home", "update-security witness");
        RequireDisjoint(observerRoot, managedRoot, "observer root", "managed root");
        RequireDisjoint(observerRoot, harnessHome, "observer root", "Harness home");
        RequireDisjoint(observerRoot, witnessPath, "observer root", "update-security witness");
        RequireDisjoint(observerRoot, configurationPath, "observer root", "configuration file");

        var liveLayout = PersonalInstallationLayout.CreateDefault();
        RequireDisjoint(isolationRoot, liveLayout.ManagedRoot, "isolation root", "live managed root");
        RequireDisjoint(isolationRoot, liveLayout.HarnessHome, "isolation root", "live Harness home");
        RequireDisjoint(
            isolationRoot,
            liveLayout.UpdateSecurityWitnessPath,
            "isolation root",
            "live update-security witness");

        configuration = configuration with
        {
            ManagedRoot = managedRoot,
            HarnessHome = harnessHome,
            UpdateSecurityWitnessPath = witnessPath,
            ObserverRoot = observerRoot,
        };
        var context = new PersonalDevelopmentLiveUpdateContext(
            arguments,
            layoutArguments,
            configuration);
        context.EnsureObserverRoot();
        return context;
    }

    internal LauncherSettings CreateSettings() => new()
    {
        Channel = TrustedPolicy.Channel,
        ManifestUrl = ManifestUri.AbsoluteUri,
        DevelopmentManifestPublicKeyPath = Path.Combine(
            Layout.StateRoot,
            "unused-development-release-public-key.pem"),
        RuntimeDirectory = Path.Combine(Layout.RuntimeVersionsRoot, "uninstalled"),
        RuntimeRootDirectory = Layout.RuntimeVersionsRoot,
        DshDataDirectory = Layout.HarnessHome,
        LogDirectory = Path.Combine(Layout.StateRoot, "live-update-logs"),
        PackageDirectory = Layout.PackageRoot,
        Port = RuntimePort,
        OpenWebUiAfterStart = false,
    };

    internal async Task<PersonalUpdateCheckOutcomeV2> CheckAsync(
        LauncherSettings settings,
        CancellationToken cancellationToken)
    {
        using var client = CreateHttpClient(TimeSpan.FromSeconds(20));
        return await PersonalUpdateCoordinatorV2.CheckAsync(
            settings,
            Layout,
            ManifestUri,
            TrustedPolicy,
            client,
            DateTimeOffset.UtcNow,
            cancellationToken).ConfigureAwait(false);
    }

    internal async Task<PersonalAcquiredReleaseSet> DownloadAsync(
        PersonalUpdateCheckOutcomeV2 outcome,
        IProgress<double>? progress,
        CancellationToken cancellationToken)
    {
        using var client = CreateHttpClient(TimeSpan.FromHours(2));
        return await PersonalUpdateCoordinatorV2.DownloadAsync(
            Layout,
            client,
            outcome,
            progress,
            cancellationToken).ConfigureAwait(false);
    }

    internal Task<PersonalReleaseSetInstallationResult> StageAsync(
        LauncherSettings settings,
        PersonalUpdateCheckOutcomeV2 outcome,
        PersonalAcquiredReleaseSet download,
        IProgress<double>? progress,
        CancellationToken cancellationToken) =>
        PersonalUpdateCoordinatorV2.StageAsync(
            settings,
            Layout,
            outcome,
            download,
            progress,
            cancellationToken);

    internal PersonalInstalledReleaseSetPointer RequireCurrentSequence(long expectedSequence)
    {
        var pointer = new PersonalReleaseSetPointerStore(Layout).ReadRequired();
        if (pointer.Current.HealthState != PersonalReleaseHealthStates.Healthy
            || pointer.Current.Sequence != expectedSequence)
        {
            throw new InvalidDataException(
                "Personal development live-update release sequence is not admitted and healthy.");
        }
        return pointer;
    }

    internal PersonalInstalledReleaseSetPointer RequireCurrentExpectedSequence()
    {
        var pointer = new PersonalReleaseSetPointerStore(Layout).ReadRequired();
        if (pointer.Current.HealthState != PersonalReleaseHealthStates.Healthy
            || pointer.Current.Sequence != InitialSequence
                && pointer.Current.Sequence != TargetSequence)
        {
            throw new InvalidDataException(
                "Personal development live-update release sequence is not an expected healthy release.");
        }
        return pointer;
    }

    internal bool RequireRestoredBaselineObservation(
        PersonalInstalledReleaseSetPointer pointer)
    {
        ArgumentNullException.ThrowIfNull(pointer);
        if (!ObserveFailureRecovery)
        {
            return false;
        }
        if (pointer.Current.Sequence != InitialSequence
            || pointer.Current.HealthState != PersonalReleaseHealthStates.Healthy
            || pointer.Previous is not null)
        {
            throw new InvalidDataException(
                "Personal development failure recovery did not restore the expected healthy baseline.");
        }

        var requiredPhases = new[]
        {
            "baseline-runtime-owned",
            "stage-begin",
            "stage-authenticated-complete",
        };
        var evidencePresent = requiredPhases
            .Select(phase => File.Exists(ObserverPath(phase)))
            .ToArray();
        if (!evidencePresent.Any(present => present))
        {
            return false;
        }
        if (evidencePresent.Any(present => !present))
        {
            throw new InvalidDataException(
                "Personal development failure recovery evidence is incomplete.");
        }

        var baseline = ReadObserverEvent(requiredPhases[0]);
        var stageBegin = ReadObserverEvent(requiredPhases[1]);
        var stageComplete = ReadObserverEvent(requiredPhases[2]);
        var now = DateTimeOffset.UtcNow;
        if (baseline.Pid == stageBegin.Pid
            || stageBegin.Pid != stageComplete.Pid
            || baseline.TimeUtc > stageBegin.TimeUtc
            || stageBegin.TimeUtc > stageComplete.TimeUtc
            || stageComplete.TimeUtc > now)
        {
            throw new InvalidDataException(
                "Personal development failure recovery evidence is not a valid staged transition.");
        }
        return true;
    }

    internal void RecordPhase(string phase, int? processId = null)
    {
        RequirePhase(phase);
        EnsureObserverRoot();
        var path = ObserverPath(phase);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(new ObserverEvent
        {
            Pid = processId ?? Environment.ProcessId,
            TimeUtc = DateTimeOffset.UtcNow,
            RunId = RunId,
            Phase = phase,
        }, JsonOptions);
        using var stream = new FileStream(
            path,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.Read,
            bufferSize: 4096,
            FileOptions.WriteThrough);
        stream.Write(bytes);
        stream.Flush(flushToDisk: true);
    }

    internal bool TryCreateFirstReceiverFailureMarker()
    {
        if (!FailFirstReceiverBeforeReady)
        {
            return false;
        }
        EnsureObserverRoot();
        var path = Path.Combine(ObserverRoot, "first-receiver-failure.claim");
        try
        {
            using var stream = new FileStream(
                path,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.Read,
                bufferSize: 1,
                FileOptions.WriteThrough);
            stream.WriteByte(0x31);
            stream.Flush(flushToDisk: true);
            return true;
        }
        catch (IOException) when (File.Exists(path))
        {
            return false;
        }
    }

    internal bool FirstReceiverFailureWasClaimed =>
        File.Exists(Path.Combine(ObserverRoot, "first-receiver-failure.claim"));

    private string ObserverPath(string phase) =>
        Path.Combine(ObserverRoot, $"{phase}.json");

    private ObserverEvent ReadObserverEvent(string phase)
    {
        RequirePhase(phase);
        EnsureObserverRoot();
        var path = ObserverPath(phase);
        PersonalPathGuard.RequireSingleLinkFile(path);
        using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 4096,
            FileOptions.SequentialScan);
        if (stream.Length is <= 0 or > 4096)
        {
            throw new InvalidDataException(
                "Personal development live-update observer receipt has an invalid size.");
        }
        using var document = JsonDocument.Parse(stream, new JsonDocumentOptions
        {
            AllowTrailingCommas = false,
            CommentHandling = JsonCommentHandling.Disallow,
            MaxDepth = 8,
        });
        RequireNoDuplicateProperties(document.RootElement);
        var observed = document.RootElement.Deserialize<ObserverEvent>(JsonOptions)
            ?? throw new InvalidDataException(
                "Personal development live-update observer receipt is empty.");
        if (observed.Pid <= 0
            || observed.TimeUtc.Offset != TimeSpan.Zero
            || observed.TimeUtc <= DateTimeOffset.UnixEpoch
            || !string.Equals(observed.RunId, RunId, StringComparison.Ordinal)
            || !string.Equals(observed.Phase, phase, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Personal development live-update observer receipt does not match this run.");
        }
        return observed;
    }

    private HttpClient CreateHttpClient(TimeSpan timeout)
    {
        var expectedHash = _expectedTlsCertificateDerSha256.ToArray();
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
            if (!string.Equals(
                    context.DnsEndPoint.Host,
                    ServerName,
                    StringComparison.OrdinalIgnoreCase)
                || context.DnsEndPoint.Port != 443)
            {
                throw new HttpRequestException(
                    "Personal development live-update destination is not admitted.");
            }
            var socket = new Socket(
                AddressFamily.InterNetwork,
                SocketType.Stream,
                ProtocolType.Tcp)
            {
                NoDelay = true,
            };
            try
            {
                await socket.ConnectAsync(
                    IPAddress.Loopback,
                    LoopbackPort,
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
        return new HttpClient(handler, disposeHandler: true)
        {
            Timeout = timeout,
            DefaultRequestVersion = HttpVersion.Version11,
            DefaultVersionPolicy = HttpVersionPolicy.RequestVersionExact,
        };
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
                SHA256.HashData(received.RawData),
                expectedHash)
            && now >= received.NotBefore.ToUniversalTime()
            && now <= received.NotAfter.ToUniversalTime()
            && received.MatchesHostname(
                ServerName,
                allowWildcards: false,
                allowCommonName: false);
    }

    private void EnsureObserverRoot()
    {
        Directory.CreateDirectory(ObserverRoot);
        RejectReparseChain(ObserverRoot);
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
            || !string.Equals(
                uri.AbsolutePath,
                $"/v2/channels/{channel}/release-set.v2.json",
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Personal development live-update manifest URI is invalid.");
        }
    }

    private static string RequireCanonicalLocalPath(
        string path,
        string label,
        bool directory)
    {
        if (string.IsNullOrWhiteSpace(path)
            || path.StartsWith("\\\\", StringComparison.Ordinal)
            || path.StartsWith("//", StringComparison.Ordinal)
            || !Path.IsPathFullyQualified(path))
        {
            throw new InvalidDataException(
                $"Personal development {label} must be one absolute local path.");
        }
        var normalized = directory
            ? Path.TrimEndingDirectorySeparator(Path.GetFullPath(path))
            : Path.GetFullPath(path);
        if (!string.Equals(normalized, path, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                $"Personal development {label} must be canonical.");
        }
        RejectReparseChain(directory
            ? normalized
            : Path.GetDirectoryName(normalized)
                ?? throw new InvalidDataException(
                    $"Personal development {label} has no parent directory."));
        if (!directory
            && File.Exists(normalized)
            && (File.GetAttributes(normalized) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException(
                $"Personal development {label} is a filesystem link.");
        }
        return normalized;
    }

    private static string RequireStrictChild(
        string root,
        string path,
        string label,
        bool directory)
    {
        var admitted = RequireCanonicalLocalPath(path, label, directory);
        if (!admitted.StartsWith(
                Path.TrimEndingDirectorySeparator(root) + Path.DirectorySeparatorChar,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                $"Personal development {label} is outside the isolation root.");
        }
        return admitted;
    }

    private static void RequireExactPath(string configured, string admitted, string label)
    {
        var normalized = Path.TrimEndingDirectorySeparator(Path.GetFullPath(configured));
        var expected = Path.TrimEndingDirectorySeparator(Path.GetFullPath(admitted));
        if (!string.Equals(normalized, expected, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                $"Personal development live-update {label} does not match the admitted layout.");
        }
    }

    private static void RequireDisjoint(
        string left,
        string right,
        string leftName,
        string rightName)
    {
        var normalizedLeft = Path.TrimEndingDirectorySeparator(Path.GetFullPath(left));
        var normalizedRight = Path.TrimEndingDirectorySeparator(Path.GetFullPath(right));
        var leftPrefix = normalizedLeft + Path.DirectorySeparatorChar;
        var rightPrefix = normalizedRight + Path.DirectorySeparatorChar;
        if (string.Equals(normalizedLeft, normalizedRight, StringComparison.OrdinalIgnoreCase)
            || normalizedLeft.StartsWith(rightPrefix, StringComparison.OrdinalIgnoreCase)
            || normalizedRight.StartsWith(leftPrefix, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                $"Personal development {leftName} and {rightName} overlap.");
        }
    }

    private static void RejectReparseChain(string path)
    {
        for (var current = new DirectoryInfo(path); current is not null; current = current.Parent)
        {
            if (current.Exists && (current.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException(
                    "Personal development live-update path crosses a filesystem link.");
            }
        }
    }

    private static void RequireLowerHex(string value, int length, string label)
    {
        if (value.Length != length
            || value.Any(character => character is not (>= '0' and <= '9')
                and not (>= 'a' and <= 'f')))
        {
            throw new InvalidDataException(
                $"Personal development live-update {label} is invalid.");
        }
    }

    private static void RequirePhase(string phase)
    {
        if (string.IsNullOrEmpty(phase)
            || phase.Length > 80
            || phase[0] is < 'a' or > 'z'
            || phase.Any(character => character is not (>= 'a' and <= 'z')
                and not (>= '0' and <= '9') and not '-'))
        {
            throw new InvalidDataException(
                "Personal development live-update observer phase is invalid.");
        }
    }

    private static void RequireNoDuplicateProperties(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name))
                {
                    throw new InvalidDataException(
                        "Personal development live-update configuration has duplicate properties.");
                }
                RequireNoDuplicateProperties(property.Value);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
            {
                RequireNoDuplicateProperties(item);
            }
        }
    }

    [JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
    private sealed record LiveUpdateConfiguration
    {
        public required int SchemaVersion { get; init; }
        public required string RunId { get; init; }
        public required string ManagedRoot { get; init; }
        public required string HarnessHome { get; init; }
        public required string UpdateSecurityWitnessPath { get; init; }
        public required Uri ManifestUri { get; init; }
        public required int LoopbackPort { get; init; }
        public required string ExpectedTlsCertificateDerSha256 { get; init; }
        public required PersonalReleaseTrustPolicy TrustedPolicy { get; init; }
        public required string ObserverRoot { get; init; }
        public required int RuntimePort { get; init; }
        public required long InitialSequence { get; init; }
        public required long TargetSequence { get; init; }
        public required bool FailFirstReceiverBeforeReady { get; init; }
        public bool ObserveFailureRecovery { get; init; }
    }

    private sealed record ObserverEvent
    {
        public required int Pid { get; init; }
        public required DateTimeOffset TimeUtc { get; init; }
        public required string RunId { get; init; }
        public required string Phase { get; init; }
    }
}
