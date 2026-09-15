using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using Ensou.Dsh.Enterprise.Client;
using Ensou.Dsh.Enterprise.Installation;

namespace Ensou.Dsh.Enterprise.DevelopmentE2ETests;

internal static partial class Program
{
    private const string EnterpriseManagedRuntimeProfile = "enterprise-managed";
    private const string EnterpriseDirectLocalRuntimeProfile = "enterprise-direct-local";
    private const string DevelopmentGatewayOriginEnvironmentName =
        "ENSOU_DSH_E2E_GATEWAY_ORIGIN";

    // Only the transport is redirected to a pinned loopback TLS fixture. The
    // installed App owns refresh, update admission, download, health and restart.
    private static async Task<object> RunInstalledLauncherUpdateAsync(
        RunnerOptions options,
        EnterpriseReleaseSetManifest manifest,
        EnterpriseCompiledReleaseTrust trust,
        DevelopmentHttpsArtifactServer server)
    {
        var target = options.GetTargetLauncherTuple()
            ?? throw new InvalidDataException("Installed Launcher update requires a distinct target.");
        var layout = EnterpriseInstallationLayout.CreateDevelopmentE2E(
            options.LocalAppDataRoot!, options.UserProfileRoot!);
        var paths = CreatePaths(options);
        var store = new EnterpriseReleaseSetPointerStore(layout, trust);
        var before = store.ReadRequired();
        var launcherArtifact = manifest.Artifacts.Single(x =>
            x.Component == EnterpriseReleaseSetContract.LauncherComponent);
        if (before.Current.Sequence != 2 || manifest.Sequence != 3
            || before.Current.HealthState != EnterpriseReleaseHealthStates.Healthy
            || target.LauncherReleaseId != launcherArtifact.ReleaseId
            || before.Current.Launcher.ReleaseId == launcherArtifact.ReleaseId
            || before.Current.Launcher.ArchiveSha256 == launcherArtifact.Sha256
            || before.Current.Launcher.CompleteTreeSha256 == launcherArtifact.CompleteTreeSha256)
        {
            throw new InvalidDataException("Installed Launcher lane requires healthy sequence2 and distinct sequence3.");
        }
        var credentials = new EnterpriseBindingCredentialStore(paths,
            new EnterpriseProtectedArtifactStore(paths,
                $"com.ensou.dsh.enterprise.development-e2e.{options.IsolationIdentifier}"));
        var bindingBefore = await credentials.ReadCommittedAsync().ConfigureAwait(false)
            ?? throw new InvalidDataException("Installed Launcher lane requires existing enrollment.");
        var dataBefore = EnsureLocalDataSentinels(paths, options.IsolationIdentifier);
        var receiptPath = Path.Combine(layout.LocalAppDataRoot, "installed-launcher-restart.json");
        if (File.Exists(receiptPath) || Directory.Exists(receiptPath))
            throw new IOException("Installed Launcher restart receipt already exists.");

        WriteSignal(options.ReadySignalPath!, options.SignalToken!);
        await WaitForSignalAsync(options.ContinueSignalPath!, options.SignalToken!,
            TimeSpan.FromSeconds(90)).ConfigureAwait(false);
        EnterpriseStableBootstrapperVerifier.RequireTrusted(layout);
        using var trustedEntry = EnterpriseAuthenticodeVerifier.OpenTrustedExecutableForLaunch(
            layout.BootstrapperPath, layout);
        var start = new ProcessStartInfo(layout.BootstrapperPath)
        {
            WorkingDirectory = layout.ManagedRoot,
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
        };
        start.ArgumentList.Add("--background-startup");
        ApplyDevelopmentUpdateTrustEnvironment(start, layout, trust, options.IsolationIdentifier);
        ApplyDevelopmentControlPlaneTrustEnvironment(start, options);
        foreach (var entry in new Dictionary<string, string?>
        {
            ["ENSOU_DSH_E2E_UPDATE_TLS_CERT_SHA256"] = server.LeafCertificateSha256,
            ["ENSOU_DSH_E2E_UPDATE_LOOPBACK_PORT"] = server.LoopbackPort.ToString(CultureInfo.InvariantCulture),
            ["ENSOU_DSH_E2E_RESTART_RECEIPT_PATH"] = receiptPath,
        })
        {
            if (string.IsNullOrWhiteSpace(entry.Value))
                throw new InvalidDataException("Installed Launcher lane has incomplete public test trust.");
            start.Environment[entry.Key] = entry.Value;
        }
        using var contained = trustedEntry.StartContained(start,
            _ => EnterpriseLegacySqliteUpgradeGuard.RequireJsonlOnlyHarnessHomeAndNoWriter(layout));
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(8));
        try
        {
            while (!File.Exists(receiptPath))
            {
                if (contained.Process.HasExited && contained.Process.ExitCode != 0)
                    throw new InvalidDataException("Installed stable entry exited unsuccessfully.");
                await Task.Delay(100, deadline.Token).ConfigureAwait(false);
            }
            EnterprisePathGuard.ValidateExistingPathWithin(receiptPath, layout.LocalAppDataRoot, false);
            if (new FileInfo(receiptPath).Length is <= 0 or > 8192)
                throw new InvalidDataException("Installed restart receipt is not bounded.");
            using var receipt = JsonDocument.Parse(await File.ReadAllBytesAsync(receiptPath, deadline.Token)
                .ConfigureAwait(false));
            var r = receipt.RootElement;
            var receiverPid = r.GetProperty("receiverPid").GetInt32();
            var parentPid = r.GetProperty("parentPid").GetInt32();
            if (r.GetProperty("schemaVersion").GetInt32() != 1
                || r.GetProperty("event").GetString() != "enterprise-development-restart"
                || r.GetProperty("scope").GetString() != "Enterprise"
                || !r.GetProperty("backgroundStartup").GetBoolean()
                || !r.GetProperty("parentExited").GetBoolean()
                || r.GetProperty("outcome").GetString() != "parent-exited"
                || r.GetProperty("sequence").GetInt64() != 3
                || r.GetProperty("launcherReleaseId").GetString() != launcherArtifact.ReleaseId
                || receiverPid <= 0 || parentPid <= 0 || receiverPid == parentPid)
                throw new InvalidDataException("Installed Launcher receipt did not prove the expected takeover.");
            using var receiver = Process.GetProcessById(receiverPid);
            var after = store.ReadRequired();
            using var receiverImage = EnterpriseAuthenticodeVerifier.OpenTrustedExecutableForLaunch(
                Path.Combine(after.Current.Launcher.Directory, EnterpriseInstallationLayout.LauncherExecutableName), layout);
            receiverImage.RequireProcessImage(receiver);
            if (receiver.HasExited || HasVisibleOwnedWindow(receiverPid))
                throw new InvalidDataException("Installed receiver exited or displayed a window during background takeover.");
            try
            {
                using var predecessor = Process.GetProcessById(parentPid);
                if (!predecessor.HasExited)
                    throw new InvalidDataException("Installed restart predecessor is still running.");
            }
            catch (ArgumentException) { }
            using (var singleton = Mutex.OpenExisting(EnterpriseProductIdentity.DevelopmentE2ESingleInstanceMutexName))
            {
                var acquired = false;
                try { acquired = singleton.WaitOne(0); }
                catch (AbandonedMutexException) { acquired = true; }
                if (acquired)
                {
                    singleton.ReleaseMutex();
                    throw new InvalidDataException("Installed receiver has not retained the singleton.");
                }
            }
            var bindingAfter = await credentials.ReadCommittedAsync().ConfigureAwait(false)
                ?? throw new InvalidDataException("Installed update lost enrollment.");
            var requests = server.SuccessfulRequests;
            var authorizations = server.AuthorizedRequests;
            if (!authorizations.Any(x => x.Uri == SignedLabManifestUri)
                || !authorizations.Any(x => x.Uri == launcherArtifact.Uri)
                || authorizations.Any(x => x.BindingId.ToString("D") != bindingBefore.Receipt.BindingId)
                || authorizations.Select(x => x.RequestId).Distinct().Count() != authorizations.Count)
                throw new InvalidDataException("Installed downloads lack distinct real control authorization decisions.");
            var launcherFetches = requests.Count(x => x.Uri == launcherArtifact.Uri);
            var runtimeUri = manifest.Artifacts.Single(x => x.Component == EnterpriseReleaseSetContract.RuntimeComponent).Uri;
            var policyUri = manifest.Artifacts.Single(x => x.Component == EnterpriseReleaseSetContract.PluginPolicyComponent).Uri;
            var runtimeFetches = requests.Count(x => x.Uri == runtimeUri);
            var policyFetches = requests.Count(x => x.Uri == policyUri);
            var dataAfter = EnsureLocalDataSentinels(paths, options.IsolationIdentifier);
            if (after.Current.Sequence != 3 || after.Current.HealthState != EnterpriseReleaseHealthStates.Healthy
                || after.Current.ReleaseSetId != manifest.ReleaseSetId
                || after.Current.Launcher.ReleaseId != launcherArtifact.ReleaseId
                || after.Current.Launcher.ArchiveSha256 != launcherArtifact.Sha256
                || after.Current.Launcher.CompleteTreeSha256 != launcherArtifact.CompleteTreeSha256
                || JsonSerializer.Serialize(before.Current.Runtime) != JsonSerializer.Serialize(after.Current.Runtime)
                || JsonSerializer.Serialize(before.Current.PluginPolicy) != JsonSerializer.Serialize(after.Current.PluginPolicy)
                || bindingBefore.Receipt.BindingId != bindingAfter.Receipt.BindingId
                || dataBefore != dataAfter
                || launcherFetches < 1 || runtimeFetches != 0 || policyFetches != 0)
                throw new InvalidDataException("Installed update changed identity, retained components or local data unexpectedly.");

            // The fixture owns this entire process tree. Stop it before later
            // lifecycle chat/revocation checks open the same isolated workspace.
            contained.TerminateRequired();
            return new
            {
                sequence = 3, healthState = after.Current.HealthState,
                bindingId = bindingAfter.Receipt.BindingId,
                artifactTransport = "LOCAL_PINNED_HTTPS", artifactTransportPubliclyReachable = false,
                launcherDownloaded = true, distinctLauncherActivated = true,
                launcherOnlyComponentsUnchanged = true, runtimeDownloaded = false,
                targetLauncherHttpsFetchCount = launcherFetches,
                unchangedRuntimeHttpsFetchCount = runtimeFetches,
                unchangedPluginPolicyHttpsFetchCount = policyFetches,
                actualInstalledLauncherRestart = true, parentPid, receiverPid,
                workspaceSentinelSha256 = dataAfter.WorkspaceSha256,
                historySentinelSha256 = dataAfter.HistorySha256,
                backgroundTakeover = true, ownedProcessTreeTerminated = true,
                restartReceiptSha256 = HashFile(receiptPath),
                feedAuthorization = new
                {
                    source = "REAL_CONTROL_API_DPOP_AND_DATABASE",
                    accepted = authorizations.Select(x => new
                    {
                        uri = x.Uri.AbsoluteUri, requestId = x.RequestId, bindingId = x.BindingId,
                        policyId = x.PolicyId, policyVersion = x.PolicyVersion,
                    }).ToArray(),
                },
            };
        }
        catch (OperationCanceledException exception) when (deadline.IsCancellationRequested)
        {
            throw new TimeoutException(
                "Installed Launcher restart receipt was not published within the eight-minute observation window. "
                + "Inspect the retained development-health-diagnostics restart stages; no takeover is accepted.",
                exception);
        }
        finally
        {
            // Dispose retains the exact Job handle and kills descendants even
            // when the stable entry has already exited; no PID-name sweep.
            contained.Dispose();
        }
    }

    private static void AssertInstalledLauncherControlPlaneTrustEnvironmentContract(
        RunnerOptions fixtureOptions)
    {
        ArgumentNullException.ThrowIfNull(fixtureOptions);
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicParameters = signer.ExportParameters(false);
        var control = new Uri("https://control.example/");
        var gateway = new Uri("https://gateway.example/");
        var common = fixtureOptions with
        {
            ControlOrigin = control,
            LeaseKeyId = "installed-launcher-contract-key",
            LeaseKeyX = Base64Url(publicParameters.Q.X!),
            LeaseKeyY = Base64Url(publicParameters.Q.Y!),
            ServerCertificateSha256 = new string('a', 64),
        };

        var direct = new ProcessStartInfo();
        direct.Environment[DevelopmentGatewayOriginEnvironmentName] =
            "https://inherited.example/";
        SeedInheritedDevelopmentSecrets(direct);
        ApplyDevelopmentControlPlaneTrustEnvironment(
            direct,
            common with
            {
                RuntimeProfile = EnterpriseDirectLocalRuntimeProfile,
                GatewayOrigin = null,
            });
        if (direct.Environment.ContainsKey(DevelopmentGatewayOriginEnvironmentName)
            || HasInheritedDevelopmentSecret(direct)
            || !HasExactDevelopmentControlPlaneTrust(direct, common, control))
        {
            throw new InvalidDataException(
                "Direct-local Launcher environment did not preserve exact public trust boundaries.");
        }

        var managed = new ProcessStartInfo();
        SeedInheritedDevelopmentSecrets(managed);
        ApplyDevelopmentControlPlaneTrustEnvironment(
            managed,
            common with
            {
                RuntimeProfile = EnterpriseManagedRuntimeProfile,
                GatewayOrigin = gateway,
            });
        if (!managed.Environment.TryGetValue(
                DevelopmentGatewayOriginEnvironmentName,
                out var managedGateway)
            || !string.Equals(
                managedGateway,
                gateway.AbsoluteUri,
                StringComparison.Ordinal)
            || HasInheritedDevelopmentSecret(managed)
            || !HasExactDevelopmentControlPlaneTrust(managed, common, control))
        {
            throw new InvalidDataException(
                "Managed Launcher environment did not preserve exact public trust boundaries.");
        }

        var cleared = new ProcessStartInfo();
        SeedInheritedDevelopmentSecrets(cleared);
        foreach (var name in DevelopmentControlPlaneEnvironmentNames())
        {
            cleared.Environment[name] = "must-not-propagate";
        }
        ClearDevelopmentControlPlaneTrustEnvironment(cleared);
        if (DevelopmentControlPlaneEnvironmentNames().Any(cleared.Environment.ContainsKey)
            || HasInheritedDevelopmentSecret(cleared))
        {
            throw new InvalidDataException(
                "Legacy initial managed health did not explicitly remove unavailable control-plane trust.");
        }

        AssertThrows<InvalidDataException>(() =>
            ApplyDevelopmentControlPlaneTrustEnvironment(
                new ProcessStartInfo(),
                common with { RuntimeProfile = null, GatewayOrigin = gateway }));
        AssertThrows<InvalidDataException>(() =>
            ApplyDevelopmentControlPlaneTrustEnvironment(
                new ProcessStartInfo(),
                common with { RuntimeProfile = "enterprise-unknown", GatewayOrigin = gateway }));
        AssertThrows<InvalidDataException>(() =>
            ApplyDevelopmentControlPlaneTrustEnvironment(
                new ProcessStartInfo(),
                common with
                {
                    RuntimeProfile = EnterpriseManagedRuntimeProfile,
                    GatewayOrigin = null,
                }));
        AssertThrows<InvalidDataException>(() =>
            ApplyDevelopmentControlPlaneTrustEnvironment(
                new ProcessStartInfo(),
                common with
                {
                    RuntimeProfile = EnterpriseDirectLocalRuntimeProfile,
                    GatewayOrigin = gateway,
                }));
        AssertThrows<InvalidDataException>(() =>
            ApplyDevelopmentControlPlaneTrustEnvironment(
                new ProcessStartInfo(),
                common with
                {
                    RuntimeProfile = EnterpriseDirectLocalRuntimeProfile,
                    GatewayOrigin = null,
                    ControlOrigin = null,
                }));
        AssertThrows<InvalidDataException>(() =>
            ApplyDevelopmentControlPlaneTrustEnvironment(
                new ProcessStartInfo(),
                common with
                {
                    RuntimeProfile = EnterpriseDirectLocalRuntimeProfile,
                    GatewayOrigin = null,
                    LeaseKeyId = null,
                }));
        AssertThrows<InvalidDataException>(() =>
            ApplyDevelopmentControlPlaneTrustEnvironment(
                new ProcessStartInfo(),
                common with
                {
                    RuntimeProfile = EnterpriseDirectLocalRuntimeProfile,
                    GatewayOrigin = null,
                    ServerCertificateSha256 = "not-a-sha256",
                }));
    }

    private static void ApplyDevelopmentControlPlaneTrustEnvironment(
        ProcessStartInfo start,
        RunnerOptions options)
    {
        ArgumentNullException.ThrowIfNull(start);
        ArgumentNullException.ThrowIfNull(options);
        var controlOrigin = options.ControlOrigin
            ?? throw new InvalidDataException(
                "Development Launcher requires one control-plane origin.");
        var leaseKey = new EnterpriseAuthorizationLeasePublicKey(
            options.LeaseKeyId
                ?? throw new InvalidDataException(
                    "Development Launcher requires one authorization lease key ID."),
            options.LeaseKeyX
                ?? throw new InvalidDataException(
                    "Development Launcher requires one authorization lease key X coordinate."),
            options.LeaseKeyY
                ?? throw new InvalidDataException(
                    "Development Launcher requires one authorization lease key Y coordinate."));
        var trustPolicy = options.RuntimeProfile switch
        {
            EnterpriseManagedRuntimeProfile => new EnterpriseAuthorizationLeaseTrustPolicy(
                controlOrigin,
                options.GatewayOrigin
                    ?? throw new InvalidDataException(
                        "Managed Development Launcher requires one gateway origin."),
                controlOrigin,
                [leaseKey]),
            EnterpriseDirectLocalRuntimeProfile when options.GatewayOrigin is null =>
                EnterpriseAuthorizationLeaseTrustPolicy.CreateEnterpriseDirectLocal(
                    controlOrigin,
                    controlOrigin,
                    [leaseKey]),
            EnterpriseDirectLocalRuntimeProfile => throw new InvalidDataException(
                "Direct-local Development Launcher must not receive a gateway origin."),
            _ => throw new InvalidDataException(
                "Development Launcher requires one exact supported runtime profile."),
        };
        var certificateSha256 = options.ServerCertificateSha256;
        if (certificateSha256 is null
            || certificateSha256.Length != 64
            || certificateSha256.Any(character => !Uri.IsHexDigit(character)))
        {
            throw new InvalidDataException(
                "Development Launcher requires one exact TLS certificate SHA-256.");
        }
        var publicTrust = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["ENSOU_DSH_E2E_CONTROL_ORIGIN"] = trustPolicy.IssuerOrigin.AbsoluteUri,
            ["ENSOU_DSH_E2E_AUTH_ORIGIN"] = trustPolicy.IssuerOrigin.AbsoluteUri,
            ["ENSOU_DSH_E2E_ARTIFACT_ORIGIN"] = trustPolicy.ArtifactOrigin.AbsoluteUri,
            ["ENSOU_DSH_E2E_LEASE_KEY_ID"] = leaseKey.KeyId,
            ["ENSOU_DSH_E2E_LEASE_KEY_X"] = leaseKey.X,
            ["ENSOU_DSH_E2E_LEASE_KEY_Y"] = leaseKey.Y,
            ["ENSOU_DSH_E2E_TLS_CERT_SHA256"] = certificateSha256.ToLowerInvariant(),
        };

        ClearDevelopmentControlPlaneTrustEnvironment(start);
        if (!trustPolicy.IsEnterpriseDirectLocal)
        {
            start.Environment[DevelopmentGatewayOriginEnvironmentName] =
                trustPolicy.GatewayOrigin.AbsoluteUri;
        }
        foreach (var entry in publicTrust)
        {
            start.Environment[entry.Key] = entry.Value;
        }
    }

    private static void ClearDevelopmentControlPlaneTrustEnvironment(
        ProcessStartInfo start)
    {
        ArgumentNullException.ThrowIfNull(start);
        foreach (var name in DevelopmentControlPlaneEnvironmentNames().Concat(new[]
        {
            "ENSOU_DSH_E2E_ACTIVATION_CODE",
            "ENSOU_DSH_E2E_FEED_INTERNAL_SECRET",
            "DevelopmentFeedAuthorization__InternalSecret",
            "DevelopmentFeedAuthorization:InternalSecret",
        }))
        {
            start.Environment.Remove(name);
        }
    }

    private static IEnumerable<string> DevelopmentControlPlaneEnvironmentNames()
    {
        yield return "ENSOU_DSH_E2E_CONTROL_ORIGIN";
        yield return "ENSOU_DSH_E2E_AUTH_ORIGIN";
        yield return "ENSOU_DSH_E2E_ARTIFACT_ORIGIN";
        yield return "ENSOU_DSH_E2E_LEASE_KEY_ID";
        yield return "ENSOU_DSH_E2E_LEASE_KEY_X";
        yield return "ENSOU_DSH_E2E_LEASE_KEY_Y";
        yield return "ENSOU_DSH_E2E_TLS_CERT_SHA256";
        yield return DevelopmentGatewayOriginEnvironmentName;
    }

    private static void SeedInheritedDevelopmentSecrets(ProcessStartInfo start)
    {
        start.Environment["ENSOU_DSH_E2E_ACTIVATION_CODE"] = "must-not-propagate";
        start.Environment["ENSOU_DSH_E2E_FEED_INTERNAL_SECRET"] = "must-not-propagate";
        start.Environment["DevelopmentFeedAuthorization__InternalSecret"] = "must-not-propagate";
        start.Environment["DevelopmentFeedAuthorization:InternalSecret"] = "must-not-propagate";
    }

    private static bool HasInheritedDevelopmentSecret(ProcessStartInfo start) =>
        start.Environment.ContainsKey("ENSOU_DSH_E2E_ACTIVATION_CODE")
        || start.Environment.ContainsKey("ENSOU_DSH_E2E_FEED_INTERNAL_SECRET")
        || start.Environment.ContainsKey("DevelopmentFeedAuthorization__InternalSecret")
        || start.Environment.ContainsKey("DevelopmentFeedAuthorization:InternalSecret");

    private static bool HasExactDevelopmentControlPlaneTrust(
        ProcessStartInfo start,
        RunnerOptions options,
        Uri controlOrigin) =>
        start.Environment.TryGetValue("ENSOU_DSH_E2E_CONTROL_ORIGIN", out var control)
        && string.Equals(control, controlOrigin.AbsoluteUri, StringComparison.Ordinal)
        && start.Environment.TryGetValue("ENSOU_DSH_E2E_AUTH_ORIGIN", out var auth)
        && string.Equals(auth, controlOrigin.AbsoluteUri, StringComparison.Ordinal)
        && start.Environment.TryGetValue("ENSOU_DSH_E2E_ARTIFACT_ORIGIN", out var artifact)
        && string.Equals(artifact, controlOrigin.AbsoluteUri, StringComparison.Ordinal)
        && start.Environment.TryGetValue("ENSOU_DSH_E2E_LEASE_KEY_ID", out var keyId)
        && string.Equals(keyId, options.LeaseKeyId, StringComparison.Ordinal)
        && start.Environment.TryGetValue("ENSOU_DSH_E2E_LEASE_KEY_X", out var keyX)
        && string.Equals(keyX, options.LeaseKeyX, StringComparison.Ordinal)
        && start.Environment.TryGetValue("ENSOU_DSH_E2E_LEASE_KEY_Y", out var keyY)
        && string.Equals(keyY, options.LeaseKeyY, StringComparison.Ordinal)
        && start.Environment.TryGetValue("ENSOU_DSH_E2E_TLS_CERT_SHA256", out var certificate)
        && string.Equals(
            certificate,
            options.ServerCertificateSha256,
            StringComparison.Ordinal);

    private static bool HasVisibleOwnedWindow(int processId)
    {
        var found = false;
        EnumWindows((window, _) =>
        {
            GetWindowThreadProcessId(window, out var owner);
            if (owner == (uint)processId && IsWindowVisible(window)) found = true;
            return true;
        }, IntPtr.Zero);
        return found;
    }

    private delegate bool WindowVisitor(IntPtr window, IntPtr context);
    [DllImport("user32.dll")] private static extern bool EnumWindows(WindowVisitor callback, IntPtr context);
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr window, out uint processId);
    [DllImport("user32.dll")] private static extern bool IsWindowVisible(IntPtr window);
}
