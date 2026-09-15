using System.IO.Compression;
using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using Ensou.Dsh.Enterprise.Installation;

namespace Ensou.Dsh.Enterprise.UpdateTests;

internal static class Program
{
    private const string PluginPolicyId = "11111111-2222-4333-8444-555555555555";
    private static readonly JsonSerializerOptions LegacyPointerJsonOptions = new(
        JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    private static readonly string TempRoot = Path.Combine(
        Path.GetTempPath(),
        "ensou-dsh-enterprise-update-tests",
        Guid.NewGuid().ToString("N"));
    private static readonly Action IgnoreHostHarnessWritersForIsolatedTest =
        static () => { };
    private static readonly Action<int> IgnoreHostLoopbackForIsolatedTest =
        static _ => { };

    public static async Task<int> Main(string[] args)
    {
        if (args.Length != 0 && args is not ["--operator-rollback-only"] && args is not ["--preflight-only"])
        {
            Console.Error.WriteLine("Expected no arguments, --operator-rollback-only, or --preflight-only.");
            return 2;
        }
        Directory.CreateDirectory(TempRoot);
        var tests = new (string Name, Func<Task> Run)[]
        {
            ("development health diagnostics are bounded, secret-free, and no-follow", EnterpriseDevelopmentHealthDiagnosticsTests.RunAsync),
            ("Launcher startup check requests signed feed and stages tuple", SignedUpdateStagesAsync),
            ("read-only verified preflight does not enter the exclusive update stage", ReadOnlyPreflightDoesNotMutateAsync),
            ("read-only unavailable preflight preserves the authenticated state", ReadOnlyUnavailablePreflightDoesNotMutateAsync),
            ("read-only tampered preflight preserves the authenticated state", ReadOnlyTamperedPreflightDoesNotMutateAsync),
            ("read-only quarantined preflight preserves the authenticated state", ReadOnlyQuarantinedPreflightDoesNotMutateAsync),
            ("first enterprise start reuses embedded launcher and runtime and downloads only plugin", FirstStartDownloadsOnlyPluginAsync),
            ("enterprise metadata-only release performs zero artifact GET", MetadataOnlyReleaseUsesZeroArtifactGetAsync),
            ("authenticated Previous-only reuse downloads only changed plugin and tamper fails closed", PreviousOnlyReuseDownloadsOnlyChangedPluginAndTamperFailsClosedAsync),
            ("Launcher and runtime update independently and download only the changed component", OneChangedEnterpriseComponentDownloadsOnceAsync),
            ("tampered enterprise reuse source fails before manifest or artifact GET", TamperedEnterpriseReuseFailsBeforeNetworkAsync),
            ("rewritten local tree receipt cannot authorize enterprise reuse", RewrittenTreeReceiptCannotAuthorizeReuseAsync),
            ("enterprise downloaded target race fails closed before activation", DownloadedTargetRaceFailsClosedAsync),
            ("unreferenced enterprise residue is collected and never authorizes reuse", UnreferencedEnterpriseResidueNeverAuthorizesReuseAsync),
            ("enterprise release-set requires all three components", ThreeComponentContractRequiredAsync),
            ("tampered and expired manifests preserve healthy old release", RejectedManifestPreservesOldAsync),
            ("signed wrong-channel manifests fail before state advance or artifact download", WrongChannelManifestRejectedAsync),
            ("signed incompatible Startup Stub protocols fail before state advance or artifact download", IncompatibleStartupStubProtocolRejectedAsync),
            ("signed Startup Stub range binds pointer and blocks old Stub or pointer replay", StartupStubPointerBindingRejectsReplayAsync),
            ("partial mandatory download fails closed", PartialMandatoryDownloadFailsClosedAsync),
            ("interrupted artifact download resumes with Range and If-Range", InterruptedDownloadResumesAsync),
            ("server ignoring Range safely restarts from byte zero", IgnoredRangeRestartsFromZeroAsync),
            ("changed ETag safely discards the cached prefix", ChangedEtagRestartsFromZeroAsync),
            ("corrupted cached prefix is detected and fully redownloaded", CorruptedPartialRestartsFromZeroAsync),
            ("slow chunked artifact download completes within idle bounds", SlowArtifactDownloadCompletesAsync),
            ("sequence rollback and equivocation are rejected", SequenceRollbackRejectedAsync),
            ("older Installer replay is rejected before stable writes", OlderInstallerReplayRejectedBeforeWritesAsync),
            ("health self-check failure rolls back tuple", HealthFailureRollsBackAsync),
            ("operator rollback restores Harness home with the old tuple", OperatorRollbackRestoresHarnessHomeAsync),
            ("operator rollback rejects a healthy tuple without changing data", OperatorRollbackRejectsHealthyTupleAsync),
            ("health rollback crash points recover without rerunning the candidate", HealthRollbackCrashPointsRecoverAsync),
            ("health commit crash is finalized on the next update check", HealthCommitCrashFinalizesAsync),
            ("cold-start health window is bounded for single-file extraction", ColdStartHealthWindowIsBoundedAsync),
            ("enterprise update operation lock supports long local paths", LongOperationLockPathIsSupportedAsync),
            ("enterprise Harness-home native rename supports long local paths", LongHarnessHomeRenameIsSupportedAsync),
            ("enterprise JSONL-only Harness inspection supports long local paths", LongHarnessHomeInspectionIsSupportedAsync),
            ("runtime full-tree and launcher replacement tampering fail closed", InstalledTreeTamperingRejectedAsync),
            ("enterprise update never touches personal or Harness data", PersonalAndUserDataIsolationAsync),
            ("online runtime update rejects legacy SQLite before network or state mutation", OnlineRuntimeUpdateLegacySqliteGuardPreservesStateAsync),
            ("offline update grace is bounded for initial and verified releases", OfflineGraceIsBoundedAsync),
            ("clock rollback cannot extend authenticated offline grace", ClockRollbackCannotExtendOfflineGraceAsync),
            ("protected release state deletion and replay fail closed", ProtectedReleaseStateDeletionAndReplayFailClosedAsync),
            ("pointer tuple and compiled release trust are exact", PointerTupleAndCompiledTrustAreExactAsync),
            ("old exact signed release replay preserves the newer active release", OldSignedReleaseReplayPreservesNewerAsync),
            ("stalled manifest check returns to offline policy quickly", StalledManifestReturnsQuicklyAsync),
            ("plugin policy binds exact lease identity and detects tree tampering", PluginPolicyBindingAndTamperAsync),
            ("plugin policy rejects unsafe strict contracts and revocation", PluginPolicyContractRejectsUnsafeAndRevokedAsync),
            ("plugin policy generation rollback preserves last-known-good", PluginPolicyGenerationRollbackPreservesLkgAsync),
        };
        if (args is ["--preflight-only"])
        {
            tests = tests.Where(test => test.Name.StartsWith(
                "read-only", StringComparison.Ordinal)).ToArray();
        }
        else if (args.Length != 0)
        {
            tests = tests.Where(test => test.Name.StartsWith(
                "operator rollback", StringComparison.Ordinal)).ToArray();
        }
        var failures = 0;
        try
        {
            foreach (var test in tests)
            {
                try
                {
                    await test.Run().ConfigureAwait(false);
                    Console.WriteLine($"PASS  {test.Name}");
                }
                catch (Exception exception)
                {
                    failures++;
                    Console.Error.WriteLine($"FAIL  {test.Name}");
                    Console.Error.WriteLine(exception);
                }
            }
        }
        finally
        {
            if (Directory.Exists(TempRoot))
            {
                Directory.Delete(TempRoot, recursive: true);
            }
        }
        Console.WriteLine($"{tests.Length - failures}/{tests.Length} release-set checks passed.");
        return failures == 0 ? 0 : 1;
    }

    private static Task ColdStartHealthWindowIsBoundedAsync()
    {
        AssertEqual(TimeSpan.FromMinutes(5), EnterpriseBootstrapHealthGate.ColdStartTimeout);
        return Task.CompletedTask;
    }

    private static async Task LongOperationLockPathIsSupportedAsync()
    {
        var root = NewDirectory("operation-lock-long-path");
        var local = Path.Combine(root, new string('l', 128), new string('m', 128));
        var profile = Path.Combine(root, "Profile");
        Directory.CreateDirectory(local);
        Directory.CreateDirectory(profile);
        var layout = EnterpriseInstallationLayout.CreateDevelopmentE2E(local, profile);
        AssertTrue(layout.UpdateOperationLockPath.Length > 260);

        await using var lease = await EnterpriseManagedUpdateOperationLease
            .AcquireRequiredAsync(layout)
            .ConfigureAwait(false);
        AssertTrue(File.Exists(layout.UpdateOperationLockPath));
    }

    private static Task LongHarnessHomeRenameIsSupportedAsync()
    {
        var layout = CreateLongHarnessLayout("rename");
        Directory.CreateDirectory(layout.HarnessHome);
        var sentinel = Path.Combine(layout.HarnessHome, "rename-sentinel.bin");
        File.WriteAllText(sentinel, "local-only");
        AssertTrue(sentinel.Length > 260);

        var transaction = new EnterpriseHarnessHomeUpdateTransaction(
            layout.HarnessHome,
            layout.HarnessRecoveryRoot,
            TimeProvider.System,
            moveGapHookForTesting: null,
            requireQuiescentLoopbackPort: IgnoreHostLoopbackForIsolatedTest,
            requireNoPossibleHarnessWriter: IgnoreHostHarnessWritersForIsolatedTest);
        var prepared = transaction.Prepare("set-1", 0);
        AssertTrue(Directory.Exists(prepared.OriginalDirectory));
        AssertTrue(File.Exists(Path.Combine(prepared.OriginalDirectory, "rename-sentinel.bin")));
        transaction.Rollback(prepared.TransactionId, "long-path-test");
        AssertTrue(File.Exists(sentinel));
        return Task.CompletedTask;
    }

    private static Task LongHarnessHomeInspectionIsSupportedAsync()
    {
        var layout = CreateLongHarnessLayout("inspection");
        Directory.CreateDirectory(layout.HarnessHome);
        var sentinel = Path.Combine(layout.HarnessHome, "inspection-sentinel.jsonl");
        File.WriteAllText(sentinel, "{\"kind\":\"local\"}\n");
        AssertTrue(sentinel.Length > 260);

        EnterpriseLegacySqliteUpgradeGuard.RequireJsonlOnlyHarnessHome(layout);
        return Task.CompletedTask;
    }

    private static EnterpriseInstallationLayout CreateLongHarnessLayout(string suffix)
    {
        var root = NewDirectory($"long-harness-{suffix}");
        var local = Path.Combine(root, "LocalAppData");
        var profile = Path.Combine(root, "Profile");
        // Guarantee the shorter sentinel crosses MAX_PATH independently of TEMP depth.
        // Each added segment stays well below NTFS's component-length limit.
        var layout = EnterpriseInstallationLayout.CreateDevelopmentE2E(local, profile);
        while (Path.Combine(layout.HarnessHome, "rename-sentinel.bin").Length <= 260)
        {
            profile = Path.Combine(profile, new string('p', 40));
            layout = EnterpriseInstallationLayout.CreateDevelopmentE2E(local, profile);
        }
        if (layout.HarnessHome.Length > 1024)
        {
            throw new InvalidOperationException("The isolated long-path fixture exceeds its bounded test root.");
        }
        Directory.CreateDirectory(local);
        Directory.CreateDirectory(profile);
        return layout;
    }

    private static async Task SignedUpdateStagesAsync()
    {
        using var fixture = await Fixture.CreateAsync().ConfigureAwait(false);
        var release = fixture.CreateRelease(sequence: 1, includePlugin: true);
        var outcome = await fixture.ApplyAsync(release).ConfigureAwait(false);
        AssertEqual("pending-health", outcome.State);
        AssertTrue(outcome.RequiresBootstrapHealthCheck);
        var pointer = new EnterpriseReleaseSetPointerStore(fixture.Layout).ReadRequired();
        AssertEqual("set-1", pointer.Current.ReleaseSetId);
        AssertEqual("launcher-1", pointer.Current.Launcher.ReleaseId);
        AssertEqual("runtime-1", pointer.Current.Runtime.ReleaseId);
        AssertEqual("plugin-1", pointer.Current.PluginPolicy?.ReleaseId);
        AssertEqual(
            release.Manifest.Launcher.CompleteTreeSha256,
            pointer.Current.Launcher.CompleteTreeSha256);
        AssertEqual(
            release.Manifest.Runtime.CompleteTreeSha256,
            pointer.Current.Runtime.CompleteTreeSha256);
        AssertEqual(
            release.Manifest.PluginPolicy!.CompleteTreeSha256,
            pointer.Current.PluginPolicy?.CompleteTreeSha256);
        AssertTrue(pointer.Previous is not null);
        AssertTrue(File.Exists(fixture.Layout.ReleaseSetPointerPath));
        AssertTrue(Directory.EnumerateFiles(fixture.Layout.UpdateReceiptRoot).Any());
        var homeTransaction = new EnterpriseHarnessHomeUpdateTransaction(
            fixture.Layout.HarnessHome,
            fixture.Layout.HarnessRecoveryRoot);
        var activeHome = homeTransaction.TryReadActiveState();
        AssertTrue(activeHome is not null);
        AssertEqual(
            EnterpriseHarnessHomeUpdateTransaction.PreparedStatus,
            activeHome!.Status);
        AssertEqual("set-1", activeHome.ReleaseSetId);
        AssertEqual(4, fixture.LastRequestCount);
    }

    private static async Task FirstStartDownloadsOnlyPluginAsync()
    {
        using var fixture = await Fixture.CreateAsync().ConfigureAwait(false);
        var release = fixture.CreateRelease(
            sequence: 1,
            includePlugin: true,
            useInitialLauncherRuntime: true);

        var outcome = await fixture.ApplyAsync(release).ConfigureAwait(false);

        AssertEqual("pending-health", outcome.State);
        AssertEqual(2, fixture.LastRequestCount);
        AssertEqual("launcher-initial", outcome.ActivePointer.Current.Launcher.ReleaseId);
        AssertEqual("runtime-initial", outcome.ActivePointer.Current.Runtime.ReleaseId);
        AssertEqual("plugin-1", outcome.ActivePointer.Current.PluginPolicy?.ReleaseId);
        AssertEqual(
            release.Manifest.Launcher.CompleteTreeSha256,
            outcome.ActivePointer.Current.Launcher.CompleteTreeSha256);
        AssertEqual(
            release.Manifest.Runtime.CompleteTreeSha256,
            outcome.ActivePointer.Current.Runtime.CompleteTreeSha256);
    }

    private static async Task MetadataOnlyReleaseUsesZeroArtifactGetAsync()
    {
        using var fixture = await Fixture.CreateAsync().ConfigureAwait(false);
        var first = fixture.CreateRelease(
            sequence: 1,
            includePlugin: true,
            useInitialLauncherRuntime: true);
        AssertEqual("pending-health", (await fixture.ApplyAsync(first)).State);
        CompleteHealth(fixture);
        var metadataOnly = fixture.CreateRelease(
            sequence: 2,
            includePlugin: true,
            reuseLauncherRuntimeFrom: first,
            reusePluginFromSource: true);

        var outcome = await fixture.ApplyAsync(metadataOnly).ConfigureAwait(false);

        AssertEqual("pending-health", outcome.State);
        AssertEqual(1, fixture.LastRequestCount);
        AssertEqual(
            first.Manifest.Launcher.ReleaseId,
            outcome.ActivePointer.Current.Launcher.ReleaseId);
        AssertEqual(
            first.Manifest.Runtime.ReleaseId,
            outcome.ActivePointer.Current.Runtime.ReleaseId);
        AssertEqual(
            first.Manifest.PluginPolicy!.ReleaseId,
            outcome.ActivePointer.Current.PluginPolicy?.ReleaseId);
    }

    private static async Task PreviousOnlyReuseDownloadsOnlyChangedPluginAndTamperFailsClosedAsync()
    {
        using (var fixture = await Fixture.CreateAsync().ConfigureAwait(false))
        {
            var candidate = await PreparePreviousOnlyReuseCandidateAsync(fixture)
                .ConfigureAwait(false);
            var requested = new List<Uri>();
            var handler = new StaticHandler(candidate.Content, requested.Add);

            var outcome = await fixture.ApplyWithHandlerAsync(handler)
                .ConfigureAwait(false);

            AssertEqual("pending-health", outcome.State);
            AssertEqual(2, handler.RequestCount);
            AssertTrue(requested.SequenceEqual(
            [
                Fixture.ManifestUri,
                candidate.Manifest.PluginPolicy!.Uri,
            ]));
            AssertEqual(
                "launcher-initial",
                outcome.ActivePointer.Current.Launcher.ReleaseId);
            AssertEqual(
                "runtime-initial",
                outcome.ActivePointer.Current.Runtime.ReleaseId);
            AssertEqual(
                "plugin-3",
                outcome.ActivePointer.Current.PluginPolicy?.ReleaseId);
        }

        using (var fixture = await Fixture.CreateAsync().ConfigureAwait(false))
        {
            var candidate = await PreparePreviousOnlyReuseCandidateAsync(fixture)
                .ConfigureAwait(false);
            var before = new EnterpriseReleaseSetPointerStore(
                fixture.Layout,
                fixture.CompiledTrust).ReadRequired();
            var previous = before.Previous
                ?? throw new InvalidOperationException(
                    "Enterprise Previous-only reuse test has no authenticated Previous state.");
            File.AppendAllText(
                Path.Combine(
                    previous.Launcher.Directory,
                    EnterpriseInstallationLayout.MaintenanceExecutableName),
                "tampered-previous");
            var handler = new StaticHandler(candidate.Content);

            await AssertThrowsAsync<InvalidDataException>(() =>
                fixture.ApplyWithHandlerAsync(handler));

            AssertEqual(0, handler.RequestCount);
        }
    }

    private static async Task<TestRelease> PreparePreviousOnlyReuseCandidateAsync(
        Fixture fixture)
    {
        var previous = fixture.CreateRelease(
            sequence: 1,
            includePlugin: true,
            useInitialLauncherRuntime: true);
        AssertEqual("pending-health", (await fixture.ApplyAsync(previous)
            .ConfigureAwait(false)).State);
        CompleteHealth(fixture);

        var current = fixture.CreateRelease(sequence: 2, includePlugin: true);
        AssertEqual("pending-health", (await fixture.ApplyAsync(current)
            .ConfigureAwait(false)).State);
        CompleteHealth(fixture);

        var pointer = new EnterpriseReleaseSetPointerStore(
            fixture.Layout,
            fixture.CompiledTrust).ReadRequired();
        AssertEqual(current.Manifest.ReleaseSetId, pointer.Current.ReleaseSetId);
        AssertEqual(previous.Manifest.ReleaseSetId, pointer.Previous?.ReleaseSetId);
        AssertFalse(string.Equals(
            pointer.Current.Launcher.ReleaseId,
            pointer.Previous?.Launcher.ReleaseId,
            StringComparison.Ordinal));
        AssertFalse(string.Equals(
            pointer.Current.Runtime.ReleaseId,
            pointer.Previous?.Runtime.ReleaseId,
            StringComparison.Ordinal));

        return fixture.CreateRelease(
            sequence: 3,
            includePlugin: true,
            pluginGeneration: 3,
            reuseLauncherRuntimeFrom: previous,
            reusePluginFromSource: false);
    }

    private static async Task OneChangedEnterpriseComponentDownloadsOnceAsync()
    {
        using var fixture = await Fixture.CreateAsync().ConfigureAwait(false);
        Directory.CreateDirectory(fixture.Layout.HarnessHome);
        var localSentinelPath = Path.Combine(
            fixture.Layout.HarnessHome,
            "consecutive-update-local-sentinel.bin");
        var localSentinelBytes = "local data survives complete updates"u8.ToArray();
        File.WriteAllBytes(localSentinelPath, localSentinelBytes);
        var first = fixture.CreateRelease(
            sequence: 1,
            includePlugin: true,
            useInitialLauncherRuntime: true,
            compatibleLauncherReleaseIds: ["launcher-initial", "launcher-3"],
            compatibleRuntimeReleaseIds: ["runtime-initial", "runtime-2"]);
        AssertEqual("pending-health", (await fixture.ApplyAsync(first)).State);
        CompleteHealth(fixture);
        AssertTrue(localSentinelBytes.AsSpan().SequenceEqual(
            File.ReadAllBytes(localSentinelPath)));
        var runtimeOnly = fixture.CreateRelease(
            sequence: 2,
            includePlugin: true,
            reuseLauncherRuntimeFrom: first,
            reusePluginFromSource: true,
            reuseLauncherFromSource: true,
            reuseRuntimeFromSource: false);

        var runtimeOutcome = await fixture.ApplyAsync(runtimeOnly).ConfigureAwait(false);

        AssertEqual("pending-health", runtimeOutcome.State);
        AssertEqual(2, fixture.LastRequestCount);
        AssertTrue(fixture.LastRequestUris.SequenceEqual(
            [Fixture.ManifestUri, runtimeOnly.Manifest.Runtime.Uri]));
        AssertEqual(
            first.Manifest.Launcher.ReleaseId,
            runtimeOutcome.ActivePointer.Current.Launcher.ReleaseId);
        AssertEqual("runtime-2", runtimeOutcome.ActivePointer.Current.Runtime.ReleaseId);
        AssertEqual(
            first.Manifest.PluginPolicy?.ReleaseId,
            runtimeOutcome.ActivePointer.Current.PluginPolicy?.ReleaseId);
        CompleteHealth(fixture);
        AssertTrue(localSentinelBytes.AsSpan().SequenceEqual(
            File.ReadAllBytes(localSentinelPath)));

        var launcherOnly = fixture.CreateRelease(
            sequence: 3,
            includePlugin: true,
            reuseLauncherRuntimeFrom: runtimeOnly,
            reusePluginFromSource: true,
            reuseLauncherFromSource: false,
            reuseRuntimeFromSource: true);

        var launcherOutcome = await fixture.ApplyAsync(launcherOnly).ConfigureAwait(false);

        AssertEqual("pending-health", launcherOutcome.State);
        AssertEqual(2, fixture.LastRequestCount);
        AssertTrue(fixture.LastRequestUris.SequenceEqual(
            [Fixture.ManifestUri, launcherOnly.Manifest.Launcher.Uri]));
        AssertEqual("launcher-3", launcherOutcome.ActivePointer.Current.Launcher.ReleaseId);
        AssertEqual(
            runtimeOnly.Manifest.Runtime.ReleaseId,
            launcherOutcome.ActivePointer.Current.Runtime.ReleaseId);
        AssertEqual(
            first.Manifest.PluginPolicy?.ReleaseId,
            launcherOutcome.ActivePointer.Current.PluginPolicy?.ReleaseId);
        CompleteHealth(fixture);
        var committed = new EnterpriseReleaseSetPointerStore(fixture.Layout).ReadRequired();
        AssertEqual(3L, committed.Current.Sequence);
        AssertEqual(EnterpriseReleaseHealthStates.Healthy, committed.Current.HealthState);
        AssertEqual("launcher-3", committed.Current.Launcher.ReleaseId);
        AssertEqual(runtimeOnly.Manifest.Runtime.ReleaseId, committed.Current.Runtime.ReleaseId);
        AssertEqual(
            first.Manifest.PluginPolicy?.ReleaseId,
            committed.Current.PluginPolicy?.ReleaseId);
        AssertTrue(localSentinelBytes.AsSpan().SequenceEqual(
            File.ReadAllBytes(localSentinelPath)));
    }

    private static async Task ReadOnlyPreflightDoesNotMutateAsync()
    {
        using var fixture = await Fixture.CreateAsync().ConfigureAwait(false);
        var candidate = fixture.CreateRelease(sequence: 1, includePlugin: true);
        var pointerBefore = File.ReadAllBytes(fixture.Layout.ReleaseSetPointerPath);
        var statusBefore = ReadOptionalFile(fixture.Layout.UpdateStatusPath);

        var preflight = await fixture.ProbeAsync(candidate).ConfigureAwait(false);

        AssertTrue(preflight.RequiresExclusiveStage);
        AssertTrue(preflight.TerminalOutcome is null);
        AssertEqual(1, fixture.LastRequestCount);
        AssertEqual(Fixture.ManifestUri, fixture.LastRequestUris.Single());
        AssertBytesEqual(
            pointerBefore,
            File.ReadAllBytes(fixture.Layout.ReleaseSetPointerPath),
            fixture.Layout.ReleaseSetPointerPath);
        AssertOptionalBytesEqual(
            statusBefore,
            ReadOptionalFile(fixture.Layout.UpdateStatusPath));
        AssertFalse(Directory.Exists(
            fixture.Layout.GetLauncherVersionDirectory(candidate.Manifest.Launcher.ReleaseId)));
        AssertFalse(Directory.Exists(
            fixture.Layout.GetRuntimeVersionDirectory(candidate.Manifest.Runtime.ReleaseId)));

        _ = await fixture.ApplyAsync(candidate).ConfigureAwait(false);
        CompleteHealth(fixture);
        var noChange = await fixture.ProbeAsync(candidate).ConfigureAwait(false);
        AssertFalse(noChange.RequiresExclusiveStage);
        AssertEqual("up-to-date", noChange.TerminalOutcome?.State);
        AssertEqual(1, fixture.LastRequestCount);
        AssertEqual(Fixture.ManifestUri, fixture.LastRequestUris.Single());
    }

    private static async Task ReadOnlyUnavailablePreflightDoesNotMutateAsync()
    {
        using var fixture = await Fixture.CreateAsync().ConfigureAwait(false);
        var healthy = fixture.CreateRelease(sequence: 1, includePlugin: true);
        _ = await fixture.ApplyAsync(healthy).ConfigureAwait(false);
        CompleteHealth(fixture);
        var readOnlyProbeTime = CreateAdvancedReadOnlyProbeTime(fixture);

        var unavailable = await AssertReadOnlyProbePreservesManagedStateAsync(
            fixture,
            () => fixture.ProbeUnavailableAsync(readOnlyProbeTime)).ConfigureAwait(false);
        AssertFalse(unavailable.RequiresExclusiveStage);
        AssertEqual("offline-last-known-good", unavailable.TerminalOutcome?.State);
    }

    private static async Task ReadOnlyTamperedPreflightDoesNotMutateAsync()
    {
        using var fixture = await Fixture.CreateAsync().ConfigureAwait(false);
        var healthy = fixture.CreateRelease(sequence: 1, includePlugin: true);
        _ = await fixture.ApplyAsync(healthy).ConfigureAwait(false);
        CompleteHealth(fixture);
        var readOnlyProbeTime = CreateAdvancedReadOnlyProbeTime(fixture);

        var signature = healthy.Manifest.Signature;
        var replacementValue = signature.Value[^1] == 'A'
            ? signature.Value[..^1] + "B"
            : signature.Value[..^1] + "A";
        var tamperedManifest = healthy.Manifest with
        {
            Signature = signature with { Value = replacementValue },
        };
        var tampered = healthy with
        {
            ManifestBytes = JsonSerializer.SerializeToUtf8Bytes(
                tamperedManifest,
                new JsonSerializerOptions(JsonSerializerDefaults.Web)
                {
                    WriteIndented = true,
                }),
        };
        var tamperedResult = await AssertReadOnlyProbePreservesManagedStateAsync(
            fixture,
            () => fixture.ProbeAsync(tampered, readOnlyProbeTime)).ConfigureAwait(false);
        AssertFalse(tamperedResult.RequiresExclusiveStage);
        AssertEqual("security-rejected", tamperedResult.TerminalOutcome?.State);
    }

    private static async Task ReadOnlyQuarantinedPreflightDoesNotMutateAsync()
    {
        using var fixture = await Fixture.CreateAsync().ConfigureAwait(false);
        var healthy = fixture.CreateRelease(sequence: 1, includePlugin: true);
        _ = await fixture.ApplyAsync(healthy).ConfigureAwait(false);
        CompleteHealth(fixture);
        var quarantined = fixture.CreateRelease(sequence: 2, includePlugin: true);
        _ = await fixture.ApplyAsync(quarantined).ConfigureAwait(false);
        var health = await new EnterpriseBootstrapHealthGate(
                fixture.Layout,
                TimeSpan.FromSeconds(2))
            .EnsureHealthyAsync((_, _, _, _) => Task.FromResult(7))
            .ConfigureAwait(false);
        AssertFalse(health.Healthy);
        AssertTrue(new EnterpriseReleaseHealthQuarantineStore(fixture.Layout)
            .IsRejected(quarantined.Manifest.ReleaseSetId));
        var quarantineProbeTime = CreateAdvancedReadOnlyProbeTime(fixture);

        var quarantinedResult = await AssertReadOnlyProbePreservesManagedStateAsync(
            fixture,
            () => fixture.ProbeAsync(quarantined, quarantineProbeTime)).ConfigureAwait(false);
        AssertFalse(quarantinedResult.RequiresExclusiveStage);
        AssertEqual("health-rejected-old-allowed", quarantinedResult.TerminalOutcome?.State);
    }

    private static async Task<EnterpriseReleaseUpdatePreflight>
        AssertReadOnlyProbePreservesManagedStateAsync(
            Fixture fixture,
            Func<Task<EnterpriseReleaseUpdatePreflight>> probe)
    {
        var managedTreeBefore = SnapshotExactTree(fixture.Layout.ManagedRoot);
        var securityPaths = new[]
        {
            fixture.Layout.UpdateSecurityStatePath,
            fixture.Layout.UpdateSecurityAnchorPath,
            fixture.Layout.UpdateSecurityWitnessPath,
        };
        var securityBefore = securityPaths.ToDictionary(
            path => path,
            ReadOptionalFile,
            StringComparer.OrdinalIgnoreCase);

        var preflight = await probe().ConfigureAwait(false);

        AssertEqual(managedTreeBefore, SnapshotExactTree(fixture.Layout.ManagedRoot));
        foreach (var path in securityPaths)
        {
            AssertOptionalBytesEqual(securityBefore[path], ReadOptionalFile(path));
        }
        return preflight;
    }

    private static ManualTimeProvider CreateAdvancedReadOnlyProbeTime(Fixture fixture)
    {
        var state = new EnterpriseReleaseFeedStateStore(
                fixture.Layout,
                fixture.ExpectedChannel)
            .TryRead()
            ?? throw new InvalidDataException(
                "Expected authenticated feed state before the read-only probe.");
        return new ManualTimeProvider(state.TrustedTimeUtc.AddMinutes(1));
    }

    private static async Task TamperedEnterpriseReuseFailsBeforeNetworkAsync()
    {
        using var fixture = await Fixture.CreateAsync().ConfigureAwait(false);
        var first = fixture.CreateRelease(
            sequence: 1,
            includePlugin: true,
            useInitialLauncherRuntime: true);
        AssertEqual("pending-health", (await fixture.ApplyAsync(first)).State);
        CompleteHealth(fixture);
        var metadataOnly = fixture.CreateRelease(
            sequence: 2,
            includePlugin: true,
            reuseLauncherRuntimeFrom: first,
            reusePluginFromSource: true);
        File.AppendAllText(
            Path.Combine(
                fixture.Layout.GetLauncherVersionDirectory("launcher-initial"),
                EnterpriseInstallationLayout.MaintenanceExecutableName),
            "tampered");
        var handler = new StaticHandler(metadataOnly.Content);

        await AssertThrowsAsync<InvalidDataException>(() =>
            fixture.ApplyWithHandlerAsync(handler));
        AssertEqual(0, handler.RequestCount);
    }

    private static async Task RewrittenTreeReceiptCannotAuthorizeReuseAsync()
    {
        using var fixture = await Fixture.CreateAsync().ConfigureAwait(false);
        var first = fixture.CreateRelease(
            sequence: 1,
            includePlugin: true,
            useInitialLauncherRuntime: true);
        AssertEqual("pending-health", (await fixture.ApplyAsync(first)).State);
        CompleteHealth(fixture);
        var metadataOnly = fixture.CreateRelease(
            sequence: 2,
            includePlugin: true,
            reuseLauncherRuntimeFrom: first,
            reusePluginFromSource: true);
        var launcherDirectory = fixture.Layout.GetLauncherVersionDirectory(
            first.Manifest.Launcher.ReleaseId);
        File.AppendAllText(
            Path.Combine(
                launcherDirectory,
                EnterpriseInstallationLayout.MaintenanceExecutableName),
            "attacker-controlled bytes");
        var receiptPath = Path.Combine(
            launcherDirectory,
            ".ensou-enterprise-artifact.v2.json");
        var receipt = JsonSerializer.Deserialize<EnterpriseReleaseArtifactReceiptV2>(
            File.ReadAllBytes(receiptPath),
            new JsonSerializerOptions(JsonSerializerDefaults.Web)
            {
                UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
            }) ?? throw new InvalidDataException("Enterprise test receipt is missing.");
        File.WriteAllBytes(
            receiptPath,
            JsonSerializer.SerializeToUtf8Bytes(
                receipt with
                {
                    TreeSha256 = ComputeInstalledTreeSha256(launcherDirectory),
                },
                new JsonSerializerOptions(JsonSerializerDefaults.Web)));
        var handler = new StaticHandler(metadataOnly.Content);

        await AssertThrowsAsync<InvalidDataException>(() =>
            fixture.ApplyWithHandlerAsync(handler));

        AssertEqual(0, handler.RequestCount);
    }

    private static async Task DownloadedTargetRaceFailsClosedAsync()
    {
        using var fixture = await Fixture.CreateAsync().ConfigureAwait(false);
        var release = fixture.CreateRelease(
            sequence: 1,
            includePlugin: true,
            useInitialLauncherRuntime: true);
        var plugin = release.Manifest.PluginPolicy!;
        var raced = false;
        var handler = new StaticHandler(release.Content, uri =>
        {
            if (!raced && uri == plugin.Uri)
            {
                raced = true;
                var target = fixture.Layout.GetPluginPolicyVersionDirectory(
                    plugin.ReleaseId);
                Directory.CreateDirectory(target);
                File.WriteAllText(Path.Combine(target, "attacker.txt"), "untrusted");
            }
        });

        var outcome = await fixture.ApplyWithHandlerAsync(handler)
            .ConfigureAwait(false);

        AssertTrue(raced);
        AssertEqual("download-failed-old-allowed", outcome.State);
        AssertEqual(0L, outcome.ActivePointer.Current.Sequence);
        AssertTrue(outcome.ActivePointer.Current.PluginPolicy is null);
        AssertEqual(2, handler.RequestCount);
    }

    private static async Task UnreferencedEnterpriseResidueNeverAuthorizesReuseAsync()
    {
        using var fixture = await Fixture.CreateAsync().ConfigureAwait(false);
        var release = fixture.CreateRelease(sequence: 1, includePlugin: true);
        var missingPlugin = release.Content
            .Where(pair => pair.Key != release.Manifest.PluginPolicy!.Uri)
            .ToDictionary(pair => pair.Key, pair => pair.Value);

        var interrupted = await fixture.ApplyRawManifestAsync(
            release.ManifestBytes,
            missingPlugin).ConfigureAwait(false);

        AssertEqual("download-failed-old-allowed", interrupted.State);
        AssertTrue(Directory.Exists(
            fixture.Layout.GetLauncherVersionDirectory(
                release.Manifest.Launcher.ReleaseId)));
        AssertTrue(Directory.Exists(
            fixture.Layout.GetRuntimeVersionDirectory(
                release.Manifest.Runtime.ReleaseId)));

        var retried = await fixture.ApplyAsync(release).ConfigureAwait(false);

        AssertEqual("pending-health", retried.State);
        AssertEqual(4, fixture.LastRequestCount);
    }

    private static async Task ThreeComponentContractRequiredAsync()
    {
        using var fixture = await Fixture.CreateAsync().ConfigureAwait(false);
        var release = fixture.CreateRelease(sequence: 1, includePlugin: false);
        var outcome = await fixture.ApplyAsync(release).ConfigureAwait(false);
        AssertEqual("security-rejected", outcome.State);
        AssertEqual(0L, outcome.ActivePointer.Current.Sequence);
        AssertEqual(1, fixture.LastRequestCount);
    }

    private static async Task InterruptedDownloadResumesAsync()
    {
        using var fixture = await Fixture.CreateAsync().ConfigureAwait(false);
        var release = fixture.CreateRelease(sequence: 1);
        using var handler = new ArtifactTransportHandler(
            release,
            release.Manifest.Runtime.Uri,
            ArtifactTransportScenario.Resume);

        var interrupted = await fixture.ApplyWithHandlerAsync(handler).ConfigureAwait(false);
        AssertEqual("download-failed-old-allowed", interrupted.State);
        AssertEqual(1, GetPartialFiles(fixture.Layout).Length);

        var resumed = await fixture.ApplyWithHandlerAsync(handler).ConfigureAwait(false);
        AssertEqual("pending-health", resumed.State);
        AssertEqual(2, handler.TargetRequestCount);
        AssertEqual(handler.InterruptionOffset, handler.ObservedRangeStarts.Single());
        AssertEqual(ArtifactTransportHandler.InitialETag, handler.ObservedIfRange.Single());
        AssertEqual(0, GetPartialCacheEntries(fixture.Layout).Length);
    }

    private static async Task IgnoredRangeRestartsFromZeroAsync()
    {
        using var fixture = await Fixture.CreateAsync().ConfigureAwait(false);
        var release = fixture.CreateRelease(sequence: 1);
        using var handler = new ArtifactTransportHandler(
            release,
            release.Manifest.Runtime.Uri,
            ArtifactTransportScenario.IgnoreRange);

        AssertEqual(
            "download-failed-old-allowed",
            (await fixture.ApplyWithHandlerAsync(handler).ConfigureAwait(false)).State);
        var outcome = await fixture.ApplyWithHandlerAsync(handler).ConfigureAwait(false);
        AssertEqual("pending-health", outcome.State);
        AssertEqual(2, handler.TargetRequestCount);
        AssertEqual(handler.InterruptionOffset, handler.ObservedRangeStarts.Single());
        AssertEqual(0, GetPartialCacheEntries(fixture.Layout).Length);
    }

    private static async Task ChangedEtagRestartsFromZeroAsync()
    {
        using var fixture = await Fixture.CreateAsync().ConfigureAwait(false);
        var release = fixture.CreateRelease(sequence: 1);
        using var handler = new ArtifactTransportHandler(
            release,
            release.Manifest.Runtime.Uri,
            ArtifactTransportScenario.ChangedETag);

        AssertEqual(
            "download-failed-old-allowed",
            (await fixture.ApplyWithHandlerAsync(handler).ConfigureAwait(false)).State);
        var outcome = await fixture.ApplyWithHandlerAsync(handler).ConfigureAwait(false);
        AssertEqual("pending-health", outcome.State);
        AssertEqual(3, handler.TargetRequestCount);
        AssertEqual(handler.InterruptionOffset, handler.ObservedRangeStarts.Single());
        AssertEqual(0, GetPartialCacheEntries(fixture.Layout).Length);
    }

    private static async Task CorruptedPartialRestartsFromZeroAsync()
    {
        using var fixture = await Fixture.CreateAsync().ConfigureAwait(false);
        var release = fixture.CreateRelease(sequence: 1);
        using var handler = new ArtifactTransportHandler(
            release,
            release.Manifest.Runtime.Uri,
            ArtifactTransportScenario.Resume);

        AssertEqual(
            "download-failed-old-allowed",
            (await fixture.ApplyWithHandlerAsync(handler).ConfigureAwait(false)).State);
        var partial = GetPartialFiles(fixture.Layout).Single();
        using (var stream = new FileStream(partial, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            var original = stream.ReadByte();
            AssertTrue(original >= 0);
            stream.Position = 0;
            stream.WriteByte((byte)(original ^ 0x5a));
            stream.Flush(flushToDisk: true);
        }

        var outcome = await fixture.ApplyWithHandlerAsync(handler).ConfigureAwait(false);
        AssertEqual("pending-health", outcome.State);
        AssertEqual(3, handler.TargetRequestCount);
        AssertEqual(0, GetPartialCacheEntries(fixture.Layout).Length);
    }

    private static async Task SlowArtifactDownloadCompletesAsync()
    {
        using var fixture = await Fixture.CreateAsync().ConfigureAwait(false);
        var release = fixture.CreateRelease(sequence: 1);
        using var handler = new ArtifactTransportHandler(
            release,
            release.Manifest.Runtime.Uri,
            ArtifactTransportScenario.Slow);
        var outcome = await fixture.ApplyWithHandlerAsync(handler).ConfigureAwait(false);
        AssertEqual("pending-health", outcome.State);
        AssertTrue(handler.TargetReadCount > 2);
        AssertEqual(0, GetPartialCacheEntries(fixture.Layout).Length);
    }

    private static async Task RejectedManifestPreservesOldAsync()
    {
        using var fixture = await Fixture.CreateAsync().ConfigureAwait(false);
        var release = fixture.CreateRelease(sequence: 1);
        var tampered = release.ManifestBytes.ToArray();
        var marker = Encoding.UTF8.GetBytes("set-1");
        var replacement = Encoding.UTF8.GetBytes("set-x");
        var index = tampered.AsSpan().IndexOf(marker);
        replacement.CopyTo(tampered.AsSpan(index, replacement.Length));
        var outcome = await fixture.ApplyRawManifestAsync(tampered, release.Content)
            .ConfigureAwait(false);
        AssertEqual("security-rejected", outcome.State);
        AssertEqual(0L, outcome.ActivePointer.Current.Sequence);

        var tamperedStartupStub = release.Manifest with
        {
            StartupStub = new EnterpriseStartupStubCompatibility
            {
                MinimumProtocol = EnterpriseReleaseSetContract.CurrentStartupStubProtocol,
                MaximumProtocol = EnterpriseReleaseSetContract.CurrentStartupStubProtocol + 1,
            },
        };
        var tamperedStartupStubBytes = JsonSerializer.SerializeToUtf8Bytes(
            tamperedStartupStub,
            new JsonSerializerOptions(JsonSerializerDefaults.Web) { WriteIndented = true });
        outcome = await fixture.ApplyRawManifestAsync(
                tamperedStartupStubBytes,
                release.Content)
            .ConfigureAwait(false);
        AssertEqual("security-rejected", outcome.State);
        AssertEqual(0L, outcome.ActivePointer.Current.Sequence);
        AssertEqual(1, fixture.LastRequestCount);

        var nullChannel = Encoding.UTF8.GetBytes(
            Encoding.UTF8.GetString(release.ManifestBytes).Replace(
                $"\"channel\": \"{fixture.ExpectedChannel}\"",
                "\"channel\": null",
                StringComparison.Ordinal));
        outcome = await fixture.ApplyRawManifestAsync(nullChannel, release.Content)
            .ConfigureAwait(false);
        AssertEqual("security-rejected", outcome.State);
        AssertEqual(0L, outcome.ActivePointer.Current.Sequence);

        var expired = fixture.CreateRelease(
            sequence: 1,
            issuedAtUtc: DateTimeOffset.UtcNow.AddDays(-3),
            expiresAtUtc: DateTimeOffset.UtcNow.AddDays(-2));
        outcome = await fixture.ApplyAsync(expired).ConfigureAwait(false);
        AssertEqual("security-rejected", outcome.State);
        AssertEqual(0L, outcome.ActivePointer.Current.Sequence);
    }

    private static async Task PartialMandatoryDownloadFailsClosedAsync()
    {
        using var fixture = await Fixture.CreateAsync().ConfigureAwait(false);
        var release = fixture.CreateRelease(sequence: 1, minAcceptedSequence: 1);
        var partial = release.Content.ToDictionary(pair => pair.Key, pair => pair.Value);
        var runtimeUri = release.Manifest.Runtime.Uri;
        partial[runtimeUri] = partial[runtimeUri][..^3];
        await AssertThrowsAsync<InvalidOperationException>(() =>
            fixture.ApplyRawManifestAsync(release.ManifestBytes, partial));
        var pointer = new EnterpriseReleaseSetPointerStore(fixture.Layout).ReadRequired();
        AssertEqual(0L, pointer.Current.Sequence);
        var status = EnterpriseReleaseUpdateStatusReader.TryRead(fixture.Layout)!;
        AssertTrue(status.MustUpdate);
        AssertEqual("blocked", status.State);
        AssertEqual(0, GetPartialCacheEntries(fixture.Layout).Length);
    }

    private static async Task WrongChannelManifestRejectedAsync()
    {
        using var fixture = await Fixture.CreateAsync(
            EnterpriseReleaseSetContract.StableChannel).ConfigureAwait(false);
        foreach (var wrongChannel in new[]
                 {
                     EnterpriseReleaseSetContract.LabChannel,
                     EnterpriseReleaseSetContract.PilotChannel,
                 })
        {
            var release = fixture.CreateRelease(
                sequence: 1,
                releaseSetId: $"set-{wrongChannel}",
                channel: wrongChannel);
            var outcome = await fixture.ApplyAsync(release).ConfigureAwait(false);
            AssertEqual("security-rejected", outcome.State);
            AssertEqual(0L, outcome.ActivePointer.Current.Sequence);
            AssertEqual(1, fixture.LastRequestCount);
            AssertTrue(File.Exists(fixture.Layout.UpdateSecurityStatePath));
            AssertTrue(File.Exists(fixture.Layout.UpdateSecurityAnchorPath));
            AssertTrue(File.Exists(fixture.Layout.UpdateSecurityWitnessPath));
            AssertFalse(Directory.Exists(
                fixture.Layout.GetLauncherVersionDirectory(release.Manifest.Launcher.ReleaseId)));

            var feedStateStore = new EnterpriseReleaseFeedStateStore(
                fixture.Layout,
                EnterpriseReleaseSetContract.StableChannel);
            AssertThrows<InvalidDataException>(() => feedStateStore.RecordVerified(
                release.Manifest,
                release.ManifestBytes,
                new Uri("https://updates.example/release-set.v2.json"),
                new EnterpriseReleaseSetPointerStore(fixture.Layout).ReadRequired(),
                DateTimeOffset.UtcNow));
            AssertTrue(File.Exists(fixture.Layout.UpdateSecurityStatePath));
        }

        var accepted = fixture.CreateRelease(
            sequence: 1,
            channel: EnterpriseReleaseSetContract.StableChannel);
        var acceptedOutcome = await fixture.ApplyAsync(accepted).ConfigureAwait(false);
        AssertEqual("pending-health", acceptedOutcome.State);
        AssertEqual(4, fixture.LastRequestCount);
        var persisted = new EnterpriseReleaseFeedStateStore(
            fixture.Layout,
            EnterpriseReleaseSetContract.StableChannel).TryRead()!;
        AssertEqual(EnterpriseReleaseSetContract.StableChannel, persisted.Channel);
        AssertThrows<InvalidDataException>(() =>
            _ = new EnterpriseReleaseFeedStateStore(
                fixture.Layout,
                EnterpriseReleaseSetContract.LabChannel).TryRead());
    }

    private static async Task IncompatibleStartupStubProtocolRejectedAsync()
    {
        using var fixture = await Fixture.CreateAsync().ConfigureAwait(false);
        var incompatible = fixture.CreateRelease(
            sequence: 1,
            minimumStartupStubProtocol: 2,
            maximumStartupStubProtocol: 2);

        var outcome = await fixture.ApplyAsync(incompatible).ConfigureAwait(false);

        AssertEqual("security-rejected", outcome.State);
        AssertEqual(0L, outcome.ActivePointer.Current.Sequence);
        AssertEqual(1, fixture.LastRequestCount);
        AssertTrue(File.Exists(fixture.Layout.UpdateSecurityStatePath));
        AssertTrue(File.Exists(fixture.Layout.UpdateSecurityAnchorPath));
        AssertTrue(File.Exists(fixture.Layout.UpdateSecurityWitnessPath));
        AssertFalse(Directory.Exists(
            fixture.Layout.GetLauncherVersionDirectory(
                incompatible.Manifest.Launcher.ReleaseId)));
        AssertFalse(Directory.Exists(
            fixture.Layout.GetRuntimeVersionDirectory(
                incompatible.Manifest.Runtime.ReleaseId)));

        var compatible = fixture.CreateRelease(sequence: 1);
        var accepted = await fixture.ApplyAsync(compatible).ConfigureAwait(false);
        AssertEqual("pending-health", accepted.State);
        AssertEqual(4, fixture.LastRequestCount);
    }

    private static async Task StartupStubPointerBindingRejectsReplayAsync()
    {
        using var fixture = await Fixture.CreateAsync().ConfigureAwait(false);
        var release = fixture.CreateRelease(sequence: 1);
        var outcome = await fixture.ApplyAsync(release).ConfigureAwait(false);
        AssertEqual("pending-health", outcome.State);

        var pointerBytes = File.ReadAllBytes(fixture.Layout.ReleaseSetPointerPath);
        var pointer = new EnterpriseReleaseSetPointerStore(fixture.Layout).ReadRequired();
        AssertEqual(
            EnterpriseReleaseSetContract.CurrentStartupStubProtocol,
            pointer.Current.StartupStub.MinimumProtocol);
        AssertEqual(
            EnterpriseReleaseSetContract.CurrentStartupStubProtocol,
            pointer.Current.StartupStub.MaximumProtocol);
        AssertTrue(pointer.Previous is not null);
        AssertEqual(
            EnterpriseReleaseSetContract.CurrentStartupStubProtocol,
            pointer.Previous!.StartupStub.MinimumProtocol);

        AssertThrows<InvalidDataException>(() =>
            EnterpriseReleaseSetValidator.ValidateStartupStubCompatibility(
                pointer.Current.StartupStub,
                EnterpriseReleaseSetContract.CurrentStartupStubProtocol - 1));
        EnterpriseReleaseSetValidator.ValidateStartupStubCompatibility(
            pointer.Current.StartupStub,
            EnterpriseReleaseSetContract.CurrentStartupStubProtocol);

        AssertThrows<JsonException>(() =>
            JsonSerializer.Deserialize<LegacyEnterpriseReleaseSetPointer>(
                pointerBytes,
                LegacyPointerJsonOptions));

        var legacyPointer = JsonNode.Parse(pointerBytes)!.AsObject();
        legacyPointer["schemaVersion"] = 2;
        legacyPointer["current"]!.AsObject().Remove("startupStub");
        legacyPointer["previous"]!.AsObject().Remove("startupStub");
        File.WriteAllBytes(
            fixture.Layout.ReleaseSetPointerPath,
            JsonSerializer.SerializeToUtf8Bytes(
                legacyPointer,
                new JsonSerializerOptions(JsonSerializerDefaults.Web)));
        AssertThrows<InvalidDataException>(() =>
            new EnterpriseReleaseSetPointerStore(fixture.Layout).ReadRequired());
    }

    private static async Task SequenceRollbackRejectedAsync()
    {
        using var fixture = await Fixture.CreateAsync().ConfigureAwait(false);
        var first = fixture.CreateRelease(sequence: 2);
        await fixture.ApplyAsync(first).ConfigureAwait(false);
        CompleteHealth(fixture);
        var rollback = fixture.CreateRelease(sequence: 1);
        var outcome = await fixture.ApplyAsync(rollback).ConfigureAwait(false);
        AssertEqual("security-rejected", outcome.State);
        AssertEqual(2L, outcome.ActivePointer.Current.Sequence);
        var equivocation = fixture.CreateRelease(sequence: 2, releaseSetId: "set-other");
        outcome = await fixture.ApplyAsync(equivocation).ConfigureAwait(false);
        AssertEqual("security-rejected", outcome.State);
        AssertEqual("set-2", outcome.ActivePointer.Current.ReleaseSetId);
    }

    private static async Task OperatorRollbackRestoresHarnessHomeAsync()
    {
        using var fixture = await Fixture.CreateAsync().ConfigureAwait(false);
        Directory.CreateDirectory(fixture.Layout.HarnessHome);
        var history = Path.Combine(fixture.Layout.HarnessHome, "conversation-history.jsonl");
        File.WriteAllText(history, "original-history");
        var workspace = Path.Combine(
            Path.GetDirectoryName(fixture.Layout.HarnessHome)!, "external-workspace.txt");
        File.WriteAllText(workspace, "original-workspace");
        await fixture.ApplyAsync(fixture.CreateRelease(sequence: 1)).ConfigureAwait(false);
        var transaction = new EnterpriseHarnessHomeUpdateTransaction(
            fixture.Layout.HarnessHome, fixture.Layout.HarnessRecoveryRoot);
        var prepared = transaction.TryReadActiveState()
            ?? throw new InvalidOperationException("Expected a pending Harness-home generation.");
        File.WriteAllText(history, "candidate-migrated-history");
        var candidateOnly = Path.Combine(fixture.Layout.HarnessHome, "candidate-only.txt");
        File.WriteAllText(candidateOnly, "candidate-only");

        var pointer = await new EnterpriseBootstrapHealthGate(
                fixture.Layout, TimeSpan.FromSeconds(2), fixture.CompiledTrust)
            .RollbackPendingAsync("operator requested pending-release rollback")
            .ConfigureAwait(false);

        AssertEqual(0L, pointer.Current.Sequence);
        AssertEqual(EnterpriseReleaseHealthStates.Healthy, pointer.Current.HealthState);
        AssertEqual("original-history", File.ReadAllText(history));
        AssertEqual("original-workspace", File.ReadAllText(workspace));
        AssertFalse(File.Exists(candidateOnly));
        AssertTrue(transaction.TryReadActiveState() is null);
        AssertTrue(new EnterpriseReleaseHealthQuarantineStore(fixture.Layout).IsRejected("set-1"));
        using var document = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(
            Path.GetDirectoryName(prepared.OriginalDirectory)!, "transaction.v1.json")));
        AssertEqual(EnterpriseHarnessHomeUpdateTransaction.RestoredStatus,
            document.RootElement.GetProperty("status").GetString());
        var failedDirectory = document.RootElement.GetProperty("failedCandidateDirectory").GetString()!;
        AssertEqual("candidate-only", File.ReadAllText(Path.Combine(failedDirectory, "candidate-only.txt")));
    }

    private static async Task OperatorRollbackRejectsHealthyTupleAsync()
    {
        using var fixture = await Fixture.CreateAsync().ConfigureAwait(false);
        var before = File.ReadAllBytes(fixture.Layout.ReleaseSetPointerPath);
        var initialReleaseId = new EnterpriseReleaseSetPointerStore(
            fixture.Layout, fixture.CompiledTrust).ReadRequired().Current.ReleaseSetId;
        Directory.CreateDirectory(fixture.Layout.HarnessHome);
        var history = Path.Combine(fixture.Layout.HarnessHome, "conversation-history.jsonl");
        File.WriteAllText(history, "healthy-history");
        await AssertThrowsAsync<InvalidOperationException>(() =>
            new EnterpriseBootstrapHealthGate(fixture.Layout, TimeSpan.FromSeconds(2), fixture.CompiledTrust)
                .RollbackPendingAsync("operator requested pending-release rollback"))
            .ConfigureAwait(false);
        AssertBytesEqual(before, File.ReadAllBytes(fixture.Layout.ReleaseSetPointerPath), "healthy pointer");
        AssertEqual("healthy-history", File.ReadAllText(history));
        AssertFalse(new EnterpriseReleaseHealthQuarantineStore(fixture.Layout).IsRejected(initialReleaseId));
    }

    private static async Task HealthFailureRollsBackAsync()
    {
        using var fixture = await Fixture.CreateAsync().ConfigureAwait(false);
        Directory.CreateDirectory(fixture.Layout.HarnessHome);
        var originalHistory = Path.Combine(
            fixture.Layout.HarnessHome,
            "conversation-history.json");
        File.WriteAllText(originalHistory, "original-history");
        var failedRelease = fixture.CreateRelease(sequence: 1);
        await fixture.ApplyAsync(failedRelease).ConfigureAwait(false);
        var homeTransaction = new EnterpriseHarnessHomeUpdateTransaction(
            fixture.Layout.HarnessHome,
            fixture.Layout.HarnessRecoveryRoot);
        var preparedHome = homeTransaction.TryReadActiveState()
            ?? throw new InvalidOperationException(
                "Expected an active Harness-home recovery generation.");
        File.WriteAllText(originalHistory, "candidate-migrated-history");
        var candidateOnly = Path.Combine(fixture.Layout.HarnessHome, "candidate-only.txt");
        File.WriteAllText(candidateOnly, "candidate-only");
        var result = await new EnterpriseBootstrapHealthGate(
                fixture.Layout,
                TimeSpan.FromSeconds(2))
            .EnsureHealthyAsync((_, _, _, _) => Task.FromResult(7))
            .ConfigureAwait(false);
        AssertFalse(result.Healthy);
        var pointer = new EnterpriseReleaseSetPointerStore(fixture.Layout).ReadRequired();
        AssertEqual(0L, pointer.Current.Sequence);
        AssertEqual(EnterpriseReleaseHealthStates.Healthy, pointer.Current.HealthState);
        AssertEqual("original-history", File.ReadAllText(originalHistory));
        AssertFalse(File.Exists(candidateOnly));
        AssertTrue(homeTransaction.TryReadActiveState() is null);
        var recoveryStatePath = Path.Combine(
            Path.GetDirectoryName(preparedHome.OriginalDirectory)!,
            "transaction.v1.json");
        using (var recoveryDocument = JsonDocument.Parse(
                   File.ReadAllBytes(recoveryStatePath)))
        {
            var recoveryState = recoveryDocument.RootElement;
            AssertEqual(
                EnterpriseHarnessHomeUpdateTransaction.RestoredStatus,
                recoveryState.GetProperty("status").GetString());
            var failedCandidateDirectory = recoveryState
                .GetProperty("failedCandidateDirectory")
                .GetString();
            AssertTrue(failedCandidateDirectory is not null);
            AssertEqual(
                "candidate-only",
                File.ReadAllText(Path.Combine(
                    failedCandidateDirectory!,
                    "candidate-only.txt")));
        }
        AssertTrue(Directory.EnumerateFiles(fixture.Layout.UpdateReceiptRoot)
            .Select(File.ReadAllText)
            .Any(value => value.Contains("health-rollback", StringComparison.Ordinal)));

        AssertTrue(new EnterpriseReleaseHealthQuarantineStore(fixture.Layout)
            .IsRejected("set-1"));
        _ = new EnterpriseReleaseSetPointerStore(fixture.Layout)
            .ActivatePending(failedRelease.Manifest);
        var repeatedProbeCount = 0;
        var repeatedResult = await new EnterpriseBootstrapHealthGate(
                fixture.Layout,
                TimeSpan.FromSeconds(2))
            .EnsureHealthyAsync((_, _, _, _) =>
            {
                repeatedProbeCount++;
                return Task.FromResult(0);
            })
            .ConfigureAwait(false);
        AssertFalse(repeatedResult.Healthy);
        AssertEqual(0, repeatedProbeCount);
        AssertEqual(
            0L,
            new EnterpriseReleaseSetPointerStore(fixture.Layout)
                .ReadRequired().Current.Sequence);

        // The startup update path now runs bounded managed-artifact GC before
        // checking the rejected manifest. Exercise the no-rerun health path
        // while its deliberately reactivated test tuple still exists, then
        // prove the normal retry remains on the healthy old release.
        var retried = await fixture.ApplyAsync(failedRelease)
            .ConfigureAwait(false);
        AssertEqual("health-rejected-old-allowed", retried.State);
        AssertFalse(retried.RequiresBootstrapHealthCheck);
        pointer = new EnterpriseReleaseSetPointerStore(fixture.Layout).ReadRequired();
        AssertEqual(0L, pointer.Current.Sequence);

        using var mandatoryFixture = await Fixture.CreateAsync().ConfigureAwait(false);
        var mandatoryFailedRelease = mandatoryFixture.CreateRelease(
            sequence: 1,
            minAcceptedSequence: 1);
        await mandatoryFixture.ApplyAsync(mandatoryFailedRelease).ConfigureAwait(false);
        _ = await new EnterpriseBootstrapHealthGate(
                mandatoryFixture.Layout,
                TimeSpan.FromSeconds(2))
            .EnsureHealthyAsync((_, _, _, _) => Task.FromResult(9))
            .ConfigureAwait(false);
        await AssertThrowsAsync<InvalidOperationException>(() =>
            mandatoryFixture.ApplyAsync(mandatoryFailedRelease));
        var mandatoryStatus = EnterpriseReleaseUpdateStatusReader.TryRead(
            mandatoryFixture.Layout)!;
        AssertEqual("blocked", mandatoryStatus.State);
        AssertTrue(mandatoryStatus.MustUpdate);
    }

    private static async Task HealthCommitCrashFinalizesAsync()
    {
        using var fixture = await Fixture.CreateAsync().ConfigureAwait(false);
        Directory.CreateDirectory(fixture.Layout.HarnessHome);
        var history = Path.Combine(fixture.Layout.HarnessHome, "conversation-history.json");
        File.WriteAllText(history, "original-history");
        var release = fixture.CreateRelease(sequence: 1);
        _ = await fixture.ApplyAsync(release).ConfigureAwait(false);

        var pointerStore = new EnterpriseReleaseSetPointerStore(fixture.Layout);
        var pending = pointerStore.ReadRequired();
        var token = pending.Current.HealthToken!;
        var homeTransaction = new EnterpriseHarnessHomeUpdateTransaction(
            fixture.Layout.HarnessHome,
            fixture.Layout.HarnessRecoveryRoot);
        var active = homeTransaction.TryReadActiveState()
            ?? throw new InvalidOperationException(
                "Expected an active Harness-home recovery generation.");
        File.WriteAllText(history, "candidate-healthy-history");

        homeTransaction.MarkHealthPassed(active.TransactionId);
        _ = pointerStore.MarkCurrentHealthy(token);
        AssertEqual(
            EnterpriseHarnessHomeUpdateTransaction.HealthPassedStatus,
            homeTransaction.TryReadActiveState()!.Status);

        var outcome = await fixture.ApplyAsync(release).ConfigureAwait(false);
        AssertEqual("up-to-date", outcome.State);
        AssertEqual(
            EnterpriseReleaseHealthStates.Healthy,
            pointerStore.ReadRequired().Current.HealthState);
        AssertTrue(homeTransaction.TryReadActiveState() is null);
        AssertEqual("candidate-healthy-history", File.ReadAllText(history));

        var statePath = Path.Combine(
            Path.GetDirectoryName(active.OriginalDirectory)!,
            "transaction.v1.json");
        using var stateDocument = JsonDocument.Parse(File.ReadAllBytes(statePath));
        AssertEqual(
            EnterpriseHarnessHomeUpdateTransaction.CommittedStatus,
            stateDocument.RootElement.GetProperty("status").GetString());
    }

    private static async Task HealthRollbackCrashPointsRecoverAsync()
    {
        foreach (var crashPoint in new[]
                 {
                     "quarantine-before-home",
                     "candidate-moved",
                     "original-restored",
                     "home-restored",
                     "pointer-restored",
                 })
        {
            using var fixture = await Fixture.CreateAsync().ConfigureAwait(false);
            Directory.CreateDirectory(fixture.Layout.HarnessHome);
            var history = Path.Combine(
                fixture.Layout.HarnessHome,
                "conversation-history.json");
            File.WriteAllText(history, "original-history");
            var candidateOnly = Path.Combine(
                fixture.Layout.HarnessHome,
                "candidate-only.txt");
            var release = fixture.CreateRelease(sequence: 1);
            _ = await fixture.ApplyAsync(release).ConfigureAwait(false);
            var pointerStore = new EnterpriseReleaseSetPointerStore(fixture.Layout);
            var pending = pointerStore.ReadRequired();
            var homeTransaction = new EnterpriseHarnessHomeUpdateTransaction(
                fixture.Layout.HarnessHome,
                fixture.Layout.HarnessRecoveryRoot);
            var activeHome = homeTransaction.TryReadActiveState()
                ?? throw new InvalidOperationException(
                    "Expected an active Harness-home recovery generation.");
            File.WriteAllText(history, "candidate-history");
            File.WriteAllText(candidateOnly, "candidate-only");
            var quarantine = new EnterpriseReleaseHealthQuarantineStore(fixture.Layout);

            if (crashPoint == "quarantine-before-home")
            {
                var originalHistory = Path.Combine(
                    activeHome.OriginalDirectory,
                    "conversation-history.json");
                File.WriteAllText(originalHistory, "corrupted-original");
                var initialProbeCount = 0;
                var failed = await new EnterpriseBootstrapHealthGate(
                        fixture.Layout,
                        TimeSpan.FromSeconds(2))
                    .EnsureHealthyAsync((_, _, _, _) =>
                    {
                        initialProbeCount++;
                        return Task.FromResult(7);
                    })
                    .ConfigureAwait(false);
                AssertFalse(failed.Healthy);
                AssertEqual(1, initialProbeCount);
                AssertTrue(quarantine.IsRejected(pending.Current.ReleaseSetId));
                AssertEqual(
                    EnterpriseReleaseHealthStates.Pending,
                    pointerStore.ReadRequired().Current.HealthState);
                File.WriteAllText(originalHistory, "original-history");
            }
            else
            {
                quarantine.RecordFailed(pending.Current, "simulated health failure");
                var failedDirectory = Path.Combine(
                    Path.GetDirectoryName(activeHome.OriginalDirectory)!,
                    $"failed-{crashPoint}");
                switch (crashPoint)
                {
                    case "candidate-moved":
                        Directory.Move(fixture.Layout.HarnessHome, failedDirectory);
                        break;
                    case "original-restored":
                        Directory.Move(fixture.Layout.HarnessHome, failedDirectory);
                        Directory.Move(activeHome.OriginalDirectory, fixture.Layout.HarnessHome);
                        break;
                    case "home-restored":
                        _ = homeTransaction.Rollback(
                            activeHome.TransactionId,
                            "simulated-crash");
                        break;
                    case "pointer-restored":
                        _ = homeTransaction.Rollback(
                            activeHome.TransactionId,
                            "simulated-crash");
                        _ = pointerStore.RollbackPending("simulated health failure");
                        break;
                }
            }

            var recoveryProbeCount = 0;
            var recovered = await new EnterpriseBootstrapHealthGate(
                    fixture.Layout,
                    TimeSpan.FromSeconds(2))
                .EnsureHealthyAsync((_, _, _, _) =>
                {
                    recoveryProbeCount++;
                    return Task.FromResult(0);
                })
                .ConfigureAwait(false);
            AssertEqual(0, recoveryProbeCount);
            AssertEqual(
                crashPoint == "pointer-restored",
                recovered.Healthy);
            AssertEqual("original-history", File.ReadAllText(history));
            AssertFalse(File.Exists(candidateOnly));
            AssertTrue(homeTransaction.TryReadActiveState() is null);
            AssertEqual(0L, pointerStore.ReadRequired().Current.Sequence);
            AssertTrue(quarantine.IsRejected(pending.Current.ReleaseSetId));

            var repeatedProbeCount = 0;
            var repeated = await new EnterpriseBootstrapHealthGate(
                    fixture.Layout,
                    TimeSpan.FromSeconds(2))
                .EnsureHealthyAsync((_, _, _, _) =>
                {
                    repeatedProbeCount++;
                    return Task.FromResult(0);
                })
                .ConfigureAwait(false);
            AssertTrue(repeated.Healthy);
            AssertEqual(0, repeatedProbeCount);
        }
    }

    private static async Task InstalledTreeTamperingRejectedAsync()
    {
        using var fixture = await Fixture.CreateAsync().ConfigureAwait(false);
        await fixture.ApplyAsync(fixture.CreateRelease(sequence: 1)).ConfigureAwait(false);
        CompleteHealth(fixture);
        var store = new EnterpriseReleaseSetPointerStore(fixture.Layout);
        var pointer = store.ReadRequired();
        var dependency = Path.Combine(
            pointer.Current.Runtime.Directory,
            "node_modules",
            "dependency.js");
        File.WriteAllText(dependency, "tampered");
        AssertThrows<InvalidDataException>(() => store.ReadRequired());

        using var second = await Fixture.CreateAsync().ConfigureAwait(false);
        await second.ApplyAsync(second.CreateRelease(sequence: 1)).ConfigureAwait(false);
        CompleteHealth(second);
        var secondStore = new EnterpriseReleaseSetPointerStore(second.Layout);
        var secondPointer = secondStore.ReadRequired();
        File.WriteAllText(
            Path.Combine(
                secondPointer.Current.Launcher.Directory,
                EnterpriseInstallationLayout.LauncherExecutableName),
            "replaced launcher");
        AssertThrows<InvalidDataException>(() => secondStore.ReadRequired());
    }

    private static async Task PluginPolicyBindingAndTamperAsync()
    {
        using var fixture = await Fixture.CreateAsync().ConfigureAwait(false);
        var outcome = await fixture.ApplyAsync(
                fixture.CreateRelease(sequence: 1, includePlugin: true))
            .ConfigureAwait(false);
        AssertEqual("pending-health", outcome.State);

        var store = new EnterpriseReleaseSetPointerStore(fixture.Layout);
        var validatedPointer = store.ReadRequired();
        var policy = store.ReadActivePluginPolicyRequired(validatedPointer);
        AssertEqual(PluginPolicyId, policy.PolicyId);
        AssertEqual(1L, policy.Generation);
        AssertTrue(policy.Critical);
        AssertTrue(Directory.Exists(policy.SkillsRoot));
        policy.RequireLeaseBinding(PluginPolicyId, 1, policy.PolicySha256);
        AssertThrows<InvalidDataException>(() => policy.RequireLeaseBinding(
            "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            1,
            policy.PolicySha256));
        AssertThrows<InvalidDataException>(() => policy.RequireLeaseBinding(
            PluginPolicyId,
            2,
            policy.PolicySha256));
        AssertThrows<InvalidDataException>(() => policy.RequireLeaseBinding(
            PluginPolicyId,
            1,
            new string('0', 64)));

        var receiptPath = Path.Combine(
            policy.PolicyDirectory,
            ".ensou-enterprise-plugin-policy.v2.json");
        AssertTrue(File.Exists(receiptPath));
        using (var receipt = JsonDocument.Parse(File.ReadAllBytes(receiptPath)))
        {
            AssertEqual(PluginPolicyId, receipt.RootElement.GetProperty("policyId").GetString());
            AssertEqual(1L, receipt.RootElement.GetProperty("generation").GetInt64());
            AssertEqual("skills", receipt.RootElement.GetProperty("skillsRoot").GetString());
        }
        AssertFalse(Directory.EnumerateFiles(
                policy.PolicyDirectory,
                "*.tmp",
                SearchOption.AllDirectories)
            .Any());

        File.AppendAllText(
            Path.Combine(policy.SkillsRoot, "mail-manager", "SKILL.md"),
            "tampered");
        AssertThrows<InvalidDataException>(() => store.ReadRequired());
    }

    private static async Task PluginPolicyContractRejectsUnsafeAndRevokedAsync()
    {
        var valid = CreatePluginPolicyJson(
            "launcher-1",
            "runtime-1",
            generation: 1);
        var unknown = valid[..^1] + ",\"unknown\":true}";
        var duplicate = valid.Replace(
            "\"generation\":1",
            "\"generation\":1,\"generation\":1",
            StringComparison.Ordinal);
        var escape = valid.Replace(
            "skills/mail-manager/SKILL.md",
            "../escape/SKILL.md",
            StringComparison.Ordinal);
        var absolute = valid.Replace(
            "skills/mail-manager/SKILL.md",
            "C:/escape/SKILL.md",
            StringComparison.Ordinal);
        var hashMarker = Hash(Encoding.UTF8.GetBytes(PluginSkillContents));
        var badHash = valid.Replace(
            hashMarker,
            (hashMarker[0] == '0' ? "1" : "0") + hashMarker[1..],
            StringComparison.Ordinal);

        foreach (var pluginZip in new[]
        {
            CreatePluginZipRaw(unknown),
            CreatePluginZipRaw(duplicate),
            CreatePluginZipRaw(escape),
            CreatePluginZipRaw(absolute),
            CreatePluginZipRaw(badHash),
            CreatePluginZip(
                "launcher-other",
                "runtime-1",
                generation: 1),
            CreatePluginZip(
                "launcher-1",
                "runtime-1",
                generation: 1,
                revoked: true),
            CreatePluginZip(
                "launcher-1",
                "runtime-1",
                generation: 1,
                markSkillAsReparsePoint: true),
        })
        {
            using var fixture = await Fixture.CreateAsync().ConfigureAwait(false);
            var outcome = await fixture.ApplyAsync(fixture.CreateRelease(
                    sequence: 1,
                    includePlugin: true,
                    pluginZipOverride: pluginZip))
                .ConfigureAwait(false);
            AssertEqual("download-failed-old-allowed", outcome.State);
            AssertEqual(0L, new EnterpriseReleaseSetPointerStore(fixture.Layout)
                .ReadRequired().Current.Sequence);
        }
    }

    private static async Task PluginPolicyGenerationRollbackPreservesLkgAsync()
    {
        using var fixture = await Fixture.CreateAsync().ConfigureAwait(false);
        await fixture.ApplyAsync(fixture.CreateRelease(
                sequence: 1,
                includePlugin: true,
                pluginGeneration: 2))
            .ConfigureAwait(false);
        CompleteHealth(fixture);
        var before = new EnterpriseReleaseSetPointerStore(fixture.Layout)
            .ReadActivePluginPolicyRequired();
        AssertEqual(2L, before.Generation);

        var outcome = await fixture.ApplyAsync(fixture.CreateRelease(
                sequence: 2,
                includePlugin: true,
                pluginGeneration: 1))
            .ConfigureAwait(false);
        AssertEqual("download-failed-old-allowed", outcome.State);
        var store = new EnterpriseReleaseSetPointerStore(fixture.Layout);
        AssertEqual(1L, store.ReadRequired().Current.Sequence);
        var after = store.ReadActivePluginPolicyRequired();
        AssertEqual(before.PolicyId, after.PolicyId);
        AssertEqual(2L, after.Generation);
        AssertEqual(before.PolicySha256, after.PolicySha256);
    }

    private static async Task PersonalAndUserDataIsolationAsync()
    {
        using var fixture = await Fixture.CreateAsync().ConfigureAwait(false);
        var personal = Path.Combine(
            fixture.LocalAppData,
            "Ensou",
            "DshLauncher",
            "personal-sentinel.txt");
        Directory.CreateDirectory(Path.GetDirectoryName(personal)!);
        File.WriteAllText(personal, "personal-keep");
        Directory.CreateDirectory(fixture.Layout.HarnessHome);
        var history = Path.Combine(fixture.Layout.HarnessHome, "conversation-history.json");
        File.WriteAllText(history, "history-keep");
        var workspaceRoot = Path.Combine(fixture.Layout.HarnessHome, "workspaces");
        Directory.CreateDirectory(workspaceRoot);
        var workspace = Path.Combine(workspaceRoot, "employee-project.txt");
        File.WriteAllText(workspace, "workspace-keep");
        await fixture.ApplyAsync(fixture.CreateRelease(sequence: 1)).ConfigureAwait(false);
        _ = await new EnterpriseBootstrapHealthGate(fixture.Layout, TimeSpan.FromSeconds(2))
            .EnsureHealthyAsync((_, _, _, token) => Task.FromResult(5))
            .ConfigureAwait(false);
        AssertEqual("personal-keep", File.ReadAllText(personal));
        AssertEqual("history-keep", File.ReadAllText(history));
        AssertEqual("workspace-keep", File.ReadAllText(workspace));
    }

    private static async Task OnlineRuntimeUpdateLegacySqliteGuardPreservesStateAsync()
    {
        using var fixture = await Fixture.CreateAsync().ConfigureAwait(false);
        Directory.CreateDirectory(fixture.Layout.HarnessHome);
        File.WriteAllText(
            Path.Combine(fixture.Layout.HarnessHome, "conversation-history.jsonl"),
            "jsonl-history-unchanged");
        var legacy = Path.Combine(fixture.Layout.HarnessHome, "sessions-journal");
        var legacyBytes = "legacy-sidecar-unchanged"u8.ToArray();
        File.WriteAllBytes(legacy, legacyBytes);
        var release = fixture.CreateRelease(sequence: 1, includePlugin: true);
        var handler = new StaticHandler(release.Content);
        var homeBefore = SnapshotExactTree(fixture.Layout.HarnessHome);
        var managedBefore = SnapshotExactTree(fixture.Layout.ManagedRoot);
        var pointerBefore = File.ReadAllBytes(fixture.Layout.ReleaseSetPointerPath);
        var statusBefore = ReadOptionalFile(fixture.Layout.UpdateStatusPath);

        await AssertThrowsAsync<InvalidOperationException>(() =>
            fixture.ApplyWithHandlerAsync(handler));

        AssertEqual(0, handler.RequestCount);
        AssertEqual(homeBefore, SnapshotExactTree(fixture.Layout.HarnessHome));
        AssertEqual(managedBefore, SnapshotExactTree(fixture.Layout.ManagedRoot));
        AssertTrue(pointerBefore.AsSpan().SequenceEqual(
            File.ReadAllBytes(fixture.Layout.ReleaseSetPointerPath)));
        AssertOptionalBytesEqual(statusBefore, ReadOptionalFile(fixture.Layout.UpdateStatusPath));
        AssertTrue(legacyBytes.AsSpan().SequenceEqual(File.ReadAllBytes(legacy)));
        AssertFalse(new EnterpriseHarnessHomeUpdateTransaction(
            fixture.Layout.HarnessHome,
            fixture.Layout.HarnessRecoveryRoot).TryReadActiveState() is not null);

        using var writerFixture = await Fixture.CreateAsync().ConfigureAwait(false);
        var writerRelease = writerFixture.CreateRelease(sequence: 1, includePlugin: true);
        var writerHandler = new StaticHandler(writerRelease.Content);
        var writerManagedBefore = SnapshotExactTree(writerFixture.Layout.ManagedRoot);
        var writerGuardCalls = 0;
        InvalidOperationException? writerFailure = null;
        try
        {
            _ = await writerFixture.ApplyWithHandlerAsync(
                    writerHandler,
                    requireNoPossibleHarnessWriter: () =>
                    {
                        writerGuardCalls++;
                        throw new InvalidOperationException(
                            "Injected managed Harness writer.");
                    })
                .ConfigureAwait(false);
        }
        catch (InvalidOperationException exception)
        {
            writerFailure = exception;
        }
        AssertTrue(writerFailure is not null);
        AssertEqual(
            EnterpriseLegacySqliteUpgradeGuard.BlockedMessage,
            writerFailure!.Message);
        AssertEqual(1, writerGuardCalls);
        AssertEqual(0, writerHandler.RequestCount);
        AssertEqual(
            writerManagedBefore,
            SnapshotExactTree(writerFixture.Layout.ManagedRoot));
    }

    private static string SnapshotExactTree(string root)
    {
        if (!Directory.Exists(root))
        {
            return "<absent>";
        }
        var rows = new List<string> { "D:." };
        rows.AddRange(Directory.EnumerateDirectories(root, "*", SearchOption.AllDirectories)
            .Select(path => "D:" + Path.GetRelativePath(root, path).Replace('\\', '/')));
        rows.AddRange(Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories)
            .Select(path =>
            {
                var bytes = File.ReadAllBytes(path);
                return "F:" + Path.GetRelativePath(root, path).Replace('\\', '/')
                    + ":" + bytes.LongLength
                    + ":" + Convert.ToHexStringLower(SHA256.HashData(bytes));
            }));
        rows.Sort(StringComparer.Ordinal);
        return string.Join("\n", rows);
    }

    private static byte[]? ReadOptionalFile(string path) =>
        File.Exists(path) ? File.ReadAllBytes(path) : null;

    private static void AssertOptionalBytesEqual(byte[]? expected, byte[]? actual)
    {
        if (expected is null || actual is null)
        {
            AssertTrue(expected is null && actual is null);
            return;
        }
        AssertTrue(expected.AsSpan().SequenceEqual(actual));
    }

    private static async Task OfflineGraceIsBoundedAsync()
    {
        using var fixture = await Fixture.CreateAsync().ConfigureAwait(false);
        var initial = new EnterpriseReleaseSetPointerStore(fixture.Layout).ReadRequired().Current;
        var time = new ManualTimeProvider(initial.ActivatedAtUtc.AddDays(7).AddSeconds(-1));
        var store = new EnterpriseReleaseFeedStateStore(
            fixture.Layout,
            fixture.ExpectedChannel,
            time,
            TimeSpan.FromDays(7));
        AssertTrue(store.IsCurrentAllowedOffline(initial, out _));
        time.UtcNow = initial.ActivatedAtUtc.AddDays(7).AddSeconds(1);
        AssertFalse(store.IsCurrentAllowedOffline(initial, out _));

        using var verifiedFixture = await Fixture.CreateAsync().ConfigureAwait(false);
        await verifiedFixture.ApplyAsync(verifiedFixture.CreateRelease(sequence: 1))
            .ConfigureAwait(false);
        CompleteHealth(verifiedFixture);
        var verifiedState = new EnterpriseReleaseFeedStateStore(
            verifiedFixture.Layout,
            verifiedFixture.ExpectedChannel).TryRead()!;
        var verifiedCurrent = new EnterpriseReleaseSetPointerStore(verifiedFixture.Layout)
            .ReadRequired().Current;
        time.UtcNow = verifiedState.LastVerifiedAtUtc.AddDays(7).AddSeconds(1);
        store = new EnterpriseReleaseFeedStateStore(
            verifiedFixture.Layout,
            verifiedFixture.ExpectedChannel,
            time,
            TimeSpan.FromDays(7));
        AssertFalse(store.IsCurrentAllowedOffline(verifiedCurrent, out _));
    }

    private static async Task ClockRollbackCannotExtendOfflineGraceAsync()
    {
        using var fixture = await Fixture.CreateAsync().ConfigureAwait(false);
        var current = new EnterpriseReleaseSetPointerStore(fixture.Layout)
            .ReadRequired().Current;
        var time = new ManualTimeProvider(current.ActivatedAtUtc.AddDays(6));
        var store = new EnterpriseReleaseFeedStateStore(
            fixture.Layout,
            fixture.ExpectedChannel,
            time,
            TimeSpan.FromDays(7));
        AssertTrue(store.IsCurrentAllowedOffline(current, out _));

        time.UtcNow = current.ActivatedAtUtc.AddDays(1);
        AssertTrue(store.IsCurrentAllowedOffline(current, out _));
        time.UtcNow = current.ActivatedAtUtc.AddDays(7).AddSeconds(1);
        AssertFalse(store.IsCurrentAllowedOffline(current, out _));
        time.UtcNow = current.ActivatedAtUtc.AddDays(2);
        AssertFalse(store.IsCurrentAllowedOffline(current, out _));
    }

    private static async Task ProtectedReleaseStateDeletionAndReplayFailClosedAsync()
    {
        using var fixture = await Fixture.CreateAsync().ConfigureAwait(false);
        var first = fixture.CreateRelease(sequence: 1);
        _ = await fixture.ApplyAsync(first).ConfigureAwait(false);
        CompleteHealth(fixture);
        var protectedPaths = new[]
        {
            fixture.Layout.UpdateSecurityStatePath,
            fixture.Layout.UpdateSecurityAnchorPath,
            fixture.Layout.UpdateSecurityWitnessPath,
        };
        var firstSnapshot = protectedPaths.ToDictionary(
            path => path,
            File.ReadAllBytes,
            StringComparer.OrdinalIgnoreCase);

        File.Delete(fixture.Layout.UpdateSecurityWitnessPath);
        AssertThrows<InvalidDataException>(() =>
            _ = new EnterpriseReleaseSetPointerStore(
                fixture.Layout,
                fixture.CompiledTrust).ReadRequired());
        File.WriteAllBytes(
            fixture.Layout.UpdateSecurityWitnessPath,
            firstSnapshot[fixture.Layout.UpdateSecurityWitnessPath]);

        var second = fixture.CreateRelease(sequence: 2);
        _ = await fixture.ApplyAsync(second).ConfigureAwait(false);
        CompleteHealth(fixture);
        foreach (var path in protectedPaths)
        {
            File.WriteAllBytes(path, firstSnapshot[path]);
        }
        AssertThrows<InvalidDataException>(() =>
            _ = new EnterpriseReleaseSetPointerStore(
                fixture.Layout,
                fixture.CompiledTrust).ReadRequired());

        foreach (var path in protectedPaths)
        {
            File.Delete(path);
        }
        AssertThrows<InvalidDataException>(() =>
            _ = new EnterpriseReleaseSetPointerStore(fixture.Layout).ReadRequired());
        File.Delete(fixture.Layout.ReleaseSetPointerPath);
        AssertThrows<InvalidDataException>(() =>
            _ = new EnterpriseReleaseSetPointerStore(fixture.Layout).ReadRequired());
        await AssertThrowsAsync<InvalidDataException>(() =>
            new EnterpriseInstallationService(fixture.Layout)
                .InstallExternalDevelopmentPayloadAsync(
                    fixture.InitialPayloadPath,
                    Environment.ProcessPath!)).ConfigureAwait(false);
    }

    private static async Task PointerTupleAndCompiledTrustAreExactAsync()
    {
        using var fixture = await Fixture.CreateAsync().ConfigureAwait(false);
        _ = await fixture.ApplyAsync(fixture.CreateRelease(sequence: 1))
            .ConfigureAwait(false);
        CompleteHealth(fixture);
        var first = new EnterpriseReleaseSetPointerStore(
            fixture.Layout,
            fixture.CompiledTrust).ReadRequired();
        _ = await fixture.ApplyAsync(fixture.CreateRelease(sequence: 2))
            .ConfigureAwait(false);
        CompleteHealth(fixture);
        var second = new EnterpriseReleaseSetPointerStore(
            fixture.Layout,
            fixture.CompiledTrust).ReadRequired();

        using (var wrongSigner = ECDsa.Create(ECCurve.NamedCurves.nistP256))
        {
            var wrong = wrongSigner.ExportParameters(false);
            var wrongPolicy = fixture.TrustPolicy with
            {
                TrustedKeys =
                [
                    new EnterpriseReleasePublicKey(
                        "wrong-key",
                        Base64Url(wrong.Q.X!),
                        Base64Url(wrong.Q.Y!)),
                ],
            };
            AssertThrows<InvalidDataException>(() =>
                _ = new EnterpriseReleaseSetPointerStore(
                    fixture.Layout,
                    new EnterpriseCompiledReleaseTrust(
                        Fixture.ManifestUri,
                        wrongPolicy)).ReadRequired());
        }
        AssertThrows<InvalidDataException>(() =>
            _ = new EnterpriseReleaseSetPointerStore(
                fixture.Layout,
                new EnterpriseCompiledReleaseTrust(
                    new Uri("https://updates.example/other-release-set.v2.json"),
                    fixture.TrustPolicy)).ReadRequired());

        var forged = second with
        {
            Current = second.Current with
            {
                Launcher = first.Current.Launcher,
                Runtime = first.Current.Runtime,
                PluginPolicy = first.Current.PluginPolicy,
            },
        };
        File.WriteAllBytes(
            fixture.Layout.ReleaseSetPointerPath,
            JsonSerializer.SerializeToUtf8Bytes(forged, LegacyPointerJsonOptions));
        AssertThrows<InvalidDataException>(() =>
            _ = new EnterpriseReleaseSetPointerStore(
                fixture.Layout,
                fixture.CompiledTrust).ReadRequired());
    }

    private static async Task OldSignedReleaseReplayPreservesNewerAsync()
    {
        using var fixture = await Fixture.CreateAsync().ConfigureAwait(false);
        var old = fixture.CreateRelease(sequence: 1);
        _ = await fixture.ApplyAsync(old).ConfigureAwait(false);
        CompleteHealth(fixture);
        _ = await fixture.ApplyAsync(fixture.CreateRelease(sequence: 2))
            .ConfigureAwait(false);
        CompleteHealth(fixture);

        var replay = await fixture.ApplyAsync(old).ConfigureAwait(false);
        AssertEqual("security-rejected", replay.State);
        var active = new EnterpriseReleaseSetPointerStore(
            fixture.Layout,
            fixture.CompiledTrust).ReadRequired();
        AssertEqual(2L, active.Current.Sequence);
        AssertEqual("set-2", active.Current.ReleaseSetId);
    }

    private static async Task StalledManifestReturnsQuicklyAsync()
    {
        using var fixture = await Fixture.CreateAsync().ConfigureAwait(false);
        var stopwatch = Stopwatch.StartNew();
        var outcome = await fixture.CheckWithHandlerAsync(
            new StallingHandler(),
            TimeSpan.FromMilliseconds(150)).ConfigureAwait(false);
        stopwatch.Stop();
        AssertEqual("offline-last-known-good", outcome.State);
        AssertTrue(stopwatch.Elapsed < TimeSpan.FromSeconds(2));
    }

    private static void CompleteHealth(Fixture fixture)
    {
        var pointer = new EnterpriseReleaseSetPointerStore(fixture.Layout).ReadRequired();
        var token = pointer.Current.HealthToken!;
        var coordinator = new EnterpriseReleaseHealthCoordinator(fixture.Layout);
        coordinator.WriteSignal(token);
        var healthy = coordinator.ConsumeSignalAndMarkHealthy(token);
        AssertEqual(
            EnterpriseReleaseHealthStates.Healthy,
            healthy.Current.HealthState);
        AssertTrue(new EnterpriseHarnessHomeUpdateTransaction(
            fixture.Layout.HarnessHome,
            fixture.Layout.HarnessRecoveryRoot).TryReadActiveState() is null);
    }

    private static string[] GetPartialFiles(EnterpriseInstallationLayout layout) =>
        Directory.Exists(layout.UpdatePartialCacheRoot)
            ? Directory.GetFiles(
                layout.UpdatePartialCacheRoot,
                "*.partial",
                SearchOption.TopDirectoryOnly)
            : [];

    private static string[] GetPartialCacheEntries(EnterpriseInstallationLayout layout) =>
        Directory.Exists(layout.UpdatePartialCacheRoot)
            ? Directory.GetFiles(layout.UpdatePartialCacheRoot, "*", SearchOption.TopDirectoryOnly)
            : [];

    private static async Task OlderInstallerReplayRejectedBeforeWritesAsync()
    {
        using var fixture = await Fixture.CreateAsync().ConfigureAwait(false);
        var release = fixture.CreateRelease(sequence: 1);
        _ = await fixture.ApplyAsync(release).ConfigureAwait(false);
        CompleteHealth(fixture);

        var currentPayload = CreateInstallPayload(release, "bootstrapper-current");
        var currentInstaller = Path.Combine(fixture.Root, "current-installer.exe");
        File.WriteAllText(currentInstaller, "current-installer");
        var service = new EnterpriseInstallationService(fixture.Layout);
        var currentRepair = await service.InstallExternalDevelopmentPayloadAsync(
            currentPayload,
            currentInstaller).ConfigureAwait(false);
        AssertEqual("launcher-1", currentRepair.LauncherReleaseId);
        AssertEqual("runtime-1", currentRepair.RuntimeReleaseId);

        var protectedPaths = new[]
        {
            fixture.Layout.BootstrapperPath,
            fixture.Layout.BootstrapperReceiptPath,
            fixture.Layout.InstalledInstallerPath,
            fixture.Layout.BuildProfileMarkerPath,
            fixture.Layout.LauncherPointerPath,
            fixture.Layout.RuntimePointerPath,
            fixture.Layout.ReleaseSetPointerPath,
            Path.Combine(fixture.Layout.StateRoot, "installation-receipt.json"),
        };
        var before = protectedPaths.ToDictionary(
            path => path,
            File.ReadAllBytes,
            StringComparer.OrdinalIgnoreCase);
        var oldInstaller = Path.Combine(fixture.Root, "old-installer.exe");
        File.WriteAllText(oldInstaller, "old-installer");

        await AssertThrowsAsync<InvalidOperationException>(() =>
            service.InstallExternalDevelopmentPayloadAsync(
                fixture.InitialPayloadPath,
                oldInstaller));

        foreach (var path in protectedPaths)
        {
            AssertBytesEqual(before[path], File.ReadAllBytes(path), path);
        }
        var pointer = new EnterpriseReleaseSetPointerStore(fixture.Layout).ReadRequired();
        AssertEqual(1L, pointer.Current.Sequence);
        AssertEqual("launcher-1", pointer.Current.Launcher.ReleaseId);
        AssertEqual("runtime-1", pointer.Current.Runtime.ReleaseId);
        AssertFalse(Directory.EnumerateDirectories(
            fixture.Layout.PackageRoot,
            ".install-*",
            SearchOption.TopDirectoryOnly).Any());
    }

    private sealed class Fixture : IDisposable
    {
        public static Uri ManifestUri { get; } = new(
            "https://updates.example/release-set.v2.json");
        private readonly ECDsa _signer;
        private readonly EnterpriseReleaseTrustPolicy _trust;

        private Fixture(
            string root,
            string localAppData,
            EnterpriseInstallationLayout layout,
            string initialPayloadPath,
            ECDsa signer,
            EnterpriseReleaseTrustPolicy trust)
        {
            Root = root;
            LocalAppData = localAppData;
            Layout = layout;
            InitialPayloadPath = initialPayloadPath;
            _signer = signer;
            _trust = trust;
        }

        public string Root { get; }
        public string LocalAppData { get; }
        public EnterpriseInstallationLayout Layout { get; }
        public string InitialPayloadPath { get; }
        public int LastRequestCount { get; private set; }
        public IReadOnlyList<Uri> LastRequestUris { get; private set; } = [];
        public string ExpectedChannel => _trust.ExpectedChannel;
        public EnterpriseReleaseTrustPolicy TrustPolicy => _trust;
        public EnterpriseCompiledReleaseTrust CompiledTrust => new(ManifestUri, _trust);

        public static async Task<Fixture> CreateAsync(
            string expectedChannel = EnterpriseReleaseSetContract.LabChannel)
        {
            var root = NewDirectory("fixture");
            var local = Path.Combine(root, "LocalAppData");
            var profile = Path.Combine(root, "Profile");
            Directory.CreateDirectory(local);
            Directory.CreateDirectory(profile);
            var layout = EnterpriseInstallationLayout.CreateDevelopmentE2E(local, profile);
            var payload = CreateInitialPayload();
            // This suite owns an isolated temporary Harness home and exercises
            // release-set behavior, not the machine-wide writer guard. Inject
            // a deterministic no-writer observation so an unrelated Personal
            // DSH process cannot make every update fixture environment-bound.
            await new EnterpriseInstallationService(
                    layout,
                    beforeLegacySqliteCommitForTest: null,
                    requireNoPossibleHarnessWriter:
                        IgnoreHostHarnessWritersForIsolatedTest)
                .InstallExternalDevelopmentPayloadAsync(payload, Environment.ProcessPath!)
                .ConfigureAwait(false);
            var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var parameters = signer.ExportParameters(false);
            var trust = new EnterpriseReleaseTrustPolicy
            {
                Product = EnterpriseReleaseSetContract.Product,
                Environment = EnterpriseReleaseSetContract.DevelopmentE2EEnvironment,
                ExpectedChannel = expectedChannel,
                CurrentStartupStubProtocol =
                    EnterpriseReleaseSetContract.CurrentStartupStubProtocol,
                ManifestOrigin = new Uri("https://updates.example/"),
                ArtifactOrigin = new Uri("https://artifacts.example/"),
                TrustedKeys = [new EnterpriseReleasePublicKey(
                    "test-key",
                    Base64Url(parameters.Q.X!),
                    Base64Url(parameters.Q.Y!))],
            };
            return new Fixture(root, local, layout, payload, signer, trust);
        }

        public TestRelease CreateRelease(
            long sequence,
            long minAcceptedSequence = 0,
            bool includePlugin = true,
            long? pluginGeneration = null,
            byte[]? pluginZipOverride = null,
            string? releaseSetId = null,
            string? channel = null,
            DateTimeOffset? issuedAtUtc = null,
            DateTimeOffset? expiresAtUtc = null,
            int minimumStartupStubProtocol =
                EnterpriseReleaseSetContract.CurrentStartupStubProtocol,
            int maximumStartupStubProtocol =
                EnterpriseReleaseSetContract.CurrentStartupStubProtocol,
            bool useInitialLauncherRuntime = false,
            TestRelease? reuseLauncherRuntimeFrom = null,
            bool reusePluginFromSource = false,
            bool reuseLauncherFromSource = true,
            bool reuseRuntimeFromSource = true,
            IReadOnlyList<string>? compatibleLauncherReleaseIds = null,
            IReadOnlyList<string>? compatibleRuntimeReleaseIds = null)
        {
            if (useInitialLauncherRuntime && reuseLauncherRuntimeFrom is not null)
            {
                throw new ArgumentException(
                    "Enterprise test release cannot select two component reuse sources.");
            }
            if (reusePluginFromSource && reuseLauncherRuntimeFrom is null)
            {
                throw new ArgumentException(
                    "Enterprise plugin reuse requires an explicit source release.");
            }
            var setId = releaseSetId ?? $"set-{sequence}";
            var reuseLauncher = reuseLauncherRuntimeFrom is not null
                && reuseLauncherFromSource;
            var reuseRuntime = reuseLauncherRuntimeFrom is not null
                && reuseRuntimeFromSource;
            var launcherReleaseId = useInitialLauncherRuntime
                ? "launcher-initial"
                : reuseLauncher
                    ? reuseLauncherRuntimeFrom!.Manifest.Launcher.ReleaseId
                    : $"launcher-{sequence}";
            var runtimeReleaseId = useInitialLauncherRuntime
                ? "runtime-initial"
                : reuseRuntime
                    ? reuseLauncherRuntimeFrom!.Manifest.Runtime.ReleaseId
                    : $"runtime-{sequence}";
            var launcher = useInitialLauncherRuntime
                ? File.ReadAllBytes(Path.Combine(InitialPayloadPath, "launcher.zip"))
                : reuseLauncher
                    ? reuseLauncherRuntimeFrom!.Content[
                        reuseLauncherRuntimeFrom.Manifest.Launcher.Uri]
                    : CreateLauncherZip(launcherReleaseId);
            var runtime = useInitialLauncherRuntime
                ? File.ReadAllBytes(Path.Combine(InitialPayloadPath, "runtime.zip"))
                : reuseRuntime
                    ? reuseLauncherRuntimeFrom!.Content[
                        reuseLauncherRuntimeFrom.Manifest.Runtime.Uri]
                    : CreateRuntimeZip(runtimeReleaseId);
            var content = new Dictionary<Uri, byte[]>();
            var artifacts = new List<EnterpriseReleaseArtifact>
            {
                Artifact("launcher", launcherReleaseId, launcher, content),
                Artifact("runtime", runtimeReleaseId, runtime, content),
            };
            if (includePlugin)
            {
                var sourcePlugin = reusePluginFromSource
                    ? reuseLauncherRuntimeFrom!.Manifest.PluginPolicy
                        ?? throw new InvalidDataException(
                            "Enterprise component reuse source has no plugin policy.")
                    : null;
                var pluginReleaseId = sourcePlugin?.ReleaseId ?? $"plugin-{sequence}";
                var pluginBytes = sourcePlugin is null
                    ? pluginZipOverride ?? CreatePluginZip(
                        launcherReleaseId,
                        runtimeReleaseId,
                        pluginGeneration ?? sequence,
                        compatibleLauncherReleaseIds:
                            compatibleLauncherReleaseIds,
                        compatibleRuntimeReleaseIds:
                            compatibleRuntimeReleaseIds)
                    : reuseLauncherRuntimeFrom!.Content[sourcePlugin.Uri];
                artifacts.Add(Artifact(
                    "plugin-policy",
                    pluginReleaseId,
                    pluginBytes,
                    content));
            }
            var placeholderSignature = Signature(new byte[64]);
            var placeholder = new EnterpriseReleaseSetManifest
            {
                SchemaVersion = 2,
                Product = EnterpriseReleaseSetContract.Product,
                Environment = EnterpriseReleaseSetContract.DevelopmentE2EEnvironment,
                Channel = channel ?? _trust.ExpectedChannel,
                ReleaseSetId = setId,
                Generation = 1,
                Sequence = sequence,
                MinAcceptedSequence = minAcceptedSequence,
                IssuedAtUtc = issuedAtUtc ?? DateTimeOffset.UtcNow.AddMinutes(-1),
                ExpiresAtUtc = expiresAtUtc ?? DateTimeOffset.UtcNow.AddDays(1),
                StartupStub = new EnterpriseStartupStubCompatibility
                {
                    MinimumProtocol = minimumStartupStubProtocol,
                    MaximumProtocol = maximumStartupStubProtocol,
                },
                RevokedReleaseSetIds = [],
                Artifacts = artifacts,
                Signature = placeholderSignature,
            };
            artifacts = artifacts.Select(artifact => artifact with
            {
                Signature = Sign(
                    EnterpriseReleaseCanonicalJson.ArtifactPayload(placeholder, artifact)),
            }).ToList();
            var manifest = placeholder with { Artifacts = artifacts };
            manifest = manifest with
            {
                Signature = Sign(EnterpriseReleaseCanonicalJson.ManifestPayload(manifest)),
            };
            var bytes = JsonSerializer.SerializeToUtf8Bytes(
                manifest,
                new JsonSerializerOptions(JsonSerializerDefaults.Web) { WriteIndented = true });
            content[ManifestUri] = bytes;
            return new TestRelease(manifest, bytes, content);
        }

        public Task<EnterpriseReleaseUpdateOutcome> ApplyAsync(TestRelease release) =>
            ApplyRawManifestAsync(release.ManifestBytes, release.Content);

        public async Task<EnterpriseReleaseUpdatePreflight> ProbeAsync(
            TestRelease release,
            TimeProvider? timeProvider = null)
        {
            var values = release.Content.ToDictionary(pair => pair.Key, pair => pair.Value);
            values[ManifestUri] = release.ManifestBytes;
            var requestedUris = new List<Uri>();
            using var httpClient = new HttpClient(new StaticHandler(values, requestedUris.Add));
            var preflight = await new EnterpriseReleaseStartupCoordinator(
                    Layout,
                    ManifestUri,
                    _trust,
                    httpClient,
                    timeProvider)
                .ProbeVerifiedReleaseAsync()
                .ConfigureAwait(false);
            LastRequestCount = requestedUris.Count;
            LastRequestUris = requestedUris;
            return preflight;
        }

        public async Task<EnterpriseReleaseUpdatePreflight> ProbeUnavailableAsync(
            TimeProvider? timeProvider = null)
        {
            var requestedUris = new List<Uri>();
            using var httpClient = new HttpClient(new StaticHandler(
                new Dictionary<Uri, byte[]>(),
                requestedUris.Add));
            var preflight = await new EnterpriseReleaseStartupCoordinator(
                    Layout,
                    ManifestUri,
                    _trust,
                    httpClient,
                    timeProvider)
                .ProbeVerifiedReleaseAsync()
                .ConfigureAwait(false);
            LastRequestCount = requestedUris.Count;
            LastRequestUris = requestedUris;
            return preflight;
        }

        public async Task<EnterpriseReleaseUpdateOutcome> ApplyRawManifestAsync(
            byte[] manifestBytes,
            IReadOnlyDictionary<Uri, byte[]> content)
        {
            var values = content.ToDictionary(pair => pair.Key, pair => pair.Value);
            values[ManifestUri] = manifestBytes;
            var requestedUris = new List<Uri>();
            var handler = new StaticHandler(values, requestedUris.Add);
            using var httpClient = new HttpClient(handler);
            var outcome = await new EnterpriseReleaseStartupCoordinator(
                    Layout,
                    ManifestUri,
                    _trust,
                    httpClient,
                    timeProvider: null,
                    harnessPort: 3080,
                    requireNoPossibleHarnessWriter:
                        IgnoreHostHarnessWritersForIsolatedTest,
                    requireQuiescentLoopbackPort:
                        IgnoreHostLoopbackForIsolatedTest)
                .CheckOnEveryStartupAsync()
                .ConfigureAwait(false);
            LastRequestCount = handler.RequestCount;
            LastRequestUris = requestedUris;
            return outcome;
        }

        public async Task<EnterpriseReleaseUpdateOutcome> CheckWithHandlerAsync(
            HttpMessageHandler handler,
            TimeSpan manifestTimeout,
            Action? requireNoPossibleHarnessWriter = null,
            Action<int>? requireQuiescentLoopbackPort = null)
        {
            using var httpClient = new HttpClient(handler);
            return await new EnterpriseReleaseStartupCoordinator(
                    Layout,
                    ManifestUri,
                    _trust with { ManifestRequestTimeout = manifestTimeout },
                    httpClient,
                    timeProvider: null,
                    harnessPort: 3080,
                    requireNoPossibleHarnessWriter:
                        requireNoPossibleHarnessWriter
                        ?? IgnoreHostHarnessWritersForIsolatedTest,
                    requireQuiescentLoopbackPort:
                        requireQuiescentLoopbackPort
                        ?? IgnoreHostLoopbackForIsolatedTest)
                .CheckOnEveryStartupAsync()
                .ConfigureAwait(false);
        }

        public Task<EnterpriseReleaseUpdateOutcome> ApplyWithHandlerAsync(
            HttpMessageHandler handler,
            Action? requireNoPossibleHarnessWriter = null,
            Action<int>? requireQuiescentLoopbackPort = null) =>
            CheckWithHandlerAsync(
                handler,
                _trust.ManifestRequestTimeout,
                requireNoPossibleHarnessWriter,
                requireQuiescentLoopbackPort);

        public void Dispose() => _signer.Dispose();

        private EnterpriseReleaseArtifact Artifact(
            string component,
            string releaseId,
            byte[] bytes,
            IDictionary<Uri, byte[]> content)
        {
            var uri = new Uri($"https://artifacts.example/{releaseId}.zip");
            content[uri] = bytes;
            using var archiveStream = new MemoryStream(bytes, writable: false);
            string completeTreeSha256;
            try
            {
                completeTreeSha256 = EnterpriseReleaseArchiveTreeHash.Compute(archiveStream);
            }
            catch (InvalidDataException)
            {
                // Some negative tests deliberately construct an unsafe signed ZIP.
                // Give that candidate a syntactically valid signed tree identity so
                // the installer, rather than this fixture, performs the rejection.
                completeTreeSha256 = Hash(Encoding.UTF8.GetBytes(
                    $"invalid-archive:{component}:{releaseId}"));
            }
            return new EnterpriseReleaseArtifact
            {
                Component = component,
                ReleaseId = releaseId,
                Uri = uri,
                SizeBytes = bytes.LongLength,
                Sha256 = Hash(bytes),
                CompleteTreeSha256 = completeTreeSha256,
                Signature = Signature(new byte[64]),
            };
        }

        private EnterpriseReleaseSignature Sign(ReadOnlySpan<byte> payload) => Signature(
            _signer.SignData(
                payload,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation));

        private static EnterpriseReleaseSignature Signature(byte[] value) => new()
        {
            Algorithm = "ES256",
            KeyId = "test-key",
            Value = Base64Url(value),
        };
    }

    [JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
    private sealed record LegacyEnterpriseReleaseSetReference(
        string ReleaseSetId,
        long Generation,
        long Sequence,
        long MinAcceptedSequence,
        EnterpriseReleaseComponentPointer Launcher,
        EnterpriseReleaseComponentPointer Runtime,
        EnterpriseReleaseComponentPointer? PluginPolicy,
        string HealthState,
        string? HealthToken,
        DateTimeOffset ActivatedAtUtc);

    [JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
    private sealed record LegacyEnterpriseReleaseSetPointer(
        int SchemaVersion,
        string Product,
        string Environment,
        LegacyEnterpriseReleaseSetReference Current,
        LegacyEnterpriseReleaseSetReference? Previous,
        DateTimeOffset UpdatedAtUtc);

    private sealed record TestRelease(
        EnterpriseReleaseSetManifest Manifest,
        byte[] ManifestBytes,
        IReadOnlyDictionary<Uri, byte[]> Content);

    private enum ArtifactTransportScenario
    {
        Resume,
        IgnoreRange,
        ChangedETag,
        Slow,
    }

    private sealed class ArtifactTransportHandler : HttpMessageHandler
    {
        public const string InitialETag = "\"artifact-v1\"";
        private const string ChangedETag = "\"artifact-v2\"";
        private readonly IReadOnlyDictionary<Uri, byte[]> _content;
        private readonly Uri _targetUri;
        private readonly ArtifactTransportScenario _scenario;
        private readonly byte[] _targetBytes;

        public ArtifactTransportHandler(
            TestRelease release,
            Uri targetUri,
            ArtifactTransportScenario scenario)
        {
            _content = release.Content;
            _targetUri = targetUri;
            _scenario = scenario;
            _targetBytes = release.Content[targetUri];
            InterruptionOffset = Math.Max(1, _targetBytes.Length / 2);
        }

        public int InterruptionOffset { get; }

        public int TargetRequestCount { get; private set; }

        public int TargetReadCount { get; private set; }

        public List<long> ObservedRangeStarts { get; } = [];

        public List<string> ObservedIfRange { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            if (request.RequestUri is null
                || !_content.TryGetValue(request.RequestUri, out var bytes))
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound)
                {
                    RequestMessage = request,
                });
            }
            if (request.RequestUri != _targetUri)
            {
                return Task.FromResult(FullResponse(request, bytes, InitialETag));
            }

            TargetRequestCount++;
            var range = request.Headers.Range?.Ranges.SingleOrDefault();
            if (range?.From is long rangeStart)
            {
                ObservedRangeStarts.Add(rangeStart);
            }
            if (request.Headers.IfRange?.EntityTag is { } ifRange)
            {
                ObservedIfRange.Add(ifRange.ToString());
            }

            if (_scenario == ArtifactTransportScenario.Slow)
            {
                var slow = new InstrumentedReadStream(
                    _targetBytes,
                    maximumChunkBytes: 17,
                    failAfterBytes: null,
                    delayPerRead: TimeSpan.FromMilliseconds(2),
                    () => TargetReadCount++);
                return Task.FromResult(StreamResponse(
                    request,
                    HttpStatusCode.OK,
                    slow,
                    _targetBytes.LongLength,
                    InitialETag));
            }

            if (TargetRequestCount == 1)
            {
                var interrupted = new InstrumentedReadStream(
                    _targetBytes,
                    maximumChunkBytes: InterruptionOffset,
                    failAfterBytes: InterruptionOffset,
                    delayPerRead: TimeSpan.Zero,
                    () => TargetReadCount++);
                return Task.FromResult(StreamResponse(
                    request,
                    HttpStatusCode.OK,
                    interrupted,
                    _targetBytes.LongLength,
                    InitialETag));
            }

            if (range?.From is long from)
            {
                if (_scenario == ArtifactTransportScenario.IgnoreRange)
                {
                    return Task.FromResult(FullResponse(request, _targetBytes, InitialETag));
                }
                var responseETag = _scenario == ArtifactTransportScenario.ChangedETag
                    ? ChangedETag
                    : InitialETag;
                return Task.FromResult(PartialResponse(request, _targetBytes, from, responseETag));
            }

            return Task.FromResult(FullResponse(
                request,
                _targetBytes,
                _scenario == ArtifactTransportScenario.ChangedETag
                    ? ChangedETag
                    : InitialETag));
        }

        private static HttpResponseMessage FullResponse(
            HttpRequestMessage request,
            byte[] bytes,
            string etag)
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                RequestMessage = request,
                Content = new ByteArrayContent(bytes),
            };
            response.Headers.ETag = EntityTagHeaderValue.Parse(etag);
            return response;
        }

        private static HttpResponseMessage PartialResponse(
            HttpRequestMessage request,
            byte[] bytes,
            long from,
            string etag)
        {
            if (from < 0 || from >= bytes.LongLength)
            {
                return new HttpResponseMessage(HttpStatusCode.RequestedRangeNotSatisfiable)
                {
                    RequestMessage = request,
                };
            }
            var remaining = bytes.AsSpan((int)from).ToArray();
            var response = new HttpResponseMessage(HttpStatusCode.PartialContent)
            {
                RequestMessage = request,
                Content = new ByteArrayContent(remaining),
            };
            response.Headers.ETag = EntityTagHeaderValue.Parse(etag);
            response.Content.Headers.ContentRange = new ContentRangeHeaderValue(
                from,
                bytes.LongLength - 1,
                bytes.LongLength);
            return response;
        }

        private static HttpResponseMessage StreamResponse(
            HttpRequestMessage request,
            HttpStatusCode statusCode,
            Stream stream,
            long contentLength,
            string etag)
        {
            var response = new HttpResponseMessage(statusCode)
            {
                RequestMessage = request,
                Content = new StreamContent(stream),
            };
            response.Headers.ETag = EntityTagHeaderValue.Parse(etag);
            response.Content.Headers.ContentLength = contentLength;
            return response;
        }
    }

    private sealed class InstrumentedReadStream(
        byte[] bytes,
        int maximumChunkBytes,
        int? failAfterBytes,
        TimeSpan delayPerRead,
        Action onRead) : Stream
    {
        private int _position;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => bytes.LongLength;
        public override long Position
        {
            get => _position;
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count) =>
            ReadCore(buffer.AsSpan(offset, count));

        public override ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default) =>
            ReadAsyncCore(buffer, cancellationToken);

        private async ValueTask<int> ReadAsyncCore(
            Memory<byte> buffer,
            CancellationToken cancellationToken)
        {
            if (delayPerRead > TimeSpan.Zero)
            {
                await Task.Delay(delayPerRead, cancellationToken).ConfigureAwait(false);
            }
            return ReadCore(buffer.Span);
        }

        private int ReadCore(Span<byte> buffer)
        {
            if (failAfterBytes is int failureOffset && _position >= failureOffset)
            {
                throw new IOException("Injected artifact transport interruption.");
            }
            if (_position >= bytes.Length)
            {
                return 0;
            }
            var remainingBeforeFailure = failAfterBytes is int limit
                ? limit - _position
                : int.MaxValue;
            var count = Math.Min(
                Math.Min(buffer.Length, maximumChunkBytes),
                Math.Min(bytes.Length - _position, remainingBeforeFailure));
            if (count <= 0)
            {
                throw new IOException("Injected artifact transport interruption.");
            }
            bytes.AsSpan(_position, count).CopyTo(buffer);
            _position += count;
            onRead();
            return count;
        }

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) =>
            throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();
    }

    private sealed class StaticHandler(
        IReadOnlyDictionary<Uri, byte[]> content,
        Action<Uri>? onRequest = null)
        : HttpMessageHandler
    {
        public int RequestCount { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            RequestCount++;
            if (request.RequestUri is null)
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound)
                {
                    RequestMessage = request,
                });
            }
            onRequest?.Invoke(request.RequestUri);
            if (!content.TryGetValue(request.RequestUri, out var bytes))
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound)
                {
                    RequestMessage = request,
                });
            }
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                RequestMessage = request,
                Content = new ByteArrayContent(bytes),
            });
        }
    }

    private static string ComputeInstalledTreeSha256(string root)
    {
        using var aggregate = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (var path in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories)
                     .Where(path => Path.GetRelativePath(root, path).Replace('\\', '/')
                         is not ".ensou-enterprise-launcher.json"
                         and not ".ensou-enterprise-runtime.json"
                         and not ".ensou-enterprise-plugin-policy.v2.json"
                         and not ".ensou-enterprise-artifact.v2.json")
                     .OrderBy(
                         path => Path.GetRelativePath(root, path).Replace('\\', '/'),
                         StringComparer.Ordinal))
        {
            var relative = Path.GetRelativePath(root, path).Replace('\\', '/');
            aggregate.AppendData(Encoding.UTF8.GetBytes(relative));
            aggregate.AppendData([0]);
            using var stream = File.OpenRead(path);
            aggregate.AppendData(SHA256.HashData(stream));
            aggregate.AppendData([0]);
        }
        return Convert.ToHexStringLower(aggregate.GetHashAndReset());
    }

    private sealed class ManualTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        public DateTimeOffset UtcNow { get; set; } = utcNow;

        public override DateTimeOffset GetUtcNow() => UtcNow;
    }

    private sealed class StallingHandler : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken)
                .ConfigureAwait(false);
            throw new UnreachableException();
        }
    }

    private static string CreateInitialPayload()
    {
        var payload = NewDirectory("initial-payload");
        File.WriteAllText(
            Path.Combine(payload, EnterpriseDirectoryPayloadSource.DevelopmentConsentFileName),
            EnterpriseDirectoryPayloadSource.DevelopmentConsentText);
        var launcherPath = Path.Combine(payload, "launcher.zip");
        File.WriteAllBytes(launcherPath, CreateLauncherZip("launcher-initial"));
        var runtimePath = Path.Combine(payload, "runtime.zip");
        File.WriteAllBytes(runtimePath, CreateRuntimeZip("runtime-initial"));
        var bootstrapper = Path.Combine(
            payload,
            EnterpriseInstallationLayout.BootstrapperExecutableName);
        File.WriteAllText(bootstrapper, "bootstrapper");
        var manifest = new EnterpriseInstallManifest
        {
            SchemaVersion = 1,
            LayoutProfile = EnterpriseInstallationLayout.DevelopmentE2ELayoutProfile,
            LauncherReleaseId = "launcher-initial",
            RuntimeReleaseId = "runtime-initial",
            LauncherArchive = "launcher.zip",
            LauncherArchiveSizeBytes = new FileInfo(launcherPath).Length,
            LauncherArchiveSha256 = Hash(File.ReadAllBytes(launcherPath)),
            RuntimeArchive = "runtime.zip",
            RuntimeArchiveSizeBytes = new FileInfo(runtimePath).Length,
            RuntimeArchiveSha256 = Hash(File.ReadAllBytes(runtimePath)),
            BootstrapperFile = EnterpriseInstallationLayout.BootstrapperExecutableName,
            BootstrapperSizeBytes = new FileInfo(bootstrapper).Length,
            BootstrapperSha256 = Hash(File.ReadAllBytes(bootstrapper)),
            PublishedAtUtc = DateTimeOffset.UtcNow,
        };
        File.WriteAllText(
            Path.Combine(payload, EnterpriseEmbeddedPayloadSource.ManifestFileName),
            JsonSerializer.Serialize(manifest, new JsonSerializerOptions(JsonSerializerDefaults.Web)));
        return payload;
    }

    private static string CreateInstallPayload(TestRelease release, string bootstrapperContent)
    {
        var payload = NewDirectory("installer-repair-payload");
        File.WriteAllText(
            Path.Combine(payload, EnterpriseDirectoryPayloadSource.DevelopmentConsentFileName),
            EnterpriseDirectoryPayloadSource.DevelopmentConsentText);
        var launcherArtifact = release.Manifest.Launcher;
        var runtimeArtifact = release.Manifest.Runtime;
        var launcherPath = Path.Combine(payload, "launcher.zip");
        var runtimePath = Path.Combine(payload, "runtime.zip");
        File.WriteAllBytes(launcherPath, release.Content[launcherArtifact.Uri]);
        File.WriteAllBytes(runtimePath, release.Content[runtimeArtifact.Uri]);
        var bootstrapper = Path.Combine(
            payload,
            EnterpriseInstallationLayout.BootstrapperExecutableName);
        File.WriteAllText(bootstrapper, bootstrapperContent);
        var manifest = new EnterpriseInstallManifest
        {
            SchemaVersion = 1,
            LayoutProfile = EnterpriseInstallationLayout.DevelopmentE2ELayoutProfile,
            LauncherReleaseId = launcherArtifact.ReleaseId,
            RuntimeReleaseId = runtimeArtifact.ReleaseId,
            LauncherArchive = "launcher.zip",
            LauncherArchiveSizeBytes = launcherArtifact.SizeBytes,
            LauncherArchiveSha256 = launcherArtifact.Sha256,
            RuntimeArchive = "runtime.zip",
            RuntimeArchiveSizeBytes = runtimeArtifact.SizeBytes,
            RuntimeArchiveSha256 = runtimeArtifact.Sha256,
            BootstrapperFile = EnterpriseInstallationLayout.BootstrapperExecutableName,
            BootstrapperSizeBytes = new FileInfo(bootstrapper).Length,
            BootstrapperSha256 = Hash(File.ReadAllBytes(bootstrapper)),
            PublishedAtUtc = DateTimeOffset.UtcNow,
        };
        File.WriteAllText(
            Path.Combine(payload, EnterpriseEmbeddedPayloadSource.ManifestFileName),
            JsonSerializer.Serialize(manifest, new JsonSerializerOptions(JsonSerializerDefaults.Web)));
        return payload;
    }

    private static byte[] CreateLauncherZip(string releaseId) => CreateZip(archive =>
    {
        WriteEntry(archive, EnterpriseInstallationLayout.LauncherExecutableName, releaseId);
        WriteEntry(
            archive,
            EnterpriseInstallationLayout.ClientBootstrapperExecutableName,
            $"versioned-bootstrapper-{releaseId}");
        WriteEntry(
            archive,
            EnterpriseInstallationLayout.MaintenanceExecutableName,
            $"maintenance-{releaseId}");
        WriteEntry(
            archive,
            EnterpriseInstallationLayout.BuildProfileMarkerFileName,
            JsonSerializer.Serialize(new
            {
                schemaVersion = 1,
                layoutProfile = EnterpriseInstallationLayout.DevelopmentE2ELayoutProfile,
            }));
    });

    private static byte[] CreateRuntimeZip(string releaseId)
    {
        var node = $"node-{releaseId}";
        var bin = $"bin-{releaseId}";
        var dependency = $"dependency-{releaseId}";
        return CreateZip(archive =>
        {
            WriteEntry(archive, "node.exe", node);
            WriteEntry(archive, "node_modules/@deepseek-ai/dsh/lib/bin.js", bin);
            WriteEntry(archive, "node_modules/dependency.js", dependency);
            WriteEntry(
                archive,
                EnterpriseRuntimeFileManifest.FileName,
                $"{Hash(Encoding.UTF8.GetBytes(node))}  node.exe\n" +
                $"{Hash(Encoding.UTF8.GetBytes(bin))}  node_modules/@deepseek-ai/dsh/lib/bin.js\n" +
                $"{Hash(Encoding.UTF8.GetBytes(dependency))}  node_modules/dependency.js\n");
        });
    }

    private const string PluginSkillContents =
        "---\nname: mail-manager\ndescription: Managed mail helper.\n---\n";

    private static byte[] CreatePluginZip(
        string launcherReleaseId,
        string runtimeReleaseId,
        long generation,
        bool revoked = false,
        bool markSkillAsReparsePoint = false,
        IReadOnlyList<string>? compatibleLauncherReleaseIds = null,
        IReadOnlyList<string>? compatibleRuntimeReleaseIds = null) => CreateZip(archive =>
    {
        WriteEntry(
            archive,
            "plugin-policy.json",
            CreatePluginPolicyJson(
                launcherReleaseId,
                runtimeReleaseId,
                generation,
                revoked,
                compatibleLauncherReleaseIds,
                compatibleRuntimeReleaseIds));
        var skill = WriteEntry(
            archive,
            "skills/mail-manager/SKILL.md",
            PluginSkillContents);
        if (markSkillAsReparsePoint)
        {
            skill.ExternalAttributes = (int)FileAttributes.ReparsePoint;
        }
    });

    private static byte[] CreatePluginZipRaw(string policyJson) => CreateZip(archive =>
    {
        WriteEntry(archive, "plugin-policy.json", policyJson);
        WriteEntry(
            archive,
            "skills/mail-manager/SKILL.md",
            PluginSkillContents);
    });

    private static string CreatePluginPolicyJson(
        string launcherReleaseId,
        string runtimeReleaseId,
        long generation,
        bool revoked = false,
        IReadOnlyList<string>? compatibleLauncherReleaseIds = null,
        IReadOnlyList<string>? compatibleRuntimeReleaseIds = null) =>
        JsonSerializer.Serialize(new
        {
            schemaVersion = 1,
            policyId = PluginPolicyId,
            generation,
            skillsRoot = "skills",
            skillPacks = new[]
            {
                new
                {
                    skillId = "mail-manager",
                    version = "1.0.0",
                    root = "skills/mail-manager",
                    files = new[]
                    {
                        new
                        {
                            path = "skills/mail-manager/SKILL.md",
                            sha256 = Hash(Encoding.UTF8.GetBytes(PluginSkillContents)),
                            sizeBytes = Encoding.UTF8.GetByteCount(PluginSkillContents),
                        },
                    },
                },
            },
            compatibility = new
            {
                launcherReleaseIds = compatibleLauncherReleaseIds
                    ?? [launcherReleaseId],
                runtimeReleaseIds = compatibleRuntimeReleaseIds
                    ?? [runtimeReleaseId],
            },
            revoked,
            critical = true,
        });

    private static byte[] CreateZip(Action<ZipArchive> write)
    {
        using var stream = new MemoryStream();
        using (var archive = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: true))
        {
            write(archive);
        }
        return stream.ToArray();
    }

    private static ZipArchiveEntry WriteEntry(
        ZipArchive archive,
        string path,
        string content)
    {
        var entry = archive.CreateEntry(path, CompressionLevel.NoCompression);
        using var writer = new StreamWriter(
            entry.Open(),
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        writer.Write(content);
        return entry;
    }

    private static string Hash(byte[] bytes) =>
        Convert.ToHexStringLower(SHA256.HashData(bytes));

    private static void AssertBytesEqual(byte[] expected, byte[] actual, string path)
    {
        if (!expected.AsSpan().SequenceEqual(actual))
        {
            throw new InvalidOperationException($"Expected file to remain byte-identical: {path}");
        }
    }

    private static string Base64Url(ReadOnlySpan<byte> bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static string NewDirectory(string prefix)
    {
        var path = Path.Combine(TempRoot, $"{prefix}-{Guid.NewGuid():N}");
        Directory.CreateDirectory(path);
        return path;
    }

    private static void AssertTrue(bool value)
    {
        if (!value) throw new InvalidOperationException("Expected true.");
    }
    private static void AssertFalse(bool value) => AssertTrue(!value);
    private static void AssertEqual<T>(T expected, T actual)
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
            throw new InvalidOperationException($"Expected {expected}, actual {actual}.");
    }
    private static void AssertThrows<T>(Action action) where T : Exception
    {
        try { action(); } catch (T) { return; }
        throw new InvalidOperationException($"Expected {typeof(T).Name}.");
    }
    private static async Task AssertThrowsAsync<T>(Func<Task> action) where T : Exception
    {
        try { await action().ConfigureAwait(false); } catch (T) { return; }
        throw new InvalidOperationException($"Expected {typeof(T).Name}.");
    }
}
