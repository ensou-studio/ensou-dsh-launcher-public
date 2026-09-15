using System.Diagnostics;
using System.Collections.Concurrent;
using System.ComponentModel;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Win32.SafeHandles;
using Ensou.Dsh.Contracts;
using Ensou.Dsh.Enterprise.Client;
using Ensou.Dsh.Enterprise.Contracts;
using Ensou.Dsh.Host;
using Ensou.Dsh.UpdateEngine;

namespace Ensou.Dsh.CoreTests;

internal static partial class Program
{
    private const uint ProcessQueryLimitedInformation = 0x00001000;
    private const uint ProcessSynchronize = 0x00100000;
    private const uint WaitObject0 = 0x00000000;
    private const uint WaitTimeout = 0x00000102;
    private const uint WaitFailed = 0xFFFFFFFF;
    private const string LauncherRestartParentProbe =
        "--launcher-restart-parent-probe";
    private const string LauncherRestartChildProbe =
        "--launcher-restart-child-probe";
    private const string LauncherRestartForwarderProbe =
        "--launcher-restart-forwarder-probe";
    private const string LauncherRestartExitedForwarderProbe =
        "--launcher-restart-exited-forwarder-probe";
    private const string LauncherRestartOrphanChildProbe =
        "--launcher-restart-orphan-child-probe";
    private const string SuspendedHostRootProbe =
        "--suspended-host-root-probe";
    private const string SuspendedHostChildProbe =
        "--suspended-host-child-probe";
    private const string BindingSessionId = "01234567-89ab-cdef-0123-456789abcdef";
    private const string BindingInstallId = "fedcba98-7654-3210-fedc-ba9876543210";
    private const string BindingId = "22222222-3333-4444-8555-666666666666";
    private const string BindingThumbprintVector =
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
    private const string BindingChallengeVector =
        "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8";
    private const string BindingGrantVector =
        "QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8";
    private const string BindingIdempotencyKey =
        "YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn8";
    private const string RefreshTokenVector =
        "gIGCg4SFhoeIiYqLjI2Oj5CRkpOUlZaXmJmam5ydnp8";
    private const string QrNonceVector = BindingChallengeVector;
    private const string QrPollSecretVector = BindingThumbprintVector;
    private const string QrDeviceDisplayName = "PILOT-DESKTOP workstation";
    private const string QrConfirmationCode = "7K9M2Q";
    private const string ActivationCodeVector =
        "oKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr8";

    private static readonly string TempRoot = Path.Combine(
        Path.GetTempPath(),
        "ensou-dsh-core-tests",
        Guid.NewGuid().ToString("N"));

    public static async Task<int> Main(string[] args)
    {
        if (args is [LauncherRestartOrphanChildProbe, var orphanCompletionEventName])
        {
            using var completion = EventWaitHandle.OpenExisting(
                orphanCompletionEventName);
            return completion.WaitOne(TimeSpan.FromSeconds(30)) ? 0 : 41;
        }
        if (args is
            [LauncherRestartExitedForwarderProbe, var orphanMarkerPath, var orphanCompletionEvent])
        {
            var childStart = new ProcessStartInfo
            {
                FileName = Environment.ProcessPath
                    ?? throw new InvalidOperationException(
                        "CoreTests process path is unavailable."),
                WorkingDirectory = AppContext.BaseDirectory,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            AddEntryAssemblyArgumentIfRequired(childStart);
            childStart.ArgumentList.Add(LauncherRestartOrphanChildProbe);
            childStart.ArgumentList.Add(orphanCompletionEvent);
            using var child = Process.Start(childStart);
            if (child is null)
            {
                return 42;
            }
            File.WriteAllText(
                orphanMarkerPath,
                child.Id.ToString(CultureInfo.InvariantCulture));
            return 0;
        }
        if (args is
            [LauncherRestartParentProbe, var mode, var mutexName, var markerPath, var completionEventName])
        {
            return await RunLauncherRestartParentProbeAsync(
                mode,
                mutexName,
                markerPath,
                completionEventName);
        }
        if (args is [SuspendedHostChildProbe, var suspendedChildMarker])
        {
            File.WriteAllText(suspendedChildMarker, "child-ran");
            return 0;
        }
        if (args is
            [
                SuspendedHostRootProbe,
                var suspendedRootMarker,
                var suspendedDescendantMarker,
                var inheritedSentinelText,
            ])
        {
            var inheritedSentinel = new IntPtr(long.Parse(
                inheritedSentinelText,
                CultureInfo.InvariantCulture));
            File.WriteAllText(
                suspendedRootMarker,
                SetEvent(inheritedSentinel) ? "inherited" : "not-inherited");
            Console.Out.WriteLine("suspended-host-stdout");
            Console.Error.WriteLine("suspended-host-stderr");
            var childStart = new ProcessStartInfo
            {
                FileName = Environment.ProcessPath!,
                WorkingDirectory = AppContext.BaseDirectory,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            AddEntryAssemblyArgumentIfRequired(childStart);
            childStart.ArgumentList.Add(SuspendedHostChildProbe);
            childStart.ArgumentList.Add(suspendedDescendantMarker);
            using var child = Process.Start(childStart);
            if (child is null)
            {
                return 51;
            }
            child.WaitForExit();
            return 0;
        }
        if (args is
            [
                LauncherRestartForwarderProbe,
                var forwarderMode,
                var forwarderMutexName,
                var forwarderMarkerPath,
                var forwarderCompletionEventName,
                .. var forwarderHandoffArguments
            ])
        {
            return RunLauncherRestartForwarderProbe(
                forwarderMode,
                forwarderMutexName,
                forwarderMarkerPath,
                forwarderCompletionEventName,
                forwarderHandoffArguments);
        }
        if (args is
            [
                LauncherRestartChildProbe,
                var childMode,
                var childMutexName,
                var childMarkerPath,
                var childCompletionEventName,
                .. var handoffArguments
            ])
        {
            var exitMarkerPath = $"{childMarkerPath}.exit";
            try
            {
                var exitCode = RunLauncherRestartChildProbe(
                    childMode,
                    childMutexName,
                    childMarkerPath,
                    childCompletionEventName,
                    handoffArguments);
                TryWriteLauncherProbeMarker(
                    exitMarkerPath,
                    exitCode.ToString(CultureInfo.InvariantCulture));
                return exitCode;
            }
            catch (OperationCanceledException)
            {
                TryWriteLauncherProbeMarker(exitMarkerPath, "30");
                return 30;
            }
            catch
            {
                TryWriteLauncherProbeMarker(exitMarkerPath, "31");
                return 31;
            }
        }
        if (args.Length != 0
            && (args.Length != 2
                || !string.Equals(args[0], "--filter", StringComparison.Ordinal)
                || string.IsNullOrWhiteSpace(args[1])))
        {
            return 2;
        }
        var tests = new (string Name, Func<Task> Run)[]
        {
            ("signed manifest round-trip", SignedManifestRoundTripAsync),
            ("canonical manifest vector", CanonicalManifestVectorAsync),
            ("manifest tamper rejection", ManifestTamperRejectedAsync),
            ("strict manifest parsing", StrictManifestParsingAsync),
            ("SHA-256 verification", Sha256VerificationAsync),
            ("HTTP range resume", HttpRangeResumeAsync),
            ("range fallback to full response", RangeFallbackAsync),
            ("release state comparison", ReleaseStateComparisonAsync),
            ("enterprise ready lease", EnterpriseReadyLeaseAsync),
            ("enterprise explicit outage permits local offline grace", EnterpriseOfflineGraceAsync),
            ("enterprise unknown connectivity fails closed", EnterpriseUnknownConnectivityAsync),
            ("enterprise unbound client requires QR", EnterpriseQrRequiredAsync),
            ("enterprise unknown bound state fails closed", EnterpriseUnknownBoundStateAsync),
            ("enterprise unknown API state fails closed without reset", EnterpriseUnknownApiStateAsync),
            ("enterprise unknown denial combinations fail closed without reset", EnterpriseUnknownResetCombinationsAsync),
            ("enterprise invalid enum states fail closed without reset", EnterpriseInvalidEnumStatesAsync),
            ("enterprise untrusted clock fails closed", EnterpriseUntrustedClockAsync),
            ("enterprise non-UTC clock fails closed", EnterpriseNonUtcClockAsync),
            ("enterprise clock rollback fails closed", EnterpriseClockRollbackAsync),
            ("enterprise expired lease fails closed", EnterpriseExpiredLeaseAsync),
            ("enterprise employee suspension preserves enrollment", EnterpriseEmployeeSuspensionAsync),
            ("enterprise device revocation requires security reset", EnterpriseDeviceRevocationAsync),
            ("enterprise API suspension keeps device binding", EnterpriseApiSuspensionAsync),
            ("enterprise critical update blocks start", EnterpriseCriticalUpdateAsync),
            ("enterprise invalid lease quarantines", EnterpriseInvalidLeaseAsync),
            ("enterprise epoch mismatch resets stale credentials", EnterpriseEpochMismatchAsync),
            ("enterprise API suspension wins over expired lease", EnterpriseApiSuspensionWithExpiredLeaseAsync),
            ("enterprise reset scopes cannot name user data", EnterpriseResetScopeBoundaryAsync),
            ("enterprise error codes are unique stable tokens", EnterpriseErrorCodeRegistryAsync),
            ("enterprise product paths are isolated", EnterpriseProductPathsAsync),
            ("enterprise workspace root is isolated and shell-opened directly", EnterpriseWorkspaceRootAsync),
            ("enterprise managed path rejects prefix collision", EnterpriseManagedPathPrefixAsync),
            ("enterprise managed reset excludes user data", EnterpriseManagedResetPlanAsync),
            ("enterprise security reset is a fixed allowlist", EnterpriseSecurityResetPlanAsync),
            ("enterprise managed artifact rejects unknown value", EnterpriseArtifactRejectsUnknownValueAsync),
            ("enterprise managed roots reject unsafe forms", EnterpriseRootsRejectUnsafeFormsAsync),
            ("enterprise reset rejects unknown scope", EnterpriseResetRejectsUnknownScopeAsync),
            ("enterprise startup gate requires enrollment", EnterpriseStartupGateRequiresEnrollmentAsync),
            ("enterprise session denies every host path before enrollment", EnterpriseSessionDeniesHostAsync),
            ("enterprise session allows ready host", EnterpriseSessionAllowsReadyHostAsync),
            ("enterprise session refuses unavailable WebUI", EnterpriseSessionRefusesUnavailableWebUiAsync),
            ("enterprise session stops host on suspension", EnterpriseSessionStopsOnSuspensionAsync),
            ("enterprise session stops host before managed reset", EnterpriseSessionStopsBeforeManagedResetAsync),
            ("enterprise session stops host before security reset", EnterpriseSessionStopsBeforeSecurityResetAsync),
            ("enterprise session invalid denial never resets", EnterpriseSessionInvalidDenialDoesNotResetAsync),
            ("enterprise session reset failure stays locked and retries", EnterpriseSessionResetFailureStaysLockedAndRetriesAsync),
            ("enterprise pending reset upgrades to stronger security decision", EnterprisePendingResetUpgradesAsync),
            ("enterprise completed reset barrier survives restart until online ready", EnterpriseCompletedResetBarrierSurvivesRestartAsync),
            ("enterprise incomplete reset barrier retries after restart", EnterpriseIncompleteResetBarrierRetriesAfterRestartAsync),
            ("enterprise session stops host on lease expiry", EnterpriseSessionStopsOnLeaseExpiryAsync),
            ("enterprise update-only lock preserves process but never grants access", EnterpriseUpdateOnlyLockPreservesProcessAsync),
            ("enterprise update-only lock retains monotonic expiry enforcement", EnterpriseUpdateOnlyLockExpiresAsync),
            ("enterprise update-only lock enforces later security failures and stop retry", EnterpriseUpdateOnlyLockSecurityRetryAsync),
            ("enterprise session stops host when clock crosses lease expiry", EnterpriseSessionStopsWhenClockExpiresLeaseAsync),
            ("enterprise session rechecks lease after host startup", EnterpriseSessionRechecksLeaseAfterStartupAsync),
            ("enterprise session rechecks lease after WebUI health probe", EnterpriseSessionRechecksLeaseAfterWebUiHealthAsync),
            ("enterprise session health cannot outlive lease", EnterpriseSessionHealthCannotOutliveLeaseAsync),
            ("enterprise monotonic lease deadline survives wall-clock rollback", EnterpriseMonotonicLeaseSurvivesWallClockRollbackAsync),
            ("enterprise session retries failed owned-host stop", EnterpriseSessionRetriesFailedStopAsync),
            ("enterprise installation identity persists", EnterpriseInstallationIdentityPersistsAsync),
            ("enterprise installation identity corruption fails closed", EnterpriseInstallationIdentityCorruptionAsync),
            ("enterprise DPAPI artifact round-trip", EnterpriseProtectedArtifactRoundTripAsync),
            ("enterprise DPAPI store rejects non-credential artifacts", EnterpriseProtectedArtifactBoundaryAsync),
            ("enterprise trusted time is protected, fail-closed, and future-bounded", EnterpriseTrustedTimeProtectionAsync),
            ("enterprise CNG device proof is non-exportable and signs", EnterpriseDeviceProofKeyAsync),
            ("enterprise CNG rejects archivable existing key", EnterpriseDeviceProofRejectsArchivableKeyAsync),
            ("enterprise local state rejects parent junction", EnterpriseLocalStateRejectsParentJunctionAsync),
            ("enterprise reset executor preserves installation and user data", EnterpriseResetExecutorBoundaryAsync),
            ("enterprise reset continues after locked artifact", EnterpriseResetContinuesAfterLockedArtifactAsync),
            ("enterprise wire states round-trip", EnterpriseWireStatesAsync),
            ("enterprise DPoP proof is device-bound", EnterpriseDpopProofAsync),
            ("enterprise DPoP proof omits optional nonce and stays unique", EnterpriseDpopOptionalNonceAsync),
            ("enterprise binding payload is canonical and device-signed", EnterpriseBindingPayloadAsync),
            ("enterprise binding rejects noncanonical wire values", EnterpriseBindingCanonicalInputsRejectedAsync),
            ("enterprise binding HTTP completion is strict and device-bound", EnterpriseBindingHttpClientAsync),
            ("enterprise binding HTTP redirect is rejected", EnterpriseBindingRedirectRejectedAsync),
            ("enterprise binding strict JSON rejects additions", EnterpriseBindingStrictJsonAsync),
            ("enterprise binding oversized response is rejected", EnterpriseBindingOversizedResponseRejectedAsync),
            ("enterprise binding malformed lease envelope is rejected", EnterpriseBindingMalformedLeaseRejectedAsync),
            ("enterprise authorization lease fixture verifies ready", EnterpriseAuthorizationLeaseFixtureAsync),
            ("enterprise authorization lease tampering is rejected", EnterpriseAuthorizationLeaseTamperingAsync),
            ("enterprise pending binding transaction preserves exact body", EnterprisePendingBindingTransactionRoundTripAsync),
            ("enterprise refresh HTTP request is exact and device-bound", EnterpriseRefreshHttpClientAsync),
            ("enterprise refresh rejects untrusted reset contract", EnterpriseRefreshRejectsUntrustedResetContractAsync),
            ("enterprise pending refresh transaction preserves exact body", EnterprisePendingRefreshTransactionRoundTripAsync),
            ("enterprise restart requires verified refresh after idle or trusted-time deletion", EnterpriseCleanRestartRefreshAsync),
            ("enterprise in-place refresh preserves active session until verified rotation", EnterpriseRefreshInPlaceAsync),
            ("enterprise gateway authorization is origin-gated and memory-only", EnterpriseGatewayAuthorizationAsync),
            ("enterprise loopback proxy streams only exact allowed routes", EnterpriseLoopbackProxyAsync),
            ("enterprise loopback parser rejects ambiguous requests", EnterpriseLoopbackParserRejectsAmbiguityAsync),
            ("enterprise loopback header deadline releases saturated connections", EnterpriseLoopbackHeaderDeadlineReleasesConnectionsAsync),
            ("DSH controlled environment rejects arbitrary provider keys", DshControlledEnvironmentAsync),
            ("personal Launcher restart performs a real two-process singleton handoff", PersonalLauncherRestartBoundaryAsync),
            ("Enterprise Launcher restart performs a scoped two-process singleton handoff", EnterpriseLauncherRestartBoundaryAsync),
            ("personal Launcher restart retains the exact rejected receiver handle", PersonalLauncherRestartRetainsRejectedReceiverHandleAsync),
            ("enterprise managed Host fixes argv cwd environment and hidden launch", DshEnterpriseManagedHostBoundaryAsync),
            ("enterprise direct-local Host preserves managed boundaries without a provider key", DshEnterpriseDirectLocalHostBoundaryAsync),
            ("Personal managed-update Host requires an atomic writer before process admission", DshPersonalManagedUpdateHostBoundaryAsync),
            ("DSH native suspended Host admits before resume with exact handle pipes", DshNativeSuspendedHostAdmissionAsync),
            ("DSH runtime Web auth metadata is explicit strict and legacy compatible", DshRuntimeWebAuthMetadataContractAsync),
            ("DSH browser launch announcement is strict and redacted", DshBrowserLaunchAnnouncementContractAsync),
            ("DSH browser token exchange is strict and memory-only", DshBrowserTokenExchangeContractAsync),
            ("DSH browser shell failure never exposes its launch token", DshBrowserShellFailureRedactionAsync),
            ("DSH WebUI health accepts only official and exact source-build titles", DshWebUiHealthTitlesAsync),
            ("DSH browser-cookie candidate health uses authenticated alpha RPC", DshBrowserCookieCandidateHealthAsync),
            ("DSH browser authentication startup failure stops the exact owned process", DshBrowserAuthStartupFailureStopsOwnedProcessAsync),
            ("DSH faulted output pump still releases every owned process resource", DshFaultedOutputPumpStillReleasesOwnedProcessAsync),
            ("DSH already-exited stop still releases every owned process resource", DshAlreadyExitedStopStillReleasesOwnedProcessAsync),
            ("DSH exited owned process is released before an unrelated healthy port", DshExitedOwnedProcessCleansBeforeHealthAsync),
            ("DSH unassigned process containment retains exact handle until exit is confirmed", DshUnassignedProcessContainmentTests.RunAsync),
            ("DSH runtime launch admission binds files process image and owned health", DshRuntimeAdmissionTests.RunAsync),
            ("DSH health binds exact IPv4 loopback listener owner", DshLoopbackListenerOwnershipTests.RunAsync),
            ("DSH job closes before output pumps are awaited", DshJobClosesBeforeOutputPumpsAsync),
            ("DSH delayed old exit callback cannot close a newer job", DshDelayedOldExitCallbackCannotCloseNewJobAsync),
            ("DSH exit callback retains timed-out job for synchronous retry", DshExitCallbackRetainsTimedOutJobAsync),
            ("DSH exact exit callback can race shutdown without leaking resources", DshExactExitCallbackRacesShutdownAsync),
            ("managed update exact exit defers leased channel", ManagedUpdateExactExitDefersLeasedChannelAsync),
            ("managed update normal exit closes unleased channel", ManagedUpdateNormalExitClosesUnleasedChannelAsync),
            ("managed update old exit cannot retain or clear newer channel", ManagedUpdateOldExitCannotRetainOrClearNewChannelAsync),
            ("managed update lease release requires exact process", ManagedUpdateLeaseReleaseRequiresExactProcessAsync),
            ("managed update priority preempts and orders new waits", ManagedUpdatePriorityPreemptsAndOrdersNewWaitsAsync),
            ("managed update ordinary cancellation is not priority", ManagedUpdateOrdinaryCancellationIsNotPriorityAsync),
            ("managed update retired lease cannot clear successor", ManagedUpdateRetiredLeaseCannotClearSuccessorAsync),
            ("DSH candidate install health probes exact read-only session API", DshCandidateInstallHealthSuccessAsync),
            ("DSH candidate install health rejects API failures and malformed responses", DshCandidateInstallHealthRejectsFailuresAsync),
            ("DSH candidate install health propagates caller cancellation", DshCandidateInstallHealthCancellationAsync),
            ("DSH candidate completion stops only the exact healthy owned process", DshCandidateInstallHealthControlledStopAsync),
            ("DSH candidate completion rejects a different process identity", DshCandidateInstallHealthWrongProcessAsync),
            ("DSH candidate completion rejects health after the candidate exits", DshCandidateInstallHealthRejectsProcessTakeoverAsync),
            ("DSH candidate completion cancellation releases the process gate", DshCandidateInstallHealthCompletionCancellationAsync),
            ("enterprise expired committed binding replay recovers credentials but stays locked", EnterpriseExpiredCommittedBindingReplayAsync),
            ("enterprise first binding update gate has no Ready window", EnterpriseFirstBindingUpdateGateAsync),
            ("enterprise access token vault installs expires and clears", EnterpriseAccessTokenVaultAsync),
            ("enterprise partial binding projections require recovery", EnterprisePartialBindingProjectionsRequireRecoveryAsync),
            ("enterprise enrollment HTTP status and error scope remain exact", EnterpriseEnrollmentHttpContractAsync),
            ("enterprise QR device confirmation protocol remains exact", EnterpriseQrDeviceConfirmationProtocolAsync),
            ("enterprise activation code protocol remains exact", EnterpriseActivationCodeProtocolAsync),
            ("enterprise QR HTTP create and poll", EnterpriseQrHttpClientAsync),
            ("enterprise activation claim is strict and device-bound", EnterpriseActivationClaimHttpClientAsync),
            ("enterprise activation claim response must be empty 204", EnterpriseActivationClaimStrictResponseAsync),
            ("enterprise QR terminal tuples remain exact", EnterpriseQrTerminalContractAsync),
            ("enterprise QR approved requires a valid binding challenge", EnterpriseQrBindingChallengeRequiredAsync),
            ("enterprise QR rejects overlong session", EnterpriseQrLifetimeRejectedAsync),
            ("enterprise QR local validity diagnostics preserve strict limits", EnterpriseQrValidityDiagnosticsAsync),
            ("enterprise QR HTTP redirect is rejected", EnterpriseQrRedirectRejectedAsync),
            ("enterprise QR strict JSON rejects additions", EnterpriseQrStrictJsonAsync),
            ("enterprise QR coordinator normalizes and reports device confirmation", EnterpriseQrCoordinatorProgressAsync),
            ("enterprise QR coordinator approves identity without Host", EnterpriseQrCoordinatorApprovedAsync),
            ("enterprise QR coordinator denial restores closed state", EnterpriseQrCoordinatorDeniedAsync),
            ("enterprise QR coordinator preserves account lock", EnterpriseQrCoordinatorAccountLockedAsync),
            ("enterprise QR coordinator local expiry remains retryable", EnterpriseQrCoordinatorLocalExpiryAsync),
            ("enterprise QR coordinator failure restores closed state", EnterpriseQrCoordinatorFailureAsync),
            ("enterprise WeCom coordinator opens browser and never claims activation", EnterpriseWeComCoordinatorAsync),
            ("enterprise enrollment method switch preserves recovery journal", EnterpriseEnrollmentMethodSwitchPreservesJournalAsync),
            ("enterprise expired v1 journal permits WeCom enrollment", EnterpriseExpiredV1JournalPermitsWeComAsync),
            ("enterprise activation claim lost response safely recovers by poll", EnterpriseActivationClaimLostResponseRecoveryAsync),
            ("enterprise committed activation resumes after poll outage and restart", EnterpriseCommittedActivationResumeAfterRestartAsync),
            ("enterprise activation claim timeout after send recovers by poll", EnterpriseActivationClaimTimeoutRecoveryAsync),
            ("enterprise resumed terminal enrollment deletes its journal", EnterpriseResumedTerminalEnrollmentDeletesJournalAsync),
            ("enterprise enrollment journal rejects install and device mismatch", EnterpriseEnrollmentJournalRejectsIdentityMismatchAsync),
        };

        var selectedTests = args is ["--filter", var filter]
            ? tests.Where(test => test.Name.Contains(filter, StringComparison.OrdinalIgnoreCase)).ToArray()
            : tests;
        if (selectedTests.Length == 0)
        {
            Console.Error.WriteLine("No tests matched the requested filter.");
            return 2;
        }

        Directory.CreateDirectory(TempRoot);
        var failures = 0;
        try
        {
            foreach (var test in selectedTests)
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

        Console.WriteLine($"{selectedTests.Length - failures}/{selectedTests.Length} self-checks passed.");
        return failures == 0 ? 0 : 1;
    }

    private static Task SignedManifestRoundTripAsync()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signedJson = ReleaseManifestSignature.CreateSignedJson(CreateUnsignedManifest(), "release-2026", key);
        var verified = ReleaseManifestSignature.ParseAndVerify(signedJson, key, "release-2026");

        AssertEqual("managed-v2026.08.23.1", verified.Manifest.ReleaseId);
        AssertEqual("release-2026", verified.KeyId);
        AssertEqual(64, verified.CanonicalPayloadSha256.Length);

        var canonical = Encoding.UTF8.GetString(
            ReleaseManifestJson.CreateCanonicalPayload(verified.Manifest));
        AssertFalse(canonical.Contains("signature", StringComparison.Ordinal));
        AssertTrue(canonical.StartsWith(
            "{\"schemaVersion\":1,\"releaseId\":\"managed-v2026.08.23.1\",\"channel\":\"stable\"",
            StringComparison.Ordinal));
        return Task.CompletedTask;
    }

    private static Task CanonicalManifestVectorAsync()
    {
        var vectorPath = Path.Combine(
            AppContext.BaseDirectory,
            "Fixtures",
            "canonical-payload-v1.vector.json");
        using var vector = JsonDocument.Parse(File.ReadAllBytes(vectorPath));
        var root = vector.RootElement;
        var expectedPayload = Convert.FromBase64String(
            root.GetProperty("canonicalPayloadUtf8Base64").GetString()!);
        var actualPayload = ReleaseManifestJson.CreateCanonicalPayload(CreateUnsignedManifest());
        AssertSequenceEqual(expectedPayload, actualPayload);

        var expectedDigest = root.GetProperty("canonicalPayloadSha256").GetString()!;
        AssertEqual(expectedDigest, Convert.ToHexStringLower(SHA256.HashData(actualPayload)));

        using var publicKey = ECDsa.Create();
        publicKey.ImportSubjectPublicKeyInfo(
            Convert.FromBase64String(root.GetProperty("publicKeySpkiBase64").GetString()!),
            out var bytesRead);
        AssertTrue(bytesRead > 0);
        var signature = DecodeBase64Url(
            root.GetProperty("signatureIeeeP1363Base64Url").GetString()!);
        AssertTrue(publicKey.VerifyData(
            actualPayload,
            signature,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        return Task.CompletedTask;
    }

    private static async Task ManifestTamperRejectedAsync()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signed = ReleaseManifestSignature.CreateSignedManifest(CreateUnsignedManifest(), "release-2026", key);
        var changedHash = (signed.Artifact.Sha256[0] == '0' ? "1" : "0") + signed.Artifact.Sha256[1..];
        var tampered = signed with
        {
            Artifact = signed.Artifact with { Sha256 = changedHash },
        };
        var tamperedJson = ReleaseManifestJson.SerializeSigned(tampered);

        await AssertThrowsAsync<ManifestSignatureException>(
            () => Task.Run(() => ReleaseManifestSignature.ParseAndVerify(tamperedJson, key)));
    }

    private static async Task StrictManifestParsingAsync()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var json = Encoding.UTF8.GetString(
            ReleaseManifestSignature.CreateSignedJson(CreateUnsignedManifest(), "release-2026", key));
        var unknownFieldJson = Encoding.UTF8.GetBytes(json[..^1] + ",\"unexpected\":true}");

        await AssertThrowsAsync<ManifestFormatException>(
            () => Task.Run(() => ReleaseManifestJson.ParseAndValidate(unknownFieldJson)));

        var duplicateJson = Encoding.UTF8.GetBytes(
            json.Replace(
                "\"schemaVersion\":1",
                "\"schemaVersion\":1,\"schemaVersion\":1",
                StringComparison.Ordinal));
        await AssertThrowsAsync<ManifestFormatException>(
            () => Task.Run(() => ReleaseManifestJson.ParseAndValidate(duplicateJson)));

        var shortTimestampJson = Encoding.UTF8.GetBytes(
            json.Replace("2026-08-23T00:00:00.0000000Z", "2026-08-23T00:00:00Z", StringComparison.Ordinal));
        await AssertThrowsAsync<ManifestFormatException>(
            () => Task.Run(() => ReleaseManifestJson.ParseAndValidate(shortTimestampJson)));

        var unicodeUrlManifest = CreateUnsignedManifest() with
        {
            Artifact = CreateUnsignedManifest().Artifact with
            {
                Url = "https://updates.example.test/发布.zip",
            },
        };
        await AssertThrowsAsync<ManifestValidationException>(
            () => Task.Run(() => ReleaseManifestJson.CreateCanonicalPayload(unicodeUrlManifest)));
    }

    private static async Task Sha256VerificationAsync()
    {
        var path = NewTempPath("hash.bin");
        var bytes = Encoding.UTF8.GetBytes("signed update artifact");
        await File.WriteAllBytesAsync(path, bytes).ConfigureAwait(false);
        var expected = Convert.ToHexStringLower(SHA256.HashData(bytes));

        var match = await Sha256Verifier.VerifyFileAsync(path, expected, bytes.Length).ConfigureAwait(false);
        AssertTrue(match.IsMatch);
        AssertEqual(expected, match.ActualSha256);

        var mismatch = await Sha256Verifier.VerifyFileAsync(
                path,
                new string('0', 64),
                bytes.Length)
            .ConfigureAwait(false);
        AssertFalse(mismatch.IsMatch);
    }

    private static async Task HttpRangeResumeAsync()
    {
        var payload = Encoding.UTF8.GetBytes("hello world");
        var partialPath = NewTempPath("resume.partial");
        await File.WriteAllBytesAsync(partialPath, payload[..6]).ConfigureAwait(false);

        using var client = new HttpClient(new DelegateHandler(request =>
        {
            var range = request.Headers.Range?.Ranges.Single()
                ?? throw new InvalidOperationException("Expected a range request.");
            AssertEqual(6L, range.From);
            AssertEqual<long?>(null, range.To);

            var response = new HttpResponseMessage(HttpStatusCode.PartialContent)
            {
                Content = new ByteArrayContent(payload[6..]),
            };
            response.Content.Headers.ContentRange = new ContentRangeHeaderValue(6, 10, payload.Length);
            return response;
        }));

        var downloader = new ResumableDownloader(client);
        var result = await downloader.DownloadAsync(
                new ResumableDownloadRequest(
                    new Uri("https://updates.example.test/runtime.zip"),
                    partialPath,
                    payload.Length))
            .ConfigureAwait(false);

        AssertEqual(ResumableDownloadStatus.Resumed, result.Status);
        AssertSequenceEqual(payload, await File.ReadAllBytesAsync(partialPath).ConfigureAwait(false));
    }

    private static async Task RangeFallbackAsync()
    {
        var payload = Encoding.UTF8.GetBytes("replacement payload");
        var partialPath = NewTempPath("fallback.partial");
        await File.WriteAllBytesAsync(partialPath, Encoding.UTF8.GetBytes("stale ")).ConfigureAwait(false);

        using var client = new HttpClient(new DelegateHandler(_ =>
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(payload),
            }));
        var downloader = new ResumableDownloader(client);
        var result = await downloader.DownloadAsync(
                new ResumableDownloadRequest(
                    new Uri("https://updates.example.test/runtime.zip"),
                    partialPath,
                    payload.Length))
            .ConfigureAwait(false);

        AssertEqual(ResumableDownloadStatus.Downloaded, result.Status);
        AssertSequenceEqual(payload, await File.ReadAllBytesAsync(partialPath).ConfigureAwait(false));
    }

    private static Task ReleaseStateComparisonAsync()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var target = ReleaseManifestSignature.CreateSignedManifest(CreateUnsignedManifest(), "release-2026", key);
        var state = new InstalledReleaseState
        {
            ReleaseId = "managed-v2026.08.20.1",
            LauncherVersion = "1.1.0",
            DshVersion = "0.1.0-rc.6",
            BootstrapperVersion = "1.0.0",
        };

        var update = ReleaseStateComparer.Compare(state, target);
        AssertEqual(ReleaseStateDisposition.UpdateAvailable, update.Disposition);
        AssertTrue(update.ShouldInstallTarget);

        var current = ReleaseStateComparer.Compare(
            state with
            {
                ReleaseId = target.ReleaseId,
                LauncherVersion = target.LauncherVersion,
                DshVersion = target.DshVersion,
            },
            target);
        AssertEqual(ReleaseStateDisposition.Current, current.Disposition);

        var oldBootstrapper = ReleaseStateComparer.Compare(
            state with { BootstrapperVersion = "0.9.0" },
            target);
        AssertEqual(ReleaseStateDisposition.BootstrapperUpdateRequired, oldBootstrapper.Disposition);

        var oldLauncher = ReleaseStateComparer.Compare(
            state with { LauncherVersion = "1.0.0" },
            target);
        AssertEqual(ReleaseStateDisposition.LauncherUpdateRequired, oldLauncher.Disposition);
        AssertTrue(!oldLauncher.ShouldInstallTarget);

        AssertTrue(ReleaseStateComparer.CompareVersionStrings("2026.08.2", "2026.8.1") > 0);
        AssertTrue(ReleaseStateComparer.CompareVersionStrings("0.1.0", "0.1.0-rc.7") > 0);
        return Task.CompletedTask;
    }

    private static Task EnterpriseReadyLeaseAsync()
    {
        var now = new DateTimeOffset(2026, 8, 24, 0, 0, 0, TimeSpan.Zero);
        var decision = EnterpriseAccessEvaluator.Evaluate(CreateReadyEnterpriseSnapshot(now), now);

        AssertEqual(EnterpriseClientState.Ready, decision.ClientState);
        AssertTrue(decision.MayStartHarness);
        AssertTrue(decision.MayCallManagedApi);
        AssertEqual(EnterpriseResetScope.None, decision.ResetScope);
        AssertEqual<string?>(null, decision.ErrorCode);
        return Task.CompletedTask;
    }

    private static Task EnterpriseOfflineGraceAsync()
    {
        var now = new DateTimeOffset(2026, 8, 24, 0, 0, 0, TimeSpan.Zero);
        var decision = EnterpriseAccessEvaluator.Evaluate(
            CreateReadyEnterpriseSnapshot(now) with
            {
                ControlPlane = ControlPlaneConnectivity.Unavailable,
            },
            now);

        AssertEqual(EnterpriseClientState.OfflineGrace, decision.ClientState);
        AssertTrue(decision.MayStartHarness);
        AssertFalse(decision.MayCallManagedApi);
        AssertEqual(EnterpriseResetScope.None, decision.ResetScope);
        AssertEqual(EnterpriseErrorCodes.ControlPlaneUnavailable, decision.ErrorCode);
        return Task.CompletedTask;
    }

    private static Task EnterpriseUnknownConnectivityAsync()
    {
        var now = new DateTimeOffset(2026, 8, 24, 0, 0, 0, TimeSpan.Zero);
        var decision = EnterpriseAccessEvaluator.Evaluate(
            CreateReadyEnterpriseSnapshot(now) with
            {
                ControlPlane = ControlPlaneConnectivity.Unknown,
            },
            now);

        AssertEqual(EnterpriseClientState.SecurityQuarantined, decision.ClientState);
        AssertFalse(decision.MayStartHarness);
        AssertFalse(decision.MayCallManagedApi);
        AssertEqual(EnterpriseErrorCodes.ControlPlaneUnavailable, decision.ErrorCode);
        return Task.CompletedTask;
    }

    private static Task EnterpriseQrRequiredAsync()
    {
        var now = new DateTimeOffset(2026, 8, 24, 0, 0, 0, TimeSpan.Zero);
        var decision = EnterpriseAccessEvaluator.Evaluate(
            CreateReadyEnterpriseSnapshot(now) with
            {
                Employee = EmployeeAuthorizationState.Unknown,
                Device = DeviceBindingState.Unbound,
                ApiAllocation = ApiAllocationState.Unknown,
                LeaseSignatureValid = false,
                AuthorizationEpochMatches = false,
                LeaseExpiresAtUtc = null,
            },
            now);

        AssertEqual(EnterpriseClientState.QrRequired, decision.ClientState);
        AssertFalse(decision.MayStartHarness);
        AssertEqual(EnterpriseResetScope.None, decision.ResetScope);
        return Task.CompletedTask;
    }

    private static Task EnterpriseUnknownBoundStateAsync()
    {
        var now = new DateTimeOffset(2026, 8, 24, 0, 0, 0, TimeSpan.Zero);
        var decision = EnterpriseAccessEvaluator.Evaluate(
            CreateReadyEnterpriseSnapshot(now) with
            {
                Employee = EmployeeAuthorizationState.Unknown,
            },
            now);

        AssertEqual(EnterpriseClientState.SecurityQuarantined, decision.ClientState);
        AssertFalse(decision.MayStartHarness);
        AssertEqual(EnterpriseErrorCodes.ControlPlaneUnavailable, decision.ErrorCode);
        return Task.CompletedTask;
    }

    private static Task EnterpriseUnknownApiStateAsync()
    {
        var now = new DateTimeOffset(2026, 8, 24, 0, 0, 0, TimeSpan.Zero);
        var decision = EnterpriseAccessEvaluator.Evaluate(
            CreateReadyEnterpriseSnapshot(now) with
            {
                ApiAllocation = ApiAllocationState.Unknown,
            },
            now);

        AssertEqual(EnterpriseClientState.SecurityQuarantined, decision.ClientState);
        AssertFalse(decision.MayStartHarness);
        AssertEqual(EnterpriseResetScope.None, decision.ResetScope);
        AssertEqual(EnterpriseErrorCodes.ControlPlaneUnavailable, decision.ErrorCode);
        return Task.CompletedTask;
    }

    private static Task EnterpriseInvalidEnumStatesAsync()
    {
        var now = new DateTimeOffset(2026, 8, 24, 0, 0, 0, TimeSpan.Zero);
        var invalidSnapshots = new[]
        {
            CreateReadyEnterpriseSnapshot(now) with
            {
                ApiAllocation = (ApiAllocationState)999,
            },
            CreateReadyEnterpriseSnapshot(now) with
            {
                Employee = EmployeeAuthorizationState.Suspended,
                Device = (DeviceBindingState)999,
            },
            CreateReadyEnterpriseSnapshot(now) with
            {
                Employee = EmployeeAuthorizationState.Revoked,
                Device = (DeviceBindingState)999,
            },
            CreateReadyEnterpriseSnapshot(now) with
            {
                Employee = (EmployeeAuthorizationState)999,
                Device = DeviceBindingState.QuarantinedCompromise,
            },
            CreateReadyEnterpriseSnapshot(now) with
            {
                Device = (DeviceBindingState)999,
            },
            CreateReadyEnterpriseSnapshot(now) with
            {
                ControlPlane = (ControlPlaneConnectivity)999,
            },
        };

        foreach (var snapshot in invalidSnapshots)
        {
            var decision = EnterpriseAccessEvaluator.Evaluate(snapshot, now);
            AssertEqual(EnterpriseClientState.SecurityQuarantined, decision.ClientState);
            AssertFalse(decision.MayStartHarness);
            AssertFalse(decision.MayCallManagedApi);
            AssertEqual(EnterpriseResetScope.None, decision.ResetScope);
            AssertEqual(EnterpriseErrorCodes.ControlPlaneUnavailable, decision.ErrorCode);
        }

        return Task.CompletedTask;
    }

    private static Task EnterpriseUnknownResetCombinationsAsync()
    {
        var now = new DateTimeOffset(2026, 8, 24, 0, 0, 0, TimeSpan.Zero);
        var unknownSnapshots = new[]
        {
            CreateReadyEnterpriseSnapshot(now) with
            {
                Employee = EmployeeAuthorizationState.Suspended,
                ApiAllocation = ApiAllocationState.Unknown,
            },
            CreateReadyEnterpriseSnapshot(now) with
            {
                Employee = EmployeeAuthorizationState.Revoked,
                ApiAllocation = ApiAllocationState.Unknown,
            },
            CreateReadyEnterpriseSnapshot(now) with
            {
                Device = DeviceBindingState.RevokedAdmin,
                ApiAllocation = ApiAllocationState.Unknown,
            },
        };

        foreach (var snapshot in unknownSnapshots)
        {
            var decision = EnterpriseAccessEvaluator.Evaluate(snapshot, now);
            AssertEqual(EnterpriseClientState.SecurityQuarantined, decision.ClientState);
            AssertFalse(decision.MayStartHarness);
            AssertFalse(decision.MayCallManagedApi);
            AssertEqual(EnterpriseResetScope.None, decision.ResetScope);
            AssertEqual(EnterpriseErrorCodes.ControlPlaneUnavailable, decision.ErrorCode);
        }

        return Task.CompletedTask;
    }

    private static Task EnterpriseUntrustedClockAsync()
    {
        var now = new DateTimeOffset(2026, 8, 24, 0, 0, 0, TimeSpan.Zero);
        var decision = EnterpriseAccessEvaluator.Evaluate(
            CreateReadyEnterpriseSnapshot(now) with
            {
                ClockTrusted = false,
            },
            now);

        AssertEqual(EnterpriseClientState.SecurityQuarantined, decision.ClientState);
        AssertFalse(decision.MayStartHarness);
        AssertEqual(EnterpriseErrorCodes.ClockUntrusted, decision.ErrorCode);
        return Task.CompletedTask;
    }

    private static Task EnterpriseClockRollbackAsync()
    {
        var now = new DateTimeOffset(2026, 8, 24, 0, 0, 0, TimeSpan.Zero);
        var decision = EnterpriseAccessEvaluator.Evaluate(
            CreateReadyEnterpriseSnapshot(now) with
            {
                TrustedTimeFloorUtc = now.AddMinutes(1),
            },
            now);

        AssertEqual(EnterpriseClientState.SecurityQuarantined, decision.ClientState);
        AssertFalse(decision.MayStartHarness);
        AssertEqual(EnterpriseErrorCodes.ClockRollbackDetected, decision.ErrorCode);
        return Task.CompletedTask;
    }

    private static Task EnterpriseNonUtcClockAsync()
    {
        var nowUtc = new DateTimeOffset(2026, 8, 24, 0, 0, 0, TimeSpan.Zero);
        var decision = EnterpriseAccessEvaluator.Evaluate(
            CreateReadyEnterpriseSnapshot(nowUtc),
            nowUtc.ToOffset(TimeSpan.FromHours(9)));

        AssertEqual(EnterpriseClientState.SecurityQuarantined, decision.ClientState);
        AssertFalse(decision.MayStartHarness);
        AssertEqual(EnterpriseErrorCodes.ClockUntrusted, decision.ErrorCode);
        return Task.CompletedTask;
    }

    private static Task EnterpriseExpiredLeaseAsync()
    {
        var now = new DateTimeOffset(2026, 8, 24, 0, 0, 0, TimeSpan.Zero);
        var decision = EnterpriseAccessEvaluator.Evaluate(
            CreateReadyEnterpriseSnapshot(now) with
            {
                LeaseExpiresAtUtc = now,
            },
            now);

        AssertEqual(EnterpriseClientState.LeaseExpiredLocked, decision.ClientState);
        AssertFalse(decision.MayStartHarness);
        AssertFalse(decision.MayCallManagedApi);
        AssertEqual(EnterpriseResetScope.None, decision.ResetScope);
        AssertEqual(EnterpriseErrorCodes.LeaseExpired, decision.ErrorCode);
        return Task.CompletedTask;
    }

    private static Task EnterpriseEmployeeSuspensionAsync()
    {
        var now = new DateTimeOffset(2026, 8, 24, 0, 0, 0, TimeSpan.Zero);
        var decision = EnterpriseAccessEvaluator.Evaluate(
            CreateReadyEnterpriseSnapshot(now) with
            {
                Employee = EmployeeAuthorizationState.Suspended,
            },
            now);

        AssertEqual(EnterpriseClientState.AccountLocked, decision.ClientState);
        AssertEqual(EnterpriseResetScope.ManagedConfig, decision.ResetScope);
        AssertEqual(EnterpriseErrorCodes.EmployeeSuspended, decision.ErrorCode);
        return Task.CompletedTask;
    }

    private static Task EnterpriseDeviceRevocationAsync()
    {
        var now = new DateTimeOffset(2026, 8, 24, 0, 0, 0, TimeSpan.Zero);
        var decision = EnterpriseAccessEvaluator.Evaluate(
            CreateReadyEnterpriseSnapshot(now) with
            {
                Device = DeviceBindingState.RevokedReplaced,
            },
            now);

        AssertEqual(EnterpriseClientState.DeviceRevokedResetRequired, decision.ClientState);
        AssertEqual(EnterpriseResetScope.SecurityCredentials, decision.ResetScope);
        AssertEqual(EnterpriseErrorCodes.DeviceBindingRevoked, decision.ErrorCode);
        return Task.CompletedTask;
    }

    private static Task EnterpriseApiSuspensionAsync()
    {
        var now = new DateTimeOffset(2026, 8, 24, 0, 0, 0, TimeSpan.Zero);
        var decision = EnterpriseAccessEvaluator.Evaluate(
            CreateReadyEnterpriseSnapshot(now) with
            {
                ApiAllocation = ApiAllocationState.Suspended,
            },
            now);

        AssertEqual(EnterpriseClientState.ApiDisabled, decision.ClientState);
        AssertEqual(EnterpriseResetScope.ManagedConfig, decision.ResetScope);
        AssertEqual(EnterpriseErrorCodes.ApiProfileDisabled, decision.ErrorCode);
        return Task.CompletedTask;
    }

    private static Task EnterpriseCriticalUpdateAsync()
    {
        var now = new DateTimeOffset(2026, 8, 24, 0, 0, 0, TimeSpan.Zero);
        var decision = EnterpriseAccessEvaluator.Evaluate(
            CreateReadyEnterpriseSnapshot(now) with
            {
                CriticalPluginUpdateRequired = true,
            },
            now);

        AssertEqual(EnterpriseClientState.UpdateRequired, decision.ClientState);
        AssertEqual(EnterpriseResetScope.None, decision.ResetScope);
        AssertEqual(EnterpriseErrorCodes.CriticalPluginUpdateRequired, decision.ErrorCode);

        decision = EnterpriseAccessEvaluator.Evaluate(
            CreateReadyEnterpriseSnapshot(now) with
            {
                PluginPolicyId = null,
                PluginPolicyGeneration = null,
                PluginPolicySha256 = null,
            },
            now);
        AssertEqual(EnterpriseClientState.UpdateRequired, decision.ClientState);
        AssertFalse(decision.MayStartHarness);
        AssertEqual(EnterpriseErrorCodes.CriticalPluginUpdateRequired, decision.ErrorCode);
        return Task.CompletedTask;
    }

    private static Task EnterpriseInvalidLeaseAsync()
    {
        var now = new DateTimeOffset(2026, 8, 24, 0, 0, 0, TimeSpan.Zero);
        var decision = EnterpriseAccessEvaluator.Evaluate(
            CreateReadyEnterpriseSnapshot(now) with
            {
                LeaseSignatureValid = false,
                CriticalPluginUpdateRequired = true,
            },
            now);

        AssertEqual(EnterpriseClientState.SecurityQuarantined, decision.ClientState);
        AssertEqual(EnterpriseResetScope.None, decision.ResetScope);
        AssertEqual(EnterpriseErrorCodes.LeaseSignatureInvalid, decision.ErrorCode);
        return Task.CompletedTask;
    }

    private static Task EnterpriseEpochMismatchAsync()
    {
        var now = new DateTimeOffset(2026, 8, 24, 0, 0, 0, TimeSpan.Zero);
        var decision = EnterpriseAccessEvaluator.Evaluate(
            CreateReadyEnterpriseSnapshot(now) with
            {
                AuthorizationEpochMatches = false,
                ApiAllocation = ApiAllocationState.Suspended,
                CriticalPluginUpdateRequired = true,
            },
            now);

        AssertEqual(EnterpriseClientState.SecurityQuarantined, decision.ClientState);
        AssertFalse(decision.MayStartHarness);
        AssertEqual(EnterpriseResetScope.SecurityCredentials, decision.ResetScope);
        AssertEqual(EnterpriseErrorCodes.AuthorizationEpochMismatch, decision.ErrorCode);
        return Task.CompletedTask;
    }

    private static Task EnterpriseApiSuspensionWithExpiredLeaseAsync()
    {
        var now = new DateTimeOffset(2026, 8, 24, 0, 0, 0, TimeSpan.Zero);
        var decision = EnterpriseAccessEvaluator.Evaluate(
            CreateReadyEnterpriseSnapshot(now) with
            {
                ApiAllocation = ApiAllocationState.Suspended,
                LeaseExpiresAtUtc = now,
            },
            now);

        AssertEqual(EnterpriseClientState.ApiDisabled, decision.ClientState);
        AssertFalse(decision.MayStartHarness);
        AssertEqual(EnterpriseResetScope.ManagedConfig, decision.ResetScope);
        AssertEqual(EnterpriseErrorCodes.ApiProfileDisabled, decision.ErrorCode);
        return Task.CompletedTask;
    }

    private static Task EnterpriseResetScopeBoundaryAsync()
    {
        var resetScopes = Enum.GetNames<EnterpriseResetScope>();
        AssertEqual(3, resetScopes.Length);
        AssertTrue(resetScopes.Contains(nameof(EnterpriseResetScope.None), StringComparer.Ordinal));
        AssertTrue(resetScopes.Contains(nameof(EnterpriseResetScope.ManagedConfig), StringComparer.Ordinal));
        AssertTrue(resetScopes.Contains(nameof(EnterpriseResetScope.SecurityCredentials), StringComparer.Ordinal));
        AssertFalse(resetScopes.Any(name => name.Contains("data", StringComparison.OrdinalIgnoreCase)));
        AssertFalse(resetScopes.Any(name => name.Contains("workspace", StringComparison.OrdinalIgnoreCase)));
        AssertFalse(resetScopes.Any(name => name.Contains("dsh", StringComparison.OrdinalIgnoreCase)));
        AssertEqual("NONE", EnterpriseResetScopeContract.ToWireValue(EnterpriseResetScope.None));
        AssertEqual(
            EnterpriseResetScope.ManagedConfig,
            EnterpriseResetScopeContract.ParseWireValue("MANAGED_CONFIG"));
        AssertEqual(
            EnterpriseResetScope.SecurityCredentials,
            EnterpriseResetScopeContract.ParseWireValue("SECURITY_CREDENTIALS"));
        var rejectedUserDataScope = false;
        try
        {
            _ = EnterpriseResetScopeContract.ParseWireValue("USER_DATA");
        }
        catch (FormatException)
        {
            rejectedUserDataScope = true;
        }

        AssertTrue(rejectedUserDataScope);
        return Task.CompletedTask;
    }

    private static Task EnterpriseErrorCodeRegistryAsync()
    {
        var values = typeof(EnterpriseErrorCodes)
            .GetFields(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static)
            .Where(field => field.IsLiteral && !field.IsInitOnly && field.FieldType == typeof(string))
            .Select(field => (string)field.GetRawConstantValue()!)
            .ToArray();

        AssertTrue(values.Length >= 30);
        AssertEqual(values.Length, values.Distinct(StringComparer.Ordinal).Count());
        AssertTrue(values.All(value => value.Length > 0));
        AssertTrue(values.All(value => value.All(character =>
            character is >= 'A' and <= 'Z' or >= '0' and <= '9' or '_')));
        return Task.CompletedTask;
    }

    private static Task EnterpriseProductPathsAsync()
    {
        var paths = CreateEnterpriseTestPaths();
        AssertEqual(
            Path.GetFullPath(@"C:\Users\Employee\AppData\Local\Ensou\DshEnterpriseLauncher"),
            paths.ManagedRoot);
        AssertEqual(
            Path.GetFullPath(@"C:\Users\Employee\.dsh-enterprise"),
            paths.HarnessHome);
        AssertEqual(
            Path.GetFullPath(@"C:\Users\Employee\.dsh-enterprise\workspaces"),
            paths.WorkspaceRoot);
        AssertTrue(paths.IsInsideHarnessHome(paths.WorkspaceRoot));
        AssertFalse(paths.IsInsideManagedRoot(paths.WorkspaceRoot));
        AssertFalse(paths.IsInsideManagedRoot(@"C:\Users\Employee\AppData\Local\Ensou\DshLauncher"));
        AssertFalse(paths.IsInsideHarnessHome(paths.ManagedRoot));
        AssertEqual(3081, EnterpriseProductIdentity.DefaultPort);
        AssertEqual(3181, EnterpriseProductIdentity.DevelopmentE2EDefaultPort);
        AssertEqual("Ensou.Dsh.Enterprise.Launcher.exe", EnterpriseProductIdentity.ExecutableName);
        AssertEqual("studio.ensou.dsh.enterprise.launcher", EnterpriseProductIdentity.AppUserModelId);
        AssertFalse(EnterpriseProductIdentity.SingleInstanceMutexName.Contains(
            "Dsh.Launcher.SingleInstance",
            StringComparison.Ordinal));
        return Task.CompletedTask;
    }

    private static Task EnterpriseManagedPathPrefixAsync()
    {
        var paths = CreateEnterpriseTestPaths();
        AssertTrue(paths.IsInsideManagedRoot(paths.Resolve(
            EnterpriseManagedArtifact.PluginPolicyCache)));
        AssertFalse(paths.IsInsideManagedRoot(paths.ManagedRoot + "-outside"));
        AssertFalse(paths.IsInsideManagedRoot(Path.Combine(
            Path.GetDirectoryName(paths.ManagedRoot)!,
            "DshEnterpriseLauncher-Evil",
            "credentials")));
        return Task.CompletedTask;
    }

    private static Task EnterpriseManagedResetPlanAsync()
    {
        var paths = CreateEnterpriseTestPaths();
        var plan = EnterpriseResetPlanner.Create(EnterpriseResetScope.ManagedConfig, paths);

        AssertEqual(EnterpriseResetScope.ManagedConfig, plan.Scope);
        AssertEqual(3, plan.ExactFiles.Count);
        AssertFalse(plan.DeleteDeviceProofKey);
        AssertTrue(plan.ExactFiles.Contains(EnterpriseManagedArtifact.AuthorizationLease));
        AssertTrue(plan.ExactFiles.Contains(EnterpriseManagedArtifact.ApiAllocationCache));
        AssertTrue(plan.ExactFiles.Contains(EnterpriseManagedArtifact.PluginPolicyCache));
        AssertFalse(plan.ExactFiles.Contains(EnterpriseManagedArtifact.DeviceBindingReceipt));
        AssertFalse(plan.ExactFiles.Contains(EnterpriseManagedArtifact.RefreshTokenDpapi));
        AssertFalse(plan.ExactFiles.Contains(
            EnterpriseManagedArtifact.TrustedTimeHighWaterDpapi));
        AssertTrue(plan.ExactFiles
            .Select(paths.Resolve)
            .All(path => paths.IsInsideManagedRoot(path) && !paths.IsInsideHarnessHome(path)));
        AssertFalse(plan.ExactFiles
            .Select(paths.Resolve)
            .Any(path => string.Equals(path, paths.InstallationIdentityPath, StringComparison.OrdinalIgnoreCase)));
        return Task.CompletedTask;
    }

    private static Task EnterpriseSecurityResetPlanAsync()
    {
        var paths = CreateEnterpriseTestPaths();
        var plan = EnterpriseResetPlanner.Create(EnterpriseResetScope.SecurityCredentials, paths);

        AssertEqual(10, plan.ExactFiles.Count);
        AssertTrue(plan.DeleteDeviceProofKey);
        AssertEqual(10, plan.ExactFiles.Distinct().Count());
        AssertTrue(Enum.GetValues<EnterpriseManagedArtifact>()
            .Where(artifact => artifact != EnterpriseManagedArtifact.ResetBarrierDpapi)
            .All(plan.ExactFiles.Contains));
        AssertFalse(plan.ExactFiles.Contains(EnterpriseManagedArtifact.ResetBarrierDpapi));
        AssertTrue(plan.ExactFiles.Contains(EnterpriseManagedArtifact.PendingBindingTransactionDpapi));
        AssertTrue(plan.ExactFiles.Contains(EnterpriseManagedArtifact.PendingRefreshTransactionDpapi));
        AssertTrue(plan.ExactFiles.Contains(
            EnterpriseManagedArtifact.PendingUpdateReceiptTransactionDpapi));
        AssertTrue(plan.ExactFiles.Contains(EnterpriseManagedArtifact.TrustedTimeHighWaterDpapi));
        AssertTrue(plan.ExactFiles
            .Select(paths.Resolve)
            .All(path => paths.IsInsideManagedRoot(path) && !paths.IsInsideHarnessHome(path)));
        AssertFalse(plan.ExactFiles
            .Select(paths.Resolve)
            .Any(path => string.Equals(path, paths.InstallationIdentityPath, StringComparison.OrdinalIgnoreCase)));
        return Task.CompletedTask;
    }

    private static async Task EnterpriseArtifactRejectsUnknownValueAsync()
    {
        var paths = CreateEnterpriseTestPaths();
        await AssertThrowsAsync<ArgumentOutOfRangeException>(() => Task.Run(() =>
            paths.Resolve((EnterpriseManagedArtifact)999)));
    }

    private static async Task EnterpriseRootsRejectUnsafeFormsAsync()
    {
        await AssertThrowsAsync<InvalidDataException>(() => Task.Run(() =>
            EnterpriseManagedPaths.Create(
                @"C:\Users\Employee\AppData\Local\..\Local",
                @"C:\Users\Employee")));
        await AssertThrowsAsync<InvalidDataException>(() => Task.Run(() =>
            EnterpriseManagedPaths.Create(
                @"\\server\share\AppData",
                @"C:\Users\Employee")));
        await AssertThrowsAsync<InvalidDataException>(() => Task.Run(() =>
            EnterpriseManagedPaths.Create(
                "//server/share/AppData",
                @"C:\Users\Employee")));
        await AssertThrowsAsync<InvalidDataException>(() => Task.Run(() =>
            EnterpriseManagedPaths.Create(
                @"C:\Users\Employee\AppData\Local:stream",
                @"C:\Users\Employee")));
    }

    private static async Task EnterpriseResetRejectsUnknownScopeAsync()
    {
        await AssertThrowsAsync<ArgumentOutOfRangeException>(() => Task.Run(() =>
            EnterpriseResetPlanner.Create((EnterpriseResetScope)999, CreateEnterpriseTestPaths())));
    }

    private static Task EnterpriseStartupGateRequiresEnrollmentAsync()
    {
        var gate = new EnterpriseStartupGate(new FixedTimeProvider(
            new DateTimeOffset(2026, 8, 24, 0, 0, 0, TimeSpan.Zero)));
        var decision = gate.Evaluate(EnterpriseStartupGate.CreateEnrollmentRequiredSnapshot());

        AssertEqual(EnterpriseClientState.QrRequired, decision.ClientState);
        AssertFalse(decision.MayStartHarness);
        AssertFalse(decision.MayCallManagedApi);
        AssertEqual(EnterpriseResetScope.None, decision.ResetScope);
        return Task.CompletedTask;
    }

    private static async Task EnterpriseSessionDeniesHostAsync()
    {
        var now = new DateTimeOffset(2026, 8, 24, 0, 0, 0, TimeSpan.Zero);
        var host = new FakeEnterpriseHarnessHost();
        await using var session = new EnterpriseHarnessSession(
            new EnterpriseStartupGate(new FixedTimeProvider(now)),
            host,
            EnterpriseStartupGate.CreateEnrollmentRequiredSnapshot());

        await AssertThrowsAsync<EnterpriseAccessDeniedException>(() => session.EnsureStartedAsync());
        await AssertThrowsAsync<EnterpriseAccessDeniedException>(() => session.GetWebUiUriAsync());
        await AssertThrowsAsync<EnterpriseAccessDeniedException>(
            () => session.OpenWebUiAsync());
        AssertFalse(await session.IsHealthyAsync());
        AssertEqual(0, host.EnsureStartedCalls);
        AssertEqual(0, host.HealthCheckCalls);
        AssertEqual(0, host.StopCalls);
    }

    private static async Task EnterpriseSessionAllowsReadyHostAsync()
    {
        var now = new DateTimeOffset(2026, 8, 24, 0, 0, 0, TimeSpan.Zero);
        var host = new FakeEnterpriseHarnessHost { Healthy = true };
        await using var session = new EnterpriseHarnessSession(
            new EnterpriseStartupGate(new FixedTimeProvider(now)),
            host,
            CreateReadyEnterpriseSnapshot(now));

        var startedUri = await session.EnsureStartedAsync();
        var webUiUri = await session.GetWebUiUriAsync();
        await session.OpenWebUiAsync();
        AssertTrue(await session.IsHealthyAsync());
        AssertEqual(host.WebUiUri, startedUri);
        AssertEqual(host.WebUiUri, webUiUri);
        AssertEqual(1, host.EnsureStartedCalls);
        AssertEqual(3, host.HealthCheckCalls);
        AssertEqual(1, host.OpenWebUiCalls);
        AssertEqual(0, host.StopCalls);
    }

    private static async Task EnterpriseSessionRefusesUnavailableWebUiAsync()
    {
        var now = new DateTimeOffset(2026, 8, 24, 0, 0, 0, TimeSpan.Zero);
        var host = new FakeEnterpriseHarnessHost { Healthy = false };
        await using var session = new EnterpriseHarnessSession(
            new EnterpriseStartupGate(new FixedTimeProvider(now)),
            host,
            CreateReadyEnterpriseSnapshot(now));

        await AssertThrowsAsync<InvalidOperationException>(() => session.GetWebUiUriAsync());
        AssertEqual(0, host.EnsureStartedCalls);
        AssertEqual(1, host.HealthCheckCalls);
    }

    private static async Task EnterpriseSessionStopsOnSuspensionAsync()
    {
        var now = new DateTimeOffset(2026, 8, 24, 0, 0, 0, TimeSpan.Zero);
        var host = new FakeEnterpriseHarnessHost();
        await using var session = new EnterpriseHarnessSession(
            new EnterpriseStartupGate(new FixedTimeProvider(now)),
            host,
            CreateReadyEnterpriseSnapshot(now));

        await session.EnsureStartedAsync();
        var decision = await session.ApplyAccessAsync(
            CreateReadyEnterpriseSnapshot(now) with
            {
                Employee = EmployeeAuthorizationState.Suspended,
            });

        AssertEqual(EnterpriseClientState.AccountLocked, decision.ClientState);
        AssertFalse(decision.MayStartHarness);
        AssertEqual(1, host.StopCalls);
        await AssertThrowsAsync<EnterpriseAccessDeniedException>(() => session.EnsureStartedAsync());
        AssertEqual(1, host.EnsureStartedCalls);
    }

    private static async Task EnterpriseSessionStopsBeforeManagedResetAsync()
    {
        var now = new DateTimeOffset(2026, 8, 24, 0, 0, 0, TimeSpan.Zero);
        var events = new List<string>();
        var host = new FakeEnterpriseHarnessHost
        {
            StopAction = () => events.Add("stop"),
        };
        var reset = new FakeEnterpriseResetExecutor
        {
            ExecuteAction = scope => events.Add($"reset:{scope}"),
            PersistBarrierAction = barrier => events.Add(
                $"barrier:{barrier.Decision.ResetScope}:{barrier.ResetCompleted}"),
        };
        await using var session = new EnterpriseHarnessSession(
            new EnterpriseStartupGate(new FixedTimeProvider(now)),
            host,
            CreateReadyEnterpriseSnapshot(now),
            reset);

        await session.EnsureStartedAsync();
        var decision = await session.ApplyAccessAsync(
            CreateReadyEnterpriseSnapshot(now) with
            {
                Employee = EmployeeAuthorizationState.Suspended,
            });

        AssertEqual(EnterpriseClientState.AccountLocked, decision.ClientState);
        AssertEqual(EnterpriseResetScope.ManagedConfig, decision.ResetScope);
        AssertSequenceEqual(
            new[]
            {
                "barrier:ManagedConfig:False",
                "stop",
                "reset:ManagedConfig",
                "barrier:ManagedConfig:True",
            },
            events);
        AssertSequenceEqual(
            new[] { EnterpriseResetScope.ManagedConfig },
            reset.Scopes);
    }

    private static async Task EnterpriseSessionStopsBeforeSecurityResetAsync()
    {
        var now = new DateTimeOffset(2026, 8, 24, 0, 0, 0, TimeSpan.Zero);
        var events = new List<string>();
        var host = new FakeEnterpriseHarnessHost
        {
            StopAction = () => events.Add("stop"),
        };
        var reset = new FakeEnterpriseResetExecutor
        {
            ExecuteAction = scope => events.Add($"reset:{scope}"),
        };
        await using var session = new EnterpriseHarnessSession(
            new EnterpriseStartupGate(new FixedTimeProvider(now)),
            host,
            CreateReadyEnterpriseSnapshot(now),
            reset);

        await session.EnsureStartedAsync();
        var decision = await session.ApplyAccessAsync(
            CreateReadyEnterpriseSnapshot(now) with
            {
                AuthorizationEpochMatches = false,
            });

        AssertEqual(EnterpriseClientState.SecurityQuarantined, decision.ClientState);
        AssertEqual(EnterpriseErrorCodes.AuthorizationEpochMismatch, decision.ErrorCode);
        AssertSequenceEqual(
            new[] { "stop", "reset:SecurityCredentials" },
            events);
        AssertSequenceEqual(
            new[] { EnterpriseResetScope.SecurityCredentials },
            reset.Scopes);
    }

    private static async Task EnterpriseSessionInvalidDenialDoesNotResetAsync()
    {
        var now = new DateTimeOffset(2026, 8, 24, 0, 0, 0, TimeSpan.Zero);
        var host = new FakeEnterpriseHarnessHost();
        var reset = new FakeEnterpriseResetExecutor();
        await using var session = new EnterpriseHarnessSession(
            new EnterpriseStartupGate(new FixedTimeProvider(now)),
            host,
            CreateReadyEnterpriseSnapshot(now),
            reset);

        await session.EnsureStartedAsync();
        var decision = await session.ApplyAccessAsync(
            CreateReadyEnterpriseSnapshot(now) with
            {
                LeaseSignatureValid = false,
            });

        AssertEqual(EnterpriseClientState.SecurityQuarantined, decision.ClientState);
        AssertEqual(EnterpriseResetScope.None, decision.ResetScope);
        AssertEqual(EnterpriseErrorCodes.LeaseSignatureInvalid, decision.ErrorCode);
        AssertEqual(1, host.StopCalls);
        AssertEqual(0, reset.Scopes.Count);
    }

    private static async Task EnterpriseSessionResetFailureStaysLockedAndRetriesAsync()
    {
        var now = new DateTimeOffset(2026, 8, 24, 0, 0, 0, TimeSpan.Zero);
        var timeProvider = new ManualTimeProvider(now);
        var events = new List<string>();
        var host = new FakeEnterpriseHarnessHost
        {
            StopAction = () => events.Add("stop"),
        };
        var reset = new FakeEnterpriseResetExecutor
        {
            FailuresRemaining = 1,
            ExecuteAction = scope => events.Add($"reset:{scope}"),
        };
        await using var session = new EnterpriseHarnessSession(
            new EnterpriseStartupGate(timeProvider),
            host,
            CreateReadyEnterpriseSnapshot(now),
            reset);

        await session.EnsureStartedAsync();
        await AssertThrowsAsync<IOException>(() => session.ApplyAccessAsync(
            CreateReadyEnterpriseSnapshot(now) with
            {
                Device = DeviceBindingState.RevokedAdmin,
            }));

        AssertFalse(session.CurrentDecision.MayStartHarness);
        AssertFalse(session.CurrentDecision.MayCallManagedApi);
        AssertEqual(EnterpriseClientState.DeviceRevokedResetRequired, session.CurrentDecision.ClientState);
        AssertSequenceEqual(
            new[] { "stop", "reset:SecurityCredentials" },
            events);

        timeProvider.Advance(TimeSpan.FromSeconds(1));
        await reset.SuccessfulExecution.WaitAsync(TimeSpan.FromSeconds(2));

        AssertFalse(session.CurrentDecision.MayStartHarness);
        AssertSequenceEqual(
            new[]
            {
                "stop", "reset:SecurityCredentials",
                "stop", "reset:SecurityCredentials",
            },
            events);
        await AssertThrowsAsync<EnterpriseAccessDeniedException>(() => session.EnsureStartedAsync());
        AssertEqual(1, host.EnsureStartedCalls);
    }

    private static async Task EnterprisePendingResetUpgradesAsync()
    {
        var now = new DateTimeOffset(2026, 8, 24, 0, 0, 0, TimeSpan.Zero);
        var timeProvider = new ManualTimeProvider(now);
        var events = new List<string>();
        var host = new FakeEnterpriseHarnessHost
        {
            StopAction = () => events.Add("stop"),
        };
        var reset = new FakeEnterpriseResetExecutor
        {
            FailuresRemaining = 1,
            ExecuteAction = scope => events.Add($"reset:{scope}"),
        };
        await using var session = new EnterpriseHarnessSession(
            new EnterpriseStartupGate(timeProvider),
            host,
            CreateReadyEnterpriseSnapshot(now),
            reset);

        await session.EnsureStartedAsync();
        await AssertThrowsAsync<IOException>(() => session.ApplyAccessAsync(
            CreateReadyEnterpriseSnapshot(now) with
            {
                Employee = EmployeeAuthorizationState.Suspended,
            }));

        AssertEqual(EnterpriseClientState.AccountLocked, session.CurrentDecision.ClientState);
        AssertEqual(EnterpriseResetScope.ManagedConfig, session.CurrentDecision.ResetScope);

        var upgraded = await session.ApplyAccessAsync(
            CreateReadyEnterpriseSnapshot(now) with
            {
                Device = DeviceBindingState.RevokedAdmin,
            });

        AssertEqual(EnterpriseClientState.DeviceRevokedResetRequired, upgraded.ClientState);
        AssertEqual(EnterpriseErrorCodes.DeviceBindingRevoked, upgraded.ErrorCode);
        AssertEqual(EnterpriseResetScope.SecurityCredentials, upgraded.ResetScope);
        AssertEqual(upgraded, session.CurrentDecision);
        AssertSequenceEqual(
            new[]
            {
                EnterpriseResetScope.ManagedConfig,
                EnterpriseResetScope.SecurityCredentials,
            },
            reset.Scopes);
        AssertSequenceEqual(
            new[]
            {
                "stop", "reset:ManagedConfig",
                "stop", "reset:SecurityCredentials",
            },
            events);

        AssertFalse(await session.IsHealthyAsync());
        AssertEqual(2, host.StopCalls);
        AssertEqual(0, host.HealthCheckCalls);
        AssertEqual(2, reset.Scopes.Count);
    }

    private static async Task EnterpriseCompletedResetBarrierSurvivesRestartAsync()
    {
        var now = new DateTimeOffset(2026, 8, 24, 0, 0, 0, TimeSpan.Zero);
        var reset = new FakeEnterpriseResetExecutor();
        await using (var firstSession = new EnterpriseHarnessSession(
            new EnterpriseStartupGate(new FixedTimeProvider(now)),
            new FakeEnterpriseHarnessHost(),
            CreateReadyEnterpriseSnapshot(now),
            reset))
        {
            var suspended = await firstSession.ApplyAccessAsync(
                CreateReadyEnterpriseSnapshot(now) with
                {
                    Employee = EmployeeAuthorizationState.Suspended,
                });

            AssertEqual(EnterpriseClientState.AccountLocked, suspended.ClientState);
            AssertTrue(reset.Barrier!.ResetCompleted);
            AssertEqual(EnterpriseResetScope.ManagedConfig, reset.Barrier.Decision.ResetScope);
        }

        var restartedHost = new FakeEnterpriseHarnessHost();
        await using var restartedSession = new EnterpriseHarnessSession(
            new EnterpriseStartupGate(new FixedTimeProvider(now)),
            restartedHost,
            CreateReadyEnterpriseSnapshot(now) with
            {
                ControlPlane = ControlPlaneConnectivity.Unavailable,
            },
            reset);

        AssertEqual(EnterpriseClientState.AccountLocked, restartedSession.CurrentDecision.ClientState);
        await AssertThrowsAsync<EnterpriseAccessDeniedException>(() =>
            restartedSession.EnsureStartedAsync());
        AssertEqual(0, restartedHost.EnsureStartedCalls);
        AssertTrue(reset.Barrier!.ResetCompleted);

        var stillLocked = await restartedSession.ApplyAccessAsync(
            CreateReadyEnterpriseSnapshot(now) with
            {
                ControlPlane = ControlPlaneConnectivity.Unavailable,
            });
        AssertEqual(EnterpriseClientState.AccountLocked, stillLocked.ClientState);
        AssertEqual(0, reset.ClearBarrierCalls);

        var onlineReady = await restartedSession.ApplyAccessAsync(
            CreateReadyEnterpriseSnapshot(now));
        AssertEqual(EnterpriseClientState.Ready, onlineReady.ClientState);
        AssertEqual(1, reset.ClearBarrierCalls);
        AssertTrue(reset.Barrier is null);
        _ = await restartedSession.EnsureStartedAsync();
        AssertEqual(1, restartedHost.EnsureStartedCalls);
    }

    private static async Task EnterpriseIncompleteResetBarrierRetriesAfterRestartAsync()
    {
        var now = new DateTimeOffset(2026, 8, 24, 0, 0, 0, TimeSpan.Zero);
        var reset = new FakeEnterpriseResetExecutor
        {
            FailuresRemaining = 1,
        };
        await using (var firstSession = new EnterpriseHarnessSession(
            new EnterpriseStartupGate(new FixedTimeProvider(now)),
            new FakeEnterpriseHarnessHost(),
            CreateReadyEnterpriseSnapshot(now),
            reset))
        {
            await AssertThrowsAsync<IOException>(() => firstSession.ApplyAccessAsync(
                CreateReadyEnterpriseSnapshot(now) with
                {
                    Employee = EmployeeAuthorizationState.Suspended,
                }));
            AssertFalse(reset.Barrier!.ResetCompleted);
        }

        var restartedHost = new FakeEnterpriseHarnessHost();
        await using var restartedSession = new EnterpriseHarnessSession(
            new EnterpriseStartupGate(new FixedTimeProvider(now)),
            restartedHost,
            CreateReadyEnterpriseSnapshot(now) with
            {
                ControlPlane = ControlPlaneConnectivity.Unavailable,
            },
            reset);

        AssertEqual(EnterpriseClientState.AccountLocked, restartedSession.CurrentDecision.ClientState);
        var retried = await restartedSession.ApplyAccessAsync(
            CreateReadyEnterpriseSnapshot(now) with
            {
                ControlPlane = ControlPlaneConnectivity.Unavailable,
            });
        AssertEqual(EnterpriseClientState.AccountLocked, retried.ClientState);
        AssertSequenceEqual(
            new[] { EnterpriseResetScope.ManagedConfig, EnterpriseResetScope.ManagedConfig },
            reset.Scopes);
        AssertTrue(reset.Barrier!.ResetCompleted);
        AssertEqual(1, restartedHost.StopCalls);

        var onlineReady = await restartedSession.ApplyAccessAsync(
            CreateReadyEnterpriseSnapshot(now));
        AssertEqual(EnterpriseClientState.Ready, onlineReady.ClientState);
        AssertTrue(reset.Barrier is null);
    }

    private static async Task EnterpriseUpdateOnlyLockPreservesProcessAsync()
    {
        var now = new DateTimeOffset(2026, 8, 24, 0, 0, 0, TimeSpan.Zero);
        var ready = CreateReadyEnterpriseSnapshot(now);
        EnterpriseAccessSnapshot[] updateLocks =
        [
            ready with { ClientUpdateRequired = true },
            ready with { RuntimeUpdateRequired = true },
            ready with { CriticalPluginUpdateRequired = true },
            ready with { PluginPolicySha256 = null },
        ];
        foreach (var pending in updateLocks)
        {
            var host = new FakeEnterpriseHarnessHost { Healthy = true };
            await using var session = new EnterpriseHarnessSession(
                new EnterpriseStartupGate(new FixedTimeProvider(now)), host, ready);
            await session.EnsureStartedAsync();
            var decision = await session.ApplyAccessAsync(pending);
            AssertEqual(EnterpriseClientState.UpdateRequired, decision.ClientState);
            AssertFalse(decision.MayStartHarness);
            AssertFalse(decision.MayCallManagedApi);
            AssertEqual(0, host.StopCalls);
            await AssertThrowsAsync<EnterpriseAccessDeniedException>(() => session.EnsureStartedAsync());
            await AssertThrowsAsync<EnterpriseAccessDeniedException>(() => session.EnsureManagedApiAllowedAsync());
            await AssertThrowsAsync<EnterpriseAccessDeniedException>(() => session.GetWebUiUriAsync());
            AssertFalse(await session.IsHealthyAsync());
            AssertEqual(1, host.EnsureStartedCalls);
            AssertEqual(0, host.HealthCheckCalls);
            AssertEqual(0, host.StopCalls);

            // Repeated policy checks are not a reason to kill an active process.
            await session.ApplyAccessAsync(pending);
            AssertEqual(0, host.StopCalls);
            // A later security denial still stops it, despite the prior deny state.
            decision = await session.ApplyAccessAsync(pending with
            {
                Employee = EmployeeAuthorizationState.Revoked,
            });
            AssertEqual(EnterpriseClientState.AccountLocked, decision.ClientState);
            AssertEqual(1, host.StopCalls);
        }

        // Unknown authorization connectivity must not be disguised by an update flag.
        var unknown = EnterpriseAccessEvaluator.Evaluate(ready with
        {
            ClientUpdateRequired = true,
            ControlPlane = ControlPlaneConnectivity.Unknown,
        }, now);
        AssertEqual(EnterpriseClientState.SecurityQuarantined, unknown.ClientState);

        // A cold update-locked session never starts a process to preserve.
        var coldHost = new FakeEnterpriseHarnessHost();
        await using var cold = new EnterpriseHarnessSession(
            new EnterpriseStartupGate(new FixedTimeProvider(now)), coldHost, updateLocks[0]);
        await AssertThrowsAsync<EnterpriseAccessDeniedException>(() => cold.EnsureStartedAsync());
        AssertEqual(0, coldHost.EnsureStartedCalls);
        AssertEqual(0, coldHost.StopCalls);
    }

    private static async Task EnterpriseUpdateOnlyLockExpiresAsync()
    {
        var now = new DateTimeOffset(2026, 8, 24, 0, 0, 0, TimeSpan.Zero);
        foreach (var rollClockBack in new[] { false, true })
        {
            var clock = new ManualTimeProvider(now);
            var host = new FakeEnterpriseHarnessHost();
            var ready = CreateReadyEnterpriseSnapshot(now);
            await using var session = new EnterpriseHarnessSession(
                new EnterpriseStartupGate(clock), host, ready);
            await session.EnsureStartedAsync();
            await session.ApplyAccessAsync(ready with { ClientUpdateRequired = true });
            AssertEqual(0, host.StopCalls);
            clock.Advance(TimeSpan.FromMinutes(10));
            if (rollClockBack)
            {
                clock.AdjustUtc(TimeSpan.FromMinutes(-5));
            }
            // Reapplying the same signed lease cannot move its monotonic deadline.
            await session.ApplyAccessAsync(ready with { ClientUpdateRequired = true });
            AssertEqual(0, host.StopCalls);
            clock.Advance(TimeSpan.FromMinutes(5));
            await host.StopObserved.WaitAsync(TimeSpan.FromSeconds(2));
            AssertEqual(1, host.StopCalls);
            AssertEqual(EnterpriseClientState.LeaseExpiredLocked, session.CurrentDecision.ClientState);
        }
    }

    private static async Task EnterpriseUpdateOnlyLockSecurityRetryAsync()
    {
        var now = new DateTimeOffset(2026, 8, 24, 0, 0, 0, TimeSpan.Zero);
        var pending = CreateReadyEnterpriseSnapshot(now) with { ClientUpdateRequired = true };
        EnterpriseAccessSnapshot[] securityDenials =
        [
            pending with { ClockTrusted = false },
            pending with { ControlPlane = ControlPlaneConnectivity.Unknown },
            pending with { AuthorizationEpochMatches = false },
            pending with { LeaseSignatureValid = false },
            pending with { ApiAllocation = ApiAllocationState.Suspended },
            pending with { Device = DeviceBindingState.RevokedAdmin },
        ];
        foreach (var denial in securityDenials)
        {
            var clock = new ManualTimeProvider(now);
            var host = new FakeEnterpriseHarnessHost { StopFailuresRemaining = 1 };
            await using var session = new EnterpriseHarnessSession(
                new EnterpriseStartupGate(clock), host, CreateReadyEnterpriseSnapshot(now));
            await session.EnsureStartedAsync();
            var observed = new List<EnterpriseAccessDecision>();
            session.DecisionChanged += observed.Add;
            await session.ApplyAccessAsync(pending);
            AssertEqual(0, host.StopCalls);
            await AssertThrowsAsync<InvalidOperationException>(() => session.ApplyAccessAsync(denial));
            AssertEqual(1, host.StopCalls);
            AssertFalse(session.CurrentDecision.MayStartHarness);
            AssertFalse(session.CurrentDecision.MayCallManagedApi);
            clock.Advance(TimeSpan.FromSeconds(1));
            await host.StopObserved.WaitAsync(TimeSpan.FromSeconds(2));
            AssertEqual(2, host.StopCalls);
            AssertTrue(observed.Count >= 2);
            AssertTrue(observed.All(decision => !decision.MayStartHarness && !decision.MayCallManagedApi));
        }
    }

    private static async Task EnterpriseSessionStopsOnLeaseExpiryAsync()
    {
        var now = new DateTimeOffset(2026, 8, 24, 0, 0, 0, TimeSpan.Zero);
        var host = new FakeEnterpriseHarnessHost();
        await using var session = new EnterpriseHarnessSession(
            new EnterpriseStartupGate(new FixedTimeProvider(now)),
            host,
            CreateReadyEnterpriseSnapshot(now));

        await session.EnsureStartedAsync();
        var decision = await session.ApplyAccessAsync(
            CreateReadyEnterpriseSnapshot(now) with { LeaseExpiresAtUtc = now });

        AssertEqual(EnterpriseClientState.LeaseExpiredLocked, decision.ClientState);
        AssertFalse(decision.MayStartHarness);
        AssertEqual(1, host.StopCalls);
    }

    private static async Task EnterpriseSessionStopsWhenClockExpiresLeaseAsync()
    {
        var now = new DateTimeOffset(2026, 8, 24, 0, 0, 0, TimeSpan.Zero);
        var timeProvider = new ManualTimeProvider(now);
        var host = new FakeEnterpriseHarnessHost { Healthy = true };
        await using var session = new EnterpriseHarnessSession(
            new EnterpriseStartupGate(timeProvider),
            host,
            CreateReadyEnterpriseSnapshot(now));
        var decisionChanged = new TaskCompletionSource<EnterpriseAccessDecision>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        session.DecisionChanged += decision => decisionChanged.TrySetResult(decision);

        await session.EnsureStartedAsync();
        timeProvider.Advance(TimeSpan.FromMinutes(16));
        await host.StopObserved.WaitAsync(TimeSpan.FromSeconds(2));
        var observedDecision = await decisionChanged.Task.WaitAsync(TimeSpan.FromSeconds(2));

        AssertEqual(1, host.EnsureStartedCalls);
        AssertEqual(0, host.HealthCheckCalls);
        AssertEqual(1, host.StopCalls);
        AssertFalse(session.CurrentDecision.MayStartHarness);
        AssertFalse(observedDecision.MayStartHarness);
    }

    private static async Task EnterpriseSessionRetriesFailedStopAsync()
    {
        var now = new DateTimeOffset(2026, 8, 24, 0, 0, 0, TimeSpan.Zero);
        var host = new FakeEnterpriseHarnessHost { StopFailuresRemaining = 1 };
        await using var session = new EnterpriseHarnessSession(
            new EnterpriseStartupGate(new FixedTimeProvider(now)),
            host,
            CreateReadyEnterpriseSnapshot(now));

        await session.EnsureStartedAsync();
        await AssertThrowsAsync<InvalidOperationException>(() => session.ApplyAccessAsync(
            CreateReadyEnterpriseSnapshot(now) with
            {
                Employee = EmployeeAuthorizationState.Suspended,
            }));

        AssertFalse(session.CurrentDecision.MayStartHarness);
        AssertEqual(1, host.StopCalls);
        AssertFalse(await session.IsHealthyAsync());
        AssertEqual(2, host.StopCalls);
        AssertEqual(0, host.HealthCheckCalls);
        AssertEqual(1, host.EnsureStartedCalls);
    }

    private static async Task EnterpriseSessionRechecksLeaseAfterStartupAsync()
    {
        var now = new DateTimeOffset(2026, 8, 24, 0, 0, 0, TimeSpan.Zero);
        var timeProvider = new ManualTimeProvider(now);
        var host = new FakeEnterpriseHarnessHost
        {
            EnsureStartedAction = () => timeProvider.Advance(TimeSpan.FromMinutes(16)),
        };
        await using var session = new EnterpriseHarnessSession(
            new EnterpriseStartupGate(timeProvider),
            host,
            CreateReadyEnterpriseSnapshot(now));

        await AssertThrowsAsync<EnterpriseAccessDeniedException>(() => session.EnsureStartedAsync());
        AssertEqual(1, host.EnsureStartedCalls);
        AssertEqual(1, host.StopCalls);
        AssertFalse(session.CurrentDecision.MayStartHarness);
    }

    private static async Task EnterpriseSessionRechecksLeaseAfterWebUiHealthAsync()
    {
        var now = new DateTimeOffset(2026, 8, 24, 0, 0, 0, TimeSpan.Zero);
        var timeProvider = new ManualTimeProvider(now);
        var host = new FakeEnterpriseHarnessHost
        {
            Healthy = true,
            HealthCheckAction = () => timeProvider.Advance(TimeSpan.FromMinutes(16)),
        };
        await using var session = new EnterpriseHarnessSession(
            new EnterpriseStartupGate(timeProvider),
            host,
            CreateReadyEnterpriseSnapshot(now));

        await AssertThrowsAsync<EnterpriseAccessDeniedException>(() => session.GetWebUiUriAsync());
        AssertEqual(1, host.HealthCheckCalls);
        AssertEqual(1, host.StopCalls);
        AssertFalse(session.CurrentDecision.MayStartHarness);
    }

    private static async Task EnterpriseSessionHealthCannotOutliveLeaseAsync()
    {
        var now = new DateTimeOffset(2026, 8, 24, 0, 0, 0, TimeSpan.Zero);
        var timeProvider = new ManualTimeProvider(now);
        var host = new FakeEnterpriseHarnessHost
        {
            Healthy = true,
            HealthCheckAction = () => timeProvider.Advance(TimeSpan.FromMinutes(16)),
        };
        await using var session = new EnterpriseHarnessSession(
            new EnterpriseStartupGate(timeProvider),
            host,
            CreateReadyEnterpriseSnapshot(now));

        AssertFalse(await session.IsHealthyAsync());
        AssertEqual(1, host.HealthCheckCalls);
        AssertEqual(1, host.StopCalls);
        AssertFalse(session.CurrentDecision.MayStartHarness);
    }

    private static async Task EnterpriseMonotonicLeaseSurvivesWallClockRollbackAsync()
    {
        var now = new DateTimeOffset(2026, 8, 24, 0, 0, 0, TimeSpan.Zero);
        var timeProvider = new ManualTimeProvider(now);
        var host = new FakeEnterpriseHarnessHost { Healthy = true };
        await using var session = new EnterpriseHarnessSession(
            new EnterpriseStartupGate(timeProvider),
            host,
            CreateReadyEnterpriseSnapshot(now));

        await session.EnsureStartedAsync();
        timeProvider.Advance(TimeSpan.FromMinutes(10));
        timeProvider.AdjustUtc(TimeSpan.FromMinutes(-5));
        AssertTrue(await session.IsHealthyAsync());

        timeProvider.Advance(TimeSpan.FromMinutes(5));
        await host.StopObserved.WaitAsync(TimeSpan.FromSeconds(2));

        AssertEqual(1, host.StopCalls);
        AssertFalse(session.CurrentDecision.MayStartHarness);
        AssertEqual(EnterpriseClientState.LeaseExpiredLocked, session.CurrentDecision.ClientState);
    }

    private static async Task EnterpriseInstallationIdentityPersistsAsync()
    {
        var paths = CreateEnterpriseDiskTestPaths();
        var now = new DateTimeOffset(2026, 8, 24, 1, 2, 3, TimeSpan.Zero);
        var store = new EnterpriseInstallationIdentityStore(
            paths,
            new FixedTimeProvider(now));

        var first = await store.GetOrCreateAsync();
        var second = await store.GetOrCreateAsync();

        AssertTrue(first.InstallId != Guid.Empty);
        AssertEqual(first, second);
        AssertEqual(now, first.CreatedAtUtc);
        AssertTrue(File.Exists(paths.InstallationIdentityPath));
        AssertTrue(paths.IsInsideManagedRoot(paths.InstallationIdentityPath));
        AssertFalse(paths.IsInsideHarnessHome(paths.InstallationIdentityPath));
    }

    private static async Task EnterpriseInstallationIdentityCorruptionAsync()
    {
        var paths = CreateEnterpriseDiskTestPaths();
        Directory.CreateDirectory(paths.LauncherStateDirectory);
        await File.WriteAllTextAsync(
            paths.InstallationIdentityPath,
            "{\"schema_version\":1,\"install_id\":\"not-a-guid\",\"created_at_utc\":\"2026-08-24T00:00:00Z\"}");
        var store = new EnterpriseInstallationIdentityStore(paths);

        await AssertThrowsAsync<InvalidDataException>(() => store.GetOrCreateAsync());
    }

    private static async Task EnterpriseProtectedArtifactRoundTripAsync()
    {
        var paths = CreateEnterpriseDiskTestPaths();
        var store = new EnterpriseProtectedArtifactStore(paths);
        var plaintext = Encoding.UTF8.GetBytes("refresh-secret-canary");
        var replacement = Encoding.UTF8.GetBytes("refresh-secret-rotated");

        await store.WriteAsync(EnterpriseManagedArtifact.RefreshTokenDpapi, plaintext);
        await store.WriteAsync(EnterpriseManagedArtifact.RefreshTokenDpapi, replacement);
        var restored = await store.ReadAsync(EnterpriseManagedArtifact.RefreshTokenDpapi);
        var raw = await File.ReadAllBytesAsync(
            paths.Resolve(EnterpriseManagedArtifact.RefreshTokenDpapi));

        AssertTrue(restored is not null);
        AssertSequenceEqual(replacement, restored!);
        AssertFalse(raw.AsSpan().IndexOf(plaintext) >= 0);
        AssertFalse(raw.AsSpan().IndexOf(replacement) >= 0);
        CryptographicOperations.ZeroMemory(restored!);
    }

    private static async Task EnterpriseProtectedArtifactBoundaryAsync()
    {
        var store = new EnterpriseProtectedArtifactStore(CreateEnterpriseDiskTestPaths());
        await AssertThrowsAsync<ArgumentOutOfRangeException>(() => store.WriteAsync(
            EnterpriseManagedArtifact.AuthorizationLease,
            new byte[] { 1 }));
    }

    private static async Task EnterpriseTrustedTimeProtectionAsync()
    {
        var paths = CreateEnterpriseDiskTestPaths();
        var protectedStore = new EnterpriseProtectedArtifactStore(paths);
        var trustedTimeStore = new EnterpriseTrustedTimeStore(protectedStore);
        var issuedAtUtc = new DateTimeOffset(2026, 8, 24, 2, 0, 0, TimeSpan.Zero);
        var observedUtc = issuedAtUtc.AddMinutes(5);
        var deadlineUtc = issuedAtUtc.AddMinutes(15);

        var enrollmentObservedUtc = issuedAtUtc.AddMinutes(1);
        await using (var enrollmentSession = new EnterpriseHarnessSession(
            new EnterpriseStartupGate(new FixedTimeProvider(enrollmentObservedUtc)),
            new FakeEnterpriseHarnessHost(),
            EnterpriseStartupGate.CreateEnrollmentRequiredSnapshot(),
            trustedTimeStore: trustedTimeStore))
        {
            var enrollmentDecision = await enrollmentSession.ApplyAccessAsync(
                CreateReadyEnterpriseSnapshot(issuedAtUtc) with
                {
                    LeaseIssuedAtUtc = issuedAtUtc,
                    TrustedTimeFloorUtc = issuedAtUtc,
                    LeaseExpiresAtUtc = deadlineUtc,
                });
            AssertEqual(EnterpriseClientState.Ready, enrollmentDecision.ClientState);
            AssertTrue(enrollmentDecision.MayStartHarness);
            AssertTrue(enrollmentDecision.MayCallManagedApi);
            AssertEqual(enrollmentObservedUtc, trustedTimeStore.ReadFloorUtc());
        }

        AssertEqual(observedUtc, trustedTimeStore.Advance(observedUtc, deadlineUtc));
        var rawState = await File.ReadAllBytesAsync(paths.Resolve(
            EnterpriseManagedArtifact.TrustedTimeHighWaterDpapi));
        AssertFalse(Encoding.UTF8.GetString(rawState).Contains(
            observedUtc.ToUnixTimeSeconds().ToString(),
            StringComparison.Ordinal));

        await protectedStore.WriteAsync(
            EnterpriseManagedArtifact.TrustedTimeHighWaterDpapi,
            Encoding.UTF8.GetBytes("{"));
        await using (var corruptSession = new EnterpriseHarnessSession(
            new EnterpriseStartupGate(new FixedTimeProvider(observedUtc.AddMinutes(1))),
            new FakeEnterpriseHarnessHost(),
            CreateReadyEnterpriseSnapshot(issuedAtUtc) with
            {
                LeaseIssuedAtUtc = issuedAtUtc,
                TrustedTimeFloorUtc = issuedAtUtc,
                LeaseExpiresAtUtc = deadlineUtc,
            },
            trustedTimeStore: trustedTimeStore))
        {
            AssertEqual(
                EnterpriseClientState.SecurityQuarantined,
                corruptSession.CurrentDecision.ClientState);
            AssertEqual(
                EnterpriseErrorCodes.ClockUntrusted,
                corruptSession.CurrentDecision.ErrorCode);
            AssertFalse(corruptSession.CurrentDecision.MayStartHarness);
            AssertFalse(corruptSession.CurrentDecision.MayCallManagedApi);
        }

        trustedTimeStore.Delete();
        AssertEqual(observedUtc, trustedTimeStore.Advance(observedUtc, deadlineUtc));
        var trustedSnapshot = CreateReadyEnterpriseSnapshot(issuedAtUtc) with
        {
            LeaseIssuedAtUtc = issuedAtUtc,
            TrustedTimeFloorUtc = issuedAtUtc,
            LeaseExpiresAtUtc = deadlineUtc,
        };
        await using (var futureClockSession = new EnterpriseHarnessSession(
            new EnterpriseStartupGate(new FixedTimeProvider(deadlineUtc.AddHours(12))),
            new FakeEnterpriseHarnessHost(),
            trustedSnapshot,
            trustedTimeStore: trustedTimeStore))
        {
            AssertEqual(
                EnterpriseClientState.LeaseExpiredLocked,
                futureClockSession.CurrentDecision.ClientState);
            AssertFalse(futureClockSession.CurrentDecision.MayStartHarness);
            AssertEqual(observedUtc, trustedTimeStore.ReadFloorUtc());
        }

        var correctedUtc = observedUtc.AddMinutes(1);
        await using var correctedSession = new EnterpriseHarnessSession(
            new EnterpriseStartupGate(new FixedTimeProvider(correctedUtc)),
            new FakeEnterpriseHarnessHost(),
            trustedSnapshot,
            trustedTimeStore: trustedTimeStore);
        AssertEqual(EnterpriseClientState.Ready, correctedSession.CurrentDecision.ClientState);
        AssertTrue(correctedSession.CurrentDecision.MayStartHarness);
        AssertEqual(correctedUtc, trustedTimeStore.ReadFloorUtc());

        var futureSkewWithinLeaseUtc = deadlineUtc.AddSeconds(-1);
        AssertEqual(
            futureSkewWithinLeaseUtc,
            trustedTimeStore.Advance(futureSkewWithinLeaseUtc, deadlineUtc));
        var verifiedRecoveryUtc = correctedUtc.AddMinutes(1);
        AssertEqual(
            verifiedRecoveryUtc,
            trustedTimeStore.ReconcileVerifiedServerTime(
                verifiedRecoveryUtc,
                verifiedRecoveryUtc,
                deadlineUtc,
                localClockAccepted: true));
        AssertEqual(verifiedRecoveryUtc, trustedTimeStore.ReadFloorUtc());
    }

    private static Task EnterpriseDeviceProofKeyAsync()
    {
        var keyName = $"Ensou.Dsh.Enterprise.CoreTests.{Guid.NewGuid():N}";
        var store = new EnterpriseDeviceProofKeyStore(keyName);
        try
        {
            var identity = store.GetOrCreatePublicIdentity();
            var payload = Encoding.UTF8.GetBytes("enterprise-device-proof");
            var signature = store.Sign(payload);

            using var verifier = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint
                {
                    X = DecodeBase64Url(identity.X),
                    Y = DecodeBase64Url(identity.Y),
                },
            });
            AssertEqual("EC", identity.KeyType);
            AssertEqual("P-256", identity.Curve);
            AssertEqual(43, identity.Thumbprint.Length);
            AssertTrue(verifier.VerifyData(
                payload,
                signature,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation));

            using var key = CngKey.Open(
                keyName,
                CngProvider.MicrosoftSoftwareKeyStorageProvider,
                CngKeyOpenOptions.UserKey);
            AssertEqual(CngExportPolicies.None, key.ExportPolicy);
        }
        finally
        {
            store.DeleteForSecurityReset();
        }

        return Task.CompletedTask;
    }

    private static async Task EnterpriseDeviceProofRejectsArchivableKeyAsync()
    {
        var keyName = $"Ensou.Dsh.Enterprise.CoreTests.{Guid.NewGuid():N}";
        var provider = CngProvider.MicrosoftSoftwareKeyStorageProvider;
        var creation = new CngKeyCreationParameters
        {
            ExportPolicy = CngExportPolicies.AllowPlaintextArchiving,
            KeyCreationOptions = CngKeyCreationOptions.None,
            KeyUsage = CngKeyUsages.Signing,
            Provider = provider,
            UIPolicy = new CngUIPolicy(CngUIProtectionLevels.None),
        };

        try
        {
            using (CngKey.Create(CngAlgorithm.ECDsaP256, keyName, creation))
            {
            }

            var store = new EnterpriseDeviceProofKeyStore(keyName);
            await AssertThrowsAsync<CryptographicException>(() => Task.Run(
                store.GetOrCreatePublicIdentity));
        }
        finally
        {
            if (CngKey.Exists(keyName, provider, CngKeyOpenOptions.UserKey))
            {
                using var key = CngKey.Open(keyName, provider, CngKeyOpenOptions.UserKey);
                key.Delete();
            }
        }
    }

    private static async Task EnterpriseLocalStateRejectsParentJunctionAsync()
    {
        var paths = CreateEnterpriseDiskTestPaths();
        var exactPath = paths.Resolve(EnterpriseManagedArtifact.EnrollmentSessionDpapi);
        var junctionPath = Path.GetDirectoryName(exactPath)!;
        var outsideDirectory = Path.Combine(
            Path.GetDirectoryName(paths.ManagedRoot)!,
            "outside-security-state");
        Directory.CreateDirectory(Path.GetDirectoryName(junctionPath)!);
        Directory.CreateDirectory(outsideDirectory);
        var outsideFile = Path.Combine(outsideDirectory, Path.GetFileName(exactPath));
        await File.WriteAllTextAsync(outsideFile, "must-survive");
        CreateDirectoryJunction(junctionPath, outsideDirectory);

        try
        {
            await AssertThrowsAsync<InvalidDataException>(() =>
                EnterpriseLocalStateSecurity.ReadBoundedAsync(
                    exactPath,
                    paths.ManagedRoot,
                    CancellationToken.None));
            await AssertThrowsAsync<InvalidDataException>(() => Task.Run(() =>
                EnterpriseLocalStateSecurity.DeleteExactFile(exactPath, paths.ManagedRoot)));
            AssertEqual("must-survive", await File.ReadAllTextAsync(outsideFile));
        }
        finally
        {
            if (Directory.Exists(junctionPath))
            {
                Directory.Delete(junctionPath);
            }
        }
    }

    private static async Task EnterpriseResetExecutorBoundaryAsync()
    {
        var paths = CreateEnterpriseDiskTestPaths();
        var identityStore = new EnterpriseInstallationIdentityStore(paths);
        var identity = await identityStore.GetOrCreateAsync();
        var protectedStore = new EnterpriseProtectedArtifactStore(paths);
        await protectedStore.WriteAsync(
            EnterpriseManagedArtifact.RefreshTokenDpapi,
            Encoding.UTF8.GetBytes("refresh"));
        await protectedStore.WriteAsync(
            EnterpriseManagedArtifact.EnrollmentSessionDpapi,
            Encoding.UTF8.GetBytes("enrollment"));
        _ = new EnterpriseTrustedTimeStore(protectedStore).Advance(
            new DateTimeOffset(2026, 8, 24, 2, 0, 0, TimeSpan.Zero),
            new DateTimeOffset(2026, 8, 24, 2, 15, 0, TimeSpan.Zero));

        foreach (var artifact in new[]
        {
            EnterpriseManagedArtifact.AuthorizationLease,
            EnterpriseManagedArtifact.ApiAllocationCache,
            EnterpriseManagedArtifact.PluginPolicyCache,
            EnterpriseManagedArtifact.DeviceBindingReceipt,
        })
        {
            var path = paths.Resolve(artifact);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            await File.WriteAllTextAsync(path, artifact.ToString());
        }

        Directory.CreateDirectory(paths.HarnessHome);
        var protectedUserData = Path.Combine(paths.HarnessHome, "conversation-canary.txt");
        await File.WriteAllTextAsync(protectedUserData, "must-survive");
        paths.EnsureWorkspaceRoot();
        var protectedWorkspace = Path.Combine(paths.WorkspaceRoot, "workspace-canary.txt");
        await File.WriteAllTextAsync(protectedWorkspace, "workspace-must-survive");
        var deviceKeys = new FakeDeviceProofKeyStore();
        var executor = new EnterpriseResetExecutor(paths, deviceKeys, protectedStore);
        var resetDecision = new EnterpriseAccessDecision(
            EnterpriseClientState.DeviceRevokedResetRequired,
            MayStartHarness: false,
            MayCallManagedApi: false,
            EnterpriseResetScope.SecurityCredentials,
            EnterpriseErrorCodes.DeviceBindingRevoked);
        executor.PersistBarrier(new EnterpriseResetBarrier(
            resetDecision,
            ResetCompleted: false));
        AssertEqual(resetDecision, executor.ReadBarrier()!.Decision);

        executor.Execute(EnterpriseResetScope.ManagedConfig);
        AssertFalse(File.Exists(paths.Resolve(EnterpriseManagedArtifact.AuthorizationLease)));
        AssertFalse(File.Exists(paths.Resolve(EnterpriseManagedArtifact.ApiAllocationCache)));
        AssertFalse(File.Exists(paths.Resolve(EnterpriseManagedArtifact.PluginPolicyCache)));
        AssertTrue(File.Exists(paths.Resolve(EnterpriseManagedArtifact.DeviceBindingReceipt)));
        AssertTrue(File.Exists(paths.Resolve(EnterpriseManagedArtifact.RefreshTokenDpapi)));
        AssertTrue(File.Exists(paths.Resolve(
            EnterpriseManagedArtifact.TrustedTimeHighWaterDpapi)));
        AssertEqual(0, deviceKeys.DeleteCalls);

        executor.Execute(EnterpriseResetScope.SecurityCredentials);
        AssertTrue(Enum.GetValues<EnterpriseManagedArtifact>()
            .Where(artifact => artifact != EnterpriseManagedArtifact.ResetBarrierDpapi)
            .All(artifact => !File.Exists(paths.Resolve(artifact))));
        AssertEqual(resetDecision, executor.ReadBarrier()!.Decision);
        AssertEqual(1, deviceKeys.DeleteCalls);
        AssertTrue(File.Exists(paths.InstallationIdentityPath));
        AssertEqual(identity, await identityStore.GetOrCreateAsync());
        AssertEqual("must-survive", await File.ReadAllTextAsync(protectedUserData));
        AssertEqual(
            "workspace-must-survive",
            await File.ReadAllTextAsync(protectedWorkspace));
        executor.ClearBarrier();
        AssertFalse(File.Exists(paths.Resolve(EnterpriseManagedArtifact.ResetBarrierDpapi)));
    }

    private static async Task EnterpriseResetContinuesAfterLockedArtifactAsync()
    {
        var paths = CreateEnterpriseDiskTestPaths();
        var securityResetArtifacts = EnterpriseResetPlanner.Create(
                EnterpriseResetScope.SecurityCredentials,
                paths)
            .ExactFiles;
        foreach (var artifact in securityResetArtifacts)
        {
            var path = paths.Resolve(artifact);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            await File.WriteAllTextAsync(path, artifact.ToString());
        }

        var lockedArtifact = EnterpriseManagedArtifact.AuthorizationLease;
        var lockedPath = paths.Resolve(lockedArtifact);
        var deviceKeys = new FakeDeviceProofKeyStore();
        var executor = new EnterpriseResetExecutor(paths, deviceKeys);

        using (var lockedStream = new FileStream(
            lockedPath,
            FileMode.Open,
            FileAccess.ReadWrite,
            FileShare.None))
        {
            await AssertThrowsAsync<AggregateException>(() => Task.Run(() =>
                executor.Execute(EnterpriseResetScope.SecurityCredentials)));

            AssertTrue(File.Exists(lockedPath));
            AssertTrue(securityResetArtifacts
                .Where(artifact => artifact != lockedArtifact)
                .All(artifact => !File.Exists(paths.Resolve(artifact))));
            AssertEqual(0, deviceKeys.DeleteCalls);
        }

        executor.Execute(EnterpriseResetScope.SecurityCredentials);
        AssertFalse(File.Exists(lockedPath));
        AssertEqual(1, deviceKeys.DeleteCalls);
    }

    private static async Task EnterpriseWireStatesAsync()
    {
        foreach (var state in Enum.GetValues<QrSessionState>())
        {
            AssertEqual(
                state,
                QrSessionStateContract.ParseWireValue(
                    QrSessionStateContract.ToWireValue(state)));
        }

        foreach (var state in Enum.GetValues<EnterpriseClientState>())
        {
            AssertEqual(
                state,
                EnterpriseClientStateContract.ParseWireValue(
                    EnterpriseClientStateContract.ToWireValue(state)));
        }

        await AssertThrowsAsync<FormatException>(() => Task.Run(() =>
            QrSessionStateContract.ParseWireValue("ready")));
        AssertEqual(
            QrSessionState.DeniedEmployeeSuspended,
            QrSessionStateContract.ParseWireValue("DENIED_EMPLOYEE_SUSPENDED"));
        AssertEqual(
            QrSessionState.DeniedEmployeeRevoked,
            QrSessionStateContract.ParseWireValue("DENIED_EMPLOYEE_REVOKED"));
        await AssertThrowsAsync<FormatException>(() => Task.Run(() =>
            QrSessionStateContract.ParseWireValue("DENIED_EMPLOYEE_DISABLED")));
    }

    private static Task EnterpriseDpopProofAsync()
    {
        using var deviceKeys = new EphemeralDeviceProofKeyStore();
        var now = new DateTimeOffset(2026, 8, 24, 2, 3, 4, TimeSpan.Zero);
        var factory = new EnterpriseDpopProofFactory(
            deviceKeys,
            new FixedTimeProvider(now));
        var nonce = QrNonceVector;
        var pollSecret = QrPollSecretVector;
        var uri = new Uri($"https://control.example.test/v1/auth/qr-sessions/{BindingSessionId}");

        var proof = factory.Create(HttpMethod.Get, uri, nonce, pollSecret);
        var parts = proof.Split('.');
        AssertEqual(3, parts.Length);
        using var header = JsonDocument.Parse(DecodeBase64Url(parts[0]));
        using var payload = JsonDocument.Parse(DecodeBase64Url(parts[1]));
        AssertEqual("ES256", header.RootElement.GetProperty("alg").GetString());
        AssertEqual("dpop+jwt", header.RootElement.GetProperty("typ").GetString());
        AssertEqual("EC", header.RootElement.GetProperty("jwk").GetProperty("kty").GetString());
        AssertEqual("GET", payload.RootElement.GetProperty("htm").GetString());
        AssertEqual(uri.AbsoluteUri, payload.RootElement.GetProperty("htu").GetString());
        AssertEqual(now.ToUnixTimeSeconds(), payload.RootElement.GetProperty("iat").GetInt64());
        AssertEqual(nonce, payload.RootElement.GetProperty("nonce").GetString());
        AssertEqual(
            EncodeBase64Url(SHA256.HashData(Encoding.ASCII.GetBytes(pollSecret))),
            payload.RootElement.GetProperty("ath").GetString());
        AssertTrue(deviceKeys.Verify(
            Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}"),
            DecodeBase64Url(parts[2])));
        return Task.CompletedTask;
    }

    private static Task EnterpriseBindingPayloadAsync()
    {
        var expiresAtUtc = DateTimeOffset.FromUnixTimeSeconds(1_893_456_000);
        var vectorChallenge = new EnterpriseBindingChallenge(
            BindingSessionId,
            BindingGrantVector,
            BindingChallengeVector,
            expiresAtUtc);
        const string Expected =
            "ENSOU-DSH-BINDING-V1\n" +
            "01234567-89ab-cdef-0123-456789abcdef\n" +
            "fedcba98-7654-3210-fedc-ba9876543210\n" +
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8\n" +
            "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\n" +
            "9F3IKnUj0Ul0zqBQ4wKOi_BqjuhVqdYwNOu0-57MIwU\n" +
            "1893456000";
        var vectorPayload = EnterpriseBindingPayloadBuilder.Build(
            vectorChallenge,
            BindingInstallId,
            BindingThumbprintVector);
        AssertEqual(Expected, Encoding.UTF8.GetString(vectorPayload));
        AssertEqual(
            "808be02f4101631afd59d3592fcc3d482fed55852a3d3181173d90e42691a8ad",
            Convert.ToHexString(SHA256.HashData(vectorPayload)).ToLowerInvariant());
        AssertFalse(vectorPayload[^1] == (byte)'\n');
        CryptographicOperations.ZeroMemory(vectorPayload);

        var signatureVectorPayload = EnterpriseBindingPayloadBuilder.Build(
            new EnterpriseBindingChallenge(
                "11111111-2222-3333-4444-555555555555",
                "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8",
                "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
                new DateTimeOffset(2026, 8, 24, 6, 0, 30, TimeSpan.Zero)),
            "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            "ayY_DdALxkWIDe83lcomEHWhq_hAcYZvRn2peZf5MmM");
        AssertEqual(
            "RU5TT1UtRFNILUJJTkRJTkctVjEKMTExMTExMTEtMjIyMi0zMzMzLTQ0NDQtNTU1NTU1NTU1NTU1CmFhYWFhYWFhLWJiYmItNGNjYy04ZGRkLWVlZWVlZWVlZWVlZQpheVlfRGRBTHhrV0lEZTgzbGNvbUVIV2hxX2hBY1ladlJuMnBlWmY1TW1NCkFBRUNBd1FGQmdjSUNRb0xEQTBPRHhBUkVoTVVGUllYR0JrYUd4d2RIaDgKendreDRXaTBucGgxQThyeGl2Yi1KVHRyUFlLb0VBakQ2T0h1WjhmSTNGVQoxNzg3NTUxMjMw",
            EncodeBase64Url(signatureVectorPayload));
        using (var vectorKey = ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = DecodeBase64Url("GeF5veRROmFX_uis-vlyiTmaHE3joapdJyGpbNIpx2I"),
                Y = DecodeBase64Url("jDDNn-AtDemvuWU-jKppipj5ENMMvx9nFk9gsLzJdOo"),
            },
        }))
        {
            AssertTrue(vectorKey.VerifyData(
                signatureVectorPayload,
                DecodeBase64Url(
                    "z-zraRKktRRi1nIiZD02Lo7FZt_pjsggddvAIheRnlmWlYOVDH_0tukyTNbaZKB5akenW4jLLY_-n_30EJLqrg"),
                HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        }
        CryptographicOperations.ZeroMemory(signatureVectorPayload);

        using var deviceKeys = new EphemeralDeviceProofKeyStore();
        var identity = deviceKeys.GetOrCreatePublicIdentity();
        var challenge = new EnterpriseBindingChallenge(
            BindingSessionId,
            BindingGrantVector,
            BindingChallengeVector,
            expiresAtUtc);
        AssertFalse(challenge.ToString().Contains(BindingGrantVector, StringComparison.Ordinal));
        AssertFalse(challenge.ToString().Contains(BindingChallengeVector, StringComparison.Ordinal));
        var payload = EnterpriseBindingPayloadBuilder.Build(
            challenge,
            BindingInstallId,
            identity.Thumbprint);
        var request = EnterpriseBindingPayloadBuilder.CreateSignedRequest(
            challenge,
            BindingInstallId,
            identity.Thumbprint,
            "Employee PC",
            deviceKeys);
        AssertEqual(1, request.SchemaVersion);
        AssertEqual(1, request.BindingPayloadVersion);
        AssertEqual(86, request.DeviceSignature.Length);
        AssertTrue(deviceKeys.Verify(payload, DecodeBase64Url(request.DeviceSignature)));
        CryptographicOperations.ZeroMemory(payload);
        return Task.CompletedTask;
    }

    private static async Task EnterpriseBindingCanonicalInputsRejectedAsync()
    {
        using var deviceKeys = new EphemeralDeviceProofKeyStore();
        var identity = deviceKeys.GetOrCreatePublicIdentity();
        var expiry = new DateTimeOffset(2026, 8, 24, 2, 1, 0, TimeSpan.Zero);
        var noncanonicalGrant = BindingGrantVector[..^1] + "B";
        await AssertThrowsAsync<InvalidDataException>(() => Task.Run(() =>
            EnterpriseBindingPayloadBuilder.Build(
                new EnterpriseBindingChallenge(
                    BindingSessionId,
                    noncanonicalGrant,
                    BindingChallengeVector,
                    expiry),
                BindingInstallId,
                identity.Thumbprint)));
        await AssertThrowsAsync<InvalidDataException>(() => Task.Run(() =>
            EnterpriseBindingPayloadBuilder.Build(
                new EnterpriseBindingChallenge(
                    BindingSessionId.ToUpperInvariant(),
                    BindingGrantVector,
                    BindingChallengeVector,
                    expiry),
                BindingInstallId,
                identity.Thumbprint)));
        await AssertThrowsAsync<InvalidDataException>(() => Task.Run(() =>
            EnterpriseBindingPayloadBuilder.CreateSignedRequest(
                new EnterpriseBindingChallenge(
                    BindingSessionId,
                    BindingGrantVector,
                    BindingChallengeVector,
                    expiry),
                BindingInstallId,
                identity.Thumbprint,
                " Employee PC ",
                deviceKeys)));

        var now = new DateTimeOffset(2026, 8, 24, 2, 0, 0, TimeSpan.Zero);
        using var httpClient = new HttpClient(new DelegateHandler(_ =>
            throw new InvalidOperationException("Invalid idempotency key must fail before HTTP.")));
        var bindingClient = CreateBindingHttpClient(httpClient, deviceKeys, now);
        await AssertThrowsAsync<InvalidDataException>(() => bindingClient.CompleteAsync(
            CreateBindingRequest(deviceKeys, now),
            new string('i', 43)));
        var qrClient = CreateQrHttpClient(httpClient, deviceKeys, now);
        await AssertThrowsAsync<InvalidDataException>(() => qrClient.CreateSessionAsync(
            CreateQrRequest(identity),
            new string('i', 43)));

        var validQrRequest = CreateQrRequest(identity);
        var uppercaseInstallRequest = new EnterpriseQrSessionCreateRequest
        {
            AuthorizationMethod = validQrRequest.AuthorizationMethod,
            InstallId = validQrRequest.InstallId.ToUpperInvariant(),
            DeviceJwk = validQrRequest.DeviceJwk,
            DeviceKeyThumbprint = validQrRequest.DeviceKeyThumbprint,
            DeviceDisplayName = validQrRequest.DeviceDisplayName,
            LauncherVersion = validQrRequest.LauncherVersion,
            RuntimeVersion = validQrRequest.RuntimeVersion,
            Platform = validQrRequest.Platform,
            Nonce = validQrRequest.Nonce,
        };
        await AssertThrowsAsync<InvalidDataException>(() => qrClient.CreateSessionAsync(
            uppercaseInstallRequest,
            BindingIdempotencyKey));

        var noncanonicalCoordinateRequest = new EnterpriseQrSessionCreateRequest
        {
            AuthorizationMethod = validQrRequest.AuthorizationMethod,
            InstallId = validQrRequest.InstallId,
            DeviceJwk = new EnterpriseEcPublicJwk
            {
                KeyType = validQrRequest.DeviceJwk.KeyType,
                Curve = validQrRequest.DeviceJwk.Curve,
                X = validQrRequest.DeviceJwk.X[..^1] + "B",
                Y = validQrRequest.DeviceJwk.Y,
            },
            DeviceKeyThumbprint = validQrRequest.DeviceKeyThumbprint,
            DeviceDisplayName = validQrRequest.DeviceDisplayName,
            LauncherVersion = validQrRequest.LauncherVersion,
            RuntimeVersion = validQrRequest.RuntimeVersion,
            Platform = validQrRequest.Platform,
            Nonce = validQrRequest.Nonce,
        };
        await AssertThrowsAsync<InvalidDataException>(() => qrClient.CreateSessionAsync(
            noncanonicalCoordinateRequest,
            BindingIdempotencyKey));

        var invalidPlatformRequest = new EnterpriseQrSessionCreateRequest
        {
            AuthorizationMethod = validQrRequest.AuthorizationMethod,
            InstallId = validQrRequest.InstallId,
            DeviceJwk = validQrRequest.DeviceJwk,
            DeviceKeyThumbprint = validQrRequest.DeviceKeyThumbprint,
            DeviceDisplayName = validQrRequest.DeviceDisplayName,
            LauncherVersion = validQrRequest.LauncherVersion,
            RuntimeVersion = validQrRequest.RuntimeVersion,
            Platform = "windows-arm64",
            Nonce = validQrRequest.Nonce,
        };
        await AssertThrowsAsync<InvalidDataException>(() => qrClient.CreateSessionAsync(
            invalidPlatformRequest,
            BindingIdempotencyKey));

        var invalidVersionRequest = new EnterpriseQrSessionCreateRequest
        {
            AuthorizationMethod = validQrRequest.AuthorizationMethod,
            InstallId = validQrRequest.InstallId,
            DeviceJwk = validQrRequest.DeviceJwk,
            DeviceKeyThumbprint = validQrRequest.DeviceKeyThumbprint,
            DeviceDisplayName = validQrRequest.DeviceDisplayName,
            LauncherVersion = "release version",
            RuntimeVersion = validQrRequest.RuntimeVersion,
            Platform = validQrRequest.Platform,
            Nonce = validQrRequest.Nonce,
        };
        await AssertThrowsAsync<InvalidDataException>(() => qrClient.CreateSessionAsync(
            invalidVersionRequest,
            BindingIdempotencyKey));

        var mismatchedThumbprintRequest = new EnterpriseQrSessionCreateRequest
        {
            AuthorizationMethod = validQrRequest.AuthorizationMethod,
            InstallId = validQrRequest.InstallId,
            DeviceJwk = validQrRequest.DeviceJwk,
            DeviceKeyThumbprint = BindingThumbprintVector,
            DeviceDisplayName = validQrRequest.DeviceDisplayName,
            LauncherVersion = validQrRequest.LauncherVersion,
            RuntimeVersion = validQrRequest.RuntimeVersion,
            Platform = validQrRequest.Platform,
            Nonce = validQrRequest.Nonce,
        };
        await AssertThrowsAsync<InvalidDataException>(() => qrClient.CreateSessionAsync(
            mismatchedThumbprintRequest,
            BindingIdempotencyKey));

        using var otherDeviceKeys = new EphemeralDeviceProofKeyStore();
        var foreignQrRequest = CreateQrRequest(otherDeviceKeys.GetOrCreatePublicIdentity());
        await AssertThrowsAsync<InvalidDataException>(() => qrClient.CreateSessionAsync(
            foreignQrRequest,
            BindingIdempotencyKey));
        var foreignBindingRequest = CreateBindingRequest(otherDeviceKeys, now);
        await AssertThrowsAsync<InvalidDataException>(() => bindingClient.CompleteAsync(
            foreignBindingRequest,
            BindingIdempotencyKey));

        using var invalidSessionHttp = new HttpClient(new DelegateHandler(_ => CreatedJsonResponse($$"""
            {
              "session_id":"{{BindingSessionId.ToUpperInvariant()}}",
              "poll_secret":"{{QrPollSecretVector}}",
              "authorization_url":"https://login.example.test/activate",
              "device_display_name":"{{QrDeviceDisplayName}}",
              "confirmation_code":"{{QrConfirmationCode}}",
              "expires_at":"2026-08-24T02:02:00Z",
              "poll_after_seconds":2
            }
            """)));
        var invalidSessionClient = CreateQrHttpClient(invalidSessionHttp, deviceKeys, now);
        await AssertThrowsAsync<InvalidDataException>(() => invalidSessionClient.CreateSessionAsync(
            validQrRequest,
            BindingIdempotencyKey));

        using var invalidPollSecretHttp = new HttpClient(new DelegateHandler(_ => CreatedJsonResponse($$"""
            {
              "session_id":"{{BindingSessionId}}",
              "poll_secret":"{{QrPollSecretVector[..^1]}}B",
              "authorization_url":"https://login.example.test/activate",
              "device_display_name":"{{QrDeviceDisplayName}}",
              "confirmation_code":"{{QrConfirmationCode}}",
              "expires_at":"2026-08-24T02:02:00Z",
              "poll_after_seconds":2
            }
            """)));
        var invalidPollSecretClient = CreateQrHttpClient(invalidPollSecretHttp, deviceKeys, now);
        await AssertThrowsAsync<InvalidDataException>(() => invalidPollSecretClient.CreateSessionAsync(
            validQrRequest,
            BindingIdempotencyKey));
    }

    private static async Task EnterpriseBindingHttpClientAsync()
    {
        using var deviceKeys = new EphemeralDeviceProofKeyStore();
        var now = new DateTimeOffset(2026, 8, 24, 2, 0, 0, TimeSpan.Zero);
        var request = CreateBindingRequest(deviceKeys, now);
        var lease = CreateCompactLease();
        var calls = 0;
        using var httpClient = new HttpClient(new DelegateHandler(message =>
        {
            calls++;
            AssertEqual(HttpMethod.Post, message.Method);
            AssertEqual(
                "https://control.example.test/v1/device-bindings/complete",
                message.RequestUri!.AbsoluteUri);
            AssertFalse(message.RequestUri.Query.Contains("grant", StringComparison.OrdinalIgnoreCase));
            AssertTrue(message.Headers.Contains("Idempotency-Key"));
            AssertTrue(message.Headers.Contains("DPoP"));

            var body = message.Content!.ReadAsStringAsync().GetAwaiter().GetResult();
            using var document = JsonDocument.Parse(body);
            var root = document.RootElement;
            AssertEqual(1, root.GetProperty("schema_version").GetInt32());
            AssertEqual(1, root.GetProperty("binding_payload_version").GetInt32());
            AssertEqual(request.SessionId, root.GetProperty("session_id").GetString());
            AssertEqual(request.InstallId, root.GetProperty("install_id").GetString());
            AssertEqual(request.DeviceSignature, root.GetProperty("device_signature").GetString());
            AssertEqual(
                "2026-08-24T02:01:00Z",
                root.GetProperty("binding_challenge_expires_at").GetString());

            var canonical = EnterpriseBindingPayloadBuilder.Build(
                new EnterpriseBindingChallenge(
                    request.SessionId,
                    request.BindGrant,
                    request.BindingChallenge,
                    request.BindingChallengeExpiresAtUtc),
                request.InstallId,
                request.DeviceKeyThumbprint);
            AssertTrue(deviceKeys.Verify(canonical, DecodeBase64Url(request.DeviceSignature)));
            CryptographicOperations.ZeroMemory(canonical);

            var proof = message.Headers.GetValues("DPoP").Single();
            var proofParts = proof.Split('.');
            using var proofPayload = JsonDocument.Parse(DecodeBase64Url(proofParts[1]));
            AssertEqual(request.BindingChallenge, proofPayload.RootElement.GetProperty("nonce").GetString());
            AssertEqual(
                EncodeBase64Url(SHA256.HashData(Encoding.ASCII.GetBytes(request.BindGrant))),
                proofPayload.RootElement.GetProperty("ath").GetString());

            return CreatedJsonResponse($$"""
                {
                  "schema_version":1,
                  "binding_id":"{{BindingId}}",
                  "refresh_token":"{{RefreshTokenVector}}",
                  "access_token":"{{new string('a', 43)}}",
                  "access_token_expires_at":"{{now.AddMinutes(10):yyyy-MM-ddTHH:mm:ssZ}}",
                  "authorization_lease":"{{lease}}",
                  "lease_expires_at":"{{now.AddMinutes(15):yyyy-MM-ddTHH:mm:ssZ}}",
                  "server_time":"{{now:yyyy-MM-ddTHH:mm:ssZ}}"
                }
                """);
        }));
        var client = CreateBindingHttpClient(httpClient, deviceKeys, now);

        var response = await client.CompleteAsync(request, BindingIdempotencyKey);

        AssertEqual(1, calls);
        AssertEqual(BindingId, response.BindingId);
        AssertEqual(lease, response.AuthorizationLease);
        var envelope = EnterpriseSignedLeaseEnvelopeParser.Parse(response.AuthorizationLease);
        AssertEqual(3, envelope.CompactJws.Split('.').Length);
        AssertFalse(envelope.ToString().Contains(lease, StringComparison.Ordinal));

        var exactRequestBody = EnterpriseDeviceBindingClient.SerializeExactRequest(request);
        try
        {
            var recoveryClient = CreateBindingHttpClient(
                httpClient,
                deviceKeys,
                now.AddDays(1));
            var replay = await recoveryClient.CompleteExactAsync(
                exactRequestBody,
                BindingIdempotencyKey);
            AssertEqual(BindingId, replay.BindingId);
            AssertEqual(2, calls);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(exactRequestBody);
        }
    }

    private static async Task EnterpriseBindingRedirectRejectedAsync()
    {
        using var deviceKeys = new EphemeralDeviceProofKeyStore();
        var now = new DateTimeOffset(2026, 8, 24, 2, 0, 0, TimeSpan.Zero);
        using var httpClient = new HttpClient(new DelegateHandler(_ => new HttpResponseMessage(
            HttpStatusCode.Redirect)
        {
            Headers = { Location = new Uri("https://evil.example.test/") },
        }));
        var client = CreateBindingHttpClient(httpClient, deviceKeys, now);

        await AssertThrowsAsync<HttpRequestException>(() => client.CompleteAsync(
            CreateBindingRequest(deviceKeys, now),
            BindingIdempotencyKey));
    }

    private static async Task EnterpriseBindingStrictJsonAsync()
    {
        using var deviceKeys = new EphemeralDeviceProofKeyStore();
        var now = new DateTimeOffset(2026, 8, 24, 2, 0, 0, TimeSpan.Zero);
        using var httpClient = new HttpClient(new DelegateHandler(_ => CreatedJsonResponse($$"""
            {
              "schema_version":1,
              "binding_id":"{{BindingId}}",
              "refresh_token":"{{RefreshTokenVector}}",
              "access_token":"{{new string('a', 43)}}",
              "access_token_expires_at":"{{now.AddMinutes(10):yyyy-MM-ddTHH:mm:ssZ}}",
              "authorization_lease":"{{CreateCompactLease()}}",
              "lease_expires_at":"{{now.AddMinutes(15):yyyy-MM-ddTHH:mm:ssZ}}",
              "server_time":"{{now:yyyy-MM-ddTHH:mm:ssZ}}",
              "unexpected":"rejected"
            }
            """)));
        var client = CreateBindingHttpClient(httpClient, deviceKeys, now);

        await AssertThrowsAsync<JsonException>(() => client.CompleteAsync(
            CreateBindingRequest(deviceKeys, now),
            BindingIdempotencyKey));

        using var noncanonicalTimeHttp = new HttpClient(new DelegateHandler(_ => CreatedJsonResponse($$"""
            {
              "schema_version":1,
              "binding_id":"{{BindingId}}",
              "refresh_token":"{{RefreshTokenVector}}",
              "access_token":"{{new string('a', 43)}}",
              "access_token_expires_at":"2026-08-24T02:10:00+00:00",
              "authorization_lease":"{{CreateCompactLease()}}",
              "lease_expires_at":"2026-08-24T02:15:00Z",
              "server_time":"2026-08-24T02:00:00Z"
            }
            """)));
        var noncanonicalTimeClient = CreateBindingHttpClient(
            noncanonicalTimeHttp,
            deviceKeys,
            now);
        await AssertThrowsAsync<JsonException>(() => noncanonicalTimeClient.CompleteAsync(
            CreateBindingRequest(deviceKeys, now),
            BindingIdempotencyKey));
    }

    private static async Task EnterpriseBindingOversizedResponseRejectedAsync()
    {
        using var deviceKeys = new EphemeralDeviceProofKeyStore();
        var now = new DateTimeOffset(2026, 8, 24, 2, 0, 0, TimeSpan.Zero);
        using var httpClient = new HttpClient(new DelegateHandler(_ => CreatedJsonResponse(
            new string('x', 65 * 1024))));
        var client = CreateBindingHttpClient(httpClient, deviceKeys, now);

        await AssertThrowsAsync<InvalidDataException>(() => client.CompleteAsync(
            CreateBindingRequest(deviceKeys, now),
            BindingIdempotencyKey));
    }

    private static async Task EnterpriseBindingMalformedLeaseRejectedAsync()
    {
        using var deviceKeys = new EphemeralDeviceProofKeyStore();
        var now = new DateTimeOffset(2026, 8, 24, 2, 0, 0, TimeSpan.Zero);
        using var httpClient = new HttpClient(new DelegateHandler(_ => CreatedJsonResponse($$"""
            {
              "schema_version":1,
              "binding_id":"{{BindingId}}",
              "refresh_token":"{{RefreshTokenVector}}",
              "access_token":"{{new string('a', 43)}}",
              "access_token_expires_at":"{{now.AddMinutes(10):yyyy-MM-ddTHH:mm:ssZ}}",
              "authorization_lease":"not-a-compact-jws",
              "lease_expires_at":"{{now.AddMinutes(15):yyyy-MM-ddTHH:mm:ssZ}}",
              "server_time":"{{now:yyyy-MM-ddTHH:mm:ssZ}}"
            }
            """)));
        var client = CreateBindingHttpClient(httpClient, deviceKeys, now);

        await AssertThrowsAsync<InvalidDataException>(() => client.CompleteAsync(
            CreateBindingRequest(deviceKeys, now),
            BindingIdempotencyKey));
        await AssertThrowsAsync<InvalidDataException>(() => Task.Run(() =>
            EnterpriseSignedLeaseEnvelopeParser.Parse(CreateCompactLease("JWT"))));
    }

    private static Task EnterpriseAuthorizationLeaseFixtureAsync()
    {
        var fixture = LoadAuthorizationLeaseFixture();
        var verifier = CreateAuthorizationLeaseVerifier(fixture);
        var verified = verifier.Verify(
            fixture.CompactJws,
            new EnterpriseAuthorizationLeaseVerificationContext(
                fixture.BindingId,
                fixture.InstallationId,
                fixture.DeviceKeyThumbprint,
                fixture.EvaluationTimeUtc,
                fixture.EvaluationTimeUtc));

        AssertEqual(fixture.LeaseId, verified.Claims.LeaseId);
        AssertEqual(fixture.BindingId, verified.Claims.BindingId);
        AssertEqual(fixture.InstallationId, verified.Claims.InstallationId);
        AssertEqual(fixture.DeviceKeyThumbprint, verified.Claims.DeviceKeyThumbprint);
        AssertEqual("PILOT", verified.Claims.RolloutChannel);
        AssertEqual(fixture.EvaluationTimeUtc, verified.Claims.IssuedAtUtc);
        AssertEqual(fixture.EvaluationTimeUtc.AddMinutes(15), verified.Claims.ExpiresAtUtc);
        AssertTrue(verified.AccessSnapshot.LeaseSignatureValid);
        AssertTrue(verified.AccessSnapshot.AuthorizationEpochMatches);
        AssertEqual(
            verified.Claims.PluginPolicyId,
            verified.AccessSnapshot.PluginPolicyId);
        AssertEqual(
            verified.Claims.PluginPolicyGeneration,
            verified.AccessSnapshot.PluginPolicyGeneration);
        AssertEqual(
            verified.Claims.PluginPolicySha256,
            verified.AccessSnapshot.PluginPolicySha256);
        AssertEqual(new string('a', 64), verified.Claims.PluginPolicySha256);

        var decision = EnterpriseAccessEvaluator.Evaluate(
            verified.AccessSnapshot,
            fixture.EvaluationTimeUtc);
        AssertEqual(EnterpriseClientState.Ready, decision.ClientState);
        AssertTrue(decision.MayStartHarness);
        AssertTrue(decision.MayCallManagedApi);
        AssertEqual(EnterpriseResetScope.None, decision.ResetScope);
        AssertEqual<string?>(null, decision.ErrorCode);
        return Task.CompletedTask;
    }

    private static Task EnterpriseWorkspaceRootAsync()
    {
        var root = Path.Combine(TempRoot, $"workspace-{Guid.NewGuid():N}");
        var local = Path.Combine(root, "LocalAppData");
        var profile = Path.Combine(root, "Profile");
        Directory.CreateDirectory(local);
        Directory.CreateDirectory(profile);
        var paths = EnterpriseManagedPaths.Create(local, profile);
        paths.EnsureWorkspaceRoot();
        paths.ValidateWorkspaceRoot();
        AssertTrue(Directory.Exists(paths.WorkspaceRoot));
        AssertTrue(paths.IsInsideHarnessHome(paths.WorkspaceRoot));
        AssertFalse(paths.IsInsideManagedRoot(paths.WorkspaceRoot));

        var shell = paths.CreateOpenWorkspaceStartInfo();
        AssertEqual(paths.WorkspaceRoot, shell.FileName);
        AssertEqual(paths.WorkspaceRoot, shell.WorkingDirectory);
        AssertTrue(shell.UseShellExecute);
        AssertEqual(0, shell.ArgumentList.Count);
        AssertFalse(shell.FileName.EndsWith("cmd.exe", StringComparison.OrdinalIgnoreCase));
        AssertFalse(shell.FileName.EndsWith("powershell.exe", StringComparison.OrdinalIgnoreCase));

        var outsideWorkspace = Path.Combine(root, "outside-workspace");
        Directory.CreateDirectory(outsideWorkspace);
        Directory.Delete(paths.WorkspaceRoot);
        CreateDirectoryJunction(paths.WorkspaceRoot, outsideWorkspace);
        try
        {
            var rejectedWorkspaceLink = false;
            try
            {
                paths.ValidateWorkspaceRoot();
            }
            catch (InvalidDataException)
            {
                rejectedWorkspaceLink = true;
            }
            AssertTrue(rejectedWorkspaceLink);
        }
        finally
        {
            Directory.Delete(paths.WorkspaceRoot);
        }

        var development = EnterpriseManagedPaths.CreateDevelopmentE2E(local, profile);
        development.EnsureWorkspaceRoot();
        AssertFalse(string.Equals(
            development.WorkspaceRoot,
            paths.WorkspaceRoot,
            StringComparison.OrdinalIgnoreCase));
        AssertTrue(development.IsInsideHarnessHome(development.WorkspaceRoot));
        AssertFalse(development.IsInsideManagedRoot(development.WorkspaceRoot));

        var managedSkills = Path.Combine(
            paths.PluginRoot,
            "policy-1",
            "skills");
        Directory.CreateDirectory(managedSkills);
        paths.ValidateManagedSkillsRoot(managedSkills);
        AssertTrue(paths.IsInsidePluginRoot(managedSkills));
        var outsideSkillsRejected = false;
        try
        {
            paths.ValidateManagedSkillsRoot(Path.Combine(root, "outside-skills"));
        }
        catch (InvalidDataException)
        {
            outsideSkillsRejected = true;
        }
        AssertTrue(outsideSkillsRejected);
        return Task.CompletedTask;
    }

    private static Task EnterpriseDpopOptionalNonceAsync()
    {
        using var deviceKeys = new EphemeralDeviceProofKeyStore();
        var now = new DateTimeOffset(2026, 8, 24, 2, 3, 4, TimeSpan.Zero);
        var factory = new EnterpriseDpopProofFactory(
            deviceKeys,
            new FixedTimeProvider(now));
        var uri = new Uri("https://control.example.test/v1/auth/refresh");

        var first = factory.Create(
            HttpMethod.Post,
            uri,
            authorizationSecret: RefreshTokenVector);
        var second = factory.Create(
            HttpMethod.Post,
            uri,
            authorizationSecret: RefreshTokenVector);
        var firstParts = first.Split('.');
        var secondParts = second.Split('.');
        using var firstPayload = JsonDocument.Parse(DecodeBase64Url(firstParts[1]));
        using var secondPayload = JsonDocument.Parse(DecodeBase64Url(secondParts[1]));

        AssertFalse(firstPayload.RootElement.TryGetProperty("nonce", out _));
        AssertEqual(
            EncodeBase64Url(SHA256.HashData(Encoding.ASCII.GetBytes(RefreshTokenVector))),
            firstPayload.RootElement.GetProperty("ath").GetString());
        AssertFalse(string.Equals(
            firstPayload.RootElement.GetProperty("jti").GetString(),
            secondPayload.RootElement.GetProperty("jti").GetString(),
            StringComparison.Ordinal));
        AssertTrue(deviceKeys.Verify(
            Encoding.ASCII.GetBytes($"{firstParts[0]}.{firstParts[1]}"),
            DecodeBase64Url(firstParts[2])));
        return Task.CompletedTask;
    }

    private static async Task EnterpriseAuthorizationLeaseTamperingAsync()
    {
        var fixture = LoadAuthorizationLeaseFixture();
        var verifier = CreateAuthorizationLeaseVerifier(fixture);
        var context = new EnterpriseAuthorizationLeaseVerificationContext(
            fixture.BindingId,
            fixture.InstallationId,
            fixture.DeviceKeyThumbprint,
            fixture.EvaluationTimeUtc,
            fixture.EvaluationTimeUtc);
        var parts = fixture.CompactJws.Split('.');

        var signature = DecodeBase64Url(parts[2]);
        try
        {
            signature[0] ^= 0x01;
            var signatureBitFlip = $"{parts[0]}.{parts[1]}.{EncodeBase64Url(signature)}";
            await AssertThrowsAsync<InvalidDataException>(() => Task.Run(() =>
                verifier.Verify(signatureBitFlip, context)));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(signature);
        }

        var payload = DecodeBase64Url(parts[1]);
        try
        {
            payload[0] ^= 0x01;
            var payloadBitFlip = $"{parts[0]}.{EncodeBase64Url(payload)}.{parts[2]}";
            await AssertThrowsAsync<InvalidDataException>(() => Task.Run(() =>
                verifier.Verify(payloadBitFlip, context)));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(payload);
        }

        var unknownKidHeader = fixture.HeaderJson.Replace(
            "\"kid\":\"lease-test-2026-01\"",
            "\"kid\":\"unknown-lease-key\"",
            StringComparison.Ordinal);
        var unknownKid = $"{EncodeBase64Url(Encoding.UTF8.GetBytes(unknownKidHeader))}.{parts[1]}.{parts[2]}";
        await AssertThrowsAsync<InvalidDataException>(() => Task.Run(() =>
            verifier.Verify(unknownKid, context)));

        var duplicatePayload = fixture.PayloadJson.Insert(
            fixture.PayloadJson.Length - 1,
            ",\"jti\":\"bbbbbbbb-0000-4000-8000-000000000001\"");
        var duplicateClaim = SignAuthorizationLeasePayload(fixture, duplicatePayload);
        await AssertThrowsAsync<InvalidDataException>(() => Task.Run(() =>
            verifier.Verify(duplicateClaim, context)));

        var unknownClaimPayload = fixture.PayloadJson.Insert(
            fixture.PayloadJson.Length - 1,
            ",\"unknown_claim\":1");
        var unknownClaim = SignAuthorizationLeasePayload(fixture, unknownClaimPayload);
        await AssertThrowsAsync<InvalidDataException>(() => Task.Run(() =>
            verifier.Verify(unknownClaim, context)));

        var uppercasePolicyHashPayload = fixture.PayloadJson.Replace(
            $"\"plugin_policy_sha256\":\"{new string('a', 64)}\"",
            $"\"plugin_policy_sha256\":\"{new string('A', 64)}\"",
            StringComparison.Ordinal);
        var uppercasePolicyHash = SignAuthorizationLeasePayload(
            fixture,
            uppercasePolicyHashPayload);
        await AssertThrowsAsync<InvalidDataException>(() => Task.Run(() =>
            verifier.Verify(uppercasePolicyHash, context)));
    }

    private static async Task EnterprisePendingBindingTransactionRoundTripAsync()
    {
        using var deviceKeys = new EphemeralDeviceProofKeyStore();
        var now = new DateTimeOffset(2026, 8, 24, 2, 0, 0, TimeSpan.Zero);
        var request = CreateBindingRequest(deviceKeys, now);
        var exactRequestBody = EnterpriseDeviceBindingClient.SerializeExactRequest(request);
        var expectedBody = exactRequestBody.ToArray();
        var idempotencyKey = EncodeBase64Url(RandomNumberGenerator.GetBytes(32));
        var paths = CreateEnterpriseDiskTestPaths();
        var store = new EnterprisePendingBindingTransactionStore(
            new EnterpriseProtectedArtifactStore(paths));

        try
        {
            await store.WriteNewAsync(exactRequestBody, idempotencyKey, now);
            using var pending = await store.ReadAsync()
                ?? throw new InvalidOperationException("Pending binding transaction was not persisted.");
            AssertSequenceEqual(expectedBody, pending.ExactRequestBody.ToArray());
            AssertEqual(idempotencyKey, pending.IdempotencyKey);
            AssertEqual(now, pending.CreatedAtUtc);

            var duplicateRequest = Encoding.UTF8.GetBytes(
                Encoding.UTF8.GetString(exactRequestBody.AsSpan()).Insert(
                    exactRequestBody.Length - 1,
                    $",\"install_id\":\"{request.InstallId}\""));
            try
            {
                await AssertThrowsAsync<JsonException>(() => Task.Run(() =>
                    EnterpriseDeviceBindingClient.DeserializeExactRequest(
                        duplicateRequest)));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(duplicateRequest);
            }
        }
        finally
        {
            store.Delete();
            CryptographicOperations.ZeroMemory(exactRequestBody);
            CryptographicOperations.ZeroMemory(expectedBody);
        }

        AssertFalse(File.Exists(paths.Resolve(
            EnterpriseManagedArtifact.PendingBindingTransactionDpapi)));
    }

    private static async Task EnterpriseRefreshHttpClientAsync()
    {
        using var deviceKeys = new EphemeralDeviceProofKeyStore();
        var now = new DateTimeOffset(2026, 8, 24, 2, 0, 0, TimeSpan.Zero);
        var request = new EnterpriseRefreshRequest
        {
            BindingId = BindingId,
            InstallId = BindingInstallId,
            PreviousLeaseId = "bbbbbbbb-0000-4000-8000-000000000001",
            AuthorizationEpoch = 4,
            EntitlementEpoch = 5,
            BindingEpoch = 6,
        };
        var lease = CreateCompactLease();
        var calls = 0;
        using var httpClient = new HttpClient(new DelegateHandler(message =>
        {
            calls++;
            AssertEqual(HttpMethod.Post, message.Method);
            AssertEqual(
                "https://control.example.test/v1/auth/refresh",
                message.RequestUri!.AbsoluteUri);
            AssertEqual("Refresh", message.Headers.Authorization!.Scheme);
            AssertEqual(RefreshTokenVector, message.Headers.Authorization.Parameter);
            AssertEqual(BindingIdempotencyKey, message.Headers.GetValues("Idempotency-Key").Single());

            var body = message.Content!.ReadAsStringAsync().GetAwaiter().GetResult();
            using var bodyDocument = JsonDocument.Parse(body);
            var root = bodyDocument.RootElement;
            AssertEqual(7, root.EnumerateObject().Count());
            AssertEqual(1, root.GetProperty("schema_version").GetInt32());
            AssertEqual(BindingId, root.GetProperty("binding_id").GetString());
            AssertEqual(BindingInstallId, root.GetProperty("install_id").GetString());
            AssertEqual(request.PreviousLeaseId, root.GetProperty("previous_lease_id").GetString());
            AssertEqual(4L, root.GetProperty("auth_epoch").GetInt64());
            AssertEqual(5L, root.GetProperty("entitlement_epoch").GetInt64());
            AssertEqual(6L, root.GetProperty("binding_epoch").GetInt64());

            var proof = message.Headers.GetValues("DPoP").Single();
            var proofParts = proof.Split('.');
            using var proofPayload = JsonDocument.Parse(DecodeBase64Url(proofParts[1]));
            AssertEqual("POST", proofPayload.RootElement.GetProperty("htm").GetString());
            AssertEqual(
                message.RequestUri.AbsoluteUri,
                proofPayload.RootElement.GetProperty("htu").GetString());
            AssertFalse(proofPayload.RootElement.TryGetProperty("nonce", out _));
            AssertEqual(
                EncodeBase64Url(SHA256.HashData(Encoding.ASCII.GetBytes(RefreshTokenVector))),
                proofPayload.RootElement.GetProperty("ath").GetString());

            return JsonResponse($$"""
                {
                  "schema_version":1,
                  "binding_id":"{{BindingId}}",
                  "refresh_token":"{{EncodeBase64Url(Enumerable.Range(32, 32).Select(value => (byte)value).ToArray())}}",
                  "access_token":"{{new string('r', 43)}}",
                  "access_token_expires_at":"{{now.AddMinutes(10):yyyy-MM-ddTHH:mm:ssZ}}",
                  "authorization_lease":"{{lease}}",
                  "lease_expires_at":"{{now.AddMinutes(15):yyyy-MM-ddTHH:mm:ssZ}}",
                  "server_time":"{{now:yyyy-MM-ddTHH:mm:ssZ}}"
                }
                """);
        }));
        var client = new EnterpriseRefreshClient(
            httpClient,
            new EnterpriseControlPlaneOptions(
                new Uri("https://control.example.test/"),
                new Uri("https://login.example.test/")),
            new EnterpriseDpopProofFactory(deviceKeys, new FixedTimeProvider(now)),
            new FixedTimeProvider(now));

        var response = await client.RefreshAsync(
            request,
            RefreshTokenVector,
            BindingIdempotencyKey);
        AssertEqual(BindingId, response.BindingId);
        AssertEqual(1, calls);

        var exactBody = EnterpriseRefreshClient.SerializeExactRequest(request);
        try
        {
            var replayClient = new EnterpriseRefreshClient(
                httpClient,
                new EnterpriseControlPlaneOptions(
                    new Uri("https://control.example.test/"),
                    new Uri("https://login.example.test/")),
                new EnterpriseDpopProofFactory(deviceKeys, new FixedTimeProvider(now.AddDays(1))),
                new FixedTimeProvider(now.AddDays(1)));
            _ = await replayClient.RefreshExactAsync(
                exactBody,
                RefreshTokenVector,
                BindingIdempotencyKey);
            AssertEqual(2, calls);

            var duplicateBody = Encoding.UTF8.GetBytes(
                Encoding.UTF8.GetString(exactBody).Insert(
                    exactBody.Length - 1,
                    $",\"binding_id\":\"{BindingId}\""));
            try
            {
                await AssertThrowsAsync<JsonException>(() => Task.Run(() =>
                    EnterpriseRefreshClient.DeserializeExactRequest(duplicateBody)));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(duplicateBody);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(exactBody);
        }

        using var wrongStatusHttp = new HttpClient(new DelegateHandler(_ =>
            CreatedJsonResponse($$"""
                {
                  "schema_version":1,
                  "binding_id":"{{BindingId}}",
                  "refresh_token":"{{RefreshTokenVector}}",
                  "access_token":"{{new string('r', 43)}}",
                  "access_token_expires_at":"{{now.AddMinutes(10):yyyy-MM-ddTHH:mm:ssZ}}",
                  "authorization_lease":"{{lease}}",
                  "lease_expires_at":"{{now.AddMinutes(15):yyyy-MM-ddTHH:mm:ssZ}}",
                  "server_time":"{{now:yyyy-MM-ddTHH:mm:ssZ}}"
                }
                """)));
        var wrongStatusClient = new EnterpriseRefreshClient(
            wrongStatusHttp,
            new EnterpriseControlPlaneOptions(
                new Uri("https://control.example.test/"),
                new Uri("https://login.example.test/")),
            new EnterpriseDpopProofFactory(deviceKeys, new FixedTimeProvider(now)),
            new FixedTimeProvider(now));
        await AssertThrowsAsync<InvalidDataException>(() => wrongStatusClient.RefreshAsync(
            request,
            RefreshTokenVector,
            BindingIdempotencyKey));
    }

    private static async Task EnterpriseRefreshRejectsUntrustedResetContractAsync()
    {
        using var deviceKeys = new EphemeralDeviceProofKeyStore();
        var now = new DateTimeOffset(2026, 8, 24, 2, 0, 0, TimeSpan.Zero);
        var request = new EnterpriseRefreshRequest
        {
            BindingId = BindingId,
            InstallId = BindingInstallId,
            PreviousLeaseId = "bbbbbbbb-0000-4000-8000-000000000001",
            AuthorizationEpoch = 4,
            EntitlementEpoch = 5,
            BindingEpoch = 6,
        };

        await AssertRejectedAsync("""
            {
              "error": {
                "code":"EMPLOYEE_SUSPENDED",
                "message":"account suspended",
                "client_state":"ACCOUNT_LOCKED",
                "retryable":false,
                "request_id":"request-unsafe-reset",
                "reset_scope":"SECURITY_CREDENTIALS"
              }
            }
            """);
        await AssertRejectedAsync("""
            {
              "error": {
                "code":"FUTURE_SECURITY_ERROR",
                "message":"future server contract",
                "client_state":"SECURITY_QUARANTINED",
                "retryable":false,
                "request_id":"request-unknown-reset",
                "reset_scope":"SECURITY_CREDENTIALS"
              }
            }
            """);

        async Task AssertRejectedAsync(string responseBody)
        {
            using var httpClient = new HttpClient(new DelegateHandler(_ =>
                JsonResponse(responseBody, HttpStatusCode.Forbidden)));
            var client = new EnterpriseRefreshClient(
                httpClient,
                new EnterpriseControlPlaneOptions(
                    new Uri("https://control.example.test/"),
                    new Uri("https://login.example.test/")),
                new EnterpriseDpopProofFactory(deviceKeys, new FixedTimeProvider(now)),
                new FixedTimeProvider(now));
            await AssertThrowsAsync<InvalidDataException>(() => client.RefreshAsync(
                request,
                RefreshTokenVector,
                BindingIdempotencyKey));
        }
    }

    private static async Task EnterprisePendingRefreshTransactionRoundTripAsync()
    {
        var now = new DateTimeOffset(2026, 8, 24, 2, 0, 0, TimeSpan.Zero);
        var request = new EnterpriseRefreshRequest
        {
            BindingId = BindingId,
            InstallId = BindingInstallId,
            PreviousLeaseId = "bbbbbbbb-0000-4000-8000-000000000001",
            AuthorizationEpoch = 1,
            EntitlementEpoch = 2,
            BindingEpoch = 3,
        };
        var exactRequestBody = EnterpriseRefreshClient.SerializeExactRequest(request);
        var expectedBody = exactRequestBody.ToArray();
        var paths = CreateEnterpriseDiskTestPaths();
        var store = new EnterprisePendingRefreshTransactionStore(
            new EnterpriseProtectedArtifactStore(paths));
        try
        {
            await store.WriteNewAsync(exactRequestBody, BindingIdempotencyKey, now);
            using var pending = await store.ReadAsync()
                ?? throw new InvalidOperationException("Pending refresh transaction was not persisted.");
            AssertSequenceEqual(expectedBody, pending.ExactRequestBody.ToArray());
            AssertEqual(BindingIdempotencyKey, pending.IdempotencyKey);
            AssertEqual(now, pending.CreatedAtUtc);
        }
        finally
        {
            store.Delete();
            CryptographicOperations.ZeroMemory(exactRequestBody);
            CryptographicOperations.ZeroMemory(expectedBody);
        }
    }

    private static async Task EnterpriseCleanRestartRefreshAsync()
    {
        var fixture = LoadAuthorizationLeaseFixture();
        using var deviceKeys = new EphemeralDeviceProofKeyStore();
        var deviceIdentity = deviceKeys.GetOrCreatePublicIdentity();
        var device = new EnterpriseEnrollmentDeviceContext(
            new EnterpriseInstallationIdentity(
                Guid.Parse(fixture.InstallationId),
                fixture.EvaluationTimeUtc),
            deviceIdentity);
        var initialResponse = CreateSignedRefreshTestResponse(
            fixture,
            deviceIdentity.Thumbprint,
            fixture.EvaluationTimeUtc,
            fixture.LeaseId,
            RefreshTokenVector,
            'a');
        var firstIssuedAt = fixture.EvaluationTimeUtc.AddMinutes(1);
        var firstLeaseId = "bbbbbbbb-0000-4000-8000-000000000002";
        var firstRefreshToken = EncodeBase64Url(
            Enumerable.Range(64, 32).Select(value => (byte)value).ToArray());
        var firstResponse = CreateSignedRefreshTestResponse(
            fixture,
            deviceIdentity.Thumbprint,
            firstIssuedAt,
            firstLeaseId,
            firstRefreshToken,
            'b');
        var paths = CreateEnterpriseDiskTestPaths();
        var protectedStore = new EnterpriseProtectedArtifactStore(paths);
        var trustedTimeStore = new EnterpriseTrustedTimeStore(protectedStore);
        var credentialStore = new EnterpriseBindingCredentialStore(paths, protectedStore);
        var verifier = CreateAuthorizationLeaseVerifier(fixture);
        var initialVerified = verifier.Verify(
            initialResponse.AuthorizationLease,
            new EnterpriseAuthorizationLeaseVerificationContext(
                fixture.BindingId,
                fixture.InstallationId,
                deviceIdentity.Thumbprint,
                fixture.EvaluationTimeUtc,
                fixture.EvaluationTimeUtc));
        await credentialStore.CommitOrConfirmAsync(initialResponse, initialVerified);
        var firstTimeProvider = new ManualTimeProvider(firstIssuedAt);

        try
        {
            using (var vault = new EnterpriseAccessTokenVault())
            await using (var session = new EnterpriseHarnessSession(
                new EnterpriseStartupGate(firstTimeProvider),
                new FakeEnterpriseHarnessHost(),
                EnterpriseStartupGate.CreateEnrollmentRequiredSnapshot(),
                trustedTimeStore: trustedTimeStore))
            {
                var refreshClient = new FixedRefreshClient(
                    firstResponse,
                    RefreshTokenVector,
                    fixture.LeaseId);
                var refreshUpdateGate = new RecordingEnterpriseDeviceUpdateGate(
                    session,
                    blockForUpdate: false);
                var lifecycle = new EnterpriseAuthorizationLifecycle(
                    refreshClient,
                    verifier,
                    credentialStore,
                    new EnterprisePendingRefreshTransactionStore(protectedStore),
                    vault,
                    session,
                    trustedTimeStore,
                    refreshUpdateGate,
                    firstTimeProvider);
                var result = await lifecycle.HydrateAndRefreshAsync(device);

                AssertTrue(result.HasCommittedBinding);
                AssertTrue(result.RefreshCompleted);
                AssertEqual(EnterpriseClientState.Ready, result.AccessDecision.ClientState);
                AssertEqual(1, refreshUpdateGate.Calls);
                AssertFalse(refreshUpdateGate.ObservedReady);
                AssertEqual(1, refreshClient.ExactCalls);
                AssertTrue(vault.HasUsableToken(fixture.BindingId, firstIssuedAt));
                firstTimeProvider.Advance(TimeSpan.FromMinutes(5));
                firstTimeProvider.AdjustUtc(TimeSpan.FromMinutes(-4));
            }

            var committed = await credentialStore.ReadCommittedAsync()
                ?? throw new InvalidOperationException("Rotated credential was not committed.");
            AssertEqual(firstRefreshToken, committed.RefreshToken);
            AssertEqual(firstLeaseId, committed.Receipt.LeaseId);
            AssertFalse(File.Exists(paths.Resolve(
                EnterpriseManagedArtifact.PendingRefreshTransactionDpapi)));

            var leaseProjection = paths.Resolve(EnterpriseManagedArtifact.AuthorizationLease);
            await File.WriteAllTextAsync(leaseProjection, "interrupted-projection");
            var repaired = await credentialStore.ReadCommittedAsync()
                ?? throw new InvalidOperationException("Rotated credential repair failed.");
            AssertEqual(firstRefreshToken, repaired.RefreshToken);
            AssertEqual(firstResponse.AuthorizationLease, repaired.AuthorizationLease);

            AssertEqual(firstIssuedAt, trustedTimeStore.ReadFloorUtc());
            var rollbackTime = firstTimeProvider.GetUtcNow();
            AssertEqual(firstIssuedAt.AddMinutes(1), rollbackTime);
            AssertEqual(TimeSpan.FromMinutes(5).Ticks, firstTimeProvider.GetTimestamp());
            using (var rollbackVault = new EnterpriseAccessTokenVault())
            await using (var rollbackSession = new EnterpriseHarnessSession(
                new EnterpriseStartupGate(new FixedTimeProvider(rollbackTime)),
                new FakeEnterpriseHarnessHost(),
                EnterpriseStartupGate.CreateEnrollmentRequiredSnapshot(),
                trustedTimeStore: trustedTimeStore))
            {
                var unavailableRefresh = new UnavailableRefreshClient();
                var rollbackLifecycle = new EnterpriseAuthorizationLifecycle(
                    unavailableRefresh,
                    verifier,
                    credentialStore,
                    new EnterprisePendingRefreshTransactionStore(protectedStore),
                    rollbackVault,
                    rollbackSession,
                    trustedTimeStore,
                    new PassThroughEnterpriseDeviceUpdateGate(),
                    new FixedTimeProvider(rollbackTime));

                await AssertThrowsAsync<HttpRequestException>(() =>
                    rollbackLifecycle.HydrateAndRefreshAsync(device));
                AssertEqual(1, unavailableRefresh.ExactCalls);
                AssertEqual(
                    EnterpriseClientState.SecurityQuarantined,
                    rollbackSession.CurrentDecision.ClientState);
                AssertEqual(
                    EnterpriseErrorCodes.ClockUntrusted,
                    rollbackSession.CurrentDecision.ErrorCode);
                AssertFalse(rollbackSession.CurrentDecision.MayStartHarness);
                AssertFalse(rollbackSession.CurrentDecision.MayCallManagedApi);
                AssertFalse(rollbackVault.HasUsableToken(fixture.BindingId, rollbackTime));
                AssertEqual(firstIssuedAt, trustedTimeStore.ReadFloorUtc());
            }

            var secondIssuedAt = firstIssuedAt.AddMinutes(1);
            var secondLeaseId = "bbbbbbbb-0000-4000-8000-000000000003";
            var secondRefreshToken = EncodeBase64Url(
                Enumerable.Range(96, 32).Select(value => (byte)value).ToArray());
            var secondResponse = CreateSignedRefreshTestResponse(
                fixture,
                deviceIdentity.Thumbprint,
                secondIssuedAt,
                secondLeaseId,
                secondRefreshToken,
                'c');
            using var cleanRestartVault = new EnterpriseAccessTokenVault();
            AssertFalse(cleanRestartVault.HasUsableToken(fixture.BindingId, secondIssuedAt));
            await using var cleanRestartSession = new EnterpriseHarnessSession(
                new EnterpriseStartupGate(new FixedTimeProvider(secondIssuedAt)),
                new FakeEnterpriseHarnessHost(),
                EnterpriseStartupGate.CreateEnrollmentRequiredSnapshot(),
                trustedTimeStore: trustedTimeStore);
            var secondRefreshClient = new FixedRefreshClient(
                secondResponse,
                firstRefreshToken,
                firstLeaseId);
            var cleanRestartLifecycle = new EnterpriseAuthorizationLifecycle(
                secondRefreshClient,
                verifier,
                credentialStore,
                new EnterprisePendingRefreshTransactionStore(protectedStore),
                cleanRestartVault,
                cleanRestartSession,
                trustedTimeStore,
                new PassThroughEnterpriseDeviceUpdateGate(),
                new FixedTimeProvider(secondIssuedAt));
            var restarted = await cleanRestartLifecycle.HydrateAndRefreshAsync(device);

            AssertEqual(EnterpriseClientState.Ready, restarted.AccessDecision.ClientState);
            AssertEqual(1, secondRefreshClient.ExactCalls);
            AssertTrue(cleanRestartVault.HasUsableToken(fixture.BindingId, secondIssuedAt));
            var twiceRotated = await credentialStore.ReadCommittedAsync()
                ?? throw new InvalidOperationException("Clean-restart rotation was not committed.");
            AssertEqual(secondRefreshToken, twiceRotated.RefreshToken);
            AssertEqual(secondLeaseId, twiceRotated.Receipt.LeaseId);

            var deletedFloorObservedUtc = secondIssuedAt.AddMinutes(5);
            AssertEqual(
                deletedFloorObservedUtc,
                trustedTimeStore.Advance(
                    deletedFloorObservedUtc,
                    secondResponse.LeaseExpiresAtUtc));
            trustedTimeStore.Delete();
            AssertFalse(File.Exists(paths.Resolve(
                EnterpriseManagedArtifact.TrustedTimeHighWaterDpapi)));

            var deletedFloorRollbackUtc = secondIssuedAt.AddMinutes(1);
            using (var deletedFloorVault = new EnterpriseAccessTokenVault())
            await using (var deletedFloorSession = new EnterpriseHarnessSession(
                new EnterpriseStartupGate(new FixedTimeProvider(deletedFloorRollbackUtc)),
                new FakeEnterpriseHarnessHost(),
                EnterpriseStartupGate.CreateEnrollmentRequiredSnapshot(),
                trustedTimeStore: trustedTimeStore))
            {
                var unavailableRefresh = new UnavailableRefreshClient();
                var deletedFloorLifecycle = new EnterpriseAuthorizationLifecycle(
                    unavailableRefresh,
                    verifier,
                    credentialStore,
                    new EnterprisePendingRefreshTransactionStore(protectedStore),
                    deletedFloorVault,
                    deletedFloorSession,
                    trustedTimeStore,
                    new PassThroughEnterpriseDeviceUpdateGate(),
                    new FixedTimeProvider(deletedFloorRollbackUtc));

                await AssertThrowsAsync<HttpRequestException>(() =>
                    deletedFloorLifecycle.HydrateAndRefreshAsync(device));
                AssertEqual(1, unavailableRefresh.ExactCalls);
                AssertEqual(
                    EnterpriseClientState.SecurityQuarantined,
                    deletedFloorSession.CurrentDecision.ClientState);
                AssertEqual(
                    EnterpriseErrorCodes.ClockUntrusted,
                    deletedFloorSession.CurrentDecision.ErrorCode);
                AssertFalse(deletedFloorSession.CurrentDecision.MayStartHarness);
                AssertFalse(deletedFloorSession.CurrentDecision.MayCallManagedApi);
                AssertFalse(deletedFloorVault.HasUsableToken(
                    fixture.BindingId,
                    deletedFloorRollbackUtc));
                AssertFalse(File.Exists(paths.Resolve(
                    EnterpriseManagedArtifact.TrustedTimeHighWaterDpapi)));
            }

            var recoveryIssuedAt = secondIssuedAt.AddMinutes(2);
            var recoveryLeaseId = "bbbbbbbb-0000-4000-8000-000000000004";
            var recoveryRefreshToken = EncodeBase64Url(
                Enumerable.Range(128, 32).Select(value => (byte)value).ToArray());
            var recoveryResponse = CreateSignedRefreshTestResponse(
                fixture,
                deviceIdentity.Thumbprint,
                recoveryIssuedAt,
                recoveryLeaseId,
                recoveryRefreshToken,
                'd');
            using var recoveryVault = new EnterpriseAccessTokenVault();
            await using var recoverySession = new EnterpriseHarnessSession(
                new EnterpriseStartupGate(new FixedTimeProvider(recoveryIssuedAt)),
                new FakeEnterpriseHarnessHost(),
                EnterpriseStartupGate.CreateEnrollmentRequiredSnapshot(),
                trustedTimeStore: trustedTimeStore);
            var recoveryRefreshClient = new FixedRefreshClient(
                recoveryResponse,
                secondRefreshToken,
                secondLeaseId);
            var recoveryLifecycle = new EnterpriseAuthorizationLifecycle(
                recoveryRefreshClient,
                verifier,
                credentialStore,
                new EnterprisePendingRefreshTransactionStore(protectedStore),
                recoveryVault,
                recoverySession,
                trustedTimeStore,
                new PassThroughEnterpriseDeviceUpdateGate(),
                new FixedTimeProvider(recoveryIssuedAt));
            var recovered = await recoveryLifecycle.HydrateAndRefreshAsync(device);

            AssertEqual(EnterpriseClientState.Ready, recovered.AccessDecision.ClientState);
            AssertTrue(recovered.AccessDecision.MayStartHarness);
            AssertTrue(recovered.AccessDecision.MayCallManagedApi);
            AssertEqual(1, recoveryRefreshClient.ExactCalls);
            AssertTrue(File.Exists(paths.Resolve(
                EnterpriseManagedArtifact.TrustedTimeHighWaterDpapi)));
            AssertEqual(recoveryIssuedAt, trustedTimeStore.ReadFloorUtc());
            var recoveredCredential = await credentialStore.ReadCommittedAsync()
                ?? throw new InvalidOperationException(
                    "Verified refresh did not recover the deleted trusted-time state.");
            AssertEqual(recoveryRefreshToken, recoveredCredential.RefreshToken);
            AssertEqual(recoveryLeaseId, recoveredCredential.Receipt.LeaseId);
        }
        finally
        {
            new EnterprisePendingRefreshTransactionStore(protectedStore).Delete();
            credentialStore.DeleteBindingArtifacts();
        }
    }

    private static async Task EnterpriseRefreshInPlaceAsync()
    {
        var fixture = LoadAuthorizationLeaseFixture();
        using var deviceKeys = new EphemeralDeviceProofKeyStore();
        var identity = deviceKeys.GetOrCreatePublicIdentity();
        var device = new EnterpriseEnrollmentDeviceContext(
            new EnterpriseInstallationIdentity(
                Guid.Parse(fixture.InstallationId),
                fixture.EvaluationTimeUtc),
            identity);
        var initial = CreateSignedRefreshTestResponse(
            fixture,
            identity.Thumbprint,
            fixture.EvaluationTimeUtc,
            fixture.LeaseId,
            RefreshTokenVector,
            'a');
        var rotatedAt = fixture.EvaluationTimeUtc.AddMinutes(1);
        var rotatedToken = EncodeBase64Url(
            Enumerable.Range(64, 32).Select(value => (byte)value).ToArray());
        var rotated = CreateSignedRefreshTestResponse(
            fixture,
            identity.Thumbprint,
            rotatedAt,
            "bbbbbbbb-0000-4000-8000-000000000020",
            rotatedToken,
            'b');
        var paths = CreateEnterpriseDiskTestPaths();
        var protectedStore = new EnterpriseProtectedArtifactStore(paths);
        var trustedTime = new EnterpriseTrustedTimeStore(protectedStore);
        var credentials = new EnterpriseBindingCredentialStore(paths, protectedStore);
        var verifier = CreateAuthorizationLeaseVerifier(fixture);
        var initialVerified = verifier.Verify(
            initial.AuthorizationLease,
            new EnterpriseAuthorizationLeaseVerificationContext(
                fixture.BindingId,
                fixture.InstallationId,
                identity.Thumbprint,
                fixture.EvaluationTimeUtc,
                fixture.EvaluationTimeUtc));
        await credentials.CommitOrConfirmAsync(initial, initialVerified);

        try
        {
            var host = new FakeEnterpriseHarnessHost();
            using var vault = new EnterpriseAccessTokenVault();
            vault.Install(fixture.BindingId, initial.AccessToken, initial.AccessTokenExpiresAtUtc);
            await using var session = new EnterpriseHarnessSession(
                new EnterpriseStartupGate(new FixedTimeProvider(rotatedAt)),
                host,
                initialVerified.AccessSnapshot,
                trustedTimeStore: trustedTime);
            var blocking = new BlockingRefreshClient(
                rotated,
                RefreshTokenVector,
                fixture.LeaseId);
            var lifecycle = new EnterpriseAuthorizationLifecycle(
                blocking,
                verifier,
                credentials,
                new EnterprisePendingRefreshTransactionStore(protectedStore),
                vault,
                session,
                trustedTime,
                new PassThroughEnterpriseDeviceUpdateGate(),
                new FixedTimeProvider(rotatedAt));

            var refresh = lifecycle.RefreshInPlaceAsync(device);
            await blocking.Entered.WaitAsync(TimeSpan.FromSeconds(2));
            AssertEqual(0, host.StopCalls);
            AssertTrue(vault.HasUsableToken(fixture.BindingId, rotatedAt));
            blocking.Release();
            var result = await refresh;
            AssertTrue(result.HasCommittedBinding);
            AssertTrue(result.RefreshCompleted);
            AssertEqual(EnterpriseClientState.Ready, result.AccessDecision.ClientState);
            AssertEqual(0, host.StopCalls);
            var committed = await credentials.ReadCommittedAsync()
                ?? throw new InvalidOperationException("In-place refresh did not rotate credentials.");
            AssertEqual(rotatedToken, committed.RefreshToken);
            var snapshotBeforeOutage = session.CurrentAccessSnapshot;
            var leaseExpiryBeforeOutage = committed.Receipt.LeaseExpiresAtUtc;

            var outage = new EnterpriseAuthorizationLifecycle(
                new UnavailableRefreshClient(),
                verifier,
                credentials,
                new EnterprisePendingRefreshTransactionStore(protectedStore),
                vault,
                session,
                trustedTime,
                new PassThroughEnterpriseDeviceUpdateGate(),
                new FixedTimeProvider(rotatedAt));
            await AssertThrowsAsync<HttpRequestException>(() => outage.RefreshInPlaceAsync(device));
            AssertEqual(0, host.StopCalls);
            AssertTrue(vault.HasUsableToken(fixture.BindingId, rotatedAt));
            AssertEqual(snapshotBeforeOutage, session.CurrentAccessSnapshot);
            var committedAfterOutage = await credentials.ReadCommittedAsync()
                ?? throw new InvalidOperationException("Transport outage removed committed credentials.");
            AssertEqual(leaseExpiryBeforeOutage, committedAfterOutage.Receipt.LeaseExpiresAtUtc);
            AssertFalse(vault.HasUsableToken(
                fixture.BindingId,
                rotated.AccessTokenExpiresAtUtc));

            vault.Install(fixture.BindingId, rotated.AccessToken, rotated.AccessTokenExpiresAtUtc);
            var gateFailure = new EnterpriseAuthorizationLifecycle(
                new FixedRefreshClient(
                    rotated,
                    rotatedToken,
                    "bbbbbbbb-0000-4000-8000-000000000020"),
                verifier,
                credentials,
                new EnterprisePendingRefreshTransactionStore(protectedStore),
                vault,
                session,
                trustedTime,
                new ThrowingEnterpriseDeviceUpdateGate(),
                new FixedTimeProvider(rotatedAt));
            await AssertThrowsAsync<HttpRequestException>(() =>
                gateFailure.RefreshInPlaceAsync(device));
            AssertTrue(host.StopCalls > 0);
            AssertFalse(vault.HasUsableToken(fixture.BindingId, rotatedAt));

            var revoked = new EnterpriseApiError
            {
                Code = EnterpriseErrorCodes.EmployeeRevoked,
                Message = "contact administrator",
                ClientState = EnterpriseClientState.AccountLocked,
                Retryable = false,
                ContactDisplay = "IT",
                RequestId = "request-live-refresh-revoked",
                ResetScope = EnterpriseResetScope.SecurityCredentials,
            };
            var denied = new EnterpriseAuthorizationLifecycle(
                new ThrowingRefreshClient(new EnterpriseControlPlaneException(revoked)),
                verifier,
                credentials,
                new EnterprisePendingRefreshTransactionStore(protectedStore),
                vault,
                session,
                trustedTime,
                new PassThroughEnterpriseDeviceUpdateGate(),
                new FixedTimeProvider(rotatedAt));
            await AssertThrowsAsync<EnterpriseControlPlaneException>(() =>
                denied.RefreshInPlaceAsync(device));
            AssertTrue(host.StopCalls > 0);
            AssertFalse(vault.HasUsableToken(fixture.BindingId, rotatedAt));

            var corruptHost = new FakeEnterpriseHarnessHost();
            using var corruptVault = new EnterpriseAccessTokenVault();
            corruptVault.Install(fixture.BindingId, rotated.AccessToken, rotated.AccessTokenExpiresAtUtc);
            await using var corruptSession = new EnterpriseHarnessSession(
                new EnterpriseStartupGate(new FixedTimeProvider(rotatedAt)),
                corruptHost,
                initialVerified.AccessSnapshot,
                trustedTimeStore: trustedTime);
            var corruptLifecycle = new EnterpriseAuthorizationLifecycle(
                new UnavailableRefreshClient(),
                verifier,
                credentials,
                new EnterprisePendingRefreshTransactionStore(protectedStore),
                corruptVault,
                corruptSession,
                trustedTime,
                new PassThroughEnterpriseDeviceUpdateGate(),
                new FixedTimeProvider(rotatedAt));
            var wrongDevice = new EnterpriseEnrollmentDeviceContext(
                new EnterpriseInstallationIdentity(
                    Guid.Parse("aaaaaaaa-0000-4000-8000-000000000099"),
                    fixture.EvaluationTimeUtc),
                identity);
            await AssertThrowsAsync<EnterpriseBindingRecoveryRequiredException>(() =>
                corruptLifecycle.RefreshInPlaceAsync(wrongDevice));
            AssertTrue(corruptHost.StopCalls > 0);
            AssertFalse(corruptVault.HasUsableToken(fixture.BindingId, rotatedAt));

            var emptyPaths = CreateEnterpriseDiskTestPaths();
            var emptyProtected = new EnterpriseProtectedArtifactStore(emptyPaths);
            var emptyTrustedTime = new EnterpriseTrustedTimeStore(emptyProtected);
            var emptyHost = new FakeEnterpriseHarnessHost();
            using var emptyVault = new EnterpriseAccessTokenVault();
            emptyVault.Install(fixture.BindingId, initial.AccessToken, initial.AccessTokenExpiresAtUtc);
            await using var emptySession = new EnterpriseHarnessSession(
                new EnterpriseStartupGate(new FixedTimeProvider(rotatedAt)),
                emptyHost,
                initialVerified.AccessSnapshot,
                trustedTimeStore: emptyTrustedTime);
            var noBinding = new EnterpriseAuthorizationLifecycle(
                new UnavailableRefreshClient(),
                verifier,
                new EnterpriseBindingCredentialStore(emptyPaths, emptyProtected),
                new EnterprisePendingRefreshTransactionStore(emptyProtected),
                emptyVault,
                emptySession,
                emptyTrustedTime,
                new PassThroughEnterpriseDeviceUpdateGate(),
                new FixedTimeProvider(rotatedAt));
            using var cancelled = new CancellationTokenSource();
            cancelled.Cancel();
            await AssertThrowsAsync<OperationCanceledException>(() =>
                noBinding.RefreshInPlaceAsync(device, cancelled.Token));
            var qr = await noBinding.RefreshInPlaceAsync(device);
            AssertFalse(qr.HasCommittedBinding);
            AssertFalse(qr.RefreshCompleted);
            AssertEqual(EnterpriseClientState.QrRequired, qr.AccessDecision.ClientState);
            AssertFalse(emptyVault.HasUsableToken(fixture.BindingId, rotatedAt));
        }
        finally
        {
            new EnterprisePendingRefreshTransactionStore(protectedStore).Delete();
            credentials.DeleteBindingArtifacts();
        }
    }

    private static async Task EnterpriseGatewayAuthorizationAsync()
    {
        using var deviceKeys = new EphemeralDeviceProofKeyStore();
        var now = new DateTimeOffset(2026, 8, 24, 2, 0, 0, TimeSpan.Zero);
        var token = new string('g', 64);
        using var vault = new EnterpriseAccessTokenVault();
        vault.Install(BindingId, token, now.AddMinutes(10));
        await using var session = new EnterpriseHarnessSession(
            new EnterpriseStartupGate(new FixedTimeProvider(now)),
            new FakeEnterpriseHarnessHost(),
            CreateReadyEnterpriseSnapshot(now));
        var routes = EnterprisePhase1GatewayProfile.Routes;
        var calls = 0;
        var inner = new DelegateHandler(message =>
        {
            calls++;
            AssertEqual("DPoP", message.Headers.Authorization!.Scheme);
            AssertEqual(token, message.Headers.Authorization.Parameter);
            var proof = message.Headers.GetValues("DPoP").Single();
            var parts = proof.Split('.');
            using var payload = JsonDocument.Parse(DecodeBase64Url(parts[1]));
            AssertEqual("POST", payload.RootElement.GetProperty("htm").GetString());
            AssertEqual(
                "https://gateway.example.test/v1/chat/completions",
                payload.RootElement.GetProperty("htu").GetString());
            AssertFalse(payload.RootElement.TryGetProperty("nonce", out _));
            AssertEqual(
                EncodeBase64Url(SHA256.HashData(Encoding.ASCII.GetBytes(token))),
                payload.RootElement.GetProperty("ath").GetString());
            return new HttpResponseMessage(
                calls == 1 ? HttpStatusCode.OK : HttpStatusCode.Unauthorized);
        });
        using var client = new HttpClient(new EnterpriseGatewayAuthorizationHandler(
            new Uri("https://gateway.example.test/"),
            new EnterpriseDpopProofFactory(deviceKeys, new FixedTimeProvider(now)),
            vault,
            session,
            inner,
            routes,
            new FixedTimeProvider(now)));

        await AssertThrowsAsync<InvalidOperationException>(() => client.SendAsync(
            new HttpRequestMessage(
                HttpMethod.Post,
                "https://evil.example.test/v1/chat/completions")));
        await AssertThrowsAsync<InvalidOperationException>(() => client.SendAsync(
            new HttpRequestMessage(
                HttpMethod.Post,
                "https://gateway.example.test/v1/models")));
        await AssertThrowsAsync<InvalidOperationException>(() => client.SendAsync(
            new HttpRequestMessage(
                HttpMethod.Post,
                "https://gateway.example.test/v1/chat/completions?stream=true")));
        using var firstRequest = new HttpRequestMessage(
            HttpMethod.Post,
            "https://gateway.example.test/v1/chat/completions");
        using var firstResponse = await client.SendAsync(firstRequest);
        AssertEqual(HttpStatusCode.OK, firstResponse.StatusCode);
        AssertEqual(1, calls);
        AssertTrue(firstRequest.Headers.Authorization is null);
        AssertFalse(firstRequest.Headers.Contains("DPoP"));
        AssertEqual(EnterpriseClientState.Ready, session.CurrentDecision.ClientState);

        using var secondRequest = new HttpRequestMessage(
            HttpMethod.Post,
            "https://gateway.example.test/v1/chat/completions");
        using var secondResponse = await client.SendAsync(secondRequest);
        AssertEqual(HttpStatusCode.Unauthorized, secondResponse.StatusCode);
        AssertEqual(EnterpriseClientState.Binding, session.CurrentDecision.ClientState);
        AssertFalse(vault.HasUsableToken(BindingId, now));
    }

    private static async Task EnterpriseLoopbackProxyAsync()
    {
        using var deviceKeys = new EphemeralDeviceProofKeyStore();
        var now = new DateTimeOffset(2026, 8, 24, 2, 0, 0, TimeSpan.Zero);
        var accessToken = new string('p', 64);
        using var vault = new EnterpriseAccessTokenVault();
        vault.Install(BindingId, accessToken, now.AddMinutes(10));
        await using var session = new EnterpriseHarnessSession(
            new EnterpriseStartupGate(new FixedTimeProvider(now)),
            new FakeEnterpriseHarnessHost(),
            CreateReadyEnterpriseSnapshot(now));
        var routes = EnterprisePhase1GatewayProfile.Routes;
        var upstreamCalls = 0;
        var upstreamInner = new DelegateHandler(message =>
        {
            upstreamCalls++;
            AssertEqual(
                "https://gateway.example.test/v1/chat/completions",
                message.RequestUri!.AbsoluteUri);
            AssertEqual("DPoP", message.Headers.Authorization!.Scheme);
            AssertEqual(accessToken, message.Headers.Authorization.Parameter);
            AssertTrue(message.Headers.Contains("DPoP"));
            AssertTrue(message.Headers.Accept.Any(item => item.MediaType == "application/json"));
            AssertFalse(message.Headers.Contains("x-deepseek-harness-user-id"));
            AssertFalse(message.Headers.Contains("x-deepseek-harness-session-id"));
            AssertFalse(message.Headers.Contains("x-untrusted-local-header"));
            AssertEqual(
                "application/json",
                message.Content!.Headers.ContentType!.MediaType);
            AssertEqual(
                "{\"model\":\"test\",\"stream\":true}",
                message.Content.ReadAsStringAsync().GetAwaiter().GetResult());
            return JsonResponse("{\"ok\":true}");
        });
        using var gatewayClient = new HttpClient(new EnterpriseGatewayAuthorizationHandler(
            new Uri("https://gateway.example.test/"),
            new EnterpriseDpopProofFactory(deviceKeys, new FixedTimeProvider(now)),
            vault,
            session,
            upstreamInner,
            routes,
            new FixedTimeProvider(now)));
        await using var proxy = new EnterpriseLoopbackModelProxy(
            new Uri("https://gateway.example.test/"),
            routes,
            gatewayClient);
        await proxy.StartAsync();
        var environment = proxy.CreateDshControlledEnvironment();
        AssertTrue(environment["DEEPSEEK_BASE_URL"].StartsWith(
            "http://127.0.0.1:",
            StringComparison.Ordinal));
        AssertEqual(43, environment["DEEPSEEK_API_KEY"].Length);
        AssertEqual(
            environment["DEEPSEEK_BASE_URL"],
            environment["DEEPSEEK_SEARCH_BASE_URL"]);

        using var localClient = new HttpClient();
        using var unauthorized = await localClient.PostAsync(
            new Uri(proxy.LocalOrigin, "v1/chat/completions"),
            new StringContent("{}", Encoding.UTF8, "application/json"));
        AssertEqual(HttpStatusCode.Unauthorized, unauthorized.StatusCode);
        AssertEqual(0, upstreamCalls);

        using var blockedRequest = new HttpRequestMessage(
            HttpMethod.Get,
            new Uri(proxy.LocalOrigin, "v1/models"));
        blockedRequest.Headers.Authorization = new AuthenticationHeaderValue(
            "Bearer",
            environment["DEEPSEEK_API_KEY"]);
        using var blocked = await localClient.SendAsync(blockedRequest);
        AssertEqual(HttpStatusCode.Unauthorized, blocked.StatusCode);
        AssertEqual(0, upstreamCalls);

        using var searchRequest = new HttpRequestMessage(
            HttpMethod.Post,
            new Uri(proxy.LocalOrigin, "v1/messages"))
        {
            Content = new StringContent("{}", Encoding.UTF8, "application/json"),
        };
        searchRequest.Headers.Authorization = new AuthenticationHeaderValue(
            "Bearer",
            environment["DEEPSEEK_API_KEY"]);
        searchRequest.Headers.TryAddWithoutValidation(
            "x-api-key",
            environment["DEEPSEEK_API_KEY"]);
        using var searchBlocked = await localClient.SendAsync(searchRequest);
        AssertEqual(HttpStatusCode.Unauthorized, searchBlocked.StatusCode);
        AssertEqual(0, upstreamCalls);

        using var queryRequest = new HttpRequestMessage(
            HttpMethod.Post,
            new Uri(proxy.LocalOrigin, "v1/chat/completions?stream=true"));
        queryRequest.Headers.Authorization = new AuthenticationHeaderValue(
            "Bearer",
            environment["DEEPSEEK_API_KEY"]);
        using var queryBlocked = await localClient.SendAsync(queryRequest);
        AssertEqual(HttpStatusCode.BadRequest, queryBlocked.StatusCode);
        AssertEqual(0, upstreamCalls);

        using var allowedRequest = new HttpRequestMessage(
            HttpMethod.Post,
            new Uri(proxy.LocalOrigin, "v1/chat/completions"))
        {
            Content = new StringContent(
                "{\"model\":\"test\",\"stream\":true}",
                Encoding.UTF8,
                "application/json"),
        };
        allowedRequest.Headers.Authorization = new AuthenticationHeaderValue(
            "Bearer",
            environment["DEEPSEEK_API_KEY"]);
        allowedRequest.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        allowedRequest.Headers.TryAddWithoutValidation(
            "x-deepseek-harness-user-id",
            "must-not-leave-loopback");
        allowedRequest.Headers.TryAddWithoutValidation(
            "x-deepseek-harness-session-id",
            "must-not-leave-loopback");
        allowedRequest.Headers.TryAddWithoutValidation(
            "x-untrusted-local-header",
            "must-not-leave-loopback");
        using var allowed = await localClient.SendAsync(
            allowedRequest,
            HttpCompletionOption.ResponseHeadersRead);
        AssertEqual(HttpStatusCode.OK, allowed.StatusCode);
        AssertEqual("{\"ok\":true}", await allowed.Content.ReadAsStringAsync());
        AssertEqual(1, upstreamCalls);
    }

    private static async Task EnterpriseLoopbackParserRejectsAmbiguityAsync()
    {
        var upstreamCalls = 0;
        using var gatewayClient = new HttpClient(new DelegateHandler(_ =>
        {
            upstreamCalls++;
            return JsonResponse("{\"unexpected\":true}");
        }));
        await using var proxy = new EnterpriseLoopbackModelProxy(
            new Uri("https://gateway.example.test/"),
            EnterprisePhase1GatewayProfile.Routes,
            gatewayClient);
        await proxy.StartAsync();
        var localBearer = proxy.CreateDshControlledEnvironment()["DEEPSEEK_API_KEY"];
        var port = proxy.LocalOrigin.Port;

        var queryResponse = await SendRawLoopbackRequestAsync(
            port,
            "POST /v1/chat/completions?stream=true HTTP/1.1\r\n" +
            $"Host: 127.0.0.1:{port}\r\n" +
            $"Authorization: Bearer {localBearer}\r\n" +
            "Content-Length: 0\r\n\r\n");
        AssertTrue(queryResponse.StartsWith("HTTP/1.1 400", StringComparison.Ordinal));

        var duplicateLengthResponse = await SendRawLoopbackRequestAsync(
            port,
            "POST /v1/chat/completions HTTP/1.1\r\n" +
            $"Host: 127.0.0.1:{port}\r\n" +
            $"Authorization: Bearer {localBearer}\r\n" +
            "Content-Length: 0\r\n" +
            "Content-Length: 0\r\n\r\n");
        AssertTrue(duplicateLengthResponse.StartsWith("HTTP/1.1 400", StringComparison.Ordinal));

        var transferCodingResponse = await SendRawLoopbackRequestAsync(
            port,
            "POST /v1/chat/completions HTTP/1.1\r\n" +
            $"Host: 127.0.0.1:{port}\r\n" +
            $"Authorization: Bearer {localBearer}\r\n" +
            "Transfer-Encoding: chunked\r\n\r\n");
        AssertTrue(transferCodingResponse.StartsWith("HTTP/1.1 400", StringComparison.Ordinal));
        AssertEqual(0, upstreamCalls);
    }

    private static async Task EnterpriseLoopbackHeaderDeadlineReleasesConnectionsAsync()
    {
        var upstreamCalls = 0;
        using var gatewayClient = new HttpClient(new DelegateHandler(_ =>
        {
            upstreamCalls++;
            return JsonResponse("{\"ok\":true}");
        }));
        await using var proxy = new EnterpriseLoopbackModelProxy(
            new Uri("https://gateway.example.test/"),
            EnterprisePhase1GatewayProfile.Routes,
            gatewayClient);
        await proxy.StartAsync();
        var localBearer = proxy.CreateDshControlledEnvironment()["DEEPSEEK_API_KEY"];
        var port = proxy.LocalOrigin.Port;
        var slowClients = new List<TcpClient>(32);
        using var setupTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var trickleCancellation = new CancellationTokenSource();
        Task[] trickleTasks = [];
        try
        {
            for (var index = 0; index < 32; index++)
            {
                var client = new TcpClient(AddressFamily.InterNetwork);
                slowClients.Add(client);
                await client.ConnectAsync(IPAddress.Loopback, port, setupTimeout.Token);
                await client.GetStream().WriteAsync(
                    "GET /v1/chat/completions HTTP/1.1\r\nX-Slow: "u8.ToArray(),
                    setupTimeout.Token);
            }

            trickleTasks = slowClients
                .Select(client => TrickleLoopbackHeaderAsync(client, trickleCancellation.Token))
                .ToArray();
            await Task.Delay(TimeSpan.FromMilliseconds(500), setupTimeout.Token);

            var stopwatch = Stopwatch.StartNew();
            var validResponse = await SendRawLoopbackRequestAsync(
                port,
                "POST /v1/chat/completions HTTP/1.1\r\n" +
                $"Host: 127.0.0.1:{port}\r\n" +
                $"Authorization: Bearer {localBearer}\r\n" +
                "Content-Length: 0\r\n\r\n",
                TimeSpan.FromSeconds(10));
            stopwatch.Stop();

            AssertTrue(validResponse.StartsWith("HTTP/1.1 200", StringComparison.Ordinal));
            AssertEqual(1, upstreamCalls);
            AssertTrue(stopwatch.Elapsed < TimeSpan.FromSeconds(8));
        }
        finally
        {
            trickleCancellation.Cancel();
            foreach (var client in slowClients)
            {
                client.Dispose();
            }

            await Task.WhenAll(trickleTasks);
        }
    }

    private static async Task TrickleLoopbackHeaderAsync(
        TcpClient client,
        CancellationToken cancellationToken)
    {
        var chunk = new byte[] { (byte)'a' };
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                await client.GetStream().WriteAsync(chunk, cancellationToken);
                await client.GetStream().FlushAsync(cancellationToken);
                await Task.Delay(TimeSpan.FromMilliseconds(200), cancellationToken);
            }
        }
        catch (Exception exception) when (
            exception is IOException or SocketException or ObjectDisposedException
                or OperationCanceledException)
        {
        }
    }

    private static async Task<string> SendRawLoopbackRequestAsync(
        int port,
        string request,
        TimeSpan? timeoutDuration = null)
    {
        using var timeout = new CancellationTokenSource(
            timeoutDuration ?? TimeSpan.FromSeconds(5));
        using var client = new TcpClient(AddressFamily.InterNetwork);
        await client.ConnectAsync(IPAddress.Loopback, port, timeout.Token);
        var stream = client.GetStream();
        await stream.WriteAsync(Encoding.ASCII.GetBytes(request), timeout.Token);
        await stream.FlushAsync(timeout.Token);
        using var response = new MemoryStream();
        await stream.CopyToAsync(response, timeout.Token);
        return Encoding.ASCII.GetString(response.ToArray());
    }

    private static async Task DshControlledEnvironmentAsync()
    {
        var localKey = EncodeBase64Url(RandomNumberGenerator.GetBytes(32));
        var options = new DshRuntimeOptions(
            Path.Combine(TempRoot, "controlled-runtime"),
            Path.Combine(TempRoot, "controlled-data"),
            Path.Combine(TempRoot, "controlled-logs"),
            ControlledEnvironment: new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["DEEPSEEK_BASE_URL"] = "http://127.0.0.1:54321/v1",
                ["DEEPSEEK_API_KEY"] = localKey,
                ["DEEPSEEK_SEARCH_BASE_URL"] = "http://127.0.0.1:54321/v1",
            });
        var startInfo = new ProcessStartInfo();
        startInfo.Environment["DEEPSEEK_BASE_URL"] = "https://untrusted.example.test/v1";
        startInfo.Environment["DEEPSEEK_API_KEY"] = "untrusted";
        startInfo.Environment["deepseek_search_base_url"] =
            "https://api.deepseek.com/anthropic/v1";
        options.ApplyControlledEnvironment(startInfo);
        AssertEqual(
            "http://127.0.0.1:54321/v1",
            startInfo.Environment["DEEPSEEK_BASE_URL"]);
        AssertEqual(localKey, startInfo.Environment["DEEPSEEK_API_KEY"]);
        AssertEqual(
            "http://127.0.0.1:54321/v1",
            startInfo.Environment["DEEPSEEK_SEARCH_BASE_URL"]);
        AssertFalse(options.ToString().Contains(localKey, StringComparison.Ordinal));

        var arbitrary = options with
        {
            ControlledEnvironment = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["DEEPSEEK_BASE_URL"] = "http://127.0.0.1:54321/v1",
                ["DEEPSEEK_API_KEY"] = localKey,
                ["DEEPSEEK_SEARCH_BASE_URL"] = "http://127.0.0.1:54321/v1",
                ["NODE_OPTIONS"] = "--require attacker.js",
            },
        };
        await AssertThrowsAsync<InvalidOperationException>(() => Task.Run(() =>
            arbitrary.ApplyControlledEnvironment(new ProcessStartInfo())));
        var external = options with
        {
            ControlledEnvironment = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["DEEPSEEK_BASE_URL"] = "https://gateway.example.test/v1",
                ["DEEPSEEK_API_KEY"] = localKey,
                ["DEEPSEEK_SEARCH_BASE_URL"] = "https://gateway.example.test/v1",
            },
        };
        await AssertThrowsAsync<InvalidOperationException>(() => Task.Run(() =>
            external.ApplyControlledEnvironment(new ProcessStartInfo())));
        var publicSearch = options with
        {
            ControlledEnvironment = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["DEEPSEEK_BASE_URL"] = "http://127.0.0.1:54321/v1",
                ["DEEPSEEK_API_KEY"] = localKey,
                ["DEEPSEEK_SEARCH_BASE_URL"] =
                    "https://api.deepseek.com/anthropic/v1",
            },
        };
        await AssertThrowsAsync<InvalidOperationException>(() => Task.Run(() =>
            publicSearch.ApplyControlledEnvironment(new ProcessStartInfo())));

        var nonidenticalSearch = options with
        {
            ControlledEnvironment = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["DEEPSEEK_BASE_URL"] = "http://127.0.0.1:54321/v1",
                ["DEEPSEEK_API_KEY"] = localKey,
                ["DEEPSEEK_SEARCH_BASE_URL"] = "HTTP://127.0.0.1:54321/v1",
            },
        };
        await AssertThrowsAsync<InvalidOperationException>(() => Task.Run(() =>
            nonidenticalSearch.ApplyControlledEnvironment(new ProcessStartInfo())));

        var noncanonicalBase = options with
        {
            ControlledEnvironment = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["DEEPSEEK_BASE_URL"] = "http://127.0.0.1:54321/v1/",
                ["DEEPSEEK_API_KEY"] = localKey,
                ["DEEPSEEK_SEARCH_BASE_URL"] = "http://127.0.0.1:54321/v1/",
            },
        };
        await AssertThrowsAsync<InvalidOperationException>(() => Task.Run(() =>
            noncanonicalBase.ApplyControlledEnvironment(new ProcessStartInfo())));
    }

    private static async Task PersonalLauncherRestartBoundaryAsync()
    {
        var prepareCalled = false;
        var startCalled = false;
        var releaseCalled = false;
        var resolutionFailure = await LauncherRestartCoordinator.TryStartAsync(
            () => throw new InvalidOperationException("resolve-failure"),
            () =>
            {
                prepareCalled = true;
                return Task.CompletedTask;
            },
            _ =>
            {
                startCalled = true;
                return null;
            },
            () => releaseCalled = true,
            _ => true,
            Environment.ProcessId,
            TimeSpan.FromSeconds(2));
        AssertFalse(resolutionFailure.ReadyForParentExit);
        AssertTrue(resolutionFailure.ParentOwnershipProven);
        AssertEqual(
            LauncherRestartParentOwnership.Retained,
            resolutionFailure.ParentOwnership);
        AssertEqual("resolve-failure", resolutionFailure.Failure);
        AssertFalse(prepareCalled);
        AssertFalse(startCalled);
        AssertFalse(releaseCalled);

        var processPath = Path.Combine(
            TempRoot,
            "restart-contract",
            "Ensou.Dsh.Bootstrapper.exe");
        ProcessStartInfo? captured = null;
        var startFailure = await LauncherRestartCoordinator.TryStartAsync(
            () => processPath,
            () => Task.CompletedTask,
            startInfo =>
            {
                captured = startInfo;
                throw new InvalidOperationException(
                    new string(
                        'x',
                        LauncherRestartCoordinator.MaximumFailureLength + 50) +
                    "\r\ncontrol");
            },
            () => releaseCalled = true,
            _ => true,
            Environment.ProcessId,
            TimeSpan.FromSeconds(2));
        AssertFalse(startFailure.ReadyForParentExit);
        AssertTrue(startFailure.ParentOwnershipProven);
        AssertTrue(captured is not null);
        AssertEqual(
            LauncherRestartCoordinator.MaximumFailureLength,
            startFailure.Failure!.Length);
        AssertFalse(startFailure.Failure.Any(char.IsControl));
        AssertEqual(processPath, captured!.FileName);
        AssertEqual(Path.GetDirectoryName(processPath), captured.WorkingDirectory);
        AssertFalse(captured.UseShellExecute);
        AssertTrue(captured.CreateNoWindow);
        AssertEqual(ProcessWindowStyle.Normal, captured.WindowStyle);
        AssertEqual(4, captured.ArgumentList.Count);
        var command = PersonalLauncherRestartHandoffCommand.ParseRequired(
            captured.ArgumentList.ToArray());
        AssertEqual(Environment.ProcessId, command.ParentProcessId);
        AssertFalse(releaseCalled);

        var nullProcessFailure = await LauncherRestartCoordinator.TryStartAsync(
            () => processPath,
            () => Task.CompletedTask,
            _ => null,
            () => releaseCalled = true,
            _ => true,
            Environment.ProcessId,
            TimeSpan.FromSeconds(2));
        AssertFalse(nullProcessFailure.ReadyForParentExit);
        AssertTrue(nullProcessFailure.ParentOwnershipProven);
        AssertTrue(nullProcessFailure.Failure!.Contains(
            "未能启动",
            StringComparison.Ordinal));
        AssertFalse(releaseCalled);

        AssertLauncherRestartOwnershipFailureResults();
        await AssertLauncherRestartPreconnectionCleanupFailureAsync();
        await AssertLauncherRestartExitedForwarderIsUnprovenAsync();
        await AssertLauncherRestartHandoffIntegrationAsync();
    }

    private static async Task AssertLauncherRestartHandoffIntegrationAsync()
    {
        await AssertLauncherRestartScenarioAsync(
            "forwarded-success",
            expectSuccessfulTakeover: true);
        await AssertLauncherRestartScenarioAsync(
            "delayed-prepare",
            expectSuccessfulTakeover: true);
        await AssertLauncherRestartScenarioAsync(
            "post-ready-failure",
            expectSuccessfulTakeover: false);
        await AssertLauncherRestartScenarioAsync(
            "hung-before-ready",
            expectSuccessfulTakeover: false);
        await AssertLauncherRestartScenarioAsync(
            "forwarded-hung-before-ready",
            expectSuccessfulTakeover: false);
        await AssertLauncherRestartScenarioAsync(
            "forwarded-stalled-before-connection",
            expectSuccessfulTakeover: false);
        await AssertLauncherRestartScenarioAsync(
            "delayed-before-connection",
            expectSuccessfulTakeover: true);
        await AssertLauncherRestartScenarioAsync(
            "receiver-image-mismatch",
            expectSuccessfulTakeover: false);
        await AssertLauncherRestartScenarioAsync(
            "hung-after-ready",
            expectSuccessfulTakeover: false);
        await AssertLauncherRestartScenarioAsync(
            "hung-after-ack",
            expectSuccessfulTakeover: false);
        await AssertLauncherRestartScenarioAsync(
            "release-failure",
            expectSuccessfulTakeover: false);
        await AssertLauncherRestartScenarioAsync(
            "abort-rollback",
            expectSuccessfulTakeover: false);
        await AssertLauncherRestartScenarioAsync(
            "abort-parent-crash",
            expectSuccessfulTakeover: true);
        await AssertLauncherRestartSingleFlightAsync();
    }

    private static async Task AssertLauncherRestartPreconnectionCleanupFailureAsync()
    {
        var terminateCalls = 0;
        var releaseCalled = false;
        var result = await LauncherRestartCoordinator.TryStartAsync(
            () => Environment.ProcessPath
                ?? throw new InvalidOperationException("Test process path is unavailable."),
            () => Task.CompletedTask,
            _ => Process.GetCurrentProcess(),
            () => releaseCalled = true,
            _ => true,
            Environment.ProcessId,
            handoffTimeout: TimeSpan.FromSeconds(1),
            receiverConnectionTimeout: TimeSpan.FromSeconds(1),
            cancellationGrace: TimeSpan.FromSeconds(1),
            terminateReceiver: _ =>
            {
                terminateCalls++;
                throw new InvalidOperationException("simulated preconnection cleanup failure");
            },
            waitForReceiverExit: (_, _) => throw new InvalidOperationException(
                "cleanup wait must not follow a termination failure"));

        AssertFalse(result.ReadyForParentExit);
        AssertFalse(result.ParentOwnershipProven);
        AssertEqual(
            LauncherRestartParentOwnership.Unproven,
            result.ParentOwnership);
        AssertEqual(1, terminateCalls);
        AssertFalse(releaseCalled);
        AssertTrue(result.Failure!.Contains(
            "进程树清理未获确认",
            StringComparison.Ordinal));
    }

    private static async Task AssertLauncherRestartExitedForwarderIsUnprovenAsync()
    {
        var markerPath = Path.Combine(
            TempRoot,
            $"exited-forwarder-{Guid.NewGuid():N}.txt");
        var completionName = $"Local\\Ensou.Dsh.CoreTests.Orphan.{Guid.NewGuid():N}";
        using var completion = new EventWaitHandle(
            initialState: false,
            EventResetMode.ManualReset,
            completionName,
            out var createdNew);
        AssertTrue(createdNew);
        Process? orphanChild = null;
        var releaseCalled = false;
        try
        {
            var result = await LauncherRestartCoordinator.TryStartAsync(
                () => Environment.ProcessPath
                    ?? throw new InvalidOperationException(
                        "CoreTests process path is unavailable."),
                () => Task.CompletedTask,
                _ =>
                {
                    var forwarderStart = new ProcessStartInfo
                    {
                        FileName = Environment.ProcessPath!,
                        WorkingDirectory = AppContext.BaseDirectory,
                        UseShellExecute = false,
                        CreateNoWindow = true,
                    };
                    AddEntryAssemblyArgumentIfRequired(forwarderStart);
                    forwarderStart.ArgumentList.Add(
                        LauncherRestartExitedForwarderProbe);
                    forwarderStart.ArgumentList.Add(markerPath);
                    forwarderStart.ArgumentList.Add(completionName);
                    var forwarder = Process.Start(forwarderStart)
                        ?? throw new InvalidOperationException(
                            "Exited-forwarder probe did not start.");
                    if (!forwarder.WaitForExit(5000) || forwarder.ExitCode != 0)
                    {
                        forwarder.Dispose();
                        throw new InvalidOperationException(
                            "Exited-forwarder probe did not exit cleanly.");
                    }
                    if (!File.Exists(markerPath)
                        || !int.TryParse(
                            File.ReadAllText(markerPath),
                            CultureInfo.InvariantCulture,
                            out var orphanProcessId))
                    {
                        forwarder.Dispose();
                        throw new InvalidOperationException(
                            "Exited-forwarder probe did not identify its child.");
                    }
                    orphanChild = Process.GetProcessById(orphanProcessId);
                    AssertFalse(orphanChild.HasExited);
                    return forwarder;
                },
                () => releaseCalled = true,
                _ => true,
                Environment.ProcessId,
                handoffTimeout: TimeSpan.FromSeconds(1),
                receiverConnectionTimeout: TimeSpan.FromSeconds(1));

            AssertFalse(result.ReadyForParentExit);
            AssertFalse(result.ParentOwnershipProven);
            AssertEqual(
                LauncherRestartParentOwnership.Unproven,
                result.ParentOwnership);
            AssertFalse(releaseCalled);
            AssertTrue(result.Failure!.Contains(
                "无法确认其子进程树已清理",
                StringComparison.Ordinal));
            AssertTrue(orphanChild is not null);
            AssertFalse(orphanChild!.HasExited);
        }
        finally
        {
            completion.Set();
            if (orphanChild is not null)
            {
                if (!orphanChild.WaitForExit(5000))
                {
                    orphanChild.Kill(entireProcessTree: true);
                    orphanChild.WaitForExit(5000);
                }
                orphanChild.Dispose();
            }
        }
    }

    private static async Task EnterpriseLauncherRestartBoundaryAsync()
    {
        var command = PersonalLauncherRestartHandoffCommand.Create(
            Environment.ProcessId,
            backgroundStartup: true,
            scope: LauncherRestartHandoffScope.Enterprise);
        AssertEqual(LauncherRestartHandoffScope.Enterprise, command.Scope);
        AssertTrue(command.ToArguments()[0].Contains("enterprise", StringComparison.Ordinal));
        var personal = PersonalLauncherRestartHandoffCommand.Create(Environment.ProcessId);
        AssertTrue(command.ArmedEventName != personal.ArmedEventName);
        AssertTrue(command.PipeName != personal.PipeName);
        var parsed = PersonalLauncherRestartHandoffCommand.ParseRequired(
            command.ToArguments(), LauncherRestartHandoffScope.Enterprise);
        AssertTrue(parsed.BackgroundStartup);
        AssertEqual(command.Token, parsed.Token);
        AssertFalse(PersonalLauncherRestartHandoffCommand.IsIntent(
            command.ToArguments(), LauncherRestartHandoffScope.Personal));
        AssertTrue(PersonalLauncherRestartHandoffCommand.IsIntent(
            command.ToArguments(), LauncherRestartHandoffScope.Enterprise));
        AssertFalse(PersonalLauncherRestartHandoffCommand.IsIntent(
            personal.ToArguments(), LauncherRestartHandoffScope.Enterprise));
        await AssertLauncherRestartScenarioAsync(
            "enterprise-forwarded-success",
            expectSuccessfulTakeover: true);
    }

    private static void AssertLauncherRestartOwnershipFailureResults()
    {
        var recoveryStepTimeout = TimeSpan.FromMilliseconds(50);

        LauncherRestartOwnershipResult RunRecovery(
            bool releasedInitially,
            Action<Process> terminateReceiver,
            Func<Process, TimeSpan, bool> waitForReceiverExit,
            Func<TimeSpan, bool> tryReacquireSingleton)
        {
            using var cancellation = new EventWaitHandle(
                initialState: false,
                EventResetMode.ManualReset);
            using var released = new EventWaitHandle(
                releasedInitially,
                EventResetMode.ManualReset);
            using var rollbackOwned = new EventWaitHandle(
                initialState: false,
                EventResetMode.ManualReset);
            using var receiverProcess = Process.GetCurrentProcess();
            using var receiverExit = new LauncherProcessWaitHandle(
                receiverProcess);
            var result = LauncherRestartCoordinator
                .CancelAndRecoverParentOwnership(
                    cancellation,
                    released,
                    rollbackOwned,
                    receiverProcess,
                    receiverExit,
                    tryReacquireSingleton,
                    recoveryStepTimeout,
                    terminateReceiver,
                    waitForReceiverExit);
            AssertTrue(cancellation.WaitOne(TimeSpan.Zero));
            if (!result.ParentOwnershipProven)
            {
                AssertFalse(rollbackOwned.WaitOne(TimeSpan.Zero));
            }
            return result;
        }

        static void AssertUnproven(
            LauncherRestartOwnershipResult result)
        {
            AssertEqual(
                LauncherRestartParentOwnership.Unproven,
                result.ParentOwnership);
            AssertFalse(result.ParentOwnershipProven);
            AssertTrue(!string.IsNullOrWhiteSpace(result.Failure));
        }

        var killCalls = 0;
        var waitCalls = 0;
        var reacquireCalls = 0;
        var killFailure = RunRecovery(
            releasedInitially: false,
            _ =>
            {
                killCalls++;
                throw new InvalidOperationException("simulated kill failure");
            },
            (_, _) =>
            {
                waitCalls++;
                return true;
            },
            _ =>
            {
                reacquireCalls++;
                return true;
            });
        AssertUnproven(killFailure);
        AssertEqual(1, killCalls);
        AssertEqual(0, waitCalls);
        AssertEqual(0, reacquireCalls);

        TimeSpan? exitWaitTimeout = null;
        var exitWaitFailure = RunRecovery(
            releasedInitially: false,
            _ => { },
            (_, timeout) =>
            {
                exitWaitTimeout = timeout;
                return false;
            },
            _ =>
            {
                reacquireCalls++;
                return true;
            });
        AssertUnproven(exitWaitFailure);
        AssertEqual(recoveryStepTimeout, exitWaitTimeout);
        AssertEqual(0, reacquireCalls);

        TimeSpan? reacquireTimeout = null;
        var reacquireFalse = RunRecovery(
            releasedInitially: true,
            _ => throw new InvalidOperationException(
                "released receiver must not be terminated"),
            (_, _) => throw new InvalidOperationException(
                "released receiver exit wait must not run"),
            timeout =>
            {
                reacquireTimeout = timeout;
                return false;
            });
        AssertUnproven(reacquireFalse);
        AssertEqual(recoveryStepTimeout, reacquireTimeout);

        var reacquireThrow = RunRecovery(
            releasedInitially: true,
            _ => throw new InvalidOperationException(
                "released receiver must not be terminated"),
            (_, _) => throw new InvalidOperationException(
                "released receiver exit wait must not run"),
            _ => throw new InvalidOperationException(
                "simulated reacquire failure"));
        AssertUnproven(reacquireThrow);
    }

    private static async Task AssertLauncherRestartScenarioAsync(
        string mode,
        bool expectSuccessfulTakeover)
    {
        var id = Guid.NewGuid().ToString("N");
        var mutexName = $"Local\\Ensou.Dsh.Launcher.RestartTest.{id}";
        var completionEventName =
            $"Local\\Ensou.Dsh.Launcher.RestartTest.{id}.Complete";
        var markerPath = Path.Combine(
            TempRoot,
            $"launcher-restart-{id}.marker");
        var exitMarkerPath = $"{markerPath}.exit";
        using var completion = new EventWaitHandle(
            initialState: false,
            EventResetMode.ManualReset,
            completionEventName,
            out var createdCompletion);
        AssertTrue(createdCompletion);

        using var parent = StartCurrentTestProcess(
            LauncherRestartParentProbe,
            mode,
            mutexName,
            markerPath,
            completionEventName);
        Process? child = null;
        try
        {
            using (var timeout = new CancellationTokenSource(
                TimeSpan.FromSeconds(45)))
            {
                await parent.WaitForExitAsync(timeout.Token);
            }
            AssertEqual(
                string.Equals(
                    mode,
                    "abort-parent-crash",
                    StringComparison.Ordinal)
                        ? 31
                        : 0,
                parent.ExitCode);

            if (!expectSuccessfulTakeover)
            {
                AssertFalse(File.Exists(markerPath));
                using var recovered = new Mutex(
                    initiallyOwned: true,
                    mutexName,
                    out var createdAfterRecovery);
                AssertTrue(createdAfterRecovery);
                recovered.ReleaseMutex();
                return;
            }

            var markerWait = Stopwatch.StartNew();
            while (!File.Exists(markerPath)
                && markerWait.Elapsed < TimeSpan.FromSeconds(20))
            {
                await Task.Delay(25);
            }
            AssertTrue(File.Exists(markerPath));
            var childProcessId = int.Parse(
                File.ReadAllText(markerPath),
                CultureInfo.InvariantCulture);
            child = Process.GetProcessById(childProcessId);
            AssertFalse(child.HasExited);
            using var childExitLease = OpenLiveProcessExitLease(childProcessId);

            using (var observed = new Mutex(
                initiallyOwned: false,
                mutexName,
                out var createdWhileChildOwned))
            {
                AssertFalse(createdWhileChildOwned);
                AssertFalse(observed.WaitOne(TimeSpan.Zero));
            }

            completion.Set();
            AssertEqual(
                0u,
                WaitForExitedProcessCode(
                    childExitLease,
                    childProcessId,
                    TimeSpan.FromSeconds(20)));
            AssertTrue(File.Exists(exitMarkerPath));
            AssertEqual(
                "0",
                File.ReadAllText(exitMarkerPath));

            using var final = new Mutex(
                initiallyOwned: true,
                mutexName,
                out var createdAfterChildExit);
            AssertTrue(createdAfterChildExit);
            final.ReleaseMutex();
        }
        finally
        {
            completion.Set();
            TryKillTestProcess(child);
            TryKillTestProcess(parent);
            child?.Dispose();
        }
    }

    private static async Task AssertLauncherRestartSingleFlightAsync()
    {
        var gate = new LauncherRestartOperationGate();
        using var start = new ManualResetEventSlim(initialState: false);
        using var release = new ManualResetEventSlim(initialState: false);
        using var attempted = new CountdownEvent(20);
        var winners = 0;
        var operations = Enumerable.Range(0, 20)
            .Select(_ => Task.Run(() =>
            {
                start.Wait();
                if (!gate.TryEnter(out var operation))
                {
                    attempted.Signal();
                    return;
                }

                using (operation)
                {
                    Interlocked.Increment(ref winners);
                    attempted.Signal();
                    release.Wait();
                }
            }))
            .ToArray();
        start.Set();
        AssertTrue(attempted.Wait(TimeSpan.FromSeconds(10)));
        AssertEqual(1, winners);
        release.Set();
        await Task.WhenAll(operations);
    }

    private static async Task<int> RunLauncherRestartParentProbeAsync(
        string mode,
        string mutexName,
        string markerPath,
        string completionEventName)
    {
        using var mutexOwner = new LauncherMutexOwner(mutexName);
        using var completion = EventWaitHandle.OpenExisting(
            completionEventName);
        var starterProcessId = 0;
        var receiverProcessId = 0;
        var expectedProcessPath = Environment.ProcessPath
            ?? throw new InvalidOperationException(
                "CoreTests process path is unavailable.");
        using var expectedReceiver = PersonalAuthenticodeVerifier
            .OpenExecutableForLaunchForTests(expectedProcessPath);
        string? mismatchedExecutable = null;

        async Task PrepareAsync()
        {
            if (string.Equals(
                    mode,
                    "delayed-prepare",
                    StringComparison.Ordinal))
            {
                await Task.Delay(TimeSpan.FromSeconds(4));
            }
            else if (string.Equals(
                         mode,
                         "post-ready-failure",
                         StringComparison.Ordinal))
            {
                completion.Set();
                await Task.Delay(TimeSpan.FromSeconds(10));
            }
            else if (mode is
                     "abort-rollback"
                     or "abort-parent-crash"
                     or "hung-after-ready")
            {
                throw new InvalidOperationException(
                    "simulated post-READY parent preparation failure");
            }
        }

        var attempt = await LauncherRestartCoordinator.TryStartAsync(
            () => expectedProcessPath,
            PrepareAsync,
            startInfo =>
            {
                var handoffArguments = startInfo.ArgumentList.ToArray();
                startInfo.ArgumentList.Clear();
                AddEntryAssemblyArgumentIfRequired(startInfo);
                startInfo.ArgumentList.Add(mode is
                    "forwarded-success"
                    or "enterprise-forwarded-success"
                    or "forwarded-hung-before-ready"
                    or "forwarded-stalled-before-connection"
                        ? LauncherRestartForwarderProbe
                        : LauncherRestartChildProbe);
                startInfo.ArgumentList.Add(mode);
                startInfo.ArgumentList.Add(mutexName);
                startInfo.ArgumentList.Add(markerPath);
                startInfo.ArgumentList.Add(completionEventName);
                foreach (var argument in handoffArguments)
                {
                    startInfo.ArgumentList.Add(argument);
                }
                if (string.Equals(
                        mode,
                        "receiver-image-mismatch",
                        StringComparison.Ordinal))
                {
                    mismatchedExecutable = CreateMismatchedCoreTestsExecutable();
                    startInfo.FileName = mismatchedExecutable;
                    startInfo.ArgumentList.Clear();
                    startInfo.ArgumentList.Add(LauncherRestartChildProbe);
                    startInfo.ArgumentList.Add(mode);
                    startInfo.ArgumentList.Add(mutexName);
                    startInfo.ArgumentList.Add(markerPath);
                    startInfo.ArgumentList.Add(completionEventName);
                    foreach (var argument in handoffArguments)
                    {
                        startInfo.ArgumentList.Add(argument);
                    }
                }
                var process = Process.Start(startInfo);
                starterProcessId = process?.Id ?? 0;
                return process;
            },
            () =>
            {
                if (string.Equals(
                        mode,
                        "release-failure",
                        StringComparison.Ordinal))
                {
                    throw new InvalidOperationException(
                        "simulated concurrent restart release failure");
                }
                mutexOwner.Release();
            },
            mutexOwner.TryReacquire,
            Environment.ProcessId,
            handoffTimeout: string.Equals(
                mode,
                "delayed-before-connection",
                StringComparison.Ordinal)
                ? TimeSpan.FromSeconds(1)
                : TimeSpan.FromSeconds(3),
            receiverConnectionTimeout: string.Equals(
                mode,
                "delayed-before-connection",
                StringComparison.Ordinal)
                ? TimeSpan.FromSeconds(3)
                : null,
            validateReceiverProcess: process =>
            {
                receiverProcessId = process.Id;
                try
                {
                    expectedReceiver.RequireProcessImage(process);
                }
                catch (Exception validationFailure) when (
                    expectedReceiver.RetainsRejectedProcess(process))
                {
                    throw new LauncherRestartReceiverProcessRetainedException(
                        process,
                        validationFailure);
                }
            },
            abortReleasedForTest: () =>
            {
                if (string.Equals(
                        mode,
                        "abort-parent-crash",
                        StringComparison.Ordinal))
                {
                    Environment.Exit(31);
                }
            },
            cancellationGrace: TimeSpan.FromSeconds(1),
            handoffScope: mode.StartsWith("enterprise-", StringComparison.Ordinal)
                ? LauncherRestartHandoffScope.Enterprise
                : LauncherRestartHandoffScope.Personal);

        if (string.Equals(
                mode,
                "hung-after-ack",
                StringComparison.Ordinal))
        {
            if (!attempt.ReadyForParentExit
                || attempt.ParentOwnership
                    != LauncherRestartParentOwnership.Transferred)
            {
                return 15;
            }
            using var cancelledHandoff = attempt.Handoff!;
            var ownership = cancelledHandoff.CancelAndReacquire();
            if (!ownership.ParentOwnershipProven
                || ownership.ParentOwnership
                    != LauncherRestartParentOwnership.Recovered
                || !mutexOwner.TryReacquire(TimeSpan.Zero)
                || !WaitForLauncherProbeProcessExit(
                    receiverProcessId,
                    TimeSpan.FromSeconds(5)))
            {
                return 16;
            }
            return 0;
        }

        var expectsFailure = mode is
            "post-ready-failure"
            or "hung-before-ready"
            or "forwarded-hung-before-ready"
            or "forwarded-stalled-before-connection"
            or "receiver-image-mismatch"
            or "hung-after-ready"
            or "release-failure"
            or "abort-rollback"
            or "abort-parent-crash";
        if (expectsFailure)
        {
            if (attempt.ReadyForParentExit
                || !attempt.ParentOwnershipProven
                || !mutexOwner.TryReacquire(TimeSpan.Zero))
            {
                return 10;
            }
            var expectedOwnership = mode is
                "release-failure"
                or "receiver-image-mismatch"
                or "forwarded-stalled-before-connection"
                    ? LauncherRestartParentOwnership.Retained
                    : LauncherRestartParentOwnership.Recovered;
            if (attempt.ParentOwnership != expectedOwnership)
            {
                return 17;
            }
            if (mode is "release-failure" or "abort-rollback")
            {
                var expectedChildExit = string.Equals(
                    mode,
                    "release-failure",
                    StringComparison.Ordinal)
                        ? "30"
                        : "22";
                var childExitMarker = $"{markerPath}.exit";
                var markerWait = Stopwatch.StartNew();
                while (!File.Exists(childExitMarker)
                    && markerWait.Elapsed < TimeSpan.FromSeconds(5))
                {
                    await Task.Delay(25);
                }
                if (!File.Exists(childExitMarker)
                    || !string.Equals(
                        File.ReadAllText(childExitMarker),
                        expectedChildExit,
                        StringComparison.Ordinal))
                {
                    return 11;
                }
            }
            else if (mode is
                     "hung-before-ready"
                     or "forwarded-hung-before-ready"
                     or "forwarded-stalled-before-connection"
                     or "receiver-image-mismatch"
                     or "hung-after-ready")
            {
                if (mode is not "forwarded-stalled-before-connection"
                    && !WaitForLauncherProbeProcessExit(
                        receiverProcessId,
                        TimeSpan.FromSeconds(5)))
                {
                    return 14;
                }
                if (string.Equals(
                        mode,
                        "forwarded-hung-before-ready",
                        StringComparison.Ordinal))
                {
                    if (starterProcessId == 0
                        || receiverProcessId == 0
                        || starterProcessId == receiverProcessId
                        || !WaitForLauncherProbeProcessExit(
                            starterProcessId,
                            TimeSpan.FromSeconds(5)))
                    {
                        return 18;
                    }
                    var forwarderExitMarker =
                        $"{markerPath}.forwarder-exit";
                    var markerWait = Stopwatch.StartNew();
                    while (!File.Exists(forwarderExitMarker)
                        && markerWait.Elapsed < TimeSpan.FromSeconds(5))
                    {
                        await Task.Delay(25);
                    }
                    if (!File.Exists(forwarderExitMarker)
                        || !string.Equals(
                            File.ReadAllText(forwarderExitMarker),
                            "0",
                            StringComparison.Ordinal))
                    {
                        return 19;
                    }
                }
                if (string.Equals(
                        mode,
                        "forwarded-stalled-before-connection",
                        StringComparison.Ordinal))
                {
                    var preconnectionMarker = $"{markerPath}.preconnection";
                    var markerWait = Stopwatch.StartNew();
                    while (!File.Exists(preconnectionMarker)
                        && markerWait.Elapsed < TimeSpan.FromSeconds(5))
                    {
                        await Task.Delay(25);
                    }
                    if (starterProcessId == 0
                        || !File.Exists(preconnectionMarker)
                        || !int.TryParse(
                            File.ReadAllText(preconnectionMarker),
                            CultureInfo.InvariantCulture,
                            out var forwardedChildProcessId)
                        || !WaitForLauncherProbeProcessExit(
                            starterProcessId,
                            TimeSpan.FromSeconds(5))
                        || !WaitForLauncherProbeProcessExit(
                            forwardedChildProcessId,
                            TimeSpan.FromSeconds(5)))
                    {
                        return 32;
                    }
                }
                if (string.Equals(
                        mode,
                        "receiver-image-mismatch",
                        StringComparison.Ordinal)
                    && attempt.ParentOwnership
                        != LauncherRestartParentOwnership.Retained)
                {
                    return 29;
                }
            }
            if (mismatchedExecutable is not null)
            {
                TryDeleteTestFile(mismatchedExecutable);
            }
            return 0;
        }
        if (!attempt.ReadyForParentExit)
        {
            return 12;
        }
        if (mode is "forwarded-success" or "enterprise-forwarded-success"
            && starterProcessId == receiverProcessId)
        {
            return 13;
        }

        using var handoff = attempt.Handoff!;
        handoff.Commit();
        return 0;
    }

    private static int RunLauncherRestartForwarderProbe(
        string mode,
        string mutexName,
        string markerPath,
        string completionEventName,
        IReadOnlyList<string> handoffArguments)
    {
        var scope = mode.StartsWith("enterprise-", StringComparison.Ordinal)
            ? LauncherRestartHandoffScope.Enterprise
            : LauncherRestartHandoffScope.Personal;
        var command = PersonalLauncherRestartHandoffCommand.ParseRequired(
            handoffArguments,
            scope);
        var childMode = string.Equals(
            mode,
            "forwarded-stalled-before-connection",
            StringComparison.Ordinal)
            ? "stall-before-accept"
            : mode;
        using var child = StartCurrentTestProcess(
            [
                LauncherRestartChildProbe,
                childMode,
                mutexName,
                markerPath,
                completionEventName,
                .. handoffArguments,
            ]);
        int exitCode;
        try
        {
            LauncherRestartHandoffForwarder.WaitForFinalReceiver(
                command,
                child,
                TimeSpan.FromSeconds(10));
            exitCode = 0;
        }
        catch
        {
            command.TrySignalFailure();
            exitCode = 20;
        }
        TryWriteLauncherProbeMarker(
            $"{markerPath}.forwarder-exit",
            exitCode.ToString(CultureInfo.InvariantCulture));
        return exitCode;
    }

    private static int RunLauncherRestartChildProbe(
        string mode,
        string mutexName,
        string markerPath,
        string completionEventName,
        IReadOnlyList<string> handoffArguments)
    {
        var scope = mode.StartsWith("enterprise-", StringComparison.Ordinal)
            ? LauncherRestartHandoffScope.Enterprise
            : LauncherRestartHandoffScope.Personal;
        var command = PersonalLauncherRestartHandoffCommand.ParseRequired(
            handoffArguments,
            scope);
        if (string.Equals(
                mode,
                "stall-before-accept",
                StringComparison.Ordinal))
        {
            TryWriteLauncherProbeMarker(
                $"{markerPath}.preconnection",
                Environment.ProcessId.ToString(CultureInfo.InvariantCulture));
            Thread.Sleep(TimeSpan.FromSeconds(30));
            return 28;
        }
        if (string.Equals(
                mode,
                "delayed-before-connection",
                StringComparison.Ordinal))
        {
            Thread.Sleep(TimeSpan.FromMilliseconds(1500));
        }
        var accepted = LauncherRestartCoordinator.AcceptHandoff(
            command,
            mutexName,
            TimeSpan.FromSeconds(20));
        using var receiver = accepted.Receiver;
        using var singleton = accepted.Singleton;
        var ownsSingleton = true;
        try
        {
            using var completion = EventWaitHandle.OpenExisting(
                completionEventName);
            if (mode is
                "hung-before-ready"
                or "forwarded-hung-before-ready")
            {
                Thread.Sleep(TimeSpan.FromSeconds(30));
                return 24;
            }
            receiver.MarkReady();
            if (string.Equals(
                    mode,
                    "hung-after-ready",
                    StringComparison.Ordinal))
            {
                Thread.Sleep(TimeSpan.FromSeconds(30));
                return 25;
            }
            if (string.Equals(
                    mode,
                    "post-ready-failure",
                    StringComparison.Ordinal))
            {
                if (!completion.WaitOne(TimeSpan.FromSeconds(20)))
                {
                    return 21;
                }
                Environment.Exit(23);
            }
            if (string.Equals(
                    mode,
                    "hung-after-ack",
                    StringComparison.Ordinal))
            {
                using var commit = EventWaitHandle.OpenExisting(
                    command.CommitEventName);
                using var commitAcknowledged = EventWaitHandle.OpenExisting(
                    command.CommitAcknowledgedEventName);
                if (!commit.WaitOne(TimeSpan.FromSeconds(20)))
                {
                    return 26;
                }
                commitAcknowledged.Set();
                Thread.Sleep(TimeSpan.FromSeconds(30));
                return 27;
            }

            var outcome = receiver.WaitForParentExitAsync()
                .GetAwaiter()
                .GetResult();
            if (outcome == LauncherRestartReceiverOutcome.AbortRequested)
            {
                singleton.ReleaseMutex();
                ownsSingleton = false;
                receiver.SignalReleased();
                var rollback = receiver
                    .WaitForRollbackOwnedOrParentExitAsync()
                    .GetAwaiter()
                    .GetResult();
                if (rollback == LauncherRestartRollbackOutcome.RollbackOwned)
                {
                    return 22;
                }
                try
                {
                    _ = singleton.WaitOne(Timeout.InfiniteTimeSpan);
                }
                catch (AbandonedMutexException)
                {
                    // The old parent died during rollback; this child rescues
                    // the singleton and continues as the only Launcher.
                }
                ownsSingleton = true;
            }
            var markerStagingPath =
                $"{markerPath}.pending-{Environment.ProcessId}";
            File.WriteAllText(
                markerStagingPath,
                Environment.ProcessId.ToString(CultureInfo.InvariantCulture));
            File.Move(markerStagingPath, markerPath);
            if (!completion.WaitOne(TimeSpan.FromSeconds(20)))
            {
                return 23;
            }
            return 0;
        }
        finally
        {
            if (ownsSingleton)
            {
                singleton.ReleaseMutex();
            }
        }
    }

    private static Process StartCurrentTestProcess(params string[] arguments)
    {
        var processPath = Environment.ProcessPath
            ?? throw new InvalidOperationException(
                "CoreTests process path is unavailable.");
        var startInfo = new ProcessStartInfo
        {
            FileName = processPath,
            WorkingDirectory = AppContext.BaseDirectory,
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
        };
        AddEntryAssemblyArgumentIfRequired(startInfo);
        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }
        return Process.Start(startInfo)
            ?? throw new InvalidOperationException(
                "CoreTests restart helper process did not start.");
    }

    private static bool WaitForLauncherProbeProcessExit(
        int processId,
        TimeSpan timeout)
    {
        if (processId <= 0)
        {
            return false;
        }
        try
        {
            using var process = Process.GetProcessById(processId);
            return process.HasExited
                || (process.WaitForExit(checked((int)timeout.TotalMilliseconds))
                    && process.HasExited);
        }
        catch (ArgumentException)
        {
            // The validated helper exited and its PID already left the process
            // table, which is also positive exit confirmation for this probe.
            return true;
        }
    }

    private static SafeProcessHandle OpenLiveProcessExitLease(int processId)
    {
        var processHandle = OpenProcess(
            ProcessSynchronize | ProcessQueryLimitedInformation,
            inheritHandle: false,
            checked((uint)processId));
        if (processHandle.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            processHandle.Dispose();
            throw new Win32Exception(
                error,
                $"Could not open restart helper process {processId}.");
        }

        var waitResult = WaitForSingleObject(processHandle, milliseconds: 0);
        if (waitResult == WaitTimeout)
        {
            return processHandle;
        }

        var waitError = waitResult == WaitFailed
            ? Marshal.GetLastWin32Error()
            : 0;
        processHandle.Dispose();
        if (waitResult == WaitFailed)
        {
            throw new Win32Exception(
                waitError,
                $"Could not inspect restart helper process {processId}.");
        }
        throw new InvalidOperationException(
            $"Restart helper process {processId} exited before its completion signal.");
    }

    private static uint WaitForExitedProcessCode(
        SafeProcessHandle processHandle,
        int processId,
        TimeSpan timeout)
    {
        var waitResult = WaitForSingleObject(
            processHandle,
            checked((uint)timeout.TotalMilliseconds));
        if (waitResult == WaitFailed)
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                $"Could not wait for restart helper process {processId} exit.");
        }
        if (waitResult == WaitTimeout)
        {
            throw new TimeoutException(
                $"Restart helper process {processId} did not exit within {timeout}.");
        }
        if (waitResult != WaitObject0)
        {
            throw new InvalidOperationException(
                $"Restart helper process {processId} returned unexpected wait result 0x{waitResult:X8}.");
        }
        if (!GetExitCodeProcess(processHandle, out var exitCode))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                $"Could not read restart helper process {processId} exit code.");
        }
        return exitCode;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeProcessHandle OpenProcess(
        uint desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
        uint processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetExitCodeProcess(
        SafeProcessHandle processHandle,
        out uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(
        SafeProcessHandle handle,
        uint milliseconds);

    private static string CreateMismatchedCoreTestsExecutable()
    {
        var entryAssemblyPath = Assembly.GetEntryAssembly()?.Location
            ?? throw new InvalidOperationException(
                "CoreTests entry assembly is unavailable.");
        var appHostPath = Path.ChangeExtension(entryAssemblyPath, ".exe");
        if (!File.Exists(appHostPath))
        {
            throw new InvalidOperationException(
                "CoreTests apphost is unavailable for the real image-mismatch probe.");
        }
        var mismatchPath = Path.Combine(
            Path.GetDirectoryName(appHostPath)!,
            $"Ensou.Dsh.CoreTests.mismatch-{Guid.NewGuid():N}.exe");
        File.Copy(appHostPath, mismatchPath);
        return mismatchPath;
    }

    private static void TryDeleteTestFile(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch
        {
            // Preserve the primary process-boundary test result.
        }
    }

    private static void TryWriteLauncherProbeMarker(
        string markerPath,
        string value)
    {
        try
        {
            var stagingPath =
                $"{markerPath}.pending-{Environment.ProcessId}";
            File.WriteAllText(stagingPath, value);
            File.Move(stagingPath, markerPath);
        }
        catch
        {
            // Helper diagnostics must never turn an expected cancellation
            // process into an unhandled .NET/WER event.
        }
    }

    private static void AddEntryAssemblyArgumentIfRequired(
        ProcessStartInfo startInfo)
    {
        var fileName = Path.GetFileNameWithoutExtension(startInfo.FileName);
        if (string.Equals(fileName, "dotnet", StringComparison.OrdinalIgnoreCase))
        {
            startInfo.ArgumentList.Add(
                Assembly.GetEntryAssembly()?.Location
                ?? throw new InvalidOperationException(
                    "CoreTests entry assembly is unavailable."));
        }
    }

    private static void TryKillTestProcess(Process? process)
    {
        try
        {
            if (process is not null && !process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                process.WaitForExit(5000);
            }
        }
        catch
        {
            // Preserve the test failure while containing only its helper tree.
        }
    }

    private sealed class LauncherMutexOwner : IDisposable
    {
        private readonly BlockingCollection<Action> _operations = [];
        private readonly TaskCompletionSource<bool> _ready = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly Thread _thread;
        private Mutex? _mutex;
        private bool _owns;
        private bool _disposed;

        internal LauncherMutexOwner(string mutexName)
        {
            _thread = new Thread(() => Run(mutexName))
            {
                IsBackground = true,
                Name = "Launcher restart mutex owner",
            };
            _thread.Start();
            _ready.Task.GetAwaiter().GetResult();
        }

        internal void Release() => Invoke(() =>
        {
            if (_mutex is null || !_owns)
            {
                throw new InvalidOperationException(
                    "Restart probe does not own its singleton mutex.");
            }
            _mutex.ReleaseMutex();
            _owns = false;
            return true;
        });

        internal bool TryReacquire(TimeSpan timeout) => Invoke(() =>
        {
            if (_owns)
            {
                return true;
            }
            if (_mutex is null)
            {
                return false;
            }
            try
            {
                _owns = _mutex.WaitOne(timeout);
            }
            catch (AbandonedMutexException)
            {
                _owns = true;
            }
            return _owns;
        });

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }
            _operations.CompleteAdding();
            if (!_thread.Join(TimeSpan.FromSeconds(5)))
            {
                throw new TimeoutException(
                    "Restart probe mutex-owner thread did not exit.");
            }
            _operations.Dispose();
            _disposed = true;
        }

        private void Run(string mutexName)
        {
            try
            {
                _mutex = new Mutex(
                    initiallyOwned: true,
                    mutexName,
                    out var createdNew);
                if (!createdNew)
                {
                    throw new InvalidOperationException(
                        "Restart probe singleton mutex already exists.");
                }
                _owns = true;
                _ready.SetResult(true);
                foreach (var operation in _operations.GetConsumingEnumerable())
                {
                    operation();
                }
            }
            catch (Exception exception)
            {
                _ready.TrySetException(exception);
            }
            finally
            {
                if (_owns)
                {
                    try
                    {
                        _mutex?.ReleaseMutex();
                    }
                    catch
                    {
                        // Process teardown will abandon a still-owned mutex.
                    }
                }
                _mutex?.Dispose();
            }
        }

        private T Invoke<T>(Func<T> operation)
        {
            var completion = new TaskCompletionSource<T>(
                TaskCreationOptions.RunContinuationsAsynchronously);
            _operations.Add(() =>
            {
                try
                {
                    completion.SetResult(operation());
                }
                catch (Exception exception)
                {
                    completion.SetException(exception);
                }
            });
            return completion.Task.GetAwaiter().GetResult();
        }
    }

    private static async Task DshNativeSuspendedHostAdmissionAsync()
    {
        var root = Path.Combine(
            TempRoot,
            $"native-suspended-host-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        var rootMarker = Path.Combine(root, "root.marker");
        var childMarker = Path.Combine(root, "child.marker");
        using var sentinel = new EventWaitHandle(false, EventResetMode.ManualReset);
        if (!SetHandleInformation(
                sentinel.SafeWaitHandle,
                1,
                1))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Could not make the suspended-host sentinel inheritable.");
        }

        ProcessStartInfo CreateStartInfo()
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = Environment.ProcessPath!,
                WorkingDirectory = AppContext.BaseDirectory,
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            AddEntryAssemblyArgumentIfRequired(startInfo);
            startInfo.ArgumentList.Add(SuspendedHostRootProbe);
            startInfo.ArgumentList.Add(rootMarker);
            startInfo.ArgumentList.Add(childMarker);
            startInfo.ArgumentList.Add(
                sentinel.SafeWaitHandle.DangerousGetHandle()
                    .ToInt64()
                    .ToString(CultureInfo.InvariantCulture));
            return startInfo;
        }

        var rejectedProcessId = 0;
        using (var rejectedJob = WindowsJobObject.CreateKillOnClose())
        {
            try
            {
                using var unexpected = rejectedJob.StartSuspended(
                    CreateStartInfo(),
                    suspended =>
                    {
                        rejectedProcessId = suspended.Id;
                        AssertFalse(File.Exists(rootMarker));
                        AssertFalse(File.Exists(childMarker));
                        throw new InvalidOperationException(
                            "pre-resume-admission-rejected");
                    });
                throw new InvalidOperationException(
                    "Expected suspended Host admission to reject.");
            }
            catch (InvalidOperationException exception) when (
                string.Equals(
                    exception.Message,
                    "pre-resume-admission-rejected",
                    StringComparison.Ordinal))
            {
            }
            AssertTrue(rejectedProcessId > 0);
            AssertTrue(SpinWait.SpinUntil(
                () => HasExited(rejectedProcessId),
                TimeSpan.FromSeconds(5)));
            AssertEqual(0u, rejectedJob.ReadActiveProcessCountForTest());
            AssertFalse(File.Exists(rootMarker));
            AssertFalse(File.Exists(childMarker));
        }

        using (var admittedJob = WindowsJobObject.CreateKillOnClose())
        using (var admitted = admittedJob.StartSuspended(
                   CreateStartInfo(),
                   _ =>
                   {
                       AssertFalse(File.Exists(rootMarker));
                       AssertFalse(File.Exists(childMarker));
                   }))
        {
            var readers = admitted.DetachReaders();
            using var stdout = readers.Output
                ?? throw new InvalidOperationException(
                    "Suspended Host stdout reader was not returned.");
            using var stderr = readers.Error
                ?? throw new InvalidOperationException(
                    "Suspended Host stderr reader was not returned.");
            var stdoutTask = stdout.ReadToEndAsync();
            var stderrTask = stderr.ReadToEndAsync();
            using var process = admitted.Process;
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
            AssertEqual(0, process.ExitCode);
            AssertEqual(
                "suspended-host-stdout",
                (await stdoutTask.ConfigureAwait(false)).Trim());
            AssertEqual(
                "suspended-host-stderr",
                (await stderrTask.ConfigureAwait(false)).Trim());
            AssertEqual("not-inherited", File.ReadAllText(rootMarker));
            AssertTrue(File.Exists(childMarker));
            AssertFalse(sentinel.WaitOne(0));
            AssertTrue(SpinWait.SpinUntil(
                () => admittedJob.ReadActiveProcessCountForTest() == 0,
                TimeSpan.FromSeconds(5)));
            AssertEqual(0u, admittedJob.ReadActiveProcessCountForTest());
        }
    }

    private static bool HasExited(int processId)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            return process.HasExited;
        }
        catch (ArgumentException)
        {
            return true;
        }
    }

    private static async Task DshEnterpriseManagedHostBoundaryAsync()
    {
        var root = Path.Combine(TempRoot, $"enterprise-host-{Guid.NewGuid():N}");
        var runtime = Path.Combine(root, "runtime");
        var data = Path.Combine(root, "harness-home");
        var workspace = Path.Combine(data, "workspaces");
        var logs = Path.Combine(root, "logs");
        var pluginRoot = Path.Combine(root, "plugins");
        var skillsRoot = Path.Combine(pluginRoot, "plugin-release", "skills");
        var entry = Path.Combine(
            runtime,
            "node_modules",
            "@deepseek-ai",
            "dsh",
            "lib",
            "bin.js");
        Directory.CreateDirectory(Path.GetDirectoryName(entry)!);
        Directory.CreateDirectory(workspace);
        Directory.CreateDirectory(skillsRoot);
        File.WriteAllText(Path.Combine(runtime, "node.exe"), "node");
        File.WriteAllText(entry, "entry");

        var localKey = EncodeBase64Url(RandomNumberGenerator.GetBytes(32));
        var controlled = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["DEEPSEEK_BASE_URL"] = "http://127.0.0.1:54321/v1",
            ["DEEPSEEK_API_KEY"] = localKey,
            ["DEEPSEEK_SEARCH_BASE_URL"] = "http://127.0.0.1:54321/v1",
        };
        var options = DshRuntimeOptions.CreateEnterpriseManaged(
            runtime,
            data,
            logs,
            workspace,
            fixedPort: 3181,
            pluginRoot,
            skillsRoot,
            controlledEnvironment: controlled);
        var launchValidationCount = 0;
        await using var service = new DshHostService(
            options,
            httpClient: new HttpClient(new DelegateHandler(_ =>
                new HttpResponseMessage(HttpStatusCode.ServiceUnavailable))),
            validateBeforeProcessStart: () =>
            {
                launchValidationCount++;
                throw new InvalidOperationException("pre-start-validation-sentinel");
            });
        var startInfo = service.CreateStartInfo();
        AssertEqual(0, launchValidationCount);
        await AssertThrowsAsync<InvalidOperationException>(
            () => service.EnsureStartedAsync());
        AssertEqual(1, launchValidationCount);
        AssertEqual(options.NodePath, startInfo.FileName);
        AssertEqual(workspace, startInfo.WorkingDirectory);
        AssertFalse(startInfo.UseShellExecute);
        AssertTrue(startInfo.CreateNoWindow);
        AssertEqual(ProcessWindowStyle.Hidden, startInfo.WindowStyle);
        AssertSequenceEqual(
            new[]
            {
                options.EntryPointPath,
                "--profile",
                "enterprise-managed",
                "--host",
                "127.0.0.1",
                "--port",
                "3181",
            },
            startInfo.ArgumentList.ToArray());
        AssertFalse(startInfo.ArgumentList.Contains("web", StringComparer.Ordinal));
        AssertFalse(startInfo.ArgumentList.Contains("--no-open", StringComparer.Ordinal));
        AssertSequenceEqual(
            new[] { "--host", "127.0.0.1", "--port", "3181" },
            startInfo.ArgumentList.Skip(3).ToArray());
        AssertFalse(startInfo.ArgumentList.Any(argument => argument.Contains('=')));
        AssertFalse(options.ToString().Contains(localKey, StringComparison.Ordinal));
        AssertFalse(string.Join(' ', startInfo.ArgumentList).Contains(localKey, StringComparison.Ordinal));

        var hostile = new ProcessStartInfo();
        hostile.Environment["nOdE_oPtIoNs"] = "--require attacker.js";
        hostile.Environment["Node_Path"] = @"C:\attacker";
        hostile.Environment["node_extra_ca_certs"] = @"C:\attacker-ca.pem";
        hostile.Environment["node_tls_reject_unauthorized"] = "0";
        hostile.Environment["FnM_Dir"] = @"C:\fnm";
        hostile.Environment["pNpM_Home"] = @"C:\pnpm";
        hostile.Environment["npm_config_userconfig"] = @"C:\attacker.npmrc";
        hostile.Environment["dsh_profile"] = "attacker";
        hostile.Environment["dsh_enterprise_managed_boot"] = "attacker/v9";
        hostile.Environment["eNsOu_dSh_pErSoNaL_uPdAtE_bOoT"] = "attacker/v9";
        hostile.Environment["DeepSeek_api_key"] = "attacker";
        hostile.Environment["DEEPSEEK_EXTRA"] = "attacker";
        hostile.Environment["https_proxy"] = "http://attacker:8080";
        hostile.Environment["No_Proxy"] = "attacker";
        hostile.Environment["sslkeylogfile"] = @"C:\tls.keys";
        hostile.Environment["OpEnSsL_CoNf"] = @"C:\openssl.cnf";
        hostile.Environment["Path"] = @"C:\fnm;C:\attacker";
        hostile.Environment["systemroot"] = @"C:\attacker-windows";
        hostile.Environment["windir"] = @"C:\attacker-windows";
        hostile.Environment["comspec"] = @"C:\attacker\cmd.exe";
        hostile.Environment["eNsOu_dSh_eNtErPrIsE_sKiLlS_rOoT"] =
            @"C:\attacker-skills";
        options.ApplyProcessEnvironment(hostile);

        AssertFalse(ContainsEnvironmentKey(hostile, "NODE_OPTIONS"));
        AssertFalse(ContainsEnvironmentKey(hostile, "NODE_PATH"));
        AssertFalse(ContainsEnvironmentKey(hostile, "NODE_EXTRA_CA_CERTS"));
        AssertFalse(ContainsEnvironmentKey(hostile, "NODE_TLS_REJECT_UNAUTHORIZED"));
        AssertFalse(hostile.Environment.Keys.Any(key =>
            key.StartsWith("FNM_", StringComparison.OrdinalIgnoreCase)
            || key.StartsWith("PNPM_", StringComparison.OrdinalIgnoreCase)
            || key.StartsWith("NPM_CONFIG_", StringComparison.OrdinalIgnoreCase)));
        AssertFalse(ContainsEnvironmentKey(hostile, "DSH_PROFILE"));
        AssertFalse(ContainsEnvironmentKey(hostile, "DEEPSEEK_EXTRA"));
        AssertFalse(ContainsEnvironmentKey(hostile, "HTTPS_PROXY"));
        AssertFalse(ContainsEnvironmentKey(hostile, "SSLKEYLOGFILE"));
        AssertFalse(ContainsEnvironmentKey(hostile, "OPENSSL_CONF"));
        AssertEqual(
            3,
            hostile.Environment.Keys.Count(key =>
                key.StartsWith("DSH_", StringComparison.OrdinalIgnoreCase)));
        AssertEqual(
            3,
            hostile.Environment.Keys.Count(key =>
                key.StartsWith("DEEPSEEK_", StringComparison.OrdinalIgnoreCase)));
        AssertEqual(data, hostile.Environment["DSH_HOME"]);
        AssertEqual("1", hostile.Environment["DSH_TELEMETRY_DISABLED"]);
        AssertEqual(
            DshRuntimeOptions.EnterpriseManagedBootMarker,
            hostile.Environment["DSH_ENTERPRISE_MANAGED_BOOT"]);
        AssertFalse(ContainsEnvironmentKey(
            hostile,
            DshRuntimeOptions.PersonalManagedUpdateBootEnvironmentVariable));
        AssertEqual(controlled["DEEPSEEK_BASE_URL"], hostile.Environment["DEEPSEEK_BASE_URL"]);
        AssertEqual(
            controlled["DEEPSEEK_SEARCH_BASE_URL"],
            hostile.Environment["DEEPSEEK_SEARCH_BASE_URL"]);
        AssertEqual(localKey, hostile.Environment["DEEPSEEK_API_KEY"]);
        AssertEqual(
            skillsRoot,
            hostile.Environment[
                DshRuntimeOptions.EnterpriseManagedSkillsRootEnvironmentVariable]);
        AssertEqual(
            1,
            hostile.Environment.Keys.Count(key => string.Equals(
                key,
                DshRuntimeOptions.EnterpriseManagedSkillsRootEnvironmentVariable,
                StringComparison.OrdinalIgnoreCase)));
        AssertEqual(DshRuntimeOptions.LoopbackNoProxy, hostile.Environment["NO_PROXY"]);
        var managedPath = hostile.Environment["PATH"]!.Split(Path.PathSeparator);
        AssertEqual(Path.GetFullPath(runtime), Path.GetFullPath(managedPath[0]));
        AssertFalse(managedPath.Any(path => path.Contains("fnm", StringComparison.OrdinalIgnoreCase)));
        AssertTrue(managedPath.Any(path => path.EndsWith(
            @"WindowsPowerShell\v1.0",
            StringComparison.OrdinalIgnoreCase)));
        AssertEqual(
            Path.GetFullPath(Environment.GetFolderPath(Environment.SpecialFolder.Windows)),
            Path.GetFullPath(hostile.Environment["SystemRoot"]!));
        AssertEqual(
            Path.Combine(Environment.SystemDirectory, "cmd.exe"),
            hostile.Environment["COMSPEC"]);

        var personal = new DshRuntimeOptions(runtime, data, logs, Port: 3080);
        AssertFalse(personal.SupportsManagedUpdate);
        await using var personalService = new DshHostService(personal);
        var personalStart = personalService.CreateStartInfo();
        AssertEqual(runtime, personalStart.WorkingDirectory);
        AssertFalse(personalStart.UseShellExecute);
        AssertTrue(personalStart.CreateNoWindow);
        AssertEqual(ProcessWindowStyle.Hidden, personalStart.WindowStyle);
        AssertSequenceEqual(
            new[]
            {
                personal.EntryPointPath,
                "web",
                "--no-open",
                "--host",
                "127.0.0.1",
                "--port",
                "3080",
            },
            personalStart.ArgumentList.ToArray());
        AssertFalse(ContainsEnvironmentKey(personalStart, "DSH_ENTERPRISE_MANAGED_BOOT"));
        var personalEnvironment = new ProcessStartInfo();
        personalEnvironment.Environment["nOdE_oPtIoNs"] = "--require personal-tool.js";
        personalEnvironment.Environment["Node_Path"] = @"C:\personal-node-path";
        personalEnvironment.Environment["node_extra_ca_certs"] = @"C:\personal-ca.pem";
        personalEnvironment.Environment["NoDe_TlS_ReJeCt_UnAuThOrIzEd"] = "0";
        personalEnvironment.Environment["FnM_Dir"] = @"C:\personal-fnm";
        personalEnvironment.Environment["pNpM_Home"] = @"C:\personal-pnpm";
        personalEnvironment.Environment["npm_config_userconfig"] = @"C:\personal.npmrc";
        personalEnvironment.Environment["dsh_profile"] = "attacker";
        personalEnvironment.Environment["dsh_home"] = @"C:\attacker-home";
        personalEnvironment.Environment["eNsOu_dSh_pErSoNaL_uPdAtE_bOoT"] = "attacker/v9";
        personalEnvironment.Environment["DeepSeek_api_key"] = "attacker";
        personalEnvironment.Environment["https_proxy"] = "http://attacker:8080";
        personalEnvironment.Environment["No_Proxy"] = "attacker";
        personalEnvironment.Environment["sslkeylogfile"] = @"C:\personal-tls.keys";
        personalEnvironment.Environment["OpEnSsL_CoNf"] = @"C:\personal-openssl.cnf";
        personalEnvironment.Environment["Path"] = @"C:\personal-fnm;C:\attacker";
        personalEnvironment.Environment["systemroot"] = @"C:\attacker-windows";
        personalEnvironment.Environment["windir"] = @"C:\attacker-windows";
        personalEnvironment.Environment["comspec"] = @"C:\attacker\cmd.exe";
        personalEnvironment.Environment[
            DshRuntimeOptions.EnterpriseManagedSkillsRootEnvironmentVariable] =
            "personal-value";
        personal.ApplyProcessEnvironment(personalEnvironment);
        AssertFalse(ContainsEnvironmentKey(personalEnvironment, "NODE_OPTIONS"));
        AssertFalse(ContainsEnvironmentKey(personalEnvironment, "NODE_PATH"));
        AssertFalse(ContainsEnvironmentKey(personalEnvironment, "NODE_EXTRA_CA_CERTS"));
        AssertFalse(ContainsEnvironmentKey(
            personalEnvironment,
            "NODE_TLS_REJECT_UNAUTHORIZED"));
        AssertFalse(personalEnvironment.Environment.Keys.Any(key =>
            key.StartsWith("FNM_", StringComparison.OrdinalIgnoreCase)
            || key.StartsWith("PNPM_", StringComparison.OrdinalIgnoreCase)
            || key.StartsWith("NPM_CONFIG_", StringComparison.OrdinalIgnoreCase)));
        AssertFalse(ContainsEnvironmentKey(personalEnvironment, "DSH_PROFILE"));
        AssertFalse(ContainsEnvironmentKey(personalEnvironment, "DEEPSEEK_API_KEY"));
        AssertFalse(ContainsEnvironmentKey(personalEnvironment, "HTTPS_PROXY"));
        AssertFalse(ContainsEnvironmentKey(personalEnvironment, "NO_PROXY"));
        AssertFalse(ContainsEnvironmentKey(personalEnvironment, "SSLKEYLOGFILE"));
        AssertFalse(ContainsEnvironmentKey(personalEnvironment, "OPENSSL_CONF"));
        AssertFalse(ContainsEnvironmentKey(
            personalEnvironment,
            DshRuntimeOptions.EnterpriseManagedSkillsRootEnvironmentVariable));
        AssertFalse(ContainsEnvironmentKey(
            personalEnvironment,
            DshRuntimeOptions.PersonalManagedUpdateBootEnvironmentVariable));
        AssertEqual(data, personalEnvironment.Environment["DSH_HOME"]);
        AssertEqual("1", personalEnvironment.Environment["DSH_TELEMETRY_DISABLED"]);
        AssertEqual(
            2,
            personalEnvironment.Environment.Keys.Count(key =>
                key.StartsWith("DSH_", StringComparison.OrdinalIgnoreCase)));
        var personalPath = personalEnvironment.Environment["PATH"]!.Split(Path.PathSeparator);
        AssertEqual(Path.GetFullPath(runtime), Path.GetFullPath(personalPath[0]));
        AssertFalse(personalPath.Any(path =>
            path.Contains("attacker", StringComparison.OrdinalIgnoreCase)
            || path.Contains("fnm", StringComparison.OrdinalIgnoreCase)));
        AssertEqual(
            Path.GetFullPath(Environment.GetFolderPath(Environment.SpecialFolder.Windows)),
            Path.GetFullPath(personalEnvironment.Environment["SystemRoot"]!));
        AssertEqual(
            Path.Combine(Environment.SystemDirectory, "cmd.exe"),
            personalEnvironment.Environment["COMSPEC"]);

        var inheritedNodeOptions = Environment.GetEnvironmentVariable("NODE_OPTIONS");
        var inheritedNodePath = Environment.GetEnvironmentVariable("NODE_PATH");
        var inheritedDshHome = Environment.GetEnvironmentVariable("DSH_HOME");
        try
        {
            Environment.SetEnvironmentVariable("NODE_OPTIONS", "--require inherited-attacker.js");
            Environment.SetEnvironmentVariable("NODE_PATH", @"C:\inherited-node-path");
            Environment.SetEnvironmentVariable("DSH_HOME", @"C:\inherited-attacker-home");
            var inheritedPersonalStart = personalService.CreateStartInfo();
            AssertFalse(ContainsEnvironmentKey(inheritedPersonalStart, "NODE_OPTIONS"));
            AssertFalse(ContainsEnvironmentKey(inheritedPersonalStart, "NODE_PATH"));
            AssertEqual(data, inheritedPersonalStart.Environment["DSH_HOME"]);
            AssertEqual("1", inheritedPersonalStart.Environment["DSH_TELEMETRY_DISABLED"]);
        }
        finally
        {
            Environment.SetEnvironmentVariable("NODE_OPTIONS", inheritedNodeOptions);
            Environment.SetEnvironmentVariable("NODE_PATH", inheritedNodePath);
            Environment.SetEnvironmentVariable("DSH_HOME", inheritedDshHome);
        }

        var rejectedOptions = new[]
        {
            options with { Profile = "web" },
            options with { Profile = "--profile=enterprise-managed" },
            options with { Host = "localhost" },
            options with { Port = 3182 },
            options with { EnterpriseManagedFixedPort = null },
            options with { EnterpriseManagedFixedPort = 3182 },
            options with { EnterpriseManagedPluginRoot = null },
            options with { EnterpriseManagedSkillsRoot = null },
            options with { EnterpriseManagedSkillsRoot = pluginRoot },
            options with
            {
                EnterpriseManagedSkillsRoot = Path.Combine(root, "outside-skills"),
            },
            options with { WorkingDirectory = Path.Combine(data, "other") },
            options with
            {
                WorkingDirectory = Path.Combine(data, "temporary", "..", "workspaces"),
            },
            options with { AdditionalArguments = ["web"] },
            options with { AdditionalArguments = ["--host", "127.0.0.1"] },
            options with { AdditionalArguments = ["--profile=enterprise-managed"] },
            options with { CaptureRawProcessOutput = true },
        };
        foreach (var rejected in rejectedOptions)
        {
            await AssertThrowsAsync<InvalidOperationException>(() => Task.Run(rejected.Validate));
        }
    }

    private static async Task DshEnterpriseDirectLocalHostBoundaryAsync()
    {
        var root = Path.Combine(TempRoot, $"enterprise-direct-local-host-{Guid.NewGuid():N}");
        var runtime = Path.Combine(root, "runtime");
        var data = Path.Combine(root, "harness-home");
        var workspace = Path.Combine(data, "workspaces");
        var logs = Path.Combine(root, "logs");
        var pluginRoot = Path.Combine(root, "plugins");
        var skillsRoot = Path.Combine(pluginRoot, "plugin-release", "skills");
        var entry = Path.Combine(
            runtime,
            "node_modules",
            "@deepseek-ai",
            "dsh",
            "lib",
            "bin.js");
        Directory.CreateDirectory(Path.GetDirectoryName(entry)!);
        Directory.CreateDirectory(workspace);
        Directory.CreateDirectory(skillsRoot);
        File.WriteAllText(Path.Combine(runtime, "node.exe"), "node");
        File.WriteAllText(entry, "entry");
        var runtimeMetadataPath = Path.Combine(runtime, DshRuntimeMetadata.FileName);
        const string directLocalRuntimeMetadata =
            "{\"schemaVersion\":3,\"webAuthProtocol\":\"browser-launch-cookie-v1\"," +
            "\"managedUpdateProtocol\":\"enterprise-direct-local-v1\"," +
            "\"runtimeProfile\":\"enterprise-direct-local\"}";
        File.WriteAllText(runtimeMetadataPath, directLocalRuntimeMetadata);

        var options = DshRuntimeOptions.CreateEnterpriseDirectLocal(
            runtime,
            data,
            logs,
            workspace,
            fixedPort: 3181,
            pluginRoot,
            skillsRoot);
        AssertTrue(options.IsEnterpriseDirectLocal);
        AssertFalse(options.IsEnterpriseManaged);
        AssertTrue(options.SupportsManagedUpdate);
        AssertEqual(new Uri("http://127.0.0.1:3181/"), options.WebUiUri);
        AssertTrue(options.ControlledEnvironment is null);

        await using var service = new DshHostService(options);
        var startInfo = service.CreateStartInfo();
        AssertEqual(options.NodePath, startInfo.FileName);
        AssertEqual(workspace, startInfo.WorkingDirectory);
        AssertFalse(startInfo.UseShellExecute);
        AssertTrue(startInfo.CreateNoWindow);
        AssertEqual(ProcessWindowStyle.Hidden, startInfo.WindowStyle);
        AssertSequenceEqual(
            new[]
            {
                options.EntryPointPath,
                "--profile",
                DshRuntimeOptions.EnterpriseDirectLocalProfile,
                "--host",
                "127.0.0.1",
                "--port",
                "3181",
            },
            startInfo.ArgumentList.ToArray());
        AssertFalse(ContainsEnvironmentKey(startInfo, "DEEPSEEK_API_KEY"));
        AssertFalse(ContainsEnvironmentKey(startInfo, "DEEPSEEK_BASE_URL"));
        AssertFalse(ContainsEnvironmentKey(startInfo, "DEEPSEEK_SEARCH_BASE_URL"));
        AssertFalse(options.ToString().Contains("API_KEY", StringComparison.OrdinalIgnoreCase));

        var hostile = new ProcessStartInfo();
        hostile.Environment["nOdE_oPtIoNs"] = "--require attacker.js";
        hostile.Environment["dsh_profile"] = "attacker";
        hostile.Environment["DeepSeek_api_key"] = "attacker";
        hostile.Environment["deepseek_base_url"] = "https://attacker.invalid/v1";
        hostile.Environment["https_proxy"] = "http://attacker:8080";
        hostile.Environment["eNsOu_dSh_eNtErPrIsE_sKiLlS_rOoT"] =
            @"C:\attacker-skills";
        options.ApplyProcessEnvironment(hostile);
        AssertFalse(ContainsEnvironmentKey(hostile, "NODE_OPTIONS"));
        AssertFalse(ContainsEnvironmentKey(hostile, "DSH_PROFILE"));
        AssertFalse(ContainsEnvironmentKey(hostile, "DEEPSEEK_API_KEY"));
        AssertFalse(ContainsEnvironmentKey(hostile, "DEEPSEEK_BASE_URL"));
        AssertFalse(ContainsEnvironmentKey(hostile, "HTTPS_PROXY"));
        AssertEqual(data, hostile.Environment["DSH_HOME"]);
        AssertEqual("1", hostile.Environment["DSH_TELEMETRY_DISABLED"]);
        AssertEqual(
            DshRuntimeOptions.EnterpriseManagedBootMarker,
            hostile.Environment["DSH_ENTERPRISE_MANAGED_BOOT"]);
        AssertEqual(
            skillsRoot,
            hostile.Environment[
                DshRuntimeOptions.EnterpriseManagedSkillsRootEnvironmentVariable]);
        AssertEqual(DshRuntimeOptions.LoopbackNoProxy, hostile.Environment["NO_PROXY"]);

        var providerEnvironment = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["DEEPSEEK_BASE_URL"] = "http://127.0.0.1:54321/v1",
            ["DEEPSEEK_API_KEY"] = EncodeBase64Url(RandomNumberGenerator.GetBytes(32)),
            ["DEEPSEEK_SEARCH_BASE_URL"] = "http://127.0.0.1:54321/v1",
        };
        var rejectedOptions = new[]
        {
            options with { Host = "localhost" },
            options with { Profile = DshRuntimeOptions.EnterpriseManagedProfile },
            options with { Profile = "web" },
            options with { AdditionalArguments = ["--no-open"] },
            options with { ControlledEnvironment = providerEnvironment },
            options with { EnterpriseManagedFixedPort = null },
            options with { EnterpriseManagedPluginRoot = null },
            options with { EnterpriseManagedSkillsRoot = null },
            options with { EnterpriseManagedSkillsRoot = pluginRoot },
            options with { WorkingDirectory = Path.Combine(data, "other") },
            options with { CaptureRawProcessOutput = true },
            options with { EnablePersonalManagedUpdate = true },
        };
        foreach (var rejected in rejectedOptions)
        {
            await AssertThrowsAsync<InvalidOperationException>(() => Task.Run(rejected.Validate));
        }

        File.Delete(runtimeMetadataPath);
        await AssertThrowsAsync<InvalidOperationException>(() => Task.Run(options.Validate));

        var unsupportedMetadata = new[]
        {
            "{\"schemaVersion\":1,\"webAuthProtocol\":\"browser-launch-cookie-v1\"}",
            "{\"schemaVersion\":2,\"webAuthProtocol\":\"browser-launch-cookie-v1\"," +
                "\"managedUpdateProtocol\":\"personal-web-v1\"}",
        };
        foreach (var metadata in unsupportedMetadata)
        {
            File.WriteAllText(runtimeMetadataPath, metadata);
            await AssertThrowsAsync<InvalidOperationException>(() => Task.Run(options.Validate));
        }

        var invalidDirectLocalMetadata = new[]
        {
            "{\"schemaVersion\":3,\"webAuthProtocol\":\"legacy-clean-root-v1\"," +
                "\"managedUpdateProtocol\":\"enterprise-direct-local-v1\"," +
                "\"runtimeProfile\":\"enterprise-direct-local\"}",
            "{\"schemaVersion\":3,\"webAuthProtocol\":\"browser-launch-cookie-v1\"," +
                "\"managedUpdateProtocol\":\"personal-web-v1\"," +
                "\"runtimeProfile\":\"enterprise-direct-local\"}",
            "{\"schemaVersion\":3,\"webAuthProtocol\":\"browser-launch-cookie-v1\"," +
                "\"managedUpdateProtocol\":\"enterprise-direct-local-v1\"," +
                "\"runtimeProfile\":\"enterprise-managed\"}",
            directLocalRuntimeMetadata[..^1] + ",\"unknown\":true}",
            "{\"schemaVersion\":3,\"schemaVersion\":3," +
                "\"webAuthProtocol\":\"browser-launch-cookie-v1\"," +
                "\"managedUpdateProtocol\":\"enterprise-direct-local-v1\"," +
                "\"runtimeProfile\":\"enterprise-direct-local\"}",
        };
        foreach (var metadata in invalidDirectLocalMetadata)
        {
            File.WriteAllText(runtimeMetadataPath, metadata);
            await AssertThrowsAsync<InvalidDataException>(() => Task.Run(options.Validate));
        }
    }

    private static async Task DshPersonalManagedUpdateHostBoundaryAsync()
    {
        var root = Path.Combine(TempRoot, $"personal-managed-host-{Guid.NewGuid():N}");
        var runtime = Path.Combine(root, "runtime");
        var entry = Path.Combine(
            runtime,
            "node_modules",
            "@deepseek-ai",
            "dsh",
            "lib",
            "bin.js");
        Directory.CreateDirectory(Path.GetDirectoryName(entry)!);
        File.WriteAllText(Path.Combine(runtime, "node.exe"), "node");
        File.WriteAllText(entry, "entry");
        File.WriteAllText(
            Path.Combine(runtime, DshRuntimeMetadata.FileName),
            "{\"schemaVersion\":2,\"webAuthProtocol\":\"browser-launch-cookie-v1\",\"managedUpdateProtocol\":\"personal-web-v1\"}");

        var options = DshRuntimeOptions.CreatePersonalManagedWeb(
            runtime,
            Path.Combine(root, "home"),
            Path.Combine(root, "logs"),
            port: 3182);
        AssertTrue(options.SupportsManagedUpdate);
        AssertFalse(options.IsEnterpriseManaged);
        await using (var startInfoService = new DshHostService(options))
        {
            var startInfo = startInfoService.CreateStartInfo();
            AssertSequenceEqual(
                new[]
                {
                    options.EntryPointPath,
                    "web",
                    "--no-open",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    "3182",
                },
                startInfo.ArgumentList.ToArray());
            AssertEqual(
                DshRuntimeOptions.PersonalManagedUpdateBootMarker,
                startInfo.Environment[DshRuntimeOptions.PersonalManagedUpdateBootEnvironmentVariable]);
            AssertFalse(ContainsEnvironmentKey(startInfo, "DSH_ENTERPRISE_MANAGED_BOOT"));
        }

        var preStartCalls = 0;
        await using var service = new DshHostService(
            options,
            validateBeforeProcessStart: () => preStartCalls++);
        await AssertThrowsAsync<InvalidOperationException>(() => service.EnsureStartedAsync());
        AssertEqual(0, preStartCalls);

        var enterpriseAttempt = options with { Mode = DshRuntimeMode.EnterpriseManaged };
        await AssertThrowsAsync<InvalidOperationException>(() => Task.Run(enterpriseAttempt.Validate));
        var nonLoopbackAttempt = options with { Host = "localhost" };
        await AssertThrowsAsync<InvalidOperationException>(() => Task.Run(nonLoopbackAttempt.Validate));
        var enterpriseConstraintAttempt = options with
        {
            Profile = DshRuntimeOptions.EnterpriseManagedProfile,
        };
        await AssertThrowsAsync<InvalidOperationException>(() => Task.Run(enterpriseConstraintAttempt.Validate));

        File.WriteAllText(
            Path.Combine(runtime, DshRuntimeMetadata.FileName),
            "{\"schemaVersion\":1,\"webAuthProtocol\":\"browser-launch-cookie-v1\"}");
        await AssertThrowsAsync<InvalidOperationException>(() => Task.Run(options.Validate));
    }

    private static async Task DshRuntimeWebAuthMetadataContractAsync()
    {
        var root = Path.Combine(TempRoot, $"runtime-auth-metadata-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        var path = Path.Combine(root, DshRuntimeMetadata.FileName);
        AssertEqual(
            DshRuntimeWebAuthProtocol.LegacyCleanRootV1,
            DshRuntimeMetadata.ReadWebAuthProtocol(root));
        AssertFalse(DshRuntimeMetadata.ReadSupportsPersonalManagedUpdate(root));
        AssertEqual(
            DshRuntimeWebAuthProtocolContract.LegacyCleanRootV1,
            DshRuntimeWebAuthProtocolContract.GetName(
                DshRuntimeWebAuthProtocol.LegacyCleanRootV1));

        File.WriteAllText(
            path,
            "{\"schemaVersion\":1,\"webAuthProtocol\":\"browser-launch-cookie-v1\"}");
        AssertEqual(
            DshRuntimeWebAuthProtocol.BrowserLaunchCookieV1,
            DshRuntimeMetadata.ReadWebAuthProtocol(root));
        AssertFalse(DshRuntimeMetadata.ReadSupportsPersonalManagedUpdate(root));

        File.WriteAllText(
            path,
            "{\"schemaVersion\":2,\"webAuthProtocol\":\"browser-launch-cookie-v1\",\"managedUpdateProtocol\":\"personal-web-v1\"}");
        AssertEqual(
            DshRuntimeWebAuthProtocol.BrowserLaunchCookieV1,
            DshRuntimeMetadata.ReadWebAuthProtocol(root));
        AssertTrue(DshRuntimeMetadata.ReadSupportsPersonalManagedUpdate(root));

        foreach (var rejected in new[]
        {
            "{\"schemaVersion\":1,\"webAuthProtocol\":\"unknown-v1\"}",
            "{\"schemaVersion\":1,\"schemaVersion\":1,\"webAuthProtocol\":\"browser-launch-cookie-v1\"}",
            "{\"SchemaVersion\":1,\"WebAuthProtocol\":\"browser-launch-cookie-v1\"}",
            "{\"schemaVersion\":1,\"webAuthProtocol\":\"browser-launch-cookie-v1\",\"extra\":true}",
            "{\"schemaVersion\":1,\"webAuthProtocol\":\"browser-launch-cookie-v1\",\"managedUpdateProtocol\":\"personal-web-v1\"}",
            "{\"webAuthProtocol\":\"browser-launch-cookie-v1\",\"managedUpdateProtocol\":\"personal-web-v1\"}",
            "{\"schemaVersion\":2,\"webAuthProtocol\":\"browser-launch-cookie-v1\"}",
            "{\"schemaVersion\":2,\"webAuthProtocol\":\"legacy-clean-root-v1\",\"managedUpdateProtocol\":\"personal-web-v1\"}",
            "{\"schemaVersion\":2,\"webAuthProtocol\":\"browser-launch-cookie-v1\",\"managedUpdateProtocol\":\"wrong\"}",
            "{\"schemaVersion\":2,\"webAuthProtocol\":\"browser-launch-cookie-v1\",\"managedUpdateProtocol\":\"personal-web-v1\",\"extra\":true}",
            "{\"schemaVersion\":2,\"webAuthProtocol\":\"browser-launch-cookie-v1\",\"managedUpdateProtocol\":\"personal-web-v1\",\"managedUpdateProtocol\":\"personal-web-v1\"}",
        })
        {
            File.WriteAllText(path, rejected);
            await AssertThrowsAsync<InvalidDataException>(() => Task.Run(() =>
                DshRuntimeMetadata.ReadWebAuthProtocol(root)));
        }
    }

    private static async Task DshBrowserLaunchAnnouncementContractAsync()
    {
        var webUiUri = new Uri("http://127.0.0.1:3191/");
        var token = EncodeBase64Url(RandomNumberGenerator.GetBytes(32));
        var launch = $"http://127.0.0.1:3191/?token={token}";
        AssertEqual(
            new Uri(launch),
            DshBrowserAuthentication.ParseLaunchAnnouncement(
                $"dsh web: {launch}",
                webUiUri));
        AssertTrue(DshBrowserAuthentication.ParseLaunchAnnouncement(
            "ordinary diagnostic",
            webUiUri) is null);
        var redacted = DshBrowserAuthentication.RedactTokens(
            $"before {launch} after");
        AssertFalse(redacted.Contains(token, StringComparison.Ordinal));
        AssertTrue(redacted.Contains("?token=<redacted>", StringComparison.Ordinal));

        foreach (var rejected in new[]
        {
            $"dsh web: http://localhost:3191/?token={token}",
            $"dsh web: http://127.0.0.1:3192/?token={token}",
            $"dsh web: http://127.0.0.1:3191/index.html?token={token}",
            $"dsh web: http://127.0.0.1:3191/?token={token}&extra=1",
            $"dsh web: http://127.0.0.1:3191/?token={token[..42]}",
            $"dsh web: {launch} trailing",
        })
        {
            await AssertThrowsAsync<InvalidDataException>(() => Task.Run(() =>
                DshBrowserAuthentication.ParseLaunchAnnouncement(rejected, webUiUri)));
        }

        var session = new DshBrowserSession(7, new Uri(launch), "secret-cookie");
        AssertFalse(session.ToString().Contains(token, StringComparison.Ordinal));
        AssertFalse(session.ToString().Contains("secret-cookie", StringComparison.Ordinal));
        var result = new DshLaunchResult(
            DshLaunchState.Started,
            webUiUri,
            7);
        AssertFalse(result.ToString().Contains(token, StringComparison.Ordinal));
        var serializedResult = JsonSerializer.Serialize(result);
        AssertFalse(serializedResult.Contains(token, StringComparison.Ordinal));
        AssertFalse(serializedResult.Contains("BrowserLaunch", StringComparison.Ordinal));
        AssertFalse(result.GetType().GetProperties().Any(property =>
            property.Name.Contains("BrowserLaunch", StringComparison.Ordinal)));
    }

    private static async Task DshBrowserTokenExchangeContractAsync()
    {
        var webUiUri = new Uri("http://127.0.0.1:3191/");
        var token = EncodeBase64Url(RandomNumberGenerator.GetBytes(32));
        var launchUri = new Uri($"http://127.0.0.1:3191/?token={token}");
        var cookieName = "dsh-auth-" + EncodeBase64Url(SHA256.HashData(
            Encoding.UTF8.GetBytes("127.0.0.1:3191")));
        var cookieValue = $"v1.{EncodeBase64Url(Encoding.UTF8.GetBytes("{}"))}." +
            EncodeBase64Url(RandomNumberGenerator.GetBytes(32));
        var setCookie = $"{cookieName}={cookieValue}; Max-Age=2592000; Path=/; " +
            "Expires=Tue, 29 Sep 2026 12:00:00 GMT; HttpOnly; SameSite=Strict";

        using var client = new HttpClient(new DelegateHandler(request =>
        {
            AssertEqual(HttpMethod.Get, request.Method);
            AssertEqual(launchUri, request.RequestUri);
            var response = new HttpResponseMessage(HttpStatusCode.SeeOther);
            response.Headers.Location = new Uri("/", UriKind.Relative);
            response.Headers.TryAddWithoutValidation("Cache-Control", "no-store");
            response.Headers.TryAddWithoutValidation("Referrer-Policy", "no-referrer");
            response.Headers.TryAddWithoutValidation("Set-Cookie", setCookie);
            return response;
        }));
        var session = await DshBrowserAuthentication.ExchangeAsync(
            client,
            launchUri,
            webUiUri,
            processId: 19,
            CancellationToken.None);
        AssertEqual(19, session.ProcessId);
        AssertEqual(launchUri, session.LaunchUri);
        AssertEqual($"{cookieName}={cookieValue}", session.CookieHeader);
        using var authenticated = new HttpRequestMessage(HttpMethod.Get, webUiUri);
        DshBrowserAuthentication.ApplyCookie(authenticated, session);
        AssertEqual(session.CookieHeader, authenticated.Headers.GetValues("Cookie").Single());
        AssertFalse(session.ToString().Contains(cookieValue, StringComparison.Ordinal));

        foreach (var rejectedResponse in new Func<HttpResponseMessage>[]
        {
            () =>
            {
                var response = new HttpResponseMessage(HttpStatusCode.OK);
                response.Headers.TryAddWithoutValidation("Set-Cookie", setCookie);
                return response;
            },
            () =>
            {
                var response = new HttpResponseMessage(HttpStatusCode.SeeOther);
                response.Headers.Location = new Uri("/", UriKind.Relative);
                response.Headers.TryAddWithoutValidation("Cache-Control", "no-store, private");
                response.Headers.TryAddWithoutValidation("Referrer-Policy", "no-referrer");
                response.Headers.TryAddWithoutValidation("Set-Cookie", setCookie);
                return response;
            },
            () =>
            {
                var response = new HttpResponseMessage(HttpStatusCode.SeeOther);
                response.Headers.Location = new Uri("/", UriKind.Relative);
                response.Headers.TryAddWithoutValidation("Cache-Control", "no-store");
                response.Headers.TryAddWithoutValidation("Referrer-Policy", "no-referrer");
                response.Headers.TryAddWithoutValidation(
                    "Set-Cookie",
                    setCookie.Replace(cookieName, "dsh-auth-wrong", StringComparison.Ordinal));
                return response;
            },
        })
        {
            using var rejectedClient = new HttpClient(new DelegateHandler(_ => rejectedResponse()));
            await AssertThrowsAsync<InvalidDataException>(() =>
                DshBrowserAuthentication.ExchangeAsync(
                    rejectedClient,
                    launchUri,
                    webUiUri,
                    processId: 19,
                    CancellationToken.None));
        }
    }

    private static Task DshBrowserShellFailureRedactionAsync()
    {
        var token = EncodeBase64Url(RandomNumberGenerator.GetBytes(32));
        var launchUri = new Uri($"http://127.0.0.1:3191/?token={token}");
        try
        {
            DshBrowserLauncher.Open(
                launchUri,
                startInfo => throw new InvalidOperationException(
                    $"Synthetic ShellExecute failure for {startInfo.FileName}"));
        }
        catch (InvalidOperationException exception)
        {
            AssertEqual(DshBrowserLauncher.FailureMessage, exception.Message);
            AssertFalse(exception.Message.Contains(token, StringComparison.Ordinal));
            AssertTrue(exception.InnerException is null);
            DshBrowserLauncher.Open(launchUri, _ => null);
            return Task.CompletedTask;
        }

        throw new InvalidOperationException(
            "The synthetic browser launch failure was not propagated safely.");
    }

    private static async Task DshCandidateInstallHealthSuccessAsync()
    {
        var options = CreateCandidateHealthOptions();
        var requestCount = 0;
        using var client = new HttpClient(new DelegateHandler(request =>
        {
            requestCount++;
            if (request.Method == HttpMethod.Get)
            {
                AssertEqual(options.WebUiUri, request.RequestUri);
                return CreateHealthyWebUiResponse();
            }

            AssertEqual(HttpMethod.Post, request.Method);
            AssertEqual(new Uri(options.WebUiUri, "api/session.list"), request.RequestUri);
            AssertEqual("application/json", request.Content?.Headers.ContentType?.MediaType);
            var body = request.Content?.ReadAsStringAsync().GetAwaiter().GetResult()
                ?? throw new InvalidOperationException("Candidate health request body is missing.");
            using var document = JsonDocument.Parse(body);
            var root = document.RootElement;
            AssertEqual(JsonValueKind.Object, root.ValueKind);
            AssertEqual(4, root.EnumerateObject().Count());
            AssertEqual("client-request", root.GetProperty("type").GetString());
            var rpcId = root.GetProperty("rpcId").GetString()
                ?? throw new InvalidOperationException("Candidate health rpcId is missing.");
            AssertTrue(rpcId.StartsWith(
                "candidate-install-health-",
                StringComparison.Ordinal));
            AssertEqual("session.list", root.GetProperty("method").GetString());
            var payload = root.GetProperty("payload");
            AssertEqual(JsonValueKind.Object, payload.ValueKind);
            AssertFalse(payload.EnumerateObject().Any());
            AssertEqual(
                $"{{\"type\":\"client-request\",\"rpcId\":\"{rpcId}\",\"method\":\"session.list\",\"payload\":{{}}}}",
                body);
            return CreateJsonResponse(
                $"{{\"type\":\"server-response\",\"rpcId\":\"{rpcId}\",\"result\":{{\"ok\":true,\"value\":{{\"items\":[{{\"id\":\"existing-local-session\"}}]}}}}}}");
        }));
        using var ownedProcess = StartHiddenPingProcess(keepRunning: true);
        await using var service = CreateSyntheticHealthService(options, client);
        AttachOwnedProcess(service, ownedProcess);

        AssertTrue(await service.IsCandidateInstallHealthyAsync());
        AssertEqual(2, requestCount);
        AssertFalse(await service.CompleteCandidateInstallHealthAsync(1));
        await AssertThrowsAsync<ArgumentOutOfRangeException>(() =>
            service.CompleteCandidateInstallHealthAsync(0));
    }

    private static async Task DshBrowserCookieCandidateHealthAsync()
    {
        var options = CreateCandidateHealthOptions(
            DshRuntimeWebAuthProtocol.BrowserLaunchCookieV1);
        var token = EncodeBase64Url(RandomNumberGenerator.GetBytes(32));
        var launchUri = new Uri($"{options.WebUiUri.AbsoluteUri}?token={token}");
        const string cookieHeader =
            "dsh-auth-test=v1.e30.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
        var requestCount = 0;
        using var client = new HttpClient(new DelegateHandler(request =>
        {
            requestCount++;
            AssertEqual(cookieHeader, request.Headers.GetValues("Cookie").Single());
            if (request.Method == HttpMethod.Get)
            {
                AssertEqual(options.WebUiUri, request.RequestUri);
                return CreateHealthyWebUiResponse();
            }

            AssertEqual(HttpMethod.Post, request.Method);
            AssertEqual(new Uri(options.WebUiUri, "api/session/list"), request.RequestUri);
            AssertEqual("application/json", request.Content?.Headers.ContentType?.MediaType);
            var body = request.Content?.ReadAsStringAsync().GetAwaiter().GetResult()
                ?? throw new InvalidOperationException(
                    "Alpha candidate health request body is missing.");
            using var document = JsonDocument.Parse(body);
            var root = document.RootElement;
            AssertEqual(4, root.EnumerateObject().Count());
            AssertEqual("client-request", root.GetProperty("type").GetString());
            var rpcId = root.GetProperty("rpcId").GetString()
                ?? throw new InvalidOperationException(
                    "Alpha candidate health rpcId is missing.");
            AssertEqual("session/list", root.GetProperty("method").GetString());
            var payload = root.GetProperty("payload");
            AssertEqual(1, payload.EnumerateObject().Count());
            var args = payload.GetProperty("args");
            AssertEqual(1, args.EnumerateObject().Count());
            AssertEqual(JsonValueKind.Object, args.GetProperty("_request").ValueKind);
            AssertFalse(args.GetProperty("_request").EnumerateObject().Any());
            AssertEqual(
                $"{{\"type\":\"client-request\",\"rpcId\":\"{rpcId}\",\"method\":\"session/list\",\"payload\":{{\"args\":{{\"_request\":{{}}}}}}}}",
                body);
            return CreateJsonResponse(
                $"{{\"type\":\"server-response\",\"rpcId\":\"{rpcId}\",\"result\":{{\"ok\":true,\"value\":{{\"items\":[]}}}}}}");
        }));
        using var ownedProcess = StartHiddenPingProcess(keepRunning: true);
        await using var service = CreateSyntheticHealthService(options, client);
        AttachBrowserSession(
            service,
            ownedProcess,
            new DshBrowserSession(ownedProcess.Id, launchUri, cookieHeader));
        using var staleProcessIdentity = new Process();
        InvokeOwnedProcessExited(service, staleProcessIdentity);

        AssertTrue(await service.IsCandidateInstallHealthyAsync());
        AssertEqual(2, requestCount);
        AssertEqual(2, requestCount);
        await service.StopOwnedProcessAsync();
        await AssertThrowsAsync<InvalidOperationException>(
            () => service.OpenWebUiAsync());
    }

    private static async Task DshBrowserAuthStartupFailureStopsOwnedProcessAsync()
    {
        var options = CreateCandidateHealthOptions(
            DshRuntimeWebAuthProtocol.BrowserLaunchCookieV1) with
        {
            StartupTimeout = TimeSpan.FromSeconds(5),
        };
        using var client = new HttpClient(new DelegateHandler(_ =>
            throw new InvalidOperationException(
                "Health must not run before browser authentication.")));
        using var ownedProcess = StartHiddenPingProcess(keepRunning: true);
        using var processObserver = Process.GetProcessById(ownedProcess.Id);
        await using var service = CreateSyntheticHealthService(options, client);
        AttachBrowserReadinessFailure(
            service,
            ownedProcess,
            new InvalidDataException("Synthetic malformed launch announcement."));

        await AssertThrowsAsync<InvalidDataException>(() => service.EnsureStartedAsync());
        AssertTrue(processObserver.HasExited);
        AssertFalse(service.OwnsRunningProcess);
        await AssertThrowsAsync<InvalidOperationException>(
            () => service.OpenWebUiAsync());
    }

    private static async Task DshFaultedOutputPumpStillReleasesOwnedProcessAsync()
    {
        var options = CreateCandidateHealthOptions();
        using var ownedProcess = StartHiddenPingProcess(keepRunning: true);
        using var processObserver = Process.GetProcessById(ownedProcess.Id);
        var service = new DshHostService(options);
        try
        {
            AttachOwnedProcess(service, ownedProcess);
            SetFaultedOutputPump(
                service,
                Task.FromException(new IOException("Synthetic output-pump failure.")));

            await AssertThrowsAsync<AggregateException>(
                () => service.StopOwnedProcessAsync());
            AssertTrue(processObserver.HasExited);
            AssertFalse(service.OwnsRunningProcess);
        }
        finally
        {
            await service.DisposeAsync();
        }
    }

    private static async Task DshAlreadyExitedStopStillReleasesOwnedProcessAsync()
    {
        var options = CreateCandidateHealthOptions();
        using var ownedProcess = StartHiddenPingProcess(keepRunning: false);
        await ownedProcess.WaitForExitAsync();
        var service = new DshHostService(options);
        try
        {
            AttachOwnedProcess(service, ownedProcess);
            SetFaultedOutputPump(
                service,
                Task.FromException(new IOException("Synthetic exited-process pump failure.")));

            await AssertThrowsAsync<AggregateException>(
                () => service.StopOwnedProcessAsync());
            AssertFalse(service.OwnsRunningProcess);
        }
        finally
        {
            await service.DisposeAsync();
        }
    }

    private static async Task DshExitedOwnedProcessCleansBeforeHealthAsync()
    {
        var options = CreateCandidateHealthOptions();
        using var ownedProcess = StartHiddenPingProcess(keepRunning: false);
        await ownedProcess.WaitForExitAsync();
        var healthRequests = 0;
        using var client = new HttpClient(new DelegateHandler(_ =>
        {
            healthRequests++;
            return CreateHealthyWebUiResponse();
        }));
        var service = new DshHostService(options, client);
        try
        {
            AttachOwnedProcess(service, ownedProcess);
            SetFaultedOutputPump(
                service,
                Task.FromException(new IOException("Synthetic stale-process pump failure.")));

            await AssertThrowsAsync<AggregateException>(
                () => service.EnsureStartedAsync());
            AssertEqual(0, healthRequests);
            AssertFalse(service.OwnsRunningProcess);
        }
        finally
        {
            await service.DisposeAsync();
        }
    }

    private static async Task DshJobClosesBeforeOutputPumpsAsync()
    {
        var options = CreateCandidateHealthOptions();
        using var ownedProcess = StartHiddenPingProcess(keepRunning: true);
        using var processObserver = Process.GetProcessById(ownedProcess.Id);
        var jobObject = WindowsJobObject.CreateKillOnClose();
        jobObject.Assign(ownedProcess);
        var pumpCompletion = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        ownedProcess.EnableRaisingEvents = true;
        ownedProcess.Exited += (_, _) => pumpCompletion.TrySetResult();
        var service = new DshHostService(options);
        try
        {
            AttachOwnedProcess(service, ownedProcess);
            AttachOwnedJobObject(service, jobObject);
            SetFaultedOutputPump(service, pumpCompletion.Task);

            await InvokeReleaseOwnedProcessAsync(service, ownedProcess)
                .WaitAsync(TimeSpan.FromSeconds(5));
            AssertTrue(processObserver.HasExited);
            AssertTrue(pumpCompletion.Task.IsCompletedSuccessfully);
            AssertFalse(service.OwnsRunningProcess);
        }
        finally
        {
            jobObject.Dispose();
            await service.DisposeAsync();
        }
    }

    private static async Task DshDelayedOldExitCallbackCannotCloseNewJobAsync()
    {
        var options = CreateCandidateHealthOptions();
        using var oldProcess = StartHiddenPingProcess(keepRunning: true);
        using var newProcess = StartHiddenPingProcess(keepRunning: true);
        using var oldObserver = Process.GetProcessById(oldProcess.Id);
        using var newObserver = Process.GetProcessById(newProcess.Id);
        using var oldJob = WindowsJobObject.CreateKillOnClose();
        using var newJob = WindowsJobObject.CreateKillOnClose();
        oldJob.Assign(oldProcess);
        newJob.Assign(newProcess);
        var service = new DshHostService(options);
        try
        {
            AttachOwnedProcess(service, newProcess);
            AttachOwnedJobObject(service, newJob);

            InvokeOwnedProcessExitHandler(service, oldProcess, oldJob);
            await oldObserver.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));

            AssertTrue(oldObserver.HasExited);
            AssertFalse(newObserver.HasExited);
            AssertTrue(ReferenceEquals(ReadOwnedJobObject(service), newJob));

            await service.StopOwnedProcessAsync().WaitAsync(TimeSpan.FromSeconds(5));
            await newObserver.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));
            AssertTrue(newObserver.HasExited);
            AssertTrue(ReadOwnedJobObject(service) is null);
        }
        finally
        {
            await service.DisposeAsync();
        }
    }

    private static async Task DshExitCallbackRetainsTimedOutJobAsync()
    {
        var options = CreateCandidateHealthOptions();
        using var ownedProcess = StartHiddenPingProcess(keepRunning: true);
        using var processObserver = Process.GetProcessById(ownedProcess.Id);
        using var jobObject = WindowsJobObject.CreateKillOnClose();
        jobObject.Assign(ownedProcess);
        var service = new DshHostService(options);
        try
        {
            AttachOwnedProcess(service, ownedProcess);
            AttachOwnedJobObject(service, jobObject);

            service.HandleOwnedProcessExitedForTest(
                ownedProcess,
                jobObject,
                _ => throw new TimeoutException("Synthetic Job Object timeout."));

            AssertTrue(ReferenceEquals(ReadOwnedJobObject(service), jobObject));
            AssertFalse(processObserver.HasExited);

            await service.StopOwnedProcessAsync().WaitAsync(TimeSpan.FromSeconds(5));
            await processObserver.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));
            AssertTrue(processObserver.HasExited);
            AssertTrue(ReadOwnedJobObject(service) is null);
        }
        finally
        {
            await service.DisposeAsync();
        }
    }

    private static async Task DshExactExitCallbackRacesShutdownAsync()
    {
        var options = CreateCandidateHealthOptions();
        using var ownedProcess = StartHiddenPingProcess(keepRunning: true);
        using var processObserver = Process.GetProcessById(ownedProcess.Id);
        using var jobObject = WindowsJobObject.CreateKillOnClose();
        jobObject.Assign(ownedProcess);
        var pumpCompletion = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var service = new DshHostService(options);
        try
        {
            AttachOwnedProcess(service, ownedProcess);
            AttachOwnedJobObject(service, jobObject);
            SetFaultedOutputPump(service, pumpCompletion.Task);

            var stop = service.StopOwnedProcessAsync();
            AssertTrue(SpinWait.SpinUntil(
                () => ReadOwnedJobObject(service) is null,
                TimeSpan.FromSeconds(5)));
            InvokeOwnedProcessExitHandler(service, ownedProcess, jobObject);
            pumpCompletion.TrySetResult();

            await stop.WaitAsync(TimeSpan.FromSeconds(5));
            await processObserver.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));
            AssertTrue(processObserver.HasExited);
            AssertFalse(service.OwnsRunningProcess);
            AssertTrue(ReadOwnedJobObject(service) is null);
        }
        finally
        {
            pumpCompletion.TrySetResult();
            await service.DisposeAsync();
        }
    }

    private static async Task DshWebUiHealthTitlesAsync()
    {
        var options = CreateCandidateHealthOptions();
        foreach (var testCase in new[]
        {
            (Title: "DeepSeek Harness", Expected: true),
            (Title: "DSH Local Build", Expected: true),
            (Title: "deepseek harness", Expected: false),
            (Title: "DSH local build", Expected: false),
            (Title: "DSH Local Build Preview", Expected: false),
            (Title: "Arbitrary Harness", Expected: false),
        })
        {
            using var client = new HttpClient(new DelegateHandler(_ =>
                CreateWebUiResponse(testCase.Title, includeBootMarker: true)));
            using var ownedProcess = StartHiddenPingProcess(keepRunning: true);
            await using var service = CreateSyntheticHealthService(options, client);
            AttachOwnedProcess(service, ownedProcess);
            AssertEqual(testCase.Expected, await service.IsHealthyAsync());
        }

        using var missingMarkerClient = new HttpClient(new DelegateHandler(_ =>
            CreateWebUiResponse("DSH Local Build", includeBootMarker: false)));
        using var missingMarkerOwnedProcess = StartHiddenPingProcess(keepRunning: true);
        await using var missingMarkerService = CreateSyntheticHealthService(
            options,
            missingMarkerClient);
        AttachOwnedProcess(missingMarkerService, missingMarkerOwnedProcess);
        AssertFalse(await missingMarkerService.IsHealthyAsync());
    }

    private static async Task DshCandidateInstallHealthRejectsFailuresAsync()
    {
        var options = CreateCandidateHealthOptions();
        var webUiCalls = 0;
        var apiCalls = 0;
        using (var client = new HttpClient(new DelegateHandler(request =>
               {
                   if (request.Method == HttpMethod.Get)
                   {
                       webUiCalls++;
                       return CreateHealthyWebUiResponse();
                   }

                   apiCalls++;
                   return new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
               })))
        {
            using var ownedProcess = StartHiddenPingProcess(keepRunning: true);
            await using var service = CreateSyntheticHealthService(
                options,
                client,
                candidateHealthRetryTimeout: TimeSpan.FromMilliseconds(400));
            AttachOwnedProcess(service, ownedProcess);
            AssertTrue(await service.IsHealthyAsync());
            AssertFalse(await service.IsCandidateInstallHealthyAsync());
        }
        AssertTrue(webUiCalls >= 2);
        AssertTrue(apiCalls >= 1);

        AssertFalse(await ProbeCandidateHealthAsync(_ =>
            throw new HttpRequestException("candidate-health-network-failure")));
        var transientApiCalls = 0;
        AssertTrue(await ProbeCandidateHealthAsync(request =>
        {
            transientApiCalls++;
            if (transientApiCalls == 1)
            {
                return new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
            }

            var rpcId = ReadCandidateHealthRpcId(request);
            return CreateJsonResponse(
                $"{{\"type\":\"server-response\",\"rpcId\":\"{rpcId}\",\"result\":{{\"ok\":true,\"value\":{{\"items\":[]}}}}}}");
        }));
        AssertEqual(2, transientApiCalls);
        AssertFalse(await ProbeCandidateHealthAsync(_ => new HttpResponseMessage(
            HttpStatusCode.OK)
        {
            Content = new StringContent(
                "{\"type\":\"server-response\"}",
                Encoding.UTF8,
                "text/plain"),
        }));
        AssertFalse(await ProbeCandidateHealthAsync(_ =>
            CreateJsonResponse("{")));
        AssertFalse(await ProbeCandidateHealthAsync(_ =>
            CreateJsonResponse(
                "{\"type\":\"server-response\",\"rpcId\":\"wrong-rpc-id\",\"result\":{\"ok\":true,\"value\":{\"items\":[]}}}")));
        AssertFalse(await ProbeCandidateHealthAsync(request =>
        {
            var rpcId = ReadCandidateHealthRpcId(request);
            return CreateJsonResponse(
                $"{{\"type\":\"server-response\",\"rpcId\":\"{rpcId}\",\"result\":{{\"ok\":false,\"value\":{{\"items\":[]}}}}}}");
        }));
        AssertFalse(await ProbeCandidateHealthAsync(request =>
        {
            var rpcId = ReadCandidateHealthRpcId(request);
            return CreateJsonResponse(
                $"{{\"type\":\"server-response\",\"rpcId\":\"{rpcId}\",\"result\":{{\"ok\":true,\"value\":{{\"items\":{{}}}}}}}}");
        }));
        AssertFalse(await ProbeCandidateHealthAsync(request =>
        {
            var rpcId = ReadCandidateHealthRpcId(request);
            return CreateJsonResponse(
                $"{{\"type\":\"server-response\",\"type\":\"server-response\",\"rpcId\":\"{rpcId}\",\"result\":{{\"ok\":true,\"value\":{{\"items\":[]}}}}}}");
        }));
        AssertFalse(await ProbeCandidateHealthAsync(_ =>
            CreateJsonResponse(new string('x', (1024 * 1024) + 1))));

        using var timeoutClient = new HttpClient(new AsyncDelegateHandler(
            async (request, cancellationToken) =>
            {
                if (request.Method == HttpMethod.Get)
                {
                    return CreateHealthyWebUiResponse();
                }

                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken)
                    .ConfigureAwait(false);
                return CreateJsonResponse("{}");
            }))
        {
            Timeout = TimeSpan.FromMilliseconds(100),
        };
        using var timeoutOwnedProcess = StartHiddenPingProcess(keepRunning: true);
        await using var timeoutService = CreateSyntheticHealthService(
            options,
            timeoutClient,
            candidateHealthRetryTimeout: TimeSpan.FromMilliseconds(400));
        AttachOwnedProcess(timeoutService, timeoutOwnedProcess);
        AssertFalse(await timeoutService.IsCandidateInstallHealthyAsync());

        var firstStalledBody = new TaskCompletionSource<StallingReadStream>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        using var stalledBodyClient = new HttpClient(new DelegateHandler(request =>
        {
            if (request.Method == HttpMethod.Get)
            {
                return CreateHealthyWebUiResponse();
            }

            var stalledBody = new StallingReadStream();
            firstStalledBody.TrySetResult(stalledBody);
            var content = new StreamContent(stalledBody);
            content.Headers.ContentType = new("application/json");
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = content };
        }))
        {
            Timeout = Timeout.InfiniteTimeSpan,
        };
        using var stalledBodyOwnedProcess = StartHiddenPingProcess(keepRunning: true);
        await using var stalledBodyService = CreateSyntheticHealthService(
            options,
            stalledBodyClient,
            healthProbeTimeout: TimeSpan.FromMilliseconds(100),
            candidateHealthRetryTimeout: TimeSpan.FromMilliseconds(400));
        AttachOwnedProcess(stalledBodyService, stalledBodyOwnedProcess);
        var stalledBodyTimer = Stopwatch.StartNew();
        var stalledBodyHealth = stalledBodyService.IsCandidateInstallHealthyAsync();
        var observedBody = await firstStalledBody.Task.WaitAsync(
            TimeSpan.FromSeconds(2));
        await observedBody.ReadEntered.WaitAsync(TimeSpan.FromSeconds(2));
        AssertFalse(await stalledBodyHealth);
        await observedBody.CancellationObserved.WaitAsync(TimeSpan.FromSeconds(2));
        AssertTrue(stalledBodyTimer.Elapsed < TimeSpan.FromSeconds(2));
    }

    private static async Task DshCandidateInstallHealthCancellationAsync()
    {
        var options = CreateCandidateHealthOptions();
        var apiEntered = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        using var client = new HttpClient(new AsyncDelegateHandler(
            async (request, cancellationToken) =>
            {
                if (request.Method == HttpMethod.Get)
                {
                    return CreateHealthyWebUiResponse();
                }

                apiEntered.TrySetResult();
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken)
                    .ConfigureAwait(false);
                return CreateJsonResponse("{}");
            }))
        {
            Timeout = TimeSpan.FromSeconds(10),
        };
        using var ownedProcess = StartHiddenPingProcess(keepRunning: true);
        await using var service = CreateSyntheticHealthService(
            options,
            client,
            candidateHealthRetryTimeout: TimeSpan.FromMilliseconds(400));
        AttachOwnedProcess(service, ownedProcess);
        using var cancellation = new CancellationTokenSource();
        var health = service.IsCandidateInstallHealthyAsync(cancellation.Token);
        await apiEntered.Task.WaitAsync(TimeSpan.FromSeconds(2));
        cancellation.Cancel();

        await AssertThrowsAsync<OperationCanceledException>(() => health);
    }

    private static async Task DshCandidateInstallHealthControlledStopAsync()
    {
        var options = CreateCandidateHealthOptions();
        using var client = new HttpClient(new DelegateHandler(request =>
            request.Method == HttpMethod.Get
                ? CreateHealthyWebUiResponse()
                : CreateStrictCandidateSessionListResponse(request)));
        using var ownedProcess = StartHiddenPingProcess(keepRunning: true);
        using var processObserver = Process.GetProcessById(ownedProcess.Id);
        await using var service = CreateSyntheticHealthService(
            options,
            client,
            healthProbeTimeout: TimeSpan.FromSeconds(2),
            candidateHealthRetryTimeout: TimeSpan.FromSeconds(2));
        AttachOwnedProcess(service, ownedProcess);

        AssertTrue(service.OwnsRunningProcess);
        AssertTrue(await service.CompleteCandidateInstallHealthAsync(ownedProcess.Id)
            .WaitAsync(TimeSpan.FromSeconds(5)));
        await processObserver.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));
        AssertTrue(processObserver.HasExited);
        AssertFalse(service.OwnsRunningProcess);
        AssertFalse(await service.CompleteCandidateInstallHealthAsync(
            processObserver.Id));
    }

    private static async Task DshCandidateInstallHealthWrongProcessAsync()
    {
        var options = CreateCandidateHealthOptions();
        var requestCount = 0;
        using var client = new HttpClient(new DelegateHandler(request =>
        {
            requestCount++;
            return request.Method == HttpMethod.Get
                ? CreateHealthyWebUiResponse()
                : CreateStrictCandidateSessionListResponse(request);
        }));
        using var ownedProcess = StartHiddenPingProcess(keepRunning: true);
        using var processObserver = Process.GetProcessById(ownedProcess.Id);
        await using var service = CreateSyntheticHealthService(options, client);
        AttachOwnedProcess(service, ownedProcess);
        var wrongProcessId = ownedProcess.Id == int.MaxValue
            ? ownedProcess.Id - 1
            : ownedProcess.Id + 1;

        AssertFalse(await service.CompleteCandidateInstallHealthAsync(
            wrongProcessId));
        AssertEqual(0, requestCount);
        AssertFalse(processObserver.HasExited);
        AssertTrue(service.OwnsRunningProcess);

        await service.StopOwnedProcessAsync().WaitAsync(TimeSpan.FromSeconds(5));
        await processObserver.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));
        AssertTrue(processObserver.HasExited);
    }

    private static async Task DshCandidateInstallHealthRejectsProcessTakeoverAsync()
    {
        var options = CreateCandidateHealthOptions();
        using var ownedProcess = StartHiddenPingProcess(keepRunning: false);
        using var processObserver = Process.GetProcessById(ownedProcess.Id);
        var takeoverResponseCount = 0;
        using var client = new HttpClient(new AsyncDelegateHandler(
            async (request, cancellationToken) =>
            {
                if (request.Method == HttpMethod.Get)
                {
                    return CreateHealthyWebUiResponse();
                }

                await processObserver.WaitForExitAsync(cancellationToken)
                    .ConfigureAwait(false);
                takeoverResponseCount++;
                return CreateStrictCandidateSessionListResponse(request);
            }));
        await using var service = CreateSyntheticHealthService(
            options,
            client,
            healthProbeTimeout: TimeSpan.FromSeconds(8),
            candidateHealthRetryTimeout: TimeSpan.FromSeconds(8));
        AttachOwnedProcess(service, ownedProcess);

        AssertFalse(await service.CompleteCandidateInstallHealthAsync(
                ownedProcess.Id)
            .WaitAsync(TimeSpan.FromSeconds(10)));
        AssertTrue(processObserver.HasExited);
        AssertEqual(1, takeoverResponseCount);
        AssertFalse(service.OwnsRunningProcess);
    }

    private static async Task DshCandidateInstallHealthCompletionCancellationAsync()
    {
        var options = CreateCandidateHealthOptions();
        var apiEntered = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        using var client = new HttpClient(new AsyncDelegateHandler(
            async (request, cancellationToken) =>
            {
                if (request.Method == HttpMethod.Get)
                {
                    return CreateHealthyWebUiResponse();
                }

                apiEntered.TrySetResult();
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken)
                    .ConfigureAwait(false);
                return CreateStrictCandidateSessionListResponse(request);
            }));
        using var ownedProcess = StartHiddenPingProcess(keepRunning: true);
        using var processObserver = Process.GetProcessById(ownedProcess.Id);
        await using var service = CreateSyntheticHealthService(
            options,
            client,
            healthProbeTimeout: TimeSpan.FromSeconds(5),
            candidateHealthRetryTimeout: TimeSpan.FromSeconds(5));
        AttachOwnedProcess(service, ownedProcess);
        using var cancellation = new CancellationTokenSource();

        var completion = service.CompleteCandidateInstallHealthAsync(
            ownedProcess.Id,
            cancellation.Token);
        await apiEntered.Task.WaitAsync(TimeSpan.FromSeconds(2));
        cancellation.Cancel();
        await AssertThrowsAsync<OperationCanceledException>(() => completion);

        await service.StopOwnedProcessAsync().WaitAsync(TimeSpan.FromSeconds(5));
        await processObserver.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));
        AssertTrue(processObserver.HasExited);
    }

    private static DshRuntimeOptions CreateCandidateHealthOptions(
        DshRuntimeWebAuthProtocol protocol = DshRuntimeWebAuthProtocol.LegacyCleanRootV1)
    {
        var runtime = Path.Combine(
            TempRoot,
            $"candidate-health-runtime-{Guid.NewGuid():N}");
        Directory.CreateDirectory(runtime);
        if (protocol != DshRuntimeWebAuthProtocol.LegacyCleanRootV1)
        {
            File.WriteAllText(
                Path.Combine(runtime, DshRuntimeMetadata.FileName),
                $"{{\"schemaVersion\":1,\"webAuthProtocol\":\"{DshRuntimeWebAuthProtocolContract.GetName(protocol)}\"}}");
        }
        return new DshRuntimeOptions(runtime, TempRoot, TempRoot, Port: 3191);
    }

    private static HttpResponseMessage CreateHealthyWebUiResponse() =>
        CreateWebUiResponse("DeepSeek Harness", includeBootMarker: true);

    private static HttpResponseMessage CreateWebUiResponse(
        string title,
        bool includeBootMarker) => new(
        HttpStatusCode.OK)
    {
        Content = new StringContent(
            $"<html><head><title>{title}</title></head><body>"
                + (includeBootMarker ? "<script>window.__DSH_BOOT__={};</script>" : string.Empty)
                + "</body></html>",
            Encoding.UTF8,
            "text/html"),
    };

    private static HttpResponseMessage CreateJsonResponse(string json) => new(
        HttpStatusCode.OK)
    {
        Content = new StringContent(json, Encoding.UTF8, "application/json"),
    };

    private static HttpResponseMessage CreateStrictCandidateSessionListResponse(
        HttpRequestMessage request)
    {
        AssertEqual(HttpMethod.Post, request.Method);
        var rpcId = ReadCandidateHealthRpcId(request);
        return CreateJsonResponse(
            $"{{\"type\":\"server-response\",\"rpcId\":\"{rpcId}\",\"result\":{{\"ok\":true,\"value\":{{\"items\":[]}}}}}}");
    }

    private static Process StartHiddenPingProcess(bool keepRunning)
    {
        var executable = Path.Combine(Environment.SystemDirectory, "ping.exe");
        if (!OperatingSystem.IsWindows() || !File.Exists(executable))
        {
            throw new PlatformNotSupportedException(
                "The controlled-process regression requires Windows ping.exe.");
        }

        var startInfo = new ProcessStartInfo
        {
            FileName = executable,
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        if (keepRunning)
        {
            startInfo.ArgumentList.Add("-t");
        }
        else
        {
            startInfo.ArgumentList.Add("-n");
            startInfo.ArgumentList.Add("4");
        }
        startInfo.ArgumentList.Add("127.0.0.1");
        return Process.Start(startInfo)
            ?? throw new InvalidOperationException(
                "Windows did not start the controlled test process.");
    }

    private static void AttachOwnedProcess(
        DshHostService service,
        Process process)
    {
        var field = typeof(DshHostService).GetField(
            "_ownedProcess",
            BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException(
                "DshHostService owned-process field was not found.");
        AssertTrue(field.GetValue(service) is null);
        field.SetValue(service, process);
    }

    private static void AttachOwnedJobObject(
        DshHostService service,
        WindowsJobObject jobObject)
    {
        var field = typeof(DshHostService).GetField(
            "_jobObject",
            BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException(
                "DshHostService owned-job field was not found.");
        AssertTrue(field.GetValue(service) is null);
        field.SetValue(service, jobObject);
    }

    private static WindowsJobObject? ReadOwnedJobObject(DshHostService service)
    {
        var field = typeof(DshHostService).GetField(
            "_jobObject",
            BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException(
                "DshHostService owned-job field was not found.");
        return field.GetValue(service) as WindowsJobObject;
    }

    private static void InvokeOwnedProcessExitHandler(
        DshHostService service,
        Process process,
        WindowsJobObject jobObject)
    {
        var method = typeof(DshHostService).GetMethod(
            "HandleOwnedProcessExited",
            BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException(
                "DshHostService exact process-exit handler was not found.");
        method.Invoke(service, new object?[] { process, jobObject });
    }

    private static async Task InvokeReleaseOwnedProcessAsync(
        DshHostService service,
        Process process)
    {
        var method = typeof(DshHostService).GetMethod(
            "ReleaseOwnedProcessAsync",
            BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException(
                "DshHostService owned-process release method was not found.");
        var task = method.Invoke(service, new object?[] { process }) as Task
            ?? throw new InvalidOperationException(
                "DshHostService owned-process release did not return a Task.");
        await task.ConfigureAwait(false);
    }

    private static void AttachBrowserSession(
        DshHostService service,
        Process process,
        DshBrowserSession session)
    {
        AttachOwnedProcess(service, process);
        var processField = typeof(DshHostService).GetField(
            "_browserAuthProcess",
            BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException(
                "DshHostService browser-auth Process field was not found.");
        var sessionField = typeof(DshHostService).GetField(
            "_browserSession",
            BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException(
                "DshHostService browser session field was not found.");
        processField.SetValue(service, process);
        sessionField.SetValue(service, session);
    }

    private static void AttachBrowserReadinessFailure(
        DshHostService service,
        Process process,
        Exception failure)
    {
        AttachOwnedProcess(service, process);
        var processField = typeof(DshHostService).GetField(
            "_browserAuthProcess",
            BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException(
                "DshHostService browser-auth Process field was not found.");
        var readinessField = typeof(DshHostService).GetField(
            "_browserLaunchReady",
            BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException(
                "DshHostService browser readiness field was not found.");
        var readiness = new TaskCompletionSource<Uri>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        readiness.SetException(failure);
        processField.SetValue(service, process);
        readinessField.SetValue(service, readiness);
    }

    private static void InvokeOwnedProcessExited(
        DshHostService service,
        Process process)
    {
        var method = typeof(DshHostService).GetMethod(
            "OnOwnedProcessExited",
            BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException(
                "DshHostService process-exit callback was not found.");
        method.Invoke(service, new object?[] { process, EventArgs.Empty });
    }

    private static void SetFaultedOutputPump(DshHostService service, Task pump)
    {
        var field = typeof(DshHostService).GetField(
            "_standardOutputPump",
            BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException(
                "DshHostService output pump field was not found.");
        field.SetValue(service, pump);
    }

    private static async Task<bool> ProbeCandidateHealthAsync(
        Func<HttpRequestMessage, HttpResponseMessage> apiResponse)
    {
        var options = CreateCandidateHealthOptions();
        using var client = new HttpClient(new DelegateHandler(request =>
            request.Method == HttpMethod.Get
                ? CreateHealthyWebUiResponse()
                : apiResponse(request)));
        using var ownedProcess = StartHiddenPingProcess(keepRunning: true);
        await using var service = CreateSyntheticHealthService(
            options,
            client,
            candidateHealthRetryTimeout: TimeSpan.FromMilliseconds(400));
        AttachOwnedProcess(service, ownedProcess);
        return await service.IsCandidateInstallHealthyAsync();
    }

    private static DshHostService CreateSyntheticHealthService(
        DshRuntimeOptions options,
        HttpClient client,
        TimeSpan? healthProbeTimeout = null,
        TimeSpan? candidateHealthRetryTimeout = null) => new(
            options,
            client,
            validateBeforeProcessStart: null,
            healthProbeTimeout,
            candidateHealthRetryTimeout,
            ownsLoopbackListener: static (_, _) => true);

    private static string ReadCandidateHealthRpcId(HttpRequestMessage request)
    {
        var body = request.Content?.ReadAsStringAsync().GetAwaiter().GetResult()
            ?? throw new InvalidOperationException("Candidate health request body is missing.");
        using var document = JsonDocument.Parse(body);
        return document.RootElement.GetProperty("rpcId").GetString()
            ?? throw new InvalidOperationException("Candidate health rpcId is missing.");
    }

    private static Task EnterpriseAccessTokenVaultAsync()
    {
        var bindingId = BindingId;
        var now = new DateTimeOffset(2026, 8, 24, 2, 0, 0, TimeSpan.Zero);
        using var vault = new EnterpriseAccessTokenVault();
        vault.Install(bindingId, new string('a', 64), now.AddMinutes(10));

        AssertTrue(vault.HasUsableToken(bindingId, now));
        AssertTrue(vault.HasUsableToken(bindingId, now.AddMinutes(9)));
        AssertFalse(vault.HasUsableToken(bindingId, now.AddMinutes(10)));
        AssertFalse(vault.HasUsableToken(
            "33333333-3333-4444-8555-666666666666",
            now));

        vault.Clear();
        AssertFalse(vault.HasUsableToken(bindingId, now));
        return Task.CompletedTask;
    }

    private static async Task EnterpriseExpiredCommittedBindingReplayAsync()
    {
        var fixture = LoadAuthorizationLeaseFixture();
        using var deviceKeys = new EphemeralDeviceProofKeyStore();
        var deviceIdentity = deviceKeys.GetOrCreatePublicIdentity();
        var issuedAtUtc = fixture.EvaluationTimeUtc;
        var nowUtc = issuedAtUtc.AddDays(1);
        var payloadJson = fixture.PayloadJson.Replace(
            $"\"device_key_thumbprint\":\"{fixture.DeviceKeyThumbprint}\"",
            $"\"device_key_thumbprint\":\"{deviceIdentity.Thumbprint}\"",
            StringComparison.Ordinal);
        AssertFalse(string.Equals(payloadJson, fixture.PayloadJson, StringComparison.Ordinal));
        var response = new EnterpriseDeviceBindingCompleteResponse
        {
            SchemaVersion = 1,
            BindingId = fixture.BindingId,
            RefreshToken = RefreshTokenVector,
            AccessToken = new string('a', 43),
            AccessTokenExpiresAtUtc = issuedAtUtc.AddMinutes(10),
            AuthorizationLease = SignAuthorizationLeasePayload(fixture, payloadJson),
            LeaseExpiresAtUtc = issuedAtUtc.AddMinutes(15),
            ServerTimeUtc = issuedAtUtc,
        };
        var device = new EnterpriseEnrollmentDeviceContext(
            new EnterpriseInstallationIdentity(
                Guid.Parse(fixture.InstallationId),
                issuedAtUtc),
            deviceIdentity);
        var request = EnterpriseBindingPayloadBuilder.CreateSignedRequest(
            new EnterpriseBindingChallenge(
                BindingSessionId,
                BindingGrantVector,
                BindingChallengeVector,
                issuedAtUtc.AddSeconds(30)),
            fixture.InstallationId,
            deviceIdentity.Thumbprint,
            "Recovery test device",
            deviceKeys);
        var exactRequestBody = EnterpriseDeviceBindingClient.SerializeExactRequest(request);
        var paths = CreateEnterpriseDiskTestPaths();
        var protectedStore = new EnterpriseProtectedArtifactStore(paths);
        var pendingStore = new EnterprisePendingBindingTransactionStore(protectedStore);
        var credentialStore = new EnterpriseBindingCredentialStore(paths, protectedStore);
        using var vault = new EnterpriseAccessTokenVault();
        await using var session = new EnterpriseHarnessSession(
            new EnterpriseStartupGate(new FixedTimeProvider(nowUtc)),
            new FakeEnterpriseHarnessHost(),
            EnterpriseStartupGate.CreateEnrollmentRequiredSnapshot());
        var replayClient = new FixedBindingReplayClient(response);
        var workflow = new EnterpriseDeviceBindingWorkflow(
            replayClient,
            deviceKeys,
            CreateAuthorizationLeaseVerifier(fixture),
            credentialStore,
            pendingStore,
            vault,
            session,
            new PassThroughEnterpriseDeviceUpdateGate(),
            new FixedTimeProvider(nowUtc));

        try
        {
            await pendingStore.WriteNewAsync(
                exactRequestBody,
                BindingIdempotencyKey,
                issuedAtUtc);
            await AssertThrowsAsync<EnterpriseBindingRecoveryRequiredException>(() =>
                workflow.TryResumeAsync(device));

            AssertEqual(1, replayClient.ExactCalls);
            var committed = await credentialStore.ReadCommittedAsync()
                ?? throw new InvalidOperationException(
                    "Expired committed replay did not recover the refresh credential.");
            AssertEqual(RefreshTokenVector, committed.RefreshToken);
            AssertFalse(vault.HasUsableToken(fixture.BindingId, nowUtc));
            AssertEqual(EnterpriseClientState.Binding, session.CurrentDecision.ClientState);
            AssertFalse(session.CurrentDecision.MayCallManagedApi);
            using var retainedPending = await pendingStore.ReadAsync()
                ?? throw new InvalidOperationException(
                    "Recovery journal was removed before refresh became available.");
            AssertSequenceEqual(
                exactRequestBody,
                retainedPending.ExactRequestBody.ToArray());
        }
        finally
        {
            pendingStore.Delete();
            credentialStore.DeleteBindingArtifacts();
            CryptographicOperations.ZeroMemory(exactRequestBody);
        }
    }

    private static async Task EnterpriseFirstBindingUpdateGateAsync()
    {
        var fixture = LoadAuthorizationLeaseFixture();
        using var deviceKeys = new EphemeralDeviceProofKeyStore();
        var deviceIdentity = deviceKeys.GetOrCreatePublicIdentity();
        var nowUtc = fixture.EvaluationTimeUtc;
        var payloadJson = fixture.PayloadJson.Replace(
            $"\"device_key_thumbprint\":\"{fixture.DeviceKeyThumbprint}\"",
            $"\"device_key_thumbprint\":\"{deviceIdentity.Thumbprint}\"",
            StringComparison.Ordinal);
        var response = new EnterpriseDeviceBindingCompleteResponse
        {
            SchemaVersion = 1,
            BindingId = fixture.BindingId,
            RefreshToken = RefreshTokenVector,
            AccessToken = new string('a', 43),
            AccessTokenExpiresAtUtc = nowUtc.AddMinutes(10),
            AuthorizationLease = SignAuthorizationLeasePayload(fixture, payloadJson),
            LeaseExpiresAtUtc = nowUtc.AddMinutes(15),
            ServerTimeUtc = nowUtc,
        };
        var device = new EnterpriseEnrollmentDeviceContext(
            new EnterpriseInstallationIdentity(
                Guid.Parse(fixture.InstallationId),
                nowUtc),
            deviceIdentity);
        var request = EnterpriseBindingPayloadBuilder.CreateSignedRequest(
            new EnterpriseBindingChallenge(
                BindingSessionId,
                BindingGrantVector,
                BindingChallengeVector,
                nowUtc.AddSeconds(30)),
            fixture.InstallationId,
            deviceIdentity.Thumbprint,
            "First binding update-gate test",
            deviceKeys);
        var exactRequestBody = EnterpriseDeviceBindingClient.SerializeExactRequest(request);
        var paths = CreateEnterpriseDiskTestPaths();
        var protectedStore = new EnterpriseProtectedArtifactStore(paths);
        var pendingStore = new EnterprisePendingBindingTransactionStore(protectedStore);
        var credentialStore = new EnterpriseBindingCredentialStore(paths, protectedStore);
        using var vault = new EnterpriseAccessTokenVault();
        await using var session = new EnterpriseHarnessSession(
            new EnterpriseStartupGate(new FixedTimeProvider(nowUtc)),
            new FakeEnterpriseHarnessHost(),
            EnterpriseStartupGate.CreateEnrollmentRequiredSnapshot());
        var gate = new RecordingEnterpriseDeviceUpdateGate(session, blockForUpdate: true);
        var workflow = new EnterpriseDeviceBindingWorkflow(
            new FixedBindingReplayClient(response),
            deviceKeys,
            CreateAuthorizationLeaseVerifier(fixture),
            credentialStore,
            pendingStore,
            vault,
            session,
            gate,
            new FixedTimeProvider(nowUtc));

        try
        {
            await pendingStore.WriteNewAsync(
                exactRequestBody,
                BindingIdempotencyKey,
                nowUtc);
            var result = await workflow.TryResumeAsync(device)
                ?? throw new InvalidOperationException("Pending binding was not resumed.");

            AssertEqual(EnterpriseClientState.UpdateRequired, result.AccessDecision.ClientState);
            AssertEqual(EnterpriseErrorCodes.ClientUpdateRequired, result.AccessDecision.ErrorCode);
            AssertFalse(result.AccessDecision.MayStartHarness);
            AssertFalse(result.AccessDecision.MayCallManagedApi);
            AssertTrue(result.RecoveryJournalCleared);
            AssertEqual(1, gate.Calls);
            AssertFalse(gate.ObservedReady);
            AssertFalse(vault.HasUsableToken(fixture.BindingId, nowUtc));
            AssertFalse(File.Exists(paths.Resolve(
                EnterpriseManagedArtifact.PendingBindingTransactionDpapi)));
            AssertTrue(await credentialStore.ReadCommittedAsync() is not null);
        }
        finally
        {
            pendingStore.Delete();
            credentialStore.DeleteBindingArtifacts();
            CryptographicOperations.ZeroMemory(exactRequestBody);
        }
    }

    private static async Task EnterprisePartialBindingProjectionsRequireRecoveryAsync()
    {
        foreach (var artifact in new[]
        {
            EnterpriseManagedArtifact.AuthorizationLease,
            EnterpriseManagedArtifact.DeviceBindingReceipt,
        })
        {
            var paths = CreateEnterpriseDiskTestPaths();
            var path = paths.Resolve(artifact);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            var original = Encoding.UTF8.GetBytes($"partial-{artifact}");
            await File.WriteAllBytesAsync(path, original);

            try
            {
                var store = new EnterpriseBindingCredentialStore(
                    paths,
                    new EnterpriseProtectedArtifactStore(paths));
                await AssertThrowsAsync<EnterpriseBindingRecoveryRequiredException>(() =>
                    store.ReadCommittedAsync());
                AssertSequenceEqual(original, await File.ReadAllBytesAsync(path));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(original);
            }
        }
    }

    private static async Task EnterpriseEnrollmentHttpContractAsync()
    {
        using var deviceKeys = new EphemeralDeviceProofKeyStore();
        var now = new DateTimeOffset(2026, 8, 24, 2, 0, 0, TimeSpan.Zero);
        var bindingRequest = CreateBindingRequest(deviceKeys, now);
        var validBindingResponse = $$"""
            {
              "schema_version":1,
              "binding_id":"{{BindingId}}",
              "refresh_token":"{{RefreshTokenVector}}",
              "access_token":"{{new string('a', 43)}}",
              "access_token_expires_at":"{{now.AddMinutes(10):yyyy-MM-ddTHH:mm:ssZ}}",
              "authorization_lease":"{{CreateCompactLease()}}",
              "lease_expires_at":"{{now.AddMinutes(15):yyyy-MM-ddTHH:mm:ssZ}}",
              "server_time":"{{now:yyyy-MM-ddTHH:mm:ssZ}}"
            }
            """;

        using (var wrongBindingStatusHttp = new HttpClient(new DelegateHandler(_ =>
            JsonResponse(validBindingResponse))))
        {
            var client = CreateBindingHttpClient(wrongBindingStatusHttp, deviceKeys, now);
            await AssertThrowsAsync<InvalidDataException>(() => client.CompleteAsync(
                bindingRequest,
                BindingIdempotencyKey));
        }

        var identity = deviceKeys.GetOrCreatePublicIdentity();
        using (var wrongCreateStatusHttp = new HttpClient(new DelegateHandler(_ => JsonResponse($$"""
            {
              "session_id":"{{BindingSessionId}}",
              "poll_secret":"{{QrPollSecretVector}}",
              "authorization_url":"https://login.example.test/activate",
              "expires_at":"{{now.AddMinutes(2):yyyy-MM-ddTHH:mm:ssZ}}",
              "poll_after_seconds":2
            }
            """))))
        {
            var client = CreateQrHttpClient(wrongCreateStatusHttp, deviceKeys, now);
            await AssertThrowsAsync<InvalidDataException>(() => client.CreateSessionAsync(
                CreateQrRequest(identity),
                BindingIdempotencyKey));
        }

        var session = new EnterpriseQrSessionCreateResponse
        {
            SessionId = BindingSessionId,
            PollSecret = QrPollSecretVector,
            AuthorizationUrl = new Uri("https://login.example.test/activate"),
            DeviceDisplayName = QrDeviceDisplayName,
            ConfirmationCode = QrConfirmationCode,
            ExpiresAtUtc = now.AddMinutes(2),
            PollAfterSeconds = 2,
        };
        using (var wrongPollStatusHttp = new HttpClient(new DelegateHandler(_ =>
            CreatedJsonResponse("{\"status\":\"ISSUED\",\"poll_after_seconds\":2}"))))
        {
            var client = CreateQrHttpClient(wrongPollStatusHttp, deviceKeys, now);
            await AssertThrowsAsync<InvalidDataException>(() => client.PollSessionAsync(
                session,
                QrNonceVector,
                EnterpriseEnrollmentAuthorizationMethod.AdminInvite));
        }

        using var unsafeResetHttp = new HttpClient(new DelegateHandler(_ => JsonResponse("""
            {
              "error": {
                "code":"EMPLOYEE_SUSPENDED",
                "message":"account suspended",
                "client_state":"ACCOUNT_LOCKED",
                "retryable":false,
                "request_id":"request-unsafe-reset",
                "reset_scope":"SECURITY_CREDENTIALS"
              }
            }
            """, HttpStatusCode.Forbidden)));
        var unsafeResetClient = CreateBindingHttpClient(unsafeResetHttp, deviceKeys, now);
        await AssertThrowsAsync<InvalidDataException>(() => unsafeResetClient.CompleteAsync(
            bindingRequest,
            BindingIdempotencyKey));
    }

    private static async Task EnterpriseQrDeviceConfirmationProtocolAsync()
    {
        AssertEqual(
            "Café workstation",
            EnterpriseQrProtocol.NormalizeDeviceDisplayName("  Cafe\u0301  \u00A0 workstation  "));
        AssertEqual(
            new string('A', 64),
            EnterpriseQrProtocol.NormalizeDeviceDisplayName(new string('A', 64)));
        AssertEqual(
            string.Concat(Enumerable.Repeat("😀", 40)),
            EnterpriseQrProtocol.NormalizeDeviceDisplayName(
                string.Concat(Enumerable.Repeat("😀", 40))));
        foreach (var invalidName in new[]
        {
            new string('A', 65),
            string.Concat(Enumerable.Repeat("😀", 41)),
            "device\u0001name",
            "device\u200Ename",
            "device\uE000name",
            "device\u2028name",
            "device\u2029name",
            "\uD800",
        })
        {
            await AssertThrowsAsync<ArgumentException>(() => Task.Run(() =>
                EnterpriseQrProtocol.NormalizeDeviceDisplayName(invalidName)));
        }

        EnterpriseQrProtocol.ValidateConfirmationCode(QrConfirmationCode);
        foreach (var invalidCode in new[] { "7K9M2", "7K9M2QX", "7K9M2O", "7k9m2q", "000000" })
        {
            await AssertThrowsAsync<ArgumentException>(() => Task.Run(() =>
                EnterpriseQrProtocol.ValidateConfirmationCode(invalidCode)));
        }

        var progress = new EnterpriseQrEnrollmentProgress(
            QrSessionState.Issued,
            EnterpriseEnrollmentAuthorizationMethod.AdminInvite,
            new DateTimeOffset(2026, 8, 24, 2, 2, 0, TimeSpan.Zero),
            QrDeviceDisplayName,
            QrConfirmationCode);
        AssertFalse(progress.ToString().Contains(QrConfirmationCode, StringComparison.Ordinal));

        using var deviceKeys = new EphemeralDeviceProofKeyStore();
        var now = new DateTimeOffset(2026, 8, 24, 2, 0, 0, TimeSpan.Zero);
        using var noHttp = new HttpClient(new DelegateHandler(_ =>
            throw new InvalidOperationException("Noncanonical device name must fail before HTTP.")));
        var client = CreateQrHttpClient(noHttp, deviceKeys, now);
        var canonicalRequest = CreateQrRequest(deviceKeys.GetOrCreatePublicIdentity());
        var noncanonicalRequest = new EnterpriseQrSessionCreateRequest
        {
            AuthorizationMethod = canonicalRequest.AuthorizationMethod,
            InstallId = canonicalRequest.InstallId,
            DeviceJwk = canonicalRequest.DeviceJwk,
            DeviceKeyThumbprint = canonicalRequest.DeviceKeyThumbprint,
            DeviceDisplayName = "  PILOT-DESKTOP  workstation ",
            LauncherVersion = canonicalRequest.LauncherVersion,
            RuntimeVersion = canonicalRequest.RuntimeVersion,
            Platform = canonicalRequest.Platform,
            Nonce = canonicalRequest.Nonce,
        };
        await AssertThrowsAsync<InvalidDataException>(() => client.CreateSessionAsync(
            noncanonicalRequest,
            BindingIdempotencyKey));

        using var mismatchedNameHttp = new HttpClient(new DelegateHandler(_ =>
            CreatedJsonResponse($$"""
            {
              "session_id":"{{BindingSessionId}}",
              "poll_secret":"{{QrPollSecretVector}}",
              "authorization_url":"https://login.example.test/activate",
              "device_display_name":"other workstation",
              "confirmation_code":"{{QrConfirmationCode}}",
              "expires_at":"{{now.AddMinutes(2):yyyy-MM-ddTHH:mm:ssZ}}",
              "poll_after_seconds":2
            }
            """)));
        var mismatchedNameClient = CreateQrHttpClient(mismatchedNameHttp, deviceKeys, now);
        await AssertThrowsAsync<InvalidDataException>(() => mismatchedNameClient.CreateSessionAsync(
            canonicalRequest,
            BindingIdempotencyKey));

        using var invalidCodeHttp = new HttpClient(new DelegateHandler(_ =>
            CreatedJsonResponse($$"""
            {
              "session_id":"{{BindingSessionId}}",
              "poll_secret":"{{QrPollSecretVector}}",
              "authorization_url":"https://login.example.test/activate",
              "device_display_name":"{{QrDeviceDisplayName}}",
              "confirmation_code":"7K9M2O",
              "expires_at":"{{now.AddMinutes(2):yyyy-MM-ddTHH:mm:ssZ}}",
              "poll_after_seconds":2
            }
            """)));
        var invalidCodeClient = CreateQrHttpClient(invalidCodeHttp, deviceKeys, now);
        await AssertThrowsAsync<InvalidDataException>(() => invalidCodeClient.CreateSessionAsync(
            canonicalRequest,
            BindingIdempotencyKey));
    }

    private static async Task EnterpriseActivationCodeProtocolAsync()
    {
        EnterpriseQrProtocol.ValidateActivationCode(ActivationCodeVector);
        AssertEqual(EnterpriseQrProtocol.ActivationCodeLength, ActivationCodeVector.Length);
        var request = new EnterpriseActivationClaimRequest
        {
            SessionId = BindingSessionId,
            ActivationCode = ActivationCodeVector,
        };
        AssertFalse(request.ToString().Contains(ActivationCodeVector, StringComparison.Ordinal));

        foreach (var invalidCode in new[]
        {
            string.Empty,
            ActivationCodeVector[..^1],
            ActivationCodeVector + "A",
            ActivationCodeVector + "=",
            " " + ActivationCodeVector,
            ActivationCodeVector[..^1] + "B",
        })
        {
            await AssertThrowsAsync<ArgumentException>(() => Task.Run(() =>
                EnterpriseQrProtocol.ValidateActivationCode(invalidCode)));
        }
    }

    private static async Task EnterpriseActivationClaimHttpClientAsync()
    {
        using var deviceKeys = new EphemeralDeviceProofKeyStore();
        var now = new DateTimeOffset(2026, 8, 24, 2, 0, 0, TimeSpan.Zero);
        var session = CreateQrSession(now);
        var calls = 0;
        using var httpClient = new HttpClient(new DelegateHandler(request =>
        {
            calls++;
            AssertEqual(HttpMethod.Post, request.Method);
            AssertEqual(
                "https://control.example.test/v1/auth/activation/claim",
                request.RequestUri!.AbsoluteUri);
            AssertFalse(request.RequestUri.AbsoluteUri.Contains(
                ActivationCodeVector,
                StringComparison.Ordinal));
            AssertTrue(request.Headers.Contains("DPoP"));
            AssertTrue(request.Headers.Authorization is null);
            AssertFalse(request.ToString().Contains(ActivationCodeVector, StringComparison.Ordinal));

            var body = request.Content!.ReadAsStringAsync().GetAwaiter().GetResult();
            using (var document = JsonDocument.Parse(body))
            {
                var root = document.RootElement;
                AssertEqual(3, root.EnumerateObject().Count());
                AssertEqual(1, root.GetProperty("schema_version").GetInt32());
                AssertEqual(BindingSessionId, root.GetProperty("session_id").GetString());
                AssertEqual(ActivationCodeVector, root.GetProperty("activation_code").GetString());
            }

            var proof = request.Headers.GetValues("DPoP").Single();
            var proofSegments = proof.Split('.');
            AssertEqual(3, proofSegments.Length);
            var payloadBytes = DecodeBase64Url(proofSegments[1]);
            var activationBytes = Encoding.ASCII.GetBytes(ActivationCodeVector);
            var activationHash = SHA256.HashData(activationBytes);
            try
            {
                using var payload = JsonDocument.Parse(payloadBytes);
                var root = payload.RootElement;
                AssertEqual("POST", root.GetProperty("htm").GetString());
                AssertEqual(
                    "https://control.example.test/v1/auth/activation/claim",
                    root.GetProperty("htu").GetString());
                AssertEqual(QrNonceVector, root.GetProperty("nonce").GetString());
                AssertEqual(
                    EncodeBase64Url(activationHash),
                    root.GetProperty("ath").GetString());
            }
            finally
            {
                CryptographicOperations.ZeroMemory(payloadBytes);
                CryptographicOperations.ZeroMemory(activationBytes);
                CryptographicOperations.ZeroMemory(activationHash);
            }

            return new HttpResponseMessage(HttpStatusCode.NoContent);
        }));
        var client = CreateQrHttpClient(httpClient, deviceKeys, now);

        await client.ClaimActivationAsync(
            session,
            QrNonceVector,
            ActivationCodeVector);
        AssertEqual(1, calls);
    }

    private static async Task EnterpriseActivationClaimStrictResponseAsync()
    {
        using var deviceKeys = new EphemeralDeviceProofKeyStore();
        var now = new DateTimeOffset(2026, 8, 24, 2, 0, 0, TimeSpan.Zero);
        var session = CreateQrSession(now);

        foreach (var invalidResponse in new Func<HttpResponseMessage>[]
        {
            () => new HttpResponseMessage(HttpStatusCode.OK),
            () => new HttpResponseMessage(HttpStatusCode.NoContent)
            {
                Content = new StringContent("{}", Encoding.UTF8, "application/json"),
            },
            () => new HttpResponseMessage(HttpStatusCode.NoContent)
            {
                Content = new StringContent(string.Empty, Encoding.UTF8, "application/json"),
            },
        })
        {
            using var httpClient = new HttpClient(new DelegateHandler(_ => invalidResponse()));
            var client = CreateQrHttpClient(httpClient, deviceKeys, now);
            await AssertThrowsAsync<InvalidDataException>(() => client.ClaimActivationAsync(
                session,
                QrNonceVector,
                ActivationCodeVector));
        }

        using var invalidCodeHttp = new HttpClient(new DelegateHandler(_ =>
            throw new InvalidOperationException("Invalid activation code must fail before HTTP.")));
        var invalidCodeClient = CreateQrHttpClient(invalidCodeHttp, deviceKeys, now);
        await AssertThrowsAsync<ArgumentException>(() => invalidCodeClient.ClaimActivationAsync(
            session,
            QrNonceVector,
            ActivationCodeVector[..^1]));

        using var rejectedHttp = new HttpClient(new DelegateHandler(_ => JsonResponse("""
            {
              "error": {
                "code":"ENROLLMENT_ACTIVATION_INVALID",
                "message":"activation code invalid",
                "client_state":"QR_REQUIRED",
                "retryable":false,
                "request_id":"request-activation-invalid",
                "reset_scope":"NONE"
              }
            }
            """, HttpStatusCode.Forbidden)));
        var rejectedClient = CreateQrHttpClient(rejectedHttp, deviceKeys, now);
        try
        {
            await rejectedClient.ClaimActivationAsync(
                session,
                QrNonceVector,
                ActivationCodeVector);
            throw new InvalidOperationException("Expected activation rejection.");
        }
        catch (EnterpriseControlPlaneException exception)
        {
            AssertEqual(EnterpriseErrorCodes.EnrollmentActivationInvalid, exception.Error.Code);
        }
    }

    private static async Task EnterpriseQrHttpClientAsync()
    {
        using var deviceKeys = new EphemeralDeviceProofKeyStore();
        var now = new DateTimeOffset(2026, 8, 24, 2, 0, 0, TimeSpan.Zero);
        var call = 0;
        using var httpClient = new HttpClient(new DelegateHandler(request =>
        {
            call++;
            if (call == 1)
            {
                AssertEqual(HttpMethod.Post, request.Method);
                AssertEqual(
                    "https://control.example.test/v1/auth/qr-sessions",
                    request.RequestUri!.AbsoluteUri);
                AssertTrue(request.Headers.Contains("DPoP"));
                AssertTrue(request.Headers.Contains("Idempotency-Key"));
                var body = request.Content!.ReadAsStringAsync().GetAwaiter().GetResult();
                using var document = JsonDocument.Parse(body);
                var propertyNames = document.RootElement
                    .EnumerateObject()
                    .Select(property => property.Name)
                    .Order(StringComparer.Ordinal)
                    .ToArray();
                var expectedPropertyNames = new[]
                {
                    "authorization_method",
                    "device_display_name",
                    "device_jwk",
                    "device_key_thumbprint",
                    "install_id",
                    "launcher_version",
                    "nonce",
                    "platform",
                    "runtime_version",
                    "schema_version",
                };
                AssertEqual(
                    string.Join('\n', expectedPropertyNames),
                    string.Join('\n', propertyNames));
                AssertEqual(2, document.RootElement.GetProperty("schema_version").GetInt32());
                AssertEqual(
                    "ADMIN_INVITE",
                    document.RootElement.GetProperty("authorization_method").GetString());
                AssertEqual(
                    QrDeviceDisplayName,
                    document.RootElement.GetProperty("device_display_name").GetString());
                AssertFalse(body.Contains("userid", StringComparison.OrdinalIgnoreCase));
                return CreatedJsonResponse($$"""
                    {
                      "session_id":"{{BindingSessionId}}",
                      "poll_secret":"{{QrPollSecretVector}}",
                      "authorization_url":"https://login.example.test/activate?session={{BindingSessionId}}",
                      "device_display_name":"{{QrDeviceDisplayName}}",
                      "confirmation_code":"{{QrConfirmationCode}}",
                      "expires_at":"{{now.AddMinutes(2):yyyy-MM-ddTHH:mm:ssZ}}",
                      "poll_after_seconds":2
                    }
                    """);
            }

            AssertEqual(HttpMethod.Get, request.Method);
            AssertEqual("QR-Poll", request.Headers.Authorization!.Scheme);
            AssertEqual(QrPollSecretVector, request.Headers.Authorization.Parameter);
            AssertFalse(request.RequestUri!.Query.Contains("poll", StringComparison.OrdinalIgnoreCase));
            AssertTrue(request.Headers.Contains("DPoP"));
            return JsonResponse($$"""
                {
                  "status":"APPROVED",
                  "bind_grant":"{{BindingGrantVector}}",
                  "binding_challenge":"{{BindingChallengeVector}}",
                  "binding_challenge_expires_at":"{{now.AddMinutes(1):yyyy-MM-ddTHH:mm:ssZ}}"
                }
                """);
        }));
        var options = new EnterpriseControlPlaneOptions(
            new Uri("https://control.example.test/"),
            new Uri("https://login.example.test/"));
        var client = new EnterpriseQrEnrollmentClient(
            httpClient,
            options,
            new EnterpriseDpopProofFactory(deviceKeys, new FixedTimeProvider(now)),
            new FixedTimeProvider(now));
        var request = CreateQrRequest(deviceKeys.GetOrCreatePublicIdentity());

        var session = await client.CreateSessionAsync(
            request,
            BindingIdempotencyKey);
        var polled = await client.PollSessionAsync(
            session,
            request.Nonce,
            request.AuthorizationMethod);

        AssertEqual(2, call);
        AssertEqual(QrDeviceDisplayName, session.DeviceDisplayName);
        AssertEqual(QrConfirmationCode, session.ConfirmationCode);
        AssertEqual(QrSessionState.Approved, polled.Status);
        AssertEqual(BindingGrantVector, polled.BindGrant);
        AssertEqual(BindingChallengeVector, polled.BindingChallenge);
        AssertEqual(now.AddMinutes(1), polled.BindingChallengeExpiresAtUtc);
    }

    private static async Task EnterpriseQrTerminalContractAsync()
    {
        using var deviceKeys = new EphemeralDeviceProofKeyStore();
        var now = new DateTimeOffset(2026, 8, 24, 2, 0, 0, TimeSpan.Zero);
        var session = new EnterpriseQrSessionCreateResponse
        {
            SessionId = BindingSessionId,
            PollSecret = QrPollSecretVector,
            AuthorizationUrl = new Uri("https://login.example.test/activate"),
            DeviceDisplayName = QrDeviceDisplayName,
            ConfirmationCode = QrConfirmationCode,
            ExpiresAtUtc = now.AddMinutes(2),
            PollAfterSeconds = 2,
        };
        var cases = new (
            EnterpriseEnrollmentAuthorizationMethod Method,
            string Status,
            string ErrorCode,
            string ClientState,
            bool Retryable)[]
        {
            (EnterpriseEnrollmentAuthorizationMethod.AdminInvite,
                "CONSUMED", "QR_SESSION_CONSUMED", "QR_REQUIRED", false),
            (EnterpriseEnrollmentAuthorizationMethod.AdminInvite,
                "EXPIRED", "QR_SESSION_EXPIRED", "QR_REQUIRED", true),
            (EnterpriseEnrollmentAuthorizationMethod.AdminInvite,
                "CANCELLED", "QR_SESSION_CANCELLED", "QR_REQUIRED", true),
            (EnterpriseEnrollmentAuthorizationMethod.AdminInvite,
                "DENIED_NOT_PREREGISTERED", "ENROLLMENT_ACTIVATION_INVALID", "QR_REQUIRED", false),
            (EnterpriseEnrollmentAuthorizationMethod.WeCom,
                "DENIED_NOT_PREREGISTERED", "WECOM_IDENTITY_NOT_PREREGISTERED", "QR_REQUIRED", false),
            (EnterpriseEnrollmentAuthorizationMethod.AdminInvite,
                "DENIED_EMPLOYEE_SUSPENDED", "EMPLOYEE_SUSPENDED", "ACCOUNT_LOCKED", false),
            (EnterpriseEnrollmentAuthorizationMethod.AdminInvite,
                "DENIED_EMPLOYEE_REVOKED", "EMPLOYEE_REVOKED", "ACCOUNT_LOCKED", false),
            (EnterpriseEnrollmentAuthorizationMethod.AdminInvite,
                "DENIED_ALREADY_BOUND", "DEVICE_ALREADY_BOUND", "QR_REQUIRED", false),
            (EnterpriseEnrollmentAuthorizationMethod.WeCom,
                "DENIED_ENTERPRISE_MEMBER_REQUIRED", "WECOM_ENTERPRISE_MEMBER_REQUIRED", "QR_REQUIRED", false),
            (EnterpriseEnrollmentAuthorizationMethod.AdminInvite,
                "DENIED_ENTERPRISE_MEMBER_REQUIRED", "ENROLLMENT_ACTIVATION_INVALID", "QR_REQUIRED", false),
            (EnterpriseEnrollmentAuthorizationMethod.AdminInvite,
                "DENIED_ENTITLEMENT_MISSING", "EMPLOYEE_ENTITLEMENT_MISSING", "QR_REQUIRED", false),
            (EnterpriseEnrollmentAuthorizationMethod.AdminInvite,
                "DENIED_USER_REJECTED", "DEVICE_CONFIRMATION_REJECTED", "QR_REQUIRED", true),
        };

        foreach (var item in cases)
        {
            var json = $$"""
                {
                  "status":"{{item.Status}}",
                  "error": {
                    "code":"{{item.ErrorCode}}",
                    "message":"terminal result",
                    "client_state":"{{item.ClientState}}",
                    "retryable":{{item.Retryable.ToString().ToLowerInvariant()}},
                    "request_id":"request-terminal",
                    "reset_scope":"NONE"
                  }
                }
                """;
            using var http = new HttpClient(new DelegateHandler(_ => JsonResponse(json)));
            var client = CreateQrHttpClient(http, deviceKeys, now);
            var response = await client.PollSessionAsync(
                session,
                QrNonceVector,
                item.Method);
            AssertEqual(item.Status, QrSessionStateContract.ToWireValue(response.Status));
        }

        using var mismatchedHttp = new HttpClient(new DelegateHandler(_ => JsonResponse("""
            {
              "status":"DENIED_EMPLOYEE_SUSPENDED",
              "error": {
                "code":"EMPLOYEE_REVOKED",
                "message":"mismatched terminal result",
                "client_state":"ACCOUNT_LOCKED",
                "retryable":false,
                "request_id":"request-terminal-mismatch",
                "reset_scope":"NONE"
              }
            }
            """)));
        var mismatchedClient = CreateQrHttpClient(mismatchedHttp, deviceKeys, now);
        await AssertThrowsAsync<InvalidDataException>(() => mismatchedClient.PollSessionAsync(
            session,
            QrNonceVector,
            EnterpriseEnrollmentAuthorizationMethod.AdminInvite));

        using var legacyWeComCodeHttp = new HttpClient(new DelegateHandler(_ => JsonResponse("""
            {
              "status":"DENIED_NOT_PREREGISTERED",
              "error": {
                "code":"ENROLLMENT_ACTIVATION_INVALID",
                "message":"legacy code must not weaken WeCom mode",
                "client_state":"QR_REQUIRED",
                "retryable":false,
                "request_id":"request-terminal-wecom-mismatch",
                "reset_scope":"NONE"
              }
            }
            """)));
        var legacyWeComCodeClient = CreateQrHttpClient(legacyWeComCodeHttp, deviceKeys, now);
        await AssertThrowsAsync<InvalidDataException>(() => legacyWeComCodeClient.PollSessionAsync(
            session,
            QrNonceVector,
            EnterpriseEnrollmentAuthorizationMethod.WeCom));
    }

    private static async Task EnterpriseQrBindingChallengeRequiredAsync()
    {
        using var deviceKeys = new EphemeralDeviceProofKeyStore();
        var now = new DateTimeOffset(2026, 8, 24, 2, 0, 0, TimeSpan.Zero);
        var session = new EnterpriseQrSessionCreateResponse
        {
            SessionId = BindingSessionId,
            PollSecret = QrPollSecretVector,
            AuthorizationUrl = new Uri("https://login.example.test/activate"),
            DeviceDisplayName = QrDeviceDisplayName,
            ConfirmationCode = QrConfirmationCode,
            ExpiresAtUtc = now.AddMinutes(2),
            PollAfterSeconds = 2,
        };
        using var missingChallengeHttp = new HttpClient(new DelegateHandler(_ => JsonResponse($$"""
            {"status":"APPROVED","bind_grant":"{{BindingGrantVector}}"}
            """)));
        var missingChallengeClient = CreateQrHttpClient(missingChallengeHttp, deviceKeys, now);
        await AssertThrowsAsync<InvalidDataException>(() => missingChallengeClient.PollSessionAsync(
            session,
            QrNonceVector,
            EnterpriseEnrollmentAuthorizationMethod.AdminInvite));

        using var overlongChallengeHttp = new HttpClient(new DelegateHandler(_ => JsonResponse($$"""
            {
              "status":"APPROVED",
              "bind_grant":"{{BindingGrantVector}}",
              "binding_challenge":"{{BindingChallengeVector}}",
              "binding_challenge_expires_at":"{{now.AddSeconds(61):yyyy-MM-ddTHH:mm:ssZ}}"
            }
            """)));
        var overlongChallengeClient = CreateQrHttpClient(overlongChallengeHttp, deviceKeys, now);
        await AssertThrowsAsync<InvalidDataException>(() => overlongChallengeClient.PollSessionAsync(
            session,
            QrNonceVector,
            EnterpriseEnrollmentAuthorizationMethod.AdminInvite));

        using var equalGrantChallengeHttp = new HttpClient(new DelegateHandler(_ => JsonResponse($$"""
            {
              "status":"APPROVED",
              "bind_grant":"{{BindingGrantVector}}",
              "binding_challenge":"{{BindingGrantVector}}",
              "binding_challenge_expires_at":"{{now.AddSeconds(60):yyyy-MM-ddTHH:mm:ssZ}}"
            }
            """)));
        var equalGrantChallengeClient = CreateQrHttpClient(
            equalGrantChallengeHttp,
            deviceKeys,
            now);
        await AssertThrowsAsync<InvalidDataException>(() =>
            equalGrantChallengeClient.PollSessionAsync(
                session,
                QrNonceVector,
                EnterpriseEnrollmentAuthorizationMethod.AdminInvite));
    }

    private static async Task EnterpriseQrRedirectRejectedAsync()
    {
        using var deviceKeys = new EphemeralDeviceProofKeyStore();
        var now = new DateTimeOffset(2026, 8, 24, 2, 0, 0, TimeSpan.Zero);
        using var httpClient = new HttpClient(new DelegateHandler(_ => new HttpResponseMessage(
            HttpStatusCode.Redirect)
        {
            Headers = { Location = new Uri("https://evil.example.test/") },
        }));
        var client = CreateQrHttpClient(httpClient, deviceKeys, now);

        await AssertThrowsAsync<HttpRequestException>(() => client.CreateSessionAsync(
            CreateQrRequest(deviceKeys.GetOrCreatePublicIdentity()),
            BindingIdempotencyKey));
    }

    private static async Task EnterpriseQrLifetimeRejectedAsync()
    {
        using var deviceKeys = new EphemeralDeviceProofKeyStore();
        var now = new DateTimeOffset(2026, 8, 24, 2, 0, 0, TimeSpan.Zero);
        using var httpClient = new HttpClient(new DelegateHandler(_ => CreatedJsonResponse($$"""
            {
              "session_id":"{{BindingSessionId}}",
              "poll_secret":"{{QrPollSecretVector}}",
              "authorization_url":"https://login.example.test/activate",
              "device_display_name":"{{QrDeviceDisplayName}}",
              "confirmation_code":"{{QrConfirmationCode}}",
              "expires_at":"{{now.AddSeconds(121):yyyy-MM-ddTHH:mm:ssZ}}",
              "poll_after_seconds":2
            }
            """)));
        var client = CreateQrHttpClient(httpClient, deviceKeys, now);

        await AssertThrowsAsync<InvalidDataException>(() => client.CreateSessionAsync(
            CreateQrRequest(deviceKeys.GetOrCreatePublicIdentity()),
            BindingIdempotencyKey));
    }

    private static async Task EnterpriseQrStrictJsonAsync()
    {
        using var deviceKeys = new EphemeralDeviceProofKeyStore();
        var now = new DateTimeOffset(2026, 8, 24, 2, 0, 0, TimeSpan.Zero);
        using var httpClient = new HttpClient(new DelegateHandler(_ => CreatedJsonResponse($$"""
            {
              "session_id":"{{BindingSessionId}}",
              "poll_secret":"{{QrPollSecretVector}}",
              "authorization_url":"https://login.example.test/activate",
              "device_display_name":"{{QrDeviceDisplayName}}",
              "confirmation_code":"{{QrConfirmationCode}}",
              "expires_at":"{{now.AddMinutes(2):yyyy-MM-ddTHH:mm:ssZ}}",
              "poll_after_seconds":2,
              "unexpected":"rejected"
            }
            """)));
        var client = CreateQrHttpClient(httpClient, deviceKeys, now);

        await AssertThrowsAsync<JsonException>(() => client.CreateSessionAsync(
            CreateQrRequest(deviceKeys.GetOrCreatePublicIdentity()),
            BindingIdempotencyKey));

        using var duplicateHttpClient = new HttpClient(new DelegateHandler(_ =>
            CreatedJsonResponse($$"""
            {
              "session_id":"{{BindingSessionId}}",
              "poll_secret":"{{QrPollSecretVector}}",
              "authorization_url":"https://login.example.test/activate",
              "device_display_name":"{{QrDeviceDisplayName}}",
              "confirmation_code":"{{QrConfirmationCode}}",
              "expires_at":"{{now.AddMinutes(2):yyyy-MM-ddTHH:mm:ssZ}}",
              "poll_after_seconds":2,
              "poll_after_seconds":3
            }
            """)));
        var duplicateClient = CreateQrHttpClient(
            duplicateHttpClient,
            deviceKeys,
            now);
        await AssertThrowsAsync<JsonException>(() => duplicateClient.CreateSessionAsync(
            CreateQrRequest(deviceKeys.GetOrCreatePublicIdentity()),
            BindingIdempotencyKey));
    }

    private static async Task EnterpriseQrCoordinatorProgressAsync()
    {
        var fixture = CreateEnrollmentCoordinatorFixture(
            QrSessionState.Approved,
            error: null,
            deviceLabel: "  Cafe\u0301  \u00A0 station  ");
        await using var session = fixture.Session;
        using var deviceKeys = fixture.DeviceKeys;
        var updates = new List<EnterpriseQrEnrollmentProgress>();
        var progress = new InlineProgress<EnterpriseQrEnrollmentProgress>(updates.Add);

        var pending = fixture.Coordinator.BeginAsync(ActivationCodeVector, progress);
        await fixture.Client.ClaimObserved.WaitAsync(TimeSpan.FromSeconds(2));
        var persistedSession = await new EnterpriseProtectedArtifactStore(fixture.Paths)
            .ReadAsync(EnterpriseManagedArtifact.EnrollmentSessionDpapi);
        AssertTrue(persistedSession is not null);
        var activationBytes = Encoding.ASCII.GetBytes(ActivationCodeVector);
        var activationPropertyBytes = Encoding.ASCII.GetBytes("activation_code");
        try
        {
            AssertEqual(-1, persistedSession!.AsSpan().IndexOf(activationBytes));
            AssertEqual(-1, persistedSession.AsSpan().IndexOf(activationPropertyBytes));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(persistedSession!);
            CryptographicOperations.ZeroMemory(activationBytes);
            CryptographicOperations.ZeroMemory(activationPropertyBytes);
        }
        await Task.Yield();
        fixture.TimeProvider.Advance(TimeSpan.FromSeconds(2));
        var outcome = await pending.WaitAsync(TimeSpan.FromSeconds(2));

        AssertTrue(outcome.IdentityApproved);
        AssertEqual("Café station", fixture.Client.LastCreateRequest!.DeviceDisplayName);
        AssertEqual(2, updates.Count);
        AssertEqual(QrSessionState.Issued, updates[0].State);
        AssertEqual(QrSessionState.Approved, updates[1].State);
        foreach (var update in updates)
        {
            AssertEqual(
                EnterpriseEnrollmentAuthorizationMethod.AdminInvite,
                update.AuthorizationMethod);
            AssertEqual("Café station", update.DeviceDisplayName);
            AssertEqual(QrConfirmationCode, update.ConfirmationCode);
            EnterpriseQrProtocol.ValidateConfirmationCode(update.ConfirmationCode);
            AssertFalse(update.ToString().Contains(QrConfirmationCode, StringComparison.Ordinal));
        }
    }

    private static async Task EnterpriseQrCoordinatorApprovedAsync()
    {
        var fixture = CreateEnrollmentCoordinatorFixture(
            QrSessionState.Approved,
            error: null);
        await using var session = fixture.Session;
        using var deviceKeys = fixture.DeviceKeys;

        var pending = fixture.Coordinator.BeginAsync(ActivationCodeVector);
        await fixture.Client.ClaimObserved.WaitAsync(TimeSpan.FromSeconds(2));
        await Task.Yield();
        fixture.TimeProvider.Advance(TimeSpan.FromSeconds(2));
        var outcome = await pending.WaitAsync(TimeSpan.FromSeconds(2));

        AssertTrue(outcome.IdentityApproved);
        AssertEqual(BindingGrantVector, outcome.BindGrant);
        AssertEqual(BindingSessionId, outcome.BindingChallenge!.SessionId);
        AssertEqual(BindingChallengeVector, outcome.BindingChallenge.Challenge);
        AssertEqual(
            fixture.TimeProvider.GetUtcNow().AddSeconds(58),
            outcome.BindingChallenge.ExpiresAtUtc);
        AssertEqual(EnterpriseClientState.Binding, session.CurrentDecision.ClientState);
        AssertFalse(session.CurrentDecision.MayStartHarness);
        AssertEqual(0, fixture.Host.EnsureStartedCalls);
        AssertEqual(0, fixture.Host.HealthCheckCalls);
        AssertEqual(0, fixture.Host.StopCalls);
        AssertFalse(File.Exists(fixture.Paths.Resolve(
            EnterpriseManagedArtifact.EnrollmentSessionDpapi)));
    }

    private static async Task EnterpriseQrCoordinatorDeniedAsync()
    {
        var error = new EnterpriseApiError
        {
            Code = EnterpriseErrorCodes.EnrollmentActivationInvalid,
            Message = "contact administrator",
            ClientState = EnterpriseClientState.QrRequired,
            Retryable = false,
            ContactDisplay = "IT",
            RequestId = "request-1",
            ResetScope = EnterpriseResetScope.None,
        };
        var fixture = CreateEnrollmentCoordinatorFixture(
            QrSessionState.DeniedNotPreregistered,
            error);
        await using var session = fixture.Session;
        using var deviceKeys = fixture.DeviceKeys;

        var pending = fixture.Coordinator.BeginAsync(ActivationCodeVector);
        await fixture.Client.ClaimObserved.WaitAsync(TimeSpan.FromSeconds(2));
        await Task.Yield();
        fixture.TimeProvider.Advance(TimeSpan.FromSeconds(2));
        var outcome = await pending.WaitAsync(TimeSpan.FromSeconds(2));

        AssertFalse(outcome.IdentityApproved);
        AssertEqual(error.Code, outcome.Error!.Code);
        AssertEqual(EnterpriseClientState.QrRequired, session.CurrentDecision.ClientState);
        AssertFalse(File.Exists(fixture.Paths.Resolve(
            EnterpriseManagedArtifact.EnrollmentSessionDpapi)));
        AssertEqual(0, fixture.Host.EnsureStartedCalls);
        AssertEqual(0, fixture.Host.HealthCheckCalls);
        AssertEqual(0, fixture.Host.StopCalls);
    }

    private static async Task EnterpriseQrCoordinatorAccountLockedAsync()
    {
        var error = new EnterpriseApiError
        {
            Code = EnterpriseErrorCodes.EmployeeSuspended,
            Message = "account suspended",
            ClientState = EnterpriseClientState.AccountLocked,
            Retryable = false,
            ContactDisplay = "IT",
            RequestId = "request-account-locked",
            ResetScope = EnterpriseResetScope.None,
        };
        var fixture = CreateEnrollmentCoordinatorFixture(
            QrSessionState.DeniedEmployeeSuspended,
            error);
        await using var session = fixture.Session;
        using var deviceKeys = fixture.DeviceKeys;

        var pending = fixture.Coordinator.BeginAsync(ActivationCodeVector);
        await fixture.Client.ClaimObserved.WaitAsync(TimeSpan.FromSeconds(2));
        await Task.Yield();
        fixture.TimeProvider.Advance(TimeSpan.FromSeconds(2));
        var outcome = await pending.WaitAsync(TimeSpan.FromSeconds(2));

        AssertFalse(outcome.IdentityApproved);
        AssertEqual(EnterpriseClientState.AccountLocked, session.CurrentDecision.ClientState);
        AssertEqual(EnterpriseResetScope.None, session.CurrentDecision.ResetScope);
        AssertFalse(session.CurrentDecision.MayStartHarness);
        AssertEqual(0, fixture.Host.EnsureStartedCalls);
    }

    private static async Task EnterpriseQrCoordinatorLocalExpiryAsync()
    {
        var fixture = CreateEnrollmentCoordinatorFixture(
            QrSessionState.Issued,
            error: null);
        await using var session = fixture.Session;
        using var deviceKeys = fixture.DeviceKeys;

        var pending = fixture.Coordinator.BeginAsync(ActivationCodeVector);
        await fixture.Client.ClaimObserved.WaitAsync(TimeSpan.FromSeconds(2));
        await Task.Yield();
        fixture.TimeProvider.Advance(TimeSpan.FromMinutes(2));
        var outcome = await pending.WaitAsync(TimeSpan.FromSeconds(2));

        AssertEqual(QrSessionState.Expired, outcome.State);
        AssertEqual(EnterpriseErrorCodes.QrSessionExpired, outcome.Error!.Code);
        AssertEqual(EnterpriseClientState.QrRequired, outcome.Error.ClientState);
        AssertTrue(outcome.Error.Retryable);
        AssertEqual(EnterpriseResetScope.None, outcome.Error.ResetScope);
        AssertEqual(EnterpriseClientState.QrRequired, session.CurrentDecision.ClientState);
        AssertFalse(File.Exists(fixture.Paths.Resolve(
            EnterpriseManagedArtifact.EnrollmentSessionDpapi)));
    }

    private static async Task EnterpriseQrCoordinatorFailureAsync()
    {
        var fixture = CreateEnrollmentCoordinatorFixture(
            QrSessionState.Issued,
            error: null,
            pollException: new HttpRequestException("simulated control-plane outage"));
        await using var session = fixture.Session;
        using var deviceKeys = fixture.DeviceKeys;

        var pending = fixture.Coordinator.BeginAsync(ActivationCodeVector);
        await fixture.Client.ClaimObserved.WaitAsync(TimeSpan.FromSeconds(2));
        await Task.Yield();
        fixture.TimeProvider.Advance(TimeSpan.FromSeconds(2));
        await AssertThrowsAsync<HttpRequestException>(() => pending);

        AssertEqual(EnterpriseClientState.QrRequired, session.CurrentDecision.ClientState);
        AssertTrue(File.Exists(fixture.Paths.Resolve(
            EnterpriseManagedArtifact.EnrollmentSessionDpapi)));
        AssertEqual(0, fixture.Host.EnsureStartedCalls);
        AssertEqual(0, fixture.Host.HealthCheckCalls);
        AssertEqual(0, fixture.Host.StopCalls);
    }

    private static async Task EnterpriseWeComCoordinatorAsync()
    {
        var fixture = CreateEnrollmentCoordinatorFixture(
            QrSessionState.Approved,
            error: null,
            allowPollWithoutActivationClaim: true);
        await using var session = fixture.Session;
        using var deviceKeys = fixture.DeviceKeys;

        var pending = fixture.Coordinator.BeginWithWeComAsync();
        await fixture.Browser.OpenObserved.WaitAsync(TimeSpan.FromSeconds(2));
        AssertEqual(
            "https://login.example.test/activate",
            fixture.Browser.OpenedUrl!.AbsoluteUri);
        var persistedSession = await new EnterpriseProtectedArtifactStore(fixture.Paths)
            .ReadAsync(EnterpriseManagedArtifact.EnrollmentSessionDpapi);
        AssertTrue(persistedSession is not null);
        try
        {
            using var journal = JsonDocument.Parse(persistedSession!);
            AssertEqual(
                2,
                journal.RootElement.GetProperty("schema_version").GetInt32());
            AssertEqual(
                "WECOM",
                journal.RootElement.GetProperty("enrollment_method").GetString());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(persistedSession!);
        }
        await Task.Yield();
        fixture.TimeProvider.Advance(TimeSpan.FromSeconds(2));
        var outcome = await pending.WaitAsync(TimeSpan.FromSeconds(2));

        AssertTrue(outcome.IdentityApproved);
        AssertEqual(
            EnterpriseEnrollmentAuthorizationMethod.WeCom,
            fixture.Client.LastCreateRequest!.AuthorizationMethod);
        AssertEqual(
            EnterpriseEnrollmentAuthorizationMethod.WeCom,
            fixture.Client.LastPollAuthorizationMethod);
        AssertEqual(0, fixture.Client.ClaimCalls);
        AssertEqual(1, fixture.Client.PollCalls);
        AssertFalse(File.Exists(fixture.Paths.Resolve(
            EnterpriseManagedArtifact.EnrollmentSessionDpapi)));
    }

    private static async Task EnterpriseEnrollmentMethodSwitchPreservesJournalAsync()
    {
        var fixture = CreateEnrollmentCoordinatorFixture(
            QrSessionState.Issued,
            error: null,
            pollException: new HttpRequestException("simulated recovery poll outage"));
        await using var session = fixture.Session;
        using var deviceKeys = fixture.DeviceKeys;

        var activation = fixture.Coordinator.BeginAsync(ActivationCodeVector);
        await fixture.Client.ClaimObserved.WaitAsync(TimeSpan.FromSeconds(2));
        await Task.Yield();
        fixture.TimeProvider.Advance(TimeSpan.FromSeconds(2));
        await AssertThrowsAsync<HttpRequestException>(() => activation);

        await AssertThrowsAsync<EnterpriseEnrollmentMethodConflictException>(() =>
            fixture.Coordinator.BeginWithWeComAsync());
        AssertEqual(1, fixture.Client.CreateCalls);
        AssertEqual(1, fixture.Client.ClaimCalls);
        AssertTrue(fixture.Browser.OpenedUrl is null);
        AssertTrue(File.Exists(fixture.Paths.Resolve(
            EnterpriseManagedArtifact.EnrollmentSessionDpapi)));
    }

    private static async Task EnterpriseExpiredV1JournalPermitsWeComAsync()
    {
        var fixture = CreateEnrollmentCoordinatorFixture(
            QrSessionState.Approved,
            error: null,
            pollException: new HttpRequestException("simulated recovery poll outage"),
            allowPollWithoutActivationClaim: true);
        await using var session = fixture.Session;
        using var deviceKeys = fixture.DeviceKeys;

        var activation = fixture.Coordinator.BeginAsync(ActivationCodeVector);
        await fixture.Client.ClaimObserved.WaitAsync(TimeSpan.FromSeconds(2));
        await Task.Yield();
        fixture.TimeProvider.Advance(TimeSpan.FromSeconds(2));
        await AssertThrowsAsync<HttpRequestException>(() => activation);

        var store = new EnterpriseProtectedArtifactStore(fixture.Paths);
        var currentBytes = await store.ReadAsync(
            EnterpriseManagedArtifact.EnrollmentSessionDpapi);
        AssertTrue(currentBytes is not null);
        byte[]? v1Bytes = null;
        try
        {
            var journal = JsonNode.Parse(currentBytes!)!.AsObject();
            journal["schema_version"] = 1;
            journal.Remove("enrollment_method");
            journal["expires_at"] = fixture.TimeProvider.GetUtcNow()
                .AddSeconds(-1)
                .ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);
            v1Bytes = JsonSerializer.SerializeToUtf8Bytes(journal);
            await store.WriteAsync(
                EnterpriseManagedArtifact.EnrollmentSessionDpapi,
                v1Bytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(currentBytes!);
            if (v1Bytes is not null)
            {
                CryptographicOperations.ZeroMemory(v1Bytes);
            }
        }

        fixture.Client.PollException = null;
        var weCom = fixture.Coordinator.BeginWithWeComAsync();
        await fixture.Browser.OpenObserved.WaitAsync(TimeSpan.FromSeconds(2));
        await Task.Yield();
        fixture.TimeProvider.Advance(TimeSpan.FromSeconds(2));
        var outcome = await weCom.WaitAsync(TimeSpan.FromSeconds(2));

        AssertTrue(outcome.IdentityApproved);
        AssertEqual(2, fixture.Client.CreateCalls);
        AssertEqual(1, fixture.Client.ClaimCalls);
        AssertEqual(2, fixture.Client.PollCalls);
        AssertFalse(File.Exists(fixture.Paths.Resolve(
            EnterpriseManagedArtifact.EnrollmentSessionDpapi)));
    }

    private static async Task EnterpriseActivationClaimLostResponseRecoveryAsync()
    {
        var fixture = CreateEnrollmentCoordinatorFixture(
            QrSessionState.Approved,
            error: null,
            claimException: new HttpRequestException("simulated lost 204 response"));
        await using var session = fixture.Session;
        using var deviceKeys = fixture.DeviceKeys;

        var outcome = await fixture.Coordinator.BeginAsync(ActivationCodeVector)
            .WaitAsync(TimeSpan.FromSeconds(2));

        AssertTrue(outcome.IdentityApproved);
        AssertEqual(1, fixture.Client.ClaimCalls);
        AssertEqual(1, fixture.Client.PollCalls);
        AssertEqual(BindingSessionId, outcome.BindingChallenge!.SessionId);
        AssertFalse(File.Exists(fixture.Paths.Resolve(
            EnterpriseManagedArtifact.EnrollmentSessionDpapi)));
        AssertEqual(EnterpriseClientState.Binding, session.CurrentDecision.ClientState);
    }

    private static async Task EnterpriseCommittedActivationResumeAfterRestartAsync()
    {
        var fixture = CreateEnrollmentCoordinatorFixture(
            QrSessionState.Approved,
            error: null,
            pollException: new HttpRequestException("simulated recovery poll outage"),
            claimException: new HttpRequestException("simulated lost 204 response"));
        await using var session = fixture.Session;
        using var deviceKeys = fixture.DeviceKeys;

        await AssertThrowsAsync<HttpRequestException>(() =>
            fixture.Coordinator.BeginAsync(ActivationCodeVector));

        AssertTrue(File.Exists(fixture.Paths.Resolve(
            EnterpriseManagedArtifact.EnrollmentSessionDpapi)));
        AssertEqual(1, fixture.Client.CreateCalls);
        AssertEqual(1, fixture.Client.ClaimCalls);
        AssertEqual(1, fixture.Client.PollCalls);
        fixture.Client.PollException = null;

        await using var restartedSession = new EnterpriseHarnessSession(
            new EnterpriseStartupGate(fixture.TimeProvider),
            fixture.Host,
            EnterpriseStartupGate.CreateEnrollmentRequiredSnapshot());
        var restartedCoordinator = CreateRestartedEnrollmentCoordinator(
            fixture,
            restartedSession);
        var outcome = await restartedCoordinator.BeginAsync(ActivationCodeVector)
            .WaitAsync(TimeSpan.FromSeconds(2));

        AssertTrue(outcome.IdentityApproved);
        AssertEqual(BindingSessionId, outcome.BindingChallenge!.SessionId);
        AssertEqual(1, fixture.Client.CreateCalls);
        AssertEqual(1, fixture.Client.ClaimCalls);
        AssertEqual(2, fixture.Client.PollCalls);
        AssertFalse(File.Exists(fixture.Paths.Resolve(
            EnterpriseManagedArtifact.EnrollmentSessionDpapi)));
    }

    private static async Task EnterpriseActivationClaimTimeoutRecoveryAsync()
    {
        var fixture = CreateEnrollmentCoordinatorFixture(
            QrSessionState.Approved,
            error: null,
            claimException: new TaskCanceledException("simulated timeout after send"));
        await using var session = fixture.Session;
        using var deviceKeys = fixture.DeviceKeys;

        var outcome = await fixture.Coordinator.BeginAsync(ActivationCodeVector)
            .WaitAsync(TimeSpan.FromSeconds(2));

        AssertTrue(outcome.IdentityApproved);
        AssertEqual(1, fixture.Client.CreateCalls);
        AssertEqual(1, fixture.Client.ClaimCalls);
        AssertEqual(1, fixture.Client.PollCalls);
        AssertFalse(File.Exists(fixture.Paths.Resolve(
            EnterpriseManagedArtifact.EnrollmentSessionDpapi)));
    }

    private static async Task EnterpriseResumedTerminalEnrollmentDeletesJournalAsync()
    {
        var error = new EnterpriseApiError
        {
            Code = EnterpriseErrorCodes.EnrollmentActivationInvalid,
            Message = "contact administrator",
            ClientState = EnterpriseClientState.QrRequired,
            Retryable = false,
            ContactDisplay = "IT",
            RequestId = "request-resumed-terminal",
            ResetScope = EnterpriseResetScope.None,
        };
        var fixture = CreateEnrollmentCoordinatorFixture(
            QrSessionState.DeniedNotPreregistered,
            error,
            pollException: new HttpRequestException("simulated recovery poll outage"),
            claimException: new HttpRequestException("simulated lost 204 response"));
        await using var session = fixture.Session;
        using var deviceKeys = fixture.DeviceKeys;

        await AssertThrowsAsync<HttpRequestException>(() =>
            fixture.Coordinator.BeginAsync(ActivationCodeVector));
        AssertTrue(File.Exists(fixture.Paths.Resolve(
            EnterpriseManagedArtifact.EnrollmentSessionDpapi)));
        fixture.Client.PollException = null;

        await using var restartedSession = new EnterpriseHarnessSession(
            new EnterpriseStartupGate(fixture.TimeProvider),
            fixture.Host,
            EnterpriseStartupGate.CreateEnrollmentRequiredSnapshot());
        var restartedCoordinator = CreateRestartedEnrollmentCoordinator(
            fixture,
            restartedSession);
        var outcome = await restartedCoordinator.BeginAsync(ActivationCodeVector)
            .WaitAsync(TimeSpan.FromSeconds(2));

        AssertEqual(QrSessionState.DeniedNotPreregistered, outcome.State);
        AssertEqual(error.Code, outcome.Error!.Code);
        AssertEqual(1, fixture.Client.CreateCalls);
        AssertEqual(1, fixture.Client.ClaimCalls);
        AssertEqual(2, fixture.Client.PollCalls);
        AssertFalse(File.Exists(fixture.Paths.Resolve(
            EnterpriseManagedArtifact.EnrollmentSessionDpapi)));
    }

    private static async Task EnterpriseEnrollmentJournalRejectsIdentityMismatchAsync()
    {
        var fixture = CreateEnrollmentCoordinatorFixture(
            QrSessionState.Approved,
            error: null,
            pollException: new HttpRequestException("simulated recovery poll outage"),
            claimException: new HttpRequestException("simulated lost 204 response"));
        await using var session = fixture.Session;
        using var deviceKeys = fixture.DeviceKeys;

        await AssertThrowsAsync<HttpRequestException>(() =>
            fixture.Coordinator.BeginAsync(ActivationCodeVector));
        AssertTrue(File.Exists(fixture.Paths.Resolve(
            EnterpriseManagedArtifact.EnrollmentSessionDpapi)));

        await using var restartedSession = new EnterpriseHarnessSession(
            new EnterpriseStartupGate(fixture.TimeProvider),
            fixture.Host,
            EnterpriseStartupGate.CreateEnrollmentRequiredSnapshot());
        using var replacementDeviceKeys = new EphemeralDeviceProofKeyStore();
        var changedDeviceCoordinator = CreateRestartedEnrollmentCoordinator(
            fixture,
            restartedSession,
            replacementDeviceKeys);
        await AssertThrowsAsync<InvalidDataException>(() =>
            changedDeviceCoordinator.BeginAsync(ActivationCodeVector));

        File.Delete(fixture.Paths.InstallationIdentityPath);
        var changedInstallCoordinator = CreateRestartedEnrollmentCoordinator(
            fixture,
            restartedSession);
        await AssertThrowsAsync<InvalidDataException>(() =>
            changedInstallCoordinator.BeginAsync(ActivationCodeVector));

        AssertEqual(1, fixture.Client.CreateCalls);
        AssertEqual(1, fixture.Client.ClaimCalls);
        AssertEqual(1, fixture.Client.PollCalls);
        AssertTrue(File.Exists(fixture.Paths.Resolve(
            EnterpriseManagedArtifact.EnrollmentSessionDpapi)));
    }

    private static EnterpriseQrSessionCreateRequest CreateQrRequest(
        EnterpriseDevicePublicIdentity identity) => new()
    {
        AuthorizationMethod = EnterpriseEnrollmentAuthorizationMethod.AdminInvite,
        InstallId = Guid.NewGuid().ToString("D"),
        DeviceJwk = new EnterpriseEcPublicJwk
        {
            KeyType = identity.KeyType,
            Curve = identity.Curve,
            X = identity.X,
            Y = identity.Y,
        },
        DeviceKeyThumbprint = identity.Thumbprint,
        DeviceDisplayName = QrDeviceDisplayName,
        LauncherVersion = "1.0.0",
        RuntimeVersion = "uninstalled",
        Platform = "windows-x64",
        Nonce = QrNonceVector,
    };

    private static EnterpriseQrSessionCreateResponse CreateQrSession(DateTimeOffset now) => new()
    {
        SessionId = BindingSessionId,
        PollSecret = QrPollSecretVector,
        AuthorizationUrl = new Uri("https://login.example.test/activate"),
        DeviceDisplayName = QrDeviceDisplayName,
        ConfirmationCode = QrConfirmationCode,
        ExpiresAtUtc = now.AddMinutes(2),
        PollAfterSeconds = 2,
    };

    private static AuthorizationLeaseFixture LoadAuthorizationLeaseFixture()
    {
        var fixturePath = Path.Combine(
            AppContext.BaseDirectory,
            "Fixtures",
            "authorization-lease-v1.json");
        using var document = JsonDocument.Parse(File.ReadAllBytes(fixturePath));
        var root = document.RootElement;
        var signingKey = root.GetProperty("lease_signing_jwk");
        var payloadJson = root.GetProperty("payload_json").GetString()
            ?? throw new InvalidDataException("Authorization lease fixture payload is missing.");
        using var payloadDocument = JsonDocument.Parse(payloadJson);
        var payload = payloadDocument.RootElement;
        var evaluationTimeUtc = DateTimeOffset.FromUnixTimeSeconds(
            payload.GetProperty("iat").GetInt64());

        return new AuthorizationLeaseFixture(
            root.GetProperty("compact_jws").GetString()
                ?? throw new InvalidDataException("Authorization lease fixture compact JWS is missing."),
            root.GetProperty("protected_header_json").GetString()
                ?? throw new InvalidDataException("Authorization lease fixture header is missing."),
            root.GetProperty("protected_header_base64url").GetString()
                ?? throw new InvalidDataException("Authorization lease fixture header segment is missing."),
            payloadJson,
            signingKey.GetProperty("kid").GetString()
                ?? throw new InvalidDataException("Authorization lease fixture key ID is missing."),
            signingKey.GetProperty("x").GetString()
                ?? throw new InvalidDataException("Authorization lease fixture key X is missing."),
            signingKey.GetProperty("y").GetString()
                ?? throw new InvalidDataException("Authorization lease fixture key Y is missing."),
            signingKey.GetProperty("d").GetString()
                ?? throw new InvalidDataException("Authorization lease fixture private key is missing."),
            payload.GetProperty("jti").GetString()!,
            payload.GetProperty("iss").GetString()!,
            payload.GetProperty("gateway_origin").GetString()!,
            payload.GetProperty("artifact_origin").GetString()!,
            payload.GetProperty("binding_id").GetString()!,
            payload.GetProperty("installation_id").GetString()!,
            payload.GetProperty("device_key_thumbprint").GetString()!,
            evaluationTimeUtc);
    }

    private static EnterpriseAuthorizationLeaseVerifier CreateAuthorizationLeaseVerifier(
        AuthorizationLeaseFixture fixture) =>
        new(new EnterpriseAuthorizationLeaseTrustPolicy(
            new Uri(fixture.IssuerOrigin),
            new Uri(fixture.GatewayOrigin),
            new Uri(fixture.ArtifactOrigin),
            [
                new EnterpriseAuthorizationLeasePublicKey(
                    fixture.KeyId,
                    fixture.PublicKeyX,
                    fixture.PublicKeyY),
            ]));

    private static string SignAuthorizationLeasePayload(
        AuthorizationLeaseFixture fixture,
        string payloadJson)
    {
        var payloadSegment = EncodeBase64Url(Encoding.UTF8.GetBytes(payloadJson));
        var signingInput = Encoding.ASCII.GetBytes(
            $"{fixture.HeaderSegment}.{payloadSegment}");
        var privateKey = DecodeBase64Url(fixture.PrivateKeyD);
        var publicKeyX = DecodeBase64Url(fixture.PublicKeyX);
        var publicKeyY = DecodeBase64Url(fixture.PublicKeyY);
        try
        {
            using var key = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                D = privateKey,
                Q = new ECPoint
                {
                    X = publicKeyX,
                    Y = publicKeyY,
                },
            });
            var signature = key.SignData(
                signingInput,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            try
            {
                return $"{fixture.HeaderSegment}.{payloadSegment}.{EncodeBase64Url(signature)}";
            }
            finally
            {
                CryptographicOperations.ZeroMemory(signature);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(signingInput);
            CryptographicOperations.ZeroMemory(privateKey);
            CryptographicOperations.ZeroMemory(publicKeyX);
            CryptographicOperations.ZeroMemory(publicKeyY);
        }
    }

    private static EnterpriseDeviceBindingCompleteResponse CreateSignedRefreshTestResponse(
        AuthorizationLeaseFixture fixture,
        string deviceKeyThumbprint,
        DateTimeOffset issuedAtUtc,
        string leaseId,
        string refreshToken,
        char accessTokenCharacter)
    {
        var originalIssuedAt = fixture.EvaluationTimeUtc.ToUnixTimeSeconds();
        var originalExpiresAt = fixture.EvaluationTimeUtc.AddMinutes(15).ToUnixTimeSeconds();
        var payloadJson = fixture.PayloadJson
            .Replace(
                $"\"device_key_thumbprint\":\"{fixture.DeviceKeyThumbprint}\"",
                $"\"device_key_thumbprint\":\"{deviceKeyThumbprint}\"",
                StringComparison.Ordinal)
            .Replace(
                $"\"jti\":\"{fixture.LeaseId}\"",
                $"\"jti\":\"{leaseId}\"",
                StringComparison.Ordinal)
            .Replace(
                $"\"iat\":{originalIssuedAt}",
                $"\"iat\":{issuedAtUtc.ToUnixTimeSeconds()}",
                StringComparison.Ordinal)
            .Replace(
                $"\"nbf\":{originalIssuedAt}",
                $"\"nbf\":{issuedAtUtc.ToUnixTimeSeconds()}",
                StringComparison.Ordinal)
            .Replace(
                $"\"exp\":{originalExpiresAt}",
                $"\"exp\":{issuedAtUtc.AddMinutes(15).ToUnixTimeSeconds()}",
                StringComparison.Ordinal);
        return new EnterpriseDeviceBindingCompleteResponse
        {
            SchemaVersion = 1,
            BindingId = fixture.BindingId,
            RefreshToken = refreshToken,
            AccessToken = new string(accessTokenCharacter, 43),
            AccessTokenExpiresAtUtc = issuedAtUtc.AddMinutes(10),
            AuthorizationLease = SignAuthorizationLeasePayload(fixture, payloadJson),
            LeaseExpiresAtUtc = issuedAtUtc.AddMinutes(15),
            ServerTimeUtc = issuedAtUtc,
        };
    }

    private static EnterpriseDeviceBindingCompleteRequest CreateBindingRequest(
        IEnterpriseDeviceProofKeyStore deviceKeys,
        DateTimeOffset now)
    {
        var identity = deviceKeys.GetOrCreatePublicIdentity();
        return EnterpriseBindingPayloadBuilder.CreateSignedRequest(
            new EnterpriseBindingChallenge(
                BindingSessionId,
                BindingGrantVector,
                BindingChallengeVector,
                now.AddMinutes(1)),
            BindingInstallId,
            identity.Thumbprint,
            "Employee PC",
            deviceKeys);
    }

    private static EnterpriseDeviceBindingClient CreateBindingHttpClient(
        HttpClient httpClient,
        IEnterpriseDeviceProofKeyStore deviceKeys,
        DateTimeOffset now) => new(
        httpClient,
        new EnterpriseControlPlaneOptions(
            new Uri("https://control.example.test/"),
            new Uri("https://login.example.test/")),
        new EnterpriseDpopProofFactory(deviceKeys, new FixedTimeProvider(now)),
        new FixedTimeProvider(now));

    private static string CreateCompactLease(string type = "ensou-dsh-lease+jwt")
    {
        var header = EncodeBase64Url(Encoding.UTF8.GetBytes(
            $"{{\"alg\":\"ES256\",\"kid\":\"lease-key-1\",\"typ\":\"{type}\"}}"));
        var payload = EncodeBase64Url(Encoding.UTF8.GetBytes(
            $"{{\"schema_version\":1,\"binding_id\":\"{BindingId}\"}}"));
        var signature = EncodeBase64Url(new byte[64]);
        return $"{header}.{payload}.{signature}";
    }

    private static EnterpriseQrEnrollmentClient CreateQrHttpClient(
        HttpClient httpClient,
        IEnterpriseDeviceProofKeyStore deviceKeys,
        DateTimeOffset now) => new(
        httpClient,
        new EnterpriseControlPlaneOptions(
            new Uri("https://control.example.test/"),
            new Uri("https://login.example.test/")),
        new EnterpriseDpopProofFactory(deviceKeys, new FixedTimeProvider(now)),
        new FixedTimeProvider(now));

    private static HttpResponseMessage JsonResponse(
        string json,
        HttpStatusCode statusCode = HttpStatusCode.OK) => new(statusCode)
    {
        Content = new StringContent(json, Encoding.UTF8, "application/json"),
    };

    private static HttpResponseMessage CreatedJsonResponse(string json) =>
        JsonResponse(json, HttpStatusCode.Created);

    private static EnrollmentCoordinatorFixture CreateEnrollmentCoordinatorFixture(
        QrSessionState resultState,
        EnterpriseApiError? error,
        Exception? pollException = null,
        Exception? claimException = null,
        string deviceLabel = "Ensou DSH device",
        bool allowPollWithoutActivationClaim = false)
    {
        var paths = CreateEnterpriseDiskTestPaths();
        var now = new DateTimeOffset(2026, 8, 24, 3, 0, 0, TimeSpan.Zero);
        var timeProvider = new ManualTimeProvider(now);
        var host = new FakeEnterpriseHarnessHost();
        var session = new EnterpriseHarnessSession(
            new EnterpriseStartupGate(timeProvider),
            host,
            EnterpriseStartupGate.CreateEnrollmentRequiredSnapshot());
        var deviceKeys = new EphemeralDeviceProofKeyStore();
        var preparation = new EnterpriseDeviceEnrollmentPreparation(
            new EnterpriseInstallationIdentityStore(paths, timeProvider),
            deviceKeys);
        var client = new FakeQrEnrollmentClient(
            now,
            resultState,
            error,
            pollException,
            claimException,
            allowPollWithoutActivationClaim);
        var browser = new FakeSystemBrowser();
        var coordinator = new EnterpriseQrEnrollmentCoordinator(
            preparation,
            client,
            new EnterpriseProtectedArtifactStore(paths),
            session,
            "1.0.0",
            "uninstalled",
            "windows-x64",
            timeProvider,
            deviceLabel: deviceLabel,
            systemBrowser: browser);
        return new EnrollmentCoordinatorFixture(
            paths,
            timeProvider,
            host,
            session,
            deviceKeys,
            client,
            browser,
            coordinator);
    }

    private static EnterpriseQrEnrollmentCoordinator CreateRestartedEnrollmentCoordinator(
        EnrollmentCoordinatorFixture fixture,
        EnterpriseHarnessSession session,
        IEnterpriseDeviceProofKeyStore? deviceKeys = null)
    {
        var preparation = new EnterpriseDeviceEnrollmentPreparation(
            new EnterpriseInstallationIdentityStore(
                fixture.Paths,
                fixture.TimeProvider),
            deviceKeys ?? fixture.DeviceKeys);
        return new EnterpriseQrEnrollmentCoordinator(
            preparation,
            fixture.Client,
            new EnterpriseProtectedArtifactStore(fixture.Paths),
            session,
            "1.0.0",
            "uninstalled",
            "windows-x64",
            fixture.TimeProvider);
    }

    private static EnterpriseManagedPaths CreateEnterpriseTestPaths() =>
        EnterpriseManagedPaths.Create(
            @"C:\Users\Employee\AppData\Local",
            @"C:\Users\Employee");

    private static EnterpriseManagedPaths CreateEnterpriseDiskTestPaths()
    {
        var root = Path.Combine(TempRoot, Guid.NewGuid().ToString("N"));
        return EnterpriseManagedPaths.Create(
            Path.Combine(root, "LocalAppData"),
            Path.Combine(root, "Profile"));
    }

    private static EnterpriseAccessSnapshot CreateReadyEnterpriseSnapshot(DateTimeOffset nowUtc) => new()
    {
        Employee = EmployeeAuthorizationState.Active,
        Device = DeviceBindingState.Active,
        ApiAllocation = ApiAllocationState.Active,
        ControlPlane = ControlPlaneConnectivity.Available,
        LeaseSignatureValid = true,
        AuthorizationEpochMatches = true,
        ClockTrusted = true,
        TrustedTimeFloorUtc = nowUtc,
        LeaseIssuedAtUtc = nowUtc.AddMinutes(-1),
        LeaseExpiresAtUtc = nowUtc.AddMinutes(15),
        PluginPolicyId = "11111111-2222-4333-8444-555555555555",
        PluginPolicyGeneration = 1,
        PluginPolicySha256 = new string('a', 64),
    };

    private static ReleaseManifest CreateUnsignedManifest() => new()
    {
        ReleaseId = "managed-v2026.08.23.1",
        Channel = ReleaseChannel.Stable,
        LauncherVersion = "1.1.0",
        // This value is frozen by Fixtures/canonical-payload-v1.vector.json.
        DshVersion = "0.1.0-rc.7",
        PublishedAtUtc = new DateTimeOffset(2026, 8, 23, 0, 0, 0, TimeSpan.Zero),
        MinimumBootstrapperVersion = "1.0.0",
        Artifact = new ReleaseArtifact
        {
            Url = "https://updates.example.test/releases/release-2026.08.23.1.zip",
            FileName = "release-2026.08.23.1.zip",
            SizeBytes = 123456,
            Sha256 = "baa69c5a534e2d53b73c8f3b5571e0ae0e73faa64b60d2a3b986439b6423d87f",
        },
    };

    private static string NewTempPath(string fileName)
    {
        var directory = Path.Combine(TempRoot, Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        return Path.Combine(directory, fileName);
    }

    private static void CreateDirectoryJunction(string junctionPath, string targetPath)
    {
        using var process = Process.Start(new ProcessStartInfo
        {
            FileName = Environment.GetEnvironmentVariable("ComSpec") ?? "cmd.exe",
            Arguments = $"/d /c mklink /J \"{junctionPath}\" \"{targetPath}\"",
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        }) ?? throw new InvalidOperationException("Could not start the junction test helper.");
        process.WaitForExit();
        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException(
                $"Could not create test junction: {process.StandardError.ReadToEnd()}");
        }
    }

    private static void AssertTrue(bool condition)
    {
        if (!condition)
        {
            throw new InvalidOperationException("Expected condition to be true.");
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetHandleInformation(
        SafeWaitHandle handle,
        uint mask,
        uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetEvent(IntPtr handle);

    private static void AssertFalse(bool condition) => AssertTrue(!condition);

    private static void AssertEqual<T>(T expected, T actual)
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
        {
            throw new InvalidOperationException($"Expected '{expected}', actual '{actual}'.");
        }
    }

    private static void AssertSequenceEqual(byte[] expected, byte[] actual)
    {
        if (!expected.AsSpan().SequenceEqual(actual))
        {
            throw new InvalidOperationException("Byte sequences differ.");
        }
    }

    private static byte[] DecodeBase64Url(string value)
    {
        var padding = (value.Length % 4) switch
        {
            0 => string.Empty,
            2 => "==",
            3 => "=",
            _ => throw new FormatException("Invalid base64url test vector."),
        };
        return Convert.FromBase64String(value.Replace('-', '+').Replace('_', '/') + padding);
    }

    private static string EncodeBase64Url(ReadOnlySpan<byte> value) =>
        Convert.ToBase64String(value)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    private static async Task AssertThrowsAsync<TException>(Func<Task> action)
        where TException : Exception
    {
        try
        {
            await action().ConfigureAwait(false);
        }
        catch (TException)
        {
            return;
        }

        throw new InvalidOperationException($"Expected exception {typeof(TException).Name}.");
    }

    private sealed class DelegateHandler(Func<HttpRequestMessage, HttpResponseMessage> responseFactory)
        : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(responseFactory(request));
        }
    }

    private sealed class AsyncDelegateHandler(
        Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> responseFactory)
        : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return responseFactory(request, cancellationToken);
        }
    }

    private sealed class StallingReadStream : Stream
    {
        private readonly TaskCompletionSource _readEntered = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _cancellationObserved = new(
            TaskCreationOptions.RunContinuationsAsynchronously);

        public Task ReadEntered => _readEntered.Task;

        public Task CancellationObserved => _cancellationObserved.Task;

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();

        public override Task<int> ReadAsync(
            byte[] buffer,
            int offset,
            int count,
            CancellationToken cancellationToken) => StallAsync(cancellationToken);

        public override ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default) =>
            new(StallAsync(cancellationToken));

        private async Task<int> StallAsync(CancellationToken cancellationToken)
        {
            _readEntered.TrySetResult();
            try
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken)
                    .ConfigureAwait(false);
                return 0;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                _cancellationObserved.TrySetResult();
                throw;
            }
        }

        public override long Seek(long offset, SeekOrigin origin) =>
            throw new NotSupportedException();

        public override void SetLength(long value) =>
            throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();
    }

    private sealed class FixedTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => utcNow;
    }

    private sealed class ManualTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        private readonly object _sync = new();
        private readonly List<ManualTimer> _timers = [];
        private DateTimeOffset _utcNow = utcNow;
        private long _timestamp;

        public override long TimestampFrequency => TimeSpan.TicksPerSecond;

        public override DateTimeOffset GetUtcNow()
        {
            lock (_sync)
            {
                return _utcNow;
            }
        }

        public override long GetTimestamp()
        {
            lock (_sync)
            {
                return _timestamp;
            }
        }

        public override ITimer CreateTimer(
            TimerCallback callback,
            object? state,
            TimeSpan dueTime,
            TimeSpan period)
        {
            var timer = new ManualTimer(this, callback, state);
            lock (_sync)
            {
                _timers.Add(timer);
                timer.ChangeUnderLock(dueTime, period);
            }

            return timer;
        }

        public void Advance(TimeSpan amount)
        {
            List<ManualTimer> dueTimers;
            lock (_sync)
            {
                _utcNow += amount;
                _timestamp += amount.Ticks;
                dueTimers = _timers.Where(timer => timer.IsDueUnderLock(_timestamp)).ToList();
                foreach (var timer in dueTimers)
                {
                    timer.MarkFiredUnderLock(_timestamp);
                }
            }

            foreach (var timer in dueTimers)
            {
                timer.Fire();
            }
        }

        public void AdjustUtc(TimeSpan amount)
        {
            lock (_sync)
            {
                _utcNow += amount;
            }
        }

        private sealed class ManualTimer(
            ManualTimeProvider owner,
            TimerCallback callback,
            object? state) : ITimer
        {
            private long? _dueAtTimestamp;
            private TimeSpan _period = Timeout.InfiniteTimeSpan;
            private bool _disposed;

            public bool Change(TimeSpan dueTime, TimeSpan period)
            {
                lock (owner._sync)
                {
                    if (_disposed)
                    {
                        return false;
                    }

                    ChangeUnderLock(dueTime, period);
                    return true;
                }
            }

            public void Dispose()
            {
                lock (owner._sync)
                {
                    _disposed = true;
                    _dueAtTimestamp = null;
                    owner._timers.Remove(this);
                }
            }

            public ValueTask DisposeAsync()
            {
                Dispose();
                return ValueTask.CompletedTask;
            }

            internal void ChangeUnderLock(TimeSpan dueTime, TimeSpan period)
            {
                _period = period;
                _dueAtTimestamp = dueTime == Timeout.InfiniteTimeSpan
                    ? null
                    : owner._timestamp + dueTime.Ticks;
            }

            internal bool IsDueUnderLock(long timestamp) =>
                !_disposed
                && _dueAtTimestamp is { } dueAtTimestamp
                && dueAtTimestamp <= timestamp;

            internal void MarkFiredUnderLock(long timestamp)
            {
                _dueAtTimestamp = _period == Timeout.InfiniteTimeSpan
                    ? null
                    : timestamp + _period.Ticks;
            }

            internal void Fire() => callback(state);
        }
    }

    private sealed class FakeEnterpriseHarnessHost : IEnterpriseHarnessHost
    {
        public Uri WebUiUri { get; } = new("http://127.0.0.1:3081/", UriKind.Absolute);

        public bool Healthy { get; init; }

        public int EnsureStartedCalls { get; private set; }

        public int HealthCheckCalls { get; private set; }

        public int OpenWebUiCalls { get; private set; }

        public int StopCalls { get; private set; }

        public int DisposeCalls { get; private set; }

        public int StopFailuresRemaining { get; init; }

        public Action? EnsureStartedAction { get; init; }

        public Action? HealthCheckAction { get; init; }

        public Action? StopAction { get; init; }

        public Task StopObserved => _stopObserved.Task;

        private readonly TaskCompletionSource _stopObserved = new(
            TaskCreationOptions.RunContinuationsAsynchronously);

        public Task EnsureStartedAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            EnsureStartedCalls++;
            EnsureStartedAction?.Invoke();
            return Task.CompletedTask;
        }

        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            HealthCheckCalls++;
            HealthCheckAction?.Invoke();
            return Task.FromResult(Healthy);
        }

        public Task OpenWebUiAsync(
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            OpenWebUiCalls++;
            return Task.CompletedTask;
        }

        public Task StopOwnedProcessAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            StopCalls++;
            StopAction?.Invoke();
            if (StopCalls <= StopFailuresRemaining)
            {
                throw new InvalidOperationException("Simulated owned-host stop failure.");
            }

            _stopObserved.TrySetResult();
            return Task.CompletedTask;
        }

        public ValueTask DisposeAsync()
        {
            DisposeCalls++;
            return ValueTask.CompletedTask;
        }
    }

    private sealed class FakeEnterpriseResetExecutor : IEnterpriseResetExecutor
    {
        private readonly TaskCompletionSource _successfulExecution = new(
            TaskCreationOptions.RunContinuationsAsynchronously);

        public List<EnterpriseResetScope> Scopes { get; } = [];

        public int FailuresRemaining { get; init; }

        public Action<EnterpriseResetScope>? ExecuteAction { get; init; }

        public Action<EnterpriseResetBarrier>? PersistBarrierAction { get; init; }

        public Task SuccessfulExecution => _successfulExecution.Task;

        public EnterpriseResetBarrier? Barrier { get; private set; }

        public int ClearBarrierCalls { get; private set; }

        public EnterpriseResetBarrier? ReadBarrier() => Barrier;

        public void PersistBarrier(EnterpriseResetBarrier barrier)
        {
            Barrier = barrier;
            PersistBarrierAction?.Invoke(barrier);
        }

        public void ClearBarrier()
        {
            Barrier = null;
            ClearBarrierCalls++;
        }

        public void Execute(EnterpriseResetScope scope)
        {
            Scopes.Add(scope);
            ExecuteAction?.Invoke(scope);
            if (Scopes.Count <= FailuresRemaining)
            {
                throw new IOException("Simulated enterprise reset failure.");
            }

            _successfulExecution.TrySetResult();
        }
    }

    private sealed class FakeDeviceProofKeyStore : IEnterpriseDeviceProofKeyStore
    {
        public int DeleteCalls { get; private set; }

        public EnterpriseDevicePublicIdentity GetOrCreatePublicIdentity() =>
            throw new NotSupportedException();

        public byte[] Sign(ReadOnlySpan<byte> payload) => throw new NotSupportedException();

        public void DeleteForSecurityReset() => DeleteCalls++;
    }

    private sealed class EphemeralDeviceProofKeyStore : IEnterpriseDeviceProofKeyStore, IDisposable
    {
        private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        public EnterpriseDevicePublicIdentity GetOrCreatePublicIdentity() =>
            EnterpriseDeviceProofKeyStore.CreatePublicIdentity(_key);

        public byte[] Sign(ReadOnlySpan<byte> payload) => _key.SignData(
            payload,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

        public bool Verify(ReadOnlySpan<byte> payload, ReadOnlySpan<byte> signature) =>
            _key.VerifyData(
                payload,
                signature,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

        public void DeleteForSecurityReset()
        {
        }

        public void Dispose() => _key.Dispose();
    }

    private sealed class FixedBindingReplayClient(
        EnterpriseDeviceBindingCompleteResponse response) :
        IEnterpriseDeviceBindingReplayClient
    {
        public int ExactCalls { get; private set; }

        public Task<EnterpriseDeviceBindingCompleteResponse> CompleteAsync(
            EnterpriseDeviceBindingCompleteRequest request,
            string idempotencyKey,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException(
                "The recovery test must use the exact-body replay path.");

        public Task<EnterpriseDeviceBindingCompleteResponse> CompleteExactAsync(
            ReadOnlyMemory<byte> exactRequestBody,
            string idempotencyKey,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            AssertTrue(!exactRequestBody.IsEmpty);
            AssertEqual(BindingIdempotencyKey, idempotencyKey);
            ExactCalls++;
            return Task.FromResult(response);
        }
    }

    private static void AssertSequenceEqual<T>(
        IReadOnlyList<T> expected,
        IReadOnlyList<T> actual)
    {
        if (!expected.SequenceEqual(actual))
        {
            throw new InvalidOperationException("Sequences differ.");
        }
    }

    private static bool ContainsEnvironmentKey(
        ProcessStartInfo startInfo,
        string expectedKey) => startInfo.Environment.Keys.Any(key => string.Equals(
            key,
            expectedKey,
            StringComparison.OrdinalIgnoreCase));

    private sealed class FixedRefreshClient(
        EnterpriseDeviceBindingCompleteResponse response,
        string expectedRefreshToken,
        string expectedPreviousLeaseId) : IEnterpriseRefreshClient
    {
        public int ExactCalls { get; private set; }

        public Task<EnterpriseDeviceBindingCompleteResponse> RefreshAsync(
            EnterpriseRefreshRequest request,
            string refreshToken,
            string idempotencyKey,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException(
                "The lifecycle test must use the durable exact-body refresh path.");

        public Task<EnterpriseDeviceBindingCompleteResponse> RefreshExactAsync(
            ReadOnlyMemory<byte> exactRequestBody,
            string refreshToken,
            string idempotencyKey,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var request = EnterpriseRefreshClient.DeserializeExactRequest(exactRequestBody);
            AssertEqual(expectedRefreshToken, refreshToken);
            AssertEqual(expectedPreviousLeaseId, request.PreviousLeaseId);
            AssertEqual(response.BindingId, request.BindingId);
            AssertEqual(43, idempotencyKey.Length);
            ExactCalls++;
            return Task.FromResult(response);
        }
    }

    private sealed class BlockingRefreshClient(
        EnterpriseDeviceBindingCompleteResponse response,
        string expectedRefreshToken,
        string expectedPreviousLeaseId) : IEnterpriseRefreshClient
    {
        private readonly TaskCompletionSource _entered = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _release = new(
            TaskCreationOptions.RunContinuationsAsynchronously);

        public Task Entered => _entered.Task;

        public void Release() => _release.TrySetResult();

        public Task<EnterpriseDeviceBindingCompleteResponse> RefreshAsync(
            EnterpriseRefreshRequest request,
            string refreshToken,
            string idempotencyKey,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException("The lifecycle test requires exact-body replay.");

        public async Task<EnterpriseDeviceBindingCompleteResponse> RefreshExactAsync(
            ReadOnlyMemory<byte> exactRequestBody,
            string refreshToken,
            string idempotencyKey,
            CancellationToken cancellationToken = default)
        {
            var request = EnterpriseRefreshClient.DeserializeExactRequest(exactRequestBody);
            AssertEqual(expectedRefreshToken, refreshToken);
            AssertEqual(expectedPreviousLeaseId, request.PreviousLeaseId);
            AssertEqual(response.BindingId, request.BindingId);
            AssertEqual(43, idempotencyKey.Length);
            _entered.TrySetResult();
            await _release.Task.WaitAsync(cancellationToken);
            return response;
        }
    }

    private sealed class ThrowingRefreshClient(Exception exception) : IEnterpriseRefreshClient
    {
        public Task<EnterpriseDeviceBindingCompleteResponse> RefreshAsync(
            EnterpriseRefreshRequest request,
            string refreshToken,
            string idempotencyKey,
            CancellationToken cancellationToken = default) =>
            Task.FromException<EnterpriseDeviceBindingCompleteResponse>(exception);

        public Task<EnterpriseDeviceBindingCompleteResponse> RefreshExactAsync(
            ReadOnlyMemory<byte> exactRequestBody,
            string refreshToken,
            string idempotencyKey,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromException<EnterpriseDeviceBindingCompleteResponse>(exception);
        }
    }

    private sealed class PassThroughEnterpriseDeviceUpdateGate
        : IEnterpriseDeviceUpdateGate
    {
        public Task<EnterpriseAccessSnapshot> EvaluateBeforeReadyAsync(
            EnterpriseAccessSnapshot authorizedSnapshot,
            string bindingId,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(authorizedSnapshot);
        }
    }

    private sealed class ThrowingEnterpriseDeviceUpdateGate
        : IEnterpriseDeviceUpdateGate
    {
        public Task<EnterpriseAccessSnapshot> EvaluateBeforeReadyAsync(
            EnterpriseAccessSnapshot authorizedSnapshot,
            string bindingId,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromException<EnterpriseAccessSnapshot>(
                new HttpRequestException("Simulated update-gate transport outage."));
        }
    }

    private sealed class RecordingEnterpriseDeviceUpdateGate(
        EnterpriseHarnessSession session,
        bool blockForUpdate) : IEnterpriseDeviceUpdateGate
    {
        public int Calls { get; private set; }

        public bool ObservedReady { get; private set; }

        public Task<EnterpriseAccessSnapshot> EvaluateBeforeReadyAsync(
            EnterpriseAccessSnapshot authorizedSnapshot,
            string bindingId,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls++;
            ObservedReady |= session.CurrentDecision.ClientState
                == EnterpriseClientState.Ready;
            return Task.FromResult(blockForUpdate
                ? authorizedSnapshot with { ClientUpdateRequired = true }
                : authorizedSnapshot);
        }
    }

    private sealed class UnavailableRefreshClient : IEnterpriseRefreshClient
    {
        public int ExactCalls { get; private set; }

        public Task<EnterpriseDeviceBindingCompleteResponse> RefreshAsync(
            EnterpriseRefreshRequest request,
            string refreshToken,
            string idempotencyKey,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException(
                "The rollback regression must use the exact-body refresh path.");

        public Task<EnterpriseDeviceBindingCompleteResponse> RefreshExactAsync(
            ReadOnlyMemory<byte> exactRequestBody,
            string refreshToken,
            string idempotencyKey,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ExactCalls++;
            return Task.FromException<EnterpriseDeviceBindingCompleteResponse>(
                new HttpRequestException("Simulated control-plane outage after restart."));
        }
    }

    private sealed class FakeQrEnrollmentClient(
        DateTimeOffset now,
        QrSessionState resultState,
        EnterpriseApiError? error,
        Exception? pollException,
        Exception? claimException,
        bool allowPollWithoutActivationClaim) : IEnterpriseQrEnrollmentClient
    {
        private readonly TaskCompletionSource _claimObserved = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        private string? _claimedNonce;

        public EnterpriseQrSessionCreateRequest? LastCreateRequest { get; private set; }

        public EnterpriseEnrollmentAuthorizationMethod? LastPollAuthorizationMethod
        {
            get;
            private set;
        }

        public QrSessionState ResultState { get; set; } = resultState;

        public EnterpriseApiError? Error { get; set; } = error;

        public Exception? PollException { get; set; } = pollException;

        public Exception? ClaimException { get; set; } = claimException;

        public Task ClaimObserved => _claimObserved.Task;

        public int CreateCalls { get; private set; }

        public int ClaimCalls { get; private set; }

        public int PollCalls { get; private set; }

        public Task<EnterpriseQrSessionCreateResponse> CreateSessionAsync(
            EnterpriseQrSessionCreateRequest request,
            string idempotencyKey,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            LastCreateRequest = request;
            CreateCalls++;
            return Task.FromResult(new EnterpriseQrSessionCreateResponse
            {
                SessionId = BindingSessionId,
                PollSecret = QrPollSecretVector,
                AuthorizationUrl = new Uri("https://login.example.test/activate"),
                DeviceDisplayName = request.DeviceDisplayName,
                ConfirmationCode = QrConfirmationCode,
                ExpiresAtUtc = now.AddMinutes(2),
                PollAfterSeconds = 2,
            });
        }

        public Task ClaimActivationAsync(
            EnterpriseQrSessionCreateResponse session,
            string nonce,
            string activationCode,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            AssertEqual(BindingSessionId, session.SessionId);
            AssertEqual(ActivationCodeVector, activationCode);
            var nonceBytes = DecodeBase64Url(nonce);
            try
            {
                AssertEqual(32, nonceBytes.Length);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(nonceBytes);
            }
            _claimedNonce = nonce;
            ClaimCalls++;
            _claimObserved.TrySetResult();
            return ClaimException is null
                ? Task.CompletedTask
                : Task.FromException(ClaimException);
        }

        public Task<EnterpriseQrSessionPollResponse> PollSessionAsync(
            EnterpriseQrSessionCreateResponse session,
            string nonce,
            EnterpriseEnrollmentAuthorizationMethod authorizationMethod,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            AssertTrue(Enum.IsDefined(authorizationMethod));
            LastPollAuthorizationMethod = authorizationMethod;
            if (!allowPollWithoutActivationClaim)
            {
                AssertEqual(_claimedNonce, nonce);
            }
            PollCalls++;
            if (PollException is not null)
            {
                return Task.FromException<EnterpriseQrSessionPollResponse>(PollException);
            }

            return Task.FromResult(new EnterpriseQrSessionPollResponse
            {
                Status = ResultState,
                PollAfterSeconds = ResultState is QrSessionState.Issued
                    or QrSessionState.CallbackVerified
                    or QrSessionState.EligibilityVerified
                    ? 2
                    : null,
                BindGrant = ResultState == QrSessionState.Approved
                    ? BindingGrantVector
                    : null,
                BindingChallenge = ResultState == QrSessionState.Approved
                    ? BindingChallengeVector
                    : null,
                BindingChallengeExpiresAtUtc = ResultState == QrSessionState.Approved
                    ? now.AddMinutes(1)
                    : null,
                Error = Error,
            });
        }
    }

    private sealed class FakeSystemBrowser : IEnterpriseSystemBrowser
    {
        private readonly TaskCompletionSource _openObserved = new(
            TaskCreationOptions.RunContinuationsAsynchronously);

        public Task OpenObserved => _openObserved.Task;

        public Uri? OpenedUrl { get; private set; }

        public void Open(Uri authorizationUrl)
        {
            OpenedUrl = authorizationUrl;
            _openObserved.TrySetResult();
        }
    }

    private sealed record EnrollmentCoordinatorFixture(
        EnterpriseManagedPaths Paths,
        ManualTimeProvider TimeProvider,
        FakeEnterpriseHarnessHost Host,
        EnterpriseHarnessSession Session,
        EphemeralDeviceProofKeyStore DeviceKeys,
        FakeQrEnrollmentClient Client,
        FakeSystemBrowser Browser,
        EnterpriseQrEnrollmentCoordinator Coordinator);

    private sealed class InlineProgress<T>(Action<T> report) : IProgress<T>
    {
        public void Report(T value) => report(value);
    }

    private sealed record AuthorizationLeaseFixture(
        string CompactJws,
        string HeaderJson,
        string HeaderSegment,
        string PayloadJson,
        string KeyId,
        string PublicKeyX,
        string PublicKeyY,
        string PrivateKeyD,
        string LeaseId,
        string IssuerOrigin,
        string GatewayOrigin,
        string ArtifactOrigin,
        string BindingId,
        string InstallationId,
        string DeviceKeyThumbprint,
        DateTimeOffset EvaluationTimeUtc);
}
