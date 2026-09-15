using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using System.IO.Compression;
using Ensou.Dsh.Contracts;
using Ensou.Dsh.Launcher;
using Ensou.Dsh.Personal.ReleasePublisher;
using Ensou.Dsh.UpdateEngine;
using Publisher = Ensou.Dsh.Personal.ReleasePublisher.PersonalReleasePublisher;

namespace Ensou.Dsh.Personal.UpdateTests;

internal static class Program
{
    // Frozen predecessor whose real Publisher binary is also exercised by the
    // cross-version release gate: anchor lock, then schema-v1 admission, then
    // mutation. Keep the child probe fail-closed if that predecessor changes.
    private const string LegacyPublisherV1SourceCommit =
        "c2507cab5d74bb36d64d855a46bffbb66a521f6e";
    // Keep the fixed-duration fixtures aligned with production paths that intentionally
    // consult the system UTC clock during activation admission.
    private static readonly DateTimeOffset Now =
        DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
    private static readonly string TempRoot = Path.Combine(
        Path.GetTempPath(),
        "ensou-personal-update-tests",
        Guid.NewGuid().ToString("N"));

    public static async Task<int> Main(string[] args)
    {
        var automaticStageBoundaryOnly = args is ["--automatic-stage-boundary-tests"];
        var binarySelfCheckOnly = args is ["--personal-binary-self-check-tests"];
        var rejectedProcessOwnershipOnly = args is ["--personal-rejected-process-ownership-tests"];
        if (args.Length != 0
            && !automaticStageBoundaryOnly
            && !binarySelfCheckOnly
            && !rejectedProcessOwnershipOnly)
        {
            if (args is ["--legacy-v1-anchor-admission-probe", var configPath, var anchorPath, var mutationSentinel])
            {
                return RunLegacyV1AnchorAdmissionProbe(
                    configPath,
                    anchorPath,
                    mutationSentinel);
            }
            if (args[0] == DevelopmentE2EUpdateStageCommand.CommandName)
            {
                return await DevelopmentE2EUpdateStageCommand.RunAsync(args)
                    .ConfigureAwait(false);
            }
            if (args is ["--profile-module-junction-tests"])
            {
                return await PersonalHarnessProfileModuleJunctionTests.RunAsync()
                    .ConfigureAwait(false);
            }
            if (args is ["--executable-path-budget-tests"])
            {
                return await PersonalExecutablePathBudgetTests.RunAsync()
                    .ConfigureAwait(false);
            }
            if (args is ["--health-diagnostics-tests"])
            {
                return await HealthProbeDiagnosticsTests.RunAsync()
                    .ConfigureAwait(false);
            }
            if (args is ["--development-health-port-tests"])
            {
                await PersonalDevelopmentE2EHealthPortTests.RunAsync().ConfigureAwait(false);
                Console.WriteLine("PASS personal development health port isolation");
                return 0;
            }
            if (args is ["--managed-update-drain-tests"])
            {
                await PersonalManagedRuntimeUpdateCoordinatorTests.RunAsync()
                    .ConfigureAwait(false);
                Console.WriteLine("PASS personal managed update drain");
                return 0;
            }
            if (args is ["--personal-live-update-arguments-tests"])
            {
                return await PersonalDevelopmentLiveUpdateArgumentsTests.RunAsync()
                    .ConfigureAwait(false);
            }
            return await DevelopmentPayloadPublisherCommand.RunAsync(args)
                .ConfigureAwait(false);
        }

        Directory.CreateDirectory(TempRoot);
        var tests = new List<(string Name, Func<Task> Run)>
        {
            ("development health port is isolated and ignored in production", PersonalDevelopmentE2EHealthPortTests.RunAsync),
            ("personal binary self-check protocol is exact and consumed", BinarySelfCheckProtocolIsExactAndConsumedAsync),
            ("personal v2 signed round-trip", SignedRoundTripAsync),
            ("personal v2 rejects high-S signatures without state mutation", HighSSignaturesRejectedWithoutStateMutationAsync),
            ("personal v2 low-S cutover preserves only its audited legacy prefix", LowSCutoverIsSequenceBoundAsync),
            ("personal v2 rejects public-key aliases and keyId rewrites", PublicKeyAliasesAndKeyIdRewritesRejectedAsync),
            ("personal v2 strict JSON", StrictJsonAsync),
            ("personal v2 tamper rejection", TamperRejectedAsync),
            ("personal v2 identity and origin isolation", IdentityAndOriginIsolationAsync),
            ("personal v2 rejects unknown channel and untrusted key", ChannelAndKeyIsolationAsync),
            ("personal v2 exact component tuple", ExactComponentTupleAsync),
            ("personal v2 Startup Stub compatibility", StartupStubCompatibilityAsync),
            ("same-signer old Startup Stub replay is rejected before tuple launch", SameSignerOldStartupStubReplayRejectedAsync),
            ("personal v2 expiry and offline bound", ExpiryAndOfflineBoundAsync),
            ("personal state rejects replay and equivocation", ReplayAndEquivocationRejectedAsync),
            ("personal state enforces independent ordering floors", IndependentOrderingFloorsAsync),
            ("personal state rejects trusted-time rollback", TrustedTimeRollbackRejectedAsync),
            ("personal state preserves cumulative revocations", CumulativeRevocationPreservedAsync),
            ("installed personal release enforces signed closure state", InstalledReleaseClosureAsync),
            ("personal state persists failed-release quarantine", QuarantinePersistsAsync),
            ("personal state is DPAPI protected and authenticated", DpapiStateProtectionAsync),
            ("personal state detects rollback and deletion", StateRollbackAndDeletionRejectedAsync),
            ("authenticated state backfills an absent v2 migration footprint", AuthenticatedStateBackfillsMigrationFootprintAsync),
            ("personal layout rejects colocated update security witnesses", ColocatedSecurityWitnessRejectedAsync),
            ("persistent download completes and caches", PersistentDownloadCompletesAsync),
            ("persistent download resumes with Range and If-Range", RangeIfRangeResumeAsync),
            ("persistent download safely restarts when Range is ignored", RangeIgnoredRestartsAsync),
            ("persistent download rejects changed ETag on 206", ChangedEtagOnPartialRejectedAsync),
            ("persistent download without strong ETag restarts", MissingEtagRestartsAsync),
            ("persistent download rejects hash mismatch", DownloadHashMismatchAsync),
            ("persistent download rejects cross-origin redirects", CrossOriginRedirectRejectedAsync),
            ("metadata-only release reuses authenticated tuple with zero artifact GET", MetadataOnlyReuseUsesZeroArtifactGetAsync),
            ("launcher-only update commits without touching Harness home", LauncherOnlyUpdateNeverTouchesHarnessHomeAsync),
            ("runtime-reused no-home mode requires the new Startup Stub cutover", NoHomeStartupStubCutoverRequiredAsync),
            ("no-home pointer combinations fail closed without changing v3 reference JSON", NoHomePointerShapeFailsClosedAsync),
            ("no-home commit receipt is canonical single-link and health-token bound", NoHomeCommitReceiptIsStrictAsync),
            ("healthy full-home same-runtime ignores stale no-home receipt on restart", HealthyFullHomeSameRuntimeIsNotInferredAsNoHomeAsync),
            ("no-home commit crash window recovers without touching Harness home", NoHomeCommitCrashRecoveryNeverTouchesHomeAsync),
            ("one changed personal component downloads only that artifact", OneChangedComponentDownloadsOnceAsync),
            ("consecutive runtime and Launcher updates preserve local data and unchanged components", ConsecutiveComponentUpdatesPreserveLocalDataAsync),
            ("tampered authenticated reuse source fails before artifact GET", TamperedReuseFailsBeforeArtifactGetAsync),
            ("unreferenced installed residue never authorizes personal reuse", UnreferencedResidueDoesNotAuthorizeReuseAsync),
            ("personal downloaded target appearing after acquire fails closed", DownloadedTargetAfterAcquireFailsClosedAsync),
            ("personal publisher creates and self-verifies candidate", PublisherSelfVerificationAsync),
            ("personal publisher retries only an exact committed publication", PublisherExactRetryAndConflictsAsync),
            ("personal publisher binds every candidate to one locked file identity", PublisherCandidateIdentityIsLockedAsync),
            ("personal publisher never persists a pre-commit plaintext manifest", PublisherLeavesNoPreCommitPlaintextAsync),
            ("personal publisher rejects empty tree evidence", PublisherRejectsEmptyTreeAsync),
            ("personal publisher uses independent trust and certified Stub", PublisherTrustGateAsync),
            ("personal publisher config rejects duplicate and unknown fields", PublisherConfigStrictAsync),
            ("personal publisher signer ledger rejects rollback", PublisherSignerLedgerRejectsRollbackAsync),
            ("personal publisher ledger anchor requires explicit initialization", PublisherLedgerAnchorRequiresExplicitInitializationAsync),
            ("personal publisher ledger anchor rejects missing and empty resets", PublisherLedgerAnchorRejectsEmptyResetAsync),
            ("personal publisher ledger anchor rejects whole-root replay", PublisherLedgerAnchorRejectsReplayAsync),
            ("personal publisher config cannot redirect ledger anchor authority", PublisherLedgerAnchorAuthorityCannotBeRedirectedAsync),
            ("personal development publisher authority is isolated from a foreign ledger anchor", PublisherDevelopmentAuthorityIsolatedFromForeignAnchorAsync),
            ("personal publisher ledger anchor recovers authenticated crash windows", PublisherLedgerAnchorCrashRecoveryAsync),
            ("personal publisher schema-v2 anchor fences legacy mutation", PublisherSchemaV2FenceBlocksLegacyMutationAsync),
            ("personal publisher commit completion ignores late cancellation", PublisherCommitCompletionIgnoresLateCancellationAsync),
            ("personal publisher committed cleanup failure allows exact retry only", PublisherCommittedCleanupFailureAllowsExactRetryOnlyAsync),
            ("personal publisher publication conflict fails closed", PublisherPublicationConflictFailsClosedAsync),
            ("personal publisher upgrade check leaves legacy pending state untouched", PublisherUpgradeCheckLeavesLegacyPendingUntouchedAsync),
            ("personal publisher imports bounded PKCS8 without text secrets", PublisherPkcs8LoaderAsync),
            ("personal publisher rejects linked key and ledger ancestors", PublisherLinkedAncestorRejectedAsync),
            ("personal Authenticode verification locks executable identity", PersonalAuthenticodeLockAsync),
            ("personal trusted launch lease binds the real process image through mutation races", PersonalTrustedLaunchLeaseBindsProcessIdentityAsync),
            ("personal rejected process containment retains exact handles until proven exit", PersonalRejectedProcessContainmentRetainsExactHandlesAsync),
            ("personal external image admission contains the current process when prior containment blocks validation", PersonalExternalImageAdmissionContainsCurrentProcessAsync),
            ("personal trusted launch lease serializes concurrent admissions and disposal", PersonalTrustedLaunchLeaseSerializesConcurrentAdmissionsAsync),
            ("automatic stage boundary uses coordinated home rather than unrelated legacy writers", AutomaticStageBoundaryUsesCoordinatedHomeAsync),
            ("automatic stage boundary rejects same-home writers and occupied ports", AutomaticStageBoundaryRejectsConflictsAsync),
            ("automatic stage boundary retains strict first legacy enrollment", AutomaticStageBoundaryRetainsLegacyEnrollmentGuardAsync),
            ("whole Harness home transaction restores and commits", WholeHomeTransactionAsync),
            ("Harness home refuses an open foreign writer", ForeignWriterHandleRejectedAsync),
            ("Harness home move gap permits only an exactly restored tree", MoveGapExactRestoreAsync),
            ("Harness home move gap rejects a persistent writer", MoveGapPersistentWriterAsync),
            ("Harness home move gap rejects a created entry", () => MoveGapMutationRejectedAsync("create")),
            ("Harness home move gap rejects a deleted entry", () => MoveGapMutationRejectedAsync("delete")),
            ("Harness home move gap rejects a replaced entry", () => MoveGapMutationRejectedAsync("replace")),
            ("Harness home move gap rejects a reparse entry", MoveGapReparseRejectedAsync),
            ("two-component install commits through nonce health", ComponentTupleNonceHealthAsync),
            ("health signal rejects an incomplete Harness-home attempt", IncompleteHomeHealthAttemptRejectedAsync),
            ("health signal rejects a completed attempt for another home transaction", WrongHomeTransactionHealthAttemptRejectedAsync),
            ("failed nonce health restores home and quarantines release", FailedHealthRestoresHomeAsync),
            ("first v2 health failure starts legacy v1 tuple", FirstV2FailureStartsLegacyV1TupleAsync),
            ("legacy launch serializes with authenticated v2 transition", LegacyLaunchSerializesWithV2TransitionAsync),
            ("authenticated v2 state loss forbids signed legacy fallback", AuthenticatedV2StateLossForbidsLegacyFallbackAsync),
            ("residual v2 client bundle forbids legacy fallback without footprint", ResidualV2ClientBundleForbidsLegacyFallbackAsync),
            ("tampered v2 migration footprint fails closed", TamperedV2MigrationFootprintFailsClosedAsync),
            ("prepared home without pending pointer auto-restores", PreparedHomeWithoutPointerRestoresAsync),
            ("concurrent health gates consume one nonce", ConcurrentHealthGateAsync),
            ("installed tuple tamper is rejected by authenticated state", InstalledTupleTamperRejectedAsync),
            ("installed complete tree rejects noncritical tamper", InstalledTreeTamperRejectedAsync),
            ("activation admission rejects expired candidate", ExpiredActivationRejectedAsync),
            ("client bundle missing Maintenance is rejected", MissingMaintenanceRejectedAsync),
            ("component archive rejects files outside complete tree", UnexpectedArchiveFileRejectedAsync),
        };
        tests.AddRange(PersonalHarnessProfileModuleJunctionTests.Cases);
        tests.AddRange(PersonalExecutablePathBudgetTests.Cases);
        tests.AddRange(HealthProbeDiagnosticsTests.Cases);
        tests.AddRange(ConstructorCompatibilityTests.Cases);
        tests.AddRange(AtomicHomeCompatibilityTests.Cases);
        tests.AddRange(PersonalHealthBudgetTests.Cases);
        tests.AddRange(PersonalDevelopmentLiveUpdateArgumentsTests.NonConditionalCases);
        tests.AddRange(PersonalManagedRuntimeUpdateCoordinatorTests.Cases);

        if (rejectedProcessOwnershipOnly)
        {
            tests.Clear();
            tests.Add((
                "external rejected process containment preserves caller handle ownership",
                PersonalRejectedProcessContainmentRetainsExactHandlesAsync));
        }
        else if (automaticStageBoundaryOnly)
        {
            var selectedMethods = new HashSet<string>(StringComparer.Ordinal)
            {
                nameof(AutomaticStageBoundaryUsesCoordinatedHomeAsync),
                nameof(AutomaticStageBoundaryRejectsConflictsAsync),
                nameof(AutomaticStageBoundaryRetainsLegacyEnrollmentGuardAsync),
            };
            tests.RemoveAll(test => !selectedMethods.Contains(test.Run.Method.Name));
            if (tests.Count != selectedMethods.Count)
            {
                throw new InvalidOperationException("Automatic stage-boundary focused tests are incomplete.");
            }
        }
        else if (binarySelfCheckOnly)
        {
            tests.Clear();
            tests.Add((
                "configured personal runtime trust is marker-independent",
                ConfiguredBinarySelfCheckProtocolIsExactAndConsumedAsync));
        }

        var failures = 0;
        try
        {
            foreach (var test in tests)
            {
                try
                {
                    await test.Run().ConfigureAwait(false);
                    Console.WriteLine($"PASS {test.Name}");
                }
                catch (Exception exception)
                {
                    failures++;
                    Console.Error.WriteLine($"FAIL {test.Name}: {exception}");
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

        Console.WriteLine($"{tests.Count - failures}/{tests.Count} personal update tests passed.");
        return failures == 0 ? 0 : 1;
    }

    private static Task SignedRoundTripAsync()
    {
        using var fixture = new ManifestFixture();
        var manifest = fixture.CreateSigned();
        AssertCanonicalLowS(manifest.Signature!);
        foreach (var artifact in manifest.Artifacts)
        {
            AssertCanonicalLowS(artifact.Signature!);
        }
        var bytes = PersonalReleaseSetJson.SerializeSigned(manifest);
        var verified = PersonalReleaseSetValidator.ParseAndVerify(bytes, fixture.Policy, Now);
        AssertEqual("personal-set-v1", verified.Manifest.ReleaseSetId);
        AssertEqual(PersonalReleaseSetContract.ClientBundleComponent, verified.Manifest.ClientBundle.Component);
        AssertEqual(PersonalReleaseSetContract.RuntimeComponent, verified.Manifest.Runtime.Component);
        AssertTrue(PersonalReleaseSetValidator.IsSha256(verified.CanonicalSignedManifestSha256));
        AssertSequenceEqual(bytes, PersonalReleaseCanonicalJson.SignedManifest(verified.Manifest));
        return Task.CompletedTask;
    }

    private static async Task HighSSignaturesRejectedWithoutStateMutationAsync()
    {
        using var fixture = new ManifestFixture();
        var signed = fixture.CreateSigned();

        var highManifestSignature = signed with
        {
            Signature = CreateHighSSignature(signed.Signature!),
        };
        await AssertCanonicalLowSRejectionAsync(() => Task.Run(() =>
            PersonalReleaseSetValidator.Verify(highManifestSignature, fixture.Policy, Now)));

        var artifacts = signed.Artifacts.ToArray();
        artifacts[0] = artifacts[0] with
        {
            Signature = CreateHighSSignature(artifacts[0].Signature!),
        };
        var highArtifactSignature = signed with { Artifacts = artifacts };
        await AssertCanonicalLowSRejectionAsync(() => Task.Run(() =>
            PersonalReleaseSetValidator.Verify(highArtifactSignature, fixture.Policy, Now)));

        var root = NewTempPath("high-s-no-state", "root");
        var managed = Path.Combine(root, "managed");
        var independent = Path.Combine(root, "independent");
        var statePath = Path.Combine(managed, "state.dpapi");
        var witnessPath = Path.Combine(independent, "witness.dpapi");
        var store = new PersonalReleaseSecurityStateStore(
            statePath,
            StateIdentity(),
            witnessPath);
        var highManifestBytes = PersonalReleaseSetJson.SerializeSigned(highManifestSignature);
        await AssertCanonicalLowSRejectionAsync(() => store.VerifyAndAcceptAsync(
            highManifestBytes,
            fixture.Policy,
            Now));

        AssertFalse(File.Exists(statePath));
        AssertFalse(File.Exists(statePath + ".anchor"));
        AssertFalse(File.Exists(statePath + ".anchor.pending"));
        AssertFalse(File.Exists(witnessPath));
        AssertEqual(
            0,
            Directory.Exists(independent)
                ? Directory.GetFiles(independent, "*", SearchOption.AllDirectories).Length
                : 0);
    }

    private static Task BinarySelfCheckProtocolIsExactAndConsumedAsync() =>
        BinarySelfCheckProtocolIsExactAndConsumedAsync(requireConfiguredTrust: false);

    private static Task ConfiguredBinarySelfCheckProtocolIsExactAndConsumedAsync() =>
        BinarySelfCheckProtocolIsExactAndConsumedAsync(requireConfiguredTrust: true);

    private static Task BinarySelfCheckProtocolIsExactAndConsumedAsync(
        bool requireConfiguredTrust)
    {
        var name = PersonalBinarySelfCheck.ProtocolEnvironmentVariable;
        var entryAssembly = Assembly.GetEntryAssembly()
            ?? throw new InvalidOperationException("Test entry assembly is unavailable.");
        var processPath = Environment.ProcessPath
            ?? throw new InvalidOperationException("Test process path is unavailable.");
        var expectedExecutableName = Path.GetFileName(processPath);
        if (string.IsNullOrWhiteSpace(expectedExecutableName))
        {
            throw new InvalidOperationException("Test executable name is unavailable.");
        }
        var configuredTrust = true;
        try
        {
            _ = PersonalInstallerTrustConfiguration.ReadCompiled(entryAssembly);
            _ = PersonalInstallerTrustConfiguration.ReadCompiled(
                typeof(PersonalBinarySelfCheck).Assembly);
        }
        catch (InvalidOperationException)
        {
            configuredTrust = false;
        }
        if (requireConfiguredTrust && !configuredTrust)
        {
            throw new InvalidOperationException(
                "Focused personal binary self-check tests require the complete compiled development trust configuration.");
        }
        var previous = Environment.GetEnvironmentVariable(
            name,
            EnvironmentVariableTarget.Process);
        try
        {
            foreach (var invalid in new string?[]
                     {
                         null,
                         string.Empty,
                         "ensou-personal-binary-self-check/wrong",
                         PersonalBinarySelfCheck.ProtocolValue + "-extra",
                     })
            {
                Environment.SetEnvironmentVariable(
                    name,
                    invalid,
                    EnvironmentVariableTarget.Process);
                var failure = AssertThrowsAndReturn<InvalidDataException>(() =>
                    PersonalBinarySelfCheck.RequireCurrentProcessCompiledTrust(
                        "not-an-executable",
                        entryAssembly));
                AssertEqual(
                    "Personal binary self-check machine protocol is missing or invalid.",
                    failure.Message);
                AssertTrue(Environment.GetEnvironmentVariable(
                    name,
                    EnvironmentVariableTarget.Process) is null);
            }

            Environment.SetEnvironmentVariable(
                name,
                PersonalBinarySelfCheck.ProtocolValue,
                EnvironmentVariableTarget.Process);
            if (configuredTrust)
            {
                _ = PersonalBinarySelfCheck.RequireCurrentProcessCompiledTrust(
                    expectedExecutableName,
                    entryAssembly);
            }
            else
            {
                var unconfiguredSelfCheck = AssertThrowsAndReturn<InvalidOperationException>(() =>
                    PersonalBinarySelfCheck.RequireCurrentProcessCompiledTrust(
                        expectedExecutableName,
                        entryAssembly));
                AssertFalse(string.Equals(
                    unconfiguredSelfCheck.Message,
                    "Personal binary self-check machine protocol is missing or invalid.",
                    StringComparison.Ordinal));
            }
            AssertTrue(Environment.GetEnvironmentVariable(
                name,
                EnvironmentVariableTarget.Process) is null);
            var reusedProtocolFailure = AssertThrowsAndReturn<InvalidDataException>(() =>
                PersonalBinarySelfCheck.RequireCurrentProcessCompiledTrust(
                    expectedExecutableName,
                    entryAssembly));
            AssertEqual(
                "Personal binary self-check machine protocol is missing or invalid.",
                reusedProtocolFailure.Message);

            if (configuredTrust)
            {
                _ = PersonalBinarySelfCheck.RequireCurrentRuntimeProcessCompiledTrust(
                    expectedExecutableName,
                    entryAssembly);
            }
            else
            {
                AssertThrows<InvalidOperationException>(() =>
                    PersonalBinarySelfCheck.RequireCurrentRuntimeProcessCompiledTrust(
                        expectedExecutableName,
                        entryAssembly));
            }
            AssertTrue(Environment.GetEnvironmentVariable(
                name,
                EnvironmentVariableTarget.Process) is null);

            const string untouchedMarker = "ordinary-runtime-trust-must-not-consume-this";
            Environment.SetEnvironmentVariable(
                name,
                untouchedMarker,
                EnvironmentVariableTarget.Process);
            if (configuredTrust)
            {
                _ = PersonalBinarySelfCheck.RequireCurrentRuntimeProcessCompiledTrust(
                    expectedExecutableName,
                    entryAssembly);
            }
            else
            {
                AssertThrows<InvalidOperationException>(() =>
                    PersonalBinarySelfCheck.RequireCurrentRuntimeProcessCompiledTrust(
                        expectedExecutableName,
                        entryAssembly));
            }
            AssertEqual(
                untouchedMarker,
                Environment.GetEnvironmentVariable(
                    name,
                    EnvironmentVariableTarget.Process));

            AssertThrows<InvalidDataException>(() =>
                PersonalBinarySelfCheck.RequireCurrentRuntimeProcessCompiledTrust(
                    "not-an-executable",
                    entryAssembly));
            AssertEqual(
                untouchedMarker,
                Environment.GetEnvironmentVariable(
                    name,
                    EnvironmentVariableTarget.Process));

            AssertThrows<InvalidDataException>(() =>
                PersonalBinarySelfCheck.RequireCurrentRuntimeProcessCompiledTrust(
                    expectedExecutableName,
                    typeof(PersonalBinarySelfCheck).Assembly));
            AssertEqual(
                untouchedMarker,
                Environment.GetEnvironmentVariable(
                    name,
                    EnvironmentVariableTarget.Process));

            if (configuredTrust)
            {
                var engineTrust = PersonalInstallerTrustConfiguration.ReadCompiled(
                    typeof(PersonalBinarySelfCheck).Assembly);
                var mismatchedTrust = engineTrust with
                {
                    ManifestOrigin = new Uri("https://mismatch.example.invalid/"),
                };
                AssertThrows<InvalidOperationException>(() =>
                    PersonalAuthenticodeVerifier.RequireMatchingCompiledTrustForTests(
                        mismatchedTrust,
                        engineTrust));
            }
        }
        finally
        {
            Environment.SetEnvironmentVariable(
                name,
                previous,
                EnvironmentVariableTarget.Process);
        }
        return Task.CompletedTask;
    }

    private static Task LowSCutoverIsSequenceBoundAsync()
    {
        using var fixture = new ManifestFixture();
        var signed = fixture.CreateSigned();
        var legacyHighS = signed with
        {
            Signature = CreateHighSSignature(signed.Signature!),
        };
        var auditedLegacyPolicy = fixture.Policy with
        {
            CanonicalLowSFromSequence = checked(signed.Sequence + 1),
        };

        PersonalReleaseSetValidator.Verify(legacyHighS, auditedLegacyPolicy, Now);
        AssertThrows<InvalidDataException>(() =>
            PersonalReleaseSetValidator.Verify(legacyHighS, fixture.Policy, Now));
        AssertThrows<InvalidDataException>(() =>
            (fixture.Policy with { CanonicalLowSFromSequence = 0 }).Validate());
        AssertThrows<InvalidDataException>(() =>
            (fixture.Policy with
            {
                CanonicalLowSFromSequence =
                    PersonalReleaseSetContract.MaximumSafeInteger + 1,
            }).Validate());
        return Task.CompletedTask;
    }

    private static Task PublicKeyAliasesAndKeyIdRewritesRejectedAsync()
    {
        using var fixture = new ManifestFixture();
        var signed = fixture.CreateSigned();
        var original = fixture.Policy.TrustedKeys.Single();
        var alias = original with { KeyId = "personal-release-alias" };
        var duplicatePointPolicy = fixture.Policy with
        {
            TrustedKeys = [original, alias],
        };
        AssertThrows<InvalidDataException>(() => duplicatePointPolicy.Validate());

        using var unrelatedKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var unrelated = PersonalReleaseSetSigner.ExportPublicKey(
            alias.KeyId,
            unrelatedKey);
        var distinctPointPolicy = fixture.Policy with
        {
            TrustedKeys = [original, unrelated],
        };
        distinctPointPolicy.Validate();
        var rewritten = signed with
        {
            Signature = signed.Signature! with { KeyId = unrelated.KeyId },
        };
        AssertThrows<InvalidDataException>(() =>
            PersonalReleaseSetValidator.Verify(rewritten, distinctPointPolicy, Now));
        return Task.CompletedTask;
    }

    private static async Task StrictJsonAsync()
    {
        using var fixture = new ManifestFixture();
        var manifest = fixture.CreateSigned();
        var json = Encoding.UTF8.GetString(
            PersonalReleaseSetJson.SerializeSigned(manifest));
        var duplicate = Encoding.UTF8.GetBytes(json.Replace(
            "\"schemaVersion\":2",
            "\"schemaVersion\":2,\"schemaVersion\":2",
            StringComparison.Ordinal));
        await AssertThrowsAsync<InvalidDataException>(() => Task.Run(() =>
            PersonalReleaseSetValidator.ParseAndVerify(duplicate, fixture.Policy, Now)));

        var unknown = Encoding.UTF8.GetBytes(json[..^1] + ",\"unknown\":true}");
        await AssertThrowsAsync<InvalidDataException>(() => Task.Run(() =>
            PersonalReleaseSetValidator.ParseAndVerify(unknown, fixture.Policy, Now)));

        const string issuedAtPrefix = "\"issuedAtUtc\":\"";
        var timestampStart = json.IndexOf(issuedAtPrefix, StringComparison.Ordinal)
            + issuedAtPrefix.Length;
        var timestampEnd = json.IndexOf('"', timestampStart);
        var canonicalTimestamp = json[timestampStart..timestampEnd];
        var shortTimestampText = canonicalTimestamp.Replace(".0000000Z", "Z", StringComparison.Ordinal);
        AssertFalse(string.Equals(canonicalTimestamp, shortTimestampText, StringComparison.Ordinal));
        var shortTimestamp = Encoding.UTF8.GetBytes(json.Replace(
            canonicalTimestamp,
            shortTimestampText,
            StringComparison.Ordinal));
        await AssertThrowsAsync<InvalidDataException>(() => Task.Run(() =>
            PersonalReleaseSetValidator.ParseAndVerify(shortTimestamp, fixture.Policy, Now)));
    }

    private static async Task TamperRejectedAsync()
    {
        using var fixture = new ManifestFixture();
        var json = Encoding.UTF8.GetString(
            PersonalReleaseSetJson.SerializeSigned(fixture.CreateSigned()));
        var tamperedSequence = Encoding.UTF8.GetBytes(json.Replace(
            "\"sequence\":1",
            "\"sequence\":2",
            StringComparison.Ordinal));
        await AssertThrowsAsync<InvalidDataException>(() => Task.Run(() =>
            PersonalReleaseSetValidator.ParseAndVerify(tamperedSequence, fixture.Policy, Now)));

        var tamperedArtifact = Encoding.UTF8.GetBytes(json.Replace(
            new string('1', 64),
            new string('9', 64),
            StringComparison.Ordinal));
        await AssertThrowsAsync<InvalidDataException>(() => Task.Run(() =>
            PersonalReleaseSetValidator.ParseAndVerify(tamperedArtifact, fixture.Policy, Now)));
    }

    private static async Task IdentityAndOriginIsolationAsync()
    {
        using var fixture = new ManifestFixture();
        var crossProduct = fixture.CreateSigned(product: "ensou-dsh-enterprise");
        await AssertThrowsAsync<InvalidDataException>(() => Task.Run(() =>
            PersonalReleaseSetValidator.Verify(crossProduct, fixture.Policy, Now)));

        var crossChannel = fixture.CreateSigned(channel: "pilot");
        await AssertThrowsAsync<InvalidDataException>(() => Task.Run(() =>
            PersonalReleaseSetValidator.Verify(crossChannel, fixture.Policy, Now)));

        var crossOrigin = fixture.CreateSigned(artifactOrigin: "https://evil.example.test/");
        await AssertThrowsAsync<InvalidDataException>(() => Task.Run(() =>
            PersonalReleaseSetValidator.Verify(crossOrigin, fixture.Policy, Now)));
    }

    private static async Task ChannelAndKeyIsolationAsync()
    {
        using var fixture = new ManifestFixture();
        var unknownChannel = fixture.CreateSigned(channel: "preview");
        var unknownChannelPolicy = fixture.Policy with { Channel = "preview" };
        await AssertThrowsAsync<InvalidDataException>(() => Task.Run(() =>
            PersonalReleaseSetValidator.Verify(unknownChannel, unknownChannelPolicy, Now)));

        using var otherSigner = new ManifestFixture();
        var untrusted = otherSigner.CreateSigned();
        await AssertThrowsAsync<InvalidDataException>(() => Task.Run(() =>
            PersonalReleaseSetValidator.Verify(untrusted, fixture.Policy, Now)));
    }

    private static async Task ExactComponentTupleAsync()
    {
        using var fixture = new ManifestFixture();
        var reversed = fixture.CreateSigned(reverseArtifacts: true);
        await AssertThrowsAsync<InvalidDataException>(() => Task.Run(() =>
            PersonalReleaseSetValidator.Verify(reversed, fixture.Policy, Now)));

        var duplicate = fixture.CreateSigned(duplicateClientBundle: true);
        await AssertThrowsAsync<InvalidDataException>(() => Task.Run(() =>
            PersonalReleaseSetValidator.Verify(duplicate, fixture.Policy, Now)));
    }

    private static async Task StartupStubCompatibilityAsync()
    {
        using var fixture = new ManifestFixture();
        var manifest = fixture.CreateSigned(minimumStub: "2.0.0", maximumStub: "3.0.0");
        await AssertThrowsAsync<InvalidDataException>(() => Task.Run(() =>
            PersonalReleaseSetValidator.Verify(manifest, fixture.Policy, Now)));

        var invalidRange = fixture.CreateSigned(minimumStub: "2.0.0", maximumStub: "1.0.0");
        await AssertThrowsAsync<InvalidDataException>(() => Task.Run(() =>
            PersonalReleaseSetValidator.Verify(invalidRange, fixture.Policy, Now)));
    }

    private static async Task SameSignerOldStartupStubReplayRejectedAsync()
    {
        using var fixture = new ManifestFixture(startupStubVersion: "2.0.0");
        var install = CreateInstallFixture(
            "same-signer-old-stub-replay",
            fixture,
            minimumStub: "2.0.0",
            maximumStub: "2.0.0");
        var security = new PersonalReleaseSecurityStateStore(
            install.Layout.UpdateSecurityStatePath,
            StateIdentity(),
            install.Layout.UpdateSecurityWitnessPath);
        var accepted = await security.VerifyAndAcceptAsync(
            install.ManifestBytes,
            fixture.Policy,
            Now);
        var installer = NewTestArtifactInstaller();
        await installer.InstallComponentAsync(
            install.Layout,
            accepted.Verified.Manifest.ClientBundle,
            install.ClientArchivePath,
            install.Layout.GetClientBundleDirectory(
                accepted.Verified.Manifest.ClientBundle.ReleaseId));
        await installer.InstallComponentAsync(
            install.Layout,
            accepted.Verified.Manifest.Runtime,
            install.RuntimeArchivePath,
            install.Layout.GetRuntimeDirectory(
                accepted.Verified.Manifest.Runtime.ReleaseId));
        var pointer = new PersonalReleaseSetPointerStore(install.Layout).ActivatePending(
            accepted.Verified,
            Guid.NewGuid().ToString("N"));

        AssertEqual("2.0.0", pointer.Current.StartupStub.MinimumVersion);
        AssertEqual("2.0.0", pointer.Current.StartupStub.MaximumVersion);
        var persisted = await security.TryReadAsync();
        var receipt = persisted!.AcceptedReleases.Single(release =>
            string.Equals(
                release.ReleaseSetId,
                pointer.Current.ReleaseSetId,
                StringComparison.Ordinal));
        AssertEqual("2.0.0", receipt.StartupStub.MinimumVersion);
        AssertEqual("2.0.0", receipt.StartupStub.MaximumVersion);

        var pointerWithLocallyRewrittenRange = pointer with
        {
            Current = pointer.Current with
            {
                StartupStub = new PersonalStartupStubCompatibility
                {
                    MinimumVersion = "1.0.0",
                    MaximumVersion = "2.0.0",
                },
            },
        };
        await AssertThrowsAsync<InvalidDataException>(() =>
            security.ValidateInstalledPointerForStartupStubAsync(
                pointerWithLocallyRewrittenRange,
                "1.0.0",
                Now));

        // The same release signer is still trusted. Only the signed protocol
        // range prevents a replayed 1.0.0 stable Stub from starting this tuple.
        await AssertThrowsAsync<InvalidDataException>(() =>
            security.ValidateInstalledPointerForStartupStubAsync(
                pointer,
                "1.0.0",
                Now));
        var current = await security.ValidateInstalledPointerForStartupStubAsync(
            pointer,
            "2.0.0",
            Now);
        AssertTrue(current.Allowed);
    }

    private static async Task ExpiryAndOfflineBoundAsync()
    {
        using var fixture = new ManifestFixture();
        var expired = fixture.CreateSigned(expiresAtUtc: Now.AddMinutes(-3));
        await AssertThrowsAsync<InvalidDataException>(() => Task.Run(() =>
            PersonalReleaseSetValidator.Verify(expired, fixture.Policy, Now)));

        var excessiveGrace = fixture.CreateSigned(maximumOfflineGraceSeconds: 8 * 24 * 60 * 60);
        await AssertThrowsAsync<InvalidDataException>(() => Task.Run(() =>
            PersonalReleaseSetValidator.Verify(excessiveGrace, fixture.Policy, Now)));
    }

    private static async Task ReplayAndEquivocationRejectedAsync()
    {
        using var fixture = new ManifestFixture();
        var store = NewStore("replay");
        var first = fixture.Serialize(generation: 2, sequence: 2, releaseSetId: "personal-set-v2");
        await store.VerifyAndAcceptAsync(first, fixture.Policy, Now);

        var replay = fixture.Serialize(generation: 1, sequence: 1, releaseSetId: "personal-set-v1");
        await AssertThrowsAsync<InvalidDataException>(() =>
            store.VerifyAndAcceptAsync(replay, fixture.Policy, Now));

        var equivocation = fixture.Serialize(
            generation: 2,
            sequence: 2,
            releaseSetId: "personal-set-v2-other");
        await AssertThrowsAsync<InvalidDataException>(() =>
            store.VerifyAndAcceptAsync(equivocation, fixture.Policy, Now));
    }

    private static async Task IndependentOrderingFloorsAsync()
    {
        using var fixture = new ManifestFixture();
        var store = NewStore("independent-floors");
        await store.VerifyAndAcceptAsync(
            fixture.Serialize(
                generation: 2,
                sequence: 2,
                minAcceptedSequence: 2,
                releaseSetId: "personal-set-v2"),
            fixture.Policy,
            Now);

        await AssertThrowsAsync<InvalidDataException>(() => store.VerifyAndAcceptAsync(
            fixture.Serialize(
                generation: 1,
                sequence: 3,
                minAcceptedSequence: 2,
                releaseSetId: "personal-set-generation-rollback"),
            fixture.Policy,
            Now));
        await AssertThrowsAsync<InvalidDataException>(() => store.VerifyAndAcceptAsync(
            fixture.Serialize(
                generation: 3,
                sequence: 2,
                minAcceptedSequence: 2,
                releaseSetId: "personal-set-sequence-reuse"),
            fixture.Policy,
            Now));
        await AssertThrowsAsync<InvalidDataException>(() => store.VerifyAndAcceptAsync(
            fixture.Serialize(
                generation: 3,
                sequence: 3,
                minAcceptedSequence: 1,
                releaseSetId: "personal-set-minimum-rollback"),
            fixture.Policy,
            Now));
    }

    private static async Task TrustedTimeRollbackRejectedAsync()
    {
        using var fixture = new ManifestFixture();
        var store = NewStore("trusted-time");
        await store.VerifyAndAcceptAsync(
            fixture.Serialize(
                generation: 1,
                sequence: 1,
                issuedAtUtc: Now.AddMinutes(-1),
                expiresAtUtc: Now.AddDays(10)),
            fixture.Policy,
            Now);
        await store.VerifyAndAcceptAsync(
            fixture.Serialize(
                generation: 2,
                sequence: 2,
                releaseSetId: "personal-set-v2",
                issuedAtUtc: Now.AddDays(5).AddMinutes(-1),
                expiresAtUtc: Now.AddDays(10)),
            fixture.Policy,
            Now.AddDays(5));

        var staleAfterClockRollback = fixture.Serialize(
            generation: 3,
            sequence: 3,
            releaseSetId: "personal-set-v3",
            issuedAtUtc: Now.AddMinutes(-1),
            expiresAtUtc: Now.AddDays(1));
        await AssertThrowsAsync<InvalidDataException>(() =>
            store.VerifyAndAcceptAsync(staleAfterClockRollback, fixture.Policy, Now));
    }

    private static async Task CumulativeRevocationPreservedAsync()
    {
        using var fixture = new ManifestFixture();
        var store = NewStore("revocations");
        await store.VerifyAndAcceptAsync(
            fixture.Serialize(revocations: ["personal-set-old"]),
            fixture.Policy,
            Now);
        var removal = fixture.Serialize(
            generation: 2,
            sequence: 2,
            releaseSetId: "personal-set-v2",
            revocations: []);
        await AssertThrowsAsync<InvalidDataException>(() =>
            store.VerifyAndAcceptAsync(removal, fixture.Policy, Now));
    }

    private static async Task InstalledReleaseClosureAsync()
    {
        using var fixture = new ManifestFixture();
        var store = NewStore("installed-release-closure");
        await store.VerifyAndAcceptAsync(
            fixture.Serialize(
                generation: 2,
                sequence: 2,
                minAcceptedSequence: 2,
                releaseSetId: "personal-set-v2",
                expiresAtUtc: Now.AddDays(1),
                revocations: ["personal-set-old"]),
            fixture.Policy,
            Now);

        var belowFloor = await store.EvaluateInstalledReleaseAsync(
            "personal-set-v1",
            1,
            Now);
        AssertFalse(belowFloor.Allowed);

        var revoked = await store.EvaluateInstalledReleaseAsync(
            "personal-set-old",
            2,
            Now);
        AssertFalse(revoked.Allowed);

        var current = await store.EvaluateInstalledReleaseAsync(
            "personal-set-v2",
            2,
            Now);
        AssertTrue(current.Allowed);
        AssertEqual(Now.AddDays(7), current.OfflineDeadlineUtc);

        var offlineExpired = await store.EvaluateInstalledReleaseAsync(
            "personal-set-v2",
            2,
            Now.AddDays(8));
        AssertFalse(offlineExpired.Allowed);
    }

    private static async Task QuarantinePersistsAsync()
    {
        using var fixture = new ManifestFixture();
        var store = NewStore("quarantine");
        var accepted = await store.VerifyAndAcceptAsync(
            fixture.Serialize(),
            fixture.Policy,
            Now);
        var trustedBeforeFailure = accepted.State.TrustedTimeUtc;
        await store.RecordFailureAsync(
            accepted.Verified,
            "RUNTIME_HEALTH_FAILED",
            Now.AddYears(50));
        var restored = await store.TryReadAsync();
        AssertEqual(trustedBeforeFailure, restored!.TrustedTimeUtc);
        AssertEqual(1, restored.FailedReleaseQuarantine.Count);
        AssertEqual("personal-set-v1", restored.FailedReleaseQuarantine[0].ReleaseSetId);
        await AssertThrowsAsync<InvalidDataException>(() => store.VerifyAndAcceptAsync(
            fixture.Serialize(),
            fixture.Policy,
            Now));
    }

    private static async Task StateRollbackAndDeletionRejectedAsync()
    {
        using var fixture = new ManifestFixture();
        var statePath = NewTempPath("state-rollback", "state.dpapi");
        var store = new PersonalReleaseSecurityStateStore(
            statePath,
            StateIdentity(),
            NewTempPath("state-rollback-witness", "witness.dpapi"));
        await store.VerifyAndAcceptAsync(fixture.Serialize(), fixture.Policy, Now);
        var oldState = await File.ReadAllBytesAsync(statePath);
        var oldAnchor = await File.ReadAllBytesAsync(statePath + ".anchor");
        await store.VerifyAndAcceptAsync(
            fixture.Serialize(
                generation: 2,
                sequence: 2,
                releaseSetId: "personal-set-v2"),
            fixture.Policy,
            Now);
        await File.WriteAllBytesAsync(statePath, oldState);
        await File.WriteAllBytesAsync(statePath + ".anchor", oldAnchor);
        await AssertThrowsAsync<InvalidDataException>(() => store.TryReadAsync());

        var deletedPath = NewTempPath("state-deletion", "state.dpapi");
        var deletedStore = new PersonalReleaseSecurityStateStore(
            deletedPath,
            StateIdentity(),
            NewTempPath("state-deletion-witness", "witness.dpapi"));
        await deletedStore.VerifyAndAcceptAsync(fixture.Serialize(), fixture.Policy, Now);
        File.Delete(deletedPath);
        File.Delete(deletedPath + ".anchor");
        await AssertThrowsAsync<InvalidDataException>(() => deletedStore.TryReadAsync());
    }

    private static async Task DpapiStateProtectionAsync()
    {
        using var fixture = new ManifestFixture();
        var statePath = NewTempPath("dpapi", "state.dpapi");
        var store = new PersonalReleaseSecurityStateStore(
            statePath,
            StateIdentity(),
            NewTempPath("dpapi-witness", "witness.dpapi"));
        await store.VerifyAndAcceptAsync(fixture.Serialize(), fixture.Policy, Now);
        var protectedBytes = await File.ReadAllBytesAsync(statePath);
        AssertFalse(Encoding.UTF8.GetString(protectedBytes).Contains(
            "personal-set-v1",
            StringComparison.Ordinal));

        protectedBytes[protectedBytes.Length / 2] ^= 0x55;
        await File.WriteAllBytesAsync(statePath, protectedBytes);
        await AssertThrowsAsync<InvalidDataException>(() => store.TryReadAsync());
    }

    private static async Task AuthenticatedStateBackfillsMigrationFootprintAsync()
    {
        using var fixture = new ManifestFixture();
        var install = CreateInstallFixture("migration-footprint-backfill", fixture);
        var security = new PersonalReleaseSecurityStateStore(
            install.Layout.UpdateSecurityStatePath,
            StateIdentity(),
            install.Layout.UpdateSecurityWitnessPath);
        _ = await security.VerifyAndAcceptAsync(
            install.ManifestBytes,
            fixture.Policy,
            Now);
        File.Delete(install.Layout.V2MigrationFootprintPath);

        var restored = await security.TryReadAsync();
        AssertTrue(restored is not null);
        AssertTrue(File.Exists(install.Layout.V2MigrationFootprintPath));
    }

    private static Task ColocatedSecurityWitnessRejectedAsync()
    {
        var root = NewTempPath("colocated-security-witness", "root");
        Directory.CreateDirectory(root);
        var managed = Path.Combine(root, "managed");
        var home = Path.Combine(root, "home");
        AssertThrows<InvalidDataException>(() => new PersonalInstallationLayout(
            managed,
            home,
            Path.Combine(managed, "state", "witness.dpapi")));
        AssertThrows<InvalidDataException>(() => new PersonalInstallationLayout(
            managed,
            home,
            Path.Combine(home, "witness.dpapi")));
        return Task.CompletedTask;
    }

    private static async Task PersistentDownloadCompletesAsync()
    {
        var payload = Encoding.UTF8.GetBytes("complete persistent payload");
        using var client = new HttpClient(new DelegateHandler((request, _) =>
        {
            AssertEqual<HttpMethod>(HttpMethod.Get, request.Method);
            AssertTrue(request.Headers.Range is null);
            return FullResponse(payload, "\"complete-v1\"");
        }));
        var cache = NewTempPath("download-complete", "cache");
        var downloader = new PersistentPartialDownloader(client);
        var request = DownloadRequest(payload, cache);
        var result = await downloader.DownloadAsync(request);
        AssertEqual(PersistentDownloadStatus.Downloaded, result.Status);
        var installed = await File.ReadAllBytesAsync(result.ArtifactPath);
        AssertSequenceEqual(payload, installed);

        var cached = await downloader.DownloadAsync(request);
        AssertEqual(PersistentDownloadStatus.AlreadyComplete, cached.Status);
    }

    private static async Task RangeIfRangeResumeAsync()
    {
        var payload = Encoding.UTF8.GetBytes("resume with a strong entity tag");
        using var client = new HttpClient(new DelegateHandler((request, call) =>
        {
            if (call == 1)
            {
                AssertTrue(request.Headers.Range is null);
                return ShortResponse(payload[..7], payload.Length, "\"resume-v1\"");
            }
            var range = request.Headers.Range?.Ranges.Single()
                ?? throw new InvalidOperationException("Expected Range on resume.");
            AssertEqual(7L, range.From);
            AssertEqual("\"resume-v1\"", request.Headers.IfRange?.EntityTag?.ToString());
            return PartialResponse(payload[7..], 7, payload.Length, "\"resume-v1\"");
        }));
        var downloader = new PersistentPartialDownloader(client);
        var request = DownloadRequest(payload, NewTempPath("download-resume", "cache"));
        await AssertThrowsAsync<EndOfStreamException>(() => downloader.DownloadAsync(request));
        var result = await downloader.DownloadAsync(request);
        AssertEqual(PersistentDownloadStatus.Resumed, result.Status);
        var installed = await File.ReadAllBytesAsync(result.ArtifactPath);
        AssertSequenceEqual(payload, installed);
    }

    private static async Task RangeIgnoredRestartsAsync()
    {
        var payload = Encoding.UTF8.GetBytes("server ignored range safely");
        using var client = new HttpClient(new DelegateHandler((request, call) =>
        {
            if (call == 1)
            {
                return ShortResponse(payload[..5], payload.Length, "\"old-etag\"");
            }
            AssertTrue(request.Headers.Range is not null);
            AssertEqual("\"old-etag\"", request.Headers.IfRange?.EntityTag?.ToString());
            return FullResponse(payload, "\"new-etag\"");
        }));
        var downloader = new PersistentPartialDownloader(client);
        var request = DownloadRequest(payload, NewTempPath("download-range-ignored", "cache"));
        await AssertThrowsAsync<EndOfStreamException>(() => downloader.DownloadAsync(request));
        var result = await downloader.DownloadAsync(request);
        AssertEqual(PersistentDownloadStatus.Downloaded, result.Status);
        var installed = await File.ReadAllBytesAsync(result.ArtifactPath);
        AssertSequenceEqual(payload, installed);
    }

    private static async Task ChangedEtagOnPartialRejectedAsync()
    {
        var payload = Encoding.UTF8.GetBytes("changed etag must not append");
        using var client = new HttpClient(new DelegateHandler((request, call) =>
        {
            if (call == 1)
            {
                return ShortResponse(payload[..6], payload.Length, "\"etag-v1\"");
            }
            AssertTrue(request.Headers.Range is not null);
            return PartialResponse(payload[6..], 6, payload.Length, "\"etag-v2\"");
        }));
        var cache = NewTempPath("download-etag-change", "cache");
        var request = DownloadRequest(payload, cache);
        var downloader = new PersistentPartialDownloader(client);
        await AssertThrowsAsync<EndOfStreamException>(() => downloader.DownloadAsync(request));
        await AssertThrowsAsync<InvalidDataException>(() => downloader.DownloadAsync(request));
        AssertFalse(File.Exists(Path.Combine(cache, request.ExpectedSha256 + ".partial")));
        AssertFalse(File.Exists(Path.Combine(cache, request.ExpectedSha256 + ".partial.json")));
    }

    private static async Task MissingEtagRestartsAsync()
    {
        var payload = Encoding.UTF8.GetBytes("no etag cannot safely resume");
        using var client = new HttpClient(new DelegateHandler((request, call) =>
        {
            AssertTrue(request.Headers.Range is null);
            return call == 1
                ? ShortResponse(payload[..4], payload.Length, null)
                : FullResponse(payload, "\"etag-now-present\"");
        }));
        var downloader = new PersistentPartialDownloader(client);
        var request = DownloadRequest(payload, NewTempPath("download-no-etag", "cache"));
        await AssertThrowsAsync<EndOfStreamException>(() => downloader.DownloadAsync(request));
        var result = await downloader.DownloadAsync(request);
        AssertEqual(PersistentDownloadStatus.Downloaded, result.Status);
    }

    private static async Task DownloadHashMismatchAsync()
    {
        var expected = Encoding.UTF8.GetBytes("expected bytes");
        var wrong = Encoding.UTF8.GetBytes("rejected bytes");
        AssertEqual(expected.Length, wrong.Length);
        using var client = new HttpClient(new DelegateHandler((_, _) =>
            FullResponse(wrong, "\"wrong-v1\"")));
        var cache = NewTempPath("download-hash", "cache");
        var request = DownloadRequest(expected, cache);
        await AssertThrowsAsync<InvalidDataException>(() =>
            new PersistentPartialDownloader(client).DownloadAsync(request));
        AssertFalse(File.Exists(Path.Combine(cache, request.ExpectedSha256 + ".complete")));
        AssertFalse(File.Exists(Path.Combine(cache, request.ExpectedSha256 + ".partial")));
    }

    private static async Task CrossOriginRedirectRejectedAsync()
    {
        var payload = Encoding.UTF8.GetBytes("signed bytes from forbidden origin");
        using var client = new HttpClient(new DelegateHandler((_, _) =>
        {
            var response = FullResponse(payload, "\"redirected\"");
            response.RequestMessage = new HttpRequestMessage(
                HttpMethod.Get,
                "https://github.example.test/releases/runtime.zip");
            return response;
        }));
        var request = DownloadRequest(payload, NewTempPath("download-redirect", "cache"));
        await AssertThrowsAsync<InvalidDataException>(() =>
            new PersistentPartialDownloader(client).DownloadAsync(request));
    }

    private static async Task MetadataOnlyReuseUsesZeroArtifactGetAsync()
    {
        using var fixture = new ManifestFixture("1.1.0");
        var pending = await CreateHealthyInstallAsync("reuse-metadata-only", fixture);
        var current = PersonalReleaseSetValidator.ParseAndVerify(
            pending.Install.ManifestBytes,
            fixture.Policy,
            Now).Manifest;
        var accepted = await AcceptFollowupAsync(
            pending,
            fixture,
            "personal-reuse-metadata-v2",
            current.Artifacts,
            minimumStartupStubVersion: "1.1.0");
        var requests = 0;
        using var client = new HttpClient(new DelegateHandler((request, _) =>
        {
            requests++;
            return new HttpResponseMessage(HttpStatusCode.NotFound)
            {
                RequestMessage = request,
            };
        }));

        var acquired = await new PersonalReleaseArtifactAcquisitionService(
            pending.Install.Layout,
            client,
            new FixedTimeProvider(Now)).AcquireAsync(accepted.Verified);

        AssertEqual(0, requests);
        AssertTrue(acquired.ClientBundle.ReusedComponent is not null);
        AssertTrue(acquired.Runtime.ReusedComponent is not null);
        AssertTrue(acquired.ClientBundle.ArchivePath is null);
        AssertTrue(acquired.Runtime.ArchivePath is null);
        var installed = await NewTestArtifactInstaller()
            .InstallAcquiredReleaseSetAsync(
                pending.Install.Layout,
                accepted.Verified,
                acquired,
                GetFreePort());
        AssertEqual(12L, installed.Pointer.Current.Sequence);
        AssertEqual(
            pending.Result.Pointer.Current.ClientBundle.Directory,
            installed.Pointer.Current.ClientBundle.Directory);
        AssertEqual(
            pending.Result.Pointer.Current.Runtime.Directory,
            installed.Pointer.Current.Runtime.Directory);
    }

    private static async Task LauncherOnlyUpdateNeverTouchesHarnessHomeAsync()
    {
        using var fixture = new ManifestFixture("1.1.0");
        var pending = await CreateHealthyInstallAsync("launcher-only-no-home", fixture);
        var current = PersonalReleaseSetValidator.ParseAndVerify(
            pending.Install.ManifestBytes,
            fixture.Policy,
            Now).Manifest;
        var root = Path.GetDirectoryName(pending.Install.Layout.ManagedRoot)!;
        var client = CreateComponentArchive(
            root,
            PersonalReleaseSetContract.ClientBundleComponent,
            "client-launcher-only-v2",
            new Dictionary<string, byte[]>(StringComparer.Ordinal)
            {
                [PersonalInstallationLayout.ClientBootstrapperExecutableName] =
                    Encoding.UTF8.GetBytes("client bootstrapper v2"),
                [PersonalInstallationLayout.LauncherExecutableName] =
                    Encoding.UTF8.GetBytes("launcher v2"),
                [PersonalInstallationLayout.MaintenanceExecutableName] =
                    Encoding.UTF8.GetBytes("maintenance v2"),
                ["licenses/notice.txt"] = Encoding.UTF8.GetBytes("notice v2"),
            });
        var manifestBytes = CreateFollowupManifestBytes(
            pending,
            fixture,
            "personal-launcher-only-v2",
            [client.Artifact, current.Runtime],
            minimumStartupStubVersion:
                PersonalReleaseArtifactInstaller.NoHomeMinimumStartupStubVersion);
        var manifestUri = new Uri("https://updates.example.test/release-set.v2.json");
        var manifestRequests = 0;
        using var manifestHttp = new HttpClient(new DelegateHandler((request, _) =>
        {
            manifestRequests++;
            return request.RequestUri == manifestUri
                ? FullResponse(manifestBytes, "\"manifest-v2\"")
                : new HttpResponseMessage(HttpStatusCode.NotFound)
                {
                    RequestMessage = request,
                };
        }));
        var artifactRequests = 0;
        using var artifactHttp = new HttpClient(new DelegateHandler((request, _) =>
        {
            artifactRequests++;
            return request.RequestUri == client.Artifact.Uri
                ? FullResponse(File.ReadAllBytes(client.Path), "\"launcher-only-v2\"")
                : new HttpResponseMessage(HttpStatusCode.NotFound)
                {
                    RequestMessage = request,
                };
        }));
        Directory.CreateDirectory(pending.Install.Layout.HarnessHome);
        const string conversation = "local conversation must remain exact";
        const string recoverySentinel = "recovery lock must remain exact";
        var conversationPath = Path.Combine(
            pending.Install.Layout.HarnessHome,
            "conversation.db");
        File.WriteAllText(conversationPath, conversation);
        Directory.CreateDirectory(pending.Install.Layout.HarnessRecoveryRoot);
        var recoverySentinelPath = Path.Combine(
            pending.Install.Layout.HarnessRecoveryRoot,
            "active-transaction.v1.json");
        File.WriteAllText(recoverySentinelPath, recoverySentinel);
        var conversationTimestamp = File.GetLastWriteTimeUtc(conversationPath);
        var recoveryTimestamp = File.GetLastWriteTimeUtc(
            recoverySentinelPath);

        PersonalReleaseSetInstallationResult installed;
        PersonalHealthProbeResult health;
        var settings = new LauncherSettings
        {
            Channel = "stable",
            DshDataDirectory = pending.Install.Layout.HarnessHome,
            Port = GetFreePort(),
        };
        using (var lockedConversation = new FileStream(
                   conversationPath,
                   FileMode.Open,
                   FileAccess.Read,
                   FileShare.None))
        using (var lockedRecovery = new FileStream(
                   recoverySentinelPath,
                   FileMode.Open,
                   FileAccess.Read,
                   FileShare.None))
        {
            var outcome = await PersonalUpdateCoordinatorV2.CheckAsync(
                settings,
                pending.Install.Layout,
                manifestUri,
                fixture.Policy,
                manifestHttp,
                Now);
            AssertTrue(outcome.UpdateAvailable);
            AssertTrue(outcome.Detail.Contains(
                "仅下载变化组件并复用未变组件",
                StringComparison.Ordinal));
            var acquired = await PersonalUpdateCoordinatorV2.DownloadAsync(
                pending.Install.Layout,
                artifactHttp,
                outcome);
            AssertEqual(1, manifestRequests);
            AssertEqual(1, artifactRequests);
            AssertTrue(acquired.ClientBundle.ArchivePath is not null);
            AssertTrue(acquired.Runtime.ArchivePath is null);
            AssertTrue(acquired.Runtime.ReusedComponent is not null);
            installed = await PersonalUpdateCoordinatorV2.StageAsync(
                settings,
                pending.Install.Layout,
                outcome,
                acquired);
            AssertTrue(installed.HomeTransaction is null);
            AssertEqual(
                PersonalReleaseSetPointerStore.NoHomeTransactionSentinel,
                installed.Pointer.Current.HomeTransactionId);
            AssertTrue(PersonalReleaseSetPointerStore.InstalledComponentsMatch(
                pending.Result.Pointer.Current.Runtime,
                installed.Pointer.Current.Runtime));

            var coordinator = new PersonalReleaseHealthCoordinator(
                pending.Install.Layout);
            var probes = 0;
            health = await new PersonalBootstrapHealthGate(pending.Install.Layout)
                .EnsureHealthyAsync((bootstrapperPath, token, _, _) =>
                {
                    probes++;
                    AssertEqual(
                        Path.Combine(
                            installed.Pointer.Current.ClientBundle.Directory,
                            PersonalInstallationLayout.ClientBootstrapperExecutableName),
                        bootstrapperPath);
                    CompleteFixtureHomeHealthAttemptIfRequired(
                        pending.Install.Layout,
                        token);
                    coordinator.WriteSignal(
                        token,
                        Environment.ProcessId,
                        new string('7', 64));
                    return Task.FromResult(0);
                });
            AssertEqual(1, probes);
            var secondStart = await new PersonalBootstrapHealthGate(
                    pending.Install.Layout)
                .EnsureHealthyAsync((_, _, _, _) => throw new InvalidOperationException(
                    "Healthy no-home release unexpectedly launched another probe."));
            AssertTrue(secondStart.Healthy);

            var committedReceiptPath = Path.Combine(
                pending.Install.Layout.StateRoot,
                "personal-no-home-commit.current.v1.json");
            var committedReceiptBytes = File.ReadAllBytes(committedReceiptPath);
            File.Delete(committedReceiptPath);
            await AssertThrowsAsync<InvalidDataException>(() =>
                new PersonalBootstrapHealthGate(pending.Install.Layout)
                    .EnsureHealthyAsync((_, _, _, _) => Task.FromResult(0)));
            File.WriteAllBytes(committedReceiptPath, committedReceiptBytes);
            var tamperedReceipt = JsonNode.Parse(committedReceiptBytes)!.AsObject();
            tamperedReceipt["releaseSetId"] = "personal-tampered-no-home-receipt";
            File.WriteAllText(
                committedReceiptPath,
                tamperedReceipt.ToJsonString(
                    new JsonSerializerOptions(JsonSerializerDefaults.Web)
                    {
                        WriteIndented = false,
                    }),
                new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            await AssertThrowsAsync<InvalidDataException>(() =>
                new PersonalBootstrapHealthGate(pending.Install.Layout)
                    .EnsureHealthyAsync((_, _, _, _) => Task.FromResult(0)));
            File.WriteAllBytes(committedReceiptPath, committedReceiptBytes);
        }

        AssertTrue(health.Healthy);
        AssertEqual(conversation, File.ReadAllText(conversationPath));
        AssertEqual(
            recoverySentinel,
            File.ReadAllText(recoverySentinelPath));
        AssertEqual(conversationTimestamp, File.GetLastWriteTimeUtc(conversationPath));
        AssertEqual(
            recoveryTimestamp,
            File.GetLastWriteTimeUtc(recoverySentinelPath));
        var committed = new PersonalReleaseSetPointerStore(pending.Install.Layout)
            .ReadRequired();
        AssertEqual(PersonalReleaseHealthStates.Healthy, committed.Current.HealthState);
        AssertEqual(
            PersonalReleaseSetPointerStore.NoHomeTransactionSentinel,
            committed.Current.HomeTransactionId);
        AssertEqual("personal-launcher-only-v2", committed.Current.ReleaseSetId);
        AssertEqual(client.Artifact.ReleaseId, committed.Current.ClientBundle.ReleaseId);
        AssertEqual(current.Runtime.ReleaseId, committed.Current.Runtime.ReleaseId);
        var security = await pending.Security.TryReadAsync();
        AssertEqual("personal-launcher-only-v2", security!.LastCommittedReleaseSetId);
    }

    private static async Task NoHomeStartupStubCutoverRequiredAsync()
    {
        using (var oldStubFixture = new ManifestFixture("1.0.0"))
        {
            var fenced = oldStubFixture.CreateSigned(
                minimumStub:
                    PersonalReleaseArtifactInstaller.NoHomeMinimumStartupStubVersion,
                maximumStub: "1.9.9");
            var oldStubSecurity = NewStore("no-home-old-stub-admission");
            await AssertThrowsAsync<InvalidDataException>(() =>
                oldStubSecurity.VerifyAndAcceptAsync(
                    PersonalReleaseSetJson.SerializeSigned(fenced),
                    oldStubFixture.Policy,
                    Now));
            AssertTrue(await oldStubSecurity.TryReadAsync() is null);
        }

        using var fixture = new ManifestFixture("1.1.0");
        var pending = await CreateHealthyInstallAsync("no-home-cutover", fixture);
        var current = PersonalReleaseSetValidator.ParseAndVerify(
            pending.Install.ManifestBytes,
            fixture.Policy,
            Now).Manifest;
        var accepted = await AcceptFollowupAsync(
            pending,
            fixture,
            "personal-no-home-with-old-range-v2",
            current.Artifacts);
        using var http = new HttpClient(new DelegateHandler((request, _) =>
            new HttpResponseMessage(HttpStatusCode.NotFound)
            {
                RequestMessage = request,
            }));
        var acquired = await new PersonalReleaseArtifactAcquisitionService(
            pending.Install.Layout,
            http,
            new FixedTimeProvider(Now)).AcquireAsync(accepted.Verified);
        Directory.CreateDirectory(pending.Install.Layout.HarnessHome);
        var localPath = Path.Combine(pending.Install.Layout.HarnessHome, "local.txt");
        File.WriteAllText(localPath, "unchanged");
        Directory.CreateDirectory(pending.Install.Layout.HarnessRecoveryRoot);
        var recoverySentinelPath = Path.Combine(
            pending.Install.Layout.HarnessRecoveryRoot,
            "active-transaction.v1.json");
        File.WriteAllText(recoverySentinelPath, "blocked");

        await AssertThrowsAsync<InvalidDataException>(() =>
            new PersonalReleaseArtifactInstaller(_ =>
                    throw new InvalidOperationException(
                        "Cutover rejection attempted a Harness-home transaction."))
                .InstallAcquiredReleaseSetAsync(
                    pending.Install.Layout,
                    accepted.Verified,
                    acquired,
                    GetFreePort()));

        AssertEqual("unchanged", File.ReadAllText(localPath));
        AssertEqual(
            "blocked",
            File.ReadAllText(recoverySentinelPath));
        AssertEqual(
            pending.Result.Pointer.Current.ReleaseSetId,
            new PersonalReleaseSetPointerStore(pending.Install.Layout)
                .ReadRequired().Current.ReleaseSetId);
    }

    private static async Task NoHomePointerShapeFailsClosedAsync()
    {
        using var fixture = new ManifestFixture("1.1.0");
        var pending = await CreateHealthyInstallAsync("no-home-pointer-shape", fixture);
        var current = PersonalReleaseSetValidator.ParseAndVerify(
            pending.Install.ManifestBytes,
            fixture.Policy,
            Now).Manifest;
        var accepted = await AcceptFollowupAsync(
            pending,
            fixture,
            "personal-no-home-pointer-v2",
            current.Artifacts,
            minimumStartupStubVersion:
                PersonalReleaseArtifactInstaller.NoHomeMinimumStartupStubVersion);
        using var http = new HttpClient(new DelegateHandler((request, _) =>
            new HttpResponseMessage(HttpStatusCode.NotFound)
            {
                RequestMessage = request,
            }));
        var acquired = await new PersonalReleaseArtifactAcquisitionService(
            pending.Install.Layout,
            http,
            new FixedTimeProvider(Now)).AcquireAsync(accepted.Verified);
        var pointerStore = new PersonalReleaseSetPointerStore(pending.Install.Layout);
        AssertThrows<InvalidDataException>(() => pointerStore.ActivatePending(
            accepted.Verified,
            PersonalReleaseSetPointerStore.NoHomeTransactionSentinel));
        var installed = await NewTestArtifactInstaller().InstallAcquiredReleaseSetAsync(
            pending.Install.Layout,
            accepted.Verified,
            acquired,
            GetFreePort());

        var referenceBytes = JsonSerializer.SerializeToUtf8Bytes(
            installed.Pointer.Current,
            new JsonSerializerOptions(JsonSerializerDefaults.Web));
        var frozen = JsonSerializer.Deserialize<FrozenV3InstalledReleaseSetReference>(
            referenceBytes,
            new JsonSerializerOptions(JsonSerializerDefaults.Web)
            {
                UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
            });
        AssertTrue(frozen is not null);
        AssertEqual(
            PersonalReleaseSetPointerStore.NoHomeTransactionSentinel,
            frozen!.HomeTransactionId);
        var pointerBytes = JsonSerializer.SerializeToUtf8Bytes(
            installed.Pointer,
            new JsonSerializerOptions(JsonSerializerDefaults.Web));
        var frozenPointer = JsonSerializer.Deserialize<FrozenV3InstalledReleaseSetPointer>(
            pointerBytes,
            new JsonSerializerOptions(JsonSerializerDefaults.Web)
            {
                UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
            });
        AssertTrue(frozenPointer is not null);
        AssertEqual(3, frozenPointer!.SchemaVersion);
        AssertEqual(
            PersonalReleaseSetPointerStore.NoHomeTransactionSentinel,
            frozenPointer.Current.HomeTransactionId);
        using (var document = JsonDocument.Parse(referenceBytes))
        {
            var actual = document.RootElement.EnumerateObject()
                .Select(property => property.Name)
                .Order(StringComparer.Ordinal)
                .ToArray();
            var expected = new[]
            {
                "activatedAtUtc",
                "clientBundle",
                "generation",
                "healthState",
                "healthToken",
                "homeTransactionId",
                "manifestSha256",
                "minAcceptedSequence",
                "releaseSetId",
                "runtime",
                "sequence",
                "startupStub",
            }.Order(StringComparer.Ordinal).ToArray();
            AssertTrue(expected.SequenceEqual(actual, StringComparer.Ordinal));
        }

        var noTransactionIdentity = installed.Pointer with
        {
            Current = installed.Pointer.Current with
            {
                HomeTransactionId = null,
            },
        };
        File.WriteAllBytes(
            pending.Install.Layout.ReleaseSetPointerPath,
            JsonSerializer.SerializeToUtf8Bytes(
                noTransactionIdentity,
                new JsonSerializerOptions(JsonSerializerDefaults.Web)));
        AssertThrows<InvalidDataException>(() => pointerStore.ReadRequired());

        var noPreviousRuntime = installed.Pointer with { Previous = null };
        File.WriteAllBytes(
            pending.Install.Layout.ReleaseSetPointerPath,
            JsonSerializer.SerializeToUtf8Bytes(
                noPreviousRuntime,
                new JsonSerializerOptions(JsonSerializerDefaults.Web)));
        AssertThrows<InvalidDataException>(() => pointerStore.ReadRequired());
    }

    private static async Task NoHomeCommitCrashRecoveryNeverTouchesHomeAsync()
    {
        foreach (var crashStage in Enum.GetValues<PersonalNoHomeCommitStage>())
        {
            await NoHomeCommitCrashStageRecoversAsync(crashStage);
        }
    }

    private static async Task NoHomeCommitReceiptIsStrictAsync()
    {
        using var fixture = new ManifestFixture("1.1.0");
        var pending = await CreateHealthyInstallAsync("no-home-commit-receipt", fixture);
        var current = PersonalReleaseSetValidator.ParseAndVerify(
            pending.Install.ManifestBytes,
            fixture.Policy,
            Now).Manifest;
        var accepted = await AcceptFollowupAsync(
            pending,
            fixture,
            "personal-no-home-commit-receipt-v2",
            current.Artifacts,
            minimumStartupStubVersion:
                PersonalReleaseArtifactInstaller.NoHomeMinimumStartupStubVersion);
        using var http = new HttpClient(new DelegateHandler((request, _) =>
            new HttpResponseMessage(HttpStatusCode.NotFound)
            {
                RequestMessage = request,
            }));
        var acquired = await new PersonalReleaseArtifactAcquisitionService(
            pending.Install.Layout,
            http,
            new FixedTimeProvider(Now)).AcquireAsync(accepted.Verified);
        var installed = await new PersonalReleaseArtifactInstaller(_ =>
                throw new InvalidOperationException(
                    "No-home receipt fixture attempted a Harness-home transaction."))
            .InstallAcquiredReleaseSetAsync(
                pending.Install.Layout,
                accepted.Verified,
                acquired,
                GetFreePort());
        var token = installed.Pointer.Current.HealthToken!;
        var coordinator = new PersonalReleaseHealthCoordinator(
            pending.Install.Layout);
        CompleteFixtureHomeHealthAttemptIfRequired(
            pending.Install.Layout,
            token);
        coordinator.WriteSignal(
            token,
            Environment.ProcessId,
            new string('8', 64));
        var store = new PersonalNoHomeCommitStore(pending.Install.Layout);
        var receipt = store.Prepare(installed.Pointer, token);
        AssertEqual(
            coordinator.GetSignalPath(token),
            store.GetHealthSignalPath(receipt));

        var pendingPath = Path.Combine(
            pending.Install.Layout.StateRoot,
            "personal-no-home-commit.pending.v1.json");
        var canonical = File.ReadAllBytes(pendingPath);
        AssertTrue(store.TryReadPending() is not null);

        File.WriteAllBytes(
            pendingPath,
            [.. canonical, (byte)'\n']);
        AssertThrows<InvalidDataException>(() => store.TryReadPending());

        var canonicalText = Encoding.UTF8.GetString(canonical);
        File.WriteAllText(
            pendingPath,
            "{\"schemaVersion\":1," + canonicalText[1..],
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        AssertThrows<InvalidDataException>(() => store.TryReadPending());

        var hardLinkTarget = Path.Combine(
            Path.GetDirectoryName(pending.Install.Layout.ManagedRoot)!,
            $"no-home-commit-hardlink-{Guid.NewGuid():N}.json");
        File.WriteAllBytes(hardLinkTarget, canonical);
        File.Delete(pendingPath);
        CreateHardLinkForTest(pendingPath, hardLinkTarget);
        AssertThrows<InvalidDataException>(() => store.TryReadPending());
    }

    private static async Task HealthyFullHomeSameRuntimeIsNotInferredAsNoHomeAsync()
    {
        using var fixture = new ManifestFixture("1.1.0");
        var pending = await CreateHealthyInstallAsync(
            "full-home-same-runtime-mode",
            fixture);
        var current = PersonalReleaseSetValidator.ParseAndVerify(
            pending.Install.ManifestBytes,
            fixture.Policy,
            Now).Manifest;
        var noHome = await AcceptFollowupAsync(
            pending,
            fixture,
            "personal-no-home-before-full-v2",
            current.Artifacts,
            minimumStartupStubVersion:
                PersonalReleaseArtifactInstaller.NoHomeMinimumStartupStubVersion);
        using var http = new HttpClient(new DelegateHandler((request, _) =>
            new HttpResponseMessage(HttpStatusCode.NotFound)
            {
                RequestMessage = request,
            }));
        var noHomeAcquired = await new PersonalReleaseArtifactAcquisitionService(
            pending.Install.Layout,
            http,
            new FixedTimeProvider(Now)).AcquireAsync(noHome.Verified);
        var noHomeInstalled = await NewTestArtifactInstaller()
            .InstallAcquiredReleaseSetAsync(
                pending.Install.Layout,
                noHome.Verified,
                noHomeAcquired,
                GetFreePort());
        var noHomeToken = noHomeInstalled.Pointer.Current.HealthToken!;
        var coordinator = new PersonalReleaseHealthCoordinator(pending.Install.Layout);
        CompleteFixtureHomeHealthAttemptIfRequired(
            pending.Install.Layout,
            noHomeToken);
        coordinator.WriteSignal(
            noHomeToken,
            Environment.ProcessId,
            new string('9', 64));
        var noHomeHealthy = coordinator.ConsumeSignalAndMarkHealthy(noHomeToken);
        AssertEqual(
            PersonalReleaseSetPointerStore.NoHomeTransactionSentinel,
            noHomeHealthy.Current.HomeTransactionId);

        var staleReceiptPath = Path.Combine(
            pending.Install.Layout.StateRoot,
            "personal-no-home-commit.current.v1.json");
        AssertTrue(File.Exists(staleReceiptPath));
        var fullHome = await AcceptFollowupAsync(
            pending,
            fixture,
            "personal-full-home-same-runtime-v3",
            current.Artifacts,
            minimumStartupStubVersion:
                PersonalReleaseArtifactInstaller.NoHomeMinimumStartupStubVersion,
            generation: 13,
            sequence: 13);
        var homeTransaction = NewTestHomeTransaction(
            pending.Install.Layout.HarnessHome,
            pending.Install.Layout.HarnessRecoveryRoot);
        var prepared = homeTransaction.Prepare(
            fullHome.Verified.Manifest.ReleaseSetId,
            GetFreePort());
        var pointerStore = new PersonalReleaseSetPointerStore(pending.Install.Layout);
        var fullPending = pointerStore.ActivatePending(
            fullHome.Verified,
            prepared.TransactionId);
        var fullToken = fullPending.Current.HealthToken!;
        CompleteFixtureHomeHealthAttemptIfRequired(
            pending.Install.Layout,
            fullToken);
        coordinator.WriteSignal(
            fullToken,
            Environment.ProcessId,
            new string('a', 64));
        var fullHealthy = coordinator.ConsumeSignalAndMarkHealthy(fullToken);
        AssertEqual(PersonalReleaseHealthStates.Healthy, fullHealthy.Current.HealthState);
        AssertTrue(fullHealthy.Current.HomeTransactionId is null);
        AssertTrue(fullHealthy.Previous is not null);
        AssertTrue(PersonalReleaseSetPointerStore.InstalledComponentsMatch(
            fullHealthy.Current.Runtime,
            fullHealthy.Previous!.Runtime));
        AssertTrue(File.Exists(staleReceiptPath));

        var firstRestart = await new PersonalBootstrapHealthGate(
                pending.Install.Layout)
            .EnsureHealthyAsync((_, _, _, _) => throw new InvalidOperationException(
                "Healthy full-home release unexpectedly launched a probe."));
        AssertTrue(firstRestart.Healthy);

        File.WriteAllText(staleReceiptPath, "{tampered-stale-no-home-receipt");
        var secondRestart = await new PersonalBootstrapHealthGate(
                pending.Install.Layout)
            .EnsureHealthyAsync((_, _, _, _) => throw new InvalidOperationException(
                "Healthy full-home release unexpectedly launched a second probe."));
        AssertTrue(secondRestart.Healthy);
    }

    private static async Task NoHomeCommitCrashStageRecoversAsync(
        PersonalNoHomeCommitStage crashStage)
    {
        using var fixture = new ManifestFixture("1.1.0");
        var scope = $"no-home-commit-crash-{crashStage.ToString().ToLowerInvariant()}";
        var pending = await CreateHealthyInstallAsync(scope, fixture);
        var current = PersonalReleaseSetValidator.ParseAndVerify(
            pending.Install.ManifestBytes,
            fixture.Policy,
            Now).Manifest;
        var accepted = await AcceptFollowupAsync(
            pending,
            fixture,
            $"personal-no-home-{crashStage.ToString().ToLowerInvariant()}-v2",
            current.Artifacts,
            minimumStartupStubVersion:
                PersonalReleaseArtifactInstaller.NoHomeMinimumStartupStubVersion);
        using var http = new HttpClient(new DelegateHandler((request, _) =>
            new HttpResponseMessage(HttpStatusCode.NotFound)
            {
                RequestMessage = request,
            }));
        var acquired = await new PersonalReleaseArtifactAcquisitionService(
            pending.Install.Layout,
            http,
            new FixedTimeProvider(Now)).AcquireAsync(accepted.Verified);
        var installed = await new PersonalReleaseArtifactInstaller(_ =>
                throw new InvalidOperationException(
                    "No-home crash fixture attempted a Harness-home transaction."))
            .InstallAcquiredReleaseSetAsync(
                pending.Install.Layout,
                accepted.Verified,
                acquired,
                GetFreePort());
        var token = installed.Pointer.Current.HealthToken!;
        var regularCoordinator = new PersonalReleaseHealthCoordinator(
            pending.Install.Layout);
        CompleteFixtureHomeHealthAttemptIfRequired(
            pending.Install.Layout,
            token);
        regularCoordinator.WriteSignal(
            token,
            Environment.ProcessId,
            new string('6', 64));

        Directory.CreateDirectory(pending.Install.Layout.HarnessHome);
        var conversationPath = Path.Combine(
            pending.Install.Layout.HarnessHome,
            "conversation.jsonl");
        File.WriteAllText(conversationPath, "local-history");
        Directory.CreateDirectory(pending.Install.Layout.HarnessRecoveryRoot);
        var recoveryLockPath = Path.Combine(
            pending.Install.Layout.HarnessRecoveryRoot,
            "active-transaction.v1.json");
        File.WriteAllText(recoveryLockPath, "no-home-recovery-lock");

        var crashInjected = false;
        var interruptedCoordinator = new PersonalReleaseHealthCoordinator(
            pending.Install.Layout,
            stage =>
            {
                if (stage == crashStage)
                {
                    crashInjected = true;
                    throw new InvalidOperationException("simulated power loss");
                }
            });
        using (var lockedConversation = new FileStream(
                   conversationPath,
                   FileMode.Open,
                   FileAccess.Read,
                   FileShare.None))
        using (var lockedRecovery = new FileStream(
                   recoveryLockPath,
                   FileMode.Open,
                   FileAccess.ReadWrite,
                   FileShare.None))
        {
            AssertThrows<InvalidOperationException>(() =>
                interruptedCoordinator.ConsumeSignalAndMarkHealthy(token));
            AssertTrue(crashInjected);
            var interruptedPointer = new PersonalReleaseSetPointerStore(
                pending.Install.Layout).ReadRequired();
            var beforeRecovery = await pending.Security.TryReadAsync();
            if (crashStage == PersonalNoHomeCommitStage.PendingJournalWritten)
            {
                AssertEqual(
                    PersonalReleaseHealthStates.Pending,
                    interruptedPointer.Current.HealthState);
                AssertEqual(
                    pending.Result.Pointer.Current.ReleaseSetId,
                    beforeRecovery!.LastCommittedReleaseSetId);
            }
            else
            {
                AssertEqual(
                    PersonalReleaseHealthStates.Healthy,
                    interruptedPointer.Current.HealthState);
            }

            var probes = 0;
            var recovered = await new PersonalBootstrapHealthGate(
                    pending.Install.Layout)
                .EnsureHealthyAsync((_, retryToken, _, _) =>
                {
                    probes++;
                    CompleteFixtureHomeHealthAttemptIfRequired(
                        pending.Install.Layout,
                        retryToken);
                    regularCoordinator.WriteSignal(
                        retryToken,
                        Environment.ProcessId,
                        new string('5', 64));
                    return Task.FromResult(0);
                });
            AssertTrue(recovered.Healthy);
            AssertEqual(
                crashStage == PersonalNoHomeCommitStage.PendingJournalWritten ? 1 : 0,
                probes);
        }

        AssertEqual("local-history", File.ReadAllText(conversationPath));
        AssertEqual("no-home-recovery-lock", File.ReadAllText(recoveryLockPath));
        var recoveredSecurity = await pending.Security.TryReadAsync();
        AssertEqual(
            $"personal-no-home-{crashStage.ToString().ToLowerInvariant()}-v2",
            recoveredSecurity!.LastCommittedReleaseSetId);
        var committedPointer = new PersonalReleaseSetPointerStore(
            pending.Install.Layout).ReadRequired();
        _ = new PersonalNoHomeCommitStore(pending.Install.Layout)
            .ReadCommittedRequired(committedPointer);
        AssertFalse(File.Exists(regularCoordinator.GetSignalPath(token)));
    }

    private static async Task OneChangedComponentDownloadsOnceAsync()
    {
        using var fixture = new ManifestFixture();
        var pending = await CreateHealthyInstallAsync("reuse-one-changed", fixture);
        var current = PersonalReleaseSetValidator.ParseAndVerify(
            pending.Install.ManifestBytes,
            fixture.Policy,
            Now).Manifest;
        var root = Path.GetDirectoryName(pending.Install.Layout.ManagedRoot)!;
        var runtime = CreateComponentArchive(
            root,
            PersonalReleaseSetContract.RuntimeComponent,
            "runtime-install-v2",
            new Dictionary<string, byte[]>(StringComparer.Ordinal)
            {
                ["node.exe"] = Encoding.UTF8.GetBytes("node v2"),
                ["node_modules/@deepseek-ai/dsh/lib/bin.js"] =
                    Encoding.UTF8.GetBytes("console.log('dsh v2')"),
                ["node_modules/@deepseek-ai/dsh/package.json"] =
                    Encoding.UTF8.GetBytes("{\"version\":\"0.2.0\"}"),
            });
        var accepted = await AcceptFollowupAsync(
            pending,
            fixture,
            "personal-reuse-runtime-v2",
            [current.ClientBundle, runtime.Artifact]);
        var requests = 0;
        using var client = new HttpClient(new DelegateHandler((request, _) =>
        {
            requests++;
            if (request.RequestUri != runtime.Artifact.Uri)
            {
                return new HttpResponseMessage(HttpStatusCode.NotFound)
                {
                    RequestMessage = request,
                };
            }
            return FullResponse(File.ReadAllBytes(runtime.Path), "\"runtime-v2\"");
        }));

        var acquired = await new PersonalReleaseArtifactAcquisitionService(
            pending.Install.Layout,
            client,
            new FixedTimeProvider(Now)).AcquireAsync(accepted.Verified);

        AssertEqual(1, requests);
        AssertTrue(acquired.ClientBundle.ReusedComponent is not null);
        AssertTrue(acquired.Runtime.ReusedComponent is null);
        AssertTrue(acquired.Runtime.ArchivePath is not null);
        var installed = await NewTestArtifactInstaller()
            .InstallAcquiredReleaseSetAsync(
                pending.Install.Layout,
                accepted.Verified,
                acquired,
                GetFreePort());
        AssertTrue(installed.HomeTransaction is not null);
        AssertFalse(string.Equals(
            installed.Pointer.Current.HomeTransactionId,
            PersonalReleaseSetPointerStore.NoHomeTransactionSentinel,
            StringComparison.Ordinal));
        AssertEqual(
            runtime.Artifact.ReleaseId,
            installed.Pointer.Current.Runtime.ReleaseId);
        AssertEqual(
            pending.Result.Pointer.Current.ClientBundle.Directory,
            installed.Pointer.Current.ClientBundle.Directory);
    }

    private static async Task ConsecutiveComponentUpdatesPreserveLocalDataAsync()
    {
        using var fixture = new ManifestFixture("1.1.0");
        var pending = await CreateHealthyInstallAsync("consecutive-component-updates", fixture);
        var initial = PersonalReleaseSetValidator.ParseAndVerify(
            pending.Install.ManifestBytes,
            fixture.Policy,
            Now).Manifest;
        var root = Path.GetDirectoryName(pending.Install.Layout.ManagedRoot)!;
        var runtime = CreateComponentArchive(
            root,
            PersonalReleaseSetContract.RuntimeComponent,
            "runtime-consecutive-v2",
            new Dictionary<string, byte[]>(StringComparer.Ordinal)
            {
                ["node.exe"] = Encoding.UTF8.GetBytes("node consecutive v2"),
                ["node_modules/@deepseek-ai/dsh/lib/bin.js"] =
                    Encoding.UTF8.GetBytes("console.log('dsh consecutive v2')"),
                ["node_modules/@deepseek-ai/dsh/package.json"] =
                    Encoding.UTF8.GetBytes("{\"version\":\"0.2.0\"}"),
            });
        var client = CreateComponentArchive(
            root,
            PersonalReleaseSetContract.ClientBundleComponent,
            "client-consecutive-v3",
            new Dictionary<string, byte[]>(StringComparer.Ordinal)
            {
                [PersonalInstallationLayout.ClientBootstrapperExecutableName] =
                    Encoding.UTF8.GetBytes("client bootstrapper consecutive v3"),
                [PersonalInstallationLayout.LauncherExecutableName] =
                    Encoding.UTF8.GetBytes("launcher consecutive v3"),
                [PersonalInstallationLayout.MaintenanceExecutableName] =
                    Encoding.UTF8.GetBytes("maintenance consecutive v3"),
                ["licenses/notice.txt"] = Encoding.UTF8.GetBytes("notice consecutive v3"),
            });
        var manifestUri = new Uri("https://updates.example.test/release-set.v2.json");
        var settings = new LauncherSettings
        {
            Channel = "stable",
            DshDataDirectory = pending.Install.Layout.HarnessHome,
            Port = GetFreePort(),
        };
        Directory.CreateDirectory(pending.Install.Layout.HarnessHome);
        var sentinelPath = Path.Combine(
            pending.Install.Layout.HarnessHome,
            "local-conversation-sentinel.bin");
        var sentinelBytes = Encoding.UTF8.GetBytes("local data must survive both updates");
        File.WriteAllBytes(sentinelPath, sentinelBytes);
        var initialLauncherBytes = File.ReadAllBytes(Path.Combine(
            pending.Result.Pointer.Current.ClientBundle.Directory,
            PersonalInstallationLayout.LauncherExecutableName));

        async Task StageAndCommitAsync(
            byte[] manifestBytes,
            ComponentArchive changedComponent,
            long expectedSequence,
            bool expectHomeTransaction)
        {
            var manifestRequests = 0;
            using var manifestHttp = new HttpClient(new DelegateHandler((request, _) =>
            {
                manifestRequests++;
                return request.RequestUri == manifestUri
                    ? FullResponse(manifestBytes, $"\"manifest-{expectedSequence}\"")
                    : new HttpResponseMessage(HttpStatusCode.NotFound)
                    {
                        RequestMessage = request,
                    };
            }));
            var artifactRequests = 0;
            using var artifactHttp = new HttpClient(new DelegateHandler((request, _) =>
            {
                artifactRequests++;
                return request.RequestUri == changedComponent.Artifact.Uri
                    ? FullResponse(
                        File.ReadAllBytes(changedComponent.Path),
                        $"\"artifact-{expectedSequence}\"")
                    : new HttpResponseMessage(HttpStatusCode.NotFound)
                    {
                        RequestMessage = request,
                    };
            }));

            var outcome = await PersonalUpdateCoordinatorV2.CheckAsync(
                settings,
                pending.Install.Layout,
                manifestUri,
                fixture.Policy,
                manifestHttp,
                Now);
            AssertTrue(outcome.UpdateAvailable);
            var acquired = await PersonalUpdateCoordinatorV2.DownloadAsync(
                pending.Install.Layout,
                artifactHttp,
                outcome);
            AssertEqual(1, manifestRequests);
            AssertEqual(1, artifactRequests);
            AssertTrue(acquired.ClientBundle.ArchivePath is not null ==
                string.Equals(
                    changedComponent.Artifact.Component,
                    PersonalReleaseSetContract.ClientBundleComponent,
                    StringComparison.Ordinal));
            AssertTrue(acquired.Runtime.ArchivePath is not null ==
                string.Equals(
                    changedComponent.Artifact.Component,
                    PersonalReleaseSetContract.RuntimeComponent,
                    StringComparison.Ordinal));

            // The test host may itself have an unrelated Node process.  Exercise the
            // real installer with the existing test-only quiescence injection rather
            // than treating that host-global process as this fixture's writer.
            var staged = await NewTestArtifactInstaller().InstallAcquiredReleaseSetAsync(
                pending.Install.Layout,
                outcome.Verified,
                acquired,
                settings.Port);
            AssertEqual(expectHomeTransaction, staged.HomeTransaction is not null);
            AssertEqual(expectedSequence, staged.Pointer.Current.Sequence);
            var token = staged.Pointer.Current.HealthToken!;
            var coordinator = new PersonalReleaseHealthCoordinator(pending.Install.Layout);
            var probes = 0;
            var health = await new PersonalBootstrapHealthGate(pending.Install.Layout)
                .EnsureHealthyAsync((bootstrapperPath, healthToken, _, _) =>
                {
                    probes++;
                    AssertEqual(
                        Path.Combine(
                            staged.Pointer.Current.ClientBundle.Directory,
                            PersonalInstallationLayout.ClientBootstrapperExecutableName),
                        bootstrapperPath);
                    CompleteFixtureHomeHealthAttemptIfRequired(
                        pending.Install.Layout,
                        healthToken);
                    coordinator.WriteSignal(
                        healthToken,
                        Environment.ProcessId,
                        new string(expectedSequence == 12 ? 'b' : 'c', 64));
                    return Task.FromResult(0);
                });
            AssertTrue(health.Healthy);
            AssertEqual(1, probes);
            var committed = new PersonalReleaseSetPointerStore(pending.Install.Layout)
                .ReadRequired();
            AssertEqual(expectedSequence, committed.Current.Sequence);
            AssertEqual(PersonalReleaseHealthStates.Healthy, committed.Current.HealthState);
            AssertTrue(sentinelBytes.SequenceEqual(File.ReadAllBytes(sentinelPath)));
        }

        var runtimeManifest = CreateFollowupManifestBytes(
            pending,
            fixture,
            "personal-consecutive-runtime-v2",
            [initial.ClientBundle, runtime.Artifact],
            generation: 12,
            sequence: 12);
        await StageAndCommitAsync(
            runtimeManifest,
            runtime,
            expectedSequence: 12,
            expectHomeTransaction: true);
        var afterRuntime = new PersonalReleaseSetPointerStore(pending.Install.Layout)
            .ReadRequired();
        AssertEqual(initial.ClientBundle.ReleaseId, afterRuntime.Current.ClientBundle.ReleaseId);
        AssertEqual(runtime.Artifact.ReleaseId, afterRuntime.Current.Runtime.ReleaseId);
        AssertTrue(initialLauncherBytes.SequenceEqual(File.ReadAllBytes(Path.Combine(
            afterRuntime.Current.ClientBundle.Directory,
            PersonalInstallationLayout.LauncherExecutableName))));
        var runtimeNodeBytes = File.ReadAllBytes(Path.Combine(
            afterRuntime.Current.Runtime.Directory,
            "node.exe"));

        var launcherManifest = CreateFollowupManifestBytes(
            pending,
            fixture,
            "personal-consecutive-launcher-v3",
            [client.Artifact, runtime.Artifact],
            minimumStartupStubVersion:
                PersonalReleaseArtifactInstaller.NoHomeMinimumStartupStubVersion,
            generation: 13,
            sequence: 13);
        await StageAndCommitAsync(
            launcherManifest,
            client,
            expectedSequence: 13,
            expectHomeTransaction: false);
        var afterLauncher = new PersonalReleaseSetPointerStore(pending.Install.Layout)
            .ReadRequired();
        AssertEqual(client.Artifact.ReleaseId, afterLauncher.Current.ClientBundle.ReleaseId);
        AssertEqual(runtime.Artifact.ReleaseId, afterLauncher.Current.Runtime.ReleaseId);
        AssertEqual(13L, afterLauncher.Current.Sequence);
        AssertTrue(runtimeNodeBytes.SequenceEqual(File.ReadAllBytes(Path.Combine(
            afterLauncher.Current.Runtime.Directory,
            "node.exe"))));
        AssertTrue(sentinelBytes.SequenceEqual(File.ReadAllBytes(sentinelPath)));
    }

    private static async Task TamperedReuseFailsBeforeArtifactGetAsync()
    {
        using var fixture = new ManifestFixture();
        var pending = await CreateHealthyInstallAsync("reuse-tampered", fixture);
        var current = PersonalReleaseSetValidator.ParseAndVerify(
            pending.Install.ManifestBytes,
            fixture.Policy,
            Now).Manifest;
        var accepted = await AcceptFollowupAsync(
            pending,
            fixture,
            "personal-reuse-tampered-v2",
            current.Artifacts);
        File.WriteAllText(
            Path.Combine(
                pending.Result.Pointer.Current.Runtime.Directory,
                "node_modules",
                "@deepseek-ai",
                "dsh",
                "package.json"),
            "{\"version\":\"tampered\"}");
        var requests = 0;
        using var client = new HttpClient(new DelegateHandler((request, _) =>
        {
            requests++;
            return new HttpResponseMessage(HttpStatusCode.NotFound)
            {
                RequestMessage = request,
            };
        }));

        await AssertThrowsAsync<InvalidDataException>(() =>
            new PersonalReleaseArtifactAcquisitionService(
                pending.Install.Layout,
                client,
                new FixedTimeProvider(Now)).AcquireAsync(accepted.Verified));
        AssertEqual(0, requests);
    }

    private static async Task UnreferencedResidueDoesNotAuthorizeReuseAsync()
    {
        using var fixture = new ManifestFixture();
        var pending = await CreateHealthyInstallAsync("reuse-unreferenced", fixture);
        var current = PersonalReleaseSetValidator.ParseAndVerify(
            pending.Install.ManifestBytes,
            fixture.Policy,
            Now).Manifest;
        var root = Path.GetDirectoryName(pending.Install.Layout.ManagedRoot)!;
        var residue = CreateComponentArchive(
            root,
            PersonalReleaseSetContract.RuntimeComponent,
            "runtime-residue-v2",
            new Dictionary<string, byte[]>(StringComparer.Ordinal)
            {
                ["node.exe"] = Encoding.UTF8.GetBytes("residue node"),
                ["node_modules/@deepseek-ai/dsh/lib/bin.js"] =
                    Encoding.UTF8.GetBytes("console.log('residue')"),
                ["node_modules/@deepseek-ai/dsh/package.json"] =
                    Encoding.UTF8.GetBytes("{\"version\":\"residue\"}"),
            });
        await new PersonalReleaseArtifactInstaller().InstallComponentAsync(
            pending.Install.Layout,
            residue.Artifact,
            residue.Path,
            pending.Install.Layout.GetRuntimeDirectory(residue.Artifact.ReleaseId));
        var accepted = await AcceptFollowupAsync(
            pending,
            fixture,
            "personal-residue-target-v2",
            [current.ClientBundle, residue.Artifact]);
        var requests = 0;
        using var client = new HttpClient(new DelegateHandler((request, _) =>
        {
            requests++;
            return FullResponse(File.ReadAllBytes(residue.Path), "\"residue\"");
        }));

        await AssertThrowsAsync<InvalidDataException>(() =>
            new PersonalReleaseArtifactAcquisitionService(
                pending.Install.Layout,
                client,
                new FixedTimeProvider(Now)).AcquireAsync(accepted.Verified));
        AssertEqual(0, requests);
    }

    private static async Task DownloadedTargetAfterAcquireFailsClosedAsync()
    {
        using var fixture = new ManifestFixture();
        var pending = await CreateHealthyInstallAsync("reuse-stage-race", fixture);
        var current = PersonalReleaseSetValidator.ParseAndVerify(
            pending.Install.ManifestBytes,
            fixture.Policy,
            Now).Manifest;
        var root = Path.GetDirectoryName(pending.Install.Layout.ManagedRoot)!;
        var runtime = CreateComponentArchive(
            root,
            PersonalReleaseSetContract.RuntimeComponent,
            "runtime-stage-race-v2",
            new Dictionary<string, byte[]>(StringComparer.Ordinal)
            {
                ["node.exe"] = Encoding.UTF8.GetBytes("node race v2"),
                ["node_modules/@deepseek-ai/dsh/lib/bin.js"] =
                    Encoding.UTF8.GetBytes("console.log('race v2')"),
                ["node_modules/@deepseek-ai/dsh/package.json"] =
                    Encoding.UTF8.GetBytes("{\"version\":\"0.3.0\"}"),
            });
        var accepted = await AcceptFollowupAsync(
            pending,
            fixture,
            "personal-stage-race-v2",
            [current.ClientBundle, runtime.Artifact]);
        using var client = new HttpClient(new DelegateHandler((request, _) =>
            request.RequestUri == runtime.Artifact.Uri
                ? FullResponse(File.ReadAllBytes(runtime.Path), "\"runtime-race-v2\"")
                : new HttpResponseMessage(HttpStatusCode.NotFound)
                {
                    RequestMessage = request,
                }));
        var acquired = await new PersonalReleaseArtifactAcquisitionService(
            pending.Install.Layout,
            client,
            new FixedTimeProvider(Now)).AcquireAsync(accepted.Verified);
        var racedDirectory = pending.Install.Layout.GetRuntimeDirectory(
            runtime.Artifact.ReleaseId);
        Directory.CreateDirectory(racedDirectory);
        File.WriteAllText(Path.Combine(racedDirectory, "attacker.txt"), "untrusted");

        await AssertThrowsAsync<InvalidDataException>(() =>
            NewTestArtifactInstaller().InstallAcquiredReleaseSetAsync(
                pending.Install.Layout,
                accepted.Verified,
                acquired,
                GetFreePort()));

        var pointer = new PersonalReleaseSetPointerStore(pending.Install.Layout).ReadRequired();
        AssertEqual(pending.Result.Pointer.Current.ReleaseSetId, pointer.Current.ReleaseSetId);
        AssertEqual(
            pending.Result.Pointer.Current.Runtime.ReleaseId,
            pointer.Current.Runtime.ReleaseId);
    }

    private static async Task PublisherSelfVerificationAsync()
    {
        using var fixture = new PublisherFixture("publisher-success");
        var result = await fixture.CreatePublisher().PublishAsync(
            fixture.Config,
            fixture.Key,
            Now);
        AssertTrue(File.Exists(result.OutputManifestPath));
        AssertTrue(PersonalReleaseSetValidator.IsSha256(result.Sha256));
        AssertEqual(Sha256(fixture.ClientBundleBytes), result.Verified.Manifest.ClientBundle.Sha256);
        AssertEqual(Sha256(fixture.RuntimeBytes), result.Verified.Manifest.Runtime.Sha256);
        AssertEqual(
            Sha256(fixture.ClientTreeBytes),
            result.Verified.Manifest.ClientBundle.CompleteTreeSha256);
    }

    private static async Task PublisherExactRetryAndConflictsAsync()
    {
        using var fixture = new PublisherFixture("publisher-overwrite");
        var publisher = fixture.CreatePublisher();
        var first = await publisher.PublishAsync(fixture.Config, fixture.Key, Now);
        var committedBytes = File.ReadAllBytes(fixture.Config.OutputManifestPath);
        var retry = await publisher.PublishAsync(fixture.Config, fixture.Key, Now);
        AssertEqual(first.OutputManifestPath, retry.OutputManifestPath);
        AssertEqual(first.Sha256, retry.Sha256);
        AssertSequenceEqual(
            committedBytes,
            File.ReadAllBytes(fixture.Config.OutputManifestPath));

        // Exact retry authenticates the already-committed manifest and does not
        // re-sign it. The API key object is therefore intentionally unused on
        // this branch; the configured key ID still has to match the manifest.
        using (var unrelatedPrivateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256))
        {
            var retryWithoutResigning = await publisher.PublishAsync(
                fixture.Config,
                unrelatedPrivateKey,
                Now);
            AssertEqual(first.Sha256, retryWithoutResigning.Sha256);
        }

        var configConflict = fixture.Config with
        {
            ExpiresAtUtc = fixture.Config.ExpiresAtUtc.AddMinutes(1),
        };
        await AssertThrowsAsync<IOException>(() =>
            publisher.PublishAsync(configConflict, fixture.Key, Now));
        AssertSequenceEqual(
            committedBytes,
            File.ReadAllBytes(fixture.Config.OutputManifestPath));

        var outputConflict = fixture.Config with
        {
            OutputManifestPath = Path.Combine(
                Path.GetDirectoryName(fixture.Config.OutputManifestPath)!,
                "same-publication-different-output.release-set-v2.json"),
        };
        await AssertThrowsAsync<InvalidDataException>(() =>
            publisher.PublishAsync(outputConflict, fixture.Key, Now));
        AssertFalse(File.Exists(outputConflict.OutputManifestPath));

        var clientInput = fixture.Config.Artifacts[0];
        File.Delete(clientInput.SourcePath);
        File.Delete(clientInput.CompleteTreeManifestPath);
        _ = CreateComponentArchive(
            Path.GetDirectoryName(clientInput.SourcePath)!,
            PersonalReleaseSetContract.ClientBundleComponent,
            clientInput.ReleaseId,
            new Dictionary<string, byte[]>(StringComparer.Ordinal)
            {
                [PersonalInstallationLayout.ClientBootstrapperExecutableName] =
                    Encoding.UTF8.GetBytes("changed client bootstrapper"),
                [PersonalInstallationLayout.LauncherExecutableName] =
                    Encoding.UTF8.GetBytes("changed launcher"),
                [PersonalInstallationLayout.MaintenanceExecutableName] =
                    Encoding.UTF8.GetBytes("changed maintenance"),
            });
        await AssertThrowsAsync<IOException>(() =>
            publisher.PublishAsync(fixture.Config, fixture.Key, Now));
        AssertSequenceEqual(
            committedBytes,
            File.ReadAllBytes(fixture.Config.OutputManifestPath));
    }

    private static async Task PublisherCandidateIdentityIsLockedAsync()
    {
        using var fixture = new PublisherFixture("publisher-candidate-identity");
        var clientSource = fixture.Config.Artifacts[0].SourcePath;
        var hardLink = clientSource + ".hard-link";
        var anchorBefore = SnapshotDirectoryFiles(
            fixture.SigningLedgerAnchorAuthorityRoot);
        var ledgerBefore = SnapshotDirectoryFiles(fixture.Config.SigningLedgerRoot);
        CreateHardLinkForTest(hardLink, clientSource);
        await AssertThrowsAsync<InvalidDataException>(() =>
            fixture.CreatePublisher().PublishAsync(fixture.Config, fixture.Key, Now));
        AssertFalse(File.Exists(fixture.Config.OutputManifestPath));
        AssertEqual(
            anchorBefore,
            SnapshotDirectoryFiles(fixture.SigningLedgerAnchorAuthorityRoot));
        AssertEqual(
            ledgerBefore,
            SnapshotDirectoryFiles(fixture.Config.SigningLedgerRoot));
        File.Delete(hardLink);

        var racedHardLink = clientSource + ".raced-hard-link";
        var hardLinkRacePublisher = fixture.CreatePublisher(
            beforeFinalCancellationCheckpoint: () =>
                CreateHardLinkForTest(racedHardLink, clientSource));
        await AssertThrowsAsync<InvalidDataException>(() =>
            hardLinkRacePublisher.PublishAsync(fixture.Config, fixture.Key, Now));
        AssertTrue(File.Exists(racedHardLink));
        AssertFalse(File.Exists(fixture.Config.OutputManifestPath));
        AssertEqual(
            anchorBefore,
            SnapshotDirectoryFiles(fixture.SigningLedgerAnchorAuthorityRoot));
        AssertEqual(
            ledgerBefore,
            SnapshotDirectoryFiles(fixture.Config.SigningLedgerRoot));
        AssertFalse(Directory.EnumerateFiles(
            Path.GetDirectoryName(fixture.Config.OutputManifestPath)!,
            $".{Path.GetFileName(fixture.Config.OutputManifestPath)}.*.tmp")
            .Any());
        File.Delete(racedHardLink);

        var replacement = clientSource + ".replacement";
        var renamed = clientSource + ".renamed";
        File.Copy(clientSource, replacement);
        var renameDenied = false;
        var replaceDenied = false;
        var publisher = fixture.CreatePublisher(
            beforeFinalCancellationCheckpoint: () =>
            {
                AssertMutationDenied(() => File.Move(clientSource, renamed));
                renameDenied = true;
                AssertMutationDenied(() =>
                    File.Move(replacement, clientSource, overwrite: true));
                replaceDenied = true;
            });
        var result = await publisher.PublishAsync(fixture.Config, fixture.Key, Now);
        AssertTrue(renameDenied);
        AssertTrue(replaceDenied);
        AssertTrue(File.Exists(clientSource));
        AssertFalse(File.Exists(renamed));
        AssertTrue(File.Exists(replacement));
        AssertEqual(fixture.Config.Sequence, result.Verified.Manifest.Sequence);
        AssertEqual(Sha256(fixture.ClientBundleBytes), result.Verified.Manifest.ClientBundle.Sha256);
    }

    private static async Task PublisherLeavesNoPreCommitPlaintextAsync()
    {
        using var fixture = new PublisherFixture("publisher-no-precommit-plaintext");
        using var cancellation = new CancellationTokenSource();
        var outputRoot = Path.GetDirectoryName(fixture.Config.OutputManifestPath)!;
        var before = SnapshotDirectoryFiles(outputRoot);
        var temporaryFilesObserved = new List<string>();
        using var watcher = new FileSystemWatcher(outputRoot)
        {
            IncludeSubdirectories = true,
            EnableRaisingEvents = true,
        };
        watcher.Created += (_, args) =>
        {
            if (args.FullPath.EndsWith(".tmp", StringComparison.OrdinalIgnoreCase))
            {
                lock (temporaryFilesObserved)
                {
                    temporaryFilesObserved.Add(args.FullPath);
                }
            }
        };
        var checkpointReached = false;
        var publisher = fixture.CreatePublisher(
            beforeFinalCancellationCheckpoint: () =>
            {
                checkpointReached = true;
                AssertFalse(File.Exists(fixture.Config.OutputManifestPath));
                AssertFalse(File.Exists(
                    fixture.SigningLedgerAnchorPath + ".pending.v2"));
                lock (temporaryFilesObserved)
                {
                    AssertEqual(0, temporaryFilesObserved.Count);
                }
                cancellation.Cancel();
            });

        await AssertThrowsAsync<OperationCanceledException>(() =>
            publisher.PublishAsync(
                fixture.Config,
                fixture.Key,
                Now,
                cancellation.Token));
        watcher.EnableRaisingEvents = false;
        AssertTrue(checkpointReached);
        lock (temporaryFilesObserved)
        {
            AssertEqual(0, temporaryFilesObserved.Count);
        }
        AssertEqual(before, SnapshotDirectoryFiles(outputRoot));
        AssertFalse(File.Exists(fixture.Config.OutputManifestPath));
        AssertFalse(File.Exists(fixture.SigningLedgerAnchorPath + ".pending.v2"));
    }

    private static async Task PublisherRejectsEmptyTreeAsync()
    {
        using var fixture = new PublisherFixture("publisher-empty-tree");
        File.WriteAllBytes(
            fixture.Config.Artifacts[0].CompleteTreeManifestPath,
            Array.Empty<byte>());
        await AssertThrowsAsync<InvalidDataException>(() =>
            fixture.CreatePublisher().PublishAsync(fixture.Config, fixture.Key, Now));
        AssertFalse(File.Exists(fixture.Config.OutputManifestPath));
    }

    private static async Task PublisherTrustGateAsync()
    {
        using var fixture = new PublisherFixture("publisher-trust");
        using var wrongKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        await AssertThrowsAsync<InvalidDataException>(() =>
            fixture.CreatePublisher().PublishAsync(fixture.Config, wrongKey, Now));

        var incompatible = fixture.Config with
        {
            StartupStub = new PersonalStartupStubCompatibility
            {
                MinimumVersion = "2.0.0",
                MaximumVersion = "2.9.9",
            },
        };
        await AssertThrowsAsync<InvalidDataException>(() =>
            fixture.CreatePublisher().PublishAsync(incompatible, fixture.Key, Now));
    }

    private static async Task PublisherConfigStrictAsync()
    {
        using var fixture = new PublisherFixture("publisher-config");
        var json = JsonSerializer.Serialize(fixture.Config, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        var duplicate = Encoding.UTF8.GetBytes(json.Replace(
            "\"schemaVersion\":1",
            "\"schemaVersion\":1,\"schemaVersion\":1",
            StringComparison.Ordinal));
        await AssertThrowsAsync<InvalidDataException>(() => Task.Run(() =>
            PersonalReleasePublisherConfig.Parse(duplicate)));
        var unknown = Encoding.UTF8.GetBytes(json[..^1] + ",\"unknown\":true}");
        await AssertThrowsAsync<InvalidDataException>(() => Task.Run(() =>
            PersonalReleasePublisherConfig.Parse(unknown)));
    }

    private static async Task PublisherSignerLedgerRejectsRollbackAsync()
    {
        using var fixture = new PublisherFixture("publisher-ledger");
        var publisher = fixture.CreatePublisher();
        await publisher.PublishAsync(fixture.Config, fixture.Key, Now);
        var rollback = fixture.Config with
        {
            ReleaseSetId = "personal-set-rollback",
            Generation = 9,
            Sequence = 9,
            MinAcceptedSequence = 8,
            RevokedReleaseSetIds = [],
            OutputManifestPath = Path.Combine(
                Path.GetDirectoryName(fixture.Config.OutputManifestPath)!,
                "rollback.release-set-v2.json"),
        };
        await AssertThrowsAsync<InvalidDataException>(() =>
            publisher.PublishAsync(rollback, fixture.Key, Now));
        AssertFalse(File.Exists(rollback.OutputManifestPath));
    }

    private static async Task PublisherLedgerAnchorRequiresExplicitInitializationAsync()
    {
        using var fixture = new PublisherFixture(
            "publisher-ledger-explicit-initialization",
            initializeLedgerAnchor: false);
        await AssertThrowsAsync<InvalidDataException>(() =>
            fixture.CreatePublisher().PublishAsync(fixture.Config, fixture.Key, Now));
        AssertFalse(File.Exists(fixture.Config.OutputManifestPath));

        fixture.InitializeLedgerAnchor();
        var result = await fixture.CreatePublisher().PublishAsync(fixture.Config, fixture.Key, Now);
        AssertEqual(fixture.Config.Sequence, result.Verified.Manifest.Sequence);
        AssertThrows<InvalidOperationException>(() =>
            fixture.InitializeLedgerAnchor());
    }

    private static async Task PublisherLedgerAnchorRejectsEmptyResetAsync()
    {
        using (var fixture = new PublisherFixture("publisher-ledger-empty-reset"))
        {
            await fixture.CreatePublisher().PublishAsync(fixture.Config, fixture.Key, Now);
            Directory.Delete(fixture.Config.SigningLedgerRoot, recursive: true);
            var next = NextPublisherConfig(fixture.Config, "missing-root", 11, 11);
            await AssertThrowsAsync<InvalidDataException>(() =>
                fixture.CreatePublisher().PublishAsync(next, fixture.Key, Now));
            AssertFalse(Directory.Exists(fixture.Config.SigningLedgerRoot));
            AssertFalse(File.Exists(next.OutputManifestPath));

            Directory.CreateDirectory(Path.Combine(fixture.Config.SigningLedgerRoot, "stable"));
            var empty = NextPublisherConfig(fixture.Config, "empty-root", 11, 11);
            await AssertThrowsAsync<InvalidDataException>(() =>
                fixture.CreatePublisher().PublishAsync(empty, fixture.Key, Now));
            AssertFalse(File.Exists(empty.OutputManifestPath));
        }

        using (var fixture = new PublisherFixture("publisher-ledger-missing-anchor"))
        {
            await fixture.CreatePublisher().PublishAsync(fixture.Config, fixture.Key, Now);
            File.Delete(fixture.SigningLedgerAnchorPath);
            var next = NextPublisherConfig(fixture.Config, "missing-anchor", 11, 11);
            await AssertThrowsAsync<InvalidDataException>(() =>
                fixture.CreatePublisher().PublishAsync(next, fixture.Key, Now));
            AssertFalse(File.Exists(next.OutputManifestPath));
        }
    }

    private static async Task PublisherLedgerAnchorRejectsReplayAsync()
    {
        using var fixture = new PublisherFixture("publisher-ledger-replay");
        await fixture.CreatePublisher().PublishAsync(fixture.Config, fixture.Key, Now);
        var replay = NewTempPath("publisher-ledger-replay", "old-ledger");
        CopyDirectory(fixture.Config.SigningLedgerRoot, replay);

        var second = NextPublisherConfig(fixture.Config, "second", 11, 11);
        await fixture.CreatePublisher().PublishAsync(second, fixture.Key, Now);
        Directory.Delete(fixture.Config.SigningLedgerRoot, recursive: true);
        CopyDirectory(replay, fixture.Config.SigningLedgerRoot);

        var third = NextPublisherConfig(fixture.Config, "third", 12, 12);
        await AssertThrowsAsync<InvalidDataException>(() =>
            fixture.CreatePublisher().PublishAsync(third, fixture.Key, Now));
        AssertFalse(File.Exists(third.OutputManifestPath));
    }

    private static async Task PublisherLedgerAnchorAuthorityCannotBeRedirectedAsync()
    {
        using var fixture = new PublisherFixture("publisher-ledger-anchor-authority");
        await fixture.CreatePublisher().PublishAsync(fixture.Config, fixture.Key, Now);

        var alternateLedgerRoot = Path.Combine(
            Path.GetDirectoryName(fixture.Config.SigningLedgerRoot)!,
            "attacker-selected-ledger");
        CopyDirectory(fixture.Config.SigningLedgerRoot, alternateLedgerRoot);
        var switchedRoot = NextPublisherConfig(fixture.Config, "switched-root", 11, 11) with
        {
            SigningLedgerRoot = alternateLedgerRoot,
        };
        AssertEqual(
            fixture.SigningLedgerAnchorPath,
            PersonalPublisherSigningLedger.GetAnchorPath(
                switchedRoot,
                fixture.SigningLedgerAnchorAuthorityRoot));
        await AssertThrowsAsync<InvalidDataException>(() =>
            fixture.CreatePublisher().PublishAsync(switchedRoot, fixture.Key, Now));
        AssertFalse(File.Exists(switchedRoot.OutputManifestPath));

        var json = JsonSerializer.Serialize(
            fixture.Config,
            new JsonSerializerOptions(JsonSerializerDefaults.Web));
        var redirectedAnchor = Encoding.UTF8.GetBytes(
            json[..^1] + ",\"signingLedgerAnchorPath\":\"C:\\\\attacker\\\\anchor.dpapi\"}");
        await AssertThrowsAsync<InvalidDataException>(() => Task.Run(() =>
            PersonalReleasePublisherConfig.Parse(redirectedAnchor)));
    }

    private static async Task PublisherDevelopmentAuthorityIsolatedFromForeignAnchorAsync()
    {
        using var fixture = new PublisherFixture("publisher-development-foreign-anchor");
        await fixture.CreatePublisher().PublishAsync(fixture.Config, fixture.Key, Now);
        var foreignAnchorBytes = File.ReadAllBytes(fixture.SigningLedgerAnchorPath);

        var isolatedRoot = NewTempPath(
            "publisher-development-isolated-anchor",
            "input");
        Directory.CreateDirectory(isolatedRoot);
        var isolatedConfig = fixture.Config with
        {
            ReleaseSetId = "personal-set-development-isolated",
            SigningLedgerRoot = Path.Combine(isolatedRoot, "signing-ledger"),
            OutputManifestPath = Path.Combine(
                isolatedRoot,
                "stable.release-set-v2.json"),
        };

        await AssertThrowsAsync<InvalidDataException>(() =>
            new Publisher(null, fixture.SigningLedgerAnchorAuthorityRoot)
                .PublishAsync(isolatedConfig, fixture.Key, Now));

        var isolatedAuthorityRoot = Path.Combine(isolatedRoot, "anchor-authority");
        var isolatedAnchorPath = PersonalPublisherSigningLedger.InitializeAnchor(
            isolatedConfig,
            isolatedAuthorityRoot);
        AssertFalse(string.Equals(
            fixture.SigningLedgerAnchorPath,
            isolatedAnchorPath,
            StringComparison.OrdinalIgnoreCase));

        var result = await new Publisher(null, isolatedAuthorityRoot)
            .PublishAsync(isolatedConfig, fixture.Key, Now);
        AssertEqual(isolatedConfig.ReleaseSetId, result.Verified.Manifest.ReleaseSetId);
        AssertSequenceEqual(
            foreignAnchorBytes,
            File.ReadAllBytes(fixture.SigningLedgerAnchorPath));
    }

    private static async Task PublisherLedgerAnchorCrashRecoveryAsync()
    {
        foreach (var crashStage in Enum.GetValues<PersonalPublisherSigningLedgerCommitStage>())
        {
            using var fixture = new PublisherFixture(
                $"publisher-ledger-crash-{crashStage}");
            var crashingPublisher = fixture.CreatePublisher(stage =>
            {
                if (stage == crashStage)
                {
                    throw new IOException($"simulated signing-ledger crash at {stage}");
                }
            });
            await AssertThrowsAsync<IOException>(() =>
                crashingPublisher.PublishAsync(fixture.Config, fixture.Key, Now));
            AssertEqual(
                crashStage != PersonalPublisherSigningLedgerCommitStage.PendingDeleted,
                File.Exists(fixture.SigningLedgerAnchorPath + ".pending.v2"));
            AssertEqual(
                crashStage is PersonalPublisherSigningLedgerCommitStage.ManifestPublished
                    or PersonalPublisherSigningLedgerCommitStage.PublicationReceiptCommitted
                    or PersonalPublisherSigningLedgerCommitStage.PendingDeleted,
                File.Exists(fixture.Config.OutputManifestPath));

            var result = await fixture.CreatePublisher().PublishAsync(
                fixture.Config,
                fixture.Key,
                Now);
            AssertEqual(fixture.Config.Sequence, result.Verified.Manifest.Sequence);
            AssertFalse(File.Exists(fixture.SigningLedgerAnchorPath + ".pending.v2"));
            AssertTrue(File.Exists(fixture.SigningLedgerAnchorPath + ".publication.v2"));
            var recovered = PersonalReleaseSetValidator.ParseAndVerify(
                File.ReadAllBytes(fixture.Config.OutputManifestPath),
                fixture.Policy,
                Now);
            AssertEqual(fixture.Config.Sequence, recovered.Manifest.Sequence);

            var secondRetry = await fixture.CreatePublisher().PublishAsync(
                fixture.Config,
                fixture.Key,
                Now);
            AssertEqual(result.Sha256, secondRetry.Sha256);

            var next = NextPublisherConfig(fixture.Config, "after-crash", 11, 11);
            var nextResult = await fixture.CreatePublisher().PublishAsync(
                next,
                fixture.Key,
                Now);
            AssertEqual(next.Sequence, nextResult.Verified.Manifest.Sequence);
        }
    }

    private static async Task PublisherSchemaV2FenceBlocksLegacyMutationAsync()
    {
        using (var fixture = new PublisherFixture("publisher-schema-v2-fence"))
        {
            RewriteProtectedJsonForTest(
                fixture,
                fixture.SigningLedgerAnchorPath,
                root => root["schemaVersion"] = 1);
            AssertEqual(1, ReadProtectedSchemaVersionForTest(
                fixture,
                fixture.SigningLedgerAnchorPath));

            var configPath = Path.Combine(
                Path.GetDirectoryName(fixture.Config.OutputManifestPath)!,
                "schema-v2-fence-config.json");
            File.WriteAllBytes(
                configPath,
                JsonSerializer.SerializeToUtf8Bytes(
                    fixture.Config,
                    new JsonSerializerOptions(JsonSerializerDefaults.Web)));
            var mutationSentinel = Path.Combine(
                Path.GetDirectoryName(fixture.Config.OutputManifestPath)!,
                "legacy-v1-would-mutate-n-plus-one.txt");
            var concurrentLegacyWasSerialized = false;
            var publisher = fixture.CreatePublisher(
                beforeFinalCancellationCheckpoint: () =>
                {
                    var locked = RunLegacyV1ProbeProcess(
                        configPath,
                        fixture.SigningLedgerAnchorPath,
                        mutationSentinel);
                    AssertEqual(41, locked.ExitCode);
                    AssertTrue(locked.Error.Contains(
                        "anchor lock",
                        StringComparison.Ordinal));
                    AssertFalse(File.Exists(mutationSentinel));
                    concurrentLegacyWasSerialized = true;
                });

            var result = await publisher.PublishAsync(
                fixture.Config,
                fixture.Key,
                Now);
            AssertTrue(concurrentLegacyWasSerialized);
            AssertEqual(fixture.Config.Sequence, result.Verified.Manifest.Sequence);
            AssertEqual(2, ReadProtectedSchemaVersionForTest(
                fixture,
                fixture.SigningLedgerAnchorPath));

            var afterRelease = RunLegacyV1ProbeProcess(
                configPath,
                fixture.SigningLedgerAnchorPath,
                mutationSentinel);
            AssertEqual(42, afterRelease.ExitCode);
            AssertTrue(afterRelease.Error.Contains(
                "schema-v2 downgrade fence",
                StringComparison.Ordinal));
            AssertFalse(File.Exists(mutationSentinel));
        }

        // Compatibility: the pre-fence publisher could already have written an
        // authenticated .pending.v2 whose nested anchors were schema v1. The
        // new publisher must fence first and then recover that exact intent.
        using (var fixture = new PublisherFixture(
                   "publisher-schema-v1-pending-v2-compatibility"))
        {
            var crashingPublisher = fixture.CreatePublisher(stage =>
            {
                if (stage == PersonalPublisherSigningLedgerCommitStage.PendingAnchorWritten)
                {
                    throw new IOException(
                        "simulated pre-fence crash after protected pending write");
                }
            });
            await AssertThrowsAsync<IOException>(() =>
                crashingPublisher.PublishAsync(fixture.Config, fixture.Key, Now));
            var pendingPath = fixture.SigningLedgerAnchorPath + ".pending.v2";
            AssertTrue(File.Exists(pendingPath));

            RewriteProtectedJsonForTest(
                fixture,
                fixture.SigningLedgerAnchorPath,
                root => root["schemaVersion"] = 1);
            RewriteProtectedJsonForTest(
                fixture,
                pendingPath,
                root =>
                {
                    root["previousAnchor"]!["schemaVersion"] = 1;
                    root["nextAnchor"]!["schemaVersion"] = 1;
                });

            var recovered = await fixture.CreatePublisher().PublishAsync(
                fixture.Config,
                fixture.Key,
                Now);
            AssertEqual(fixture.Config.Sequence, recovered.Verified.Manifest.Sequence);
            AssertEqual(2, ReadProtectedSchemaVersionForTest(
                fixture,
                fixture.SigningLedgerAnchorPath));
            AssertFalse(File.Exists(pendingPath));
            AssertTrue(File.Exists(fixture.Config.OutputManifestPath));
        }
    }

    private static async Task PublisherCommitCompletionIgnoresLateCancellationAsync()
    {
        using var fixture = new PublisherFixture("publisher-late-cancellation");
        using var cancellation = new CancellationTokenSource();
        var publisher = fixture.CreatePublisher(stage =>
        {
            if (stage == PersonalPublisherSigningLedgerCommitStage.PendingDeleted)
            {
                cancellation.Cancel();
            }
        });

        var result = await publisher.PublishAsync(
            fixture.Config,
            fixture.Key,
            Now,
            cancellation.Token);
        AssertTrue(cancellation.IsCancellationRequested);
        AssertEqual(fixture.Config.Sequence, result.Verified.Manifest.Sequence);
        AssertFalse(File.Exists(fixture.SigningLedgerAnchorPath + ".pending.v2"));
        AssertTrue(File.Exists(fixture.SigningLedgerAnchorPath + ".publication.v2"));

        var retry = await fixture.CreatePublisher().PublishAsync(
            fixture.Config,
            fixture.Key,
            Now);
        AssertEqual(result.Sha256, retry.Sha256);
    }

    private static async Task PublisherCommittedCleanupFailureAllowsExactRetryOnlyAsync()
    {
        using var fixture = new PublisherFixture("publisher-committed-cleanup-blocked");
        FileStream? pendingDeleteBlocker = null;
        var publisher = fixture.CreatePublisher(stage =>
        {
            if (stage == PersonalPublisherSigningLedgerCommitStage.PublicationReceiptCommitted)
            {
                pendingDeleteBlocker = new FileStream(
                    fixture.SigningLedgerAnchorPath + ".pending.v2",
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.Read);
                AssertMutationDenied(() => File.Delete(
                    fixture.SigningLedgerAnchorPath + ".pending.v2"));
            }
        });

        try
        {
            var committed = await publisher.PublishAsync(
                fixture.Config,
                fixture.Key,
                Now);
            AssertEqual(fixture.Config.Sequence, committed.Verified.Manifest.Sequence);
            AssertTrue(File.Exists(fixture.Config.OutputManifestPath));
            AssertTrue(File.Exists(fixture.SigningLedgerAnchorPath + ".publication.v2"));
            AssertTrue(File.Exists(fixture.SigningLedgerAnchorPath + ".pending.v2"));

            var anchorBefore = SnapshotDirectoryFiles(
                fixture.SigningLedgerAnchorAuthorityRoot);
            var ledgerBefore = SnapshotDirectoryFiles(fixture.Config.SigningLedgerRoot);
            var exactRetry = await fixture.CreatePublisher().PublishAsync(
                fixture.Config,
                fixture.Key,
                Now);
            AssertEqual(committed.Sha256, exactRetry.Sha256);
            AssertTrue(File.Exists(fixture.SigningLedgerAnchorPath + ".pending.v2"));

            var next = NextPublisherConfig(
                fixture.Config,
                "cleanup-blocked-next",
                11,
                11);
            using var unrelatedPrivateKey = ECDsa.Create(
                ECCurve.NamedCurves.nistP256);
            await AssertThrowsAsync<InvalidOperationException>(() =>
                fixture.CreatePublisher().PublishAsync(
                    next,
                    unrelatedPrivateKey,
                    Now));
            AssertFalse(File.Exists(next.OutputManifestPath));
            AssertEqual(
                anchorBefore,
                SnapshotDirectoryFiles(fixture.SigningLedgerAnchorAuthorityRoot));
            AssertEqual(
                ledgerBefore,
                SnapshotDirectoryFiles(fixture.Config.SigningLedgerRoot));

            AssertTrue(pendingDeleteBlocker is not null);
            pendingDeleteBlocker?.Dispose();
            pendingDeleteBlocker = null;
            var nextResult = await fixture.CreatePublisher().PublishAsync(
                next,
                fixture.Key,
                Now);
            AssertEqual(next.Sequence, nextResult.Verified.Manifest.Sequence);
            AssertFalse(File.Exists(fixture.SigningLedgerAnchorPath + ".pending.v2"));
        }
        finally
        {
            pendingDeleteBlocker?.Dispose();
        }
    }

    private static async Task PublisherPublicationConflictFailsClosedAsync()
    {
        using var fixture = new PublisherFixture("publisher-publication-conflict");
        var crashingPublisher = fixture.CreatePublisher(stage =>
        {
            if (stage == PersonalPublisherSigningLedgerCommitStage.AnchorCommitted)
            {
                throw new IOException("simulated crash before manifest publication");
            }
        });
        await AssertThrowsAsync<IOException>(() =>
            crashingPublisher.PublishAsync(fixture.Config, fixture.Key, Now));
        AssertTrue(File.Exists(fixture.SigningLedgerAnchorPath + ".pending.v2"));
        AssertFalse(File.Exists(fixture.Config.OutputManifestPath));

        var conflictingBytes = "conflicting release manifest"u8.ToArray();
        File.WriteAllBytes(fixture.Config.OutputManifestPath, conflictingBytes);
        var next = NextPublisherConfig(fixture.Config, "after-conflict", 11, 11);
        await AssertThrowsAsync<IOException>(() =>
            fixture.CreatePublisher().PublishAsync(next, fixture.Key, Now));

        AssertSequenceEqual(
            conflictingBytes,
            File.ReadAllBytes(fixture.Config.OutputManifestPath));
        AssertTrue(File.Exists(fixture.SigningLedgerAnchorPath + ".pending.v2"));
        AssertFalse(File.Exists(next.OutputManifestPath));
    }

    private static async Task PublisherUpgradeCheckLeavesLegacyPendingUntouchedAsync()
    {
        using var fixture = new PublisherFixture("publisher-legacy-pending-upgrade");
        var configPath = Path.Combine(
            Path.GetDirectoryName(fixture.Config.OutputManifestPath)!,
            "publisher-config.json");
        var readinessOnlyConfig = fixture.Config with
        {
            SigningPrivateKeyPkcs8Path = Path.Combine(
                Path.GetDirectoryName(fixture.Config.SigningPrivateKeyPkcs8Path)!,
                "missing-private-key-for-read-only-upgrade-check.pk8"),
        };
        File.WriteAllBytes(
            configPath,
            JsonSerializer.SerializeToUtf8Bytes(
                readinessOnlyConfig,
                new JsonSerializerOptions(JsonSerializerDefaults.Web)));
        AssertFalse(File.Exists(readinessOnlyConfig.SigningPrivateKeyPkcs8Path));

        var readyBefore = SnapshotDirectoryFiles(
            fixture.SigningLedgerAnchorAuthorityRoot);
        var ready = await RunPublisherUpgradeCheckAsync(fixture, configPath);
        AssertEqual(0, ready.ExitCode);
        AssertTrue(ready.Output.Contains("READY:", StringComparison.Ordinal));
        AssertEqual(
            readyBefore,
            SnapshotDirectoryFiles(fixture.SigningLedgerAnchorAuthorityRoot));

        RewriteProtectedJsonForTest(
            fixture,
            fixture.SigningLedgerAnchorPath,
            root => root["schemaVersion"] = 1);
        var legacyAnchorBytes = File.ReadAllBytes(
            fixture.SigningLedgerAnchorPath);
        var legacyPendingPath = fixture.SigningLedgerAnchorPath + ".pending";
        var v2PendingPath = fixture.SigningLedgerAnchorPath + ".pending.v2";
        var legacyBytes = "legacy publisher pending bytes must remain untouched"u8.ToArray();
        File.WriteAllBytes(legacyPendingPath, legacyBytes);
        var legacyBefore = SnapshotDirectoryFiles(
            fixture.SigningLedgerAnchorAuthorityRoot);
        var legacy = await RunPublisherUpgradeCheckAsync(fixture, configPath);
        AssertEqual(1, legacy.ExitCode);
        AssertTrue(legacy.Error.Contains(
            "legacy '.pending' state",
            StringComparison.Ordinal));
        AssertEqual(
            legacyBefore,
            SnapshotDirectoryFiles(fixture.SigningLedgerAnchorAuthorityRoot));
        AssertSequenceEqual(legacyBytes, File.ReadAllBytes(legacyPendingPath));
        await AssertThrowsAsync<InvalidDataException>(() =>
            fixture.CreatePublisher().PublishAsync(fixture.Config, fixture.Key, Now));
        AssertThrows<InvalidDataException>(() => fixture.InitializeLedgerAnchor());
        AssertSequenceEqual(legacyBytes, File.ReadAllBytes(legacyPendingPath));
        AssertSequenceEqual(
            legacyAnchorBytes,
            File.ReadAllBytes(fixture.SigningLedgerAnchorPath));

        var v2Bytes = "v2 pending conflict bytes"u8.ToArray();
        File.WriteAllBytes(v2PendingPath, v2Bytes);
        var conflictBefore = SnapshotDirectoryFiles(
            fixture.SigningLedgerAnchorAuthorityRoot);
        var conflict = await RunPublisherUpgradeCheckAsync(fixture, configPath);
        AssertEqual(1, conflict.ExitCode);
        AssertTrue(conflict.Error.Contains(
            "conflicting legacy and v2 pending markers",
            StringComparison.Ordinal));
        AssertEqual(
            conflictBefore,
            SnapshotDirectoryFiles(fixture.SigningLedgerAnchorAuthorityRoot));
        AssertSequenceEqual(legacyBytes, File.ReadAllBytes(legacyPendingPath));
        AssertSequenceEqual(v2Bytes, File.ReadAllBytes(v2PendingPath));

        File.Delete(v2PendingPath);
        File.Delete(legacyPendingPath);
        var hardLinkTarget = Path.Combine(
            fixture.SigningLedgerAnchorAuthorityRoot,
            "legacy-pending-hard-link-target.bin");
        File.WriteAllBytes(hardLinkTarget, legacyBytes);
        CreateHardLinkForTest(legacyPendingPath, hardLinkTarget);
        var linkBefore = SnapshotDirectoryFiles(
            fixture.SigningLedgerAnchorAuthorityRoot);
        var linked = await RunPublisherUpgradeCheckAsync(fixture, configPath);
        AssertEqual(1, linked.ExitCode);
        AssertTrue(linked.Error.Contains("hard link", StringComparison.Ordinal));
        AssertEqual(
            linkBefore,
            SnapshotDirectoryFiles(fixture.SigningLedgerAnchorAuthorityRoot));
        AssertSequenceEqual(legacyBytes, File.ReadAllBytes(legacyPendingPath));
        AssertSequenceEqual(legacyBytes, File.ReadAllBytes(hardLinkTarget));
    }

    private static async Task<(int ExitCode, string Output, string Error)>
        RunPublisherUpgradeCheckAsync(
            PublisherFixture fixture,
            string configPath)
    {
        using var output = new StringWriter();
        using var error = new StringWriter();
        var exitCode = await Ensou.Dsh.Personal.ReleasePublisher.Program.RunAsync(
            ["--check-signing-ledger-upgrade-ready", "--config", configPath],
            fixture.SigningLedgerAnchorAuthorityRoot,
            output,
            error);
        return (exitCode, output.ToString(), error.ToString());
    }

    private static int RunLegacyV1AnchorAdmissionProbe(
        string configPath,
        string anchorPath,
        string mutationSentinel)
    {
        try
        {
            using var anchorLock = new FileStream(
                anchorPath + ".lock",
                FileMode.OpenOrCreate,
                FileAccess.ReadWrite,
                FileShare.None,
                1,
                FileOptions.WriteThrough);
            var config = PersonalReleasePublisherConfig.Parse(
                File.ReadAllBytes(Path.GetFullPath(configPath)));
            var protectedBytes = File.ReadAllBytes(Path.GetFullPath(anchorPath));
            byte[]? plaintext = null;
            try
            {
                plaintext = ProtectedData.Unprotect(
                    protectedBytes,
                    GetSigningLedgerAnchorEntropyForTest(config),
                    DataProtectionScope.CurrentUser);
                using var document = JsonDocument.Parse(plaintext);
                var schemaVersion = document.RootElement
                    .GetProperty("schemaVersion")
                    .GetInt32();
                if (schemaVersion != 1)
                {
                    Console.Error.WriteLine(
                        $"Legacy v1 publisher {LegacyPublisherV1SourceCommit} rejected the schema-v2 downgrade fence before N+1 mutation.");
                    return 42;
                }

                File.WriteAllText(
                    Path.GetFullPath(mutationSentinel),
                    "legacy v1 anchor admission would permit N+1 mutation",
                    Encoding.UTF8);
                return 0;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(protectedBytes);
                if (plaintext is not null)
                {
                    CryptographicOperations.ZeroMemory(plaintext);
                }
            }
        }
        catch (IOException exception)
        {
            Console.Error.WriteLine(
                $"Legacy v1 publisher could not acquire the shared anchor lock: {exception.Message}");
            return 41;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine(exception.Message);
            return 43;
        }
    }

    private static (int ExitCode, string Output, string Error)
        RunLegacyV1ProbeProcess(
            string configPath,
            string anchorPath,
            string mutationSentinel)
    {
        var processPath = Environment.ProcessPath
            ?? throw new InvalidOperationException(
                "Could not resolve the current personal update test process path.");
        var startInfo = new ProcessStartInfo
        {
            FileName = processPath,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        if (string.Equals(
                Path.GetFileNameWithoutExtension(processPath),
                "dotnet",
                StringComparison.OrdinalIgnoreCase))
        {
            startInfo.ArgumentList.Add(typeof(Program).Assembly.Location);
        }
        startInfo.ArgumentList.Add("--legacy-v1-anchor-admission-probe");
        startInfo.ArgumentList.Add(configPath);
        startInfo.ArgumentList.Add(anchorPath);
        startInfo.ArgumentList.Add(mutationSentinel);
        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException(
                "Could not start the frozen legacy-v1 publisher admission probe.");
        var output = process.StandardOutput.ReadToEnd();
        var error = process.StandardError.ReadToEnd();
        if (!process.WaitForExit(10_000))
        {
            process.Kill(entireProcessTree: true);
            process.WaitForExit(5_000);
            throw new TimeoutException(
                "Frozen legacy-v1 publisher admission probe did not exit.");
        }
        return (process.ExitCode, output, error);
    }

    private static int ReadProtectedSchemaVersionForTest(
        PublisherFixture fixture,
        string path)
    {
        var protectedBytes = File.ReadAllBytes(path);
        byte[]? plaintext = null;
        try
        {
            plaintext = ProtectedData.Unprotect(
                protectedBytes,
                GetSigningLedgerAnchorEntropyForTest(fixture.Config),
                DataProtectionScope.CurrentUser);
            using var document = JsonDocument.Parse(plaintext);
            return document.RootElement.GetProperty("schemaVersion").GetInt32();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(protectedBytes);
            if (plaintext is not null)
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }
    }

    private static void RewriteProtectedJsonForTest(
        PublisherFixture fixture,
        string path,
        Action<JsonObject> mutation)
    {
        var protectedBytes = File.ReadAllBytes(path);
        byte[]? plaintext = null;
        byte[]? replacementPlaintext = null;
        byte[]? replacementProtected = null;
        var temporary = path + $".{Guid.NewGuid():N}.test-rewrite";
        try
        {
            plaintext = ProtectedData.Unprotect(
                protectedBytes,
                GetSigningLedgerAnchorEntropyForTest(fixture.Config),
                DataProtectionScope.CurrentUser);
            var root = JsonNode.Parse(plaintext) as JsonObject
                ?? throw new InvalidDataException(
                    "Protected personal publisher test state is not an object.");
            mutation(root);
            replacementPlaintext = JsonSerializer.SerializeToUtf8Bytes(
                root,
                new JsonSerializerOptions(JsonSerializerDefaults.Web)
                {
                    WriteIndented = true,
                });
            replacementProtected = ProtectedData.Protect(
                replacementPlaintext,
                GetSigningLedgerAnchorEntropyForTest(fixture.Config),
                DataProtectionScope.CurrentUser);
            File.WriteAllBytes(temporary, replacementProtected);
            File.Move(temporary, path, overwrite: true);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(protectedBytes);
            if (plaintext is not null)
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }
            if (replacementPlaintext is not null)
            {
                CryptographicOperations.ZeroMemory(replacementPlaintext);
            }
            if (replacementProtected is not null)
            {
                CryptographicOperations.ZeroMemory(replacementProtected);
            }
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
            }
        }
    }

    private static byte[] GetSigningLedgerAnchorEntropyForTest(
        PersonalReleasePublisherConfig config)
    {
        var normalizedLedgerRoot = Path.TrimEndingDirectorySeparator(
            Path.GetFullPath(config.SigningLedgerRoot));
        return SHA256.HashData(Encoding.UTF8.GetBytes(string.Join(
            '|',
            PersonalReleaseSetContract.Product,
            config.Environment,
            config.Channel,
            normalizedLedgerRoot.ToUpperInvariant(),
            "personal-publisher-signing-ledger-anchor-v1")));
    }

    private static PersonalReleasePublisherConfig NextPublisherConfig(
        PersonalReleasePublisherConfig config,
        string suffix,
        long generation,
        long sequence) => config with
    {
        ReleaseSetId = $"personal-set-{suffix}",
        Generation = generation,
        Sequence = sequence,
        OutputManifestPath = Path.Combine(
            Path.GetDirectoryName(config.OutputManifestPath)!,
            $"{suffix}.release-set-v2.json"),
    };

    private static async Task PublisherPkcs8LoaderAsync()
    {
        using var fixture = new PublisherFixture("publisher-pkcs8");
        using (var loaded = await PersonalPrivateKeyLoader.LoadAsync(
                   fixture.Config.SigningPrivateKeyPkcs8Path))
        {
            var signature = loaded.SignData(
                "bounded-private-key"u8,
                HashAlgorithmName.SHA256);
            AssertTrue(signature.Length > 0);
            CryptographicOperations.ZeroMemory(signature);
        }
        File.AppendAllBytes(fixture.Config.SigningPrivateKeyPkcs8Path, [0x00]);
        await AssertThrowsAsync<InvalidDataException>(() =>
            PersonalPrivateKeyLoader.LoadAsync(fixture.Config.SigningPrivateKeyPkcs8Path));
    }

    private static async Task PublisherLinkedAncestorRejectedAsync()
    {
        using var fixture = new PublisherFixture("publisher-links");
        var linkRoot = NewTempPath("publisher-links", "junction-root");
        var targetRoot = NewTempPath("publisher-links", "junction-target");
        Directory.CreateDirectory(targetRoot);
        CreateDirectoryLinkForTest(linkRoot, targetRoot);
        try
        {
            var linkedKey = Path.Combine(linkRoot, "private-key.pk8");
            File.WriteAllBytes(
                Path.Combine(targetRoot, "private-key.pk8"),
                fixture.Key.ExportPkcs8PrivateKey());
            await AssertThrowsAsync<InvalidDataException>(() =>
                PersonalPrivateKeyLoader.LoadAsync(linkedKey));

            var linkedLedger = fixture.Config with
            {
                SigningLedgerRoot = Path.Combine(linkRoot, "ledger"),
                OutputManifestPath = Path.Combine(
                    Path.GetDirectoryName(fixture.Config.OutputManifestPath)!,
                    "linked-ledger.release-set-v2.json"),
            };
            await AssertThrowsAsync<InvalidDataException>(() =>
                fixture.CreatePublisher().PublishAsync(linkedLedger, fixture.Key, Now));
            AssertFalse(Directory.Exists(Path.Combine(targetRoot, "ledger")));
        }
        finally
        {
            if (Directory.Exists(linkRoot))
            {
                Directory.Delete(linkRoot);
            }
        }
    }

    private static Task PersonalAuthenticodeLockAsync()
    {
        var executable = NewTempPath("personal-authenticode", "candidate.exe");
        var replacement = NewTempPath("personal-authenticode", "replacement.exe");
        Directory.CreateDirectory(Path.GetDirectoryName(executable)!);
        Directory.CreateDirectory(Path.GetDirectoryName(replacement)!);
        File.WriteAllBytes(executable, "unsigned-personal-executable"u8.ToArray());
        File.WriteAllBytes(replacement, "replacement"u8.ToArray());
        using (var locked = PersonalAuthenticodeVerifier.OpenLockedExecutable(executable))
        {
            AssertThrows<IOException>(() =>
                File.Open(executable, FileMode.Open, FileAccess.Write, FileShare.Read).Dispose());
            AssertMutationDenied(() => File.Move(replacement, executable, overwrite: true));
            AssertTrue(locked.Length > 0);
        }
        AssertThrows<InvalidDataException>(() =>
            PersonalAuthenticodeVerifier.RequireTrustedSignature(
                executable,
                new string('a', 64)));
        AssertThrows<InvalidDataException>(() =>
            PersonalAuthenticodeVerifier.RequireSha256Thumbprint("not-a-thumbprint"));
        return Task.CompletedTask;
    }

    private static async Task PersonalTrustedLaunchLeaseBindsProcessIdentityAsync()
    {
        var root = NewTempPath("personal-trusted-launch", "root");
        Directory.CreateDirectory(root);
        var source = Environment.GetEnvironmentVariable("ComSpec")
            ?? throw new InvalidOperationException("ComSpec is unavailable.");
        var executable = Path.Combine(root, "verified-launcher.exe");
        var replacement = Path.Combine(root, "replacement.exe");
        var mismatched = Path.Combine(root, "mismatched.exe");
        var renamed = Path.Combine(root, "renamed.exe");
        File.Copy(source, executable);
        File.Copy(source, replacement);
        File.Copy(source, mismatched);

        var hardLinkedSource = Path.Combine(root, "hard-linked-source.exe");
        var hardLinkedAlias = Path.Combine(root, "hard-linked-alias.exe");
        File.Copy(source, hardLinkedSource);
        if (!CreateHardLink(
                hardLinkedAlias,
                hardLinkedSource,
                IntPtr.Zero))
        {
            throw new IOException(
                "Could not create the Personal trusted-launch hard-link fixture.",
                Marshal.GetExceptionForHR(Marshal.GetHRForLastWin32Error()));
        }
        AssertThrows<InvalidDataException>(() =>
            PersonalAuthenticodeVerifier
                .OpenExecutableForLaunchForTests(hardLinkedSource)
                .Dispose());

        var linkedRoot = NewTempPath("personal-trusted-launch", "linked-root");
        CreateDirectoryLinkForTest(linkedRoot, root);
        try
        {
            AssertThrows<InvalidDataException>(() =>
                PersonalAuthenticodeVerifier
                    .OpenExecutableForLaunchForTests(
                        Path.Combine(linkedRoot, Path.GetFileName(executable)))
                    .Dispose());
        }
        finally
        {
            Directory.Delete(linkedRoot);
        }

        using var lease = PersonalAuthenticodeVerifier
            .OpenExecutableForLaunchForTests(executable);
        using var cancellation = new CancellationTokenSource();
        using var beginRace = new ManualResetEventSlim();
        var mutationSucceeded = 0;
        var renameAttempts = 0;
        var replaceAttempts = 0;
        var deleteAttempts = 0;

        void AttemptMutation(Action mutation, ref int attempts)
        {
            Interlocked.Increment(ref attempts);
            try
            {
                mutation();
                Interlocked.Exchange(ref mutationSucceeded, 1);
                cancellation.Cancel();
            }
            catch (Exception exception) when (
                exception is IOException or UnauthorizedAccessException)
            {
                // The verified file lease must reject every mutation.
            }
        }

        var racer = Task.Run(() =>
        {
            beginRace.Wait();
            while (!cancellation.IsCancellationRequested)
            {
                AttemptMutation(
                    () => File.Move(executable, renamed),
                    ref renameAttempts);
                AttemptMutation(
                    () => File.Move(replacement, executable, overwrite: true),
                    ref replaceAttempts);
                AttemptMutation(
                    () => File.Delete(executable),
                    ref deleteAttempts);
                Thread.Yield();
            }
        });

        Process? process = null;
        try
        {
            beginRace.Set();
            AssertTrue(SpinWait.SpinUntil(
                () => Volatile.Read(ref renameAttempts) > 0
                    && Volatile.Read(ref replaceAttempts) > 0
                    && Volatile.Read(ref deleteAttempts) > 0,
                TimeSpan.FromSeconds(5)));
            var startInfo = CreateLongRunningCommand(executable, root);
            process = lease.Start(startInfo);
            AssertFalse(process.HasExited);
            AssertEqual(
                lease.Identity,
                lease.InspectProcessImageIdentityForTests(process));
            await Task.Delay(TimeSpan.FromMilliseconds(100)).ConfigureAwait(false);
        }
        finally
        {
            cancellation.Cancel();
            await racer.ConfigureAwait(false);
            StopProcess(process);
            process?.Dispose();
        }

        AssertEqual(0, mutationSucceeded);
        AssertTrue(renameAttempts > 0);
        AssertTrue(replaceAttempts > 0);
        AssertTrue(deleteAttempts > 0);
        AssertTrue(File.Exists(executable));
        AssertFalse(File.Exists(renamed));

        var mismatchedProcessId = 0;
        AssertThrows<InvalidDataException>(() => lease.StartForTests(
            CreateLongRunningCommand(executable, root),
            _ =>
            {
                var started = Process.Start(
                        CreateLongRunningCommand(mismatched, root))
                    ?? throw new InvalidOperationException(
                        "Personal mismatch cleanup process did not start.");
                mismatchedProcessId = started.Id;
                return started;
            },
            lease.InspectProcessImageIdentityForTests));
        AssertTrue(mismatchedProcessId > 0);
        AssertTrue(WaitForProcessExit(mismatchedProcessId));
    }

    private static Task PersonalRejectedProcessContainmentRetainsExactHandlesAsync()
    {
        var root = NewTempPath("personal-rejected-process", "root");
        Directory.CreateDirectory(root);
        var source = Environment.GetEnvironmentVariable("ComSpec")
            ?? throw new InvalidOperationException("ComSpec is unavailable.");
        var executable = Path.Combine(root, "verified-launcher.exe");
        var mismatched = Path.Combine(root, "mismatched.exe");
        var replacement = Path.Combine(root, "replacement.exe");
        File.Copy(source, executable);
        File.Copy(source, mismatched);
        File.Copy(source, replacement);

        var lease = PersonalAuthenticodeVerifier
            .OpenExecutableForLaunchForTests(executable);
        Process? rejectedImageProcess = null;
        Process? externalRejectedProcess = null;
        Process? rejectedSelfCheckProcess = null;
        Process? rejectedSelfCheckProcessHandle = null;
        try
        {
            AssertEqual(
                0,
                PersonalTrustedExecutableLaunchLease
                    .RetainedRejectedProcessCountForTests);
            var imageHandleObserved = false;
            var originalImageFailure = new InvalidDataException(
                "Synthetic exact rejected-image admission failure.");
            AssertThrows<InvalidOperationException>(() => lease.StartForTests(
                CreateLongRunningCommand(executable, root),
                _ =>
                {
                    rejectedImageProcess = Process.Start(
                            CreateLongRunningCommand(mismatched, root))
                        ?? throw new InvalidOperationException(
                            "Personal rejected-image containment process did not start.");
                    return rejectedImageProcess;
                },
                _ => throw originalImageFailure,
                (process, _) =>
                {
                    imageHandleObserved = ReferenceEquals(
                        rejectedImageProcess,
                        process);
                    throw new InvalidOperationException(
                        "Synthetic rejected-image Kill failure.");
                }));
            AssertTrue(imageHandleObserved);
            AssertTrue(rejectedImageProcess is not null);
            AssertFalse(rejectedImageProcess!.HasExited);
            AssertTrue(lease.HasRetainedRejectedProcessForTests);
            AssertTrue(ReferenceEquals(
                originalImageFailure,
                lease.RetainedRejectedProcessFailureForTests));
            AssertEqual(
                1,
                PersonalTrustedExecutableLaunchLease
                    .RetainedRejectedProcessCountForTests);

            AssertThrows<InvalidOperationException>(() =>
                lease.RetryRejectedProcessTerminationForTests((_, _) => true));
            AssertFalse(rejectedImageProcess.HasExited);
            AssertTrue(lease.HasRetainedRejectedProcessForTests);
            AssertTrue(ReferenceEquals(
                originalImageFailure,
                lease.RetainedRejectedProcessFailureForTests));

            AssertThrows<InvalidOperationException>(() =>
                lease.RetryRejectedProcessTerminationForTests((_, _) => false));
            AssertFalse(rejectedImageProcess.HasExited);
            AssertTrue(lease.HasRetainedRejectedProcessForTests);

            var rejectedImageProcessId = rejectedImageProcess.Id;
            lease.RetryRejectedProcessTerminationForTests(TerminateForContainmentTest);
            AssertFalse(lease.HasRetainedRejectedProcessForTests);
            AssertEqual(
                0,
                PersonalTrustedExecutableLaunchLease
                    .RetainedRejectedProcessCountForTests);
            AssertTrue(WaitForProcessExit(rejectedImageProcessId));

            externalRejectedProcess = Process.Start(
                    CreateLongRunningCommand(mismatched, root))
                ?? throw new InvalidOperationException(
                    "Personal external rejected-image process did not start.");
            var externalRejectedProcessId = externalRejectedProcess.Id;
            AssertThrows<InvalidDataException>(() =>
                lease.RequireProcessImageForTests(
                    externalRejectedProcess!,
                    TerminateForContainmentTest));
            AssertTrue(externalRejectedProcess!.HasExited);
            AssertEqual(externalRejectedProcessId, externalRejectedProcess.Id);
            AssertFalse(lease.RetainsRejectedProcess(externalRejectedProcess));
            externalRejectedProcess.Dispose();
            externalRejectedProcess = null;

            rejectedSelfCheckProcess = lease.Start(
                CreateLongRunningCommand(executable, root));
            rejectedSelfCheckProcessHandle = rejectedSelfCheckProcess;
            var rejectedSelfCheckProcessId = rejectedSelfCheckProcess.Id;
            var selfCheckHandleObserved = false;
            var originalSelfCheckFailure = new InvalidDataException(
                "Synthetic self-check protocol failure.");
            AssertThrows<InvalidOperationException>(() =>
                PersonalCompiledTrustProcessVerifier
                    .RequireSelfCheckProcessTerminatedForTests(
                        lease,
                        ref rejectedSelfCheckProcess,
                        originalSelfCheckFailure,
                        (process, _) =>
                        {
                            selfCheckHandleObserved = process.Id
                                == rejectedSelfCheckProcessId;
                            throw new InvalidOperationException(
                                "Synthetic self-check Kill failure.");
                        }));
            AssertTrue(selfCheckHandleObserved);
            AssertTrue(rejectedSelfCheckProcess is null);
            AssertTrue(lease.HasRetainedRejectedProcessForTests);
            AssertTrue(ReferenceEquals(
                originalSelfCheckFailure,
                lease.RetainedRejectedProcessFailureForTests));
            AssertEqual(
                1,
                PersonalTrustedExecutableLaunchLease
                    .RetainedRejectedProcessCountForTests);

            AssertThrows<InvalidOperationException>(() =>
                lease.DisposeForTests((_, _) => false));
            AssertTrue(lease.HasRetainedRejectedProcessForTests);
            AssertMutationDenied(() =>
                File.Move(replacement, executable, overwrite: true));

            lease.RetryRejectedProcessTerminationForTests(
                TerminateForContainmentTest);
            AssertFalse(lease.HasRetainedRejectedProcessForTests);
            AssertEqual(
                0,
                PersonalTrustedExecutableLaunchLease
                    .RetainedRejectedProcessCountForTests);
            AssertTrue(WaitForProcessExit(rejectedSelfCheckProcessId));
            File.Move(replacement, executable, overwrite: true);
        }
        finally
        {
            StopProcess(rejectedImageProcess);
            StopProcess(externalRejectedProcess);
            StopProcess(rejectedSelfCheckProcessHandle);
            try
            {
                lease.RetryRejectedProcessTerminationForTests((_, _) => true);
            }
            catch
            {
                // Preserve the test failure; the real helper process was stopped above.
            }
            lease.Dispose();
            rejectedImageProcess?.Dispose();
            externalRejectedProcess?.Dispose();
            rejectedSelfCheckProcessHandle?.Dispose();
        }
        return Task.CompletedTask;

        static bool TerminateForContainmentTest(
            Process process,
            TimeSpan timeout)
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
            return process.WaitForExit(checked((int)timeout.TotalMilliseconds))
                && process.HasExited;
        }
    }

    private static async Task PersonalTrustedLaunchLeaseSerializesConcurrentAdmissionsAsync()
    {
        var root = NewTempPath("personal-concurrent-admission", "root");
        Directory.CreateDirectory(root);
        var source = Environment.GetEnvironmentVariable("ComSpec")
            ?? throw new InvalidOperationException("ComSpec is unavailable.");
        var executable = Path.Combine(root, "verified-launcher.exe");
        var mismatched = Path.Combine(root, "mismatched.exe");
        File.Copy(source, executable);
        File.Copy(source, mismatched);

        var lease = PersonalAuthenticodeVerifier
            .OpenExecutableForLaunchForTests(executable);
        using var firstInspectEntered = new ManualResetEventSlim();
        using var releaseFirstInspect = new ManualResetEventSlim();
        using var secondAttempted = new ManualResetEventSlim();
        Process? firstProcess = null;
        Process? secondProcess = null;
        var firstProcessId = 0;
        Task firstStart = Task.CompletedTask;
        Task secondStart = Task.CompletedTask;
        var secondStartCalls = 0;
        try
        {
            firstStart = Task.Run(() =>
                AssertThrows<InvalidOperationException>(() => lease.StartForTests(
                    CreateLongRunningCommand(executable, root),
                    _ =>
                    {
                        firstProcess = Process.Start(
                                CreateLongRunningCommand(mismatched, root))
                            ?? throw new InvalidOperationException(
                                "First concurrent admission process did not start.");
                        firstProcessId = firstProcess.Id;
                        return firstProcess;
                    },
                    process =>
                    {
                        firstInspectEntered.Set();
                        if (!releaseFirstInspect.Wait(TimeSpan.FromSeconds(5)))
                        {
                            throw new TimeoutException(
                                "First concurrent admission was not released.");
                        }
                        return lease.InspectProcessImageIdentityForTests(process);
                    },
                    (_, _) => throw new InvalidOperationException(
                        "Synthetic first concurrent containment failure."))));
            AssertTrue(firstInspectEntered.Wait(TimeSpan.FromSeconds(5)));

            secondStart = Task.Run(() =>
            {
                AssertThrows<InvalidOperationException>(() => lease.StartForTests(
                    CreateLongRunningCommand(executable, root),
                    _ =>
                    {
                        Interlocked.Increment(ref secondStartCalls);
                        secondProcess = Process.Start(
                                CreateLongRunningCommand(mismatched, root))
                            ?? throw new InvalidOperationException(
                                "Second concurrent admission process did not start.");
                        return secondProcess;
                    },
                    lease.InspectProcessImageIdentityForTests,
                    (_, _) => throw new InvalidOperationException(
                        "Synthetic second concurrent containment failure."),
                    secondAttempted.Set));
            });
            AssertTrue(secondAttempted.Wait(TimeSpan.FromSeconds(5)));
            AssertEqual(0, Volatile.Read(ref secondStartCalls));

            releaseFirstInspect.Set();
            await Task.WhenAll(firstStart, secondStart).ConfigureAwait(false);
            AssertEqual(1, Volatile.Read(ref secondStartCalls));
            AssertTrue(firstProcess is not null);
            AssertTrue(secondProcess is not null);
            AssertTrue(firstProcessId > 0);
            AssertTrue(WaitForProcessExit(firstProcessId));
            AssertFalse(secondProcess!.HasExited);
            AssertTrue(ReferenceEquals(
                secondProcess,
                lease.RetainedRejectedProcessForTests));
            AssertEqual(
                1,
                PersonalTrustedExecutableLaunchLease
                    .RetainedRejectedProcessCountForTests);

            lease.RetryRejectedProcessTerminationForTests(
                TerminateForConcurrentAdmissionTest);
            AssertEqual(
                0,
                PersonalTrustedExecutableLaunchLease
                    .RetainedRejectedProcessCountForTests);
        }
        finally
        {
            releaseFirstInspect.Set();
            try
            {
                await Task.WhenAll(firstStart, secondStart).ConfigureAwait(false);
            }
            catch
            {
                // Preserve the original assertion while joining both workers.
            }
            StopProcess(firstProcess);
            StopProcess(secondProcess);
            try
            {
                lease.RetryRejectedProcessTerminationForTests((_, _) => true);
            }
            catch
            {
                // Preserve the test failure; both helper processes were stopped above.
            }
            lease.Dispose();
            firstProcess?.Dispose();
            secondProcess?.Dispose();
        }

        var externalExecutable = Path.Combine(root, "external-launcher.exe");
        File.Copy(source, externalExecutable);
        var externalLease = PersonalAuthenticodeVerifier
            .OpenExecutableForLaunchForTests(externalExecutable);
        using var externalFailureObserved = new ManualResetEventSlim();
        using var releaseExternalContainment = new ManualResetEventSlim();
        using var concurrentStartAttempted = new ManualResetEventSlim();
        Process? externalReceiver = null;
        Process? concurrentAdmittedProcess = null;
        Task externalValidation = Task.CompletedTask;
        Task<Process>? concurrentAdmission = null;
        var concurrentAdmissionStartCalls = 0;
        var externalBarrierTimedOut = 0;
        try
        {
            externalReceiver = Process.Start(
                    CreateLongRunningCommand(mismatched, root))
                ?? throw new InvalidOperationException(
                    "External receiver concurrency process did not start.");
            var externalReceiverId = externalReceiver.Id;
            externalValidation = Task.Run(() =>
                AssertThrows<InvalidOperationException>(() =>
                    externalLease.RequireProcessImageForTests(
                        externalReceiver,
                        (_, _) => false,
                        terminatePreviouslyRejectedProcess: null,
                        admissionFailureObserved: () =>
                        {
                            externalFailureObserved.Set();
                            if (!releaseExternalContainment.Wait(
                                    TimeSpan.FromSeconds(5)))
                            {
                                Interlocked.Exchange(
                                    ref externalBarrierTimedOut,
                                    1);
                            }
                        })));
            AssertTrue(externalFailureObserved.Wait(TimeSpan.FromSeconds(5)));
            AssertFalse(externalLease.RetainsRejectedProcess(externalReceiver));

            concurrentAdmission = Task.Run(() => externalLease.StartForTests(
                CreateLongRunningCommand(externalExecutable, root),
                startInfo =>
                {
                    Interlocked.Increment(ref concurrentAdmissionStartCalls);
                    return Process.Start(startInfo)
                        ?? throw new InvalidOperationException(
                            "Concurrent admission after external rejection did not start.");
                },
                externalLease.InspectProcessImageIdentityForTests,
                admissionAttempted: concurrentStartAttempted.Set));
            AssertTrue(concurrentStartAttempted.Wait(TimeSpan.FromSeconds(5)));
            AssertEqual(0, Volatile.Read(ref concurrentAdmissionStartCalls));
            AssertFalse(concurrentAdmission.IsCompleted);

            releaseExternalContainment.Set();
            await externalValidation.ConfigureAwait(false);
            concurrentAdmittedProcess = await concurrentAdmission.ConfigureAwait(false);
            AssertEqual(0, Volatile.Read(ref externalBarrierTimedOut));
            AssertEqual(1, Volatile.Read(ref concurrentAdmissionStartCalls));
            AssertTrue(WaitForProcessExit(externalReceiverId));
            AssertFalse(concurrentAdmittedProcess.HasExited);
        }
        finally
        {
            releaseExternalContainment.Set();
            try
            {
                await externalValidation.ConfigureAwait(false);
            }
            catch
            {
                // Preserve the first concurrency assertion.
            }
            if (concurrentAdmission is not null)
            {
                try
                {
                    concurrentAdmittedProcess ??=
                        await concurrentAdmission.ConfigureAwait(false);
                }
                catch
                {
                    // Preserve the first concurrency assertion.
                }
            }
            StopProcess(externalReceiver);
            StopProcess(concurrentAdmittedProcess);
            try
            {
                externalLease.RetryRejectedProcessTerminationForTests(
                    TerminateForConcurrentAdmissionTest);
            }
            catch
            {
                // Preserve the test failure while retaining the exact handle.
            }
            externalLease.Dispose();
            externalReceiver?.Dispose();
            concurrentAdmittedProcess?.Dispose();
        }

        var disposalExecutable = Path.Combine(root, "disposal-launcher.exe");
        var disposalReplacement = Path.Combine(root, "disposal-replacement.exe");
        File.Copy(source, disposalExecutable);
        File.Copy(source, disposalReplacement);
        var disposalLease = PersonalAuthenticodeVerifier
            .OpenExecutableForLaunchForTests(disposalExecutable);
        using var disposalInspectEntered = new ManualResetEventSlim();
        using var releaseDisposalInspect = new ManualResetEventSlim();
        using var disposeAttempted = new ManualResetEventSlim();
        Process? admittedProcess = null;
        Task<Process>? admittedStart = null;
        Task disposeTask = Task.CompletedTask;
        try
        {
            admittedStart = Task.Run(() => disposalLease.StartForTests(
                CreateLongRunningCommand(disposalExecutable, root),
                startInfo => Process.Start(startInfo)
                    ?? throw new InvalidOperationException(
                        "Concurrent disposal admission process did not start."),
                process =>
                {
                    disposalInspectEntered.Set();
                    if (!releaseDisposalInspect.Wait(TimeSpan.FromSeconds(5)))
                    {
                        throw new TimeoutException(
                            "Concurrent disposal admission was not released.");
                    }
                    return disposalLease
                        .InspectProcessImageIdentityForTests(process);
                }));
            AssertTrue(disposalInspectEntered.Wait(TimeSpan.FromSeconds(5)));
            disposeTask = Task.Run(() =>
            {
                disposalLease.DisposeForTests(
                    TerminateForConcurrentAdmissionTest,
                    disposeAttempted.Set);
            });
            AssertTrue(disposeAttempted.Wait(TimeSpan.FromSeconds(5)));
            AssertFalse(disposeTask.IsCompleted);
            AssertMutationDenied(() => File.Move(
                disposalReplacement,
                disposalExecutable,
                overwrite: true));

            releaseDisposalInspect.Set();
            admittedProcess = await admittedStart.ConfigureAwait(false);
            await disposeTask.ConfigureAwait(false);
            AssertThrows<ObjectDisposedException>(() =>
                disposalLease.StartForTests(
                    CreateLongRunningCommand(disposalExecutable, root),
                    _ => throw new InvalidOperationException(
                        "Disposed admission lease unexpectedly started a process."),
                    disposalLease.InspectProcessImageIdentityForTests));
        }
        finally
        {
            releaseDisposalInspect.Set();
            if (admittedStart is not null)
            {
                try
                {
                    admittedProcess ??= await admittedStart.ConfigureAwait(false);
                }
                catch
                {
                    // Preserve the original test failure.
                }
            }
            try
            {
                await disposeTask.ConfigureAwait(false);
            }
            catch
            {
                // Preserve the original test failure.
            }
            StopProcess(admittedProcess);
            admittedProcess?.Dispose();
            disposalLease.Dispose();
        }

        static bool TerminateForConcurrentAdmissionTest(
            Process process,
            TimeSpan timeout)
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
            return process.WaitForExit(checked((int)timeout.TotalMilliseconds))
                && process.HasExited;
        }
    }

    private static Task AutomaticStageBoundaryUsesCoordinatedHomeAsync()
    {
        var home = NewTempPath("automatic-stage-coordinated", "home");
        using (var enrollment = new PersonalHarnessHomeCoordinator(home).AcquireLease())
        {
            enrollment.RequireMutationAdmission(home);
        }

        var availablePortChecks = 0;
        var legacyChecks = 0;
        MainWindow.RequireAutomaticStageBoundary(
            home,
            49191,
            _ => availablePortChecks++,
            _ =>
            {
                legacyChecks++;
                throw new InvalidOperationException(
                    "An unrelated legacy Node process must not fence an enrolled home.");
            });

        AssertEqual(1, availablePortChecks);
        AssertEqual(0, legacyChecks);
        return Task.CompletedTask;
    }

    private static Task AutomaticStageBoundaryRejectsConflictsAsync()
    {
        var writerHome = NewTempPath("automatic-stage-active-writer", "home");
        using (var lease = new PersonalHarnessHomeCoordinator(writerHome).AcquireLease())
        using (var writer = lease.BeginRuntimeSession())
        {
            try
            {
                AssertThrows<InvalidOperationException>(() =>
                    MainWindow.RequireAutomaticStageBoundary(
                        writerHome,
                        49192,
                        _ => { },
                        _ => { }));
            }
            finally
            {
                writer.RecordNeverStarted();
            }
        }

        var portHome = NewTempPath("automatic-stage-occupied-port", "home");
        using (var enrollment = new PersonalHarnessHomeCoordinator(portHome).AcquireLease())
        {
            enrollment.RequireMutationAdmission(portHome);
        }
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var occupiedPort = ((IPEndPoint)listener.LocalEndpoint).Port;
        AssertThrows<InvalidOperationException>(() =>
            MainWindow.RequireAutomaticStageBoundary(portHome, occupiedPort));
        return Task.CompletedTask;
    }

    private static Task AutomaticStageBoundaryRetainsLegacyEnrollmentGuardAsync()
    {
        var home = NewTempPath("automatic-stage-legacy", "home");
        Directory.CreateDirectory(home);
        File.WriteAllText(Path.Combine(home, "legacy-history.jsonl"), "preserve");
        var legacyChecks = 0;

        AssertThrows<InvalidOperationException>(() =>
            MainWindow.RequireAutomaticStageBoundary(
                home,
                49193,
                _ => throw new InvalidOperationException(
                    "Port admission must not run before legacy enrollment."),
                _ =>
                {
                    legacyChecks++;
                    throw new InvalidOperationException(
                        "Injected conservative legacy writer conflict.");
                }));

        AssertEqual(1, legacyChecks);
        AssertEqual(
            "preserve",
            File.ReadAllText(Path.Combine(home, "legacy-history.jsonl")));
        AssertThrows<InvalidOperationException>(() =>
        {
            using var unexpected = new PersonalHarnessHomeCoordinator(home).AcquireLease();
        });
        return Task.CompletedTask;
    }

    private static Task PersonalExternalImageAdmissionContainsCurrentProcessAsync()
    {
        var root = NewTempPath("personal-external-image-pre-admission", "root");
        Directory.CreateDirectory(root);
        var source = Environment.GetEnvironmentVariable("ComSpec")
            ?? throw new InvalidOperationException("ComSpec is unavailable.");
        var blockerExecutable = Path.Combine(root, "blocker-launcher.exe");
        var receiverExecutable = Path.Combine(root, "receiver-launcher.exe");
        var mismatched = Path.Combine(root, "mismatched.exe");
        File.Copy(source, blockerExecutable);
        File.Copy(source, receiverExecutable);
        File.Copy(source, mismatched);

        var blockerLease = PersonalAuthenticodeVerifier
            .OpenExecutableForLaunchForTests(blockerExecutable);
        var receiverLease = PersonalAuthenticodeVerifier
            .OpenExecutableForLaunchForTests(receiverExecutable);
        Process? blockerProcess = null;
        Process? receiverProcess = null;
        try
        {
            AssertEqual(
                0,
                PersonalTrustedExecutableLaunchLease
                    .RetainedRejectedProcessCountForTests);
            AssertThrows<InvalidOperationException>(() => blockerLease.StartForTests(
                CreateLongRunningCommand(blockerExecutable, root),
                _ =>
                {
                    blockerProcess = Process.Start(
                            CreateLongRunningCommand(mismatched, root))
                        ?? throw new InvalidOperationException(
                            "Prior containment blocker process did not start.");
                    return blockerProcess;
                },
                _ => throw new InvalidDataException(
                    "Synthetic prior image rejection."),
                (_, _) => false));
            AssertTrue(blockerProcess is not null);
            AssertFalse(blockerProcess!.HasExited);
            AssertTrue(blockerLease.RetainsRejectedProcess(blockerProcess));

            receiverProcess = Process.Start(
                    CreateLongRunningCommand(receiverExecutable, root))
                ?? throw new InvalidOperationException(
                    "External receiver containment process did not start.");
            var priorRetryObservedExactProcess = false;
            var currentContainmentObservedExactProcess = false;
            AssertThrows<InvalidOperationException>(() =>
                receiverLease.RequireProcessImageForTests(
                    receiverProcess,
                    (process, _) =>
                    {
                        currentContainmentObservedExactProcess =
                            ReferenceEquals(process, receiverProcess);
                        return true;
                    },
                    (process, _) =>
                    {
                        priorRetryObservedExactProcess =
                            ReferenceEquals(process, blockerProcess);
                        return false;
                    }));

            AssertTrue(priorRetryObservedExactProcess);
            AssertTrue(currentContainmentObservedExactProcess);
            AssertFalse(blockerProcess.HasExited);
            AssertFalse(receiverProcess.HasExited);
            AssertTrue(blockerLease.RetainsRejectedProcess(blockerProcess));
            AssertTrue(receiverLease.RetainsRejectedProcess(receiverProcess));
            AssertEqual(
                2,
                PersonalTrustedExecutableLaunchLease
                    .RetainedRejectedProcessCountForTests);

            blockerLease.RetryRejectedProcessTerminationForTests(
                TerminateForExternalImageAdmissionTest);
            receiverLease.RetryRejectedProcessTerminationForTests(
                TerminateForExternalImageAdmissionTest);
            AssertEqual(
                0,
                PersonalTrustedExecutableLaunchLease
                    .RetainedRejectedProcessCountForTests);
        }
        finally
        {
            StopProcess(blockerProcess);
            StopProcess(receiverProcess);
            try
            {
                blockerLease.RetryRejectedProcessTerminationForTests(
                    TerminateForExternalImageAdmissionTest);
            }
            catch
            {
                // Preserve the test failure while retaining the exact helper handle.
            }
            try
            {
                receiverLease.RetryRejectedProcessTerminationForTests(
                    TerminateForExternalImageAdmissionTest);
            }
            catch
            {
                // Preserve the test failure while retaining the exact helper handle.
            }
            blockerLease.Dispose();
            receiverLease.Dispose();
            blockerProcess?.Dispose();
            receiverProcess?.Dispose();
        }
        return Task.CompletedTask;

        static bool TerminateForExternalImageAdmissionTest(
            Process process,
            TimeSpan timeout)
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
            return process.WaitForExit(checked((int)timeout.TotalMilliseconds))
                && process.HasExited;
        }
    }

    private static ProcessStartInfo CreateLongRunningCommand(
        string executable,
        string workingDirectory)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = executable,
            WorkingDirectory = workingDirectory,
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
        };
        startInfo.ArgumentList.Add("/d");
        startInfo.ArgumentList.Add("/c");
        startInfo.ArgumentList.Add("ping -t 127.0.0.1 > nul");
        return startInfo;
    }

    private static void StopProcess(Process? process)
    {
        try
        {
            if (process is not null && !process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                process.WaitForExit(5_000);
            }
        }
        catch
        {
            // Preserve the test failure while containing only its helper tree.
        }
    }

    private static bool WaitForProcessExit(int processId)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            return process.HasExited
                || (process.WaitForExit(5_000) && process.HasExited);
        }
        catch (ArgumentException)
        {
            return true;
        }
    }

    [DllImport(
        "kernel32.dll",
        EntryPoint = "CreateHardLinkW",
        CharSet = CharSet.Unicode,
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateHardLink(
        string fileName,
        string existingFileName,
        IntPtr securityAttributes);

    private static void CopyDirectory(string source, string destination)
    {
        Directory.CreateDirectory(destination);
        foreach (var directory in Directory.EnumerateDirectories(
                     source,
                     "*",
                     SearchOption.AllDirectories))
        {
            Directory.CreateDirectory(Path.Combine(
                destination,
                Path.GetRelativePath(source, directory)));
        }
        foreach (var file in Directory.EnumerateFiles(
                     source,
                     "*",
                     SearchOption.AllDirectories))
        {
            var target = Path.Combine(destination, Path.GetRelativePath(source, file));
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            File.Copy(file, target, overwrite: false);
        }
    }

    private static string SnapshotDirectoryFiles(string root)
    {
        if (!Directory.Exists(root))
        {
            return "<missing>";
        }
        return string.Join(
            "\n",
            Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories)
                .Select(path => new
                {
                    Path = Path.GetRelativePath(root, path).Replace('\\', '/'),
                    Bytes = File.ReadAllBytes(path),
                })
                .OrderBy(item => item.Path, StringComparer.Ordinal)
                .Select(item =>
                    $"{item.Path}|{item.Bytes.LongLength}|{Sha256(item.Bytes)}"));
    }

    private static void CreateHardLinkForTest(
        string linkPath,
        string targetPath)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = "cmd.exe",
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardError = true,
            RedirectStandardOutput = true,
        };
        startInfo.ArgumentList.Add("/d");
        startInfo.ArgumentList.Add("/c");
        startInfo.ArgumentList.Add("mklink");
        startInfo.ArgumentList.Add("/H");
        startInfo.ArgumentList.Add(linkPath);
        startInfo.ArgumentList.Add(targetPath);
        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException(
                "Could not start hard-link test helper.");
        var output = process.StandardOutput.ReadToEnd();
        var error = process.StandardError.ReadToEnd();
        process.WaitForExit();
        if (process.ExitCode != 0 || !File.Exists(linkPath))
        {
            throw new InvalidOperationException(
                $"Could not create test hard link: {output} {error}");
        }
    }

    private static void CreateDirectoryLinkForTest(string linkPath, string targetPath)
    {
        try
        {
            Directory.CreateSymbolicLink(linkPath, targetPath);
            return;
        }
        catch (IOException) when (OperatingSystem.IsWindows())
        {
            // Windows junctions exercise the same ancestor reparse-point boundary and do not
            // require the symbolic-link privilege on standard test workers.
        }
        var startInfo = new ProcessStartInfo
        {
            FileName = "cmd.exe",
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardError = true,
            RedirectStandardOutput = true,
        };
        startInfo.ArgumentList.Add("/d");
        startInfo.ArgumentList.Add("/c");
        startInfo.ArgumentList.Add("mklink");
        startInfo.ArgumentList.Add("/J");
        startInfo.ArgumentList.Add(linkPath);
        startInfo.ArgumentList.Add(targetPath);
        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("Could not start junction test helper.");
        var output = process.StandardOutput.ReadToEnd();
        var error = process.StandardError.ReadToEnd();
        process.WaitForExit();
        if (process.ExitCode != 0 || !Directory.Exists(linkPath))
        {
            throw new InvalidOperationException(
                $"Could not create test junction: {output} {error}");
        }
    }

    private static Task WholeHomeTransactionAsync()
    {
        var scope = NewTempPath("whole-home", "root");
        var home = Path.Combine(scope, "home");
        var recovery = Path.Combine(scope, "recovery");
        Directory.CreateDirectory(Path.Combine(home, "unknown-local-data"));
        File.WriteAllText(Path.Combine(home, "unknown-local-data", "conversation.bin"), "original");
        File.WriteAllText(Path.Combine(home, "root-secret.dat"), "keep-me");
        var transaction = NewTestHomeTransaction(home, recovery);
        var prepared = transaction.Prepare("personal-home-v1", GetFreePort());
        File.WriteAllText(Path.Combine(home, "candidate-write.dat"), "candidate");
        var restored = transaction.Rollback(prepared.TransactionId, "TEST_FAILURE");
        AssertEqual(PersonalHarnessHomeTransaction.RestoredStatus, restored.Status);
        AssertEqual(
            "original",
            File.ReadAllText(Path.Combine(home, "unknown-local-data", "conversation.bin")));
        AssertFalse(File.Exists(Path.Combine(home, "candidate-write.dat")));

        var committed = transaction.Prepare("personal-home-v2", GetFreePort());
        File.WriteAllText(Path.Combine(home, "committed-write.dat"), "committed");
        _ = transaction.VerifyCandidateReadable(committed.TransactionId);
        transaction.MarkHealthPassed(committed.TransactionId);
        transaction.FinalizeCommit(committed.TransactionId);
        AssertTrue(File.Exists(Path.Combine(home, "committed-write.dat")));
        AssertTrue(transaction.TryReadActive() is null);

        var tampered = transaction.Prepare("personal-home-v3", GetFreePort());
        _ = transaction.VerifyCandidateReadable(tampered.TransactionId);
        File.WriteAllText(Path.Combine(home, "post-health-check.dat"), "must-reject");
        AssertThrows<InvalidDataException>(() =>
            transaction.MarkHealthPassed(tampered.TransactionId));
        _ = transaction.Rollback(tampered.TransactionId, "TEST_TAMPER");
        return Task.CompletedTask;
    }

    private static async Task ForeignWriterHandleRejectedAsync()
    {
        var scope = NewTempPath("foreign-writer", "root");
        var home = Path.Combine(scope, "home");
        var recovery = Path.Combine(scope, "recovery");
        Directory.CreateDirectory(home);
        var path = Path.Combine(home, "conversation.bin");
        File.WriteAllText(path, "local-data");
        await using var writer = new FileStream(
            path,
            FileMode.Open,
            FileAccess.ReadWrite,
            FileShare.Read | FileShare.Delete);
        await AssertThrowsAsync<InvalidOperationException>(() => Task.Run(() =>
            NewTestHomeTransaction(home, recovery)
                .Prepare("foreign-writer-v1", GetFreePort())));
        await writer.DisposeAsync();
        AssertEqual("local-data", File.ReadAllText(path));
    }

    private static Task MoveGapExactRestoreAsync()
    {
        var fixture = CreateMoveGapFixture("move-gap-exact-restore");
        var sawRelockedCloneBoundary = false;
        var transaction = NewTestHomeTransaction(
            fixture.Home,
            fixture.Recovery,
            TimeProvider.System,
            (phase, _, originalDirectory) =>
            {
                var originalData = Path.Combine(
                    originalDirectory,
                    "nested",
                    "conversation.bin");
                if (phase == PersonalHarnessHomeMoveGapPhase.DescendantsReleasedBeforeMove)
                {
                    File.WriteAllText(fixture.DataPath, "transient-write");
                    File.WriteAllText(fixture.DataPath, fixture.OriginalData);
                }
                else if (phase == PersonalHarnessHomeMoveGapPhase.DestinationRelockedBeforeClone)
                {
                    sawRelockedCloneBoundary = true;
                    AssertMutationDenied(() =>
                        File.WriteAllText(originalData, "blocked-write"));
                }
            });

        var prepared = transaction.Prepare("move-gap-exact-v1", GetFreePort());
        AssertTrue(sawRelockedCloneBoundary);
        AssertEqual(fixture.OriginalData, File.ReadAllText(fixture.DataPath));
        _ = transaction.Rollback(prepared.TransactionId, "TEST_COMPLETE");
        AssertEqual(fixture.OriginalData, File.ReadAllText(fixture.DataPath));
        return Task.CompletedTask;
    }

    private static Task MoveGapPersistentWriterAsync()
    {
        var fixture = CreateMoveGapFixture("move-gap-persistent-writer");
        FileStream? writer = null;
        var transaction = NewTestHomeTransaction(
            fixture.Home,
            fixture.Recovery,
            TimeProvider.System,
            (phase, _, originalDirectory) =>
            {
                if (phase != PersonalHarnessHomeMoveGapPhase.RootMovedBeforeRelock)
                {
                    return;
                }
                writer = new FileStream(
                    Path.Combine(originalDirectory, "nested", "conversation.bin"),
                    FileMode.Open,
                    FileAccess.ReadWrite,
                    FileShare.Read | FileShare.Delete);
            });

        try
        {
            AssertThrows<InvalidOperationException>(() =>
                transaction.Prepare("move-gap-writer-v1", GetFreePort()));
            AssertTrue(transaction.TryReadActive() is not null);
        }
        finally
        {
            writer?.Dispose();
        }
        var recovered = transaction.RecoverInterrupted();
        AssertEqual(PersonalHarnessHomeTransaction.RestoredStatus, recovered!.Status);
        AssertEqual(fixture.OriginalData, File.ReadAllText(fixture.DataPath));
        return Task.CompletedTask;
    }

    private static Task MoveGapMutationRejectedAsync(string mutation)
    {
        var fixture = CreateMoveGapFixture("move-gap-" + mutation);
        var extraPath = Path.Combine(fixture.Home, "nested", "extra.bin");
        var transaction = NewTestHomeTransaction(
            fixture.Home,
            fixture.Recovery,
            TimeProvider.System,
            (phase, _, _) =>
            {
                if (phase != PersonalHarnessHomeMoveGapPhase.DescendantsReleasedBeforeMove)
                {
                    return;
                }
                switch (mutation)
                {
                    case "create":
                        File.WriteAllText(extraPath, "extra");
                        break;
                    case "delete":
                        File.Delete(fixture.DataPath);
                        break;
                    case "replace":
                        File.Delete(fixture.DataPath);
                        File.WriteAllText(fixture.DataPath, "replacement");
                        break;
                    default:
                        throw new ArgumentOutOfRangeException(nameof(mutation));
                }
            });

        AssertThrows<InvalidDataException>(() =>
            transaction.Prepare("move-gap-" + mutation + "-v1", GetFreePort()));
        var active = transaction.TryReadActive()
            ?? throw new InvalidOperationException("Expected fail-closed active recovery state.");
        var movedData = Path.Combine(
            active.OriginalDirectory,
            "nested",
            "conversation.bin");
        if (mutation == "create")
        {
            File.Delete(Path.Combine(active.OriginalDirectory, "nested", "extra.bin"));
        }
        else
        {
            File.WriteAllText(movedData, fixture.OriginalData);
        }
        var recovered = transaction.RecoverInterrupted();
        AssertEqual(PersonalHarnessHomeTransaction.RestoredStatus, recovered!.Status);
        AssertEqual(fixture.OriginalData, File.ReadAllText(fixture.DataPath));
        return Task.CompletedTask;
    }

    private static Task MoveGapReparseRejectedAsync()
    {
        var fixture = CreateMoveGapFixture("move-gap-reparse");
        var target = NewTempPath("move-gap-reparse", "linked-target");
        Directory.CreateDirectory(target);
        File.WriteAllText(Path.Combine(target, "outside.bin"), "outside");
        var transaction = NewTestHomeTransaction(
            fixture.Home,
            fixture.Recovery,
            TimeProvider.System,
            (phase, _, _) =>
            {
                if (phase == PersonalHarnessHomeMoveGapPhase.DescendantsReleasedBeforeMove)
                {
                    CreateDirectoryLinkForTest(
                        Path.Combine(fixture.Home, "nested", "linked"),
                        target);
                }
            });

        AssertThrows<InvalidDataException>(() =>
            transaction.Prepare("move-gap-reparse-v1", GetFreePort()));
        var active = transaction.TryReadActive()
            ?? throw new InvalidOperationException("Expected fail-closed active recovery state.");
        Directory.Delete(Path.Combine(active.OriginalDirectory, "nested", "linked"));
        var recovered = transaction.RecoverInterrupted();
        AssertEqual(PersonalHarnessHomeTransaction.RestoredStatus, recovered!.Status);
        AssertEqual(fixture.OriginalData, File.ReadAllText(fixture.DataPath));
        return Task.CompletedTask;
    }

    private static PersonalHarnessHomeTransaction NewTestHomeTransaction(
        string harnessHome,
        string recoveryRoot,
        TimeProvider? timeProvider = null,
        Action<PersonalHarnessHomeMoveGapPhase, string, string>? moveGapHook = null) =>
        new(
            harnessHome,
            recoveryRoot,
            timeProvider,
            moveGapHook,
            _ => { });

    private static PersonalReleaseArtifactInstaller NewTestArtifactInstaller() =>
        new(_ => { });

    private static MoveGapFixture CreateMoveGapFixture(string scope)
    {
        const string originalData = "original-local-data";
        var root = NewTempPath(scope, "root");
        var home = Path.Combine(root, "home");
        var recovery = Path.Combine(root, "recovery");
        var dataPath = Path.Combine(home, "nested", "conversation.bin");
        Directory.CreateDirectory(Path.GetDirectoryName(dataPath)!);
        File.WriteAllText(dataPath, originalData);
        return new MoveGapFixture(home, recovery, dataPath, originalData);
    }

    private sealed record MoveGapFixture(
        string Home,
        string Recovery,
        string DataPath,
        string OriginalData);

    private static async Task ComponentTupleNonceHealthAsync()
    {
        using var fixture = new ManifestFixture();
        var install = CreateInstallFixture("tuple-health", fixture);
        var security = new PersonalReleaseSecurityStateStore(
            install.Layout.UpdateSecurityStatePath,
            StateIdentity(),
            install.Layout.UpdateSecurityWitnessPath);
        var accepted = await security.VerifyAndAcceptAsync(
            install.ManifestBytes,
            fixture.Policy,
            Now);
        var result = await NewTestArtifactInstaller().InstallReleaseSetAsync(
            install.Layout,
            accepted.Verified,
            install.ClientArchivePath,
            install.RuntimeArchivePath,
            GetFreePort());
        AssertEqual(PersonalReleaseHealthStates.Pending, result.Pointer.Current.HealthState);
        var token = result.Pointer.Current.HealthToken!;
        var coordinator = new PersonalReleaseHealthCoordinator(install.Layout);
        CompleteFixtureHomeHealthAttemptIfRequired(install.Layout, token);
        coordinator.WriteSignal(token, Environment.ProcessId, new string('a', 64));
        var healthy = coordinator.ConsumeSignalAndMarkHealthy(token);
        AssertEqual(PersonalReleaseHealthStates.Healthy, healthy.Current.HealthState);
        AssertTrue(new PersonalReleaseSetPointerStore(install.Layout).ReadRequired()
            .Current.HealthToken is null);
        AssertTrue(NewTestHomeTransaction(
            install.Layout.HarnessHome,
            install.Layout.HarnessRecoveryRoot).TryReadActive() is null);
    }

    private static async Task IncompleteHomeHealthAttemptRejectedAsync()
    {
        using var fixture = new ManifestFixture();
        var pending = await CreatePendingInstallAsync("incomplete-home-health", fixture);
        var pointer = pending.Result.Pointer.Current;
        var token = pointer.HealthToken!;
        var transactionId = pointer.HomeTransactionId!;
        using var lease = new PersonalHarnessHomeCoordinator(
                pending.Install.Layout.HarnessHome)
            .AcquireLease(static () => { });
        lease.AdmitHealthAttempt(transactionId, token);
        using (var runtimeSession = lease.BeginRuntimeSession())
        {
            // Fixture-only stand-in; no real DSH process is started by this test.
            runtimeSession.RecordAssignedProcess(12345, 1);
            runtimeSession.RecordJobEmpty();
        }
        AssertThrows<InvalidOperationException>(() =>
            new PersonalReleaseHealthCoordinator(pending.Install.Layout, lease)
                .WriteSignal(token, Environment.ProcessId, new string('b', 64)));
    }

    private static async Task WrongHomeTransactionHealthAttemptRejectedAsync()
    {
        using var fixture = new ManifestFixture();
        var pending = await CreatePendingInstallAsync("wrong-home-health-transaction", fixture);
        var pointer = pending.Result.Pointer.Current;
        var token = pointer.HealthToken!;
        var wrongTransactionId = Guid.NewGuid().ToString("N");
        AssertFalse(string.Equals(
            pointer.HomeTransactionId,
            wrongTransactionId,
            StringComparison.Ordinal));
        using var lease = new PersonalHarnessHomeCoordinator(
                pending.Install.Layout.HarnessHome)
            .AcquireLease(static () => { });
        CompleteFixtureHomeHealthAttempt(
            lease,
            pointer.HomeTransactionId!,
            token);
        var coordinator = new PersonalReleaseHealthCoordinator(
            pending.Install.Layout,
            lease);
        coordinator.WriteSignal(
            token,
            Environment.ProcessId,
            new string('c', 64));
        lease.AdmitHealthAttempt(wrongTransactionId, token);
        using (var runtimeSession = lease.BeginRuntimeSession())
        {
            // Fixture-only stand-in; no real DSH process is started by this test.
            runtimeSession.RecordAssignedProcess(12345, 1);
            runtimeSession.RecordJobEmpty();
        }
        lease.CompleteHealthAttempt(wrongTransactionId, token);
        AssertThrows<InvalidOperationException>(() =>
            coordinator.ConsumeSignalAndMarkHealthy(token));
    }

    private static async Task FailedHealthRestoresHomeAsync()
    {
        using var fixture = new ManifestFixture();
        var install = CreateInstallFixture("tuple-health-failed", fixture);
        var originalPath = Path.Combine(install.Layout.HarnessHome, "conversation.db");
        Directory.CreateDirectory(install.Layout.HarnessHome);
        File.WriteAllText(originalPath, "last-good-local-data");
        var security = new PersonalReleaseSecurityStateStore(
            install.Layout.UpdateSecurityStatePath,
            StateIdentity(),
            install.Layout.UpdateSecurityWitnessPath);
        var accepted = await security.VerifyAndAcceptAsync(
            install.ManifestBytes,
            fixture.Policy,
            Now);
        _ = await NewTestArtifactInstaller().InstallReleaseSetAsync(
            install.Layout,
            accepted.Verified,
            install.ClientArchivePath,
            install.RuntimeArchivePath,
            GetFreePort());
        File.WriteAllText(originalPath, "candidate-mutated-data");
        var health = await new PersonalBootstrapHealthGate(
            install.Layout,
            TimeSpan.FromSeconds(5)).EnsureHealthyAsync(
                (_, _, _, _) => Task.FromResult(17));
        AssertFalse(health.Healthy);
        AssertEqual("last-good-local-data", File.ReadAllText(originalPath));
        AssertTrue(new PersonalReleaseSetPointerStore(install.Layout).TryRead() is null);
        var state = await security.TryReadAsync();
        AssertEqual("personal-install-v1", state!.FailedReleaseQuarantine.Single().ReleaseSetId);
    }

    private static async Task FirstV2FailureStartsLegacyV1TupleAsync()
    {
        using var fixture = new ManifestFixture();
        var install = CreateInstallFixture("legacy-v1-first-v2-failure", fixture);
        var legacy = CreateLegacyV1Fallback(install.Layout);
        var security = new PersonalReleaseSecurityStateStore(
            install.Layout.UpdateSecurityStatePath,
            StateIdentity(),
            install.Layout.UpdateSecurityWitnessPath);
        var accepted = await security.VerifyAndAcceptAsync(
            install.ManifestBytes,
            fixture.Policy,
            Now);
        _ = await NewTestArtifactInstaller().InstallReleaseSetAsync(
            install.Layout,
            accepted.Verified,
            install.ClientArchivePath,
            install.RuntimeArchivePath,
            GetFreePort());

        var health = await new PersonalBootstrapHealthGate(
            install.Layout,
            TimeSpan.FromSeconds(5)).EnsureHealthyAsync(
                (_, _, _, cancellationToken) =>
                    RunRealExitProcessAsync(17, cancellationToken));
        AssertFalse(health.Healthy);
        AssertTrue(new PersonalReleaseSetPointerStore(install.Layout).TryRead() is null);

        var recovered = await new PersonalLegacyV1FallbackStore(install.Layout)
            .TryReadAllowedAsync();
        AssertTrue(recovered is not null);
        AssertEqual(legacy.ReleaseId, recovered!.ReleaseId);
        AssertEqual(legacy.RuntimeDirectory, recovered.RuntimeDirectory);

        Process? restartedProcess = null;
        var launches = 0;
        var started = await new PersonalLegacyV1FallbackStore(install.Layout)
            .TryStartLauncherAsync(
            Array.Empty<string>(),
            startInfo =>
            {
                Interlocked.Increment(ref launches);
                AssertEqual(legacy.LauncherExecutablePath, startInfo.FileName);
                restartedProcess = StartRealExitProcess(0);
                return restartedProcess;
            });
        AssertTrue(started);
        AssertEqual(1, launches);
        AssertTrue(restartedProcess is not null);
        await restartedProcess!.WaitForExitAsync();
        AssertEqual(0, restartedProcess.ExitCode);
        restartedProcess.Dispose();
        AssertTrue(File.Exists(Path.Combine(legacy.RuntimeDirectory, "node.exe")));
    }

    private static async Task AuthenticatedV2StateLossForbidsLegacyFallbackAsync()
    {
        using var fixture = new ManifestFixture();
        var install = CreateInstallFixture("legacy-v1-v2-state-loss", fixture);
        _ = CreateLegacyV1Fallback(install.Layout);
        var legacyRuntimePointer = await File.ReadAllBytesAsync(
            install.Layout.LegacyRuntimePointerPath);
        var legacyLauncherPointer = await File.ReadAllBytesAsync(
            install.Layout.LegacyLauncherPointerPath);
        var security = new PersonalReleaseSecurityStateStore(
            install.Layout.UpdateSecurityStatePath,
            StateIdentity(),
            install.Layout.UpdateSecurityWitnessPath);
        _ = await security.VerifyAndAcceptAsync(
            install.ManifestBytes,
            fixture.Policy,
            Now);

        AssertTrue(File.Exists(install.Layout.V2MigrationFootprintPath));
        AssertFalse(Encoding.UTF8.GetString(File.ReadAllBytes(
            install.Layout.V2MigrationFootprintPath)).Contains(
            "personal-install-v1",
            StringComparison.Ordinal));
        AssertFalse(PersonalPathGuard.IsSameOrDescendant(
            install.Layout.V2MigrationFootprintPath,
            install.Layout.ManagedRoot));
        AssertFalse(PersonalPathGuard.IsSameOrDescendant(
            install.Layout.UpdateSecurityWitnessPath,
            install.Layout.ManagedRoot));
        AssertFalse(PersonalPathGuard.IsSameOrDescendant(
            install.Layout.V2MigrationFootprintPath,
            install.Layout.HarnessHome));
        Directory.Delete(install.Layout.StateRoot, recursive: true);
        Directory.CreateDirectory(install.Layout.StateRoot);
        await File.WriteAllBytesAsync(
            install.Layout.LegacyRuntimePointerPath,
            legacyRuntimePointer);
        await File.WriteAllBytesAsync(
            install.Layout.LegacyLauncherPointerPath,
            legacyLauncherPointer);
        File.Delete(install.Layout.UpdateSecurityWitnessPath);
        AssertTrue(File.Exists(install.Layout.V2MigrationFootprintPath));

        var fallback = new PersonalLegacyV1FallbackStore(install.Layout);
        await AssertThrowsAsync<InvalidDataException>(() =>
            fallback.TryReadAllowedAsync());
        var launches = 0;
        await AssertThrowsAsync<InvalidDataException>(() =>
            fallback.TryStartLauncherAsync(
                Array.Empty<string>(),
                _ =>
                {
                    Interlocked.Increment(ref launches);
                    return StartRealExitProcess(0);
                }));
        AssertEqual(0, launches);
    }

    private static async Task LegacyLaunchSerializesWithV2TransitionAsync()
    {
        using var fixture = new ManifestFixture();
        var install = CreateInstallFixture("legacy-v1-transition-serialization", fixture);
        _ = CreateLegacyV1Fallback(install.Layout);
        var security = new PersonalReleaseSecurityStateStore(
            install.Layout.UpdateSecurityStatePath,
            StateIdentity(),
            install.Layout.UpdateSecurityWitnessPath);
        var enteredLaunch = new TaskCompletionSource<bool>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        using var releaseLaunch = new ManualResetEventSlim(initialState: false);
        Process? launchedProcess = null;
        var launchTask = Task.Run(() =>
            new PersonalLegacyV1FallbackStore(install.Layout)
                .TryStartLauncherAsync(
                    Array.Empty<string>(),
                    _ =>
                    {
                        enteredLaunch.TrySetResult(true);
                        if (!releaseLaunch.Wait(TimeSpan.FromSeconds(5)))
                        {
                            throw new TimeoutException(
                                "Test did not release the serialized legacy launch.");
                        }
                        launchedProcess = StartRealExitProcess(0);
                        return launchedProcess;
                    }));

        await enteredLaunch.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var transition = security.VerifyAndAcceptAsync(
            install.ManifestBytes,
            fixture.Policy,
            Now);
        try
        {
            await Task.Delay(TimeSpan.FromMilliseconds(150));
            AssertFalse(transition.IsCompleted);
        }
        finally
        {
            releaseLaunch.Set();
        }

        AssertTrue(await launchTask);
        _ = await transition;
        AssertTrue(File.Exists(install.Layout.V2MigrationFootprintPath));
        AssertTrue(launchedProcess is not null);
        await launchedProcess!.WaitForExitAsync();
        AssertEqual(0, launchedProcess.ExitCode);
        launchedProcess.Dispose();
    }

    private static async Task ResidualV2ClientBundleForbidsLegacyFallbackAsync()
    {
        using var fixture = new ManifestFixture();
        var install = CreateInstallFixture("legacy-v1-residual-v2", fixture);
        _ = CreateLegacyV1Fallback(install.Layout);
        var residual = install.Layout.GetClientBundleDirectory("residual-client-v2");
        Directory.CreateDirectory(residual);
        File.WriteAllText(Path.Combine(residual, "residual.bin"), "v2");

        var fallback = new PersonalLegacyV1FallbackStore(install.Layout);
        await AssertThrowsAsync<InvalidDataException>(() =>
            fallback.TryReadAllowedAsync());
    }

    private static async Task TamperedV2MigrationFootprintFailsClosedAsync()
    {
        using var fixture = new ManifestFixture();
        var install = CreateInstallFixture("legacy-v1-tampered-footprint", fixture);
        _ = CreateLegacyV1Fallback(install.Layout);
        var security = new PersonalReleaseSecurityStateStore(
            install.Layout.UpdateSecurityStatePath,
            StateIdentity(),
            install.Layout.UpdateSecurityWitnessPath);
        _ = await security.VerifyAndAcceptAsync(
            install.ManifestBytes,
            fixture.Policy,
            Now);
        DeleteMutableV2State(install.Layout);

        var protectedBytes = await File.ReadAllBytesAsync(
            install.Layout.V2MigrationFootprintPath);
        protectedBytes[protectedBytes.Length / 2] ^= 0x5a;
        await File.WriteAllBytesAsync(
            install.Layout.V2MigrationFootprintPath,
            protectedBytes);

        await AssertThrowsAsync<InvalidDataException>(() =>
            new PersonalLegacyV1FallbackStore(install.Layout)
                .TryReadAllowedAsync());
    }

    private static void DeleteMutableV2State(PersonalInstallationLayout layout)
    {
        foreach (var path in new[]
        {
            layout.ReleaseSetPointerPath,
            layout.UpdateSecurityStatePath,
            layout.UpdateSecurityStatePath + ".anchor",
            layout.UpdateSecurityStatePath + ".anchor.pending",
            layout.UpdateSecurityWitnessPath,
        })
        {
            File.Delete(path);
        }
    }

    private static async Task PreparedHomeWithoutPointerRestoresAsync()
    {
        using var fixture = new ManifestFixture();
        var pending = await CreatePendingInstallAsync("orphan-prepared", fixture);
        var token = pending.Result.Pointer.Current.HealthToken!;
        var coordinator = new PersonalReleaseHealthCoordinator(pending.Install.Layout);
        CompleteFixtureHomeHealthAttemptIfRequired(pending.Install.Layout, token);
        coordinator.WriteSignal(token, Environment.ProcessId, new string('b', 64));
        _ = coordinator.ConsumeSignalAndMarkHealthy(token);

        var localData = Path.Combine(pending.Install.Layout.HarnessHome, "conversation.bin");
        File.WriteAllText(localData, "last-committed");
        var transaction = NewTestHomeTransaction(
            pending.Install.Layout.HarnessHome,
            pending.Install.Layout.HarnessRecoveryRoot);
        _ = transaction.Prepare("orphan-candidate-v2", GetFreePort());
        File.WriteAllText(localData, "orphan-candidate-write");
        var probes = 0;
        var recovered = await new PersonalBootstrapHealthGate(pending.Install.Layout)
            .EnsureHealthyAsync((_, _, _, _) =>
            {
                Interlocked.Increment(ref probes);
                return Task.FromResult(0);
            });
        AssertTrue(recovered.Healthy);
        AssertEqual(0, probes);
        AssertEqual("last-committed", File.ReadAllText(localData));
        AssertTrue(transaction.TryReadActive() is null);
    }

    private static async Task ConcurrentHealthGateAsync()
    {
        using var fixture = new ManifestFixture();
        var pending = await CreatePendingInstallAsync("concurrent-health", fixture);
        var coordinator = new PersonalReleaseHealthCoordinator(pending.Install.Layout);
        var probes = 0;
        async Task<int> Probe(
            string _,
            string healthToken,
            TimeSpan __,
            CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref probes);
            await Task.Delay(100, cancellationToken);
            CompleteFixtureHomeHealthAttemptIfRequired(
                pending.Install.Layout,
                healthToken);
            coordinator.WriteSignal(
                healthToken,
                Environment.ProcessId,
                new string('c', 64));
            return 0;
        }

        var first = new PersonalBootstrapHealthGate(pending.Install.Layout)
            .EnsureHealthyAsync(Probe);
        var second = new PersonalBootstrapHealthGate(pending.Install.Layout)
            .EnsureHealthyAsync(Probe);
        var results = await Task.WhenAll(first, second);
        AssertTrue(results.All(result => result.Healthy));
        AssertEqual(1, probes);
        AssertEqual(
            PersonalReleaseHealthStates.Healthy,
            new PersonalReleaseSetPointerStore(pending.Install.Layout)
                .ReadRequired().Current.HealthState);
        var state = await pending.Security.TryReadAsync();
        AssertEqual(0, state!.FailedReleaseQuarantine.Count);
    }

    private static async Task InstalledTupleTamperRejectedAsync()
    {
        using var fixture = new ManifestFixture();
        var pending = await CreatePendingInstallAsync("tuple-tamper", fixture);
        var token = pending.Result.Pointer.Current.HealthToken!;
        var coordinator = new PersonalReleaseHealthCoordinator(pending.Install.Layout);
        CompleteFixtureHomeHealthAttemptIfRequired(pending.Install.Layout, token);
        coordinator.WriteSignal(token, Environment.ProcessId, new string('d', 64));
        var healthy = coordinator.ConsumeSignalAndMarkHealthy(token);
        var tampered = healthy with
        {
            Current = healthy.Current with
            {
                ManifestSha256 = new string('f', 64),
            },
        };
        await File.WriteAllBytesAsync(
            pending.Install.Layout.ReleaseSetPointerPath,
            JsonSerializer.SerializeToUtf8Bytes(
                tampered,
                new JsonSerializerOptions(JsonSerializerDefaults.Web)));
        await AssertThrowsAsync<InvalidDataException>(() =>
            new PersonalBootstrapHealthGate(pending.Install.Layout)
                .EnsureHealthyAsync((_, _, _, _) => Task.FromResult(0)));
    }

    private static async Task InstalledTreeTamperRejectedAsync()
    {
        using var fixture = new ManifestFixture();
        var pending = await CreatePendingInstallAsync("tree-tamper", fixture);
        var token = pending.Result.Pointer.Current.HealthToken!;
        var coordinator = new PersonalReleaseHealthCoordinator(pending.Install.Layout);
        CompleteFixtureHomeHealthAttemptIfRequired(pending.Install.Layout, token);
        coordinator.WriteSignal(token, Environment.ProcessId, new string('e', 64));
        var healthy = coordinator.ConsumeSignalAndMarkHealthy(token);
        File.WriteAllText(
            Path.Combine(
                healthy.Current.Runtime.Directory,
                "node_modules",
                "@deepseek-ai",
                "dsh",
                "package.json"),
            "{\"version\":\"tampered\"}");
        await AssertThrowsAsync<InvalidDataException>(() => Task.Run(() =>
            new PersonalReleaseSetPointerStore(pending.Install.Layout).ReadRequired()));
    }

    private static async Task ExpiredActivationRejectedAsync()
    {
        using var fixture = new ManifestFixture();
        var store = NewStore("expired-activation");
        var accepted = await store.VerifyAndAcceptAsync(
            fixture.Serialize(expiresAtUtc: Now.AddHours(1)),
            fixture.Policy,
            Now);
        await AssertThrowsAsync<InvalidDataException>(async () =>
        {
            await using var admission = await store.AcquireActivationAdmissionAsync(
                accepted.Verified,
                Now.AddHours(2));
        });
    }

    private static async Task UnexpectedArchiveFileRejectedAsync()
    {
        var root = NewTempPath("unexpected-archive", "root");
        Directory.CreateDirectory(root);
        var layout = new PersonalInstallationLayout(
            Path.Combine(root, "managed"),
            Path.Combine(root, "home"));
        var archive = CreateComponentArchive(
            root,
            PersonalReleaseSetContract.ClientBundleComponent,
            "client-unexpected-v1",
            new Dictionary<string, byte[]>(StringComparer.Ordinal)
            {
                [PersonalInstallationLayout.ClientBootstrapperExecutableName] = [1],
                [PersonalInstallationLayout.LauncherExecutableName] = [2],
                [PersonalInstallationLayout.MaintenanceExecutableName] = [3],
            },
            new Dictionary<string, byte[]>(StringComparer.Ordinal)
            {
                ["unexpected.dll"] = [3],
            });
        await AssertThrowsAsync<InvalidDataException>(() =>
            new PersonalReleaseArtifactInstaller().InstallComponentAsync(
                layout,
                archive.Artifact,
                archive.Path,
                layout.GetClientBundleDirectory(archive.Artifact.ReleaseId)));
    }

    private static async Task MissingMaintenanceRejectedAsync()
    {
        var root = NewTempPath("missing-maintenance", "root");
        Directory.CreateDirectory(root);
        var layout = new PersonalInstallationLayout(
            Path.Combine(root, "managed"),
            Path.Combine(root, "home"));
        var archive = CreateComponentArchive(
            root,
            PersonalReleaseSetContract.ClientBundleComponent,
            "client-missing-maintenance-v1",
            new Dictionary<string, byte[]>(StringComparer.Ordinal)
            {
                [PersonalInstallationLayout.ClientBootstrapperExecutableName] = [1],
                [PersonalInstallationLayout.LauncherExecutableName] = [2],
            });
        await AssertThrowsAsync<InvalidDataException>(() =>
            new PersonalReleaseArtifactInstaller().InstallComponentAsync(
                layout,
                archive.Artifact,
                archive.Path,
                layout.GetClientBundleDirectory(archive.Artifact.ReleaseId)));
    }

    private static async Task<PendingInstall> CreateHealthyInstallAsync(
        string scope,
        ManifestFixture fixture)
    {
        var pending = await CreatePendingInstallAsync(scope, fixture);
        var token = pending.Result.Pointer.Current.HealthToken!;
        var coordinator = new PersonalReleaseHealthCoordinator(pending.Install.Layout);
        CompleteFixtureHomeHealthAttemptIfRequired(pending.Install.Layout, token);
        coordinator.WriteSignal(token, Environment.ProcessId, new string('8', 64));
        _ = coordinator.ConsumeSignalAndMarkHealthy(token);
        return pending;
    }

    private static void CompleteFixtureHomeHealthAttemptIfRequired(
        PersonalInstallationLayout layout,
        string healthToken)
    {
        var pointer = new PersonalReleaseSetPointerStore(layout).ReadRequired();
        var homeMode = PersonalReleaseSetPointerStore
            .GetPendingHomeTransactionMode(pointer);
        if (homeMode == PersonalReleaseHomeTransactionMode.NoneRuntimeReused)
        {
            return;
        }
        AssertEqual(pointer.Current.HealthToken, healthToken);
        var transactionId = pointer.Current.HomeTransactionId
            ?? throw new InvalidDataException(
                "Fixture pending release has no Harness-home transaction.");
        using var lease = new PersonalHarnessHomeCoordinator(layout.HarnessHome)
            .AcquireLease(static () => { });
        CompleteFixtureHomeHealthAttempt(lease, transactionId, healthToken);
    }

    private static void CompleteFixtureHomeHealthAttempt(
        PersonalHarnessHomeLease lease,
        string transactionId,
        string healthToken)
    {
        lease.AdmitHealthAttempt(transactionId, healthToken);
        using (var runtimeSession = lease.BeginRuntimeSession())
        {
            // Fixture-only stand-in for the DshHostService job events; no process starts.
            runtimeSession.RecordAssignedProcess(12345, 1);
            runtimeSession.RecordJobEmpty();
        }
        lease.CompleteHealthAttempt(transactionId, healthToken);
        lease.RequireCompletedHealthAttempt(transactionId, healthToken);
    }

    private static async Task<PersonalReleaseAdmissionResult> AcceptFollowupAsync(
        PendingInstall pending,
        ManifestFixture fixture,
        string releaseSetId,
        IReadOnlyList<PersonalReleaseArtifact> artifacts,
        string? minimumStartupStubVersion = null,
        long generation = 12,
        long sequence = 12)
    {
        return await pending.Security.VerifyAndAcceptAsync(
            CreateFollowupManifestBytes(
                pending,
                fixture,
                releaseSetId,
                artifacts,
                minimumStartupStubVersion,
                generation,
                sequence),
            fixture.Policy,
            Now);
    }

    private static byte[] CreateFollowupManifestBytes(
        PendingInstall pending,
        ManifestFixture fixture,
        string releaseSetId,
        IReadOnlyList<PersonalReleaseArtifact> artifacts,
        string? minimumStartupStubVersion = null,
        long generation = 12,
        long sequence = 12)
    {
        var current = PersonalReleaseSetValidator.ParseAndVerify(
            pending.Install.ManifestBytes,
            fixture.Policy,
            Now).Manifest;
        var unsigned = current with
        {
            ReleaseSetId = releaseSetId,
            Generation = generation,
            Sequence = sequence,
            IssuedAtUtc = Now,
            ExpiresAtUtc = Now.AddDays(2),
            Artifacts = artifacts,
            StartupStub = minimumStartupStubVersion is null
                ? current.StartupStub
                : current.StartupStub with
                {
                    MinimumVersion = minimumStartupStubVersion,
                },
            Signature = null,
        };
        return PersonalReleaseSetJson.SerializeSigned(PersonalReleaseSetSigner.Sign(
            unsigned,
            "personal-release-2026",
            fixture.Key));
    }

    private static async Task<PendingInstall> CreatePendingInstallAsync(
        string scope,
        ManifestFixture fixture)
    {
        var install = CreateInstallFixture(scope, fixture);
        var security = new PersonalReleaseSecurityStateStore(
            install.Layout.UpdateSecurityStatePath,
            StateIdentity(),
            install.Layout.UpdateSecurityWitnessPath);
        var accepted = await security.VerifyAndAcceptAsync(
            install.ManifestBytes,
            fixture.Policy,
            Now);
        var result = await NewTestArtifactInstaller().InstallReleaseSetAsync(
            install.Layout,
            accepted.Verified,
            install.ClientArchivePath,
            install.RuntimeArchivePath,
            GetFreePort());
        return new PendingInstall(install, security, result);
    }

    private static PersonalReleaseSecurityStateStore NewStore(string name) => new(
        NewTempPath(name, "state.dpapi"),
        StateIdentity(),
        NewTempPath($"{name}-witness", "witness.dpapi"));

    private static PersonalReleaseStateIdentity StateIdentity() => new(
        PersonalReleaseSetContract.Product,
        PersonalReleaseSetContract.ProductionEnvironment,
        "stable");

    private static PersistentArtifactDownloadRequest DownloadRequest(byte[] payload, string cache) => new(
        new Uri("https://updates.example.test/artifacts/runtime.zip"),
        cache,
        payload.LongLength,
        Sha256(payload),
        ReadIdleTimeout: TimeSpan.FromSeconds(2));

    private static HttpResponseMessage FullResponse(byte[] payload, string? etag)
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(payload),
        };
        SetEtag(response, etag);
        return response;
    }

    private static HttpResponseMessage ShortResponse(
        byte[] payload,
        long advertisedLength,
        string? etag)
    {
        var response = FullResponse(payload, etag);
        response.Content.Headers.ContentLength = advertisedLength;
        return response;
    }

    private static HttpResponseMessage PartialResponse(
        byte[] payload,
        long start,
        long total,
        string etag)
    {
        var response = new HttpResponseMessage(HttpStatusCode.PartialContent)
        {
            Content = new ByteArrayContent(payload),
        };
        response.Content.Headers.ContentRange = new ContentRangeHeaderValue(
            start,
            total - 1,
            total);
        SetEtag(response, etag);
        return response;
    }

    private static void SetEtag(HttpResponseMessage response, string? etag)
    {
        if (etag is not null)
        {
            response.Headers.ETag = new EntityTagHeaderValue(etag);
        }
    }

    private static string NewTempPath(string scope, string leaf)
    {
        var directory = Path.Combine(TempRoot, scope);
        Directory.CreateDirectory(directory);
        return Path.Combine(directory, leaf);
    }

    private static string Sha256(ReadOnlySpan<byte> value) =>
        Convert.ToHexStringLower(SHA256.HashData(value));

    private static int GetFreePort()
    {
        var listener = new TcpListener(System.Net.IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            return ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
        }
        finally
        {
            listener.Stop();
        }
    }

    private static InstallFixture CreateInstallFixture(
        string scope,
        ManifestFixture fixture,
        string minimumStub = "1.0.0",
        string maximumStub = "1.9.9")
    {
        var root = NewTempPath(scope, "install-root");
        Directory.CreateDirectory(root);
        var layout = new PersonalInstallationLayout(
            Path.Combine(root, "managed"),
            Path.Combine(root, "home"));
        var client = CreateComponentArchive(
            root,
            PersonalReleaseSetContract.ClientBundleComponent,
            "client-install-v1",
            new Dictionary<string, byte[]>(StringComparer.Ordinal)
            {
                [PersonalInstallationLayout.ClientBootstrapperExecutableName] =
                    Encoding.UTF8.GetBytes("client bootstrapper"),
                [PersonalInstallationLayout.LauncherExecutableName] =
                    Encoding.UTF8.GetBytes("launcher"),
                [PersonalInstallationLayout.MaintenanceExecutableName] =
                    Encoding.UTF8.GetBytes("maintenance"),
                ["licenses/notice.txt"] = Encoding.UTF8.GetBytes("notice"),
            });
        var runtime = CreateComponentArchive(
            root,
            PersonalReleaseSetContract.RuntimeComponent,
            "runtime-install-v1",
            new Dictionary<string, byte[]>(StringComparer.Ordinal)
            {
                ["node.exe"] = Encoding.UTF8.GetBytes("node"),
                ["node_modules/@deepseek-ai/dsh/lib/bin.js"] =
                    Encoding.UTF8.GetBytes("console.log('dsh')"),
                ["node_modules/@deepseek-ai/dsh/package.json"] =
                    Encoding.UTF8.GetBytes("{\"version\":\"0.1.1\"}"),
            });
        var unsigned = fixture.CreateSigned(
            minimumStub: minimumStub,
            maximumStub: maximumStub) with
        {
            ReleaseSetId = "personal-install-v1",
            Generation = 11,
            Sequence = 11,
            MinAcceptedSequence = 10,
            Artifacts = [client.Artifact, runtime.Artifact],
            Signature = null,
        };
        var signed = PersonalReleaseSetSigner.Sign(
            unsigned,
            "personal-release-2026",
            fixture.Key);
        return new InstallFixture(
            layout,
            client.Path,
            runtime.Path,
            PersonalReleaseSetJson.SerializeSigned(signed));
    }

    private static ComponentArchive CreateComponentArchive(
        string root,
        string component,
        string releaseId,
        IReadOnlyDictionary<string, byte[]> files,
        IReadOnlyDictionary<string, byte[]>? unexpectedFiles = null)
    {
        var tree = new PersonalCompleteTreeManifest
        {
            SchemaVersion = 1,
            Component = component,
            ReleaseId = releaseId,
            Files = files.OrderBy(pair => pair.Key, StringComparer.Ordinal)
                .Select(pair => new PersonalCompleteTreeFile
                {
                    Path = pair.Key,
                    SizeBytes = pair.Value.LongLength,
                    Sha256 = Sha256(pair.Value),
                })
                .ToArray(),
        };
        var treeBytes = JsonSerializer.SerializeToUtf8Bytes(
            tree,
            new JsonSerializerOptions(JsonSerializerDefaults.Web));
        var treePath = Path.Combine(root, releaseId + ".tree.json");
        File.WriteAllBytes(treePath, treeBytes);
        var path = Path.Combine(root, releaseId + ".zip");
        using (var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        using (var archive = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: false))
        {
            foreach (var pair in files.OrderBy(pair => pair.Key, StringComparer.Ordinal))
            {
                var entry = archive.CreateEntry(pair.Key, CompressionLevel.NoCompression);
                using var stream = entry.Open();
                stream.Write(pair.Value);
            }
            foreach (var pair in (unexpectedFiles ?? new Dictionary<string, byte[]>())
                .OrderBy(pair => pair.Key, StringComparer.Ordinal))
            {
                var entry = archive.CreateEntry(pair.Key, CompressionLevel.NoCompression);
                using var stream = entry.Open();
                stream.Write(pair.Value);
            }
            var treeEntry = archive.CreateEntry(
                PersonalReleaseArtifactInstaller.CompleteTreeEntryName,
                CompressionLevel.NoCompression);
            using var treeStream = treeEntry.Open();
            treeStream.Write(treeBytes);
        }
        var archiveBytes = File.ReadAllBytes(path);
        return new ComponentArchive(
            path,
            treePath,
            new PersonalReleaseArtifact
            {
                Component = component,
                ReleaseId = releaseId,
                Uri = new Uri($"https://updates.example.test/artifacts/{releaseId}.zip"),
                SizeBytes = archiveBytes.LongLength,
                Sha256 = Sha256(archiveBytes),
                CompleteTreeSha256 = Sha256(treeBytes),
            });
    }

    private sealed record ComponentArchive(
        string Path,
        string TreePath,
        PersonalReleaseArtifact Artifact);

    [JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
    private sealed record FrozenV3InstalledReleaseSetReference(
        string ReleaseSetId,
        long Generation,
        long Sequence,
        long MinAcceptedSequence,
        string ManifestSha256,
        PersonalStartupStubCompatibility StartupStub,
        PersonalInstalledComponentReference ClientBundle,
        PersonalInstalledComponentReference Runtime,
        string HealthState,
        string? HealthToken,
        string? HomeTransactionId,
        DateTimeOffset ActivatedAtUtc);

    [JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
    private sealed record FrozenV3InstalledReleaseSetPointer(
        int SchemaVersion,
        string Product,
        string Environment,
        string Channel,
        FrozenV3InstalledReleaseSetReference Current,
        FrozenV3InstalledReleaseSetReference? Previous,
        DateTimeOffset UpdatedAtUtc);

    private static PersonalLegacyV1FallbackReference CreateLegacyV1Fallback(
        PersonalInstallationLayout layout)
    {
        const string releaseId = "legacy-runtime-v1";
        layout.EnsureManagedRoots();
        var runtimeDirectory = layout.GetRuntimeDirectory(releaseId);
        Directory.CreateDirectory(Path.Combine(
            runtimeDirectory,
            "node_modules",
            "@deepseek-ai",
            "dsh",
            "lib"));
        File.WriteAllText(Path.Combine(runtimeDirectory, "node.exe"), "legacy node");
        File.WriteAllText(
            Path.Combine(
                runtimeDirectory,
                "node_modules",
                "@deepseek-ai",
                "dsh",
                "lib",
                "bin.js"),
            "console.log('legacy runtime')");
        File.WriteAllBytes(
            Path.Combine(runtimeDirectory, ".ensou-release.json"),
            JsonSerializer.SerializeToUtf8Bytes(new
            {
                schemaVersion = 1,
                releaseId,
                dshVersion = "0.1.0",
                artifactSha256 = new string('9', 64),
                installedAtUtc = Now,
            }));
        File.WriteAllBytes(
            layout.LegacyRuntimePointerPath,
            JsonSerializer.SerializeToUtf8Bytes(new
            {
                schemaVersion = 1,
                releaseId,
                runtimeDirectory,
                previousReleaseId = (string?)null,
                previousRuntimeDirectory = (string?)null,
                pendingHealthValidation = false,
                snapshotDirectory = (string?)null,
                updatedAtUtc = Now,
            }));
        var launcherDirectory = Path.Combine(
            layout.LegacyLauncherVersionsRoot,
            "legacy-launcher-v1");
        Directory.CreateDirectory(launcherDirectory);
        var launcherPath = Path.Combine(
            launcherDirectory,
            PersonalInstallationLayout.LauncherExecutableName);
        File.Copy(
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe"),
            launcherPath,
            overwrite: true);
        File.WriteAllBytes(
            layout.LegacyLauncherPointerPath,
            JsonSerializer.SerializeToUtf8Bytes(new
            {
                schemaVersion = 1,
                launcherDirectory,
                previousLauncherDirectory = (string?)null,
                updatedAtUtc = Now,
            }));
        return new PersonalLegacyV1FallbackReference(
            releaseId,
            runtimeDirectory,
            launcherPath);
    }

    private static async Task<int> RunRealExitProcessAsync(
        int exitCode,
        CancellationToken cancellationToken)
    {
        using var process = StartRealExitProcess(exitCode);
        await process.WaitForExitAsync(cancellationToken);
        return process.ExitCode;
    }

    private static Process StartRealExitProcess(int exitCode)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                "cmd.exe"),
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        startInfo.ArgumentList.Add("/d");
        startInfo.ArgumentList.Add("/c");
        startInfo.ArgumentList.Add("exit");
        startInfo.ArgumentList.Add("/b");
        startInfo.ArgumentList.Add(exitCode.ToString(System.Globalization.CultureInfo.InvariantCulture));
        return Process.Start(startInfo)
            ?? throw new InvalidOperationException("Could not start real process test helper.");
    }

    private sealed record InstallFixture(
        PersonalInstallationLayout Layout,
        string ClientArchivePath,
        string RuntimeArchivePath,
        byte[] ManifestBytes);

    private sealed record PendingInstall(
        InstallFixture Install,
        PersonalReleaseSecurityStateStore Security,
        PersonalReleaseSetInstallationResult Result);

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

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
        throw new InvalidOperationException($"Expected {typeof(TException).Name}.");
    }

    private static void AssertThrows<TException>(Action action)
        where TException : Exception
    {
        try
        {
            action();
        }
        catch (TException)
        {
            return;
        }
        throw new InvalidOperationException($"Expected {typeof(TException).Name}.");
    }

    private static TException AssertThrowsAndReturn<TException>(Action action)
        where TException : Exception
    {
        try
        {
            action();
        }
        catch (TException exception)
        {
            return exception;
        }
        throw new InvalidOperationException($"Expected {typeof(TException).Name}.");
    }

    private static void AssertMutationDenied(Action action)
    {
        try
        {
            action();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return;
        }
        throw new InvalidOperationException("Expected the locked file mutation to be denied.");
    }

    private static void AssertTrue(bool value)
    {
        if (!value)
        {
            throw new InvalidOperationException("Expected true.");
        }
    }

    private static void AssertFalse(bool value) => AssertTrue(!value);

    private static void AssertEqual<T>(T expected, T actual)
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
        {
            throw new InvalidOperationException($"Expected '{expected}', got '{actual}'.");
        }
    }

    private static void AssertSequenceEqual(ReadOnlySpan<byte> expected, ReadOnlySpan<byte> actual)
    {
        if (!expected.SequenceEqual(actual))
        {
            throw new InvalidOperationException("Byte sequences differ.");
        }
    }

    private static async Task AssertCanonicalLowSRejectionAsync(Func<Task> action)
    {
        try
        {
            await action().ConfigureAwait(false);
        }
        catch (InvalidDataException exception)
        {
            AssertTrue(exception.Message.Contains(
                "canonical low-S",
                StringComparison.Ordinal));
            return;
        }
        throw new InvalidOperationException("Expected canonical low-S rejection.");
    }

    private static void AssertCanonicalLowS(PersonalReleaseSignature signature)
    {
        var bytes = Ensou.Dsh.Contracts.PersonalReleaseBase64Url.Decode(
            signature.Value,
            "test signature");
        var halfOrder = Convert.FromHexString(
            "7FFFFFFF800000007FFFFFFFFFFFFFFFDE737D56D38BCF4279DCE5617E3192A8");
        AssertEqual(64, bytes.Length);
        AssertTrue(bytes.AsSpan(32).SequenceCompareTo(halfOrder) <= 0);
    }

    private static PersonalReleaseSignature CreateHighSSignature(
        PersonalReleaseSignature signature)
    {
        var bytes = Ensou.Dsh.Contracts.PersonalReleaseBase64Url.Decode(
            signature.Value,
            "test signature");
        var order = Convert.FromHexString(
            "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
        var halfOrder = Convert.FromHexString(
            "7FFFFFFF800000007FFFFFFFFFFFFFFFDE737D56D38BCF4279DCE5617E3192A8");
        AssertEqual(64, bytes.Length);
        AssertTrue(bytes.AsSpan(32).SequenceCompareTo(halfOrder) <= 0);

        Span<byte> highS = stackalloc byte[32];
        var borrow = 0;
        for (var index = 31; index >= 0; index--)
        {
            var difference = order[index] - bytes[index + 32] - borrow;
            if (difference < 0)
            {
                difference += 256;
                borrow = 1;
            }
            else
            {
                borrow = 0;
            }
            highS[index] = (byte)difference;
        }
        AssertEqual(0, borrow);
        AssertTrue(highS.SequenceCompareTo(halfOrder) > 0);
        highS.CopyTo(bytes.AsSpan(32));
        return signature with
        {
            Value = Ensou.Dsh.Contracts.PersonalReleaseBase64Url.Encode(bytes),
        };
    }

    private sealed class DelegateHandler(
        Func<HttpRequestMessage, int, HttpResponseMessage> handler) : HttpMessageHandler
    {
        private int _calls;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var response = handler(request, Interlocked.Increment(ref _calls));
            response.RequestMessage ??= request;
            return Task.FromResult(response);
        }
    }

    private sealed class ManifestFixture : IDisposable
    {
        public ManifestFixture(string startupStubVersion = "1.0.0")
        {
            Key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            Policy = new PersonalReleaseTrustPolicy
            {
                Product = PersonalReleaseSetContract.Product,
                Environment = PersonalReleaseSetContract.ProductionEnvironment,
                Channel = "stable",
                ArtifactOrigin = new Uri("https://updates.example.test/"),
                StartupStubVersion = startupStubVersion,
                TrustedKeys = [PersonalReleaseSetSigner.ExportPublicKey("personal-release-2026", Key)],
            };
        }

        public ECDsa Key { get; }

        public PersonalReleaseTrustPolicy Policy { get; }

        public byte[] Serialize(
            long generation = 1,
            long sequence = 1,
            long minAcceptedSequence = 0,
            string releaseSetId = "personal-set-v1",
            DateTimeOffset? issuedAtUtc = null,
            DateTimeOffset? expiresAtUtc = null,
            IReadOnlyList<string>? revocations = null) => PersonalReleaseSetJson.SerializeSigned(
                CreateSigned(
                    generation: generation,
                    sequence: sequence,
                    minAcceptedSequence: minAcceptedSequence,
                    releaseSetId: releaseSetId,
                    issuedAtUtc: issuedAtUtc,
                    expiresAtUtc: expiresAtUtc,
                    revocations: revocations));

        public PersonalReleaseSetManifest CreateSigned(
            string product = PersonalReleaseSetContract.Product,
            string channel = "stable",
            string artifactOrigin = "https://updates.example.test/",
            long generation = 1,
            long sequence = 1,
            long minAcceptedSequence = 0,
            string releaseSetId = "personal-set-v1",
            DateTimeOffset? issuedAtUtc = null,
            DateTimeOffset? expiresAtUtc = null,
            long maximumOfflineGraceSeconds = 7 * 24 * 60 * 60,
            string minimumStub = "1.0.0",
            string maximumStub = "1.9.9",
            IReadOnlyList<string>? revocations = null,
            bool reverseArtifacts = false,
            bool duplicateClientBundle = false)
        {
            var artifacts = new[]
            {
                new PersonalReleaseArtifact
                {
                    Component = PersonalReleaseSetContract.ClientBundleComponent,
                    ReleaseId = "client-v1",
                    Uri = new Uri(artifactOrigin + "artifacts/client.zip"),
                    SizeBytes = 100,
                    Sha256 = new string('1', 64),
                    CompleteTreeSha256 = new string('2', 64),
                },
                new PersonalReleaseArtifact
                {
                    Component = duplicateClientBundle
                        ? PersonalReleaseSetContract.ClientBundleComponent
                        : PersonalReleaseSetContract.RuntimeComponent,
                    ReleaseId = "runtime-v1",
                    Uri = new Uri(artifactOrigin + "artifacts/runtime.zip"),
                    SizeBytes = 200,
                    Sha256 = new string('3', 64),
                    CompleteTreeSha256 = new string('4', 64),
                },
            };
            if (reverseArtifacts)
            {
                Array.Reverse(artifacts);
            }

            var unsigned = new PersonalReleaseSetManifest
            {
                SchemaVersion = PersonalReleaseSetContract.SchemaVersion,
                Product = product,
                Environment = PersonalReleaseSetContract.ProductionEnvironment,
                Channel = channel,
                ReleaseSetId = releaseSetId,
                Provenance = new PersonalReleaseProvenance
                {
                    LauncherRepositoryCommit = new string('a', 40),
                    HarnessSourceTag = "dsh-v0.1.1-rc.2",
                    HarnessSourceCommit = new string('b', 40),
                },
                Generation = generation,
                Sequence = sequence,
                MinAcceptedSequence = minAcceptedSequence,
                IssuedAtUtc = issuedAtUtc ?? Now.AddMinutes(-1),
                ExpiresAtUtc = expiresAtUtc ?? Now.AddDays(1),
                MaximumOfflineGraceSeconds = maximumOfflineGraceSeconds,
                StartupStub = new PersonalStartupStubCompatibility
                {
                    MinimumVersion = minimumStub,
                    MaximumVersion = maximumStub,
                },
                RevokedReleaseSetIds = revocations ?? Array.Empty<string>(),
                Artifacts = artifacts,
            };
            return PersonalReleaseSetSigner.Sign(unsigned, "personal-release-2026", Key);
        }

        public void Dispose() => Key.Dispose();
    }

    private sealed class PublisherFixture : IDisposable
    {
        public PublisherFixture(string scope, bool initializeLedgerAnchor = true)
        {
            var root = NewTempPath(scope, "input");
            Directory.CreateDirectory(root);
            SigningLedgerAnchorAuthorityRoot = Path.Combine(
                root,
                "publisher-security-authority");
            var client = CreateComponentArchive(
                root,
                PersonalReleaseSetContract.ClientBundleComponent,
                "client-v10",
                new Dictionary<string, byte[]>(StringComparer.Ordinal)
                {
                    [PersonalInstallationLayout.ClientBootstrapperExecutableName] =
                        Encoding.UTF8.GetBytes("client bootstrapper"),
                    [PersonalInstallationLayout.LauncherExecutableName] =
                        Encoding.UTF8.GetBytes("launcher"),
                    [PersonalInstallationLayout.MaintenanceExecutableName] =
                        Encoding.UTF8.GetBytes("maintenance"),
                });
            var runtime = CreateComponentArchive(
                root,
                PersonalReleaseSetContract.RuntimeComponent,
                "runtime-v10",
                new Dictionary<string, byte[]>(StringComparer.Ordinal)
                {
                    ["node.exe"] = Encoding.UTF8.GetBytes("node"),
                    ["node_modules/@deepseek-ai/dsh/lib/bin.js"] =
                        Encoding.UTF8.GetBytes("console.log('dsh')"),
                });
            ClientBundleBytes = File.ReadAllBytes(client.Path);
            RuntimeBytes = File.ReadAllBytes(runtime.Path);
            ClientTreeBytes = File.ReadAllBytes(client.TreePath);
            Key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            Config = new PersonalReleasePublisherConfig
            {
                SchemaVersion = 1,
                Environment = PersonalReleaseSetContract.ProductionEnvironment,
                Channel = "stable",
                ReleaseSetId = "personal-set-published",
                Provenance = new PersonalReleaseProvenance
                {
                    LauncherRepositoryCommit = new string('c', 40),
                    HarnessSourceTag = "dsh-v0.1.1-rc.2",
                    HarnessSourceCommit = new string('d', 40),
                },
                Generation = 10,
                Sequence = 10,
                MinAcceptedSequence = 9,
                IssuedAtUtc = Now.AddMinutes(-1),
                ExpiresAtUtc = Now.AddDays(1),
                MaximumOfflineGraceSeconds = 7 * 24 * 60 * 60,
                StartupStub = new PersonalStartupStubCompatibility
                {
                    MinimumVersion = "1.0.0",
                    MaximumVersion = "1.9.9",
                },
                CertifiedStartupStubVersion = "1.0.0",
                RevokedReleaseSetIds = ["personal-set-revoked"],
                ArtifactOrigin = new Uri("https://updates.example.test/"),
                SigningKeyId = "personal-release-2026",
                TrustedKeys =
                [
                    PersonalReleaseSetSigner.ExportPublicKey(
                        "personal-release-2026",
                        Key),
                ],
                SigningPrivateKeyPkcs8Path = Path.Combine(root, "private-key.pk8"),
                SigningLedgerRoot = Path.Combine(root, "signing-ledger"),
                OutputManifestPath = Path.Combine(root, "stable.release-set-v2.json"),
                Artifacts =
                [
                    new PersonalReleasePublisherArtifactInput
                    {
                        Component = PersonalReleaseSetContract.ClientBundleComponent,
                        ReleaseId = "client-v10",
                        Uri = new Uri("https://updates.example.test/artifacts/client.zip"),
                        SourcePath = client.Path,
                        CompleteTreeManifestPath = client.TreePath,
                    },
                    new PersonalReleasePublisherArtifactInput
                    {
                        Component = PersonalReleaseSetContract.RuntimeComponent,
                        ReleaseId = "runtime-v10",
                        Uri = new Uri("https://updates.example.test/artifacts/runtime.zip"),
                        SourcePath = runtime.Path,
                        CompleteTreeManifestPath = runtime.TreePath,
                    },
                ],
            };
            File.WriteAllBytes(
                Config.SigningPrivateKeyPkcs8Path,
                Key.ExportPkcs8PrivateKey());
            SigningLedgerAnchorPath = PersonalPublisherSigningLedger.GetAnchorPath(
                Config,
                SigningLedgerAnchorAuthorityRoot);
            if (initializeLedgerAnchor)
            {
                InitializeLedgerAnchor();
            }
        }

        public ECDsa Key { get; }

        public PersonalReleasePublisherConfig Config { get; }

        public PersonalReleaseTrustPolicy Policy => new()
        {
            Product = PersonalReleaseSetContract.Product,
            Environment = Config.Environment,
            Channel = Config.Channel,
            ArtifactOrigin = Config.ArtifactOrigin,
            StartupStubVersion = Config.CertifiedStartupStubVersion,
            TrustedKeys = Config.TrustedKeys,
        };

        public string SigningLedgerAnchorAuthorityRoot { get; }

        public string SigningLedgerAnchorPath { get; }

        public byte[] ClientBundleBytes { get; }

        public byte[] RuntimeBytes { get; }

        public byte[] ClientTreeBytes { get; }

        public Publisher CreatePublisher(
            Action<PersonalPublisherSigningLedgerCommitStage>? checkpoint = null,
            Action? beforeFinalCancellationCheckpoint = null) => new(
                checkpoint,
                SigningLedgerAnchorAuthorityRoot,
                beforeFinalCancellationCheckpoint);

        public void InitializeLedgerAnchor() =>
            PersonalPublisherSigningLedger.InitializeAnchor(
                Config,
                SigningLedgerAnchorAuthorityRoot);

        public void Dispose() => Key.Dispose();
    }
}
