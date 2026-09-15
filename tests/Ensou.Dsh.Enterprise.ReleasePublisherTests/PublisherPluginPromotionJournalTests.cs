using System.Security.Cryptography;
using System.Text.Json;
using Ensou.Dsh.Enterprise.Installation;
using Ensou.Dsh.Enterprise.ReleasePublisher;

namespace Ensou.Dsh.Enterprise.ReleasePublisherTests;

internal static class PublisherPluginPromotionJournalTests
{
    public static Task RunAsync()
    {
        if (!OperatingSystem.IsWindows())
        {
            return Task.CompletedTask;
        }
        var root = Path.Combine(Path.GetTempPath(), "ensou-dsh-plugin-journal-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var point = signer.ExportParameters(false).Q;
            var trust = new PublisherPluginPromotionJournalTrust("journal-test-key",
                PublisherRuntimeAdmissionEncoding.EncodeBase64Url(point.X!),
                PublisherRuntimeAdmissionEncoding.EncodeBase64Url(point.Y!));
            trust.RequireIndependentFrom((
                "other-test-key",
                HashCoordinate('A'),
                HashCoordinate('B'),
                "other test"));
            AssertThrows(() => trust.RequireIndependentFrom((
                trust.KeyId,
                trust.X,
                trust.Y,
                "reused test")));
            var initialization = PublisherPluginPromotionJournal.Initialize(trust, root);
            var genesisChallenge = PublisherPluginPromotionJournal.ReadChallenge(trust, root);
            AssertTrue(
                genesisChallenge == initialization,
                "initialized journal challenge must be stable before consumption");
            var challengeNow = new DateTimeOffset(
                2026, 8, 27, 0, 0, 0, TimeSpan.Zero);
            var externalChallenge = PublisherPluginPromotionJournalChallenge.Create(
                genesisChallenge,
                challengeNow);
            var externalChallengeJson = JsonSerializer.SerializeToUtf8Bytes(
                externalChallenge,
                new JsonSerializerOptions(JsonSerializerDefaults.Web));
            using (var challengeDocument = JsonDocument.Parse(externalChallengeJson))
            {
                AssertTrue(
                    challengeDocument.RootElement.EnumerateObject()
                        .Select(property => property.Name)
                        .SequenceEqual(new[]
                        {
                            "schemaVersion", "challengeType", "journalInstanceId",
                            "expectedStateRevision", "expectedHeadSha256",
                            "issuedAtUtc", "expiresAtUtc",
                        }),
                    "external journal challenge must match the signer contract exactly");
            }
            AssertTrue(
                externalChallenge.JournalInstanceId == initialization.JournalInstanceId
                    && externalChallenge.ExpectedStateRevision == 0
                    && externalChallenge.ExpectedHeadSha256 == initialization.HeadSha256
                    && externalChallenge.IssuedAtUtc == challengeNow
                    && externalChallenge.ExpiresAtUtc == challengeNow.AddMinutes(15),
                "external journal challenge must bind the live state and a short validity window");
            AssertThrows(() => PublisherPluginPromotionJournal.Initialize(trust, root));
            var intent = Intent();
            AssertIntentExportShape(intent);
            AssertTrue(
                PublisherPluginPromotionJournalCommand.IsRequested(
                    ["--plugin-promotion-journal-intent", "--config", "C:\\release\\publisher.json"]),
                "intent command must be recognized without a private-key argument");
            var authorization = Sign(signer, trust.KeyId, initialization, intent);
            var bytes = JsonSerializer.SerializeToUtf8Bytes(authorization, new JsonSerializerOptions(JsonSerializerDefaults.Web));
            var first = PublisherPluginPromotionJournal.Consume(bytes, trust, intent, DateTimeOffset.UtcNow, root);
            AssertFalse(first.RecoveredExactAuthorization, "first consumption must advance the journal");
            var firstRetry = PublisherPluginPromotionJournal.Consume(
                bytes,
                trust,
                intent,
                DateTimeOffset.UtcNow.AddDays(2),
                root);
            AssertTrue(
                firstRetry.RecoveredExactAuthorization
                    && firstRetry.EntryPath == first.EntryPath
                    && firstRetry.EntrySha256 == first.EntrySha256,
                "exact latest authorization retry must return the durable journal receipt without advancing");
            var reformattedFirst = JsonSerializer.SerializeToUtf8Bytes(
                authorization,
                new JsonSerializerOptions(JsonSerializerDefaults.Web)
                {
                    WriteIndented = true,
                });
            AssertThrows(() => PublisherPluginPromotionJournal.Consume(
                reformattedFirst,
                trust,
                intent,
                DateTimeOffset.UtcNow,
                root));

            var tampered = bytes.ToArray();
            tampered[^1] ^= 1;
            AssertThrows(() => PublisherPluginPromotionJournal.Consume(tampered, trust, intent, DateTimeOffset.UtcNow, root));
            AssertThrows(() => PublisherPluginPromotionJournal.Consume(bytes, trust, intent with { Sequence = 2 }, DateTimeOffset.UtcNow, root));
            var oldInstance = Sign(signer, trust.KeyId, initialization with { JournalInstanceId = Guid.NewGuid().ToString("D") }, intent);
            AssertThrows(() => PublisherPluginPromotionJournal.Consume(JsonSerializer.SerializeToUtf8Bytes(oldInstance, new JsonSerializerOptions(JsonSerializerDefaults.Web)), trust, intent, DateTimeOffset.UtcNow, root));

            var nextIntent = intent with { Sequence = 2 };
            var next = Sign(signer, trust.KeyId, initialization with { StateRevision = 2, HeadSha256 = first.EntrySha256 }, nextIntent);
            AssertThrows(() => PublisherPluginPromotionJournal.Consume(JsonSerializer.SerializeToUtf8Bytes(next, new JsonSerializerOptions(JsonSerializerDefaults.Web)), trust, nextIntent, DateTimeOffset.UtcNow, root));
            var wrongKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using (wrongKey)
            {
                var wrong = Sign(wrongKey, trust.KeyId, initialization with { StateRevision = 1, HeadSha256 = first.EntrySha256 }, intent with { Sequence = 2 });
                AssertThrows(() => PublisherPluginPromotionJournal.Consume(JsonSerializer.SerializeToUtf8Bytes(wrong, new JsonSerializerOptions(JsonSerializerDefaults.Web)), trust, intent with { Sequence = 2 }, DateTimeOffset.UtcNow, root));
            }

            var currentChallenge = PublisherPluginPromotionJournal.ReadChallenge(trust, root);
            AssertTrue(
                currentChallenge.StateRevision == 1
                    && currentChallenge.HeadSha256 == first.EntrySha256,
                "journal challenge must advance to the committed head");
            var validNext = Sign(signer, trust.KeyId, currentChallenge, nextIntent);
            var second = PublisherPluginPromotionJournal.Consume(
                JsonSerializer.SerializeToUtf8Bytes(validNext, new JsonSerializerOptions(JsonSerializerDefaults.Web)),
                trust,
                nextIntent,
                DateTimeOffset.UtcNow,
                root);
            AssertFalse(second.RecoveredExactAuthorization, "next exact authorization must advance once");
            var secondRetry = PublisherPluginPromotionJournal.Consume(
                JsonSerializer.SerializeToUtf8Bytes(validNext, new JsonSerializerOptions(JsonSerializerDefaults.Web)),
                trust,
                nextIntent,
                DateTimeOffset.UtcNow.AddDays(2),
                root);
            AssertTrue(
                secondRetry.RecoveredExactAuthorization
                    && secondRetry.EntryPath == second.EntryPath
                    && secondRetry.EntrySha256 == second.EntrySha256,
                "latest authorization retry must remain idempotent after a later journal advance");
            AssertThrows(() => PublisherPluginPromotionJournal.Consume(
                bytes,
                trust,
                intent,
                DateTimeOffset.UtcNow,
                root));

            var anchor = Directory.EnumerateFiles(Path.Combine(root, "PluginPromotionJournalAnchors"), "*.dpapi").Single();
            File.Delete(anchor);
            AssertThrows(() => PublisherPluginPromotionJournal.Consume(bytes, trust, intent, DateTimeOffset.UtcNow, root));

            var missingJournalRoot = Path.Combine(Path.GetTempPath(), "ensou-dsh-plugin-journal-tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(missingJournalRoot);
            try
            {
                var missingJournalInitialization = PublisherPluginPromotionJournal.Initialize(trust, missingJournalRoot);
                var missingJournalAuthorization = Sign(signer, trust.KeyId, missingJournalInitialization, intent);
                var missingJournalBytes = JsonSerializer.SerializeToUtf8Bytes(missingJournalAuthorization, new JsonSerializerOptions(JsonSerializerDefaults.Web));
                _ = PublisherPluginPromotionJournal.Consume(missingJournalBytes, trust, intent, DateTimeOffset.UtcNow, missingJournalRoot);
                var journalDirectory = Path.Combine(missingJournalRoot, "PluginPromotionJournal", "v1");
                foreach (var file in Directory.EnumerateFiles(journalDirectory, "*", SearchOption.AllDirectories))
                {
                    File.SetAttributes(file, FileAttributes.Normal);
                }
                Directory.Delete(journalDirectory, recursive: true);
                AssertThrows(() => PublisherPluginPromotionJournal.Consume(missingJournalBytes, trust, intent, DateTimeOffset.UtcNow, missingJournalRoot));
            }
            finally
            {
                DeleteTree(missingJournalRoot);
            }

            RunCrashWindowMatrix(signer, trust, intent);
            return Task.CompletedTask;
        }
        finally
        {
            DeleteTree(root);
        }
    }

    private static void RunCrashWindowMatrix(
        ECDsa signer,
        PublisherPluginPromotionJournalTrust trust,
        PublisherPluginPromotionJournalIntent intent)
    {
        foreach (var crashStage in Enum.GetValues<PublisherPluginPromotionJournalCommitStage>())
        {
            var recoveryRoot = Path.Combine(
                Path.GetTempPath(),
                "ensou-dsh-plugin-journal-tests",
                Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(recoveryRoot);
            try
            {
                var initialization = PublisherPluginPromotionJournal.Initialize(trust, recoveryRoot);
                var authorization = Sign(signer, trust.KeyId, initialization, intent);
                var authorizationBytes = JsonSerializer.SerializeToUtf8Bytes(
                    authorization,
                    new JsonSerializerOptions(JsonSerializerDefaults.Web));
                var consumedAtUtc = DateTimeOffset.UtcNow;
                var crashObserved = false;
                try
                {
                    _ = PublisherPluginPromotionJournal.Consume(
                        authorizationBytes,
                        trust,
                        intent,
                        consumedAtUtc,
                        recoveryRoot,
                        stage =>
                        {
                            if (stage == crashStage)
                            {
                                throw new IOException($"injected journal crash at {crashStage}");
                            }
                        });
                }
                catch (IOException)
                {
                    crashObserved = true;
                }
                AssertTrue(crashObserved, $"{crashStage} checkpoint must be reachable");

                var competingAuthorization = Sign(signer, trust.KeyId, initialization, intent);
                AssertThrows(() => PublisherPluginPromotionJournal.Consume(
                    JsonSerializer.SerializeToUtf8Bytes(
                        competingAuthorization,
                        new JsonSerializerOptions(JsonSerializerDefaults.Web)),
                    trust,
                    intent,
                    consumedAtUtc,
                    recoveryRoot));

                if (crashStage == PublisherPluginPromotionJournalCommitStage.EntryWritten)
                {
                    var wrongRecoveryInstance = Sign(
                        signer,
                        trust.KeyId,
                        initialization with { JournalInstanceId = Guid.NewGuid().ToString("D") },
                        intent);
                    AssertThrows(() => PublisherPluginPromotionJournal.Consume(
                        JsonSerializer.SerializeToUtf8Bytes(
                            wrongRecoveryInstance,
                            new JsonSerializerOptions(JsonSerializerDefaults.Web)),
                        trust,
                        intent,
                        consumedAtUtc,
                        recoveryRoot));
                }

                var authorizationExpiredAtUtc = consumedAtUtc.AddDays(2);
                PublisherPluginPromotionJournalConsumption recovered;
                if (crashStage is PublisherPluginPromotionJournalCommitStage.AnchorCommitted
                    or PublisherPluginPromotionJournalCommitStage.PendingDeleted)
                {
                    recovered = PublisherPluginPromotionJournal.Consume(
                        authorizationBytes,
                        trust,
                        intent,
                        authorizationExpiredAtUtc,
                        recoveryRoot);
                }
                else
                {
                    AssertThrows(() => PublisherPluginPromotionJournal.Consume(
                        authorizationBytes,
                        trust,
                        intent,
                        authorizationExpiredAtUtc,
                        recoveryRoot));
                    recovered = PublisherPluginPromotionJournal.Consume(
                        authorizationBytes,
                        trust,
                        intent,
                        consumedAtUtc,
                        recoveryRoot);
                }
                AssertTrue(
                    recovered.RecoveredExactAuthorization,
                    $"{crashStage} must recover only the exact authorization");

                var afterRecovery = PublisherPluginPromotionJournal.ReadChallenge(trust, recoveryRoot);
                AssertTrue(
                    afterRecovery.StateRevision == 1
                        && afterRecovery.HeadSha256 == recovered.EntrySha256,
                    $"{crashStage} recovery must advance exactly once");
                var exactRetry = PublisherPluginPromotionJournal.Consume(
                    authorizationBytes,
                    trust,
                    intent,
                    authorizationExpiredAtUtc,
                    recoveryRoot);
                AssertTrue(
                    exactRetry.RecoveredExactAuthorization
                        && exactRetry.EntryPath == recovered.EntryPath
                        && exactRetry.EntrySha256 == recovered.EntrySha256,
                    $"{crashStage} exact retry must be read-only and must not produce N+1");
            }
            finally
            {
                DeleteTree(recoveryRoot);
            }
        }
    }

    private static PublisherPluginPromotionJournalIntent Intent() => new(
        "production", "pilot", "enterprise-2026.08.27.1", "release-key", 1, 1, 0,
        Artifact("launcher", "launcher-1", "https://example.invalid/launcher.zip"),
        Artifact("runtime", "runtime-1", "https://example.invalid/runtime.zip"),
        Artifact("plugin-policy", "plugins-1", "https://example.invalid/plugins.zip"),
        "11111111-2222-4333-8444-555555555555", 1,
        Hash('a'), Hash('b'), Hash('c'), Hash('d'), Hash('e'),
        Hash('f'), "plugin-ledger-test", Hash('7'), Hash('8'), Hash('0'));

    private static PublisherPluginPromotionArtifactIdentity Artifact(string component, string releaseId, string uri) =>
        new(component, releaseId, uri, 1, Hash('1'), Hash('2'));

    private static void AssertIntentExportShape(PublisherPluginPromotionJournalIntent intent)
    {
        using var document = JsonDocument.Parse(JsonSerializer.SerializeToUtf8Bytes(
            intent,
            new JsonSerializerOptions(JsonSerializerDefaults.Web) { WriteIndented = true }));
        AssertTrue(
            document.RootElement.EnumerateObject().Select(value => value.Name).SequenceEqual(
            [
                "environment", "channel", "releaseSetId", "releaseSigningKeyId",
                "generation", "sequence", "minAcceptedSequence", "launcher", "runtime",
                "pluginPolicy", "policyId", "policyGeneration", "pluginMetadataSha256",
                "rawPolicySha256", "promotionHandoffSha256", "compatibilityReceiptSha256",
                "reservationSha256", "runtimeSourceMetadataSha256", "generationLedgerNamespace",
                "generationLedgerPathSha256", "generationLedgerSha256",
                "organizationAdmissionReceiptSha256",
            ]),
            "exported intent must use the signer-facing camelCase contract without journal state");
    }

    private static PublisherPluginPromotionJournalAuthorization Sign(
        ECDsa signer,
        string keyId,
        PublisherPluginPromotionJournalInitialization initialization,
        PublisherPluginPromotionJournalIntent intent)
    {
        var value = new PublisherPluginPromotionJournalAuthorization
        {
            SchemaVersion = 1,
            AuthorizationType = PublisherPluginPromotionJournalAuthorization.CurrentAuthorizationType,
            AuthorizationId = Guid.NewGuid().ToString("D"),
            JournalInstanceId = initialization.JournalInstanceId,
            ExpectedStateRevision = initialization.StateRevision,
            ExpectedHeadSha256 = initialization.HeadSha256,
            IssuedAtUtc = DateTimeOffset.UtcNow.AddMinutes(-1),
            ExpiresAtUtc = DateTimeOffset.UtcNow.AddHours(1),
            Intent = intent,
            Signature = new EnterpriseReleaseSignature { Algorithm = EnterpriseReleaseSetContract.SignatureAlgorithm, KeyId = keyId, Value = new string('a', 86) },
        };
        return value with
        {
            Signature = value.Signature with
            {
                Value = PublisherRuntimeAdmissionEncoding.EncodeBase64Url(signer.SignData(value.CanonicalPayload(), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)),
            },
        };
    }

    private static string Hash(char character) => new(character, 64);
    private static string HashCoordinate(char character) =>
        PublisherRuntimeAdmissionEncoding.EncodeBase64Url(
            Enumerable.Repeat((byte)character, 32).ToArray());
    private static void DeleteTree(string root)
    {
        if (!Directory.Exists(root))
        {
            return;
        }
        foreach (var file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
        {
            File.SetAttributes(file, FileAttributes.Normal);
        }
        Directory.Delete(root, recursive: true);
    }
    private static void AssertTrue(bool value, string label) { if (!value) throw new InvalidOperationException(label); }
    private static void AssertFalse(bool value, string label) { if (value) throw new InvalidOperationException(label); }
    private static void AssertThrows(Action action)
    {
        try { action(); }
        catch (InvalidDataException) { return; }
        throw new InvalidOperationException("Expected InvalidDataException.");
    }
}
