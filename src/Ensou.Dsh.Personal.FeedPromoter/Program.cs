using System.Text.Json;

namespace Ensou.Dsh.Personal.FeedPromoter;

internal static class Program
{
    internal static int Main(string[] args)
    {
        try
        {
            LinuxNative.RequireRoot();
            if (args is ["export-completed-operation", "--feed-root", var exportFeed,
                "--trust-policy", var exportTrust, "--operation-id", var exportOperation,
                "--output-directory", var exportDirectory])
            {
                PersonalFeedCompletedOperationExport.Export(exportFeed, exportTrust, exportOperation, exportDirectory);
                Console.WriteLine("PERSONAL-COMPLETED-OPERATION-EXPORT-PASS unsigned-snapshot-only");
                return 0;
            }
            if (args is ["initialize", "--feed-root", var feedRoot])
            {
                var layout = PersonalFeedLayout.Initialize(feedRoot);
                var initialized = PersonalFeedLayout.ReadInitializationResult(layout.Root);
                Console.WriteLine(JsonSerializer.Serialize(
                    initialized,
                    PersonalFeedJson.Options));
                return 0;
            }

            if (args.Length > 0
                && string.Equals(args[0], "certify-distribution", StringComparison.Ordinal))
            {
                var certification = new PersonalDistributionReceiptProducer()
                    .Produce(ParseCertification(args));
                Console.WriteLine(
                    $"PERSONAL-DISTRIBUTION-CERTIFICATION-PASS {certification.ReleaseSetId} "
                    + $"receipt={certification.ReceiptSha256} "
                    + $"gate={certification.ProductionGateEvidenceSha256} "
                    + $"installer={certification.InstallerSha256}");
                return 0;
            }

            if (args.Length > 0
                && string.Equals(args[0], "preflight-distribution", StringComparison.Ordinal))
            {
                var preflight = new PersonalDistributionReceiptProducer()
                    .Preflight(ParsePreflight(args));
                Console.WriteLine(
                    $"PERSONAL-DISTRIBUTION-PREFLIGHT-PASS {preflight.ReleaseSetId} "
                    + $"pilot={preflight.PilotManifestSha256} "
                    + $"stable={preflight.StableManifestSha256} "
                    + $"receipt-preview={preflight.ReceiptPreviewSha256} "
                    + $"gate={preflight.ProductionGateEvidenceSha256} "
                    + $"installer={preflight.InstallerSha256} "
                    + $"release-key={preflight.ReleaseKeyId} "
                    + $"signer={preflight.AuthenticodeSignerSha256Thumbprint} "
                    + $"manifest-origin={preflight.ManifestOrigin} "
                    + $"artifact-origin={preflight.ArtifactOrigin} "
                    + $"launcher-commit={preflight.LauncherRepositoryCommit} "
                    + $"harness-tag={preflight.HarnessSourceTag} "
                    + $"harness-commit={preflight.HarnessSourceCommit} "
                    + "receipt-created=false");
                return 0;
            }

            var options = ParsePromotion(args);
            var result = new PersonalFeedPromoter().Promote(options);
            WriteResultReceipt(
                options.ResultReceiptPath
                    ?? throw new InvalidDataException(
                        "Production promotion requires a result receipt path."),
                result,
                options.FeedRoot,
                options.CandidateDirectory,
                options.TrustConfigurationPath);
            Console.WriteLine(
                $"PERSONAL-FEED-PROMOTION-PASS {result.Channel} "
                + $"{result.ReleaseSetId} {result.ManifestSha256} "
                + $"journal={result.JournalEntrySha256}");
            return 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine($"Personal feed operation failed: {exception.Message}");
            return 1;
        }
    }

    private static PersonalFeedPromotionOptions ParsePromotion(string[] args)
    {
        if (args.Length < 9
            || !string.Equals(args[0], "promote", StringComparison.Ordinal)
            || (args.Length - 1) % 2 != 0)
        {
            throw new ArgumentException(Usage);
        }
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var index = 1; index < args.Length; index += 2)
        {
            if (!values.TryAdd(args[index], args[index + 1]))
            {
                throw new ArgumentException("Personal FeedPromoter argument was repeated.");
            }
        }
        var allowed = new HashSet<string>(StringComparer.Ordinal)
        {
            "--candidate",
            "--feed-root",
            "--trust-policy",
            "--channel",
            "--certified-distribution-receipt",
            "--stable-authorization",
            "--clean-device-lifecycle",
            "--two-update-upgrade-lifecycle",
            "--failure-recovery-lifecycle",
            "--production-gate-evidence",
            "--operation-id",
            "--expected-feed-identity-sha256",
            "--expected-channel-head",
            "--expected-journal-head",
            "--result-receipt",
        };
        if (values.Keys.Any(key => !allowed.Contains(key)))
        {
            throw new ArgumentException("Personal FeedPromoter received an unknown argument.");
        }
        return new PersonalFeedPromotionOptions(
            Require(values, "--candidate"),
            Require(values, "--feed-root"),
            Require(values, "--trust-policy"),
            Require(values, "--channel"),
            Optional(values, "--certified-distribution-receipt"),
            Optional(values, "--stable-authorization"),
            Optional(values, "--clean-device-lifecycle"),
            Optional(values, "--two-update-upgrade-lifecycle"),
            Optional(values, "--failure-recovery-lifecycle"),
            Optional(values, "--production-gate-evidence"),
            new PersonalFeedProductionFoundation(
                Require(values, "--operation-id"),
                Require(values, "--expected-feed-identity-sha256"),
                ParseRawExpectation(
                    Require(values, "--expected-channel-head"),
                    "channel head"),
                ParseRawExpectation(
                    Require(values, "--expected-journal-head"),
                    "journal head")),
            Require(values, "--result-receipt"));
    }

    internal static PersonalFeedRawStateExpectation ParseRawExpectation(
        string value,
        string label)
    {
        if (string.Equals(value, "missing", StringComparison.Ordinal))
        {
            return PersonalFeedRawStateExpectation.Missing();
        }
        var parts = value.Split(':', StringSplitOptions.None);
        if (parts is ["present", var sizeText, var sha256]
            && long.TryParse(
                sizeText,
                System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture,
                out var size))
        {
            var expectation = PersonalFeedRawStateExpectation.Present(size, sha256);
            expectation.Validate(label);
            return expectation;
        }
        throw new ArgumentException(
            $"Personal expected {label} must be 'missing' or 'present:<raw-size>:<sha256>'.");
    }

    internal static void WriteResultReceipt(
        string path,
        PersonalFeedPromotionResult result,
        string? feedRoot = null,
        string? candidateRoot = null,
        string? trustPath = null)
    {
        var receipt = result.ProductionReceipt
            ?? throw new InvalidDataException(
                "Personal production promotion did not produce an operation receipt.");
        if (feedRoot is not null && candidateRoot is not null && trustPath is not null)
        {
            path = PersonalFeedPathGuard.RequireExternalResultReceiptPath(
                path,
                feedRoot,
                candidateRoot,
                trustPath);
        }
        if (!Path.IsPathFullyQualified(path))
        {
            throw new InvalidDataException(
                "Personal promotion result receipt must use an absolute path.");
        }
        var full = Path.GetFullPath(path);
        var parent = Path.GetDirectoryName(full)
            ?? throw new InvalidDataException(
                "Personal promotion result receipt has no parent.");
        _ = PersonalFeedPathGuard.RequireExistingDirectory(
            parent,
            "promotion result receipt parent");
        PersonalFeedPathGuard.RequireSafeFileName(
            Path.GetFileName(full),
            "promotion result receipt filename");
        var bytes = PersonalFeedOperationStore.SerializeReceipt(receipt);
        if (File.Exists(full))
        {
            var existing = PersonalFeedPathGuard.ReadBoundedRegularFile(
                full,
                256 * 1024,
                "existing promotion result receipt");
            if (!existing.AsSpan().SequenceEqual(bytes))
            {
                throw new InvalidDataException(
                    "Existing Personal promotion result receipt conflicts with this operation.");
            }
            return;
        }
        PersonalFeedPathGuard.WriteNewDurableAtomicallyCreateOnly(full, bytes);
    }

    private static PersonalDistributionCertificationOptions ParseCertification(
        string[] args)
    {
        if (args.Length != 19 || (args.Length - 1) % 2 != 0)
        {
            throw new ArgumentException(Usage);
        }
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var index = 1; index < args.Length; index += 2)
        {
            if (!values.TryAdd(args[index], args[index + 1]))
            {
                throw new ArgumentException(
                    "Personal distribution certification argument was repeated.");
            }
        }
        var expected = new[]
        {
            "--trust-policy",
            "--pilot-manifest",
            "--stable-manifest",
            "--production-gate-evidence",
            "--external-pilot-feed-evidence",
            "--clean-device-lifecycle",
            "--two-update-upgrade-lifecycle",
            "--failure-recovery-lifecycle",
            "--output",
        };
        if (values.Count != expected.Length
            || expected.Any(key => !values.ContainsKey(key)))
        {
            throw new ArgumentException(Usage);
        }
        return new PersonalDistributionCertificationOptions(
            Require(values, "--trust-policy"),
            Require(values, "--pilot-manifest"),
            Require(values, "--stable-manifest"),
            Require(values, "--production-gate-evidence"),
            Require(values, "--external-pilot-feed-evidence"),
            Require(values, "--clean-device-lifecycle"),
            Require(values, "--two-update-upgrade-lifecycle"),
            Require(values, "--failure-recovery-lifecycle"),
            Require(values, "--output"));
    }

    internal static PersonalDistributionPreflightOptions ParsePreflight(string[] args)
    {
        if (args.Length != 17
            || !string.Equals(args[0], "preflight-distribution", StringComparison.Ordinal)
            || (args.Length - 1) % 2 != 0)
        {
            throw new ArgumentException(Usage);
        }
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var index = 1; index < args.Length; index += 2)
        {
            if (!values.TryAdd(args[index], args[index + 1]))
            {
                throw new ArgumentException(
                    "Personal distribution preflight argument was repeated.");
            }
        }
        var expected = new[]
        {
            "--trust-policy",
            "--pilot-manifest",
            "--stable-manifest",
            "--production-gate-evidence",
            "--external-pilot-feed-evidence",
            "--clean-device-lifecycle",
            "--two-update-upgrade-lifecycle",
            "--failure-recovery-lifecycle",
        };
        if (values.Count != expected.Length
            || expected.Any(key => !values.ContainsKey(key)))
        {
            throw new ArgumentException(Usage);
        }
        return new PersonalDistributionPreflightOptions(
            Require(values, "--trust-policy"),
            Require(values, "--pilot-manifest"),
            Require(values, "--stable-manifest"),
            Require(values, "--production-gate-evidence"),
            Require(values, "--external-pilot-feed-evidence"),
            Require(values, "--clean-device-lifecycle"),
            Require(values, "--two-update-upgrade-lifecycle"),
            Require(values, "--failure-recovery-lifecycle"));
    }

    private static string Require(IReadOnlyDictionary<string, string> values, string name) =>
        Optional(values, name)
        ?? throw new ArgumentException($"Personal FeedPromoter requires {name}.");

    private static string? Optional(IReadOnlyDictionary<string, string> values, string name) =>
        values.TryGetValue(name, out var value) && !string.IsNullOrWhiteSpace(value)
            ? value
            : null;

    private const string Usage =
        "Usage: initialize --feed-root <absolute-empty-directory> | "
        + "promote --candidate <absolute-directory> --feed-root <absolute-directory> "
        + "--trust-policy <absolute-json> --channel <lab|pilot|stable> "
        + "[--certified-distribution-receipt <absolute-json> "
        + "--stable-authorization <absolute-json> "
        + "--clean-device-lifecycle <absolute-json> "
        + "--two-update-upgrade-lifecycle <absolute-json> "
        + "--failure-recovery-lifecycle <absolute-json> "
        + "--production-gate-evidence <absolute-json>] "
        + "--operation-id <lowercase-guid-n> "
        + "--expected-feed-identity-sha256 <sha256> "
        + "--expected-channel-head <missing|present:raw-size:sha256> "
        + "--expected-journal-head <missing|present:raw-size:sha256> "
        + "--result-receipt <new-absolute-json> | "
        + "certify-distribution --trust-policy <absolute-json> "
        + "--pilot-manifest <absolute-json> --stable-manifest <absolute-json> "
        + "--production-gate-evidence <absolute-json> "
        + "--external-pilot-feed-evidence <absolute-json> "
        + "--clean-device-lifecycle <absolute-json> "
        + "--two-update-upgrade-lifecycle <absolute-json> "
        + "--failure-recovery-lifecycle <absolute-json> "
        + "--output <absolute-new-json> | "
        + "preflight-distribution --trust-policy <absolute-json> "
        + "--pilot-manifest <absolute-json> --stable-manifest <absolute-json> "
        + "--production-gate-evidence <absolute-json> "
        + "--external-pilot-feed-evidence <absolute-json> "
        + "--clean-device-lifecycle <absolute-json> "
        + "--two-update-upgrade-lifecycle <absolute-json> "
        + "--failure-recovery-lifecycle <absolute-json>";
}
