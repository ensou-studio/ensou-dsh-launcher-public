using System.Text.Json.Serialization;
using System.Text.Json;
using Ensou.Dsh.Enterprise.Installation;

namespace Ensou.Dsh.Enterprise.FeedPromoter;

internal static class Program
{
    internal static int Main(string[] args)
    {
        try
        {
            LinuxIdentity.RequireRoot();
            if (args is
                [
                    "initialize",
                    "--feed-root",
                    var feedRoot,
                    "--trust-policy",
                    var trustPath
                ])
            {
                var trustBytes = EnterpriseFeedLinuxSecurity.ReadRootOwnedStableFile(
                    trustPath,
                    256 * 1024,
                    "enterprise feed trust configuration");
                var trust = EnterpriseFeedTrustConfiguration.Parse(trustBytes, "pilot");
                var initialized = EnterpriseFeedIdentityStore.Initialize(feedRoot, trust);
                Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(
                    initialized,
                    new System.Text.Json.JsonSerializerOptions(FeedJson.Options) { WriteIndented = false }));
                return 0;
            }
            if (args.Length == 11 && string.Equals(args[0], "attest-publication", StringComparison.Ordinal))
            {
                var values = ParsePublicationAttestationArguments(args);
                var envelope = new EnterpriseStablePublicationAttestor().Attest(new(
                    values["--feed-root"], values["--context"], values["--trust-policy"],
                    values["--signing-key"], values["--output-bundle"]));
                Console.WriteLine(JsonSerializer.Serialize(envelope, FeedJson.Options));
                return 0;
            }
            var options = Parse(args);
            var result = new EnterpriseFeedPromoter().Promote(options);
            if (options.ResultReceiptPath is not null)
            {
                WriteResultReceipt(
                    options.ResultReceiptPath,
                    result,
                    options.FeedRoot,
                    options.CandidateDirectory,
                    options.TrustConfigurationPath);
            }
            Console.WriteLine(
                $"ENTERPRISE-FEED-PROMOTION-PASS {result.Channel} "
                + $"{result.ReleaseSetId} {result.ManifestSha256} "
                + $"journal={result.JournalEntrySha256}");
            return 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine($"Enterprise feed promotion failed: {exception.Message}");
            return 1;
        }
    }

    private static EnterpriseFeedPromotionOptions Parse(string[] args)
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
                throw new ArgumentException("Feed promoter argument was repeated.");
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
            "--result-receipt",
            "--operation-id",
            "--expected-feed-identity-sha256",
            "--expected-channel-head",
            "--expected-journal-head",
        };
        if (values.Keys.Any(key => !allowed.Contains(key)))
        {
            throw new ArgumentException("Feed promoter received an unknown argument.");
        }
        return new EnterpriseFeedPromotionOptions(
            Require(values, "--candidate"),
            Require(values, "--feed-root"),
            Require(values, "--trust-policy"),
            Require(values, "--channel"),
            Optional(values, "--certified-distribution-receipt"),
            Optional(values, "--stable-authorization"),
            Require(values, "--result-receipt"),
            new EnterpriseFeedProductionFoundation(
                Require(values, "--operation-id"),
                Require(values, "--expected-feed-identity-sha256"),
                ParseRawExpectation(
                    Require(values, "--expected-channel-head"),
                    "channel head"),
                ParseRawExpectation(
                    Require(values, "--expected-journal-head"),
                    "journal head")));
    }

    private static Dictionary<string, string> ParsePublicationAttestationArguments(string[] args)
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var index = 1; index < args.Length; index += 2)
        {
            if (!values.TryAdd(args[index], args[index + 1]))
                throw new ArgumentException("Publication attestation argument was repeated.");
        }
        var required = new[] { "--feed-root", "--context", "--trust-policy", "--signing-key", "--output-bundle" };
        if (values.Count != required.Length || required.Any(key => !values.ContainsKey(key)) || values.Values.Any(string.IsNullOrWhiteSpace))
            throw new ArgumentException("Publication attestation requires exactly --feed-root --context --trust-policy --signing-key --output-bundle.");
        return values;
    }

    internal static EnterpriseFeedRawStateExpectation ParseRawExpectation(
        string value,
        string label)
    {
        if (string.Equals(value, "missing", StringComparison.Ordinal))
        {
            return EnterpriseFeedRawStateExpectation.Missing();
        }
        var parts = value.Split(':', StringSplitOptions.None);
        if (parts is ["present", var sizeText, var sha256]
            && long.TryParse(
                sizeText,
                System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture,
                out var size))
        {
            var expectation = EnterpriseFeedRawStateExpectation.Present(size, sha256);
            expectation.Validate(label);
            return expectation;
        }
        throw new ArgumentException(
            $"Enterprise expected {label} must be 'missing' or 'present:<raw-size>:<sha256>'.");
    }

    private static string Require(IReadOnlyDictionary<string, string> values, string name)
    {
        var value = Optional(values, name);
        return value ?? throw new ArgumentException($"Feed promoter requires {name}.");
    }

    private static string? Optional(IReadOnlyDictionary<string, string> values, string name) =>
        values.TryGetValue(name, out var value) && !string.IsNullOrWhiteSpace(value)
            ? value
            : null;

    internal static void WriteResultReceipt(
        string path,
        EnterpriseFeedPromotionResult result,
        string? feedRoot = null,
        string? candidateRoot = null,
        string? trustPath = null)
    {
        if (feedRoot is not null && candidateRoot is not null && trustPath is not null)
        {
            path = FeedPathGuard.RequireExternalResultReceiptPath(
                path,
                feedRoot,
                candidateRoot,
                trustPath);
        }
        if (!Path.IsPathFullyQualified(path))
        {
            throw new InvalidDataException(
                "Promotion result receipt must use an absolute file path.");
        }
        var full = Path.GetFullPath(path);
        var parent = Path.GetDirectoryName(full)
            ?? throw new InvalidDataException("Promotion result receipt has no parent.");
        _ = FeedPathGuard.RequireExistingDirectory(parent, "promotion result receipt parent");
        FeedPathGuard.RequireSafeFileName(
            Path.GetFileName(full),
            "promotion result receipt filename");
        var bytes = result.ProductionReceipt is not null
            ? EnterpriseFeedOperationStore.SerializeReceipt(result.ProductionReceipt)
            : FeedJson.Serialize(new EnterpriseFeedPromotionResultReceipt(
            1,
            result.Product,
            result.Environment,
            result.Channel,
            result.ReleaseSetId,
            result.Generation,
            result.Sequence,
            result.MinAcceptedSequence,
            result.ManifestSha256,
            result.ChannelManifestPath,
            result.JournalEntryPath,
            result.JournalEntrySha256,
            result.PublishedAtUtc));
        if (File.Exists(full))
        {
            var existing = FeedPathGuard.ReadBoundedRegularFile(
                full,
                128 * 1024,
                "existing promotion result receipt");
            if (!existing.AsSpan().SequenceEqual(bytes))
            {
                throw new InvalidDataException(
                    "Existing promotion result receipt conflicts with this promotion.");
            }
            return;
        }
        FeedPathGuard.WriteNewDurableAtomicallyCreateOnly(full, bytes);
    }

    private const string Usage =
        "Usage: initialize --feed-root <absolute-directory> --trust-policy <absolute-json> | "
        + "promote --candidate <absolute-directory> --feed-root <absolute-directory> "
        + "--trust-policy <absolute-json> --channel <lab|pilot|stable> "
        + "[--certified-distribution-receipt <absolute-json> "
        + "--stable-authorization <absolute-json>] "
        + "--operation-id <lowercase-guid-n> "
        + "--expected-feed-identity-sha256 <sha256> "
        + "--expected-channel-head <missing|present:raw-size:sha256> "
        + "--expected-journal-head <missing|present:raw-size:sha256> "
        + "--result-receipt <new-absolute-json>";
}

internal sealed record EnterpriseFeedPromotionResultReceipt(
    int SchemaVersion,
    string Product,
    string Environment,
    string Channel,
    string ReleaseSetId,
    long Generation,
    long Sequence,
    long MinAcceptedSequence,
    string ManifestSha256,
    string ChannelManifestPath,
    string PromotionJournalEntryPath,
    string PromotionJournalSha256,
    [property: JsonConverter(typeof(EnterpriseWholeSecondUtcJsonConverter))]
    DateTimeOffset PublishedAtUtc);
