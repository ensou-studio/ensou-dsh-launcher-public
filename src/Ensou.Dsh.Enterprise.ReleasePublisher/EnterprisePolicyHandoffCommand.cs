using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Ensou.Dsh.Enterprise.Installation;

namespace Ensou.Dsh.Enterprise.ReleasePublisher;

internal static class EnterprisePolicyHandoffCommand
{
    private const int MaximumJournalBytes = 512 * 1024;
    private const int MaximumManifestBytes = 512 * 1024;
    private const int MaximumPromotionResultBytes = 128 * 1024;
    private const int MaximumPrivateKeyBytes = 1024 * 1024;
    private static readonly TimeSpan ManifestValidationClockSkew = TimeSpan.FromMinutes(2);
    private static readonly JsonSerializerOptions JsonOptions = CreateJsonOptions();

    public static bool IsRequested(IReadOnlyList<string> args) =>
        args.Count >= 2
        && string.Equals(args[0], "release-policy", StringComparison.Ordinal)
        && string.Equals(args[1], "sign-handoff", StringComparison.Ordinal);

    private static JsonSerializerOptions CreateJsonOptions()
    {
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web)
        {
            PropertyNameCaseInsensitive = false,
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
            WriteIndented = true,
        };
        options.Converters.Add(new EnterpriseWholeSecondUtcJsonConverter());
        return options;
    }

    public static int Run(string[] args)
    {
        try
        {
            var options = Parse(args);
            Sign(options, TimeProvider.System.GetUtcNow());
            Console.WriteLine("ENTERPRISE-RELEASE-POLICY-HANDOFF-PASS");
            return 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine(
                $"Enterprise release-policy handoff signing failed: {exception.Message}");
            return 1;
        }
    }

    internal static EnterpriseReleasePolicyHandoff Sign(
        EnterprisePolicyHandoffSigningOptions options,
        DateTimeOffset nowUtc) => Sign(options, nowUtc, null);

    internal static EnterpriseReleasePolicyHandoff Sign(
        EnterprisePolicyHandoffSigningOptions options,
        DateTimeOffset nowUtc,
        Action? inputsLocked)
    {
        ArgumentNullException.ThrowIfNull(options);
        PublisherPathGuard.RequireSafeExistingFile(options.PromotionJournalEntryPath);
        PublisherPathGuard.RequireSafeExistingFile(options.ChannelManifestPath);
        PublisherPathGuard.RequireSafeExistingFile(options.PromotionResultReceiptPath);
        PublisherPathGuard.RequireSafeExistingFile(options.PrivateKeyPath);
        PublisherPathGuard.RequireSafeDestination(options.OutputPath);
        RequireNewOutput(options.OutputPath);
        EnterpriseReleaseSetValidator.ValidateToken(options.KeyId, "keyId", 64);
        if (options.Environment is not EnterpriseReleaseSetContract.ProductionEnvironment
            and not EnterpriseReleaseSetContract.DevelopmentE2EEnvironment
            || options.ValidHours is < 1 or > 744
            || options.GraceHours < 0
            || options.GraceHours > options.ValidHours)
        {
            throw new InvalidDataException("Release-policy handoff signing options are invalid.");
        }

        using var journalInput = PublisherSafeFile.OpenLockedRead(
            options.PromotionJournalEntryPath);
        using var manifestInput = PublisherSafeFile.OpenLockedRead(options.ChannelManifestPath);
        using var promotionResultInput = PublisherSafeFile.OpenLockedRead(
            options.PromotionResultReceiptPath);
        using var privateKeyInput = PublisherSafeFile.OpenLockedRead(options.PrivateKeyPath);
        inputsLocked?.Invoke();

        var journalBytes = ReadLockedInput(journalInput, MaximumJournalBytes);
        EnterpriseReleaseJson.RequireNoDuplicateMembers(journalBytes);
        var journal = JsonSerializer.Deserialize<PromotionJournalSource>(journalBytes, JsonOptions)
            ?? throw new InvalidDataException("Promotion journal entry is empty.");
        journal.Validate();
        var journalSha256 = Convert.ToHexStringLower(SHA256.HashData(journalBytes));
        var manifestBytes = ReadLockedInput(manifestInput, MaximumManifestBytes);
        var manifestSha256 = Convert.ToHexStringLower(SHA256.HashData(manifestBytes));
        var manifest = EnterpriseReleaseSetManifest.Parse(manifestBytes);
        journal.RequireExactManifest(
            manifest,
            manifestSha256,
            options.Environment,
            options.KeyId);
        var promotionResultBytes = ReadLockedInput(
            promotionResultInput,
            MaximumPromotionResultBytes);
        EnterpriseReleaseJson.RequireNoDuplicateMembers(promotionResultBytes);
        var promotionResult = JsonSerializer.Deserialize<PromotionResultSource>(
            promotionResultBytes,
            JsonOptions) ?? throw new InvalidDataException(
                "FeedPromoter promotion result receipt is empty.");
        var promotionResultSha256 = Convert.ToHexStringLower(
            SHA256.HashData(promotionResultBytes));
        promotionResult.RequireExactPromotion(
            manifest,
            journal,
            manifestSha256,
            journalSha256,
            options.Environment,
            options.ChannelManifestPath,
            options.PromotionJournalEntryPath);
        var issuedAt = WholeSecond(nowUtc);
        if (journal.PublishedAtUtc > issuedAt
            || promotionResult.PublishedAtUtc > issuedAt)
        {
            throw new InvalidDataException(
                "Promotion journal publication time may not follow handoff issuance.");
        }

        var privateKeyBytes = ReadLockedInput(privateKeyInput, MaximumPrivateKeyBytes);
        using var signer = ECDsa.Create();
        try
        {
            signer.ImportPkcs8PrivateKey(privateKeyBytes, out var consumed);
            if (consumed != privateKeyBytes.Length)
            {
                throw new InvalidDataException("Release PKCS8 key contains trailing bytes.");
            }
            var publicParameters = signer.ExportParameters(includePrivateParameters: false);
            if (publicParameters.Q.X?.Length != 32 || publicParameters.Q.Y?.Length != 32)
            {
                throw new InvalidDataException("Release-policy signer must use P-256.");
            }
            var publicKey = new EnterpriseReleasePublicKey(
                options.KeyId,
                EnterpriseBase64Url.Encode(publicParameters.Q.X),
                EnterpriseBase64Url.Encode(publicParameters.Q.Y));
            var artifactOrigin = new Uri(
                manifest.Artifacts[0].Uri.GetLeftPart(UriPartial.Authority) + "/");
            EnterpriseReleaseSetValidator.Verify(
                manifest,
                new EnterpriseReleaseTrustPolicy
                {
                    Product = EnterpriseReleaseSetContract.Product,
                    Environment = options.Environment,
                    ExpectedChannel = manifest.Channel,
                    CurrentStartupStubProtocol =
                        EnterpriseReleaseSetContract.CurrentStartupStubProtocol,
                    ManifestOrigin = artifactOrigin,
                    ArtifactOrigin = artifactOrigin,
                    TrustedKeys = [publicKey],
                    AllowedClockSkew = ManifestValidationClockSkew,
                },
                issuedAt);

            var expiresAt = issuedAt.AddHours(options.ValidHours);
            var graceUntil = issuedAt.AddHours(options.GraceHours);
            if (expiresAt > manifest.ExpiresAtUtc)
            {
                throw new InvalidDataException(
                    "Requested handoff validity exceeds the bound manifest validity window.");
            }
            var unsignedSignature = new EnterpriseReleaseSignature
            {
                Algorithm = EnterpriseReleaseSetContract.SignatureAlgorithm,
                KeyId = options.KeyId,
                Value = EnterpriseBase64Url.Encode(new byte[64]),
            };
            var handoff = new EnterpriseReleasePolicyHandoff
            {
                SchemaVersion = EnterpriseReleasePolicyHandoffContract.SchemaVersion,
                Product = EnterpriseReleaseSetContract.Product,
                Environment = options.Environment,
                Channel = journal.Channel,
                ReleaseSetId = journal.ReleaseSetId,
                Generation = journal.Generation,
                Sequence = journal.Sequence,
                MinAcceptedSequence = journal.MinAcceptedSequence,
                ManifestSha256 = journal.ManifestSha256,
                PromotionResultSha256 = promotionResultSha256,
                PromotionJournalSha256 = journalSha256,
                IssuedAtUtc = issuedAt,
                ExpiresAtUtc = expiresAt,
                GraceUntilUtc = graceUntil,
                Signature = unsignedSignature,
            };
            handoff = handoff with
            {
                Signature = new EnterpriseReleaseSignature
                {
                    Algorithm = EnterpriseReleaseSetContract.SignatureAlgorithm,
                    KeyId = options.KeyId,
                    Value = EnterpriseBase64Url.Encode(signer.SignData(
                        EnterpriseReleasePolicyHandoff.CanonicalPayload(handoff),
                        HashAlgorithmName.SHA256,
                        DSASignatureFormat.IeeeP1363FixedFieldConcatenation)),
                },
            };
            handoff.Verify(options.Environment, [publicKey], issuedAt, TimeSpan.Zero);

            var outputBytes = JsonSerializer.SerializeToUtf8Bytes(handoff, JsonOptions);
            PublisherPathGuard.RequireSafeDestination(options.OutputPath);
            using var output = new FileStream(
                options.OutputPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                4096,
                FileOptions.WriteThrough);
            PublisherSafeFile.RequireExpectedPathAndRegularFile(output, options.OutputPath);
            PublisherPathGuard.RequireSafeDestination(options.OutputPath);
            output.Write(outputBytes);
            output.WriteByte((byte)'\n');
            output.Flush(flushToDisk: true);
            return handoff;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateKeyBytes);
        }
    }

    private static byte[] ReadLockedInput(FileStream stream, int maximumBytes)
    {
        ArgumentNullException.ThrowIfNull(stream);
        var identity = PublisherSafeFile.GetIdentity(stream);
        var length = stream.Length;
        if (length is <= 0 || length > maximumBytes || length > int.MaxValue)
        {
            throw new InvalidDataException("Release-policy handoff input size is invalid.");
        }

        var bytes = new byte[checked((int)length)];
        try
        {
            stream.Position = 0;
            stream.ReadExactly(bytes);
            if (stream.Position != length
                || stream.Length != length
                || PublisherSafeFile.GetIdentity(stream) != identity)
            {
                throw new IOException(
                    "Release-policy handoff input identity or length changed while locked.");
            }
            stream.Position = 0;
            return bytes;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(bytes);
            throw;
        }
    }

    private static EnterprisePolicyHandoffSigningOptions Parse(IReadOnlyList<string> args)
    {
        if (!IsRequested(args) || (args.Count - 2) % 2 != 0)
        {
            throw new ArgumentException(Usage);
        }
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var index = 2; index < args.Count; index += 2)
        {
            if (!values.TryAdd(args[index], args[index + 1]))
            {
                throw new ArgumentException("Release-policy handoff argument was repeated.");
            }
        }
        var allowed = new HashSet<string>(
            ["--promotion-journal-entry", "--channel-manifest", "--promotion-result-receipt", "--environment", "--private-key-file", "--key-id",
             "--output", "--valid-hours", "--grace-hours"],
            StringComparer.Ordinal);
        if (values.Keys.Any(value => !allowed.Contains(value)))
        {
            throw new ArgumentException("Release-policy handoff received an unknown argument.");
        }
        return new EnterprisePolicyHandoffSigningOptions(
            Require(values, "--promotion-journal-entry"),
            Require(values, "--channel-manifest"),
            Require(values, "--promotion-result-receipt"),
            Require(values, "--environment"),
            Require(values, "--private-key-file"),
            Require(values, "--key-id"),
            Require(values, "--output"),
            ParseHours(values.GetValueOrDefault("--valid-hours") ?? "168", "valid-hours"),
            ParseHours(values.GetValueOrDefault("--grace-hours") ?? "24", "grace-hours", true));
    }

    private static int ParseHours(string value, string label, bool allowZero = false) =>
        int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed)
        && parsed >= (allowZero ? 0 : 1)
        && parsed <= 744
        && value == parsed.ToString(CultureInfo.InvariantCulture)
            ? parsed
            : throw new ArgumentException($"--{label} is invalid.");

    private static string Require(IReadOnlyDictionary<string, string> values, string name) =>
        values.TryGetValue(name, out var value) && !string.IsNullOrWhiteSpace(value)
            ? value
            : throw new ArgumentException($"{name} is required.");

    private static void RequireNewOutput(string path)
    {
        if (!Path.IsPathFullyQualified(path) || File.Exists(path))
        {
            throw new IOException("Release-policy handoff output must be a new absolute file.");
        }
        var parent = Path.GetDirectoryName(path);
        if (parent is null || !Directory.Exists(parent))
        {
            throw new DirectoryNotFoundException(
                "Release-policy handoff output parent must already exist.");
        }
    }

    private static DateTimeOffset WholeSecond(DateTimeOffset value) =>
        new(value.UtcTicks - value.UtcTicks % TimeSpan.TicksPerSecond, TimeSpan.Zero);

    private const string Usage =
        "Usage: release-policy sign-handoff --promotion-journal-entry <absolute-json> "
        + "--channel-manifest <absolute-release-set.v2.json> "
        + "--promotion-result-receipt <absolute-json> "
        + "--environment <production|development-e2e> --private-key-file <absolute-pkcs8> "
        + "--key-id <release-key-id> --output <new-absolute-json> "
        + "[--valid-hours <1..744>] [--grace-hours <0..valid-hours>]";
}

internal sealed record EnterprisePolicyHandoffSigningOptions(
    string PromotionJournalEntryPath,
    string ChannelManifestPath,
    string PromotionResultReceiptPath,
    string Environment,
    string PrivateKeyPath,
    string KeyId,
    string OutputPath,
    int ValidHours,
    int GraceHours);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PromotionResultSource(
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
    DateTimeOffset PublishedAtUtc)
{
    public void RequireExactPromotion(
        EnterpriseReleaseSetManifest manifest,
        PromotionJournalSource journal,
        string manifestSha256,
        string promotionJournalSha256,
        string expectedEnvironment,
        string exactLocalChannelManifestPath,
        string exactLocalPromotionJournalEntryPath)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentNullException.ThrowIfNull(journal);
        if (SchemaVersion != 1
            || !string.Equals(Product, EnterpriseReleaseSetContract.Product, StringComparison.Ordinal)
            || !string.Equals(Environment, expectedEnvironment, StringComparison.Ordinal)
            || !string.Equals(Channel, manifest.Channel, StringComparison.Ordinal)
            || !string.Equals(Channel, journal.Channel, StringComparison.Ordinal)
            || !string.Equals(ReleaseSetId, manifest.ReleaseSetId, StringComparison.Ordinal)
            || !string.Equals(ReleaseSetId, journal.ReleaseSetId, StringComparison.Ordinal)
            || Generation != manifest.Generation
            || Generation != journal.Generation
            || Sequence != manifest.Sequence
            || Sequence != journal.Sequence
            || MinAcceptedSequence != manifest.MinAcceptedSequence
            || MinAcceptedSequence != journal.MinAcceptedSequence
            || !string.Equals(ManifestSha256, manifestSha256, StringComparison.Ordinal)
            || !string.Equals(PromotionJournalSha256, promotionJournalSha256, StringComparison.Ordinal)
            || PublishedAtUtc != journal.PublishedAtUtc)
        {
            throw new InvalidDataException(
                "FeedPromoter promotion result does not match the exact manifest and journal evidence.");
        }
        EnterpriseReleaseValueValidator.ValidateReleaseId(ReleaseSetId);
        RequireReceiptPaths(
            expectedEnvironment,
            Channel,
            Sequence,
            ReleaseSetId,
            ManifestSha256,
            ChannelManifestPath,
            PromotionJournalEntryPath,
            exactLocalChannelManifestPath,
            exactLocalPromotionJournalEntryPath);
    }

    internal static void RequireReceiptPaths(
        string environment,
        string channel,
        long sequence,
        string releaseSetId,
        string manifestSha256,
        string receiptChannelManifestPath,
        string receiptPromotionJournalEntryPath,
        string exactLocalChannelManifestPath,
        string exactLocalPromotionJournalEntryPath)
    {
        if (string.Equals(
            environment,
            EnterpriseReleaseSetContract.ProductionEnvironment,
            StringComparison.Ordinal))
        {
            var expectedManifestPath =
                $"/srv/ensou-dsh-enterprise-feed/public/channels/{channel}/release-set.v2.json";
            var expectedJournalFileName = string.Create(
                CultureInfo.InvariantCulture,
                $"{sequence:D20}-{releaseSetId}-{manifestSha256}.json");
            var expectedJournalPath =
                $"/srv/ensou-dsh-enterprise-feed/journal/{channel}/{expectedJournalFileName}";
            if (!string.Equals(
                    receiptChannelManifestPath,
                    expectedManifestPath,
                    StringComparison.Ordinal)
                || !string.Equals(
                    receiptPromotionJournalEntryPath,
                    expectedJournalPath,
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "FeedPromoter receipt paths are not canonical production server paths.");
            }
            return;
        }

        if (!string.Equals(
                environment,
                EnterpriseReleaseSetContract.DevelopmentE2EEnvironment,
                StringComparison.Ordinal)
            || !PathsEqual(receiptChannelManifestPath, exactLocalChannelManifestPath)
            || !PathsEqual(
                receiptPromotionJournalEntryPath,
                exactLocalPromotionJournalEntryPath))
        {
            throw new InvalidDataException(
                "Development FeedPromoter receipt paths do not match the exact locked local inputs.");
        }
    }

    private static bool PathsEqual(string receiptPath, string exactLocalPath) =>
        !string.IsNullOrWhiteSpace(receiptPath)
        && Path.IsPathFullyQualified(receiptPath)
        && Path.IsPathFullyQualified(exactLocalPath)
        && string.Equals(
            Path.GetFullPath(receiptPath),
            Path.GetFullPath(exactLocalPath),
            OperatingSystem.IsWindows()
                ? StringComparison.OrdinalIgnoreCase
                : StringComparison.Ordinal);
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PromotionJournalSource(
    int SchemaVersion,
    string Channel,
    string ReleaseSetId,
    long Generation,
    long Sequence,
    long MinAcceptedSequence,
    string ManifestSha256,
    string PreviousEntrySha256,
    IReadOnlyList<PromotionJournalArtifact> Artifacts,
    [property: JsonConverter(typeof(EnterpriseWholeSecondUtcJsonConverter))]
    DateTimeOffset PublishedAtUtc)
{
    public void Validate()
    {
        if (SchemaVersion != 1
            || !EnterpriseReleasePolicyHandoffContract.Channels.Contains(Channel)
            || Generation is <= 0 or > EnterpriseReleasePolicyHandoffContract.MaximumSafeInteger
            || Sequence is <= 0 or > EnterpriseReleasePolicyHandoffContract.MaximumSafeInteger
            || MinAcceptedSequence is < 0 or > EnterpriseReleasePolicyHandoffContract.MaximumSafeInteger
            || MinAcceptedSequence > Sequence
            || !EnterpriseReleaseValueValidator.IsSha256(ManifestSha256)
            || !EnterpriseReleaseValueValidator.IsSha256(PreviousEntrySha256)
            || PublishedAtUtc.Offset != TimeSpan.Zero
            || PublishedAtUtc.Ticks % TimeSpan.TicksPerSecond != 0
            || Artifacts is null
            || Artifacts.Count != 3
            || Artifacts.Select(value => value.Component).Distinct(StringComparer.Ordinal).Count() != 3)
        {
            throw new InvalidDataException("Promotion journal entry is not canonical.");
        }
        EnterpriseReleaseValueValidator.ValidateReleaseId(ReleaseSetId);
        var required = new HashSet<string>(["launcher", "runtime", "plugin-policy"], StringComparer.Ordinal);
        foreach (var artifact in Artifacts)
        {
            artifact.Validate();
            required.Remove(artifact.Component);
        }
        if (required.Count != 0)
        {
            throw new InvalidDataException("Promotion journal entry is missing an artifact component.");
        }
    }

    public void RequireExactManifest(
        EnterpriseReleaseSetManifest manifest,
        string manifestSha256,
        string expectedEnvironment,
        string expectedKeyId)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        var receipts = manifest.Artifacts.Select(value => new PromotionJournalArtifact(
            value.Component,
            value.ReleaseId,
            Path.GetFileName(value.Uri.AbsolutePath),
            value.SizeBytes,
            value.Sha256)).ToArray();
        if (manifest.SchemaVersion != EnterpriseReleaseSetContract.SchemaVersion
            || !string.Equals(
                manifest.Product,
                EnterpriseReleaseSetContract.Product,
                StringComparison.Ordinal)
            || !string.Equals(manifest.Environment, expectedEnvironment, StringComparison.Ordinal)
            || !string.Equals(manifest.Channel, Channel, StringComparison.Ordinal)
            || !string.Equals(manifest.ReleaseSetId, ReleaseSetId, StringComparison.Ordinal)
            || manifest.Generation != Generation
            || manifest.Sequence != Sequence
            || manifest.MinAcceptedSequence != MinAcceptedSequence
            || !string.Equals(ManifestSha256, manifestSha256, StringComparison.Ordinal)
            || !string.Equals(manifest.Signature.KeyId, expectedKeyId, StringComparison.Ordinal)
            || manifest.Artifacts.Any(value => !string.Equals(
                value.Signature.KeyId,
                expectedKeyId,
                StringComparison.Ordinal))
            || !receipts.SequenceEqual(Artifacts))
        {
            throw new InvalidDataException(
                "Promoted channel manifest does not match the immutable promotion journal entry.");
        }
    }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PromotionJournalArtifact(
    string Component,
    string ReleaseId,
    string FileName,
    long SizeBytes,
    string Sha256)
{
    public void Validate()
    {
        if (Component is not "launcher" and not "runtime" and not "plugin-policy"
            || FileName != Path.GetFileName(FileName)
            || string.IsNullOrWhiteSpace(FileName)
            || FileName.Any(char.IsControl)
            || SizeBytes <= 0
            || !EnterpriseReleaseValueValidator.IsSha256(Sha256))
        {
            throw new InvalidDataException("Promotion journal artifact is not canonical.");
        }
        EnterpriseReleaseValueValidator.ValidateReleaseId(ReleaseId);
    }
}
