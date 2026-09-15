using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Ensou.Dsh.Enterprise.Installation;
using Ensou.Dsh.Enterprise.ReleasePublisher;

namespace Ensou.Dsh.EnterprisePluginCompatibilityRunner;

internal static class EnterprisePluginCompatibilityRunner
{
    public const string ProductionFileName =
        "Ensou.Dsh.EnterprisePluginCompatibilityRunner.exe";
    public const string ComponentName = "Ensou.Dsh.EnterprisePluginCompatibilityRunner";
    public const string HarnessSourceTag = "dsh-v0.1.2-rc.1";

    private const int MaximumMetadataBytes = 4 * 1024 * 1024;
    private static readonly TimeSpan MaximumRunDuration = TimeSpan.FromHours(4);
    private static readonly string[] ObservationNames =
    [
        "launcherBinarySelfCheck",
        "runtimeHealth",
        "pluginPolicyInstalled",
        "pluginCommandExecuted",
        "managedPolicyEnforced",
        "startupUpdateCheck",
        "rollbackRestoredPreviousRuntime",
        "conversationHistoryPreserved",
        "workspacePreserved",
    ];

    public static void Run(
        CompatibilityRunnerOptions options,
        PublisherRuntimeAdmissionTrust runtimeTrust,
        PublisherPluginAdmissionTrust pluginTrust,
        CompatibilityRunnerIdentity runnerIdentity,
        ICompatibilityProbeExecutor probeExecutor,
        TimeProvider timeProvider,
        string testRunId)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(runtimeTrust);
        ArgumentNullException.ThrowIfNull(pluginTrust);
        ArgumentNullException.ThrowIfNull(runnerIdentity);
        ArgumentNullException.ThrowIfNull(probeExecutor);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ValidateOptions(options, runnerIdentity, testRunId);
        runtimeTrust.Validate();
        pluginTrust.Validate();

        using var staging = PublisherInputStaging.Create();
        using var inputs = CompatibilityLockedInputs.Capture(options, staging);
        inputs.RequireExpectedHashes(options);

        var sourceMetadata = PublisherRuntimeAdmissionValidator.ValidateFiles(
            inputs.RuntimeArchive.Staged.StagedPath,
            options.RuntimeReleaseId,
            inputs.RuntimeMetadata.Staged.StagedPath,
            inputs.RuntimeAdmissionReceipt.Staged.StagedPath,
            runtimeTrust);
        if (!string.Equals(sourceMetadata.SourceTag, HarnessSourceTag, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Runtime source metadata does not identify the fixed compatibility Harness source tag.");
        }

        var inspection = EnterprisePluginPolicyArchiveValidator.Validate(
            inputs.PluginArchive.Staged.StagedPath,
            options.LauncherReleaseId,
            options.RuntimeReleaseId);
        _ = PublisherPluginPolicyMetadata.Validate(
            inputs.PluginMetadata.Staged.StagedPath,
            inputs.PluginArchive.Staged.StagedPath,
            inspection);
        PluginExecutionAdmissionReceipt.ParseAndVerify(
            inputs.PluginExecutionAdmissionReceipt.Staged.StagedPath,
            pluginTrust,
            inspection,
            inputs.PluginArchive.Staged,
            inputs.PluginMetadata.Staged,
            WholeSecond(timeProvider.GetUtcNow()),
            options.LauncherReleaseId,
            options.RuntimeReleaseId);
        if (inspection.LauncherReleaseIds.Count is <= 0 or > 64
            || inspection.RuntimeReleaseIds.Count is <= 0 or > 64
            || !inspection.LauncherReleaseIds.Contains(
                options.LauncherReleaseId,
                StringComparer.Ordinal)
            || !inspection.RuntimeReleaseIds.Contains(
                options.RuntimeReleaseId,
                StringComparer.Ordinal))
        {
            throw new InvalidDataException(
                "Production compatibility evidence requires the selected Launcher/runtime tuple in the exact policy compatibility sets.");
        }

        var executionStarted = WholeSecond(timeProvider.GetUtcNow());
        var context = new CompatibilityProbeContext(
            testRunId,
            runnerIdentity,
            options.LauncherReleaseId,
            inputs.LauncherArchive.Staged,
            options.RuntimeReleaseId,
            inputs.RuntimeArchive.Staged,
            inputs.RuntimeMetadata.Staged,
            inputs.RuntimeAdmissionReceipt.Staged,
            inputs.PluginArchive.Staged,
            inputs.PluginMetadata.Staged,
            inputs.PluginExecutionAdmissionReceipt.Staged,
            inspection);
        var evidenceBytes = probeExecutor.Execute(context);
        if (evidenceBytes.Length is <= 0 or > MaximumMetadataBytes)
        {
            throw new InvalidDataException("Compatibility probe evidence size is invalid.");
        }
        var evidence = PublisherRuntimeAdmissionJson.Parse<CompatibilityProbeEvidence>(
            evidenceBytes,
            "Plugin compatibility probe evidence");
        ValidateEvidence(
            evidence,
            context,
            executionStarted,
            WholeSecond(timeProvider.GetUtcNow()));
        inputs.VerifyUnchanged();

        var receiptBytes = SerializeReceipt(
            options,
            runnerIdentity,
            inputs,
            inspection,
            evidence);
        WriteNewVerified(options.OutputPath, receiptBytes);
        inputs.VerifyUnchanged();
    }

    private static void ValidateOptions(
        CompatibilityRunnerOptions options,
        CompatibilityRunnerIdentity runner,
        string testRunId)
    {
        RequireProductionReleaseId(options.LauncherReleaseId, "Launcher");
        RequireProductionReleaseId(options.RuntimeReleaseId, "runtime");
        RequireSha256(options.LauncherArchiveSha256, "Launcher archive");
        RequireSha256(options.RuntimeArchiveSha256, "runtime archive");
        RequireSha256(options.RuntimeSourceMetadataSha256, "runtime source metadata");
        RequireSha256(options.PluginPolicyArchiveSha256, "plugin-policy archive");
        RequireSha256(options.PluginPolicyMetadataSha256, "plugin-policy metadata");
        if (!Guid.TryParseExact(testRunId, "D", out var parsed)
            || parsed.Version is < 1 or > 5
            || !string.Equals(parsed.ToString("D"), testRunId, StringComparison.Ordinal))
        {
            throw new InvalidDataException("Compatibility testRunId is not a canonical RFC 4122 UUID.");
        }
        if (!string.Equals(runner.FileName, ProductionFileName, StringComparison.Ordinal)
            || runner.SizeBytes <= 0
            || runner.SizeBytes > 9_007_199_254_740_991L)
        {
            throw new InvalidDataException("Compatibility runner binary identity is invalid.");
        }
        RequireSha256(runner.Sha256, "compatibility runner");

        var inputPaths = new[]
        {
            options.LauncherArchivePath,
            options.RuntimeArchivePath,
            options.RuntimeSourceMetadataPath,
            options.RuntimeOrganizationAdmissionReceiptPath,
            options.PluginPolicyArchivePath,
            options.PluginPolicyMetadataPath,
            options.PluginPolicyExecutionAdmissionReceiptPath,
        };
        if (inputPaths.Any(path => !Path.IsPathFullyQualified(path))
            || inputPaths.Select(Path.GetFullPath)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Count() != inputPaths.Length)
        {
            throw new InvalidDataException(
                "Compatibility runner inputs must be distinct absolute files.");
        }
        var output = Path.GetFullPath(options.OutputPath);
        if (!Path.IsPathFullyQualified(options.OutputPath)
            || inputPaths.Any(path => string.Equals(
                Path.GetFullPath(path),
                output,
                StringComparison.OrdinalIgnoreCase))
            || !string.Equals(Path.GetExtension(output), ".json", StringComparison.OrdinalIgnoreCase)
            || File.Exists(output)
            || Directory.Exists(output))
        {
            throw new InvalidDataException(
                "Compatibility receipt output must be a distinct new absolute JSON file.");
        }
        var outputDirectory = Path.GetDirectoryName(output)
            ?? throw new InvalidDataException("Compatibility receipt output has no directory.");
        PublisherPathGuard.RequireSafeExistingDirectory(outputDirectory);
        PublisherPathGuard.RequireSafeDestination(output);
    }

    private static void ValidateEvidence(
        CompatibilityProbeEvidence evidence,
        CompatibilityProbeContext context,
        DateTimeOffset executionStarted,
        DateTimeOffset validationTime)
    {
        var started = ParseWholeSecondUtc(evidence.StartedAtUtc, "probe startedAtUtc");
        var completed = ParseWholeSecondUtc(evidence.CompletedAtUtc, "probe completedAtUtc");
        if (started < executionStarted.AddMinutes(-1)
            || started > completed
            || completed - started > MaximumRunDuration
            || completed > validationTime.AddMinutes(5))
        {
            throw new InvalidDataException("Compatibility probe timing is invalid.");
        }
        if (evidence.SchemaVersion != 1
            || !string.Equals(
                evidence.EvidenceType,
                "ensou-dsh-managed-plugin-compatibility-observations",
                StringComparison.Ordinal)
            || !string.Equals(evidence.Result, "PASS", StringComparison.Ordinal)
            || !string.Equals(
                evidence.RunnerSha256,
                context.RunnerIdentity.Sha256,
                StringComparison.Ordinal)
            || string.IsNullOrWhiteSpace(evidence.Nonce)
            || !string.Equals(evidence.TestRunId, context.TestRunId, StringComparison.Ordinal)
            || !string.Equals(
                evidence.LauncherReleaseId,
                context.LauncherReleaseId,
                StringComparison.Ordinal)
            || !string.Equals(
                evidence.LauncherArchiveSha256,
                context.LauncherArchive.Sha256,
                StringComparison.Ordinal)
            || !string.Equals(
                evidence.RuntimeReleaseId,
                context.RuntimeReleaseId,
                StringComparison.Ordinal)
            || !string.Equals(
                evidence.RuntimeArchiveSha256,
                context.RuntimeArchive.Sha256,
                StringComparison.Ordinal)
            || !string.Equals(
                evidence.RuntimeSourceMetadataSha256,
                context.RuntimeMetadata.Sha256,
                StringComparison.Ordinal)
            || !string.Equals(evidence.PolicyId, context.Policy.PolicyId, StringComparison.Ordinal)
            || evidence.PolicyGeneration != context.Policy.Generation
            || !string.Equals(
                evidence.PluginPolicyArchiveSha256,
                context.PluginArchive.Sha256,
                StringComparison.Ordinal)
            || !string.Equals(
                evidence.PluginPolicyMetadataSha256,
                context.PluginMetadata.Sha256,
                StringComparison.Ordinal)
            || !string.Equals(
                evidence.PluginPolicyExecutionAdmissionReceiptSha256,
                context.PluginExecutionAdmissionReceipt.Sha256,
                StringComparison.Ordinal)
            || !string.Equals(
                evidence.RawPolicySha256,
                context.Policy.PolicySha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Compatibility probe evidence does not bind the exact admitted input tuple.");
        }
        RequireObservations(evidence.Observations);
        RequirePluginObservations(evidence.Plugins, context.Policy.SkillPacks);
    }

    private static void RequireObservations(IReadOnlyDictionary<string, string>? observations)
    {
        if (observations is null || observations.Count != ObservationNames.Length)
        {
            throw new InvalidDataException(
                "Compatibility probe observations are incomplete or unexpected.");
        }
        foreach (var name in ObservationNames)
        {
            if (!observations.TryGetValue(name, out var result)
                || !string.Equals(result, "PASS", StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    $"Compatibility probe observation is not PASS: {name}.");
            }
        }
    }

    private static void RequirePluginObservations(
        IReadOnlyList<CompatibilityPluginObservation>? actual,
        IReadOnlyList<EnterprisePluginSkillPackInspection> expected)
    {
        if (actual is null
            || actual.Count != expected.Count
            || actual.Select(item => item.SkillId)
                .Distinct(StringComparer.Ordinal)
                .Count() != actual.Count)
        {
            throw new InvalidDataException(
                "Compatibility probe did not test every managed skill pack exactly once.");
        }
        var ordered = actual.OrderBy(item => item.SkillId, StringComparer.Ordinal).ToArray();
        for (var index = 0; index < expected.Count; index++)
        {
            var observed = ordered[index];
            var skill = expected[index];
            if (!string.Equals(observed.SkillId, skill.SkillId, StringComparison.Ordinal)
                || !string.Equals(observed.Version, skill.Version, StringComparison.Ordinal)
                || !string.Equals(observed.Root, skill.Root, StringComparison.Ordinal)
                || !string.Equals(
                    observed.DeclaredTreeSha256,
                    skill.DeclaredTreeSha256,
                    StringComparison.Ordinal)
                || !string.Equals(observed.CommandExecuted, "PASS", StringComparison.Ordinal)
                || !string.Equals(
                    observed.ManagedPolicyEnforced,
                    "PASS",
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    $"Compatibility probe skill observation is incomplete or drifted: {skill.SkillId}.");
            }
        }
    }

    private static byte[] SerializeReceipt(
        CompatibilityRunnerOptions options,
        CompatibilityRunnerIdentity runner,
        CompatibilityLockedInputs inputs,
        EnterprisePluginPolicyArchiveInspection policy,
        CompatibilityProbeEvidence evidence)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteNumber("schemaVersion", 1);
            writer.WriteString("receiptType", "managed-plugin-harness-compatibility");
            writer.WriteStartObject("producer");
            writer.WriteString("component", ComponentName);
            writer.WriteString("testRunId", evidence.TestRunId);
            writer.WriteString("fileName", runner.FileName);
            writer.WriteNumber("sizeBytes", runner.SizeBytes);
            writer.WriteString("sha256", runner.Sha256);
            writer.WriteEndObject();
            writer.WriteString("result", "PASS");
            writer.WriteString("startedAtUtc", evidence.StartedAtUtc);
            writer.WriteString("observedAtUtc", evidence.CompletedAtUtc);
            writer.WriteString("launcherReleaseId", options.LauncherReleaseId);
            writer.WriteStartObject("launcherArtifact");
            writer.WriteString("fileName", Path.GetFileName(options.LauncherArchivePath));
            writer.WriteNumber("sizeBytes", inputs.LauncherArchive.Staged.Length);
            writer.WriteString("sha256", inputs.LauncherArchive.Staged.Sha256);
            writer.WriteEndObject();
            writer.WriteString("runtimeReleaseId", options.RuntimeReleaseId);
            writer.WriteStartObject("runtimeArtifact");
            writer.WriteString("fileName", Path.GetFileName(options.RuntimeArchivePath));
            writer.WriteNumber("sizeBytes", inputs.RuntimeArchive.Staged.Length);
            writer.WriteString("sha256", inputs.RuntimeArchive.Staged.Sha256);
            writer.WriteString("sourceMetadataSha256", inputs.RuntimeMetadata.Staged.Sha256);
            writer.WriteEndObject();
            writer.WriteString("harnessSourceTag", HarnessSourceTag);
            writer.WriteStartObject("policy");
            writer.WriteString("policyId", policy.PolicyId);
            writer.WriteNumber("generation", policy.Generation);
            writer.WriteString("archiveSha256", policy.ArchiveSha256);
            writer.WriteString("metadataSha256", inputs.PluginMetadata.Staged.Sha256);
            writer.WriteString("rawPolicySha256", policy.PolicySha256);
            writer.WriteString(
                "executionAdmissionReceiptSha256",
                inputs.PluginExecutionAdmissionReceipt.Staged.Sha256);
            writer.WriteEndObject();
            writer.WriteStartArray("plugins");
            foreach (var plugin in evidence.Plugins.OrderBy(item => item.SkillId, StringComparer.Ordinal))
            {
                writer.WriteStartObject();
                writer.WriteString("skillId", plugin.SkillId);
                writer.WriteString("version", plugin.Version);
                writer.WriteString("root", plugin.Root);
                writer.WriteString("declaredTreeSha256", plugin.DeclaredTreeSha256);
                writer.WriteString("commandExecuted", plugin.CommandExecuted);
                writer.WriteString("managedPolicyEnforced", plugin.ManagedPolicyEnforced);
                writer.WriteEndObject();
            }
            writer.WriteEndArray();
            writer.WriteStartObject("observations");
            foreach (var name in ObservationNames)
            {
                writer.WriteString(name, evidence.Observations[name]);
            }
            writer.WriteEndObject();
            writer.WriteEndObject();
        }
        return stream.ToArray();
    }

    private static void WriteNewVerified(string path, byte[] bytes)
    {
        var fullPath = Path.GetFullPath(path);
        try
        {
            using (var output = new FileStream(
                fullPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                64 * 1024,
                FileOptions.WriteThrough))
            {
                output.Write(bytes);
                output.Flush(flushToDisk: true);
            }
            using var verification = PublisherSafeFile.OpenLockedRead(fullPath);
            if (verification.Length != bytes.LongLength
                || !string.Equals(
                    PublisherSafeFile.HashAndRewind(verification),
                    Convert.ToHexStringLower(SHA256.HashData(bytes)),
                    StringComparison.Ordinal))
            {
                throw new IOException("Compatibility receipt output verification failed.");
            }
        }
        catch
        {
            if (File.Exists(fullPath)
                && (File.GetAttributes(fullPath) & FileAttributes.ReparsePoint) == 0)
            {
                File.Delete(fullPath);
            }
            throw;
        }
    }

    private static DateTimeOffset WholeSecond(DateTimeOffset value) =>
        DateTimeOffset.FromUnixTimeSeconds(value.ToUnixTimeSeconds());

    private static DateTimeOffset ParseWholeSecondUtc(string? value, string field)
    {
        if (value is null
            || !DateTimeOffset.TryParseExact(
                value,
                "yyyy-MM-dd'T'HH:mm:ss'Z'",
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out var parsed)
            || !string.Equals(
                parsed.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture),
                value,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException($"Compatibility {field} is not canonical whole-second UTC.");
        }
        return parsed;
    }

    private static void RequireSha256(string value, string field)
    {
        if (!PublisherPluginPolicyMetadata.IsLowercaseSha256(value))
        {
            throw new InvalidDataException($"{field} expected SHA-256 is invalid.");
        }
    }

    private static void RequireProductionReleaseId(string value, string field)
    {
        PublisherRuntimeAdmissionEncoding.ValidateToken(value, $"{field} releaseId", 128);
        var lower = value.ToLowerInvariant();
        string[] rejected =
        [
            "placeholder", "example", "fixture", "dummy", "fake", "mock", "sample",
            "unknown", "todo", "test", "localhost", "development", "e2e", "staging",
            "preview", "local",
        ];
        if (rejected.Any(lower.Contains))
        {
            throw new InvalidDataException($"{field} releaseId is not production immutable.");
        }
    }
}

internal sealed class CompatibilityLockedInputs : IDisposable
{
    private readonly CompatibilityLockedInput[] _all;

    private CompatibilityLockedInputs(
        CompatibilityLockedInput launcherArchive,
        CompatibilityLockedInput runtimeArchive,
        CompatibilityLockedInput runtimeMetadata,
        CompatibilityLockedInput runtimeAdmissionReceipt,
        CompatibilityLockedInput pluginArchive,
        CompatibilityLockedInput pluginMetadata,
        CompatibilityLockedInput pluginExecutionAdmissionReceipt)
    {
        LauncherArchive = launcherArchive;
        RuntimeArchive = runtimeArchive;
        RuntimeMetadata = runtimeMetadata;
        RuntimeAdmissionReceipt = runtimeAdmissionReceipt;
        PluginArchive = pluginArchive;
        PluginMetadata = pluginMetadata;
        PluginExecutionAdmissionReceipt = pluginExecutionAdmissionReceipt;
        _all =
        [
            launcherArchive, runtimeArchive, runtimeMetadata, runtimeAdmissionReceipt,
            pluginArchive, pluginMetadata, pluginExecutionAdmissionReceipt,
        ];
    }

    public CompatibilityLockedInput LauncherArchive { get; }
    public CompatibilityLockedInput RuntimeArchive { get; }
    public CompatibilityLockedInput RuntimeMetadata { get; }
    public CompatibilityLockedInput RuntimeAdmissionReceipt { get; }
    public CompatibilityLockedInput PluginArchive { get; }
    public CompatibilityLockedInput PluginMetadata { get; }
    public CompatibilityLockedInput PluginExecutionAdmissionReceipt { get; }

    public static CompatibilityLockedInputs Capture(
        CompatibilityRunnerOptions options,
        PublisherInputStaging staging)
    {
        var captured = new List<CompatibilityLockedInput>();
        try
        {
            CompatibilityLockedInput Capture(string path)
            {
                var item = CompatibilityLockedInput.Capture(path, staging);
                captured.Add(item);
                return item;
            }
            var result = new CompatibilityLockedInputs(
                Capture(options.LauncherArchivePath),
                Capture(options.RuntimeArchivePath),
                Capture(options.RuntimeSourceMetadataPath),
                Capture(options.RuntimeOrganizationAdmissionReceiptPath),
                Capture(options.PluginPolicyArchivePath),
                Capture(options.PluginPolicyMetadataPath),
                Capture(options.PluginPolicyExecutionAdmissionReceiptPath));
            if (result._all.Select(item => item.Identity).Distinct().Count() != result._all.Length)
            {
                throw new InvalidDataException(
                    "Compatibility runner inputs must be distinct filesystem objects.");
            }
            return result;
        }
        catch
        {
            foreach (var item in captured.AsEnumerable().Reverse())
            {
                item.Dispose();
            }
            throw;
        }
    }

    public void RequireExpectedHashes(CompatibilityRunnerOptions options)
    {
        Require(LauncherArchive, options.LauncherArchiveSha256, "Launcher archive");
        Require(RuntimeArchive, options.RuntimeArchiveSha256, "runtime archive");
        Require(RuntimeMetadata, options.RuntimeSourceMetadataSha256, "runtime source metadata");
        Require(PluginArchive, options.PluginPolicyArchiveSha256, "plugin-policy archive");
        Require(PluginMetadata, options.PluginPolicyMetadataSha256, "plugin-policy metadata");

        static void Require(CompatibilityLockedInput input, string expected, string field)
        {
            if (!string.Equals(input.Staged.Sha256, expected, StringComparison.Ordinal))
            {
                throw new InvalidDataException($"{field} SHA-256 drifted from the reviewed input.");
            }
        }
    }

    public void VerifyUnchanged()
    {
        foreach (var input in _all)
        {
            input.VerifyUnchanged();
        }
    }

    public void Dispose()
    {
        foreach (var input in _all.Reverse())
        {
            input.Dispose();
        }
    }
}

internal sealed class CompatibilityLockedInput : IDisposable
{
    private readonly FileStream _source;

    private CompatibilityLockedInput(
        string sourcePath,
        PublisherFileIdentity identity,
        FileStream source,
        PublisherStagedInputFile staged)
    {
        SourcePath = sourcePath;
        Identity = identity;
        _source = source;
        Staged = staged;
    }

    public string SourcePath { get; }
    public PublisherFileIdentity Identity { get; }
    public PublisherStagedInputFile Staged { get; }

    public static CompatibilityLockedInput Capture(string path, PublisherInputStaging staging)
    {
        var fullPath = Path.GetFullPath(path);
        var source = PublisherSafeFile.OpenLockedRead(fullPath);
        try
        {
            var identity = PublisherSafeFile.GetIdentity(source);
            var staged = staging.CaptureFromLockedHandle(source, fullPath);
            if (source.Length != staged.Length
                || !string.Equals(
                    PublisherSafeFile.HashAndRewind(source),
                    staged.Sha256,
                    StringComparison.Ordinal))
            {
                throw new IOException(
                    "Compatibility input changed while its locked snapshot was captured.");
            }
            return new CompatibilityLockedInput(fullPath, identity, source, staged);
        }
        catch
        {
            source.Dispose();
            throw;
        }
    }

    public void VerifyUnchanged()
    {
        PublisherSafeFile.RequireExpectedPathAndRegularFile(_source, SourcePath);
        if (PublisherSafeFile.GetIdentity(_source) != Identity
            || _source.Length != Staged.Length
            || !string.Equals(
                PublisherSafeFile.HashAndRewind(_source),
                Staged.Sha256,
                StringComparison.Ordinal))
        {
            throw new IOException(
                "Compatibility input path, identity, length, or SHA-256 changed during the run.");
        }
    }

    public void Dispose() => _source.Dispose();
}

internal sealed record CompatibilityProbeContext(
    string TestRunId,
    CompatibilityRunnerIdentity RunnerIdentity,
    string LauncherReleaseId,
    PublisherStagedInputFile LauncherArchive,
    string RuntimeReleaseId,
    PublisherStagedInputFile RuntimeArchive,
    PublisherStagedInputFile RuntimeMetadata,
    PublisherStagedInputFile RuntimeAdmissionReceipt,
    PublisherStagedInputFile PluginArchive,
    PublisherStagedInputFile PluginMetadata,
    PublisherStagedInputFile PluginExecutionAdmissionReceipt,
    EnterprisePluginPolicyArchiveInspection Policy);

internal interface ICompatibilityProbeExecutor
{
    byte[] Execute(CompatibilityProbeContext context);
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record CompatibilityProbeEvidence
{
    public required int SchemaVersion { get; init; }
    public required string EvidenceType { get; init; }
    public required string Result { get; init; }
    public required string Nonce { get; init; }
    public required string RunnerSha256 { get; init; }
    public required string TestRunId { get; init; }
    public required string StartedAtUtc { get; init; }
    public required string CompletedAtUtc { get; init; }
    public required string LauncherReleaseId { get; init; }
    public required string LauncherArchiveSha256 { get; init; }
    public required string RuntimeReleaseId { get; init; }
    public required string RuntimeArchiveSha256 { get; init; }
    public required string RuntimeSourceMetadataSha256 { get; init; }
    public required string PolicyId { get; init; }
    public required long PolicyGeneration { get; init; }
    public required string PluginPolicyArchiveSha256 { get; init; }
    public required string PluginPolicyMetadataSha256 { get; init; }
    public required string PluginPolicyExecutionAdmissionReceiptSha256 { get; init; }
    public required string RawPolicySha256 { get; init; }
    public required IReadOnlyList<CompatibilityPluginObservation> Plugins { get; init; }
    public required IReadOnlyDictionary<string, string> Observations { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record CompatibilityPluginObservation
{
    public required string SkillId { get; init; }
    public required string Version { get; init; }
    public required string Root { get; init; }
    public required string DeclaredTreeSha256 { get; init; }
    public required string CommandExecuted { get; init; }
    public required string ManagedPolicyEnforced { get; init; }
}
