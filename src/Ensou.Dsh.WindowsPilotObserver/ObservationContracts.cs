using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace Ensou.Dsh.WindowsPilotObserver;

public static partial class ObservationContract
{
    public const string PlanType = "ensou-dsh-windows-pilot-observation-plan";
    public const string SummaryType = "ensou-dsh-windows-pilot-observation-summary";
    public const int SchemaVersion = 1;
    public const int MinimumDurationSeconds = 900;
    public const int LightweightIntervalMilliseconds = 250;
    public const int FullSnapshotMaximumIntervalMilliseconds = 1000;

    public static readonly string[] CandidateRoles =
    [
        "manifest",
        "installer",
        "launcher",
        "bootstrapper",
        "maintenance",
        "node",
        "runtime-entrypoint",
    ];

    public static readonly string[] RequiredActions =
    [
        "launcher-first-start",
        "tray-hide-show",
        "dsh-start",
        "webui-open",
        "subprocess-path",
        "workspace-terminal-path",
        "controlled-failure-recovery",
        "update-rollback-recovery",
        "launcher-restart",
    ];

    public static JsonSerializerOptions JsonOptions { get; } = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = false,
        ReadCommentHandling = JsonCommentHandling.Disallow,
        AllowTrailingCommas = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        WriteIndented = false,
    };

    public static ObservationPlan ParsePlan(ReadOnlySpan<byte> utf8)
    {
        StrictJson.ValidateNoDuplicateProperties(utf8);
        var plan = JsonSerializer.Deserialize<ObservationPlan>(utf8, JsonOptions)
            ?? throw new InvalidDataException("Observation plan is empty.");
        plan.Validate();
        return plan;
    }

    public static string Sha256Hex(ReadOnlySpan<byte> value) =>
        Convert.ToHexStringLower(SHA256.HashData(value));

    public static string Sha256File(string path)
    {
        using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            1024 * 128,
            FileOptions.SequentialScan);
        return Convert.ToHexStringLower(SHA256.HashData(stream));
    }

    internal static void RequireLowerSha256(string value, string name)
    {
        if (string.IsNullOrWhiteSpace(value) || !LowerSha256().IsMatch(value))
        {
            throw new InvalidDataException($"{name} must be one lowercase SHA-256 value.");
        }
    }

    internal static void RequireAbsolutePath(string value, string name)
    {
        if (string.IsNullOrWhiteSpace(value)
            || !Path.IsPathFullyQualified(value)
            || value.IndexOf('\0') >= 0
            || value.StartsWith(@"\\?\", StringComparison.Ordinal)
            || value.StartsWith(@"\\.\", StringComparison.Ordinal)
            || (value.Length > 2 && value[2..].IndexOf(':') >= 0)
            || !string.Equals(Path.GetFullPath(value), value, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException($"{name} must be one canonical absolute Windows path.");
        }
    }

    internal static void RequireToken(string value, string name)
    {
        if (string.IsNullOrWhiteSpace(value) || !SafeToken().IsMatch(value))
        {
            throw new InvalidDataException($"{name} contains unsupported characters.");
        }
    }

    [GeneratedRegex("^[0-9a-f]{64}$", RegexOptions.CultureInvariant)]
    private static partial Regex LowerSha256();

    [GeneratedRegex("^[A-Za-z0-9._:+/-]{1,160}$", RegexOptions.CultureInvariant)]
    private static partial Regex SafeToken();
}

public sealed class ObservationPlan
{
    public required int SchemaVersion { get; init; }
    public required string PlanType { get; init; }
    public required string Edition { get; init; }
    public required string TestRunId { get; init; }
    public required int MinimumObservationSeconds { get; init; }
    public required string ExpectedObserverSha256 { get; init; }
    public required RecordingPlan Recording { get; init; }
    public required CandidatePlan Candidate { get; init; }
    public required string[] RequiredActions { get; init; }
    public required string[] AllowedVisibleImageNames { get; init; }

    public void Validate()
    {
        if (SchemaVersion != ObservationContract.SchemaVersion
            || !string.Equals(PlanType, ObservationContract.PlanType, StringComparison.Ordinal))
        {
            throw new InvalidDataException("Unsupported observation plan contract.");
        }

        if (Edition is not ("personal" or "enterprise"))
        {
            throw new InvalidDataException("edition must be personal or enterprise.");
        }

        if (!Guid.TryParseExact(TestRunId, "D", out var parsedRunId)
            || !string.Equals(parsedRunId.ToString("D"), TestRunId, StringComparison.Ordinal))
        {
            throw new InvalidDataException("testRunId must be one canonical lowercase UUID.");
        }

        if (MinimumObservationSeconds < ObservationContract.MinimumDurationSeconds
            || MinimumObservationSeconds > 7200)
        {
            throw new InvalidDataException("minimumObservationSeconds must be between 900 and 7200.");
        }

        if (Recording is null
            || Candidate is null
            || RequiredActions is null
            || AllowedVisibleImageNames is null)
        {
            throw new InvalidDataException("Observation plan contains a null object or array.");
        }
        ObservationContract.RequireLowerSha256(ExpectedObserverSha256, nameof(ExpectedObserverSha256));
        Recording.Validate();
        Candidate.Validate();
        var recordingOutput = Path.GetFullPath(Recording.OutputPath);
        if (string.Equals(
                recordingOutput,
                Path.GetFullPath(Recording.RecorderExecutablePath),
                StringComparison.OrdinalIgnoreCase)
            || Candidate.Files.Any(file => string.Equals(
                recordingOutput,
                Path.GetFullPath(file.Path),
                StringComparison.OrdinalIgnoreCase)))
        {
            throw new InvalidDataException("Recording output must be separate from all executable candidate paths.");
        }

        if (!RequiredActions.SequenceEqual(ObservationContract.RequiredActions, StringComparer.Ordinal))
        {
            throw new InvalidDataException("requiredActions must contain the complete ordered action catalog.");
        }

        if (AllowedVisibleImageNames.Length > 32
            || AllowedVisibleImageNames.Any(static item =>
                string.IsNullOrWhiteSpace(item)
                || item.Length > 128
                || !string.Equals(Path.GetFileName(item), item, StringComparison.Ordinal)
                || !string.Equals(item.ToLowerInvariant(), item, StringComparison.Ordinal))
            || AllowedVisibleImageNames.Distinct(StringComparer.OrdinalIgnoreCase).Count()
                != AllowedVisibleImageNames.Length)
        {
            throw new InvalidDataException("allowedVisibleImageNames must be unique lowercase base names.");
        }
    }
}

public sealed class RecordingPlan
{
    public required string RecorderExecutablePath { get; init; }
    public required string RecorderExecutableSha256 { get; init; }
    public required string OutputPath { get; init; }
    public required string MediaType { get; init; }
    public required bool AudioCaptured { get; init; }

    internal void Validate()
    {
        ObservationContract.RequireAbsolutePath(RecorderExecutablePath, nameof(RecorderExecutablePath));
        ObservationContract.RequireAbsolutePath(OutputPath, nameof(OutputPath));
        ObservationContract.RequireLowerSha256(RecorderExecutableSha256, nameof(RecorderExecutableSha256));
        if (MediaType is not ("video/mp4" or "application/octet-stream"))
        {
            throw new InvalidDataException("Unsupported recording mediaType.");
        }
        if (AudioCaptured)
        {
            throw new InvalidDataException("Pilot recordings must not capture audio.");
        }
    }
}

public sealed class CandidatePlan
{
    public required string ReleaseSetId { get; init; }
    public required long Generation { get; init; }
    public required long Sequence { get; init; }
    public required string LauncherRepositoryCommit { get; init; }
    public required string HarnessSourceTag { get; init; }
    public required string HarnessSourceCommit { get; init; }
    public required CandidateFilePlan[] Files { get; init; }

    internal void Validate()
    {
        ObservationContract.RequireToken(ReleaseSetId, nameof(ReleaseSetId));
        ObservationContract.RequireToken(HarnessSourceTag, nameof(HarnessSourceTag));
        if (Generation <= 0 || Sequence <= 0
            || Generation > 9_007_199_254_740_991L
            || Sequence > 9_007_199_254_740_991L)
        {
            throw new InvalidDataException("generation and sequence must be positive safe integers.");
        }
        if (string.IsNullOrWhiteSpace(LauncherRepositoryCommit)
            || string.IsNullOrWhiteSpace(HarnessSourceCommit)
            || !Regex.IsMatch(LauncherRepositoryCommit, "^[0-9a-f]{40}$", RegexOptions.CultureInvariant)
            || !Regex.IsMatch(HarnessSourceCommit, "^[0-9a-f]{40}$", RegexOptions.CultureInvariant))
        {
            throw new InvalidDataException("Repository commits must be lowercase full commit ids.");
        }
        if (Files is null
            || Files.Any(static item => item is null)
            || Files.Length != ObservationContract.CandidateRoles.Length
            || !Files.Select(static item => item.Role)
                .SequenceEqual(ObservationContract.CandidateRoles, StringComparer.Ordinal))
        {
            throw new InvalidDataException("candidate.files must contain the complete ordered role catalog.");
        }
        foreach (var file in Files)
        {
            file.Validate();
        }
        if (Files.Select(static item => Path.GetFullPath(item.Path))
            .Distinct(StringComparer.OrdinalIgnoreCase).Count() != Files.Length)
        {
            throw new InvalidDataException("candidate file paths must be unique.");
        }
    }
}

public sealed class CandidateFilePlan
{
    public required string Role { get; init; }
    public required string Path { get; init; }
    public required string Sha256 { get; init; }
    public required bool RequiredAtStart { get; init; }

    internal void Validate()
    {
        ObservationContract.RequireAbsolutePath(Path, $"candidate.{Role}.path");
        ObservationContract.RequireLowerSha256(Sha256, $"candidate.{Role}.sha256");
        if (string.IsNullOrWhiteSpace(System.IO.Path.GetFileName(Path)))
        {
            throw new InvalidDataException($"candidate.{Role}.path must name a file.");
        }
    }
}

public sealed record ObservationSummary
{
    public int SchemaVersion { get; init; } = ObservationContract.SchemaVersion;
    public string SummaryType { get; init; } = ObservationContract.SummaryType;
    public bool StandaloneAdmissionEvidence { get; init; }
    public required string TestRunId { get; init; }
    public required string Edition { get; init; }
    public required string Verdict { get; init; }
    public required string[] ReasonCodes { get; init; }
    public required string PlanSha256 { get; init; }
    public required string ObserverExecutableSha256 { get; init; }
    public required string StartedAtUtc { get; init; }
    public required string CompletedAtUtc { get; init; }
    public required long MonotonicDurationMilliseconds { get; init; }
    public required SamplingSummary Sampling { get; init; }
    public required ExecutionIdentitySummary ExecutionIdentity { get; init; }
    public required PlatformSummary Platform { get; init; }
    public required CandidateSummary Candidate { get; init; }
    public required CompletedActionSummary[] Actions { get; init; }
    public required RecordingSummary Recording { get; init; }
    public required EvidenceLogSummary EvidenceLog { get; init; }
    public required UnexpectedWindowSummary[] UnexpectedWindows { get; init; }
}

public sealed record SamplingSummary(
    int LightweightIntervalMilliseconds,
    int FullSnapshotMaximumIntervalMilliseconds,
    long LightweightCount,
    long FullCount,
    long MaximumFullGapMilliseconds,
    long LostEventCount);

public sealed record ExecutionIdentitySummary(
    string ElevationType,
    int IntegrityRid,
    string AdministratorMembership);

public sealed record PlatformSummary(
    string OperatingSystemFamily,
    string Release,
    int MajorVersion,
    int MinorVersion,
    int BuildNumber,
    bool Workstation,
    string ProcessArchitecture,
    string OperatingSystemArchitecture,
    string ProcessMachine,
    string NativeMachine,
    bool WowOrEmulated);

public sealed record CandidateSummary(
    string ReleaseSetId,
    long Generation,
    long Sequence,
    string LauncherRepositoryCommit,
    string HarnessSourceTag,
    string HarnessSourceCommit,
    CandidateFileSummary[] Files);

public sealed record CandidateFileSummary(
    string Role,
    string Sha256,
    long SizeBytes,
    bool Observed);

public sealed record CompletedActionSummary(string ActionId, long CompletedAtMonotonicMilliseconds);

public sealed record RecordingSummary(
    string MediaType,
    long SizeBytes,
    string Sha256,
    long ObservationCoverageMilliseconds,
    bool AudioCaptured,
    string StartChallengeSha256,
    string EndChallengeSha256);

public sealed record EvidenceLogSummary(
    string MediaType,
    long SizeBytes,
    string Sha256,
    string TerminalRecordSha256,
    long RecordCount);

public sealed record UnexpectedWindowSummary(
    string ProcessImageName,
    string ClassName,
    string TitleSha256,
    string TitleCategory,
    long FirstSeenMonotonicMilliseconds);

public static class StrictJson
{
    public static void ValidateNoDuplicateProperties(ReadOnlySpan<byte> utf8)
    {
        using var document = JsonDocument.Parse(utf8.ToArray(), new JsonDocumentOptions
        {
            AllowTrailingCommas = false,
            CommentHandling = JsonCommentHandling.Disallow,
            MaxDepth = 32,
        });
        ValidateElement(document.RootElement, "$", 0);
    }

    private static void ValidateElement(JsonElement element, string path, int depth)
    {
        if (depth > 32)
        {
            throw new InvalidDataException("JSON depth exceeds the observation contract limit.");
        }
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name))
                {
                    throw new InvalidDataException($"Duplicate JSON property at {path}.{property.Name}.");
                }
                ValidateElement(property.Value, $"{path}.{property.Name}", depth + 1);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            var index = 0;
            foreach (var item in element.EnumerateArray())
            {
                ValidateElement(item, $"{path}[{index}]", depth + 1);
                index++;
            }
        }
    }
}
