using System.Security.Cryptography;

namespace Ensou.Dsh.WindowsPilotObserver;

public sealed record RecordingCompletion(
    string MediaType,
    long SizeBytes,
    string Sha256,
    long CoverageMilliseconds,
    bool AudioCaptured,
    string StartChallengeSha256,
    string EndChallengeSha256);

public sealed class ExternalRecordingMonitor
{
    private readonly RecordingPlan plan;
    private string? recorderIdentity;
    private bool began;
    private string? endChallenge;

    public ExternalRecordingMonitor(RecordingPlan plan)
    {
        this.plan = plan;
        StartChallenge = CreateChallenge("START");
    }

    public string StartChallenge { get; }

    public void Begin(DesktopSnapshot snapshot)
    {
        try
        {
            _ = CandidateBindingTracker.VerifyExactFile(new CandidateFilePlan
            {
                Role = "external-recorder",
                Path = plan.RecorderExecutablePath,
                Sha256 = plan.RecorderExecutableSha256,
                RequiredAtStart = true,
            });
        }
        catch (CandidateBindingException exception)
        {
            throw new CandidateBindingException(
                "RECORDER_IDENTITY_INVALID",
                "The external recorder executable does not match its exact planned identity.",
                exception);
        }
        var exactPath = Path.GetFullPath(plan.RecorderExecutablePath);
        var matches = snapshot.Processes
            .Where(process => process.ExecutablePath is not null
                && string.Equals(
                    Path.GetFullPath(process.ExecutablePath),
                    exactPath,
                    StringComparison.OrdinalIgnoreCase))
            .ToArray();
        if (matches.Length != 1 || matches[0].CreationTimeUtcFileTime == 0)
        {
            throw new InvalidDataException("Exactly one identified external recorder process must be running.");
        }
        recorderIdentity = matches[0].IdentityKey;
        began = true;
    }

    public bool IsContinuous(DesktopSnapshot snapshot)
    {
        if (!began || recorderIdentity is null)
        {
            return false;
        }
        return snapshot.Processes.Any(process =>
            string.Equals(process.IdentityKey, recorderIdentity, StringComparison.Ordinal));
    }

    public string IssueEndChallenge()
    {
        endChallenge ??= CreateChallenge("END");
        return endChallenge;
    }

    public RecordingCompletion Complete(long coverageMilliseconds)
    {
        if (!began || endChallenge is null)
        {
            throw new InvalidOperationException("Recording challenges are incomplete.");
        }
        using var stream = CandidateBindingTracker.OpenExactReadOnly(
            plan.OutputPath,
            "external recording output");
        if (stream.Length <= 0 || stream.Length > 16L * 1024L * 1024L * 1024L)
        {
            throw new InvalidDataException("Recording output size is outside the accepted range.");
        }
        var hash = Convert.ToHexStringLower(SHA256.HashData(stream));
        return new RecordingCompletion(
            plan.MediaType,
            stream.Length,
            hash,
            coverageMilliseconds,
            false,
            ObservationPrivacy.HashSensitiveText(StartChallenge),
            ObservationPrivacy.HashSensitiveText(endChallenge));
    }

    private static string CreateChallenge(string stage) =>
        $"ENSOU-{stage}-{Convert.ToHexString(RandomNumberGenerator.GetBytes(12))}";
}
