namespace Ensou.Dsh.WindowsPilotObserver;

public static class ObservationSummaryVerifier
{
    public static void Validate(ObservationSummary summary, ObservationPlan plan)
    {
        var violations = GetViolations(summary, plan);
        if (violations.Length != 0)
        {
            throw new InvalidDataException(
                $"Observation summary invariants failed: {string.Join(", ", violations)}.");
        }
    }

    public static string[] GetEligibilityViolations(ObservationSummary summary, ObservationPlan plan)
    {
        if (!string.Equals(summary.Verdict, "ELIGIBLE_FOR_REVIEW", StringComparison.Ordinal))
        {
            return [];
        }

        var violations = new List<string>();
        var requiredDuration = Math.Max(
            ObservationContract.MinimumDurationSeconds * 1000L,
            checked(plan.MinimumObservationSeconds * 1000L));
        if (summary.MonotonicDurationMilliseconds < requiredDuration)
        {
            violations.Add("ELIGIBLE_DURATION_INVALID");
        }
        if (summary.ReasonCodes.Length != 0)
        {
            violations.Add("ELIGIBLE_REASON_CODES_PRESENT");
        }
        if (summary.Sampling.LightweightCount <= 0
            || summary.Sampling.FullCount <= 0
            || summary.Sampling.MaximumFullGapMilliseconds
                > ObservationContract.FullSnapshotMaximumIntervalMilliseconds
            || summary.Sampling.LostEventCount != 0)
        {
            violations.Add("ELIGIBLE_SAMPLING_INVALID");
        }
        if (summary.Actions.Length != ObservationContract.RequiredActions.Length
            || !summary.Actions.Select(static item => item.ActionId)
                .SequenceEqual(ObservationContract.RequiredActions, StringComparer.Ordinal)
            || summary.Actions.Any(item =>
                item.CompletedAtMonotonicMilliseconds < 0
                || item.CompletedAtMonotonicMilliseconds > summary.MonotonicDurationMilliseconds)
            || summary.Actions.Zip(summary.Actions.Skip(1), static (left, right) =>
                    left.CompletedAtMonotonicMilliseconds > right.CompletedAtMonotonicMilliseconds)
                .Any(static reversed => reversed))
        {
            violations.Add("ELIGIBLE_ACTIONS_INVALID");
        }
        if (summary.Candidate.Files.Length != ObservationContract.CandidateRoles.Length
            || !summary.Candidate.Files.Select(static item => item.Role)
                .SequenceEqual(ObservationContract.CandidateRoles, StringComparer.Ordinal)
            || summary.Candidate.Files.Any(static item => !item.Observed || item.SizeBytes <= 0)
            || summary.Candidate.Files.Zip(plan.Candidate.Files, static (actual, expected) =>
                    !string.Equals(actual.Sha256, expected.Sha256, StringComparison.Ordinal))
                .Any(static mismatch => mismatch))
        {
            violations.Add("ELIGIBLE_CANDIDATE_INVALID");
        }
        if (summary.Recording.SizeBytes <= 0
            || summary.Recording.ObservationCoverageMilliseconds < requiredDuration
            || summary.Recording.ObservationCoverageMilliseconds
                < summary.MonotonicDurationMilliseconds
            || summary.Recording.AudioCaptured
            || IsZeroSha256(summary.Recording.Sha256))
        {
            violations.Add("ELIGIBLE_RECORDING_INVALID");
        }
        if (summary.UnexpectedWindows.Length != 0)
        {
            violations.Add("ELIGIBLE_UNEXPECTED_WINDOWS_PRESENT");
        }
        if (!ExecutionIdentityPolicy.IsAccepted(
                ParseElevation(summary.ExecutionIdentity.ElevationType),
                summary.ExecutionIdentity.IntegrityRid))
        {
            violations.Add("ELIGIBLE_EXECUTION_IDENTITY_INVALID");
        }
        if (!PlatformEvidence.IsSupportedSummary(summary.Platform))
        {
            violations.Add("ELIGIBLE_PLATFORM_INVALID");
        }
        return violations.ToArray();
    }

    private static string[] GetViolations(ObservationSummary summary, ObservationPlan plan)
    {
        var violations = new List<string>();
        if (summary.SchemaVersion != ObservationContract.SchemaVersion
            || !string.Equals(summary.SummaryType, ObservationContract.SummaryType, StringComparison.Ordinal)
            || summary.StandaloneAdmissionEvidence
            || !string.Equals(summary.TestRunId, plan.TestRunId, StringComparison.Ordinal)
            || !string.Equals(summary.Edition, plan.Edition, StringComparison.Ordinal)
            || summary.Verdict is not ("ELIGIBLE_FOR_REVIEW" or "BLOCKED" or "FAIL"))
        {
            violations.Add("SUMMARY_BINDING_INVALID");
        }
        if (!string.Equals(summary.Candidate.ReleaseSetId, plan.Candidate.ReleaseSetId, StringComparison.Ordinal)
            || summary.Candidate.Generation != plan.Candidate.Generation
            || summary.Candidate.Sequence != plan.Candidate.Sequence
            || !string.Equals(summary.Candidate.LauncherRepositoryCommit, plan.Candidate.LauncherRepositoryCommit, StringComparison.Ordinal)
            || !string.Equals(summary.Candidate.HarnessSourceTag, plan.Candidate.HarnessSourceTag, StringComparison.Ordinal)
            || !string.Equals(summary.Candidate.HarnessSourceCommit, plan.Candidate.HarnessSourceCommit, StringComparison.Ordinal))
        {
            violations.Add("SUMMARY_CANDIDATE_TUPLE_INVALID");
        }
        if (summary.Sampling.LightweightIntervalMilliseconds != ObservationContract.LightweightIntervalMilliseconds
            || summary.Sampling.FullSnapshotMaximumIntervalMilliseconds
                != ObservationContract.FullSnapshotMaximumIntervalMilliseconds
            || summary.EvidenceLog.SizeBytes <= 0
            || summary.EvidenceLog.RecordCount <= 0
            || IsZeroSha256(summary.EvidenceLog.Sha256)
            || IsZeroSha256(summary.EvidenceLog.TerminalRecordSha256))
        {
            violations.Add("SUMMARY_EVIDENCE_INVALID");
        }
        if (!ExecutionIdentityPolicy.IsAccepted(
                ParseElevation(summary.ExecutionIdentity.ElevationType),
                summary.ExecutionIdentity.IntegrityRid))
        {
            violations.Add("SUMMARY_EXECUTION_IDENTITY_INVALID");
        }
        if (!PlatformEvidence.IsSupportedSummary(summary.Platform))
        {
            violations.Add("SUMMARY_PLATFORM_INVALID");
        }
        violations.AddRange(GetEligibilityViolations(summary, plan));
        return violations.Distinct(StringComparer.Ordinal).ToArray();
    }

    private static ProcessTokenElevationType ParseElevation(string value) => value switch
    {
        "default" => ProcessTokenElevationType.Default,
        "limited" => ProcessTokenElevationType.Limited,
        _ => ProcessTokenElevationType.Full,
    };

    private static bool IsZeroSha256(string value) =>
        string.Equals(value, new string('0', 64), StringComparison.Ordinal);
}
