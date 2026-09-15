namespace Ensou.Dsh.WindowsPilotObserver;

public enum ObservationVerdict
{
    EligibleForReview,
    Blocked,
    Fail,
}

public sealed class ObservationDecision
{
    private readonly object sync = new();
    private readonly HashSet<string> reasons = new(StringComparer.Ordinal);
    private readonly HashSet<string> completedActions = new(StringComparer.Ordinal);
    private ObservationVerdict verdict = ObservationVerdict.EligibleForReview;

    public ObservationVerdict Verdict
    {
        get { lock (sync) { return verdict; } }
    }

    public string[] ReasonCodes
    {
        get { lock (sync) { return reasons.Order(StringComparer.Ordinal).ToArray(); } }
    }

    public void CompleteAction(string actionId)
    {
        if (!ObservationContract.RequiredActions.Contains(actionId, StringComparer.Ordinal))
        {
            throw new ArgumentOutOfRangeException(nameof(actionId));
        }
        lock (sync)
        {
            completedActions.Add(actionId);
        }
    }

    public bool IsActionComplete(string actionId)
    {
        lock (sync) { return completedActions.Contains(actionId); }
    }

    public void Block(string reasonCode) => Change(ObservationVerdict.Blocked, reasonCode);

    public void Fail(string reasonCode) => Change(ObservationVerdict.Fail, reasonCode);

    public void Finalize(long durationMilliseconds, int minimumObservationSeconds)
    {
        if (durationMilliseconds < checked((long)minimumObservationSeconds * 1000L))
        {
            Block("OBSERVATION_DURATION_INSUFFICIENT");
        }
        lock (sync)
        {
            foreach (var action in ObservationContract.RequiredActions)
            {
                if (!completedActions.Contains(action))
                {
                    ChangeLocked(ObservationVerdict.Blocked, "REQUIRED_ACTION_INCOMPLETE");
                    break;
                }
            }
        }
    }

    public string ToContractValue() => Verdict switch
    {
        ObservationVerdict.Fail => "FAIL",
        ObservationVerdict.Blocked => "BLOCKED",
        _ => "ELIGIBLE_FOR_REVIEW",
    };

    private void Change(ObservationVerdict requested, string reasonCode)
    {
        if (string.IsNullOrWhiteSpace(reasonCode)
            || reasonCode.Any(static character =>
                !char.IsAsciiLetterUpper(character)
                && !char.IsAsciiDigit(character)
                && character != '_'))
        {
            throw new ArgumentException("Reason code must be uppercase ASCII.", nameof(reasonCode));
        }
        lock (sync)
        {
            ChangeLocked(requested, reasonCode);
        }
    }

    private void ChangeLocked(ObservationVerdict requested, string reasonCode)
    {
        reasons.Add(reasonCode);
        if (requested > verdict)
        {
            verdict = requested;
        }
    }
}
