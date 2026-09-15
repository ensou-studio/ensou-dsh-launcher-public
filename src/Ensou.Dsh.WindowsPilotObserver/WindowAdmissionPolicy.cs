namespace Ensou.Dsh.WindowsPilotObserver;

public enum WindowAdmissionResult
{
    Allowed,
    Blocked,
    Unexpected,
}

public sealed class WindowAdmissionPolicy
{
    private static readonly HashSet<string> ConsoleClasses = new(StringComparer.OrdinalIgnoreCase)
    {
        "ConsoleWindowClass",
        "CASCADIA_HOSTING_WINDOW_CLASS",
        "PseudoConsoleWindow",
    };

    private readonly HashSet<string> baseline;
    private readonly HashSet<string> allowedImageNames;
    private readonly HashSet<string> candidateImageNames;
    private readonly HashSet<string> candidatePaths;
    private readonly int observerProcessId;
    private readonly string recorderImageName;

    public WindowAdmissionPolicy(
        IEnumerable<WindowObservation> baselineWindows,
        ObservationPlan plan,
        int observerProcessId)
    {
        baseline = baselineWindows.Select(static item => item.IdentityKey)
            .ToHashSet(StringComparer.Ordinal);
        allowedImageNames = plan.AllowedVisibleImageNames
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        allowedImageNames.Add("explorer.exe");
        candidateImageNames = plan.Candidate.Files
            .Select(static file => Path.GetFileName(file.Path))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        candidatePaths = plan.Candidate.Files
            .Select(static file => Path.GetFullPath(file.Path))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        recorderImageName = Path.GetFileName(plan.Recording.RecorderExecutablePath);
        this.observerProcessId = observerProcessId;
    }

    public WindowAdmissionResult Evaluate(
        WindowObservation window,
        bool candidateRelated,
        bool allowBaseline = true)
    {
        if (window.ProcessId == observerProcessId)
        {
            return WindowAdmissionResult.Allowed;
        }
        if (window.TitleCategory is "application-error" or "unhandled-error" or "security-prompt")
        {
            return WindowAdmissionResult.Unexpected;
        }
        if (ConsoleClasses.Contains(window.ClassName))
        {
            return WindowAdmissionResult.Unexpected;
        }
        if (string.Equals(window.ClassName, "#32770", StringComparison.OrdinalIgnoreCase))
        {
            return WindowAdmissionResult.Unexpected;
        }
        if (allowBaseline && baseline.Contains(window.IdentityKey))
        {
            return WindowAdmissionResult.Allowed;
        }
        if (!window.Visible)
        {
            return WindowAdmissionResult.Allowed;
        }
        var exactCandidatePath = window.ExecutablePath is not null
            && candidatePaths.Contains(Path.GetFullPath(window.ExecutablePath));
        if (exactCandidatePath
            || (window.ExecutablePath is null
                && candidateRelated
                && candidateImageNames.Contains(window.ProcessImageName))
            || allowedImageNames.Contains(window.ProcessImageName)
            || string.Equals(
                window.ProcessImageName,
                recorderImageName,
                StringComparison.OrdinalIgnoreCase))
        {
            return WindowAdmissionResult.Allowed;
        }
        if (window.ExecutablePath is null
            && candidateImageNames.Contains(window.ProcessImageName))
        {
            return WindowAdmissionResult.Blocked;
        }
        return WindowAdmissionResult.Unexpected;
    }
}
