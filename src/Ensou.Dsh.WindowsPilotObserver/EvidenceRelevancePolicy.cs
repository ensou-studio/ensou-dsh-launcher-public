namespace Ensou.Dsh.WindowsPilotObserver;

public sealed class EvidenceRelevancePolicy
{
    private readonly HashSet<string> candidateImageNames;
    private readonly HashSet<string> candidatePaths;
    private readonly string recorderImageName;
    private readonly string recorderPath;

    public EvidenceRelevancePolicy(ObservationPlan plan)
    {
        candidateImageNames = plan.Candidate.Files
            .Select(static item => Path.GetFileName(item.Path))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        candidatePaths = plan.Candidate.Files
            .Select(static item => Path.GetFullPath(item.Path))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        recorderImageName = Path.GetFileName(plan.Recording.RecorderExecutablePath);
        recorderPath = Path.GetFullPath(plan.Recording.RecorderExecutablePath);
    }

    public bool IsRelevant(ProcessObservation process)
    {
        if (process.CandidateRelated
            || candidateImageNames.Contains(process.ImageName)
            || NativeDesktop.SuspiciousImageNames.Contains(process.ImageName)
            || string.Equals(process.ImageName, recorderImageName, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (process.ExecutablePath is null)
        {
            return false;
        }

        var path = Path.GetFullPath(process.ExecutablePath);
        return candidatePaths.Contains(path)
            || string.Equals(path, recorderPath, StringComparison.OrdinalIgnoreCase);
    }

    public bool IsRelevant(WindowObservation window, ProcessObservation? process) =>
        (process is not null && IsRelevant(process))
        || candidateImageNames.Contains(window.ProcessImageName)
        || NativeDesktop.SuspiciousImageNames.Contains(window.ProcessImageName)
        || string.Equals(window.ProcessImageName, recorderImageName, StringComparison.OrdinalIgnoreCase)
        || window.TitleCategory is "application-error" or "unhandled-error" or "security-prompt"
        || string.Equals(window.ClassName, "#32770", StringComparison.OrdinalIgnoreCase)
        || string.Equals(window.ClassName, "ConsoleWindowClass", StringComparison.OrdinalIgnoreCase)
        || string.Equals(window.ClassName, "CASCADIA_HOSTING_WINDOW_CLASS", StringComparison.OrdinalIgnoreCase)
        || string.Equals(window.ClassName, "PseudoConsoleWindow", StringComparison.OrdinalIgnoreCase);

    public static bool HasUsableCreationTime(ProcessObservation process) =>
        process.CreationTimeUtcFileTime > 0;

    public static bool HasUsableCreationTime(WindowObservation window) =>
        window.ProcessCreationTimeUtcFileTime > 0;
}
