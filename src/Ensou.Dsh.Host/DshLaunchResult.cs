namespace Ensou.Dsh.Host;

public enum DshLaunchState
{
    Started,
    AlreadyHealthy
}

public sealed class DshLaunchResult
{
    internal DshLaunchResult(
        DshLaunchState state,
        Uri webUiUri,
        int? processId)
    {
        State = state;
        WebUiUri = webUiUri ?? throw new ArgumentNullException(nameof(webUiUri));
        ProcessId = processId;
    }

    public DshLaunchState State { get; }

    public Uri WebUiUri { get; }

    public int? ProcessId { get; }

    public override string ToString() =>
        $"DshLaunchResult {{ State = {State}, WebUiUri = {WebUiUri}, ProcessId = {ProcessId} }}";
}
