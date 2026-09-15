using System.Globalization;
using System.Security.Cryptography;

namespace Ensou.Dsh.Contracts;

public enum LauncherRestartHandoffScope
{
    Personal,
    Enterprise,
}

public sealed record PersonalLauncherRestartHandoffCommand
{
    public const string CommandSwitch = "--launcher-restart-handoff";
    public const string EnterpriseCommandSwitch = "--enterprise-launcher-restart-handoff";
    public const string ParentProcessIdSwitch = "--parent-pid";
    public const string BackgroundStartupSwitch = "--background-startup";
    public const int TokenLength = 43;

    private string EventPrefix => Scope == LauncherRestartHandoffScope.Enterprise
        ? "Local\\Ensou.Dsh.Enterprise.Launcher.Restart."
        : "Local\\Ensou.Dsh.Launcher.Restart.";
    private string PipePrefix => Scope == LauncherRestartHandoffScope.Enterprise
        ? "Ensou.Dsh.Enterprise.Launcher.Restart."
        : "Ensou.Dsh.Launcher.Restart.";

    private PersonalLauncherRestartHandoffCommand(
        string token,
        int parentProcessId,
        bool backgroundStartup,
        LauncherRestartHandoffScope scope)
    {
        Token = token;
        ParentProcessId = parentProcessId;
        BackgroundStartup = backgroundStartup;
        Scope = scope;
    }

    public string Token { get; }

    public int ParentProcessId { get; }

    public bool BackgroundStartup { get; }

    public LauncherRestartHandoffScope Scope { get; }

    public string ArmedEventName => $"{EventPrefix}{Token}.Armed";

    public string OwnedEventName => $"{EventPrefix}{Token}.Owned";

    public string ReadyEventName => $"{EventPrefix}{Token}.Ready";

    public string CancellationEventName => $"{EventPrefix}{Token}.Cancelled";

    public string FailureEventName => $"{EventPrefix}{Token}.Failed";

    public string CommitEventName => $"{EventPrefix}{Token}.Commit";

    public string CommitAcknowledgedEventName =>
        $"{EventPrefix}{Token}.CommitAcknowledged";

    public string ReleasedEventName => $"{EventPrefix}{Token}.Released";

    public string RollbackOwnedEventName =>
        $"{EventPrefix}{Token}.RollbackOwned";

    public string PipeName => $"{PipePrefix}{Token}.Control";

    public static bool IsIntent(
        IReadOnlyList<string> args,
        LauncherRestartHandoffScope scope = LauncherRestartHandoffScope.Personal) =>
        args.Count > 0
        && string.Equals(args[0], SwitchFor(scope), StringComparison.Ordinal);

    public static PersonalLauncherRestartHandoffCommand Create(
        int parentProcessId,
        bool backgroundStartup = false,
        LauncherRestartHandoffScope scope = LauncherRestartHandoffScope.Personal)
    {
        if (parentProcessId <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(parentProcessId));
        }

        _ = SwitchFor(scope);
        var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
        return new PersonalLauncherRestartHandoffCommand(
            token,
            parentProcessId,
            backgroundStartup,
            scope);
    }

    public static bool TryParse(
        IReadOnlyList<string> args,
        out PersonalLauncherRestartHandoffCommand? command,
        LauncherRestartHandoffScope scope = LauncherRestartHandoffScope.Personal)
    {
        command = null;
        if (args.Count is not (4 or 5)
            || !string.Equals(args[0], SwitchFor(scope), StringComparison.Ordinal)
            || !string.Equals(args[2], ParentProcessIdSwitch, StringComparison.Ordinal)
            || (args.Count == 5
                && !string.Equals(args[4], BackgroundStartupSwitch, StringComparison.Ordinal)))
        {
            return false;
        }
        var token = args[1];
        var parentProcessIdText = args[3];
        if (!IsCanonicalToken(token)
            || !int.TryParse(
                parentProcessIdText,
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out var parentProcessId)
            || parentProcessId <= 0)
        {
            return false;
        }

        var backgroundStartup = args.Count == 5;

        command = new PersonalLauncherRestartHandoffCommand(
            token,
            parentProcessId,
            backgroundStartup,
            scope);
        return true;
    }

    public static PersonalLauncherRestartHandoffCommand ParseRequired(
        IReadOnlyList<string> args,
        LauncherRestartHandoffScope scope = LauncherRestartHandoffScope.Personal) =>
        TryParse(args, out var command, scope)
            ? command!
            : throw new ArgumentException(
                "Launcher restart handoff arguments are invalid.",
                nameof(args));

    public IReadOnlyList<string> ToArguments()
    {
        var arguments = new List<string>
        {
            SwitchFor(Scope),
            Token,
            ParentProcessIdSwitch,
            ParentProcessId.ToString(CultureInfo.InvariantCulture),
        };
        if (BackgroundStartup)
        {
            arguments.Add(BackgroundStartupSwitch);
        }
        return arguments;
    }

    public void TrySignalFailure()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }
        try
        {
            using var failure = EventWaitHandle.OpenExisting(FailureEventName);
            failure.Set();
        }
        catch
        {
            // The parent may already have cancelled or exited. Handoff failure
            // reporting must never replace the original failure.
        }
    }

    public static void TrySignalFailure(
        IReadOnlyList<string> args,
        LauncherRestartHandoffScope scope = LauncherRestartHandoffScope.Personal)
    {
        if (TryParse(args, out var command, scope))
        {
            command!.TrySignalFailure();
        }
    }

    private static string SwitchFor(LauncherRestartHandoffScope scope) => scope switch
    {
        LauncherRestartHandoffScope.Personal => CommandSwitch,
        LauncherRestartHandoffScope.Enterprise => EnterpriseCommandSwitch,
        _ => throw new ArgumentOutOfRangeException(nameof(scope)),
    };

    private static bool IsCanonicalToken(string token) =>
        token.Length == TokenLength
        && token.All(character =>
            character is >= 'A' and <= 'Z'
                or >= 'a' and <= 'z'
                or >= '0' and <= '9'
                or '-'
                or '_');
}
