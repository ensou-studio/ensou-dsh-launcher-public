namespace Ensou.Dsh.Contracts;

public enum LauncherStartupAction
{
    CompleteRestartHandoff,
    InitializeBackground,
    ShowLauncher,
}

public static class LauncherStartupPolicy
{
    public static LauncherStartupAction SelectAction(
        bool hasIncomingRestartHandoff,
        bool backgroundStartup)
    {
        // A hidden receiver must finish the same ownership handshake as a
        // visible receiver before it initializes updates or starts a runtime.
        if (hasIncomingRestartHandoff)
        {
            return LauncherStartupAction.CompleteRestartHandoff;
        }

        return backgroundStartup
            ? LauncherStartupAction.InitializeBackground
            : LauncherStartupAction.ShowLauncher;
    }
}
