namespace Ensou.Dsh.Enterprise.Client;

public static class EnterpriseProductIdentity
{
    public const string ProductName = "Ensou DSH Enterprise Launcher";
    public const string ExecutableName = "Ensou.Dsh.Enterprise.Launcher.exe";
    public const string AppUserModelId = "studio.ensou.dsh.enterprise.launcher";
    public const string ManagedRootName = "DshEnterpriseLauncher";
    public const string HarnessHomeName = ".dsh-enterprise";
    public const string DeviceKeyName = "Ensou.Dsh.Enterprise.DeviceKey.v1";
    public const string SingleInstanceMutexName = "Local\\Ensou.Dsh.EnterpriseLauncher.SingleInstance";
    public const string ActivationEventName = "Local\\Ensou.Dsh.EnterpriseLauncher.Activate";
    public const int DefaultPort = 3081;

    public const string DevelopmentE2EProductName = "Ensou DSH Enterprise Launcher (Dev E2E)";
    public const string DevelopmentE2EAppUserModelId =
        "studio.ensou.dsh.enterprise.launcher.dev-e2e";
    public const string DevelopmentE2EManagedRootName = "DshEnterpriseLauncherDevE2E";
    public const string DevelopmentE2EHarnessHomeName = ".dsh-enterprise-dev-e2e";
    public const string DevelopmentE2EDeviceKeyName =
        "Ensou.Dsh.Enterprise.DeviceKey.DevE2E.v1";
    public const string DevelopmentE2ESingleInstanceMutexName =
        "Local\\Ensou.Dsh.EnterpriseLauncher.DevE2E.SingleInstance";
    public const string DevelopmentE2EActivationEventName =
        "Local\\Ensou.Dsh.EnterpriseLauncher.DevE2E.Activate";
    public const int DevelopmentE2EDefaultPort = 3181;
}
