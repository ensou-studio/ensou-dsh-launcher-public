namespace Ensou.Dsh.Enterprise.Installation;

public enum EnterpriseMaintenanceCommandKind
{
    BinarySelfCheck,
    RepairShell,
    Uninstall,
}

public sealed record EnterpriseMaintenanceCommand(
    EnterpriseMaintenanceCommandKind Kind,
    bool Quiet = false,
    bool Detached = false,
    bool DevelopmentE2ELayout = false,
    int? ParentProcessId = null,
    int? StartupStubProcessId = null,
    string? ExpectedWorkerSha256 = null);

public static class EnterpriseMaintenanceCommandLine
{
    public static EnterpriseMaintenanceCommand Parse(
        IReadOnlyList<string> args,
        bool developmentE2EEnabled)
    {
        ArgumentNullException.ThrowIfNull(args);
        if (args.Count == 1 && args[0] == "--binary-self-check")
        {
            return new EnterpriseMaintenanceCommand(
                EnterpriseMaintenanceCommandKind.BinarySelfCheck);
        }
        if (args.Count == 0
            || args[0] is not ("--repair-shell" or "--uninstall"))
        {
            throw new ArgumentException(
                "Enterprise Maintenance accepts only binary-self-check, repair-shell, or uninstall.");
        }

        var kind = args[0] == "--repair-shell"
            ? EnterpriseMaintenanceCommandKind.RepairShell
            : EnterpriseMaintenanceCommandKind.Uninstall;
        var quiet = false;
        var detached = false;
        var developmentE2ELayout = false;
        int? parentProcessId = null;
        int? startupStubProcessId = null;
        string? expectedWorkerSha256 = null;
        for (var index = 1; index < args.Count; index++)
        {
            switch (args[index])
            {
                case "--quiet" when !quiet:
                    quiet = true;
                    break;
                case "--dev-e2e-layout" when !developmentE2ELayout:
                    if (!developmentE2EEnabled)
                    {
                        throw new ArgumentException(
                            "Production Enterprise Maintenance does not accept Development-E2E layout options.");
                    }
                    developmentE2ELayout = true;
                    break;
                case "--detached" when !detached:
                    detached = true;
                    break;
                case "--parent-pid" when parentProcessId is null:
                    parentProcessId = ReadPositiveProcessId(
                        args,
                        ref index,
                        "--parent-pid");
                    break;
                case "--startup-stub-pid" when startupStubProcessId is null:
                    startupStubProcessId = ReadPositiveProcessId(
                        args,
                        ref index,
                        "--startup-stub-pid");
                    break;
                case "--expected-worker-sha256" when expectedWorkerSha256 is null:
                    expectedWorkerSha256 = ReadSha256(
                        args,
                        ref index,
                        "--expected-worker-sha256");
                    break;
                default:
                    throw new ArgumentException(
                        "Enterprise Maintenance arguments are duplicated or invalid.");
            }
        }

        if (kind == EnterpriseMaintenanceCommandKind.RepairShell)
        {
            if (detached
                || parentProcessId is not null
                || startupStubProcessId is not null
                || expectedWorkerSha256 is not null)
            {
                throw new ArgumentException(
                    "Enterprise shell repair does not accept uninstall worker arguments.");
            }
            return new EnterpriseMaintenanceCommand(
                kind,
                quiet,
                DevelopmentE2ELayout: developmentE2ELayout);
        }

        if (startupStubProcessId is null
            || detached != (parentProcessId is not null)
            || detached != (expectedWorkerSha256 is not null))
        {
            throw new ArgumentException(
                "Enterprise uninstall requires an exact Startup Stub binding and complete detached-worker binding.");
        }
        return new EnterpriseMaintenanceCommand(
            kind,
            quiet,
            detached,
            developmentE2ELayout,
            parentProcessId,
            startupStubProcessId,
            expectedWorkerSha256);
    }

    private static int ReadPositiveProcessId(
        IReadOnlyList<string> args,
        ref int index,
        string option)
    {
        if (++index >= args.Count
            || !int.TryParse(
                args[index],
                System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture,
                out var value)
            || value <= 0)
        {
            throw new ArgumentException(
                $"{option} requires one positive process ID.");
        }
        return value;
    }

    private static string ReadSha256(
        IReadOnlyList<string> args,
        ref int index,
        string option)
    {
        if (++index >= args.Count
            || args[index].Length != 64
            || args[index].Any(character => character is not (>= '0' and <= '9')
                and not (>= 'a' and <= 'f')))
        {
            throw new ArgumentException(
                $"{option} requires one canonical lowercase SHA-256.");
        }
        return args[index];
    }
}
