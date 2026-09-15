namespace Ensou.Dsh.UpdateEngine;

internal enum PersonalInstallerCommandKind
{
    Install,
    BinarySelfCheck,
    DevelopmentPayloadSelfCheck,
    ProductionPayloadSelfCheck,
}

internal sealed record PersonalInstallerCommand(
    PersonalInstallerCommandKind Kind,
    bool Quiet,
    bool AllowUnsignedDevelopmentInstall,
    PersonalInstallerDevelopmentE2ELayout? DevelopmentE2ELayout)
{
    public bool IsMachineSelfCheck => Kind is not PersonalInstallerCommandKind.Install;
}

internal sealed record PersonalInstallerDevelopmentE2ELayout(
    string ManagedRoot,
    string HarnessHome,
    string UpdateSecurityWitnessPath);

internal sealed class PersonalInstallerInstallAdmissionException(string message)
    : InvalidOperationException(message);

internal static class PersonalInstallerCommandLine
{
    internal const string InstallArgument = "--install";
    internal const string QuietArgument = "--quiet";
    internal const string DevelopmentOverrideArgument =
        "--allow-unsigned-development-install";
    internal const string DevelopmentE2ELayoutArgument = "--dev-e2e-layout";
    internal const string DevelopmentManagedRootArgument = "--dev-managed-root";
    internal const string DevelopmentHarnessHomeArgument = "--dev-harness-home";
    internal const string DevelopmentUpdateSecurityWitnessArgument =
        "--dev-update-security-witness";
    internal const string DevelopmentNoShellRegistrationArgument =
        "--dev-no-shell-registration";
    internal const string BinarySelfCheckArgument = "--binary-self-check";
    internal const string DevelopmentPayloadSelfCheckArgument =
        "--development-payload-self-check";
    internal const string ProductionPayloadSelfCheckArgument =
        "--production-payload-self-check";

    internal static bool HasMachineSelfCheckIntent(IReadOnlyList<string> arguments) =>
        arguments.Count > 0
        && arguments[0] is BinarySelfCheckArgument
            or DevelopmentPayloadSelfCheckArgument
            or ProductionPayloadSelfCheckArgument;

    internal static PersonalInstallerCommand Parse(IReadOnlyList<string> arguments)
    {
        ArgumentNullException.ThrowIfNull(arguments);

        if (arguments.Count == 1
            && string.Equals(
                arguments[0],
                BinarySelfCheckArgument,
                StringComparison.Ordinal))
        {
            return new PersonalInstallerCommand(
                PersonalInstallerCommandKind.BinarySelfCheck,
                Quiet: true,
                AllowUnsignedDevelopmentInstall: false,
                DevelopmentE2ELayout: null);
        }

        if (arguments.Count > 0
            && arguments[0] is DevelopmentPayloadSelfCheckArgument
                or ProductionPayloadSelfCheckArgument)
        {
            if (arguments.Count != 10
                || arguments.Any(argument => string.Equals(
                    argument,
                    DevelopmentOverrideArgument,
                    StringComparison.Ordinal)))
            {
                throw new ArgumentException(
                    "Personal Installer machine self-check arguments are invalid.");
            }

            return new PersonalInstallerCommand(
                arguments[0] == DevelopmentPayloadSelfCheckArgument
                    ? PersonalInstallerCommandKind.DevelopmentPayloadSelfCheck
                    : PersonalInstallerCommandKind.ProductionPayloadSelfCheck,
                Quiet: true,
                AllowUnsignedDevelopmentInstall: false,
                DevelopmentE2ELayout: null);
        }

        var install = false;
        var quiet = false;
        var allowUnsignedDevelopmentInstall = false;
        var developmentE2ELayout = false;
        var developmentNoShellRegistration = false;
        string? managedRoot = null;
        string? harnessHome = null;
        string? updateSecurityWitnessPath = null;
        for (var index = 0; index < arguments.Count; index++)
        {
            switch (arguments[index])
            {
                case InstallArgument when !install:
                    install = true;
                    break;
                case QuietArgument when !quiet:
                    quiet = true;
                    break;
                case DevelopmentOverrideArgument when !allowUnsignedDevelopmentInstall:
                    allowUnsignedDevelopmentInstall = true;
                    break;
                case DevelopmentE2ELayoutArgument when !developmentE2ELayout:
                    developmentE2ELayout = true;
                    break;
                case DevelopmentNoShellRegistrationArgument
                    when !developmentNoShellRegistration:
                    developmentNoShellRegistration = true;
                    break;
                case DevelopmentManagedRootArgument when managedRoot is null:
                    managedRoot = RequireDevelopmentPathArgument(arguments, ref index);
                    break;
                case DevelopmentHarnessHomeArgument when harnessHome is null:
                    harnessHome = RequireDevelopmentPathArgument(arguments, ref index);
                    break;
                case DevelopmentUpdateSecurityWitnessArgument
                    when updateSecurityWitnessPath is null:
                    updateSecurityWitnessPath = RequireDevelopmentPathArgument(arguments, ref index);
                    break;
                default:
                    throw new ArgumentException(
                        "Personal Installer arguments are invalid.");
            }
        }

        PersonalInstallerDevelopmentE2ELayout? e2eLayout = null;
        if (developmentE2ELayout || developmentNoShellRegistration
            || managedRoot is not null || harnessHome is not null
            || updateSecurityWitnessPath is not null)
        {
            if (!install || !quiet || !developmentE2ELayout || !developmentNoShellRegistration
                || managedRoot is null || harnessHome is null
                || updateSecurityWitnessPath is null)
            {
                throw new ArgumentException(
                    "Personal development E2E installation requires quiet mode, its exact layout, three absolute paths, and no-shell-registration flag.");
            }
            e2eLayout = new PersonalInstallerDevelopmentE2ELayout(
                managedRoot,
                harnessHome,
                updateSecurityWitnessPath);
        }

        return new PersonalInstallerCommand(
            PersonalInstallerCommandKind.Install,
            quiet,
            allowUnsignedDevelopmentInstall,
            e2eLayout);
    }

    private static string RequireDevelopmentPathArgument(
        IReadOnlyList<string> arguments,
        ref int index)
    {
        if (index == arguments.Count - 1
            || string.IsNullOrWhiteSpace(arguments[index + 1]))
        {
            throw new ArgumentException(
                "Personal development E2E installation path argument is missing.");
        }
        index++;
        return arguments[index];
    }

    internal static void RequireInstallAllowed(
        PersonalInstallerCommand command,
        bool productionBuild,
        bool developmentE2ECompiled)
    {
        ArgumentNullException.ThrowIfNull(command);
        if (command.Kind is not PersonalInstallerCommandKind.Install)
        {
            throw new PersonalInstallerInstallAdmissionException(
                "Machine self-check commands cannot enter Personal installation.");
        }
        if (productionBuild && command.AllowUnsignedDevelopmentInstall)
        {
            throw new PersonalInstallerInstallAdmissionException(
                "Production Personal Installer rejects the unsigned-development override.");
        }
        if (!productionBuild && !command.AllowUnsignedDevelopmentInstall)
        {
            throw new PersonalInstallerInstallAdmissionException(
                "This unsigned Personal development Installer is non-distributable and refuses ordinary installation. "
                + $"A trusted developer must explicitly pass {DevelopmentOverrideArgument}.");
        }
        if (!productionBuild && developmentE2ECompiled
            && command.DevelopmentE2ELayout is null)
        {
            throw new PersonalInstallerInstallAdmissionException(
                "This compiled Personal development E2E Installer requires its exact isolated layout and no-shell-registration flags.");
        }
        if (command.DevelopmentE2ELayout is not null
            && (productionBuild || !developmentE2ECompiled))
        {
            throw new PersonalInstallerInstallAdmissionException(
                "Personal development E2E installation is unavailable in this compiled Installer.");
        }
    }
}
