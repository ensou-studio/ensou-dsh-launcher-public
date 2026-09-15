using System.Diagnostics;
using System.Reflection;
using Ensou.Dsh.Contracts;
using Ensou.Dsh.UpdateEngine;

namespace Ensou.Dsh.Bootstrapper;

/// <summary>
/// Stable personal Startup Stub. Its protocol surface is intentionally tiny:
/// select one validated client-bundle tuple, finish pending nonce health, and
/// start only that bundle's versioned Bootstrapper.
/// </summary>
internal static class Program
{
    private const string StartupStubVersionMetadataKey = "PersonalStartupStubVersion";
    private const string DevelopmentPendingHealthCommand = "--dev-e2e-apply-pending";
    private const string BackgroundStartupCommand = "--background-startup";
    private const string MachineCommandFailureMessage =
        "Ensou DSH Personal Startup Stub machine command failed.";
    private static readonly string CurrentStartupStubVersion =
        ReadCurrentStartupStubVersion();
    private static HealthProbeDiagnostics _diagnostics = new("stub", enabled: false);

    private sealed class DiagnosticForwarder : IDisposable
    {
        private readonly CancellationTokenSource _stop = new();
        private readonly Task _pump;

        private DiagnosticForwarder(StreamReader reader) => _pump = PumpAsync(reader, _stop.Token);

        internal static DiagnosticForwarder? TryCreate(Process process)
        {
            try { return process.StartInfo.RedirectStandardError ? new(process.StandardError) : null; }
            catch { return null; }
        }

        private static async Task PumpAsync(StreamReader reader, CancellationToken cancellationToken)
        {
            try
            {
                var buffer = new char[512];
                var line = new System.Text.StringBuilder(512);
                var discard = false;
                while (true)
                {
                    var count = await reader.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false);
                    if (count == 0) return;
                    for (var index = 0; index < count; index++)
                    {
                        var character = buffer[index];
                        if (character == '\n')
                        {
                            if (!discard) ForwardRecord(line.ToString().TrimEnd('\r'));
                            line.Clear();
                            discard = false;
                        }
                        else if (!discard)
                        {
                            if (line.Length >= 4096) { line.Clear(); discard = true; }
                            else line.Append(character);
                        }
                    }
                }
            }
            catch { /* Diagnostic transport never changes health or cleanup outcomes. */ }
        }

        private static void ForwardRecord(string line)
        {
            try
            {
                using var document = System.Text.Json.JsonDocument.Parse(line);
                var value = document.RootElement;
                if (value.ValueKind != System.Text.Json.JsonValueKind.Object
                    || value.GetProperty("schemaVersion").GetInt32() != 1
                    || value.GetProperty("event").GetString() != "personal-health-trace"
                    || value.GetProperty("component").GetString() is not ("client" or "launcher")
                    || !Identifier(value.GetProperty("phase").GetString())
                    || value.GetProperty("pid").GetInt32() <= 0
                    || !value.GetProperty("utc").TryGetDateTimeOffset(out _)
                    || !value.GetProperty("tickCount64").TryGetInt64(out _)
                    || !value.GetProperty("elapsedMilliseconds").TryGetDouble(out var elapsed)
                    || !double.IsFinite(elapsed) || elapsed < 0) return;
                var names = new HashSet<string>(StringComparer.Ordinal);
                foreach (var property in value.EnumerateObject())
                {
                    if (!names.Add(property.Name)) return;
                    switch (property.Name)
                    {
                        case "schemaVersion": case "event": case "component": case "phase":
                        case "pid": case "utc": case "tickCount64": case "elapsedMilliseconds":
                            break;
                        case "childProcessId":
                            if (!property.Value.TryGetInt32(out var child) || child <= 0) return;
                            break;
                        case "exitCode": case "hresult": case "innerHresult":
                            if (!property.Value.TryGetInt32(out _)) return;
                            break;
                        case "budgetMilliseconds":
                            if (!property.Value.TryGetInt64(out var budget) || budget < 0) return;
                            break;
                        case "exceptionType": case "innerExceptionType":
                            if (!Identifier(property.Value.GetString())) return;
                            break;
                        default: return;
                    }
                }
                // Re-serialize only the strictly validated diagnostic schema, never arbitrary stderr.
                Console.Error.WriteLine(System.Text.Json.JsonSerializer.Serialize(value));
                Console.Error.Flush();
            }
            catch { /* Drop malformed or unrelated output without exposing it. */ }
        }

        private static bool Identifier(string? value) =>
            value is { Length: > 0 and <= 64 }
            && value.All(character => character is >= 'a' and <= 'z'
                or >= 'A' and <= 'Z' or >= '0' and <= '9' or '_' or '-');

        public void Dispose()
        {
            try
            {
                if (!_pump.Wait(TimeSpan.FromSeconds(2))) _stop.Cancel();
            }
            catch { /* Teardown remains best effort and bounded. */ }
            finally { _stop.Dispose(); }
        }
    }

    [STAThread]
    private static int Main(string[] args)
    {
        var isMachineCommand = IsMachineCommandIntent(args)
            || PersonalDevelopmentLiveUpdateArguments.IsIntent(args);
        var developmentE2ECompiled = false;
        PersonalLauncherRestartHandoffCommand? restartHandoffForFailure = null;
        try
        {
            ApplicationConfiguration.Initialize();
            if (args is ["--binary-self-check"])
            {
                var fingerprint = PersonalBinarySelfCheck
                    .RequireCurrentProcessCompiledTrust(
                        PersonalInstallationLayout.StartupStubExecutableName,
                        Assembly.GetExecutingAssembly());
                PersonalBinarySelfCheck.WriteCanonicalCompiledTrust(fingerprint);
                return 0;
            }
            developmentE2ECompiled = PersonalDevelopmentE2ELayoutArguments.IsCompiled(
                Assembly.GetExecutingAssembly());
            var developmentArguments = PersonalDevelopmentE2ELayoutArguments.ParseAndStrip(
                args,
                developmentE2ECompiled,
                out var commandArguments);
            using var developmentLiveUpdateArguments =
                PersonalDevelopmentLiveUpdateArguments.ParseAndStrip(
                    commandArguments,
                    developmentE2ECompiled,
                    developmentArguments,
                    out commandArguments);
            var suppliedOverallDeadline = ParseOverallDeadlineAndStrip(
                commandArguments,
                out var boundedCommandArguments);
            commandArguments = boundedCommandArguments;
            if (PersonalLauncherRestartHandoffCommand.IsIntent(commandArguments))
            {
                restartHandoffForFailure =
                    PersonalLauncherRestartHandoffCommand.ParseRequired(commandArguments);
            }
            if (developmentE2ECompiled && developmentArguments is null)
            {
                throw new ArgumentException(
                    "This compiled Personal development E2E Startup Stub requires its explicit isolated layout.");
            }
            if (IsDevelopmentPendingHealthCommand(commandArguments)
                && (!developmentE2ECompiled || developmentArguments is null))
            {
                throw new ArgumentException(
                    "Development pending health requires the compiled E2E identity and explicit isolated layout.");
            }
            if (developmentArguments is not null
                && developmentLiveUpdateArguments is null
                && !IsInstallerHealthCommand(commandArguments)
                && !IsDevelopmentPendingHealthCommand(commandArguments))
            {
                throw new ArgumentException(
                    "Personal development E2E layout is limited to isolated pending health.");
            }
            if (developmentLiveUpdateArguments is not null
                && commandArguments is not [BackgroundStartupCommand]
                && restartHandoffForFailure is null)
            {
                throw new ArgumentException(
                    "Personal development live-update is limited to background startup or a real Launcher restart handoff.");
            }
            if (!IsAllowedInstalledCommand(commandArguments))
            {
                throw new ArgumentException(
                    "Personal Startup Stub command is not supported.");
            }

            _diagnostics = new HealthProbeDiagnostics(
                "stub", developmentE2ECompiled && developmentArguments is not null);
            _diagnostics.Mark("entry_admitted");
            var layout = developmentArguments?.Layout
                ?? PersonalInstallationLayout.CreateDefault();
            var overallDeadline = suppliedOverallDeadline
                ?? PersonalHealthBudgetV1.CreateDeadlineTickCount64(
                    PersonalHealthBudgetV1.OverallHealthEnvelope);
            using var overallTimeout = PersonalHealthBudgetV1.CreateCancellationUntil(
                overallDeadline,
                PersonalHealthBudgetV1.OverallHealthEnvelope);
            RequireInstalledEntryOrDevelopment(layout);
            layout.EnsureManagedRoots();
            var pointerStore = new PersonalReleaseSetPointerStore(layout);
            PersonalInstalledReleaseSetPointer? pointer;
            try
            {
                _diagnostics.Mark("pointer_begin");
                pointer = pointerStore.TryRead(overallTimeout.Token);
                _diagnostics.Mark("pointer_end");
            }
            catch (Exception exception) when (IsMaintenanceCommand(commandArguments)
                && exception is InvalidDataException
                    or IOException
                    or UnauthorizedAccessException)
            {
                throw new PersonalBinaryRepairRequiresInstallerException(
                    "The installed release cannot authorize its versioned maintenance host.",
                    exception);
            }
            if (pointer is null)
            {
                if (developmentLiveUpdateArguments is not null)
                {
                    throw new InvalidDataException(
                        "Personal development live-update requires an installed release tuple.");
                }
                if (IsInstallerHealthCommand(commandArguments)
                    || IsDevelopmentPendingHealthCommand(commandArguments))
                {
                    throw new InvalidDataException(
                        "Personal health command has no pending installed tuple.");
                }
                if (IsMaintenanceCommand(commandArguments))
                {
                    throw new PersonalBinaryRepairRequiresInstallerException(
                        "No installed release is available for offline shell maintenance.");
                }
                _ = new PersonalHarnessHomeTransaction(
                    layout.HarnessHome,
                    layout.HarnessRecoveryRoot).RecoverInterrupted();
                if (new PersonalLegacyV1FallbackStore(layout)
                    .TryStartLauncherAsync(commandArguments)
                    .GetAwaiter()
                    .GetResult())
                {
                    return 0;
                }
                if (TryStartDevelopmentLauncher(commandArguments))
                {
                    return 0;
                }
                throw new InvalidDataException(
                    "Personal Launcher is not installed; run the signed installer or repair package.");
            }

            // The signed compatibility range is authenticated in the DPAPI-backed
            // security state before this stable entry starts any versioned tuple.
            _diagnostics.Mark("installed_security_begin");
            RequireAllowedInstalledPointer(layout, pointer, overallTimeout.Token);
            _diagnostics.Mark("installed_security_end");

            if (IsDevelopmentPendingHealthCommand(commandArguments))
            {
                if (pointer.Current.HealthState != PersonalReleaseHealthStates.Pending)
                {
                    throw new InvalidDataException(
                        "Development update health requires a pending installed release tuple.");
                }
                var candidate = pointer.Current;
                var pendingHealth = new PersonalBootstrapHealthGate(
                        layout,
                        timeout: null,
                        diagnostic: (phase, exception) => _diagnostics.Mark(phase, exception),
                        overallDeadlineTickCount64: overallDeadline)
                    .EnsureHealthyBoundedAsync((path, token, activeDeadline, cancellationToken) =>
                        RunHealthProbeAsync(
                            path,
                            token,
                            activeDeadline,
                            cancellationToken,
                            developmentArguments),
                        overallTimeout.Token)
                    .GetAwaiter()
                    .GetResult();
                _diagnostics.Mark("confirmed_pointer_begin");
                var confirmed = pointerStore.TryRead(overallTimeout.Token);
                _diagnostics.Mark("confirmed_pointer_end");
                if (!pendingHealth.Healthy
                    || confirmed is null
                    || confirmed.Current.HealthState != PersonalReleaseHealthStates.Healthy
                    || confirmed.Current.Sequence != candidate.Sequence
                    || !string.Equals(confirmed.Current.ReleaseSetId, candidate.ReleaseSetId, StringComparison.Ordinal)
                    || !string.Equals(confirmed.Current.ManifestSha256, candidate.ManifestSha256, StringComparison.Ordinal))
                {
                    throw new InvalidDataException(
                        "Development update candidate did not commit its exact healthy release tuple.");
                }
                // A headless probe must not fall through to normal UI startup.
                return 0;
            }

            if (IsMaintenanceCommand(commandArguments))
            {
                return RunMaintenance(layout, pointer.Current, commandArguments);
            }

            if (commandArguments is ["--self-check"])
            {
                if (pointer.Current.HealthState != PersonalReleaseHealthStates.Healthy)
                {
                    throw new InvalidDataException(
                        "Personal release-set is still pending health verification.");
                }
                RequireAllowedInstalledPointer(layout, pointer, overallTimeout.Token);
                _ = PersonalMaintenanceIntegrity.RequireActiveClientBundle(
                    layout,
                    pointer.Current);
                return 0;
            }

            if (IsInstallerHealthCommand(commandArguments))
            {
                var installerHealth = new PersonalBootstrapHealthGate(
                        layout,
                        timeout: null,
                        diagnostic: (phase, exception) => _diagnostics.Mark(phase, exception),
                        overallDeadlineTickCount64: overallDeadline)
                    .EnsureInstallerHealthyBoundedAsync((path, token, activeDeadline, cancellationToken) =>
                        RunHealthProbeAsync(
                            path,
                            token,
                            activeDeadline,
                            cancellationToken,
                            developmentArguments),
                        overallTimeout.Token)
                    .GetAwaiter()
                    .GetResult();
                if (!installerHealth.Healthy)
                {
                    throw new InvalidDataException(
                        "Personal Installer release failed its isolated health command.");
                }
                return 0;
            }

            var health = new PersonalBootstrapHealthGate(
                    layout,
                    timeout: null,
                    diagnostic: (phase, exception) => _diagnostics.Mark(phase, exception),
                    overallDeadlineTickCount64: overallDeadline)
                .EnsureHealthyBoundedAsync((path, token, activeDeadline, cancellationToken) =>
                    RunHealthProbeAsync(
                        path,
                        token,
                        activeDeadline,
                        cancellationToken,
                        developmentArguments),
                    overallTimeout.Token)
                .GetAwaiter()
                .GetResult();
            pointer = pointerStore.TryRead(overallTimeout.Token);
            if (pointer is null)
            {
                if (new PersonalLegacyV1FallbackStore(layout)
                    .TryStartLauncherAsync(commandArguments)
                    .GetAwaiter()
                    .GetResult())
                {
                    return 0;
                }
                throw new InvalidDataException(
                    "The initial personal release failed health verification and was removed.");
            }
            if (!health.Healthy
                && pointer.Current.HealthState != PersonalReleaseHealthStates.Healthy)
            {
                throw new InvalidDataException(
                    "Personal release health verification failed without a healthy fallback.");
            }

            RequireAllowedInstalledPointer(layout, pointer, overallTimeout.Token);

            StartVersionedBootstrapper(
                pointer.Current,
                commandArguments,
                developmentArguments,
                developmentLiveUpdateArguments);
            return 0;
        }
        catch (Exception exception)
        {
            _diagnostics.Mark("entry_exception", exception);
            if (isMachineCommand || developmentE2ECompiled)
            {
                if (restartHandoffForFailure is not null)
                {
                    restartHandoffForFailure.TrySignalFailure();
                }
                else
                {
                    TrySignalForwardedRestartFailure(args);
                }
                WriteMachineCommandFailure();
            }
            else
            {
                MessageBox.Show(
                    exception.Message,
                    "Ensou DSH Launcher 无法启动",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
            }
            return 1;
        }
    }

    private static void RequireAllowedInstalledPointer(
        PersonalInstallationLayout layout,
        PersonalInstalledReleaseSetPointer pointer,
        CancellationToken cancellationToken)
    {
        var decision = new PersonalReleaseSecurityStateStore(
                layout.UpdateSecurityStatePath,
                new PersonalReleaseStateIdentity(
                    PersonalReleaseSetContract.Product,
                    PersonalReleaseSetContract.ProductionEnvironment,
                    pointer.Channel),
                layout.UpdateSecurityWitnessPath)
            .ValidateInstalledPointerForStartupStubAsync(
                pointer,
                CurrentStartupStubVersion,
                DateTimeOffset.UtcNow,
                cancellationToken)
            .GetAwaiter()
            .GetResult();
        if (!decision.Allowed)
        {
            throw new InvalidDataException(decision.Reason);
        }
    }

    private static string ReadCurrentStartupStubVersion()
    {
        var values = typeof(Program).Assembly
            .GetCustomAttributes<AssemblyMetadataAttribute>()
            .Where(attribute => string.Equals(
                attribute.Key,
                StartupStubVersionMetadataKey,
                StringComparison.Ordinal))
            .Select(attribute => attribute.Value)
            .ToArray();
        if (values.Length != 1 || string.IsNullOrWhiteSpace(values[0]))
        {
            throw new InvalidDataException(
                "Personal Startup Stub has no unique compiled protocol version.");
        }
        var value = values[0]!;
        _ = PersonalReleaseVersion.Compare(value, value);
        return value;
    }

    private static async Task<int> RunHealthProbeAsync(
        string bootstrapperPath,
        string healthToken,
        long activeDeadlineTickCount64,
        CancellationToken cancellationToken,
        PersonalDevelopmentE2ELayoutArguments? developmentArguments)
    {
        var workingDirectory = Path.GetDirectoryName(bootstrapperPath)
            ?? throw new InvalidDataException(
                "Versioned personal Bootstrapper has no working directory.");
        var expectedTrust = PersonalCompiledTrustFingerprint.ReadCompiled(
            Assembly.GetExecutingAssembly());
        var remaining = PersonalHealthBudgetV1.GetRemaining(
            activeDeadlineTickCount64,
            PersonalHealthBudgetV1.ActiveHealthEnvelope);
        _diagnostics.Mark(
            "child_lease_begin",
            budgetMilliseconds: (long)remaining.TotalMilliseconds);
        using var executable = PersonalCompiledTrustProcessVerifier
            .AcquireExecutableLaunchLease(
                bootstrapperPath,
                PersonalInstallationLayout.ClientBootstrapperExecutableName,
                expectedTrust);
        _diagnostics.Mark("child_lease_end");
        var startInfo = new ProcessStartInfo
        {
            FileName = bootstrapperPath,
            WorkingDirectory = workingDirectory,
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
            RedirectStandardError = developmentArguments is not null,
        };
        startInfo.ArgumentList.Add("--release-health-token");
        startInfo.ArgumentList.Add(healthToken);
        startInfo.ArgumentList.Add(PersonalHealthBudgetV1.ActiveDeadlineArgument);
        startInfo.ArgumentList.Add(activeDeadlineTickCount64.ToString(
            System.Globalization.CultureInfo.InvariantCulture));
        if (developmentArguments is not null)
        {
            foreach (var argument in developmentArguments.ToArguments())
            {
                startInfo.ArgumentList.Add(argument);
            }
        }
        using var process = executable.Start(startInfo);
        using var diagnosticForwarder = DiagnosticForwarder.TryCreate(process);
        _diagnostics.Mark("child_started", childProcessId: process.Id);
        try
        {
            _diagnostics.Mark("child_wait_begin", childProcessId: process.Id);
            await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
            _diagnostics.Mark("child_result", childProcessId: process.Id, exitCode: process.ExitCode);
            return process.ExitCode;
        }
        catch (OperationCanceledException exception)
        {
            _diagnostics.Mark("child_wait_cancelled", exception, childProcessId: process.Id);
            Exception? cleanupFailure = null;
            try
            {
                if (!process.HasExited)
                {
                    _diagnostics.Mark("child_kill_begin", childProcessId: process.Id);
                    process.Kill(entireProcessTree: true);
                    _diagnostics.Mark("child_kill_requested", childProcessId: process.Id);
                }
            }
            catch (InvalidOperationException) when (process.HasExited)
            {
                // The exact child exited between observation and termination.
            }
            catch (Exception killException)
            {
                cleanupFailure = killException;
                _diagnostics.Mark("child_kill_exception", killException, childProcessId: process.Id);
            }
            try
            {
                using var exitTimeout = new CancellationTokenSource(
                    PersonalHealthBudgetV1.OutputDrainTimeout);
                await process.WaitForExitAsync(exitTimeout.Token).ConfigureAwait(false);
            }
            catch (Exception exitException)
            {
                cleanupFailure = cleanupFailure is null
                    ? exitException
                    : new AggregateException(cleanupFailure, exitException);
            }
            if (!process.HasExited)
            {
                _diagnostics.Mark("child_exit_unconfirmed", cleanupFailure, childProcessId: process.Id);
                throw new TimeoutException(
                    "Personal release health deadline expired and exact child exit was not confirmed.",
                    cleanupFailure);
            }
            _diagnostics.Mark("child_exit_confirmed", childProcessId: process.Id);
            throw new TimeoutException(
                "Personal release health exceeded its bounded active deadline.",
                cleanupFailure);
        }
    }

    private static long? ParseOverallDeadlineAndStrip(
        IReadOnlyList<string> args,
        out string[] commandArguments)
    {
        if (args is ["--installer-health", PersonalHealthBudgetV1.OverallDeadlineArgument, var value])
        {
            commandArguments = ["--installer-health"];
            return PersonalHealthBudgetV1.ParseDeadlineTickCount64(
                value,
                PersonalHealthBudgetV1.OverallHealthEnvelope);
        }
        if (args.Contains(PersonalHealthBudgetV1.OverallDeadlineArgument, StringComparer.Ordinal))
        {
            throw new ArgumentException(
                "Personal health overall deadline is limited to Installer health.");
        }
        commandArguments = args.ToArray();
        return null;
    }

    private static void StartVersionedBootstrapper(
        PersonalInstalledReleaseSetReference current,
        IReadOnlyList<string> args,
        PersonalDevelopmentE2ELayoutArguments? developmentArguments,
        PersonalDevelopmentLiveUpdateArguments? developmentLiveUpdateArguments)
    {
        var path = Path.Combine(
            current.ClientBundle.Directory,
            PersonalInstallationLayout.ClientBootstrapperExecutableName);
        var expectedTrust = PersonalCompiledTrustFingerprint.ReadCompiled(
            Assembly.GetExecutingAssembly());
        using var executable = PersonalCompiledTrustProcessVerifier
            .AcquireExecutableLaunchLease(
                path,
                PersonalInstallationLayout.ClientBootstrapperExecutableName,
                expectedTrust);
        var isRestartHandoff =
            PersonalLauncherRestartHandoffCommand.TryParse(
                args,
                out var restartHandoff);
        var isBackgroundStartup = args is [BackgroundStartupCommand];
        var startInfo = new ProcessStartInfo
        {
            FileName = path,
            WorkingDirectory = current.ClientBundle.Directory,
            UseShellExecute = false,
            CreateNoWindow = isRestartHandoff || isBackgroundStartup,
            WindowStyle = isRestartHandoff || isBackgroundStartup
                ? ProcessWindowStyle.Hidden
                : ProcessWindowStyle.Normal,
        };
        if (isRestartHandoff || isBackgroundStartup)
        {
            foreach (var argument in args)
            {
                startInfo.ArgumentList.Add(argument);
            }
            if (developmentArguments is not null)
            {
                foreach (var argument in developmentArguments.ToArguments())
                {
                    startInfo.ArgumentList.Add(argument);
                }
            }
            if (developmentLiveUpdateArguments is not null)
            {
                foreach (var argument in developmentLiveUpdateArguments.ToArguments())
                {
                    startInfo.ArgumentList.Add(argument);
                }
            }
        }
        using var process = executable.Start(startInfo);
        if (restartHandoff is not null)
        {
            LauncherRestartHandoffForwarder.WaitForFinalReceiver(
                restartHandoff,
                process);
        }
    }

    private static int RunMaintenance(
        PersonalInstallationLayout layout,
        PersonalInstalledReleaseSetReference current,
        IReadOnlyList<string> args)
    {
        var expectedTrust = PersonalCompiledTrustFingerprint.ReadCompiled(
            Assembly.GetExecutingAssembly());
        using var maintenanceExecutable = PersonalMaintenanceIntegrity
            .AcquireActiveMaintenanceExecutableLaunchLease(
                layout,
                current,
                expectedTrust);
        var startInfo = new ProcessStartInfo
        {
            FileName = maintenanceExecutable.ExecutablePath,
            WorkingDirectory = Path.GetDirectoryName(
                maintenanceExecutable.ExecutablePath)
                ?? throw new InvalidDataException(
                    "Versioned personal Maintenance has no working directory."),
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
        };
        startInfo.ArgumentList.Add(
            args[0] == "--maintenance-repair" ? "--repair-shell" : "--uninstall");
        if (args[0] == "--maintenance-uninstall")
        {
            startInfo.ArgumentList.Add("--startup-stub-pid");
            startInfo.ArgumentList.Add(Environment.ProcessId.ToString(
                System.Globalization.CultureInfo.InvariantCulture));
        }
        if (args.Contains("--quiet", StringComparer.Ordinal))
        {
            startInfo.ArgumentList.Add("--quiet");
        }
        using var process = maintenanceExecutable.Start(startInfo);
        process.WaitForExit();
        return process.ExitCode;
    }

    private static bool IsMaintenanceCommand(IReadOnlyList<string> args) =>
        args is ["--maintenance-repair"]
        or ["--maintenance-uninstall"]
        or ["--maintenance-uninstall", "--quiet"];

    private static bool IsInstallerHealthCommand(IReadOnlyList<string> args) =>
        args is ["--installer-health"];

    private static bool IsDevelopmentPendingHealthCommand(IReadOnlyList<string> args) =>
        args is [DevelopmentPendingHealthCommand];

    private static bool IsAllowedInstalledCommand(IReadOnlyList<string> args) =>
        args.Count == 0
        || args is [BackgroundStartupCommand]
        || args is ["--self-check"]
        || IsInstallerHealthCommand(args)
        || IsDevelopmentPendingHealthCommand(args)
        || IsMaintenanceCommand(args)
        || PersonalLauncherRestartHandoffCommand.TryParse(args, out _);

    private static bool IsMachineCommandIntent(IReadOnlyList<string> args) =>
        args.Count > 0
        && args[0] is "--binary-self-check"
            or BackgroundStartupCommand
            or "--self-check"
            or "--installer-health"
            or DevelopmentPendingHealthCommand
            or "--maintenance-repair"
            or "--maintenance-uninstall"
            or PersonalLauncherRestartHandoffCommand.CommandSwitch;

    private static void TrySignalForwardedRestartFailure(IReadOnlyList<string> args)
    {
        if (!PersonalLauncherRestartHandoffCommand.IsIntent(args))
        {
            return;
        }
        var commandLength = args.Count >= 5
            && string.Equals(
                args[4],
                PersonalLauncherRestartHandoffCommand.BackgroundStartupSwitch,
                StringComparison.Ordinal)
                ? 5
                : 4;
        if (args.Count >= commandLength)
        {
            PersonalLauncherRestartHandoffCommand.TrySignalFailure(
                args.Take(commandLength).ToArray());
        }
    }

    private static void WriteMachineCommandFailure()
    {
        try
        {
            Console.Error.WriteLine(MachineCommandFailureMessage);
        }
        catch
        {
            // Machine commands must never fall back to a desktop error box.
        }
    }

    private static void RequireInstalledEntryOrDevelopment(
        PersonalInstallationLayout layout)
    {
        var processPath = Environment.ProcessPath
            ?? throw new InvalidOperationException(
                "Unable to identify the personal Startup Stub executable.");
        if (string.Equals(
                Path.GetFullPath(processPath),
                Path.GetFullPath(layout.StartupStubPath),
                StringComparison.OrdinalIgnoreCase))
        {
            PersonalAuthenticodeVerifier.RequireTrustedEnsouExecutable(processPath);
            return;
        }
        if (!string.Equals(
                Environment.GetEnvironmentVariable(
                    "ENSOU_DSH_ALLOW_DEVELOPMENT_LAUNCHER"),
                "1",
                StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "Start the personal Launcher from its installed shortcut. Source debugging must be explicitly enabled.");
        }
    }

    private static bool TryStartDevelopmentLauncher(IReadOnlyList<string> args)
    {
        if (args.Count != 0
            || !string.Equals(
                Environment.GetEnvironmentVariable(
                    "ENSOU_DSH_ALLOW_DEVELOPMENT_LAUNCHER"),
                "1",
                StringComparison.Ordinal))
        {
            return false;
        }
        var configuration = new DirectoryInfo(AppContext.BaseDirectory).Parent?.Name ?? "Debug";
        var launcherDirectory = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory,
            "..",
            "..",
            "..",
            "..",
            "Ensou.Dsh.Launcher",
            "bin",
            configuration,
            "net10.0-windows"));
        var launcherPath = Path.Combine(
            launcherDirectory,
            PersonalInstallationLayout.LauncherExecutableName);
        if (!File.Exists(launcherPath))
        {
            throw new FileNotFoundException(
                "Development personal Launcher was not built.",
                launcherPath);
        }
        _ = Process.Start(new ProcessStartInfo
        {
            FileName = launcherPath,
            WorkingDirectory = launcherDirectory,
            UseShellExecute = true,
        }) ?? throw new InvalidOperationException(
            "Development personal Launcher did not start.");
        return true;
    }
}
