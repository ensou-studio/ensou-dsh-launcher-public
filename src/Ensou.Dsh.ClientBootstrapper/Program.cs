using System.Diagnostics;
using System.Reflection;
using Ensou.Dsh.Contracts;
using Ensou.Dsh.UpdateEngine;

namespace Ensou.Dsh.ClientBootstrapper;

internal static class Program
{
    private const string MachineCommandFailureMessage =
        "Ensou DSH Personal ClientBootstrapper machine command failed.";
    private const string BackgroundStartupCommand = "--background-startup";
    private static HealthProbeDiagnostics _diagnostics = new("client", enabled: false);

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
                        PersonalInstallationLayout.ClientBootstrapperExecutableName,
                        Assembly.GetExecutingAssembly());
                PersonalBinarySelfCheck.WriteCanonicalCompiledTrust(fingerprint);
                return 0;
            }
            if (Environment.ProcessPath is { } processPath)
            {
                PersonalAuthenticodeVerifier.RequireTrustedEnsouExecutable(processPath);
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
            if (developmentE2ECompiled && developmentArguments is null)
            {
                throw new ArgumentException(
                    "This compiled Personal development E2E ClientBootstrapper requires its explicit isolated layout.");
            }
            if (developmentArguments is not null
                && developmentLiveUpdateArguments is null
                && commandArguments is not [
                    "--release-health-token",
                    _,
                    PersonalHealthBudgetV1.ActiveDeadlineArgument,
                    _])
            {
                throw new ArgumentException(
                    "Personal development E2E layout is limited to release health.");
            }
            var restartHandoff =
                PersonalLauncherRestartHandoffCommand.IsIntent(commandArguments)
                    ? PersonalLauncherRestartHandoffCommand.ParseRequired(commandArguments)
                    : null;
            restartHandoffForFailure = restartHandoff;
            if (developmentLiveUpdateArguments is not null
                && commandArguments is not [BackgroundStartupCommand]
                && restartHandoff is null)
            {
                throw new ArgumentException(
                    "Personal development live-update is limited to background startup or a real Launcher restart handoff.");
            }
            var healthCommand = commandArguments switch
            {
                [] => (Token: (string?)null, Deadline: (long?)null),
                [BackgroundStartupCommand] => (Token: (string?)null, Deadline: (long?)null),
                [
                    "--release-health-token",
                    var token,
                    PersonalHealthBudgetV1.ActiveDeadlineArgument,
                    var deadlineValue] => (
                        Token: (string?)token,
                        Deadline: (long?)PersonalHealthBudgetV1.ParseDeadlineTickCount64(
                            deadlineValue,
                            PersonalHealthBudgetV1.ActiveHealthEnvelope)),
                _ when restartHandoff is not null => (Token: (string?)null, Deadline: (long?)null),
                _ => throw new ArgumentException(
                    "Versioned personal Bootstrapper accepts only the release health token."),
            };
            var healthToken = healthCommand.Token;
            using var healthTimeout = healthCommand.Deadline is { } activeDeadline
                ? PersonalHealthBudgetV1.CreateCancellationUntil(
                    activeDeadline,
                    PersonalHealthBudgetV1.ActiveHealthEnvelope)
                : null;
            var healthCancellationToken = healthTimeout?.Token ?? CancellationToken.None;
            _diagnostics = new HealthProbeDiagnostics(
                "client", developmentE2ECompiled && developmentArguments is not null);
            _diagnostics.Mark("entry_admitted");
            var layout = developmentArguments?.Layout
                ?? PersonalInstallationLayout.CreateDefault();
            _diagnostics.Mark("pointer_begin");
            var pointer = new PersonalReleaseSetPointerStore(layout)
                .ReadRequired(healthCancellationToken);
            _diagnostics.Mark("pointer_end");
            RequireActiveBundle(pointer.Current);
            if (restartHandoff is not null)
            {
                if (pointer.Current.HealthState != PersonalReleaseHealthStates.Healthy)
                {
                    throw new InvalidDataException(
                        "A restart handoff requires a healthy personal release.");
                }
                using var forwardedLauncher = StartLauncher(
                    pointer.Current,
                    healthToken: null,
                    restartHandoff: restartHandoff,
                    developmentArguments: developmentArguments,
                    developmentLiveUpdateArguments: developmentLiveUpdateArguments);
                LauncherRestartHandoffForwarder.WaitForFinalReceiver(
                    restartHandoff,
                    forwardedLauncher);
                return 0;
            }
            if (healthToken is null)
            {
                if (pointer.Current.HealthState != PersonalReleaseHealthStates.Healthy)
                {
                    throw new InvalidDataException(
                        "A pending personal release may be started only by the stable Startup Stub.");
                }
                StartLauncher(
                    pointer.Current,
                    healthToken: null,
                    developmentArguments: developmentArguments,
                    developmentLiveUpdateArguments: developmentLiveUpdateArguments,
                    backgroundStartup: commandArguments is [BackgroundStartupCommand]);
                return 0;
            }
            if (pointer.Current.HealthState != PersonalReleaseHealthStates.Pending
                || !string.Equals(
                    pointer.Current.HealthToken,
                    healthToken,
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Personal release health token does not match the active client bundle.");
            }
            return RunLauncherHealth(
                pointer.Current,
                healthToken,
                healthCommand.Deadline!.Value,
                developmentArguments);
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

    private static bool IsMachineCommandIntent(IReadOnlyList<string> args) =>
        args.Count > 0
        && args[0] is "--binary-self-check"
            or "--release-health-token"
            or BackgroundStartupCommand
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
            // A machine command must terminate without entering a desktop UI,
            // even when its redirected diagnostic stream is unavailable.
        }
    }

    private static int RunLauncherHealth(
        PersonalInstalledReleaseSetReference current,
        string healthToken,
        long activeDeadlineTickCount64,
        PersonalDevelopmentE2ELayoutArguments? developmentArguments)
    {
        var remaining = PersonalHealthBudgetV1.GetRemaining(
            activeDeadlineTickCount64,
            PersonalHealthBudgetV1.ActiveHealthEnvelope);
        using var process = StartLauncher(
            current,
            healthToken,
            activeDeadlineTickCount64: activeDeadlineTickCount64,
            developmentArguments: developmentArguments);
        using var diagnosticForwarder = DiagnosticForwarder.TryCreate(process);
        _diagnostics.Mark("child_budget_armed", childProcessId: process.Id,
            budgetMilliseconds: (long)remaining.TotalMilliseconds);
        try
        {
            remaining = PersonalHealthBudgetV1.GetRemaining(
                activeDeadlineTickCount64,
                PersonalHealthBudgetV1.ActiveHealthEnvelope);
            if (!process.WaitForExit(
                    checked((int)Math.Ceiling(remaining.TotalMilliseconds))))
            {
                _diagnostics.Mark("child_deadline_expired", childProcessId: process.Id);
                var timeout = new TimeoutException(
                    "Personal Launcher runtime/WebUI health process timed out.");
                try
                {
                    StopAndConfirmHealthChild(process);
                }
                catch (Exception cleanupFailure)
                {
                    throw new AggregateException(
                        "Personal Launcher health timed out and exact child exit was not confirmed.",
                        timeout,
                        cleanupFailure);
                }
                throw timeout;
            }
            _diagnostics.Mark("child_result", childProcessId: process.Id, exitCode: process.ExitCode);
            return process.ExitCode;
        }
        catch
        {
            if (!process.HasExited)
            {
                StopAndConfirmHealthChild(process);
            }
            throw;
        }
    }

    private static void StopAndConfirmHealthChild(Process process)
    {
        if (!process.HasExited)
        {
            _diagnostics.Mark("child_kill_begin", childProcessId: process.Id);
            try
            {
                process.Kill(entireProcessTree: true);
                _diagnostics.Mark("child_kill_requested", childProcessId: process.Id);
            }
            catch (InvalidOperationException) when (process.HasExited)
            {
                // The exact child exited between observation and termination.
            }
        }
        if (!process.WaitForExit(checked((int)
                PersonalHealthBudgetV1.OutputDrainTimeout.TotalMilliseconds))
            || !process.HasExited)
        {
            _diagnostics.Mark("child_exit_unconfirmed", childProcessId: process.Id);
            throw new TimeoutException(
                "Personal ClientBootstrapper could not confirm exact Launcher health-process exit.");
        }
        _diagnostics.Mark("child_exit_confirmed", childProcessId: process.Id);
    }

    private static Process StartLauncher(
        PersonalInstalledReleaseSetReference current,
        string? healthToken,
        PersonalLauncherRestartHandoffCommand? restartHandoff = null,
        long? activeDeadlineTickCount64 = null,
        PersonalDevelopmentE2ELayoutArguments? developmentArguments = null,
        PersonalDevelopmentLiveUpdateArguments? developmentLiveUpdateArguments = null,
        bool backgroundStartup = false)
    {
        var launcherPath = Path.Combine(
            current.ClientBundle.Directory,
            PersonalInstallationLayout.LauncherExecutableName);
        var expectedTrust = PersonalCompiledTrustFingerprint.ReadCompiled(
            Assembly.GetExecutingAssembly());
        _diagnostics.Mark("child_lease_begin");
        using var executable = PersonalCompiledTrustProcessVerifier
            .AcquireExecutableLaunchLease(
                launcherPath,
                PersonalInstallationLayout.LauncherExecutableName,
                expectedTrust);
        _diagnostics.Mark("child_lease_end");
        var startInfo = new ProcessStartInfo
        {
            FileName = launcherPath,
            WorkingDirectory = current.ClientBundle.Directory,
            UseShellExecute = false,
            CreateNoWindow = healthToken is not null || restartHandoff is not null || backgroundStartup,
            RedirectStandardError = healthToken is not null && developmentArguments is not null,
            WindowStyle = healthToken is null && restartHandoff is null && !backgroundStartup
                ? ProcessWindowStyle.Normal
                : ProcessWindowStyle.Hidden,
        };
        if (healthToken is not null)
        {
            if (activeDeadlineTickCount64 is null)
            {
                throw new ArgumentException(
                    "Personal release health requires its inherited active deadline.");
            }
            startInfo.ArgumentList.Add("--release-health-token");
            startInfo.ArgumentList.Add(healthToken);
            startInfo.ArgumentList.Add(PersonalHealthBudgetV1.ActiveDeadlineArgument);
            startInfo.ArgumentList.Add(activeDeadlineTickCount64.Value.ToString(
                System.Globalization.CultureInfo.InvariantCulture));
        }
        else if (restartHandoff is not null)
        {
            foreach (var argument in restartHandoff.ToArguments())
            {
                startInfo.ArgumentList.Add(argument);
            }
        }
        else if (backgroundStartup)
        {
            startInfo.ArgumentList.Add(BackgroundStartupCommand);
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
        var process = executable.Start(startInfo);
        _diagnostics.Mark("child_started", childProcessId: process.Id);
        return process;
    }

    private static void RequireActiveBundle(PersonalInstalledReleaseSetReference current)
    {
        var actual = Path.TrimEndingDirectorySeparator(Path.GetFullPath(AppContext.BaseDirectory));
        var expected = Path.TrimEndingDirectorySeparator(
            Path.GetFullPath(current.ClientBundle.Directory));
        if (string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }
        if (!string.Equals(
                Environment.GetEnvironmentVariable(
                    "ENSOU_DSH_ALLOW_DEVELOPMENT_LAUNCHER"),
                "1",
                StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "Versioned personal Bootstrapper is not running from the active client bundle.");
        }
    }
}
