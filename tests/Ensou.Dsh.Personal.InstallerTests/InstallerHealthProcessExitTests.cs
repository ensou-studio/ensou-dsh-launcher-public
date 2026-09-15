using Ensou.Dsh.Personal.Installer;
using InstallerProgram = Ensou.Dsh.Personal.Installer.PersonalInstallerHealthProcessExit;

namespace Ensou.Dsh.Personal.InstallerTests;

internal static class InstallerHealthProcessExitTests
{
    internal static async Task RunAsync()
    {
        var timeout = new TimeoutException("synthetic health timeout");
        var killed = 0;
        var waited = 0;
        var retained = 0;
        await InstallerProgram.RequireConfirmedHealthExitAsync(timeout, () => true,
            () => killed++, _ => { waited++; return Task.CompletedTask; }, () => retained++);
        Require(killed == 0 && waited == 0 && retained == 0);

        // Exit can race Kill or the wait. A positive final observation is authoritative.
        foreach (var failureAt in new[] { "none", "kill", "wait" })
        {
            var exited = false;
            await InstallerProgram.RequireConfirmedHealthExitAsync(timeout, () => exited,
                () =>
                {
                    exited = true;
                    if (failureAt == "kill") throw new InvalidOperationException("synthetic exit race");
                },
                token => failureAt == "wait"
                    ? Task.FromException(new IOException("synthetic wait failure after exit"))
                    : Task.CompletedTask,
                () => throw new InvalidOperationException("Confirmed exit must not retain ownership."));
        }

        foreach (var failureAt in new[] { "kill", "wait", "observation", "false-wait-success" })
        {
            var retainCalls = 0;
            Exception? failure = null;
            try
            {
                await InstallerProgram.RequireConfirmedHealthExitAsync(timeout,
                    () => failureAt == "observation"
                        ? throw new IOException("synthetic observation failure") : false,
                    () =>
                    {
                        if (failureAt == "kill") throw new System.ComponentModel.Win32Exception(5);
                    },
                    token => failureAt == "wait"
                        ? Task.FromException(new OperationCanceledException(token))
                        : Task.CompletedTask,
                    () => retainCalls++);
            }
            catch (PersonalInstallerHealthExitUnconfirmedException exception) { failure = exception; }
            Require(failure is not null && retainCalls == 1);
            var unconfirmed = failure ?? throw new InvalidOperationException("Unconfirmed failure was missing.");
            Require(((AggregateException)unconfirmed.InnerException!).InnerExceptions.Contains(timeout));
            foreach (var guardedFailure in new[]
                     { unconfirmed, new InvalidOperationException("synthetic migration wrapper", unconfirmed), new AggregateException(unconfirmed) })
            {
                var rollbackCalls = 0;
                try
                {
                    await InstallerProgram.RollbackOrAggregateAsync(_ =>
                    {
                        rollbackCalls++;
                        return Task.CompletedTask;
                    }, guardedFailure, abandonPendingCandidate: true);
                    throw new Exception("Unconfirmed health failure unexpectedly returned.");
                }
                catch (Exception exception) when (ReferenceEquals(exception, guardedFailure)) { }
                Require(rollbackCalls == 0);
            }
        }

        var confirmedRollbackCalls = 0;
        try
        {
            await InstallerProgram.RollbackOrAggregateAsync(abandon =>
            {
                Require(abandon);
                confirmedRollbackCalls++;
                return Task.CompletedTask;
            }, timeout, abandonPendingCandidate: true);
        }
        catch (TimeoutException exception) when (ReferenceEquals(exception, timeout)) { }
        Require(confirmedRollbackCalls == 1);
    }

    private static void Require(bool condition)
    {
        if (!condition) throw new InvalidOperationException("Installer exact health-process exit assertion failed.");
    }
}
