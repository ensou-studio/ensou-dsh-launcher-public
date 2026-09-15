using Ensou.Dsh.UpdateEngine;

namespace Ensou.Dsh.Personal.Installer;

internal static class PersonalInstallerHealthProcessExit
{
    internal static async Task RollbackOrAggregateAsync(
        Func<bool, Task> rollback,
        Exception failure,
        bool abandonPendingCandidate)
    {
        // No journal, stable Stub, pointer, or home restoration is admitted while
        // the previous health process might still own those resources.
        if (ContainsUnconfirmedHealthExit(failure))
            System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(failure).Throw();
        try
        {
            await rollback(abandonPendingCandidate).ConfigureAwait(false);
        }
        catch (Exception rollbackFailure)
        {
            throw new AggregateException(
                "Personal installation failed and its durable rollback could not be certified.",
                failure,
                rollbackFailure);
        }
        System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(failure).Throw();
    }

    private static bool ContainsUnconfirmedHealthExit(Exception failure) =>
        failure is PersonalInstallerHealthExitUnconfirmedException
        || failure is AggregateException aggregate
            && aggregate.InnerExceptions.Any(ContainsUnconfirmedHealthExit)
        || failure.InnerException is { } inner && ContainsUnconfirmedHealthExit(inner);

    internal static async Task RequireConfirmedHealthExitAsync(
        Exception failure,
        Func<bool> hasExited,
        Action kill,
        Func<CancellationToken, Task> waitForExit,
        Action retainUnconfirmedProcess)
    {
        var cleanupFailures = new List<Exception>();
        try { if (hasExited()) return; }
        catch (Exception exception) { cleanupFailures.Add(exception); }
        try { kill(); }
        catch (Exception exception) { cleanupFailures.Add(exception); }
        try
        {
            using var exitTimeout = new CancellationTokenSource(PersonalHealthBudgetV1.OutputDrainTimeout);
            await waitForExit(exitTimeout.Token).ConfigureAwait(false);
        }
        catch (Exception exception) { cleanupFailures.Add(exception); }
        try { if (hasExited()) return; }
        catch (Exception exception) { cleanupFailures.Add(exception); }

        retainUnconfirmedProcess();
        throw new PersonalInstallerHealthExitUnconfirmedException(
            new AggregateException(new[] { failure }.Concat(cleanupFailures)));
    }
}

internal sealed class PersonalInstallerHealthExitUnconfirmedException(Exception innerException)
    : InvalidOperationException(
        "PERSONAL_INSTALLER_HEALTH_EXIT_UNCONFIRMED: The exact health process exit could not be confirmed. Installation state was retained; rollback is not permitted until that process has stopped.",
        innerException);
