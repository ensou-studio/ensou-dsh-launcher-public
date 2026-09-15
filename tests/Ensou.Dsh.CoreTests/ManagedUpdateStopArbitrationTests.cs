using Ensou.Dsh.Host;

namespace Ensou.Dsh.CoreTests;

internal static partial class Program
{
    private static Task ManagedUpdatePriorityPreemptsAndOrdersNewWaitsAsync()
    {
        var arbitration = new ManagedUpdateStopArbitration();
        using var active = arbitration.BeginManagedWait();
        using var priority = arbitration.BeginPriorityStop();
        AssertTrue(active.IsPriorityCancellationRequested);
        active.Dispose();
        AssertManagedUpdateArbitrationThrows<OperationCanceledException>(
            () => arbitration.BeginManagedWait());

        priority.Dispose();
        using var successor = arbitration.BeginManagedWait();
        AssertFalse(successor.IsPriorityCancellationRequested);
        return Task.CompletedTask;
    }

    private static Task ManagedUpdateOrdinaryCancellationIsNotPriorityAsync()
    {
        var arbitration = new ManagedUpdateStopArbitration();
        using var active = arbitration.BeginManagedWait();
        using var ordinaryCancellation = new CancellationTokenSource();
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(
            ordinaryCancellation.Token,
            active.Token);
        ordinaryCancellation.Cancel();

        AssertTrue(linked.IsCancellationRequested);
        AssertFalse(active.IsPriorityCancellationRequested);
        return Task.CompletedTask;
    }

    private static Task ManagedUpdateRetiredLeaseCannotClearSuccessorAsync()
    {
        var arbitration = new ManagedUpdateStopArbitration();
        var retired = arbitration.BeginManagedWait();
        retired.Dispose();
        using var successor = arbitration.BeginManagedWait();
        retired.Dispose();
        AssertFalse(successor.IsPriorityCancellationRequested);

        using var priority = arbitration.BeginPriorityStop();
        AssertTrue(successor.IsPriorityCancellationRequested);
        return Task.CompletedTask;
    }

    private static void AssertManagedUpdateArbitrationThrows<TException>(Action action)
        where TException : Exception
    {
        try { action(); }
        catch (TException) { return; }
        throw new InvalidOperationException($"Expected {typeof(TException).Name}.");
    }
}
