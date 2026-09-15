using Ensou.Dsh.Launcher;

namespace Ensou.Dsh.Personal.UpdateTests;

internal static class PersonalManagedRuntimeUpdateCoordinatorTests
{
    internal static IReadOnlyList<(string Name, Func<Task> Run)> Cases { get; } =
    [
        ("Personal managed update drain restores only failed stages", RestoresOnlyFailedStagesAsync),
        ("Personal managed update drain defers unsupported running runtimes", DefersUnsupportedRuntimeAsync),
        ("Personal managed update drain preserves Host cancellation recovery", PreservesCancellationRecoveryAsync),
        ("Personal managed update drain restores deferred boundaries", RestoresAfterDeferredBoundaryAsync),
        ("Personal staged update retry never reopens the old runtime", PersonalStagedRetryNeverReopensOldRuntimeAsync),
    ];

    internal static async Task RunAsync()
    {
        foreach (var (_, run) in Cases)
        {
            await run().ConfigureAwait(false);
        }
    }

    internal static async Task RestoresOnlyFailedStagesAsync()
    {
        var events = new List<string>();
        var drained = false;
        var coordinator = Create(
            supportsManagedUpdate: true,
            ownsRuntime: () => true,
            drain: (_, _) =>
            {
                events.Add("drain");
                drained = true;
                return Task.CompletedTask;
            },
            restore: _ =>
            {
                events.Add("restore");
                return Task.CompletedTask;
            });

        await AssertThrowsAsync<InvalidDataException>(async () =>
        {
            await coordinator.RunAsync(
                _ =>
                {
                    AssertTrue(drained);
                    return Task.FromException<bool>(new InvalidDataException("stage failed"));
                });
        });
        AssertSequence(["drain", "restore"], events);

        events.Clear();
        drained = false;
        var result = await coordinator.RunAsync(_ =>
        {
            AssertTrue(drained);
            events.Add("stage");
            return Task.FromResult(true);
        });
        AssertEqual(PersonalManagedRuntimeUpdateDisposition.Staged, result);
        AssertSequence(["drain", "stage"], events);
    }

    internal static async Task DefersUnsupportedRuntimeAsync()
    {
        var invoked = false;
        var coordinator = Create(
            supportsManagedUpdate: false,
            ownsRuntime: () => true,
            drain: (_, _) =>
            {
                invoked = true;
                return Task.CompletedTask;
            },
            restore: _ => throw new InvalidOperationException("unexpected restore"));

        var result = await coordinator.RunAsync(_ =>
        {
            invoked = true;
            return Task.FromResult(true);
        });
        AssertEqual(PersonalManagedRuntimeUpdateDisposition.DeferredUnsupportedRuntime, result);
        AssertFalse(invoked);
    }

    internal static async Task PreservesCancellationRecoveryAsync()
    {
        var restored = false;
        var coordinator = Create(
            supportsManagedUpdate: true,
            ownsRuntime: () => true,
            drain: (_, cancellationToken) => Task.FromCanceled(cancellationToken),
            restore: _ =>
            {
                restored = true;
                return Task.CompletedTask;
            });
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await AssertThrowsAsync<OperationCanceledException>(async () =>
        {
            await coordinator.RunAsync(
                _ => Task.FromResult(true), cancellation.Token);
        });
        AssertFalse(restored);
    }

    private static PersonalManagedRuntimeUpdateCoordinator Create(
        bool supportsManagedUpdate,
        Func<bool> ownsRuntime,
        Func<Guid, CancellationToken, Task> drain,
        Func<CancellationToken, Task> restore) => new(
            supportsManagedUpdate,
            ownsRuntime,
            drain,
            restore);

    private static async Task RestoresAfterDeferredBoundaryAsync()
    {
        var restored = false;
        var coordinator = Create(
            supportsManagedUpdate: true,
            ownsRuntime: () => true,
            drain: (_, _) => Task.CompletedTask,
            restore: _ =>
            {
                restored = true;
                return Task.CompletedTask;
            });
        var result = await coordinator.RunAsync(_ => Task.FromResult(false));
        AssertEqual(PersonalManagedRuntimeUpdateDisposition.DeferredStageBoundary, result);
        AssertTrue(restored);
    }

    // Test boundary: coordinator-only repeated-call semantics (no App restart handoff/scheduler involved).
    private static async Task PersonalStagedRetryNeverReopensOldRuntimeAsync()
    {
        var events = new List<string>();
        var runtimeOwned = true;
        var drainCount = 0;
        var restoreCount = 0;

        var coordinator = Create(
            supportsManagedUpdate: true,
            ownsRuntime: () => runtimeOwned,
            drain: (_, _) =>
            {
                events.Add("drain");
                drainCount++;
                runtimeOwned = false;
                return Task.CompletedTask;
            },
            restore: _ =>
            {
                restoreCount++;
                return Task.CompletedTask;
            });

        var first = await coordinator.RunAsync(_ =>
        {
            events.Add("stage");
            return Task.FromResult(true);
        });
        AssertEqual(PersonalManagedRuntimeUpdateDisposition.Staged, first);

        var second = await coordinator.RunAsync(_ =>
        {
            events.Add("retry-boundary");
            return Task.FromResult(true);
        });
        AssertEqual(PersonalManagedRuntimeUpdateDisposition.Staged, second);

        AssertSequence(["drain", "stage", "retry-boundary"], events);
        AssertEqual(1, drainCount);
        AssertEqual(0, restoreCount);
        AssertFalse(runtimeOwned);

        var third = await coordinator.RunAsync(_ =>
        {
            events.Add("retry-deferred");
            return Task.FromResult(false);
        });
        AssertEqual(PersonalManagedRuntimeUpdateDisposition.DeferredStageBoundary, third);
        AssertSequence(["drain", "stage", "retry-boundary", "retry-deferred"], events);
        AssertEqual(1, drainCount);
        AssertEqual(0, restoreCount);
        AssertFalse(runtimeOwned);
    }

    private static async Task AssertThrowsAsync<TException>(Func<Task> action)
        where TException : Exception
    {
        try
        {
            await action().ConfigureAwait(false);
        }
        catch (TException)
        {
            return;
        }
        throw new InvalidOperationException($"Expected {typeof(TException).Name}.");
    }

    private static void AssertFalse(bool value)
    {
        if (value) throw new InvalidOperationException("Expected false.");
    }

    private static void AssertTrue(bool value)
    {
        if (!value) throw new InvalidOperationException("Expected true.");
    }

    private static void AssertEqual<T>(T expected, T actual)
        where T : notnull
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
            throw new InvalidOperationException("Expected values to match.");
    }

    private static void AssertSequence(IReadOnlyList<string> expected, IReadOnlyList<string> actual)
    {
        if (!expected.SequenceEqual(actual, StringComparer.Ordinal))
            throw new InvalidOperationException("Expected event sequence to match.");
    }
}
