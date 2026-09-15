using Ensou.Dsh.Contracts;

var tests = new (string Name, Func<Task> Run)[]
{
    ("startup-periodic-reconnect", StartupPeriodicReconnectAsync),
    ("single-flight-coalesces", SingleFlightAsync),
    ("busy-and-failure-retry", RetryAsync),
    ("pipeline-exception-contained", ExceptionContainedAsync),
    ("dispose-cancels", DisposeCancelsAsync)
    ,("prestart-and-repeated-start", PrestartAndRepeatedStartAsync)
    ,("concurrent-dispose-reconnect", ConcurrentDisposeReconnectAsync)
    ,("invalid-options", InvalidOptionsAsync)
    ,("failure-backoff-cap", BackoffCapAsync)
    ,("cancellation-callback-reentry", CancellationCallbackReentryAsync)
};

foreach (var test in tests)
{
    await test.Run();
    Console.WriteLine($"PASS {test.Name}");
}

static AutomaticUpdateSchedulerOptions Options() => new()
{
    Period = TimeSpan.FromMinutes(5), BusyBackoff = TimeSpan.FromSeconds(2),
    InitialFailureBackoff = TimeSpan.FromSeconds(3), MaximumFailureBackoff = TimeSpan.FromSeconds(6)
};

static async Task StartupPeriodicReconnectAsync()
{
    var clock = new ManualTimeProvider();
    var calls = new System.Collections.Concurrent.ConcurrentQueue<AutomaticUpdateTrigger>();
    await using var scheduler = new AutomaticUpdateScheduler((t, _) => { calls.Enqueue(t); return Task.FromResult(AutomaticUpdatePipelineResult.Success); }, Options(), clock);
    scheduler.Start();
    await EventuallyAsync(() => calls.Count == 1);
    scheduler.NotifyReconnect();
    await EventuallyAsync(() => calls.Count == 2);
    clock.Advance(TimeSpan.FromMinutes(5));
    await EventuallyAsync(() => calls.Count == 3);
    Assert(calls.Contains(AutomaticUpdateTrigger.Startup) && calls.Contains(AutomaticUpdateTrigger.Reconnect) && calls.Contains(AutomaticUpdateTrigger.Periodic), "missing trigger");
}

static async Task SingleFlightAsync()
{
    var clock = new ManualTimeProvider();
    var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
    var active = 0; var maximum = 0; var calls = 0;
    await using var scheduler = new AutomaticUpdateScheduler(async (_, ct) => { Interlocked.Increment(ref calls); var current = Interlocked.Increment(ref active); Interlocked.Exchange(ref maximum, Math.Max(Volatile.Read(ref maximum), current)); await gate.Task.WaitAsync(ct); Interlocked.Decrement(ref active); return AutomaticUpdatePipelineResult.Success; }, Options(), clock);
    scheduler.Start(); await EventuallyAsync(() => Volatile.Read(ref calls) == 1);
    scheduler.NotifyReconnect(); scheduler.NotifyReconnect(); clock.Advance(TimeSpan.FromMinutes(5));
    gate.SetResult(); await EventuallyAsync(() => Volatile.Read(ref calls) == 2);
    Assert(Volatile.Read(ref maximum) == 1 && Volatile.Read(ref calls) == 2, "pipeline overlapped or triggers did not coalesce");
}

static async Task RetryAsync()
{
    var clock = new ManualTimeProvider();
    var results = new Queue<AutomaticUpdatePipelineResult>([AutomaticUpdatePipelineResult.DeferredBusy, AutomaticUpdatePipelineResult.Failure, AutomaticUpdatePipelineResult.Success]);
    var calls = 0;
    await using var scheduler = new AutomaticUpdateScheduler((_, _) => { Interlocked.Increment(ref calls); return Task.FromResult(results.Dequeue()); }, Options(), clock);
    scheduler.Start(); await EventuallyAsync(() => Volatile.Read(ref calls) == 1);
    await EventuallyAsync(() => clock.ActiveOneShotTimers == 1);
    clock.Advance(TimeSpan.FromSeconds(2)); await EventuallyAsync(() => Volatile.Read(ref calls) == 2);
    await EventuallyAsync(() => clock.ActiveOneShotTimers == 1);
    clock.Advance(TimeSpan.FromSeconds(3)); await EventuallyAsync(() => Volatile.Read(ref calls) == 3);
}

static async Task ExceptionContainedAsync()
{
    var clock = new ManualTimeProvider(); var calls = 0;
    await using var scheduler = new AutomaticUpdateScheduler((_, _) => { var count = Interlocked.Increment(ref calls); return count == 1 ? throw new InvalidOperationException("test") : Task.FromResult(AutomaticUpdatePipelineResult.Success); }, Options(), clock);
    scheduler.Start(); await EventuallyAsync(() => Volatile.Read(ref calls) == 1);
    await EventuallyAsync(() => clock.ActiveOneShotTimers == 1);
    clock.Advance(TimeSpan.FromSeconds(3)); await EventuallyAsync(() => Volatile.Read(ref calls) == 2);
}

static async Task DisposeCancelsAsync()
{
    var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
    var cancelled = 0;
    var scheduler = new AutomaticUpdateScheduler(async (_, ct) => { entered.SetResult(); try { await Task.Delay(Timeout.InfiniteTimeSpan, ct); } catch (OperationCanceledException) { Interlocked.Exchange(ref cancelled, 1); throw; } return AutomaticUpdatePipelineResult.Success; });
    scheduler.Start(); await entered.Task.WaitAsync(TimeSpan.FromSeconds(2)); await scheduler.DisposeAsync();
    Assert(Volatile.Read(ref cancelled) == 1, "dispose did not cancel pipeline");
}

static async Task PrestartAndRepeatedStartAsync()
{
    var clock = new ManualTimeProvider(); var calls = 0;
    await using var scheduler = new AutomaticUpdateScheduler((_, _) => { Interlocked.Increment(ref calls); return Task.FromResult(AutomaticUpdatePipelineResult.Success); }, Options(), clock);
    scheduler.NotifyReconnect(); await Task.Delay(20); Assert(Volatile.Read(ref calls) == 0, "pre-start reconnect ran pipeline");
    scheduler.Start(); scheduler.Start(); await EventuallyAsync(() => Volatile.Read(ref calls) == 1);
    Assert(clock.PeriodicTimers == 1, "repeated start created another timer");
}

static async Task ConcurrentDisposeReconnectAsync()
{
    var scheduler = new AutomaticUpdateScheduler((_, _) => Task.FromResult(AutomaticUpdatePipelineResult.Success));
    scheduler.Start();
    var reconnects = Task.Run(() => Parallel.For(0, 1000, _ => scheduler.NotifyReconnect()));
    var disposals = Task.WhenAll(Enumerable.Range(0, 8).Select(_ => scheduler.DisposeAsync().AsTask()));
    await Task.WhenAll(reconnects, disposals);
    Assert(scheduler.Completion.IsCompletedSuccessfully && scheduler.UnexpectedWorkerException is null, "dispose race faulted worker");
}

static Task InvalidOptionsAsync()
{
    AssertThrows(() => new AutomaticUpdateScheduler((_, _) => Task.FromResult(AutomaticUpdatePipelineResult.Success), new() { Period = TimeSpan.Zero }));
    AssertThrows(() => new AutomaticUpdateScheduler((_, _) => Task.FromResult(AutomaticUpdatePipelineResult.Success), new() { Period = TimeSpan.FromDays(60) }));
    AssertThrows(() => new AutomaticUpdateScheduler((_, _) => Task.FromResult(AutomaticUpdatePipelineResult.Success), new() { InitialFailureBackoff = TimeSpan.FromMinutes(2), MaximumFailureBackoff = TimeSpan.FromMinutes(1) }));
    return Task.CompletedTask;
}

static async Task BackoffCapAsync()
{
    var clock = new ManualTimeProvider(); var calls = 0;
    await using var scheduler = new AutomaticUpdateScheduler((_, _) => { Interlocked.Increment(ref calls); return Task.FromResult(AutomaticUpdatePipelineResult.Failure); }, Options(), clock);
    scheduler.Start(); await EventuallyAsync(() => Volatile.Read(ref calls) == 1);
    foreach (var seconds in new[] { 3, 6, 6 })
    {
        await EventuallyAsync(() => clock.ActiveOneShotTimers == 1);
        var expected = Volatile.Read(ref calls) + 1;
        clock.Advance(TimeSpan.FromSeconds(seconds));
        await EventuallyAsync(() => Volatile.Read(ref calls) == expected);
    }
}

static async Task CancellationCallbackReentryAsync()
{
    var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
    AutomaticUpdateScheduler? scheduler = null;
    scheduler = new AutomaticUpdateScheduler(async (_, ct) =>
    {
        using var registration = ct.Register(() =>
        {
            scheduler!.NotifyReconnect();
            throw new InvalidOperationException("injected cancellation callback");
        });
        entered.SetResult();
        await Task.Delay(Timeout.InfiniteTimeSpan, ct);
        return AutomaticUpdatePipelineResult.Success;
    });
    scheduler.Start();
    await entered.Task.WaitAsync(TimeSpan.FromSeconds(2));
    await scheduler.DisposeAsync();
    Assert(scheduler.Completion.IsCompletedSuccessfully, "worker did not complete after throwing callback");
    Assert(scheduler.CancellationCallbackException is AggregateException, "callback failure was not retained");
}

static async Task EventuallyAsync(Func<bool> condition)
{
    for (var i = 0; i < 100 && !condition(); i++) await Task.Delay(5);
    Assert(condition(), "condition timed out");
}

static void Assert(bool condition, string message)
{
    if (!condition) throw new InvalidOperationException(message);
}

static void AssertThrows(Action action)
{
    try { action(); } catch (ArgumentException) { return; }
    throw new InvalidOperationException("expected argument exception");
}

sealed class ManualTimeProvider : TimeProvider
{
    private readonly object _gate = new();
    private readonly List<ManualTimer> _timers = [];
    private long _ticks;
    public int ActiveOneShotTimers { get { lock (_gate) return _timers.Count(t => t.IsActiveOneShot); } }
    public int PeriodicTimers { get { lock (_gate) return _timers.Count(t => t.IsPeriodic); } }
    public override long TimestampFrequency => TimeSpan.TicksPerSecond;
    public override long GetTimestamp() => Interlocked.Read(ref _ticks);
    public override DateTimeOffset GetUtcNow() => DateTimeOffset.UnixEpoch + TimeSpan.FromTicks(GetTimestamp());
    public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
    {
        var timer = new ManualTimer(this, callback, state, dueTime, period);
        lock (_gate) _timers.Add(timer);
        return timer;
    }
    public void Advance(TimeSpan amount)
    {
        Interlocked.Add(ref _ticks, amount.Ticks);
        ManualTimer[] timers; lock (_gate) timers = [.. _timers];
        foreach (var timer in timers) timer.FireDue(GetTimestamp());
    }
    private sealed class ManualTimer(ManualTimeProvider owner, TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period) : ITimer
    {
        private long _next = owner.GetTimestamp() + dueTime.Ticks;
        private long _period = period.Ticks;
        private int _disposed;
        public bool IsActiveOneShot => Volatile.Read(ref _disposed) == 0 && _period == Timeout.InfiniteTimeSpan.Ticks;
        public bool IsPeriodic => Volatile.Read(ref _disposed) == 0 && _period > 0;
        public bool Change(TimeSpan dueTime, TimeSpan period) { _next = owner.GetTimestamp() + dueTime.Ticks; _period = period.Ticks; return Volatile.Read(ref _disposed) == 0; }
        public void FireDue(long now) { if (Volatile.Read(ref _disposed) == 0 && now >= _next) { if (_period > 0) _next = now + _period; else Interlocked.Exchange(ref _disposed, 1); callback(state); } }
        public void Dispose() => Interlocked.Exchange(ref _disposed, 1);
        public ValueTask DisposeAsync() { Dispose(); return ValueTask.CompletedTask; }
    }
}
