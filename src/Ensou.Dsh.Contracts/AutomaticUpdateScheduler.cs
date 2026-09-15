namespace Ensou.Dsh.Contracts;

public enum AutomaticUpdateTrigger
{
    Startup,
    Reconnect,
    Periodic,
    Retry
}

public enum AutomaticUpdatePipelineResult
{
    Success,
    DeferredBusy,
    Failure
}

public sealed record AutomaticUpdateSchedulerOptions
{
    public TimeSpan Period { get; init; } = TimeSpan.FromMinutes(5);
    public TimeSpan InitialFailureBackoff { get; init; } = TimeSpan.FromSeconds(15);
    public TimeSpan MaximumFailureBackoff { get; init; } = TimeSpan.FromMinutes(5);
    public TimeSpan BusyBackoff { get; init; } = TimeSpan.FromSeconds(15);
}

/// <summary>
/// Coalesces unattended update checks. The injected pipeline remains responsible for
/// trust, authorization, leases, download, installation, and process coordination.
/// </summary>
public sealed class AutomaticUpdateScheduler : IDisposable, IAsyncDisposable
{
    private readonly Func<AutomaticUpdateTrigger, CancellationToken, Task<AutomaticUpdatePipelineResult>> _pipeline;
    private readonly AutomaticUpdateSchedulerOptions _options;
    private readonly TimeProvider _timeProvider;
    private readonly CancellationTokenSource _stopping = new();
    private readonly SemaphoreSlim _signal = new(0, 1);
    private readonly object _lifecycle = new();
    private readonly Task _worker;
    private ITimer? _timer;
    private int _pending;
    private int _started;
    private int _disposed;
    private AutomaticUpdateTrigger _latestTrigger;

    public Task Completion => _worker;
    public Exception? UnexpectedWorkerException { get; private set; }
    public Exception? CancellationCallbackException { get; private set; }

    public AutomaticUpdateScheduler(
        Func<AutomaticUpdateTrigger, CancellationToken, Task<AutomaticUpdatePipelineResult>> pipeline,
        AutomaticUpdateSchedulerOptions? options = null,
        TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(pipeline);
        _pipeline = pipeline;
        _options = options ?? new AutomaticUpdateSchedulerOptions();
        _timeProvider = timeProvider ?? TimeProvider.System;
        ValidatePositive(_options.Period, nameof(_options.Period));
        ValidatePositive(_options.InitialFailureBackoff, nameof(_options.InitialFailureBackoff));
        ValidatePositive(_options.MaximumFailureBackoff, nameof(_options.MaximumFailureBackoff));
        ValidatePositive(_options.BusyBackoff, nameof(_options.BusyBackoff));
        ValidateTimerRange(_options.Period, nameof(_options.Period));
        ValidateTimerRange(_options.InitialFailureBackoff, nameof(_options.InitialFailureBackoff));
        ValidateTimerRange(_options.MaximumFailureBackoff, nameof(_options.MaximumFailureBackoff));
        ValidateTimerRange(_options.BusyBackoff, nameof(_options.BusyBackoff));
        if (_options.MaximumFailureBackoff < _options.InitialFailureBackoff)
            throw new ArgumentException("Maximum failure backoff cannot be shorter than initial failure backoff.", nameof(options));
        _worker = RunAsync();
    }

    public void Start()
    {
        lock (_lifecycle)
        {
            ThrowIfDisposed();
            if (_started != 0)
                return;
            try
            {
                _timer = _timeProvider.CreateTimer(static state =>
                    ((AutomaticUpdateScheduler)state!).Trigger(AutomaticUpdateTrigger.Periodic), this, _options.Period, _options.Period);
                _started = 1;
                TriggerLocked(AutomaticUpdateTrigger.Startup);
            }
            catch
            {
                _timer?.Dispose();
                _timer = null;
                _started = 0;
                throw;
            }
        }
    }

    public void NotifyReconnect() => Trigger(AutomaticUpdateTrigger.Reconnect);

    private void Trigger(AutomaticUpdateTrigger trigger)
    {
        lock (_lifecycle)
        {
            if (_disposed != 0 || _started == 0)
                return;
            TriggerLocked(trigger);
        }
    }

    private void TriggerLocked(AutomaticUpdateTrigger trigger)
    {
        _latestTrigger = trigger;
        if (Interlocked.Exchange(ref _pending, 1) == 0)
            _signal.Release();
    }

    private async Task RunAsync()
    {
        var failures = 0;
        try
        {
            while (true)
            {
                await _signal.WaitAsync(_stopping.Token).ConfigureAwait(false);
                Interlocked.Exchange(ref _pending, 0);
                var trigger = _latestTrigger;
                AutomaticUpdatePipelineResult result;
                try
                {
                    result = await _pipeline(trigger, _stopping.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (_stopping.IsCancellationRequested)
                {
                    break;
                }
                catch
                {
                    result = AutomaticUpdatePipelineResult.Failure;
                }

                if (result == AutomaticUpdatePipelineResult.Success)
                {
                    failures = 0;
                    continue;
                }

                var delay = result == AutomaticUpdatePipelineResult.DeferredBusy
                    ? _options.BusyBackoff
                    : FailureDelay(++failures);
                try
                {
                    await Task.Delay(delay, _timeProvider, _stopping.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (_stopping.IsCancellationRequested)
                {
                    break;
                }
                Trigger(AutomaticUpdateTrigger.Retry);
            }
        }
        catch (OperationCanceledException) when (_stopping.IsCancellationRequested) { }
        catch (Exception ex)
        {
            UnexpectedWorkerException = ex;
        }
    }

    private TimeSpan FailureDelay(int failures)
    {
        var multiplier = Math.Pow(2, Math.Min(failures - 1, 30));
        var ticks = Math.Min(_options.MaximumFailureBackoff.Ticks, _options.InitialFailureBackoff.Ticks * multiplier);
        return TimeSpan.FromTicks((long)ticks);
    }

    public void Dispose()
    {
        ITimer? timer;
        lock (_lifecycle)
        {
            if (_disposed != 0)
                return;
            _disposed = 1;
            timer = _timer;
            _timer = null;
        }
        timer?.Dispose();
        try
        {
            _stopping.Cancel(throwOnFirstException: false);
        }
        catch (Exception ex)
        {
            CancellationCallbackException = ex;
        }
    }

    public async ValueTask DisposeAsync()
    {
        Dispose();
        try { await _worker.ConfigureAwait(false); } catch { }
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);

    private static void ValidatePositive(TimeSpan value, string name)
    {
        if (value <= TimeSpan.Zero || value == Timeout.InfiniteTimeSpan)
            throw new ArgumentOutOfRangeException(name);
    }

    private static void ValidateTimerRange(TimeSpan value, string name)
    {
        if (value.TotalMilliseconds > uint.MaxValue - 1)
            throw new ArgumentOutOfRangeException(name, "Timer duration exceeds the supported range.");
    }
}
