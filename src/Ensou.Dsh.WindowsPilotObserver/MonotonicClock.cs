using System.Diagnostics;

namespace Ensou.Dsh.WindowsPilotObserver;

public interface IMonotonicClock
{
    long Milliseconds { get; }
}

public sealed class StopwatchMonotonicClock : IMonotonicClock
{
    private readonly Stopwatch stopwatch = Stopwatch.StartNew();

    public long Milliseconds => stopwatch.ElapsedMilliseconds;
}
