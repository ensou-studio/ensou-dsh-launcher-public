namespace Ensou.Dsh.WindowsPilotObserver;

public static class ObservationTiming
{
    public const int LightweightMaximumGapMilliseconds = 750;

    public static long BeginAfterPreflight(long currentMonotonicMilliseconds) =>
        currentMonotonicMilliseconds;

    public static long Elapsed(long startMonotonicMilliseconds, long currentMonotonicMilliseconds) =>
        Math.Max(0, currentMonotonicMilliseconds - startMonotonicMilliseconds);

    public static bool IsLightweightGapAccepted(long previousElapsed, long currentElapsed) =>
        currentElapsed >= previousElapsed
        && currentElapsed - previousElapsed <= LightweightMaximumGapMilliseconds;

    public static bool IsFullGapAccepted(long previousElapsed, long currentElapsed) =>
        currentElapsed >= previousElapsed
        && currentElapsed - previousElapsed <= ObservationContract.FullSnapshotMaximumIntervalMilliseconds;
}
