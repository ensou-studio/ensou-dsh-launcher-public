using Ensou.Dsh.UpdateEngine;

namespace Ensou.Dsh.Personal.UpdateTests;

internal static class PersonalHealthBudgetTests
{
    internal static IReadOnlyList<(string Name, Func<Task> Run)> Cases { get; } =
    [
        ("personal health budgets remain exact and finite", ExactBudgetsAsync),
        ("personal health deadline roundtrip never resets", DeadlineRoundtripAsync),
        ("personal health deadline rejects extension and expiry", DeadlineBoundsAsync),
        ("personal installed tree hash observes chunk cancellation", ChunkCancellationAsync),
        ("personal installed tree hash preserves SHA256 for empty and multichunk streams", HashCompatibilityAsync),
    ];

    private static Task ExactBudgetsAsync()
    {
        RequireEqual(TimeSpan.FromSeconds(600), PersonalHealthBudgetV1.ActiveHealthEnvelope);
        RequireEqual(TimeSpan.FromSeconds(765), PersonalHealthBudgetV1.OverallHealthEnvelope);
        RequireEqual(TimeSpan.FromSeconds(120), PersonalHealthBudgetV1.FailureCleanupTimeout);
        RequireEqual(TimeSpan.FromSeconds(5), PersonalHealthBudgetV1.OutputDrainTimeout);
        RequireEqual(
            PersonalHealthBudgetV1.ActiveHealthEnvelope,
            PersonalBootstrapHealthGate.ColdStartTimeout);
        return Task.CompletedTask;
    }

    private static Task DeadlineRoundtripAsync()
    {
        var overall = PersonalHealthBudgetV1.CreateDeadlineTickCount64(
            PersonalHealthBudgetV1.OverallHealthEnvelope);
        var active = PersonalHealthBudgetV1.ConstrainDeadlineTickCount64(
            overall,
            PersonalHealthBudgetV1.ActiveHealthEnvelope);
        var parsed = PersonalHealthBudgetV1.ParseDeadlineTickCount64(
            active.ToString(System.Globalization.CultureInfo.InvariantCulture),
            PersonalHealthBudgetV1.ActiveHealthEnvelope);
        RequireEqual(active, parsed);
        if (parsed > overall)
        {
            throw new InvalidOperationException(
                "The inherited active deadline exceeded its outer deadline.");
        }
        var remaining = PersonalHealthBudgetV1.GetRemaining(
            parsed,
            PersonalHealthBudgetV1.ActiveHealthEnvelope);
        if (remaining <= TimeSpan.Zero
            || remaining > PersonalHealthBudgetV1.ActiveHealthEnvelope)
        {
            throw new InvalidOperationException(
                "The inherited active deadline was reset or became non-finite.");
        }
        return Task.CompletedTask;
    }

    private static Task DeadlineBoundsAsync()
    {
        RequireThrows<InvalidDataException>(() =>
            PersonalHealthBudgetV1.ParseDeadlineTickCount64(
                checked(
                    Environment.TickCount64
                    + (long)PersonalHealthBudgetV1.ActiveHealthEnvelope.TotalMilliseconds
                    + 5_000L)
                    .ToString(System.Globalization.CultureInfo.InvariantCulture),
                PersonalHealthBudgetV1.ActiveHealthEnvelope));
        RequireThrows<TimeoutException>(() =>
            PersonalHealthBudgetV1.ParseDeadlineTickCount64(
                Environment.TickCount64.ToString(
                    System.Globalization.CultureInfo.InvariantCulture),
                PersonalHealthBudgetV1.ActiveHealthEnvelope));
        RequireThrows<ArgumentException>(() =>
            PersonalHealthBudgetV1.ParseDeadlineTickCount64(
                "+123",
                PersonalHealthBudgetV1.ActiveHealthEnvelope));
        return Task.CompletedTask;
    }

    private static Task ChunkCancellationAsync()
    {
        using var cancellation = new CancellationTokenSource();
        using var stream = new CancellingReadStream(cancellation);
        RequireThrows<OperationCanceledException>(() =>
            PersonalReleaseArtifactInstaller.ComputeSha256(
                stream,
                cancellation.Token));
        RequireEqual(1, stream.ReadCount);
        return Task.CompletedTask;
    }

    private static Task HashCompatibilityAsync()
    {
        foreach (var length in new[] { 0, 1, 128 * 1024, 384 * 1024 + 17 })
        {
            var bytes = Enumerable.Range(0, length).Select(index => (byte)(index % 251)).ToArray();
            using var stream = new MemoryStream(bytes, writable: false);
            RequireEqual(Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(bytes)),
                PersonalReleaseArtifactInstaller.ComputeSha256(stream, CancellationToken.None));
        }
        return Task.CompletedTask;
    }

    private static void RequireEqual<T>(T expected, T actual)
        where T : IEquatable<T>
    {
        if (!expected.Equals(actual))
        {
            throw new InvalidOperationException(
                $"Expected '{expected}', got '{actual}'.");
        }
    }

    private static void RequireThrows<TException>(Action action)
        where TException : Exception
    {
        try
        {
            action();
        }
        catch (TException)
        {
            return;
        }
        throw new InvalidOperationException(
            $"Expected {typeof(TException).Name}.");
    }

    private sealed class CancellingReadStream : Stream
    {
        private readonly CancellationTokenSource _cancellation;

        internal CancellingReadStream(CancellationTokenSource cancellation) =>
            _cancellation = cancellation;

        internal int ReadCount { get; private set; }
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            ReadCount++;
            buffer[offset] = 0x5a;
            _cancellation.Cancel();
            return 1;
        }

        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();
    }
}
