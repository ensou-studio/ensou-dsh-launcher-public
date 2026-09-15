using System.Diagnostics;
using System.Text.Json;

namespace Ensou.Dsh.Personal.InstallerTests;

// Test-only bounded diagnostics: no exception text, paths, tokens, or argument values.
internal sealed class InstallerFixtureHealthTrace(bool reportSuccess) : IDisposable
{
    private static readonly HashSet<string> Phases = new(StringComparer.Ordinal)
    {
        "gate_budget_armed", "gate_pointer_begin", "gate_pointer_end",
        "gate_healthy_pointer_begin", "gate_healthy_pointer_end",
        "gate_security_begin", "gate_security_end", "gate_probe_begin", "gate_probe_end",
        "gate_probe_nonzero", "gate_signal_consume_begin", "gate_signal_consume_end",
        "gate_exception", "gate_budget_cancelled", "gate_caller_cancelled",
        "gate_rollback_begin", "gate_rollback_end", "gate_rollback_exception",
        "fixture_callback_begin", "fixture_pointer_begin", "fixture_pointer_end",
        "fixture_home_lease_begin", "fixture_home_lease_acquired", "fixture_attempt_admitted",
        "fixture_session_released", "fixture_attempt_completed", "fixture_home_released",
        "fixture_signal_written",
    };
    private readonly Stopwatch _elapsed = Stopwatch.StartNew();
    private readonly List<string> _records = [];
    public bool Succeeded { get; set; }

    public void Mark(string phase, Exception? exception = null) => Add(phase, exception, null);

    public void MarkCancellation(string phase, CancellationToken token) =>
        Add(phase, null, token.IsCancellationRequested);

    private void Add(string phase, Exception? exception, bool? cancelled)
    {
        try
        {
            if (_records.Count >= 64) return;
            _records.Add(JsonSerializer.Serialize(new
            {
                schemaVersion = 1,
                @event = "installer-fixture-health",
                phase = Phases.Contains(phase) ? phase : "unknown",
                elapsedMilliseconds = _elapsed.ElapsedMilliseconds,
                cancelled,
                exceptionType = exception?.GetType().Name,
                exceptionHResult = exception?.HResult,
                // Metadata method names only; never StackTrace.ToString()/exception.Message.
                methods = exception is null ? null : new StackTrace(exception, false)
                    .GetFrames().Take(6).Select(frame => frame.GetMethod()?.Name).ToArray(),
            }));
        }
        catch { /* Diagnostics must not mask the original fixture result. */ }
    }

    public void Dispose()
    {
        if (Succeeded && !reportSuccess) return;
        try
        {
            foreach (var record in _records) Console.Error.WriteLine(record);
            Console.Error.Flush();
        }
        catch { /* Diagnostics must not mask the original fixture result. */ }
    }
}
