using System.Diagnostics;
using System.Text.Json;

namespace Ensou.Dsh.Contracts;

/// <summary>Best-effort, content-free diagnostics for explicitly admitted development health probes.</summary>
public sealed class HealthProbeDiagnostics
{
    private readonly string _component;
    private readonly bool _enabled;
    private readonly long _started = Stopwatch.GetTimestamp();

    public HealthProbeDiagnostics(string component, bool enabled)
    {
        _component = component;
        _enabled = enabled && IsIdentifier(component);
    }

    public void Mark(
        string phase,
        Exception? exception = null,
        int? childProcessId = null,
        int? exitCode = null,
        long? budgetMilliseconds = null)
    {
        if (!_enabled || !IsIdentifier(phase)) return;
        try
        {
            var record = new Dictionary<string, object?>
            {
                ["schemaVersion"] = 1,
                ["event"] = "personal-health-trace",
                ["component"] = _component,
                ["phase"] = phase,
                ["pid"] = Environment.ProcessId,
                ["utc"] = DateTimeOffset.UtcNow,
                ["tickCount64"] = Environment.TickCount64,
                ["elapsedMilliseconds"] = Stopwatch.GetElapsedTime(_started).TotalMilliseconds,
            };
            if (childProcessId is not null) record["childProcessId"] = childProcessId;
            if (exitCode is not null) record["exitCode"] = exitCode;
            if (budgetMilliseconds is not null) record["budgetMilliseconds"] = budgetMilliseconds;
            if (exception is not null)
            {
                record["exceptionType"] = exception.GetType().Name;
                record["hresult"] = exception.HResult;
                if (exception.InnerException is { } inner)
                {
                    record["innerExceptionType"] = inner.GetType().Name;
                    record["innerHresult"] = inner.HResult;
                }
            }
            // Never serialize exception objects, messages, stacks, paths, or command arguments.
            Console.Error.WriteLine(JsonSerializer.Serialize(record));
            Console.Error.Flush();
        }
        catch
        {
            // Diagnostic transport failure must not change admission, cleanup, or exit behavior.
        }
    }

    private static bool IsIdentifier(string? value) =>
        value is { Length: > 0 and <= 64 }
        && value.All(character => character is >= 'a' and <= 'z'
            or >= 'A' and <= 'Z' or >= '0' and <= '9' or '_' or '-');
}
