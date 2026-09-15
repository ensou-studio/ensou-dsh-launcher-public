using System.Text.Json;
using Ensou.Dsh.Contracts;

namespace Ensou.Dsh.Personal.UpdateTests;

internal static class HealthProbeDiagnosticsTests
{
    // These tests replace process-local Console.Error and must be run serially.
    internal static IReadOnlyList<(string Name, Func<Task> Run)> Cases { get; } =
    [
        ("health diagnostics emit the bounded enabled schema", EnabledAsync),
        ("disabled health diagnostics never touch the writer", DisabledAsync),
        ("health diagnostics reject invalid identifiers", InvalidIdentifiersAsync),
        ("health diagnostics swallow write and flush failures", ThrowingWriterAsync),
        ("health diagnostics exclude exception secrets", SecretFreeAsync),
    ];

    internal static async Task<int> RunAsync()
    {
        var failures = 0;
        foreach (var test in Cases)
        {
            try { await test.Run().ConfigureAwait(false); Console.WriteLine($"PASS {test.Name}"); }
            catch { failures++; Console.Error.WriteLine($"FAIL {test.Name}"); }
        }
        return failures == 0 ? 0 : 1;
    }

    private static Task EnabledAsync() => Capture(writer =>
    {
        new HealthProbeDiagnostics("stub", true).Mark("pointer_begin",
            childProcessId: 123, exitCode: 0, budgetMilliseconds: 120000);
        using var document = JsonDocument.Parse(writer.ToString());
        var value = document.RootElement;
        Require(value.GetProperty("schemaVersion").GetInt32() == 1);
        Require(value.GetProperty("event").GetString() == "personal-health-trace");
        Require(value.GetProperty("component").GetString() == "stub");
        Require(value.GetProperty("phase").GetString() == "pointer_begin");
        Require(value.GetProperty("pid").GetInt32() == Environment.ProcessId);
        Require(value.GetProperty("childProcessId").GetInt32() == 123);
        Require(value.GetProperty("exitCode").GetInt32() == 0);
        Require(value.GetProperty("budgetMilliseconds").GetInt64() == 120000);
        Require(value.GetProperty("utc").TryGetDateTimeOffset(out _));
        Require(value.GetProperty("tickCount64").TryGetInt64(out _));
        Require(value.GetProperty("elapsedMilliseconds").GetDouble() >= 0);
        Require(writer.FlushCalls == 1);
    });

    private static Task DisabledAsync()
    {
        var original = Console.Error;
        using var writer = new ThrowingWriter(throwOnFlush: false);
        try
        {
            Console.SetError(writer);
            new HealthProbeDiagnostics("launcher", false).Mark("ignored", new IOException("secret"));
            Require(writer.Calls == 0);
        }
        finally { Console.SetError(original); }
        return Task.CompletedTask;
    }

    private static Task InvalidIdentifiersAsync() => Capture(writer =>
    {
        foreach (var identifier in new[] { "", "bad.phase", "bad\nphase", "bad/phase", "非ASCII", new string('x', 65) })
        {
            new HealthProbeDiagnostics(identifier, true).Mark("valid");
            new HealthProbeDiagnostics("client", true).Mark(identifier);
        }
        Require(writer.ToString().Length == 0 && writer.FlushCalls == 0);
    });

    private static Task ThrowingWriterAsync()
    {
        var original = Console.Error;
        try
        {
            foreach (var throwOnFlush in new[] { false, true })
            {
                using var writer = new ThrowingWriter(throwOnFlush);
                Console.SetError(writer);
                new HealthProbeDiagnostics("client", true).Mark("probe_failed", new IOException("secret"));
                Require(writer.Calls > 0);
            }
        }
        finally { Console.SetError(original); }
        return Task.CompletedTask;
    }

    private static Task SecretFreeAsync() => Capture(writer =>
    {
        const string secret = "SECRET_TOKEN_PATH_CREDENTIAL_6a5592";
        var exception = new InvalidOperationException(secret, new IOException(secret));
        exception.Data["credential"] = secret;
        new HealthProbeDiagnostics("launcher", true).Mark("probe_failed", exception);
        var output = writer.ToString();
        Require(!output.Contains(secret, StringComparison.Ordinal));
        using var document = JsonDocument.Parse(output);
        var value = document.RootElement;
        Require(value.GetProperty("exceptionType").GetString() == nameof(InvalidOperationException));
        Require(value.GetProperty("hresult").GetInt32() == exception.HResult);
        Require(value.GetProperty("innerExceptionType").GetString() == nameof(IOException));
        Require(value.GetProperty("innerHresult").GetInt32() == exception.InnerException!.HResult);
        var allowed = new HashSet<string>(StringComparer.Ordinal)
        {
            "schemaVersion", "event", "component", "phase", "pid", "utc", "tickCount64",
            "elapsedMilliseconds", "exceptionType", "hresult", "innerExceptionType", "innerHresult",
        };
        Require(value.EnumerateObject().All(property => allowed.Contains(property.Name)));
    });

    private static Task Capture(Action<CapturingWriter> action)
    {
        var original = Console.Error;
        using var writer = new CapturingWriter();
        try { Console.SetError(writer); action(writer); }
        finally { Console.SetError(original); }
        return Task.CompletedTask;
    }

    private static void Require(bool condition)
    {
        if (!condition) throw new InvalidOperationException("Health diagnostic assertion failed.");
    }

    private sealed class CapturingWriter : StringWriter
    {
        internal int FlushCalls { get; private set; }
        public override void Flush() { FlushCalls++; base.Flush(); }
    }

    private sealed class ThrowingWriter(bool throwOnFlush) : StringWriter
    {
        internal int Calls { get; private set; }
        public override void WriteLine(string? value)
        {
            Calls++;
            if (!throwOnFlush) throw new IOException("synthetic writer failure");
        }
        public override void Flush()
        {
            Calls++;
            if (throwOnFlush) throw new IOException("synthetic flush failure");
        }
    }
}
