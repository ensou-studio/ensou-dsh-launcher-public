using System;
using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Threading;

internal sealed record FixtureConfiguration(
    string Mode,
    string MarkerPath,
    string? ChildMarkerPath,
    string ExpectedArgument,
    string? ExpectedProtocol);

internal static class Program
{
    private const string ConfigurationFileName = "fixture.config.json";
    private const string ChildArgument = "--fixture-child";
    private static readonly JsonSerializerOptions ConfigurationJsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    private static int Main(string[] args)
    {
        try
        {
            return Run(args);
        }
        catch (IOException)
        {
            return 98;
        }
        catch (JsonException)
        {
            return 98;
        }
        catch (InvalidDataException)
        {
            return 98;
        }
    }

    private static int Run(string[] args)
    {
        var configuration = ReadConfiguration();
        if (args is [ChildArgument])
        {
            return RunChild(configuration);
        }
        if (args.Length != 1 || !string.Equals(args[0], configuration.ExpectedArgument, StringComparison.Ordinal))
        {
            return 92;
        }
        if (!string.IsNullOrEmpty(configuration.ExpectedProtocol)
            && !string.Equals(
                Environment.GetEnvironmentVariable("ENSOU_DSH_PERSONAL_BINARY_SELF_CHECK_PROTOCOL"),
                configuration.ExpectedProtocol,
                StringComparison.Ordinal))
        {
            return 93;
        }

        WriteIdentity(configuration.MarkerPath);
        return configuration.Mode switch
        {
            "success" => WriteSuccess(),
            "stdout" => WriteBoundedOverflow(Console.Out),
            "stderr" => WriteBoundedOverflow(Console.Error),
            "timeout" => SleepForever(),
            "child-survives-root" => StartChildAndExit(configuration),
            _ => 97,
        };
    }

    private static FixtureConfiguration ReadConfiguration()
    {
        var path = Path.Combine(AppContext.BaseDirectory, ConfigurationFileName);
        var configuration = JsonSerializer.Deserialize<FixtureConfiguration>(File.ReadAllBytes(path), ConfigurationJsonOptions)
            ?? throw new InvalidDataException("Fixture configuration is absent.");
        if (string.IsNullOrWhiteSpace(configuration.Mode)
            || string.IsNullOrWhiteSpace(configuration.MarkerPath)
            || string.IsNullOrWhiteSpace(configuration.ExpectedArgument)
            || !Path.IsPathFullyQualified(configuration.MarkerPath)
            || (configuration.ChildMarkerPath is not null
                && !Path.IsPathFullyQualified(configuration.ChildMarkerPath)))
        {
            throw new InvalidDataException("Fixture configuration is invalid.");
        }
        return configuration;
    }

    private static int RunChild(FixtureConfiguration configuration)
    {
        if (!string.Equals(configuration.Mode, "child-survives-root", StringComparison.Ordinal)
            || string.IsNullOrWhiteSpace(configuration.ChildMarkerPath))
        {
            return 94;
        }
        WriteIdentity(configuration.ChildMarkerPath);
        return SleepForever();
    }

    private static int StartChildAndExit(FixtureConfiguration configuration)
    {
        if (string.IsNullOrWhiteSpace(configuration.ChildMarkerPath))
        {
            return 94;
        }
        var childStartInfo = new ProcessStartInfo
        {
            FileName = Environment.ProcessPath
                ?? throw new InvalidOperationException("Fixture executable path is unavailable."),
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WorkingDirectory = AppContext.BaseDirectory,
        };
        childStartInfo.ArgumentList.Add(ChildArgument);
        using var child = Process.Start(childStartInfo);
        if (child is null)
        {
            return 94;
        }
        var readiness = Stopwatch.StartNew();
        while (readiness.ElapsedMilliseconds < 2_000)
        {
            if (child.HasExited)
            {
                return 95;
            }
            if (TryReadExactIdentity(configuration.ChildMarkerPath, child.Id))
            {
                return WriteSuccess();
            }
            Thread.Sleep(10);
        }
        return 96;
    }

    private static bool TryReadExactIdentity(string markerPath, int expectedPid)
    {
        try
        {
            using var document = JsonDocument.Parse(File.ReadAllBytes(markerPath));
            return document.RootElement.TryGetProperty("pid", out var pid)
                && pid.TryGetInt32(out var markerPid)
                && markerPid == expectedPid
                && document.RootElement.TryGetProperty("startFileTime", out var startFileTime)
                && startFileTime.TryGetInt64(out var value)
                && value > 0;
        }
        catch (IOException)
        {
            return false;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static void WriteIdentity(string markerPath)
    {
        using var current = Process.GetCurrentProcess();
        using var stream = new FileStream(markerPath, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
        JsonSerializer.Serialize(stream, new
        {
            pid = current.Id,
            startFileTime = current.StartTime.ToUniversalTime().ToFileTimeUtc(),
        });
    }

    private static int WriteSuccess()
    {
        Console.Write("{\"probe\":\"fixed-safe-fixture\"}");
        return 0;
    }

    private static int WriteBoundedOverflow(TextWriter writer)
    {
        for (var index = 0; index < 1_024; index++)
        {
            writer.Write(new string('x', 1_024));
        }
        writer.Flush();
        return SleepForever();
    }

    private static int SleepForever()
    {
        Thread.Sleep(120_000);
        return 0;
    }
}
