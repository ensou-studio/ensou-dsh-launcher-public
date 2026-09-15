using System.Globalization;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

namespace Ensou.Dsh.WindowsPilotObserver;

public sealed record EvidenceLogCompletion(
    string Path,
    long SizeBytes,
    string Sha256,
    string TerminalRecordSha256,
    long RecordCount);

public sealed class EvidenceSessionStore : IDisposable
{
    private const string HashDomain = "ENSOU-DSH-WINDOWS-PILOT-EVENT-V1";
    private readonly object sync = new();
    private readonly FileStream logStream;
    private readonly StreamWriter writer;
    private long sequence;
    private string previousHash = new('0', 64);
    private bool completed;

    public EvidenceSessionStore(string testRunId, string? evidenceRoot = null)
    {
        if (!Guid.TryParseExact(testRunId, "D", out _))
        {
            throw new ArgumentException("testRunId must be a canonical UUID.", nameof(testRunId));
        }
        evidenceRoot ??= Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Ensou",
            "DshPilotObserver",
            "runs");
        evidenceRoot = Path.GetFullPath(evidenceRoot);
        Directory.CreateDirectory(evidenceRoot);
        RejectReparseAncestors(evidenceRoot);
        RunDirectory = Path.Combine(evidenceRoot, testRunId);
        if (!NativeEvidenceStore.CreateDirectory(RunDirectory, IntPtr.Zero))
        {
            var error = Marshal.GetLastWin32Error();
            throw new IOException(
                error == NativeEvidenceStore.ErrorAlreadyExists
                    ? "Evidence run directory already exists."
                    : $"Unable to create evidence run directory (Win32 {error}).");
        }
        LogPath = Path.Combine(RunDirectory, "events.v1.jsonl");
        SummaryPath = Path.Combine(RunDirectory, "summary.v1.json");
        logStream = new FileStream(
            LogPath,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.Read,
            4096,
            FileOptions.WriteThrough);
        writer = new StreamWriter(logStream, new UTF8Encoding(false), 4096, leaveOpen: true)
        {
            NewLine = "\n",
        };
    }

    public string RunDirectory { get; }
    public string LogPath { get; }
    public string SummaryPath { get; }
    public long RecordCount { get { lock (sync) { return sequence; } } }
    public string TerminalRecordSha256 { get { lock (sync) { return previousHash; } } }

    public string Append(string eventType, long monotonicMilliseconds, object data)
    {
        if (string.IsNullOrWhiteSpace(eventType))
        {
            throw new ArgumentException("eventType is required.", nameof(eventType));
        }
        if (monotonicMilliseconds < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(monotonicMilliseconds));
        }
        var dataElement = JsonSerializer.SerializeToElement(data, ObservationContract.JsonOptions);
        ObservationPrivacy.AssertSafePayload(dataElement);
        lock (sync)
        {
            ObjectDisposedException.ThrowIf(completed, this);
            var nextSequence = checked(sequence + 1);
            var observedAtUtc = DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture);
            var recordHash = ComputeRecordHash(
                previousHash,
                nextSequence,
                observedAtUtc,
                monotonicMilliseconds,
                eventType,
                dataElement);
            var record = new EvidenceEventRecord
            {
                Sequence = nextSequence,
                ObservedAtUtc = observedAtUtc,
                MonotonicMilliseconds = monotonicMilliseconds,
                EventType = eventType,
                Data = dataElement,
                PreviousSha256 = previousHash,
                RecordSha256 = recordHash,
            };
            writer.WriteLine(JsonSerializer.Serialize(record, ObservationContract.JsonOptions));
            writer.Flush();
            logStream.Flush(flushToDisk: true);
            sequence = nextSequence;
            previousHash = recordHash;
            return recordHash;
        }
    }

    public EvidenceLogCompletion CompleteLog()
    {
        lock (sync)
        {
            if (completed)
            {
                throw new InvalidOperationException("Evidence log was already completed.");
            }
            writer.Flush();
            logStream.Flush(flushToDisk: true);
            writer.Dispose();
            logStream.Dispose();
            completed = true;
            var info = new FileInfo(LogPath);
            return new EvidenceLogCompletion(
                LogPath,
                info.Length,
                ObservationContract.Sha256File(LogPath),
                previousHash,
                sequence);
        }
    }

    public void WriteSummary(ObservationSummary summary)
    {
        if (!completed)
        {
            throw new InvalidOperationException("Complete the evidence log before writing the summary.");
        }
        if (summary.StandaloneAdmissionEvidence)
        {
            throw new InvalidDataException("Observer evidence must never be standalone admission evidence.");
        }
        var element = JsonSerializer.SerializeToElement(summary, ObservationContract.JsonOptions);
        ObservationPrivacy.AssertSafePayload(element);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(summary, new JsonSerializerOptions(ObservationContract.JsonOptions)
        {
            WriteIndented = true,
        });
        using var stream = new FileStream(
            SummaryPath,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.Read,
            4096,
            FileOptions.WriteThrough);
        stream.Write(bytes);
        stream.Flush(flushToDisk: true);
    }

    public static string ComputeRecordHash(
        string previousSha256,
        long sequence,
        string observedAtUtc,
        long monotonicMilliseconds,
        string eventType,
        JsonElement data)
    {
        var material = string.Join(
            "\n",
            HashDomain,
            previousSha256,
            sequence.ToString(CultureInfo.InvariantCulture),
            observedAtUtc,
            monotonicMilliseconds.ToString(CultureInfo.InvariantCulture),
            eventType,
            data.GetRawText());
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(material)));
    }

    public void Dispose()
    {
        lock (sync)
        {
            if (completed)
            {
                return;
            }
            writer.Dispose();
            logStream.Dispose();
            completed = true;
        }
    }

    private static void RejectReparseAncestors(string path)
    {
        var root = Path.GetPathRoot(path)
            ?? throw new InvalidDataException("Evidence root has no filesystem root.");
        var current = root;
        foreach (var segment in Path.GetRelativePath(root, path).Split(
                     Path.DirectorySeparatorChar,
                     StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, segment);
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException("Evidence root contains a reparse point.");
            }
        }
    }

    private sealed class EvidenceEventRecord
    {
        public required long Sequence { get; init; }
        public required string ObservedAtUtc { get; init; }
        public required long MonotonicMilliseconds { get; init; }
        public required string EventType { get; init; }
        public required JsonElement Data { get; init; }
        public required string PreviousSha256 { get; init; }
        public required string RecordSha256 { get; init; }
    }
}

internal static class NativeEvidenceStore
{
    internal const int ErrorAlreadyExists = 183;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CreateDirectory(string path, IntPtr securityAttributes);
}
