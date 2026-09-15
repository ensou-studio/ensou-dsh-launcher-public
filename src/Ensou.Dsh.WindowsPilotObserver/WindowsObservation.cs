using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json.Serialization;
using Microsoft.Win32.SafeHandles;

namespace Ensou.Dsh.WindowsPilotObserver;

public sealed record ProcessObservation(
    int ProcessId,
    int ParentProcessId,
    long CreationTimeUtcFileTime,
    string ImageName,
    string? ExecutablePath,
    string? ExecutableSha256,
    bool CandidateRelated)
{
    public string IdentityKey => $"{ProcessId}:{CreationTimeUtcFileTime}";

    public object ToEvidence() => new
    {
        processId = ProcessId,
        parentProcessId = ParentProcessId,
        creationTimeUtcFileTime = CreationTimeUtcFileTime,
        imageName = ImageName,
        executablePath = ExecutablePath is null
            ? null
            : ObservationPrivacy.NormalizePrivatePath(ExecutablePath),
        executableSha256 = ExecutableSha256,
        candidateRelated = CandidateRelated,
    };
}

public sealed record WindowObservation(
    long WindowHandle,
    int ProcessId,
    long ProcessCreationTimeUtcFileTime,
    string ProcessImageName,
    string ClassName,
    string TitleSha256,
    int TitleLength,
    string TitleCategory,
    bool Visible)
{
    [JsonIgnore]
    public string? ExecutablePath { get; init; }

    public string IdentityKey =>
        $"{WindowHandle:x}:{ProcessId}:{ProcessCreationTimeUtcFileTime}:{ClassName}:{TitleSha256}";
}

public sealed record DesktopSnapshot(
    IReadOnlyList<ProcessObservation> Processes,
    IReadOnlyList<WindowObservation> Windows);

public interface IDesktopProbe
{
    DesktopSnapshot Capture(bool enriched);
}

public sealed class WindowsDesktopProbe : IDesktopProbe
{
    private static readonly StringComparer PathComparer = StringComparer.OrdinalIgnoreCase;
    private readonly Dictionary<string, CandidateFilePlan> candidatesByPath;
    private readonly HashSet<string> candidateBaseNames;
    private readonly Dictionary<string, CachedImageHash> imageHashCache =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly int currentSessionId;

    public WindowsDesktopProbe(ObservationPlan plan)
    {
        candidatesByPath = plan.Candidate.Files.ToDictionary(
            static item => Path.GetFullPath(item.Path),
            PathComparer);
        candidateBaseNames = plan.Candidate.Files
            .Select(static item => Path.GetFileName(item.Path))
            .Where(static item => !string.IsNullOrWhiteSpace(item))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (!NativeDesktop.ProcessIdToSessionId(Environment.ProcessId, out currentSessionId))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "ProcessIdToSessionId failed.");
        }
    }

    public DesktopSnapshot Capture(bool enriched)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Windows Pilot Observer requires Windows.");
        }

        var processes = CaptureProcesses(enriched);
        var byId = processes
            .GroupBy(static item => item.ProcessId)
            .ToDictionary(static group => group.Key, static group => group.First());
        MarkCandidateDescendants(processes, byId);
        var windows = CaptureWindows();
        return new DesktopSnapshot(processes, windows);
    }

    private List<ProcessObservation> CaptureProcesses(bool enriched)
    {
        using var snapshot = NativeDesktop.CreateToolhelp32Snapshot(
            NativeDesktop.Th32csSnapProcess,
            0);
        if (snapshot.IsInvalid)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateToolhelp32Snapshot failed.");
        }

        var entry = new NativeDesktop.ProcessEntry32
        {
            Size = checked((uint)Marshal.SizeOf<NativeDesktop.ProcessEntry32>()),
        };
        var result = new List<ProcessObservation>();
        if (!NativeDesktop.Process32First(snapshot, ref entry))
        {
            var error = Marshal.GetLastWin32Error();
            if (error == NativeDesktop.ErrorNoMoreFiles)
            {
                return result;
            }
            throw new Win32Exception(error, "Process32First failed.");
        }

        do
        {
            var processId = checked((int)entry.ProcessId);
            if (!NativeDesktop.ProcessIdToSessionId(processId, out var sessionId)
                || sessionId != currentSessionId)
            {
                continue;
            }
            var imageName = (entry.ExecutableFile ?? string.Empty).TrimEnd('\0').ToLowerInvariant();
            var parentProcessId = checked((int)entry.ParentProcessId);
            var creationTime = 0L;
            string? executablePath = null;
            string? executableSha256 = null;
            using var process = NativeDesktop.OpenProcess(
                NativeDesktop.ProcessQueryLimitedInformation,
                false,
                processId);
            if (!process.IsInvalid)
            {
                creationTime = NativeDesktop.TryReadCreationTime(process);
                if (enriched || candidateBaseNames.Contains(imageName))
                {
                    executablePath = NativeDesktop.TryReadProcessPath(process);
                    if (enriched
                        && executablePath is not null
                        && (candidateBaseNames.Contains(imageName)
                            || NativeDesktop.SuspiciousImageNames.Contains(imageName)))
                    {
                        executableSha256 = TryHashFileCached(executablePath);
                    }
                }
            }
            var candidateRelated = executablePath is not null
                && candidatesByPath.ContainsKey(Path.GetFullPath(executablePath));
            result.Add(new ProcessObservation(
                processId,
                parentProcessId,
                creationTime,
                imageName,
                executablePath,
                executableSha256,
                candidateRelated));
        }
        while (NativeDesktop.Process32Next(snapshot, ref entry));

        var finalError = Marshal.GetLastWin32Error();
        if (finalError != NativeDesktop.ErrorNoMoreFiles)
        {
            throw new Win32Exception(finalError, "Process32Next failed.");
        }
        return result;
    }

    private static void MarkCandidateDescendants(
        List<ProcessObservation> processes,
        IReadOnlyDictionary<int, ProcessObservation> byId)
    {
        var changed = true;
        while (changed)
        {
            changed = false;
            for (var index = 0; index < processes.Count; index++)
            {
                var process = processes[index];
                if (process.CandidateRelated
                    || !byId.TryGetValue(process.ParentProcessId, out var parent)
                    || !parent.CandidateRelated
                    || (parent.CreationTimeUtcFileTime > 0
                        && process.CreationTimeUtcFileTime > 0
                        && parent.CreationTimeUtcFileTime > process.CreationTimeUtcFileTime))
                {
                    continue;
                }
                processes[index] = process with { CandidateRelated = true };
                changed = true;
            }
            if (changed)
            {
                byId = processes
                    .GroupBy(static item => item.ProcessId)
                    .ToDictionary(static group => group.Key, static group => group.First());
            }
        }
    }

    private static List<WindowObservation> CaptureWindows()
    {
        var windows = new List<WindowObservation>();
        var callback = new NativeDesktop.EnumWindowsCallback((window, _) =>
        {
            if (!NativeDesktop.IsWindowVisible(window)
                || NativeDesktop.GetAncestor(window, NativeDesktop.GaRoot) != window)
            {
                return true;
            }
            var observation = CaptureWindow(window);
            if (observation is not null)
            {
                windows.Add(observation);
            }
            return true;
        });
        if (!NativeDesktop.EnumWindows(callback, IntPtr.Zero))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "EnumWindows failed.");
        }
        GC.KeepAlive(callback);
        return windows;
    }

    internal static WindowObservation? CaptureWindow(IntPtr window)
    {
        if (window == IntPtr.Zero || !NativeDesktop.IsWindow(window))
        {
            return null;
        }
        _ = NativeDesktop.GetWindowThreadProcessId(window, out var processIdValue);
        var processId = checked((int)processIdValue);
        var creationTime = 0L;
        var imageName = "unknown";
        string? executablePath = null;
        using (var process = NativeDesktop.OpenProcess(
                   NativeDesktop.ProcessQueryLimitedInformation,
                   false,
                   processId))
        {
            if (!process.IsInvalid)
            {
                creationTime = NativeDesktop.TryReadCreationTime(process);
                executablePath = NativeDesktop.TryReadProcessPath(process);
                if (!string.IsNullOrWhiteSpace(executablePath))
                {
                    imageName = Path.GetFileName(executablePath).ToLowerInvariant();
                }
            }
        }
        var title = NativeDesktop.ReadWindowText(window);
        return new WindowObservation(
            window.ToInt64(),
            processId,
            creationTime,
            imageName,
            NativeDesktop.ReadClassName(window),
            ObservationPrivacy.HashSensitiveText(title),
            title.Length,
            ObservationPrivacy.ClassifyTitle(title),
            NativeDesktop.IsWindowVisible(window))
        {
            ExecutablePath = executablePath,
        };
    }

    private string? TryHashFileCached(string path)
    {
        try
        {
            var info = new FileInfo(path);
            var length = info.Length;
            var lastWriteUtcTicks = info.LastWriteTimeUtc.Ticks;
            if (imageHashCache.TryGetValue(path, out var cached)
                && cached.Length == length
                && cached.LastWriteUtcTicks == lastWriteUtcTicks)
            {
                return cached.Sha256;
            }
            var hash = ObservationContract.Sha256File(path);
            imageHashCache[path] = new CachedImageHash(length, lastWriteUtcTicks, hash);
            return hash;
        }
        catch (IOException)
        {
            return null;
        }
        catch (UnauthorizedAccessException)
        {
            return null;
        }
    }

    private sealed record CachedImageHash(long Length, long LastWriteUtcTicks, string Sha256);
}

internal static class NativeDesktop
{
    internal const uint Th32csSnapProcess = 0x00000002;
    internal const uint ProcessQueryLimitedInformation = 0x1000;
    internal const int ErrorNoMoreFiles = 18;
    internal const uint GaRoot = 2;

    internal static readonly HashSet<string> SuspiciousImageNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "cmd.exe",
        "powershell.exe",
        "pwsh.exe",
        "dotnet.exe",
        "conhost.exe",
        "openconsole.exe",
        "werfault.exe",
        "wermgr.exe",
    };

    internal delegate bool EnumWindowsCallback(IntPtr window, IntPtr parameter);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct ProcessEntry32
    {
        public uint Size;
        public uint Usage;
        public uint ProcessId;
        public IntPtr DefaultHeapId;
        public uint ModuleId;
        public uint Threads;
        public uint ParentProcessId;
        public int PriorityClassBase;
        public uint Flags;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string? ExecutableFile;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FileTime
    {
        public uint Low;
        public uint High;

        public long ToInt64() => unchecked((long)(((ulong)High << 32) | Low));
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern SafeFileHandle CreateToolhelp32Snapshot(uint flags, uint processId);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool Process32First(
        SafeFileHandle snapshot,
        ref ProcessEntry32 entry);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool Process32Next(
        SafeFileHandle snapshot,
        ref ProcessEntry32 entry);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern SafeProcessHandle OpenProcess(
        uint desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
        int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool QueryFullProcessImageName(
        SafeProcessHandle process,
        uint flags,
        StringBuilder executableName,
        ref int size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetProcessTimes(
        SafeProcessHandle process,
        out FileTime creation,
        out FileTime exit,
        out FileTime kernel,
        out FileTime user);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool ProcessIdToSessionId(int processId, out int sessionId);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool EnumWindows(EnumWindowsCallback callback, IntPtr parameter);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool IsWindowVisible(IntPtr window);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool IsWindow(IntPtr window);

    [DllImport("user32.dll")]
    internal static extern IntPtr GetAncestor(IntPtr window, uint flags);

    [DllImport("user32.dll", SetLastError = true)]
    internal static extern uint GetWindowThreadProcessId(IntPtr window, out uint processId);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern int GetWindowText(IntPtr window, StringBuilder text, int maximumCount);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern int GetWindowTextLength(IntPtr window);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern int GetClassName(IntPtr window, StringBuilder className, int maximumCount);

    internal static string? TryReadProcessPath(SafeProcessHandle process)
    {
        var capacity = 32768;
        var builder = new StringBuilder(capacity);
        return QueryFullProcessImageName(process, 0, builder, ref capacity)
            ? builder.ToString()
            : null;
    }

    internal static long TryReadCreationTime(SafeProcessHandle process) =>
        GetProcessTimes(process, out var creation, out _, out _, out _)
            ? creation.ToInt64()
            : 0L;

    internal static string ReadWindowText(IntPtr window)
    {
        var length = Math.Clamp(GetWindowTextLength(window), 0, 4096);
        var builder = new StringBuilder(length + 1);
        _ = GetWindowText(window, builder, builder.Capacity);
        return builder.ToString();
    }

    internal static string ReadClassName(IntPtr window)
    {
        var builder = new StringBuilder(256);
        return GetClassName(window, builder, builder.Capacity) > 0
            ? builder.ToString()
            : "unknown";
    }
}
