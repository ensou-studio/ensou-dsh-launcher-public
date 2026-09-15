using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Ensou.Dsh.WindowsPilotObserver;

public sealed class CandidateBindingException : Exception
{
    public CandidateBindingException(string reasonCode, string message)
        : base(message)
    {
        ReasonCode = reasonCode;
    }

    public CandidateBindingException(string reasonCode, string message, Exception innerException)
        : base(message, innerException)
    {
        ReasonCode = reasonCode;
    }

    public string ReasonCode { get; }
}

public sealed record CandidateFileEvidence(
    string Role,
    string Sha256,
    long SizeBytes,
    bool Observed);

public sealed class CandidateBindingTracker
{
    private readonly CandidatePlan plan;
    private readonly Dictionary<string, CandidateFileEvidence> observed =
        new(StringComparer.Ordinal);

    public CandidateBindingTracker(CandidatePlan plan)
    {
        this.plan = plan;
    }

    public CandidateFileEvidence[] Evidence => plan.Files
        .Select(item => observed.TryGetValue(item.Role, out var evidence)
            ? evidence
            : new CandidateFileEvidence(item.Role, item.Sha256, 0, false))
        .ToArray();

    public void VerifyRequiredAtStart()
    {
        foreach (var file in plan.Files.Where(static item => item.RequiredAtStart))
        {
            observed[file.Role] = VerifyExactFile(file);
        }
    }

    public CandidateFileEvidence[] ObserveNewlyAvailable()
    {
        var newlyObserved = new List<CandidateFileEvidence>();
        foreach (var file in plan.Files)
        {
            if (observed.ContainsKey(file.Role) || !File.Exists(file.Path))
            {
                continue;
            }
            var evidence = VerifyExactFile(file);
            observed.Add(file.Role, evidence);
            newlyObserved.Add(evidence);
        }
        return newlyObserved.ToArray();
    }

    public CandidateFileEvidence[] VerifyAllAtEnd()
    {
        var result = new List<CandidateFileEvidence>();
        foreach (var file in plan.Files)
        {
            if (!File.Exists(file.Path))
            {
                throw new CandidateBindingException(
                    "CANDIDATE_FILE_MISSING",
                    $"Candidate role {file.Role} is absent at finalization.");
            }
            var current = VerifyExactFile(file);
            if (observed.TryGetValue(file.Role, out var earlier)
                && (!string.Equals(current.Sha256, earlier.Sha256, StringComparison.Ordinal)
                    || current.SizeBytes != earlier.SizeBytes))
            {
                throw new CandidateBindingException(
                    "CANDIDATE_FILE_CHANGED",
                    $"Candidate role {file.Role} changed during observation.");
            }
            observed[file.Role] = current;
            result.Add(current);
        }
        return result.ToArray();
    }

    internal static CandidateFileEvidence VerifyExactFile(CandidateFilePlan file)
    {
        try
        {
            using var stream = OpenExactReadOnly(file.Path, file.Role);
            var actualHash = Convert.ToHexStringLower(
                System.Security.Cryptography.SHA256.HashData(stream));
            if (!string.Equals(actualHash, file.Sha256, StringComparison.Ordinal))
            {
                throw new CandidateBindingException(
                    "CANDIDATE_HASH_MISMATCH",
                    $"Candidate role {file.Role} does not match its planned bytes.");
            }
            return new CandidateFileEvidence(file.Role, actualHash, stream.Length, true);
        }
        catch (FileNotFoundException exception)
        {
            throw new CandidateBindingException(
                "CANDIDATE_FILE_MISSING",
                $"Candidate role {file.Role} is absent.", exception);
        }
    }

    internal static FileStream OpenExactReadOnly(string path, string role)
    {
        var expectedPath = Path.GetFullPath(path);
        RejectReparseAncestors(expectedPath);
        FileStream? stream = null;
        try
        {
            stream = new FileStream(
                expectedPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                1024 * 128,
                FileOptions.SequentialScan);
            if (!NativeFileIdentity.GetFileInformationByHandle(stream.SafeFileHandle, out var identity))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    $"Unable to identify {role}.");
            }
            if (identity.NumberOfLinks != 1)
            {
                throw new CandidateBindingException(
                    "CANDIDATE_FILE_LINKED",
                    $"{role} must have exactly one hard link.");
            }
            var finalPath = NativeFileIdentity.ReadFinalPath(stream.SafeFileHandle);
            if (!string.Equals(
                    NormalizeFinalPath(finalPath),
                    expectedPath,
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new CandidateBindingException(
                    "CANDIDATE_PATH_REDIRECTED",
                    $"{role} resolves outside its planned path.");
            }
            var result = stream;
            stream = null;
            return result;
        }
        finally
        {
            stream?.Dispose();
        }
    }

    private static void RejectReparseAncestors(string path)
    {
        var root = Path.GetPathRoot(path)
            ?? throw new CandidateBindingException("CANDIDATE_PATH_INVALID", "Candidate path has no root.");
        var relative = Path.GetRelativePath(root, path);
        var current = root;
        foreach (var segment in relative.Split(
                     Path.DirectorySeparatorChar,
                     StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, segment);
            if (!File.Exists(current) && !Directory.Exists(current))
            {
                continue;
            }
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
            {
                throw new CandidateBindingException(
                    "CANDIDATE_PATH_REPARSE",
                    "Candidate path contains a reparse point.");
            }
        }
    }

    private static string NormalizeFinalPath(string path)
    {
        const string uncDevicePrefix = @"\\?\UNC\";
        const string devicePrefix = @"\\?\";
        if (path.StartsWith(uncDevicePrefix, StringComparison.OrdinalIgnoreCase))
        {
            return @"\\" + path[uncDevicePrefix.Length..];
        }
        return path.StartsWith(devicePrefix, StringComparison.Ordinal)
            ? path[devicePrefix.Length..]
            : path;
    }
}

internal static class NativeFileIdentity
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public NativeDesktop.FileTime CreationTime;
        public NativeDesktop.FileTime LastAccessTime;
        public NativeDesktop.FileTime LastWriteTime;
        public uint VolumeId;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetFileInformationByHandle(
        SafeFileHandle file,
        out ByHandleFileInformation information);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandle(
        SafeFileHandle file,
        char[] path,
        uint pathLength,
        uint flags);

    internal static string ReadFinalPath(SafeFileHandle file)
    {
        var buffer = new char[32768];
        var length = GetFinalPathNameByHandle(file, buffer, checked((uint)buffer.Length), 0);
        if (length == 0 || length >= buffer.Length)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "GetFinalPathNameByHandle failed.");
        }
        return new string(buffer, 0, checked((int)length));
    }
}
