using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Ensou.Dsh.Enterprise.Installation;

/// <summary>
/// Read-only admission guard for the JSONL-only enterprise runtime. The guard
/// deliberately scans only the enterprise Harness home and never follows or
/// inspects the employee-owned workspaces subtree.
/// </summary>
public static class EnterpriseLegacySqliteUpgradeGuard
{
    public const string BlockedMessage =
        "DSH_LEGACY_SQLITE_UPGRADE_BLOCKED：检测到旧版 DSH SQLite 本地数据，或无法安全确认本地数据状态。请先使用旧版 DSH 导出数据，然后联系管理员；本次操作未修改任何本地数据。";

    internal const string ContainmentFailureMessage =
        "DSH_LEGACY_SQLITE_CONTAINMENT_FAILED：检测到旧版 DSH SQLite 风险，但无法确认已启动进程完全停止。请立即联系管理员。";

    internal const string InstallationRollbackFailureMessage =
        "DSH_LEGACY_SQLITE_INSTALL_ROLLBACK_FAILED：检测到旧版 DSH SQLite 风险，但无法确认安装状态已完整回退。请立即联系管理员。";

    internal const string RepairRollbackFailureMessage =
        "DSH_LEGACY_SQLITE_REPAIR_ROLLBACK_FAILED：检测到旧版 DSH SQLite 风险，但无法确认修复状态已完整回退。请立即联系管理员。";

    private const string WorkspacesDirectoryName = "workspaces";
    private const int MaximumEntries = 200_000;
    private const long MaximumConfigBytes = 16L * 1024 * 1024;
    private const uint GenericRead = 0x80000000;
    private const uint FileListDirectory = 0x00000001;
    private const uint FileReadAttributes = 0x00000080;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint FileShareDelete = 0x00000004;
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const int ErrorFileNotFound = 2;
    private const int ErrorPathNotFound = 3;
    private const uint FileNameNormalized = 0;

    private static ReadOnlySpan<byte> SqliteMagic => "SQLite format 3\0"u8;

    private static ReadOnlySpan<byte> LegacyProviderToken =>
        "session-persistence-sqlite"u8;

    private static readonly string[] SqliteExtensions =
        [".db", ".sqlite", ".sqlite3"];

    private static readonly string[] SqliteSidecarSuffixes =
        ["-wal", "-shm", "-journal"];

    private static readonly HashSet<string> CordisCompositionFileNames = new(
        [
            "cordis.patch.yml",
            "cordis.patch.yaml",
            "cordis.yml",
            "cordis.yaml",
        ],
        StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Requires the enterprise Harness home to contain no evidence of the
    /// removed persistent SQLite provider. Every failure is surfaced through
    /// one bounded, path-free operator message.
    /// </summary>
    public static void RequireJsonlOnlyHarnessHome(
        EnterpriseInstallationLayout layout) =>
        RequireJsonlOnlyHarnessHomeWithTestRace(layout, null);

    public static void RequireJsonlOnlyHarnessHomeAndNoWriter(
        EnterpriseInstallationLayout layout) =>
        RequireJsonlOnlyHarnessHomeAndNoWriter(
            layout,
            () => EnterpriseHarnessProcessWriterGuard
                .RequireNoPossibleHarnessWriter(layout));

    internal static void RequireJsonlOnlyHarnessHomeAndNoWriter(
        EnterpriseInstallationLayout layout,
        Action requireNoPossibleHarnessWriter)
    {
        ArgumentNullException.ThrowIfNull(requireNoPossibleHarnessWriter);
        try
        {
            requireNoPossibleHarnessWriter();
            RequireJsonlOnlyHarnessHome(layout);
        }
        catch (Exception exception) when (IsBoundedGuardFailure(exception))
        {
            _ = exception;
            throw new InvalidOperationException(BlockedMessage);
        }
    }

    internal static void RequireJsonlOnlyHarnessHomeForTest(
        EnterpriseInstallationLayout layout,
        Action betweenSnapshotsForTest) =>
        RequireJsonlOnlyHarnessHomeWithTestRace(
            layout,
            betweenSnapshotsForTest
                ?? throw new ArgumentNullException(nameof(betweenSnapshotsForTest)));

    private static void RequireJsonlOnlyHarnessHomeWithTestRace(
        EnterpriseInstallationLayout layout,
        Action? betweenSnapshotsForTest)
    {
        ArgumentNullException.ThrowIfNull(layout);
        try
        {
            using var first = Capture(layout);
            betweenSnapshotsForTest?.Invoke();
            using var second = Capture(layout);
            RequireSameSnapshot(first, second);
        }
        catch (Exception exception) when (IsBoundedGuardFailure(exception))
        {
            _ = exception;
            throw new InvalidOperationException(BlockedMessage);
        }
    }

    /// <summary>
    /// Executes one synchronous action between a stable pre-inspection and a
    /// stable post-inspection. Open handles keep already-inspected file bytes
    /// available for identity comparison, but are deliberately not represented
    /// as a Windows namespace lock: NTFS permits child creation and delete/name
    /// replacement while directory handles are open. The post-inspection is the
    /// required protection against those races.
    /// </summary>
    internal static TResult ExecuteWithJsonlOnlyHarnessHomeAdmission<TResult>(
        EnterpriseInstallationLayout layout,
        Func<TResult> action,
        Action<TResult> rejectResult)
    {
        ArgumentNullException.ThrowIfNull(layout);
        ArgumentNullException.ThrowIfNull(action);
        ArgumentNullException.ThrowIfNull(rejectResult);

        using var before = CaptureStableOrThrowBounded(layout);
        var result = action();
        try
        {
            using var after = CaptureStableOrThrowBounded(layout);
            try
            {
                RequireSameSnapshot(before, after);
            }
            catch (Exception exception) when (IsBoundedGuardFailure(exception))
            {
                _ = exception;
                throw new InvalidOperationException(BlockedMessage);
            }
        }
        catch (InvalidOperationException exception) when (
            string.Equals(exception.Message, BlockedMessage, StringComparison.Ordinal))
        {
            try
            {
                rejectResult(result);
            }
            catch
            {
                throw new InvalidOperationException(ContainmentFailureMessage);
            }
            throw new InvalidOperationException(BlockedMessage);
        }
        return result;
    }

    public static Process StartProcessWithJsonlOnlyHarnessHomeAdmission(
        EnterpriseInstallationLayout layout,
        Func<Process?> startProcess) =>
        ExecuteWithJsonlOnlyHarnessHomeAdmission(
            layout,
            () => startProcess()
                ?? throw new InvalidOperationException(
                    "Windows did not start the admitted enterprise process."),
            TerminateProcessTreeRequired);

    internal static bool IsBlockedFailure(Exception exception) =>
        exception is InvalidOperationException
        && string.Equals(exception.Message, BlockedMessage, StringComparison.Ordinal)
        && exception.InnerException is null;

    private static void TerminateProcessTreeRequired(Process process)
    {
        ArgumentNullException.ThrowIfNull(process);
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
            if (!process.WaitForExit((int)TimeSpan.FromSeconds(30).TotalMilliseconds)
                || !process.HasExited)
            {
                throw new InvalidOperationException(
                    "Rejected enterprise process did not stop within the bounded timeout.");
            }
        }
        finally
        {
            process.Dispose();
        }
    }

    private static GuardSnapshot CaptureStableOrThrowBounded(
        EnterpriseInstallationLayout layout)
    {
        GuardSnapshot? first = null;
        try
        {
            first = Capture(layout);
            var second = Capture(layout);
            try
            {
                RequireSameSnapshot(first, second);
                first.Dispose();
                return second;
            }
            catch
            {
                second.Dispose();
                throw;
            }
        }
        catch (Exception exception) when (IsBoundedGuardFailure(exception))
        {
            first?.Dispose();
            _ = exception;
            throw new InvalidOperationException(BlockedMessage);
        }
    }

    private static GuardSnapshot Capture(EnterpriseInstallationLayout layout)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "Enterprise legacy SQLite admission requires Windows file identities.");
        }

        var profileRoot = NormalizeComparablePath(layout.UserProfileRoot);
        var harnessHome = NormalizeComparablePath(layout.HarnessHome);
        var expectedHomeName = layout.IsDevelopmentE2E
            ? EnterpriseInstallationLayout.DevelopmentE2EHarnessHomeName
            : EnterpriseInstallationLayout.HarnessHomeName;
        if (!Path.IsPathFullyQualified(profileRoot)
            || !Path.IsPathFullyQualified(harnessHome)
            || !string.Equals(
                NormalizeComparablePath(Path.GetDirectoryName(harnessHome)
                    ?? throw new InvalidDataException("Harness home has no parent.")),
                profileRoot,
                StringComparison.OrdinalIgnoreCase)
            || !string.Equals(
                Path.GetFileName(harnessHome),
                expectedHomeName,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException("Enterprise Harness home boundary is invalid.");
        }

        var snapshot = new GuardSnapshot();
        try
        {
            var ancestorIndex = 0;
            var ancestors = EnumerateDirectoryChain(profileRoot).ToArray();
            foreach (var ancestor in ancestors)
            {
                var entry = OpenAndValidate(
                        ancestor,
                        requireDirectory: true,
                        allowAbsent: false,
                        holdExistingContentStable: ancestorIndex == ancestors.Length - 1)
                    ?? throw new DirectoryNotFoundException();
                snapshot.Add($"@ancestor:{ancestorIndex++}", entry);
            }

            var homeEntry = OpenAndValidate(
                harnessHome,
                requireDirectory: true,
                allowAbsent: true,
                holdExistingContentStable: true);
            if (homeEntry is null)
            {
                snapshot.HomePresent = false;
                return snapshot;
            }

            snapshot.HomePresent = true;
            snapshot.Add(string.Empty, homeEntry);
            var pending = new Stack<(string Path, int Depth)>();
            pending.Push((harnessHome, 0));
            while (pending.Count > 0)
            {
                var current = pending.Pop();
                string[] children;
                try
                {
                    children = Directory.GetFileSystemEntries(
                        current.Path,
                        "*",
                        SearchOption.TopDirectoryOnly);
                }
                catch (Exception exception) when (IsBoundedGuardFailure(exception))
                {
                    throw new IOException("Enterprise Harness home enumeration failed.");
                }

                Array.Sort(children, StringComparer.OrdinalIgnoreCase);
                foreach (var child in children)
                {
                    if (snapshot.EntryCount >= MaximumEntries)
                    {
                        throw new InvalidDataException(
                            "Enterprise Harness home exceeds the inspection bound.");
                    }

                    var absoluteChild = NormalizeComparablePath(child);
                    if (!string.Equals(
                            NormalizeComparablePath(Path.GetDirectoryName(absoluteChild)
                                ?? throw new InvalidDataException("Harness entry has no parent.")),
                            NormalizeComparablePath(current.Path),
                            StringComparison.OrdinalIgnoreCase))
                    {
                        throw new InvalidDataException(
                            "Enterprise Harness enumeration escaped its parent.");
                    }

                    var relative = Path.GetRelativePath(harnessHome, absoluteChild)
                        .Replace(Path.AltDirectorySeparatorChar, Path.DirectorySeparatorChar);
                    if (relative is "." or ".."
                        || relative.StartsWith(
                            ".." + Path.DirectorySeparatorChar,
                            StringComparison.Ordinal))
                    {
                        throw new InvalidDataException(
                            "Enterprise Harness enumeration escaped its root.");
                    }

                    var isWorkspaceRoot = current.Depth == 0
                        && string.Equals(
                            Path.GetFileName(absoluteChild),
                            WorkspacesDirectoryName,
                            StringComparison.OrdinalIgnoreCase);
                    var opened = OpenAndValidate(
                            absoluteChild,
                            requireDirectory: null,
                            allowAbsent: false,
                            holdExistingContentStable: !isWorkspaceRoot)
                        ?? throw new FileNotFoundException();
                    snapshot.Add(relative, opened);
                    if (opened.IsDirectory)
                    {
                        if (isWorkspaceRoot)
                        {
                            continue;
                        }
                        pending.Push((absoluteChild, checked(current.Depth + 1)));
                    }
                    else
                    {
                        InspectFile(opened.Handle, opened.Identity, relative);
                    }
                }
            }
            return snapshot;
        }
        catch
        {
            snapshot.Dispose();
            throw;
        }
    }

    private static OpenedEntry? OpenAndValidate(
        string path,
        bool? requireDirectory,
        bool allowAbsent,
        bool holdExistingContentStable)
    {
        using var attributesHandle = OpenHandle(
            path,
            FileReadAttributes,
            holdExistingContentStable
                ? FileShareRead | FileShareDelete
                : FileShareRead | FileShareWrite | FileShareDelete,
            allowAbsent);
        if (attributesHandle is null)
        {
            return null;
        }

        var firstIdentity = EnterpriseManagedGcPathSafety.GetFileIdentity(attributesHandle);
        var isDirectory = (firstIdentity.FileAttributes & (uint)FileAttributes.Directory) != 0;
        if ((firstIdentity.FileAttributes & (uint)FileAttributes.ReparsePoint) != 0
            || requireDirectory is not null && requireDirectory.Value != isDirectory
            || !isDirectory && firstIdentity.NumberOfLinks != 1)
        {
            throw new InvalidDataException(
                "Enterprise Harness home contains an unsafe filesystem entry.");
        }

        var heldHandle = OpenHandle(
                path,
                isDirectory ? FileListDirectory | FileReadAttributes : GenericRead,
                isDirectory
                    ? holdExistingContentStable
                        ? FileShareRead | FileShareDelete
                        : FileShareRead | FileShareWrite | FileShareDelete
                    : FileShareRead | FileShareDelete,
                allowAbsent: false)
            ?? throw new FileNotFoundException();
        try
        {
            var secondIdentity = EnterpriseManagedGcPathSafety.GetFileIdentity(heldHandle);
            if (!firstIdentity.Equals(secondIdentity)
                || (secondIdentity.FileAttributes & (uint)FileAttributes.ReparsePoint) != 0
                || !isDirectory && secondIdentity.NumberOfLinks != 1
                || !string.Equals(
                    NormalizeComparablePath(GetFinalPath(heldHandle)),
                    NormalizeComparablePath(path),
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new IOException(
                    "Enterprise Harness entry identity changed while it was inspected.");
            }
            return new OpenedEntry(heldHandle, secondIdentity, isDirectory);
        }
        catch
        {
            heldHandle.Dispose();
            throw;
        }
    }

    private static SafeFileHandle? OpenHandle(
        string path,
        uint desiredAccess,
        uint shareMode,
        bool allowAbsent)
    {
        var handle = CreateFile(
            EnterpriseMaintenanceIntegrity.ToExtendedWindowsPath(path),
            desiredAccess,
            shareMode,
            IntPtr.Zero,
            OpenExisting,
            FileFlagBackupSemantics | FileFlagOpenReparsePoint,
            IntPtr.Zero);
        if (!handle.IsInvalid)
        {
            return handle;
        }

        var error = Marshal.GetLastWin32Error();
        handle.Dispose();
        if (allowAbsent && error is ErrorFileNotFound or ErrorPathNotFound)
        {
            return null;
        }
        throw new IOException(
            "Enterprise Harness entry could not be opened for read-only inspection.",
            new Win32Exception(error));
    }

    private static void InspectFile(
        SafeFileHandle handle,
        EnterpriseManagedFileIdentity identity,
        string relativePath)
    {
        var fileName = Path.GetFileName(relativePath);
        if (IsSqliteArtifactName(fileName))
        {
            throw new InvalidDataException("Legacy SQLite filename evidence was detected.");
        }

        if (string.IsNullOrEmpty(Path.GetExtension(fileName))
            && HasPrefix(handle, identity.Length, SqliteMagic))
        {
            throw new InvalidDataException("Legacy SQLite magic evidence was detected.");
        }

        if (IsConfigCandidate(relativePath)
            && ContainsLegacyProviderToken(handle, identity.Length))
        {
            throw new InvalidDataException("Legacy SQLite configuration evidence was detected.");
        }

        var afterRead = EnterpriseManagedGcPathSafety.GetFileIdentity(handle);
        if (!identity.Equals(afterRead)
            || afterRead.NumberOfLinks != 1
            || (afterRead.FileAttributes & (uint)FileAttributes.ReparsePoint) != 0)
        {
            throw new IOException(
                "Enterprise Harness entry identity changed while content was inspected.");
        }
    }

    private static bool IsSqliteArtifactName(string fileName)
    {
        if (SqliteSidecarSuffixes.Any(suffix =>
                fileName.EndsWith(suffix, StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }
        foreach (var extension in SqliteExtensions)
        {
            if (fileName.EndsWith(extension, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
            foreach (var suffix in SqliteSidecarSuffixes)
            {
                if (fileName.EndsWith(
                    extension + suffix,
                    StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
        }
        return false;
    }

    private static bool IsConfigCandidate(string relativePath)
    {
        var normalized = relativePath.Replace(
            Path.AltDirectorySeparatorChar,
            Path.DirectorySeparatorChar);
        var segments = normalized.Split(
            Path.DirectorySeparatorChar,
            StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length == 1)
        {
            return CordisCompositionFileNames.Contains(segments[0]);
        }
        return segments.Length == 3
            && string.Equals(segments[0], "profiles", StringComparison.OrdinalIgnoreCase)
            && IsSafeProfileSegment(segments[1])
            && CordisCompositionFileNames.Contains(segments[2]);
    }

    private static bool IsSafeProfileSegment(string value) =>
        !string.IsNullOrEmpty(value)
        && value is not "." and not ".."
        && !string.Equals(value, "node_modules", StringComparison.OrdinalIgnoreCase)
        && value.IndexOfAny([Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar]) < 0;

    internal delegate int PrefixReader(Span<byte> destination, long fileOffset);

    private static bool HasPrefix(
        SafeFileHandle handle,
        long length,
        ReadOnlySpan<byte> expected) =>
        HasPrefix(
            length,
            expected,
            (destination, fileOffset) =>
                RandomAccess.Read(handle, destination, fileOffset));

    internal static bool HasPrefixForTest(
        long length,
        ReadOnlySpan<byte> expected,
        PrefixReader read) =>
        HasPrefix(length, expected, read);

    private static bool HasPrefix(
        long length,
        ReadOnlySpan<byte> expected,
        PrefixReader read)
    {
        ArgumentNullException.ThrowIfNull(read);
        if (length < expected.Length)
        {
            return false;
        }
        Span<byte> buffer = stackalloc byte[16];
        if (expected.IsEmpty || expected.Length > buffer.Length)
        {
            throw new ArgumentOutOfRangeException(nameof(expected));
        }
        var destination = buffer[..expected.Length];
        var offset = 0;
        while (offset < destination.Length)
        {
            var readCount = read(destination[offset..], offset);
            if (readCount <= 0 || readCount > destination.Length - offset)
            {
                throw new EndOfStreamException(
                    "Enterprise Harness file ended during SQLite magic inspection.");
            }
            offset += readCount;
        }
        return destination.SequenceEqual(expected);
    }

    private static bool ContainsLegacyProviderToken(SafeFileHandle handle, long length)
    {
        if (length < LegacyProviderToken.Length)
        {
            return false;
        }
        if (length > MaximumConfigBytes || length > int.MaxValue)
        {
            throw new InvalidDataException(
                "Enterprise Harness configuration exceeds the inspection bound.");
        }

        var contents = new byte[checked((int)length)];
        var offset = 0;
        while (offset < contents.Length)
        {
            var read = RandomAccess.Read(handle, contents.AsSpan(offset), offset);
            if (read <= 0)
            {
                throw new EndOfStreamException(
                    "Enterprise Harness configuration ended during inspection.");
            }
            offset += read;
        }
        return Encoding.UTF8.GetString(contents)
            .Contains(
                Encoding.ASCII.GetString(LegacyProviderToken),
                StringComparison.OrdinalIgnoreCase);
    }

    private static IEnumerable<string> EnumerateDirectoryChain(string directory)
    {
        var fullPath = NormalizeComparablePath(directory);
        var root = Path.GetPathRoot(fullPath)
            ?? throw new InvalidDataException("Enterprise profile root has no volume root.");
        var current = NormalizeComparablePath(root);
        yield return current;
        var relative = Path.GetRelativePath(root, fullPath);
        if (relative == ".")
        {
            yield break;
        }
        foreach (var segment in relative.Split(
                     [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar],
                     StringSplitOptions.RemoveEmptyEntries))
        {
            if (segment is "." or "..")
            {
                throw new InvalidDataException(
                    "Enterprise profile root contains traversal.");
            }
            current = NormalizeComparablePath(Path.Combine(current, segment));
            yield return current;
        }
    }

    private static void RequireSameSnapshot(GuardSnapshot first, GuardSnapshot second)
    {
        if (first.HomePresent != second.HomePresent
            || first.Entries.Count != second.Entries.Count)
        {
            throw new IOException(
                "Enterprise Harness home changed during inspection.");
        }
        foreach (var pair in first.Entries)
        {
            if (!second.Entries.TryGetValue(pair.Key, out var current)
                || !pair.Value.Equals(current))
            {
                throw new IOException(
                    "Enterprise Harness entry changed during inspection.");
            }
        }
    }

    private static string GetFinalPath(SafeFileHandle handle)
    {
        var capacity = 512;
        while (capacity <= 32_768)
        {
            var buffer = new char[capacity];
            var length = GetFinalPathNameByHandle(
                handle,
                buffer,
                checked((uint)buffer.Length),
                FileNameNormalized);
            if (length == 0)
            {
                throw new IOException(
                    "Enterprise Harness entry final path could not be resolved.",
                    new Win32Exception(Marshal.GetLastWin32Error()));
            }
            if (length < buffer.Length)
            {
                return new string(buffer, 0, checked((int)length));
            }
            capacity = checked((int)length + 1);
        }
        throw new PathTooLongException(
            "Enterprise Harness entry final path exceeds the inspection bound.");
    }

    private static string NormalizeComparablePath(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var value = path;
        if (value.StartsWith("\\\\?\\UNC\\", StringComparison.OrdinalIgnoreCase))
        {
            value = "\\\\" + value[8..];
        }
        else if (value.StartsWith("\\\\?\\", StringComparison.Ordinal))
        {
            value = value[4..];
        }
        return Path.TrimEndingDirectorySeparator(Path.GetFullPath(value));
    }

    private static bool IsBoundedGuardFailure(Exception exception) =>
        exception is not OutOfMemoryException
            and not StackOverflowException
            and not AccessViolationException;

    private sealed class GuardSnapshot : IDisposable
    {
        private readonly List<SafeFileHandle> _handles = [];

        public Dictionary<string, EnterpriseManagedFileIdentity> Entries { get; } =
            new(StringComparer.OrdinalIgnoreCase);

        public bool HomePresent { get; set; }

        public int EntryCount => Entries.Count;

        public void Add(string key, OpenedEntry entry)
        {
            if (!Entries.TryAdd(key, entry.Identity))
            {
                entry.Handle.Dispose();
                throw new InvalidDataException(
                    "Enterprise Harness enumeration produced a duplicate path.");
            }
            _handles.Add(entry.Handle);
        }

        public void Dispose()
        {
            foreach (var handle in _handles)
            {
                handle.Dispose();
            }
            _handles.Clear();
        }
    }

    private sealed record OpenedEntry(
        SafeFileHandle Handle,
        EnterpriseManagedFileIdentity Identity,
        bool IsDirectory);

    [DllImport(
        "kernel32.dll",
        EntryPoint = "CreateFileW",
        CharSet = CharSet.Unicode,
        SetLastError = true)]
    private static extern SafeFileHandle CreateFile(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport(
        "kernel32.dll",
        EntryPoint = "GetFinalPathNameByHandleW",
        CharSet = CharSet.Unicode,
        SetLastError = true)]
    private static extern uint GetFinalPathNameByHandle(
        SafeFileHandle file,
        [Out] char[] filePath,
        uint filePathLength,
        uint flags);
}
