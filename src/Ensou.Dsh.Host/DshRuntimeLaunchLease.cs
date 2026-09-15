using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Ensou.Dsh.Host;

/// <summary>
/// Retains no-write/no-delete handles for every admitted runtime file and
/// watches the validated tree until termination of the exact admitted process
/// has been confirmed. Name-set barriers detect additions; production release
/// directories must also be ACL-isolated because Windows file handles do not
/// prevent the same user from creating a new sibling name.
/// </summary>
internal sealed class DshRuntimeLaunchLease : IDisposable
{
    private const int MaximumProcessImagePathCharacters = 32_768;
    private const int MaximumRuntimeEntries = 250_000;
    private const int MaximumParallelFileOpens = 16;
    private const int RuntimeWatcherBufferBytes = 64 * 1024;
    private const uint GenericRead = 0x80000000;
    private const uint OpenExisting = 3;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileFlagSequentialScan = 0x08000000;
    private static readonly TimeSpan RuntimeWatcherEventDrain =
        TimeSpan.FromMilliseconds(50);
    private static readonly EnumerationOptions RuntimeEnumerationOptions = new()
    {
        RecurseSubdirectories = false,
        IgnoreInaccessible = false,
        AttributesToSkip = 0,
        ReturnSpecialDirectories = false,
        MatchCasing = MatchCasing.CaseInsensitive,
        MatchType = MatchType.Simple,
    };
    private static readonly string[] KnownTrustMetadataFileNames =
    [
        ".ensou-complete-tree.v1.json",
        ".ensou-personal-component.v1.json",
        "runtime-files.sha256",
        ".ensou-release.json",
        "ensou-runtime-metadata.json",
    ];

    private FileStream? _lockedNode;
    private FileStream? _lockedEntryPoint;
    private List<LockedTrustMetadata>? _lockedTrustMetadata;
    private LockedRuntimeInventory? _lockedRuntimeInventory;
    private RuntimeTreeChangeMonitor? _runtimeTreeChangeMonitor;
    private int _fullInventoryScanCount;

    private DshRuntimeLaunchLease(
        string runtimeRoot,
        string nodePath,
        string entryPointPath,
        FileStream lockedNode,
        FileStream lockedEntryPoint,
        List<LockedTrustMetadata> lockedTrustMetadata,
        LockedRuntimeInventory lockedRuntimeInventory,
        RuntimeTreeChangeMonitor runtimeTreeChangeMonitor,
        DshRuntimeFileIdentity nodeIdentity,
        DshRuntimeFileIdentity entryPointIdentity)
    {
        RuntimeRoot = runtimeRoot;
        NodePath = nodePath;
        EntryPointPath = entryPointPath;
        _lockedNode = lockedNode;
        _lockedEntryPoint = lockedEntryPoint;
        _lockedTrustMetadata = lockedTrustMetadata;
        _lockedRuntimeInventory = lockedRuntimeInventory;
        _runtimeTreeChangeMonitor = runtimeTreeChangeMonitor;
        NodeIdentity = nodeIdentity;
        EntryPointIdentity = entryPointIdentity;
    }

    internal string NodePath { get; }

    internal string RuntimeRoot { get; }

    internal string EntryPointPath { get; }

    private DshRuntimeFileIdentity NodeIdentity { get; }

    private DshRuntimeFileIdentity EntryPointIdentity { get; }

    internal int FullInventoryScanCountForTests =>
        Volatile.Read(ref _fullInventoryScanCount);

    internal Action? BeforeCompleteInventoryScanForTests { get; set; }

    internal static DshRuntimeLaunchLease Acquire(
        DshRuntimeOptions options,
        Action validateBeforeProcessStart)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(validateBeforeProcessStart);
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "The DSH runtime launch lease requires Windows file identities.");
        }

        var runtimeRoot = NormalizeDirectory(options.RuntimeDirectory);
        var nodePath = RequireRuntimeFilePath(
            options.NodePath,
            runtimeRoot,
            "runtime executable");
        var entryPointPath = RequireRuntimeFilePath(
            options.EntryPointPath,
            runtimeRoot,
            "runtime entry point");
        // A first enumeration of freshly extracted Windows directories can
        // deliver delayed LastWrite notifications from extraction. Materialize
        // that directory metadata before the admission watcher is established.
        // This read-only pass grants no trust and its inventory is discarded:
        // the unchanged watched, locked inventory and validation below remain
        // the only admission boundary. Never reset or ignore watcher events.
        _ = EnumerateRuntimeInventory(runtimeRoot, onFile: null);
        var runtimeTreeChangeMonitor = RuntimeTreeChangeMonitor.Start(runtimeRoot);
        FileStream? lockedNode = null;
        FileStream? lockedEntryPoint = null;
        List<LockedTrustMetadata>? lockedTrustMetadata = null;
        LockedRuntimeInventory? lockedRuntimeInventory = null;
        try
        {
            lockedRuntimeInventory = LockRuntimeInventory(runtimeRoot);
            lockedNode = OpenLockedRuntimeFile(nodePath, "runtime executable");
            lockedEntryPoint = OpenLockedRuntimeFile(
                entryPointPath,
                "runtime entry point");
            lockedTrustMetadata = LockKnownTrustMetadata(runtimeRoot);
            var nodeIdentity = GetFileIdentity(
                lockedNode.SafeFileHandle,
                "runtime executable");
            var entryPointIdentity = GetFileIdentity(
                lockedEntryPoint.SafeFileHandle,
                "runtime entry point");

            // Admission deliberately runs after both critical files are locked.
            // Existing complete-tree and pointer validators can still read the
            // files, while another process cannot replace or modify them.
            validateBeforeProcessStart();
            runtimeTreeChangeMonitor.RequireUnchanged();
            Thread.Sleep(RuntimeWatcherEventDrain);
            runtimeTreeChangeMonitor.RequireUnchanged();
            RequirePathIdentity(
                nodePath,
                nodeIdentity,
                "runtime executable");
            RequirePathIdentity(
                entryPointPath,
                entryPointIdentity,
                "runtime entry point");
            RequireTrustMetadataStillCurrent(lockedTrustMetadata);
            RequireRuntimeInventoryStillCurrent(
                runtimeRoot,
                lockedRuntimeInventory,
                requireLockedFileIdentities: false);
            runtimeTreeChangeMonitor.RequireUnchanged();

            return new DshRuntimeLaunchLease(
                runtimeRoot,
                nodePath,
                entryPointPath,
                lockedNode,
                lockedEntryPoint,
                lockedTrustMetadata,
                lockedRuntimeInventory,
                runtimeTreeChangeMonitor,
                nodeIdentity,
                entryPointIdentity);
        }
        catch (Exception acquisitionFailure)
        {
            var cleanupFailures = new List<Exception>();
            DisposeTrustMetadata(lockedTrustMetadata, cleanupFailures);
            TryDispose(lockedRuntimeInventory, cleanupFailures);
            TryDispose(lockedEntryPoint, cleanupFailures);
            TryDispose(lockedNode, cleanupFailures);
            TryDispose(runtimeTreeChangeMonitor, cleanupFailures);
            if (cleanupFailures.Count > 0)
            {
                throw new AggregateException(
                    "DSH runtime admission failed and one or more acquired locks did not release cleanly.",
                    new[] { acquisitionFailure }.Concat(cleanupFailures));
            }
            throw;
        }
    }

    internal void RequireFilesStillCurrent()
    {
        var lockedNode = _lockedNode
            ?? throw new ObjectDisposedException(nameof(DshRuntimeLaunchLease));
        var lockedEntryPoint = _lockedEntryPoint
            ?? throw new ObjectDisposedException(nameof(DshRuntimeLaunchLease));
        var lockedTrustMetadata = _lockedTrustMetadata
            ?? throw new ObjectDisposedException(nameof(DshRuntimeLaunchLease));
        _ = _lockedRuntimeInventory
            ?? throw new ObjectDisposedException(nameof(DshRuntimeLaunchLease));
        var runtimeTreeChangeMonitor = _runtimeTreeChangeMonitor
            ?? throw new ObjectDisposedException(nameof(DshRuntimeLaunchLease));
        runtimeTreeChangeMonitor.RequireUnchanged();
        RequireIdentity(
            NodeIdentity,
            GetFileIdentity(lockedNode.SafeFileHandle, "runtime executable"),
            "runtime executable changed while locked");
        RequireIdentity(
            EntryPointIdentity,
            GetFileIdentity(
                lockedEntryPoint.SafeFileHandle,
                "runtime entry point"),
            "runtime entry point changed while locked");
        RequirePathIdentity(NodePath, NodeIdentity, "runtime executable");
        RequirePathIdentity(
            EntryPointPath,
            EntryPointIdentity,
            "runtime entry point");
        RequireTrustMetadataStillCurrent(lockedTrustMetadata);
        runtimeTreeChangeMonitor.RequireUnchanged();
    }

    internal void RequireCompleteInventoryStillCurrent()
    {
        var lockedRuntimeInventory = _lockedRuntimeInventory
            ?? throw new ObjectDisposedException(nameof(DshRuntimeLaunchLease));
        var runtimeTreeChangeMonitor = _runtimeTreeChangeMonitor
            ?? throw new ObjectDisposedException(nameof(DshRuntimeLaunchLease));
        RequireFilesStillCurrent();
        Thread.Sleep(RuntimeWatcherEventDrain);
        runtimeTreeChangeMonitor.RequireUnchanged();
        BeforeCompleteInventoryScanForTests?.Invoke();
        Interlocked.Increment(ref _fullInventoryScanCount);
        RequireRuntimeInventoryStillCurrent(
            RuntimeRoot,
            lockedRuntimeInventory,
            requireLockedFileIdentities: false);
        runtimeTreeChangeMonitor.RequireUnchanged();
        RequireFilesStillCurrent();
    }

    internal void RequireProcessImage(Process process)
    {
        ArgumentNullException.ThrowIfNull(process);
        RequireFilesStillCurrent();
        var processImagePath = ReadProcessImagePath(process);
        using var processImage = OpenLockedRuntimeFile(
            processImagePath,
            "started runtime process image");
        var processIdentity = GetFileIdentity(
            processImage.SafeFileHandle,
            "started runtime process image");
        RequireIdentity(
            NodeIdentity,
            processIdentity,
            $"started runtime process image '{processImagePath}' does not match the admitted node.exe");
    }

    internal void ReportWatcherErrorForTests()
    {
        var runtimeTreeChangeMonitor = _runtimeTreeChangeMonitor
            ?? throw new ObjectDisposedException(nameof(DshRuntimeLaunchLease));
        runtimeTreeChangeMonitor.ReportErrorForTests();
    }

    internal void DisableWatcherNotificationsForTests()
    {
        var runtimeTreeChangeMonitor = _runtimeTreeChangeMonitor
            ?? throw new ObjectDisposedException(nameof(DshRuntimeLaunchLease));
        runtimeTreeChangeMonitor.DisableNotificationsForTests();
    }

    public void Dispose()
    {
        var failures = new List<Exception>();
        TryDispose(
            Interlocked.Exchange(ref _runtimeTreeChangeMonitor, null),
            failures);
        DisposeTrustMetadata(
            Interlocked.Exchange(ref _lockedTrustMetadata, null),
            failures);
        TryDispose(
            Interlocked.Exchange(ref _lockedRuntimeInventory, null),
            failures);
        TryDispose(
            Interlocked.Exchange(ref _lockedEntryPoint, null),
            failures);
        TryDispose(Interlocked.Exchange(ref _lockedNode, null), failures);
        if (failures.Count > 0)
        {
            throw new AggregateException(
                "One or more DSH runtime admission locks did not release cleanly.",
                failures);
        }
    }

    private static List<LockedTrustMetadata> LockKnownTrustMetadata(
        string runtimeRoot)
    {
        var locked = new List<LockedTrustMetadata>();
        try
        {
            foreach (var fileName in KnownTrustMetadataFileNames)
            {
                var path = Path.Combine(runtimeRoot, fileName);
                if (!File.Exists(path))
                {
                    continue;
                }
                var label = $"runtime trust metadata '{fileName}'";
                var stream = OpenLockedRuntimeFile(path, label);
                try
                {
                    locked.Add(new LockedTrustMetadata(
                        path,
                        label,
                        stream,
                        GetFileIdentity(stream.SafeFileHandle, label)));
                }
                catch (Exception identityFailure)
                {
                    try
                    {
                        stream.Dispose();
                    }
                    catch (Exception cleanupFailure)
                    {
                        throw new AggregateException(
                            "DSH runtime trust metadata admission failed and its lock did not release cleanly.",
                            identityFailure,
                            cleanupFailure);
                    }
                    throw;
                }
            }
            return locked;
        }
        catch (Exception metadataFailure)
        {
            var cleanupFailures = new List<Exception>();
            DisposeTrustMetadata(locked, cleanupFailures);
            if (cleanupFailures.Count > 0)
            {
                throw new AggregateException(
                    "DSH runtime trust metadata admission failed and one or more locks did not release cleanly.",
                    new[] { metadataFailure }.Concat(cleanupFailures));
            }
            throw;
        }
    }

    private static void RequireTrustMetadataStillCurrent(
        IReadOnlyList<LockedTrustMetadata> lockedTrustMetadata)
    {
        foreach (var metadata in lockedTrustMetadata)
        {
            RequireIdentity(
                metadata.Identity,
                GetFileIdentity(metadata.Stream.SafeFileHandle, metadata.Label),
                $"{metadata.Label} changed while locked");
            RequirePathIdentity(
                metadata.Path,
                metadata.Identity,
                metadata.Label);
        }
    }

    private static void DisposeTrustMetadata(
        List<LockedTrustMetadata>? lockedTrustMetadata,
        List<Exception> failures)
    {
        ArgumentNullException.ThrowIfNull(failures);
        if (lockedTrustMetadata is null)
        {
            return;
        }
        for (var index = lockedTrustMetadata.Count - 1; index >= 0; index--)
        {
            TryDispose(lockedTrustMetadata[index].Stream, failures);
        }
    }

    private static void TryDispose(
        IDisposable? resource,
        List<Exception> failures)
    {
        if (resource is null)
        {
            return;
        }
        try
        {
            resource.Dispose();
        }
        catch (Exception exception)
        {
            failures.Add(exception);
        }
    }

    private static LockedRuntimeInventory LockRuntimeInventory(
        string runtimeRoot)
    {
        LockedRuntimeFile?[] lockedFiles = [];
        try
        {
            var candidates = new List<RuntimeFileCandidate>();
            var paths = EnumerateRuntimeInventory(
                runtimeRoot,
                (path, relativePath) => candidates.Add(
                    new RuntimeFileCandidate(path, relativePath)));
            lockedFiles = new LockedRuntimeFile?[candidates.Count];
            Parallel.For(
                fromInclusive: 0,
                toExclusive: candidates.Count,
                new ParallelOptions
                {
                    MaxDegreeOfParallelism = MaximumParallelFileOpens,
                },
                index =>
                {
                    var candidate = candidates[index];
                    var path = candidate.Path;
                    var relativePath = candidate.RelativePath;
                    var label = $"runtime inventory file '{relativePath}'";
                    SafeFileHandle? handle = OpenLockedRuntimeFileHandle(
                        path,
                        label);
                    try
                    {
                        lockedFiles[index] = new LockedRuntimeFile(
                            path,
                            relativePath,
                            handle,
                            GetFileIdentity(
                                handle,
                                label,
                                requireNonEmpty: false));
                        handle = null;
                    }
                    finally
                    {
                        handle?.Dispose();
                    }
                });
            var completedFiles = lockedFiles
                .Select(static file => file
                    ?? throw new InvalidOperationException(
                        "A DSH runtime inventory file lock was not acquired."))
                .ToList();
            return new LockedRuntimeInventory(
                completedFiles,
                paths.Files,
                paths.Directories);
        }
        catch (Exception inventoryFailure)
        {
            var cleanupFailures = new List<Exception>();
            for (var index = lockedFiles.Length - 1; index >= 0; index--)
            {
                TryDispose(lockedFiles[index]?.Handle, cleanupFailures);
            }
            if (cleanupFailures.Count > 0)
            {
                throw new AggregateException(
                    "DSH runtime inventory admission failed and one or more native file locks did not release cleanly.",
                    new[] { inventoryFailure }.Concat(cleanupFailures));
            }
            throw;
        }
    }

    private static void RequireRuntimeInventoryStillCurrent(
        string runtimeRoot,
        LockedRuntimeInventory lockedRuntimeInventory,
        bool requireLockedFileIdentities = true)
    {
        var current = EnumerateRuntimeInventory(
            runtimeRoot,
            onFile: null);
        if (!lockedRuntimeInventory.FilePaths.SetEquals(current.Files)
            || !lockedRuntimeInventory.DirectoryPaths.SetEquals(
                current.Directories))
        {
            throw new InvalidDataException(
                "DSH runtime admission failed: the complete runtime inventory changed during validation.");
        }

        if (!requireLockedFileIdentities)
        {
            return;
        }

        foreach (var file in lockedRuntimeInventory.Files)
        {
            var label = $"runtime inventory file '{file.RelativePath}'";
            RequireIdentity(
                file.Identity,
                GetFileIdentity(
                    file.Handle,
                    label,
                    requireNonEmpty: false),
                $"{label} changed while its native lock was held");
        }
    }

    private static RuntimeInventoryPaths EnumerateRuntimeInventory(
        string runtimeRoot,
        Action<string, string>? onFile)
    {
        if (!Directory.Exists(runtimeRoot)
            || (File.GetAttributes(runtimeRoot) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException(
                "The DSH runtime inventory root is missing or linked.");
        }

        var files = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var directories = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".",
        };
        var pending = new Queue<string>();
        pending.Enqueue(runtimeRoot);
        var entryCount = 0;
        while (pending.Count > 0)
        {
            var directory = pending.Dequeue();
            foreach (var entry in new DirectoryInfo(directory)
                         .EnumerateFileSystemInfos(
                             "*",
                             RuntimeEnumerationOptions))
            {
                entryCount++;
                if (entryCount > MaximumRuntimeEntries)
                {
                    throw new InvalidDataException(
                        "The DSH runtime inventory exceeds its bounded entry count.");
                }

                var attributes = entry.Attributes;
                if ((attributes & FileAttributes.ReparsePoint) != 0)
                {
                    throw new InvalidDataException(
                        "The DSH runtime inventory contains a filesystem link.");
                }
                var path = entry.FullName;
                var relativePath = RequireRuntimeRelativePath(
                    runtimeRoot,
                    path);
                if ((attributes & FileAttributes.Directory) != 0)
                {
                    if (!directories.Add(relativePath))
                    {
                        throw new InvalidDataException(
                            "The DSH runtime inventory repeats a directory path.");
                    }
                    pending.Enqueue(path);
                    continue;
                }

                if (!files.Add(relativePath))
                {
                    throw new InvalidDataException(
                        "The DSH runtime inventory repeats a file path.");
                }
                onFile?.Invoke(path, relativePath);
            }
        }
        if (files.Count == 0)
        {
            throw new InvalidDataException(
                "The DSH runtime inventory contains no files.");
        }
        return new RuntimeInventoryPaths(files, directories);
    }

    private static string RequireRuntimeRelativePath(
        string runtimeRoot,
        string path)
    {
        var relativePath = Path.GetRelativePath(runtimeRoot, path);
        if (Path.IsPathRooted(relativePath)
            || relativePath is "." or ".."
            || relativePath.StartsWith(
                $"..{Path.DirectorySeparatorChar}",
                StringComparison.Ordinal)
            || relativePath.StartsWith(
                $"..{Path.AltDirectorySeparatorChar}",
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "The DSH runtime inventory contains a path escape.");
        }
        return relativePath.Replace('\\', '/');
    }

    private static SafeFileHandle OpenLockedRuntimeFileHandle(
        string path,
        string label)
    {
        var handle = CreateFile(
            ToExtendedNativeFilePath(path),
            GenericRead,
            (uint)FileShare.Read,
            IntPtr.Zero,
            OpenExisting,
            FileFlagOpenReparsePoint | FileFlagSequentialScan,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new InvalidDataException(
                $"The DSH {label} could not be locked for complete-tree admission.",
                new Win32Exception(error));
        }
        return handle;
    }

    private static string ToExtendedNativeFilePath(string path)
    {
        // Inventory paths have already passed containment and reparse checks.
        // Native CreateFileW needs an extended path independently of the host
        // executable's manifest and the machine-wide long-path policy.
        if (!Path.IsPathFullyQualified(path))
        {
            throw new InvalidDataException("A native runtime file path must be absolute.");
        }
        var fullPath = Path.GetFullPath(path);
        if (fullPath.StartsWith(@"\\?\", StringComparison.Ordinal))
        {
            return fullPath;
        }
        return fullPath.StartsWith(@"\\", StringComparison.Ordinal)
            ? @"\\?\UNC\" + fullPath[2..]
            : @"\\?\" + fullPath;
    }

    private static string RequireRuntimeFilePath(
        string path,
        string runtimeRoot,
        string label)
    {
        var fullPath = Path.GetFullPath(path);
        var relative = Path.GetRelativePath(runtimeRoot, fullPath);
        if (Path.IsPathRooted(relative)
            || relative == ".."
            || relative.StartsWith(
                $"..{Path.DirectorySeparatorChar}",
                StringComparison.Ordinal)
            || relative.StartsWith(
                $"..{Path.AltDirectorySeparatorChar}",
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"The DSH {label} is outside its runtime directory.");
        }

        RejectReparseChain(
            Path.GetDirectoryName(fullPath)
                ?? throw new InvalidDataException(
                    $"The DSH {label} has no parent directory."),
            runtimeRoot,
            label);
        if (!File.Exists(fullPath)
            || (File.GetAttributes(fullPath) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException(
                $"The DSH {label} is missing or linked.");
        }
        return fullPath;
    }

    private static void RejectReparseChain(
        string startDirectory,
        string runtimeRoot,
        string label)
    {
        var current = new DirectoryInfo(Path.GetFullPath(startDirectory));
        while (true)
        {
            if (!current.Exists
                || (current.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException(
                    $"The DSH {label} path crosses a missing or linked directory.");
            }
            var normalized = NormalizeDirectory(current.FullName);
            if (string.Equals(
                    normalized,
                    runtimeRoot,
                    StringComparison.OrdinalIgnoreCase))
            {
                return;
            }
            current = current.Parent
                ?? throw new InvalidDataException(
                    $"The DSH {label} path escaped its runtime directory.");
        }
    }

    private static FileStream OpenLockedRuntimeFile(string path, string label)
    {
        try
        {
            var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                128 * 1024,
                FileOptions.SequentialScan);
            if (stream.Length <= 0)
            {
                stream.Dispose();
                throw new InvalidDataException($"The DSH {label} is empty.");
            }
            return stream;
        }
        catch (Exception exception) when (exception is
            IOException or UnauthorizedAccessException)
        {
            throw new InvalidDataException(
                $"The DSH {label} could not be locked for trusted launch.",
                exception);
        }
    }

    private static void RequirePathIdentity(
        string path,
        DshRuntimeFileIdentity expected,
        string label)
    {
        using var reopened = OpenLockedRuntimeFile(path, label);
        var actual = GetFileIdentity(reopened.SafeFileHandle, label);
        RequireIdentity(
            expected,
            actual,
            $"the current {label} path no longer names the admitted file");
    }

    private static void RequireIdentity(
        DshRuntimeFileIdentity expected,
        DshRuntimeFileIdentity actual,
        string failure)
    {
        if (actual != expected)
        {
            throw new InvalidDataException($"DSH runtime admission failed: {failure}.");
        }
    }

    private static DshRuntimeFileIdentity GetFileIdentity(
        SafeFileHandle handle,
        string label,
        bool requireNonEmpty = true)
    {
        if (!GetFileInformationByHandle(handle, out var information))
        {
            throw new IOException(
                $"Unable to read the DSH {label} file identity.",
                new Win32Exception(Marshal.GetLastWin32Error()));
        }
        if ((information.FileAttributes & (uint)(
                FileAttributes.ReparsePoint | FileAttributes.Directory)) != 0
            || information.NumberOfLinks != 1)
        {
            throw new InvalidDataException(
                $"The DSH {label} must be a single-link regular file.");
        }
        var length = checked((long)(
            ((ulong)information.FileSizeHigh << 32)
            | information.FileSizeLow));
        if (requireNonEmpty && length <= 0)
        {
            throw new InvalidDataException($"The DSH {label} is empty.");
        }
        return new DshRuntimeFileIdentity(
            information.VolumeSerialNumber,
            ((ulong)information.FileIndexHigh << 32)
                | information.FileIndexLow,
            length);
    }

    private static string ReadProcessImagePath(Process process)
    {
        var path = new StringBuilder(MaximumProcessImagePathCharacters);
        var length = (uint)path.Capacity;
        if (!QueryFullProcessImageName(process.Handle, 0, path, ref length)
            || length == 0
            || length >= MaximumProcessImagePathCharacters)
        {
            throw new IOException(
                "Unable to inspect the DSH runtime process image path.",
                new Win32Exception(Marshal.GetLastWin32Error()));
        }
        return Path.GetFullPath(path.ToString(0, checked((int)length)));
    }

    private static string NormalizeDirectory(string path) =>
        Path.GetFullPath(path).TrimEnd(
            Path.DirectorySeparatorChar,
            Path.AltDirectorySeparatorChar);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageName(
        IntPtr process,
        uint flags,
        StringBuilder executableName,
        ref uint size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle file,
        out ByHandleFileInformation information);

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

    private readonly record struct DshRuntimeFileIdentity(
        uint VolumeSerialNumber,
        ulong FileIndex,
        long Length);

    private sealed record LockedTrustMetadata(
        string Path,
        string Label,
        FileStream Stream,
        DshRuntimeFileIdentity Identity);

    private sealed record LockedRuntimeFile(
        string Path,
        string RelativePath,
        SafeFileHandle Handle,
        DshRuntimeFileIdentity Identity);

    private sealed record RuntimeFileCandidate(
        string Path,
        string RelativePath);

    private sealed class LockedRuntimeInventory(
        List<LockedRuntimeFile> files,
        HashSet<string> filePaths,
        HashSet<string> directoryPaths) : IDisposable
    {
        private List<LockedRuntimeFile>? _files = files;

        internal IReadOnlyList<LockedRuntimeFile> Files => _files
            ?? throw new ObjectDisposedException(nameof(LockedRuntimeInventory));

        internal HashSet<string> FilePaths { get; } = filePaths;

        internal HashSet<string> DirectoryPaths { get; } = directoryPaths;

        public void Dispose()
        {
            var lockedFiles = Interlocked.Exchange(ref _files, null);
            if (lockedFiles is null)
            {
                return;
            }
            var failures = new List<Exception>();
            for (var index = lockedFiles.Count - 1; index >= 0; index--)
            {
                TryDispose(lockedFiles[index].Handle, failures);
            }
            if (failures.Count > 0)
            {
                throw new AggregateException(
                    "One or more complete-tree native runtime locks did not release cleanly.",
                    failures);
            }
        }
    }

    private sealed record RuntimeInventoryPaths(
        HashSet<string> Files,
        HashSet<string> Directories);

    private sealed class RuntimeTreeChangeMonitor : IDisposable
    {
        private FileSystemWatcher? _watcher;
        private int _changed;
        private int _ignoreChangesForTests;

        private RuntimeTreeChangeMonitor(FileSystemWatcher watcher)
        {
            _watcher = watcher;
            watcher.Changed += OnChanged;
            watcher.Created += OnChanged;
            watcher.Deleted += OnChanged;
            watcher.Renamed += OnChanged;
            watcher.Error += OnError;
            watcher.EnableRaisingEvents = true;
        }

        internal static RuntimeTreeChangeMonitor Start(string runtimeRoot)
        {
            var watcher = new FileSystemWatcher(runtimeRoot)
            {
                Filter = "*",
                IncludeSubdirectories = true,
                InternalBufferSize = RuntimeWatcherBufferBytes,
                NotifyFilter = NotifyFilters.FileName
                    | NotifyFilters.DirectoryName
                    | NotifyFilters.Size
                    | NotifyFilters.LastWrite
                    | NotifyFilters.CreationTime
                    | NotifyFilters.Security,
            };
            try
            {
                return new RuntimeTreeChangeMonitor(watcher);
            }
            catch
            {
                watcher.Dispose();
                throw;
            }
        }

        internal void RequireUnchanged()
        {
            ObjectDisposedException.ThrowIf(_watcher is null, this);
            if (Volatile.Read(ref _changed) != 0)
            {
                throw new InvalidDataException(
                    "DSH runtime admission failed: the validated runtime tree changed while its process was admitted.");
            }
        }

        internal void ReportErrorForTests() =>
            Interlocked.Exchange(ref _changed, 1);

        internal void DisableNotificationsForTests()
        {
            Interlocked.Exchange(ref _ignoreChangesForTests, 1);
            var watcher = _watcher
                ?? throw new ObjectDisposedException(
                    nameof(RuntimeTreeChangeMonitor));
            watcher.EnableRaisingEvents = false;
            Interlocked.Exchange(ref _changed, 0);
        }

        public void Dispose()
        {
            var watcher = Interlocked.Exchange(ref _watcher, null);
            if (watcher is null)
            {
                return;
            }
            var failures = new List<Exception>();
            try
            {
                watcher.EnableRaisingEvents = false;
            }
            catch (Exception exception)
            {
                failures.Add(exception);
            }
            try
            {
                watcher.Dispose();
            }
            catch (Exception exception)
            {
                failures.Add(exception);
            }
            if (failures.Count > 0)
            {
                throw new AggregateException(
                    "The DSH runtime tree watcher did not release cleanly.",
                    failures);
            }
        }

        private void OnChanged(object sender, FileSystemEventArgs args)
        {
            if (Volatile.Read(ref _ignoreChangesForTests) == 0)
            {
                Interlocked.Exchange(ref _changed, 1);
            }
        }

        private void OnError(object sender, ErrorEventArgs args)
        {
            if (Volatile.Read(ref _ignoreChangesForTests) == 0)
            {
                Interlocked.Exchange(ref _changed, 1);
            }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }
}
