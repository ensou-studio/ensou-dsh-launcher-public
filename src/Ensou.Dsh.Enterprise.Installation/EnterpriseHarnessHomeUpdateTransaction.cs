using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Win32.SafeHandles;

[assembly: System.Runtime.CompilerServices.InternalsVisibleTo(
    "Ensou.Dsh.Enterprise.HomeRecoveryTests")]

namespace Ensou.Dsh.Enterprise.Installation;

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record EnterpriseHarnessHomeRecoveryState(
    int SchemaVersion,
    string TransactionId,
    string ReleaseSetId,
    string Status,
    string HarnessHome,
    string OriginalDirectory,
    string? FailedCandidateDirectory,
    string OriginalTreeSha256,
    long OriginalFileCount,
    long OriginalSizeBytes,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset UpdatedAtUtc);

public sealed record EnterpriseHarnessHomePreparedTransaction(
    string TransactionId,
    string ReleaseSetId,
    string HarnessHome,
    string OriginalDirectory,
    string OriginalTreeSha256,
    long OriginalFileCount,
    long OriginalSizeBytes);

internal enum EnterpriseHarnessHomeMoveGapPhase
{
    StatePersistedBeforeSecondGuard = 1,
    DescendantsReleasedBeforeMove = 2,
    RootMovedBeforeRelock = 3,
    DestinationRelockedBeforeClone = 4,
}

internal static class EnterpriseHarnessProcessWriterGuard
{
    private static readonly string[] PossibleHarnessWriterProcessNames =
        ["node", "dsh", "deepseek-harness"];

    /// <summary>
    /// Conservative fallback for callers that do not have an installation
    /// layout. Production install and update entry points use the scoped
    /// overload below so unrelated Node applications are not treated as DSH.
    /// </summary>
    public static void RequireNoPossibleHarnessWriter()
        => RequireNoPossibleHarnessWriterCore(managedRoot: null);

    public static void RequireNoPossibleHarnessWriter(
        EnterpriseInstallationLayout layout)
    {
        ArgumentNullException.ThrowIfNull(layout);
        RequireNoPossibleHarnessWriterCore(layout.ManagedRoot);
    }

    private static void RequireNoPossibleHarnessWriterCore(string? managedRoot)
    {
        foreach (var processName in PossibleHarnessWriterProcessNames)
        {
            foreach (var process in Process.GetProcessesByName(processName))
            {
                using (process)
                {
                    try
                    {
                        if (!process.HasExited
                            && IsPossibleHarnessWriter(
                                process.ProcessName,
                                () => process.MainModule?.FileName
                                    ?? throw new InvalidOperationException(
                                        "Harness writer image path is unavailable."),
                                managedRoot))
                        {
                            throw new InvalidOperationException(
                                $"Harness-home update cannot prove writer quiescence while {process.ProcessName} process {process.Id} is running.");
                        }
                    }
                    catch (InvalidOperationException)
                    {
                        throw;
                    }
                    catch (Exception exception) when (exception is System.ComponentModel.Win32Exception
                        or NotSupportedException)
                    {
                        throw new InvalidOperationException(
                            "Harness-home update could not inspect a possible Runtime writer.",
                            exception);
                    }
                }
            }
        }
    }

    internal static bool IsPossibleHarnessWriterForTest(
        string processName,
        Func<string> readExecutablePath,
        string managedRoot)
    {
        ArgumentNullException.ThrowIfNull(readExecutablePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(managedRoot);
        return IsPossibleHarnessWriter(processName, readExecutablePath, managedRoot);
    }

    private static bool IsPossibleHarnessWriter(
        string processName,
        Func<string> readExecutablePath,
        string? managedRoot)
    {
        if (!IsPossibleHarnessWriterName(processName))
        {
            return false;
        }
        if (managedRoot is null)
        {
            return true;
        }

        try
        {
            var executablePath = readExecutablePath();
            if (string.IsNullOrWhiteSpace(executablePath)
                || !Path.IsPathFullyQualified(executablePath))
            {
                throw new InvalidDataException(
                    "Harness writer image path is not absolute.");
            }
            return EnterprisePathGuard.IsSameOrDescendant(
                executablePath,
                managedRoot);
        }
        catch (Exception exception) when (exception is not OutOfMemoryException
            and not StackOverflowException
            and not AccessViolationException)
        {
            throw new InvalidOperationException(
                "Harness-home update could not inspect a possible Runtime writer.",
                exception);
        }
    }

    private static bool IsPossibleHarnessWriterName(string processName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(processName);
        var normalized = processName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
            ? processName[..^4]
            : processName;
        foreach (var possibleWriterName in PossibleHarnessWriterProcessNames)
        {
            if (string.Equals(
                    normalized,
                    possibleWriterName,
                    StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        return false;
    }
}

/// <summary>
/// Protects the complete enterprise Harness home while a candidate Runtime is
/// still in its pre-commit health window. The original directory is moved, not
/// modified, and remains available until an explicit commit or rollback.
/// </summary>
public sealed class EnterpriseHarnessHomeUpdateTransaction
{
    public const string PreparingStatus = "preparing";
    public const string PreparedStatus = "prepared";
    public const string HealthPassedStatus = "health-passed";
    public const string CommittedStatus = "committed";
    public const string RestoredStatus = "restored";

    private const string ActivePointerFileName = "active-transaction.v1.json";
    private const string StateFileName = "transaction.v1.json";
    private const long MaximumFiles = 1_000_000;
    private const long MaximumBytes = 2L * 1024 * 1024 * 1024 * 1024;

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    private readonly string _harnessHome;
    private readonly string _recoveryRoot;
    private readonly TimeProvider _timeProvider;
    private readonly Action<int> _requireQuiescentLoopbackPort;
    private readonly Action _requireNoPossibleHarnessWriter;
    private readonly Action<EnterpriseHarnessHomeMoveGapPhase, string, string>?
        _moveGapHookForTesting;

    public EnterpriseHarnessHomeUpdateTransaction(
        string harnessHome,
        string recoveryRoot,
        TimeProvider? timeProvider = null)
        : this(
            harnessHome,
            recoveryRoot,
            timeProvider,
            null,
            EnterpriseHarnessWriterGuard.RequireQuiescentLoopbackPort,
            EnterpriseHarnessProcessWriterGuard.RequireNoPossibleHarnessWriter)
    {
    }

    internal EnterpriseHarnessHomeUpdateTransaction(
        string harnessHome,
        string recoveryRoot,
        TimeProvider? timeProvider,
        Action<EnterpriseHarnessHomeMoveGapPhase, string, string>?
            moveGapHookForTesting)
        : this(
            harnessHome,
            recoveryRoot,
            timeProvider,
            moveGapHookForTesting,
            EnterpriseHarnessWriterGuard.RequireQuiescentLoopbackPort,
            EnterpriseHarnessProcessWriterGuard.RequireNoPossibleHarnessWriter)
    {
    }

    internal EnterpriseHarnessHomeUpdateTransaction(
        string harnessHome,
        string recoveryRoot,
        TimeProvider? timeProvider,
        Action<EnterpriseHarnessHomeMoveGapPhase, string, string>?
            moveGapHookForTesting,
        Action<int> requireQuiescentLoopbackPort,
        Action requireNoPossibleHarnessWriter)
    {
        _harnessHome = NormalizeAbsoluteDirectory(harnessHome, nameof(harnessHome));
        _recoveryRoot = NormalizeAbsoluteDirectory(recoveryRoot, nameof(recoveryRoot));
        _timeProvider = timeProvider ?? TimeProvider.System;
        _moveGapHookForTesting = moveGapHookForTesting;
        _requireQuiescentLoopbackPort = requireQuiescentLoopbackPort
            ?? throw new ArgumentNullException(nameof(requireQuiescentLoopbackPort));
        _requireNoPossibleHarnessWriter = requireNoPossibleHarnessWriter
            ?? throw new ArgumentNullException(nameof(requireNoPossibleHarnessWriter));
        RequireNonOverlappingSameVolume(_harnessHome, _recoveryRoot);
    }

    public EnterpriseHarnessHomePreparedTransaction Prepare(
        string releaseSetId,
        int loopbackPort,
        Action? validateHomeUnderWriterExclusion = null)
    {
        EnterprisePathGuard.ValidateReleaseId(releaseSetId);
        _requireQuiescentLoopbackPort(loopbackPort);
        _requireNoPossibleHarnessWriter();
        Directory.CreateDirectory(_recoveryRoot);
        RejectReparseChain(_recoveryRoot);
        using var processLock = AcquireLock();
        _ = RecoverInterruptedCore();
        if (File.Exists(ActivePointerPath))
        {
            throw new InvalidOperationException(
                "An enterprise Harness-home update transaction is already active.");
        }

        if (!Directory.Exists(_harnessHome))
        {
            Directory.CreateDirectory(_harnessHome);
        }
        RejectReparseTree(_harnessHome);

        var transactionId = $"{releaseSetId}-{Guid.NewGuid():N}";
        var transactionRoot = CombineExactChild(_recoveryRoot, transactionId);
        var originalDirectory = Path.Combine(transactionRoot, "original");
        var now = _timeProvider.GetUtcNow();
        TreeMeasurement before;
        EnterpriseHarnessHomeRecoveryState state;
        try
        {
            using (var writerExclusion = AcquireWriterExclusion(_harnessHome))
            {
                validateHomeUnderWriterExclusion?.Invoke();
                Directory.CreateDirectory(transactionRoot);
                before = MeasureTree(_harnessHome);
                state = new EnterpriseHarnessHomeRecoveryState(
                    1,
                    transactionId,
                    releaseSetId,
                    PreparingStatus,
                    _harnessHome,
                    originalDirectory,
                    null,
                    before.Sha256,
                    before.FileCount,
                    before.SizeBytes,
                    now,
                    now);
                WriteState(transactionRoot, state);
                WriteJsonAtomically(ActivePointerPath, state);
                _moveGapHookForTesting?.Invoke(
                    EnterpriseHarnessHomeMoveGapPhase.StatePersistedBeforeSecondGuard,
                    _harnessHome,
                    originalDirectory);
                _requireQuiescentLoopbackPort(loopbackPort);
                _requireNoPossibleHarnessWriter();

                // NTFS cannot rename the root while descendant handles remain
                // open. Keep the root DELETE lease, release descendants at the
                // last possible point, rename by handle, then immediately lock
                // and exactly remeasure the destination before cloning it.
                writerExclusion.ReleaseDescendantsForRootMove();
                _moveGapHookForTesting?.Invoke(
                    EnterpriseHarnessHomeMoveGapPhase.DescendantsReleasedBeforeMove,
                    _harnessHome,
                    originalDirectory);
                writerExclusion.MoveRootTo(originalDirectory);
                _moveGapHookForTesting?.Invoke(
                    EnterpriseHarnessHomeMoveGapPhase.RootMovedBeforeRelock,
                    _harnessHome,
                    originalDirectory);
                using var movedOriginalExclusion = AcquireWriterExclusion(
                    originalDirectory);
                var originalAfterMove = MeasureTree(originalDirectory);
                if (originalAfterMove != before)
                {
                    throw new InvalidDataException(
                        "Enterprise Harness home changed during its Windows rename boundary.");
                }
                _moveGapHookForTesting?.Invoke(
                    EnterpriseHarnessHomeMoveGapPhase.DestinationRelockedBeforeClone,
                    _harnessHome,
                    originalDirectory);
                CopyTree(originalDirectory, _harnessHome);
                var candidate = MeasureTree(_harnessHome);
                var originalAfterClone = MeasureTree(originalDirectory);
                if (candidate != before || originalAfterClone != before)
                {
                    throw new InvalidDataException(
                        "Enterprise Harness home changed while its complete recovery generation was cloned.");
                }
            }
            state = state with
            {
                Status = PreparedStatus,
                UpdatedAtUtc = _timeProvider.GetUtcNow(),
            };
            WriteState(transactionRoot, state);
            WriteJsonAtomically(ActivePointerPath, state);
            return ToPrepared(state);
        }
        catch
        {
            try
            {
                if (File.Exists(ActivePointerPath))
                {
                    _ = RestoreOriginal(ReadState(ActivePointerPath), "prepare-failed");
                }
            }
            catch
            {
                // Preserve the preparation failure. The active pointer remains
                // for deterministic recovery on the next Launcher start.
            }
            throw;
        }
    }

    public EnterpriseHarnessHomePreparedTransaction? TryReadPrepared()
    {
        if (!File.Exists(ActivePointerPath))
        {
            return null;
        }
        var state = ReadState(ActivePointerPath);
        return state.Status == PreparedStatus ? ToPrepared(state) : null;
    }

    public EnterpriseHarnessHomeRecoveryState? TryReadActiveState() =>
        File.Exists(ActivePointerPath) ? ReadState(ActivePointerPath) : null;

    public void MarkHealthPassed(string transactionId)
    {
        using var processLock = AcquireLock();
        var state = ReadActiveRequired(transactionId);
        if (state.Status == HealthPassedStatus)
        {
            return;
        }
        if (state.Status != PreparedStatus)
        {
            throw new InvalidOperationException(
                "Only a prepared enterprise Harness-home transaction can pass health.");
        }
        RequireOriginalUnchanged(state);
        _ = MeasureTree(_harnessHome);
        var next = state with
        {
            Status = HealthPassedStatus,
            UpdatedAtUtc = _timeProvider.GetUtcNow(),
        };
        WriteState(GetTransactionRoot(state), next);
        WriteJsonAtomically(ActivePointerPath, next);
    }

    public void FinalizeCommit(string transactionId)
    {
        using var processLock = AcquireLock();
        var state = ReadActiveRequired(transactionId);
        if (state.Status != HealthPassedStatus)
        {
            throw new InvalidOperationException(
                "Only a health-passed enterprise Harness-home transaction can finalize.");
        }
        RequireOriginalUnchanged(state);
        var committed = state with
        {
            Status = CommittedStatus,
            UpdatedAtUtc = _timeProvider.GetUtcNow(),
        };
        WriteState(GetTransactionRoot(state), committed);
        File.Delete(ActivePointerPath);
    }

    public void Commit(string transactionId)
    {
        MarkHealthPassed(transactionId);
        FinalizeCommit(transactionId);
    }

    public EnterpriseHarnessHomeRecoveryState Rollback(
        string transactionId,
        string reasonCode)
    {
        ValidateReason(reasonCode);
        using var processLock = AcquireLock();
        var state = ReadActiveRequired(transactionId);
        if (state.Status is not PreparingStatus
            and not PreparedStatus
            and not HealthPassedStatus)
        {
            throw new InvalidOperationException(
                "Only an uncommitted enterprise Harness-home transaction can roll back.");
        }
        return RestoreOriginal(state, reasonCode);
    }

    public EnterpriseHarnessHomeRecoveryState? RecoverInterrupted()
    {
        Directory.CreateDirectory(_recoveryRoot);
        using var processLock = AcquireLock();
        return RecoverInterruptedCore();
    }

    private EnterpriseHarnessHomeRecoveryState? RecoverInterruptedCore()
    {
        if (!File.Exists(ActivePointerPath))
        {
            return null;
        }
        var state = ReadState(ActivePointerPath);
        if (state.Status is CommittedStatus or RestoredStatus)
        {
            File.Delete(ActivePointerPath);
            return state;
        }
        return RestoreOriginal(state, "interrupted-update");
    }

    private EnterpriseHarnessHomeRecoveryState RestoreOriginal(
        EnterpriseHarnessHomeRecoveryState state,
        string reasonCode)
    {
        ValidateState(state);
        ValidateReason(reasonCode);
        var transactionRoot = GetTransactionRoot(state);
        if (!Directory.Exists(state.OriginalDirectory))
        {
            if (Directory.Exists(_harnessHome)
                && MeasureTree(_harnessHome) == OriginalMeasurement(state))
            {
                var alreadyRestored = state with
                {
                    Status = RestoredStatus,
                    UpdatedAtUtc = _timeProvider.GetUtcNow(),
                };
                WriteState(transactionRoot, alreadyRestored);
                File.Delete(ActivePointerPath);
                return alreadyRestored;
            }
            throw new DirectoryNotFoundException(
                "Enterprise Harness-home recovery generation is missing.");
        }
        RequireOriginalUnchanged(state);

        string? failedDirectory = state.FailedCandidateDirectory;
        if (Directory.Exists(_harnessHome))
        {
            failedDirectory ??= Path.Combine(
                transactionRoot,
                $"failed-{NormalizeReason(reasonCode)}-{_timeProvider.GetUtcNow():yyyyMMddTHHmmssfffffffZ}");
            if (Directory.Exists(failedDirectory))
            {
                throw new IOException("Enterprise failed-candidate quarantine already exists.");
            }
            Directory.Move(_harnessHome, failedDirectory);
        }
        Directory.Move(state.OriginalDirectory, _harnessHome);
        if (MeasureTree(_harnessHome) != OriginalMeasurement(state))
        {
            throw new InvalidDataException(
                "Restored enterprise Harness home failed its complete-tree verification.");
        }
        var restored = state with
        {
            Status = RestoredStatus,
            FailedCandidateDirectory = failedDirectory,
            UpdatedAtUtc = _timeProvider.GetUtcNow(),
        };
        WriteState(transactionRoot, restored);
        File.Delete(ActivePointerPath);
        return restored;
    }

    private void RequireOriginalUnchanged(EnterpriseHarnessHomeRecoveryState state)
    {
        RejectReparseTree(state.OriginalDirectory);
        if (MeasureTree(state.OriginalDirectory) != OriginalMeasurement(state))
        {
            throw new InvalidDataException(
                "Enterprise Harness-home recovery generation was modified.");
        }
    }

    private EnterpriseHarnessHomeRecoveryState ReadActiveRequired(string transactionId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(transactionId);
        var state = ReadState(ActivePointerPath);
        if (!string.Equals(state.TransactionId, transactionId, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Enterprise Harness-home transaction identity does not match the active update.");
        }
        return state;
    }

    private EnterpriseHarnessHomeRecoveryState ReadState(string path)
    {
        var fullPath = Path.GetFullPath(path);
        if (!File.Exists(fullPath)
            || !IsSameOrDescendant(fullPath, _recoveryRoot)
            || (File.GetAttributes(fullPath) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException("Enterprise Harness-home recovery state path is unsafe.");
        }
        var state = JsonSerializer.Deserialize<EnterpriseHarnessHomeRecoveryState>(
            File.ReadAllBytes(fullPath),
            JsonOptions) ?? throw new InvalidDataException(
                "Enterprise Harness-home recovery state is empty.");
        ValidateState(state);
        return state;
    }

    private void ValidateState(EnterpriseHarnessHomeRecoveryState state)
    {
        if (state.SchemaVersion != 1
            || state.TransactionId.Length is < 10 or > 160
            || state.TransactionId.Any(character => !char.IsAsciiLetterOrDigit(character)
                && character is not '-' and not '.' and not '_')
            || state.Status is not PreparingStatus
                and not PreparedStatus
                and not HealthPassedStatus
                and not CommittedStatus
                and not RestoredStatus
            || !string.Equals(state.HarnessHome, _harnessHome, StringComparison.OrdinalIgnoreCase)
            || !IsSameOrDescendant(state.OriginalDirectory, _recoveryRoot)
            || (state.FailedCandidateDirectory is not null
                && !IsSameOrDescendant(state.FailedCandidateDirectory, _recoveryRoot))
            || !EnterpriseHash.IsSha256(state.OriginalTreeSha256)
            || state.OriginalFileCount < 0
            || state.OriginalFileCount > MaximumFiles
            || state.OriginalSizeBytes < 0
            || state.OriginalSizeBytes > MaximumBytes
            || state.CreatedAtUtc.Offset != TimeSpan.Zero
            || state.UpdatedAtUtc.Offset != TimeSpan.Zero
            || state.UpdatedAtUtc < state.CreatedAtUtc)
        {
            throw new InvalidDataException("Enterprise Harness-home recovery state is invalid.");
        }
        EnterprisePathGuard.ValidateReleaseId(state.ReleaseSetId);
    }

    private static EnterpriseHarnessHomePreparedTransaction ToPrepared(
        EnterpriseHarnessHomeRecoveryState state) => new(
            state.TransactionId,
            state.ReleaseSetId,
            state.HarnessHome,
            state.OriginalDirectory,
            state.OriginalTreeSha256,
            state.OriginalFileCount,
            state.OriginalSizeBytes);

    private static TreeMeasurement OriginalMeasurement(
        EnterpriseHarnessHomeRecoveryState state) => new(
            state.OriginalTreeSha256,
            state.OriginalFileCount,
            state.OriginalSizeBytes);

    private string GetTransactionRoot(EnterpriseHarnessHomeRecoveryState state) =>
        CombineExactChild(_recoveryRoot, state.TransactionId);

    private string ActivePointerPath => Path.Combine(_recoveryRoot, ActivePointerFileName);

    private static string NormalizeAbsoluteDirectory(string path, string parameterName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (!Path.IsPathFullyQualified(path)
            || path.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                .Any(segment => segment == ".."))
        {
            throw new ArgumentException("Recovery paths must be absolute and canonical.", parameterName);
        }
        return Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
    }

    private static void RequireNonOverlappingSameVolume(string home, string recovery)
    {
        if (IsSameOrDescendant(home, recovery)
            || IsSameOrDescendant(recovery, home)
            || !string.Equals(
                Path.GetPathRoot(home),
                Path.GetPathRoot(recovery),
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "Harness home and recovery root must be separate directories on one volume.");
        }
    }

    private static string CombineExactChild(string root, string child)
    {
        var result = Path.GetFullPath(Path.Combine(root, child));
        if (!IsStrictDescendant(result, root)
            || !string.Equals(Path.GetFileName(result), child, StringComparison.Ordinal))
        {
            throw new InvalidDataException("Recovery transaction path escaped its root.");
        }
        return result;
    }

    private static void CopyTree(string source, string destination)
    {
        RejectReparseTree(source);
        Directory.CreateDirectory(destination);
        foreach (var directory in Directory.EnumerateDirectories(source, "*", SearchOption.AllDirectories))
        {
            var relative = Path.GetRelativePath(source, directory);
            Directory.CreateDirectory(Path.Combine(destination, relative));
        }
        foreach (var file in Directory.EnumerateFiles(source, "*", SearchOption.AllDirectories))
        {
            var relative = Path.GetRelativePath(source, file);
            var target = Path.Combine(destination, relative);
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            using var input = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read);
            using var output = new FileStream(
                target,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                128 * 1024,
                FileOptions.WriteThrough);
            input.CopyTo(output, 128 * 1024);
            output.Flush(flushToDisk: true);
            File.SetLastWriteTimeUtc(target, File.GetLastWriteTimeUtc(file));
        }
    }

    private static WriterExclusionLease AcquireWriterExclusion(string root)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "Enterprise Harness-home writer exclusion requires Windows file sharing semantics.");
        }

        var directoryLeases = new List<SafeFileHandle>();
        var fileLeases = new List<FileStream>();
        try
        {
            var pending = new Queue<string>();
            var rootLease = OpenDirectoryWriterExclusionLease(
                root,
                requireDeleteAccess: true);
            directoryLeases.Add(rootLease);
            pending.Enqueue(root);
            while (pending.TryDequeue(out var directory))
            {
                foreach (var path in Directory.EnumerateFileSystemEntries(
                             directory,
                             "*",
                             SearchOption.TopDirectoryOnly))
                {
                    var attributes = File.GetAttributes(path);
                    if ((attributes & FileAttributes.ReparsePoint) != 0)
                    {
                        throw new InvalidDataException(
                            "Enterprise Harness-home writer exclusion does not traverse filesystem links.");
                    }
                    if ((attributes & FileAttributes.Directory) != 0)
                    {
                        directoryLeases.Add(OpenDirectoryWriterExclusionLease(
                            path,
                            requireDeleteAccess: false));
                        pending.Enqueue(path);
                    }
                    else
                    {
                        fileLeases.Add(new FileStream(
                            path,
                            FileMode.Open,
                            FileAccess.Read,
                            FileShare.Read | FileShare.Delete,
                            1,
                            FileOptions.SequentialScan));
                    }
                }
            }
            return new WriterExclusionLease(
                root,
                rootLease,
                directoryLeases,
                fileLeases);
        }
        catch (Exception exception) when (exception is IOException
            or UnauthorizedAccessException)
        {
            DisposeWriterExclusionLeases(directoryLeases, fileLeases);
            throw new InvalidOperationException(
                "Enterprise Harness-home update could not exclude an open foreign writer.",
                exception);
        }
        catch
        {
            DisposeWriterExclusionLeases(directoryLeases, fileLeases);
            throw;
        }
    }

    private static SafeFileHandle OpenDirectoryWriterExclusionLease(
        string path,
        bool requireDeleteAccess)
    {
        const uint fileListDirectory = 0x00000001;
        const uint deleteAccess = 0x00010000;
        const uint fileFlagBackupSemantics = 0x02000000;
        const uint fileFlagOpenReparsePoint = 0x00200000;
        var handle = CreateFileW(
            EnterpriseMaintenanceIntegrity.ToExtendedWindowsPath(path),
            fileListDirectory | (requireDeleteAccess ? deleteAccess : 0),
            FileShare.Read | FileShare.Delete,
            IntPtr.Zero,
            FileMode.Open,
            fileFlagBackupSemantics | fileFlagOpenReparsePoint,
            IntPtr.Zero);
        if (!handle.IsInvalid)
        {
            return handle;
        }
        var error = Marshal.GetLastPInvokeError();
        handle.Dispose();
        throw new IOException(
            $"Could not acquire a write-denying directory lease for '{path}'.",
            new System.ComponentModel.Win32Exception(error));
    }

    private static void MoveDirectoryByHandle(
        SafeFileHandle directoryHandle,
        string source,
        string destination)
    {
        const int fileRenameInfo = 3;
        var fullSource = Path.GetFullPath(source);
        var fullDestination = Path.GetFullPath(destination);
        if (!Path.IsPathFullyQualified(fullDestination)
            || !string.Equals(
                Path.GetPathRoot(fullSource),
                Path.GetPathRoot(fullDestination),
                StringComparison.OrdinalIgnoreCase)
            || Directory.Exists(fullDestination)
            || File.Exists(fullDestination))
        {
            throw new IOException(
                "The enterprise Harness-home move destination must be absent on the same volume.");
        }

        var fileNameBytes = Encoding.Unicode.GetBytes(
            EnterpriseMaintenanceIntegrity.ToExtendedWindowsPath(fullDestination));
        var rootDirectoryOffset = IntPtr.Size == 8 ? 8 : 4;
        var fileNameLengthOffset = IntPtr.Size == 8 ? 16 : 8;
        var fileNameOffset = IntPtr.Size == 8 ? 20 : 12;
        var bufferBytes = new byte[checked(fileNameOffset + fileNameBytes.Length + sizeof(char))];
        BinaryPrimitives.WriteUInt32LittleEndian(bufferBytes.AsSpan(0, 4), 0);
        if (IntPtr.Size == 8)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(
                bufferBytes.AsSpan(rootDirectoryOffset, 8),
                0);
        }
        else
        {
            BinaryPrimitives.WriteUInt32LittleEndian(
                bufferBytes.AsSpan(rootDirectoryOffset, 4),
                0);
        }
        BinaryPrimitives.WriteUInt32LittleEndian(
            bufferBytes.AsSpan(fileNameLengthOffset, 4),
            checked((uint)fileNameBytes.Length));
        fileNameBytes.CopyTo(bufferBytes.AsSpan(fileNameOffset));

        var buffer = Marshal.AllocHGlobal(bufferBytes.Length);
        try
        {
            Marshal.Copy(bufferBytes, 0, buffer, bufferBytes.Length);
            if (!SetFileInformationByHandle(
                    directoryHandle,
                    fileRenameInfo,
                    buffer,
                    checked((uint)bufferBytes.Length)))
            {
                var error = Marshal.GetLastPInvokeError();
                throw new IOException(
                    $"Could not move the write-excluded enterprise Harness home to '{fullDestination}'.",
                    new System.ComponentModel.Win32Exception(error));
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static void DisposeWriterExclusionLeases(
        IReadOnlyList<SafeFileHandle> directoryLeases,
        IReadOnlyList<FileStream> fileLeases)
    {
        foreach (var lease in fileLeases)
        {
            lease.Dispose();
        }
        foreach (var lease in directoryLeases)
        {
            lease.Dispose();
        }
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(
        string fileName,
        uint desiredAccess,
        FileShare shareMode,
        IntPtr securityAttributes,
        FileMode creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(
        SafeFileHandle fileHandle,
        int fileInformationClass,
        IntPtr fileInformation,
        uint bufferSize);

    private static TreeMeasurement MeasureTree(string root)
    {
        RejectReparseTree(root);
        using var aggregate = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        long fileCount = 0;
        long sizeBytes = 0;
        foreach (var directory in Directory.EnumerateDirectories(root, "*", SearchOption.AllDirectories)
                     .Select(path => Path.GetRelativePath(root, path).Replace('\\', '/'))
                     .Order(StringComparer.Ordinal))
        {
            AppendRecord(aggregate, "d", directory, 0, []);
        }
        foreach (var path in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories)
                     .OrderBy(path => Path.GetRelativePath(root, path).Replace('\\', '/'), StringComparer.Ordinal))
        {
            var info = new FileInfo(path);
            fileCount = checked(fileCount + 1);
            sizeBytes = checked(sizeBytes + info.Length);
            if (fileCount > MaximumFiles || sizeBytes > MaximumBytes)
            {
                throw new InvalidDataException("Enterprise Harness home exceeds recovery limits.");
            }
            using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                128 * 1024,
                FileOptions.SequentialScan);
            AppendRecord(
                aggregate,
                "f",
                Path.GetRelativePath(root, path).Replace('\\', '/'),
                info.Length,
                SHA256.HashData(stream));
        }
        return new TreeMeasurement(
            Convert.ToHexStringLower(aggregate.GetHashAndReset()),
            fileCount,
            sizeBytes);
    }

    private static void AppendRecord(
        IncrementalHash aggregate,
        string kind,
        string relative,
        long length,
        ReadOnlySpan<byte> digest)
    {
        aggregate.AppendData(Encoding.UTF8.GetBytes(kind));
        aggregate.AppendData([0]);
        aggregate.AppendData(Encoding.UTF8.GetBytes(relative));
        aggregate.AppendData([0]);
        aggregate.AppendData(Encoding.ASCII.GetBytes(length.ToString(
            System.Globalization.CultureInfo.InvariantCulture)));
        aggregate.AppendData([0]);
        aggregate.AppendData(digest);
        aggregate.AppendData([0]);
    }

    private static void RejectReparseTree(string root)
    {
        if (!Directory.Exists(root))
        {
            throw new DirectoryNotFoundException(root);
        }
        RejectReparseChain(root);
        foreach (var path in Directory.EnumerateFileSystemEntries(root, "*", SearchOption.AllDirectories))
        {
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException(
                    "Enterprise Harness-home recovery does not traverse filesystem links.");
            }
        }
    }

    private static void RejectReparseChain(string path)
    {
        var current = new DirectoryInfo(Path.GetFullPath(path));
        while (current is not null)
        {
            if (current.Exists
                && (current.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException("Recovery path crosses a filesystem link.");
            }
            current = current.Parent;
        }
    }

    private static bool IsSameOrDescendant(string candidate, string root)
    {
        var normalizedCandidate = Path.TrimEndingDirectorySeparator(Path.GetFullPath(candidate));
        var normalizedRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
        return string.Equals(normalizedCandidate, normalizedRoot, StringComparison.OrdinalIgnoreCase)
            || normalizedCandidate.StartsWith(
                normalizedRoot + Path.DirectorySeparatorChar,
                StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsStrictDescendant(string candidate, string root) =>
        !string.Equals(
            Path.TrimEndingDirectorySeparator(Path.GetFullPath(candidate)),
            Path.TrimEndingDirectorySeparator(Path.GetFullPath(root)),
            StringComparison.OrdinalIgnoreCase)
        && IsSameOrDescendant(candidate, root);

    private void WriteState(string transactionRoot, EnterpriseHarnessHomeRecoveryState state)
    {
        ValidateState(state);
        WriteJsonAtomically(Path.Combine(transactionRoot, StateFileName), state);
    }

    private static void WriteJsonAtomically(string path, EnterpriseHarnessHomeRecoveryState state)
    {
        var parent = Path.GetDirectoryName(path)
            ?? throw new InvalidDataException("Recovery state path has no parent.");
        Directory.CreateDirectory(parent);
        var temporary = Path.Combine(parent, $".{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp");
        try
        {
            using (var stream = new FileStream(
                       temporary,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       4096,
                       FileOptions.WriteThrough))
            {
                JsonSerializer.Serialize(stream, state, JsonOptions);
                stream.Flush(flushToDisk: true);
            }
            File.Move(temporary, path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
            }
        }
    }

    private FileStream AcquireLock()
    {
        Directory.CreateDirectory(_recoveryRoot);
        return new FileStream(
            Path.Combine(_recoveryRoot, "transaction.lock"),
            FileMode.OpenOrCreate,
            FileAccess.ReadWrite,
            FileShare.None,
            1,
            FileOptions.WriteThrough);
    }

    private static void ValidateReason(string reasonCode)
    {
        _ = NormalizeReason(reasonCode);
    }

    private static string NormalizeReason(string reasonCode)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reasonCode);
        var normalized = new string(reasonCode
            .Select(character => char.IsAsciiLetterOrDigit(character) ? character : '-')
            .ToArray()).Trim('-');
        if (normalized.Length is < 1 or > 64)
        {
            throw new ArgumentException("Recovery reason code is invalid.", nameof(reasonCode));
        }
        return normalized;
    }

    private readonly record struct TreeMeasurement(
        string Sha256,
        long FileCount,
        long SizeBytes);

    private sealed class WriterExclusionLease(
        string root,
        SafeFileHandle rootLease,
        List<SafeFileHandle> directoryLeases,
        List<FileStream> fileLeases) : IDisposable
    {
        private bool _descendantsReleased;
        private bool _disposed;

        public void ReleaseDescendantsForRootMove()
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_descendantsReleased)
            {
                throw new InvalidOperationException(
                    "Enterprise Harness-home descendant writer exclusions were already released.");
            }
            foreach (var lease in fileLeases)
            {
                lease.Dispose();
            }
            for (var index = directoryLeases.Count - 1; index >= 1; index--)
            {
                directoryLeases[index].Dispose();
            }
            _descendantsReleased = true;
        }

        public void MoveRootTo(string destination)
        {
            if (!_descendantsReleased)
            {
                throw new InvalidOperationException(
                    "Enterprise Harness-home descendant writer exclusions must be released before the Windows root rename.");
            }
            MoveDirectoryByHandle(rootLease, root, destination);
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }
            _disposed = true;
            DisposeWriterExclusionLeases(directoryLeases, fileLeases);
        }
    }
}
