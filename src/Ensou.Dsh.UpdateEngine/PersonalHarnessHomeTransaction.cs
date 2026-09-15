using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Win32.SafeHandles;

namespace Ensou.Dsh.UpdateEngine;

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record PersonalHarnessHomeRecoveryState(
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
    DateTimeOffset UpdatedAtUtc,
    string? CandidateTreeSha256 = null,
    long? CandidateFileCount = null,
    long? CandidateSizeBytes = null);

public sealed record PersonalHarnessHomeCandidateEvidence(
    string TreeSha256,
    long FileCount,
    long SizeBytes);

internal enum PersonalHarnessHomeMoveGapPhase
{
    DescendantsReleasedBeforeMove = 1,
    RootMovedBeforeRelock = 2,
    DestinationRelockedBeforeClone = 3,
}

public static class PersonalHarnessWriterGuard
{
    public static void RequireQuiescentLoopbackPort(int port)
    {
        RequireAvailableLoopbackPort(port);
        RequireLegacyWriterQuiescence();
    }

    public static void RequireAvailableLoopbackPort(int port)
    {
        if (port is < 1 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(port));
        }
        var listeners = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners();
        if (listeners.Any(endpoint => endpoint.Port == port
            && (IPAddress.IsLoopback(endpoint.Address)
                || endpoint.Address.Equals(IPAddress.Any)
                || endpoint.Address.Equals(IPAddress.IPv6Any))))
        {
            throw new InvalidOperationException(
                $"Harness port {port} is still owned by a managed or foreign process.");
        }
    }

    private static void RequireLegacyWriterQuiescence()
    {
        foreach (var processName in new[] { "node", "dsh", "deepseek-harness" })
        {
            foreach (var process in Process.GetProcessesByName(processName))
            {
                using (process)
                {
                    try
                    {
                        if (!process.HasExited && IsPossibleHarnessWriter(process))
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

    private static bool IsPossibleHarnessWriter(Process process)
    {
        // Legacy, nonempty homes have no cooperative runtime-generation record.
        // Enrollment retains this conservative check once; enrolled homes use
        // their home lease and exact Job termination evidence instead.
        return ClassifyPossibleHarnessWriter(process.ProcessName);
    }

    internal static bool ClassifyPossibleHarnessWriter(string processName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(processName);
        return string.Equals(processName, "node", StringComparison.OrdinalIgnoreCase)
            || string.Equals(processName, "node.exe", StringComparison.OrdinalIgnoreCase)
            || string.Equals(processName, "dsh", StringComparison.OrdinalIgnoreCase)
            || string.Equals(processName, "dsh.exe", StringComparison.OrdinalIgnoreCase)
            || string.Equals(processName, "deepseek-harness", StringComparison.OrdinalIgnoreCase)
            || string.Equals(processName, "deepseek-harness.exe", StringComparison.OrdinalIgnoreCase);
    }
}

internal enum PersonalHarnessHomeRollbackCheckpoint
{
    RestoredJournalWritten,
    RestoredActiveWritten,
    HealthAttemptAborted,
    LegacyCoordinationPrepared,
}

/// <summary>
/// Keeps the complete local Harness home recoverable while a candidate runtime
/// is in its pre-user-activity health window. The original tree is moved aside
/// on the same volume and a byte-verified clone becomes the candidate home.
/// </summary>
public sealed class PersonalHarnessHomeTransaction
{
    public const string PreparingStatus = "preparing";
    public const string PreparedStatus = "prepared";
    public const string HealthPassedStatus = "health-passed";
    public const string CommittedStatus = "committed";
    public const string RestoredStatus = "restored";

    private const string ActiveFileName = "active-transaction.v1.json";
    private const string StateFileName = "transaction.v1.json";
    private const long MaximumFiles = 1_000_000;
    private const long MaximumBytes = 2L * 1024 * 1024 * 1024 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        AllowTrailingCommas = false,
        MaxDepth = 32,
        NumberHandling = JsonNumberHandling.Strict,
        PropertyNameCaseInsensitive = false,
        ReadCommentHandling = JsonCommentHandling.Disallow,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        WriteIndented = false,
    };

    private readonly string _harnessHome;
    private readonly string _recoveryRoot;
    private readonly TimeProvider _timeProvider;
    private readonly Action<int> _writerGuard;
    private readonly Action<int> _legacyEnrollmentGuard;
    private readonly PersonalHarnessHomeLease? _homeLease;
    private readonly Action<PersonalHarnessHomeMoveGapPhase, string, string>?
        _moveGapHookForTesting;
    private readonly Action<PersonalHarnessHomeRollbackCheckpoint>? _rollbackCheckpointForTesting;
    private VerifiedRollbackProof? _verifiedRollbackProof;

    public PersonalHarnessHomeTransaction(
        string harnessHome,
        string recoveryRoot,
        TimeProvider? timeProvider = null)
        : this(
            harnessHome,
            recoveryRoot,
            timeProvider,
            null,
            writerGuardForTesting: null)
    {
    }

    public PersonalHarnessHomeTransaction(
        string harnessHome,
        string recoveryRoot,
        PersonalHarnessHomeLease homeLease,
        TimeProvider? timeProvider = null)
        : this(
            harnessHome,
            recoveryRoot,
            timeProvider,
            moveGapHookForTesting: null,
            writerGuardForTesting: null,
            homeLease: homeLease ?? throw new ArgumentNullException(nameof(homeLease)))
    {
    }

    internal PersonalHarnessHomeTransaction(
        string harnessHome,
        string recoveryRoot,
        TimeProvider? timeProvider,
        Action<PersonalHarnessHomeMoveGapPhase, string, string>? moveGapHookForTesting,
        Action<int>? writerGuardForTesting = null,
        PersonalHarnessHomeLease? homeLease = null,
        Action<PersonalHarnessHomeRollbackCheckpoint>? rollbackCheckpointForTesting = null)
    {
        _harnessHome = PersonalPathGuard.NormalizeDirectory(harnessHome);
        _recoveryRoot = PersonalPathGuard.NormalizeDirectory(recoveryRoot);
        _timeProvider = timeProvider ?? TimeProvider.System;
        _writerGuard = writerGuardForTesting
            ?? PersonalHarnessWriterGuard.RequireAvailableLoopbackPort;
        _legacyEnrollmentGuard = writerGuardForTesting
            ?? PersonalHarnessWriterGuard.RequireQuiescentLoopbackPort;
        _homeLease = homeLease;
        _moveGapHookForTesting = moveGapHookForTesting;
        _rollbackCheckpointForTesting = rollbackCheckpointForTesting;
        if (PersonalPathGuard.IsSameOrDescendant(_harnessHome, _recoveryRoot)
            || PersonalPathGuard.IsSameOrDescendant(_recoveryRoot, _harnessHome)
            || !string.Equals(
                Path.GetPathRoot(_harnessHome),
                Path.GetPathRoot(_recoveryRoot),
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "Harness home and recovery root must be separate directories on one volume.");
        }
    }

    public PersonalHarnessHomeRecoveryState Prepare(string releaseSetId, int loopbackPort)
    {
        PersonalPathGuard.ValidateReleaseId(releaseSetId);
        using var homeAdmission = AcquireHomeMutationAdmission(loopbackPort);
        _writerGuard(loopbackPort);
        Directory.CreateDirectory(_recoveryRoot);
        RejectReparseChain(_recoveryRoot);
        using var processLock = AcquireLock();
        _ = RecoverInterruptedCore(_homeLease ?? homeAdmission!);
        if (File.Exists(ActivePath))
        {
            throw new InvalidOperationException(
                "A personal Harness-home update transaction is already active.");
        }

        if (!Directory.Exists(_harnessHome))
        {
            Directory.CreateDirectory(_harnessHome);
        }
        RejectReparseTree(_harnessHome);

        var transactionId = $"{releaseSetId}-{Guid.NewGuid():N}";
        var transactionRoot = CombineTransactionRoot(transactionId);
        var originalDirectory = Path.Combine(transactionRoot, "original");
        var now = _timeProvider.GetUtcNow();
        TreeMeasurement before;
        PersonalHarnessHomeRecoveryState state;
        try
        {
            using (var writerExclusion = AcquireWriterExclusion(_harnessHome))
            {
                Directory.CreateDirectory(transactionRoot);
                before = MeasureTree(_harnessHome);
                state = new PersonalHarnessHomeRecoveryState(
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
                WriteStateFile(ActivePath, state);
                _writerGuard(loopbackPort);
                // NTFS refuses a parent-directory rename while any descendant
                // handle remains open, even when every handle shares DELETE.
                // Keep the root lease, perform the handle-based rename, then
                // immediately reacquire every destination lease and require the
                // canonical tree to equal the pre-release measurement. A path-
                // based child create is not excluded by a directory share mode;
                // the exact post-rename and post-clone measurements are therefore
                // part of the exclusion protocol, not merely diagnostics.
                writerExclusion.ReleaseDescendantsForRootMove();
                _moveGapHookForTesting?.Invoke(
                    PersonalHarnessHomeMoveGapPhase.DescendantsReleasedBeforeMove,
                    _harnessHome,
                    originalDirectory);
                writerExclusion.MoveRootTo(originalDirectory);
                _moveGapHookForTesting?.Invoke(
                    PersonalHarnessHomeMoveGapPhase.RootMovedBeforeRelock,
                    _harnessHome,
                    originalDirectory);
                using var movedOriginalExclusion = AcquireWriterExclusion(
                    originalDirectory);
                var originalAfterMove = MeasureTree(originalDirectory);
                if (originalAfterMove != before)
                {
                    throw new InvalidDataException(
                        "Harness home changed during its Windows rename boundary.");
                }
                _moveGapHookForTesting?.Invoke(
                    PersonalHarnessHomeMoveGapPhase.DestinationRelockedBeforeClone,
                    _harnessHome,
                    originalDirectory);
                CopyTree(originalDirectory, _harnessHome);
                var candidate = MeasureTree(_harnessHome);
                var originalAfterClone = MeasureTree(originalDirectory);
                if (candidate != before || originalAfterClone != before)
                {
                    throw new InvalidDataException(
                        "Harness home changed while its complete recovery generation was cloned.");
                }
            }
            state = state with
            {
                Status = PreparedStatus,
                UpdatedAtUtc = _timeProvider.GetUtcNow(),
            };
            WriteState(transactionRoot, state);
            WriteStateFile(ActivePath, state);
            return state;
        }
        catch
        {
            try
            {
                if (File.Exists(ActivePath))
                {
                    _ = RestoreOriginal(
                        ReadState(ActivePath), "prepare-failed", _homeLease ?? homeAdmission!);
                }
            }
            catch
            {
                // The active record intentionally remains for deterministic recovery.
            }
            throw;
        }
    }

    public PersonalHarnessHomeRecoveryState? TryReadActive() =>
        File.Exists(ActivePath) ? ReadState(ActivePath) : null;

    public void MarkHealthPassed(string transactionId)
    {
        using var homeAdmission = AcquireHomeMutationAdmission();
        using var processLock = AcquireLock();
        var state = ReadActiveRequired(transactionId);
        if (state.Status == HealthPassedStatus)
        {
            return;
        }
        if (state.Status != PreparedStatus)
        {
            throw new InvalidOperationException(
                "Only a prepared personal Harness-home transaction can pass health.");
        }
        RequireOriginalUnchanged(state);
        using var candidateExclusion = AcquireWriterExclusion(_harnessHome);
        RequireCandidateUnchanged(state);
        var next = state with
        {
            Status = HealthPassedStatus,
            UpdatedAtUtc = _timeProvider.GetUtcNow(),
        };
        WriteState(GetTransactionRoot(state), next);
        WriteStateFile(ActivePath, next);
    }

    public PersonalHarnessHomeCandidateEvidence VerifyCandidateReadable(
        string transactionId)
    {
        using var homeAdmission = AcquireHomeMutationAdmission();
        using var processLock = AcquireLock();
        var state = ReadActiveRequired(transactionId);
        if (state.Status != PreparedStatus)
        {
            throw new InvalidOperationException(
                "Only a prepared personal Harness-home candidate can be verified.");
        }
        using var candidateExclusion = AcquireWriterExclusion(_harnessHome);
        var measured = MeasureTree(_harnessHome);
        var next = state with
        {
            CandidateTreeSha256 = measured.Sha256,
            CandidateFileCount = measured.FileCount,
            CandidateSizeBytes = measured.SizeBytes,
            UpdatedAtUtc = _timeProvider.GetUtcNow(),
        };
        WriteState(GetTransactionRoot(state), next);
        WriteStateFile(ActivePath, next);
        return new PersonalHarnessHomeCandidateEvidence(
            measured.Sha256,
            measured.FileCount,
            measured.SizeBytes);
    }

    public void FinalizeCommit(string transactionId)
    {
        using var homeAdmission = AcquireHomeMutationAdmission();
        using var processLock = AcquireLock();
        var state = ReadActiveRequired(transactionId);
        if (state.Status is not HealthPassedStatus and not CommittedStatus)
        {
            throw new InvalidOperationException(
                "Only a health-passed personal Harness-home transaction can commit.");
        }
        RequireOriginalUnchanged(state);
        using var candidateExclusion = AcquireWriterExclusion(_harnessHome);
        RequireCandidateUnchanged(state);
        var committed = state with
        {
            Status = CommittedStatus,
            UpdatedAtUtc = _timeProvider.GetUtcNow(),
        };
        WriteState(GetTransactionRoot(state), committed);
        (_homeLease ?? homeAdmission!).AbortHealthAttempt(state.TransactionId);
        File.Delete(ActivePath);
    }

    public PersonalHarnessHomeRecoveryState Rollback(
        string transactionId,
        string reasonCode)
    {
        using var homeAdmission = AcquireHomeMutationAdmission();
        using var processLock = AcquireLock();
        var state = ReadActiveRequired(transactionId);
        if (state.Status is not PreparingStatus
            and not PreparedStatus
            and not HealthPassedStatus
            and not RestoredStatus)
        {
            throw new InvalidOperationException(
                "Only an uncommitted personal Harness-home transaction can roll back.");
        }
        return RestoreOriginal(state, reasonCode, _homeLease ?? homeAdmission!);
    }

    public PersonalHarnessHomeRecoveryState? RecoverInterrupted()
    {
        using var homeAdmission = AcquireHomeMutationAdmission();
        Directory.CreateDirectory(_recoveryRoot);
        using var processLock = AcquireLock();
        return RecoverInterruptedCore(_homeLease ?? homeAdmission!);
    }

    private PersonalHarnessHomeLease? AcquireHomeMutationAdmission(
        int loopbackPort = PersonalInstallMigrationService.DefaultLoopbackPort)
    {
        if (_homeLease is not null)
        {
            _homeLease.RequireMutationAdmission(_harnessHome);
            return null;
        }

        var lease = new PersonalHarnessHomeCoordinator(_harnessHome)
            .AcquireLease(() => _legacyEnrollmentGuard(loopbackPort));
        try
        {
            lease.RequireMutationAdmission(_harnessHome);
            return lease;
        }
        catch
        {
            lease.Dispose();
            throw;
        }
    }

    private PersonalHarnessHomeRecoveryState? RecoverInterruptedCore(
        PersonalHarnessHomeLease homeLease)
    {
        if (!File.Exists(ActivePath))
        {
            return null;
        }
        var state = ReadState(ActivePath);
        if (state.Status == CommittedStatus)
        {
            homeLease.AbortHealthAttempt(state.TransactionId);
            File.Delete(ActivePath);
            return state;
        }
        return RestoreOriginal(state, "interrupted-update", homeLease);
    }

    private PersonalHarnessHomeRecoveryState RestoreOriginal(
        PersonalHarnessHomeRecoveryState state,
        string reasonCode,
        PersonalHarnessHomeLease homeLease)
    {
        ValidateReason(reasonCode);
        var transactionRoot = GetTransactionRoot(state);
        if (state.Status == RestoredStatus)
        {
            if (Directory.Exists(state.OriginalDirectory))
                throw new InvalidDataException("A restored transaction still has an ambiguous original recovery directory.");
            return FinalizeVerifiedRollback(state, homeLease);
        }
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
                // A crash may leave the restored journal ahead of the active marker.
                // Retain its failed-candidate reference after verifying its exact transaction binding.
                var journal = ReadState(Path.Combine(transactionRoot, StateFileName));
                if (journal.Status == RestoredStatus)
                {
                    if (journal.TransactionId != state.TransactionId
                        || journal.ReleaseSetId != state.ReleaseSetId
                        || journal.OriginalDirectory != state.OriginalDirectory
                        || journal.CreatedAtUtc != state.CreatedAtUtc
                        || OriginalMeasurement(journal) != OriginalMeasurement(state))
                        throw new InvalidDataException("Restored journal does not match the active rollback transaction.");
                    alreadyRestored = journal;
                }
                return FinalizeVerifiedRollback(alreadyRestored, homeLease);
            }
            throw new DirectoryNotFoundException(
                "Personal Harness-home recovery generation is missing.");
        }
        RequireOriginalUnchanged(state);

        var failedDirectory = state.FailedCandidateDirectory;
        if (Directory.Exists(_harnessHome))
        {
            failedDirectory ??= Path.Combine(
                transactionRoot,
                $"failed-{NormalizeReason(reasonCode)}-{_timeProvider.GetUtcNow():yyyyMMddTHHmmssfffffffZ}");
            if (Directory.Exists(failedDirectory))
            {
                throw new IOException("Personal failed-candidate quarantine already exists.");
            }
            Directory.Move(_harnessHome, failedDirectory);
        }
        Directory.Move(state.OriginalDirectory, _harnessHome);
        if (MeasureTree(_harnessHome) != OriginalMeasurement(state))
        {
            throw new InvalidDataException(
                "Restored personal Harness home failed complete-tree verification.");
        }
        var restored = state with
        {
            Status = RestoredStatus,
            FailedCandidateDirectory = failedDirectory,
            UpdatedAtUtc = _timeProvider.GetUtcNow(),
        };
        return FinalizeVerifiedRollback(restored, homeLease);
    }

    private PersonalHarnessHomeRecoveryState FinalizeVerifiedRollback(
        PersonalHarnessHomeRecoveryState state, PersonalHarnessHomeLease homeLease)
    {
        if (state.Status != RestoredStatus)
            throw new InvalidDataException("Legacy enrollment requires a restored transaction.");
        homeLease.RequireMutationAdmission(_harnessHome);
        using var restoredExclusion = AcquireWriterExclusion(_harnessHome);
        if (MeasureTree(_harnessHome) != OriginalMeasurement(state))
            throw new InvalidDataException("Restored personal Harness home failed complete-tree re-verification.");
        var restored = state with { UpdatedAtUtc = _timeProvider.GetUtcNow() };
        WriteState(GetTransactionRoot(restored), restored);
        _rollbackCheckpointForTesting?.Invoke(PersonalHarnessHomeRollbackCheckpoint.RestoredJournalWritten);
        // Publish rollback intent before removing the atomic generation fence. Health accepts Prepared only.
        WriteStateFile(ActivePath, restored);
        _rollbackCheckpointForTesting?.Invoke(PersonalHarnessHomeRollbackCheckpoint.RestoredActiveWritten);
        homeLease.AbortHealthAttempt(restored.TransactionId);
        _rollbackCheckpointForTesting?.Invoke(PersonalHarnessHomeRollbackCheckpoint.HealthAttemptAborted);
        var proof = new VerifiedRollbackProof(this, homeLease, restored, homeLease.RollbackGenerationId);
        _verifiedRollbackProof = proof;
        try { homeLease.PrepareLegacyCoordinationAfterVerifiedRollback(proof); }
        finally { _verifiedRollbackProof = null; }
        _rollbackCheckpointForTesting?.Invoke(PersonalHarnessHomeRollbackCheckpoint.LegacyCoordinationPrepared);
        File.Delete(ActivePath);
        return restored;
    }

    internal sealed class VerifiedRollbackProof(
        PersonalHarnessHomeTransaction issuer, PersonalHarnessHomeLease lease,
        PersonalHarnessHomeRecoveryState restored, string? generationId)
    {
        private bool _consumed;

        internal void RequireCurrent(PersonalHarnessHomeLease expectedLease, string home, string? currentGenerationId)
        {
            if (_consumed || !ReferenceEquals(issuer._verifiedRollbackProof, this)
                || !ReferenceEquals(lease, expectedLease) || generationId != currentGenerationId
                || restored.Status != RestoredStatus
                || !string.Equals(issuer._harnessHome, home, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("PERSONAL_HOME_COORDINATION_INVALID: Verified rollback proof is stale or belongs to another home.");
        }

        internal void Consume() => _consumed = true;
    }

    private void RequireOriginalUnchanged(PersonalHarnessHomeRecoveryState state)
    {
        RejectReparseTree(state.OriginalDirectory);
        if (MeasureTree(state.OriginalDirectory) != OriginalMeasurement(state))
        {
            throw new InvalidDataException(
                "Personal Harness-home recovery generation was modified.");
        }
    }

    private void RequireCandidateUnchanged(PersonalHarnessHomeRecoveryState state)
    {
        if (state.CandidateTreeSha256 is null
            || state.CandidateFileCount is null
            || state.CandidateSizeBytes is null
            || !Ensou.Dsh.Contracts.PersonalReleaseSetValidator.IsSha256(state.CandidateTreeSha256))
        {
            throw new InvalidDataException(
                "Personal candidate Harness-home evidence is missing.");
        }
        var measured = MeasureTree(_harnessHome);
        if (!string.Equals(measured.Sha256, state.CandidateTreeSha256, StringComparison.Ordinal)
            || measured.FileCount != (state.CandidateFileCount ?? -1)
            || measured.SizeBytes != (state.CandidateSizeBytes ?? -1))
        {
            throw new InvalidDataException(
                "Personal candidate Harness-home changed after health verification.");
        }
    }

    private PersonalHarnessHomeRecoveryState ReadActiveRequired(string transactionId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(transactionId);
        var state = ReadState(ActivePath);
        if (!string.Equals(state.TransactionId, transactionId, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Personal Harness-home transaction identity does not match.");
        }
        return state;
    }

    private PersonalHarnessHomeRecoveryState ReadState(string path)
    {
        var fullPath = Path.GetFullPath(path);
        if (!File.Exists(fullPath)
            || !PersonalPathGuard.IsSameOrDescendant(fullPath, _recoveryRoot)
            || (File.GetAttributes(fullPath) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException(
                "Personal Harness-home recovery state path is unsafe.");
        }
        var state = JsonSerializer.Deserialize<PersonalHarnessHomeRecoveryState>(
            File.ReadAllBytes(fullPath),
            JsonOptions) ?? throw new InvalidDataException(
                "Personal Harness-home recovery state is empty.");
        ValidateState(state);
        return state;
    }

    private void ValidateState(PersonalHarnessHomeRecoveryState state)
    {
        var transactionRoot = CombineTransactionRoot(state.TransactionId);
        var expectedOriginal = Path.Combine(transactionRoot, "original");
        var candidateEvidenceAbsent = state.CandidateTreeSha256 is null
            && state.CandidateFileCount is null
            && state.CandidateSizeBytes is null;
        var candidateEvidenceValid = state.CandidateTreeSha256 is not null
            && state.CandidateFileCount is >= 0 and <= MaximumFiles
            && state.CandidateSizeBytes is >= 0 and <= MaximumBytes
            && Ensou.Dsh.Contracts.PersonalReleaseSetValidator.IsSha256(state.CandidateTreeSha256);
        if (state.SchemaVersion != 1
            || state.TransactionId.Length is < 10 or > 192
            || state.TransactionId.Any(character => !char.IsAsciiLetterOrDigit(character)
                && character is not '-' and not '.' and not '_')
            || state.Status is not PreparingStatus
                and not PreparedStatus
                and not HealthPassedStatus
                and not CommittedStatus
                and not RestoredStatus
            || !string.Equals(state.HarnessHome, _harnessHome, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(
                Path.GetFullPath(state.OriginalDirectory),
                expectedOriginal,
                StringComparison.OrdinalIgnoreCase)
            || (state.FailedCandidateDirectory is not null
                && (!PersonalPathGuard.IsStrictDescendant(
                        state.FailedCandidateDirectory,
                        transactionRoot)
                    || !string.Equals(
                        Path.GetDirectoryName(Path.GetFullPath(state.FailedCandidateDirectory)),
                        transactionRoot,
                        StringComparison.OrdinalIgnoreCase)))
            || !Ensou.Dsh.Contracts.PersonalReleaseSetValidator.IsSha256(
                state.OriginalTreeSha256)
            || state.OriginalFileCount < 0
            || state.OriginalFileCount > MaximumFiles
            || state.OriginalSizeBytes < 0
            || state.OriginalSizeBytes > MaximumBytes
            || !candidateEvidenceAbsent && !candidateEvidenceValid
            || state.Status is PreparingStatus
                && !candidateEvidenceAbsent
            || state.CreatedAtUtc.Offset != TimeSpan.Zero
            || state.UpdatedAtUtc.Offset != TimeSpan.Zero
            || state.UpdatedAtUtc < state.CreatedAtUtc)
        {
            throw new InvalidDataException(
                "Personal Harness-home recovery state is invalid.");
        }
        PersonalPathGuard.ValidateReleaseId(state.ReleaseSetId);
        if (!state.TransactionId.StartsWith(
                state.ReleaseSetId + "-",
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Personal recovery transaction is not bound to its release-set.");
        }
    }

    private string GetTransactionRoot(PersonalHarnessHomeRecoveryState state) =>
        CombineTransactionRoot(state.TransactionId);

    private string CombineTransactionRoot(string transactionId)
    {
        if (transactionId.Length is < 10 or > 192
            || transactionId.Any(character => !char.IsAsciiLetterOrDigit(character)
                && character is not '-' and not '.' and not '_'))
        {
            throw new InvalidDataException("Personal recovery transaction id is invalid.");
        }
        var path = Path.GetFullPath(Path.Combine(_recoveryRoot, transactionId));
        if (!PersonalPathGuard.IsStrictDescendant(path, _recoveryRoot)
            || !string.Equals(Path.GetFileName(path), transactionId, StringComparison.Ordinal))
        {
            throw new InvalidDataException("Personal recovery transaction escaped its root.");
        }
        return path;
    }

    private string ActivePath => Path.Combine(_recoveryRoot, ActiveFileName);

    private static TreeMeasurement OriginalMeasurement(
        PersonalHarnessHomeRecoveryState state) => new(
            state.OriginalTreeSha256,
            state.OriginalFileCount,
            state.OriginalSizeBytes);

    private static void CopyTree(string source, string destination)
    {
        var entries = EnumerateTreeEntries(source).ToArray();
        Directory.CreateDirectory(destination);
        RejectReparseChain(destination);
        foreach (var directory in entries.Where(entry => entry.Kind == "d"))
        {
            Directory.CreateDirectory(Path.Combine(
                destination,
                directory.RelativePath));
        }
        foreach (var entry in entries.Where(entry => entry.Kind == "f"))
        {
            var file = entry.Path;
            var target = Path.Combine(destination, entry.RelativePath);
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            using var input = new FileStream(
                file,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                128 * 1024,
                FileOptions.SequentialScan);
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
        foreach (var entry in entries.Where(entry => entry.Kind == "j"))
        {
            using var junction = PersonalHarnessProfileModuleJunction.OpenRead(source, entry.Path);
            if (!junction.RawData.AsSpan().SequenceEqual(entry.JunctionData!))
                throw new InvalidDataException("A profile-module junction changed before cloning.");
            PersonalHarnessProfileModuleJunction.CreateClone(
                destination, Path.Combine(destination, entry.RelativePath), entry.JunctionData!);
            junction.RequireUnchanged();
        }
    }

    private static WriterExclusionLease AcquireWriterExclusion(string root)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "Personal Harness-home writer exclusion requires Windows file sharing semantics.");
        }

        var directoryLeases = new List<SafeFileHandle>();
        var fileLeases = new List<FileStream>();
        var junctionLeases = new List<PersonalHarnessProfileModuleJunction>();
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
                        junctionLeases.Add(PersonalHarnessProfileModuleJunction.OpenRead(root, path));
                        continue;
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
                fileLeases,
                junctionLeases);
        }
        catch (Exception exception) when (exception is IOException
            or UnauthorizedAccessException)
        {
            DisposeWriterExclusionLeases(directoryLeases, fileLeases, junctionLeases);
            throw new InvalidOperationException(
                "Harness-home update could not exclude an open foreign writer.",
                exception);
        }
        catch
        {
            DisposeWriterExclusionLeases(directoryLeases, fileLeases, junctionLeases);
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
            PersonalHarnessProfileModuleJunction.Extended(path),
            fileListDirectory | (requireDeleteAccess ? deleteAccess : 0),
            FileShare.Read | FileShare.Delete,
            IntPtr.Zero,
            FileMode.Open,
            fileFlagBackupSemantics | fileFlagOpenReparsePoint,
            IntPtr.Zero);
        if (!handle.IsInvalid)
        {
            try
            {
                PersonalHarnessProfileModuleJunction.RequireOrdinaryDirectoryHandle(handle);
                return handle;
            }
            catch { handle.Dispose(); throw; }
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
                "The personal Harness-home move destination must be absent on the same volume.");
        }

        // FILE_RENAME_INFO carries a Win32 absolute path. Use its extended-length
        // form only at the native boundary; logical state paths remain canonical DOS paths.
        var fileNameBytes = Encoding.Unicode.GetBytes(
            PersonalHarnessProfileModuleJunction.Extended(fullDestination));
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
                    $"Could not move the write-excluded Harness home to '{fullDestination}'.",
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
        IReadOnlyList<FileStream> fileLeases,
        IReadOnlyList<PersonalHarnessProfileModuleJunction> junctionLeases)
    {
        foreach (var lease in junctionLeases)
        {
            lease.Dispose();
        }
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
        var entries = EnumerateTreeEntries(root).ToArray();
        using var aggregate = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        long fileCount = 0;
        long sizeBytes = 0;
        foreach (var directory in entries.Where(entry => entry.Kind == "d")
                 .Select(entry => entry.RelativePath)
                 .Order(StringComparer.Ordinal))
        {
            AppendRecord(aggregate, "d", directory, 0, []);
        }
        foreach (var entry in entries.Where(entry => entry.Kind == "f")
                     .OrderBy(entry => entry.RelativePath, StringComparer.Ordinal))
        {
            var path = entry.Path;
            var info = new FileInfo(path);
            fileCount = checked(fileCount + 1);
            sizeBytes = checked(sizeBytes + info.Length);
            if (fileCount > MaximumFiles || sizeBytes > MaximumBytes)
            {
                throw new InvalidDataException(
                    "Personal Harness home exceeds complete-recovery limits.");
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
        // Existing link-free trees retain their exact d/f serialization. A
        // junction is a separately typed leaf, never its target's contents.
        foreach (var entry in entries.Where(entry => entry.Kind == "j")
                     .OrderBy(entry => entry.RelativePath, StringComparer.Ordinal))
        {
            using var junction = PersonalHarnessProfileModuleJunction.OpenRead(root, entry.Path);
            var raw = junction.RawData;
            if (!raw.AsSpan().SequenceEqual(entry.JunctionData!))
                throw new InvalidDataException("A profile-module junction changed during measurement.");
            fileCount = checked(fileCount + 1);
            sizeBytes = checked(sizeBytes + raw.Length);
            if (fileCount > MaximumFiles || sizeBytes > MaximumBytes)
                throw new InvalidDataException("Personal Harness home exceeds complete-recovery limits.");
            AppendRecord(aggregate, "j", entry.RelativePath, raw.Length, SHA256.HashData(raw));
            junction.RequireUnchanged();
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
        foreach (var _ in EnumerateTreeEntries(root)) { }
    }

    private static IEnumerable<HomeTreeEntry> EnumerateTreeEntries(string root)
    {
        if (!Directory.Exists(root))
        {
            throw new DirectoryNotFoundException(root);
        }
        RejectReparseChain(root);
        var pending = new Queue<string>();
        pending.Enqueue(root);
        long count = 0;
        while (pending.TryDequeue(out var directory))
        {
            RejectReparseChain(directory);
            foreach (var path in Directory.EnumerateFileSystemEntries(directory, "*", SearchOption.TopDirectoryOnly))
            {
                if (++count > MaximumFiles)
                    throw new InvalidDataException("Personal Harness home exceeds complete-recovery entry limits.");
                var relative = Path.GetRelativePath(root, path).Replace('\\', '/');
                var attributes = File.GetAttributes(path);
                if ((attributes & FileAttributes.ReparsePoint) != 0)
                {
                    using var junction = PersonalHarnessProfileModuleJunction.OpenRead(root, path);
                    yield return new HomeTreeEntry(path, relative, "j", junction.RawData);
                    continue;
                }
                if ((attributes & FileAttributes.Directory) != 0)
                {
                    yield return new HomeTreeEntry(path, relative, "d", null);
                    pending.Enqueue(path);
                }
                else
                {
                    yield return new HomeTreeEntry(path, relative, "f", null);
                }
            }
        }
    }

    private sealed record HomeTreeEntry(string Path, string RelativePath, string Kind, byte[]? JunctionData);

    private static void RejectReparseChain(string path)
    {
        var current = new DirectoryInfo(Path.GetFullPath(path));
        while (current is not null)
        {
            if (current.Exists && (current.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException("Personal recovery path crosses a filesystem link.");
            }
            current = current.Parent;
        }
    }

    private void WriteState(string transactionRoot, PersonalHarnessHomeRecoveryState state)
    {
        ValidateState(state);
        WriteStateFile(Path.Combine(transactionRoot, StateFileName), state);
    }

    private static void WriteStateFile(string path, PersonalHarnessHomeRecoveryState state)
    {
        var parent = Path.GetDirectoryName(path)
            ?? throw new InvalidDataException("Personal recovery state path has no parent.");
        Directory.CreateDirectory(parent);
        var temporary = Path.Combine(
            parent,
            $".{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp");
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

    private static void ValidateReason(string reasonCode) => _ = NormalizeReason(reasonCode);

    private static string NormalizeReason(string reasonCode)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reasonCode);
        var normalized = new string(reasonCode
            .Select(character => char.IsAsciiLetterOrDigit(character) ? character : '-')
            .ToArray()).Trim('-');
        if (normalized.Length is < 1 or > 64)
        {
            throw new ArgumentException(
                "Personal recovery reason code is invalid.",
                nameof(reasonCode));
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
        List<FileStream> fileLeases,
        List<PersonalHarnessProfileModuleJunction> junctionLeases) : IDisposable
    {
        private bool _descendantsReleased;
        private bool _disposed;

        public void ReleaseDescendantsForRootMove()
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_descendantsReleased)
            {
                throw new InvalidOperationException(
                    "Harness-home descendant writer exclusions were already released.");
            }
            foreach (var lease in fileLeases)
            {
                lease.Dispose();
            }
            foreach (var lease in junctionLeases)
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
                    "Descendant writer exclusions must be released before the Windows root rename.");
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
            DisposeWriterExclusionLeases(directoryLeases, fileLeases, junctionLeases);
        }
    }
}
