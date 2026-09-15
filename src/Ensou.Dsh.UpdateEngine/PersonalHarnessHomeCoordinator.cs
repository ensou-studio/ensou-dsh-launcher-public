using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Ensou.Dsh.Contracts;
using Microsoft.Win32.SafeHandles;

namespace Ensou.Dsh.UpdateEngine;

/// <summary>Coordinates trusted Personal writers of one logical home, independently of install layout.</summary>
public sealed class PersonalHarnessHomeCoordinator
{
    private readonly string _home;
    public PersonalHarnessHomeCoordinator(string harnessHome)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(harnessHome);
        if (!Path.IsPathFullyQualified(harnessHome)) throw new ArgumentException("Harness home must be an absolute path.", nameof(harnessHome));
        _home = Path.GetFullPath(harnessHome);
    }

    public PersonalHarnessHomeLease AcquireLease(Action? admitLegacyNonemptyHome = null)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Personal home coordination requires Windows.");
        var directories = new List<SafeFileHandle>();
        FileStream? file = null;
        try
        {
            var home = PersonalHomeCoordinationNative.CanonicalHome(_home, directories);
            using var identity = WindowsIdentity.GetCurrent();
            var sid = identity.User?.Value
                ?? throw new InvalidDataException("PERSONAL_HOME_COORDINATION_INVALID: User SID is unavailable.");
            var key = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(sid + "\n" + home.ToUpperInvariant())));
            var root = Path.Combine(Path.GetDirectoryName(home)!, ".ensou-dsh-home-coordination", key);
            foreach (var path in new[] { Path.GetDirectoryName(root)!, root })
            {
                PersonalHomeCoordinationNative.RejectLink(path);
                Directory.CreateDirectory(path);
                directories.Add(PersonalHomeCoordinationNative.OpenDirectory(path));
            }
            var handle = PersonalManagedOperationLockHandleSafety.TryOpen(PersonalHomeCoordinationNative.ExtendedPath(Path.Combine(root, "home.lock")))
                ?? throw new InvalidOperationException("PERSONAL_HOME_BUSY: This Harness home is in use.");
            try { PersonalManagedOperationLockHandleSafety.RequireSingleLinkHandle(handle); }
            catch { handle.Dispose(); throw; }
            file = new FileStream(handle, FileAccess.ReadWrite, 1, false);
            var lease = new PersonalHarnessHomeLease(home, key, root, file, directories);
            file = null;
            directories = [];
            try { lease.EnsureEnrollment(admitLegacyNonemptyHome); return lease; }
            catch { lease.Dispose(); throw; }
        }
        catch
        {
            file?.Dispose();
            foreach (var directory in directories) directory.Dispose();
            throw;
        }
    }
}

public sealed class PersonalHarnessHomeLease : IDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        PropertyNameCaseInsensitive = false,
        MaxDepth = 16,
    };
    private readonly object _gate = new();
    private readonly string _root;
    private readonly string _key;
    private readonly FileStream _file;
    private readonly List<SafeFileHandle> _directories;
    private int _references = 1;
    private int _writerSessions;
    private bool _disposed;
    private HomeState? _state;
    public string CanonicalHarnessHome { get; }

    internal PersonalHarnessHomeLease(string home, string key, string root, FileStream file, List<SafeFileHandle> directories)
    { CanonicalHarnessHome = home; _key = key; _root = root; _file = file; _directories = directories; }

    internal void EnsureEnrollment(Action? admitLegacyNonemptyHome)
    {
        lock (_gate)
        {
            var path = StatePath;
            PersonalHomeCoordinationNative.RejectLink(path);
            if (File.Exists(path))
            {
                using var stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.Read);
                PersonalManagedOperationLockHandleSafety.RequireSingleLinkHandle(stream.SafeFileHandle);
                if (stream.Length is <= 0 or > 32768) throw Invalid("Invalid state length.");
                _state = JsonSerializer.Deserialize<HomeState>(stream, JsonOptions) ?? throw Invalid("Missing state.");
                ValidateState(_state);
                return;
            }
            PersonalHomeCoordinationNative.RejectLink(CanonicalHarnessHome);
            if (Directory.Exists(CanonicalHarnessHome) && Directory.EnumerateFileSystemEntries(CanonicalHarnessHome).Any())
            {
                if (admitLegacyNonemptyHome is null)
                    throw new InvalidOperationException("PERSONAL_HOME_LEGACY_WRITER_CONFLICT: Existing home requires one-time conservative admission.");
                admitLegacyNonemptyHome();
            }
            Write(new HomeState(1, CanonicalHarnessHome, _key, null, null));
        }
    }

    public void RequireQuiescent()
    {
        lock (_gate) { RequireUsable(); RequireQuiescentCore(); }
    }

    private void RequireQuiescentCore()
    {
        var state = _state ?? throw Invalid("Home is not enrolled.");
        var runtime = state.Runtime;
        if (runtime is null || runtime.Phase == "clean") return;
        if (_writerSessions != 0) throw new InvalidOperationException("PERSONAL_HOME_BUSY: The owned runtime session is still active.");
        var tick = PersonalHomeCoordinationNative.GetTickCount64();
        // A decreasing native uptime is sufficient reset evidence. The converse proves nothing.
        if (tick < runtime.MaximumObservedNativeTickCount64)
        {
            Write(state with { Runtime = runtime with { Phase = "clean", CleanEvidence = "epoch-reset" } });
            return;
        }
        if (runtime.ContainmentProtocol == PersonalAtomicHomeRecoveryPolicy.AtomicProtocol)
        {
            var observerSession = PersonalHomeCoordinationNative.TryGetCurrentSessionId();
            if (observerSession is not null && observerSession == runtime.OwnerSessionId)
            {
                using var owner = PersonalHomeCoordinationNative.ObserveOwner(
                    runtime.OwnerPid, runtime.OwnerCreationFileTimeUtc);
                if (owner.Kind == PersonalOwnerObservationKind.Gone)
                {
                    using var job = PersonalHomeCoordinationNative.ObserveExactJob(runtime.JobName);
                    var evidence = PersonalAtomicHomeRecoveryPolicy.RecoveryEvidence(
                        state.SchemaVersion, runtime.ContainmentProtocol,
                        runtime.OwnerSessionId, observerSession, owner.Kind, job.Kind);
                    if (evidence is not null)
                    {
                        // Retain both successfully opened native identities until the state is durable.
                        Write(state with { Runtime = runtime with { Phase = "clean", CleanEvidence = evidence } });
                        return;
                    }
                }
                else if (owner.Kind == PersonalOwnerObservationKind.Alive)
                {
                    throw new InvalidOperationException("PERSONAL_HOME_BUSY: The exact atomic runtime owner is still alive.");
                }
            }
        }
        else if (PersonalHomeCoordinationNative.IsExactJobEmpty(runtime.JobName))
        {
            Write(state with { Runtime = runtime with { Phase = "clean", CleanEvidence = "recovered-job-empty" } });
            return;
        }
        Write(state with { Runtime = runtime with { Phase = "shutdown-unconfirmed", MaximumObservedNativeTickCount64 = tick } });
        throw new InvalidOperationException("PERSONAL_HOME_SHUTDOWN_UNCONFIRMED: Previous DSH shutdown is unconfirmed. Restart Windows and retry; maintenance is required if recovery remains blocked.");
    }

    public void RequireMutationAdmission(string harnessHome)
    {
        lock (_gate)
        {
            RequireUsable();
            var handles = new List<SafeFileHandle>();
            try
            {
                var canonical = PersonalHomeCoordinationNative.CanonicalHome(harnessHome, handles);
                if (!string.Equals(canonical, CanonicalHarnessHome, StringComparison.OrdinalIgnoreCase)) throw Invalid("Lease belongs to a different home.");
            }
            finally { foreach (var handle in handles) handle.Dispose(); }
            RequireQuiescentCore();
        }
    }

    internal string? RollbackGenerationId
    {
        get { lock (_gate) { RequireUsable(); return _state?.Runtime?.GenerationId; } }
    }

    internal void PrepareLegacyCoordinationAfterVerifiedRollback(
        PersonalHarnessHomeTransaction.VerifiedRollbackProof proof)
    {
        lock (_gate)
        {
            RequireUsable();
            proof.RequireCurrent(this, CanonicalHarnessHome, _state?.Runtime?.GenerationId);
            if (_writerSessions != 0)
                throw new InvalidOperationException("PERSONAL_HOME_BUSY: A writer session still owns the rollback generation.");
            RequireQuiescentCore();
            if (_state!.HealthAttempt is not null)
                throw new InvalidOperationException("PERSONAL_HOME_HEALTH_ATTEMPT_CONFLICT: Rollback enrollment cannot discard an outstanding health attempt.");
            // This is fresh idle enrollment after real restoration, never a relabeled runtime generation.
            if (_state.SchemaVersion != 1 || _state.Runtime is not null)
                Write(new HomeState(1, CanonicalHarnessHome, _key, null, null));
            proof.Consume();
        }
    }

    public IDshHomeWriterSession BeginRuntimeSession() => BeginRuntimeSessionCore(atomic: false);

    /// <summary>Commits to atomic Job-list creation before any child may be created.</summary>
    public IDshAtomicHomeWriterSession BeginAtomicRuntimeSession() =>
        (IDshAtomicHomeWriterSession)BeginRuntimeSessionCore(atomic: true);

    private IDshHomeWriterSession BeginRuntimeSessionCore(bool atomic)
    {
        lock (_gate)
        {
            RequireUsable();
            RequireQuiescentCore();
            var state = _state!;
            if (state.HealthAttempt is { Phase: "completed" }) throw new InvalidOperationException("PERSONAL_HOME_HEALTH_ATTEMPT_CONFLICT: Completed health must be committed or aborted before another runtime starts.");
            if (state.HealthAttempt is { GenerationId: not null }) throw new InvalidOperationException("PERSONAL_HOME_HEALTH_ATTEMPT_CONFLICT: Health runtime has already been admitted.");
            var id = Guid.NewGuid().ToString("N");
            using var ownerProcess = Process.GetCurrentProcess();
            var ownerSession = atomic
                ? PersonalHomeCoordinationNative.TryGetCurrentSessionId()
                    ?? throw Invalid("Cannot identify the atomic owner's Windows session.")
                : (uint?)null;
            var schemaVersion = atomic ? 2 : state.SchemaVersion;
            var protocol = atomic ? PersonalAtomicHomeRecoveryPolicy.AtomicProtocol
                : schemaVersion == 2 ? PersonalAtomicHomeRecoveryPolicy.LegacyProtocol : null;
            var runtime = new RuntimeGeneration(id,
                (atomic ? "Local\\Ensou.Dsh.Home.v2." : "Local\\Ensou.Dsh.Home.") + _key + "." + id,
                Environment.ProcessId, ownerProcess.StartTime.ToUniversalTime().ToFileTimeUtc(), null, null,
                PersonalHomeCoordinationNative.GetTickCount64(), "starting",
                ContainmentProtocol: protocol, OwnerSessionId: ownerSession);
            Write(state with { SchemaVersion = schemaVersion, Runtime = runtime, HealthAttempt = state.HealthAttempt is { } attempt ? attempt with { GenerationId = id } : null });
            _references++;
            _writerSessions++;
            return atomic ? new AtomicWriterSession(this, runtime) : new WriterSession(this, runtime);
        }
    }

    public void AdmitHealthAttempt(string transactionId, string healthToken)
    {
        lock (_gate)
        {
            RequireUsable(); RequireQuiescentCore();
            var digest = TokenDigest(transactionId, healthToken);
            if (_state!.HealthAttempt is { } previous && (previous.Phase != "completed" || previous.TransactionId == transactionId))
                throw new InvalidOperationException("PERSONAL_HOME_HEALTH_ATTEMPT_CONFLICT: This health attempt has already been admitted.");
            Write(_state with { HealthAttempt = new HealthAttempt(transactionId, digest, "admitted", null) });
        }
    }

    public void CompleteHealthAttempt(string transactionId, string healthToken)
    {
        lock (_gate)
        {
            RequireUsable();
            var attempt = RequireAttempt(transactionId, healthToken);
            if (attempt.Phase != "admitted" || attempt.GenerationId is null || _state!.Runtime is not { Phase: "clean", RuntimePid: not null, CleanEvidence: "owned-job-empty" } runtime || runtime.GenerationId != attempt.GenerationId)
                throw new InvalidOperationException("PERSONAL_HOME_HEALTH_ATTEMPT_CONFLICT: Health requires a started and cleanly stopped exact generation.");
            Write(_state with { HealthAttempt = attempt with { Phase = "completed" } });
        }
    }

    public void RequireCompletedHealthAttempt(string transactionId, string healthToken)
    {
        lock (_gate)
        {
            RequireUsable();
            var attempt = RequireAttempt(transactionId, healthToken);
            if (attempt.Phase != "completed" || attempt.GenerationId is null || _state!.Runtime is not { Phase: "clean", RuntimePid: not null, CleanEvidence: "owned-job-empty" } runtime || runtime.GenerationId != attempt.GenerationId)
                throw new InvalidOperationException("PERSONAL_HOME_HEALTH_ATTEMPT_CONFLICT: Exact completed health evidence is missing.");
        }
    }

    /// <summary>Call only after the matching transaction has been committed or restored under this lease.</summary>
    public void AbortHealthAttempt(string transactionId, string healthToken)
    {
        lock (_gate)
        {
            RequireUsable(); RequireQuiescentCore();
            if (_state!.HealthAttempt is null) return;
            _ = RequireAttempt(transactionId, healthToken);
            Write(_state with { HealthAttempt = null });
        }
    }

    /// <summary>Reconciles only the exact transaction after its home was restored or committed.</summary>
    public void AbortHealthAttempt(string transactionId)
    {
        lock (_gate)
        {
            RequireUsable(); RequireQuiescentCore();
            if (_state!.HealthAttempt is null) return;
            if (_state.HealthAttempt.TransactionId != transactionId)
            {
                if (_state.HealthAttempt.Phase == "completed") return;
                throw new InvalidOperationException("PERSONAL_HOME_HEALTH_ATTEMPT_CONFLICT: Cannot clear another transaction's health attempt.");
            }
            Write(_state with { HealthAttempt = null });
        }
    }

    private HealthAttempt RequireAttempt(string transactionId, string token)
    {
        var digest = TokenDigest(transactionId, token);
        var attempt = _state!.HealthAttempt;
        if (attempt is null || attempt.TransactionId != transactionId || attempt.HealthTokenSha256 != digest)
            throw new InvalidOperationException("PERSONAL_HOME_HEALTH_ATTEMPT_CONFLICT: Health transaction or token does not match.");
        return attempt;
    }

    private static string TokenDigest(string transactionId, string token)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(transactionId);
        ArgumentException.ThrowIfNullOrWhiteSpace(token);
        if (transactionId.Length > 192 || token.Length > 512) throw Invalid("Health identity is too long.");
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(token)));
    }

    private void UpdateGeneration(string generationId, Func<RuntimeGeneration, RuntimeGeneration> update)
    {
        lock (_gate)
        {
            if (_references <= 0 || _state?.Runtime is not { } runtime || runtime.GenerationId != generationId) throw Invalid("Runtime generation no longer owns the lease.");
            Write(_state with { Runtime = update(runtime) });
        }
    }

    private void Write(HomeState state)
    {
        ValidateState(state);
        PersonalHomeCoordinationNative.RejectLink(StatePath);
        var temporary = Path.Combine(_root, Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            { JsonSerializer.Serialize(stream, state, JsonOptions); stream.Flush(true); }
            File.Move(temporary, StatePath, true);
            _state = state;
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }

    private void ValidateState(HomeState state)
    {
        if (state.SchemaVersion is not (1 or 2) || state.HomeKey != _key || !string.Equals(state.CanonicalHarnessHome, CanonicalHarnessHome, StringComparison.OrdinalIgnoreCase)) throw Invalid("State identity does not match this home.");
        if (state.SchemaVersion == 2 && state.Runtime is null) throw Invalid("Version 2 requires an explicit generation protocol.");
        if (state.Runtime is { } r)
        {
            var atomic = r.ContainmentProtocol == PersonalAtomicHomeRecoveryPolicy.AtomicProtocol;
            if (state.SchemaVersion == 1
                ? r.ContainmentProtocol is not null || r.OwnerSessionId is not null
                : atomic ? r.OwnerSessionId is null
                : r.ContainmentProtocol != PersonalAtomicHomeRecoveryPolicy.LegacyProtocol || r.OwnerSessionId is not null)
                throw Invalid("Runtime containment protocol is invalid.");
            var expectedJob = (atomic ? "Local\\Ensou.Dsh.Home.v2." : "Local\\Ensou.Dsh.Home.") + _key + "." + r.GenerationId;
            if (!Guid.TryParseExact(r.GenerationId, "N", out _) || r.JobName != expectedJob || r.OwnerPid <= 0 || r.OwnerCreationFileTimeUtc <= 0 || r.Phase is not ("starting" or "running" or "clean" or "shutdown-unconfirmed") || (r.RuntimePid is null) != (r.RuntimeCreationFileTimeUtc is null) || r.RuntimePid is <= 0 || r.RuntimeCreationFileTimeUtc is <= 0) throw Invalid("Runtime state is invalid.");
            var validCleanEvidence = r.CleanEvidence is "owned-job-empty" or "never-started" or "epoch-reset"
                || (atomic ? r.CleanEvidence is "recovered-atomic-job-empty" or "recovered-atomic-job-absent"
                    : r.CleanEvidence == "recovered-job-empty");
            if (r.Phase == "clean" ? !validCleanEvidence : r.CleanEvidence is not null) throw Invalid("Runtime shutdown evidence is invalid.");
        }
        if (state.HealthAttempt is { } a && (string.IsNullOrWhiteSpace(a.TransactionId) || a.TransactionId.Length > 192 || a.HealthTokenSha256.Length != 64 || !a.HealthTokenSha256.All(char.IsAsciiHexDigit) || a.Phase is not ("admitted" or "completed") || a.GenerationId is not null && !Guid.TryParseExact(a.GenerationId, "N", out _))) throw Invalid("Health attempt state is invalid.");
    }

    private string StatePath => Path.Combine(_root, "state.v1.json");
    private void RequireUsable() { ObjectDisposedException.ThrowIf(_disposed, this); if (_references <= 0) throw Invalid("Home lease has been released."); }
    private static InvalidDataException Invalid(string detail) => new("PERSONAL_HOME_COORDINATION_INVALID: " + detail);
    public void Dispose() { lock (_gate) { if (_disposed) return; _disposed = true; ReleaseReference(); } }
    private void ReleaseReference()
    {
        if (--_references != 0) return;
        _file.Dispose();
        foreach (var handle in _directories) handle.Dispose();
    }

    private class WriterSession(PersonalHarnessHomeLease owner, RuntimeGeneration initial) : IDshHomeWriterSession
    {
        private bool _disposed;
        public string JobName => initial.JobName;
        public void RecordAssignedProcess(int processId, long creationFileTimeUtc)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (processId <= 0 || creationFileTimeUtc <= 0) throw Invalid("Assigned process identity is invalid.");
            owner.UpdateGeneration(initial.GenerationId, r => r.Phase == "starting" && r.RuntimePid is null
                ? r with { RuntimePid = processId, RuntimeCreationFileTimeUtc = creationFileTimeUtc, Phase = "running" }
                : throw Invalid("Runtime was already assigned."));
        }
        public void RecordJobEmpty()
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            owner.UpdateGeneration(initial.GenerationId, r => r with { Phase = "clean", CleanEvidence = "owned-job-empty" });
        }
        public void RecordNeverStarted()
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            owner.UpdateGeneration(initial.GenerationId, r => r.Phase == "starting" && r.RuntimePid is null
                ? r with { Phase = "clean", CleanEvidence = "never-started" } : throw Invalid("Runtime may already have started."));
        }
        public void Dispose() { lock (owner._gate) { if (_disposed) return; _disposed = true; owner._writerSessions--; owner.ReleaseReference(); } }
    }

    private sealed class AtomicWriterSession(PersonalHarnessHomeLease owner, RuntimeGeneration initial)
        : WriterSession(owner, initial), IDshAtomicHomeWriterSession
    {
    }

    private sealed record HomeState(int SchemaVersion, string CanonicalHarnessHome, string HomeKey, RuntimeGeneration? Runtime, HealthAttempt? HealthAttempt);
    private sealed record RuntimeGeneration(string GenerationId, string JobName, int OwnerPid, long OwnerCreationFileTimeUtc, int? RuntimePid, long? RuntimeCreationFileTimeUtc, ulong MaximumObservedNativeTickCount64, string Phase, string? CleanEvidence = null,
        [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? ContainmentProtocol = null,
        [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] uint? OwnerSessionId = null);
    private sealed record HealthAttempt(string TransactionId, string HealthTokenSha256, string Phase, string? GenerationId);
}

internal enum PersonalOwnerObservationKind { Unknown, Alive, Gone }
internal enum PersonalJobObservationKind { Unknown, NotFound, Empty, Active }

internal static class PersonalAtomicHomeRecoveryPolicy
{
    internal const string AtomicProtocol = "windows-job-list-v2";
    internal const string LegacyProtocol = "legacy-create-assign-v1";

    internal static string? RecoveryEvidence(int schemaVersion, string? protocol,
        uint? ownerSessionId, uint? observerSessionId,
        PersonalOwnerObservationKind owner, PersonalJobObservationKind job)
    {
        if (schemaVersion != 2 || protocol != AtomicProtocol
            || ownerSessionId is null || observerSessionId is null || ownerSessionId != observerSessionId
            || owner != PersonalOwnerObservationKind.Gone) return null;
        return job switch
        {
            PersonalJobObservationKind.Empty => "recovered-atomic-job-empty",
            PersonalJobObservationKind.NotFound => "recovered-atomic-job-absent",
            _ => null,
        };
    }
}

internal sealed class PersonalOwnerObservation(
    PersonalOwnerObservationKind kind, SafeProcessHandle? handle = null, int win32Error = 0) : IDisposable
{
    internal PersonalOwnerObservationKind Kind { get; } = kind;
    internal int Win32Error { get; } = win32Error;
    public void Dispose() => handle?.Dispose();
}

internal sealed class PersonalJobObservation(
    PersonalJobObservationKind kind, SafeFileHandle? handle = null, int win32Error = 0) : IDisposable
{
    internal PersonalJobObservationKind Kind { get; } = kind;
    internal int Win32Error { get; } = win32Error;
    public void Dispose() => handle?.Dispose();
}

internal static class PersonalHomeCoordinationNative
{
    internal static uint? TryGetCurrentSessionId() =>
        ProcessIdToSessionId(checked((uint)Environment.ProcessId), out var sessionId) ? sessionId : null;

    internal static PersonalOwnerObservation ObserveOwner(int processId, long creationFileTimeUtc)
    {
        if (processId <= 0 || creationFileTimeUtc <= 0)
            return new(PersonalOwnerObservationKind.Unknown);
        // Keep this exact process object referenced through the recovery decision, preventing PID reuse.
        var handle = OpenProcess(0x00101000, false, checked((uint)processId)); // SYNCHRONIZE | QUERY_LIMITED_INFORMATION
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            handle.Dispose();
            // Invalid-parameter alone is not an absence proof. Access denied always stays unknown.
            return error == 87 && IsOwnerAbsentFromCompleteProcessList(processId)
                ? new(PersonalOwnerObservationKind.Gone)
                : new(PersonalOwnerObservationKind.Unknown, win32Error: error);
        }
        if (!GetProcessTimes(handle, out var creation, out _, out _, out _))
        {
            var error = Marshal.GetLastWin32Error();
            handle.Dispose();
            return new(PersonalOwnerObservationKind.Unknown, win32Error: error);
        }
        var actualCreation = unchecked((long)(((ulong)creation.High << 32) | creation.Low));
        if (actualCreation != creationFileTimeUtc)
            return new(PersonalOwnerObservationKind.Gone, handle);
        var wait = WaitForSingleObject(handle, 0);
        if (wait == 0) return new(PersonalOwnerObservationKind.Gone, handle);
        if (wait == 258) return new(PersonalOwnerObservationKind.Alive, handle);
        var waitError = wait == uint.MaxValue ? Marshal.GetLastWin32Error() : 0;
        handle.Dispose();
        return new(PersonalOwnerObservationKind.Unknown, win32Error: waitError);
    }

    private static bool IsOwnerAbsentFromCompleteProcessList(int processId)
    {
        // Query identifiers only. A saturated or failed enumeration never proves absence.
        const int maximumIdentifiers = 1024 * 1024 / sizeof(uint);
        for (var capacity = 4096; capacity <= maximumIdentifiers; capacity *= 2)
        {
            var identifiers = new uint[capacity];
            var bytes = checked((uint)(capacity * sizeof(uint)));
            if (!K32EnumProcesses(identifiers, bytes, out var returned) || returned > bytes || returned % sizeof(uint) != 0)
                return false;
            if (returned == bytes) continue;
            return Array.IndexOf(identifiers, checked((uint)processId), 0, checked((int)(returned / sizeof(uint)))) < 0;
        }
        return false;
    }

    internal static PersonalJobObservation ObserveExactJob(string name)
    {
        var handle = OpenJobObjectW(4, false, name); // JOB_OBJECT_QUERY only; never inherit an observation handle.
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            handle.Dispose();
            return new(error == 2 ? PersonalJobObservationKind.NotFound : PersonalJobObservationKind.Unknown,
                win32Error: error);
        }
        if (!QueryInformationJobObject(handle, 1, out var accounting, (uint)Marshal.SizeOf<JobAccounting>(), IntPtr.Zero))
        {
            var error = Marshal.GetLastWin32Error();
            handle.Dispose();
            return new(PersonalJobObservationKind.Unknown, win32Error: error);
        }
        return new(accounting.ActiveProcesses == 0 ? PersonalJobObservationKind.Empty : PersonalJobObservationKind.Active, handle);
    }

    internal static string CanonicalHome(string input, List<SafeFileHandle> handles)
    {
        if (!Path.IsPathFullyQualified(input)) throw new ArgumentException("Harness home must be an absolute path.", nameof(input));
        var full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(input));
        if (!Path.IsPathFullyQualified(full) || full.StartsWith("\\\\", StringComparison.Ordinal) || Path.GetPathRoot(full) == full)
            throw new InvalidDataException("PERSONAL_HOME_COORDINATION_INVALID: Home must be a local non-root directory.");
        if (string.Equals(Path.GetFileName(full), ".ensou-dsh-home-coordination", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("PERSONAL_HOME_COORDINATION_INVALID: Home conflicts with the reserved coordination directory.");
        var parent = Path.GetDirectoryName(full)!;
        var chain = new Stack<string>();
        for (var d = new DirectoryInfo(parent); d is not null; d = d.Parent) chain.Push(d.FullName);
        while (chain.TryPop(out var path))
        {
            RejectLink(path);
            Directory.CreateDirectory(path);
            handles.Add(OpenDirectory(path));
        }
        var buffer = new StringBuilder(32768);
        var length = GetFinalPathNameByHandleW(handles[^1], buffer, (uint)buffer.Capacity, 0);
        if (length == 0 || length >= buffer.Capacity) throw new IOException("Cannot canonicalize Harness-home parent.", new Win32Exception(Marshal.GetLastWin32Error()));
        var canonicalParent = buffer.ToString();
        if (canonicalParent.StartsWith("\\\\?\\", StringComparison.Ordinal)) canonicalParent = canonicalParent[4..];
        var home = Path.Combine(canonicalParent, Path.GetFileName(full));
        RejectLink(home);
        if (File.Exists(home)) throw new InvalidDataException("Harness home is a file.");
        if (Directory.Exists(home))
        {
            using var handle = OpenDirectory(home);
            length = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Capacity, 0);
            if (length == 0 || length >= buffer.Capacity) throw new IOException("Cannot canonicalize Harness home.");
            home = buffer.ToString();
            if (home.StartsWith("\\\\?\\", StringComparison.Ordinal)) home = home[4..];
        }
        return Path.TrimEndingDirectorySeparator(home);
    }

    internal static void RejectLink(string path)
    {
        try { if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) throw new InvalidDataException("PERSONAL_HOME_COORDINATION_INVALID: Coordination paths cannot traverse links."); }
        catch (FileNotFoundException) { }
        catch (DirectoryNotFoundException) { }
    }

    internal static SafeFileHandle OpenDirectory(string path)
    {
        var handle = CreateFileW(ExtendedPath(path), 0x80, 3, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
        if (handle.IsInvalid) { var error = Marshal.GetLastWin32Error(); handle.Dispose(); throw new IOException($"Cannot retain coordination directory '{path}'.", new Win32Exception(error)); }
        try
        {
            if (!GetFileInformationByHandle(handle, out var info)) throw new IOException("Cannot inspect coordination directory.");
            if ((info.Attributes & 0x400) != 0 || (info.Attributes & 0x10) == 0) throw new InvalidDataException("Coordination directory must be an ordinary directory.");
            return handle;
        }
        catch { handle.Dispose(); throw; }
    }

    internal static bool IsExactJobEmpty(string name)
    {
        using var handle = OpenJobObjectW(4, false, name);
        if (handle.IsInvalid) return false;
        return QueryInformationJobObject(handle, 1, out var accounting, (uint)Marshal.SizeOf<JobAccounting>(), IntPtr.Zero) && accounting.ActiveProcesses == 0;
    }

    internal static string ExtendedPath(string path) => path.StartsWith("\\\\?\\", StringComparison.Ordinal) ? path : "\\\\?\\" + path;

    [DllImport("kernel32.dll")] internal static extern ulong GetTickCount64();
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool ProcessIdToSessionId(uint processId, out uint sessionId);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern SafeProcessHandle OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint processId);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool GetProcessTimes(SafeProcessHandle process, out NativeFileTime creation, out NativeFileTime exit, out NativeFileTime kernel, out NativeFileTime user);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern uint WaitForSingleObject(SafeProcessHandle process, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool K32EnumProcesses([Out] uint[] processIds, uint sizeBytes, out uint returnedBytes);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern uint GetFinalPathNameByHandleW(SafeFileHandle handle, StringBuilder path, uint length, uint flags);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInformation info);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern SafeFileHandle OpenJobObjectW(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, string name);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool QueryInformationJobObject(SafeFileHandle job, int informationClass, out JobAccounting information, uint length, IntPtr returnedLength);
    [StructLayout(LayoutKind.Sequential)] private struct FileInformation { public uint Attributes; public System.Runtime.InteropServices.ComTypes.FILETIME Creation; public System.Runtime.InteropServices.ComTypes.FILETIME Access; public System.Runtime.InteropServices.ComTypes.FILETIME Write; public uint Volume; public uint SizeHigh; public uint SizeLow; public uint Links; public uint IndexHigh; public uint IndexLow; }
    [StructLayout(LayoutKind.Sequential)] private struct JobAccounting { public long TotalUserTime; public long TotalKernelTime; public long ThisPeriodUserTime; public long ThisPeriodKernelTime; public uint PageFaults; public uint TotalProcesses; public uint ActiveProcesses; public uint TerminatedProcesses; }
    [StructLayout(LayoutKind.Sequential)] private struct NativeFileTime { public uint Low; public uint High; }
}
