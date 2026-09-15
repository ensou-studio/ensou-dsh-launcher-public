using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Runtime.InteropServices;
using System.ComponentModel;
using Microsoft.Win32.SafeHandles;

namespace Ensou.Dsh.UpdateEngine;

public enum PersonalManagedArtifactGcStatus
{
    Completed,
    SkippedBusy,
    SkippedPending,
}

public sealed record PersonalManagedArtifactGcResult(
    PersonalManagedArtifactGcStatus Status,
    int RemovedVersionDirectories,
    int RemovedCacheFiles,
    bool RetriedPreviousFailure);

/// <summary>
/// Cross-process lease shared by personal update checks, downloads, activation, and managed GC.
/// Its link-free LocalAppData sibling root stays outside the renameable managed program tree and
/// is independent from Harness user data and recovery generations.
/// </summary>
public sealed class PersonalManagedUpdateOperationLease : IDisposable, IAsyncDisposable
{
    private FileStream? _stream;

    private PersonalManagedUpdateOperationLease(FileStream stream) => _stream = stream;

    public static async Task<PersonalManagedUpdateOperationLease> AcquireRequiredAsync(
        PersonalInstallationLayout layout,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(layout);
        var deadline = DateTimeOffset.UtcNow.AddSeconds(30);
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var lease = TryAcquire(layout);
            if (lease is not null)
            {
                return lease;
            }
            if (DateTimeOffset.UtcNow >= deadline)
            {
                throw new TimeoutException(
                    "Timed out waiting for the personal managed update operation lock.");
            }
            await Task.Delay(TimeSpan.FromMilliseconds(50), cancellationToken)
                .ConfigureAwait(false);
        }
    }

    internal static PersonalManagedUpdateOperationLease? TryAcquire(
        PersonalInstallationLayout layout)
    {
        ArgumentNullException.ThrowIfNull(layout);
        layout.EnsureUpdateOperationLockRoot();
        var path = layout.UpdateOperationLockPath;
        var handle = PersonalManagedOperationLockHandleSafety.TryOpen(path);
        if (handle is null)
        {
            return null;
        }
        FileStream? stream = null;
        try
        {
            PersonalManagedOperationLockHandleSafety.RequireSingleLinkHandle(
                handle);
            stream = new FileStream(
                handle,
                FileAccess.ReadWrite,
                bufferSize: 1,
                isAsync: false);
            return new PersonalManagedUpdateOperationLease(stream);
        }
        catch
        {
            stream?.Dispose();
            if (stream is null)
            {
                handle.Dispose();
            }
            throw;
        }
    }

    public void Dispose() => Interlocked.Exchange(ref _stream, null)?.Dispose();

    public ValueTask DisposeAsync()
    {
        Dispose();
        return ValueTask.CompletedTask;
    }

}

internal static class PersonalManagedOperationLockHandleSafety
{
    private const uint GenericRead = 0x80000000;
    private const uint GenericWrite = 0x40000000;
    private const uint FileShareRead = 0x00000001;
    private const uint OpenAlways = 4;
    private const uint FileAttributeNormal = 0x00000080;
    private const uint FileFlagWriteThrough = 0x80000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;

    public static SafeFileHandle? TryOpen(string path)
    {
        if (!OperatingSystem.IsWindows())
        {
            try
            {
                return File.OpenHandle(
                    path,
                    FileMode.OpenOrCreate,
                    FileAccess.ReadWrite,
                    FileShare.Read,
                    FileOptions.WriteThrough);
            }
            catch (IOException exception) when ((exception.HResult & 0xffff) is 32 or 33)
            {
                return null;
            }
        }
        var handle = CreateFile(
            path,
            GenericRead | GenericWrite,
            FileShareRead,
            IntPtr.Zero,
            OpenAlways,
            FileAttributeNormal | FileFlagWriteThrough | FileFlagOpenReparsePoint,
            IntPtr.Zero);
        if (!handle.IsInvalid)
        {
            return handle;
        }
        var error = Marshal.GetLastWin32Error();
        handle.Dispose();
        if (error is 32 or 33)
        {
            return null;
        }
        throw new IOException(
            "Unable to open the personal update operation lock.",
            new Win32Exception(error));
    }

    public static void RequireSingleLinkHandle(SafeFileHandle handle)
    {
        ArgumentNullException.ThrowIfNull(handle);
        if (!OperatingSystem.IsWindows())
        {
            return;
        }
        if (!GetFileInformationByHandle(handle, out var information))
        {
            throw new IOException(
                "Unable to inspect the personal update operation lock.",
                Marshal.GetExceptionForHR(Marshal.GetHRForLastWin32Error()));
        }
        if ((information.FileAttributes & (uint)FileAttributes.ReparsePoint) != 0
            || information.NumberOfLinks != 1)
        {
            throw new InvalidDataException(
                "Personal update operation lock must not be linked.");
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle file,
        out ByHandleFileInformation information);

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

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

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PersonalManagedUpdateSession
{
    public required int SchemaVersion { get; init; }

    public required string ReleaseSetId { get; init; }

    public required string ManifestSha256 { get; init; }

    public required string ClientBundleSha256 { get; init; }

    public required string RuntimeSha256 { get; init; }

    public required DateTimeOffset StartedAtUtc { get; init; }
}

/// <summary>
/// Durable bridge between the separate personal Download and Stage calls. A live marker prevents
/// GC from deleting a fully downloaded candidate in the short lock-free handoff between them.
/// </summary>
public sealed class PersonalManagedUpdateSessionStore
{
    private const int SchemaVersion = 1;
    private const int MaximumDocumentBytes = 32 * 1024;
    private static readonly TimeSpan MaximumAbandonedAge = TimeSpan.FromHours(24);
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        AllowTrailingCommas = false,
        MaxDepth = 16,
        PropertyNameCaseInsensitive = false,
        ReadCommentHandling = JsonCommentHandling.Disallow,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        WriteIndented = false,
    };
    private readonly PersonalInstallationLayout _layout;

    public PersonalManagedUpdateSessionStore(PersonalInstallationLayout layout)
    {
        _layout = layout ?? throw new ArgumentNullException(nameof(layout));
    }

    public void Begin(
        string releaseSetId,
        string manifestSha256,
        string clientBundleSha256,
        string runtimeSha256)
    {
        PersonalPathGuard.ValidateReleaseId(releaseSetId);
        RequireSha256(manifestSha256, nameof(manifestSha256));
        RequireSha256(clientBundleSha256, nameof(clientBundleSha256));
        RequireSha256(runtimeSha256, nameof(runtimeSha256));
        _layout.EnsureManagedRoots();
        Write(new PersonalManagedUpdateSession
        {
            SchemaVersion = SchemaVersion,
            ReleaseSetId = releaseSetId,
            ManifestSha256 = manifestSha256,
            ClientBundleSha256 = clientBundleSha256,
            RuntimeSha256 = runtimeSha256,
            StartedAtUtc = DateTimeOffset.UtcNow,
        });
    }

    public void RequireMatches(
        string releaseSetId,
        string manifestSha256,
        string clientBundleSha256,
        string runtimeSha256)
    {
        var session = ReadRequired();
        if (!string.Equals(session.ReleaseSetId, releaseSetId, StringComparison.Ordinal)
            || !string.Equals(session.ManifestSha256, manifestSha256, StringComparison.Ordinal)
            || !string.Equals(
                session.ClientBundleSha256,
                clientBundleSha256,
                StringComparison.Ordinal)
            || !string.Equals(session.RuntimeSha256, runtimeSha256, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Personal downloaded candidate does not match the active update session.");
        }
    }

    public void Complete(
        string releaseSetId,
        string manifestSha256,
        string clientBundleSha256,
        string runtimeSha256)
    {
        RequireMatches(
            releaseSetId,
            manifestSha256,
            clientBundleSha256,
            runtimeSha256);
        DeleteMarker();
    }

    internal bool HasActiveOrClearAbandoned(DateTimeOffset observedNowUtc)
    {
        RequireUtc(observedNowUtc);
        if (!File.Exists(MarkerPath))
        {
            return false;
        }
        var session = ReadRequired();
        if (observedNowUtc < session.StartedAtUtc.Subtract(TimeSpan.FromMinutes(5)))
        {
            throw new InvalidDataException(
                "Personal update session time moved backwards; GC is blocked.");
        }
        if (observedNowUtc - session.StartedAtUtc <= MaximumAbandonedAge)
        {
            return true;
        }
        DeleteMarker();
        return false;
    }

    private string MarkerPath => Path.Combine(
        _layout.StateRoot,
        "managed-update-session.v1.json");

    private PersonalManagedUpdateSession ReadRequired()
    {
        var path = MarkerPath;
        RequireSafeFile(path);
        var info = new FileInfo(path);
        if (info.Length is <= 0 or > MaximumDocumentBytes)
        {
            throw new InvalidDataException("Personal managed update session has an invalid size.");
        }
        PersonalManagedUpdateSession session;
        try
        {
            session = JsonSerializer.Deserialize<PersonalManagedUpdateSession>(
                File.ReadAllBytes(path),
                JsonOptions) ?? throw new InvalidDataException(
                    "Personal managed update session is empty.");
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException(
                "Personal managed update session is malformed.",
                exception);
        }
        if (session.SchemaVersion != SchemaVersion
            || session.StartedAtUtc.Offset != TimeSpan.Zero)
        {
            throw new InvalidDataException("Personal managed update session identity is invalid.");
        }
        PersonalPathGuard.ValidateReleaseId(session.ReleaseSetId);
        RequireSha256(session.ManifestSha256, nameof(session.ManifestSha256));
        RequireSha256(session.ClientBundleSha256, nameof(session.ClientBundleSha256));
        RequireSha256(session.RuntimeSha256, nameof(session.RuntimeSha256));
        return session;
    }

    private void Write(PersonalManagedUpdateSession session)
    {
        if (File.Exists(MarkerPath))
        {
            _ = ReadRequired();
        }
        PersonalReleaseSetPointerStore.WriteFileAtomically(
            MarkerPath,
            JsonSerializer.SerializeToUtf8Bytes(session, JsonOptions),
            _layout.ManagedRoot);
    }

    private void DeleteMarker()
    {
        if (!File.Exists(MarkerPath))
        {
            throw new InvalidDataException("Personal managed update session is missing.");
        }
        RequireSafeFile(MarkerPath);
        File.Delete(MarkerPath);
    }

    private void RequireSafeFile(string path)
    {
        if (!File.Exists(path)
            || !PersonalPathGuard.IsStrictDescendant(path, _layout.ManagedRoot)
            || (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException("Personal managed update session file is unsafe.");
        }
        PersonalPathGuard.RequireSingleLinkFile(path);
    }

    private static void RequireSha256(string value, string field)
    {
        if (!Ensou.Dsh.Contracts.PersonalReleaseSetValidator.IsSha256(value))
        {
            throw new InvalidDataException($"Personal update session {field} is invalid.");
        }
    }

    private static void RequireUtc(DateTimeOffset value)
    {
        if (value.Offset != TimeSpan.Zero)
        {
            throw new ArgumentException("Personal GC time must be UTC.", nameof(value));
        }
    }
}

/// <summary>
/// Bounded, fail-closed cleanup for immutable v2 program trees and package cache only.
/// Harness home and recovery generations are deliberately outside every accepted root.
/// </summary>
public sealed partial class PersonalManagedArtifactGarbageCollector
{
    private const int MaximumRetainedPartialGroups = 4;
    private static readonly TimeSpan MaximumPartialAge = TimeSpan.FromDays(7);
    private readonly PersonalInstallationLayout _layout;
    private readonly TimeProvider _timeProvider;
    private readonly Action<string>? _beforeDeleteForTest;

    public PersonalManagedArtifactGarbageCollector(
        PersonalInstallationLayout layout,
        TimeProvider? timeProvider = null)
        : this(layout, timeProvider, beforeDeleteForTest: null)
    {
    }

    internal PersonalManagedArtifactGarbageCollector(
        PersonalInstallationLayout layout,
        TimeProvider? timeProvider,
        Action<string>? beforeDeleteForTest)
    {
        _layout = layout ?? throw new ArgumentNullException(nameof(layout));
        _timeProvider = timeProvider ?? TimeProvider.System;
        _beforeDeleteForTest = beforeDeleteForTest;
    }

    public async Task<PersonalManagedArtifactGcResult> CollectAsync(
        CancellationToken cancellationToken = default)
    {
        var lease = PersonalManagedUpdateOperationLease.TryAcquire(_layout);
        if (lease is null)
        {
            return new PersonalManagedArtifactGcResult(
                PersonalManagedArtifactGcStatus.SkippedBusy,
                0,
                0,
                false);
        }
        using (lease)
        {
            var store = new PersonalReleaseSetPointerStore(_layout);
            var before = store.ReadRequired();
            if (before.Current.HealthState != PersonalReleaseHealthStates.Healthy
                || before.Previous is { HealthState: not PersonalReleaseHealthStates.Healthy }
                || new PersonalHarnessHomeTransaction(
                        _layout.HarnessHome,
                        _layout.HarnessRecoveryRoot)
                    .TryReadActive() is not null)
            {
                return new PersonalManagedArtifactGcResult(
                    PersonalManagedArtifactGcStatus.SkippedPending,
                    0,
                    0,
                    false);
            }

            var security = new PersonalReleaseSecurityStateStore(
                _layout.UpdateSecurityStatePath,
                new PersonalReleaseStateIdentity(
                    before.Product,
                    before.Environment,
                    before.Channel),
                _layout.UpdateSecurityWitnessPath);
            var decision = await security.ValidateInstalledPointerAsync(
                before,
                _timeProvider.GetUtcNow(),
                cancellationToken).ConfigureAwait(false);
            if (!decision.Allowed)
            {
                throw new InvalidDataException(
                    $"Personal managed GC requires an allowed authenticated pointer: {decision.Reason}");
            }

            return CollectTrustedUnderLease(
                before,
                store.ReadRequired,
                _timeProvider.GetUtcNow());
        }
    }

    internal PersonalManagedArtifactGcResult CollectTrustedUnderLease(
        PersonalInstalledReleaseSetPointer before,
        Func<PersonalInstalledReleaseSetPointer> readPointerAgain,
        DateTimeOffset observedNowUtc)
    {
        ArgumentNullException.ThrowIfNull(before);
        ArgumentNullException.ThrowIfNull(readPointerAgain);
        if (observedNowUtc.Offset != TimeSpan.Zero)
        {
            throw new ArgumentException("Personal GC observation time must be UTC.");
        }
        if (before.Current.HealthState != PersonalReleaseHealthStates.Healthy
            || before.Previous is { HealthState: not PersonalReleaseHealthStates.Healthy })
        {
            return new PersonalManagedArtifactGcResult(
                PersonalManagedArtifactGcStatus.SkippedPending,
                0,
                0,
                false);
        }
        if (new PersonalManagedUpdateSessionStore(_layout)
            .HasActiveOrClearAbandoned(observedNowUtc))
        {
            return new PersonalManagedArtifactGcResult(
                PersonalManagedArtifactGcStatus.SkippedPending,
                0,
                0,
                false);
        }

        var retried = File.Exists(RetryMarkerPath) || Directory.Exists(QuarantineRoot);
        var removedVersions = 0;
        var removedCacheFiles = 0;
        try
        {
            _layout.EnsureManagedRoots();
            RetryQuarantineCleanup();
            removedVersions += CollectVersionRoot(
                _layout.ClientBundleVersionsRoot,
                new[]
                {
                    before.Current.ClientBundle.ReleaseId,
                    before.Previous?.ClientBundle.ReleaseId,
                },
                "client");
            removedVersions += CollectVersionRoot(
                _layout.RuntimeVersionsRoot,
                new[]
                {
                    before.Current.Runtime.ReleaseId,
                    before.Previous?.Runtime.ReleaseId,
                },
                "runtime");
            removedCacheFiles += CollectPartialCache(observedNowUtc);
            RemoveEmptyQuarantineRoot();

            var after = readPointerAgain();
            if (before != after)
            {
                throw new InvalidDataException(
                    "Personal release pointer changed while managed GC held its operation lock.");
            }
            DeleteRetryMarkerIfPresent();
            return new PersonalManagedArtifactGcResult(
                PersonalManagedArtifactGcStatus.Completed,
                removedVersions,
                removedCacheFiles,
                retried);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            try
            {
                WriteRetryMarker(exception);
            }
            catch (Exception markerException)
            {
                throw new InvalidOperationException(
                    "Personal managed artifact GC failed and could not persist its retry marker.",
                    new AggregateException(exception, markerException));
            }
            throw new InvalidOperationException(
                "Personal managed artifact GC failed closed; cleanup will be retried.",
                exception);
        }
    }

    private int CollectVersionRoot(
        string versionRoot,
        IEnumerable<string?> protectedReleaseIds,
        string component)
    {
        PersonalPathGuard.EnsureDirectoryChain(_layout.ManagedRoot, versionRoot);
        var keep = protectedReleaseIds
            .Where(value => value is not null)
            .Cast<string>()
            .ToHashSet(StringComparer.Ordinal);
        if (keep.Count > 2)
        {
            throw new InvalidDataException("Personal GC retained more than current and previous.");
        }
        var removed = 0;
        foreach (var entry in new DirectoryInfo(versionRoot)
                     .EnumerateFileSystemInfos("*", SearchOption.TopDirectoryOnly)
                     .OrderBy(value => value.Name, StringComparer.Ordinal))
        {
            if (entry is not DirectoryInfo directory)
            {
                throw new InvalidDataException(
                    "Personal version roots may contain only controlled directories.");
            }
            RejectReparse(directory.FullName);
            if (TryParseStagingName(directory.Name, out _))
            {
                QuarantineAndDelete(directory.FullName, component + "-staging");
                removed++;
                continue;
            }
            PersonalPathGuard.ValidateReleaseId(directory.Name);
            var exact = PersonalPathGuard.CombineExactChild(versionRoot, directory.Name);
            if (!string.Equals(exact, directory.FullName, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException("Personal version directory is not an exact child.");
            }
            if (keep.Contains(directory.Name))
            {
                PersonalPathGuard.ValidateSafeTree(directory.FullName, _layout.ManagedRoot);
                continue;
            }
            QuarantineAndDelete(directory.FullName, component);
            removed++;
        }
        return removed;
    }

    private int CollectPartialCache(DateTimeOffset observedNowUtc)
    {
        PersonalPathGuard.EnsureDirectoryChain(_layout.PackageRoot, _layout.PartialCacheRoot);
        var groups = new Dictionary<string, List<FileInfo>>(StringComparer.Ordinal);
        var removed = 0;
        foreach (var entry in new DirectoryInfo(_layout.PartialCacheRoot)
                     .EnumerateFileSystemInfos("*", SearchOption.TopDirectoryOnly)
                     .ToArray())
        {
            if (entry is not FileInfo file)
            {
                throw new InvalidDataException(
                    "Personal partial cache may contain only controlled files.");
            }
            RejectReparse(file.FullName);
            PersonalPathGuard.RequireSingleLinkFile(file.FullName);
            if (TemporaryMetadataNameRegex().IsMatch(file.Name))
            {
                DeleteCacheFile(file.FullName);
                removed++;
                continue;
            }
            var key = ParsePersonalCacheKey(file.Name)
                ?? throw new InvalidDataException(
                    "Personal partial cache contains an unrecognized entry.");
            if (!groups.TryGetValue(key, out var files))
            {
                files = [];
                groups.Add(key, files);
            }
            files.Add(file);
        }

        var partialCandidates = groups
            .Where(group => !group.Value.Any(file => file.Name.EndsWith(
                ".complete",
                StringComparison.Ordinal)))
            .Select(group => new
            {
                group.Key,
                Files = group.Value,
                LastWriteUtc = group.Value.Max(file => file.LastWriteTimeUtc),
                CompletePair = group.Value.Any(file => file.Name.EndsWith(
                        ".partial",
                        StringComparison.Ordinal))
                    && group.Value.Any(file => file.Name.EndsWith(
                        ".partial.json",
                        StringComparison.Ordinal)),
            })
            .Where(group => group.CompletePair)
            .OrderByDescending(group => group.LastWriteUtc)
            .ThenBy(group => group.Key, StringComparer.Ordinal)
            .Take(MaximumRetainedPartialGroups)
            .Where(group => observedNowUtc - new DateTimeOffset(
                    DateTime.SpecifyKind(group.LastWriteUtc, DateTimeKind.Utc))
                <= MaximumPartialAge)
            .Select(group => group.Key)
            .ToHashSet(StringComparer.Ordinal);

        foreach (var group in groups.OrderBy(value => value.Key, StringComparer.Ordinal))
        {
            if (partialCandidates.Contains(group.Key))
            {
                continue;
            }
            foreach (var file in group.Value.OrderBy(value => value.Name, StringComparer.Ordinal))
            {
                DeleteCacheFile(file.FullName);
                removed++;
            }
        }
        return removed;
    }

    private void QuarantineAndDelete(string source, string component)
    {
        PersonalPathGuard.ValidateSafeTree(source, _layout.ManagedRoot);
        EnsureQuarantineRoot();
        var destination = Path.Combine(
            QuarantineRoot,
            $"q-{Guid.NewGuid():N}");
        if (!PersonalPathGuard.IsStrictDescendant(destination, QuarantineRoot)
            || Directory.Exists(destination)
            || File.Exists(destination))
        {
            throw new InvalidDataException(
                $"Personal {component} GC quarantine destination is unsafe.");
        }
        Directory.Move(source, destination);
        PersonalPathGuard.ValidateSafeTree(destination, _layout.ManagedRoot);
        DeleteQuarantinedTree(destination);
    }

    private void RetryQuarantineCleanup()
    {
        if (!Directory.Exists(QuarantineRoot))
        {
            return;
        }
        PersonalPathGuard.ValidateSafeTree(QuarantineRoot, _layout.ManagedRoot);
        foreach (var entry in new DirectoryInfo(QuarantineRoot)
                     .EnumerateFileSystemInfos("*", SearchOption.TopDirectoryOnly)
                     .OrderBy(value => value.Name, StringComparer.Ordinal))
        {
            if (entry is not DirectoryInfo directory
                || !QuarantineNameRegex().IsMatch(directory.Name))
            {
                throw new InvalidDataException(
                    "Personal GC quarantine contains an unrecognized entry.");
            }
            DeleteQuarantinedTree(directory.FullName);
        }
        if (!Directory.EnumerateFileSystemEntries(QuarantineRoot).Any())
        {
            Directory.Delete(QuarantineRoot);
        }
    }

    private void DeleteQuarantinedTree(string path)
    {
        PersonalPathGuard.ValidateSafeTree(path, _layout.ManagedRoot);
        _beforeDeleteForTest?.Invoke(path);
        PersonalPathGuard.ValidateSafeTree(path, _layout.ManagedRoot);
        Directory.Delete(path, recursive: true);
    }

    private void DeleteCacheFile(string path)
    {
        if (!PersonalPathGuard.IsStrictDescendant(path, _layout.PartialCacheRoot))
        {
            throw new InvalidDataException("Personal cache deletion escaped its root.");
        }
        RejectReparse(path);
        PersonalPathGuard.RequireSingleLinkFile(path);
        _beforeDeleteForTest?.Invoke(path);
        RejectReparse(path);
        PersonalPathGuard.RequireSingleLinkFile(path);
        File.Delete(path);
    }

    private void EnsureQuarantineRoot()
    {
        PersonalPathGuard.EnsureDirectoryChain(_layout.PackageRoot, QuarantineRoot);
        RejectReparse(QuarantineRoot);
    }

    private void RemoveEmptyQuarantineRoot()
    {
        if (!Directory.Exists(QuarantineRoot))
        {
            return;
        }
        PersonalPathGuard.ValidateSafeTree(QuarantineRoot, _layout.ManagedRoot);
        if (!Directory.EnumerateFileSystemEntries(QuarantineRoot).Any())
        {
            Directory.Delete(QuarantineRoot);
        }
    }

    private void WriteRetryMarker(Exception exception)
    {
        _layout.EnsureManagedRoots();
        var attempt = 1;
        if (File.Exists(RetryMarkerPath))
        {
            RequireSafeRetryMarker();
            try
            {
                using var document = JsonDocument.Parse(File.ReadAllBytes(RetryMarkerPath));
                if (document.RootElement.TryGetProperty("attempt", out var value)
                    && value.TryGetInt32(out var previous)
                    && previous is >= 1 and < int.MaxValue)
                {
                    attempt = previous + 1;
                }
            }
            catch (JsonException parseException)
            {
                throw new InvalidDataException("Personal GC retry marker is malformed.", parseException);
            }
        }
        var bytes = JsonSerializer.SerializeToUtf8Bytes(new
        {
            schemaVersion = 1,
            attempt,
            failure = exception.GetType().Name,
            recordedAtUtc = _timeProvider.GetUtcNow(),
        });
        PersonalReleaseSetPointerStore.WriteFileAtomically(
            RetryMarkerPath,
            bytes,
            _layout.ManagedRoot);
    }

    private void DeleteRetryMarkerIfPresent()
    {
        if (!File.Exists(RetryMarkerPath))
        {
            return;
        }
        RequireSafeRetryMarker();
        File.Delete(RetryMarkerPath);
    }

    private void RequireSafeRetryMarker()
    {
        if (!PersonalPathGuard.IsStrictDescendant(RetryMarkerPath, _layout.ManagedRoot)
            || (File.GetAttributes(RetryMarkerPath) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException("Personal GC retry marker is unsafe.");
        }
        PersonalPathGuard.RequireSingleLinkFile(RetryMarkerPath);
    }

    private string QuarantineRoot => Path.Combine(
        _layout.PackageRoot,
        ".managed-gc-quarantine-v1");

    private string RetryMarkerPath => Path.Combine(
        _layout.StateRoot,
        "managed-artifact-gc.retry.v1.json");

    private static bool TryParseStagingName(string name, out string releaseId)
    {
        var match = StagingNameRegex().Match(name);
        releaseId = match.Success ? match.Groups["release"].Value : string.Empty;
        if (!match.Success)
        {
            return false;
        }
        PersonalPathGuard.ValidateReleaseId(releaseId);
        return true;
    }

    private static string? ParsePersonalCacheKey(string name)
    {
        foreach (var regex in new[]
        {
            CompleteNameRegex(),
            PartialNameRegex(),
            MetadataNameRegex(),
            LockNameRegex(),
            TemporaryMetadataNameRegex(),
        })
        {
            var match = regex.Match(name);
            if (match.Success)
            {
                return match.Groups["key"].Value;
            }
        }
        return null;
    }

    private static void RejectReparse(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException("Personal GC refuses filesystem links.");
        }
    }

    [GeneratedRegex("^\\.(?<release>[A-Za-z0-9][A-Za-z0-9._+-]{0,127})\\.staging-[0-9a-f]{32}$", RegexOptions.CultureInvariant)]
    private static partial Regex StagingNameRegex();

    [GeneratedRegex("^q-[0-9a-f]{32}$", RegexOptions.CultureInvariant)]
    private static partial Regex QuarantineNameRegex();

    [GeneratedRegex("^(?<key>[0-9a-f]{64})\\.complete$", RegexOptions.CultureInvariant)]
    private static partial Regex CompleteNameRegex();

    [GeneratedRegex("^(?<key>[0-9a-f]{64})\\.partial$", RegexOptions.CultureInvariant)]
    private static partial Regex PartialNameRegex();

    [GeneratedRegex("^(?<key>[0-9a-f]{64})\\.partial\\.json$", RegexOptions.CultureInvariant)]
    private static partial Regex MetadataNameRegex();

    [GeneratedRegex("^\\.(?<key>[0-9a-f]{64})\\.lock$", RegexOptions.CultureInvariant)]
    private static partial Regex LockNameRegex();

    [GeneratedRegex("^\\.(?<key>[0-9a-f]{64})\\.partial\\.json\\.[0-9a-f]{32}\\.tmp$", RegexOptions.CultureInvariant)]
    private static partial Regex TemporaryMetadataNameRegex();
}
