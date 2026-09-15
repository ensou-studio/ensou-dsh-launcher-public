using System.Runtime.InteropServices;
using System.ComponentModel;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;

namespace Ensou.Dsh.Enterprise.Installation;

public enum EnterpriseManagedArtifactGcStatus
{
    Completed,
    SkippedBusy,
    SkippedPending,
}

public sealed record EnterpriseManagedArtifactGcResult(
    EnterpriseManagedArtifactGcStatus Status,
    int RemovedVersionDirectories,
    int RemovedCacheFiles,
    int RemovedOperationDirectories,
    bool RetriedPreviousFailure);

/// <summary>
/// Cross-process lease shared by enterprise install, automatic update, and managed GC.
/// </summary>
public sealed class EnterpriseManagedUpdateOperationLease : IDisposable, IAsyncDisposable
{
    private FileStream? _stream;

    private EnterpriseManagedUpdateOperationLease(FileStream stream) => _stream = stream;

    public static async Task<EnterpriseManagedUpdateOperationLease> AcquireRequiredAsync(
        EnterpriseInstallationLayout layout,
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
                    "等待企业托管更新操作锁超时。");
            }
            await Task.Delay(TimeSpan.FromMilliseconds(50), cancellationToken)
                .ConfigureAwait(false);
        }
    }

    internal static EnterpriseManagedUpdateOperationLease? TryAcquire(
        EnterpriseInstallationLayout layout)
    {
        ArgumentNullException.ThrowIfNull(layout);
        layout.EnsureUpdateOperationLockRoot();
        var path = layout.UpdateOperationLockPath;
        var handle = EnterpriseManagedGcPathSafety.TryOpenOperationLock(path);
        if (handle is null)
        {
            return null;
        }
        FileStream? stream = null;
        try
        {
            EnterpriseManagedGcPathSafety.RequireSingleLinkHandle(handle);
            stream = new FileStream(
                handle,
                FileAccess.ReadWrite,
                bufferSize: 1,
                isAsync: false);
            return new EnterpriseManagedUpdateOperationLease(stream);
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

/// <summary>
/// Bounded, fail-closed cleanup for immutable enterprise component trees and update packages.
/// Harness home and Harness recovery generations are intentionally unreachable from this class.
/// </summary>
public sealed partial class EnterpriseManagedArtifactGarbageCollector
{
    private const int MaximumRetainedPartialGroups = 4;
    private static readonly TimeSpan MaximumPartialAge = TimeSpan.FromDays(7);
    private readonly EnterpriseInstallationLayout _layout;
    private readonly EnterpriseCompiledReleaseTrust _compiledTrust;
    private readonly TimeProvider _timeProvider;
    private readonly Action<string>? _beforeDeleteForTest;

    public EnterpriseManagedArtifactGarbageCollector(
        EnterpriseInstallationLayout layout,
        EnterpriseCompiledReleaseTrust compiledTrust,
        TimeProvider? timeProvider = null)
        : this(layout, compiledTrust, timeProvider, beforeDeleteForTest: null)
    {
    }

    internal EnterpriseManagedArtifactGarbageCollector(
        EnterpriseInstallationLayout layout,
        EnterpriseCompiledReleaseTrust compiledTrust,
        TimeProvider? timeProvider,
        Action<string>? beforeDeleteForTest)
    {
        _layout = layout ?? throw new ArgumentNullException(nameof(layout));
        _compiledTrust = compiledTrust ?? throw new ArgumentNullException(nameof(compiledTrust));
        _timeProvider = timeProvider ?? TimeProvider.System;
        _beforeDeleteForTest = beforeDeleteForTest;
    }

    public Task<EnterpriseManagedArtifactGcResult> CollectAsync(
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var lease = EnterpriseManagedUpdateOperationLease.TryAcquire(_layout);
        if (lease is null)
        {
            return Task.FromResult(new EnterpriseManagedArtifactGcResult(
                EnterpriseManagedArtifactGcStatus.SkippedBusy,
                0,
                0,
                0,
                false));
        }
        using (lease)
        {
            EnterpriseManagedOperationRecovery.RecoverInterruptedUnderLease(_layout);
            var store = new EnterpriseReleaseSetPointerStore(
                _layout,
                _compiledTrust,
                _timeProvider);
            var before = store.ReadRequired();
            if (before.Current.HealthState != EnterpriseReleaseHealthStates.Healthy
                || before.Previous is { HealthState: not EnterpriseReleaseHealthStates.Healthy }
                || new EnterpriseHarnessHomeUpdateTransaction(
                        _layout.HarnessHome,
                        _layout.HarnessRecoveryRoot,
                        _timeProvider)
                    .TryReadActiveState() is not null)
            {
                return Task.FromResult(new EnterpriseManagedArtifactGcResult(
                    EnterpriseManagedArtifactGcStatus.SkippedPending,
                    0,
                    0,
                    0,
                    false));
            }
            return Task.FromResult(CollectTrustedUnderLease(
                before,
                store.ReadRequired,
                _timeProvider.GetUtcNow()));
        }
    }

    internal EnterpriseManagedArtifactGcResult CollectTrustedUnderLease(
        EnterpriseReleaseSetPointer before,
        Func<EnterpriseReleaseSetPointer> readPointerAgain,
        DateTimeOffset observedNowUtc)
    {
        ArgumentNullException.ThrowIfNull(before);
        ArgumentNullException.ThrowIfNull(readPointerAgain);
        if (observedNowUtc.Offset != TimeSpan.Zero)
        {
            throw new ArgumentException("Enterprise GC observation time must be UTC.");
        }
        if (before.Current.HealthState != EnterpriseReleaseHealthStates.Healthy
            || before.Previous is { HealthState: not EnterpriseReleaseHealthStates.Healthy })
        {
            return new EnterpriseManagedArtifactGcResult(
                EnterpriseManagedArtifactGcStatus.SkippedPending,
                0,
                0,
                0,
                false);
        }

        var retried = File.Exists(RetryMarkerPath) || Directory.Exists(QuarantineRoot);
        var removedVersions = 0;
        var removedCacheFiles = 0;
        var removedOperationDirectories = 0;
        try
        {
            _layout.EnsureManagedRoots();
            RetryQuarantineCleanup();
            removedVersions += CollectVersionRoot(
                _layout.LauncherVersionsRoot,
                new[]
                {
                    before.Current.Launcher.ReleaseId,
                    before.Previous?.Launcher.ReleaseId,
                },
                "launcher");
            removedVersions += CollectVersionRoot(
                _layout.RuntimeVersionsRoot,
                new[]
                {
                    before.Current.Runtime.ReleaseId,
                    before.Previous?.Runtime.ReleaseId,
                },
                "runtime");
            removedVersions += CollectVersionRoot(
                _layout.PluginPolicyVersionsRoot,
                new[]
                {
                    before.Current.PluginPolicy?.ReleaseId,
                    before.Previous?.PluginPolicy?.ReleaseId,
                },
                "plugin");
            removedCacheFiles += CollectPartialCache(observedNowUtc);
            removedOperationDirectories += CollectAbandonedOperationDirectories();
            RemoveEmptyQuarantineRoot();

            var after = readPointerAgain();
            if (before != after)
            {
                throw new InvalidDataException(
                    "Enterprise release pointer changed while managed GC held its operation lock.");
            }
            DeleteRetryMarkerIfPresent();
            return new EnterpriseManagedArtifactGcResult(
                EnterpriseManagedArtifactGcStatus.Completed,
                removedVersions,
                removedCacheFiles,
                removedOperationDirectories,
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
                    "Enterprise managed artifact GC failed and could not persist its retry marker.",
                    new AggregateException(exception, markerException));
            }
            throw new InvalidOperationException(
                "Enterprise managed artifact GC failed closed; cleanup will be retried.",
                exception);
        }
    }

    private int CollectVersionRoot(
        string versionRoot,
        IEnumerable<string?> protectedReleaseIds,
        string component)
    {
        EnterprisePathGuard.EnsureDirectoryChain(_layout.ManagedRoot, versionRoot);
        var keep = protectedReleaseIds
            .Where(value => value is not null)
            .Cast<string>()
            .ToHashSet(StringComparer.Ordinal);
        if (keep.Count > 2)
        {
            throw new InvalidDataException("Enterprise GC retained more than current and previous.");
        }
        var removed = 0;
        foreach (var entry in new DirectoryInfo(versionRoot)
                     .EnumerateFileSystemInfos("*", SearchOption.TopDirectoryOnly)
                     .OrderBy(value => value.Name, StringComparer.Ordinal))
        {
            if (entry is not DirectoryInfo directory)
            {
                throw new InvalidDataException(
                    "Enterprise version roots may contain only controlled directories.");
            }
            EnterpriseManagedGcPathSafety.RejectReparse(directory.FullName);
            if (TryParseStagingName(directory.Name, out _))
            {
                QuarantineAndDelete(directory.FullName, component + "-staging");
                removed++;
                continue;
            }
            EnterprisePathGuard.ValidateReleaseId(directory.Name);
            var exact = EnterprisePathGuard.CombineExactChild(versionRoot, directory.Name);
            if (!string.Equals(exact, directory.FullName, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException("Enterprise version directory is not an exact child.");
            }
            if (keep.Contains(directory.Name))
            {
                EnterpriseManagedGcPathSafety.ValidateSafeTreeWithSingleLinks(
                    directory.FullName,
                    _layout.ManagedRoot);
                continue;
            }
            QuarantineAndDelete(directory.FullName, component);
            removed++;
        }
        return removed;
    }

    private int CollectPartialCache(DateTimeOffset observedNowUtc)
    {
        EnterprisePathGuard.EnsureDirectoryChain(
            _layout.PackageRoot,
            _layout.UpdatePartialCacheRoot);
        var groups = new Dictionary<string, List<FileInfo>>(StringComparer.Ordinal);
        var removed = 0;
        foreach (var entry in new DirectoryInfo(_layout.UpdatePartialCacheRoot)
                     .EnumerateFileSystemInfos("*", SearchOption.TopDirectoryOnly)
                     .ToArray())
        {
            if (entry is not FileInfo file)
            {
                throw new InvalidDataException(
                    "Enterprise partial cache may contain only controlled files.");
            }
            EnterpriseManagedGcPathSafety.RequireSingleLinkFile(
                file.FullName,
                _layout.ManagedRoot);
            if (TemporaryMetadataNameRegex().IsMatch(file.Name))
            {
                DeleteCacheFile(file.FullName);
                removed++;
                continue;
            }
            var key = ParseCacheKey(file.Name)
                ?? throw new InvalidDataException(
                    "Enterprise partial cache contains an unrecognized entry.");
            if (!groups.TryGetValue(key, out var files))
            {
                files = [];
                groups.Add(key, files);
            }
            files.Add(file);
        }

        var retained = groups
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
            if (retained.Contains(group.Key))
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

    private int CollectAbandonedOperationDirectories()
    {
        var removed = 0;
        foreach (var entry in new DirectoryInfo(_layout.PackageRoot)
                     .EnumerateFileSystemInfos("*", SearchOption.TopDirectoryOnly)
                     .OrderBy(value => value.Name, StringComparer.Ordinal))
        {
            if (string.Equals(
                    entry.FullName,
                    _layout.UpdatePartialCacheRoot,
                    StringComparison.OrdinalIgnoreCase)
                || string.Equals(
                    entry.FullName,
                    QuarantineRoot,
                    StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }
            if (entry is not DirectoryInfo directory
                || !OperationDirectoryNameRegex().IsMatch(directory.Name))
            {
                throw new InvalidDataException(
                    "Enterprise package root contains an unrecognized entry.");
            }
            QuarantineAndDelete(directory.FullName, "operation");
            removed++;
        }
        return removed;
    }

    private void QuarantineAndDelete(string source, string component)
    {
        EnterpriseManagedGcPathSafety.ValidateSafeTreeWithSingleLinks(
            source,
            _layout.ManagedRoot);
        EnsureQuarantineRoot();
        var destination = Path.Combine(QuarantineRoot, $"q-{Guid.NewGuid():N}");
        if (!EnterprisePathGuard.IsSameOrDescendant(destination, QuarantineRoot)
            || string.Equals(destination, QuarantineRoot, StringComparison.OrdinalIgnoreCase)
            || Directory.Exists(destination)
            || File.Exists(destination))
        {
            throw new InvalidDataException(
                $"Enterprise {component} GC quarantine destination is unsafe.");
        }
        Directory.Move(source, destination);
        EnterpriseManagedGcPathSafety.ValidateSafeTreeWithSingleLinks(
            destination,
            _layout.ManagedRoot);
        DeleteQuarantinedTree(destination);
    }

    private void RetryQuarantineCleanup()
    {
        if (!Directory.Exists(QuarantineRoot))
        {
            return;
        }
        EnterpriseManagedGcPathSafety.ValidateSafeTreeWithSingleLinks(
            QuarantineRoot,
            _layout.ManagedRoot);
        foreach (var entry in new DirectoryInfo(QuarantineRoot)
                     .EnumerateFileSystemInfos("*", SearchOption.TopDirectoryOnly)
                     .OrderBy(value => value.Name, StringComparer.Ordinal))
        {
            if (entry is not DirectoryInfo directory
                || !QuarantineNameRegex().IsMatch(directory.Name))
            {
                throw new InvalidDataException(
                    "Enterprise GC quarantine contains an unrecognized entry.");
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
        EnterpriseManagedGcPathSafety.ValidateSafeTreeWithSingleLinks(
            path,
            _layout.ManagedRoot);
        _beforeDeleteForTest?.Invoke(path);
        EnterpriseManagedGcPathSafety.ValidateSafeTreeWithSingleLinks(
            path,
            _layout.ManagedRoot);
        Directory.Delete(path, recursive: true);
    }

    private void DeleteCacheFile(string path)
    {
        if (!EnterprisePathGuard.IsSameOrDescendant(path, _layout.UpdatePartialCacheRoot)
            || string.Equals(
                EnterprisePathGuard.NormalizeDirectory(path),
                EnterprisePathGuard.NormalizeDirectory(_layout.UpdatePartialCacheRoot),
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("Enterprise cache deletion escaped its root.");
        }
        EnterpriseManagedGcPathSafety.RequireSingleLinkFile(path, _layout.ManagedRoot);
        _beforeDeleteForTest?.Invoke(path);
        EnterpriseManagedGcPathSafety.RequireSingleLinkFile(path, _layout.ManagedRoot);
        File.Delete(path);
    }

    private void EnsureQuarantineRoot()
    {
        EnterprisePathGuard.EnsureDirectoryChain(_layout.PackageRoot, QuarantineRoot);
        EnterpriseManagedGcPathSafety.RejectReparse(QuarantineRoot);
    }

    private void RemoveEmptyQuarantineRoot()
    {
        if (!Directory.Exists(QuarantineRoot))
        {
            return;
        }
        EnterpriseManagedGcPathSafety.ValidateSafeTreeWithSingleLinks(
            QuarantineRoot,
            _layout.ManagedRoot);
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
            EnterpriseManagedGcPathSafety.RequireSingleLinkFile(
                RetryMarkerPath,
                _layout.ManagedRoot);
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
                throw new InvalidDataException(
                    "Enterprise GC retry marker is malformed.",
                    parseException);
            }
        }
        EnterprisePathGuard.WriteFileAtomically(
            RetryMarkerPath,
            JsonSerializer.SerializeToUtf8Bytes(new
            {
                schemaVersion = 1,
                attempt,
                failure = exception.GetType().Name,
                recordedAtUtc = _timeProvider.GetUtcNow(),
            }),
            _layout.ManagedRoot);
    }

    private void DeleteRetryMarkerIfPresent()
    {
        if (!File.Exists(RetryMarkerPath))
        {
            return;
        }
        EnterpriseManagedGcPathSafety.RequireSingleLinkFile(
            RetryMarkerPath,
            _layout.ManagedRoot);
        File.Delete(RetryMarkerPath);
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
        EnterprisePathGuard.ValidateReleaseId(releaseId);
        return true;
    }

    private static string? ParseCacheKey(string name)
    {
        foreach (var regex in new[]
        {
            PartialNameRegex(),
            MetadataNameRegex(),
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

    [GeneratedRegex("^\\.(?<release>[A-Za-z0-9][A-Za-z0-9._+-]{0,127})\\.staging-[0-9a-f]{32}$", RegexOptions.CultureInvariant)]
    private static partial Regex StagingNameRegex();

    [GeneratedRegex("^q-[0-9a-f]{32}$", RegexOptions.CultureInvariant)]
    private static partial Regex QuarantineNameRegex();

    [GeneratedRegex("^\\.(?:release-set|install)-[0-9a-f]{32}$", RegexOptions.CultureInvariant)]
    private static partial Regex OperationDirectoryNameRegex();

    [GeneratedRegex("^(?<key>[0-9a-f]{64})\\.partial$", RegexOptions.CultureInvariant)]
    private static partial Regex PartialNameRegex();

    [GeneratedRegex("^(?<key>[0-9a-f]{64})\\.partial\\.json$", RegexOptions.CultureInvariant)]
    private static partial Regex MetadataNameRegex();

    [GeneratedRegex("^\\.(?<key>[0-9a-f]{64})\\.partial\\.json\\.[0-9a-f]{32}\\.tmp$", RegexOptions.CultureInvariant)]
    private static partial Regex TemporaryMetadataNameRegex();
}

internal readonly record struct EnterpriseManagedFileIdentity(
    uint VolumeSerialNumber,
    ulong FileIndex,
    long Length,
    uint FileAttributes,
    uint NumberOfLinks);

internal static class EnterpriseManagedGcPathSafety
{
    private const uint GenericRead = 0x80000000;
    private const uint GenericWrite = 0x40000000;
    private const uint FileShareRead = 0x00000001;
    private const uint OpenAlways = 4;
    private const uint FileAttributeNormal = 0x00000080;
    private const uint FileFlagWriteThrough = 0x80000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;

    public static SafeFileHandle? TryOpenOperationLock(string path)
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
        var win32Path = ToExtendedLengthWin32Path(path);
        var handle = CreateFile(
            win32Path,
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
            "Unable to open the enterprise update operation lock.",
            new Win32Exception(error));
    }

    private static string ToExtendedLengthWin32Path(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var fullPath = Path.GetFullPath(path);
        if (!Path.IsPathFullyQualified(fullPath)
            || fullPath.StartsWith("\\\\", StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Enterprise update operation lock path must be a local Windows path.");
        }

        return fullPath.StartsWith("\\\\?\\", StringComparison.Ordinal)
            ? fullPath
            : "\\\\?\\" + fullPath;
    }

    public static void RequireSafeExistingFileIfPresent(string path, string managedRoot)
    {
        if (File.Exists(path))
        {
            EnterprisePathGuard.ValidateExistingPathWithin(
                path,
                managedRoot,
                requireDirectory: false);
            RejectReparse(path);
        }
    }

    public static void RequireSingleLinkFile(string path, string managedRoot)
    {
        EnterprisePathGuard.ValidateExistingPathWithin(path, managedRoot, requireDirectory: false);
        RejectReparse(path);
        if (!OperatingSystem.IsWindows())
        {
            return;
        }
        using var handle = File.OpenHandle(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read);
        if (!GetFileInformationByHandle(handle, out var information))
        {
            throw new IOException(
                "Unable to inspect enterprise managed file link count.",
                Marshal.GetExceptionForHR(Marshal.GetHRForLastWin32Error()));
        }
        if ((information.FileAttributes & (uint)FileAttributes.ReparsePoint) != 0
            || information.NumberOfLinks != 1)
        {
            throw new InvalidDataException(
                "Enterprise managed GC refuses linked files.");
        }
    }

    public static void RequireSingleLinkHandle(SafeFileHandle handle)
    {
        ArgumentNullException.ThrowIfNull(handle);
        if (!OperatingSystem.IsWindows())
        {
            return;
        }
        var identity = GetFileIdentity(handle);
        if ((identity.FileAttributes & (uint)FileAttributes.ReparsePoint) != 0
            || identity.NumberOfLinks != 1)
        {
            throw new InvalidDataException(
                "Enterprise managed GC refuses linked files.");
        }
    }

    public static EnterpriseManagedFileIdentity GetFileIdentity(SafeFileHandle handle)
    {
        ArgumentNullException.ThrowIfNull(handle);
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "Enterprise managed file identity requires Windows.");
        }
        if (!GetFileInformationByHandle(handle, out var information))
        {
            throw new IOException(
                "Unable to inspect enterprise managed file identity.",
                Marshal.GetExceptionForHR(Marshal.GetHRForLastWin32Error()));
        }
        var unsignedLength =
            ((ulong)information.FileSizeHigh << 32)
            | information.FileSizeLow;
        if (unsignedLength > long.MaxValue)
        {
            throw new InvalidDataException(
                "Enterprise managed file length exceeds the supported range.");
        }
        return new EnterpriseManagedFileIdentity(
            information.VolumeSerialNumber,
            ((ulong)information.FileIndexHigh << 32) | information.FileIndexLow,
            checked((long)unsignedLength),
            information.FileAttributes,
            information.NumberOfLinks);
    }

    public static void ValidateSafeTreeWithSingleLinks(string path, string managedRoot)
    {
        EnterprisePathGuard.ValidateSafeTree(path, managedRoot);
        foreach (var file in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories))
        {
            RequireSingleLinkFile(file, managedRoot);
        }
    }

    public static void RejectReparse(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException("Enterprise managed GC refuses filesystem links.");
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
