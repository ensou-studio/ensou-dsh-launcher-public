using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using Ensou.Dsh.Contracts;
using Microsoft.Win32.SafeHandles;

namespace Ensou.Dsh.UpdateEngine;

public enum PersonalLegacyInstallClassification
{
    Clean = 0,
    LocalDataOnly = 1,
    ExactV1 = 2,
    ManagedV2 = 3,
    UnknownManualConflict = 4,
}

public sealed record PersonalInstallPreflightResult(
    PersonalLegacyInstallClassification ExistingInstall,
    long MinimumAvailableDiskBytes,
    bool IsBelowRecommendedDiskSpace);

public sealed class PersonalInstallPreflightException : InvalidOperationException
{
    public PersonalInstallPreflightException(
        string code,
        string message,
        Exception? innerException = null)
        : base($"[{code}] {message}", innerException)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(code);
        Code = code;
    }

    public string Code { get; }
}

public static class PersonalInstallPreflight
{
    public const long MinimumDiskBytes = 2L * 1024 * 1024 * 1024;
    public const long RecommendedDiskBytes = 5L * 1024 * 1024 * 1024;

    public static PersonalInstallPreflightResult RequireReady(
        PersonalInstallationLayout layout,
        int loopbackPort = PersonalInstallMigrationService.DefaultLoopbackPort) =>
        RequireReady(layout, loopbackPort, PersonalInstallPreflightProbes.ForLayout(layout));

    internal static PersonalInstallPreflightResult RequireReady(
        PersonalInstallationLayout layout,
        int loopbackPort,
        PersonalInstallPreflightProbes probes)
    {
        ArgumentNullException.ThrowIfNull(layout);
        ArgumentNullException.ThrowIfNull(probes);
        if (loopbackPort is < 1 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(loopbackPort));
        }

        var platform = RunProbe(
            "PERSONAL_PREFLIGHT_PLATFORM_PROBE_FAILED",
            "无法确认当前 Windows 与处理器环境；安装尚未开始。",
            probes.ReadPlatform);
        if (!platform.IsWindows
            || !platform.IsClientOperatingSystem
            || platform.OperatingSystemVersion.Major != 10
            || platform.OperatingSystemVersion.Minor != 0
            || platform.OperatingSystemVersion.Build < PersonalInstallPlatformSnapshot.MinimumSupportedWindowsBuild)
        {
            throw Failure(
                "PERSONAL_PREFLIGHT_WINDOWS_VERSION_UNSUPPORTED",
                "仅支持原生 Windows 10 或 Windows 11 x64；安装尚未开始。");
        }
        if (platform.OperatingSystemArchitecture != Architecture.X64
            || platform.ProcessArchitecture != Architecture.X64)
        {
            throw Failure(
                "PERSONAL_PREFLIGHT_ARCHITECTURE_UNSUPPORTED",
                "仅支持原生 x64 Windows 与 x64 安装器进程；安装尚未开始。");
        }
        if (platform.IsElevated
            || platform.IntegrityLevelRid != PersonalInstallPlatformSnapshot.MediumIntegrityRid)
        {
            throw Failure(
                "PERSONAL_PREFLIGHT_TOKEN_UNSUPPORTED",
                "请使用普通用户权限启动安装器，不要以管理员身份运行；安装尚未开始。");
        }

        RunProbe(
            "PERSONAL_PREFLIGHT_INSTALL_ROOT_UNSAFE",
            "安装目录、用户数据目录或安全状态目录不可安全写入，或路径包含文件系统链接；安装尚未开始。",
            () => probes.RequireOrdinaryWritableRoots(
                PersonalInstallPreflightFileSystem.GetProtectedRoots(layout)));

        RunProbe(
            "PERSONAL_PREFLIGHT_RUNTIME_CONFLICT",
            $"请先退出 DeepSeek Harness Launcher，并确认端口 {loopbackPort} 未被占用；安装尚未开始。",
            () => probes.RequireNoRuntimeConflict(loopbackPort));

        var classification = RunProbe(
            "PERSONAL_PREFLIGHT_LEGACY_INSPECTION_FAILED",
            "无法安全识别已有 Personal 安装；安装尚未开始。",
            () => PersonalInstallPreflightFileSystem.ClassifyExistingInstall(layout));
        if (classification == PersonalLegacyInstallClassification.UnknownManualConflict)
        {
            throw Failure(
                "PERSONAL_PREFLIGHT_UNKNOWN_MANUAL_CONFLICT",
                "检测到无法自动接管的旧版、残缺 v2 或手工 DSH 程序目录。请联系支持人员处理，安装尚未开始。");
        }

        var volumeRoots = PersonalInstallPreflightFileSystem.GetProtectedRoots(layout)
            .Select(Path.GetPathRoot)
            .Where(root => !string.IsNullOrWhiteSpace(root))
            .Select(root => Path.TrimEndingDirectorySeparator(Path.GetFullPath(root!)))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (volumeRoots.Length == 0)
        {
            throw Failure(
                "PERSONAL_PREFLIGHT_DISK_PROBE_FAILED",
                "无法识别安装目标磁盘；安装尚未开始。");
        }
        var availableBytes = volumeRoots
            .Select(root => RunProbe(
                "PERSONAL_PREFLIGHT_DISK_PROBE_FAILED",
                "无法读取安装目标磁盘的可用空间；安装尚未开始。",
                () => probes.ReadAvailableDiskBytes(root)))
            .ToArray();
        var minimumAvailable = availableBytes.Min();
        if (minimumAvailable < MinimumDiskBytes)
        {
            throw Failure(
                "PERSONAL_PREFLIGHT_DISK_SPACE_INSUFFICIENT",
                "安装目标磁盘至少需要 2 GB 可用空间，建议保留 5 GB；安装尚未开始。");
        }

        var hasDefaultBrowser = RunProbe(
            "PERSONAL_PREFLIGHT_DEFAULT_BROWSER_PROBE_FAILED",
            "无法确认 Windows 默认浏览器；安装尚未开始。",
            probes.HasDefaultHttpBrowser);
        if (!hasDefaultBrowser)
        {
            throw Failure(
                "PERSONAL_PREFLIGHT_DEFAULT_BROWSER_MISSING",
                "请先在 Windows 中设置默认浏览器，以便打开 DSH WebUI；安装尚未开始。");
        }

        return new PersonalInstallPreflightResult(
            classification,
            minimumAvailable,
            minimumAvailable < RecommendedDiskBytes);
    }

    private static PersonalInstallPreflightException Failure(
        string code,
        string message,
        Exception? innerException = null) => new(code, message, innerException);

    private static void RunProbe(
        string code,
        string message,
        Action probe)
    {
        try
        {
            probe();
        }
        catch (PersonalInstallPreflightException)
        {
            throw;
        }
        catch (Exception exception)
        {
            throw Failure(code, message, exception);
        }
    }

    private static T RunProbe<T>(
        string code,
        string message,
        Func<T> probe)
    {
        try
        {
            return probe();
        }
        catch (PersonalInstallPreflightException)
        {
            throw;
        }
        catch (Exception exception)
        {
            throw Failure(code, message, exception);
        }
    }
}

internal sealed record PersonalInstallPlatformSnapshot(
    bool IsWindows,
    bool IsClientOperatingSystem,
    Version OperatingSystemVersion,
    Architecture OperatingSystemArchitecture,
    Architecture ProcessArchitecture,
    bool IsElevated,
    int IntegrityLevelRid)
{
    public const int MinimumSupportedWindowsBuild = 10240;
    public const int MediumIntegrityRid = 0x2000;
}

internal sealed record PersonalInstallPreflightProbes(
    Func<PersonalInstallPlatformSnapshot> ReadPlatform,
    Action<IReadOnlyCollection<string>> RequireOrdinaryWritableRoots,
    Action<int> RequireNoRuntimeConflict,
    Func<string, long> ReadAvailableDiskBytes,
    Func<bool> HasDefaultHttpBrowser)
{
    public static PersonalInstallPreflightProbes ForLayout(
        PersonalInstallationLayout layout) => new(
        PersonalInstallPreflightWindows.ReadPlatform,
        PersonalInstallPreflightFileSystem.RequireOrdinaryWritableRoots,
        port =>
        {
            PersonalInstallerProcessGuard.RequireNoManagedClientProcesses();
            PersonalHarnessWriterGuard.RequireAvailableLoopbackPort(port);
            using var lease = new PersonalHarnessHomeCoordinator(layout.HarnessHome)
                .AcquireLease(() =>
                    PersonalHarnessWriterGuard.RequireQuiescentLoopbackPort(port));
            lease.RequireMutationAdmission(layout.HarnessHome);
        },
        PersonalInstallPreflightFileSystem.ReadAvailableDiskBytes,
        PersonalInstallPreflightWindows.HasDefaultHttpBrowser);
}

internal static class PersonalInstallPreflightFileSystem
{
    private const int MaximumLegacyEntries = 1_000_000;
    private const string ProbePrefix = ".ensou-personal-preflight-";

    public static IReadOnlyCollection<string> GetProtectedRoots(
        PersonalInstallationLayout layout)
    {
        ArgumentNullException.ThrowIfNull(layout);
        var provenance = new PersonalInstallProvenanceStore(layout, TimeProvider.System);
        return new[]
            {
                layout.ManagedRoot,
                layout.HarnessHome,
                layout.HarnessRecoveryRoot,
                layout.UpdateOperationLockRoot,
                Path.GetDirectoryName(layout.UpdateSecurityWitnessPath)
                    ?? throw new InvalidDataException(
                        "Personal update-security witness has no parent directory."),
                Path.GetDirectoryName(layout.V2MigrationFootprintPath)
                    ?? throw new InvalidDataException(
                        "Personal migration footprint has no parent directory."),
                Path.GetDirectoryName(provenance.PrimaryPath)
                    ?? throw new InvalidDataException(
                        "Personal install provenance primary has no parent directory."),
                Path.GetDirectoryName(provenance.WitnessPath)
                    ?? throw new InvalidDataException(
                        "Personal install provenance witness has no parent directory."),
            }
            .Select(PersonalPathGuard.NormalizeDirectory)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    public static void RequireOrdinaryWritableRoots(
        IReadOnlyCollection<string> roots)
    {
        ArgumentNullException.ThrowIfNull(roots);
        if (roots.Count == 0)
        {
            throw new InvalidDataException("Personal preflight has no protected roots.");
        }

        var probeDirectories = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var root in roots)
        {
            var normalized = PersonalPathGuard.NormalizeDirectory(root);
            var closestExistingDirectory = RequireOrdinaryAncestors(normalized);
            probeDirectories.Add(closestExistingDirectory);
        }
        foreach (var directory in probeDirectories)
        {
            ProbeWriteAndRemove(directory);
        }
    }

    public static long ReadAvailableDiskBytes(string volumeRoot)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(volumeRoot);
        var drive = new DriveInfo(volumeRoot);
        if (!drive.IsReady)
        {
            throw new IOException("Personal installation volume is not ready.");
        }
        return drive.AvailableFreeSpace;
    }

    public static PersonalLegacyInstallClassification ClassifyExistingInstall(
        PersonalInstallationLayout layout)
    {
        ArgumentNullException.ThrowIfNull(layout);
        var journal = new PersonalInstallMigrationJournalStore(layout, TimeProvider.System);
        try
        {
            if (journal.TryReadForPreflight() is not null)
            {
                return PersonalLegacyInstallClassification.ManagedV2;
            }
        }
        catch (Exception exception) when (IsClassificationFailure(exception))
        {
            return PersonalLegacyInstallClassification.UnknownManualConflict;
        }

        var provenanceStore = new PersonalInstallProvenanceStore(
            layout,
            TimeProvider.System);
        PersonalInstallProvenance? provenance;
        try
        {
            provenance = provenanceStore.TryReadAuthenticatedForPreflight();
        }
        catch (Exception exception) when (IsClassificationFailure(exception))
        {
            return PersonalLegacyInstallClassification.UnknownManualConflict;
        }

        var v2EvidencePaths = GetV2EvidencePaths(
            layout,
            journal,
            provenanceStore);
        var hasAnyV2Evidence = v2EvidencePaths.Any(EntryExists);
        if (File.Exists(layout.ManagedRoot))
        {
            return PersonalLegacyInstallClassification.UnknownManualConflict;
        }
        if (!Directory.Exists(layout.ManagedRoot))
        {
            if (hasAnyV2Evidence || provenance is not null)
            {
                return PersonalLegacyInstallClassification.UnknownManualConflict;
            }
            return Directory.Exists(layout.HarnessHome)
                ? PersonalLegacyInstallClassification.LocalDataOnly
                : PersonalLegacyInstallClassification.Clean;
        }
        try
        {
            if (IsExactV1(layout.ManagedRoot))
            {
                if (hasAnyV2Evidence || provenance is not null)
                {
                    return PersonalLegacyInstallClassification.UnknownManualConflict;
                }
                return PersonalLegacyInstallClassification.ExactV1;
            }
        }
        catch (InvalidDataException)
        {
            return PersonalLegacyInstallClassification.UnknownManualConflict;
        }
        if (provenance is not null && IsCompleteManagedV2(
                layout,
                provenanceStore,
                provenance))
        {
            return PersonalLegacyInstallClassification.ManagedV2;
        }
        return PersonalLegacyInstallClassification.UnknownManualConflict;
    }

    private static string RequireOrdinaryAncestors(string path)
    {
        string? closestExistingDirectory = null;
        for (var current = new DirectoryInfo(path);
             current is not null;
             current = current.Parent)
        {
            if (File.Exists(current.FullName))
            {
                throw new InvalidDataException(
                    "A Personal installation directory segment is occupied by a file.");
            }
            if (!current.Exists)
            {
                continue;
            }
            if ((current.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException(
                    "A Personal installation path crosses a filesystem link.");
            }
            closestExistingDirectory ??= current.FullName;
        }
        return closestExistingDirectory
            ?? throw new DirectoryNotFoundException(
                "Personal installation path has no existing local ancestor.");
    }

    private static void ProbeWriteAndRemove(string directory)
    {
        var probePath = Path.Combine(
            directory,
            ProbePrefix + Guid.NewGuid().ToString("N") + ".tmp");
        Exception? failure = null;
        try
        {
            using var probe = new FileStream(
                probePath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                1,
                FileOptions.DeleteOnClose | FileOptions.WriteThrough);
            probe.WriteByte(0);
            probe.Flush(flushToDisk: true);
        }
        catch (Exception exception)
        {
            failure = exception;
        }
        finally
        {
            try
            {
                if (File.Exists(probePath))
                {
                    if ((File.GetAttributes(probePath) & FileAttributes.ReparsePoint) != 0)
                    {
                        throw new InvalidDataException(
                            "Personal write probe was replaced by a filesystem link.");
                    }
                    File.Delete(probePath);
                }
                if (File.Exists(probePath) || Directory.Exists(probePath))
                {
                    throw new IOException(
                        "Personal write probe could not be removed without residue.");
                }
            }
            catch (Exception cleanupFailure)
            {
                throw new AggregateException(
                    "Personal write probe failed and could not prove residue-free cleanup.",
                    failure is null ? [cleanupFailure] : [failure, cleanupFailure]);
            }
        }
        if (failure is not null)
        {
            throw new IOException(
                "Personal installation parent directory is not writable.",
                failure);
        }
    }

    private static bool IsExactV1(string root)
    {
        var expected = new Dictionary<string, bool>(StringComparer.Ordinal)
        {
            ["runtimes"] = true,
            ["snapshots"] = true,
            ["state"] = true,
            ["launcher.settings.json"] = false,
        };
        var entries = Directory.EnumerateFileSystemEntries(
                root,
                "*",
                SearchOption.TopDirectoryOnly)
            .ToArray();
        if (entries.Length != expected.Count)
        {
            return false;
        }
        foreach (var entry in entries)
        {
            var name = Path.GetFileName(entry);
            if (!expected.TryGetValue(name, out var shouldBeDirectory)
                || (File.GetAttributes(entry) & FileAttributes.ReparsePoint) != 0
                || shouldBeDirectory != Directory.Exists(entry)
                || !shouldBeDirectory && !File.Exists(entry))
            {
                return false;
            }
        }
        var stateEntries = Directory.EnumerateFileSystemEntries(
                Path.Combine(root, "state"),
                "*",
                SearchOption.TopDirectoryOnly)
            .ToArray();
        if (stateEntries.Length != 1
            || !string.Equals(
                Path.GetFileName(stateEntries[0]),
                "runtime-current.json",
                StringComparison.Ordinal)
            || !File.Exists(stateEntries[0])
            || (File.GetAttributes(stateEntries[0]) & FileAttributes.ReparsePoint) != 0)
        {
            return false;
        }
        RequireOrdinarySingleLinkTree(root);
        return true;
    }

    private static void RequireOrdinarySingleLinkTree(string root)
    {
        var normalizedRoot = PersonalPathGuard.NormalizeDirectory(root);
        var pending = new Queue<string>();
        pending.Enqueue(normalizedRoot);
        var observed = 0;
        while (pending.Count != 0)
        {
            var directory = pending.Dequeue();
            foreach (var entry in Directory.EnumerateFileSystemEntries(
                         directory,
                         "*",
                         SearchOption.TopDirectoryOnly))
            {
                observed++;
                if (observed > MaximumLegacyEntries
                    || !PersonalPathGuard.IsStrictDescendant(entry, normalizedRoot)
                    || (File.GetAttributes(entry) & FileAttributes.ReparsePoint) != 0)
                {
                    throw new InvalidDataException(
                        "Personal legacy tree is unbounded, linked, or escaped its root.");
                }
                if (Directory.Exists(entry))
                {
                    pending.Enqueue(entry);
                }
                else
                {
                    PersonalPathGuard.RequireSingleLinkFile(entry);
                }
            }
        }
    }

    private static IReadOnlyList<string> GetV2EvidencePaths(
        PersonalInstallationLayout layout,
        PersonalInstallMigrationJournalStore journal,
        PersonalInstallProvenanceStore provenance)
    {
        return new[]
        {
            journal.JournalPath,
            layout.UpdateOperationLockPath,
            layout.ReleaseSetPointerPath,
            layout.InstallationIdentityReceiptPath,
            layout.InstallationIdentityProtectedPath,
            layout.UpdateSecurityStatePath,
            layout.UpdateSecurityStatePath + ".anchor",
            layout.UpdateSecurityStatePath + ".anchor.pending",
            layout.UpdateSecurityStatePath + ".lock",
            layout.UpdateSecurityWitnessPath,
            layout.V2MigrationFootprintPath,
            layout.StartupStubPath,
        }.Concat(provenance.EvidencePaths)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static bool IsCompleteManagedV2(
        PersonalInstallationLayout layout,
        PersonalInstallProvenanceStore provenanceStore,
        PersonalInstallProvenance provenance)
    {
        try
        {
            foreach (var requiredPath in new[]
            {
                layout.ReleaseSetPointerPath,
                layout.UpdateSecurityStatePath,
                layout.UpdateSecurityStatePath + ".anchor",
                layout.UpdateSecurityWitnessPath,
                layout.V2MigrationFootprintPath,
                layout.StartupStubPath,
                provenanceStore.PrimaryPath,
                provenanceStore.WitnessPath,
            })
            {
                RequireRegularSingleLinkFile(requiredPath);
            }
            var hasIdentityReceipt = EntryExists(layout.InstallationIdentityReceiptPath);
            var hasIdentityWitness = EntryExists(layout.InstallationIdentityProtectedPath);
            if (hasIdentityReceipt != hasIdentityWitness)
            {
                return false;
            }
            if (hasIdentityReceipt)
            {
                _ = new PersonalInstallationIdentityStore(layout).ReadRequired();
            }
            if (provenanceStore.EvidencePaths.Skip(2).Any(EntryExists)
                || EntryExists(layout.UpdateSecurityStatePath + ".anchor.pending"))
            {
                return false;
            }

            var pointer = new PersonalReleaseSetPointerStore(layout).ReadRequired();
            if (!hasIdentityReceipt
                && PersonalReleaseVersion.Compare(
                    pointer.Current.StartupStub.MinimumVersion,
                    PersonalInstallationIdentityStore.IdentityAwareStartupStubVersion) >= 0)
            {
                return false;
            }
            if (pointer.Current.HealthState != PersonalReleaseHealthStates.Healthy)
            {
                return false;
            }
            var releaseSecurity = new PersonalReleaseSecurityStateStore(
                    layout.UpdateSecurityStatePath,
                    new PersonalReleaseStateIdentity(
                        PersonalReleaseSetContract.Product,
                        PersonalReleaseSetContract.ProductionEnvironment,
                        provenance.SecurityState.Channel),
                    layout.UpdateSecurityWitnessPath)
                .TryReadForPreflightAsync()
                .GetAwaiter()
                .GetResult() ?? throw new InvalidDataException(
                    "Personal managed v2 release security state is missing.");
            PersonalInstallProvenanceStore.RequireMatchingSecurityState(
                provenance,
                releaseSecurity);
            var footprint = new PersonalV2MigrationFootprintStore(
                    layout.UpdateSecurityStatePath,
                    layout.UpdateSecurityWitnessPath,
                    layout.V2MigrationFootprintPath)
                .TryRead() ?? throw new InvalidDataException(
                    "Personal managed v2 footprint is missing.");
            PersonalInstallProvenanceStore.RequireMatchingFootprint(
                provenance,
                footprint);
            var security = provenance.SecurityState;
            if (!string.Equals(pointer.Channel, security.Channel, StringComparison.Ordinal)
                || !string.Equals(
                    pointer.Current.ReleaseSetId,
                    security.LastCommittedReleaseSetId,
                    StringComparison.Ordinal)
                || pointer.Current.Sequence != security.LastCommittedSequence
                || !string.Equals(
                    pointer.Current.ManifestSha256,
                    security.LastCommittedManifestSha256,
                    StringComparison.Ordinal))
            {
                return false;
            }
            return true;
        }
        catch (Exception exception) when (IsClassificationFailure(exception))
        {
            return false;
        }
    }

    private static void RequireRegularSingleLinkFile(string path)
    {
        if (!File.Exists(path)
            || (File.GetAttributes(path) & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
        {
            throw new InvalidDataException(
                "Personal managed v2 evidence is missing, linked, or not a regular file.");
        }
        PersonalPathGuard.RequireSingleLinkFile(path);
    }

    private static bool EntryExists(string path)
    {
        try
        {
            _ = File.GetAttributes(path);
            return true;
        }
        catch (Exception exception) when (exception is FileNotFoundException
            or DirectoryNotFoundException)
        {
            return false;
        }
    }

    private static bool IsClassificationFailure(Exception exception) => exception is
        InvalidDataException
        or IOException
        or UnauthorizedAccessException
        or System.Security.Cryptography.CryptographicException
        or System.Text.Json.JsonException
        or Win32Exception
        or NotSupportedException;
}

[SupportedOSPlatform("windows")]
internal static class PersonalInstallPreflightWindows
{
    private const uint TokenQuery = 0x0008;
    private const int TokenElevation = 20;
    private const int TokenIntegrityLevel = 25;
    private const uint AssocStringExecutable = 2;
    private const int ErrorInsufficientBuffer = 122;
    private const uint SFalse = 1;
    private const byte VerNtWorkstation = 1;

    public static PersonalInstallPlatformSnapshot ReadPlatform()
    {
        if (!OperatingSystem.IsWindows())
        {
            return new PersonalInstallPlatformSnapshot(
                false,
                false,
                Environment.OSVersion.Version,
                RuntimeInformation.OSArchitecture,
                RuntimeInformation.ProcessArchitecture,
                false,
                0);
        }
        var windowsIdentity = ReadWindowsIdentity();
        using var process = Process.GetCurrentProcess();
        if (!OpenProcessToken(process.Handle, TokenQuery, out var token))
        {
            throw new Win32Exception(
                Marshal.GetLastPInvokeError(),
                "Unable to open the Personal Installer process token.");
        }
        using (token)
        {
            return new PersonalInstallPlatformSnapshot(
                true,
                windowsIdentity.IsClientOperatingSystem,
                windowsIdentity.Version,
                RuntimeInformation.OSArchitecture,
                RuntimeInformation.ProcessArchitecture,
                ReadElevation(token),
                ReadIntegrityLevelRid(token));
        }
    }

    private static PersonalWindowsIdentitySnapshot ReadWindowsIdentity()
    {
        var value = new OsVersionInfoEx();
        value.Size = Marshal.SizeOf(value);
        var status = RtlGetVersion(value);
        if (status != 0)
        {
            throw new InvalidOperationException(
                $"Unable to read the native Windows product identity (NTSTATUS 0x{status:X8}).");
        }
        return new PersonalWindowsIdentitySnapshot(
            new Version(
                checked((int)value.MajorVersion),
                checked((int)value.MinorVersion),
                checked((int)value.BuildNumber)),
            value.ProductType == VerNtWorkstation);
    }

    public static bool HasDefaultHttpBrowser()
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }
        uint requiredCharacters = 0;
        var first = AssocQueryString(
            0,
            AssocStringExecutable,
            "http",
            null,
            null,
            ref requiredCharacters);
        if (requiredCharacters <= 1
            || first is not 0 and not SFalse
                && Marshal.GetLastPInvokeError() != ErrorInsufficientBuffer)
        {
            return false;
        }
        var output = new StringBuilder(checked((int)requiredCharacters));
        var second = AssocQueryString(
            0,
            AssocStringExecutable,
            "http",
            null,
            output,
            ref requiredCharacters);
        if (second != 0)
        {
            return false;
        }
        var executable = Environment.ExpandEnvironmentVariables(output.ToString().Trim());
        return !string.IsNullOrWhiteSpace(executable) && File.Exists(executable);
    }

    private static bool ReadElevation(SafeAccessTokenHandle token)
    {
        var size = sizeof(int);
        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (!GetTokenInformation(
                    token,
                    TokenElevation,
                    buffer,
                    size,
                    out _))
            {
                throw new Win32Exception(
                    Marshal.GetLastPInvokeError(),
                    "Unable to read the Personal Installer token elevation.");
            }
            return Marshal.ReadInt32(buffer) != 0;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static int ReadIntegrityLevelRid(SafeAccessTokenHandle token)
    {
        _ = GetTokenInformation(
            token,
            TokenIntegrityLevel,
            IntPtr.Zero,
            0,
            out var requiredBytes);
        if (requiredBytes <= 0
            || Marshal.GetLastPInvokeError() != ErrorInsufficientBuffer)
        {
            throw new Win32Exception(
                Marshal.GetLastPInvokeError(),
                "Unable to size the Personal Installer integrity token.");
        }
        var buffer = Marshal.AllocHGlobal(requiredBytes);
        try
        {
            if (!GetTokenInformation(
                    token,
                    TokenIntegrityLevel,
                    buffer,
                    requiredBytes,
                    out _))
            {
                throw new Win32Exception(
                    Marshal.GetLastPInvokeError(),
                    "Unable to read the Personal Installer integrity token.");
            }
            var sid = Marshal.ReadIntPtr(buffer);
            if (sid == IntPtr.Zero || !IsValidSid(sid))
            {
                throw new InvalidDataException(
                    "Personal Installer integrity token has an invalid SID.");
            }
            var countPointer = GetSidSubAuthorityCount(sid);
            if (countPointer == IntPtr.Zero)
            {
                throw new Win32Exception(
                    Marshal.GetLastPInvokeError(),
                    "Unable to read the Personal Installer integrity SID.");
            }
            var count = Marshal.ReadByte(countPointer);
            if (count == 0)
            {
                throw new InvalidDataException(
                    "Personal Installer integrity SID has no authority RID.");
            }
            var ridPointer = GetSidSubAuthority(sid, (uint)(count - 1));
            if (ridPointer == IntPtr.Zero)
            {
                throw new Win32Exception(
                    Marshal.GetLastPInvokeError(),
                    "Unable to read the Personal Installer integrity RID.");
            }
            return Marshal.ReadInt32(ridPointer);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(
        IntPtr processHandle,
        uint desiredAccess,
        out SafeAccessTokenHandle tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(
        SafeAccessTokenHandle tokenHandle,
        int tokenInformationClass,
        IntPtr tokenInformation,
        int tokenInformationLength,
        out int returnLength);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsValidSid(IntPtr sid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern IntPtr GetSidSubAuthority(IntPtr sid, uint subAuthority);

    [DllImport("shlwapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint AssocQueryString(
        uint flags,
        uint associationString,
        string association,
        string? extra,
        StringBuilder? output,
        ref uint outputCharacters);

    [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
    private static extern int RtlGetVersion([In, Out] OsVersionInfoEx versionInformation);

    private sealed record PersonalWindowsIdentitySnapshot(
        Version Version,
        bool IsClientOperatingSystem);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private sealed class OsVersionInfoEx
    {
        public int Size;
        public uint MajorVersion;
        public uint MinorVersion;
        public uint BuildNumber;
        public uint PlatformId;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string ServicePack = string.Empty;

        public ushort ServicePackMajor;
        public ushort ServicePackMinor;
        public ushort SuiteMask;
        public byte ProductType;
        public byte Reserved;
    }
}
