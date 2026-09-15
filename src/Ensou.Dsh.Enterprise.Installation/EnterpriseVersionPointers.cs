using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Ensou.Dsh.Enterprise.Installation;

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record EnterpriseLauncherPointer(
    int SchemaVersion,
    string ReleaseId,
    string LauncherDirectory,
    string? PreviousReleaseId,
    string? PreviousLauncherDirectory,
    DateTimeOffset UpdatedAtUtc);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record EnterpriseRuntimePointer(
    int SchemaVersion,
    string ReleaseId,
    string RuntimeDirectory,
    string? PreviousReleaseId,
    string? PreviousRuntimeDirectory,
    DateTimeOffset UpdatedAtUtc);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record EnterpriseInstalledReleaseReceipt(
    int SchemaVersion,
    string ReleaseId,
    string ArchiveSha256,
    string PrimaryExecutableSha256,
    string? SecondaryFileSha256,
    DateTimeOffset InstalledAtUtc);

public sealed class EnterpriseLauncherPointerStore(EnterpriseInstallationLayout layout)
{
    private const string ReceiptFileName = ".ensou-enterprise-launcher.json";
    private readonly EnterpriseInstallationLayout _layout = layout
        ?? throw new ArgumentNullException(nameof(layout));

    public EnterpriseLauncherPointer? TryRead()
    {
        if (!File.Exists(_layout.LauncherPointerPath))
        {
            return null;
        }

        EnterprisePathGuard.ValidateExistingPathWithin(
            _layout.LauncherPointerPath,
            _layout.ManagedRoot,
            requireDirectory: false);
        var pointer = EnterprisePointerJson.Deserialize<EnterpriseLauncherPointer>(
            File.ReadAllBytes(_layout.LauncherPointerPath));
        Validate(pointer);
        return pointer;
    }

    public EnterpriseLauncherPointer ReadRequired() =>
        TryRead()
        ?? throw new InvalidDataException(
            "企业 Launcher 尚未安装完成；请运行企业安装器进行安装或修复。");

    public EnterpriseLauncherPointer Activate(string releaseId)
    {
        var launcherDirectory = _layout.GetLauncherVersionDirectory(releaseId);
        ValidateInstalledRelease(releaseId, launcherDirectory);
        using var writer = EnterprisePointerWriter.Acquire();
        var current = TryReadRecoverableForActivation();
        var next = current is not null
            && string.Equals(current.ReleaseId, releaseId, StringComparison.Ordinal)
            ? current with { UpdatedAtUtc = DateTimeOffset.UtcNow }
            : new EnterpriseLauncherPointer(
                1,
                releaseId,
                launcherDirectory,
                current?.ReleaseId,
                current?.LauncherDirectory,
                DateTimeOffset.UtcNow);
        Write(next);
        return next;
    }

    public EnterpriseLauncherPointer Rollback()
    {
        using var writer = EnterprisePointerWriter.Acquire();
        var current = ReadRequired();
        if (string.IsNullOrWhiteSpace(current.PreviousReleaseId)
            || string.IsNullOrWhiteSpace(current.PreviousLauncherDirectory))
        {
            throw new InvalidOperationException("没有可回滚的企业 Launcher 版本。");
        }

        ValidateInstalledRelease(
            current.PreviousReleaseId,
            current.PreviousLauncherDirectory);
        var rollback = new EnterpriseLauncherPointer(
            1,
            current.PreviousReleaseId,
            current.PreviousLauncherDirectory,
            current.ReleaseId,
            current.LauncherDirectory,
            DateTimeOffset.UtcNow);
        Write(rollback);
        return rollback;
    }

    public void Validate(EnterpriseLauncherPointer pointer)
    {
        ArgumentNullException.ThrowIfNull(pointer);
        if (pointer.SchemaVersion != 1)
        {
            throw new InvalidDataException("企业 Launcher 指针版本不受支持。");
        }

        ValidateInstalledRelease(pointer.ReleaseId, pointer.LauncherDirectory);
        ValidatePreviousTuple(
            pointer.PreviousReleaseId,
            pointer.PreviousLauncherDirectory,
            _layout.LauncherVersionsRoot);
    }

    internal static void WriteReceipt(
        string directory,
        EnterpriseInstalledReleaseReceipt receipt,
        string managedRoot)
    {
        var path = Path.Combine(directory, ReceiptFileName);
        EnterprisePathGuard.WriteFileAtomically(
            path,
            EnterprisePointerJson.Serialize(receipt),
            managedRoot);
    }

    private void ValidateInstalledRelease(string releaseId, string launcherDirectory)
    {
        EnterprisePathGuard.ValidateReleaseId(releaseId);
        var expected = _layout.GetLauncherVersionDirectory(releaseId);
        if (!string.Equals(
                EnterprisePathGuard.NormalizeDirectory(launcherDirectory),
                expected,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "企业 Launcher 指针越过了 launcher-versions 边界。");
        }

        EnterprisePathGuard.ValidateExistingPathWithin(
            expected,
            _layout.ManagedRoot,
            requireDirectory: true);
        ValidateReceiptAndPrimaryFile(
            expected,
            ReceiptFileName,
            EnterpriseInstallationLayout.LauncherExecutableName,
            secondaryRelativePath: null,
            releaseId,
            _layout.ManagedRoot);
    }

    private void Write(EnterpriseLauncherPointer pointer) =>
        EnterprisePathGuard.WriteFileAtomically(
            _layout.LauncherPointerPath,
            EnterprisePointerJson.Serialize(pointer),
            _layout.ManagedRoot);

    private EnterpriseLauncherPointer? TryReadRecoverableForActivation()
    {
        try
        {
            return TryRead();
        }
        catch (Exception exception) when (
            exception is InvalidDataException or IOException or JsonException)
        {
            return null;
        }
    }

    internal static void ValidateReceiptAndPrimaryFile(
        string directory,
        string receiptFileName,
        string primaryRelativePath,
        string? secondaryRelativePath,
        string releaseId,
        string managedRoot)
    {
        var receiptPath = Path.Combine(directory, receiptFileName);
        var primaryPath = Path.GetFullPath(Path.Combine(directory, primaryRelativePath));
        var secondaryPath = secondaryRelativePath is null
            ? null
            : Path.GetFullPath(Path.Combine(directory, secondaryRelativePath));
        if (!EnterprisePathGuard.IsSameOrDescendant(primaryPath, directory))
        {
            throw new InvalidDataException("Enterprise primary executable escaped its release root.");
        }

        if (secondaryPath is not null
            && !EnterprisePathGuard.IsSameOrDescendant(secondaryPath, directory))
        {
            throw new InvalidDataException("Enterprise secondary file escaped its release root.");
        }

        EnterprisePathGuard.ValidateExistingPathWithin(
            receiptPath,
            managedRoot,
            requireDirectory: false);
        EnterprisePathGuard.ValidateExistingPathWithin(
            primaryPath,
            managedRoot,
            requireDirectory: false);
        if (secondaryPath is not null)
        {
            EnterprisePathGuard.ValidateExistingPathWithin(
                secondaryPath,
                managedRoot,
                requireDirectory: false);
        }
        var receipt = EnterprisePointerJson.Deserialize<EnterpriseInstalledReleaseReceipt>(
            File.ReadAllBytes(receiptPath));
        if (receipt.SchemaVersion != 1
            || !string.Equals(receipt.ReleaseId, releaseId, StringComparison.Ordinal)
            || !EnterpriseHash.IsSha256(receipt.ArchiveSha256)
            || !EnterpriseHash.IsSha256(receipt.PrimaryExecutableSha256)
            || ((secondaryPath is null) != (receipt.SecondaryFileSha256 is null))
            || (receipt.SecondaryFileSha256 is not null
                && !EnterpriseHash.IsSha256(receipt.SecondaryFileSha256)))
        {
            throw new InvalidDataException("Enterprise release receipt is invalid.");
        }

        var actualSha256 = EnterpriseHash.ComputeFile(primaryPath);
        if (!string.Equals(
                actualSha256,
                receipt.PrimaryExecutableSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException("Enterprise release primary executable was modified.");
        }

        if (secondaryPath is not null
            && !string.Equals(
                EnterpriseHash.ComputeFile(secondaryPath),
                receipt.SecondaryFileSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException("Enterprise release secondary file was modified.");
        }
    }

    private static void ValidatePreviousTuple(
        string? previousReleaseId,
        string? previousDirectory,
        string versionRoot)
    {
        if ((previousReleaseId is null) != (previousDirectory is null))
        {
            throw new InvalidDataException("Enterprise previous-version pointer is incomplete.");
        }

        if (previousReleaseId is null)
        {
            return;
        }

        EnterprisePathGuard.ValidateReleaseId(previousReleaseId);
        var expected = EnterprisePathGuard.CombineExactChild(versionRoot, previousReleaseId);
        if (!string.Equals(
                EnterprisePathGuard.NormalizeDirectory(previousDirectory!),
                expected,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("Enterprise previous-version pointer escaped its root.");
        }
    }
}

public sealed class EnterpriseRuntimePointerStore(EnterpriseInstallationLayout layout)
{
    private const string ReceiptFileName = ".ensou-enterprise-runtime.json";
    private const string RuntimeEntryPoint =
        "node_modules/@deepseek-ai/dsh/lib/bin.js";
    private readonly EnterpriseInstallationLayout _layout = layout
        ?? throw new ArgumentNullException(nameof(layout));

    public EnterpriseRuntimePointer? TryRead()
    {
        if (!File.Exists(_layout.RuntimePointerPath))
        {
            return null;
        }

        EnterprisePathGuard.ValidateExistingPathWithin(
            _layout.RuntimePointerPath,
            _layout.ManagedRoot,
            requireDirectory: false);
        var pointer = EnterprisePointerJson.Deserialize<EnterpriseRuntimePointer>(
            File.ReadAllBytes(_layout.RuntimePointerPath));
        Validate(pointer);
        return pointer;
    }

    public EnterpriseRuntimePointer ReadRequired() =>
        TryRead()
        ?? throw new InvalidDataException(
            "企业 DSH 运行时尚未安装完成；请运行企业安装器进行安装或修复。");

    public EnterpriseRuntimePointer Activate(string releaseId)
    {
        var runtimeDirectory = _layout.GetRuntimeVersionDirectory(releaseId);
        ValidateInstalledRelease(releaseId, runtimeDirectory);
        using var writer = EnterprisePointerWriter.Acquire();
        var current = TryReadRecoverableForActivation();
        var next = current is not null
            && string.Equals(current.ReleaseId, releaseId, StringComparison.Ordinal)
            ? current with { UpdatedAtUtc = DateTimeOffset.UtcNow }
            : new EnterpriseRuntimePointer(
                1,
                releaseId,
                runtimeDirectory,
                current?.ReleaseId,
                current?.RuntimeDirectory,
                DateTimeOffset.UtcNow);
        Write(next);
        return next;
    }

    public EnterpriseRuntimePointer Rollback()
    {
        using var writer = EnterprisePointerWriter.Acquire();
        var current = ReadRequired();
        if (string.IsNullOrWhiteSpace(current.PreviousReleaseId)
            || string.IsNullOrWhiteSpace(current.PreviousRuntimeDirectory))
        {
            throw new InvalidOperationException("没有可回滚的企业 DSH 运行时版本。");
        }

        ValidateInstalledRelease(
            current.PreviousReleaseId,
            current.PreviousRuntimeDirectory);
        var rollback = new EnterpriseRuntimePointer(
            1,
            current.PreviousReleaseId,
            current.PreviousRuntimeDirectory,
            current.ReleaseId,
            current.RuntimeDirectory,
            DateTimeOffset.UtcNow);
        Write(rollback);
        return rollback;
    }

    public void Validate(EnterpriseRuntimePointer pointer)
    {
        ArgumentNullException.ThrowIfNull(pointer);
        if (pointer.SchemaVersion != 1)
        {
            throw new InvalidDataException("企业 DSH 运行时指针版本不受支持。");
        }

        ValidateInstalledRelease(pointer.ReleaseId, pointer.RuntimeDirectory);
        ValidatePreviousTuple(pointer.PreviousReleaseId, pointer.PreviousRuntimeDirectory);
    }

    internal static void WriteReceipt(
        string directory,
        EnterpriseInstalledReleaseReceipt receipt,
        string managedRoot)
    {
        var path = Path.Combine(directory, ReceiptFileName);
        EnterprisePathGuard.WriteFileAtomically(
            path,
            EnterprisePointerJson.Serialize(receipt),
            managedRoot);
    }

    private void ValidateInstalledRelease(string releaseId, string runtimeDirectory)
    {
        EnterprisePathGuard.ValidateReleaseId(releaseId);
        var expected = _layout.GetRuntimeVersionDirectory(releaseId);
        if (!string.Equals(
                EnterprisePathGuard.NormalizeDirectory(runtimeDirectory),
                expected,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "企业 DSH 运行时指针越过了 runtimes 边界。");
        }

        EnterprisePathGuard.ValidateExistingPathWithin(
            expected,
            _layout.ManagedRoot,
            requireDirectory: true);
        EnterpriseLauncherPointerStore.ValidateReceiptAndPrimaryFile(
            expected,
            ReceiptFileName,
            "node.exe",
            RuntimeEntryPoint,
            releaseId,
            _layout.ManagedRoot);
    }

    private void ValidatePreviousTuple(string? previousReleaseId, string? previousDirectory)
    {
        if ((previousReleaseId is null) != (previousDirectory is null))
        {
            throw new InvalidDataException("Enterprise previous runtime pointer is incomplete.");
        }

        if (previousReleaseId is null)
        {
            return;
        }

        EnterprisePathGuard.ValidateReleaseId(previousReleaseId);
        var expected = _layout.GetRuntimeVersionDirectory(previousReleaseId);
        if (!string.Equals(
                EnterprisePathGuard.NormalizeDirectory(previousDirectory!),
                expected,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "Enterprise previous runtime pointer escaped its root.");
        }
    }

    private void Write(EnterpriseRuntimePointer pointer) =>
        EnterprisePathGuard.WriteFileAtomically(
            _layout.RuntimePointerPath,
            EnterprisePointerJson.Serialize(pointer),
            _layout.ManagedRoot);

    private EnterpriseRuntimePointer? TryReadRecoverableForActivation()
    {
        try
        {
            return TryRead();
        }
        catch (Exception exception) when (
            exception is InvalidDataException or IOException or JsonException)
        {
            return null;
        }
    }
}

internal static class EnterprisePointerJson
{
    private static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    public static byte[] Serialize<T>(T value) => JsonSerializer.SerializeToUtf8Bytes(value, Options);

    public static T Deserialize<T>(ReadOnlySpan<byte> value) =>
        JsonSerializer.Deserialize<T>(value, Options)
        ?? throw new InvalidDataException("Enterprise installation state is empty.");
}

internal static class EnterpriseHash
{
    public static string ComputeFile(string path)
    {
        using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 128 * 1024,
            FileOptions.SequentialScan);
        return Convert.ToHexStringLower(SHA256.HashData(stream));
    }

    public static bool IsSha256(string value) =>
        value.Length == 64 && value.All(character =>
            character is >= '0' and <= '9' or >= 'a' and <= 'f');
}

internal static class EnterprisePointerWriter
{
    private const string MutexName = "Local\\Ensou.Dsh.Enterprise.Installation.PointerWriter";

    public static IDisposable Acquire()
    {
        var mutex = new Mutex(initiallyOwned: false, MutexName);
        try
        {
            if (!mutex.WaitOne(TimeSpan.FromSeconds(30)))
            {
                throw new TimeoutException("等待企业安装状态写入锁超时。");
            }

            return new Releaser(mutex);
        }
        catch
        {
            mutex.Dispose();
            throw;
        }
    }

    private sealed class Releaser(Mutex mutex) : IDisposable
    {
        private Mutex? _mutex = mutex;

        public void Dispose()
        {
            var value = Interlocked.Exchange(ref _mutex, null);
            if (value is null)
            {
                return;
            }

            value.ReleaseMutex();
            value.Dispose();
        }
    }
}
