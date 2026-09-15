using System.ComponentModel;
using System.Diagnostics;
using System.IO.Compression;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Win32.SafeHandles;

namespace Ensou.Dsh.Enterprise.Installation;

public enum EnterpriseLegacyMigrationDisposition
{
    FreshInstallRequired,
    CurrentInstallationAlreadyTrusted,
    Migrated,
    RegistrationRecovered,
}

public sealed record EnterpriseLegacyMigrationResult(
    EnterpriseLegacyMigrationDisposition Disposition,
    string? LauncherReleaseId,
    string? RuntimeReleaseId,
    string? PreservedLegacyProgramDirectory);

internal sealed record EnterpriseLegacyMigrationCandidate(
    string LauncherReleaseId,
    string RuntimeReleaseId);

internal sealed record EnterpriseLegacyMigrationCallbacks(
    Func<string, IEnterprisePayloadSource, CancellationToken,
        Task<EnterpriseLegacyMigrationCandidate>> StageCandidateAsync,
    Func<EnterpriseLegacyMigrationCandidate, CancellationToken, Task> FinalizeAsync,
    Action<EnterpriseLegacyMigrationCandidate> ValidateFinalized,
    Func<EnterpriseLegacyMigrationCandidate, CancellationToken, Task> RegisterAsync,
    Action<EnterpriseLegacyMigrationCandidate> ValidateRegistration);

internal enum EnterpriseLegacyMigrationFaultPoint
{
    AfterIntentJournal,
    AfterCandidateStagedBeforeJournal,
    AfterCandidatePreparedJournal,
    AfterOldRootRenameBeforeJournal,
    AfterOldIsolatedJournal,
    AfterCandidateRenameBeforeJournal,
    AfterCandidateActivatedJournal,
    AfterFinalizationBeforeJournal,
    AfterRegistrationPendingJournal,
    AfterRegistrationBeforeJournal,
    AfterMigrationTombstoneBeforeWitness,
    AfterMigrationWitnessBeforeJournalRetirement,
}

internal sealed class EnterpriseLegacyMigrationInjectedCrashException(
    EnterpriseLegacyMigrationFaultPoint faultPoint)
    : IOException($"Injected enterprise legacy migration crash at {faultPoint}.")
{
    public EnterpriseLegacyMigrationFaultPoint FaultPoint { get; } = faultPoint;
}

/// <summary>
/// Keeps the verified external Installer file identity locked while exposing
/// only the signed, embedded payload. FileShare.Read prevents replacement,
/// deletion, and writes for the lifetime of this lease.
/// </summary>
internal sealed class EnterpriseLegacyMigrationTrustedInstallerLease : IDisposable
{
    private const int MaximumManifestBytes = 128 * 1024;
    private readonly EnterpriseInstallationLayout _layout;
    private readonly FileStream _installer;
    private readonly IEnterprisePayloadSource _payloadSource;
    private readonly EnterpriseFileIdentity _identity;
    private bool _disposed;

    private EnterpriseLegacyMigrationTrustedInstallerLease(
        EnterpriseInstallationLayout layout,
        string installerPath,
        FileStream installer,
        IEnterprisePayloadSource payloadSource,
        EnterpriseInstallManifest manifest,
        string installerSha256,
        string payloadIdentitySha256,
        string launcherArchiveTreeSha256,
        string runtimeArchiveTreeSha256,
        EnterpriseFileIdentity identity)
    {
        _layout = layout;
        InstallerPath = installerPath;
        _installer = installer;
        _payloadSource = payloadSource;
        Manifest = manifest;
        InstallerSha256 = installerSha256;
        PayloadIdentitySha256 = payloadIdentitySha256;
        LauncherArchiveTreeSha256 = launcherArchiveTreeSha256;
        RuntimeArchiveTreeSha256 = runtimeArchiveTreeSha256;
        _identity = identity;
    }

    public string InstallerPath { get; }

    public string InstallerSha256 { get; }

    public string PayloadIdentitySha256 { get; }

    public string LauncherArchiveTreeSha256 { get; }

    public string RuntimeArchiveTreeSha256 { get; }

    public EnterpriseInstallManifest Manifest { get; }

    public static EnterpriseLegacyMigrationTrustedInstallerLease OpenProduction(
        EnterpriseInstallationLayout layout,
        Assembly installerAssembly,
        string installerExecutablePath)
    {
        ArgumentNullException.ThrowIfNull(layout);
        ArgumentNullException.ThrowIfNull(installerAssembly);
        ArgumentException.ThrowIfNullOrWhiteSpace(installerExecutablePath);
        if (layout.IsDevelopmentE2E)
        {
            throw new InvalidOperationException(
                "Legacy employee-install migration is unavailable in Development E2E mode.");
        }
        if (!ReferenceEquals(installerAssembly, Assembly.GetEntryAssembly())
            || !string.Equals(
                installerAssembly.GetName().Name,
                "Ensou.Dsh.Enterprise.Installer",
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Legacy migration requires the current Enterprise Installer entry assembly.");
        }
        var processPath = Environment.ProcessPath
            ?? throw new InvalidOperationException("Cannot identify the current Installer process.");
        if (!SamePath(processPath, installerExecutablePath))
        {
            throw new InvalidDataException(
                "Legacy migration Installer path does not identify the current process bytes.");
        }

        return OpenCore(
            layout,
            installerExecutablePath,
            new EnterpriseEmbeddedPayloadSource(installerAssembly),
            requireAuthenticode: true);
    }

    internal static EnterpriseLegacyMigrationTrustedInstallerLease OpenForTest(
        EnterpriseInstallationLayout layout,
        string installerExecutablePath,
        IEnterprisePayloadSource payloadSource)
    {
        ArgumentNullException.ThrowIfNull(payloadSource);
        return OpenCore(
            layout,
            installerExecutablePath,
            payloadSource,
            requireAuthenticode: false);
    }

    public IEnterprisePayloadSource RequirePayloadSource()
    {
        RequireIdentityUnchanged();
        return _payloadSource;
    }

    public void RequireIdentityUnchanged()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var current = EnterpriseFileIdentity.Read(_installer.SafeFileHandle);
        if (!_identity.Equals(current)
            || _installer.Length != _identity.Length
            || _identity.NumberOfLinks != 1
            || (_identity.Attributes & (uint)FileAttributes.ReparsePoint) != 0)
        {
            throw new IOException(
                "The verified external Enterprise Installer identity changed during migration.");
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        _payloadSource.Dispose();
        _installer.Dispose();
    }

    private static EnterpriseLegacyMigrationTrustedInstallerLease OpenCore(
        EnterpriseInstallationLayout layout,
        string installerExecutablePath,
        IEnterprisePayloadSource payloadSource,
        bool requireAuthenticode)
    {
        ArgumentNullException.ThrowIfNull(layout);
        ArgumentException.ThrowIfNullOrWhiteSpace(installerExecutablePath);
        var absolutePath = Path.GetFullPath(installerExecutablePath);
        RequireExternalInstallerPath(layout, absolutePath);

        FileStream? lockedInstaller = null;
        try
        {
            lockedInstaller = EnterpriseAuthenticodeVerifier.OpenLockedExecutable(absolutePath);
            var identity = EnterpriseFileIdentity.Read(lockedInstaller.SafeFileHandle);
            if (identity.NumberOfLinks != 1
                || (identity.Attributes & (uint)FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException(
                    "External Enterprise Installer must be an ordinary single-link file.");
            }
            if (requireAuthenticode)
            {
                EnterpriseAuthenticodeVerifier.RequireTrustedSignature(absolutePath);
            }

            var installerSha256 = HashLockedInstaller(lockedInstaller);
            var payload = VerifyAndIdentifyPayload(payloadSource);
            var manifest = payload.Manifest;
            var requiredLayoutProfile = requireAuthenticode
                ? EnterpriseInstallationLayout.ProductionLayoutProfile
                : layout.LayoutProfile;
            if (!string.Equals(
                    manifest.LayoutProfile,
                    requiredLayoutProfile,
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Legacy migration accepts only the embedded production layout payload.");
            }

            var result = new EnterpriseLegacyMigrationTrustedInstallerLease(
                layout,
                absolutePath,
                lockedInstaller,
                payloadSource,
                manifest,
                installerSha256,
                payload.PayloadIdentitySha256,
                payload.LauncherArchiveTreeSha256,
                payload.RuntimeArchiveTreeSha256,
                identity);
            lockedInstaller = null;
            payloadSource = null!;
            return result;
        }
        catch
        {
            lockedInstaller?.Dispose();
            payloadSource.Dispose();
            throw;
        }
    }

    private static void RequireExternalInstallerPath(
        EnterpriseInstallationLayout layout,
        string absolutePath)
    {
        if (!Path.IsPathFullyQualified(absolutePath)
            || EnterprisePathGuard.IsSameOrDescendant(absolutePath, layout.ManagedRoot)
            || EnterprisePathGuard.IsSameOrDescendant(absolutePath, layout.HarnessHome)
            || EnterprisePathGuard.IsSameOrDescendant(absolutePath, layout.HarnessRecoveryRoot)
            || !File.Exists(absolutePath)
            || (File.GetAttributes(absolutePath) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException(
                "Legacy migration requires an ordinary external Installer file.");
        }
        EnterpriseLegacyMigrationPathSafety.RejectLinkedAncestors(
            Path.GetDirectoryName(absolutePath)
            ?? throw new InvalidDataException("External Installer has no parent directory."));
    }

    private static string HashLockedInstaller(FileStream stream)
    {
        stream.Position = 0;
        var hash = Convert.ToHexStringLower(SHA256.HashData(stream));
        stream.Position = 0;
        return hash;
    }

    private static EnterpriseVerifiedInstallerPayload
        VerifyAndIdentifyPayload(IEnterprisePayloadSource source)
    {
        byte[] manifestBytes;
        using (var stream = source.Open(EnterpriseEmbeddedPayloadSource.ManifestFileName))
        {
            manifestBytes = ReadBounded(stream, MaximumManifestBytes, "manifest");
        }
        var manifest = EnterpriseInstallManifest.Parse(manifestBytes);
        VerifyPayload(
            source,
            manifest.LauncherArchive,
            manifest.LauncherArchiveSizeBytes,
            manifest.LauncherArchiveSha256);
        VerifyPayload(
            source,
            manifest.RuntimeArchive,
            manifest.RuntimeArchiveSizeBytes,
            manifest.RuntimeArchiveSha256);
        VerifyPayload(
            source,
            manifest.BootstrapperFile,
            manifest.BootstrapperSizeBytes,
            manifest.BootstrapperSha256);
        var launcherTreeSha256 = ComputeArchiveTreeSha256(
            source,
            manifest.LauncherArchive,
            "launcher");
        var runtimeTreeSha256 = ComputeArchiveTreeSha256(
            source,
            manifest.RuntimeArchive,
            "runtime");
        var manifestSha256 = Convert.ToHexStringLower(SHA256.HashData(manifestBytes));
        var identity = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(
            string.Join(
                '\n',
                "ensou-enterprise-installer-payload-v1",
                manifestSha256,
                manifest.LauncherArchiveSha256,
                manifest.RuntimeArchiveSha256,
                manifest.BootstrapperSha256))));
        CryptographicOperations.ZeroMemory(manifestBytes);
        return new EnterpriseVerifiedInstallerPayload(
            manifest,
            identity,
            launcherTreeSha256,
            runtimeTreeSha256);
    }

    private static string ComputeArchiveTreeSha256(
        IEnterprisePayloadSource source,
        string archiveName,
        string component)
    {
        const int maximumEntries = 200_000;
        const long maximumExpandedBytes = 8L * 1024 * 1024 * 1024;
        using var stream = source.Open(archiveName);
        using var archive = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: false);
        if (archive.Entries.Count == 0 || archive.Entries.Count > maximumEntries)
        {
            throw new InvalidDataException(
                $"Enterprise migration {component} archive entry count is invalid.");
        }
        var files = new List<(string RelativePath, string Sha256)>(archive.Entries.Count);
        var canonical = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        long expandedBytes = 0;
        foreach (var entry in archive.Entries)
        {
            var relative = ValidateArchiveEntry(entry);
            if (!canonical.Add(relative))
            {
                throw new InvalidDataException(
                    $"Enterprise migration {component} archive repeats a canonical path.");
            }
            expandedBytes = checked(expandedBytes + entry.Length);
            if (expandedBytes > maximumExpandedBytes)
            {
                throw new InvalidDataException(
                    $"Enterprise migration {component} archive expands beyond its bound.");
            }
            if (relative.EndsWith("/", StringComparison.Ordinal))
            {
                continue;
            }
            if (IsReservedReceiptPath(relative))
            {
                throw new InvalidDataException(
                    "Signed enterprise archives may not supply installer-owned receipt files.");
            }
            using var entryStream = entry.Open();
            var sha256 = Convert.ToHexStringLower(SHA256.HashData(entryStream));
            files.Add((relative, sha256));
        }
        using var aggregate = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (var file in files.OrderBy(file => file.RelativePath, StringComparer.Ordinal))
        {
            aggregate.AppendData(Encoding.UTF8.GetBytes(file.RelativePath));
            aggregate.AppendData([0]);
            aggregate.AppendData(Convert.FromHexString(file.Sha256));
            aggregate.AppendData([0]);
        }
        return Convert.ToHexStringLower(aggregate.GetHashAndReset());
    }

    private static string ValidateArchiveEntry(ZipArchiveEntry entry)
    {
        if ((entry.ExternalAttributes & (int)FileAttributes.ReparsePoint) != 0
            || ((entry.ExternalAttributes >> 16) & 0xF000) == 0xA000)
        {
            throw new InvalidDataException(
                "Enterprise migration archive contains a filesystem link.");
        }
        var normalized = entry.FullName.Replace('\\', '/');
        if (string.IsNullOrWhiteSpace(normalized)
            || normalized.StartsWith("/", StringComparison.Ordinal)
            || normalized.Length > 1024)
        {
            throw new InvalidDataException(
                "Enterprise migration archive path is invalid.");
        }
        var isDirectory = normalized.EndsWith("/", StringComparison.Ordinal);
        var segments = normalized.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length == 0)
        {
            throw new InvalidDataException(
                "Enterprise migration archive path is empty.");
        }
        foreach (var segment in segments)
        {
            if (segment is "." or ".."
                || segment.EndsWith(' ')
                || segment.EndsWith('.')
                || segment.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0
                || IsReservedWindowsName(segment))
            {
                throw new InvalidDataException(
                    "Enterprise migration archive contains an unsafe Windows path.");
            }
        }
        return string.Join('/', segments) + (isDirectory ? "/" : string.Empty);
    }

    private static bool IsReservedReceiptPath(string relativePath) =>
        relativePath is ".ensou-enterprise-launcher.json"
            or ".ensou-enterprise-runtime.json"
            or ".ensou-enterprise-plugin-policy.v2.json"
            or ".ensou-enterprise-artifact.v2.json";

    private static bool IsReservedWindowsName(string segment)
    {
        var name = segment.Split('.', 2)[0];
        return name.Equals("CON", StringComparison.OrdinalIgnoreCase)
            || name.Equals("PRN", StringComparison.OrdinalIgnoreCase)
            || name.Equals("AUX", StringComparison.OrdinalIgnoreCase)
            || name.Equals("NUL", StringComparison.OrdinalIgnoreCase)
            || (name.Length == 4
                && (name.StartsWith("COM", StringComparison.OrdinalIgnoreCase)
                    || name.StartsWith("LPT", StringComparison.OrdinalIgnoreCase))
                && name[3] is >= '1' and <= '9');
    }

    private static void VerifyPayload(
        IEnterprisePayloadSource source,
        string name,
        long expectedBytes,
        string expectedSha256)
    {
        using var stream = source.Open(name);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[1024 * 1024];
        long total = 0;
        while (true)
        {
            var read = stream.Read(buffer, 0, buffer.Length);
            if (read == 0)
            {
                break;
            }
            total = checked(total + read);
            if (total > expectedBytes)
            {
                throw new InvalidDataException(
                    "Embedded migration payload exceeds its signed manifest length.");
            }
            hash.AppendData(buffer, 0, read);
        }
        if (total != expectedBytes
            || !FixedHashEquals(
                Convert.ToHexStringLower(hash.GetHashAndReset()),
                expectedSha256))
        {
            throw new InvalidDataException(
                "Embedded migration payload differs from its signed manifest identity.");
        }
    }

    private static byte[] ReadBounded(Stream stream, int maximumBytes, string field)
    {
        using var output = new MemoryStream();
        var buffer = new byte[64 * 1024];
        while (true)
        {
            var read = stream.Read(buffer, 0, buffer.Length);
            if (read == 0)
            {
                break;
            }
            if (output.Length + read > maximumBytes)
            {
                throw new InvalidDataException(
                    $"Enterprise migration {field} exceeds its bounded size.");
            }
            output.Write(buffer, 0, read);
        }
        if (output.Length == 0)
        {
            throw new InvalidDataException($"Enterprise migration {field} is empty.");
        }
        return output.ToArray();
    }

    private static bool FixedHashEquals(string left, string right)
    {
        if (!EnterpriseHash.IsSha256(left) || !EnterpriseHash.IsSha256(right))
        {
            return false;
        }
        var leftBytes = Convert.FromHexString(left);
        var rightBytes = Convert.FromHexString(right);
        try
        {
            return CryptographicOperations.FixedTimeEquals(leftBytes, rightBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(leftBytes);
            CryptographicOperations.ZeroMemory(rightBytes);
        }
    }

    private static bool SamePath(string left, string right) => string.Equals(
        Path.TrimEndingDirectorySeparator(Path.GetFullPath(left)),
        Path.TrimEndingDirectorySeparator(Path.GetFullPath(right)),
        StringComparison.OrdinalIgnoreCase);
}

internal sealed record EnterpriseVerifiedInstallerPayload(
    EnterpriseInstallManifest Manifest,
    string PayloadIdentitySha256,
    string LauncherArchiveTreeSha256,
    string RuntimeArchiveTreeSha256);

/// <summary>
/// One-time, deletion-free migration transaction for the pre-protected-state
/// enterprise test installation. Old JSON and old managed executables are
/// never authority and are never launched. The old program tree remains in a
/// retained quarantine after success.
///
/// CurrentUser DPAPI and user-writable filesystem state protect against
/// accidental/partial loss and stale-package replay. They are deliberately not
/// a boundary against hostile code already running as this Windows user or a
/// local administrator.
/// </summary>
internal sealed class EnterpriseLegacyTestInstallationMigrator
{
    private const string LegacyPlainFeedFileName = "release-feed-state.v2.json";
    private readonly EnterpriseInstallationLayout _layout;
    private readonly TimeProvider _timeProvider;
    private readonly Action<EnterpriseLegacyMigrationFaultPoint>? _faultObserver;
    private readonly Action<string>? _beforeLegacyIsolationCommitForTest;
    private readonly EnterpriseLegacyMigrationJournalStore _journalStore;

    public EnterpriseLegacyTestInstallationMigrator(
        EnterpriseInstallationLayout layout,
        TimeProvider? timeProvider = null,
        Action<EnterpriseLegacyMigrationFaultPoint>? faultObserver = null,
        Action<string>? beforeLegacyIsolationCommitForTest = null)
    {
        _layout = layout ?? throw new ArgumentNullException(nameof(layout));
        _timeProvider = timeProvider ?? TimeProvider.System;
        _faultObserver = faultObserver;
        _beforeLegacyIsolationCommitForTest = beforeLegacyIsolationCommitForTest;
        _journalStore = new EnterpriseLegacyMigrationJournalStore(layout);
    }

    public async Task<EnterpriseLegacyMigrationResult> MigrateIfRequiredAsync(
        EnterpriseLegacyMigrationTrustedInstallerLease trustedInstaller,
        EnterpriseLegacyMigrationCallbacks callbacks,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(trustedInstaller);
        ArgumentNullException.ThrowIfNull(callbacks);
        cancellationToken.ThrowIfCancellationRequested();
        trustedInstaller.RequireIdentityUnchanged();
        RequireIndependentBoundaries();
        EnterpriseLegacySqliteUpgradeGuard.RequireJsonlOnlyHarnessHomeAndNoWriter(_layout);

        await using var operationLease = await EnterpriseManagedUpdateOperationLease
            .AcquireRequiredAsync(_layout, cancellationToken)
            .ConfigureAwait(false);
        return await MigrateIfRequiredUnderExistingLeaseAsync(
            trustedInstaller,
            callbacks,
            enforceLegacySqliteGuard: true,
            cancellationToken).ConfigureAwait(false);
    }

    internal async Task<EnterpriseLegacyMigrationResult>
        MigrateIfRequiredUnderExistingLeaseAsync(
            EnterpriseLegacyMigrationTrustedInstallerLease trustedInstaller,
            EnterpriseLegacyMigrationCallbacks callbacks,
            bool enforceLegacySqliteGuard,
            CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(trustedInstaller);
        ArgumentNullException.ThrowIfNull(callbacks);
        cancellationToken.ThrowIfCancellationRequested();
        trustedInstaller.RequireIdentityUnchanged();
        RequireIndependentBoundaries();

        if (enforceLegacySqliteGuard)
        {
            EnterpriseLegacySqliteUpgradeGuard.RequireJsonlOnlyHarnessHomeAndNoWriter(_layout);
        }
        EnterpriseManagedOperationRecovery.RecoverInterruptedUnderLease(
            _layout,
            trustedInstaller);
        trustedInstaller.RequireIdentityUnchanged();
        if (enforceLegacySqliteGuard)
        {
            EnterpriseLegacySqliteUpgradeGuard.RequireJsonlOnlyHarnessHomeAndNoWriter(_layout);
        }

        var tombstone = _journalStore.TryReadTombstone();
        var witness = _journalStore.TryReadWitness();
        var completed = ReconcileCompletionFootprints(tombstone, witness);
        if (completed is not null)
        {
            var classification = ClassifyAfterCompletedMigration();
            if (classification == EnterpriseLegacyInstallationClassification.Fresh)
            {
                return new EnterpriseLegacyMigrationResult(
                    EnterpriseLegacyMigrationDisposition.FreshInstallRequired,
                    null,
                    null,
                    null);
            }
            if (tombstone is null)
            {
                _journalStore.WriteTombstone(completed);
            }
            if (witness is null)
            {
                _journalStore.WriteWitness(completed);
            }
            _journalStore.RetireActiveJournal(completed.TransactionId);
            var pointer = RequireCurrentInstallationTrusted();
            return new EnterpriseLegacyMigrationResult(
                EnterpriseLegacyMigrationDisposition.CurrentInstallationAlreadyTrusted,
                pointer.Current.Launcher.ReleaseId,
                pointer.Current.Runtime.ReleaseId,
                null);
        }

        var journal = _journalStore.TryRead();
        if (journal is null)
        {
            var classification = ClassifyWithoutTrustingLegacyState();
            if (classification == EnterpriseLegacyInstallationClassification.Fresh)
            {
                return new EnterpriseLegacyMigrationResult(
                    EnterpriseLegacyMigrationDisposition.FreshInstallRequired,
                    null,
                    null,
                    null);
            }
            if (classification == EnterpriseLegacyInstallationClassification.CurrentTrusted)
            {
                var current = RequireCurrentInstallationTrusted();
                return new EnterpriseLegacyMigrationResult(
                    EnterpriseLegacyMigrationDisposition.CurrentInstallationAlreadyTrusted,
                    current.Current.Launcher.ReleaseId,
                    current.Current.Runtime.ReleaseId,
                    null);
            }

            ValidateLegacyTreeForIsolation();
            var transactionId = Guid.NewGuid().ToString("N");
            journal = EnterpriseLegacyMigrationJournal.CreateIntent(
                _layout,
                transactionId,
                trustedInstaller,
                UtcNow());
            _journalStore.Write(journal);
            Fault(EnterpriseLegacyMigrationFaultPoint.AfterIntentJournal);
        }

        RequireJournalInstallerIdentity(journal, trustedInstaller);
        var recoveringRegistration = string.Equals(
            journal.Phase,
            EnterpriseLegacyMigrationPhases.RegistrationPending,
            StringComparison.Ordinal);
        return await ResumeAsync(
            journal,
            trustedInstaller,
            callbacks,
            recoveringRegistration,
            enforceLegacySqliteGuard,
            cancellationToken).ConfigureAwait(false);
    }

    private async Task<EnterpriseLegacyMigrationResult> ResumeAsync(
        EnterpriseLegacyMigrationJournal journal,
        EnterpriseLegacyMigrationTrustedInstallerLease trustedInstaller,
        EnterpriseLegacyMigrationCallbacks callbacks,
        bool recoveringRegistration,
        bool enforceLegacySqliteGuard,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            trustedInstaller.RequireIdentityUnchanged();
            _journalStore.Validate(journal);

            switch (journal.Phase)
            {
                case EnterpriseLegacyMigrationPhases.Intent:
                {
                    RequireLegacyRootStillActive(journal);
                    PreservePartialCandidateIfPresent(journal);
                    var candidate = await callbacks.StageCandidateAsync(
                            journal.CandidateDirectory,
                            trustedInstaller.RequirePayloadSource(),
                            cancellationToken)
                        .ConfigureAwait(false);
                    ValidateStagedCandidate(journal, trustedInstaller, candidate);
                    EnterpriseLegacyMigrationDurability.FlushTree(
                        journal.CandidateDirectory,
                        Path.GetDirectoryName(journal.CandidateDirectory)
                            ?? throw new InvalidDataException(
                                "Enterprise migration candidate has no parent."));
                    ValidateStagedCandidate(journal, trustedInstaller, candidate);
                    Fault(EnterpriseLegacyMigrationFaultPoint.AfterCandidateStagedBeforeJournal);
                    journal = journal with
                    {
                        Phase = EnterpriseLegacyMigrationPhases.CandidatePrepared,
                        LauncherReleaseId = candidate.LauncherReleaseId,
                        RuntimeReleaseId = candidate.RuntimeReleaseId,
                        CandidateProgramTreeSha256 = ComputeProgramTreeSha256(
                            journal.CandidateDirectory),
                        UpdatedAtUtc = NextTransitionUtc(journal),
                    };
                    _journalStore.Write(journal);
                    Fault(EnterpriseLegacyMigrationFaultPoint.AfterCandidatePreparedJournal);
                    continue;
                }

                case EnterpriseLegacyMigrationPhases.CandidatePrepared:
                {
                    var candidate = CandidateFrom(journal);
                    if (!Directory.Exists(_layout.ManagedRoot)
                        && Directory.Exists(journal.LegacyQuarantineDirectory))
                    {
                        ValidatePreparedCandidate(journal, trustedInstaller, candidate);
                        journal = Advance(
                            journal,
                            EnterpriseLegacyMigrationPhases.OldIsolated);
                        _journalStore.Write(journal);
                        Fault(EnterpriseLegacyMigrationFaultPoint.AfterOldIsolatedJournal);
                        continue;
                    }

                    RequireLegacyRootStillActive(journal);
                    ValidatePreparedCandidate(journal, trustedInstaller, candidate);
                    ValidateLegacyTreeForIsolation();
                    EnterpriseLegacyMigrationTreeRenameProbe.RequireMovable(
                        _layout.ManagedRoot);
                    RejectRunningManagedProcesses(_layout.ManagedRoot);
                    // Windows does not provide one atomic primitive spanning
                    // process/module enumeration and a whole-tree rename. The
                    // final scan after this controlled race seam catches an
                    // ordinary process that starts before commit; a later
                    // sharing violation makes the write-through rename fail
                    // with the authenticated journal and original tree still
                    // retryable. A hostile same-user process deliberately
                    // racing the final scan with share-delete access remains
                    // outside this migration's local threat boundary.
                    _beforeLegacyIsolationCommitForTest?.Invoke(_layout.ManagedRoot);
                    if (enforceLegacySqliteGuard)
                    {
                        EnterpriseLegacySqliteUpgradeGuard
                            .RequireJsonlOnlyHarnessHomeAndNoWriter(_layout);
                    }
                    RejectRunningManagedProcesses(_layout.ManagedRoot);
                    EnterpriseLegacyMigrationTreeRenameProbe.RequireMovable(
                        _layout.ManagedRoot);
                    EnterpriseLegacyMigrationDurability.MoveDirectory(
                        _layout.ManagedRoot,
                        journal.LegacyQuarantineDirectory);
                    Fault(EnterpriseLegacyMigrationFaultPoint.AfterOldRootRenameBeforeJournal);
                    journal = Advance(
                        journal,
                        EnterpriseLegacyMigrationPhases.OldIsolated);
                    _journalStore.Write(journal);
                    Fault(EnterpriseLegacyMigrationFaultPoint.AfterOldIsolatedJournal);
                    continue;
                }

                case EnterpriseLegacyMigrationPhases.OldIsolated:
                {
                    var candidate = CandidateFrom(journal);
                    RequireRetainedLegacyQuarantine(journal);
                    if (Directory.Exists(_layout.ManagedRoot)
                        && !Directory.Exists(journal.CandidateDirectory))
                    {
                        ValidateActivatedProgramTree(journal, trustedInstaller, candidate);
                    }
                    else
                    {
                        if (Directory.Exists(_layout.ManagedRoot)
                            || !Directory.Exists(journal.CandidateDirectory))
                        {
                            throw new InvalidDataException(
                                "Enterprise legacy migration activation paths are inconsistent.");
                        }
                        ValidatePreparedCandidate(journal, trustedInstaller, candidate);
                        EnterpriseLegacyMigrationTreeRenameProbe.RequireMovable(
                            journal.CandidateDirectory);
                        EnterpriseLegacyMigrationDurability.MoveDirectory(
                            journal.CandidateDirectory,
                            _layout.ManagedRoot);
                        Fault(
                            EnterpriseLegacyMigrationFaultPoint.AfterCandidateRenameBeforeJournal);
                    }
                    journal = Advance(
                        journal,
                        EnterpriseLegacyMigrationPhases.CandidateActivated);
                    _journalStore.Write(journal);
                    Fault(EnterpriseLegacyMigrationFaultPoint.AfterCandidateActivatedJournal);
                    continue;
                }

                case EnterpriseLegacyMigrationPhases.CandidateActivated:
                {
                    var candidate = CandidateFrom(journal);
                    RequireRetainedLegacyQuarantine(journal);
                    ValidateActivatedProgramTree(journal, trustedInstaller, candidate);
                    if (enforceLegacySqliteGuard)
                    {
                        EnterpriseLegacySqliteUpgradeGuard
                            .RequireJsonlOnlyHarnessHomeAndNoWriter(_layout);
                    }
                    await callbacks.FinalizeAsync(candidate, cancellationToken)
                        .ConfigureAwait(false);
                    if (enforceLegacySqliteGuard)
                    {
                        EnterpriseLegacySqliteUpgradeGuard
                            .RequireJsonlOnlyHarnessHomeAndNoWriter(_layout);
                    }
                    EnterpriseLegacyMigrationDurability.FlushTree(
                        _layout.StateRoot,
                        _layout.ManagedRoot);
                    callbacks.ValidateFinalized(candidate);
                    ValidateFinalizedInstallerState(candidate);
                    ValidateActivatedProgramTree(journal, trustedInstaller, candidate);
                    Fault(EnterpriseLegacyMigrationFaultPoint.AfterFinalizationBeforeJournal);
                    journal = Advance(
                        journal,
                        EnterpriseLegacyMigrationPhases.RegistrationPending);
                    _journalStore.Write(journal);
                    Fault(EnterpriseLegacyMigrationFaultPoint.AfterRegistrationPendingJournal);
                    continue;
                }

                case EnterpriseLegacyMigrationPhases.RegistrationPending:
                {
                    var candidate = CandidateFrom(journal);
                    RequireRetainedLegacyQuarantine(journal);
                    ValidateActivatedProgramTree(journal, trustedInstaller, candidate);
                    callbacks.ValidateFinalized(candidate);
                    ValidateFinalizedInstallerState(candidate);
                    if (enforceLegacySqliteGuard)
                    {
                        EnterpriseLegacySqliteUpgradeGuard
                            .RequireJsonlOnlyHarnessHomeAndNoWriter(_layout);
                    }
                    await callbacks.RegisterAsync(candidate, cancellationToken)
                        .ConfigureAwait(false);
                    callbacks.ValidateRegistration(candidate);
                    if (enforceLegacySqliteGuard)
                    {
                        EnterpriseLegacySqliteUpgradeGuard
                            .RequireJsonlOnlyHarnessHomeAndNoWriter(_layout);
                    }
                    Fault(EnterpriseLegacyMigrationFaultPoint.AfterRegistrationBeforeJournal);
                    WriteCompletionFootprints(journal);
                    return Result(
                        recoveringRegistration
                            ? EnterpriseLegacyMigrationDisposition.RegistrationRecovered
                            : EnterpriseLegacyMigrationDisposition.Migrated,
                        journal);
                }

                case EnterpriseLegacyMigrationPhases.Completed:
                {
                    var candidate = CandidateFrom(journal);
                    RequireRetainedLegacyQuarantine(journal);
                    ValidateActivatedProgramTree(journal, trustedInstaller, candidate);
                    callbacks.ValidateFinalized(candidate);
                    ValidateFinalizedInstallerState(candidate);
                    callbacks.ValidateRegistration(candidate);
                    if (enforceLegacySqliteGuard)
                    {
                        EnterpriseLegacySqliteUpgradeGuard
                            .RequireJsonlOnlyHarnessHomeAndNoWriter(_layout);
                    }
                    WriteCompletionFootprints(journal);
                    return Result(EnterpriseLegacyMigrationDisposition.Migrated, journal);
                }

                default:
                    throw new InvalidDataException(
                        "Enterprise legacy migration phase is unsupported.");
            }
        }
    }

    private EnterpriseLegacyInstallationClassification ClassifyWithoutTrustingLegacyState()
    {
        var migrationRootExists = Directory.Exists(_journalStore.MigrationRoot);
        if (!Directory.Exists(_layout.ManagedRoot))
        {
            if (migrationRootExists)
            {
                _journalStore.RequireOnlyRetiredArtifactsForFreshInstall();
            }
            RequireNoOrphanTransactionTreesForFreshInstall();
            return EnterpriseLegacyInstallationClassification.Fresh;
        }

        EnterprisePathGuard.ValidateExistingPathWithin(
            _layout.ManagedRoot,
            _layout.LocalAppDataRoot,
            requireDirectory: true);
        var hasModernSecurityTrace = File.Exists(_layout.UpdateSecurityStatePath)
            || File.Exists(_layout.UpdateSecurityAnchorPath)
            || File.Exists(_layout.UpdateSecurityPendingAnchorPath)
            || File.Exists(_layout.UpdateSecurityWitnessPath);
        var legacyPlainFeedPath = Path.Combine(
            _layout.StateRoot,
            LegacyPlainFeedFileName);
        var hasLegacyPlainFeed = File.Exists(legacyPlainFeedPath);

        if (hasModernSecurityTrace)
        {
            _ = RequireCurrentInstallationTrusted();
            return EnterpriseLegacyInstallationClassification.CurrentTrusted;
        }
        if (hasLegacyPlainFeed)
        {
            RequireLegacyFootprint(legacyPlainFeedPath);
            return EnterpriseLegacyInstallationClassification.LegacyUntrusted;
        }
        if (_journalStore.HasCompletedJournalArchives())
        {
            throw new InvalidDataException(
                "A retired enterprise migration journal exists without either completion footprint.");
        }
        _ = RequireCurrentInstallationTrusted();
        return EnterpriseLegacyInstallationClassification.CurrentTrusted;
    }

    private EnterpriseLegacyInstallationClassification ClassifyAfterCompletedMigration()
    {
        if (!Directory.Exists(_layout.ManagedRoot))
        {
            return EnterpriseLegacyInstallationClassification.Fresh;
        }
        var legacyPlainFeedPath = Path.Combine(
            _layout.StateRoot,
            LegacyPlainFeedFileName);
        if (File.Exists(legacyPlainFeedPath))
        {
            throw new InvalidDataException(
                "A completed enterprise migration footprint forbids legacy plain-state replay.");
        }
        _ = RequireCurrentInstallationTrusted();
        return EnterpriseLegacyInstallationClassification.CurrentTrusted;
    }

    private void RequireNoOrphanTransactionTreesForFreshInstall()
    {
        var managedParent = Path.GetDirectoryName(_layout.ManagedRoot)
            ?? throw new InvalidDataException("Enterprise ManagedRoot has no parent.");
        if (!Directory.Exists(managedParent))
        {
            return;
        }
        var managedLeaf = Path.GetFileName(_layout.ManagedRoot);
        var prefixes = new[]
        {
            $".{managedLeaf}.migration-candidate-",
            $".{managedLeaf}.legacy-quarantine-",
            $".{managedLeaf}.abandoned-candidate-",
        };
        if (Directory.EnumerateFileSystemEntries(managedParent)
            .Select(Path.GetFileName)
            .Any(name => name is not null
                && prefixes.Any(prefix => name.StartsWith(
                    prefix,
                    StringComparison.Ordinal))))
        {
            throw new InvalidDataException(
                "Fresh enterprise installation is blocked by an orphaned migration tree.");
        }
    }

    private EnterpriseReleaseSetPointer RequireCurrentInstallationTrusted()
    {
        EnterpriseManagedGcPathSafety.ValidateSafeTreeWithSingleLinks(
            _layout.ManagedRoot,
            _layout.LocalAppDataRoot);
        EnterpriseBuildProfileMarker.ReadAndValidate(
            _layout.BuildProfileMarkerPath,
            _layout.LayoutProfile);
        EnterpriseStableBootstrapperVerifier.RequireTrusted(_layout);
        EnterprisePathGuard.ValidateExistingPathWithin(
            _layout.InstalledInstallerPath,
            _layout.ManagedRoot,
            requireDirectory: false);
        EnterpriseManagedGcPathSafety.RequireSingleLinkFile(
            _layout.InstalledInstallerPath,
            _layout.ManagedRoot);
        EnterpriseAuthenticodeVerifier.RequireTrustedSignature(
            _layout.InstalledInstallerPath,
            _layout);
        var releaseSet = new EnterpriseReleaseSetPointerStore(_layout).ReadRequired();
        var launcher = new EnterpriseLauncherPointerStore(_layout).ReadRequired();
        var runtime = new EnterpriseRuntimePointerStore(_layout).ReadRequired();
        if (!string.Equals(
                launcher.ReleaseId,
                releaseSet.Current.Launcher.ReleaseId,
                StringComparison.Ordinal)
            || !string.Equals(
                runtime.ReleaseId,
                releaseSet.Current.Runtime.ReleaseId,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Enterprise component repair pointers do not match the authenticated release-set.");
        }
        RejectCrossComponentReceipt(
            launcher.LauncherDirectory,
            ".ensou-enterprise-runtime.json");
        RejectCrossComponentReceipt(
            runtime.RuntimeDirectory,
            ".ensou-enterprise-launcher.json");
        var receiptPath = Path.Combine(_layout.StateRoot, "installation-receipt.json");
        EnterprisePathGuard.ValidateExistingPathWithin(
            receiptPath,
            _layout.ManagedRoot,
            requireDirectory: false);
        var receipt = JsonSerializer.Deserialize<EnterpriseInstallationReceipt>(
                File.ReadAllBytes(receiptPath),
                EnterpriseInstallJson.Options)
            ?? throw new InvalidDataException(
                "Enterprise installation receipt is empty.");
        EnterprisePathGuard.ValidateReleaseId(receipt.LauncherReleaseId);
        EnterprisePathGuard.ValidateReleaseId(receipt.RuntimeReleaseId);
        if (receipt.SchemaVersion != 1
            || !string.Equals(
                receipt.LayoutProfile,
                _layout.LayoutProfile,
                StringComparison.Ordinal)
            || receipt.DevelopmentUnsignedPayload != _layout.IsDevelopmentE2E
            || receipt.InstalledAtUtc.Offset != TimeSpan.Zero
            || releaseSet.Current.Generation == 0
                && (!string.Equals(
                        receipt.LauncherReleaseId,
                        releaseSet.Current.Launcher.ReleaseId,
                        StringComparison.Ordinal)
                    || !string.Equals(
                        receipt.RuntimeReleaseId,
                        releaseSet.Current.Runtime.ReleaseId,
                        StringComparison.Ordinal)))
        {
            throw new InvalidDataException(
                "Enterprise installation receipt identity is invalid.");
        }
        return releaseSet;
    }

    private EnterpriseLegacyMigrationTombstone? ReconcileCompletionFootprints(
        EnterpriseLegacyMigrationTombstone? tombstone,
        EnterpriseLegacyMigrationTombstone? witness)
    {
        if (tombstone is null)
        {
            return witness;
        }
        if (witness is null)
        {
            return tombstone;
        }
        if (!string.Equals(
                tombstone.TransactionId,
                witness.TransactionId,
                StringComparison.Ordinal)
            || tombstone.CompletedAtUtc != witness.CompletedAtUtc
            || !string.Equals(
                tombstone.ManagedRoot,
                witness.ManagedRoot,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "Enterprise migration tombstone and independent witness disagree.");
        }
        return tombstone;
    }

    private void WriteCompletionFootprints(EnterpriseLegacyMigrationJournal journal)
    {
        var tombstone = EnterpriseLegacyMigrationTombstone.Create(
            _layout,
            journal,
            NextTransitionUtc(journal));
        _journalStore.WriteTombstone(tombstone);
        Fault(EnterpriseLegacyMigrationFaultPoint.AfterMigrationTombstoneBeforeWitness);
        _journalStore.WriteWitness(tombstone);
        Fault(EnterpriseLegacyMigrationFaultPoint
            .AfterMigrationWitnessBeforeJournalRetirement);
        _journalStore.RetireActiveJournal(journal.TransactionId);
    }

    private void RequireLegacyFootprint(string legacyPlainFeedPath)
    {
        var requiredFiles = new[]
        {
            _layout.ReleaseSetPointerPath,
            legacyPlainFeedPath,
            _layout.BuildProfileMarkerPath,
            _layout.BootstrapperPath,
            _layout.InstalledInstallerPath,
        };
        var requiredDirectories = new[]
        {
            _layout.StateRoot,
            _layout.LauncherVersionsRoot,
            _layout.RuntimeVersionsRoot,
        };
        if (requiredFiles.Any(path => !File.Exists(path))
            || requiredDirectories.Any(path => !Directory.Exists(path))
            || !Directory.EnumerateDirectories(_layout.LauncherVersionsRoot).Any()
            || !Directory.EnumerateDirectories(_layout.RuntimeVersionsRoot).Any())
        {
            throw new InvalidDataException(
                "ManagedRoot is neither a trusted current install nor an exact legacy test footprint.");
        }
    }

    private void ValidateLegacyTreeForIsolation()
    {
        EnterpriseManagedGcPathSafety.ValidateSafeTreeWithSingleLinks(
            _layout.ManagedRoot,
            _layout.LocalAppDataRoot);
    }

    private void RequireLegacyRootStillActive(EnterpriseLegacyMigrationJournal journal)
    {
        if (!Directory.Exists(_layout.ManagedRoot)
            || Directory.Exists(journal.LegacyQuarantineDirectory))
        {
            throw new InvalidDataException(
                "Enterprise legacy program root changed before isolation committed.");
        }
        var legacyPlainFeedPath = Path.Combine(
            _layout.StateRoot,
            LegacyPlainFeedFileName);
        RequireLegacyFootprint(legacyPlainFeedPath);
        ValidateLegacyTreeForIsolation();
    }

    private void PreservePartialCandidateIfPresent(
        EnterpriseLegacyMigrationJournal journal)
    {
        if (!Directory.Exists(journal.CandidateDirectory))
        {
            return;
        }
        EnterpriseManagedGcPathSafety.ValidateSafeTreeWithSingleLinks(
            journal.CandidateDirectory,
            _layout.LocalAppDataRoot);
        var managedParent = Path.GetDirectoryName(_layout.ManagedRoot)
            ?? throw new InvalidDataException("Enterprise ManagedRoot has no parent.");
        var preserved = Path.Combine(
            managedParent,
            $".{Path.GetFileName(_layout.ManagedRoot)}.abandoned-candidate-{Guid.NewGuid():N}");
        EnterpriseLegacyMigrationDurability.MoveDirectory(
            journal.CandidateDirectory,
            preserved);
    }

    private void ValidateStagedCandidate(
        EnterpriseLegacyMigrationJournal journal,
        EnterpriseLegacyMigrationTrustedInstallerLease trustedInstaller,
        EnterpriseLegacyMigrationCandidate candidate)
    {
        EnterprisePathGuard.ValidateReleaseId(candidate.LauncherReleaseId);
        EnterprisePathGuard.ValidateReleaseId(candidate.RuntimeReleaseId);
        if (!string.Equals(
                candidate.LauncherReleaseId,
                trustedInstaller.Manifest.LauncherReleaseId,
                StringComparison.Ordinal)
            || !string.Equals(
                candidate.RuntimeReleaseId,
                trustedInstaller.Manifest.RuntimeReleaseId,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Staged enterprise candidate does not match the locked Installer payload.");
        }
        ValidateCandidateBase(journal.CandidateDirectory, trustedInstaller, candidate);
        RequireEmptyMutableCandidateDirectory(journal.CandidateDirectory, "state");
        RequireEmptyMutableCandidateDirectory(journal.CandidateDirectory, "packages");
    }

    private void ValidatePreparedCandidate(
        EnterpriseLegacyMigrationJournal journal,
        EnterpriseLegacyMigrationTrustedInstallerLease trustedInstaller,
        EnterpriseLegacyMigrationCandidate candidate)
    {
        ValidateCandidateBase(journal.CandidateDirectory, trustedInstaller, candidate);
        RequireEmptyMutableCandidateDirectory(journal.CandidateDirectory, "state");
        RequireEmptyMutableCandidateDirectory(journal.CandidateDirectory, "packages");
        RequireProgramTreeHash(journal.CandidateDirectory, journal);
    }

    private void ValidateActivatedProgramTree(
        EnterpriseLegacyMigrationJournal journal,
        EnterpriseLegacyMigrationTrustedInstallerLease trustedInstaller,
        EnterpriseLegacyMigrationCandidate candidate)
    {
        ValidateCandidateBase(_layout.ManagedRoot, trustedInstaller, candidate);
        RequireProgramTreeHash(_layout.ManagedRoot, journal);
    }

    private static void ValidateCandidateBase(
        string root,
        EnterpriseLegacyMigrationTrustedInstallerLease trustedInstaller,
        EnterpriseLegacyMigrationCandidate candidate)
    {
        if (!Directory.Exists(root))
        {
            throw new DirectoryNotFoundException(
                "Enterprise legacy migration candidate is missing.");
        }
        var rootParent = Path.GetDirectoryName(root)
            ?? throw new InvalidDataException(
                "Enterprise migration candidate has no parent directory.");
        EnterpriseManagedGcPathSafety.ValidateSafeTreeWithSingleLinks(root, rootParent);
        var requiredPaths = new[]
        {
            Path.Combine(root, EnterpriseInstallationLayout.BootstrapperExecutableName),
            Path.Combine(root, EnterpriseInstallationLayout.InstallerExecutableName),
            Path.Combine(root, EnterpriseInstallationLayout.BuildProfileMarkerFileName),
            Path.Combine(root, "launcher-versions", candidate.LauncherReleaseId),
            Path.Combine(root, "runtimes", candidate.RuntimeReleaseId),
        };
        if (requiredPaths.Take(3).Any(path => !File.Exists(path))
            || requiredPaths.Skip(3).Any(path => !Directory.Exists(path)))
        {
            throw new InvalidDataException(
                "Enterprise migration candidate is incomplete.");
        }
        RequireExactCandidateShape(root, trustedInstaller, candidate);
        var installedInstaller = requiredPaths[1];
        var bootstrapper = requiredPaths[0];
        if (!FixedHashEquals(
                EnterpriseHash.ComputeFile(installedInstaller),
                trustedInstaller.InstallerSha256)
            || !FixedHashEquals(
                EnterpriseHash.ComputeFile(bootstrapper),
                trustedInstaller.Manifest.BootstrapperSha256))
        {
            throw new InvalidDataException(
                "Enterprise migration candidate stable files do not match the locked Installer.");
        }
    }

    private static void RequireExactCandidateShape(
        string root,
        EnterpriseLegacyMigrationTrustedInstallerLease trustedInstaller,
        EnterpriseLegacyMigrationCandidate candidate)
    {
        var allowedTopLevel = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            EnterpriseInstallationLayout.BootstrapperExecutableName,
            EnterpriseInstallationLayout.InstallerExecutableName,
            EnterpriseInstallationLayout.BuildProfileMarkerFileName,
            "launcher-versions",
            "runtimes",
            "plugins",
            "state",
            "packages",
        };
        foreach (var entry in Directory.EnumerateFileSystemEntries(root))
        {
            if (!allowedTopLevel.Remove(Path.GetFileName(entry)))
            {
                throw new InvalidDataException(
                    "Enterprise migration candidate has an unexpected stable top-level entry.");
            }
        }
        if (allowedTopLevel.Any(name => name is not "state" and not "packages"))
        {
            throw new InvalidDataException(
                "Enterprise migration candidate is missing a required stable top-level entry.");
        }

        EnterpriseBuildProfileMarker.ReadAndValidate(
            Path.Combine(root, EnterpriseInstallationLayout.BuildProfileMarkerFileName),
            trustedInstaller.Manifest.LayoutProfile);
        var launcherVersionsRoot = Path.Combine(root, "launcher-versions");
        var runtimeVersionsRoot = Path.Combine(root, "runtimes");
        var pluginRoot = Path.Combine(root, "plugins");
        RequireOnlyVersionDirectory(
            launcherVersionsRoot,
            candidate.LauncherReleaseId);
        RequireOnlyVersionDirectory(
            runtimeVersionsRoot,
            candidate.RuntimeReleaseId);
        if (Directory.EnumerateFileSystemEntries(pluginRoot).Any())
        {
            throw new InvalidDataException(
                "Installer-bootstrap migration candidate may not preinstall plugin policy state.");
        }

        var launcherDirectory = Path.Combine(
            launcherVersionsRoot,
            candidate.LauncherReleaseId);
        var runtimeDirectory = Path.Combine(
            runtimeVersionsRoot,
            candidate.RuntimeReleaseId);
        EnterpriseBuildProfileMarker.ReadAndValidate(
            Path.Combine(
                launcherDirectory,
                EnterpriseInstallationLayout.BuildProfileMarkerFileName),
            trustedInstaller.Manifest.LayoutProfile);
        var launcherExecutables = new[]
        {
            EnterpriseInstallationLayout.LauncherExecutableName,
            EnterpriseInstallationLayout.ClientBootstrapperExecutableName,
            EnterpriseInstallationLayout.MaintenanceExecutableName,
        };
        if (launcherExecutables.Any(name => !File.Exists(Path.Combine(launcherDirectory, name))))
        {
            throw new InvalidDataException(
                "Enterprise migration candidate client bundle is incomplete.");
        }

        ValidateComponentReceipts(
            launcherDirectory,
            candidate.LauncherReleaseId,
            trustedInstaller.Manifest.LauncherArchiveSha256,
            trustedInstaller.LauncherArchiveTreeSha256,
            EnterpriseReleaseSetContract.LauncherComponent,
            EnterpriseInstallationLayout.LauncherExecutableName,
            secondaryRelativePath: null,
            runtime: false,
            root);
        RejectCrossComponentReceipt(
            launcherDirectory,
            ".ensou-enterprise-runtime.json");
        ValidateComponentReceipts(
            runtimeDirectory,
            candidate.RuntimeReleaseId,
            trustedInstaller.Manifest.RuntimeArchiveSha256,
            trustedInstaller.RuntimeArchiveTreeSha256,
            EnterpriseReleaseSetContract.RuntimeComponent,
            "node.exe",
            "node_modules/@deepseek-ai/dsh/lib/bin.js",
            runtime: true,
            root);
        RejectCrossComponentReceipt(
            runtimeDirectory,
            ".ensou-enterprise-launcher.json");
    }

    private static void RejectCrossComponentReceipt(
        string componentDirectory,
        string forbiddenReceiptFileName)
    {
        var forbidden = Path.Combine(componentDirectory, forbiddenReceiptFileName);
        if (File.Exists(forbidden) || Directory.Exists(forbidden))
        {
            throw new InvalidDataException(
                "Enterprise migration component contains a cross-component receipt.");
        }
    }

    private static void RequireOnlyVersionDirectory(string root, string releaseId)
    {
        if (!Directory.Exists(root)
            || Directory.EnumerateFiles(root).Any())
        {
            throw new InvalidDataException(
                "Enterprise migration version root shape is invalid.");
        }
        var directories = Directory.EnumerateDirectories(root).ToArray();
        if (directories.Length != 1
            || !string.Equals(
                Path.GetFileName(directories[0]),
                releaseId,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Enterprise migration version root does not contain exactly the signed release.");
        }
    }

    private static void ValidateComponentReceipts(
        string directory,
        string releaseId,
        string archiveSha256,
        string expectedTreeSha256,
        string component,
        string primaryRelativePath,
        string? secondaryRelativePath,
        bool runtime,
        string managedRoot)
    {
        var receiptFileName = runtime
            ? ".ensou-enterprise-runtime.json"
            : ".ensou-enterprise-launcher.json";
        EnterpriseLauncherPointerStore.ValidateReceiptAndPrimaryFile(
            directory,
            receiptFileName,
            primaryRelativePath,
            secondaryRelativePath,
            releaseId,
            managedRoot);
        var receipt = EnterprisePointerJson.Deserialize<EnterpriseInstalledReleaseReceipt>(
            File.ReadAllBytes(Path.Combine(directory, receiptFileName)));
        if (!FixedHashEquals(receipt.ArchiveSha256, archiveSha256))
        {
            throw new InvalidDataException(
                "Enterprise migration component receipt is not bound to the locked archive.");
        }

        var runtimeManifestSha256 = runtime
            ? EnterpriseRuntimeFileManifest.ValidateCompleteTree(directory)
            : null;
        var artifactReceipt = EnterprisePointerJson
            .Deserialize<EnterpriseReleaseArtifactReceiptV2>(
                File.ReadAllBytes(Path.Combine(directory, EnterpriseTreeHash.ReceiptFileName)));
        var actualTreeSha256 = EnterpriseTreeHash.Compute(directory);
        if (artifactReceipt.SchemaVersion != 2
            || !string.Equals(artifactReceipt.Component, component, StringComparison.Ordinal)
            || !string.Equals(artifactReceipt.ReleaseId, releaseId, StringComparison.Ordinal)
            || !FixedHashEquals(artifactReceipt.ArchiveSha256, archiveSha256)
            || !FixedHashEquals(artifactReceipt.TreeSha256, expectedTreeSha256)
            || !FixedHashEquals(actualTreeSha256, expectedTreeSha256)
            || runtime && !FixedHashEquals(
                artifactReceipt.RuntimeFilesManifestSha256,
                runtimeManifestSha256)
            || !runtime && artifactReceipt.RuntimeFilesManifestSha256 is not null)
        {
            throw new InvalidDataException(
                "Enterprise migration complete-tree receipt is not bound to the locked archive.");
        }
    }

    private void ValidateFinalizedInstallerState(
        EnterpriseLegacyMigrationCandidate candidate)
    {
        var launcher = new EnterpriseLauncherPointerStore(_layout).ReadRequired();
        var runtime = new EnterpriseRuntimePointerStore(_layout).ReadRequired();
        var releaseSet = new EnterpriseReleaseSetPointerStore(_layout).ReadRequired();
        if (!string.Equals(launcher.ReleaseId, candidate.LauncherReleaseId, StringComparison.Ordinal)
            || !string.Equals(runtime.ReleaseId, candidate.RuntimeReleaseId, StringComparison.Ordinal)
            || !string.Equals(
                releaseSet.Current.Launcher.ReleaseId,
                candidate.LauncherReleaseId,
                StringComparison.Ordinal)
            || !string.Equals(
                releaseSet.Current.Runtime.ReleaseId,
                candidate.RuntimeReleaseId,
                StringComparison.Ordinal)
            || !string.Equals(
                releaseSet.Current.HealthState,
                EnterpriseReleaseHealthStates.Healthy,
                StringComparison.Ordinal)
            || releaseSet.Previous is not null
            || File.Exists(Path.Combine(_layout.StateRoot, LegacyPlainFeedFileName)))
        {
            throw new InvalidDataException(
                "Enterprise migration final installer-bootstrap state is not exact.");
        }
        EnterpriseStableBootstrapperVerifier.RequireTrusted(_layout);
        var receiptPath = Path.Combine(_layout.StateRoot, "installation-receipt.json");
        EnterprisePathGuard.ValidateExistingPathWithin(
            receiptPath,
            _layout.ManagedRoot,
            requireDirectory: false);
        var receipt = JsonSerializer.Deserialize<EnterpriseInstallationReceipt>(
                File.ReadAllBytes(receiptPath),
                EnterpriseInstallJson.Options)
            ?? throw new InvalidDataException(
                "Enterprise migration installation receipt is empty.");
        if (receipt.SchemaVersion != 1
            || !string.Equals(receipt.LayoutProfile, _layout.LayoutProfile, StringComparison.Ordinal)
            || !string.Equals(
                receipt.LauncherReleaseId,
                candidate.LauncherReleaseId,
                StringComparison.Ordinal)
            || !string.Equals(
                receipt.RuntimeReleaseId,
                candidate.RuntimeReleaseId,
                StringComparison.Ordinal)
            || receipt.DevelopmentUnsignedPayload != _layout.IsDevelopmentE2E
            || receipt.InstalledAtUtc.Offset != TimeSpan.Zero)
        {
            throw new InvalidDataException(
                "Enterprise migration installation receipt is invalid.");
        }
    }

    private static void RequireEmptyMutableCandidateDirectory(string root, string leaf)
    {
        var directory = Path.Combine(root, leaf);
        if (File.Exists(directory)
            || Directory.Exists(directory)
                && Directory.EnumerateFileSystemEntries(directory).Any())
        {
            throw new InvalidDataException(
                "Enterprise migration candidate contains pre-activation mutable state.");
        }
    }

    private static void RequireProgramTreeHash(
        string root,
        EnterpriseLegacyMigrationJournal journal)
    {
        var actual = ComputeProgramTreeSha256(root);
        if (!FixedHashEquals(actual, journal.CandidateProgramTreeSha256!))
        {
            throw new InvalidDataException(
                "Enterprise migration candidate program tree changed after preparation.");
        }
    }

    private static string ComputeProgramTreeSha256(string root)
    {
        var rootParent = Path.GetDirectoryName(root)
            ?? throw new InvalidDataException(
                "Enterprise migration program root has no parent directory.");
        EnterpriseManagedGcPathSafety.ValidateSafeTreeWithSingleLinks(root, rootParent);
        using var aggregate = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (var directory in Directory.EnumerateDirectories(root, "*", SearchOption.AllDirectories)
                     .Where(path => !IsMutablePath(root, path))
                     .Select(path => NormalizeRelative(root, path))
                     .Order(StringComparer.Ordinal))
        {
            AppendTreeRecord(aggregate, "d", directory, 0, []);
        }
        foreach (var path in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories)
                     .Where(path => !IsMutablePath(root, path))
                     .OrderBy(path => NormalizeRelative(root, path), StringComparer.Ordinal))
        {
            var relative = NormalizeRelative(root, path);
            var info = new FileInfo(path);
            using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                128 * 1024,
                FileOptions.SequentialScan);
            var hash = SHA256.HashData(stream);
            AppendTreeRecord(aggregate, "f", relative, info.Length, hash);
        }
        return Convert.ToHexStringLower(aggregate.GetHashAndReset());
    }

    private static bool IsMutablePath(string root, string path)
    {
        var relative = NormalizeRelative(root, path);
        var first = relative.Split('/', 2)[0];
        return string.Equals(first, "state", StringComparison.Ordinal)
            || string.Equals(first, "packages", StringComparison.Ordinal);
    }

    private static string NormalizeRelative(string root, string path) =>
        Path.GetRelativePath(root, path).Replace('\\', '/');

    private static void AppendTreeRecord(
        IncrementalHash aggregate,
        string kind,
        string relativePath,
        long length,
        ReadOnlySpan<byte> hash)
    {
        var header = Encoding.UTF8.GetBytes($"{kind}\0{relativePath}\0{length}\0");
        aggregate.AppendData(header);
        aggregate.AppendData(hash);
        aggregate.AppendData([0]);
    }

    private void RequireRetainedLegacyQuarantine(
        EnterpriseLegacyMigrationJournal journal)
    {
        if (!Directory.Exists(journal.LegacyQuarantineDirectory)
            || File.Exists(journal.LegacyQuarantineDirectory)
            || (File.GetAttributes(journal.LegacyQuarantineDirectory)
                & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException(
                "Preserved legacy enterprise program quarantine is missing or linked.");
        }
    }

    private static void RequireJournalInstallerIdentity(
        EnterpriseLegacyMigrationJournal journal,
        EnterpriseLegacyMigrationTrustedInstallerLease installer)
    {
        if (!FixedHashEquals(journal.InstallerSha256, installer.InstallerSha256)
            || !FixedHashEquals(
                journal.PayloadIdentitySha256,
                installer.PayloadIdentitySha256)
            || !string.Equals(
                journal.LauncherReleaseId ?? installer.Manifest.LauncherReleaseId,
                installer.Manifest.LauncherReleaseId,
                StringComparison.Ordinal)
            || !string.Equals(
                journal.RuntimeReleaseId ?? installer.Manifest.RuntimeReleaseId,
                installer.Manifest.RuntimeReleaseId,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Enterprise migration must resume with the exact verified Installer payload.");
        }
    }

    private static EnterpriseLegacyMigrationCandidate CandidateFrom(
        EnterpriseLegacyMigrationJournal journal)
    {
        if (string.IsNullOrWhiteSpace(journal.LauncherReleaseId)
            || string.IsNullOrWhiteSpace(journal.RuntimeReleaseId)
            || journal.CandidateProgramTreeSha256 is not { } candidateTreeSha256
            || !EnterpriseHash.IsSha256(candidateTreeSha256))
        {
            throw new InvalidDataException(
                "Enterprise migration candidate identity is incomplete.");
        }
        return new EnterpriseLegacyMigrationCandidate(
            journal.LauncherReleaseId,
            journal.RuntimeReleaseId);
    }

    private EnterpriseLegacyMigrationJournal Advance(
        EnterpriseLegacyMigrationJournal journal,
        string phase) => journal with
        {
            Phase = phase,
            UpdatedAtUtc = NextTransitionUtc(journal),
        };

    private DateTimeOffset NextTransitionUtc(
        EnterpriseLegacyMigrationJournal journal)
    {
        var now = UtcNow();
        return now < journal.UpdatedAtUtc
            ? journal.UpdatedAtUtc
            : now;
    }

    private EnterpriseLegacyMigrationResult Result(
        EnterpriseLegacyMigrationDisposition disposition,
        EnterpriseLegacyMigrationJournal journal) => new(
        disposition,
        journal.LauncherReleaseId,
        journal.RuntimeReleaseId,
        journal.LegacyQuarantineDirectory);

    private DateTimeOffset UtcNow()
    {
        var now = _timeProvider.GetUtcNow();
        if (now.Offset != TimeSpan.Zero)
        {
            throw new InvalidOperationException(
                "Enterprise migration TimeProvider must return UTC timestamps.");
        }
        return now;
    }

    private void Fault(EnterpriseLegacyMigrationFaultPoint point) =>
        _faultObserver?.Invoke(point);

    private void RequireIndependentBoundaries()
    {
        _journalStore.RequireIndependentBoundaries();
        var paths = new[]
        {
            _layout.ManagedRoot,
            _layout.HarnessHome,
            _layout.HarnessRecoveryRoot,
            _layout.UpdateOperationLockRoot,
            _journalStore.MigrationRoot,
            _journalStore.WitnessRoot,
        };
        for (var left = 0; left < paths.Length; left++)
        {
            for (var right = left + 1; right < paths.Length; right++)
            {
                if (EnterprisePathGuard.IsSameOrDescendant(paths[left], paths[right])
                    || EnterprisePathGuard.IsSameOrDescendant(paths[right], paths[left]))
                {
                    throw new InvalidDataException(
                        "Enterprise migration, program, lock, and user-data roots must be independent.");
                }
            }
        }
    }

    private static void RejectRunningManagedProcesses(string managedRoot)
    {
        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                try
                {
                    if (process.Id == Environment.ProcessId)
                    {
                        continue;
                    }
                    if (process.MainModule?.FileName is { } executable
                        && EnterprisePathGuard.IsSameOrDescendant(executable, managedRoot))
                    {
                        throw new IOException(
                            $"A process is running from legacy Enterprise ManagedRoot: {process.Id}");
                    }
                    foreach (ProcessModule module in process.Modules)
                    {
                        if (EnterprisePathGuard.IsSameOrDescendant(
                                module.FileName,
                                managedRoot))
                        {
                            throw new IOException(
                                $"A process loaded a module from legacy Enterprise ManagedRoot: {process.Id}");
                        }
                    }
                }
                catch (Win32Exception)
                {
                    // Protected unrelated processes cannot load this user's writable files.
                }
                catch (InvalidOperationException)
                {
                    // Process exited during enumeration.
                }
            }
        }
    }

    private static bool FixedHashEquals(string? left, string? right)
    {
        if (left is null
            || right is null
            || !EnterpriseHash.IsSha256(left)
            || !EnterpriseHash.IsSha256(right))
        {
            return false;
        }
        var leftBytes = Convert.FromHexString(left);
        var rightBytes = Convert.FromHexString(right);
        try
        {
            return CryptographicOperations.FixedTimeEquals(leftBytes, rightBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(leftBytes);
            CryptographicOperations.ZeroMemory(rightBytes);
        }
    }
}

internal enum EnterpriseLegacyInstallationClassification
{
    Fresh,
    CurrentTrusted,
    LegacyUntrusted,
}

internal static class EnterpriseLegacyMigrationPhases
{
    public const string Intent = "intent";
    public const string CandidatePrepared = "candidate-prepared";
    public const string OldIsolated = "old-isolated";
    public const string CandidateActivated = "candidate-activated";
    public const string RegistrationPending = "registration-pending";
    public const string Completed = "completed";

    public static bool IsValid(string phase) => phase is Intent
        or CandidatePrepared
        or OldIsolated
        or CandidateActivated
        or RegistrationPending
        or Completed;
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record EnterpriseLegacyMigrationJournal(
    int SchemaVersion,
    string Product,
    string Environment,
    string LayoutProfile,
    string ManagedRoot,
    string TransactionId,
    string Phase,
    string InstallerSha256,
    string PayloadIdentitySha256,
    string CandidateDirectory,
    string LegacyQuarantineDirectory,
    string? LauncherReleaseId,
    string? RuntimeReleaseId,
    string? CandidateProgramTreeSha256,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset UpdatedAtUtc)
{
    public static EnterpriseLegacyMigrationJournal CreateIntent(
        EnterpriseInstallationLayout layout,
        string transactionId,
        EnterpriseLegacyMigrationTrustedInstallerLease installer,
        DateTimeOffset nowUtc)
    {
        var migrationRoot = EnterpriseLegacyMigrationJournalStore.GetMigrationRoot(layout);
        var managedParent = Path.GetDirectoryName(layout.ManagedRoot)
            ?? throw new InvalidDataException("Enterprise ManagedRoot has no parent.");
        var managedLeaf = Path.GetFileName(layout.ManagedRoot);
        return new EnterpriseLegacyMigrationJournal(
            1,
            EnterpriseReleaseSetContract.Product,
            EnterpriseReleaseSetContract.EnvironmentForDevelopmentE2E(
                layout.IsDevelopmentE2E),
            layout.LayoutProfile,
            layout.ManagedRoot,
            transactionId,
            EnterpriseLegacyMigrationPhases.Intent,
            installer.InstallerSha256,
            installer.PayloadIdentitySha256,
            Path.Combine(
                managedParent,
                $".{managedLeaf}.migration-candidate-{transactionId}"),
            Path.Combine(
                managedParent,
                $".{managedLeaf}.legacy-quarantine-{transactionId}"),
            null,
            null,
            null,
            nowUtc,
            nowUtc);
    }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record EnterpriseLegacyMigrationTombstone(
    int SchemaVersion,
    string Product,
    string Environment,
    string LayoutProfile,
    string ManagedRoot,
    string TransactionId,
    DateTimeOffset CompletedAtUtc)
{
    public static EnterpriseLegacyMigrationTombstone Create(
        EnterpriseInstallationLayout layout,
        EnterpriseLegacyMigrationJournal journal,
        DateTimeOffset completedAtUtc) => new(
        1,
        EnterpriseReleaseSetContract.Product,
        EnterpriseReleaseSetContract.EnvironmentForDevelopmentE2E(
            layout.IsDevelopmentE2E),
        layout.LayoutProfile,
        layout.ManagedRoot,
        journal.TransactionId,
        completedAtUtc);
}

internal sealed class EnterpriseLegacyMigrationJournalStore
{
    private const int MaximumProtectedJournalBytes = 512 * 1024;
    private static readonly byte[] ProtectedEnvelopeMagic =
        "EDSHLM1\0"u8.ToArray();
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
    private readonly EnterpriseInstallationLayout _layout;
    private readonly byte[] _entropy;
    private readonly byte[] _tombstoneEntropy;
    private readonly byte[] _witnessEntropy;

    public EnterpriseLegacyMigrationJournalStore(EnterpriseInstallationLayout layout)
    {
        _layout = layout ?? throw new ArgumentNullException(nameof(layout));
        MigrationRoot = GetMigrationRoot(layout);
        JournalPath = Path.Combine(
            MigrationRoot,
            "legacy-schema2-program-migration.v1.dpapi");
        TombstonePath = Path.Combine(
            MigrationRoot,
            "legacy-schema2-migrated.v1.dpapi");
        WitnessRoot = layout.ReleaseSecurityWitnessRoot;
        WitnessPath = Path.Combine(
            WitnessRoot,
            "legacy-schema2-migrated.v1.witness.dpapi");
        _entropy = SHA256.HashData(Encoding.UTF8.GetBytes(string.Join(
            '|',
            EnterpriseReleaseSetContract.Product,
            EnterpriseReleaseSetContract.EnvironmentForDevelopmentE2E(
                layout.IsDevelopmentE2E),
            layout.LayoutProfile,
            EnterprisePathGuard.NormalizeDirectory(layout.ManagedRoot),
            "legacy-schema2-program-migration-v1")));
        _tombstoneEntropy = SHA256.HashData(Encoding.UTF8.GetBytes(string.Join(
            '|',
            EnterpriseReleaseSetContract.Product,
            EnterpriseReleaseSetContract.EnvironmentForDevelopmentE2E(
                layout.IsDevelopmentE2E),
            layout.LayoutProfile,
            EnterprisePathGuard.NormalizeDirectory(layout.ManagedRoot),
            "legacy-schema2-migrated-v1")));
        _witnessEntropy = SHA256.HashData(Encoding.UTF8.GetBytes(string.Join(
            '|',
            EnterpriseReleaseSetContract.Product,
            EnterpriseReleaseSetContract.EnvironmentForDevelopmentE2E(
                layout.IsDevelopmentE2E),
            layout.LayoutProfile,
            EnterprisePathGuard.NormalizeDirectory(layout.ManagedRoot),
            "legacy-schema2-migrated-witness-v1")));
    }

    public string MigrationRoot { get; }

    public string JournalPath { get; }

    public string TombstonePath { get; }

    public string WitnessRoot { get; }

    public string WitnessPath { get; }

    private string CompletedJournalRoot => Path.Combine(
        MigrationRoot,
        "completed-journals");

    public static string GetMigrationRoot(EnterpriseInstallationLayout layout) =>
        Path.Combine(
            layout.LocalAppDataRoot,
            "Ensou",
            ".DshEnterpriseLegacyMigration",
            layout.LayoutProfile);

    public EnterpriseLegacyMigrationJournal? TryRead()
    {
        if (!File.Exists(JournalPath))
        {
            return null;
        }
        RequireIndependentBoundaries();
        EnterprisePathGuard.ValidateExistingPathWithin(
            JournalPath,
            MigrationRoot,
            requireDirectory: false);
        EnterpriseManagedGcPathSafety.RequireSingleLinkFile(JournalPath, MigrationRoot);
        var file = new FileInfo(JournalPath);
        if (file.Length is <= 0 or > MaximumProtectedJournalBytes)
        {
            throw new InvalidDataException(
                "Protected enterprise migration journal size is invalid.");
        }
        var envelopeBytes = File.ReadAllBytes(JournalPath);
        var protectedBytes = UnwrapProtectedEnvelope(envelopeBytes, "journal");
        byte[]? plaintext = null;
        try
        {
            plaintext = ProtectedData.Unprotect(
                protectedBytes,
                _entropy,
                DataProtectionScope.CurrentUser);
            if (plaintext.Length is <= 0 or > MaximumProtectedJournalBytes)
            {
                throw new InvalidDataException(
                    "Enterprise migration journal plaintext size is invalid.");
            }
            RejectDuplicateProperties(plaintext);
            var journal = JsonSerializer.Deserialize<EnterpriseLegacyMigrationJournal>(
                    plaintext,
                    JsonOptions)
                ?? throw new InvalidDataException(
                    "Enterprise migration journal is empty.");
            Validate(journal);
            return journal;
        }
        catch (CryptographicException exception)
        {
            throw new InvalidDataException(
                "Enterprise migration journal cannot be authenticated for this Windows user.",
                exception);
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException(
                "Enterprise migration journal JSON is invalid.",
                exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(envelopeBytes);
            CryptographicOperations.ZeroMemory(protectedBytes);
            if (plaintext is not null)
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }
    }

    public bool HasActiveJournal()
    {
        if (Directory.Exists(JournalPath))
        {
            throw new InvalidDataException(
                "Enterprise migration journal path is unexpectedly a directory.");
        }
        if (!File.Exists(JournalPath))
        {
            return false;
        }
        return TryRead() is not null;
    }

    public EnterpriseLegacyMigrationTombstone? TryReadTombstone()
    {
        if (!File.Exists(TombstonePath))
        {
            return null;
        }
        var tombstone = ReadProtected<EnterpriseLegacyMigrationTombstone>(
            TombstonePath,
            MigrationRoot,
            _tombstoneEntropy,
            "tombstone");
        ValidateTombstone(tombstone);
        return tombstone;
    }

    public EnterpriseLegacyMigrationTombstone? TryReadWitness()
    {
        if (!File.Exists(WitnessPath))
        {
            return null;
        }
        var witness = ReadProtected<EnterpriseLegacyMigrationTombstone>(
            WitnessPath,
            WitnessRoot,
            _witnessEntropy,
            "independent witness");
        ValidateTombstone(witness);
        return witness;
    }

    public void Write(EnterpriseLegacyMigrationJournal journal)
    {
        Validate(journal);
        EnterpriseLegacyMigrationDurability.EnsureDirectory(
            _layout.LocalAppDataRoot,
            MigrationRoot);
        var plaintext = JsonSerializer.SerializeToUtf8Bytes(journal, JsonOptions);
        byte[]? protectedBytes = null;
        try
        {
            protectedBytes = ProtectedData.Protect(
                plaintext,
                _entropy,
                DataProtectionScope.CurrentUser);
            if (protectedBytes.Length is <= 0 or > MaximumProtectedJournalBytes)
            {
                throw new InvalidDataException(
                    "Protected enterprise migration journal size is invalid.");
            }
            var envelope = WrapProtectedEnvelope(protectedBytes);
            try
            {
                EnterpriseLegacyMigrationDurability.WriteFileAtomically(
                    JournalPath,
                    envelope,
                    MigrationRoot);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(envelope);
            }
            EnterpriseManagedGcPathSafety.RequireSingleLinkFile(JournalPath, MigrationRoot);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            if (protectedBytes is not null)
            {
                CryptographicOperations.ZeroMemory(protectedBytes);
            }
        }
    }

    public void WriteTombstone(EnterpriseLegacyMigrationTombstone tombstone)
    {
        ValidateTombstone(tombstone);
        WriteProtected(
            TombstonePath,
            MigrationRoot,
            tombstone,
            _tombstoneEntropy,
            "tombstone");
    }

    public void WriteWitness(EnterpriseLegacyMigrationTombstone tombstone)
    {
        ValidateTombstone(tombstone);
        WriteProtected(
            WitnessPath,
            WitnessRoot,
            tombstone,
            _witnessEntropy,
            "independent witness");
    }

    public void RetireActiveJournal(string transactionId)
    {
        if (!File.Exists(JournalPath))
        {
            return;
        }
        if (!Guid.TryParseExact(transactionId, "N", out _))
        {
            throw new InvalidDataException(
                "Enterprise migration journal retirement identity is invalid.");
        }
        var active = TryRead()
            ?? throw new InvalidDataException(
                "Enterprise active migration journal disappeared during retirement.");
        if (!string.Equals(
                active.TransactionId,
                transactionId,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Enterprise active migration journal does not match its completion footprint.");
        }
        var archiveRoot = CompletedJournalRoot;
        EnterpriseLegacyMigrationDurability.EnsureDirectory(MigrationRoot, archiveRoot);
        var archivePath = Path.Combine(archiveRoot, transactionId + ".v1.dpapi");
        if (File.Exists(archivePath) || Directory.Exists(archivePath))
        {
            throw new InvalidDataException(
                "Enterprise completed migration journal archive already exists unexpectedly.");
        }
        EnterpriseLegacyMigrationDurability.MoveFile(JournalPath, archivePath);
    }

    public bool HasCompletedJournalArchives()
    {
        if (!Directory.Exists(CompletedJournalRoot))
        {
            return false;
        }
        ValidateCompletedJournalArchives();
        return Directory.EnumerateFiles(
            CompletedJournalRoot,
            "*",
            SearchOption.TopDirectoryOnly).Any();
    }

    public void RequireOnlyRetiredArtifactsForFreshInstall()
    {
        if (!Directory.Exists(MigrationRoot))
        {
            return;
        }
        RequireIndependentBoundaries();
        EnterpriseManagedGcPathSafety.ValidateSafeTreeWithSingleLinks(
            MigrationRoot,
            _layout.LocalAppDataRoot);
        foreach (var entry in Directory.EnumerateFileSystemEntries(MigrationRoot))
        {
            if (!string.Equals(
                    Path.GetFileName(entry),
                    Path.GetFileName(CompletedJournalRoot),
                    StringComparison.Ordinal)
                || !Directory.Exists(entry))
            {
                throw new InvalidDataException(
                    "Fresh enterprise installation is blocked by an unfinished migration artifact.");
            }
        }
        ValidateCompletedJournalArchives();
    }

    private void ValidateCompletedJournalArchives()
    {
        EnterpriseManagedGcPathSafety.ValidateSafeTreeWithSingleLinks(
            CompletedJournalRoot,
            MigrationRoot);
        if (Directory.EnumerateDirectories(CompletedJournalRoot).Any())
        {
            throw new InvalidDataException(
                "Enterprise completed migration archive contains a directory.");
        }
        foreach (var path in Directory.EnumerateFiles(CompletedJournalRoot))
        {
            var name = Path.GetFileName(path);
            const string suffix = ".v1.dpapi";
            if (!name.EndsWith(suffix, StringComparison.Ordinal)
                || !Guid.TryParseExact(name[..^suffix.Length], "N", out _))
            {
                throw new InvalidDataException(
                    "Enterprise completed migration archive name is invalid.");
            }
            var journal = ReadProtected<EnterpriseLegacyMigrationJournal>(
                path,
                CompletedJournalRoot,
                _entropy,
                "completed journal");
            Validate(journal);
            if (!string.Equals(
                    journal.TransactionId + suffix,
                    name,
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Enterprise completed migration archive identity is invalid.");
            }
        }
    }

    public void Validate(EnterpriseLegacyMigrationJournal journal)
    {
        ArgumentNullException.ThrowIfNull(journal);
        RequireIndependentBoundaries();
        if (journal.SchemaVersion != 1
            || !string.Equals(
                journal.Product,
                EnterpriseReleaseSetContract.Product,
                StringComparison.Ordinal)
            || !string.Equals(
                journal.Environment,
                EnterpriseReleaseSetContract.EnvironmentForDevelopmentE2E(
                    _layout.IsDevelopmentE2E),
                StringComparison.Ordinal)
            || !string.Equals(journal.LayoutProfile, _layout.LayoutProfile, StringComparison.Ordinal)
            || !SamePath(journal.ManagedRoot, _layout.ManagedRoot)
            || !Guid.TryParseExact(journal.TransactionId, "N", out _)
            || !EnterpriseLegacyMigrationPhases.IsValid(journal.Phase)
            || !EnterpriseHash.IsSha256(journal.InstallerSha256)
            || !EnterpriseHash.IsSha256(journal.PayloadIdentitySha256)
            || journal.CreatedAtUtc.Offset != TimeSpan.Zero
            || journal.UpdatedAtUtc.Offset != TimeSpan.Zero
            || journal.UpdatedAtUtc < journal.CreatedAtUtc)
        {
            throw new InvalidDataException(
                "Enterprise migration journal identity or ordering is invalid.");
        }
        var managedParent = Path.GetDirectoryName(_layout.ManagedRoot)
            ?? throw new InvalidDataException("Enterprise ManagedRoot has no parent.");
        var managedLeaf = Path.GetFileName(_layout.ManagedRoot);
        var expectedCandidate = Path.Combine(
            managedParent,
            $".{managedLeaf}.migration-candidate-{journal.TransactionId}");
        var expectedQuarantine = Path.Combine(
            managedParent,
            $".{managedLeaf}.legacy-quarantine-{journal.TransactionId}");
        if (!SamePath(journal.CandidateDirectory, expectedCandidate)
            || !SamePath(journal.LegacyQuarantineDirectory, expectedQuarantine))
        {
            throw new InvalidDataException(
                "Enterprise migration journal escaped its exact transaction paths.");
        }
        var hasCandidateIdentity = journal.Phase != EnterpriseLegacyMigrationPhases.Intent;
        if (hasCandidateIdentity
            && (string.IsNullOrWhiteSpace(journal.LauncherReleaseId)
                || string.IsNullOrWhiteSpace(journal.RuntimeReleaseId)
                || journal.CandidateProgramTreeSha256 is not { } candidateTreeSha256
                || !EnterpriseHash.IsSha256(candidateTreeSha256)))
        {
            throw new InvalidDataException(
                "Enterprise migration journal candidate identity is incomplete.");
        }
        if (!hasCandidateIdentity
            && (journal.LauncherReleaseId is not null
                || journal.RuntimeReleaseId is not null
                || journal.CandidateProgramTreeSha256 is not null))
        {
            throw new InvalidDataException(
                "Enterprise migration intent contains an uncommitted candidate identity.");
        }
    }

    private void ValidateTombstone(EnterpriseLegacyMigrationTombstone tombstone)
    {
        ArgumentNullException.ThrowIfNull(tombstone);
        RequireIndependentBoundaries();
        if (tombstone.SchemaVersion != 1
            || !string.Equals(
                tombstone.Product,
                EnterpriseReleaseSetContract.Product,
                StringComparison.Ordinal)
            || !string.Equals(
                tombstone.Environment,
                EnterpriseReleaseSetContract.EnvironmentForDevelopmentE2E(
                    _layout.IsDevelopmentE2E),
                StringComparison.Ordinal)
            || !string.Equals(
                tombstone.LayoutProfile,
                _layout.LayoutProfile,
                StringComparison.Ordinal)
            || !SamePath(tombstone.ManagedRoot, _layout.ManagedRoot)
            || !Guid.TryParseExact(tombstone.TransactionId, "N", out _)
            || tombstone.CompletedAtUtc.Offset != TimeSpan.Zero
            || tombstone.CompletedAtUtc <= DateTimeOffset.UnixEpoch)
        {
            throw new InvalidDataException(
                "Enterprise completed migration tombstone identity is invalid.");
        }
    }

    private T ReadProtected<T>(
        string path,
        string trustedRoot,
        byte[] entropy,
        string field)
    {
        RequireIndependentBoundaries();
        EnterprisePathGuard.ValidateExistingPathWithin(
            path,
            trustedRoot,
            requireDirectory: false);
        EnterpriseManagedGcPathSafety.RequireSingleLinkFile(path, trustedRoot);
        var file = new FileInfo(path);
        if (file.Length is <= 0 or > MaximumProtectedJournalBytes)
        {
            throw new InvalidDataException(
                $"Protected enterprise migration {field} size is invalid.");
        }
        var envelopeBytes = File.ReadAllBytes(path);
        var protectedBytes = UnwrapProtectedEnvelope(envelopeBytes, field);
        byte[]? plaintext = null;
        try
        {
            plaintext = ProtectedData.Unprotect(
                protectedBytes,
                entropy,
                DataProtectionScope.CurrentUser);
            if (plaintext.Length is <= 0 or > MaximumProtectedJournalBytes)
            {
                throw new InvalidDataException(
                    $"Enterprise migration {field} plaintext size is invalid.");
            }
            RejectDuplicateProperties(plaintext);
            return JsonSerializer.Deserialize<T>(plaintext, JsonOptions)
                ?? throw new InvalidDataException(
                    $"Enterprise migration {field} is empty.");
        }
        catch (CryptographicException exception)
        {
            throw new InvalidDataException(
                $"Enterprise migration {field} cannot be authenticated for this Windows user.",
                exception);
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException(
                $"Enterprise migration {field} JSON is invalid.",
                exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(envelopeBytes);
            CryptographicOperations.ZeroMemory(protectedBytes);
            if (plaintext is not null)
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }
    }

    private void WriteProtected<T>(
        string path,
        string trustedRoot,
        T value,
        byte[] entropy,
        string field)
    {
        EnterpriseLegacyMigrationDurability.EnsureDirectory(
            string.Equals(
                trustedRoot,
                MigrationRoot,
                StringComparison.OrdinalIgnoreCase)
                ? _layout.LocalAppDataRoot
                : _layout.UserProfileRoot,
            trustedRoot);
        var plaintext = JsonSerializer.SerializeToUtf8Bytes(value, JsonOptions);
        byte[]? protectedBytes = null;
        try
        {
            protectedBytes = ProtectedData.Protect(
                plaintext,
                entropy,
                DataProtectionScope.CurrentUser);
            if (protectedBytes.Length is <= 0 or > MaximumProtectedJournalBytes)
            {
                throw new InvalidDataException(
                    $"Protected enterprise migration {field} size is invalid.");
            }
            var envelope = WrapProtectedEnvelope(protectedBytes);
            try
            {
                EnterpriseLegacyMigrationDurability.WriteFileAtomically(
                    path,
                    envelope,
                    trustedRoot);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(envelope);
            }
            EnterpriseManagedGcPathSafety.RequireSingleLinkFile(path, trustedRoot);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            if (protectedBytes is not null)
            {
                CryptographicOperations.ZeroMemory(protectedBytes);
            }
        }
    }

    public void RequireIndependentBoundaries()
    {
        var parent = Path.GetDirectoryName(_layout.ManagedRoot)
            ?? throw new InvalidDataException("Enterprise ManagedRoot has no parent.");
        if (!string.Equals(
                Path.GetPathRoot(MigrationRoot),
                Path.GetPathRoot(_layout.ManagedRoot),
                StringComparison.OrdinalIgnoreCase)
            || !EnterprisePathGuard.IsSameOrDescendant(MigrationRoot, parent)
            || EnterprisePathGuard.IsSameOrDescendant(MigrationRoot, _layout.ManagedRoot)
            || EnterprisePathGuard.IsSameOrDescendant(_layout.ManagedRoot, MigrationRoot)
            || EnterprisePathGuard.IsSameOrDescendant(MigrationRoot, _layout.HarnessHome)
            || EnterprisePathGuard.IsSameOrDescendant(_layout.HarnessHome, MigrationRoot)
            || EnterprisePathGuard.IsSameOrDescendant(
                MigrationRoot,
                _layout.HarnessRecoveryRoot)
            || EnterprisePathGuard.IsSameOrDescendant(
                _layout.HarnessRecoveryRoot,
                MigrationRoot)
            || !EnterprisePathGuard.IsSameOrDescendant(
                WitnessRoot,
                _layout.UserProfileRoot)
            || EnterprisePathGuard.IsSameOrDescendant(WitnessRoot, MigrationRoot)
            || EnterprisePathGuard.IsSameOrDescendant(MigrationRoot, WitnessRoot)
            || EnterprisePathGuard.IsSameOrDescendant(WitnessRoot, _layout.ManagedRoot)
            || EnterprisePathGuard.IsSameOrDescendant(_layout.ManagedRoot, WitnessRoot)
            || EnterprisePathGuard.IsSameOrDescendant(WitnessRoot, _layout.HarnessHome)
            || EnterprisePathGuard.IsSameOrDescendant(_layout.HarnessHome, WitnessRoot)
            || EnterprisePathGuard.IsSameOrDescendant(
                WitnessRoot,
                _layout.HarnessRecoveryRoot)
            || EnterprisePathGuard.IsSameOrDescendant(
                _layout.HarnessRecoveryRoot,
                WitnessRoot))
        {
            throw new InvalidDataException(
                "Enterprise migration roots must be same-volume siblings outside user data.");
        }
    }

    private static byte[] WrapProtectedEnvelope(ReadOnlySpan<byte> protectedBytes)
    {
        if (protectedBytes.Length is <= 0 or > MaximumProtectedJournalBytes)
        {
            throw new InvalidDataException(
                "Protected enterprise migration blob size is invalid.");
        }
        var envelope = new byte[checked(
            ProtectedEnvelopeMagic.Length + sizeof(int) + protectedBytes.Length)];
        ProtectedEnvelopeMagic.CopyTo(envelope, 0);
        System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(
            envelope.AsSpan(ProtectedEnvelopeMagic.Length, sizeof(int)),
            protectedBytes.Length);
        protectedBytes.CopyTo(envelope.AsSpan(
            ProtectedEnvelopeMagic.Length + sizeof(int)));
        return envelope;
    }

    private static byte[] UnwrapProtectedEnvelope(
        ReadOnlySpan<byte> envelope,
        string field)
    {
        var headerLength = ProtectedEnvelopeMagic.Length + sizeof(int);
        if (envelope.Length <= headerLength
            || !envelope[..ProtectedEnvelopeMagic.Length]
                .SequenceEqual(ProtectedEnvelopeMagic))
        {
            throw new InvalidDataException(
                $"Enterprise migration {field} protected envelope is invalid.");
        }
        var protectedLength = System.Buffers.Binary.BinaryPrimitives
            .ReadInt32LittleEndian(envelope.Slice(
                ProtectedEnvelopeMagic.Length,
                sizeof(int)));
        if (protectedLength is <= 0 or > MaximumProtectedJournalBytes
            || envelope.Length != headerLength + protectedLength)
        {
            throw new InvalidDataException(
                $"Enterprise migration {field} protected envelope length is invalid.");
        }
        return envelope[headerLength..].ToArray();
    }

    private static void RejectDuplicateProperties(ReadOnlySpan<byte> bytes)
    {
        using var document = JsonDocument.Parse(bytes.ToArray(), new JsonDocumentOptions
        {
            AllowTrailingCommas = false,
            CommentHandling = JsonCommentHandling.Disallow,
            MaxDepth = 32,
        });
        RejectDuplicateProperties(document.RootElement, "journal");
    }

    private static void RejectDuplicateProperties(JsonElement value, string path)
    {
        if (value.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in value.EnumerateObject())
            {
                if (!names.Add(property.Name))
                {
                    throw new InvalidDataException(
                        $"Enterprise migration {path} has duplicate property '{property.Name}'.");
                }
                RejectDuplicateProperties(property.Value, $"{path}.{property.Name}");
            }
        }
        else if (value.ValueKind == JsonValueKind.Array)
        {
            var index = 0;
            foreach (var item in value.EnumerateArray())
            {
                RejectDuplicateProperties(item, $"{path}[{index++}]");
            }
        }
    }

    private static bool SamePath(string left, string right) => string.Equals(
        Path.TrimEndingDirectorySeparator(Path.GetFullPath(left)),
        Path.TrimEndingDirectorySeparator(Path.GetFullPath(right)),
        StringComparison.OrdinalIgnoreCase);
}

internal static class EnterpriseLegacyMigrationDurability
{
    private const uint MoveFileReplaceExisting = 0x1;
    private const uint MoveFileWriteThrough = 0x8;
    private const uint GenericRead = 0x80000000;
    private const uint GenericWrite = 0x40000000;
    private const uint FileShareRead = 0x1;
    private const uint FileShareWrite = 0x2;
    private const uint FileShareDelete = 0x4;
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;

    public static void EnsureDirectory(string trustedRoot, string directory)
    {
        var normalizedRoot = EnterprisePathGuard.NormalizeDirectory(trustedRoot);
        var normalizedDirectory = EnterprisePathGuard.NormalizeDirectory(directory);
        if (!EnterprisePathGuard.IsSameOrDescendant(
                normalizedDirectory,
                normalizedRoot))
        {
            throw new InvalidDataException(
                "Durable migration directory escaped its trusted root.");
        }
        EnterprisePathGuard.EnsureDirectoryChain(trustedRoot, directory);
        EnterpriseLegacyMigrationPathSafety.RejectLinkedAncestors(directory);
        for (var current = normalizedDirectory;;)
        {
            FlushDirectory(current);
            if (string.Equals(
                    current,
                    normalizedRoot,
                    StringComparison.OrdinalIgnoreCase))
            {
                break;
            }
            current = Path.GetDirectoryName(current)
                ?? throw new InvalidDataException(
                    "Durable migration directory chain escaped its trusted root.");
        }
    }

    public static void FlushTree(string root, string trustedRoot)
    {
        var normalizedRoot = EnterprisePathGuard.NormalizeDirectory(root);
        var normalizedTrustedRoot = EnterprisePathGuard.NormalizeDirectory(trustedRoot);
        EnterpriseManagedGcPathSafety.ValidateSafeTreeWithSingleLinks(
            normalizedRoot,
            normalizedTrustedRoot);
        foreach (var path in Directory.EnumerateFiles(
                     normalizedRoot,
                     "*",
                     SearchOption.AllDirectories))
        {
            using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.ReadWrite,
                FileShare.Read,
                4096,
                FileOptions.WriteThrough);
            stream.Flush(flushToDisk: true);
        }
        foreach (var directory in Directory.EnumerateDirectories(
                     normalizedRoot,
                     "*",
                     SearchOption.AllDirectories)
                     .OrderByDescending(path => path.Count(character =>
                         character == Path.DirectorySeparatorChar)))
        {
            FlushDirectory(directory);
        }
        FlushDirectory(normalizedRoot);
        var parent = Path.GetDirectoryName(normalizedRoot);
        if (parent is not null)
        {
            FlushDirectory(parent);
        }
    }

    public static void WriteFileAtomically(
        string path,
        ReadOnlySpan<byte> contents,
        string trustedRoot)
    {
        var absolutePath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(absolutePath)
            ?? throw new InvalidDataException("Durable migration state has no parent.");
        EnsureDirectory(trustedRoot, directory);
        if (File.Exists(absolutePath))
        {
            EnterpriseManagedGcPathSafety.RequireSingleLinkFile(absolutePath, trustedRoot);
        }
        var temporaryPath = Path.Combine(
            directory,
            $".{Path.GetFileName(absolutePath)}.{Guid.NewGuid():N}.tmp");
        try
        {
            using (var stream = new FileStream(
                       temporaryPath,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       4096,
                       FileOptions.WriteThrough))
            {
                stream.Write(contents);
                stream.Flush(flushToDisk: true);
            }
            MoveFileRequired(
                temporaryPath,
                absolutePath,
                MoveFileReplaceExisting | MoveFileWriteThrough);
            FlushDirectory(directory);
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }

    public static void MoveDirectory(string source, string destination)
    {
        var absoluteSource = EnterprisePathGuard.NormalizeDirectory(source);
        var absoluteDestination = EnterprisePathGuard.NormalizeDirectory(destination);
        var destinationParent = Path.GetDirectoryName(absoluteDestination)
            ?? throw new InvalidDataException("Migration move destination has no parent.");
        var sourceParent = Path.GetDirectoryName(absoluteSource)
            ?? throw new InvalidDataException("Migration move source has no parent.");
        if (!Directory.Exists(absoluteSource)
            || Directory.Exists(absoluteDestination)
            || File.Exists(absoluteDestination)
            || !string.Equals(
                Path.GetPathRoot(absoluteSource),
                Path.GetPathRoot(absoluteDestination),
                StringComparison.OrdinalIgnoreCase))
        {
            throw new IOException(
                "Enterprise migration directory move requires an absent same-volume destination.");
        }
        EnterpriseLegacyMigrationPathSafety.RejectLinkedAncestors(sourceParent);
        EnterpriseLegacyMigrationPathSafety.RejectLinkedAncestors(destinationParent);
        MoveFileRequired(absoluteSource, absoluteDestination, MoveFileWriteThrough);
        FlushDirectory(sourceParent);
        if (!string.Equals(sourceParent, destinationParent, StringComparison.OrdinalIgnoreCase))
        {
            FlushDirectory(destinationParent);
        }
        if (Directory.Exists(absoluteSource) || !Directory.Exists(absoluteDestination))
        {
            throw new IOException(
                "Enterprise migration durable directory move did not commit exactly.");
        }
    }

    public static void MoveFile(string source, string destination)
    {
        var absoluteSource = Path.GetFullPath(source);
        var absoluteDestination = Path.GetFullPath(destination);
        var sourceParent = Path.GetDirectoryName(absoluteSource)
            ?? throw new InvalidDataException("Migration file source has no parent.");
        var destinationParent = Path.GetDirectoryName(absoluteDestination)
            ?? throw new InvalidDataException("Migration file destination has no parent.");
        if (!File.Exists(absoluteSource)
            || File.Exists(absoluteDestination)
            || Directory.Exists(absoluteDestination)
            || !string.Equals(
                Path.GetPathRoot(absoluteSource),
                Path.GetPathRoot(absoluteDestination),
                StringComparison.OrdinalIgnoreCase))
        {
            throw new IOException(
                "Enterprise migration file move requires an absent same-volume destination.");
        }
        EnterpriseLegacyMigrationPathSafety.RejectLinkedAncestors(sourceParent);
        EnterpriseLegacyMigrationPathSafety.RejectLinkedAncestors(destinationParent);
        MoveFileRequired(absoluteSource, absoluteDestination, MoveFileWriteThrough);
        FlushDirectory(sourceParent);
        if (!string.Equals(sourceParent, destinationParent, StringComparison.OrdinalIgnoreCase))
        {
            FlushDirectory(destinationParent);
        }
        if (File.Exists(absoluteSource) || !File.Exists(absoluteDestination))
        {
            throw new IOException(
                "Enterprise migration durable file move did not commit exactly.");
        }
    }

    private static void MoveFileRequired(string source, string destination, uint flags)
    {
        if (!OperatingSystem.IsWindows())
        {
            if ((flags & MoveFileReplaceExisting) != 0)
            {
                File.Move(source, destination, overwrite: true);
            }
            else
            {
                Directory.Move(source, destination);
            }
            return;
        }
        if (!MoveFileEx(
                EnterpriseMaintenanceIntegrity.ToExtendedWindowsPath(source),
                EnterpriseMaintenanceIntegrity.ToExtendedWindowsPath(destination),
                flags))
        {
            throw new IOException(
                $"Durable enterprise migration move failed: '{source}' -> '{destination}'.",
                new Win32Exception(Marshal.GetLastWin32Error()));
        }
    }

    private static void FlushDirectory(string directory)
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }
        using var handle = CreateFile(
            EnterpriseMaintenanceIntegrity.ToExtendedWindowsPath(directory),
            GenericRead | GenericWrite,
            FileShareRead | FileShareWrite | FileShareDelete,
            IntPtr.Zero,
            OpenExisting,
            FileFlagBackupSemantics | FileFlagOpenReparsePoint,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            throw new IOException(
                $"Cannot open enterprise migration directory for durable flush: {directory}",
                new Win32Exception(Marshal.GetLastWin32Error()));
        }
        if (!FlushFileBuffers(handle))
        {
            throw new IOException(
                $"Cannot durably flush enterprise migration directory: {directory}",
                new Win32Exception(Marshal.GetLastWin32Error()));
        }
    }

    [DllImport("kernel32.dll", EntryPoint = "MoveFileExW", CharSet = CharSet.Unicode,
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool MoveFileEx(
        string existingFileName,
        string newFileName,
        uint flags);

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode,
        SetLastError = true)]
    private static extern SafeFileHandle CreateFile(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FlushFileBuffers(SafeFileHandle fileHandle);
}

internal static class EnterpriseLegacyMigrationTreeRenameProbe
{
    private const uint GenericRead = 0x80000000;
    private const uint Delete = 0x00010000;
    private const uint ShareRead = 0x00000001;
    private const uint ShareWrite = 0x00000002;
    private const uint ShareDelete = 0x00000004;
    private const uint OpenExisting = 3;
    private const uint BackupSemantics = 0x02000000;
    private const uint OpenReparsePoint = 0x00200000;

    public static void RequireMovable(string root)
    {
        var rootParent = Path.GetDirectoryName(root)
            ?? throw new InvalidDataException(
                "Enterprise migration rename root has no parent directory.");
        EnterpriseManagedGcPathSafety.ValidateSafeTreeWithSingleLinks(root, rootParent);
        var entries = new List<(string Path, bool Directory)> { (root, true) };
        entries.AddRange(Directory.EnumerateDirectories(root, "*", SearchOption.AllDirectories)
            .Order(StringComparer.OrdinalIgnoreCase)
            .Select(path => (path, true)));
        entries.AddRange(Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories)
            .Order(StringComparer.OrdinalIgnoreCase)
            .Select(path => (path, false)));
        var handles = new List<SafeFileHandle>(entries.Count);
        try
        {
            foreach (var entry in entries)
            {
                var handle = CreateFile(
                    EnterpriseMaintenanceIntegrity.ToExtendedWindowsPath(entry.Path),
                    GenericRead | Delete,
                    ShareRead | ShareWrite | ShareDelete,
                    IntPtr.Zero,
                    OpenExisting,
                    (entry.Directory ? BackupSemantics : 0) | OpenReparsePoint,
                    IntPtr.Zero);
                if (handle.IsInvalid)
                {
                    var error = new Win32Exception(Marshal.GetLastWin32Error());
                    handle.Dispose();
                    throw new IOException(
                        $"Enterprise migration cannot exclude an open managed path: {entry.Path}",
                        error);
                }
                var identity = EnterpriseFileIdentity.Read(handle);
                if ((identity.Attributes & (uint)FileAttributes.ReparsePoint) != 0
                    || !entry.Directory && identity.NumberOfLinks != 1)
                {
                    handle.Dispose();
                    throw new InvalidDataException(
                        "Enterprise migration refuses linked managed paths.");
                }
                handles.Add(handle);
            }
        }
        finally
        {
            foreach (var handle in handles)
            {
                handle.Dispose();
            }
        }
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode,
        SetLastError = true)]
    private static extern SafeFileHandle CreateFile(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);
}

internal static class EnterpriseLegacyMigrationPathSafety
{
    public static void RejectLinkedAncestors(string path)
    {
        for (var current = new DirectoryInfo(Path.GetFullPath(path));
             current is not null;
             current = current.Parent)
        {
            if (current.Exists
                && (current.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException(
                    "Enterprise migration path crosses a filesystem link.");
            }
        }
    }
}

internal readonly record struct EnterpriseFileIdentity(
    uint VolumeSerialNumber,
    uint FileIndexHigh,
    uint FileIndexLow,
    uint NumberOfLinks,
    uint Attributes,
    long Length)
{
    public static EnterpriseFileIdentity Read(SafeFileHandle handle)
    {
        if (!OperatingSystem.IsWindows())
        {
            return new EnterpriseFileIdentity(0, 0, 0, 1, 0, 0);
        }
        if (!GetFileInformationByHandle(handle, out var information))
        {
            throw new IOException(
                "Cannot inspect enterprise migration file identity.",
                new Win32Exception(Marshal.GetLastWin32Error()));
        }
        var length = ((long)information.FileSizeHigh << 32) | information.FileSizeLow;
        return new EnterpriseFileIdentity(
            information.VolumeSerialNumber,
            information.FileIndexHigh,
            information.FileIndexLow,
            information.NumberOfLinks,
            information.FileAttributes,
            length);
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle file,
        out ByHandleFileInformation information);

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
