using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Win32;

namespace Ensou.Dsh.Enterprise.Installation;

/// <summary>
/// Durable same-volume rollback journal for Installer file and shell changes.
/// Every destructive phase is DPAPI-protected and flushed before it advances.
/// </summary>
internal sealed class EnterpriseInstallRollbackTransaction : IDisposable
{
    private const int SchemaVersion = 1;
    private const string Product = "Ensou.Dsh.Enterprise.InstallRollback";
    private const string StateFileName = "install-rollback-state.v1.dpapi";
    private const int MaximumStateBytes = 8 * 1024 * 1024;
    private const string ActiveStatus = "active";
    private const string CommittedStatus = "committed";
    private const string RolledBackStatus = "rolled-back";
    private const string PlannedPhase = "planned";
    private const string CapturedPhase = "captured";
    private const string RestoredPhase = "restored";
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        MaxDepth = 16,
    };

    private readonly EnterpriseInstallationLayout _layout;
    private readonly string _journalRoot;
    private readonly string _statePath;
    private DurableState _state;
    private bool _completed;
    private bool _rollbackAttempted;

    public EnterpriseInstallRollbackTransaction(
        EnterpriseInstallationLayout layout,
        EnterpriseWindowsRegistrationContext? registrationContext = null,
        EnterpriseWindowsRegistrationRollbackSnapshot? registrationSnapshot = null)
    {
        _layout = layout ?? throw new ArgumentNullException(nameof(layout));
        if ((registrationContext is null) != (registrationSnapshot is null))
        {
            throw new ArgumentException(
                "Enterprise registration context and snapshot must be supplied together.");
        }

        var parent = GetManagedRootParent(layout);
        EnterprisePathGuard.EnsureDirectoryChain(layout.LocalAppDataRoot, parent);
        var transactionId = Guid.NewGuid().ToString("N");
        _journalRoot = Path.Combine(parent, GetJournalPrefix(layout) + transactionId);
        _statePath = Path.Combine(_journalRoot, StateFileName);
        ValidateJournalPath(layout, _journalRoot, transactionId);
        Directory.CreateDirectory(_journalRoot);
        EnterprisePathGuard.ValidateExistingPathWithin(
            _journalRoot,
            layout.LocalAppDataRoot,
            requireDirectory: true);
        _state = new DurableState(
            SchemaVersion,
            Product,
            layout.LayoutProfile,
            layout.ManagedRoot,
            transactionId,
            ActiveStatus,
            Directory.Exists(layout.ManagedRoot),
            [],
            registrationContext is null
                ? null
                : EnterpriseDurableWindowsRegistration.Create(
                    registrationContext.WithoutObservers(),
                    registrationSnapshot!));
        WriteState();
    }

    private EnterpriseInstallRollbackTransaction(
        EnterpriseInstallationLayout layout,
        string journalRoot,
        DurableState state)
    {
        _layout = layout;
        _journalRoot = journalRoot;
        _statePath = Path.Combine(journalRoot, StateFileName);
        _state = state;
    }

    public static void RecoverInterrupted(EnterpriseInstallationLayout layout)
    {
        ArgumentNullException.ThrowIfNull(layout);
        var parent = GetManagedRootParent(layout);
        if (!Directory.Exists(parent))
        {
            return;
        }
        EnterprisePathGuard.ValidateExistingPathWithin(
            parent,
            layout.LocalAppDataRoot,
            requireDirectory: true);
        var prefix = GetJournalPrefix(layout);
        var loaded = new List<EnterpriseInstallRollbackTransaction>();
        foreach (var journal in Directory.EnumerateDirectories(
                     parent,
                     prefix + "*",
                     SearchOption.TopDirectoryOnly)
                 .Order(StringComparer.Ordinal))
        {
            var leaf = Path.GetFileName(journal);
            if (!leaf.StartsWith(prefix, StringComparison.Ordinal)
                || !Guid.TryParseExact(leaf[prefix.Length..], "N", out _))
            {
                throw new InvalidDataException(
                    "Enterprise install rollback journal name is invalid.");
            }
            var transactionId = leaf[prefix.Length..];
            ValidateJournalPath(layout, journal, transactionId);
            RejectReparse(journal);
            var statePath = Path.Combine(journal, StateFileName);
            if (!File.Exists(statePath))
            {
                RequireEmptyPreStateJournal(journal);
                DeleteJournal(layout, journal);
                continue;
            }
            var state = ReadState(layout, journal, statePath);
            ValidateState(layout, journal, state);
            loaded.Add(new EnterpriseInstallRollbackTransaction(layout, journal, state));
        }

        if (loaded.Count(value => value._state.Status == ActiveStatus) > 1)
        {
            throw new InvalidDataException(
                "Multiple active Enterprise install rollback journals exist.");
        }
        foreach (var transaction in loaded)
        {
            if (transaction._state.Status == ActiveStatus)
            {
                transaction.Rollback();
            }
            else
            {
                transaction._completed = true;
                transaction.TryDeleteJournal();
            }
        }
    }

    internal static void RewriteStatePlaintextForTest(
        EnterpriseInstallationLayout layout,
        string journalRoot,
        Func<byte[], byte[]> transform)
    {
        ArgumentNullException.ThrowIfNull(layout);
        ArgumentNullException.ThrowIfNull(transform);
        var leaf = Path.GetFileName(Path.GetFullPath(journalRoot));
        var prefix = GetJournalPrefix(layout);
        if (!leaf.StartsWith(prefix, StringComparison.Ordinal)
            || !Guid.TryParseExact(leaf[prefix.Length..], "N", out _))
        {
            throw new InvalidDataException(
                "Enterprise test journal path is invalid.");
        }
        ValidateJournalPath(layout, journalRoot, leaf[prefix.Length..]);
        var statePath = Path.Combine(journalRoot, StateFileName);
        ValidateOrdinarySingleLinkFile(statePath, journalRoot);
        var protectedBytes = File.ReadAllBytes(statePath);
        byte[]? plaintext = null;
        byte[]? mutated = null;
        byte[]? rewritten = null;
        var temporary = Path.Combine(
            journalRoot,
            $".install-rollback-state.{Guid.NewGuid():N}.tmp");
        try
        {
            plaintext = UnprotectCurrentUser(protectedBytes, GetEntropy(layout));
            mutated = transform(plaintext.ToArray());
            rewritten = ProtectCurrentUser(mutated, GetEntropy(layout));
            using (var stream = new FileStream(
                       temporary,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       bufferSize: 4_096,
                       FileOptions.WriteThrough))
            {
                stream.Write(rewritten);
                stream.Flush(flushToDisk: true);
            }
            File.Move(temporary, statePath, overwrite: true);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(protectedBytes);
            if (plaintext is not null)
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }
            if (mutated is not null)
            {
                CryptographicOperations.ZeroMemory(mutated);
            }
            if (rewritten is not null)
            {
                CryptographicOperations.ZeroMemory(rewritten);
            }
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
            }
        }
    }

    public void CaptureFile(string path)
    {
        RequireActive();
        var target = RequireAllowedFileTarget(path);
        if (_state.Entries.Any(entry => SamePath(entry.Target, target)))
        {
            return;
        }

        var existed = File.Exists(target);
        if (Directory.Exists(target))
        {
            throw new InvalidDataException(
                "Enterprise install file target is unexpectedly a directory.");
        }
        string? expectedSha256 = null;
        long expectedLength = 0;
        if (existed)
        {
            ValidateOrdinarySingleLinkFile(target, _layout.ManagedRoot);
            expectedSha256 = ComputeFileSha256(target);
            expectedLength = new FileInfo(target).Length;
        }

        var index = _state.Entries.Count;
        var backup = GetBackupPath(index, directory: false);
        AppendEntry(new DurableEntry(
            index,
            target,
            backup,
            existed,
            Directory: false,
            expectedSha256,
            expectedLength,
            PlannedPhase));
        if (existed)
        {
            CopyFileDurably(target, backup);
            RequireFileIdentity(backup, expectedSha256!, expectedLength, _journalRoot);
        }
        SetEntryPhase(index, CapturedPhase);
    }

    public void PrepareDirectoryReplacement(string path)
    {
        RequireActive();
        var target = RequireAllowedVersionDirectory(path);
        if (_state.Entries.Any(entry => SamePath(entry.Target, target)))
        {
            throw new InvalidOperationException(
                "Enterprise install directory was captured more than once.");
        }

        var existed = Directory.Exists(target);
        if (File.Exists(target))
        {
            throw new InvalidDataException(
                "Enterprise install directory target is unexpectedly a file.");
        }
        var expectedIdentity = existed
            ? ComputeDirectoryIdentity(target, _layout.ManagedRoot)
            : null;
        var index = _state.Entries.Count;
        var backup = GetBackupPath(index, directory: true);
        AppendEntry(new DurableEntry(
            index,
            target,
            backup,
            existed,
            Directory: true,
            expectedIdentity,
            ExpectedLength: 0,
            PlannedPhase));
        if (existed)
        {
            Directory.Move(target, backup);
            RequireDirectoryIdentity(backup, expectedIdentity!, _layout.LocalAppDataRoot);
        }
        SetEntryPhase(index, CapturedPhase);
    }

    public void Commit()
    {
        RequireActive();
        _state = _state with { Status = CommittedStatus };
        WriteState();
        _completed = true;
        TryDeleteJournal();
    }

    public void Rollback()
    {
        if (_completed)
        {
            return;
        }
        if (_rollbackAttempted)
        {
            return;
        }
        _rollbackAttempted = true;
        ValidateState(_layout, _journalRoot, _state);
        if (_state.Status != ActiveStatus)
        {
            _completed = true;
            TryDeleteJournal();
            return;
        }

        foreach (var entry in _state.Entries.Reverse())
        {
            RestoreEntry(entry);
            SetEntryPhase(entry.Index, RestoredPhase);
        }
        if (!_state.ManagedRootExisted && Directory.Exists(_layout.ManagedRoot))
        {
            ComputeDirectoryIdentity(_layout.ManagedRoot, _layout.LocalAppDataRoot);
            EnterprisePathGuard.DeleteDirectoryTree(
                _layout.ManagedRoot,
                _layout.LocalAppDataRoot);
        }
        if (_state.Registration is not null)
        {
            var (context, snapshot) = _state.Registration.ToRuntime();
            EnterpriseWindowsRegistration.RestoreRollbackSnapshot(
                _layout,
                context,
                snapshot);
        }
        _state = _state with { Status = RolledBackStatus };
        WriteState();
        _completed = true;
        TryDeleteJournal();
    }

    public void Dispose()
    {
        if (!_completed && !_rollbackAttempted)
        {
            Rollback();
        }
    }

    private void RestoreEntry(DurableEntry entry)
    {
        if (entry.Directory)
        {
            RestoreDirectory(entry);
        }
        else
        {
            RestoreFile(entry);
        }
    }

    private void RestoreDirectory(DurableEntry entry)
    {
        if (File.Exists(entry.Target) || File.Exists(entry.Backup))
        {
            throw new InvalidDataException(
                "Enterprise directory rollback path became a file.");
        }
        if (!entry.Existed)
        {
            if (Directory.Exists(entry.Backup))
            {
                throw new InvalidDataException(
                    "Enterprise absent directory unexpectedly has a rollback backup.");
            }
            if (Directory.Exists(entry.Target))
            {
                ComputeDirectoryIdentity(entry.Target, _layout.ManagedRoot);
                EnterprisePathGuard.DeleteDirectoryTree(entry.Target, _layout.ManagedRoot);
            }
            return;
        }

        if (Directory.Exists(entry.Backup))
        {
            RequireDirectoryIdentity(
                entry.Backup,
                entry.ExpectedSha256!,
                _layout.LocalAppDataRoot);
            if (Directory.Exists(entry.Target))
            {
                ComputeDirectoryIdentity(entry.Target, _layout.ManagedRoot);
                EnterprisePathGuard.DeleteDirectoryTree(entry.Target, _layout.ManagedRoot);
            }
            Directory.Move(entry.Backup, entry.Target);
        }
        RequireDirectoryIdentity(
            entry.Target,
            entry.ExpectedSha256!,
            _layout.ManagedRoot);
    }

    private void RestoreFile(DurableEntry entry)
    {
        if (Directory.Exists(entry.Target) || Directory.Exists(entry.Backup))
        {
            throw new InvalidDataException(
                "Enterprise file rollback path became a directory.");
        }
        if (!entry.Existed)
        {
            if (File.Exists(entry.Backup))
            {
                throw new InvalidDataException(
                    "Enterprise absent file unexpectedly has a rollback backup.");
            }
            if (File.Exists(entry.Target))
            {
                ValidateOrdinarySingleLinkFile(entry.Target, _layout.ManagedRoot);
                File.Delete(entry.Target);
            }
            return;
        }

        if (File.Exists(entry.Target)
            && FileMatchesIdentity(
                entry.Target,
                entry.ExpectedSha256!,
                entry.ExpectedLength,
                _layout.ManagedRoot))
        {
            if (File.Exists(entry.Backup))
            {
                // A kill during CopyFileDurably may leave a partial backup
                // while the original target is still exact. The durable
                // planned phase authorizes deleting only that controlled copy.
                ValidateOrdinarySingleLinkFile(entry.Backup, _journalRoot);
                File.Delete(entry.Backup);
            }
            return;
        }
        if (File.Exists(entry.Backup))
        {
            RequireFileIdentity(
                entry.Backup,
                entry.ExpectedSha256!,
                entry.ExpectedLength,
                _journalRoot);
            if (File.Exists(entry.Target))
            {
                ValidateOrdinarySingleLinkFile(entry.Target, _layout.ManagedRoot);
                File.Delete(entry.Target);
            }
            var parent = Path.GetDirectoryName(entry.Target)
                ?? throw new InvalidDataException(
                    "Enterprise rollback file target has no parent.");
            EnterprisePathGuard.EnsureDirectoryChain(_layout.ManagedRoot, parent);
            File.Move(entry.Backup, entry.Target);
        }
        RequireFileIdentity(
            entry.Target,
            entry.ExpectedSha256!,
            entry.ExpectedLength,
            _layout.ManagedRoot);
    }

    private void AppendEntry(DurableEntry entry)
    {
        _state = _state with { Entries = _state.Entries.Append(entry).ToArray() };
        WriteState();
    }

    private void SetEntryPhase(int index, string phase)
    {
        var entries = _state.Entries.ToArray();
        entries[index] = entries[index] with { Phase = phase };
        _state = _state with { Entries = entries };
        WriteState();
    }

    private void WriteState()
    {
        ValidateState(_layout, _journalRoot, _state);
        var plaintext = JsonSerializer.SerializeToUtf8Bytes(_state, JsonOptions);
        byte[]? protectedBytes = null;
        var temporary = Path.Combine(
            _journalRoot,
            $".install-rollback-state.{Guid.NewGuid():N}.tmp");
        try
        {
            protectedBytes = ProtectCurrentUser(plaintext, GetEntropy(_layout));
            if (protectedBytes.Length > MaximumStateBytes)
            {
                throw new InvalidDataException(
                    "Enterprise install rollback state exceeds its size limit.");
            }
            using (var stream = new FileStream(
                       temporary,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       bufferSize: 4_096,
                       FileOptions.WriteThrough))
            {
                stream.Write(protectedBytes);
                stream.Flush(flushToDisk: true);
            }
            File.Move(temporary, _statePath, overwrite: true);
            ValidateOrdinarySingleLinkFile(_statePath, _journalRoot);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            if (protectedBytes is not null)
            {
                CryptographicOperations.ZeroMemory(protectedBytes);
            }
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
            }
        }
    }

    private static DurableState ReadState(
        EnterpriseInstallationLayout layout,
        string journalRoot,
        string statePath)
    {
        ValidateOrdinarySingleLinkFile(statePath, journalRoot);
        var protectedBytes = File.ReadAllBytes(statePath);
        if (protectedBytes.Length is <= 0 or > MaximumStateBytes)
        {
            throw new InvalidDataException(
                "Enterprise install rollback state size is invalid.");
        }
        byte[]? plaintext = null;
        try
        {
            plaintext = UnprotectCurrentUser(protectedBytes, GetEntropy(layout));
            RejectDuplicateJsonProperties(plaintext);
            return JsonSerializer.Deserialize<DurableState>(plaintext, JsonOptions)
                ?? throw new InvalidDataException(
                    "Enterprise install rollback state is empty.");
        }
        catch (CryptographicException exception)
        {
            throw new InvalidDataException(
                "Enterprise install rollback state authentication failed.",
                exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(protectedBytes);
            if (plaintext is not null)
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }
    }

    private static void ValidateState(
        EnterpriseInstallationLayout layout,
        string journalRoot,
        DurableState state)
    {
        if (state.SchemaVersion != SchemaVersion
            || !string.Equals(state.Product, Product, StringComparison.Ordinal)
            || !string.Equals(state.LayoutProfile, layout.LayoutProfile, StringComparison.Ordinal)
            || !SamePath(state.ManagedRoot, layout.ManagedRoot)
            || !Guid.TryParseExact(state.TransactionId, "N", out _)
            || state.Status is not (ActiveStatus or CommittedStatus or RolledBackStatus)
            || state.Entries is null
            || state.Entries.Count > 32)
        {
            throw new InvalidDataException(
                "Enterprise install rollback state identity is invalid.");
        }
        ValidateJournalPath(layout, journalRoot, state.TransactionId);
        for (var index = 0; index < state.Entries.Count; index++)
        {
            var entry = state.Entries[index];
            if (entry.Index != index
                || entry.Phase is not (PlannedPhase or CapturedPhase or RestoredPhase)
                || entry.Existed != (entry.ExpectedSha256 is not null)
                || entry.Existed && !EnterpriseHash.IsSha256(entry.ExpectedSha256!)
                || !entry.Existed && entry.ExpectedLength != 0
                || entry.ExpectedLength < 0
                || !SamePath(
                    entry.Backup,
                    Path.Combine(journalRoot, GetBackupName(index, entry.Directory))))
            {
                throw new InvalidDataException(
                    "Enterprise install rollback entry is invalid.");
            }
            if (entry.Directory)
            {
                RequireAllowedVersionDirectory(layout, entry.Target);
                if (entry.ExpectedLength != 0)
                {
                    throw new InvalidDataException(
                        "Enterprise directory rollback length must be zero.");
                }
            }
            else
            {
                RequireAllowedFileTarget(layout, entry.Target);
            }
        }
        if (state.Entries.Select(entry => entry.Target)
                .Distinct(StringComparer.OrdinalIgnoreCase).Count()
            != state.Entries.Count)
        {
            throw new InvalidDataException(
                "Enterprise install rollback targets are duplicated.");
        }
        state.Registration?.Validate(layout);
    }

    private static void RequireEmptyPreStateJournal(string journalRoot)
    {
        foreach (var entry in Directory.EnumerateFileSystemEntries(
                     journalRoot,
                     "*",
                     SearchOption.TopDirectoryOnly))
        {
            RejectReparse(entry);
            var leaf = Path.GetFileName(entry);
            if (Directory.Exists(entry)
                || !leaf.StartsWith(".install-rollback-state.", StringComparison.Ordinal)
                || !leaf.EndsWith(".tmp", StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Enterprise pre-state rollback journal contains unexpected data.");
            }
        }
    }

    private string RequireAllowedFileTarget(string path) =>
        RequireAllowedFileTarget(_layout, path);

    private static string RequireAllowedFileTarget(
        EnterpriseInstallationLayout layout,
        string path)
    {
        var target = Path.GetFullPath(path);
        var allowed = new[]
        {
            layout.BootstrapperPath,
            layout.BootstrapperReceiptPath,
            layout.BuildProfileMarkerPath,
            layout.InstalledInstallerPath,
            layout.RuntimePointerPath,
            layout.LauncherPointerPath,
            layout.ReleaseSetPointerPath,
            Path.Combine(layout.StateRoot, "installation-receipt.json"),
        };
        if (!allowed.Any(candidate => SamePath(candidate, target)))
        {
            throw new InvalidDataException(
                "Enterprise install rollback file target is not in the fixed mutation set.");
        }
        return target;
    }

    private string RequireAllowedVersionDirectory(string path) =>
        RequireAllowedVersionDirectory(_layout, path);

    private static string RequireAllowedVersionDirectory(
        EnterpriseInstallationLayout layout,
        string path)
    {
        var target = EnterprisePathGuard.NormalizeDirectory(path);
        var parent = Path.GetDirectoryName(target)
            ?? throw new InvalidDataException(
                "Enterprise version rollback target has no parent.");
        if (!SamePath(parent, layout.LauncherVersionsRoot)
            && !SamePath(parent, layout.RuntimeVersionsRoot))
        {
            throw new InvalidDataException(
                "Enterprise install rollback directory is not an exact version child.");
        }
        EnterprisePathGuard.ValidateReleaseId(Path.GetFileName(target));
        return target;
    }

    private string GetBackupPath(int index, bool directory) => Path.Combine(
        _journalRoot,
        GetBackupName(index, directory));

    private static string GetBackupName(int index, bool directory) =>
        $"{(directory ? "directory" : "file")}-{index:D4}.rollback";

    private static void CopyFileDurably(string source, string destination)
    {
        using var input = new FileStream(
            source,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 128 * 1024,
            FileOptions.SequentialScan);
        using var output = new FileStream(
            destination,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            bufferSize: 128 * 1024,
            FileOptions.WriteThrough);
        input.CopyTo(output);
        output.Flush(flushToDisk: true);
    }

    private static string ComputeFileSha256(string path)
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

    private static string ComputeDirectoryIdentity(string directory, string boundary)
    {
        EnterprisePathGuard.ValidateSafeTree(directory, boundary);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var root = EnterprisePathGuard.NormalizeDirectory(directory);
        foreach (var child in Directory.EnumerateDirectories(
                     root,
                     "*",
                     SearchOption.AllDirectories)
                 .Order(StringComparer.OrdinalIgnoreCase))
        {
            RejectReparse(child);
            AppendText(hash, "D\0" + NormalizeRelative(root, child) + "\0");
        }
        var buffer = new byte[128 * 1024];
        try
        {
            foreach (var file in Directory.EnumerateFiles(
                         root,
                         "*",
                         SearchOption.AllDirectories)
                     .Order(StringComparer.OrdinalIgnoreCase))
            {
                ValidateOrdinarySingleLinkFile(file, boundary);
                var info = new FileInfo(file);
                AppendText(
                    hash,
                    "F\0" + NormalizeRelative(root, file) + "\0" + info.Length + "\0");
                using var stream = new FileStream(
                    file,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.Read,
                    buffer.Length,
                    FileOptions.SequentialScan);
                int read;
                while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    hash.AppendData(buffer, 0, read);
                }
                AppendText(hash, "\0");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
        return Convert.ToHexStringLower(hash.GetHashAndReset());
    }

    private static void RequireDirectoryIdentity(
        string directory,
        string expectedSha256,
        string boundary)
    {
        if (!Directory.Exists(directory)
            || !string.Equals(
                ComputeDirectoryIdentity(directory, boundary),
                expectedSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Enterprise install rollback directory identity changed.");
        }
    }

    private static void RequireFileIdentity(
        string path,
        string expectedSha256,
        long expectedLength,
        string boundary)
    {
        ValidateOrdinarySingleLinkFile(path, boundary);
        if (new FileInfo(path).Length != expectedLength
            || !string.Equals(
                ComputeFileSha256(path),
                expectedSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Enterprise install rollback file identity changed.");
        }
    }

    private static bool FileMatchesIdentity(
        string path,
        string expectedSha256,
        long expectedLength,
        string boundary)
    {
        if (!File.Exists(path))
        {
            return false;
        }
        ValidateOrdinarySingleLinkFile(path, boundary);
        return new FileInfo(path).Length == expectedLength
            && string.Equals(
                ComputeFileSha256(path),
                expectedSha256,
                StringComparison.Ordinal);
    }

    private static void ValidateOrdinarySingleLinkFile(string path, string boundary)
    {
        EnterprisePathGuard.ValidateExistingPathWithin(
            path,
            boundary,
            requireDirectory: false);
        RejectReparse(path);
        EnterpriseMaintenanceIntegrity.RequireSingleLinkFile(path);
    }

    private static void RejectReparse(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException(
                "Enterprise install rollback path must not be a filesystem link.");
        }
    }

    private static void AppendText(IncrementalHash hash, string value) =>
        hash.AppendData(Encoding.UTF8.GetBytes(value));

    private static string NormalizeRelative(string root, string path) =>
        Path.GetRelativePath(root, path).Replace('\\', '/');

    private static byte[] GetEntropy(EnterpriseInstallationLayout layout) =>
        SHA256.HashData(Encoding.UTF8.GetBytes(
            Product + "\n" + layout.LayoutProfile + "\n" + layout.ManagedRoot));

    private static void RejectDuplicateJsonProperties(ReadOnlySpan<byte> json)
    {
        var reader = new Utf8JsonReader(
            json,
            new JsonReaderOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 16,
            });
        var objects = new Stack<HashSet<string>>();
        while (reader.Read())
        {
            switch (reader.TokenType)
            {
                case JsonTokenType.StartObject:
                    objects.Push(new HashSet<string>(StringComparer.Ordinal));
                    break;
                case JsonTokenType.EndObject:
                    if (objects.Count == 0)
                    {
                        throw new InvalidDataException(
                            "Enterprise install rollback JSON object nesting is invalid.");
                    }
                    _ = objects.Pop();
                    break;
                case JsonTokenType.PropertyName:
                    if (objects.Count == 0
                        || !objects.Peek().Add(reader.GetString()!))
                    {
                        throw new InvalidDataException(
                            "Enterprise install rollback JSON contains a duplicate property.");
                    }
                    break;
            }
        }
        if (objects.Count != 0)
        {
            throw new InvalidDataException(
                "Enterprise install rollback JSON nesting is incomplete.");
        }
    }

    private static byte[] ProtectCurrentUser(
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> entropy) =>
        TransformDpapi(plaintext, entropy, protect: true);

    private static byte[] UnprotectCurrentUser(
        ReadOnlySpan<byte> protectedBytes,
        ReadOnlySpan<byte> entropy) =>
        TransformDpapi(protectedBytes, entropy, protect: false);

    private static byte[] TransformDpapi(
        ReadOnlySpan<byte> input,
        ReadOnlySpan<byte> entropy,
        bool protect)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "Enterprise install rollback authentication requires Windows DPAPI.");
        }
        var inputBytes = input.ToArray();
        var entropyBytes = entropy.ToArray();
        var inputPointer = IntPtr.Zero;
        var entropyPointer = IntPtr.Zero;
        var output = default(DataBlob);
        try
        {
            inputPointer = Marshal.AllocHGlobal(inputBytes.Length);
            Marshal.Copy(inputBytes, 0, inputPointer, inputBytes.Length);
            entropyPointer = Marshal.AllocHGlobal(entropyBytes.Length);
            Marshal.Copy(entropyBytes, 0, entropyPointer, entropyBytes.Length);
            var inputBlob = new DataBlob(inputBytes.Length, inputPointer);
            var entropyBlob = new DataBlob(entropyBytes.Length, entropyPointer);
            var succeeded = protect
                ? CryptProtectData(
                    ref inputBlob,
                    null,
                    ref entropyBlob,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    CryptProtectUiForbidden,
                    out output)
                : CryptUnprotectData(
                    ref inputBlob,
                    IntPtr.Zero,
                    ref entropyBlob,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    CryptProtectUiForbidden,
                    out output);
            if (!succeeded)
            {
                throw new CryptographicException(
                    "Windows DPAPI could not transform Enterprise install rollback state.",
                    new Win32Exception(Marshal.GetLastWin32Error()));
            }
            var result = new byte[output.Length];
            Marshal.Copy(output.Data, result, 0, result.Length);
            return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(inputBytes);
            CryptographicOperations.ZeroMemory(entropyBytes);
            if (inputPointer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(inputPointer);
            }
            if (entropyPointer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(entropyPointer);
            }
            if (output.Data != IntPtr.Zero)
            {
                _ = LocalFree(output.Data);
            }
        }
    }

    private static string GetManagedRootParent(EnterpriseInstallationLayout layout) =>
        Path.GetDirectoryName(layout.ManagedRoot)
        ?? throw new InvalidDataException(
            "Enterprise ManagedRoot has no parent for the install journal.");

    private static string GetJournalPrefix(EnterpriseInstallationLayout layout) =>
        $".{Path.GetFileName(layout.ManagedRoot)}.install-rollback-";

    private static void ValidateJournalPath(
        EnterpriseInstallationLayout layout,
        string path,
        string transactionId)
    {
        var absolute = EnterprisePathGuard.NormalizeDirectory(path);
        var expected = Path.Combine(
            GetManagedRootParent(layout),
            GetJournalPrefix(layout) + transactionId);
        if (!SamePath(absolute, expected)
            || !EnterprisePathGuard.IsSameOrDescendant(absolute, layout.LocalAppDataRoot))
        {
            throw new InvalidDataException(
                "Enterprise install rollback journal escaped its exact sibling boundary.");
        }
    }

    private void RequireActive()
    {
        if (_completed || _state.Status != ActiveStatus)
        {
            throw new InvalidOperationException(
                "Enterprise install rollback transaction is no longer active.");
        }
    }

    private void TryDeleteJournal()
    {
        if (!Directory.Exists(_journalRoot))
        {
            return;
        }
        try
        {
            DeleteJournal(_layout, _journalRoot);
        }
        catch (IOException)
        {
            // The inactive authenticated journal is retried by the next Installer.
        }
        catch (UnauthorizedAccessException)
        {
            // The inactive sibling never exposes an executable entrypoint.
        }
    }

    private static void DeleteJournal(
        EnterpriseInstallationLayout layout,
        string journalRoot)
    {
        if (!Directory.Exists(journalRoot))
        {
            return;
        }
        ComputeDirectoryIdentity(journalRoot, layout.LocalAppDataRoot);
        EnterprisePathGuard.DeleteDirectoryTree(journalRoot, layout.LocalAppDataRoot);
    }

    private static bool SamePath(string left, string right) =>
        string.Equals(
            Path.TrimEndingDirectorySeparator(Path.GetFullPath(left)),
            Path.TrimEndingDirectorySeparator(Path.GetFullPath(right)),
            StringComparison.OrdinalIgnoreCase);

    private const uint CryptProtectUiForbidden = 0x1;

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct DataBlob(int length, IntPtr data)
    {
        public readonly int Length = length;
        public readonly IntPtr Data = data;
    }

    [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptProtectData(
        ref DataBlob dataIn,
        string? description,
        ref DataBlob optionalEntropy,
        IntPtr reserved,
        IntPtr prompt,
        uint flags,
        out DataBlob dataOut);

    [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptUnprotectData(
        ref DataBlob dataIn,
        IntPtr description,
        ref DataBlob optionalEntropy,
        IntPtr reserved,
        IntPtr prompt,
        uint flags,
        out DataBlob dataOut);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);

    [JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
    private sealed record DurableState(
        int SchemaVersion,
        string Product,
        string LayoutProfile,
        string ManagedRoot,
        string TransactionId,
        string Status,
        bool ManagedRootExisted,
        IReadOnlyList<DurableEntry> Entries,
        EnterpriseDurableWindowsRegistration? Registration);

    [JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
    private sealed record DurableEntry(
        int Index,
        string Target,
        string Backup,
        bool Existed,
        bool Directory,
        string? ExpectedSha256,
        long ExpectedLength,
        string Phase);

}
