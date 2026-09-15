using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Ensou.Dsh.Enterprise.Installation;

internal enum EnterpriseUninstallCrashPoint
{
    ManagedRootRenamedBeforePhase,
    RegistrationRemovedBeforePhase,
    CommittedBeforeCleanup,
}

/// <summary>
/// Durable, same-volume uninstall transaction. An uncommitted transaction is
/// always restored to the exact pre-uninstall program and registration state;
/// a committed transaction can only finish removal and quarantine cleanup.
/// </summary>
internal sealed class EnterpriseUninstallRollbackTransaction
{
    private const int SchemaVersion = 1;
    private const string Product = "Ensou.Dsh.Enterprise.UninstallRollback";
    private const string StateFileName = "uninstall-rollback-state.v1.dpapi";
    private const int MaximumStateBytes = 8 * 1024 * 1024;
    private const string ActiveStatus = "active";
    private const string CommittedStatus = "committed";
    private const string RolledBackStatus = "rolled-back";
    private const string PreparedPhase = "prepared";
    private const string QuarantinedPhase = "quarantined";
    private const string RegistrationRemovedPhase = "registration-removed";
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        MaxDepth = 16,
    };

    private readonly EnterpriseInstallationLayout _layout;
    private readonly EnterpriseWindowsRegistrationContext _runtimeRegistrationContext;
    private readonly string _journalRoot;
    private readonly string _statePath;
    private readonly Func<EnterpriseManagedProgramQuarantine, bool>? _deleteQuarantine;
    private readonly Action<EnterpriseUninstallCrashPoint>? _crashPointForTest;
    private DurableState _state;
    private bool _completed;

    public EnterpriseUninstallRollbackTransaction(
        EnterpriseInstallationLayout layout,
        EnterpriseWindowsRegistrationContext registrationContext,
        Func<EnterpriseManagedProgramQuarantine, bool>? deleteQuarantine = null,
        Action<EnterpriseUninstallCrashPoint>? crashPointForTest = null)
    {
        _layout = layout ?? throw new ArgumentNullException(nameof(layout));
        _runtimeRegistrationContext = registrationContext
            ?? throw new ArgumentNullException(nameof(registrationContext));
        _deleteQuarantine = deleteQuarantine;
        _crashPointForTest = crashPointForTest;
        if (!Directory.Exists(layout.ManagedRoot))
        {
            throw new DirectoryNotFoundException(layout.ManagedRoot);
        }

        RequireIndependentDataBoundary(layout);
        _ = EnterpriseMaintenanceIntegrity.RequireActiveMaintenance(layout);
        EnterpriseStableBootstrapperVerifier.RequireTrusted(layout);
        RequireTreeIdentity(layout, layout.ManagedRoot, expectedSha256: null, out var treeSha256);
        EnterpriseMaintenanceOperations.RejectRunningManagedProcesses(layout.ManagedRoot);

        var cleanContext = registrationContext.WithoutObservers();
        var registrationSnapshot = EnterpriseWindowsRegistration.CaptureRollbackSnapshot(
            layout,
            cleanContext);
        var parent = GetManagedRootParent(layout);
        EnterprisePathGuard.EnsureDirectoryChain(layout.LocalAppDataRoot, parent);
        var transactionId = Guid.NewGuid().ToString("N");
        _journalRoot = Path.Combine(parent, GetJournalPrefix(layout) + transactionId);
        _statePath = Path.Combine(_journalRoot, StateFileName);
        var quarantinePath = Path.Combine(parent, GetQuarantinePrefix(layout) + transactionId);
        ValidateJournalPath(layout, _journalRoot, transactionId);
        ValidateQuarantinePath(layout, quarantinePath, transactionId);
        if (Directory.Exists(_journalRoot)
            || File.Exists(_journalRoot)
            || Directory.Exists(quarantinePath)
            || File.Exists(quarantinePath))
        {
            throw new IOException(
                "Enterprise uninstall transaction paths already exist unexpectedly.");
        }

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
            PreparedPhase,
            quarantinePath,
            treeSha256,
            EnterpriseDurableWindowsRegistration.Create(
                cleanContext,
                registrationSnapshot));
        WriteState();
    }

    private EnterpriseUninstallRollbackTransaction(
        EnterpriseInstallationLayout layout,
        string journalRoot,
        DurableState state)
    {
        _layout = layout;
        _journalRoot = journalRoot;
        _statePath = Path.Combine(journalRoot, StateFileName);
        _state = state;
        (_runtimeRegistrationContext, _) = state.Registration.ToRuntime();
    }

    public string QuarantineManagedRoot()
    {
        RequireActive(PreparedPhase);
        RequireTreeIdentity(_layout, _layout.ManagedRoot, _state.TreeSha256, out _);
        EnterpriseMaintenanceOperations.RejectRunningManagedProcesses(_layout.ManagedRoot);
        using (var treeLease = EnterpriseMaintenanceOperations
                   .EnterpriseManagedTreeRenameLease.Acquire(_layout.ManagedRoot))
        {
            EnterpriseMaintenanceOperations.RejectRunningManagedProcesses(_layout.ManagedRoot);
        }

        Directory.Move(_layout.ManagedRoot, _state.QuarantinePath);
        _crashPointForTest?.Invoke(
            EnterpriseUninstallCrashPoint.ManagedRootRenamedBeforePhase);
        if (Directory.Exists(_layout.ManagedRoot)
            || !Directory.Exists(_state.QuarantinePath))
        {
            throw new IOException(
                "Enterprise uninstall quarantine rename did not commit atomically.");
        }
        RequireTreeIdentity(_layout, _state.QuarantinePath, _state.TreeSha256, out _);
        _state = _state with { Phase = QuarantinedPhase };
        WriteState();
        return _state.QuarantinePath;
    }

    public void RemoveRegistration()
    {
        RequireActive(QuarantinedPhase);
        RequireQuarantinedTree();
        EnterpriseWindowsRegistration.Remove(_layout, _runtimeRegistrationContext);
        _crashPointForTest?.Invoke(
            EnterpriseUninstallCrashPoint.RegistrationRemovedBeforePhase);
        _state = _state with { Phase = RegistrationRemovedPhase };
        WriteState();
    }

    public void Commit()
    {
        RequireActive(RegistrationRemovedPhase);
        RequireQuarantinedTree();
        _state = _state with { Status = CommittedStatus };
        WriteState();
        _crashPointForTest?.Invoke(
            EnterpriseUninstallCrashPoint.CommittedBeforeCleanup);
    }

    public bool CompleteCommittedCleanup()
    {
        if (_state.Status != CommittedStatus)
        {
            throw new InvalidOperationException(
                "Enterprise uninstall cleanup requires a committed journal.");
        }
        if (_completed)
        {
            return true;
        }

        // A later trusted install may already have recreated ManagedRoot and
        // its registration. Never remove registration in that case.
        if (!Directory.Exists(_layout.ManagedRoot))
        {
            EnterpriseWindowsRegistration.Remove(
                _layout,
                _runtimeRegistrationContext.WithoutObservers());
        }
        if (Directory.Exists(_state.QuarantinePath))
        {
            try
            {
                RequireTreeIdentity(
                    _layout,
                    _state.QuarantinePath,
                    _state.TreeSha256,
                    out _);
                using var treeLease = EnterpriseMaintenanceOperations
                    .EnterpriseManagedTreeRenameLease.Acquire(_state.QuarantinePath);
                // Opening every entry for DELETE is the no-partial-delete
                // preflight. Content identity was verified immediately above.
            }
            catch (IOException)
            {
                return false;
            }
            catch (UnauthorizedAccessException)
            {
                return false;
            }
            if (!TryDeleteQuarantine())
            {
                return false;
            }
        }
        if (Directory.Exists(_state.QuarantinePath))
        {
            return false;
        }
        _completed = true;
        TryDeleteJournal();
        return true;
    }

    public void Rollback()
    {
        if (_completed)
        {
            return;
        }
        ValidateState(_layout, _journalRoot, _state);
        if (_state.Status == CommittedStatus)
        {
            _ = CompleteCommittedCleanup();
            return;
        }
        if (_state.Status == RolledBackStatus)
        {
            _completed = true;
            TryDeleteJournal();
            return;
        }

        var managedExists = Directory.Exists(_layout.ManagedRoot);
        var quarantineExists = Directory.Exists(_state.QuarantinePath);
        if (managedExists && quarantineExists)
        {
            throw new InvalidDataException(
                "Enterprise uninstall rollback found both active and quarantined program trees.");
        }
        if (!managedExists && !quarantineExists)
        {
            throw new InvalidDataException(
                "Enterprise uninstall rollback cannot find its authenticated program tree.");
        }
        if (quarantineExists)
        {
            RequireTreeIdentity(
                _layout,
                _state.QuarantinePath,
                _state.TreeSha256,
                out _);
            Directory.Move(_state.QuarantinePath, _layout.ManagedRoot);
        }
        RequireTreeIdentity(_layout, _layout.ManagedRoot, _state.TreeSha256, out _);
        var (context, snapshot) = _state.Registration.ToRuntime();
        EnterpriseWindowsRegistration.RestoreRollbackSnapshot(
            _layout,
            context,
            snapshot);
        _state = _state with { Status = RolledBackStatus };
        WriteState();
        _completed = true;
        TryDeleteJournal();
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
        var loaded = new List<EnterpriseUninstallRollbackTransaction>();
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
                    "Enterprise uninstall rollback journal name is invalid.");
            }
            var transactionId = leaf[prefix.Length..];
            ValidateJournalPath(layout, journal, transactionId);
            EnterpriseManagedGcPathSafety.RejectReparse(journal);
            var statePath = Path.Combine(journal, StateFileName);
            if (!File.Exists(statePath))
            {
                RequireEmptyPreStateJournal(journal);
                DeleteJournal(layout, journal);
                continue;
            }
            var state = ReadState(layout, journal, statePath);
            ValidateState(layout, journal, state);
            loaded.Add(new EnterpriseUninstallRollbackTransaction(layout, journal, state));
        }
        if (loaded.Count(value => value._state.Status == ActiveStatus) > 1)
        {
            throw new InvalidDataException(
                "Multiple active Enterprise uninstall rollback journals exist.");
        }
        foreach (var transaction in loaded)
        {
            if (transaction._state.Status == ActiveStatus)
            {
                transaction.Rollback();
            }
            else if (transaction._state.Status == CommittedStatus)
            {
                _ = transaction.CompleteCommittedCleanup();
            }
            else
            {
                transaction._completed = true;
                transaction.TryDeleteJournal();
            }
        }
    }

    internal static IEnumerable<string> FindJournalDirectoriesForTest(
        EnterpriseInstallationLayout layout)
    {
        var parent = GetManagedRootParent(layout);
        return Directory.Exists(parent)
            ? Directory.EnumerateDirectories(
                parent,
                GetJournalPrefix(layout) + "*",
                SearchOption.TopDirectoryOnly)
            : [];
    }

    internal static bool HasPendingJournal(EnterpriseInstallationLayout layout) =>
        FindJournalDirectoriesForTest(layout).Any();

    private void RequireQuarantinedTree()
    {
        if (Directory.Exists(_layout.ManagedRoot)
            || !Directory.Exists(_state.QuarantinePath))
        {
            throw new InvalidDataException(
                "Enterprise uninstall journal is not in its quarantined filesystem state.");
        }
        RequireTreeIdentity(
            _layout,
            _state.QuarantinePath,
            _state.TreeSha256,
            out _);
    }

    private bool TryDeleteQuarantine()
    {
        try
        {
            var quarantine = new EnterpriseManagedProgramQuarantine(
                _state.QuarantinePath);
            var deleted = _deleteQuarantine is null
                ? DeleteQuarantineDirectory(quarantine)
                : _deleteQuarantine(quarantine);
            return deleted && !Directory.Exists(_state.QuarantinePath);
        }
        catch (IOException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static bool DeleteQuarantineDirectory(
        EnterpriseManagedProgramQuarantine quarantine)
    {
        Directory.Delete(quarantine.Directory, recursive: true);
        return !Directory.Exists(quarantine.Directory);
    }

    private void RequireActive(string phase)
    {
        if (_completed
            || _state.Status != ActiveStatus
            || !string.Equals(_state.Phase, phase, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "Enterprise uninstall transaction is not in the required active phase.");
        }
    }

    private void WriteState()
    {
        ValidateState(_layout, _journalRoot, _state);
        var plaintext = JsonSerializer.SerializeToUtf8Bytes(_state, JsonOptions);
        byte[]? protectedBytes = null;
        var temporary = Path.Combine(
            _journalRoot,
            $".uninstall-rollback-state.{Guid.NewGuid():N}.tmp");
        try
        {
            protectedBytes = ProtectCurrentUser(plaintext, GetEntropy(_layout));
            if (protectedBytes.Length > MaximumStateBytes)
            {
                throw new InvalidDataException(
                    "Enterprise uninstall rollback state exceeds its size limit.");
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
            EnterpriseManagedGcPathSafety.RequireSingleLinkFile(
                _statePath,
                _journalRoot);
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
        EnterpriseManagedGcPathSafety.RequireSingleLinkFile(statePath, journalRoot);
        var protectedBytes = File.ReadAllBytes(statePath);
        if (protectedBytes.Length is <= 0 or > MaximumStateBytes)
        {
            throw new InvalidDataException(
                "Enterprise uninstall rollback state size is invalid.");
        }
        byte[]? plaintext = null;
        try
        {
            plaintext = UnprotectCurrentUser(protectedBytes, GetEntropy(layout));
            RejectDuplicateJsonProperties(plaintext);
            return JsonSerializer.Deserialize<DurableState>(plaintext, JsonOptions)
                ?? throw new InvalidDataException(
                    "Enterprise uninstall rollback state is empty.");
        }
        catch (CryptographicException exception)
        {
            throw new InvalidDataException(
                "Enterprise uninstall rollback state authentication failed.",
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
            || state.Phase is not (PreparedPhase or QuarantinedPhase or RegistrationRemovedPhase)
            || state.Status == CommittedStatus && state.Phase != RegistrationRemovedPhase
            || !EnterpriseHash.IsSha256(state.TreeSha256))
        {
            throw new InvalidDataException(
                "Enterprise uninstall rollback state identity is invalid.");
        }
        ValidateJournalPath(layout, journalRoot, state.TransactionId);
        ValidateQuarantinePath(layout, state.QuarantinePath, state.TransactionId);
        state.Registration.Validate(layout);
    }

    private static void RequireTreeIdentity(
        EnterpriseInstallationLayout layout,
        string directory,
        string? expectedSha256,
        out string actualSha256)
    {
        EnterpriseManagedGcPathSafety.ValidateSafeTreeWithSingleLinks(
            directory,
            layout.LocalAppDataRoot);
        var root = EnterprisePathGuard.NormalizeDirectory(directory);
        using var aggregate = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (var child in Directory.EnumerateDirectories(
                     root,
                     "*",
                     SearchOption.AllDirectories)
                 .OrderBy(path => NormalizeRelative(root, path), StringComparer.Ordinal))
        {
            AppendText(aggregate, "D\0" + NormalizeRelative(root, child) + "\0");
        }
        var buffer = new byte[128 * 1024];
        try
        {
            foreach (var file in Directory.EnumerateFiles(
                         root,
                         "*",
                         SearchOption.AllDirectories)
                     .OrderBy(path => NormalizeRelative(root, path), StringComparer.Ordinal))
            {
                EnterpriseManagedGcPathSafety.RequireSingleLinkFile(
                    file,
                    layout.LocalAppDataRoot);
                var info = new FileInfo(file);
                AppendText(
                    aggregate,
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
                    aggregate.AppendData(buffer, 0, read);
                }
                AppendText(aggregate, "\0");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
        actualSha256 = Convert.ToHexStringLower(aggregate.GetHashAndReset());
        if (expectedSha256 is not null
            && !string.Equals(actualSha256, expectedSha256, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Enterprise uninstall program tree identity changed.");
        }
    }

    private static void RequireIndependentDataBoundary(
        EnterpriseInstallationLayout layout)
    {
        if (EnterprisePathGuard.IsSameOrDescendant(layout.HarnessHome, layout.ManagedRoot)
            || EnterprisePathGuard.IsSameOrDescendant(layout.ManagedRoot, layout.HarnessHome)
            || EnterprisePathGuard.IsSameOrDescendant(
                layout.HarnessRecoveryRoot,
                layout.ManagedRoot)
            || EnterprisePathGuard.IsSameOrDescendant(
                layout.ManagedRoot,
                layout.HarnessRecoveryRoot))
        {
            throw new InvalidDataException(
                "Enterprise Harness data/recovery overlaps managed program files.");
        }
    }

    private static void RequireEmptyPreStateJournal(string journalRoot)
    {
        foreach (var entry in Directory.EnumerateFileSystemEntries(
                     journalRoot,
                     "*",
                     SearchOption.TopDirectoryOnly))
        {
            EnterpriseManagedGcPathSafety.RejectReparse(entry);
            var leaf = Path.GetFileName(entry);
            if (Directory.Exists(entry)
                || !leaf.StartsWith(".uninstall-rollback-state.", StringComparison.Ordinal)
                || !leaf.EndsWith(".tmp", StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Enterprise pre-state uninstall journal contains unexpected data.");
            }
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
            // An inactive authenticated journal is retried by the next
            // operation that acquires the shared operation lease.
        }
        catch (UnauthorizedAccessException)
        {
            // The inactive sibling contains no executable entrypoint.
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
        EnterpriseManagedGcPathSafety.ValidateSafeTreeWithSingleLinks(
            journalRoot,
            layout.LocalAppDataRoot);
        Directory.Delete(journalRoot, recursive: true);
    }

    private static string GetManagedRootParent(EnterpriseInstallationLayout layout) =>
        Path.GetDirectoryName(layout.ManagedRoot)
        ?? throw new InvalidDataException(
            "Enterprise ManagedRoot has no parent for the uninstall journal.");

    private static string GetJournalPrefix(EnterpriseInstallationLayout layout) =>
        $".{Path.GetFileName(layout.ManagedRoot)}.uninstall-rollback-";

    private static string GetQuarantinePrefix(EnterpriseInstallationLayout layout) =>
        $".{Path.GetFileName(layout.ManagedRoot)}.uninstall-quarantine-";

    private static void ValidateJournalPath(
        EnterpriseInstallationLayout layout,
        string path,
        string transactionId)
    {
        var expected = Path.Combine(
            GetManagedRootParent(layout),
            GetJournalPrefix(layout) + transactionId);
        if (!SamePath(path, expected)
            || !EnterprisePathGuard.IsSameOrDescendant(path, layout.LocalAppDataRoot))
        {
            throw new InvalidDataException(
                "Enterprise uninstall journal escaped its exact sibling boundary.");
        }
    }

    private static void ValidateQuarantinePath(
        EnterpriseInstallationLayout layout,
        string path,
        string transactionId)
    {
        var expected = Path.Combine(
            GetManagedRootParent(layout),
            GetQuarantinePrefix(layout) + transactionId);
        if (!SamePath(path, expected)
            || !EnterprisePathGuard.IsSameOrDescendant(path, layout.LocalAppDataRoot))
        {
            throw new InvalidDataException(
                "Enterprise uninstall quarantine escaped its exact sibling boundary.");
        }
    }

    private static bool SamePath(string left, string right) =>
        string.Equals(
            Path.TrimEndingDirectorySeparator(Path.GetFullPath(left)),
            Path.TrimEndingDirectorySeparator(Path.GetFullPath(right)),
            StringComparison.OrdinalIgnoreCase);

    private static string NormalizeRelative(string root, string path) =>
        Path.GetRelativePath(root, path).Replace('\\', '/');

    private static void AppendText(IncrementalHash hash, string value) =>
        hash.AppendData(Encoding.UTF8.GetBytes(value));

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
                            "Enterprise uninstall rollback JSON object nesting is invalid.");
                    }
                    _ = objects.Pop();
                    break;
                case JsonTokenType.PropertyName:
                    if (objects.Count == 0
                        || !objects.Peek().Add(reader.GetString()!))
                    {
                        throw new InvalidDataException(
                            "Enterprise uninstall rollback JSON contains a duplicate property.");
                    }
                    break;
            }
        }
        if (objects.Count != 0)
        {
            throw new InvalidDataException(
                "Enterprise uninstall rollback JSON nesting is incomplete.");
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
                "Enterprise uninstall rollback authentication requires Windows DPAPI.");
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
                    "Windows DPAPI could not transform Enterprise uninstall rollback state.",
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
        string Phase,
        string QuarantinePath,
        string TreeSha256,
        EnterpriseDurableWindowsRegistration Registration);
}
