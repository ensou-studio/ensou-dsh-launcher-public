using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Ensou.Dsh.Enterprise.Installation;

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record EnterpriseReleaseSecurityAnchor(
    int SchemaVersion,
    string Product,
    string Environment,
    long StateRevision,
    string StateCommitId,
    string StateSha256);

/// <summary>
/// Crash-consistent CurrentUser-DPAPI storage for release anti-rollback state.
/// The independent witness detects ordinary deletion, partial restore, and
/// accidental rollback. CurrentUser DPAPI is deliberately not described as a
/// security boundary against arbitrary code already running as the same Windows
/// user; that stronger boundary requires a service identity, machine key/TPM,
/// or administrator-owned ACL outside this user-mode Launcher.
/// </summary>
internal sealed class EnterpriseReleaseSecurityStateProtection
{
    private const int AnchorSchemaVersion = 1;
    private const int MaximumProtectedBytes = 4 * 1024 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        AllowTrailingCommas = false,
        MaxDepth = 64,
        NumberHandling = JsonNumberHandling.Strict,
        PropertyNameCaseInsensitive = false,
        ReadCommentHandling = JsonCommentHandling.Disallow,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        WriteIndented = false,
    };

    private readonly EnterpriseInstallationLayout _layout;
    private readonly byte[] _stateEntropy;
    private readonly byte[] _anchorEntropy;
    private readonly byte[] _witnessEntropy;

    public EnterpriseReleaseSecurityStateProtection(EnterpriseInstallationLayout layout)
    {
        _layout = layout ?? throw new ArgumentNullException(nameof(layout));
        var identity = string.Join(
            '|',
            EnterpriseReleaseSetContract.Product,
            EnterpriseReleaseSetContract.EnvironmentForDevelopmentE2E(layout.IsDevelopmentE2E));
        _stateEntropy = Entropy(identity, "release-security-state-v3");
        _anchorEntropy = Entropy(identity, "release-security-anchor-v1");
        _witnessEntropy = Entropy(identity, "release-security-witness-v1");
    }

    public EnterpriseReleaseFeedState? TryRead()
    {
        EnsurePathsSafe();
        if (File.Exists(_layout.UpdateSecurityPendingAnchorPath))
        {
            RecoverPendingWrite();
        }

        var stateExists = File.Exists(_layout.UpdateSecurityStatePath);
        var anchorExists = File.Exists(_layout.UpdateSecurityAnchorPath);
        var witnessExists = File.Exists(_layout.UpdateSecurityWitnessPath);
        if (!stateExists && !anchorExists && !witnessExists)
        {
            return null;
        }
        if (!stateExists || !anchorExists || !witnessExists)
        {
            throw new InvalidDataException(
                "Enterprise release security state, rollback anchor, or independent witness is missing.");
        }

        var state = ReadState();
        var anchor = ReadAnchor(
            _layout.UpdateSecurityAnchorPath,
            _anchorEntropy,
            "rollback anchor");
        var witness = ReadAnchor(
            _layout.UpdateSecurityWitnessPath,
            _witnessEntropy,
            "independent witness");
        RequireMatchingAnchor(state, anchor);
        RequireMatchingAnchor(state, witness);
        return state;
    }

    public void Write(EnterpriseReleaseFeedState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        EnterpriseReleaseFeedStateStore.ValidatePersistedState(
            _layout,
            state,
            expectedChannel: null);
        var previous = TryRead();
        if (previous is null)
        {
            if (state.StateRevision != 1)
            {
                throw new InvalidDataException(
                    "Enterprise release security state cannot start above revision one.");
            }
        }
        else if (state.StateRevision != checked(previous.StateRevision + 1)
            || state.TrustedTimeUtc < previous.TrustedTimeUtc
            || state.HighestGeneration < previous.HighestGeneration
            || state.HighestSequence < previous.HighestSequence
            || state.MinAcceptedSequence < previous.MinAcceptedSequence
            || previous.RevokedReleaseSetIds.Except(
                state.RevokedReleaseSetIds,
                StringComparer.Ordinal).Any()
            || previous.FailedReleaseQuarantine.Any(failure =>
                !state.FailedReleaseQuarantine.Any(candidate => string.Equals(
                    candidate.ReleaseSetId,
                    failure.ReleaseSetId,
                    StringComparison.Ordinal))))
        {
            throw new InvalidDataException(
                "Enterprise release security state attempted rollback or non-monotonic replacement.");
        }
        _layout.EnsureManagedRoots();
        EnsurePathsSafe();

        var plaintext = JsonSerializer.SerializeToUtf8Bytes(state, JsonOptions);
        var anchor = CreateAnchor(state, plaintext);
        var anchorPlaintext = JsonSerializer.SerializeToUtf8Bytes(anchor, JsonOptions);
        byte[]? protectedState = null;
        byte[]? protectedAnchor = null;
        byte[]? protectedWitness = null;
        try
        {
            protectedState = Protect(plaintext, _stateEntropy);
            protectedAnchor = Protect(anchorPlaintext, _anchorEntropy);
            protectedWitness = Protect(anchorPlaintext, _witnessEntropy);
            ValidateProtectedSize(protectedState, "state");
            ValidateProtectedSize(protectedAnchor, "rollback anchor");
            ValidateProtectedSize(protectedWitness, "independent witness");

            WriteManagedAtomic(
                _layout.UpdateSecurityPendingAnchorPath,
                protectedAnchor);
            WriteManagedAtomic(_layout.UpdateSecurityStatePath, protectedState);
            WriteManagedAtomic(_layout.UpdateSecurityAnchorPath, protectedAnchor);
            WriteWitnessAtomic(protectedWitness);
            File.Delete(_layout.UpdateSecurityPendingAnchorPath);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(anchorPlaintext);
            Zero(protectedState);
            Zero(protectedAnchor);
            Zero(protectedWitness);
        }
    }

    private void RecoverPendingWrite()
    {
        var pending = ReadAnchor(
            _layout.UpdateSecurityPendingAnchorPath,
            _anchorEntropy,
            "pending rollback anchor");
        var state = File.Exists(_layout.UpdateSecurityStatePath) ? ReadState() : null;
        var anchor = File.Exists(_layout.UpdateSecurityAnchorPath)
            ? ReadAnchor(
                _layout.UpdateSecurityAnchorPath,
                _anchorEntropy,
                "rollback anchor")
            : null;
        var witness = File.Exists(_layout.UpdateSecurityWitnessPath)
            ? ReadAnchor(
                _layout.UpdateSecurityWitnessPath,
                _witnessEntropy,
                "independent witness")
            : null;

        if (state is null && anchor is null && witness is null)
        {
            File.Delete(_layout.UpdateSecurityPendingAnchorPath);
            return;
        }

        if (state is not null && AnchorMatchesState(pending, state))
        {
            if ((anchor is not null && anchor.StateRevision > pending.StateRevision)
                || (witness is not null && witness.StateRevision > pending.StateRevision))
            {
                throw new InvalidDataException(
                    "Enterprise pending release-security write is older than an installed witness.");
            }

            var anchorPlaintext = JsonSerializer.SerializeToUtf8Bytes(pending, JsonOptions);
            byte[]? protectedAnchor = null;
            byte[]? protectedWitness = null;
            try
            {
                protectedAnchor = Protect(anchorPlaintext, _anchorEntropy);
                protectedWitness = Protect(anchorPlaintext, _witnessEntropy);
                WriteManagedAtomic(_layout.UpdateSecurityAnchorPath, protectedAnchor);
                WriteWitnessAtomic(protectedWitness);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(anchorPlaintext);
                Zero(protectedAnchor);
                Zero(protectedWitness);
            }
            File.Delete(_layout.UpdateSecurityPendingAnchorPath);
            return;
        }

        if (state is not null
            && anchor is not null
            && witness is not null
            && AnchorMatchesState(anchor, state)
            && AnchorMatchesState(witness, state)
            && state.StateRevision < pending.StateRevision)
        {
            File.Delete(_layout.UpdateSecurityPendingAnchorPath);
            return;
        }

        throw new InvalidDataException(
            "Enterprise pending release-security transaction is inconsistent.");
    }

    private EnterpriseReleaseFeedState ReadState()
    {
        var plaintext = ReadProtected(
            _layout.UpdateSecurityStatePath,
            _stateEntropy,
            "state");
        try
        {
            RejectDuplicateProperties(plaintext, "release security state");
            var state = JsonSerializer.Deserialize<EnterpriseReleaseFeedState>(
                    plaintext,
                    JsonOptions)
                ?? throw new InvalidDataException(
                    "Enterprise release security state is empty.");
            EnterpriseReleaseFeedStateStore.ValidatePersistedState(
                _layout,
                state,
                expectedChannel: null);
            return state;
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException(
                "Enterprise release security state JSON is invalid.",
                exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private EnterpriseReleaseSecurityAnchor ReadAnchor(
        string path,
        byte[] entropy,
        string field)
    {
        var plaintext = ReadProtected(path, entropy, field);
        try
        {
            RejectDuplicateProperties(plaintext, field);
            var anchor = JsonSerializer.Deserialize<EnterpriseReleaseSecurityAnchor>(
                    plaintext,
                    JsonOptions)
                ?? throw new InvalidDataException(
                    $"Enterprise release-security {field} is empty.");
            ValidateAnchor(anchor);
            return anchor;
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException(
                $"Enterprise release-security {field} JSON is invalid.",
                exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private byte[] ReadProtected(string path, byte[] entropy, string field)
    {
        var file = new FileInfo(path);
        if (file.Length is <= 0 or > MaximumProtectedBytes)
        {
            throw new InvalidDataException(
                $"Enterprise protected release-security {field} size is invalid.");
        }
        var protectedBytes = File.ReadAllBytes(path);
        try
        {
            var plaintext = Unprotect(protectedBytes, entropy);
            if (plaintext.Length is <= 0 or > MaximumProtectedBytes)
            {
                CryptographicOperations.ZeroMemory(plaintext);
                throw new InvalidDataException(
                    $"Enterprise release-security {field} plaintext size is invalid.");
            }
            return plaintext;
        }
        catch (CryptographicException exception)
        {
            throw new InvalidDataException(
                $"Enterprise protected release-security {field} could not be authenticated for this Windows user.",
                exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(protectedBytes);
        }
    }

    private EnterpriseReleaseSecurityAnchor CreateAnchor(
        EnterpriseReleaseFeedState state,
        ReadOnlySpan<byte> plaintext)
    {
        var anchor = new EnterpriseReleaseSecurityAnchor(
            AnchorSchemaVersion,
            state.Product,
            state.Environment,
            state.StateRevision,
            state.StateCommitId,
            Convert.ToHexStringLower(SHA256.HashData(plaintext)));
        ValidateAnchor(anchor);
        return anchor;
    }

    private void ValidateAnchor(EnterpriseReleaseSecurityAnchor anchor)
    {
        if (anchor.SchemaVersion != AnchorSchemaVersion
            || !string.Equals(
                anchor.Product,
                EnterpriseReleaseSetContract.Product,
                StringComparison.Ordinal)
            || !string.Equals(
                anchor.Environment,
                EnterpriseReleaseSetContract.EnvironmentForDevelopmentE2E(
                    _layout.IsDevelopmentE2E),
                StringComparison.Ordinal)
            || anchor.StateRevision <= 0
            || !Guid.TryParseExact(anchor.StateCommitId, "N", out _)
            || !EnterpriseHash.IsSha256(anchor.StateSha256))
        {
            throw new InvalidDataException(
                "Enterprise release-security rollback anchor is invalid.");
        }
    }

    private static void RequireMatchingAnchor(
        EnterpriseReleaseFeedState state,
        EnterpriseReleaseSecurityAnchor anchor)
    {
        if (!AnchorMatchesState(anchor, state))
        {
            throw new InvalidDataException(
                "Enterprise release security state does not match its rollback witness.");
        }
    }

    private static bool AnchorMatchesState(
        EnterpriseReleaseSecurityAnchor anchor,
        EnterpriseReleaseFeedState state)
    {
        var plaintext = JsonSerializer.SerializeToUtf8Bytes(state, JsonOptions);
        try
        {
            return anchor.StateRevision == state.StateRevision
                && string.Equals(
                    anchor.StateCommitId,
                    state.StateCommitId,
                    StringComparison.Ordinal)
                && string.Equals(
                    anchor.StateSha256,
                    Convert.ToHexStringLower(SHA256.HashData(plaintext)),
                    StringComparison.Ordinal);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private void EnsurePathsSafe()
    {
        if (File.Exists(_layout.UpdateSecurityStatePath))
        {
            EnterprisePathGuard.ValidateExistingPathWithin(
                _layout.UpdateSecurityStatePath,
                _layout.ManagedRoot,
                requireDirectory: false);
        }
        if (File.Exists(_layout.UpdateSecurityAnchorPath))
        {
            EnterprisePathGuard.ValidateExistingPathWithin(
                _layout.UpdateSecurityAnchorPath,
                _layout.ManagedRoot,
                requireDirectory: false);
        }
        if (File.Exists(_layout.UpdateSecurityPendingAnchorPath))
        {
            EnterprisePathGuard.ValidateExistingPathWithin(
                _layout.UpdateSecurityPendingAnchorPath,
                _layout.ManagedRoot,
                requireDirectory: false);
        }
        if (File.Exists(_layout.UpdateSecurityWitnessPath))
        {
            EnterprisePathGuard.ValidateExistingPathWithin(
                _layout.UpdateSecurityWitnessPath,
                _layout.ReleaseSecurityWitnessRoot,
                requireDirectory: false);
        }
    }

    private void WriteManagedAtomic(string path, ReadOnlySpan<byte> contents) =>
        EnterprisePathGuard.WriteFileAtomically(
            path,
            contents,
            _layout.ManagedRoot);

    private void WriteWitnessAtomic(ReadOnlySpan<byte> contents) =>
        EnterprisePathGuard.WriteFileAtomically(
            _layout.UpdateSecurityWitnessPath,
            contents,
            _layout.ReleaseSecurityWitnessRoot);

    private static byte[] Protect(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> entropy)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "Enterprise release security state requires Windows DPAPI.");
        }
        var plaintextBytes = plaintext.ToArray();
        var entropyBytes = entropy.ToArray();
        try
        {
            return ProtectedData.Protect(
                plaintextBytes,
                entropyBytes,
                DataProtectionScope.CurrentUser);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintextBytes);
            CryptographicOperations.ZeroMemory(entropyBytes);
        }
    }

    private static byte[] Unprotect(
        ReadOnlySpan<byte> protectedBytes,
        ReadOnlySpan<byte> entropy)
    {
        var ciphertext = protectedBytes.ToArray();
        var entropyBytes = entropy.ToArray();
        try
        {
            return ProtectedData.Unprotect(
                ciphertext,
                entropyBytes,
                DataProtectionScope.CurrentUser);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(entropyBytes);
        }
    }

    private static byte[] Entropy(string identity, string purpose) =>
        SHA256.HashData(Encoding.UTF8.GetBytes($"{identity}|{purpose}"));

    private static void ValidateProtectedSize(byte[] value, string field)
    {
        if (value.Length is <= 0 or > MaximumProtectedBytes)
        {
            throw new InvalidDataException(
                $"Enterprise protected release-security {field} size is invalid.");
        }
    }

    private static void RejectDuplicateProperties(ReadOnlySpan<byte> bytes, string field)
    {
        using var document = JsonDocument.Parse(bytes.ToArray(), new JsonDocumentOptions
        {
            AllowTrailingCommas = false,
            CommentHandling = JsonCommentHandling.Disallow,
            MaxDepth = 64,
        });
        RejectDuplicateProperties(document.RootElement, field);
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
                        $"Enterprise {path} has duplicate property '{property.Name}'.");
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

    private static void Zero(byte[]? value)
    {
        if (value is not null)
        {
            CryptographicOperations.ZeroMemory(value);
        }
    }
}
