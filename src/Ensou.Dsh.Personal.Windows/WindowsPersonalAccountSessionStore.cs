using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Ensou.Dsh.Contracts;
using Ensou.Dsh.Personal.Client;

namespace Ensou.Dsh.Personal.Windows;

/// <summary>
/// Stores one installation's online Personal account session under its verified
/// managed state root. It never reads or writes the Harness home.
/// </summary>
public sealed class WindowsPersonalAccountSessionStore : IPersonalAccountSessionStore
{
    private const int SchemaVersion = 1;
    private const int MaximumPlaintextBytes = 16 * 1024;
    private const string Product = "ensou-dsh-personal";
    private const string EntropyDomain = "ensou.dsh.personal.account-session.dpapi.v1";
    private const string StateDirectoryName = "personal-account";
    private const string StateFileName = "session.v1.dpapi";
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        AllowTrailingCommas = false,
        MaxDepth = 8,
        NumberHandling = JsonNumberHandling.Strict,
        PropertyNameCaseInsensitive = false,
        ReadCommentHandling = JsonCommentHandling.Disallow,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        WriteIndented = false,
    };

    private readonly string _stateRoot;
    private readonly string _statePath;
    private readonly Uri _origin;
    private readonly string _installationId;
    private readonly IPersonalAccountDataProtector _protector;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public WindowsPersonalAccountSessionStore(
        string verifiedStateRoot,
        Uri canonicalOrigin,
        string installedInstallationId)
        : this(
            verifiedStateRoot,
            canonicalOrigin,
            installedInstallationId,
            new WindowsCurrentUserPersonalAccountDataProtector())
    {
    }

    internal WindowsPersonalAccountSessionStore(
        string verifiedStateRoot,
        Uri canonicalOrigin,
        string installedInstallationId,
        IPersonalAccountDataProtector protector)
    {
        _stateRoot = RequireLocalStateRoot(verifiedStateRoot);
        _origin = PersonalAccountFormat.RequireOrigin(canonicalOrigin);
        _installationId = PersonalAccountFormat.RequireUuid(installedInstallationId);
        _protector = protector ?? throw new ArgumentNullException(nameof(protector));
        _statePath = Path.Combine(_stateRoot, StateDirectoryName, StateFileName);
    }

    public async Task<PersonalAccountSession?> LoadAsync(
        CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            byte[] protectedBytes;
            try
            {
                protectedBytes = await WindowsLocalStateSecurity.ReadBoundedAsync(
                        _statePath,
                        _stateRoot,
                        cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (FileNotFoundException)
            {
                return null;
            }

            byte[]? entropy = null;
            byte[]? plaintext = null;
            try
            {
                entropy = CreateEntropy();
                plaintext = _protector.Unprotect(protectedBytes, entropy);
                if (plaintext.Length is <= 0 or > MaximumPlaintextBytes)
                {
                    throw InvalidState();
                }

                return ParseCanonical(plaintext);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception) when (IsInvalidPersistedState(exception))
            {
                throw InvalidState(exception);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(protectedBytes);
                Zero(entropy);
                Zero(plaintext);
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task SaveAsync(
        PersonalAccountSession session,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(session);
        var validated = PersonalAccountSessionPersistence.RestoreValidated(
            _origin,
            _installationId,
            session.Origin.AbsoluteUri,
            session.SessionId,
            session.AccountId,
            session.InstallationId,
            session.AccessToken,
            session.RefreshToken,
            session.IssuedAtUtc,
            session.AccessExpiresAtUtc,
            session.RefreshExpiresAtUtc);
        var document = StoredSession.From(validated);
        var plaintext = JsonSerializer.SerializeToUtf8Bytes(document, JsonOptions);
        byte[]? entropy = null;
        byte[]? protectedBytes = null;
        try
        {
            if (plaintext.Length is <= 0 or > MaximumPlaintextBytes)
            {
                throw InvalidState();
            }

            entropy = CreateEntropy();
            protectedBytes = _protector.Protect(plaintext, entropy);
            await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                await WindowsLocalStateSecurity.WriteAtomicAsync(
                        _statePath,
                        _stateRoot,
                        protectedBytes,
                        overwrite: true,
                        cancellationToken)
                    .ConfigureAwait(false);
            }
            finally
            {
                _gate.Release();
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            Zero(entropy);
            Zero(protectedBytes);
        }
    }

    public async Task ClearAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            WindowsLocalStateSecurity.DeleteExactFile(_statePath, _stateRoot);
        }
        finally
        {
            _gate.Release();
        }
    }

    private PersonalAccountSession ParseCanonical(byte[] plaintext)
    {
        using var document = JsonDocument.Parse(
            plaintext.AsMemory(),
            new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 8,
            });
        RequireExactProperties(document.RootElement);
        var stored = JsonSerializer.Deserialize<StoredSession>(plaintext.AsSpan(), JsonOptions)
            ?? throw InvalidState();
        var canonical = JsonSerializer.SerializeToUtf8Bytes(stored, JsonOptions);
        try
        {
            if (!plaintext.SequenceEqual(canonical))
            {
                throw InvalidState();
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(canonical);
        }

        if (stored.SchemaVersion != SchemaVersion
            || !string.Equals(stored.Product, Product, StringComparison.Ordinal))
        {
            throw InvalidState();
        }

        return PersonalAccountSessionPersistence.RestoreValidated(
            _origin,
            _installationId,
            stored.Origin,
            stored.SessionId,
            stored.AccountId,
            stored.InstallationId,
            stored.AccessToken,
            stored.RefreshToken,
            stored.IssuedAtUtc,
            stored.AccessExpiresAtUtc,
            stored.RefreshExpiresAtUtc);
    }

    private static void RequireExactProperties(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object)
        {
            throw InvalidState();
        }

        string[] expected =
        [
            "schemaVersion",
            "product",
            "origin",
            "sessionId",
            "accountId",
            "installationId",
            "accessToken",
            "refreshToken",
            "issuedAtUtc",
            "accessExpiresAtUtc",
            "refreshExpiresAtUtc",
        ];
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in root.EnumerateObject())
        {
            if (!names.Add(property.Name)
                || !expected.Contains(property.Name, StringComparer.Ordinal))
            {
                throw InvalidState();
            }
        }

        if (names.Count != expected.Length)
        {
            throw InvalidState();
        }
    }

    private byte[] CreateEntropy()
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        AppendEntropyField(hash, EntropyDomain);
        AppendEntropyField(hash, Product);
        AppendEntropyField(hash, _origin.AbsoluteUri);
        AppendEntropyField(hash, _installationId);
        AppendEntropyField(hash, _stateRoot.ToUpperInvariant());
        AppendEntropyField(hash, _statePath.ToUpperInvariant());
        return hash.GetHashAndReset();
    }

    private static void AppendEntropyField(IncrementalHash hash, string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        Span<byte> length = stackalloc byte[sizeof(uint)];
        try
        {
            BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)bytes.Length));
            hash.AppendData(length);
            hash.AppendData(bytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
            CryptographicOperations.ZeroMemory(length);
        }
    }

    private static string RequireLocalStateRoot(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        if (!Path.IsPathFullyQualified(value))
        {
            throw new ArgumentException("A verified local Personal state root is required.", nameof(value));
        }

        var full = Path.GetFullPath(value)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (!Path.IsPathFullyQualified(full)
            || full.StartsWith("\\\\", StringComparison.Ordinal)
            || full.StartsWith("//", StringComparison.Ordinal)
            || full.IndexOf(':', 2) >= 0
            || string.Equals(full, Path.GetPathRoot(full), StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("A verified local Personal state root is required.", nameof(value));
        }

        return full;
    }

    private static bool IsInvalidPersistedState(Exception exception) => exception is
        ArgumentException
        or CryptographicException
        or FormatException
        or InvalidDataException
        or JsonException
        or OverflowException;

    private static InvalidDataException InvalidState(Exception? inner = null) =>
        new("Personal account session state is unavailable.", inner);

    private static void Zero(byte[]? bytes)
    {
        if (bytes is not null)
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    [JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
    private sealed record StoredSession
    {
        [JsonPropertyOrder(0)]
        public required int SchemaVersion { get; init; }

        [JsonPropertyOrder(1)]
        public required string Product { get; init; }

        [JsonPropertyOrder(2)]
        public required string Origin { get; init; }

        [JsonPropertyOrder(3)]
        public required string SessionId { get; init; }

        [JsonPropertyOrder(4)]
        public required string AccountId { get; init; }

        [JsonPropertyOrder(5)]
        public required string InstallationId { get; init; }

        [JsonPropertyOrder(6)]
        public required string AccessToken { get; init; }

        [JsonPropertyOrder(7)]
        public required string RefreshToken { get; init; }

        [JsonPropertyOrder(8)]
        public required DateTimeOffset IssuedAtUtc { get; init; }

        [JsonPropertyOrder(9)]
        public required DateTimeOffset AccessExpiresAtUtc { get; init; }

        [JsonPropertyOrder(10)]
        public required DateTimeOffset RefreshExpiresAtUtc { get; init; }

        public static StoredSession From(PersonalAccountSession session) => new()
        {
            SchemaVersion = WindowsPersonalAccountSessionStore.SchemaVersion,
            Product = WindowsPersonalAccountSessionStore.Product,
            Origin = session.Origin.AbsoluteUri,
            SessionId = session.SessionId,
            AccountId = session.AccountId,
            InstallationId = session.InstallationId,
            AccessToken = session.AccessToken,
            RefreshToken = session.RefreshToken,
            IssuedAtUtc = session.IssuedAtUtc,
            AccessExpiresAtUtc = session.AccessExpiresAtUtc,
            RefreshExpiresAtUtc = session.RefreshExpiresAtUtc,
        };
    }
}

internal interface IPersonalAccountDataProtector
{
    byte[] Protect(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> entropy);
    byte[] Unprotect(ReadOnlySpan<byte> protectedBytes, ReadOnlySpan<byte> entropy);
}

internal sealed class WindowsCurrentUserPersonalAccountDataProtector : IPersonalAccountDataProtector
{
    public byte[] Protect(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> entropy)
    {
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

    public byte[] Unprotect(ReadOnlySpan<byte> protectedBytes, ReadOnlySpan<byte> entropy)
    {
        var protectedCopy = protectedBytes.ToArray();
        var entropyBytes = entropy.ToArray();
        try
        {
            return ProtectedData.Unprotect(
                protectedCopy,
                entropyBytes,
                DataProtectionScope.CurrentUser);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(protectedCopy);
            CryptographicOperations.ZeroMemory(entropyBytes);
        }
    }
}
