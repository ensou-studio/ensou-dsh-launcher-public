using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Ensou.Dsh.Contracts;

namespace Ensou.Dsh.UpdateEngine;

public sealed record PersonalInstallationIdentity(
    string InstallationId,
    DateTimeOffset CreatedAtUtc,
    string StateBindingSha256,
    string ReceiptSha256);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PersonalInstallationIdentityReceipt
{
    public required int SchemaVersion { get; init; }

    public required string ReceiptType { get; init; }

    public required string Product { get; init; }

    public required string InstallationId { get; init; }

    public required DateTimeOffset CreatedAtUtc { get; init; }

    public required string StateBindingSha256 { get; init; }
}

/// <summary>
/// Owns one path-bound Personal installation identity. The readable receipt is
/// evidence only; the identical DPAPI-protected copy prevents a receipt copied
/// from another Windows user, machine, or managed root from being adopted.
/// Both files live inside the managed root, so an authenticated upgrade keeps
/// the identity while a completed uninstall followed by a clean install gets a
/// new UUID. No token, credential, or private key is stored here.
/// </summary>
public sealed class PersonalInstallationIdentityStore
{
    internal const string IdentityAwareStartupStubVersion = "1.1.0";
    private const int SchemaVersion = 1;
    private const int MaximumDocumentBytes = 64 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        AllowTrailingCommas = false,
        MaxDepth = 16,
        NumberHandling = JsonNumberHandling.Strict,
        PropertyNameCaseInsensitive = false,
        ReadCommentHandling = JsonCommentHandling.Disallow,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        WriteIndented = false,
    };

    private readonly PersonalInstallationLayout _layout;
    private readonly TimeProvider _timeProvider;
    private readonly IPersonalReleaseStateProtector _protector;
    private readonly byte[] _entropy;
    private readonly string _pathBindingSha256;

    public PersonalInstallationIdentityStore(
        PersonalInstallationLayout layout,
        TimeProvider? timeProvider = null)
        : this(
            layout,
            timeProvider ?? TimeProvider.System,
            new WindowsDpapiPersonalReleaseStateProtector())
    {
    }

    internal PersonalInstallationIdentityStore(
        PersonalInstallationLayout layout,
        TimeProvider timeProvider,
        IPersonalReleaseStateProtector protector)
    {
        _layout = layout ?? throw new ArgumentNullException(nameof(layout));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
        _protector = protector ?? throw new ArgumentNullException(nameof(protector));
        _pathBindingSha256 = Sha256(Encoding.UTF8.GetBytes(string.Join(
            '|',
            PersonalReleaseSetContract.Product,
            _layout.ManagedRoot.ToUpperInvariant(),
            _layout.HarnessHome.ToUpperInvariant(),
            "personal-installation-path-binding-v1")));
        _entropy = SHA256.HashData(Encoding.UTF8.GetBytes(string.Join(
            '|',
            PersonalReleaseSetContract.Product,
            _pathBindingSha256,
            "personal-installation-identity-dpapi-v1")));
    }

    public PersonalInstallationIdentity GetOrCreate() =>
        GetOrCreate(
            expectedInstallationId: null,
            expectedReceiptSha256: null,
            existingPointer: new PersonalReleaseSetPointerStore(_layout).TryRead(),
            allowSignedLegacyMigration: false);

    internal PersonalInstallationIdentity GetOrCreateForActivation(
        PersonalInstalledReleaseSetPointer? existingPointer,
        bool allowSignedLegacyMigration) =>
        GetOrCreate(
            expectedInstallationId: null,
            expectedReceiptSha256: null,
            existingPointer,
            allowSignedLegacyMigration);

    private PersonalInstallationIdentity GetOrCreate(
        string? expectedInstallationId,
        string? expectedReceiptSha256,
        PersonalInstalledReleaseSetPointer? existingPointer,
        bool allowSignedLegacyMigration)
    {
        if ((expectedInstallationId is null) != (expectedReceiptSha256 is null))
        {
            throw new InvalidDataException(
                "Personal installation identity expectations must bind both UUID and receipt SHA-256.");
        }
        _layout.EnsureManagedRoots();
        using var writer = AcquireWriter();
        var hasReceipt = File.Exists(_layout.InstallationIdentityReceiptPath);
        var hasProtected = File.Exists(_layout.InstallationIdentityProtectedPath);
        if (hasReceipt || hasProtected)
        {
            if (!hasProtected)
            {
                throw new InvalidDataException(
                    "Personal installation identity has an unauthenticated public receipt only.");
            }
            var protectedReceipt = ReadProtectedReceipt();
            if (!hasReceipt)
            {
                WritePublicReceipt(protectedReceipt);
            }
            var publicReceipt = ReadPublicReceipt();
            RequireEqual(publicReceipt, protectedReceipt);
            return CreateResult(
                publicReceipt,
                expectedInstallationId,
                expectedReceiptSha256);
        }

        if (expectedInstallationId is not null || expectedReceiptSha256 is not null)
        {
            throw new InvalidDataException(
                "Personal release pointer requires installation identity evidence that is missing.");
        }
        if (existingPointer is not null
            && (!allowSignedLegacyMigration
                || existingPointer.Current.HealthState
                    != PersonalReleaseHealthStates.Healthy
                || PersonalReleaseVersion.Compare(
                    existingPointer.Current.StartupStub.MinimumVersion,
                    IdentityAwareStartupStubVersion) >= 0))
        {
            throw new InvalidDataException(
                "Personal managed installation lost its established identity; only a signed pre-1.1 Installer migration may create one for an existing pointer.");
        }

        var installationId = Guid.NewGuid().ToString("D");
        var receipt = new PersonalInstallationIdentityReceipt
        {
            SchemaVersion = SchemaVersion,
            ReceiptType = "ensou-dsh-personal-installation-identity",
            Product = PersonalReleaseSetContract.Product,
            InstallationId = installationId,
            CreatedAtUtc = RequireUtc(_timeProvider.GetUtcNow()),
            StateBindingSha256 = ComputeStateBindingSha256(installationId),
        };
        Validate(receipt);
        WriteProtectedReceipt(receipt);
        WritePublicReceipt(receipt);
        return CreateResult(receipt, null, null);
    }

    public PersonalInstallationIdentity ReadRequired(
        string expectedInstallationId,
        string expectedReceiptSha256)
    {
        RequireCanonicalInstallationId(expectedInstallationId);
        RequireSha256(expectedReceiptSha256, "installation identity receipt");
        _layout.EnsureManagedRoots();
        using var writer = AcquireWriter();
        if (!File.Exists(_layout.InstallationIdentityReceiptPath)
            || !File.Exists(_layout.InstallationIdentityProtectedPath))
        {
            throw new InvalidDataException(
                "Personal installation identity receipt or protected witness is missing.");
        }
        var publicReceipt = ReadPublicReceipt();
        var protectedReceipt = ReadProtectedReceipt();
        RequireEqual(publicReceipt, protectedReceipt);
        return CreateResult(
            publicReceipt,
            expectedInstallationId,
            expectedReceiptSha256);
    }

    internal PersonalInstallationIdentity ReadRequired()
    {
        _layout.EnsureManagedRoots();
        using var writer = AcquireWriter();
        if (!File.Exists(_layout.InstallationIdentityReceiptPath)
            || !File.Exists(_layout.InstallationIdentityProtectedPath))
        {
            throw new InvalidDataException(
                "Personal installation identity receipt or protected witness is missing.");
        }
        var publicReceipt = ReadPublicReceipt();
        var protectedReceipt = ReadProtectedReceipt();
        RequireEqual(publicReceipt, protectedReceipt);
        return CreateResult(publicReceipt, null, null);
    }

    private PersonalInstallationIdentityReceipt ReadPublicReceipt()
    {
        RequireSafeFile(_layout.InstallationIdentityReceiptPath);
        return Parse(ReadBounded(_layout.InstallationIdentityReceiptPath), "public receipt");
    }

    private PersonalInstallationIdentityReceipt ReadProtectedReceipt()
    {
        RequireSafeFile(_layout.InstallationIdentityProtectedPath);
        var protectedBytes = ReadBounded(_layout.InstallationIdentityProtectedPath);
        byte[]? plaintext = null;
        try
        {
            try
            {
                plaintext = _protector.Unprotect(protectedBytes, _entropy);
            }
            catch (CryptographicException exception)
            {
                throw new InvalidDataException(
                    "Personal installation identity is not valid for this Windows user, machine, and managed root.",
                    exception);
            }
            return Parse(plaintext, "protected witness");
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

    private PersonalInstallationIdentityReceipt Parse(
        ReadOnlySpan<byte> bytes,
        string label)
    {
        if (bytes.Length is <= 0 or > MaximumDocumentBytes)
        {
            throw new InvalidDataException(
                $"Personal installation identity {label} size is invalid.");
        }
        try
        {
            RejectDuplicateProperties(bytes, label);
            var receipt = JsonSerializer.Deserialize<PersonalInstallationIdentityReceipt>(
                    bytes,
                    JsonOptions)
                ?? throw new InvalidDataException(
                    $"Personal installation identity {label} is empty.");
            Validate(receipt);
            var canonical = Serialize(receipt);
            if (!bytes.SequenceEqual(canonical))
            {
                throw new InvalidDataException(
                    $"Personal installation identity {label} is not canonical JSON.");
            }
            return receipt;
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException(
                $"Personal installation identity {label} JSON is invalid.",
                exception);
        }
    }

    private void WritePublicReceipt(PersonalInstallationIdentityReceipt receipt) =>
        PersonalReleaseSetPointerStore.WriteFileAtomically(
            _layout.InstallationIdentityReceiptPath,
            Serialize(receipt),
            _layout.ManagedRoot);

    private void WriteProtectedReceipt(PersonalInstallationIdentityReceipt receipt)
    {
        var plaintext = Serialize(receipt);
        byte[]? protectedBytes = null;
        try
        {
            protectedBytes = _protector.Protect(plaintext, _entropy);
            if (protectedBytes.Length is <= 0 or > MaximumDocumentBytes)
            {
                throw new InvalidDataException(
                    "Protected Personal installation identity size is invalid.");
            }
            PersonalReleaseSetPointerStore.WriteFileAtomically(
                _layout.InstallationIdentityProtectedPath,
                protectedBytes,
                _layout.ManagedRoot);
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

    private PersonalInstallationIdentity CreateResult(
        PersonalInstallationIdentityReceipt receipt,
        string? expectedInstallationId,
        string? expectedReceiptSha256)
    {
        var receiptSha256 = Sha256(Serialize(receipt));
        if (expectedInstallationId is not null
            && (!string.Equals(
                    receipt.InstallationId,
                    expectedInstallationId,
                    StringComparison.Ordinal)
                || !string.Equals(
                    receiptSha256,
                    expectedReceiptSha256,
                    StringComparison.Ordinal)))
        {
            throw new InvalidDataException(
                "Personal installation identity does not match the authenticated release pointer.");
        }
        return new PersonalInstallationIdentity(
            receipt.InstallationId,
            receipt.CreatedAtUtc,
            receipt.StateBindingSha256,
            receiptSha256);
    }

    private void Validate(PersonalInstallationIdentityReceipt receipt)
    {
        if (receipt.SchemaVersion != SchemaVersion
            || !string.Equals(
                receipt.ReceiptType,
                "ensou-dsh-personal-installation-identity",
                StringComparison.Ordinal)
            || !string.Equals(
                receipt.Product,
                PersonalReleaseSetContract.Product,
                StringComparison.Ordinal)
            || !string.Equals(
                receipt.StateBindingSha256,
                ComputeStateBindingSha256(receipt.InstallationId),
                StringComparison.Ordinal)
            || receipt.CreatedAtUtc.Offset != TimeSpan.Zero
            || receipt.CreatedAtUtc <= DateTimeOffset.UnixEpoch)
        {
            throw new InvalidDataException(
                "Personal installation identity receipt is invalid.");
        }
        RequireCanonicalInstallationId(receipt.InstallationId);
    }

    private string ComputeStateBindingSha256(string installationId) =>
        Sha256(Encoding.UTF8.GetBytes(string.Join(
            '|',
            PersonalReleaseSetContract.Product,
            _pathBindingSha256,
            installationId,
            "personal-installation-state-binding-v1")));

    private static void RequireEqual(
        PersonalInstallationIdentityReceipt left,
        PersonalInstallationIdentityReceipt right)
    {
        if (!Serialize(left).AsSpan().SequenceEqual(Serialize(right)))
        {
            throw new InvalidDataException(
                "Personal installation identity receipt and protected witness disagree.");
        }
    }

    internal static void RequireCanonicalInstallationId(string? value)
    {
        if (!Guid.TryParseExact(value, "D", out var parsed)
            || parsed == Guid.Empty
            || !string.Equals(parsed.ToString("D"), value, StringComparison.Ordinal)
            || value[14] != '4'
            || value[19] is not ('8' or '9' or 'a' or 'b'))
        {
            throw new InvalidDataException(
                "Personal installationId must be one lowercase canonical random UUID v4.");
        }
    }

    private static void RequireSha256(string? value, string label)
    {
        if (!PersonalReleaseSetValidator.IsSha256(value ?? string.Empty))
        {
            throw new InvalidDataException($"Personal {label} SHA-256 is invalid.");
        }
    }

    private FileStream AcquireWriter() => new(
        Path.Combine(_layout.StateRoot, "personal-installation-identity-writer.lock"),
        FileMode.OpenOrCreate,
        FileAccess.ReadWrite,
        FileShare.None,
        1,
        FileOptions.WriteThrough);

    private void RequireSafeFile(string path)
    {
        if (!File.Exists(path)
            || !PersonalPathGuard.IsStrictDescendant(path, _layout.ManagedRoot)
            || (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException(
                "Personal installation identity file is missing, linked, or escaped its managed root.");
        }
        PersonalPathGuard.RequireSingleLinkFile(path);
    }

    private static byte[] ReadBounded(string path)
    {
        using var input = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            16 * 1024,
            FileOptions.SequentialScan);
        if (input.Length is <= 0 or > MaximumDocumentBytes)
        {
            throw new InvalidDataException(
                "Personal installation identity file size is invalid.");
        }
        var bytes = new byte[input.Length];
        input.ReadExactly(bytes);
        return bytes;
    }

    private static byte[] Serialize(PersonalInstallationIdentityReceipt receipt) =>
        JsonSerializer.SerializeToUtf8Bytes(receipt, JsonOptions);

    private static string Sha256(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexStringLower(SHA256.HashData(bytes));

    private static DateTimeOffset RequireUtc(DateTimeOffset value) =>
        value.Offset == TimeSpan.Zero && value > DateTimeOffset.UnixEpoch
            ? value
            : throw new InvalidDataException(
                "Personal installation identity creation time must be valid UTC.");

    private static void RejectDuplicateProperties(ReadOnlySpan<byte> bytes, string label)
    {
        using var document = JsonDocument.Parse(bytes.ToArray(), new JsonDocumentOptions
        {
            AllowTrailingCommas = false,
            CommentHandling = JsonCommentHandling.Disallow,
            MaxDepth = 32,
        });
        RejectDuplicateProperties(document.RootElement, label);
    }

    private static void RejectDuplicateProperties(JsonElement element, string path)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name))
                {
                    throw new InvalidDataException(
                        $"Personal installation identity contains duplicate property at {path}.");
                }
                RejectDuplicateProperties(property.Value, $"{path}.{property.Name}");
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            var index = 0;
            foreach (var item in element.EnumerateArray())
            {
                RejectDuplicateProperties(item, $"{path}[{index++}]");
            }
        }
    }
}
