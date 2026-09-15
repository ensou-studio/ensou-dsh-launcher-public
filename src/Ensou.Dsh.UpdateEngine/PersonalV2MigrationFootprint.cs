using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Ensou.Dsh.Contracts;

namespace Ensou.Dsh.UpdateEngine;

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PersonalV2MigrationFootprint
{
    public required int SchemaVersion { get; init; }

    public required string Product { get; init; }

    public required string Environment { get; init; }

    public required string StateBindingSha256 { get; init; }

    public required string FirstChannel { get; init; }

    public required string FirstReleaseSetId { get; init; }

    public required long FirstGeneration { get; init; }

    public required long FirstSequence { get; init; }

    public required string FirstManifestSha256 { get; init; }

    public required DateTimeOffset EstablishedAtUtc { get; init; }
}

/// <summary>
/// Persists the one-way transition from legacy runtime-v1 to authenticated
/// release-set v2 independently from the mutable release pointer and state set.
/// DPAPI provides accidental cross-profile isolation and authenticity; it is
/// not a defense against an arbitrary process already running as this user or
/// a local administrator.
/// </summary>
internal sealed class PersonalV2MigrationFootprintStore
{
    private const int SchemaVersion = 1;
    private const int MaximumProtectedBytes = 64 * 1024;
    private const string FootprintDirectoryName = "personal-v2-migration-footprints";
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

    private readonly string _path;
    private readonly string _stateBindingSha256;
    private readonly byte[] _entropy;
    private readonly IPersonalReleaseStateProtector _protector;

    public PersonalV2MigrationFootprintStore(
        string statePath,
        string witnessPath,
        string? footprintPath = null)
    {
        var normalizedStatePath = PersonalPathGuard.NormalizeFilePath(statePath);
        var normalizedWitnessPath = PersonalPathGuard.NormalizeFilePath(witnessPath);
        _path = PersonalPathGuard.NormalizeFilePath(
            footprintPath ?? DerivePath(normalizedStatePath, normalizedWitnessPath));
        if (string.Equals(_path, normalizedStatePath, StringComparison.OrdinalIgnoreCase)
            || string.Equals(_path, normalizedWitnessPath, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "Personal v2 migration footprint must be independent from update state and witness files.");
        }

        _stateBindingSha256 = ComputeStateBinding(normalizedStatePath);
        _entropy = SHA256.HashData(Encoding.UTF8.GetBytes(
            $"{PersonalReleaseSetContract.Product}|{PersonalReleaseSetContract.ProductionEnvironment}|{_stateBindingSha256}|personal-v2-migration-footprint-v1"));
        _protector = new WindowsDpapiPersonalReleaseStateProtector();
    }

    public string Path => _path;

    public static string DerivePath(string statePath, string witnessPath)
    {
        var normalizedStatePath = PersonalPathGuard.NormalizeFilePath(statePath);
        var normalizedWitnessPath = PersonalPathGuard.NormalizeFilePath(witnessPath);
        var witnessParent = System.IO.Path.GetDirectoryName(normalizedWitnessPath)
            ?? throw new InvalidDataException(
                "Personal update security witness has no parent directory.");
        var binding = ComputeStateBinding(normalizedStatePath);
        return PersonalPathGuard.NormalizeFilePath(System.IO.Path.Combine(
            witnessParent,
            FootprintDirectoryName,
            $"personal-v2-{binding[..24]}.dpapi"));
    }

    public static string DeriveIndependentWitnessPath(
        string managedRoot,
        string statePath)
    {
        var normalizedManagedRoot = PersonalPathGuard.NormalizeDirectory(managedRoot);
        var managedParent = System.IO.Path.GetDirectoryName(normalizedManagedRoot)
            ?? throw new InvalidDataException(
                "Personal managed root has no parent directory for its independent security witness.");
        var binding = ComputeStateBinding(statePath);
        return PersonalPathGuard.NormalizeFilePath(System.IO.Path.Combine(
            managedParent,
            ".ensou-dsh-launcher-security",
            $"personal-update-security-{binding[..24]}.witness.dpapi"));
    }

    public PersonalV2MigrationFootprint? TryRead()
    {
        EnsurePathSafe();
        if (!File.Exists(_path))
        {
            return null;
        }

        PersonalPathGuard.RequireSingleLinkFile(_path);
        byte[] protectedBytes;
        using (var input = new FileStream(
            _path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            16 * 1024,
            FileOptions.SequentialScan))
        {
            if (input.Length is <= 0 or > MaximumProtectedBytes)
            {
                throw new InvalidDataException(
                    "Protected personal v2 migration footprint size is invalid.");
            }
            protectedBytes = new byte[input.Length];
            input.ReadExactly(protectedBytes);
        }

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
                    "Personal v2 migration footprint could not be authenticated for this Windows user and installation.",
                    exception);
            }
            if (plaintext.Length is <= 0 or > MaximumProtectedBytes)
            {
                throw new InvalidDataException(
                    "Personal v2 migration footprint plaintext size is invalid.");
            }
            RejectDuplicateProperties(plaintext);
            var footprint = JsonSerializer.Deserialize<PersonalV2MigrationFootprint>(
                plaintext,
                JsonOptions) ?? throw new InvalidDataException(
                    "Personal v2 migration footprint is empty.");
            Validate(footprint);
            return footprint;
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException(
                "Personal v2 migration footprint JSON is invalid.",
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

    public void EnsureEstablished(
        VerifiedPersonalReleaseSetManifest verified,
        DateTimeOffset establishedAtUtc)
    {
        ArgumentNullException.ThrowIfNull(verified);
        var manifest = verified.Manifest;
        EnsureEstablished(new PersonalV2MigrationFootprint
        {
            SchemaVersion = SchemaVersion,
            Product = PersonalReleaseSetContract.Product,
            Environment = PersonalReleaseSetContract.ProductionEnvironment,
            StateBindingSha256 = _stateBindingSha256,
            FirstChannel = manifest.Channel,
            FirstReleaseSetId = manifest.ReleaseSetId,
            FirstGeneration = manifest.Generation,
            FirstSequence = manifest.Sequence,
            FirstManifestSha256 = verified.CanonicalSignedManifestSha256,
            EstablishedAtUtc = establishedAtUtc,
        });
    }

    public void EnsureEstablished(PersonalReleaseSecurityState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        var firstSeen = state.AcceptedReleases
            .OrderBy(release => release.Sequence)
            .ThenBy(release => release.ReleaseSetId, StringComparer.Ordinal)
            .FirstOrDefault() ?? throw new InvalidDataException(
                "Authenticated personal v2 state has no accepted release for its migration footprint.");
        EnsureEstablished(new PersonalV2MigrationFootprint
        {
            SchemaVersion = SchemaVersion,
            Product = PersonalReleaseSetContract.Product,
            Environment = PersonalReleaseSetContract.ProductionEnvironment,
            StateBindingSha256 = _stateBindingSha256,
            FirstChannel = state.Channel,
            FirstReleaseSetId = firstSeen.ReleaseSetId,
            FirstGeneration = firstSeen.Generation,
            FirstSequence = firstSeen.Sequence,
            FirstManifestSha256 = firstSeen.ManifestSha256,
            EstablishedAtUtc = state.TrustedTimeUtc,
        });
    }

    private void EnsureEstablished(PersonalV2MigrationFootprint proposed)
    {
        Validate(proposed);
        var existing = TryRead();
        if (existing is not null)
        {
            return;
        }

        var plaintext = JsonSerializer.SerializeToUtf8Bytes(proposed, JsonOptions);
        byte[]? protectedBytes = null;
        var parent = System.IO.Path.GetDirectoryName(_path)
            ?? throw new InvalidDataException(
                "Personal v2 migration footprint has no parent directory.");
        PersonalPathGuard.EnsureIndependentDirectory(parent);
        var temporaryPath = System.IO.Path.Combine(
            parent,
            $".{System.IO.Path.GetFileName(_path)}.{Guid.NewGuid():N}.tmp");
        try
        {
            protectedBytes = _protector.Protect(plaintext, _entropy);
            if (protectedBytes.Length is <= 0 or > MaximumProtectedBytes)
            {
                throw new InvalidDataException(
                    "Protected personal v2 migration footprint size is invalid.");
            }
            using (var output = new FileStream(
                temporaryPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                16 * 1024,
                FileOptions.WriteThrough))
            {
                output.Write(protectedBytes);
                output.Flush(flushToDisk: true);
            }
            PersonalPathGuard.RequireSingleLinkFile(temporaryPath);
            try
            {
                File.Move(temporaryPath, _path, overwrite: false);
            }
            catch (IOException) when (File.Exists(_path))
            {
                _ = TryRead();
            }
            PersonalPathGuard.RequireSingleLinkFile(_path);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            if (protectedBytes is not null)
            {
                CryptographicOperations.ZeroMemory(protectedBytes);
            }
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }

    private void Validate(PersonalV2MigrationFootprint footprint)
    {
        if (footprint.SchemaVersion != SchemaVersion
            || !string.Equals(
                footprint.Product,
                PersonalReleaseSetContract.Product,
                StringComparison.Ordinal)
            || !string.Equals(
                footprint.Environment,
                PersonalReleaseSetContract.ProductionEnvironment,
                StringComparison.Ordinal)
            || !string.Equals(
                footprint.StateBindingSha256,
                _stateBindingSha256,
                StringComparison.Ordinal)
            || footprint.FirstGeneration is <= 0 or > PersonalReleaseSetContract.MaximumSafeInteger
            || footprint.FirstSequence is <= 0 or > PersonalReleaseSetContract.MaximumSafeInteger
            || !PersonalReleaseSetValidator.IsSha256(footprint.FirstManifestSha256)
            || footprint.EstablishedAtUtc.Offset != TimeSpan.Zero
            || footprint.EstablishedAtUtc <= DateTimeOffset.UnixEpoch)
        {
            throw new InvalidDataException(
                "Personal v2 migration footprint identity or ordering is invalid.");
        }
        PersonalReleaseSetValidator.ValidateChannel(footprint.FirstChannel);
        PersonalReleaseSetValidator.ValidateReleaseId(
            footprint.FirstReleaseSetId,
            "migration footprint releaseSetId");
    }

    private void EnsurePathSafe()
    {
        var parent = System.IO.Path.GetDirectoryName(_path)
            ?? throw new InvalidDataException(
                "Personal v2 migration footprint has no parent directory.");
        PersonalPathGuard.EnsureIndependentDirectory(parent);
        if (File.Exists(_path)
            && (File.GetAttributes(_path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException(
                "Personal v2 migration footprint must not be a filesystem link.");
        }
    }

    private static string ComputeStateBinding(string statePath)
    {
        var normalized = PersonalPathGuard.NormalizeFilePath(statePath)
            .ToUpperInvariant();
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(normalized)));
    }

    private static void RejectDuplicateProperties(byte[] bytes)
    {
        using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions
        {
            AllowTrailingCommas = false,
            CommentHandling = JsonCommentHandling.Disallow,
            MaxDepth = 16,
        });
        RejectDuplicateProperties(document.RootElement, "footprint");
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
                        $"Personal v2 migration {path} has duplicate property '{property.Name}'.");
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
