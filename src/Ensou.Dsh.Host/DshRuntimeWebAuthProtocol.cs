using System.Text.Json;
using System.Text.Json.Serialization;

namespace Ensou.Dsh.Host;

public enum DshRuntimeWebAuthProtocol
{
    LegacyCleanRootV1 = 0,
    BrowserLaunchCookieV1 = 1,
}

public static class DshRuntimeWebAuthProtocolContract
{
    public const string LegacyCleanRootV1 = "legacy-clean-root-v1";
    public const string BrowserLaunchCookieV1 = "browser-launch-cookie-v1";

    public static string GetName(DshRuntimeWebAuthProtocol protocol) => protocol switch
    {
        DshRuntimeWebAuthProtocol.LegacyCleanRootV1 => LegacyCleanRootV1,
        DshRuntimeWebAuthProtocol.BrowserLaunchCookieV1 => BrowserLaunchCookieV1,
        _ => throw new ArgumentOutOfRangeException(nameof(protocol)),
    };

    internal static DshRuntimeWebAuthProtocol Parse(string value) => value switch
    {
        LegacyCleanRootV1 => DshRuntimeWebAuthProtocol.LegacyCleanRootV1,
        BrowserLaunchCookieV1 => DshRuntimeWebAuthProtocol.BrowserLaunchCookieV1,
        _ => throw new InvalidDataException(
            "The DSH runtime metadata declares an unsupported Web authentication protocol."),
    };
}

/// <summary>
/// Reads the Web authentication contract from the integrity-bound runtime tree.
/// Existing runtimes without this file remain on the legacy clean-root protocol.
/// New protocol behavior therefore requires an explicit immutable artifact input.
/// </summary>
public static class DshRuntimeMetadata
{
    public const int SchemaVersion = 1;
    public const int PersonalManagedUpdateSchemaVersion = 2;
    public const int EnterpriseDirectLocalSchemaVersion = 3;
    public const int MaximumBytes = 4096;
    public const string FileName = "ensou-runtime-metadata.json";
    public const string PersonalManagedUpdateProtocol = "personal-web-v1";
    public const string EnterpriseDirectLocalUpdateProtocol = "enterprise-direct-local-v1";
    public const string EnterpriseDirectLocalProfile = "enterprise-direct-local";

    public static DshRuntimeWebAuthProtocol ReadWebAuthProtocol(string runtimeDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(runtimeDirectory);
        if (!Path.IsPathFullyQualified(runtimeDirectory))
        {
            throw new InvalidDataException("The DSH runtime metadata root must be absolute.");
        }

        return Read(runtimeDirectory).WebAuthProtocol;
    }

    /// <summary>
    /// Returns whether this integrity-bound runtime expressly implements the
    /// Personal Launcher private managed-update bootstrap.
    /// </summary>
    public static bool ReadSupportsPersonalManagedUpdate(string runtimeDirectory) =>
        Read(runtimeDirectory).SupportsPersonalManagedUpdate;

    /// <summary>
    /// A direct-local Host must not infer its reserved profile from an older
    /// gateway or Personal artifact. The signed runtime tree declares it.
    /// </summary>
    public static bool ReadSupportsEnterpriseDirectLocal(string runtimeDirectory) =>
        Read(runtimeDirectory).SupportsEnterpriseDirectLocal;

    private static RuntimeMetadata Read(string runtimeDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(runtimeDirectory);
        if (!Path.IsPathFullyQualified(runtimeDirectory))
        {
            throw new InvalidDataException("The DSH runtime metadata root must be absolute.");
        }

        var root = Path.GetFullPath(runtimeDirectory);
        var path = Path.GetFullPath(Path.Combine(root, FileName));
        if (!string.Equals(Path.GetDirectoryName(path), root, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("The DSH runtime metadata path escaped its runtime root.");
        }
        if (!File.Exists(path))
        {
            return new RuntimeMetadata(DshRuntimeWebAuthProtocol.LegacyCleanRootV1, false);
        }

        var file = new FileInfo(path);
        if ((file.Attributes & FileAttributes.ReparsePoint) != 0
            || file.Length is <= 0 or > MaximumBytes)
        {
            throw new InvalidDataException("The DSH runtime metadata file is not a bounded regular file.");
        }

        byte[] bytes;
        try
        {
            bytes = File.ReadAllBytes(path);
        }
        catch (IOException exception)
        {
            throw new InvalidDataException("The DSH runtime metadata file could not be read.", exception);
        }

        try
        {
            using var document = JsonDocument.Parse(
                bytes,
                new JsonDocumentOptions
                {
                    AllowTrailingCommas = false,
                    CommentHandling = JsonCommentHandling.Disallow,
                    MaxDepth = 8,
            });
            RejectDuplicateProperties(document.RootElement);
            if (!document.RootElement.TryGetProperty("schemaVersion", out var schema)
                || !schema.TryGetInt32(out var schemaVersion))
            {
                throw new InvalidDataException("The DSH runtime metadata schema is invalid.");
            }
            return schemaVersion switch
            {
                SchemaVersion => ReadSchemaV1(bytes),
                PersonalManagedUpdateSchemaVersion => ReadSchemaV2(bytes),
                EnterpriseDirectLocalSchemaVersion => ReadSchemaV3(bytes),
                _ => throw new InvalidDataException("The DSH runtime metadata schema is unsupported."),
            };
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("The DSH runtime metadata JSON is invalid.", exception);
        }
        finally
        {
            Array.Clear(bytes);
        }
    }

    private static RuntimeMetadata ReadSchemaV1(byte[] bytes)
    {
        var metadata = JsonSerializer.Deserialize<RuntimeMetadataV1Document>(bytes)
            ?? throw new InvalidDataException("The DSH runtime metadata is empty.");
        if (metadata.SchemaVersion != SchemaVersion
            || string.IsNullOrWhiteSpace(metadata.WebAuthProtocol))
        {
            throw new InvalidDataException("The DSH runtime metadata contract is invalid.");
        }
        return new RuntimeMetadata(
            DshRuntimeWebAuthProtocolContract.Parse(metadata.WebAuthProtocol),
            false);
    }

    private static RuntimeMetadata ReadSchemaV2(byte[] bytes)
    {
        var metadata = JsonSerializer.Deserialize<RuntimeMetadataV2Document>(bytes)
            ?? throw new InvalidDataException("The DSH runtime metadata is empty.");
        if (metadata.SchemaVersion != PersonalManagedUpdateSchemaVersion
            || !string.Equals(
                metadata.WebAuthProtocol,
                DshRuntimeWebAuthProtocolContract.BrowserLaunchCookieV1,
                StringComparison.Ordinal)
            || !string.Equals(
                metadata.ManagedUpdateProtocol,
                PersonalManagedUpdateProtocol,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException("The Personal managed-update runtime metadata contract is invalid.");
        }
        return new RuntimeMetadata(DshRuntimeWebAuthProtocol.BrowserLaunchCookieV1, true);
    }

    private static RuntimeMetadata ReadSchemaV3(byte[] bytes)
    {
        var metadata = JsonSerializer.Deserialize<RuntimeMetadataV3Document>(bytes)
            ?? throw new InvalidDataException("The DSH runtime metadata is empty.");
        if (metadata.SchemaVersion != EnterpriseDirectLocalSchemaVersion
            || !string.Equals(
                metadata.WebAuthProtocol,
                DshRuntimeWebAuthProtocolContract.BrowserLaunchCookieV1,
                StringComparison.Ordinal)
            || !string.Equals(
                metadata.ManagedUpdateProtocol,
                EnterpriseDirectLocalUpdateProtocol,
                StringComparison.Ordinal)
            || !string.Equals(
                metadata.RuntimeProfile,
                EnterpriseDirectLocalProfile,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "The Enterprise direct-local runtime metadata contract is invalid.");
        }

        return new RuntimeMetadata(
            DshRuntimeWebAuthProtocol.BrowserLaunchCookieV1,
            SupportsPersonalManagedUpdate: false,
            SupportsEnterpriseDirectLocal: true);
    }

    private static void RejectDuplicateProperties(JsonElement element)
    {
        if (element.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException("The DSH runtime metadata must be one JSON object.");
        }

        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in element.EnumerateObject())
        {
            if (!names.Add(property.Name))
            {
                throw new InvalidDataException(
                    "The DSH runtime metadata contains duplicate JSON properties.");
            }
        }
    }

    [JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
    private sealed record RuntimeMetadataV1Document
    {
        [JsonPropertyName("schemaVersion")]
        public required int SchemaVersion { get; init; }

        [JsonPropertyName("webAuthProtocol")]
        public required string WebAuthProtocol { get; init; }
    }

    [JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
    private sealed record RuntimeMetadataV2Document
    {
        [JsonPropertyName("schemaVersion")]
        public required int SchemaVersion { get; init; }

        [JsonPropertyName("webAuthProtocol")]
        public required string WebAuthProtocol { get; init; }

        [JsonPropertyName("managedUpdateProtocol")]
        public required string ManagedUpdateProtocol { get; init; }
    }

    [JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
    private sealed record RuntimeMetadataV3Document
    {
        [JsonPropertyName("schemaVersion")]
        public required int SchemaVersion { get; init; }

        [JsonPropertyName("webAuthProtocol")]
        public required string WebAuthProtocol { get; init; }

        [JsonPropertyName("managedUpdateProtocol")]
        public required string ManagedUpdateProtocol { get; init; }

        [JsonPropertyName("runtimeProfile")]
        public required string RuntimeProfile { get; init; }
    }

    private sealed record RuntimeMetadata(
        DshRuntimeWebAuthProtocol WebAuthProtocol,
        bool SupportsPersonalManagedUpdate,
        bool SupportsEnterpriseDirectLocal = false);
}
