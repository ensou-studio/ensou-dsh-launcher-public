using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Ensou.Dsh.Contracts;

namespace Ensou.Dsh.Personal.ReleasePublisher;

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record PersonalReleasePublisherArtifactInput
{
    public required string Component { get; init; }

    public required string ReleaseId { get; init; }

    public required Uri Uri { get; init; }

    public required string SourcePath { get; init; }

    public required string CompleteTreeManifestPath { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record PersonalReleasePublisherConfig
{
    public required int SchemaVersion { get; init; }

    public required string Environment { get; init; }

    public required string Channel { get; init; }

    public required string ReleaseSetId { get; init; }

    public required PersonalReleaseProvenance Provenance { get; init; }

    public required long Generation { get; init; }

    public required long Sequence { get; init; }

    public required long MinAcceptedSequence { get; init; }

    public required DateTimeOffset IssuedAtUtc { get; init; }

    public required DateTimeOffset ExpiresAtUtc { get; init; }

    public required long MaximumOfflineGraceSeconds { get; init; }

    public required PersonalStartupStubCompatibility StartupStub { get; init; }

    public required string CertifiedStartupStubVersion { get; init; }

    public required IReadOnlyList<string> RevokedReleaseSetIds { get; init; }

    public required Uri ArtifactOrigin { get; init; }

    public required string SigningKeyId { get; init; }

    public required IReadOnlyList<PersonalReleasePublicKey> TrustedKeys { get; init; }

    public required string SigningPrivateKeyPkcs8Path { get; init; }

    public required string SigningLedgerRoot { get; init; }

    public required string OutputManifestPath { get; init; }

    public required IReadOnlyList<PersonalReleasePublisherArtifactInput> Artifacts { get; init; }

    public static PersonalReleasePublisherConfig Parse(ReadOnlySpan<byte> json)
    {
        if (json.Length is <= 0 or > 512 * 1024)
        {
            throw new InvalidDataException("Personal publisher config size is invalid.");
        }

        try
        {
            using var document = JsonDocument.Parse(json.ToArray(), new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 32,
            });
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                throw new InvalidDataException("Personal publisher config must be one JSON object.");
            }
            RejectDuplicates(document.RootElement, "$");
            return JsonSerializer.Deserialize<PersonalReleasePublisherConfig>(json, JsonOptions)
                ?? throw new InvalidDataException("Personal publisher config is empty.");
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("Personal publisher config JSON is invalid.", exception);
        }
    }

    internal static string ComputeTransactionSha256(
        PersonalReleasePublisherConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);
        var canonical = JsonSerializer.SerializeToUtf8Bytes(config, JsonOptions);
        try
        {
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            hash.AppendData(
                "ensou-personal-release-publisher-config-v1\0"u8);
            hash.AppendData(canonical);
            return Convert.ToHexStringLower(hash.GetHashAndReset());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(canonical);
        }
    }

    internal static PersonalReleasePublisherConfig CaptureTransactionSnapshot(
        PersonalReleasePublisherConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);
        var canonical = JsonSerializer.SerializeToUtf8Bytes(config, JsonOptions);
        try
        {
            return Parse(canonical);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(canonical);
        }
    }

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        AllowTrailingCommas = false,
        MaxDepth = 32,
        NumberHandling = JsonNumberHandling.Strict,
        PropertyNameCaseInsensitive = false,
        ReadCommentHandling = JsonCommentHandling.Disallow,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    private static void RejectDuplicates(JsonElement element, string path)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name))
                {
                    throw new InvalidDataException(
                        $"Personal publisher config contains duplicate property '{property.Name}' at {path}.");
                }
                RejectDuplicates(property.Value, $"{path}.{property.Name}");
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            var index = 0;
            foreach (var item in element.EnumerateArray())
            {
                RejectDuplicates(item, $"{path}[{index++}]");
            }
        }
    }
}
