using System.Buffers;
using System.Globalization;
using System.Text.Json;
using System.Text.Encodings.Web;
using System.Text.Json.Serialization;

namespace Ensou.Dsh.Contracts;

public sealed class ManifestFormatException : Exception
{
    public ManifestFormatException(string message)
        : base(message)
    {
    }

    public ManifestFormatException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

public static class ReleaseManifestJson
{
    public const int MaximumManifestBytes = 1024 * 1024;
    public const string CanonicalUtcTimestampFormat = "yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'";

    private static readonly JsonSerializerOptions SerializerOptions = CreateOptions();

    public static ReleaseManifest ParseAndValidate(ReadOnlySpan<byte> json)
    {
        if (json.IsEmpty || json.Length > MaximumManifestBytes)
        {
            throw new ManifestFormatException(
                $"Release manifest must contain between 1 and {MaximumManifestBytes} bytes.");
        }

        RejectDuplicateProperties(json);

        try
        {
            var manifest = JsonSerializer.Deserialize<ReleaseManifest>(json, SerializerOptions)
                ?? throw new ManifestFormatException("Release manifest is JSON null.");
            ReleaseManifestValidator.ValidateAndThrow(manifest);
            return manifest;
        }
        catch (ManifestFormatException)
        {
            throw;
        }
        catch (ManifestValidationException)
        {
            throw;
        }
        catch (JsonException exception)
        {
            throw new ManifestFormatException("Release manifest is not valid schema-v1 JSON.", exception);
        }
    }

    public static byte[] SerializeSigned(ReleaseManifest manifest)
    {
        ReleaseManifestValidator.ValidateAndThrow(manifest);
        return JsonSerializer.SerializeToUtf8Bytes(manifest, SerializerOptions);
    }

    /// <summary>
    /// Creates the exact payload covered by the signature. The signature property is excluded;
    /// fields are emitted in a fixed order as compact UTF-8 JSON, and UTC timestamps use seven
    /// fractional digits followed by Z.
    /// </summary>
    public static byte[] CreateCanonicalPayload(ReleaseManifest manifest)
    {
        var unsigned = manifest with { Signature = null };
        ReleaseManifestValidator.ValidateAndThrow(unsigned, requireSignature: false);

        var output = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(
                   output,
                   new JsonWriterOptions
                   {
                       Indented = false,
                       Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
                   }))
        {
            writer.WriteStartObject();
            writer.WriteNumber("schemaVersion", unsigned.SchemaVersion);
            writer.WriteString("releaseId", unsigned.ReleaseId);
            writer.WriteString("channel", ChannelName(unsigned.Channel));
            writer.WriteString("launcherVersion", unsigned.LauncherVersion);
            writer.WriteString("dshVersion", unsigned.DshVersion);
            writer.WriteString(
                "publishedAtUtc",
                unsigned.PublishedAtUtc.UtcDateTime.ToString(
                    CanonicalUtcTimestampFormat,
                    CultureInfo.InvariantCulture));
            writer.WriteString("minimumBootstrapperVersion", unsigned.MinimumBootstrapperVersion);
            writer.WriteStartObject("artifact");
            writer.WriteString("url", unsigned.Artifact.Url);
            writer.WriteString("fileName", unsigned.Artifact.FileName);
            writer.WriteNumber("sizeBytes", unsigned.Artifact.SizeBytes);
            writer.WriteString("sha256", unsigned.Artifact.Sha256);
            writer.WriteEndObject();
            writer.WriteEndObject();
            writer.Flush();
        }

        return output.WrittenSpan.ToArray();
    }

    private static string ChannelName(ReleaseChannel channel) => channel switch
    {
        ReleaseChannel.Lab => "lab",
        ReleaseChannel.Pilot => "pilot",
        ReleaseChannel.Stable => "stable",
        _ => throw new ManifestValidationException(
            [new ManifestValidationError("$.channel", "enum", "Channel is unknown.")]),
    };

    private static JsonSerializerOptions CreateOptions()
    {
        var options = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            PropertyNameCaseInsensitive = false,
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            NumberHandling = JsonNumberHandling.Strict,
            MaxDepth = 16,
            WriteIndented = false,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        };
        options.Converters.Add(new CanonicalUtcDateTimeOffsetConverter());
        options.Converters.Add(new JsonStringEnumConverter(JsonNamingPolicy.CamelCase, allowIntegerValues: false));
        return options;
    }

    private sealed class CanonicalUtcDateTimeOffsetConverter : JsonConverter<DateTimeOffset>
    {
        public override DateTimeOffset Read(
            ref Utf8JsonReader reader,
            Type typeToConvert,
            JsonSerializerOptions options)
        {
            if (reader.TokenType != JsonTokenType.String ||
                reader.GetString() is not { } value ||
                !DateTimeOffset.TryParseExact(
                    value,
                    CanonicalUtcTimestampFormat,
                    CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                    out var parsed))
            {
                throw new JsonException(
                    "publishedAtUtc must use yyyy-MM-ddTHH:mm:ss.fffffffZ with exactly seven fractional digits.");
            }

            return parsed;
        }

        public override void Write(
            Utf8JsonWriter writer,
            DateTimeOffset value,
            JsonSerializerOptions options) =>
            writer.WriteStringValue(value.UtcDateTime.ToString(
                CanonicalUtcTimestampFormat,
                CultureInfo.InvariantCulture));
    }

    private static void RejectDuplicateProperties(ReadOnlySpan<byte> json)
    {
        try
        {
            using var document = JsonDocument.Parse(
                json.ToArray(),
                new JsonDocumentOptions
                {
                    AllowTrailingCommas = false,
                    CommentHandling = JsonCommentHandling.Disallow,
                    MaxDepth = 16,
                });
            RejectDuplicateProperties(document.RootElement, "$");
            if (document.RootElement.ValueKind == JsonValueKind.Object &&
                document.RootElement.TryGetProperty("publishedAtUtc", out var publishedAt) &&
                publishedAt.ValueKind == JsonValueKind.String &&
                publishedAt.GetString() is { } publishedAtText &&
                !publishedAtText.EndsWith('Z'))
            {
                throw new ManifestFormatException(
                    "Release manifest publishedAtUtc must use the canonical UTC Z suffix.");
            }
        }
        catch (ManifestFormatException)
        {
            throw;
        }
        catch (JsonException exception)
        {
            throw new ManifestFormatException("Release manifest is not valid JSON.", exception);
        }
    }

    private static void RejectDuplicateProperties(JsonElement element, string path)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                {
                    var names = new HashSet<string>(StringComparer.Ordinal);
                    foreach (var property in element.EnumerateObject())
                    {
                        if (!names.Add(property.Name))
                        {
                            throw new ManifestFormatException(
                                $"Release manifest contains duplicate property '{property.Name}' at {path}.");
                        }

                        RejectDuplicateProperties(property.Value, $"{path}.{property.Name}");
                    }

                    break;
                }
            case JsonValueKind.Array:
                {
                    var index = 0;
                    foreach (var item in element.EnumerateArray())
                    {
                        RejectDuplicateProperties(item, $"{path}[{index}]");
                        index++;
                    }

                    break;
                }
        }
    }
}
