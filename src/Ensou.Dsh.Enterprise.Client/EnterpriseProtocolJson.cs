using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Ensou.Dsh.Enterprise.Client;

internal sealed class EnterpriseWholeSecondUtcDateTimeOffsetConverter
    : JsonConverter<DateTimeOffset>
{
    private const string WireFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'";

    public override DateTimeOffset Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options)
    {
        if (reader.TokenType != JsonTokenType.String
            || reader.GetString() is not { } value
            || !DateTimeOffset.TryParseExact(
                value,
                WireFormat,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out var parsed))
        {
            throw new JsonException(
                "Enterprise timestamps must use whole-second UTC with an uppercase Z suffix.");
        }

        return parsed;
    }

    public override void Write(
        Utf8JsonWriter writer,
        DateTimeOffset value,
        JsonSerializerOptions options)
    {
        EnterpriseBindingValidation.ValidateCanonicalUtcSecond(value, nameof(value));
        writer.WriteStringValue(value.ToString(WireFormat, CultureInfo.InvariantCulture));
    }
}

internal static class EnterpriseStrictJson
{
    public static void ValidateNoDuplicateProperties(
        ReadOnlyMemory<byte> utf8Json,
        int maximumDepth = 32)
    {
        try
        {
            using var document = JsonDocument.Parse(utf8Json, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = maximumDepth,
            });
            ValidateElement(document.RootElement);
        }
        catch (JsonException)
        {
            throw;
        }
    }

    private static void ValidateElement(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name))
                {
                    throw new JsonException(
                        "Enterprise JSON objects must not contain duplicate properties.");
                }

                ValidateElement(property.Value);
            }

            return;
        }

        if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
            {
                ValidateElement(item);
            }
        }
    }
}
