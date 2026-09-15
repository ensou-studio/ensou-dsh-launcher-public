using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Ensou.Dsh.Enterprise.Installation;

public static class EnterpriseReleasePolicyHandoffContract
{
    public const int SchemaVersion = 1;
    public const string Domain = "ensou-dsh-enterprise-release-policy-handoff-v1";
    public const long MaximumSafeInteger = 9_007_199_254_740_991;
    public static readonly TimeSpan MaximumLifetime = TimeSpan.FromDays(31);

    public static IReadOnlySet<string> Channels { get; } =
        new HashSet<string>(["lab", "pilot", "stable"], StringComparer.Ordinal);
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record EnterpriseReleasePolicyHandoff
{
    public required int SchemaVersion { get; init; }
    public required string Product { get; init; }
    public required string Environment { get; init; }
    public required string Channel { get; init; }
    public required string ReleaseSetId { get; init; }
    public required long Generation { get; init; }
    public required long Sequence { get; init; }
    public required long MinAcceptedSequence { get; init; }
    public required string ManifestSha256 { get; init; }
    public required string PromotionResultSha256 { get; init; }
    public required string PromotionJournalSha256 { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset ExpiresAtUtc { get; init; }
    public required DateTimeOffset GraceUntilUtc { get; init; }
    public required EnterpriseReleaseSignature Signature { get; init; }

    public static EnterpriseReleasePolicyHandoff Parse(ReadOnlySpan<byte> json)
    {
        if (json.Length is <= 0 or > 128 * 1024)
        {
            throw new InvalidDataException("Enterprise release-policy handoff size is invalid.");
        }
        try
        {
            EnterpriseReleaseJson.RequireNoDuplicateMembers(json);
            return JsonSerializer.Deserialize<EnterpriseReleasePolicyHandoff>(
                       json,
                       EnterpriseReleasePolicyHandoffJson.Options)
                   ?? throw new InvalidDataException(
                       "Enterprise release-policy handoff is empty.");
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException(
                "Enterprise release-policy handoff JSON is invalid.",
                exception);
        }
    }

    public static byte[] CanonicalPayload(EnterpriseReleasePolicyHandoff value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return Encoding.UTF8.GetBytes(string.Join(
            '\n',
            EnterpriseReleasePolicyHandoffContract.Domain,
            value.Product,
            value.Environment,
            value.Channel,
            value.ReleaseSetId,
            value.Generation.ToString(CultureInfo.InvariantCulture),
            value.Sequence.ToString(CultureInfo.InvariantCulture),
            value.MinAcceptedSequence.ToString(CultureInfo.InvariantCulture),
            value.ManifestSha256,
            value.PromotionResultSha256,
            value.PromotionJournalSha256,
            FormatTimestamp(value.IssuedAtUtc),
            FormatTimestamp(value.ExpiresAtUtc),
            FormatTimestamp(value.GraceUntilUtc)));
    }

    public void Verify(
        string expectedEnvironment,
        IReadOnlyList<EnterpriseReleasePublicKey> trustedKeys,
        DateTimeOffset nowUtc,
        TimeSpan allowedClockSkew)
    {
        if (allowedClockSkew < TimeSpan.Zero || allowedClockSkew > TimeSpan.FromMinutes(10))
        {
            throw new InvalidDataException(
                "Enterprise release-policy handoff clock skew is invalid.");
        }
        ValidateValues(expectedEnvironment, nowUtc, allowedClockSkew);
        EnterpriseEs256SignatureVerifier.Verify(
            Signature,
            CanonicalPayload(this),
            trustedKeys);
    }

    public void ValidateValues(
        string expectedEnvironment,
        DateTimeOffset nowUtc,
        TimeSpan allowedClockSkew)
    {
        if (SchemaVersion != EnterpriseReleasePolicyHandoffContract.SchemaVersion
            || !string.Equals(Product, EnterpriseReleaseSetContract.Product, StringComparison.Ordinal)
            || expectedEnvironment is not EnterpriseReleaseSetContract.ProductionEnvironment
                and not EnterpriseReleaseSetContract.DevelopmentE2EEnvironment
            || !string.Equals(Environment, expectedEnvironment, StringComparison.Ordinal)
            || !EnterpriseReleasePolicyHandoffContract.Channels.Contains(Channel)
            || Generation is <= 0 or > EnterpriseReleasePolicyHandoffContract.MaximumSafeInteger
            || Sequence is <= 0 or > EnterpriseReleasePolicyHandoffContract.MaximumSafeInteger
            || MinAcceptedSequence is < 0 or > EnterpriseReleasePolicyHandoffContract.MaximumSafeInteger
            || MinAcceptedSequence > Sequence
            || !EnterpriseReleaseValueValidator.IsSha256(ManifestSha256)
            || !EnterpriseReleaseValueValidator.IsSha256(PromotionResultSha256)
            || !EnterpriseReleaseValueValidator.IsSha256(PromotionJournalSha256)
            || !IsWholeSecondUtc(IssuedAtUtc)
            || !IsWholeSecondUtc(ExpiresAtUtc)
            || !IsWholeSecondUtc(GraceUntilUtc)
            || IssuedAtUtc >= ExpiresAtUtc
            || GraceUntilUtc < IssuedAtUtc
            || GraceUntilUtc > ExpiresAtUtc
            || ExpiresAtUtc - IssuedAtUtc > EnterpriseReleasePolicyHandoffContract.MaximumLifetime
            || IssuedAtUtc > nowUtc + allowedClockSkew
            || ExpiresAtUtc <= nowUtc - allowedClockSkew)
        {
            throw new InvalidDataException(
                "Enterprise release-policy handoff identity, ordering, or validity is invalid.");
        }
        EnterpriseReleaseValueValidator.ValidateReleaseId(ReleaseSetId);
    }

    private static bool IsWholeSecondUtc(DateTimeOffset value) =>
        value.Offset == TimeSpan.Zero && value.Ticks % TimeSpan.TicksPerSecond == 0;

    private static string FormatTimestamp(DateTimeOffset value) =>
        value.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);
}

internal static class EnterpriseReleasePolicyHandoffJson
{
    public static JsonSerializerOptions Options { get; } = Create();

    private static JsonSerializerOptions Create()
    {
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web)
        {
            PropertyNameCaseInsensitive = false,
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
            WriteIndented = true,
        };
        options.Converters.Add(new EnterpriseWholeSecondUtcJsonConverter());
        return options;
    }
}

public sealed class EnterpriseWholeSecondUtcJsonConverter
    : JsonConverter<DateTimeOffset>
{
    public override DateTimeOffset Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options)
    {
        var value = reader.TokenType == JsonTokenType.String
            ? reader.GetString()
            : null;
        return value is not null
            && DateTimeOffset.TryParseExact(
                value,
                "yyyy-MM-dd'T'HH:mm:ss'Z'",
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out var parsed)
                ? parsed
                : throw new JsonException(
                    "Enterprise timestamp must be canonical whole-second UTC.");
    }

    public override void Write(
        Utf8JsonWriter writer,
        DateTimeOffset value,
        JsonSerializerOptions options)
    {
        if (value.Offset != TimeSpan.Zero
            || value.Ticks % TimeSpan.TicksPerSecond != 0)
        {
            throw new JsonException(
                "Enterprise timestamp must be canonical whole-second UTC.");
        }
        writer.WriteStringValue(value.ToString(
            "yyyy-MM-dd'T'HH:mm:ss'Z'",
            CultureInfo.InvariantCulture));
    }
}
