using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Ensou.Dsh.Enterprise.Contracts;

public sealed class EnterpriseEcPublicJwk
{
    [JsonPropertyName("kty")]
    public required string KeyType { get; init; }

    [JsonPropertyName("crv")]
    public required string Curve { get; init; }

    [JsonPropertyName("x")]
    public required string X { get; init; }

    [JsonPropertyName("y")]
    public required string Y { get; init; }
}

public static class EnterpriseQrProtocol
{
    public const string ConfirmationCodeAlphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ";

    public const int ActivationCodeByteLength = 32;

    public const int ActivationCodeLength = 43;

    public static string NormalizeDeviceDisplayName(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        var source = value.Normalize(NormalizationForm.FormC).Trim();
        var builder = new StringBuilder(source.Length);
        var previousWasSpace = false;
        var runeCount = 0;
        foreach (var rune in source.EnumerateRunes())
        {
            runeCount++;
            var category = Rune.GetUnicodeCategory(rune);
            if (category is UnicodeCategory.Control
                or UnicodeCategory.Format
                or UnicodeCategory.Surrogate
                or UnicodeCategory.PrivateUse
                or UnicodeCategory.LineSeparator
                or UnicodeCategory.ParagraphSeparator)
            {
                throw new ArgumentException(
                    "Device display name contains unsafe characters.",
                    nameof(value));
            }

            if (Rune.IsWhiteSpace(rune))
            {
                if (!previousWasSpace)
                {
                    builder.Append(' ');
                    previousWasSpace = true;
                }

                continue;
            }

            previousWasSpace = false;
            builder.Append(rune.ToString());
        }

        var normalized = builder.ToString().Trim();
        if (normalized.Length is 0 or > 80 || runeCount > 64)
        {
            throw new ArgumentException(
                "Device display name must be between 1 and 64 visible characters.",
                nameof(value));
        }

        return normalized;
    }

    public static void ValidateConfirmationCode(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        if (value.Length != 6
            || value.Any(character => !ConfirmationCodeAlphabet.Contains(character)))
        {
            throw new ArgumentException("Confirmation code is invalid.", nameof(value));
        }
    }

    public static void ValidateActivationCode(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        if (value.Length != ActivationCodeLength
            || value.Any(character => !char.IsAsciiLetterOrDigit(character)
                && character is not '-' and not '_'))
        {
            throw new ArgumentException(
                "Activation code must be canonical unpadded base64url for 32 bytes.",
                nameof(value));
        }

        byte[] decoded;
        try
        {
            decoded = Convert.FromBase64String(
                value.Replace('-', '+').Replace('_', '/') + "=");
        }
        catch (FormatException exception)
        {
            throw new ArgumentException(
                "Activation code must be canonical unpadded base64url for 32 bytes.",
                nameof(value),
                exception);
        }

        try
        {
            var canonical = Convert.ToBase64String(decoded)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
            if (decoded.Length != ActivationCodeByteLength
                || !string.Equals(canonical, value, StringComparison.Ordinal))
            {
                throw new ArgumentException(
                    "Activation code must be canonical unpadded base64url for 32 bytes.",
                    nameof(value));
            }
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(decoded);
        }
    }
}

public sealed class EnterpriseActivationClaimRequest
{
    [JsonPropertyName("schema_version")]
    public int SchemaVersion { get; init; } = 1;

    [JsonPropertyName("session_id")]
    public required string SessionId { get; init; }

    [JsonPropertyName("activation_code")]
    public required string ActivationCode { get; init; }

    public override string ToString() => "Enterprise activation claim [REDACTED]";
}

public sealed class EnterpriseQrSessionCreateRequest
{
    [JsonPropertyName("schema_version")]
    public int SchemaVersion { get; init; } = 2;

    [JsonPropertyName("authorization_method")]
    [JsonConverter(typeof(EnterpriseEnrollmentAuthorizationMethodJsonConverter))]
    public required EnterpriseEnrollmentAuthorizationMethod AuthorizationMethod { get; init; }

    [JsonPropertyName("install_id")]
    public required string InstallId { get; init; }

    [JsonPropertyName("device_jwk")]
    public required EnterpriseEcPublicJwk DeviceJwk { get; init; }

    [JsonPropertyName("device_key_thumbprint")]
    public required string DeviceKeyThumbprint { get; init; }

    [JsonPropertyName("device_display_name")]
    public required string DeviceDisplayName { get; init; }

    [JsonPropertyName("launcher_version")]
    public required string LauncherVersion { get; init; }

    [JsonPropertyName("runtime_version")]
    public required string RuntimeVersion { get; init; }

    [JsonPropertyName("platform")]
    public required string Platform { get; init; }

    [JsonPropertyName("nonce")]
    public required string Nonce { get; init; }
}

public sealed class EnterpriseQrSessionCreateResponse
{
    [JsonPropertyName("session_id")]
    public required string SessionId { get; init; }

    [JsonPropertyName("poll_secret")]
    public required string PollSecret { get; init; }

    [JsonPropertyName("authorization_url")]
    public required Uri AuthorizationUrl { get; init; }

    [JsonPropertyName("device_display_name")]
    public required string DeviceDisplayName { get; init; }

    [JsonPropertyName("confirmation_code")]
    public required string ConfirmationCode { get; init; }

    [JsonPropertyName("expires_at")]
    public required DateTimeOffset ExpiresAtUtc { get; init; }

    [JsonPropertyName("poll_after_seconds")]
    public required int PollAfterSeconds { get; init; }

    public override string ToString() =>
        $"QR session {SessionId}, expires {ExpiresAtUtc:O}";
}

public sealed class EnterpriseQrSessionPollResponse
{
    [JsonPropertyName("status")]
    [JsonConverter(typeof(QrSessionStateJsonConverter))]
    public required QrSessionState Status { get; init; }

    [JsonPropertyName("poll_after_seconds")]
    public int? PollAfterSeconds { get; init; }

    [JsonPropertyName("bind_grant")]
    public string? BindGrant { get; init; }

    [JsonPropertyName("binding_challenge")]
    public string? BindingChallenge { get; init; }

    [JsonPropertyName("binding_challenge_expires_at")]
    public DateTimeOffset? BindingChallengeExpiresAtUtc { get; init; }

    [JsonPropertyName("error")]
    public EnterpriseApiError? Error { get; init; }

    public EnterpriseBindingChallenge ToBindingChallenge(string sessionId) => new(
        sessionId,
        BindGrant ?? throw new InvalidOperationException("QR response has no bind grant."),
        BindingChallenge ?? throw new InvalidOperationException("QR response has no binding challenge."),
        BindingChallengeExpiresAtUtc
            ?? throw new InvalidOperationException("QR response has no binding challenge expiry."));

    public override string ToString() => $"QR session state {Status}";
}

public sealed class EnterpriseApiError
{
    [JsonPropertyName("code")]
    public required string Code { get; init; }

    [JsonPropertyName("message")]
    public required string Message { get; init; }

    [JsonPropertyName("client_state")]
    [JsonConverter(typeof(EnterpriseClientStateJsonConverter))]
    public required EnterpriseClientState ClientState { get; init; }

    [JsonPropertyName("retryable")]
    public required bool Retryable { get; init; }

    [JsonPropertyName("contact_display")]
    public string? ContactDisplay { get; init; }

    [JsonPropertyName("request_id")]
    public required string RequestId { get; init; }

    [JsonPropertyName("reset_scope")]
    [JsonConverter(typeof(EnterpriseResetScopeJsonConverter))]
    public required EnterpriseResetScope ResetScope { get; init; }

    public override string ToString() => $"{Code} ({RequestId})";
}

public sealed class EnterpriseErrorEnvelope
{
    [JsonPropertyName("error")]
    public required EnterpriseApiError Error { get; init; }
}

public sealed class QrSessionStateJsonConverter : JsonConverter<QrSessionState>
{
    public override QrSessionState Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options) =>
        QrSessionStateContract.ParseWireValue(
            reader.GetString() ?? throw new JsonException("QR state must be a string."));

    public override void Write(
        Utf8JsonWriter writer,
        QrSessionState value,
        JsonSerializerOptions options) =>
        writer.WriteStringValue(QrSessionStateContract.ToWireValue(value));
}

public sealed class EnterpriseEnrollmentAuthorizationMethodJsonConverter
    : JsonConverter<EnterpriseEnrollmentAuthorizationMethod>
{
    public override EnterpriseEnrollmentAuthorizationMethod Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options) =>
        EnterpriseEnrollmentAuthorizationMethodContract.ParseWireValue(
            reader.GetString()
                ?? throw new JsonException("Enrollment authorization method must be a string."));

    public override void Write(
        Utf8JsonWriter writer,
        EnterpriseEnrollmentAuthorizationMethod value,
        JsonSerializerOptions options) =>
        writer.WriteStringValue(
            EnterpriseEnrollmentAuthorizationMethodContract.ToWireValue(value));
}

public sealed class EnterpriseClientStateJsonConverter : JsonConverter<EnterpriseClientState>
{
    public override EnterpriseClientState Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options) =>
        EnterpriseClientStateContract.ParseWireValue(
            reader.GetString() ?? throw new JsonException("Client state must be a string."));

    public override void Write(
        Utf8JsonWriter writer,
        EnterpriseClientState value,
        JsonSerializerOptions options) =>
        writer.WriteStringValue(EnterpriseClientStateContract.ToWireValue(value));
}

public sealed class EnterpriseResetScopeJsonConverter : JsonConverter<EnterpriseResetScope>
{
    public override EnterpriseResetScope Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options) =>
        EnterpriseResetScopeContract.ParseWireValue(
            reader.GetString() ?? throw new JsonException("Reset scope must be a string."));

    public override void Write(
        Utf8JsonWriter writer,
        EnterpriseResetScope value,
        JsonSerializerOptions options) =>
        writer.WriteStringValue(EnterpriseResetScopeContract.ToWireValue(value));
}
