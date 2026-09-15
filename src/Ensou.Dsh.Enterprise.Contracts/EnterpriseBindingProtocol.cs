using System.Text.Json.Serialization;

namespace Ensou.Dsh.Enterprise.Contracts;

public sealed record EnterpriseBindingChallenge(
    string SessionId,
    string BindGrant,
    string Challenge,
    DateTimeOffset ExpiresAtUtc)
{
    public override string ToString() => $"Enterprise binding challenge for {SessionId}";
}

public sealed class EnterpriseDeviceBindingCompleteRequest
{
    [JsonPropertyName("schema_version")]
    public int SchemaVersion { get; init; } = 1;

    [JsonPropertyName("binding_payload_version")]
    public int BindingPayloadVersion { get; init; } = 1;

    [JsonPropertyName("bind_grant")]
    public required string BindGrant { get; init; }

    [JsonPropertyName("session_id")]
    public required string SessionId { get; init; }

    [JsonPropertyName("install_id")]
    public required string InstallId { get; init; }

    [JsonPropertyName("device_key_thumbprint")]
    public required string DeviceKeyThumbprint { get; init; }

    [JsonPropertyName("device_label")]
    public required string DeviceLabel { get; init; }

    [JsonPropertyName("binding_challenge")]
    public required string BindingChallenge { get; init; }

    [JsonPropertyName("binding_challenge_expires_at")]
    public required DateTimeOffset BindingChallengeExpiresAtUtc { get; init; }

    [JsonPropertyName("device_signature")]
    public required string DeviceSignature { get; init; }
}

public sealed class EnterpriseDeviceBindingCompleteResponse
{
    [JsonPropertyName("schema_version")]
    public required int SchemaVersion { get; init; }

    [JsonPropertyName("binding_id")]
    public required string BindingId { get; init; }

    [JsonPropertyName("refresh_token")]
    public required string RefreshToken { get; init; }

    [JsonPropertyName("access_token")]
    public required string AccessToken { get; init; }

    [JsonPropertyName("access_token_expires_at")]
    public required DateTimeOffset AccessTokenExpiresAtUtc { get; init; }

    [JsonPropertyName("authorization_lease")]
    public required string AuthorizationLease { get; init; }

    [JsonPropertyName("lease_expires_at")]
    public required DateTimeOffset LeaseExpiresAtUtc { get; init; }

    [JsonPropertyName("server_time")]
    public required DateTimeOffset ServerTimeUtc { get; init; }
}

public sealed class EnterpriseRefreshRequest
{
    [JsonPropertyName("schema_version")]
    public int SchemaVersion { get; init; } = 1;

    [JsonPropertyName("binding_id")]
    public required string BindingId { get; init; }

    [JsonPropertyName("install_id")]
    public required string InstallId { get; init; }

    [JsonPropertyName("previous_lease_id")]
    public required string PreviousLeaseId { get; init; }

    [JsonPropertyName("auth_epoch")]
    public required long AuthorizationEpoch { get; init; }

    [JsonPropertyName("entitlement_epoch")]
    public required long EntitlementEpoch { get; init; }

    [JsonPropertyName("binding_epoch")]
    public required long BindingEpoch { get; init; }
}

public sealed record EnterpriseSignedLeaseEnvelope(
    string CompactJws,
    string ProtectedHeaderSegment,
    string PayloadSegment,
    string SignatureSegment)
{
    public override string ToString() => "Enterprise signed lease envelope [REDACTED]";
}
