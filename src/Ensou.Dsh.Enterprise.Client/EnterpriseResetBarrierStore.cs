using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Ensou.Dsh.Enterprise.Contracts;

namespace Ensou.Dsh.Enterprise.Client;

public sealed record EnterpriseResetBarrier(
    EnterpriseAccessDecision Decision,
    bool ResetCompleted)
{
    public override string ToString() => "Enterprise reset barrier [REDACTED]";
}

public sealed class EnterpriseResetBarrierStore
{
    private static readonly JsonSerializerOptions StrictJson = new()
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    private readonly EnterpriseProtectedArtifactStore _protectedStore;

    public EnterpriseResetBarrierStore(EnterpriseProtectedArtifactStore protectedStore)
    {
        _protectedStore = protectedStore ?? throw new ArgumentNullException(nameof(protectedStore));
    }

    public EnterpriseResetBarrier? Read()
    {
        var documentBytes = _protectedStore.ReadAsync(
                EnterpriseManagedArtifact.ResetBarrierDpapi)
            .GetAwaiter()
            .GetResult();
        if (documentBytes is null)
        {
            return null;
        }

        try
        {
            EnterpriseStrictJson.ValidateNoDuplicateProperties(documentBytes);
            var document = JsonSerializer.Deserialize<ResetBarrierDocument>(
                    documentBytes,
                    StrictJson)
                ?? throw new InvalidDataException("Enterprise reset barrier is empty.");
            if (document.SchemaVersion != 1)
            {
                throw new InvalidDataException(
                    "Enterprise reset barrier version is unsupported.");
            }

            var barrier = new EnterpriseResetBarrier(
                new EnterpriseAccessDecision(
                    EnterpriseClientStateContract.ParseWireValue(document.ClientState),
                    MayStartHarness: false,
                    MayCallManagedApi: false,
                    EnterpriseResetScopeContract.ParseWireValue(document.ResetScope),
                    document.ErrorCode),
                document.ResetCompleted);
            Validate(barrier);
            return barrier;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(documentBytes);
        }
    }

    public void Write(EnterpriseResetBarrier barrier)
    {
        Validate(barrier);
        var documentBytes = JsonSerializer.SerializeToUtf8Bytes(
            new ResetBarrierDocument
            {
                SchemaVersion = 1,
                ClientState = EnterpriseClientStateContract.ToWireValue(
                    barrier.Decision.ClientState),
                ResetScope = EnterpriseResetScopeContract.ToWireValue(
                    barrier.Decision.ResetScope),
                ErrorCode = barrier.Decision.ErrorCode!,
                ResetCompleted = barrier.ResetCompleted,
            },
            StrictJson);
        try
        {
            _protectedStore.WriteAsync(
                    EnterpriseManagedArtifact.ResetBarrierDpapi,
                    documentBytes)
                .GetAwaiter()
                .GetResult();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(documentBytes);
        }
    }

    public void Delete() => _protectedStore.Delete(
        EnterpriseManagedArtifact.ResetBarrierDpapi);

    private static void Validate(EnterpriseResetBarrier barrier)
    {
        ArgumentNullException.ThrowIfNull(barrier);
        ArgumentNullException.ThrowIfNull(barrier.Decision);
        var decision = barrier.Decision;
        if (!Enum.IsDefined(decision.ClientState)
            || decision.ClientState is not EnterpriseClientState.AccountLocked
                and not EnterpriseClientState.DeviceRevokedResetRequired
                and not EnterpriseClientState.ApiDisabled
                and not EnterpriseClientState.SecurityQuarantined
            || decision.MayStartHarness
            || decision.MayCallManagedApi
            || decision.ResetScope is not EnterpriseResetScope.ManagedConfig
                and not EnterpriseResetScope.SecurityCredentials
            || string.IsNullOrWhiteSpace(decision.ErrorCode)
            || decision.ErrorCode.Length > 128
            || decision.ErrorCode.Any(character => character is not (
                >= 'A' and <= 'Z' or >= '0' and <= '9' or '_')))
        {
            throw new InvalidDataException(
                "Enterprise reset barrier contains an invalid locked decision.");
        }
    }

    private sealed class ResetBarrierDocument
    {
        [JsonPropertyName("schema_version")]
        public required int SchemaVersion { get; init; }

        [JsonPropertyName("client_state")]
        public required string ClientState { get; init; }

        [JsonPropertyName("reset_scope")]
        public required string ResetScope { get; init; }

        [JsonPropertyName("error_code")]
        public required string ErrorCode { get; init; }

        [JsonPropertyName("reset_completed")]
        public required bool ResetCompleted { get; init; }
    }
}
