using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Ensou.Dsh.Enterprise.Client;

public sealed class EnterprisePendingUpdateReceiptTransaction : IDisposable
{
    private byte[]? _exactRequestBody;

    public EnterprisePendingUpdateReceiptTransaction(
        ReadOnlySpan<byte> exactRequestBody,
        string idempotencyKey,
        DateTimeOffset createdAtUtc,
        DateTimeOffset? acknowledgedAtUtc = null)
    {
        _exactRequestBody = exactRequestBody.ToArray();
        IdempotencyKey = idempotencyKey;
        CreatedAtUtc = createdAtUtc;
        AcknowledgedAtUtc = acknowledgedAtUtc;
        EnterprisePendingUpdateReceiptTransactionStore.ValidateTransaction(
            _exactRequestBody,
            IdempotencyKey,
            CreatedAtUtc,
            AcknowledgedAtUtc);
    }

    public ReadOnlyMemory<byte> ExactRequestBody => _exactRequestBody
        ?? throw new ObjectDisposedException(nameof(EnterprisePendingUpdateReceiptTransaction));

    public string IdempotencyKey { get; }

    public DateTimeOffset CreatedAtUtc { get; }

    public DateTimeOffset? AcknowledgedAtUtc { get; }

    public bool IsAcknowledged => AcknowledgedAtUtc is not null;

    public void Dispose()
    {
        if (_exactRequestBody is null)
        {
            return;
        }

        CryptographicOperations.ZeroMemory(_exactRequestBody);
        _exactRequestBody = null;
    }

    public override string ToString() =>
        "Enterprise pending update receipt transaction [REDACTED]";
}

public interface IEnterprisePendingUpdateReceiptTransactionStore
{
    Task WriteNewAsync(
        ReadOnlyMemory<byte> exactRequestBody,
        string idempotencyKey,
        DateTimeOffset createdAtUtc,
        CancellationToken cancellationToken = default);

    Task<EnterprisePendingUpdateReceiptTransaction?> ReadAsync(
        CancellationToken cancellationToken = default);

    Task MarkAcknowledgedAsync(
        EnterprisePendingUpdateReceiptTransaction transaction,
        DateTimeOffset acknowledgedAtUtc,
        CancellationToken cancellationToken = default);

    void Delete();
}

/// <summary>
/// CurrentUser-DPAPI protects one exact, create-only update receipt request.
/// The file is removed only after the server acknowledges that exact receipt,
/// so a lost response is retried with identical bytes and idempotency key.
/// </summary>
public sealed class EnterprisePendingUpdateReceiptTransactionStore
    : IEnterprisePendingUpdateReceiptTransactionStore
{
    private const int MaximumExactRequestBytes = 64 * 1024;
    private static readonly JsonSerializerOptions StrictJson = new()
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        Converters = { new EnterpriseWholeSecondUtcDateTimeOffsetConverter() },
    };

    private readonly EnterpriseProtectedArtifactStore _protectedStore;

    public EnterprisePendingUpdateReceiptTransactionStore(
        EnterpriseProtectedArtifactStore protectedStore)
    {
        _protectedStore = protectedStore ?? throw new ArgumentNullException(nameof(protectedStore));
    }

    public async Task WriteNewAsync(
        ReadOnlyMemory<byte> exactRequestBody,
        string idempotencyKey,
        DateTimeOffset createdAtUtc,
        CancellationToken cancellationToken = default)
    {
        ValidateTransaction(exactRequestBody, idempotencyKey, createdAtUtc, null);
        var documentBytes = SerializeDocument(
            exactRequestBody,
            idempotencyKey,
            createdAtUtc,
            acknowledgedAtUtc: null);
        try
        {
            await _protectedStore.WriteNewAsync(
                    EnterpriseManagedArtifact.PendingUpdateReceiptTransactionDpapi,
                    documentBytes,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(documentBytes);
        }
    }

    public async Task<EnterprisePendingUpdateReceiptTransaction?> ReadAsync(
        CancellationToken cancellationToken = default)
    {
        var documentBytes = await _protectedStore.ReadAsync(
                EnterpriseManagedArtifact.PendingUpdateReceiptTransactionDpapi,
                cancellationToken)
            .ConfigureAwait(false);
        if (documentBytes is null)
        {
            return null;
        }

        byte[]? exactRequestBody = null;
        try
        {
            EnterpriseStrictJson.ValidateNoDuplicateProperties(documentBytes);
            var document = JsonSerializer.Deserialize<PendingUpdateReceiptDocument>(
                    documentBytes,
                    StrictJson)
                ?? throw new InvalidDataException(
                    "Enterprise pending update receipt transaction is empty.");
            if (document.SchemaVersion != 1)
            {
                throw new InvalidDataException(
                    "Enterprise pending update receipt transaction version is unsupported.");
            }
            if (document.State is not "PENDING" and not "ACKNOWLEDGED"
                || (document.State == "PENDING") != (document.AcknowledgedAtUtc is null))
            {
                throw new InvalidDataException(
                    "Enterprise pending update receipt transaction state is invalid.");
            }

            exactRequestBody = EnterpriseBindingValidation.Base64UrlDecode(
                document.ExactRequestBody,
                "pending_update_receipt.exact_request_body",
                MaximumExactRequestBytes);
            ValidateTransaction(
                exactRequestBody,
                document.IdempotencyKey,
                document.CreatedAtUtc,
                document.AcknowledgedAtUtc);
            var result = new EnterprisePendingUpdateReceiptTransaction(
                exactRequestBody,
                document.IdempotencyKey,
                document.CreatedAtUtc,
                document.AcknowledgedAtUtc);
            return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(documentBytes);
            if (exactRequestBody is not null)
            {
                CryptographicOperations.ZeroMemory(exactRequestBody);
            }
        }
    }

    public async Task MarkAcknowledgedAsync(
        EnterprisePendingUpdateReceiptTransaction transaction,
        DateTimeOffset acknowledgedAtUtc,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(transaction);
        if (transaction.IsAcknowledged)
        {
            throw new InvalidOperationException(
                "Enterprise update receipt transaction is already acknowledged.");
        }
        ValidateTransaction(
            transaction.ExactRequestBody,
            transaction.IdempotencyKey,
            transaction.CreatedAtUtc,
            acknowledgedAtUtc);
        var documentBytes = SerializeDocument(
            transaction.ExactRequestBody,
            transaction.IdempotencyKey,
            transaction.CreatedAtUtc,
            acknowledgedAtUtc);
        try
        {
            await _protectedStore.WriteAsync(
                    EnterpriseManagedArtifact.PendingUpdateReceiptTransactionDpapi,
                    documentBytes,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(documentBytes);
        }
    }

    public void Delete() => _protectedStore.Delete(
        EnterpriseManagedArtifact.PendingUpdateReceiptTransactionDpapi);

    internal static void ValidateTransaction(
        ReadOnlyMemory<byte> exactRequestBody,
        string idempotencyKey,
        DateTimeOffset createdAtUtc,
        DateTimeOffset? acknowledgedAtUtc)
    {
        if (exactRequestBody.IsEmpty || exactRequestBody.Length > MaximumExactRequestBytes)
        {
            throw new InvalidDataException(
                "Enterprise pending update receipt body is empty or too large.");
        }
        EnterpriseBindingValidation.ValidateCanonicalBase64Url(
            idempotencyKey,
            nameof(idempotencyKey),
            32);
        EnterpriseBindingValidation.ValidateCanonicalUtcSecond(
            createdAtUtc,
            nameof(createdAtUtc));
        if (acknowledgedAtUtc is not null)
        {
            EnterpriseBindingValidation.ValidateCanonicalUtcSecond(
                acknowledgedAtUtc.Value,
                nameof(acknowledgedAtUtc));
            if (acknowledgedAtUtc < createdAtUtc)
            {
                throw new InvalidDataException(
                    "Enterprise update receipt acknowledgement predates its durable request.");
            }
        }
        _ = EnterpriseDeviceUpdateManagementClient.DeserializeExactReceipt(exactRequestBody);
    }

    private static byte[] SerializeDocument(
        ReadOnlyMemory<byte> exactRequestBody,
        string idempotencyKey,
        DateTimeOffset createdAtUtc,
        DateTimeOffset? acknowledgedAtUtc) => JsonSerializer.SerializeToUtf8Bytes(
            new PendingUpdateReceiptDocument
            {
                SchemaVersion = 1,
                State = acknowledgedAtUtc is null ? "PENDING" : "ACKNOWLEDGED",
                IdempotencyKey = idempotencyKey,
                ExactRequestBody = EnterpriseBindingValidation.Base64UrlEncode(
                    exactRequestBody.Span),
                CreatedAtUtc = createdAtUtc,
                AcknowledgedAtUtc = acknowledgedAtUtc,
            },
            StrictJson);

    private sealed class PendingUpdateReceiptDocument
    {
        [JsonPropertyName("schema_version")]
        public required int SchemaVersion { get; init; }

        [JsonPropertyName("state")]
        public required string State { get; init; }

        [JsonPropertyName("idempotency_key")]
        public required string IdempotencyKey { get; init; }

        [JsonPropertyName("exact_request_body")]
        public required string ExactRequestBody { get; init; }

        [JsonPropertyName("created_at")]
        public required DateTimeOffset CreatedAtUtc { get; init; }

        [JsonPropertyName("acknowledged_at")]
        public DateTimeOffset? AcknowledgedAtUtc { get; init; }
    }
}
