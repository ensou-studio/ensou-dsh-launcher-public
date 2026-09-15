using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Ensou.Dsh.Enterprise.Client;

public sealed class EnterprisePendingBindingTransaction : IDisposable
{
    private byte[]? _exactRequestBody;

    internal EnterprisePendingBindingTransaction(
        byte[] exactRequestBody,
        string idempotencyKey,
        DateTimeOffset createdAtUtc)
    {
        _exactRequestBody = exactRequestBody
            ?? throw new ArgumentNullException(nameof(exactRequestBody));
        IdempotencyKey = idempotencyKey;
        CreatedAtUtc = createdAtUtc;
    }

    public ReadOnlyMemory<byte> ExactRequestBody => _exactRequestBody
        ?? throw new ObjectDisposedException(nameof(EnterprisePendingBindingTransaction));

    public string IdempotencyKey { get; }

    public DateTimeOffset CreatedAtUtc { get; }

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
        "Enterprise pending binding transaction [REDACTED]";
}

public sealed class EnterprisePendingBindingTransactionStore
{
    private static readonly JsonSerializerOptions StrictJson = new()
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        Converters = { new EnterpriseWholeSecondUtcDateTimeOffsetConverter() },
    };

    private readonly EnterpriseProtectedArtifactStore _protectedStore;

    public EnterprisePendingBindingTransactionStore(
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
        ValidateTransaction(exactRequestBody, idempotencyKey, createdAtUtc);
        var documentBytes = JsonSerializer.SerializeToUtf8Bytes(
            new PendingBindingDocument
            {
                SchemaVersion = 1,
                IdempotencyKey = idempotencyKey,
                ExactRequestBody = EnterpriseBindingValidation.Base64UrlEncode(
                    exactRequestBody.Span),
                CreatedAtUtc = createdAtUtc,
            },
            StrictJson);
        try
        {
            await _protectedStore.WriteNewAsync(
                    EnterpriseManagedArtifact.PendingBindingTransactionDpapi,
                    documentBytes,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(documentBytes);
        }
    }

    public async Task<EnterprisePendingBindingTransaction?> ReadAsync(
        CancellationToken cancellationToken = default)
    {
        var documentBytes = await _protectedStore.ReadAsync(
                EnterpriseManagedArtifact.PendingBindingTransactionDpapi,
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
            var document = JsonSerializer.Deserialize<PendingBindingDocument>(
                    documentBytes,
                    StrictJson)
                ?? throw new InvalidDataException(
                    "Enterprise pending binding transaction is empty.");
            if (document.SchemaVersion != 1)
            {
                throw new InvalidDataException(
                    "Enterprise pending binding transaction version is unsupported.");
            }

            exactRequestBody = EnterpriseBindingValidation.Base64UrlDecode(
                document.ExactRequestBody,
                "pending_binding.exact_request_body",
                16 * 1024);
            ValidateTransaction(
                exactRequestBody,
                document.IdempotencyKey,
                document.CreatedAtUtc);
            var result = new EnterprisePendingBindingTransaction(
                exactRequestBody,
                document.IdempotencyKey,
                document.CreatedAtUtc);
            exactRequestBody = null;
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

    public void Delete() => _protectedStore.Delete(
        EnterpriseManagedArtifact.PendingBindingTransactionDpapi);

    private static void ValidateTransaction(
        ReadOnlyMemory<byte> exactRequestBody,
        string idempotencyKey,
        DateTimeOffset createdAtUtc)
    {
        EnterpriseBindingValidation.ValidateCanonicalBase64Url(
            idempotencyKey,
            nameof(idempotencyKey),
            32);
        EnterpriseBindingValidation.ValidateCanonicalUtcSecond(
            createdAtUtc,
            nameof(createdAtUtc));
        _ = EnterpriseDeviceBindingClient.DeserializeExactRequest(exactRequestBody);
    }

    private sealed class PendingBindingDocument
    {
        [JsonPropertyName("schema_version")]
        public required int SchemaVersion { get; init; }

        [JsonPropertyName("idempotency_key")]
        public required string IdempotencyKey { get; init; }

        [JsonPropertyName("exact_request_body")]
        public required string ExactRequestBody { get; init; }

        [JsonPropertyName("created_at")]
        public required DateTimeOffset CreatedAtUtc { get; init; }
    }
}
