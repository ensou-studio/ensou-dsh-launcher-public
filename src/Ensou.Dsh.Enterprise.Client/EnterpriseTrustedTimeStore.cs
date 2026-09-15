using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Ensou.Dsh.Enterprise.Client;

/// <summary>
/// Persists the latest UTC value at which a signed enterprise lease was allowed.
/// The value is installation-local security state, not employee workspace data.
/// </summary>
public sealed class EnterpriseTrustedTimeStore
{
    private static readonly JsonSerializerOptions StrictJson = new()
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    private readonly EnterpriseProtectedArtifactStore _protectedStore;
    private readonly object _sync = new();

    public EnterpriseTrustedTimeStore(EnterpriseProtectedArtifactStore protectedStore)
    {
        _protectedStore = protectedStore ?? throw new ArgumentNullException(nameof(protectedStore));
    }

    public DateTimeOffset? ReadFloorUtc()
    {
        lock (_sync)
        {
            return ReadCore();
        }
    }

    public DateTimeOffset Advance(
        DateTimeOffset observedUtc,
        DateTimeOffset signedLeaseDeadlineUtc)
    {
        var canonicalObservedUtc = FloorToUtcSecond(observedUtc, nameof(observedUtc));
        var canonicalDeadlineUtc = RequireCanonicalUtcSecond(
            signedLeaseDeadlineUtc,
            nameof(signedLeaseDeadlineUtc));
        if (canonicalObservedUtc >= canonicalDeadlineUtc)
        {
            throw new InvalidDataException(
                "Enterprise trusted time cannot advance at or beyond the signed lease deadline.");
        }

        lock (_sync)
        {
            var existing = ReadCore();
            if (existing is { } existingUtc && existingUtc >= canonicalObservedUtc)
            {
                return existingUtc;
            }

            WriteCore(canonicalObservedUtc);
            return canonicalObservedUtc;
        }
    }

    /// <summary>
    /// Reconciles the local floor only after a newly verified server response has
    /// been durably committed. A verified response may repair a floor left ahead
    /// by a temporary future wall clock; an unaccepted local clock can only raise
    /// the floor to authenticated server time.
    /// </summary>
    public DateTimeOffset ReconcileVerifiedServerTime(
        DateTimeOffset serverTimeUtc,
        DateTimeOffset observedUtc,
        DateTimeOffset signedLeaseDeadlineUtc,
        bool localClockAccepted)
    {
        var canonicalServerUtc = RequireCanonicalUtcSecond(
            serverTimeUtc,
            nameof(serverTimeUtc));
        var canonicalObservedUtc = FloorToUtcSecond(observedUtc, nameof(observedUtc));
        var canonicalDeadlineUtc = RequireCanonicalUtcSecond(
            signedLeaseDeadlineUtc,
            nameof(signedLeaseDeadlineUtc));
        if (canonicalServerUtc >= canonicalDeadlineUtc
            || (localClockAccepted
                && (canonicalObservedUtc < canonicalServerUtc
                    || canonicalObservedUtc >= canonicalDeadlineUtc)))
        {
            throw new InvalidDataException(
                "Enterprise verified time is outside its signed lease interval.");
        }

        lock (_sync)
        {
            var existing = ReadCore();
            DateTimeOffset reconciled;
            if (!localClockAccepted)
            {
                reconciled = existing is { } existingUtc && existingUtc > canonicalServerUtc
                    ? existingUtc
                    : canonicalServerUtc;
            }
            else if (existing is { } futureUtc && futureUtc > canonicalObservedUtc)
            {
                // Only a newly verified and committed server response can lower a
                // future-skewed local floor. This prevents a future clock from
                // permanently denying later valid leases while keeping offline
                // rollback attempts fail-closed.
                reconciled = canonicalObservedUtc;
            }
            else
            {
                reconciled = existing is { } existingUtc && existingUtc > canonicalObservedUtc
                    ? existingUtc
                    : canonicalObservedUtc;
            }

            if (existing != reconciled)
            {
                WriteCore(reconciled);
            }

            return reconciled;
        }
    }

    public void Delete() => _protectedStore.Delete(
        EnterpriseManagedArtifact.TrustedTimeHighWaterDpapi);

    private DateTimeOffset? ReadCore()
    {
        var documentBytes = _protectedStore.ReadAsync(
                EnterpriseManagedArtifact.TrustedTimeHighWaterDpapi)
            .GetAwaiter()
            .GetResult();
        if (documentBytes is null)
        {
            return null;
        }

        try
        {
            TrustedTimeDocument document;
            try
            {
                EnterpriseStrictJson.ValidateNoDuplicateProperties(documentBytes);
                document = JsonSerializer.Deserialize<TrustedTimeDocument>(
                        documentBytes,
                        StrictJson)
                    ?? throw new InvalidDataException(
                        "Enterprise trusted-time state is empty.");
            }
            catch (JsonException exception)
            {
                throw new InvalidDataException(
                    "Enterprise trusted-time state is malformed.",
                    exception);
            }

            if (document.SchemaVersion != 1)
            {
                throw new InvalidDataException(
                    "Enterprise trusted-time state version is unsupported.");
            }

            try
            {
                return DateTimeOffset.FromUnixTimeSeconds(
                    document.LastObservedUnixSeconds);
            }
            catch (ArgumentOutOfRangeException exception)
            {
                throw new InvalidDataException(
                    "Enterprise trusted-time state is outside the supported UTC range.",
                    exception);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(documentBytes);
        }
    }

    private void WriteCore(DateTimeOffset valueUtc)
    {
        var documentBytes = JsonSerializer.SerializeToUtf8Bytes(
            new TrustedTimeDocument
            {
                SchemaVersion = 1,
                LastObservedUnixSeconds = valueUtc.ToUnixTimeSeconds(),
            },
            StrictJson);
        try
        {
            // EnterpriseProtectedArtifactStore uses DPAPI and an atomic same-root
            // replacement, so a crash cannot expose a partially written floor.
            _protectedStore.WriteAsync(
                    EnterpriseManagedArtifact.TrustedTimeHighWaterDpapi,
                    documentBytes)
                .GetAwaiter()
                .GetResult();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(documentBytes);
        }
    }

    private static DateTimeOffset FloorToUtcSecond(
        DateTimeOffset valueUtc,
        string parameterName)
    {
        if (valueUtc.Offset != TimeSpan.Zero)
        {
            throw new InvalidDataException($"{parameterName} must use UTC.");
        }

        return DateTimeOffset.FromUnixTimeSeconds(valueUtc.ToUnixTimeSeconds());
    }

    private static DateTimeOffset RequireCanonicalUtcSecond(
        DateTimeOffset valueUtc,
        string parameterName)
    {
        var canonical = FloorToUtcSecond(valueUtc, parameterName);
        if (canonical != valueUtc)
        {
            throw new InvalidDataException(
                $"{parameterName} must use canonical whole-second UTC precision.");
        }

        return canonical;
    }

    private sealed class TrustedTimeDocument
    {
        [JsonPropertyName("schema_version")]
        public required int SchemaVersion { get; init; }

        [JsonPropertyName("last_observed_unix_seconds")]
        public required long LastObservedUnixSeconds { get; init; }
    }
}
