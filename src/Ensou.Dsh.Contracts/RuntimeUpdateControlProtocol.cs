using System.Text.Json;

namespace Ensou.Dsh.Contracts;

/// <summary>Strict runtime-to-Host update control response.</summary>
public sealed record RuntimeUpdateControlReceipt(
    Guid RuntimeInstanceId,
    Guid OperationId,
    int ProcessId,
    string Phase,
    int ActiveOperations,
    bool PersistenceFlushed);

/// <summary>Parses and validates the fixed runtime update control response.</summary>
/// <remarks>
/// Message validity does not establish process ownership or prove that every runtime writer has drained.
/// A caller must also authenticate the exact owned process and retain the existing runtime and data-directory leases.
/// </remarks>
public static class RuntimeUpdateControlProtocol
{
    public const string Protocol = "ensou.dsh.runtime-update.v1";
    public const int MaximumMessageBytes = 8 * 1024;
    private const string Draining = "draining";
    private const string Ready = "ready";
    private const string Resumed = "resumed";

    /// <summary>
    /// Parses one exact UTF-8 receipt and validates its identity against the caller's expected runtime.
    /// </summary>
    /// <param name="utf8Json">One complete, bounded response body from the authenticated runtime.</param>
    /// <param name="expectedRuntimeInstanceId">Nonempty identity pinned when the exact process was launched.</param>
    /// <param name="expectedOperationId">Nonempty identity unique to this update attempt.</param>
    /// <param name="expectedProcessId">Positive identifier of the retained owned process.</param>
    /// <param name="forProcessStop">Requires ready-state consistency; this check alone never authorizes termination.</param>
    public static RuntimeUpdateControlReceipt Parse(
        ReadOnlySpan<byte> utf8Json,
        Guid expectedRuntimeInstanceId,
        Guid expectedOperationId,
        int expectedProcessId,
        bool forProcessStop = false)
    {
        if (utf8Json.Length > MaximumMessageBytes)
        {
            throw new InvalidDataException("Runtime update control receipt exceeds 8 KiB.");
        }

        using var document = JsonDocument.Parse(utf8Json.ToArray(), new JsonDocumentOptions
        {
            AllowTrailingCommas = false,
            CommentHandling = JsonCommentHandling.Disallow,
        });
        if (document.RootElement.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException("Runtime update control receipt must be a JSON object.");
        }

        var values = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        foreach (var property in document.RootElement.EnumerateObject())
        {
            if (!values.TryAdd(property.Name, property.Value))
            {
                throw new InvalidDataException($"Runtime update control receipt repeats '{property.Name}'.");
            }
        }

        var expectedNames = new[]
        {
            "protocol", "runtimeInstanceId", "operationId", "processId",
            "phase", "activeOperations", "persistenceFlushed",
        };
        if (values.Count != expectedNames.Length
            || expectedNames.Any(name => !values.ContainsKey(name)))
        {
            throw new InvalidDataException("Runtime update control receipt has an unexpected field set.");
        }

        var receipt = new RuntimeUpdateControlReceipt(
            ParseGuid(values["runtimeInstanceId"], "runtimeInstanceId"),
            ParseGuid(values["operationId"], "operationId"),
            ParsePositiveInt(values["processId"], "processId"),
            ParsePhase(values["phase"]),
            ParseNonnegativeInt(values["activeOperations"], "activeOperations"),
            ParseBoolean(values["persistenceFlushed"], "persistenceFlushed"));

        if (values["protocol"].ValueKind != JsonValueKind.String
            || !string.Equals(values["protocol"].GetString(), Protocol, StringComparison.Ordinal))
        {
            throw new InvalidDataException("Runtime update control receipt protocol is invalid.");
        }

        Validate(receipt, expectedRuntimeInstanceId, expectedOperationId, expectedProcessId, forProcessStop);
        return receipt;
    }

    /// <summary>Validates identity and lifecycle rules for a parsed receipt.</summary>
    public static void Validate(
        RuntimeUpdateControlReceipt receipt,
        Guid expectedRuntimeInstanceId,
        Guid expectedOperationId,
        int expectedProcessId,
        bool forProcessStop = false)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        if (expectedProcessId <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(expectedProcessId));
        }
        if (expectedRuntimeInstanceId == Guid.Empty || expectedOperationId == Guid.Empty)
        {
            throw new ArgumentException("Runtime and operation identities must be nonempty.");
        }
        if (receipt.RuntimeInstanceId != expectedRuntimeInstanceId
            || receipt.OperationId != expectedOperationId
            || receipt.ProcessId != expectedProcessId)
        {
            throw new InvalidDataException("Runtime update control receipt identity does not match the request.");
        }
        if (receipt.ActiveOperations < 0)
        {
            throw new InvalidDataException("Runtime update control activeOperations cannot be negative.");
        }
        if (receipt.Phase is not Draining and not Ready and not Resumed)
        {
            throw new InvalidDataException("Runtime update control phase is invalid.");
        }
        if (receipt.Phase == Ready
            && (receipt.ActiveOperations != 0 || !receipt.PersistenceFlushed))
        {
            throw new InvalidDataException("A ready runtime update receipt requires zero active operations and flushed persistence.");
        }
        if (receipt.Phase == Resumed && receipt.PersistenceFlushed)
        {
            throw new InvalidDataException("A resumed runtime update receipt cannot attest paused persistence.");
        }
        if (forProcessStop && receipt.Phase != Ready)
        {
            throw new InvalidDataException("A draining receipt cannot authorize process stop.");
        }
    }

    private static Guid ParseGuid(JsonElement value, string name) =>
        value.ValueKind == JsonValueKind.String
            && Guid.TryParseExact(value.GetString(), "D", out var parsed)
            && parsed != Guid.Empty
            ? parsed
            : throw new InvalidDataException($"Runtime update control {name} must be a GUID in D format.");

    private static int ParsePositiveInt(JsonElement value, string name) =>
        value.ValueKind == JsonValueKind.Number
            && value.TryGetInt32(out var parsed)
            && parsed > 0
            ? parsed
            : throw new InvalidDataException($"Runtime update control {name} must be a positive integer.");

    private static int ParseNonnegativeInt(JsonElement value, string name) =>
        value.ValueKind == JsonValueKind.Number
            && value.TryGetInt32(out var parsed)
            && parsed >= 0
            ? parsed
            : throw new InvalidDataException($"Runtime update control {name} must be a nonnegative integer.");

    private static bool ParseBoolean(JsonElement value, string name) =>
        value.ValueKind == JsonValueKind.True ? true
        : value.ValueKind == JsonValueKind.False ? false
        : throw new InvalidDataException($"Runtime update control {name} must be boolean.");

    private static string ParsePhase(JsonElement value)
    {
        var phase = value.ValueKind == JsonValueKind.String ? value.GetString() : null;
        return phase is Draining or Ready or Resumed
            ? phase
            : throw new InvalidDataException("Runtime update control phase is invalid.");
    }
}
