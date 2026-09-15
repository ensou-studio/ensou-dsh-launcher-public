using System.Buffers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Ensou.Dsh.Enterprise.Installation;

namespace Ensou.Dsh.Enterprise.Client;

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record EnterpriseAuthenticatedUpdateCapabilityProbe(
    int SchemaVersion,
    string ProbeType,
    string Edition,
    string Channel,
    string ManifestPath,
    bool FreshAuthorizationRequired,
    IReadOnlyList<string> AdmittedClientStates,
    string TransportContract,
    string TransactionClientLifetime,
    string UnauthorizedBehavior,
    string ForbiddenReadyBehavior,
    string ForbiddenUpdateRequiredBehavior,
    string BootstrapHealthBehavior,
    string SideEffectContract);

/// <summary>
/// Emits a bounded public capability descriptor. Authenticity is established
/// by verifying the exact Launcher binary before invoking this command; the
/// command itself never reads secrets, accesses the network, or mutates state.
/// </summary>
public static class EnterpriseAuthenticatedUpdateCapabilityProbeContract
{
    public const int SchemaVersion = 1;
    public const string ProbeType =
        "ensou-dsh-enterprise-authenticated-stable-update-capability-v1";
    public const string Command =
        "--authenticated-stable-update-capability-self-check";
    public const string FailureMessage =
        "Ensou DSH Enterprise authenticated update capability probe failed.";
    public const int MaximumCanonicalBytes = 4 * 1024;

    private const string Edition = "Enterprise";
    private const string StableChannel = "stable";
    private const string StableManifestPath =
        "/v2/channels/stable/release-set.v2.json";
    private const string ReadyState = "Ready";
    private const string UpdateRequiredState = "UpdateRequired";
    private const string TransportContract = "authenticated-dpop-transaction-v1";
    private const string TransactionClientLifetime = "single-check";
    private const string UnauthorizedBehavior = "clear-token-lock-session";
    private const string ForbiddenReadyBehavior = "continue-verified-stable";
    private const string ForbiddenUpdateRequiredBehavior = "remain-locked";
    private const string BootstrapHealthBehavior =
        "restart-through-stable-bootstrapper";
    private const string SideEffectContract = "no-secrets-no-network-no-mutation";

    private static readonly JsonSerializerOptions StrictJson = new(
        JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    public static bool IsExactCommand(IReadOnlyList<string> args) =>
        args is [Command];

    public static EnterpriseAuthenticatedUpdateCapabilityProbe Create() => new(
        SchemaVersion,
        ProbeType,
        Edition,
        StableChannel,
        StableManifestPath,
        FreshAuthorizationRequired: true,
        [ReadyState, UpdateRequiredState],
        TransportContract,
        TransactionClientLifetime,
        UnauthorizedBehavior,
        ForbiddenReadyBehavior,
        ForbiddenUpdateRequiredBehavior,
        BootstrapHealthBehavior,
        SideEffectContract);

    public static byte[] SerializeCanonical(
        EnterpriseAuthenticatedUpdateCapabilityProbe probe)
    {
        ArgumentNullException.ThrowIfNull(probe);
        Validate(probe);
        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(
                   buffer,
                   new JsonWriterOptions
                   {
                       Indented = false,
                       SkipValidation = false,
                   }))
        {
            writer.WriteStartObject();
            writer.WriteNumber("schemaVersion", probe.SchemaVersion);
            writer.WriteString("probeType", probe.ProbeType);
            writer.WriteString("edition", probe.Edition);
            writer.WriteString("channel", probe.Channel);
            writer.WriteString("manifestPath", probe.ManifestPath);
            writer.WriteBoolean(
                "freshAuthorizationRequired",
                probe.FreshAuthorizationRequired);
            writer.WritePropertyName("admittedClientStates");
            writer.WriteStartArray();
            foreach (var state in probe.AdmittedClientStates)
            {
                writer.WriteStringValue(state);
            }
            writer.WriteEndArray();
            writer.WriteString("transportContract", probe.TransportContract);
            writer.WriteString(
                "transactionClientLifetime",
                probe.TransactionClientLifetime);
            writer.WriteString("unauthorizedBehavior", probe.UnauthorizedBehavior);
            writer.WriteString(
                "forbiddenReadyBehavior",
                probe.ForbiddenReadyBehavior);
            writer.WriteString(
                "forbiddenUpdateRequiredBehavior",
                probe.ForbiddenUpdateRequiredBehavior);
            writer.WriteString(
                "bootstrapHealthBehavior",
                probe.BootstrapHealthBehavior);
            writer.WriteString("sideEffectContract", probe.SideEffectContract);
            writer.WriteEndObject();
        }

        var canonical = buffer.WrittenSpan.ToArray();
        if (canonical.Length is <= 0 or > MaximumCanonicalBytes)
        {
            throw new InvalidDataException(
                "Enterprise authenticated update capability probe is unbounded.");
        }
        return canonical;
    }

    public static EnterpriseAuthenticatedUpdateCapabilityProbe ParseCanonical(
        ReadOnlySpan<byte> utf8Json)
    {
        if (utf8Json.Length is <= 0 or > MaximumCanonicalBytes
            || utf8Json.Length >= 3
                && utf8Json[0] == 0xEF
                && utf8Json[1] == 0xBB
                && utf8Json[2] == 0xBF)
        {
            throw new InvalidDataException(
                "Enterprise authenticated update capability probe size or encoding is invalid.");
        }

        try
        {
            EnterpriseReleaseJson.RequireNoDuplicateMembers(utf8Json);
            var probe = JsonSerializer.Deserialize<
                            EnterpriseAuthenticatedUpdateCapabilityProbe>(
                            utf8Json,
                            StrictJson)
                        ?? throw new InvalidDataException(
                            "Enterprise authenticated update capability probe is empty.");
            Validate(probe);
            if (!utf8Json.SequenceEqual(SerializeCanonical(probe)))
            {
                throw new InvalidDataException(
                    "Enterprise authenticated update capability probe is not canonical JSON.");
            }
            return probe;
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException(
                "Enterprise authenticated update capability probe JSON is invalid.",
                exception);
        }
    }

    public static void WriteCanonicalToStandardOutput()
    {
        using var output = Console.OpenStandardOutput();
        WriteCanonical(output, SerializeCanonical(Create()));
    }

    public static void WriteBoundedFailureToStandardError()
    {
        try
        {
            using var error = Console.OpenStandardError();
            WriteBoundedFailure(error);
        }
        catch
        {
            // Machine probes must never fall back to desktop UI when their
            // diagnostic stream is unavailable.
        }
    }

    internal static void WriteCanonical(Stream output, ReadOnlySpan<byte> canonical)
    {
        ArgumentNullException.ThrowIfNull(output);
        _ = ParseCanonical(canonical);
        output.Write(canonical);
        output.Flush();
    }

    internal static void WriteBoundedFailure(Stream error)
    {
        ArgumentNullException.ThrowIfNull(error);
        var bytes = Encoding.UTF8.GetBytes(FailureMessage);
        if (bytes.Length > 256)
        {
            throw new InvalidOperationException(
                "Enterprise authenticated update capability probe failure is unbounded.");
        }
        error.Write(bytes);
        error.Flush();
    }

    private static void Validate(
        EnterpriseAuthenticatedUpdateCapabilityProbe probe)
    {
        if (probe.SchemaVersion != SchemaVersion
            || !string.Equals(probe.ProbeType, ProbeType, StringComparison.Ordinal)
            || !string.Equals(probe.Edition, Edition, StringComparison.Ordinal)
            || !string.Equals(probe.Channel, StableChannel, StringComparison.Ordinal)
            || !string.Equals(
                probe.ManifestPath,
                StableManifestPath,
                StringComparison.Ordinal)
            || !probe.FreshAuthorizationRequired
            || probe.AdmittedClientStates is not [ReadyState, UpdateRequiredState]
            || !string.Equals(
                probe.TransportContract,
                TransportContract,
                StringComparison.Ordinal)
            || !string.Equals(
                probe.TransactionClientLifetime,
                TransactionClientLifetime,
                StringComparison.Ordinal)
            || !string.Equals(
                probe.UnauthorizedBehavior,
                UnauthorizedBehavior,
                StringComparison.Ordinal)
            || !string.Equals(
                probe.ForbiddenReadyBehavior,
                ForbiddenReadyBehavior,
                StringComparison.Ordinal)
            || !string.Equals(
                probe.ForbiddenUpdateRequiredBehavior,
                ForbiddenUpdateRequiredBehavior,
                StringComparison.Ordinal)
            || !string.Equals(
                probe.BootstrapHealthBehavior,
                BootstrapHealthBehavior,
                StringComparison.Ordinal)
            || !string.Equals(
                probe.SideEffectContract,
                SideEffectContract,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Enterprise authenticated update capability probe contract is invalid.");
        }
    }
}
