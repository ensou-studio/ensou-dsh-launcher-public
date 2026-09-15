using System.Text;
using System.Text.Json;
using Ensou.Dsh.Contracts;

var instance = Guid.Parse("11111111-1111-1111-1111-111111111111");
var operation = Guid.Parse("22222222-2222-2222-2222-222222222222");
const int pid = 4312;
var tests = new (string Name, Action Run)[]
{
    ("parses draining receipt with exact identity", ParsesDraining),
    ("accepts ready only when quiescent and flushed", AcceptsReady),
    ("accepts resumed only without stop authorization", AcceptsResumed),
    ("rejects draining as process-stop authorization", RejectsDrainStop),
    ("rejects identity mismatch and invalid types", RejectsIdentityAndTypes),
    ("rejects invalid protocol and empty identities", RejectsProtocolAndEmptyIdentities),
    ("rejects invalid numeric ranges", RejectsNumericRanges),
    ("rejects every missing required field", RejectsEveryMissingField),
    ("rejects malformed and trailing JSON", RejectsMalformedJson),
    ("rejects duplicate unknown and oversized fields", RejectsFieldSet),
};
var failures = 0;
foreach (var test in tests)
{
    try { test.Run(); Console.WriteLine($"PASS  {test.Name}"); }
    catch (Exception exception) { failures++; Console.Error.WriteLine($"FAIL  {test.Name}\n{exception}"); }
}
Console.WriteLine($"{tests.Length - failures}/{tests.Length} self-checks passed.");
return failures == 0 ? 0 : 1;

void ParsesDraining()
{
    var receipt = Parse("draining", 2, false);
    Assert(receipt.Phase == "draining" && receipt.ActiveOperations == 2 && !receipt.PersistenceFlushed);
    Assert(Parse("draining", 2, true).PersistenceFlushed);
}

void AcceptsReady()
{
    var receipt = Parse("ready", 0, true);
    RuntimeUpdateControlProtocol.Validate(receipt, instance, operation, pid, forProcessStop: true);
}

void RejectsDrainStop() => Throws<InvalidDataException>(() => Parse("draining", 1, false, forProcessStop: true));

void AcceptsResumed()
{
    Assert(Parse("resumed", 1, false).Phase == "resumed");
    Throws<InvalidDataException>(() => Parse("resumed", 0, true));
    Throws<InvalidDataException>(() => Parse("resumed", 0, false, forProcessStop: true));
}

void RejectsIdentityAndTypes()
{
    Throws<InvalidDataException>(() => Parse("ready", 0, true, runtimeInstanceId: "33333333-3333-3333-3333-333333333333"));
    Throws<InvalidDataException>(() => Parse("ready", 0, true, operationId: "33333333-3333-3333-3333-333333333333"));
    Throws<InvalidDataException>(() => RuntimeUpdateControlProtocol.Parse(
        Utf8(Json("ready", 0, true, process: "4313")), instance, operation, pid));
    Throws<InvalidDataException>(() => Parse("ready", 0, true, processId: "4312"));
    Throws<InvalidDataException>(() => Parse("ready", 1, true));
    Throws<InvalidDataException>(() => Parse("ready", 0, false));
}

void RejectsProtocolAndEmptyIdentities()
{
    Throws<InvalidDataException>(() => RuntimeUpdateControlProtocol.Parse(
        Utf8(Json("ready", 0, true).Replace(RuntimeUpdateControlProtocol.Protocol, "other", StringComparison.Ordinal)), instance, operation, pid));
    Throws<InvalidDataException>(() => Parse("ready", 0, true, runtimeInstanceId: Guid.Empty.ToString("D")));
    Throws<InvalidDataException>(() => Parse("ready", 0, true, operationId: Guid.Empty.ToString("D")));
    Throws<ArgumentException>(() => RuntimeUpdateControlProtocol.Parse(
        Utf8(Json("ready", 0, true)), Guid.Empty, operation, pid));
    Throws<ArgumentException>(() => RuntimeUpdateControlProtocol.Parse(
        Utf8(Json("ready", 0, true)), instance, Guid.Empty, pid));
    Throws<ArgumentOutOfRangeException>(() => RuntimeUpdateControlProtocol.Parse(
        Utf8(Json("ready", 0, true)), instance, operation, 0));
}

void RejectsNumericRanges()
{
    Throws<InvalidDataException>(() => Parse("ready", 0, true, processId: 0));
    Throws<InvalidDataException>(() => Parse("ready", 0, true, processId: -1));
    Throws<InvalidDataException>(() => Parse("draining", -1, false));
    Throws<InvalidDataException>(() => RuntimeUpdateControlProtocol.Parse(
        Utf8(Json("draining", 0, false).Replace("\"activeOperations\":0", "\"activeOperations\":2147483648", StringComparison.Ordinal)), instance, operation, pid));
    Throws<InvalidDataException>(() => RuntimeUpdateControlProtocol.Parse(
        Utf8(Json("draining", 0, false).Replace($"\"processId\":{pid}", "\"processId\":2147483648", StringComparison.Ordinal)), instance, operation, pid));
}

void RejectsEveryMissingField()
{
    foreach (var field in new[] { "protocol", "runtimeInstanceId", "operationId", "processId", "phase", "activeOperations", "persistenceFlushed" })
    {
        var json = field switch
        {
            "protocol" => Json("ready", 0, true).Replace("\"protocol\":\"ensou.dsh.runtime-update.v1\",", "", StringComparison.Ordinal),
            "runtimeInstanceId" => Json("ready", 0, true).Replace($"\"runtimeInstanceId\":\"{instance:D}\",", "", StringComparison.Ordinal),
            "operationId" => Json("ready", 0, true).Replace($"\"operationId\":\"{operation:D}\",", "", StringComparison.Ordinal),
            "processId" => Json("ready", 0, true).Replace($"\"processId\":{pid},", "", StringComparison.Ordinal),
            "phase" => Json("ready", 0, true).Replace("\"phase\":\"ready\",", "", StringComparison.Ordinal),
            "activeOperations" => Json("ready", 0, true).Replace("\"activeOperations\":0,", "", StringComparison.Ordinal),
            _ => Json("ready", 0, true).Replace(",\"persistenceFlushed\":true", "", StringComparison.Ordinal),
        };
        Throws<InvalidDataException>(() => RuntimeUpdateControlProtocol.Parse(Utf8(json), instance, operation, pid));
    }
}

void RejectsMalformedJson()
{
    Throws<JsonException>(() => RuntimeUpdateControlProtocol.Parse(Utf8("{"), instance, operation, pid));
    Throws<JsonException>(() => RuntimeUpdateControlProtocol.Parse(Utf8(Json("ready", 0, true) + " trailing"), instance, operation, pid));
    Throws<JsonException>(() => RuntimeUpdateControlProtocol.Parse(Utf8(Json("ready", 0, true).TrimEnd('}') + ",}"), instance, operation, pid));
}

void RejectsFieldSet()
{
    Throws<InvalidDataException>(() => RuntimeUpdateControlProtocol.Parse(
        Utf8("{\"protocol\":\"ensou.dsh.runtime-update.v1\",\"runtimeInstanceId\":\"11111111-1111-1111-1111-111111111111\",\"runtimeInstanceId\":\"11111111-1111-1111-1111-111111111111\",\"operationId\":\"22222222-2222-2222-2222-222222222222\",\"processId\":4312,\"phase\":\"ready\",\"activeOperations\":0,\"persistenceFlushed\":true}"), instance, operation, pid));
    Throws<InvalidDataException>(() => RuntimeUpdateControlProtocol.Parse(
        Utf8(Json("ready", 0, true).TrimEnd('}') + ",\"extra\":1}"), instance, operation, pid));
    Throws<InvalidDataException>(() => RuntimeUpdateControlProtocol.Parse(
        Utf8("{\"protocol\":\"ensou.dsh.runtime-update.v1\"}"), instance, operation, pid));
    Throws<InvalidDataException>(() => RuntimeUpdateControlProtocol.Parse(
        Encoding.UTF8.GetBytes(new string('x', RuntimeUpdateControlProtocol.MaximumMessageBytes + 1)), instance, operation, pid));
}

RuntimeUpdateControlReceipt Parse(string phase, int active, bool flushed, bool forProcessStop = false, string? runtimeInstanceId = null, string? operationId = null, object? processId = null)
{
    var process = processId is null ? pid.ToString() : processId is string text ? $"\"{text}\"" : processId.ToString();
    return RuntimeUpdateControlProtocol.Parse(Utf8(Json(phase, active, flushed, runtimeInstanceId, process, operationId)), instance, operation, pid, forProcessStop);
}

string Json(string phase, int active, bool flushed, string? runtimeInstanceId = null, string? process = null, string? operationId = null) =>
    $"{{\"protocol\":\"ensou.dsh.runtime-update.v1\",\"runtimeInstanceId\":\"{runtimeInstanceId ?? instance.ToString("D")}\",\"operationId\":\"{operationId ?? operation.ToString("D")}\",\"processId\":{process ?? pid.ToString()},\"phase\":\"{phase}\",\"activeOperations\":{active},\"persistenceFlushed\":{flushed.ToString().ToLowerInvariant()}}}";

static byte[] Utf8(string value) => Encoding.UTF8.GetBytes(value);
static void Assert(bool condition) { if (!condition) throw new InvalidOperationException("Assertion failed."); }
static void Throws<T>(Action action) where T : Exception { try { action(); } catch (T) { return; } throw new InvalidOperationException($"Expected {typeof(T).Name}."); }
