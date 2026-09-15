using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Ensou.Dsh.Enterprise.Installation;
using Ensou.Dsh.Enterprise.ReleasePublisher;

internal static class PilotTrustConfigTests
{
    public static void Run()
    {
        ReportSerializationMatchesSchema();
        var source = Path.Combine(FindRepositoryRoot(), "release", "examples",
            "enterprise-pilot-readiness.config.example.json");
        var baseline = JsonNode.Parse(File.ReadAllBytes(source))!.AsObject();
        using var release = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var lease = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        SetKey(baseline["launcherTrust"]!, "release", release);
        SetKey(baseline["launcherTrust"]!, "lease", lease);
        foreach (var property in baseline["launcherTrust"]!.AsObject().ToArray())
        {
            if (property.Value?.GetValue<string>().StartsWith("https://", StringComparison.Ordinal) == true)
                baseline["launcherTrust"]![property.Key] = property.Value.GetValue<string>()
                    .Replace("replace.example", "acme-corp.com", StringComparison.Ordinal);
        }
        baseline["launcherTrust"]!["authenticodeSignerSha256Thumbprint"] = new string('a', 64);
        var direct = (JsonObject)baseline.DeepClone();
        direct["schemaVersion"] = 2;
        var trust = direct["launcherTrust"]!.DeepClone().AsObject();
        direct.Remove("launcherTrust");
        trust.Remove("gatewayOrigin");
        trust["runtimeProfile"] = "enterprise-direct-local";
        trust["apiProvider"] = "deepseek";
        direct["launcherDirectLocalTrust"] = trust;

        var root = Directory.CreateTempSubdirectory("ensou-direct-pilot-trust-").FullName;
        try
        {
#if ENTERPRISE_DIRECT_LOCAL_RUNTIME_ADMISSION
            var parsed = Read(direct, root);
            Equal(2, parsed.Config.SchemaVersion);
            Equal(EnterpriseDirectLocalProductionTrustFingerprint.ComputeSha256(
                parsed.Config.LauncherDirectLocalTrust),
                EnterprisePilotReadinessValidator.ComputeLauncherTrustSha256(parsed.Config));
            var serialized = JsonSerializer.Serialize(parsed.Config,
                new JsonSerializerOptions(JsonSerializerDefaults.Web));
            using var result = JsonDocument.Parse(serialized);
            if (result.RootElement.TryGetProperty("launcherTrust", out _))
                throw new InvalidOperationException("v2 emitted the legacy trust member.");
            Reject(baseline, root);
            foreach (var mutate in new Action<JsonObject>[]
            {
                value => value["schemaVersion"] = 1,
                value => value["launcherTrust"] = null,
                value => value["launcherTrust"] = baseline["launcherTrust"]!.DeepClone(),
                value => value["launcherDirectLocalTrust"]!["gatewayOrigin"] = "https://gateway.invalid/",
                value => value["launcherDirectLocalTrust"]!["apiProvider"] = "other",
                value => value["launcherDirectLocalTrust"]!["runtimeProfile"] = "enterprise-managed",
                value => value["launcherDirectLocalTrust"]!.AsObject().Remove("leaseKeyId"),
                value => value["launcherDirectLocalTrust"]!["ReleaseKeyId"] = "case-alias",
                value => value["launcherDirectLocalTrust"] = null,
            })
            {
                var changed = (JsonObject)direct.DeepClone();
                mutate(changed);
                Reject(changed, root);
            }
            var duplicate = direct.ToJsonString().Replace(
                "\"apiProvider\":\"deepseek\"",
                "\"apiProvider\":\"deepseek\",\"apiProvider\":\"deepseek\"",
                StringComparison.Ordinal);
            RejectRaw(duplicate, root);
            foreach (var invalidRoot in new[] { "[]", "null", "true", "42" })
                RejectRaw(invalidRoot, root);
            using var runtimeKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var brandKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var runtimePoint = runtimeKey.ExportParameters(false).Q;
            var brandPoint = brandKey.ExportParameters(false).Q;
            var runtime = new PublisherRuntimeAdmissionTrust
            {
                KeyId = "independent-runtime", X = Encode(runtimePoint.X!), Y = Encode(runtimePoint.Y!),
            };
            var brand = new PublisherBrandAuthorizationTrust
            {
                KeyId = "independent-brand", X = Encode(brandPoint.X!), Y = Encode(brandPoint.Y!),
            };
            brand.RequireIndependentFrom(runtime, parsed.Config.LauncherDirectLocalTrust);
            Throws(() => (brand with { KeyId = parsed.Config.LauncherTrust.ReleaseKeyId })
                .RequireIndependentFrom(runtime, parsed.Config.LauncherDirectLocalTrust));
            Throws(() => (brand with
            {
                X = parsed.Config.LauncherTrust.LeaseKeyX,
                Y = parsed.Config.LauncherTrust.LeaseKeyY,
            }).RequireIndependentFrom(runtime, parsed.Config.LauncherDirectLocalTrust));
            Equal(2, PilotReadinessReport.CurrentSchemaVersion);
#else
            var parsed = Read(baseline, root);
            Equal(1, parsed.Config.SchemaVersion);
            Equal(EnterpriseProductionTrustFingerprint.ComputeSha256(parsed.Config.LauncherTrust),
                EnterprisePilotReadinessValidator.ComputeLauncherTrustSha256(parsed.Config));
            Reject(direct, root);
            var mixed = (JsonObject)baseline.DeepClone();
            mixed["launcherDirectLocalTrust"] = direct["launcherDirectLocalTrust"]!.DeepClone();
            Reject(mixed, root);
            Equal(1, PilotReadinessReport.CurrentSchemaVersion);
#endif
            Console.WriteLine("PASS compile-selected Pilot trust config, cross-version rejection and key separation");
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static void ReportSerializationMatchesSchema()
    {
        var schemaPath = Path.Combine(FindRepositoryRoot(), "release", "schemas",
            $"enterprise-pilot-readiness-report-v{PilotReadinessReport.CurrentSchemaVersion}.schema.json");
        using var schema = JsonDocument.Parse(File.ReadAllBytes(schemaPath));
        var schemaProperties = schema.RootElement.GetProperty("properties");
        var required = schema.RootElement.GetProperty("required").EnumerateArray()
            .Select(value => value.GetString()!).ToHashSet(StringComparer.Ordinal);
        Equal(false, schema.RootElement.GetProperty("additionalProperties").GetBoolean());
        foreach (var admit in new[] { true, false })
        {
            var report = new PilotReadinessReport
            {
                SchemaVersion = PilotReadinessReport.CurrentSchemaVersion,
                ReportType = PilotReadinessReport.CurrentReportType,
                Decision = admit ? "ADMIT" : "REJECT",
                GeneratedAtUtc = DateTimeOffset.UtcNow,
                Environment = "production",
                Channel = "pilot",
                PublisherExecutableSha256 = new string('a', 64),
                ReleaseSetId = admit ? "serialization-only" : null,
                Generation = admit ? 1 : null,
                Sequence = admit ? 1 : null,
                UpdateContractId = EnterpriseProductionTrustFingerprint.PilotUpdateContractId,
                BrandAuthorizationId = admit ? "00000000-0000-4000-8000-000000000001" : null,
                BrandAuthorizationKeyId = admit ? "serialization-brand" : null,
                BrandAuthorizationReceiptSha256 = admit ? new string('b', 64) : null,
                BrandAuthorizationExpiresAtUtc = admit ? DateTimeOffset.UtcNow.AddHours(1) : null,
                LocalDataCertificationId = admit ? "00000000-0000-4000-8000-000000000002" : null,
                LocalDataCertificationKeyId = admit ? "serialization-local-data" : null,
                LocalDataCertificationReceiptSha256 = admit ? new string('c', 64) : null,
                LocalDataCertificationExpiresAtUtc = admit ? DateTimeOffset.UtcNow.AddHours(1) : null,
                Checks = [new("serialization-only", admit ? "PASS" : "FAIL", "synthetic test only")],
                FailureCode = admit ? null : "config-contract",
                FailureMessage = admit ? null : "Synthetic rejected input.",
            };
            using var emitted = JsonDocument.Parse(JsonSerializer.SerializeToUtf8Bytes(
                report, new JsonSerializerOptions(JsonSerializerDefaults.Web)));
            var actualNames = emitted.RootElement.EnumerateObject()
                .Select(property => property.Name).ToHashSet(StringComparer.Ordinal);
            if (!required.SetEquals(actualNames))
                throw new InvalidOperationException("Readiness report fields differ from the versioned schema.");
            foreach (var property in emitted.RootElement.EnumerateObject())
            {
                var propertySchema = schemaProperties.GetProperty(property.Name);
                if (propertySchema.TryGetProperty("const", out var fixedValue)
                    && !JsonElement.DeepEquals(property.Value, fixedValue))
                    throw new InvalidOperationException("Readiness report constant differs from schema.");
            }
            Equal(admit ? "ADMIT" : "REJECT", emitted.RootElement.GetProperty("decision").GetString());
            Equal(admit, emitted.RootElement.GetProperty("failureCode").ValueKind == JsonValueKind.Null);
        }
    }

    private static PilotReadinessConfigRead Read(JsonObject value, string root) =>
        ReadRaw(value.ToJsonString(), root);

    private static PilotReadinessConfigRead ReadRaw(string value, string root)
    {
        var path = Path.Combine(root, Guid.NewGuid().ToString("N") + ".json");
        using (var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write))
        {
            stream.Write(Encoding.UTF8.GetBytes(value));
        }
        return EnterprisePilotReadinessValidator.ReadAndValidateConfig(path);
    }

    private static void Reject(JsonObject value, string root) =>
        Throws(() => Read(value, root));

    private static void RejectRaw(string value, string root) =>
        Throws(() => ReadRaw(value, root));

    private static void Throws(Action action)
    {
        try { action(); }
        catch (InvalidDataException) { return; }
        throw new InvalidOperationException("Invalid Pilot trust config was accepted.");
    }

    private static void SetKey(JsonNode trust, string prefix, ECDsa key)
    {
        var point = key.ExportParameters(false).Q;
        trust[prefix + "KeyX"] = Encode(point.X!);
        trust[prefix + "KeyY"] = Encode(point.Y!);
    }

    private static string Encode(byte[] value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static void Equal<T>(T expected, T actual)
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
            throw new InvalidOperationException("Pilot trust contract differs.");
    }

    internal static string FindRepositoryRoot()
    {
        foreach (var start in new[] { Directory.GetCurrentDirectory(), AppContext.BaseDirectory })
        {
            var directory = new DirectoryInfo(start);
            while (directory is not null)
            {
                if (File.Exists(Path.Combine(directory.FullName, "versions", "locked.json")))
                    return directory.FullName;
                directory = directory.Parent;
            }
        }
        throw new DirectoryNotFoundException("Repository root was not found.");
    }
}
