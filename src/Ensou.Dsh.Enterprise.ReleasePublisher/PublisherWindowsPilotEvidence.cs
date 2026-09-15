using System.Net;
using System.Net.Http.Headers;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Ensou.Dsh.Enterprise.Installation;

namespace Ensou.Dsh.Enterprise.ReleasePublisher;

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PublisherWindowsPilotEvidenceTrust
{
    public required string KeyId { get; init; }
    public required string X { get; init; }
    public required string Y { get; init; }

    public void Validate()
    {
        PublisherRuntimeAdmissionEncoding.ValidateToken(
            KeyId,
            "Windows Pilot evidence keyId",
            64);
        var x = PublisherRuntimeAdmissionEncoding.DecodeBase64Url(
            X,
            "Windows Pilot evidence key x",
            32);
        var y = PublisherRuntimeAdmissionEncoding.DecodeBase64Url(
            Y,
            "Windows Pilot evidence key y",
            32);
        try
        {
            using var verifier = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = x, Y = y },
            });
        }
        catch (CryptographicException exception)
        {
            throw new InvalidDataException(
                "Windows Pilot evidence trust is not a valid P-256 public key.",
                exception);
        }
    }

    public void RequireIndependentFrom(
        params (string KeyId, string X, string Y, string Purpose)[] otherKeys)
    {
        Validate();
        var x = PublisherRuntimeAdmissionEncoding.DecodeBase64Url(
            X,
            "Windows Pilot evidence key x",
            32);
        var y = PublisherRuntimeAdmissionEncoding.DecodeBase64Url(
            Y,
            "Windows Pilot evidence key y",
            32);
        foreach (var other in otherKeys)
        {
            PublisherRuntimeAdmissionEncoding.ValidateToken(
                other.KeyId,
                $"{other.Purpose} keyId",
                64);
            var otherX = PublisherRuntimeAdmissionEncoding.DecodeBase64Url(
                other.X,
                $"{other.Purpose} key x",
                32);
            var otherY = PublisherRuntimeAdmissionEncoding.DecodeBase64Url(
                other.Y,
                $"{other.Purpose} key y",
                32);
            if (string.Equals(KeyId, other.KeyId, StringComparison.Ordinal)
                || (CryptographicOperations.FixedTimeEquals(x, otherX)
                    && CryptographicOperations.FixedTimeEquals(y, otherY)))
            {
                throw new InvalidDataException(
                    $"Windows Pilot evidence trust must be independent from {other.Purpose} trust.");
            }
        }
    }
}

internal static class PublisherWindowsPilotEvidenceTrustResolver
{
    private const string KeyIdName = "EnterprisePilotEvidenceKeyId";
    private const string KeyXName = "EnterprisePilotEvidenceKeyX";
    private const string KeyYName = "EnterprisePilotEvidenceKeyY";

    public static PublisherWindowsPilotEvidenceTrust ResolveProduction()
    {
        var metadata = typeof(Program).Assembly
            .GetCustomAttributes<AssemblyMetadataAttribute>()
            .ToArray();
        var trust = new PublisherWindowsPilotEvidenceTrust
        {
            KeyId = RequireSingle(metadata, KeyIdName),
            X = RequireSingle(metadata, KeyXName),
            Y = RequireSingle(metadata, KeyYName),
        };
        trust.Validate();
        return trust;
    }

    private static string RequireSingle(
        IReadOnlyList<AssemblyMetadataAttribute> metadata,
        string name)
    {
        var values = metadata
            .Where(value => string.Equals(value.Key, name, StringComparison.Ordinal))
            .Select(value => value.Value)
            .ToArray();
        if (values.Length != 1 || string.IsNullOrWhiteSpace(values[0]))
        {
            throw new InvalidDataException(
                $"Production publisher assembly is missing exact {name} trust metadata.");
        }
        return values[0]!;
    }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PublisherWindowsPilotEvidenceBodyBinding
{
    public required int SchemaVersion { get; init; }
    public required string EvidenceType { get; init; }
    public required long SizeBytes { get; init; }
    public required string Sha256 { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record PublisherWindowsPilotEvidenceEnvelope
{
    public const int CurrentSchemaVersion = 2;
    public const string CurrentEvidenceType =
        "ensou-dsh-enterprise-windows-pilot-evidence-envelope";
    public const string CurrentBodyEvidenceType =
        "ensou-dsh-enterprise-windows-pilot-evidence-body";

    public required int SchemaVersion { get; init; }
    public required string EvidenceType { get; init; }
    public required PublisherWindowsPilotEvidenceBodyBinding Body { get; init; }
    public required EnterpriseReleaseSignature Attestation { get; init; }

    public static PublisherWindowsPilotEvidenceEnvelope Parse(ReadOnlySpan<byte> bytes)
    {
        EnterpriseReleaseJson.RequireNoDuplicateMembers(bytes);
        try
        {
            return JsonSerializer.Deserialize<PublisherWindowsPilotEvidenceEnvelope>(
                bytes,
                PublisherWindowsPilotEvidenceJson.Options)
                ?? throw new InvalidDataException("Windows Pilot evidence envelope is empty.");
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException(
                "Windows Pilot evidence envelope is not the exact v2 contract.",
                exception);
        }
    }
}

internal static class PublisherWindowsPilotEvidenceCanonicalPayload
{
    public static byte[] Create(PublisherWindowsPilotEvidenceEnvelope envelope) =>
        Encoding.UTF8.GetBytes(string.Join(
            '\n',
            "ensou-dsh-enterprise-windows-pilot-evidence-attestation-v2",
            envelope.SchemaVersion.ToString(System.Globalization.CultureInfo.InvariantCulture),
            envelope.EvidenceType,
            envelope.Body.SchemaVersion.ToString(System.Globalization.CultureInfo.InvariantCulture),
            envelope.Body.EvidenceType,
            envelope.Body.SizeBytes.ToString(System.Globalization.CultureInfo.InvariantCulture),
            envelope.Body.Sha256));
}

internal sealed record PublisherWindowsPilotEvidenceVerification(
    string BodySha256,
    long BodySizeBytes,
    string KeyId);

internal static class PublisherWindowsPilotEvidenceVerifier
{
    public static PublisherWindowsPilotEvidenceVerification Verify(
        ReadOnlySpan<byte> envelopeBytes,
        ReadOnlySpan<byte> bodyBytes,
        PublisherWindowsPilotEvidenceTrust trust)
    {
        ArgumentNullException.ThrowIfNull(trust);
        trust.Validate();
        var envelope = PublisherWindowsPilotEvidenceEnvelope.Parse(envelopeBytes);
        var bodySha256 = Convert.ToHexStringLower(SHA256.HashData(bodyBytes));
        if (envelope.SchemaVersion != PublisherWindowsPilotEvidenceEnvelope.CurrentSchemaVersion
            || !string.Equals(
                envelope.EvidenceType,
                PublisherWindowsPilotEvidenceEnvelope.CurrentEvidenceType,
                StringComparison.Ordinal)
            || envelope.Body is null
            || envelope.Body.SchemaVersion !=
                PublisherWindowsPilotEvidenceEnvelope.CurrentSchemaVersion
            || !string.Equals(
                envelope.Body.EvidenceType,
                PublisherWindowsPilotEvidenceEnvelope.CurrentBodyEvidenceType,
                StringComparison.Ordinal)
            || envelope.Body.SizeBytes != bodyBytes.Length
            || envelope.Body.SizeBytes is <= 0 or > 16 * 1024 * 1024
            || !string.Equals(envelope.Body.Sha256, bodySha256, StringComparison.Ordinal)
            || envelope.Attestation is null
            || !string.Equals(envelope.Attestation.KeyId, trust.KeyId, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Windows Pilot evidence envelope does not bind the exact attested body and trusted key.");
        }
        EnterpriseEs256SignatureVerifier.Verify(
            envelope.Attestation,
            PublisherWindowsPilotEvidenceCanonicalPayload.Create(envelope),
            [new EnterpriseReleasePublicKey(trust.KeyId, trust.X, trust.Y)]);
        return new PublisherWindowsPilotEvidenceVerification(
            bodySha256,
            bodyBytes.Length,
            trust.KeyId);
    }
}

internal static class PublisherWindowsPilotEvidenceCommand
{
    private const string TrustCommand = "--windows-pilot-trust";
    private const string AttestationCommand = "--verify-windows-pilot-attestation";
    private const string ManifestCommand = "--verify-windows-pilot-manifest";
    private const string LiveHeadCommand = "--verify-windows-pilot-live-head";
    private const int MaximumJsonBytes = 16 * 1024 * 1024;
    private static readonly JsonSerializerOptions OutputJson = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
    };

    public static bool IsRequested(string[] args) => args.Length > 0
        && args[0] is TrustCommand or AttestationCommand or ManifestCommand or LiveHeadCommand;

    public static int Run(string[] args)
    {
        try
        {
            return args[0] switch
            {
                TrustCommand => WriteTrust(args),
                AttestationCommand => VerifyAttestation(args),
                ManifestCommand => VerifyManifest(args),
                LiveHeadCommand => VerifyLiveHead(args),
                _ => throw new ArgumentException("Unknown Windows Pilot verification command."),
            };
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine($"Windows Pilot verification failed: {exception.Message}");
            return 1;
        }
    }

    private static int WriteTrust(string[] args)
    {
        if (args.Length != 1)
        {
            throw new ArgumentException($"Usage: {TrustCommand}");
        }
        var trust = PublisherWindowsPilotEvidenceTrustResolver.ResolveProduction();
        Console.WriteLine(JsonSerializer.Serialize(new
        {
            schemaVersion = 1,
            trustType = "ensou-dsh-enterprise-windows-pilot-verification-trust",
            pilotEvidenceKeyId = trust.KeyId,
            authenticodeSignerSha256Thumbprint =
                EnterpriseAuthenticodeVerifier.GetCompiledSignerSha256Thumbprint(),
        }, OutputJson));
        return 0;
    }

    private static int VerifyAttestation(string[] args)
    {
        var values = ParsePairs(args, AttestationCommand,
            "--evidence-envelope", "--evidence-body", "--pilot-readiness-config");
        var config = EnterprisePilotReadinessValidator
            .ReadAndValidateConfig(values["--pilot-readiness-config"]).Config;
        var trust = PublisherWindowsPilotEvidenceTrustResolver.ResolveProduction();
        RequireIndependentTrust(trust, config);
        var envelopeBytes = ReadLocked(values["--evidence-envelope"], 256 * 1024,
            "Windows Pilot evidence envelope");
        var bodyBytes = ReadLocked(values["--evidence-body"], MaximumJsonBytes,
            "Windows Pilot evidence body");
        var verification = PublisherWindowsPilotEvidenceVerifier.Verify(
            envelopeBytes,
            bodyBytes,
            trust);
        Console.WriteLine(JsonSerializer.Serialize(new
        {
            schemaVersion = 1,
            verificationType = "windows-pilot-evidence-attestation",
            status = "VERIFIED",
            pilotEvidenceKeyId = verification.KeyId,
            bodySha256 = verification.BodySha256,
            bodySizeBytes = verification.BodySizeBytes,
        }, OutputJson));
        return 0;
    }

    private static int VerifyManifest(string[] args)
    {
        var values = ParsePairs(args, ManifestCommand,
            "--pilot-readiness-config", "--release-manifest");
        var config = EnterprisePilotReadinessValidator
            .ReadAndValidateConfig(values["--pilot-readiness-config"]).Config;
        var bytes = ReadLocked(values["--release-manifest"], 512 * 1024,
            "Windows Pilot release manifest");
        WriteManifestVerification(VerifyReleaseManifest(bytes, config));
        return 0;
    }

    private static int VerifyLiveHead(string[] args)
    {
        var values = ParsePairs(args, LiveHeadCommand, "--pilot-readiness-config");
        var config = EnterprisePilotReadinessValidator
            .ReadAndValidateConfig(values["--pilot-readiness-config"]).Config;
        var uri = new Uri(config.LauncherTrust.UpdateManifestUri, UriKind.Absolute);
        using var handler = new HttpClientHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            UseCookies = false,
        };
        using var client = new HttpClient(handler)
        {
            Timeout = TimeSpan.FromSeconds(30),
        };
        using var request = new HttpRequestMessage(HttpMethod.Get, uri);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.CacheControl = new CacheControlHeaderValue
        {
            NoCache = true,
            NoStore = true,
        };
        using var response = client.Send(
            request,
            HttpCompletionOption.ResponseHeadersRead);
        if (response.StatusCode != HttpStatusCode.OK
            || response.RequestMessage?.RequestUri is null
            || !string.Equals(
                response.RequestMessage.RequestUri.AbsoluteUri,
                uri.AbsoluteUri,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Live Windows Pilot head did not return one non-redirected HTTP 200 response.");
        }
        using var stream = response.Content.ReadAsStream();
        using var output = new MemoryStream();
        var buffer = new byte[64 * 1024];
        while (true)
        {
            var read = stream.Read(buffer, 0, buffer.Length);
            if (read == 0)
            {
                break;
            }
            if (output.Length + read > 512 * 1024)
            {
                throw new InvalidDataException("Live Windows Pilot head is too large.");
            }
            output.Write(buffer, 0, read);
        }
        WriteManifestVerification(VerifyReleaseManifest(output.ToArray(), config));
        return 0;
    }

    private static PublisherWindowsPilotManifestVerification VerifyReleaseManifest(
        byte[] bytes,
        PilotReadinessConfig config)
    {
        var manifest = EnterpriseReleaseSetManifest.Parse(bytes);
        var publicKey = new EnterpriseReleasePublicKey(
            config.LauncherTrust.ReleaseKeyId,
            config.LauncherTrust.ReleaseKeyX,
            config.LauncherTrust.ReleaseKeyY);
        EnterpriseReleaseSetValidator.Verify(
            manifest,
            new EnterpriseReleaseTrustPolicy
            {
                Product = EnterpriseReleaseSetContract.Product,
                Environment = EnterpriseReleaseSetContract.ProductionEnvironment,
                ExpectedChannel = config.Channel,
                CurrentStartupStubProtocol =
                    EnterpriseReleaseSetContract.CurrentStartupStubProtocol,
                ManifestOrigin = new Uri(
                    config.LauncherTrust.UpdateManifestOrigin,
                    UriKind.Absolute),
                ArtifactOrigin = new Uri(
                    config.LauncherTrust.UpdateArtifactOrigin,
                    UriKind.Absolute),
                TrustedKeys = [publicKey],
            },
            DateTimeOffset.UtcNow);
        return new PublisherWindowsPilotManifestVerification(
            manifest.ReleaseSetId,
            manifest.Generation,
            manifest.Sequence,
            Convert.ToHexStringLower(SHA256.HashData(bytes)),
            publicKey.KeyId);
    }

    private static void WriteManifestVerification(
        PublisherWindowsPilotManifestVerification verification) =>
        Console.WriteLine(JsonSerializer.Serialize(new
        {
            schemaVersion = 1,
            verificationType = "windows-pilot-release-manifest",
            status = "VERIFIED",
            releaseSetId = verification.ReleaseSetId,
            generation = verification.Generation,
            sequence = verification.Sequence,
            manifestSha256 = verification.ManifestSha256,
            releaseKeyId = verification.ReleaseKeyId,
        }, OutputJson));

    private static Dictionary<string, string> ParsePairs(
        string[] args,
        string command,
        params string[] required)
    {
        if (args.Length != 1 + required.Length * 2 || args[0] != command)
        {
            throw new ArgumentException(
                $"Usage: {command} {string.Join(' ', required.Select(value => value + " <absolute-path>"))}");
        }
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var index = 1; index < args.Length; index += 2)
        {
            if (!Path.IsPathFullyQualified(args[index + 1]))
            {
                throw new ArgumentException(
                    "Windows Pilot verification paths must be absolute.");
            }
            if (!required.Contains(args[index], StringComparer.Ordinal)
                || !values.TryAdd(args[index], Path.GetFullPath(args[index + 1])))
            {
                throw new ArgumentException("Windows Pilot verification argument is unknown or repeated.");
            }
        }
        if (required.Any(value => !values.ContainsKey(value)))
        {
            throw new ArgumentException("Windows Pilot verification argument is missing.");
        }
        return values;
    }

    private static byte[] ReadLocked(string path, int maximumBytes, string field)
    {
        PublisherPathGuard.RequireSafeExistingFile(path);
        using var stream = PublisherSafeFile.OpenLockedRead(path);
        if (stream.Length is <= 0 || stream.Length > maximumBytes)
        {
            throw new InvalidDataException($"{field} size is invalid.");
        }
        using var output = new MemoryStream(checked((int)stream.Length));
        stream.CopyTo(output);
        if (output.Length != stream.Length)
        {
            throw new IOException($"{field} changed while it was read.");
        }
        return output.ToArray();
    }

    private static void RequireIndependentTrust(
        PublisherWindowsPilotEvidenceTrust trust,
        PilotReadinessConfig config)
    {
        var runtime = PublisherRuntimeAdmissionTrustResolver.ResolveProduction();
        var plugin = PublisherPluginAdmissionTrustResolver.ResolveProduction();
        var journal = PublisherPluginPromotionJournalTrustResolver.ResolveProduction();
        var brand = PublisherBrandAuthorizationTrustResolver.ResolveProduction();
        var lease = PublisherLeaseVerificationTrustResolver.ResolveProduction();
        var localData =
            PublisherLocalDataCompatibilityCertificationTrustResolver.ResolveProduction();
        trust.RequireIndependentFrom(
            (config.LauncherTrust.ReleaseKeyId, config.LauncherTrust.ReleaseKeyX,
                config.LauncherTrust.ReleaseKeyY, "release-signing"),
            (runtime.KeyId, runtime.X, runtime.Y, "runtime-admission"),
            (plugin.KeyId, plugin.X, plugin.Y, "plugin-admission"),
            (journal.KeyId, journal.X, journal.Y, "plugin-journal"),
            (brand.KeyId, brand.X, brand.Y, "brand-authorization"),
            (lease.KeyId, lease.X, lease.Y, "lease"),
            (localData.KeyId, localData.X, localData.Y, "local-data-certification"));
    }
}

internal sealed record PublisherWindowsPilotManifestVerification(
    string ReleaseSetId,
    long Generation,
    long Sequence,
    string ManifestSha256,
    string ReleaseKeyId);

internal static class PublisherWindowsPilotEvidenceJson
{
    public static JsonSerializerOptions Options { get; } = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };
}
