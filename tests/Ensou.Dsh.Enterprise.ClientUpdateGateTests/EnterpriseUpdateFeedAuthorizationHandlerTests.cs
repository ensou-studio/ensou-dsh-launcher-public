using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Ensou.Dsh.Enterprise.Client;

namespace Ensou.Dsh.Enterprise.ClientUpdateGateTests;

internal static class EnterpriseUpdateFeedAuthorizationHandlerTests
{
    private const string BindingId = "22222222-3333-4444-8555-666666666666";
    private const string AccessToken =
        "gIGCg4SFhoeIiYqLjI2Oj5CRkpOUlZaXmJmam5ydnp8";
    private static readonly DateTimeOffset Now =
        DateTimeOffset.Parse("2026-08-26T02:00:00Z");
    private static readonly Uri ManifestUri = new(
        "https://updates.example.test/v2/channels/stable/release-set.v2.json");
    private static readonly Uri ArtifactOrigin = new("https://updates.example.test/");
    private static readonly Uri ArtifactUri = new(
        "https://updates.example.test/v2/releases/release-2026/enterprise.zip");

    public static async Task RunAsync()
    {
        await PrivateLaneUsesFreshProofAndStripsHeadersAsync().ConfigureAwait(false);
        await PublicLanePreservesPublicBytesAsync().ConfigureAwait(false);
        await RequestTargetsAndCallerHeadersAreExactAsync().ConfigureAwait(false);
        await TokenLifetimeIsBoundedAsync().ConfigureAwait(false);
        await AuthorizationDenialsAreTypedAsync().ConfigureAwait(false);
        await RedirectAndResponseMetadataFailClosedAsync().ConfigureAwait(false);
        await ManifestArtifactLaneConfusionFailsClosedAsync().ConfigureAwait(false);
#if ENTERPRISE_DEVELOPMENT_E2E
        DevelopmentE2ETransportIsLimitedToPinnedReservedOrigins();
#endif
    }

#if ENTERPRISE_DEVELOPMENT_E2E
    private static void DevelopmentE2ETransportIsLimitedToPinnedReservedOrigins()
    {
        const string certificateSha256 =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        var previousCertificateSha256 = Environment.GetEnvironmentVariable(
            "ENSOU_DSH_E2E_UPDATE_TLS_CERT_SHA256");
        var previousLoopbackPort = Environment.GetEnvironmentVariable(
            "ENSOU_DSH_E2E_UPDATE_LOOPBACK_PORT");
        var manifestUri = new Uri(
            "https://updates.example/v2/channels/stable/release-set.v2.json");
        var labManifestUri = new Uri(
            "https://updates.example/v2/channels/lab/release-set.v2.json");
        var artifactOrigin = new Uri("https://updates.example/");
        try
        {
            Environment.SetEnvironmentVariable(
                "ENSOU_DSH_E2E_UPDATE_TLS_CERT_SHA256",
                certificateSha256);
            Environment.SetEnvironmentVariable(
                "ENSOU_DSH_E2E_UPDATE_LOOPBACK_PORT",
                "43123");

            AssertTrue(EnterpriseUpdateFeedTransport.IsDevelopmentE2EUpdateEndpoint(
                new Uri("https://updates.example/v2/channels/stable/release-set.v2.json")));
            AssertTrue(EnterpriseUpdateFeedTransport.IsDevelopmentE2EUpdateEndpoint(
                new Uri("https://artifacts.example/v2/releases/lab/runtime.zip")));
            AssertFalse(EnterpriseUpdateFeedTransport.IsDevelopmentE2EUpdateEndpoint(
                new Uri("http://updates.example/v2/channels/stable/release-set.v2.json")));
            AssertFalse(EnterpriseUpdateFeedTransport.IsDevelopmentE2EUpdateEndpoint(
                new Uri("https://updates.example:444/v2/channels/stable/release-set.v2.json")));
            AssertFalse(EnterpriseUpdateFeedTransport.IsDevelopmentE2EUpdateEndpoint(
                new Uri("https://updates.example.invalid/v2/channels/stable/release-set.v2.json")));

            using var keys = new EphemeralKeyStore();
            using var vault = new EnterpriseAccessTokenVault();
            vault.Install(BindingId, AccessToken, Now.AddMinutes(5));
            using var accepted = CreateDevelopmentE2ETransactionClient(
                manifestUri,
                artifactOrigin,
                keys,
                vault);
            using var labAccepted = CreateDevelopmentE2ETransactionClient(
                labManifestUri,
                artifactOrigin,
                keys,
                vault);
            AssertEqual(TimeSpan.FromHours(2), accepted.Timeout);
            AssertEqual(TimeSpan.FromHours(2), labAccepted.Timeout);

            Environment.SetEnvironmentVariable("ENSOU_DSH_E2E_UPDATE_LOOPBACK_PORT", "0");
            AssertThrows<InvalidOperationException>(() =>
            {
                using var ignored = CreateDevelopmentE2ETransactionClient(
                    manifestUri,
                    artifactOrigin,
                    keys,
                    vault);
            });

            Environment.SetEnvironmentVariable("ENSOU_DSH_E2E_UPDATE_LOOPBACK_PORT", "43123");
            Environment.SetEnvironmentVariable("ENSOU_DSH_E2E_UPDATE_TLS_CERT_SHA256", "not-a-pin");
            AssertThrows<InvalidOperationException>(() =>
            {
                using var ignored = CreateDevelopmentE2ETransactionClient(
                    manifestUri,
                    artifactOrigin,
                    keys,
                    vault);
            });

            Environment.SetEnvironmentVariable(
                "ENSOU_DSH_E2E_UPDATE_TLS_CERT_SHA256",
                certificateSha256);
            AssertThrows<ArgumentException>(() =>
            {
                using var ignored = CreateDevelopmentE2ETransactionClient(
                    new Uri("https://untrusted.example/v2/channels/stable/release-set.v2.json"),
                    new Uri("https://untrusted.example/"),
                    keys,
                    vault);
            });
            AssertThrows<ArgumentException>(() =>
            {
                using var ignored = CreateDevelopmentE2ETransactionClient(
                    new Uri("https://updates.example/v2/channels/preview/release-set.v2.json"),
                    artifactOrigin,
                    keys,
                    vault);
            });
            AssertThrows<ArgumentException>(() =>
            {
                using var ignored = CreateDevelopmentE2ETransactionClient(
                    new Uri("https://updates.example/v2/channels/lab/not-a-manifest.json"),
                    artifactOrigin,
                    keys,
                    vault);
            });
        }
        finally
        {
            Environment.SetEnvironmentVariable(
                "ENSOU_DSH_E2E_UPDATE_TLS_CERT_SHA256",
                previousCertificateSha256);
            Environment.SetEnvironmentVariable(
                "ENSOU_DSH_E2E_UPDATE_LOOPBACK_PORT",
                previousLoopbackPort);
        }
    }

    private static HttpClient CreateDevelopmentE2ETransactionClient(
        Uri manifestUri,
        Uri artifactOrigin,
        EphemeralKeyStore keys,
        EnterpriseAccessTokenVault vault)
    {
        return EnterpriseUpdateFeedTransport.CreateTransactionClient(
            manifestUri,
            artifactOrigin,
            new EnterpriseDpopProofFactory(keys, new FixedTimeProvider(Now)),
            vault,
            new FixedTimeProvider(Now));
    }

    private static void AssertThrows<TException>(Action action)
        where TException : Exception
    {
        try
        {
            action();
        }
        catch (TException)
        {
            return;
        }
        throw new InvalidOperationException($"Expected {typeof(TException).Name}.");
    }
#endif

    private static async Task PrivateLaneUsesFreshProofAndStripsHeadersAsync()
    {
        var proofs = new List<(string Jti, string Htu)>();
        var captured = new List<HttpRequestMessage>();
        var requestIndex = 0;
        using var context = CreateContext(request =>
        {
            captured.Add(request);
            proofs.Add(ReadProof(request));
            return AuthorizedResponse(
                request,
                EnterpriseUpdateFeedAuthorizationWire.PrivateStableDecision,
                ++requestIndex);
        });

        using var manifestRequest = new HttpRequestMessage(HttpMethod.Get, ManifestUri);
        using var manifestResponse = await context.Client.SendAsync(manifestRequest)
            .ConfigureAwait(false);
        AssertTrue(EnterpriseUpdateFeedAuthorizationWire.TryGetDecision(
            manifestResponse,
            out var manifestDecision));
        AssertTrue(manifestDecision!.IsPrivate);
        AssertFalse(manifestResponse.Headers.Contains(
            EnterpriseUpdateFeedAuthorizationWire.DecisionHeaderName));
        AssertFalse(manifestResponse.Headers.Contains(
            EnterpriseUpdateFeedAuthorizationWire.SharedCacheHeaderName));
        AssertEqual("private-head", await manifestResponse.Content.ReadAsStringAsync()
            .ConfigureAwait(false));

        using var artifactRequest = new HttpRequestMessage(HttpMethod.Get, ArtifactUri);
        artifactRequest.Headers.Range = new RangeHeaderValue(0, 15);
        using var artifactResponse = await context.Client.SendAsync(artifactRequest)
            .ConfigureAwait(false);
        AssertTrue(EnterpriseUpdateFeedAuthorizationWire.TryGetDecision(
            artifactResponse,
            out var artifactDecision));
        AssertTrue(artifactDecision!.IsPrivate);
        AssertEqual(2, proofs.Count);
        AssertEqual(ManifestUri.AbsoluteUri, proofs[0].Htu);
        AssertEqual(ArtifactUri.AbsoluteUri, proofs[1].Htu);
        AssertFalse(string.Equals(proofs[0].Jti, proofs[1].Jti, StringComparison.Ordinal));
        foreach (var request in captured)
        {
            AssertTrue(request.Headers.Authorization is null);
            AssertFalse(request.Headers.Contains("DPoP"));
        }
    }

    private static async Task PublicLanePreservesPublicBytesAsync()
    {
        using var context = CreateContext(request => AuthorizedResponse(
            request,
            EnterpriseUpdateFeedAuthorizationWire.PublicStableDecision,
            request.RequestUri == ManifestUri ? 1 : 2,
            body: "old-public-stable"));
        using var manifest = await context.Client.GetAsync(ManifestUri).ConfigureAwait(false);
        using var artifact = await context.Client.GetAsync(ArtifactUri).ConfigureAwait(false);
        AssertEqual("old-public-stable", await manifest.Content.ReadAsStringAsync()
            .ConfigureAwait(false));
        AssertEqual("old-public-stable", await artifact.Content.ReadAsStringAsync()
            .ConfigureAwait(false));
        AssertTrue(EnterpriseUpdateFeedAuthorizationWire.TryGetDecision(manifest, out var decision));
        AssertFalse(decision!.IsPrivate);
    }

    private static async Task RequestTargetsAndCallerHeadersAreExactAsync()
    {
        var calls = 0;
        using var context = CreateContext(request =>
        {
            calls++;
            return AuthorizedResponse(
                request,
                EnterpriseUpdateFeedAuthorizationWire.PrivateStableDecision,
                calls);
        });
        var invalid = new[]
        {
            new HttpRequestMessage(HttpMethod.Post, ManifestUri),
            new HttpRequestMessage(HttpMethod.Get, ManifestUri)
            {
                Content = new ByteArrayContent([0x01]),
            },
            new HttpRequestMessage(HttpMethod.Get, ManifestUri + "?candidate=true"),
            new HttpRequestMessage(
                HttpMethod.Get,
                "https://updates.example.test/v2/channels/pilot/release-set.v2.json"),
            new HttpRequestMessage(
                HttpMethod.Get,
                "https://updates.example.test/v2/releases/release-2026/sub/file.zip"),
            new HttpRequestMessage(
                HttpMethod.Get,
                "https://other.example.test/v2/releases/release-2026/file.zip"),
        };
        foreach (var request in invalid)
        {
            using (request)
            {
                await AssertThrowsAsync<EnterpriseUpdateFeedProtocolException>(
                    () => context.Client.SendAsync(request)).ConfigureAwait(false);
            }
        }

        foreach (var header in new[]
                 {
                     "Authorization",
                     "DPoP",
                     EnterpriseUpdateFeedAuthorizationWire.OriginalFeedUriHeaderName,
                     EnterpriseUpdateFeedAuthorizationWire.InternalAuthorizationHeaderName,
                     EnterpriseUpdateFeedAuthorizationWire.RequestIdHeaderName,
                     EnterpriseUpdateFeedAuthorizationWire.DecisionHeaderName,
                     EnterpriseUpdateFeedAuthorizationWire.ErrorHeaderName,
                     EnterpriseUpdateFeedAuthorizationWire.SharedCacheHeaderName,
                 })
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, ManifestUri);
            if (header == "Authorization")
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("DPoP", AccessToken);
            }
            else
            {
                request.Headers.TryAddWithoutValidation(header, "caller-controlled");
            }
            await AssertThrowsAsync<EnterpriseUpdateFeedProtocolException>(
                () => context.Client.SendAsync(request)).ConfigureAwait(false);
        }
        AssertEqual(0, calls);
    }

    private static async Task TokenLifetimeIsBoundedAsync()
    {
        var calls = 0;
        using var keys = new EphemeralKeyStore();
        using var vault = new EnterpriseAccessTokenVault();
        vault.Install(BindingId, AccessToken, Now.AddMinutes(11));
        using var client = new HttpClient(new EnterpriseUpdateFeedAuthorizationHandler(
            ManifestUri,
            ArtifactOrigin,
            new EnterpriseDpopProofFactory(keys, new FixedTimeProvider(Now)),
            vault,
            new DelegateHandler(request =>
            {
                calls++;
                return AuthorizedResponse(
                    request,
                    EnterpriseUpdateFeedAuthorizationWire.PrivateStableDecision,
                    calls);
            }),
            new FixedTimeProvider(Now)));
        await AssertThrowsAsync<EnterpriseAccessTokenUnavailableException>(
            () => client.GetAsync(ManifestUri)).ConfigureAwait(false);
        AssertEqual(0, calls);

        vault.Install(BindingId, AccessToken, Now);
        await AssertThrowsAsync<EnterpriseAccessTokenUnavailableException>(
            () => client.GetAsync(ManifestUri)).ConfigureAwait(false);
        AssertEqual(0, calls);
    }

    private static async Task AuthorizationDenialsAreTypedAsync()
    {
        using (var unauthorized = CreateContext(request => new HttpResponseMessage(
                   HttpStatusCode.Unauthorized)
               {
                   RequestMessage = request,
               }))
        {
            var exception = await AssertThrowsAsync<
                EnterpriseUpdateFeedAuthorizationDeniedException>(
                () => unauthorized.Client.GetAsync(ManifestUri)).ConfigureAwait(false);
            AssertEqual(HttpStatusCode.Unauthorized, exception.StatusCode);
            AssertTrue(exception.TokenCleared);
            AssertFalse(unauthorized.Vault.HasUsableToken(BindingId, Now));
            AssertFalse((Exception)exception is HttpRequestException);
        }

        using (var forbidden = CreateContext(request => new HttpResponseMessage(
                   HttpStatusCode.Forbidden)
               {
                   RequestMessage = request,
               }))
        {
            var exception = await AssertThrowsAsync<
                EnterpriseUpdateFeedAuthorizationDeniedException>(
                () => forbidden.Client.GetAsync(ManifestUri)).ConfigureAwait(false);
            AssertEqual(HttpStatusCode.Forbidden, exception.StatusCode);
            AssertFalse(exception.TokenCleared);
            AssertTrue(forbidden.Vault.HasUsableToken(BindingId, Now));
            AssertFalse((Exception)exception is HttpRequestException);
        }

        using (var unavailable = CreateContext(request => new HttpResponseMessage(
                   HttpStatusCode.ServiceUnavailable)
               {
                   RequestMessage = request,
               }))
        {
            var exception = await AssertThrowsAsync<
                EnterpriseUpdateFeedUnavailableException>(
                () => unavailable.Client.GetAsync(ManifestUri)).ConfigureAwait(false);
            AssertEqual(HttpStatusCode.ServiceUnavailable, exception.StatusCode);
            AssertTrue(unavailable.Vault.HasUsableToken(BindingId, Now));
            AssertFalse((Exception)exception is HttpRequestException);
        }
    }

    private static async Task RedirectAndResponseMetadataFailClosedAsync()
    {
        using (var productionTransport = EnterpriseUpdateFeedTransport
                   .CreateProductionTransport())
        {
            AssertFalse(productionTransport.AllowAutoRedirect);
            AssertFalse(productionTransport.UseCookies);
            AssertTrue(productionTransport.CheckCertificateRevocationList);
        }

        var redirectCalls = 0;
        HttpRequestMessage? redirectedRequest = null;
        using (var redirect = CreateContext(request =>
               {
                   redirectCalls++;
                   redirectedRequest = request;
                   return new HttpResponseMessage(HttpStatusCode.Redirect)
                   {
                       RequestMessage = request,
                       Headers = { Location = ArtifactUri },
                   };
               }))
        {
            await AssertThrowsAsync<EnterpriseUpdateFeedProtocolException>(
                () => redirect.Client.GetAsync(ManifestUri)).ConfigureAwait(false);
            AssertEqual(1, redirectCalls);
            AssertEqual(ManifestUri, redirectedRequest?.RequestUri);
            AssertTrue(redirectedRequest?.Headers.Authorization is null);
            AssertFalse(redirectedRequest!.Headers.Contains("DPoP"));
        }

        using (var missingMetadata = CreateContext(request => new HttpResponseMessage(
                   HttpStatusCode.OK)
               {
                   RequestMessage = request,
                   Content = new StringContent("candidate"),
               }))
        {
            await AssertThrowsAsync<EnterpriseUpdateFeedProtocolException>(
                () => missingMetadata.Client.GetAsync(ManifestUri)).ConfigureAwait(false);
        }

        using (var redirectedFinal = CreateContext(request => AuthorizedResponse(
                   new HttpRequestMessage(HttpMethod.Get, ArtifactUri),
                   EnterpriseUpdateFeedAuthorizationWire.PrivateStableDecision,
                   1)))
        {
            await AssertThrowsAsync<EnterpriseUpdateFeedProtocolException>(
                () => redirectedFinal.Client.GetAsync(ManifestUri)).ConfigureAwait(false);
        }
    }

    private static async Task ManifestArtifactLaneConfusionFailsClosedAsync()
    {
        using (var transactionReuse = CreateContext(request => AuthorizedResponse(
                   request,
                   EnterpriseUpdateFeedAuthorizationWire.PrivateStableDecision,
                   1)))
        {
            using var manifest = await transactionReuse.Client.GetAsync(ManifestUri)
                .ConfigureAwait(false);
            await AssertThrowsAsync<EnterpriseUpdateFeedTransactionConsumedException>(
                () => transactionReuse.Client.GetAsync(ManifestUri)).ConfigureAwait(false);
        }

        using (var publicThenPrivate = CreateContext(request => AuthorizedResponse(
                   request,
                   request.RequestUri == ManifestUri
                       ? EnterpriseUpdateFeedAuthorizationWire.PublicStableDecision
                       : EnterpriseUpdateFeedAuthorizationWire.PrivateStableDecision,
                   request.RequestUri == ManifestUri ? 1 : 2)))
        {
            using var manifest = await publicThenPrivate.Client.GetAsync(ManifestUri)
                .ConfigureAwait(false);
            await AssertThrowsAsync<EnterpriseUpdateFeedProtocolException>(
                () => publicThenPrivate.Client.GetAsync(ArtifactUri)).ConfigureAwait(false);
        }

        using (var artifactFirst = CreateContext(request => AuthorizedResponse(
                   request,
                   EnterpriseUpdateFeedAuthorizationWire.PrivateStableDecision,
                   1)))
        {
            await AssertThrowsAsync<EnterpriseUpdateFeedProtocolException>(
                () => artifactFirst.Client.GetAsync(ArtifactUri)).ConfigureAwait(false);
        }

        using (var policySwitch = CreateContext(request => AuthorizedResponse(
                   request,
                   EnterpriseUpdateFeedAuthorizationWire.PrivateStableDecision,
                   request.RequestUri == ManifestUri ? 1 : 2,
                   policyVersion: request.RequestUri == ManifestUri ? 7 : 8)))
        {
            using var manifest = await policySwitch.Client.GetAsync(ManifestUri)
                .ConfigureAwait(false);
            await AssertThrowsAsync<EnterpriseUpdateFeedProtocolException>(
                () => policySwitch.Client.GetAsync(ArtifactUri)).ConfigureAwait(false);
        }
    }

    private static TestContext CreateContext(
        Func<HttpRequestMessage, HttpResponseMessage> responseFactory)
    {
        var keys = new EphemeralKeyStore();
        var vault = new EnterpriseAccessTokenVault();
        vault.Install(BindingId, AccessToken, Now.AddMinutes(5));
        var handler = new EnterpriseUpdateFeedAuthorizationHandler(
            ManifestUri,
            ArtifactOrigin,
            new EnterpriseDpopProofFactory(keys, new FixedTimeProvider(Now)),
            vault,
            new DelegateHandler(responseFactory),
            new FixedTimeProvider(Now));
        return new TestContext(new HttpClient(handler), vault, keys);
    }

    private static HttpResponseMessage AuthorizedResponse(
        HttpRequestMessage request,
        string exposure,
        int requestNumber,
        string body = "private-head",
        long policyVersion = 7)
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            RequestMessage = request,
            Content = new StringContent(body, Encoding.UTF8, "application/octet-stream"),
        };
        response.Headers.CacheControl = new CacheControlHeaderValue
        {
            Private = true,
            NoStore = true,
        };
        response.Headers.Vary.Add("Authorization");
        response.Headers.TryAddWithoutValidation(
            EnterpriseUpdateFeedAuthorizationWire.SharedCacheHeaderName,
            EnterpriseUpdateFeedAuthorizationWire.SharedCacheBypass);
        response.Headers.TryAddWithoutValidation(
            EnterpriseUpdateFeedAuthorizationWire.DecisionHeaderName,
            EnterpriseUpdateFeedAuthorizationWire.FormatDecision(new(
                exposure,
                Guid.Parse($"00000000-0000-4000-8000-{requestNumber:000000000000}"),
                Guid.Parse(BindingId),
                "stable-private-pilot-2026",
                policyVersion)));
        return response;
    }

    private static (string Jti, string Htu) ReadProof(HttpRequestMessage request)
    {
        AssertEqual("DPoP", request.Headers.Authorization?.Scheme);
        AssertEqual(AccessToken, request.Headers.Authorization?.Parameter);
        var proof = request.Headers.GetValues("DPoP").Single();
        var parts = proof.Split('.');
        AssertEqual(3, parts.Length);
        using var payload = JsonDocument.Parse(DecodeBase64Url(parts[1]));
        AssertEqual("GET", payload.RootElement.GetProperty("htm").GetString());
        AssertEqual(
            request.RequestUri!.AbsoluteUri,
            payload.RootElement.GetProperty("htu").GetString());
        AssertEqual(
            EncodeBase64Url(SHA256.HashData(Encoding.ASCII.GetBytes(AccessToken))),
            payload.RootElement.GetProperty("ath").GetString());
        return (
            payload.RootElement.GetProperty("jti").GetString()!,
            payload.RootElement.GetProperty("htu").GetString()!);
    }

    private static byte[] DecodeBase64Url(string value)
    {
        var padding = (value.Length % 4) switch
        {
            0 => string.Empty,
            2 => "==",
            3 => "=",
            _ => throw new FormatException("Invalid base64url proof segment."),
        };
        return Convert.FromBase64String(
            value.Replace('-', '+').Replace('_', '/') + padding);
    }

    private static string EncodeBase64Url(ReadOnlySpan<byte> value) =>
        Convert.ToBase64String(value)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    private static async Task<TException> AssertThrowsAsync<TException>(Func<Task> action)
        where TException : Exception
    {
        try
        {
            await action().ConfigureAwait(false);
        }
        catch (TException exception)
        {
            return exception;
        }
        throw new InvalidOperationException($"Expected {typeof(TException).Name}.");
    }

    private static void AssertTrue(bool value)
    {
        if (!value)
        {
            throw new InvalidOperationException("Expected true.");
        }
    }

    private static void AssertFalse(bool value) => AssertTrue(!value);

    private static void AssertEqual<T>(T expected, T actual)
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
        {
            throw new InvalidOperationException($"Expected '{expected}', actual '{actual}'.");
        }
    }

    private sealed class TestContext(
        HttpClient client,
        EnterpriseAccessTokenVault vault,
        EphemeralKeyStore keys) : IDisposable
    {
        public HttpClient Client { get; } = client;
        public EnterpriseAccessTokenVault Vault { get; } = vault;

        public void Dispose()
        {
            Client.Dispose();
            Vault.Dispose();
            keys.Dispose();
        }
    }

    private sealed class DelegateHandler(
        Func<HttpRequestMessage, HttpResponseMessage> responseFactory)
        : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(responseFactory(request));
        }
    }

    private sealed class FixedTimeProvider(DateTimeOffset nowUtc) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => nowUtc;
    }

    private sealed class EphemeralKeyStore : IEnterpriseDeviceProofKeyStore, IDisposable
    {
        private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly EnterpriseDevicePublicIdentity _identity;

        public EphemeralKeyStore()
        {
            var parameters = _key.ExportParameters(false);
            var x = EncodeBase64Url(parameters.Q.X!);
            var y = EncodeBase64Url(parameters.Q.Y!);
            var canonical = $"{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}";
            _identity = new EnterpriseDevicePublicIdentity(
                "EC",
                "P-256",
                x,
                y,
                EncodeBase64Url(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))));
        }

        public EnterpriseDevicePublicIdentity GetOrCreatePublicIdentity() => _identity;

        public byte[] Sign(ReadOnlySpan<byte> payload) => _key.SignData(
            payload,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

        public void DeleteForSecurityReset()
        {
        }

        public void Dispose() => _key.Dispose();
    }
}
