using System.Net;
using System.Net.Http.Headers;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;

namespace Ensou.Dsh.Enterprise.DevelopmentE2ETests;

internal static class DevelopmentFeedAuthorizationForwarderTests
{
    private static readonly Uri ManifestUri = new(
        "https://updates.example/v2/channels/lab/release-set.v2.json");
    private static readonly Uri ControlUri = new(
        "https://127.0.0.1:4443/internal/v2/feed-authorization");
    private const string AccessToken = "access-token-for-forwarder-contract-123456";
    private const string Dpop = "dpop-proof-for-forwarder-contract-123456";
    private static readonly string InternalSecret = Convert.ToBase64String(new byte[32])
        .TrimEnd('=').Replace('+', '-').Replace('/', '_');
    private const string Decision =
        "v=2;decision=PRIVATE_STABLE;request_id=00000000-0000-4000-8000-000000000001;"
        + "binding_id=00000000-0000-4000-8000-000000000002;policy_id=stable-private-pilot-2026;"
        + "policy_version=7";

    internal static async Task<int> RunAsync()
    {
        var passed = 0;
        await AcceptedResponseForwardsExactHeadersAsync().ConfigureAwait(false);
        passed++;
        await MissingOrDuplicateHeadersAreRejectedBeforeApiAsync().ConfigureAwait(false);
        passed++;
        await CallerAuthorizationHeaderSmugglingIsRejectedAsync().ConfigureAwait(false);
        passed++;
        await MalformedSecretOrOriginIsRejectedBeforeApiAsync().ConfigureAwait(false);
        passed++;
        await MalformedAcceptedResponseFailsClosedAsync().ConfigureAwait(false);
        passed++;
        await ApiFailureIsNotRetriedAsync().ConfigureAwait(false);
        passed++;
        await TransportFailureIsNotRetriedAsync().ConfigureAwait(false);
        passed++;
        await DeniedResponseDoesNotAuthorizeOrCarryBytesAsync().ConfigureAwait(false);
        passed++;
        await RealHttpsFixtureUsesAuthorizationDecisionAsync().ConfigureAwait(false);
        passed++;
        return passed;
    }

    private static async Task AcceptedResponseForwardsExactHeadersAsync()
    {
        HttpRequestMessage? captured = null;
        using var client = NewClient(request =>
        {
            captured = request;
            var response = new HttpResponseMessage(HttpStatusCode.NoContent)
            {
                RequestMessage = request,
            };
            response.Headers.CacheControl = new CacheControlHeaderValue
            {
                Private = true,
                NoStore = true,
            };
            response.Headers.Vary.Add("Authorization");
            response.Headers.Pragma.ParseAdd("no-cache");
            response.Headers.TryAddWithoutValidation("X-Content-Type-Options", "nosniff");
            response.Headers.TryAddWithoutValidation(
                "X-Ensou-Feed-Authorization", Decision);
            response.Headers.TryAddWithoutValidation("X-Ensou-Shared-Cache", "bypass");
            return response;
        });
        using var forwarder = new DevelopmentFeedAuthorizationForwarder(client, InternalSecret);
        var headers = NewHeaders();
        var result = await forwarder.AuthorizeAsync(ManifestUri, headers)
            .ConfigureAwait(false);

        Assert(result.Authorized, "Valid authorization response was not accepted.");
        Assert(captured?.Method == HttpMethod.Get, "Forwarded method was not GET.");
        Assert(captured?.RequestUri == ControlUri, "Forwarded URI was not the loopback API URI.");
        Assert(captured.Headers.GetValues("X-Ensou-Original-Feed-Uri").Single()
            == ManifestUri.AbsoluteUri, "Original feed URI was not forwarded exactly.");
        Assert(captured?.Headers.Authorization?.Scheme == "DPoP"
            && captured.Headers.Authorization.Parameter == AccessToken,
            "Authorization was not forwarded exactly.");
        Assert(captured.Headers.GetValues("DPoP").Single() == Dpop,
            "DPoP was not forwarded exactly.");
        Assert(captured.Headers.GetValues("X-Ensou-Internal-Feed-Authorization").Single()
            == InternalSecret, "Internal secret was not server-side injected.");
        Assert(result.Headers["X-Ensou-Feed-Authorization"] == Decision,
            "Accepted decision was not returned.");
    }

    private static async Task CallerAuthorizationHeaderSmugglingIsRejectedAsync()
    {
        var calls = 0;
        using var client = NewClient(_ =>
        {
            calls++;
            return ValidResponse(_);
        });
        using var forwarder = new DevelopmentFeedAuthorizationForwarder(client, InternalSecret);
        foreach (var name in new[]
                 {
                     "X-Ensou-Internal-Feed-Authorization",
                     "X-Ensou-Feed-Authorization",
                     "X-Ensou-Feed-Authorization-Error",
                     "X-Ensou-Feed-Request-Id",
                 })
        {
            var headers = NewHeaders();
            headers[name] = "caller-controlled";
            var result = await forwarder.AuthorizeAsync(ManifestUri, headers)
                .ConfigureAwait(false);
            Assert(!result.Authorized, $"Caller-supplied {name} was accepted.");
        }
        Assert(calls == 0, "Caller authorization header smuggling reached the API.");
    }

    private static async Task MalformedSecretOrOriginIsRejectedBeforeApiAsync()
    {
        var constructorRejected = false;
        using (var invalidClient = NewClient(_ =>
                   throw new InvalidOperationException("API must not be called.")))
        {
            try
            {
                using var invalid = new DevelopmentFeedAuthorizationForwarder(invalidClient, "not-a-secret");
            }
            catch (ArgumentException)
            {
                constructorRejected = true;
            }
        }
        Assert(constructorRejected, "Malformed internal secret was accepted.");

        using var client = NewClient(_ =>
            throw new InvalidOperationException("API must not be called."));
        using var forwarder = new DevelopmentFeedAuthorizationForwarder(client, InternalSecret);
        var result = await forwarder.AuthorizeAsync(
                new Uri("http://updates.example/v2/channels/lab/release-set.v2.json"),
                NewHeaders())
            .ConfigureAwait(false);
        Assert(!result.Authorized, "Malformed origin was accepted.");
    }

    private static async Task MissingOrDuplicateHeadersAreRejectedBeforeApiAsync()
    {
        var calls = 0;
        using var client = NewClient(_ =>
        {
            calls++;
            return new HttpResponseMessage(HttpStatusCode.NoContent);
        });
        using var forwarder = new DevelopmentFeedAuthorizationForwarder(client, InternalSecret);

        var missing = new HeaderDictionary
        {
            ["Authorization"] = "DPoP " + AccessToken,
        };
        var missingResult = await forwarder.AuthorizeAsync(ManifestUri, missing)
            .ConfigureAwait(false);
        Assert(!missingResult.Authorized, "Missing DPoP was accepted.");

        var duplicate = NewHeaders();
        duplicate["DPoP"] = new StringValues([Dpop, Dpop]);
        var duplicateResult = await forwarder.AuthorizeAsync(ManifestUri, duplicate)
            .ConfigureAwait(false);
        Assert(!duplicateResult.Authorized, "Duplicate DPoP was accepted.");
        Assert(calls == 0, "Malformed caller headers reached the API.");
    }

    private static async Task MalformedAcceptedResponseFailsClosedAsync()
    {
        foreach (var responseFactory in new Func<HttpRequestMessage, HttpResponseMessage>[]
                 {
                     request => ValidResponse(request, HttpStatusCode.OK),
                     request => Response(HttpStatusCode.NoContent, request,
                        includeCacheHeaders: false, includeDecision: true),
                     request => Response(HttpStatusCode.NoContent, request,
                         includeCacheHeaders: true, includeDecision: false),
                     request => Response(HttpStatusCode.NoContent, request,
                         includeCacheHeaders: true, includeDecision: true, body: [1]),
                 })
        {
            using var client = NewClient(responseFactory);
            using var forwarder = new DevelopmentFeedAuthorizationForwarder(client, InternalSecret);
            var result = await forwarder.AuthorizeAsync(ManifestUri, NewHeaders())
                .ConfigureAwait(false);
            Assert(!result.Authorized, "Malformed accepted response was admitted.");
        }
    }

    private static async Task ApiFailureIsNotRetriedAsync()
    {
        var calls = 0;
        using var client = NewClient(request =>
        {
            calls++;
            return new HttpResponseMessage(HttpStatusCode.ServiceUnavailable)
            {
                RequestMessage = request,
            };
        });
        using var forwarder = new DevelopmentFeedAuthorizationForwarder(client, InternalSecret);
        var result = await forwarder.AuthorizeAsync(ManifestUri, NewHeaders())
            .ConfigureAwait(false);
        Assert(!result.Authorized, "API failure was treated as authorization.");
        Assert(calls == 1, "API failure was retried.");
    }

    private static async Task TransportFailureIsNotRetriedAsync()
    {
        var calls = 0;
        using var client = NewClient(_ =>
        {
            calls++;
            throw new HttpRequestException("injected transport failure");
        });
        using var forwarder = new DevelopmentFeedAuthorizationForwarder(client, InternalSecret);
        var result = await forwarder.AuthorizeAsync(ManifestUri, NewHeaders())
            .ConfigureAwait(false);
        Assert(!result.Authorized, "Transport failure was treated as authorization.");
        Assert(calls == 1, "Transport failure was retried.");
    }

    private static async Task DeniedResponseDoesNotAuthorizeOrCarryBytesAsync()
    {
        using var client = NewClient(request =>
            new HttpResponseMessage(HttpStatusCode.Forbidden)
            {
                RequestMessage = request,
                Content = new ByteArrayContent(Array.Empty<byte>()),
            });
        using var forwarder = new DevelopmentFeedAuthorizationForwarder(client, InternalSecret);
        var result = await forwarder.AuthorizeAsync(ManifestUri, NewHeaders())
            .ConfigureAwait(false);
        Assert(!result.Authorized, "Denied authorization was accepted.");
        Assert(!result.Headers.ContainsKey("X-Ensou-Feed-Authorization"),
            "Denied response exposed a decision header.");
        Assert(!result.Headers.ContainsKey("X-Ensou-Internal-Feed-Authorization"),
            "Denied response exposed the internal secret.");
    }

    private static async Task RealHttpsFixtureUsesAuthorizationDecisionAsync()
    {
        var manifestBytes = new byte[] { 0x6c, 0x61, 0x62, 0x2d, 0x6d, 0x61, 0x6e, 0x69, 0x66, 0x65, 0x73, 0x74 };
        using var deniedControl = NewClient(request =>
            Response(HttpStatusCode.Forbidden, request, includeCacheHeaders: true, includeDecision: false));
        using var deniedForwarder = new DevelopmentFeedAuthorizationForwarder(
            deniedControl, InternalSecret);
        await using (var deniedServer = await DevelopmentHttpsArtifactServer.StartAsync(
                         new Dictionary<Uri, byte[]> { [ManifestUri] = manifestBytes },
                         authorization: deniedForwarder).ConfigureAwait(false))
        using (var deniedClient = deniedServer.CreateClient())
        {
            using var missing = await deniedClient.GetAsync(ManifestUri).ConfigureAwait(false);
            Assert(missing.StatusCode == HttpStatusCode.Unauthorized,
                "Missing credentials did not return 401.");
            using var denied = await SendAuthorizedAsync(deniedClient).ConfigureAwait(false);
            Assert(denied.StatusCode == HttpStatusCode.Forbidden,
                "Denied credentials did not return 403.");
            Assert(deniedServer.SuccessfulRequests.Count == 0,
                "Denied HTTPS fixture wrote artifact bytes.");
        }

        using var acceptedControl = NewClient(request => ValidResponse(request));
        using var acceptedForwarder = new DevelopmentFeedAuthorizationForwarder(
            acceptedControl, InternalSecret);
        await using var acceptedServer = await DevelopmentHttpsArtifactServer.StartAsync(
            new Dictionary<Uri, byte[]> { [ManifestUri] = manifestBytes },
            authorization: acceptedForwarder).ConfigureAwait(false);
        using var acceptedClient = acceptedServer.CreateClient();
        using var response = await SendAuthorizedAsync(acceptedClient).ConfigureAwait(false);
        Assert(response.StatusCode == HttpStatusCode.OK,
            "Accepted HTTPS fixture did not return 200.");
        Assert((await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false))
            .AsSpan().SequenceEqual(manifestBytes),
            "Accepted HTTPS fixture bytes differed.");
        Assert(response.Headers.GetValues("X-Ensou-Feed-Authorization").Single() == Decision,
            "Accepted HTTPS fixture did not forward the authorization decision.");
        Assert(acceptedServer.SuccessfulRequests.Count == 1,
            "Accepted HTTPS fixture did not record exactly one request.");
        Assert(acceptedServer.AuthorizedRequests.Count == 1,
            "Accepted authorization decision was not recorded.");
        Assert(acceptedServer.AuthorizedRequests[0].Uri == ManifestUri,
            "Accepted decision URI differed from the original feed URI.");
    }

    private static Task<HttpResponseMessage> SendAuthorizedAsync(HttpClient client)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, ManifestUri);
        request.Headers.Authorization = new AuthenticationHeaderValue("DPoP", AccessToken);
        request.Headers.TryAddWithoutValidation("DPoP", Dpop);
        return client.SendAsync(request);
    }

    private static HttpClient NewClient(Func<HttpRequestMessage, HttpResponseMessage> factory) =>
        new(new DelegateHandler(factory))
        {
            BaseAddress = new Uri("https://127.0.0.1:4443/"),
        };

    private static HeaderDictionary NewHeaders() => new()
    {
        ["Authorization"] = "DPoP " + AccessToken,
        ["DPoP"] = Dpop,
    };

    private static HttpResponseMessage Response(
        HttpStatusCode status,
        HttpRequestMessage request,
        bool includeCacheHeaders,
        bool includeDecision,
        byte[]? body = null)
    {
        var response = new HttpResponseMessage(status)
        {
            RequestMessage = request,
            Content = new ByteArrayContent(body ?? Array.Empty<byte>()),
        };
        response.Headers.Pragma.ParseAdd("no-cache");
        response.Headers.TryAddWithoutValidation("X-Content-Type-Options", "nosniff");
        if (includeCacheHeaders)
        {
            response.Headers.CacheControl = new CacheControlHeaderValue
            {
                Private = true,
                NoStore = true,
            };
            response.Headers.Vary.Add("Authorization");
            response.Headers.TryAddWithoutValidation("X-Ensou-Shared-Cache", "bypass");
        }
        if (includeDecision)
        {
            response.Headers.TryAddWithoutValidation(
                "X-Ensou-Feed-Authorization", Decision);
        }
        return response;
    }

    private static HttpResponseMessage ValidResponse(
        HttpRequestMessage request,
        HttpStatusCode status = HttpStatusCode.NoContent) =>
        Response(status, request, includeCacheHeaders: true, includeDecision: true);

    private sealed class DelegateHandler(
        Func<HttpRequestMessage, HttpResponseMessage> factory) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) =>
            Task.FromResult(factory(request));
    }

    private static void Assert([System.Diagnostics.CodeAnalysis.DoesNotReturnIf(false)] bool condition, string message)
    {
        if (!condition) throw new InvalidDataException(message);
    }
}
