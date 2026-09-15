using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Ensou.Dsh.Enterprise.Client;
using Microsoft.AspNetCore.Http;

namespace Ensou.Dsh.Enterprise.DevelopmentE2ETests;

// A test-owned nginx auth-request equivalent. Only the real control API can
// authorize a download; this adapter never creates a successful decision.
internal sealed class DevelopmentFeedAuthorizationForwarder : IDisposable
{
    private const string InternalPath = "/internal/v2/feed-authorization";
    private readonly HttpClient _client;
    private readonly Uri _endpoint;
    private string? _internalSecret;
    private int _attempts;
    private readonly ConcurrentQueue<DevelopmentFeedAuthorizationObservation> _accepted = new();

    public DevelopmentFeedAuthorizationForwarder(Uri controlOrigin, string certificateSha256, string internalSecret)
    {
        ValidateSecret(internalSecret);
        RequireControlOrigin(controlOrigin);
        _client = CreatePinnedClient(controlOrigin, certificateSha256);
        _endpoint = new Uri(controlOrigin, InternalPath);
        _internalSecret = internalSecret;
    }

    // Injected transport is confined to this test assembly, never the Launcher.
    internal DevelopmentFeedAuthorizationForwarder(HttpClient client, string internalSecret)
    {
        ArgumentNullException.ThrowIfNull(client);
        ValidateSecret(internalSecret);
        RequireControlOrigin(client.BaseAddress!);
        _client = client;
        _endpoint = new Uri(client.BaseAddress!, InternalPath);
        _internalSecret = internalSecret;
    }

    public IReadOnlyList<DevelopmentFeedAuthorizationObservation> Accepted => _accepted.ToArray();

    public async Task<DevelopmentFeedAuthorizationResult> AuthorizeAsync(
        Uri originalUri, IHeaderDictionary headers, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_internalSecret is null, this);
        if (!AllowedFeedUri(originalUri)) return Denied(403);
        if (new[]
            {
                EnterpriseUpdateFeedAuthorizationWire.OriginalFeedUriHeaderName,
                EnterpriseUpdateFeedAuthorizationWire.InternalAuthorizationHeaderName,
                EnterpriseUpdateFeedAuthorizationWire.RequestIdHeaderName,
                EnterpriseUpdateFeedAuthorizationWire.DecisionHeaderName,
                EnterpriseUpdateFeedAuthorizationWire.ErrorHeaderName,
                EnterpriseUpdateFeedAuthorizationWire.SharedCacheHeaderName,
            }.Any(headers.ContainsKey)
            || !SingleIncoming(headers, "Authorization", out var authorization)
            || !authorization.StartsWith("DPoP ", StringComparison.Ordinal)
            || authorization.Length <= 5 || authorization[5..].Any(char.IsWhiteSpace)
            || !SingleIncoming(headers, "DPoP", out var proof)) return Denied(401);

        // A bounded test lane has no reason to perform hundreds of downloads.
        if (Interlocked.Increment(ref _attempts) > 256) return Denied(503);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(10));
        using var request = new HttpRequestMessage(HttpMethod.Get, _endpoint);
        request.Headers.TryAddWithoutValidation("Authorization", authorization);
        request.Headers.TryAddWithoutValidation("DPoP", proof);
        request.Headers.Add(EnterpriseUpdateFeedAuthorizationWire.OriginalFeedUriHeaderName, originalUri.AbsoluteUri);
        request.Headers.Add(EnterpriseUpdateFeedAuthorizationWire.InternalAuthorizationHeaderName, _internalSecret);
        try
        {
            // Never retry a DPoP proof: a failed observation can already have
            // consumed its jti in the real server transaction.
            using var response = await _client.SendAsync(request,
                HttpCompletionOption.ResponseHeadersRead, deadline.Token).ConfigureAwait(false);
            if (response.StatusCode != HttpStatusCode.NoContent)
            {
                var status = response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden
                    ? (int)response.StatusCode : 503;
                var result = Denied(status);
                if (SingleResponse(response.Headers, EnterpriseUpdateFeedAuthorizationWire.ErrorHeaderName, out var error)
                    && EnterpriseUpdateFeedAuthorizationWire.IsToken(error, 128))
                    result.Headers[EnterpriseUpdateFeedAuthorizationWire.ErrorHeaderName] = error;
                return result;
            }
            if (!PrivateNoStore(response)
                || !Exact(response, "Vary", "Authorization")
                || !Exact(response, "Pragma", "no-cache")
                || !Exact(response, "X-Content-Type-Options", "nosniff")
                || !Exact(response, EnterpriseUpdateFeedAuthorizationWire.SharedCacheHeaderName, "bypass")
                || response.Headers.Contains(EnterpriseUpdateFeedAuthorizationWire.ErrorHeaderName)
                || response.Headers.Contains(EnterpriseUpdateFeedAuthorizationWire.InternalAuthorizationHeaderName)
                || response.Headers.TransferEncoding.Count != 0
                || response.Content.Headers.ContentLength is > 0
                || !SingleResponse(response.Headers, EnterpriseUpdateFeedAuthorizationWire.DecisionHeaderName, out var value))
                return Denied(503);
            var decision = EnterpriseUpdateFeedAuthorizationWire.ParseDecision(value);
            await using var body = await response.Content.ReadAsStreamAsync(deadline.Token).ConfigureAwait(false);
            if (await body.ReadAsync(new byte[1], deadline.Token).ConfigureAwait(false) != 0)
                return Denied(503);
            var accepted = PrivateHeaders();
            accepted[EnterpriseUpdateFeedAuthorizationWire.SharedCacheHeaderName] = "bypass";
            accepted[EnterpriseUpdateFeedAuthorizationWire.DecisionHeaderName] = value;
            _accepted.Enqueue(new(originalUri, decision.RequestId, decision.BindingId, decision.PolicyId, decision.PolicyVersion));
            return new(204, accepted, true);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception exception) when (exception is HttpRequestException or IOException
            or OperationCanceledException or EnterpriseUpdateFeedProtocolException or ArgumentException)
        {
            return Denied(503);
        }
    }

    public void Dispose()
    {
        _internalSecret = null;
        _client.Dispose();
    }

    private static DevelopmentFeedAuthorizationResult Denied(int status) => new(status, PrivateHeaders(), false);
    private static Dictionary<string, string> PrivateHeaders() => new(StringComparer.OrdinalIgnoreCase)
    {
        ["Cache-Control"] = "private, no-store", ["Vary"] = "Authorization",
        ["Pragma"] = "no-cache", ["X-Content-Type-Options"] = "nosniff",
    };
    private static bool Exact(HttpResponseMessage response, string name, string expected) =>
        SingleResponse(response.Headers, name, out var value) && value == expected;
    private static bool PrivateNoStore(HttpResponseMessage response) =>
        SingleResponse(response.Headers, "Cache-Control", out var value)
        && value.Split(',').Select(x => x.Trim()).OrderBy(x => x, StringComparer.Ordinal)
            .SequenceEqual(new[] { "no-store", "private" }, StringComparer.Ordinal);
    private static bool SingleResponse(HttpResponseHeaders headers, string name, out string value)
    {
        value = string.Empty;
        if (!headers.TryGetValues(name, out var values)) return false;
        var items = values.Take(2).ToArray();
        if (items.Length != 1 || !SafeHeader(items[0])) return false;
        value = items[0];
        return true;
    }
    private static bool SingleIncoming(IHeaderDictionary headers, string name, out string value)
    {
        value = string.Empty;
        if (!headers.TryGetValue(name, out var values) || values.Count != 1 || !SafeHeader(values[0])
            || values[0]!.Contains(',')) return false;
        value = values[0]!;
        return true;
    }
    private static bool SafeHeader(string? value) => value is { Length: > 0 and <= 8192 }
        && value.All(character => character is >= ' ' and <= '~');

    private static bool AllowedFeedUri(Uri uri)
    {
        if (!uri.IsAbsoluteUri || uri.Scheme != "https" || uri.IdnHost != "updates.example" || uri.Port != 443
            || uri.UserInfo.Length != 0 || uri.Query.Length != 0 || uri.Fragment.Length != 0
            || uri.OriginalString != uri.AbsoluteUri || uri.OriginalString.Contains('%') || uri.OriginalString.Contains('\\'))
            return false;
        if (uri.AbsolutePath == "/v2/channels/lab/release-set.v2.json") return true;
        var parts = uri.AbsolutePath.Split('/');
        return parts.Length == 5 && parts[0] == "" && parts[1] == "v2" && parts[2] == "releases"
            && EnterpriseUpdateFeedAuthorizationWire.IsToken(parts[3], 128)
            && EnterpriseUpdateFeedAuthorizationWire.IsToken(parts[4], 256)
            && parts[3] is not "." and not ".." && parts[4] is not "." and not "..";
    }

    private static void ValidateSecret(string value)
    {
        if (value is not { Length: 43 } || value.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not '-' and not '_'))
            throw new ArgumentException("A canonical 32-byte internal test secret is required.");
        var bytes = Convert.FromBase64String(value.Replace('-', '+').Replace('_', '/') + "=");
        try
        {
            if (bytes.Length != 32 || Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_') != value)
                throw new ArgumentException("The internal test secret is not canonical.");
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    private static void RequireControlOrigin(Uri origin)
    {
        if (origin is null || !origin.IsAbsoluteUri || origin.Scheme != "https" || origin.Port <= 0
            || origin.UserInfo.Length != 0 || origin.Query.Length != 0 || origin.Fragment.Length != 0
            || origin.AbsolutePath != "/" || origin.OriginalString != origin.AbsoluteUri
            || (origin.IdnHost != "localhost" && (!IPAddress.TryParse(origin.IdnHost.Trim('[', ']'), out var address)
                || !IPAddress.IsLoopback(address))))
            throw new ArgumentException("The control API must be an exact HTTPS loopback origin.");
    }

    private static HttpClient CreatePinnedClient(Uri origin, string certificateSha256)
    {
        if (certificateSha256.Length != 64 || certificateSha256.Any(c => !Uri.IsHexDigit(c)))
            throw new ArgumentException("A SHA-256 control TLS pin is required.");
        var pin = Convert.FromHexString(certificateSha256);
        var address = origin.IdnHost == "localhost" ? IPAddress.Loopback : IPAddress.Parse(origin.IdnHost.Trim('[', ']'));
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false, UseProxy = false, UseCookies = false,
            AutomaticDecompression = DecompressionMethods.None, MaxResponseHeadersLength = 16,
            ConnectTimeout = TimeSpan.FromSeconds(5), MaxConnectionsPerServer = 2,
            ConnectCallback = async (context, cancellationToken) =>
            {
                if (context.InitialRequestMessage.RequestUri != new Uri(origin, InternalPath)
                    || context.DnsEndPoint.Host != origin.IdnHost.Trim('[', ']') || context.DnsEndPoint.Port != origin.Port)
                    throw new HttpRequestException("Control authorization destination escaped its pinned loopback origin.");
                var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                try
                {
                    await socket.ConnectAsync(address, origin.Port, cancellationToken).ConfigureAwait(false);
                    return new NetworkStream(socket, ownsSocket: true);
                }
                catch { socket.Dispose(); throw; }
            },
            SslOptions = new SslClientAuthenticationOptions
            {
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                RemoteCertificateValidationCallback = (_, certificate, _, errors) =>
                {
                    if (certificate is null || (errors & ~SslPolicyErrors.RemoteCertificateChainErrors) != SslPolicyErrors.None)
                        return false;
                    using var leaf = X509CertificateLoader.LoadCertificate(certificate.Export(X509ContentType.Cert));
                    return CryptographicOperations.FixedTimeEquals(SHA256.HashData(leaf.RawData), pin)
                        && DateTime.UtcNow >= leaf.NotBefore.ToUniversalTime() && DateTime.UtcNow <= leaf.NotAfter.ToUniversalTime()
                        && leaf.MatchesHostname(origin.IdnHost.Trim('[', ']'), allowWildcards: false, allowCommonName: false);
                },
            },
        };
        return new HttpClient(handler) { BaseAddress = origin, Timeout = TimeSpan.FromSeconds(10) };
    }
}

internal sealed record DevelopmentFeedAuthorizationResult(int StatusCode, Dictionary<string, string> Headers, bool Authorized);
internal sealed record DevelopmentFeedAuthorizationObservation(Uri Uri, Guid RequestId, Guid BindingId, string PolicyId, long PolicyVersion);
