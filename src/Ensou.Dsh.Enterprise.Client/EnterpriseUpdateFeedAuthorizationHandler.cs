using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Runtime.CompilerServices;
#if ENTERPRISE_DEVELOPMENT_E2E
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
#endif

namespace Ensou.Dsh.Enterprise.Client;

public static class EnterpriseUpdateFeedAuthorizationWire
{
    public const string OriginalFeedUriHeaderName = "X-Ensou-Original-Feed-Uri";
    public const string InternalAuthorizationHeaderName =
        "X-Ensou-Internal-Feed-Authorization";
    public const string RequestIdHeaderName = "X-Ensou-Feed-Request-Id";
    public const string DecisionHeaderName = "X-Ensou-Feed-Authorization";
    public const string ErrorHeaderName = "X-Ensou-Feed-Authorization-Error";
    public const string SharedCacheHeaderName = "X-Ensou-Shared-Cache";
    public const string SharedCacheBypass = "bypass";
    public const string PrivateStableDecision = "PRIVATE_STABLE";
    public const string PublicStableDecision = "PUBLIC_STABLE";

    private static readonly ConditionalWeakTable<
        HttpResponseMessage,
        EnterpriseUpdateFeedAuthorizationDecision> Decisions = new();

    public static bool TryGetDecision(
        HttpResponseMessage response,
        out EnterpriseUpdateFeedAuthorizationDecision? decision)
    {
        ArgumentNullException.ThrowIfNull(response);
        return Decisions.TryGetValue(response, out decision);
    }

    internal static void SetDecision(
        HttpResponseMessage response,
        EnterpriseUpdateFeedAuthorizationDecision decision)
    {
        Decisions.Remove(response);
        Decisions.Add(response, decision);
    }

    internal static EnterpriseUpdateFeedAuthorizationDecision ParseDecision(
        string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        if (value.Length > 512)
        {
            throw new EnterpriseUpdateFeedProtocolException(
                "Enterprise update-feed authorization decision is oversized.");
        }

        var fields = value.Split(';', StringSplitOptions.None);
        if (fields.Length != 6
            || fields[0] != "v=2"
            || !fields[1].StartsWith("decision=", StringComparison.Ordinal)
            || !fields[2].StartsWith("request_id=", StringComparison.Ordinal)
            || !fields[3].StartsWith("binding_id=", StringComparison.Ordinal)
            || !fields[4].StartsWith("policy_id=", StringComparison.Ordinal)
            || !fields[5].StartsWith("policy_version=", StringComparison.Ordinal))
        {
            throw new EnterpriseUpdateFeedProtocolException(
                "Enterprise update-feed authorization decision is not canonical.");
        }

        var exposure = fields[1]["decision=".Length..];
        var requestIdText = fields[2]["request_id=".Length..];
        var bindingIdText = fields[3]["binding_id=".Length..];
        var policyId = fields[4]["policy_id=".Length..];
        var policyVersionText = fields[5]["policy_version=".Length..];
        if (exposure is not PrivateStableDecision and not PublicStableDecision
            || !TryCanonicalUuid(requestIdText, out var requestId)
            || !TryCanonicalUuid(bindingIdText, out var bindingId)
            || !IsToken(policyId, 128)
            || !long.TryParse(
                policyVersionText,
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out var policyVersion)
            || policyVersion is <= 0 or > 9_007_199_254_740_991)
        {
            throw new EnterpriseUpdateFeedProtocolException(
                "Enterprise update-feed authorization decision fields are invalid.");
        }

        var decision = new EnterpriseUpdateFeedAuthorizationDecision(
            exposure,
            requestId,
            bindingId,
            policyId,
            policyVersion);
        if (!string.Equals(FormatDecision(decision), value, StringComparison.Ordinal))
        {
            throw new EnterpriseUpdateFeedProtocolException(
                "Enterprise update-feed authorization decision is not canonical.");
        }
        return decision;
    }

    public static string FormatDecision(
        EnterpriseUpdateFeedAuthorizationDecision decision)
    {
        ArgumentNullException.ThrowIfNull(decision);
        if (decision.Exposure is not PrivateStableDecision and not PublicStableDecision
            || decision.RequestId == Guid.Empty
            || decision.BindingId == Guid.Empty
            || !IsToken(decision.PolicyId, 128)
            || decision.PolicyVersion is <= 0 or > 9_007_199_254_740_991)
        {
            throw new ArgumentException(
                "Enterprise update-feed authorization decision fields are invalid.",
                nameof(decision));
        }
        return string.Create(
            CultureInfo.InvariantCulture,
            $"v=2;decision={decision.Exposure};request_id={decision.RequestId:D};binding_id={decision.BindingId:D};policy_id={decision.PolicyId};policy_version={decision.PolicyVersion}");
    }

    internal static bool IsToken(string? value, int maximumLength) =>
        value is { Length: > 0 }
        && value.Length <= maximumLength
        && char.IsAsciiLetterOrDigit(value[0])
        && value.All(character => char.IsAsciiLetterOrDigit(character)
            || character is '.' or '_' or '+' or '-');

    private static bool TryCanonicalUuid(string value, out Guid parsed) =>
        Guid.TryParseExact(value, "D", out parsed)
        && string.Equals(parsed.ToString("D"), value, StringComparison.Ordinal);
}

public sealed record EnterpriseUpdateFeedAuthorizationDecision(
    string Exposure,
    Guid RequestId,
    Guid BindingId,
    string PolicyId,
    long PolicyVersion)
{
    public bool IsPrivate =>
        string.Equals(
            Exposure,
            EnterpriseUpdateFeedAuthorizationWire.PrivateStableDecision,
            StringComparison.Ordinal);
}

public static class EnterpriseUpdateFeedTransport
{
#if ENTERPRISE_DEVELOPMENT_E2E
    private const string DevelopmentE2EUpdateCertificateSha256EnvironmentVariable =
        "ENSOU_DSH_E2E_UPDATE_TLS_CERT_SHA256";
    private const string DevelopmentE2EUpdateLoopbackPortEnvironmentVariable =
        "ENSOU_DSH_E2E_UPDATE_LOOPBACK_PORT";
    private const string DevelopmentE2EManifestHost = "updates.example";
    private const string DevelopmentE2EArtifactHost = "artifacts.example";
#endif

    public static HttpClient CreateTransactionClient(
        Uri exactStableManifestUri,
        Uri artifactOrigin,
        EnterpriseDpopProofFactory proofFactory,
        IEnterpriseAccessTokenVault accessTokenVault,
        TimeProvider? timeProvider = null)
    {
#if ENTERPRISE_DEVELOPMENT_E2E
        HttpMessageHandler transport = CreateDevelopmentE2ETransport(
            exactStableManifestUri,
            artifactOrigin);
#else
        HttpMessageHandler transport = CreateProductionTransport();
#endif
        var authorization = new EnterpriseUpdateFeedAuthorizationHandler(
            exactStableManifestUri,
            artifactOrigin,
            proofFactory,
            accessTokenVault,
            transport,
            timeProvider);
        return new HttpClient(authorization)
        {
            // Enterprise runtime archives can be large and the employee path
            // may be bandwidth constrained. Keep the same bounded transfer
            // window as Personal while the update service independently
            // enforces manifest and per-read idle deadlines, signed size, and
            // SHA-256 before activation.
            Timeout = TimeSpan.FromHours(2),
        };
    }

    internal static HttpClientHandler CreateProductionTransport() => new()
    {
        AllowAutoRedirect = false,
        AutomaticDecompression = DecompressionMethods.None,
        CheckCertificateRevocationList = true,
        UseCookies = false,
    };

#if ENTERPRISE_DEVELOPMENT_E2E
    private static SocketsHttpHandler CreateDevelopmentE2ETransport(
        Uri exactStableManifestUri,
        Uri artifactOrigin)
    {
        RequireDevelopmentE2EUpdateEndpoint(exactStableManifestUri);
        RequireDevelopmentE2EUpdateEndpoint(artifactOrigin);

        var loopbackPort = ReadDevelopmentE2ELoopbackPort();
        var expectedCertificateSha256 = ReadDevelopmentE2ECertificateSha256();
        return new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            ConnectCallback = (context, cancellationToken) =>
                ConnectDevelopmentE2ELoopbackAsync(context, loopbackPort, cancellationToken),
            ConnectTimeout = TimeSpan.FromSeconds(10),
            MaxConnectionsPerServer = 2,
            PooledConnectionLifetime = TimeSpan.Zero,
            UseCookies = false,
            UseProxy = false,
            SslOptions = new SslClientAuthenticationOptions
            {
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                RemoteCertificateValidationCallback = (_, certificate, _, errors) =>
                    IsPinnedDevelopmentE2ECertificate(
                        certificate,
                        expectedCertificateSha256,
                        errors),
            },
        };
    }

    private static string ReadDevelopmentE2ECertificateSha256()
    {
        var value = Environment.GetEnvironmentVariable(
            DevelopmentE2EUpdateCertificateSha256EnvironmentVariable) ?? string.Empty;
        if (value.Length != 64 || value.Any(character => !Uri.IsHexDigit(character)))
        {
            throw new InvalidOperationException(
                "Development E2E update HTTPS requires "
                + DevelopmentE2EUpdateCertificateSha256EnvironmentVariable
                + ".");
        }
        return value;
    }

    private static int ReadDevelopmentE2ELoopbackPort()
    {
        var value = Environment.GetEnvironmentVariable(
            DevelopmentE2EUpdateLoopbackPortEnvironmentVariable) ?? string.Empty;
        if (!int.TryParse(
                value,
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out var port)
            || port is <= 0 or > ushort.MaxValue)
        {
            throw new InvalidOperationException(
                "Development E2E update HTTPS requires "
                + DevelopmentE2EUpdateLoopbackPortEnvironmentVariable
                + " to be an explicit TCP port.");
        }
        return port;
    }

    private static async ValueTask<Stream> ConnectDevelopmentE2ELoopbackAsync(
        SocketsHttpConnectionContext context,
        int loopbackPort,
        CancellationToken cancellationToken)
    {
        var requestUri = context.InitialRequestMessage.RequestUri;
        if (!IsDevelopmentE2EUpdateEndpoint(requestUri)
            || !string.Equals(
                context.DnsEndPoint.Host,
                requestUri!.IdnHost,
                StringComparison.OrdinalIgnoreCase)
            || context.DnsEndPoint.Port != requestUri.Port)
        {
            throw new HttpRequestException(
                "Development E2E update HTTPS destination is not admitted.");
        }

        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)
        {
            NoDelay = true,
        };
        try
        {
            await socket.ConnectAsync(IPAddress.Loopback, loopbackPort, cancellationToken)
                .ConfigureAwait(false);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    private static bool IsPinnedDevelopmentE2ECertificate(
        X509Certificate? certificate,
        string expectedCertificateSha256,
        SslPolicyErrors errors)
    {
        if (certificate is null
            || (errors & ~SslPolicyErrors.RemoteCertificateChainErrors)
                != SslPolicyErrors.None)
        {
            return false;
        }

        using var received = X509CertificateLoader.LoadCertificate(
            certificate.Export(X509ContentType.Cert));
        var now = DateTime.UtcNow;
        return CryptographicOperations.FixedTimeEquals(
                SHA256.HashData(received.RawData),
                Convert.FromHexString(expectedCertificateSha256))
            && now >= received.NotBefore.ToUniversalTime()
            && now <= received.NotAfter.ToUniversalTime()
            && (received.MatchesHostname(
                    DevelopmentE2EManifestHost,
                    allowWildcards: false,
                    allowCommonName: false)
                || received.MatchesHostname(
                    DevelopmentE2EArtifactHost,
                    allowWildcards: false,
                    allowCommonName: false));
    }

    internal static bool IsDevelopmentE2EUpdateEndpoint(Uri? value)
    {
        if (value is null
            || !value.IsAbsoluteUri
            || value.Scheme != Uri.UriSchemeHttps
            || value.Port != 443
            || !string.IsNullOrEmpty(value.UserInfo)
            || !string.IsNullOrEmpty(value.Query)
            || !string.IsNullOrEmpty(value.Fragment)
            || !string.Equals(value.OriginalString, value.AbsoluteUri, StringComparison.Ordinal))
        {
            return false;
        }
        return string.Equals(
                   value.IdnHost,
                   DevelopmentE2EManifestHost,
                   StringComparison.OrdinalIgnoreCase)
            || string.Equals(
                   value.IdnHost,
                   DevelopmentE2EArtifactHost,
                   StringComparison.OrdinalIgnoreCase);
    }

    private static void RequireDevelopmentE2EUpdateEndpoint(Uri value)
    {
        if (!IsDevelopmentE2EUpdateEndpoint(value))
        {
            throw new ArgumentException(
                "Development E2E update HTTPS is limited to the signed update origins.",
                nameof(value));
        }
    }
#endif
}

internal sealed class EnterpriseUpdateFeedAuthorizationHandler : DelegatingHandler
{
    public static readonly TimeSpan MaximumAccessTokenLifetime = TimeSpan.FromMinutes(10);

    private readonly Uri _manifestUri;
    private readonly Uri _artifactOrigin;
    private readonly EnterpriseDpopProofFactory _proofFactory;
    private readonly IEnterpriseAccessTokenVault _accessTokenVault;
    private readonly TimeProvider _timeProvider;
    private readonly object _decisionGate = new();
    private EnterpriseUpdateFeedAuthorizationDecision? _manifestDecision;
    private bool _manifestInFlight;

    public EnterpriseUpdateFeedAuthorizationHandler(
        Uri exactStableManifestUri,
        Uri artifactOrigin,
        EnterpriseDpopProofFactory proofFactory,
        IEnterpriseAccessTokenVault accessTokenVault,
        HttpMessageHandler innerHandler,
        TimeProvider? timeProvider = null)
        : base(innerHandler ?? throw new ArgumentNullException(nameof(innerHandler)))
    {
        _manifestUri = RequireManifestUri(exactStableManifestUri);
        _artifactOrigin = RequireOrigin(artifactOrigin, nameof(artifactOrigin));
        if (!string.Equals(
                _manifestUri.GetLeftPart(UriPartial.Authority),
                _artifactOrigin.GetLeftPart(UriPartial.Authority),
                StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "Enterprise Stable manifest and immutable artifacts must share one authenticated origin.",
                nameof(artifactOrigin));
        }
        _proofFactory = proofFactory ?? throw new ArgumentNullException(nameof(proofFactory));
        _accessTokenVault = accessTokenVault
            ?? throw new ArgumentNullException(nameof(accessTokenVault));
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var targetKind = RequireAllowedTarget(request);
        RejectCallerAuthorizationHeaders(request);
        var manifestReservation = ReserveTarget(targetKind);
        try
        {
            return await SendAuthorizedAsync(request, targetKind, cancellationToken)
                .ConfigureAwait(false);
        }
        catch
        {
            if (manifestReservation)
            {
                ReleaseManifestReservation();
            }
            throw;
        }
    }

    private async Task<HttpResponseMessage> SendAuthorizedAsync(
        HttpRequestMessage request,
        TargetKind targetKind,
        CancellationToken cancellationToken)
    {
        var now = _timeProvider.GetUtcNow();
        using var tokenLease = _accessTokenVault.Acquire(now);
        if (tokenLease.ExpiresAtUtc <= now
            || tokenLease.ExpiresAtUtc > now.Add(MaximumAccessTokenLifetime))
        {
            throw new EnterpriseAccessTokenUnavailableException();
        }

        var token = tokenLease.Materialize();
        HttpResponseMessage? response = null;
        try
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("DPoP", token);
            request.Headers.TryAddWithoutValidation(
                "DPoP",
                _proofFactory.Create(
                    HttpMethod.Get,
                    request.RequestUri!,
                    authorizationSecret: token));
            response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            request.Headers.Authorization = null;
            request.Headers.Remove("DPoP");
        }

        try
        {
            RequireNoRedirect(response, request.RequestUri!);
            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                _accessTokenVault.Clear();
                throw new EnterpriseUpdateFeedAuthorizationDeniedException(
                    response.StatusCode,
                    tokenCleared: true);
            }
            if (response.StatusCode == HttpStatusCode.Forbidden)
            {
                throw new EnterpriseUpdateFeedAuthorizationDeniedException(
                    response.StatusCode,
                    tokenCleared: false);
            }
            if ((int)response.StatusCode is >= 500 and <= 599)
            {
                throw new EnterpriseUpdateFeedUnavailableException(response.StatusCode);
            }

            var decision = ReadAndStripServerDecision(response);
            if (!string.Equals(
                    decision.BindingId.ToString("D"),
                    tokenLease.BindingId,
                    StringComparison.Ordinal))
            {
                throw new EnterpriseUpdateFeedProtocolException(
                    "Enterprise update-feed decision is bound to another device.");
            }
            RequireConsistentLane(targetKind, decision);
            EnterpriseUpdateFeedAuthorizationWire.SetDecision(response, decision);
            return response;
        }
        catch
        {
            response.Dispose();
            throw;
        }
    }

    private bool ReserveTarget(TargetKind targetKind)
    {
        lock (_decisionGate)
        {
            if (targetKind == TargetKind.Manifest)
            {
                if (_manifestInFlight || _manifestDecision is not null)
                {
                    throw new EnterpriseUpdateFeedTransactionConsumedException();
                }
                _manifestInFlight = true;
                return true;
            }
            if (_manifestDecision is null)
            {
                throw new EnterpriseUpdateFeedProtocolException(
                    "Enterprise authenticated artifact fetch preceded its manifest decision.");
            }
            return false;
        }
    }

    private void ReleaseManifestReservation()
    {
        lock (_decisionGate)
        {
            if (_manifestDecision is null)
            {
                _manifestInFlight = false;
            }
        }
    }

    private TargetKind RequireAllowedTarget(HttpRequestMessage request)
    {
        if (request.Method != HttpMethod.Get
            || request.Content is not null
            || request.RequestUri is null
            || !request.RequestUri.IsAbsoluteUri
            || !string.Equals(
                request.RequestUri.Scheme,
                Uri.UriSchemeHttps,
                StringComparison.Ordinal)
            || !string.IsNullOrEmpty(request.RequestUri.UserInfo)
            || !string.IsNullOrEmpty(request.RequestUri.Query)
            || !string.IsNullOrEmpty(request.RequestUri.Fragment)
            || !string.Equals(
                request.RequestUri.OriginalString,
                request.RequestUri.AbsoluteUri,
                StringComparison.Ordinal))
        {
            throw new EnterpriseUpdateFeedProtocolException(
                "Enterprise authenticated update-feed request target is invalid.");
        }
        if (string.Equals(
                request.RequestUri.AbsoluteUri,
                _manifestUri.AbsoluteUri,
                StringComparison.Ordinal))
        {
            return TargetKind.Manifest;
        }
        if (!string.Equals(
                request.RequestUri.GetLeftPart(UriPartial.Authority),
                _artifactOrigin.GetLeftPart(UriPartial.Authority),
                StringComparison.Ordinal))
        {
            throw new EnterpriseUpdateFeedProtocolException(
                "Enterprise authenticated update-feed request escaped the artifact origin.");
        }

        var segments = request.RequestUri.AbsolutePath.Split(
            '/',
            StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length != 4
            || segments[0] != "v2"
            || segments[1] != "releases"
            || !EnterpriseUpdateFeedAuthorizationWire.IsToken(segments[2], 128)
            || !EnterpriseUpdateFeedAuthorizationWire.IsToken(segments[3], 256)
            || segments[2] is "." or ".."
            || segments[3] is "." or ".."
            || request.RequestUri.OriginalString.Contains('%', StringComparison.Ordinal)
            || request.RequestUri.OriginalString.Contains('\\', StringComparison.Ordinal))
        {
            throw new EnterpriseUpdateFeedProtocolException(
                "Enterprise authenticated update-feed artifact route is invalid.");
        }
        return TargetKind.Artifact;
    }

    private static void RejectCallerAuthorizationHeaders(HttpRequestMessage request)
    {
        if (request.Headers.Authorization is not null
            || request.Headers.Contains("DPoP")
            || request.Headers.Contains(
                EnterpriseUpdateFeedAuthorizationWire.OriginalFeedUriHeaderName)
            || request.Headers.Contains(
                EnterpriseUpdateFeedAuthorizationWire.InternalAuthorizationHeaderName)
            || request.Headers.Contains(
                EnterpriseUpdateFeedAuthorizationWire.RequestIdHeaderName)
            || request.Headers.Contains(
                EnterpriseUpdateFeedAuthorizationWire.DecisionHeaderName)
            || request.Headers.Contains(
                EnterpriseUpdateFeedAuthorizationWire.ErrorHeaderName)
            || request.Headers.Contains(
                EnterpriseUpdateFeedAuthorizationWire.SharedCacheHeaderName))
        {
            throw new EnterpriseUpdateFeedProtocolException(
                "Enterprise update-feed callers cannot supply authorization decision headers.");
        }
    }

    private static void RequireNoRedirect(
        HttpResponseMessage response,
        Uri originalRequestUri)
    {
        if ((int)response.StatusCode is >= 300 and < 400
            || response.RequestMessage?.RequestUri is null
            || !string.Equals(
                response.RequestMessage.RequestUri.AbsoluteUri,
                originalRequestUri.AbsoluteUri,
                StringComparison.Ordinal))
        {
            throw new EnterpriseUpdateFeedProtocolException(
                "Enterprise authenticated update-feed redirects are forbidden.");
        }
    }

    private static EnterpriseUpdateFeedAuthorizationDecision ReadAndStripServerDecision(
        HttpResponseMessage response)
    {
        if (response.Headers.CacheControl is not { Private: true, NoStore: true } cacheControl
            || cacheControl.Public
            || !response.Headers.Vary.Any(
                value => string.Equals(value, "Authorization", StringComparison.OrdinalIgnoreCase))
            || !TryReadSingleHeader(
                response,
                EnterpriseUpdateFeedAuthorizationWire.SharedCacheHeaderName,
                out var sharedCache)
            || sharedCache != EnterpriseUpdateFeedAuthorizationWire.SharedCacheBypass
            || !TryReadSingleHeader(
                response,
                EnterpriseUpdateFeedAuthorizationWire.DecisionHeaderName,
                out var rawDecision))
        {
            throw new EnterpriseUpdateFeedProtocolException(
                "Enterprise authenticated update-feed response lacks private cache isolation.");
        }

        var decision = EnterpriseUpdateFeedAuthorizationWire.ParseDecision(rawDecision);
        response.Headers.Remove(EnterpriseUpdateFeedAuthorizationWire.DecisionHeaderName);
        response.Headers.Remove(EnterpriseUpdateFeedAuthorizationWire.SharedCacheHeaderName);
        return decision;
    }

    private static bool TryReadSingleHeader(
        HttpResponseMessage response,
        string name,
        out string value)
    {
        value = string.Empty;
        if (!response.Headers.TryGetValues(name, out var values))
        {
            return false;
        }
        var materialized = values.ToArray();
        if (materialized.Length != 1)
        {
            return false;
        }
        value = materialized[0];
        return true;
    }

    private void RequireConsistentLane(
        TargetKind targetKind,
        EnterpriseUpdateFeedAuthorizationDecision decision)
    {
        lock (_decisionGate)
        {
            if (targetKind == TargetKind.Manifest)
            {
                if (!_manifestInFlight || _manifestDecision is not null)
                {
                    throw new EnterpriseUpdateFeedTransactionConsumedException();
                }
                _manifestDecision = decision;
                _manifestInFlight = false;
                return;
            }
            if (_manifestDecision is null)
            {
                throw new EnterpriseUpdateFeedProtocolException(
                    "Enterprise authenticated artifact fetch preceded its manifest decision.");
            }
            RequireSameLane(_manifestDecision, decision);
        }
    }

    private static void RequireSameLane(
        EnterpriseUpdateFeedAuthorizationDecision expected,
        EnterpriseUpdateFeedAuthorizationDecision observed)
    {
        if (!string.Equals(expected.Exposure, observed.Exposure, StringComparison.Ordinal)
            || expected.BindingId != observed.BindingId
            || !string.Equals(expected.PolicyId, observed.PolicyId, StringComparison.Ordinal)
            || expected.PolicyVersion != observed.PolicyVersion)
        {
            throw new EnterpriseUpdateFeedProtocolException(
                "Enterprise update-feed manifest and artifact authorization lanes differ.");
        }
    }

    private static Uri RequireManifestUri(Uri value)
    {
        var uri = RequireAbsoluteHttps(value, nameof(value));
        if (uri.AbsolutePath != "/v2/channels/stable/release-set.v2.json"
#if ENTERPRISE_DEVELOPMENT_E2E
            // The isolated development E2E release set is signed for Lab.
            // No other non-production channel or path is admitted.
            && uri.AbsolutePath != "/v2/channels/lab/release-set.v2.json"
#endif
            )
        {
            throw new ArgumentException(
                "Enterprise authenticated update manifest must be the exact Stable v2 route.",
                nameof(value));
        }
        return uri;
    }

    private static Uri RequireOrigin(Uri value, string parameterName)
    {
        var uri = RequireAbsoluteHttps(value, parameterName);
        if (uri.AbsolutePath != "/")
        {
            throw new ArgumentException(
                "Enterprise artifact origin must contain no path.",
                parameterName);
        }
        return uri;
    }

    private static Uri RequireAbsoluteHttps(Uri value, string parameterName)
    {
        ArgumentNullException.ThrowIfNull(value, parameterName);
        if (!value.IsAbsoluteUri
            || value.Scheme != Uri.UriSchemeHttps
            || string.IsNullOrWhiteSpace(value.Host)
            || !string.IsNullOrEmpty(value.UserInfo)
            || !string.IsNullOrEmpty(value.Query)
            || !string.IsNullOrEmpty(value.Fragment)
            || !string.Equals(value.OriginalString, value.AbsoluteUri, StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "Enterprise update-feed URI must be canonical HTTPS.",
                parameterName);
        }
        return value;
    }

    private enum TargetKind
    {
        Manifest,
        Artifact,
    }
}

public sealed class EnterpriseUpdateFeedAuthorizationDeniedException
    : InvalidOperationException
{
    public EnterpriseUpdateFeedAuthorizationDeniedException(
        HttpStatusCode statusCode,
        bool tokenCleared)
        : base("Enterprise update-feed authorization was explicitly denied.")
    {
        if (statusCode is not HttpStatusCode.Unauthorized and not HttpStatusCode.Forbidden)
        {
            throw new ArgumentOutOfRangeException(nameof(statusCode));
        }
        StatusCode = statusCode;
        TokenCleared = tokenCleared;
    }

    public HttpStatusCode StatusCode { get; }

    public bool TokenCleared { get; }
}

public sealed class EnterpriseUpdateFeedProtocolException(string message)
    : InvalidOperationException(message);

public sealed class EnterpriseUpdateFeedUnavailableException
    : InvalidOperationException
{
    public EnterpriseUpdateFeedUnavailableException(HttpStatusCode statusCode)
        : base("Enterprise authenticated update-feed authorization is unavailable.")
    {
        if ((int)statusCode is < 500 or > 599)
        {
            throw new ArgumentOutOfRangeException(nameof(statusCode));
        }
        StatusCode = statusCode;
    }

    public HttpStatusCode StatusCode { get; }
}

public sealed class EnterpriseUpdateFeedTransactionConsumedException()
    : InvalidOperationException(
        "Enterprise authenticated update-feed client cannot be reused for another manifest transaction.");
