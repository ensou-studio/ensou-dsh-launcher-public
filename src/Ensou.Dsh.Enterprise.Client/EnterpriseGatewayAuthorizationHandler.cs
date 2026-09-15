using System.Net;
using System.Net.Http.Headers;

namespace Ensou.Dsh.Enterprise.Client;

public static class EnterprisePhase1GatewayProfile
{
    public const string ChatCompletionsPath = "/v1/chat/completions";

    public static IReadOnlyList<EnterpriseLoopbackRoute> Routes { get; } =
        Array.AsReadOnly(
        [
            new EnterpriseLoopbackRoute(HttpMethod.Post, ChatCompletionsPath),
        ]);
}

public sealed class EnterpriseGatewayAuthorizationHandler : DelegatingHandler
{
    private readonly Uri _gatewayOrigin;
    private readonly EnterpriseDpopProofFactory _proofFactory;
    private readonly IEnterpriseAccessTokenVault _accessTokenVault;
    private readonly EnterpriseHarnessSession _harnessSession;
    private readonly TimeProvider _timeProvider;
    private readonly HashSet<string> _allowedRoutes;

    public EnterpriseGatewayAuthorizationHandler(
        Uri gatewayOrigin,
        EnterpriseDpopProofFactory proofFactory,
        IEnterpriseAccessTokenVault accessTokenVault,
        EnterpriseHarnessSession harnessSession,
        HttpMessageHandler innerHandler,
        IEnumerable<EnterpriseLoopbackRoute> allowedRoutes,
        TimeProvider? timeProvider = null)
        : base(innerHandler ?? throw new ArgumentNullException(nameof(innerHandler)))
    {
        _gatewayOrigin = ValidateOrigin(gatewayOrigin);
        _proofFactory = proofFactory ?? throw new ArgumentNullException(nameof(proofFactory));
        _accessTokenVault = accessTokenVault
            ?? throw new ArgumentNullException(nameof(accessTokenVault));
        _harnessSession = harnessSession ?? throw new ArgumentNullException(nameof(harnessSession));
        _timeProvider = timeProvider ?? TimeProvider.System;
        ArgumentNullException.ThrowIfNull(allowedRoutes);
        _allowedRoutes = new HashSet<string>(StringComparer.Ordinal);
        foreach (var route in allowedRoutes)
        {
            ArgumentNullException.ThrowIfNull(route);
            if (!_allowedRoutes.Add(ToRouteKey(route.Method, route.Path)))
            {
                throw new ArgumentException(
                    "Enterprise gateway route allowlist contains duplicates.",
                    nameof(allowedRoutes));
            }
        }

        if (_allowedRoutes.Count is 0 or > 32)
        {
            throw new ArgumentException(
                "Enterprise gateway route allowlist must contain 1-32 exact routes.",
                nameof(allowedRoutes));
        }
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ValidateRequestTarget(request.Method, request.RequestUri);
        if (request.Headers.Authorization is not null || request.Headers.Contains("DPoP"))
        {
            throw new InvalidOperationException(
                "Enterprise gateway requests must not supply caller-controlled authorization headers.");
        }

        await _harnessSession.EnsureManagedApiAllowedAsync(cancellationToken)
            .ConfigureAwait(false);
        EnterpriseAccessTokenLease tokenLease;
        try
        {
            tokenLease = _accessTokenVault.Acquire(_timeProvider.GetUtcNow());
        }
        catch (EnterpriseAccessTokenUnavailableException)
        {
            await LockForRefreshAsync().ConfigureAwait(false);
            throw;
        }

        using (tokenLease)
        {
            var accessToken = tokenLease.Materialize();
            try
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("DPoP", accessToken);
                request.Headers.TryAddWithoutValidation(
                    "DPoP",
                    _proofFactory.Create(
                        request.Method,
                        request.RequestUri!,
                        authorizationSecret: accessToken));
                var response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
                if (response.StatusCode == HttpStatusCode.Unauthorized)
                {
                    _accessTokenVault.Clear();
                    await LockForRefreshAsync().ConfigureAwait(false);
                }

                return response;
            }
            finally
            {
                request.Headers.Authorization = null;
                request.Headers.Remove("DPoP");
            }
        }
    }

    private void ValidateRequestTarget(HttpMethod method, Uri? requestUri)
    {
        if (requestUri is null
            || !requestUri.IsAbsoluteUri
            || !string.Equals(requestUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            || !string.IsNullOrEmpty(requestUri.UserInfo)
            || !string.IsNullOrEmpty(requestUri.Query)
            || !string.IsNullOrEmpty(requestUri.Fragment)
            || !string.Equals(requestUri.Host, _gatewayOrigin.Host, StringComparison.OrdinalIgnoreCase)
            || requestUri.Port != _gatewayOrigin.Port
            || !_allowedRoutes.Contains(ToRouteKey(method, requestUri.AbsolutePath)))
        {
            throw new InvalidOperationException(
                "Enterprise managed API request escaped the build-pinned gateway origin.");
        }
    }

    private static string ToRouteKey(HttpMethod method, string path) =>
        $"{method.Method.ToUpperInvariant()} {path}";

    private async Task LockForRefreshAsync() => await _harnessSession.ApplyAccessAsync(
            EnterpriseStartupGate.CreateEnrollmentPendingSnapshot(),
            CancellationToken.None)
        .ConfigureAwait(false);

    private static Uri ValidateOrigin(Uri origin)
    {
        ArgumentNullException.ThrowIfNull(origin);
        if (!origin.IsAbsoluteUri
            || !string.Equals(origin.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            || !string.IsNullOrEmpty(origin.UserInfo)
            || !string.IsNullOrEmpty(origin.Query)
            || !string.IsNullOrEmpty(origin.Fragment)
            || origin.AbsolutePath != "/")
        {
            throw new ArgumentException(
                "Enterprise gateway origin must be one exact HTTPS origin.",
                nameof(origin));
        }

        return new UriBuilder(Uri.UriSchemeHttps, origin.Host, origin.Port).Uri;
    }
}
