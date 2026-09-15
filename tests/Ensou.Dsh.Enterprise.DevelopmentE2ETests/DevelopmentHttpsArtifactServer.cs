using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Logging;

namespace Ensou.Dsh.Enterprise.DevelopmentE2ETests;

internal sealed class DevelopmentHttpsArtifactServer : IAsyncDisposable
{
    private const string ManifestHost = "updates.example";
    private const string ArtifactHost = "artifacts.example";
    private const int MaximumConnections = 8;
    private static readonly TimeSpan ShutdownTimeout = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan RequestHeadersTimeout = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan ResponseWriteTimeout = TimeSpan.FromSeconds(10);

    private readonly WebApplication _application;
    private readonly X509Certificate2 _certificate;
    private readonly IReadOnlyDictionary<string, Route> _routes;
    private readonly SafeTlsDiagnostics _diagnostics;
    private readonly DevelopmentFeedAuthorizationForwarder? _authorization;
    private readonly ConcurrentQueue<DevelopmentHttpsArtifactRequest> _successfulRequests = new();
    private int _connectAttempts;
    private int _disposed;

    private DevelopmentHttpsArtifactServer(
        WebApplication application,
        X509Certificate2 certificate,
        IReadOnlyDictionary<string, Route> routes,
        SafeTlsDiagnostics diagnostics,
        DevelopmentFeedAuthorizationForwarder? authorization)
    {
        _application = application;
        _certificate = certificate;
        _routes = routes;
        _diagnostics = diagnostics;
        _authorization = authorization;
    }

    public string LeafCertificateSha256 { get; private set; } = string.Empty;
    public int LoopbackPort => GetLoopbackEndpoint().Port;
    public int ConnectAttempts => Volatile.Read(ref _connectAttempts);
    public IReadOnlyList<DevelopmentHttpsArtifactRequest> SuccessfulRequests =>
        _successfulRequests.ToArray();
    public IReadOnlyList<DevelopmentFeedAuthorizationObservation> AuthorizedRequests =>
        _authorization?.Accepted ?? [];
    public DevelopmentHttpsArtifactTlsDiagnostics TlsDiagnostics => _diagnostics.Snapshot();
    public IReadOnlyList<DevelopmentHttpsArtifactServerError> ServerErrors =>
        _diagnostics.ServerErrors;

    public static async Task<DevelopmentHttpsArtifactServer> StartAsync(
        Dictionary<Uri, byte[]> prevalidatedRoutes,
        CancellationToken cancellationToken = default,
        DevelopmentFeedAuthorizationForwarder? authorization = null,
        string? certificateOnlyHost = null)
    {
        if (certificateOnlyHost is not null
            && !string.Equals(certificateOnlyHost, ManifestHost, StringComparison.Ordinal)
            && !string.Equals(certificateOnlyHost, ArtifactHost, StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "The optional certificate-only host must be updates.example or artifacts.example.",
                nameof(certificateOnlyHost));
        }

        var routes = ValidateAndCopyRoutes(prevalidatedRoutes);
        var certificate = CreateCertificate(certificateOnlyHost);
        var diagnostics = new SafeTlsDiagnostics();
        WebApplication? application = null;
        try
        {
            var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions
            {
                Args = Array.Empty<string>(),
            });
            builder.Configuration.Sources.Clear();
            builder.Logging.ClearProviders();
            builder.Logging.AddProvider(new SafeKestrelLoggerProvider(diagnostics));
            builder.Logging.AddFilter<SafeKestrelLoggerProvider>(
                "Microsoft.AspNetCore.Server.Kestrel",
                LogLevel.Debug);
            builder.WebHost.ConfigureKestrel(options =>
            {
                options.Limits.MaxConcurrentConnections = MaximumConnections;
                options.Limits.MaxConcurrentUpgradedConnections = 0;
                options.Limits.MaxRequestBodySize = 0;
                options.Limits.RequestHeadersTimeout = RequestHeadersTimeout;
                options.Limits.KeepAliveTimeout = ShutdownTimeout;
                options.Listen(IPAddress.Loopback, 0, listen => listen.UseHttps(certificate));
            });
            application = builder.Build();
            var server = new DevelopmentHttpsArtifactServer(
                application,
                certificate,
                routes,
                diagnostics,
                authorization);
            application.Run(server.HandleRequestAsync);
            await application.StartAsync(cancellationToken).ConfigureAwait(false);
            server.LeafCertificateSha256 = Convert.ToHexString(
                SHA256.HashData(certificate.RawData)).ToLowerInvariant();
            return server;
        }
        catch
        {
            if (application is not null)
            {
                await application.DisposeAsync().ConfigureAwait(false);
            }
            certificate.Dispose();
            throw;
        }
    }

    public HttpClient CreateClient(string? expectedLeafCertificateSha256 = null)
    {
        ThrowIfDisposed();
        var expectedHash = Convert.FromHexString(
            expectedLeafCertificateSha256 ?? LeafCertificateSha256);
        if (expectedHash.Length != 32)
        {
            throw new ArgumentException("Expected TLS leaf hash must be SHA-256.",
                nameof(expectedLeafCertificateSha256));
        }

        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            ConnectTimeout = TimeSpan.FromSeconds(10),
            MaxConnectionsPerServer = 2,
            PooledConnectionLifetime = TimeSpan.Zero,
            UseCookies = false,
            UseProxy = false,
        };
        handler.ConnectCallback = ConnectAsync;
        handler.SslOptions = new SslClientAuthenticationOptions
        {
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            RemoteCertificateValidationCallback = (_, certificate, _, errors) =>
                ValidateServerCertificate(certificate, expectedHash, errors),
        };
        return new HttpClient(handler, disposeHandler: true)
        {
            Timeout = TimeSpan.FromSeconds(30),
        };
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        using var shutdown = new CancellationTokenSource(ShutdownTimeout);
        try
        {
            await _application.StopAsync(shutdown.Token).ConfigureAwait(false);
        }
        finally
        {
            await _application.DisposeAsync().ConfigureAwait(false);
            _certificate.Dispose();
        }
    }

    private async Task HandleRequestAsync(HttpContext context)
    {
        if (!HttpMethods.IsGet(context.Request.Method))
        {
            context.Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
            return;
        }
        if (context.Request.ContentLength is > 0 ||
            context.Request.Headers.TransferEncoding.Count > 0)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }
        if (!TryGetRoute(context.Request, out var route))
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }

        if (_authorization is not null)
        {
            var authorization = await _authorization.AuthorizeAsync(
                route.OriginalUri, context.Request.Headers, context.RequestAborted).ConfigureAwait(false);
            foreach (var header in authorization.Headers)
                context.Response.Headers[header.Key] = header.Value;
            if (!authorization.Authorized)
            {
                context.Response.StatusCode = authorization.StatusCode;
                return;
            }
        }
        context.Response.StatusCode = StatusCodes.Status200OK;
        context.Response.ContentType = "application/octet-stream";
        context.Response.ContentLength = route.Bytes.Length;
        using var writeDeadline = CancellationTokenSource.CreateLinkedTokenSource(
            context.RequestAborted);
        writeDeadline.CancelAfter(ResponseWriteTimeout);
        await context.Response.Body.WriteAsync(route.Bytes, writeDeadline.Token)
            .ConfigureAwait(false);
        _successfulRequests.Enqueue(new DevelopmentHttpsArtifactRequest(route.OriginalUri, route.Bytes.Length));
    }

    private ValueTask<Stream> ConnectAsync(
        SocketsHttpConnectionContext context,
        CancellationToken cancellationToken)
    {
        var requestUri = context.InitialRequestMessage.RequestUri;
        if (requestUri is null
            || !requestUri.IsAbsoluteUri
            || requestUri.Scheme != Uri.UriSchemeHttps
            || requestUri.Port != 443
            || !string.IsNullOrEmpty(requestUri.UserInfo)
            || !IsAllowedHost(requestUri.IdnHost)
            || !string.Equals(context.DnsEndPoint.Host, requestUri.IdnHost,
                StringComparison.OrdinalIgnoreCase)
            || context.DnsEndPoint.Port != requestUri.Port)
        {
            throw new HttpRequestException("Development HTTPS artifact destination is not admitted.");
        }
        ThrowIfDisposed();
        Interlocked.Increment(ref _connectAttempts);
        return ConnectLoopbackAsync(cancellationToken);
    }

    private async ValueTask<Stream> ConnectLoopbackAsync(CancellationToken cancellationToken)
    {
        var endpoint = GetLoopbackEndpoint();
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)
        {
            NoDelay = true,
        };
        try
        {
            await socket.ConnectAsync(endpoint.Address, endpoint.Port, cancellationToken)
                .ConfigureAwait(false);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    private IPEndPoint GetLoopbackEndpoint()
    {
        var value = _application.Urls.SingleOrDefault(listenerAddress =>
            Uri.TryCreate(listenerAddress, UriKind.Absolute, out var uri)
            && uri.Scheme == Uri.UriSchemeHttps
            && IPAddress.TryParse(uri.Host, out var ipAddress)
            && IPAddress.IsLoopback(ipAddress)
            && uri.Port is > 0 and <= ushort.MaxValue);
        if (value is null || !Uri.TryCreate(value, UriKind.Absolute, out var endpointUri) ||
            !IPAddress.TryParse(endpointUri.Host, out var address))
        {
            throw new InvalidOperationException("Development HTTPS listener has no IPv4 loopback endpoint.");
        }
        return new IPEndPoint(address, endpointUri.Port);
    }

    private bool TryGetRoute(HttpRequest request, out Route route)
    {
        route = default!;
        if (!IsAllowedHost(request.Host.Host) ||
            request.Host.Port is not null and not 443)
        {
            return false;
        }
        var pathAndQuery = string.Concat(
            request.PathBase.Value,
            request.Path.Value,
            request.QueryString.Value);
        return _routes.TryGetValue(RouteKey(request.Host.Host, pathAndQuery), out route!);
    }

    private static IReadOnlyDictionary<string, Route> ValidateAndCopyRoutes(
        Dictionary<Uri, byte[]> prevalidatedRoutes)
    {
        ArgumentNullException.ThrowIfNull(prevalidatedRoutes);
        if (prevalidatedRoutes.Count == 0)
        {
            throw new ArgumentException("Development HTTPS artifact routes are empty.", nameof(prevalidatedRoutes));
        }

        var routes = new Dictionary<string, Route>(StringComparer.Ordinal);
        foreach (var (uri, bytes) in prevalidatedRoutes)
        {
            if (uri is null || bytes is null || bytes.Length == 0 ||
                !uri.IsAbsoluteUri || uri.Scheme != Uri.UriSchemeHttps || uri.Port != 443 ||
                !string.IsNullOrEmpty(uri.UserInfo) || !string.IsNullOrEmpty(uri.Query) ||
                !string.IsNullOrEmpty(uri.Fragment) || !IsAllowedHost(uri.IdnHost))
            {
                throw new ArgumentException("Development HTTPS artifact route is outside the signed contract.",
                    nameof(prevalidatedRoutes));
            }
            var key = RouteKey(uri.IdnHost, uri.PathAndQuery);
            if (!routes.TryAdd(key, new Route(uri, bytes.ToArray())))
            {
                throw new ArgumentException("Development HTTPS artifact routes contain an alias collision.",
                    nameof(prevalidatedRoutes));
            }
        }
        return routes;
    }

    private static X509Certificate2 CreateCertificate(string? certificateOnlyHost = null)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=updates.example",
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        var names = new SubjectAlternativeNameBuilder();
        if (certificateOnlyHost is null
            || string.Equals(certificateOnlyHost, ManifestHost, StringComparison.Ordinal))
        {
            names.AddDnsName(ManifestHost);
        }
        if (certificateOnlyHost is null
            || string.Equals(certificateOnlyHost, ArtifactHost, StringComparison.Ordinal))
        {
            names.AddDnsName(ArtifactHost);
        }
        request.CertificateExtensions.Add(names.Build());
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
            critical: true));
        var now = DateTimeOffset.UtcNow;
        X509Certificate2? temporaryCertificate = null;
        byte[]? pkcs12Bytes = null;
        try
        {
            temporaryCertificate = request.CreateSelfSigned(now.AddMinutes(-1), now.AddMinutes(30));
            pkcs12Bytes = temporaryCertificate.Export(X509ContentType.Pkcs12, string.Empty);
            return X509CertificateLoader.LoadPkcs12(
                pkcs12Bytes,
                string.Empty,
                X509KeyStorageFlags.UserKeySet);
        }
        finally
        {
            if (pkcs12Bytes is not null)
            {
                CryptographicOperations.ZeroMemory(pkcs12Bytes);
            }
            temporaryCertificate?.Dispose();
        }
    }

    private bool ValidateServerCertificate(
        X509Certificate? certificate,
        byte[] expectedHash,
        SslPolicyErrors errors)
    {
        try
        {
            var accepted = CertificateMatches(certificate, expectedHash, errors);
            _diagnostics.RecordClientCertificateValidation(errors, accepted, null);
            return accepted;
        }
        catch (Exception exception)
        {
            _diagnostics.RecordClientCertificateValidation(errors, accepted: false, exception);
            return false;
        }
    }

    private static bool CertificateMatches(
        X509Certificate? certificate,
        byte[] expectedHash,
        SslPolicyErrors errors)
    {
        if (certificate is null ||
            (errors & ~SslPolicyErrors.RemoteCertificateChainErrors) != SslPolicyErrors.None)
        {
            return false;
        }

        using var received = X509CertificateLoader.LoadCertificate(
            certificate.Export(X509ContentType.Cert));
        var now = DateTime.UtcNow;
        return CryptographicOperations.FixedTimeEquals(
                SHA256.HashData(received.RawData), expectedHash)
            && now >= received.NotBefore.ToUniversalTime()
            && now <= received.NotAfter.ToUniversalTime()
            && (received.MatchesHostname(ManifestHost,
                    allowWildcards: false,
                    allowCommonName: false)
                || received.MatchesHostname(ArtifactHost,
                    allowWildcards: false,
                    allowCommonName: false));
    }

    private static bool IsAllowedHost(string host) =>
        string.Equals(host, ManifestHost, StringComparison.OrdinalIgnoreCase)
        || string.Equals(host, ArtifactHost, StringComparison.OrdinalIgnoreCase);

    private static string RouteKey(string host, string pathAndQuery) =>
        host.ToLowerInvariant() + "\n" + pathAndQuery;

    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            throw new ObjectDisposedException(nameof(DevelopmentHttpsArtifactServer));
        }
    }

    private sealed record Route(Uri OriginalUri, byte[] Bytes);

    private sealed class SafeTlsDiagnostics
    {
        private const int MaximumServerErrors = 8;
        private readonly ConcurrentQueue<DevelopmentHttpsArtifactServerError> _serverErrors = new();
        private int _certificateValidationCallbacks;
        private int _certificateValidationAccepted;
        private int _certificateValidationRejected;
        private int _lastSslPolicyErrors;
        private string? _callbackExceptionType;
        private int _callbackExceptionHResult;

        public IReadOnlyList<DevelopmentHttpsArtifactServerError> ServerErrors =>
            _serverErrors.ToArray();

        public void RecordClientCertificateValidation(
            SslPolicyErrors errors,
            bool accepted,
            Exception? exception)
        {
            Interlocked.Increment(ref _certificateValidationCallbacks);
            Interlocked.Exchange(ref _lastSslPolicyErrors, (int)errors);
            if (accepted)
            {
                Interlocked.Increment(ref _certificateValidationAccepted);
            }
            else
            {
                Interlocked.Increment(ref _certificateValidationRejected);
            }
            if (exception is not null)
            {
                _callbackExceptionType = exception.GetType().Name;
                Interlocked.Exchange(ref _callbackExceptionHResult, exception.HResult);
            }
        }

        public void RecordServerError(string category, EventId eventId, Exception exception)
        {
            if (_serverErrors.Count >= MaximumServerErrors)
            {
                return;
            }
            _serverErrors.Enqueue(new DevelopmentHttpsArtifactServerError(
                category,
                eventId.Id,
                exception.GetType().Name,
                exception.HResult));
        }

        public DevelopmentHttpsArtifactTlsDiagnostics Snapshot() => new(
            Volatile.Read(ref _certificateValidationCallbacks),
            Volatile.Read(ref _certificateValidationAccepted),
            Volatile.Read(ref _certificateValidationRejected),
            (SslPolicyErrors)Volatile.Read(ref _lastSslPolicyErrors),
            _callbackExceptionType,
            Volatile.Read(ref _callbackExceptionHResult));
    }

    private sealed class SafeKestrelLoggerProvider(SafeTlsDiagnostics diagnostics) : ILoggerProvider
    {
        public ILogger CreateLogger(string categoryName) => new SafeKestrelLogger(categoryName, diagnostics);
        public void Dispose() { }
    }

    private sealed class SafeKestrelLogger(string categoryName, SafeTlsDiagnostics diagnostics) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Debug;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            _ = state;
            _ = formatter;
            if (exception is not null
                && logLevel >= LogLevel.Debug
                && categoryName.StartsWith("Microsoft.AspNetCore.Server.Kestrel", StringComparison.Ordinal))
            {
                diagnostics.RecordServerError(categoryName, eventId, exception);
            }
        }
    }
}

internal sealed record DevelopmentHttpsArtifactRequest(Uri Uri, int Bytes);
internal sealed record DevelopmentHttpsArtifactTlsDiagnostics(
    int CertificateValidationCallbacks,
    int CertificateValidationAccepted,
    int CertificateValidationRejected,
    SslPolicyErrors LastSslPolicyErrors,
    string? CallbackExceptionType,
    int CallbackExceptionHResult);
internal sealed record DevelopmentHttpsArtifactServerError(
    string Category,
    int EventId,
    string ExceptionType,
    int HResult);
