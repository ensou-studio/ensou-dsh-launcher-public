using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace Ensou.Dsh.Enterprise.Client;

public sealed record EnterpriseLoopbackRoute
{
    public EnterpriseLoopbackRoute(HttpMethod method, string path)
    {
        ArgumentNullException.ThrowIfNull(method);
        if (method != HttpMethod.Get && method != HttpMethod.Post)
        {
            throw new ArgumentException(
                "Enterprise loopback routes permit only explicit GET or POST operations.",
                nameof(method));
        }

        if (string.IsNullOrEmpty(path)
            || !path.StartsWith("/v1/", StringComparison.Ordinal)
            || path.Length > 256
            || path.Contains('?', StringComparison.Ordinal)
            || path.Contains('#', StringComparison.Ordinal)
            || path.Contains('%', StringComparison.Ordinal)
            || path.Contains("..", StringComparison.Ordinal)
            || path.Any(character => character > 0x7f || char.IsControl(character)))
        {
            throw new ArgumentException(
                "Enterprise loopback route must be one exact ASCII /v1 path.",
                nameof(path));
        }

        Method = method;
        Path = path;
    }

    public HttpMethod Method { get; }

    public string Path { get; }
}

public sealed class EnterpriseLoopbackModelProxy : IAsyncDisposable
{
    private const int MaximumHeaderBytes = 64 * 1024;
    private const long MaximumRequestBodyBytes = 32L * 1024 * 1024;
    private const int MaximumConcurrentConnections = 32;
    private static readonly TimeSpan RequestHeaderCompletionTimeout = TimeSpan.FromSeconds(5);
    private static readonly byte[] HeaderTerminator = "\r\n\r\n"u8.ToArray();
    private static readonly HashSet<string> HopByHopHeaders = new(
        [
            "Connection",
            "Keep-Alive",
            "Proxy-Authenticate",
            "Proxy-Authorization",
            "TE",
            "Trailer",
            "Transfer-Encoding",
            "Upgrade",
            "Host",
            "Authorization",
            "DPoP",
            "Content-Length",
        ],
        StringComparer.OrdinalIgnoreCase);
    private static readonly HashSet<string> ForwardedRequestHeaders = new(
        [
            "Accept",
            "Content-Type",
        ],
        StringComparer.OrdinalIgnoreCase);

    private readonly Uri _gatewayOrigin;
    private readonly HttpClient _gatewayClient;
    private readonly HashSet<string> _allowedRoutes;
    private readonly string _localBearer;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly SemaphoreSlim _connectionSlots = new(
        MaximumConcurrentConnections,
        MaximumConcurrentConnections);
    private readonly CancellationTokenSource _shutdown = new();
    private readonly ConcurrentDictionary<long, Task> _connections = new();
    private TcpListener? _listener;
    private Task? _acceptLoop;
    private Uri? _localOrigin;
    private long _connectionSequence;
    private bool _disposed;

    public EnterpriseLoopbackModelProxy(
        Uri gatewayOrigin,
        IEnumerable<EnterpriseLoopbackRoute> allowedRoutes,
        HttpClient gatewayClient)
    {
        _gatewayOrigin = ValidateGatewayOrigin(gatewayOrigin);
        ArgumentNullException.ThrowIfNull(allowedRoutes);
        _allowedRoutes = new HashSet<string>(StringComparer.Ordinal);
        foreach (var route in allowedRoutes)
        {
            ArgumentNullException.ThrowIfNull(route);
            if (!_allowedRoutes.Add(ToRouteKey(route.Method.Method, route.Path)))
            {
                throw new ArgumentException(
                    "Enterprise loopback route allowlist contains duplicates.",
                    nameof(allowedRoutes));
            }
        }

        if (_allowedRoutes.Count is 0 or > 32)
        {
            throw new ArgumentException(
                "Enterprise loopback route allowlist must contain 1-32 exact routes.",
                nameof(allowedRoutes));
        }

        _gatewayClient = gatewayClient ?? throw new ArgumentNullException(nameof(gatewayClient));
        _localBearer = Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
    }

    public Uri LocalOrigin => _localOrigin
        ?? throw new InvalidOperationException("Enterprise loopback proxy has not started.");

    public async Task StartAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_listener is not null)
            {
                return;
            }

            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Server.NoDelay = true;
            listener.Start(MaximumConcurrentConnections);
            var endpoint = listener.LocalEndpoint as IPEndPoint
                ?? throw new InvalidOperationException(
                    "Enterprise loopback proxy did not receive an IPv4 endpoint.");
            if (!IPAddress.Loopback.Equals(endpoint.Address) || endpoint.Port <= 0)
            {
                listener.Stop();
                throw new InvalidOperationException(
                    "Enterprise loopback proxy escaped the IPv4 loopback boundary.");
            }

            _listener = listener;
            _localOrigin = new UriBuilder(
                Uri.UriSchemeHttp,
                "127.0.0.1",
                endpoint.Port,
                "/").Uri;
            _acceptLoop = AcceptLoopAsync(listener, _shutdown.Token);
        }
        finally
        {
            _gate.Release();
        }
    }

    public IReadOnlyDictionary<string, string> CreateDshControlledEnvironment()
    {
        var baseUri = new Uri(LocalOrigin, "v1");
        return new ReadOnlyDictionary<string, string>(
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["DEEPSEEK_BASE_URL"] = baseUri.AbsoluteUri.TrimEnd('/'),
                ["DEEPSEEK_API_KEY"] = _localBearer,
                ["DEEPSEEK_SEARCH_BASE_URL"] = baseUri.AbsoluteUri.TrimEnd('/'),
            });
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _shutdown.Cancel();
            _listener?.Stop();
            _listener = null;
            _localOrigin = null;
        }
        finally
        {
            _gate.Release();
        }

        if (_acceptLoop is not null)
        {
            try
            {
                await _acceptLoop.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
        }

        var connections = _connections.Values.ToArray();
        if (connections.Length > 0)
        {
            try
            {
                await Task.WhenAll(connections).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
        }

        _shutdown.Dispose();
        _connectionSlots.Dispose();
        _gate.Dispose();
    }

    private async Task AcceptLoopAsync(TcpListener listener, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await listener.AcceptTcpClientAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return;
            }
            catch (SocketException) when (cancellationToken.IsCancellationRequested)
            {
                return;
            }

            try
            {
                await _connectionSlots.WaitAsync(cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                client.Dispose();
                throw;
            }

            var id = Interlocked.Increment(ref _connectionSequence);
            var task = HandleConnectionAsync(client, cancellationToken);
            _connections[id] = task;
            _ = task.ContinueWith(
                completedTask =>
                {
                    _ = completedTask.Exception;
                    _connections.TryRemove(id, out var removedTask);
                    _connectionSlots.Release();
                },
                CancellationToken.None,
                TaskContinuationOptions.ExecuteSynchronously,
                TaskScheduler.Default);
        }
    }

    private async Task HandleConnectionAsync(
        TcpClient client,
        CancellationToken shutdownToken)
    {
        using (client)
        using (var requestCancellation = CancellationTokenSource.CreateLinkedTokenSource(
            shutdownToken))
        {
            client.NoDelay = true;
            var network = client.GetStream();
            var disconnectMonitor = MonitorDisconnectAsync(client, requestCancellation);
            try
            {
                ParsedRequest? parsed;
                using (var headerCancellation = CancellationTokenSource.CreateLinkedTokenSource(
                    requestCancellation.Token))
                {
                    headerCancellation.CancelAfter(RequestHeaderCompletionTimeout);
                    parsed = await ReadRequestAsync(network, headerCancellation.Token)
                        .ConfigureAwait(false);
                }

                if (parsed is null)
                {
                    return;
                }

                using (parsed)
                {
                    if (!parsed.HasValidAuthorization(_localBearer)
                        || !_allowedRoutes.Contains(ToRouteKey(parsed.Method, parsed.Path)))
                    {
                        await WriteSimpleResponseAsync(
                                network,
                                HttpStatusCode.Unauthorized,
                                requestCancellation.Token)
                            .ConfigureAwait(false);
                        return;
                    }

                    await ForwardAsync(parsed, network, requestCancellation.Token)
                        .ConfigureAwait(false);
                }
            }
            catch (EnterpriseAccessDeniedException)
            {
                await TryWriteSimpleResponseAsync(network, HttpStatusCode.Unauthorized, shutdownToken)
                    .ConfigureAwait(false);
            }
            catch (EnterpriseAccessTokenUnavailableException)
            {
                await TryWriteSimpleResponseAsync(network, HttpStatusCode.Unauthorized, shutdownToken)
                    .ConfigureAwait(false);
            }
            catch (InvalidDataException)
            {
                await TryWriteSimpleResponseAsync(network, HttpStatusCode.BadRequest, shutdownToken)
                    .ConfigureAwait(false);
            }
            catch (HttpRequestException)
            {
                await TryWriteSimpleResponseAsync(network, HttpStatusCode.BadGateway, shutdownToken)
                    .ConfigureAwait(false);
            }
            catch (Exception exception) when (
                exception is IOException or SocketException or OperationCanceledException)
            {
                // Downstream disconnect and cancellation terminate the upstream request.
            }
            finally
            {
                requestCancellation.Cancel();
                try
                {
                    await disconnectMonitor.ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                }
            }
        }
    }

    private async Task ForwardAsync(
        ParsedRequest request,
        Stream downstream,
        CancellationToken cancellationToken)
    {
        var upstreamUri = new Uri(_gatewayOrigin, request.PathAndQuery);
        using var upstreamRequest = new HttpRequestMessage(
            new HttpMethod(request.Method),
            upstreamUri);
        if (request.ContentLength > 0 || request.Method == "POST")
        {
            upstreamRequest.Content = new StreamContent(request.Body);
            upstreamRequest.Content.Headers.ContentLength = request.ContentLength;
        }

        foreach (var header in request.Headers)
        {
            if (!ForwardedRequestHeaders.Contains(header.Key))
            {
                continue;
            }

            if (!upstreamRequest.Headers.TryAddWithoutValidation(header.Key, header.Value))
            {
                upstreamRequest.Content?.Headers.TryAddWithoutValidation(
                    header.Key,
                    header.Value);
            }
        }

        using var upstreamResponse = await _gatewayClient.SendAsync(
                upstreamRequest,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken)
            .ConfigureAwait(false);
        await WriteUpstreamResponseAsync(upstreamResponse, downstream, cancellationToken)
            .ConfigureAwait(false);
    }

    private static async Task WriteUpstreamResponseAsync(
        HttpResponseMessage response,
        Stream downstream,
        CancellationToken cancellationToken)
    {
        var contentLength = response.Content.Headers.ContentLength;
        var header = new StringBuilder()
            .Append("HTTP/1.1 ")
            .Append((int)response.StatusCode)
            .Append(' ')
            .Append(SanitizeReasonPhrase(response.ReasonPhrase))
            .Append("\r\nConnection: close\r\n");
        foreach (var item in response.Headers.Concat(response.Content.Headers))
        {
            if (HopByHopHeaders.Contains(item.Key))
            {
                continue;
            }

            foreach (var value in item.Value)
            {
                if (value.All(character => character is >= (char)0x20 and <= (char)0x7e))
                {
                    header.Append(item.Key).Append(": ").Append(value).Append("\r\n");
                }
            }
        }

        if (contentLength is not null)
        {
            header.Append("Content-Length: ").Append(contentLength.Value).Append("\r\n");
        }
        else
        {
            header.Append("Transfer-Encoding: chunked\r\n");
        }

        header.Append("\r\n");
        await downstream.WriteAsync(
                Encoding.ASCII.GetBytes(header.ToString()),
                cancellationToken)
            .ConfigureAwait(false);
        await using var content = await response.Content.ReadAsStreamAsync(cancellationToken)
            .ConfigureAwait(false);
        if (contentLength is not null)
        {
            await content.CopyToAsync(downstream, cancellationToken).ConfigureAwait(false);
            return;
        }

        var buffer = new byte[16 * 1024];
        try
        {
            while (true)
            {
                var read = await content.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                await downstream.WriteAsync(
                        Encoding.ASCII.GetBytes(read.ToString("X", CultureInfo.InvariantCulture) + "\r\n"),
                        cancellationToken)
                    .ConfigureAwait(false);
                await downstream.WriteAsync(buffer.AsMemory(0, read), cancellationToken)
                    .ConfigureAwait(false);
                await downstream.WriteAsync("\r\n"u8.ToArray(), cancellationToken)
                    .ConfigureAwait(false);
                await downstream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }

            await downstream.WriteAsync("0\r\n\r\n"u8.ToArray(), cancellationToken)
                .ConfigureAwait(false);
            await downstream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    private static async Task<ParsedRequest?> ReadRequestAsync(
        NetworkStream stream,
        CancellationToken cancellationToken)
    {
        using var bytes = new MemoryStream();
        var buffer = new byte[4096];
        try
        {
            var headerEnd = -1;
            while (headerEnd < 0)
            {
                var read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    return bytes.Length == 0
                        ? null
                        : throw new InvalidDataException(
                            "Enterprise loopback request ended inside its headers.");
                }

                if (bytes.Length + read > MaximumHeaderBytes)
                {
                    throw new InvalidDataException(
                        "Enterprise loopback request headers exceed their bound.");
                }

                await bytes.WriteAsync(buffer.AsMemory(0, read), cancellationToken)
                    .ConfigureAwait(false);
                headerEnd = IndexOf(bytes.GetBuffer().AsSpan(0, checked((int)bytes.Length)), HeaderTerminator);
            }

            var allBytes = bytes.GetBuffer().AsSpan(0, checked((int)bytes.Length));
            var headerBytes = allBytes[..headerEnd];
            if (ContainsNonAsciiOrNull(headerBytes))
            {
                throw new InvalidDataException(
                    "Enterprise loopback request headers must be ASCII.");
            }

            var headerText = Encoding.ASCII.GetString(headerBytes);
            var lines = headerText.Split("\r\n", StringSplitOptions.None);
            var requestLine = lines[0].Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (requestLine.Length != 3
                || requestLine[0] is not "GET" and not "POST"
                || requestLine[2] is not "HTTP/1.1" and not "HTTP/1.0")
            {
                throw new InvalidDataException(
                    "Enterprise loopback request line is outside the supported profile.");
            }

            var target = requestLine[1];
            if (!target.StartsWith("/v1/", StringComparison.Ordinal)
                || target.Contains('?', StringComparison.Ordinal)
                || target.Contains('#', StringComparison.Ordinal)
                || target.Contains('%', StringComparison.Ordinal)
                || target.Contains("..", StringComparison.Ordinal)
                || target.Length > 4096
                || target.Any(character => char.IsWhiteSpace(character)
                    || char.IsControl(character)))
            {
                throw new InvalidDataException(
                    "Enterprise loopback request target is outside the exact query-free /v1 profile.");
            }

            var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var line in lines.Skip(1))
            {
                var separator = line.IndexOf(':');
                var headerName = separator > 0 ? line[..separator] : string.Empty;
                var headerValue = separator > 0
                    ? line[(separator + 1)..].Trim()
                    : string.Empty;
                if (separator <= 0
                    || char.IsWhiteSpace(line[0])
                    || !IsValidHeaderName(headerName)
                    || headerValue.Any(character => character is < (char)0x20 or (char)0x7f)
                    || !headers.TryAdd(headerName, headerValue))
                {
                    throw new InvalidDataException(
                        "Enterprise loopback request contains malformed or duplicate headers.");
                }
            }

            if (headers.ContainsKey("Transfer-Encoding"))
            {
                throw new InvalidDataException(
                    "Enterprise loopback request transfer coding is not supported.");
            }

            var contentLength = 0L;
            if (headers.TryGetValue("Content-Length", out var contentLengthText)
                && (!long.TryParse(
                        contentLengthText,
                        NumberStyles.None,
                        CultureInfo.InvariantCulture,
                        out contentLength)
                    || contentLength < 0
                    || contentLength > MaximumRequestBodyBytes))
            {
                throw new InvalidDataException(
                    "Enterprise loopback request content length is invalid.");
            }

            var bodyOffset = headerEnd + HeaderTerminator.Length;
            var prefix = allBytes[bodyOffset..].ToArray();
            if (prefix.LongLength > contentLength)
            {
                throw new InvalidDataException(
                    "Enterprise loopback request contains pipelined or excess body bytes.");
            }

            return new ParsedRequest(
                requestLine[0],
                target,
                target,
                headers,
                contentLength,
                new BoundedPrefixStream(prefix, stream, contentLength));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
            CryptographicOperations.ZeroMemory(bytes.GetBuffer());
        }
    }

    private static async Task MonitorDisconnectAsync(
        TcpClient client,
        CancellationTokenSource cancellation)
    {
        try
        {
            while (!cancellation.IsCancellationRequested)
            {
                if (client.Client.Poll(1000, SelectMode.SelectRead)
                    && client.Client.Available == 0)
                {
                    cancellation.Cancel();
                    return;
                }

                await Task.Delay(TimeSpan.FromMilliseconds(100), cancellation.Token)
                    .ConfigureAwait(false);
            }
        }
        catch (Exception exception) when (
            exception is SocketException or ObjectDisposedException)
        {
            cancellation.Cancel();
        }
    }

    private static async Task TryWriteSimpleResponseAsync(
        Stream stream,
        HttpStatusCode statusCode,
        CancellationToken cancellationToken)
    {
        try
        {
            await WriteSimpleResponseAsync(stream, statusCode, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception exception) when (
            exception is IOException or SocketException or OperationCanceledException)
        {
        }
    }

    private static async Task WriteSimpleResponseAsync(
        Stream stream,
        HttpStatusCode statusCode,
        CancellationToken cancellationToken)
    {
        var bytes = Encoding.ASCII.GetBytes(
            $"HTTP/1.1 {(int)statusCode} {statusCode}\r\n" +
            "Connection: close\r\nContent-Length: 0\r\n\r\n");
        await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private static int IndexOf(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> needle)
    {
        for (var index = 0; index <= haystack.Length - needle.Length; index++)
        {
            if (haystack.Slice(index, needle.Length).SequenceEqual(needle))
            {
                return index;
            }
        }

        return -1;
    }

    private static bool ContainsNonAsciiOrNull(ReadOnlySpan<byte> value)
    {
        foreach (var item in value)
        {
            if (item > 0x7f || item == 0)
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsValidHeaderName(string value)
    {
        if (value.Length is 0 or > 256)
        {
            return false;
        }

        foreach (var character in value)
        {
            if (!char.IsAsciiLetterOrDigit(character)
                && character is not '!' and not '#' and not '$' and not '%' and not '&'
                    and not '\'' and not '*' and not '+' and not '-' and not '.' and not '^'
                    and not '_' and not '`' and not '|' and not '~')
            {
                return false;
            }
        }

        return true;
    }

    private static string SanitizeReasonPhrase(string? value) =>
        string.IsNullOrWhiteSpace(value)
            || value.Any(character => character > 0x7f || char.IsControl(character))
            ? "Response"
            : value;

    private static string ToRouteKey(string method, string path) =>
        $"{method.ToUpperInvariant()} {path}";

    private static Uri ValidateGatewayOrigin(Uri origin)
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
                "Enterprise loopback proxy gateway must be one exact HTTPS origin.",
                nameof(origin));
        }

        return new UriBuilder(Uri.UriSchemeHttps, origin.Host, origin.Port).Uri;
    }

    private static string Base64UrlEncode(ReadOnlySpan<byte> bytes) =>
        Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    public override string ToString() => "Enterprise loopback model proxy [credentials redacted]";

    private sealed class ParsedRequest : IDisposable
    {
        public ParsedRequest(
            string method,
            string path,
            string pathAndQuery,
            IReadOnlyDictionary<string, string> headers,
            long contentLength,
            Stream body)
        {
            Method = method;
            Path = path;
            PathAndQuery = pathAndQuery;
            Headers = headers;
            ContentLength = contentLength;
            Body = body;
        }

        public string Method { get; }

        public string Path { get; }

        public string PathAndQuery { get; }

        public IReadOnlyDictionary<string, string> Headers { get; }

        public long ContentLength { get; }

        public Stream Body { get; }

        public bool HasValidAuthorization(string expectedBearer)
        {
            if (!Headers.TryGetValue("Authorization", out var header)
                || !AuthenticationHeaderValue.TryParse(header, out var authorization)
                || !string.Equals(authorization.Scheme, "Bearer", StringComparison.Ordinal)
                || authorization.Parameter is null)
            {
                return false;
            }

            var actual = Encoding.ASCII.GetBytes(authorization.Parameter);
            var expected = Encoding.ASCII.GetBytes(expectedBearer);
            try
            {
                return actual.Length == expected.Length
                    && CryptographicOperations.FixedTimeEquals(actual, expected);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(actual);
                CryptographicOperations.ZeroMemory(expected);
            }
        }

        public void Dispose() => Body.Dispose();
    }

    private sealed class BoundedPrefixStream : Stream
    {
        private readonly byte[] _prefix;
        private readonly Stream _inner;
        private readonly long _length;
        private int _prefixOffset;
        private long _remaining;

        public BoundedPrefixStream(byte[] prefix, Stream inner, long length)
        {
            _prefix = prefix;
            _inner = inner;
            _length = length;
            _remaining = length;
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => _length;
        public override long Position
        {
            get => _length - _remaining;
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count) =>
            ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

        public override async ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            if (_remaining == 0 || buffer.IsEmpty)
            {
                return 0;
            }

            var boundedCount = (int)Math.Min(buffer.Length, _remaining);
            var copied = 0;
            if (_prefixOffset < _prefix.Length)
            {
                copied = Math.Min(boundedCount, _prefix.Length - _prefixOffset);
                _prefix.AsMemory(_prefixOffset, copied).CopyTo(buffer);
                _prefixOffset += copied;
            }

            if (copied == 0)
            {
                copied = await _inner.ReadAsync(
                        buffer[..boundedCount],
                        cancellationToken)
                    .ConfigureAwait(false);
                if (copied == 0)
                {
                    throw new InvalidDataException(
                        "Enterprise loopback request body ended before Content-Length.");
                }
            }

            _remaining -= copied;
            return copied;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                CryptographicOperations.ZeroMemory(_prefix);
            }

            base.Dispose(disposing);
        }

        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();
    }
}
