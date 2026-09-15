using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;

namespace Ensou.Dsh.Personal.Client;

/// <summary>
/// One installation's online account transport. No retries, cookies, redirects,
/// model credentials, offline grants, or persistent credential storage.
/// </summary>
public sealed class PersonalAccountClient : IPersonalAccountClient, IDisposable
{
    private const int MaximumResponseBytes = 16 * 1024;
    private readonly Uri _origin;
    private readonly string _installationId;
    private readonly PersonalDeviceProofFactory _proofs;
    private readonly HttpClient _http;
    private readonly TimeProvider _clock;
    private readonly SemaphoreSlim _operation = new(1, 1);
    private int _disposed;

    public PersonalAccountClient(Uri origin, string installationId, IPersonalDeviceProofKey key,
        TimeProvider? clock = null)
        : this(origin, installationId, key, CreateTransport(), clock) { }

    internal PersonalAccountClient(Uri origin, string installationId, IPersonalDeviceProofKey key,
        HttpMessageHandler transport, TimeProvider? clock = null)
    {
        ArgumentNullException.ThrowIfNull(transport);
        try
        {
            _origin = PersonalAccountFormat.RequireOrigin(origin);
            PersonalAccountFormat.RequireUuid(installationId);
            _installationId = installationId;
            _clock = clock ?? TimeProvider.System;
            _proofs = new PersonalDeviceProofFactory(key, installationId, _clock);
            _http = new HttpClient(transport, disposeHandler: true) { Timeout = Timeout.InfiniteTimeSpan };
        }
        catch { transport.Dispose(); throw; }
    }

    public Task<PersonalEmailChallenge> RequestEmailAsync(string email, CancellationToken cancellationToken = default)
    {
        var canonical = PersonalAccountFormat.CanonicalizeEmail(email);
        return RunAsync(async token =>
        {
            var proof = await ProofAsync("issue", canonical, PersonalAccountRoutes.EmailRequest, token);
            using var response = await PostAsync(PersonalAccountRoutes.EmailRequest,
                new { email = canonical, deviceProof = proof }, HttpStatusCode.Accepted, false, token);
            RequireFields(response.RootElement, "status", "challengeId");
            if (ReadString(response.RootElement, "status") != "submitted") throw InvalidResponse();
            var challenge = ReadString(response.RootElement, "challengeId");
            PersonalAccountFormat.RequireBase64Url(challenge, 24);
            return new PersonalEmailChallenge(challenge);
        }, cancellationToken);
    }

    public Task<PersonalAccountSession> SignInAsync(PersonalEmailChallenge challenge, string code,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(challenge);
        PersonalAccountFormat.RequireBase64Url(challenge.ChallengeId, 24);
        if (code is not { Length: 6 } || code.Any(c => !char.IsAsciiDigit(c)))
            throw new ArgumentException("A six-digit code is required.");
        return RunAsync(async token =>
        {
            var proof = await ProofAsync("redeem", challenge.ChallengeId, PersonalAccountRoutes.SignIn, token);
            using var response = await PostAsync(PersonalAccountRoutes.SignIn,
                new { challengeId = challenge.ChallengeId, code, deviceProof = proof }, HttpStatusCode.OK, true, token);
            try { return ReadGrant(response.RootElement, previous: null); }
            catch { throw Reauthenticate(); }
        }, cancellationToken);
    }

    public Task<PersonalAccountAccess> ValidateAccessAsync(PersonalAccountSession session,
        CancellationToken cancellationToken = default)
    {
        RequireSession(session);
        return RunAsync(async token =>
        {
            var proof = await ProofAsync("session-access", session.AccessToken, PersonalAccountRoutes.Access, token);
            using var response = await PostAsync(PersonalAccountRoutes.Access,
                new { accessToken = session.AccessToken, deviceProof = proof }, HttpStatusCode.OK, false, token);
            var root = response.RootElement;
            RequireFields(root, "status", "sessionId", "accountId", "installationId", "checkedAtUtc", "accessExpiresAtUtc");
            if (ReadString(root, "status") != "allowed"
                || ReadString(root, "sessionId") != session.SessionId
                || ReadString(root, "accountId") != session.AccountId
                || ReadString(root, "installationId") != _installationId) throw InvalidResponse();
            var checkedAt = ReadUtc(root, "checkedAtUtc");
            var expiresAt = ReadUtc(root, "accessExpiresAtUtc");
            RequireRecent(checkedAt);
            if (expiresAt != session.AccessExpiresAtUtc || expiresAt <= checkedAt
                || expiresAt <= _clock.GetUtcNow()) throw InvalidResponse();
            return new PersonalAccountAccess(checkedAt, expiresAt);
        }, cancellationToken);
    }

    public Task<PersonalAccountSession> RefreshAsync(PersonalAccountSession session,
        CancellationToken cancellationToken = default)
    {
        RequireSession(session);
        return RunAsync(async token =>
        {
            var proof = await ProofAsync("session-refresh", session.RefreshToken, PersonalAccountRoutes.Refresh, token);
            using var response = await PostAsync(PersonalAccountRoutes.Refresh,
                new { refreshToken = session.RefreshToken, deviceProof = proof }, HttpStatusCode.OK, true, token);
            try { return ReadGrant(response.RootElement, session); }
            catch { throw Reauthenticate(); }
        }, cancellationToken);
    }

    private async Task<T> RunAsync<T>(Func<CancellationToken, Task<T>> operation, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        if (!await _operation.WaitAsync(0, cancellationToken))
            throw new PersonalAccountException(PersonalAccountFailure.Busy);
        try
        {
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            deadline.CancelAfter(TimeSpan.FromSeconds(15));
            try { return await operation(deadline.Token); }
            catch (PersonalAccountException) { throw; }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (JsonException) { throw InvalidResponse(); }
            catch (FormatException) { throw InvalidResponse(); }
            catch (ArgumentException) { throw InvalidResponse(); }
            catch (InvalidOperationException) { throw InvalidResponse(); }
            catch (Exception) { throw new PersonalAccountException(PersonalAccountFailure.Unavailable); }
        }
        finally { _operation.Release(); }
    }

    private async Task<string> ProofAsync(string operation, string value, string path, CancellationToken token)
    {
        using var response = await PostAsync(PersonalAccountRoutes.Nonce, new { operation, value }, HttpStatusCode.OK, false, token);
        RequireFields(response.RootElement, "nonce", "expiresAtUtc");
        var nonce = ReadString(response.RootElement, "nonce");
        PersonalAccountFormat.RequireBase64Url(nonce, 32);
        var expires = ReadUtc(response.RootElement, "expiresAtUtc");
        var now = _clock.GetUtcNow();
        if (expires <= now || expires > now.AddSeconds(240)) throw InvalidResponse();
        token.ThrowIfCancellationRequested();
        return _proofs.Create(new Uri(_origin, path), operation, value, nonce);
    }

    private async Task<JsonDocument> PostAsync(string path, object payload, HttpStatusCode expectedStatus,
        bool createsCredentials, CancellationToken cancellationToken)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(payload);
        var submitted = false;
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(_origin, path))
            {
                Version = HttpVersion.Version11,
                VersionPolicy = HttpVersionPolicy.RequestVersionExact,
                Content = new ByteArrayContent(bytes),
            };
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json") { CharSet = "utf-8" };
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            request.Headers.CacheControl = new CacheControlHeaderValue { NoStore = true };
            cancellationToken.ThrowIfCancellationRequested();
            submitted = true;
            using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            if (response.StatusCode == HttpStatusCode.Unauthorized)
                throw new PersonalAccountException(PersonalAccountFailure.Denied);
            if (response.StatusCode == HttpStatusCode.TooManyRequests)
                throw new PersonalAccountException(PersonalAccountFailure.RateLimited);
            if (response.StatusCode != expectedStatus)
                throw createsCredentials ? Reauthenticate() : new PersonalAccountException(PersonalAccountFailure.Unavailable);
            if (response.Headers.CacheControl?.NoStore != true || response.Content.Headers.ContentEncoding.Count != 0
                || response.Content.Headers.ContentLength > MaximumResponseBytes
                || !IsJson(response.Content.Headers.ContentType))
                throw createsCredentials ? Reauthenticate() : InvalidResponse();
            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
            var buffer = new byte[MaximumResponseBytes + 1];
            try
            {
                var count = 0;
                while (count < buffer.Length)
                {
                    var read = await stream.ReadAsync(buffer.AsMemory(count), cancellationToken);
                    if (read == 0) break;
                    count += read;
                }
                if (count == 0 || count > MaximumResponseBytes)
                    throw createsCredentials ? Reauthenticate() : InvalidResponse();
                // Stream parsing gives the document its own buffer; the request-local
                // response bytes can then be erased without corrupting the document.
                using var payloadStream = new MemoryStream(buffer, 0, count, writable: false);
                return JsonDocument.Parse(payloadStream, new JsonDocumentOptions { MaxDepth = 4 });
            }
            finally { CryptographicOperations.ZeroMemory(buffer); }
        }
        catch (PersonalAccountException) { throw; }
        catch (Exception) when (createsCredentials && submitted) { throw Reauthenticate(); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    private PersonalAccountSession ReadGrant(JsonElement root, PersonalAccountSession? previous)
    {
        RequireFields(root, "status", "sessionId", "accountId", "installationId", "accessToken", "refreshToken",
            "issuedAtUtc", "accessExpiresAtUtc", "refreshExpiresAtUtc");
        var sessionId = ReadString(root, "sessionId");
        var accountId = ReadString(root, "accountId");
        var installationId = ReadString(root, "installationId");
        PersonalAccountFormat.RequireUuid(sessionId);
        if (!Guid.TryParseExact(accountId, "D", out var account) || account == Guid.Empty || account.ToString("D") != accountId)
            throw InvalidResponse();
        if (ReadString(root, "status") != "authorized" || installationId != _installationId) throw InvalidResponse();
        var access = ReadString(root, "accessToken");
        var refresh = ReadString(root, "refreshToken");
        PersonalAccountFormat.RequireToken(access, "psa_");
        PersonalAccountFormat.RequireToken(refresh, "psr_");
        var issued = ReadUtc(root, "issuedAtUtc");
        var accessExpiry = ReadUtc(root, "accessExpiresAtUtc");
        var refreshExpiry = ReadUtc(root, "refreshExpiresAtUtc");
        RequireRecent(issued);
        if (accessExpiry < issued.AddMinutes(1) || accessExpiry > issued.AddMinutes(15)
            || accessExpiry <= _clock.GetUtcNow()
            || refreshExpiry < issued.AddHours(1) || refreshExpiry > issued.AddDays(30)) throw InvalidResponse();
        if (previous is not null && (sessionId != previous.SessionId || accountId != previous.AccountId
            || access == previous.AccessToken || refresh == previous.RefreshToken || issued < previous.IssuedAtUtc))
            throw InvalidResponse();
        return new PersonalAccountSession(_origin, sessionId, accountId, installationId, access, refresh,
            issued, accessExpiry, refreshExpiry);
    }

    private void RequireSession(PersonalAccountSession session)
    {
        ArgumentNullException.ThrowIfNull(session);
        if (session.Origin != _origin || session.InstallationId != _installationId)
            throw new ArgumentException("Personal session does not belong to this client.");
        PersonalAccountFormat.RequireToken(session.AccessToken, "psa_");
        PersonalAccountFormat.RequireToken(session.RefreshToken, "psr_");
    }

    private void RequireRecent(DateTimeOffset value)
    {
        var now = _clock.GetUtcNow();
        if (value < now.AddSeconds(-120) || value > now.AddSeconds(120)) throw InvalidResponse();
    }

    private static void RequireFields(JsonElement root, params string[] fields)
    {
        if (root.ValueKind != JsonValueKind.Object) throw InvalidResponse();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in root.EnumerateObject())
            if (!fields.Contains(property.Name, StringComparer.Ordinal) || !seen.Add(property.Name)) throw InvalidResponse();
        if (seen.Count != fields.Length) throw InvalidResponse();
    }
    private static string ReadString(JsonElement root, string field) =>
        root.GetProperty(field) is { ValueKind: JsonValueKind.String } value && value.GetString() is { Length: > 0 } text
        && text.Length <= 1024 && !text.Any(char.IsControl) ? text : throw InvalidResponse();
    private static DateTimeOffset ReadUtc(JsonElement root, string field) =>
        root.GetProperty(field).TryGetDateTimeOffset(out var value) && value.Offset == TimeSpan.Zero ? value : throw InvalidResponse();
    private static bool IsJson(MediaTypeHeaderValue? type) => type is not null
        && string.Equals(type.MediaType, "application/json", StringComparison.OrdinalIgnoreCase)
        && (type.Parameters.Count == 0 || type.Parameters.Count == 1
            && string.Equals(type.Parameters.First().Name, "charset", StringComparison.OrdinalIgnoreCase)
            && string.Equals(type.CharSet?.Trim('"'), "utf-8", StringComparison.OrdinalIgnoreCase));
    private static PersonalAccountException InvalidResponse() => new(PersonalAccountFailure.InvalidResponse);
    private static PersonalAccountException Reauthenticate() => new(PersonalAccountFailure.ReauthenticationRequired);
    private static SocketsHttpHandler CreateTransport() => new()
    {
        AllowAutoRedirect = false,
        UseCookies = false,
        Credentials = null,
        ConnectTimeout = TimeSpan.FromSeconds(5),
        MaxConnectionsPerServer = 4,
        MaxResponseHeadersLength = 16,
        PooledConnectionLifetime = TimeSpan.FromMinutes(5),
        AutomaticDecompression = DecompressionMethods.None,
    };
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0) _http.Dispose();
        // Do not dispose the semaphore while an in-flight operation releases it.
    }
}
