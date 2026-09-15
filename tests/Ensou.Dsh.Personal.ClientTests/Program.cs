using System.Buffers.Binary;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Ensou.Dsh.Personal.Client;

namespace Ensou.Dsh.Personal.ClientTests;

internal static class Program
{
    private static readonly Uri Origin = new("https://personal.example.test/");
    private static readonly DateTimeOffset Now = new(2026, 9, 9, 0, 0, 0, TimeSpan.Zero);
    private const string InstallationId = "11111111-1111-4111-8111-111111111111";
    private const string AccountId = "22222222-2222-4222-8222-222222222222";
    private const string SessionId = "33333333-3333-4333-8333-333333333333";
    private const string ChallengeId = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";
    private const string NoncePath = "/v1/personal/device-proofs/nonce";
    private const string EmailRequestPath = "/v1/personal/email/request";
    private const string SignInPath = "/v1/personal/sessions/sign-in";
    private const string AccessPath = "/v1/personal/sessions/access";
    private const string RefreshPath = "/v1/personal/sessions/refresh";
    private static readonly string AccessToken = "psa_" + Base64Url(Enumerable.Repeat((byte)0xA1, 32).ToArray());
    private static readonly string RefreshToken = "psr_" + Base64Url(Enumerable.Repeat((byte)0xB2, 32).ToArray());
    private static readonly string RefreshedAccessToken = "psa_" + Base64Url(Enumerable.Repeat((byte)0xA3, 32).ToArray());
    private static readonly string RefreshedRefreshToken = "psr_" + Base64Url(Enumerable.Repeat((byte)0xB4, 32).ToArray());

    public static async Task<int> Main()
    {
        var tests = new (string Name, Func<Task> Run)[]
        {
            ("four client operations use nonce-bound ES256 proofs", NormalFourOperationsAsync),
            ("foreign-origin session is rejected before transport", ForeignOriginRejectedBeforeTransportAsync),
            ("sign-in response installation identity is exact", WrongSignInInstallationRejectedAsync),
            ("access and refresh response identities are exact", WrongAccessAndRefreshIdentitiesRejectedAsync),
            ("response time windows are rejected when invalid", InvalidResponseTimesRejectedAsync),
            ("malformed response JSON is rejected", MalformedResponseRejectedAsync),
            ("duplicate response fields are rejected", DuplicateResponseRejectedAsync),
            ("oversized response is rejected", OversizedResponseRejectedAsync),
            ("no-store response header is required", MissingNoStoreRejectedAsync),
            ("clear HTTP denial and rate limit are classified", ClearHttpFailuresAreClassifiedAsync),
            ("submitted sign-in transport failure requires reauthentication without retry", SubmittedSignInTransportFailureRequiresReauthenticationAsync),
            ("submitted refresh cancellation requires reauthentication without retry", SubmittedRefreshCancellationRequiresReauthenticationAsync),
            ("concurrent refresh fails busy without a queue", ConcurrentRefreshIsBusyAsync),
            ("authorization coordinator preserves session and runtime ordering", PersonalAuthorizationCoordinatorTests.RunAsync),
            ("compiled account endpoint rejects missing duplicate and noncanonical values", PersonalAccountEndpointTests.RunAsync),
            ("account build self-check is deterministic and fails before output", PersonalAccountBuildSelfCheckTests.RunAsync),
        };

        var failures = 0;
        foreach (var test in tests)
        {
            try
            {
                await test.Run().ConfigureAwait(false);
                Console.WriteLine($"PASS personal-client {test.Name}");
            }
            catch (Exception exception)
            {
                failures++;
                Console.Error.WriteLine($"FAIL personal-client {test.Name}: {exception.GetType().Name}");
            }
        }

        Console.WriteLine($"PERSONAL CLIENT RESULT {tests.Length - failures}/{tests.Length} passed");
        return failures == 0 ? 0 : 1;
    }

    private static async Task NormalFourOperationsAsync()
    {
        using var key = new TestDeviceKey();
        using var transport = new ProtocolHandler();
        using var client = NewClient(key, transport);

        var challenge = await client.RequestEmailAsync("member@example.test").ConfigureAwait(false);
        var session = await client.SignInAsync(challenge, "123456").ConfigureAwait(false);
        var access = await client.ValidateAccessAsync(session).ConfigureAwait(false);
        var refreshed = await client.RefreshAsync(session).ConfigureAwait(false);

        Require(challenge.ChallengeId == ChallengeId);
        Require(session.Origin == Origin && session.InstallationId == InstallationId);
        Require(access.CheckedAtUtc == Now && access.AccessExpiresAtUtc == Now.AddMinutes(5));
        Require(refreshed.SessionId == SessionId && refreshed.AccessToken != session.AccessToken);
        Require(transport.NonceRequests == 4 && transport.ActionRequests == 4);
    }

    private static async Task ForeignOriginRejectedBeforeTransportAsync()
    {
        using var key = new TestDeviceKey();
        using var transport = new CountingHandler();
        using var client = NewClient(key, transport);
        var foreign = new PersonalAccountSession(
            new Uri("https://other.example.test/"), SessionId, AccountId, InstallationId,
            AccessToken, RefreshToken, Now, Now.AddMinutes(5), Now.AddDays(7));

        await ExpectArgumentFailureAsync(
            () => client.ValidateAccessAsync(foreign)).ConfigureAwait(false);
        Require(transport.Calls == 0);
    }

    private static async Task WrongSignInInstallationRejectedAsync()
    {
        using var key = new TestDeviceKey();
        using var transport = new ProtocolHandler { GrantInstallationId = "44444444-4444-4444-8444-444444444444" };
        using var client = NewClient(key, transport);

        var challenge = await client.RequestEmailAsync("member@example.test").ConfigureAwait(false);
        await ExpectFailureAsync(
            () => client.SignInAsync(challenge, "123456"), PersonalAccountFailure.ReauthenticationRequired).ConfigureAwait(false);
    }

    private static async Task WrongAccessAndRefreshIdentitiesRejectedAsync()
    {
        using var key = new TestDeviceKey();
        using var transport = new ProtocolHandler();
        using var client = NewClient(key, transport);
        var challenge = await client.RequestEmailAsync("member@example.test").ConfigureAwait(false);
        var session = await client.SignInAsync(challenge, "123456").ConfigureAwait(false);

        transport.AccessAccountId = "55555555-5555-4555-8555-555555555555";
        await ExpectFailureAsync(
            () => client.ValidateAccessAsync(session), PersonalAccountFailure.InvalidResponse).ConfigureAwait(false);

        transport.AccessAccountId = null;
        transport.RefreshSessionId = "66666666-6666-4666-8666-666666666666";
        await ExpectFailureAsync(
            () => client.RefreshAsync(session), PersonalAccountFailure.ReauthenticationRequired).ConfigureAwait(false);
    }

    private static async Task InvalidResponseTimesRejectedAsync()
    {
        using var key = new TestDeviceKey();
        using var transport = new ProtocolHandler { InvalidGrantTimes = true };
        using var client = NewClient(key, transport);
        var challenge = await client.RequestEmailAsync("member@example.test").ConfigureAwait(false);

        await ExpectFailureAsync(
            () => client.SignInAsync(challenge, "123456"), PersonalAccountFailure.ReauthenticationRequired).ConfigureAwait(false);
    }

    private static Task MalformedResponseRejectedAsync() =>
        AssertNonceResponseFailureAsync("{", includeNoStore: true);

    private static Task DuplicateResponseRejectedAsync() =>
        AssertNonceResponseFailureAsync(
            "{\"nonce\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"nonce\":\"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\",\"expiresAtUtc\":\"2026-09-09T00:02:00Z\"}",
            includeNoStore: true);

    private static Task OversizedResponseRejectedAsync() =>
        AssertNonceResponseFailureAsync("{\"nonce\":\"" + new string('A', 16 * 1024) + "\"}", includeNoStore: true);

    private static Task MissingNoStoreRejectedAsync() =>
        AssertNonceResponseFailureAsync(
            "{\"nonce\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"expiresAtUtc\":\"2026-09-09T00:02:00Z\"}",
            includeNoStore: false);

    private static async Task AssertNonceResponseFailureAsync(string json, bool includeNoStore)
    {
        using var key = new TestDeviceKey();
        using var transport = new StaticResponseHandler(() => JsonResponse(HttpStatusCode.OK, json, includeNoStore));
        using var client = NewClient(key, transport);
        await ExpectFailureAsync(
            () => client.RequestEmailAsync("member@example.test"), PersonalAccountFailure.InvalidResponse).ConfigureAwait(false);
        Require(transport.Calls == 1);
    }

    private static async Task ClearHttpFailuresAreClassifiedAsync()
    {
        using var key = new TestDeviceKey();
        using (var deniedTransport = new StaticResponseHandler(
                   () => JsonResponse(HttpStatusCode.Unauthorized, "{\"error\":\"denied\"}", includeNoStore: true)))
        using (var deniedClient = NewClient(key, deniedTransport))
        {
            await ExpectFailureAsync(
                () => deniedClient.RequestEmailAsync("member@example.test"), PersonalAccountFailure.Denied).ConfigureAwait(false);
        }
        using var limitedTransport = new StaticResponseHandler(
            () => JsonResponse((HttpStatusCode)429, "{\"error\":\"rate_limited\"}", includeNoStore: true));
        using var limitedClient = NewClient(key, limitedTransport);
        await ExpectFailureAsync(
            () => limitedClient.RequestEmailAsync("member@example.test"), PersonalAccountFailure.RateLimited).ConfigureAwait(false);
    }

    private static async Task SubmittedRefreshCancellationRequiresReauthenticationAsync()
    {
        using var key = new TestDeviceKey();
        using var transport = new ProtocolHandler { BlockRefresh = true };
        using var client = NewClient(key, transport);
        var session = await CreateSessionAsync(client).ConfigureAwait(false);
        using var cancellation = new CancellationTokenSource();
        var refresh = client.RefreshAsync(session, cancellation.Token);
        await transport.RefreshSubmitted.Task.WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
        cancellation.Cancel();

        await ExpectFailureAsync(
            async () => _ = await refresh.ConfigureAwait(false),
            PersonalAccountFailure.ReauthenticationRequired).ConfigureAwait(false);
        Require(transport.RefreshActionRequests == 1);
    }

    private static async Task SubmittedSignInTransportFailureRequiresReauthenticationAsync()
    {
        using var key = new TestDeviceKey();
        using var transport = new ProtocolHandler { FailSignInSubmitted = true };
        using var client = NewClient(key, transport);
        var challenge = await client.RequestEmailAsync("member@example.test").ConfigureAwait(false);

        await ExpectFailureAsync(
            () => client.SignInAsync(challenge, "123456"), PersonalAccountFailure.ReauthenticationRequired).ConfigureAwait(false);
        Require(transport.ActionRequests == 2);
    }

    private static async Task ConcurrentRefreshIsBusyAsync()
    {
        using var key = new TestDeviceKey();
        using var transport = new ProtocolHandler { BlockRefresh = true };
        using var client = NewClient(key, transport);
        var session = await CreateSessionAsync(client).ConfigureAwait(false);
        var first = client.RefreshAsync(session);
        await transport.RefreshSubmitted.Task.WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);

        await ExpectFailureAsync(
            async () => _ = await client.RefreshAsync(session).ConfigureAwait(false),
            PersonalAccountFailure.Busy).ConfigureAwait(false);
        Require(transport.RefreshActionRequests == 1);

        transport.ReleaseBlockedRefresh();
        var result = await first.ConfigureAwait(false);
        Require(result.SessionId == SessionId);
    }

    private static async Task<PersonalAccountSession> CreateSessionAsync(PersonalAccountClient client)
    {
        var challenge = await client.RequestEmailAsync("member@example.test").ConfigureAwait(false);
        return await client.SignInAsync(challenge, "123456").ConfigureAwait(false);
    }

    private static PersonalAccountClient NewClient(TestDeviceKey key, HttpMessageHandler transport) =>
        new(Origin, InstallationId, key, transport, new FixedTimeProvider(Now));

    private static async Task ExpectFailureAsync(Func<Task> action, PersonalAccountFailure expected)
    {
        try
        {
            await action().ConfigureAwait(false);
        }
        catch (PersonalAccountException exception) when (exception.Failure == expected)
        {
            return;
        }
        throw new InvalidOperationException();
    }

    private static async Task ExpectArgumentFailureAsync(Func<Task> action)
    {
        try
        {
            await action().ConfigureAwait(false);
        }
        catch (ArgumentException)
        {
            return;
        }
        throw new InvalidOperationException();
    }

    private static HttpResponseMessage JsonResponse(HttpStatusCode status, string body, bool includeNoStore)
    {
        var response = new HttpResponseMessage(status)
        {
            Content = new StringContent(body, new UTF8Encoding(false), "application/json"),
        };
        if (includeNoStore)
        {
            response.Headers.CacheControl = new CacheControlHeaderValue { NoStore = true };
        }
        return response;
    }

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] DecodeBase64Url(string value, int expectedLength)
    {
        if (string.IsNullOrEmpty(value) || value.Contains('=') ||
            value.Any(static c => !char.IsAsciiLetterOrDigit(c) && c is not '-' and not '_'))
            throw new InvalidOperationException();
        var padded = value.Replace('-', '+').Replace('_', '/');
        padded += (value.Length % 4) switch { 0 => "", 2 => "==", 3 => "=", _ => throw new InvalidOperationException() };
        var bytes = Convert.FromBase64String(padded);
        if ((expectedLength >= 0 && bytes.Length != expectedLength) || Base64Url(bytes) != value) throw new InvalidOperationException();
        return bytes;
    }

    private static void RequireExactProperties(JsonElement value, params string[] names)
    {
        if (value.ValueKind != JsonValueKind.Object) throw new InvalidOperationException();
        var expected = new HashSet<string>(names, StringComparer.Ordinal);
        var actual = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in value.EnumerateObject())
            if (!expected.Contains(property.Name) || !actual.Add(property.Name)) throw new InvalidOperationException();
        if (!actual.SetEquals(expected)) throw new InvalidOperationException();
    }

    private static string RequiredString(JsonElement value, string name) =>
        value.TryGetProperty(name, out var property) && property.ValueKind == JsonValueKind.String
            ? property.GetString() ?? throw new InvalidOperationException()
            : throw new InvalidOperationException();

    private static string RequestHash(string operation, string purpose, string semanticValue)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Span<byte> length = stackalloc byte[sizeof(uint)];
        foreach (var field in new[]
                 {
                     "ensou.dsh.personal.device-proof.request.v1", operation, purpose, semanticValue,
                 })
        {
            var bytes = Encoding.UTF8.GetBytes(field);
            try
            {
                BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)bytes.Length));
                hash.AppendData(length);
                hash.AppendData(bytes);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(bytes);
                CryptographicOperations.ZeroMemory(length);
            }
        }
        return Base64Url(hash.GetHashAndReset());
    }

    private static void Require(bool value)
    {
        if (!value) throw new InvalidOperationException();
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private sealed class TestDeviceKey : IPersonalDeviceProofKey, IDisposable
    {
        private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        public PersonalDevicePublicKey ReadPublicKey()
        {
            var parameters = _key.ExportParameters(false);
            return new PersonalDevicePublicKey(Base64Url(parameters.Q.X!), Base64Url(parameters.Q.Y!));
        }

        public byte[] Sign(ReadOnlySpan<byte> signingInput) =>
            _key.SignData(signingInput, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

        public void Dispose() => _key.Dispose();
    }

    private sealed class CountingHandler : HttpMessageHandler
    {
        public int Calls { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls++;
            throw new InvalidOperationException();
        }
    }

    private sealed class StaticResponseHandler(Func<HttpResponseMessage> factory) : HttpMessageHandler
    {
        public int Calls { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult(factory());
        }
    }

    private sealed class ProtocolHandler : HttpMessageHandler
    {
        private readonly Dictionary<string, string> _nonces = new(StringComparer.Ordinal);
        private int _nonceSequence;
        public int NonceRequests { get; private set; }
        public int ActionRequests { get; private set; }
        public int RefreshActionRequests { get; private set; }
        public string? GrantInstallationId { get; init; }
        public string? AccessAccountId { get; set; }
        public string? RefreshSessionId { get; set; }
        public bool InvalidGrantTimes { get; init; }
        public bool FailSignInSubmitted { get; init; }
        public bool BlockRefresh { get; init; }
        public TaskCompletionSource<bool> RefreshSubmitted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private TaskCompletionSource<HttpResponseMessage>? _blockedRefresh;

        public void ReleaseBlockedRefresh() =>
            _blockedRefresh?.TrySetResult(GrantResponse(RefreshSessionId ?? SessionId, AccountId, InstallationId, false, true));

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var requestUri = request.RequestUri ?? throw new InvalidOperationException();
            Require(request.Method == HttpMethod.Post
                && requestUri.Scheme == Uri.UriSchemeHttps
                && requestUri.GetLeftPart(UriPartial.Authority) == Origin.GetLeftPart(UriPartial.Authority));
            var path = requestUri.AbsolutePath;
            var body = await request.Content!.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            using var document = JsonDocument.Parse(body);
            if (path == NoncePath)
            {
                NonceRequests++;
                RequireExactProperties(document.RootElement, "operation", "value");
                var operation = RequiredString(document.RootElement, "operation");
                var value = RequiredString(document.RootElement, "value");
                Require(operation is "issue" or "redeem" or "session-access" or "session-refresh");
                var nonce = Base64Url(Enumerable.Repeat((byte)++_nonceSequence, 32).ToArray());
                _nonces[operation] = nonce;
                return JsonResponse(HttpStatusCode.OK, JsonSerializer.Serialize(new
                {
                    nonce,
                    expiresAtUtc = Now.AddMinutes(2),
                }), includeNoStore: true);
            }

            ActionRequests++;
            return path switch
            {
                EmailRequestPath => EmailRequest(document.RootElement),
                SignInPath => SignIn(document.RootElement),
                AccessPath => Access(document.RootElement),
                RefreshPath => await RefreshAsync(document.RootElement, cancellationToken).ConfigureAwait(false),
                _ => throw new InvalidOperationException(),
            };
        }

        private HttpResponseMessage EmailRequest(JsonElement value)
        {
            RequireExactProperties(value, "email", "deviceProof");
            var email = RequiredString(value, "email");
            VerifyProof(RequiredString(value, "deviceProof"), "issue", "personal.login", _nonces["issue"], email, EmailRequestPath);
            return JsonResponse(HttpStatusCode.Accepted, JsonSerializer.Serialize(new
            {
                status = "submitted",
                challengeId = ChallengeId,
            }), includeNoStore: true);
        }

        private HttpResponseMessage SignIn(JsonElement value)
        {
            RequireExactProperties(value, "challengeId", "code", "deviceProof");
            Require(RequiredString(value, "challengeId") == ChallengeId && RequiredString(value, "code") == "123456");
            VerifyProof(RequiredString(value, "deviceProof"), "redeem", "personal.login", _nonces["redeem"], ChallengeId, SignInPath);
            if (FailSignInSubmitted) throw new HttpRequestException();
            return GrantResponse(SessionId, AccountId, GrantInstallationId ?? InstallationId, InvalidGrantTimes, false);
        }

        private HttpResponseMessage Access(JsonElement value)
        {
            RequireExactProperties(value, "accessToken", "deviceProof");
            var token = RequiredString(value, "accessToken");
            VerifyProof(RequiredString(value, "deviceProof"), "session-access", "personal.session.access", _nonces["session-access"], Base64Url(SHA256.HashData(Encoding.UTF8.GetBytes(token))), AccessPath);
            return JsonResponse(HttpStatusCode.OK, JsonSerializer.Serialize(new
            {
                status = "allowed",
                sessionId = SessionId,
                accountId = AccessAccountId ?? AccountId,
                installationId = InstallationId,
                checkedAtUtc = Now,
                accessExpiresAtUtc = Now.AddMinutes(5),
            }), includeNoStore: true);
        }

        private async Task<HttpResponseMessage> RefreshAsync(JsonElement value, CancellationToken cancellationToken)
        {
            RefreshActionRequests++;
            RequireExactProperties(value, "refreshToken", "deviceProof");
            var token = RequiredString(value, "refreshToken");
            VerifyProof(RequiredString(value, "deviceProof"), "session-refresh", "personal.session.refresh", _nonces["session-refresh"], Base64Url(SHA256.HashData(Encoding.UTF8.GetBytes(token))), RefreshPath);
            if (!BlockRefresh) return GrantResponse(RefreshSessionId ?? SessionId, AccountId, InstallationId, false, true);

            _blockedRefresh = new TaskCompletionSource<HttpResponseMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
            RefreshSubmitted.TrySetResult(true);
            return await _blockedRefresh.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
        }

        private void VerifyProof(string proof, string operation, string purpose, string nonce, string semanticValue, string route)
        {
            var segments = proof.Split('.');
            Require(segments.Length == 3 && segments.All(static value => value.Length > 0));
            var headerBytes = DecodeBase64Url(segments[0], expectedLength: -1);
            var payloadBytes = DecodeBase64Url(segments[1], expectedLength: -1);
            var signature = DecodeBase64Url(segments[2], 64);
            try
            {
                using var header = JsonDocument.Parse(headerBytes);
                RequireExactProperties(header.RootElement, "alg", "typ", "jwk");
                Require(RequiredString(header.RootElement, "alg") == "ES256" && RequiredString(header.RootElement, "typ") == "dpop+jwt");
                var jwk = header.RootElement.GetProperty("jwk");
                RequireExactProperties(jwk, "kty", "crv", "x", "y");
                Require(RequiredString(jwk, "kty") == "EC" && RequiredString(jwk, "crv") == "P-256");
                var x = DecodeBase64Url(RequiredString(jwk, "x"), 32);
                var y = DecodeBase64Url(RequiredString(jwk, "y"), 32);
                try
                {
                    using var payload = JsonDocument.Parse(payloadBytes);
                    RequireExactProperties(payload.RootElement, "htm", "htu", "iat", "jti", "nonce", "installation_id", "operation", "purpose", "request_hash");
                    Require(RequiredString(payload.RootElement, "htm") == "POST");
                    Require(RequiredString(payload.RootElement, "htu") == new Uri(Origin, route).AbsoluteUri);
                    Require(RequiredString(payload.RootElement, "operation") == operation && RequiredString(payload.RootElement, "purpose") == purpose);
                    Require(RequiredString(payload.RootElement, "nonce") == nonce && RequiredString(payload.RootElement, "installation_id") == InstallationId);
                    Require(payload.RootElement.GetProperty("iat").TryGetInt64(out var iat) && iat == Now.ToUnixTimeSeconds());
                    _ = DecodeBase64Url(RequiredString(payload.RootElement, "jti"), 32);
                    Require(RequiredString(payload.RootElement, "request_hash") == RequestHash(operation, purpose, semanticValue));
                    using var verifier = ECDsa.Create(new ECParameters
                    {
                        Curve = ECCurve.NamedCurves.nistP256,
                        Q = new ECPoint { X = x, Y = y },
                    });
                    var signingInput = Encoding.ASCII.GetBytes(segments[0] + "." + segments[1]);
                    try
                    {
                        Require(verifier.VerifyData(signingInput, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
                    }
                    finally { CryptographicOperations.ZeroMemory(signingInput); }
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(x);
                    CryptographicOperations.ZeroMemory(y);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(headerBytes);
                CryptographicOperations.ZeroMemory(payloadBytes);
                CryptographicOperations.ZeroMemory(signature);
            }
        }

        private static HttpResponseMessage GrantResponse(
            string sessionId, string accountId, string installationId, bool invalidTimes, bool rotated)
        {
            var issued = invalidTimes ? Now.AddMinutes(5) : Now;
            var accessExpiry = invalidTimes ? Now : Now.AddMinutes(5);
            return JsonResponse(HttpStatusCode.OK, JsonSerializer.Serialize(new
            {
                status = "authorized",
                sessionId,
                accountId,
                installationId,
                accessToken = rotated ? RefreshedAccessToken : AccessToken,
                refreshToken = rotated ? RefreshedRefreshToken : RefreshToken,
                issuedAtUtc = issued,
                accessExpiresAtUtc = accessExpiry,
                refreshExpiresAtUtc = Now.AddDays(7),
            }), includeNoStore: true);
        }
    }
}
