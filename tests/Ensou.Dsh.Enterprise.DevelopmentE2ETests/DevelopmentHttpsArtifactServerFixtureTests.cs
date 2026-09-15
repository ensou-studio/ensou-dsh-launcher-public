using System.Net;
using System.ComponentModel;
using System.Text;
using Ensou.Dsh.Enterprise.Client;

namespace Ensou.Dsh.Enterprise.DevelopmentE2ETests;

internal static class DevelopmentHttpsArtifactServerTests
{
    private static readonly Uri ManifestUri = new(
        "https://updates.example/v2/channels/lab/release-set.v2.json");
    private static readonly Uri ArtifactUri = new(
        "https://artifacts.example/releases/lab/runtime.zip");

    internal static async Task<object> RunAsync()
    {
        var authenticatedTransportConstruction =
            AssertDevelopmentAuthenticatedTransportConstruction();
        var authorizationContractChecks = await DevelopmentFeedAuthorizationForwarderTests.RunAsync()
            .ConfigureAwait(false);
        var manifestBytes = Encoding.UTF8.GetBytes("signed-manifest-fixture");
        var artifactBytes = Encoding.UTF8.GetBytes("signed-artifact-fixture");
        await using var server = await DevelopmentHttpsArtifactServer.StartAsync(
            new Dictionary<Uri, byte[]>
            {
                [ManifestUri] = manifestBytes,
                [ArtifactUri] = artifactBytes,
            }).ConfigureAwait(false);

        using (var client = server.CreateClient())
        {
            AssertBytesEqual(
                manifestBytes,
                await RunStageAsync(
                        "manifest-get",
                        server,
                        () => client.GetByteArrayAsync(ManifestUri))
                    .ConfigureAwait(false),
                "Pinned HTTPS manifest bytes differ.");
            AssertBytesEqual(
                artifactBytes,
                await RunStageAsync(
                        "artifact-get",
                        server,
                        () => client.GetByteArrayAsync(ArtifactUri))
                    .ConfigureAwait(false),
                "Pinned HTTPS artifact bytes differ.");

            var beforeUnknownOrigin = server.ConnectAttempts;
            await RunStageAsync("unknown-origin", server, async () =>
            {
                await AssertThrowsAsync<HttpRequestException>(() => client.GetAsync(
                    new Uri("https://untrusted.example/v2/channels/lab/release-set.v2.json")))
                    .ConfigureAwait(false);
                if (server.ConnectAttempts != beforeUnknownOrigin)
                {
                    throw new InvalidDataException(
                        "An unknown HTTPS origin reached the owned loopback listener.");
                }
            }).ConfigureAwait(false);

            var beforeHttpOrigin = server.ConnectAttempts;
            await RunStageAsync("http-origin", server, async () =>
            {
                await AssertThrowsAsync<HttpRequestException>(() => client.GetAsync(
                    new Uri("http://updates.example:443/v2/channels/lab/release-set.v2.json")))
                    .ConfigureAwait(false);
                if (server.ConnectAttempts != beforeHttpOrigin)
                {
                    throw new InvalidDataException(
                        "A non-HTTPS same-host origin reached the owned loopback listener.");
                }
            }).ConfigureAwait(false);

            var beforeUserInfoOrigin = server.ConnectAttempts;
            await RunStageAsync("userinfo-origin", server, async () =>
            {
                await AssertThrowsAsync<HttpRequestException>(() => client.GetAsync(
                    new Uri("https://untrusted@updates.example/v2/channels/lab/release-set.v2.json")))
                    .ConfigureAwait(false);
                if (server.ConnectAttempts != beforeUserInfoOrigin)
                {
                    throw new InvalidDataException(
                        "A userinfo-bearing HTTPS origin reached the owned loopback listener.");
                }
            }).ConfigureAwait(false);

            await RunStageAsync("invalid-route", server, async () =>
            {
                using var invalidRoute = await client.GetAsync(
                    new Uri("https://updates.example/v2/channels/lab/unknown.json"))
                    .ConfigureAwait(false);
                if (invalidRoute.StatusCode != HttpStatusCode.NotFound)
                {
                    throw new InvalidDataException("An unadmitted HTTPS artifact route was not denied.");
                }
            }).ConfigureAwait(false);

            await RunStageAsync("invalid-query", server, async () =>
            {
                using var invalidQuery = await client.GetAsync(
                    new Uri("https://updates.example/v2/channels/lab/release-set.v2.json?unexpected=1"))
                    .ConfigureAwait(false);
                if (invalidQuery.StatusCode != HttpStatusCode.NotFound)
                {
                    throw new InvalidDataException("An unadmitted HTTPS artifact query was not denied.");
                }
            }).ConfigureAwait(false);

            await RunStageAsync("host-misuse", server, async () =>
            {
                using var hostMisuseRequest = new HttpRequestMessage(HttpMethod.Get, ManifestUri);
                hostMisuseRequest.Headers.Host = "artifacts.example";
                using var hostMisuse = await client.SendAsync(hostMisuseRequest).ConfigureAwait(false);
                if (hostMisuse.StatusCode != HttpStatusCode.NotFound)
                {
                    throw new InvalidDataException("A mismatched HTTPS Host header was not denied.");
                }
            }).ConfigureAwait(false);

            await RunStageAsync("invalid-method", server, async () =>
            {
                using var invalidMethod = await client.PostAsync(
                    ManifestUri,
                    new ByteArrayContent([1])).ConfigureAwait(false);
                if (invalidMethod.StatusCode != HttpStatusCode.MethodNotAllowed)
                {
                    throw new InvalidDataException("A non-GET HTTPS artifact request was not denied.");
                }
            }).ConfigureAwait(false);
        }

        using (var wrongPinClient = server.CreateClient(new string('0', 64)))
        {
            await RunStageAsync("wrong-pin", server, () =>
                AssertThrowsAsync<HttpRequestException>(() => wrongPinClient.GetAsync(ManifestUri)))
                .ConfigureAwait(false);
        }

        var wrongHostnameRejected = false;
        await using (var wrongHostnameServer = await DevelopmentHttpsArtifactServer.StartAsync(
            new Dictionary<Uri, byte[]>
            {
                [ManifestUri] = manifestBytes,
            },
            certificateOnlyHost: ArtifactUri.Host).ConfigureAwait(false))
        {
            using var wrongHostnameClient = wrongHostnameServer.CreateClient(
                wrongHostnameServer.LeafCertificateSha256);
            await RunStageAsync("wrong-hostname-certificate", wrongHostnameServer, async () =>
            {
                await AssertThrowsAsync<HttpRequestException>(() =>
                    wrongHostnameClient.GetByteArrayAsync(ManifestUri)).ConfigureAwait(false);
                if (wrongHostnameServer.SuccessfulRequests.Count != 0)
                {
                    throw new InvalidDataException(
                        "A certificate without the requested hostname reached the HTTPS route.");
                }
                if (wrongHostnameServer.TlsDiagnostics.CertificateValidationRejected < 1)
                {
                    throw new InvalidDataException(
                        "The wrong-hostname certificate was not rejected during TLS validation.");
                }
            }).ConfigureAwait(false);
            wrongHostnameRejected = true;
        }

        var requests = server.SuccessfulRequests;
        if (requests.Count != 2
            || requests[0].Uri != ManifestUri
            || requests[0].Bytes != manifestBytes.Length
            || requests[1].Uri != ArtifactUri
            || requests[1].Bytes != artifactBytes.Length)
        {
            throw new InvalidDataException(
                "Pinned HTTPS artifact request evidence is incomplete or unexpected.");
        }

        return new
        {
            authenticatedTransportConstruction,
            authorizationContractChecks,
            authorizationContractScope = "MOCK_CONTROL_TRANSPORT_ONLY_NOT_LIVE_DATABASE",
            successfulRequestCount = requests.Count,
            manifestBytes = manifestBytes.Length,
            artifactBytes = artifactBytes.Length,
            tlsCertificateValidationCallbacks = server.TlsDiagnostics.CertificateValidationCallbacks,
            tlsCertificateValidationRejected = server.TlsDiagnostics.CertificateValidationRejected,
            serverErrorCount = server.ServerErrors.Count,
            unknownOriginRejectedBeforeConnect = true,
            invalidRouteRejected = true,
            wrongPinRejected = true,
            wrongHostnameRejected,
        };
    }

    private static bool AssertDevelopmentAuthenticatedTransportConstruction()
    {
        const string certificateVariable = "ENSOU_DSH_E2E_UPDATE_TLS_CERT_SHA256";
        const string portVariable = "ENSOU_DSH_E2E_UPDATE_LOOPBACK_PORT";
        var previousCertificate = Environment.GetEnvironmentVariable(certificateVariable);
        var previousPort = Environment.GetEnvironmentVariable(portVariable);
        try
        {
            Environment.SetEnvironmentVariable(certificateVariable, new string('a', 64));
            Environment.SetEnvironmentVariable(portVariable, "43123");
            var keyStore = new ConstructionOnlyDeviceProofKeyStore();
            using var vault = new EnterpriseAccessTokenVault();
            using var client = EnterpriseUpdateFeedTransport.CreateTransactionClient(
                ManifestUri,
                new Uri("https://updates.example/"),
                new EnterpriseDpopProofFactory(keyStore),
                vault);
            if (client.Timeout != TimeSpan.FromHours(2) || keyStore.WasUsed)
            {
                throw new InvalidDataException(
                    "Development authenticated update transport construction was not side-effect free.");
            }
            return true;
        }
        finally
        {
            Environment.SetEnvironmentVariable(certificateVariable, previousCertificate);
            Environment.SetEnvironmentVariable(portVariable, previousPort);
        }
    }

    private static async Task<T> RunStageAsync<T>(
        string stage,
        DevelopmentHttpsArtifactServer server,
        Func<Task<T>> action)
    {
        try
        {
            return await action().ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            throw StageFailure(stage, server, exception);
        }
    }

    private static async Task RunStageAsync(
        string stage,
        DevelopmentHttpsArtifactServer server,
        Func<Task> action)
    {
        try
        {
            await action().ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            throw StageFailure(stage, server, exception);
        }
    }

    private static InvalidDataException StageFailure(
        string stage,
        DevelopmentHttpsArtifactServer server,
        Exception exception)
    {
        var tls = server.TlsDiagnostics;
        var serverErrors = server.ServerErrors;
        var serverErrorSummary = string.Join(
            ",",
            serverErrors.Select(error =>
                $"{error.ExceptionType}@0x{error.HResult:X8}:{error.EventId}"));
        return new InvalidDataException(
            $"HTTPS fixture stage={stage}; chain={DescribeExceptionChain(exception)}; "
            + $"tls=callbacks:{tls.CertificateValidationCallbacks},accepted:{tls.CertificateValidationAccepted},"
            + $"rejected:{tls.CertificateValidationRejected},errors:{tls.LastSslPolicyErrors},"
            + $"callback:{tls.CallbackExceptionType ?? "none"}@0x{tls.CallbackExceptionHResult:X8}; "
            + $"serverErrors:{serverErrors.Count}[{serverErrorSummary}]",
            exception);
    }

    private static string DescribeExceptionChain(Exception exception)
    {
        var values = new List<string>();
        for (var current = exception; current is not null && values.Count < 4;
             current = current.InnerException)
        {
            var nativeError = current is Win32Exception win32
                ? $"/native=0x{win32.NativeErrorCode:X8}"
                : string.Empty;
            values.Add($"{current.GetType().Name}@0x{current.HResult:X8}{nativeError}");
        }
        return string.Join(">", values);
    }

    private static async Task AssertThrowsAsync<TException>(Func<Task> action)
        where TException : Exception
    {
        try
        {
            await action().ConfigureAwait(false);
        }
        catch (TException)
        {
            return;
        }

        throw new InvalidDataException($"Expected {typeof(TException).Name} was not thrown.");
    }

    private static void AssertBytesEqual(byte[] expected, byte[] actual, string message)
    {
        if (!expected.AsSpan().SequenceEqual(actual))
        {
            throw new InvalidDataException(message);
        }
    }

    private sealed class ConstructionOnlyDeviceProofKeyStore : IEnterpriseDeviceProofKeyStore
    {
        public bool WasUsed { get; private set; }

        public EnterpriseDevicePublicIdentity GetOrCreatePublicIdentity()
        {
            WasUsed = true;
            throw new InvalidOperationException("Construction must not materialize a device key.");
        }

        public byte[] Sign(ReadOnlySpan<byte> payload)
        {
            WasUsed = true;
            throw new InvalidOperationException("Construction must not sign a device proof.");
        }

        public void DeleteForSecurityReset() => WasUsed = true;
    }
}
