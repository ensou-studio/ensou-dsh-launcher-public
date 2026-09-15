using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Ensou.Dsh.Enterprise.Client;

namespace Ensou.Dsh.Enterprise.Launcher;

internal static class EnterpriseControlPlaneTransportFactory
{
    public static HttpClient Create()
    {
        return new HttpClient(CreateTransport(DecompressionMethods.GZip | DecompressionMethods.Deflate))
        {
            Timeout = TimeSpan.FromSeconds(30),
        };
    }

    public static HttpClient CreateGateway(
        Uri gatewayOrigin,
        EnterpriseDpopProofFactory proofFactory,
        IEnterpriseAccessTokenVault accessTokenVault,
        EnterpriseHarnessSession harnessSession,
        IEnumerable<EnterpriseLoopbackRoute> allowedRoutes)
    {
        var authorizationHandler = new EnterpriseGatewayAuthorizationHandler(
            gatewayOrigin,
            proofFactory,
            accessTokenVault,
            harnessSession,
            CreateTransport(DecompressionMethods.None),
            allowedRoutes);
        return new HttpClient(authorizationHandler)
        {
            Timeout = Timeout.InfiniteTimeSpan,
        };
    }

    public static HttpClient CreateUpdate() => new(
        CreateTransport(DecompressionMethods.None))
    {
        Timeout = TimeSpan.FromMinutes(5),
    };

    private static HttpClientHandler CreateTransport(
        DecompressionMethods automaticDecompression)
    {
        var handler = new HttpClientHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = automaticDecompression,
            CheckCertificateRevocationList = true,
            UseCookies = false,
            UseDefaultCredentials = false,
        };
#if ENTERPRISE_DEVELOPMENT_E2E
        var pinnedCertificateSha256 = Environment.GetEnvironmentVariable(
            "ENSOU_DSH_E2E_TLS_CERT_SHA256") ?? string.Empty;
        if (pinnedCertificateSha256.Length != 64
            || pinnedCertificateSha256.Any(character => !Uri.IsHexDigit(character)))
        {
            throw new InvalidOperationException(
                "Development E2E HTTPS requires ENSOU_DSH_E2E_TLS_CERT_SHA256.");
        }
        handler.CheckCertificateRevocationList = false;
        handler.ServerCertificateCustomValidationCallback = (
            request,
            certificate,
            _,
            _) => IsPinnedDevelopmentCertificate(
                request,
                certificate,
                pinnedCertificateSha256);
#endif
        return handler;
    }

#if ENTERPRISE_DEVELOPMENT_E2E
    private static bool IsPinnedDevelopmentCertificate(
        HttpRequestMessage request,
        X509Certificate2? certificate,
        string expectedSha256)
    {
        var host = request.RequestUri?.Host;
        if (certificate is null
            || host is null
            || !(string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase)
                || string.Equals(host, "127.0.0.1", StringComparison.Ordinal)
                || string.Equals(host, "::1", StringComparison.Ordinal))
            || DateTimeOffset.UtcNow < certificate.NotBefore.ToUniversalTime()
            || DateTimeOffset.UtcNow > certificate.NotAfter.ToUniversalTime())
        {
            return false;
        }
        return string.Equals(
            certificate.GetCertHashString(HashAlgorithmName.SHA256),
            expectedSha256,
            StringComparison.OrdinalIgnoreCase);
    }
#endif
}
