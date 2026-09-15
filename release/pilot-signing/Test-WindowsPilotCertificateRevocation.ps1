#requires -Version 7.4
[CmdletBinding()]
param([switch]$OnlineLoopback)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'WindowsPilotCertificateRevocation.psm1') -Force

# RSA keys remain in memory. The optional HTTP probe listens only on loopback.
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

public static class PilotRevocationFixture
{
    public static X509Certificate2 NewIssuer()
    {
        using var key = RSA.Create(3072);
        var request = new CertificateRequest("CN=Ephemeral DSH CRL test " + Guid.NewGuid(),
            key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(90));
    }

    public static X509Certificate2 NewLeaf(X509Certificate2 issuer, X509Extension cdp)
    {
        using var key = RSA.Create(3072);
        var request = new CertificateRequest("CN=Ephemeral DSH signing test", key,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new Oid("1.3.6.1.5.5.7.3.3") }, false));
        request.CertificateExtensions.Add(cdp);
        return request.Create(issuer, DateTimeOffset.UtcNow.AddMinutes(-2),
            DateTimeOffset.UtcNow.AddDays(30), RandomNumberGenerator.GetBytes(16));
    }

    public static object OnlineCheck(X509Certificate2 issuer, X509Certificate2 leaf)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(issuer);
        chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.3"));
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
        chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
        chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
        chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(5);
        bool valid = chain.Build(leaf);
        return new { valid, flags = chain.ChainStatus.Select(s => s.Status.ToString()).ToArray() };
    }
}

public sealed class PilotCrlLoopbackServer : IDisposable
{
    readonly TcpListener listener = new TcpListener(IPAddress.Loopback, 0);
    readonly CancellationTokenSource cancellation = new CancellationTokenSource();
    readonly Task worker;
    public byte[] Response = Array.Empty<byte>();
    public int Requests;
    public string Uri { get; }

    public PilotCrlLoopbackServer()
    {
        listener.Start();
        Uri = "http://127.0.0.1:" + ((IPEndPoint)listener.LocalEndpoint).Port + "/" + Guid.NewGuid().ToString("N") + ".crl";
        worker = Task.Run(async () =>
        {
            try
            {
                while (!cancellation.IsCancellationRequested)
                {
                    using var client = await listener.AcceptTcpClientAsync(cancellation.Token);
                    client.ReceiveTimeout = 5000;
                    using var stream = client.GetStream();
                    using var reader = new StreamReader(stream, Encoding.ASCII, false, 1024, true);
                    string line = await reader.ReadLineAsync(cancellation.Token);
                    if (line == null) continue;
                    while (!string.IsNullOrEmpty(await reader.ReadLineAsync(cancellation.Token))) { }
                    Interlocked.Increment(ref Requests);
                    byte[] body = Response;
                    byte[] header = Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Type: application/pkix-crl\r\nContent-Length: "
                        + body.Length + "\r\nConnection: close\r\n\r\n");
                    await stream.WriteAsync(header, cancellation.Token);
                    await stream.WriteAsync(body, cancellation.Token);
                    await stream.FlushAsync(cancellation.Token);
                }
            }
            catch (OperationCanceledException) { }
            catch (ObjectDisposedException) when (cancellation.IsCancellationRequested) { }
            catch (SocketException) when (cancellation.IsCancellationRequested) { }
        });
    }

    public void Dispose()
    {
        cancellation.Cancel();
        listener.Stop();
        if (!worker.Wait(TimeSpan.FromSeconds(10)))
            throw new InvalidOperationException("Loopback CRL server did not stop.");
        cancellation.Dispose();
    }
}
'@

$checks = 0
function Assert-Probe([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
    $script:checks++
}

foreach ($invalidUri in @('file:///C:/test.crl', 'https://user:pass@example.invalid/a.crl',
    'https://example.invalid/a.crl?token=test', 'https://example.invalid/a.crl#fragment',
    'https://example.invalid/', 'https://example.invalid/a/../b.crl')) {
    $rejected = $false
    try { $null = New-WindowsPilotCrlDistributionPointExtension -Uri $invalidUri }
    catch { $rejected = $true }
    Assert-Probe $rejected 'An invalid CRL URI was accepted.'
}

$issuer = [PilotRevocationFixture]::NewIssuer()
try {
    $now = [DateTimeOffset]::UtcNow.AddSeconds(-30)
    [byte[]]$crl = New-WindowsPilotInitialCertificateRevocationList `
        -Issuer $issuer -ThisUpdate $now -NextUpdate $now.AddDays(7)
    $crlNumber = [Numerics.BigInteger]::Zero
    $null = [Security.Cryptography.X509Certificates.CertificateRevocationListBuilder]::Load($crl, [ref]$crlNumber)
    Assert-Probe ($crlNumber -eq 1) 'The initial CRL must have number one.'
    $rejected = $false
    try { $null = New-WindowsPilotInitialCertificateRevocationList -Issuer $issuer -ThisUpdate $now -NextUpdate $now.AddDays(8) }
    catch { $rejected = $true }
    Assert-Probe $rejected 'The CRL lifetime ceiling was not enforced.'

    if ($OnlineLoopback) {
        if (-not $IsWindows) { throw 'This probe must validate the Windows online chain implementation.' }
        $scenarioIssuerThumbprints = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase)
        foreach ($scenario in @('good', 'revoked', 'wrong-issuer')) {
            $server = [PilotCrlLoopbackServer]::new()
            $scenarioIssuer = $null
            $leaf = $null
            $wrongIssuer = $null
            try {
                $scenarioIssuer = [PilotRevocationFixture]::NewIssuer()
                Assert-Probe $scenarioIssuerThumbprints.Add($scenarioIssuer.Thumbprint) `
                    'Online revocation scenarios reused an issuer identity.'
                $cdp = New-WindowsPilotCrlDistributionPointExtension -Uri $server.Uri
                $leaf = [PilotRevocationFixture]::NewLeaf($scenarioIssuer, $cdp)
                if ($scenario -eq 'revoked') {
                    $revoked = [Security.Cryptography.X509Certificates.CertificateRevocationListBuilder]::new()
                    $revoked.AddEntry($leaf, $now, [Security.Cryptography.X509Certificates.X509RevocationReason]::KeyCompromise)
                    $server.Response = $revoked.Build($scenarioIssuer, [Numerics.BigInteger]2, $now.AddDays(1),
                        [Security.Cryptography.HashAlgorithmName]::SHA256,
                        [Security.Cryptography.RSASignaturePadding]::Pkcs1, $now)
                }
                elseif ($scenario -eq 'wrong-issuer') {
                    $wrongIssuer = [PilotRevocationFixture]::NewIssuer()
                    $server.Response = New-WindowsPilotInitialCertificateRevocationList `
                        -Issuer $wrongIssuer -ThisUpdate $now -NextUpdate $now.AddDays(1)
                }
                else {
                    $server.Response = New-WindowsPilotInitialCertificateRevocationList `
                        -Issuer $scenarioIssuer -ThisUpdate $now -NextUpdate $now.AddDays(1)
                }
                $result = [PilotRevocationFixture]::OnlineCheck($scenarioIssuer, $leaf)
                Assert-Probe ($server.Requests -gt 0) "The $scenario CRL was not fetched from the isolated HTTP server."
                Assert-Probe ($result.valid -eq ($scenario -eq 'good')) "Unexpected online chain result: $scenario."
                if ($scenario -eq 'revoked') {
                    Assert-Probe ($result.flags -contains 'Revoked') 'The revoked leaf was not identified as revoked.'
                }
                [pscustomobject]@{scenario=$scenario; fetched=$server.Requests; valid=$result.valid; flags=$result.flags} | ConvertTo-Json -Compress
            }
            finally {
                if ($null -ne $leaf) { $leaf.Dispose() }
                if ($null -ne $wrongIssuer) { $wrongIssuer.Dispose() }
                if ($null -ne $scenarioIssuer) { $scenarioIssuer.Dispose() }
                $server.Dispose()
            }
        }
    }
}
finally { $issuer.Dispose() }

[pscustomobject]@{status='PASS'; checks=$checks; onlineLoopback=$OnlineLoopback.IsPresent; certificateStoreWrites=$false} | ConvertTo-Json
