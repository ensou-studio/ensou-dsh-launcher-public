#requires -Version 7.4
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function New-WindowsPilotCrlDistributionPointExtension {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Uri)

    $parsed = $null
    if (-not [Uri]::TryCreate($Uri, [UriKind]::Absolute, [ref]$parsed) -or
        $parsed.Scheme -cnotin @('http', 'https') -or
        [string]::IsNullOrEmpty($parsed.Host) -or
        -not [string]::IsNullOrEmpty($parsed.UserInfo) -or
        -not [string]::IsNullOrEmpty($parsed.Query) -or
        -not [string]::IsNullOrEmpty($parsed.Fragment) -or
        $parsed.AbsolutePath -eq '/' -or
        -not $parsed.AbsolutePath.EndsWith('.crl', [StringComparison]::Ordinal) -or
        $Uri -cne $parsed.AbsoluteUri -or $Uri.Length -gt 2048) {
        throw 'The CRL distribution point must be a canonical HTTP(S) .crl URL without credentials, query, or fragment.'
    }

    return [Security.Cryptography.X509Certificates.CertificateRevocationListBuilder]::BuildCrlDistributionPointExtension(
        [string[]]@($parsed.AbsoluteUri), $false)
}

function New-WindowsPilotInitialCertificateRevocationList {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [Security.Cryptography.X509Certificates.X509Certificate2]$Issuer,
        [Parameter(Mandatory = $true)][DateTimeOffset]$ThisUpdate,
        [Parameter(Mandatory = $true)][DateTimeOffset]$NextUpdate
    )

    if ($ThisUpdate -lt [DateTimeOffset]$Issuer.NotBefore.ToUniversalTime() -or
        $NextUpdate -gt [DateTimeOffset]$Issuer.NotAfter.ToUniversalTime() -or
        $NextUpdate -le $ThisUpdate -or
        ($NextUpdate - $ThisUpdate).TotalDays -gt 7) {
        throw 'The initial CRL must be valid within the issuer lifetime for at most seven days.'
    }

    # This function is only for a newly generated CA with no prior issued leaves.
    # It is not a renewal API: renewing must retain revoked entries and increase the CRL number.
    $builder = [Security.Cryptography.X509Certificates.CertificateRevocationListBuilder]::new()
    [byte[]]$bytes = $builder.Build(
        $Issuer, [Numerics.BigInteger]::One, $NextUpdate,
        [Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.RSASignaturePadding]::Pkcs1, $ThisUpdate)
    return ,$bytes
}

Export-ModuleMember -Function @(
    'New-WindowsPilotCrlDistributionPointExtension',
    'New-WindowsPilotInitialCertificateRevocationList'
)
