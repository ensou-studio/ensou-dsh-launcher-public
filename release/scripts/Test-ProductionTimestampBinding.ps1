#Requires -Version 7.4
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'ProductionReleaseState.psm1') -Force

# These certificates and signatures exist only in memory. This suite exercises
# timestamp binding, not OS certificate trust, signed application identity, or
# production release admission. It never writes to a certificate store.
$fixtures = [Collections.Generic.List[object]]::new()
$script:Passed = 0

function Assert-Test {
    param([bool]$Condition, [string]$Label)
    if (-not $Condition) { throw "FAIL: $Label" }
    $script:Passed++
    Write-Output "PASS: $Label"
}

function Assert-Rejected {
    param([string]$Label, [string]$ExpectedMessage, [scriptblock]$Action)
    $failure = $null
    try { $null = & $Action } catch { $failure = $_.Exception.Message }
    Assert-Test ($null -ne $failure -and $failure.Contains($ExpectedMessage)) `
        "$Label (expected: $ExpectedMessage; actual: $failure)"
}

function New-MemoryCertificate {
    param([string]$Subject, [switch]$Timestamping)
    $key = [Security.Cryptography.ECDsa]::Create(
        [Security.Cryptography.ECCurve+NamedCurves]::nistP256)
    $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
        $Subject, $key, [Security.Cryptography.HashAlgorithmName]::SHA256)
    $request.CertificateExtensions.Add(
        [Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new(
            $false, $false, 0, $true))
    $request.CertificateExtensions.Add(
        [Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
            [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature, $true))
    $oids = [Security.Cryptography.OidCollection]::new()
    $usage = if ($Timestamping) { '1.3.6.1.5.5.7.3.8' } else { '1.3.6.1.5.5.7.3.3' }
    $null = $oids.Add([Security.Cryptography.Oid]::new($usage))
    $request.CertificateExtensions.Add(
        [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($oids, $true))
    $fixture = [pscustomobject]@{
        Key = $key
        Certificate = $request.CreateSelfSigned(
            [DateTimeOffset]::UtcNow.AddDays(-1), [DateTimeOffset]::UtcNow.AddDays(2))
    }
    $fixtures.Add($fixture)
    return $fixture.Certificate
}

function New-PrimaryCms {
    param([Security.Cryptography.X509Certificates.X509Certificate2]$Certificate, [string]$Content)
    $cms = [Security.Cryptography.Pkcs.SignedCms]::new(
        [Security.Cryptography.Pkcs.ContentInfo]::new([Text.Encoding]::UTF8.GetBytes($Content)), $false)
    $signer = [Security.Cryptography.Pkcs.CmsSigner]::new(
        [Security.Cryptography.Pkcs.SubjectIdentifierType]::IssuerAndSerialNumber, $Certificate)
    $signer.IncludeOption = [Security.Cryptography.X509Certificates.X509IncludeOption]::EndCertOnly
    $cms.ComputeSignature($signer)
    return $cms
}

function New-TimestampToken {
    param(
        [Security.Cryptography.Pkcs.SignerInfo]$PrimarySigner,
        [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )
    $writer = [Formats.Asn1.AsnWriter]::new([Formats.Asn1.AsnEncodingRules]::DER)
    $null = $writer.PushSequence()
    $writer.WriteInteger([long]1)
    $writer.WriteObjectIdentifier('1.3.6.1.4.1.55555.1')
    $null = $writer.PushSequence()
    $null = $writer.PushSequence()
    $writer.WriteObjectIdentifier('2.16.840.1.101.3.4.2.1')
    $writer.WriteNull()
    $writer.PopSequence()
    $writer.WriteOctetString([Security.Cryptography.SHA256]::HashData($PrimarySigner.GetSignature()))
    $writer.PopSequence()
    $writer.WriteInteger([long]1)
    $writer.WriteGeneralizedTime([DateTimeOffset]::UtcNow, $true)
    $writer.PopSequence()
    $cms = [Security.Cryptography.Pkcs.SignedCms]::new(
        [Security.Cryptography.Pkcs.ContentInfo]::new(
            [Security.Cryptography.Oid]::new('1.2.840.113549.1.9.16.1.4'), $writer.Encode()), $false)
    $signer = [Security.Cryptography.Pkcs.CmsSigner]::new(
        [Security.Cryptography.Pkcs.SubjectIdentifierType]::IssuerAndSerialNumber, $Certificate)
    $signer.IncludeOption = [Security.Cryptography.X509Certificates.X509IncludeOption]::EndCertOnly
    $essWriter = [Formats.Asn1.AsnWriter]::new([Formats.Asn1.AsnEncodingRules]::DER)
    $null = $essWriter.PushSequence()
    $null = $essWriter.PushSequence()
    $null = $essWriter.PushSequence()
    $essWriter.WriteOctetString([Security.Cryptography.SHA256]::HashData($Certificate.RawData))
    $essWriter.PopSequence()
    $essWriter.PopSequence()
    $essWriter.PopSequence()
    $null = $signer.SignedAttributes.Add([Security.Cryptography.AsnEncodedData]::new(
        [Security.Cryptography.Oid]::new('1.2.840.113549.1.9.16.2.47'), $essWriter.Encode()))
    $cms.ComputeSignature($signer)
    return ,$cms.Encode()
}

function Add-TimestampAttribute {
    param([Security.Cryptography.Pkcs.SignedCms]$Cms, [string]$Oid, [byte[]]$Token)
    $Cms.SignerInfos[0].AddUnsignedAttribute(
        [Security.Cryptography.AsnEncodedData]::new([Security.Cryptography.Oid]::new($Oid), $Token))
}

try {
    $codeCertificate = New-MemoryCertificate -Subject 'CN=Ensou timestamp regression code'
    $tsaCertificate = New-MemoryCertificate -Subject 'CN=Ensou timestamp regression TSA' -Timestamping
    $otherCertificate = New-MemoryCertificate -Subject 'CN=Ensou unrelated timestamp TSA' -Timestamping
    $cmsOid = '1.2.840.113549.1.9.16.2.14'
    $windowsOid = '1.3.6.1.4.1.311.3.3.1'
    $expected = @{
        ExpectedSigner = $codeCertificate
        ExpectedTimestampSigner = $tsaCertificate
    }
    foreach ($oid in @($cmsOid, $windowsOid)) {
        $primary = New-PrimaryCms -Certificate $codeCertificate -Content "valid-$oid"
        $token = New-TimestampToken -PrimarySigner $primary.SignerInfos[0] -Certificate $tsaCertificate
        Add-TimestampAttribute -Cms $primary -Oid $oid -Token $token
        $binding = Assert-AuthenticodeSignerRfc3161Timestamp -PrimarySigner $primary.SignerInfos[0] @expected
        Assert-Test ($binding.TimestampProtocol -ceq 'RFC3161' -and
            $binding.TimestampTokenOid -ceq $oid -and
            $binding.TimestampContentTypeOid -ceq '1.2.840.113549.1.9.16.1.4' -and
            -not $binding.LegacyCounterSignaturePresent) "Accept one bound timestamp: $oid"
        Assert-Rejected "Reject wrong TSA certificate: $oid" 'differs from the trusted Authenticode timestamper' {
            Assert-AuthenticodeSignerRfc3161Timestamp -PrimarySigner $primary.SignerInfos[0] `
                -ExpectedSigner $codeCertificate -ExpectedTimestampSigner $otherCertificate
        }
        Assert-Rejected "Reject wrong primary certificate: $oid" 'differs from the trusted signer' {
            Assert-AuthenticodeSignerRfc3161Timestamp -PrimarySigner $primary.SignerInfos[0] `
                -ExpectedSigner $otherCertificate -ExpectedTimestampSigner $tsaCertificate
        }
        $unrelated = New-PrimaryCms -Certificate $codeCertificate -Content "unrelated-$oid"
        Add-TimestampAttribute -Cms $unrelated -Oid $oid -Token $token
        Assert-Rejected "Reject replay onto another primary signature: $oid" 'messageImprint' {
            Assert-AuthenticodeSignerRfc3161Timestamp -PrimarySigner $unrelated.SignerInfos[0] @expected
        }
        Assert-Rejected "Reject token with trailing data: $oid" 'not one exact canonical token' {
            Assert-Rfc3161TimestampTokenBinding -TokenBytes ([byte[]]($token + @(0))) `
                -PrimarySigner $primary.SignerInfos[0] -ExpectedTimestampSigner $tsaCertificate `
                -TimestampAttributeOid $oid
        }
        $malformed = New-PrimaryCms -Certificate $codeCertificate -Content "malformed-$oid"
        Add-TimestampAttribute -Cms $malformed -Oid $oid -Token ([byte[]]@(0x30, 0))
        Assert-Rejected "Reject malformed token: $oid" 'not one exact canonical token' {
            Assert-AuthenticodeSignerRfc3161Timestamp -PrimarySigner $malformed.SignerInfos[0] @expected
        }
        # A valid token must not hide a second, invalid token under the same OID.
        Add-TimestampAttribute -Cms $primary -Oid $oid -Token ([byte[]]@(0x30, 0))
        Assert-Rejected "Reject multiple values: $oid" 'exactly one RFC3161 timestamp attribute with exactly one value' {
            Assert-AuthenticodeSignerRfc3161Timestamp -PrimarySigner $primary.SignerInfos[0] @expected
        }
    }
    $both = New-PrimaryCms -Certificate $codeCertificate -Content 'both-supported-oids'
    $token = New-TimestampToken -PrimarySigner $both.SignerInfos[0] -Certificate $tsaCertificate
    foreach ($oid in @($cmsOid, $windowsOid)) { Add-TimestampAttribute -Cms $both -Oid $oid -Token $token }
    Assert-Rejected 'Reject simultaneous CMS and Windows timestamp attributes' 'exactly one RFC3161 timestamp attribute with exactly one value' {
        Assert-AuthenticodeSignerRfc3161Timestamp -PrimarySigner $both.SignerInfos[0] @expected
    }
    $missing = New-PrimaryCms -Certificate $codeCertificate -Content 'no-timestamp'
    Assert-Rejected 'Reject absent timestamp' 'exactly one RFC3161 timestamp attribute with exactly one value' {
        Assert-AuthenticodeSignerRfc3161Timestamp -PrimarySigner $missing.SignerInfos[0] @expected
    }
    $token = New-TimestampToken -PrimarySigner $missing.SignerInfos[0] -Certificate $tsaCertificate
    Add-TimestampAttribute -Cms $missing -Oid '1.2.840.113549.1.9.16.2.15' -Token $token
    Assert-Rejected 'Reject unrecognized timestamp OID' 'exactly one RFC3161 timestamp attribute with exactly one value' {
        Assert-AuthenticodeSignerRfc3161Timestamp -PrimarySigner $missing.SignerInfos[0] @expected
    }
    foreach ($includeRfc3161 in @($false, $true)) {
        $legacy = New-PrimaryCms -Certificate $codeCertificate -Content "legacy-$includeRfc3161"
        if ($includeRfc3161) {
            $token = New-TimestampToken -PrimarySigner $legacy.SignerInfos[0] -Certificate $tsaCertificate
            Add-TimestampAttribute -Cms $legacy -Oid $windowsOid -Token $token
        }
        $counterSigner = [Security.Cryptography.Pkcs.CmsSigner]::new(
            [Security.Cryptography.Pkcs.SubjectIdentifierType]::IssuerAndSerialNumber, $tsaCertificate)
        $counterSigner.IncludeOption = [Security.Cryptography.X509Certificates.X509IncludeOption]::EndCertOnly
        $legacy.SignerInfos[0].ComputeCounterSignature($counterSigner)
        Assert-Rejected "Reject legacy countersignature; RFC3161 also present=$includeRfc3161" 'forbidden legacy counterSignature' {
            Assert-AuthenticodeSignerRfc3161Timestamp -PrimarySigner $legacy.SignerInfos[0] @expected
        }
    }
    Write-Output "PRODUCTION-TIMESTAMP-BINDING-PASS: $script:Passed checks; in-memory fixtures only; no production admission claimed."
}
finally {
    foreach ($fixture in $fixtures) {
        $fixture.Certificate.Dispose()
        $fixture.Key.Dispose()
    }
}
