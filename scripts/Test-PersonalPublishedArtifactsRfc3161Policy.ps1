#requires -Version 7.2

[CmdletBinding()]
param(
    [string]$RealRfc3161PeFixturePath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$productionReleaseStateModule = [IO.Path]::GetFullPath((Join-Path `
    $PSScriptRoot `
    '..\release\scripts\ProductionReleaseState.psm1'))
Microsoft.PowerShell.Core\Import-Module `
    -Name $productionReleaseStateModule `
    -Force `
    -ErrorAction Stop

function Assert-Throws {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Action,
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][string]$ExpectedMessage
    )

    try {
        & $Action
    }
    catch {
        if (-not $_.Exception.Message.Contains(
                $ExpectedMessage,
                [StringComparison]::OrdinalIgnoreCase)) {
            throw "$Label failed for the wrong reason: $($_.Exception.Message)"
        }
        return
    }
    throw "$Label did not fail closed."
}

function New-TestSigningCertificate {
    param(
        [Parameter(Mandatory = $true)][string]$Subject,
        [switch]$Timestamping
    )

    $key = [Security.Cryptography.ECDsa]::Create(
        [Security.Cryptography.ECCurve+NamedCurves]::nistP256)
    try {
        $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
            $Subject,
            $key,
            [Security.Cryptography.HashAlgorithmName]::SHA256)
        $request.CertificateExtensions.Add(
            [Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new(
                $false,
                $false,
                0,
                $true))
        $request.CertificateExtensions.Add(
            [Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
                [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature,
                $true))
        $oids = [Security.Cryptography.OidCollection]::new()
        $eku = if ($Timestamping) {
            '1.3.6.1.5.5.7.3.8'
        }
        else {
            '1.3.6.1.5.5.7.3.3'
        }
        [void]$oids.Add([Security.Cryptography.Oid]::new($eku))
        $request.CertificateExtensions.Add(
            [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new(
                $oids,
                $true))
        return $request.CreateSelfSigned(
            [DateTimeOffset]::UtcNow.AddDays(-1),
            [DateTimeOffset]::UtcNow.AddDays(2))
    }
    finally {
        $key.Dispose()
    }
}

function New-TestUnsignedPe {
    [byte[]]$bytes = [byte[]]::new(512)
    $bytes[0] = 0x4d
    $bytes[1] = 0x5a
    [BitConverter]::GetBytes([int]0x80).CopyTo($bytes, 0x3c)
    $bytes[0x80] = 0x50
    $bytes[0x81] = 0x45
    [BitConverter]::GetBytes([uint16]224).CopyTo($bytes, 0x80 + 20)
    $optionalOffset = 0x80 + 24
    [BitConverter]::GetBytes([uint16]0x10b).CopyTo($bytes, $optionalOffset)
    return ,$bytes
}

function New-TestSpcIndirectDataContent {
    param([Parameter(Mandatory = $true)][byte[]]$PeBytes)

    $digest = [Convert]::FromHexString(
        (ProductionReleaseState\Get-PeContentSha256 -Bytes $PeBytes))
    $writer = [Formats.Asn1.AsnWriter]::new(
        [Formats.Asn1.AsnEncodingRules]::DER)
    $null = $writer.PushSequence()
    $null = $writer.PushSequence()
    $writer.WriteObjectIdentifier('1.3.6.1.4.1.311.2.1.15')
    $writer.PopSequence()
    $null = $writer.PushSequence()
    $null = $writer.PushSequence()
    $writer.WriteObjectIdentifier('2.16.840.1.101.3.4.2.1')
    $writer.WriteNull()
    $writer.PopSequence()
    $writer.WriteOctetString($digest)
    $writer.PopSequence()
    $writer.PopSequence()
    return $writer.Encode()
}

function New-TestPrimaryCms {
    param(
        [Parameter(Mandatory = $true)]
        [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory = $true)][byte[]]$PeBytes,
        [string]$ContentTypeOid = '1.3.6.1.4.1.311.2.1.4',
        [AllowNull()][byte[]]$Content = $null
    )

    if ($null -eq $Content) {
        $Content = New-TestSpcIndirectDataContent -PeBytes $PeBytes
    }
    $cms = [Security.Cryptography.Pkcs.SignedCms]::new(
        [Security.Cryptography.Pkcs.ContentInfo]::new(
            [Security.Cryptography.Oid]::new($ContentTypeOid),
            $Content),
        $false)
    $signer = [Security.Cryptography.Pkcs.CmsSigner]::new(
        [Security.Cryptography.Pkcs.SubjectIdentifierType]::IssuerAndSerialNumber,
        $Certificate)
    $signer.IncludeOption =
        [Security.Cryptography.X509Certificates.X509IncludeOption]::EndCertOnly
    $cms.ComputeSignature($signer)
    return $cms
}

function New-TestRfc3161Token {
    param(
        [Parameter(Mandatory = $true)]
        [Security.Cryptography.Pkcs.SignerInfo]$PrimarySigner,
        [Parameter(Mandatory = $true)]
        [Security.Cryptography.X509Certificates.X509Certificate2]$TimestampCertificate
    )

    $signatureHash = [Security.Cryptography.SHA256]::HashData(
        $PrimarySigner.GetSignature())
    $writer = [Formats.Asn1.AsnWriter]::new(
        [Formats.Asn1.AsnEncodingRules]::DER)
    $null = $writer.PushSequence()
    $writer.WriteInteger([long]1)
    $writer.WriteObjectIdentifier('1.3.6.1.4.1.55555.1')
    $null = $writer.PushSequence()
    $null = $writer.PushSequence()
    $writer.WriteObjectIdentifier('2.16.840.1.101.3.4.2.1')
    $writer.WriteNull()
    $writer.PopSequence()
    $writer.WriteOctetString($signatureHash)
    $writer.PopSequence()
    $writer.WriteInteger([long]1)
    $writer.WriteGeneralizedTime([DateTimeOffset]::UtcNow, $true)
    $writer.PopSequence()

    $contentInfo = [Security.Cryptography.Pkcs.ContentInfo]::new(
        [Security.Cryptography.Oid]::new('1.2.840.113549.1.9.16.1.4'),
        $writer.Encode())
    $tokenCms = [Security.Cryptography.Pkcs.SignedCms]::new($contentInfo, $false)
    $timestampSigner = [Security.Cryptography.Pkcs.CmsSigner]::new(
        [Security.Cryptography.Pkcs.SubjectIdentifierType]::IssuerAndSerialNumber,
        $TimestampCertificate)
    $timestampSigner.IncludeOption =
        [Security.Cryptography.X509Certificates.X509IncludeOption]::EndCertOnly

    $essWriter = [Formats.Asn1.AsnWriter]::new(
        [Formats.Asn1.AsnEncodingRules]::DER)
    $null = $essWriter.PushSequence()
    $null = $essWriter.PushSequence()
    $null = $essWriter.PushSequence()
    $essWriter.WriteOctetString(
        [Security.Cryptography.SHA256]::HashData(
            $TimestampCertificate.RawData))
    $essWriter.PopSequence()
    $essWriter.PopSequence()
    $essWriter.PopSequence()
    [void]$timestampSigner.SignedAttributes.Add(
        [Security.Cryptography.AsnEncodedData]::new(
            [Security.Cryptography.Oid]::new('1.2.840.113549.1.9.16.2.47'),
            $essWriter.Encode()))
    $tokenCms.ComputeSignature($timestampSigner)
    return $tokenCms.Encode()
}

function Add-Rfc3161Token {
    param(
        [Parameter(Mandatory = $true)]
        [Security.Cryptography.Pkcs.SignerInfo]$PrimarySigner,
        [Parameter(Mandatory = $true)][byte[]]$TokenBytes
    )

    $PrimarySigner.AddUnsignedAttribute(
        [Security.Cryptography.AsnEncodedData]::new(
            [Security.Cryptography.Oid]::new('1.2.840.113549.1.9.16.2.14'),
            $TokenBytes))
}

function New-TestPeWithCms {
    param(
        [Parameter(Mandatory = $true)][byte[]]$UnsignedPe,
        [Parameter(Mandatory = $true)][object[]]$Cms
    )

    $cmsPayloads = [Collections.Generic.List[byte[]]]::new()
    $certificateSize = 0
    foreach ($candidate in $Cms) {
        [byte[]]$cmsBytes = $candidate.Encode()
        $cmsPayloads.Add($cmsBytes)
        $certificateLength = 8 + $cmsBytes.Length
        $certificateSize += ($certificateLength + 7) -band (-bnot 7)
    }
    $certificateOffset = $UnsignedPe.Length
    [byte[]]$bytes = [byte[]]::new($certificateOffset + $certificateSize)
    [Array]::Copy($UnsignedPe, 0, $bytes, 0, $UnsignedPe.Length)
    $optionalOffset = 0x80 + 24
    $securityEntryOffset = $optionalOffset + 96 + 32
    [BitConverter]::GetBytes([uint32]$certificateOffset).CopyTo(
        $bytes,
        $securityEntryOffset)
    [BitConverter]::GetBytes([uint32]$certificateSize).CopyTo(
        $bytes,
        $securityEntryOffset + 4)
    $cursor = $certificateOffset
    foreach ($cmsBytes in $cmsPayloads) {
        $certificateLength = 8 + $cmsBytes.Length
        [BitConverter]::GetBytes([uint32]$certificateLength).CopyTo(
            $bytes,
            $cursor)
        [BitConverter]::GetBytes([uint16]0x0200).CopyTo(
            $bytes,
            $cursor + 4)
        [BitConverter]::GetBytes([uint16]0x0002).CopyTo(
            $bytes,
            $cursor + 6)
        [Array]::Copy(
            $cmsBytes,
            0,
            $bytes,
            $cursor + 8,
            $cmsBytes.Length)
        $cursor += ($certificateLength + 7) -band (-bnot 7)
    }
    return ,$bytes
}

function Copy-TestCmsWithMutatedContent {
    param(
        [Parameter(Mandatory = $true)]
        [Security.Cryptography.Pkcs.SignedCms]$Cms
    )

    [byte[]]$encoded = $Cms.Encode()
    [byte[]]$content = $Cms.ContentInfo.Content
    $contentOffset = -1
    for ($candidateOffset = 0;
        $candidateOffset -le $encoded.Length - $content.Length;
        $candidateOffset++) {
        $matches = $true
        for ($index = 0; $index -lt $content.Length; $index++) {
            if ($encoded[$candidateOffset + $index] -ne $content[$index]) {
                $matches = $false
                break
            }
        }
        if ($matches) {
            $contentOffset = $candidateOffset
            break
        }
    }
    if ($contentOffset -lt 0) {
        throw 'Could not locate signed CMS content for the invalid-signature fixture.'
    }
    $mutationOffset = $contentOffset + $content.Length - 1
    $encoded[$mutationOffset] = $encoded[$mutationOffset] -bxor 1
    $mutated = [Security.Cryptography.Pkcs.SignedCms]::new()
    $mutated.Decode($encoded)
    return $mutated
}

function Test-RealRfc3161Fixture {
    param([string]$ExplicitPath)

    $candidates = [Collections.Generic.List[string]]::new()
    if (-not [string]::IsNullOrWhiteSpace($ExplicitPath)) {
        $candidates.Add([IO.Path]::GetFullPath($ExplicitPath))
    }
    else {
        foreach ($candidate in @(
                (Join-Path $PSHOME 'pwsh.exe'),
                (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'),
                (Join-Path $env:SystemRoot 'System32\notepad.exe'),
                'C:\Program Files\Git\cmd\git.exe',
                'C:\Program Files\dotnet\dotnet.exe')) {
            $candidates.Add($candidate)
        }
    }

    $diagnostics = [Collections.Generic.List[string]]::new()
    foreach ($candidate in $candidates) {
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            $diagnostics.Add("missing: $candidate")
            continue
        }
        $signature = Microsoft.PowerShell.Security\Get-AuthenticodeSignature `
            -LiteralPath $candidate
        if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
            [string]$signature.SignatureType -cne 'Authenticode' -or
            $null -eq $signature.SignerCertificate -or
            $null -eq $signature.TimeStamperCertificate) {
            $diagnostics.Add("not an admitted Authenticode candidate: $candidate")
            continue
        }
        try {
            $admission = ProductionReleaseState\Assert-PeRfc3161Timestamp `
                -Bytes ([IO.File]::ReadAllBytes($candidate)) `
                -SignerCertificate $signature.SignerCertificate `
                -TimeStamperCertificate $signature.TimeStamperCertificate
            if ([string]$admission.TimestampProtocol -cne 'RFC3161') {
                throw 'Canonical parser returned a non-RFC3161 protocol.'
            }
            Write-Output "PERSONAL-RFC3161-REAL-FIXTURE-PASS: $candidate"
            return
        }
        catch {
            $diagnostics.Add("$candidate`: $($_.Exception.Message)")
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($ExplicitPath)) {
        throw 'The explicitly supplied Personal RFC3161 fixture was not admitted: ' +
            ($diagnostics -join ' | ')
    }
    Write-Output ('PERSONAL-RFC3161-REAL-FIXTURE-PENDING: ' +
        ($diagnostics -join ' | '))
}

$codeCertificate = New-TestSigningCertificate `
    -Subject 'CN=Ensou Personal RFC3161 code fixture'
$timestampCertificate = New-TestSigningCertificate `
    -Subject 'CN=Ensou Personal RFC3161 TSA fixture' `
    -Timestamping
try {
    $unsignedPe = New-TestUnsignedPe
    $validCms = New-TestPrimaryCms `
        -Certificate $codeCertificate `
        -PeBytes $unsignedPe
    $validToken = New-TestRfc3161Token `
        -PrimarySigner $validCms.SignerInfos[0] `
        -TimestampCertificate $timestampCertificate
    Add-Rfc3161Token -PrimarySigner $validCms.SignerInfos[0] -TokenBytes $validToken
    $validPe = New-TestPeWithCms `
        -UnsignedPe $unsignedPe `
        -Cms @($validCms)
    $validAdmission = ProductionReleaseState\Assert-PeRfc3161Timestamp `
        -Bytes $validPe `
        -SignerCertificate $codeCertificate `
        -TimeStamperCertificate $timestampCertificate
    if ([string]$validAdmission.TimestampProtocol -cne 'RFC3161') {
        throw 'Synthetic Personal RFC3161 positive did not pass canonical admission.'
    }

    $alignmentCms = $null
    for ($alignmentAttempt = 0; $alignmentAttempt -lt 16; $alignmentAttempt++) {
        $alignmentCandidate = [Security.Cryptography.Pkcs.SignedCms]::new()
        $alignmentCandidate.Decode($validCms.Encode())
        if ($alignmentAttempt -gt 0) {
            $alignmentWriter = [Formats.Asn1.AsnWriter]::new(
                [Formats.Asn1.AsnEncodingRules]::DER)
            $alignmentWriter.WriteOctetString(
                [byte[]]::new($alignmentAttempt))
            $alignmentCandidate.SignerInfos[0].AddUnsignedAttribute(
                [Security.Cryptography.AsnEncodedData]::new(
                    [Security.Cryptography.Oid]::new(
                        '1.3.6.1.4.1.311.89.999.1'),
                    $alignmentWriter.Encode()))
        }
        if (((8 + $alignmentCandidate.Encode().Length) % 8) -ne 0) {
            $alignmentCms = $alignmentCandidate
            break
        }
    }
    if ($null -eq $alignmentCms) {
        throw 'Could not create a Personal WIN_CERTIFICATE alignment fixture.'
    }
    $alignmentPe = New-TestPeWithCms `
        -UnsignedPe $unsignedPe `
        -Cms @($alignmentCms)
    [void](ProductionReleaseState\Assert-PeRfc3161Timestamp `
        -Bytes $alignmentPe `
        -SignerCertificate $codeCertificate `
        -TimeStamperCertificate $timestampCertificate)
    $certificateOffset = [int][BitConverter]::ToUInt32(
        $alignmentPe,
        0x80 + 24 + 96 + 32)
    $certificateLength = [int][BitConverter]::ToUInt32(
        $alignmentPe,
        $certificateOffset)
    $alignedCertificateLength =
        ($certificateLength + 7) -band (-bnot 7)
    $alignmentPadding = $alignedCertificateLength - $certificateLength
    if ($alignmentPadding -le 0) {
        throw 'Personal truncated-alignment fixture unexpectedly has no WIN_CERTIFICATE padding.'
    }
    [byte[]]$truncatedAlignmentPe = [byte[]]::new(
        $alignmentPe.Length - $alignmentPadding)
    [Array]::Copy(
        $alignmentPe,
        $truncatedAlignmentPe,
        $truncatedAlignmentPe.Length)
    [BitConverter]::GetBytes([uint32]$certificateLength).CopyTo(
        $truncatedAlignmentPe,
        0x80 + 24 + 96 + 32 + 4)
    Assert-Throws `
        -Label 'Personal truncated WIN_CERTIFICATE alignment regression' `
        -ExpectedMessage 'aligned WIN_CERTIFICATE boundary' `
        -Action {
            [void](ProductionReleaseState\Assert-PeRfc3161Timestamp `
                -Bytes $truncatedAlignmentPe `
                -SignerCertificate $codeCertificate `
                -TimeStamperCertificate $timestampCertificate)
        }

    $wrongPrimaryCms = New-TestPrimaryCms `
        -Certificate $codeCertificate `
        -PeBytes $unsignedPe
    Add-Rfc3161Token `
        -PrimarySigner $wrongPrimaryCms.SignerInfos[0] `
        -TokenBytes $validToken
    Assert-Throws `
        -Label 'Personal wrong-primary-SignerInfo RFC3161 token regression' `
        -ExpectedMessage 'messageImprint' `
        -Action {
            [void](ProductionReleaseState\Assert-PeRfc3161Timestamp `
                -Bytes (New-TestPeWithCms `
                    -UnsignedPe $unsignedPe `
                    -Cms @($wrongPrimaryCms)) `
                -SignerCertificate $codeCertificate `
                -TimeStamperCertificate $timestampCertificate)
        }

    $invalidCmsSource = New-TestPrimaryCms `
        -Certificate $codeCertificate `
        -PeBytes $unsignedPe
    $invalidCmsToken = New-TestRfc3161Token `
        -PrimarySigner $invalidCmsSource.SignerInfos[0] `
        -TimestampCertificate $timestampCertificate
    Add-Rfc3161Token `
        -PrimarySigner $invalidCmsSource.SignerInfos[0] `
        -TokenBytes $invalidCmsToken
    $invalidCms = Copy-TestCmsWithMutatedContent $invalidCmsSource
    Assert-Throws `
        -Label 'Personal invalid primary CMS with bound RFC3161 token regression' `
        -ExpectedMessage 'CMS signature is invalid' `
        -Action {
            [void](ProductionReleaseState\Assert-PeRfc3161Timestamp `
                -Bytes (New-TestPeWithCms `
                    -UnsignedPe $unsignedPe `
                    -Cms @($invalidCms)) `
                -SignerCertificate $codeCertificate `
                -TimeStamperCertificate $timestampCertificate)
        }

    [byte[]]$digestMismatchPe = $unsignedPe.Clone()
    $digestMismatchPe[400] = 1
    Assert-Throws `
        -Label 'Personal Authenticode locked-PE digest regression' `
        -ExpectedMessage 'digest differs from the locked PE bytes' `
        -Action {
            [void](ProductionReleaseState\Assert-PeRfc3161Timestamp `
                -Bytes (New-TestPeWithCms `
                    -UnsignedPe $digestMismatchPe `
                    -Cms @($validCms)) `
                -SignerCertificate $codeCertificate `
                -TimeStamperCertificate $timestampCertificate)
        }

    [byte[]]$sectionLayoutPe = $unsignedPe.Clone()
    $sectionLayoutPe[0x80 + 6] = 1
    Assert-Throws `
        -Label 'Personal Authenticode section-layout digest regression' `
        -ExpectedMessage 'digest differs from the locked PE bytes' `
        -Action {
            [void](ProductionReleaseState\Assert-PeRfc3161Timestamp `
                -Bytes (New-TestPeWithCms `
                    -UnsignedPe $sectionLayoutPe `
                    -Cms @($validCms)) `
                -SignerCertificate $codeCertificate `
                -TimeStamperCertificate $timestampCertificate)
        }

    [byte[]]$postCertificateOverlayPe = [byte[]]::new($validPe.Length + 1)
    [Array]::Copy($validPe, $postCertificateOverlayPe, $validPe.Length)
    $postCertificateOverlayPe[$postCertificateOverlayPe.Length - 1] = 1
    Assert-Throws `
        -Label 'Personal post-certificate overlay digest regression' `
        -ExpectedMessage 'digest differs from the locked PE bytes' `
        -Action {
            [void](ProductionReleaseState\Assert-PeRfc3161Timestamp `
                -Bytes $postCertificateOverlayPe `
                -SignerCertificate $codeCertificate `
                -TimeStamperCertificate $timestampCertificate)
        }

    $genericCms = New-TestPrimaryCms `
        -Certificate $codeCertificate `
        -PeBytes $unsignedPe `
        -ContentTypeOid '1.2.840.113549.1.7.1' `
        -Content ([Text.Encoding]::UTF8.GetBytes('not-spc-indirect-data'))
    $genericToken = New-TestRfc3161Token `
        -PrimarySigner $genericCms.SignerInfos[0] `
        -TimestampCertificate $timestampCertificate
    Add-Rfc3161Token `
        -PrimarySigner $genericCms.SignerInfos[0] `
        -TokenBytes $genericToken
    Assert-Throws `
        -Label 'Personal non-Authenticode CMS content-type regression' `
        -ExpectedMessage 'content type is not SpcIndirectDataContent' `
        -Action {
            [void](ProductionReleaseState\Assert-PeRfc3161Timestamp `
                -Bytes (New-TestPeWithCms `
                    -UnsignedPe $unsignedPe `
                    -Cms @($genericCms)) `
                -SignerCertificate $codeCertificate `
                -TimeStamperCertificate $timestampCertificate)
        }

    $auxiliaryPrimaryCms = New-TestPrimaryCms `
        -Certificate $codeCertificate `
        -PeBytes $unsignedPe
    $auxiliaryCmsSource = New-TestPrimaryCms `
        -Certificate $codeCertificate `
        -PeBytes $unsignedPe
    $auxiliaryToken = New-TestRfc3161Token `
        -PrimarySigner $auxiliaryCmsSource.SignerInfos[0] `
        -TimestampCertificate $timestampCertificate
    Add-Rfc3161Token `
        -PrimarySigner $auxiliaryCmsSource.SignerInfos[0] `
        -TokenBytes $auxiliaryToken
    $invalidAuxiliaryCms = Copy-TestCmsWithMutatedContent $auxiliaryCmsSource
    Assert-Throws `
        -Label 'Personal invalid auxiliary CMS RFC3161 regression' `
        -ExpectedMessage 'CMS signature is invalid' `
        -Action {
            [void](ProductionReleaseState\Assert-PeRfc3161Timestamp `
                -Bytes (New-TestPeWithCms `
                    -UnsignedPe $unsignedPe `
                    -Cms @($auxiliaryPrimaryCms, $invalidAuxiliaryCms)) `
                -SignerCertificate $codeCertificate `
                -TimeStamperCertificate $timestampCertificate)
        }

    $legacyCms = New-TestPrimaryCms `
        -Certificate $codeCertificate `
        -PeBytes $unsignedPe
    $legacyCounterSigner = [Security.Cryptography.Pkcs.CmsSigner]::new(
        [Security.Cryptography.Pkcs.SubjectIdentifierType]::IssuerAndSerialNumber,
        $timestampCertificate)
    $legacyCounterSigner.IncludeOption =
        [Security.Cryptography.X509Certificates.X509IncludeOption]::EndCertOnly
    $legacyCms.SignerInfos[0].ComputeCounterSignature($legacyCounterSigner)
    Assert-Throws `
        -Label 'Personal legacy counterSignature regression' `
        -ExpectedMessage 'legacy counterSignature' `
        -Action {
            [void](ProductionReleaseState\Assert-PeRfc3161Timestamp `
                -Bytes (New-TestPeWithCms `
                    -UnsignedPe $unsignedPe `
                    -Cms @($legacyCms)) `
                -SignerCertificate $codeCertificate `
                -TimeStamperCertificate $timestampCertificate)
        }

    Write-Output 'PERSONAL-RFC3161-NEGATIVE-CONTRACTS-PASS'
    Test-RealRfc3161Fixture -ExplicitPath $RealRfc3161PeFixturePath
    Write-Output 'PERSONAL-RFC3161-POLICY-CONTRACT-PASS'
}
finally {
    $timestampCertificate.Dispose()
    $codeCertificate.Dispose()
}
