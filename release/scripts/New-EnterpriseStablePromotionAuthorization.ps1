#requires -Version 7.2

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ReleaseSetId,

    [Parameter(Mandatory)]
    [string]$ReceiptPath,

    [Parameter(Mandatory)]
    [string]$ReceiptAuthenticationPath,

    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')]
    [string]$ReceiptAuthenticationKeyId,

    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9_-]{43}$')]
    [string]$ReceiptAuthenticationKeyX,

    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9_-]{43}$')]
    [string]$ReceiptAuthenticationKeyY,

    [Parameter(Mandatory)]
    [string]$InstallerPath,

    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9A-Fa-f]{64}$')]
    [string]$ExpectedInstallerSignerSha256Thumbprint,

    [Parameter(Mandatory)]
    [string]$ManifestPath,

    [Parameter(Mandatory)]
    [string]$ProtectedSnapshotBasePath,

    [Parameter(Mandatory)]
    [string]$CertificationPrivateKeyPath,

    [Parameter(Mandatory)]
    [string]$CertificationKeyId,

    [Parameter(Mandatory)]
    [string]$OutputPath,

    [ValidateRange(1, 168)]
    [int]$MaximumReceiptAgeHours = 24,

    [ValidateRange(1, 168)]
    [int]$ValidHours = 24,

    [string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'CertifiedDistributionInput.ps1')

function ConvertTo-Base64Url([byte[]]$Bytes) {
    return [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

if ($ReleaseSetId -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$') {
    throw 'ReleaseSetId is invalid.'
}
if ($CertificationKeyId -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$') {
    throw 'CertificationKeyId is invalid.'
}
if ($CertificationKeyId -ceq $ReceiptAuthenticationKeyId) {
    throw 'Stable authorization and receipt authentication must use distinct key IDs.'
}
if (-not [IO.Path]::IsPathFullyQualified($OutputPath) -or
    (Test-Path -LiteralPath $OutputPath)) {
    throw 'OutputPath must be a new absolute file.'
}
$outputFullPath = [IO.Path]::GetFullPath($OutputPath)
$outputParent = Assert-CertifiedDistributionOrdinaryDirectoryChain `
    -Path ([IO.Path]::GetDirectoryName($outputFullPath)) `
    -Label 'OutputPath parent'

$leases = [Collections.Generic.List[IDisposable]]::new()
$privateKey = $null
$signer = $null
try {
    $privateKeyFile = Open-CertifiedDistributionLockedInput `
        -Path $CertificationPrivateKeyPath `
        -Label 'CertificationPrivateKeyPath' `
        -MaximumBytes (64KB) `
        -Leases $leases

    $admissionOutput = @(& (Join-Path $PSScriptRoot `
            'Test-CertifiedDistributionReceipt.ps1') `
        -Product 'ensou-dsh-enterprise' `
        -ReleaseSetId $ReleaseSetId `
        -ReceiptPath $ReceiptPath `
        -ReceiptAuthenticationPath $ReceiptAuthenticationPath `
        -ReceiptAuthenticationKeyId $ReceiptAuthenticationKeyId `
        -ReceiptAuthenticationKeyX $ReceiptAuthenticationKeyX `
        -ReceiptAuthenticationKeyY $ReceiptAuthenticationKeyY `
        -InstallerPath $InstallerPath `
        -ExpectedInstallerSignerSha256Thumbprint `
            $ExpectedInstallerSignerSha256Thumbprint `
        -ManifestPath $ManifestPath `
        -ProtectedSnapshotBasePath $ProtectedSnapshotBasePath `
        -MaximumReceiptAgeHours $MaximumReceiptAgeHours `
        -RepositoryRoot $RepositoryRoot `
        -PassThru)
    if ($admissionOutput.Count -ne 1) {
        throw 'Certified distribution gate did not return one exact admission snapshot.'
    }
    $admission = $admissionOutput[0]
    $expectedAdmissionProperties = @(
        'InstallerFileName',
        'InstallerSha256',
        'InstallerSignerSha256Thumbprint',
        'InstallerSizeBytes',
        'ManifestSha256',
        'Product',
        'ReceiptAuthenticationKeyId',
        'ReceiptSha256',
        'ReleaseSetId',
        'SchemaVersion')
    if ((@($admission.PSObject.Properties.Name | Sort-Object) -join ',') -cne
            (@($expectedAdmissionProperties | Sort-Object) -join ',') -or
        $admission.SchemaVersion -ne 1 -or
        $admission.Product -cne 'ensou-dsh-enterprise' -or
        $admission.ReleaseSetId -cne $ReleaseSetId -or
        $admission.ReceiptAuthenticationKeyId -cne $ReceiptAuthenticationKeyId -or
        $admission.InstallerSignerSha256Thumbprint -cne
            $ExpectedInstallerSignerSha256Thumbprint.ToLowerInvariant()) {
        throw 'Certified distribution gate returned an invalid admission snapshot.'
    }

    $issuedAt = [DateTimeOffset]::UtcNow
    $expiresAt = $issuedAt.AddHours($ValidHours)
    $issuedText = $issuedAt.ToString('O', [Globalization.CultureInfo]::InvariantCulture)
    $expiresText = $expiresAt.ToString('O', [Globalization.CultureInfo]::InvariantCulture)
    $payloadLines = @(
        'ensou-dsh-enterprise-stable-promotion-authorization-v1',
        'ensou-dsh-enterprise',
        'stable',
        $ReleaseSetId,
        [string]$admission.ManifestSha256,
        [string]$admission.ReceiptSha256,
        [string]$admission.InstallerFileName,
        ([int64]$admission.InstallerSizeBytes).ToString(
            [Globalization.CultureInfo]::InvariantCulture),
        [string]$admission.InstallerSha256,
        $issuedText,
        $expiresText)
    $payload = [Text.Encoding]::UTF8.GetBytes($payloadLines -join "`n")
    $privateKey = Read-CertifiedDistributionLockedBytes `
        -Descriptor $privateKeyFile `
        -MaximumBytes (64KB)
    $signer = [Security.Cryptography.ECDsa]::Create()
    $consumed = 0
    $signer.ImportPkcs8PrivateKey($privateKey, [ref]$consumed)
    if ($consumed -ne $privateKey.Length) {
        throw 'Certification PKCS8 private key has trailing bytes.'
    }
    $parameters = $signer.ExportParameters($false)
    if ($parameters.Q.X.Length -ne 32 -or $parameters.Q.Y.Length -ne 32) {
        throw 'Certification private key must use P-256.'
    }
    $receiptAuthenticationX = ConvertFrom-CertifiedDistributionBase64Url `
        -Value $ReceiptAuthenticationKeyX `
        -ExpectedBytes 32 `
        -Label 'Receipt authentication key X'
    $receiptAuthenticationY = ConvertFrom-CertifiedDistributionBase64Url `
        -Value $ReceiptAuthenticationKeyY `
        -ExpectedBytes 32 `
        -Label 'Receipt authentication key Y'
    if ([Convert]::ToHexString($parameters.Q.X) -ceq
            [Convert]::ToHexString($receiptAuthenticationX) -and
        [Convert]::ToHexString($parameters.Q.Y) -ceq
            [Convert]::ToHexString($receiptAuthenticationY)) {
        throw 'Stable authorization and receipt authentication must use independent P-256 keys.'
    }

    Assert-CertifiedDistributionLockedInputUnchanged -Descriptor $privateKeyFile
    $signature = $signer.SignData(
        $payload,
        [Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)
    if ($signature.Length -ne 64 -or -not $signer.VerifyData(
            $payload,
            $signature,
            [Security.Cryptography.HashAlgorithmName]::SHA256,
            [Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)) {
        throw 'Stable promotion authorization signature self-check failed.'
    }

    $authorization = [ordered]@{
        schemaVersion = 1
        product = 'ensou-dsh-enterprise'
        channel = 'stable'
        releaseSetId = $ReleaseSetId
        manifestSha256 = [string]$admission.ManifestSha256
        certificationReceiptSha256 = [string]$admission.ReceiptSha256
        installerFileName = [string]$admission.InstallerFileName
        installerSizeBytes = [int64]$admission.InstallerSizeBytes
        installerSha256 = [string]$admission.InstallerSha256
        issuedAtUtc = $issuedText
        expiresAtUtc = $expiresText
        signature = [ordered]@{
            algorithm = 'ES256'
            keyId = $CertificationKeyId
            value = ConvertTo-Base64Url $signature
        }
    }
    $json = $authorization | ConvertTo-Json -Depth 8
    $schemaPath = Join-Path $RepositoryRoot `
        'release\schemas\enterprise-stable-promotion-authorization-v1.schema.json'
    if (-not (Test-Json -Json $json -SchemaFile $schemaPath -ErrorAction Stop)) {
        throw 'Generated stable promotion authorization failed its strict schema.'
    }
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json + "`n")
    $output = [IO.FileStream]::new(
        $outputFullPath,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None)
    try {
        [void][EnsouDshCertifiedDistributionInput.NativeFileIdentity]::
            RequireOrdinarySingleLink($output.SafeFileHandle)
        $output.Write($bytes, 0, $bytes.Length)
        $output.Flush($true)
    }
    finally {
        $output.Dispose()
    }
    [void](Assert-CertifiedDistributionOrdinaryDirectoryChain `
        -Path $outputParent `
        -Label 'OutputPath parent')
    Write-Host "STABLE-PROMOTION-AUTHORIZATION-PASS $ReleaseSetId $($admission.ManifestSha256)"
}
finally {
    if ($null -ne $privateKey) {
        [Array]::Clear($privateKey, 0, $privateKey.Length)
    }
    if ($null -ne $signer) {
        $signer.Dispose()
    }
    for ($index = $leases.Count - 1; $index -ge 0; $index--) {
        $leases[$index].Dispose()
    }
}
