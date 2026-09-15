#requires -Version 7.2

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('ensou-dsh-personal', 'ensou-dsh-enterprise')]
    [string]$Product,

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

    [ValidateRange(1, 168)]
    [int]$MaximumReceiptAgeHours = 24,

    [switch]$PassThru,

    [string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'CertifiedDistributionInput.ps1')

if ($ReleaseSetId -cnotmatch '^managed-v[0-9]{4}\.[0-9]{2}\.[0-9]{2}\.[1-9][0-9]*$') {
    throw 'ReleaseSetId is invalid.'
}
$expectedInstallerSigner = $ExpectedInstallerSignerSha256Thumbprint.ToLowerInvariant()
$leases = [Collections.Generic.List[IDisposable]]::new()
$receiptBytes = $null
$authenticationBytes = $null
$snapshotRoot = $null
try {
    $receiptFile = Open-CertifiedDistributionLockedInput `
        -Path $ReceiptPath `
        -Label 'ReceiptPath' `
        -MaximumBytes (512KB) `
        -Leases $leases
    $authenticationFile = Open-CertifiedDistributionLockedInput `
        -Path $ReceiptAuthenticationPath `
        -Label 'ReceiptAuthenticationPath' `
        -MaximumBytes (128KB) `
        -Leases $leases
    $installerFile = Open-CertifiedDistributionLockedInput `
        -Path $InstallerPath `
        -Label 'InstallerPath' `
        -MaximumBytes (8L * 1024 * 1024 * 1024) `
        -Leases $leases
    $manifestFile = Open-CertifiedDistributionLockedInput `
        -Path $ManifestPath `
        -Label 'ManifestPath' `
        -MaximumBytes (4MB) `
        -Leases $leases

    $identities = @(
        $receiptFile,
        $authenticationFile,
        $installerFile,
        $manifestFile) | ForEach-Object {
        '{0}:{1}' -f $_.VolumeSerialNumber, $_.FileIndex
    }
    if (@($identities | Select-Object -Unique).Count -ne $identities.Count) {
        throw 'Certified distribution inputs must be four distinct ordinary files.'
    }

    $snapshotBase = Assert-CertifiedDistributionOrdinaryDirectoryChain `
        -Path $ProtectedSnapshotBasePath `
        -Label 'Certified distribution snapshot base'
    $snapshotRoot = Join-Path `
        $snapshotBase `
        ('ensou-certified-distribution-' + [Guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($snapshotRoot) | Out-Null
    $snapshotDirectory = Open-CertifiedDistributionLockedDirectory `
        -Path $snapshotRoot `
        -Label 'Certified distribution snapshot root' `
        -Leases $leases
    $installerSnapshot = Copy-CertifiedDistributionLockedSnapshot `
        -Descriptor $installerFile `
        -DirectoryDescriptor $snapshotDirectory `
        -Destination (Join-Path $snapshotRoot 'certified-installer.exe') `
        -Leases $leases

    $receiptBytes = Read-CertifiedDistributionLockedBytes `
        -Descriptor $receiptFile `
        -MaximumBytes (512KB)
    $authenticationBytes = Read-CertifiedDistributionLockedBytes `
        -Descriptor $authenticationFile `
        -MaximumBytes (128KB)
    Assert-CertifiedDistributionStrictJson `
        -Bytes $receiptBytes `
        -Label 'Certified distribution receipt'
    Assert-CertifiedDistributionStrictJson `
        -Bytes $authenticationBytes `
        -Label 'Certified distribution receipt authentication'

    $receiptJson = [Text.UTF8Encoding]::new($false, $true).GetString($receiptBytes)
    $schemaPath = Join-Path $RepositoryRoot `
        'release\schemas\certified-distribution-receipt-v1.schema.json'
    if (-not (Test-Json -Json $receiptJson -SchemaFile $schemaPath -ErrorAction Stop)) {
        throw 'Certified distribution receipt does not satisfy the strict schema.'
    }
    $receipt = $receiptJson | ConvertFrom-Json -Depth 32
    $receiptSha256 = ([Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($receiptBytes))).ToLowerInvariant()

    $authenticationJson = [Text.UTF8Encoding]::new($false, $true).GetString(
        $authenticationBytes)
    $authenticationSchemaPath = Join-Path $RepositoryRoot `
        'release\schemas\certified-distribution-receipt-authentication-v1.schema.json'
    if (-not (Test-Json `
            -Json $authenticationJson `
            -SchemaFile $authenticationSchemaPath `
            -ErrorAction Stop)) {
        throw 'Certified distribution receipt authentication does not satisfy the strict schema.'
    }
    $authentication = $authenticationJson | ConvertFrom-Json -Depth 16
    if ($authentication.product -cne $Product -or
        $authentication.releaseSetId -cne $ReleaseSetId -or
        $authentication.receiptSha256 -cne $receiptSha256 -or
        $authentication.signature.algorithm -cne 'ES256' -or
        $authentication.signature.keyId -cne $ReceiptAuthenticationKeyId) {
        throw 'Certified distribution receipt authentication identity does not match this exact receipt.'
    }
    $authenticationPayload = [Text.Encoding]::UTF8.GetBytes((@(
        'ensou-dsh-certified-distribution-receipt-authentication-v1',
        $Product,
        $ReleaseSetId,
        $receiptSha256) -join "`n"))
    $authenticationSignature = ConvertFrom-CertifiedDistributionBase64Url `
        -Value ([string]$authentication.signature.value) `
        -ExpectedBytes 64 `
        -Label 'Receipt authentication signature'
    $receiptVerifier = New-CertifiedDistributionP256Verifier `
        -X $ReceiptAuthenticationKeyX `
        -Y $ReceiptAuthenticationKeyY
    try {
        if (-not $receiptVerifier.VerifyData(
                $authenticationPayload,
                $authenticationSignature,
                [Security.Cryptography.HashAlgorithmName]::SHA256,
                [Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)) {
            throw 'Certified distribution receipt authentication signature is invalid.'
        }
    }
    finally {
        $receiptVerifier.Dispose()
    }

    if ($receipt.product -cne $Product -or
        $receipt.channel -cne 'stable' -or
        $receipt.releaseSetId -cne $ReleaseSetId -or
        $receipt.distributionAuthorized -ne $true) {
        throw 'Certified distribution receipt identity does not match this release.'
    }

    $installerHash = $installerSnapshot.Sha256
    if ($receipt.installer.fileName -cne $installerFile.FileName -or
        [int64]$receipt.installer.sizeBytes -ne $installerSnapshot.SizeBytes -or
        $receipt.installer.sha256 -cne $installerHash) {
        throw 'Certified distribution receipt does not bind the exact Installer bytes.'
    }

    $manifestHash = Get-CertifiedDistributionStreamSha256 -Stream $manifestFile.Stream
    if ($receipt.manifestSha256 -cne $manifestHash -or
        $receipt.feed.externalManifestSha256 -cne $manifestHash) {
        throw 'Certified distribution receipt does not bind the exact signed manifest bytes.'
    }

    $feedManifestUri = [Uri]$receipt.feed.manifestUri
    $expectedArtifactCount = if ($Product -ceq 'ensou-dsh-enterprise') { 3 } else { 2 }
    if (-not $feedManifestUri.IsAbsoluteUri -or
        $feedManifestUri.Scheme -cne 'https' -or
        $feedManifestUri.UserInfo.Length -ne 0 -or
        $feedManifestUri.Query.Length -ne 0 -or
        $feedManifestUri.Fragment.Length -ne 0 -or
        $feedManifestUri.AbsolutePath -cne '/v2/channels/pilot/release-set.v2.json' -or
        [int]$receipt.feed.verifiedArtifactCount -ne $expectedArtifactCount) {
        throw 'Certified distribution receipt must bind the exact externally verified Pilot head and component count.'
    }

    Assert-CertifiedDistributionLockedDirectoryUnchanged `
        -Descriptor $snapshotDirectory
    Assert-CertifiedDistributionLockedInputUnchanged `
        -Descriptor $installerSnapshot
    Assert-CertifiedDistributionLockedPathStillNamesInput `
        -Descriptor $installerSnapshot
    $signature = Get-AuthenticodeSignature -LiteralPath $installerSnapshot.Path
    Assert-CertifiedDistributionLockedPathStillNamesInput `
        -Descriptor $installerSnapshot
    Assert-CertifiedDistributionLockedInputUnchanged `
        -Descriptor $installerSnapshot
    Assert-CertifiedDistributionLockedDirectoryUnchanged `
        -Descriptor $snapshotDirectory
    if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
        $null -eq $signature.SignerCertificate) {
        throw "Installer Authenticode status is $($signature.Status), not Valid."
    }
    $certificateHash = [Security.Cryptography.SHA256]::HashData(
        $signature.SignerCertificate.RawData)
    $certificateSha256 = [Convert]::ToHexString($certificateHash).ToLowerInvariant()
    if ($certificateSha256 -cne $expectedInstallerSigner -or
        $receipt.installer.signerSha256Thumbprint -cne $expectedInstallerSigner) {
        throw 'Certified distribution receipt or Installer does not match the independently expected signer.'
    }
    if ($null -eq $signature.TimeStamperCertificate) {
        throw 'Installer signature has no trusted timestamp certificate.'
    }

    if ($Product -ceq 'ensou-dsh-enterprise' -and
        $receipt.certification.enterprisePluginLoaded -ne $true) {
        throw 'Enterprise distribution requires certified managed-plugin startup.'
    }
    if ($Product -ceq 'ensou-dsh-personal' -and
        $null -ne $receipt.certification.enterprisePluginLoaded) {
        throw 'Personal distribution receipt must not claim enterprise-plugin startup.'
    }

    $receiptDocument = [Text.Json.JsonDocument]::Parse(
        [ReadOnlyMemory[byte]]::new($receiptBytes))
    try {
        $approvedAtText = $receiptDocument.RootElement.
            GetProperty('approvedAtUtc').GetString()
        $feedVerifiedAtText = $receiptDocument.RootElement.
            GetProperty('feed').GetProperty('verifiedAtUtc').GetString()
    }
    finally {
        $receiptDocument.Dispose()
    }
    $approvedAt = [DateTimeOffset]::ParseExact(
        $approvedAtText,
        'O',
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::None)
    $feedVerifiedAt = [DateTimeOffset]::ParseExact(
        $feedVerifiedAtText,
        'O',
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::None)
    $currentUtc = [DateTimeOffset]::UtcNow
    $oldestAcceptedUtc = $currentUtc.AddHours(-$MaximumReceiptAgeHours)
    if ($approvedAt.Offset -ne [TimeSpan]::Zero -or
        $feedVerifiedAt.Offset -ne [TimeSpan]::Zero -or
        $approvedAt -lt $feedVerifiedAt -or
        $approvedAt -gt $currentUtc -or
        $feedVerifiedAt -gt $currentUtc -or
        $approvedAt -lt $oldestAcceptedUtc -or
        $feedVerifiedAt -lt $oldestAcceptedUtc) {
        throw 'Distribution approval timestamps are future-dated, stale, or precede feed verification.'
    }

    foreach ($descriptor in @(
        $receiptFile,
        $authenticationFile,
        $installerFile,
        $manifestFile)) {
        Assert-CertifiedDistributionLockedInputUnchanged -Descriptor $descriptor
    }

    $admission = [pscustomobject]@{
        SchemaVersion = 1
        Product = $Product
        ReleaseSetId = $ReleaseSetId
        ManifestSha256 = $manifestHash
        ReceiptSha256 = $receiptSha256
        InstallerFileName = [string]$receipt.installer.fileName
        InstallerSizeBytes = [int64]$receipt.installer.sizeBytes
        InstallerSha256 = [string]$receipt.installer.sha256
        InstallerSignerSha256Thumbprint = $expectedInstallerSigner
        ReceiptAuthenticationKeyId = $ReceiptAuthenticationKeyId
    }
    Write-Host "CERTIFIED-DISTRIBUTION-PASS $Product $ReleaseSetId $installerHash"
    if ($PassThru) {
        Write-Output $admission
    }
}
finally {
    if ($null -ne $receiptBytes) {
        [Array]::Clear($receiptBytes, 0, $receiptBytes.Length)
    }
    if ($null -ne $authenticationBytes) {
        [Array]::Clear($authenticationBytes, 0, $authenticationBytes.Length)
    }
    for ($index = $leases.Count - 1; $index -ge 0; $index--) {
        $leases[$index].Dispose()
    }
    if ($null -ne $snapshotRoot -and (Test-Path -LiteralPath $snapshotRoot)) {
        $resolvedSnapshot = [IO.Path]::GetFullPath($snapshotRoot)
        $expectedPrefix = [IO.Path]::GetFullPath($ProtectedSnapshotBasePath).TrimEnd(
            [IO.Path]::DirectorySeparatorChar) +
            [IO.Path]::DirectorySeparatorChar +
            'ensou-certified-distribution-'
        if (-not $resolvedSnapshot.StartsWith(
                $expectedPrefix,
                [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Refusing to remove an unexpected certified distribution snapshot root.'
        }
        foreach ($entry in Get-ChildItem -LiteralPath $resolvedSnapshot -Force -Recurse) {
            if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'Refusing to remove a linked certified distribution snapshot tree.'
            }
        }
        [IO.Directory]::Delete($resolvedSnapshot, $true)
    }
}
