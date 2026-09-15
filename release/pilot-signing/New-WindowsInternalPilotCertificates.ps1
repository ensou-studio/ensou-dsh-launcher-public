#requires -Version 7.4

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('I UNDERSTAND THIS IS PILOT ONLY')]
    [string]$PilotOnlyConfirmation,

    [Parameter(Mandatory = $true)]
    [ValidateSet('PersonalTwoDevice', 'EnterpriseTwoDevice')]
    [string]$PilotProfile,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$')]
    [string]$Publisher,

    [Parameter(Mandatory = $true)][string]$OutputDirectory,

    [Parameter(Mandatory = $true)][string]$CrlDistributionPointUri,

    [ValidateRange(30, 90)][int]$LeafValidityDays = 60,
    [ValidateRange(90, 730)][int]$RootValidityDays = 365
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$modulePath = Join-Path $PSScriptRoot 'WindowsPilotSigning.psm1'
Microsoft.PowerShell.Core\Import-Module $modulePath -Force
Microsoft.PowerShell.Core\Import-Module (
    Join-Path $PSScriptRoot 'WindowsPilotCertificateRevocation.psm1') -Force

$crlDistributionPoint = New-WindowsPilotCrlDistributionPointExtension `
    -Uri $CrlDistributionPointUri

if (-not [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
        [Runtime.InteropServices.OSPlatform]::Windows) -or
    [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne
        [Runtime.InteropServices.Architecture]::X64 -or
    [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -ne
        [Runtime.InteropServices.Architecture]::X64) {
    throw 'This Pilot certificate helper requires native Windows x64 and x64 PowerShell.'
}
if ($RootValidityDays -le $LeafValidityDays) {
    throw 'RootValidityDays must be greater than LeafValidityDays.'
}
if (-not (Test-WindowsLocalAbsolutePathShape `
        -Path $OutputDirectory -Directory)) {
    throw 'OutputDirectory must be a canonical local drive path below the drive root.'
}
if ($null -eq (Get-Command New-SelfSignedCertificate -ErrorAction SilentlyContinue) -or
    $null -eq (Get-Command Export-Certificate -ErrorAction SilentlyContinue)) {
    throw 'Windows PKI cmdlets are unavailable.'
}

$outputFullPath = [IO.Path]::GetFullPath($OutputDirectory)
$outputParentPath = [IO.Path]::GetDirectoryName($outputFullPath)
if ([string]::IsNullOrWhiteSpace($outputParentPath)) {
    throw 'OutputDirectory must have an immediate parent.'
}
$parentObservation = Get-WindowsNoFollowPathObservation `
    -Path $outputParentPath -ExpectedKind Directory
if (-not $parentObservation.safe) {
    throw 'OutputDirectory immediate parent must be an existing no-follow-safe directory.'
}
$outputObservation = Get-WindowsNoFollowPathObservation `
    -Path $outputFullPath -ExpectedKind Directory
if ($outputObservation.safe) {
    throw 'OutputDirectory must be absent.'
}
if ($outputObservation.reparseDetected -or
    $outputObservation.blockedComponentIndex -ne
        ($outputObservation.totalComponentCount - 1)) {
    throw 'OutputDirectory path failed before its absent final component.'
}

$targetDescription =
    "CurrentUser\My $PilotProfile Pilot root and non-exportable leaf; public CER files in $outputFullPath"
if (-not $PSCmdlet.ShouldProcess($targetDescription, 'Create internal Pilot certificates')) {
    return
}

$profileDefinition = switch ($PilotProfile) {
    'PersonalTwoDevice' {
        [pscustomobject][ordered]@{
            certificateLabel = 'Personal Two-Device Pilot'
            fileStem = 'personal-two-device-pilot'
            scope = 'two-explicit-personal-test-devices-only'
        }
    }
    'EnterpriseTwoDevice' {
        [pscustomobject][ordered]@{
            certificateLabel = 'Enterprise Two-Device Pilot'
            fileStem = 'enterprise-two-device-pilot'
            scope = 'two-explicit-enterprise-test-devices-only'
        }
    }
    default { throw 'Unsupported PilotProfile.' }
}

[IO.Directory]::CreateDirectory($outputFullPath) | Out-Null
$root = $null
$leaf = $null
try {
    $now = Get-Date
    $root = New-SelfSignedCertificate `
        -Type Custom `
        -Subject "CN=$Publisher DSH $($profileDefinition.certificateLabel) Root" `
        -FriendlyName "$Publisher DSH $($profileDefinition.certificateLabel) Root - NOT PRODUCTION" `
        -CertStoreLocation 'Cert:\CurrentUser\My' `
        -Provider 'Microsoft Software Key Storage Provider' `
        -KeyAlgorithm RSA `
        -KeyLength 3072 `
        -HashAlgorithm SHA256 `
        -KeyExportPolicy NonExportable `
        -KeyUsage CertSign, CRLSign, DigitalSignature `
        -NotBefore $now.AddMinutes(-5) `
        -NotAfter $now.AddDays($RootValidityDays) `
        -TextExtension @('2.5.29.19={critical}{text}ca=1&pathlength=0')

    $leaf = New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject "CN=$Publisher" `
        -FriendlyName "$Publisher DSH $($profileDefinition.certificateLabel) Code Signing - NOT PRODUCTION" `
        -CertStoreLocation 'Cert:\CurrentUser\My' `
        -Provider 'Microsoft Software Key Storage Provider' `
        -KeyAlgorithm RSA `
        -KeyLength 3072 `
        -HashAlgorithm SHA256 `
        -KeyExportPolicy NonExportable `
        -KeyUsage DigitalSignature `
        -Extension @($crlDistributionPoint) `
        -Signer $root `
        -NotBefore $now.AddMinutes(-5) `
        -NotAfter $now.AddDays($LeafValidityDays)

    $rootExportability = Get-WindowsPrivateKeyExportability -Certificate $root
    $leafExportability = Get-WindowsPrivateKeyExportability -Certificate $leaf
    if ($rootExportability -cne 'NonExportable' -or
        $leafExportability -cne 'NonExportable') {
        throw 'Generated private-key exportability was not proven NonExportable.'
    }

    $rootCerPath = Join-Path $outputFullPath (
        "ensou-dsh-$($profileDefinition.fileStem)-root-public.cer")
    $leafCerPath = Join-Path $outputFullPath (
        "ensou-dsh-$($profileDefinition.fileStem)-code-signing-public.cer")
    [void](Export-Certificate -Cert $root -FilePath $rootCerPath -Type CERT)
    [void](Export-Certificate -Cert $leaf -FilePath $leafCerPath -Type CERT)

    $crlThisUpdate = [DateTimeOffset]::UtcNow.AddMinutes(-1)
    $crlNextUpdate = $crlThisUpdate.AddDays(7)
    [byte[]]$initialCrl = New-WindowsPilotInitialCertificateRevocationList `
        -Issuer $root -ThisUpdate $crlThisUpdate -NextUpdate $crlNextUpdate
    $crlPath = Join-Path $outputFullPath (
        "ensou-dsh-$($profileDefinition.fileStem)-root.crl")
    $crlStream = [IO.File]::Open($crlPath, [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $crlStream.Write($initialCrl); $crlStream.Flush($true) }
    finally { $crlStream.Dispose() }

    [pscustomobject][ordered]@{
        schemaVersion = 2
        resultType = 'ensou-dsh-internal-pilot-certificate-creation'
        status = 'CREATED_PILOT_ONLY'
        productionAdmission = 'NO_GO'
        publisher = $Publisher
        pilotProfile = $PilotProfile
        scope = $profileDefinition.scope
        storeLocation = 'CurrentUser/My'
        rootInstalledAsTrusted = $false
        privateKeyExported = $false
        pfxCreated = $false
        rootCertificateSha256 = [Convert]::ToHexString(
            [Security.Cryptography.SHA256]::HashData($root.RawData)).ToLowerInvariant()
        leafCertificateSha256 = [Convert]::ToHexString(
            [Security.Cryptography.SHA256]::HashData($leaf.RawData)).ToLowerInvariant()
        leafStoreThumbprint = $leaf.Thumbprint.ToUpperInvariant()
        rootNotAfterUtc = $root.NotAfter.ToUniversalTime().ToString('o')
        leafNotAfterUtc = $leaf.NotAfter.ToUniversalTime().ToString('o')
        rootPublicCerPath = $rootCerPath
        leafPublicCerPath = $leafCerPath
        crlDistributionPointUri = $CrlDistributionPointUri
        initialCrlPath = $crlPath
        initialCrlSha256 = [Convert]::ToHexString(
            [Security.Cryptography.SHA256]::HashData($initialCrl)).ToLowerInvariant()
        initialCrlNumber = 1
        initialCrlThisUpdateUtc = $crlThisUpdate.ToString('o')
        initialCrlNextUpdateUtc = $crlNextUpdate.ToString('o')
        crlPublished = $false
        blockers = @(
            'ROOT_TRUST_NOT_INSTALLED_ON_TEST_DEVICES',
            'RFC3161_TSA_NOT_VERIFIED',
            'REVOCATION_CRL_NOT_PUBLISHED_OR_PROVEN',
            'REAL_SIGNING_NOT_PERFORMED'
        )
    } | ConvertTo-Json -Depth 8
}
catch {
    # Remove only certificates created by this invocation. No trust-store entry
    # is ever created by this helper.
    foreach ($created in @($leaf, $root)) {
        if ($null -ne $created) {
            Remove-Item -LiteralPath (
                'Cert:\CurrentUser\My\' + $created.Thumbprint) -Force -ErrorAction SilentlyContinue
        }
    }
    throw
}
finally {
    if ($null -ne $leaf) { $leaf.Dispose() }
    if ($null -ne $root) { $root.Dispose() }
}
