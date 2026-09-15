#requires -Version 7.2

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$RequestPath,

    [Parameter(Mandatory = $true)]
    [string]$PromotionHeadPath,

    [Parameter(Mandatory = $true)]
    [string]$AuthorizationPrivateKeyPath,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$')]
    [string]$AuthorizationKeyId,

    [Parameter(Mandatory = $true)]
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$stateModulePath = Join-Path $PSScriptRoot 'ProductionReleaseState.psm1'
$promotionModulePath = Join-Path $PSScriptRoot 'ProductionFeedPromotion.psm1'
$requestSchemaPath = Join-Path `
    $repositoryRoot `
    'release\schemas\launcher-feed-promotion-request-v1.schema.json'
$headSchemaPath = Join-Path `
    $repositoryRoot `
    'release\schemas\launcher-feed-promotion-state-v1.schema.json'
$responseSchemaPath = Join-Path `
    $repositoryRoot `
    'release\schemas\launcher-feed-promotion-response-v1.schema.json'

Microsoft.PowerShell.Core\Import-Module $promotionModulePath -Force
# ProductionFeedPromotion imports shared modules into its private scope. Load
# the state module last so both module-qualified public contracts remain bound
# in this signer scope.
Microsoft.PowerShell.Core\Import-Module $stateModulePath -Force

$p256Order = [byte[]](
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
    0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51)
$p256HalfOrder = [byte[]](
    0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00,
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42,
    0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8)

function ConvertTo-Base64Url {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    return [Convert]::ToBase64String($Bytes).
        TrimEnd('=').
        Replace('+', '-').
        Replace('/', '_')
}

function Compare-UnsignedBigEndian {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Left,
        [Parameter(Mandatory = $true)][byte[]]$Right
    )

    if ($Left.Length -ne $Right.Length) {
        throw 'Unsigned comparison requires equal-length values.'
    }
    for ($index = 0; $index -lt $Left.Length; $index++) {
        if ($Left[$index] -lt $Right[$index]) { return -1 }
        if ($Left[$index] -gt $Right[$index]) { return 1 }
    }
    return 0
}

function Subtract-UnsignedBigEndian {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Left,
        [Parameter(Mandatory = $true)][byte[]]$Right
    )

    if ($Left.Length -ne $Right.Length -or
        (Compare-UnsignedBigEndian -Left $Left -Right $Right) -lt 0) {
        throw 'Unsigned subtraction requires equal-length, ordered values.'
    }
    $result = [byte[]]::new($Left.Length)
    $borrow = 0
    for ($index = $Left.Length - 1; $index -ge 0; $index--) {
        $value = [int]$Left[$index] - [int]$Right[$index] - $borrow
        if ($value -lt 0) {
            $value += 256
            $borrow = 1
        }
        else {
            $borrow = 0
        }
        $result[$index] = [byte]$value
    }
    if ($borrow -ne 0) {
        throw 'Unsigned subtraction underflowed.'
    }
    return ,$result
}

function ConvertTo-LowSP256Signature {
    param([Parameter(Mandatory = $true)][byte[]]$Signature)

    if ($Signature.Length -ne 64) {
        throw 'Feed-promotion authorization must use a 64-byte P1363 signature.'
    }
    $r = [byte[]]::new(32)
    $s = [byte[]]::new(32)
    [Array]::Copy($Signature, 0, $r, 0, 32)
    [Array]::Copy($Signature, 32, $s, 0, 32)
    $zero = [byte[]]::new(32)
    if ((Compare-UnsignedBigEndian -Left $r -Right $zero) -eq 0 -or
        (Compare-UnsignedBigEndian -Left $r -Right $p256Order) -ge 0 -or
        (Compare-UnsignedBigEndian -Left $s -Right $zero) -eq 0 -or
        (Compare-UnsignedBigEndian -Left $s -Right $p256Order) -ge 0) {
        throw 'Feed-promotion authorization signature contains an invalid scalar.'
    }
    if ((Compare-UnsignedBigEndian -Left $s -Right $p256HalfOrder) -gt 0) {
        $s = Subtract-UnsignedBigEndian -Left $p256Order -Right $s
    }
    $normalized = [byte[]]::new(64)
    [Array]::Copy($r, 0, $normalized, 0, 32)
    [Array]::Copy($s, 0, $normalized, 32, 32)
    ProductionReleaseState\Assert-ProductionEs256P1363LowS `
        -Signature $normalized `
        -Label 'Feed-promotion authorization response signature'
    return ,$normalized
}

function Assert-AbsoluteExternalInput {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if (-not [IO.Path]::IsPathFullyQualified($Path) -or
        $Path.StartsWith('\\', [StringComparison]::Ordinal) -or
        $Path.StartsWith('//', [StringComparison]::Ordinal)) {
        throw "$Label must use an absolute local path."
    }
    $full = [IO.Path]::GetFullPath($Path)
    $repositoryBoundary = $repositoryRoot.TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    if ($full.Equals(
            $repositoryBoundary,
            [StringComparison]::OrdinalIgnoreCase) -or
        $full.StartsWith(
            $repositoryBoundary + [IO.Path]::DirectorySeparatorChar,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label must remain outside the source repository."
    }
    return $full
}

function Open-StrictLockedJson {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][string]$SchemaPath
    )

    $descriptor = ProductionReleaseState\Open-ProductionReleaseInput `
        -Path $Path `
        -Label $Label `
        -MaximumBytes 1MB
    try {
        $bytes = ProductionReleaseState\Read-ProductionReleaseInputBytes `
            -Descriptor $descriptor `
            -Label $Label
        $value = ProductionReleaseState\ConvertFrom-StrictProductionJsonBytes `
            -Bytes $bytes `
            -Label $Label `
            -SchemaPath $SchemaPath
        $descriptor | Add-Member `
            -NotePropertyName Bytes `
            -NotePropertyValue $bytes
        $descriptor | Add-Member `
            -NotePropertyName Value `
            -NotePropertyValue $value
        [void](ProductionReleaseState\Assert-CanonicalProductionJsonInput `
            -Input $descriptor `
            -Label $Label)
        return $descriptor
    }
    catch {
        $descriptor.Stream.Dispose()
        throw
    }
}

$requestFullPath = Assert-AbsoluteExternalInput `
    -Path $RequestPath `
    -Label 'Feed-promotion request'
$headFullPath = Assert-AbsoluteExternalInput `
    -Path $PromotionHeadPath `
    -Label 'Feed-promotion CAS head'
$keyFullPath = Assert-AbsoluteExternalInput `
    -Path $AuthorizationPrivateKeyPath `
    -Label 'Feed-promotion authorization private key'
if (-not [IO.Path]::IsPathFullyQualified($OutputPath) -or
    $OutputPath.StartsWith('\\', [StringComparison]::Ordinal) -or
    $OutputPath.StartsWith('//', [StringComparison]::Ordinal)) {
    throw 'Feed-promotion authorization output must use an absolute local path.'
}
$outputFullPath = [IO.Path]::GetFullPath($OutputPath)
$repositoryBoundary = $repositoryRoot.TrimEnd(
    [IO.Path]::DirectorySeparatorChar,
    [IO.Path]::AltDirectorySeparatorChar)
if ($outputFullPath.Equals(
        $repositoryBoundary,
        [StringComparison]::OrdinalIgnoreCase) -or
    $outputFullPath.StartsWith(
        $repositoryBoundary + [IO.Path]::DirectorySeparatorChar,
        [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Feed-promotion authorization output must remain outside the source repository.'
}
if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $outputFullPath) {
    throw 'Feed-promotion authorization output is create-only and already exists.'
}
if ($outputFullPath -in @($requestFullPath, $headFullPath, $keyFullPath)) {
    throw 'Feed-promotion authorization output must be separate from every input.'
}
$outputParent = [IO.Path]::GetDirectoryName($outputFullPath)
$outputParentItem = Microsoft.PowerShell.Management\Get-Item `
    -LiteralPath $outputParent `
    -Force `
    -ErrorAction Stop
if (-not $outputParentItem.PSIsContainer -or
    ($outputParentItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'Feed-promotion authorization output parent must be an ordinary directory.'
}
for ($current = $outputParentItem; $null -ne $current; $current = $current.Parent) {
    if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Feed-promotion authorization output parent crosses a filesystem link.'
    }
}
$outputPendingPath = $outputFullPath + '.pending'
if (Microsoft.PowerShell.Management\Test-Path `
        -LiteralPath $outputPendingPath) {
    throw 'Feed-promotion authorization output has unresolved pending bytes.'
}

$requestInput = $null
$headInput = $null
$privateKeyInput = $null
$outputParentLease = $null
$privateKeyBytes = $null
$signer = $null
try {
    $outputParentLease =
        ProductionReleaseState\Open-ProductionReleaseDirectoryLease `
            -Path $outputParent `
            -Label 'Feed-promotion authorization output parent'
    $requestInput = Open-StrictLockedJson `
        -Path $requestFullPath `
        -Label 'Feed-promotion request' `
        -SchemaPath $requestSchemaPath
    $headInput = Open-StrictLockedJson `
        -Path $headFullPath `
        -Label 'Feed-promotion CAS head' `
        -SchemaPath $headSchemaPath
    $privateKeyInput = ProductionReleaseState\Open-ProductionReleaseInput `
        -Path $keyFullPath `
        -Label 'Feed-promotion authorization private key' `
        -MaximumBytes 64KB

    $request = $requestInput.Value
    $head = $headInput.Value
    if ([string]$head.operationId -cne [string]$request.operationId -or
        [string]$head.requestSha256 -cne [string]$requestInput.Sha256 -or
        [string]$head.requestNonce -cne [string]$request.requestNonce -or
        [string]$head.sourceStateHeadSha256 -cne
            [string]$request.sourceState.headSha256 -or
        [string]$head.payloadSetSha256 -cne [string]$request.payloadSetSha256 -or
        [string]$head.updatedAtUtc -cne [string]$request.createdAtUtc) {
        throw 'Feed-promotion CAS head is not bound to the exact request bytes.'
    }
    if ([string]$request.authorizationTrust.keyId -cne $AuthorizationKeyId -or
        [string]$request.authorizationTrust.algorithm -cne 'ES256' -or
        [string]$request.authorizationTrust.purpose -cne
            'feed-promotion-response') {
        throw 'Feed-promotion request does not select the supplied authorization key.'
    }

    $createdAt = ProductionReleaseState\ConvertFrom-ProductionUtc `
        -Value ([string]$request.createdAtUtc) `
        -Label 'Feed-promotion request creation time'
    $expiresAt = ProductionReleaseState\ConvertFrom-ProductionUtc `
        -Value ([string]$request.expiresAtUtc) `
        -Label 'Feed-promotion request expiry time'
    $now = [DateTimeOffset]::UtcNow
    if ($expiresAt -le $createdAt -or
        ($expiresAt - $createdAt) -gt [TimeSpan]::FromMinutes(60) -or
        $createdAt -gt $now.AddMinutes(2) -or
        $expiresAt -le $now.AddSeconds(5)) {
        throw 'Feed-promotion request is expired, future-dated, or has an invalid lifetime.'
    }

    [byte[]]$privateKeyBytes = @(
        ProductionReleaseState\Read-ProductionReleaseInputBytes `
            -Descriptor $privateKeyInput `
            -Label 'Feed-promotion authorization private key')
    $signer = [Security.Cryptography.ECDsa]::Create()
    $consumed = 0
    try {
        $signer.ImportPkcs8PrivateKey($privateKeyBytes, [ref]$consumed)
    }
    catch {
        throw 'Feed-promotion authorization private key is not valid PKCS8.'
    }
    if ($consumed -ne $privateKeyBytes.Length) {
        throw 'Feed-promotion authorization private key has trailing bytes.'
    }
    $public = $signer.ExportParameters($false)
    if ($public.Q.X.Length -ne 32 -or $public.Q.Y.Length -ne 32 -or
        (ConvertTo-Base64Url -Bytes $public.Q.X) -cne
            [string]$request.authorizationTrust.x -or
        (ConvertTo-Base64Url -Bytes $public.Q.Y) -cne
            [string]$request.authorizationTrust.y) {
        throw 'Feed-promotion authorization private key does not match the request trust anchor.'
    }

    $completedAt = $now.ToUniversalTime().ToString(
        "yyyy-MM-dd'T'HH:mm:ss'Z'",
        [Globalization.CultureInfo]::InvariantCulture)
    $response = [ordered]@{
        schemaVersion = 1
        responseType = 'ensou-dsh-launcher-offline-feed-promotion-response'
        operationId = [string]$request.operationId
        orchestrationId = [string]$request.orchestrationId
        edition = [string]$request.edition
        exposureRing = [string]$request.exposureRing
        feedChannel = [string]$request.feedChannel
        publishScope = [string]$request.publishScope
        releaseSetId = [string]$request.releaseSetId
        requestSha256 = [string]$requestInput.Sha256
        requestNonce = [string]$request.requestNonce
        basePromotionHeadSha256 = [string]$headInput.Sha256
        sourceStateHeadSha256 = [string]$request.sourceState.headSha256
        payloadSetSha256 = [string]$request.payloadSetSha256
        feedCasSha256 = [string]$request.feedCasSha256
        decision = 'AUTHORIZE_OFFLINE_BUNDLE'
        completedAtUtc = $completedAt
        requestExpiresAtUtc = [string]$request.expiresAtUtc
        productionAdmission = 'OFFLINE_BUNDLE_ONLY'
        networkPublishPerformed = $false
        authentication = [ordered]@{
            algorithm = 'ES256'
            keyId = $AuthorizationKeyId
            purpose = 'feed-promotion-response'
            payloadType =
                'ensou-dsh-launcher-feed-promotion-response-authentication-v1'
        }
    }
    [byte[]]$payload = @(
        ProductionFeedPromotion\Get-ProductionFeedPromotionResponseAuthenticationPayload `
            -Response ([pscustomobject]$response))
    $rawSignature = $signer.SignData(
        $payload,
        [Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)
    $signature = ConvertTo-LowSP256Signature -Signature $rawSignature
    if (-not $signer.VerifyData(
            $payload,
            $signature,
            [Security.Cryptography.HashAlgorithmName]::SHA256,
            [Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)) {
        throw 'Feed-promotion authorization signature self-check failed.'
    }
    $response.authentication.value = ConvertTo-Base64Url -Bytes $signature
    $responseBytes = ProductionReleaseState\ConvertTo-ProductionJsonBytes `
        -Value $response
    $responseInput = ProductionReleaseState\ConvertFrom-StrictProductionJsonBytes `
        -Bytes $responseBytes `
        -Label 'Generated feed-promotion authorization response' `
        -SchemaPath $responseSchemaPath
    [void](ProductionReleaseState\Assert-CanonicalProductionJsonInput `
        -Input ([pscustomobject]@{
            Value = $responseInput
            Bytes = $responseBytes
            Sha256 = ProductionReleaseState\Get-ProductionSha256Bytes `
                -Bytes $responseBytes
        }) `
        -Label 'Generated feed-promotion authorization response')

    ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
        -Descriptor $requestInput `
        -Label 'Feed-promotion request'
    ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
        -Descriptor $headInput `
        -Label 'Feed-promotion CAS head'
    ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
        -Descriptor $privateKeyInput `
        -Label 'Feed-promotion authorization private key'
    ProductionReleaseState\Assert-ProductionReleaseDirectoryStillLocked `
        -Descriptor $outputParentLease `
        -Label 'Feed-promotion authorization output parent'
    $output = [IO.File]::Open(
        $outputPendingPath,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None)
    try {
        [void][EnsouLauncherProduction.NativeFileIdentity]::
            RequireOrdinarySingleLink($output.SafeFileHandle)
        $output.Write($responseBytes, 0, $responseBytes.Length)
        $output.Flush($true)
    }
    finally {
        $output.Dispose()
    }
    ProductionReleaseState\Assert-ProductionReleaseDirectoryStillLocked `
        -Descriptor $outputParentLease `
        -Label 'Feed-promotion authorization output parent'
    $outputParentVolume = $outputParentLease.VolumeSerialNumber
    $outputParentFileIndex = $outputParentLease.FileIndex
    # Windows cannot rename a child while the parent read lease denies share
    # write. Release only for the single create-only atomic rename, then prove
    # that the same parent directory identity still names the path.
    $outputParentLease.Handle.Dispose()
    $outputParentLease = $null
    [IO.File]::Move($outputPendingPath, $outputFullPath, $false)
    $outputParentLease =
        ProductionReleaseState\Open-ProductionReleaseDirectoryLease `
            -Path $outputParent `
            -Label 'Feed-promotion authorization output parent'
    if ($outputParentLease.VolumeSerialNumber -ne $outputParentVolume -or
        $outputParentLease.FileIndex -ne $outputParentFileIndex) {
        throw 'Feed-promotion authorization output parent identity changed during atomic publication.'
    }
    $committedOutput =
        ProductionReleaseState\Open-ProductionReleaseInput `
            -Path $outputFullPath `
            -Label 'Committed feed-promotion authorization response' `
            -MaximumBytes 1MB
    try {
        if ([int64]$committedOutput.SizeBytes -ne
                [int64]$responseBytes.LongLength -or
            [string]$committedOutput.Sha256 -cne
                (ProductionReleaseState\Get-ProductionSha256Bytes `
                    -Bytes $responseBytes)) {
            throw 'Committed feed-promotion authorization response differs from the signed bytes.'
        }
    }
    finally {
        $committedOutput.Stream.Dispose()
    }
    ProductionReleaseState\Assert-ProductionReleaseDirectoryStillLocked `
        -Descriptor $outputParentLease `
        -Label 'Feed-promotion authorization output parent'
    [pscustomobject]@{
        OutputPath = $outputFullPath
        ResponseSha256 = ProductionReleaseState\Get-ProductionSha256Bytes `
            -Bytes $responseBytes
        OperationId = [string]$request.operationId
        RequestSha256 = [string]$requestInput.Sha256
        PromotionHeadSha256 = [string]$headInput.Sha256
        ProductionAdmission = 'OFFLINE_BUNDLE_ONLY'
        NetworkPublishPerformed = $false
    }
}
finally {
    if ($null -ne $privateKeyBytes) {
        [Array]::Clear($privateKeyBytes, 0, $privateKeyBytes.Length)
    }
    if ($null -ne $signer) {
        $signer.Dispose()
    }
    if ($null -ne $outputParentLease) {
        $outputParentLease.Handle.Dispose()
    }
    foreach ($input in @($requestInput, $headInput, $privateKeyInput)) {
        if ($null -ne $input -and
            $null -ne $input.PSObject.Properties['Stream'] -and
            $null -ne $input.Stream) {
            $input.Stream.Dispose()
        }
    }
}
