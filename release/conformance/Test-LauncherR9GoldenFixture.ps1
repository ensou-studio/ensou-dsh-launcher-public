#requires -Version 7.2

[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [string]$FixturePath = (Join-Path $PSScriptRoot 'launcher-r9-golden-v1\fixture.v1.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$expectedRawSha256 =
    '9c9d9aad4e3be5b7631cd6e9008a9e4b35b6965f08e9a6e9b30ae5533d7c0922'
$expectedFixtureSetSha256 =
    'c45aab11ac642cb0932f534cff2f9de32f5f6989f78d6a90e12c61c70d4874fa'
$expectedPaths = @(
    'state-package/request.v1.json',
    'state-package/response.v1.json',
    'state-package/promotion-head.v1.json',
    'state-package/bundle-head.v1.json',
    'state-package/promotion-admission.v1.json',
    'authorization-trust.v1.json',
    'promotion-root/head.json',
    'promotion-root/bundle/request.v1.json',
    'promotion-root/bundle/response.v1.json',
    'promotion-root/bundle/head.v1.json',
    'promotion-root/bundle/payload/release-set.v2.json',
    'promotion-root/bundle/payload/release-public-key.v2.json',
    'promotion-root/bundle/payload/Ensou.Dsh.Enterprise.Bootstrapper.exe',
    'promotion-root/bundle/payload/EnsouDshRuntime-managed-v2026.08.30.1-win-x64.zip.sha256',
    'promotion-root/bundle/payload/Ensou.Dsh.Enterprise.Launcher.exe'
)

function Assert-Equal {
    param(
        [Parameter(Mandatory = $true)]$Actual,
        [Parameter(Mandatory = $true)]$Expected,
        [Parameter(Mandatory = $true)][string]$Label
    )
    if ([string]$Actual -cne [string]$Expected) {
        throw "$Label differs."
    }
}

function Get-RawSha256 {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    return [Convert]::ToHexStringLower(
        [Security.Cryptography.SHA256]::HashData($Bytes))
}

$stateModulePath = Join-Path $RepositoryRoot `
    'release\scripts\ProductionReleaseState.psm1'
$promotionModulePath = Join-Path $RepositoryRoot `
    'release\scripts\ProductionFeedPromotion.psm1'
Import-Module $stateModulePath -Force -DisableNameChecking
Import-Module $promotionModulePath -Force -DisableNameChecking
Import-Module $stateModulePath -Force -DisableNameChecking

$fixtureBytes = [IO.File]::ReadAllBytes($FixturePath)
Assert-Equal `
    -Actual (Get-RawSha256 -Bytes $fixtureBytes) `
    -Expected $expectedRawSha256 `
    -Label 'Raw Launcher r9 golden fixture SHA-256'
$strictUtf8 = [Text.UTF8Encoding]::new($false, $true)
$fixture = $strictUtf8.GetString($fixtureBytes) |
    ConvertFrom-Json -Depth 100
ProductionReleaseState\Assert-ExactProductionJsonMembers `
    -Value $fixture `
    -Expected @(
        'schemaVersion', 'fixtureType', 'generatedBy', 'schemaPins',
        'operationContract', 'files', 'fixtureSetSha256') `
    -Label 'Launcher r9 golden fixture'
if ([int]$fixture.schemaVersion -ne 1 -or
    [string]$fixture.fixtureType -cne
        'ensou-dsh-launcher-r9-golden-fixture' -or
    [bool]$fixture.generatedBy.privateKeyMaterialRetained) {
    throw 'Launcher r9 golden fixture metadata is not fail closed.'
}
Assert-Equal `
    -Actual ([string]$fixture.fixtureSetSha256) `
    -Expected $expectedFixtureSetSha256 `
    -Label 'Recorded Launcher r9 fixture-set SHA-256'

$schemaPins = @($fixture.schemaPins)
if ($schemaPins.Count -ne 4) {
    throw 'Launcher r9 golden fixture must pin exactly four wire schemas.'
}
foreach ($pin in $schemaPins) {
    if ([string]$pin.path -cnotmatch
            '^release/schemas/launcher-feed-promotion-[a-z0-9-]+-v1\.schema\.json$' -or
        [string]$pin.sha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'Launcher r9 golden fixture has a malformed schema pin.'
    }
    $schemaPath = Join-Path $RepositoryRoot `
        ([string]$pin.path).Replace('/', [IO.Path]::DirectorySeparatorChar)
    Assert-Equal `
        -Actual ((Get-FileHash -LiteralPath $schemaPath -Algorithm SHA256).Hash.ToLowerInvariant()) `
        -Expected ([string]$pin.sha256) `
        -Label "Current schema pin $($pin.path)"
}

$files = @($fixture.files)
if ($files.Count -ne $expectedPaths.Count) {
    throw 'Launcher r9 golden fixture logical inventory count differs.'
}
$identities = @()
$decoded = [Collections.Generic.Dictionary[string, byte[]]]::new(
    [StringComparer]::Ordinal)
for ($index = 0; $index -lt $files.Count; $index++) {
    $file = $files[$index]
    $path = [string]$file.relativePath
    Assert-Equal -Actual $path -Expected $expectedPaths[$index] `
        -Label "Launcher r9 fixture path index $index"
    if ([IO.Path]::IsPathFullyQualified($path) -or
        $path.Contains('\', [StringComparison]::Ordinal) -or
        @($path.Split('/') | Where-Object { $_ -in @('', '.', '..') }).Count -ne 0 -or
        -not $decoded.TryAdd($path, [byte[]]::new(0))) {
        throw "Launcher r9 fixture path '$path' is unsafe or repeated."
    }
    try {
        [byte[]]$bytes = [Convert]::FromBase64String([string]$file.contentBase64)
    }
    catch [FormatException] {
        throw "Launcher r9 fixture file '$path' is not base64."
    }
    if ([Convert]::ToBase64String($bytes) -cne [string]$file.contentBase64 -or
        [int64]$file.sizeBytes -ne $bytes.LongLength -or
        (Get-RawSha256 -Bytes $bytes) -cne [string]$file.sha256) {
        throw "Launcher r9 fixture file '$path' differs from its byte identity."
    }
    $decoded[$path] = $bytes
    $identities += [ordered]@{
        relativePath = $path
        sizeBytes = [int64]$bytes.LongLength
        sha256 = [string]$file.sha256
    }
}
[byte[]]$identityBytes = @(
    ProductionReleaseState\ConvertTo-ProductionJsonBytes -Value $identities)
[byte[]]$prefix = [Text.Encoding]::UTF8.GetBytes(
    "ensou-dsh-launcher-r9-golden-fixture-set-v1`n")
[byte[]]$setInput = [byte[]]::new($prefix.Length + $identityBytes.Length)
[Buffer]::BlockCopy($prefix, 0, $setInput, 0, $prefix.Length)
[Buffer]::BlockCopy(
    $identityBytes, 0, $setInput, $prefix.Length, $identityBytes.Length)
Assert-Equal `
    -Actual (Get-RawSha256 -Bytes $setInput) `
    -Expected $expectedFixtureSetSha256 `
    -Label 'Computed Launcher r9 fixture-set SHA-256'

$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) (
    'ensou-launcher-r9-golden-' + [Guid]::NewGuid().ToString('N'))
$admission = $null
try {
    [IO.Directory]::CreateDirectory($temporaryRoot) | Out-Null
    foreach ($path in $expectedPaths) {
        $target = Join-Path $temporaryRoot `
            $path.Replace('/', [IO.Path]::DirectorySeparatorChar)
        [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target)) |
            Out-Null
        [IO.File]::WriteAllBytes($target, $decoded[$path])
    }
    foreach ($pair in @(
            @('state-package/request.v1.json', 'promotion-root/bundle/request.v1.json'),
            @('state-package/response.v1.json', 'promotion-root/bundle/response.v1.json'),
            @('state-package/promotion-head.v1.json', 'promotion-root/head.json'),
            @('state-package/bundle-head.v1.json', 'promotion-root/bundle/head.v1.json'))) {
        if (-not [Security.Cryptography.CryptographicOperations]::FixedTimeEquals(
                $decoded[$pair[0]], $decoded[$pair[1]])) {
            throw "Launcher r9 duplicated wire file '$($pair[0])' differs."
        }
    }

    $contract = $fixture.operationContract
    $admission = ProductionFeedPromotion\Open-ProductionFeedPromotionBundleAdmission `
        -PromotionRoot (Join-Path $temporaryRoot 'promotion-root') `
        -ExpectedPromotionHeadSha256 ([string]$contract.promotionHeadSha256) `
        -ExpectedBundleHeadSha256 ([string]$contract.bundleHeadSha256) `
        -ExpectedSourceHeadSha256 ([string]$contract.sourceStateHeadSha256) `
        -ExpectedRequestSha256 ([string]$contract.requestSha256) `
        -ExpectedResponseSha256 ([string]$contract.responseSha256) `
        -ExpectedBundleSetSha256 ([string]$contract.bundleSetSha256)
    foreach ($check in @(
            @($admission.OperationId, $contract.operationId, 'operationId'),
            @($admission.RequestSha256, $contract.requestSha256, 'request SHA-256'),
            @($admission.ResponseSha256, $contract.responseSha256, 'response SHA-256'),
            @($admission.PromotionHeadSha256, $contract.promotionHeadSha256, 'promotion-head SHA-256'),
            @($admission.BundleHeadSha256, $contract.bundleHeadSha256, 'bundle-head SHA-256'),
            @($admission.BundleSetSha256, $contract.bundleSetSha256, 'bundle-set SHA-256'),
            @($admission.SourceHeadSha256, $contract.sourceStateHeadSha256, 'source-head SHA-256'),
            @($admission.ProductionAdmission, $contract.expectedProductionAdmission, 'production admission'))) {
        Assert-Equal -Actual $check[0] -Expected $check[1] -Label $check[2]
    }
    if ([bool]$admission.NetworkPublishPerformed -or
        @($admission.PayloadInputs).Count -ne 5) {
        throw 'Launcher r9 production bundle admission crossed the NO-GO boundary.'
    }
}
finally {
    if ($null -ne $admission) {
        ProductionFeedPromotion\Close-ProductionFeedPromotionBundleAdmission `
            -Admission $admission
    }
    if (Test-Path -LiteralPath $temporaryRoot) {
        $resolved = [IO.Path]::GetFullPath($temporaryRoot)
        $temp = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
        if (-not $resolved.StartsWith($temp, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Refusing to remove a non-temporary golden fixture directory.'
        }
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}

Write-Output (
    'PASS Launcher r9 golden fixture conformance: raw={0} set={1} operation={2}' -f
        $expectedRawSha256,
        $expectedFixtureSetSha256,
        [string]$fixture.operationContract.operationId)
