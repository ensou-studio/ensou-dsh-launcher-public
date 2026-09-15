#requires -Version 7.2

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SourceRoot,

    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9]+[.][0-9]+[.][0-9]+(?:[-+][0-9A-Za-z][0-9A-Za-z.-]*)?$')]
    [string]$Version,

    [Parameter(Mandatory = $true)]
    [string]$ManifestOrigin,

    [Parameter(Mandatory = $true)]
    [string]$ArtifactOrigin,

    [Parameter(Mandatory = $true)]
    [string]$PersonalAccountOrigin,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]*$')]
    [string]$ReleaseManifestKeyId,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9_-]{43}$')]
    [string]$ReleaseManifestKeyX,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9_-]{43}$')]
    [string]$ReleaseManifestKeyY,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$AuthenticodeSignerSha256Thumbprint,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9]+[.][0-9]+[.][0-9]+(?:[-+][0-9A-Za-z][0-9A-Za-z.-]*)?$')]
    [string]$StartupStubVersion = '1.2.0',

    [ValidateRange(1, [long]::MaxValue)]
    [long]$CanonicalLowSFromSequence = 1,

    [guid]$BuildIntentId = [guid]::NewGuid()
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$script:RepositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$script:SchemaPath = Join-Path $script:RepositoryRoot `
    'release\schemas\personal-two-clean-build-intent-v1.schema.json'
$script:StateModulePath = Join-Path $PSScriptRoot 'ProductionReleaseState.psm1'
$script:PersonalAccountConfigurationModulePath = Join-Path `
    $PSScriptRoot 'PersonalAccountReleaseConfiguration.psm1'

function Assert-CanonicalHttpsOrigin([string]$Value, [string]$Label) {
    $uri = $null
    if (-not [Uri]::TryCreate($Value, [UriKind]::Absolute, [ref]$uri) -or
        $uri.Scheme -cne 'https' -or
        -not [string]::IsNullOrEmpty($uri.UserInfo) -or
        -not [string]::IsNullOrEmpty($uri.Query) -or
        -not [string]::IsNullOrEmpty($uri.Fragment) -or
        $uri.AbsolutePath -cne '/' -or
        $uri.AbsoluteUri -cne $Value) {
        throw "$Label must be one canonical HTTPS origin ending in '/'."
    }
}

function ConvertFrom-CanonicalP256Coordinate([string]$Value, [string]$Label) {
    try {
        [byte[]]$decoded = [Convert]::FromBase64String(
            $Value.Replace('-', '+').Replace('_', '/') + '=')
    }
    catch {
        throw "$Label is not canonical base64url."
    }

    try {
        if ($decoded.Length -ne 32 -or
            [Convert]::ToBase64String($decoded).TrimEnd('=').Replace('+', '-').Replace('/', '_') -cne $Value) {
            throw "$Label is not one canonical P-256 coordinate."
        }

        return $decoded
    }
    catch {
        [Security.Cryptography.CryptographicOperations]::ZeroMemory($decoded)
        throw
    }
}

function Assert-P256PublicKey([string]$X, [string]$Y) {
    [byte[]]$xBytes = @()
    [byte[]]$yBytes = @()
    $ecdsa = $null
    try {
        $xBytes = ConvertFrom-CanonicalP256Coordinate -Value $X -Label 'ReleaseManifestKeyX'
        $yBytes = ConvertFrom-CanonicalP256Coordinate -Value $Y -Label 'ReleaseManifestKeyY'
        $parameters = [Security.Cryptography.ECParameters]@{
            Curve = [Security.Cryptography.ECCurve+NamedCurves]::nistP256
            Q = [Security.Cryptography.ECPoint]@{ X = $xBytes; Y = $yBytes }
        }
        $ecdsa = [Security.Cryptography.ECDsa]::Create()
        $ecdsa.ImportParameters($parameters)
    }
    catch {
        throw 'Release manifest public key is not a valid P-256 point.'
    }
    finally {
        if ($null -ne $ecdsa) { $ecdsa.Dispose() }
        [Security.Cryptography.CryptographicOperations]::ZeroMemory($xBytes)
        [Security.Cryptography.CryptographicOperations]::ZeroMemory($yBytes)
    }
}

function Assert-OrdinaryDirectoryAndAncestors([string]$Path, [string]$Label) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (-not $item.PSIsContainer) {
        throw "$Label must be a directory."
    }

    for ($current = $item; $null -ne $current; $current = $current.Parent) {
        if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Label crosses a filesystem link."
        }
    }
}

function Invoke-RequiredGit([string]$Root, [string[]]$Arguments, [string]$Label) {
    $output = @(& git -C $Root @Arguments 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "$Label failed: $($output -join ' ')"
    }

    return ($output -join "`n").Trim()
}

function Assert-NewOutputDirectory([string]$Path) {
    if (-not [IO.Path]::IsPathFullyQualified($Path)) {
        throw 'OutputDirectory must be absolute.'
    }

    $fullPath = [IO.Path]::GetFullPath($Path)
    if (Test-Path -LiteralPath $fullPath) {
        throw 'OutputDirectory must be a new absent directory.'
    }

    $parent = [IO.Path]::GetDirectoryName($fullPath)
    if ([string]::IsNullOrWhiteSpace($parent) -or -not (Test-Path -LiteralPath $parent)) {
        throw 'OutputDirectory parent must already exist.'
    }

    Assert-OrdinaryDirectoryAndAncestors -Path $parent -Label 'OutputDirectory parent'

    return $fullPath
}

if (-not (Test-Path -LiteralPath $script:SchemaPath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $script:StateModulePath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $script:PersonalAccountConfigurationModulePath -PathType Leaf)) {
    throw 'Personal Pilot intent producer dependencies are missing.'
}

Import-Module -Name $script:StateModulePath -Force -ErrorAction Stop
Import-Module -Name $script:PersonalAccountConfigurationModulePath -Force -ErrorAction Stop

if (-not [IO.Path]::IsPathFullyQualified($SourceRoot)) {
    throw 'SourceRoot must be absolute.'
}

$sourcePath = [IO.Path]::GetFullPath($SourceRoot)
Assert-OrdinaryDirectoryAndAncestors -Path $sourcePath -Label 'SourceRoot'

$topLevel = Invoke-RequiredGit -Root $sourcePath `
    -Arguments @('rev-parse', '--show-toplevel') -Label 'Personal source Git admission'
$topLevelPath = [IO.Path]::GetFullPath($topLevel)
if (-not $topLevelPath.Equals($sourcePath, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'SourceRoot must be the exact Git top-level checkout.'
}

$status = Invoke-RequiredGit -Root $sourcePath `
    -Arguments @('status', '--porcelain=v1', '--untracked-files=all') -Label 'Personal source clean-tree admission'
if (-not [string]::IsNullOrWhiteSpace($status)) {
    throw 'Personal Pilot intent requires a completely clean source checkout.'
}

$sourceCommit = Invoke-RequiredGit -Root $sourcePath `
    -Arguments @('rev-parse', '--verify', 'HEAD') -Label 'Personal source commit admission'
$sourceTree = Invoke-RequiredGit -Root $sourcePath `
    -Arguments @('rev-parse', '--verify', 'HEAD^{tree}') -Label 'Personal source tree admission'
if ($sourceCommit -notmatch '^[0-9a-f]{40,64}$' -or
    $sourceTree -notmatch '^[0-9a-f]{40,64}$') {
    throw 'Personal source Git identity is malformed.'
}

Assert-CanonicalHttpsOrigin -Value $ManifestOrigin -Label 'ManifestOrigin'
Assert-CanonicalHttpsOrigin -Value $ArtifactOrigin -Label 'ArtifactOrigin'
$canonicalPersonalAccountOrigin = PersonalAccountReleaseConfiguration\Assert-PersonalAccountOrigin `
    -Value $PersonalAccountOrigin `
    -Label 'PersonalAccountOrigin'
Assert-P256PublicKey -X $ReleaseManifestKeyX -Y $ReleaseManifestKeyY

$outputPath = Assert-NewOutputDirectory -Path $OutputDirectory

$intent = [ordered]@{
    schemaVersion = 1
    intentType = 'ensou-dsh-personal-two-clean-production-build-intent'
    buildIntentId = $BuildIntentId.ToString('D')
    sourceCommit = $sourceCommit
    sourceTree = $sourceTree
    version = $Version
    configuration = 'Release'
    runtimeIdentifier = 'win-x64'
    selfContained = $true
    publishSingleFile = $true
    enableCompressionInSingleFile = $true
    manifestOrigin = $ManifestOrigin
    artifactOrigin = $ArtifactOrigin
    personalAccountOrigin = $canonicalPersonalAccountOrigin
    channel = 'pilot'
    releaseManifestTrust = [ordered]@{
        algorithm = 'ES256'
        keyId = $ReleaseManifestKeyId
        purpose = 'release-manifest-signing'
        x = $ReleaseManifestKeyX
        y = $ReleaseManifestKeyY
    }
    startupStubVersion = $StartupStubVersion
    canonicalLowSFromSequence = $CanonicalLowSFromSequence
    authenticodeSignerSha256Thumbprint = $AuthenticodeSignerSha256Thumbprint
}

[byte[]]$intentBytes = ProductionReleaseState\ConvertTo-ProductionJsonBytes -Value $intent
try {
    $intentJson = [Text.UTF8Encoding]::new($false, $true).GetString($intentBytes)
    if (-not (Test-Json -Json $intentJson -SchemaFile $script:SchemaPath -ErrorAction Stop)) {
        throw 'Generated Personal Pilot build intent does not satisfy its schema.'
    }

    [void][IO.Directory]::CreateDirectory($outputPath)
    $destination = Join-Path $outputPath 'personal-two-clean-build-intent.v1.json'
    ProductionReleaseState\Write-ProductionStateFile -Path $destination -Bytes $intentBytes
    [pscustomobject][ordered]@{
        status = 'READY_FOR_TWO_CLEAN_BUILD'
        buildIntentPath = $destination
        buildIntentSha256 = ProductionReleaseState\Get-ProductionSha256Bytes -Bytes $intentBytes
        sourceCommit = $sourceCommit
        sourceTree = $sourceTree
        nextProducer = (Join-Path $script:RepositoryRoot 'release\scripts\New-PersonalTwoCleanBuildEvidence.ps1')
        note = 'This writes no signing key, certificate, installer, feed, or device state.'
    }
}
finally {
    [Security.Cryptography.CryptographicOperations]::ZeroMemory($intentBytes)
}
