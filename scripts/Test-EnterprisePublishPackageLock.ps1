[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PackageDirectory,

    [string]$LockPath = (Join-Path $PSScriptRoot `
        '..\installer\enterprise-publish-runtime-packs.lock.json')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Assert-OrdinaryPath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][bool]$Directory
    )

    $resolved = [IO.Path]::GetFullPath($Path)
    $item = Get-Item -LiteralPath $resolved -Force
    if ($item.PSIsContainer -ne $Directory -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Expected an ordinary local path: $resolved"
    }

    return $resolved
}

function Get-Sha512Base64 {
    param([Parameter(Mandatory = $true)][string]$Path)

    $stream = [IO.File]::OpenRead($Path)
    try {
        $algorithm = [Security.Cryptography.SHA512]::Create()
        try {
            return [Convert]::ToBase64String($algorithm.ComputeHash($stream))
        } finally {
            $algorithm.Dispose()
        }
    } finally {
        $stream.Dispose()
    }
}

$packageRoot = Assert-OrdinaryPath -Path $PackageDirectory -Directory $true
$resolvedLock = Assert-OrdinaryPath -Path $LockPath -Directory $false
$lock = Get-Content -LiteralPath $resolvedLock -Raw | ConvertFrom-Json
$rootProperties = @($lock.PSObject.Properties.Name | Sort-Object)
if (($rootProperties -join ',') -ne `
        'dotnetSdkVersion,packages,runtimeIdentifier,schemaVersion,selfContained,source' -or
    $lock.schemaVersion -ne 1 -or
    $lock.dotnetSdkVersion -cne '10.0.302' -or
    $lock.runtimeIdentifier -cne 'win-x64' -or
    $lock.selfContained -ne $true -or
    $lock.source -cne 'https://api.nuget.org/v3/index.json') {
    throw "Enterprise publish package lock metadata is invalid: $resolvedLock"
}

$actualSdk = (& dotnet --version).Trim()
if ($LASTEXITCODE -ne 0 -or $actualSdk -cne $lock.dotnetSdkVersion) {
    throw "Required .NET SDK is $($lock.dotnetSdkVersion); actual is $actualSdk."
}

$expectedFileNames = [Collections.Generic.HashSet[string]]::new(
    [StringComparer]::OrdinalIgnoreCase)
$results = foreach ($package in @($lock.packages)) {
    $properties = @($package.PSObject.Properties.Name | Sort-Object)
    if (($properties -join ',') -ne 'bytes,id,kind,sha512,version' -or
        $package.kind -cnotin @('runtime-pack', 'publish-tool') -or
        $package.id -cnotmatch '^[A-Za-z0-9.-]+$' -or
        $package.version -cnotmatch '^\d+\.\d+\.\d+$' -or
        $package.bytes -isnot [long] -and $package.bytes -isnot [int] -or
        [long]$package.bytes -le 0 -or
        $package.sha512 -cnotmatch '^[A-Za-z0-9+/]{86}==$') {
        throw 'Enterprise publish package lock contains an invalid package entry.'
    }

    $fileName = "$($package.id.ToLowerInvariant()).$($package.version).nupkg"
    if (-not $expectedFileNames.Add($fileName)) {
        throw "Duplicate enterprise publish package: $fileName"
    }

    $packagePath = Assert-OrdinaryPath `
        -Path (Join-Path $packageRoot $fileName) `
        -Directory $false
    $item = Get-Item -LiteralPath $packagePath -Force
    if ($item.Length -ne [long]$package.bytes) {
        throw "Enterprise publish package size mismatch: $fileName"
    }

    $actualHash = Get-Sha512Base64 $packagePath
    if ($actualHash -cne $package.sha512) {
        throw "Enterprise publish package SHA-512 mismatch: $fileName"
    }

    [pscustomobject]@{
        Id = $package.id
        Version = $package.version
        Kind = $package.kind
        Bytes = $item.Length
        Sha512Verified = $true
    }
}

$unexpected = Get-ChildItem -LiteralPath $packageRoot -Filter '*.nupkg' -File -Force |
    Where-Object { -not $expectedFileNames.Contains($_.Name) } |
    Select-Object -First 1
if ($unexpected) {
    throw "Unpinned package exists in enterprise publish source: $($unexpected.Name)"
}

$results
[pscustomobject]@{
    DotnetSdkVersion = $lock.dotnetSdkVersion
    RuntimeIdentifier = $lock.runtimeIdentifier
    SelfContained = $lock.selfContained
    Source = $lock.source
    PackageCount = @($results).Count
}
