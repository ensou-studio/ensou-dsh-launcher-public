[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$WorkDirectory,

    [Parameter(Mandatory = $true)]
    [string]$OutputDescriptorPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function ConvertTo-Base64Url {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    return [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

$workRoot = [IO.Path]::GetFullPath($WorkDirectory)
if (Test-Path -LiteralPath $workRoot) {
    $work = Get-Item -LiteralPath $workRoot -Force
    if (-not $work.PSIsContainer -or
        ($work.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        @(Get-ChildItem -LiteralPath $workRoot -Force).Count -ne 0) {
        throw 'Development trust work directory must be absent or empty and ordinary.'
    }
} else {
    New-Item -ItemType Directory -Path $workRoot | Out-Null
}
for ($current = Get-Item -LiteralPath $workRoot -Force;
     $null -ne $current;
     $current = $current.Parent) {
    if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Development trust work directory crosses a filesystem link.'
    }
}

$descriptorPath = [IO.Path]::GetFullPath($OutputDescriptorPath)
$descriptorParent = Split-Path -Parent $descriptorPath
if (-not (Test-Path -LiteralPath $descriptorParent -PathType Container)) {
    New-Item -ItemType Directory -Path $descriptorParent | Out-Null
}
if (Test-Path -LiteralPath $descriptorPath) {
    throw 'Development trust descriptor is create-only and already exists.'
}

$key = [Security.Cryptography.ECDsa]::Create(
    [Security.Cryptography.ECCurve+NamedCurves]::nistP256)
try {
    $parameters = $key.ExportParameters($true)
    $keyPath = Join-Path $workRoot 'ephemeral-private.pk8'
    $keyBytes = $key.ExportPkcs8PrivateKey()
    try {
        $keyStream = [IO.File]::Open(
            $keyPath,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None)
        try {
            $keyStream.Write($keyBytes)
            $keyStream.Flush($true)
        } finally {
            $keyStream.Dispose()
        }
    } finally {
        [Security.Cryptography.CryptographicOperations]::ZeroMemory($keyBytes)
    }
    $descriptor = [ordered]@{
        schemaVersion = 1
        productionBuild = $false
        manifestOrigin = 'https://updates.example.test/'
        artifactOrigin = 'https://updates.example.test/'
        channel = 'stable'
        keyId = 'personal-ci-ephemeral'
        keyX = ConvertTo-Base64Url $parameters.Q.X
        keyY = ConvertTo-Base64Url $parameters.Q.Y
        startupStubVersion = '1.2.0'
        canonicalLowSFromSequence = 1
        authenticodeSignerSha256Thumbprint = $null
        signingPrivateKeyPkcs8Path = $keyPath
    }
    $bytes = [Text.Encoding]::UTF8.GetBytes(
        ($descriptor | ConvertTo-Json -Depth 4 -Compress))
    try {
        $output = [IO.File]::Open(
            $descriptorPath,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::Read)
        try {
            $output.Write($bytes)
            $output.Flush($true)
        } finally {
            $output.Dispose()
        }
    } finally {
        [Security.Cryptography.CryptographicOperations]::ZeroMemory($bytes)
    }
} finally {
    $key.Dispose()
}

Write-Output $descriptorPath
