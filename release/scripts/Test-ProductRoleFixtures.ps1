#requires -Version 7.2

[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:Assertions = 0

Import-Module (Join-Path $PSScriptRoot 'ProductRoleFixtures.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'ProductionReleaseState.psm1') -Force

function Assert-True {
    param([Parameter(Mandatory = $true)][bool]$Condition, [Parameter(Mandatory = $true)][string]$Label)

    if (-not $Condition) {
        throw $Label
    }
    $script:Assertions++
}

function Assert-Throws {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Action,
        [Parameter(Mandatory = $true)][string]$ExpectedMessage,
        [Parameter(Mandatory = $true)][string]$Label
    )

    try {
        & $Action
    }
    catch {
        if (-not $_.Exception.Message.Contains($ExpectedMessage, [StringComparison]::Ordinal)) {
            throw "$Label failed with an unexpected error: $($_.Exception.Message)"
        }
        $script:Assertions++
        return
    }
    throw "$Label did not fail."
}

function Get-Sha256 {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    return ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Bytes))).ToLowerInvariant()
}

function Get-PeContentSha256ForTest {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    return ProductionReleaseState\Get-PeContentSha256 -Bytes $Bytes
}

function ConvertTo-Base64Url {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    return ([Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_'))
}

function New-TestPeBytes {
    param([Parameter(Mandatory = $true)][byte]$Salt)

    [byte[]]$bytes = [byte[]]::new(512)
    $bytes[0] = 0x4d
    $bytes[1] = 0x5a
    [BitConverter]::GetBytes([int]0x80).CopyTo($bytes, 0x3c)
    $bytes[0x80] = 0x50
    $bytes[0x81] = 0x45
    [BitConverter]::GetBytes([uint16]0x20b).CopyTo($bytes, 0x98)
    [BitConverter]::GetBytes([uint16]240).CopyTo($bytes, 0x94)
    $bytes[511] = $Salt
    return $bytes
}

function New-ValidProductRoleFixture {
    param([Parameter(Mandatory = $true)][string]$Root)

    [IO.Directory]::CreateDirectory($Root) | Out-Null
    $signer = [Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve+NamedCurves]::nistP256)
    [byte[]]$keyBytes = $null
    try {
        $public = $signer.ExportParameters($false)
        $roles = @(
            @{ edition = 'Personal'; role = 'startup-stub'; fileName = 'Ensou.Dsh.Bootstrapper.exe'; targetChannel = 'pilot'; releaseCompatibility = [ordered]@{ startupStubVersion = '1.2.0'; canonicalLowSFromSequence = 1 } },
            @{ edition = 'Personal'; role = 'client-bootstrapper'; fileName = 'Ensou.Dsh.ClientBootstrapper.exe'; targetChannel = 'pilot'; releaseCompatibility = [ordered]@{ startupStubVersion = '1.2.0'; canonicalLowSFromSequence = 1 } },
            @{ edition = 'Personal'; role = 'launcher'; fileName = 'Ensou.Dsh.Launcher.exe'; targetChannel = 'pilot'; releaseCompatibility = [ordered]@{ startupStubVersion = '1.2.0'; canonicalLowSFromSequence = 1 } },
            @{ edition = 'Personal'; role = 'maintenance'; fileName = 'Ensou.Dsh.Personal.Maintenance.exe'; targetChannel = 'pilot'; releaseCompatibility = [ordered]@{ startupStubVersion = '1.2.0'; canonicalLowSFromSequence = 1 } },
            @{ edition = 'Enterprise'; role = 'bootstrapper'; fileName = 'Ensou.Dsh.Enterprise.Bootstrapper.exe'; targetChannel = 'stable'; releaseCompatibility = [ordered]@{ startupStubProtocol = 1 } },
            @{ edition = 'Enterprise'; role = 'launcher'; fileName = 'Ensou.Dsh.Enterprise.Launcher.exe'; targetChannel = 'stable'; releaseCompatibility = [ordered]@{ startupStubProtocol = 1 } },
            @{ edition = 'Enterprise'; role = 'client-bootstrapper'; fileName = 'Ensou.Dsh.Enterprise.ClientBootstrapper.exe'; targetChannel = 'stable'; releaseCompatibility = [ordered]@{ startupStubProtocol = 1 } },
            @{ edition = 'Enterprise'; role = 'maintenance'; fileName = 'Ensou.Dsh.Enterprise.Maintenance.exe'; targetChannel = 'stable'; releaseCompatibility = [ordered]@{ startupStubProtocol = 1 } }
        )
        for ($index = 0; $index -lt $roles.Count; $index++) {
            $role = $roles[$index]
            $bytes = New-TestPeBytes -Salt ([byte]($index + 1))
            $sha256 = Get-Sha256 -Bytes $bytes
            $peContentSha256 = Get-PeContentSha256ForTest -Bytes $bytes
            foreach ($kind in @('unsigned', 'signed')) {
                $directory = Join-Path (Join-Path $Root $kind) ([string]$role.edition)
                [IO.Directory]::CreateDirectory($directory) | Out-Null
                $path = Join-Path $directory ([string]$role.fileName)
                [IO.File]::WriteAllBytes($path, $bytes)
                $role[$kind] = [ordered]@{
                    relativePath = "$kind/$($role.edition)/$($role.fileName)"
                    sizeBytes = [int64]$bytes.Length
                    sha256 = $sha256
                    peContentSha256 = $peContentSha256
                }
            }
        }
        $manifest = [ordered]@{
            schemaVersion = 1
            fixtureType = 'ensou-dsh-launcher-product-role-fixtures'
            releaseManifestTrust = [ordered]@{
                algorithm = 'ES256'
                purpose = 'release-manifest-signing'
                keyId = 'launcher-release-manifest-signing-test'
                x = ConvertTo-Base64Url -Bytes $public.Q.X
                y = ConvertTo-Base64Url -Bytes $public.Q.Y
            }
            authenticodePolicy = [ordered]@{ signerSha256Thumbprint = ('a' * 64) }
            roles = $roles
        }
        [IO.File]::WriteAllText((Join-Path $Root 'product-role-fixtures.v1.json'), ($manifest | ConvertTo-Json -Depth 16 -Compress), [Text.UTF8Encoding]::new($false))
        $keyBytes = $signer.ExportPkcs8PrivateKey()
        [IO.File]::WriteAllBytes((Join-Path $Root 'release-manifest-test-key.pk8'), $keyBytes)
        return $manifest
    }
    finally {
        if ($null -ne $keyBytes) {
            [Array]::Clear($keyBytes, 0, $keyBytes.Length)
        }
        $signer.Dispose()
    }
}

function Read-TestManifest {
    param([Parameter(Mandatory = $true)][string]$Root)

    return [IO.File]::ReadAllText((Join-Path $Root 'product-role-fixtures.v1.json'), [Text.UTF8Encoding]::new($false, $true)) | ConvertFrom-Json -Depth 32 -DateKind String
}

function Write-TestManifest {
    param([Parameter(Mandatory = $true)][string]$Root, [Parameter(Mandatory = $true)]$Manifest)

    [IO.File]::WriteAllText((Join-Path $Root 'product-role-fixtures.v1.json'), ($Manifest | ConvertTo-Json -Depth 32 -Compress), [Text.UTF8Encoding]::new($false))
}

$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('ensou-product-role-fixtures-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($testRoot) | Out-Null
try {
    $validRoot = Join-Path $testRoot 'valid'
    $validManifest = New-ValidProductRoleFixture -Root $validRoot
    $template = New-ProductRoleFixtureManifestTemplate
    Assert-True ($template.fixtureType -ceq 'ensou-dsh-launcher-product-role-fixtures' -and $template.roles.Count -eq 8) 'Fixture template lost its fixed eight-role public contract.'
    Assert-True ($null -eq $template.PSObject.Properties['privateKey'] -and $null -eq $template.PSObject.Properties['pfxPath']) 'Fixture template exposed a secret-bearing input.'
    $contract = Import-ProductRoleFixtureContract `
        -FixtureRoot $validRoot `
        -ManifestPath (Join-Path $validRoot 'product-role-fixtures.v1.json') `
        -ReleaseManifestKeyPath (Join-Path $validRoot 'release-manifest-test-key.pk8') `
        -DestinationRoot (Join-Path $testRoot 'private-copy')
    try {
        Assert-True ($contract.Roles.Count -eq 8) 'Valid fixture did not materialize every role.'
        Assert-True ($contract.SignerSha256 -ceq ('a' * 64)) 'Valid fixture signer hash changed.'
        $expectedPublic = $contract.ReleaseManifestSigner.ExportParameters($false)
        Assert-True ((ConvertTo-Base64Url -Bytes $expectedPublic.Q.X) -ceq [string]$validManifest.releaseManifestTrust.x) 'Imported release key X coordinate changed.'
        Assert-True ((ConvertTo-Base64Url -Bytes $expectedPublic.Q.Y) -ceq [string]$validManifest.releaseManifestTrust.y) 'Imported release key Y coordinate changed.'
        foreach ($role in @($contract.Roles)) {
            Assert-True ((Test-Path -LiteralPath $role.UnsignedPath -PathType Leaf) -and (Test-Path -LiteralPath $role.SignedPath -PathType Leaf)) "Role $($role.Edition)/$($role.Role) private copies were not materialized."
        }
    }
    finally {
        $contract.ReleaseManifestSigner.Dispose()
    }

    foreach ($negative in @(
            [pscustomobject]@{
                Label = 'schema-version-string'
                Mutate = { param($manifest, $root) $manifest.schemaVersion = '1' }
                MutateKey = $false
                ExpectedMessage = 'schemaVersion must be a JSON integer'
            },
            [pscustomobject]@{
                Label = 'size-fractional'
                Mutate = { param($manifest, $root) $manifest.roles[0].unsigned.sizeBytes = 512.5 }
                MutateKey = $false
                ExpectedMessage = 'sizeBytes must be a JSON integer'
            },
            [pscustomobject]@{
                Label = 'compatibility-string'
                Mutate = { param($manifest, $root) $manifest.roles[0].releaseCompatibility.canonicalLowSFromSequence = '1' }
                MutateKey = $false
                ExpectedMessage = 'canonicalLowSFromSequence must be a JSON integer'
            },
            [pscustomobject]@{
                Label = 'file-name-number'
                Mutate = { param($manifest, $root) $manifest.roles[0].fileName = 1 }
                MutateKey = $false
                ExpectedMessage = 'fileName must be a JSON string'
            },
            [pscustomobject]@{
                Label = 'missing-role'
                Mutate = { param($manifest, $root) $manifest.roles = @($manifest.roles)[0..6] }
                MutateKey = $false
                ExpectedMessage = 'exactly eight role profiles'
            },
            [pscustomobject]@{
                Label = 'personal-channel-mismatch'
                Mutate = { param($manifest, $root) $manifest.roles[0].targetChannel = 'stable' }
                MutateKey = $false
                ExpectedMessage = 'mismatched fixed profile'
            },
            [pscustomobject]@{
                Label = 'declared-hash-mismatch'
                Mutate = { param($manifest, $root) $manifest.roles[0].unsigned.sha256 = ('0' * 64) }
                MutateKey = $false
                ExpectedMessage = 'differs from its declared full or PE-content identity'
            },
            [pscustomobject]@{
                Label = 'signed-pe-content-binding-mismatch'
                Mutate = {
                    param($manifest, $root)
                    $role = $manifest.roles[0]
                    $relativePath = ([string]$role.signed.relativePath).Replace('/', [IO.Path]::DirectorySeparatorChar)
                    $path = Join-Path $root $relativePath
                    [byte[]]$bytes = [IO.File]::ReadAllBytes($path)
                    $bytes[511] = 0x7f
                    [IO.File]::WriteAllBytes($path, $bytes)
                    $role.signed.sha256 = Get-Sha256 -Bytes $bytes
                    $role.signed.peContentSha256 = Get-PeContentSha256ForTest -Bytes $bytes
                }
                MutateKey = $false
                ExpectedMessage = 'signed PE content differs from its unsigned role input'
            },
            [pscustomobject]@{
                Label = 'traversal-relative-path'
                Mutate = { param($manifest, $root) $manifest.roles[0].signed.relativePath = '../signed.exe' }
                MutateKey = $false
                ExpectedMessage = 'path must be'
            },
            [pscustomobject]@{
                Label = 'public-key-mismatch'
                Mutate = { param($manifest, $root) $manifest.releaseManifestTrust.x = ('A' * 43) }
                MutateKey = $false
                ExpectedMessage = 'public parameters differ'
            },
            [pscustomobject]@{
                Label = 'non-p256-pkcs8'
                Mutate = {
                    param($manifest, $root)
                    $signer = [Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve+NamedCurves]::nistP384)
                    [byte[]]$raw = $null
                    try {
                        $raw = $signer.ExportPkcs8PrivateKey()
                        [IO.File]::WriteAllBytes((Join-Path $root 'release-manifest-test-key.pk8'), $raw)
                    }
                    finally {
                        if ($null -ne $raw) { [Array]::Clear($raw, 0, $raw.Length) }
                        $signer.Dispose()
                    }
                }
                MutateKey = $true
                ExpectedMessage = 'not NIST P-256'
            },
            [pscustomobject]@{
                Label = 'trailing-pkcs8'
                Mutate = {
                    param($manifest, $root)
                    [byte[]]$raw = [IO.File]::ReadAllBytes((Join-Path $root 'release-manifest-test-key.pk8'))
                    [byte[]]$trailing = $null
                    try {
                        [byte[]]$trailing = [byte[]]::new($raw.Length + 1)
                        [Array]::Copy($raw, $trailing, $raw.Length)
                        $trailing[$trailing.Length - 1] = 0
                        [IO.File]::WriteAllBytes((Join-Path $root 'release-manifest-test-key.pk8'), $trailing)
                    }
                    finally {
                        if ($null -ne $raw) { [Array]::Clear($raw, 0, $raw.Length) }
                        if ($null -ne $trailing) { [Array]::Clear($trailing, 0, $trailing.Length) }
                    }
                }
                MutateKey = $true
                ExpectedMessage = 'trailing or incomplete PKCS#8 bytes'
            }
        )) {
        $negativeRoot = Join-Path $testRoot ([string]$negative.Label)
        Copy-Item -LiteralPath $validRoot -Destination $negativeRoot -Recurse
        $manifest = Read-TestManifest -Root $negativeRoot
        & $negative.Mutate $manifest $negativeRoot
        if (-not [bool]$negative.MutateKey) {
            Write-TestManifest -Root $negativeRoot -Manifest $manifest
        }
        Assert-Throws -Label "Negative product role fixture '$($negative.Label)'" -ExpectedMessage ([string]$negative.ExpectedMessage) -Action {
            $failed = Import-ProductRoleFixtureContract `
                -FixtureRoot $negativeRoot `
                -ManifestPath (Join-Path $negativeRoot 'product-role-fixtures.v1.json') `
                -ReleaseManifestKeyPath (Join-Path $negativeRoot 'release-manifest-test-key.pk8') `
                -DestinationRoot (Join-Path $negativeRoot 'private-copy')
            if ($null -ne $failed) {
                $failed.ReleaseManifestSigner.Dispose()
            }
        }
    }
    Write-Output "PASS Test-ProductRoleFixtures metadata-only-synthetic-contract assertions=$script:Assertions"
}
finally {
    if (Test-Path -LiteralPath $testRoot) {
        $resolvedRoot = [IO.Path]::GetFullPath($testRoot)
        $temporaryPrefix = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd(
            [IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
        if (-not $resolvedRoot.StartsWith($temporaryPrefix, [StringComparison]::OrdinalIgnoreCase) -or
            [IO.Path]::GetFileName($resolvedRoot) -cnotmatch '^ensou-product-role-fixtures-[0-9a-f]{32}$' -or
            ((Get-Item -LiteralPath $resolvedRoot -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Refusing cleanup outside the exact owned product-role fixture directory.'
        }
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}
