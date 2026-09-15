#requires -Version 7.2

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'ProductionReleaseState.psm1') -Force -Scope Local

$script:MaximumManifestBytes = 256KB
$script:MaximumKeyBytes = 8KB
$script:MaximumArtifactBytes = 512MB
$script:FixtureType = 'ensou-dsh-launcher-product-role-fixtures'
$script:ReleaseManifestKeyId = 'launcher-release-manifest-signing-test'
$script:RoleProfiles = @(
    [pscustomobject]@{ Edition = 'Personal'; Role = 'startup-stub'; FileName = 'Ensou.Dsh.Bootstrapper.exe'; TargetChannel = 'pilot'; Compatibility = 'personal' },
    [pscustomobject]@{ Edition = 'Personal'; Role = 'client-bootstrapper'; FileName = 'Ensou.Dsh.ClientBootstrapper.exe'; TargetChannel = 'pilot'; Compatibility = 'personal' },
    [pscustomobject]@{ Edition = 'Personal'; Role = 'launcher'; FileName = 'Ensou.Dsh.Launcher.exe'; TargetChannel = 'pilot'; Compatibility = 'personal' },
    [pscustomobject]@{ Edition = 'Personal'; Role = 'maintenance'; FileName = 'Ensou.Dsh.Personal.Maintenance.exe'; TargetChannel = 'pilot'; Compatibility = 'personal' },
    [pscustomobject]@{ Edition = 'Enterprise'; Role = 'bootstrapper'; FileName = 'Ensou.Dsh.Enterprise.Bootstrapper.exe'; TargetChannel = 'stable'; Compatibility = 'enterprise' },
    [pscustomobject]@{ Edition = 'Enterprise'; Role = 'launcher'; FileName = 'Ensou.Dsh.Enterprise.Launcher.exe'; TargetChannel = 'stable'; Compatibility = 'enterprise' },
    [pscustomobject]@{ Edition = 'Enterprise'; Role = 'client-bootstrapper'; FileName = 'Ensou.Dsh.Enterprise.ClientBootstrapper.exe'; TargetChannel = 'stable'; Compatibility = 'enterprise' },
    [pscustomobject]@{ Edition = 'Enterprise'; Role = 'maintenance'; FileName = 'Ensou.Dsh.Enterprise.Maintenance.exe'; TargetChannel = 'stable'; Compatibility = 'enterprise' }
)

function Assert-ProductRoleFixtureExactMembers {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string[]]$Expected,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ($null -eq $Value) {
        throw "$Label is required."
    }
    $actual = @($Value.PSObject.Properties | ForEach-Object Name)
    if ($actual.Count -ne $Expected.Count) {
        throw "$Label has an unexpected member count."
    }
    foreach ($name in $Expected) {
        if ($actual -cnotcontains $name) {
            throw "$Label is missing required member '$name'."
        }
    }
    foreach ($name in $actual) {
        if ($Expected -cnotcontains $name) {
            throw "$Label contains unexpected member '$name'."
        }
    }
}

function Assert-ProductRoleFixtureHexSha256 {
    param([Parameter(Mandatory = $true)][string]$Value, [Parameter(Mandatory = $true)][string]$Label)

    if ($Value -cnotmatch '^[0-9a-f]{64}$') {
        throw "$Label must be one lowercase SHA-256 hex value."
    }
}

function Assert-ProductRoleFixtureString {
    param([Parameter(Mandatory = $true)]$Value, [Parameter(Mandatory = $true)][string]$Label)

    if ($Value -isnot [string]) {
        throw "$Label must be a JSON string."
    }
    return [string]$Value
}

function Assert-ProductRoleFixtureInteger {
    param([Parameter(Mandatory = $true)]$Value, [Parameter(Mandatory = $true)][string]$Label)

    if ($Value -isnot [int64]) {
        throw "$Label must be a JSON integer."
    }
    return [int64]$Value
}

function ConvertTo-ProductRoleFixtureBase64Url {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    return ([Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_'))
}

function ConvertFrom-ProductRoleFixtureP256Coordinate {
    param([Parameter(Mandatory = $true)][string]$Value, [Parameter(Mandatory = $true)][string]$Label)

    if ($Value -cnotmatch '^[A-Za-z0-9_-]{43}$') {
        throw "$Label must be one canonical 32-byte base64url P-256 coordinate."
    }
    try {
        $bytes = [Convert]::FromBase64String($Value.Replace('-', '+').Replace('_', '/') + '=')
    }
    catch {
        throw "$Label is not base64url."
    }
    if ($bytes.Length -ne 32 -or (ConvertTo-ProductRoleFixtureBase64Url -Bytes $bytes) -cne $Value) {
        throw "$Label is not canonical 32-byte base64url."
    }
    return $bytes
}

function Resolve-ProductRoleFixtureContainedFile {
    param(
        [Parameter(Mandatory = $true)][string]$FixtureRoot,
        [Parameter(Mandatory = $true)]$RelativePath,
        [Parameter(Mandatory = $true)][string]$ExpectedRelativePath,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $relative = Assert-ProductRoleFixtureString -Value $RelativePath -Label "$Label relativePath"
    if ($relative -cne $ExpectedRelativePath) {
        throw "$Label path must be '$ExpectedRelativePath'."
    }
    $candidate = [IO.Path]::GetFullPath(
        (Join-Path $FixtureRoot ($relative.Replace('/', [IO.Path]::DirectorySeparatorChar))))
    $prefix = $FixtureRoot.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    if (-not $candidate.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label escapes the caller-owned fixture root."
    }
    return ProductionReleaseState\Resolve-OrdinaryProductionFile -Path $candidate -Label $Label
}

function Read-ProductRoleFixtureLockedInput {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][int64]$MaximumBytes
    )

    $input = ProductionReleaseState\Open-ProductionReleaseInput -Path $Path -Label $Label -MaximumBytes $MaximumBytes
    try {
        $bytes = ProductionReleaseState\Read-ProductionReleaseInputBytes -Descriptor $input -Label $Label
        ProductionReleaseState\Assert-ProductionReleaseInputStillLocked -Descriptor $input -Label $Label
        return [pscustomobject]@{
            Path = $input.Path
            Bytes = $bytes
            Sha256 = [string]$input.Sha256
            SizeBytes = [int64]$input.SizeBytes
        }
    }
    finally {
        $input.Stream.Dispose()
    }
}

function Read-ProductRoleFixtureManifest {
    param([Parameter(Mandatory = $true)][string]$FixtureRoot, [Parameter(Mandatory = $true)][string]$ManifestPath)

    $expectedPath = Join-Path $FixtureRoot 'product-role-fixtures.v1.json'
    if ([IO.Path]::GetFullPath($ManifestPath) -cne [IO.Path]::GetFullPath($expectedPath)) {
        throw 'Product role fixture manifest must use the fixed root-relative product-role-fixtures.v1.json path.'
    }
    $input = ProductionReleaseState\Open-ProductionReleaseInput -Path $expectedPath -Label 'Product role fixture manifest' -MaximumBytes $script:MaximumManifestBytes
    try {
        $bytes = ProductionReleaseState\Read-ProductionReleaseInputBytes -Descriptor $input -Label 'Product role fixture manifest'
        $value = ProductionReleaseState\ConvertFrom-StrictProductionJsonBytes -Bytes $bytes -Label 'Product role fixture manifest'
        ProductionReleaseState\Assert-ProductionReleaseInputStillLocked -Descriptor $input -Label 'Product role fixture manifest'
        return $value
    }
    finally {
        $input.Stream.Dispose()
    }
}

function Assert-ProductRoleFixtureArtifact {
    param(
        [Parameter(Mandatory = $true)]$Artifact,
        [Parameter(Mandatory = $true)][string]$FixtureRoot,
        [Parameter(Mandatory = $true)][string]$ExpectedRelativePath,
        [Parameter(Mandatory = $true)][string]$Label
    )

    Assert-ProductRoleFixtureExactMembers -Value $Artifact -Expected @('relativePath', 'sizeBytes', 'sha256', 'peContentSha256') -Label $Label
    $sizeBytes = Assert-ProductRoleFixtureInteger -Value $Artifact.sizeBytes -Label "$Label sizeBytes"
    if ($sizeBytes -le 0 -or $sizeBytes -gt $script:MaximumArtifactBytes) {
        throw "$Label sizeBytes is outside the artifact bound."
    }
    $sha256 = Assert-ProductRoleFixtureString -Value $Artifact.sha256 -Label "$Label sha256"
    $peContentSha256 = Assert-ProductRoleFixtureString -Value $Artifact.peContentSha256 -Label "$Label peContentSha256"
    Assert-ProductRoleFixtureHexSha256 -Value $sha256 -Label "$Label sha256"
    Assert-ProductRoleFixtureHexSha256 -Value $peContentSha256 -Label "$Label peContentSha256"
    return Resolve-ProductRoleFixtureContainedFile -FixtureRoot $FixtureRoot -RelativePath $Artifact.relativePath -ExpectedRelativePath $ExpectedRelativePath -Label $Label
}

function Get-ProductRoleFixtureRoleProfile {
    param([Parameter(Mandatory = $true)][string]$Edition, [Parameter(Mandatory = $true)][string]$Role)

    $matches = @($script:RoleProfiles | Where-Object { $_.Edition -ceq $Edition -and $_.Role -ceq $Role })
    if ($matches.Count -ne 1) {
        throw "Product role fixture uses unsupported role '$Edition/$Role'."
    }
    return $matches[0]
}

function Import-ProductRoleFixtureReleaseManifestSigner {
    param(
        [Parameter(Mandatory = $true)][string]$FixtureRoot,
        [Parameter(Mandatory = $true)][string]$ReleaseManifestKeyPath,
        [Parameter(Mandatory = $true)]$ReleaseManifestTrust
    )

    $expectedPath = Join-Path $FixtureRoot 'release-manifest-test-key.pk8'
    if ([IO.Path]::GetFullPath($ReleaseManifestKeyPath) -cne [IO.Path]::GetFullPath($expectedPath)) {
        throw 'Release-manifest test key must use the fixed root-relative release-manifest-test-key.pk8 path.'
    }
    $keyInput = ProductionReleaseState\Open-ProductionReleaseInput -Path $expectedPath -Label 'Release-manifest test key' -MaximumBytes $script:MaximumKeyBytes
    [byte[]]$rawKey = $null
    $signer = $null
    try {
        $rawKey = ProductionReleaseState\Read-ProductionReleaseInputBytes -Descriptor $keyInput -Label 'Release-manifest test key'
        $signer = [Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve+NamedCurves]::nistP256)
        [int]$bytesRead = 0
        try {
            $signer.ImportPkcs8PrivateKey($rawKey, [ref]$bytesRead)
        }
        catch {
            throw 'Release-manifest test key is not one P-256 PKCS#8 private key.'
        }
        if ($bytesRead -ne $rawKey.Length) {
            throw 'Release-manifest test key has trailing or incomplete PKCS#8 bytes.'
        }
        $public = $signer.ExportParameters($false)
        if ([string]$public.Curve.Oid.Value -cne '1.2.840.10045.3.1.7') {
            throw 'Release-manifest test key is not NIST P-256.'
        }
        if ($public.Q.X.Length -ne 32 -or $public.Q.Y.Length -ne 32 -or
            (ConvertTo-ProductRoleFixtureBase64Url -Bytes $public.Q.X) -cne [string]$ReleaseManifestTrust.x -or
            (ConvertTo-ProductRoleFixtureBase64Url -Bytes $public.Q.Y) -cne [string]$ReleaseManifestTrust.y) {
            throw 'Release-manifest test key public parameters differ from the fixture manifest trust key.'
        }
        ProductionReleaseState\Assert-ProductionReleaseInputStillLocked -Descriptor $keyInput -Label 'Release-manifest test key'
        $result = $signer
        $signer = $null
        return $result
    }
    finally {
        if ($null -ne $signer) {
            $signer.Dispose()
        }
        if ($null -ne $rawKey) {
            [Array]::Clear($rawKey, 0, $rawKey.Length)
        }
        $keyInput.Stream.Dispose()
    }
}

function Copy-ProductRoleFixtureArtifact {
    param(
        [Parameter(Mandatory = $true)][string]$SourcePath,
        [Parameter(Mandatory = $true)]$DeclaredArtifact,
        [Parameter(Mandatory = $true)][string]$DestinationPath,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $source = ProductionReleaseState\Open-ProductionReleaseInput -Path $SourcePath -Label $Label -MaximumBytes $script:MaximumArtifactBytes
    try {
        $bytes = ProductionReleaseState\Read-ProductionReleaseInputBytes -Descriptor $source -Label $Label
        $peContentSha256 = ProductionReleaseState\Get-PeContentSha256 -Bytes $bytes
        if ($source.SizeBytes -ne [int64]$DeclaredArtifact.sizeBytes -or
            $source.Sha256 -cne [string]$DeclaredArtifact.sha256 -or
            $peContentSha256 -cne [string]$DeclaredArtifact.peContentSha256) {
            throw "$Label differs from its declared full or PE-content identity."
        }
        ProductionReleaseState\Assert-ProductionReleaseInputStillLocked -Descriptor $source -Label $Label
        $destination = [IO.File]::Open($DestinationPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try {
            $destination.Write($bytes, 0, $bytes.Length)
            $destination.Flush($true)
        }
        finally {
            $destination.Dispose()
        }
        ProductionReleaseState\Assert-ProductionReleaseInputStillLocked -Descriptor $source -Label $Label
        $copied = Read-ProductRoleFixtureLockedInput -Path $DestinationPath -Label "$Label private copy" -MaximumBytes $script:MaximumArtifactBytes
        if ($copied.SizeBytes -ne $source.SizeBytes -or $copied.Sha256 -cne $source.Sha256 -or
            (ProductionReleaseState\Get-PeContentSha256 -Bytes $copied.Bytes) -cne $peContentSha256) {
            throw "$Label private copy differs from the held source bytes."
        }
        return [pscustomobject]@{ Path = $copied.Path; Sha256 = $copied.Sha256; PeContentSha256 = $peContentSha256; SizeBytes = $copied.SizeBytes }
    }
    finally {
        $source.Stream.Dispose()
    }
}

function New-ProductRoleFixtureManifestTemplate {
    $roles = foreach ($profile in $script:RoleProfiles) {
        $compatibility = if ($profile.Compatibility -ceq 'personal') {
            [ordered]@{ startupStubVersion = '1.2.0'; canonicalLowSFromSequence = 1 }
        }
        else {
            [ordered]@{ startupStubProtocol = 1 }
        }
        [ordered]@{
            edition = $profile.Edition
            role = $profile.Role
            fileName = $profile.FileName
            targetChannel = $profile.TargetChannel
            releaseCompatibility = $compatibility
            unsigned = [ordered]@{ relativePath = "unsigned/$($profile.Edition)/$($profile.FileName)"; sizeBytes = 0; sha256 = ('0' * 64); peContentSha256 = ('0' * 64) }
            signed = [ordered]@{ relativePath = "signed/$($profile.Edition)/$($profile.FileName)"; sizeBytes = 0; sha256 = ('0' * 64); peContentSha256 = ('0' * 64) }
        }
    }
    return [ordered]@{
        schemaVersion = 1
        fixtureType = $script:FixtureType
        releaseManifestTrust = [ordered]@{ algorithm = 'ES256'; purpose = 'release-manifest-signing'; keyId = $script:ReleaseManifestKeyId; x = 'REPLACE_WITH_PUBLIC_P256_X'; y = 'REPLACE_WITH_PUBLIC_P256_Y' }
        authenticodePolicy = [ordered]@{ signerSha256Thumbprint = ('0' * 64) }
        roles = @($roles)
    }
}

function Import-ProductRoleFixtureContract {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$FixtureRoot,
        [Parameter(Mandatory = $true)][string]$ManifestPath,
        [Parameter(Mandatory = $true)][string]$ReleaseManifestKeyPath,
        [Parameter(Mandatory = $true)][string]$DestinationRoot
    )

    foreach ($inputPath in @($FixtureRoot, $ManifestPath, $ReleaseManifestKeyPath, $DestinationRoot)) {
        if (-not [IO.Path]::IsPathFullyQualified($inputPath)) {
            throw 'Product role fixture root, manifest, key, and private destination paths must be absolute.'
        }
    }
    $destinationFull = [IO.Path]::GetFullPath($DestinationRoot)
    if (Test-Path -LiteralPath $destinationFull) {
        throw 'Product role fixture private destination root must be create-only and absent.'
    }
    $destinationParent = [IO.Path]::GetDirectoryName($destinationFull)
    $destinationParentLease = ProductionReleaseState\Open-ProductionReleaseDirectoryLease -Path $destinationParent -Label 'Product role fixture private destination parent'
    $fixtureLease = $null
    $signer = $null
    try {
        $fixtureLease = ProductionReleaseState\Open-ProductionReleaseDirectoryLease -Path $FixtureRoot -Label 'Product role fixture root'
        $fixtureRootFull = [string]$fixtureLease.Path
        $manifest = Read-ProductRoleFixtureManifest -FixtureRoot $fixtureRootFull -ManifestPath $ManifestPath
        Assert-ProductRoleFixtureExactMembers -Value $manifest -Expected @('schemaVersion', 'fixtureType', 'releaseManifestTrust', 'authenticodePolicy', 'roles') -Label 'Product role fixture manifest'
        if ((Assert-ProductRoleFixtureInteger -Value $manifest.schemaVersion -Label 'Product role fixture manifest schemaVersion') -ne 1 -or
            (Assert-ProductRoleFixtureString -Value $manifest.fixtureType -Label 'Product role fixture manifest fixtureType') -cne $script:FixtureType) {
            throw 'Product role fixture manifest schemaVersion or fixtureType is invalid.'
        }
        Assert-ProductRoleFixtureExactMembers -Value $manifest.releaseManifestTrust -Expected @('algorithm', 'purpose', 'keyId', 'x', 'y') -Label 'Product role fixture releaseManifestTrust'
        if ((Assert-ProductRoleFixtureString -Value $manifest.releaseManifestTrust.algorithm -Label 'Product role fixture releaseManifestTrust algorithm') -cne 'ES256' -or
            (Assert-ProductRoleFixtureString -Value $manifest.releaseManifestTrust.purpose -Label 'Product role fixture releaseManifestTrust purpose') -cne 'release-manifest-signing' -or
            (Assert-ProductRoleFixtureString -Value $manifest.releaseManifestTrust.keyId -Label 'Product role fixture releaseManifestTrust keyId') -cne $script:ReleaseManifestKeyId) {
            throw 'Product role fixture releaseManifestTrust has an unsupported fixed contract.'
        }
        [void](ConvertFrom-ProductRoleFixtureP256Coordinate -Value (Assert-ProductRoleFixtureString -Value $manifest.releaseManifestTrust.x -Label 'Product role fixture releaseManifestTrust.x') -Label 'Product role fixture releaseManifestTrust.x')
        [void](ConvertFrom-ProductRoleFixtureP256Coordinate -Value (Assert-ProductRoleFixtureString -Value $manifest.releaseManifestTrust.y -Label 'Product role fixture releaseManifestTrust.y') -Label 'Product role fixture releaseManifestTrust.y')
        Assert-ProductRoleFixtureExactMembers -Value $manifest.authenticodePolicy -Expected @('signerSha256Thumbprint') -Label 'Product role fixture authenticodePolicy'
        Assert-ProductRoleFixtureHexSha256 -Value (Assert-ProductRoleFixtureString -Value $manifest.authenticodePolicy.signerSha256Thumbprint -Label 'Product role fixture signerSha256Thumbprint') -Label 'Product role fixture signerSha256Thumbprint'
        if (@($manifest.roles).Count -ne $script:RoleProfiles.Count) {
            throw 'Product role fixture manifest must contain exactly eight role profiles.'
        }

        $validatedRoles = [Collections.Generic.List[object]]::new()
        $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($role in @($manifest.roles)) {
            Assert-ProductRoleFixtureExactMembers -Value $role -Expected @('edition', 'role', 'fileName', 'targetChannel', 'releaseCompatibility', 'unsigned', 'signed') -Label 'Product role fixture role'
            $edition = Assert-ProductRoleFixtureString -Value $role.edition -Label 'Product role fixture role edition'
            $roleName = Assert-ProductRoleFixtureString -Value $role.role -Label 'Product role fixture role role'
            $fileName = Assert-ProductRoleFixtureString -Value $role.fileName -Label 'Product role fixture role fileName'
            $targetChannel = Assert-ProductRoleFixtureString -Value $role.targetChannel -Label 'Product role fixture role targetChannel'
            $profile = Get-ProductRoleFixtureRoleProfile -Edition $edition -Role $roleName
            $identity = $edition + [char]0 + $roleName
            if (-not $seen.Add($identity) -or $fileName -cne [string]$profile.FileName -or $targetChannel -cne [string]$profile.TargetChannel) {
                throw "Product role fixture role '$identity' is duplicated or has a mismatched fixed profile."
            }
            if ($profile.Compatibility -ceq 'personal') {
                Assert-ProductRoleFixtureExactMembers -Value $role.releaseCompatibility -Expected @('startupStubVersion', 'canonicalLowSFromSequence') -Label "Product role fixture $identity releaseCompatibility"
                if ((Assert-ProductRoleFixtureString -Value $role.releaseCompatibility.startupStubVersion -Label "Product role fixture $identity startupStubVersion") -cne '1.2.0' -or
                    (Assert-ProductRoleFixtureInteger -Value $role.releaseCompatibility.canonicalLowSFromSequence -Label "Product role fixture $identity canonicalLowSFromSequence") -ne 1) {
                    throw "Product role fixture $identity has an invalid Personal compatibility profile."
                }
            }
            else {
                Assert-ProductRoleFixtureExactMembers -Value $role.releaseCompatibility -Expected @('startupStubProtocol') -Label "Product role fixture $identity releaseCompatibility"
                if ((Assert-ProductRoleFixtureInteger -Value $role.releaseCompatibility.startupStubProtocol -Label "Product role fixture $identity startupStubProtocol") -ne 1) {
                    throw "Product role fixture $identity has an invalid Enterprise compatibility profile."
                }
            }
            $unsignedPath = Assert-ProductRoleFixtureArtifact -Artifact $role.unsigned -FixtureRoot $fixtureRootFull -ExpectedRelativePath "unsigned/$($profile.Edition)/$($profile.FileName)" -Label "Product role fixture $identity unsigned"
            $signedPath = Assert-ProductRoleFixtureArtifact -Artifact $role.signed -FixtureRoot $fixtureRootFull -ExpectedRelativePath "signed/$($profile.Edition)/$($profile.FileName)" -Label "Product role fixture $identity signed"
            $validatedRoles.Add([pscustomobject]@{ Profile = $profile; Manifest = $role; UnsignedPath = $unsignedPath; SignedPath = $signedPath })
        }
        if ($seen.Count -ne $script:RoleProfiles.Count) {
            throw 'Product role fixture manifest does not bind every required role exactly once.'
        }

        $signer = Import-ProductRoleFixtureReleaseManifestSigner -FixtureRoot $fixtureRootFull -ReleaseManifestKeyPath $ReleaseManifestKeyPath -ReleaseManifestTrust $manifest.releaseManifestTrust
        [IO.Directory]::CreateDirectory($destinationFull) | Out-Null
        [IO.Directory]::CreateDirectory((Join-Path $destinationFull 'unsigned')) | Out-Null
        [IO.Directory]::CreateDirectory((Join-Path $destinationFull 'signed')) | Out-Null
        $copiedRoles = [Collections.Generic.List[object]]::new()
        foreach ($validated in $validatedRoles) {
            $profile = $validated.Profile
            $unsignedDestination = Join-Path (Join-Path $destinationFull 'unsigned') $profile.FileName
            $signedDestination = Join-Path (Join-Path $destinationFull 'signed') $profile.FileName
            $unsignedCopy = Copy-ProductRoleFixtureArtifact -SourcePath $validated.UnsignedPath -DeclaredArtifact $validated.Manifest.unsigned -DestinationPath $unsignedDestination -Label "Product role fixture $($profile.Edition)/$($profile.Role) unsigned"
            $signedCopy = Copy-ProductRoleFixtureArtifact -SourcePath $validated.SignedPath -DeclaredArtifact $validated.Manifest.signed -DestinationPath $signedDestination -Label "Product role fixture $($profile.Edition)/$($profile.Role) signed"
            if ($unsignedCopy.PeContentSha256 -cne $signedCopy.PeContentSha256) {
                throw "Product role fixture $($profile.Edition)/$($profile.Role) signed PE content differs from its unsigned role input."
            }
            $copiedRoles.Add([pscustomobject]@{
                Edition = $profile.Edition
                Role = $profile.Role
                FileName = $profile.FileName
                TargetChannel = $profile.TargetChannel
                ReleaseCompatibility = $validated.Manifest.releaseCompatibility
                UnsignedPath = $unsignedCopy.Path
                SignedPath = $signedCopy.Path
                UnsignedSha256 = $unsignedCopy.Sha256
                SignedSha256 = $signedCopy.Sha256
                PeContentSha256 = $unsignedCopy.PeContentSha256
            })
        }
        $result = [pscustomobject]@{
            FixtureRoot = $fixtureRootFull
            SignerSha256 = [string]$manifest.authenticodePolicy.signerSha256Thumbprint
            ReleaseManifestTrust = $manifest.releaseManifestTrust
            ReleaseManifestSigner = $signer
            Roles = @($copiedRoles)
        }
        $signer = $null
        return $result
    }
    finally {
        if ($null -ne $signer) {
            $signer.Dispose()
        }
        if ($null -ne $fixtureLease) {
            $fixtureLease.Handle.Dispose()
        }
        $destinationParentLease.Handle.Dispose()
    }
}

Export-ModuleMember -Function @(
    'Import-ProductRoleFixtureContract',
    'New-ProductRoleFixtureManifestTemplate'
)
