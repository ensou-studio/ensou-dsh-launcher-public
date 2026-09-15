#requires -Version 7.2

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$DirectLocalMetadataPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$validatorPath = Join-Path $PSScriptRoot 'Test-SourceRuntimeMetadata.ps1'
$legacyMetadataPath = Join-Path $PSScriptRoot '..\examples\source-runtime.metadata.json'
$directMetadataPath = (Resolve-Path -LiteralPath $DirectLocalMetadataPath -ErrorAction Stop).Path
$directText = Get-Content -Raw -LiteralPath $directMetadataPath
$direct = $directText | ConvertFrom-Json -Depth 64
$testParent = [IO.Path]::TrimEndingDirectorySeparator([IO.Path]::GetFullPath([IO.Path]::GetTempPath()))
$testLeaf = 'ensou-source-runtime-version-dispatch-' + [Guid]::NewGuid().ToString('N')
$testRoot = [IO.Path]::GetFullPath((Join-Path $testParent $testLeaf))
if (-not $testRoot.StartsWith($testParent + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase) -or
    [IO.Path]::GetFileName($testRoot) -cne $testLeaf) { throw 'Fixture root escaped its temporary ownership boundary.' }
[IO.Directory]::CreateDirectory($testRoot) | Out-Null
$script:checks = 0

function Write-TestMetadata([string]$Name, [string]$Json) {
    $path = Join-Path $testRoot $Name
    [IO.File]::WriteAllText($path, $Json, [Text.UTF8Encoding]::new($false))
    return $path
}

function ConvertTo-TestJson($Value) {
    return $Value | ConvertTo-Json -Depth 64
}

function Assert-Rejected(
    [string]$Name,
    [scriptblock]$Body,
    [string]$ExpectedMessage = ''
) {
    $rejected = $false
    try {
        & $Body
    }
    catch {
        $rejected = $true
        if ($ExpectedMessage -and $_.Exception.Message -cne $ExpectedMessage) {
            throw "Source-runtime metadata validator rejected $Name for the wrong reason: $($_.Exception.Message)"
        }
    }
    if (-not $rejected) {
        throw "Source-runtime metadata validator accepted $Name."
    }
    $script:checks++
}

try {
    $legacy = & $validatorPath -MetadataPath $legacyMetadataPath
    if ([int]$legacy.schemaVersion -ne 2 -or
        [string]$legacy.artifactType -cne 'ensou-dsh-enterprise-managed-source-runtime') {
        throw 'Controlled production v2 metadata did not retain the legacy contract.'
    }
    $script:checks++

    Assert-Rejected 'direct-local v3 metadata without explicit profile opt-in' {
        & $validatorPath -MetadataPath $directMetadataPath | Out-Null
    } 'Source-runtime metadata schemaVersion 3 does not match expected runtime profile enterprise-managed.'

    Assert-Rejected 'legacy v2 metadata under explicit direct-local profile' {
        & $validatorPath `
            -MetadataPath $legacyMetadataPath `
            -ExpectedRuntimeProfile enterprise-direct-local | Out-Null
    } 'Source-runtime metadata schemaVersion 2 does not match expected runtime profile enterprise-direct-local.'

    $admittedDirect = & $validatorPath `
        -MetadataPath $directMetadataPath `
        -ExpectedRuntimeProfile enterprise-direct-local `
        -ExpectedReleaseId ([string]$direct.releaseId) `
        -ExpectedArtifactFileName ([string]$direct.artifact.fileName) `
        -ExpectedArtifactSha256 ([string]$direct.artifact.sha256)
    if ([int]$admittedDirect.schemaVersion -ne 3 -or
        [string]$admittedDirect.runtimeProfile -cne 'enterprise-direct-local' -or
        [string]$admittedDirect.managedUpdateProtocol -cne 'enterprise-direct-local-v1') {
        throw 'Production direct-local v3 metadata lost its exact profile identity.'
    }
    $script:checks++

    $unknown = $directText | ConvertFrom-Json -Depth 64
    $unknown.schemaVersion = 4
    $unknownPath = Write-TestMetadata 'unknown.metadata.json' (ConvertTo-TestJson $unknown)
    Assert-Rejected 'an unknown schema version' {
        & $validatorPath `
            -MetadataPath $unknownPath `
            -ExpectedRuntimeProfile enterprise-direct-local | Out-Null
    } 'Unsupported source-runtime metadata schemaVersion: 4.'

    $lab = $directText | ConvertFrom-Json -Depth 64
    $lab.releaseId = 'lab-direct-local-version-dispatch'
    $lab.promotionEligible = $false
    $lab.artifact.fileName = 'EnsouDshRuntime-lab-direct-local-version-dispatch-win-x64.zip'
    $labPath = Write-TestMetadata 'lab.metadata.json' (ConvertTo-TestJson $lab)
    Assert-Rejected 'promotionEligible=false Lab metadata by default' {
        & $validatorPath `
            -MetadataPath $labPath `
            -ExpectedRuntimeProfile enterprise-direct-local | Out-Null
    }

    $mixed = $directText | ConvertFrom-Json -Depth 64
    $mixed.schemaVersion = 2
    $mixedPath = Write-TestMetadata 'mixed-version.metadata.json' (ConvertTo-TestJson $mixed)
    Assert-Rejected 'direct-local members under schema version 2' {
        & $validatorPath `
            -MetadataPath $mixedPath `
            -ExpectedRuntimeProfile enterprise-direct-local | Out-Null
    }

    $changedPatch = $directText | ConvertFrom-Json -Depth 64
    $changedPatch.managedPatch.patchSha256 = '0' * 64
    $changedPatchPath = Write-TestMetadata 'changed-patch.metadata.json' (
        ConvertTo-TestJson $changedPatch)
    Assert-Rejected 'a changed managed patch digest' {
        & $validatorPath `
            -MetadataPath $changedPatchPath `
            -ExpectedRuntimeProfile enterprise-direct-local | Out-Null
    }

    $smokeFalse = $directText | ConvertFrom-Json -Depth 64
    $smokeFalse.verification.directLocalExtractedSmoke.exactChildExited = $false
    $smokeFalsePath = Write-TestMetadata 'smoke-false.metadata.json' (
        ConvertTo-TestJson $smokeFalse)
    Assert-Rejected 'a false extracted-runtime smoke invariant' {
        & $validatorPath `
            -MetadataPath $smokeFalsePath `
            -ExpectedRuntimeProfile enterprise-direct-local | Out-Null
    }

    Assert-Rejected 'an expected artifact hash mismatch' {
        & $validatorPath `
            -MetadataPath $directMetadataPath `
            -ExpectedRuntimeProfile enterprise-direct-local `
            -ExpectedArtifactSha256 ('0' * 64) | Out-Null
    }

    $duplicateVersion = $directText -replace '^[\s\r\n]*\{', "{`n  `"schemaVersion`": 3,"
    if ($duplicateVersion -ceq $directText) {
        throw 'Could not construct duplicate schemaVersion metadata.'
    }
    $duplicateVersionPath = Write-TestMetadata 'duplicate-version.metadata.json' $duplicateVersion
    Assert-Rejected 'duplicate schemaVersion members' {
        & $validatorPath `
            -MetadataPath $duplicateVersionPath `
            -ExpectedRuntimeProfile enterprise-direct-local | Out-Null
    }

    $profileMarker = '"runtimeProfile": "enterprise-direct-local",'
    $duplicateProfile = $directText.Replace(
        $profileMarker,
        $profileMarker + "`n  `"runtimeProfile`": `"enterprise-direct-local`",",
        [StringComparison]::Ordinal)
    if ($duplicateProfile -ceq $directText) {
        throw 'Could not construct duplicate runtimeProfile metadata.'
    }
    $duplicateProfilePath = Write-TestMetadata 'duplicate-profile.metadata.json' $duplicateProfile
    Assert-Rejected 'duplicate runtimeProfile members' {
        & $validatorPath `
            -MetadataPath $duplicateProfilePath `
            -ExpectedRuntimeProfile enterprise-direct-local | Out-Null
    }

    $wrongProfile = $directText | ConvertFrom-Json -Depth 64
    $wrongProfile.runtimeProfile = 'enterprise-managed'
    $wrongProfilePath = Write-TestMetadata 'wrong-profile.metadata.json' (
        ConvertTo-TestJson $wrongProfile)
    Assert-Rejected 'a mixed direct-local schema and managed runtime profile' {
        & $validatorPath `
            -MetadataPath $wrongProfilePath `
            -ExpectedRuntimeProfile enterprise-direct-local | Out-Null
    }

    Write-Output "PASS Source-runtime metadata version dispatch: $script:checks checks."
}
finally {
    if (Test-Path -LiteralPath $testRoot) {
        $ownedRoot = Get-Item -LiteralPath $testRoot -Force
        if (-not $ownedRoot.PSIsContainer -or ($ownedRoot.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            [IO.Path]::GetDirectoryName($ownedRoot.FullName) -cne $testParent -or
            [IO.Path]::GetFileName($ownedRoot.FullName) -cne $testLeaf) {
            throw 'Refusing to remove an unowned or linked metadata fixture.'
        }
        Remove-Item -LiteralPath $ownedRoot.FullName -Recurse -Force
    }
}
