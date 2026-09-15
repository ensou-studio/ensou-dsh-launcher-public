#requires -Version 7.4
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'RuntimeProtocolMetadata.psm1') -Force
$roots = @()
$rejectionChecks = 0
function New-TestRoot {
    $path = Join-Path $PSScriptRoot ('.runtime-metadata-test-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $path | Out-Null
    $script:roots += $path
    $path
}
function Assert-Throws([scriptblock]$Action) { try { & $Action } catch { $script:rejectionChecks++; return }; throw 'Expected metadata validation failure.' }
try {
    Assert-Throws { Read-RuntimeProtocolMetadata (Join-Path $PSScriptRoot '.runtime-metadata-missing') }
    $legacyRoot = New-TestRoot
    $legacy = Write-RuntimeProtocolMetadata $legacyRoot
    if ($legacy.SchemaVersion -ne 1 -or $legacy.WebAuthProtocol -cne 'legacy-clean-root-v1' -or $legacy.SupportsPersonalManagedUpdate) { throw 'Legacy metadata contract failed.' }
    $browserRoot = New-TestRoot
    $browser = Write-RuntimeProtocolMetadata $browserRoot -WebAuthProtocol 'browser-launch-cookie-v1'
    if ($browser.SchemaVersion -ne 1 -or $browser.WebAuthProtocol -cne 'browser-launch-cookie-v1') { throw 'Browser schema 1 contract failed.' }
    $personalRoot = New-TestRoot
    $personal = Write-RuntimeProtocolMetadata $personalRoot -WebAuthProtocol 'browser-launch-cookie-v1' -PersonalManagedUpdate
    if ($personal.SchemaVersion -ne 2 -or !$personal.SupportsPersonalManagedUpdate -or $personal.ManagedUpdateProtocol -cne 'personal-web-v1') { throw 'Personal schema 2 contract failed.' }
    if ($legacy.SupportsEnterpriseDirectLocal -or $browser.SupportsEnterpriseDirectLocal -or $personal.SupportsEnterpriseDirectLocal) { throw 'Older metadata must not admit Enterprise direct-local.' }
    $directRoot = New-TestRoot
    $direct = Write-RuntimeProtocolMetadata $directRoot -WebAuthProtocol 'browser-launch-cookie-v1' -EnterpriseDirectLocal
    if ($direct.SchemaVersion -ne 3 -or !$direct.SupportsEnterpriseDirectLocal -or $direct.SupportsPersonalManagedUpdate -or $direct.ManagedUpdateProtocol -cne 'enterprise-direct-local-v1' -or $direct.RuntimeProfile -cne 'enterprise-direct-local') { throw 'Enterprise direct-local schema 3 contract failed.' }
    $directJson = [IO.File]::ReadAllText((Join-Path $directRoot 'ensou-runtime-metadata.json'))
    if ($directJson -cne '{"schemaVersion":3,"webAuthProtocol":"browser-launch-cookie-v1","managedUpdateProtocol":"enterprise-direct-local-v1","runtimeProfile":"enterprise-direct-local"}') { throw 'Enterprise direct-local bytes are not canonical.' }
    Assert-Throws { New-RuntimeProtocolMetadataBytes -EnterpriseDirectLocal }
    Assert-Throws { New-RuntimeProtocolMetadataBytes -WebAuthProtocol 'browser-launch-cookie-v1' -PersonalManagedUpdate -EnterpriseDirectLocal }
    Assert-Throws { Write-RuntimeProtocolMetadata $directRoot -WebAuthProtocol 'browser-launch-cookie-v1' -EnterpriseDirectLocal }
    Assert-Throws { New-RuntimeProtocolMetadataBytes -PersonalManagedUpdate }
    Assert-Throws { New-RuntimeProtocolMetadataBytes -WebAuthProtocol 'LEGACY-CLEAN-ROOT-V1' }
    Assert-Throws { Write-RuntimeProtocolMetadata $legacyRoot }
    $directoryRoot = New-TestRoot
    New-Item -ItemType Directory -Path (Join-Path $directoryRoot 'ensou-runtime-metadata.json') | Out-Null
    Assert-Throws { Read-RuntimeProtocolMetadata $directoryRoot }
    Assert-Throws { Write-RuntimeProtocolMetadata $directoryRoot }
    $linkTarget = New-TestRoot
    $link = Join-Path $PSScriptRoot ('.runtime-metadata-link-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Junction -Path $link -Target $linkTarget | Out-Null
    try {
        Assert-Throws { Read-RuntimeProtocolMetadata $link }
        Assert-Throws { Write-RuntimeProtocolMetadata $link }
    } finally {
        $linkFull = [IO.Path]::GetFullPath($link)
        if ([IO.Path]::GetDirectoryName($linkFull) -cne [IO.Path]::GetFullPath($PSScriptRoot) -or
            [IO.Path]::GetFileName($linkFull) -cnotmatch '^\.runtime-metadata-link-[a-f0-9]{32}$' -or
            !((Get-Item -LiteralPath $linkFull -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Test link cleanup target differs.' }
        Remove-Item -LiteralPath $linkFull -Force
    }
    $schemaValidationRoot = New-TestRoot
    foreach ($invalidDirect in @(
        $directJson.Replace('"enterprise-direct-local-v1"', '"personal-web-v1"'),
        $directJson.Replace('"enterprise-direct-local"', '"enterprise-managed"'),
        $directJson.Replace('"browser-launch-cookie-v1"', '"legacy-clean-root-v1"'),
        $directJson.Replace(',"runtimeProfile":"enterprise-direct-local"', ''),
        $directJson.Replace('}', ',"extra":true}'),
        $directJson.Replace('}', ',"runtimeProfile":"enterprise-direct-local"}'),
        $directJson.Replace('"enterprise-direct-local"', 'null'),
        $directJson.Replace('"enterprise-direct-local"', '123'),
        $directJson.Replace('"enterprise-direct-local"', '"ENTERPRISE-DIRECT-LOCAL"'),
        $directJson.Replace('"schemaVersion":3', '"schemaVersion":4')
    )) {
        [IO.File]::WriteAllText((Join-Path $schemaValidationRoot 'ensou-runtime-metadata.json'), $invalidDirect, [Text.UTF8Encoding]::new($false))
        Assert-Throws { Read-RuntimeProtocolMetadata $schemaValidationRoot }
    }
    [IO.File]::WriteAllText((Join-Path $schemaValidationRoot 'ensou-runtime-metadata.json'), '{"schemaVersion":0,"webAuthProtocol":"legacy-clean-root-v1"}', [Text.UTF8Encoding]::new($false)); Assert-Throws { Read-RuntimeProtocolMetadata $schemaValidationRoot }
    [IO.File]::WriteAllText((Join-Path $schemaValidationRoot 'ensou-runtime-metadata.json'), '{"schemaVersion":3,"webAuthProtocol":"legacy-clean-root-v1"}', [Text.UTF8Encoding]::new($false)); Assert-Throws { Read-RuntimeProtocolMetadata $schemaValidationRoot }
    [IO.File]::WriteAllText((Join-Path $schemaValidationRoot 'ensou-runtime-metadata.json'), '{"schemaVersion":1}', [Text.UTF8Encoding]::new($false)); Assert-Throws { Read-RuntimeProtocolMetadata $schemaValidationRoot }
    [IO.File]::WriteAllText((Join-Path $schemaValidationRoot 'ensou-runtime-metadata.json'), '{"schemaVersion":2,"webAuthProtocol":"browser-launch-cookie-v1"}', [Text.UTF8Encoding]::new($false)); Assert-Throws { Read-RuntimeProtocolMetadata $schemaValidationRoot }
    [IO.File]::WriteAllText((Join-Path $legacyRoot 'ensou-runtime-metadata.json'), '{"schemaVersion":1,"webAuthProtocol":"legacy-clean-root-v1","extra":1}', [Text.UTF8Encoding]::new($false)); Assert-Throws { Read-RuntimeProtocolMetadata $legacyRoot }
    [IO.File]::WriteAllText((Join-Path $legacyRoot 'ensou-runtime-metadata.json'), '{"schemaVersion":1,"webAuthProtocol":"legacy-clean-root-v1","webAuthProtocol":"browser-launch-cookie-v1"}', [Text.UTF8Encoding]::new($false)); Assert-Throws { Read-RuntimeProtocolMetadata $legacyRoot }
    [IO.File]::WriteAllBytes((Join-Path $legacyRoot 'ensou-runtime-metadata.json'), [byte[]](0xC3, 0x28)); Assert-Throws { Read-RuntimeProtocolMetadata $legacyRoot }
    [IO.File]::WriteAllBytes((Join-Path $legacyRoot 'ensou-runtime-metadata.json'), (New-Object byte[] 4097)); Assert-Throws { Read-RuntimeProtocolMetadata $legacyRoot }
    [pscustomobject]@{ status = 'PASS'; roundTrips = 4; rejectionChecks = $rejectionChecks; scope = 'RUNTIME_PROTOCOL_METADATA_PURE_CONTRACT_ONLY' } | ConvertTo-Json -Compress
} finally {
    foreach ($ownedRoot in $roots) {
        $ownedFull = [IO.Path]::GetFullPath($ownedRoot)
        if ([IO.Path]::GetDirectoryName($ownedFull) -cne [IO.Path]::GetFullPath($PSScriptRoot) -or
            [IO.Path]::GetFileName($ownedFull) -cnotmatch '^\.runtime-metadata-test-[a-f0-9]{32}$') { throw 'Test cleanup target escaped its scope.' }
        if (Test-Path -LiteralPath $ownedFull) {
            if ((Get-Item -LiteralPath $ownedFull -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Test cleanup root became linked.' }
            Remove-Item -LiteralPath $ownedFull -Recurse -Force
        }
    }
}
