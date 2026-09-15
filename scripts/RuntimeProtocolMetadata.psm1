Set-StrictMode -Version Latest

$script:RuntimeMetadataFileName = 'ensou-runtime-metadata.json'
$script:MaximumRuntimeMetadataBytes = 4096
$script:LegacyCleanRootV1 = 'legacy-clean-root-v1'
$script:BrowserLaunchCookieV1 = 'browser-launch-cookie-v1'
$script:PersonalManagedUpdateV1 = 'personal-web-v1'
$script:EnterpriseDirectLocalV1 = 'enterprise-direct-local-v1'
$script:EnterpriseDirectLocalProfile = 'enterprise-direct-local'

function New-RuntimeProtocolMetadataBytes {
    [CmdletBinding()]
    param(
        [ValidateSet('legacy-clean-root-v1', 'browser-launch-cookie-v1')]
        [string]$WebAuthProtocol = 'legacy-clean-root-v1',
        [switch]$PersonalManagedUpdate,
        [switch]$EnterpriseDirectLocal
    )
    if ($WebAuthProtocol -cnotin @($script:LegacyCleanRootV1, $script:BrowserLaunchCookieV1)) {
        throw 'Runtime metadata declares an unsupported Web authentication protocol.'
    }
    if ($PersonalManagedUpdate -and $WebAuthProtocol -cne $script:BrowserLaunchCookieV1) {
        throw 'Personal managed-update metadata requires browser-launch-cookie-v1.'
    }
    if ($EnterpriseDirectLocal -and ($PersonalManagedUpdate -or $WebAuthProtocol -cne $script:BrowserLaunchCookieV1)) {
        throw 'Enterprise direct-local metadata requires browser-launch-cookie-v1 and excludes Personal managed-update.'
    }
    $document = [ordered]@{ schemaVersion = if ($EnterpriseDirectLocal) { 3 } elseif ($PersonalManagedUpdate) { 2 } else { 1 }; webAuthProtocol = $WebAuthProtocol }
    if ($PersonalManagedUpdate) { $document.managedUpdateProtocol = $script:PersonalManagedUpdateV1 }
    if ($EnterpriseDirectLocal) {
        $document.managedUpdateProtocol = $script:EnterpriseDirectLocalV1
        $document.runtimeProfile = $script:EnterpriseDirectLocalProfile
    }
    $json = $document | ConvertTo-Json -Compress
    [Text.UTF8Encoding]::new($false).GetBytes($json)
}

function Assert-RuntimeMetadataDirectory {
    param([Parameter(Mandatory)][string]$RuntimeDirectory)
    if (![IO.Path]::IsPathFullyQualified($RuntimeDirectory)) { throw 'Runtime metadata root must be absolute.' }
    $root = [IO.Path]::GetFullPath($RuntimeDirectory)
    if (!(Test-Path -LiteralPath $root -PathType Container)) { throw 'Runtime metadata root directory is missing.' }
    $item = Get-Item -LiteralPath $root -Force
    while ($null -ne $item) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Runtime metadata root or ancestor may not be a link.' }
        $item = $item.Parent
    }
    $root
}

function Read-RuntimeProtocolMetadata {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$RuntimeDirectory)
    $root = Assert-RuntimeMetadataDirectory $RuntimeDirectory
    $path = [IO.Path]::GetFullPath((Join-Path $root $script:RuntimeMetadataFileName))
    if ([IO.Path]::GetDirectoryName($path) -ne $root) { throw 'Runtime metadata path escaped its root.' }
    $metadataItem = $null
    try { $metadataItem = Get-Item -LiteralPath $path -Force -ErrorAction Stop }
    catch [System.Management.Automation.ItemNotFoundException] { }
    if ($null -eq $metadataItem) {
        return [pscustomobject]@{ SchemaVersion = 1; WebAuthProtocol = $script:LegacyCleanRootV1; ManagedUpdateProtocol = $null; SupportsPersonalManagedUpdate = $false; RuntimeProfile = $null; SupportsEnterpriseDirectLocal = $false }
    }
    $file = $metadataItem
    if ($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Length -le 0 -or $file.Length -gt $script:MaximumRuntimeMetadataBytes) { throw 'Runtime metadata must be a bounded regular file.' }
    $bytes = [IO.File]::ReadAllBytes($path)
    $document = $null
    try {
        $text = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
        $document = [Text.Json.JsonDocument]::Parse($text, [Text.Json.JsonDocumentOptions]@{ AllowTrailingCommas = $false; CommentHandling = [Text.Json.JsonCommentHandling]::Disallow; MaxDepth = 8 })
        $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($property in $document.RootElement.EnumerateObject()) { if (!$names.Add($property.Name)) { throw 'Runtime metadata contains duplicate properties.' } }
        $schema = $document.RootElement.GetProperty('schemaVersion').GetInt32()
        $web = $document.RootElement.GetProperty('webAuthProtocol').GetString()
        if ($schema -eq 1) {
            if ($names.Count -cne 2 -or $web -cnotin @($script:LegacyCleanRootV1, $script:BrowserLaunchCookieV1)) { throw 'Runtime metadata schema 1 is invalid.' }
            return [pscustomobject]@{ SchemaVersion = 1; WebAuthProtocol = $web; ManagedUpdateProtocol = $null; SupportsPersonalManagedUpdate = $false; RuntimeProfile = $null; SupportsEnterpriseDirectLocal = $false }
        }
        if ($schema -eq 2) {
            $managed = $document.RootElement.GetProperty('managedUpdateProtocol').GetString()
            if ($names.Count -cne 3 -or $web -cne $script:BrowserLaunchCookieV1 -or $managed -cne $script:PersonalManagedUpdateV1) { throw 'Personal managed-update runtime metadata is invalid.' }
            return [pscustomobject]@{ SchemaVersion = 2; WebAuthProtocol = $web; ManagedUpdateProtocol = $managed; SupportsPersonalManagedUpdate = $true; RuntimeProfile = $null; SupportsEnterpriseDirectLocal = $false }
        }
        if ($schema -eq 3) {
            $managed = $document.RootElement.GetProperty('managedUpdateProtocol').GetString()
            $profile = $document.RootElement.GetProperty('runtimeProfile').GetString()
            if ($names.Count -cne 4 -or $web -cne $script:BrowserLaunchCookieV1 -or $managed -cne $script:EnterpriseDirectLocalV1 -or $profile -cne $script:EnterpriseDirectLocalProfile) { throw 'Enterprise direct-local runtime metadata is invalid.' }
            return [pscustomobject]@{ SchemaVersion = 3; WebAuthProtocol = $web; ManagedUpdateProtocol = $managed; SupportsPersonalManagedUpdate = $false; RuntimeProfile = $profile; SupportsEnterpriseDirectLocal = $true }
        }
        throw 'Runtime metadata schema is unsupported.'
    } catch [Text.Json.JsonException] { throw 'Runtime metadata JSON is invalid.' }
    finally { if ($null -ne $document) { $document.Dispose() }; [Array]::Clear($bytes) }
}

function Write-RuntimeProtocolMetadata {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RuntimeDirectory,
        [ValidateSet('legacy-clean-root-v1', 'browser-launch-cookie-v1')]
        [string]$WebAuthProtocol = 'legacy-clean-root-v1',
        [switch]$PersonalManagedUpdate,
        [switch]$EnterpriseDirectLocal
    )
    $root = Assert-RuntimeMetadataDirectory $RuntimeDirectory
    $path = Join-Path $root $script:RuntimeMetadataFileName
    $bytes = [byte[]](New-RuntimeProtocolMetadataBytes -WebAuthProtocol $WebAuthProtocol -PersonalManagedUpdate:$PersonalManagedUpdate -EnterpriseDirectLocal:$EnterpriseDirectLocal)
    $stream = [IO.FileStream]::new($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($bytes); $stream.Flush($true) }
    finally { $stream.Dispose() }
    Read-RuntimeProtocolMetadata $root
}

Export-ModuleMember -Function New-RuntimeProtocolMetadataBytes, Read-RuntimeProtocolMetadata, Write-RuntimeProtocolMetadata
