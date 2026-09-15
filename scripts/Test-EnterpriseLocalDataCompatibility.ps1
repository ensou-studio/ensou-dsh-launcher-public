#requires -Version 7.4

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $SourceRuntimeArchivePath,

    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9A-Fa-f]{64}$')]
    [string] $SourceRuntimeSha256,

    [Parameter(Mandatory)]
    [string] $TargetRuntimeArchivePath,

    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9A-Fa-f]{64}$')]
    [string] $TargetRuntimeSha256,

    [Parameter(Mandatory)]
    [string] $EvidenceRoot,

    [ValidateRange(10, 180)]
    [int] $BootTimeoutSeconds = 60,

    [switch] $KeepWorkingDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

$script:Utf8NoBom = [System.Text.UTF8Encoding]::new($false)
$script:TranscriptPath = $null
$script:TranscriptSequence = 0
$script:EvidenceRootFull = $null
$script:WorkRoot = $null

function Write-Utf8NoBom {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Text
    )

    $parent = [System.IO.Path]::GetDirectoryName($Path)
    if (-not [string]::IsNullOrEmpty($parent)) {
        [System.IO.Directory]::CreateDirectory($parent) | Out-Null
    }
    [System.IO.File]::WriteAllText($Path, $Text, $script:Utf8NoBom)
}

function Write-JsonFile {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] $Value
    )

    $json = $Value | ConvertTo-Json -Depth 100
    Write-Utf8NoBom -Path $Path -Text ($json + "`n")
}

function Get-Sha256 {
    param([Parameter(Mandatory)] [string] $Path)

    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-TextSha256 {
    param([Parameter(Mandatory)] [AllowEmptyString()] [string] $Text)

    $bytes = $script:Utf8NoBom.GetBytes($Text)
    return [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
}

function Write-RunnerEvent {
    param(
        [Parameter(Mandatory)] [string] $Phase,
        [Parameter(Mandatory)] [ValidateSet('START', 'PASS', 'FAIL', 'INFO')] [string] $Status,
        [Parameter(Mandatory)] [string] $Code,
        [hashtable] $Detail = @{}
    )

    if ($null -eq $script:TranscriptPath) { return }
    $script:TranscriptSequence++
    $event = [ordered]@{
        schemaVersion = 1
        sequence = $script:TranscriptSequence
        timestampUtc = [DateTimeOffset]::UtcNow.ToString('O')
        phase = $Phase
        status = $Status
        code = $Code
        detail = $Detail
    }
    $line = $event | ConvertTo-Json -Depth 20 -Compress
    [System.IO.File]::AppendAllText($script:TranscriptPath, $line + "`n", $script:Utf8NoBom)
}

function Assert-PathInside {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $Boundary,
        [switch] $AllowBoundary
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
    $fullBoundary = [System.IO.Path]::GetFullPath($Boundary).TrimEnd('\', '/')
    $comparison = [StringComparison]::OrdinalIgnoreCase
    if ($AllowBoundary -and $fullPath.Equals($fullBoundary, $comparison)) { return $fullPath }
    $prefix = $fullBoundary + [System.IO.Path]::DirectorySeparatorChar
    if (-not $fullPath.StartsWith($prefix, $comparison)) {
        throw "path '$fullPath' is outside the runner boundary '$fullBoundary'"
    }
    return $fullPath
}

function Remove-RunnerDirectory {
    param([Parameter(Mandatory)] [string] $Path)

    $full = Assert-PathInside -Path $Path -Boundary $script:WorkRoot
    if ([System.IO.Directory]::Exists($full)) {
        [System.IO.Directory]::Delete($full, $true)
    }
}

function Assert-NoReparsePoints {
    param([Parameter(Mandatory)] [string] $Root)

    foreach ($item in Get-ChildItem -LiteralPath $Root -Force -Recurse) {
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "reparse points are not admitted in compatibility evidence: $($item.FullName)"
        }
    }
}

function New-TreeManifest {
    param(
        [Parameter(Mandatory)] [string] $Root,
        [Parameter(Mandatory)] [string] $Scope,
        [Parameter(Mandatory)] [string] $OutputPath
    )

    $rootFull = [System.IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
    if (-not [System.IO.Directory]::Exists($rootFull)) {
        throw "manifest root does not exist: $rootFull"
    }
    Assert-NoReparsePoints -Root $rootFull

    $entries = [System.Collections.Generic.List[object]]::new()
    foreach ($item in Get-ChildItem -LiteralPath $rootFull -Force -Recurse) {
        $relative = [System.IO.Path]::GetRelativePath($rootFull, $item.FullName).Replace('\', '/')
        if ($relative.Contains("`n") -or $relative.Contains("`r") -or $relative.Contains("`t")) {
            throw "manifest paths may not contain line-control characters: $relative"
        }
        if ($item.PSIsContainer) {
            $entries.Add([ordered]@{ type = 'directory'; path = $relative })
        }
        else {
            $entries.Add([ordered]@{
                type = 'file'
                path = $relative
                bytes = [int64] $item.Length
                sha256 = Get-Sha256 -Path $item.FullName
            })
        }
    }

    $orderedEntries = @($entries | Sort-Object -Property @{ Expression = 'path'; Ascending = $true }, @{ Expression = 'type'; Ascending = $true })
    $canonical = [System.Text.StringBuilder]::new()
    foreach ($entry in $orderedEntries) {
        if ($entry.type -eq 'directory') {
            [void] $canonical.Append("directory`t$($entry.path)`n")
        }
        else {
            [void] $canonical.Append("file`t$($entry.path)`t$($entry.bytes)`t$($entry.sha256)`n")
        }
    }

    $document = [ordered]@{
        schemaVersion = 1
        manifestType = 'ensou-dsh-canonical-tree'
        scope = $Scope
        root = $rootFull
        treeSha256 = Get-TextSha256 -Text $canonical.ToString()
        entryCount = $orderedEntries.Count
        fileCount = @($orderedEntries | Where-Object type -eq 'file').Count
        directoryCount = @($orderedEntries | Where-Object type -eq 'directory').Count
        entries = $orderedEntries
    }
    Write-JsonFile -Path $OutputPath -Value $document
    return $document
}

function Compare-TreeManifest {
    param(
        [Parameter(Mandatory)] $Before,
        [Parameter(Mandatory)] $After
    )

    $beforeMap = @{}
    foreach ($entry in $Before.entries) { $beforeMap[$entry.path] = $entry }
    $afterMap = @{}
    foreach ($entry in $After.entries) { $afterMap[$entry.path] = $entry }

    $paths = @($beforeMap.Keys + $afterMap.Keys | Sort-Object -Unique)
    $changes = [System.Collections.Generic.List[object]]::new()
    foreach ($path in $paths) {
        $left = $beforeMap[$path]
        $right = $afterMap[$path]
        if ($null -eq $left) {
            $changes.Add([ordered]@{ path = $path; change = 'added'; type = $right.type })
        }
        elseif ($null -eq $right) {
            $changes.Add([ordered]@{ path = $path; change = 'removed'; type = $left.type })
        }
        elseif ($left.type -ne $right.type) {
            $changes.Add([ordered]@{ path = $path; change = 'type-changed'; beforeType = $left.type; afterType = $right.type })
        }
        elseif ($left.type -eq 'file' -and ($left.bytes -ne $right.bytes -or $left.sha256 -ne $right.sha256)) {
            $changes.Add([ordered]@{
                path = $path
                change = 'content-changed'
                beforeBytes = $left.bytes
                afterBytes = $right.bytes
                beforeSha256 = $left.sha256
                afterSha256 = $right.sha256
            })
        }
    }
    return @($changes)
}

function Assert-ZipEntriesSafe {
    param([Parameter(Mandatory)] [string] $ArchivePath)

    $archive = [System.IO.Compression.ZipFile]::OpenRead($ArchivePath)
    try {
        $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($entry in $archive.Entries) {
            $name = $entry.FullName.Replace('\', '/')
            if ([string]::IsNullOrWhiteSpace($name)) { throw "archive contains an empty entry name: $ArchivePath" }
            if ($name.StartsWith('/') -or $name -match '^[A-Za-z]:' -or $name.Contains([char]0)) {
                throw "archive contains an absolute or invalid entry: $name"
            }
            $segments = $name.Split('/', [StringSplitOptions]::RemoveEmptyEntries)
            if ($segments -contains '..') { throw "archive contains a traversal entry: $name" }
            if (-not $seen.Add($name)) { throw "archive contains a case-colliding duplicate entry: $name" }
        }
    }
    finally {
        $archive.Dispose()
    }
}

function Expand-VerifiedRuntime {
    param(
        [Parameter(Mandatory)] [string] $ArchivePath,
        [Parameter(Mandatory)] [string] $ExpectedSha256,
        [Parameter(Mandatory)] [string] $Destination,
        [Parameter(Mandatory)] [ValidateSet('source', 'target')] [string] $Role,
        [Parameter(Mandatory)] [string] $MetadataPath
    )

    $archiveFull = (Resolve-Path -LiteralPath $ArchivePath).Path
    $actualSha256 = Get-Sha256 -Path $archiveFull
    if ($actualSha256 -ne $ExpectedSha256.ToLowerInvariant()) {
        throw "$Role runtime archive SHA-256 mismatch: expected $($ExpectedSha256.ToLowerInvariant()), got $actualSha256"
    }
    Assert-ZipEntriesSafe -ArchivePath $archiveFull

    [System.IO.Directory]::CreateDirectory($Destination) | Out-Null
    [System.IO.Compression.ZipFile]::ExtractToDirectory($archiveFull, $Destination)
    Assert-NoReparsePoints -Root $Destination

    $nodePath = Join-Path $Destination 'node.exe'
    $entryPath = Join-Path $Destination 'node_modules\@deepseek-ai\dsh\lib\bin.js'
    $runtimeManifestPath = Join-Path $Destination 'runtime-files.sha256'
    foreach ($required in @($nodePath, $entryPath, $runtimeManifestPath)) {
        if (-not [System.IO.File]::Exists($required)) { throw "$Role runtime is missing required file: $required" }
    }

    $expectedFiles = [System.Collections.Generic.Dictionary[string, string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($line in [System.IO.File]::ReadAllLines($runtimeManifestPath)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        if ($line -notmatch '^([0-9a-fA-F]{64})  (.+)$') {
            throw "$Role runtime-files.sha256 has a malformed line"
        }
        $hash = $Matches[1].ToLowerInvariant()
        $relative = $Matches[2].Replace('\', '/')
        if ($relative.StartsWith('/') -or $relative -match '^[A-Za-z]:' -or $relative.Split('/') -contains '..') {
            throw "$Role runtime-files.sha256 contains an unsafe path: $relative"
        }
        if (-not $expectedFiles.TryAdd($relative, $hash)) {
            throw "$Role runtime-files.sha256 repeats a path: $relative"
        }
    }

    $actualFiles = @(
        Get-ChildItem -LiteralPath $Destination -File -Force -Recurse |
            ForEach-Object { [System.IO.Path]::GetRelativePath($Destination, $_.FullName).Replace('\', '/') } |
            Where-Object { $_ -ne 'runtime-files.sha256' }
    )
    foreach ($relative in $actualFiles) {
        if (-not $expectedFiles.ContainsKey($relative)) {
            throw "$Role runtime contains a file absent from runtime-files.sha256: $relative"
        }
        $actual = Get-Sha256 -Path (Join-Path $Destination $relative.Replace('/', '\'))
        if ($actual -ne $expectedFiles[$relative]) {
            throw "$Role runtime internal hash mismatch: $relative"
        }
    }
    if ($actualFiles.Count -ne $expectedFiles.Count) {
        $missing = @($expectedFiles.Keys | Where-Object { $_ -notin $actualFiles })
        throw "$Role runtime is missing $($missing.Count) file(s) declared by runtime-files.sha256"
    }

    $sourceBuildPath = Join-Path $Destination 'source-build.json'
    $sourceBuild = if (Test-Path -LiteralPath $sourceBuildPath) {
        Get-Content -LiteralPath $sourceBuildPath -Raw | ConvertFrom-Json -Depth 100
    }
    else { $null }

    $metadata = [ordered]@{
        schemaVersion = 1
        metadataType = 'ensou-dsh-runtime-archive-verification'
        role = $Role
        archivePath = $archiveFull
        archiveBytes = (Get-Item -LiteralPath $archiveFull).Length
        archiveSha256 = $actualSha256
        runtimeFileCount = $actualFiles.Count
        runtimeManifestSha256 = Get-Sha256 -Path $runtimeManifestPath
        nodeSha256 = Get-Sha256 -Path $nodePath
        entrySha256 = Get-Sha256 -Path $entryPath
        sourceBuild = $sourceBuild
    }
    Write-JsonFile -Path $MetadataPath -Value $metadata
    return [pscustomobject]@{
        Root = $Destination
        NodePath = $nodePath
        EntryPath = $entryPath
        Metadata = $metadata
        ArchiveSha256 = $actualSha256
    }
}

function Get-ProjectKey {
    param([Parameter(Mandatory)] [string] $Cwd)

    if ($Cwd.Length -eq 0) { throw 'cannot encode an empty project path' }
    $builder = [System.Text.StringBuilder]::new()
    $separatorRun = $false
    foreach ($ch in $Cwd.ToCharArray()) {
        if ($ch -eq '/' -or $ch -eq '\' -or $ch -eq ':') {
            if (-not $separatorRun) { [void] $builder.Append('-') }
            $separatorRun = $true
        }
        elseif ($ch -ne '~' -and $ch.ToString() -match '^[A-Za-z0-9._-]$') {
            [void] $builder.Append($ch)
            $separatorRun = $false
        }
        else {
            [void] $builder.Append(('~{0:X4}' -f [int] $ch))
            $separatorRun = $false
        }
    }
    $slug = $builder.ToString() -replace '^-+', ''
    if ($slug.Length -eq 0) { $slug = 'root' }
    if ($slug.Length -gt 251) { $slug = $slug.Substring(0, 251) }
    return "--$slug--"
}

function New-SyntheticRc7Fixture {
    param(
        [Parameter(Mandatory)] [string] $HomeRoot,
        [Parameter(Mandatory)] $SourceRuntime,
        [Parameter(Mandatory)] [string] $FixtureMetadataPath
    )

    [System.IO.Directory]::CreateDirectory($HomeRoot) | Out-Null
    $workspaceId = '00000000-0000-4000-8000-0000000000c7'
    $sessionId = 'compat-session-rc7'
    $headerOnlySessionId = 'compat-session-header-only-rc7'
    $workspace = Join-Path $HomeRoot 'workspaces\compat-workspace'
    [System.IO.Directory]::CreateDirectory($workspace) | Out-Null
    $workspace = (Resolve-Path -LiteralPath $workspace).Path

    Write-Utf8NoBom -Path (Join-Path $workspace 'README.txt') -Text "Synthetic rc7 local-data compatibility workspace.`n"
    Write-JsonFile -Path (Join-Path $workspace '.compat-workspace-marker.json') -Value ([ordered]@{
        schemaVersion = 1
        fixture = 'rc7-local-data-compatibility'
        sessionId = $sessionId
    })

    $credentialsPath = Join-Path $HomeRoot '.credentials.yaml'
    $flatCredentials = "# synthetic rc7 compatibility value; not a production secret`nCOMPAT_TEST_REF: fixture-only-value`n"
    Write-Utf8NoBom -Path $credentialsPath -Text $flatCredentials

    $png = [Convert]::FromBase64String('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=')
    $attachmentSha = [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($png)).ToLowerInvariant()
    $attachmentId = "sha256:$attachmentSha"
    $attachmentPath = Join-Path (Join-Path (Join-Path $HomeRoot 'attachments\v1\objects') $attachmentSha.Substring(0, 2)) $attachmentSha
    [System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($attachmentPath)) | Out-Null
    [System.IO.File]::WriteAllBytes($attachmentPath, $png)

    $createdAt = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    $header = [ordered]@{
        type = 'session'
        version = 0
        id = $sessionId
        createdAt = $createdAt
        cwd = $workspace
        delegationDepth = 0
        agentPreset = 'enterprise'
    }
    $headerScratch = Join-Path $script:WorkRoot 'fixture-header.jsonl'
    Write-Utf8NoBom -Path $headerScratch -Text (($header | ConvertTo-Json -Compress) + "`n")
    $headerOnlyHeader = [ordered]@{
        type = 'session'
        version = 0
        id = $headerOnlySessionId
        createdAt = $createdAt + 2
        cwd = $workspace
        delegationDepth = 0
        agentPreset = 'enterprise'
    }
    $headerOnlyScratch = Join-Path $script:WorkRoot 'fixture-header-only.jsonl'
    Write-Utf8NoBom -Path $headerOnlyScratch -Text (($headerOnlyHeader | ConvertTo-Json -Compress) + "`n")
    $attachmentEvent = [ordered]@{
        type = 'user/message'
        seq = 0
        time = $createdAt + 1
        data = [ordered]@{
            id = 'compat-attachment-message-rc7'
            role = 'user'
            content = @(
                [ordered]@{ type = 'text'; text = 'compatattachmenthistoricalrc7' },
                [ordered]@{
                    type = 'image'
                    attachment = [ordered]@{
                        attachmentId = $attachmentId
                        mediaType = 'image/png'
                        bytes = $png.Length
                        width = 1
                        height = 1
                        name = 'compat-fixture.png'
                    }
                }
            )
            source = [ordered]@{ kind = 'user' }
        }
        surfaceOp = 'append'
    }
    $eventScratch = Join-Path $script:WorkRoot 'fixture-event.jsonl'
    Write-Utf8NoBom -Path $eventScratch -Text (($attachmentEvent | ConvertTo-Json -Depth 20 -Compress) + "`n")

    $sessionDirectory = Join-Path (Join-Path (Join-Path $HomeRoot 'sessions') (Get-ProjectKey -Cwd $workspace)) $sessionId
    [System.IO.Directory]::CreateDirectory($sessionDirectory) | Out-Null
    $sessionLog = Join-Path $sessionDirectory 'session.jsonl.zstd'
    $compressorPath = Join-Path $script:WorkRoot 'compress-fixture.mjs'
    Write-Utf8NoBom -Path $compressorPath -Text @'
import { readFile, writeFile } from 'node:fs/promises'
import { constants, zstdCompress } from 'node:zlib'
import { promisify } from 'node:util'

const compress = promisify(zstdCompress)
const [outputPath, ...inputPaths] = process.argv.slice(2)
if (!outputPath || inputPaths.length === 0) throw new Error('output and input paths are required')
const frames = []
for (const inputPath of inputPaths) {
  frames.push(await compress(await readFile(inputPath), {
    params: { [constants.ZSTD_c_checksumFlag]: 1 },
  }))
}
await writeFile(outputPath, Buffer.concat(frames))
'@
    $compressProcess = Start-Process -FilePath $SourceRuntime.NodePath -ArgumentList @(
        $compressorPath,
        $sessionLog,
        $headerScratch,
        $eventScratch
    ) -NoNewWindow -Wait -PassThru
    if ($compressProcess.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $sessionLog)) {
        throw 'the source runtime Node executable could not build the checksummed Zstandard fixture'
    }
    $headerOnlySessionDirectory = Join-Path (Join-Path (Join-Path $HomeRoot 'sessions') (Get-ProjectKey -Cwd $workspace)) $headerOnlySessionId
    [System.IO.Directory]::CreateDirectory($headerOnlySessionDirectory) | Out-Null
    $headerOnlySessionLog = Join-Path $headerOnlySessionDirectory 'session.jsonl.zstd'
    $headerOnlyCompressProcess = Start-Process -FilePath $SourceRuntime.NodePath -ArgumentList @(
        $compressorPath,
        $headerOnlySessionLog,
        $headerOnlyScratch
    ) -NoNewWindow -Wait -PassThru
    if ($headerOnlyCompressProcess.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $headerOnlySessionLog)) {
        throw 'the source runtime Node executable could not build the header-only Zstandard fixture'
    }

    $storageRoot = Join-Path $HomeRoot 'storages'
    [System.IO.Directory]::CreateDirectory($storageRoot) | Out-Null
    $stamp = [DateTimeOffset]::FromUnixTimeMilliseconds($createdAt).ToString('O')
    $workspaceStorage = [ordered]@{
        unit = [ordered]@{ name = 'workspace'; version = 2 }
        global = [ordered]@{
            initialized = $true
            workspaceIds = @($workspaceId)
            archivedSessionIds = @()
        }
        tables = [ordered]@{
            workspaces = [ordered]@{
                $workspaceId = [ordered]@{
                    path = $workspace
                    title = 'Compatibility Fixture'
                    sessionIds = @($sessionId, $headerOnlySessionId)
                    createdAt = $stamp
                    updatedAt = $stamp
                }
            }
        }
    }
    Write-JsonFile -Path (Join-Path $storageRoot 'workspace.json') -Value $workspaceStorage

    $fixtureMetadata = [ordered]@{
        schemaVersion = 1
        fixtureType = 'ensou-dsh-synthetic-rc7-local-data'
        credentials = [ordered]@{
            relativePath = '.credentials.yaml'
            layout = 'pre-release-flat'
            sha256 = Get-Sha256 -Path $credentialsPath
        }
        session = [ordered]@{
            id = $sessionId
            formatVersion = 0
            compression = 'zstd-checksummed-frame'
            relativePath = [System.IO.Path]::GetRelativePath($HomeRoot, $sessionLog).Replace('\', '/')
            sha256 = Get-Sha256 -Path $sessionLog
            eventCoverage = 'one-durable-user-image-event'
        }
        headerOnlySession = [ordered]@{
            id = $headerOnlySessionId
            formatVersion = 0
            compression = 'zstd-checksummed-frame'
            relativePath = [System.IO.Path]::GetRelativePath($HomeRoot, $headerOnlySessionLog).Replace('\', '/')
            sha256 = Get-Sha256 -Path $headerOnlySessionLog
            eventCoverage = 'header-only'
        }
        storage = [ordered]@{
            relativePath = 'storages/workspace.json'
            unit = 'workspace'
            version = 2
            sha256 = Get-Sha256 -Path (Join-Path $storageRoot 'workspace.json')
        }
        attachment = [ordered]@{
            relativePath = [System.IO.Path]::GetRelativePath($HomeRoot, $attachmentPath).Replace('\', '/')
            objectSha256 = $attachmentSha
            attachmentId = $attachmentId
            bytes = $png.Length
        }
        workspace = [ordered]@{
            id = $workspaceId
            relativePath = [System.IO.Path]::GetRelativePath($HomeRoot, $workspace).Replace('\', '/')
            sessionIds = @($sessionId, $headerOnlySessionId)
        }
    }
    Write-JsonFile -Path $FixtureMetadataPath -Value $fixtureMetadata
    return [pscustomobject]@{
        Home = $HomeRoot
        Workspace = $workspace
        CredentialsPath = $credentialsPath
        SessionLog = $sessionLog
        HeaderOnlySessionLog = $headerOnlySessionLog
        WorkspaceStoragePath = Join-Path $storageRoot 'workspace.json'
        AttachmentPath = $attachmentPath
        AttachmentId = $attachmentId
        AttachmentSessionId = $sessionId
        WorkspaceId = $workspaceId
        Metadata = $fixtureMetadata
    }
}

function Get-FreeTcpPort {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try { return ([System.Net.IPEndPoint] $listener.LocalEndpoint).Port }
    finally { $listener.Stop() }
}

function Get-SanitizedProcessText {
    param([AllowEmptyString()] [string] $Text)

    $sanitized = $Text.Replace('fixture-only-value', '<redacted-fixture-value>')
    $sanitized = $sanitized.Replace('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', '<redacted-fixture-api-key>')
    return $sanitized
}

function Invoke-RuntimeBoot {
    param(
        [Parameter(Mandatory)] $Runtime,
        [Parameter(Mandatory)] [string] $HomeRoot,
        [Parameter(Mandatory)] [string] $Workspace,
        [Parameter(Mandatory)] [string] $Phase,
        [Parameter(Mandatory)] [string] $LogRoot,
        [Parameter(Mandatory)] [int] $TimeoutSeconds
    )

    $port = Get-FreeTcpPort
    $apiPort = Get-FreeTcpPort
    $agentsHome = Join-Path $script:WorkRoot 'agents-home'
    $skillsRoot = Join-Path $script:WorkRoot 'managed-skills'
    [System.IO.Directory]::CreateDirectory($agentsHome) | Out-Null
    [System.IO.Directory]::CreateDirectory($skillsRoot) | Out-Null

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $Runtime.NodePath
    $startInfo.WorkingDirectory = $Workspace
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($arg in @($Runtime.EntryPath, '--profile', 'enterprise-managed', '--host', '127.0.0.1', '--port', [string] $port)) {
        [void] $startInfo.ArgumentList.Add($arg)
    }

    $blockedPrefixes = @('DSH_', 'DEEPSEEK_', 'ENSOU_DSH_', 'ANTHROPIC_', 'OPENAI_')
    foreach ($entry in [System.Environment]::GetEnvironmentVariables().GetEnumerator()) {
        $name = [string] $entry.Key
        if ($blockedPrefixes | Where-Object { $name.StartsWith($_, [StringComparison]::OrdinalIgnoreCase) }) { continue }
        $startInfo.Environment[$name] = [string] $entry.Value
    }
    $startInfo.Environment['DSH_ENTERPRISE_MANAGED_BOOT'] = 'ensou-dsh-launcher/v1'
    $startInfo.Environment['DSH_HOME'] = $HomeRoot
    $startInfo.Environment['DSH_AGENTS_HOME'] = $agentsHome
    $startInfo.Environment['ENSOU_DSH_ENTERPRISE_SKILLS_ROOT'] = $skillsRoot
    $startInfo.Environment['DSH_TELEMETRY_DISABLED'] = '1'
    $startInfo.Environment['DEEPSEEK_BASE_URL'] = "http://127.0.0.1:$apiPort/v1"
    $startInfo.Environment['DEEPSEEK_SEARCH_BASE_URL'] = "http://127.0.0.1:$apiPort/v1"
    $startInfo.Environment['DEEPSEEK_API_KEY'] = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    $startInfo.Environment['NO_PROXY'] = '127.0.0.1,localhost'
    $startInfo.Environment['no_proxy'] = '127.0.0.1,localhost'
    $startInfo.Environment['BROWSER'] = 'none'

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $startedAt = [DateTimeOffset]::UtcNow
    if (-not $process.Start()) { throw "$Phase runtime process did not start" }
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()

    $ready = $false
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    $handler = [System.Net.Http.HttpClientHandler]::new()
    $handler.UseProxy = $false
    $client = [System.Net.Http.HttpClient]::new($handler)
    $client.Timeout = [TimeSpan]::FromMilliseconds(750)
    try {
        while ([DateTimeOffset]::UtcNow -lt $deadline) {
            if ($process.HasExited) { break }
            try {
                $response = $client.GetAsync("http://127.0.0.1:$port/").GetAwaiter().GetResult()
                try {
                    if ([int] $response.StatusCode -ge 200 -and [int] $response.StatusCode -lt 500) {
                        $ready = $true
                        break
                    }
                }
                finally { $response.Dispose() }
            }
            catch { }
            Start-Sleep -Milliseconds 150
        }
    }
    finally {
        $client.Dispose()
        $handler.Dispose()
    }

    $exitedNaturally = $process.HasExited
    if (-not $process.HasExited) {
        $process.Kill($true)
        $process.WaitForExit(10000) | Out-Null
    }
    $stdout = Get-SanitizedProcessText -Text $stdoutTask.GetAwaiter().GetResult()
    $stderr = Get-SanitizedProcessText -Text $stderrTask.GetAwaiter().GetResult()
    $exitCode = if ($process.HasExited) { $process.ExitCode } else { $null }
    $duration = [DateTimeOffset]::UtcNow - $startedAt
    $process.Dispose()

    $stdoutPath = Join-Path $LogRoot "$Phase.stdout.log"
    $stderrPath = Join-Path $LogRoot "$Phase.stderr.log"
    Write-Utf8NoBom -Path $stdoutPath -Text $stdout
    Write-Utf8NoBom -Path $stderrPath -Text $stderr
    return [pscustomobject]@{
        Phase = $Phase
        Ready = $ready
        ExitedNaturally = $exitedNaturally
        ExitCode = $exitCode
        Port = $port
        DurationMilliseconds = [int64] $duration.TotalMilliseconds
        StdoutPath = $stdoutPath
        StderrPath = $stderrPath
        StdoutSha256 = Get-Sha256 -Path $stdoutPath
        StderrSha256 = Get-Sha256 -Path $stderrPath
        Diagnostic = ($stdout + "`n" + $stderr)
    }
}

function Invoke-RuntimeApiLane {
    param(
        [Parameter(Mandatory)] $Runtime,
        [Parameter(Mandatory)] $Fixture,
        [Parameter(Mandatory)] [ValidateSet('source-seed', 'target-forward', 'source-restored')] [string] $Phase,
        [Parameter(Mandatory)] [string] $ResultPath,
        [Parameter(Mandatory)] [int] $TimeoutSeconds
    )

    $driverPath = Join-Path $PSScriptRoot 'local-data-compatibility-api-lane.mjs'
    if (-not (Test-Path -LiteralPath $driverPath)) { throw "API lane driver is missing: $driverPath" }
    $phaseToken = $Phase.Replace('-', '_')
    $runtimeStdoutPath = Join-Path $script:EvidenceRootFull "logs\$Phase.runtime.stdout.log"
    $runtimeStderrPath = Join-Path $script:EvidenceRootFull "logs\$Phase.runtime.stderr.log"
    $driverStdoutPath = Join-Path $script:EvidenceRootFull "logs\$Phase.driver.stdout.log"
    $driverStderrPath = Join-Path $script:EvidenceRootFull "logs\$Phase.driver.stderr.log"
    $configPath = Join-Path $script:WorkRoot "$Phase.api-lane.config.json"
    $configuration = [ordered]@{
        schemaVersion = 1
        phase = $Phase
        nodePath = $Runtime.NodePath
        entryPath = $Runtime.EntryPath
        runtimeArchiveSha256 = $Runtime.ArchiveSha256
        homeRoot = $Fixture.Home
        workspace = if ($Phase -eq 'source-restored') {
            Join-Path $Fixture.Home 'workspaces\compat-workspace'
        } else { $Fixture.Workspace }
        workspaceId = $Fixture.WorkspaceId
        attachmentSessionId = $Fixture.AttachmentSessionId
        attachmentId = $Fixture.AttachmentId
        apiSessionId = 'compat-api-session-cross-runtime'
        agentsHome = Join-Path $script:WorkRoot 'agents-home'
        skillsRoot = Join-Path $script:WorkRoot 'managed-skills'
        port = Get-FreeTcpPort
        timeoutSeconds = $TimeoutSeconds
        resultPath = $ResultPath
        runtimeStdoutPath = $runtimeStdoutPath
        runtimeStderrPath = $runtimeStderrPath
        markers = [ordered]@{
            sourcePrompt = 'orioncobaltrcseven'
            sourceResponse = 'providerackrcseven'
            targetPrompt = 'orioncobaltrctwo'
            targetResponse = 'providerackrctwo'
            restoredPrompt = 'orioncobaltrestored'
            restoredResponse = 'providerackrestored'
        }
    }
    Write-JsonFile -Path $configPath -Value $configuration

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $Runtime.NodePath
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    [void] $startInfo.ArgumentList.Add($driverPath)
    [void] $startInfo.ArgumentList.Add($configPath)
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    if (-not $process.Start()) { throw "$Phase API lane driver did not start" }
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    $process.WaitForExit()
    $stdout = Get-SanitizedProcessText -Text $stdoutTask.GetAwaiter().GetResult()
    $stderr = Get-SanitizedProcessText -Text $stderrTask.GetAwaiter().GetResult()
    $exitCode = $process.ExitCode
    $process.Dispose()
    Write-Utf8NoBom -Path $driverStdoutPath -Text $stdout
    Write-Utf8NoBom -Path $driverStderrPath -Text $stderr
    if ($exitCode -ne 0) {
        throw "$Phase API lane failed with exit code $exitCode; inspect $driverStderrPath and $ResultPath"
    }
    if (-not (Test-Path -LiteralPath $ResultPath)) { throw "$Phase API lane produced no result" }
    $result = Get-Content -LiteralPath $ResultPath -Raw | ConvertFrom-Json -Depth 100
    if ($result.decision -ne 'PASS' -or -not $result.runtimeBootPassed) {
        throw "$Phase API lane result is not PASS"
    }
    return $result
}

function Get-FileEntryMap {
    param([Parameter(Mandatory)] $Manifest)
    $map = @{}
    foreach ($entry in $Manifest.entries | Where-Object type -eq 'file') { $map[$entry.path] = $entry }
    return $map
}

function Assert-AuthoritativeDataPreserved {
    param(
        [Parameter(Mandatory)] $Before,
        [Parameter(Mandatory)] $After,
        [switch] $AllowSessionAppend
    )

    $beforeMap = Get-FileEntryMap -Manifest $Before
    $afterMap = Get-FileEntryMap -Manifest $After
    $authoritative = @(
        $beforeMap.Keys | Where-Object {
            $_ -like 'sessions/*' -or
            $_ -eq 'storages/workspace.json' -or
            $_ -eq 'storages/message_feedback.json' -or
            $_ -like 'attachments/v1/objects/*' -or
            $_ -like 'workspaces/*'
        }
    )
    foreach ($path in $authoritative) {
        if (-not $afterMap.ContainsKey($path)) { throw "target boot removed authoritative local data: $path" }
        if ($AllowSessionAppend -and $path -like 'sessions/*') { continue }
        if ($beforeMap[$path].sha256 -ne $afterMap[$path].sha256 -or $beforeMap[$path].bytes -ne $afterMap[$path].bytes) {
            throw "target boot rewrote authoritative local data: $path"
        }
    }
    return @($authoritative | Sort-Object)
}

function Get-SqliteArtifacts {
    param([Parameter(Mandatory)] [string] $Root)
    return @(
        Get-ChildItem -LiteralPath $Root -File -Force -Recurse |
            Where-Object { $_.Extension -in @('.sqlite', '.sqlite3', '.db') } |
            ForEach-Object { [System.IO.Path]::GetRelativePath($Root, $_.FullName).Replace('\', '/') } |
            Sort-Object
    )
}

function New-ArtifactReference {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $Root
    )
    return [ordered]@{
        path = [System.IO.Path]::GetRelativePath($Root, $Path).Replace('\', '/')
        bytes = (Get-Item -LiteralPath $Path).Length
        sha256 = Get-Sha256 -Path $Path
    }
}

$startedUtc = [DateTimeOffset]::UtcNow
$failure = $null
try {
    if (-not $IsWindows) { throw 'this compatibility runner requires Windows because the managed runtime archives are win-x64' }

    $script:EvidenceRootFull = [System.IO.Path]::GetFullPath($EvidenceRoot).TrimEnd('\', '/')
    if ([System.IO.Directory]::Exists($script:EvidenceRootFull) -or [System.IO.File]::Exists($script:EvidenceRootFull)) {
        throw "EvidenceRoot must not already exist: $($script:EvidenceRootFull)"
    }
    [System.IO.Directory]::CreateDirectory($script:EvidenceRootFull) | Out-Null
    foreach ($directory in @('manifests', 'results', 'logs', 'artifacts')) {
        [System.IO.Directory]::CreateDirectory((Join-Path $script:EvidenceRootFull $directory)) | Out-Null
    }
    $runnerCopyPath = Join-Path $script:EvidenceRootFull 'artifacts\Test-EnterpriseLocalDataCompatibility.ps1'
    [System.IO.File]::Copy($PSCommandPath, $runnerCopyPath, $false)
    $apiDriverPath = Join-Path $PSScriptRoot 'local-data-compatibility-api-lane.mjs'
    if (-not (Test-Path -LiteralPath $apiDriverPath)) { throw "API lane driver is missing: $apiDriverPath" }
    $apiDriverCopyPath = Join-Path $script:EvidenceRootFull 'artifacts\local-data-compatibility-api-lane.mjs'
    [System.IO.File]::Copy($apiDriverPath, $apiDriverCopyPath, $false)
    $script:WorkRoot = Join-Path $script:EvidenceRootFull 'work'
    [System.IO.Directory]::CreateDirectory($script:WorkRoot) | Out-Null
    $script:TranscriptPath = Join-Path $script:EvidenceRootFull 'runner-transcript.jsonl'
    Write-Utf8NoBom -Path $script:TranscriptPath -Text ''

    Write-RunnerEvent -Phase 'runner' -Status START -Code 'LOCAL_DATA_COMPATIBILITY_STARTED' -Detail @{
        coverage = 'credentials-canonical-tree-rollback-and-full-public-api-lanes'
    }

    $sourceRuntime = Expand-VerifiedRuntime `
        -ArchivePath $SourceRuntimeArchivePath `
        -ExpectedSha256 $SourceRuntimeSha256 `
        -Destination (Join-Path $script:WorkRoot 'source-runtime') `
        -Role source `
        -MetadataPath (Join-Path $script:EvidenceRootFull 'manifests\source-runtime.json')
    Write-RunnerEvent -Phase 'archives' -Status PASS -Code 'SOURCE_RUNTIME_EXACT_ZIP_VERIFIED' -Detail @{
        sha256 = $sourceRuntime.ArchiveSha256
    }

    $targetRuntime = Expand-VerifiedRuntime `
        -ArchivePath $TargetRuntimeArchivePath `
        -ExpectedSha256 $TargetRuntimeSha256 `
        -Destination (Join-Path $script:WorkRoot 'target-runtime') `
        -Role target `
        -MetadataPath (Join-Path $script:EvidenceRootFull 'manifests\target-runtime.json')
    Write-RunnerEvent -Phase 'archives' -Status PASS -Code 'TARGET_RUNTIME_EXACT_ZIP_VERIFIED' -Detail @{
        sha256 = $targetRuntime.ArchiveSha256
    }

    $fixture = New-SyntheticRc7Fixture `
        -HomeRoot (Join-Path $script:WorkRoot 'live-home') `
        -SourceRuntime $sourceRuntime `
        -FixtureMetadataPath (Join-Path $script:EvidenceRootFull 'manifests\synthetic-rc7-fixture.json')
    Write-RunnerEvent -Phase 'fixture' -Status PASS -Code 'SYNTHETIC_RC7_FIXTURE_CREATED' -Detail @{
        sessionFormatVersion = 0
        workspaceStorageVersion = 2
        sessionEventCoverage = 'durable-image-event-plus-separate-header-only-artifact'
    }

    $sourceSeedApiResultPath = Join-Path $script:EvidenceRootFull 'results\source-seed-api-lane.json'
    $sourceSeedApi = Invoke-RuntimeApiLane `
        -Runtime $sourceRuntime `
        -Fixture $fixture `
        -Phase 'source-seed' `
        -ResultPath $sourceSeedApiResultPath `
        -TimeoutSeconds $BootTimeoutSeconds
    foreach ($required in @(
        $sourceSeedApi.sessionApiResumeAppend.passed,
        $sourceSeedApi.conversationProviderRoundTrip.passed,
        $sourceSeedApi.sessionQuerySemanticParity.passed,
        $sourceSeedApi.attachment.publicApiRoundTripPassed
    )) {
        if (-not $required) { throw 'source-seed API lane omitted a required public API result' }
    }
    Write-RunnerEvent -Phase 'source-seed-api' -Status PASS -Code 'SOURCE_PUBLIC_API_FIXTURE_SEEDED' -Detail @{
        resultSha256 = Get-Sha256 -Path $sourceSeedApiResultPath
        providerRequests = $sourceSeedApi.provider.requestCount
        requestImageNormalization = $sourceSeedApi.attachment.requestImageNormalization.status
    }

    $preCredentialsSha = Get-Sha256 -Path $fixture.CredentialsPath
    $preManifest = New-TreeManifest `
        -Root $fixture.Home `
        -Scope 'pre-upgrade-enterprise-managed-home' `
        -OutputPath (Join-Path $script:EvidenceRootFull 'manifests\pre-upgrade-tree.json')
    $preWorkspaceManifest = New-TreeManifest `
        -Root $fixture.Workspace `
        -Scope 'pre-upgrade-workspace' `
        -OutputPath (Join-Path $script:EvidenceRootFull 'manifests\pre-upgrade-workspace-tree.json')
    $preSqlite = @(Get-SqliteArtifacts -Root $fixture.Home)
    if ($preSqlite.Count -ne 0) { throw 'the synthetic fixture unexpectedly contains a SQLite artifact' }

    $historicalFixturePath = Join-Path $script:EvidenceRootFull 'artifacts\historical-rc7-home-fixture.zip'
    [System.IO.Compression.ZipFile]::CreateFromDirectory(
        $fixture.Home,
        $historicalFixturePath,
        [System.IO.Compression.CompressionLevel]::Optimal,
        $false)
    Assert-ZipEntriesSafe -ArchivePath $historicalFixturePath
    $backupPath = Join-Path $script:EvidenceRootFull 'artifacts\pre-upgrade-home-backup.zip'
    [System.IO.Compression.ZipFile]::CreateFromDirectory($fixture.Home, $backupPath, [System.IO.Compression.CompressionLevel]::Optimal, $false)
    Assert-ZipEntriesSafe -ArchivePath $backupPath
    Write-RunnerEvent -Phase 'backup' -Status PASS -Code 'PRE_UPGRADE_CANONICAL_BACKUP_CREATED' -Detail @{
        treeSha256 = $preManifest.treeSha256
        workspaceTreeSha256 = $preWorkspaceManifest.treeSha256
        historicalFixtureSha256 = Get-Sha256 -Path $historicalFixturePath
        backupSha256 = Get-Sha256 -Path $backupPath
    }

    $targetForwardApiResultPath = Join-Path $script:EvidenceRootFull 'results\target-forward-api-lane.json'
    $targetForwardApi = Invoke-RuntimeApiLane `
        -Runtime $targetRuntime `
        -Fixture $fixture `
        -Phase 'target-forward' `
        -ResultPath $targetForwardApiResultPath `
        -TimeoutSeconds $BootTimeoutSeconds
    foreach ($required in @(
        $targetForwardApi.sessionApiResumeAppend.passed,
        $targetForwardApi.conversationProviderRoundTrip.passed,
        $targetForwardApi.sessionQuerySemanticParity.passed,
        $targetForwardApi.attachment.publicApiRoundTripPassed
    )) {
        if (-not $required) { throw 'target-forward API lane omitted a required public API result' }
    }

    $migratedText = [System.IO.File]::ReadAllText($fixture.CredentialsPath, $script:Utf8NoBom)
    $migrationShape = $migratedText -match '(?m)^version: 1\r?$' -and
        $migratedText -match '(?m)^refs:\r?$' -and
        $migratedText -match '(?m)^  COMPAT_TEST_REF: fixture-only-value\r?$'
    if (-not $migrationShape) { throw 'target runtime became ready without producing the expected version-1 credentials layout' }
    $postCredentialsSha = Get-Sha256 -Path $fixture.CredentialsPath
    if ($postCredentialsSha -eq $preCredentialsSha) { throw 'credentials migration did not change the document bytes' }

    $postForwardManifest = New-TreeManifest `
        -Root $fixture.Home `
        -Scope 'post-target-forward-boot-enterprise-managed-home' `
        -OutputPath (Join-Path $script:EvidenceRootFull 'manifests\post-forward-tree.json')
    $postForwardWorkspaceManifest = New-TreeManifest `
        -Root $fixture.Workspace `
        -Scope 'post-target-forward-boot-workspace' `
        -OutputPath (Join-Path $script:EvidenceRootFull 'manifests\post-forward-workspace-tree.json')
    if ($postForwardWorkspaceManifest.treeSha256 -ne $preWorkspaceManifest.treeSha256) {
        throw 'target runtime boot changed the workspace tree'
    }
    $preservedPaths = Assert-AuthoritativeDataPreserved -Before $preManifest -After $postForwardManifest -AllowSessionAppend
    $postForwardSqlite = @(Get-SqliteArtifacts -Root $fixture.Home)
    if ($postForwardSqlite.Count -ne 0) { throw 'target runtime materialized a SQLite file in enterprise-managed local data' }
    $forwardChanges = @(Compare-TreeManifest -Before $preManifest -After $postForwardManifest)
    Write-RunnerEvent -Phase 'forward' -Status PASS -Code 'TARGET_BOOT_MIGRATED_CREDENTIALS' -Detail @{
        preCredentialsSha256 = $preCredentialsSha
        postCredentialsSha256 = $postCredentialsSha
        authoritativeFilesPreserved = $preservedPaths.Count
        sqliteArtifacts = 0
    }

    $sourceRollbackBoot = Invoke-RuntimeBoot `
        -Runtime $sourceRuntime `
        -HomeRoot $fixture.Home `
        -Workspace $fixture.Workspace `
        -Phase 'source-in-place-rollback-boot' `
        -LogRoot (Join-Path $script:EvidenceRootFull 'logs') `
        -TimeoutSeconds ([Math]::Min($BootTimeoutSeconds, 30))
    if ($sourceRollbackBoot.Ready) { throw 'source runtime unexpectedly accepted the target-migrated credentials document in place' }
    if (-not $sourceRollbackBoot.ExitedNaturally) { throw 'source runtime neither became ready nor refused the migrated document within the timeout' }
    if ($sourceRollbackBoot.ExitCode -eq 0) { throw 'source runtime exited successfully instead of refusing the migrated credentials document' }
    if ($sourceRollbackBoot.Diagnostic -notmatch '(?is)credentials-local.*(version|must be a string|flat)') {
        throw 'source runtime failed, but the diagnostic does not prove credentials-layout refusal'
    }
    Write-RunnerEvent -Phase 'rollback' -Status PASS -Code 'SOURCE_IN_PLACE_ROLLBACK_REFUSED' -Detail @{
        exitCode = $sourceRollbackBoot.ExitCode
        diagnosticClass = 'credentials-layout-refusal'
    }

    $restoreStage = Join-Path $script:WorkRoot 'restore-stage'
    [System.IO.Directory]::CreateDirectory($restoreStage) | Out-Null
    [System.IO.Compression.ZipFile]::ExtractToDirectory($backupPath, $restoreStage)
    Assert-NoReparsePoints -Root $restoreStage
    Remove-RunnerDirectory -Path $fixture.Home
    [System.IO.Directory]::Move($restoreStage, $fixture.Home)

    $restoredManifest = New-TreeManifest `
        -Root $fixture.Home `
        -Scope 'restored-enterprise-managed-home-before-source-boot' `
        -OutputPath (Join-Path $script:EvidenceRootFull 'manifests\restored-tree.json')
    $restoredWorkspace = Join-Path $fixture.Home 'workspaces\compat-workspace'
    $restoredWorkspaceManifest = New-TreeManifest `
        -Root $restoredWorkspace `
        -Scope 'restored-workspace-before-source-boot' `
        -OutputPath (Join-Path $script:EvidenceRootFull 'manifests\restored-workspace-tree.json')
    if ($restoredManifest.treeSha256 -ne $preManifest.treeSha256) { throw 'whole-home restore is not byte-exact' }
    if ($restoredWorkspaceManifest.treeSha256 -ne $preWorkspaceManifest.treeSha256) { throw 'workspace restore is not byte-exact' }
    $restoredCredentialsPath = Join-Path $fixture.Home '.credentials.yaml'
    if ((Get-Sha256 -Path $restoredCredentialsPath) -ne $preCredentialsSha) { throw 'restore did not recover the flat rc7 credentials bytes' }
    Write-RunnerEvent -Phase 'restore' -Status PASS -Code 'WHOLE_HOME_RESTORE_BYTE_EXACT' -Detail @{
        treeSha256 = $restoredManifest.treeSha256
        workspaceTreeSha256 = $restoredWorkspaceManifest.treeSha256
    }

    $sourceRestoredApiResultPath = Join-Path $script:EvidenceRootFull 'results\source-restored-api-lane.json'
    $sourceRestoredApi = Invoke-RuntimeApiLane `
        -Runtime $sourceRuntime `
        -Fixture $fixture `
        -Phase 'source-restored' `
        -ResultPath $sourceRestoredApiResultPath `
        -TimeoutSeconds $BootTimeoutSeconds
    foreach ($required in @(
        $sourceRestoredApi.sessionApiResumeAppend.passed,
        $sourceRestoredApi.conversationProviderRoundTrip.passed,
        $sourceRestoredApi.sessionQuerySemanticParity.passed,
        $sourceRestoredApi.attachment.publicApiRoundTripPassed
    )) {
        if (-not $required) { throw 'source-restored API lane omitted a required public API result' }
    }
    $postRestoredBootManifest = New-TreeManifest `
        -Root $fixture.Home `
        -Scope 'post-restored-source-boot-enterprise-managed-home' `
        -OutputPath (Join-Path $script:EvidenceRootFull 'manifests\post-restored-source-boot-tree.json')
    $restoredAuthoritativePaths = Assert-AuthoritativeDataPreserved -Before $preManifest -After $postRestoredBootManifest -AllowSessionAppend
    $postRestoredSqlite = @(Get-SqliteArtifacts -Root $fixture.Home)
    if ($postRestoredSqlite.Count -ne 0) { throw 'source runtime materialized a SQLite file after restore' }
    Write-RunnerEvent -Phase 'rollback' -Status PASS -Code 'SOURCE_BOOT_AFTER_RESTORE_PASSED' -Detail @{
        authoritativeFilesPreserved = $restoredAuthoritativePaths.Count
        sqliteArtifacts = 0
    }

    $queryModes = @(@(
        [string] $sourceSeedApi.sessionQuerySemanticParity.mode,
        [string] $targetForwardApi.sessionQuerySemanticParity.mode,
        [string] $sourceRestoredApi.sessionQuerySemanticParity.mode
    ) | Sort-Object -Unique)
    if ($queryModes.Count -ne 1) { throw 'session.search semantic mode differs across rc7, rc2, and restored rc7' }
    if ($queryModes[0] -eq 'managed-disabled-public-api-policy') {
        foreach ($field in @('errorCode', 'diagnosticClass', 'messageSha256')) {
            $values = @(@(
                [string] $sourceSeedApi.sessionQuerySemanticParity.$field,
                [string] $targetForwardApi.sessionQuerySemanticParity.$field,
                [string] $sourceRestoredApi.sessionQuerySemanticParity.$field
            ) | Sort-Object -Unique)
            if ($values.Count -ne 1 -or [string]::IsNullOrWhiteSpace($values[0])) {
                throw "session.search managed-disabled $field differs across runtime phases"
            }
        }
    }

    $forwardResultPath = Join-Path $script:EvidenceRootFull 'results\forward-result.json'
    $forwardRecordedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
    $expectedRefusalByPhase = @{
        'source-seed' = @{
            stage = 'select-model'
            code = 'model-unavailable'
            diagnosticClass = 'managed-text-only-model-selection-refusal'
        }
        'target-forward' = @{
            stage = 'image-prompt'
            code = 'attachment-error'
            diagnosticClass = 'managed-text-only-image-prompt-refusal'
        }
        'source-restored' = @{
            stage = 'select-model'
            code = 'model-unavailable'
            diagnosticClass = 'managed-text-only-model-selection-refusal'
        }
    }
    foreach ($apiResult in @($sourceSeedApi, $targetForwardApi, $sourceRestoredApi)) {
        $normalization = $apiResult.attachment.requestImageNormalization
        $refusal = $normalization.publicPolicyRefusal
        $expectedRefusal = $expectedRefusalByPhase[[string] $apiResult.phase]
        if ($null -eq $expectedRefusal) {
            throw "local-data v1 received an unknown API phase: $($apiResult.phase)"
        }
        if ($normalization.status -ne 'not-applicable-managed-text-only-policy' -or
            $refusal.stage -ne $expectedRefusal.stage -or
            $refusal.code -ne $expectedRefusal.code -or
            $refusal.diagnosticClass -ne $expectedRefusal.diagnosticClass -or
            [string] $refusal.messageSha256 -notmatch '^[0-9a-f]{64}$' -or
            $refusal.provider -ne 'deepseek-official' -or
            $refusal.model -ne 'deepseek-v4-flash-vision-exp' -or
            @($normalization.requestImageFiles).Count -ne 0) {
            throw "local-data v1 managed text-only public refusal evidence is incomplete for $($apiResult.phase)"
        }
    }
    $normalizationCoverage = 'not-applicable-managed-text-only-policy-public-refusal-proven'
    $coveredLanes = @(
        'exact-runtime-archive-and-internal-manifest-verification',
        'rc7-flat-credentials-to-version-1-boot-migration',
        'header-only-zstd-session-artifact-preservation',
        'zstd-session-v0-public-api-resume-append',
        'loopback-fake-provider-conversation-roundtrip',
        'attachment-public-api-byte-roundtrip',
        'session-query-public-api-managed-disabled-policy-parity',
        'workspace-v2-json-storage-preservation',
        'content-addressed-attachment-object-preservation',
        'workspace-file-tree-preservation'
    )
    $forwardResult = [ordered]@{
        schemaVersion = 1
        resultType = 'ensou-dsh-local-data-forward-result'
        fromUpstreamTag = [string] $sourceRuntime.Metadata.sourceBuild.sourceTag
        toUpstreamTag = [string] $targetRuntime.Metadata.sourceBuild.sourceTag
        decision = 'PASS'
        sourceRuntimeArchiveSha256 = $sourceRuntime.ArchiveSha256
        targetRuntimeArchiveSha256 = $targetRuntime.ArchiveSha256
        targetRuntimeBootPassed = $true
        credentialsMigrationObserved = $true
        credentialsLayoutBefore = 'pre-release-flat'
        credentialsLayoutAfter = 'version-1-refs'
        credentialsSha256Before = $preCredentialsSha
        credentialsSha256After = $postCredentialsSha
        authoritativeFilesPreserved = $preservedPaths
        workspaceTreePreserved = $true
        apiLanes = [ordered]@{
            sourceSeedDecision = [string] $sourceSeedApi.decision
            targetForwardDecision = [string] $targetForwardApi.decision
            fullSessionApiRoundTripPassed = [bool] $targetForwardApi.sessionApiResumeAppend.passed
            conversationProviderRoundTripPassed = [bool] $targetForwardApi.conversationProviderRoundTrip.passed
            attachmentPublicApiRoundTripPassed = [bool] $targetForwardApi.attachment.publicApiRoundTripPassed
            sessionQuerySemanticParityPassed = [bool] $targetForwardApi.sessionQuerySemanticParity.passed
            requestImageNormalization = $normalizationCoverage
        }
        queryPersistence = [ordered]@{
            classification = 'memory-only-derived'
            sqliteArtifactsBefore = $preSqlite
            sqliteArtifactsAfter = $postForwardSqlite
        }
        treeChanges = $forwardChanges
        recordedAtUtc = $forwardRecordedAtUtc
        coveredLanes = $coveredLanes
        deferredLanes = @()
    }
    Write-JsonFile -Path $forwardResultPath -Value $forwardResult

    $rollbackResultPath = Join-Path $script:EvidenceRootFull 'results\rollback-result.json'
    $rollbackRecordedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
    $rollbackResult = [ordered]@{
        schemaVersion = 1
        resultType = 'ensou-dsh-local-data-rollback-result'
        fromUpstreamTag = [string] $sourceRuntime.Metadata.sourceBuild.sourceTag
        toUpstreamTag = [string] $targetRuntime.Metadata.sourceBuild.sourceTag
        decision = 'PASS'
        inPlaceRollbackRefusedAsExpected = $true
        refusalClass = 'credentials-layout-refusal'
        historicalFixtureSha256 = Get-Sha256 -Path $historicalFixturePath
        backupArchiveSha256 = Get-Sha256 -Path $backupPath
        preUpgradeTreeSha256 = $preManifest.treeSha256
        restoredTreeSha256 = $restoredManifest.treeSha256
        preUpgradeWorkspaceTreeSha256 = $preWorkspaceManifest.treeSha256
        restoredWorkspaceTreeSha256 = $restoredWorkspaceManifest.treeSha256
        backupRestoreByteExactPassed = $true
        sourceRuntimeBootAfterRestorePassed = $true
        sourceRuntimeAuthoritativeFilesPreservedAfterBoot = $restoredAuthoritativePaths
        sqliteArtifactsAfterRestoreAndBoot = $postRestoredSqlite
        recordedAtUtc = $rollbackRecordedAtUtc
    }
    Write-JsonFile -Path $rollbackResultPath -Value $rollbackResult

    Write-RunnerEvent -Phase 'runner' -Status PASS -Code 'LOCAL_DATA_COMPATIBILITY_FULL_API_PASSED' -Detail @{
        forwardDecision = 'PASS'
        rollbackDecision = 'PASS'
        deferredLaneCount = $forwardResult.deferredLanes.Count
    }

    $evidencePath = Join-Path $script:EvidenceRootFull 'local-data-compatibility-evidence.json'
    $evidenceArtifacts = @(
        'manifests\source-runtime.json',
        'manifests\target-runtime.json',
        'manifests\synthetic-rc7-fixture.json',
        'manifests\pre-upgrade-tree.json',
        'manifests\pre-upgrade-workspace-tree.json',
        'manifests\post-forward-tree.json',
        'manifests\post-forward-workspace-tree.json',
        'manifests\restored-tree.json',
        'manifests\restored-workspace-tree.json',
        'manifests\post-restored-source-boot-tree.json',
        'results\forward-result.json',
        'results\rollback-result.json',
        'results\source-seed-api-lane.json',
        'results\target-forward-api-lane.json',
        'results\source-restored-api-lane.json',
        'artifacts\Test-EnterpriseLocalDataCompatibility.ps1',
        'artifacts\local-data-compatibility-api-lane.mjs',
        'artifacts\historical-rc7-home-fixture.zip',
        'artifacts\pre-upgrade-home-backup.zip',
        'logs\source-seed.runtime.stdout.log',
        'logs\source-seed.runtime.stderr.log',
        'logs\source-seed.driver.stdout.log',
        'logs\source-seed.driver.stderr.log',
        'logs\target-forward.runtime.stdout.log',
        'logs\target-forward.runtime.stderr.log',
        'logs\target-forward.driver.stdout.log',
        'logs\target-forward.driver.stderr.log',
        'logs\source-in-place-rollback-boot.stdout.log',
        'logs\source-in-place-rollback-boot.stderr.log',
        'logs\source-restored.runtime.stdout.log',
        'logs\source-restored.runtime.stderr.log',
        'logs\source-restored.driver.stdout.log',
        'logs\source-restored.driver.stderr.log',
        'runner-transcript.jsonl'
    ) | ForEach-Object { New-ArtifactReference -Path (Join-Path $script:EvidenceRootFull $_) -Root $script:EvidenceRootFull }

    $evidence = [ordered]@{
        schemaVersion = 1
        evidenceType = 'ensou-dsh-enterprise-local-data-compatibility'
        decision = 'PASS'
        startedUtc = $startedUtc.ToString('O')
        completedUtc = [DateTimeOffset]::UtcNow.ToString('O')
        fromUpstreamTag = [string] $sourceRuntime.Metadata.sourceBuild.sourceTag
        toUpstreamTag = [string] $targetRuntime.Metadata.sourceBuild.sourceTag
        sourceRuntimeArchiveSha256 = $sourceRuntime.ArchiveSha256
        targetRuntimeArchiveSha256 = $targetRuntime.ArchiveSha256
        testRunner = New-ArtifactReference -Path $runnerCopyPath -Root $script:EvidenceRootFull
        historicalFixture = New-ArtifactReference -Path $historicalFixturePath -Root $script:EvidenceRootFull
        preUpgradeBackup = New-ArtifactReference -Path $backupPath -Root $script:EvidenceRootFull
        forwardResult = New-ArtifactReference -Path $forwardResultPath -Root $script:EvidenceRootFull
        rollbackResult = New-ArtifactReference -Path $rollbackResultPath -Root $script:EvidenceRootFull
        apiLanes = [ordered]@{
            sourceSeed = New-ArtifactReference -Path $sourceSeedApiResultPath -Root $script:EvidenceRootFull
            targetForward = New-ArtifactReference -Path $targetForwardApiResultPath -Root $script:EvidenceRootFull
            sourceRestored = New-ArtifactReference -Path $sourceRestoredApiResultPath -Root $script:EvidenceRootFull
        }
        transcript = New-ArtifactReference -Path $script:TranscriptPath -Root $script:EvidenceRootFull
        artifacts = @($evidenceArtifacts)
        coverage = [ordered]@{
            credentialsP0 = 'covered'
            canonicalWholeHomeBackupRestore = 'covered'
            workspaceTreeBackupRestore = 'covered'
            sameTreeOldRuntimeRefusal = 'covered'
            headerOnlySessionArtifact = 'preserved-and-discovered-at-boot'
            fullSessionApiRoundTrip = 'covered'
            conversationProviderRoundTrip = 'covered'
            attachmentPublicApiRoundTrip = 'covered'
            sessionQuerySemanticParity = 'covered'
            requestImageNormalization = $normalizationCoverage
            sqliteLocalDataGate = 'not-applicable-memory-only-derived-and-no-artifacts-observed'
        }
    }
    Write-JsonFile -Path $evidencePath -Value $evidence

    if (-not $KeepWorkingDirectory) {
        Remove-RunnerDirectory -Path (Join-Path $script:WorkRoot 'source-runtime')
        Remove-RunnerDirectory -Path (Join-Path $script:WorkRoot 'target-runtime')
        Remove-RunnerDirectory -Path (Join-Path $script:WorkRoot 'live-home')
        foreach ($file in @(
            'fixture-header.jsonl',
            'fixture-header-only.jsonl',
            'fixture-event.jsonl',
            'compress-fixture.mjs',
            'source-seed.api-lane.config.json',
            'target-forward.api-lane.config.json',
            'source-restored.api-lane.config.json'
        )) {
            $candidate = Join-Path $script:WorkRoot $file
            if (Test-Path -LiteralPath $candidate) { Remove-Item -LiteralPath $candidate -Force }
        }
    }

    [pscustomobject]@{
        decision = 'PASS'
        evidencePath = $evidencePath
        evidenceSha256 = Get-Sha256 -Path $evidencePath
        forwardResultPath = $forwardResultPath
        rollbackResultPath = $rollbackResultPath
    } | ConvertTo-Json -Compress
}
catch {
    $failure = $_
    if ($null -ne $script:TranscriptPath) {
        Write-RunnerEvent -Phase 'runner' -Status FAIL -Code 'LOCAL_DATA_COMPATIBILITY_FAILED' -Detail @{
            errorType = $_.Exception.GetType().FullName
            message = Get-SanitizedProcessText -Text $_.Exception.Message
        }
        $failurePath = Join-Path $script:EvidenceRootFull 'results\failure.json'
        Write-JsonFile -Path $failurePath -Value ([ordered]@{
            schemaVersion = 1
            resultType = 'ensou-dsh-local-data-compatibility-failure'
            decision = 'FAIL'
            startedUtc = $startedUtc.ToString('O')
            failedUtc = [DateTimeOffset]::UtcNow.ToString('O')
            errorType = $_.Exception.GetType().FullName
            message = Get-SanitizedProcessText -Text $_.Exception.Message
            transcriptPath = $script:TranscriptPath
        })
    }
    throw
}
