#requires -Version 7.2
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$DirectLocalMetadataPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$publisherPath = Join-Path $PSScriptRoot 'Publish-SourceRuntimeCandidate.ps1'
$metadataValidatorPath = Join-Path $PSScriptRoot 'Test-SourceRuntimeMetadata.ps1'
$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$fixtureRoot = Join-Path $tempRoot ('direct-local-publication-preflight-' + [Guid]::NewGuid().ToString('N'))
$recordRoot = Join-Path $tempRoot ('direct-local-publication-record-' + [Guid]::NewGuid().ToString('N'))
$releaseId = 'managed-v2026.09.15.1'
$launcherCommit = 'f' * 40
$sourceMetadata = Get-Item -LiteralPath ([IO.Path]::GetFullPath($DirectLocalMetadataPath)) -Force -ErrorAction Stop
if ($sourceMetadata.PSIsContainer -or ($sourceMetadata.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'Direct-local metadata input must be one ordinary file.'
}
if (-not $sourceMetadata.FullName.EndsWith('.metadata.json', [StringComparison]::Ordinal)) {
    throw 'Direct-local metadata input must be the a10 metadata JSON file.'
}

function Get-Sha256([string]$Path) {
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Write-JsonCreate([string]$Path, $Value) {
    [IO.File]::WriteAllText(
        $Path,
        ($Value | ConvertTo-Json -Depth 32),
        [Text.UTF8Encoding]::new($false))
}

function New-LocalReviewedRecord([string]$Path, [string]$ArtifactPath, [string]$MetadataPath,
    [string]$HashPath, [string]$ManagedPath) {
    $files = @(
        [ordered]@{ role = 'archive'; fileName = [IO.Path]::GetFileName($ArtifactPath); path = $ArtifactPath; sizeBytes = [IO.FileInfo]::new($ArtifactPath).Length; sha256 = Get-Sha256 $ArtifactPath },
        [ordered]@{ role = 'metadata'; fileName = [IO.Path]::GetFileName($MetadataPath); path = $MetadataPath; sizeBytes = [IO.FileInfo]::new($MetadataPath).Length; sha256 = Get-Sha256 $MetadataPath },
        [ordered]@{ role = 'hash-evidence'; fileName = [IO.Path]::GetFileName($HashPath); path = $HashPath; sizeBytes = [IO.FileInfo]::new($HashPath).Length; sha256 = Get-Sha256 $HashPath },
        [ordered]@{ role = 'managed-candidate'; fileName = [IO.Path]::GetFileName($ManagedPath); path = $ManagedPath; sizeBytes = [IO.FileInfo]::new($ManagedPath).Length; sha256 = Get-Sha256 $ManagedPath })
    Write-JsonCreate $Path ([ordered]@{
        schemaVersion = 1
        authority = 'UNSIGNED_REVIEW_INPUT_ONLY'
        repository = 'fixture-owner/fixture-launcher'
        releaseId = $releaseId
        launcherSourceCommit = $launcherCommit
        immutableReservationTag = "ensou-dsh-source-candidate/$releaseId"
        inputs = $files
    })
}

function Invoke-PublisherChild([string]$RecordPath, [string]$RecordSha256, [string]$Workspace) {
    $psi = [Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = Join-Path $PSHOME 'pwsh.exe'
    $psi.ArgumentList.Add('-NoProfile'); $psi.ArgumentList.Add('-NonInteractive')
    $psi.ArgumentList.Add('-File'); $psi.ArgumentList.Add($publisherPath)
    $psi.ArgumentList.Add('-LocalReviewedPublicationInputPath'); $psi.ArgumentList.Add($RecordPath)
    $psi.ArgumentList.Add('-ExpectedLocalReviewedPublicationInputSha256'); $psi.ArgumentList.Add($RecordSha256)
    $psi.ArgumentList.Add('-LocalVerificationWorkspace'); $psi.ArgumentList.Add($Workspace)
    $psi.ArgumentList.Add('-RuntimeProfile'); $psi.ArgumentList.Add('enterprise-direct-local')
    $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
    foreach ($entry in [Environment]::GetEnvironmentVariables('Process').GetEnumerator()) {
        if ($entry.Key -cne 'GH_TOKEN') { $psi.EnvironmentVariables[[string]$entry.Key] = [string]$entry.Value }
    }
    foreach ($name in @($psi.EnvironmentVariables.Keys)) {
        if ([string]$name -ieq 'GH_TOKEN') { [void]$psi.EnvironmentVariables.Remove($name) }
    }
    if (@($psi.EnvironmentVariables.Keys | Where-Object { [string]$_ -ieq 'GH_TOKEN' }).Count -ne 0) {
        throw 'Publisher child environment still contains GH_TOKEN.'
    }
    $process = [Diagnostics.Process]::new(); $process.StartInfo = $psi
    if (-not $process.Start()) { throw 'Could not start bounded publisher child.' }
    try {
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(60000)) {
            try { $process.Kill($true) } catch { $process.Kill() }
            [void]$process.WaitForExit(5000)
            throw 'Publisher child exceeded 60-second bound.'
        }
        [pscustomobject]@{ ExitCode = $process.ExitCode; Output = $stdout.GetAwaiter().GetResult() + $stderr.GetAwaiter().GetResult() }
    }
    finally { $process.Dispose() }
}

$checks = 0
try {
    [IO.Directory]::CreateDirectory($fixtureRoot) | Out-Null
    [IO.Directory]::CreateDirectory($recordRoot) | Out-Null
    $artifactPath = Join-Path $fixtureRoot "EnsouDshRuntime-$releaseId-win-x64.zip"
    $metadataPath = Join-Path $fixtureRoot "EnsouDshRuntime-$releaseId-win-x64.metadata.json"
    $hashPath = Join-Path $fixtureRoot "EnsouDshRuntime-$releaseId-win-x64.zip.sha256"
    $managedPath = Join-Path $fixtureRoot 'managed-candidate.json'
    $recordPath = Join-Path $recordRoot 'local-reviewed-source-runtime-publication.v1.json'
    [IO.File]::WriteAllBytes($artifactPath, [byte[]](0x45, 0x4E, 0x53, 0x4F, 0x55, 0x2D, 0x46, 0x49, 0x58, 0x54, 0x55, 0x52, 0x45))
    $artifactHash = Get-Sha256 $artifactPath

    $metadata = Get-Content -LiteralPath $sourceMetadata.FullName -Raw | ConvertFrom-Json -Depth 64
    $metadata.releaseId = $releaseId
    $metadata.artifact.fileName = [IO.Path]::GetFileName($artifactPath)
    $metadata.artifact.sizeBytes = [IO.FileInfo]::new($artifactPath).Length
    $metadata.artifact.sha256 = $artifactHash
    Write-JsonCreate $metadataPath $metadata
    [IO.File]::WriteAllText($hashPath, "$artifactHash  $([IO.Path]::GetFileName($artifactPath))`n", [Text.Encoding]::ASCII)
    $managed = [ordered]@{
        artifact = $metadata.artifact; launcherRepositoryCommit = $launcherCommit
        launcherVersion = '0.1.0'; managedPatch = $metadata.managedPatch; managedPolicy = $metadata.managedPolicy
        minimumBootstrapperVersion = '0.1.0'; promotionEligible = $true; releaseId = $releaseId
        remainingGates = @('Ensou application code signing', 'release manifest signing', 'Lab', 'Pilot', 'legal review')
        runtimeWebAuthProtocol = $metadata.runtimeWebAuthProtocol; schemaVersion = 1; sourceBuilt = $true; stableEligible = $false
        upstreamCommit = $metadata.sourceCommit; upstreamTag = $metadata.sourceTag; upstreamTree = $metadata.sourceTree
    }
    Write-JsonCreate $managedPath $managed
    New-LocalReviewedRecord $recordPath $artifactPath $metadataPath $hashPath $managedPath
    $recordSha256 = Get-Sha256 $recordPath

    $bad = Get-Content -LiteralPath $metadataPath -Raw | ConvertFrom-Json -Depth 64
    $bad.runtimeProfile = 'enterprise-managed'
    Write-JsonCreate $metadataPath $bad
    New-LocalReviewedRecord $recordPath $artifactPath $metadataPath $hashPath $managedPath
    $badResult = Invoke-PublisherChild $recordPath (Get-Sha256 $recordPath) (Join-Path $fixtureRoot 'bad-workspace')
    if ($badResult.ExitCode -eq 0 -or $badResult.Output -notmatch 'runtimeProfile' -or
        $badResult.Output -notmatch 'enterprise-direct-local') {
        $safeBadOutput = [Regex]::Replace($badResult.Output, '(?i)(key|secret|token|password)[^\r\n]*', '$1=<redacted>')
        throw ('Changed direct-local profile did not fail before the GH_TOKEN publication gate. Synthetic output: ' + $safeBadOutput)
    }
    $checks++

    Write-JsonCreate $metadataPath $metadata
    New-LocalReviewedRecord $recordPath $artifactPath $metadataPath $hashPath $managedPath
    $goodResult = Invoke-PublisherChild $recordPath (Get-Sha256 $recordPath) (Join-Path $fixtureRoot 'good-workspace')
    $normalizedGoodOutput = [Regex]::Replace($goodResult.Output, '\s+', ' ')
    if ($goodResult.ExitCode -eq 0 -or $goodResult.Output -notmatch '(?s)GH_TOKEN is required only for the controlled candidate publication.*transaction\.') {
        throw 'Actual metadata/candidate validation did not reach the expected no-token publication gate.'
    }
    $checks++
    Write-Output "PASS DirectLocal source publication preflight: $checks checks; local validation only; no publish/network mutation."
}
finally {
    $fullFixture = [IO.Path]::GetFullPath($fixtureRoot)
    $leaf = [IO.Path]::GetFileName($fullFixture)
    if (-not $fullFixture.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -or
        $fullFixture -eq $tempRoot -or $leaf -notmatch '^direct-local-publication-preflight-[0-9a-f]{32}$') {
        throw 'Fixture cleanup bounds rejected.'
    }
    if ([IO.Directory]::Exists($fullFixture)) {
        $item = Get-Item -LiteralPath $fullFixture -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Fixture cleanup refuses a reparse-point root.' }
        Remove-Item -LiteralPath $fullFixture -Recurse -Force
    }
    $fullRecordRoot = [IO.Path]::GetFullPath($recordRoot)
    $recordLeaf = [IO.Path]::GetFileName($fullRecordRoot)
    if (-not $fullRecordRoot.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -or
        $recordLeaf -notmatch '^direct-local-publication-record-[0-9a-f]{32}$') {
        throw 'Record cleanup bounds rejected.'
    }
    if ([IO.Directory]::Exists($fullRecordRoot)) { Remove-Item -LiteralPath $fullRecordRoot -Recurse -Force }
}
