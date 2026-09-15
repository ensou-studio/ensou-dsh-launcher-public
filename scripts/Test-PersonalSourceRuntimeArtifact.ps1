#requires -Version 7.2

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$packager = Join-Path $PSScriptRoot 'New-PersonalSourceRuntimeArtifact.ps1'
$metadataExample = Join-Path $repositoryRoot `
    'release\examples\source-runtime.metadata.json'
$releaseId = 'managed-v2099.01.01.1'
$utf8 = [Text.UTF8Encoding]::new($false, $true)
$tempParent = Join-Path ([IO.Path]::GetTempPath()) `
    'ensou-personal-source-runtime-tests'
$testRoot = Join-Path $tempParent ([Guid]::NewGuid().ToString('N'))
$completed = $false

function Assert-True {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )

    if (-not $Condition) { throw $Message }
}

function Get-FileSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)

    return ((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash).ToLowerInvariant()
}

function Add-ZipFile {
    param(
        [Parameter(Mandatory = $true)][IO.Compression.ZipArchive]$Archive,
        [Parameter(Mandatory = $true)][string]$EntryName,
        [Parameter(Mandatory = $true)][string]$SourcePath,
        [int]$ExternalAttributes = 0
    )

    $entry = $Archive.CreateEntry(
        $EntryName,
        [IO.Compression.CompressionLevel]::Optimal)
    $entry.LastWriteTime = [DateTimeOffset]::new(
        1980, 1, 1, 0, 0, 0, [TimeSpan]::Zero)
    $entry.ExternalAttributes = $ExternalAttributes
    $input = [IO.File]::OpenRead($SourcePath)
    $output = $entry.Open()
    try {
        $input.CopyTo($output)
    } finally {
        $output.Dispose()
        $input.Dispose()
    }
}

function Add-ZipBytes {
    param(
        [Parameter(Mandatory = $true)][IO.Compression.ZipArchive]$Archive,
        [Parameter(Mandatory = $true)][string]$EntryName,
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [int]$ExternalAttributes = 0
    )

    $entry = $Archive.CreateEntry(
        $EntryName,
        [IO.Compression.CompressionLevel]::Optimal)
    $entry.LastWriteTime = [DateTimeOffset]::new(
        1980, 1, 1, 0, 0, 0, [TimeSpan]::Zero)
    $entry.ExternalAttributes = $ExternalAttributes
    $output = $entry.Open()
    try {
        $output.Write($Bytes, 0, $Bytes.Length)
    } finally {
        $output.Dispose()
    }
}

function New-SourceFixture {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [ValidateSet('Valid', 'Traversal', 'Duplicate', 'Link', 'Placeholder')]
        [string]$Mode = 'Valid',
        [ValidateSet(
            'None',
            'StringSchemaVersion',
            'ArrayProtocol',
            'ArrayTag')]
        [string]$SourceBuildTypeTamper = 'None',
        [string]$FixtureReleaseId = $releaseId,
        [bool]$PromotionEligible = $true
    )

    $caseRoot = Join-Path $testRoot $Name
    $treeRoot = Join-Path $caseRoot 'tree'
    [IO.Directory]::CreateDirectory(
        (Join-Path $treeRoot 'node_modules\@deepseek-ai\dsh\lib')) |
        Out-Null
    $nodePath = Join-Path $treeRoot 'node.exe'
    if ($Mode -ceq 'Placeholder') {
        [IO.File]::WriteAllText(
            $nodePath,
            'CI-only placeholder Node runtime',
            $utf8)
    } else {
        $nodeBytes = [byte[]]::new(4096)
        $nodeBytes[0] = 0x4D
        $nodeBytes[1] = 0x5A
        for ($index = 2; $index -lt $nodeBytes.Length; $index++) {
            $nodeBytes[$index] = [byte](($index * 31) % 251)
        }
        [IO.File]::WriteAllBytes($nodePath, $nodeBytes)
    }
    $dshPath = Join-Path $treeRoot `
        'node_modules\@deepseek-ai\dsh\lib\bin.js'
    [IO.File]::WriteAllText(
        $dshPath,
        "#!/usr/bin/env node`nconsole.log('fixture');`n",
        $utf8)
    [IO.File]::WriteAllText(
        (Join-Path $treeRoot 'LICENSE'),
        'fixture license',
        $utf8)
    $metadata = Get-Content -Raw -LiteralPath $metadataExample |
        ConvertFrom-Json -Depth 20
    $builtAt = [DateTimeOffset]::UtcNow.ToString(
        'O',
        [Globalization.CultureInfo]::InvariantCulture)
    $metadata.releaseId = $FixtureReleaseId
    $metadata.promotionEligible = $PromotionEligible
    $metadata.builtAtUtc = $builtAt
    $metadata.toolchain.nodeSha256 = Get-FileSha256 $nodePath
    $sourceBuild = [ordered]@{
        schemaVersion = 3
        sourceBuilt = $true
        releaseId = $FixtureReleaseId
        promotionEligible = $PromotionEligible
        artifactType = [string]$metadata.artifactType
        sourceIdentity = [string]$metadata.sourceIdentity
        sourceRepository = [string]$metadata.sourceRepository
        sourceTag = [string]$metadata.sourceTag
        sourceCommit = [string]$metadata.sourceCommit
        sourceTree = [string]$metadata.sourceTree
        runtimeWebAuthProtocol = [string]$metadata.runtimeWebAuthProtocol
        platform = 'win32-x64'
        nodeSha256 = [string]$metadata.toolchain.nodeSha256
        buildPipeline = 'installation-owned-isolated-managed-source-v1'
        runtimeClosureAgainstPinnedSourceAndLock = $true
        managedFocusedTests = $true
        managedWindowsExcludedFocusedTests = $true
        managedRefusalSmoke = $true
        officialCheckoutUnchanged = $true
        builtAtUtc = $builtAt
    }
    switch ($SourceBuildTypeTamper) {
        'StringSchemaVersion' {
            $sourceBuild.schemaVersion = '3'
        }
        'ArrayProtocol' {
            $sourceBuild.runtimeWebAuthProtocol =
                @([string]$metadata.runtimeWebAuthProtocol)
        }
        'ArrayTag' {
            $sourceBuild.sourceTag = @([string]$metadata.sourceTag)
        }
    }
    [IO.File]::WriteAllText(
        (Join-Path $treeRoot 'source-build.json'),
        ($sourceBuild | ConvertTo-Json -Depth 5 -Compress),
        $utf8)

    [string[]]$hashedPaths = @(
        'LICENSE',
        'node.exe',
        'node_modules/@deepseek-ai/dsh/lib/bin.js',
        'source-build.json'
    )
    [Array]::Sort($hashedPaths, [StringComparer]::Ordinal)
    $hashLines = foreach ($relative in $hashedPaths) {
        $native = $relative.Replace('/', [IO.Path]::DirectorySeparatorChar)
        '{0}  {1}' -f (Get-FileSha256 (Join-Path $treeRoot $native)), $relative
    }
    [IO.File]::WriteAllLines(
        (Join-Path $treeRoot 'runtime-files.sha256'),
        $hashLines,
        [Text.Encoding]::ASCII)

    Add-Type -AssemblyName System.IO.Compression
    $archiveName = "EnsouDshRuntime-$FixtureReleaseId-win-x64.zip"
    $archivePath = Join-Path $caseRoot $archiveName
    $stream = [IO.File]::Open(
        $archivePath,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::None)
    try {
        $archive = [IO.Compression.ZipArchive]::new(
            $stream,
            [IO.Compression.ZipArchiveMode]::Create,
            $true)
        try {
            [string[]]$zipPaths = @($hashedPaths) + 'runtime-files.sha256'
            [Array]::Sort($zipPaths, [StringComparer]::Ordinal)
            foreach ($relative in $zipPaths) {
                Add-ZipFile `
                    -Archive $archive `
                    -EntryName $relative `
                    -SourcePath (Join-Path $treeRoot (
                        $relative.Replace('/', [IO.Path]::DirectorySeparatorChar)))
            }
            if ($Mode -ceq 'Traversal') {
                Add-ZipBytes `
                    -Archive $archive `
                    -EntryName '../escape.txt' `
                    -Bytes $utf8.GetBytes('escape')
            } elseif ($Mode -ceq 'Duplicate') {
                Add-ZipFile `
                    -Archive $archive `
                    -EntryName 'node.exe' `
                    -SourcePath $nodePath
            } elseif ($Mode -ceq 'Link') {
                Add-ZipBytes `
                    -Archive $archive `
                    -EntryName 'linked-runtime' `
                    -Bytes $utf8.GetBytes('node.exe') `
                    -ExternalAttributes -1610612736
            }
        } finally {
            $archive.Dispose()
        }
        $stream.Flush($true)
    } finally {
        $stream.Dispose()
    }

    $archiveItem = Get-Item -LiteralPath $archivePath -Force
    $archiveSha256 = Get-FileSha256 $archivePath
    $metadata.artifact.fileName = $archiveName
    $metadata.artifact.sizeBytes = $archiveItem.Length
    $metadata.artifact.sha256 = $archiveSha256
    $metadataPath = Join-Path $caseRoot `
        "EnsouDshRuntime-$FixtureReleaseId-win-x64.metadata.json"
    [IO.File]::WriteAllText(
        $metadataPath,
        ($metadata | ConvertTo-Json -Depth 20),
        $utf8)
    $hashPath = $archivePath + '.sha256'
    [IO.File]::WriteAllText(
        $hashPath,
        "$archiveSha256  $archiveName`n",
        [Text.Encoding]::ASCII)

    return [pscustomobject]@{
        Root = $caseRoot
        ArchivePath = $archivePath
        MetadataPath = $metadataPath
        HashPath = $hashPath
        OutputPath = Join-Path $caseRoot 'output'
        WorkPath = Join-Path $caseRoot 'work'
        ReleaseId = $FixtureReleaseId
        PromotionEligible = $PromotionEligible
    }
}

function Invoke-Packager {
    param(
        [Parameter(Mandatory = $true)]$Fixture,
        [scriptblock]$LockedObserver = $null,
        [switch]$AllowLocalLab
    )

    $arguments = @{
        SourceRuntimeArchivePath = $Fixture.ArchivePath
        SourceRuntimeMetadataPath = $Fixture.MetadataPath
        SourceRuntimeHashEvidencePath = $Fixture.HashPath
        ReleaseId = $Fixture.ReleaseId
        OutputDirectory = $Fixture.OutputPath
        WorkDirectory = $Fixture.WorkPath
    }
    if ($null -ne $LockedObserver) {
        $arguments.SourceEvidenceLockedObserver = $LockedObserver
    }
    if ($AllowLocalLab) {
        $arguments.AllowLocalLab = $true
    }
    return @(& $packager @arguments)
}

function Assert-PackagingFails {
    param(
        [Parameter(Mandatory = $true)]$Fixture,
        [Parameter(Mandatory = $true)][string]$Label,
        [string]$ExpectedErrorPattern = ''
    )

    $failed = $false
    $failureText = ''
    try {
        Invoke-Packager $Fixture | Out-Null
    } catch {
        $failed = $true
        $failureText = $_.ToString()
    }
    Assert-True $failed "$Label was accepted unexpectedly."
    if ($ExpectedErrorPattern) {
        Assert-True `
            ($failureText -match $ExpectedErrorPattern) `
            "$Label failed for the wrong reason: $failureText"
    }
    Assert-True `
        (-not (Test-Path -LiteralPath $Fixture.OutputPath)) `
        "$Label published output despite rejection."
    Write-Output "PASS  $Label rejected"
}

try {
    [IO.Directory]::CreateDirectory($testRoot) | Out-Null

    $valid = New-SourceFixture -Name 'valid'
    $result = Invoke-Packager $valid
    Assert-True ($result.Count -eq 1) `
        'Valid source-runtime packaging did not return one descriptor.'
    $descriptor = $result[0]
    Assert-True ([IO.File]::Exists($descriptor.ArchivePath)) `
        'Valid Personal runtime archive was not published.'
    Assert-True ([IO.File]::Exists($descriptor.CompleteTreeManifestPath)) `
        'Valid Personal runtime complete-tree descriptor was not published.'
    Assert-True ([IO.File]::Exists($descriptor.ArtifactDescriptorPath)) `
        'Valid Personal runtime artifact descriptor was not published.'
    Assert-True (@(Get-ChildItem -LiteralPath $valid.OutputPath -Force).Count -eq 3) `
        'Valid Personal runtime output is not the exact three-file closure.'
    $artifactDescriptorBytes = [IO.File]::ReadAllBytes(
        $descriptor.ArtifactDescriptorPath)
    $artifactDescriptor = $utf8.GetString($artifactDescriptorBytes) |
        ConvertFrom-Json -Depth 20
    Assert-True ($artifactDescriptor.schemaVersion -eq 1) `
        'Artifact descriptor schemaVersion changed.'
    Assert-True `
        ($artifactDescriptor.artifactType -ceq
            'ensou-dsh-personal-source-runtime-artifact') `
        'Artifact descriptor type changed.'
    Assert-True ($artifactDescriptor.releaseId -ceq $releaseId) `
        'Artifact descriptor releaseId changed.'
    Assert-True ($artifactDescriptor.promotionEligible -eq $true) `
        'Production Personal artifact descriptor lost promotion eligibility.'
    Assert-True ($artifactDescriptor.archive.path -ceq $descriptor.ArchivePath) `
        'Artifact descriptor does not bind the exact archive path.'
    Assert-True `
        ($artifactDescriptor.completeTree.path -ceq
            $descriptor.CompleteTreeManifestPath) `
        'Artifact descriptor does not bind the exact tree path.'
    Assert-True `
        ($artifactDescriptor.sourceRuntime.metadata.sha256 -ceq
            (Get-FileSha256 $valid.MetadataPath)) `
        'Artifact descriptor does not bind source metadata bytes.'
    Assert-True `
        ($artifactDescriptor.sourceRuntime.hashEvidence.sha256 -ceq
            (Get-FileSha256 $valid.HashPath)) `
        'Artifact descriptor does not bind source hash evidence bytes.'
    $treeBytes = [IO.File]::ReadAllBytes($descriptor.CompleteTreeManifestPath)
    $tree = $utf8.GetString($treeBytes) | ConvertFrom-Json -Depth 10
    Assert-True ($tree.schemaVersion -eq 1) 'Complete-tree schemaVersion changed.'
    Assert-True ($tree.component -ceq 'runtime') 'Complete-tree component changed.'
    Assert-True ($tree.releaseId -ceq $releaseId) 'Complete-tree releaseId changed.'
    [string[]]$treePaths = @($tree.files | ForEach-Object path)
    [string[]]$sortedPaths = $treePaths.Clone()
    [Array]::Sort($sortedPaths, [StringComparer]::Ordinal)
    Assert-True `
        (([string]::Join("`n", $treePaths)) -ceq
            ([string]::Join("`n", $sortedPaths))) `
        'Complete-tree file descriptors are not ordinal-sorted.'
    Assert-True ($treePaths -ccontains 'node.exe') `
        'Complete-tree omitted node.exe.'
    Assert-True `
        ($treePaths -ccontains 'node_modules/@deepseek-ai/dsh/lib/bin.js') `
        'Complete-tree omitted the DSH entry.'
    Assert-True ($treePaths -cnotcontains '.ensou-complete-tree.v1.json') `
        'Complete-tree recursively listed itself.'
    $sourceProvenance = @($tree.files | Where-Object path -CEQ 'source-build.json')
    Assert-True ($sourceProvenance.Count -eq 1) `
        'Complete-tree omitted exact source provenance evidence.'
    Assert-True `
        ($sourceProvenance[0].sha256 -ceq
            $artifactDescriptor.sourceRuntime.provenance.sha256) `
        'Artifact descriptor does not bind source-build.json bytes.'

    $zip = [IO.Compression.ZipFile]::OpenRead($descriptor.ArchivePath)
    try {
        $embedded = @($zip.Entries | Where-Object {
            $_.FullName -ceq '.ensou-complete-tree.v1.json'
        })
        Assert-True ($embedded.Count -eq 1) `
            'Personal runtime archive lacks one embedded complete-tree manifest.'
        $stream = $embedded[0].Open()
        $memory = [IO.MemoryStream]::new()
        try {
            $stream.CopyTo($memory)
            Assert-True `
                (([Convert]::ToHexString(
                    [Security.Cryptography.SHA256]::HashData($memory.ToArray()))) -ceq
                ([Convert]::ToHexString(
                    [Security.Cryptography.SHA256]::HashData($treeBytes)))) `
                'Embedded and external complete-tree manifests differ.'
        } finally {
            $memory.Dispose()
            $stream.Dispose()
        }
    } finally {
        $zip.Dispose()
    }
    Write-Output 'PASS  valid source-runtime converts to one Personal runtime artifact'

    Assert-PackagingFails `
        (New-SourceFixture `
            -Name 'lab-default-reject' `
            -FixtureReleaseId 'lab-personal-default-reject' `
            -PromotionEligible:$false) `
        'local Lab Personal artifact without explicit switch'
    $labFixture = New-SourceFixture `
        -Name 'lab-explicit-admission' `
        -FixtureReleaseId 'lab-personal-explicit-admission' `
        -PromotionEligible:$false
    $labResult = @(Invoke-Packager -Fixture $labFixture -AllowLocalLab)
    Assert-True ($labResult.Count -eq 1) `
        'Explicit local Lab Personal packaging did not return one artifact.'
    $labDescriptor = Get-Content -Raw -LiteralPath `
        $labResult[0].ArtifactDescriptorPath | ConvertFrom-Json -Depth 20
    Assert-True `
        ($labResult[0].PromotionEligible -eq $false -and
            $labDescriptor.promotionEligible -eq $false -and
            $labDescriptor.releaseId -ceq 'lab-personal-explicit-admission') `
        'Explicit local Lab Personal artifact lost its non-promotable identity.'
    Write-Output 'PASS  explicit local Lab source-runtime stays non-promotable'

    Assert-PackagingFails `
        (New-SourceFixture `
            -Name 'string-schema-version' `
            -SourceBuildTypeTamper StringSchemaVersion) `
        'source-build string schemaVersion'
    Assert-PackagingFails `
        (New-SourceFixture `
            -Name 'array-runtime-web-auth-protocol' `
            -SourceBuildTypeTamper ArrayProtocol) `
        'source-build array runtimeWebAuthProtocol'
    Assert-PackagingFails `
        (New-SourceFixture `
            -Name 'array-source-tag' `
            -SourceBuildTypeTamper ArrayTag) `
        'source-build array sourceTag'

    Assert-PackagingFails `
        (New-SourceFixture -Name 'traversal' -Mode Traversal) `
        'path traversal ZIP'
    Assert-PackagingFails `
        (New-SourceFixture -Name 'duplicate' -Mode Duplicate) `
        'duplicate ZIP entry'
    Assert-PackagingFails `
        (New-SourceFixture -Name 'link' -Mode Link) `
        'linked ZIP entry'
    Assert-PackagingFails `
        (New-SourceFixture -Name 'placeholder' -Mode Placeholder) `
        'CI placeholder node.exe'

    $badHash = New-SourceFixture -Name 'bad-hash'
    [IO.File]::WriteAllText(
        $badHash.HashPath,
        "$('0' * 64)  $([IO.Path]::GetFileName($badHash.ArchivePath))`n",
        [Text.Encoding]::ASCII)
    Assert-PackagingFails $badHash 'mismatched source hash evidence'

    $externalHardLinkRoot = Join-Path $testRoot 'external-hardlinks'
    [IO.Directory]::CreateDirectory($externalHardLinkRoot) | Out-Null
    foreach ($hardLinkCase in @(
        @{ Name = 'archive'; Property = 'ArchivePath' },
        @{ Name = 'metadata'; Property = 'MetadataPath' },
        @{ Name = 'hash-evidence'; Property = 'HashPath' }
    )) {
        $hardLinkFixture = New-SourceFixture `
            -Name "hardlink-$($hardLinkCase.Name)"
        $targetPath = [string]$hardLinkFixture.($hardLinkCase.Property)
        $hardLinkPath = Join-Path $externalHardLinkRoot `
            "$($hardLinkCase.Name).second-link"
        New-Item `
            -ItemType HardLink `
            -Path $hardLinkPath `
            -Target $targetPath | Out-Null
        try {
            Assert-PackagingFails `
                -Fixture $hardLinkFixture `
                -Label "source $($hardLinkCase.Name) NumberOfLinks != 1" `
                -ExpectedErrorPattern 'ordinary single-link'
        } finally {
            Remove-Item -LiteralPath $hardLinkPath -Force
        }
    }

    $lockedRace = New-SourceFixture -Name 'locked-evidence-race'
    $admittedMetadataSha = Get-FileSha256 $lockedRace.MetadataPath
    $admittedHashEvidenceSha = Get-FileSha256 $lockedRace.HashPath
    $metadataReplacement = Join-Path $testRoot 'metadata-replacement.json'
    $hashReplacement = Join-Path $testRoot 'hash-replacement.sha256'
    [IO.File]::WriteAllText($metadataReplacement, '{}', $utf8)
    [IO.File]::WriteAllText(
        $hashReplacement,
        "$('0' * 64)  replacement.zip`n",
        [Text.Encoding]::ASCII)
    $raceState = [pscustomobject]@{
        MetadataBlocked = $false
        HashEvidenceBlocked = $false
    }
    $raceObserver = {
        param($evidence)
        try {
            [IO.File]::Move(
                $metadataReplacement,
                $evidence.Metadata.Path,
                $true)
        } catch {
            $raceState.MetadataBlocked = $true
        }
        try {
            [IO.File]::Move(
                $hashReplacement,
                $evidence.HashEvidence.Path,
                $true)
        } catch {
            $raceState.HashEvidenceBlocked = $true
        }
    }.GetNewClosure()
    $raceResult = @(Invoke-Packager `
        -Fixture $lockedRace `
        -LockedObserver $raceObserver)
    Assert-True ($raceResult.Count -eq 1) `
        'Locked source-evidence race did not produce one admitted artifact.'
    $raceDescriptor = Get-Content -Raw -LiteralPath `
        $raceResult[0].ArtifactDescriptorPath | ConvertFrom-Json -Depth 20
    Assert-True `
        ($raceDescriptor.sourceRuntime.metadata.sha256 -ceq $admittedMetadataSha) `
        'Locked source-evidence race admitted replacement metadata bytes.'
    Assert-True `
        ($raceDescriptor.sourceRuntime.hashEvidence.sha256 -ceq
            $admittedHashEvidenceSha) `
        'Locked source-evidence race admitted replacement hash-evidence bytes.'
    Write-Output `
        "PASS  locked source evidence stayed on admitted bytes (metadataBlocked=$($raceState.MetadataBlocked), hashBlocked=$($raceState.HashEvidenceBlocked))"

    $completed = $true
    Write-Output '15/15 Personal source-runtime packaging checks passed.'
} finally {
    if ($completed -and (Test-Path -LiteralPath $testRoot)) {
        $resolvedRoot = [IO.Path]::GetFullPath($testRoot)
        $resolvedParent = [IO.Path]::GetFullPath($tempParent).TrimEnd(
            [IO.Path]::DirectorySeparatorChar,
            [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
        if (-not $resolvedRoot.StartsWith(
                $resolvedParent,
                [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Refusing to clean a Personal source-runtime test path outside its temp root.'
        }
        Remove-Item -LiteralPath $resolvedRoot -Recurse -Force
    } elseif (Test-Path -LiteralPath $testRoot) {
        Write-Warning "Failed Personal source-runtime fixture retained at $testRoot"
    }
}
