#requires -Version 7.2

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$payloadScript = Join-Path $PSScriptRoot `
    'New-PersonalDevelopmentInstallerPayload.ps1'
$runtimeBuilder = Join-Path $PSScriptRoot `
    'New-PersonalSourceRuntimeArtifact.ps1'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$metadataExample = Join-Path $repositoryRoot `
    'release\examples\source-runtime.metadata.json'
$runtimeReleaseId = 'managed-v2099.01.02.1'
$tempParent = Join-Path ([IO.Path]::GetTempPath()) `
    'ensou-personal-development-runtime-payload-tests'
$testRoot = Join-Path $tempParent ([Guid]::NewGuid().ToString('N'))
$utf8 = [Text.UTF8Encoding]::new($false, $true)
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

function Get-BytesSha256 {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    return ([Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($Bytes))).ToLowerInvariant()
}

function Get-DefaultPublisherAnchorState {
    $localApplicationData = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::LocalApplicationData,
        [Environment+SpecialFolderOption]::DoNotVerify)
    if ([string]::IsNullOrWhiteSpace($localApplicationData)) {
        throw 'Cannot resolve the CurrentUser Personal publisher anchor root.'
    }
    $anchorIdentityText = @(
        'ensou-dsh-personal',
        'production',
        'stable',
        'personal-publisher-signing-ledger-anchor-authority-v1') -join '|'
    $anchorIdentity = Get-BytesSha256 `
        ([Text.Encoding]::UTF8.GetBytes($anchorIdentityText))
    $anchorPath = Join-Path (Join-Path (Join-Path (Join-Path `
        $localApplicationData 'Ensou') 'Dsh') `
        'PersonalReleasePublisher\SigningLedgerAnchors') `
        "$anchorIdentity.dpapi"
    return (@($anchorPath, $anchorPath + '.pending', $anchorPath + '.lock') |
        ForEach-Object {
            $path = $_
            if (-not (Test-Path -LiteralPath $path)) {
                return "$path|absent"
            }
            $item = Get-Item -LiteralPath $path -Force
            $kind = if ($item.PSIsContainer) { 'directory' } else { 'file' }
            $sha256 = if (-not $item.PSIsContainer -and
                ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) {
                Get-FileSha256 $path
            } else {
                '-'
            }
            $length = if ($item.PSIsContainer) { -1 } else { $item.Length }
            "$path|$kind|$([int]$item.Attributes)|$length|$sha256|$($item.LastWriteTimeUtc.Ticks)"
        }) -join "`n"
}

function Get-IsolatedDevelopmentAnchorPath {
    param([Parameter(Mandatory = $true)][string]$WorkDirectory)

    $authorityRoot = Join-Path $WorkDirectory `
        'signing-ledger-anchor-authority'
    Assert-True `
        (Test-Path -LiteralPath $authorityRoot -PathType Container) `
        'Development payload did not create its isolated signing-ledger anchor authority.'
    $anchors = @(Get-ChildItem -LiteralPath $authorityRoot `
        -Filter '*.dpapi' -File -Force)
    Assert-True ($anchors.Count -eq 1) `
        'Development payload did not create exactly one isolated DPAPI anchor.'
    Assert-True ($anchors[0].Length -gt 0) `
        'Development payload created an empty isolated DPAPI anchor.'
    return $anchors[0].FullName
}

function ConvertTo-Base64Url {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    return [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Add-ZipBytes {
    param(
        [Parameter(Mandatory = $true)][IO.Compression.ZipArchive]$Archive,
        [Parameter(Mandatory = $true)][string]$EntryName,
        [Parameter(Mandatory = $true)][byte[]]$Bytes
    )

    $entry = $Archive.CreateEntry(
        $EntryName,
        [IO.Compression.CompressionLevel]::Optimal)
    $entry.LastWriteTime = [DateTimeOffset]::new(
        1980, 1, 1, 0, 0, 0, [TimeSpan]::Zero)
    $entry.ExternalAttributes = 0
    $output = $entry.Open()
    try {
        $output.Write($Bytes, 0, $Bytes.Length)
    } finally {
        $output.Dispose()
    }
}

function New-PersonalArtifact {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Component,
        [Parameter(Mandatory = $true)][string]$ReleaseId,
        [Parameter(Mandatory = $true)][Collections.IDictionary]$Files,
        [string]$TamperArchivePath = ''
    )

    $root = Join-Path $testRoot $Name
    [IO.Directory]::CreateDirectory($root) | Out-Null
    [string[]]$paths = @($Files.Keys)
    [Array]::Sort($paths, [StringComparer]::Ordinal)
    $descriptors = [Collections.Generic.List[object]]::new()
    foreach ($path in $paths) {
        [byte[]]$bytes = $Files[$path]
        $descriptors.Add([ordered]@{
            path = $path
            sizeBytes = $bytes.LongLength
            sha256 = Get-BytesSha256 $bytes
        })
    }
    $treeBytes = $utf8.GetBytes(([ordered]@{
        schemaVersion = 1
        component = $Component
        releaseId = $ReleaseId
        files = $descriptors
    } | ConvertTo-Json -Depth 6 -Compress))
    $treePath = Join-Path $root "$Name.complete-tree.json"
    [IO.File]::WriteAllBytes($treePath, $treeBytes)

    Add-Type -AssemblyName System.IO.Compression
    $archivePath = Join-Path $root "$Name.zip"
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
            [string[]]$entryPaths = @($paths) + '.ensou-complete-tree.v1.json'
            [Array]::Sort($entryPaths, [StringComparer]::Ordinal)
            foreach ($path in $entryPaths) {
                if ($path -ceq '.ensou-complete-tree.v1.json') {
                    [byte[]]$bytes = $treeBytes
                } elseif ($path -ceq $TamperArchivePath) {
                    [byte[]]$bytes = $utf8.GetBytes('tampered archive bytes')
                } else {
                    [byte[]]$bytes = $Files[$path]
                }
                Add-ZipBytes -Archive $archive -EntryName $path -Bytes $bytes
            }
        } finally {
            $archive.Dispose()
        }
        $stream.Flush($true)
    } finally {
        $stream.Dispose()
    }

    return [pscustomobject]@{
        ArchivePath = $archivePath
        CompleteTreePath = $treePath
        ReleaseId = $ReleaseId
    }
}

function New-SourceRuntimeArtifact {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [int]$Variant = 0,
        [string]$FixtureReleaseId = $runtimeReleaseId,
        [bool]$PromotionEligible = $true
    )

    $root = Join-Path $testRoot "source-$Name"
    [IO.Directory]::CreateDirectory($root) | Out-Null
    $nodeBytes = [byte[]]::new(4096)
    $nodeBytes[0] = 0x4D
    $nodeBytes[1] = 0x5A
    for ($index = 2; $index -lt $nodeBytes.Length; $index++) {
        $nodeBytes[$index] = [byte](($index * 31 + $Variant) % 251)
    }
    $builtAt = [DateTimeOffset]::UtcNow.ToString(
        'O',
        [Globalization.CultureInfo]::InvariantCulture)
    $metadata = Get-Content -Raw -LiteralPath $metadataExample |
        ConvertFrom-Json -Depth 20
    $metadata.releaseId = $FixtureReleaseId
    $metadata.promotionEligible = $PromotionEligible
    $metadata.builtAtUtc = $builtAt
    $metadata.toolchain.nodeSha256 = Get-BytesSha256 $nodeBytes
    $sourceBuildBytes = $utf8.GetBytes(([ordered]@{
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
    } | ConvertTo-Json -Depth 5 -Compress))
    $files = [ordered]@{
        'LICENSE' = $utf8.GetBytes('fixture license')
        'node.exe' = $nodeBytes
        'node_modules/@deepseek-ai/dsh/lib/bin.js' =
            $utf8.GetBytes("#!/usr/bin/env node`nconsole.log('fixture');`n")
        'source-build.json' = $sourceBuildBytes
    }
    [string[]]$paths = @($files.Keys)
    [Array]::Sort($paths, [StringComparer]::Ordinal)
    $hashLines = @($paths | ForEach-Object {
        '{0}  {1}' -f (Get-BytesSha256 ([byte[]]$files[$_])), $_
    })
    $files['runtime-files.sha256'] =
        [Text.Encoding]::ASCII.GetBytes(($hashLines -join "`n") + "`n")

    Add-Type -AssemblyName System.IO.Compression
    $archiveName = "EnsouDshRuntime-$FixtureReleaseId-win-x64.zip"
    $archivePath = Join-Path $root $archiveName
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
            [string[]]$archivePaths = @($files.Keys)
            [Array]::Sort($archivePaths, [StringComparer]::Ordinal)
            foreach ($path in $archivePaths) {
                Add-ZipBytes `
                    -Archive $archive `
                    -EntryName $path `
                    -Bytes ([byte[]]$files[$path])
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
    $metadataPath = Join-Path $root `
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
    $runtimeBuilderArguments = @{
        SourceRuntimeArchivePath = $archivePath
        SourceRuntimeMetadataPath = $metadataPath
        SourceRuntimeHashEvidencePath = $hashPath
        ReleaseId = $FixtureReleaseId
        OutputDirectory = Join-Path $root 'output'
        WorkDirectory = Join-Path $root 'work'
    }
    if (-not $PromotionEligible) {
        $runtimeBuilderArguments.AllowLocalLab = $true
    }
    $result = @(& $runtimeBuilder @runtimeBuilderArguments)
    Assert-True ($result.Count -eq 1) `
        'Source-runtime builder did not return one artifact descriptor.'
    return $result[0]
}

function Copy-BuilderClosure {
    param(
        [Parameter(Mandatory = $true)]$Artifact,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $root = Join-Path $testRoot "closure-$Name"
    [IO.Directory]::CreateDirectory($root) | Out-Null
    $sourceDescriptor = Get-Content -Raw -LiteralPath `
        $Artifact.ArtifactDescriptorPath | ConvertFrom-Json -Depth 20
    $archivePath = Join-Path $root ([IO.Path]::GetFileName($Artifact.ArchivePath))
    $treePath = Join-Path $root `
        ([IO.Path]::GetFileName($Artifact.CompleteTreeManifestPath))
    $descriptorPath = Join-Path $root `
        ([IO.Path]::GetFileName($Artifact.ArtifactDescriptorPath))
    [IO.File]::Copy($Artifact.ArchivePath, $archivePath, $false)
    [IO.File]::Copy($Artifact.CompleteTreeManifestPath, $treePath, $false)
    $sourceDescriptor.archive.path = $archivePath
    $sourceDescriptor.completeTree.path = $treePath
    [IO.File]::WriteAllText(
        $descriptorPath,
        ($sourceDescriptor | ConvertTo-Json -Depth 20 -Compress),
        $utf8)
    return [pscustomobject]@{
        ArchivePath = $archivePath
        CompleteTreeManifestPath = $treePath
        ArtifactDescriptorPath = $descriptorPath
    }
}

function New-RepackedArchive {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination,
        [string]$TamperEntry = ''
    )

    $input = [IO.Compression.ZipFile]::OpenRead($Source)
    $outputStream = [IO.File]::Open(
        $Destination,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::None)
    try {
        $output = [IO.Compression.ZipArchive]::new(
            $outputStream,
            [IO.Compression.ZipArchiveMode]::Create,
            $true)
        try {
            foreach ($entry in @($input.Entries | Sort-Object FullName -Descending)) {
                $replacement = $output.CreateEntry(
                    $entry.FullName,
                    [IO.Compression.CompressionLevel]::NoCompression)
                $replacement.LastWriteTime = $entry.LastWriteTime
                $replacement.ExternalAttributes = $entry.ExternalAttributes
                $sourceStream = $entry.Open()
                $destinationStream = $replacement.Open()
                try {
                    if ($entry.FullName -ceq $TamperEntry) {
                        $tamperedBytes = $utf8.GetBytes('tampered runtime bytes')
                        $destinationStream.Write(
                            $tamperedBytes,
                            0,
                            $tamperedBytes.Length)
                    } else {
                        $sourceStream.CopyTo($destinationStream)
                    }
                } finally {
                    $destinationStream.Dispose()
                    $sourceStream.Dispose()
                }
            }
        } finally {
            $output.Dispose()
        }
        $outputStream.Flush($true)
    } finally {
        $outputStream.Dispose()
        $input.Dispose()
    }
}

function New-TypeTamperedRuntimeClosure {
    param(
        [Parameter(Mandatory = $true)]$Artifact,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)]
        [ValidateSet('StringSchemaVersion', 'ArrayProtocol', 'ArrayTag')]
        [string]$SourceBuildTypeTamper
    )

    $closure = Copy-BuilderClosure -Artifact $Artifact -Name $Name
    $entryBytes = [ordered]@{}
    $input = [IO.Compression.ZipFile]::OpenRead($closure.ArchivePath)
    try {
        foreach ($entry in $input.Entries) {
            $entryStream = $entry.Open()
            $memory = [IO.MemoryStream]::new()
            try {
                $entryStream.CopyTo($memory)
                $entryBytes[$entry.FullName] = $memory.ToArray()
            } finally {
                $memory.Dispose()
                $entryStream.Dispose()
            }
        }
    } finally {
        $input.Dispose()
    }

    [byte[]]$oldSourceBuildBytes = $entryBytes['source-build.json']
    [byte[]]$oldHashManifestBytes = $entryBytes['runtime-files.sha256']
    $sourceBuild = $utf8.GetString($oldSourceBuildBytes) |
        ConvertFrom-Json -Depth 20
    switch ($SourceBuildTypeTamper) {
        'StringSchemaVersion' {
            $sourceBuild.schemaVersion = '3'
        }
        'ArrayProtocol' {
            $sourceBuild.runtimeWebAuthProtocol = [object[]]@(
                [string]$sourceBuild.runtimeWebAuthProtocol)
        }
        'ArrayTag' {
            $sourceBuild.sourceTag = [object[]]@(
                [string]$sourceBuild.sourceTag)
        }
    }
    [byte[]]$newSourceBuildBytes = $utf8.GetBytes(
        ($sourceBuild | ConvertTo-Json -Depth 20 -Compress))
    $newSourceBuildSha256 = Get-BytesSha256 $newSourceBuildBytes

    $hashLines = [Collections.Generic.List[string]]::new()
    $sourceBuildBindings = 0
    foreach ($line in ([Text.Encoding]::ASCII.GetString(
                $oldHashManifestBytes) -split "`r?`n")) {
        if ([string]::IsNullOrEmpty($line)) {
            continue
        }
        if ($line -match '\A[0-9a-f]{64}  source-build\.json\z') {
            $sourceBuildBindings++
            $hashLines.Add("$newSourceBuildSha256  source-build.json")
        } else {
            $hashLines.Add($line)
        }
    }
    Assert-True ($sourceBuildBindings -eq 1) `
        'Type-tamper fixture did not find one source-build hash binding.'
    [byte[]]$newHashManifestBytes = [Text.Encoding]::ASCII.GetBytes(
        ($hashLines -join "`n") + "`n")

    $tree = Get-Content -Raw -LiteralPath `
        $closure.CompleteTreeManifestPath | ConvertFrom-Json -Depth 20
    foreach ($binding in @(
        [pscustomobject]@{
            Path = 'source-build.json'
            Bytes = $newSourceBuildBytes
        },
        [pscustomobject]@{
            Path = 'runtime-files.sha256'
            Bytes = $newHashManifestBytes
        })) {
        $records = @($tree.files | Where-Object {
            $_.path -ceq $binding.Path
        })
        Assert-True ($records.Count -eq 1) `
            "Type-tamper fixture lacks one $($binding.Path) tree binding."
        [byte[]]$bindingBytes = $binding.Bytes
        $records[0].sizeBytes = $bindingBytes.LongLength
        $records[0].sha256 = Get-BytesSha256 $bindingBytes
    }
    [byte[]]$newTreeBytes = $utf8.GetBytes(
        ($tree | ConvertTo-Json -Depth 20 -Compress))

    $entryBytes['source-build.json'] = $newSourceBuildBytes
    $entryBytes['runtime-files.sha256'] = $newHashManifestBytes
    $entryBytes['.ensou-complete-tree.v1.json'] = $newTreeBytes
    $rebuiltArchivePath = Join-Path $testRoot "$Name-rebuilt.zip"
    $outputStream = [IO.File]::Open(
        $rebuiltArchivePath,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::None)
    try {
        $output = [IO.Compression.ZipArchive]::new(
            $outputStream,
            [IO.Compression.ZipArchiveMode]::Create,
            $true)
        try {
            [string[]]$entryPaths = @($entryBytes.Keys)
            [Array]::Sort($entryPaths, [StringComparer]::Ordinal)
            foreach ($entryPath in $entryPaths) {
                Add-ZipBytes `
                    -Archive $output `
                    -EntryName $entryPath `
                    -Bytes ([byte[]]$entryBytes[$entryPath])
            }
        } finally {
            $output.Dispose()
        }
        $outputStream.Flush($true)
    } finally {
        $outputStream.Dispose()
    }
    [IO.File]::Delete($closure.ArchivePath)
    [IO.File]::Move($rebuiltArchivePath, $closure.ArchivePath)
    [IO.File]::WriteAllBytes(
        $closure.CompleteTreeManifestPath,
        $newTreeBytes)

    $descriptor = Get-Content -Raw -LiteralPath `
        $closure.ArtifactDescriptorPath | ConvertFrom-Json -Depth 20
    $descriptor.archive.sizeBytes =
        (Get-Item -LiteralPath $closure.ArchivePath).Length
    $descriptor.archive.sha256 = Get-FileSha256 $closure.ArchivePath
    $descriptor.completeTree.sizeBytes = $newTreeBytes.LongLength
    $descriptor.completeTree.sha256 = Get-BytesSha256 $newTreeBytes
    $descriptor.sourceRuntime.provenance.sizeBytes =
        $newSourceBuildBytes.LongLength
    $descriptor.sourceRuntime.provenance.sha256 = $newSourceBuildSha256
    $descriptor.expandedSizeBytes = [int64]$descriptor.expandedSizeBytes +
        ($newSourceBuildBytes.LongLength - $oldSourceBuildBytes.LongLength) +
        ($newHashManifestBytes.LongLength - $oldHashManifestBytes.LongLength)
    [IO.File]::WriteAllText(
        $closure.ArtifactDescriptorPath,
        ($descriptor | ConvertTo-Json -Depth 20 -Compress),
        $utf8)
    return $closure
}

function New-InvocationPaths {
    param([Parameter(Mandatory = $true)][string]$Name)

    $root = Join-Path $testRoot "invocation-$Name"
    [IO.Directory]::CreateDirectory($root) | Out-Null
    return [pscustomobject]@{
        Output = Join-Path $root 'output'
        Work = Join-Path $root 'work'
    }
}

function Invoke-Payload {
    param(
        [Parameter(Mandatory = $true)]$Paths,
        $RuntimeArtifact = $null,
        [scriptblock]$LockedObserver = $null,
        [switch]$AllowLocalLab
    )

    $arguments = @{
        StartupStubPath = $script:startupStub
        ClientBundleArchivePath = $script:clientArtifact.ArchivePath
        ClientBundleCompleteTreePath = $script:clientArtifact.CompleteTreePath
        TrustDescriptorPath = $script:trustPath
        OutputDirectory = $Paths.Output
        WorkDirectory = $Paths.Work
    }
    if ($null -ne $RuntimeArtifact) {
        $arguments.RuntimeArtifactDescriptorPath =
            $RuntimeArtifact.ArtifactDescriptorPath
        if ($null -ne $LockedObserver) {
            $arguments.RuntimeArtifactLockedObserver = $LockedObserver
        }
        if ($AllowLocalLab) {
            $arguments.AllowLocalLab = $true
        }
    }
    & $payloadScript @arguments | Out-Null
    return Get-Content -Raw -LiteralPath `
        (Join-Path $Paths.Work 'development-payload.json') |
        ConvertFrom-Json -Depth 10
}

function Assert-InvocationFails {
    param(
        [Parameter(Mandatory = $true)]$Paths,
        [Parameter(Mandatory = $true)]$RuntimeArtifact,
        [Parameter(Mandatory = $true)][string]$Label,
        [string]$ExpectedErrorPattern = ''
    )

    $failed = $false
    $failureText = ''
    try {
        Invoke-Payload `
            -Paths $Paths `
            -RuntimeArtifact $RuntimeArtifact | Out-Null
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
        (-not (Test-Path -LiteralPath (Join-Path $Paths.Output 'release-set.v2.json'))) `
        "$Label emitted a signed development manifest despite rejection."
    Write-Output "PASS  $Label rejected"
}

try {
    [IO.Directory]::CreateDirectory($testRoot) | Out-Null
    $startupStub = Join-Path $testRoot 'fixture-bootstrapper.exe'
    [IO.File]::WriteAllBytes(
        $startupStub,
        $utf8.GetBytes('development fixture bootstrapper'))

    $clientArtifact = New-PersonalArtifact `
        -Name 'client-bundle' `
        -Component 'client-bundle' `
        -ReleaseId 'fixture-client-v1' `
        -Files ([ordered]@{
            'Ensou.Dsh.ClientBootstrapper.exe' = $utf8.GetBytes('client bootstrapper')
            'Ensou.Dsh.Launcher.exe' = $utf8.GetBytes('launcher')
            'Ensou.Dsh.Personal.Maintenance.exe' = $utf8.GetBytes('maintenance')
        })
    $runtimeArtifact = New-SourceRuntimeArtifact -Name 'runtime-a'

    $keyPath = Join-Path $testRoot 'development-signing-key.pkcs8'
    $signer = [Security.Cryptography.ECDsa]::Create(
        [Security.Cryptography.ECCurve+NamedCurves]::nistP256)
    try {
        [IO.File]::WriteAllBytes($keyPath, $signer.ExportPkcs8PrivateKey())
        $public = $signer.ExportParameters($false)
        $trustPath = Join-Path $testRoot 'development-trust.json'
        [IO.File]::WriteAllText(
            $trustPath,
            ([ordered]@{
                schemaVersion = 1
                productionBuild = $false
                manifestOrigin = 'https://updates.example.test/'
                artifactOrigin = 'https://updates.example.test/'
                channel = 'stable'
                keyId = 'fixture-development-key'
                keyX = ConvertTo-Base64Url $public.Q.X
                keyY = ConvertTo-Base64Url $public.Q.Y
                startupStubVersion = '1.2.0'
                canonicalLowSFromSequence = 1
                authenticodeSignerSha256Thumbprint = $null
                signingPrivateKeyPkcs8Path = $keyPath
            } | ConvertTo-Json -Depth 6),
            $utf8)
    } finally {
        $signer.Dispose()
    }

    $defaultAnchorBefore = Get-DefaultPublisherAnchorState

    $defaultPaths = New-InvocationPaths 'default'
    $defaultDescriptor = Invoke-Payload -Paths $defaultPaths
    Assert-True ($defaultDescriptor.nonDistributableDevelopment -eq $true) `
        'Default development payload lacks its non-distributable marker.'
    Assert-True ($defaultDescriptor.runtimeSource -ceq 'ci-placeholder') `
        'Default CI placeholder behavior changed.'
    Assert-True ($defaultDescriptor.runtimeReleaseId -ceq 'ci-personal-runtime-v1') `
        'Default CI placeholder releaseId changed.'
    Assert-True ($defaultDescriptor.runtimePromotionEligible -eq $false) `
        'Default CI placeholder must remain explicitly non-promotable.'
    Assert-True `
        ($defaultDescriptor.runtimeArtifactTrustBoundary -ceq
            'trusted-local-development-build-account' -and
        $defaultDescriptor.runtimeArtifactAuthenticity -ceq 'not-asserted') `
        'Development payload incorrectly claims runtime artifact authenticity.'
    Assert-True `
        ($defaultDescriptor.developmentInstallDefault -ceq 'refused' -and
        $defaultDescriptor.developmentInstallOverrideArgument -ceq
            '--allow-unsigned-development-install') `
        'Development payload does not describe its fail-closed install admission.'
    Write-Output 'PASS  default CI placeholder behavior remains explicit'

    $verifiedPaths = New-InvocationPaths 'verified'
    $verifiedDescriptor = Invoke-Payload `
        -Paths $verifiedPaths `
        -RuntimeArtifact $runtimeArtifact
    Assert-True ($verifiedDescriptor.nonDistributableDevelopment -eq $true) `
        'Verified runtime development payload lacks its non-distributable marker.'
    Assert-True `
        ($verifiedDescriptor.runtimeSource -ceq 'verified-source-runtime-artifact') `
        'Verified runtime development payload has the wrong runtimeSource marker.'
    Assert-True ($verifiedDescriptor.runtimeReleaseId -ceq $runtimeArtifact.ReleaseId) `
        'Verified runtime development payload releaseId changed.'
    Assert-True ($verifiedDescriptor.runtimePromotionEligible -eq $true) `
        'Managed development payload lost its promotion eligibility identity.'
    Assert-True `
        (@($verifiedDescriptor.PSObject.Properties.Name | Where-Object {
            $_ -match '(?i)production'
        }).Count -eq 0) `
        'Development payload descriptor contains a production marker.'
    Assert-True `
        ((Get-FileSha256 (Join-Path $verifiedPaths.Output 'runtime.zip')) -ceq
            (Get-FileSha256 $runtimeArtifact.ArchivePath)) `
        'Verified runtime archive changed in the Installer payload.'
    Assert-True `
        ($verifiedDescriptor.runtimeArtifactDescriptorSha256 -ceq
            (Get-FileSha256 $runtimeArtifact.ArtifactDescriptorPath)) `
        'Development payload did not bind the exact builder descriptor.'
    $manifest = Get-Content -Raw -LiteralPath `
        (Join-Path $verifiedPaths.Output 'release-set.v2.json') |
        ConvertFrom-Json -Depth 20
    $runtimeManifestArtifact = @($manifest.artifacts | Where-Object {
        $_.component -ceq 'runtime'
    })
    Assert-True ($runtimeManifestArtifact.Count -eq 1) `
        'Development release manifest has no exact runtime artifact.'
    Assert-True `
        ($runtimeManifestArtifact[0].releaseId -ceq $runtimeArtifact.ReleaseId) `
        'Development release manifest runtime releaseId changed.'
    Assert-True `
        ($runtimeManifestArtifact[0].sha256 -ceq
            $verifiedDescriptor.runtimeArchiveSha256) `
        'Development release manifest runtime SHA changed.'
    Assert-True `
        ($runtimeManifestArtifact[0].completeTreeSha256 -ceq
            $verifiedDescriptor.runtimeCompleteTreeSha256) `
        'Development release manifest complete-tree SHA changed.'
    Write-Output 'PASS  verified source-runtime artifact enters non-distributable payload'

    $labRuntimeArtifact = New-SourceRuntimeArtifact `
        -Name 'runtime-local-lab' `
        -FixtureReleaseId 'lab-personal-development-payload' `
        -PromotionEligible:$false
    Assert-InvocationFails `
        -Paths (New-InvocationPaths 'lab-default-reject') `
        -RuntimeArtifact $labRuntimeArtifact `
        -Label 'local Lab development payload without explicit switch'
    $labPayloadPaths = New-InvocationPaths 'lab-explicit-admission'
    $labPayloadDescriptor = Invoke-Payload `
        -Paths $labPayloadPaths `
        -RuntimeArtifact $labRuntimeArtifact `
        -AllowLocalLab
    Assert-True `
        ($labPayloadDescriptor.nonDistributableDevelopment -eq $true -and
            $labPayloadDescriptor.runtimePromotionEligible -eq $false -and
            $labPayloadDescriptor.runtimeReleaseId -ceq
                'lab-personal-development-payload') `
        'Explicit local Lab development payload lost its non-distributable identity.'
    Write-Output 'PASS  explicit local Lab runtime enters only non-distributable development payload'

    foreach ($typeCase in @(
        [pscustomobject]@{
            Name = 'string-schema-version'
            Tamper = 'StringSchemaVersion'
            Label = 'source-build string schemaVersion'
        },
        [pscustomobject]@{
            Name = 'array-runtime-web-auth-protocol'
            Tamper = 'ArrayProtocol'
            Label = 'source-build array runtimeWebAuthProtocol'
        },
        [pscustomobject]@{
            Name = 'array-source-tag'
            Tamper = 'ArrayTag'
            Label = 'source-build array sourceTag'
        })) {
        $typeTamperedArtifact = New-TypeTamperedRuntimeClosure `
            -Artifact $runtimeArtifact `
            -Name $typeCase.Name `
            -SourceBuildTypeTamper $typeCase.Tamper
        Assert-InvocationFails `
            -Paths (New-InvocationPaths $typeCase.Name) `
            -RuntimeArtifact $typeTamperedArtifact `
            -Label $typeCase.Label
    }

    $defaultAnchorAfter = Get-DefaultPublisherAnchorState
    Assert-True ($defaultAnchorAfter -ceq $defaultAnchorBefore) `
        'Repeated development payload publishing changed the CurrentUser production anchor.'
    $defaultIsolatedAnchor = Get-IsolatedDevelopmentAnchorPath `
        -WorkDirectory $defaultPaths.Work
    $verifiedIsolatedAnchor = Get-IsolatedDevelopmentAnchorPath `
        -WorkDirectory $verifiedPaths.Work
    Assert-True `
        (-not [IO.Path]::GetFullPath($defaultIsolatedAnchor).Equals(
            [IO.Path]::GetFullPath($verifiedIsolatedAnchor),
            [StringComparison]::OrdinalIgnoreCase)) `
        'Repeated development payloads reused one signing-ledger anchor authority.'
    Write-Output `
        'PASS  repeated payloads use isolated anchors and preserve the CurrentUser production anchor'

    $runtimeB = New-SourceRuntimeArtifact -Name 'runtime-b' -Variant 17
    $swappedArchive = Copy-BuilderClosure `
        -Artifact $runtimeArtifact `
        -Name 'swapped-archive'
    [IO.File]::Copy(
        $runtimeB.ArchivePath,
        $swappedArchive.ArchivePath,
        $true)
    Assert-InvocationFails `
        -Paths (New-InvocationPaths 'swapped-archive') `
        -RuntimeArtifact $swappedArchive `
        -Label 'descriptor-fixed swapped archive'

    $repacked = Copy-BuilderClosure `
        -Artifact $runtimeArtifact `
        -Name 'repacked-archive'
    $repackedBytes = Join-Path $testRoot 'same-tree-different-container.zip'
    New-RepackedArchive `
        -Source $repacked.ArchivePath `
        -Destination $repackedBytes
    Assert-True `
        ((Get-FileSha256 $repackedBytes) -cne
            (Get-FileSha256 $repacked.ArchivePath)) `
        'Repacked negative fixture did not change the ZIP container bytes.'
    [IO.File]::Delete($repacked.ArchivePath)
    [IO.File]::Move($repackedBytes, $repacked.ArchivePath)
    Assert-InvocationFails `
        -Paths (New-InvocationPaths 'repacked-archive') `
        -RuntimeArtifact $repacked `
        -Label 'same tree in different ZIP container'

    $semanticTree = Copy-BuilderClosure `
        -Artifact $runtimeArtifact `
        -Name 'semantic-tree'
    [IO.File]::AppendAllText(
        $semanticTree.CompleteTreeManifestPath,
        "`n",
        $utf8)
    Assert-InvocationFails `
        -Paths (New-InvocationPaths 'semantic-tree') `
        -RuntimeArtifact $semanticTree `
        -Label 'semantic-equivalent but byte-different external tree'

    $externalHardLinkRoot = Join-Path $testRoot 'external-hardlinks'
    [IO.Directory]::CreateDirectory($externalHardLinkRoot) | Out-Null
    foreach ($hardLinkCase in @(
        @{ Name = 'descriptor'; Property = 'ArtifactDescriptorPath' },
        @{ Name = 'archive'; Property = 'ArchivePath' },
        @{ Name = 'tree'; Property = 'CompleteTreeManifestPath' }
    )) {
        $hardLinkArtifact = Copy-BuilderClosure `
            -Artifact $runtimeArtifact `
            -Name "hardlink-$($hardLinkCase.Name)"
        $targetPath = [string]$hardLinkArtifact.($hardLinkCase.Property)
        $hardLinkPath = Join-Path $externalHardLinkRoot `
            "$($hardLinkCase.Name).second-link"
        New-Item `
            -ItemType HardLink `
            -Path $hardLinkPath `
            -Target $targetPath | Out-Null
        try {
            Assert-InvocationFails `
                -Paths (New-InvocationPaths "hardlink-$($hardLinkCase.Name)") `
                -RuntimeArtifact $hardLinkArtifact `
                -Label "$($hardLinkCase.Name) NumberOfLinks != 1" `
                -ExpectedErrorPattern 'ordinary single-link'
        } finally {
            Remove-Item -LiteralPath $hardLinkPath -Force
        }
    }

    $sameRoot = Join-Path $testRoot 'invocation-same'
    [IO.Directory]::CreateDirectory($sameRoot) | Out-Null
    $samePath = Join-Path $sameRoot 'shared'
    Assert-InvocationFails `
        -Paths ([pscustomobject]@{ Output = $samePath; Work = $samePath }) `
        -RuntimeArtifact $runtimeArtifact `
        -Label 'OutputDirectory equals WorkDirectory'

    $nestedRoot = Join-Path $testRoot 'invocation-nested'
    [IO.Directory]::CreateDirectory($nestedRoot) | Out-Null
    $outer = Join-Path $nestedRoot 'outer'
    Assert-InvocationFails `
        -Paths ([pscustomobject]@{
            Output = $outer
            Work = Join-Path $outer 'work'
        }) `
        -RuntimeArtifact $runtimeArtifact `
        -Label 'WorkDirectory nested below OutputDirectory'
    Assert-InvocationFails `
        -Paths ([pscustomobject]@{
            Output = Join-Path $outer 'output'
            Work = $outer
        }) `
        -RuntimeArtifact $runtimeArtifact `
        -Label 'OutputDirectory nested below WorkDirectory'

    $runtimeClosure = Split-Path -Parent $runtimeArtifact.ArtifactDescriptorPath
    Assert-InvocationFails `
        -Paths ([pscustomobject]@{
            Output = Join-Path $runtimeClosure 'payload-output'
            Work = (New-InvocationPaths 'closure-output').Work
        }) `
        -RuntimeArtifact $runtimeArtifact `
        -Label 'OutputDirectory inside runtime input closure'
    Assert-InvocationFails `
        -Paths ([pscustomobject]@{
            Output = (New-InvocationPaths 'closure-work').Output
            Work = Join-Path $runtimeClosure 'payload-work'
        }) `
        -RuntimeArtifact $runtimeArtifact `
        -Label 'WorkDirectory inside runtime input closure'

    foreach ($junctionCase in @('output', 'work')) {
        $realParent = Join-Path $testRoot "junction-$junctionCase-real"
        $junctionParent = Join-Path $testRoot "junction-$junctionCase-link"
        [IO.Directory]::CreateDirectory($realParent) | Out-Null
        New-Item `
            -ItemType Junction `
            -Path $junctionParent `
            -Target $realParent | Out-Null
        try {
            $ordinaryPaths = New-InvocationPaths "junction-$junctionCase"
            if ($junctionCase -ceq 'output') {
                $junctionPaths = [pscustomobject]@{
                    Output = Join-Path $junctionParent 'output'
                    Work = $ordinaryPaths.Work
                }
            } else {
                $junctionPaths = [pscustomobject]@{
                    Output = $ordinaryPaths.Output
                    Work = Join-Path $junctionParent 'work'
                }
            }
            Assert-InvocationFails `
                -Paths $junctionPaths `
                -RuntimeArtifact $runtimeArtifact `
                -Label "$junctionCase directory with junction ancestor"
        } finally {
            [IO.Directory]::Delete($junctionParent)
        }
    }

    $tampered = Copy-BuilderClosure `
        -Artifact $runtimeArtifact `
        -Name 'self-consistent-tampered'
    $tamperedArchive = Join-Path $testRoot 'tampered-runtime.zip'
    New-RepackedArchive `
        -Source $tampered.ArchivePath `
        -Destination $tamperedArchive `
        -TamperEntry 'node.exe'
    [IO.File]::Delete($tampered.ArchivePath)
    [IO.File]::Move($tamperedArchive, $tampered.ArchivePath)
    $tamperedDescriptor = Get-Content -Raw -LiteralPath `
        $tampered.ArtifactDescriptorPath | ConvertFrom-Json -Depth 20
    $tamperedDescriptor.archive.sizeBytes =
        (Get-Item -LiteralPath $tampered.ArchivePath).Length
    $tamperedDescriptor.archive.sha256 = Get-FileSha256 $tampered.ArchivePath
    [IO.File]::WriteAllText(
        $tampered.ArtifactDescriptorPath,
        ($tamperedDescriptor | ConvertTo-Json -Depth 20 -Compress),
        $utf8)
    Assert-InvocationFails `
        -Paths (New-InvocationPaths 'self-consistent-tampered') `
        -RuntimeArtifact $tampered `
        -Label 'self-consistent descriptor with archive content mismatch'

    $raceArtifact = Copy-BuilderClosure `
        -Artifact $runtimeArtifact `
        -Name 'locked-race'
    $raceReplacement = Join-Path $testRoot 'locked-race-replacement.zip'
    New-RepackedArchive `
        -Source $raceArtifact.ArchivePath `
        -Destination $raceReplacement
    $raceState = [pscustomobject]@{ ReplacementBlocked = $false }
    $raceObserver = {
        param($artifact)
        try {
            [IO.File]::Move(
                $raceReplacement,
                $artifact.Archive.Path,
                $true)
        } catch {
            $raceState.ReplacementBlocked = $true
        }
    }.GetNewClosure()
    $racePaths = New-InvocationPaths 'locked-race'
    $raceDescriptor = Invoke-Payload `
        -Paths $racePaths `
        -RuntimeArtifact $raceArtifact `
        -LockedObserver $raceObserver
    $raceOutputSha = Get-FileSha256 (Join-Path $racePaths.Output 'runtime.zip')
    Assert-True `
        ($raceOutputSha -ceq $runtimeArtifact.ArchiveSha256) `
        'Locked runtime race emitted replacement bytes instead of admitted bytes.'
    Assert-True `
        ($raceDescriptor.runtimeArchiveSha256 -ceq $runtimeArtifact.ArchiveSha256) `
        'Locked runtime race descriptor changed from admitted bytes.'
    Write-Output `
        "PASS  locked replacement either failed or copied the admitted A bytes (blocked=$($raceState.ReplacementBlocked))"

    $completed = $true
    Write-Output '23/23 Personal development runtime payload checks passed.'
} finally {
    if ($completed -and (Test-Path -LiteralPath $testRoot)) {
        $resolvedRoot = [IO.Path]::GetFullPath($testRoot)
        $resolvedParent = [IO.Path]::GetFullPath($tempParent).TrimEnd(
            [IO.Path]::DirectorySeparatorChar,
            [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
        if (-not $resolvedRoot.StartsWith(
                $resolvedParent,
                [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Refusing to clean a development runtime payload test outside its temp root.'
        }
        Remove-Item -LiteralPath $resolvedRoot -Recurse -Force
    } elseif (Test-Path -LiteralPath $testRoot) {
        Write-Warning "Failed development runtime payload fixture retained at $testRoot"
    }
}
