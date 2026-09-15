#requires -Version 7.2

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:DevelopmentConsentMarker = 'ALLOW-UNSIGNED-DEVELOPMENT-PAYLOAD.txt'
$script:PayloadFileNames = @(
    'Ensou.Dsh.Enterprise.Bootstrapper.exe',
    'enterprise-install-manifest.json',
    'launcher.zip',
    'runtime.zip')
$script:MaximumClientBytes = 512MB
$script:MaximumRuntimeBytes = 8L * 1024 * 1024 * 1024
$script:MaximumRuntimeEntries = 200000
$script:MaximumRuntimeExpandedBytes = 8L * 1024 * 1024 * 1024
$script:FixedZipTimestamp = [DateTimeOffset]::new(
    1980,
    1,
    1,
    0,
    0,
    0,
    [TimeSpan]::Zero)

$productionReleaseStateModule = [IO.Path]::GetFullPath((Join-Path `
    $PSScriptRoot `
    '..\release\scripts\ProductionReleaseState.psm1'))
Microsoft.PowerShell.Core\Import-Module `
    -Name $productionReleaseStateModule `
    -Force `
    -ErrorAction Stop

function Assert-EnterpriseProductionHost {
    if ($PSVersionTable.PSEdition -ne 'Core' -or
        $PSVersionTable.PSVersion -lt [version]'7.2') {
        throw 'Enterprise production payload packaging requires PowerShell 7.2 or newer.'
    }
    if (-not $IsWindows -or
        [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -ne
            [Runtime.InteropServices.Architecture]::X64) {
        throw 'Enterprise production payload packaging requires native Windows x64.'
    }
}

function Test-SameOrDescendantPath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Root
    )

    $candidate = [IO.Path]::TrimEndingDirectorySeparator(
        [IO.Path]::GetFullPath($Path))
    $boundary = [IO.Path]::TrimEndingDirectorySeparator(
        [IO.Path]::GetFullPath($Root))
    return $candidate.Equals($boundary, [StringComparison]::OrdinalIgnoreCase) -or
        $candidate.StartsWith(
            $boundary + [IO.Path]::DirectorySeparatorChar,
            [StringComparison]::OrdinalIgnoreCase)
}

function Resolve-EnterpriseProductionDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if (-not [IO.Path]::IsPathFullyQualified($Path) -or
        $Path.StartsWith('\\', [StringComparison]::Ordinal) -or
        $Path.StartsWith('//', [StringComparison]::Ordinal)) {
        throw "$Label must use an absolute local path."
    }
    $fullPath = [IO.Path]::GetFullPath($Path)
    $item = Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Label must be one ordinary non-linked directory: $fullPath"
    }
    for ($current = $item; $null -ne $current; $current = $current.Parent) {
        if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Label crosses a filesystem link: $fullPath"
        }
    }
    return $fullPath
}

function Get-EnterpriseProductionFileSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)

    $stream = [IO.File]::Open(
        $Path,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    try {
        return [Convert]::ToHexString(
            [Security.Cryptography.SHA256]::HashData($stream)).ToLowerInvariant()
    }
    finally {
        $stream.Dispose()
    }
}

function Get-EnterpriseProductionRelativePath {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $relative = [IO.Path]::GetRelativePath($Root, $Path).Replace('\', '/')
    if ([string]::IsNullOrWhiteSpace($relative) -or
        $relative.StartsWith('/', [StringComparison]::Ordinal) -or
        $relative -cmatch '^[A-Za-z]:' -or
        @($relative.Split('/') | Where-Object { $_ -in @('', '.', '..') }).Count -ne 0) {
        throw "Enterprise production input has an unsafe relative path: $relative"
    }
    return $relative
}

function Open-EnterpriseProductionTree {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $descriptors = [Collections.Generic.List[object]]::new()
    try {
        $entries = @(Get-ChildItem -LiteralPath $Root -Recurse -Force)
        foreach ($entry in $entries) {
            if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "$Label contains a filesystem link: $($entry.FullName)"
            }
            $relative = Get-EnterpriseProductionRelativePath `
                -Root $Root `
                -Path $entry.FullName
            if ([string]::Equals(
                    $entry.Name,
                    $script:DevelopmentConsentMarker,
                    [StringComparison]::OrdinalIgnoreCase)) {
                throw "$Label contains the forbidden Development consent marker: $relative"
            }
            if ($entry.PSIsContainer) {
                continue
            }
            $descriptor = ProductionReleaseState\Open-ProductionReleaseInput `
                -Path $entry.FullName `
                -Label "$Label file '$relative'" `
                -MaximumBytes $script:MaximumClientBytes
            Add-Member -InputObject $descriptor -NotePropertyName RelativePath -NotePropertyValue $relative
            $descriptors.Add($descriptor)
        }
        if ($descriptors.Count -eq 0) {
            throw "$Label contains no files."
        }
        $names = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase)
        foreach ($descriptor in $descriptors) {
            if (-not $names.Add([string]$descriptor.RelativePath)) {
                throw "$Label contains a case-insensitive file-name collision."
            }
        }
        return [pscustomobject]@{
            Root = $Root
            Label = $Label
            Files = @($descriptors)
        }
    }
    catch {
        for ($index = $descriptors.Count - 1; $index -ge 0; $index--) {
            $descriptors[$index].Stream.Dispose()
        }
        throw
    }
}

function Get-EnterpriseProductionTreeFile {
    param(
        [Parameter(Mandatory = $true)]$Tree,
        [Parameter(Mandatory = $true)][string]$RelativePath
    )

    $matches = @($Tree.Files | Where-Object {
        [string]$_.RelativePath -ceq $RelativePath
    })
    if ($matches.Count -ne 1) {
        throw "$($Tree.Label) must contain exactly '$RelativePath'."
    }
    return $matches[0]
}

function Assert-EnterpriseProductionTreeContract {
    param(
        [Parameter(Mandatory = $true)]$Tree,
        [Parameter(Mandatory = $true)][string]$ExpectedExecutable,
        [switch]$RequireProfile
    )

    [void](Get-EnterpriseProductionTreeFile `
        -Tree $Tree `
        -RelativePath $ExpectedExecutable)
    $forbiddenToolNames = @(
        'node.exe',
        'npm.exe',
        'npm.cmd',
        'pnpm.exe',
        'pnpm.cmd',
        'fnm.exe')
    foreach ($descriptor in $Tree.Files) {
        $relative = [string]$descriptor.RelativePath
        $leaf = [IO.Path]::GetFileName($relative)
        $segments = @($relative.Split('/'))
        if ($segments | Where-Object { $_ -in @('node_modules', '.fnm', 'fnm') }) {
            throw "$($Tree.Label) contains a forbidden toolchain directory: $relative"
        }
        if ($leaf -in $forbiddenToolNames -or
            $leaf.EndsWith('.dll', [StringComparison]::OrdinalIgnoreCase) -or
            $leaf.EndsWith('.deps.json', [StringComparison]::OrdinalIgnoreCase) -or
            $leaf.EndsWith('.runtimeconfig.json', [StringComparison]::OrdinalIgnoreCase)) {
            throw "$($Tree.Label) contains a forbidden framework or toolchain sidecar: $relative"
        }
        if ($leaf.EndsWith('.exe', [StringComparison]::OrdinalIgnoreCase) -and
            $relative -cne $ExpectedExecutable) {
            throw "$($Tree.Label) contains an unexpected executable: $relative"
        }
    }
    if ($RequireProfile) {
        $profile = Get-EnterpriseProductionTreeFile `
            -Tree $Tree `
            -RelativePath 'enterprise-build-profile.json'
        $bytes = ProductionReleaseState\Read-ProductionReleaseInputBytes `
            -Descriptor $profile `
            -Label "$($Tree.Label) production profile"
        try {
            if ($bytes.Length -gt 4096) {
                throw "$($Tree.Label) production profile exceeds its byte bound."
            }
            $value = ProductionReleaseState\ConvertFrom-StrictProductionJsonBytes `
                -Bytes $bytes `
                -Label "$($Tree.Label) production profile"
            ProductionReleaseState\Assert-ExactProductionJsonMembers `
                -Value $value `
                -Expected @('schemaVersion', 'layoutProfile') `
                -Label "$($Tree.Label) production profile"
            if ([int]$value.schemaVersion -ne 1 -or
                [string]$value.layoutProfile -cne 'enterprise') {
                throw "$($Tree.Label) does not use the production enterprise profile."
            }
        }
        finally {
            [Array]::Clear($bytes, 0, $bytes.Length)
        }
    }
}

function Assert-EnterpriseProductionAuthenticode {
    param(
        [Parameter(Mandatory = $true)]$Descriptor,
        [Parameter(Mandatory = $true)][string]$SignerSha256Thumbprint,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $signature = Microsoft.PowerShell.Security\Get-AuthenticodeSignature `
        -LiteralPath $Descriptor.Path
    if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
        [string]$signature.SignatureType -cne 'Authenticode' -or
        $null -eq $signature.SignerCertificate) {
        throw "$Label is not one valid embedded Authenticode executable."
    }
    $signer = $signature.SignerCertificate.GetCertHashString(
        [Security.Cryptography.HashAlgorithmName]::SHA256)
    if ($signer -cne $SignerSha256Thumbprint.ToUpperInvariant()) {
        throw "$Label Authenticode signer does not match the pinned SHA-256 thumbprint."
    }
    if ($null -eq $signature.TimeStamperCertificate) {
        throw "$Label has no trusted Authenticode timestamp."
    }
    $bytes = ProductionReleaseState\Read-ProductionReleaseInputBytes `
        -Descriptor $Descriptor `
        -Label $Label
    try {
        $timestamp = ProductionReleaseState\Assert-PeRfc3161Timestamp `
            -Bytes $bytes `
            -SignerCertificate $signature.SignerCertificate `
            -TimeStamperCertificate $signature.TimeStamperCertificate
        if ([string]$timestamp.TimestampProtocol -cne 'RFC3161') {
            throw "$Label did not pass canonical RFC3161 admission."
        }
        return [pscustomobject]@{
            Path = [string]$Descriptor.Path
            Sha256 = [string]$Descriptor.Sha256
            SizeBytes = [int64]$Descriptor.SizeBytes
            SignerSha256Thumbprint = $signer.ToLowerInvariant()
            TimestampProtocol = [string]$timestamp.TimestampProtocol
            TimestampSignerSha256 = [string]$timestamp.TimestampSignerSha256
        }
    }
    finally {
        [Array]::Clear($bytes, 0, $bytes.Length)
    }
}

function Read-EnterpriseProductionZipEntryBytes {
    param(
        [Parameter(Mandatory = $true)][IO.Compression.ZipArchiveEntry]$Entry,
        [Parameter(Mandatory = $true)][int64]$MaximumBytes,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ($Entry.Length -le 0 -or
        $Entry.Length -gt $MaximumBytes -or
        $Entry.Length -gt [int]::MaxValue) {
        throw "$Label is empty or exceeds its byte bound."
    }
    $stream = $Entry.Open()
    try {
        $bytes = [byte[]]::new([int]$Entry.Length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($read -le 0) {
                throw "$Label ended before its declared size."
            }
            $offset += $read
        }
        if ($stream.ReadByte() -ne -1) {
            throw "$Label exceeds its declared size."
        }
        return $bytes
    }
    finally {
        $stream.Dispose()
    }
}

function Assert-EnterpriseProductionZipEntryName {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ([string]::IsNullOrWhiteSpace($Name) -or
        $Name.Contains('\') -or
        $Name.StartsWith('/', [StringComparison]::Ordinal) -or
        $Name -cmatch '^[A-Za-z]:' -or
        $Name.Contains([char]0)) {
        throw "$Label contains an unsafe ZIP path: $Name"
    }
    $segments = @($Name.Split('/'))
    for ($index = 0; $index -lt $segments.Count; $index++) {
        $segment = $segments[$index]
        $isDirectoryMarker = $index -eq $segments.Count - 1 -and
            $segment.Length -eq 0
        if (-not $isDirectoryMarker -and
            ($segment.Length -eq 0 -or $segment -in @('.', '..'))) {
            throw "$Label contains an ambiguous ZIP path: $Name"
        }
    }
}

function Assert-EnterpriseProductionRuntimeArchive {
    param(
        [Parameter(Mandatory = $true)]$Descriptor,
        [Parameter(Mandatory = $true)][string]$ExpectedReleaseId
    )

    Add-Type -AssemblyName System.IO.Compression
    $Descriptor.Stream.Position = 0
    $archive = [IO.Compression.ZipArchive]::new(
        $Descriptor.Stream,
        [IO.Compression.ZipArchiveMode]::Read,
        $true)
    try {
        if ($archive.Entries.Count -gt $script:MaximumRuntimeEntries) {
            throw 'Enterprise production runtime archive contains too many entries.'
        }
        $seen = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase)
        $expandedBytes = 0L
        $required = [ordered]@{
            'node.exe' = $false
            'node_modules/@deepseek-ai/dsh/lib/bin.js' = $false
            'source-build.json' = $false
            'runtime-files.sha256' = $false
        }
        $sourceBuildEntry = $null
        foreach ($entry in $archive.Entries) {
            $name = [string]$entry.FullName
            Assert-EnterpriseProductionZipEntryName `
                -Name $name `
                -Label 'Enterprise production runtime archive'
            if (-not $seen.Add($name)) {
                throw "Enterprise production runtime archive repeats a path: $name"
            }
            $unixFileType = (([uint32]$entry.ExternalAttributes -shr 16) -band 0xF000)
            if ($unixFileType -eq 0xA000) {
                throw "Enterprise production runtime archive contains a symbolic link: $name"
            }
            $expandedBytes += [int64]$entry.Length
            if ($expandedBytes -gt $script:MaximumRuntimeExpandedBytes) {
                throw 'Enterprise production runtime archive exceeds its expanded byte bound.'
            }
            $leaf = [IO.Path]::GetFileName($name.TrimEnd('/'))
            if ([string]::Equals(
                    $leaf,
                    $script:DevelopmentConsentMarker,
                    [StringComparison]::OrdinalIgnoreCase)) {
                throw 'Enterprise production runtime archive contains the forbidden Development consent marker.'
            }
            if ($name.StartsWith('.git/', [StringComparison]::OrdinalIgnoreCase) -or
                $name.Contains('/.git/', [StringComparison]::OrdinalIgnoreCase) -or
                $leaf -in @('npm.exe', 'npm.cmd', 'pnpm.exe', 'pnpm.cmd', 'fnm.exe')) {
                throw "Enterprise production runtime archive contains a forbidden build tool: $name"
            }
            if ($required.Contains($name)) {
                if ($entry.Length -le 0) {
                    throw "Enterprise production runtime archive has an empty required entry: $name"
                }
                $required[$name] = $true
                if ($name -ceq 'source-build.json') {
                    $sourceBuildEntry = $entry
                }
            }
        }
        if (@($required.GetEnumerator() | Where-Object { -not $_.Value }).Count -ne 0) {
            throw 'Enterprise production runtime archive is missing node.exe, DSH, source-build.json, or runtime-files.sha256.'
        }
        $sourceBuildBytes = Read-EnterpriseProductionZipEntryBytes `
            -Entry $sourceBuildEntry `
            -MaximumBytes 1MB `
            -Label 'Enterprise production runtime source-build.json'
        try {
            $sourceBuild = ProductionReleaseState\ConvertFrom-StrictProductionJsonBytes `
                -Bytes $sourceBuildBytes `
                -Label 'Enterprise production runtime source-build.json'
            foreach ($property in @(
                    'schemaVersion',
                    'sourceBuilt',
                    'releaseId',
                    'promotionEligible',
                    'artifactType')) {
                if ($null -eq $sourceBuild.PSObject.Properties[$property]) {
                    throw "Enterprise production runtime source-build.json lacks '$property'."
                }
            }
            if ([int]$sourceBuild.schemaVersion -ne 3 -or
                [bool]$sourceBuild.sourceBuilt -ne $true -or
                [bool]$sourceBuild.promotionEligible -ne $true -or
                [string]$sourceBuild.releaseId -cne $ExpectedReleaseId -or
                [string]$sourceBuild.artifactType -cne
                    'ensou-dsh-enterprise-managed-source-runtime') {
                throw 'Enterprise production runtime is not one promotion-eligible managed source build for the requested release.'
            }
        }
        finally {
            [Array]::Clear($sourceBuildBytes, 0, $sourceBuildBytes.Length)
        }
        return [pscustomobject]@{
            Sha256 = [string]$Descriptor.Sha256
            SizeBytes = [int64]$Descriptor.SizeBytes
            EntryCount = [int]$archive.Entries.Count
            ExpandedSizeBytes = $expandedBytes
            ReleaseId = $ExpectedReleaseId
            ArtifactType = 'ensou-dsh-enterprise-managed-source-runtime'
            PromotionEligible = $true
        }
    }
    finally {
        $archive.Dispose()
        $Descriptor.Stream.Position = 0
    }
}

function Write-EnterpriseProductionDescriptor {
    param(
        [Parameter(Mandatory = $true)]$Descriptor,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $stream = [IO.FileStream]::new(
        $Path,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None,
        1MB,
        [IO.FileOptions]::WriteThrough)
    try {
        $Descriptor.Stream.Position = 0
        $Descriptor.Stream.CopyTo($stream)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
        $Descriptor.Stream.Position = 0
    }
    $item = Get-Item -LiteralPath $Path -Force
    $sha256 = Get-EnterpriseProductionFileSha256 -Path $Path
    if ($item.Length -ne [int64]$Descriptor.SizeBytes -or
        $sha256 -cne [string]$Descriptor.Sha256) {
        throw "$Label differs from its locked source bytes."
    }
    return [pscustomobject]@{
        Path = $Path
        SizeBytes = [int64]$item.Length
        Sha256 = $sha256
    }
}

function Write-EnterpriseProductionNewBytes {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][byte[]]$Bytes
    )

    $stream = [IO.FileStream]::new(
        $Path,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None,
        64KB,
        [IO.FileOptions]::WriteThrough)
    try {
        $stream.Write($Bytes)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
}

function New-EnterpriseProductionLauncherArchive {
    param(
        [Parameter(Mandatory = $true)]$LauncherTree,
        [Parameter(Mandatory = $true)]$ClientBootstrapper,
        [Parameter(Mandatory = $true)]$Maintenance,
        [Parameter(Mandatory = $true)][string]$Path
    )

    Assert-EnterpriseProductionTreeContract `
        -Tree $LauncherTree `
        -ExpectedExecutable 'Ensou.Dsh.Enterprise.Launcher.exe' `
        -RequireProfile
    if (@($LauncherTree.Files).Count -ne 2) {
        throw 'Enterprise production Launcher archive requires exactly the signed Launcher and its production profile marker.'
    }

    Add-Type -AssemblyName System.IO.Compression
    $items = [Collections.Generic.List[object]]::new()
    $names = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    foreach ($descriptor in $LauncherTree.Files) {
        $relative = [string]$descriptor.RelativePath
        if ($relative -ceq 'enterprise-build-profile.json') {
            continue
        }
        if (-not $names.Add($relative)) {
            throw "Enterprise Launcher publish repeats a case-insensitive archive path: $relative"
        }
        $items.Add([pscustomobject]@{
            RelativePath = $relative
            Descriptor = $descriptor
            Bytes = $null
        })
    }
    foreach ($addition in @(
            [pscustomobject]@{
                RelativePath = 'Ensou.Dsh.Enterprise.ClientBootstrapper.exe'
                Descriptor = $ClientBootstrapper
                Bytes = $null
            },
            [pscustomobject]@{
                RelativePath = 'Ensou.Dsh.Enterprise.Maintenance.exe'
                Descriptor = $Maintenance
                Bytes = $null
            })) {
        if (-not $names.Add([string]$addition.RelativePath)) {
            throw "Enterprise Launcher archive input collides at '$($addition.RelativePath)'."
        }
        $items.Add($addition)
    }
    $profileBytes = ProductionReleaseState\ConvertTo-ProductionJsonBytes `
        -Value ([ordered]@{
            schemaVersion = 1
            layoutProfile = 'enterprise'
        })
    if (-not $names.Add('enterprise-build-profile.json')) {
        throw "Enterprise Launcher archive input collides at 'enterprise-build-profile.json'."
    }
    $items.Add([pscustomobject]@{
        RelativePath = 'enterprise-build-profile.json'
        Descriptor = $null
        Bytes = $profileBytes
    })

    $orderedPaths = [string[]]@($items | ForEach-Object RelativePath)
    [Array]::Sort($orderedPaths, [StringComparer]::Ordinal)
    $byPath = @{}
    foreach ($item in $items) {
        $byPath[[string]$item.RelativePath] = $item
    }

    $file = [IO.FileStream]::new(
        $Path,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::None,
        1MB,
        [IO.FileOptions]::WriteThrough)
    try {
        $archive = [IO.Compression.ZipArchive]::new(
            $file,
            [IO.Compression.ZipArchiveMode]::Create,
            $true)
        try {
            foreach ($relative in $orderedPaths) {
                Assert-EnterpriseProductionZipEntryName `
                    -Name $relative `
                    -Label 'Enterprise production Launcher archive'
                $entry = $archive.CreateEntry(
                    $relative,
                    [IO.Compression.CompressionLevel]::Optimal)
                $entry.LastWriteTime = $script:FixedZipTimestamp
                $entry.ExternalAttributes = 0
                $entryStream = $entry.Open()
                try {
                    $item = $byPath[$relative]
                    if ($null -ne $item.Descriptor) {
                        $item.Descriptor.Stream.Position = 0
                        $item.Descriptor.Stream.CopyTo($entryStream)
                    }
                    else {
                        $entryStream.Write($item.Bytes, 0, $item.Bytes.Length)
                    }
                }
                finally {
                    $entryStream.Dispose()
                    if ($null -ne $byPath[$relative].Descriptor) {
                        $byPath[$relative].Descriptor.Stream.Position = 0
                    }
                }
            }
        }
        finally {
            $archive.Dispose()
        }
        $file.Flush($true)
    }
    finally {
        $file.Dispose()
    }
    $item = Get-Item -LiteralPath $Path -Force
    return [pscustomobject]@{
        Path = $Path
        SizeBytes = [int64]$item.Length
        Sha256 = Get-EnterpriseProductionFileSha256 -Path $Path
    }
}

function Assert-EnterpriseProductionPayloadInventory {
    param([Parameter(Mandatory = $true)][string]$Directory)

    $entries = @(Get-ChildItem -LiteralPath $Directory -Force)
    $names = @($entries | ForEach-Object Name)
    if ($entries.Count -ne $script:PayloadFileNames.Count -or
        @($entries | Where-Object {
            $_.PSIsContainer -or
            ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            $_.Length -le 0
        }).Count -ne 0 -or
        @(Compare-Object `
            -ReferenceObject $script:PayloadFileNames `
            -DifferenceObject $names `
            -CaseSensitive).Count -ne 0) {
        throw 'Enterprise production payload must contain exactly its four ordinary non-empty files.'
    }
    if ($names | Where-Object {
            [string]::Equals(
                $_,
                $script:DevelopmentConsentMarker,
                [StringComparison]::OrdinalIgnoreCase)
        }) {
        throw 'Enterprise production payload contains the forbidden Development consent marker.'
    }
}

function Read-EnterpriseProductionInstallManifest {
    param([Parameter(Mandatory = $true)]$Descriptor)

    $bytes = ProductionReleaseState\Read-ProductionReleaseInputBytes `
        -Descriptor $Descriptor `
        -Label 'Enterprise production install manifest'
    try {
        if ($bytes.Length -gt 128KB) {
            throw 'Enterprise production install manifest exceeds its byte bound.'
        }
        $manifest = ProductionReleaseState\ConvertFrom-StrictProductionJsonBytes `
            -Bytes $bytes `
            -Label 'Enterprise production install manifest'
        ProductionReleaseState\Assert-ExactProductionJsonMembers `
            -Value $manifest `
            -Expected @(
                'schemaVersion',
                'layoutProfile',
                'launcherReleaseId',
                'runtimeReleaseId',
                'launcherArchive',
                'launcherArchiveSizeBytes',
                'launcherArchiveSha256',
                'runtimeArchive',
                'runtimeArchiveSizeBytes',
                'runtimeArchiveSha256',
                'bootstrapperFile',
                'bootstrapperSizeBytes',
                'bootstrapperSha256',
                'publishedAtUtc') `
            -Label 'Enterprise production install manifest'
        if ([int]$manifest.schemaVersion -ne 1 -or
            [string]$manifest.layoutProfile -cne 'enterprise' -or
            [string]$manifest.launcherReleaseId -cnotmatch
                '^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$' -or
            [string]$manifest.runtimeReleaseId -cnotmatch
                '^managed-v[0-9]{4}\.[0-9]{2}\.[0-9]{2}\.[1-9][0-9]*$' -or
            [string]$manifest.launcherArchive -cne 'launcher.zip' -or
            [string]$manifest.runtimeArchive -cne 'runtime.zip' -or
            [string]$manifest.bootstrapperFile -cne
                'Ensou.Dsh.Enterprise.Bootstrapper.exe' -or
            [string]$manifest.launcherArchiveSha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [string]$manifest.runtimeArchiveSha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [string]$manifest.bootstrapperSha256 -cnotmatch '^[0-9a-f]{64}$') {
            throw 'Enterprise production install manifest violates its canonical contract.'
        }
        $published = [DateTimeOffset]::MinValue
        if (-not [DateTimeOffset]::TryParseExact(
                [string]$manifest.publishedAtUtc,
                'yyyy-MM-ddTHH:mm:ssZ',
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::AssumeUniversal -bor
                    [Globalization.DateTimeStyles]::AdjustToUniversal,
                [ref]$published)) {
            throw 'Enterprise production install manifest publishedAtUtc must be whole-second UTC.'
        }
        return $manifest
    }
    finally {
        [Array]::Clear($bytes, 0, $bytes.Length)
    }
}

function Write-EnterpriseProductionExtractedEntry {
    param(
        [Parameter(Mandatory = $true)][IO.Compression.ZipArchiveEntry]$Entry,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $input = $Entry.Open()
    $output = [IO.FileStream]::new(
        $Path,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None,
        1MB,
        [IO.FileOptions]::WriteThrough)
    try {
        $input.CopyTo($output)
        $output.Flush($true)
    }
    finally {
        $output.Dispose()
        $input.Dispose()
    }
}

function Remove-EnterpriseProductionOwnedTemporaryDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Parent,
        [Parameter(Mandatory = $true)][string]$Prefix
    )

    if (-not [IO.Directory]::Exists($Path)) {
        return
    }
    $fullPath = [IO.Path]::GetFullPath($Path)
    $fullParent = [IO.Path]::TrimEndingDirectorySeparator(
        [IO.Path]::GetFullPath($Parent))
    if ([IO.Path]::GetDirectoryName($fullPath) -cne $fullParent -or
        -not [IO.Path]::GetFileName($fullPath).StartsWith(
            $Prefix,
            [StringComparison]::Ordinal)) {
        throw 'Refusing to remove an unexpected Enterprise production temporary directory.'
    }
    Remove-Item -LiteralPath $fullPath -Recurse -Force
}

function Test-EnterpriseProductionPayload {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$PayloadDirectory,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9A-Fa-f]{64}$')]
        [string]$SignerSha256Thumbprint,

        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9A-Fa-f]{64}$')]
        [string]$ExpectedLauncherArchiveSha256,

        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9A-Fa-f]{64}$')]
        [string]$ExpectedRuntimeArchiveSha256
    )

    Assert-EnterpriseProductionHost
    $payloadRoot = Resolve-EnterpriseProductionDirectory `
        -Path $PayloadDirectory `
        -Label 'Enterprise production payload directory'
    Assert-EnterpriseProductionPayloadInventory -Directory $payloadRoot

    $descriptors = [Collections.Generic.List[object]]::new()
    $temporaryRoot = $null
    try {
        $byName = @{}
        foreach ($name in $script:PayloadFileNames) {
            $maximum = if ($name -ceq 'runtime.zip') {
                $script:MaximumRuntimeBytes
            }
            elseif ($name -ceq 'enterprise-install-manifest.json') {
                128KB
            }
            else {
                1GB
            }
            $descriptor = ProductionReleaseState\Open-ProductionReleaseInput `
                -Path (Join-Path $payloadRoot $name) `
                -Label "Enterprise production payload '$name'" `
                -MaximumBytes $maximum
            $descriptors.Add($descriptor)
            $byName[$name] = $descriptor
        }
        $manifest = Read-EnterpriseProductionInstallManifest `
            -Descriptor $byName['enterprise-install-manifest.json']
        foreach ($binding in @(
                [pscustomobject]@{
                    Name = 'launcher.zip'
                    Size = [int64]$manifest.launcherArchiveSizeBytes
                    Sha = [string]$manifest.launcherArchiveSha256
                },
                [pscustomobject]@{
                    Name = 'runtime.zip'
                    Size = [int64]$manifest.runtimeArchiveSizeBytes
                    Sha = [string]$manifest.runtimeArchiveSha256
                },
                [pscustomobject]@{
                    Name = 'Ensou.Dsh.Enterprise.Bootstrapper.exe'
                    Size = [int64]$manifest.bootstrapperSizeBytes
                    Sha = [string]$manifest.bootstrapperSha256
                })) {
            $descriptor = $byName[$binding.Name]
            if ([int64]$descriptor.SizeBytes -ne $binding.Size -or
                [string]$descriptor.Sha256 -cne $binding.Sha) {
                throw "Enterprise production payload '$($binding.Name)' differs from its manifest binding."
            }
        }
        if ([string]$byName['launcher.zip'].Sha256 -cne
                $ExpectedLauncherArchiveSha256.ToLowerInvariant()) {
            throw 'Enterprise production payload Launcher archive does not equal the exact r5 candidate Launcher archive hash.'
        }
        if ([string]$byName['runtime.zip'].Sha256 -cne
                $ExpectedRuntimeArchiveSha256.ToLowerInvariant()) {
            throw 'Enterprise production payload runtime archive does not equal the exact r5 candidate runtime archive hash.'
        }

        $bootstrapperEvidence = Assert-EnterpriseProductionAuthenticode `
            -Descriptor $byName['Ensou.Dsh.Enterprise.Bootstrapper.exe'] `
            -SignerSha256Thumbprint $SignerSha256Thumbprint `
            -Label 'Enterprise production Bootstrapper payload'
        $runtimeEvidence = Assert-EnterpriseProductionRuntimeArchive `
            -Descriptor $byName['runtime.zip'] `
            -ExpectedReleaseId ([string]$manifest.runtimeReleaseId)

        $temporaryParent = Resolve-EnterpriseProductionDirectory `
            -Path ([IO.Path]::GetTempPath()) `
            -Label 'Enterprise production self-check temporary parent'
        $temporaryRoot = Join-Path `
            $temporaryParent `
            ('ensou-enterprise-production-payload-check-' + [Guid]::NewGuid().ToString('N'))
        [IO.Directory]::CreateDirectory($temporaryRoot) | Out-Null

        $launcherDescriptor = $byName['launcher.zip']
        $launcherDescriptor.Stream.Position = 0
        $archive = [IO.Compression.ZipArchive]::new(
            $launcherDescriptor.Stream,
            [IO.Compression.ZipArchiveMode]::Read,
            $true)
        try {
            $seen = [Collections.Generic.HashSet[string]]::new(
                [StringComparer]::OrdinalIgnoreCase)
            $entriesByName = @{}
            foreach ($entry in $archive.Entries) {
                $name = [string]$entry.FullName
                Assert-EnterpriseProductionZipEntryName `
                    -Name $name `
                    -Label 'Enterprise production Launcher archive'
                if (-not $seen.Add($name)) {
                    throw "Enterprise production Launcher archive repeats a path: $name"
                }
                $unixFileType =
                    (([uint32]$entry.ExternalAttributes -shr 16) -band 0xF000)
                if ($unixFileType -eq 0xA000) {
                    throw "Enterprise production Launcher archive contains a symbolic link: $name"
                }
                $leaf = [IO.Path]::GetFileName($name.TrimEnd('/'))
                if ([string]::Equals(
                        $leaf,
                        $script:DevelopmentConsentMarker,
                        [StringComparison]::OrdinalIgnoreCase)) {
                    throw 'Enterprise production Launcher archive contains the forbidden Development consent marker.'
                }
                $entriesByName[$name] = $entry
            }
            $requiredLauncherEntries = @(
                'Ensou.Dsh.Enterprise.Launcher.exe',
                'Ensou.Dsh.Enterprise.ClientBootstrapper.exe',
                'Ensou.Dsh.Enterprise.Maintenance.exe',
                'enterprise-build-profile.json')
            $actualLauncherEntries = @($archive.Entries | ForEach-Object FullName)
            if ($archive.Entries.Count -ne $requiredLauncherEntries.Count -or
                @(Compare-Object `
                    -ReferenceObject $requiredLauncherEntries `
                    -DifferenceObject $actualLauncherEntries `
                    -CaseSensitive).Count -ne 0) {
                throw 'Enterprise production Launcher archive must contain exactly its four canonical entries.'
            }
            foreach ($name in $requiredLauncherEntries) {
                if (-not $entriesByName.ContainsKey($name) -or
                    $entriesByName[$name].Length -le 0) {
                    throw "Enterprise production Launcher archive lacks '$name'."
                }
            }
            foreach ($name in $requiredLauncherEntries[0..2]) {
                if ($entriesByName[$name].Length -gt $script:MaximumClientBytes) {
                    throw "Enterprise production Launcher archive entry '$name' exceeds its byte bound."
                }
            }
            $profileBytes = Read-EnterpriseProductionZipEntryBytes `
                -Entry $entriesByName['enterprise-build-profile.json'] `
                -MaximumBytes 4096 `
                -Label 'Enterprise production Launcher archive profile'
            try {
                $profile = ProductionReleaseState\ConvertFrom-StrictProductionJsonBytes `
                    -Bytes $profileBytes `
                    -Label 'Enterprise production Launcher archive profile'
                ProductionReleaseState\Assert-ExactProductionJsonMembers `
                    -Value $profile `
                    -Expected @('schemaVersion', 'layoutProfile') `
                    -Label 'Enterprise production Launcher archive profile'
                if ([int]$profile.schemaVersion -ne 1 -or
                    [string]$profile.layoutProfile -cne 'enterprise') {
                    throw 'Enterprise production Launcher archive carries a non-production profile.'
                }
            }
            finally {
                [Array]::Clear($profileBytes, 0, $profileBytes.Length)
            }

            $clientEvidence = [ordered]@{}
            foreach ($definition in @(
                    [pscustomobject]@{
                        Role = 'Launcher'
                        Name = 'Ensou.Dsh.Enterprise.Launcher.exe'
                    },
                    [pscustomobject]@{
                        Role = 'ClientBootstrapper'
                        Name = 'Ensou.Dsh.Enterprise.ClientBootstrapper.exe'
                    },
                    [pscustomobject]@{
                        Role = 'Maintenance'
                        Name = 'Ensou.Dsh.Enterprise.Maintenance.exe'
                    })) {
                $path = Join-Path $temporaryRoot $definition.Name
                Write-EnterpriseProductionExtractedEntry `
                    -Entry $entriesByName[$definition.Name] `
                    -Path $path
                $descriptor = ProductionReleaseState\Open-ProductionReleaseInput `
                    -Path $path `
                    -Label "Enterprise production $($definition.Role) archive entry" `
                    -MaximumBytes $script:MaximumClientBytes
                try {
                    $clientEvidence[$definition.Role] = Assert-EnterpriseProductionAuthenticode `
                        -Descriptor $descriptor `
                        -SignerSha256Thumbprint $SignerSha256Thumbprint `
                        -Label "Enterprise production $($definition.Role) archive entry"
                }
                finally {
                    $descriptor.Stream.Dispose()
                }
            }
        }
        finally {
            $archive.Dispose()
            $launcherDescriptor.Stream.Position = 0
        }

        foreach ($descriptor in $descriptors) {
            ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
                -Descriptor $descriptor `
                -Label "Enterprise production payload '$($descriptor.FileName)'"
        }
        Assert-EnterpriseProductionPayloadInventory -Directory $payloadRoot
        return [pscustomobject]@{
            Decision = 'PASS'
            PayloadDirectory = $payloadRoot
            LayoutProfile = 'enterprise'
            LauncherReleaseId = [string]$manifest.launcherReleaseId
            RuntimeReleaseId = [string]$manifest.runtimeReleaseId
            SignerSha256Thumbprint = $SignerSha256Thumbprint.ToLowerInvariant()
            ManifestSha256 = [string]$byName['enterprise-install-manifest.json'].Sha256
            LauncherArchiveSha256 = [string]$byName['launcher.zip'].Sha256
            RuntimeArchiveSha256 = [string]$byName['runtime.zip'].Sha256
            R5CandidateLauncherArchiveSha256 =
                $ExpectedLauncherArchiveSha256.ToLowerInvariant()
            R5CandidateRuntimeArchiveSha256 =
                $ExpectedRuntimeArchiveSha256.ToLowerInvariant()
            BootstrapperSha256 = [string]$byName['Ensou.Dsh.Enterprise.Bootstrapper.exe'].Sha256
            RuntimeEvidence = $runtimeEvidence
            BootstrapperEvidence = $bootstrapperEvidence
            ClientEvidence = [pscustomobject]$clientEvidence
            DevelopmentMarkerPresent = $false
        }
    }
    finally {
        if ($null -ne $temporaryRoot) {
            Remove-EnterpriseProductionOwnedTemporaryDirectory `
                -Path $temporaryRoot `
                -Parent ([IO.Path]::GetTempPath()) `
                -Prefix 'ensou-enterprise-production-payload-check-'
        }
        for ($index = $descriptors.Count - 1; $index -ge 0; $index--) {
            $descriptors[$index].Stream.Dispose()
        }
    }
}

function New-EnterpriseProductionPayload {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$')]
        [string]$LauncherReleaseId,

        [Parameter(Mandatory = $true)]
        [ValidatePattern('^managed-v[0-9]{4}\.[0-9]{2}\.[0-9]{2}\.[1-9][0-9]*$')]
        [string]$RuntimeReleaseId,

        [Parameter(Mandatory = $true)][string]$LauncherPublishDirectory,
        [Parameter(Mandatory = $true)][string]$ClientBootstrapperPublishDirectory,
        [Parameter(Mandatory = $true)][string]$MaintenancePublishDirectory,
        [Parameter(Mandatory = $true)][string]$BootstrapperPublishDirectory,
        [Parameter(Mandatory = $true)][string]$RuntimeArchivePath,

        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9A-Fa-f]{64}$')]
        [string]$ExpectedLauncherArchiveSha256,

        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9A-Fa-f]{64}$')]
        [string]$ExpectedRuntimeArchiveSha256,

        [Parameter(Mandatory = $true)][string]$OutputDirectory,

        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9A-Fa-f]{64}$')]
        [string]$SignerSha256Thumbprint,

        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$')]
        [string]$PublishedAtUtc
    )

    Assert-EnterpriseProductionHost
    $published = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParseExact(
            $PublishedAtUtc,
            'yyyy-MM-ddTHH:mm:ssZ',
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AssumeUniversal -bor
                [Globalization.DateTimeStyles]::AdjustToUniversal,
            [ref]$published)) {
        throw 'Enterprise production payload PublishedAtUtc must be valid whole-second UTC.'
    }

    $launcherRoot = Resolve-EnterpriseProductionDirectory `
        -Path $LauncherPublishDirectory `
        -Label 'Enterprise Launcher publish directory'
    $clientBootstrapperRoot = Resolve-EnterpriseProductionDirectory `
        -Path $ClientBootstrapperPublishDirectory `
        -Label 'Enterprise ClientBootstrapper publish directory'
    $maintenanceRoot = Resolve-EnterpriseProductionDirectory `
        -Path $MaintenancePublishDirectory `
        -Label 'Enterprise Maintenance publish directory'
    $bootstrapperRoot = Resolve-EnterpriseProductionDirectory `
        -Path $BootstrapperPublishDirectory `
        -Label 'Enterprise Bootstrapper publish directory'
    if (-not [IO.Path]::IsPathFullyQualified($OutputDirectory) -or
        $OutputDirectory.StartsWith('\\', [StringComparison]::Ordinal) -or
        $OutputDirectory.StartsWith('//', [StringComparison]::Ordinal)) {
        throw 'Enterprise production payload output must use an absolute local path.'
    }
    $outputRoot = [IO.Path]::GetFullPath($OutputDirectory)
    if (Test-Path -LiteralPath $outputRoot) {
        throw 'Enterprise production payload output must be one new create-only directory.'
    }
    $outputParent = Resolve-EnterpriseProductionDirectory `
        -Path ([IO.Path]::GetDirectoryName($outputRoot)) `
        -Label 'Enterprise production payload output parent'
    foreach ($inputRoot in @(
            $launcherRoot,
            $clientBootstrapperRoot,
            $maintenanceRoot,
            $bootstrapperRoot)) {
        if ((Test-SameOrDescendantPath -Path $outputRoot -Root $inputRoot) -or
            (Test-SameOrDescendantPath -Path $inputRoot -Root $outputRoot)) {
            throw 'Enterprise production payload output may not overlap an input publish directory.'
        }
    }

    $runtimeDescriptor = $null
    $trees = [Collections.Generic.List[object]]::new()
    $stagingRoot = Join-Path `
        $outputParent `
        ('.enterprise-production-payload-' + [Guid]::NewGuid().ToString('N'))
    try {
        $runtimeDescriptor = ProductionReleaseState\Open-ProductionReleaseInput `
            -Path $RuntimeArchivePath `
            -Label 'Enterprise production runtime archive' `
            -MaximumBytes $script:MaximumRuntimeBytes
        if ([IO.Path]::GetExtension($runtimeDescriptor.Path) -cne '.zip') {
            throw 'Enterprise production runtime archive must use a lowercase .zip extension.'
        }
        if ([string]$runtimeDescriptor.Sha256 -cne
                $ExpectedRuntimeArchiveSha256.ToLowerInvariant()) {
            throw 'Enterprise production runtime archive does not equal the exact r5 candidate runtime archive hash.'
        }
        if (Test-SameOrDescendantPath `
                -Path $outputRoot `
                -Root ([IO.Path]::GetDirectoryName($runtimeDescriptor.Path))) {
            throw 'Enterprise production payload output may not be inside the runtime input directory.'
        }

        $launcherTree = Open-EnterpriseProductionTree `
            -Root $launcherRoot `
            -Label 'Enterprise Launcher publish'
        $trees.Add($launcherTree)
        $clientBootstrapperTree = Open-EnterpriseProductionTree `
            -Root $clientBootstrapperRoot `
            -Label 'Enterprise ClientBootstrapper publish'
        $trees.Add($clientBootstrapperTree)
        $maintenanceTree = Open-EnterpriseProductionTree `
            -Root $maintenanceRoot `
            -Label 'Enterprise Maintenance publish'
        $trees.Add($maintenanceTree)
        $bootstrapperTree = Open-EnterpriseProductionTree `
            -Root $bootstrapperRoot `
            -Label 'Enterprise Bootstrapper publish'
        $trees.Add($bootstrapperTree)

        Assert-EnterpriseProductionTreeContract `
            -Tree $launcherTree `
            -ExpectedExecutable 'Ensou.Dsh.Enterprise.Launcher.exe' `
            -RequireProfile
        Assert-EnterpriseProductionTreeContract `
            -Tree $clientBootstrapperTree `
            -ExpectedExecutable 'Ensou.Dsh.Enterprise.ClientBootstrapper.exe' `
            -RequireProfile
        Assert-EnterpriseProductionTreeContract `
            -Tree $maintenanceTree `
            -ExpectedExecutable 'Ensou.Dsh.Enterprise.Maintenance.exe'
        Assert-EnterpriseProductionTreeContract `
            -Tree $bootstrapperTree `
            -ExpectedExecutable 'Ensou.Dsh.Enterprise.Bootstrapper.exe' `
            -RequireProfile

        $launcher = Get-EnterpriseProductionTreeFile `
            -Tree $launcherTree `
            -RelativePath 'Ensou.Dsh.Enterprise.Launcher.exe'
        $clientBootstrapper = Get-EnterpriseProductionTreeFile `
            -Tree $clientBootstrapperTree `
            -RelativePath 'Ensou.Dsh.Enterprise.ClientBootstrapper.exe'
        $maintenance = Get-EnterpriseProductionTreeFile `
            -Tree $maintenanceTree `
            -RelativePath 'Ensou.Dsh.Enterprise.Maintenance.exe'
        $bootstrapper = Get-EnterpriseProductionTreeFile `
            -Tree $bootstrapperTree `
            -RelativePath 'Ensou.Dsh.Enterprise.Bootstrapper.exe'

        $authenticodeEvidence = [ordered]@{}
        foreach ($definition in @(
                [pscustomobject]@{ Role = 'Launcher'; Descriptor = $launcher },
                [pscustomobject]@{ Role = 'ClientBootstrapper'; Descriptor = $clientBootstrapper },
                [pscustomobject]@{ Role = 'Maintenance'; Descriptor = $maintenance },
                [pscustomobject]@{ Role = 'Bootstrapper'; Descriptor = $bootstrapper })) {
            $authenticodeEvidence[$definition.Role] = Assert-EnterpriseProductionAuthenticode `
                -Descriptor $definition.Descriptor `
                -SignerSha256Thumbprint $SignerSha256Thumbprint `
                -Label "Enterprise production $($definition.Role)"
        }
        $runtimeEvidence = Assert-EnterpriseProductionRuntimeArchive `
            -Descriptor $runtimeDescriptor `
            -ExpectedReleaseId $RuntimeReleaseId

        [IO.Directory]::CreateDirectory($stagingRoot) | Out-Null
        $launcherArchive = New-EnterpriseProductionLauncherArchive `
            -LauncherTree $launcherTree `
            -ClientBootstrapper $clientBootstrapper `
            -Maintenance $maintenance `
            -Path (Join-Path $stagingRoot 'launcher.zip')
        if ([string]$launcherArchive.Sha256 -cne
                $ExpectedLauncherArchiveSha256.ToLowerInvariant()) {
            throw 'Enterprise production Launcher archive does not equal the exact r5 candidate Launcher archive hash.'
        }
        $runtimeArchive = Write-EnterpriseProductionDescriptor `
            -Descriptor $runtimeDescriptor `
            -Path (Join-Path $stagingRoot 'runtime.zip') `
            -Label 'Enterprise production runtime payload'
        $bootstrapperPayload = Write-EnterpriseProductionDescriptor `
            -Descriptor $bootstrapper `
            -Path (Join-Path $stagingRoot 'Ensou.Dsh.Enterprise.Bootstrapper.exe') `
            -Label 'Enterprise production Bootstrapper payload'

        $manifestValue = [ordered]@{
            schemaVersion = 1
            layoutProfile = 'enterprise'
            launcherReleaseId = $LauncherReleaseId
            runtimeReleaseId = $RuntimeReleaseId
            launcherArchive = 'launcher.zip'
            launcherArchiveSizeBytes = [int64]$launcherArchive.SizeBytes
            launcherArchiveSha256 = [string]$launcherArchive.Sha256
            runtimeArchive = 'runtime.zip'
            runtimeArchiveSizeBytes = [int64]$runtimeArchive.SizeBytes
            runtimeArchiveSha256 = [string]$runtimeArchive.Sha256
            bootstrapperFile = 'Ensou.Dsh.Enterprise.Bootstrapper.exe'
            bootstrapperSizeBytes = [int64]$bootstrapperPayload.SizeBytes
            bootstrapperSha256 = [string]$bootstrapperPayload.Sha256
            publishedAtUtc = $PublishedAtUtc
        }
        $manifestBytes = ProductionReleaseState\ConvertTo-ProductionJsonBytes `
            -Value $manifestValue
        Write-EnterpriseProductionNewBytes `
            -Path (Join-Path $stagingRoot 'enterprise-install-manifest.json') `
            -Bytes $manifestBytes

        Assert-EnterpriseProductionPayloadInventory -Directory $stagingRoot
        $selfCheck = Test-EnterpriseProductionPayload `
            -PayloadDirectory $stagingRoot `
            -SignerSha256Thumbprint $SignerSha256Thumbprint `
            -ExpectedLauncherArchiveSha256 $ExpectedLauncherArchiveSha256 `
            -ExpectedRuntimeArchiveSha256 $ExpectedRuntimeArchiveSha256

        foreach ($tree in $trees) {
            $actualNames = @(Get-ChildItem -LiteralPath $tree.Root -Recurse -Force |
                Where-Object { -not $_.PSIsContainer } |
                ForEach-Object {
                    Get-EnterpriseProductionRelativePath `
                        -Root $tree.Root `
                        -Path $_.FullName
                })
            $expectedNames = @($tree.Files | ForEach-Object RelativePath)
            if (@(Compare-Object `
                    -ReferenceObject $expectedNames `
                    -DifferenceObject $actualNames `
                    -CaseSensitive).Count -ne 0) {
                throw "$($tree.Label) inventory changed during production payload creation."
            }
            foreach ($descriptor in $tree.Files) {
                ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
                    -Descriptor $descriptor `
                    -Label "$($tree.Label) file '$($descriptor.RelativePath)'"
            }
        }
        ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
            -Descriptor $runtimeDescriptor `
            -Label 'Enterprise production runtime archive'
        Assert-EnterpriseProductionPayloadInventory -Directory $stagingRoot

        [IO.Directory]::Move($stagingRoot, $outputRoot)
        return [pscustomobject]@{
            Decision = 'PASS'
            OutputDirectory = $outputRoot
            LauncherReleaseId = $LauncherReleaseId
            RuntimeReleaseId = $RuntimeReleaseId
            PublishedAtUtc = $PublishedAtUtc
            SignerSha256Thumbprint = $SignerSha256Thumbprint.ToLowerInvariant()
            ManifestSha256 = [string]$selfCheck.ManifestSha256
            LauncherArchiveSha256 = [string]$selfCheck.LauncherArchiveSha256
            RuntimeArchiveSha256 = [string]$selfCheck.RuntimeArchiveSha256
            R5CandidateLauncherArchiveSha256 =
                $ExpectedLauncherArchiveSha256.ToLowerInvariant()
            R5CandidateRuntimeArchiveSha256 =
                $ExpectedRuntimeArchiveSha256.ToLowerInvariant()
            BootstrapperSha256 = [string]$selfCheck.BootstrapperSha256
            AuthenticodeEvidence = [pscustomobject]$authenticodeEvidence
            RuntimeEvidence = $runtimeEvidence
            ProductionOnly = $true
            DevelopmentOnly = $false
            DevelopmentMarkerPresent = $false
        }
    }
    finally {
        if ([IO.Directory]::Exists($stagingRoot)) {
            Remove-EnterpriseProductionOwnedTemporaryDirectory `
                -Path $stagingRoot `
                -Parent $outputParent `
                -Prefix '.enterprise-production-payload-'
        }
        if ($null -ne $runtimeDescriptor) {
            $runtimeDescriptor.Stream.Dispose()
        }
        for ($treeIndex = $trees.Count - 1; $treeIndex -ge 0; $treeIndex--) {
            $files = @($trees[$treeIndex].Files)
            for ($fileIndex = $files.Count - 1; $fileIndex -ge 0; $fileIndex--) {
                $files[$fileIndex].Stream.Dispose()
            }
        }
    }
}

Export-ModuleMember -Function @(
    'New-EnterpriseProductionLauncherArchive',
    'New-EnterpriseProductionPayload',
    'Test-EnterpriseProductionPayload')
