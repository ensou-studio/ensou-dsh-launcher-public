#requires -Version 7.2

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('isolated-a', 'isolated-b')]
    [string]$RunLabel,

    [Parameter(Mandatory = $true)]
    [string]$RepositoryRoot,

    [Parameter(Mandatory = $true)]
    [string]$PlanPath,

    [Parameter(Mandatory = $true)]
    [string]$BuildOutputRoot,

    [Parameter(Mandatory = $true)]
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$releaseRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$stateModulePath = Join-Path $PSScriptRoot 'ProductionReleaseState.psm1'
$planSchemaPath = Join-Path $releaseRoot `
    'release\schemas\launcher-production-release-plan-v2.schema.json'
$receiptSchemaPath = Join-Path $releaseRoot `
    'release\schemas\personal-reproducible-build-run-v1.schema.json'
Import-Module $stateModulePath -Force

function Test-ProductionSha256([string]$Value) {
    return $Value -match '^[0-9a-f]{64}$' -and
        $Value -notmatch '^([0-9a-f])\1{63}$'
}

function Test-ProductionGitObject([string]$Value) {
    return $Value -match '^(?:[0-9a-f]{40}|[0-9a-f]{64})$' -and
        $Value -notmatch '^([0-9a-f])\1{39}(?:\1{24})?$'
}

function Get-TextSha256([string]$Value) {
    $bytes = [Text.Encoding]::UTF8.GetBytes($Value)
    try {
        return ProductionReleaseState\Get-ProductionSha256Bytes -Bytes $bytes
    }
    finally {
        [Security.Cryptography.CryptographicOperations]::ZeroMemory($bytes)
    }
}

function Test-SameOrDescendant([string]$Candidate, [string]$Parent) {
    $candidatePath = [IO.Path]::GetFullPath($Candidate).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    $parentPath = [IO.Path]::GetFullPath($Parent).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    return $candidatePath.Equals(
            $parentPath,
            [StringComparison]::OrdinalIgnoreCase) -or
        $candidatePath.StartsWith(
            $parentPath + [IO.Path]::DirectorySeparatorChar,
            [StringComparison]::OrdinalIgnoreCase)
}

function Invoke-ReceiptGit([string[]]$Arguments) {
    $output = @(& git @Arguments 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "git failed: $($output -join [Environment]::NewLine)"
    }
    return @($output | ForEach-Object { [string]$_ })
}

function Open-OutputDescriptor(
    [string]$Root,
    [string]$Role,
    [string]$FileName
) {
    $path = Join-Path $Root $FileName
    $input = ProductionReleaseState\Open-ProductionReleaseInput `
        -Path $path -Label "Personal reproducible output '$Role'" `
        -MaximumBytes 1GB
    try {
        if ([string]$input.FileName -cne $FileName -or
            [int64]$input.SizeBytes -lt 256) {
            throw "Personal reproducible output '$Role' is not the exact expected PE file."
        }
        [byte[]]$bytes =
            ProductionReleaseState\Read-ProductionReleaseInputBytes `
                -Descriptor $input `
                -Label "Personal reproducible output '$Role'"
        try {
            $peContentSha256 = ProductionReleaseState\Get-PeContentSha256 `
                -Bytes $bytes
        }
        finally {
            [Security.Cryptography.CryptographicOperations]::ZeroMemory($bytes)
        }
        if (-not (Test-ProductionSha256 ([string]$input.Sha256)) -or
            -not (Test-ProductionSha256 $peContentSha256)) {
            throw "Personal reproducible output '$Role' has a placeholder identity."
        }
        return [ordered]@{
            role = $Role
            fileName = $FileName
            sizeBytes = [int64]$input.SizeBytes
            sha256 = [string]$input.Sha256
            peContentSha256 = $peContentSha256
        }
    }
    finally {
        $input.Stream.Dispose()
    }
}

$repositoryPath = [IO.Path]::GetFullPath($RepositoryRoot)
$buildOutputPath = [IO.Path]::GetFullPath($BuildOutputRoot)
$receiptPath = [IO.Path]::GetFullPath($OutputPath)
if (Test-SameOrDescendant -Candidate $buildOutputPath -Parent $repositoryPath) {
    throw 'Reproducible build outputs must be outside the clean source checkout.'
}
if (Test-SameOrDescendant -Candidate $receiptPath -Parent $repositoryPath) {
    throw 'Reproducible build receipt must be outside the clean source checkout.'
}
if (Test-Path -LiteralPath $receiptPath) {
    throw 'Reproducible build receipt is create-only and already exists.'
}
if ([string]$env:CI -cne 'true') {
    throw 'Reproducible receipt creation requires CI=true from the deterministic build environment.'
}

$repositoryLease = ProductionReleaseState\Open-ProductionReleaseDirectoryLease `
    -Path $repositoryPath -Label 'Personal reproducible source checkout'
$outputLease = $null
try {
    $outputLease = ProductionReleaseState\Open-ProductionReleaseDirectoryLease `
        -Path $buildOutputPath -Label 'Personal reproducible output root'

    $planInput = ProductionReleaseState\Read-StrictProductionJsonFile `
        -Path ([IO.Path]::GetFullPath($PlanPath)) `
        -Label 'Personal production Pilot plan' -SchemaPath $planSchemaPath
    [void](ProductionReleaseState\Assert-CanonicalProductionJsonInput `
        -JsonInput $planInput -Label 'Personal production Pilot plan')
    $plan = $planInput.Value
    if ([string]$plan.edition -cne 'Personal' -or
        [string]$plan.targetChannel -cne 'pilot' -or
        $plan.PSObject.Properties.Name -ccontains
            'personalPilotTemplateStatus') {
        throw 'Reproducible build receipt requires a non-template Personal Pilot plan.'
    }
    if (-not (Test-ProductionGitObject ([string]$plan.sourceCommit))) {
        throw 'Personal production plan has a placeholder or malformed source commit.'
    }

    $safeDirectory = 'safe.directory=' + $repositoryPath.Replace('\', '/')
    $gitPrefix = @('-c', $safeDirectory, '-C', $repositoryPath)
    $inside = @(Invoke-ReceiptGit ($gitPrefix + @(
        'rev-parse', '--is-inside-work-tree')))
    if ($inside.Count -ne 1 -or $inside[0] -cne 'true') {
        throw 'Personal reproducible source is not a Git worktree.'
    }
    $status = @(Invoke-ReceiptGit ($gitPrefix + @(
        'status', '--porcelain=v1', '--untracked-files=all')))
    if ($status.Count -ne 0) {
        throw 'Personal reproducible source checkout is not completely clean.'
    }
    $commit = @(Invoke-ReceiptGit ($gitPrefix + @('rev-parse', 'HEAD')))[0]
    $tree = @(Invoke-ReceiptGit ($gitPrefix + @(
        'rev-parse', "$commit`^{tree}")))[0]
    if ([string]$commit -cne [string]$plan.sourceCommit -or
        -not (Test-ProductionGitObject $commit) -or
        -not (Test-ProductionGitObject $tree)) {
        throw 'Personal plan, clean checkout HEAD, and source tree are not one immutable source.'
    }
    $inventoryLines = @(Invoke-ReceiptGit ($gitPrefix + @(
        'ls-tree', '-r', '--full-tree', $commit)))
    if ($inventoryLines.Count -eq 0) {
        throw 'Personal source inventory is empty.'
    }
    $sourceInventorySha256 = Get-TextSha256 `
        (($inventoryLines -join "`n") + "`n")

    $sdkLock = Get-Content -LiteralPath (Join-Path $repositoryPath 'global.json') `
        -Raw | ConvertFrom-Json -Depth 8
    $sdkVersion = [string]$sdkLock.sdk.version
    $actualSdkVersion = [string](& dotnet --version)
    if ($LASTEXITCODE -ne 0 -or $sdkVersion -cne '10.0.302' -or
        $actualSdkVersion.Trim() -cne $sdkVersion) {
        throw 'Personal reproducible build did not use the exact locked .NET SDK 10.0.302.'
    }

    $packagePaths = @(
        'Directory.Build.props',
        'global.json',
        'installer/personal-publish-runtime-packs.lock.json',
        'release/locks/dotnet-sdk-10.0.302-win-x64.files.lock.json',
        'src/Ensou.Dsh.Contracts/packages.lock.json',
        'src/Ensou.Dsh.UpdateEngine/packages.lock.json',
        'src/Ensou.Dsh.Personal.Installer/packages.lock.json'
    )
    $packageLines = [Collections.Generic.List[string]]::new()
    foreach ($relativePath in $packagePaths) {
        $nativePath = $relativePath.Replace(
            '/', [IO.Path]::DirectorySeparatorChar)
        $input = ProductionReleaseState\Open-ProductionReleaseInput `
            -Path (Join-Path $repositoryPath $nativePath) `
            -Label "Personal dependency closure '$relativePath'" `
            -MaximumBytes 64MB
        try {
            $packageLines.Add(
                "$relativePath|$([int64]$input.SizeBytes)|$([string]$input.Sha256)")
        }
        finally {
            $input.Stream.Dispose()
        }
    }
    $packageClosureSha256 = Get-TextSha256 `
        (($packageLines -join "`n") + "`n")

    $outputContract = @(
        [pscustomobject]@{ Role = 'startup-stub'; FileName = 'Ensou.Dsh.Bootstrapper.exe' },
        [pscustomobject]@{ Role = 'client-bootstrapper'; FileName = 'Ensou.Dsh.ClientBootstrapper.exe' },
        [pscustomobject]@{ Role = 'launcher'; FileName = 'Ensou.Dsh.Launcher.exe' },
        [pscustomobject]@{ Role = 'maintenance'; FileName = 'Ensou.Dsh.Personal.Maintenance.exe' },
        [pscustomobject]@{ Role = 'installer'; FileName = 'Ensou.Dsh.Personal.Installer.exe' }
    )
    $actualEntries = @(Get-ChildItem -LiteralPath $buildOutputPath -Force)
    if ($actualEntries.Count -ne $outputContract.Count -or
        @($actualEntries | Where-Object PSIsContainer).Count -ne 0 -or
        (@($actualEntries.Name | Sort-Object) -join "`n") -cne
            (@($outputContract.FileName | Sort-Object) -join "`n")) {
        throw 'Personal reproducible output root must contain exactly the five canonical PE files.'
    }
    $outputs = [Collections.Generic.List[object]]::new()
    foreach ($expected in $outputContract) {
        $outputs.Add((Open-OutputDescriptor -Root $buildOutputPath `
            -Role $expected.Role -FileName $expected.FileName))
    }
    for ($index = 0; $index -lt 4; $index++) {
        $planned = $plan.clientSigningInputs[$index]
        $actual = $outputs[$index]
        if ([string]$planned.role -cne [string]$actual.role -or
            [string]$planned.fileName -cne [string]$actual.fileName -or
            [int64]$planned.sizeBytes -ne [int64]$actual.sizeBytes -or
            [string]$planned.sha256 -cne [string]$actual.sha256 -or
            [string]$planned.peContentSha256 -cne
                [string]$actual.peContentSha256) {
            throw "Personal plan client input '$([string]$actual.role)' differs from this isolated build output."
        }
    }

    $receipt = [ordered]@{
        schemaVersion = 1
        evidenceType = 'ensou-dsh-personal-isolated-reproducible-build-run'
        runLabel = $RunLabel
        buildId = [Guid]::NewGuid().ToString().ToLowerInvariant()
        planSha256 = [string]$planInput.Sha256
        sourceCommit = $commit
        sourceTree = $tree
        sourceStatus = 'CLEAN_TRACKED_HEAD'
        sourceInventorySha256 = $sourceInventorySha256
        checkoutIdentitySha256 = Get-TextSha256 `
            ($repositoryPath.ToLowerInvariant() + "`n")
        outputRootIdentitySha256 = Get-TextSha256 `
            ($buildOutputPath.ToLowerInvariant() + "`n")
        sdkVersion = $sdkVersion
        buildMode = 'deterministic-ci-release-win-x64-self-contained-single-file'
        packageClosureSha256 = $packageClosureSha256
        outputs = @($outputs)
        result = 'PASS'
    }
    [byte[]]$receiptBytes =
        ProductionReleaseState\ConvertTo-ProductionJsonBytes -Value $receipt
    try {
        if (-not (Test-Json -Json ([Text.Encoding]::UTF8.GetString($receiptBytes)) `
                -SchemaFile $receiptSchemaPath -ErrorAction Stop)) {
            throw 'Generated Personal reproducible build receipt violates its schema.'
        }
        $parent = [IO.Path]::GetDirectoryName($receiptPath)
        if (-not (Test-Path -LiteralPath $parent)) {
            [IO.Directory]::CreateDirectory($parent) | Out-Null
        }
        $stream = [IO.File]::Open(
            $receiptPath,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None)
        try {
            $stream.Write($receiptBytes)
            $stream.Flush($true)
        }
        finally {
            $stream.Dispose()
        }
    }
    finally {
        [Security.Cryptography.CryptographicOperations]::ZeroMemory(
            $receiptBytes)
    }

    [pscustomobject]@{
        Result = 'PASS'
        RunLabel = $RunLabel
        SourceCommit = $commit
        SourceTree = $tree
        OutputCount = 5
        ReceiptPath = $receiptPath
    }
}
finally {
    if ($null -ne $outputLease) {
        $outputLease.Handle.Dispose()
    }
    $repositoryLease.Handle.Dispose()
}
