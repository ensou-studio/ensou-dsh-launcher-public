#requires -Version 7.2

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$generator = Join-Path $PSScriptRoot `
    'New-PersonalReproducibleBuildRunReceipt.ps1'
$templatePath = Join-Path $repositoryRoot `
    'release\examples\personal-pilot-release-plan.example.json'
$schemaPath = Join-Path $repositoryRoot `
    'release\schemas\personal-reproducible-build-run-v1.schema.json'
$stateModulePath = Join-Path $PSScriptRoot 'ProductionReleaseState.psm1'
Import-Module $stateModulePath -Force

$tempParent = [IO.Path]::GetTempPath()
$testRoot = Join-Path $tempParent `
    ('ensou-personal-repro-build-' + [Guid]::NewGuid().ToString('N'))
$sourceA = Join-Path $testRoot 'source-a'
$sourceB = Join-Path $testRoot 'source-b'
$outputA = Join-Path $testRoot 'output-a'
$outputB = Join-Path $testRoot 'output-b'
$receiptRoot = Join-Path $testRoot 'receipts'
$utf8 = [Text.UTF8Encoding]::new($false)
$completed = $false
$assertions = 0

function Assert-True([bool]$Condition, [string]$Message) {
    $script:assertions++
    if (-not $Condition) { throw $Message }
}

function Get-FileSha256([string]$Path) {
    $stream = [IO.File]::OpenRead($Path)
    try {
        return ([Convert]::ToHexString(
            [Security.Cryptography.SHA256]::HashData($stream))).ToLowerInvariant()
    }
    finally {
        $stream.Dispose()
    }
}

function Get-TextSha256([string]$Value) {
    $bytes = $utf8.GetBytes($Value)
    try {
        return ProductionReleaseState\Get-ProductionSha256Bytes -Bytes $bytes
    }
    finally {
        [Security.Cryptography.CryptographicOperations]::ZeroMemory($bytes)
    }
}

function Invoke-TestGit([string[]]$Arguments) {
    $output = @(& git @Arguments 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "git fixture operation failed: $($output -join [Environment]::NewLine)"
    }
    return @($output | ForEach-Object { [string]$_ })
}

function Write-CanonicalJson([string]$Path, $Value) {
    [byte[]]$bytes =
        ProductionReleaseState\ConvertTo-ProductionJsonBytes -Value $Value
    try {
        [IO.File]::WriteAllBytes($Path, $bytes)
    }
    finally {
        [Security.Cryptography.CryptographicOperations]::ZeroMemory($bytes)
    }
}

function Copy-FixtureFile([string]$RelativePath) {
    $native = $RelativePath.Replace('/', [IO.Path]::DirectorySeparatorChar)
    $destination = Join-Path $sourceA $native
    [IO.Directory]::CreateDirectory(
        [IO.Path]::GetDirectoryName($destination)) | Out-Null
    Copy-Item -LiteralPath (Join-Path $repositoryRoot $native) `
        -Destination $destination
}

function Assert-GeneratorRejected(
    [scriptblock]$Action,
    [string]$Pattern,
    [string]$Message
) {
    $rejected = $false
    try {
        & $Action | Out-Null
    }
    catch {
        $rejected = $_.ToString() -match $Pattern
    }
    Assert-True $rejected $Message
}

try {
    [IO.Directory]::CreateDirectory($sourceA) | Out-Null
    foreach ($relativePath in @(
        'Directory.Build.props',
        'global.json',
        'installer/personal-publish-runtime-packs.lock.json',
        'release/locks/dotnet-sdk-10.0.302-win-x64.files.lock.json',
        'src/Ensou.Dsh.Contracts/packages.lock.json',
        'src/Ensou.Dsh.UpdateEngine/packages.lock.json',
        'src/Ensou.Dsh.Personal.Installer/packages.lock.json'
    )) {
        Copy-FixtureFile $relativePath
    }
    [void](Invoke-TestGit @('-C', $sourceA, 'init', '--quiet'))
    [void](Invoke-TestGit @('-C', $sourceA, 'config', 'user.name', 'ensou-test'))
    [void](Invoke-TestGit @('-C', $sourceA, 'config', 'user.email', 'ensou-test@example.invalid'))
    [void](Invoke-TestGit @('-C', $sourceA, 'add', '--all'))
    [void](Invoke-TestGit @('-C', $sourceA, 'commit', '--quiet', '-m', 'fixture'))
    [void](Invoke-TestGit @('clone', '--quiet', '--no-hardlinks', $sourceA, $sourceB))
    $commit = @(Invoke-TestGit @('-C', $sourceA, 'rev-parse', 'HEAD'))[0]

    [IO.Directory]::CreateDirectory($outputA) | Out-Null
    [IO.Directory]::CreateDirectory($outputB) | Out-Null
    [IO.Directory]::CreateDirectory($receiptRoot) | Out-Null
    $peSource = (Get-Command pwsh -ErrorAction Stop).Source
    $contract = @(
        [pscustomobject]@{ Role = 'startup-stub'; FileName = 'Ensou.Dsh.Bootstrapper.exe' },
        [pscustomobject]@{ Role = 'client-bootstrapper'; FileName = 'Ensou.Dsh.ClientBootstrapper.exe' },
        [pscustomobject]@{ Role = 'launcher'; FileName = 'Ensou.Dsh.Launcher.exe' },
        [pscustomobject]@{ Role = 'maintenance'; FileName = 'Ensou.Dsh.Personal.Maintenance.exe' },
        [pscustomobject]@{ Role = 'installer'; FileName = 'Ensou.Dsh.Personal.Installer.exe' }
    )
    foreach ($item in $contract) {
        Copy-Item -LiteralPath $peSource -Destination `
            (Join-Path $outputA $item.FileName)
        Copy-Item -LiteralPath $peSource -Destination `
            (Join-Path $outputB $item.FileName)
    }

    $plan = Get-Content -LiteralPath $templatePath -Raw |
        ConvertFrom-Json -Depth 64 -DateKind String
    $plan.PSObject.Properties.Remove('personalPilotTemplateStatus')
    $plan.sourceCommit = $commit
    $plan.runtimeCandidate.archive.sha256 = Get-TextSha256 'runtime-archive'
    $plan.runtimeCandidate.metadata.sha256 = Get-TextSha256 'runtime-metadata'
    $plan.runtimeCandidate.hashEvidence.sha256 =
        Get-TextSha256 'runtime-hash-evidence'
    $plan.authenticodePolicy.signerSha256Thumbprint =
        Get-TextSha256 'authenticode-signer'
    for ($index = 0; $index -lt 4; $index++) {
        $planned = $plan.clientSigningInputs[$index]
        $path = Join-Path $outputA $contract[$index].FileName
        $bytes = [IO.File]::ReadAllBytes($path)
        try {
            $planned.path = $path
            $planned.sizeBytes = [int64]$bytes.LongLength
            $planned.sha256 = Get-FileSha256 $path
            $planned.peContentSha256 =
                ProductionReleaseState\Get-PeContentSha256 -Bytes $bytes
        }
        finally {
            [Security.Cryptography.CryptographicOperations]::ZeroMemory($bytes)
        }
    }
    $planPath = Join-Path $testRoot 'personal-plan.json'
    Write-CanonicalJson -Path $planPath -Value $plan

    $previousCi = $env:CI
    try {
        $env:CI = 'true'
        $receiptA = Join-Path $receiptRoot 'isolated-a.json'
        $receiptB = Join-Path $receiptRoot 'isolated-b.json'
        $resultA = & $generator -RunLabel isolated-a `
            -RepositoryRoot $sourceA -PlanPath $planPath `
            -BuildOutputRoot $outputA -OutputPath $receiptA
        $resultB = & $generator -RunLabel isolated-b `
            -RepositoryRoot $sourceB -PlanPath $planPath `
            -BuildOutputRoot $outputB -OutputPath $receiptB
        Assert-True ($resultA.Result -ceq 'PASS' -and
            $resultB.Result -ceq 'PASS') `
            'Two clean isolated receipt generations did not pass.'

        $receiptAJson = Get-Content -LiteralPath $receiptA -Raw
        $receiptBJson = Get-Content -LiteralPath $receiptB -Raw
        Assert-True (Test-Json -Json $receiptAJson -SchemaFile $schemaPath `
            -ErrorAction Stop) 'Run A receipt violates its schema.'
        Assert-True (Test-Json -Json $receiptBJson -SchemaFile $schemaPath `
            -ErrorAction Stop) 'Run B receipt violates its schema.'
        $a = $receiptAJson | ConvertFrom-Json -Depth 64 -DateKind String
        $b = $receiptBJson | ConvertFrom-Json -Depth 64 -DateKind String
        Assert-True ([string]$a.buildId -cne [string]$b.buildId) `
            'Two generated build IDs are not distinct.'
        Assert-True ([string]$a.checkoutIdentitySha256 -cne
            [string]$b.checkoutIdentitySha256) `
            'Two generated checkout identities are not distinct.'
        Assert-True ([string]$a.outputRootIdentitySha256 -cne
            [string]$b.outputRootIdentitySha256) `
            'Two generated output-root identities are not distinct.'
        Assert-True ((@($a.outputs | ForEach-Object sha256) -join ',') -ceq
            (@($b.outputs | ForEach-Object sha256) -join ',')) `
            'Two identical isolated output roots produced different SHA-256 closures.'

        $dirtyPath = Join-Path $sourceA 'untracked-dirty.txt'
        [IO.File]::WriteAllText($dirtyPath, 'dirty', $utf8)
        try {
            Assert-GeneratorRejected -Action {
                & $generator -RunLabel isolated-a `
                    -RepositoryRoot $sourceA -PlanPath $planPath `
                    -BuildOutputRoot $outputA `
                    -OutputPath (Join-Path $receiptRoot 'dirty.json')
            } -Pattern 'not completely clean' `
                -Message 'Dirty source checkout was admitted.'
        }
        finally {
            Remove-Item -LiteralPath $dirtyPath -Force
        }

        $wrongPlan = $plan | ConvertTo-Json -Depth 64 -Compress |
            ConvertFrom-Json -Depth 64 -DateKind String
        $wrongPlan.clientSigningInputs[2].sha256 =
            Get-TextSha256 'wrong-launcher-output'
        $wrongPlanPath = Join-Path $testRoot 'wrong-plan.json'
        Write-CanonicalJson -Path $wrongPlanPath -Value $wrongPlan
        Assert-GeneratorRejected -Action {
            & $generator -RunLabel isolated-a `
                -RepositoryRoot $sourceA -PlanPath $wrongPlanPath `
                -BuildOutputRoot $outputA `
                -OutputPath (Join-Path $receiptRoot 'wrong-plan.json')
        } -Pattern 'differs from this isolated build output' `
            -Message 'Build output not matching the plan was admitted.'

        Assert-GeneratorRejected -Action {
            & $generator -RunLabel isolated-a `
                -RepositoryRoot $sourceA -PlanPath $planPath `
                -BuildOutputRoot $sourceA `
                -OutputPath (Join-Path $receiptRoot 'inside-source.json')
        } -Pattern 'outside the clean source checkout' `
            -Message 'Build output root inside source was admitted.'

        $env:CI = 'false'
        Assert-GeneratorRejected -Action {
            & $generator -RunLabel isolated-a `
                -RepositoryRoot $sourceA -PlanPath $planPath `
                -BuildOutputRoot $outputA `
                -OutputPath (Join-Path $receiptRoot 'not-ci.json')
        } -Pattern 'requires CI=true' `
            -Message 'Receipt creation outside deterministic CI mode was admitted.'
    }
    finally {
        $env:CI = $previousCi
    }

    $completed = $true
    Write-Output `
        "PASS Personal reproducible build receipt contract assertions=$assertions"
}
finally {
    if ($completed -and (Test-Path -LiteralPath $testRoot)) {
        $resolved = [IO.Path]::GetFullPath($testRoot)
        $boundary = [IO.Path]::GetFullPath($tempParent).TrimEnd(
            [IO.Path]::DirectorySeparatorChar,
            [IO.Path]::AltDirectorySeparatorChar) +
            [IO.Path]::DirectorySeparatorChar
        if (-not $resolved.StartsWith(
                $boundary,
                [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Refusing to clean a reproducible-build fixture outside temp.'
        }
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
    elseif (Test-Path -LiteralPath $testRoot) {
        Write-Warning "Failed fixture retained at $testRoot"
    }
}
