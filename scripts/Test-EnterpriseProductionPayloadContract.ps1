#requires -Version 7.2

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($PSVersionTable.PSEdition -ne 'Core' -or
    $PSVersionTable.PSVersion -lt [version]'7.2' -or
    -not $IsWindows) {
    throw 'Enterprise production payload contract tests require Windows PowerShell Core 7.2 or newer.'
}

$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$generatorPath = Join-Path $PSScriptRoot 'New-EnterpriseProductionPayload.ps1'
$selfCheckPath = Join-Path $PSScriptRoot 'Test-EnterpriseProductionPayload.ps1'
$modulePath = Join-Path $PSScriptRoot 'EnterpriseProductionPayload.psm1'
$publisherAdapterPath = Join-Path `
    $repositoryRoot `
    'release\scripts\New-EnterpriseProductionPublisherInput.ps1'
$testParent = [IO.Path]::TrimEndingDirectorySeparator(
    [IO.Path]::GetFullPath([IO.Path]::GetTempPath()))
$testRoot = Join-Path `
    $testParent `
    ('ensou-enterprise-production-payload-contract-' + [Guid]::NewGuid().ToString('N'))

function Assert-Throws {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Action,
        [Parameter(Mandatory = $true)][string]$ExpectedMessage,
        [Parameter(Mandatory = $true)][string]$Label
    )

    try {
        & $Action
    }
    catch {
        if (-not $_.Exception.Message.Contains(
                $ExpectedMessage,
                [StringComparison]::OrdinalIgnoreCase)) {
            throw "$Label failed for the wrong reason: $($_.Exception.Message)"
        }
        return
    }
    throw "$Label did not fail closed."
}

function Write-NewBytes {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][byte[]]$Bytes
    )

    $stream = [IO.FileStream]::new(
        $Path,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None)
    try {
        $stream.Write($Bytes)
    }
    finally {
        $stream.Dispose()
    }
}

function Write-NewText {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Text
    )

    Write-NewBytes `
        -Path $Path `
        -Bytes ([Text.UTF8Encoding]::new($false, $true).GetBytes($Text))
}

function Get-Descriptor {
    param([Parameter(Mandatory = $true)][string]$Path)

    $item = Get-Item -LiteralPath $Path -Force
    $stream = [IO.File]::OpenRead($Path)
    try {
        $sha256 = [Convert]::ToHexString(
            [Security.Cryptography.SHA256]::HashData($stream)).ToLowerInvariant()
    }
    finally {
        $stream.Dispose()
    }
    return [pscustomobject]@{
        SizeBytes = [int64]$item.Length
        Sha256 = $sha256
    }
}

function Write-ZipEntry {
    param(
        [Parameter(Mandatory = $true)][IO.Compression.ZipArchive]$Archive,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][byte[]]$Bytes
    )

    $entry = $Archive.CreateEntry($Name, [IO.Compression.CompressionLevel]::NoCompression)
    $entry.LastWriteTime = [DateTimeOffset]::new(1980, 1, 1, 0, 0, 0, [TimeSpan]::Zero)
    $stream = $entry.Open()
    try {
        $stream.Write($Bytes)
    }
    finally {
        $stream.Dispose()
    }
}

function New-TestRuntimeArchive {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ReleaseId
    )

    Add-Type -AssemblyName System.IO.Compression
    $file = [IO.FileStream]::new(
        $Path,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::None)
    try {
        $archive = [IO.Compression.ZipArchive]::new(
            $file,
            [IO.Compression.ZipArchiveMode]::Create,
            $true)
        try {
            Write-ZipEntry -Archive $archive -Name 'node.exe' -Bytes ([byte[]](1, 2, 3))
            Write-ZipEntry `
                -Archive $archive `
                -Name 'node_modules/@deepseek-ai/dsh/lib/bin.js' `
                -Bytes ([Text.Encoding]::UTF8.GetBytes('console.log("fixture")'))
            $sourceBuild = [ordered]@{
                schemaVersion = 3
                sourceBuilt = $true
                releaseId = $ReleaseId
                promotionEligible = $true
                artifactType = 'ensou-dsh-enterprise-managed-source-runtime'
            } | ConvertTo-Json -Compress
            Write-ZipEntry `
                -Archive $archive `
                -Name 'source-build.json' `
                -Bytes ([Text.UTF8Encoding]::new($false, $true).GetBytes($sourceBuild))
            Write-ZipEntry `
                -Archive $archive `
                -Name 'runtime-files.sha256' `
                -Bytes ([Text.Encoding]::ASCII.GetBytes(('0' * 64) + '  node.exe'))
        }
        finally {
            $archive.Dispose()
        }
    }
    finally {
        $file.Dispose()
    }
}

function New-TestLauncherArchive {
    param([Parameter(Mandatory = $true)][string]$Path)

    Add-Type -AssemblyName System.IO.Compression
    $file = [IO.FileStream]::new(
        $Path,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::None)
    try {
        $archive = [IO.Compression.ZipArchive]::new(
            $file,
            [IO.Compression.ZipArchiveMode]::Create,
            $true)
        try {
            foreach ($name in @(
                    'Ensou.Dsh.Enterprise.Launcher.exe',
                    'Ensou.Dsh.Enterprise.ClientBootstrapper.exe',
                    'Ensou.Dsh.Enterprise.Maintenance.exe')) {
                Write-ZipEntry -Archive $archive -Name $name -Bytes ([byte[]](0x4D, 0x5A, 1, 2))
            }
            Write-ZipEntry `
                -Archive $archive `
                -Name 'enterprise-build-profile.json' `
                -Bytes ([Text.UTF8Encoding]::new($false, $true).GetBytes(
                    '{"schemaVersion":1,"layoutProfile":"enterprise"}'))
        }
        finally {
            $archive.Dispose()
        }
    }
    finally {
        $file.Dispose()
    }
}

function New-UnsignedInputFixture {
    param([Parameter(Mandatory = $true)][string]$Root)

    $names = @(
        'launcher',
        'client-bootstrapper',
        'maintenance',
        'bootstrapper')
    foreach ($name in $names) {
        [IO.Directory]::CreateDirectory((Join-Path $Root $name)) | Out-Null
    }
    $executables = [ordered]@{
        launcher = 'Ensou.Dsh.Enterprise.Launcher.exe'
        'client-bootstrapper' = 'Ensou.Dsh.Enterprise.ClientBootstrapper.exe'
        maintenance = 'Ensou.Dsh.Enterprise.Maintenance.exe'
        bootstrapper = 'Ensou.Dsh.Enterprise.Bootstrapper.exe'
    }
    foreach ($name in $executables.Keys) {
        Write-NewBytes `
            -Path (Join-Path (Join-Path $Root $name) $executables[$name]) `
            -Bytes ([byte[]](0x4D, 0x5A, 0, 0, 1, 2, 3, 4))
    }
    $profile = '{"schemaVersion":1,"layoutProfile":"enterprise"}'
    foreach ($name in @('launcher', 'client-bootstrapper', 'bootstrapper')) {
        Write-NewText `
            -Path (Join-Path (Join-Path $Root $name) 'enterprise-build-profile.json') `
            -Text $profile
    }
    $runtimePath = Join-Path $Root 'managed-runtime.zip'
    New-TestRuntimeArchive `
        -Path $runtimePath `
        -ReleaseId 'managed-v2026.09.01.1'
    return [pscustomobject]@{
        Launcher = Join-Path $Root 'launcher'
        ClientBootstrapper = Join-Path $Root 'client-bootstrapper'
        Maintenance = Join-Path $Root 'maintenance'
        Bootstrapper = Join-Path $Root 'bootstrapper'
        Runtime = $runtimePath
    }
}

function Get-GeneratorArguments {
    param(
        [Parameter(Mandatory = $true)]$Fixture,
        [Parameter(Mandatory = $true)][string]$Output
    )

    return @{
        LauncherReleaseId = 'launcher-2026.09.01.1'
        RuntimeReleaseId = 'managed-v2026.09.01.1'
        LauncherPublishDirectory = $Fixture.Launcher
        ClientBootstrapperPublishDirectory = $Fixture.ClientBootstrapper
        MaintenancePublishDirectory = $Fixture.Maintenance
        BootstrapperPublishDirectory = $Fixture.Bootstrapper
        RuntimeArchivePath = $Fixture.Runtime
        ExpectedLauncherArchiveSha256 = '0' * 64
        ExpectedRuntimeArchiveSha256 = (Get-Descriptor $Fixture.Runtime).Sha256
        OutputDirectory = $Output
        SignerSha256Thumbprint = '0' * 64
        PublishedAtUtc = '2026-09-01T00:00:00Z'
    }
}

function Assert-OutputAbsent {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if (Test-Path -LiteralPath $Path) {
        throw "$Label left a production payload output behind."
    }
}

foreach ($path in @(
        $generatorPath,
        $selfCheckPath,
        $modulePath,
        $publisherAdapterPath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Enterprise production payload contract file is missing: $path"
    }
    $tokens = $null
    $parseErrors = $null
    [void][Management.Automation.Language.Parser]::ParseFile(
        $path,
        [ref]$tokens,
        [ref]$parseErrors)
    if ($parseErrors.Count -ne 0) {
        throw "Enterprise production payload contract file does not parse: $path"
    }
}

$generatorTokens = $null
$generatorParseErrors = $null
$generatorAst = [Management.Automation.Language.Parser]::ParseFile(
    $generatorPath,
    [ref]$generatorTokens,
    [ref]$generatorParseErrors)
$parameterNames = @($generatorAst.ParamBlock.Parameters | ForEach-Object {
    $_.Name.VariablePath.UserPath
})
$expectedParameters = @(
    'LauncherReleaseId',
    'RuntimeReleaseId',
    'LauncherPublishDirectory',
    'ClientBootstrapperPublishDirectory',
    'MaintenancePublishDirectory',
    'BootstrapperPublishDirectory',
    'RuntimeArchivePath',
    'ExpectedLauncherArchiveSha256',
    'ExpectedRuntimeArchiveSha256',
    'OutputDirectory',
    'SignerSha256Thumbprint',
    'PublishedAtUtc')
if (@(Compare-Object `
        -ReferenceObject $expectedParameters `
        -DifferenceObject $parameterNames `
        -CaseSensitive).Count -ne 0 -or
    $parameterNames | Where-Object { $_ -match 'Dev|Unsigned|Skip|Allow|Bypass' }) {
    throw 'Enterprise production payload generator exposes an unexpected or bypass parameter.'
}
$moduleText = [IO.File]::ReadAllText($modulePath)
foreach ($requiredContract in @(
        'Open-ProductionReleaseInput',
        'Assert-ProductionReleaseInputStillLocked',
        'Assert-PeRfc3161Timestamp',
        'Get-AuthenticodeSignature',
        'ALLOW-UNSIGNED-DEVELOPMENT-PAYLOAD.txt',
        'ExpectedLauncherArchiveSha256',
        'ExpectedRuntimeArchiveSha256',
        'New-EnterpriseProductionLauncherArchive',
        'Enterprise production payload must contain exactly its four ordinary non-empty files.')) {
    if (-not $moduleText.Contains($requiredContract, [StringComparison]::Ordinal)) {
        throw "Enterprise production payload module does not bind '$requiredContract'."
    }
}
$publisherAdapterText = [IO.File]::ReadAllText($publisherAdapterPath)
if (-not $publisherAdapterText.Contains(
        'EnterpriseProductionPayload\New-EnterpriseProductionLauncherArchive',
        [StringComparison]::Ordinal) -or
    $publisherAdapterText.Contains(
        'function New-DeterministicLauncherArchive',
        [StringComparison]::Ordinal)) {
    throw 'Enterprise production Publisher adapter does not reuse the one canonical Launcher archive helper.'
}

[IO.Directory]::CreateDirectory($testRoot) | Out-Null
try {
    $fixtureRoot = Join-Path $testRoot 'unsigned-input'
    [IO.Directory]::CreateDirectory($fixtureRoot) | Out-Null
    $fixture = New-UnsignedInputFixture -Root $fixtureRoot

    $r5RuntimeMismatchOutput = Join-Path $testRoot 'r5-runtime-mismatch-output'
    $r5RuntimeMismatchArguments = Get-GeneratorArguments `
        -Fixture $fixture `
        -Output $r5RuntimeMismatchOutput
    $r5RuntimeMismatchArguments.ExpectedRuntimeArchiveSha256 = 'f' * 64
    Assert-Throws `
        -Label 'Exact r5 runtime candidate hash rejection' `
        -ExpectedMessage 'exact r5 candidate runtime archive hash' `
        -Action { & $generatorPath @r5RuntimeMismatchArguments }
    Assert-OutputAbsent `
        -Path $r5RuntimeMismatchOutput `
        -Label 'Exact r5 runtime candidate hash rejection'

    $unsignedOutput = Join-Path $testRoot 'unsigned-output'
    $unsignedArguments = Get-GeneratorArguments `
        -Fixture $fixture `
        -Output $unsignedOutput
    Assert-Throws `
        -Label 'Unsigned Enterprise production PE rejection' `
        -ExpectedMessage 'not one valid embedded Authenticode executable' `
        -Action { & $generatorPath @unsignedArguments }
    Assert-OutputAbsent `
        -Path $unsignedOutput `
        -Label 'Unsigned Enterprise production PE rejection'

    $developmentMarker = Join-Path `
        $fixture.Launcher `
        'ALLOW-UNSIGNED-DEVELOPMENT-PAYLOAD.txt'
    Write-NewText -Path $developmentMarker -Text 'development-only'
    $markerOutput = Join-Path $testRoot 'marker-output'
    $markerArguments = Get-GeneratorArguments `
        -Fixture $fixture `
        -Output $markerOutput
    Assert-Throws `
        -Label 'Development consent marker rejection' `
        -ExpectedMessage 'forbidden Development consent marker' `
        -Action { & $generatorPath @markerArguments }
    Assert-OutputAbsent `
        -Path $markerOutput `
        -Label 'Development consent marker rejection'
    Remove-Item -LiteralPath $developmentMarker -Force

    $profilePath = Join-Path $fixture.Launcher 'enterprise-build-profile.json'
    [IO.File]::WriteAllBytes(
        $profilePath,
        [Text.UTF8Encoding]::new($false, $true).GetBytes(
            '{"schemaVersion":1,"layoutProfile":"development-e2e"}'))
    $profileOutput = Join-Path $testRoot 'profile-output'
    $profileArguments = Get-GeneratorArguments `
        -Fixture $fixture `
        -Output $profileOutput
    Assert-Throws `
        -Label 'Development profile rejection' `
        -ExpectedMessage 'does not use the production enterprise profile' `
        -Action { & $generatorPath @profileArguments }
    Assert-OutputAbsent `
        -Path $profileOutput `
        -Label 'Development profile rejection'

    $payloadRoot = Join-Path $testRoot 'payload-extra-marker'
    [IO.Directory]::CreateDirectory($payloadRoot) | Out-Null
    $launcherArchivePath = Join-Path $payloadRoot 'launcher.zip'
    New-TestLauncherArchive -Path $launcherArchivePath
    $runtimePayloadPath = Join-Path $payloadRoot 'runtime.zip'
    [IO.File]::Copy($fixture.Runtime, $runtimePayloadPath)
    $bootstrapperPayloadPath = Join-Path `
        $payloadRoot `
        'Ensou.Dsh.Enterprise.Bootstrapper.exe'
    [IO.File]::Copy(
        (Join-Path $fixture.Bootstrapper 'Ensou.Dsh.Enterprise.Bootstrapper.exe'),
        $bootstrapperPayloadPath)
    $launcherDescriptor = Get-Descriptor $launcherArchivePath
    $runtimeDescriptor = Get-Descriptor $runtimePayloadPath
    $bootstrapperDescriptor = Get-Descriptor $bootstrapperPayloadPath
    $manifest = [ordered]@{
        schemaVersion = 1
        layoutProfile = 'enterprise'
        launcherReleaseId = 'launcher-2026.09.01.1'
        runtimeReleaseId = 'managed-v2026.09.01.1'
        launcherArchive = 'launcher.zip'
        launcherArchiveSizeBytes = $launcherDescriptor.SizeBytes
        launcherArchiveSha256 = $launcherDescriptor.Sha256
        runtimeArchive = 'runtime.zip'
        runtimeArchiveSizeBytes = $runtimeDescriptor.SizeBytes
        runtimeArchiveSha256 = $runtimeDescriptor.Sha256
        bootstrapperFile = 'Ensou.Dsh.Enterprise.Bootstrapper.exe'
        bootstrapperSizeBytes = $bootstrapperDescriptor.SizeBytes
        bootstrapperSha256 = $bootstrapperDescriptor.Sha256
        publishedAtUtc = '2026-09-01T00:00:00Z'
    } | ConvertTo-Json -Compress
    Write-NewText `
        -Path (Join-Path $payloadRoot 'enterprise-install-manifest.json') `
        -Text $manifest
    Write-NewText `
        -Path (Join-Path $payloadRoot 'ALLOW-UNSIGNED-DEVELOPMENT-PAYLOAD.txt') `
        -Text 'development-only'
    Assert-Throws `
        -Label 'Production self-check extra marker rejection' `
        -ExpectedMessage 'exactly its four ordinary non-empty files' `
        -Action {
            & $selfCheckPath `
                -PayloadDirectory $payloadRoot `
                -SignerSha256Thumbprint ('0' * 64) `
                -ExpectedLauncherArchiveSha256 $launcherDescriptor.Sha256 `
                -ExpectedRuntimeArchiveSha256 $runtimeDescriptor.Sha256
        }

    Remove-Item `
        -LiteralPath (Join-Path $payloadRoot 'ALLOW-UNSIGNED-DEVELOPMENT-PAYLOAD.txt') `
        -Force
    Assert-Throws `
        -Label 'Exact r5 Launcher candidate hash rejection' `
        -ExpectedMessage 'exact r5 candidate Launcher archive hash' `
        -Action {
            & $selfCheckPath `
                -PayloadDirectory $payloadRoot `
                -SignerSha256Thumbprint ('0' * 64) `
                -ExpectedLauncherArchiveSha256 ('f' * 64) `
                -ExpectedRuntimeArchiveSha256 $runtimeDescriptor.Sha256
        }
    Assert-Throws `
        -Label 'Production self-check unsigned Bootstrapper rejection' `
        -ExpectedMessage 'not one valid embedded Authenticode executable' `
        -Action {
            & $selfCheckPath `
                -PayloadDirectory $payloadRoot `
                -SignerSha256Thumbprint ('0' * 64) `
                -ExpectedLauncherArchiveSha256 $launcherDescriptor.Sha256 `
                -ExpectedRuntimeArchiveSha256 $runtimeDescriptor.Sha256
        }

    Write-Output 'ENTERPRISE-PRODUCTION-PAYLOAD-CONTRACT-PASS'
}
finally {
    if ([IO.Directory]::Exists($testRoot)) {
        $fullRoot = [IO.Path]::GetFullPath($testRoot)
        if ([IO.Path]::GetDirectoryName($fullRoot) -cne $testParent -or
            -not [IO.Path]::GetFileName($fullRoot).StartsWith(
                'ensou-enterprise-production-payload-contract-',
                [StringComparison]::Ordinal)) {
            throw 'Refusing to remove an unexpected Enterprise production payload contract directory.'
        }
        Remove-Item -LiteralPath $fullRoot -Recurse -Force
    }
}
