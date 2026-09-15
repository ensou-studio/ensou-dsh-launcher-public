#requires -Version 7.2

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$DotNetSdkArchivePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $IsWindows -or
    [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -ne
        [Runtime.InteropServices.Architecture]::X64) {
    throw 'Enterprise Installer trusted-build tests require native Windows x64.'
}

$sourceRepo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$DotNetSdkArchivePath = [IO.Path]::GetFullPath($DotNetSdkArchivePath)
if (-not [IO.File]::Exists($DotNetSdkArchivePath) -or
    [IO.Path]::GetFileName($DotNetSdkArchivePath) -cne
        'dotnet-sdk-10.0.302-win-x64.zip') {
    throw 'Trusted-build test requires the exact official dotnet-sdk-10.0.302-win-x64.zip path.'
}
$testRoot = Join-Path `
    ([IO.Path]::GetTempPath()) `
    ('ensou-enterprise-installer-trusted-build-test-' +
        [Guid]::NewGuid().ToString('N'))
$cleanRepo = Join-Path $testRoot 'repo'
$packageRoot = Join-Path $testRoot 'packages'
$payloadRoot = Join-Path $testRoot 'payload-inputs'
$outputRoot = Join-Path $testRoot 'output'
$dirtyOutput = Join-Path $testRoot 'dirty-output'
$utf8 = [Text.UTF8Encoding]::new($false, $true)
$payloadDescriptors = [Collections.Generic.List[object]]::new()
$result = $null
$script:AssertionCount = 0

function Assert-True {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )
    if (-not $Condition) {
        throw $Message
    }
    $script:AssertionCount++
}

function Assert-Throws {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][string]$ExpectedMessage,
        [Parameter(Mandatory = $true)][scriptblock]$Action
    )
    try {
        & $Action
    }
    catch {
        if (-not $_.Exception.Message.Contains(
                $ExpectedMessage,
                [StringComparison]::OrdinalIgnoreCase)) {
            throw "$Label failed for an unexpected reason: $($_.Exception.Message)"
        }
        $script:AssertionCount++
        return
    }
    throw "$Label unexpectedly succeeded."
}

function Get-Sha256Bytes {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    return [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($Bytes)).ToLowerInvariant()
}

function ConvertTo-TestBase64Url {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    return [Convert]::ToBase64String($Bytes).TrimEnd('=').
        Replace('+', '-').Replace('/', '_')
}

function New-TestP256Trust {
    param(
        [Parameter(Mandatory = $true)][string]$KeyId,
        [Parameter(Mandatory = $true)][string]$Purpose
    )
    $ecdsa = [Security.Cryptography.ECDsa]::Create(
        [Security.Cryptography.ECCurve+NamedCurves]::nistP256)
    try {
        $parameters = $ecdsa.ExportParameters($false)
        return [ordered]@{
            algorithm = 'ES256'
            keyId = $KeyId
            purpose = $Purpose
            x = ConvertTo-TestBase64Url -Bytes $parameters.Q.X
            y = ConvertTo-TestBase64Url -Bytes $parameters.Q.Y
        }
    }
    finally {
        $ecdsa.Dispose()
    }
}

function New-TestFileEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$Role,
        [Parameter(Mandatory = $true)][string]$FileName,
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][string]$RelativePath,
        [switch]$Pe
    )
    $value = [ordered]@{
        role = $Role
        fileName = $FileName
        relativePath = $RelativePath
        sizeBytes = [int64]$Bytes.LongLength
        sha256 = Get-Sha256Bytes -Bytes $Bytes
    }
    if ($Pe) {
        $value.peContentSha256 = Get-Sha256Bytes -Bytes $Bytes
    }
    return $value
}

function Write-BytesCreateNew {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][byte[]]$Bytes
    )
    [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($Path)) |
        Out-Null
    $stream = [IO.File]::Open(
        $Path,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None)
    try {
        $stream.Write($Bytes)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
}

function Invoke-TestProcess {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory
    )
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $FilePath
    $start.WorkingDirectory = $WorkingDirectory
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in $Arguments) {
        [void]$start.ArgumentList.Add($argument)
    }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    try {
        [void]$process.Start()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(600000)) {
            $process.Kill($true)
            throw "Test process timed out: $FilePath"
        }
        $process.WaitForExit()
        if ($process.ExitCode -ne 0) {
            throw "Test process failed: $FilePath`n$($stdout.Result)`n$($stderr.Result)"
        }
        return $stdout.Result.Trim()
    }
    finally {
        $process.Dispose()
    }
}

function Copy-TestSourceInventory {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination
    )
    [IO.Directory]::CreateDirectory($Destination) | Out-Null
    $git = (Get-Command git.exe -CommandType Application -ErrorAction Stop |
        Select-Object -First 1).Source
    $trackedOutput = Invoke-TestProcess `
        -FilePath $git `
        -Arguments @(
            '-c', "safe.directory=$($Source.Replace('\', '/'))",
            '-c', 'core.quotepath=false', 'ls-files') `
        -WorkingDirectory $Source
    $paths = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    foreach ($relative in @($trackedOutput -split "`n")) {
        if (-not [string]::IsNullOrWhiteSpace($relative)) {
            [void]$paths.Add($relative.TrimEnd("`r"))
        }
    }
    foreach ($relative in @(
            'release/scripts/EnterpriseInstallerTrustedBuild.psm1',
            'release/scripts/Test-EnterpriseInstallerTrustedBuild.ps1',
            'release/scripts/PortableDotNetSdkClosure.psm1',
            'release/scripts/InstallerSigningContracts.psm1',
            'release/schemas/enterprise-installer-trusted-build-evidence-v1.schema.json',
            'release/schemas/launcher-enterprise-installer-signing-request-v2.schema.json',
            'release/schemas/portable-dotnet-sdk-byte-closure-v1.schema.json',
            'release/locks/dotnet-sdk-10.0.302-win-x64.files.lock.json')) {
        [void]$paths.Add($relative)
    }
    foreach ($relative in $paths) {
        $sourcePath = Join-Path $Source $relative.Replace('/', '\')
        $destinationPath = Join-Path $Destination $relative.Replace('/', '\')
        if (-not [IO.File]::Exists($sourcePath)) {
            throw "Trusted-build test source inventory is missing '$relative'."
        }
        [IO.Directory]::CreateDirectory(
            [IO.Path]::GetDirectoryName($destinationPath)) | Out-Null
        [IO.File]::Copy($sourcePath, $destinationPath, $false)
    }
}

function New-JsonInput {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string]$FileName
    )
    $bytes = ProductionReleaseState\ConvertTo-ProductionJsonBytes -Value $Value
    return [pscustomobject]@{
        Path = Join-Path $testRoot $FileName
        Bytes = $bytes
        SizeBytes = [int64]$bytes.LongLength
        Sha256 = Get-Sha256Bytes -Bytes $bytes
        Value = $Value
    }
}

function New-PayloadDescriptor {
    param(
        [Parameter(Mandatory = $true)][string]$Role,
        [Parameter(Mandatory = $true)][string]$FileName,
        [Parameter(Mandatory = $true)][byte[]]$Bytes
    )
    $path = Join-Path $payloadRoot $FileName
    Write-BytesCreateNew -Path $path -Bytes $Bytes
    $descriptor = ProductionReleaseState\Open-ProductionReleaseInput `
        -Path $path `
        -Label "Trusted-build test payload '$Role'" `
        -MaximumBytes 512MB
    $payloadDescriptors.Add($descriptor)
    return [pscustomobject]@{
        Role = $Role
        Descriptor = $descriptor
    }
}

try {
    [IO.Directory]::CreateDirectory($testRoot) | Out-Null
    Copy-TestSourceInventory -Source $sourceRepo -Destination $cleanRepo
    $gitPath = (Get-Command git.exe -CommandType Application -ErrorAction Stop |
        Select-Object -First 1).Source
    [void](Invoke-TestProcess -FilePath $gitPath -Arguments @('init') -WorkingDirectory $cleanRepo)
    [void](Invoke-TestProcess -FilePath $gitPath -Arguments @('config', 'user.email', 'trusted-build@test.invalid') -WorkingDirectory $cleanRepo)
    [void](Invoke-TestProcess -FilePath $gitPath -Arguments @('config', 'user.name', 'Trusted Build Test') -WorkingDirectory $cleanRepo)
    [void](Invoke-TestProcess -FilePath $gitPath -Arguments @('add', '--all') -WorkingDirectory $cleanRepo)
    [void](Invoke-TestProcess -FilePath $gitPath -Arguments @('commit', '-m', 'trusted build fixture') -WorkingDirectory $cleanRepo)
    $sourceCommit = Invoke-TestProcess `
        -FilePath $gitPath `
        -Arguments @('rev-parse', 'HEAD') `
        -WorkingDirectory $cleanRepo

    $packageLock = Get-Content `
        -LiteralPath (Join-Path $cleanRepo 'installer\enterprise-publish-runtime-packs.lock.json') `
        -Raw | ConvertFrom-Json -Depth 16
    [IO.Directory]::CreateDirectory($packageRoot) | Out-Null
    foreach ($package in @($packageLock.packages)) {
        $fileName =
            "$(([string]$package.id).ToLowerInvariant()).$($package.version).nupkg"
        $sourcePackage = Join-Path `
            $env:USERPROFILE `
            ".nuget\packages\$(([string]$package.id).ToLowerInvariant())\$($package.version)\$fileName"
        if (-not [IO.File]::Exists($sourcePackage)) {
            throw "Trusted-build real test requires cached package '$fileName'."
        }
        [IO.File]::Copy($sourcePackage, (Join-Path $packageRoot $fileName), $false)
    }

    $modulePath = Join-Path `
        $cleanRepo `
        'release\scripts\EnterpriseInstallerTrustedBuild.psm1'
    $stateModulePath = Join-Path `
        $cleanRepo `
        'release\scripts\ProductionReleaseState.psm1'
    $signingContractsPath = Join-Path `
        $cleanRepo `
        'release\scripts\InstallerSigningContracts.psm1'
    Import-Module $modulePath -Force -ErrorAction Stop
    Import-Module $signingContractsPath -Force -ErrorAction Stop
    Import-Module $stateModulePath -Force -ErrorAction Stop

    $launcherBytes = $utf8.GetBytes('trusted-r5-launcher-archive-fixture')
    $runtimeBytes = $utf8.GetBytes('trusted-r5-runtime-archive-fixture')
    $bootstrapperBytes = $utf8.GetBytes('trusted-r3-bootstrapper-fixture')
    $releaseSetBytes = $utf8.GetBytes('trusted-r5-release-set-fixture')
    $releasePublicKeyBytes = $utf8.GetBytes('trusted-r5-public-key-fixture')
    $pluginPolicyBytes = $utf8.GetBytes('trusted-r5-plugin-policy-fixture')
    $clientLauncherBytes = $utf8.GetBytes('trusted-r3-client-launcher-fixture')
    $clientBootstrapperBytes =
        $utf8.GetBytes('trusted-r3-client-bootstrapper-fixture')
    $maintenanceBytes = $utf8.GetBytes('trusted-r3-maintenance-fixture')
    $launcherSha = Get-Sha256Bytes -Bytes $launcherBytes
    $runtimeSha = Get-Sha256Bytes -Bytes $runtimeBytes
    $bootstrapperSha = Get-Sha256Bytes -Bytes $bootstrapperBytes
    $r5CompletedAtUtc = '2026-09-01T00:00:00Z'
    $manifestValue = [ordered]@{
        schemaVersion = 1
        layoutProfile = 'enterprise'
        launcherReleaseId = 'trusted-launcher-v1'
        runtimeReleaseId = 'managed-v2026.09.01.1'
        launcherArchive = 'launcher.zip'
        launcherArchiveSizeBytes = [int64]$launcherBytes.LongLength
        launcherArchiveSha256 = $launcherSha
        runtimeArchive = 'runtime.zip'
        runtimeArchiveSizeBytes = [int64]$runtimeBytes.LongLength
        runtimeArchiveSha256 = $runtimeSha
        bootstrapperFile = 'Ensou.Dsh.Enterprise.Bootstrapper.exe'
        bootstrapperSizeBytes = [int64]$bootstrapperBytes.LongLength
        bootstrapperSha256 = $bootstrapperSha
        publishedAtUtc = $r5CompletedAtUtc
    }
    $manifestBytes = ProductionReleaseState\ConvertTo-ProductionJsonBytes `
        -Value $manifestValue
    $manifestSha = Get-Sha256Bytes -Bytes $manifestBytes
    $payloadInputs = @(
        New-PayloadDescriptor `
            -Role 'install-manifest' `
            -FileName 'enterprise-install-manifest.json' `
            -Bytes $manifestBytes
        New-PayloadDescriptor `
            -Role 'launcher' `
            -FileName 'launcher.zip' `
            -Bytes $launcherBytes
        New-PayloadDescriptor `
            -Role 'runtime' `
            -FileName 'runtime.zip' `
            -Bytes $runtimeBytes
        New-PayloadDescriptor `
            -Role 'bootstrapper' `
            -FileName 'Ensou.Dsh.Enterprise.Bootstrapper.exe' `
            -Bytes $bootstrapperBytes)

    $orchestrationId = [Guid]::NewGuid().ToString()
    $releaseManifestTrust = New-TestP256Trust `
        -KeyId 'trusted-release-manifest' `
        -Purpose 'release-manifest-signing'
    $installerSigningTrust = New-TestP256Trust `
        -KeyId 'trusted-installer-signing' `
        -Purpose 'installer-signing-response'
    $releaseManifestTrustSha = Get-Sha256Bytes `
        -Bytes (ProductionReleaseState\ConvertTo-ProductionJsonBytes `
            -Value $releaseManifestTrust)
    $releaseCompatibilitySha = Get-Sha256Bytes `
        -Bytes (ProductionReleaseState\ConvertTo-ProductionJsonBytes `
            -Value ([ordered]@{ contract = 'trusted-build-test' }))
    $plan = [ordered]@{
        schemaVersion = 2
        planType = 'ensou-dsh-launcher-production-release'
        orchestrationId = $orchestrationId
        edition = 'Enterprise'
        releaseSetId = 'trusted-build-real-fixture'
        targetChannel = 'stable'
        sourceCommit = $sourceCommit
        authenticodePolicy = [ordered]@{
            signerSha256Thumbprint = 'a' * 64
            requireTrustedTimestamp = $true
            maximumResponseAgeMinutes = 60
        }
        releaseManifestTrust = $releaseManifestTrust
        externalResponseTrusts = [ordered]@{
            installerSigning = $installerSigningTrust
        }
    }
    $planInput = New-JsonInput -Value $plan -FileName 'plan.json'
    $r3Files = @(
        [ordered]@{
            role = 'bootstrapper'
            fileName = 'Ensou.Dsh.Enterprise.Bootstrapper.exe'
            sizeBytes = [int64]$bootstrapperBytes.LongLength
            sha256 = $bootstrapperSha
            peContentSha256 = Get-Sha256Bytes -Bytes $bootstrapperBytes
        },
        [ordered]@{
            role = 'launcher'
            fileName = 'Ensou.Dsh.Enterprise.Launcher.exe'
            sizeBytes = [int64]$clientLauncherBytes.LongLength
            sha256 = Get-Sha256Bytes -Bytes $clientLauncherBytes
            peContentSha256 = Get-Sha256Bytes -Bytes $clientLauncherBytes
        },
        [ordered]@{
            role = 'client-bootstrapper'
            fileName = 'Ensou.Dsh.Enterprise.ClientBootstrapper.exe'
            sizeBytes = [int64]$clientBootstrapperBytes.LongLength
            sha256 = Get-Sha256Bytes -Bytes $clientBootstrapperBytes
            peContentSha256 = Get-Sha256Bytes -Bytes $clientBootstrapperBytes
        },
        [ordered]@{
            role = 'maintenance'
            fileName = 'Ensou.Dsh.Enterprise.Maintenance.exe'
            sizeBytes = [int64]$maintenanceBytes.LongLength
            sha256 = Get-Sha256Bytes -Bytes $maintenanceBytes
            peContentSha256 = Get-Sha256Bytes -Bytes $maintenanceBytes
        })
    $r3Probes = @(
        [ordered]@{
            role = 'bootstrapper'
            fileName = 'Ensou.Dsh.Enterprise.Bootstrapper.exe'
            probeSha256 = '1' * 64
        },
        [ordered]@{
            role = 'launcher'
            fileName = 'Ensou.Dsh.Enterprise.Launcher.exe'
            probeSha256 = '2' * 64
        },
        [ordered]@{
            role = 'client-bootstrapper'
            fileName = 'Ensou.Dsh.Enterprise.ClientBootstrapper.exe'
            probeSha256 = '3' * 64
        })
    $r3 = [ordered]@{
        schemaVersion = 2
        receiptType = 'ensou-dsh-launcher-production-release-transition'
        orchestrationId = $orchestrationId
        edition = 'Enterprise'
        targetChannel = 'stable'
        planSha256 = $planInput.Sha256
        revision = 3
        phase = 'CLIENT_SIGNATURES_IMPORTED'
        data = [ordered]@{
            files = $r3Files
            releaseManifestTrustProbes = $r3Probes
        }
    }
    $r3Input = New-JsonInput -Value $r3 -FileName 'r3.json'
    $candidateRoot = 'imports/stable-signed-candidate.v1/candidate/'
    $candidateFiles = @(
        New-TestFileEvidence `
            -Role 'release-manifest' `
            -FileName 'release-set.v2.json' `
            -Bytes $releaseSetBytes `
            -RelativePath ($candidateRoot + 'release-set.v2.json')
        New-TestFileEvidence `
            -Role 'release-public-key' `
            -FileName 'release-public-key.v2.json' `
            -Bytes $releasePublicKeyBytes `
            -RelativePath ($candidateRoot + 'release-public-key.v2.json')
        New-TestFileEvidence `
            -Role 'launcher' `
            -FileName 'launcher.zip' `
            -Bytes $launcherBytes `
            -RelativePath ($candidateRoot + 'launcher.zip')
        New-TestFileEvidence `
            -Role 'runtime' `
            -FileName 'runtime.zip' `
            -Bytes $runtimeBytes `
            -RelativePath ($candidateRoot + 'runtime.zip')
        New-TestFileEvidence `
            -Role 'plugin-policy' `
            -FileName 'enterprise-plugin-policy.v1.json' `
            -Bytes $pluginPolicyBytes `
            -RelativePath ($candidateRoot + 'enterprise-plugin-policy.v1.json'))
    $r5 = [ordered]@{
        schemaVersion = 2
        receiptType = 'ensou-dsh-launcher-production-release-transition'
        orchestrationId = $orchestrationId
        edition = 'Enterprise'
        targetChannel = 'stable'
        planSha256 = $planInput.Sha256
        revision = 5
        phase = 'STABLE_SIGNED_CANDIDATE_IMPORTED'
        data = [ordered]@{
            completedAtUtc = $r5CompletedAtUtc
            responseSha256 = '4' * 64
            manifestSha256 = Get-Sha256Bytes -Bytes $releaseSetBytes
            releaseManifestTrustSha256 = $releaseManifestTrustSha
            releaseCompatibilitySha256 = $releaseCompatibilitySha
            files = $candidateFiles
        }
    }
    $r5Input = New-JsonInput -Value $r5 -FileName 'r5.json'
    $head = [ordered]@{
        revision = 5
        phase = 'STABLE_SIGNED_CANDIDATE_IMPORTED'
        receiptSha256 = $r5Input.Sha256
    }
    $headInput = New-JsonInput -Value $head -FileName 'head.json'
    $state = [pscustomobject]@{
        HeadSha256 = $headInput.Sha256
        Head = $head
        Receipts = @(
            $null,
            $null,
            $r3,
            [pscustomobject]@{ data = [pscustomobject]@{ requestSha256 = '5' * 64 } },
            $r5)
    }
    $payloadAdmission = [pscustomobject]@{
        Decision = 'PASS'
        SignerSha256Thumbprint = 'a' * 64
        ManifestSha256 = $manifestSha
        LauncherArchiveSha256 = $launcherSha
        RuntimeArchiveSha256 = $runtimeSha
        BootstrapperSha256 = $bootstrapperSha
        RuntimeEvidence = [pscustomobject]@{ Status = 'VERIFIED' }
        BootstrapperEvidence = [pscustomobject]@{ Status = 'VERIFIED' }
        ClientEvidence = [pscustomobject]@{ Status = 'VERIFIED' }
    }

    $msbuildInjectionMarker =
        Join-Path $testRoot 'MSBUILD-ENVIRONMENT-INJECTION-EXECUTED.txt'
    $maliciousTargetsPath = Join-Path $testRoot 'hostile-environment.targets'
    $escapedMarkerPath =
        [Security.SecurityElement]::Escape($msbuildInjectionMarker)
    $maliciousTargets = @"
<Project>
  <Target Name="EnsouHostileEnvironmentInjection" BeforeTargets="PrepareForBuild">
    <WriteLinesToFile File="$escapedMarkerPath" Lines="MSBUILD-ENVIRONMENT-INJECTION-EXECUTED" Overwrite="true" />
  </Target>
</Project>
"@
    [IO.File]::WriteAllText($maliciousTargetsPath, $maliciousTargets, $utf8)
    $hostileExtensionsPath = Join-Path $testRoot 'hostile-msbuild-extensions'
    [IO.Directory]::CreateDirectory($hostileExtensionsPath) | Out-Null
    $hostileValues = [ordered]@{
        DirectoryBuildPropsPath = $maliciousTargetsPath
        DirectoryBuildTargetsPath = $maliciousTargetsPath
        CustomBeforeMicrosoftCommonProps = $maliciousTargetsPath
        CustomAfterMicrosoftCommonProps = $maliciousTargetsPath
        CustomBeforeMicrosoftCommonTargets = $maliciousTargetsPath
        CustomAfterMicrosoftCommonTargets = $maliciousTargetsPath
        MSBuildExtensionsPath = $hostileExtensionsPath
        MSBuildExtensionsPath32 = $hostileExtensionsPath
        MSBuildExtensionsPath64 = $hostileExtensionsPath
        MSBuildUserExtensionsPath = $hostileExtensionsPath
        MSBuildSDKsPath = $hostileExtensionsPath
        MSBUILD_EXE_PATH = $maliciousTargetsPath
        MSBuildToolsPath = $hostileExtensionsPath
        GIT_WORK_TREE = (Join-Path $testRoot 'hostile-git-work-tree')
        GIT_DIR = (Join-Path $testRoot 'hostile-git-dir')
        GIT_INDEX_FILE = (Join-Path $testRoot 'hostile-git-index')
        GIT_CONFIG_SYSTEM = $maliciousTargetsPath
        GIT_CONFIG_GLOBAL = $maliciousTargetsPath
        GIT_CONFIG_COUNT = '1'
        GIT_CONFIG_KEY_0 = 'core.worktree'
        GIT_CONFIG_VALUE_0 = (Join-Path $testRoot 'hostile-git-work-tree')
        DOTNET_STARTUP_HOOKS = $maliciousTargetsPath
        DOTNET_ADDITIONAL_DEPS = $maliciousTargetsPath
        DOTNET_SHARED_STORE = $hostileExtensionsPath
        DOTNET_MSBUILD_SDK_RESOLVER_CLI_DIR = $hostileExtensionsPath
        DOTNET_MSBUILD_SDK_RESOLVER_SDKS_DIR = $hostileExtensionsPath
        DOTNET_MSBUILD_SDK_RESOLVER_SDKS_VER = '0.0.0-hostile'
        NUGET_PLUGIN_PATHS = $maliciousTargetsPath
        NUGET_CREDENTIALPROVIDERS_PATH = $hostileExtensionsPath
        PATH = $hostileExtensionsPath
    }
    $oldEnvironment = @{}
    foreach ($name in $hostileValues.Keys) {
        $oldEnvironment[$name] = [Environment]::GetEnvironmentVariable($name)
        [Environment]::SetEnvironmentVariable(
            $name,
            [string]$hostileValues[$name])
    }
    try {
        $result = New-EnterpriseInstallerTrustedBuild `
            -PlanInput $planInput `
            -ProductionState $state `
            -BaseHeadInput $headInput `
            -R5ReceiptInput $r5Input `
            -R3ReceiptInput $r3Input `
            -PayloadInputs $payloadInputs `
            -PayloadAdmission $payloadAdmission `
            -PackageDirectory $packageRoot `
            -DotNetSdkArchivePath $DotNetSdkArchivePath `
            -OutputDirectory $outputRoot
    }
    finally {
        foreach ($name in $hostileValues.Keys) {
            [Environment]::SetEnvironmentVariable($name, $oldEnvironment[$name])
        }
    }

    Assert-True `
        -Condition (-not (Test-Path -LiteralPath $msbuildInjectionMarker)) `
        -Message 'A hostile inherited MSBuild .targets file executed during the trusted build.'

    Assert-True `
        -Condition ([string]$result.Status -ceq
            'SIGNING_REQUEST_READY_NO_GO' -and
            [string]$result.ProductionAdmission -ceq 'NO_GO') `
        -Message 'Trusted build did not produce an honest fail-closed signing request.'
    Assert-True `
        -Condition ([string]$result.Blocker -ceq
            'INSTALLER_SIGNING_RESPONSE_REQUIRED') `
        -Message 'Trusted build did not advance to the exact signing-response gate.'
    Assert-True `
        -Condition ((Test-Path -LiteralPath (
                    Join-Path $outputRoot 'installer-signing-request.v2.json')) -and
            [int]$result.Request.schemaVersion -eq 2 -and
            $null -eq $result.Request.PSObject.Properties['payloadSelfCheck']) `
        -Message 'Trusted build did not produce request v2 without an unsigned self-check claim.'
    Assert-True `
        -Condition (-not (Test-Path -LiteralPath (Join-Path $outputRoot '.work'))) `
        -Message 'Trusted build retained private mutable work state.'
    Assert-True `
        -Condition ([string]$result.Evidence.signingRequestEligibility.status -ceq
            'ELIGIBLE_FOR_PILOT_SIGNING' -and
            [int]$result.Evidence.signingRequestEligibility.requestSchemaVersion -eq 2 -and
            [string]$result.Evidence.signingRequestEligibility.productionAdmission -ceq
                'NO_GO') `
        -Message 'Trusted-build evidence did not encode typed Pilot-only request eligibility.'
    Assert-True `
        -Condition ([string]$result.Evidence.toolchainLock.sdkFileClosureStatus -ceq
            'VERIFIED') `
        -Message 'Trusted-build evidence did not verify the private portable SDK closure.'
    Assert-True `
        -Condition ([string]$result.Evidence.toolchainLock.archiveSha512 -ceq
                '7d170ed75fa9af34c00646621d92011dbd71943952e2787cd15df9be78e6452b55dadef34d7eff77b802e6af4959e071a55855ac649afeac70901c3a2a258716' -and
            [string]$result.Evidence.toolchainLock.trackedLockSha256 -ceq
                (Get-FileHash -LiteralPath (Join-Path $cleanRepo `
                    'release\locks\dotnet-sdk-10.0.302-win-x64.files.lock.json') `
                    -Algorithm SHA256).Hash.ToLowerInvariant() -and
            [string]$result.Evidence.toolchainLock.inventorySha256 -ceq
                '61f22e921d448c2803f053616f581c47bcf4d9408fbc5e50e15e9b524ed2d9f3' -and
            [int]$result.Evidence.toolchainLock.fileCount -eq 5611 -and
            [int64]$result.Evidence.toolchainLock.totalSizeBytes -eq 798277746 -and
            [string]$result.Evidence.toolchainLock.archiveBindingStatus -ceq
                'ZIP_SHA512_AND_FILE_INVENTORY_VERIFIED') `
        -Message 'Trusted-build evidence did not bind the exact official SDK archive, reviewed lock, and file inventory.'
    Assert-True `
        -Condition ([string]$result.Evidence.toolchainLock.subprocessEnvironmentPolicy -ceq
            'clear-all-inherited-then-explicit-allowlist-and-msbuild-property-pins-v1') `
        -Message 'Trusted-build evidence omitted the subprocess environment policy.'
    Assert-True `
        -Condition (@($result.Evidence.sourceBuildInputs.transitiveProjects).Count -eq
            3) `
        -Message 'Trusted build did not close the real three-project Enterprise graph.'
    $trackedSourceInputs = @(
        $result.Evidence.sourceBuildInputs.files | Where-Object {
            [string]$_.identityPath -clike 'repo/*' -and
            [string]$_.kind -cne 'directory-build-targets-absent'
        })
    $gitBlobBindingInput =
        ProductionReleaseState\Read-StrictProductionJsonFile `
            -Path (Join-Path $result.OutputDirectory `
                'build-inputs\generated\git-blob-bindings.v1.json') `
            -Label 'Trusted-build Git blob bindings'
    $gitBlobBindings = $gitBlobBindingInput.Value
    ProductionReleaseState\Assert-ExactProductionJsonMembers `
        -Value $gitBlobBindings `
        -Expected @(
            'schemaVersion', 'bindingType', 'sourceCommit', 'sourceTree', 'files') `
        -Label 'Trusted-build Git blob bindings'
    Assert-True `
        -Condition ([int]$gitBlobBindings.schemaVersion -eq 1 -and
            [string]$gitBlobBindings.bindingType -ceq
                'ensou-dsh-enterprise-installer-git-blob-bindings' -and
            [string]$gitBlobBindings.sourceCommit -ceq
                [string]$result.Evidence.sourceCommit -and
            [string]$gitBlobBindings.sourceTree -ceq
                [string]$result.Evidence.sourceTree -and
            @($gitBlobBindings.files).Count -eq $trackedSourceInputs.Count) `
        -Message 'Git blob binding manifest does not close the exact tracked source set.'
    foreach ($binding in @($gitBlobBindings.files)) {
        ProductionReleaseState\Assert-ExactProductionJsonMembers `
            -Value $binding `
            -Expected @('identityPath', 'mode', 'objectId', 'sizeBytes', 'sha256') `
            -Label 'Trusted-build Git blob binding'
        $source = @($trackedSourceInputs | Where-Object {
                [string]$_.identityPath -ceq [string]$binding.identityPath
            })
        Assert-True `
            -Condition ($source.Count -eq 1 -and
                [string]$binding.mode -in @('100644', '100755') -and
                [string]$binding.objectId -cmatch
                    '^(?:[0-9a-f]{40}|[0-9a-f]{64})$' -and
                [int64]$binding.sizeBytes -eq [int64]$source[0].sizeBytes -and
                [string]$binding.sha256 -ceq [string]$source[0].sha256) `
            -Message "Git blob binding differs from source evidence: $($binding.identityPath)"
    }
    Assert-True `
        -Condition (@($result.Evidence.packageClosure.packages).Count -eq 4) `
        -Message 'Trusted build did not close the exact four-package offline feed.'
    Assert-True `
        -Condition (@($result.Evidence.resourceBinding.resources).Count -eq 4) `
        -Message 'Trusted build did not verify all four managed payload resources.'
    Assert-True `
        -Condition ([string]$result.Evidence.unsignedInstaller.authenticodeStatus -ceq
            'NotSigned') `
        -Message 'Trusted build output is not an exact unsigned Installer PE.'

    $tamperedRequest = ProductionReleaseState\ConvertFrom-StrictProductionJsonBytes `
        -Bytes (ProductionReleaseState\ConvertTo-ProductionJsonBytes `
            -Value $result.Request) `
        -Label 'Tampered request-v2 fixture'
    $tamperedRequest.resourceBinding.resources[0].sha256 = 'f' * 64
    Assert-Throws `
        -Label 'Resource binding tamper rejection' `
        -ExpectedMessage 'resource' `
        -Action {
            [void](InstallerSigningContracts\Assert-InstallerSigningRequestContract `
                -Request $tamperedRequest `
                -InstallerSigningTrust $installerSigningTrust `
                -ReleaseManifestTrust $releaseManifestTrust)
        }

    $legacySdkRequest =
        ProductionReleaseState\ConvertFrom-StrictProductionJsonBytes `
            -Bytes (ProductionReleaseState\ConvertTo-ProductionJsonBytes `
                -Value $result.Request) `
            -Label 'Legacy SDK prerequisite request-v2 fixture'
    $legacySdkRequest.trustedBuildEvidence.sdkFileClosureStatus =
        'EXTERNAL_HOST_PREREQUISITE_NOT_SNAPSHOTTED'
    Assert-Throws `
        -Label 'Legacy SDK prerequisite evidence rejection' `
        -ExpectedMessage 'verified portable SDK closure' `
        -Action {
            [void](InstallerSigningContracts\Assert-InstallerSigningRequestContract `
                -Request $legacySdkRequest `
                -InstallerSigningTrust $installerSigningTrust `
                -ReleaseManifestTrust $releaseManifestTrust)
        }

    Write-BytesCreateNew `
        -Path (Join-Path $cleanRepo 'untracked-hostile-build-input.txt') `
        -Bytes $utf8.GetBytes('must reject')
    Assert-Throws `
        -Label 'Dirty source rejection' `
        -ExpectedMessage 'dirty or contains untracked' `
        -Action {
            [void](New-EnterpriseInstallerTrustedBuild `
                -PlanInput $planInput `
                -ProductionState $state `
                -BaseHeadInput $headInput `
                -R5ReceiptInput $r5Input `
                -R3ReceiptInput $r3Input `
                -PayloadInputs $payloadInputs `
                -PayloadAdmission $payloadAdmission `
                -PackageDirectory $packageRoot `
                -DotNetSdkArchivePath $DotNetSdkArchivePath `
                -OutputDirectory $dirtyOutput)
        }
    Assert-True `
        -Condition (-not (Test-Path -LiteralPath $dirtyOutput)) `
        -Message 'Rejected dirty build created an output directory.'

    $moduleText = Get-Content -LiteralPath $modulePath -Raw
    foreach ($requiredSanitization in @(
            '$start.Environment.Clear()',
            'clear-all-inherited-then-explicit-allowlist-and-msbuild-property-pins-v1',
            'PortableDotNetSdkClosure\Open-PortableDotNetSdkArchiveClosure',
            'PortableDotNetSdkClosure\New-PortableDotNetSdkPrivateCopy',
            'PortableDotNetSdkClosure\Get-PortableDotNetSdkPrivateToolchain',
            'DOTNET_ROOT = $privateDotNetRoot',
            'DOTNET_ROOT_X64 = $privateDotNetRoot',
            "DOTNET_MULTILEVEL_LOOKUP = '0'",
            '-p:DirectoryBuildPropsPath=',
            '-p:DirectoryBuildTargetsPath=',
            '-p:CustomBeforeMicrosoftCommonProps=',
            '-p:CustomAfterMicrosoftCommonProps=',
            '-p:CustomBeforeMicrosoftCommonTargets=',
            '-p:CustomAfterMicrosoftCommonTargets=')) {
        Assert-True `
            -Condition $moduleText.Contains(
                $requiredSanitization,
                [StringComparison]::Ordinal) `
            -Message "Trusted build omits subprocess isolation evidence: $requiredSanitization."
    }
    Assert-True `
        -Condition (-not $moduleText.Contains(
                "Join-Path `$programFiles 'dotnet\dotnet.exe'",
                [StringComparison]::Ordinal)) `
        -Message 'Trusted build retained a Program Files dotnet fallback.'

    [pscustomobject]@{
        Decision = 'PASS'
        AssertionCount = $script:AssertionCount
        BuildStatus = [string]$result.Status
        Blocker = [string]$result.Blocker
        SourceCommit = [string]$result.Evidence.sourceCommit
        SourceTree = [string]$result.Evidence.sourceTree
        SourceInputCount = @($result.Evidence.sourceBuildInputs.files).Count
        GitBlobBindingCount = @($gitBlobBindings.files).Count
        TransitiveProjectCount =
            @($result.Evidence.sourceBuildInputs.transitiveProjects).Count
        OfflinePackageCount = @($result.Evidence.packageClosure.packages).Count
        ResourceBindingCount = @($result.Evidence.resourceBinding.resources).Count
        SdkFileClosureStatus =
            [string]$result.Evidence.toolchainLock.sdkFileClosureStatus
        SdkArchiveSha512 =
            [string]$result.Evidence.toolchainLock.archiveSha512
        SdkTrackedLockSha256 =
            [string]$result.Evidence.toolchainLock.trackedLockSha256
        SdkInventorySha256 =
            [string]$result.Evidence.toolchainLock.inventorySha256
        SdkFileCount = [int]$result.Evidence.toolchainLock.fileCount
        SdkTotalSizeBytes =
            [int64]$result.Evidence.toolchainLock.totalSizeBytes
        UnsignedInstallerSha256 =
            [string]$result.Evidence.unsignedInstaller.sha256
        RequestSchemaVersion = [int]$result.Request.schemaVersion
        UnsignedSelfCheckClaimed =
            $null -ne $result.Request.PSObject.Properties['payloadSelfCheck']
        ResourceTamperRejected = $true
        HostileEnvironmentNeutralized = $true
        MaliciousMsBuildTargetsRejected = $true
        DirtyCheckoutRejected = $true
    }
}
finally {
    if ($null -ne $result) {
        $result.Dispose()
    }
    for ($index = $payloadDescriptors.Count - 1; $index -ge 0; $index--) {
        $payloadDescriptors[$index].Stream.Dispose()
    }
    if ([IO.Directory]::Exists($testRoot) -and
        [IO.Path]::GetFileName($testRoot).StartsWith(
            'ensou-enterprise-installer-trusted-build-test-',
            [StringComparison]::Ordinal)) {
        [GC]::Collect()
        [GC]::WaitForPendingFinalizers()
        [GC]::Collect()
        for ($attempt = 0; $attempt -lt 50; $attempt++) {
            try {
                Remove-Item `
                    -LiteralPath $testRoot `
                    -Recurse `
                    -Force `
                    -ErrorAction Stop
                break
            }
            catch [IO.IOException], [UnauthorizedAccessException] {
                if ($attempt -eq 49) {
                    throw
                }
                [GC]::Collect()
                [GC]::WaitForPendingFinalizers()
                Start-Sleep -Milliseconds 100
            }
        }
    }
}
