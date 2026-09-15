#requires -Version 7.2

[CmdletBinding()]
param(
    [switch]$RunTrustedBuild,
    [string]$DotNetSdkArchivePath = '',
    [string]$PackageDirectory = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:Assertions = 0
function Assert-True {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )
    $script:Assertions++
    if (-not $Condition) {
        throw "ASSERTION FAILED: $Message"
    }
}

function Assert-Equal {
    param(
        [Parameter(Mandatory = $true)]$Expected,
        [Parameter(Mandatory = $true)]$Actual,
        [Parameter(Mandatory = $true)][string]$Message
    )
    $script:Assertions++
    if ($Expected -cne $Actual) {
        throw "ASSERTION FAILED: $Message Expected='$Expected' Actual='$Actual'"
    }
}

function Assert-Throws {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Action,
        [Parameter(Mandatory = $true)][string]$Pattern,
        [Parameter(Mandatory = $true)][string]$Message
    )
    $script:Assertions++
    try {
        & $Action
    }
    catch {
        if ($_.Exception.Message -notmatch $Pattern) {
            throw "ASSERTION FAILED: $Message Wrong error: $($_.Exception.Message)"
        }
        return
    }
    throw "ASSERTION FAILED: $Message No exception was thrown."
}

function ConvertTo-TestBase64Url {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    return [Convert]::ToBase64String($Bytes).TrimEnd('=').
        Replace('+', '-').Replace('/', '_')
}

function Get-TestSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    $stream = [IO.File]::OpenRead($Path)
    try {
        return [Convert]::ToHexString(
            [Security.Cryptography.SHA256]::HashData($stream)).ToLowerInvariant()
    }
    finally {
        $stream.Dispose()
    }
}

function New-TestArchive {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$EntryName,
        [Parameter(Mandatory = $true)][string]$Content
    )
    $file = [IO.FileStream]::new(
        $Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write,
        [IO.FileShare]::None)
    try {
        $zip = [IO.Compression.ZipArchive]::new(
            $file, [IO.Compression.ZipArchiveMode]::Create, $true)
        try {
            $entry = $zip.CreateEntry(
                $EntryName,
                [IO.Compression.CompressionLevel]::Optimal)
            $stream = $entry.Open()
            try {
                $bytes = [Text.UTF8Encoding]::new($false, $true).GetBytes($Content)
                $stream.Write($bytes)
            }
            finally {
                $stream.Dispose()
            }
        }
        finally {
            $zip.Dispose()
        }
        $file.Flush($true)
    }
    finally {
        $file.Dispose()
    }
}

$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$modulePath = Join-Path $PSScriptRoot 'PersonalInstallerTrustedBuild.psm1'
$stateModulePath = Join-Path $PSScriptRoot 'ProductionReleaseState.psm1'
$evidenceSchemaPath = Join-Path `
    ([IO.Path]::GetDirectoryName($PSScriptRoot)) `
    'schemas\personal-installer-trusted-build-evidence-v1.schema.json'
$requestSchemaPath = Join-Path `
    ([IO.Path]::GetDirectoryName($PSScriptRoot)) `
    'schemas\personal-installer-signing-request-v2.schema.json'
$packageLockPath = Join-Path $repositoryRoot `
    'installer\personal-publish-runtime-packs.lock.json'
$sdkLockPath = Join-Path $repositoryRoot `
    'release\locks\dotnet-sdk-10.0.302-win-x64.files.lock.json'

foreach ($required in @(
        $modulePath, $stateModulePath, $evidenceSchemaPath,
        $requestSchemaPath, $packageLockPath, $sdkLockPath)) {
    Assert-True ([IO.File]::Exists($required)) "Required file exists: $required"
}
$moduleText = [IO.File]::ReadAllText($modulePath)
Assert-True ($moduleText.Contains(
        'INSTALLER_SIGNING_RESPONSE_REQUIRED',
        [StringComparison]::Ordinal)) 'Builder emits the exact response-required blocker.'
Assert-True ($moduleText.Contains(
        "unsignedArtifactExecution = 'FORBIDDEN_AND_NOT_PERFORMED'",
        [StringComparison]::Ordinal)) 'Builder records unsigned execution prohibition.'
Assert-True (-not $moduleText.Contains(
        'Start-Process',
        [StringComparison]::OrdinalIgnoreCase)) 'Builder has no Start-Process escape path.'
Assert-True (-not $moduleText.Contains(
        'AssemblyLoadContext',
        [StringComparison]::Ordinal)) `
    'Builder never creates an AssemblyLoadContext for unsigned bytes.'
Assert-True (-not $moduleText.Contains(
        'LoadFromStream',
        [StringComparison]::Ordinal)) `
    'Builder never loads the unsigned managed resource carrier.'
Assert-True ($moduleText.Contains(
        '[Reflection.PortableExecutable.PEReader]::new',
        [StringComparison]::Ordinal)) `
    'Builder inspects the PE container without runtime assembly loading.'
Assert-True ($moduleText.Contains(
        '[Reflection.Metadata.PEReaderExtensions]::GetMetadataReader(',
        [StringComparison]::Ordinal)) `
    'Builder reads only manifest-resource metadata.'
Assert-True ($moduleText.Contains(
        '[IO.FileShare]::Read)',
        [StringComparison]::Ordinal)) `
    'Source-file leases deny concurrent write and delete access.'
Assert-True ($moduleText.Contains(
        '[EnsouLauncherPersonalBuild.SourceMutationMonitor]::new',
        [StringComparison]::Ordinal)) `
    'Source tree carries a transient mutation monitor for the full build.'

$tokens = $null
$parseErrors = $null
[void][Management.Automation.Language.Parser]::ParseFile(
    $modulePath, [ref]$tokens, [ref]$parseErrors)
Assert-Equal 0 $parseErrors.Count 'Builder module parses without PowerShell errors.'
$evidenceSchema = [IO.File]::ReadAllText($evidenceSchemaPath)
$requestSchema = [IO.File]::ReadAllText($requestSchemaPath)
Assert-True (Test-Json -Json $evidenceSchema -ErrorAction Stop) `
    'Evidence schema is valid JSON schema.'
Assert-True (Test-Json -Json $requestSchema -ErrorAction Stop) `
    'Request schema is valid JSON schema.'
$evidenceSchemaValue = $evidenceSchema | ConvertFrom-Json -Depth 64
$requestSchemaValue = $requestSchema | ConvertFrom-Json -Depth 64
Assert-Equal 'pilot' $evidenceSchemaValue.properties.channel.const `
    'Trusted-build evidence is explicitly Personal Pilot only.'
Assert-Equal 'pilot' $requestSchemaValue.properties.channel.const `
    'Personal signing request is explicitly Pilot only.'
Assert-Equal 'PILOT_SIGNED_CANDIDATE_IMPORTED' `
    $requestSchemaValue.properties.basePhase.const `
    'Personal signing request cannot claim a Stable r5 phase.'

Import-Module $modulePath -Force -ErrorAction Stop
Import-Module $stateModulePath -Force -ErrorAction Stop
$command = Get-Command New-PersonalInstallerTrustedBuild -ErrorAction Stop
foreach ($parameter in @(
        'Context', 'CompiledTrust', 'InstallerSigningResponseTrust',
        'PayloadDirectory', 'PackageDirectory', 'DotNetSdkArchivePath',
        'OutputDirectory', 'RepositoryRoot', 'GitPath')) {
    Assert-True $command.Parameters.ContainsKey($parameter) `
        "Builder exposes required parameter $parameter."
}

$trustedModule = Get-Module PersonalInstallerTrustedBuild
$packageLock = Get-Content -LiteralPath $packageLockPath -Raw |
    ConvertFrom-Json -Depth 16
Assert-True ([bool](& $trustedModule {
            param($value)
            Assert-PersonalTrustedPackageLockContract -Lock $value
        } $packageLock)) `
    'Exact four-package kind/id/version allowlist is accepted.'
foreach ($attack in @(
        [pscustomobject]@{ Field = 'kind'; Value = 'arbitrary-tool' },
        [pscustomobject]@{ Field = 'id'; Value = '..\..\attacker' },
        [pscustomobject]@{ Field = 'version'; Value = '..\10.0.10' })) {
    Assert-Throws {
        $tampered = $packageLock | ConvertTo-Json -Depth 16 -Compress |
            ConvertFrom-Json -Depth 16
        $tampered.packages[0].($attack.Field) = $attack.Value
        & $trustedModule {
            param($value)
            [void](Assert-PersonalTrustedPackageLockContract -Lock $value)
        } $tampered
    } 'fixed kind/id/version/byte contract' `
        "Package-lock $($attack.Field) traversal/substitution is rejected."
}

$guardTestRoot = Join-Path ([IO.Path]::GetTempPath()) (
    'ensou-personal-source-guard-test-' + [Guid]::NewGuid().ToString('N'))
$guardWorkRoot = Join-Path $guardTestRoot 'work'
$guardSourceRoot = Join-Path $guardWorkRoot 'repo'
$guard = $null
try {
    [IO.Directory]::CreateDirectory($guardSourceRoot) | Out-Null
    $guardFile = Join-Path $guardSourceRoot 'source.cs'
    [IO.File]::WriteAllText(
        $guardFile,
        'sealed class Guarded {}',
        [Text.UTF8Encoding]::new($false, $true))
    $guardRecord = & $trustedModule {
        param($path)
        [ordered]@{
            relativePath = 'source.cs'
            gitObjectId = Get-PersonalTrustedGitBlobObjectId `
                -Path $path `
                -ExpectedObjectId ('0' * 40)
            sizeBytes = [int64](Get-Item -LiteralPath $path -Force).Length
            sha256 = Get-PersonalTrustedFileSha256 -Path $path
        }
    } $guardFile
    $guardSource = [pscustomobject]@{ Files = @($guardRecord) }
    $guard = & $trustedModule {
        param($snapshot, $source, $work)
        Open-PersonalTrustedSourceGuard `
            -SnapshotRoot $snapshot `
            -Source $source `
            -WorkRoot $work
    } $guardSourceRoot $guardSource $guardWorkRoot
    Assert-Throws {
        [IO.File]::WriteAllText($guardFile, 'temporary-tamper-then-restore')
    } 'being used by another process|used by another process' `
        'Held source file cannot be temporarily rewritten.'
    Assert-Throws {
        [IO.File]::Delete($guardFile)
    } 'being used by another process|used by another process' `
        'Held source file cannot be deleted and replaced.'
    Assert-Throws {
        [IO.Directory]::Move($guardSourceRoot, "$guardSourceRoot-moved")
    } 'being used by another process|used by another process|Access.*denied' `
        'Held source directory identity cannot be swapped.'
    $transient = Join-Path $guardSourceRoot 'transient.cs'
    [IO.File]::WriteAllText($transient, 'transient-injection')
    [IO.File]::Delete($transient)
    Assert-Throws {
        & $trustedModule {
            param($value)
            Assert-PersonalTrustedSourceGuardUnchanged -Guard $value
        } $guard
    } 'source snapshot was mutated during build' `
        'Transient create-and-delete source injection is detected.'
}
finally {
    if ($null -ne $guard) {
        & $trustedModule {
            param($value)
            Close-PersonalTrustedSourceGuard -Guard $value
        } $guard
    }
    if ([IO.Directory]::Exists($guardTestRoot)) {
        Remove-Item -LiteralPath $guardTestRoot -Recurse -Force
    }
}

$invalidContext = [ordered]@{
    orchestrationId = 'not-a-uuid'
    channel = 'pilot'
    expectedReleaseSetId = 'personal-test-1'
    planSha256 = 'a' * 64
    baseHeadSha256 = 'b' * 64
    maximumResponseAgeMinutes = 120
}
$placeholderTrust = [ordered]@{
    manifestOrigin = 'https://updates.example.com/'
    artifactOrigin = 'https://artifacts.example.com/'
    releaseKeyId = 'release-key'
    releaseKeyX = 'A' * 43
    releaseKeyY = 'B' * 43
    startupStubVersion = '1.1.0'
    canonicalLowSFromSequence = 1
    authenticodeSignerSha256Thumbprint = 'c' * 64
}
$placeholderResponseTrust = [ordered]@{
    algorithm = 'ES256'
    purpose = 'installer-signing-response'
    keyId = 'response-key'
    x = 'C' * 43
    y = 'D' * 43
}
Assert-Throws {
    New-PersonalInstallerTrustedBuild `
        -Context $invalidContext `
        -CompiledTrust $placeholderTrust `
        -InstallerSigningResponseTrust $placeholderResponseTrust `
        -PayloadDirectory $repositoryRoot `
        -PackageDirectory $repositoryRoot `
        -DotNetSdkArchivePath $modulePath `
        -OutputDirectory (Join-Path ([IO.Path]::GetTempPath()) 'not-created')
} 'context is not canonical' 'Invalid context fails before any build or output.'
$stableContext = [ordered]@{
    orchestrationId = '12345678-1234-4abc-8def-1234567890ab'
    channel = 'stable'
    expectedReleaseSetId = 'personal-test-1'
    planSha256 = 'a' * 64
    baseHeadSha256 = 'b' * 64
    maximumResponseAgeMinutes = 120
}
Assert-Throws {
    New-PersonalInstallerTrustedBuild `
        -Context $stableContext `
        -CompiledTrust $placeholderTrust `
        -InstallerSigningResponseTrust $placeholderResponseTrust `
        -PayloadDirectory $repositoryRoot `
        -PackageDirectory $repositoryRoot `
        -DotNetSdkArchivePath $modulePath `
        -OutputDirectory (Join-Path ([IO.Path]::GetTempPath()) 'stable-not-created')
} 'context is not canonical' `
    'Personal Stable build is rejected before any filesystem output.'

if (-not $RunTrustedBuild) {
    "PASS Test-PersonalInstallerTrustedBuild contract assertions=$script:Assertions trustedBuild=NOT_REQUESTED"
    return
}
if ([string]::IsNullOrWhiteSpace($DotNetSdkArchivePath)) {
    throw '-RunTrustedBuild requires -DotNetSdkArchivePath.'
}
$DotNetSdkArchivePath = [IO.Path]::GetFullPath($DotNetSdkArchivePath)
Assert-True ([IO.File]::Exists($DotNetSdkArchivePath)) `
    'Requested portable SDK archive exists.'
Assert-Equal `
    -Expected 'dotnet-sdk-10.0.302-win-x64.zip' `
    -Actual ([IO.Path]::GetFileName($DotNetSdkArchivePath)) `
    -Message 'Requested portable SDK archive has the fixed name.'

$testRoot = Join-Path ([IO.Path]::GetTempPath()) (
    'ensou-personal-trusted-build-test-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($testRoot) | Out-Null
$fixtureRepository = Join-Path $testRoot 'repo'
$payloadRoot = Join-Path $testRoot 'payload'
$feedRoot = Join-Path $testRoot 'feed'
$outputRoot = Join-Path $testRoot 'output'
$result = $null
try {
    [IO.Directory]::CreateDirectory($fixtureRepository) | Out-Null
    $gitPath = Join-Path `
        ([Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)) `
        'Git\cmd\git.exe'
    Assert-True ([IO.File]::Exists($gitPath)) 'Native Program Files Git exists.'
    $tracked = @(& $gitPath `
            -c "safe.directory=$($repositoryRoot.Replace('\', '/'))" `
            -C $repositoryRoot `
            -c core.quotepath=false `
            ls-files)
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not list source repository tracked files.'
    }
    foreach ($relative in $tracked) {
        $source = Join-Path $repositoryRoot $relative.Replace('/', '\')
        $destination = Join-Path $fixtureRepository $relative.Replace('/', '\')
        $parent = [IO.Path]::GetDirectoryName($destination)
        if (-not [IO.Directory]::Exists($parent)) {
            [IO.Directory]::CreateDirectory($parent) | Out-Null
        }
        [IO.File]::Copy($source, $destination, $false)
    }
    foreach ($relative in @(
            'installer/personal-publish-runtime-packs.lock.json',
            'release/locks/dotnet-sdk-10.0.302-win-x64.files.lock.json',
            'release/schemas/personal-installer-trusted-build-evidence-v1.schema.json',
            'release/schemas/personal-installer-signing-request-v2.schema.json',
            'release/scripts/PersonalInstallerTrustedBuild.psm1',
            'release/scripts/Test-PersonalInstallerTrustedBuild.ps1',
            'src/Ensou.Dsh.Personal.Installer/PersonalInstallerProductionPayloadSelfCheckOutput.cs')) {
        $source = Join-Path $repositoryRoot $relative.Replace('/', '\')
        if (-not [IO.File]::Exists($source)) {
            continue
        }
        $destination = Join-Path $fixtureRepository $relative.Replace('/', '\')
        $parent = [IO.Path]::GetDirectoryName($destination)
        if (-not [IO.Directory]::Exists($parent)) {
            [IO.Directory]::CreateDirectory($parent) | Out-Null
        }
        [IO.File]::Copy($source, $destination, $true)
    }
    & $gitPath -C $fixtureRepository init --quiet
    & $gitPath -C $fixtureRepository config user.name 'ensou-test'
    & $gitPath -C $fixtureRepository config user.email 'test@example.invalid'
    & $gitPath -C $fixtureRepository config core.autocrlf false
    & $gitPath -C $fixtureRepository add --all --force
    & $gitPath -C $fixtureRepository commit --quiet -m 'personal trusted build fixture'
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not create clean Personal trusted-build fixture repository.'
    }
    Assert-Equal '' `
        ((& $gitPath -C $fixtureRepository status --porcelain=v1 `
                --untracked-files=all) -join '') `
        'Fixture repository is clean.'

    if ([string]::IsNullOrWhiteSpace($PackageDirectory)) {
        [IO.Directory]::CreateDirectory($feedRoot) | Out-Null
        $packageLock = Get-Content `
            -LiteralPath $packageLockPath `
            -Raw | ConvertFrom-Json -Depth 16
        foreach ($package in @($packageLock.packages)) {
            $fileName = "$(([string]$package.id).ToLowerInvariant()).$($package.version).nupkg"
            $source = Join-Path `
                (Join-Path `
                    (Join-Path `
                        (Join-Path $env:USERPROFILE '.nuget\packages') `
                        ([string]$package.id).ToLowerInvariant()) `
                    ([string]$package.version)) `
                $fileName
            Assert-True ([IO.File]::Exists($source)) `
                "Local locked test package exists: $fileName"
            [IO.File]::Copy($source, (Join-Path $feedRoot $fileName), $false)
        }
        $PackageDirectory = $feedRoot
    }
    else {
        $PackageDirectory = [IO.Path]::GetFullPath($PackageDirectory)
    }

    [IO.Directory]::CreateDirectory($payloadRoot) | Out-Null
    $clientArchive = Join-Path $payloadRoot 'client-bundle.zip'
    $runtimeArchive = Join-Path $payloadRoot 'runtime.zip'
    New-TestArchive `
        -Path $clientArchive `
        -EntryName 'client.txt' `
        -Content 'locked-personal-client'
    New-TestArchive `
        -Path $runtimeArchive `
        -EntryName 'runtime.txt' `
        -Content 'locked-personal-runtime'
    [IO.File]::WriteAllBytes(
        (Join-Path $payloadRoot 'Ensou.Dsh.Bootstrapper.exe'),
        [Text.UTF8Encoding]::new($false).GetBytes('locked-signed-stub-placeholder'))
    $releaseKey = [Security.Cryptography.ECDsa]::Create(
        [Security.Cryptography.ECCurve+NamedCurves]::nistP256)
    $responseKey = [Security.Cryptography.ECDsa]::Create(
        [Security.Cryptography.ECCurve+NamedCurves]::nistP256)
    try {
        $releaseParameters = $releaseKey.ExportParameters($false)
        $responseParameters = $responseKey.ExportParameters($false)
        $releaseKeyX = ConvertTo-TestBase64Url $releaseParameters.Q.X
        $releaseKeyY = ConvertTo-TestBase64Url $releaseParameters.Q.Y
        $responseKeyX = ConvertTo-TestBase64Url $responseParameters.Q.X
        $responseKeyY = ConvertTo-TestBase64Url $responseParameters.Q.Y
    }
    finally {
        $releaseKey.Dispose()
        $responseKey.Dispose()
    }
    $releaseSetId = 'personal-pilot-test-1'
    $artifactOrigin = 'https://artifacts.example.com/personal/'
    $signature = [ordered]@{
        algorithm = 'ES256'
        keyId = 'personal-release-test'
        value = 'A' * 86
    }
    $manifest = [ordered]@{
        schemaVersion = 2
        product = 'ensou-dsh-personal'
        environment = 'production'
        channel = 'pilot'
        releaseSetId = $releaseSetId
        provenance = [ordered]@{
            launcherRepositoryCommit = 'a' * 40
            harnessSourceTag = 'dsh-v0.1.2-test'
            harnessSourceCommit = 'b' * 40
        }
        generation = 1
        sequence = 1
        minAcceptedSequence = 0
        issuedAtUtc = '2026-09-03T00:00:00.0000000Z'
        expiresAtUtc = '2026-09-10T00:00:00.0000000Z'
        maximumOfflineGraceSeconds = 604800
        startupStub = [ordered]@{
            minimumVersion = '1.1.0'
            maximumVersion = '1.9.9'
        }
        revokedReleaseSetIds = @()
        artifacts = @(
            [ordered]@{
                component = 'client-bundle'
                releaseId = 'client-test-1'
                uri = $artifactOrigin + 'client-bundle.zip'
                sizeBytes = [int64](Get-Item $clientArchive).Length
                sha256 = Get-TestSha256 $clientArchive
                completeTreeSha256 = 'c' * 64
                signature = $signature
            },
            [ordered]@{
                component = 'runtime'
                releaseId = 'runtime-test-1'
                uri = $artifactOrigin + 'runtime.zip'
                sizeBytes = [int64](Get-Item $runtimeArchive).Length
                sha256 = Get-TestSha256 $runtimeArchive
                completeTreeSha256 = 'd' * 64
                signature = $signature
            })
        signature = $signature
    }
    [IO.File]::WriteAllBytes(
        (Join-Path $payloadRoot 'release-set.v2.json'),
        (ProductionReleaseState\ConvertTo-ProductionJsonBytes -Value $manifest))
    $context = [ordered]@{
        orchestrationId = [Guid]::NewGuid().ToString()
        channel = 'pilot'
        expectedReleaseSetId = $releaseSetId
        planSha256 = 'e' * 64
        baseHeadSha256 = 'f' * 64
        maximumResponseAgeMinutes = 120
    }
    $compiledTrust = [ordered]@{
        manifestOrigin = 'https://updates.example.com/personal/'
        artifactOrigin = $artifactOrigin
        releaseKeyId = 'personal-release-test'
        releaseKeyX = $releaseKeyX
        releaseKeyY = $releaseKeyY
        startupStubVersion = '1.1.0'
        canonicalLowSFromSequence = 1
        authenticodeSignerSha256Thumbprint = '1' * 64
    }
    $responseTrust = [ordered]@{
        algorithm = 'ES256'
        purpose = 'installer-signing-response'
        keyId = 'personal-installer-response-test'
        x = $responseKeyX
        y = $responseKeyY
    }
    $result = New-PersonalInstallerTrustedBuild `
        -Context $context `
        -CompiledTrust $compiledTrust `
        -InstallerSigningResponseTrust $responseTrust `
        -PayloadDirectory $payloadRoot `
        -PackageDirectory $PackageDirectory `
        -DotNetSdkArchivePath $DotNetSdkArchivePath `
        -OutputDirectory $outputRoot `
        -RepositoryRoot $fixtureRepository `
        -GitPath $gitPath
    Assert-Equal 'SIGNING_REQUEST_READY_NO_GO' $result.Status `
        'Trusted builder returns the Personal Pilot request-ready status.'
    Assert-Equal 'INSTALLER_SIGNING_RESPONSE_REQUIRED' `
        $result.Blocker `
        'Trusted builder remains NO_GO until genuine signing response import.'
    Assert-Equal 'NO_GO' $result.ProductionAdmission `
        'Trusted builder cannot admit production.'
    Assert-Equal 'FORBIDDEN_AND_NOT_PERFORMED' `
        $result.Evidence.buildExecution.unsignedArtifactExecution `
        'Evidence records that the unsigned artifact was not executed.'
    Assert-Equal 'VERIFIED' $result.Evidence.sdkClosure.status `
        'Evidence binds the verified portable SDK closure.'
    Assert-Equal 'pilot' $result.Evidence.channel `
        'Real trusted build is Personal Pilot only.'
    Assert-Equal 'READY' `
        $result.Evidence.signingRequestEligibility.status `
        'Exact signing request is eligible for isolated external signing.'
    Assert-Equal 'pe-metadata-embedded-resource-inspection-no-assembly-load-v1' `
        $result.Evidence.resourceBinding.verificationMethod `
        'Real payload resource bytes were inspected without loading the assembly.'
    Assert-Equal `
        'git-head-archive-held-file-leases-directory-identity-mutation-monitor-v2' `
        $result.Evidence.source.snapshotContract `
        'Real build records continuous source file and directory protection.'
    Assert-Equal `
        -Expected 4 `
        -Actual @($result.Evidence.payload.files).Count `
        -Message 'Evidence binds exactly four payload files.'
    Assert-True (-not [IO.Directory]::Exists((Join-Path $outputRoot 'work'))) `
        'Private SDK, source, and restore work tree is removed before return.'
    foreach ($path in @(
            (Join-Path $outputRoot 'personal-installer-signing-request.v2.json'),
            (Join-Path $outputRoot 'trusted-build\trusted-build-evidence.v1.json'),
            (Join-Path $outputRoot 'unsigned\Ensou.Dsh.Personal.Installer.exe'))) {
        Assert-True ([IO.File]::Exists($path)) "Expected builder output exists: $path"
    }
    $requestJson = [IO.File]::ReadAllText(
        (Join-Path $outputRoot 'personal-installer-signing-request.v2.json'))
    $evidenceJson = [IO.File]::ReadAllText(
        (Join-Path $outputRoot 'trusted-build\trusted-build-evidence.v1.json'))
    Assert-True (Test-Json -Json $requestJson -SchemaFile $requestSchemaPath) `
        'Real signing request satisfies its strict schema.'
    Assert-True (Test-Json -Json $evidenceJson -SchemaFile $evidenceSchemaPath) `
        'Real trusted-build evidence satisfies its strict schema.'
    Assert-Equal 'NotSigned' `
        (Get-AuthenticodeSignature `
            -LiteralPath (Join-Path $outputRoot `
                'unsigned\Ensou.Dsh.Personal.Installer.exe')).Status.ToString() `
        'Builder output remains unsigned for isolated r6 signing.'
    Assert-Equal '' `
        ((& $gitPath -C $fixtureRepository status --porcelain=v1 `
                --untracked-files=all) -join '') `
        'Trusted build does not mutate its source fixture.'
    "PASS Test-PersonalInstallerTrustedBuild assertions=$script:Assertions trustedBuild=REAL blocker=$($result.Blocker)"
}
finally {
    if ($null -ne $result) {
        $result.Dispose()
    }
    if ([IO.Directory]::Exists($testRoot) -and
        [IO.Path]::GetFileName($testRoot).StartsWith(
            'ensou-personal-trusted-build-test-',
            [StringComparison]::Ordinal)) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}
