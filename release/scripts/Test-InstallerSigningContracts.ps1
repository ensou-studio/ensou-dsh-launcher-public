#requires -Version 7.2

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$modulePath = Join-Path $PSScriptRoot 'InstallerSigningContracts.psm1'
$personalPipelinePath = Join-Path $PSScriptRoot 'PersonalInstallerSigningPipeline.psm1'
$stateModulePath = Join-Path $PSScriptRoot 'ProductionReleaseState.psm1'
$schemaRoot = Join-Path $repositoryRoot 'release\schemas'
$requestSchema = Join-Path $schemaRoot 'launcher-installer-signing-request-v1.schema.json'
$requestSchemaV2 = Join-Path $schemaRoot 'launcher-installer-signing-request-v2.schema.json'
$enterpriseRequestSchemaV2 = Join-Path `
    $schemaRoot 'launcher-enterprise-installer-signing-request-v2.schema.json'
$responseSchema = Join-Path $schemaRoot 'launcher-installer-signing-response-v1.schema.json'
$personalResponseSchemaV2 = Join-Path `
    $schemaRoot 'personal-installer-signing-response-v2.schema.json'
$admissionSchema = Join-Path $schemaRoot 'launcher-installer-signing-admission-v1.schema.json'
$fixtureStatusPath = Join-Path $repositoryRoot `
    'release\fixtures\installer-signing-contract-v1\fixture-status.v1.json'
Microsoft.PowerShell.Core\Import-Module $personalPipelinePath -Force
Microsoft.PowerShell.Core\Import-Module $modulePath -Force
Microsoft.PowerShell.Core\Import-Module $stateModulePath -Force

$script:Utf8 = [Text.UTF8Encoding]::new($false, $true)
$script:P256Order = [Convert]::FromHexString(
    'FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551')
$script:P256HalfOrder = [Convert]::FromHexString(
    '7FFFFFFF800000007FFFFFFFFFFFFFFFDE737D56D38BCF4279DCE5617E3192A8')

function Assert-True {
    param([Parameter(Mandatory = $true)][bool]$Condition, [string]$Message = '')
    if (-not $Condition) {
        throw "ASSERT-TRUE failed: $Message"
    }
}

function Assert-Equal {
    param($Actual, $Expected, [string]$Message = '')
    if ($Actual -cne $Expected) {
        throw "ASSERT-EQUAL failed: $Message; expected '$Expected', got '$Actual'."
    }
}

function Assert-Fails {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Action,
        [Parameter(Mandatory = $true)][string]$Pattern,
        [Parameter(Mandatory = $true)][string]$Message
    )
    try {
        & $Action
    }
    catch {
        if ($_.Exception.Message -notlike "*$Pattern*") {
            throw "ASSERT-FAILS wrong error: $Message; $($_.Exception.Message)"
        }
        return
    }
    throw "ASSERT-FAILS did not fail: $Message"
}

function Get-TestSha256 {
    param([Parameter(Mandatory = $true)][string]$Seed)
    return [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($script:Utf8.GetBytes($Seed))).
        ToLowerInvariant()
}

function ConvertTo-TestBase64Url {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    return [Convert]::ToBase64String($Bytes).TrimEnd('=').
        Replace('+', '-').Replace('/', '_')
}

function Compare-TestBigEndian {
    param([byte[]]$Left, [byte[]]$Right)
    for ($index = 0; $index -lt $Left.Length; $index++) {
        if ($Left[$index] -lt $Right[$index]) { return -1 }
        if ($Left[$index] -gt $Right[$index]) { return 1 }
    }
    return 0
}

function Subtract-TestBigEndian {
    param([byte[]]$Left, [byte[]]$Right)
    $result = [byte[]]::new($Left.Length)
    $borrow = 0
    for ($index = $Left.Length - 1; $index -ge 0; $index--) {
        $value = [int]$Left[$index] - [int]$Right[$index] - $borrow
        if ($value -lt 0) {
            $value += 256
            $borrow = 1
        }
        else {
            $borrow = 0
        }
        $result[$index] = [byte]$value
    }
    if ($borrow -ne 0) { throw 'Test P-256 subtraction underflowed.' }
    return $result
}

function ConvertTo-TestLowS {
    param([Parameter(Mandatory = $true)][byte[]]$Signature)
    if ($Signature.Length -ne 64) { throw 'Test signature is not P1363.' }
    [byte[]]$s = $Signature[32..63]
    if ((Compare-TestBigEndian $s $script:P256HalfOrder) -gt 0) {
        $s = Subtract-TestBigEndian $script:P256Order $s
        [Array]::Copy($s, 0, $Signature, 32, 32)
    }
    return $Signature
}

function ConvertTo-TestHighS {
    param([Parameter(Mandatory = $true)][byte[]]$LowSignature)
    $high = [byte[]]$LowSignature.Clone()
    [byte[]]$s = $high[32..63]
    $s = Subtract-TestBigEndian $script:P256Order $s
    if ((Compare-TestBigEndian $s $script:P256HalfOrder) -le 0) {
        throw 'Test could not construct a high-S signature.'
    }
    [Array]::Copy($s, 0, $high, 32, 32)
    return $high
}

function New-TestTrust {
    param(
        [Parameter(Mandatory = $true)][string]$KeyId,
        [Parameter(Mandatory = $true)][string]$Purpose
    )
    $signer = [Security.Cryptography.ECDsa]::Create(
        [Security.Cryptography.ECCurve+NamedCurves]::nistP256)
    $parameters = $signer.ExportParameters($true)
    return [pscustomobject]@{
        Signer = $signer
        Trust = [pscustomobject][ordered]@{
            algorithm = 'ES256'
            keyId = $KeyId
            purpose = $Purpose
            x = ConvertTo-TestBase64Url -Bytes $parameters.Q.X
            y = ConvertTo-TestBase64Url -Bytes $parameters.Q.Y
        }
    }
}

function ConvertTo-WholeSecondUtc {
    param([Parameter(Mandatory = $true)][DateTimeOffset]$Value)
    $utc = $Value.ToUniversalTime()
    $whole = [DateTimeOffset]::new(
        $utc.UtcTicks - ($utc.UtcTicks % [TimeSpan]::TicksPerSecond),
        [TimeSpan]::Zero)
    return $whole.ToString(
        'yyyy-MM-ddTHH:mm:ssZ',
        [Globalization.CultureInfo]::InvariantCulture)
}

function New-TestFile {
    param(
        [string]$Role,
        [string]$FileName,
        [string]$RelativePath,
        [string]$Seed,
        [long]$Size = 101
    )
    return [pscustomobject][ordered]@{
        role = $Role
        fileName = $FileName
        relativePath = $RelativePath
        sizeBytes = $Size
        sha256 = Get-TestSha256 "$Seed-full"
    }
}

function New-TestSignedClient {
    param(
        [string]$Role,
        [string]$FileName,
        [string]$Seed,
        [long]$Size = 201
    )
    $file = New-TestFile `
        -Role $Role `
        -FileName $FileName `
        -RelativePath "imports/client-signing.v1/signed/$FileName" `
        -Seed $Seed `
        -Size $Size
    $file | Add-Member -NotePropertyName peContentSha256 `
        -NotePropertyValue (Get-TestSha256 "$Seed-pe")
    return $file
}

function New-TestPayloadFile {
    param(
        [string]$Edition,
        [string]$Role,
        [string]$FileName,
        [string]$SourceKind,
        [string]$SourceRole,
        [string]$Sha256,
        [long]$SizeBytes
    )
    return [pscustomobject][ordered]@{
        role = $Role
        fileName = $FileName
        embeddedLogicalName = "Ensou.Dsh.$Edition.Installer.Payload.$FileName"
        sourceKind = $SourceKind
        sourceRole = $SourceRole
        sourceSha256 = $Sha256
        sizeBytes = $SizeBytes
        sha256 = $Sha256
    }
}

function New-TestBuildInput {
    param(
        [Parameter(Mandatory = $true)][string]$Kind,
        [Parameter(Mandatory = $true)][string]$IdentityPath,
        [Parameter(Mandatory = $true)][string]$Sha256,
        [long]$SizeBytes = 91
    )
    return [pscustomobject][ordered]@{
        kind = $Kind
        identityPath = $IdentityPath
        snapshotRelativePath = 'build-inputs/' + $IdentityPath
        sizeBytes = $SizeBytes
        sha256 = $Sha256
    }
}

function New-TestUnsignedPeBytes {
    [byte[]]$bytes = [byte[]]::new(512)
    $bytes[0] = 0x4d
    $bytes[1] = 0x5a
    [BitConverter]::GetBytes([int]0x80).CopyTo($bytes, 0x3c)
    $bytes[0x80] = 0x50
    $bytes[0x81] = 0x45
    [BitConverter]::GetBytes([uint16]0xe0).CopyTo($bytes, 0x80 + 20)
    [BitConverter]::GetBytes([uint16]0x10b).CopyTo($bytes, 0x80 + 24)
    return $bytes
}

function Copy-TestObject {
    param([Parameter(Mandatory = $true)]$Value)
    $bytes = ProductionReleaseState\ConvertTo-ProductionJsonBytes -Value $Value
    return $script:Utf8.GetString($bytes) |
        ConvertFrom-Json -Depth 128 -DateKind String
}

function Write-TestJson {
    param([string]$Path, $Value)
    [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($Path)) | Out-Null
    [IO.File]::WriteAllBytes(
        $Path,
        (ProductionReleaseState\ConvertTo-ProductionJsonBytes -Value $Value))
}

function Sync-TestSourceBuildInputClosure {
    param([Parameter(Mandatory = $true)][psobject]$Request)

    $files = @($Request.sourceBuildInputs.files)
    $setSha = Get-InstallerSigningObjectSha256 -Value $files
    [int64]$total = 0
    foreach ($file in $files) {
        if ([string]$file.kind -cne 'directory-build-targets-absent') {
            $total += [int64]$file.sizeBytes
        }
    }
    $Request.sourceBuildInputSetSha256 = $setSha
    $Request.sourceBuildInputs.inventorySha256 = $setSha
    $Request.sourceBuildInputs.preBuildInventorySha256 = $setSha
    $Request.sourceBuildInputs.postBuildInventorySha256 = $setSha
    $Request.sourceBuildInputs.totalSizeBytes = $total
    $Request.buildExecution.targetBuildIdentitySha256 =
        Get-InstallerTargetBuildIdentitySha256 -Request $Request
}

function New-TestRequest {
    param(
        [ValidateSet('Personal', 'Enterprise')][string]$Edition,
        [ValidateSet('pilot', 'stable')][string]$Channel,
        [psobject]$InstallerTrust,
        [psobject]$ReleaseTrust,
        [DateTimeOffset]$Now
    )
    $candidateRoot = "imports/$Channel-signed-candidate.v1/candidate/"
    if ($Edition -ceq 'Personal') {
        $candidate = @(
            (New-TestFile 'release-manifest' 'release-set.v2.json' `
                ($candidateRoot + 'release-set.v2.json') 'personal-manifest' 301),
            (New-TestFile 'client-bundle' 'client-bundle.zip' `
                ($candidateRoot + 'client-bundle.zip') 'personal-client' 302),
            (New-TestFile 'runtime' 'runtime.zip' `
                ($candidateRoot + 'runtime.zip') 'personal-runtime' 303))
        $signedClients = @(
            (New-TestSignedClient 'startup-stub' 'Ensou.Dsh.Bootstrapper.exe' `
                'personal-stub' 401),
            (New-TestSignedClient 'client-bootstrapper' `
                'Ensou.Dsh.ClientBootstrapper.exe' 'personal-client-bootstrapper' 402),
            (New-TestSignedClient 'launcher' 'Ensou.Dsh.Launcher.exe' `
                'personal-launcher' 403),
            (New-TestSignedClient 'maintenance' 'Ensou.Dsh.Personal.Maintenance.exe' `
                'personal-maintenance' 404))
        $probeRoles = @('startup-stub', 'client-bootstrapper', 'launcher', 'maintenance')
        $payload = @(
            (New-TestPayloadFile Personal 'release-manifest' 'release-set.v2.json' `
                'r5-candidate' 'release-manifest' $candidate[0].sha256 $candidate[0].sizeBytes),
            (New-TestPayloadFile Personal 'startup-stub' 'Ensou.Dsh.Bootstrapper.exe' `
                'r3-signed-client' 'startup-stub' $signedClients[0].sha256 $signedClients[0].sizeBytes),
            (New-TestPayloadFile Personal 'client-bundle' 'client-bundle.zip' `
                'r5-candidate' 'client-bundle' $candidate[1].sha256 $candidate[1].sizeBytes),
            (New-TestPayloadFile Personal 'runtime' 'runtime.zip' `
                'r5-candidate' 'runtime' $candidate[2].sha256 $candidate[2].sizeBytes))
        $installerName = 'Ensou.Dsh.Personal.Installer.exe'
    }
    else {
        $candidate = @(
            (New-TestFile 'release-manifest' 'release-set.v2.json' `
                ($candidateRoot + 'release-set.v2.json') 'enterprise-manifest' 501),
            (New-TestFile 'release-public-key' 'release-public-key.v2.json' `
                ($candidateRoot + 'release-public-key.v2.json') 'enterprise-key' 502),
            (New-TestFile 'launcher' 'launcher.zip' `
                ($candidateRoot + 'launcher.zip') 'enterprise-launcher-archive' 503),
            (New-TestFile 'runtime' 'runtime.zip' `
                ($candidateRoot + 'runtime.zip') 'enterprise-runtime' 504),
            (New-TestFile 'plugin-policy' 'managed-plugin-policy-g3.zip' `
                ($candidateRoot + 'managed-plugin-policy-g3.zip') 'enterprise-plugin' 505))
        $signedClients = @(
            (New-TestSignedClient 'bootstrapper' `
                'Ensou.Dsh.Enterprise.Bootstrapper.exe' 'enterprise-stub' 601),
            (New-TestSignedClient 'launcher' `
                'Ensou.Dsh.Enterprise.Launcher.exe' 'enterprise-launcher' 602),
            (New-TestSignedClient 'client-bootstrapper' `
                'Ensou.Dsh.Enterprise.ClientBootstrapper.exe' `
                'enterprise-client-bootstrapper' 603),
            (New-TestSignedClient 'maintenance' `
                'Ensou.Dsh.Enterprise.Maintenance.exe' 'enterprise-maintenance' 604))
        $probeRoles = @('bootstrapper', 'launcher', 'client-bootstrapper')
        $installManifestSha = Get-TestSha256 'enterprise-install-manifest'
        $payload = @(
            (New-TestPayloadFile Enterprise 'install-manifest' `
                'enterprise-install-manifest.json' 'generated-descriptor' `
                'install-manifest' $installManifestSha 701),
            (New-TestPayloadFile Enterprise 'launcher' 'launcher.zip' `
                'r5-candidate' 'launcher' $candidate[2].sha256 $candidate[2].sizeBytes),
            (New-TestPayloadFile Enterprise 'runtime' 'runtime.zip' `
                'r5-candidate' 'runtime' $candidate[3].sha256 $candidate[3].sizeBytes),
            (New-TestPayloadFile Enterprise 'bootstrapper' `
                'Ensou.Dsh.Enterprise.Bootstrapper.exe' 'r3-signed-client' `
                'bootstrapper' $signedClients[0].sha256 $signedClients[0].sizeBytes))
        $installerName = 'Ensou.Dsh.Enterprise.Installer.exe'
    }
    $probes = @($probeRoles | ForEach-Object {
            $role = $_
            $client = $signedClients | Where-Object { $_.role -ceq $role }
            [pscustomobject][ordered]@{
                role = $role
                fileName = [string]$client.fileName
                probeSha256 = Get-TestSha256 "$Edition-$role-probe"
            }
        })
    $candidateSha = Get-InstallerSigningObjectSha256 -Value $candidate
    $signedClientSha = Get-InstallerSigningObjectSha256 -Value $signedClients
    $probeSha = Get-InstallerSigningObjectSha256 -Value $probes
    $payloadSha = Get-InstallerSigningObjectSha256 -Value $payload
    $releaseTrustSha = Get-InstallerSigningObjectSha256 -Value $ReleaseTrust
    $projectName = "Ensou.Dsh.$Edition.Installer.csproj"
    $rootProjectIdentity =
        "repo/src/Ensou.Dsh.$Edition.Installer/$projectName"
    $sourceTree = Get-TestSha256 "$Edition-source-tree"
    $globalJsonSha = Get-TestSha256 "$Edition-global-json"
    $projectSha = Get-TestSha256 "$Edition-project"
    $assetsSha = Get-TestSha256 "$Edition-assets"
    $packagesLockSha = Get-TestSha256 "$Edition-packages-lock"
    $sourceInputs = @(
        (New-TestBuildInput 'restore-graph' 'generated/project.assets.json' `
            $assetsSha 801),
        (New-TestBuildInput 'generated-input' `
            'payload/installer-payload-set.v1.json' `
            (Get-TestSha256 "$Edition-payload-descriptor") 802),
        (New-TestBuildInput 'directory-build-props' `
            'repo/Directory.Build.props' `
            (Get-TestSha256 "$Edition-directory-build-props") 803),
        ([pscustomobject][ordered]@{
            kind = 'directory-build-targets-absent'
            identityPath = 'repo/Directory.Build.targets'
            absenceStatus = 'VERIFIED_ABSENT'
        }),
        (New-TestBuildInput 'global-json' 'repo/global.json' `
            $globalJsonSha 804),
        (New-TestBuildInput 'project' $rootProjectIdentity $projectSha 805),
        (New-TestBuildInput 'packages-lock' `
            "repo/src/Ensou.Dsh.$Edition.Installer/packages.lock.json" `
            $packagesLockSha 807),
        (New-TestBuildInput 'source' `
            "repo/src/Ensou.Dsh.$Edition.Installer/Program.cs" `
            (Get-TestSha256 "$Edition-program-source") 806),
        (New-TestBuildInput 'packages-lock' `
            'repo/src/Shared/packages.lock.json' `
            (Get-TestSha256 "$Edition-shared-packages-lock") 811),
        (New-TestBuildInput 'source' 'repo/src/Shared/Support.cs' `
            (Get-TestSha256 "$Edition-shared-source") 808),
        (New-TestBuildInput 'project' 'repo/src/Shared/Support.csproj' `
            (Get-TestSha256 "$Edition-shared-project") 809),
        (New-TestBuildInput 'runtime-pack' `
            'runtime-pack/Microsoft.NETCore.App.Runtime.win-x64/10.0.302/pack.sha256' `
            (Get-TestSha256 "$Edition-runtime-pack") 810)
    )
    $sourceInputSetSha = Get-InstallerSigningObjectSha256 -Value $sourceInputs
    [int64]$sourceInputTotalBytes = 0
    foreach ($sourceInput in $sourceInputs) {
        if ([string]$sourceInput.kind -cne
            'directory-build-targets-absent') {
            $sourceInputTotalBytes += [int64]$sourceInput.sizeBytes
        }
    }
    $runtimeInputs = @($sourceInputs | Where-Object {
            [string]$_.kind -ceq 'runtime-pack'
        })
    $dependencyInputs = @($sourceInputs | Where-Object {
            [string]$_.kind -in @(
                'project', 'packages-lock', 'restore-graph', 'runtime-pack')
        })
    $sourceBuildInputs = [pscustomobject][ordered]@{
        contract = 'tracked-clean-ordinary-single-link-exact-msbuild-graph-v1'
        sourceTree = $sourceTree
        rootProjectIdentityPath = $rootProjectIdentity
        inventorySha256 = $sourceInputSetSha
        preBuildInventorySha256 = $sourceInputSetSha
        postBuildInventorySha256 = $sourceInputSetSha
        totalSizeBytes = $sourceInputTotalBytes
        trackedClean = $true
        dirtyPathCount = 0
        untrackedPathCount = 0
        linkedInputCount = 0
        raceCheckStatus = 'VERIFIED_UNCHANGED'
        files = $sourceInputs
    }
    $toolchain = [pscustomobject][ordered]@{
        sdkVersion = '10.0.302'
        globalJsonRelativePath = 'toolchain/global.json'
        globalJsonSha256 = $globalJsonSha
        projectFileName = $projectName
        projectRelativePath = "toolchain/$projectName"
        projectSha256 = $projectSha
        packagesLockRelativePath = 'toolchain/packages.lock.json'
        packagesLockSha256 = $packagesLockSha
        packagesLockStatus = 'VERIFIED'
        restoreGraphRelativePath = 'toolchain/project.assets.json'
        restoreGraphSha256 = $assetsSha
        dependencyClosureSha256 = Get-InstallerSigningObjectSha256 `
            -Value $dependencyInputs
        runtimePackSetSha256 = Get-InstallerSigningObjectSha256 `
            -Value $runtimeInputs
        sdkInfoRelativePath = 'toolchain/dotnet-sdk-info.v1.json'
        sdkInfoSha256 = Get-TestSha256 "$Edition-sdk-info"
        configuration = 'Release'
        runtimeIdentifier = 'win-x64'
        selfContained = $true
        publishSingleFile = $true
        deterministic = $true
        continuousIntegrationBuild = $true
        restoreMode = 'packages-lock-locked-offline'
        networkAccess = 'disabled'
        publishArgumentsSha256 = Get-TestSha256 "$Edition-publish-args"
    }
    $toolchainSha = Get-InstallerSigningObjectSha256 -Value $toolchain
    $unsignedSha = Get-TestSha256 "$Edition-unsigned-installer"
    $buildStarted = ConvertTo-WholeSecondUtc $Now.AddSeconds(-3)
    $buildCompleted = ConvertTo-WholeSecondUtc $Now.AddSeconds(-2)
    $selfCheckCompleted = ConvertTo-WholeSecondUtc $Now.AddSeconds(-1)
    $created = ConvertTo-WholeSecondUtc $Now
    $request = [pscustomobject][ordered]@{
        schemaVersion = 1
        requestType = 'ensou-dsh-launcher-installer-signing-request'
        orchestrationId = if ($Edition -ceq 'Personal') {
            '11111111-1111-4111-8111-111111111111'
        } else {
            '22222222-2222-4222-8222-222222222222'
        }
        edition = $Edition
        releaseSetId = "$($Edition.ToLowerInvariant())-2026.08.31.1"
        channel = $Channel
        planSha256 = Get-TestSha256 "$Edition-plan"
        sourceCommit = 'a' * 40
        sourceTree = $sourceTree
        sourceBuildInputSetSha256 = $sourceInputSetSha
        sourceBuildInputs = $sourceBuildInputs
        baseHeadSha256 = Get-TestSha256 "$Edition-r5-head"
        baseRevision = 5
        basePhase = $Channel.ToUpperInvariant() + '_SIGNED_CANDIDATE_IMPORTED'
        requestedRevision = 6
        requestNonce = ConvertTo-TestBase64Url `
            -Bytes ([Security.Cryptography.SHA256]::HashData(
                $script:Utf8.GetBytes("$Edition-request-nonce")))
        createdAtUtc = $created
        expiresAtUtc = ConvertTo-WholeSecondUtc $Now.AddMinutes(30)
        r5Evidence = [pscustomobject][ordered]@{
            headRelativePath = 'head.json'
            headSha256 = Get-TestSha256 "$Edition-r5-head"
            receiptRelativePath =
                "receipts/0005-$Channel-signed-candidate-imported.json"
            receiptSha256 = Get-TestSha256 "$Edition-r5-receipt"
            manifestPublishingRequestSha256 = Get-TestSha256 "$Edition-r4-request"
            manifestPublishingResponseSha256 = Get-TestSha256 "$Edition-r5-response"
            manifestRelativePath = $candidateRoot + 'release-set.v2.json'
            manifestSha256 = [string]$candidate[0].sha256
            releaseManifestTrustSha256 = $releaseTrustSha
            releaseCompatibilitySha256 = Get-TestSha256 "$Edition-compatibility"
            productionAdmission = 'NO_GO'
        }
        candidate = [pscustomobject][ordered]@{
            inventorySha256 = $candidateSha
            files = $candidate
        }
        r3Evidence = [pscustomobject][ordered]@{
            receiptRelativePath = 'receipts/0003-client-signatures-imported.json'
            receiptSha256 = Get-TestSha256 "$Edition-r3-receipt"
            signedClientSetSha256 = $signedClientSha
            signedClients = $signedClients
            releaseManifestTrustSha256 = $releaseTrustSha
            releaseManifestTrustProbeSetSha256 = $probeSha
            releaseManifestTrustProbes = $probes
        }
        installerPayload = [pscustomobject][ordered]@{
            inventorySha256 = $payloadSha
            files = $payload
        }
        toolchainLock = $toolchain
        toolchainLockSha256 = $toolchainSha
        buildExecution = [pscustomobject][ordered]@{
            buildId = if ($Edition -ceq 'Personal') {
                '33333333-3333-4333-8333-333333333333'
            } else {
                '44444444-4444-4444-8444-444444444444'
            }
            targetBuildIdentitySha256 = '0' * 64
            reservationSha256 = Get-TestSha256 "$Edition-build-reservation"
            buildOrdinal = 1
            buildCountForTarget = 1
            outputCreationMode = 'create-new'
            rebuildPolicy =
                'rebuild-forbidden-exact-reserved-unsigned-bytes-replay-only'
            startedAtUtc = $buildStarted
            completedAtUtc = $buildCompleted
            exitCode = 0
        }
        unsignedInstaller = [pscustomobject][ordered]@{
            role = 'installer'
            fileName = $installerName
            relativePath = "unsigned/$installerName"
            sizeBytes = 10001
            sha256 = $unsignedSha
            peContentSha256 = Get-TestSha256 "$Edition-installer-pe"
        }
        payloadSelfCheck = [pscustomobject][ordered]@{
            command = '--production-payload-self-check'
            status = 'VERIFIED'
            exitCode = 0
            inspectedInstallerSha256 = $unsignedSha
            resultSha256 = Get-TestSha256 "$Edition-unsigned-self-check"
            candidateSetSha256 = $candidateSha
            payloadSetSha256 = $payloadSha
            r3SignedClientSetSha256 = $signedClientSha
            releaseManifestTrustSha256 = $releaseTrustSha
            releaseManifestTrustProbeSetSha256 = $probeSha
            completedAtUtc = $selfCheckCompleted
        }
        responseAuthentication = [pscustomobject][ordered]@{
            algorithm = 'ES256'
            keyId = [string]$InstallerTrust.keyId
            purpose = 'installer-signing-response'
            payloadType =
                'ensou-dsh-launcher-installer-signing-response-authentication-v1'
            trustSha256 = Get-InstallerSigningObjectSha256 -Value $InstallerTrust
            maximumResponseAgeMinutes = 30
        }
    }
    $request.buildExecution.targetBuildIdentitySha256 =
        Get-InstallerTargetBuildIdentitySha256 -Request $request
    return $request
}

function ConvertTo-TestEnterpriseRequestV2 {
    param([Parameter(Mandatory = $true)][psobject]$Request)

    if ([string]$Request.edition -cne 'Enterprise' -or
        [string]$Request.channel -cne 'stable') {
        throw 'Only one Enterprise Stable request may become request v2.'
    }
    $Request.schemaVersion = 2
    $Request.PSObject.Properties.Remove('payloadSelfCheck')
    $resources = @(
        foreach ($payload in @($Request.installerPayload.files)) {
            [pscustomobject][ordered]@{
                role = [string]$payload.role
                embeddedLogicalName = [string]$payload.embeddedLogicalName
                sizeBytes = [int64]$payload.sizeBytes
                sha256 = [string]$payload.sha256
                status = 'VERIFIED'
            }
        })
    $binding = [pscustomobject][ordered]@{
        verificationType =
            'managed-assembly-resource-to-single-file-build-input-v1'
        verificationMethod =
            'collectible-load-context-manifest-resource-inspection-no-entrypoint'
        status = 'VERIFIED'
        managedAssembly = [pscustomobject][ordered]@{
            fileName = 'Ensou.Dsh.Enterprise.Installer.dll'
            sizeBytes = 4096
            sha256 = Get-TestSha256 'Enterprise-v2-managed-assembly'
        }
        resourceSetSha256 =
            Get-InstallerSigningObjectSha256 -Value $resources
        resources = $resources
        unsignedInstallerSha256 = [string]$Request.unsignedInstaller.sha256
    }
    Add-Member -InputObject $Request -NotePropertyName resourceBinding `
        -NotePropertyValue $binding
    Add-Member -InputObject $Request -NotePropertyName trustedBuildEvidence `
        -NotePropertyValue ([pscustomobject][ordered]@{
            role = 'trusted-build-evidence'
            fileName = 'trusted-build-evidence.v1.json'
            relativePath = 'trusted-build/trusted-build-evidence.v1.json'
            schemaVersion = 1
            evidenceType = 'ensou-dsh-enterprise-installer-trusted-build'
            sizeBytes = 8192
            sha256 = Get-TestSha256 'Enterprise-v2-trusted-build-evidence'
            resourceBindingSha256 =
                Get-InstallerSigningObjectSha256 -Value $binding
            sdkFileClosureStatus = 'VERIFIED'
            productionAdmission = 'NO_GO'
        })
    $Request.buildExecution.targetBuildIdentitySha256 =
        Get-InstallerTargetBuildIdentitySha256 -Request $Request
    $reservation = [pscustomobject][ordered]@{
        schemaVersion = 1
        reservationType =
            'ensou-dsh-enterprise-installer-trusted-build-reservation'
        buildId = [string]$Request.buildExecution.buildId
        targetBuildIdentitySha256 =
            [string]$Request.buildExecution.targetBuildIdentitySha256
        sourceBuildInputSetSha256 =
            [string]$Request.sourceBuildInputSetSha256
        unsignedInstallerSha256 = [string]$Request.unsignedInstaller.sha256
    }
    $Request.buildExecution.reservationSha256 =
        Get-InstallerSigningObjectSha256 -Value $reservation
    return $Request
}

function New-TestPersonalRequestV2 {
    param(
        [Parameter(Mandatory = $true)][psobject]$InstallerTrust,
        [Parameter(Mandatory = $true)][psobject]$ReleaseTrust,
        [Parameter(Mandatory = $true)][DateTimeOffset]$Now
    )

    $payloadFiles = @(
        (New-TestFile `
            -Role 'release-manifest' `
            -FileName 'release-set.v2.json' `
            -RelativePath 'payload/release-set.v2.json' `
            -Seed 'personal-v2-manifest'),
        (New-TestFile `
            -Role 'startup-stub' `
            -FileName 'Ensou.Dsh.Bootstrapper.exe' `
            -RelativePath 'payload/Ensou.Dsh.Bootstrapper.exe' `
            -Seed 'personal-v2-startup'),
        (New-TestFile `
            -Role 'client-bundle' `
            -FileName 'client-bundle.zip' `
            -RelativePath 'payload/client-bundle.zip' `
            -Seed 'personal-v2-client'),
        (New-TestFile `
            -Role 'runtime' `
            -FileName 'runtime.zip' `
            -RelativePath 'payload/runtime.zip' `
            -Seed 'personal-v2-runtime'))
    $logicalNames = @(
        'Ensou.Dsh.Personal.Installer.Payload.release-set.v2.json',
        'Ensou.Dsh.Personal.Installer.Payload.Ensou.Dsh.Bootstrapper.exe',
        'Ensou.Dsh.Personal.Installer.Payload.client-bundle.zip',
        'Ensou.Dsh.Personal.Installer.Payload.runtime.zip')
    $resources = @(
        for ($index = 0; $index -lt $payloadFiles.Count; $index++) {
            [pscustomobject][ordered]@{
                role = [string]$payloadFiles[$index].role
                logicalName = [string]$logicalNames[$index]
                sizeBytes = [int64]$payloadFiles[$index].sizeBytes
                sha256 = [string]$payloadFiles[$index].sha256
                status = 'VERIFIED'
            }
        })
    $packageClosure = [pscustomobject][ordered]@{
        lockRelativePath =
            'repo/installer/personal-publish-runtime-packs.lock.json'
        lockSha256 = Get-TestSha256 'personal-v2-package-lock'
        packageCount = 4
        inventorySha256 = Get-TestSha256 'personal-v2-package-inventory'
    }
    $sdkClosure = [pscustomobject][ordered]@{
        sdkVersion = '10.0.302'
        archiveFileName = 'dotnet-sdk-10.0.302-win-x64.zip'
        archiveSha512 =
            (Get-TestSha256 'personal-v2-sdk-a') +
            (Get-TestSha256 'personal-v2-sdk-b')
        lockRelativePath =
            'repo/release/locks/dotnet-sdk-10.0.302-win-x64.files.lock.json'
        lockSha256 = Get-TestSha256 'personal-v2-sdk-lock'
        inventorySha256 = Get-TestSha256 'personal-v2-sdk-inventory'
        fileCount = 5611
        totalSizeBytes = 798277746
        status = 'VERIFIED'
        privateCopyPolicy =
            'create-only-private-copy-held-open-through-version-restore-publish-v1'
    }
    $releasePublicIdentity = [ordered]@{
        algorithm = [string]$ReleaseTrust.algorithm
        keyId = [string]$ReleaseTrust.keyId
        x = [string]$ReleaseTrust.x
        y = [string]$ReleaseTrust.y
    }
    $created = ConvertTo-WholeSecondUtc $Now
    $unsignedSha = Get-TestSha256 'personal-v2-unsigned-installer'
    return [pscustomobject][ordered]@{
        schemaVersion = 2
        requestType = 'ensou-dsh-personal-installer-signing-request'
        orchestrationId = '12345678-1234-4abc-8def-1234567890ab'
        edition = 'Personal'
        releaseSetId = 'personal-2026.09.03.1'
        channel = 'pilot'
        planSha256 = Get-TestSha256 'personal-v2-plan'
        baseHeadSha256 = Get-TestSha256 'personal-v2-r5-head'
        baseRevision = 5
        basePhase = 'PILOT_SIGNED_CANDIDATE_IMPORTED'
        requestedRevision = 6
        requestNonce = ConvertTo-TestBase64Url `
            ([Security.Cryptography.SHA256]::HashData(
                $script:Utf8.GetBytes('personal-v2-request-nonce')))
        createdAtUtc = $created
        expiresAtUtc = ConvertTo-WholeSecondUtc $Now.AddMinutes(30)
        source = [pscustomobject][ordered]@{
            commit = Get-TestSha256 'personal-v2-source-commit'
            tree = Get-TestSha256 'personal-v2-source-tree'
            status = 'CLEAN_TRACKED_HEAD'
            snapshotContract =
                'git-head-archive-held-file-leases-directory-identity-mutation-monitor-v2'
            rootProject =
                'src/Ensou.Dsh.Personal.Installer/Ensou.Dsh.Personal.Installer.csproj'
            fileCount = 100
            totalSizeBytes = 100000
            inventorySha256 = Get-TestSha256 'personal-v2-source-inventory'
        }
        payload = [pscustomobject][ordered]@{
            status = 'EXACT_FOUR_FILE_BYTE_CLOSURE_VERIFIED'
            authenticationStatus =
                'STRUCTURE_AND_ARTIFACT_HASHES_VERIFIED_SIGNED_MANIFEST_TRUST_NOT_YET_SHARED_R6_ADMITTED'
            inventorySha256 = Get-InstallerSigningObjectSha256 `
                -Value $payloadFiles
            files = $payloadFiles
        }
        compiledTrust = [pscustomobject][ordered]@{
            manifestOrigin = 'https://updates.example.test/'
            artifactOrigin = 'https://artifacts.example.test/'
            channel = 'pilot'
            releaseKeyId = [string]$ReleaseTrust.keyId
            releaseKeyIdentitySha256 = Get-InstallerSigningObjectSha256 `
                -Value $releasePublicIdentity
            startupStubVersion = '1.1.0'
            canonicalLowSFromSequence = 1
            authenticodeSignerSha256Thumbprint =
                Get-TestSha256 'personal-v2-code-signing-certificate'
        }
        toolchain = [pscustomobject][ordered]@{
            packageClosure = $packageClosure
            sdkClosure = $sdkClosure
            toolchainIdentitySha256 = Get-InstallerSigningObjectSha256 `
                -Value ([ordered]@{
                    packageClosure = $packageClosure
                    sdkClosure = $sdkClosure
                })
        }
        buildExecution = [pscustomobject][ordered]@{
            startedAtUtc = ConvertTo-WholeSecondUtc $Now.AddMinutes(-2)
            completedAtUtc = ConvertTo-WholeSecondUtc $Now.AddMinutes(-1)
            exitCode = 0
            runtimeIdentifier = 'win-x64'
            selfContained = $true
            singleFile = $true
            offlineRestore = $true
            inheritedEnvironmentCleared = $true
            unsignedArtifactExecution = 'FORBIDDEN_AND_NOT_PERFORMED'
        }
        unsignedInstaller = [pscustomobject][ordered]@{
            role = 'installer'
            fileName = 'Ensou.Dsh.Personal.Installer.exe'
            relativePath = 'unsigned/Ensou.Dsh.Personal.Installer.exe'
            sizeBytes = 4096
            sha256 = $unsignedSha
            peContentSha256 = Get-TestSha256 'personal-v2-unsigned-pe'
            authenticodeStatus = 'NotSigned'
        }
        resourceBinding = [pscustomobject][ordered]@{
            verificationMethod =
                'pe-metadata-embedded-resource-inspection-no-assembly-load-v1'
            status = 'VERIFIED'
            resourceSetSha256 = Get-InstallerSigningObjectSha256 `
                -Value $resources
            resources = $resources
            unsignedInstallerSha256 = $unsignedSha
        }
        trustedBuildEvidence = [pscustomobject][ordered]@{
            fileName = 'trusted-build-evidence.v1.json'
            relativePath =
                'trusted-build/trusted-build-evidence.v1.json'
            sizeBytes = 8192
            sha256 = Get-TestSha256 'personal-v2-trusted-build-evidence'
            productionAdmission = 'NO_GO'
        }
        responseAuthentication = [pscustomobject][ordered]@{
            algorithm = 'ES256'
            keyId = [string]$InstallerTrust.keyId
            purpose = 'personal-installer-signing-response'
            payloadType =
                'ensou-dsh-personal-installer-signing-response-authentication-v2'
            trustSha256 = Get-InstallerSigningObjectSha256 `
                -Value $InstallerTrust
            maximumResponseAgeMinutes = 30
        }
        admission = [pscustomobject][ordered]@{
            status = 'READY'
            blocker = 'INSTALLER_SIGNING_RESPONSE_REQUIRED'
            productionAdmission = 'NO_GO'
            reason =
                'Trusted build verification is complete; a cryptographically authenticated signed-installer response is required.'
        }
    }
}

function Set-TestResponseSignature {
    param([psobject]$Response, [Security.Cryptography.ECDsa]$Signer)
    $payloadBytes = Get-InstallerSigningResponseAuthenticationPayload `
        -Response $Response
    [byte[]]$signature = $Signer.SignData(
        $payloadBytes,
        [Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)
    $signature = ConvertTo-TestLowS -Signature $signature
    $Response.authentication.value = ConvertTo-TestBase64Url -Bytes $signature
}

function Set-TestPersonalResponseSignature {
    param([psobject]$Response, [Security.Cryptography.ECDsa]$Signer)
    [byte[]]$payloadBytes =
        PersonalInstallerSigningPipeline\Get-PersonalInstallerSigningResponseAuthenticationPayload `
            -Response $Response
    [byte[]]$signature = $Signer.SignData(
        $payloadBytes,
        [Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)
    $signature = ConvertTo-TestLowS -Signature $signature
    $Response.authentication.value = ConvertTo-TestBase64Url -Bytes $signature
}

function New-TestResponse {
    param(
        $RequestInput,
        [string]$R6HeadSha256,
        [string]$R6ReceiptSha256,
        [Security.Cryptography.ECDsa]$Signer,
        [DateTimeOffset]$Now
    )
    $request = $RequestInput.Value
    $signedSha = Get-TestSha256 "$($request.edition)-signed-installer"
    $response = [pscustomobject][ordered]@{
        schemaVersion = 1
        responseType = 'ensou-dsh-launcher-installer-signing-response'
        orchestrationId = [string]$request.orchestrationId
        edition = [string]$request.edition
        releaseSetId = [string]$request.releaseSetId
        channel = [string]$request.channel
        planSha256 = [string]$request.planSha256
        sourceTree = [string]$request.sourceTree
        sourceBuildInputSetSha256 =
            [string]$request.sourceBuildInputSetSha256
        requestRelativePath =
            'requests/installer-signing.v1/installer-signing-request.v1.json'
        requestSha256 = [string]$RequestInput.Sha256
        requestNonce = [string]$request.requestNonce
        baseHeadSha256 = [string]$request.baseHeadSha256
        admissionHeadSha256 = $R6HeadSha256
        admissionRevision = 6
        r6ReceiptRelativePath = 'receipts/0006-installer-signing-requested.json'
        r6ReceiptSha256 = $R6ReceiptSha256
        requestCreatedAtUtc = [string]$request.createdAtUtc
        requestExpiresAtUtc = [string]$request.expiresAtUtc
        completedAtUtc = ConvertTo-WholeSecondUtc $Now.AddSeconds(1)
        candidateSetSha256 = [string]$request.candidate.inventorySha256
        payloadSetSha256 = [string]$request.installerPayload.inventorySha256
        r3SignedClientSetSha256 = [string]$request.r3Evidence.signedClientSetSha256
        releaseManifestTrustSha256 =
            [string]$request.r3Evidence.releaseManifestTrustSha256
        releaseManifestTrustProbeSetSha256 =
            [string]$request.r3Evidence.releaseManifestTrustProbeSetSha256
        toolchainLockSha256 = [string]$request.toolchainLockSha256
        targetBuildIdentitySha256 =
            [string]$request.buildExecution.targetBuildIdentitySha256
        unsignedInstaller = Copy-TestObject $request.unsignedInstaller
        signedInstaller = [pscustomobject][ordered]@{
            role = 'installer'
            fileName = [string]$request.unsignedInstaller.fileName
            relativePath = 'signed/' + [string]$request.unsignedInstaller.fileName
            sizeBytes = [int64]$request.unsignedInstaller.sizeBytes + 4096
            sha256 = $signedSha
            peContentSha256 = [string]$request.unsignedInstaller.peContentSha256
            fullHashChangedFromUnsigned = $true
        }
        authenticode = [pscustomobject][ordered]@{
            status = 'Valid'
            signatureType = 'Authenticode'
            primarySignerCount = 1
            signerCertificateSha256 = Get-TestSha256 'contract-only-code-signing-cert'
            signerDigestAlgorithmOid = '2.16.840.1.101.3.4.2.1'
            spcIndirectDataContentTypeOid = '1.3.6.1.4.1.311.2.1.4'
            spcPeImageDataTypeOid = '1.3.6.1.4.1.311.2.1.15'
            spcDigestAlgorithmOid = '2.16.840.1.101.3.4.2.1'
            spcPeContentSha256 = [string]$request.unsignedInstaller.peContentSha256
            timestampProtocol = 'RFC3161'
            timestampTokenOid = '1.2.840.113549.1.9.16.2.14'
            timestampContentTypeOid = '1.2.840.113549.1.9.16.1.4'
            timestampSignerCertificateSha256 =
                Get-TestSha256 'contract-only-tsa-cert'
            timestampUtc = ConvertTo-WholeSecondUtc $Now
            rfc3161PrimarySignerBound = $true
        }
        payloadSelfCheck = [pscustomobject][ordered]@{
            command = '--production-payload-self-check'
            status = 'VERIFIED'
            exitCode = 0
            inspectedInstallerSha256 = $signedSha
            resultSha256 = Get-TestSha256 "$($request.edition)-signed-self-check"
            candidateSetSha256 = [string]$request.candidate.inventorySha256
            payloadSetSha256 = [string]$request.installerPayload.inventorySha256
            r3SignedClientSetSha256 =
                [string]$request.r3Evidence.signedClientSetSha256
            releaseManifestTrustSha256 =
                [string]$request.r3Evidence.releaseManifestTrustSha256
            releaseManifestTrustProbeSetSha256 =
                [string]$request.r3Evidence.releaseManifestTrustProbeSetSha256
            completedAtUtc = ConvertTo-WholeSecondUtc $Now.AddSeconds(1)
        }
        authentication = [pscustomobject][ordered]@{
            algorithm = 'ES256'
            keyId = [string]$request.responseAuthentication.keyId
            purpose = 'installer-signing-response'
            payloadType =
                'ensou-dsh-launcher-installer-signing-response-authentication-v1'
            value = 'A' * 86
        }
    }
    Set-TestResponseSignature -Response $response -Signer $Signer
    return $response
}

function Assert-SchemaRejects {
    param($Value, [string]$SchemaPath, [string]$Root, [string]$Name)
    $path = Join-Path $Root "$Name.json"
    Write-TestJson -Path $path -Value $Value
    Assert-Fails `
        -Action {
            [void](Read-InstallerSigningContractInput `
                -Path $path `
                -SchemaPath $SchemaPath `
                -Label $Name)
        } `
        -Pattern 'schema' `
        -Message $Name
}

function Assert-SchemaAccepts {
    param($Value, [string]$SchemaPath, [string]$Root, [string]$Name)
    $path = Join-Path $Root "$Name.json"
    Write-TestJson -Path $path -Value $Value
    [void](Read-InstallerSigningContractInput `
        -Path $path `
        -SchemaPath $SchemaPath `
        -Label $Name)
}

$testRoot = Join-Path ([IO.Path]::GetTempPath()) `
    ('ensou-installer-signing-contract-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($testRoot) | Out-Null
$installerTrustFixture = New-TestTrust `
    -KeyId 'installer-signing-contract-test' `
    -Purpose 'installer-signing-response'
$personalInstallerTrustFixture = New-TestTrust `
    -KeyId 'personal-installer-signing-contract-test' `
    -Purpose 'personal-installer-signing-response'
$releaseTrustFixture = New-TestTrust `
    -KeyId 'release-manifest-contract-test' `
    -Purpose 'release-manifest-signing'
try {
    $now = [DateTimeOffset]::UtcNow
    foreach ($case in @(
            [pscustomobject]@{ Edition = 'Personal'; Channel = 'pilot' },
            [pscustomobject]@{ Edition = 'Personal'; Channel = 'stable' },
            [pscustomobject]@{ Edition = 'Enterprise'; Channel = 'stable' })) {
        $caseRoot = Join-Path $testRoot ($case.Edition + '-' + $case.Channel)
        $requestPath = Join-Path $caseRoot 'installer-signing-request.v1.json'
        $request = New-TestRequest `
            -Edition $case.Edition `
            -Channel $case.Channel `
            -InstallerTrust $installerTrustFixture.Trust `
            -ReleaseTrust $releaseTrustFixture.Trust `
            -Now $now
        Write-TestJson -Path $requestPath -Value $request
        $requestInput = Read-InstallerSigningContractInput `
            -Path $requestPath `
            -SchemaPath $requestSchema `
            -Label "$($case.Edition) $($case.Channel) r6 request"
        Assert-True (Assert-InstallerSigningRequestContract `
            -Request $requestInput.Value `
            -InstallerSigningTrust $installerTrustFixture.Trust `
            -ReleaseManifestTrust $releaseTrustFixture.Trust) `
            'Valid r6 request semantic closure'

        $r6HeadSha = Get-TestSha256 "$($case.Edition)-$($case.Channel)-r6-head"
        $r6ReceiptSha = Get-TestSha256 "$($case.Edition)-$($case.Channel)-r6-receipt"
        $response = New-TestResponse `
            -RequestInput $requestInput `
            -R6HeadSha256 $r6HeadSha `
            -R6ReceiptSha256 $r6ReceiptSha `
            -Signer $installerTrustFixture.Signer `
            -Now $now
        $responsePath = Join-Path $caseRoot 'installer-signing-response.v1.json'
        Write-TestJson -Path $responsePath -Value $response
        $responseInput = Read-InstallerSigningContractInput `
            -Path $responsePath `
            -SchemaPath $responseSchema `
            -Label "$($case.Edition) $($case.Channel) r7 response"
        Assert-True (Assert-InstallerSigningResponseContract `
            -RequestInput $requestInput `
            -ResponseInput $responseInput `
            -R6HeadSha256 $r6HeadSha `
            -R6ReceiptSha256 $r6ReceiptSha `
            -InstallerSigningTrust $installerTrustFixture.Trust) `
            'Valid r7 response semantic/authentication closure'

        $plusResponse = Copy-TestObject $response
        $plusResponse.releaseSetId = 'release+2026.08.31'
        Assert-SchemaAccepts `
            $plusResponse $responseSchema $caseRoot 'plus-response-release-set-id'
        $colonResponse = Copy-TestObject $response
        $colonResponse.releaseSetId = 'release:2026.08.31'
        Assert-SchemaRejects `
            $colonResponse $responseSchema $caseRoot 'colon-response-release-set-id'

        if ($IsWindows) {
            [byte[]]$unsignedPeBytes = New-TestUnsignedPeBytes
            $unsignedPePath = Join-Path `
                $caseRoot ([string]$response.signedInstaller.fileName)
            [IO.File]::WriteAllBytes($unsignedPePath, $unsignedPeBytes)
            $unsignedPeResponse = Copy-TestObject $response
            $unsignedPeFullSha =
                ProductionReleaseState\Get-ProductionSha256Bytes `
                    -Bytes $unsignedPeBytes
            $unsignedPeContentSha =
                ProductionReleaseState\Get-PeContentSha256 `
                    -Bytes $unsignedPeBytes
            $unsignedPeDescriptor = Copy-TestObject $request.unsignedInstaller
            $unsignedPeDescriptor.sizeBytes = [int64]$unsignedPeBytes.LongLength
            $unsignedPeDescriptor.sha256 = $unsignedPeFullSha
            $unsignedPeDescriptor.peContentSha256 = $unsignedPeContentSha
            Assert-True (Assert-UnsignedInstallerSigningInput `
                -Path $unsignedPePath `
                -Descriptor $unsignedPeDescriptor) `
                'Exact unsigned PE and NotSigned status are required at r6'
            $unsignedPeResponse.signedInstaller.sizeBytes =
                [int64]$unsignedPeBytes.LongLength
            $unsignedPeResponse.signedInstaller.sha256 = $unsignedPeFullSha
            $unsignedPeResponse.signedInstaller.peContentSha256 =
                $unsignedPeContentSha
            $unsignedPeResponse.unsignedInstaller.peContentSha256 =
                $unsignedPeContentSha
            $unsignedPeResponse.authenticode.spcPeContentSha256 =
                $unsignedPeContentSha
            Assert-Fails `
                -Action { [void](Assert-SignedInstallerAuthenticode `
                        -Path $unsignedPePath `
                        -Response $unsignedPeResponse `
                        -ExpectedSignerCertificateSha256 `
                            (Get-TestSha256 'contract-only-code-signing-cert')) } `
                -Pattern 'Authenticode Status=Valid' `
                -Message 'r7 rejects a PE without Windows-trusted Authenticode status'
        }

        $admission = [pscustomobject][ordered]@{
            schemaVersion = 1
            admissionType = 'ensou-dsh-launcher-installer-signature-admission'
            orchestrationId = [string]$request.orchestrationId
            edition = [string]$request.edition
            releaseSetId = [string]$request.releaseSetId
            channel = [string]$request.channel
            planSha256 = [string]$request.planSha256
            sourceTree = [string]$request.sourceTree
            sourceBuildInputSetSha256 =
                [string]$request.sourceBuildInputSetSha256
            r7Head = [pscustomobject][ordered]@{
                relativePath = 'head.json'
                sha256 = Get-TestSha256 "$($case.Edition)-r7-head"
                revision = 7
                phase = 'INSTALLER_SIGNATURE_IMPORTED'
                receiptSha256 = Get-TestSha256 "$($case.Edition)-r7-receipt"
            }
            r7Receipt = [pscustomobject][ordered]@{
                relativePath = 'receipts/0007-installer-signature-imported.json'
                sha256 = Get-TestSha256 "$($case.Edition)-r7-receipt"
            }
            request = [pscustomobject][ordered]@{
                relativePath =
                    'requests/installer-signing.v1/installer-signing-request.v1.json'
                sha256 = [string]$requestInput.Sha256
                nonce = [string]$request.requestNonce
                baseHeadSha256 = [string]$request.baseHeadSha256
                r6HeadSha256 = $r6HeadSha
                r6ReceiptSha256 = $r6ReceiptSha
                createdAtUtc = [string]$request.createdAtUtc
                expiresAtUtc = [string]$request.expiresAtUtc
            }
            response = [pscustomobject][ordered]@{
                relativePath =
                    'imports/installer-signing.v1/installer-signing-response.v1.json'
                sha256 = [string]$responseInput.Sha256
                completedAtUtc = [string]$response.completedAtUtc
            }
            candidateSetSha256 = [string]$response.candidateSetSha256
            payloadSetSha256 = [string]$response.payloadSetSha256
            r3SignedClientSetSha256 = [string]$response.r3SignedClientSetSha256
            releaseManifestTrustSha256 =
                [string]$response.releaseManifestTrustSha256
            releaseManifestTrustProbeSetSha256 =
                [string]$response.releaseManifestTrustProbeSetSha256
            toolchainLockSha256 = [string]$response.toolchainLockSha256
            targetBuildIdentitySha256 =
                [string]$response.targetBuildIdentitySha256
            unsignedInstaller = [pscustomobject][ordered]@{
                fileName = [string]$request.unsignedInstaller.fileName
                relativePath = 'requests/installer-signing.v1/' +
                    [string]$request.unsignedInstaller.relativePath
                sizeBytes = [int64]$request.unsignedInstaller.sizeBytes
                sha256 = [string]$request.unsignedInstaller.sha256
                peContentSha256 = [string]$request.unsignedInstaller.peContentSha256
            }
            signedInstaller = [pscustomobject][ordered]@{
                fileName = [string]$response.signedInstaller.fileName
                relativePath = 'imports/installer-signing.v1/' +
                    [string]$response.signedInstaller.relativePath
                sizeBytes = [int64]$response.signedInstaller.sizeBytes
                sha256 = [string]$response.signedInstaller.sha256
                peContentSha256 = [string]$response.signedInstaller.peContentSha256
            }
            authenticodeEvidenceSha256 = Get-InstallerSigningObjectSha256 `
                -Value $response.authenticode
            payloadSelfCheckResultSha256 =
                [string]$response.payloadSelfCheck.resultSha256
            verification = [pscustomobject][ordered]@{
                requestSchema = 'VERIFIED'
                responseSchema = 'VERIFIED'
                outerEs256P1363LowS = 'VERIFIED'
                exactRequestNonceAndWindow = 'VERIFIED'
                exactR5R6HeadsAndReceipts = 'VERIFIED'
                exactReplay = 'VERIFIED'
                unsignedFullSha256 = 'VERIFIED'
                signedFullSha256 = 'VERIFIED'
                peContentPreserved = 'VERIFIED'
                authenticodeStatusValid = 'VERIFIED'
                primarySignedCmsSha256 = 'VERIFIED'
                spcIndirectDataPeDigest = 'VERIFIED'
                rfc3161PrimarySignerBinding = 'VERIFIED'
                payloadSelfCheck = 'VERIFIED'
                releaseManifestTrustProbe = 'VERIFIED'
            }
            productionAdmission = 'NO_GO'
            nextRequiredGate = if ($case.Channel -ceq 'pilot') {
                'PILOT_PROMOTION_REQUESTED'
            } else {
                'PILOT_EVIDENCE_BOUND'
            }
        }
        $admissionPath = Join-Path $caseRoot 'installer-signing-admission.v1.json'
        Write-TestJson -Path $admissionPath -Value $admission
        [void](Read-InstallerSigningContractInput `
            -Path $admissionPath `
            -SchemaPath $admissionSchema `
            -Label "$($case.Edition) $($case.Channel) r7 admission")
        $plusAdmission = Copy-TestObject $admission
        $plusAdmission.releaseSetId = 'release+2026.08.31'
        Assert-SchemaAccepts `
            $plusAdmission $admissionSchema $caseRoot `
            'plus-admission-release-set-id'
        $colonAdmission = Copy-TestObject $admission
        $colonAdmission.releaseSetId = 'release:2026.08.31'
        Assert-SchemaRejects `
            $colonAdmission $admissionSchema $caseRoot `
            'colon-admission-release-set-id'
        $unknownAdmission = Copy-TestObject $admission
        $unknownAdmission | Add-Member -NotePropertyName surprise `
            -NotePropertyValue 'not-admissible'
        Assert-SchemaRejects `
            $unknownAdmission $admissionSchema $caseRoot `
            'unknown-admission-field'

        $wrongReceipt = Copy-TestObject $request
        $wrongReceipt.r5Evidence.receiptRelativePath =
            'receipts/0005-PILOT_SIGNED_CANDIDATE_IMPORTED.json'
        Assert-SchemaRejects $wrongReceipt $requestSchema $caseRoot 'wrong-r5-receipt-path'

        $wrongChannelReceipt = Copy-TestObject $request
        $otherChannel = if ($case.Channel -ceq 'pilot') { 'stable' } else { 'pilot' }
        $wrongChannelReceipt.r5Evidence.receiptRelativePath =
            "receipts/0005-$otherChannel-signed-candidate-imported.json"
        Assert-Fails `
            -Action { [void](Assert-InstallerSigningRequestContract `
                    -Request $wrongChannelReceipt) } `
            -Pattern 'exact r5 target-channel head and receipt' `
            -Message 'r5 receipt path belongs to another target channel'

        $unknownRequest = Copy-TestObject $request
        $unknownRequest | Add-Member -NotePropertyName surprise `
            -NotePropertyValue 'not-admissible'
        Assert-SchemaRejects `
            $unknownRequest $requestSchema $caseRoot 'unknown-request-field'

        $missingPackageLock = Copy-TestObject $request
        $missingPackageLock.toolchainLock.packagesLockStatus = 'MISSING'
        Assert-SchemaRejects `
            $missingPackageLock $requestSchema $caseRoot 'missing-packages-lock'

        $missingTransitivePackageLock = Copy-TestObject $request
        $missingTransitivePackageLock.sourceBuildInputs.files = @(
            $missingTransitivePackageLock.sourceBuildInputs.files |
                Where-Object { [string]$_.identityPath -cne
                    'repo/src/Shared/packages.lock.json' })
        Sync-TestSourceBuildInputClosure -Request $missingTransitivePackageLock
        Assert-Fails `
            -Action { [void](Assert-InstallerSigningRequestContract `
                    -Request $missingTransitivePackageLock) } `
            -Pattern 'packages.lock.json for every transitive project' `
            -Message 'Transitive ProjectReference has no package lock'

        $secondBuild = Copy-TestObject $request
        $secondBuild.buildExecution.buildCountForTarget = 2
        Assert-SchemaRejects $secondBuild $requestSchema $caseRoot 'second-build'

        $wrongSigningWindow = Copy-TestObject $request
        $wrongSigningWindow.responseAuthentication.maximumResponseAgeMinutes = 31
        Assert-Fails `
            -Action { [void](Assert-InstallerSigningRequestContract `
                    -Request $wrongSigningWindow) } `
            -Pattern 'lifetime order is invalid' `
            -Message 'Signing window differs from its exact bounded duration'

        $oversizedInstaller = Copy-TestObject $request
        $oversizedInstaller.unsignedInstaller.sizeBytes = 1073741825
        Assert-SchemaRejects `
            $oversizedInstaller $requestSchema $caseRoot 'oversized-installer'

        $plusReleaseSet = Copy-TestObject $request
        $plusReleaseSet.releaseSetId =
            "$($case.Edition.ToLowerInvariant())+2026.08.31.1"
        $plusReleaseSet.buildExecution.targetBuildIdentitySha256 =
            Get-InstallerTargetBuildIdentitySha256 -Request $plusReleaseSet
        $plusReleasePath = Join-Path $caseRoot 'plus-release-set-id.json'
        Write-TestJson $plusReleasePath $plusReleaseSet
        $plusReleaseInput = Read-InstallerSigningContractInput `
            -Path $plusReleasePath `
            -SchemaPath $requestSchema `
            -Label 'plus release-set id'
        Assert-True (Assert-InstallerSigningRequestContract `
            -Request $plusReleaseInput.Value) 'Plus release-set id is canonical'

        $colonReleaseSet = Copy-TestObject $request
        $colonReleaseSet.releaseSetId = 'release:2026.08.31'
        Assert-SchemaRejects `
            $colonReleaseSet $requestSchema $caseRoot 'colon-release-set-id'

        $wrongSourceTree = Copy-TestObject $request
        $wrongSourceTree.sourceTree = Get-TestSha256 'wrong-source-tree'
        Assert-Fails `
            -Action { [void](Assert-InstallerSigningRequestContract `
                    -Request $wrongSourceTree) } `
            -Pattern 'source-tree closure' `
            -Message 'Source tree differs from its exact build input closure'

        $wrongProps = Copy-TestObject $request
        $props = @($wrongProps.sourceBuildInputs.files | Where-Object {
                [string]$_.kind -ceq 'directory-build-props'
            })
        $props[0].sha256 = Get-TestSha256 'mutated-directory-build-props'
        Assert-Fails `
            -Action { [void](Assert-InstallerSigningRequestContract `
                    -Request $wrongProps) } `
            -Pattern 'source-tree closure' `
            -Message 'Directory.Build.props changed after inventory capture'

        $wrongSource = Copy-TestObject $request
        $source = @($wrongSource.sourceBuildInputs.files | Where-Object {
                [string]$_.kind -ceq 'source'
            })
        $source[0].sha256 = Get-TestSha256 'mutated-installer-source'
        Assert-Fails `
            -Action { [void](Assert-InstallerSigningRequestContract `
                    -Request $wrongSource) } `
            -Pattern 'source-tree closure' `
            -Message 'Source file changed after inventory capture'

        $caseCollision = Copy-TestObject $request
        $sharedProject = @($caseCollision.sourceBuildInputs.files |
            Where-Object { [string]$_.identityPath -ceq
                'repo/src/Shared/Support.csproj' })[0]
        $sharedProject.identityPath = 'repo/src/shared/support.cs'
        $sharedProject.snapshotRelativePath =
            'build-inputs/repo/src/shared/support.cs'
        Sync-TestSourceBuildInputClosure -Request $caseCollision
        Assert-Fails `
            -Action { [void](Assert-InstallerSigningRequestContract `
                    -Request $caseCollision) } `
            -Pattern 'unique and strictly identity-path sorted' `
            -Message 'Windows case-insensitive source identity collision'

        $oversized = Copy-TestObject $request
        $oversized.sourceBuildInputs.totalSizeBytes = 1073741825
        Assert-SchemaRejects `
            $oversized $requestSchema $caseRoot 'oversized-source-input-set'

        $lyingTotal = Copy-TestObject $request
        $lyingTotal.sourceBuildInputs.totalSizeBytes++
        Assert-Fails `
            -Action { [void](Assert-InstallerSigningRequestContract `
                    -Request $lyingTotal) } `
            -Pattern 'total size does not equal' `
            -Message 'Source input total size differs from inventory sum'

        $overBudget = Copy-TestObject $request
        $largeInput = @($overBudget.sourceBuildInputs.files | Where-Object {
                [string]$_.kind -ceq 'generated-input'
            })[0]
        $largeInput.sizeBytes = 1073741824
        Sync-TestSourceBuildInputClosure -Request $overBudget
        Assert-Fails `
            -Action { [void](Assert-InstallerSigningRequestContract `
                    -Request $overBudget) } `
            -Pattern '1 GiB total snapshot limit' `
            -Message 'Aggregate source input snapshot exceeds 1 GiB'

        $presentTargets = Copy-TestObject $request
        $targets = @($presentTargets.sourceBuildInputs.files | Where-Object {
                [string]$_.kind -ceq 'directory-build-targets-absent'
            })[0]
        $targets.kind = 'directory-build-targets'
        $targets.PSObject.Properties.Remove('absenceStatus')
        $targets | Add-Member -NotePropertyName snapshotRelativePath `
            -NotePropertyValue 'build-inputs/repo/Directory.Build.targets'
        $targets | Add-Member -NotePropertyName sizeBytes -NotePropertyValue 87
        $targets | Add-Member -NotePropertyName sha256 `
            -NotePropertyValue (Get-TestSha256 "$($case.Edition)-directory-targets")
        Sync-TestSourceBuildInputClosure -Request $presentTargets
        Assert-True (Assert-InstallerSigningRequestContract `
            -Request $presentTargets) `
            'Present Directory.Build.targets is exactly bound'

        $missingTargets = Copy-TestObject $request
        $missingTargets.sourceBuildInputs.files = @(
            $missingTargets.sourceBuildInputs.files | Where-Object {
                [string]$_.kind -notin @(
                    'directory-build-targets',
                    'directory-build-targets-absent')
            })
        Sync-TestSourceBuildInputClosure -Request $missingTargets
        Assert-Fails `
            -Action { [void](Assert-InstallerSigningRequestContract `
                    -Request $missingTargets) } `
            -Pattern 'Directory.Build.targets' `
            -Message 'Directory.Build.targets silently omitted'

        $wrongCandidateRole = Copy-TestObject $request
        $wrongCandidateRole.candidate.files[0].role = 'runtime'
        Assert-Fails `
            -Action { [void](Assert-InstallerSigningRequestContract `
                    -Request $wrongCandidateRole) } `
            -Pattern 'noncanonical role' `
            -Message 'Wrong candidate role order'

        $wrongPayloadSource = Copy-TestObject $request
        $wrongPayloadSource.installerPayload.files[-1].sourceSha256 =
            Get-TestSha256 'wrong-payload-source'
        Assert-Fails `
            -Action { [void](Assert-InstallerSigningRequestContract `
                    -Request $wrongPayloadSource) } `
            -Pattern 'canonical set SHA-256' `
            -Message 'Payload mutation invalidates exact set hash'

        $wrongNonce = Copy-TestObject $response
        $wrongNonce.requestNonce = ConvertTo-TestBase64Url `
            -Bytes ([Security.Cryptography.SHA256]::HashData(
                $script:Utf8.GetBytes('wrong-nonce')))
        Assert-Fails `
            -Action { [void](Assert-InstallerSigningResponseContract `
                    -RequestInput $requestInput `
                    -ResponseInput ([pscustomobject]@{
                        Value = $wrongNonce
                        Sha256 = Get-InstallerSigningObjectSha256 $wrongNonce
                    }) `
                    -R6HeadSha256 $r6HeadSha `
                    -R6ReceiptSha256 $r6ReceiptSha `
                    -InstallerSigningTrust $installerTrustFixture.Trust) } `
            -Pattern 'exact request, nonce' `
            -Message 'Wrong request nonce'

        $wrongCas = Copy-TestObject $response
        $wrongCas.admissionHeadSha256 = Get-TestSha256 'wrong-r6-head'
        Assert-Fails `
            -Action { [void](Assert-InstallerSigningResponseContract `
                    -RequestInput $requestInput `
                    -ResponseInput ([pscustomobject]@{ Value = $wrongCas }) `
                    -R6HeadSha256 $r6HeadSha `
                    -R6ReceiptSha256 $r6ReceiptSha `
                    -InstallerSigningTrust $installerTrustFixture.Trust) } `
            -Pattern 'r6 CAS' `
            -Message 'Wrong r6 CAS head'

        $wrongResponseTree = Copy-TestObject $response
        $wrongResponseTree.sourceTree = Get-TestSha256 'wrong-response-tree'
        Assert-Fails `
            -Action { [void](Assert-InstallerSigningResponseContract `
                    -RequestInput $requestInput `
                    -ResponseInput ([pscustomobject]@{
                        Value = $wrongResponseTree
                    }) `
                    -R6HeadSha256 $r6HeadSha `
                    -R6ReceiptSha256 $r6ReceiptSha `
                    -InstallerSigningTrust $installerTrustFixture.Trust) } `
            -Pattern 'exact request, nonce' `
            -Message 'r7 response source tree differs from r6'

        $wrongResponseSourceSet = Copy-TestObject $response
        $wrongResponseSourceSet.sourceBuildInputSetSha256 =
            Get-TestSha256 'wrong-response-source-set'
        Assert-Fails `
            -Action { [void](Assert-InstallerSigningResponseContract `
                    -RequestInput $requestInput `
                    -ResponseInput ([pscustomobject]@{
                        Value = $wrongResponseSourceSet
                    }) `
                    -R6HeadSha256 $r6HeadSha `
                    -R6ReceiptSha256 $r6ReceiptSha `
                    -InstallerSigningTrust $installerTrustFixture.Trust) } `
            -Pattern 'exact request, nonce' `
            -Message 'r7 response source input set differs from r6'

        $wrongPe = Copy-TestObject $response
        $wrongPe.signedInstaller.peContentSha256 = Get-TestSha256 'wrong-signed-pe'
        Assert-Fails `
            -Action { [void](Assert-InstallerSigningResponseContract `
                    -RequestInput $requestInput `
                    -ResponseInput ([pscustomobject]@{ Value = $wrongPe }) `
                    -R6HeadSha256 $r6HeadSha `
                    -R6ReceiptSha256 $r6ReceiptSha `
                    -InstallerSigningTrust $installerTrustFixture.Trust) } `
            -Pattern 'preserve the exact r6 PE content' `
            -Message 'Signed PE content changed'

        $sameFullHash = Copy-TestObject $response
        $sameFullHash.signedInstaller.sha256 =
            [string]$request.unsignedInstaller.sha256
        Assert-Fails `
            -Action { [void](Assert-InstallerSigningResponseContract `
                    -RequestInput $requestInput `
                    -ResponseInput ([pscustomobject]@{ Value = $sameFullHash }) `
                    -R6HeadSha256 $r6HeadSha `
                    -R6ReceiptSha256 $r6ReceiptSha `
                    -InstallerSigningTrust $installerTrustFixture.Trust) } `
            -Pattern 'preserve the exact r6 PE content' `
            -Message 'Signed full hash did not change'

        $nonGrowingSignature = Copy-TestObject $response
        $nonGrowingSignature.signedInstaller.sizeBytes =
            [int64]$request.unsignedInstaller.sizeBytes
        Assert-Fails `
            -Action { [void](Assert-InstallerSigningResponseContract `
                    -RequestInput $requestInput `
                    -ResponseInput ([pscustomobject]@{
                        Value = $nonGrowingSignature
                    }) `
                    -R6HeadSha256 $r6HeadSha `
                    -R6ReceiptSha256 $r6ReceiptSha `
                    -InstallerSigningTrust $installerTrustFixture.Trust) } `
            -Pattern 'preserve the exact r6 PE content' `
            -Message 'Signed Installer did not add certificate-table bytes'

        $highS = Copy-TestObject $response
        [byte[]]$lowBytes = [Convert]::FromBase64String(
            ([string]$highS.authentication.value).Replace('-', '+').
                Replace('_', '/') + '==')
        $highS.authentication.value = ConvertTo-TestBase64Url `
            -Bytes (ConvertTo-TestHighS -LowSignature $lowBytes)
        Assert-Fails `
            -Action { [void](Assert-InstallerSigningResponseAuthentication `
                    -Response $highS `
                    -Request $request `
                    -InstallerSigningTrust $installerTrustFixture.Trust) } `
            -Pattern 'low-S' `
            -Message 'High-S outer response signature'

        $unknown = Copy-TestObject $response
        $unknown | Add-Member -NotePropertyName surprise `
            -NotePropertyValue 'not-admissible'
        Assert-SchemaRejects $unknown $responseSchema $caseRoot 'unknown-response-field'

        $badWindow = Copy-TestObject $response
        $badWindow.completedAtUtc = ConvertTo-WholeSecondUtc $now.AddHours(1)
        Assert-Fails `
            -Action { [void](Assert-InstallerSigningResponseContract `
                    -RequestInput $requestInput `
                    -ResponseInput ([pscustomobject]@{ Value = $badWindow }) `
                    -R6HeadSha256 $r6HeadSha `
                    -R6ReceiptSha256 $r6ReceiptSha `
                    -InstallerSigningTrust $installerTrustFixture.Trust) } `
            -Pattern 'outside its exact request window' `
            -Message 'Response outside request lifetime'

        $oldTimestamp = Copy-TestObject $response
        $oldTimestamp.authenticode.timestampUtc =
            ConvertTo-WholeSecondUtc $now.AddMinutes(-1)
        Assert-Fails `
            -Action { [void](Assert-InstallerSigningResponseContract `
                    -RequestInput $requestInput `
                    -ResponseInput ([pscustomobject]@{ Value = $oldTimestamp }) `
                    -R6HeadSha256 $r6HeadSha `
                    -R6ReceiptSha256 $r6ReceiptSha `
                    -InstallerSigningTrust $installerTrustFixture.Trust) } `
            -Pattern 'RFC3161 timestamp' `
            -Message 'RFC3161 timestamp predates exact r6 request window'

        $lateTimestamp = Copy-TestObject $response
        $lateTimestamp.authenticode.timestampUtc =
            ConvertTo-WholeSecondUtc $now.AddSeconds(2)
        Assert-Fails `
            -Action { [void](Assert-InstallerSigningResponseContract `
                    -RequestInput $requestInput `
                    -ResponseInput ([pscustomobject]@{ Value = $lateTimestamp }) `
                    -R6HeadSha256 $r6HeadSha `
                    -R6ReceiptSha256 $r6ReceiptSha `
                    -InstallerSigningTrust $installerTrustFixture.Trust) } `
            -Pattern 'RFC3161 timestamp' `
            -Message 'RFC3161 timestamp follows exact response completion'

        $replayRoot = Join-Path $caseRoot 'replay'
        $expectedResponsePath = Join-Path $replayRoot 'expected-response.json'
        $replayResponsePath = Join-Path $replayRoot 'replay-response.json'
        [byte[]]$replayBytes = $script:Utf8.GetBytes(
            "$($case.Edition)-signed-bytes")
        $replayContract = Copy-TestObject $response
        $replayContract.signedInstaller.sizeBytes =
            [int64]$replayBytes.LongLength
        $replayContract.signedInstaller.sha256 =
            ProductionReleaseState\Get-ProductionSha256Bytes -Bytes $replayBytes
        $replayContract.payloadSelfCheck.inspectedInstallerSha256 =
            [string]$replayContract.signedInstaller.sha256
        Set-TestResponseSignature `
            -Response $replayContract `
            -Signer $installerTrustFixture.Signer
        Write-TestJson $expectedResponsePath $replayContract
        Write-TestJson $replayResponsePath $replayContract
        $expectedResponseInput = Read-InstallerSigningContractInput `
            -Path $expectedResponsePath -SchemaPath $responseSchema -Label 'expected replay'
        $replayResponseInput = Read-InstallerSigningContractInput `
            -Path $replayResponsePath -SchemaPath $responseSchema -Label 'exact replay'
        $expectedInstallerPath = Join-Path `
            (Join-Path $replayRoot 'expected') `
            ([string]$response.signedInstaller.fileName)
        $replayInstallerPath = Join-Path `
            (Join-Path $replayRoot 'replay') `
            ([string]$response.signedInstaller.fileName)
        [IO.Directory]::CreateDirectory(
            [IO.Path]::GetDirectoryName($expectedInstallerPath)) | Out-Null
        [IO.Directory]::CreateDirectory(
            [IO.Path]::GetDirectoryName($replayInstallerPath)) | Out-Null
        [IO.File]::WriteAllBytes($expectedInstallerPath, $replayBytes)
        [IO.File]::WriteAllBytes($replayInstallerPath, $replayBytes)
        Assert-True (Assert-InstallerSigningExactReplay `
            -ExpectedResponseInput $expectedResponseInput `
            -ReplayResponseInput $replayResponseInput `
            -ExpectedSignedInstallerPath $expectedInstallerPath `
            -ReplaySignedInstallerPath $replayInstallerPath) 'Exact response replay'
        [IO.File]::WriteAllBytes(
            $replayInstallerPath,
            $script:Utf8.GetBytes("$($case.Edition)-changed-signed-bytes"))
        Assert-Fails `
            -Action { [void](Assert-InstallerSigningExactReplay `
                    -ExpectedResponseInput $expectedResponseInput `
                    -ReplayResponseInput $replayResponseInput `
                    -ExpectedSignedInstallerPath $expectedInstallerPath `
                    -ReplaySignedInstallerPath $replayInstallerPath) } `
            -Pattern 'changed exact signed Installer bytes' `
            -Message 'Changed signed Installer replay'
    }

    $enterpriseV2 = ConvertTo-TestEnterpriseRequestV2 `
        -Request (New-TestRequest `
            -Edition Enterprise `
            -Channel stable `
            -InstallerTrust $installerTrustFixture.Trust `
            -ReleaseTrust $releaseTrustFixture.Trust `
            -Now $now)
    $enterpriseV2Path = Join-Path $testRoot 'enterprise-request-v2.json'
    Write-TestJson -Path $enterpriseV2Path -Value $enterpriseV2
    $enterpriseV2Input = Read-InstallerSigningContractInput `
        -Path $enterpriseV2Path `
        -SchemaPath $requestSchemaV2 `
        -Label 'Enterprise Stable request v2 portable SDK closure'
    Assert-True (Assert-InstallerSigningRequestContract `
        -Request $enterpriseV2Input.Value `
        -InstallerSigningTrust $installerTrustFixture.Trust `
        -ReleaseManifestTrust $releaseTrustFixture.Trust) `
        'Enterprise request v2 accepts only verified portable SDK closure evidence'

    $personalV2 = New-TestPersonalRequestV2 `
        -InstallerTrust $personalInstallerTrustFixture.Trust `
        -ReleaseTrust $releaseTrustFixture.Trust `
        -Now $now
    $personalV2Path = Join-Path $testRoot 'personal-pilot-request-v2.json'
    Write-TestJson -Path $personalV2Path -Value $personalV2
    $personalV2Input = Read-InstallerSigningContractInput `
        -Path $personalV2Path `
        -SchemaPath $requestSchemaV2 `
        -Label 'Personal Pilot request v2'
    Assert-True (Assert-InstallerSigningRequestContract `
        -Request $personalV2Input.Value `
        -InstallerSigningTrust $personalInstallerTrustFixture.Trust `
        -ReleaseManifestTrust $releaseTrustFixture.Trust) `
        'Personal Pilot request v2 closes payload, resource, toolchain, and trust evidence'

    $personalR6HeadSha = Get-TestSha256 'personal-v2-r6-head'
    $personalR6ReceiptSha = Get-TestSha256 'personal-v2-r6-receipt'
    $personalSignedSha = Get-TestSha256 'personal-v2-signed-installer'
    $personalResponseCompleted = [string]$personalV2.createdAtUtc
    $personalPayloadFiles = @($personalV2.payload.files)
    $personalResponseV2 = [pscustomobject][ordered]@{
        schemaVersion = 2
        responseType = 'ensou-dsh-personal-installer-signing-response'
        orchestrationId = [string]$personalV2.orchestrationId
        edition = 'Personal'
        releaseSetId = [string]$personalV2.releaseSetId
        channel = 'pilot'
        planSha256 = [string]$personalV2.planSha256
        requestRelativePath =
            'requests/installer-signing.v2/installer-signing-request.v2.json'
        requestSha256 = [string]$personalV2Input.Sha256
        requestNonce = [string]$personalV2.requestNonce
        baseHeadSha256 = [string]$personalV2.baseHeadSha256
        admissionHeadSha256 = $personalR6HeadSha
        admissionRevision = 6
        r6ReceiptRelativePath =
            'receipts/0006-installer-signing-requested.json'
        r6ReceiptSha256 = $personalR6ReceiptSha
        requestCreatedAtUtc = [string]$personalV2.createdAtUtc
        requestExpiresAtUtc = [string]$personalV2.expiresAtUtc
        completedAtUtc = $personalResponseCompleted
        requestBindings = [pscustomobject][ordered]@{
            sourceSha256 = Get-InstallerSigningObjectSha256 `
                -Value $personalV2.source
            payloadSha256 = Get-InstallerSigningObjectSha256 `
                -Value $personalV2.payload
            compiledTrustSha256 = Get-InstallerSigningObjectSha256 `
                -Value $personalV2.compiledTrust
            toolchainSha256 = Get-InstallerSigningObjectSha256 `
                -Value $personalV2.toolchain
            buildExecutionSha256 = Get-InstallerSigningObjectSha256 `
                -Value $personalV2.buildExecution
            resourceBindingSha256 = Get-InstallerSigningObjectSha256 `
                -Value $personalV2.resourceBinding
            trustedBuildEvidenceSha256 = Get-InstallerSigningObjectSha256 `
                -Value $personalV2.trustedBuildEvidence
            admissionSha256 = Get-InstallerSigningObjectSha256 `
                -Value $personalV2.admission
        }
        unsignedInstaller = $personalV2.unsignedInstaller
        signedInstaller = [pscustomobject][ordered]@{
            role = 'installer'
            fileName = 'Ensou.Dsh.Personal.Installer.exe'
            relativePath = 'signed/Ensou.Dsh.Personal.Installer.exe'
            sizeBytes = [int64]$personalV2.unsignedInstaller.sizeBytes + 2048
            sha256 = $personalSignedSha
            peContentSha256 = [string]$personalV2.unsignedInstaller.peContentSha256
            fullHashChangedFromUnsigned = $true
        }
        authenticode = [pscustomobject][ordered]@{
            status = 'Valid'
            signatureType = 'Authenticode'
            primarySignerCount = 1
            signerCertificateSha256 =
                [string]$personalV2.compiledTrust.authenticodeSignerSha256Thumbprint
            signerDigestAlgorithmOid = '2.16.840.1.101.3.4.2.1'
            spcIndirectDataContentTypeOid = '1.3.6.1.4.1.311.2.1.4'
            spcPeImageDataTypeOid = '1.3.6.1.4.1.311.2.1.15'
            spcDigestAlgorithmOid = '2.16.840.1.101.3.4.2.1'
            spcPeContentSha256 =
                [string]$personalV2.unsignedInstaller.peContentSha256
            timestampProtocol = 'RFC3161'
            timestampTokenOid = '1.2.840.113549.1.9.16.2.14'
            timestampContentTypeOid = '1.2.840.113549.1.9.16.1.4'
            timestampSignerCertificateSha256 =
                Get-TestSha256 'personal-v2-timestamp-certificate'
            timestampUtc = $personalResponseCompleted
            rfc3161PrimarySignerBound = $true
        }
        payloadSelfCheck = [pscustomobject][ordered]@{
            schemaVersion = 1
            evidenceType =
                'ensou-dsh-personal-installer-production-payload-self-check-consumption'
            command = '--production-payload-self-check'
            status = 'VERIFIED'
            exitCode = 0
            inspectedInstallerSha256 = $personalSignedSha
            releaseSetId = [string]$personalV2.releaseSetId
            manifestSha256 = [string]$personalPayloadFiles[0].sha256
            manifestSizeBytes = [int64]$personalPayloadFiles[0].sizeBytes
            startupStubSha256 = [string]$personalPayloadFiles[1].sha256
            startupStubSizeBytes = [int64]$personalPayloadFiles[1].sizeBytes
            clientBundleSha256 = [string]$personalPayloadFiles[2].sha256
            clientBundleSizeBytes = [int64]$personalPayloadFiles[2].sizeBytes
            runtimeSha256 = [string]$personalPayloadFiles[3].sha256
            runtimeSizeBytes = [int64]$personalPayloadFiles[3].sizeBytes
            canonicalJsonSizeBytes = 1000
            canonicalJsonSha256 = Get-TestSha256 'personal-v2-self-check-json'
            canonicalLineSizeBytes = 1002
            canonicalLineSha256 = Get-TestSha256 'personal-v2-self-check-line'
            completedAtUtc = $personalResponseCompleted
        }
        authentication = [pscustomobject][ordered]@{
            algorithm = 'ES256'
            keyId = [string]$personalInstallerTrustFixture.Trust.keyId
            purpose = 'personal-installer-signing-response'
            payloadType =
                'ensou-dsh-personal-installer-signing-response-authentication-v2'
            value = 'A' * 86
        }
    }
    Set-TestPersonalResponseSignature `
        -Response $personalResponseV2 `
        -Signer $personalInstallerTrustFixture.Signer
    $personalResponseV2Path = Join-Path `
        $testRoot 'personal-installer-signing-response.v2.json'
    Write-TestJson -Path $personalResponseV2Path -Value $personalResponseV2
    $personalResponseV2Input = Read-InstallerSigningContractInput `
        -Path $personalResponseV2Path `
        -SchemaPath $personalResponseSchemaV2 `
        -Label 'Personal signing response v2 real-shape fixture'
    Assert-True `
        (PersonalInstallerSigningPipeline\Assert-PersonalInstallerSigningResponseV2Contract `
            -RequestInput $personalV2Input `
            -ResponseInput $personalResponseV2Input `
            -R6HeadSha256 $personalR6HeadSha `
            -R6ReceiptSha256 $personalR6ReceiptSha `
            -InstallerSigningTrust $personalInstallerTrustFixture.Trust) `
        'Dedicated Personal response-v2 real-shape fixture is accepted.'

    $personalGenericConfusion = Copy-TestObject $personalResponseV2
    $personalGenericConfusion.responseType =
        'ensou-dsh-launcher-installer-signing-response'
    $personalGenericConfusion.authentication.purpose =
        'installer-signing-response'
    $personalGenericConfusion.authentication.payloadType =
        'ensou-dsh-launcher-installer-signing-response-authentication-v1'
    Assert-SchemaRejects `
        $personalGenericConfusion `
        $personalResponseSchemaV2 `
        $testRoot `
        'personal-response-v2-generic-type-confusion'

    $personalSourceTamper = Copy-TestObject $personalResponseV2
    $personalSourceTamper.requestBindings.sourceSha256 =
        Get-TestSha256 'personal-v2-source-substitution'
    Set-TestPersonalResponseSignature `
        -Response $personalSourceTamper `
        -Signer $personalInstallerTrustFixture.Signer
    Assert-Fails `
        -Action { [void](PersonalInstallerSigningPipeline\Assert-PersonalInstallerSigningResponseV2Contract `
                -RequestInput $personalV2Input `
                -ResponseInput ([pscustomobject]@{
                    Value = $personalSourceTamper
                    Sha256 = Get-TestSha256 'source-tampered-response'
                }) `
                -R6HeadSha256 $personalR6HeadSha `
                -R6ReceiptSha256 $personalR6ReceiptSha `
                -InstallerSigningTrust $personalInstallerTrustFixture.Trust) } `
        -Pattern 'RESPONSE_CLOSURE_INVALID' `
        -Message 'Personal source-binding substitution is rejected even when re-signed.'

    $personalSelfCheckTamper = Copy-TestObject $personalResponseV2
    $personalSelfCheckTamper.payloadSelfCheck.runtimeSha256 =
        Get-TestSha256 'personal-v2-runtime-substitution'
    Set-TestPersonalResponseSignature `
        -Response $personalSelfCheckTamper `
        -Signer $personalInstallerTrustFixture.Signer
    Assert-Fails `
        -Action { [void](PersonalInstallerSigningPipeline\Assert-PersonalInstallerSigningResponseV2Contract `
                -RequestInput $personalV2Input `
                -ResponseInput ([pscustomobject]@{
                    Value = $personalSelfCheckTamper
                    Sha256 = Get-TestSha256 'self-check-tampered-response'
                }) `
                -R6HeadSha256 $personalR6HeadSha `
                -R6ReceiptSha256 $personalR6ReceiptSha `
                -InstallerSigningTrust $personalInstallerTrustFixture.Trust) } `
        -Pattern 'RESPONSE_CLOSURE_INVALID' `
        -Message 'Personal payload self-check substitution is rejected even when re-signed.'

    $personalStaleResponse = Copy-TestObject $personalResponseV2
    $personalStaleResponse.completedAtUtc =
        ConvertTo-WholeSecondUtc $Now.AddMinutes(31)
    $personalStaleResponse.payloadSelfCheck.completedAtUtc =
        [string]$personalStaleResponse.completedAtUtc
    Set-TestPersonalResponseSignature `
        -Response $personalStaleResponse `
        -Signer $personalInstallerTrustFixture.Signer
    Assert-Fails `
        -Action { [void](PersonalInstallerSigningPipeline\Assert-PersonalInstallerSigningResponseV2Contract `
                -RequestInput $personalV2Input `
                -ResponseInput ([pscustomobject]@{
                    Value = $personalStaleResponse
                    Sha256 = Get-TestSha256 'stale-personal-response'
                }) `
                -R6HeadSha256 $personalR6HeadSha `
                -R6ReceiptSha256 $personalR6ReceiptSha `
                -InstallerSigningTrust $personalInstallerTrustFixture.Trust) } `
        -Pattern 'RESPONSE_LIFETIME_INVALID' `
        -Message 'Stale Personal response-v2 is rejected even when re-signed.'

    $personalStableV2 = Copy-TestObject $personalV2
    $personalStableV2.channel = 'stable'
    $personalStableV2.basePhase = 'STABLE_SIGNED_CANDIDATE_IMPORTED'
    $personalStableV2.compiledTrust.channel = 'stable'
    Assert-SchemaRejects `
        $personalStableV2 `
        $requestSchemaV2 `
        $testRoot `
        'personal-v2-stable-not-admitted'
    Assert-Fails `
        -Action { [void](Assert-InstallerSigningRequestContract `
                -Request $personalStableV2) } `
        -Pattern 'edition/channel identity is invalid' `
        -Message 'Personal v2 Stable is not implicitly admitted with Pilot'

    $personalEnterpriseField = Copy-TestObject $personalV2
    Add-Member -InputObject $personalEnterpriseField `
        -NotePropertyName sourceCommit `
        -NotePropertyValue (Get-TestSha256 'cross-edition-source-commit')
    Assert-SchemaRejects `
        $personalEnterpriseField `
        $requestSchemaV2 `
        $testRoot `
        'personal-v2-enterprise-field-smuggling'

    $wrongPersonalPayload = Copy-TestObject $personalV2
    $wrongPersonalPayload.payload.files[2].sha256 =
        Get-TestSha256 'personal-v2-client-substitution'
    Assert-Fails `
        -Action { [void](Assert-InstallerSigningRequestContract `
                -Request $wrongPersonalPayload) } `
        -Pattern 'four-file trusted-build closure' `
        -Message 'Personal v2 payload substitution invalidates its set hash'

    $wrongPersonalResource = Copy-TestObject $personalV2
    $wrongPersonalResource.resourceBinding.resources[2].sha256 =
        Get-TestSha256 'personal-v2-resource-substitution'
    $wrongPersonalResource.resourceBinding.resourceSetSha256 =
        Get-InstallerSigningObjectSha256 `
            -Value @($wrongPersonalResource.resourceBinding.resources)
    Assert-Fails `
        -Action { [void](Assert-InstallerSigningRequestContract `
                -Request $wrongPersonalResource) } `
        -Pattern "resource 'client-bundle' differs" `
        -Message 'Personal v2 resource substitution cannot be hidden by rehashing the resource set'

    $wrongPersonalToolchain = Copy-TestObject $personalV2
    $wrongPersonalToolchain.toolchain.sdkClosure.inventorySha256 =
        Get-TestSha256 'personal-v2-sdk-substitution'
    Assert-Fails `
        -Action { [void](Assert-InstallerSigningRequestContract `
                -Request $wrongPersonalToolchain) } `
        -Pattern 'exact offline package and portable SDK closure' `
        -Message 'Personal v2 SDK substitution invalidates the toolchain identity'

    $wrongPersonalReleaseTrust = Copy-TestObject $personalV2
    $wrongPersonalReleaseTrust.compiledTrust.releaseKeyIdentitySha256 =
        Get-TestSha256 'personal-v2-wrong-release-trust'
    Assert-Fails `
        -Action { [void](Assert-InstallerSigningRequestContract `
                -Request $wrongPersonalReleaseTrust `
                -InstallerSigningTrust $personalInstallerTrustFixture.Trust `
                -ReleaseManifestTrust $releaseTrustFixture.Trust) } `
        -Pattern 'exact release-manifest plan trust' `
        -Message 'Personal v2 compiled trust cannot substitute the plan release key'

    $legacyExternalSdkV2 = Copy-TestObject $enterpriseV2
    $legacyExternalSdkV2.trustedBuildEvidence.sdkFileClosureStatus =
        'EXTERNAL_HOST_PREREQUISITE_NOT_SNAPSHOTTED'
    Assert-SchemaRejects `
        $legacyExternalSdkV2 `
        $requestSchemaV2 `
        $testRoot `
        'enterprise-v2-legacy-external-sdk-prerequisite'
    Assert-Fails `
        -Action { [void](Assert-InstallerSigningRequestContract `
                -Request $legacyExternalSdkV2 `
                -InstallerSigningTrust $installerTrustFixture.Trust `
                -ReleaseManifestTrust $releaseTrustFixture.Trust) } `
        -Pattern 'verified portable SDK closure' `
        -Message 'Enterprise request v2 rejects legacy external SDK pseudo-evidence'

    $enterprisePilot = New-TestRequest `
        -Edition Enterprise `
        -Channel pilot `
        -InstallerTrust $installerTrustFixture.Trust `
        -ReleaseTrust $releaseTrustFixture.Trust `
        -Now $now
    Assert-SchemaRejects `
        $enterprisePilot `
        $requestSchema `
        $testRoot `
        'enterprise-cross-channel-pilot'

    $reusedPointInstallerTrust = Copy-TestObject $releaseTrustFixture.Trust
    $reusedPointInstallerTrust.keyId = 'installer-reusing-release-point'
    $reusedPointInstallerTrust.purpose = 'installer-signing-response'
    $sameTrustRequest = New-TestRequest `
        -Edition Personal `
        -Channel stable `
        -InstallerTrust $reusedPointInstallerTrust `
        -ReleaseTrust $releaseTrustFixture.Trust `
        -Now $now
    Assert-Fails `
        -Action { [void](Assert-InstallerSigningRequestContract `
                -Request $sameTrustRequest `
                -InstallerSigningTrust $reusedPointInstallerTrust `
                -ReleaseManifestTrust $releaseTrustFixture.Trust) } `
        -Pattern 'independent from release-manifest' `
        -Message 'Installer and release-manifest trust reuse'

    $fixtureStatus = Get-Content -Raw -LiteralPath $fixtureStatusPath |
        ConvertFrom-Json -Depth 16
    Assert-Equal $fixtureStatus.authenticodeCertificate 'PENDING' `
        'Real Authenticode certificate fixture'
    Assert-Equal $fixtureStatus.rfc3161TimestampAuthority 'PENDING' `
        'Real RFC3161 TSA fixture'
    Assert-Equal $fixtureStatus.realSignedPersonalInstaller 'PENDING' `
        'Real Personal Installer fixture'
    Assert-Equal $fixtureStatus.realSignedEnterpriseInstaller 'PENDING' `
        'Real Enterprise Installer fixture'
    Assert-Equal $fixtureStatus.realUnsignedPayloadSelfChecks 'PENDING' `
        'Real unsigned Installer payload self-check fixtures'
    Assert-Equal $fixtureStatus.realSignedPayloadSelfChecks 'PENDING' `
        'Real signed Installer payload self-check fixtures'
    Assert-Equal $fixtureStatus.realReleaseManifestTrustProbes 'PENDING' `
        'Real release-manifest trust probe fixtures'
    Assert-Equal $fixtureStatus.exactSingleRfc3161AttributeValue 'PENDING' `
        'Real exact single-value RFC3161 fixture'
    Assert-Equal $fixtureStatus.legacyCounterSignatureAbsence 'PENDING' `
        'Real legacy counterSignature absence fixture'
    Assert-Equal $fixtureStatus.rfc3161RequestWindowBinding 'PENDING' `
        'Real RFC3161 request-window fixture'
    Assert-Equal $fixtureStatus.packagesLockFiles 'AVAILABLE' `
        'Current packages.lock.json bytes'
    Assert-Equal $fixtureStatus.productionLockedOfflineRestoreReplay 'PENDING' `
        'Production locked-offline restore replay fixture'
    Assert-Equal $fixtureStatus.realSourceBuildInputInventory 'PENDING' `
        'Real source-build input inventory fixture'
    Assert-Equal $fixtureStatus.productionAdmission 'NO_GO' `
        'Contract-only fixtures never claim production admission'

    foreach ($schemaPath in @(
            $requestSchema, $requestSchemaV2, $enterpriseRequestSchemaV2,
            $responseSchema, $personalResponseSchemaV2, $admissionSchema)) {
        Get-Content -Raw -LiteralPath $schemaPath | ConvertFrom-Json -Depth 128 |
            Out-Null
    }
    'INSTALLER-SIGNING-CONTRACTS-PASS'
    'REAL-AUTHENTICODE-RFC3161-INSTALLER-FIXTURES-PENDING'
}
finally {
    $installerTrustFixture.Signer.Dispose()
    $personalInstallerTrustFixture.Signer.Dispose()
    $releaseTrustFixture.Signer.Dispose()
    if (Test-Path -LiteralPath $testRoot) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}
