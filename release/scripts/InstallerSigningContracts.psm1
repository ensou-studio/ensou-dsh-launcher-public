#requires -Version 7.2

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$stateModulePath = Join-Path $PSScriptRoot 'ProductionReleaseState.psm1'
Microsoft.PowerShell.Core\Import-Module $stateModulePath -Force -ErrorAction Stop
$script:Utf8Strict = [Text.UTF8Encoding]::new($false, $true)
$script:MaximumInstallerBytes = 1024MB
$script:MaximumSourceBuildInputBytes = 1024MB
$script:Sha256Oid = '2.16.840.1.101.3.4.2.1'
$script:SpcIndirectDataOid = '1.3.6.1.4.1.311.2.1.4'
$script:SpcPeImageDataOid = '1.3.6.1.4.1.311.2.1.15'
$script:Rfc3161AttributeOids = @(
    '1.2.840.113549.1.9.16.2.14',
    '1.3.6.1.4.1.311.3.3.1')
$script:Rfc3161ContentTypeOid = '1.2.840.113549.1.9.16.1.4'
$script:LegacyCounterSignatureOid = '1.2.840.113549.1.9.6'

function Get-InstallerSigningSha256Bytes {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    return ProductionReleaseState\Get-ProductionSha256Bytes -Bytes $Bytes
}

function Get-InstallerSigningObjectSha256 {
    param([Parameter(Mandatory = $true)]$Value)

    $bytes = ProductionReleaseState\ConvertTo-ProductionJsonBytes -Value $Value
    return Get-InstallerSigningSha256Bytes -Bytes $bytes
}

function ConvertFrom-InstallerSigningBase64UrlStrict {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ($Value -notmatch '^[A-Za-z0-9_-]+$') {
        throw "$Label is not canonical base64url."
    }
    $padded = $Value.Replace('-', '+').Replace('_', '/')
    switch ($padded.Length % 4) {
        0 {}
        2 { $padded += '==' }
        3 { $padded += '=' }
        default { throw "$Label has an invalid base64url length." }
    }
    try {
        $bytes = [Convert]::FromBase64String($padded)
    }
    catch {
        throw "$Label is not valid base64url."
    }
    $canonical = [Convert]::ToBase64String($bytes).TrimEnd('=').
        Replace('+', '-').Replace('/', '_')
    if ($canonical -cne $Value) {
        throw "$Label is not canonical base64url."
    }
    return $bytes
}

function Read-InstallerSigningContractInput {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$SchemaPath,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $input = ProductionReleaseState\Read-StrictProductionJsonFile `
        -Path $Path `
        -SchemaPath $SchemaPath `
        -Label $Label
    [void](ProductionReleaseState\Assert-CanonicalProductionJsonInput `
        -JsonInput $input `
        -Label $Label)
    return $input
}

function Get-InstallerSigningExpectedReceiptPath {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('pilot', 'stable')]
        [string]$Channel
    )

    return "receipts/0005-$Channel-signed-candidate-imported.json"
}

function Get-InstallerSigningCandidateRoot {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('pilot', 'stable')]
        [string]$Channel
    )

    return "imports/$Channel-signed-candidate.v1/candidate/"
}

function Get-InstallerSigningExpectedRoles {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Personal', 'Enterprise')]
        [string]$Edition,
        [Parameter(Mandatory = $true)]
        [ValidateSet('candidate', 'signed-client', 'trust-probe', 'payload')]
        [string]$Set
    )

    if ($Edition -ceq 'Personal') {
        if ($Set -ceq 'candidate') {
            return @('release-manifest', 'client-bundle', 'runtime')
        }
        if ($Set -in @('signed-client', 'trust-probe')) {
            return @('startup-stub', 'client-bootstrapper', 'launcher', 'maintenance')
        }
        return @('release-manifest', 'startup-stub', 'client-bundle', 'runtime')
    }
    if ($Set -ceq 'candidate') {
        return @(
            'release-manifest',
            'release-public-key',
            'launcher',
            'runtime',
            'plugin-policy')
    }
    if ($Set -ceq 'signed-client') {
        return @('bootstrapper', 'launcher', 'client-bootstrapper', 'maintenance')
    }
    if ($Set -ceq 'trust-probe') {
        return @('bootstrapper', 'launcher', 'client-bootstrapper')
    }
    return @('install-manifest', 'launcher', 'runtime', 'bootstrapper')
}

function Assert-InstallerSigningOrderedRoles {
    param(
        [Parameter(Mandatory = $true)][object[]]$Files,
        [Parameter(Mandatory = $true)][string[]]$ExpectedRoles,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ($Files.Count -ne $ExpectedRoles.Count) {
        throw "$Label does not contain its exact edition inventory."
    }
    $names = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    for ($index = 0; $index -lt $ExpectedRoles.Count; $index++) {
        if ([string]$Files[$index].role -cne [string]$ExpectedRoles[$index] -or
            -not $names.Add([string]$Files[$index].fileName)) {
            throw "$Label has a repeated filename or noncanonical role at index $index."
        }
    }
}

function Assert-InstallerSigningSetHash {
    param(
        [Parameter(Mandatory = $true)][object[]]$Files,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $actual = Get-InstallerSigningObjectSha256 -Value $Files
    if ($actual -cne $ExpectedSha256) {
        throw "$Label does not equal its canonical set SHA-256."
    }
}

function Get-InstallerTargetBuildIdentitySha256 {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][psobject]$Request)

    $identity = [ordered]@{
        schemaVersion = 1
        identityType = 'ensou-dsh-launcher-installer-build-target'
        orchestrationId = [string]$Request.orchestrationId
        edition = [string]$Request.edition
        releaseSetId = [string]$Request.releaseSetId
        channel = [string]$Request.channel
        planSha256 = [string]$Request.planSha256
        sourceCommit = [string]$Request.sourceCommit
        sourceTree = [string]$Request.sourceTree
        sourceBuildInputSetSha256 = [string]$Request.sourceBuildInputSetSha256
        r5HeadSha256 = [string]$Request.r5Evidence.headSha256
        r5ReceiptSha256 = [string]$Request.r5Evidence.receiptSha256
        candidateSetSha256 = [string]$Request.candidate.inventorySha256
        r3SignedClientSetSha256 = [string]$Request.r3Evidence.signedClientSetSha256
        releaseManifestTrustProbeSetSha256 =
            [string]$Request.r3Evidence.releaseManifestTrustProbeSetSha256
        payloadSetSha256 = [string]$Request.installerPayload.inventorySha256
        toolchainLockSha256 = [string]$Request.toolchainLockSha256
    }
    return Get-InstallerSigningObjectSha256 -Value $identity
}

function Assert-InstallerSourceBuildInputContract {
    param([Parameter(Mandatory = $true)][psobject]$Request)

    $set = $Request.sourceBuildInputs
    $files = @($set.files)
    if ([string]$set.sourceTree -cne [string]$Request.sourceTree -or
        [string]$set.inventorySha256 -cne
            [string]$Request.sourceBuildInputSetSha256 -or
        [string]$set.preBuildInventorySha256 -cne
            [string]$Request.sourceBuildInputSetSha256 -or
        [string]$set.postBuildInventorySha256 -cne
            [string]$Request.sourceBuildInputSetSha256 -or
        (Get-InstallerSigningObjectSha256 -Value $files) -cne
            [string]$Request.sourceBuildInputSetSha256 -or
        -not [bool]$set.trackedClean -or
        [int]$set.dirtyPathCount -ne 0 -or
        [int]$set.untrackedPathCount -ne 0 -or
        [int]$set.linkedInputCount -ne 0 -or
        [string]$set.raceCheckStatus -cne 'VERIFIED_UNCHANGED') {
        throw 'Installer source-build input set is not one clean, exact, pre/post-verified source-tree closure.'
    }
    $expectedRootProject =
        "repo/src/Ensou.Dsh.$($Request.edition).Installer/" +
        "Ensou.Dsh.$($Request.edition).Installer.csproj"
    if ([string]$set.rootProjectIdentityPath -cne $expectedRootProject) {
        throw 'Installer source-build input set names the wrong edition root project.'
    }

    $identities = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    $previousIdentity = ''
    [int64]$totalSizeBytes = 0
    foreach ($file in $files) {
        $identity = [string]$file.identityPath
        $isTargetsAbsent =
            [string]$file.kind -ceq 'directory-build-targets-absent'
        if (-not $identities.Add($identity) -or
            ($previousIdentity -and
             [string]::Compare(
                 $previousIdentity,
                 $identity,
                 [StringComparison]::OrdinalIgnoreCase) -ge 0) -or
            (-not $isTargetsAbsent -and
             [string]$file.snapshotRelativePath -cne
                ('build-inputs/' + $identity))) {
            throw 'Installer source-build inputs must be unique and strictly identity-path sorted with canonical snapshots.'
        }
        if ($isTargetsAbsent) {
            ProductionReleaseState\Assert-ExactProductionJsonMembers `
                -Value $file `
                -Expected @('kind', 'identityPath', 'absenceStatus') `
                -Label 'Directory.Build.targets absence binding'
            if ($identity -cne 'repo/Directory.Build.targets' -or
                [string]$file.absenceStatus -cne 'VERIFIED_ABSENT') {
                throw 'Installer source-build inputs contain an invalid Directory.Build.targets absence binding.'
            }
        }
        else {
            ProductionReleaseState\Assert-ExactProductionJsonMembers `
                -Value $file `
                -Expected @(
                    'kind',
                    'identityPath',
                    'snapshotRelativePath',
                    'sizeBytes',
                    'sha256') `
                -Label "Installer source-build input '$identity'"
            if ([int64]$file.sizeBytes -le 0 -or
                [int64]$file.sizeBytes -gt
                    $script:MaximumSourceBuildInputBytes) {
                throw 'Installer source-build input exceeds its bounded snapshot size.'
            }
            $totalSizeBytes += [int64]$file.sizeBytes
            if ($totalSizeBytes -gt $script:MaximumSourceBuildInputBytes) {
                throw 'Installer source-build input set exceeds its 1 GiB total snapshot limit.'
            }
        }
        $previousIdentity = $identity
    }
    if ([int64]$set.totalSizeBytes -ne $totalSizeBytes) {
        throw 'Installer source-build input total size does not equal its exact bounded inventory.'
    }
    $requiredKinds = [ordered]@{
        source = 1
        project = 1
        'directory-build-props' = 1
        'global-json' = 1
        'packages-lock' = 1
        'restore-graph' = 1
        'runtime-pack' = 1
        'generated-input' = 1
    }
    foreach ($kind in $requiredKinds.Keys) {
        $count = @($files | Where-Object { [string]$_.kind -ceq $kind }).Count
        if ($count -lt [int]$requiredKinds[$kind]) {
            throw "Installer source-build input set omits required '$kind' evidence."
        }
    }
    $projectInputs = @($files | Where-Object {
            [string]$_.kind -ceq 'project'
        })
    $packageLockInputs = @($files | Where-Object {
            [string]$_.kind -ceq 'packages-lock'
        })
    if ($packageLockInputs.Count -ne $projectInputs.Count) {
        throw 'Installer source-build input set must contain one packages.lock.json for every transitive project.'
    }
    foreach ($projectInput in $projectInputs) {
        $projectPath = [string]$projectInput.identityPath
        $expectedLockPath =
            $projectPath.Substring(0, $projectPath.LastIndexOf('/') + 1) +
            'packages.lock.json'
        if (@($packageLockInputs | Where-Object {
                    [string]$_.identityPath -ceq $expectedLockPath
                }).Count -ne 1) {
            throw "Installer transitive project '$projectPath' has no exact packages.lock.json input."
        }
    }
    $directoryProps = @($files | Where-Object {
            [string]$_.kind -ceq 'directory-build-props'
        })
    if ($directoryProps.Count -ne 1 -or
        [string]$directoryProps[0].identityPath -cne
            'repo/Directory.Build.props') {
        throw 'Installer source-build input set must bind exact repo/Directory.Build.props bytes.'
    }
    $directoryTargets = @($files | Where-Object {
            [string]$_.kind -in @(
                'directory-build-targets',
                'directory-build-targets-absent')
        })
    if ($directoryTargets.Count -ne 1 -or
        [string]$directoryTargets[0].identityPath -cne
            'repo/Directory.Build.targets') {
        throw 'Installer source-build input set must bind Directory.Build.targets as exact present bytes or explicit verified absence.'
    }
    $globalJson = @($files | Where-Object {
            [string]$_.kind -ceq 'global-json'
        })
    $rootProject = @($files | Where-Object {
            [string]$_.identityPath -ceq $expectedRootProject
        })
    $restoreGraph = @($files | Where-Object {
            [string]$_.kind -ceq 'restore-graph' -and
            [string]$_.identityPath -ceq 'generated/project.assets.json'
        })
    $rootPackageLock = @($files | Where-Object {
            [string]$_.kind -ceq 'packages-lock' -and
            [string]$_.identityPath -ceq
                ($expectedRootProject.Substring(
                    0,
                    $expectedRootProject.LastIndexOf('/') + 1) +
                 'packages.lock.json')
        })
    if ($globalJson.Count -ne 1 -or
        [string]$globalJson[0].identityPath -cne 'repo/global.json' -or
        [string]$globalJson[0].sha256 -cne
            [string]$Request.toolchainLock.globalJsonSha256 -or
        $rootProject.Count -ne 1 -or
        [string]$rootProject[0].kind -cne 'project' -or
        [string]$rootProject[0].sha256 -cne
            [string]$Request.toolchainLock.projectSha256 -or
        $restoreGraph.Count -ne 1 -or
        [string]$restoreGraph[0].sha256 -cne
            [string]$Request.toolchainLock.restoreGraphSha256 -or
        $rootPackageLock.Count -ne 1 -or
        [string]$rootPackageLock[0].sha256 -cne
            [string]$Request.toolchainLock.packagesLockSha256 -or
        [string]$Request.toolchainLock.packagesLockStatus -cne 'VERIFIED' -or
        [string]$Request.toolchainLock.restoreMode -cne
            'packages-lock-locked-offline') {
        throw 'Installer toolchain lock does not equal the detailed global/project/packages/assets source-build inputs.'
    }
    $runtimePacks = @($files | Where-Object {
            [string]$_.kind -ceq 'runtime-pack'
        })
    if ((Get-InstallerSigningObjectSha256 -Value $runtimePacks) -cne
        [string]$Request.toolchainLock.runtimePackSetSha256) {
        throw 'Installer runtime-pack set differs from the detailed source-build inventory.'
    }
    $dependencyInputs = @($files | Where-Object {
            [string]$_.kind -in @(
                'project', 'packages-lock', 'restore-graph', 'runtime-pack')
        })
    if ((Get-InstallerSigningObjectSha256 -Value $dependencyInputs) -cne
        [string]$Request.toolchainLock.dependencyClosureSha256) {
        throw 'Installer dependency closure differs from its typed detailed build inputs.'
    }
}

function Assert-InstallerSigningTrustDomain {
    param(
        [Parameter(Mandatory = $true)][psobject]$InstallerSigningTrust,
        [Parameter(Mandatory = $true)][psobject]$Request,
        [psobject]$ReleaseManifestTrust
    )

    ProductionReleaseState\Assert-ExactProductionJsonMembers `
        -Value $InstallerSigningTrust `
        -Expected @('algorithm', 'keyId', 'purpose', 'x', 'y') `
        -Label 'Installer-signing plan trust'
    $expectedPurpose = if ([int]$Request.schemaVersion -eq 2 -and
        [string]$Request.edition -ceq 'Personal') {
        'personal-installer-signing-response'
    }
    else {
        'installer-signing-response'
    }
    if ([string]$InstallerSigningTrust.algorithm -cne 'ES256' -or
        [string]$InstallerSigningTrust.purpose -cne $expectedPurpose -or
        [string]$InstallerSigningTrust.keyId -cne
            [string]$Request.responseAuthentication.keyId -or
        (Get-InstallerSigningObjectSha256 -Value $InstallerSigningTrust) -cne
            [string]$Request.responseAuthentication.trustSha256) {
        throw 'Installer-signing request does not bind the exact isolated plan trust domain.'
    }
    [void](ProductionReleaseState\Get-ProductionReleaseP256PublicKeyIdentity `
        -Trust $InstallerSigningTrust `
        -Label 'Installer-signing plan trust')
    if ($null -ne $ReleaseManifestTrust) {
        $installerPoint = ProductionReleaseState\Get-ProductionReleaseP256PublicKeyIdentity `
            -Trust $InstallerSigningTrust `
            -Label 'Installer-signing plan trust'
        $releasePoint = ProductionReleaseState\Get-ProductionReleaseP256PublicKeyIdentity `
            -Trust $ReleaseManifestTrust `
            -Label 'Release-manifest plan trust'
        if ([string]$InstallerSigningTrust.keyId -ceq
                [string]$ReleaseManifestTrust.keyId -or
            [string]$installerPoint -ceq [string]$releasePoint) {
            throw 'Installer-signing trust must be independent from release-manifest signing trust.'
        }
        if ([int]$Request.schemaVersion -eq 2 -and
            [string]$Request.edition -ceq 'Personal') {
            $releasePublicIdentity = [ordered]@{
                algorithm = [string]$ReleaseManifestTrust.algorithm
                keyId = [string]$ReleaseManifestTrust.keyId
                x = [string]$ReleaseManifestTrust.x
                y = [string]$ReleaseManifestTrust.y
            }
            if ([string]$ReleaseManifestTrust.algorithm -cne 'ES256' -or
                [string]$ReleaseManifestTrust.purpose -cne
                    'release-manifest-signing' -or
                [string]$Request.compiledTrust.releaseKeyId -cne
                    [string]$ReleaseManifestTrust.keyId -or
                [string]$Request.compiledTrust.releaseKeyIdentitySha256 -cne
                    (Get-InstallerSigningObjectSha256 `
                        -Value $releasePublicIdentity)) {
                throw 'Personal Installer-signing request does not bind the exact release-manifest plan trust.'
            }
        }
        elseif ((Get-InstallerSigningObjectSha256 -Value $ReleaseManifestTrust) -cne
            [string]$Request.r3Evidence.releaseManifestTrustSha256) {
            throw 'Installer-signing request does not bind the exact release-manifest plan trust.'
        }
    }
}

function Assert-PersonalInstallerSigningRequestV2Contract {
    param(
        [Parameter(Mandatory = $true)][psobject]$Request,
        [psobject]$InstallerSigningTrust,
        [psobject]$ReleaseManifestTrust
    )

    if ([string]$Request.requestType -cne
            'ensou-dsh-personal-installer-signing-request' -or
        [int]$Request.baseRevision -ne 5 -or
        [int]$Request.requestedRevision -ne 6 -or
        [string]$Request.basePhase -cne
            'PILOT_SIGNED_CANDIDATE_IMPORTED' -or
        [string]$Request.compiledTrust.channel -cne 'pilot') {
        throw 'Personal Installer-signing request v2 is not bound to the exact Pilot r5 identity.'
    }

    $created = ProductionReleaseState\ConvertFrom-ProductionUtc `
        -Value ([string]$Request.createdAtUtc) `
        -Label 'Personal Installer-signing request creation time'
    $expires = ProductionReleaseState\ConvertFrom-ProductionUtc `
        -Value ([string]$Request.expiresAtUtc) `
        -Label 'Personal Installer-signing request expiry time'
    $buildStarted = ProductionReleaseState\ConvertFrom-ProductionUtc `
        -Value ([string]$Request.buildExecution.startedAtUtc) `
        -Label 'Personal Installer build start time'
    $buildCompleted = ProductionReleaseState\ConvertFrom-ProductionUtc `
        -Value ([string]$Request.buildExecution.completedAtUtc) `
        -Label 'Personal Installer build completion time'
    if ($expires -le $created -or
        ($expires - $created) -ne
            [TimeSpan]::FromMinutes(
                [int]$Request.responseAuthentication.maximumResponseAgeMinutes) -or
        $buildStarted -gt $buildCompleted -or
        $buildCompleted -gt $created) {
        throw 'Personal Installer build or request lifetime order is invalid.'
    }

    $payloadFiles = @($Request.payload.files)
    Assert-InstallerSigningOrderedRoles `
        -Files $payloadFiles `
        -ExpectedRoles (Get-InstallerSigningExpectedRoles `
            -Edition Personal -Set payload) `
        -Label 'Personal Installer payload inventory'
    if ((Get-InstallerSigningObjectSha256 -Value $payloadFiles) -cne
            [string]$Request.payload.inventorySha256 -or
        [string]$Request.payload.status -cne
            'EXACT_FOUR_FILE_BYTE_CLOSURE_VERIFIED' -or
        [string]$Request.payload.authenticationStatus -cne
            'STRUCTURE_AND_ARTIFACT_HASHES_VERIFIED_SIGNED_MANIFEST_TRUST_NOT_YET_SHARED_R6_ADMITTED') {
        throw 'Personal Installer payload does not equal its exact four-file trusted-build closure.'
    }

    $payloadDefinitions = @(
        [pscustomobject]@{
            Role = 'release-manifest'
            FileName = 'release-set.v2.json'
            RelativePath = 'payload/release-set.v2.json'
            LogicalName =
                'Ensou.Dsh.Personal.Installer.Payload.release-set.v2.json'
        },
        [pscustomobject]@{
            Role = 'startup-stub'
            FileName = 'Ensou.Dsh.Bootstrapper.exe'
            RelativePath = 'payload/Ensou.Dsh.Bootstrapper.exe'
            LogicalName =
                'Ensou.Dsh.Personal.Installer.Payload.Ensou.Dsh.Bootstrapper.exe'
        },
        [pscustomobject]@{
            Role = 'client-bundle'
            FileName = 'client-bundle.zip'
            RelativePath = 'payload/client-bundle.zip'
            LogicalName =
                'Ensou.Dsh.Personal.Installer.Payload.client-bundle.zip'
        },
        [pscustomobject]@{
            Role = 'runtime'
            FileName = 'runtime.zip'
            RelativePath = 'payload/runtime.zip'
            LogicalName =
                'Ensou.Dsh.Personal.Installer.Payload.runtime.zip'
        })
    $resources = @($Request.resourceBinding.resources)
    if ($resources.Count -ne $payloadDefinitions.Count -or
        [string]$Request.resourceBinding.verificationMethod -cne
            'pe-metadata-embedded-resource-inspection-no-assembly-load-v1' -or
        [string]$Request.resourceBinding.status -cne 'VERIFIED' -or
        [string]$Request.resourceBinding.unsignedInstallerSha256 -cne
            [string]$Request.unsignedInstaller.sha256 -or
        (Get-InstallerSigningObjectSha256 -Value $resources) -cne
            [string]$Request.resourceBinding.resourceSetSha256) {
        throw 'Personal Installer request v2 does not carry one exact build-time resource binding.'
    }
    for ($index = 0; $index -lt $payloadDefinitions.Count; $index++) {
        $definition = $payloadDefinitions[$index]
        $payload = $payloadFiles[$index]
        $resource = $resources[$index]
        if ([string]$payload.role -cne [string]$definition.Role -or
            [string]$payload.fileName -cne [string]$definition.FileName -or
            [string]$payload.relativePath -cne
                [string]$definition.RelativePath -or
            [string]$resource.role -cne [string]$definition.Role -or
            [string]$resource.logicalName -cne [string]$definition.LogicalName -or
            [int64]$resource.sizeBytes -ne [int64]$payload.sizeBytes -or
            [string]$resource.sha256 -cne [string]$payload.sha256 -or
            [string]$resource.status -cne 'VERIFIED') {
            throw "Personal Installer resource '$($definition.Role)' differs from its exact payload bytes."
        }
    }

    $toolchainIdentity = [ordered]@{
        packageClosure = $Request.toolchain.packageClosure
        sdkClosure = $Request.toolchain.sdkClosure
    }
    if ((Get-InstallerSigningObjectSha256 -Value $toolchainIdentity) -cne
            [string]$Request.toolchain.toolchainIdentitySha256 -or
        [string]$Request.toolchain.packageClosure.lockRelativePath -cne
            'repo/installer/personal-publish-runtime-packs.lock.json' -or
        [int]$Request.toolchain.packageClosure.packageCount -ne 4 -or
        [string]$Request.toolchain.sdkClosure.sdkVersion -cne '10.0.302' -or
        [string]$Request.toolchain.sdkClosure.status -cne 'VERIFIED' -or
        [string]$Request.toolchain.sdkClosure.privateCopyPolicy -cne
            'create-only-private-copy-held-open-through-version-restore-publish-v1') {
        throw 'Personal Installer toolchain is not the exact offline package and portable SDK closure.'
    }

    if ([string]$Request.source.status -cne 'CLEAN_TRACKED_HEAD' -or
        [string]$Request.source.snapshotContract -cne
            'git-head-archive-held-file-leases-directory-identity-mutation-monitor-v2' -or
        [string]$Request.source.rootProject -cne
            'src/Ensou.Dsh.Personal.Installer/Ensou.Dsh.Personal.Installer.csproj' -or
        [int]$Request.buildExecution.exitCode -ne 0 -or
        [string]$Request.buildExecution.runtimeIdentifier -cne 'win-x64' -or
        -not [bool]$Request.buildExecution.selfContained -or
        -not [bool]$Request.buildExecution.singleFile -or
        -not [bool]$Request.buildExecution.offlineRestore -or
        -not [bool]$Request.buildExecution.inheritedEnvironmentCleared -or
        [string]$Request.buildExecution.unsignedArtifactExecution -cne
            'FORBIDDEN_AND_NOT_PERFORMED' -or
        [string]$Request.unsignedInstaller.fileName -cne
            'Ensou.Dsh.Personal.Installer.exe' -or
        [string]$Request.unsignedInstaller.relativePath -cne
            'unsigned/Ensou.Dsh.Personal.Installer.exe' -or
        [string]$Request.unsignedInstaller.authenticodeStatus -cne 'NotSigned') {
        throw 'Personal Installer request v2 is not one clean offline self-contained unsigned build.'
    }

    if ([string]$Request.trustedBuildEvidence.fileName -cne
            'trusted-build-evidence.v1.json' -or
        [string]$Request.trustedBuildEvidence.relativePath -cne
            'trusted-build/trusted-build-evidence.v1.json' -or
        [string]$Request.trustedBuildEvidence.productionAdmission -cne 'NO_GO' -or
        [string]$Request.admission.status -cne 'READY' -or
        [string]$Request.admission.blocker -cne
            'INSTALLER_SIGNING_RESPONSE_REQUIRED' -or
        [string]$Request.admission.productionAdmission -cne 'NO_GO') {
        throw 'Personal Installer request v2 does not preserve its exact trusted-build NO_GO admission.'
    }

    if ($null -ne $InstallerSigningTrust) {
        Assert-InstallerSigningTrustDomain `
            -InstallerSigningTrust $InstallerSigningTrust `
            -Request $Request `
            -ReleaseManifestTrust $ReleaseManifestTrust
    }
    return $true
}

function Assert-InstallerSigningRequestContract {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][psobject]$Request,
        [psobject]$InstallerSigningTrust,
        [psobject]$ReleaseManifestTrust
    )

    $requestSchemaVersion = [int]$Request.schemaVersion
    $edition = [string]$Request.edition
    $channel = [string]$Request.channel
    if ($requestSchemaVersion -notin @(1, 2) -or
        $edition -notin @('Personal', 'Enterprise') -or
        $channel -notin @('pilot', 'stable') -or
        ($edition -ceq 'Enterprise' -and $channel -cne 'stable') -or
        ($requestSchemaVersion -eq 2 -and
         -not (($edition -ceq 'Enterprise' -and $channel -ceq 'stable') -or
               ($edition -ceq 'Personal' -and $channel -ceq 'pilot')))) {
        throw 'Installer-signing request edition/channel identity is invalid.'
    }
    if ($requestSchemaVersion -eq 2 -and $edition -ceq 'Personal') {
        return Assert-PersonalInstallerSigningRequestV2Contract `
            -Request $Request `
            -InstallerSigningTrust $InstallerSigningTrust `
            -ReleaseManifestTrust $ReleaseManifestTrust
    }
    $expectedPhase = $channel.ToUpperInvariant() + '_SIGNED_CANDIDATE_IMPORTED'
    if ([int]$Request.baseRevision -ne 5 -or
        [int]$Request.requestedRevision -ne 6 -or
        [string]$Request.basePhase -cne $expectedPhase -or
        [string]$Request.baseHeadSha256 -cne
            [string]$Request.r5Evidence.headSha256 -or
        [string]$Request.r5Evidence.receiptRelativePath -cne
            (Get-InstallerSigningExpectedReceiptPath -Channel $channel) -or
        [string]$Request.r5Evidence.manifestRelativePath -cne
            ((Get-InstallerSigningCandidateRoot -Channel $channel) +
             'release-set.v2.json')) {
        throw 'Installer-signing request is not bound to the exact r5 target-channel head and receipt.'
    }
    if ([string]$Request.r3Evidence.receiptRelativePath -cne
        'receipts/0003-client-signatures-imported.json') {
        throw 'Installer-signing request is not bound to the exact r3 receipt path.'
    }
    Assert-InstallerSourceBuildInputContract -Request $Request

    $created = ProductionReleaseState\ConvertFrom-ProductionUtc `
        -Value ([string]$Request.createdAtUtc) `
        -Label 'Installer-signing request creation time'
    $expires = ProductionReleaseState\ConvertFrom-ProductionUtc `
        -Value ([string]$Request.expiresAtUtc) `
        -Label 'Installer-signing request expiry time'
    $buildStarted = ProductionReleaseState\ConvertFrom-ProductionUtc `
        -Value ([string]$Request.buildExecution.startedAtUtc) `
        -Label 'Installer build start time'
    $buildCompleted = ProductionReleaseState\ConvertFrom-ProductionUtc `
        -Value ([string]$Request.buildExecution.completedAtUtc) `
        -Label 'Installer build completion time'
    if ($expires -le $created -or
        ($expires - $created) -ne
            [TimeSpan]::FromMinutes(
                [int]$Request.responseAuthentication.maximumResponseAgeMinutes) -or
        $buildStarted -gt $buildCompleted -or
        $buildCompleted -gt $created) {
        throw 'Installer build or request lifetime order is invalid.'
    }
    if ($requestSchemaVersion -eq 1) {
        $selfCheckCompleted = ProductionReleaseState\ConvertFrom-ProductionUtc `
            -Value ([string]$Request.payloadSelfCheck.completedAtUtc) `
            -Label 'Unsigned Installer payload self-check time'
        if ($selfCheckCompleted -lt $buildCompleted -or
            $selfCheckCompleted -gt $created) {
            throw 'Installer unsigned payload self-check time is outside its build/request window.'
        }
    }

    $candidateFiles = @($Request.candidate.files)
    Assert-InstallerSigningOrderedRoles `
        -Files $candidateFiles `
        -ExpectedRoles (Get-InstallerSigningExpectedRoles `
            -Edition $edition -Set candidate) `
        -Label 'r5 signed-candidate inventory'
    $candidateRoot = Get-InstallerSigningCandidateRoot -Channel $channel
    foreach ($file in $candidateFiles) {
        if ([string]$file.relativePath -cne
            ($candidateRoot + [string]$file.fileName)) {
            throw 'r5 signed-candidate inventory contains a noncanonical target-channel path.'
        }
    }
    Assert-InstallerSigningSetHash `
        -Files $candidateFiles `
        -ExpectedSha256 ([string]$Request.candidate.inventorySha256) `
        -Label 'r5 signed-candidate inventory'
    if ([string]$candidateFiles[0].sha256 -cne
        [string]$Request.r5Evidence.manifestSha256) {
        throw 'r5 signed-candidate manifest differs from its exact r5 receipt binding.'
    }

    $signedClients = @($Request.r3Evidence.signedClients)
    Assert-InstallerSigningOrderedRoles `
        -Files $signedClients `
        -ExpectedRoles (Get-InstallerSigningExpectedRoles `
            -Edition $edition -Set signed-client) `
        -Label 'r3 signed-client inventory'
    foreach ($file in $signedClients) {
        if ([string]$file.relativePath -cne
            ('imports/client-signing.v1/signed/' + [string]$file.fileName)) {
            throw 'r3 signed-client inventory contains a noncanonical path.'
        }
    }
    Assert-InstallerSigningSetHash `
        -Files $signedClients `
        -ExpectedSha256 ([string]$Request.r3Evidence.signedClientSetSha256) `
        -Label 'r3 signed-client inventory'

    $probes = @($Request.r3Evidence.releaseManifestTrustProbes)
    Assert-InstallerSigningOrderedRoles `
        -Files $probes `
        -ExpectedRoles (Get-InstallerSigningExpectedRoles `
            -Edition $edition -Set trust-probe) `
        -Label 'r3 release-manifest trust-probe inventory'
    Assert-InstallerSigningSetHash `
        -Files $probes `
        -ExpectedSha256 (
            [string]$Request.r3Evidence.releaseManifestTrustProbeSetSha256) `
        -Label 'r3 release-manifest trust-probe inventory'
    foreach ($probe in $probes) {
        $client = @($signedClients | Where-Object {
                [string]$_.role -ceq [string]$probe.role
            })
        if ($client.Count -ne 1 -or
            [string]$client[0].fileName -cne [string]$probe.fileName) {
            throw 'r3 release-manifest trust probe is not bound to its exact signed client.'
        }
    }
    if ([string]$Request.r3Evidence.releaseManifestTrustSha256 -cne
        [string]$Request.r5Evidence.releaseManifestTrustSha256) {
        throw 'r3 compiled release trust differs from the exact r5 signed-candidate trust.'
    }

    $payloadFiles = @($Request.installerPayload.files)
    Assert-InstallerSigningOrderedRoles `
        -Files $payloadFiles `
        -ExpectedRoles (Get-InstallerSigningExpectedRoles `
            -Edition $edition -Set payload) `
        -Label 'Installer payload inventory'
    Assert-InstallerSigningSetHash `
        -Files $payloadFiles `
        -ExpectedSha256 ([string]$Request.installerPayload.inventorySha256) `
        -Label 'Installer payload inventory'
    foreach ($payload in $payloadFiles) {
        if ([string]$payload.sourceSha256 -cne [string]$payload.sha256) {
            throw "Installer payload role '$($payload.role)' is not exact source bytes."
        }
        if ([string]$payload.sourceKind -ceq 'r5-candidate') {
            $source = @($candidateFiles | Where-Object {
                    [string]$_.role -ceq [string]$payload.sourceRole
                })
        }
        elseif ([string]$payload.sourceKind -ceq 'r3-signed-client') {
            $source = @($signedClients | Where-Object {
                    [string]$_.role -ceq [string]$payload.sourceRole
                })
        }
        else {
            $source = @()
            if ([string]$payload.role -cne 'install-manifest' -or
                $edition -cne 'Enterprise') {
                throw 'Only the Enterprise install-manifest may be a generated payload descriptor.'
            }
        }
        if ([string]$payload.sourceKind -cne 'generated-descriptor' -and
            ($source.Count -ne 1 -or
             [string]$source[0].sha256 -cne [string]$payload.sha256 -or
             [int64]$source[0].sizeBytes -ne [int64]$payload.sizeBytes)) {
            throw "Installer payload role '$($payload.role)' differs from its exact r3/r5 source."
        }
    }

    if ((Get-InstallerSigningObjectSha256 -Value $Request.toolchainLock) -cne
        [string]$Request.toolchainLockSha256) {
        throw 'Installer toolchain lock SHA-256 is not exact.'
    }
    $expectedProject = "Ensou.Dsh.$edition.Installer.csproj"
    if ([string]$Request.toolchainLock.projectFileName -cne $expectedProject -or
        [string]$Request.toolchainLock.projectRelativePath -cne
            ('toolchain/' + $expectedProject)) {
        throw 'Installer toolchain lock uses the wrong edition project.'
    }
    if ([int]$Request.buildExecution.buildOrdinal -ne 1 -or
        [int]$Request.buildExecution.buildCountForTarget -ne 1 -or
        [string]$Request.buildExecution.outputCreationMode -cne 'create-new' -or
        [string]$Request.buildExecution.rebuildPolicy -cne
            'rebuild-forbidden-exact-reserved-unsigned-bytes-replay-only' -or
        [int]$Request.buildExecution.exitCode -ne 0 -or
        [string]$Request.buildExecution.targetBuildIdentitySha256 -cne
            (Get-InstallerTargetBuildIdentitySha256 -Request $Request)) {
        throw 'Installer target was not bound to one create-only build and exact-byte replay policy.'
    }

    if ($requestSchemaVersion -eq 1) {
        $selfCheck = $Request.payloadSelfCheck
        if ([string]$selfCheck.inspectedInstallerSha256 -cne
                [string]$Request.unsignedInstaller.sha256 -or
            [string]$selfCheck.candidateSetSha256 -cne
                [string]$Request.candidate.inventorySha256 -or
            [string]$selfCheck.payloadSetSha256 -cne
                [string]$Request.installerPayload.inventorySha256 -or
            [string]$selfCheck.r3SignedClientSetSha256 -cne
                [string]$Request.r3Evidence.signedClientSetSha256 -or
            [string]$selfCheck.releaseManifestTrustSha256 -cne
                [string]$Request.r3Evidence.releaseManifestTrustSha256 -or
            [string]$selfCheck.releaseManifestTrustProbeSetSha256 -cne
                [string]$Request.r3Evidence.releaseManifestTrustProbeSetSha256) {
            throw 'Unsigned Installer payload self-check does not close the exact r3/r5/payload trust tuple.'
        }
    }
    else {
        $binding = $Request.resourceBinding
        $resources = @($binding.resources)
        $payloadRoles = Get-InstallerSigningExpectedRoles `
            -Edition Enterprise `
            -Set payload
        if ([string]$binding.verificationType -cne
                'managed-assembly-resource-to-single-file-build-input-v1' -or
            [string]$binding.verificationMethod -cne
                'collectible-load-context-manifest-resource-inspection-no-entrypoint' -or
            [string]$binding.status -cne 'VERIFIED' -or
            [string]$binding.unsignedInstallerSha256 -cne
                [string]$Request.unsignedInstaller.sha256 -or
            $resources.Count -ne $payloadRoles.Count -or
            (Get-InstallerSigningObjectSha256 -Value $resources) -cne
                [string]$binding.resourceSetSha256) {
            throw 'Installer signing request v2 does not carry one exact build-time resource binding.'
        }
        for ($index = 0; $index -lt $payloadRoles.Count; $index++) {
            $resource = $resources[$index]
            $payload = $payloadFiles[$index]
            if ([string]$resource.role -cne [string]$payloadRoles[$index] -or
                [string]$resource.role -cne [string]$payload.role -or
                [string]$resource.embeddedLogicalName -cne
                    [string]$payload.embeddedLogicalName -or
                [int64]$resource.sizeBytes -ne [int64]$payload.sizeBytes -or
                [string]$resource.sha256 -cne [string]$payload.sha256 -or
                [string]$resource.status -cne 'VERIFIED') {
                throw "Installer signing request v2 resource '$($payloadRoles[$index])' differs from its exact payload bytes."
            }
        }
        $evidence = $Request.trustedBuildEvidence
        if ([string]$evidence.evidenceType -cne
                'ensou-dsh-enterprise-installer-trusted-build' -or
            [string]$evidence.relativePath -cne
                'trusted-build/trusted-build-evidence.v1.json' -or
            [string]$evidence.resourceBindingSha256 -cne
                (Get-InstallerSigningObjectSha256 -Value $binding) -or
            [string]$evidence.sdkFileClosureStatus -cne
                'VERIFIED' -or
            [string]$evidence.productionAdmission -cne 'NO_GO') {
            throw 'Installer signing request v2 trusted-build evidence does not bind the exact resource proof and verified portable SDK closure.'
        }
        $reservation = [ordered]@{
            schemaVersion = 1
            reservationType =
                'ensou-dsh-enterprise-installer-trusted-build-reservation'
            buildId = [string]$Request.buildExecution.buildId
            targetBuildIdentitySha256 =
                [string]$Request.buildExecution.targetBuildIdentitySha256
            sourceBuildInputSetSha256 =
                [string]$Request.sourceBuildInputSetSha256
            unsignedInstallerSha256 =
                [string]$Request.unsignedInstaller.sha256
        }
        if ([string]$Request.buildExecution.reservationSha256 -cne
            (Get-InstallerSigningObjectSha256 -Value $reservation)) {
            throw 'Installer signing request v2 build reservation is not exact.'
        }
    }

    if ($null -ne $InstallerSigningTrust) {
        Assert-InstallerSigningTrustDomain `
            -InstallerSigningTrust $InstallerSigningTrust `
            -Request $Request `
            -ReleaseManifestTrust $ReleaseManifestTrust
    }
    return $true
}

function Assert-UnsignedInstallerSigningInput {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][psobject]$Descriptor
    )

    $input = ProductionReleaseState\Open-ProductionReleaseInput `
        -Path $Path `
        -Label 'Unsigned Installer' `
        -MaximumBytes $script:MaximumInstallerBytes
    try {
        if ([string]$input.FileName -cne [string]$Descriptor.fileName) {
            throw 'Unsigned Installer uses a noncanonical filename.'
        }
        [byte[]]$bytes = ProductionReleaseState\Read-ProductionReleaseInputBytes `
            -Descriptor $input `
            -Label 'Unsigned Installer'
        if ([int64]$bytes.LongLength -ne [int64]$Descriptor.sizeBytes -or
            [string]$input.Sha256 -cne [string]$Descriptor.sha256 -or
            (ProductionReleaseState\Get-PeContentSha256 -Bytes $bytes) -cne
                [string]$Descriptor.peContentSha256) {
            throw 'Unsigned Installer bytes differ from the exact r6 request.'
        }
        $signature = Microsoft.PowerShell.Security\Get-AuthenticodeSignature `
            -LiteralPath $input.Path
        [void](ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
            -Descriptor $input `
            -Label 'Unsigned Installer')
        if ([string]$signature.Status -cne 'NotSigned') {
            throw 'Unsigned Installer already contains or resolves to a signature.'
        }
        return $true
    }
    finally {
        $input.Stream.Dispose()
    }
}

function Get-InstallerSigningResponseAuthenticationPayload {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][psobject]$Response)

    $body = [ordered]@{}
    foreach ($property in $Response.PSObject.Properties) {
        if ($property.Name -cne 'authentication') {
            $body[$property.Name] = $property.Value
        }
    }
    $body['authentication'] = [ordered]@{
        algorithm = [string]$Response.authentication.algorithm
        keyId = [string]$Response.authentication.keyId
        purpose = [string]$Response.authentication.purpose
        payloadType = [string]$Response.authentication.payloadType
    }
    $domain = $script:Utf8Strict.GetBytes(
        'installer-signing-response' + [char]10)
    $json = ProductionReleaseState\ConvertTo-ProductionJsonBytes -Value $body
    $payload = [byte[]]::new($domain.Length + $json.Length)
    [Array]::Copy($domain, 0, $payload, 0, $domain.Length)
    [Array]::Copy($json, 0, $payload, $domain.Length, $json.Length)
    return $payload
}

function Assert-InstallerSigningResponseAuthentication {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][psobject]$Response,
        [Parameter(Mandatory = $true)][psobject]$Request,
        [Parameter(Mandatory = $true)][psobject]$InstallerSigningTrust
    )

    Assert-InstallerSigningTrustDomain `
        -InstallerSigningTrust $InstallerSigningTrust `
        -Request $Request
    if ([string]$Response.authentication.algorithm -cne 'ES256' -or
        [string]$Response.authentication.keyId -cne
            [string]$InstallerSigningTrust.keyId -or
        [string]$Response.authentication.purpose -cne
            'installer-signing-response' -or
        [string]$Response.authentication.payloadType -cne
            'ensou-dsh-launcher-installer-signing-response-authentication-v1') {
        throw 'Installer-signing response authentication is outside its isolated trust domain.'
    }
    $x = ConvertFrom-InstallerSigningBase64UrlStrict `
        -Value ([string]$InstallerSigningTrust.x) `
        -Label 'Installer-signing response key X'
    $y = ConvertFrom-InstallerSigningBase64UrlStrict `
        -Value ([string]$InstallerSigningTrust.y) `
        -Label 'Installer-signing response key Y'
    $signature = ConvertFrom-InstallerSigningBase64UrlStrict `
        -Value ([string]$Response.authentication.value) `
        -Label 'Installer-signing response signature'
    if ($x.Length -ne 32 -or $y.Length -ne 32 -or $signature.Length -ne 64) {
        throw 'Installer-signing response uses invalid P-256 P1363 sizes.'
    }
    ProductionReleaseState\Assert-ProductionEs256P1363LowS `
        -Signature $signature `
        -Label 'Installer-signing response signature'

    $parameters = [Security.Cryptography.ECParameters]::new()
    $parameters.Curve = [Security.Cryptography.ECCurve+NamedCurves]::nistP256
    $point = [Security.Cryptography.ECPoint]::new()
    $point.X = $x
    $point.Y = $y
    $parameters.Q = $point
    $ecdsa = [Security.Cryptography.ECDsa]::Create()
    try {
        try {
            $ecdsa.ImportParameters($parameters)
        }
        catch {
            throw 'Installer-signing response trust is not one valid P-256 point.'
        }
        $payload = Get-InstallerSigningResponseAuthenticationPayload `
            -Response $Response
        if (-not $ecdsa.VerifyData(
                $payload,
                $signature,
                [Security.Cryptography.HashAlgorithmName]::SHA256,
                [Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)) {
            throw 'Installer-signing response authentication signature is invalid.'
        }
    }
    finally {
        $ecdsa.Dispose()
    }
    return $true
}

function Assert-InstallerSigningResponseContract {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$RequestInput,
        [Parameter(Mandatory = $true)]$ResponseInput,
        [Parameter(Mandatory = $true)][string]$R6HeadSha256,
        [Parameter(Mandatory = $true)][string]$R6ReceiptSha256,
        [Parameter(Mandatory = $true)][psobject]$InstallerSigningTrust,
        [switch]$EnforceCurrentLifetime
    )

    $request = $RequestInput.Value
    $response = $ResponseInput.Value
    $expectedRequestRelativePath = if ([int]$request.schemaVersion -eq 2) {
        'requests/installer-signing.v2/installer-signing-request.v2.json'
    }
    else {
        'requests/installer-signing.v1/installer-signing-request.v1.json'
    }
    [void](Assert-InstallerSigningRequestContract `
        -Request $request `
        -InstallerSigningTrust $InstallerSigningTrust)
    if ([string]$response.orchestrationId -cne [string]$request.orchestrationId -or
        [string]$response.edition -cne [string]$request.edition -or
        [string]$response.releaseSetId -cne [string]$request.releaseSetId -or
        [string]$response.channel -cne [string]$request.channel -or
        [string]$response.planSha256 -cne [string]$request.planSha256 -or
        [string]$response.sourceTree -cne [string]$request.sourceTree -or
        [string]$response.sourceBuildInputSetSha256 -cne
            [string]$request.sourceBuildInputSetSha256 -or
        [string]$response.requestRelativePath -cne
            $expectedRequestRelativePath -or
        [string]$response.requestSha256 -cne [string]$RequestInput.Sha256 -or
        [string]$response.requestNonce -cne [string]$request.requestNonce -or
        [string]$response.baseHeadSha256 -cne [string]$request.baseHeadSha256 -or
        [string]$response.admissionHeadSha256 -cne $R6HeadSha256 -or
        [int]$response.admissionRevision -ne 6 -or
        [string]$response.r6ReceiptSha256 -cne $R6ReceiptSha256 -or
        [string]$response.requestCreatedAtUtc -cne [string]$request.createdAtUtc -or
        [string]$response.requestExpiresAtUtc -cne [string]$request.expiresAtUtc) {
        throw 'Installer-signing response is not bound to the exact request, nonce, r5 base, and r6 CAS head/receipt.'
    }
    $created = ProductionReleaseState\ConvertFrom-ProductionUtc `
        -Value ([string]$request.createdAtUtc) `
        -Label 'Installer-signing request creation time'
    $expires = ProductionReleaseState\ConvertFrom-ProductionUtc `
        -Value ([string]$request.expiresAtUtc) `
        -Label 'Installer-signing request expiry time'
    $completed = ProductionReleaseState\ConvertFrom-ProductionUtc `
        -Value ([string]$response.completedAtUtc) `
        -Label 'Installer-signing response completion time'
    $timestamp = ProductionReleaseState\ConvertFrom-ProductionUtc `
        -Value ([string]$response.authenticode.timestampUtc) `
        -Label 'Installer Authenticode RFC3161 timestamp'
    $signedSelfCheckCompleted = ProductionReleaseState\ConvertFrom-ProductionUtc `
        -Value ([string]$response.payloadSelfCheck.completedAtUtc) `
        -Label 'Signed Installer payload self-check time'
    $now = [DateTimeOffset]::UtcNow
    if ($completed -lt $created -or $completed -gt $expires -or
        $completed -gt $now.AddMinutes(5) -or
        $timestamp -lt $created -or $timestamp -gt $completed -or
        $timestamp -gt $expires -or
        $signedSelfCheckCompleted -lt $timestamp -or
        $signedSelfCheckCompleted -gt $completed -or
        ($EnforceCurrentLifetime -and $now -gt $expires)) {
        throw 'Installer-signing response, RFC3161 timestamp, or payload self-check is stale, future-dated, or outside its exact request window.'
    }

    $closure = [ordered]@{
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
    }
    foreach ($name in $closure.Keys) {
        if ([string]$response.$name -cne [string]$closure[$name]) {
            throw "Installer-signing response closure '$name' differs from r6."
        }
    }
    if ((Get-InstallerSigningObjectSha256 -Value $response.unsignedInstaller) -cne
            (Get-InstallerSigningObjectSha256 -Value $request.unsignedInstaller) -or
        [string]$response.signedInstaller.fileName -cne
            [string]$request.unsignedInstaller.fileName -or
        [string]$response.signedInstaller.peContentSha256 -cne
            [string]$request.unsignedInstaller.peContentSha256 -or
        [string]$response.signedInstaller.sha256 -ceq
            [string]$request.unsignedInstaller.sha256 -or
        [int64]$response.signedInstaller.sizeBytes -le
            [int64]$request.unsignedInstaller.sizeBytes -or
        -not [bool]$response.signedInstaller.fullHashChangedFromUnsigned) {
        throw 'Signed Installer does not preserve the exact r6 PE content while changing only the signable full-file identity.'
    }
    $selfCheck = $response.payloadSelfCheck
    if ([string]$selfCheck.inspectedInstallerSha256 -cne
            [string]$response.signedInstaller.sha256 -or
        [string]$selfCheck.candidateSetSha256 -cne
            [string]$closure.candidateSetSha256 -or
        [string]$selfCheck.payloadSetSha256 -cne
            [string]$closure.payloadSetSha256 -or
        [string]$selfCheck.r3SignedClientSetSha256 -cne
            [string]$closure.r3SignedClientSetSha256 -or
        [string]$selfCheck.releaseManifestTrustSha256 -cne
            [string]$closure.releaseManifestTrustSha256 -or
        [string]$selfCheck.releaseManifestTrustProbeSetSha256 -cne
            [string]$closure.releaseManifestTrustProbeSetSha256) {
        throw 'Signed Installer payload self-check does not replay the exact r6 closure.'
    }
    [void](Assert-InstallerSigningResponseAuthentication `
        -Response $response `
        -Request $request `
        -InstallerSigningTrust $InstallerSigningTrust)
    return $true
}

function Get-EmbeddedAuthenticodePrimaryEvidence {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    if ($Bytes.Length -lt 256 -or $Bytes[0] -ne 0x4d -or $Bytes[1] -ne 0x5a) {
        throw 'Signed Installer is not a bounded PE image.'
    }
    $peOffset = [BitConverter]::ToInt32($Bytes, 0x3c)
    if ($peOffset -lt 0x40 -or $peOffset -gt $Bytes.Length - 256 -or
        $Bytes[$peOffset] -ne 0x50 -or $Bytes[$peOffset + 1] -ne 0x45) {
        throw 'Signed Installer has an invalid PE header.'
    }
    $optionalOffset = $peOffset + 24
    $optionalSize = [BitConverter]::ToUInt16($Bytes, $peOffset + 20)
    $magic = [BitConverter]::ToUInt16($Bytes, $optionalOffset)
    $dataDirectoryOffset = if ($magic -eq 0x10b) {
        $optionalOffset + 96
    }
    elseif ($magic -eq 0x20b) {
        $optionalOffset + 112
    }
    else {
        throw 'Signed Installer has an unsupported PE optional header.'
    }
    $securityEntryOffset = $dataDirectoryOffset + 32
    if ($optionalSize -lt 128 -or
        $securityEntryOffset + 8 -gt $optionalOffset + $optionalSize) {
        throw 'Signed Installer has an invalid PE security directory.'
    }
    $certificateOffset = [int64][BitConverter]::ToUInt32($Bytes, $securityEntryOffset)
    $certificateSize = [int64][BitConverter]::ToUInt32($Bytes, $securityEntryOffset + 4)
    if ($certificateOffset -le 0 -or $certificateSize -lt 8 -or
        $certificateOffset + $certificateSize -gt $Bytes.LongLength) {
        throw 'Signed Installer has no bounded embedded certificate table.'
    }

    $cmsValues = [Collections.Generic.List[object]]::new()
    $cursor = $certificateOffset
    $end = $certificateOffset + $certificateSize
    while ($cursor -lt $end) {
        if ($end - $cursor -lt 8) {
            throw 'Signed Installer certificate table is truncated.'
        }
        $length = [int64][BitConverter]::ToUInt32($Bytes, [int]$cursor)
        $certificateType = [BitConverter]::ToUInt16($Bytes, [int]$cursor + 6)
        if ($length -lt 8 -or $cursor + $length -gt $end) {
            throw 'Signed Installer contains an invalid WIN_CERTIFICATE length.'
        }
        $alignedLength = [int64](([int64]$length + 7) -band (-bnot 7))
        if ($cursor + $alignedLength -gt $end) {
            throw 'Signed Installer WIN_CERTIFICATE alignment escapes the certificate table.'
        }
        if ($certificateType -eq 0x0002) {
            $cmsBytes = [byte[]]::new([int]$length - 8)
            [Array]::Copy($Bytes, [int]$cursor + 8, $cmsBytes, 0, $cmsBytes.Length)
            $cms = [Security.Cryptography.Pkcs.SignedCms]::new()
            try {
                $cms.Decode($cmsBytes)
                $cms.CheckSignature($true)
            }
            catch {
                throw 'Signed Installer primary Authenticode SignedCms is invalid.'
            }
            if ([string]$cms.ContentInfo.ContentType.Value -ceq
                $script:SpcIndirectDataOid) {
                $cmsValues.Add([pscustomobject]@{
                    Cms = $cms
                    Bytes = $cmsBytes
                })
            }
        }
        $cursor += $alignedLength
    }
    if ($cmsValues.Count -ne 1 -or $cmsValues[0].Cms.SignerInfos.Count -ne 1) {
        throw 'Signed Installer must contain one exact primary Authenticode SignedCms signer.'
    }
    $primary = $cmsValues[0].Cms.SignerInfos[0]
    if ($null -eq $primary.Certificate -or
        [string]$primary.DigestAlgorithm.Value -cne $script:Sha256Oid) {
        throw 'Signed Installer primary Authenticode signer must embed its certificate and use SHA-256.'
    }
    return [pscustomobject]@{
        Cms = $cmsValues[0].Cms
        CmsSha256 = Get-InstallerSigningSha256Bytes -Bytes $cmsValues[0].Bytes
        PrimarySigner = $primary
        SignerCertificateSha256 = Get-InstallerSigningSha256Bytes `
            -Bytes $primary.Certificate.RawData
        SignerDigestAlgorithmOid = [string]$primary.DigestAlgorithm.Value
    }
}

function Get-Rfc3161PrimarySignerTimestampUtc {
    param(
        [Parameter(Mandatory = $true)]
        [Security.Cryptography.Pkcs.SignerInfo]$PrimarySigner
    )

    $timestamps = [Collections.Generic.List[DateTimeOffset]]::new()
    [int]$rfc3161AttributeCount = 0
    [int]$rfc3161ValueCount = 0
    foreach ($attribute in $PrimarySigner.UnsignedAttributes) {
        if ([string]$attribute.Oid.Value -ceq
            $script:LegacyCounterSignatureOid) {
            throw 'Signed Installer primary signer contains a forbidden legacy counterSignature.'
        }
        if ([string]$attribute.Oid.Value -notin $script:Rfc3161AttributeOids) {
            continue
        }
        $rfc3161AttributeCount++
        foreach ($encodedValue in $attribute.Values) {
            $rfc3161ValueCount++
            $token = $null
            [int]$consumed = 0
            if (-not [Security.Cryptography.Pkcs.Rfc3161TimestampToken]::TryDecode(
                        [ReadOnlyMemory[byte]]::new($encodedValue.RawData),
                        [ref]$token,
                        [ref]$consumed) -or
                $null -eq $token -or
                $consumed -ne $encodedValue.RawData.Length) {
                throw 'Signed Installer primary signer contains a malformed RFC3161 attribute value.'
            }
            $timestampSigner = $null
            if (-not $token.VerifySignatureForSignerInfo(
                    $PrimarySigner,
                    [ref]$timestampSigner)) {
                throw 'Signed Installer primary signer contains an RFC3161 value that is not bound to that signer.'
            }
            $timestamps.Add($token.TokenInfo.Timestamp)
        }
    }
    if ($rfc3161AttributeCount -ne 1 -or
        $rfc3161ValueCount -ne 1 -or
        $timestamps.Count -ne 1) {
        throw 'Signed Installer must contain exactly one RFC3161 attribute with exactly one value bound to its primary signer.'
    }
    $value = $timestamps[0].ToUniversalTime()
    $wholeSecond = [DateTimeOffset]::new(
        $value.UtcTicks - ($value.UtcTicks % [TimeSpan]::TicksPerSecond),
        [TimeSpan]::Zero)
    return ProductionReleaseState\ConvertTo-ProductionUtc -Value $wholeSecond
}

function Get-ExactPeAuthenticodeEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9a-f]{64}$')]
        [string]$ExpectedSignerCertificateSha256,
        [ValidatePattern('^(?:|[0-9a-f]{64})$')]
        [string]$ExpectedPeContentSha256 = ''
    )

    $input = ProductionReleaseState\Open-ProductionReleaseInput `
        -Path $Path `
        -Label 'Signed PE Authenticode evidence input' `
        -MaximumBytes $script:MaximumInstallerBytes
    try {
        [byte[]]$bytes = ProductionReleaseState\Read-ProductionReleaseInputBytes `
            -Descriptor $input `
            -Label 'Signed PE Authenticode evidence input'
        $peContentSha256 =
            ProductionReleaseState\Get-PeContentSha256 -Bytes $bytes
        if (-not [string]::IsNullOrEmpty($ExpectedPeContentSha256) -and
            $peContentSha256 -cne $ExpectedPeContentSha256) {
            throw 'Signed PE content identity differs from the expected unsigned PE content.'
        }

        $authenticode = Microsoft.PowerShell.Security\Get-AuthenticodeSignature `
            -LiteralPath $input.Path
        [void](ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
            -Descriptor $input `
            -Label 'Signed PE Authenticode evidence input')
        if ([string]$authenticode.Status -cne 'Valid' -or
            $null -eq $authenticode.SignerCertificate -or
            $null -eq $authenticode.TimeStamperCertificate) {
            throw 'Signed PE does not have Windows Authenticode Status=Valid with signer and timestamper certificates.'
        }
        $signerSha256 = Get-InstallerSigningSha256Bytes `
            -Bytes $authenticode.SignerCertificate.RawData
        $timestampSignerSha256 = Get-InstallerSigningSha256Bytes `
            -Bytes $authenticode.TimeStamperCertificate.RawData
        if ($signerSha256 -cne $ExpectedSignerCertificateSha256) {
            throw 'Signed PE Authenticode signer differs from the pinned certificate.'
        }

        $primary = Get-EmbeddedAuthenticodePrimaryEvidence -Bytes $bytes
        if ([string]$primary.SignerCertificateSha256 -cne $signerSha256 -or
            [string]$primary.SignerDigestAlgorithmOid -cne $script:Sha256Oid) {
            throw 'Signed PE primary SignedCms signer is not the exact pinned SHA-256 Authenticode signer.'
        }

        # This parser enforces exactly one RFC3161 unsigned attribute containing
        # exactly one value and rejects every legacy counterSignature. Run it
        # before the shared token-binding verifier, which intentionally returns
        # the first valid token and therefore is not sufficient by itself.
        $timestampUtc = Get-Rfc3161PrimarySignerTimestampUtc `
            -PrimarySigner $primary.PrimarySigner
        $timestampBinding = ProductionReleaseState\Assert-PeRfc3161Timestamp `
            -Bytes $bytes `
            -SignerCertificate $authenticode.SignerCertificate `
            -TimeStamperCertificate $authenticode.TimeStamperCertificate
        if ([string]$timestampBinding.TimestampProtocol -cne 'RFC3161' -or
            [string]$timestampBinding.TimestampTokenOid -notin
                $script:Rfc3161AttributeOids -or
            [string]$timestampBinding.TimestampContentTypeOid -cne
                $script:Rfc3161ContentTypeOid -or
            [string]$timestampBinding.TimestampSignerSha256 -cne
                $timestampSignerSha256 -or
            [bool]$timestampBinding.LegacyCounterSignaturePresent) {
            throw 'Signed PE RFC3161 token is not exact evidence bound to its primary Authenticode signer.'
        }

        [void](ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
            -Descriptor $input `
            -Label 'Signed PE Authenticode evidence input')
        return [pscustomobject][ordered]@{
            FileName = [string]$input.FileName
            SizeBytes = [int64]$input.SizeBytes
            SignedFileSha256 = [string]$input.Sha256
            PeContentSha256 = [string]$peContentSha256
            AuthenticodeStatus = 'Valid'
            SignatureType = 'Authenticode'
            PrimarySignerCount = 1
            PrimarySignedCmsSha256 = [string]$primary.CmsSha256
            SignerCertificateSha256 = [string]$signerSha256
            SignerDigestAlgorithmOid = $script:Sha256Oid
            SpcIndirectDataContentTypeOid = $script:SpcIndirectDataOid
            SpcPeImageDataTypeOid = $script:SpcPeImageDataOid
            SpcDigestAlgorithmOid = $script:Sha256Oid
            SpcPeContentSha256 = [string]$peContentSha256
            TimestampProtocol = 'RFC3161'
            TimestampTokenOid = [string]$timestampBinding.TimestampTokenOid
            TimestampContentTypeOid = $script:Rfc3161ContentTypeOid
            TimestampSignerCertificateSha256 = [string]$timestampSignerSha256
            TimestampUtc = [string]$timestampUtc
            Rfc3161PrimarySignerBound = $true
            LegacyCounterSignaturePresent = $false
        }
    }
    finally {
        $input.Stream.Dispose()
    }
}

function Assert-SignedInstallerAuthenticode {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][psobject]$Response,
        [Parameter(Mandatory = $true)][string]$ExpectedSignerCertificateSha256
    )

    $evidence = Get-ExactPeAuthenticodeEvidence `
        -Path $Path `
        -ExpectedSignerCertificateSha256 $ExpectedSignerCertificateSha256 `
        -ExpectedPeContentSha256 ([string]$Response.unsignedInstaller.peContentSha256)
    if ([string]$evidence.FileName -cne
            [string]$Response.signedInstaller.fileName) {
        throw 'Signed Installer uses a noncanonical filename.'
    }
    if ([int64]$evidence.SizeBytes -ne
            [int64]$Response.signedInstaller.sizeBytes -or
        [string]$evidence.SignedFileSha256 -cne
            [string]$Response.signedInstaller.sha256 -or
        [string]$evidence.PeContentSha256 -cne
            [string]$Response.signedInstaller.peContentSha256 -or
        [string]$evidence.SignerCertificateSha256 -cne
            [string]$Response.authenticode.signerCertificateSha256 -or
        [string]$evidence.TimestampSignerCertificateSha256 -cne
            [string]$Response.authenticode.timestampSignerCertificateSha256 -or
        [string]$evidence.SignerDigestAlgorithmOid -cne
            [string]$Response.authenticode.signerDigestAlgorithmOid -or
        [string]$evidence.SpcIndirectDataContentTypeOid -cne
            [string]$Response.authenticode.spcIndirectDataContentTypeOid -or
        [string]$evidence.SpcPeImageDataTypeOid -cne
            [string]$Response.authenticode.spcPeImageDataTypeOid -or
        [string]$evidence.SpcDigestAlgorithmOid -cne
            [string]$Response.authenticode.spcDigestAlgorithmOid -or
        [string]$evidence.SpcPeContentSha256 -cne
            [string]$Response.authenticode.spcPeContentSha256 -or
        [string]$evidence.TimestampProtocol -cne
            [string]$Response.authenticode.timestampProtocol -or
        [string]$evidence.TimestampTokenOid -cne
            [string]$Response.authenticode.timestampTokenOid -or
        [string]$evidence.TimestampContentTypeOid -cne
            [string]$Response.authenticode.timestampContentTypeOid -or
        [string]$evidence.TimestampUtc -cne
            [string]$Response.authenticode.timestampUtc -or
        -not [bool]$Response.authenticode.rfc3161PrimarySignerBound) {
        throw 'Signed Installer full, PE-content, Authenticode, or RFC3161 evidence differs from the authenticated response and r6 request.'
    }
    return [pscustomobject]@{
        SignedInstallerSha256 = [string]$evidence.SignedFileSha256
        PeContentSha256 = [string]$evidence.PeContentSha256
        AuthenticodeStatus = [string]$evidence.AuthenticodeStatus
        PrimarySignedCmsSha256 = [string]$evidence.PrimarySignedCmsSha256
        SignerCertificateSha256 = [string]$evidence.SignerCertificateSha256
        TimestampSignerCertificateSha256 =
            [string]$evidence.TimestampSignerCertificateSha256
        TimestampUtc = [string]$evidence.TimestampUtc
    }
}

function Assert-InstallerSigningExactReplay {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$ExpectedResponseInput,
        [Parameter(Mandatory = $true)]$ReplayResponseInput,
        [Parameter(Mandatory = $true)][string]$ExpectedSignedInstallerPath,
        [Parameter(Mandatory = $true)][string]$ReplaySignedInstallerPath
    )

    if ([string]$ExpectedResponseInput.Sha256 -cne
            [string]$ReplayResponseInput.Sha256 -or
        [int64]$ExpectedResponseInput.Bytes.LongLength -ne
            [int64]$ReplayResponseInput.Bytes.LongLength) {
        throw 'Installer-signing response replay changed canonical response bytes.'
    }
    $expectedInput = ProductionReleaseState\Open-ProductionReleaseInput `
        -Path $ExpectedSignedInstallerPath `
        -Label 'Expected signed Installer replay input' `
        -MaximumBytes $script:MaximumInstallerBytes
    $replayInput = $null
    try {
        $replayInput = ProductionReleaseState\Open-ProductionReleaseInput `
            -Path $ReplaySignedInstallerPath `
            -Label 'Replay signed Installer input' `
            -MaximumBytes $script:MaximumInstallerBytes
        $signedDescriptor = $ExpectedResponseInput.Value.signedInstaller
        if ([string]$expectedInput.FileName -cne
                [string]$signedDescriptor.fileName -or
            [int64]$expectedInput.SizeBytes -ne
                [int64]$signedDescriptor.sizeBytes -or
            [string]$expectedInput.Sha256 -cne
                [string]$signedDescriptor.sha256 -or
            [int64]$expectedInput.SizeBytes -ne [int64]$replayInput.SizeBytes -or
            [string]$expectedInput.Sha256 -cne [string]$replayInput.Sha256) {
            throw 'Installer-signing response replay changed exact signed Installer bytes.'
        }
        [void](ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
            -Descriptor $expectedInput `
            -Label 'Expected signed Installer replay input')
        [void](ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
            -Descriptor $replayInput `
            -Label 'Replay signed Installer input')
        return $true
    }
    finally {
        if ($null -ne $replayInput) {
            $replayInput.Stream.Dispose()
        }
        $expectedInput.Stream.Dispose()
    }
}

function Assert-ProductionClientSigningHistory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][psobject]$Plan,
        [Parameter(Mandatory = $true)][psobject]$State
    )

    # This is deliberately opt-in: Get-ProductionReleaseState remains a
    # backwards-compatible structural replay.  The caller owns the state read
    # lock; every file opened here is additionally descriptor-locked.
    if ([int]$Plan.schemaVersion -ne 2 -or [string]$Plan.edition -cne 'Enterprise' -or
        [string]$Plan.targetChannel -cne 'stable' -or [int]$State.Head.revision -lt 3 -or
        @($State.Receipts).Count -lt 3) {
        throw 'Client signing history requires a committed Enterprise Stable r3 state.'
    }
    $r2 = $State.Receipts[1]; $r3 = $State.Receipts[2]
    if ([int]$r2.revision -ne 2 -or [string]$r2.phase -cne 'CLIENT_SIGNING_REQUESTED' -or
        [int]$r3.revision -ne 3 -or [string]$r3.phase -cne 'CLIENT_SIGNATURES_IMPORTED') {
        throw 'Client signing history requires exact r2 and r3 receipts.'
    }
    $schemaRoot = Join-Path $PSScriptRoot '..\schemas'
    $leases = [Collections.Generic.List[object]]::new()
    try {
        $openJson = {
            param([string]$Path, [string]$Label, [string]$Schema)
            $descriptor = ProductionReleaseState\Open-ProductionReleaseInput -Path $Path -Label $Label -MaximumBytes 64MB
            try {
                $bytes = ProductionReleaseState\Read-ProductionReleaseInputBytes -Descriptor $descriptor -Label $Label
                $value = ProductionReleaseState\ConvertFrom-StrictProductionJsonBytes -Bytes $bytes -Label $Label -SchemaPath $Schema
                $jsonInput = [pscustomobject]@{ Descriptor=$descriptor; Bytes=$bytes; Sha256=[string]$descriptor.Sha256; Value=$value }
                $leases.Add($descriptor); $descriptor = $null; return $jsonInput
            } finally { if ($null -ne $descriptor) { $descriptor.Stream.Dispose() } }
        }
        $root = [string]$State.StateRoot
        $request = & $openJson (Join-Path $root 'requests/client-signing.v1/signing-request.v1.json') 'Committed r2 client signing request' (Join-Path $schemaRoot 'launcher-external-signing-request-v1.schema.json')
        $response = & $openJson (Join-Path $root 'imports/client-signing.v1/signing-response.v1.json') 'Committed r3 client signing response' (Join-Path $schemaRoot 'launcher-external-signing-response-v1.schema.json')
        [void](ProductionReleaseState\Assert-CanonicalProductionJsonInput -Input $request -Label 'Committed r2 client signing request')
        # Original client imports retain raw response bytes, including legal
        # whitespace. Their receipt SHA binds those bytes; ES256 binds the
        # existing canonical authentication payload, not raw JSON formatting.
        $trust = $Plan.externalResponseTrusts.clientSigning
        $payloadType = 'ensou-dsh-launcher-external-signing-response-authentication-v2'
        if ([string]$request.Sha256 -cne [string]$r2.data.requestSha256 -or [string]$response.Sha256 -cne [string]$r3.data.responseSha256 -or
            [string]$request.Value.planSha256 -cne [string]$State.Identity.planSha256 -or [string]$request.Value.orchestrationId -cne [string]$State.Identity.orchestrationId -or
            [string]$request.Value.orchestrationId -cne [string]$Plan.orchestrationId -or
            [string]$request.Value.edition -cne [string]$Plan.edition -or [string]$request.Value.edition -cne [string]$State.Identity.edition -or
            [string]$request.Value.releaseSetId -cne [string]$Plan.releaseSetId -or
            [string]$response.Value.orchestrationId -cne [string]$request.Value.orchestrationId -or
            [string]$response.Value.edition -cne [string]$request.Value.edition -or
            [string]$response.Value.releaseSetId -cne [string]$request.Value.releaseSetId -or
            [string]$response.Value.planSha256 -cne [string]$request.Value.planSha256 -or
            [string]$response.Value.requestSha256 -cne [string]$request.Sha256 -or [string]$response.Value.requestNonce -cne [string]$request.Value.nonce) {
            throw 'Committed r2/r3 client-signing documents differ from their state receipt or identity.'
        }
        if ([string]$request.Value.responseAuthentication.algorithm -cne 'ES256' -or
            [string]$request.Value.responseAuthentication.keyId -cne [string]$trust.keyId -or
            [string]$request.Value.responseAuthentication.purpose -cne 'client-signing-response' -or
            [string]$trust.purpose -cne 'client-signing-response' -or
            [string]$request.Value.responseAuthentication.payloadType -cne $payloadType -or
            [string]$request.Value.authenticode.signerSha256Thumbprint -cne [string]$Plan.authenticodePolicy.signerSha256Thumbprint -or
            $request.Value.authenticode.requireTrustedTimestamp -ne $true -or
            $Plan.authenticodePolicy.requireTrustedTimestamp -ne $true -or
            [string]$r2.data.requestRelativePath -cne 'requests/client-signing.v1/signing-request.v1.json' -or
            [string]$r2.data.nonce -cne [string]$request.Value.nonce -or
            [string]$r2.data.createdAtUtc -cne [string]$request.Value.createdAtUtc -or
            [string]$r2.data.expiresAtUtc -cne [string]$request.Value.expiresAtUtc -or
            [string]$r3.data.responseRelativePath -cne 'imports/client-signing.v1/signing-response.v1.json' -or
            [string]$r3.data.completedAtUtc -cne [string]$response.Value.completedAtUtc -or
            [string]$r3.data.authenticationKeyId -cne [string]$trust.keyId -or
            [string]$r3.data.authenticationPurpose -cne 'client-signing-response' -or
            [string]$r3.data.authenticationPayloadType -cne $payloadType) {
            throw 'Committed r2/r3 client-signing policy or receipt binding differs from the plan.'
        }
        [void](ProductionReleaseState\Assert-ProductionReleaseSigningResponseAuthentication -Response $response.Value -Trust $trust)
        $created = ProductionReleaseState\ConvertFrom-ProductionUtc -Value ([string]$request.Value.createdAtUtc) -Label 'Committed r2 request creation time'
        $expires = ProductionReleaseState\ConvertFrom-ProductionUtc -Value ([string]$request.Value.expiresAtUtc) -Label 'Committed r2 request expiry time'
        $completed = ProductionReleaseState\ConvertFrom-ProductionUtc -Value ([string]$response.Value.completedAtUtc) -Label 'Committed r3 response completion time'
        $recorded = ProductionReleaseState\ConvertFrom-ProductionUtc -Value ([string]$r3.recordedAtUtc) -Label 'Committed r3 receipt time'
        # Replay the original import's freshness decision at receipt time. An old
        # successful import does not become stale merely because Status runs later.
        $maximumAgeMinutes = [int]$Plan.authenticodePolicy.maximumResponseAgeMinutes
        if ($maximumAgeMinutes -le 0 -or $expires -le $created -or $completed -lt $created -or
            $completed -gt $expires -or $completed -gt $recorded.AddMinutes(5) -or
            $completed -lt $recorded.AddMinutes(-$maximumAgeMinutes)) {
            throw 'Committed r3 response is stale, future-dated, or outside its original r2 lifetime.'
        }
        $expectedRoles = @('bootstrapper','launcher','client-bootstrapper','maintenance')
        $requestFiles = @($request.Value.files); $responseFiles = @($response.Value.files); $receiptFiles = @($r3.data.files)
        $plannedFiles = @($Plan.clientSigningInputs); $requestReceiptFiles = @($r2.data.files)
        if ($requestFiles.Count -ne 4 -or $responseFiles.Count -ne 4 -or $receiptFiles.Count -ne 4 -or
            $plannedFiles.Count -ne 4 -or $requestReceiptFiles.Count -ne 4) { throw 'Committed client signing inventory must contain exactly four files.' }
        for ($i=0; $i -lt 4; $i++) {
            $q=$requestFiles[$i]; $s=$responseFiles[$i]; $receipt=$receiptFiles[$i]
            $planned=$plannedFiles[$i]; $requestedReceipt=$requestReceiptFiles[$i]
            if ([string]$q.role -cne $expectedRoles[$i] -or [string]$s.role -cne $expectedRoles[$i] -or [string]$receipt.role -cne $expectedRoles[$i] -or
                [string]$planned.role -cne $expectedRoles[$i] -or [string]$requestedReceipt.role -cne $expectedRoles[$i] -or
                [string]$q.fileName -cne [string]$planned.fileName -or [string]$q.fileName -cne [string]$requestedReceipt.fileName -or
                [string]$q.relativePath -cne ('unsigned/' + [string]$planned.fileName) -or
                [int64]$q.sizeBytes -ne [int64]$planned.sizeBytes -or
                [string]$q.sha256 -cne [string]$planned.sha256 -or [string]$q.sha256 -cne [string]$requestedReceipt.sha256 -or
                [string]$q.peContentSha256 -cne [string]$planned.peContentSha256 -or [string]$q.peContentSha256 -cne [string]$requestedReceipt.peContentSha256 -or
                [string]$q.fileName -cne [string]$s.fileName -or [string]$q.fileName -cne [string]$receipt.fileName -or
                [string]$s.relativePath -cne ('signed/' + [string]$s.fileName) -or [string]$q.sha256 -cne [string]$s.inputSha256 -or
                [string]$q.peContentSha256 -cne [string]$s.inputPeContentSha256 -or
                [string]$q.peContentSha256 -cne [string]$s.signedPeContentSha256) { throw "Committed client-signing role index $i differs across plan/r2/r3." }
            $path = Join-Path $root ('imports/client-signing.v1/' + [string]$s.relativePath)
            $signedDescriptor = ProductionReleaseState\Open-ProductionReleaseInput -Path $path -Label "Committed r3 signed client role $($s.role)" -MaximumBytes 512MB
            $leases.Add($signedDescriptor)
            $evidence = Get-ExactPeAuthenticodeEvidence -Path $path -ExpectedSignerCertificateSha256 ([string]$Plan.authenticodePolicy.signerSha256Thumbprint) -ExpectedPeContentSha256 ([string]$q.peContentSha256)
            if ([string]$evidence.AuthenticodeStatus -cne 'Valid' -or
                [string]$evidence.TimestampProtocol -cne 'RFC3161' -or
                [int]$evidence.PrimarySignerCount -ne 1 -or
                [bool]$evidence.LegacyCounterSignaturePresent) {
                throw "Committed client-signing role index $i lacks exact Authenticode and RFC3161 evidence."
            }
            if ([int64]$signedDescriptor.SizeBytes -ne [int64]$s.sizeBytes -or [string]$signedDescriptor.Sha256 -cne [string]$s.sha256 -or
                [int64]$evidence.SizeBytes -ne [int64]$s.sizeBytes -or [string]$evidence.SignedFileSha256 -cne [string]$s.sha256 -or [string]$evidence.PeContentSha256 -cne [string]$s.signedPeContentSha256 -or
                [int64]$receipt.sizeBytes -ne [int64]$s.sizeBytes -or [string]$receipt.sha256 -cne [string]$s.sha256 -or [string]$receipt.peContentSha256 -cne [string]$s.signedPeContentSha256 -or
                [string]$receipt.timestampProtocol -cne 'RFC3161') { throw "Committed client-signing role index $i differs from locked bytes or r3 receipt." }
        }
        foreach ($lease in $leases) { [void](ProductionReleaseState\Assert-ProductionReleaseInputStillLocked -Descriptor $lease -Label 'Committed client-signing history input') }
        return [pscustomobject]@{ Status='CLIENT_SIGNING_HISTORY_REVALIDATED'; CurrentHeadSha256=[string]$State.HeadSha256; ResponseSha256=[string]$response.Sha256; VerifiedFileCount=4; RecordedAtUtc=[string]$r3.recordedAtUtc }
    } finally { for($i=$leases.Count-1;$i -ge 0;$i--){$leases[$i].Stream.Dispose()} }
}

Export-ModuleMember -Function @(
    'Assert-InstallerSigningExactReplay',
    'Assert-InstallerSigningRequestContract',
    'Assert-InstallerSigningResponseAuthentication',
    'Assert-InstallerSigningResponseContract',
    'Assert-SignedInstallerAuthenticode',
    'Assert-UnsignedInstallerSigningInput',
    'Get-ExactPeAuthenticodeEvidence',
    'Assert-ProductionClientSigningHistory',
    'Get-InstallerSigningObjectSha256',
    'Get-InstallerSigningResponseAuthenticationPayload',
    'Get-InstallerTargetBuildIdentitySha256',
    'Read-InstallerSigningContractInput'
)
