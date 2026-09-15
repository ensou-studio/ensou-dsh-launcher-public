#requires -Version 7.2

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = Join-Path $PSScriptRoot 'ProductionFeedPromotion.psm1'
$stateModulePath = Join-Path $PSScriptRoot 'ProductionReleaseState.psm1'
$schemaRoot = Join-Path $PSScriptRoot '..\schemas'
$requestSchemaPath = Join-Path $schemaRoot 'launcher-feed-promotion-request-v1.schema.json'
$responseSchemaPath = Join-Path $schemaRoot 'launcher-feed-promotion-response-v1.schema.json'
$planSchemaPath = Join-Path $schemaRoot 'launcher-production-release-plan-v2.schema.json'
$stateSchemaPath = Join-Path $schemaRoot 'launcher-production-release-state-v2.schema.json'
Import-Module $modulePath -Force -DisableNameChecking
Import-Module $stateModulePath -Force -DisableNameChecking

$utf8 = [Text.UTF8Encoding]::new($false, $true)
$assertions = 0

function Assert-True {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )

    $script:assertions++
    if (-not $Condition) {
        throw $Message
    }
}

function Assert-Fails {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Action,
        [Parameter(Mandatory = $true)][string]$Expected,
        [Parameter(Mandatory = $true)][string]$Message
    )

    $script:assertions++
    try {
        & $Action
    }
    catch {
        if ($_.Exception.Message.IndexOf(
                $Expected,
                [StringComparison]::OrdinalIgnoreCase) -lt 0) {
            throw "$Message Unexpected error: $($_.Exception.Message)"
        }
        return
    }
    throw $Message
}

function Write-CanonicalJson {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Value
    )

    $parent = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($Path))
    [IO.Directory]::CreateDirectory($parent) | Out-Null
    [IO.File]::WriteAllBytes($Path, (ConvertTo-ProductionJsonBytes -Value $Value))
}

function Get-Sha256 {
    param([Parameter(Mandatory = $true)][string]$Path)

    return ([Convert]::ToHexString(
            [Security.Cryptography.SHA256]::HashData(
                [IO.File]::ReadAllBytes($Path)))).ToLowerInvariant()
}

function ConvertTo-TestBase64Url {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    return [Convert]::ToBase64String($Bytes).
        TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function New-TestTrust {
    param(
        [Parameter(Mandatory = $true)][Security.Cryptography.ECDsa]$Signer,
        [Parameter(Mandatory = $true)][string]$KeyId,
        [Parameter(Mandatory = $true)][string]$Purpose
    )

    $public = $Signer.ExportParameters($false)
    return [ordered]@{
        algorithm = 'ES256'
        keyId = $KeyId
        purpose = $Purpose
        x = ConvertTo-TestBase64Url -Bytes $public.Q.X
        y = ConvertTo-TestBase64Url -Bytes $public.Q.Y
    }
}

function New-TestLowSP256Signature {
    param(
        [Parameter(Mandatory = $true)][Security.Cryptography.ECDsa]$Signer,
        [Parameter(Mandatory = $true)][byte[]]$Payload
    )

    foreach ($attempt in 1..128) {
        $signature = $Signer.SignData(
            $Payload,
            [Security.Cryptography.HashAlgorithmName]::SHA256,
            [Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)
        try {
            Assert-ProductionEs256P1363LowS `
                -Signature $signature `
                -Label 'Test feed-promotion response signature'
            return ,$signature
        }
        catch {
            # P-256 signing is randomized; retry until the canonical low-S half
            # of the signature space is selected.
        }
    }
    throw 'Test signer did not produce one canonical low-S P-256 signature.'
}

function New-CompletedPromotionBundleFixture {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][Security.Cryptography.ECDsa]$Signer,
        [Parameter(Mandatory = $true)]$FeedModule,
        [ValidateSet('Enterprise', 'Personal')][string]$Edition = 'Enterprise',
        [ValidateSet('pilot', 'stable')][string]$ExposureRing = 'pilot'
    )

    $promotionRoot = Join-Path $Root 'promotion'
    $bundleRoot = Join-Path $promotionRoot 'bundle'
    $payloadRoot = Join-Path $bundleRoot 'payload'
    [IO.Directory]::CreateDirectory($payloadRoot) | Out-Null
    $definitions = @(
        [ordered]@{
            role = 'release-manifest'
            fileName = 'release-set.v2.json'
            bytes = $utf8.GetBytes('{"fixture":"manifest"}')
        },
        [ordered]@{
            role = 'release-public-key'
            fileName = 'release-public-key.v2.json'
            bytes = $utf8.GetBytes('{"fixture":"release-key"}')
        },
        [ordered]@{
            role = 'launcher'
            fileName = 'launcher.zip'
            bytes = $utf8.GetBytes('locked-launcher-payload')
        },
        [ordered]@{
            role = 'runtime'
            fileName = 'runtime.zip'
            bytes = $utf8.GetBytes('locked-runtime-payload')
        },
        [ordered]@{
            role = 'plugin-policy'
            fileName = 'plugin-policy.json'
            bytes = $utf8.GetBytes('{"fixture":"plugin-policy"}')
        })
    if ($Edition -ceq 'Personal') {
        $definitions = @($definitions | Where-Object {
            $_.role -cin @('release-manifest', 'launcher', 'runtime')
        })
    }
    $channel = if ($Edition -ceq 'Personal') { $ExposureRing } else { 'stable' }
    $scope = if ($Edition -ceq 'Personal') { 'channel-head' }
        elseif ($ExposureRing -ceq 'pilot') { 'private-pilot-allowlist' }
        else { 'public-stable' }
    $files = [Collections.Generic.List[object]]::new()
    foreach ($definition in $definitions) {
        $path = Join-Path $payloadRoot ([string]$definition.fileName)
        [IO.File]::WriteAllBytes($path, [byte[]]$definition.bytes)
        $item = Get-Item -LiteralPath $path
        $files.Add([ordered]@{
            role = [string]$definition.role
            fileName = [string]$definition.fileName
            relativePath = 'payload/' + [string]$definition.fileName
            sizeBytes = [int64]$item.Length
            sha256 = Get-Sha256 -Path $path
        })
    }
    $payloadSetSha256 = & $FeedModule {
        param($Files)
        Get-FeedPromotionDomainDigest `
            -Domain 'ensou-dsh-launcher-feed-promotion-payload-set-v1' `
            -Value $Files
    } @($files)
    $feedCas = [ordered]@{
        channelHead = [ordered]@{ state = 'missing' }
        journalHead = [ordered]@{ state = 'missing' }
    }
    $feedCasSha256 = & $FeedModule {
        param($Value)
        Get-FeedPromotionDomainDigest `
            -Domain 'ensou-dsh-launcher-feed-promotion-cas-v1' `
            -Value $Value
    } $feedCas
    $sourceHeadSha256 = 'a' * 64
    $request = [ordered]@{
        schemaVersion = 1
        requestType = 'ensou-dsh-launcher-offline-feed-promotion-request'
        operationId = [Guid]::NewGuid().ToString('N')
        orchestrationId = [Guid]::NewGuid().ToString()
        edition = $Edition
        exposureRing = $ExposureRing
        feedChannel = $channel
        publishScope = $scope
        releaseSetId = 'managed-v2026.09.05.1'
        sourceState = [ordered]@{
            schemaVersion = 2
            targetChannel = $channel
            revision = $(if ($ExposureRing -ceq 'pilot') { 7 } else { 8 })
            phase = $(if ($ExposureRing -ceq 'pilot') { 'INSTALLER_SIGNATURE_IMPORTED' } else { 'PILOT_EVIDENCE_BOUND' })
            planSizeBytes = 101
            planSha256 = '1' * 64
            identitySizeBytes = 102
            identitySha256 = '2' * 64
            headSizeBytes = 103
            headSha256 = $sourceHeadSha256
            receiptChainStartRevision = 1
            receiptChainSha256 = '3' * 64
            candidateReceiptSha256 = '4' * 64
        }
        expectedFeedIdentitySha256 = '5' * 64
        feedCas = $feedCas
        feedCasSha256 = $feedCasSha256
        payloadSetSha256 = $payloadSetSha256
        files = @($files)
        authorizationTrust = New-TestTrust `
            -Signer $Signer `
            -KeyId 'bundle-admission-test' `
            -Purpose 'feed-promotion-response'
        requestNonce = ConvertTo-TestBase64Url -Bytes ([byte[]](1..32))
        createdAtUtc = '2026-09-05T01:00:00Z'
        expiresAtUtc = '2026-09-05T01:30:00Z'
        productionAdmission = 'NO_GO'
        networkPublishPerformed = $false
    }
    $requestPath = Join-Path $bundleRoot 'request.v1.json'
    Write-CanonicalJson -Path $requestPath -Value $request
    $requestSha256 = Get-Sha256 -Path $requestPath
    $promotionHead = [ordered]@{
        schemaVersion = 1
        stateType = 'ensou-dsh-launcher-offline-feed-promotion-state'
        operationId = [string]$request.operationId
        requestSha256 = $requestSha256
        requestNonce = [string]$request.requestNonce
        sourceStateHeadSha256 = $sourceHeadSha256
        payloadSetSha256 = $payloadSetSha256
        status = 'PROMOTION_REQUEST_READY'
        productionAdmission = 'NO_GO'
        networkPublishPerformed = $false
        updatedAtUtc = [string]$request.createdAtUtc
    }
    $promotionHeadPath = Join-Path $promotionRoot 'head.json'
    Write-CanonicalJson -Path $promotionHeadPath -Value $promotionHead
    $promotionHeadSha256 = Get-Sha256 -Path $promotionHeadPath
    $response = [ordered]@{
        schemaVersion = 1
        responseType = 'ensou-dsh-launcher-offline-feed-promotion-response'
        operationId = [string]$request.operationId
        orchestrationId = [string]$request.orchestrationId
        edition = $Edition
        exposureRing = $ExposureRing
        feedChannel = $channel
        publishScope = $scope
        releaseSetId = [string]$request.releaseSetId
        requestSha256 = $requestSha256
        requestNonce = [string]$request.requestNonce
        basePromotionHeadSha256 = $promotionHeadSha256
        sourceStateHeadSha256 = $sourceHeadSha256
        payloadSetSha256 = $payloadSetSha256
        feedCasSha256 = $feedCasSha256
        decision = 'AUTHORIZE_OFFLINE_BUNDLE'
        completedAtUtc = '2026-09-05T01:15:00Z'
        requestExpiresAtUtc = [string]$request.expiresAtUtc
        productionAdmission = 'OFFLINE_BUNDLE_ONLY'
        networkPublishPerformed = $false
        authentication = [ordered]@{
            algorithm = 'ES256'
            keyId = 'bundle-admission-test'
            purpose = 'feed-promotion-response'
            payloadType =
                'ensou-dsh-launcher-feed-promotion-response-authentication-v1'
        }
    }
    $authenticationPayload =
        Get-ProductionFeedPromotionResponseAuthenticationPayload `
            -Response ([pscustomobject]$response)
    $response.authentication.value = ConvertTo-TestBase64Url `
        -Bytes (New-TestLowSP256Signature `
            -Signer $Signer `
            -Payload $authenticationPayload)
    $responsePath = Join-Path $bundleRoot 'response.v1.json'
    Write-CanonicalJson -Path $responsePath -Value $response
    $responseSha256 = Get-Sha256 -Path $responsePath
    $bundleSetSha256 = & $FeedModule {
        param($RequestSha256, $RequestSize, $ResponseSha256, $ResponseSize, $Files)
        Get-FeedPromotionBundleSetSha256 `
            -RequestSha256 $RequestSha256 `
            -RequestSizeBytes $RequestSize `
            -ResponseSha256 $ResponseSha256 `
            -ResponseSizeBytes $ResponseSize `
            -Files $Files
    } $requestSha256 `
        ([int64](Get-Item -LiteralPath $requestPath).Length) `
        $responseSha256 `
        ([int64](Get-Item -LiteralPath $responsePath).Length) `
        @($files)
    $bundleHead = [ordered]@{
        schemaVersion = 1
        stateType = 'ensou-dsh-launcher-offline-feed-promotion-bundle'
        operationId = [string]$request.operationId
        requestSha256 = $requestSha256
        requestNonce = [string]$request.requestNonce
        sourceStateHeadSha256 = $sourceHeadSha256
        payloadSetSha256 = $payloadSetSha256
        basePromotionHeadSha256 = $promotionHeadSha256
        responseSha256 = $responseSha256
        bundleSetSha256 = $bundleSetSha256
        status = 'EXTERNAL_PUBLISH_BUNDLE_READY'
        productionAdmission = 'NO_GO'
        networkPublishPerformed = $false
        updatedAtUtc = [string]$response.completedAtUtc
    }
    $bundleHeadPath = Join-Path $bundleRoot 'head.v1.json'
    Write-CanonicalJson -Path $bundleHeadPath -Value $bundleHead
    return [pscustomobject]@{
        PromotionRoot = $promotionRoot
        RequestPath = $requestPath
        ResponsePath = $responsePath
        PromotionHeadPath = $promotionHeadPath
        BundleHeadPath = $bundleHeadPath
        PayloadPath = Join-Path $payloadRoot ([string]$files[0].fileName)
        RequestSha256 = $requestSha256
        ResponseSha256 = $responseSha256
        PromotionHeadSha256 = $promotionHeadSha256
        BundleHeadSha256 = Get-Sha256 -Path $bundleHeadPath
        SourceHeadSha256 = $sourceHeadSha256
        BundleSetSha256 = $bundleSetSha256
    }
}

function New-AnchoredSourceFixture {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][ValidateSet('Personal', 'Enterprise')]
        [string]$Edition,
        [Parameter(Mandatory = $true)][Security.Cryptography.ECDsa[]]$Signers
    )

    $stateRoot = Join-Path $Root 'state'
    $candidateRoot = Join-Path $Root 'candidate'
    [IO.Directory]::CreateDirectory($Root) | Out-Null
    [IO.Directory]::CreateDirectory($candidateRoot) | Out-Null
    $targetChannel = if ($Edition -ceq 'Enterprise') { 'stable' } else { 'pilot' }
    $inputs = [Collections.Generic.List[object]]::new()
    foreach ($index in 1..4) {
        $inputs.Add([ordered]@{
            role = "fixture-$index"
            fileName = "Fixture$index.exe"
            path = "C:\fixture\Fixture$index.exe"
            sizeBytes = 1024
            sha256 = ([string]$index) * 64
            peContentSha256 = ([string](4 + $index)) * 64
        })
    }
    $plan = [ordered]@{
        schemaVersion = 2
        planType = 'ensou-dsh-launcher-production-release'
        orchestrationId = [Guid]::NewGuid().ToString()
        edition = $Edition
        releaseSetId = if ($Edition -ceq 'Enterprise') {
            'managed-v2026.09.03.1'
        }
        else {
            'personal-v2026.09.03.1'
        }
        targetChannel = $targetChannel
        sourceCommit = '1' * 40
        manifestUri = "https://updates.example.invalid/v2/channels/$targetChannel/release-set.v2.json"
        artifactBaseUri = 'https://artifacts.example.invalid/releases/'
        runtimeCandidate = [ordered]@{
            releaseId = 'runtime-v2026.09.03.1'
            githubReleaseTag = 'runtime-v2026.09.03.1'
            archive = [ordered]@{
                fileName = 'runtime.zip'
                path = 'C:\fixture\runtime.zip'
                sizeBytes = 1
                sha256 = 'a' * 64
            }
            metadata = [ordered]@{
                fileName = 'runtime-metadata.json'
                path = 'C:\fixture\runtime-metadata.json'
                sizeBytes = 1
                sha256 = 'b' * 64
            }
            hashEvidence = [ordered]@{
                fileName = 'runtime-hashes.json'
                path = 'C:\fixture\runtime-hashes.json'
                sizeBytes = 1
                sha256 = 'c' * 64
            }
        }
        authenticodePolicy = [ordered]@{
            signerSha256Thumbprint = 'd' * 64
            requireTrustedTimestamp = $true
            maximumResponseAgeMinutes = 60
        }
        releaseManifestTrust = New-TestTrust `
            -Signer $Signers[0] `
            -KeyId 'release-manifest-test' `
            -Purpose 'release-manifest-signing'
        releaseCompatibility = if ($Edition -ceq 'Enterprise') {
            [ordered]@{ startupStubProtocol = 1 }
        }
        else {
            [ordered]@{
                startupStubVersion = '1.2.0'
                canonicalLowSFromSequence = 1
            }
        }
        externalResponseTrusts = [ordered]@{
            clientSigning = New-TestTrust `
                -Signer $Signers[1] `
                -KeyId 'client-signing-test' `
                -Purpose 'client-signing-response'
            manifestPublishing = New-TestTrust `
                -Signer $Signers[2] `
                -KeyId 'manifest-publishing-test' `
                -Purpose 'manifest-publishing-response'
            installerSigning = New-TestTrust `
                -Signer $Signers[3] `
                -KeyId 'installer-signing-test' `
                -Purpose $(if ($Edition -ceq 'Personal') {
                    'personal-installer-signing-response'
                } else {
                    'installer-signing-response'
                })
            feedPromotion = New-TestTrust `
                -Signer $Signers[4] `
                -KeyId 'feed-promotion-test' `
                -Purpose 'feed-promotion-response'
        }
        clientSigningInputs = @($inputs)
    }
    if ($Edition -ceq 'Enterprise') {
        $plan.pilotEvidenceTrustPolicySha256 = 'e' * 64
    }
    else {
        $plan.personalAccountOrigin = 'https://accounts.example.invalid/'
        $sharedChecks = @(
            'startup-update-detection',
            'runtime-only-update',
            'launcher-only-update',
            'failed-update-rollback',
            'offline-last-known-good',
            'local-chat-and-workspace-unchanged',
            'no-command-window')
        $plan.personalPilotDevices = @(
            [ordered]@{
                deviceId = 'pilot-desktop-desktop'
                hostLabel = 'PILOT-DESKTOP'
                architecture = 'win-x64'
                lane = 'existing-install-upgrade'
                installationIdentity = 'separate-device-identity'
                tokenOrSecretIncluded = $false
                roleAcceptance = 'existing-version-upgrade'
                perDeviceAcceptance = @($sharedChecks)
            },
            [ordered]@{
                deviceId = 'pilot-notebook'
                hostLabel = 'PilotNotebook notebook'
                architecture = 'win-x64'
                lane = 'clean-first-install'
                installationIdentity = 'separate-device-identity'
                tokenOrSecretIncluded = $false
                roleAcceptance = 'first-install'
                perDeviceAcceptance = @($sharedChecks)
            })
    }
    $planBytes = ConvertTo-ProductionJsonBytes -Value $plan
    Assert-True `
        (Test-Json `
            -Json $utf8.GetString($planBytes) `
            -SchemaFile $planSchemaPath `
            -ErrorAction Stop) `
        "$Edition anchored plan fixture is invalid."

    if ($Edition -ceq 'Enterprise') {
        $lock = Enter-ProductionReleaseStateLock `
            -StateRoot $stateRoot `
            -PlanBytes $planBytes `
            -Plan ([pscustomobject]$plan)
        try {
            [void](Initialize-ProductionReleaseState `
                -Lock $lock `
                -PlanBytes $planBytes `
                -Plan ([pscustomobject]$plan) `
                -StateSchemaPath $stateSchemaPath)
        }
        finally {
            $lock.Stream.Dispose()
        }
    }
    else {
        [IO.Directory]::CreateDirectory($stateRoot) | Out-Null
        [IO.File]::WriteAllBytes(
            (Join-Path $stateRoot 'state.lock'),
            [byte[]]::new(0))
        Write-CanonicalJson -Path (Join-Path $stateRoot 'plan.json') -Value $plan
    }
    $planPath = Join-Path $stateRoot 'plan.json'
    $planSha256 = Get-Sha256 -Path $planPath
    $identityPath = Join-Path $stateRoot 'identity.json'
    if ($Edition -ceq 'Personal') {
        Write-CanonicalJson -Path $identityPath -Value ([ordered]@{
            schemaVersion = 2
            identityType = 'ensou-dsh-launcher-production-release-state'
            orchestrationId = [string]$plan.orchestrationId
            edition = 'Personal'
            planSha256 = $planSha256
            initializationSha256 = 'e' * 64
            createdAtUtc = '2026-09-03T00:00:00Z'
            targetChannel = 'pilot'
        })
    }
    $identitySha256 = Get-Sha256 -Path $identityPath
    $headPath = Join-Path $stateRoot 'head.json'
    Write-CanonicalJson -Path $headPath -Value ([ordered]@{
        schemaVersion = 2
        stateType = 'ensou-dsh-launcher-production-release-head'
        orchestrationId = [string]$plan.orchestrationId
        edition = $Edition
        planSha256 = $planSha256
        identitySha256 = $identitySha256
        revision = 7
        phase = 'INSTALLER_SIGNATURE_IMPORTED'
        receiptFileName = '0007-installer-signature-imported.json'
        receiptSha256 = '7' * 64
        updatedAtUtc = '2026-09-03T00:33:00Z'
        targetChannel = $targetChannel
    })
    return [pscustomobject]@{
        StateRoot = $stateRoot
        CandidateRoot = $candidateRoot
        PlanPath = $planPath
        IdentityPath = $identityPath
        HeadPath = $headPath
        PlanSha256 = $planSha256
        IdentitySha256 = $identitySha256
        HeadSha256 = Get-Sha256 -Path $headPath
        Plan = [pscustomobject]$plan
    }
}

function Write-R5ToR7OnlyAttackReceipt {
    param(
        [Parameter(Mandatory = $true)]$Fixture,
        [Parameter(Mandatory = $true)]$FeedModule,
        [Parameter(Mandatory = $true)][int]$Revision,
        [Parameter(Mandatory = $true)][string]$Phase,
        [Parameter(Mandatory = $true)][string]$PreviousReceiptSha256,
        [Parameter(Mandatory = $true)]$Data,
        [Parameter(Mandatory = $true)][string]$RecordedAtUtc
    )

    $receipt = [ordered]@{
        schemaVersion = 2
        receiptType = 'ensou-dsh-launcher-production-release-transition'
        orchestrationId = [string]$Fixture.Plan.orchestrationId
        edition = 'Enterprise'
        targetChannel = 'stable'
        planSha256 = [string]$Fixture.PlanSha256
        identitySha256 = [string]$Fixture.IdentitySha256
        revision = $Revision
        phase = $Phase
        previousReceiptSha256 = $PreviousReceiptSha256
        transitionSha256 = '0' * 64
        data = $Data
        recordedAtUtc = $RecordedAtUtc
    }
    $receipt.transitionSha256 = & $FeedModule {
        param($Value)
        Get-FeedPromotionSourceTransitionSha256 `
            -Receipt ([pscustomobject]$Value) `
            -TargetChannel stable
    } $receipt
    $fileName = $Revision.ToString('0000') + '-' +
        $Phase.ToLowerInvariant().Replace('_', '-') + '.json'
    $path = Join-Path (Join-Path $Fixture.StateRoot 'receipts') $fileName
    Write-CanonicalJson -Path $path -Value $receipt
    Assert-True `
        (Test-Json `
            -Json ([IO.File]::ReadAllText($path, $utf8)) `
            -SchemaFile $stateSchemaPath `
            -ErrorAction Stop) `
        "r5-r7-only attack receipt $Revision is not schema-valid."
    return [pscustomobject]@{
        FileName = $fileName
        Path = $path
        Sha256 = Get-Sha256 -Path $path
        Value = [pscustomobject]$receipt
    }
}

function Add-R5ToR7OnlyAttackChain {
    param(
        [Parameter(Mandatory = $true)]$Fixture,
        [Parameter(Mandatory = $true)]$FeedModule
    )

    $hash = {
        param([Parameter(Mandatory = $true)][string]$Label)
        return Get-ProductionSha256Bytes -Bytes $utf8.GetBytes($Label)
    }
    $candidateDefinitions = @(
        [ordered]@{
            role = 'release-public-key'
            fileName = 'release-public-key.v2.json'
            bytes = $utf8.GetBytes('{"fixture":"release-public-key"}')
        },
        [ordered]@{
            role = 'launcher'
            fileName = 'launcher.zip'
            bytes = $utf8.GetBytes('fixture-launcher')
        },
        [ordered]@{
            role = 'runtime'
            fileName = 'runtime.zip'
            bytes = $utf8.GetBytes('fixture-runtime')
        },
        [ordered]@{
            role = 'plugin-policy'
            fileName = 'plugin-policy.json'
            bytes = $utf8.GetBytes('{"fixture":"plugin-policy"}')
        })
    $candidateByRole = [ordered]@{}
    foreach ($definition in $candidateDefinitions) {
        $path = Join-Path $Fixture.CandidateRoot ([string]$definition.fileName)
        [IO.File]::WriteAllBytes($path, [byte[]]$definition.bytes)
        $item = Get-Item -LiteralPath $path
        $candidateByRole[[string]$definition.role] = [ordered]@{
            role = [string]$definition.role
            fileName = [string]$definition.fileName
            relativePath = 'candidate/' + [string]$definition.fileName
            sizeBytes = [int64]$item.Length
            sha256 = Get-Sha256 -Path $path
        }
    }
    $manifestArtifacts = [Collections.Generic.List[object]]::new()
    foreach ($role in @('launcher', 'runtime', 'plugin-policy')) {
        $file = $candidateByRole[$role]
        $manifestArtifacts.Add([ordered]@{
            component = $role
            releaseId = "$role-v2026.09.03.1"
            uri = 'https://artifacts.example.invalid/releases/' +
                [string]$file.fileName
            sizeBytes = [int64]$file.sizeBytes
            sha256 = [string]$file.sha256
            completeTreeSha256 = & $hash "$role-complete-tree"
            signature = [ordered]@{
                algorithm = 'ES256'
                keyId = 'artifact-fixture'
                value = 'A' * 86
            }
        })
    }
    $manifestPath = Join-Path $Fixture.CandidateRoot 'release-set.v2.json'
    Write-CanonicalJson -Path $manifestPath -Value ([ordered]@{
        schemaVersion = 2
        product = 'ensou-dsh-enterprise'
        environment = 'production'
        channel = 'stable'
        releaseSetId = [string]$Fixture.Plan.releaseSetId
        generation = 1
        sequence = 1
        minAcceptedSequence = 1
        issuedAtUtc = '2026-09-03T00:00:00Z'
        expiresAtUtc = '2026-09-04T00:00:00Z'
        startupStub = [ordered]@{ protocol = 1 }
        revokedReleaseSetIds = @()
        artifacts = @($manifestArtifacts)
        signature = [ordered]@{
            algorithm = 'ES256'
            keyId = [string]$Fixture.Plan.releaseManifestTrust.keyId
            value = 'A' * 86
        }
    })
    $manifestItem = Get-Item -LiteralPath $manifestPath
    $manifestFile = [ordered]@{
        role = 'release-manifest'
        fileName = 'release-set.v2.json'
        relativePath = 'candidate/release-set.v2.json'
        sizeBytes = [int64]$manifestItem.Length
        sha256 = Get-Sha256 -Path $manifestPath
    }
    $candidateFiles = @(
        $manifestFile,
        $candidateByRole['release-public-key'],
        $candidateByRole['launcher'],
        $candidateByRole['runtime'],
        $candidateByRole['plugin-policy'])
    $manifestBytes = [IO.File]::ReadAllBytes($manifestPath)
    $manifestValue = ConvertFrom-StrictProductionJsonBytes `
        -Bytes $manifestBytes `
        -Label 'r5-r7-only attack manifest'
    & $FeedModule {
        param($Plan, $ManifestValue, $ManifestBytes, $ManifestSha256, $Files)
        Assert-FeedPromotionCandidateManifest `
            -Plan $Plan `
            -ManifestInput ([pscustomobject]@{
                Value = $ManifestValue
                Bytes = $ManifestBytes
                Sha256 = $ManifestSha256
            }) `
            -Files $Files
    } $Fixture.Plan $manifestValue $manifestBytes $manifestFile.sha256 $candidateFiles
    Assert-True $true `
        'r5-r7-only attack candidate did not satisfy the former local candidate gate.'

    $r5 = Write-R5ToR7OnlyAttackReceipt `
        -Fixture $Fixture `
        -FeedModule $FeedModule `
        -Revision 5 `
        -Phase STABLE_SIGNED_CANDIDATE_IMPORTED `
        -PreviousReceiptSha256 ('0' * 64) `
        -RecordedAtUtc '2026-09-03T00:25:00Z' `
        -Data ([ordered]@{
            responseRelativePath =
                'imports/stable-signed-candidate.v1/manifest-publishing-response.v1.json'
            responseSha256 = & $hash 'r5-response'
            requestSha256 = & $hash 'r5-request'
            requestNonce = 'A' * 43
            baseHeadSha256 = & $hash 'r5-base-head'
            admissionHeadSha256 = & $hash 'r5-admission-head'
            admissionRevision = 4
            requestExpiresAtUtc = '2026-09-03T01:00:00Z'
            completedAtUtc = '2026-09-03T00:24:00Z'
            authenticationKeyId =
                [string]$Fixture.Plan.externalResponseTrusts.manifestPublishing.keyId
            authenticationPurpose = 'manifest-publishing-response'
            authenticationPayloadType =
                'ensou-dsh-launcher-manifest-publishing-response-authentication-v1'
            manifestRelativePath =
                'imports/stable-signed-candidate.v1/candidate/release-set.v2.json'
            manifestSha256 = [string]$manifestFile.sha256
            releaseManifestTrustSha256 = & $hash 'release-manifest-trust'
            releaseCompatibilitySha256 = & $hash 'release-compatibility'
            componentReleaseIdsSha256 = & $hash 'component-release-ids'
            runtimeProvenanceSha256 = & $hash 'runtime-provenance'
            compiledReleaseTrustStatus = 'VERIFIED'
            productionAdmission = 'NO_GO'
            files = $candidateFiles
        })

    $unsignedInstaller = [ordered]@{
        fileName = 'Ensou.Dsh.Enterprise.Installer.exe'
        relativePath =
            'requests/installer-signing.v2/unsigned/Ensou.Dsh.Enterprise.Installer.exe'
        sizeBytes = 1024
        sha256 = & $hash 'unsigned-installer'
        peContentSha256 = & $hash 'installer-pe-content'
    }
    $r6 = Write-R5ToR7OnlyAttackReceipt `
        -Fixture $Fixture `
        -FeedModule $FeedModule `
        -Revision 6 `
        -Phase INSTALLER_SIGNING_REQUESTED `
        -PreviousReceiptSha256 ([string]$r5.Sha256) `
        -RecordedAtUtc '2026-09-03T00:30:00Z' `
        -Data ([ordered]@{
            evidenceType = 'INSTALLER_SIGNING_REQUESTED'
            requestSchemaVersion = 2
            requestRelativePath =
                'requests/installer-signing.v2/installer-signing-request.v2.json'
            requestSha256 = & $hash 'installer-request'
            baseHeadSha256 = & $hash 'r6-base-head'
            baseReceiptSha256 = [string]$r5.Sha256
            sourceBuildInputSetSha256 = & $hash 'source-build-input-set'
            targetBuildIdentitySha256 = & $hash 'target-build-identity'
            payloadSetSha256 = & $hash 'installer-payload-set'
            r5LauncherSha256 = [string]$candidateByRole['launcher'].sha256
            r5RuntimeSha256 = [string]$candidateByRole['runtime'].sha256
            trustedBuildEvidenceRelativePath =
                'requests/installer-signing.v2/trusted-build/trusted-build-evidence.v1.json'
            trustedBuildEvidenceSha256 = & $hash 'trusted-build-evidence'
            resourceBindingSha256 = & $hash 'resource-binding'
            sdkFileClosureStatus = 'VERIFIED'
            signingRequestEligibilityStatus = 'ELIGIBLE_FOR_PILOT_SIGNING'
            unsignedInstaller = $unsignedInstaller
            createdAtUtc = '2026-09-03T00:29:00Z'
            expiresAtUtc = '2026-09-03T01:29:00Z'
            authenticationKeyId =
                [string]$Fixture.Plan.externalResponseTrusts.installerSigning.keyId
            authenticationPurpose = 'installer-signing-response'
            admissionReason = 'INSTALLER_SIGNING_RESPONSE_REQUIRED'
            productionAdmission = 'NO_GO'
        })

    $signedInstaller = [ordered]@{
        fileName = 'Ensou.Dsh.Enterprise.Installer.exe'
        relativePath =
            'imports/installer-signing.v1/signed/Ensou.Dsh.Enterprise.Installer.exe'
        sizeBytes = 1024
        sha256 = & $hash 'signed-installer'
        peContentSha256 = [string]$unsignedInstaller.peContentSha256
    }
    $r7 = Write-R5ToR7OnlyAttackReceipt `
        -Fixture $Fixture `
        -FeedModule $FeedModule `
        -Revision 7 `
        -Phase INSTALLER_SIGNATURE_IMPORTED `
        -PreviousReceiptSha256 ([string]$r6.Sha256) `
        -RecordedAtUtc '2026-09-03T00:33:00Z' `
        -Data ([ordered]@{
            evidenceType = 'INSTALLER_SIGNATURE_IMPORTED'
            responseRelativePath =
                'imports/installer-signing.v1/installer-signing-response.v1.json'
            responseSha256 = & $hash 'installer-response'
            requestSchemaVersion = 2
            requestSha256 = & $hash 'installer-request'
            admissionHeadSha256 = & $hash 'r7-admission-head'
            r6ReceiptSha256 = [string]$r6.Sha256
            r5LauncherSha256 = [string]$candidateByRole['launcher'].sha256
            r5RuntimeSha256 = [string]$candidateByRole['runtime'].sha256
            trustedBuildEvidenceSha256 = & $hash 'trusted-build-evidence'
            resourceBindingSha256 = & $hash 'resource-binding'
            sdkFileClosureStatus = 'VERIFIED'
            signingRequestEligibilityStatus = 'ELIGIBLE_FOR_PILOT_SIGNING'
            sourceBuildInputSetSha256 = & $hash 'source-build-input-set'
            targetBuildIdentitySha256 = & $hash 'target-build-identity'
            payloadSetSha256 = & $hash 'installer-payload-set'
            signedInstaller = $signedInstaller
            signerCertificateSha256 = & $hash 'signer-certificate'
            timestampSignerCertificateSha256 = & $hash 'timestamp-certificate'
            timestampProtocol = 'RFC3161'
            timestampUtc = '2026-09-03T00:31:00Z'
            authenticationKeyId =
                [string]$Fixture.Plan.externalResponseTrusts.installerSigning.keyId
            authenticationPurpose = 'installer-signing-response'
            completedAtUtc = '2026-09-03T00:32:00Z'
            admissionReason = 'INSTALLER_SIGNING_RESPONSE_REQUIRED'
            productionAdmission = 'NO_GO'
        })

    Write-CanonicalJson -Path $Fixture.HeadPath -Value ([ordered]@{
        schemaVersion = 2
        stateType = 'ensou-dsh-launcher-production-release-head'
        orchestrationId = [string]$Fixture.Plan.orchestrationId
        edition = 'Enterprise'
        planSha256 = [string]$Fixture.PlanSha256
        identitySha256 = [string]$Fixture.IdentitySha256
        revision = 7
        phase = 'INSTALLER_SIGNATURE_IMPORTED'
        receiptFileName = [string]$r7.FileName
        receiptSha256 = [string]$r7.Sha256
        updatedAtUtc = [string]$r7.Value.recordedAtUtc
        targetChannel = 'stable'
    })
    $Fixture.HeadSha256 = Get-Sha256 -Path $Fixture.HeadPath
}

$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) (
    'ensou-feed-promotion-security-test-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($fixtureRoot) | Out-Null
$signers = [Collections.Generic.List[Security.Cryptography.ECDsa]]::new()
try {
    foreach ($nullValue in 1..6) {
        $signers.Add([Security.Cryptography.ECDsa]::Create(
            [Security.Cryptography.ECCurve+NamedCurves]::nistP256))
    }
    $personal = New-AnchoredSourceFixture `
        -Root (Join-Path $fixtureRoot 'personal') `
        -Edition Personal `
        -Signers @($signers | Select-Object -First 5)
    $missing = [ordered]@{ state = 'missing' }
    $personalPromotionRoot = Join-Path $fixtureRoot 'personal-promotion'
    Assert-Fails `
        -Action {
            New-ProductionFeedPromotionRequest `
                -PromotionRoot $personalPromotionRoot `
                -SourceStateRoot $personal.StateRoot `
                -CandidateRoot $personal.CandidateRoot `
                -ExposureRing pilot `
                -ExpectedChannelHead $missing `
                -ExpectedJournalHead $missing `
                -ExpectedFeedIdentitySha256 ('f' * 64) `
                -ExpectedSourcePlanSha256 $personal.PlanSha256 `
                -ExpectedSourceIdentitySha256 $personal.IdentitySha256 `
                -ExpectedSourceHeadSha256 $personal.HeadSha256 | Out-Null
        } `
        -Expected 'initialization owner is missing' `
        -Message 'Placeholder Personal head without an authoritative r1-r7 state reached feed promotion.'
    Assert-True `
        (-not (Test-Path -LiteralPath (Join-Path $personalPromotionRoot 'request'))) `
        'Personal NO-GO created a promotion request bundle.'
    Assert-True `
        (-not (Test-Path -LiteralPath (Join-Path $personalPromotionRoot 'head.json'))) `
        'Personal NO-GO created a promotion CAS head.'

    Assert-Fails `
        -Action {
            New-ProductionFeedPromotionRequest `
                -PromotionRoot (Join-Path $fixtureRoot 'wrong-plan-anchor') `
                -SourceStateRoot $personal.StateRoot `
                -CandidateRoot $personal.CandidateRoot `
                -ExposureRing pilot `
                -ExpectedChannelHead $missing `
                -ExpectedJournalHead $missing `
                -ExpectedFeedIdentitySha256 ('f' * 64) `
                -ExpectedSourcePlanSha256 ('0' * 64) `
                -ExpectedSourceIdentitySha256 $personal.IdentitySha256 `
                -ExpectedSourceHeadSha256 $personal.HeadSha256 | Out-Null
        } `
        -Expected 'externally locked' `
        -Message 'A source-selected plan trust root bypassed the external plan anchor.'

    Assert-Fails `
        -Action {
            New-ProductionFeedPromotionRequest `
                -PromotionRoot (Join-Path $fixtureRoot 'wrong-identity-anchor') `
                -SourceStateRoot $personal.StateRoot `
                -CandidateRoot $personal.CandidateRoot `
                -ExposureRing pilot `
                -ExpectedChannelHead $missing `
                -ExpectedJournalHead $missing `
                -ExpectedFeedIdentitySha256 ('f' * 64) `
                -ExpectedSourcePlanSha256 $personal.PlanSha256 `
                -ExpectedSourceIdentitySha256 ('0' * 64) `
                -ExpectedSourceHeadSha256 $personal.HeadSha256 | Out-Null
        } `
        -Expected 'externally locked' `
        -Message 'A source-selected release identity bypassed the external identity anchor.'

    Assert-Fails `
        -Action {
            New-ProductionFeedPromotionRequest `
                -PromotionRoot (Join-Path $fixtureRoot 'wrong-head-anchor') `
                -SourceStateRoot $personal.StateRoot `
                -CandidateRoot $personal.CandidateRoot `
                -ExposureRing pilot `
                -ExpectedChannelHead $missing `
                -ExpectedJournalHead $missing `
                -ExpectedFeedIdentitySha256 ('f' * 64) `
                -ExpectedSourcePlanSha256 $personal.PlanSha256 `
                -ExpectedSourceIdentitySha256 $personal.IdentitySha256 `
                -ExpectedSourceHeadSha256 ('0' * 64) | Out-Null
        } `
        -Expected 'externally locked' `
        -Message 'A source-selected state head bypassed the external head anchor.'

    $selfKeyPlan = $personal.Plan |
        ConvertTo-Json -Depth 64 -Compress |
        ConvertFrom-Json -Depth 64 -DateKind String
    $selfPublic = $signers[5].ExportParameters($false)
    $selfKeyPlan.externalResponseTrusts.feedPromotion.x =
        ConvertTo-TestBase64Url -Bytes $selfPublic.Q.X
    $selfKeyPlan.externalResponseTrusts.feedPromotion.y =
        ConvertTo-TestBase64Url -Bytes $selfPublic.Q.Y
    Write-CanonicalJson -Path $personal.PlanPath -Value $selfKeyPlan
    $selfPlanSha256 = Get-Sha256 -Path $personal.PlanPath
    $selfIdentity = [IO.File]::ReadAllText($personal.IdentityPath, $utf8) |
        ConvertFrom-Json -Depth 64 -DateKind String
    $selfIdentity.planSha256 = $selfPlanSha256
    Write-CanonicalJson -Path $personal.IdentityPath -Value $selfIdentity
    $selfIdentitySha256 = Get-Sha256 -Path $personal.IdentityPath
    $selfHead = [IO.File]::ReadAllText($personal.HeadPath, $utf8) |
        ConvertFrom-Json -Depth 64 -DateKind String
    $selfHead.planSha256 = $selfPlanSha256
    $selfHead.identitySha256 = $selfIdentitySha256
    Write-CanonicalJson -Path $personal.HeadPath -Value $selfHead
    Assert-Fails `
        -Action {
            New-ProductionFeedPromotionRequest `
                -PromotionRoot (Join-Path $fixtureRoot 'self-key') `
                -SourceStateRoot $personal.StateRoot `
                -CandidateRoot $personal.CandidateRoot `
                -ExposureRing pilot `
                -ExpectedChannelHead $missing `
                -ExpectedJournalHead $missing `
                -ExpectedFeedIdentitySha256 ('f' * 64) `
                -ExpectedSourcePlanSha256 $personal.PlanSha256 `
                -ExpectedSourceIdentitySha256 $personal.IdentitySha256 `
                -ExpectedSourceHeadSha256 $personal.HeadSha256 | Out-Null
        } `
        -Expected 'externally locked' `
        -Message 'A self-selected feed key and rewritten plan bypassed the external trust root.'

    $module = Get-Module ProductionFeedPromotion
    $enterprise = New-AnchoredSourceFixture `
        -Root (Join-Path $fixtureRoot 'enterprise') `
        -Edition Enterprise `
        -Signers @($signers | Select-Object -First 5)
    Add-R5ToR7OnlyAttackChain `
        -Fixture $enterprise `
        -FeedModule $module
    Assert-Fails `
        -Action {
            New-ProductionFeedPromotionRequest `
                -PromotionRoot (Join-Path $fixtureRoot 'truncated-chain') `
                -SourceStateRoot $enterprise.StateRoot `
                -CandidateRoot $enterprise.CandidateRoot `
                -ExposureRing pilot `
                -ExpectedChannelHead $missing `
                -ExpectedJournalHead $missing `
                -ExpectedFeedIdentitySha256 ('f' * 64) `
                -ExpectedSourcePlanSha256 $enterprise.PlanSha256 `
                -ExpectedSourceIdentitySha256 $enterprise.IdentitySha256 `
                -ExpectedSourceHeadSha256 $enterprise.HeadSha256 | Out-Null
        } `
        -Expected 'missing admitted receipts' `
        -Message 'A schema-valid r5-r7-only Enterprise receipt chain was accepted as an r7 source.'

    $stableR7 = [pscustomobject]@{
        Head = [pscustomobject]@{
            revision = 7
            phase = 'INSTALLER_SIGNATURE_IMPORTED'
        }
        Receipts = @(1..7)
    }
    Assert-Fails `
        -Action {
            & $module {
                param($Plan, $State)
                Assert-FeedPromotionValidatedLifecycle `
                    -Plan $Plan `
                    -ValidatedState $State `
                    -ExposureRing stable
            } $enterprise.Plan $stableR7
        } `
        -Expected 'revision 8 phase PILOT_EVIDENCE_BOUND' `
        -Message 'Enterprise public Stable accepted an r7-only source.'
    $stableR8 = [pscustomobject]@{
        Head = [pscustomobject]@{
            revision = 8
            phase = 'PILOT_EVIDENCE_BOUND'
        }
        Receipts = @(1..8)
    }
    & $module {
        param($Plan, $State)
        Assert-FeedPromotionValidatedLifecycle `
            -Plan $Plan `
            -ValidatedState $State `
            -ExposureRing stable
    } $enterprise.Plan $stableR8
    Assert-True $true 'Enterprise certified-r8 lifecycle gate rejected its exact shape.'

    $requestCommand = Get-Command New-ProductionFeedPromotionRequest
    $importCommand = Get-Command Import-ProductionFeedPromotionResponse
    foreach ($command in @($requestCommand, $importCommand)) {
        $mandatoryAnchors = @(
            'ExpectedSourcePlanSha256',
            'ExpectedSourceIdentitySha256',
            'ExpectedSourceHeadSha256')
        Assert-True `
            (@($mandatoryAnchors | Where-Object {
                        -not $command.Parameters.ContainsKey($_) -or
                        @($command.Parameters[$_].Attributes | Where-Object {
                                $_ -is [Management.Automation.ParameterAttribute] -and
                                $_.Mandatory
                            }).Count -ne 1
                    }).Count -eq 0) `
            "$($command.Name) does not require all three external source trust anchors."
    }
    Assert-True `
        (-not $importCommand.Parameters.ContainsKey('NowUtc')) `
        'Production response import still exposes a caller-controlled clock.'
    Assert-Fails `
        -Action {
            Import-ProductionFeedPromotionResponse `
                -PromotionRoot 'C:\invalid' `
                -SourceStateRoot 'C:\invalid-state' `
                -CandidateRoot 'C:\invalid-candidate' `
                -ExposureRing pilot `
                -ResponsePath 'C:\invalid-response.json' `
                -ExpectedPromotionHeadSha256 ('1' * 64) `
                -ExpectedSourcePlanSha256 ('2' * 64) `
                -ExpectedSourceIdentitySha256 ('3' * 64) `
                -ExpectedSourceHeadSha256 ('4' * 64) `
                -NowUtc ([DateTimeOffset]::UnixEpoch) | Out-Null
        } `
        -Expected 'NowUtc' `
        -Message 'A caller rolled response validation time backward.'

    $openAdmissionCommand =
        Get-Command Open-ProductionFeedPromotionBundleAdmission
    $closeAdmissionCommand =
        Get-Command Close-ProductionFeedPromotionBundleAdmission
    Assert-True ($null -ne $closeAdmissionCommand) `
        'Feed-promotion bundle admission close contract is not exported.'
    $admissionAnchors = @(
        'PromotionRoot',
        'ExpectedPromotionHeadSha256',
        'ExpectedBundleHeadSha256',
        'ExpectedSourceHeadSha256',
        'ExpectedRequestSha256',
        'ExpectedResponseSha256',
        'ExpectedBundleSetSha256')
    Assert-True `
        (@($admissionAnchors | Where-Object {
                    -not $openAdmissionCommand.Parameters.ContainsKey($_) -or
                    @($openAdmissionCommand.Parameters[$_].Attributes | Where-Object {
                            $_ -is [Management.Automation.ParameterAttribute] -and
                            $_.Mandatory
                        }).Count -ne 1
                }).Count -eq 0) `
        'Feed-promotion bundle admission does not require every caller-owned digest pin.'

    $admissionFixture = New-CompletedPromotionBundleFixture `
        -Root (Join-Path $fixtureRoot 'bundle-admission') `
        -Signer $signers[4] `
        -FeedModule $module
    $admissionArguments = @{
        PromotionRoot = $admissionFixture.PromotionRoot
        ExpectedPromotionHeadSha256 = $admissionFixture.PromotionHeadSha256
        ExpectedBundleHeadSha256 = $admissionFixture.BundleHeadSha256
        ExpectedSourceHeadSha256 = $admissionFixture.SourceHeadSha256
        ExpectedRequestSha256 = $admissionFixture.RequestSha256
        ExpectedResponseSha256 = $admissionFixture.ResponseSha256
        ExpectedBundleSetSha256 = $admissionFixture.BundleSetSha256
    }
    $unrelatedStateRoot = Join-Path $fixtureRoot 'prelocked-state'
    [IO.Directory]::CreateDirectory($unrelatedStateRoot) | Out-Null
    $unrelatedStateLockPath = Join-Path $unrelatedStateRoot 'state.lock'
    $unrelatedStateLock = [IO.File]::Open(
        $unrelatedStateLockPath,
        [IO.FileMode]::OpenOrCreate,
        [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::None)
    $bundleAdmission = $null
    try {
        $bundleAdmission =
            Open-ProductionFeedPromotionBundleAdmission @admissionArguments
        Assert-True `
            ($bundleAdmission.Root -ceq
                [IO.Path]::GetFullPath($admissionFixture.PromotionRoot) -and
             $bundleAdmission.PromotionRoot -ceq $bundleAdmission.Root -and
             $null -ne $bundleAdmission.PromotionLock) `
            'Bundle admission did not return its held PromotionRoot lock.'
        Assert-True `
            ($bundleAdmission.HeldDescriptors.Count -eq 9 -and
             $bundleAdmission.PayloadInputs.Count -eq 5) `
            'Bundle admission did not retain four JSON inputs and exactly five payloads.'
        Assert-True `
            ($bundleAdmission.RequestInput.Value.edition -ceq 'Enterprise' -and
             $bundleAdmission.ResponseInput.Value.decision -ceq
                'AUTHORIZE_OFFLINE_BUNDLE' -and
             $bundleAdmission.PromotionHeadInput.Value.status -ceq
                'PROMOTION_REQUEST_READY' -and
             $bundleAdmission.BundleHeadInput.Value.status -ceq
                'EXTERNAL_PUBLISH_BUNDLE_READY') `
            'Bundle admission did not return all four parsed locked JSON inputs.'
        Assert-True `
            ($bundleAdmission.PromotionHeadSha256 -ceq
                $admissionFixture.PromotionHeadSha256 -and
             $bundleAdmission.BundleHeadSha256 -ceq
                $admissionFixture.BundleHeadSha256 -and
             $bundleAdmission.SourceHeadSha256 -ceq
                $admissionFixture.SourceHeadSha256 -and
             $bundleAdmission.RequestSha256 -ceq
                $admissionFixture.RequestSha256 -and
             $bundleAdmission.ResponseSha256 -ceq
                $admissionFixture.ResponseSha256 -and
             $bundleAdmission.BundleSetSha256 -ceq
                $admissionFixture.BundleSetSha256) `
            'Bundle admission returned a digest that differs from the caller-owned pins.'
        Assert-True `
            (@($bundleAdmission.HeldDescriptors | Where-Object {
                        $null -eq $_.Stream -or -not $_.Stream.CanRead
                    }).Count -eq 0) `
            'Bundle admission returned an input whose held descriptor is already closed.'
        foreach ($descriptor in $bundleAdmission.HeldDescriptors) {
            Assert-ProductionReleaseInputStillLocked `
                -Descriptor $descriptor `
                -Label "Focused held bundle input $($descriptor.FileName)"
        }
        Assert-Fails `
            -Action {
                & $module {
                    param($Root)
                    $contender = Enter-FeedPromotionLock -PromotionRoot $Root
                    $contender.Stream.Dispose()
                } $admissionFixture.PromotionRoot
            } `
            -Expected 'locked by another promotion process' `
            -Message 'Bundle admission released its PromotionRoot lock before Close.'
        $payloadMutationWasBlocked = $false
        try {
            $mutationStream = [IO.File]::Open(
                $admissionFixture.PayloadPath,
                [IO.FileMode]::Open,
                [IO.FileAccess]::Write,
                [IO.FileShare]::None)
            $mutationStream.Dispose()
        }
        catch {
            $payloadMutationWasBlocked = $true
        }
        Assert-True $payloadMutationWasBlocked `
            'A locked external bundle payload could be opened for mutation.'
    }
    finally {
        Close-ProductionFeedPromotionBundleAdmission -Admission $bundleAdmission
        $unrelatedStateLock.Dispose()
    }
    $postClosePayload = [IO.File]::Open(
        $admissionFixture.PayloadPath,
        [IO.FileMode]::Open,
        [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::None)
    $postClosePayload.Dispose()
    $postClosePromotionLock = & $module {
        param($Root)
        Enter-FeedPromotionLock -PromotionRoot $Root
    } $admissionFixture.PromotionRoot
    $postClosePromotionLock.Stream.Dispose()
    Assert-True $true `
        'Bundle admission Close did not release every file and PromotionRoot lock.'

    $replayAdmission =
        Open-ProductionFeedPromotionBundleAdmission @admissionArguments
    try {
        Assert-True `
            ($replayAdmission.BundleSetSha256 -ceq
                $admissionFixture.BundleSetSha256) `
            'Exact completed-bundle replay changed its admitted bundle-set digest.'
    }
    finally {
        Close-ProductionFeedPromotionBundleAdmission -Admission $replayAdmission
    }
    foreach ($anchor in $admissionAnchors | Where-Object { $_ -cne 'PromotionRoot' }) {
        $wrongArguments = @{}
        foreach ($entry in $admissionArguments.GetEnumerator()) {
            $wrongArguments[$entry.Key] = $entry.Value
        }
        $wrongArguments[$anchor] = 'f' * 64
        Assert-Fails `
            -Action {
                Open-ProductionFeedPromotionBundleAdmission @wrongArguments | Out-Null
            } `
            -Expected 'caller-pinned digest' `
            -Message "Bundle admission accepted a replay with wrong $anchor."
    }

    $originalPayloadBytes = [IO.File]::ReadAllBytes($admissionFixture.PayloadPath)
    $mutatedPayloadBytes = [byte[]]::new($originalPayloadBytes.Length + 1)
    [Array]::Copy(
        $originalPayloadBytes,
        0,
        $mutatedPayloadBytes,
        0,
        $originalPayloadBytes.Length)
    $mutatedPayloadBytes[$mutatedPayloadBytes.Length - 1] = 0x7f
    [IO.File]::WriteAllBytes($admissionFixture.PayloadPath, $mutatedPayloadBytes)
    try {
        Assert-Fails `
            -Action {
                Open-ProductionFeedPromotionBundleAdmission @admissionArguments | Out-Null
            } `
            -Expected 'differs from its request identity' `
            -Message 'Mutated external bundle payload was admitted under the old digest pins.'
    }
    finally {
        [IO.File]::WriteAllBytes(
            $admissionFixture.PayloadPath,
            $originalPayloadBytes)
    }
    $restoredAdmission =
        Open-ProductionFeedPromotionBundleAdmission @admissionArguments
    Close-ProductionFeedPromotionBundleAdmission -Admission $restoredAdmission
    Assert-True $true `
        'Restored exact external bundle could not be replay-admitted after mutation rejection.'

    # A Personal offline bundle is still authorization only. It must opt into
    # the three-file Pilot shape; existing Enterprise callers cannot admit it.
    $personalBundle = New-CompletedPromotionBundleFixture `
        -Root (Join-Path $fixtureRoot 'personal-bundle-admission') `
        -Signer $signers[4] -FeedModule $module -Edition Personal
    $personalBundleArguments = @{
        PromotionRoot = $personalBundle.PromotionRoot
        ExpectedPromotionHeadSha256 = $personalBundle.PromotionHeadSha256
        ExpectedBundleHeadSha256 = $personalBundle.BundleHeadSha256
        ExpectedSourceHeadSha256 = $personalBundle.SourceHeadSha256
        ExpectedRequestSha256 = $personalBundle.RequestSha256
        ExpectedResponseSha256 = $personalBundle.ResponseSha256
        ExpectedBundleSetSha256 = $personalBundle.BundleSetSha256
    }
    Assert-Fails -Action {
        $unexpected = Open-ProductionFeedPromotionBundleAdmission @personalBundleArguments
        Close-ProductionFeedPromotionBundleAdmission $unexpected
    } -Expected 'caller-pinned Enterprise edition' `
        -Message 'Default Enterprise admission accepted a Personal bundle.'
    Assert-Fails -Action {
        $unexpected = Open-ProductionFeedPromotionBundleAdmission @admissionArguments -ExpectedEdition Personal
        Close-ProductionFeedPromotionBundleAdmission $unexpected
    } -Expected 'caller-pinned Personal edition' `
        -Message 'Personal admission accepted the Enterprise five-file bundle.'
    $personalStableBundle = New-CompletedPromotionBundleFixture `
        -Root (Join-Path $fixtureRoot 'personal-stable-bundle-refusal') `
        -Signer $signers[4] -FeedModule $module -Edition Personal -ExposureRing stable
    Assert-Fails -Action {
        $unexpected = Open-ProductionFeedPromotionBundleAdmission -ExpectedEdition Personal `
            -PromotionRoot $personalStableBundle.PromotionRoot `
            -ExpectedPromotionHeadSha256 $personalStableBundle.PromotionHeadSha256 `
            -ExpectedBundleHeadSha256 $personalStableBundle.BundleHeadSha256 `
            -ExpectedSourceHeadSha256 $personalStableBundle.SourceHeadSha256 `
            -ExpectedRequestSha256 $personalStableBundle.RequestSha256 `
            -ExpectedResponseSha256 $personalStableBundle.ResponseSha256 `
            -ExpectedBundleSetSha256 $personalStableBundle.BundleSetSha256
        Close-ProductionFeedPromotionBundleAdmission $unexpected
    } -Expected 'restricted to Pilot channel-head publication' `
        -Message 'Personal Pilot-only result admission accepted stable publication.'
    $personalAdmission = $null
    try {
        $personalAdmission = Open-ProductionFeedPromotionBundleAdmission @personalBundleArguments -ExpectedEdition Personal
        Assert-True ($personalAdmission.HeldDescriptors.Count -eq 7 -and
            $personalAdmission.PayloadInputs.Count -eq 3 -and
            (@($personalAdmission.PayloadInputs.role) -join ',') -ceq 'release-manifest,launcher,runtime') `
            'Personal admission did not retain its exact three payloads and four metadata files.'
        Assert-True ($personalAdmission.RequestInput.Value.edition -ceq 'Personal' -and
            $personalAdmission.RequestInput.Value.feedChannel -ceq 'pilot' -and
            $personalAdmission.RequestInput.Value.publishScope -ceq 'channel-head' -and
            $personalAdmission.ProductionAdmission -ceq 'NO_GO' -and
            $personalAdmission.NetworkPublishPerformed -eq $false) `
            'Personal offline authorization was mislabeled as completed publication.'
        $writeRejected = $false
        try { [IO.File]::WriteAllBytes($personalBundle.PayloadPath, [byte[]]@(1)) }
        catch [IO.IOException] { $writeRejected = $true }
        Assert-True $writeRejected 'Personal admission did not hold its payload bytes locked.'
    }
    finally { Close-ProductionFeedPromotionBundleAdmission $personalAdmission }
    $personalBytes = [IO.File]::ReadAllBytes($personalBundle.PayloadPath)
    [IO.File]::WriteAllBytes($personalBundle.PayloadPath, [byte[]]($personalBytes + @(1)))
    try {
        Assert-Fails -Action {
            $unexpected = Open-ProductionFeedPromotionBundleAdmission @personalBundleArguments -ExpectedEdition Personal
            Close-ProductionFeedPromotionBundleAdmission $unexpected
        } -Expected 'differs from its request identity' `
            -Message 'Personal admission accepted mutated payload bytes.'
    }
    finally { [IO.File]::WriteAllBytes($personalBundle.PayloadPath, $personalBytes) }
    $personalReplay = Open-ProductionFeedPromotionBundleAdmission @personalBundleArguments -ExpectedEdition Personal
    Close-ProductionFeedPromotionBundleAdmission $personalReplay
    Assert-True $true 'Personal replay retained a failed-admission lock or rejected the restored exact bundle.'

    $moduleAstTokens = $null
    $moduleAstErrors = $null
    $moduleAst = [Management.Automation.Language.Parser]::ParseFile(
        $modulePath,
        [ref]$moduleAstTokens,
        [ref]$moduleAstErrors)
    Assert-True ($moduleAstErrors.Count -eq 0) `
        'Feed-promotion module did not parse for focused lock-order inspection.'
    $openAdmissionAst = @($moduleAst.FindAll({
                param($Ast)
                $Ast -is [Management.Automation.Language.FunctionDefinitionAst] -and
                $Ast.Name -ceq 'Open-ProductionFeedPromotionBundleAdmission'
            }, $true))[0]
    $openAdmissionCommands = @($openAdmissionAst.Body.FindAll({
                param($Ast)
                $Ast -is [Management.Automation.Language.CommandAst]
            }, $true))
    Assert-True `
        ($openAdmissionCommands[0].GetCommandName() -ceq 'Enter-FeedPromotionLock') `
        'Bundle admission does not acquire PromotionRoot before every other lock.'
    foreach ($forbiddenStateCommand in @(
            'Enter-ProductionReleaseStateLock',
            'Enter-ProductionReleaseStateReadLock',
            'Get-ProductionReleaseState')) {
        Assert-True `
            (@($openAdmissionCommands | Where-Object {
                        $_.GetCommandName() -ceq $forbiddenStateCommand
                    }).Count -eq 0) `
            "Bundle admission acquires or reads state through $forbiddenStateCommand."
    }
    $closeAdmissionAst = @($moduleAst.FindAll({
                param($Ast)
                $Ast -is [Management.Automation.Language.FunctionDefinitionAst] -and
                $Ast.Name -ceq 'Close-ProductionFeedPromotionBundleAdmission'
            }, $true))[0]
    Assert-True `
        ($closeAdmissionAst.Extent.Text.Contains('$heldDescriptors.Count - 1') -and
         $closeAdmissionAst.Extent.Text.Contains('$index--')) `
        'Bundle admission Close no longer releases held descriptors in reverse order.'
    $newRequestAst = @($moduleAst.FindAll({
                param($Ast)
                $Ast -is [Management.Automation.Language.FunctionDefinitionAst] -and
                $Ast.Name -ceq 'New-ProductionFeedPromotionRequest'
            }, $true))[0]
    $importResponseAst = @($moduleAst.FindAll({
                param($Ast)
                $Ast -is [Management.Automation.Language.FunctionDefinitionAst] -and
                $Ast.Name -ceq 'Import-ProductionFeedPromotionResponse'
            }, $true))[0]
    Assert-True `
        $newRequestAst.Extent.Text.Contains('PromotionHeadSha256') `
        'New feed-promotion request result lost its explicit promotion-head digest.'
    Assert-True `
        ($importResponseAst.Extent.Text.Contains('PromotionHeadSha256') -and
         $importResponseAst.Extent.Text.Contains('BundleHeadSha256')) `
        'Feed-promotion response import result lost its explicit head digests.'
    Assert-True `
        ($importResponseAst.Extent.Text.Contains(
                'AllowPersonalPilotPromotionRequestState') -and
         $importResponseAst.Extent.Text.Contains(
                'External Personal promotion request differs from the exact request sealed by r8.')) `
        'Personal r8 response import lost its sealed-request admission boundary.'

    $casParent = Join-Path $fixtureRoot 'cas'
    [IO.Directory]::CreateDirectory($casParent) | Out-Null
    $casRoot = Join-Path $casParent 'promotion'
    [IO.Directory]::CreateDirectory($casRoot) | Out-Null
    $headBytes = $utf8.GetBytes('{"head":"one"}')
    & $module {
        param($Root, $Bytes)
        Write-FeedPromotionHeadCas `
            -PromotionRoot $Root `
            -Bytes $Bytes `
            -ExpectedHeadSha256 ''
    } $casRoot $headBytes
    $headPath = Join-Path $casRoot 'head.json'
    $originalHeadSha256 = Get-Sha256 -Path $headPath
    Assert-Fails `
        -Action {
            & $module {
                param($Root, $Bytes, $Expected)
                Write-FeedPromotionHeadCas `
                    -PromotionRoot $Root `
                    -Bytes $Bytes `
                    -ExpectedHeadSha256 $Expected
            } $casRoot $utf8.GetBytes('{"head":"two"}') $originalHeadSha256
        } `
        -Expected 'append-only' `
        -Message 'Promotion head CAS overwrote an admitted head.'
    Assert-True `
        ((Get-Sha256 -Path $headPath) -ceq $originalHeadSha256) `
        'Rejected head overwrite changed committed bytes.'

    $pendingRoot = Join-Path $casParent 'pending-conflict'
    [IO.Directory]::CreateDirectory($pendingRoot) | Out-Null
    [IO.File]::WriteAllBytes(
        (Join-Path $pendingRoot 'head.json.pending'),
        $utf8.GetBytes('{"attacker":"pending"}'))
    Assert-Fails `
        -Action {
            & $module {
                param($Root, $Bytes)
                Write-FeedPromotionHeadCas `
                    -PromotionRoot $Root `
                    -Bytes $Bytes `
                    -ExpectedHeadSha256 ''
            } $pendingRoot $headBytes
        } `
        -Expected 'conflicts' `
        -Message 'Conflicting pending CAS bytes were replaced.'
    Assert-True `
        (-not (Test-Path -LiteralPath (Join-Path $pendingRoot 'head.json'))) `
        'Pending conflict created a committed promotion head.'

    $pendingReplayRoot = Join-Path $casParent 'pending-replay'
    [IO.Directory]::CreateDirectory($pendingReplayRoot) | Out-Null
    [IO.File]::WriteAllBytes(
        (Join-Path $pendingReplayRoot 'head.json.pending'),
        $headBytes)
    & $module {
        param($Root, $Bytes)
        Write-FeedPromotionHeadCas `
            -PromotionRoot $Root `
            -Bytes $Bytes `
            -ExpectedHeadSha256 ''
    } $pendingReplayRoot $headBytes
    Assert-True `
        ((Get-Sha256 -Path (Join-Path $pendingReplayRoot 'head.json')) -ceq
         (Get-ProductionSha256Bytes -Bytes $headBytes)) `
        'Exact pending CAS replay did not commit the intended immutable head.'
    Assert-True `
        (-not (Test-Path -LiteralPath (
                    Join-Path $pendingReplayRoot 'head.json.pending'))) `
        'Exact pending CAS replay left unresolved residue.'

    $concurrentRoot = Join-Path $casParent 'concurrent-create'
    [IO.Directory]::CreateDirectory($concurrentRoot) | Out-Null
    $concurrentGate = [Threading.Barrier]::new(2)
    $firstWorkerReady = [Threading.ManualResetEventSlim]::new($false)
    $jobs = [Collections.Generic.List[object]]::new()
    $firstBytes = $utf8.GetBytes('{"writer":"one"}')
    $secondBytes = $utf8.GetBytes('{"writer":"two"}')
    $worker = {
        param($ModulePath, $Root, $Bytes, $Gate, $ReadySignal)

        Import-Module $ModulePath -Force -DisableNameChecking
        if ($null -ne $ReadySignal) {
            $ReadySignal.Set()
        }
        $feedModule = Get-Module ProductionFeedPromotion
        [void]$Gate.SignalAndWait([TimeSpan]::FromSeconds(10))
        try {
            & $feedModule {
                param($PromotionRoot, $HeadBytes)
                Write-FeedPromotionHeadCas `
                    -PromotionRoot $PromotionRoot `
                    -Bytes $HeadBytes `
                    -ExpectedHeadSha256 ''
            } $Root $Bytes
            return [pscustomobject]@{ Outcome = 'success' }
        }
        catch {
            return [pscustomobject]@{
                Outcome = 'failure'
                Error = $_.Exception.Message
            }
        }
    }
    try {
        $jobs.Add((Start-ThreadJob `
                    -ArgumentList @(
                        $modulePath,
                        $concurrentRoot,
                        $firstBytes,
                        $concurrentGate,
                        $firstWorkerReady) `
                    -ScriptBlock $worker))
        Assert-True `
            $firstWorkerReady.Wait([TimeSpan]::FromSeconds(10)) `
            'First concurrent CAS writer did not reach its synchronized gate.'
        $jobs.Add((Start-ThreadJob `
                    -ArgumentList @(
                        $modulePath,
                        $concurrentRoot,
                        $secondBytes,
                        $concurrentGate,
                        $null) `
                    -ScriptBlock $worker))
        [void]($jobs | Wait-Job -Timeout 20)
        $jobResults = @($jobs | Receive-Job)
        Assert-True `
            ($jobResults.Count -eq 2 -and
             @($jobResults | Where-Object Outcome -ceq 'success').Count -eq 1 -and
             @($jobResults | Where-Object Outcome -ceq 'failure').Count -eq 1) `
            'Concurrent create-only head writers did not admit exactly one winner.'
        $committedConcurrentBytes = [IO.File]::ReadAllBytes(
            (Join-Path $concurrentRoot 'head.json'))
        $committedConcurrentSha256 = Get-ProductionSha256Bytes `
            -Bytes $committedConcurrentBytes
        Assert-True `
            ($committedConcurrentSha256 -cin @(
                    Get-ProductionSha256Bytes -Bytes $firstBytes
                    Get-ProductionSha256Bytes -Bytes $secondBytes)) `
            'Concurrent head creation produced overwritten or mixed bytes.'
        Assert-True `
            (-not (Test-Path -LiteralPath (
                        Join-Path $concurrentRoot 'head.json.pending'))) `
            'Concurrent create-only head race left a pending file after one winner committed.'
    }
    finally {
        foreach ($job in $jobs) {
            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        }
        $firstWorkerReady.Dispose()
        $concurrentGate.Dispose()
    }

    [IO.File]::WriteAllBytes(
        (Join-Path $casRoot 'head.json.pending'),
        $headBytes)
    Assert-Fails `
        -Action {
            & $module {
                param($Root)
                Get-FeedPromotionCurrentHead -PromotionRoot $Root | Out-Null
            } $casRoot
        } `
        -Expected 'pending residue' `
        -Message 'Committed head silently ignored pending CAS residue.'

    $bundleConflictRoot = Join-Path $casParent 'bundle-conflict'
    $bundleConflict = Join-Path $bundleConflictRoot 'bundle'
    [IO.Directory]::CreateDirectory($bundleConflict) | Out-Null
    [IO.File]::WriteAllBytes(
        (Join-Path $bundleConflict 'head.v1.json'),
        $headBytes)
    [IO.File]::WriteAllBytes(
        (Join-Path $bundleConflict 'head.v1.json.pending'),
        $headBytes)
    Assert-Fails `
        -Action {
            & $module {
                param($Root)
                Get-FeedPromotionBundleHead -PromotionRoot $Root | Out-Null
            } $bundleConflictRoot
        } `
        -Expected 'pending residue' `
        -Message 'Committed append-only bundle head ignored pending residue.'

    $moduleText = [IO.File]::ReadAllText($modulePath, $utf8)
    Assert-True `
        ($moduleText.Contains('Get-ProductionReleaseState')) `
        'Feed promotion no longer delegates full-chain validation to the shared state machine.'
    Assert-True `
        ($moduleText.Contains('Assert-EnterpriseProductionPilotEvidenceInputBinding') -and
         $moduleText.Contains('-EnforceCurrentLifetime')) `
        'Enterprise Stable no longer enforces the certified-Pilot r8 validator and lifetime.'
    Assert-True `
        (-not $moduleText.Contains('[IO.File]::Move($pendingPath, $headPath, $true)')) `
        'Feed promotion retained an overwrite-capable head move.'
    foreach ($forbidden in @(
            'Invoke-WebRequest', 'Invoke-RestMethod', 'HttpClient',
            'Start-BitsTransfer', 'curl.exe', 'wget.exe')) {
        Assert-True `
            ($moduleText.IndexOf(
                    $forbidden,
                    [StringComparison]::OrdinalIgnoreCase) -lt 0) `
            "Offline promotion module contains network primitive '$forbidden'."
    }

    $requestSchema = [Text.Json.JsonDocument]::Parse(
        [IO.File]::ReadAllText($requestSchemaPath, $utf8))
    try {
        $startRevision = $requestSchema.RootElement.
            GetProperty('properties').
            GetProperty('sourceState').
            GetProperty('properties').
            GetProperty('receiptChainStartRevision').
            GetProperty('const').GetInt32()
        Assert-True ($startRevision -eq 1) `
            'Feed request schema still permits a receipt chain that starts after r1.'
    }
    finally {
        $requestSchema.Dispose()
    }
    [void]([Text.Json.JsonDocument]::Parse(
            [IO.File]::ReadAllText($responseSchemaPath, $utf8))).Dispose()
    Assert-True $true 'Feed-promotion response schema did not parse.'

    "Production feed promotion security tests passed ($assertions assertions)."
}
finally {
    foreach ($signer in $signers) {
        $signer.Dispose()
    }
    if (Test-Path -LiteralPath $fixtureRoot) {
        Remove-Item -LiteralPath $fixtureRoot -Recurse -Force
    }
}
