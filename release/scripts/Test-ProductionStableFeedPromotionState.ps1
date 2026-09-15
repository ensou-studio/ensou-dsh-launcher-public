#requires -Version 7.2

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = Join-Path $PSScriptRoot 'ProductionReleaseState.psm1'
$schemaRoot = Join-Path $PSScriptRoot '..\schemas'
Import-Module $modulePath -Force -DisableNameChecking
$stateModule = Get-Module ProductionReleaseState
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

    [IO.Directory]::CreateDirectory(
        [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($Path))) | Out-Null
    [IO.File]::WriteAllBytes(
        $Path,
        (ConvertTo-ProductionJsonBytes -Value $Value))
}

function Get-TestFileInput {
    param([Parameter(Mandatory = $true)][string]$Path)

    $bytes = [IO.File]::ReadAllBytes($Path)
    return [pscustomobject]@{
        Bytes = $bytes
        SizeBytes = [int64]$bytes.LongLength
        Sha256 = Get-ProductionSha256Bytes -Bytes $bytes
    }
}

function ConvertTo-TestBase64Url {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    return [Convert]::ToBase64String($Bytes).
        TrimEnd('=').Replace('+', '-').Replace('/', '_')
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
                -Label 'Test stable feed-promotion signature'
            return ,$signature
        }
        catch {
            # Signing is randomized; select the canonical low-S half.
        }
    }
    throw 'Test signer did not produce one canonical low-S P-256 signature.'
}

$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) (
    'ensou-stable-promotion-state-' + [Guid]::NewGuid().ToString('N'))
$stateRoot = Join-Path $fixtureRoot 'state'
$signer = [Security.Cryptography.ECDsa]::Create(
    [Security.Cryptography.ECCurve+NamedCurves]::nistP256)

try {
    [IO.Directory]::CreateDirectory($stateRoot) | Out-Null
    [IO.Directory]::CreateDirectory((Join-Path $stateRoot 'receipts')) | Out-Null
    [IO.Directory]::CreateDirectory((Join-Path $stateRoot 'requests')) | Out-Null

    $public = $signer.ExportParameters($false)
    $trust = [ordered]@{
        algorithm = 'ES256'
        keyId = 'stable-promotion-state-test'
        purpose = 'feed-promotion-response'
        x = ConvertTo-TestBase64Url -Bytes $public.Q.X
        y = ConvertTo-TestBase64Url -Bytes $public.Q.Y
    }
    $orchestrationId = [Guid]::NewGuid().ToString().ToLowerInvariant()
    $plan = [ordered]@{
        schemaVersion = 2
        orchestrationId = $orchestrationId
        edition = 'Enterprise'
        targetChannel = 'stable'
        releaseSetId = 'managed-v2026.09.05.1'
        externalResponseTrusts = [ordered]@{
            feedPromotion = $trust
        }
    }
    $planPath = Join-Path $stateRoot 'plan.json'
    Write-CanonicalJson -Path $planPath -Value $plan
    $planInput = Get-TestFileInput -Path $planPath
    $identity = [ordered]@{
        schemaVersion = 2
        identityType = 'ensou-dsh-launcher-production-release-state'
        orchestrationId = $orchestrationId
        edition = 'Enterprise'
        planSha256 = [string]$planInput.Sha256
        initializationSha256 = 'a' * 64
        createdAtUtc = '2026-09-05T01:00:00Z'
        targetChannel = 'stable'
    }
    $identityPath = Join-Path $stateRoot 'identity.json'
    Write-CanonicalJson -Path $identityPath -Value $identity
    $identityInput = Get-TestFileInput -Path $identityPath

    $candidateRoot = Join-Path `
        (Join-Path (Join-Path $stateRoot 'imports') `
            'stable-signed-candidate.v1') `
        'candidate'
    [IO.Directory]::CreateDirectory($candidateRoot) | Out-Null
    $definitions = @(
        [ordered]@{
            role = 'release-manifest'
            fileName = 'release-set.v2.json'
            bytes = $utf8.GetBytes('{"fixture":"manifest"}')
        },
        [ordered]@{
            role = 'release-public-key'
            fileName = 'release-public-key.v2.json'
            bytes = $utf8.GetBytes('{"fixture":"public-key"}')
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
    $candidateFiles = [Collections.Generic.List[object]]::new()
    foreach ($definition in $definitions) {
        $path = Join-Path $candidateRoot ([string]$definition.fileName)
        [IO.File]::WriteAllBytes($path, [byte[]]$definition.bytes)
        $input = Get-TestFileInput -Path $path
        $candidateFiles.Add([ordered]@{
            role = [string]$definition.role
            fileName = [string]$definition.fileName
            relativePath = 'candidate/' + [string]$definition.fileName
            sizeBytes = [int64]$input.SizeBytes
            sha256 = [string]$input.Sha256
        })
    }

    $phaseNames = @(
        'PLAN_ADMITTED',
        'CLIENT_SIGNING_REQUESTED',
        'CLIENT_SIGNATURES_IMPORTED',
        'STABLE_MANIFEST_SIGNING_REQUESTED',
        'STABLE_SIGNED_CANDIDATE_IMPORTED',
        'INSTALLER_SIGNING_REQUESTED',
        'INSTALLER_SIGNATURE_IMPORTED',
        'PILOT_EVIDENCE_BOUND')
    $receipts = [Collections.Generic.List[object]]::new()
    $receiptIdentities = [Collections.Generic.List[object]]::new()
    for ($revision = 1; $revision -le 8; $revision++) {
        $phase = $phaseNames[$revision - 1]
        $data = if ($revision -eq 5) {
            [ordered]@{
                productionAdmission = 'NO_GO'
                files = @($candidateFiles)
            }
        }
        else {
            [ordered]@{ productionAdmission = 'NO_GO' }
        }
        $receipt = [ordered]@{
            revision = $revision
            phase = $phase
            recordedAtUtc = "2026-09-05T01:$($revision.ToString('00')):00Z"
            data = $data
        }
        $fileName = $revision.ToString('0000') + '-' +
            $phase.ToLowerInvariant().Replace('_', '-') + '.json'
        $path = Join-Path (Join-Path $stateRoot 'receipts') $fileName
        Write-CanonicalJson -Path $path -Value $receipt
        $input = Get-TestFileInput -Path $path
        $receiptIdentities.Add([ordered]@{
            revision = $revision
            fileName = $fileName
            sizeBytes = [int64]$input.SizeBytes
            sha256 = [string]$input.Sha256
        })
        $receipts.Add([pscustomobject]$receipt)
    }
    $candidateReceiptInput = Get-TestFileInput -Path (
        Join-Path (Join-Path $stateRoot 'receipts') `
            '0005-stable-signed-candidate-imported.json')
    $r8ReceiptInput = Get-TestFileInput -Path (
        Join-Path (Join-Path $stateRoot 'receipts') `
            '0008-pilot-evidence-bound.json')
    $r8Head = [ordered]@{
        schemaVersion = 2
        stateType = 'ensou-dsh-launcher-production-release-head'
        orchestrationId = $orchestrationId
        edition = 'Enterprise'
        planSha256 = [string]$planInput.Sha256
        identitySha256 = [string]$identityInput.Sha256
        revision = 8
        phase = 'PILOT_EVIDENCE_BOUND'
        receiptFileName = '0008-pilot-evidence-bound.json'
        receiptSha256 = [string]$r8ReceiptInput.Sha256
        updatedAtUtc = [string]$receipts[7].recordedAtUtc
        targetChannel = 'stable'
    }
    $r8HeadBytes = ConvertTo-ProductionJsonBytes -Value $r8Head
    $r8HeadSha256 = Get-ProductionSha256Bytes -Bytes $r8HeadBytes
    $receiptChainSha256 = & $stateModule {
        param($Inventory)
        Get-ProductionStableFeedPromotionDomainDigest `
            -Domain 'ensou-dsh-launcher-feed-promotion-source-receipt-chain-v1' `
            -Value $Inventory
    } @($receiptIdentities)

    Assert-Fails `
        -Action {
            Assert-ProductionStableFeedPromotionAdmission `
                -StateRoot $stateRoot `
                -Plan ([pscustomobject]$plan) `
                -Identity ([pscustomobject]$identity) `
                -IdentitySha256 ([string]$identityInput.Sha256) `
                -Receipts $receipts `
                -CommittedRevision 8 `
                -AdmittedRevision 9 | Out-Null
        } `
        -Expected 'missing its exact state-owned admission bundle' `
        -Message 'Admitted r9 accepted a missing stable feed-promotion bundle.'

    $requestFiles = [Collections.Generic.List[object]]::new()
    foreach ($candidateFile in $candidateFiles) {
        $requestFiles.Add([ordered]@{
            role = [string]$candidateFile.role
            fileName = [string]$candidateFile.fileName
            relativePath = 'payload/' + [string]$candidateFile.fileName
            sizeBytes = [int64]$candidateFile.sizeBytes
            sha256 = [string]$candidateFile.sha256
        })
    }
    $feedCas = [ordered]@{
        channelHead = [ordered]@{ state = 'missing' }
        journalHead = [ordered]@{ state = 'missing' }
    }
    $feedCasSha256 = & $stateModule {
        param($Value)
        Get-ProductionStableFeedPromotionDomainDigest `
            -Domain 'ensou-dsh-launcher-feed-promotion-cas-v1' `
            -Value $Value
    } $feedCas
    $payloadSetSha256 = & $stateModule {
        param($Value)
        Get-ProductionStableFeedPromotionDomainDigest `
            -Domain 'ensou-dsh-launcher-feed-promotion-payload-set-v1' `
            -Value $Value
    } @($requestFiles)
    $request = [ordered]@{
        schemaVersion = 1
        requestType = 'ensou-dsh-launcher-offline-feed-promotion-request'
        operationId = [Guid]::NewGuid().ToString('N')
        orchestrationId = $orchestrationId
        edition = 'Enterprise'
        exposureRing = 'stable'
        feedChannel = 'stable'
        publishScope = 'public-stable'
        releaseSetId = [string]$plan.releaseSetId
        sourceState = [ordered]@{
            schemaVersion = 2
            targetChannel = 'stable'
            revision = 8
            phase = 'PILOT_EVIDENCE_BOUND'
            planSizeBytes = [int64]$planInput.SizeBytes
            planSha256 = [string]$planInput.Sha256
            identitySizeBytes = [int64]$identityInput.SizeBytes
            identitySha256 = [string]$identityInput.Sha256
            headSizeBytes = [int64]$r8HeadBytes.LongLength
            headSha256 = $r8HeadSha256
            receiptChainStartRevision = 1
            receiptChainSha256 = $receiptChainSha256
            candidateReceiptSha256 = [string]$candidateReceiptInput.Sha256
        }
        expectedFeedIdentitySha256 = 'b' * 64
        feedCas = $feedCas
        feedCasSha256 = $feedCasSha256
        payloadSetSha256 = $payloadSetSha256
        files = @($requestFiles)
        authorizationTrust = $trust
        requestNonce = ConvertTo-TestBase64Url -Bytes ([byte[]](1..32))
        createdAtUtc = '2026-09-05T02:00:00Z'
        expiresAtUtc = '2026-09-05T02:30:00Z'
        productionAdmission = 'NO_GO'
        networkPublishPerformed = $false
    }
    $admissionRoot = Join-Path `
        (Join-Path $stateRoot 'requests') `
        'stable-feed-promotion.v1'
    [IO.Directory]::CreateDirectory($admissionRoot) | Out-Null
    $requestPath = Join-Path $admissionRoot 'request.v1.json'
    Write-CanonicalJson -Path $requestPath -Value $request
    $requestInput = Get-TestFileInput -Path $requestPath

    $promotionHead = [ordered]@{
        schemaVersion = 1
        stateType = 'ensou-dsh-launcher-offline-feed-promotion-state'
        operationId = [string]$request.operationId
        requestSha256 = [string]$requestInput.Sha256
        requestNonce = [string]$request.requestNonce
        sourceStateHeadSha256 = $r8HeadSha256
        payloadSetSha256 = $payloadSetSha256
        status = 'PROMOTION_REQUEST_READY'
        productionAdmission = 'NO_GO'
        networkPublishPerformed = $false
        updatedAtUtc = [string]$request.createdAtUtc
    }
    $promotionHeadPath = Join-Path $admissionRoot 'promotion-head.v1.json'
    Write-CanonicalJson -Path $promotionHeadPath -Value $promotionHead
    $promotionHeadInput = Get-TestFileInput -Path $promotionHeadPath

    $response = [ordered]@{
        schemaVersion = 1
        responseType = 'ensou-dsh-launcher-offline-feed-promotion-response'
        operationId = [string]$request.operationId
        orchestrationId = $orchestrationId
        edition = 'Enterprise'
        exposureRing = 'stable'
        feedChannel = 'stable'
        publishScope = 'public-stable'
        releaseSetId = [string]$plan.releaseSetId
        requestSha256 = [string]$requestInput.Sha256
        requestNonce = [string]$request.requestNonce
        basePromotionHeadSha256 = [string]$promotionHeadInput.Sha256
        sourceStateHeadSha256 = $r8HeadSha256
        payloadSetSha256 = $payloadSetSha256
        feedCasSha256 = $feedCasSha256
        decision = 'AUTHORIZE_OFFLINE_BUNDLE'
        completedAtUtc = '2026-09-05T02:10:00Z'
        requestExpiresAtUtc = [string]$request.expiresAtUtc
        productionAdmission = 'OFFLINE_BUNDLE_ONLY'
        networkPublishPerformed = $false
        authentication = [ordered]@{
            algorithm = 'ES256'
            keyId = [string]$trust.keyId
            purpose = 'feed-promotion-response'
            payloadType = 'ensou-dsh-launcher-feed-promotion-response-authentication-v1'
            value = 'A' * 86
        }
    }
    $authenticationPayload = & $stateModule {
        param($Value)
        Get-ProductionStableFeedPromotionResponseAuthenticationPayload `
            -Response ([pscustomobject]$Value)
    } $response
    $response.authentication.value = ConvertTo-TestBase64Url -Bytes (
        New-TestLowSP256Signature `
            -Signer $signer `
            -Payload $authenticationPayload)
    $responsePath = Join-Path $admissionRoot 'response.v1.json'
    Write-CanonicalJson -Path $responsePath -Value $response
    $responseInput = Get-TestFileInput -Path $responsePath

    $bundleInventory = [Collections.Generic.List[object]]::new()
    $bundleInventory.Add([ordered]@{
        role = 'promotion-request'
        fileName = 'request.v1.json'
        relativePath = 'bundle/request.v1.json'
        sizeBytes = [int64]$requestInput.SizeBytes
        sha256 = [string]$requestInput.Sha256
    })
    $bundleInventory.Add([ordered]@{
        role = 'promotion-response'
        fileName = 'response.v1.json'
        relativePath = 'bundle/response.v1.json'
        sizeBytes = [int64]$responseInput.SizeBytes
        sha256 = [string]$responseInput.Sha256
    })
    foreach ($file in $requestFiles) {
        $bundleInventory.Add([ordered]@{
            role = [string]$file.role
            fileName = [string]$file.fileName
            relativePath = 'bundle/payload/' + [string]$file.fileName
            sizeBytes = [int64]$file.sizeBytes
            sha256 = [string]$file.sha256
        })
    }
    $bundleSetSha256 = & $stateModule {
        param($Value)
        Get-ProductionStableFeedPromotionDomainDigest `
            -Domain 'ensou-dsh-launcher-feed-promotion-offline-bundle-v1' `
            -Value $Value
    } @($bundleInventory)
    $bundleHead = [ordered]@{
        schemaVersion = 1
        stateType = 'ensou-dsh-launcher-offline-feed-promotion-bundle'
        operationId = [string]$request.operationId
        requestSha256 = [string]$requestInput.Sha256
        requestNonce = [string]$request.requestNonce
        sourceStateHeadSha256 = $r8HeadSha256
        payloadSetSha256 = $payloadSetSha256
        basePromotionHeadSha256 = [string]$promotionHeadInput.Sha256
        responseSha256 = [string]$responseInput.Sha256
        bundleSetSha256 = $bundleSetSha256
        status = 'EXTERNAL_PUBLISH_BUNDLE_READY'
        productionAdmission = 'NO_GO'
        networkPublishPerformed = $false
        updatedAtUtc = [string]$response.completedAtUtc
    }
    $bundleHeadPath = Join-Path $admissionRoot 'bundle-head.v1.json'
    Write-CanonicalJson -Path $bundleHeadPath -Value $bundleHead
    $bundleHeadInput = Get-TestFileInput -Path $bundleHeadPath

    $admissionFiles = [Collections.Generic.List[object]]::new()
    foreach ($file in $requestFiles) {
        $admissionFiles.Add([ordered]@{
            role = [string]$file.role
            fileName = [string]$file.fileName
            sizeBytes = [int64]$file.sizeBytes
            sha256 = [string]$file.sha256
        })
    }
    $admission = [ordered]@{
        schemaVersion = 1
        evidenceType = 'STABLE_PROMOTION_REQUESTED'
        orchestrationId = $orchestrationId
        edition = 'Enterprise'
        targetChannel = 'stable'
        exposureRing = 'stable'
        feedChannel = 'stable'
        publishScope = 'public-stable'
        releaseSetId = [string]$plan.releaseSetId
        sourceState = [ordered]@{
            revision = 8
            phase = 'PILOT_EVIDENCE_BOUND'
            planSha256 = [string]$planInput.Sha256
            identitySha256 = [string]$identityInput.Sha256
            headSha256 = $r8HeadSha256
            r8ReceiptSha256 = [string]$r8ReceiptInput.Sha256
            receiptChainSha256 = $receiptChainSha256
            candidateReceiptSha256 = [string]$candidateReceiptInput.Sha256
        }
        operationId = [string]$request.operationId
        feedFoundation = [ordered]@{
            expectedFeedIdentitySha256 = [string]$request.expectedFeedIdentitySha256
            expectedChannelHead = $feedCas.channelHead
            expectedJournalHead = $feedCas.journalHead
            feedCasSha256 = $feedCasSha256
        }
        payloadSetSha256 = $payloadSetSha256
        request = [ordered]@{
            fileName = 'request.v1.json'
            sizeBytes = [int64]$requestInput.SizeBytes
            sha256 = [string]$requestInput.Sha256
        }
        response = [ordered]@{
            fileName = 'response.v1.json'
            sizeBytes = [int64]$responseInput.SizeBytes
            sha256 = [string]$responseInput.Sha256
            keyId = [string]$response.authentication.keyId
            purpose = 'feed-promotion-response'
            payloadType = 'ensou-dsh-launcher-feed-promotion-response-authentication-v1'
            decision = 'AUTHORIZE_OFFLINE_BUNDLE'
            completedAtUtc = [string]$response.completedAtUtc
            requestExpiresAtUtc = [string]$request.expiresAtUtc
        }
        promotionHead = [ordered]@{
            fileName = 'promotion-head.v1.json'
            sizeBytes = [int64]$promotionHeadInput.SizeBytes
            sha256 = [string]$promotionHeadInput.Sha256
        }
        bundleHead = [ordered]@{
            fileName = 'bundle-head.v1.json'
            sizeBytes = [int64]$bundleHeadInput.SizeBytes
            sha256 = [string]$bundleHeadInput.Sha256
            bundleSetSha256 = $bundleSetSha256
            status = 'EXTERNAL_PUBLISH_BUNDLE_READY'
        }
        files = @($admissionFiles)
        productionAdmission = 'NO_GO'
        networkPublishPerformed = $false
    }
    $admissionPath = Join-Path $admissionRoot 'promotion-admission.v1.json'
    Write-CanonicalJson -Path $admissionPath -Value $admission
    $admissionInput = Get-TestFileInput -Path $admissionPath

    $preReceipt = Assert-ProductionStableFeedPromotionAdmission `
        -StateRoot $stateRoot `
        -Plan ([pscustomobject]$plan) `
        -Identity ([pscustomobject]$identity) `
        -IdentitySha256 ([string]$identityInput.Sha256) `
        -Receipts $receipts `
        -CommittedRevision 8 `
        -AdmittedRevision 8
    Assert-True `
        ($preReceipt.Sha256 -ceq [string]$admissionInput.Sha256 -and
         $preReceipt.BundleSetSha256 -ceq $bundleSetSha256 -and
         $preReceipt.ProductionAdmission -ceq 'NO_GO' -and
         -not $preReceipt.NetworkPublishPerformed) `
        'Committed r8 pre-receipt recovery did not return the exact NO_GO admission.'

    Assert-Fails `
        -Action {
            Assert-ProductionStableFeedPromotionAdmission `
                -StateRoot $stateRoot `
                -Plan ([pscustomobject]$plan) `
                -Identity ([pscustomobject]$identity) `
                -IdentitySha256 ([string]$identityInput.Sha256) `
                -Receipts $receipts `
                -CommittedRevision 7 `
                -AdmittedRevision 8 | Out-Null
        } `
        -Expected 'outside the committed Enterprise Stable r8 lifecycle' `
        -Message 'Stable promotion state was accepted before committed r8.'

    $r9Receipt = [pscustomobject][ordered]@{
        revision = 9
        phase = 'STABLE_PROMOTION_REQUESTED'
        recordedAtUtc = '2026-09-05T02:11:00Z'
        data = [ordered]@{
            evidenceType = 'STABLE_PROMOTION_REQUESTED'
            relativePath =
                'requests/stable-feed-promotion.v1/promotion-admission.v1.json'
            sha256 = [string]$admissionInput.Sha256
        }
    }
    $receipts.Add($r9Receipt)
    $orphan = Assert-ProductionStableFeedPromotionAdmission `
        -StateRoot $stateRoot `
        -Plan ([pscustomobject]$plan) `
        -Identity ([pscustomobject]$identity) `
        -IdentitySha256 ([string]$identityInput.Sha256) `
        -Receipts $receipts `
        -CommittedRevision 8 `
        -AdmittedRevision 9
    Assert-True `
        ($orphan.RelativePath -ceq
            'requests/stable-feed-promotion.v1/promotion-admission.v1.json') `
        'R9 orphan recovery did not bind the fixed admission relative path.'

    $receipts[8].data.sha256 = 'f' * 64
    Assert-Fails `
        -Action {
            Assert-ProductionStableFeedPromotionAdmission `
                -StateRoot $stateRoot `
                -Plan ([pscustomobject]$plan) `
                -Identity ([pscustomobject]$identity) `
                -IdentitySha256 ([string]$identityInput.Sha256) `
                -Receipts $receipts `
                -CommittedRevision 8 `
                -AdmittedRevision 9 | Out-Null
        } `
        -Expected 'differs from its r9 receipt or orphan receipt' `
        -Message 'R9 orphan recovery accepted a receipt digest mismatch.'
    $receipts[8].data.sha256 = [string]$admissionInput.Sha256

    $requestBytes = [IO.File]::ReadAllBytes($requestPath)
    [IO.File]::WriteAllBytes(
        $requestPath,
        $requestBytes + [byte[]]@(0x20))
    Assert-Fails `
        -Action {
            Assert-ProductionStableFeedPromotionAdmission `
                -StateRoot $stateRoot `
                -Plan ([pscustomobject]$plan) `
                -Identity ([pscustomobject]$identity) `
                -IdentitySha256 ([string]$identityInput.Sha256) `
                -Receipts $receipts `
                -CommittedRevision 9 `
                -AdmittedRevision 9 | Out-Null
        } `
        -Expected 'canonical' `
        -Message 'Repeated r9 validation accepted noncanonical request bytes.'
    [IO.File]::WriteAllBytes($requestPath, $requestBytes)

    $admission.productionAdmission = 'GO'
    Write-CanonicalJson -Path $admissionPath -Value $admission
    Assert-Fails `
        -Action {
            Assert-ProductionStableFeedPromotionAdmission `
                -StateRoot $stateRoot `
                -Plan ([pscustomobject]$plan) `
                -Identity ([pscustomobject]$identity) `
                -IdentitySha256 ([string]$identityInput.Sha256) `
                -Receipts $receipts `
                -CommittedRevision 9 `
                -AdmittedRevision 9 | Out-Null
        } `
        -Expected 'schema' `
        -Message 'Stable admission upgraded NO_GO to GO.'
    $admission.productionAdmission = 'NO_GO'
    Write-CanonicalJson -Path $admissionPath -Value $admission

    [IO.File]::WriteAllBytes(
        (Join-Path $admissionRoot 'unexpected.json'),
        $utf8.GetBytes('{}'))
    Assert-Fails `
        -Action {
            Assert-ProductionStableFeedPromotionAdmission `
                -StateRoot $stateRoot `
                -Plan ([pscustomobject]$plan) `
                -Identity ([pscustomobject]$identity) `
                -IdentitySha256 ([string]$identityInput.Sha256) `
                -Receipts $receipts `
                -CommittedRevision 9 `
                -AdmittedRevision 9 | Out-Null
        } `
        -Expected 'exact expected inventory' `
        -Message 'Stable promotion state accepted a sixth JSON file.'

    Assert-True `
        (Test-Json `
            -Json ([IO.File]::ReadAllText($admissionPath, $utf8)) `
            -SchemaFile (Join-Path $schemaRoot `
                'launcher-feed-promotion-admission-v1.schema.json') `
            -ErrorAction Stop) `
        'Stable feed-promotion admission fixture does not satisfy its schema.'

    Write-Output "Production stable feed-promotion state tests passed ($assertions assertions)."
}
finally {
    $signer.Dispose()
    if (Test-Path -LiteralPath $fixtureRoot) {
        Remove-Item -LiteralPath $fixtureRoot -Recurse -Force
    }
}
