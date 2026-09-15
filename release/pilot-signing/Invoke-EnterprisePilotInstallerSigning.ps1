#requires -Version 7.2

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)][string]$PolicyPath,
    [Parameter(Mandatory = $true)][string]$PlanPath,
    [Parameter(Mandatory = $true)][string]$RequestPath,
    [Parameter(Mandatory = $true)][string]$R6ReceiptPath,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{64}$')][string]$R6HeadSha256,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$')]
    [string]$OutputDirectoryName,
    [ValidateRange(100, 300000)][int]$SelfCheckTimeoutMilliseconds = 300000
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$executionModulePath = Join-Path $PSScriptRoot 'WindowsPilotSigningExecution.psm1'
$pilotSigningModulePath = Join-Path $PSScriptRoot 'WindowsPilotSigning.psm1'
$stateModulePath = Join-Path $PSScriptRoot '..\scripts\ProductionReleaseState.psm1'
$contractsModulePath = Join-Path $PSScriptRoot '..\scripts\InstallerSigningContracts.psm1'
$payloadSelfCheckModulePath = Join-Path `
    $PSScriptRoot '..\scripts\EnterpriseInstallerProductionPayloadSelfCheck.psm1'
$schemaRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\schemas'))
$planSchemaPath = Join-Path $schemaRoot 'launcher-production-release-plan-v2.schema.json'
$requestSchemaPath = Join-Path $schemaRoot 'launcher-enterprise-installer-signing-request-v2.schema.json'
$responseSchemaPath = Join-Path $schemaRoot 'launcher-installer-signing-response-v1.schema.json'
$stateSchemaPath = Join-Path $schemaRoot 'launcher-production-release-state-v2.schema.json'
$trustedBuildSchemaPath = Join-Path $schemaRoot 'enterprise-installer-trusted-build-evidence-v1.schema.json'
$utf8Strict = [Text.UTF8Encoding]::new($false, $true)
Microsoft.PowerShell.Core\Import-Module $executionModulePath -Force -ErrorAction Stop
Microsoft.PowerShell.Core\Import-Module $contractsModulePath -Force -ErrorAction Stop
Microsoft.PowerShell.Core\Import-Module $pilotSigningModulePath -Force -ErrorAction Stop
Microsoft.PowerShell.Core\Import-Module `
    $payloadSelfCheckModulePath -Force -ErrorAction Stop
Microsoft.PowerShell.Core\Import-Module $stateModulePath -Force -ErrorAction Stop

function Open-EnterprisePilotInstallerHeldJson {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label,
        [string]$SchemaPath = ''
    )
    $input = ProductionReleaseState\Open-ProductionReleaseInput `
        -Path $Path -Label $Label -MaximumBytes 64MB
    try {
        [byte[]]$bytes = ProductionReleaseState\Read-ProductionReleaseInputBytes `
            -Descriptor $input -Label $Label
        $value = ProductionReleaseState\ConvertFrom-StrictProductionJsonBytes `
            -Bytes $bytes -Label $Label -SchemaPath $SchemaPath
        $input | Add-Member -NotePropertyName Bytes -NotePropertyValue $bytes
        $input | Add-Member -NotePropertyName Value -NotePropertyValue $value
        [void](ProductionReleaseState\Assert-CanonicalProductionJsonInput `
            -JsonInput $input -Label $Label)
        return $input
    }
    catch {
        $input.Stream.Dispose()
        throw
    }
}

function Get-EnterprisePilotFileByRole {
    param(
        [Parameter(Mandatory = $true)][object[]]$Files,
        [Parameter(Mandatory = $true)][string]$Role,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $matches = @($Files | Where-Object { [string]$_.role -ceq $Role })
    if ($matches.Count -ne 1) {
        throw "$Label must contain exactly one '$Role' role."
    }
    return $matches[0]
}

function Assert-EnterprisePilotFileBytes {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][psobject]$Expected,
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][int64]$MaximumBytes
    )
    $input = ProductionReleaseState\Open-ProductionReleaseInput `
        -Path $Path -Label $Label -MaximumBytes $MaximumBytes
    try {
        if ([string]$input.FileName -cne [string]$Expected.fileName -or
            [int64]$input.SizeBytes -ne [int64]$Expected.sizeBytes -or
            [string]$input.Sha256 -cne [string]$Expected.sha256) {
            throw "$Label differs from its authenticated request identity."
        }
        [void](ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
            -Descriptor $input -Label $Label)
        return $true
    }
    finally {
        $input.Stream.Dispose()
    }
}

function Assert-EnterprisePilotExactInventory {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][Collections.IDictionary]$Expected,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $observation = WindowsPilotSigning\Get-WindowsNoFollowPathObservation `
        -Path $Path -ExpectedKind Directory
    if (-not [bool]$observation.safe -or [bool]$observation.reparseDetected) {
        throw "$Label must be an ordinary no-follow directory."
    }
    $items = @(Get-ChildItem -LiteralPath $Path -Force)
    if ($items.Count -ne $Expected.Count) {
        throw "$Label does not contain its exact inventory."
    }
    foreach ($item in $items) {
        if (-not $Expected.Contains($item.Name) -or
            [bool]$item.PSIsContainer -ne [bool]$Expected[$item.Name] -or
            ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Label contains an unexpected or linked entry."
        }
    }
    return $true
}

function Assert-EnterprisePilotInstallerRequestBundle {
    param(
        [Parameter(Mandatory = $true)][string]$RequestPath,
        [Parameter(Mandatory = $true)][string]$RequestRoot,
        [Parameter(Mandatory = $true)]$RequestInput
    )
    $request = $RequestInput.Value
    $requestFullPath = [IO.Path]::GetFullPath($RequestPath)
    $rootFullPath = [IO.Path]::GetFullPath($RequestRoot).TrimEnd('\')
    $bundleRoot = [IO.Path]::GetDirectoryName($requestFullPath)
    if ([IO.Path]::GetFileName($requestFullPath) -cne
            'installer-signing-request.v2.json' -or
        [IO.Path]::GetFileName($bundleRoot) -cne 'installer-signing.v2' -or
        [IO.Path]::GetDirectoryName($bundleRoot) -cne $rootFullPath) {
        throw 'Enterprise Installer signing request must be the canonical installer-signing.v2 bundle below the protected request root.'
    }
    [void](Assert-EnterprisePilotExactInventory `
        -Path $bundleRoot `
        -Expected ([ordered]@{
            'installer-signing-request.v2.json' = $false
            'unsigned' = $true
            'payload' = $true
            'trusted-build' = $true
        }) `
        -Label 'Enterprise Installer signing request bundle')
    $unsignedRoot = Join-Path $bundleRoot 'unsigned'
    [void](Assert-EnterprisePilotExactInventory `
        -Path $unsignedRoot `
        -Expected ([ordered]@{
            'Ensou.Dsh.Enterprise.Installer.exe' = $false
        }) `
        -Label 'Enterprise unsigned Installer bundle')
    $payloadExpected = [ordered]@{}
    foreach ($file in @($request.installerPayload.files)) {
        $payloadExpected[[string]$file.fileName] = $false
    }
    [void](Assert-EnterprisePilotExactInventory `
        -Path (Join-Path $bundleRoot 'payload') `
        -Expected $payloadExpected `
        -Label 'Enterprise Installer payload bundle')
    [void](Assert-EnterprisePilotExactInventory `
        -Path (Join-Path $bundleRoot 'trusted-build') `
        -Expected ([ordered]@{ 'trusted-build-evidence.v1.json' = $false }) `
        -Label 'Enterprise Installer trusted-build bundle')

    foreach ($file in @($request.installerPayload.files)) {
        [void](Assert-EnterprisePilotFileBytes `
            -Path (Join-Path (Join-Path $bundleRoot 'payload') ([string]$file.fileName)) `
            -Expected $file `
            -Label "Enterprise Installer payload '$($file.role)'" `
            -MaximumBytes 8GB)
    }
    $evidencePath = Join-Path `
        (Join-Path $bundleRoot 'trusted-build') `
        'trusted-build-evidence.v1.json'
    $evidenceInput = Open-EnterprisePilotInstallerHeldJson `
        -Path $evidencePath `
        -Label 'Enterprise Installer trusted-build evidence' `
        -SchemaPath $trustedBuildSchemaPath
    try {
        if ([int64]$evidenceInput.SizeBytes -ne
                [int64]$request.trustedBuildEvidence.sizeBytes -or
            [string]$evidenceInput.Sha256 -cne
                [string]$request.trustedBuildEvidence.sha256 -or
            [string]$evidenceInput.Value.sourceBuildInputs.inventorySha256 -cne
                [string]$request.sourceBuildInputSetSha256 -or
            [string]$evidenceInput.Value.buildExecution.targetBuildIdentitySha256 -cne
                [string]$request.buildExecution.targetBuildIdentitySha256 -or
            (InstallerSigningContracts\Get-InstallerSigningObjectSha256 `
                -Value $evidenceInput.Value.resourceBinding) -cne
                [string]$request.trustedBuildEvidence.resourceBindingSha256 -or
            [string]$evidenceInput.Value.signingRequestEligibility.status -cne
                'ELIGIBLE_FOR_PILOT_SIGNING' -or
            [string]$evidenceInput.Value.signingRequestEligibility.blocker -cne
                'INSTALLER_SIGNING_RESPONSE_REQUIRED' -or
            [string]$evidenceInput.Value.signingRequestEligibility.productionAdmission -cne
                'NO_GO') {
            throw 'Enterprise trusted-build evidence differs from the exact Installer request closure.'
        }
        [void](ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
            -Descriptor $evidenceInput -Label 'Enterprise Installer trusted-build evidence')
    }
    finally {
        $evidenceInput.Stream.Dispose()
    }
    return $bundleRoot
}

function Assert-EnterprisePilotR6ReceiptBinding {
    param(
        [Parameter(Mandatory = $true)]$ReceiptInput,
        [Parameter(Mandatory = $true)]$RequestInput,
        [Parameter(Mandatory = $true)][psobject]$Plan,
        [Parameter(Mandatory = $true)][string]$ExpectedHeadSha256
    )
    $receipt = $ReceiptInput.Value
    $request = $RequestInput.Value
    $data = $receipt.data
    $launcher = Get-EnterprisePilotFileByRole `
        -Files @($request.candidate.files) -Role 'launcher' `
        -Label 'Enterprise r5 candidate'
    $runtime = Get-EnterprisePilotFileByRole `
        -Files @($request.candidate.files) -Role 'runtime' `
        -Label 'Enterprise r5 candidate'
    if ([int]$receipt.schemaVersion -ne 2 -or
        [string]$receipt.receiptType -cne
            'ensou-dsh-launcher-production-release-transition' -or
        [string]$receipt.orchestrationId -cne [string]$request.orchestrationId -or
        [string]$receipt.edition -cne 'Enterprise' -or
        [string]$receipt.targetChannel -cne 'stable' -or
        [string]$receipt.planSha256 -cne [string]$request.planSha256 -or
        [int]$receipt.revision -ne 6 -or
        [string]$receipt.phase -cne 'INSTALLER_SIGNING_REQUESTED' -or
        [string]$receipt.previousReceiptSha256 -cne
            [string]$request.r5Evidence.receiptSha256 -or
        [string]$data.requestRelativePath -cne
            'requests/installer-signing.v2/installer-signing-request.v2.json' -or
        [string]$data.requestSha256 -cne [string]$RequestInput.Sha256 -or
        [string]$data.baseHeadSha256 -cne [string]$request.baseHeadSha256 -or
        [string]$data.baseReceiptSha256 -cne
            [string]$request.r5Evidence.receiptSha256 -or
        [string]$data.sourceBuildInputSetSha256 -cne
            [string]$request.sourceBuildInputSetSha256 -or
        [string]$data.targetBuildIdentitySha256 -cne
            [string]$request.buildExecution.targetBuildIdentitySha256 -or
        [string]$data.payloadSetSha256 -cne
            [string]$request.installerPayload.inventorySha256 -or
        [string]$data.r5LauncherSha256 -cne [string]$launcher.sha256 -or
        [string]$data.r5RuntimeSha256 -cne [string]$runtime.sha256 -or
        [string]$data.trustedBuildEvidenceRelativePath -cne
            'requests/installer-signing.v2/trusted-build/trusted-build-evidence.v1.json' -or
        [string]$data.trustedBuildEvidenceSha256 -cne
            [string]$request.trustedBuildEvidence.sha256 -or
        [string]$data.resourceBindingSha256 -cne
            [string]$request.trustedBuildEvidence.resourceBindingSha256 -or
        [string]$data.sdkFileClosureStatus -cne 'VERIFIED' -or
        [string]$data.signingRequestEligibilityStatus -cne
            'ELIGIBLE_FOR_PILOT_SIGNING' -or
        [string]$data.unsignedInstaller.fileName -cne
            'Ensou.Dsh.Enterprise.Installer.exe' -or
        [string]$data.unsignedInstaller.relativePath -cne
            'requests/installer-signing.v2/unsigned/Ensou.Dsh.Enterprise.Installer.exe' -or
        [int64]$data.unsignedInstaller.sizeBytes -ne
            [int64]$request.unsignedInstaller.sizeBytes -or
        [string]$data.unsignedInstaller.sha256 -cne
            [string]$request.unsignedInstaller.sha256 -or
        [string]$data.unsignedInstaller.peContentSha256 -cne
            [string]$request.unsignedInstaller.peContentSha256 -or
        [string]$data.createdAtUtc -cne [string]$request.createdAtUtc -or
        [string]$data.expiresAtUtc -cne [string]$request.expiresAtUtc -or
        [string]$data.authenticationKeyId -cne
            [string]$request.responseAuthentication.keyId -or
        [string]$data.authenticationPurpose -cne 'installer-signing-response' -or
        [string]$data.admissionReason -cne
            'INSTALLER_SIGNING_RESPONSE_REQUIRED' -or
        [string]$data.productionAdmission -cne 'NO_GO') {
        throw 'Enterprise r6 receipt is not bound to the exact Installer request closure.'
    }
    $transition = [ordered]@{
        transitionType = 'ensou-dsh-launcher-production-release-transition-v2'
        schemaVersion = 2
        targetChannel = 'stable'
        orchestrationId = [string]$receipt.orchestrationId
        edition = 'Enterprise'
        planSha256 = [string]$receipt.planSha256
        identitySha256 = [string]$receipt.identitySha256
        revision = 6
        phase = 'INSTALLER_SIGNING_REQUESTED'
        previousReceiptSha256 = [string]$receipt.previousReceiptSha256
        data = $data
    }
    $transitionSha256 = ProductionReleaseState\Get-ProductionSha256Bytes `
        -Bytes (ProductionReleaseState\ConvertTo-ProductionJsonBytes -Value $transition)
    if ([string]$receipt.transitionSha256 -cne $transitionSha256) {
        throw 'Enterprise r6 receipt transition SHA-256 is not canonical.'
    }
    $head = [ordered]@{
        schemaVersion = 2
        stateType = 'ensou-dsh-launcher-production-release-head'
        orchestrationId = [string]$receipt.orchestrationId
        edition = 'Enterprise'
        planSha256 = [string]$receipt.planSha256
        identitySha256 = [string]$receipt.identitySha256
        revision = 6
        phase = 'INSTALLER_SIGNING_REQUESTED'
        receiptFileName = '0006-installer-signing-requested.json'
        receiptSha256 = [string]$ReceiptInput.Sha256
        updatedAtUtc = [string]$receipt.recordedAtUtc
        targetChannel = 'stable'
    }
    $actualHeadSha256 = ProductionReleaseState\Get-ProductionSha256Bytes `
        -Bytes (ProductionReleaseState\ConvertTo-ProductionJsonBytes -Value $head)
    if ($actualHeadSha256 -cne $ExpectedHeadSha256) {
        throw 'Enterprise r6 receipt does not reconstruct the expected r6 CAS head.'
    }
    return $true
}

$policyInput = $null
$planInput = $null
$requestInput = $null
$r6ReceiptInput = $null
try {
    $policyInput = WindowsPilotSigningExecution\Read-WindowsPilotSigningPolicy `
        -Path $PolicyPath
    $planInput = Open-EnterprisePilotInstallerHeldJson `
        -Path $PlanPath -Label 'Enterprise Pilot production plan' `
        -SchemaPath $planSchemaPath
    $requestInput = Open-EnterprisePilotInstallerHeldJson `
        -Path $RequestPath -Label 'Enterprise Pilot Installer signing request' `
        -SchemaPath $requestSchemaPath
    $r6ReceiptInput = Open-EnterprisePilotInstallerHeldJson `
        -Path $R6ReceiptPath -Label 'Enterprise Pilot r6 signing-request receipt' `
        -SchemaPath $stateSchemaPath
    $policy = $policyInput.Value
    $plan = $planInput.Value
    $request = $requestInput.Value
    [void](WindowsPilotSigningExecution\Assert-WindowsPilotPolicyLane `
        -Policy $policy `
        -ExpectedExecutionAdmission 'ENTERPRISE_PILOT_SIGNING' `
        -ExpectedProfile 'EnterpriseTwoDevice')
    if ([int]$plan.schemaVersion -ne 2 -or
        [string]$plan.edition -cne 'Enterprise' -or
        [string]$plan.targetChannel -cne 'stable' -or
        [string]$request.edition -cne 'Enterprise' -or
        [string]$request.channel -cne 'stable' -or
        [string]$request.orchestrationId -cne [string]$plan.orchestrationId -or
        [string]$request.releaseSetId -cne [string]$plan.releaseSetId -or
        [string]$request.planSha256 -cne [string]$planInput.Sha256 -or
        [string]$request.sourceCommit -cne [string]$plan.sourceCommit -or
        [string]$policy.authenticode.certificateSha256 -cne
            [string]$plan.authenticodePolicy.signerSha256Thumbprint -or
        [int]$request.responseAuthentication.maximumResponseAgeMinutes -ne
            [int]$plan.authenticodePolicy.maximumResponseAgeMinutes -or
        [string]$request.r5Evidence.releaseManifestTrustSha256 -cne
            (InstallerSigningContracts\Get-InstallerSigningObjectSha256 `
                -Value $plan.releaseManifestTrust) -or
        [string]$request.r5Evidence.releaseCompatibilitySha256 -cne
            (InstallerSigningContracts\Get-InstallerSigningObjectSha256 `
                -Value $plan.releaseCompatibility)) {
        throw 'Enterprise Pilot Installer request is not bound to the exact stable plan and signing policy.'
    }
    $trust = $plan.externalResponseTrusts.installerSigning
    $keyPolicy = $policy.responseKeys.enterpriseInstallerSigning
    if ([string]$request.responseAuthentication.algorithm -cne 'ES256' -or
        [string]$request.responseAuthentication.keyId -cne [string]$trust.keyId -or
        [string]$request.responseAuthentication.purpose -cne
            'installer-signing-response' -or
        [string]$request.responseAuthentication.payloadType -cne
            'ensou-dsh-launcher-installer-signing-response-authentication-v1' -or
        [string]$keyPolicy.keyId -cne [string]$trust.keyId -or
        [string]$keyPolicy.purpose -cne [string]$trust.purpose -or
        [string]$keyPolicy.x -cne [string]$trust.x -or
        [string]$keyPolicy.y -cne [string]$trust.y) {
        throw 'Enterprise Pilot Installer response key is not bound to plan trust.'
    }
    [void](InstallerSigningContracts\Assert-InstallerSigningRequestContract `
        -Request $request `
        -InstallerSigningTrust $trust `
        -ReleaseManifestTrust $plan.releaseManifestTrust)
    [void](Assert-EnterprisePilotR6ReceiptBinding `
        -ReceiptInput $r6ReceiptInput -RequestInput $requestInput `
        -Plan $plan -ExpectedHeadSha256 $R6HeadSha256)
    $created = ProductionReleaseState\ConvertFrom-ProductionUtc `
        -Value ([string]$request.createdAtUtc) `
        -Label 'Enterprise Installer signing request creation time'
    $expires = ProductionReleaseState\ConvertFrom-ProductionUtc `
        -Value ([string]$request.expiresAtUtc) `
        -Label 'Enterprise Installer signing request expiry time'
    $now = [DateTimeOffset]::UtcNow
    if ($expires -le $created -or $now -lt $created.AddMinutes(-5) -or
        $now -gt $expires) {
        throw 'Enterprise Pilot Installer signing request is not currently valid.'
    }
    $requestDirectory = Assert-EnterprisePilotInstallerRequestBundle `
        -RequestPath $requestInput.Path `
        -RequestRoot ([string]$policy.roots.requestRoot) `
        -RequestInput $requestInput
    $unsigned = $request.unsignedInstaller
    $sourcePath = [IO.Path]::GetFullPath((Join-Path `
        $requestDirectory ([string]$unsigned.relativePath).Replace('/', '\')))
    [void](InstallerSigningContracts\Assert-UnsignedInstallerSigningInput `
        -Path $sourcePath -Descriptor $unsigned)
    $target = [pscustomobject][ordered]@{
        role = 'installer'
        fileName = 'Ensou.Dsh.Enterprise.Installer.exe'
        sourcePath = $sourcePath
        sizeBytes = [int64]$unsigned.sizeBytes
        sha256 = [string]$unsigned.sha256
        peContentSha256 = [string]$unsigned.peContentSha256
    }
    $manifestPayload = Get-EnterprisePilotFileByRole `
        -Files @($request.installerPayload.files) `
        -Role 'install-manifest' -Label 'Enterprise Installer payload'
    $manifestInput = Open-EnterprisePilotInstallerHeldJson `
        -Path (Join-Path (Join-Path $requestDirectory 'payload') `
            ([string]$manifestPayload.fileName)) `
        -Label 'Enterprise install manifest payload'
    try {
        $installManifest = $manifestInput.Value
        ProductionReleaseState\Assert-ExactProductionJsonMembers `
            -Value $installManifest `
            -Expected @(
                'schemaVersion', 'layoutProfile', 'launcherReleaseId',
                'runtimeReleaseId', 'launcherArchive',
                'launcherArchiveSizeBytes', 'launcherArchiveSha256',
                'runtimeArchive', 'runtimeArchiveSizeBytes',
                'runtimeArchiveSha256', 'bootstrapperFile',
                'bootstrapperSizeBytes', 'bootstrapperSha256',
                'publishedAtUtc') `
            -Label 'Enterprise install manifest payload'
        $launcherPayload = Get-EnterprisePilotFileByRole `
            -Files @($request.installerPayload.files) `
            -Role 'launcher' -Label 'Enterprise Installer payload'
        $runtimePayload = Get-EnterprisePilotFileByRole `
            -Files @($request.installerPayload.files) `
            -Role 'runtime' -Label 'Enterprise Installer payload'
        $bootstrapperPayload = Get-EnterprisePilotFileByRole `
            -Files @($request.installerPayload.files) `
            -Role 'bootstrapper' -Label 'Enterprise Installer payload'
        if ([int]$installManifest.schemaVersion -ne 1 -or
            [string]$installManifest.layoutProfile -cne 'enterprise' -or
            [string]$installManifest.launcherArchive -cne [string]$launcherPayload.fileName -or
            [string]$installManifest.launcherArchiveSha256 -cne [string]$launcherPayload.sha256 -or
            [int64]$installManifest.launcherArchiveSizeBytes -ne [int64]$launcherPayload.sizeBytes -or
            [string]$installManifest.runtimeArchive -cne [string]$runtimePayload.fileName -or
            [string]$installManifest.runtimeArchiveSha256 -cne [string]$runtimePayload.sha256 -or
            [int64]$installManifest.runtimeArchiveSizeBytes -ne [int64]$runtimePayload.sizeBytes -or
            [string]$installManifest.bootstrapperFile -cne [string]$bootstrapperPayload.fileName -or
            [string]$installManifest.bootstrapperSha256 -cne [string]$bootstrapperPayload.sha256 -or
            [int64]$installManifest.bootstrapperSizeBytes -ne [int64]$bootstrapperPayload.sizeBytes) {
            throw 'Enterprise install manifest does not bind the exact production payload request.'
        }
        [void](ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
            -Descriptor $manifestInput -Label 'Enterprise install manifest payload')
    }
    finally {
        $manifestInput.Stream.Dispose()
    }
    $finalOutputPath = Join-Path `
        ([string]$policy.roots.outputRoot) $OutputDirectoryName
    if (-not $PSCmdlet.ShouldProcess(
            $finalOutputPath,
            'Sign the locked Enterprise Installer copy, execute its trusted payload self-check, and atomically commit the authenticated response')) {
        return [pscustomobject][ordered]@{
            status = 'WHAT_IF'
            productionAdmission = 'NO_GO'
            outputPath = [IO.Path]::GetFullPath($finalOutputPath)
        }
    }

    $responseBuilder = {
        param([object[]]$evidence, [string]$transactionPath)
        if ($evidence.Count -ne 1) {
            throw 'Enterprise Installer signing response requires exactly one evidence item.'
        }
        $item = $evidence[0]
        $signedInstaller = [ordered]@{
            role = 'installer'
            fileName = 'Ensou.Dsh.Enterprise.Installer.exe'
            relativePath = 'signed/Ensou.Dsh.Enterprise.Installer.exe'
            sizeBytes = [int64]$item.SizeBytes
            sha256 = [string]$item.SignedFileSha256
            peContentSha256 = [string]$item.PeContentSha256
            fullHashChangedFromUnsigned = $true
        }
        $authenticode = [ordered]@{
            status = 'Valid'
            signatureType = 'Authenticode'
            primarySignerCount = 1
            signerCertificateSha256 = [string]$item.SignerCertificateSha256
            signerDigestAlgorithmOid = [string]$item.SignerDigestAlgorithmOid
            spcIndirectDataContentTypeOid = [string]$item.SpcIndirectDataContentTypeOid
            spcPeImageDataTypeOid = [string]$item.SpcPeImageDataTypeOid
            spcDigestAlgorithmOid = [string]$item.SpcDigestAlgorithmOid
            spcPeContentSha256 = [string]$item.SpcPeContentSha256
            timestampProtocol = 'RFC3161'
            timestampTokenOid = [string]$item.TimestampTokenOid
            timestampContentTypeOid = [string]$item.TimestampContentTypeOid
            timestampSignerCertificateSha256 =
                [string]$item.TimestampSignerCertificateSha256
            timestampUtc = [string]$item.TimestampUtc
            rfc3161PrimarySignerBound = $true
        }
        $signedPath = Join-Path `
            (Join-Path $transactionPath 'signed') `
            'Ensou.Dsh.Enterprise.Installer.exe'
        $signedInput = ProductionReleaseState\Open-ProductionReleaseInput `
            -Path $signedPath -Label 'Signed Enterprise Installer self-check input' `
            -MaximumBytes 1GB
        try {
            $payloadSelfCheck =
                EnterpriseInstallerProductionPayloadSelfCheck\Invoke-EnterpriseInstallerProductionPayloadSelfCheck `
                -InstallerInput $signedInput `
                -Request $request `
                -InstallManifest $installManifest `
                -ExpectedSignerCertificateSha256 `
                    ([string]$policy.authenticode.certificateSha256) `
                -TimeoutMilliseconds $SelfCheckTimeoutMilliseconds `
                -MaximumOutputBytes ([int]$policy.limits.maximumProcessOutputBytes)
            [void](ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
                -Descriptor $signedInput `
                -Label 'Signed Enterprise Installer after payload self-check')
        }
        finally {
            $signedInput.Stream.Dispose()
        }
        $completed = [DateTimeOffset]::UtcNow
        if ($completed -lt $created -or $completed -gt $expires) {
            throw 'Enterprise Installer signing completed outside the request lifetime.'
        }
        $response = [ordered]@{
            schemaVersion = 1
            responseType = 'ensou-dsh-launcher-installer-signing-response'
            orchestrationId = [string]$request.orchestrationId
            edition = 'Enterprise'
            releaseSetId = [string]$request.releaseSetId
            channel = 'stable'
            planSha256 = [string]$request.planSha256
            sourceTree = [string]$request.sourceTree
            sourceBuildInputSetSha256 = [string]$request.sourceBuildInputSetSha256
            requestRelativePath =
                'requests/installer-signing.v2/installer-signing-request.v2.json'
            requestSha256 = [string]$requestInput.Sha256
            requestNonce = [string]$request.requestNonce
            baseHeadSha256 = [string]$request.baseHeadSha256
            admissionHeadSha256 = [string]$R6HeadSha256
            admissionRevision = 6
            r6ReceiptRelativePath = 'receipts/0006-installer-signing-requested.json'
            r6ReceiptSha256 = [string]$r6ReceiptInput.Sha256
            requestCreatedAtUtc = [string]$request.createdAtUtc
            requestExpiresAtUtc = [string]$request.expiresAtUtc
            completedAtUtc = ProductionReleaseState\ConvertTo-ProductionUtc `
                -Value $completed
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
            unsignedInstaller = $request.unsignedInstaller
            signedInstaller = $signedInstaller
            authenticode = $authenticode
            payloadSelfCheck = $payloadSelfCheck
            authentication = [ordered]@{
                algorithm = 'ES256'
                keyId = [string]$keyPolicy.keyId
                purpose = 'installer-signing-response'
                payloadType =
                    'ensou-dsh-launcher-installer-signing-response-authentication-v1'
                value = ''
            }
        }
        [byte[]]$payload =
            InstallerSigningContracts\Get-InstallerSigningResponseAuthenticationPayload `
                -Response ([pscustomobject]$response)
        $response.authentication.value =
            WindowsPilotSigningExecution\New-WindowsPilotEs256ResponseSignature `
                -Payload $payload -KeyPolicy $keyPolicy
        return $response
    }.GetNewClosure()

    $responseValidator = {
        param($generatedInput, [object[]]$evidence)
        if ($evidence.Count -ne 1) {
            throw 'Generated Enterprise Installer response requires one exact signing evidence item.'
        }
        $parsed = ProductionReleaseState\ConvertFrom-StrictProductionJsonBytes `
            -Bytes $generatedInput.Bytes `
            -Label 'Generated Enterprise Pilot Installer signing response' `
            -SchemaPath $responseSchemaPath
        $parsedInput = [pscustomobject]@{
            Value = $parsed
            Bytes = $generatedInput.Bytes
            Sha256 = $generatedInput.Sha256
        }
        [void](ProductionReleaseState\Assert-CanonicalProductionJsonInput `
            -JsonInput $parsedInput `
            -Label 'Generated Enterprise Pilot Installer signing response')
        [void](InstallerSigningContracts\Assert-InstallerSigningResponseContract `
            -RequestInput $requestInput `
            -ResponseInput $parsedInput `
            -R6HeadSha256 $R6HeadSha256 `
            -R6ReceiptSha256 ([string]$r6ReceiptInput.Sha256) `
            -InstallerSigningTrust $trust `
            -EnforceCurrentLifetime)
        $signedPath = Join-Path `
            (Join-Path ([IO.Path]::GetDirectoryName($generatedInput.Path)) 'signed') `
            'Ensou.Dsh.Enterprise.Installer.exe'
        $verified = InstallerSigningContracts\Assert-SignedInstallerAuthenticode `
            -Path $signedPath `
            -Response $parsed `
            -ExpectedSignerCertificateSha256 `
                ([string]$policy.authenticode.certificateSha256)
        if ([string]$verified.SignedInstallerSha256 -cne
                [string]$parsed.signedInstaller.sha256 -or
            [string]$verified.SignedInstallerSha256 -cne
                [string]$evidence[0].SignedFileSha256 -or
            [string]$verified.PeContentSha256 -cne
                [string]$evidence[0].PeContentSha256 -or
            [string]$parsed.payloadSelfCheck.inspectedInstallerSha256 -cne
                [string]$parsed.signedInstaller.sha256 -or
            [string]$parsed.payloadSelfCheck.resultSha256 -cne
                (EnterpriseInstallerProductionPayloadSelfCheck\Get-EnterpriseInstallerProductionPayloadSelfCheckResultSha256 `
                    -SelfCheck $parsed.payloadSelfCheck) -or
            [string]$parsed.authenticode.timestampProtocol -cne 'RFC3161') {
            throw 'Generated Enterprise Installer response did not survive exact Authenticode, RFC3161, and self-check import verification.'
        }
        return $true
    }.GetNewClosure()

    return WindowsPilotSigningExecution\Invoke-WindowsPilotSigningTransaction `
        -PolicyInput $policyInput `
        -Targets @($target) `
        -FinalOutputPath $finalOutputPath `
        -ResponseFileName 'installer-signing-response.v1.json' `
        -ResponseBuilder $responseBuilder `
        -ResponseValidator $responseValidator `
        -ExpectedExecutionAdmission 'ENTERPRISE_PILOT_SIGNING' `
        -ExpectedProfile 'EnterpriseTwoDevice'
}
finally {
    if ($null -ne $r6ReceiptInput) { $r6ReceiptInput.Stream.Dispose() }
    if ($null -ne $requestInput) { $requestInput.Stream.Dispose() }
    if ($null -ne $planInput) { $planInput.Stream.Dispose() }
    if ($null -ne $policyInput) { $policyInput.Stream.Dispose() }
}
