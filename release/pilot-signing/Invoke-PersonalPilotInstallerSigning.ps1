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
$stateModulePath = Join-Path $PSScriptRoot '..\scripts\ProductionReleaseState.psm1'
$contractsModulePath = Join-Path $PSScriptRoot '..\scripts\InstallerSigningContracts.psm1'
$pipelineModulePath = Join-Path $PSScriptRoot '..\scripts\PersonalInstallerSigningPipeline.psm1'
$selfCheckModulePath = Join-Path $PSScriptRoot '..\scripts\PersonalInstallerProductionPayloadSelfCheck.psm1'
$schemaRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\schemas'))
$planSchemaPath = Join-Path $schemaRoot 'launcher-production-release-plan-v2.schema.json'
$requestSchemaPath = Join-Path $schemaRoot 'personal-installer-signing-request-v2.schema.json'
$responseSchemaPath = Join-Path $schemaRoot 'personal-installer-signing-response-v2.schema.json'
Microsoft.PowerShell.Core\Import-Module $executionModulePath -Force -ErrorAction Stop
Microsoft.PowerShell.Core\Import-Module $pipelineModulePath -Force -ErrorAction Stop
Microsoft.PowerShell.Core\Import-Module $selfCheckModulePath -Force -ErrorAction Stop
Microsoft.PowerShell.Core\Import-Module $contractsModulePath -Force -ErrorAction Stop
Microsoft.PowerShell.Core\Import-Module $stateModulePath -Force -ErrorAction Stop

function Open-PersonalPilotInstallerHeldJson {
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

function Assert-PersonalPilotR6ReceiptBinding {
    param(
        [Parameter(Mandatory = $true)]$ReceiptInput,
        [Parameter(Mandatory = $true)]$RequestInput,
        [Parameter(Mandatory = $true)][psobject]$Plan,
        [Parameter(Mandatory = $true)][string]$ExpectedHeadSha256
    )
    $receipt = $ReceiptInput.Value
    $request = $RequestInput.Value
    $expectedMembers = @(
        'schemaVersion', 'receiptType', 'orchestrationId', 'edition',
        'targetChannel', 'planSha256', 'identitySha256', 'revision', 'phase',
        'previousReceiptSha256', 'data', 'recordedAtUtc')
    ProductionReleaseState\Assert-ExactProductionJsonMembers `
        -Value $receipt -Expected $expectedMembers -Label 'Personal r6 receipt'
    $bindings =
        PersonalInstallerSigningPipeline\Get-PersonalInstallerSigningRequestBindings `
            -Request $request
    if ([int]$receipt.schemaVersion -ne 2 -or
        [string]$receipt.receiptType -cne
            'ensou-dsh-launcher-production-release-transition' -or
        [string]$receipt.orchestrationId -cne [string]$request.orchestrationId -or
        [string]$receipt.edition -cne 'Personal' -or
        [string]$receipt.targetChannel -cne 'pilot' -or
        [string]$receipt.planSha256 -cne [string]$request.planSha256 -or
        [int]$receipt.revision -ne 6 -or
        [string]$receipt.phase -cne 'INSTALLER_SIGNING_REQUESTED' -or
        [string]$receipt.data.requestRelativePath -cne
            'requests/installer-signing.v2/installer-signing-request.v2.json' -or
        [string]$receipt.data.requestSha256 -cne [string]$RequestInput.Sha256 -or
        [string]$receipt.data.baseHeadSha256 -cne [string]$request.baseHeadSha256 -or
        [string]$receipt.data.sourceSha256 -cne [string]$bindings.sourceSha256 -or
        [string]$receipt.data.payloadSha256 -cne [string]$bindings.payloadSha256 -or
        [string]$receipt.data.compiledTrustSha256 -cne
            [string]$bindings.compiledTrustSha256 -or
        [string]$receipt.data.toolchainSha256 -cne [string]$bindings.toolchainSha256 -or
        [string]$receipt.data.buildExecutionSha256 -cne
            [string]$bindings.buildExecutionSha256 -or
        [string]$receipt.data.resourceBindingSha256 -cne
            [string]$bindings.resourceBindingSha256 -or
        [string]$receipt.data.trustedBuildEvidenceSha256 -cne
            [string]$bindings.trustedBuildEvidenceSha256 -or
        [string]$receipt.data.admissionSha256 -cne [string]$bindings.admissionSha256 -or
        [string]$receipt.data.authenticationKeyId -cne
            [string]$request.responseAuthentication.keyId -or
        [string]$receipt.data.authenticationPurpose -cne
            'personal-installer-signing-response' -or
        [string]$receipt.data.authenticationPayloadType -cne
            'ensou-dsh-personal-installer-signing-response-authentication-v2' -or
        [string]$receipt.data.productionAdmission -cne 'NO_GO') {
        throw 'Personal r6 receipt is not bound to the exact Installer request closure.'
    }
    $head = [ordered]@{
        schemaVersion = 2
        stateType = 'ensou-dsh-launcher-production-release-head'
        orchestrationId = [string]$receipt.orchestrationId
        edition = 'Personal'
        planSha256 = [string]$receipt.planSha256
        identitySha256 = [string]$receipt.identitySha256
        revision = 6
        phase = 'INSTALLER_SIGNING_REQUESTED'
        receiptFileName = '0006-installer-signing-requested.json'
        receiptSha256 = [string]$ReceiptInput.Sha256
        updatedAtUtc = [string]$receipt.recordedAtUtc
        targetChannel = 'pilot'
    }
    $actualHeadSha256 = ProductionReleaseState\Get-ProductionSha256Bytes `
        -Bytes (ProductionReleaseState\ConvertTo-ProductionJsonBytes -Value $head)
    if ($actualHeadSha256 -cne $ExpectedHeadSha256) {
        throw 'Personal r6 receipt does not reconstruct the expected r6 CAS head.'
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
    $planInput = Open-PersonalPilotInstallerHeldJson `
        -Path $PlanPath -Label 'Personal Pilot production plan' `
        -SchemaPath $planSchemaPath
    $requestInput = Open-PersonalPilotInstallerHeldJson `
        -Path $RequestPath -Label 'Personal Pilot Installer signing request' `
        -SchemaPath $requestSchemaPath
    $r6ReceiptInput = Open-PersonalPilotInstallerHeldJson `
        -Path $R6ReceiptPath -Label 'Personal Pilot r6 signing-request receipt'
    $policy = $policyInput.Value
    $plan = $planInput.Value
    $request = $requestInput.Value
    if ([string]$policy.executionAdmission -cne 'PERSONAL_PILOT_SIGNING' -or
        [string]$policy.profile -cne 'PersonalTwoDevice' -or
        [int]$plan.schemaVersion -ne 2 -or
        [string]$plan.edition -cne 'Personal' -or
        [string]$plan.targetChannel -cne 'pilot' -or
        [string]$request.edition -cne 'Personal' -or
        [string]$request.channel -cne 'pilot' -or
        [string]$request.orchestrationId -cne [string]$plan.orchestrationId -or
        [string]$request.releaseSetId -cne [string]$plan.releaseSetId -or
        [string]$request.planSha256 -cne [string]$planInput.Sha256 -or
        [string]$policy.authenticode.certificateSha256 -cne
            [string]$plan.authenticodePolicy.signerSha256Thumbprint) {
        throw 'Personal Pilot Installer request is not bound to the exact plan and signing policy.'
    }
    $trust = $plan.externalResponseTrusts.installerSigning
    $keyPolicy = $policy.responseKeys.personalInstallerSigning
    if ([string]$request.responseAuthentication.algorithm -cne 'ES256' -or
        [string]$request.responseAuthentication.keyId -cne [string]$trust.keyId -or
        [string]$request.responseAuthentication.purpose -cne
            'personal-installer-signing-response' -or
        [string]$request.responseAuthentication.payloadType -cne
            'ensou-dsh-personal-installer-signing-response-authentication-v2' -or
        [string]$keyPolicy.keyId -cne [string]$trust.keyId -or
        [string]$keyPolicy.purpose -cne [string]$trust.purpose -or
        [string]$keyPolicy.x -cne [string]$trust.x -or
        [string]$keyPolicy.y -cne [string]$trust.y) {
        throw 'Personal Pilot Installer response key is not bound to plan trust.'
    }
    [void](InstallerSigningContracts\Assert-InstallerSigningRequestContract `
        -Request $request -InstallerSigningTrust $trust)
    [void](Assert-PersonalPilotR6ReceiptBinding `
        -ReceiptInput $r6ReceiptInput -RequestInput $requestInput `
        -Plan $plan -ExpectedHeadSha256 $R6HeadSha256)
    $created = ProductionReleaseState\ConvertFrom-ProductionUtc `
        -Value ([string]$request.createdAtUtc) `
        -Label 'Personal Installer signing request creation time'
    $expires = ProductionReleaseState\ConvertFrom-ProductionUtc `
        -Value ([string]$request.expiresAtUtc) `
        -Label 'Personal Installer signing request expiry time'
    $now = [DateTimeOffset]::UtcNow
    if ($expires -le $created -or $now -lt $created.AddMinutes(-5) -or
        $now -gt $expires) {
        throw 'Personal Pilot Installer signing request is not currently valid.'
    }
    $requestDirectory = [IO.Path]::GetDirectoryName($requestInput.Path)
    $unsigned = $request.unsignedInstaller
    $target = [pscustomobject][ordered]@{
        role = 'installer'
        fileName = [string]$unsigned.fileName
        sourcePath = [IO.Path]::GetFullPath((Join-Path `
            $requestDirectory ([string]$unsigned.relativePath).Replace('/', '\')))
        sizeBytes = [int64]$unsigned.sizeBytes
        sha256 = [string]$unsigned.sha256
        peContentSha256 = [string]$unsigned.peContentSha256
    }
    $expectation =
        PersonalInstallerSigningPipeline\Get-PersonalSigningPipelinePayloadExpectation `
            -Request $request
    $requestBindings =
        PersonalInstallerSigningPipeline\Get-PersonalInstallerSigningRequestBindings `
            -Request $request
    $finalOutputPath = Join-Path `
        ([string]$policy.roots.outputRoot) $OutputDirectoryName
    if (-not $PSCmdlet.ShouldProcess(
            $finalOutputPath,
            'Sign the locked Personal Installer copy, run its production payload self-check, and atomically commit the authenticated response')) {
        return [pscustomobject][ordered]@{
            status = 'WHAT_IF'
            productionAdmission = 'NO_GO'
            outputPath = [IO.Path]::GetFullPath($finalOutputPath)
        }
    }

    $responseBuilder = {
        param([object[]]$evidence, [string]$transactionPath)
        if ($evidence.Count -ne 1) {
            throw 'Personal Installer signing response requires exactly one evidence item.'
        }
        $item = $evidence[0]
        $signedInstaller = [ordered]@{
            role = 'installer'
            fileName = 'Ensou.Dsh.Personal.Installer.exe'
            relativePath = 'signed/Ensou.Dsh.Personal.Installer.exe'
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
        $draft = [pscustomobject][ordered]@{
            unsignedInstaller = $request.unsignedInstaller
            signedInstaller = [pscustomobject]$signedInstaller
            authenticode = [pscustomobject]$authenticode
        }
        $signedPath = Join-Path `
            (Join-Path $transactionPath 'signed') `
            'Ensou.Dsh.Personal.Installer.exe'
        $signedInput = ProductionReleaseState\Open-ProductionReleaseInput `
            -Path $signedPath -Label 'Signed Personal Installer self-check input' `
            -MaximumBytes 1GB
        try {
            $payloadSelfCheck =
                PersonalInstallerProductionPayloadSelfCheck\Invoke-PersonalInstallerProductionPayloadSelfCheck `
                    -InstallerInput $signedInput `
                    -Response $draft `
                    -ExpectedSignerCertificateSha256 `
                        ([string]$policy.authenticode.certificateSha256) `
                    -Expectation $expectation `
                    -TimeoutMilliseconds $SelfCheckTimeoutMilliseconds
            [void](ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
                -Descriptor $signedInput `
                -Label 'Signed Personal Installer after payload self-check')
        }
        finally {
            $signedInput.Stream.Dispose()
        }
        $completed = [DateTimeOffset]::UtcNow
        if ($completed -lt $created -or $completed -gt $expires) {
            throw 'Personal Installer signing completed outside the request lifetime.'
        }
        $response = [ordered]@{
            schemaVersion = 2
            responseType = 'ensou-dsh-personal-installer-signing-response'
            orchestrationId = [string]$request.orchestrationId
            edition = 'Personal'
            releaseSetId = [string]$request.releaseSetId
            channel = 'pilot'
            planSha256 = [string]$request.planSha256
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
            requestBindings = $requestBindings
            unsignedInstaller = $request.unsignedInstaller
            signedInstaller = $signedInstaller
            authenticode = $authenticode
            payloadSelfCheck = $payloadSelfCheck
            authentication = [ordered]@{
                algorithm = 'ES256'
                keyId = [string]$keyPolicy.keyId
                purpose = 'personal-installer-signing-response'
                payloadType =
                    'ensou-dsh-personal-installer-signing-response-authentication-v2'
                value = ''
            }
        }
        [byte[]]$payload =
            PersonalInstallerSigningPipeline\Get-PersonalInstallerSigningResponseAuthenticationPayload `
                -Response ([pscustomobject]$response)
        $response.authentication.value =
            WindowsPilotSigningExecution\New-WindowsPilotEs256ResponseSignature `
                -Payload $payload -KeyPolicy $keyPolicy
        return $response
    }.GetNewClosure()

    $responseValidator = {
        param($generatedInput, [object[]]$evidence)
        $parsed = ProductionReleaseState\ConvertFrom-StrictProductionJsonBytes `
            -Bytes $generatedInput.Bytes `
            -Label 'Generated Personal Pilot Installer signing response' `
            -SchemaPath $responseSchemaPath
        $parsedInput = [pscustomobject]@{
            Value = $parsed
            Bytes = $generatedInput.Bytes
            Sha256 = $generatedInput.Sha256
        }
        [void](ProductionReleaseState\Assert-CanonicalProductionJsonInput `
            -JsonInput $parsedInput `
            -Label 'Generated Personal Pilot Installer signing response')
        [void](PersonalInstallerSigningPipeline\Assert-PersonalInstallerSigningResponseV2Contract `
            -RequestInput $requestInput `
            -ResponseInput $parsedInput `
            -R6HeadSha256 $R6HeadSha256 `
            -R6ReceiptSha256 ([string]$r6ReceiptInput.Sha256) `
            -InstallerSigningTrust $trust `
            -EnforceCurrentLifetime)
        $signedPath = Join-Path `
            (Join-Path ([IO.Path]::GetDirectoryName($generatedInput.Path)) 'signed') `
            'Ensou.Dsh.Personal.Installer.exe'
        $verified = InstallerSigningContracts\Assert-SignedInstallerAuthenticode `
            -Path $signedPath `
            -Response $parsed `
            -ExpectedSignerCertificateSha256 `
                ([string]$policy.authenticode.certificateSha256)
        if ([string]$verified.SignedInstallerSha256 -cne
                [string]$parsed.signedInstaller.sha256 -or
            [string]$parsed.payloadSelfCheck.inspectedInstallerSha256 -cne
                [string]$parsed.signedInstaller.sha256) {
            throw 'Generated Personal Installer response did not survive import-side verification.'
        }
        return $true
    }.GetNewClosure()

    return WindowsPilotSigningExecution\Invoke-WindowsPilotSigningTransaction `
        -PolicyInput $policyInput `
        -Targets @($target) `
        -FinalOutputPath $finalOutputPath `
        -ResponseFileName 'personal-installer-signing-response.v2.json' `
        -ResponseBuilder $responseBuilder `
        -ResponseValidator $responseValidator
}
finally {
    if ($null -ne $r6ReceiptInput) { $r6ReceiptInput.Stream.Dispose() }
    if ($null -ne $requestInput) { $requestInput.Stream.Dispose() }
    if ($null -ne $planInput) { $planInput.Stream.Dispose() }
    if ($null -ne $policyInput) { $policyInput.Stream.Dispose() }
}
