#requires -Version 7.2

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)][string]$PolicyPath,
    [Parameter(Mandatory = $true)][string]$PlanPath,
    [Parameter(Mandatory = $true)][string]$RequestPath,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$')]
    [string]$OutputDirectoryName
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$executionModulePath = Join-Path $PSScriptRoot 'WindowsPilotSigningExecution.psm1'
$stateModulePath = Join-Path $PSScriptRoot '..\scripts\ProductionReleaseState.psm1'
$schemaRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\schemas'))
$planSchemaPath = Join-Path $schemaRoot 'launcher-production-release-plan-v2.schema.json'
$requestSchemaPath = Join-Path $schemaRoot 'launcher-external-signing-request-v1.schema.json'
$responseSchemaPath = Join-Path $schemaRoot 'launcher-external-signing-response-v1.schema.json'
Microsoft.PowerShell.Core\Import-Module $executionModulePath -Force -ErrorAction Stop
Microsoft.PowerShell.Core\Import-Module $stateModulePath -Force -ErrorAction Stop

function Open-PersonalPilotClientHeldJson {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][string]$SchemaPath
    )
    $input = ProductionReleaseState\Open-ProductionReleaseInput `
        -Path $Path -Label $Label -MaximumBytes 16MB
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

$policyInput = $null
$planInput = $null
$requestInput = $null
try {
    $policyInput = WindowsPilotSigningExecution\Read-WindowsPilotSigningPolicy `
        -Path $PolicyPath
    $planInput = Open-PersonalPilotClientHeldJson `
        -Path $PlanPath -Label 'Personal Pilot production plan' `
        -SchemaPath $planSchemaPath
    $requestInput = Open-PersonalPilotClientHeldJson `
        -Path $RequestPath -Label 'Personal Pilot client signing request' `
        -SchemaPath $requestSchemaPath
    $policy = $policyInput.Value
    $plan = $planInput.Value
    $request = $requestInput.Value
    if ([string]$policy.executionAdmission -cne 'PERSONAL_PILOT_SIGNING' -or
        [string]$policy.profile -cne 'PersonalTwoDevice' -or
        [int]$plan.schemaVersion -ne 2 -or
        [string]$plan.edition -cne 'Personal' -or
        [string]$plan.targetChannel -cne 'pilot' -or
        [string]$request.edition -cne 'Personal' -or
        [string]$request.orchestrationId -cne [string]$plan.orchestrationId -or
        [string]$request.releaseSetId -cne [string]$plan.releaseSetId -or
        [string]$request.planSha256 -cne [string]$planInput.Sha256 -or
        [string]$request.authenticode.signerSha256Thumbprint -cne
            [string]$plan.authenticodePolicy.signerSha256Thumbprint -or
        [string]$request.authenticode.signerSha256Thumbprint -cne
            [string]$policy.authenticode.certificateSha256 -or
        -not [bool]$request.authenticode.requireTrustedTimestamp) {
        throw 'Personal Pilot client request is not bound to the exact plan and signing policy.'
    }
    $trust = $plan.externalResponseTrusts.clientSigning
    $keyPolicy = $policy.responseKeys.clientSigning
    if ([string]$request.responseAuthentication.algorithm -cne 'ES256' -or
        [string]$request.responseAuthentication.keyId -cne [string]$trust.keyId -or
        [string]$request.responseAuthentication.purpose -cne
            'client-signing-response' -or
        [string]$request.responseAuthentication.payloadType -cne
            'ensou-dsh-launcher-external-signing-response-authentication-v2' -or
        [string]$keyPolicy.keyId -cne [string]$trust.keyId -or
        [string]$keyPolicy.purpose -cne [string]$trust.purpose -or
        [string]$keyPolicy.x -cne [string]$trust.x -or
        [string]$keyPolicy.y -cne [string]$trust.y) {
        throw 'Personal Pilot client response key is not bound to plan trust.'
    }
    $created = ProductionReleaseState\ConvertFrom-ProductionUtc `
        -Value ([string]$request.createdAtUtc) -Label 'Client signing request creation time'
    $expires = ProductionReleaseState\ConvertFrom-ProductionUtc `
        -Value ([string]$request.expiresAtUtc) -Label 'Client signing request expiry time'
    $now = [DateTimeOffset]::UtcNow
    if ($expires -le $created -or $now -lt $created.AddMinutes(-5) -or
        $now -gt $expires) {
        throw 'Personal Pilot client signing request is not currently valid.'
    }
    if (@($request.files).Count -ne 4) {
        throw 'Personal Pilot client signing request must contain exactly four files.'
    }
    $requestDirectory = [IO.Path]::GetDirectoryName($requestInput.Path)
    $targets = [Collections.Generic.List[object]]::new()
    foreach ($file in @($request.files)) {
        $targets.Add([pscustomobject][ordered]@{
            role = [string]$file.role
            fileName = [string]$file.fileName
            sourcePath = [IO.Path]::GetFullPath((Join-Path `
                $requestDirectory ([string]$file.relativePath).Replace('/', '\')))
            sizeBytes = [int64]$file.sizeBytes
            sha256 = [string]$file.sha256
            peContentSha256 = [string]$file.peContentSha256
        })
    }
    $finalOutputPath = Join-Path `
        ([string]$policy.roots.outputRoot) $OutputDirectoryName
    if (-not $PSCmdlet.ShouldProcess(
            $finalOutputPath,
            'Sign four locked Personal Pilot client copies and atomically commit the authenticated response')) {
        return [pscustomobject][ordered]@{
            status = 'WHAT_IF'
            productionAdmission = 'NO_GO'
            outputPath = [IO.Path]::GetFullPath($finalOutputPath)
        }
    }

    $responseBuilder = {
        param([object[]]$evidence, [string]$transactionPath)
        if ($evidence.Count -ne 4) {
            throw 'Client signing response requires exactly four signed evidence items.'
        }
        $completed = [DateTimeOffset]::UtcNow
        if ($completed -lt $created -or $completed -gt $expires) {
            throw 'Client signing completed outside the request lifetime.'
        }
        $files = [Collections.Generic.List[object]]::new()
        for ($index = 0; $index -lt $targets.Count; $index++) {
            $files.Add([ordered]@{
                role = [string]$targets[$index].role
                fileName = [string]$targets[$index].fileName
                relativePath = 'signed/' + [string]$targets[$index].fileName
                inputSha256 = [string]$targets[$index].sha256
                inputPeContentSha256 = [string]$targets[$index].peContentSha256
                sizeBytes = [int64]$evidence[$index].SizeBytes
                sha256 = [string]$evidence[$index].SignedFileSha256
                signedPeContentSha256 = [string]$evidence[$index].PeContentSha256
            })
        }
        $response = [ordered]@{
            schemaVersion = 1
            responseType = 'ensou-dsh-launcher-client-authenticode-signing-response'
            orchestrationId = [string]$request.orchestrationId
            edition = 'Personal'
            releaseSetId = [string]$request.releaseSetId
            planSha256 = [string]$request.planSha256
            requestSha256 = [string]$requestInput.Sha256
            requestNonce = [string]$request.nonce
            completedAtUtc = ProductionReleaseState\ConvertTo-ProductionUtc `
                -Value $completed
            files = $files
            authentication = [ordered]@{
                algorithm = 'ES256'
                keyId = [string]$keyPolicy.keyId
                purpose = 'client-signing-response'
                payloadType =
                    'ensou-dsh-launcher-external-signing-response-authentication-v2'
                value = ''
            }
        }
        [byte[]]$payload =
            ProductionReleaseState\Get-ProductionReleaseSigningResponseAuthenticationPayload `
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
            -Label 'Generated Personal Pilot client signing response' `
            -SchemaPath $responseSchemaPath
        $parsedInput = [pscustomobject]@{
            Value = $parsed
            Bytes = $generatedInput.Bytes
            Sha256 = $generatedInput.Sha256
        }
        [void](ProductionReleaseState\Assert-CanonicalProductionJsonInput `
            -JsonInput $parsedInput `
            -Label 'Generated Personal Pilot client signing response')
        if ([string]$parsed.orchestrationId -cne [string]$request.orchestrationId -or
            [string]$parsed.edition -cne 'Personal' -or
            [string]$parsed.releaseSetId -cne [string]$request.releaseSetId -or
            [string]$parsed.planSha256 -cne [string]$request.planSha256 -or
            [string]$parsed.requestSha256 -cne [string]$requestInput.Sha256 -or
            [string]$parsed.requestNonce -cne [string]$request.nonce -or
            [string]$parsed.authentication.keyId -cne [string]$trust.keyId -or
            @($parsed.files).Count -ne 4) {
            throw 'Generated Personal Pilot client response is not request-bound.'
        }
        $completed = ProductionReleaseState\ConvertFrom-ProductionUtc `
            -Value ([string]$parsed.completedAtUtc) -Label 'Client signing completion time'
        if ($completed -lt $created -or $completed -gt $expires -or
            $completed -gt [DateTimeOffset]::UtcNow.AddMinutes(1)) {
            throw 'Generated Personal Pilot client response lifetime is invalid.'
        }
        for ($index = 0; $index -lt 4; $index++) {
            $file = $parsed.files[$index]
            if ([string]$file.role -cne [string]$targets[$index].role -or
                [string]$file.fileName -cne [string]$targets[$index].fileName -or
                [string]$file.relativePath -cne
                    ('signed/' + [string]$targets[$index].fileName) -or
                [string]$file.inputSha256 -cne [string]$targets[$index].sha256 -or
                [string]$file.inputPeContentSha256 -cne
                    [string]$targets[$index].peContentSha256 -or
                [string]$file.sha256 -cne [string]$evidence[$index].SignedFileSha256 -or
                [string]$file.signedPeContentSha256 -cne
                    [string]$evidence[$index].PeContentSha256) {
                throw 'Generated Personal Pilot client response file evidence is not exact.'
            }
        }
        [void](ProductionReleaseState\Assert-ProductionReleaseSigningResponseAuthentication `
            -Response $parsed -Trust $trust)
        return $true
    }.GetNewClosure()

    return WindowsPilotSigningExecution\Invoke-WindowsPilotSigningTransaction `
        -PolicyInput $policyInput `
        -Targets ([object[]]$targets.ToArray()) `
        -FinalOutputPath $finalOutputPath `
        -ResponseFileName 'signing-response.v1.json' `
        -ResponseBuilder $responseBuilder `
        -ResponseValidator $responseValidator
}
finally {
    if ($null -ne $requestInput) { $requestInput.Stream.Dispose() }
    if ($null -ne $planInput) { $planInput.Stream.Dispose() }
    if ($null -ne $policyInput) { $policyInput.Stream.Dispose() }
}
