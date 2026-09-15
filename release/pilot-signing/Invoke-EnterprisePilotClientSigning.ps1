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
$pilotSigningModulePath = Join-Path $PSScriptRoot 'WindowsPilotSigning.psm1'
$stateModulePath = Join-Path $PSScriptRoot '..\scripts\ProductionReleaseState.psm1'
$contractsModulePath = Join-Path $PSScriptRoot '..\scripts\InstallerSigningContracts.psm1'
$schemaRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\schemas'))
$planSchemaPath = Join-Path $schemaRoot 'launcher-production-release-plan-v2.schema.json'
$requestSchemaPath = Join-Path $schemaRoot 'launcher-external-signing-request-v1.schema.json'
$responseSchemaPath = Join-Path $schemaRoot 'launcher-external-signing-response-v1.schema.json'
Microsoft.PowerShell.Core\Import-Module $executionModulePath -Force -ErrorAction Stop
Microsoft.PowerShell.Core\Import-Module $contractsModulePath -Force -ErrorAction Stop
Microsoft.PowerShell.Core\Import-Module $pilotSigningModulePath -Force -ErrorAction Stop
Microsoft.PowerShell.Core\Import-Module $stateModulePath -Force -ErrorAction Stop

function Open-EnterprisePilotClientHeldJson {
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

function Assert-EnterprisePilotClientRequestBundle {
    param(
        [Parameter(Mandatory = $true)][string]$RequestPath,
        [Parameter(Mandatory = $true)][string]$RequestRoot,
        [Parameter(Mandatory = $true)][psobject]$Request
    )
    $requestFullPath = [IO.Path]::GetFullPath($RequestPath)
    $rootFullPath = [IO.Path]::GetFullPath($RequestRoot).TrimEnd('\')
    $bundleRoot = [IO.Path]::GetDirectoryName($requestFullPath)
    if ([IO.Path]::GetFileName($requestFullPath) -cne 'signing-request.v1.json' -or
        [IO.Path]::GetFileName($bundleRoot) -cne 'client-signing.v1' -or
        [IO.Path]::GetDirectoryName($bundleRoot) -cne $rootFullPath) {
        throw 'Enterprise client signing request must be the canonical client-signing.v1 bundle below the protected request root.'
    }
    $bundleObservation = WindowsPilotSigning\Get-WindowsNoFollowPathObservation `
        -Path $bundleRoot -ExpectedKind Directory
    if (-not [bool]$bundleObservation.safe -or
        [bool]$bundleObservation.reparseDetected) {
        throw 'Enterprise client signing request bundle must not traverse filesystem links.'
    }
    $rootItems = @(Get-ChildItem -LiteralPath $bundleRoot -Force)
    if ($rootItems.Count -ne 2 -or
        @($rootItems | Where-Object { $_.Name -ceq 'signing-request.v1.json' -and -not $_.PSIsContainer }).Count -ne 1 -or
        @($rootItems | Where-Object { $_.Name -ceq 'unsigned' -and $_.PSIsContainer }).Count -ne 1 -or
        @($rootItems | Where-Object {
                ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
            }).Count -ne 0) {
        throw 'Enterprise client signing request bundle inventory is not exact.'
    }
    $unsignedRoot = Join-Path $bundleRoot 'unsigned'
    $unsignedObservation = WindowsPilotSigning\Get-WindowsNoFollowPathObservation `
        -Path $unsignedRoot -ExpectedKind Directory
    if (-not [bool]$unsignedObservation.safe -or
        [bool]$unsignedObservation.reparseDetected) {
        throw 'Enterprise client unsigned directory must not traverse filesystem links.'
    }
    $actual = @(Get-ChildItem -LiteralPath $unsignedRoot -Force)
    if ($actual.Count -ne @($Request.files).Count -or
        @($actual | Where-Object {
                $_.PSIsContainer -or
                ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
            }).Count -ne 0) {
        throw 'Enterprise client unsigned inventory is not exact.'
    }
    $actualNames = @($actual | ForEach-Object Name | Sort-Object -CaseSensitive)
    $expectedNames = @($Request.files | ForEach-Object { [string]$_.fileName } |
        Sort-Object -CaseSensitive)
    if (($actualNames -join [char]0) -cne ($expectedNames -join [char]0)) {
        throw 'Enterprise client unsigned filenames differ from the authenticated request.'
    }
    return $bundleRoot
}

$policyInput = $null
$planInput = $null
$requestInput = $null
try {
    $policyInput = WindowsPilotSigningExecution\Read-WindowsPilotSigningPolicy `
        -Path $PolicyPath
    $planInput = Open-EnterprisePilotClientHeldJson `
        -Path $PlanPath -Label 'Enterprise Pilot production plan' `
        -SchemaPath $planSchemaPath
    $requestInput = Open-EnterprisePilotClientHeldJson `
        -Path $RequestPath -Label 'Enterprise Pilot client signing request' `
        -SchemaPath $requestSchemaPath
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
        [string]$request.requestType -cne
            'ensou-dsh-launcher-client-authenticode-signing' -or
        [string]$request.edition -cne 'Enterprise' -or
        [string]$request.orchestrationId -cne [string]$plan.orchestrationId -or
        [string]$request.releaseSetId -cne [string]$plan.releaseSetId -or
        [string]$request.planSha256 -cne [string]$planInput.Sha256 -or
        [string]$request.authenticode.signerSha256Thumbprint -cne
            [string]$plan.authenticodePolicy.signerSha256Thumbprint -or
        [string]$request.authenticode.signerSha256Thumbprint -cne
            [string]$policy.authenticode.certificateSha256 -or
        -not [bool]$request.authenticode.requireTrustedTimestamp) {
        throw 'Enterprise Pilot client request is not bound to the exact stable plan and signing policy.'
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
        throw 'Enterprise Pilot client response key is not bound to plan trust.'
    }
    $created = ProductionReleaseState\ConvertFrom-ProductionUtc `
        -Value ([string]$request.createdAtUtc) `
        -Label 'Enterprise client signing request creation time'
    $expires = ProductionReleaseState\ConvertFrom-ProductionUtc `
        -Value ([string]$request.expiresAtUtc) `
        -Label 'Enterprise client signing request expiry time'
    $now = [DateTimeOffset]::UtcNow
    if ($expires -le $created -or
        ($expires - $created) -ne [TimeSpan]::FromMinutes(
            [int]$plan.authenticodePolicy.maximumResponseAgeMinutes) -or
        $now -lt $created.AddMinutes(-5) -or
        $now -gt $expires) {
        throw 'Enterprise Pilot client signing request lifetime is not exact or currently valid.'
    }
    $roles = @('bootstrapper', 'launcher', 'client-bootstrapper', 'maintenance')
    $fileNames = @(
        'Ensou.Dsh.Enterprise.Bootstrapper.exe',
        'Ensou.Dsh.Enterprise.Launcher.exe',
        'Ensou.Dsh.Enterprise.ClientBootstrapper.exe',
        'Ensou.Dsh.Enterprise.Maintenance.exe')
    if (@($request.files).Count -ne 4 -or
        @($plan.clientSigningInputs).Count -ne 4) {
        throw 'Enterprise Pilot client request must contain exactly four client roles.'
    }
    $requestDirectory = Assert-EnterprisePilotClientRequestBundle `
        -RequestPath $requestInput.Path `
        -RequestRoot ([string]$policy.roots.requestRoot) `
        -Request $request
    $targets = [Collections.Generic.List[object]]::new()
    for ($index = 0; $index -lt 4; $index++) {
        $file = $request.files[$index]
        $planned = $plan.clientSigningInputs[$index]
        if ([string]$file.role -cne $roles[$index] -or
            [string]$file.fileName -cne $fileNames[$index] -or
            [string]$file.relativePath -cne ('unsigned/' + $fileNames[$index]) -or
            [string]$planned.role -cne $roles[$index] -or
            [string]$planned.fileName -cne $fileNames[$index] -or
            [int64]$planned.sizeBytes -ne [int64]$file.sizeBytes -or
            [string]$planned.sha256 -cne [string]$file.sha256 -or
            [string]$planned.peContentSha256 -cne [string]$file.peContentSha256) {
            throw "Enterprise Pilot client role index $index differs from its canonical plan and request identity."
        }
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
    [void](ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
        -Descriptor $planInput -Label 'Enterprise Pilot production plan')
    [void](ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
        -Descriptor $requestInput -Label 'Enterprise Pilot client signing request')
    $finalOutputPath = Join-Path `
        ([string]$policy.roots.outputRoot) $OutputDirectoryName
    if (-not $PSCmdlet.ShouldProcess(
            $finalOutputPath,
            'Sign four locked Enterprise Pilot client copies and atomically commit the authenticated response')) {
        return [pscustomobject][ordered]@{
            status = 'WHAT_IF'
            productionAdmission = 'NO_GO'
            outputPath = [IO.Path]::GetFullPath($finalOutputPath)
        }
    }

    $responseBuilder = {
        param([object[]]$evidence, [string]$transactionPath)
        if ($evidence.Count -ne 4) {
            throw 'Enterprise client signing response requires exactly four signed evidence items.'
        }
        $completed = [DateTimeOffset]::UtcNow
        if ($completed -lt $created -or $completed -gt $expires) {
            throw 'Enterprise client signing completed outside the request lifetime.'
        }
        $files = [Collections.Generic.List[object]]::new()
        for ($index = 0; $index -lt 4; $index++) {
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
            edition = 'Enterprise'
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
            -Label 'Generated Enterprise Pilot client signing response' `
            -SchemaPath $responseSchemaPath
        $parsedInput = [pscustomobject]@{
            Value = $parsed
            Bytes = $generatedInput.Bytes
            Sha256 = $generatedInput.Sha256
        }
        [void](ProductionReleaseState\Assert-CanonicalProductionJsonInput `
            -JsonInput $parsedInput `
            -Label 'Generated Enterprise Pilot client signing response')
        if ([string]$parsed.orchestrationId -cne [string]$request.orchestrationId -or
            [string]$parsed.edition -cne 'Enterprise' -or
            [string]$parsed.releaseSetId -cne [string]$request.releaseSetId -or
            [string]$parsed.planSha256 -cne [string]$request.planSha256 -or
            [string]$parsed.requestSha256 -cne [string]$requestInput.Sha256 -or
            [string]$parsed.requestNonce -cne [string]$request.nonce -or
            [string]$parsed.authentication.keyId -cne [string]$trust.keyId -or
            @($parsed.files).Count -ne 4) {
            throw 'Generated Enterprise Pilot client response is not request-bound.'
        }
        $completed = ProductionReleaseState\ConvertFrom-ProductionUtc `
            -Value ([string]$parsed.completedAtUtc) `
            -Label 'Enterprise client signing completion time'
        if ($completed -lt $created -or $completed -gt $expires -or
            $completed -gt [DateTimeOffset]::UtcNow.AddMinutes(1)) {
            throw 'Generated Enterprise Pilot client response lifetime is invalid.'
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
                throw 'Generated Enterprise Pilot client response file evidence is not exact.'
            }
            $signedPath = Join-Path `
                (Join-Path ([IO.Path]::GetDirectoryName($generatedInput.Path)) 'signed') `
                ([string]$file.fileName)
            $importEvidence =
                InstallerSigningContracts\Get-ExactPeAuthenticodeEvidence `
                    -Path $signedPath `
                    -ExpectedSignerCertificateSha256 `
                        ([string]$policy.authenticode.certificateSha256) `
                    -ExpectedPeContentSha256 ([string]$targets[$index].peContentSha256)
            if ([string]$importEvidence.SignedFileSha256 -cne [string]$file.sha256 -or
                [int]$importEvidence.PrimarySignerCount -ne 1 -or
                [string]$importEvidence.TimestampProtocol -cne 'RFC3161' -or
                [bool]$importEvidence.LegacyCounterSignaturePresent) {
                throw 'Generated Enterprise client did not survive Authenticode and RFC3161 import-side verification.'
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
        -ResponseValidator $responseValidator `
        -ExpectedExecutionAdmission 'ENTERPRISE_PILOT_SIGNING' `
        -ExpectedProfile 'EnterpriseTwoDevice'
}
finally {
    if ($null -ne $requestInput) { $requestInput.Stream.Dispose() }
    if ($null -ne $planInput) { $planInput.Stream.Dispose() }
    if ($null -ne $policyInput) { $policyInput.Stream.Dispose() }
}
