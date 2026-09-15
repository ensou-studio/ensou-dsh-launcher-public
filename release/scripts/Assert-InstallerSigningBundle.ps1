#requires -Version 7.2

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PlanPath,
    [Parameter(Mandatory = $true)][string]$RequestPath,
    [Parameter(Mandatory = $true)][string]$ResponsePath,
    [Parameter(Mandatory = $true)][string]$UnsignedInstallerPath,
    [Parameter(Mandatory = $true)][string]$SignedInstallerPath,
    [Parameter(Mandatory = $true)][string]$R6HeadPath,
    [Parameter(Mandatory = $true)][string]$R6ReceiptPath,
    [Parameter(Mandatory = $true)][string]$ExpectedSourceTree
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $IsWindows) {
    throw 'Installer r7 Authenticode admission must run on Windows.'
}
if ($ExpectedSourceTree -notmatch '^(?:[0-9a-f]{40}|[0-9a-f]{64})$') {
    throw 'ExpectedSourceTree must be one lowercase Git tree SHA.'
}

$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$stateModulePath = Join-Path $PSScriptRoot 'ProductionReleaseState.psm1'
$contractModulePath = Join-Path $PSScriptRoot 'InstallerSigningContracts.psm1'
$schemaRoot = Join-Path $repositoryRoot 'release\schemas'
$planSchemaPath = Join-Path `
    $schemaRoot 'launcher-production-release-plan-v2.schema.json'
$requestSchemaPath = Join-Path `
    $schemaRoot 'launcher-installer-signing-request-v1.schema.json'
$responseSchemaPath = Join-Path `
    $schemaRoot 'launcher-installer-signing-response-v1.schema.json'

Microsoft.PowerShell.Core\Import-Module $contractModulePath -Force -ErrorAction Stop
Microsoft.PowerShell.Core\Import-Module $stateModulePath -Force -ErrorAction Stop

$planInput = ProductionReleaseState\Read-StrictProductionJsonFile `
    -Path $PlanPath `
    -SchemaPath $planSchemaPath `
    -Label 'Production release plan v2'
[void](ProductionReleaseState\Assert-CanonicalProductionJsonInput `
    -JsonInput $planInput `
    -Label 'Production release plan v2')
$requestInput = Read-InstallerSigningContractInput `
    -Path $RequestPath `
    -SchemaPath $requestSchemaPath `
    -Label 'Installer signing r6 request'
$responseInput = Read-InstallerSigningContractInput `
    -Path $ResponsePath `
    -SchemaPath $responseSchemaPath `
    -Label 'Installer signing r7 response'

$plan = $planInput.Value
$request = $requestInput.Value
$response = $responseInput.Value
if ([string]$request.planSha256 -cne [string]$planInput.Sha256 -or
    [string]$request.orchestrationId -cne [string]$plan.orchestrationId -or
    [string]$request.edition -cne [string]$plan.edition -or
    [string]$request.releaseSetId -cne [string]$plan.releaseSetId -or
    [string]$request.channel -cne [string]$plan.targetChannel -or
    [string]$request.sourceCommit -cne [string]$plan.sourceCommit -or
    [string]$request.sourceTree -cne $ExpectedSourceTree -or
    [int]$request.responseAuthentication.maximumResponseAgeMinutes -ne
        [int]$plan.authenticodePolicy.maximumResponseAgeMinutes) {
    throw 'Installer r6 request differs from the exact plan and state source-tree identity.'
}

if ([IO.Path]::GetFileName([IO.Path]::GetFullPath($R6HeadPath)) -cne
        'head.json' -or
    [IO.Path]::GetFileName([IO.Path]::GetFullPath($R6ReceiptPath)) -cne
        '0006-installer-signing-requested.json') {
    throw 'r6 head or receipt uses a noncanonical filename.'
}
$r6HeadInput = ProductionReleaseState\Open-ProductionReleaseInput `
    -Path $R6HeadPath -Label 'r6 head' -MaximumBytes 8MB
$r6ReceiptInput = $null
try {
    $r6ReceiptInput = ProductionReleaseState\Open-ProductionReleaseInput `
        -Path $R6ReceiptPath -Label 'r6 receipt' -MaximumBytes 8MB
    [void](Assert-InstallerSigningRequestContract `
        -Request $request `
        -InstallerSigningTrust $plan.externalResponseTrusts.installerSigning `
        -ReleaseManifestTrust $plan.releaseManifestTrust)
    [void](Assert-UnsignedInstallerSigningInput `
        -Path $UnsignedInstallerPath `
        -Descriptor $request.unsignedInstaller)
    [void](Assert-InstallerSigningResponseContract `
        -RequestInput $requestInput `
        -ResponseInput $responseInput `
        -R6HeadSha256 ([string]$r6HeadInput.Sha256) `
        -R6ReceiptSha256 ([string]$r6ReceiptInput.Sha256) `
        -InstallerSigningTrust $plan.externalResponseTrusts.installerSigning `
        -EnforceCurrentLifetime)
    $authenticode = Assert-SignedInstallerAuthenticode `
        -Path $SignedInstallerPath `
        -Response $response `
        -ExpectedSignerCertificateSha256 `
            ([string]$plan.authenticodePolicy.signerSha256Thumbprint)
    [void](ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
        -Descriptor $r6HeadInput -Label 'r6 head')
    [void](ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
        -Descriptor $r6ReceiptInput -Label 'r6 receipt')

    [pscustomobject][ordered]@{
        schemaVersion = 1
        verificationType = 'ensou-dsh-launcher-installer-r6-r7-bundle'
        status = 'VERIFIED'
        edition = [string]$request.edition
        releaseSetId = [string]$request.releaseSetId
        channel = [string]$request.channel
        sourceTree = [string]$request.sourceTree
        requestSha256 = [string]$requestInput.Sha256
        responseSha256 = [string]$responseInput.Sha256
        signedInstallerSha256 = [string]$authenticode.SignedInstallerSha256
        peContentSha256 = [string]$authenticode.PeContentSha256
        authenticodeStatus = [string]$authenticode.AuthenticodeStatus
        productionAdmission = 'NO_GO'
        nextRequiredGate = 'ORCHESTRATION_R6_R7_INTEGRATION_AND_REAL_R8_EVIDENCE'
    }
}
finally {
    if ($null -ne $r6ReceiptInput) {
        $r6ReceiptInput.Stream.Dispose()
    }
    $r6HeadInput.Stream.Dispose()
}
