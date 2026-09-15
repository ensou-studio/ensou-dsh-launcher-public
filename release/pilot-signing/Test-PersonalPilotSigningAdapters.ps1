#requires -Version 7.2

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-True {
    param([Parameter(Mandatory = $true)][bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

function Assert-SourceOrder {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string[]]$Needles,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $cursor = -1
    foreach ($needle in $Needles) {
        $index = $Source.IndexOf($needle, [StringComparison]::Ordinal)
        Assert-True ($index -gt $cursor) `
            "$Label must import '$needle' after the previous direct dependency."
        $cursor = $index
    }
}

$clientPath = Join-Path $PSScriptRoot 'Invoke-PersonalPilotClientSigning.ps1'
$installerPath = Join-Path $PSScriptRoot 'Invoke-PersonalPilotInstallerSigning.ps1'
$policySchemaPath = Join-Path `
    $PSScriptRoot '..\schemas\windows-pilot-signing-policy-v1.schema.json'
$policyExamplePath = Join-Path `
    $PSScriptRoot 'windows-pilot-signing-policy.example.json'
$executionModulePath = Join-Path $PSScriptRoot 'WindowsPilotSigningExecution.psm1'
$stateModulePath = Join-Path $PSScriptRoot '..\scripts\ProductionReleaseState.psm1'
$contractsModulePath = Join-Path $PSScriptRoot '..\scripts\InstallerSigningContracts.psm1'
$pipelineModulePath = Join-Path $PSScriptRoot '..\scripts\PersonalInstallerSigningPipeline.psm1'
$selfCheckModulePath = Join-Path $PSScriptRoot '..\scripts\PersonalInstallerProductionPayloadSelfCheck.psm1'

foreach ($path in @($clientPath, $installerPath)) {
    $tokens = $null
    $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile(
        [IO.Path]::GetFullPath($path), [ref]$tokens, [ref]$errors)
    Assert-True ($errors.Count -eq 0) "$(Split-Path $path -Leaf) must parse."
    $commands = @($ast.FindAll({
                param($node)
                $node -is [Management.Automation.Language.CommandAst]
            }, $true) | ForEach-Object { $_.GetCommandName() })
    foreach ($forbidden in @(
            'Start-Process', 'Invoke-WebRequest', 'Invoke-RestMethod',
            'New-SelfSignedCertificate', 'Export-PfxCertificate')) {
        Assert-True ($forbidden -cnotin $commands) `
            "$(Split-Path $path -Leaf) must not call $forbidden."
    }
    Assert-True (@($commands | Where-Object {
                $_ -match '(?:^|\\)Invoke-WindowsPilotSigningTransaction$'
            }).Count -eq 1) `
        "$(Split-Path $path -Leaf) must use the shared atomic transaction."
    $source = [IO.File]::ReadAllText($path)
    Assert-True ($source -match "ConfirmImpact\s*=\s*'High'") `
        "$(Split-Path $path -Leaf) must require high-impact confirmation."
    Assert-True ($source -match 'edition\s+-cne\s+''Personal''') `
        "$(Split-Path $path -Leaf) must reject non-Personal inputs."
}

$clientSource = [IO.File]::ReadAllText($clientPath)
Assert-SourceOrder `
    -Source $clientSource `
    -Needles @(
        '$executionModulePath -Force -ErrorAction Stop',
        '$stateModulePath -Force -ErrorAction Stop') `
    -Label 'Personal client adapter'
foreach ($required in @(
        'Get-ProductionReleaseSigningResponseAuthenticationPayload',
        'New-WindowsPilotEs256ResponseSignature',
        'Assert-ProductionReleaseSigningResponseAuthentication',
        'signing-response.v1.json')) {
    Assert-True ($clientSource.Contains($required)) `
        "Client adapter must retain $required."
}

$installerSource = [IO.File]::ReadAllText($installerPath)
Assert-SourceOrder `
    -Source $installerSource `
    -Needles @(
        '$executionModulePath -Force -ErrorAction Stop',
        '$pipelineModulePath -Force -ErrorAction Stop',
        '$selfCheckModulePath -Force -ErrorAction Stop',
        '$contractsModulePath -Force -ErrorAction Stop',
        '$stateModulePath -Force -ErrorAction Stop') `
    -Label 'Personal Installer adapter'
foreach ($required in @(
        'Assert-PersonalPilotR6ReceiptBinding',
        'Invoke-PersonalInstallerProductionPayloadSelfCheck',
        'Get-PersonalInstallerSigningResponseAuthenticationPayload',
        'New-WindowsPilotEs256ResponseSignature',
        'Assert-PersonalInstallerSigningResponseV2Contract',
        'Assert-SignedInstallerAuthenticode',
        'personal-installer-signing-response.v2.json')) {
    Assert-True ($installerSource.Contains($required)) `
        "Installer adapter must retain $required."
}

$example = [IO.File]::ReadAllText($policyExamplePath) |
    ConvertFrom-Json -Depth 32
$example.signTool | Add-Member -NotePropertyName unknown -NotePropertyValue $true
$mutated = $example | ConvertTo-Json -Depth 32 -Compress
Assert-True (-not [bool](Microsoft.PowerShell.Utility\Test-Json `
        -Json $mutated -SchemaFile $policySchemaPath `
        -ErrorAction SilentlyContinue)) `
    'Signing policy schema must reject nested SignTool properties.'
$example = [IO.File]::ReadAllText($policyExamplePath) |
    ConvertFrom-Json -Depth 32
$example.responseKeys.clientSigning |
    Add-Member -NotePropertyName privateMaterial -NotePropertyValue 'forbidden'
$mutated = $example | ConvertTo-Json -Depth 32 -Compress
Assert-True (-not [bool](Microsoft.PowerShell.Utility\Test-Json `
        -Json $mutated -SchemaFile $policySchemaPath `
        -ErrorAction SilentlyContinue)) `
    'Signing policy schema must reject response-key private material.'
$example = [IO.File]::ReadAllText($policyExamplePath) |
    ConvertFrom-Json -Depth 32
$example.tsa.PSObject.Properties.Remove('trustedSignerChains')
$mutated = $example | ConvertTo-Json -Depth 32 -Compress
Assert-True (-not [bool](Microsoft.PowerShell.Utility\Test-Json `
        -Json $mutated -SchemaFile $policySchemaPath `
        -ErrorAction SilentlyContinue)) `
    'Signing policy schema must require pre-approved TSA signer-chain identities.'
$example = [IO.File]::ReadAllText($policyExamplePath) |
    ConvertFrom-Json -Depth 32
$example.tsa.trustedSignerChains[0] |
    Add-Member -NotePropertyName subjectName -NotePropertyValue 'forbidden-unpinned-identity'
$mutated = $example | ConvertTo-Json -Depth 32 -Compress
Assert-True (-not [bool](Microsoft.PowerShell.Utility\Test-Json `
        -Json $mutated -SchemaFile $policySchemaPath `
        -ErrorAction SilentlyContinue)) `
    'Signing policy schema must reject unmodeled TSA signer-chain properties.'

# Execute both exact adapter import orders in a clean module table and invoke
# qualified commands afterward. This catches nested Import-Module -Force hiding
# a direct dependency, which parsing or source matching alone cannot detect.
$moduleNames = @(
    'WindowsPilotSigningExecution', 'WindowsPilotSigning',
    'ProductionReleaseState', 'InstallerSigningContracts',
    'PersonalInstallerSigningPipeline',
    'PersonalInstallerProductionPayloadSelfCheck')
Microsoft.PowerShell.Core\Remove-Module `
    $moduleNames -Force -ErrorAction SilentlyContinue
Microsoft.PowerShell.Core\Import-Module `
    $executionModulePath -Force -ErrorAction Stop
Microsoft.PowerShell.Core\Import-Module `
    $stateModulePath -Force -ErrorAction Stop
foreach ($commandName in @(
        'WindowsPilotSigningExecution\Assert-WindowsPilotPolicyLane',
        'ProductionReleaseState\Get-ProductionSha256Bytes')) {
    Assert-True ($null -ne (Get-Command $commandName -ErrorAction SilentlyContinue)) `
        "Personal client import order must expose '$commandName' at runtime."
}
$clientLane = WindowsPilotSigningExecution\Assert-WindowsPilotPolicyLane `
    -Policy ([pscustomobject]@{
        profile = 'PersonalTwoDevice'
        executionAdmission = 'PERSONAL_PILOT_SIGNING'
    }) `
    -ExpectedExecutionAdmission 'PERSONAL_PILOT_SIGNING' `
    -ExpectedProfile 'PersonalTwoDevice'
Assert-True ([string]$clientLane.Profile -ceq 'PersonalTwoDevice') `
    'Personal client runtime import probe must invoke the exact Personal lane.'

Microsoft.PowerShell.Core\Remove-Module `
    $moduleNames -Force -ErrorAction SilentlyContinue
Microsoft.PowerShell.Core\Import-Module `
    $executionModulePath -Force -ErrorAction Stop
Microsoft.PowerShell.Core\Import-Module `
    $pipelineModulePath -Force -ErrorAction Stop -WarningAction SilentlyContinue
Microsoft.PowerShell.Core\Import-Module `
    $selfCheckModulePath -Force -ErrorAction Stop
Microsoft.PowerShell.Core\Import-Module `
    $contractsModulePath -Force -ErrorAction Stop
Microsoft.PowerShell.Core\Import-Module `
    $stateModulePath -Force -ErrorAction Stop
foreach ($commandName in @(
        'WindowsPilotSigningExecution\Assert-WindowsPilotPolicyLane',
        'ProductionReleaseState\Get-ProductionSha256Bytes',
        'InstallerSigningContracts\Get-InstallerSigningObjectSha256',
        'PersonalInstallerSigningPipeline\Get-PersonalInstallerSigningResponseAuthenticationPayload',
        'PersonalInstallerProductionPayloadSelfCheck\Invoke-PersonalInstallerProductionPayloadSelfCheck')) {
    Assert-True ($null -ne (Get-Command $commandName -ErrorAction SilentlyContinue)) `
        "Personal Installer import order must expose '$commandName' at runtime."
}
$runtimeDigest = ProductionReleaseState\Get-ProductionSha256Bytes `
    -Bytes ([byte[]](1..4))
Assert-True ($runtimeDigest -ceq
    '9f64a747e1b97f131fabb6b447296c9b6f0201e79fb3c5356e6c77e89b6a806a') `
    'Personal Installer runtime import probe must invoke the direct state module.'

Write-Output 'PERSONAL-PILOT-SIGNING-ADAPTERS-PASS'
Write-Output 'PERSONAL-ADAPTER-MODULE-IMPORT-RUNTIME-PASS'
Write-Output 'NO-SIGNING-KEY-CERTIFICATE-NETWORK-OR-PUBLICATION-PERFORMED'
