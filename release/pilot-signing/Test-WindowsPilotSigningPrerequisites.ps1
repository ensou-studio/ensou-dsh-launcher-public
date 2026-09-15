#requires -Version 7.2

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$SignToolPath,
    [Parameter(Mandatory = $true)][string]$ExpectedSignToolFileVersion,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedSignToolSha256,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-fA-F]{40}$')]
    [string]$CertificateStoreThumbprint,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedCertificateSha256,
    [Parameter(Mandatory = $true)][string]$PilotRootCertificatePath,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedPilotRootCertificateSha256,
    [Parameter(Mandatory = $true)][string]$TsaUri,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{64}$')]
    [string]$ExpectedTsaUriSha256,
    [Parameter(Mandatory = $true)][string]$AllowedTargetRoot,
    [AllowEmptyCollection()][string[]]$TargetPath = @(),
    [AllowEmptyCollection()][string[]]$ExpectedTargetSha256 = @(),
    [ValidateRange(1, 365)][int]$MinimumCertificateValidityDays = 30
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = Join-Path $PSScriptRoot 'WindowsPilotSigning.psm1'
Microsoft.PowerShell.Core\Import-Module $modulePath -Force

$observation = Get-WindowsPilotSigningObservation @PSBoundParameters
$result = Test-WindowsPilotSigningObservation -Observation $observation
$result | ConvertTo-Json -Depth 16

if ($result.pilotSigningReadiness -cne 'READY_FOR_EXPLICIT_SIGNING_STEP') {
    exit 3
}
exit 0
