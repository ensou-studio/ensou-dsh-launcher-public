#requires -Version 7.2

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PayloadDirectory,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9A-Fa-f]{64}$')]
    [string]$SignerSha256Thumbprint,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9A-Fa-f]{64}$')]
    [string]$ExpectedLauncherArchiveSha256,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9A-Fa-f]{64}$')]
    [string]$ExpectedRuntimeArchiveSha256
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = Join-Path $PSScriptRoot 'EnterpriseProductionPayload.psm1'
Microsoft.PowerShell.Core\Import-Module -Name $modulePath -Force -ErrorAction Stop

EnterpriseProductionPayload\Test-EnterpriseProductionPayload @PSBoundParameters
