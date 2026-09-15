#requires -Version 7.2

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$')]
    [string]$LauncherReleaseId,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^managed-v[0-9]{4}\.[0-9]{2}\.[0-9]{2}\.[1-9][0-9]*$')]
    [string]$RuntimeReleaseId,

    [Parameter(Mandatory = $true)][string]$LauncherPublishDirectory,
    [Parameter(Mandatory = $true)][string]$ClientBootstrapperPublishDirectory,
    [Parameter(Mandatory = $true)][string]$MaintenancePublishDirectory,
    [Parameter(Mandatory = $true)][string]$BootstrapperPublishDirectory,
    [Parameter(Mandatory = $true)][string]$RuntimeArchivePath,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9A-Fa-f]{64}$')]
    [string]$ExpectedLauncherArchiveSha256,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9A-Fa-f]{64}$')]
    [string]$ExpectedRuntimeArchiveSha256,

    [Parameter(Mandatory = $true)][string]$OutputDirectory,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9A-Fa-f]{64}$')]
    [string]$SignerSha256Thumbprint,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$')]
    [string]$PublishedAtUtc
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = Join-Path $PSScriptRoot 'EnterpriseProductionPayload.psm1'
Microsoft.PowerShell.Core\Import-Module -Name $modulePath -Force -ErrorAction Stop

EnterpriseProductionPayload\New-EnterpriseProductionPayload @PSBoundParameters
