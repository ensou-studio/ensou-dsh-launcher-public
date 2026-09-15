#requires -Version 7.2

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-True {
    param([Parameter(Mandatory = $true)][bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

$contractsPath = Join-Path $PSScriptRoot '..\scripts\InstallerSigningContracts.psm1'
$clientImporterPath = Join-Path $PSScriptRoot '..\scripts\Invoke-LauncherProductionRelease.ps1'
$module = Microsoft.PowerShell.Core\Import-Module `
    $contractsPath -Force -PassThru -ErrorAction Stop
Assert-True ('Get-ExactPeAuthenticodeEvidence' -cin
        @($module.ExportedCommands.Keys)) `
    'Exact Authenticode/RFC3161 verifier must be exported for both lanes.'

$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    [IO.Path]::GetFullPath($contractsPath), [ref]$tokens, [ref]$errors)
Assert-True ($errors.Count -eq 0) 'Installer signing contracts must parse.'
$functionAst = $ast.Find({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Get-ExactPeAuthenticodeEvidence'
    }, $true)
Assert-True ($null -ne $functionAst) `
    'Exact Authenticode/RFC3161 verifier function must exist.'
$commands = @($functionAst.FindAll({
            param($node)
            $node -is [Management.Automation.Language.CommandAst]
        }, $true) | ForEach-Object { $_.GetCommandName() })
foreach ($required in @(
        'Open-ProductionReleaseInput',
        'Read-ProductionReleaseInputBytes',
        'Get-AuthenticodeSignature',
        'Get-EmbeddedAuthenticodePrimaryEvidence',
        'Get-Rfc3161PrimarySignerTimestampUtc',
        'Assert-PeRfc3161Timestamp',
        'Assert-ProductionReleaseInputStillLocked')) {
    Assert-True (@($commands | Where-Object {
                $_ -match ('(?:^|\\)' + [regex]::Escape($required) + '$')
            }).Count -ge 1) `
        "Exact Authenticode verifier must call $required."
}
$source = $functionAst.Extent.Text
foreach ($required in @(
        'PrimarySignerCount = 1',
        "TimestampProtocol = 'RFC3161'",
        'LegacyCounterSignaturePresent = $false',
        'SignerDigestAlgorithmOid',
        'SpcPeContentSha256')) {
    Assert-True ($source.Contains($required)) `
        "Exact Authenticode verifier must return $required."
}
$clientImporterSource = [IO.File]::ReadAllText($clientImporterPath)
Assert-True ($clientImporterSource.Contains(
        'InstallerSigningContracts\Get-ExactPeAuthenticodeEvidence')) `
    'Client response import must reuse the exact Authenticode/RFC3161 verifier.'

Write-Output 'WINDOWS-PILOT-SIGNING-CONTRACTS-PASS'
Write-Output 'REAL-AUTHENTICODE-RFC3161-POSITIVE-FIXTURE-REMAINS-PENDING'
