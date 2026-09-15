#requires -Version 7.2

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$stateModulePath = Join-Path $repositoryRoot 'release\scripts\ProductionReleaseState.psm1'
$twoCleanProducerPath = Join-Path $repositoryRoot `
    'release\scripts\New-PersonalTwoCleanBuildEvidence.ps1'

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

Import-Module -Name $stateModulePath -Force -ErrorAction Stop

[byte[]]$empty = @()
[byte[]]$nonEmpty = [Text.Encoding]::ASCII.GetBytes('abc')
try {
    $tokens = $null
    $parseErrors = $null
    $producerAst = [Management.Automation.Language.Parser]::ParseFile(
        $twoCleanProducerPath,
        [ref]$tokens,
        [ref]$parseErrors)
    Assert-True ($parseErrors.Count -eq 0) `
        'The Personal two-clean producer has PowerShell parse errors.'
    $producerHasher = @($producerAst.FindAll({
                param($node)
                $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -ceq 'Get-Sha256Bytes'
            }, $true))
    Assert-True ($producerHasher.Count -eq 1) `
        'The Personal two-clean producer must define exactly one Get-Sha256Bytes helper.'
    . ([scriptblock]::Create($producerHasher[0].Extent.Text))

    $hashers = @(
        [pscustomobject]@{
            Name = 'ProductionReleaseState'
            GetEmpty = { Get-ProductionSha256Bytes -Bytes $empty }
            GetNonEmpty = { Get-ProductionSha256Bytes -Bytes $nonEmpty }
            GetNull = { Get-ProductionSha256Bytes -Bytes $null -ErrorAction Stop }
        },
        [pscustomobject]@{
            Name = 'PersonalTwoCleanProducer'
            GetEmpty = { Get-Sha256Bytes -Bytes $empty }
            GetNonEmpty = { Get-Sha256Bytes -Bytes $nonEmpty }
            GetNull = { Get-Sha256Bytes -Bytes $null -ErrorAction Stop }
        }
    )
    foreach ($hasher in $hashers) {
        Assert-True ((& $hasher.GetEmpty) -ceq
            'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855') `
            "$($hasher.Name) changed the empty transcript SHA-256 digest."
        Assert-True ((& $hasher.GetNonEmpty) -ceq
            'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad') `
            "$($hasher.Name) changed the non-empty transcript SHA-256 digest."

        $nullError = $null
        try { & $hasher.GetNull | Out-Null }
        catch { $nullError = $_.Exception }
        Assert-True ($null -ne $nullError -and
            $nullError.GetType().FullName -ceq
                'System.Management.Automation.ParameterBindingValidationException') `
            "$($hasher.Name) must reject null bytes with a binding validation error."
    }

    Write-Output 'PERSONAL-EMPTY-SHA256-CONTRACT-PASS'
}
finally {
    [Security.Cryptography.CryptographicOperations]::ZeroMemory($nonEmpty)
}
