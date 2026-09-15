#requires -Version 7.2
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $PSScriptRoot 'Invoke-LauncherProductionRelease.ps1'), [ref]$tokens, [ref]$errors)
if ($errors.Count -ne 0) { throw 'Orchestrator syntax is invalid.' }
$name = 'WindowsPilotReadinessSchemaVersion'
$parameter = @($ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -ceq $name })
if ($parameter.Count -ne 1 -or $parameter[0].DefaultValue.Value -ne 1) { throw 'Selector default must be 1.' }
if ($ast.ParamBlock.Parameters[-2].Name.VariablePath.UserPath -cne $name -or
    $ast.ParamBlock.Parameters[-1].Name.VariablePath.UserPath -cne 'EnterpriseRuntimeProfile') {
    throw 'Keep the readiness selector position and append the new runtime selector after it.'
}
$attribute = @($parameter[0].Attributes | Where-Object { $_.TypeName.Name -ceq 'ValidateSet' })
if ($attribute.Count -ne 1 -or ($attribute[0].PositionalArguments.Value -join ',') -cne '1,2') {
    throw 'Selector must allow exactly 1 and 2.'
}
$calls = @($ast.FindAll({ param($node)
    $node -is [Management.Automation.Language.CommandAst] -and
        $node.CommandElements[0].Extent.Text -cin @('$PilotAdapterPath', '$enterprisePilotEvidenceAdapterPath')
}, $true))
if ($calls.Count -ne 2) { throw 'Expected binding and revalidation adapter calls.' }
$status = @($ast.FindAll({ param($node)
    $node -is [Management.Automation.Language.CommandAst] -and
        $node.GetCommandName() -ceq 'Get-EnterpriseRevalidatedProductionStatus'
}, $true))
if ($status.Count -ne 1 -or -not $status[0].Extent.Text.Contains(
    '-WindowsPilotReadinessSchemaVersion $WindowsPilotReadinessSchemaVersion', [StringComparison]::Ordinal)) {
    throw 'Status must forward the explicit version separately from nine evidence paths.'
}
# Replay only the actual argument expressions against a capture-only adapter;
# the production state, signing and publication bodies never execute.
$capture = {
    param($StateRoot, $ExpectedHeadSha256, $ExpectedR7HeadSha256, [switch]$RevalidateOnly,
        [ValidateSet(1, 2)][int]$WindowsPilotReadinessSchemaVersion = 1,
        $WindowsPilotEvidenceEnvelopePath, $WindowsPilotEvidenceBodyPath,
        $WindowsPilotVerificationReportPath, $WindowsPilotReadinessConfigPath,
        $WindowsPilotStoredReadinessReportPath, $WindowsPilotReplayedReadinessReportPath,
        $LocalDataCertificationReceiptPath, $StablePrivatePilotObservationPath,
        $PilotTrustPolicyPath, $OutputPath)
    [pscustomobject]@{Version=$WindowsPilotReadinessSchemaVersion;Paths=@(
        $WindowsPilotEvidenceEnvelopePath, $WindowsPilotEvidenceBodyPath,
        $WindowsPilotVerificationReportPath, $WindowsPilotReadinessConfigPath,
        $WindowsPilotStoredReadinessReportPath, $WindowsPilotReplayedReadinessReportPath,
        $LocalDataCertificationReceiptPath, $StablePrivatePilotObservationPath, $PilotTrustPolicyPath)}
}
$PilotAdapterPath = $capture
$enterprisePilotEvidenceAdapterPath = $capture
$State = [pscustomobject]@{StateRoot='not-opened'}
$r7StateRoot = 'not-opened'
$ExpectedHeadSha256 = 'a' * 64
$stagedPilotEvidencePath = 'not-created'
$EvidencePaths = @{}
foreach ($field in @('WindowsPilotEvidenceEnvelopePath', 'WindowsPilotEvidenceBodyPath',
    'WindowsPilotVerificationReportPath', 'WindowsPilotReadinessConfigPath',
    'WindowsPilotStoredReadinessReportPath', 'WindowsPilotReplayedReadinessReportPath',
    'LocalDataCertificationReceiptPath', 'StablePrivatePilotObservationPath', 'PilotTrustPolicyPath')) {
    Set-Variable -Name $field -Value "unused-$field"
    $EvidencePaths[$field] = "unused-$field"
}
foreach ($WindowsPilotReadinessSchemaVersion in @(1, 2)) {
    foreach ($call in $calls) {
        $result = @(& ([scriptblock]::Create($call.Extent.Text)))
        if ($result.Count -ne 1 -or $result[0].Version -ne $WindowsPilotReadinessSchemaVersion -or
            $result[0].Paths.Count -ne 9 -or @($result[0].Paths | Where-Object { -not $_ }).Count -ne 0) {
            throw 'Argument forwarding changed the version or nine evidence paths.'
        }
    }
}
foreach ($schema in @('enterprise-pilot-readiness-v2.schema.json', 'enterprise-pilot-readiness-report-v2.schema.json')) {
    if (-not $ast.Extent.Text.Contains("release/schemas/$schema", [StringComparison]::Ordinal)) {
        throw 'Direct readiness schema is missing from source inventory.'
    }
}
$orchestrator = Join-Path $PSScriptRoot 'Invoke-LauncherProductionRelease.ps1'
foreach ($negative in @(
    @{Edition='Enterprise';Version=3;Message='WindowsPilotReadinessSchemaVersion'},
    @{Edition='Personal';Version=2;Message='Versioned Windows Pilot readiness selection is available only for Enterprise.'}
)) {
    $rejected = $false
    try {
        & $orchestrator -Edition $negative.Edition -Phase Status `
            -PlanPath 'not-opened' -StateRoot 'not-created' `
            -WindowsPilotReadinessSchemaVersion $negative.Version | Out-Null
    }
    catch {
        if (-not $_.Exception.Message.Contains($negative.Message, [StringComparison]::Ordinal)) {
            throw 'Invalid selector failed for an unrelated reason.'
        }
        $rejected = $true
    }
    if (-not $rejected) { throw 'Invalid selector reached release processing.' }
}
Write-Host 'PASS default-v1/explicit-v2, four actual Bind/Revalidate argument replays and two early negative guards; no release operation.'
