#requires -Version 7.2
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$orchestratorPath = Join-Path $PSScriptRoot 'Invoke-LauncherProductionRelease.ps1'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($orchestratorPath, [ref]$tokens, [ref]$errors)
if ($errors.Count -ne 0) { throw 'Production orchestrator syntax is invalid.' }
$selector = @($ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -ceq 'EnterpriseRuntimeProfile' })
if ($selector.Count -ne 1 -or $selector[0].DefaultValue.Value -cne 'enterprise-managed' -or
    $ast.ParamBlock.Parameters[-1].Name.VariablePath.UserPath -cne 'EnterpriseRuntimeProfile') {
    throw 'Runtime selector must preserve the legacy default and append after existing parameters.'
}
$allowed = @($selector[0].Attributes | Where-Object { $_.TypeName.Name -ceq 'ValidateSet' })
if ($allowed.Count -ne 1 -or ($allowed[0].PositionalArguments.Value -join ',') -cne 'enterprise-managed,enterprise-direct-local') {
    throw 'Runtime selector must allow exactly the two reviewed profiles.'
}
$calls = @($ast.FindAll({ param($node)
    $node -is [Management.Automation.Language.CommandAst] -and
        $node.CommandElements[0].Extent.Text -ceq '$metadataValidatorPath'
}, $true))
if ($calls.Count -ne 1 -or -not $calls[0].Extent.Text.Contains(
    '-ExpectedRuntimeProfile $EnterpriseRuntimeProfile', [StringComparison]::Ordinal)) {
    throw 'Production runtime admission lost its exact expected-profile forwarding.'
}

# Replay only the actual argument expression; no release plan, files or state are opened.
$metadataValidatorPath = {
    param($MetadataPath, $ArtifactPath, $ExpectedReleaseId, $ExpectedArtifactFileName,
        $ExpectedArtifactSha256, $ExpectedRuntimeProfile)
    [pscustomobject]@{Profile=$ExpectedRuntimeProfile;Metadata=$MetadataPath;Artifact=$ArtifactPath;Release=$ExpectedReleaseId}
}
$runtimeMetadataSnapshot = [pscustomobject]@{Path='unused-metadata'}
$runtimeArchiveSnapshot = [pscustomobject]@{Path='unused-archive'}
$runtimeArchive = [pscustomobject]@{FileName='unused.zip';Sha256=('a' * 64)}
$Plan = [pscustomobject]@{runtimeCandidate=[pscustomobject]@{releaseId='unused-release'}}
foreach ($EnterpriseRuntimeProfile in @('enterprise-managed','enterprise-direct-local')) {
    $result = @(& ([scriptblock]::Create($calls[0].Extent.Text)))
    if ($result.Count -ne 1 -or $result[0].Profile -cne $EnterpriseRuntimeProfile -or
        $result[0].Metadata -cne 'unused-metadata' -or $result[0].Artifact -cne 'unused-archive' -or
        $result[0].Release -cne 'unused-release') { throw 'Actual runtime admission argument expression changed.' }
}
$rejected = $false
try {
    & $orchestratorPath -Edition Personal -Phase Status -PlanPath 'not-opened' -StateRoot 'not-created' `
        -EnterpriseRuntimeProfile enterprise-direct-local | Out-Null
}
catch {
    if ($_.Exception.Message -cne 'Direct-local runtime selection is available only for Enterprise.') {
        throw 'Personal/direct selection failed for an unrelated reason.'
    }
    $rejected = $true
}
if (-not $rejected) { throw 'Personal accepted the Enterprise-only direct-local selection.' }
Write-Output 'PASS runtime profile legacy default, selector contract, two actual argument replays and Personal/direct early rejection; no release operation.'
