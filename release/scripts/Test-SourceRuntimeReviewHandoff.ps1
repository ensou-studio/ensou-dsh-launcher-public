#requires -Version 7.2
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Execute only the actual pure handoff functions, never the GitHub publisher.
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $PSScriptRoot 'Publish-SourceRuntimeCandidate.ps1'), [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Source publisher does not parse.' }
foreach ($name in @('Assert-ExactReleaseAssets', 'New-SourceRuntimeReviewEvidence')) {
    $functions = @($ast.FindAll({ param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name
    }, $false))
    if ($functions.Count -ne 1) { throw "Missing exact handoff function $name." }
    . ([scriptblock]::Create($functions[0].Extent.Text))
}
$script:checks = 0
function Assert-Handoff([bool]$Condition, [string]$Label) {
    if (-not $Condition) { throw $Label }; $script:checks++
}
function Assert-HandoffRejected([scriptblock]$Action) {
    $rejected = $false
    try { [void](& $Action) } catch { $rejected = $true }
    Assert-Handoff $rejected 'Malformed source-review evidence was accepted.'
}
function Copy-Handoff($Value) { $Value | ConvertTo-Json -Depth 20 | ConvertFrom-Json }
$names = @('runtime.zip', 'runtime.metadata.json', 'runtime.zip.sha256')
$uploaded = @(for ($i=0; $i -lt 3; $i++) {
    [pscustomobject]@{ Id=[long](100+$i); Name=$names[$i]; SizeBytes=[long](200+$i) }
})
$inputs = @(for ($i=0; $i -lt 3; $i++) {
    [pscustomobject]@{ Name=$names[$i]; File=[pscustomobject]@{Length=[long](200+$i)}; Sha256=([string]($i+1))*64 }
})
$release = [pscustomobject]@{
    id=[long]500; tag_name='managed-v2026.09.10.1'; target_commitish='b'*40
    immutable=$true; draft=$false
    assets=@(for ($i=0; $i -lt 3; $i++) {
        [pscustomobject]@{id=$uploaded[$i].Id; name=$names[$i]; size=$uploaded[$i].SizeBytes}
    })
}
$result = New-SourceRuntimeReviewEvidence 'ensou-studio/ensou-dsh-launcher' $release ('b'*40) $uploaded $inputs
Assert-Handoff ($result.authority -ceq 'UNSIGNED_REVIEW_INPUT_ONLY') 'Review output must not claim admission.'
Assert-Handoff ($result.sourceRelease.targetCommit -ceq ('b'*40)) 'Runtime build commit was lost.'
Assert-Handoff ($result.sourceRelease.githubReleaseId -eq 500) 'Immutable release numeric identity was lost.'
Assert-Handoff (@($result.sourceRelease.assets).Count -eq 3) 'Exact three assets were lost.'
for ($i=0; $i -lt 3; $i++) {
    $asset = $result.sourceRelease.assets[$i]
    Assert-Handoff ($asset.role -ceq @('archive','metadata','hash-evidence')[$i]) 'Asset role order changed.'
    Assert-Handoff ($asset.githubAssetId -eq $uploaded[$i].Id -and $asset.fileName -ceq $names[$i] -and
        $asset.sizeBytes -eq $uploaded[$i].SizeBytes -and $asset.sha256 -ceq $inputs[$i].Sha256) 'Exact asset descriptor was lost.'
}
Assert-HandoffRejected { New-SourceRuntimeReviewEvidence 'ensou-studio/ensou-dsh-launcher' $release ('c'*40) $uploaded $inputs }
foreach ($mutation in @(
    {param($r) $r.immutable=$false}, {param($r) $r.draft=$true},
    {param($r) $r.id=0}, {param($r) $r.id=9007199254740992L},
    {param($r) $r.assets[0].id=999}, {param($r) $r.assets[1].size=999},
    {param($r) $r.assets += $r.assets[0]}, {param($r) $r.tag_name='not-managed'}
)) {
    $changed = Copy-Handoff $release; & $mutation $changed
    Assert-HandoffRejected { New-SourceRuntimeReviewEvidence 'ensou-studio/ensou-dsh-launcher' $changed ('b'*40) $uploaded $inputs }
}
$badInputs = Copy-Handoff $inputs; $badInputs[1].Sha256='A'*64
Assert-HandoffRejected { New-SourceRuntimeReviewEvidence 'ensou-studio/ensou-dsh-launcher' $release ('b'*40) $uploaded $badInputs }
Assert-HandoffRejected { New-SourceRuntimeReviewEvidence '../wrong/repository' $release ('b'*40) $uploaded $inputs }
Write-Output "PASS Source runtime review handoff: $script:checks checks; unsigned fact-preservation only, no GitHub calls or admission."
