#requires -Version 7.4
[CmdletBinding()]
param(
    [string]$ManifestPath = (Join-Path $PSScriptRoot '..\..\.tmp\tencent-dsh-prerelease-20260910\installed-enterprise-lifecycle-06\evidence\02h-release-set-sequence-3.json'),
    [string]$ObservationPath = (Join-Path $PSScriptRoot '..\..\.tmp\tencent-dsh-prerelease-20260910\installed-enterprise-lifecycle-06\evidence\02i-real-launcher-automatic-update.json'),
    [string]$ExpectedReleaseId = 'launcher-development-e2e-v2',
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$ExpectedArchiveSha256 = 'cb613f8cab170f215a83e1f2bdbbb74c9713dc465d522b29337427f81894d671'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Require([bool]$Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function Expect-Rejected([scriptblock]$Action, [string]$Message) {
    $rejected = $false
    try {
        & $Action | Out-Null
    } catch {
        $rejected = $true
    }
    Require $rejected $Message
}

function Copy-Document($Value) {
    $Value | ConvertTo-Json -Depth 40 | ConvertFrom-Json -Depth 40
}

$lifecyclePath = Join-Path $PSScriptRoot 'Test-EnterpriseDevelopmentLifecycle.ps1'
$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    $lifecyclePath,
    [ref]$tokens,
    [ref]$parseErrors)
Require ($parseErrors.Count -eq 0) 'Lifecycle script does not parse.'
$definition = @($ast.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Get-EnterpriseDevelopmentExpectedLauncherArtifactUri'
}, $true))
Require ($definition.Count -eq 1) 'Expected Launcher URI helper definition is not unique.'
. ([scriptblock]::Create($definition[0].Extent.Text))

$manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json -Depth 40
$observation = Get-Content -LiteralPath $ObservationPath -Raw | ConvertFrom-Json -Depth 40
$expectedUri = Get-EnterpriseDevelopmentExpectedLauncherArtifactUri `
    -Manifest $manifest `
    -ExpectedReleaseId $ExpectedReleaseId `
    -ExpectedArchiveSha256 $ExpectedArchiveSha256
$accepted = @($observation.evidence.feedAuthorization.accepted)
Require (@($accepted | Where-Object {
    [string]$_.uri -ceq $expectedUri
}).Count -eq 1) 'Retained sequence-3 Launcher authorization URI was not accepted exactly once.'

foreach ($wrongUri in @(
    'https://updates.example/launcher.zip',
    $expectedUri.Replace('https://updates.example/', 'https://wrong.example/'),
    ($expectedUri + '?download=1')
)) {
    Require (-not ([string]$wrongUri -ceq $expectedUri)) "Non-exact observation URI was accepted: $wrongUri"
}

$otherComponent = Copy-Document $manifest
@($otherComponent.artifacts | Where-Object component -CEQ 'launcher')[0].component = 'runtime'
Expect-Rejected {
    Get-EnterpriseDevelopmentExpectedLauncherArtifactUri $otherComponent $ExpectedReleaseId $ExpectedArchiveSha256
} 'An artifact with another component was accepted as Launcher.'

$missing = Copy-Document $manifest
$missing.artifacts = @($missing.artifacts | Where-Object component -CNE 'launcher')
Expect-Rejected {
    Get-EnterpriseDevelopmentExpectedLauncherArtifactUri $missing $ExpectedReleaseId $ExpectedArchiveSha256
} 'A manifest without a Launcher artifact was accepted.'

$duplicate = Copy-Document $manifest
$duplicate.artifacts = @($duplicate.artifacts) + @((Copy-Document (@($duplicate.artifacts | Where-Object component -CEQ 'launcher')[0])))
Expect-Rejected {
    Get-EnterpriseDevelopmentExpectedLauncherArtifactUri $duplicate $ExpectedReleaseId $ExpectedArchiveSha256
} 'Duplicate target Launcher artifacts were accepted.'

$wrongHash = Copy-Document $manifest
@($wrongHash.artifacts | Where-Object component -CEQ 'launcher')[0].sha256 = ('0' * 64)
Expect-Rejected {
    Get-EnterpriseDevelopmentExpectedLauncherArtifactUri $wrongHash $ExpectedReleaseId $ExpectedArchiveSha256
} 'A target Launcher with the wrong hash was accepted.'

Write-Output 'PASS Enterprise Development Lifecycle Launcher audit URI contract'
