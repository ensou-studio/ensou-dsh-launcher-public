#requires -Version 7.2
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$builderPath = Join-Path $PSScriptRoot 'build-source-runtime.ps1'
$builder = [IO.File]::ReadAllText($builderPath)
$null = [scriptblock]::Create($builder)
$guardEnd = $builder.IndexOf('$oldPath = $env:Path', [StringComparison]::Ordinal)
if ($guardEnd -lt 0) { throw 'Builder startup guard boundary not found.' }
# Execute only real parameter/selection guards, before environment, Git or build effects.
$guardSource = $builder.Substring(0, $guardEnd).Replace(
    '$PSScriptRoot', "'" + $PSScriptRoot.Replace("'", "''") + "'")
$guard = [scriptblock]::Create($guardSource + @'

[pscustomobject]@{
    variant = $PatchVariant
    index = $ManagedPatchIndexPath
    artifactType = $RuntimeArtifactType
    promotionEligible = $promotionEligible
}
'@)
$common = @{
    ReleaseId = 'managed-v2026.09.14.1'
    OfficialTag = 'dsh-v0.1.2-rc.1'
    OfficialCommit = 'a66e4702047846cdaa10c66c9d3df3951f5ea70d'
    NodeVersion = '24.19.0'
    RuntimeWebAuthProtocol = 'browser-launch-cookie-v1'
}
$script:passed = 0
function Assert-Case([bool]$Condition, [string]$Name) {
    if (-not $Condition) { throw "FAIL: $Name" }
    $script:passed++
    Write-Output "PASS: $Name"
}
function Invoke-Rejection([string]$Name, [hashtable]$Overrides, [string]$Message) {
    $arguments = $common.Clone()
    $arguments.EnterpriseDirectLocal = $true
    foreach ($overrideName in $Overrides.Keys) { $arguments[$overrideName] = $Overrides[$overrideName] }
    $errorMessage = $null
    try { $null = & $guard @arguments } catch { $errorMessage = $_.Exception.Message }
    Assert-Case ($null -ne $errorMessage -and $errorMessage.Contains($Message, [StringComparison]::Ordinal)) $Name
}

$legacy = & $guard @common
Assert-Case ($legacy.variant -ceq 'enterprise-managed-v1' -and
    $legacy.artifactType -ceq 'ensou-dsh-enterprise-managed-source-runtime' -and
    $legacy.index.EndsWith('upstream-patches\index.json', [StringComparison]::Ordinal)) 'default retains the exact old variant/index/artifact type'
$direct = & $guard @common -EnterpriseDirectLocal
Assert-Case ($direct.variant -ceq 'enterprise-direct-local-v1' -and
    $direct.artifactType -ceq 'ensou-dsh-enterprise-direct-local-source-runtime' -and
    $direct.index.EndsWith('upstream-patches\direct-local-index.v1.json', [StringComparison]::Ordinal)) 'direct-local requires the distinct installation-owned variant/index/artifact type'
$personal = & $guard @common -PersonalManagedUpdate
Assert-Case ($personal.variant -ceq 'enterprise-managed-v1') 'Personal default source variant remains unchanged'
$labArgs = $common.Clone()
$labArgs.ReleaseId = 'lab-direct-contract'
$lab = & $guard @labArgs -EnterpriseDirectLocal -LocalLab
Assert-Case ($lab.promotionEligible -eq $false) 'Lab direct-local remains non-promotable'
Invoke-Rejection 'mixed Personal and direct-local capabilities reject' @{ PersonalManagedUpdate = $true } 'cannot be combined'
Invoke-Rejection 'wrong direct-local source tag rejects' @{ OfficialTag = 'dsh-v0.1.2-alpha.3' } 'exact reviewed rc.1 source'
Invoke-Rejection 'wrong direct-local source commit rejects' @{ OfficialCommit = ('a' * 40) } 'exact reviewed rc.1 source'
Invoke-Rejection 'omitted browser protocol rejects' @{ RuntimeWebAuthProtocol = '' } 'explicit browser-launch-cookie-v1'
Invoke-Rejection 'legacy browser protocol rejects' @{ RuntimeWebAuthProtocol = 'legacy-clean-root-v1' } 'explicit browser-launch-cookie-v1'

$assembledSmoke = $builder.IndexOf('Invoke-EnterpriseDirectLocalSmoke $runtimeRoot', [StringComparison]::Ordinal)
$metadataWrite = $builder.IndexOf('Write-RuntimeProtocolMetadata $runtimeRoot', [StringComparison]::Ordinal)
$extractedSmoke = $builder.IndexOf('Invoke-EnterpriseDirectLocalSmoke $extractedRuntimeRoot', [StringComparison]::Ordinal)
$metadataOutput = $builder.IndexOf('$metadata | ConvertTo-Json', [StringComparison]::Ordinal)
Assert-Case ($assembledSmoke -gt 0 -and $metadataWrite -gt $assembledSmoke) 'built direct-local smoke precedes capability emission'
Assert-Case ($extractedSmoke -gt $metadataWrite -and $metadataOutput -gt $extractedSmoke) 'extracted runtime smoke precedes final artifact metadata'
Assert-Case ($builder.Contains('-PatchVariant $PatchVariant', [StringComparison]::Ordinal) -and
    $builder.Contains('-EnterpriseDirectLocal:$EnterpriseDirectLocal', [StringComparison]::Ordinal)) 'source selection and exact runtime capability are explicitly forwarded'
$remoteTypePrerequisite = $builder.IndexOf("'direct-local generated remote contracts'", [StringComparison]::Ordinal)
$changedTypeCheck = $builder.IndexOf("'managed changed-package type build'", [StringComparison]::Ordinal)
Assert-Case ($remoteTypePrerequisite -gt 0 -and $changedTypeCheck -gt $remoteTypePrerequisite) 'generated Host remote types precede direct-local client type validation'

function Get-SelectedBuilderInventory([string]$Name, [bool]$DirectLocal) {
    $assignments = @([scriptblock]::Create($builder).Ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.AssignmentStatementAst] -and
            $node.Left -is [Management.Automation.Language.VariableExpressionAst] -and
            $node.Left.VariablePath.UserPath -ceq $Name
    }.GetNewClosure(), $true))
    $initial = @($assignments | Where-Object Operator -EQ 'Equals')
    $addition = @($assignments | Where-Object Operator -EQ 'PlusEquals')
    if ($initial.Count -ne 1 -or $addition.Count -ne 1) {
        throw "Expected one literal base and one direct-only addition for $Name."
    }
    $parent = $addition[0].Parent
    while ($null -ne $parent -and $parent -isnot [Management.Automation.Language.IfStatementAst]) {
        $parent = $parent.Parent
    }
    if ($null -eq $parent -or $parent.Clauses.Count -ne 1 -or
        $parent.Clauses[0].Item1.Extent.Text -cne '$EnterpriseDirectLocal') {
        throw "$Name addition must stay under the exact direct-only selector."
    }
    foreach ($assignment in $assignments) {
        if (@($assignment.Right.FindAll({param($node)
            $node -is [Management.Automation.Language.CommandAst] -or
                $node -is [Management.Automation.Language.VariableExpressionAst]
        }, $true)).Count -ne 0) {
            throw "Inventory $Name must remain literal and side-effect free."
        }
    }
    . ([scriptblock]::Create($initial[0].Extent.Text))
    if ($DirectLocal) { . ([scriptblock]::Create($addition[0].Extent.Text)) }
    foreach ($entry in (Get-Variable -Name $Name -ValueOnly)) { [string]$entry }
}
$directTests = @(Get-SelectedBuilderInventory 'managedFocusedTestFiles' $true)
$legacyTests = @(Get-SelectedBuilderInventory 'managedFocusedTestFiles' $false)
$directManifestPath = Join-Path $PSScriptRoot '../upstream-patches/dsh-v0.1.2-rc.1/enterprise-direct-local-v1/manifest.json'
$directManifest = [IO.File]::ReadAllText($directManifestPath) | ConvertFrom-Json
$reviewedPaths = @($directManifest.files | ForEach-Object path)
foreach ($test in @(
    'apps/cli/tests/managed-runtime-update.spec.ts',
    'packages/host/webserver/tests/webserver.spec.ts',
    'packages/credentials/credentials-local/tests/drain.spec.ts',
    'packages/settings/settings/tests/settings.spec.ts'
)) {
    Assert-Case ($directTests -ccontains $test -and $legacyTests -cnotcontains $test) "real update barrier regression selected only for direct build: $test"
    Assert-Case ($reviewedPaths -ccontains $test) "selected regression is in the exact reviewed direct source patch: $test"
}
$directProjects = @(Get-SelectedBuilderInventory 'managedProjectConfigs' $true)
$legacyProjects = @(Get-SelectedBuilderInventory 'managedProjectConfigs' $false)
foreach ($project in @(
    'packages/host/webserver/tsconfig.json',
    'packages/credentials/credentials/tsconfig.json',
    'packages/credentials/credentials-local/tsconfig.json',
    'packages/settings/settings/tsconfig.json'
)) {
    Assert-Case ($directProjects -ccontains $project -and $legacyProjects -cnotcontains $project) "update barrier owner type project selected only for direct build: $project"
}
$receiptFunction = [scriptblock]::Create($builder).Ast.Find({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Read-EnterpriseDirectLocalSmokeReceipt'
}, $true)
if ($null -eq $receiptFunction) { throw 'Builder receipt validator is missing.' }
. ([scriptblock]::Create($receiptFunction.Extent.Text))
$positive = [ordered]@{
    status = 'PASS'; resultStatus = 'PASS'
    scope = 'BUILT_ENTERPRISE_DIRECT_LOCAL_RUNTIME_CAPABILITY_ONLY'
    cycles = 2; kernelBootstrapVerified = $true; settingsReadOnly = $true
    credentialsWritable = $true; exactChildExited = $true
    authenticationNegativesVerified = $true; launchRefusalsVerified = $true
    modelRequestsSent = 0; outputBytes = 1024
}
$positiveJson = $positive | ConvertTo-Json -Compress
$parsed = Read-EnterpriseDirectLocalSmokeReceipt $positiveJson
Assert-Case ($parsed.status -ceq 'PASS' -and $parsed.modelRequestsSent -eq 0) 'strict positive smoke receipt accepts'
function Assert-ReceiptRejected([string]$Text, [string]$Label) {
    $rejected = $false
    try { $null = Read-EnterpriseDirectLocalSmokeReceipt $Text } catch { $rejected = $true }
    Assert-Case $rejected $Label
}
foreach ($field in $positive.Keys) {
    $missing = $positiveJson | ConvertFrom-Json -AsHashtable
    $missing.Remove($field)
    Assert-ReceiptRejected ($missing | ConvertTo-Json -Compress) "missing receipt field $field rejects"
}
foreach ($field in @('kernelBootstrapVerified', 'settingsReadOnly', 'credentialsWritable',
    'exactChildExited', 'authenticationNegativesVerified', 'launchRefusalsVerified')) {
    foreach ($invalid in @($false, 'true', 1, $null)) {
        $changed = $positiveJson | ConvertFrom-Json -AsHashtable
        $changed[$field] = $invalid
        Assert-ReceiptRejected ($changed | ConvertTo-Json -Compress) "non-boolean-positive $field rejects"
    }
}
foreach ($case in @(
    @('status', 'pass'), @('resultStatus', 'FAIL'), @('scope', 'OTHER'),
    @('cycles', 1), @('cycles', '2'), @('modelRequestsSent', 1),
    @('modelRequestsSent', '0'), @('outputBytes', -1), @('outputBytes', 8388609),
    @('outputBytes', 0.5), @('outputBytes', '1024'), @('unreviewed', $true)
)) {
    $changed = $positiveJson | ConvertFrom-Json -AsHashtable
    $changed[$case[0]] = $case[1]
    Assert-ReceiptRejected ($changed | ConvertTo-Json -Compress) "invalid receipt $($case[0]) rejects"
}
Assert-ReceiptRejected ($positiveJson.TrimEnd('}') + ',"status":"PASS"}') 'duplicate receipt field rejects'
Assert-ReceiptRejected ('[' + $positiveJson + ']') 'array receipt rejects'
Assert-ReceiptRejected ($positiveJson + (' ' * 4096)) 'oversized receipt rejects'
Write-Output "Direct-local source-build contract passed $script:passed checks; no runtime or release acceptance claimed."
