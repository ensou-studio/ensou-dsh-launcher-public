#requires -Version 7.2

[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:Assertions = 0

function Assert-True {
    param([Parameter(Mandatory = $true)][bool]$Condition, [Parameter(Mandatory = $true)][string]$Label)

    $script:Assertions++
    if (-not $Condition) { throw $Label }
}

function Invoke-EarlyModeFailure {
    param(
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [Parameter(Mandatory = $true)][string[]]$AdditionalArguments
    )

    $psi = [Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = 'pwsh'
    foreach ($argument in @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $ScriptPath, '-RepositoryRoot', $RepositoryRoot) + $AdditionalArguments) {
        [void]$psi.ArgumentList.Add($argument)
    }
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $psi
    try {
        Assert-True $process.Start() 'Fixture-mode negative subprocess did not start.'
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(30000)) {
            $process.Kill($true)
            [void]$process.WaitForExit(10000)
            throw 'Fixture-mode negative subprocess exceeded its 30-second bound.'
        }
        return [pscustomobject]@{
            ExitCode = $process.ExitCode
            Output = $stdoutTask.GetAwaiter().GetResult() + $stderrTask.GetAwaiter().GetResult()
        }
    }
    finally {
        $process.Dispose()
    }
}

function Test-ChildFailureMessage {
    param([Parameter(Mandatory = $true)][string]$Output, [Parameter(Mandatory = $true)][string]$Message)

    return ((ConvertTo-OrchestrationDiagnosticText -Text $Output).Contains(
        $Message, [StringComparison]::Ordinal))
}

$repositoryRootFull = [IO.Path]::GetFullPath($RepositoryRoot)
$orchestratorPath = Join-Path $repositoryRootFull 'release\scripts\Test-LauncherProductionReleaseOrchestration.ps1'
if (-not (Test-Path -LiteralPath $orchestratorPath -PathType Leaf)) {
    throw 'Launcher production orchestration test script is missing.'
}

$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($orchestratorPath, [ref]$tokens, [ref]$parseErrors)
Assert-True ($parseErrors.Count -eq 0) 'Launcher production orchestration test script does not parse.'
$normalizers = @($ast.EndBlock.Statements | Where-Object {
        $_ -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $_.Name -ceq 'ConvertTo-OrchestrationDiagnosticText'
    })
Assert-True ($normalizers.Count -eq 1) 'Expected one shared diagnostic normalizer.'
. ([scriptblock]::Create($normalizers[0].Extent.Text))

$requireParameters = @($ast.ParamBlock.Parameters | Where-Object {
        [string]$_.Name.VariablePath.UserPath -ceq 'RequireProductRoleFixture'
    })
Assert-True ($requireParameters.Count -eq 1 -and $requireParameters[0].Extent.Text.Contains('[switch]', [StringComparison]::Ordinal)) 'RequireProductRoleFixture must remain one switch parameter.'

$source = [IO.File]::ReadAllText($orchestratorPath, [Text.UTF8Encoding]::new($false, $true))
$shardParameters = @($ast.ParamBlock.Parameters | Where-Object {
        $_.Name.VariablePath.UserPath -ceq 'Shard'
    })
Assert-True ($shardParameters.Count -eq 1 -and
    $shardParameters[0].DefaultValue.Extent.Text -ceq "'All'" -and
    $shardParameters[0].Extent.Text.Contains("[ValidateSet('All', 'FoundationR8', 'ImportAndPersonal')]")) `
    'Shards must preserve the default full suite and admit only both named partitions.'
$shardGuards = @($ast.FindAll({ param($node)
        $node -is [Management.Automation.Language.IfStatementAst] -and
        $node.Clauses[0].Item1.Extent.Text -in @(
            '$Shard -in @(''All'', ''FoundationR8'')',
            '$Shard -in @(''All'', ''ImportAndPersonal'')')
    }, $true))
Assert-True ($shardGuards.Count -eq 2) 'Both complete shard guards must exist exactly once.'
$foundationGuard = @($shardGuards | Where-Object {
        $_.Clauses[0].Item1.Extent.Text -ceq '$Shard -in @(''All'', ''FoundationR8'')'
    })[0]
$importGuard = @($shardGuards | Where-Object {
        $_.Clauses[0].Item1.Extent.Text -ceq '$Shard -in @(''All'', ''ImportAndPersonal'')'
    })[0]
Assert-True ($foundationGuard.Extent.Text.Contains('} $pilotV2FoundationState $stableV2FoundationState') -and
    $foundationGuard.Extent.Text.Contains('Copy-State -Source $pilotV2State -Destination $pilotV2FoundationState') -and
    $importGuard.Extent.Text.Contains('-Label ''verification-workspace-residue''')) `
    'Shard boundaries lost copied-state isolation or the last original negative case.'
$continuationSelectors = @($ast.FindAll({ param($node)
        $node -is [Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left.Extent.Text -ceq '$realRfc3161ContinuationBranches'
    }, $true))
Assert-True ($continuationSelectors.Count -eq 1) 'Expected one actual RFC3161 continuation selector.'
# Execute the source selector, not a proxy, against the full tree with both shard guards.
$selfAst = $ast
. ([scriptblock]::Create($continuationSelectors[0].Extent.Text))
Assert-True ($realRfc3161ContinuationBranches.Count -eq 1 -and
    $realRfc3161ContinuationBranches[0].Clauses[0].Item1.Extent.Text -ceq '$useProductRoleFixture') `
    'The actual RFC3161 continuation selector must not also select an enclosing shard guard.'
$requireGuard = "if (`$RequireProductRoleFixture -and -not `$useProductRoleFixture)"
$requireMessage = 'PRODUCT_SIGNING_FIXTURE_REQUIRED: Signed-product acceptance requires all three explicit product-role fixture inputs.'
Assert-True ($source.Contains($requireGuard, [StringComparison]::Ordinal) -and $source.Contains($requireMessage, [StringComparison]::Ordinal)) 'Required ProductRole fixture mode must fail before fixture work starts.'

$newResponse = @($ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'New-ResponseFixture'
    }, $true))
Assert-True ($newResponse.Count -eq 1) 'Expected exactly one New-ResponseFixture definition.'
$responseText = $newResponse[0].Body.Extent.Text
Assert-True ($responseText.Contains('elseif ($CheckoutCasCryptoFixture)', [StringComparison]::Ordinal) -and
    $responseText.Contains('Copy-Item -LiteralPath $script:UnsignedPeFixturePath -Destination $signedPath', [StringComparison]::Ordinal)) 'Ordinary no-product responses must copy the unsigned PE fixture.'

$cryptoCalls = @($ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.CommandAst] -and
        $node.GetCommandName() -ceq 'New-ResponseFixture' -and
        $node.Extent.Text.Contains('-CheckoutCasCryptoFixture', [StringComparison]::Ordinal)
    }, $true))
Assert-True ($cryptoCalls.Count -eq 1 -and
    $cryptoCalls[0].Extent.Text.Contains('$importRaceState', [StringComparison]::Ordinal) -and
    $cryptoCalls[0].Extent.Text.Contains('import-head-race-response', [StringComparison]::Ordinal)) 'Checkout/CAS cryptographic fixture must remain confined to the marked import-race clone.'

$positiveImports = @($ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.IfStatementAst] -and
        $node.Clauses[0].Item1.Extent.Text -cne '$Shard -in @(''All'', ''ImportAndPersonal'')' -and
        $node.Extent.Text.Contains("-Phase ImportClientSignatures", [StringComparison]::Ordinal) -and
        $node.Extent.Text.Contains("CLIENT_SIGNATURES_IMPORTED", [StringComparison]::Ordinal)
    }, $true))
Assert-True ($positiveImports.Count -ge 2) 'Expected both edition import-success branches.'
foreach ($branch in $positiveImports) {
    Assert-True ($branch.Clauses[0].Item1.Extent.Text -ceq '$useProductRoleFixture') 'Real product import success must be gated by explicit ProductRole fixture mode, not discovered system PE.'
}

$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ('ensou-product-role-orchestration-modes-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($temporaryRoot) | Out-Null
try {
    $missing = Invoke-EarlyModeFailure -ScriptPath $orchestratorPath -RepositoryRoot $repositoryRootFull -AdditionalArguments @('-RequireProductRoleFixture')
    Assert-True ($missing.ExitCode -ne 0 -and (Test-ChildFailureMessage -Output $missing.Output -Message $requireMessage)) 'Required mode without fixture inputs did not fail early with the required message.'

    $partial = Invoke-EarlyModeFailure -ScriptPath $orchestratorPath -RepositoryRoot $repositoryRootFull -AdditionalArguments @('-ProductRoleFixtureRoot', (Join-Path $temporaryRoot 'fixture'))
    Assert-True ($partial.ExitCode -ne 0 -and (Test-ChildFailureMessage -Output $partial.Output -Message 'Product role fixture mode requires -ProductRoleFixtureRoot, -ProductRoleFixtureManifestPath, and -ReleaseManifestTestKeyPath together.')) 'Partial ProductRole fixture inputs did not fail early.'

    $requiredShard = Invoke-EarlyModeFailure -ScriptPath $orchestratorPath -RepositoryRoot $repositoryRootFull -AdditionalArguments @(
        '-RequireProductRoleFixture', '-Shard', 'FoundationR8',
        '-ProductRoleFixtureRoot', (Join-Path $temporaryRoot 'fixture'),
        '-ProductRoleFixtureManifestPath', (Join-Path $temporaryRoot 'manifest.json'),
        '-ReleaseManifestTestKeyPath', (Join-Path $temporaryRoot 'key.json'))
    Assert-True ($requiredShard.ExitCode -ne 0 -and
        (Test-ChildFailureMessage -Output $requiredShard.Output -Message 'SIGNED_PRODUCT_REQUIRES_FULL_SUITE')) `
        'A partial shard was allowed to stand in for required full signed-product acceptance.'

    Write-Output "PASS Test-ProductRoleOrchestrationModes assertions=$script:Assertions metadata-and-mode-only"
}
finally {
    if (Test-Path -LiteralPath $temporaryRoot) {
        $resolved = [IO.Path]::GetFullPath($temporaryRoot)
        $prefix = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar + 'ensou-product-role-orchestration-modes-'
        if (-not $resolved.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) -or
            [IO.Path]::GetFileName($resolved) -cnotmatch '^ensou-product-role-orchestration-modes-[0-9a-f]{32}$' -or
            ((Get-Item -LiteralPath $resolved -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Refusing cleanup outside the exact owned ProductRole orchestration mode fixture directory.'
        }
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
