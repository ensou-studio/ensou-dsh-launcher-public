#requires -Version 7.2

[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [string]$ProductRoleFixtureRoot = '',
    [string]$ProductRoleFixtureManifestPath = '',
    [string]$ReleaseManifestTestKeyPath = '',
    [switch]$RequireProductRoleFixture,
    [ValidateSet('All', 'FoundationR8', 'ImportAndPersonal')]
    [string]$Shard = 'All'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$utf8 = [Text.UTF8Encoding]::new($false)
$script:SignedPeFixturePath = ''
$script:Rfc3161SignedPeFixturePath = ''
$script:UnsignedPeFixturePath = ''
$script:ProductRoleFixtureContract = $null
$script:AssertionCount = 0
$script:ExpectedFailureCount = 0
$providedProductRoleFixtureInputs = @(
    @($ProductRoleFixtureRoot, $ProductRoleFixtureManifestPath, $ReleaseManifestTestKeyPath) |
        Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }
)
if ($providedProductRoleFixtureInputs.Count -ne 0 -and $providedProductRoleFixtureInputs.Count -ne 3) {
    throw 'Product role fixture mode requires -ProductRoleFixtureRoot, -ProductRoleFixtureManifestPath, and -ReleaseManifestTestKeyPath together.'
}
$useProductRoleFixture = ($providedProductRoleFixtureInputs.Count -eq 3)
if ($RequireProductRoleFixture -and -not $useProductRoleFixture) {
    throw 'PRODUCT_SIGNING_FIXTURE_REQUIRED: Signed-product acceptance requires all three explicit product-role fixture inputs.'
}
if ($RequireProductRoleFixture -and $Shard -cne 'All') {
    throw 'SIGNED_PRODUCT_REQUIRES_FULL_SUITE: Required signed-product acceptance must run -Shard All.'
}

function Assert-True {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if (-not $Condition) {
        throw $Label
    }
    $script:AssertionCount++
}

function Assert-ProductionFeedPromotionAstContracts {
    param([Management.Automation.Language.ScriptBlockAst]$OrchestratorAst)

    # Count calls within their actual lifecycle branch, not across both editions.
    $commands = @(
        'ProductionFeedPromotion\New-ProductionFeedPromotionRequest',
        'ProductionFeedPromotion\Import-ProductionFeedPromotionResponse',
        'ProductionFeedPromotion\Open-ProductionFeedPromotionBundleAdmission',
        'ProductionReleaseState\Assert-ProductionStableFeedPromotionAdmission')
    $branches = @(
        @{ Name = 'Invoke-PersonalPilotFeedPromotionPhase'; Counts = @(1, 1, 0, 0); Writer = '$stateLock'; State = '$writerState'; Validation = '$preCommitValidation'; Completion = 'Complete-ProductionBundleAfterCheckoutAdmission'; Phase = 'PILOT_PROMOTION_REQUESTED' },
        @{ Name = 'Invoke-PersonalPilotCompletedResultImport'; Counts = @(0, 0, 1, 0); Writer = '$writer'; State = '$state'; Validation = '$validate'; Completion = 'Complete-ProductionBundleAfterCheckoutAdmission'; Phase = 'PILOT_FEED_PROMOTED' },
        @{ Name = 'Invoke-EnterpriseStableFeedPromotionPhase'; Counts = @(1, 1, 1, 1); Writer = '$localStateLock'; State = '$writerState'; Validation = '$preCommitValidation'; Completion = 'Complete-ValidatedProductionBundleAfterCheckoutAdmission'; Phase = 'STABLE_PROMOTION_REQUESTED' })
    foreach ($branch in $branches) {
        $functions = @($OrchestratorAst.FindAll({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $branch.Name
        }.GetNewClosure(), $true))
        Assert-True ($functions.Count -eq 1) "Promote branch '$($branch.Name)' must exist exactly once."
        $function = $functions[0]
        $calls = @($function.FindAll({ param($node) $node -is [Management.Automation.Language.CommandAst] }, $true))
        for ($index = 0; $index -lt $commands.Count; $index++) {
            $name = $commands[$index]
            $matches = @($calls | Where-Object { $_.GetCommandName() -ceq $name })
            Assert-True ($matches.Count -eq $branch.Counts[$index]) "Promote branch '$($branch.Name)' lost its exact '$name' call contract."
            foreach ($call in $matches) {
                $parameters = @($call.CommandElements | Where-Object { $_ -is [Management.Automation.Language.CommandParameterAst] } | ForEach-Object ParameterName)
                $required = switch ($index) {
                    0 { @('ExpectedChannelHead', 'ExpectedJournalHead', 'ExpectedFeedIdentitySha256', 'ExpectedSourcePlanSha256', 'ExpectedSourceIdentitySha256', 'ExpectedSourceHeadSha256') }
                    1 { @('ResponsePath', 'ExpectedPromotionHeadSha256', 'ExpectedSourcePlanSha256', 'ExpectedSourceIdentitySha256', 'ExpectedSourceHeadSha256') }
                    2 { @('ExpectedPromotionHeadSha256', 'ExpectedBundleHeadSha256', 'ExpectedSourceHeadSha256', 'ExpectedRequestSha256', 'ExpectedResponseSha256', 'ExpectedBundleSetSha256') }
                    3 { @('Plan', 'Identity', 'IdentitySha256', 'Receipts', 'CommittedRevision', 'AdmittedRevision') }
                }
                foreach ($parameter in $required) {
                    Assert-True ($parameters -ccontains $parameter) "Promote branch '$($branch.Name)' lost '$name -$parameter'."
                }
            }
        }
        $writerCalls = @($calls | Where-Object { $_.GetCommandName() -ceq 'Enter-ProductionReleaseStateLock' })
        $completionCalls = @($calls | Where-Object { $_.GetCommandName() -ceq $branch.Completion })
        $receiptCalls = @($calls | Where-Object { $_.GetCommandName() -ceq 'ProductionReleaseState\Add-ProductionReleaseReceipt' })
        Assert-True ($writerCalls.Count -eq 1 -and $completionCalls.Count -eq 1 -and $receiptCalls.Count -eq 1) "Promote branch '$($branch.Name)' must retain its sole writer, checkout-admitted completion, and receipt append."
        Assert-True ($writerCalls[0].Extent.StartOffset -lt $completionCalls[0].Extent.StartOffset -and $completionCalls[0].Extent.StartOffset -lt $receiptCalls[0].Extent.StartOffset) "Promote branch '$($branch.Name)' publishes outside its state writer sequence."
        $text = [regex]::Replace($function.Extent.Text, '\s+', ' ')
        $cas = if ($branch.State -ceq '$state') { '$state.HeadSha256 -cne $InitialState.HeadSha256' } else { '[string]$writerState.HeadSha256 -cne [string]$initialState.HeadSha256' }
        $casIndex = $text.IndexOf($cas, [StringComparison]::Ordinal)
        Assert-True ($casIndex -gt $text.IndexOf('Enter-ProductionReleaseStateLock ', [StringComparison]::Ordinal) -and
            $casIndex -lt $text.IndexOf($branch.Completion + ' ', [StringComparison]::Ordinal)) "Promote branch '$($branch.Name)' lost its writer-held, pre-publication source-head CAS."
        $receiptText = [regex]::Replace($receiptCalls[0].Extent.Text, '\s+', ' ')
        $receiptCas = if ($branch.State -ceq '$state') { '-ExpectedHeadSha256 $ExpectedHeadSha256' } else { '-ExpectedHeadSha256 ([string]$initialState.HeadSha256)' }
        foreach ($contract in @($receiptCas, ('-PreCommitValidation ' + $branch.Validation), ("-Phase '" + $branch.Phase + "'"))) {
            Assert-True ($receiptText.Contains($contract, [StringComparison]::Ordinal)) "Promote branch '$($branch.Name)' lost receipt contract '$contract'."
        }
        $validationName = $branch.Validation.Substring(1)
        $validators = @($function.FindAll({
            param($node)
            $node -is [Management.Automation.Language.AssignmentStatementAst] -and
                $node.Left -is [Management.Automation.Language.VariableExpressionAst] -and
                $node.Left.VariablePath.UserPath -ceq $validationName
        }.GetNewClosure(), $true))
        Assert-True ($validators.Count -eq 1) "Promote branch '$($branch.Name)' lost its sole precommit closure."
        $validatorText = [regex]::Replace($validators[0].Extent.Text, '\s+', ' ')
        $requiredValidation = if ($branch.Phase -ceq 'PILOT_PROMOTION_REQUESTED') {
            @('Assert-ProductionReleaseInputStillLocked', '-Descriptor $requestInput', '-Descriptor $stateRequestInput')
        } elseif ($branch.Phase -ceq 'PILOT_FEED_PROMOTED') {
            @('Assert-PersonalFeedPromotionResultBinding -Admission $result @context -Fresh', 'Assert-PersonalFeedPromotionResultBinding -Admission $stored @context -Fresh', '$offline.HeldDescriptors', 'Assert-ProductionReleaseInputStillLocked')
        } else {
            @('-Admission $canonicalAdmission', '-Admission $pilotAdmission', '$externalAdmission.HeldDescriptors', 'Assert-ProductionReleaseInputStillLocked', '$effectiveRecordedAt -ge $pilotExpiresAt', '$effectiveRecordedAt -ge $requestExpiresAt')
        }
        foreach ($contract in $requiredValidation) {
            Assert-True ($validatorText.Contains($contract, [StringComparison]::Ordinal)) "Promote branch '$($branch.Name)' lost precommit validation '$contract'."
        }
        $finallyBlocks = @($function.FindAll({ param($node) $node -is [Management.Automation.Language.TryStatementAst] -and $null -ne $node.Finally }, $true) | ForEach-Object Finally)
        $cleanup = @($finallyBlocks | Where-Object { $_.Extent.Text.Contains(($branch.Writer + '.Stream.Dispose()'), [StringComparison]::Ordinal) })
        Assert-True ($cleanup.Count -eq 1) "Promote branch '$($branch.Name)' lost exact writer cleanup in finally."
        if ($branch.Counts[2] -eq 1) {
            $open = @($calls | Where-Object { $_.GetCommandName() -ceq $commands[2] })[0]
            Assert-True ($open.Extent.StartOffset -lt $writerCalls[0].Extent.StartOffset) "Promote branch '$($branch.Name)' must acquire external bundle admission before the state writer."
            $closeCalls = @($cleanup[0].FindAll({ param($node) $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -ceq 'ProductionFeedPromotion\Close-ProductionFeedPromotionBundleAdmission' }, $true))
            $closedAdmission = if ($branch.Phase -ceq 'PILOT_FEED_PROMOTED') { '$offline' } else { '$externalAdmission' }
            Assert-True ($closeCalls.Count -eq 1 -and $closeCalls[0].Extent.Text.Contains($closedAdmission, [StringComparison]::Ordinal)) "Promote branch '$($branch.Name)' lost exact external admission cleanup."
        }
        if ($branch.Phase -ceq 'PILOT_FEED_PROMOTED') {
            Assert-True ($open.Extent.Text.Contains('-ExpectedEdition Personal', [StringComparison]::Ordinal)) 'Personal completed-result admission lost its exact edition binding.'
            foreach ($contract in @('$ExpectedHeadSha256 -cne $InitialState.HeadSha256', '$r.sourceR8HeadSha256 -cne $ExpectedHeadSha256', 'Get-PersonalFeedPromotionStateContext', 'Assert-PersonalFeedPromotionResultBinding')) {
                Assert-True ($text.Contains($contract, [StringComparison]::Ordinal)) "Personal completed-result admission lost '$contract'."
            }
        }
    }
    for ($index = 0; $index -lt $commands.Count; $index++) {
        $name = $commands[$index]
        $allCalls = @($OrchestratorAst.FindAll({ param($node) $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -ceq $name }.GetNewClosure(), $true))
        $expected = 0
        foreach ($branch in $branches) { $expected += $branch.Counts[$index] }
        Assert-True ($allCalls.Count -eq $expected) "Promote command '$name' appears outside its admitted lifecycle branches."
    }
}

function Assert-Throws {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Action,
        [Parameter(Mandatory = $true)][string]$Label,
        [string]$ExpectedMessage = ''
    )

    $threw = $false
    try {
        & $Action
    }
    catch {
        $threw = $true
        if ($ExpectedMessage -and
            -not $_.Exception.Message.Contains(
                $ExpectedMessage,
                [StringComparison]::OrdinalIgnoreCase)) {
            throw "$Label failed for the wrong reason: $($_.Exception.Message)"
        }
    }
    if (-not $threw) {
        throw "$Label did not fail closed."
    }
    $script:AssertionCount++
    $script:ExpectedFailureCount++
}

function ConvertTo-Base64Url {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    return [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Write-Json {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Value
    )

    $json = $Value | Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 64
    [IO.File]::WriteAllText($Path, $json + [char]10, $utf8)
}

function Read-Json {
    param([Parameter(Mandatory = $true)][string]$Path)

    return [IO.File]::ReadAllText($Path, [Text.UTF8Encoding]::new($false, $true)) |
        Microsoft.PowerShell.Utility\ConvertFrom-Json -Depth 64 -DateKind String
}

function Get-Sha256 {
    param([Parameter(Mandatory = $true)][string]$Path)

    return (Microsoft.PowerShell.Utility\Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

function Get-StateTreeSnapshot {
    param([Parameter(Mandatory = $true)][string]$Path)

    $root = [IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $root)) {
        return '<MISSING>'
    }
    $records = [Collections.Generic.List[string]]::new()
    $records.Add('D' + [char]9 + '.')
    foreach ($entry in @(Get-ChildItem -LiteralPath $root -Force -Recurse | Sort-Object FullName)) {
        $relativePath = [IO.Path]::GetRelativePath($root, $entry.FullName).Replace([IO.Path]::DirectorySeparatorChar, '/')
        if ($entry.PSIsContainer) {
            $records.Add('D' + [char]9 + $relativePath)
            continue
        }
        [byte[]]$bytes = [IO.File]::ReadAllBytes($entry.FullName)
        $sha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
        $records.Add(
            'F' + [char]9 + $relativePath + [char]9 +
            $bytes.LongLength + [char]9 + $sha256 + [char]9 +
            [Convert]::ToBase64String($bytes))
    }
    return $records -join [char]10
}

function ConvertTo-NonCanonicalBase64Url {
    param([Parameter(Mandatory = $true)][string]$Value)

    if ($Value.Length -ne 43) {
        throw 'P-256 fixture coordinate must contain 43 base64url characters.'
    }
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
    $lastIndex = $alphabet.IndexOf($Value[$Value.Length - 1])
    if ($lastIndex -lt 0 -or $lastIndex % 4 -ne 0) {
        throw 'P-256 fixture coordinate did not end in a canonical 32-byte base64url character.'
    }
    return $Value.Substring(0, $Value.Length - 1) + $alphabet[$lastIndex + 1]
}

function Invoke-Git {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    $output = @(& git -c core.autocrlf=false -C $Root @Arguments 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "Git fixture command failed: git -c core.autocrlf=false -C $Root $($Arguments -join ' '): $($output -join ' ')"
    }
    return @($output)
}

function Install-ImportHeadRaceTrustStub {
    param(
        [Parameter(Mandatory = $true)][string]$FixtureRoot,
        [Parameter(Mandatory = $true)][string]$ImportRaceRepositoryRoot,
        [Parameter(Mandatory = $true)][string]$ExpectedSourceSha256
    )

    # This is deliberately limited to the committed, temporary import-race
    # clone. It isolates checkout/CAS behavior only; it is not an
    # Authenticode, native-probe, or signed-release acceptance path.
    $fixtureRootFull = [IO.Path]::GetFullPath($FixtureRoot)
    $expectedRepositoryRoot = Join-Path $fixtureRootFull 'import-head-race-repo'
    $repositoryRootFull = [IO.Path]::GetFullPath($ImportRaceRepositoryRoot)
    if (-not [string]::Equals(
            $repositoryRootFull,
            $expectedRepositoryRoot,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Import HEAD-race trust stub target is not the exact owned temporary clone.'
    }
    $fixtureDirectory = [IO.DirectoryInfo]::new($fixtureRootFull)
    if (-not $fixtureDirectory.Exists) {
        throw 'Import HEAD-race fixture root is not a directory.'
    }
    $cursor = [IO.DirectoryInfo]::new($repositoryRootFull)
    while ($true) {
        if (-not $cursor.Exists -or
            (($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw 'Import HEAD-race trust stub target crosses a linked or non-directory fixture path.'
        }
        if ([string]::Equals(
                $cursor.FullName,
                $fixtureDirectory.FullName,
                [StringComparison]::OrdinalIgnoreCase)) {
            break
        }
        if ($null -eq $cursor.Parent) {
            throw 'Import HEAD-race trust stub target escaped its fixture root.'
        }
        $cursor = $cursor.Parent
    }

    $scriptPath = Join-Path `
        $repositoryRootFull `
        'release\scripts\Invoke-LauncherProductionRelease.ps1'
    if ((Get-Sha256 -Path $scriptPath) -cne $ExpectedSourceSha256) {
        throw 'Import HEAD-race clone script differs from the exact admitted source before fixture instrumentation.'
    }
    $tokens = $null
    $parseErrors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile(
        $scriptPath,
        [ref]$tokens,
        [ref]$parseErrors)
    if ($parseErrors.Count -ne 0) {
        throw 'Import HEAD-race clone script did not parse before fixture instrumentation.'
    }
    $targets = @($ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Invoke-ReleaseManifestTrustProbe'
    }, $true))
    if ($targets.Count -ne 1) {
        throw 'Import HEAD-race clone does not contain exactly one release-manifest trust-probe function.'
    }

    # Keep the production function's exact parameter block. New production
    # inputs (such as a verification snapshot) must remain mechanically
    # compatible with this checkout/CAS-only fixture.
    $originalParameterBlock = if ($null -eq $targets[0].Body.ParamBlock) {
        $null
    }
    else {
        $targets[0].Body.ParamBlock.Extent.Text
    }
    $replacement = '{' + [Environment]::NewLine
    if ($null -ne $originalParameterBlock) {
        $replacement += $originalParameterBlock + [Environment]::NewLine
    }
    $replacement += @'
    # TEST_ONLY_CHECKOUT_CAS_FIXTURE_NOT_RELEASE_ACCEPTANCE
    # The import HEAD-race isolates the final checkout/CAS boundary. Real
    # Authenticode and native release-probe acceptance are covered separately.
    if ([string]$Plan.edition -ceq 'Enterprise' -and $Role -ceq 'maintenance') {
        return $null
    }
    $identity = [Text.Encoding]::UTF8.GetBytes(
        'TEST_ONLY_CHECKOUT_CAS_FIXTURE_NOT_RELEASE_ACCEPTANCE:' +
        [string]$Plan.edition + ':' + $Role + ':' + $FileName)
    return [pscustomobject]@{
        Role = $Role
        FileName = $FileName
        ProbeSha256 = ([Convert]::ToHexString(
            [Security.Cryptography.SHA256]::HashData($identity))).ToLowerInvariant()
    }
}
'@
    $source = [IO.File]::ReadAllText(
        $scriptPath,
        [Text.UTF8Encoding]::new($false, $true))
    $target = $targets[0]
    $patched = $source.Remove(
        $target.Body.Extent.StartOffset,
        $target.Body.Extent.EndOffset - $target.Body.Extent.StartOffset).Insert(
        $target.Body.Extent.StartOffset,
        $replacement)
    [IO.File]::WriteAllText($scriptPath, $patched, $utf8)
    $markerPath = Join-Path `
        $repositoryRootFull `
        '.test-only-import-head-race-not-release-acceptance'
    [IO.File]::WriteAllText(
        $markerPath,
        'TEST_ONLY_CHECKOUT_CAS_FIXTURE_NOT_RELEASE_ACCEPTANCE' + [char]10,
        $utf8)

    $patchedTokens = $null
    $patchedErrors = $null
    $patchedAst = [Management.Automation.Language.Parser]::ParseFile(
        $scriptPath,
        [ref]$patchedTokens,
        [ref]$patchedErrors)
    if ($patchedErrors.Count -ne 0) {
        throw 'Import HEAD-race fixture patch introduced PowerShell parse errors.'
    }
    $patchedTargets = @($patchedAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Invoke-ReleaseManifestTrustProbe'
    }, $true))
    $patchedParameterBlock = if ($patchedTargets.Count -eq 1 -and
        $null -ne $patchedTargets[0].Body.ParamBlock) {
        $patchedTargets[0].Body.ParamBlock.Extent.Text
    }
    else {
        $null
    }
    if ($patchedTargets.Count -ne 1 -or
        -not [string]::Equals(
            $originalParameterBlock,
            $patchedParameterBlock,
            [StringComparison]::Ordinal) -or
        -not $patchedTargets[0].Extent.Text.Contains(
            'TEST_ONLY_CHECKOUT_CAS_FIXTURE_NOT_RELEASE_ACCEPTANCE',
            [StringComparison]::Ordinal)) {
        throw 'Import HEAD-race fixture patch did not preserve exactly one marked trust-probe function and its parameter block.'
    }
    if (@(Get-ChildItem -LiteralPath $repositoryRootFull -Force -Recurse `
                -Filter '.test-only-import-head-race-not-release-acceptance').Count -ne 1) {
        throw 'Import HEAD-race fixture marker count is invalid.'
    }
    [void](Invoke-Git -Root $repositoryRootFull -Arguments @(
            'add', '--',
            'release/scripts/Invoke-LauncherProductionRelease.ps1',
            '.test-only-import-head-race-not-release-acceptance'))
    [void](Invoke-Git -Root $repositoryRootFull -Arguments @(
            'commit', '--quiet', '-m',
            'test-only import checkout CAS fixture'))
    if (@(Invoke-Git -Root $repositoryRootFull -Arguments @('status', '--porcelain')).Count -ne 0) {
        throw 'Import HEAD-race fixture clone is not clean after its test-only commit.'
    }
    return [pscustomobject]@{
        SourceSha256 = $ExpectedSourceSha256
        ScriptPath = $scriptPath
        MarkerPath = $markerPath
        Commit = [string]@(Invoke-Git -Root $repositoryRootFull -Arguments @('rev-parse', 'HEAD'))[0]
    }
}

function ConvertTo-OrchestrationDiagnosticText {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text)

    # ConciseView colors every display line before its continuation marker.
    # Remove display-only SGR codes first so a wrapped error remains one
    # semantic message regardless of the CI terminal's color configuration.
    $plainText = [regex]::Replace($Text, '\x1b\[[0-9;:]*m', '')
    $withoutContinuationMarkers = [regex]::Replace(
        $plainText,
        '(?m)^[\p{Zs}\t]*\|[\p{Zs}\t]?',
        '')
    return [regex]::Replace($withoutContinuationMarkers, '\s+', ' ').Trim()
}

function Invoke-Orchestrator {
    param(
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$Edition,
        [Parameter(Mandatory = $true)][string]$Phase,
        [Parameter(Mandatory = $true)][string]$PlanPath,
        [Parameter(Mandatory = $true)][string]$StateRoot,
        [string]$ResponsePath = '',
        [string]$PublisherInputPath = '',
        [string]$InstallerSigningInputPath = '',
        [string]$EnterpriseInstallerPayloadPath = '',
        [string]$EnterpriseInstallerPackageDirectory = '',
        [string]$EnterpriseInstallerDotNetSdkArchivePath = '',
        [string]$PersonalInstallerPayloadPath = '',
        [string]$PersonalInstallerPackageDirectory = '',
        [string]$PersonalInstallerDotNetSdkArchivePath = '',
        [string]$WindowsPilotEvidenceEnvelopePath = '',
        [string]$WindowsPilotEvidenceBodyPath = '',
        [string]$WindowsPilotVerificationReportPath = '',
        [string]$WindowsPilotReadinessConfigPath = '',
        [string]$WindowsPilotStoredReadinessReportPath = '',
        [string]$WindowsPilotReplayedReadinessReportPath = '',
        [string]$LocalDataCertificationReceiptPath = '',
        [string]$StablePrivatePilotObservationPath = '',
        [string]$PilotTrustPolicyPath = '',
        [string]$PromotionRoot = '',
        [string]$FeedPromotionResponsePath = '',
        [string]$EnterpriseStablePublicationContextPath = '',
        [string]$EnterpriseStablePublicationResultBundlePath = '',
        [string]$ExpectedFeedIdentitySha256 = '',
        [string]$ExpectedChannelHead = '',
        [string]$ExpectedJournalHead = '',
        [string]$ExpectedHeadSha256 = '',
        [string]$FaultPoint = '',
        [switch]$ExpectFailure,
        [string]$ExpectedMessage = ''
    )

    $arguments = @(
        '-NoLogo',
        '-NoProfile',
        '-NonInteractive',
        '-File',
        $ScriptPath,
        '-RepositoryRoot',
        $RepoRoot,
        '-Edition',
        $Edition,
        '-Phase',
        $Phase,
        '-PlanPath',
        $PlanPath,
        '-StateRoot',
        $StateRoot
    )
    if ($ResponsePath) {
        $arguments += @('-ResponsePath', $ResponsePath)
    }
    if ($PublisherInputPath) {
        $arguments += @('-PublisherInputPath', $PublisherInputPath)
    }
    if ($InstallerSigningInputPath) {
        $arguments += @('-InstallerSigningInputPath', $InstallerSigningInputPath)
    }
    if ($EnterpriseInstallerPayloadPath) {
        $arguments += @(
            '-EnterpriseInstallerPayloadPath',
            $EnterpriseInstallerPayloadPath)
    }
    if ($EnterpriseInstallerPackageDirectory) {
        $arguments += @(
            '-EnterpriseInstallerPackageDirectory',
            $EnterpriseInstallerPackageDirectory)
    }
    if ($EnterpriseInstallerDotNetSdkArchivePath) {
        $arguments += @(
            '-EnterpriseInstallerDotNetSdkArchivePath',
            $EnterpriseInstallerDotNetSdkArchivePath)
    }
    if ($PersonalInstallerPayloadPath) {
        $arguments += @(
            '-PersonalInstallerPayloadPath',
            $PersonalInstallerPayloadPath)
    }
    if ($PersonalInstallerPackageDirectory) {
        $arguments += @(
            '-PersonalInstallerPackageDirectory',
            $PersonalInstallerPackageDirectory)
    }
    if ($PersonalInstallerDotNetSdkArchivePath) {
        $arguments += @(
            '-PersonalInstallerDotNetSdkArchivePath',
            $PersonalInstallerDotNetSdkArchivePath)
    }
    foreach ($pilotEvidenceArgument in @(
            [pscustomobject]@{
                Name = 'WindowsPilotEvidenceEnvelopePath'
                Value = $WindowsPilotEvidenceEnvelopePath
            },
            [pscustomobject]@{
                Name = 'WindowsPilotEvidenceBodyPath'
                Value = $WindowsPilotEvidenceBodyPath
            },
            [pscustomobject]@{
                Name = 'WindowsPilotVerificationReportPath'
                Value = $WindowsPilotVerificationReportPath
            },
            [pscustomobject]@{
                Name = 'WindowsPilotReadinessConfigPath'
                Value = $WindowsPilotReadinessConfigPath
            },
            [pscustomobject]@{
                Name = 'WindowsPilotStoredReadinessReportPath'
                Value = $WindowsPilotStoredReadinessReportPath
            },
            [pscustomobject]@{
                Name = 'WindowsPilotReplayedReadinessReportPath'
                Value = $WindowsPilotReplayedReadinessReportPath
            },
            [pscustomobject]@{
                Name = 'LocalDataCertificationReceiptPath'
                Value = $LocalDataCertificationReceiptPath
            },
            [pscustomobject]@{
                Name = 'StablePrivatePilotObservationPath'
                Value = $StablePrivatePilotObservationPath
            },
            [pscustomobject]@{
                Name = 'PilotTrustPolicyPath'
                Value = $PilotTrustPolicyPath
            })) {
        if ([string]$pilotEvidenceArgument.Value) {
            $argumentCountBefore = $arguments.Count
            $expectedArgumentName =
                '-' + [string]$pilotEvidenceArgument.Name
            $expectedArgumentValue = [string]$pilotEvidenceArgument.Value
            $arguments += $expectedArgumentName
            $arguments += $expectedArgumentValue
            Assert-True `
                ($arguments.Count -eq $argumentCountBefore + 2 -and
                 $arguments[$argumentCountBefore] -ceq $expectedArgumentName -and
                 $arguments[$argumentCountBefore + 1] -ceq $expectedArgumentValue) `
                "Pilot evidence parameter '$($pilotEvidenceArgument.Name)' must remain two exact argv entries without name/value concatenation."
        }
    }
    foreach ($feedPromotionArgument in @(
            [pscustomobject]@{
                Name = 'PromotionRoot'
                Value = $PromotionRoot
            },
            [pscustomobject]@{
                Name = 'FeedPromotionResponsePath'
                Value = $FeedPromotionResponsePath
            },
            [pscustomobject]@{
                Name = 'EnterpriseStablePublicationContextPath'
                Value = $EnterpriseStablePublicationContextPath
            },
            [pscustomobject]@{
                Name = 'EnterpriseStablePublicationResultBundlePath'
                Value = $EnterpriseStablePublicationResultBundlePath
            },
            [pscustomobject]@{
                Name = 'ExpectedFeedIdentitySha256'
                Value = $ExpectedFeedIdentitySha256
            },
            [pscustomobject]@{
                Name = 'ExpectedChannelHead'
                Value = $ExpectedChannelHead
            },
            [pscustomobject]@{
                Name = 'ExpectedJournalHead'
                Value = $ExpectedJournalHead
            })) {
        if ([string]$feedPromotionArgument.Value) {
            $argumentCountBefore = $arguments.Count
            $expectedArgumentName =
                '-' + [string]$feedPromotionArgument.Name
            $expectedArgumentValue = [string]$feedPromotionArgument.Value
            $arguments += $expectedArgumentName
            $arguments += $expectedArgumentValue
            Assert-True `
                ($arguments.Count -eq $argumentCountBefore + 2 -and
                 $arguments[$argumentCountBefore] -ceq $expectedArgumentName -and
                 $arguments[$argumentCountBefore + 1] -ceq $expectedArgumentValue) `
                "Feed-promotion parameter '$($feedPromotionArgument.Name)' must remain two exact argv entries without name/value concatenation."
        }
    }
    if ($ExpectedHeadSha256) {
        $arguments += @('-ExpectedHeadSha256', $ExpectedHeadSha256)
    }
    if ($FaultPoint) {
        $arguments += @('-FaultPoint', $FaultPoint)
    }
    $invocationTimer = [Diagnostics.Stopwatch]::StartNew()
    $exitCode = $null
    # Information-stream diagnostics must not contaminate the returned result.
    Write-Host "ORCHESTRATOR-START $Edition/$Phase"
    try {
        $output = @(& pwsh @arguments 2>&1 | ForEach-Object { [string]$_ })
        $exitCode = $LASTEXITCODE
    }
    finally {
        $invocationTimer.Stop()
        Write-Host "ORCHESTRATOR-END $Edition/$Phase exit=$exitCode elapsedMs=$($invocationTimer.ElapsedMilliseconds)"
    }
    # Expected child failures are contract data; do not leak their native exit
    # status into a caller such as the GitHub Actions pwsh wrapper.
    $global:LASTEXITCODE = 0
    if ($ExpectFailure) {
        if ($exitCode -eq 0) {
            throw "Expected orchestration failure for $Edition/$Phase."
        }
        $normalizedOutput = ConvertTo-OrchestrationDiagnosticText `
            -Text ($output -join [char]10)
        $normalizedExpectedMessage = if ($ExpectedMessage) {
            [regex]::Replace(
                $ExpectedMessage,
                '\s+',
                ' ').Trim()
        }
        else {
            ''
        }
        if ($ExpectedMessage -and
            -not $normalizedOutput.Contains(
                $normalizedExpectedMessage,
                [StringComparison]::OrdinalIgnoreCase)) {
            throw "Orchestration failure for $Edition/$Phase did not contain '$ExpectedMessage': $($output -join ' ')"
        }
        $script:AssertionCount++
        $script:ExpectedFailureCount++
    }
    elseif ($exitCode -ne 0) {
        throw "Orchestration failed for $Edition/${Phase}: $($output -join ' ')"
    }
    return [pscustomobject]@{
        ExitCode = $exitCode
        Output = $output
    }
}

function Invoke-ProductionInitializationRace {
    param(
        [Parameter(Mandatory = $true)][string]$ModulePath,
        [Parameter(Mandatory = $true)][string]$PlanPath,
        [Parameter(Mandatory = $true)][string]$StateRoot,
        [Parameter(Mandatory = $true)][string]$FixtureRoot
    )

    $workerPath = Join-Path $FixtureRoot 'initialization-race-worker.ps1'
    $workerSource = @'
param($ModulePath, $PlanPath, $StateRoot, $ReadyPath, $GoPath, $ResultPath)
$ErrorActionPreference = 'Stop'
try {
    Import-Module $ModulePath -Force
    $planBytes = [IO.File]::ReadAllBytes($PlanPath)
    $plan = ConvertFrom-StrictProductionJsonBytes -Bytes $planBytes -Label 'Initialization race plan'
    [IO.File]::WriteAllText($ReadyPath, 'READY', [Text.UTF8Encoding]::new($false))
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(120)
    while (-not (Test-Path -LiteralPath $GoPath -PathType Leaf)) {
        if ([DateTimeOffset]::UtcNow -ge $deadline) {
            [IO.File]::WriteAllText($ResultPath, 'FAILED barrier timeout', [Text.UTF8Encoding]::new($false))
            exit 90
        }
        Start-Sleep -Milliseconds 10
    }
}
catch {
    [IO.File]::WriteAllText(
        $ResultPath,
        ('FAILED startup ' + $_.Exception.ToString()),
        [Text.UTF8Encoding]::new($false))
    exit 91
}
$stateLock = $null
try {
    $stateLock = Enter-ProductionReleaseStateLock -StateRoot $StateRoot -PlanBytes $planBytes -Plan $plan
    [IO.File]::WriteAllText($ResultPath, 'ACQUIRED', [Text.UTF8Encoding]::new($false))
    Start-Sleep -Milliseconds 3000
    $exitCode = 0
}
catch {
    [IO.File]::WriteAllText($ResultPath, ('REJECTED ' + $_.Exception.Message), [Text.UTF8Encoding]::new($false))
    $exitCode = 42
}
finally {
    if ($null -ne $stateLock) {
        $stateLock.Stream.Dispose()
    }
}
exit $exitCode
'@
    [IO.File]::WriteAllText($workerPath, $workerSource, $utf8)
    $goPath = Join-Path $FixtureRoot 'initialization-race.go'
    $processes = [Collections.Generic.List[Diagnostics.Process]]::new()
    $readyPaths = [Collections.Generic.List[string]]::new()
    $resultPaths = [Collections.Generic.List[string]]::new()
    try {
        foreach ($index in 1..2) {
            $readyPath = Join-Path $FixtureRoot "initialization-race-$index.ready"
            $resultPath = Join-Path $FixtureRoot "initialization-race-$index.result"
            $readyPaths.Add($readyPath)
            $resultPaths.Add($resultPath)
            $startInfo = [Diagnostics.ProcessStartInfo]::new()
            $startInfo.FileName = [IO.Path]::GetFullPath((Join-Path $PSHOME 'pwsh.exe'))
            $startInfo.UseShellExecute = $false
            $startInfo.CreateNoWindow = $true
            foreach ($argument in @(
                    '-NoLogo',
                    '-NoProfile',
                    '-NonInteractive',
                    '-File',
                    $workerPath,
                    $ModulePath,
                    $PlanPath,
                    $StateRoot,
                    $readyPath,
                    $goPath,
                    $resultPath)) {
                [void]$startInfo.ArgumentList.Add([string]$argument)
            }
            $process = [Diagnostics.Process]::new()
            $process.StartInfo = $startInfo
            if (-not $process.Start()) {
                throw 'Could not start an initialization race worker.'
            }
            $processes.Add($process)
            # Start and warm each worker deterministically before launching the
            # next. Both remain blocked on the shared GO file, so lock
            # acquisition is still concurrent without racing two Add-Type /
            # module-import cold starts against the CI host.
            $workerReadyDeadline = [DateTimeOffset]::UtcNow.AddSeconds(90)
            while (-not (Test-Path -LiteralPath $readyPath -PathType Leaf)) {
                if ($process.HasExited) {
                    $result = if (Test-Path -LiteralPath $resultPath -PathType Leaf) {
                        [IO.File]::ReadAllText(
                            $resultPath,
                            [Text.UTF8Encoding]::new($false, $true))
                    }
                    else {
                        '<no worker result>'
                    }
                    throw "Initialization race worker $index exited before the shared barrier: pid=$($process.Id) exit=$($process.ExitCode) result=$result"
                }
                if ([DateTimeOffset]::UtcNow -ge $workerReadyDeadline) {
                    throw "Initialization race worker $index did not reach the shared barrier: pid=$($process.Id) exited=$($process.HasExited) ready=$(Test-Path -LiteralPath $readyPath -PathType Leaf) result=$(Test-Path -LiteralPath $resultPath -PathType Leaf)"
                }
                Start-Sleep -Milliseconds 10
            }
        }
        Assert-True (@($readyPaths | Where-Object {
                    Test-Path -LiteralPath $_ -PathType Leaf
                }).Count -eq 2) 'Deterministic initialization race barrier did not retain both ready workers.'
        [IO.File]::WriteAllText($goPath, 'GO', $utf8)
        foreach ($process in $processes) {
            if (-not $process.WaitForExit(30000)) {
                throw 'Initialization race worker did not exit within 30 seconds.'
            }
        }
        $results = @($resultPaths | ForEach-Object {
            [IO.File]::ReadAllText($_, [Text.UTF8Encoding]::new($false, $true))
        })
        Assert-True (@($results | Where-Object { $_ -ceq 'ACQUIRED' }).Count -eq 1) 'Concurrent initialization did not produce exactly one lock owner.'
        Assert-True (@($results | Where-Object { $_ -clike 'REJECTED *locked by another orchestration process*' }).Count -eq 1) 'Concurrent initialization did not fail the non-owner closed on the state lock.'
    }
    finally {
        foreach ($process in $processes) {
            if (-not $process.HasExited) {
                $process.Kill($true)
                [void]$process.WaitForExit(5000)
            }
            $process.Dispose()
        }
    }
}

function Invoke-OrchestratorHeadRace {
    param(
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$Edition,
        [Parameter(Mandatory = $true)][ValidateSet('Prepare', 'ImportClientSignatures')][string]$Phase,
        [Parameter(Mandatory = $true)][string]$PlanPath,
        [Parameter(Mandatory = $true)][string]$StateRoot,
        [Parameter(Mandatory = $true)][ValidateSet('request', 'import')][string]$Purpose,
        [Parameter(Mandatory = $true)][string]$FaultPoint,
        [string]$ResponsePath = '',
        [string]$PromotionRoot = '',
        [string]$FeedPromotionResponsePath = '',
        [string]$ExpectedFeedIdentitySha256 = '',
        [string]$ExpectedChannelHead = '',
        [string]$ExpectedJournalHead = '',
        [string]$ExpectedHeadSha256 = ''
    )

    $plan = Read-Json -Path $PlanPath
    $operationId = ([Guid]::Parse([string]$plan.orchestrationId)).ToString('N')
    $stagingPrefix = ".ensou-launcher-production-staging-$operationId-$Purpose-"
    $stateParent = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($StateRoot))
    $pwshPath = [IO.Path]::GetFullPath((Join-Path $PSHOME 'pwsh.exe'))
    if (-not (Test-Path -LiteralPath $pwshPath -PathType Leaf)) {
        throw 'The current PowerShell runtime has no exact pwsh.exe child-process path.'
    }
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $pwshPath
    $startInfo.WorkingDirectory = [IO.Path]::GetFullPath($RepoRoot)
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in @(
            '-NoLogo',
            '-NoProfile',
            '-NonInteractive',
            '-File',
            $ScriptPath,
            '-RepositoryRoot',
            $RepoRoot,
            '-Edition',
            $Edition,
            '-Phase',
            $Phase,
            '-PlanPath',
            $PlanPath,
            '-StateRoot',
            $StateRoot,
            '-FaultPoint',
            $FaultPoint)) {
        [void]$startInfo.ArgumentList.Add([string]$argument)
    }
    if ($ResponsePath) {
        [void]$startInfo.ArgumentList.Add('-ResponsePath')
        [void]$startInfo.ArgumentList.Add($ResponsePath)
    }
    foreach ($feedPromotionArgument in @(
            [pscustomobject]@{
                Name = 'PromotionRoot'
                Value = $PromotionRoot
            },
            [pscustomobject]@{
                Name = 'FeedPromotionResponsePath'
                Value = $FeedPromotionResponsePath
            },
            [pscustomobject]@{
                Name = 'ExpectedFeedIdentitySha256'
                Value = $ExpectedFeedIdentitySha256
            },
            [pscustomobject]@{
                Name = 'ExpectedChannelHead'
                Value = $ExpectedChannelHead
            },
            [pscustomobject]@{
                Name = 'ExpectedJournalHead'
                Value = $ExpectedJournalHead
            })) {
        if ([string]$feedPromotionArgument.Value) {
            [void]$startInfo.ArgumentList.Add(
                '-' + [string]$feedPromotionArgument.Name)
            [void]$startInfo.ArgumentList.Add(
                [string]$feedPromotionArgument.Value)
        }
    }
    if ($ExpectedHeadSha256) {
        [void]$startInfo.ArgumentList.Add('-ExpectedHeadSha256')
        [void]$startInfo.ArgumentList.Add($ExpectedHeadSha256)
    }

    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $started = $false
    try {
        if (-not $process.Start()) {
            throw "Could not start the real $Purpose HEAD-race orchestrator process."
        }
        $started = $true
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $readyPath = $null
        $deadline = [DateTimeOffset]::UtcNow.AddSeconds(30)
        while ($null -eq $readyPath -and [DateTimeOffset]::UtcNow -lt $deadline) {
            $candidates = @(
                Get-ChildItem -LiteralPath $stateParent -Directory -Force -Filter ($stagingPrefix + '*') -ErrorAction SilentlyContinue |
                    Where-Object {
                        Test-Path -LiteralPath (Join-Path $_.FullName 'checkout-admission.ready')
                    })
            if ($candidates.Count -gt 1) {
                throw "Multiple operation-owned $Purpose staging roots reached the checkout race gate."
            }
            if ($candidates.Count -eq 1) {
                $readyPath = Join-Path $candidates[0].FullName 'checkout-admission.ready'
                break
            }
            if ($process.HasExited) {
                break
            }
            Start-Sleep -Milliseconds 25
        }
        if ($null -eq $readyPath) {
            if (-not $process.HasExited) {
                $process.Kill($true)
                [void]$process.WaitForExit(10000)
            }
            $earlyOutput = $stdoutTask.GetAwaiter().GetResult() + [char]10 + $stderrTask.GetAwaiter().GetResult()
            throw "Real $Purpose HEAD-race process did not reach its checkout gate: $earlyOutput"
        }

        [void](Invoke-Git -Root $RepoRoot -Arguments @(
            'commit', '--allow-empty', '--quiet', '-m', "$Purpose checkout race"))
        [IO.File]::Copy(
            $readyPath,
            (Join-Path ([IO.Path]::GetDirectoryName($readyPath)) 'checkout-admission.continue'),
            $false)
        if (-not $process.WaitForExit(30000)) {
            $process.Kill($true)
            [void]$process.WaitForExit(10000)
            throw "Real $Purpose HEAD-race process did not terminate after checkout admission resumed."
        }
        $output = $stdoutTask.GetAwaiter().GetResult() + [char]10 + $stderrTask.GetAwaiter().GetResult()
        if ($process.ExitCode -eq 0) {
            throw "Real $Purpose HEAD-race process unexpectedly succeeded: $output"
        }
        if (-not $output.Contains('HEAD differs', [StringComparison]::OrdinalIgnoreCase)) {
            throw "Real $Purpose HEAD-race process failed for the wrong reason: $output"
        }
        $script:AssertionCount += 2
        $script:ExpectedFailureCount++
        return [pscustomobject]@{
            ExitCode = $process.ExitCode
            Output = $output
            StagingPrefix = $stagingPrefix
            StateParent = $stateParent
        }
    }
    finally {
        if ($started -and -not $process.HasExited) {
            $process.Kill($true)
            [void]$process.WaitForExit(10000)
        }
        $process.Dispose()
    }
}

function Invoke-OrchestratorValidatedMoveMutationRace {
    param(
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][hashtable]$Arguments,
        [Parameter(Mandatory = $true)][string]$Purpose,
        [Parameter(Mandatory = $true)][string]$BundleRelativeFile,
        [string]$MutationSourcePath = '',
        [switch]$InventoryOnlyMutation
    )

    $inventoryOnlyRelativeFile =
        'imports\pilot-evidence.v1\signed\Ensou.Dsh.Enterprise.Installer.exe'
    if ($InventoryOnlyMutation) {
        if ([string]::IsNullOrWhiteSpace($MutationSourcePath) -or
            $BundleRelativeFile -cne $inventoryOnlyRelativeFile) {
            throw 'Inventory-only mutation requires its non-empty synthetic PE source and exact signed-installer-shaped bundle path.'
        }
    }
    elseif (-not [string]::IsNullOrWhiteSpace($MutationSourcePath)) {
        throw 'Ordinary validated-move mutation cannot supply a replacement source.'
    }

    $plan = Read-Json -Path ([string]$Arguments.PlanPath)
    $operationId = ([Guid]::Parse([string]$plan.orchestrationId)).ToString('N')
    $stagingPrefix = ".ensou-launcher-production-staging-$operationId-$Purpose-"
    $rejectedPrefix =
        ".ensou-launcher-production-rejected-$operationId-$Purpose-"
    $stateRoot = [IO.Path]::GetFullPath([string]$Arguments.StateRoot)
    $stateParent = [IO.Path]::GetDirectoryName($stateRoot)
    $rejectedBefore = @(
        Get-ChildItem -LiteralPath $stateParent -Directory -Force `
            -Filter ($rejectedPrefix + '*') -ErrorAction SilentlyContinue |
            ForEach-Object { [string]$_.FullName })
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = [IO.Path]::GetFullPath((Join-Path $PSHOME 'pwsh.exe'))
    $startInfo.WorkingDirectory = [IO.Path]::GetFullPath($RepoRoot)
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in @(
            '-NoLogo', '-NoProfile', '-NonInteractive', '-File', $ScriptPath,
            '-RepositoryRoot', $RepoRoot)) {
        [void]$startInfo.ArgumentList.Add([string]$argument)
    }
    foreach ($entry in $Arguments.GetEnumerator()) {
        [void]$startInfo.ArgumentList.Add('-' + [string]$entry.Key)
        [void]$startInfo.ArgumentList.Add([string]$entry.Value)
    }
    [void]$startInfo.ArgumentList.Add('-FaultPoint')
    [void]$startInfo.ArgumentList.Add('TestOnlyWaitBeforeValidatedBundleAtomicMove')

    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $started = $false
    try {
        if (-not $process.Start()) {
            throw "Could not start the real $Purpose validated-move race process."
        }
        $started = $true
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $stagingRoot = $null
        $readyPath = $null
        $deadline = [DateTimeOffset]::UtcNow.AddSeconds(30)
        while ($null -eq $readyPath -and [DateTimeOffset]::UtcNow -lt $deadline) {
            $candidates = @(
                Get-ChildItem -LiteralPath $stateParent -Directory -Force `
                    -Filter ($stagingPrefix + '*') -ErrorAction SilentlyContinue |
                    Where-Object {
                        Test-Path -LiteralPath `
                            (Join-Path $_.FullName 'checkout-admission.ready')
                    })
            if ($candidates.Count -gt 1) {
                throw "Multiple $Purpose staging roots reached the validated-move gate."
            }
            if ($candidates.Count -eq 1) {
                $stagingRoot = [string]$candidates[0].FullName
                $readyPath = Join-Path $stagingRoot 'checkout-admission.ready'
                break
            }
            if ($process.HasExited) { break }
            Start-Sleep -Milliseconds 25
        }
        if ($null -eq $readyPath) {
            if (-not $process.HasExited) {
                $process.Kill($true)
                [void]$process.WaitForExit(10000)
            }
            $earlyOutput =
                $stdoutTask.GetAwaiter().GetResult() + [char]10 +
                $stderrTask.GetAwaiter().GetResult()
            throw "Real $Purpose process did not reach the validated-move gate: $earlyOutput"
        }
        $ready = Read-Json -Path $readyPath
        Assert-True `
            ([string]$ready.gateType -ceq
                'ensou-dsh-launcher-test-only-checkout-admission' -and
             [string]$ready.purpose -ceq $Purpose) `
            "Real $Purpose validated-move gate metadata changed."
        $mutationPath = Join-Path $stagingRoot $BundleRelativeFile
        if (-not $InventoryOnlyMutation) {
            [byte[]]$originalBytes = [IO.File]::ReadAllBytes($mutationPath)
            [byte[]]$mutatedBytes = [byte[]]::new($originalBytes.Length + 1)
            [Array]::Copy($originalBytes, $mutatedBytes, $originalBytes.Length)
            $mutatedBytes[$mutatedBytes.Length - 1] = 0x20
            [IO.File]::WriteAllBytes($mutationPath, $mutatedBytes)
        }
        else {
            [IO.Directory]::CreateDirectory(
                [IO.Path]::GetDirectoryName($mutationPath)) | Out-Null
            [IO.File]::Copy(
                [IO.Path]::GetFullPath($MutationSourcePath),
                $mutationPath,
                $false)
        }
        [IO.File]::Copy(
            $readyPath,
            (Join-Path $stagingRoot 'checkout-admission.continue'),
            $false)
        if (-not $process.WaitForExit(30000)) {
            $process.Kill($true)
            [void]$process.WaitForExit(10000)
            throw "Real $Purpose process did not terminate after validated-move mutation."
        }
        $output =
            $stdoutTask.GetAwaiter().GetResult() + [char]10 +
            $stderrTask.GetAwaiter().GetResult()
        Assert-True ($process.ExitCode -ne 0) `
            "Real $Purpose validated-move mutation unexpectedly succeeded."
        $failureReasonMatched = if (-not $InventoryOnlyMutation) {
            $output.Contains(
                'canonical',
                [StringComparison]::OrdinalIgnoreCase) -or
            $output.Contains(
                'changed',
                [StringComparison]::OrdinalIgnoreCase)
        }
        else {
            $output.Contains(
                'does not contain its exact expected inventory.',
                [StringComparison]::OrdinalIgnoreCase) -or
            $output.Contains(
                'contains unexpected or linked entry',
                [StringComparison]::OrdinalIgnoreCase)
        }
        Assert-True `
            $failureReasonMatched `
            "Real $Purpose validated-move mutation failed for the wrong reason: $output"
        $rejected = @(
            Get-ChildItem -LiteralPath $stateParent -Directory -Force `
                -Filter ($rejectedPrefix + '*') -ErrorAction SilentlyContinue |
                Where-Object {
                    [string]$_.FullName -notin $rejectedBefore
                })
        Assert-True ($rejected.Count -eq 1) `
            "Real $Purpose invalid canonical publication was not retained in exactly one diagnostic quarantine."
        Assert-True `
            (-not (Test-Path -LiteralPath $stagingRoot)) `
            "Real $Purpose staging residue remained after rejected publication."
        $script:ExpectedFailureCount++
        return [pscustomobject]@{
            ExitCode = $process.ExitCode
            Output = $output
            RejectedPath = [string]$rejected[0].FullName
        }
    }
    finally {
        if ($started -and -not $process.HasExited) {
            $process.Kill($true)
            [void]$process.WaitForExit(10000)
        }
        $process.Dispose()
    }
}

function Get-PeSecurityLayout {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    $peOffset = [BitConverter]::ToInt32($Bytes, 0x3c)
    $optionalOffset = $peOffset + 24
    $magic = [BitConverter]::ToUInt16($Bytes, $optionalOffset)
    $dataDirectoryOffset = if ($magic -eq 0x10b) {
        $optionalOffset + 96
    }
    elseif ($magic -eq 0x20b) {
        $optionalOffset + 112
    }
    else {
        throw 'Signed fixture is not a supported PE image.'
    }
    $securityEntryOffset = $dataDirectoryOffset + 32
    return [pscustomobject]@{
        ChecksumOffset = $optionalOffset + 64
        SecurityEntryOffset = $securityEntryOffset
        CertificateOffset = [int][BitConverter]::ToUInt32($Bytes, $securityEntryOffset)
        CertificateSize = [int][BitConverter]::ToUInt32($Bytes, $securityEntryOffset + 4)
    }
}

function New-UnsignedPeFixture {
    param(
        [Parameter(Mandatory = $true)][string]$OutputPath
    )

    [IO.File]::Copy($script:UnsignedPeFixturePath, $OutputPath, $false)
}

function New-UnsignedPeFixtureFromSigned {
    param(
        [Parameter(Mandatory = $true)][string]$SignedPath,
        [Parameter(Mandatory = $true)][string]$OutputPath
    )

    [byte[]]$bytes = [IO.File]::ReadAllBytes($SignedPath)
    $layout = Get-PeSecurityLayout -Bytes $bytes
    if ($layout.CertificateOffset -le 0 -or
        $layout.CertificateSize -le 0 -or
        $layout.CertificateOffset + $layout.CertificateSize -gt $bytes.Length) {
        throw 'Signed PE fixture has no removable Authenticode certificate table.'
    }
    for ($index = 0; $index -lt 4; $index++) {
        $bytes[$layout.ChecksumOffset + $index] = 0
    }
    for ($index = 0; $index -lt 8; $index++) {
        $bytes[$layout.SecurityEntryOffset + $index] = 0
    }
    [Array]::Resize([ref]$bytes, $layout.CertificateOffset)
    [IO.File]::WriteAllBytes($OutputPath, $bytes)
}

function New-FoundationSignedPeFixture {
    param(
        [Parameter(Mandatory = $true)][string]$UnsignedPath,
        [Parameter(Mandatory = $true)][string]$OutputPath
    )

    # Foundation-state tests exercise schema, byte identity, and CAS replay;
    # production Authenticode/RFC3161 admission is tested on its separate path.
    # Append one bounded WIN_CERTIFICATE-shaped table so the signed fixture has
    # different full bytes while retaining the exact unsigned PE content hash.
    [byte[]]$bytes = [IO.File]::ReadAllBytes($UnsignedPath)
    $layout = Get-PeSecurityLayout -Bytes $bytes
    if ($layout.CertificateOffset -ne 0 -or $layout.CertificateSize -ne 0) {
        throw 'Foundation unsigned PE fixture unexpectedly has a certificate table.'
    }
    $certificateOffset = $bytes.Length
    $certificateSize = 8
    [Array]::Resize([ref]$bytes, $certificateOffset + $certificateSize)
    [BitConverter]::GetBytes([uint32]$certificateSize).CopyTo(
        $bytes,
        $certificateOffset)
    [BitConverter]::GetBytes([uint16]0x0200).CopyTo(
        $bytes,
        $certificateOffset + 4)
    [BitConverter]::GetBytes([uint16]0x0002).CopyTo(
        $bytes,
        $certificateOffset + 6)
    [BitConverter]::GetBytes([uint32]$certificateOffset).CopyTo(
        $bytes,
        $layout.SecurityEntryOffset)
    [BitConverter]::GetBytes([uint32]$certificateSize).CopyTo(
        $bytes,
        $layout.SecurityEntryOffset + 4)
    [IO.File]::WriteAllBytes($OutputPath, $bytes)
}

function New-TestSigningCertificate {
    param(
        [Parameter(Mandatory = $true)][string]$Subject,
        [switch]$Timestamping
    )

    $key = [Security.Cryptography.ECDsa]::Create(
        [Security.Cryptography.ECCurve+NamedCurves]::nistP256)
    $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
        $Subject,
        $key,
        [Security.Cryptography.HashAlgorithmName]::SHA256)
    $request.CertificateExtensions.Add(
        [Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new(
            $false,
            $false,
            0,
            $true))
    $request.CertificateExtensions.Add(
        [Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
            [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature,
            $true))
    $oids = [Security.Cryptography.OidCollection]::new()
    if ($Timestamping) {
        [void]$oids.Add([Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.8'))
    }
    else {
        [void]$oids.Add([Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.3'))
    }
    $request.CertificateExtensions.Add(
        [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new(
            $oids,
            $true))
    $certificate = $request.CreateSelfSigned(
        [DateTimeOffset]::UtcNow.AddDays(-1),
        [DateTimeOffset]::UtcNow.AddDays(2))
    return [pscustomobject]@{
        Key = $key
        Certificate = $certificate
    }
}

function New-TestPrimaryCms {
    param(
        [Parameter(Mandatory = $true)][Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory = $true)][byte[]]$Content
    )

    $cms = [Security.Cryptography.Pkcs.SignedCms]::new(
        [Security.Cryptography.Pkcs.ContentInfo]::new($Content),
        $false)
    $signer = [Security.Cryptography.Pkcs.CmsSigner]::new(
        [Security.Cryptography.Pkcs.SubjectIdentifierType]::IssuerAndSerialNumber,
        $Certificate)
    $signer.IncludeOption =
        [Security.Cryptography.X509Certificates.X509IncludeOption]::EndCertOnly
    $cms.ComputeSignature($signer)
    return $cms
}

function New-TestRfc3161Token {
    param(
        [Parameter(Mandatory = $true)][Security.Cryptography.Pkcs.SignerInfo]$PrimarySigner,
        [Parameter(Mandatory = $true)][Security.Cryptography.X509Certificates.X509Certificate2]$TimestampCertificate
    )

    $signatureHash = [Security.Cryptography.SHA256]::HashData(
        $PrimarySigner.GetSignature())
    $writer = [Formats.Asn1.AsnWriter]::new(
        [Formats.Asn1.AsnEncodingRules]::DER)
    $null = $writer.PushSequence()
    $writer.WriteInteger([long]1)
    $writer.WriteObjectIdentifier('1.3.6.1.4.1.55555.1')
    $null = $writer.PushSequence()
    $null = $writer.PushSequence()
    $writer.WriteObjectIdentifier('2.16.840.1.101.3.4.2.1')
    $writer.WriteNull()
    $writer.PopSequence()
    $writer.WriteOctetString($signatureHash)
    $writer.PopSequence()
    $writer.WriteInteger([long]1)
    $writer.WriteGeneralizedTime([DateTimeOffset]::UtcNow, $true)
    $writer.PopSequence()
    $tstInfo = $writer.Encode()

    $contentInfo = [Security.Cryptography.Pkcs.ContentInfo]::new(
        [Security.Cryptography.Oid]::new('1.2.840.113549.1.9.16.1.4'),
        $tstInfo)
    $cms = [Security.Cryptography.Pkcs.SignedCms]::new($contentInfo, $false)
    $signer = [Security.Cryptography.Pkcs.CmsSigner]::new(
        [Security.Cryptography.Pkcs.SubjectIdentifierType]::IssuerAndSerialNumber,
        $TimestampCertificate)
    $signer.IncludeOption =
        [Security.Cryptography.X509Certificates.X509IncludeOption]::EndCertOnly

    $essWriter = [Formats.Asn1.AsnWriter]::new(
        [Formats.Asn1.AsnEncodingRules]::DER)
    $null = $essWriter.PushSequence()
    $null = $essWriter.PushSequence()
    $null = $essWriter.PushSequence()
    $essWriter.WriteOctetString(
        [Security.Cryptography.SHA256]::HashData(
            $TimestampCertificate.RawData))
    $essWriter.PopSequence()
    $essWriter.PopSequence()
    $essWriter.PopSequence()
    $essAttribute = [Security.Cryptography.AsnEncodedData]::new(
        [Security.Cryptography.Oid]::new('1.2.840.113549.1.9.16.2.47'),
        $essWriter.Encode())
    [void]$signer.SignedAttributes.Add($essAttribute)
    $cms.ComputeSignature($signer)
    return $cms.Encode()
}

function Copy-State {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    $copyTimer = [Diagnostics.Stopwatch]::StartNew()
    $copyLabel = [IO.Path]::GetFileName($Destination)
    Write-Host "STATE-COPY-START $copyLabel"
    try {
        [IO.Directory]::CreateDirectory($Destination) | Out-Null
        foreach ($entry in Get-ChildItem -LiteralPath $Source -Force) {
            Copy-Item -LiteralPath $entry.FullName -Destination $Destination -Recurse -Force
        }
    }
    finally {
        $copyTimer.Stop()
        Write-Host "STATE-COPY-END $copyLabel elapsedMs=$($copyTimer.ElapsedMilliseconds)"
    }
}

# State/schema/CAS contract fixture only. This deliberately bypasses response
# authentication and PE/RFC3161 admission; the production-import integration
# track below must pass Invoke-LauncherProductionRelease.ps1 before it can move
# beyond CLIENT_SIGNING_REQUESTED.
function Add-V2FoundationStateContractClientEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$StateRoot,
        [Parameter(Mandatory = $true)][string]$StateSchemaPath
    )

    $plan = Read-Json -Path (Join-Path $StateRoot 'plan.json')
    $importRoot = Join-Path $StateRoot 'imports\client-signing.v1'
    $signedRoot = Join-Path $importRoot 'signed'
    [IO.Directory]::CreateDirectory($signedRoot) | Out-Null
    $files = [Collections.Generic.List[object]]::new()
    foreach ($input in @($plan.clientSigningInputs)) {
        $sourcePath = Join-Path (Join-Path $StateRoot 'requests\client-signing.v1\unsigned') ([string]$input.fileName)
        $signedPath = Join-Path $signedRoot ([string]$input.fileName)
        [IO.File]::Copy($sourcePath, $signedPath, $false)
        $signedBytes = [IO.File]::ReadAllBytes($signedPath)
        $files.Add([ordered]@{
            role = [string]$input.role
            fileName = [string]$input.fileName
            sizeBytes = [int64]$signedBytes.LongLength
            sha256 = Get-Sha256 -Path $signedPath
            peContentSha256 = Get-PeContentSha256 -Bytes $signedBytes
            timestampProtocol = 'RFC3161'
        })
    }
    $responsePath = Join-Path $importRoot 'signing-response.v1.json'
    Write-Json -Path $responsePath -Value ([ordered]@{
        fixtureType = 'ensou-dsh-launcher-foundation-state-contract-only'
        productionImportAdmission = $false
        targetChannel = [string]$plan.targetChannel
    })
    $completedAtUtc = [DateTimeOffset]::UtcNow.ToUniversalTime().ToString(
        'yyyy-MM-ddTHH:mm:ssZ',
        [Globalization.CultureInfo]::InvariantCulture)
    $manifestUri = [Uri]::new([string]$plan.manifestUri, [UriKind]::Absolute)
    $artifactUri = [Uri]::new([string]$plan.artifactBaseUri, [UriKind]::Absolute)
    $manifestOrigin = $manifestUri.GetLeftPart([UriPartial]::Authority) + '/'
    $artifactOrigin = $artifactUri.GetLeftPart([UriPartial]::Authority) + '/'
    $releaseManifestTrustProbes = [Collections.Generic.List[object]]::new()
    for ($index = 0; $index -lt @($plan.clientSigningInputs).Count; $index++) {
        $input = $plan.clientSigningInputs[$index]
        if ([string]$plan.edition -ceq 'Enterprise' -and
            [string]$input.role -ceq 'maintenance') {
            continue
        }
        $probe = if ([string]$plan.edition -ceq 'Personal') {
            [ordered]@{
                schemaVersion = 2
                productionBuild = $true
                manifestOrigin = $manifestOrigin
                artifactOrigin = $artifactOrigin
                product = 'ensou-dsh-personal'
                environment = 'production'
                channel = [string]$plan.targetChannel
                startupStubVersion = [string]$plan.releaseCompatibility.startupStubVersion
                releaseKeyId = [string]$plan.releaseManifestTrust.keyId
                releaseKeyX = [string]$plan.releaseManifestTrust.x
                releaseKeyY = [string]$plan.releaseManifestTrust.y
                canonicalLowSFromSequence =
                    [int64]$plan.releaseCompatibility.canonicalLowSFromSequence
                authenticodeSignerSha256Thumbprint =
                    ([string]$plan.authenticodePolicy.signerSha256Thumbprint).ToUpperInvariant()
            }
        }
        else {
            [ordered]@{
                schemaVersion = 1
                probeType = 'ensou-dsh-enterprise-release-manifest-trust-probe-v1'
                edition = 'Enterprise'
                product = 'ensou-dsh-enterprise'
                environment = 'production'
                channel = 'stable'
                manifestUri = [string]$plan.manifestUri
                manifestOrigin = $manifestOrigin
                artifactOrigin = $artifactOrigin
                authenticodeSignerSha256Thumbprint =
                    [string]$plan.authenticodePolicy.signerSha256Thumbprint
                releaseManifestTrust = $plan.releaseManifestTrust
                releaseCompatibility = $plan.releaseCompatibility
            }
        }
        $probeBytes = ConvertTo-ProductionJsonBytes -Value $probe
        $releaseManifestTrustProbes.Add([ordered]@{
            role = [string]$input.role
            fileName = [string]$input.fileName
            probeSha256 = Get-ProductionSha256Bytes -Bytes $probeBytes
        })
    }
    $state = Get-ProductionReleaseState -StateRoot $StateRoot -StateSchemaPath $StateSchemaPath
    return Add-ProductionReleaseReceipt `
        -StateRoot $StateRoot `
        -StateSchemaPath $StateSchemaPath `
        -Phase 'CLIENT_SIGNATURES_IMPORTED' `
        -ExpectedPreviousPhase 'CLIENT_SIGNING_REQUESTED' `
        -ExpectedHeadSha256 ([string]$state.HeadSha256) `
        -Data ([ordered]@{
            responseRelativePath = 'imports/client-signing.v1/signing-response.v1.json'
            responseSha256 = Get-Sha256 -Path $responsePath
            completedAtUtc = $completedAtUtc
            authenticationKeyId = [string]$plan.externalResponseTrusts.clientSigning.keyId
            authenticationPurpose = 'client-signing-response'
            authenticationPayloadType = 'ensou-dsh-launcher-external-signing-response-authentication-v2'
            releaseManifestTrustProbeStatus = 'VERIFIED'
            releaseManifestTrustProbes = $releaseManifestTrustProbes
            files = @($files)
        })
}

function New-V2FoundationEvidenceData {
    param(
        [Parameter(Mandatory = $true)][int]$Revision,
        [Parameter(Mandatory = $true)][string]$Phase
    )

    if ($Revision -in @(6, 7)) {
        throw 'Foundation r6/r7 transitions require an edition-specific typed Installer fixture.'
    }
    $phaseSlug = $Phase.ToLowerInvariant().Replace('_', '-')
    return [ordered]@{
        evidenceType = $Phase
        relativePath = "evidence/foundation/$($Revision.ToString('00'))-$phaseSlug.json"
        sha256 = ([string]$Revision).PadLeft(64, '0')
    }
}

function New-PersonalV2FoundationInstallerTransition {
    param(
        [Parameter(Mandatory = $true)][psobject]$State,
        [Parameter(Mandatory = $true)][ValidateSet(6, 7)][int]$Revision
    )

    # This is a typed state-replay fixture only. Its WIN_CERTIFICATE-shaped PE
    # and declared signer data are synthetic and must never be interpreted as
    # successful production Authenticode/RFC3161 admission.
    if ([string]$State.Identity.edition -cne 'Personal' -or
        [string]$State.TargetChannel -cne 'pilot') {
        throw 'Personal foundation Installer fixture requires Personal/pilot state.'
    }
    $requestRoot = Join-Path $State.StateRoot 'requests\installer-signing.v2'
    $requestPath = Join-Path $requestRoot 'installer-signing-request.v2.json'
    $installerFileName = 'Ensou.Dsh.Personal.Installer.exe'
    $hashObject = {
        param([Parameter(Mandatory = $true)]$Value)
        return Get-ProductionSha256Bytes -Bytes (
            ConvertTo-ProductionJsonBytes -Value $Value)
    }
    $hashLabel = {
        param([Parameter(Mandatory = $true)][string]$Label)
        return Get-ProductionSha256Bytes -Bytes $utf8.GetBytes($Label)
    }

    if ($Revision -eq 6) {
        if ([int]$State.Head.revision -ne 5 -or
            [string]$State.Head.phase -cne
                'PILOT_SIGNED_CANDIDATE_IMPORTED') {
            throw 'Personal foundation r6 fixture requires an exact r5 state.'
        }
        $unsignedRoot = Join-Path $requestRoot 'unsigned'
        $payloadRoot = Join-Path $requestRoot 'payload'
        $trustedBuildRoot = Join-Path $requestRoot 'trusted-build'
        foreach ($directory in @(
                $requestRoot, $unsignedRoot, $payloadRoot,
                $trustedBuildRoot)) {
            [IO.Directory]::CreateDirectory($directory) | Out-Null
        }

        $r5Files = @($State.Receipts[4].data.files)
        $r5CandidateRoot = Split-Path -Parent (Join-Path `
            $State.StateRoot `
            ([string]$State.Receipts[4].data.responseRelativePath))
        $payloadFiles = [Collections.Generic.List[object]]::new()
        foreach ($definition in @(
                [pscustomobject]@{
                    Role = 'release-manifest'
                    FileName = 'release-set.v2.json'
                    SourceRole = 'release-manifest'
                },
                [pscustomobject]@{
                    Role = 'startup-stub'
                    FileName = 'Ensou.Dsh.Bootstrapper.exe'
                    SourceRole = ''
                },
                [pscustomobject]@{
                    Role = 'client-bundle'
                    FileName = 'client-bundle.zip'
                    SourceRole = 'client-bundle'
                },
                [pscustomobject]@{
                    Role = 'runtime'
                    FileName = 'runtime.zip'
                    SourceRole = 'runtime'
                })) {
            $destination = Join-Path $payloadRoot $definition.FileName
            if ([string]::IsNullOrEmpty([string]$definition.SourceRole)) {
                [IO.File]::Copy(
                    $script:UnsignedPeFixturePath,
                    $destination,
                    $false)
            }
            else {
                $matches = @($r5Files | Where-Object {
                        [string]$_.role -ceq [string]$definition.SourceRole
                    })
                if ($matches.Count -ne 1) {
                    throw "Personal foundation r6 fixture lacks one exact '$($definition.SourceRole)' r5 file."
                }
                [IO.File]::Copy(
                    (Join-Path $r5CandidateRoot `
                        ([string]$matches[0].relativePath)),
                    $destination,
                    $false)
            }
            $item = Get-Item -LiteralPath $destination -Force
            $payloadFiles.Add([ordered]@{
                role = [string]$definition.Role
                fileName = [string]$definition.FileName
                relativePath = 'payload/' + [string]$definition.FileName
                sizeBytes = [int64]$item.Length
                sha256 = Get-Sha256 -Path $destination
            })
        }

        $unsignedPath = Join-Path $unsignedRoot $installerFileName
        New-UnsignedPeFixture -OutputPath $unsignedPath
        [byte[]]$unsignedBytes = [IO.File]::ReadAllBytes($unsignedPath)
        $unsignedInstaller = [ordered]@{
            role = 'installer'
            fileName = $installerFileName
            relativePath = 'unsigned/' + $installerFileName
            sizeBytes = [int64]$unsignedBytes.LongLength
            sha256 = Get-Sha256 -Path $unsignedPath
            peContentSha256 = Get-PeContentSha256 -Bytes $unsignedBytes
            authenticodeStatus = 'NotSigned'
        }
        $source = [ordered]@{
            commit = 'a' * 40
            tree = 'b' * 40
            status = 'CLEAN_TRACKED_HEAD'
            snapshotContract =
                'git-head-archive-held-file-leases-directory-identity-mutation-monitor-v2'
            rootProject =
                'src/Ensou.Dsh.Personal.Installer/Ensou.Dsh.Personal.Installer.csproj'
            fileCount = 1
            totalSizeBytes = 1
            inventorySha256 = & $hashLabel 'personal-foundation-source'
        }
        $payload = [ordered]@{
            status = 'EXACT_FOUR_FILE_BYTE_CLOSURE_VERIFIED'
            authenticationStatus =
                'STRUCTURE_AND_ARTIFACT_HASHES_VERIFIED_SIGNED_MANIFEST_TRUST_NOT_YET_SHARED_R6_ADMITTED'
            inventorySha256 = & $hashObject @($payloadFiles)
            files = @($payloadFiles)
        }
        $compiledTrust = [ordered]@{
            manifestOrigin = 'https://updates.ensou.invalid/'
            artifactOrigin = 'https://artifacts.ensou.invalid/'
            channel = 'pilot'
            releaseKeyId = 'foundation-personal-release-key'
            releaseKeyIdentitySha256 =
                & $hashLabel 'personal-foundation-release-key'
            startupStubVersion = 'foundation-state-only'
            canonicalLowSFromSequence = 1
            authenticodeSignerSha256Thumbprint =
                & $hashLabel 'personal-foundation-authenticode'
        }
        $packageClosure = [ordered]@{
            lockRelativePath =
                'repo/installer/personal-publish-runtime-packs.lock.json'
            lockSha256 = & $hashLabel 'personal-foundation-package-lock'
            packageCount = 4
            inventorySha256 =
                & $hashLabel 'personal-foundation-package-inventory'
        }
        $sdkClosure = [ordered]@{
            sdkVersion = '10.0.302'
            archiveFileName = 'dotnet-sdk-10.0.302-win-x64.zip'
            archiveSha512 = 'c' * 128
            lockRelativePath =
                'repo/release/locks/dotnet-sdk-10.0.302-win-x64.files.lock.json'
            lockSha256 = & $hashLabel 'personal-foundation-sdk-lock'
            inventorySha256 = & $hashLabel 'personal-foundation-sdk-inventory'
            fileCount = 1
            totalSizeBytes = 1
            status = 'VERIFIED'
            privateCopyPolicy =
                'create-only-private-copy-held-open-through-version-restore-publish-v1'
        }
        $now = [DateTimeOffset]::UtcNow
        $createdAtUtc = ConvertTo-ProductionUtc -Value $now.AddMinutes(-1)
        $expiresAtUtc = ConvertTo-ProductionUtc -Value $now.AddHours(12)
        $buildExecution = [ordered]@{
            startedAtUtc = ConvertTo-ProductionUtc -Value $now.AddMinutes(-3)
            completedAtUtc = ConvertTo-ProductionUtc -Value $now.AddMinutes(-2)
            exitCode = 0
            runtimeIdentifier = 'win-x64'
            selfContained = $true
            singleFile = $true
            offlineRestore = $true
            inheritedEnvironmentCleared = $true
            unsignedArtifactExecution = 'FORBIDDEN_AND_NOT_PERFORMED'
        }
        $resources = @($payloadFiles | ForEach-Object {
                [ordered]@{
                    role = [string]$_.role
                    logicalName =
                        'Ensou.Dsh.Personal.Installer.Payload.' +
                            [string]$_.fileName
                    sizeBytes = [int64]$_.sizeBytes
                    sha256 = [string]$_.sha256
                    status = 'VERIFIED'
                }
            })
        $resourceBinding = [ordered]@{
            verificationMethod =
                'pe-metadata-embedded-resource-inspection-no-assembly-load-v1'
            status = 'VERIFIED'
            resourceSetSha256 = & $hashObject $resources
            resources = $resources
            unsignedInstallerSha256 = [string]$unsignedInstaller.sha256
        }
        $admission = [ordered]@{
            status = 'READY'
            blocker = 'INSTALLER_SIGNING_RESPONSE_REQUIRED'
            productionAdmission = 'NO_GO'
            reason =
                'Synthetic foundation state remains blocked on a real signing response.'
        }
        $trustedBuildEvidence = [ordered]@{
            schemaVersion = 1
            evidenceType = 'ensou-dsh-personal-installer-trusted-build'
            buildId = '66666666-6666-4666-8666-666666666666'
            edition = 'Personal'
            channel = 'pilot'
            releaseSetId = [string]$State.Plan.releaseSetId
            source = $source
            payload = $payload
            compiledTrust = $compiledTrust
            packageClosure = $packageClosure
            sdkClosure = $sdkClosure
            buildExecution = $buildExecution
            unsignedInstaller = $unsignedInstaller
            resourceBinding = $resourceBinding
            signingRequestEligibility = $admission
        }
        $trustedBuildPath = Join-Path `
            $trustedBuildRoot `
            'trusted-build-evidence.v1.json'
        Write-CanonicalJson `
            -Path $trustedBuildPath `
            -Value $trustedBuildEvidence
        $trustedBuildItem = Get-Item -LiteralPath $trustedBuildPath -Force
        $trustedBuildDescriptor = [ordered]@{
            fileName = 'trusted-build-evidence.v1.json'
            relativePath = 'trusted-build/trusted-build-evidence.v1.json'
            sizeBytes = [int64]$trustedBuildItem.Length
            sha256 = Get-Sha256 -Path $trustedBuildPath
            productionAdmission = 'NO_GO'
        }
        $toolchain = [ordered]@{
            packageClosure = $packageClosure
            sdkClosure = $sdkClosure
            toolchainIdentitySha256 = & $hashObject ([ordered]@{
                    packageClosure = $packageClosure
                    sdkClosure = $sdkClosure
                })
        }
        $request = [ordered]@{
            schemaVersion = 2
            requestType = 'ensou-dsh-personal-installer-signing-request'
            orchestrationId = [string]$State.Identity.orchestrationId
            edition = 'Personal'
            releaseSetId = [string]$State.Plan.releaseSetId
            channel = 'pilot'
            planSha256 = [string]$State.Identity.planSha256
            baseHeadSha256 = [string]$State.HeadSha256
            baseRevision = 5
            basePhase = 'PILOT_SIGNED_CANDIDATE_IMPORTED'
            requestedRevision = 6
            requestNonce = 'A' * 43
            createdAtUtc = $createdAtUtc
            expiresAtUtc = $expiresAtUtc
            source = $source
            payload = $payload
            compiledTrust = $compiledTrust
            toolchain = $toolchain
            buildExecution = $buildExecution
            unsignedInstaller = $unsignedInstaller
            resourceBinding = $resourceBinding
            trustedBuildEvidence = $trustedBuildDescriptor
            responseAuthentication = [ordered]@{
                algorithm = 'ES256'
                keyId = 'foundation-personal-response-key'
                purpose = 'personal-installer-signing-response'
                payloadType =
                    'ensou-dsh-personal-installer-signing-response-authentication-v2'
                trustSha256 =
                    & $hashLabel 'personal-foundation-response-trust'
                maximumResponseAgeMinutes = 120
            }
            admission = $admission
        }
        Write-CanonicalJson -Path $requestPath -Value $request
        Assert-True `
            (Test-Json `
                -Json ([IO.File]::ReadAllText(
                    $trustedBuildPath,
                    [Text.UTF8Encoding]::new($false, $true))) `
                -SchemaFile (Join-Path $PSScriptRoot `
                    '..\schemas\personal-installer-trusted-build-evidence-v1.schema.json') `
                -ErrorAction Stop) `
            'Synthetic Personal foundation r6 trusted-build evidence does not satisfy its real schema.'
        Assert-True `
            (Test-Json `
                -Json ([IO.File]::ReadAllText(
                    $requestPath,
                    [Text.UTF8Encoding]::new($false, $true))) `
                -SchemaFile (Join-Path $PSScriptRoot `
                    '..\schemas\personal-installer-signing-request-v2.schema.json') `
                -ErrorAction Stop) `
            'Synthetic Personal foundation r6 request does not satisfy its real schema.'

        $r5ReceiptPath = Join-Path `
            (Join-Path $State.StateRoot 'receipts') `
            '0005-pilot-signed-candidate-imported.json'
        return [ordered]@{
            evidenceType = 'INSTALLER_SIGNING_REQUESTED'
            requestSchemaVersion = 2
            requestRelativePath =
                'requests/installer-signing.v2/installer-signing-request.v2.json'
            requestSha256 = Get-Sha256 -Path $requestPath
            baseHeadSha256 = [string]$request.baseHeadSha256
            baseReceiptSha256 = Get-Sha256 -Path $r5ReceiptPath
            sourceSha256 = & $hashObject $request.source
            payloadSha256 = & $hashObject $request.payload
            compiledTrustSha256 = & $hashObject $request.compiledTrust
            toolchainSha256 = & $hashObject $request.toolchain
            buildExecutionSha256 = & $hashObject $request.buildExecution
            resourceBindingSha256 = & $hashObject $request.resourceBinding
            trustedBuildEvidenceSha256 =
                & $hashObject $request.trustedBuildEvidence
            admissionSha256 = & $hashObject $request.admission
            r5ManifestSha256 = [string]$payloadFiles[0].sha256
            r5ClientBundleSha256 = [string]$payloadFiles[2].sha256
            r5RuntimeSha256 = [string]$payloadFiles[3].sha256
            unsignedInstaller = [ordered]@{
                fileName = $installerFileName
                relativePath =
                    'requests/installer-signing.v2/unsigned/' +
                        $installerFileName
                sizeBytes = [int64]$unsignedInstaller.sizeBytes
                sha256 = [string]$unsignedInstaller.sha256
                peContentSha256 =
                    [string]$unsignedInstaller.peContentSha256
            }
            createdAtUtc = [string]$request.createdAtUtc
            expiresAtUtc = [string]$request.expiresAtUtc
            authenticationKeyId =
                [string]$request.responseAuthentication.keyId
            authenticationPurpose =
                'personal-installer-signing-response'
            authenticationPayloadType =
                'ensou-dsh-personal-installer-signing-response-authentication-v2'
            admissionReason = 'INSTALLER_SIGNING_RESPONSE_REQUIRED'
            productionAdmission = 'NO_GO'
        }
    }

    if ([int]$State.Head.revision -ne 6 -or
        [string]$State.Head.phase -cne 'INSTALLER_SIGNING_REQUESTED') {
        throw 'Personal foundation r7 fixture requires an exact r6 state.'
    }
    $request = Read-Json -Path $requestPath
    $r6Data = $State.Receipts[5].data
    $importRoot = Join-Path $State.StateRoot 'imports\installer-signing.v2'
    $signedRoot = Join-Path $importRoot 'signed'
    [IO.Directory]::CreateDirectory($signedRoot) | Out-Null
    $signedPath = Join-Path $signedRoot $installerFileName
    New-FoundationSignedPeFixture `
        -UnsignedPath (Join-Path `
            (Join-Path $requestRoot 'unsigned') `
            $installerFileName) `
        -OutputPath $signedPath
    [byte[]]$signedBytes = [IO.File]::ReadAllBytes($signedPath)
    $signedItem = Get-Item -LiteralPath $signedPath -Force
    $signedSha256 = Get-Sha256 -Path $signedPath
    $signedPeContentSha256 = Get-PeContentSha256 -Bytes $signedBytes
    if ($signedPeContentSha256 -cne
        [string]$request.unsignedInstaller.peContentSha256) {
        throw 'Synthetic Personal foundation signed PE changed PE content.'
    }
    $manifest = @($request.payload.files | Where-Object {
            [string]$_.role -ceq 'release-manifest'
        })[0]
    $startup = @($request.payload.files | Where-Object {
            [string]$_.role -ceq 'startup-stub'
        })[0]
    $client = @($request.payload.files | Where-Object {
            [string]$_.role -ceq 'client-bundle'
        })[0]
    $runtime = @($request.payload.files | Where-Object {
            [string]$_.role -ceq 'runtime'
        })[0]
    [byte[]]$selfCheckCanonical = ConvertTo-ProductionJsonBytes -Value (
        [ordered]@{
            releaseSetId = [string]$request.releaseSetId
            inspectedInstallerSha256 = $signedSha256
        })
    [byte[]]$selfCheckLine = [byte[]]::new($selfCheckCanonical.Length + 1)
    [Array]::Copy(
        $selfCheckCanonical,
        $selfCheckLine,
        $selfCheckCanonical.Length)
    $selfCheckLine[$selfCheckLine.Length - 1] = 10
    $now = [DateTimeOffset]::UtcNow
    $selfCheck = [ordered]@{
        schemaVersion = 1
        evidenceType =
            'ensou-dsh-personal-installer-production-payload-self-check-consumption'
        command = '--production-payload-self-check'
        status = 'VERIFIED'
        exitCode = 0
        inspectedInstallerSha256 = $signedSha256
        releaseSetId = [string]$request.releaseSetId
        manifestSha256 = [string]$manifest.sha256
        manifestSizeBytes = [int64]$manifest.sizeBytes
        startupStubSha256 = [string]$startup.sha256
        startupStubSizeBytes = [int64]$startup.sizeBytes
        clientBundleSha256 = [string]$client.sha256
        clientBundleSizeBytes = [int64]$client.sizeBytes
        runtimeSha256 = [string]$runtime.sha256
        runtimeSizeBytes = [int64]$runtime.sizeBytes
        canonicalJsonSizeBytes = [int64]$selfCheckCanonical.LongLength
        canonicalJsonSha256 =
            Get-ProductionSha256Bytes -Bytes $selfCheckCanonical
        canonicalLineSizeBytes = [int64]$selfCheckLine.LongLength
        canonicalLineSha256 = Get-ProductionSha256Bytes -Bytes $selfCheckLine
        completedAtUtc = ConvertTo-ProductionUtc -Value $now.AddSeconds(-30)
    }
    $response = [ordered]@{
        schemaVersion = 2
        responseType = 'ensou-dsh-personal-installer-signing-response'
        orchestrationId = [string]$request.orchestrationId
        edition = 'Personal'
        releaseSetId = [string]$request.releaseSetId
        channel = 'pilot'
        planSha256 = [string]$request.planSha256
        requestRelativePath =
            'requests/installer-signing.v2/installer-signing-request.v2.json'
        requestSha256 = Get-Sha256 -Path $requestPath
        requestNonce = [string]$request.requestNonce
        baseHeadSha256 = [string]$request.baseHeadSha256
        admissionHeadSha256 = [string]$State.HeadSha256
        admissionRevision = 6
        r6ReceiptRelativePath =
            'receipts/0006-installer-signing-requested.json'
        r6ReceiptSha256 = [string]$State.Head.receiptSha256
        requestCreatedAtUtc = [string]$request.createdAtUtc
        requestExpiresAtUtc = [string]$request.expiresAtUtc
        completedAtUtc = ConvertTo-ProductionUtc -Value $now
        requestBindings = [ordered]@{
            sourceSha256 = [string]$r6Data.sourceSha256
            payloadSha256 = [string]$r6Data.payloadSha256
            compiledTrustSha256 = [string]$r6Data.compiledTrustSha256
            toolchainSha256 = [string]$r6Data.toolchainSha256
            buildExecutionSha256 = [string]$r6Data.buildExecutionSha256
            resourceBindingSha256 = [string]$r6Data.resourceBindingSha256
            trustedBuildEvidenceSha256 =
                [string]$r6Data.trustedBuildEvidenceSha256
            admissionSha256 = [string]$r6Data.admissionSha256
        }
        unsignedInstaller = $request.unsignedInstaller
        signedInstaller = [ordered]@{
            role = 'installer'
            fileName = $installerFileName
            relativePath = 'signed/' + $installerFileName
            sizeBytes = [int64]$signedItem.Length
            sha256 = $signedSha256
            peContentSha256 = $signedPeContentSha256
            fullHashChangedFromUnsigned = $true
        }
        authenticode = [ordered]@{
            status = 'Valid'
            signatureType = 'Authenticode'
            primarySignerCount = 1
            signerCertificateSha256 =
                & $hashLabel 'personal-foundation-signer'
            signerDigestAlgorithmOid = '2.16.840.1.101.3.4.2.1'
            spcIndirectDataContentTypeOid = '1.3.6.1.4.1.311.2.1.4'
            spcPeImageDataTypeOid = '1.3.6.1.4.1.311.2.1.15'
            spcDigestAlgorithmOid = '2.16.840.1.101.3.4.2.1'
            spcPeContentSha256 = $signedPeContentSha256
            timestampProtocol = 'RFC3161'
            timestampTokenOid = '1.2.840.113549.1.9.16.2.14'
            timestampContentTypeOid = '1.2.840.113549.1.9.16.1.4'
            timestampSignerCertificateSha256 =
                & $hashLabel 'personal-foundation-timestamp-signer'
            timestampUtc = ConvertTo-ProductionUtc -Value $now.AddMinutes(-1)
            rfc3161PrimarySignerBound = $true
        }
        payloadSelfCheck = $selfCheck
        authentication = [ordered]@{
            algorithm = 'ES256'
            keyId = [string]$request.responseAuthentication.keyId
            purpose = 'personal-installer-signing-response'
            payloadType =
                'ensou-dsh-personal-installer-signing-response-authentication-v2'
            value = 'A' * 86
        }
    }
    $responsePath = Join-Path `
        $importRoot `
        'personal-installer-signing-response.v2.json'
    Write-CanonicalJson -Path $responsePath -Value $response
    Assert-True `
        (Test-Json `
            -Json ([IO.File]::ReadAllText(
                $responsePath,
                [Text.UTF8Encoding]::new($false, $true))) `
            -SchemaFile (Join-Path $PSScriptRoot `
                '..\schemas\personal-installer-signing-response-v2.schema.json') `
            -ErrorAction Stop) `
        'Synthetic Personal foundation r7 response does not satisfy its real schema.'

    return [ordered]@{
        evidenceType = 'INSTALLER_SIGNATURE_IMPORTED'
        responseRelativePath =
            'imports/installer-signing.v2/personal-installer-signing-response.v2.json'
        responseSha256 = Get-Sha256 -Path $responsePath
        requestSchemaVersion = 2
        requestSha256 = [string]$response.requestSha256
        admissionHeadSha256 = [string]$State.HeadSha256
        r6ReceiptSha256 = [string]$State.Head.receiptSha256
        sourceSha256 = [string]$r6Data.sourceSha256
        payloadSha256 = [string]$r6Data.payloadSha256
        compiledTrustSha256 = [string]$r6Data.compiledTrustSha256
        toolchainSha256 = [string]$r6Data.toolchainSha256
        buildExecutionSha256 = [string]$r6Data.buildExecutionSha256
        resourceBindingSha256 = [string]$r6Data.resourceBindingSha256
        trustedBuildEvidenceSha256 =
            [string]$r6Data.trustedBuildEvidenceSha256
        admissionSha256 = [string]$r6Data.admissionSha256
        signedInstaller = [ordered]@{
            fileName = $installerFileName
            relativePath =
                'imports/installer-signing.v2/signed/' + $installerFileName
            sizeBytes = [int64]$signedItem.Length
            sha256 = $signedSha256
            peContentSha256 = $signedPeContentSha256
        }
        signerCertificateSha256 =
            [string]$response.authenticode.signerCertificateSha256
        timestampSignerCertificateSha256 =
            [string]$response.authenticode.timestampSignerCertificateSha256
        timestampProtocol = 'RFC3161'
        timestampUtc = [string]$response.authenticode.timestampUtc
        authenticationKeyId = [string]$response.authentication.keyId
        authenticationPurpose = 'personal-installer-signing-response'
        authenticationPayloadType =
            'ensou-dsh-personal-installer-signing-response-authentication-v2'
        payloadSelfCheckCanonicalJsonSha256 =
            [string]$response.payloadSelfCheck.canonicalJsonSha256
        completedAtUtc = [string]$response.completedAtUtc
        admissionReason = 'PERSONAL_SIGNED_WINDOWS_PILOT_REQUIRED'
        productionAdmission = 'NO_GO'
    }
}

function New-EnterpriseV2FoundationPilotEvidenceTransition {
    param(
        [Parameter(Mandatory = $true)][psobject]$State,
        [ValidateRange(1, 43200)][int]$LifetimeSeconds = 43200
    )

    if ([int]$State.Head.revision -ne 7 -or
        [string]$State.Head.phase -cne 'INSTALLER_SIGNATURE_IMPORTED') {
        throw 'Enterprise foundation r8 fixture requires an exact r7 state.'
    }
    $r5Data = $State.Receipts[4].data
    $r7Data = $State.Receipts[6].data
    $now = [DateTimeOffset]::UtcNow
    $createdAtUtc = ConvertTo-ProductionUtc -Value $now.AddMinutes(-1)
    $expiresAtUtc = ConvertTo-ProductionUtc `
        -Value $now.AddSeconds($LifetimeSeconds)
    $windowsCompletedAtUtc = $now.AddMinutes(-2).ToUniversalTime().ToString(
        'yyyy-MM-ddTHH:mm:ss.fffffffZ',
        [Globalization.CultureInfo]::InvariantCulture)
    $stableCollectedAtUtc = ConvertTo-ProductionUtc -Value $now.AddSeconds(-90)
    $manifest = @($r5Data.files | Where-Object {
            [string]$_.role -ceq 'release-manifest'
        })
    $runtime = @($r5Data.files | Where-Object {
            [string]$_.role -ceq 'runtime'
        })
    if ($manifest.Count -ne 1 -or $runtime.Count -ne 1) {
        throw 'Enterprise foundation r8 fixture requires exact r5 manifest/runtime identities.'
    }
    $hash = {
        param([Parameter(Mandatory = $true)][string]$Label)
        return Get-ProductionSha256Bytes -Bytes $utf8.GetBytes($Label)
    }
    $binding = {
        param(
            [Parameter(Mandatory = $true)][string]$FileName,
            [Parameter(Mandatory = $true)][string]$Label
        )
        return [ordered]@{
            fileName = $FileName
            sizeBytes = 1
            sha256 = & $hash $Label
        }
    }
    $importRoot = Join-Path $State.StateRoot 'imports\pilot-evidence.v1'
    [IO.Directory]::CreateDirectory($importRoot) | Out-Null
    $inputPath = Join-Path $importRoot 'pilot-evidence-input.v1.json'
    $input = [ordered]@{
        schemaVersion = 1
        inputType =
            'ensou-dsh-enterprise-production-pilot-evidence-import-input'
        orchestrationId = [string]$State.Identity.orchestrationId
        edition = 'Enterprise'
        targetChannel = 'stable'
        releaseSetId = [string]$State.Plan.releaseSetId
        createdAtUtc = $createdAtUtc
        expiresAtUtc = $expiresAtUtc
        planAnchor = [ordered]@{
            planSha256 = [string]$State.Identity.planSha256
            pilotEvidenceTrustPolicySha256 =
                [string]$State.Plan.pilotEvidenceTrustPolicySha256
        }
        r7 = [ordered]@{
            revision = 7
            phase = 'INSTALLER_SIGNATURE_IMPORTED'
            headSha256 = [string]$State.HeadSha256
            planSha256 = [string]$State.Identity.planSha256
            receiptRelativePath =
                'receipts/0007-installer-signature-imported.json'
            receiptSha256 = Get-Sha256 -Path (Join-Path `
                (Join-Path $State.StateRoot 'receipts') `
                '0007-installer-signature-imported.json')
            productionAdmission = 'NO_GO'
            signingResponseSha256 = [string]$r7Data.responseSha256
            signingResponseAuthenticationKeyId =
                [string]$r7Data.authenticationKeyId
            signingResponseAuthenticationPurpose =
                [string]$r7Data.authenticationPurpose
            signerCertificateSha256 =
                [string]$r7Data.signerCertificateSha256
            timestampSignerCertificateSha256 =
                [string]$r7Data.timestampSignerCertificateSha256
            timestampUtc = [string]$r7Data.timestampUtc
            signedInstaller = [ordered]@{
                fileName = [string]$r7Data.signedInstaller.fileName
                relativePath = [string]$r7Data.signedInstaller.relativePath
                sizeBytes = [int64]$r7Data.signedInstaller.sizeBytes
                sha256 = [string]$r7Data.signedInstaller.sha256
                peContentSha256 =
                    [string]$r7Data.signedInstaller.peContentSha256
            }
        }
        trustPolicy = [ordered]@{
            fileName = 'pilot-trust-policy.v1.json'
            sizeBytes = 1
            sha256 = [string]$State.Plan.pilotEvidenceTrustPolicySha256
        }
        windowsOperationalPilot = [ordered]@{
            envelope = & $binding 'windows-envelope.v2.json' 'r8-envelope'
            body = & $binding 'windows-body.v2.json' 'r8-body'
            verificationReport =
                & $binding 'windows-report.v2.json' 'r8-report'
            readinessConfig =
                & $binding 'readiness-config.v1.json' 'r8-readiness-config'
            storedReadinessReport =
                & $binding 'stored-readiness.v1.json' 'r8-stored-readiness'
            replayedReadinessReport =
                & $binding 'replayed-readiness.v1.json' 'r8-replayed-readiness'
            testRunId = '22222222-2222-4222-8222-222222222222'
            customerAudienceId = '33333333-3333-4333-8333-333333333333'
            completedAtUtc = $windowsCompletedAtUtc
            evidenceKeyId = 'foundation-r8-windows-evidence'
            installerSha256 = [string]$r7Data.signedInstaller.sha256
            gateCount = 21
        }
        stablePrivatePilot = [ordered]@{
            sourceEvidence =
                & $binding 'stable-observation.v1.json' 'r8-stable'
            r8SubsetSha256 = & $hash 'r8-stable-subset'
            collectedAtUtc = $stableCollectedAtUtc
            allowlistExpiresAtUtc = $expiresAtUtc
            freshInstallDeviceIdentitySha256 = & $hash 'r8-fresh-device'
            onlineUpgradeDeviceIdentitySha256 = & $hash 'r8-upgrade-device'
            freshInstallInventorySha256 = & $hash 'r8-fresh-inventory'
            onlineUpgradeInventorySha256 = & $hash 'r8-upgrade-inventory'
            targetManifestSha256 = [string]$manifest[0].sha256
            targetObjectSetSha256 = & $hash 'r8-target-object-set'
            installerSha256 = [string]$r7Data.signedInstaller.sha256
        }
        localDataCertification = [ordered]@{
            receipt = & $binding 'local-data-receipt.v1.json' 'r8-local-data'
            certificationId = '44444444-4444-4444-8444-444444444444'
            certificationAudienceId =
                '55555555-5555-4555-8555-555555555555'
            keyId = 'foundation-r8-local-data'
            evidenceReportSha256 = & $hash 'r8-local-data-report'
            targetRuntimeSha256 = [string]$runtime[0].sha256
            expiresAtUtc = $expiresAtUtc
        }
        verification = [ordered]@{
            r7ReceiptAuthoritative = 'VERIFIED'
            exactSignedInstallerBytes = 'VERIFIED'
            exactSigningResponse = 'VERIFIED'
            productionWindowsPilotVerifierReport = 'VERIFIED'
            independentEvidenceTrustPolicy = 'VERIFIED'
            twentyOneOperationalGates = 'VERIFIED'
            noVisibleConsoleGate = 'VERIFIED'
            rollbackAndRecoveryGates = 'VERIFIED'
            revocationGates = 'VERIFIED'
            localDataCertification = 'VERIFIED'
            twoDistinctWindowsDevices = 'VERIFIED'
            freshInstallLane = 'VERIFIED'
            onlineUpgradeLane = 'VERIFIED'
            stableTargetObjects = 'VERIFIED'
            freshEvidence = 'VERIFIED'
            purposeSeparatedKeys = 'VERIFIED'
        }
        productionAdmission = 'NO_GO'
        nextRequiredGate = 'PILOT_EVIDENCE_BOUND'
    }
    Write-CanonicalJson -Path $inputPath -Value $input
    return [ordered]@{
        evidenceType = 'PILOT_EVIDENCE_BOUND'
        relativePath =
            'imports/pilot-evidence.v1/pilot-evidence-input.v1.json'
        sha256 = Get-Sha256 -Path $inputPath
    }
}

function New-EnterpriseV2FoundationInstallerTransition {
    param(
        [Parameter(Mandatory = $true)][psobject]$State,
        [Parameter(Mandatory = $true)][ValidateSet(6, 7)][int]$Revision
    )

    $stateRoot = [string]$State.StateRoot
    $requestRoot = Join-Path $stateRoot 'requests\installer-signing.v2'
    $requestPath = Join-Path $requestRoot 'installer-signing-request.v2.json'
    $installerFileName = 'Ensou.Dsh.Enterprise.Installer.exe'
    if ($Revision -eq 6) {
        $hash = {
            param([Parameter(Mandatory = $true)][string]$Label)
            return Get-ProductionSha256Bytes -Bytes $utf8.GetBytes($Label)
        }
        $r3Receipt = $State.Receipts[2]
        $r5Receipt = $State.Receipts[4]
        $r3Data = $r3Receipt.data
        $r5Data = $r5Receipt.data
        $launcher = @($r5Data.files | Where-Object {
                [string]$_.role -ceq 'launcher'
            })
        $runtime = @($r5Data.files | Where-Object {
                [string]$_.role -ceq 'runtime'
            })
        $bootstrapper = @($r3Data.files | Where-Object {
                [string]$_.role -ceq 'bootstrapper'
            })
        if ($launcher.Count -ne 1 -or $runtime.Count -ne 1 -or
            $bootstrapper.Count -ne 1) {
            throw 'Enterprise foundation r6 fixture requires exact r3 bootstrapper and r5 Launcher/runtime identities.'
        }
        $unsignedRoot = Join-Path $requestRoot 'unsigned'
        $payloadRoot = Join-Path $requestRoot 'payload'
        $trustedBuildRoot = Join-Path $requestRoot 'trusted-build'
        [IO.Directory]::CreateDirectory($unsignedRoot) | Out-Null
        [IO.Directory]::CreateDirectory($payloadRoot) | Out-Null
        [IO.Directory]::CreateDirectory($trustedBuildRoot) | Out-Null
        $payloadFiles = [Collections.Generic.List[object]]::new()
        foreach ($definition in @(
                [pscustomobject]@{
                    Role = 'install-manifest'
                    FileName = 'enterprise-install-manifest.json'
                    LogicalName =
                        'Ensou.Dsh.Enterprise.Installer.Payload.enterprise-install-manifest.json'
                    SourceKind = 'generated-descriptor'
                    SourceRole = 'install-manifest'
                    SourcePath = ''
                },
                [pscustomobject]@{
                    Role = 'launcher'
                    FileName = 'launcher.zip'
                    LogicalName =
                        'Ensou.Dsh.Enterprise.Installer.Payload.launcher.zip'
                    SourceKind = 'r5-candidate'
                    SourceRole = 'launcher'
                    SourcePath = Join-Path $stateRoot (
                        'imports\stable-signed-candidate.v1\' +
                        [string]$launcher[0].relativePath)
                },
                [pscustomobject]@{
                    Role = 'runtime'
                    FileName = 'runtime.zip'
                    LogicalName =
                        'Ensou.Dsh.Enterprise.Installer.Payload.runtime.zip'
                    SourceKind = 'r5-candidate'
                    SourceRole = 'runtime'
                    SourcePath = Join-Path $stateRoot (
                        'imports\stable-signed-candidate.v1\' +
                        [string]$runtime[0].relativePath)
                },
                [pscustomobject]@{
                    Role = 'bootstrapper'
                    FileName = 'Ensou.Dsh.Enterprise.Bootstrapper.exe'
                    LogicalName =
                        'Ensou.Dsh.Enterprise.Installer.Payload.Ensou.Dsh.Enterprise.Bootstrapper.exe'
                    SourceKind = 'r3-signed-client'
                    SourceRole = 'bootstrapper'
                    SourcePath = Join-Path $stateRoot (
                        'imports\client-signing.v1\signed\' +
                        [string]$bootstrapper[0].fileName)
                })) {
            $path = Join-Path $payloadRoot ([string]$definition.FileName)
            if ([string]::IsNullOrWhiteSpace([string]$definition.SourcePath)) {
                [IO.File]::WriteAllBytes(
                    $path,
                    $utf8.GetBytes("FOUNDATION-ONLY-$($definition.Role)"))
            }
            else {
                [IO.File]::Copy([string]$definition.SourcePath, $path, $false)
            }
            $item = Get-Item -LiteralPath $path -Force
            $sha256 = Get-Sha256 -Path $path
            $payloadFiles.Add([ordered]@{
                role = [string]$definition.Role
                fileName = [string]$definition.FileName
                embeddedLogicalName = [string]$definition.LogicalName
                sourceKind = [string]$definition.SourceKind
                sourceRole = [string]$definition.SourceRole
                sourceSha256 = $sha256
                sizeBytes = [int64]$item.Length
                sha256 = $sha256
            })
        }
        $payloadSetSha256 = Get-ProductionSha256Bytes -Bytes (
            ConvertTo-ProductionJsonBytes -Value @($payloadFiles))
        $unsignedPath = Join-Path $unsignedRoot $installerFileName
        New-UnsignedPeFixture -OutputPath $unsignedPath
        $unsignedItem = Get-Item -LiteralPath $unsignedPath -Force
        $unsignedSha256 = Get-Sha256 -Path $unsignedPath
        $unsignedPeContentSha256 = Get-PeContentSha256 `
            -Bytes ([IO.File]::ReadAllBytes($unsignedPath))
        $sourceInputFiles = @(
            [ordered]@{ kind = 'restore-graph'; identityPath = 'generated/project.assets.json' },
            [ordered]@{ kind = 'generated-input'; identityPath = 'generated/publish-arguments.json' },
            [ordered]@{ kind = 'directory-build-props'; identityPath = 'repo/Directory.Build.props' },
            [ordered]@{ kind = 'directory-build-targets-absent'; identityPath = 'repo/Directory.Build.targets'; absenceStatus = 'VERIFIED_ABSENT' },
            [ordered]@{ kind = 'global-json'; identityPath = 'repo/global.json' },
            [ordered]@{ kind = 'project'; identityPath = 'repo/src/Ensou.Dsh.Enterprise.Installer/Ensou.Dsh.Enterprise.Installer.csproj' },
            [ordered]@{ kind = 'packages-lock'; identityPath = 'repo/src/Ensou.Dsh.Enterprise.Installer/packages.lock.json' },
            [ordered]@{ kind = 'source'; identityPath = 'repo/src/Ensou.Dsh.Enterprise.Installer/Program.cs' },
            [ordered]@{ kind = 'runtime-pack'; identityPath = 'runtime-pack/microsoft.netcore.app.runtime.win-x64.10.0.10.nupkg' }
        )
        foreach ($sourceInput in $sourceInputFiles) {
            if ([string]$sourceInput.kind -cne
                'directory-build-targets-absent') {
                $sourceInput['snapshotRelativePath'] =
                    'build-inputs/' + [string]$sourceInput.identityPath
                $sourceInput['sizeBytes'] = 1
                $sourceInput['sha256'] = & $hash (
                    'r6-source-input-' + [string]$sourceInput.identityPath)
            }
        }
        $sourceSetSha256 = Get-ProductionSha256Bytes -Bytes (
            ConvertTo-ProductionJsonBytes -Value $sourceInputFiles)
        $sourceBuildInputs = [ordered]@{
            contract =
                'tracked-clean-ordinary-single-link-exact-msbuild-graph-v1'
            sourceTree = [string]$State.Receipts[0].data.sourceTree
            rootProjectIdentityPath =
                'repo/src/Ensou.Dsh.Enterprise.Installer/Ensou.Dsh.Enterprise.Installer.csproj'
            inventorySha256 = $sourceSetSha256
            preBuildInventorySha256 = $sourceSetSha256
            postBuildInventorySha256 = $sourceSetSha256
            totalSizeBytes = 8
            trackedClean = $true
            dirtyPathCount = 0
            untrackedPathCount = 0
            linkedInputCount = 0
            raceCheckStatus = 'VERIFIED_UNCHANGED'
            files = $sourceInputFiles
        }
        $getSourceInput = {
            param([Parameter(Mandatory = $true)][string]$IdentityPath)
            return @($sourceInputFiles | Where-Object {
                    [string]$_.identityPath -ceq $IdentityPath
                })[0]
        }
        $runtimePackInputs = @($sourceInputFiles | Where-Object {
                [string]$_.kind -ceq 'runtime-pack'
            })
        $dependencyInputs = @($sourceInputFiles | Where-Object {
                [string]$_.kind -in @(
                    'project', 'packages-lock', 'restore-graph',
                    'runtime-pack')
            })
        $toolchainLock = [ordered]@{
            sdkVersion = '10.0.302'
            globalJsonRelativePath = 'toolchain/global.json'
            globalJsonSha256 = [string](& $getSourceInput `
                'repo/global.json').sha256
            projectFileName = 'Ensou.Dsh.Enterprise.Installer.csproj'
            projectRelativePath =
                'toolchain/Ensou.Dsh.Enterprise.Installer.csproj'
            projectSha256 = [string](& $getSourceInput `
                'repo/src/Ensou.Dsh.Enterprise.Installer/Ensou.Dsh.Enterprise.Installer.csproj').sha256
            restoreGraphRelativePath = 'toolchain/project.assets.json'
            restoreGraphSha256 = [string](& $getSourceInput `
                'generated/project.assets.json').sha256
            packagesLockRelativePath = 'toolchain/packages.lock.json'
            packagesLockSha256 = [string](& $getSourceInput `
                'repo/src/Ensou.Dsh.Enterprise.Installer/packages.lock.json').sha256
            packagesLockStatus = 'VERIFIED'
            dependencyClosureSha256 = Get-ProductionSha256Bytes -Bytes (
                ConvertTo-ProductionJsonBytes -Value $dependencyInputs)
            runtimePackSetSha256 = Get-ProductionSha256Bytes -Bytes (
                ConvertTo-ProductionJsonBytes -Value $runtimePackInputs)
            sdkInfoRelativePath = 'toolchain/dotnet-sdk-info.v1.json'
            sdkInfoSha256 = & $hash 'r6-sdk-info'
            configuration = 'Release'
            runtimeIdentifier = 'win-x64'
            selfContained = $true
            publishSingleFile = $true
            deterministic = $true
            continuousIntegrationBuild = $true
            restoreMode = 'packages-lock-locked-offline'
            networkAccess = 'disabled'
            publishArgumentsSha256 = [string](& $getSourceInput `
                'generated/publish-arguments.json').sha256
        }
        $toolchainLockSha256 = Get-ProductionSha256Bytes -Bytes (
            ConvertTo-ProductionJsonBytes -Value $toolchainLock)
        $candidateFiles = @($r5Data.files | ForEach-Object {
                [ordered]@{
                    role = [string]$_.role
                    fileName = [string]$_.fileName
                    relativePath =
                        'imports/stable-signed-candidate.v1/' +
                        [string]$_.relativePath
                    sizeBytes = [int64]$_.sizeBytes
                    sha256 = [string]$_.sha256
                }
            })
        $candidateSetSha256 = Get-ProductionSha256Bytes -Bytes (
            ConvertTo-ProductionJsonBytes -Value $candidateFiles)
        $signedClients = @($r3Data.files | ForEach-Object {
                [ordered]@{
                    role = [string]$_.role
                    fileName = [string]$_.fileName
                    relativePath =
                        'imports/client-signing.v1/signed/' +
                        [string]$_.fileName
                    sizeBytes = [int64]$_.sizeBytes
                    sha256 = [string]$_.sha256
                    peContentSha256 = [string]$_.peContentSha256
                }
            })
        $signedClientSetSha256 = Get-ProductionSha256Bytes -Bytes (
            ConvertTo-ProductionJsonBytes -Value $signedClients)
        $trustProbes = @($r3Data.releaseManifestTrustProbes | ForEach-Object {
                [ordered]@{
                    role = [string]$_.role
                    fileName = [string]$_.fileName
                    probeSha256 = [string]$_.probeSha256
                }
            })
        $trustProbeSetSha256 = Get-ProductionSha256Bytes -Bytes (
            ConvertTo-ProductionJsonBytes -Value $trustProbes)
        $r5ReceiptPath = Join-Path `
            (Join-Path $stateRoot 'receipts') `
            '0005-stable-signed-candidate-imported.json'
        $r5ReceiptSha256 = Get-Sha256 -Path $r5ReceiptPath
        $r3ReceiptSha256 = Get-Sha256 -Path (Join-Path `
            (Join-Path $stateRoot 'receipts') `
            '0003-client-signatures-imported.json')
        $sourceCommit = [string]$State.Plan.sourceCommit
        $sourceTree = [string]$State.Receipts[0].data.sourceTree
        $targetIdentity = [ordered]@{
            schemaVersion = 1
            identityType = 'ensou-dsh-launcher-installer-build-target'
            orchestrationId = [string]$State.Identity.orchestrationId
            edition = 'Enterprise'
            releaseSetId = [string]$State.Plan.releaseSetId
            channel = 'stable'
            planSha256 = [string]$State.Identity.planSha256
            sourceCommit = $sourceCommit
            sourceTree = $sourceTree
            sourceBuildInputSetSha256 = $sourceSetSha256
            r5HeadSha256 = [string]$State.HeadSha256
            r5ReceiptSha256 = $r5ReceiptSha256
            candidateSetSha256 = $candidateSetSha256
            r3SignedClientSetSha256 = $signedClientSetSha256
            releaseManifestTrustProbeSetSha256 = $trustProbeSetSha256
            payloadSetSha256 = $payloadSetSha256
            toolchainLockSha256 = $toolchainLockSha256
        }
        $targetBuildSha256 = Get-ProductionSha256Bytes -Bytes (
            ConvertTo-ProductionJsonBytes -Value $targetIdentity)
        $buildId = '77777777-7777-4777-8777-777777777777'
        $reservation = [ordered]@{
            schemaVersion = 1
            reservationType =
                'ensou-dsh-enterprise-installer-trusted-build-reservation'
            buildId = $buildId
            targetBuildIdentitySha256 = $targetBuildSha256
            sourceBuildInputSetSha256 = $sourceSetSha256
            unsignedInstallerSha256 = $unsignedSha256
        }
        $buildExecution = [ordered]@{
            buildId = $buildId
            targetBuildIdentitySha256 = $targetBuildSha256
            reservationSha256 = Get-ProductionSha256Bytes -Bytes (
                ConvertTo-ProductionJsonBytes -Value $reservation)
            buildOrdinal = 1
            buildCountForTarget = 1
            outputCreationMode = 'create-new'
            rebuildPolicy =
                'rebuild-forbidden-exact-reserved-unsigned-bytes-replay-only'
            startedAtUtc = '2026-08-30T23:58:00Z'
            completedAtUtc = '2026-08-30T23:59:00Z'
            exitCode = 0
        }
        $resourceRecords = @($payloadFiles | ForEach-Object {
                [ordered]@{
                    role = [string]$_.role
                    embeddedLogicalName = [string]$_.embeddedLogicalName
                    sizeBytes = [int64]$_.sizeBytes
                    sha256 = [string]$_.sha256
                    status = 'VERIFIED'
                }
            })
        $resourceBinding = [ordered]@{
            verificationType =
                'managed-assembly-resource-to-single-file-build-input-v1'
            verificationMethod =
                'collectible-load-context-manifest-resource-inspection-no-entrypoint'
            status = 'VERIFIED'
            managedAssembly = [ordered]@{
                fileName = 'Ensou.Dsh.Enterprise.Installer.dll'
                sizeBytes = 256
                sha256 = & $hash 'r6-managed-assembly'
            }
            resourceSetSha256 = Get-ProductionSha256Bytes -Bytes (
                ConvertTo-ProductionJsonBytes -Value $resourceRecords)
            resources = $resourceRecords
            unsignedInstallerSha256 = $unsignedSha256
        }
        $resourceBindingSha256 = Get-ProductionSha256Bytes -Bytes (
            ConvertTo-ProductionJsonBytes -Value $resourceBinding)
        $evidence = [ordered]@{
            schemaVersion = 1
            evidenceType = 'ensou-dsh-enterprise-installer-trusted-build'
            orchestrationId = [string]$State.Identity.orchestrationId
            planSha256 = [string]$State.Identity.planSha256
            baseHeadSha256 = [string]$State.HeadSha256
            sourceCommit = $sourceCommit
            sourceTree = $sourceTree
            sourceBuildInputs = [ordered]@{
                inventorySha256 = $sourceSetSha256
            }
            toolchainLock = [ordered]@{
                sdkFileClosureStatus = 'VERIFIED'
            }
            buildExecution = [ordered]@{
                targetBuildIdentitySha256 = $targetBuildSha256
            }
            unsignedInstaller = [ordered]@{
                sha256 = $unsignedSha256
            }
            resourceBinding = $resourceBinding
            signingRequestEligibility = [ordered]@{
                status = 'ELIGIBLE_FOR_PILOT_SIGNING'
                blocker = 'INSTALLER_SIGNING_RESPONSE_REQUIRED'
            }
        }
        $evidencePath = Join-Path `
            $trustedBuildRoot `
            'trusted-build-evidence.v1.json'
        Write-CanonicalJson -Path $evidencePath -Value $evidence
        $evidenceItem = Get-Item -LiteralPath $evidencePath -Force
        $evidenceSha256 = Get-Sha256 -Path $evidencePath
        $request = [ordered]@{
            schemaVersion = 2
            requestType = 'ensou-dsh-launcher-installer-signing-request'
            orchestrationId = [string]$State.Identity.orchestrationId
            edition = 'Enterprise'
            releaseSetId = [string]$State.Plan.releaseSetId
            channel = 'stable'
            planSha256 = [string]$State.Identity.planSha256
            sourceCommit = $sourceCommit
            sourceTree = $sourceTree
            baseHeadSha256 = [string]$State.HeadSha256
            sourceBuildInputSetSha256 = $sourceSetSha256
            sourceBuildInputs = $sourceBuildInputs
            baseRevision = 5
            basePhase = 'STABLE_SIGNED_CANDIDATE_IMPORTED'
            requestedRevision = 6
            requestNonce = 'A' * 43
            createdAtUtc = '2026-08-31T00:00:00Z'
            expiresAtUtc = '2026-08-31T02:00:00Z'
            r5Evidence = [ordered]@{
                headRelativePath = 'head.json'
                headSha256 = [string]$State.HeadSha256
                receiptRelativePath =
                    'receipts/0005-stable-signed-candidate-imported.json'
                receiptSha256 = $r5ReceiptSha256
                manifestPublishingRequestSha256 =
                    [string]$r5Data.requestSha256
                manifestPublishingResponseSha256 =
                    [string]$r5Data.responseSha256
                manifestRelativePath = [string]$r5Data.manifestRelativePath
                manifestSha256 = [string]$r5Data.manifestSha256
                releaseManifestTrustSha256 =
                    [string]$r5Data.releaseManifestTrustSha256
                releaseCompatibilitySha256 =
                    [string]$r5Data.releaseCompatibilitySha256
                productionAdmission = 'NO_GO'
            }
            candidate = [ordered]@{
                inventorySha256 = $candidateSetSha256
                files = $candidateFiles
            }
            r3Evidence = [ordered]@{
                receiptRelativePath =
                    'receipts/0003-client-signatures-imported.json'
                receiptSha256 = $r3ReceiptSha256
                signedClientSetSha256 = $signedClientSetSha256
                signedClients = $signedClients
                releaseManifestTrustSha256 =
                    [string]$r5Data.releaseManifestTrustSha256
                releaseManifestTrustProbeSetSha256 = $trustProbeSetSha256
                releaseManifestTrustProbes = $trustProbes
            }
            installerPayload = [ordered]@{
                inventorySha256 = $payloadSetSha256
                files = @($payloadFiles)
            }
            toolchainLock = $toolchainLock
            toolchainLockSha256 = $toolchainLockSha256
            buildExecution = $buildExecution
            unsignedInstaller = [ordered]@{
                role = 'installer'
                fileName = $installerFileName
                relativePath = 'unsigned/Ensou.Dsh.Enterprise.Installer.exe'
                sizeBytes = [int64]$unsignedItem.Length
                sha256 = $unsignedSha256
                peContentSha256 = $unsignedPeContentSha256
            }
            resourceBinding = $resourceBinding
            trustedBuildEvidence = [ordered]@{
                role = 'trusted-build-evidence'
                fileName = 'trusted-build-evidence.v1.json'
                relativePath =
                    'trusted-build/trusted-build-evidence.v1.json'
                schemaVersion = 1
                evidenceType =
                    'ensou-dsh-enterprise-installer-trusted-build'
                sizeBytes = [int64]$evidenceItem.Length
                sha256 = $evidenceSha256
                resourceBindingSha256 = $resourceBindingSha256
                sdkFileClosureStatus = 'VERIFIED'
                productionAdmission = 'NO_GO'
            }
            responseAuthentication = [ordered]@{
                algorithm = 'ES256'
                keyId = [string]$State.Plan.externalResponseTrusts.installerSigning.keyId
                purpose = 'installer-signing-response'
                payloadType =
                    'ensou-dsh-launcher-installer-signing-response-authentication-v1'
                trustSha256 = Get-ProductionSha256Bytes -Bytes (
                    ConvertTo-ProductionJsonBytes -Value `
                        $State.Plan.externalResponseTrusts.installerSigning)
                maximumResponseAgeMinutes =
                    [int]$State.Plan.authenticodePolicy.maximumResponseAgeMinutes
            }
        }
        Write-CanonicalJson -Path $requestPath -Value $request
        return [ordered]@{
            evidenceType = 'INSTALLER_SIGNING_REQUESTED'
            requestSchemaVersion = 2
            requestRelativePath = 'requests/installer-signing.v2/installer-signing-request.v2.json'
            requestSha256 = Get-Sha256 -Path $requestPath
            baseHeadSha256 = [string]$State.HeadSha256
            baseReceiptSha256 = $r5ReceiptSha256
            sourceBuildInputSetSha256 = $sourceSetSha256
            targetBuildIdentitySha256 = $targetBuildSha256
            payloadSetSha256 = $payloadSetSha256
            r5LauncherSha256 = [string]$launcher[0].sha256
            r5RuntimeSha256 = [string]$runtime[0].sha256
            trustedBuildEvidenceRelativePath =
                'requests/installer-signing.v2/trusted-build/trusted-build-evidence.v1.json'
            trustedBuildEvidenceSha256 = $evidenceSha256
            resourceBindingSha256 = $resourceBindingSha256
            sdkFileClosureStatus = 'VERIFIED'
            signingRequestEligibilityStatus = 'ELIGIBLE_FOR_PILOT_SIGNING'
            unsignedInstaller = [ordered]@{
                fileName = $installerFileName
                relativePath = 'requests/installer-signing.v2/unsigned/Ensou.Dsh.Enterprise.Installer.exe'
                sizeBytes = [int64]$unsignedItem.Length
                sha256 = $unsignedSha256
                peContentSha256 = $unsignedPeContentSha256
            }
            createdAtUtc = '2026-08-31T00:00:00Z'
            expiresAtUtc = '2026-08-31T02:00:00Z'
            authenticationKeyId = 'foundation-only-installer-signing'
            authenticationPurpose = 'installer-signing-response'
            admissionReason = 'INSTALLER_SIGNING_RESPONSE_REQUIRED'
            productionAdmission = 'NO_GO'
        }
    }

    $request = Read-Json -Path $requestPath
    $importRoot = Join-Path $stateRoot 'imports\installer-signing.v1'
    $signedRoot = Join-Path $importRoot 'signed'
    [IO.Directory]::CreateDirectory($signedRoot) | Out-Null
    $signedPath = Join-Path $signedRoot $installerFileName
    New-FoundationSignedPeFixture `
        -UnsignedPath (Join-Path `
            (Join-Path $requestRoot 'unsigned') `
            $installerFileName) `
        -OutputPath $signedPath
    $signedItem = Get-Item -LiteralPath $signedPath -Force
    $signedSha256 = Get-Sha256 -Path $signedPath
    $response = [ordered]@{
        schemaVersion = 1
        responseType = 'ensou-dsh-launcher-installer-signing-response'
        orchestrationId = [string]$request.orchestrationId
        edition = 'Enterprise'
        releaseSetId = [string]$request.releaseSetId
        channel = 'stable'
        planSha256 = [string]$request.planSha256
        sourceTree = [string]$request.sourceTree
        sourceBuildInputSetSha256 =
            [string]$State.Receipts[5].data.sourceBuildInputSetSha256
        requestRelativePath =
            'requests/installer-signing.v2/installer-signing-request.v2.json'
        requestSha256 = Get-Sha256 -Path $requestPath
        requestNonce = [string]$request.requestNonce
        baseHeadSha256 = [string]$request.baseHeadSha256
        admissionHeadSha256 = [string]$State.HeadSha256
        admissionRevision = 6
        r6ReceiptRelativePath =
            'receipts/0006-installer-signing-requested.json'
        r6ReceiptSha256 = [string]$State.Head.receiptSha256
        requestCreatedAtUtc = [string]$request.createdAtUtc
        requestExpiresAtUtc = [string]$request.expiresAtUtc
        completedAtUtc = '2026-08-31T00:31:00Z'
        candidateSetSha256 = [string]$request.candidate.inventorySha256
        payloadSetSha256 = [string]$State.Receipts[5].data.payloadSetSha256
        r3SignedClientSetSha256 =
            [string]$request.r3Evidence.signedClientSetSha256
        releaseManifestTrustSha256 =
            [string]$request.r3Evidence.releaseManifestTrustSha256
        releaseManifestTrustProbeSetSha256 =
            [string]$request.r3Evidence.releaseManifestTrustProbeSetSha256
        toolchainLockSha256 = [string]$request.toolchainLockSha256
        targetBuildIdentitySha256 =
            [string]$State.Receipts[5].data.targetBuildIdentitySha256
        unsignedInstaller = $request.unsignedInstaller
        signedInstaller = [ordered]@{
            role = 'installer'
            fileName = $installerFileName
            relativePath = 'signed/Ensou.Dsh.Enterprise.Installer.exe'
            sizeBytes = [int64]$signedItem.Length
            sha256 = $signedSha256
            peContentSha256 = [string]$request.unsignedInstaller.peContentSha256
            fullHashChangedFromUnsigned = $true
        }
        authenticode = [ordered]@{
            status = 'Valid'
            signatureType = 'Authenticode'
            primarySignerCount = 1
            signerCertificateSha256 = 'a' * 64
            signerDigestAlgorithmOid = '2.16.840.1.101.3.4.2.1'
            spcIndirectDataContentTypeOid = '1.3.6.1.4.1.311.2.1.4'
            spcPeImageDataTypeOid = '1.3.6.1.4.1.311.2.1.15'
            spcDigestAlgorithmOid = '2.16.840.1.101.3.4.2.1'
            spcPeContentSha256 =
                [string]$request.unsignedInstaller.peContentSha256
            timestampProtocol = 'RFC3161'
            timestampTokenOid = '1.2.840.113549.1.9.16.2.14'
            timestampContentTypeOid = '1.2.840.113549.1.9.16.1.4'
            timestampSignerCertificateSha256 = 'b' * 64
            timestampUtc = '2026-08-31T00:30:00Z'
            rfc3161PrimarySignerBound = $true
        }
        payloadSelfCheck = [ordered]@{
            command = '--production-payload-self-check'
            status = 'VERIFIED'
            exitCode = 0
            inspectedInstallerSha256 = $signedSha256
            resultSha256 = Get-ProductionSha256Bytes -Bytes (
                $utf8.GetBytes('foundation-r7-payload-self-check'))
            candidateSetSha256 = [string]$request.candidate.inventorySha256
            payloadSetSha256 = [string]$State.Receipts[5].data.payloadSetSha256
            r3SignedClientSetSha256 =
                [string]$request.r3Evidence.signedClientSetSha256
            releaseManifestTrustSha256 =
                [string]$request.r3Evidence.releaseManifestTrustSha256
            releaseManifestTrustProbeSetSha256 =
                [string]$request.r3Evidence.releaseManifestTrustProbeSetSha256
            completedAtUtc = '2026-08-31T00:30:30Z'
        }
        authentication = [ordered]@{
            algorithm = 'ES256'
            keyId = [string]$request.responseAuthentication.keyId
            purpose = 'installer-signing-response'
            payloadType =
                'ensou-dsh-launcher-installer-signing-response-authentication-v1'
            value = 'A' * 86
        }
    }
    $responsePath = Join-Path $importRoot 'installer-signing-response.v1.json'
    Write-CanonicalJson -Path $responsePath -Value $response
    $r6Data = $State.Receipts[5].data
    return [ordered]@{
        evidenceType = 'INSTALLER_SIGNATURE_IMPORTED'
        responseRelativePath = 'imports/installer-signing.v1/installer-signing-response.v1.json'
        responseSha256 = Get-Sha256 -Path $responsePath
        requestSchemaVersion = 2
        requestSha256 = [string]$response.requestSha256
        admissionHeadSha256 = [string]$State.HeadSha256
        r6ReceiptSha256 = [string]$State.Head.receiptSha256
        r5LauncherSha256 = [string]$r6Data.r5LauncherSha256
        r5RuntimeSha256 = [string]$r6Data.r5RuntimeSha256
        trustedBuildEvidenceSha256 =
            [string]$r6Data.trustedBuildEvidenceSha256
        resourceBindingSha256 = [string]$r6Data.resourceBindingSha256
        sdkFileClosureStatus = [string]$r6Data.sdkFileClosureStatus
        signingRequestEligibilityStatus =
            [string]$r6Data.signingRequestEligibilityStatus
        sourceBuildInputSetSha256 = [string]$r6Data.sourceBuildInputSetSha256
        targetBuildIdentitySha256 = [string]$r6Data.targetBuildIdentitySha256
        payloadSetSha256 = [string]$r6Data.payloadSetSha256
        signedInstaller = [ordered]@{
            fileName = $installerFileName
            relativePath = 'imports/installer-signing.v1/signed/Ensou.Dsh.Enterprise.Installer.exe'
            sizeBytes = [int64]$signedItem.Length
            sha256 = $signedSha256
            peContentSha256 = [string]$r6Data.unsignedInstaller.peContentSha256
        }
        signerCertificateSha256 = 'a' * 64
        timestampSignerCertificateSha256 = 'b' * 64
        timestampProtocol = 'RFC3161'
        timestampUtc = '2026-08-31T00:30:00Z'
        authenticationKeyId = 'foundation-only-installer-signing'
        authenticationPurpose = 'installer-signing-response'
        completedAtUtc = '2026-08-31T00:31:00Z'
        admissionReason = 'INSTALLER_SIGNING_RESPONSE_REQUIRED'
        productionAdmission = 'NO_GO'
    }
}

function Add-V2FoundationTransition {
    param(
        [Parameter(Mandatory = $true)][string]$StateRoot,
        [Parameter(Mandatory = $true)][string]$StateSchemaPath,
        [Parameter(Mandatory = $true)][string]$Phase,
        [Parameter(Mandatory = $true)]$Data,
        [switch]$FaultAfterReceipt
    )

    $state = Get-ProductionReleaseState -StateRoot $StateRoot -StateSchemaPath $StateSchemaPath
    return Add-ProductionReleaseReceipt `
        -StateRoot $StateRoot `
        -StateSchemaPath $StateSchemaPath `
        -Phase $Phase `
        -ExpectedPreviousPhase ([string]$state.Head.phase) `
        -ExpectedHeadSha256 ([string]$state.HeadSha256) `
        -Data $Data `
        -FaultAfterReceipt:$FaultAfterReceipt
}

function Advance-V2FoundationState {
    param(
        [Parameter(Mandatory = $true)][string]$StateRoot,
        [Parameter(Mandatory = $true)][string]$StateSchemaPath,
        [Parameter(Mandatory = $true)][int]$TargetRevision
    )

    $state = Get-ProductionReleaseState -StateRoot $StateRoot -StateSchemaPath $StateSchemaPath
    if ([string]$state.Identity.edition -ceq 'Personal' -and [string]$state.TargetChannel -ceq 'pilot' -and $TargetRevision -ge 8) {
        throw 'Personal r8/r9 require sealed request and authenticated completed execution; foundation evidence is not publication.'
    }
    if ([int]$state.Head.revision -lt 5 -and $TargetRevision -ge 4) {
        throw 'Foundation r4/r5 transitions require the typed manifest publishing request/import fixture.'
    }
    while ([int]$state.Head.revision -lt $TargetRevision) {
        $transition = $state.Lifecycle.Transitions[[int]$state.Head.revision]
        $data = if ([string]$state.Identity.edition -ceq 'Personal' -and
            [int]$transition.Revision -in @(6, 7)) {
            New-PersonalV2FoundationInstallerTransition `
                -State $state `
                -Revision ([int]$transition.Revision)
        }
        elseif ([string]$state.Identity.edition -ceq 'Enterprise' -and
            [int]$transition.Revision -in @(6, 7)) {
            New-EnterpriseV2FoundationInstallerTransition `
                -State $state `
                -Revision ([int]$transition.Revision)
        }
        elseif ([string]$state.Identity.edition -ceq 'Enterprise' -and
            [string]$state.TargetChannel -ceq 'stable' -and
            [int]$transition.Revision -eq 8) {
            New-EnterpriseV2FoundationPilotEvidenceTransition `
                -State $state
        }
        else {
            New-V2FoundationEvidenceData `
                -Revision ([int]$transition.Revision) `
                -Phase ([string]$transition.Phase)
        }
        $state = Add-V2FoundationTransition -StateRoot $StateRoot -StateSchemaPath $StateSchemaPath -Phase ([string]$transition.Phase) -Data $data
    }
    return $state
}

function Assert-V2StateDocumentsMatchLifecycle {
    param(
        [Parameter(Mandatory = $true)][string]$StateRoot,
        [Parameter(Mandatory = $true)][string]$StateSchemaPath,
        [Parameter(Mandatory = $true)][ValidateSet('pilot', 'stable')][string]$TargetChannel
    )

    $lifecycle = Get-ProductionReleaseLifecycleContract -SchemaVersion 2 -TargetChannel $TargetChannel
    $identityPath = Join-Path $StateRoot 'identity.json'
    $identity = Read-Json -Path $identityPath
    foreach ($transition in @($lifecycle.Transitions)) {
        $phaseSlug = ([string]$transition.Phase).ToLowerInvariant().Replace('_', '-')
        $receiptFileName = ([int]$transition.Revision).ToString('0000') + '-' + $phaseSlug + '.json'
        $receiptPath = Join-Path (Join-Path $StateRoot 'receipts') $receiptFileName
        $receipt = Read-Json -Path $receiptPath
        $receiptJson = $receipt | ConvertTo-Json -Depth 64 -Compress
        Assert-True (Test-Json -Json $receiptJson -SchemaFile $StateSchemaPath -ErrorAction Stop) "Valid $TargetChannel receipt revision $($transition.Revision) did not satisfy the v2 schema."

        $wrongPhase = if ([int]$transition.Revision -lt [int]$lifecycle.TerminalRevision) {
            [string]$lifecycle.Transitions[[int]$transition.Revision].Phase
        }
        else {
            [string]$lifecycle.Transitions[0].Phase
        }
        $receipt.phase = $wrongPhase
        $wrongReceiptJson = $receipt | ConvertTo-Json -Depth 64 -Compress
        Assert-True (-not (Test-Json -Json $wrongReceiptJson -SchemaFile $StateSchemaPath -ErrorAction SilentlyContinue)) "Receipt revision $($transition.Revision) accepted phase '$wrongPhase'."

        $head = [ordered]@{
            schemaVersion = 2
            stateType = 'ensou-dsh-launcher-production-release-head'
            orchestrationId = [string]$identity.orchestrationId
            edition = [string]$identity.edition
            planSha256 = [string]$identity.planSha256
            identitySha256 = Get-Sha256 -Path $identityPath
            revision = [int]$transition.Revision
            phase = [string]$transition.Phase
            receiptFileName = $receiptFileName
            receiptSha256 = Get-Sha256 -Path $receiptPath
            updatedAtUtc = [string](Read-Json -Path $receiptPath).recordedAtUtc
            targetChannel = $TargetChannel
        }
        $headJson = $head | ConvertTo-Json -Depth 64 -Compress
        Assert-True (Test-Json -Json $headJson -SchemaFile $StateSchemaPath -ErrorAction Stop) "Valid $TargetChannel head revision $($transition.Revision) did not satisfy the v2 schema."
        $head.phase = $wrongPhase
        $wrongHeadJson = $head | ConvertTo-Json -Depth 64 -Compress
        Assert-True (-not (Test-Json -Json $wrongHeadJson -SchemaFile $StateSchemaPath -ErrorAction SilentlyContinue)) "Head revision $($transition.Revision) accepted phase '$wrongPhase'."
    }

    $terminalTransition = $lifecycle.Transitions[[int]$lifecycle.TerminalRevision - 1]
    $terminalPhaseSlug = ([string]$terminalTransition.Phase).ToLowerInvariant().Replace('_', '-')
    $terminalReceiptPath = Join-Path (Join-Path $StateRoot 'receipts') (([int]$terminalTransition.Revision).ToString('0000') + '-' + $terminalPhaseSlug + '.json')
    $beyondReceipt = Read-Json -Path $terminalReceiptPath
    $beyondHead = Read-Json -Path (Join-Path $StateRoot 'head.json')
    $beyondRevision = [int]$lifecycle.TerminalRevision + 1
    if ($TargetChannel -ceq 'pilot') {
        $beyondPhase = 'STABLE_MANIFEST_SIGNING_REQUESTED'
        $beyondReceipt.data.evidenceType = $beyondPhase
        $beyondReceipt.data.relativePath = 'evidence/foundation/10-stable-manifest-signing-requested.json'
        $beyondReceipt.data.sha256 = 'a' * 64
    }
    else {
        $beyondPhase = 'STABLE_FEED_PROMOTED'
    }
    $beyondReceipt.revision = $beyondRevision
    $beyondReceipt.phase = $beyondPhase
    $beyondReceiptJson = $beyondReceipt | ConvertTo-Json -Depth 64 -Compress
    Assert-True (-not (Test-Json -Json $beyondReceiptJson -SchemaFile $StateSchemaPath -ErrorAction SilentlyContinue)) "$TargetChannel receipt revision $beyondRevision satisfied the v2 schema."
    $beyondHead.revision = $beyondRevision
    $beyondHead.phase = $beyondPhase
    $beyondHeadJson = $beyondHead | ConvertTo-Json -Depth 64 -Compress
    Assert-True (-not (Test-Json -Json $beyondHeadJson -SchemaFile $StateSchemaPath -ErrorAction SilentlyContinue)) "$TargetChannel head revision $beyondRevision satisfied the v2 schema."
}

function New-PlanFixture {
    param(
        [Parameter(Mandatory = $true)][string]$Edition,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Commit,
        [Parameter(Mandatory = $true)][string]$RuntimeArchivePath,
        [Parameter(Mandatory = $true)][string]$RuntimeMetadataPath,
        [Parameter(Mandatory = $true)][string]$RuntimeHashPath,
        [Parameter(Mandatory = $true)][string]$UnsignedRoot,
        [Parameter(Mandatory = $true)][string]$SignerSha256,
        [Parameter(Mandatory = $true)][Security.Cryptography.ECParameters]$ResponsePublic,
        [AllowNull()][object]$ManifestResponsePublic,
        [AllowNull()][object]$ReleaseManifestPublic,
        [AllowNull()][object]$RoleFixtureContract = $script:ProductRoleFixtureContract,
        [ValidateSet(1, 2)][int]$SchemaVersion = 1,
        [ValidateSet('pilot', 'stable')][string]$TargetChannel = 'pilot'
    )

    $contract = if ($Edition -ceq 'Personal') {
        @(
            [pscustomobject]@{ role = 'startup-stub'; fileName = 'Ensou.Dsh.Bootstrapper.exe' },
            [pscustomobject]@{ role = 'client-bootstrapper'; fileName = 'Ensou.Dsh.ClientBootstrapper.exe' },
            [pscustomobject]@{ role = 'launcher'; fileName = 'Ensou.Dsh.Launcher.exe' },
            [pscustomobject]@{ role = 'maintenance'; fileName = 'Ensou.Dsh.Personal.Maintenance.exe' }
        )
    }
    else {
        @(
            [pscustomobject]@{ role = 'bootstrapper'; fileName = 'Ensou.Dsh.Enterprise.Bootstrapper.exe' },
            [pscustomobject]@{ role = 'launcher'; fileName = 'Ensou.Dsh.Enterprise.Launcher.exe' },
            [pscustomobject]@{ role = 'client-bootstrapper'; fileName = 'Ensou.Dsh.Enterprise.ClientBootstrapper.exe' },
            [pscustomobject]@{ role = 'maintenance'; fileName = 'Ensou.Dsh.Enterprise.Maintenance.exe' }
        )
    }
    [IO.Directory]::CreateDirectory($UnsignedRoot) | Out-Null
    $inputs = [Collections.Generic.List[object]]::new()
    foreach ($item in $contract) {
        $inputPath = Join-Path $UnsignedRoot $item.fileName
        if ($null -eq $RoleFixtureContract) {
            New-UnsignedPeFixture -OutputPath $inputPath
        }
        else {
            $fixtureRole = @($RoleFixtureContract.Roles | Where-Object {
                    [string]$_.Edition -ceq $Edition -and
                    [string]$_.Role -ceq [string]$item.role -and
                    [string]$_.FileName -ceq [string]$item.fileName
                })
            if ($fixtureRole.Count -ne 1) {
                throw "Product role fixture does not bind exact unsigned input '$Edition/$($item.role)/$($item.fileName)'."
            }
            $fixtureInput = Open-ProductionReleaseInput `
                -Path ([string]$fixtureRole[0].UnsignedPath) `
                -Label "Product role fixture unsigned $Edition/$($item.role)" `
                -MaximumBytes 512MB
            try {
                $fixtureBytes = Read-ProductionReleaseInputBytes `
                    -Descriptor $fixtureInput `
                    -Label "Product role fixture unsigned $Edition/$($item.role)"
                if ($fixtureInput.Sha256 -cne [string]$fixtureRole[0].UnsignedSha256 -or
                    (Get-PeContentSha256 -Bytes $fixtureBytes) -cne [string]$fixtureRole[0].PeContentSha256) {
                    throw "Product role fixture unsigned $Edition/$($item.role) changed after fixture admission."
                }
                [IO.File]::WriteAllBytes($inputPath, $fixtureBytes)
                Assert-ProductionReleaseInputStillLocked `
                    -Descriptor $fixtureInput `
                    -Label "Product role fixture unsigned $Edition/$($item.role)"
            }
            finally {
                $fixtureInput.Stream.Dispose()
            }
        }
        $bytes = [IO.File]::ReadAllBytes($inputPath)
        $inputs.Add([ordered]@{
            role = $item.role
            fileName = $item.fileName
            path = $inputPath
            sizeBytes = [int64]$bytes.Length
            sha256 = Get-Sha256 -Path $inputPath
            peContentSha256 = Get-PeContentSha256 -Bytes $bytes
        })
    }
    $runtimeArchive = Get-Item -LiteralPath $RuntimeArchivePath -Force
    $runtimeMetadata = Get-Item -LiteralPath $RuntimeMetadataPath -Force
    $runtimeHash = Get-Item -LiteralPath $RuntimeHashPath -Force
    $plan = [ordered]@{
        schemaVersion = $SchemaVersion
        planType = 'ensou-dsh-launcher-production-release'
        orchestrationId = [Guid]::NewGuid().ToString()
        edition = $Edition
        releaseSetId = if ($Edition -ceq 'Personal') {
            'personal-v2026.08.30.1'
        }
        else {
            'managed-v2026.08.30.1'
        }
        channel = 'pilot'
        sourceCommit = $Commit
        manifestUri = 'https://updates.example.invalid/v2/channels/pilot/release-set.v2.json'
        artifactBaseUri = 'https://artifacts.example.invalid/launcher/'
        runtimeCandidate = [ordered]@{
            releaseId = 'managed-v2026.08.30.1'
            githubReleaseTag = 'managed-v2026.08.30.1'
            archive = [ordered]@{
                fileName = $runtimeArchive.Name
                path = $runtimeArchive.FullName
                sizeBytes = [int64]$runtimeArchive.Length
                sha256 = Get-Sha256 -Path $runtimeArchive.FullName
            }
            metadata = [ordered]@{
                fileName = $runtimeMetadata.Name
                path = $runtimeMetadata.FullName
                sizeBytes = [int64]$runtimeMetadata.Length
                sha256 = Get-Sha256 -Path $runtimeMetadata.FullName
            }
            hashEvidence = [ordered]@{
                fileName = $runtimeHash.Name
                path = $runtimeHash.FullName
                sizeBytes = [int64]$runtimeHash.Length
                sha256 = Get-Sha256 -Path $runtimeHash.FullName
            }
        }
        authenticodePolicy = [ordered]@{
            signerSha256Thumbprint = $SignerSha256
            requireTrustedTimestamp = $true
            maximumResponseAgeMinutes = 120
        }
        externalResponseTrust = [ordered]@{
            algorithm = 'ES256'
            keyId = 'launcher-external-response-test'
            x = ConvertTo-Base64Url -Bytes $ResponsePublic.Q.X
            y = ConvertTo-Base64Url -Bytes $ResponsePublic.Q.Y
        }
        clientSigningInputs = $inputs
    }
    if ($SchemaVersion -eq 2) {
        $plan.Remove('channel')
        $plan.Insert(5, 'targetChannel', $TargetChannel)
        $plan.manifestUri = "https://updates.example.invalid/v2/channels/$TargetChannel/release-set.v2.json"
        $plan.Remove('externalResponseTrust')
        $additionalTrustSigners = [Collections.Generic.List[Security.Cryptography.ECDsa]]::new()
        try {
            if ($null -eq $ManifestResponsePublic) {
                throw 'Plan v2 fixture requires an independent manifest-response public key.'
            }
            if ($null -eq $ReleaseManifestPublic) {
                throw 'Plan v2 fixture requires an independent release-manifest public key.'
            }
            $domainPublics = [Collections.Generic.List[Security.Cryptography.ECParameters]]::new()
            $domainPublics.Add($ResponsePublic)
            $domainPublics.Add(
                [Security.Cryptography.ECParameters]$ManifestResponsePublic)
            for ($index = 0; $index -lt 2; $index++) {
                $domainSigner = [Security.Cryptography.ECDsa]::Create(
                    [Security.Cryptography.ECCurve+NamedCurves]::nistP256)
                $additionalTrustSigners.Add($domainSigner)
                $domainPublics.Add($domainSigner.ExportParameters($false))
            }
            $plan.externalResponseTrusts = [ordered]@{
                clientSigning = [ordered]@{
                    algorithm = 'ES256'
                    keyId = 'launcher-client-signing-response-test'
                    purpose = 'client-signing-response'
                    x = ConvertTo-Base64Url -Bytes $domainPublics[0].Q.X
                    y = ConvertTo-Base64Url -Bytes $domainPublics[0].Q.Y
                }
                manifestPublishing = [ordered]@{
                    algorithm = 'ES256'
                    keyId = 'launcher-manifest-publishing-response-test'
                    purpose = 'manifest-publishing-response'
                    x = ConvertTo-Base64Url -Bytes $domainPublics[1].Q.X
                    y = ConvertTo-Base64Url -Bytes $domainPublics[1].Q.Y
                }
                installerSigning = [ordered]@{
                    algorithm = 'ES256'
                    keyId = 'launcher-installer-signing-response-test'
                    purpose = if ($Edition -ceq 'Personal') {
                        'personal-installer-signing-response'
                    }
                    else {
                        'installer-signing-response'
                    }
                    x = ConvertTo-Base64Url -Bytes $domainPublics[2].Q.X
                    y = ConvertTo-Base64Url -Bytes $domainPublics[2].Q.Y
                }
                feedPromotion = [ordered]@{
                    algorithm = 'ES256'
                    keyId = 'launcher-feed-promotion-response-test'
                    purpose = 'feed-promotion-response'
                    x = ConvertTo-Base64Url -Bytes $domainPublics[3].Q.X
                    y = ConvertTo-Base64Url -Bytes $domainPublics[3].Q.Y
                }
            }
            $releasePublic = [Security.Cryptography.ECParameters]$ReleaseManifestPublic
            $plan.releaseManifestTrust = [ordered]@{
                algorithm = 'ES256'
                purpose = 'release-manifest-signing'
                keyId = 'launcher-release-manifest-signing-test'
                x = ConvertTo-Base64Url -Bytes $releasePublic.Q.X
                y = ConvertTo-Base64Url -Bytes $releasePublic.Q.Y
            }
            $plan.releaseCompatibility = if ($Edition -ceq 'Personal') {
                [ordered]@{
                    startupStubVersion = '1.2.0'
                    canonicalLowSFromSequence = 1
                }
            }
            else {
                [ordered]@{ startupStubProtocol = 1 }
            }
            if ($Edition -ceq 'Personal') {
                $plan.personalAccountOrigin = 'https://accounts.example.invalid/'
                $sharedChecks = @(
                    'startup-update-detection',
                    'runtime-only-update',
                    'launcher-only-update',
                    'failed-update-rollback',
                    'offline-last-known-good',
                    'local-chat-and-workspace-unchanged',
                    'no-command-window'
                )
                $plan.personalPilotDevices = @(
                    [ordered]@{
                        deviceId = 'pilot-desktop-desktop'
                        hostLabel = 'PILOT-DESKTOP'
                        architecture = 'win-x64'
                        lane = 'existing-install-upgrade'
                        installationIdentity = 'separate-device-identity'
                        tokenOrSecretIncluded = $false
                        roleAcceptance = 'existing-version-upgrade'
                        perDeviceAcceptance = $sharedChecks
                    },
                    [ordered]@{
                        deviceId = 'pilot-notebook'
                        hostLabel = 'PilotNotebook notebook'
                        architecture = 'win-x64'
                        lane = 'clean-first-install'
                        installationIdentity = 'separate-device-identity'
                        tokenOrSecretIncluded = $false
                        roleAcceptance = 'first-install'
                        perDeviceAcceptance = $sharedChecks
                    }
                )
            }
            if ($Edition -ceq 'Enterprise') {
                $plan.pilotEvidenceTrustPolicySha256 = 'e' * 64
            }
        }
        finally {
            for ($index = $additionalTrustSigners.Count - 1; $index -ge 0; $index--) {
                $additionalTrustSigners[$index].Dispose()
            }
        }
    }
    Write-Json -Path $Path -Value $plan
    return $plan
}

function Get-FrozenV1SigningAuthenticationPayload {
    param([Parameter(Mandatory = $true)][psobject]$Response)

    $files = [Collections.Generic.List[object]]::new()
    foreach ($file in @($Response.files)) {
        $files.Add([ordered]@{
            role = [string]$file.role
            fileName = [string]$file.fileName
            relativePath = [string]$file.relativePath
            inputSha256 = [string]$file.inputSha256
            inputPeContentSha256 = [string]$file.inputPeContentSha256
            sizeBytes = [int64]$file.sizeBytes
            sha256 = [string]$file.sha256
            signedPeContentSha256 = [string]$file.signedPeContentSha256
        })
    }
    $body = [ordered]@{
        schemaVersion = [int]$Response.schemaVersion
        responseType = [string]$Response.responseType
        orchestrationId = [string]$Response.orchestrationId
        edition = [string]$Response.edition
        releaseSetId = [string]$Response.releaseSetId
        planSha256 = [string]$Response.planSha256
        requestSha256 = [string]$Response.requestSha256
        requestNonce = [string]$Response.requestNonce
        completedAtUtc = [string]$Response.completedAtUtc
        files = $files
    }
    $domain = $utf8.GetBytes(
        'ensou-dsh-launcher-external-signing-response-authentication-v1' +
        [char]10)
    $json = ConvertTo-ProductionJsonBytes -Value $body
    $payload = [byte[]]::new($domain.Length + $json.Length)
    [Array]::Copy($domain, 0, $payload, 0, $domain.Length)
    [Array]::Copy($json, 0, $payload, $domain.Length, $json.Length)
    return $payload
}

function New-ResponseFixture {
    param(
        [Parameter(Mandatory = $true)][string]$RequestPath,
        [Parameter(Mandatory = $true)][string]$OutputRoot,
        [Parameter(Mandatory = $true)][Security.Cryptography.ECDsa]$Signer,
        [int]$CompletedOffsetMinutes = 0,
        [string]$NonceOverride = '',
        [int]$UnsignedRoleIndex = -1,
        [int]$CorruptHashIndex = -1,
        [AllowNull()][object]$RoleFixtureContract = $script:ProductRoleFixtureContract,
        [switch]$CheckoutCasCryptoFixture,
        [switch]$MissingRole,
        [switch]$ExtraRole,
        [switch]$HighS
    )

    # Only the instrumented checkout/CAS clone may use a cryptographic-only
    # system PE. That clone replaces the executable trust probe and cannot
    # supply release acceptance. All ordinary no-product responses are unsigned
    # negatives, so production import never executes an installed application.
    if ($CheckoutCasCryptoFixture -and $null -eq $RoleFixtureContract -and
        [string]::IsNullOrWhiteSpace($script:Rfc3161SignedPeFixturePath)) {
        throw 'Checkout/CAS cryptographic fixture requires an admitted RFC3161 PE.'
    }

    [IO.Directory]::CreateDirectory($OutputRoot) | Out-Null
    $signedRoot = Join-Path $OutputRoot 'signed'
    [IO.Directory]::CreateDirectory($signedRoot) | Out-Null
    $request = Read-Json -Path $RequestPath
    $files = [Collections.Generic.List[object]]::new()
    for ($index = 0; $index -lt @($request.files).Count; $index++) {
        $requested = $request.files[$index]
        $signedPath = Join-Path $signedRoot ([string]$requested.fileName)
        if ($index -eq $UnsignedRoleIndex) {
            Copy-Item -LiteralPath (Join-Path ([IO.Path]::GetDirectoryName($RequestPath)) ([string]$requested.relativePath).Replace('/', [IO.Path]::DirectorySeparatorChar)) -Destination $signedPath
        }
        elseif ($null -ne $RoleFixtureContract) {
            $fixtureRole = @($RoleFixtureContract.Roles | Where-Object {
                    [string]$_.Edition -ceq [string]$request.edition -and
                    [string]$_.Role -ceq [string]$requested.role -and
                    [string]$_.FileName -ceq [string]$requested.fileName
                })
            if ($fixtureRole.Count -ne 1) {
                throw "Product role fixture does not bind exact signed response '$($request.edition)/$($requested.role)/$($requested.fileName)'."
            }
            $fixtureInput = Open-ProductionReleaseInput `
                -Path ([string]$fixtureRole[0].SignedPath) `
                -Label "Product role fixture signed $($request.edition)/$($requested.role)" `
                -MaximumBytes 512MB
            try {
                $fixtureBytes = Read-ProductionReleaseInputBytes `
                    -Descriptor $fixtureInput `
                    -Label "Product role fixture signed $($request.edition)/$($requested.role)"
                if ($fixtureInput.Sha256 -cne [string]$fixtureRole[0].SignedSha256 -or
                    (Get-PeContentSha256 -Bytes $fixtureBytes) -cne [string]$fixtureRole[0].PeContentSha256 -or
                    [string]$fixtureRole[0].PeContentSha256 -cne [string]$requested.peContentSha256) {
                    throw "Product role fixture signed $($request.edition)/$($requested.role) changed after fixture admission."
                }
                [IO.File]::WriteAllBytes($signedPath, $fixtureBytes)
                Assert-ProductionReleaseInputStillLocked `
                    -Descriptor $fixtureInput `
                    -Label "Product role fixture signed $($request.edition)/$($requested.role)"
            }
            finally {
                $fixtureInput.Stream.Dispose()
            }
        }
        elseif ($CheckoutCasCryptoFixture) {
            Copy-Item -LiteralPath $script:Rfc3161SignedPeFixturePath -Destination $signedPath
        }
        else {
            Copy-Item -LiteralPath $script:UnsignedPeFixturePath -Destination $signedPath
        }
        $signedBytes = [IO.File]::ReadAllBytes($signedPath)
        $sha256 = Get-Sha256 -Path $signedPath
        if ($index -eq $CorruptHashIndex) {
            $sha256 = '0' * 64
        }
        $files.Add([ordered]@{
            role = [string]$requested.role
            fileName = [string]$requested.fileName
            relativePath = 'signed/' + [string]$requested.fileName
            inputSha256 = [string]$requested.sha256
            inputPeContentSha256 = [string]$requested.peContentSha256
            sizeBytes = [int64]$signedBytes.Length
            sha256 = $sha256
            signedPeContentSha256 = Get-PeContentSha256 -Bytes $signedBytes
        })
    }
    if ($MissingRole) {
        $files.RemoveAt($files.Count - 1)
    }
    if ($ExtraRole) {
        $files.Add($files[0])
    }
    $completed = [DateTimeOffset]::UtcNow.AddMinutes($CompletedOffsetMinutes)
    $response = [ordered]@{
        schemaVersion = 1
        responseType = 'ensou-dsh-launcher-client-authenticode-signing-response'
        orchestrationId = [string]$request.orchestrationId
        edition = [string]$request.edition
        releaseSetId = [string]$request.releaseSetId
        planSha256 = [string]$request.planSha256
        requestSha256 = Get-Sha256 -Path $RequestPath
        requestNonce = if ($NonceOverride) { $NonceOverride } else { [string]$request.nonce }
        completedAtUtc = $completed.ToUniversalTime().ToString(
            'yyyy-MM-ddTHH:mm:ssZ',
            [Globalization.CultureInfo]::InvariantCulture)
        files = $files
    }
    $authentication = [ordered]@{
        algorithm = 'ES256'
        keyId = [string]$request.responseAuthentication.keyId
    }
    $requestPurposeProperty = $request.responseAuthentication.PSObject.Properties['purpose']
    if ($null -ne $requestPurposeProperty) {
        $authentication['purpose'] = [string]$requestPurposeProperty.Value
        $authentication['payloadType'] = [string]$request.responseAuthentication.payloadType
    }
    $response['authentication'] = $authentication
    $dictionaryPayload = Get-ProductionReleaseSigningResponseAuthenticationPayload -Response ([pscustomobject]$response)
    $payloadResponse = $response | ConvertTo-Json -Depth 64 -Compress | ConvertFrom-Json -Depth 64 -DateKind String
    $payload = Get-ProductionReleaseSigningResponseAuthenticationPayload -Response $payloadResponse
    Assert-True (
        [Convert]::ToHexString($dictionaryPayload) -ceq [Convert]::ToHexString($payload)) `
        'External-response authentication payload changed after JSON round-trip.'
    $signature = $Signer.SignData(
        $payload,
        [Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)
    if ($null -ne $requestPurposeProperty) {
        $signature = ConvertTo-LowSP256Signature -Signature $signature
        if ($HighS) {
            $signature = ConvertTo-HighSP256Signature -LowSignature $signature
        }
    }
    $response.authentication['value'] = ConvertTo-Base64Url -Bytes $signature
    $responsePath = Join-Path $OutputRoot 'signing-response.v1.json'
    Write-Json -Path $responsePath -Value $response
    return $responsePath
}

function New-MutatedResponseBundle {
    param(
        [Parameter(Mandatory = $true)][string]$SourceResponsePath,
        [Parameter(Mandatory = $true)][string]$OutputRoot,
        [Parameter(Mandatory = $true)][scriptblock]$Mutate
    )

    [IO.Directory]::CreateDirectory($OutputRoot) | Out-Null
    $signedRoot = Join-Path $OutputRoot 'signed'
    [IO.Directory]::CreateDirectory($signedRoot) | Out-Null
    $sourceSignedRoot = Join-Path ([IO.Path]::GetDirectoryName($SourceResponsePath)) 'signed'
    foreach ($signedFile in @(Get-ChildItem -LiteralPath $sourceSignedRoot -File)) {
        [IO.File]::Copy($signedFile.FullName, (Join-Path $signedRoot $signedFile.Name), $false)
    }
    $response = Read-Json -Path $SourceResponsePath
    & $Mutate $response
    $responsePath = Join-Path $OutputRoot 'signing-response.v1.json'
    Write-Json -Path $responsePath -Value $response
    return $responsePath
}

function ConvertFrom-Base64UrlFixture {
    param([Parameter(Mandatory = $true)][string]$Value)

    $padded = $Value.Replace('-', '+').Replace('_', '/')
    switch ($padded.Length % 4) {
        0 {}
        2 { $padded += '==' }
        3 { $padded += '=' }
        default { throw 'Fixture base64url value has an invalid length.' }
    }
    return [Convert]::FromBase64String($padded)
}

function New-MutatedManifestPublishingResponseBundle {
    param(
        [Parameter(Mandatory = $true)][string]$SourceResponsePath,
        [Parameter(Mandatory = $true)][string]$OutputRoot,
        [Parameter(Mandatory = $true)][scriptblock]$Mutate,
        [AllowNull()][Security.Cryptography.ECDsa]$Signer,
        [switch]$Resign,
        [switch]$HighS,
        [switch]$NonCanonical
    )

    [IO.Directory]::CreateDirectory($OutputRoot) | Out-Null
    $candidateRoot = Join-Path $OutputRoot 'candidate'
    [IO.Directory]::CreateDirectory($candidateRoot) | Out-Null
    $sourceCandidateRoot = Join-Path `
        ([IO.Path]::GetDirectoryName($SourceResponsePath)) `
        'candidate'
    foreach ($candidate in @(Get-ChildItem -LiteralPath $sourceCandidateRoot -File)) {
        [IO.File]::Copy(
            $candidate.FullName,
            (Join-Path $candidateRoot $candidate.Name),
            $false)
    }
    $response = Read-Json -Path $SourceResponsePath
    & $Mutate $response $candidateRoot
    if ($Resign) {
        if ($null -eq $Signer) {
            throw 'Manifest response mutation requested resigning without a signer.'
        }
        $payload = Get-ProductionReleaseManifestPublishingResponseAuthenticationPayload `
            -Response $response
        $signature = ConvertTo-LowSP256Signature -Signature ($Signer.SignData(
            $payload,
            [Security.Cryptography.HashAlgorithmName]::SHA256,
            [Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation))
        $response.authentication.value = ConvertTo-Base64Url -Bytes $signature
    }
    if ($HighS) {
        $low = ConvertFrom-Base64UrlFixture `
            -Value ([string]$response.authentication.value)
        $response.authentication.value = ConvertTo-Base64Url `
            -Bytes (ConvertTo-HighSP256Signature -LowSignature $low)
    }
    $responsePath = Join-Path `
        $OutputRoot `
        'manifest-publishing-response.v1.json'
    if ($NonCanonical) {
        Write-Json -Path $responsePath -Value $response
    }
    else {
        Write-CanonicalJson -Path $responsePath -Value $response
    }
    return $responsePath
}

function New-MutatedSignedCandidateManifestBundle {
    param(
        [Parameter(Mandatory = $true)][string]$SourceResponsePath,
        [Parameter(Mandatory = $true)][string]$OutputRoot,
        [Parameter(Mandatory = $true)][scriptblock]$Mutate,
        [Parameter(Mandatory = $true)][Security.Cryptography.ECDsa]$ReleaseSigner,
        [Parameter(Mandatory = $true)][Security.Cryptography.ECDsa]$ResponseSigner,
        [int]$HighSArtifactIndex = -1,
        [switch]$HighSManifest,
        [switch]$UseGenericEnterprisePayloadForInvalidTimestampFixture
    )

    [IO.Directory]::CreateDirectory($OutputRoot) | Out-Null
    $candidateRoot = Join-Path $OutputRoot 'candidate'
    [IO.Directory]::CreateDirectory($candidateRoot) | Out-Null
    $sourceCandidateRoot = Join-Path `
        ([IO.Path]::GetDirectoryName($SourceResponsePath)) `
        'candidate'
    foreach ($candidate in @(Get-ChildItem -LiteralPath $sourceCandidateRoot -File)) {
        [IO.File]::Copy(
            $candidate.FullName,
            (Join-Path $candidateRoot $candidate.Name),
            $false)
    }
    $response = Read-Json -Path $SourceResponsePath
    $manifestPath = Join-Path $candidateRoot 'release-set.v2.json'
    $manifest = Read-Json -Path $manifestPath
    & $Mutate $manifest $response $candidateRoot

    for ($index = 0; $index -lt @($manifest.artifacts).Count; $index++) {
        $artifact = $manifest.artifacts[$index]
        $artifactPayloadLines = if ([string]$response.edition -ceq 'Personal') {
            @(
                'ensou-dsh-personal-artifact-v2', [string]$manifest.product,
                [string]$manifest.environment, [string]$manifest.channel,
                [string]$manifest.releaseSetId, [string]$manifest.generation,
                [string]$manifest.sequence, [string]$artifact.component,
                [string]$artifact.releaseId, [string]$artifact.uri,
                [string]$artifact.sizeBytes, [string]$artifact.sha256,
                [string]$artifact.completeTreeSha256)
        }
        else {
            @(
                'ensou-dsh-enterprise-artifact-v2', [string]$manifest.product,
                [string]$manifest.environment, [string]$manifest.releaseSetId,
                [string]$artifact.component, [string]$artifact.releaseId,
                [string]$artifact.sizeBytes, [string]$artifact.sha256,
                [string]$artifact.completeTreeSha256, [string]$artifact.uri)
        }
        $artifactPayload = $utf8.GetBytes($artifactPayloadLines -join [char]10)
        $artifactSignature = ConvertTo-LowSP256Signature -Signature (
            $ReleaseSigner.SignData(
                $artifactPayload,
                [Security.Cryptography.HashAlgorithmName]::SHA256,
                [Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation))
        if ($index -eq $HighSArtifactIndex) {
            $artifactSignature = ConvertTo-HighSP256Signature -LowSignature $artifactSignature
        }
        $artifact.signature = [pscustomobject][ordered]@{
            algorithm = 'ES256'
            keyId = [string]$manifest.signature.keyId
            value = ConvertTo-Base64Url -Bytes $artifactSignature
        }
    }
    $manifestPayloadObject = [ordered]@{}
    foreach ($property in $manifest.PSObject.Properties) {
        if ([string]$property.Name -cne 'signature') {
            $manifestPayloadObject[[string]$property.Name] = $property.Value
        }
    }
    $manifestPayload = if (
        [string]$response.edition -ceq 'Enterprise' -and
        -not $UseGenericEnterprisePayloadForInvalidTimestampFixture) {
        ConvertTo-ProductionEnterpriseReleaseManifestPayloadBytes `
            -Manifest $manifestPayloadObject
    }
    else {
        ConvertTo-ProductionSystemTextJsonBytes -Value $manifestPayloadObject
    }
    $manifestSignature = ConvertTo-LowSP256Signature -Signature (
        $ReleaseSigner.SignData(
            $manifestPayload,
            [Security.Cryptography.HashAlgorithmName]::SHA256,
            [Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation))
    if ($HighSManifest) {
        $manifestSignature = ConvertTo-HighSP256Signature -LowSignature $manifestSignature
    }
    $manifest.signature = [pscustomobject][ordered]@{
        algorithm = 'ES256'
        keyId = [string]$manifest.signature.keyId
        value = ConvertTo-Base64Url -Bytes $manifestSignature
    }
    Write-CanonicalJson -Path $manifestPath -Value $manifest
    $manifestItem = Get-Item -LiteralPath $manifestPath -Force
    $response.files[0].sizeBytes = [int64]$manifestItem.Length
    $response.files[0].sha256 = Get-Sha256 -Path $manifestPath
    $responsePayload = Get-ProductionReleaseManifestPublishingResponseAuthenticationPayload `
        -Response $response
    $responseSignature = ConvertTo-LowSP256Signature -Signature (
        $ResponseSigner.SignData(
            $responsePayload,
            [Security.Cryptography.HashAlgorithmName]::SHA256,
            [Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation))
    $response.authentication.value = ConvertTo-Base64Url -Bytes $responseSignature
    $responsePath = Join-Path $OutputRoot 'manifest-publishing-response.v1.json'
    Write-CanonicalJson -Path $responsePath -Value $response
    return $responsePath
}

function Write-CanonicalJson {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Value
    )

    [IO.File]::WriteAllBytes($Path, (ConvertTo-ProductionJsonBytes -Value $Value))
}

function New-ProductReleaseManifestValidatorRunner {
    param(
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [Parameter(Mandatory = $true)][string]$OutputRoot
    )

    [IO.Directory]::CreateDirectory($OutputRoot) | Out-Null
    $contractsProject = [Security.SecurityElement]::Escape(
        (Join-Path $RepositoryRoot 'src\Ensou.Dsh.Contracts\Ensou.Dsh.Contracts.csproj'))
    $enterpriseProject = [Security.SecurityElement]::Escape(
        (Join-Path $RepositoryRoot 'src\Ensou.Dsh.Enterprise.ReleaseContracts\Ensou.Dsh.Enterprise.ReleaseContracts.csproj'))
    $projectPath = Join-Path $OutputRoot 'ProductReleaseManifestValidator.csproj'
    $projectText = @"
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net10.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
    <TreatWarningsAsErrors>true</TreatWarningsAsErrors>
  </PropertyGroup>
  <ItemGroup>
    <ProjectReference Include="$contractsProject" />
    <ProjectReference Include="$enterpriseProject" />
  </ItemGroup>
</Project>
"@
    [IO.File]::WriteAllText($projectPath, $projectText, $utf8)
    $programPath = Join-Path $OutputRoot 'Program.cs'
    $programText = @'
using System.Globalization;
using System.Security.Cryptography;
using Ensou.Dsh.Contracts;
using Ensou.Dsh.Enterprise.Installation;

// Rejections are test results, not unhandled CLR exceptions that can show a
// Windows application-error dialog on the developer's desktop.
try
{
if (args.Length == 3 && args[0] == "--canonical-payload-sha256")
{
    var payloadManifestBytes = File.ReadAllBytes(args[2]);
    var payload = args[1] switch
    {
        "Personal" => PersonalReleaseCanonicalJson.ManifestPayload(
            PersonalReleaseSetJson.Parse(payloadManifestBytes)),
        "Enterprise" => EnterpriseReleaseCanonicalJson.ManifestPayload(
            EnterpriseReleaseSetManifest.Parse(payloadManifestBytes)),
        _ => throw new InvalidDataException(
            "Product release manifest canonical-payload edition is invalid."),
    };
    Console.WriteLine(
        "PRODUCT-RELEASE-MANIFEST-CANONICAL-PAYLOAD-SHA256="
        + Convert.ToHexString(SHA256.HashData(payload)).ToLowerInvariant());
    return 0;
}

if (args.Length != 11)
{
    throw new InvalidDataException("Product release manifest validator runner arguments are invalid.");
}

var edition = args[0];
var manifestBytes = File.ReadAllBytes(args[1]);
var channel = args[2];
var artifactOrigin = new Uri(args[3], UriKind.Absolute);
var manifestOrigin = new Uri(args[4], UriKind.Absolute);
var compatibility = args[5];
var canonicalLowSFromSequence = long.Parse(args[6], CultureInfo.InvariantCulture);
var keyId = args[7];
var keyX = args[8];
var keyY = args[9];
var validationTimeUtc = DateTimeOffset.ParseExact(
    args[10],
    "yyyy-MM-dd'T'HH:mm:ss'Z'",
    CultureInfo.InvariantCulture,
    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);

if (edition == "Personal")
{
    _ = PersonalReleaseSetValidator.ParseAndVerify(
        manifestBytes,
        new PersonalReleaseTrustPolicy
        {
            Product = PersonalReleaseSetContract.Product,
            Environment = PersonalReleaseSetContract.ProductionEnvironment,
            Channel = channel,
            ArtifactOrigin = artifactOrigin,
            StartupStubVersion = compatibility,
            CanonicalLowSFromSequence = canonicalLowSFromSequence,
            TrustedKeys = [new PersonalReleasePublicKey(keyId, keyX, keyY)],
        },
        validationTimeUtc);
}
else if (edition == "Enterprise")
{
    var manifest = EnterpriseReleaseSetManifest.Parse(manifestBytes);
    EnterpriseReleaseSetValidator.Verify(
        manifest,
        new EnterpriseReleaseTrustPolicy
        {
            Product = EnterpriseReleaseSetContract.Product,
            Environment = EnterpriseReleaseSetContract.ProductionEnvironment,
            ExpectedChannel = channel,
            CurrentStartupStubProtocol = int.Parse(compatibility, CultureInfo.InvariantCulture),
            ManifestOrigin = manifestOrigin,
            ArtifactOrigin = artifactOrigin,
            TrustedKeys = [new EnterpriseReleasePublicKey(keyId, keyX, keyY)],
        },
        validationTimeUtc);
}
else
{
    throw new InvalidDataException("Product release manifest validator runner edition is invalid.");
}

Console.WriteLine("PRODUCT-RELEASE-MANIFEST-VALIDATOR-ACCEPTED");
return 0;
}
catch (Exception exception)
{
    Console.Error.WriteLine("PRODUCT-RELEASE-MANIFEST-VALIDATOR-REJECTED="
        + exception.GetType().Name);
    return 1;
}
'@
    [IO.File]::WriteAllText($programPath, $programText, $utf8)
    $nugetConfigPath = Join-Path $OutputRoot 'NuGet.Config'
    $nugetConfigText = @'
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
  </packageSources>
</configuration>
'@
    [IO.File]::WriteAllText($nugetConfigPath, $nugetConfigText, $utf8)
    $restoreOutput = @(& dotnet restore $projectPath `
        --configfile $nugetConfigPath `
        --nologo `
        --verbosity quiet 2>&1 |
        ForEach-Object { [string]$_ })
    $restoreExitCode = $LASTEXITCODE
    $global:LASTEXITCODE = 0
    if ($restoreExitCode -ne 0) {
        throw "Product release manifest validator runner failed its hermetic restore: $($restoreOutput -join ' ')"
    }
    $buildOutput = @(& dotnet build $projectPath -c Release --no-restore --nologo --verbosity quiet 2>&1 |
        ForEach-Object { [string]$_ })
    $buildExitCode = $LASTEXITCODE
    $global:LASTEXITCODE = 0
    if ($buildExitCode -ne 0) {
        throw "Product release manifest validator runner failed to build: $($buildOutput -join ' ')"
    }
    $runnerPath = Join-Path $OutputRoot 'bin\Release\net10.0\ProductReleaseManifestValidator.dll'
    if (-not (Test-Path -LiteralPath $runnerPath -PathType Leaf)) {
        throw 'Product release manifest validator runner build did not emit its exact assembly.'
    }
    return $runnerPath
}

function Assert-ProductReleaseManifestPayloadParity {
    param(
        [Parameter(Mandatory = $true)][string]$RunnerPath,
        [Parameter(Mandatory = $true)][ValidateSet('Personal', 'Enterprise')][string]$Edition,
        [Parameter(Mandatory = $true)][string]$ManifestPath
    )

    $manifest = Read-Json -Path $ManifestPath
    $payloadObject = [ordered]@{}
    foreach ($property in $manifest.PSObject.Properties) {
        if ([string]$property.Name -cne 'signature') {
            $payloadObject[[string]$property.Name] = $property.Value
        }
    }
    $payloadBytes = if ($Edition -ceq 'Enterprise') {
        ConvertTo-ProductionEnterpriseReleaseManifestPayloadBytes `
            -Manifest $payloadObject
    }
    else {
        ConvertTo-ProductionSystemTextJsonBytes -Value $payloadObject
    }
    $expected = 'PRODUCT-RELEASE-MANIFEST-CANONICAL-PAYLOAD-SHA256=' + (
        Get-ProductionSha256Bytes -Bytes $payloadBytes)
    $output = @(& dotnet $RunnerPath `
        '--canonical-payload-sha256' `
        $Edition `
        $ManifestPath 2>&1 | ForEach-Object { [string]$_ })
    $exitCode = $LASTEXITCODE
    $global:LASTEXITCODE = 0
    Assert-True (
        $exitCode -eq 0 -and
        $output.Count -eq 1 -and
        [string]$output[0] -ceq $expected) `
        ("Exact {0} canonical payload bytes diverged from the actual product writer: {1}" -f $Edition, ($output -join ' '))
}

function Assert-ProductReleaseManifestAccepted {
    param(
        [Parameter(Mandatory = $true)][string]$RunnerPath,
        [Parameter(Mandatory = $true)][string]$PlanPath,
        [Parameter(Mandatory = $true)][string]$ResponsePath
    )

    $plan = Read-Json -Path $PlanPath
    $response = Read-Json -Path $ResponsePath
    $manifestPath = Join-Path `
        (Join-Path ([IO.Path]::GetDirectoryName($ResponsePath)) 'candidate') `
        'release-set.v2.json'
    $artifactOrigin = ([Uri]$plan.artifactBaseUri).GetLeftPart([UriPartial]::Authority) + '/'
    $manifestOrigin = ([Uri]$plan.manifestUri).GetLeftPart([UriPartial]::Authority) + '/'
    $compatibility = if ([string]$plan.edition -ceq 'Personal') {
        [string]$plan.releaseCompatibility.startupStubVersion
    }
    else {
        [string]$plan.releaseCompatibility.startupStubProtocol
    }
    $canonicalLowSFromSequence = if ([string]$plan.edition -ceq 'Personal') {
        [string]$plan.releaseCompatibility.canonicalLowSFromSequence
    }
    else {
        '1'
    }
    $output = @(& dotnet $RunnerPath `
        ([string]$plan.edition) `
        $manifestPath `
        ([string]$plan.targetChannel) `
        $artifactOrigin `
        $manifestOrigin `
        $compatibility `
        $canonicalLowSFromSequence `
        ([string]$plan.releaseManifestTrust.keyId) `
        ([string]$plan.releaseManifestTrust.x) `
        ([string]$plan.releaseManifestTrust.y) `
        ([string]$response.completedAtUtc) 2>&1 | ForEach-Object { [string]$_ })
    $exitCode = $LASTEXITCODE
    $global:LASTEXITCODE = 0
    Assert-True (
        $exitCode -eq 0 -and
        ($output -join [char]10).Contains(
            'PRODUCT-RELEASE-MANIFEST-VALIDATOR-ACCEPTED',
            [StringComparison]::Ordinal)) `
        ("Actual {0} product release-set validator rejected the admitted exact manifest bytes: {1}" -f [string]$plan.edition, ($output -join ' '))
}

function ConvertTo-LowSP256Signature {
    param([Parameter(Mandatory = $true)][byte[]]$Signature)

    if ($Signature.Length -ne 64) {
        throw 'P-256 P1363 fixture signature must contain 64 bytes.'
    }
    $orderBytes = [Convert]::FromHexString(
        'FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551')
    $halfOrderBytes = [Convert]::FromHexString(
        '7FFFFFFF800000007FFFFFFFFFFFFFFFDE737D56D38BCF4279DCE5617E3192A8')
    $highS = $false
    foreach ($index in 0..31) {
        if ($Signature[$index + 32] -gt $halfOrderBytes[$index]) {
            $highS = $true
            break
        }
        if ($Signature[$index + 32] -lt $halfOrderBytes[$index]) {
            break
        }
    }
    if (-not $highS) {
        return [byte[]]$Signature.Clone()
    }
    $order = [Numerics.BigInteger]::new($orderBytes, $true, $true)
    $sBytes = [byte[]]::new(32)
    [Array]::Copy($Signature, 32, $sBytes, 0, 32)
    $s = [Numerics.BigInteger]::new($sBytes, $true, $true)
    $lowBytes = ($order - $s).ToByteArray($true, $true)
    if ($lowBytes.Length -gt 32) {
        throw 'Normalized P-256 fixture scalar exceeded 32 bytes.'
    }
    $result = [byte[]]$Signature.Clone()
    [Array]::Clear($result, 32, 32)
    [Array]::Copy($lowBytes, 0, $result, 64 - $lowBytes.Length, $lowBytes.Length)
    return $result
}

function ConvertTo-HighSP256Signature {
    param([Parameter(Mandatory = $true)][byte[]]$LowSignature)

    $orderBytes = [Convert]::FromHexString(
        'FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551')
    $order = [Numerics.BigInteger]::new($orderBytes, $true, $true)
    $sBytes = [byte[]]::new(32)
    [Array]::Copy($LowSignature, 32, $sBytes, 0, 32)
    $s = [Numerics.BigInteger]::new($sBytes, $true, $true)
    $highBytes = ($order - $s).ToByteArray($true, $true)
    $result = [byte[]]$LowSignature.Clone()
    [Array]::Clear($result, 32, 32)
    [Array]::Copy($highBytes, 0, $result, 64 - $highBytes.Length, $highBytes.Length)
    return $result
}

function New-PublisherInputFixture {
    param(
        [Parameter(Mandatory = $true)][string]$PlanPath,
        [Parameter(Mandatory = $true)][string]$StateRoot,
        [Parameter(Mandatory = $true)][string]$OutputRoot
    )

    [IO.Directory]::CreateDirectory($OutputRoot) | Out-Null
    $payloadRoot = Join-Path $OutputRoot 'payload'
    [IO.Directory]::CreateDirectory($payloadRoot) | Out-Null
    $plan = Read-Json -Path $PlanPath
    $identity = Read-Json -Path (Join-Path $StateRoot 'identity.json')
    $planReceipt = Read-Json -Path (
        Join-Path (Join-Path $StateRoot 'receipts') '0001-plan-admitted.json')
    $clientReceiptPath = Join-Path `
        (Join-Path $StateRoot 'receipts') `
        '0003-client-signatures-imported.json'
    $clientReceipt = Read-Json -Path $clientReceiptPath
    $files = [Collections.Generic.List[object]]::new()
    for ($index = 0; $index -lt @($plan.clientSigningInputs).Count; $index++) {
        $planned = $plan.clientSigningInputs[$index]
        $imported = $clientReceipt.data.files[$index]
        $source = Join-Path `
            (Join-Path (Join-Path $StateRoot 'imports\client-signing.v1') 'signed') `
            ([string]$planned.fileName)
        $destination = Join-Path $payloadRoot ([string]$planned.fileName)
        [IO.File]::Copy($source, $destination, $false)
        $files.Add([ordered]@{
            role = 'client-' + [string]$planned.role
            fileName = [string]$planned.fileName
            relativePath = 'payload/' + [string]$planned.fileName
            sizeBytes = [int64]$imported.sizeBytes
            sha256 = [string]$imported.sha256
        })
    }
    $runtimeRoles = @('runtime-archive', 'runtime-metadata', 'runtime-hash-evidence')
    $runtimeDescriptors = @(
        $plan.runtimeCandidate.archive,
        $plan.runtimeCandidate.metadata,
        $plan.runtimeCandidate.hashEvidence)
    for ($index = 0; $index -lt $runtimeDescriptors.Count; $index++) {
        $runtime = $runtimeDescriptors[$index]
        [IO.File]::Copy(
            [string]$runtime.path,
            (Join-Path $payloadRoot ([string]$runtime.fileName)),
            $false)
        $files.Add([ordered]@{
            role = [string]$runtimeRoles[$index]
            fileName = [string]$runtime.fileName
            relativePath = 'payload/' + [string]$runtime.fileName
            sizeBytes = [int64]$runtime.sizeBytes
            sha256 = [string]$runtime.sha256
        })
    }
    $descriptor = [ordered]@{
        schemaVersion = 1
        descriptorType = 'ensou-dsh-launcher-production-publisher-input'
        orchestrationId = [string]$plan.orchestrationId
        edition = [string]$plan.edition
        releaseSetId = [string]$plan.releaseSetId
        channel = [string]$plan.targetChannel
        planSha256 = [string]$identity.planSha256
        sourceCommit = [string]$plan.sourceCommit
        manifestUri = [string]$plan.manifestUri
        artifactBaseUri = [string]$plan.artifactBaseUri
        releaseManifestTrust = $plan.releaseManifestTrust
        releaseCompatibility = $plan.releaseCompatibility
        componentReleaseIds = if ([string]$plan.edition -ceq 'Personal') {
            [ordered]@{
                clientBundle = 'client+' + [string]$plan.releaseSetId
                runtime = [string]$plan.runtimeCandidate.releaseId
            }
        }
        else {
            [ordered]@{
                launcher = 'launcher+' + [string]$plan.releaseSetId
                runtime = [string]$plan.runtimeCandidate.releaseId
                pluginPolicy = 'plugins+' + [string]$plan.releaseSetId
            }
        }
        runtimeProvenance = [ordered]@{
            harnessSourceTag = [string]$planReceipt.data.runtimeCandidate.harnessSourceTag
            harnessSourceCommit = [string]$planReceipt.data.runtimeCandidate.harnessSourceCommit
        }
        files = $files
    }
    $path = Join-Path $OutputRoot 'publisher-input.v1.json'
    Write-CanonicalJson -Path $path -Value $descriptor
    return $path
}

function New-ManifestPublishingResponseFixture {
    param(
        [Parameter(Mandatory = $true)][string]$RequestPath,
        [Parameter(Mandatory = $true)][string]$AdmissionHeadSha256,
        [Parameter(Mandatory = $true)][string]$OutputRoot,
        [Parameter(Mandatory = $true)][Security.Cryptography.ECDsa]$Signer,
        [Parameter(Mandatory = $true)][Security.Cryptography.ECDsa]$ReleaseSigner
    )

    [IO.Directory]::CreateDirectory($OutputRoot) | Out-Null
    $candidateRoot = Join-Path $OutputRoot 'candidate'
    [IO.Directory]::CreateDirectory($candidateRoot) | Out-Null
    $request = Read-Json -Path $RequestPath
    $publisherInput = Read-Json -Path (
        Join-Path ([IO.Path]::GetDirectoryName($RequestPath)) 'publisher-input.v1.json')
    $issued = [DateTimeOffset]::UtcNow.AddMinutes(-1)
    $expires = $issued.AddDays(1)
    $timestampFormat = if ([string]$request.edition -ceq 'Personal') {
        "yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'"
    }
    else {
        "yyyy-MM-dd'T'HH:mm:ss.fffffffzzz"
    }
    $issuedText = $issued.ToUniversalTime().ToString(
        $timestampFormat,
        [Globalization.CultureInfo]::InvariantCulture)
    $expiresText = $expires.ToUniversalTime().ToString(
        $timestampFormat,
        [Globalization.CultureInfo]::InvariantCulture)
    $keyId = [string]$request.releaseManifestTrust.keyId
    $artifactDefinitions = if ([string]$request.edition -ceq 'Personal') {
        @(
            [pscustomobject]@{ Component = 'client-bundle'; Source = $request.publisherInput.files[0] },
            [pscustomobject]@{ Component = 'runtime'; Source = $request.publisherInput.files[-1] })
    }
    else {
        @(
            [pscustomobject]@{ Component = 'launcher'; Source = $request.publisherInput.files[0] },
            [pscustomobject]@{ Component = 'runtime'; Source = $request.publisherInput.files[-1] },
            [pscustomobject]@{ Component = 'plugin-policy'; Source = $request.publisherInput.files[1] })
    }
    $artifacts = [Collections.Generic.List[object]]::new()
    foreach ($definition in $artifactDefinitions) {
        $source = $definition.Source
        $componentReleaseId = if ([string]$request.edition -ceq 'Personal') {
            if ([string]$definition.Component -ceq 'client-bundle') {
                [string]$request.componentReleaseIds.clientBundle
            }
            else {
                [string]$request.componentReleaseIds.runtime
            }
        }
        else {
            switch ([string]$definition.Component) {
                'launcher' { [string]$request.componentReleaseIds.launcher }
                'runtime' { [string]$request.componentReleaseIds.runtime }
                'plugin-policy' { [string]$request.componentReleaseIds.pluginPolicy }
            }
        }
        $artifact = [ordered]@{
            component = [string]$definition.Component
            releaseId = $componentReleaseId
            uri = [string]$publisherInput.artifactBaseUri + [string]$source.fileName
            sizeBytes = [int64]$source.sizeBytes
            sha256 = [string]$source.sha256
            completeTreeSha256 = [string]$source.sha256
        }
        $artifactPayload = if ([string]$request.edition -ceq 'Personal') {
            $utf8.GetBytes((@(
                    'ensou-dsh-personal-artifact-v2',
                    'ensou-dsh-personal',
                    'production',
                    [string]$request.channel,
                    [string]$request.releaseSetId,
                    '1',
                    '1',
                    [string]$artifact.component,
                    [string]$artifact.releaseId,
                    [string]$artifact.uri,
                    [string]$artifact.sizeBytes,
                    [string]$artifact.sha256,
                    [string]$artifact.completeTreeSha256) -join [char]10))
        }
        else {
            $utf8.GetBytes((@(
                    'ensou-dsh-enterprise-artifact-v2',
                    'ensou-dsh-enterprise',
                    'production',
                    [string]$request.releaseSetId,
                    [string]$artifact.component,
                    [string]$artifact.releaseId,
                    [string]$artifact.sizeBytes,
                    [string]$artifact.sha256,
                    [string]$artifact.completeTreeSha256,
                    [string]$artifact.uri) -join [char]10))
        }
        $artifactSignature = ConvertTo-LowSP256Signature -Signature (
            $ReleaseSigner.SignData(
                $artifactPayload,
                [Security.Cryptography.HashAlgorithmName]::SHA256,
                [Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation))
        $artifact.signature = [ordered]@{
            algorithm = 'ES256'
            keyId = $keyId
            value = ConvertTo-Base64Url -Bytes $artifactSignature
        }
        $artifacts.Add($artifact)
    }
    $manifest = if ([string]$request.edition -ceq 'Personal') {
        [ordered]@{
            schemaVersion = 2
            product = 'ensou-dsh-personal'
            environment = 'production'
            channel = [string]$request.channel
            releaseSetId = [string]$request.releaseSetId
            provenance = [ordered]@{
                launcherRepositoryCommit = [string]$publisherInput.sourceCommit
                harnessSourceTag = [string]$request.runtimeProvenance.harnessSourceTag
                harnessSourceCommit = [string]$request.runtimeProvenance.harnessSourceCommit
            }
            generation = 1
            sequence = 1
            minAcceptedSequence = 0
            issuedAtUtc = $issuedText
            expiresAtUtc = $expiresText
            maximumOfflineGraceSeconds = 86400
            startupStub = [ordered]@{
                minimumVersion = [string]$request.releaseCompatibility.startupStubVersion
                maximumVersion = [string]$request.releaseCompatibility.startupStubVersion
            }
            revokedReleaseSetIds = @()
            artifacts = $artifacts
        }
    }
    else {
        [ordered]@{
            schemaVersion = 2
            product = 'ensou-dsh-enterprise'
            environment = 'production'
            channel = [string]$request.channel
            releaseSetId = [string]$request.releaseSetId
            generation = 1
            sequence = 1
            minAcceptedSequence = 0
            issuedAtUtc = $issuedText
            expiresAtUtc = $expiresText
            startupStub = [ordered]@{
                minimumProtocol = [int]$request.releaseCompatibility.startupStubProtocol
                maximumProtocol = [int]$request.releaseCompatibility.startupStubProtocol
            }
            revokedReleaseSetIds = @()
            artifacts = $artifacts
        }
    }
    $manifestPayload = if ([string]$request.edition -ceq 'Enterprise') {
        ConvertTo-ProductionEnterpriseReleaseManifestPayloadBytes `
            -Manifest $manifest
    }
    else {
        ConvertTo-ProductionSystemTextJsonBytes -Value $manifest
    }
    $manifestSignature = ConvertTo-LowSP256Signature -Signature (
        $ReleaseSigner.SignData(
            $manifestPayload,
            [Security.Cryptography.HashAlgorithmName]::SHA256,
            [Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation))
    $manifest.signature = [ordered]@{
        algorithm = 'ES256'
        keyId = $keyId
        value = ConvertTo-Base64Url -Bytes $manifestSignature
    }
    $manifestPath = Join-Path $candidateRoot 'release-set.v2.json'
    Write-CanonicalJson -Path $manifestPath -Value $manifest
    $candidateFiles = [Collections.Generic.List[object]]::new()
    $manifestItem = Get-Item -LiteralPath $manifestPath -Force
    $candidateFiles.Add([ordered]@{
        role = 'release-manifest'
        fileName = 'release-set.v2.json'
        relativePath = 'candidate/release-set.v2.json'
        sizeBytes = [int64]$manifestItem.Length
        sha256 = Get-Sha256 -Path $manifestPath
    })
    if ([string]$request.edition -ceq 'Enterprise') {
        $releaseKeyPath = Join-Path $candidateRoot 'release-public-key.v2.json'
        Write-CanonicalJson -Path $releaseKeyPath -Value ([ordered]@{
            keyId = [string]$request.releaseManifestTrust.keyId
            x = [string]$request.releaseManifestTrust.x
            y = [string]$request.releaseManifestTrust.y
        })
        $releaseKeyItem = Get-Item -LiteralPath $releaseKeyPath -Force
        $candidateFiles.Add([ordered]@{
            role = 'release-public-key'
            fileName = 'release-public-key.v2.json'
            relativePath = 'candidate/release-public-key.v2.json'
            sizeBytes = [int64]$releaseKeyItem.Length
            sha256 = Get-Sha256 -Path $releaseKeyPath
        })
    }
    $requestPayloadRoot = Join-Path `
        ([IO.Path]::GetDirectoryName($RequestPath)) `
        'payload'
    foreach ($definition in $artifactDefinitions) {
        $source = $definition.Source
        $artifactPath = Join-Path $candidateRoot ([string]$source.fileName)
        [IO.File]::Copy(
            (Join-Path $requestPayloadRoot ([string]$source.fileName)),
            $artifactPath,
            $false)
        $artifactItem = Get-Item -LiteralPath $artifactPath -Force
        $candidateFiles.Add([ordered]@{
            role = [string]$definition.Component
            fileName = [string]$source.fileName
            relativePath = 'candidate/' + [string]$source.fileName
            sizeBytes = [int64]$artifactItem.Length
            sha256 = Get-Sha256 -Path $artifactPath
        })
    }
    $response = [ordered]@{
        schemaVersion = 1
        responseType = 'ensou-dsh-launcher-manifest-publishing-response'
        orchestrationId = [string]$request.orchestrationId
        edition = [string]$request.edition
        releaseSetId = [string]$request.releaseSetId
        channel = [string]$request.channel
        planSha256 = [string]$request.planSha256
        requestSha256 = Get-Sha256 -Path $RequestPath
        requestNonce = [string]$request.requestNonce
        baseHeadSha256 = [string]$request.baseHeadSha256
        admissionHeadSha256 = $AdmissionHeadSha256
        admissionRevision = 4
        requestExpiresAtUtc = [string]$request.expiresAtUtc
        completedAtUtc = [DateTimeOffset]::UtcNow.ToUniversalTime().ToString(
            'yyyy-MM-ddTHH:mm:ssZ',
            [Globalization.CultureInfo]::InvariantCulture)
        files = $candidateFiles
        authentication = [ordered]@{
            algorithm = 'ES256'
            keyId = [string]$request.responseAuthentication.keyId
            purpose = 'manifest-publishing-response'
            payloadType =
                'ensou-dsh-launcher-manifest-publishing-response-authentication-v1'
        }
    }
    $payload = Get-ProductionReleaseManifestPublishingResponseAuthenticationPayload `
        -Response ([pscustomobject]$response)
    $signature = ConvertTo-LowSP256Signature -Signature ($Signer.SignData(
        $payload,
        [Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation))
    $response.authentication['value'] = ConvertTo-Base64Url -Bytes $signature
    $path = Join-Path $OutputRoot 'manifest-publishing-response.v1.json'
    Write-CanonicalJson -Path $path -Value $response
    return $path
}

function Invoke-TestPilotManifestFoundation {
    param(
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$Edition,
        [Parameter(Mandatory = $true)][string]$PlanPath,
        [Parameter(Mandatory = $true)][string]$StateRoot,
        [Parameter(Mandatory = $true)][string]$FixtureRoot,
        [Parameter(Mandatory = $true)][Security.Cryptography.ECDsa]$Signer,
        [Parameter(Mandatory = $true)][Security.Cryptography.ECDsa]$ReleaseSigner
    )

    $publisherInputPath = New-PublisherInputFixture `
        -PlanPath $PlanPath `
        -StateRoot $StateRoot `
        -OutputRoot (Join-Path $FixtureRoot 'publisher-input')
    $plan = Read-Json -Path $PlanPath
    $targetChannel = [string]$plan.targetChannel
    $phasePrefix = $targetChannel.ToUpperInvariant()
    $r3HeadSha256 = Get-Sha256 -Path (Join-Path $StateRoot 'head.json')
    [void](Invoke-Orchestrator `
        -ScriptPath $ScriptPath `
        -RepoRoot $RepoRoot `
        -Edition $Edition `
        -Phase PrepareManifestSigning `
        -PlanPath $PlanPath `
        -StateRoot $StateRoot `
        -PublisherInputPath $publisherInputPath `
        -ExpectedHeadSha256 $r3HeadSha256)
    $r4HeadSha256 = Get-Sha256 -Path (Join-Path $StateRoot 'head.json')
    [void](Invoke-Orchestrator `
        -ScriptPath $ScriptPath `
        -RepoRoot $RepoRoot `
        -Edition $Edition `
        -Phase PrepareManifestSigning `
        -PlanPath $PlanPath `
        -StateRoot $StateRoot `
        -PublisherInputPath $publisherInputPath `
        -ExpectedHeadSha256 $r3HeadSha256)
    Assert-True ((Get-Sha256 -Path (Join-Path $StateRoot 'head.json')) -ceq $r4HeadSha256) 'Exact target-channel manifest-request replay changed the admitted r4 head.'
    Assert-True (@(Get-ChildItem -LiteralPath (Join-Path $StateRoot 'receipts') -Force).Count -eq 4) 'Exact target-channel manifest-request replay appended a receipt.'
    $requestPath = Join-Path `
        (Join-Path (Join-Path $StateRoot 'requests') ($targetChannel + '-manifest-publishing.v1')) `
        'manifest-publishing-request.v1.json'
    $responsePath = New-ManifestPublishingResponseFixture `
        -RequestPath $requestPath `
        -AdmissionHeadSha256 $r4HeadSha256 `
        -OutputRoot (Join-Path $FixtureRoot 'signed-candidate-response') `
        -Signer $Signer `
        -ReleaseSigner $ReleaseSigner
    [void](Invoke-Orchestrator `
        -ScriptPath $ScriptPath `
        -RepoRoot $RepoRoot `
        -Edition $Edition `
        -Phase ImportSignedCandidate `
        -PlanPath $PlanPath `
        -StateRoot $StateRoot `
        -ResponsePath $responsePath `
        -ExpectedHeadSha256 $r4HeadSha256)
    $r5HeadSha256 = Get-Sha256 -Path (Join-Path $StateRoot 'head.json')
    [void](Invoke-Orchestrator `
        -ScriptPath $ScriptPath `
        -RepoRoot $RepoRoot `
        -Edition $Edition `
        -Phase ImportSignedCandidate `
        -PlanPath $PlanPath `
        -StateRoot $StateRoot `
        -ResponsePath $responsePath `
        -ExpectedHeadSha256 $r4HeadSha256)
    Assert-True ((Get-Sha256 -Path (Join-Path $StateRoot 'head.json')) -ceq $r5HeadSha256) 'Exact target-channel signed-candidate response replay changed the admitted r5 head.'
    Assert-True (@(Get-ChildItem -LiteralPath (Join-Path $StateRoot 'receipts') -Force).Count -eq 5) 'Exact target-channel signed-candidate response replay appended a receipt.'
    return [pscustomobject]@{
        PublisherInputPath = $publisherInputPath
        RequestPath = $requestPath
        ResponsePath = $responsePath
        R3HeadSha256 = $r3HeadSha256
        R4HeadSha256 = $r4HeadSha256
        R5HeadSha256 = $r5HeadSha256
        RequestPhase = $phasePrefix + '_MANIFEST_SIGNING_REQUESTED'
        CandidatePhase = $phasePrefix + '_SIGNED_CANDIDATE_IMPORTED'
    }
}

function Assert-ManifestFoundationFailurePreservesState {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$Edition,
        [Parameter(Mandatory = $true)][string]$Phase,
        [Parameter(Mandatory = $true)][string]$PlanPath,
        [Parameter(Mandatory = $true)][string]$StateRoot,
        [string]$PublisherInputPath = '',
        [string]$ResponsePath = '',
        [string]$ExpectedHeadSha256 = '',
        [string]$ExpectedMessage = ''
    )

    $before = Get-StateTreeSnapshot -Path $StateRoot
    [void](Invoke-Orchestrator `
        -ScriptPath $ScriptPath `
        -RepoRoot $RepoRoot `
        -Edition $Edition `
        -Phase $Phase `
        -PlanPath $PlanPath `
        -StateRoot $StateRoot `
        -PublisherInputPath $PublisherInputPath `
        -ResponsePath $ResponsePath `
        -ExpectedHeadSha256 $ExpectedHeadSha256 `
        -ExpectFailure `
        -ExpectedMessage $ExpectedMessage)
    Assert-True ((Get-StateTreeSnapshot -Path $StateRoot) -ceq $before) `
        "$Label changed production state inventory or bytes."
}

function Assert-NoManifestFoundationStaging {
    param(
        [Parameter(Mandatory = $true)][string]$StateParent,
        [Parameter(Mandatory = $true)][string]$OrchestrationId,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $operationId = ([Guid]::Parse($OrchestrationId)).ToString('N')
    foreach ($purpose in @('manifest-request', 'manifest-import')) {
        $prefix = ".ensou-launcher-production-staging-$operationId-$purpose-"
        Assert-True (@(
                Get-ChildItem `
                    -LiteralPath $StateParent `
                    -Directory `
                    -Force `
                    -Filter ($prefix + '*')
            ).Count -eq 0) "$Label left $purpose staging residue."
    }
}

function Assert-StateFailure {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][string]$SourceState,
        [Parameter(Mandatory = $true)][scriptblock]$Mutate,
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$PlanPath,
        [Parameter(Mandatory = $true)][string]$VariantRoot
    )

    $negativeTimer = [Diagnostics.Stopwatch]::StartNew()
    Write-Host "NEGATIVE-START $Label"
    try {
        Copy-State -Source $SourceState -Destination $VariantRoot
        & $Mutate $VariantRoot
        [void](Invoke-Orchestrator -ScriptPath $ScriptPath -RepoRoot $RepoRoot -Edition Personal -Phase Status -PlanPath $PlanPath -StateRoot $VariantRoot -ExpectFailure)
        Write-Output "NEGATIVE-PASS $Label"
    }
    finally {
        $negativeTimer.Stop()
        Write-Host "NEGATIVE-END $Label elapsedMs=$($negativeTimer.ElapsedMilliseconds)"
    }
}

function Assert-FrozenV1StateReplay {
    param(
        [Parameter(Mandatory = $true)][string]$FixtureRoot,
        [Parameter(Mandatory = $true)][string]$PlanSchemaPath,
        [Parameter(Mandatory = $true)][string]$StateSchemaPath
    )

    $documents = [ordered]@{
        'plan.json' = [pscustomobject]@{
            Sha256 = '4f3ec494f30fecff3cffb0024966607ad644927f2e31044f419063c11fd05c02'
            Json = '{"schemaVersion":1,"planType":"ensou-dsh-launcher-production-release","orchestrationId":"11111111-1111-4111-8111-111111111111","edition":"Personal","releaseSetId":"frozen-v1-replay","channel":"pilot","sourceCommit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","manifestUri":"https://updates.example.invalid/v2/channels/pilot/release-set.v2.json","artifactBaseUri":"https://artifacts.example.invalid/launcher/","runtimeCandidate":{"releaseId":"frozen-v1-runtime","githubReleaseTag":"frozen-v1-runtime","archive":{"fileName":"runtime.zip","path":"C:\\frozen\\runtime.zip","sizeBytes":201,"sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},"metadata":{"fileName":"runtime.metadata.json","path":"C:\\frozen\\runtime.metadata.json","sizeBytes":202,"sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"},"hashEvidence":{"fileName":"runtime.sha256","path":"C:\\frozen\\runtime.sha256","sizeBytes":203,"sha256":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}},"authenticodePolicy":{"signerSha256Thumbprint":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","requireTrustedTimestamp":true,"maximumResponseAgeMinutes":120},"externalResponseTrust":{"algorithm":"ES256","keyId":"frozen-v1-response","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","y":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"},"clientSigningInputs":[{"role":"personal-x64","fileName":"EnsouLauncher.Personal.x64.exe","path":"C:\\frozen\\EnsouLauncher.Personal.x64.exe","sizeBytes":101,"sha256":"1111111111111111111111111111111111111111111111111111111111111111","peContentSha256":"5555555555555555555555555555555555555555555555555555555555555555"},{"role":"personal-arm64","fileName":"EnsouLauncher.Personal.arm64.exe","path":"C:\\frozen\\EnsouLauncher.Personal.arm64.exe","sizeBytes":102,"sha256":"2222222222222222222222222222222222222222222222222222222222222222","peContentSha256":"6666666666666666666666666666666666666666666666666666666666666666"},{"role":"enterprise-x64","fileName":"EnsouLauncher.Enterprise.x64.exe","path":"C:\\frozen\\EnsouLauncher.Enterprise.x64.exe","sizeBytes":103,"sha256":"3333333333333333333333333333333333333333333333333333333333333333","peContentSha256":"7777777777777777777777777777777777777777777777777777777777777777"},{"role":"enterprise-arm64","fileName":"EnsouLauncher.Enterprise.arm64.exe","path":"C:\\frozen\\EnsouLauncher.Enterprise.arm64.exe","sizeBytes":104,"sha256":"4444444444444444444444444444444444444444444444444444444444444444","peContentSha256":"8888888888888888888888888888888888888888888888888888888888888888"}]}'
        }
        'identity.json' = [pscustomobject]@{
            Sha256 = 'ea0e2c0ae7c0317db3835cfaad6ccb6b850404cc60d56b5297a78005ad6af258'
            Json = '{"schemaVersion":1,"identityType":"ensou-dsh-launcher-production-release-state","orchestrationId":"11111111-1111-4111-8111-111111111111","edition":"Personal","planSha256":"4f3ec494f30fecff3cffb0024966607ad644927f2e31044f419063c11fd05c02","createdAtUtc":"2026-08-29T00:00:00Z"}'
        }
        'receipts\0001-plan-admitted.json' = [pscustomobject]@{
            Sha256 = '9d7f46f607e078b34f99c0b669334b3798c9b11489ed8f9b6ac120d0bdc84607'
            Json = '{"schemaVersion":1,"receiptType":"ensou-dsh-launcher-production-release-transition","orchestrationId":"11111111-1111-4111-8111-111111111111","edition":"Personal","planSha256":"4f3ec494f30fecff3cffb0024966607ad644927f2e31044f419063c11fd05c02","identitySha256":"ea0e2c0ae7c0317db3835cfaad6ccb6b850404cc60d56b5297a78005ad6af258","revision":1,"phase":"PLAN_ADMITTED","previousReceiptSha256":"0000000000000000000000000000000000000000000000000000000000000000","transitionSha256":"d05aca9b55ec60d2f5ff6c847bded97963e724905e96a6f050c6f5d475b5e9c0","data":{"releaseSetId":"frozen-v1-replay","channel":"pilot","sourceCommit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sourceTree":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","manifestUri":"https://updates.example.invalid/v2/channels/pilot/release-set.v2.json","artifactBaseUri":"https://artifacts.example.invalid/launcher/","runtimeCandidate":{"releaseId":"frozen-v1-runtime","githubReleaseTag":"frozen-v1-runtime","archiveSha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","metadataSha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","hashEvidenceSha256":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","localMetadataPromotionEligible":true,"publicationStatus":"IMMUTABLE_SOURCE_RELEASE_UNVERIFIED"},"clientInputs":[{"role":"personal-x64","fileName":"EnsouLauncher.Personal.x64.exe","sizeBytes":101,"sha256":"1111111111111111111111111111111111111111111111111111111111111111","peContentSha256":"5555555555555555555555555555555555555555555555555555555555555555"},{"role":"personal-arm64","fileName":"EnsouLauncher.Personal.arm64.exe","sizeBytes":102,"sha256":"2222222222222222222222222222222222222222222222222222222222222222","peContentSha256":"6666666666666666666666666666666666666666666666666666666666666666"},{"role":"enterprise-x64","fileName":"EnsouLauncher.Enterprise.x64.exe","sizeBytes":103,"sha256":"3333333333333333333333333333333333333333333333333333333333333333","peContentSha256":"7777777777777777777777777777777777777777777777777777777777777777"},{"role":"enterprise-arm64","fileName":"EnsouLauncher.Enterprise.arm64.exe","sizeBytes":104,"sha256":"4444444444444444444444444444444444444444444444444444444444444444","peContentSha256":"8888888888888888888888888888888888888888888888888888888888888888"}]},"recordedAtUtc":"2026-08-29T00:00:01Z"}'
        }
        'head.json' = [pscustomobject]@{
            Sha256 = 'd3d11c7dd85b1d00b31c6fa84c8f4ec70fc4e731aae2be5248325bd350d1bc54'
            Json = '{"schemaVersion":1,"stateType":"ensou-dsh-launcher-production-release-head","orchestrationId":"11111111-1111-4111-8111-111111111111","edition":"Personal","planSha256":"4f3ec494f30fecff3cffb0024966607ad644927f2e31044f419063c11fd05c02","identitySha256":"ea0e2c0ae7c0317db3835cfaad6ccb6b850404cc60d56b5297a78005ad6af258","revision":1,"phase":"PLAN_ADMITTED","receiptFileName":"0001-plan-admitted.json","receiptSha256":"9d7f46f607e078b34f99c0b669334b3798c9b11489ed8f9b6ac120d0bdc84607","updatedAtUtc":"2026-08-29T00:00:01Z"}'
        }
    }

    foreach ($directoryName in @('receipts', 'requests', 'imports')) {
        [IO.Directory]::CreateDirectory((Join-Path $FixtureRoot $directoryName)) | Out-Null
    }
    foreach ($entry in $documents.GetEnumerator()) {
        $bytes = $utf8.GetBytes([string]$entry.Value.Json)
        Assert-True ((Get-ProductionSha256Bytes -Bytes $bytes) -ceq [string]$entry.Value.Sha256) "Frozen pre-v2 fixture bytes drifted for $($entry.Key)."
        [IO.File]::WriteAllBytes((Join-Path $FixtureRoot ([string]$entry.Key)), $bytes)
    }
    Assert-True (Test-Json -Json ([string]$documents['plan.json'].Json) -SchemaFile $PlanSchemaPath -ErrorAction Stop) 'Frozen pre-v2 plan snapshot no longer satisfies plan v1.'
    $summary = Get-ProductionReleaseStateSummary -StateRoot $FixtureRoot -StateSchemaPath $StateSchemaPath
    Assert-True ([int]$summary.SchemaVersion -eq 1 -and [int]$summary.Revision -eq 1 -and [string]$summary.Phase -ceq 'PLAN_ADMITTED') 'Frozen pre-v2 state/status replay changed revision or phase.'
    Assert-True ([string]$summary.TargetChannel -ceq 'pilot' -and [string]$summary.PlanSha256 -ceq [string]$documents['plan.json'].Sha256) 'Frozen pre-v2 state/status replay changed its v1 plan binding.'
    Assert-True ([string]$summary.HeadSha256 -ceq [string]$documents['head.json'].Sha256) 'Frozen pre-v2 state/status replay changed head bytes.'
    Assert-True ([string]$summary.NextPhase -ceq 'CLIENT_SIGNING_REQUESTED') 'Frozen pre-v2 state/status replay changed the v1 next phase.'
    Assert-True ([string]$summary.NoGoCode -ceq 'IMMUTABLE_SOURCE_RELEASE_UNVERIFIED') 'Frozen pre-v2 state/status replay changed the v1 NO-GO contract.'
    Assert-True (-not [bool]$summary.PilotReady -and -not [bool]$summary.StableReady -and -not [bool]$summary.LifecycleTerminal) 'Frozen pre-v2 state/status replay claimed v2 readiness or terminal state.'
}

& (Join-Path $PSScriptRoot 'Test-ProductionReleaseDirectoryLease.ps1')

$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) ('ensou-launcher-production-orchestration-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($fixtureRoot) | Out-Null
$responseSigner = [Security.Cryptography.ECDsa]::Create(
    [Security.Cryptography.ECCurve+NamedCurves]::nistP256)
$manifestResponseSigner = [Security.Cryptography.ECDsa]::Create(
    [Security.Cryptography.ECCurve+NamedCurves]::nistP256)
$productRoleFixture = $null
$releaseManifestSigner = $null
$codeSigningFixture = $null
$timestampSigningFixture = $null
try {
    $releaseManifestSigner = if ($useProductRoleFixture) {
        Import-Module (Join-Path $PSScriptRoot 'ProductRoleFixtures.psm1') -Force
        $productRoleFixture = Import-ProductRoleFixtureContract `
            -FixtureRoot $ProductRoleFixtureRoot `
            -ManifestPath $ProductRoleFixtureManifestPath `
            -ReleaseManifestKeyPath $ReleaseManifestTestKeyPath `
            -DestinationRoot (Join-Path $fixtureRoot 'product-role-fixture-private-copy')
        $script:ProductRoleFixtureContract = $productRoleFixture
        $productRoleFixture.ReleaseManifestSigner
    }
    else {
        [Security.Cryptography.ECDsa]::Create(
            [Security.Cryptography.ECCurve+NamedCurves]::nistP256)
    }
    $pilotStableAdr = [IO.File]::ReadAllText(
        (Join-Path $RepositoryRoot 'docs\adr\0006-pilot-stable-production-orchestration.md'),
        [Text.UTF8Encoding]::new($false, $true))
    foreach ($requiredAdrContract in @(
            'Plan v2 deliberately has no Pilot-to-Stable continuation.',
            'targetChannel: stable',
            'There is no second manifest.',
            'Enterprise permits only',
            'PersonalReleaseSetValidator',
            'EnterpriseReleaseSetValidator',
            'PersonalDistributionCertification',
            'must never be relabeled')) {
        Assert-True ($pilotStableAdr.Contains($requiredAdrContract, [StringComparison]::Ordinal)) "ADR 0006 lost its direct-target v2 contract: $requiredAdrContract"
    }
    $sourceRepo = Join-Path $fixtureRoot 'launcher-repo'
    [IO.Directory]::CreateDirectory($sourceRepo) | Out-Null
    $trackedFiles = @(
        'release/scripts/Invoke-LauncherProductionRelease.ps1',
        'release/scripts/ProductionReleaseState.psm1',
        'release/scripts/ProductionReleaseProbeProcess.cs',
        'src/Ensou.Dsh.Host/WindowsJobObject.cs',
        'release/scripts/PersonalProductionReleaseAdapter.psm1',
        'release/scripts/EnterpriseProductionReleaseAdapter.psm1',
        'release/scripts/New-EnterpriseProductionPilotEvidenceInput.ps1',
        'release/scripts/EnterpriseProductionPilotEvidence.psm1',
        'release/scripts/CertifiedDistributionInput.ps1',
        'release/scripts/InstallerSigningContracts.psm1',
        'release/scripts/PersonalInstallerTrustedBuild.psm1',
        'release/scripts/PersonalInstallerSigningPipeline.psm1',
        'release/scripts/PersonalInstallerProductionPayloadSelfCheck.psm1',
        'release/scripts/ProductionBoundedProcess.psm1',
        'release/scripts/EnterpriseInstallerTrustedBuild.psm1',
        'release/scripts/ProductionFeedPromotion.psm1',
        'release/scripts/PersonalFeedPromotionResult.psm1',
        'release/scripts/PersonalFeedExecutionResultProducer.psm1',
        'release/scripts/EnterpriseStablePublicationResult.psm1',
        'release/schemas/enterprise-stable-publication-context-v1.schema.json',
        'release/schemas/enterprise-stable-publication-result-v1.schema.json',
        'release/schemas/enterprise-stable-publication-statement-v1.schema.json',
        'release/schemas/personal-feed-execution-result-v1.schema.json',
        'release/scripts/PortableDotNetSdkClosure.psm1',
        'release/locks/dotnet-sdk-10.0.302-win-x64.files.lock.json',
        'scripts/EnterpriseProductionPayload.psm1',
        'release/scripts/Test-SourceRuntimeMetadata.ps1',
        'release/schemas/launcher-production-release-plan-v1.schema.json',
        'release/schemas/launcher-production-release-plan-v2.schema.json',
        'release/schemas/launcher-external-signing-request-v1.schema.json',
        'release/schemas/launcher-external-signing-response-v1.schema.json',
        'release/schemas/launcher-production-publisher-input-v1.schema.json',
        'release/schemas/launcher-manifest-publishing-request-v1.schema.json',
        'release/schemas/launcher-manifest-publishing-response-v1.schema.json',
        'release/schemas/launcher-installer-signing-request-v1.schema.json',
        'release/schemas/launcher-installer-signing-request-v2.schema.json',
        'release/schemas/personal-installer-signing-request-v2.schema.json',
        'release/schemas/personal-installer-signing-response-v2.schema.json',
        'release/schemas/personal-installer-trusted-build-evidence-v1.schema.json',
        'release/schemas/personal-installer-production-payload-self-check-result-v1.schema.json',
        'release/schemas/personal-installer-production-payload-self-check-evidence-v1.schema.json',
        'release/schemas/launcher-enterprise-installer-signing-request-v2.schema.json',
        'release/schemas/launcher-installer-signing-response-v1.schema.json',
        'release/schemas/enterprise-installer-trusted-build-evidence-v1.schema.json',
        'release/schemas/enterprise-production-pilot-evidence-input-v1.schema.json',
        'release/schemas/enterprise-production-pilot-evidence-trust-v1.schema.json',
        'release/schemas/enterprise-windows-pilot-evidence-envelope-v2.schema.json',
        'release/schemas/enterprise-windows-pilot-evidence-body-v2.schema.json',
        'release/schemas/enterprise-windows-pilot-verification-report-v2.schema.json',
        'release/schemas/enterprise-pilot-readiness-v1.schema.json',
        'release/schemas/enterprise-pilot-readiness-report-v1.schema.json',
        'release/schemas/enterprise-pilot-readiness-v2.schema.json',
        'release/schemas/enterprise-pilot-readiness-report-v2.schema.json',
        'release/schemas/enterprise-local-data-compatibility-certification-receipt-v1.schema.json',
        'release/schemas/enterprise-production-stable-private-pilot-observation-v1.schema.json',
        'release/schemas/enterprise-windows-pilot-gate-contract-v2.schema.json',
        'release/schemas/launcher-feed-promotion-request-v1.schema.json',
        'release/schemas/launcher-feed-promotion-response-v1.schema.json',
        'release/schemas/launcher-feed-promotion-state-v1.schema.json',
        'release/schemas/launcher-feed-promotion-admission-v1.schema.json',
        'release/enterprise-windows-pilot-gate-contract-v2.json',
        'release/schemas/launcher-release-manifest-trust-probe-v1.schema.json',
        'release/schemas/launcher-production-release-state-v1.schema.json',
        'release/schemas/launcher-production-release-state-v2.schema.json',
        'release/schemas/source-runtime-metadata.schema.json',
        'release/schemas/enterprise-direct-local-source-runtime-metadata.schema.json',
        'installer/personal-publish-runtime-packs.lock.json'
    )
    foreach ($relativePath in $trackedFiles) {
        $destination = Join-Path $sourceRepo $relativePath.Replace('/', [IO.Path]::DirectorySeparatorChar)
        [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($destination)) | Out-Null
        [IO.File]::Copy(
            (Join-Path $RepositoryRoot $relativePath.Replace('/', [IO.Path]::DirectorySeparatorChar)),
            $destination,
            $false)
    }
    [void](Invoke-Git -Root $sourceRepo -Arguments @('init', '--quiet'))
    [void](Invoke-Git -Root $sourceRepo -Arguments @(
        'config', '--local', 'core.autocrlf', 'false'))
    [void](Invoke-Git -Root $sourceRepo -Arguments @('config', 'user.email', 'launcher-test@ensou.invalid'))
    [void](Invoke-Git -Root $sourceRepo -Arguments @('config', 'user.name', 'ensou-launcher-test'))
    [void](Invoke-Git -Root $sourceRepo -Arguments @('add', '--all'))
    [void](Invoke-Git -Root $sourceRepo -Arguments @('commit', '--quiet', '-m', 'production orchestration fixture'))
    $commit = [string]@(Invoke-Git -Root $sourceRepo -Arguments @('rev-parse', 'HEAD'))[0]
    $orchestrator = Join-Path $sourceRepo 'release\scripts\Invoke-LauncherProductionRelease.ps1'
    $orchestratorText = [IO.File]::ReadAllText($orchestrator, [Text.UTF8Encoding]::new($false, $true))
    Assert-True (-not $orchestratorText.Contains('Get-AuthenticodeSignature -LiteralPath $locked.Path', [StringComparison]::Ordinal)) 'Authenticode regressed to the caller-controlled locked-input path namespace.'
    Assert-True ($orchestratorText.Contains('Get-AuthenticodeSignature -LiteralPath $verificationSnapshot.Path', [StringComparison]::Ordinal)) 'Authenticode is not bound to a private locked verification snapshot.'
    Assert-True ($orchestratorText.Contains('-MetadataPath $runtimeMetadataSnapshot.Path -ArtifactPath $runtimeArchiveSnapshot.Path', [StringComparison]::Ordinal)) 'Runtime metadata validation is not bound to private locked verification snapshots.'
    Assert-True ($orchestratorText.Contains('Production state contains a stale or unexpected path-verification workspace.', [StringComparison]::Ordinal)) 'Path-verification crash residue is not fail-closed.'
    $orchestratorTokens = $null
    $orchestratorParseErrors = $null
    $orchestratorAst = [Management.Automation.Language.Parser]::ParseFile(
        $orchestrator,
        [ref]$orchestratorTokens,
        [ref]$orchestratorParseErrors)
    Assert-True ($orchestratorParseErrors.Count -eq 0) 'Production orchestrator did not parse for atomic-publication source contracts.'
    $requiredFeedPromotionBootstrapFiles = @(
        'release/scripts/ProductionFeedPromotion.psm1',
        'release/scripts/PersonalFeedPromotionResult.psm1',
        'release/scripts/PersonalFeedExecutionResultProducer.psm1',
        'release/scripts/EnterpriseStablePublicationResult.psm1',
        'release/schemas/enterprise-stable-publication-context-v1.schema.json',
        'release/schemas/enterprise-stable-publication-result-v1.schema.json',
        'release/schemas/enterprise-stable-publication-statement-v1.schema.json',
        'release/schemas/personal-feed-execution-result-v1.schema.json',
        'release/schemas/launcher-feed-promotion-request-v1.schema.json',
        'release/schemas/launcher-feed-promotion-response-v1.schema.json',
        'release/schemas/launcher-feed-promotion-state-v1.schema.json',
        'release/schemas/launcher-feed-promotion-admission-v1.schema.json')
    foreach ($relativePath in $requiredFeedPromotionBootstrapFiles) {
        Assert-True `
            ($trackedFiles -ccontains $relativePath -and
             (Test-Path -LiteralPath (
                    Join-Path $sourceRepo $relativePath.Replace(
                        '/',
                        [IO.Path]::DirectorySeparatorChar)) `
                -PathType Leaf)) `
            "Temporary orchestration checkout omitted feed-promotion bootstrap input '$relativePath'."
    }
    $orchestratorParameterNames = @(
        $orchestratorAst.ParamBlock.Parameters |
            ForEach-Object { [string]$_.Name.VariablePath.UserPath })
    foreach ($parameterName in @(
            'PromotionRoot',
            'FeedPromotionResponsePath',
            'ExpectedFeedIdentitySha256',
            'ExpectedChannelHead',
            'ExpectedJournalHead')) {
        Assert-True `
            (@($orchestratorParameterNames | Where-Object {
                        $_ -ceq $parameterName
                    }).Count -eq 1) `
            "Production orchestrator lost exact feed-promotion parameter '$parameterName'."
    }
    Assert-ProductionFeedPromotionAstContracts -OrchestratorAst $orchestratorAst
    $stableAdmissionFunctions = @($orchestratorAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'New-StableFeedPromotionStateAdmissionValue'
    }, $true))
    Assert-True `
        ($stableAdmissionFunctions.Count -eq 1) `
        'Production orchestrator lost its single Stable feed-promotion admission builder.'
    $stableAdmissionText = [string]$stableAdmissionFunctions[0].Extent.Text
    Assert-True `
        ($stableAdmissionText.Contains(
            "productionAdmission = 'NO_GO'",
            [StringComparison]::Ordinal) -and
         $stableAdmissionText.Contains(
            'networkPublishPerformed = $false',
            [StringComparison]::Ordinal) -and
         -not $stableAdmissionText.Contains(
            'STABLE_FEED_PROMOTED',
            [StringComparison]::Ordinal)) `
        'R9 state admission must remain NO_GO, offline-only, and must not claim r10 Stable-feed promotion.'
    $trustProbeFunctions = @($orchestratorAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Invoke-ReleaseManifestTrustProbe'
    }, $true))
    Assert-True ($trustProbeFunctions.Count -eq 1) 'Production orchestrator lost its single release-manifest trust probe helper.'
    $trustProbeText = [string]$trustProbeFunctions[0].Extent.Text
    $nativeProbeCalls = @($trustProbeFunctions[0].FindAll({
        param($node)
        $node -is [Management.Automation.Language.InvokeMemberExpressionAst] -and
            $node.Static -and $node.Member.Value -ceq 'Execute'
    }, $true))
    Assert-True ($nativeProbeCalls.Count -eq 1) 'Release trust probe must call its single native facade once.'
    $nativeProbeCall = $nativeProbeCalls[0]
    Assert-True ($nativeProbeCall.Expression.Extent.Text -ceq '$probeProcessType' -and $nativeProbeCall.Arguments.Count -eq 3) 'Release trust probe must use its admitted runtime type and exact three-argument facade.'
    Assert-True ($nativeProbeCall.Arguments[0].Extent.Text -ceq '$ExecutablePath' -and $nativeProbeCall.Arguments[1].Extent.Text -ceq '$VerificationSnapshot.Stream.SafeFileHandle') 'Release trust probe lost its exact executable and expected-image identity handle.'
    Assert-True ($nativeProbeCall.Arguments[2].Extent.Text -ceq "([string]`$Plan.edition -ceq 'Personal')") 'Release trust probe must derive the fixed machine protocol only from the exact plan edition.'
    Assert-True (-not $trustProbeText.Contains('ENSOU_DSH_PERSONAL_BINARY_SELF_CHECK_PROTOCOL', [StringComparison]::Ordinal) -and -not $trustProbeText.Contains('ArgumentList', [StringComparison]::Ordinal)) 'Orchestrator must not append arguments or override the fixed native machine protocol.'
    $probeFacadeText = [IO.File]::ReadAllText((Join-Path $sourceRepo 'release/scripts/ProductionReleaseProbeProcess.cs')).Replace("`r`n", "`n")
    $facadeProtocolContract = @'
        if (personal)
        {
            startInfo.Environment["ENSOU_DSH_PERSONAL_BINARY_SELF_CHECK_PROTOCOL"] =
                "ensou-personal-binary-self-check/v1";
            startInfo.ArgumentList.Add("--binary-self-check");
        }
        else
        {
            startInfo.ArgumentList.Add("--release-manifest-trust-probe");
        }
'@
    Assert-True ($probeFacadeText.Contains($facadeProtocolContract.Replace("`r`n", "`n"), [StringComparison]::Ordinal)) 'Native release probe must retain its two exclusive fixed machine protocols.'
    Assert-True (($probeFacadeText.Split('ArgumentList.Add(', [StringSplitOptions]::None).Count - 1) -eq 2 -and ($probeFacadeText.Split('ENSOU_DSH_PERSONAL_BINARY_SELF_CHECK_PROTOCOL', [StringSplitOptions]::None).Count - 1) -eq 1) 'Native release probe added arguments or duplicated the Personal protocol injection.'
    Assert-True ($probeFacadeText.IndexOf('startInfo.Environment.Clear();', [StringComparison]::Ordinal) -ge 0 -and $probeFacadeText.IndexOf('startInfo.Environment.Clear();', [StringComparison]::Ordinal) -lt $probeFacadeText.IndexOf($facadeProtocolContract.Replace("`r`n", "`n"), [StringComparison]::Ordinal)) 'Native release probe must clear inherited environment before its fixed child-only protocol.'
    $completionFunctions = @($orchestratorAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Complete-ProductionBundleAfterCheckoutAdmission'
    }, $true))
    Assert-True ($completionFunctions.Count -eq 1) 'Production orchestrator lost its single checkout-admitted bundle completion helper.'
    $completionText = [string]$completionFunctions[0].Extent.Text
    $completionCheckoutIndex = $completionText.IndexOf(
        'Assert-LauncherSourceCheckout',
        [StringComparison]::Ordinal)
    $completionMoveIndex = $completionText.IndexOf(
        '[IO.Directory]::Move',
        [StringComparison]::Ordinal)
    Assert-True ($completionCheckoutIndex -ge 0 -and $completionMoveIndex -gt $completionCheckoutIndex) 'Atomic bundle completion no longer performs final checkout admission immediately before its move.'
    $completionCalls = @($orchestratorAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.CommandAst] -and
            $node.GetCommandName() -ceq 'Complete-ProductionBundleAfterCheckoutAdmission'
    }, $true))
    $completionCallContracts = @(
        @{ Name = 'Personal r9 completed result'; Function = 'Invoke-PersonalPilotCompletedResultImport'; RelativeBundlePath = "'pilot-feed-result.v1'"; DestinationParent = "(Join-Path `$state.StateRoot 'imports')"; RequiredArgument = '-AllowExisting' },
        @{ Name = 'Personal r8 request seal'; Function = 'Invoke-PersonalPilotFeedPromotionPhase'; RelativeBundlePath = "'pilot-feed-promotion.v1'"; DestinationParent = "(Join-Path `$writerState.StateRoot 'requests')"; RequiredArgument = '-AllowExisting' },
        @{ Name = 'Enterprise r10 authenticated publication result'; Function = 'Invoke-EnterpriseStableCompletedPublication'; RelativeBundlePath = "'stable-feed-result.v1'"; DestinationParent = "(Join-Path `$state.StateRoot 'imports')"; RequiredArgument = '-AllowExisting:$existingResult' },
        @{ Name = 'legacy client-signing request'; Function = ''; RelativeBundlePath = "'requests\client-signing.v1'"; DestinationParent = "(Join-Path `$stateLock.StateRoot 'requests')"; RequiredArgument = '' },
        @{ Name = 'legacy client-signing import'; Function = ''; RelativeBundlePath = "'imports\client-signing.v1'"; DestinationParent = "(Join-Path `$stateLock.StateRoot 'imports')"; RequiredArgument = '-AllowExisting:$importAlreadyPublished' },
        @{ Name = 'legacy target-channel manifest request'; Function = ''; RelativeBundlePath = "'requests\' + [string]`$manifestChannelContract.RequestBundleName"; DestinationParent = "(Join-Path `$stateLock.StateRoot 'requests')"; RequiredArgument = '-AllowExisting:$requestAlreadyPublished' },
        @{ Name = 'legacy target-channel signed-candidate import'; Function = ''; RelativeBundlePath = "'imports\' + [string]`$manifestChannelContract.CandidateBundleName"; DestinationParent = "(Join-Path `$stateLock.StateRoot 'imports')"; RequiredArgument = '-AllowExisting:$importAlreadyPublished' }
    )
    Assert-True ($completionCalls.Count -eq $completionCallContracts.Count) 'Checkout-admitted completion calls no longer match the exact legacy, Personal r8/r9, and Enterprise r10 mapping.'
    foreach ($contract in $completionCallContracts) {
        $matches = @($completionCalls | Where-Object {
            $callText = [string]$_.Extent.Text
            $callText.Contains($contract.RelativeBundlePath, [StringComparison]::Ordinal) -and
            $callText.Contains($contract.DestinationParent, [StringComparison]::Ordinal) -and
            ([string]::IsNullOrEmpty($contract.RequiredArgument) -or
             $callText.Contains($contract.RequiredArgument, [StringComparison]::Ordinal))
        })
        Assert-True ($matches.Count -eq 1) "Checkout-admitted completion is missing or duplicated for $($contract.Name)."
        if (-not [string]::IsNullOrEmpty($contract.Function)) {
            $function = @($orchestratorAst.FindAll({
                param($node)
                $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                    $node.Name -ceq $contract.Function
            }.GetNewClosure(), $true))
            Assert-True ($function.Count -eq 1 -and
                $matches[0].Extent.StartOffset -ge $function[0].Extent.StartOffset -and
                $matches[0].Extent.EndOffset -le $function[0].Extent.EndOffset) "Checkout-admitted completion for $($contract.Name) escaped its exact lifecycle function."
        }
    }
    $personalResultFunctions = @($orchestratorAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Invoke-PersonalPilotCompletedResultImport'
    }, $true))
    Assert-True ($personalResultFunctions.Count -eq 1) 'Personal r9 completed-result import entry is missing or duplicated.'
    $personalResultCompletionCalls = @($personalResultFunctions[0].FindAll({
        param($node)
        $node -is [Management.Automation.Language.CommandAst] -and
            $node.GetCommandName() -ceq 'Complete-ProductionBundleAfterCheckoutAdmission'
    }, $true))
    Assert-True ($personalResultCompletionCalls.Count -eq 1) 'Personal r9 completed-result import must use exactly one checkout-admitted bundle completion.'
    $validatedCompletionFunctions = @($orchestratorAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq
                'Complete-ValidatedProductionBundleAfterCheckoutAdmission'
    }, $true))
    Assert-True ($validatedCompletionFunctions.Count -eq 1) 'Production orchestrator lost its single identity-bound validated bundle completion helper.'
    $validatedCompletionText =
        [string]$validatedCompletionFunctions[0].Extent.Text
    foreach ($boundaryContract in @(
            'Open-ProductionReleaseDirectoryMoveLease',
            'Move-ProductionReleaseDirectoryLease',
            'Assert-ProductionBundleAdmissionMatchesPins',
            'Assert-ProductionBundleAdmissionStillLocked',
            'PublicationDirectoryLease',
            '.ensou-launcher-production-rejected-')) {
        Assert-True `
            ($validatedCompletionText.Contains(
                $boundaryContract,
                [StringComparison]::Ordinal)) `
            "Validated bundle completion lost '$boundaryContract'."
    }
    $validatedCompletionCalls = @($orchestratorAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.CommandAst] -and
            $node.GetCommandName() -ceq
                'Complete-ValidatedProductionBundleAfterCheckoutAdmission'
    }, $true))
    Assert-True ($validatedCompletionCalls.Count -eq 6) 'Personal r6/r7, Enterprise r6/r7, Pilot r8, and Stable r9 do not all use identity-bound validated completion.'
    foreach ($validatedCompletionCall in $validatedCompletionCalls) {
        $validatedCallText = [string]$validatedCompletionCall.Extent.Text
        foreach ($requiredArgument in @(
                '-PostWaitAdmission',
                '-ExpectedPins',
                '-OpenFinalAdmission',
                '-ExpectedPreMoveFaultPoint')) {
            Assert-True `
                ($validatedCallText.Contains(
                    $requiredArgument,
                    [StringComparison]::Ordinal)) `
                "Validated bundle completion call lost '$requiredArgument'."
        }
    }
    foreach ($r8WiringContract in @(
            'New-EnterpriseProductionPilotEvidenceInput.ps1',
            'Assert-EnterpriseProductionPilotEvidenceInputBinding',
            "-Phase 'PILOT_EVIDENCE_BOUND'",
            "-Purpose pilot-evidence-import",
            'imports/pilot-evidence.v1/pilot-evidence-input.v1.json',
            'AfterPilotEvidenceBundle',
            'AfterPilotEvidenceReceipt')) {
        Assert-True `
            ($orchestratorText.Contains(
                $r8WiringContract,
                [StringComparison]::Ordinal)) `
            "Enterprise r8 orchestration wiring is missing '$r8WiringContract'."
    }
    foreach ($r8RecoveryContract in @(
            'Add-ProductionBundlePublicationLease',
            'Move-RejectedEnterprisePilotEvidenceCanonical',
            'R8_ORPHAN_CANONICAL_QUARANTINED',
            'R8_ORPHAN_LEDGER_RESTART_REQUIRED',
            '-RequireCommittedR8Receipt',
            '-PreCommitValidation $pilotPreCommitValidation',
            "-Label 'Exact Enterprise Pilot-evidence crash-recovery canonical'",
            "-Label 'Expired Enterprise Pilot-evidence canonical'",
            'Retry with nine fresh evidence inputs.')) {
        Assert-True `
            ($orchestratorText.Contains(
                $r8RecoveryContract,
                [StringComparison]::Ordinal)) `
            "Enterprise r8 recovery lost '$r8RecoveryContract'."
    }
    Assert-True `
        (-not $orchestratorText.Contains(
            'Published Enterprise Pilot-evidence recovery bundle',
            [StringComparison]::Ordinal)) `
        'Enterprise r8 retained its unsafe path-only canonical recovery branch.'
    $bindPilotEvidenceBranches = @($orchestratorAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.IfStatementAst] -and
            [string]$node.Extent.Text -like
                '*$requiredPilotEvidencePaths*' -and
            [string]$node.Extent.Text -like '*PILOT_EVIDENCE_BOUND*'
    }, $true))
    Assert-True `
        ($bindPilotEvidenceBranches.Count -eq 1) `
        'Enterprise r8 BindPilotEvidence implementation is missing or ambiguous.'
    $bindPilotEvidenceText =
        [string]$bindPilotEvidenceBranches[0].Extent.Text
    Assert-True `
        ($bindPilotEvidenceText.Contains(
            '-WindowsPilotReadinessSchemaVersion $WindowsPilotReadinessSchemaVersion',
            [StringComparison]::Ordinal)) `
        'Enterprise Pilot binding no longer forwards the explicit readiness version.'
    foreach ($requiredPilotEvidencePath in @(
            'WindowsPilotEvidenceEnvelopePath',
            'WindowsPilotEvidenceBodyPath',
            'WindowsPilotVerificationReportPath',
            'WindowsPilotReadinessConfigPath',
            'WindowsPilotStoredReadinessReportPath',
            'WindowsPilotReplayedReadinessReportPath',
            'LocalDataCertificationReceiptPath',
            'StablePrivatePilotObservationPath',
            'PilotTrustPolicyPath')) {
        Assert-True `
            ($bindPilotEvidenceText.Contains(
                $requiredPilotEvidencePath,
                [StringComparison]::Ordinal)) `
            "Enterprise r8 recovery no longer requires raw input '$requiredPilotEvidencePath'."
    }
    Assert-True `
        ($bindPilotEvidenceText.Contains(
            'throw "BindPilotEvidence requires -$([string]$entry.Key)."',
            [StringComparison]::Ordinal)) `
        'Enterprise r8 recovery no longer rejects every missing raw evidence path.'
    Assert-True `
        (([regex]::Matches(
            $bindPilotEvidenceText,
            '(?m)^\s*-EnforceCurrentLifetime\)?\s*$')).Count -ge 4) `
        'Enterprise r8 recovery no longer checks current lifetime before, after, at final admission, and before receipt commit.'
    $firstCurrentLifetimeIndex = $bindPilotEvidenceText.IndexOf(
        '-EnforceCurrentLifetime)',
        [StringComparison]::Ordinal)
    $recoveryPublicationLeaseIndex = $bindPilotEvidenceText.IndexOf(
        'Add-ProductionBundlePublicationLease',
        [StringComparison]::Ordinal)
    $preWaitAdmissionIndex = $bindPilotEvidenceText.IndexOf(
        "-Label 'Staged Enterprise Pilot-evidence bundle before wait'",
        [StringComparison]::Ordinal)
    Assert-True `
        ($firstCurrentLifetimeIndex -ge 0 -and
         $recoveryPublicationLeaseIndex -gt $firstCurrentLifetimeIndex -and
         $preWaitAdmissionIndex -gt $recoveryPublicationLeaseIndex) `
        'Enterprise r8 exact recovery must acquire its sole publication move lease only after initial freshness and before the wait.'
    Assert-True `
        ($bindPilotEvidenceText.LastIndexOf(
            '-EnforceCurrentLifetime)',
            [StringComparison]::Ordinal) -ge 0 -and
         $bindPilotEvidenceText.LastIndexOf(
            '-EnforceCurrentLifetime)',
            [StringComparison]::Ordinal) -lt
         $bindPilotEvidenceText.LastIndexOf(
            'Add-ProductionReleaseReceipt',
            [StringComparison]::Ordinal)) `
        'Enterprise r8 recovery does not recheck current lifetime before receipt commit.'
    $stateModuleText = [IO.File]::ReadAllText(
        (Join-Path $sourceRepo 'release\scripts\ProductionReleaseState.psm1'),
        [Text.UTF8Encoding]::new($false, $true))
    foreach ($historicalR8Contract in @(
            "'STALE'",
            "'R8_BINDING_EXPIRED'",
            'historical only and cannot authorize a mutating phase',
            'Committed Enterprise Pilot-evidence status input differs from its typed r8 receipt.',
            'PilotEvidenceExpiresAtUtc')) {
        Assert-True `
            ($stateModuleText.Contains(
                $historicalR8Contract,
                [StringComparison]::Ordinal)) `
            "Historical committed r8 status lost '$historicalR8Contract'."
    }
    $stateTokens = $null
    $stateParseErrors = $null
    $stateAst = [Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $sourceRepo 'release\scripts\ProductionReleaseState.psm1'),
        [ref]$stateTokens,
        [ref]$stateParseErrors)
    Assert-True ($stateParseErrors.Count -eq 0) `
        'Production state module did not parse for receipt precommit inspection.'
    $addReceiptFunctions = @($stateAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Add-ProductionReleaseReceipt'
    }, $true))
    Assert-True ($addReceiptFunctions.Count -eq 1) `
        'Production state module lost its single receipt append function.'
    $addReceiptText = [string]$addReceiptFunctions[0].Extent.Text
    $addReceiptStateReadIndex = $addReceiptText.IndexOf(
        'Get-ProductionReleaseState',
        [StringComparison]::Ordinal)
    $addReceiptPrecommitIndex = $addReceiptText.IndexOf(
        '& $PreCommitValidation $recordedAtInstant',
        [StringComparison]::Ordinal)
    $addReceiptWriteIndex = $addReceiptText.IndexOf(
        'Write-ProductionStateFile',
        [StringComparison]::Ordinal)
    Assert-True `
        ($addReceiptStateReadIndex -ge 0 -and
         $addReceiptPrecommitIndex -gt $addReceiptStateReadIndex -and
         $addReceiptWriteIndex -gt $addReceiptPrecommitIndex) `
        'Receipt precommit validation no longer runs after state replay and before the immutable receipt write.'
    Assert-True (([regex]::Matches(
                $orchestratorText,
                '(?m)^\s*-ExecuteTrustedInstaller\s*$')).Count -eq 1) 'Enterprise r6 must not execute the signed-only production payload self-check, and r7 must execute it exactly once.'
    Assert-True ([regex]::Matches($orchestratorText, '\[IO\.Directory\]::Move\(').Count -eq 1) 'Production orchestrator contains a bundle-move bypass outside its single completion helper.'
    $finalContractsImport =
        'Microsoft.PowerShell.Core\Import-Module $installerSigningContractsPath -Force'
    $finalStateImport =
        'Microsoft.PowerShell.Core\Import-Module $stateModulePath -Force'
    $finalContractsImportIndex = $orchestratorText.LastIndexOf(
        $finalContractsImport,
        [StringComparison]::Ordinal)
    $finalStateImportIndex = $orchestratorText.LastIndexOf(
        $finalStateImport,
        [StringComparison]::Ordinal)
    Assert-True `
        ($finalContractsImportIndex -ge 0 -and
         $finalStateImportIndex -gt $finalContractsImportIndex) `
        'Production orchestrator no longer re-imports signing contracts and state in the safe final order.'

    $moduleImportOrderProbePath = Join-Path $fixtureRoot 'module-import-order-probe.ps1'
    $moduleImportOrderProbeSource = @'
param([Parameter(Mandatory = $true)][string]$RepositoryRoot)
$ErrorActionPreference = 'Stop'
$state = Join-Path $RepositoryRoot 'release/scripts/ProductionReleaseState.psm1'
$personalAdapter = Join-Path $RepositoryRoot 'release/scripts/PersonalProductionReleaseAdapter.psm1'
$enterpriseAdapter = Join-Path $RepositoryRoot 'release/scripts/EnterpriseProductionReleaseAdapter.psm1'
$contracts = Join-Path $RepositoryRoot 'release/scripts/InstallerSigningContracts.psm1'
$personalBuild = Join-Path $RepositoryRoot 'release/scripts/PersonalInstallerTrustedBuild.psm1'
$personalPipeline = Join-Path $RepositoryRoot 'release/scripts/PersonalInstallerSigningPipeline.psm1'
$enterprisePayload = Join-Path $RepositoryRoot 'scripts/EnterpriseProductionPayload.psm1'
$enterpriseBuild = Join-Path $RepositoryRoot 'release/scripts/EnterpriseInstallerTrustedBuild.psm1'
$feedPromotion = Join-Path $RepositoryRoot 'release/scripts/ProductionFeedPromotion.psm1'

Import-Module $state -Force
Import-Module $personalAdapter -Force
Import-Module $enterpriseAdapter -Force
Import-Module $contracts -Force
Import-Module $personalBuild -Force
Import-Module $personalPipeline -Force
Import-Module $enterprisePayload -Force
Import-Module $enterpriseBuild -Force
Import-Module $feedPromotion -Force
Import-Module $contracts -Force
Import-Module $state -Force

$probe = [ordered]@{ importOrder = 'nested-force-import' }
$unqualifiedHash = Get-InstallerSigningObjectSha256 -Value $probe
$qualifiedHash = InstallerSigningContracts\Get-InstallerSigningObjectSha256 -Value $probe
if ($unqualifiedHash -cne $qualifiedHash) {
    throw 'Unqualified signing-contract hash command resolved to a different implementation.'
}
[void](ConvertTo-ProductionJsonBytes -Value $probe)
'MODULE-IMPORT-ORDER-PASS'
'@
    [IO.File]::WriteAllText(
        $moduleImportOrderProbePath,
        $moduleImportOrderProbeSource,
        [Text.UTF8Encoding]::new($false))
    $moduleImportOrderProbeOutput = @(
        & pwsh -NoLogo -NoProfile -File $moduleImportOrderProbePath `
            -RepositoryRoot $sourceRepo 2>&1 |
            ForEach-Object { [string]$_ })
    $moduleImportOrderProbeExitCode = $LASTEXITCODE
    $global:LASTEXITCODE = 0
    Assert-True `
        ($moduleImportOrderProbeExitCode -eq 0) `
        "Nested force-import regression probe failed: $($moduleImportOrderProbeOutput -join ' ')"
    Assert-True `
        (($moduleImportOrderProbeOutput -join [char]10).Contains(
            'MODULE-IMPORT-ORDER-PASS',
            [StringComparison]::Ordinal)) `
        'Nested force-import regression probe did not prove both unqualified shared-module contracts remain bound.'
    $selfTokens = $null
    $selfErrors = $null
    $selfAst = [Management.Automation.Language.Parser]::ParseFile(
        $PSCommandPath,
        [ref]$selfTokens,
        [ref]$selfErrors)
    Assert-True ($selfErrors.Count -eq 0) `
        'Production orchestration test script did not parse for conditional-path inspection.'
    $realRfc3161ContinuationBranches = @($selfAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.IfStatementAst] -and
            ([string]$node.Clauses[0].Item1.Extent.Text).Trim() -ceq
                '$useProductRoleFixture' -and
            [string]$node.Extent.Text -like
                '*V2-PRODUCTION-IMPORT-INTEGRATION-PASS*'
    }, $true))
    Assert-True ($realRfc3161ContinuationBranches.Count -eq 1) `
        'Real RFC3161 continuation branch is missing or ambiguous.'
    $realRfc3161ContinuationText =
        [string]$realRfc3161ContinuationBranches[0].Extent.Text
    $typedFoundationExchangeCount = [regex]::Matches(
        $realRfc3161ContinuationText,
        '(?m)^\s*\[void\]\(Invoke-TestPilotManifestFoundation\s*`?\s*$').Count
    $lastTypedFoundationExchange = $realRfc3161ContinuationText.LastIndexOf(
        'Invoke-TestPilotManifestFoundation',
        [StringComparison]::Ordinal)
    $firstConditionalFoundationAdvance = $realRfc3161ContinuationText.IndexOf(
        'Advance-V2FoundationState',
        [StringComparison]::Ordinal)
    Assert-True `
        ($typedFoundationExchangeCount -eq 2 -and
         $lastTypedFoundationExchange -ge 0 -and
         $firstConditionalFoundationAdvance -gt $lastTypedFoundationExchange) `
        'Real RFC3161 continuation does not build typed Personal/Enterprise r4/r5 receipts before foundation advance.'
    Import-Module (Join-Path $sourceRepo 'release\scripts\ProductionReleaseState.psm1') -Force

    $moveLeaseFixture = Join-Path $fixtureRoot 'directory-move-lease'
    $moveLeaseSource = Join-Path $moveLeaseFixture 'source'
    $moveLeaseDestination = Join-Path $moveLeaseFixture 'destination'
    [IO.Directory]::CreateDirectory($moveLeaseSource) | Out-Null
    $moveLeaseFilePath = Join-Path $moveLeaseSource 'pinned.bin'
    [IO.File]::WriteAllBytes($moveLeaseFilePath, [byte[]](1, 2, 3, 4))
    $readDirectoryLease = Open-ProductionReleaseDirectoryLease `
        -Path $moveLeaseSource -Label 'Move-lease read fixture'
    $readFileLease = Open-ProductionReleaseInput `
        -Path $moveLeaseFilePath -Label 'Move-lease file fixture' `
        -MaximumBytes 64
    $moveDirectoryLease = Open-ProductionReleaseDirectoryMoveLease `
        -Path $moveLeaseSource -Label 'Move-lease fixture'
    try {
        $renameBlocked = $false
        try {
            [IO.Directory]::Move(
                $moveLeaseSource,
                (Join-Path $moveLeaseFixture 'unauthorized-move'))
        }
        catch {
            $renameBlocked = $true
        }
        Assert-True $renameBlocked 'Pinned production bundle root could be renamed without its move lease.'
        $readFileLease.Stream.Dispose()
        $readDirectoryLease.Handle.Dispose()
        [void](Move-ProductionReleaseDirectoryLease `
            -Descriptor $moveDirectoryLease `
            -DestinationPath $moveLeaseDestination `
            -Label 'Move-lease fixture publication')
        $finalDirectoryLease = Open-ProductionReleaseDirectoryLease `
            -Path $moveLeaseDestination -Label 'Moved directory fixture'
        $finalFileLease = Open-ProductionReleaseInput `
            -Path (Join-Path $moveLeaseDestination 'pinned.bin') `
            -Label 'Moved file fixture' -MaximumBytes 64
        try {
            Assert-True `
                ($finalDirectoryLease.VolumeSerialNumber -eq
                    $moveDirectoryLease.VolumeSerialNumber -and
                 $finalDirectoryLease.FileIndex -eq $moveDirectoryLease.FileIndex) `
                'Handle-based atomic publication changed the admitted directory identity.'
            Assert-True `
                ([string]$finalFileLease.Sha256 -ceq
                    [string]$readFileLease.Sha256) `
                'Handle-based atomic publication changed the admitted file bytes.'
            $finalFileLease.Stream.Dispose()
            $finalDirectoryLease.Handle.Dispose()
            $finalRenameBlocked = $false
            try {
                [IO.Directory]::Move(
                    $moveLeaseDestination,
                    (Join-Path $moveLeaseFixture 'post-publication-unauthorized-move'))
            }
            catch {
                $finalRenameBlocked = $true
            }
            Assert-True `
                $finalRenameBlocked `
                'Retained publication move lease did not deny rename across receipt/head commit.'
        }
        finally {
            $finalFileLease.Stream.Dispose()
            $finalDirectoryLease.Handle.Dispose()
        }
    }
    finally {
        $readFileLease.Stream.Dispose()
        $readDirectoryLease.Handle.Dispose()
        $moveDirectoryLease.Handle.Dispose()
    }

    $pilotLifecycle = Get-ProductionReleaseLifecycleContract -SchemaVersion 2 -TargetChannel pilot
    $stableLifecycle = Get-ProductionReleaseLifecycleContract -SchemaVersion 2 -TargetChannel stable
    $v1Lifecycle = Get-ProductionReleaseLifecycleContract -SchemaVersion 1 -TargetChannel pilot
    Assert-True ($v1Lifecycle.TerminalRevision -eq 3 -and [string]$v1Lifecycle.TerminalPhase -ceq 'CLIENT_SIGNATURES_IMPORTED') 'State v1 lifecycle compatibility changed.'
    $frozenV1StateRoot = Join-Path $fixtureRoot 'frozen-pre-v2-state-v1'
    Assert-FrozenV1StateReplay `
        -FixtureRoot $frozenV1StateRoot `
        -PlanSchemaPath (Join-Path $sourceRepo 'release\schemas\launcher-production-release-plan-v1.schema.json') `
        -StateSchemaPath (Join-Path $sourceRepo 'release\schemas\launcher-production-release-state-v1.schema.json')
    [IO.File]::WriteAllBytes((Join-Path $frozenV1StateRoot 'state.lock'), [byte[]]::new(0))
    $frozenV1PlanBytes = [IO.File]::ReadAllBytes((Join-Path $frozenV1StateRoot 'plan.json'))
    $frozenV1Plan = ConvertFrom-StrictProductionJsonBytes -Bytes $frozenV1PlanBytes -Label 'Frozen legacy plan'
    $frozenV1Lock = Enter-ProductionReleaseStateLock `
        -StateRoot $frozenV1StateRoot `
        -PlanBytes $frozenV1PlanBytes `
        -Plan $frozenV1Plan
    $frozenV1Lock.Stream.Dispose()
    Assert-True $true 'Fully initialized markerless v1 state was not admitted read-compatible.'
    foreach ($missingLegacyDirectory in @('imports', 'receipts', 'requests')) {
        $partialLegacyRoot = Join-Path $fixtureRoot "partial-legacy-missing-$missingLegacyDirectory"
        Copy-State -Source $frozenV1StateRoot -Destination $partialLegacyRoot
        Remove-Item -LiteralPath (Join-Path $partialLegacyRoot $missingLegacyDirectory) -Recurse -Force
        $partialLegacySnapshotBefore = Get-StateTreeSnapshot -Path $partialLegacyRoot
        Assert-Throws `
            -Label "Partial markerless legacy state $missingLegacyDirectory" `
            -ExpectedMessage 'is incomplete' `
            -Action {
                $unexpectedLegacyLock = Enter-ProductionReleaseStateLock `
                    -StateRoot $partialLegacyRoot `
                    -PlanBytes $frozenV1PlanBytes `
                    -Plan $frozenV1Plan
                $unexpectedLegacyLock.Stream.Dispose()
            }
        Assert-True ((Get-StateTreeSnapshot -Path $partialLegacyRoot) -ceq $partialLegacySnapshotBefore) "Partial markerless legacy state '$missingLegacyDirectory' was mutated."
    }
    Assert-True ($pilotLifecycle.TerminalRevision -eq 9 -and [string]$pilotLifecycle.TerminalPhase -ceq 'PILOT_FEED_PROMOTED') 'Plan v2 Pilot lifecycle does not terminate at revision 9.'
    Assert-True ($stableLifecycle.TerminalRevision -eq 10 -and [string]$stableLifecycle.TerminalPhase -ceq 'STABLE_FEED_PROMOTED') 'Plan v2 Stable lifecycle does not terminate at revision 10.'
    [void](Assert-ProductionReleaseLifecycleSequence -SchemaVersion 2 -TargetChannel pilot -Phases @($pilotLifecycle.Transitions.Phase))
    Assert-True $true 'Plan v2 Pilot valid transition path was rejected.'
    [void](Assert-ProductionReleaseLifecycleSequence -SchemaVersion 2 -TargetChannel stable -Phases @($stableLifecycle.Transitions.Phase))
    Assert-True $true 'Plan v2 Stable valid transition path was rejected.'
    Assert-Throws -Label 'Pilot transition after terminal revision' -ExpectedMessage 'after terminal' -Action {
        [void](Assert-ProductionReleaseLifecycleSequence -SchemaVersion 2 -TargetChannel pilot -Phases @($stableLifecycle.Transitions.Phase[0..9]))
    }
    $allPredecessors = @($null) + @($stableLifecycle.Transitions.Phase)
    foreach ($transition in @($stableLifecycle.Transitions)) {
        [void](Assert-ProductionReleaseTransitionContract -SchemaVersion 2 -TargetChannel stable -Revision ([int]$transition.Revision) -Phase ([string]$transition.Phase) -PreviousPhase $transition.PreviousPhase)
        Assert-True $true "Valid predecessor was rejected for $($transition.Phase)."
        foreach ($candidatePredecessor in $allPredecessors) {
            if ([string]$candidatePredecessor -ceq [string]$transition.PreviousPhase) {
                continue
            }
            Assert-Throws -Label "Illegal predecessor '$candidatePredecessor' for $($transition.Phase)" -ExpectedMessage 'requires phase' -Action {
                [void](Assert-ProductionReleaseTransitionContract -SchemaVersion 2 -TargetChannel stable -Revision ([int]$transition.Revision) -Phase ([string]$transition.Phase) -PreviousPhase $candidatePredecessor)
            }
        }
    }

    $stateV2SchemaPath = Join-Path $sourceRepo 'release\schemas\launcher-production-release-state-v2.schema.json'
    $externalReceiptFixture = [ordered]@{
        schemaVersion = 2
        receiptType = 'ensou-dsh-launcher-production-release-transition'
        orchestrationId = [Guid]::NewGuid().ToString()
        edition = 'Personal'
        targetChannel = 'pilot'
        planSha256 = '1' * 64
        identitySha256 = '2' * 64
        revision = 4
        phase = 'PILOT_MANIFEST_SIGNING_REQUESTED'
        previousReceiptSha256 = '3' * 64
        transitionSha256 = '4' * 64
        data = [ordered]@{
            requestRelativePath = 'requests/pilot-manifest-publishing.v1/manifest-publishing-request.v1.json'
            requestSha256 = '5' * 64
            publisherInputDescriptorSha256 = '6' * 64
            baseHeadSha256 = '7' * 64
            requestNonce = 'A' * 43
            createdAtUtc = '2026-08-30T00:00:00Z'
            expiresAtUtc = '2026-08-30T01:00:00Z'
            responseAuthenticationKeyId = 'manifest-response-test'
            responseAuthenticationPurpose = 'manifest-publishing-response'
            responseAuthenticationPayloadType = 'ensou-dsh-launcher-manifest-publishing-response-authentication-v1'
            releaseManifestTrustSha256 = '8' * 64
            releaseCompatibilitySha256 = '9' * 64
            componentReleaseIdsSha256 = 'a' * 64
            runtimeProvenanceSha256 = 'b' * 64
            compiledReleaseTrustStatus = 'VERIFIED'
            files = @(1..7 | ForEach-Object {
                [ordered]@{
                    role = "fixture-role-$_"
                    fileName = "fixture-$_.bin"
                    relativePath = "payload/fixture-$_.bin"
                    sizeBytes = $_
                    sha256 = ([string]$_).PadLeft(64, '0')
                }
            })
        }
        recordedAtUtc = '2026-08-30T00:00:00Z'
    }
    $externalReceiptJson = $externalReceiptFixture | ConvertTo-Json -Depth 64 -Compress
    Assert-True (Test-Json -Json $externalReceiptJson -SchemaFile $stateV2SchemaPath -ErrorAction Stop) 'Canonical v2 external evidence path did not satisfy the strict state schema.'
    foreach ($traversalPath in @(
            'requests/a/../../imports/x.json',
            'requests/../imports/x.json',
            'requests//x.json',
            'requests/.hidden/x.json',
            'requests\x.json')) {
        $externalReceiptFixture.data.requestRelativePath = $traversalPath
        $traversalJson = $externalReceiptFixture | ConvertTo-Json -Depth 64 -Compress
        Assert-True (-not (Test-Json -Json $traversalJson -SchemaFile $stateV2SchemaPath -ErrorAction SilentlyContinue)) "Traversal path '$traversalPath' satisfied the v2 state schema."
    }
    $externalReceiptFixture.data.requestRelativePath = 'requests/pilot-manifest-publishing.v1/manifest-publishing-request.v1.json'

    $stateCanonicalCandidate = $externalReceiptJson | ConvertFrom-Json -Depth 64 -DateKind String
    $stateCanonicalCandidate.planSha256 = ('1' * 64) + [char]10
    Assert-True (-not (Test-Json -Json ($stateCanonicalCandidate | ConvertTo-Json -Depth 64 -Compress) -SchemaFile $stateV2SchemaPath -ErrorAction SilentlyContinue)) 'State v2 SHA-256 accepted a trailing LF.'
    $stateCanonicalCandidate = $externalReceiptJson | ConvertFrom-Json -Depth 64 -DateKind String
    $stateCanonicalCandidate.planSha256 = ('1' * 63) + [char]31
    Assert-True (-not (Test-Json -Json ($stateCanonicalCandidate | ConvertTo-Json -Depth 64 -Compress) -SchemaFile $stateV2SchemaPath -ErrorAction SilentlyContinue)) 'State v2 SHA-256 accepted a control character.'
    $stateCanonicalCandidate = $externalReceiptJson | ConvertFrom-Json -Depth 64 -DateKind String
    $stateCanonicalCandidate.recordedAtUtc = '2026-08-30T00:00:00Z' + [char]10
    Assert-True (-not (Test-Json -Json ($stateCanonicalCandidate | ConvertTo-Json -Depth 64 -Compress) -SchemaFile $stateV2SchemaPath -ErrorAction SilentlyContinue)) 'State v2 UTC accepted a trailing LF.'
    $stateCanonicalCandidate = $externalReceiptJson | ConvertFrom-Json -Depth 64 -DateKind String
    $stateCanonicalCandidate.recordedAtUtc = '2026-08-30' + [char]9 + '00:00:00Z'
    Assert-True (-not (Test-Json -Json ($stateCanonicalCandidate | ConvertTo-Json -Depth 64 -Compress) -SchemaFile $stateV2SchemaPath -ErrorAction SilentlyContinue)) 'State v2 UTC accepted a control character.'
    foreach ($badCanonicalPath in @(
            'requests/pilot-manifest/signing-request.json' + [char]10,
            'requests/pilot-manifest/' + [char]31 + 'signing-request.json')) {
        $stateCanonicalCandidate = $externalReceiptJson | ConvertFrom-Json -Depth 64 -DateKind String
        $stateCanonicalCandidate.data.requestRelativePath = $badCanonicalPath
        Assert-True (-not (Test-Json -Json ($stateCanonicalCandidate | ConvertTo-Json -Depth 64 -Compress) -SchemaFile $stateV2SchemaPath -ErrorAction SilentlyContinue)) 'State v2 canonical path accepted a control character or trailing LF.'
    }

    $script:UnsignedPeFixturePath = Join-Path $fixtureRoot 'unsigned-client-fixture.dll'
    Add-Type -TypeDefinition @'
namespace Ensou.Launcher.ProductionOrchestrationTests
{
    public static class UnsignedClientFixture
    {
        public static int Value => 3161;
    }
}
'@ -Language CSharp -OutputAssembly $script:UnsignedPeFixturePath -OutputType Library
    $unsignedFixtureSignature = Microsoft.PowerShell.Security\Get-AuthenticodeSignature -LiteralPath $script:UnsignedPeFixturePath
    Assert-True ($unsignedFixtureSignature.Status -eq [Management.Automation.SignatureStatus]::NotSigned) 'Generated unsigned client PE fixture unexpectedly has Authenticode.'

    $foundationSyntheticRoot = Join-Path `
        $fixtureRoot `
        'foundation-typed-state-only-synthetic-pe'
    [IO.Directory]::CreateDirectory($foundationSyntheticRoot) | Out-Null
    $foundationSyntheticPath = Join-Path `
        $foundationSyntheticRoot `
        'Ensou.Dsh.Enterprise.Installer.exe'
    New-FoundationSignedPeFixture `
        -UnsignedPath $script:UnsignedPeFixturePath `
        -OutputPath $foundationSyntheticPath
    [byte[]]$foundationUnsignedBytes =
        [IO.File]::ReadAllBytes($script:UnsignedPeFixturePath)
    [byte[]]$foundationSyntheticBytes =
        [IO.File]::ReadAllBytes($foundationSyntheticPath)
    $foundationUnsignedPeSha256 =
        Get-PeContentSha256 -Bytes $foundationUnsignedBytes
    $foundationSyntheticPeSha256 =
        Get-PeContentSha256 -Bytes $foundationSyntheticBytes
    $foundationUnsignedSha256 = Get-Sha256 `
        -Path $script:UnsignedPeFixturePath
    $foundationSyntheticSha256 = Get-Sha256 `
        -Path $foundationSyntheticPath
    Assert-True `
        ($foundationUnsignedPeSha256 -ceq $foundationSyntheticPeSha256) `
        'Foundation synthetic certificate table changed the unsigned PE content hash.'
    Assert-True `
        ($foundationSyntheticBytes.LongLength -gt
            $foundationUnsignedBytes.LongLength -and
         $foundationSyntheticSha256 -cne $foundationUnsignedSha256) `
        'Foundation synthetic certificate table did not change full file size and SHA-256.'
    $foundationSyntheticResponse = [pscustomobject]@{
        unsignedInstaller = [pscustomobject]@{
            peContentSha256 = $foundationUnsignedPeSha256
        }
        signedInstaller = [pscustomobject]@{
            fileName = 'Ensou.Dsh.Enterprise.Installer.exe'
            sizeBytes = [int64]$foundationSyntheticBytes.LongLength
            sha256 = $foundationSyntheticSha256
            peContentSha256 = $foundationSyntheticPeSha256
        }
        authenticode = [pscustomobject]@{}
    }
    Assert-Throws `
        -Label 'Foundation synthetic PE production Authenticode admission' `
        -Action {
            [void](InstallerSigningContracts\Assert-SignedInstallerAuthenticode `
                -Path $foundationSyntheticPath `
                -Response $foundationSyntheticResponse `
                -ExpectedSignerCertificateSha256 ('a' * 64))
        }
    Write-Output `
        'FOUNDATION-SYNTHETIC-PE-NON-PRODUCTION-PASS: typed-state-only WIN_CERTIFICATE shape preserves PE-content hash and changes file bytes, while the real Authenticode/RFC3161 admission gate rejects it.'

    $codeSigningFixture = New-TestSigningCertificate -Subject 'CN=Ensou RFC3161 code fixture'
    $timestampSigningFixture = New-TestSigningCertificate -Subject 'CN=Ensou RFC3161 TSA fixture' -Timestamping
    $primaryCms = New-TestPrimaryCms -Certificate $codeSigningFixture.Certificate -Content ([Text.Encoding]::UTF8.GetBytes('primary-signer-one'))
    $rfc3161TokenBytes = New-TestRfc3161Token -PrimarySigner $primaryCms.SignerInfos[0] -TimestampCertificate $timestampSigningFixture.Certificate
    $syntheticBinding = Assert-Rfc3161TimestampTokenBinding -TokenBytes $rfc3161TokenBytes -PrimarySigner $primaryCms.SignerInfos[0] -ExpectedTimestampSigner $timestampSigningFixture.Certificate
    Assert-True ([string]$syntheticBinding.TimestampProtocol -ceq 'RFC3161') 'Synthetic RFC3161 token did not bind its primary SignerInfo.'
    $unrelatedCms = New-TestPrimaryCms -Certificate $codeSigningFixture.Certificate -Content ([Text.Encoding]::UTF8.GetBytes('different-primary-signer'))
    Assert-Throws -Label 'Unrelated RFC3161 token messageImprint regression' -ExpectedMessage 'messageImprint' -Action {
        [void](Assert-Rfc3161TimestampTokenBinding -TokenBytes $rfc3161TokenBytes -PrimarySigner $unrelatedCms.SignerInfos[0] -ExpectedTimestampSigner $timestampSigningFixture.Certificate)
    }
    $legacyCms = New-TestPrimaryCms -Certificate $codeSigningFixture.Certificate -Content ([Text.Encoding]::UTF8.GetBytes('legacy-primary-signer'))
    $legacyCounterSigner = [Security.Cryptography.Pkcs.CmsSigner]::new(
        [Security.Cryptography.Pkcs.SubjectIdentifierType]::IssuerAndSerialNumber,
        $timestampSigningFixture.Certificate)
    $legacyCounterSigner.IncludeOption =
        [Security.Cryptography.X509Certificates.X509IncludeOption]::EndCertOnly
    $legacyCms.SignerInfos[0].ComputeCounterSignature($legacyCounterSigner)
    Assert-Throws -Label 'Legacy Authenticode counterSignature regression' -ExpectedMessage 'legacy counterSignature' -Action {
        [void](Assert-AuthenticodeSignerRfc3161Timestamp -PrimarySigner $legacyCms.SignerInfos[0] -ExpectedSigner $codeSigningFixture.Certificate -ExpectedTimestampSigner $timestampSigningFixture.Certificate)
    }

    $signedCandidates = @(
        (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'),
        (Join-Path $env:SystemRoot 'System32\notepad.exe'),
        (Join-Path $env:SystemRoot 'System32\cmd.exe'),
        (Join-Path $PSHOME 'pwsh.exe'),
        'C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe',
        'C:\Program Files\Git\cmd\git.exe',
        'C:\Program Files\Git\bin\git.exe',
        'C:\Program Files\dotnet\dotnet.exe',
        'C:\Program Files\nodejs\node.exe',
        'C:\Program Files\GitHub CLI\gh.exe',
        'C:\Program Files\Docker\Docker\Docker Desktop.exe',
        'C:\Program Files\Docker\Docker\resources\bin\docker.exe',
        'C:\Program Files\Microsoft VS Code\Code.exe',
        'C:\Users\example\AppData\Local\Programs\Microsoft VS Code\Code.exe',
        'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe',
        'C:\Program Files\Google\Chrome\Application\chrome.exe'
    )
    foreach ($commandName in @('git', 'dotnet', 'node')) {
        $command = Microsoft.PowerShell.Core\Get-Command -Name $commandName -CommandType Application -ErrorAction SilentlyContinue
        if ($null -ne $command) {
            $signedCandidates += [string]$command.Source
        }
    }
    $signature = $null
    $rfc3161Signature = $null
    $candidateDiagnostics = [Collections.Generic.List[string]]::new()
    foreach ($candidate in $signedCandidates) {
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            continue
        }
        $candidateBytes = [IO.File]::ReadAllBytes($candidate)
        $layout = Get-PeSecurityLayout -Bytes $candidateBytes
        $candidateSignature = Microsoft.PowerShell.Security\Get-AuthenticodeSignature -LiteralPath $candidate
        if ($layout.CertificateOffset -gt 0 -and
            $layout.CertificateSize -gt 0 -and
            $candidateSignature.Status -eq [Management.Automation.SignatureStatus]::Valid -and
            $null -ne $candidateSignature.SignerCertificate -and
            $null -ne $candidateSignature.TimeStamperCertificate) {
            if ([string]::IsNullOrWhiteSpace($script:SignedPeFixturePath)) {
                $script:SignedPeFixturePath = $candidate
                $signature = $candidateSignature
            }
            try {
                $timestampAdmission = Assert-PeRfc3161Timestamp -Bytes $candidateBytes -SignerCertificate $candidateSignature.SignerCertificate -TimeStamperCertificate $candidateSignature.TimeStamperCertificate
                if ([string]$timestampAdmission.TimestampProtocol -ceq 'RFC3161') {
                    $script:SignedPeFixturePath = $candidate
                    $script:Rfc3161SignedPeFixturePath = $candidate
                    $signature = $candidateSignature
                    $rfc3161Signature = $candidateSignature
                    break
                }
            }
            catch {
                $candidateDiagnostics.Add($candidate + ': ' + $_.Exception.Message)
                continue
            }
        }
    }
    if ([string]::IsNullOrWhiteSpace($script:SignedPeFixturePath)) {
        $script:SignedPeFixturePath = $script:UnsignedPeFixturePath
    }
    if ($null -ne $signature) {
        Assert-True ($signature.Status -eq [Management.Automation.SignatureStatus]::Valid) 'Real Authenticode fixture is not valid.'
        Assert-True ($null -ne $signature.SignerCertificate) 'Real Authenticode fixture has no signer certificate.'
        Assert-True ($null -ne $signature.TimeStamperCertificate) 'Real Authenticode fixture has no trusted timestamp.'
        $matchingUnsignedFixture = Join-Path $fixtureRoot 'unsigned-client-from-signed.exe'
        New-UnsignedPeFixtureFromSigned -SignedPath $script:SignedPeFixturePath -OutputPath $matchingUnsignedFixture
        $script:UnsignedPeFixturePath = $matchingUnsignedFixture
    }
    $realRfc3161FixtureAvailable =
        -not [string]::IsNullOrWhiteSpace($script:Rfc3161SignedPeFixturePath)
    if ($realRfc3161FixtureAvailable) {
        $rfc3161Positive = Assert-PeRfc3161Timestamp -Bytes ([IO.File]::ReadAllBytes($script:Rfc3161SignedPeFixturePath)) -SignerCertificate $rfc3161Signature.SignerCertificate -TimeStamperCertificate $rfc3161Signature.TimeStamperCertificate
        Assert-True ([string]$rfc3161Positive.TimestampProtocol -ceq 'RFC3161') 'Real Authenticode fixture did not pass explicit RFC3161 admission.'
        Assert-True `
            ([string]$rfc3161Positive.TimestampTokenOid -in @(
                '1.2.840.113549.1.9.16.2.14',
                '1.3.6.1.4.1.311.3.3.1')) `
            'Real Authenticode fixture used an unsupported RFC3161 timestamp attribute OID.'
        [byte[]]$nonRfcBytes = [IO.File]::ReadAllBytes($script:Rfc3161SignedPeFixturePath)
        [byte[]]$rfcOidDer = if ([string]$rfc3161Positive.TimestampTokenOid -ceq
                '1.3.6.1.4.1.311.3.3.1') {
            @(0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x03, 0x03, 0x01)
        }
        else {
            @(0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x0e)
        }
        $oidOffset = -1
        for ($candidateOffset = 0; $candidateOffset -le $nonRfcBytes.Length - $rfcOidDer.Length; $candidateOffset++) {
            $match = $true
            for ($oidIndex = 0; $oidIndex -lt $rfcOidDer.Length; $oidIndex++) {
                if ($nonRfcBytes[$candidateOffset + $oidIndex] -ne $rfcOidDer[$oidIndex]) {
                    $match = $false
                    break
                }
            }
            if ($match) {
                $oidOffset = $candidateOffset
                break
            }
        }
        Assert-True ($oidOffset -ge 0) 'RFC3161 fixture did not contain its admitted timestamp attribute OID.'
        $nonRfcBytes[$oidOffset + $rfcOidDer.Length - 1] = 0x0f
        Assert-Throws -Label 'Non-RFC3161 timestamp-token OID regression' -Action {
            [void](Assert-PeRfc3161Timestamp -Bytes $nonRfcBytes -SignerCertificate $rfc3161Signature.SignerCertificate -TimeStamperCertificate $rfc3161Signature.TimeStamperCertificate)
        }
    }
    else {
        Write-Output ('IMPORT-POSITIVE-PENDING-REAL-TRUSTED-RFC3161-FIXTURE: ' + ($candidateDiagnostics -join ' | '))
    }
    $authenticodeSignerSha256 = if ($null -ne $productRoleFixture) {
        [string]$productRoleFixture.SignerSha256
    }
    else {
        $policySignerCertificate = if ($null -eq $signature) {
            $codeSigningFixture.Certificate
        }
        else {
            $signature.SignerCertificate
        }
        ([Convert]::ToHexString(
            [Security.Cryptography.SHA256]::HashData(
                $policySignerCertificate.RawData))).ToLowerInvariant()
    }

    $evidenceRoot = Join-Path $fixtureRoot 'evidence'
    [IO.Directory]::CreateDirectory($evidenceRoot) | Out-Null
    $runtimeName = 'EnsouDshRuntime-managed-v2026.08.30.1-win-x64.zip'
    $runtimeArchivePath = Join-Path $evidenceRoot $runtimeName
    [IO.File]::WriteAllBytes(
        $runtimeArchivePath,
        [Text.Encoding]::UTF8.GetBytes('LOCAL-DESCRIPTOR-ONLY-NOT-IMMUTABLE-GITHUB-RELEASE'))
    $runtimeSha256 = Get-Sha256 -Path $runtimeArchivePath
    $metadata = Read-Json -Path (Join-Path $RepositoryRoot 'release\examples\source-runtime.metadata.json')
    $metadata.releaseId = 'managed-v2026.08.30.1'
    $metadata.promotionEligible = $true
    $metadata.artifact.fileName = $runtimeName
    $metadata.artifact.sizeBytes = (Get-Item -LiteralPath $runtimeArchivePath).Length
    $metadata.artifact.sha256 = $runtimeSha256
    $runtimeMetadataPath = $runtimeArchivePath + '.metadata.json'
    Write-Json -Path $runtimeMetadataPath -Value $metadata
    $runtimeHashPath = $runtimeArchivePath + '.sha256'
    [IO.File]::WriteAllText(
        $runtimeHashPath,
        $runtimeSha256 + '  ' + $runtimeName + [char]10,
        $utf8)

    $public = $responseSigner.ExportParameters($false)
    $manifestPublic = $manifestResponseSigner.ExportParameters($false)
    $releaseManifestPublic = $releaseManifestSigner.ExportParameters($false)
    $personalPlanPath = Join-Path $evidenceRoot 'personal-plan.json'
    $enterprisePlanPath = Join-Path $evidenceRoot 'enterprise-plan.json'
    $personalPlan = New-PlanFixture -Edition Personal -Path $personalPlanPath -Commit $commit -RuntimeArchivePath $runtimeArchivePath -RuntimeMetadataPath $runtimeMetadataPath -RuntimeHashPath $runtimeHashPath -UnsignedRoot (Join-Path $evidenceRoot 'personal-unsigned') -SignerSha256 $authenticodeSignerSha256 -ResponsePublic $public -ManifestResponsePublic $manifestPublic -ReleaseManifestPublic $releaseManifestPublic -RoleFixtureContract $productRoleFixture -SchemaVersion 2 -TargetChannel pilot
    $enterprisePlan = New-PlanFixture -Edition Enterprise -Path $enterprisePlanPath -Commit $commit -RuntimeArchivePath $runtimeArchivePath -RuntimeMetadataPath $runtimeMetadataPath -RuntimeHashPath $runtimeHashPath -UnsignedRoot (Join-Path $evidenceRoot 'enterprise-unsigned') -SignerSha256 $authenticodeSignerSha256 -ResponsePublic $public -ManifestResponsePublic $manifestPublic -ReleaseManifestPublic $releaseManifestPublic -RoleFixtureContract $productRoleFixture -SchemaVersion 2 -TargetChannel stable
    $pilotV2PlanPath = Join-Path $evidenceRoot 'personal-pilot-plan-v2.json'
    $stableV2PlanPath = Join-Path $evidenceRoot 'enterprise-stable-plan-v2.json'
    $pilotV2Plan = New-PlanFixture -Edition Personal -Path $pilotV2PlanPath -Commit $commit -RuntimeArchivePath $runtimeArchivePath -RuntimeMetadataPath $runtimeMetadataPath -RuntimeHashPath $runtimeHashPath -UnsignedRoot (Join-Path $evidenceRoot 'personal-pilot-v2-unsigned') -SignerSha256 $authenticodeSignerSha256 -ResponsePublic $public -ManifestResponsePublic $manifestPublic -ReleaseManifestPublic $releaseManifestPublic -RoleFixtureContract $productRoleFixture -SchemaVersion 2 -TargetChannel pilot
    $stableV2Plan = New-PlanFixture -Edition Enterprise -Path $stableV2PlanPath -Commit $commit -RuntimeArchivePath $runtimeArchivePath -RuntimeMetadataPath $runtimeMetadataPath -RuntimeHashPath $runtimeHashPath -UnsignedRoot (Join-Path $evidenceRoot 'enterprise-stable-v2-unsigned') -SignerSha256 $authenticodeSignerSha256 -ResponsePublic $public -ManifestResponsePublic $manifestPublic -ReleaseManifestPublic $releaseManifestPublic -RoleFixtureContract $productRoleFixture -SchemaVersion 2 -TargetChannel stable

    # Validate each edition before race/Prepare tests so a fixture contract drift
    # cannot be mistaken for a transaction or process failure.
    $planV2SchemaPath = Join-Path $sourceRepo 'release\schemas\launcher-production-release-plan-v2.schema.json'
    foreach ($fixturePlanPath in @($personalPlanPath, $enterprisePlanPath, $pilotV2PlanPath, $stableV2PlanPath)) {
        $fixturePlanJson = [IO.File]::ReadAllText($fixturePlanPath, $utf8)
        $fixturePlan = $fixturePlanJson | ConvertFrom-Json -Depth 64 -DateKind String
        if ([string]$fixturePlan.edition -ceq 'Personal') {
            Assert-True ([string]$fixturePlan.releaseCompatibility.startupStubVersion -ceq '1.2.0') 'Fresh Personal plan fixture must use Startup Stub 1.2.0.'
            Assert-True ($null -eq $fixturePlan.PSObject.Properties['pilotEvidenceTrustPolicySha256']) 'Personal plan fixture must not contain the Enterprise Pilot trust anchor.'
        }
        Assert-True (Test-Json -Json $fixturePlanJson -SchemaFile $planV2SchemaPath -ErrorAction Stop) "Generated $($fixturePlan.edition) plan fixture did not satisfy the production schema before Prepare."
    }

    $initializationRaceState = Join-Path $fixtureRoot 'initialization-race-state'
    Invoke-ProductionInitializationRace `
        -ModulePath (Join-Path $sourceRepo 'release\scripts\ProductionReleaseState.psm1') `
        -PlanPath $personalPlanPath `
        -StateRoot $initializationRaceState `
        -FixtureRoot $fixtureRoot
    $initializationOperationId = ([Guid]::Parse([string]$personalPlan.orchestrationId)).ToString('N')
    Assert-True (@(
            Get-ChildItem `
                -LiteralPath $fixtureRoot `
                -Directory `
                -Force `
                -Filter ".ensou-launcher-state-init-$initializationOperationId-*"
        ).Count -eq 0) 'Concurrent initialization left operation-owned staging residue.'
    [void](Invoke-Orchestrator `
        -ScriptPath $orchestrator `
        -RepoRoot $sourceRepo `
        -Edition Personal `
        -Phase Prepare `
        -PlanPath $personalPlanPath `
        -StateRoot $initializationRaceState)
    Assert-True ([string]((Read-Json -Path (Join-Path $initializationRaceState 'head.json')).phase) -ceq 'CLIENT_SIGNING_REQUESTED') 'Concurrent initialization owner transaction did not resume through Prepare.'

    $canonicalV2PlanJson = [IO.File]::ReadAllText($stableV2PlanPath, [Text.UTF8Encoding]::new($false, $true))
    Assert-True (Test-Json -Json $canonicalV2PlanJson -SchemaFile $planV2SchemaPath -ErrorAction Stop) 'Canonical plan v2 fixture did not satisfy its schema.'
    $planCanonicalCandidate = $canonicalV2PlanJson | ConvertFrom-Json -Depth 64 -DateKind String
    $planCanonicalCandidate.runtimeCandidate.archive.sha256 = ('a' * 64) + [char]10
    Assert-True (-not (Test-Json -Json ($planCanonicalCandidate | ConvertTo-Json -Depth 64 -Compress) -SchemaFile $planV2SchemaPath -ErrorAction SilentlyContinue)) 'Plan v2 SHA-256 accepted a trailing LF.'
    $planCanonicalCandidate = $canonicalV2PlanJson | ConvertFrom-Json -Depth 64 -DateKind String
    $planCanonicalCandidate.releaseSetId = [string]$planCanonicalCandidate.releaseSetId + [char]10
    Assert-True (-not (Test-Json -Json ($planCanonicalCandidate | ConvertTo-Json -Depth 64 -Compress) -SchemaFile $planV2SchemaPath -ErrorAction SilentlyContinue)) 'Plan v2 identifier accepted a trailing LF.'
    $planCanonicalCandidate = $canonicalV2PlanJson | ConvertFrom-Json -Depth 64 -DateKind String
    $planCanonicalCandidate.manifestUri = [string]$planCanonicalCandidate.manifestUri + [char]10
    Assert-True (-not (Test-Json -Json ($planCanonicalCandidate | ConvertTo-Json -Depth 64 -Compress) -SchemaFile $planV2SchemaPath -ErrorAction SilentlyContinue)) 'Plan v2 URI accepted a trailing LF.'
    $planCanonicalCandidate = $canonicalV2PlanJson | ConvertFrom-Json -Depth 64 -DateKind String
    $planCanonicalCandidate.manifestUri = [string]$planCanonicalCandidate.manifestUri + [char]0x85
    Assert-True (-not (Test-Json -Json ($planCanonicalCandidate | ConvertTo-Json -Depth 64 -Compress) -SchemaFile $planV2SchemaPath -ErrorAction SilentlyContinue)) 'Plan v2 URI accepted the C1 control character U+0085.'
    $planCanonicalCandidate = $canonicalV2PlanJson | ConvertFrom-Json -Depth 64 -DateKind String
    $planCanonicalCandidate.clientSigningInputs[0].path = [string]$planCanonicalCandidate.clientSigningInputs[0].path + [char]31
    Assert-True (-not (Test-Json -Json ($planCanonicalCandidate | ConvertTo-Json -Depth 64 -Compress) -SchemaFile $planV2SchemaPath -ErrorAction SilentlyContinue)) 'Plan v2 local path accepted a control character.'
    $planCanonicalCandidate = $canonicalV2PlanJson | ConvertFrom-Json -Depth 64 -DateKind String
    $planCanonicalCandidate.externalResponseTrusts.clientSigning.x = [string]$planCanonicalCandidate.externalResponseTrusts.clientSigning.x + [char]10
    Assert-True (-not (Test-Json -Json ($planCanonicalCandidate | ConvertTo-Json -Depth 64 -Compress) -SchemaFile $planV2SchemaPath -ErrorAction SilentlyContinue)) 'Plan v2 P-256 coordinate accepted a trailing LF.'
    $planCanonicalCandidate = $canonicalV2PlanJson | ConvertFrom-Json -Depth 64 -DateKind String
    $planCanonicalCandidate.PSObject.Properties.Remove(
        'pilotEvidenceTrustPolicySha256')
    Assert-True (-not (Test-Json -Json ($planCanonicalCandidate | ConvertTo-Json -Depth 64 -Compress) -SchemaFile $planV2SchemaPath -ErrorAction SilentlyContinue)) 'Enterprise plan v2 accepted a missing Pilot evidence trust-policy anchor.'
    $planCanonicalCandidate = $canonicalV2PlanJson | ConvertFrom-Json -Depth 64 -DateKind String
    $planCanonicalCandidate | Add-Member -NotePropertyName continuation -NotePropertyValue ([pscustomobject]@{
        pilotTerminalHeadSha256 = 'a' * 64
    })
    Assert-True (-not (Test-Json -Json ($planCanonicalCandidate | ConvertTo-Json -Depth 64 -Compress) -SchemaFile $planV2SchemaPath -ErrorAction SilentlyContinue)) 'Plan v2 accepted a Pilot-to-Stable continuation that belongs to a future schema version.'

    foreach ($trustNegative in @(
            'missing-domain', 'mixed-purpose', 'duplicate-key-id',
            'duplicate-public-key', 'release-duplicate-key-id',
            'release-duplicate-public-key')) {
        $negativePlanPath = Join-Path $evidenceRoot ("trust-$trustNegative-plan-v2.json")
        $negativePlan = Read-Json -Path $stableV2PlanPath
        if ($trustNegative -ceq 'missing-domain') {
            $negativePlan.externalResponseTrusts.PSObject.Properties.Remove('manifestPublishing')
        }
        elseif ($trustNegative -ceq 'mixed-purpose') {
            $negativePlan.externalResponseTrusts.manifestPublishing.purpose = 'client-signing-response'
        }
        elseif ($trustNegative -ceq 'duplicate-key-id') {
            $negativePlan.externalResponseTrusts.manifestPublishing.keyId = [string]$negativePlan.externalResponseTrusts.clientSigning.keyId
        }
        elseif ($trustNegative -ceq 'duplicate-public-key') {
            $negativePlan.externalResponseTrusts.manifestPublishing.x = [string]$negativePlan.externalResponseTrusts.clientSigning.x
            $negativePlan.externalResponseTrusts.manifestPublishing.y = [string]$negativePlan.externalResponseTrusts.clientSigning.y
        }
        elseif ($trustNegative -ceq 'release-duplicate-key-id') {
            $negativePlan.releaseManifestTrust.keyId = [string]$negativePlan.externalResponseTrusts.clientSigning.keyId
        }
        else {
            $negativePlan.releaseManifestTrust.x = [string]$negativePlan.externalResponseTrusts.clientSigning.x
            $negativePlan.releaseManifestTrust.y = [string]$negativePlan.externalResponseTrusts.clientSigning.y
        }
        Write-Json -Path $negativePlanPath -Value $negativePlan
        $expectedTrustFailure = if ($trustNegative -in @('duplicate-key-id', 'release-duplicate-key-id')) {
            'five distinct key IDs'
        }
        elseif ($trustNegative -in @('duplicate-public-key', 'release-duplicate-public-key')) {
            'five distinct P-256 public key'
        }
        else {
            'not valid'
        }
        [void](Invoke-Orchestrator -ScriptPath $orchestrator -RepoRoot $sourceRepo -Edition Enterprise -Phase Prepare -PlanPath $negativePlanPath -StateRoot (Join-Path $fixtureRoot "trust-$trustNegative-state") -ExpectFailure -ExpectedMessage $expectedTrustFailure)
    }

    foreach ($planShapeNegative in @(
            'missing-release-trust', 'wrong-release-purpose',
            'missing-release-compatibility', 'unknown-release-compatibility',
            'wrong-enterprise-release-compatibility')) {
        $negativePlan = Read-Json -Path $stableV2PlanPath
        if ($planShapeNegative -ceq 'missing-release-trust') {
            $negativePlan.PSObject.Properties.Remove('releaseManifestTrust')
        }
        elseif ($planShapeNegative -ceq 'wrong-release-purpose') {
            $negativePlan.releaseManifestTrust.purpose = 'manifest-publishing-response'
        }
        elseif ($planShapeNegative -ceq 'missing-release-compatibility') {
            $negativePlan.PSObject.Properties.Remove('releaseCompatibility')
        }
        elseif ($planShapeNegative -ceq 'unknown-release-compatibility') {
            $negativePlan.releaseCompatibility | Add-Member -NotePropertyName unknown -NotePropertyValue 1
        }
        else {
            $negativePlan.releaseCompatibility.startupStubProtocol = 2
        }
        $negativePlanPath = Join-Path $evidenceRoot ($planShapeNegative + '-plan-v2.json')
        Write-Json -Path $negativePlanPath -Value $negativePlan
        [void](Invoke-Orchestrator -ScriptPath $orchestrator -RepoRoot $sourceRepo -Edition Enterprise -Phase Prepare -PlanPath $negativePlanPath -StateRoot (Join-Path $fixtureRoot ($planShapeNegative + '-state')) -ExpectFailure -ExpectedMessage 'not valid')
    }
    foreach ($personalCompatibilityNegative in @(
            'missing-personal-compatibility-member',
            'wrong-personal-low-s-sequence')) {
        $negativePlan = Read-Json -Path $pilotV2PlanPath
        if ($personalCompatibilityNegative -ceq 'missing-personal-compatibility-member') {
            $negativePlan.releaseCompatibility.PSObject.Properties.Remove(
                'canonicalLowSFromSequence')
        }
        else {
            $negativePlan.releaseCompatibility.canonicalLowSFromSequence = 0
        }
        $negativePlanPath = Join-Path $evidenceRoot ($personalCompatibilityNegative + '-plan-v2.json')
        Write-Json -Path $negativePlanPath -Value $negativePlan
        [void](Invoke-Orchestrator -ScriptPath $orchestrator -RepoRoot $sourceRepo -Edition Personal -Phase Prepare -PlanPath $negativePlanPath -StateRoot (Join-Path $fixtureRoot ($personalCompatibilityNegative + '-state')) -ExpectFailure -ExpectedMessage 'not valid')
    }
    $enterprisePilotPlan = Read-Json -Path $stableV2PlanPath
    $enterprisePilotPlan.targetChannel = 'pilot'
    $enterprisePilotPlan.manifestUri = 'https://updates.example.invalid/v2/channels/pilot/release-set.v2.json'
    $enterprisePilotPlanPath = Join-Path $evidenceRoot 'enterprise-pilot-plan-v2.json'
    Write-Json -Path $enterprisePilotPlanPath -Value $enterprisePilotPlan
    [void](Invoke-Orchestrator -ScriptPath $orchestrator -RepoRoot $sourceRepo -Edition Enterprise -Phase Prepare -PlanPath $enterprisePilotPlanPath -StateRoot (Join-Path $fixtureRoot 'enterprise-pilot-plan-v2-state') -ExpectFailure -ExpectedMessage 'not valid')

    $trustDomainNames = @(
        'releaseManifestTrust', 'clientSigning', 'manifestPublishing',
        'installerSigning', 'feedPromotion')
    $invalidCoordinate = ConvertTo-Base64Url -Bytes ([byte[]]::new(32))
    foreach ($trustDomainName in $trustDomainNames) {
        $invalidPointPlan = $stableV2Plan | ConvertTo-Json -Depth 64 -Compress | ConvertFrom-Json -Depth 64 -DateKind String
        $invalidPointTrust = if ($trustDomainName -ceq 'releaseManifestTrust') {
            $invalidPointPlan.releaseManifestTrust
        }
        else {
            $invalidPointPlan.externalResponseTrusts.PSObject.Properties[$trustDomainName].Value
        }
        $invalidPointTrust.x = $invalidCoordinate
        $invalidPointTrust.y = $invalidCoordinate
        $invalidPointPlanPath = Join-Path $evidenceRoot "enterprise-stable-v2-$trustDomainName-invalid-point.json"
        Write-Json -Path $invalidPointPlanPath -Value $invalidPointPlan
        $invalidPointState = Join-Path $fixtureRoot "trust-$trustDomainName-invalid-point-state"
        [void](Invoke-Orchestrator -ScriptPath $orchestrator -RepoRoot $sourceRepo -Edition Enterprise -Phase Prepare -PlanPath $invalidPointPlanPath -StateRoot $invalidPointState -ExpectFailure -ExpectedMessage 'not a valid P-256 public point')
        Assert-True (-not (Test-Path -LiteralPath $invalidPointState)) "Invalid P-256 $trustDomainName trust created a production state root."

        $nonCanonicalPlan = $stableV2Plan | ConvertTo-Json -Depth 64 -Compress | ConvertFrom-Json -Depth 64 -DateKind String
        $nonCanonicalTrust = if ($trustDomainName -ceq 'releaseManifestTrust') {
            $nonCanonicalPlan.releaseManifestTrust
        }
        else {
            $nonCanonicalPlan.externalResponseTrusts.PSObject.Properties[$trustDomainName].Value
        }
        $nonCanonicalTrust.x = ConvertTo-NonCanonicalBase64Url -Value ([string]$nonCanonicalTrust.x)
        $nonCanonicalPlanPath = Join-Path $evidenceRoot "enterprise-stable-v2-$trustDomainName-noncanonical-point.json"
        Write-Json -Path $nonCanonicalPlanPath -Value $nonCanonicalPlan
        $nonCanonicalState = Join-Path $fixtureRoot "trust-$trustDomainName-noncanonical-point-state"
        [void](Invoke-Orchestrator -ScriptPath $orchestrator -RepoRoot $sourceRepo -Edition Enterprise -Phase Prepare -PlanPath $nonCanonicalPlanPath -StateRoot $nonCanonicalState -ExpectFailure -ExpectedMessage 'not canonical base64url')
        Assert-True (-not (Test-Path -LiteralPath $nonCanonicalState)) "Non-canonical P-256 $trustDomainName trust created a production state root."
    }

    $requestRaceRepo = Join-Path $fixtureRoot 'request-head-race-repo'
    [void](Invoke-Git -Root $fixtureRoot -Arguments @('clone', '--quiet', $sourceRepo, $requestRaceRepo))
    [void](Invoke-Git -Root $requestRaceRepo -Arguments @(
        'config', '--local', 'core.autocrlf', 'false'))
    [void](Invoke-Git -Root $requestRaceRepo -Arguments @('config', 'user.email', 'launcher-race@ensou.invalid'))
    [void](Invoke-Git -Root $requestRaceRepo -Arguments @('config', 'user.name', 'ensou-launcher-race'))
    $requestRacePlanPath = Join-Path $evidenceRoot 'personal-pilot-request-head-race-plan-v2.json'
    $requestRacePlan = $pilotV2Plan | ConvertTo-Json -Depth 64 -Compress | ConvertFrom-Json -Depth 64 -DateKind String
    $requestRacePlan.orchestrationId = [Guid]::NewGuid().ToString()
    $requestRacePlan.sourceCommit = [string]@(Invoke-Git -Root $requestRaceRepo -Arguments @('rev-parse', 'HEAD'))[0]
    Write-Json -Path $requestRacePlanPath -Value $requestRacePlan
    $requestRaceState = Join-Path $fixtureRoot 'request-head-race-state'
    $requestRaceOrchestrator = Join-Path $requestRaceRepo 'release\scripts\Invoke-LauncherProductionRelease.ps1'
    [void](Invoke-Orchestrator `
        -ScriptPath $requestRaceOrchestrator `
        -RepoRoot $requestRaceRepo `
        -Edition Personal `
        -Phase Prepare `
        -PlanPath $requestRacePlanPath `
        -StateRoot $requestRaceState `
        -FaultPoint AfterPlanReceipt `
        -ExpectFailure `
        -ExpectedMessage 'INJECTED-CRASH')
    $requestRaceRecovered = Get-ProductionReleaseState `
        -StateRoot $requestRaceState `
        -StateSchemaPath $stateV2SchemaPath
    if ($null -eq $requestRaceRecovered.Head) {
        [void](Add-ProductionReleaseReceipt `
            -StateRoot $requestRaceState `
            -StateSchemaPath $stateV2SchemaPath `
            -Phase 'PLAN_ADMITTED' `
            -ExpectedPreviousPhase $null `
            -ExpectedHeadSha256 '' `
            -Data $requestRaceRecovered.OrphanReceipt.data)
        $requestRaceRecovered = Get-ProductionReleaseState `
            -StateRoot $requestRaceState `
            -StateSchemaPath $stateV2SchemaPath
    }
    Assert-True ([string]$requestRaceRecovered.Head.phase -ceq 'PLAN_ADMITTED') 'Request HEAD-race fixture did not stabilize at PLAN_ADMITTED.'
    $requestRaceSnapshotBefore = Get-StateTreeSnapshot -Path $requestRaceState
    $requestRaceResult = Invoke-OrchestratorHeadRace `
        -ScriptPath $requestRaceOrchestrator `
        -RepoRoot $requestRaceRepo `
        -Edition Personal `
        -Phase Prepare `
        -PlanPath $requestRacePlanPath `
        -StateRoot $requestRaceState `
        -Purpose request `
        -FaultPoint TestOnlyWaitBeforeRequestCheckoutAdmission
    Assert-True ((Get-StateTreeSnapshot -Path $requestRaceState) -ceq $requestRaceSnapshotBefore) 'Request HEAD race changed production-state inventory or bytes before checkout admission.'
    Assert-True (@(Get-ChildItem -LiteralPath $requestRaceResult.StateParent -Directory -Force -Filter ($requestRaceResult.StagingPrefix + '*')).Count -eq 0) 'Request HEAD race left operation-owned staging residue.'

    if ($realRfc3161FixtureAvailable -or $useProductRoleFixture) {
        $importRaceRepo = Join-Path $fixtureRoot 'import-head-race-repo'
        [void](Invoke-Git -Root $fixtureRoot -Arguments @('clone', '--quiet', $sourceRepo, $importRaceRepo))
        [void](Invoke-Git -Root $importRaceRepo -Arguments @(
            'config', '--local', 'core.autocrlf', 'false'))
        [void](Invoke-Git -Root $importRaceRepo -Arguments @('config', 'user.email', 'launcher-race@ensou.invalid'))
        [void](Invoke-Git -Root $importRaceRepo -Arguments @('config', 'user.name', 'ensou-launcher-race'))
        $importRaceFixture = Install-ImportHeadRaceTrustStub `
            -FixtureRoot $fixtureRoot `
            -ImportRaceRepositoryRoot $importRaceRepo `
            -ExpectedSourceSha256 (Get-Sha256 -Path $orchestrator)
        Assert-True `
            ((Get-Sha256 -Path $orchestrator) -ceq
             [string]$importRaceFixture.SourceSha256) `
            'Import HEAD-race fixture instrumentation changed the admitted source checkout.'
        Assert-True `
            ((Test-Path -LiteralPath $importRaceFixture.MarkerPath -PathType Leaf) -and
             @(Get-ChildItem -LiteralPath $importRaceRepo -Force -Recurse `
                    -Filter '.test-only-import-head-race-not-release-acceptance').Count -eq 1) `
            'Import HEAD-race test-only non-release marker is absent or duplicated.'
        Write-Output `
            'IMPORT-HEAD-RACE-TEST-ONLY-CHECKOUT-CAS-NOT-RELEASE-ACCEPTANCE: authentic signed-role and native-probe acceptance remain separate release gates.'
        $importRacePlanPath = Join-Path $evidenceRoot 'personal-pilot-import-head-race-plan-v2.json'
        $importRacePlan = $pilotV2Plan | ConvertTo-Json -Depth 64 -Compress | ConvertFrom-Json -Depth 64 -DateKind String
        $importRacePlan.orchestrationId = [Guid]::NewGuid().ToString()
        $importRacePlan.sourceCommit = [string]@(Invoke-Git -Root $importRaceRepo -Arguments @('rev-parse', 'HEAD'))[0]
        Write-Json -Path $importRacePlanPath -Value $importRacePlan
        $importRaceState = Join-Path $fixtureRoot 'import-head-race-state'
        $importRaceOrchestrator = Join-Path $importRaceRepo 'release\scripts\Invoke-LauncherProductionRelease.ps1'
        [void](Invoke-Orchestrator `
            -ScriptPath $importRaceOrchestrator `
            -RepoRoot $importRaceRepo `
            -Edition Personal `
            -Phase Prepare `
            -PlanPath $importRacePlanPath `
            -StateRoot $importRaceState)
        $importRaceResponsePath = New-ResponseFixture `
            -RequestPath (Join-Path $importRaceState 'requests\client-signing.v1\signing-request.v1.json') `
            -OutputRoot (Join-Path $fixtureRoot 'import-head-race-response') `
            -Signer $responseSigner `
            -CheckoutCasCryptoFixture
        $importRaceSnapshotBefore = Get-StateTreeSnapshot -Path $importRaceState
        $importRaceResult = Invoke-OrchestratorHeadRace `
            -ScriptPath $importRaceOrchestrator `
            -RepoRoot $importRaceRepo `
            -Edition Personal `
            -Phase ImportClientSignatures `
            -PlanPath $importRacePlanPath `
            -StateRoot $importRaceState `
            -Purpose import `
            -FaultPoint TestOnlyWaitBeforeImportCheckoutAdmission `
            -ResponsePath $importRaceResponsePath `
            -ExpectedHeadSha256 (Get-Sha256 -Path (Join-Path $importRaceState 'head.json'))
        Assert-True ((Get-StateTreeSnapshot -Path $importRaceState) -ceq $importRaceSnapshotBefore) 'Import HEAD race changed production-state inventory or bytes before checkout admission.'
        Assert-True (@(Get-ChildItem -LiteralPath $importRaceResult.StateParent -Directory -Force -Filter ($importRaceResult.StagingPrefix + '*')).Count -eq 0) 'Import HEAD race left operation-owned staging residue.'
    }
    else {
        Write-Output 'IMPORT-HEAD-RACE-PENDING-REAL-TRUSTED-RFC3161-FIXTURE: request race remains mandatory; import race runs wherever real trusted RFC3161 admission is available.'
    }

    $personalState = Join-Path $fixtureRoot 'personal-state'
    $enterpriseState = Join-Path $fixtureRoot 'enterprise-state'
    $personalPrepare = Invoke-Orchestrator -ScriptPath $orchestrator -RepoRoot $sourceRepo -Edition Personal -Phase Prepare -PlanPath $personalPlanPath -StateRoot $personalState
    $enterprisePrepare = Invoke-Orchestrator -ScriptPath $orchestrator -RepoRoot $sourceRepo -Edition Enterprise -Phase Prepare -PlanPath $enterprisePlanPath -StateRoot $enterpriseState
    Assert-True (($personalPrepare.Output -join ' ').Contains('IMMUTABLE_SOURCE_RELEASE_UNVERIFIED')) 'Personal Prepare did not remain explicit NO-GO.'
    Assert-True (($enterprisePrepare.Output -join ' ').Contains('IMMUTABLE_SOURCE_RELEASE_UNVERIFIED')) 'Enterprise Prepare did not remain explicit NO-GO.'
    $personalHeadPath = Join-Path $personalState 'head.json'
    $enterpriseHeadPath = Join-Path $enterpriseState 'head.json'
    $personalHead = Read-Json -Path $personalHeadPath
    $enterpriseHead = Read-Json -Path $enterpriseHeadPath
    Assert-True ([string]$personalHead.phase -ceq 'CLIENT_SIGNING_REQUESTED') 'Personal Prepare did not reach client signing request.'
    Assert-True ([string]$enterpriseHead.phase -ceq 'CLIENT_SIGNING_REQUESTED') 'Enterprise Prepare did not reach client signing request.'
    $planReceipt = Read-Json -Path (Join-Path $personalState 'receipts\0001-plan-admitted.json')
    Assert-True ([string]$planReceipt.data.sourceCommit -ceq $commit) 'Plan receipt lost the Launcher source commit.'
    Assert-True ([string]$planReceipt.data.runtimeCandidate.publicationStatus -ceq 'IMMUTABLE_SOURCE_RELEASE_UNVERIFIED') 'Local runtime candidate was mislabeled as immutable admission.'

    $statusUpgradeRepo = Join-Path $fixtureRoot 'v1-status-upgrade-repo'
    [void](Invoke-Git -Root $fixtureRoot -Arguments @('clone', '--quiet', $sourceRepo, $statusUpgradeRepo))
    [void](Invoke-Git -Root $statusUpgradeRepo -Arguments @(
        'config', '--local', 'core.autocrlf', 'false'))
    $statusUpgradeState = Join-Path $fixtureRoot 'v1-status-upgrade-state'
    $statusUpgradeOrchestrator = Join-Path $statusUpgradeRepo 'release\scripts\Invoke-LauncherProductionRelease.ps1'
    Copy-State -Source $frozenV1StateRoot -Destination $statusUpgradeState
    $statusUpgradePlanPath = Join-Path $statusUpgradeState 'plan.json'
    [void](Invoke-Git -Root $statusUpgradeRepo -Arguments @(
        '-c', 'user.email=launcher-test@ensou.invalid',
        '-c', 'user.name=ensou-launcher-test',
        'commit', '--allow-empty', '--quiet', '-m', 'new orchestrator checkout'))
    $statusUpgradeSnapshotBefore = Get-StateTreeSnapshot -Path $statusUpgradeState
    $crossCommitStatus = Invoke-Orchestrator -ScriptPath $statusUpgradeOrchestrator -RepoRoot $statusUpgradeRepo -Edition Personal -Phase Status -PlanPath $statusUpgradePlanPath -StateRoot $statusUpgradeState
    Assert-True (($crossCommitStatus.Output -join ' ').Contains('PLAN_ADMITTED', [StringComparison]::Ordinal)) 'Current Orchestrator Status could not replay a v1 state bound to an older source commit.'
    Assert-True ((Get-StateTreeSnapshot -Path $statusUpgradeState) -ceq $statusUpgradeSnapshotBefore) 'Cross-commit Status changed production state inventory or bytes.'
    foreach ($mutatingPhase in @(
            'Prepare',
            'ImportClientSignatures',
            'PrepareManifestSigning',
            'ImportSignedCandidate',
            'PrepareInstallerSigning',
            'ImportInstallerSignature',
            'BindPilotEvidence',
            'Promote')) {
        $v1MutationSnapshotBefore = Get-StateTreeSnapshot -Path $statusUpgradeState
        [void](Invoke-Orchestrator `
            -ScriptPath $statusUpgradeOrchestrator `
            -RepoRoot $statusUpgradeRepo `
            -Edition Personal `
            -Phase $mutatingPhase `
            -PlanPath $statusUpgradePlanPath `
            -StateRoot $statusUpgradeState `
            -ExpectFailure `
            -ExpectedMessage 'historical Status replay only')
        Assert-True `
            ((Get-StateTreeSnapshot -Path $statusUpgradeState) -ceq
                $v1MutationSnapshotBefore) `
            "Plan v1 mutating phase '$mutatingPhase' changed historical state."
    }

    $emptyStatusState = Join-Path $fixtureRoot 'status-empty-existing-state'
    [IO.Directory]::CreateDirectory($emptyStatusState) | Out-Null
    $emptyStatusSnapshotBefore = Get-StateTreeSnapshot -Path $emptyStatusState
    [void](Invoke-Orchestrator -ScriptPath $statusUpgradeOrchestrator -RepoRoot $statusUpgradeRepo -Edition Personal -Phase Status -PlanPath $statusUpgradePlanPath -StateRoot $emptyStatusState -ExpectFailure -ExpectedMessage 'lock file is missing')
    Assert-True ((Get-StateTreeSnapshot -Path $emptyStatusState) -ceq $emptyStatusSnapshotBefore) 'Status populated an empty pre-existing state root.'

    $headlessV1StatusState = Join-Path $fixtureRoot 'status-headless-v1-orphan-state'
    Copy-State -Source $statusUpgradeState -Destination $headlessV1StatusState
    Remove-Item -LiteralPath (Join-Path $headlessV1StatusState 'head.json') -Force
    $headlessV1SnapshotBefore = Get-StateTreeSnapshot -Path $headlessV1StatusState
    $headlessV1Status = Invoke-Orchestrator `
        -ScriptPath $statusUpgradeOrchestrator `
        -RepoRoot $statusUpgradeRepo `
        -Edition Personal `
        -Phase Status `
        -PlanPath $statusUpgradePlanPath `
        -StateRoot $headlessV1StatusState
    Assert-True `
        (($headlessV1Status.Output -join ' ').Contains(
            'PLAN_ADMITTED',
            [StringComparison]::Ordinal)) `
        'Historical v1 Status could not replay one valid orphan transition without a head.'
    Assert-True `
        ((Get-StateTreeSnapshot -Path $headlessV1StatusState) -ceq
            $headlessV1SnapshotBefore) `
        'Historical v1 orphan Status replay created or recovered a head.'

    foreach ($optionalV1Directory in @('requests', 'imports')) {
        $optionalV1StatusState = Join-Path `
            $fixtureRoot `
            "status-without-$optionalV1Directory-v1-state"
        Copy-State `
            -Source $statusUpgradeState `
            -Destination $optionalV1StatusState
        Remove-Item `
            -LiteralPath (Join-Path $optionalV1StatusState $optionalV1Directory) `
            -Recurse `
            -Force
        $optionalV1SnapshotBefore = Get-StateTreeSnapshot `
            -Path $optionalV1StatusState
        $optionalV1Status = Invoke-Orchestrator `
            -ScriptPath $statusUpgradeOrchestrator `
            -RepoRoot $statusUpgradeRepo `
            -Edition Personal `
            -Phase Status `
            -PlanPath $statusUpgradePlanPath `
            -StateRoot $optionalV1StatusState
        Assert-True `
            (($optionalV1Status.Output -join ' ').Contains(
                'PLAN_ADMITTED',
                [StringComparison]::Ordinal)) `
            "Historical v1 Status could not replay without optional empty '$optionalV1Directory'."
        Assert-True `
            ((Get-StateTreeSnapshot -Path $optionalV1StatusState) -ceq
                $optionalV1SnapshotBefore) `
            "Historical v1 Status recreated optional empty '$optionalV1Directory'."
    }

    foreach ($missingStateEntry in @(
            'state.lock',
            'identity.json',
            'plan.json',
            'receipts')) {
        $caseLabel = $missingStateEntry.Replace('.', '-').Replace([IO.Path]::DirectorySeparatorChar, '-')
        $missingEntryStatusState = Join-Path $fixtureRoot "status-missing-$caseLabel-state"
        Copy-State -Source $statusUpgradeState -Destination $missingEntryStatusState
        $missingEntryPath = Join-Path $missingEntryStatusState $missingStateEntry
        $missingEntry = Get-Item -LiteralPath $missingEntryPath -Force
        if ($missingEntry.PSIsContainer) {
            Remove-Item -LiteralPath $missingEntryPath -Recurse -Force
        }
        else {
            Remove-Item -LiteralPath $missingEntryPath -Force
        }
        $missingEntrySnapshotBefore = Get-StateTreeSnapshot -Path $missingEntryStatusState
        [void](Invoke-Orchestrator -ScriptPath $statusUpgradeOrchestrator -RepoRoot $statusUpgradeRepo -Edition Personal -Phase Status -PlanPath $statusUpgradePlanPath -StateRoot $missingEntryStatusState -ExpectFailure)
        Assert-True ((Get-StateTreeSnapshot -Path $missingEntryStatusState) -ceq $missingEntrySnapshotBefore) "Status recreated or repaired missing expected state entry '$missingStateEntry'."
    }

    $pilotV2State = Join-Path $fixtureRoot 'personal-pilot-v2-state'
    $stableV2State = Join-Path $fixtureRoot 'enterprise-stable-v2-state'
    [void](Invoke-Orchestrator -ScriptPath $orchestrator -RepoRoot $sourceRepo -Edition Personal -Phase Prepare -PlanPath $pilotV2PlanPath -StateRoot $pilotV2State)
    [void](Invoke-Orchestrator -ScriptPath $orchestrator -RepoRoot $sourceRepo -Edition Enterprise -Phase Prepare -PlanPath $stableV2PlanPath -StateRoot $stableV2State)
    $markerlessV2State = Join-Path $fixtureRoot 'markerless-v2-prepare-state'
    Copy-State -Source $pilotV2State -Destination $markerlessV2State
    Remove-Item -LiteralPath (Join-Path $markerlessV2State 'initialization.json') -Force
    $markerlessV2SnapshotBefore = Get-StateTreeSnapshot -Path $markerlessV2State
    [void](Invoke-Orchestrator `
        -ScriptPath $orchestrator `
        -RepoRoot $sourceRepo `
        -Edition Personal `
        -Phase Prepare `
        -PlanPath $pilotV2PlanPath `
        -StateRoot $markerlessV2State `
        -ExpectFailure `
        -ExpectedMessage 'not bound to an initialization owner')
    Assert-True ((Get-StateTreeSnapshot -Path $markerlessV2State) -ceq $markerlessV2SnapshotBefore) 'Prepare adopted or mutated a markerless v2 state root.'
    $pilotV2Head = Read-Json -Path (Join-Path $pilotV2State 'head.json')
    $stableV2Head = Read-Json -Path (Join-Path $stableV2State 'head.json')
    Assert-True ([int]$pilotV2Head.schemaVersion -eq 2 -and [string]$pilotV2Head.targetChannel -ceq 'pilot' -and [string]$pilotV2Head.phase -ceq 'CLIENT_SIGNING_REQUESTED') 'Plan v2 Pilot Prepare did not preserve its versioned lifecycle state.'
    Assert-True ([int]$stableV2Head.schemaVersion -eq 2 -and [string]$stableV2Head.targetChannel -ceq 'stable' -and [string]$stableV2Head.phase -ceq 'CLIENT_SIGNING_REQUESTED') 'Plan v2 Stable Prepare did not preserve its versioned lifecycle state.'
    $stateC1Candidate = Read-Json -Path (Join-Path $pilotV2State 'receipts\0001-plan-admitted.json')
    $stateC1Candidate.data.manifestUri = [string]$stateC1Candidate.data.manifestUri + [char]0x85
    Assert-True (-not (Test-Json -Json ($stateC1Candidate | ConvertTo-Json -Depth 64 -Compress) -SchemaFile $stateV2SchemaPath -ErrorAction SilentlyContinue)) 'State v2 plan URI accepted the C1 control character U+0085.'
    $pilotV2Summary = Get-ProductionReleaseStateSummary -StateRoot $pilotV2State -StateSchemaPath (Join-Path $sourceRepo 'release\schemas\launcher-production-release-state-v2.schema.json')
    Assert-True ([string]$pilotV2Summary.NoGoCode -ceq 'CLIENT_SIGNATURES_REQUIRED') 'Plan v2 summary lost its machine NO-GO code.'
    Assert-True ([string]$pilotV2Summary.NextPhase -ceq 'CLIENT_SIGNATURES_IMPORTED') 'Plan v2 summary lost its next phase.'
    Assert-True ([string]$pilotV2Summary.ExpectedHeadSha256 -ceq (Get-Sha256 -Path (Join-Path $pilotV2State 'head.json'))) 'Plan v2 summary lost its state CAS head.'
    Assert-True ([string]$pilotV2Summary.RequestPath -ceq (Join-Path $pilotV2State 'requests\client-signing.v1\signing-request.v1.json')) 'Plan v2 summary lost its request handoff path.'
    Assert-True (-not [bool]$pilotV2Summary.PilotReady -and -not [bool]$pilotV2Summary.StableReady) 'Plan v2 foundation incorrectly claimed external readiness.'

    $earlyStablePromotionRoot = Join-Path `
        $fixtureRoot `
        'must-not-create-early-stable-promotion'
    $earlyStableStateSnapshot = Get-StateTreeSnapshot -Path $stableV2State
    [void](Invoke-Orchestrator `
        -ScriptPath $orchestrator `
        -RepoRoot $sourceRepo `
        -Edition Enterprise `
        -Phase Promote `
        -PlanPath $stableV2PlanPath `
        -StateRoot $stableV2State `
        -PromotionRoot $earlyStablePromotionRoot `
        -FeedPromotionResponsePath (
            Join-Path $fixtureRoot 'must-not-read-feed-response.json') `
        -ExpectedFeedIdentitySha256 ('f' * 64) `
        -ExpectedChannelHead '{"state":"missing"}' `
        -ExpectedJournalHead '{"state":"missing"}' `
        -ExpectedHeadSha256 (Get-Sha256 -Path (
            Join-Path $stableV2State 'head.json')) `
        -ExpectFailure `
        -ExpectedMessage 'NO-GO: Enterprise Stable promotion can only prepare the authenticated r9 offline bundle from exact r8 Pilot evidence.')
    Assert-True `
        ((Get-StateTreeSnapshot -Path $stableV2State) -ceq
            $earlyStableStateSnapshot) `
        'Early Enterprise Stable Promote changed the pre-r8 production state.'
    Assert-True `
        (-not (Test-Path -LiteralPath $earlyStablePromotionRoot)) `
        'Early Enterprise Stable Promote created an external promotion root before r8.'

    $pilotV2OrphanState = Join-Path $fixtureRoot 'personal-pilot-v2-orphan-state'
    [void](Invoke-Orchestrator -ScriptPath $orchestrator -RepoRoot $sourceRepo -Edition Personal -Phase Prepare -PlanPath $pilotV2PlanPath -StateRoot $pilotV2OrphanState -FaultPoint AfterPlanReceipt -ExpectFailure -ExpectedMessage 'INJECTED-CRASH')
    [void](Invoke-Orchestrator -ScriptPath $orchestrator -RepoRoot $sourceRepo -Edition Personal -Phase Prepare -PlanPath $pilotV2PlanPath -StateRoot $pilotV2OrphanState)
    Assert-True ([string]((Read-Json -Path (Join-Path $pilotV2OrphanState 'head.json')).phase) -ceq 'CLIENT_SIGNING_REQUESTED') 'Plan v2 orphan transition did not recover through the data-driven table.'
    Assert-True (@(Get-ChildItem -LiteralPath (Join-Path $pilotV2OrphanState 'receipts') -Force).Count -eq 2) 'Plan v2 orphan recovery duplicated a transition receipt.'

    Assert-Throws -Label 'Plan v2 stale CAS after revision 2' -ExpectedMessage 'stale production state head' -Action {
        [void](Add-ProductionReleaseReceipt -StateRoot $pilotV2State -StateSchemaPath (Join-Path $sourceRepo 'release\schemas\launcher-production-release-state-v2.schema.json') -Phase 'CLIENT_SIGNATURES_IMPORTED' -ExpectedPreviousPhase 'CLIENT_SIGNING_REQUESTED' -ExpectedHeadSha256 ('0' * 64) -Data ([ordered]@{}))
    }
    [void](Invoke-Orchestrator `
        -ScriptPath $orchestrator `
        -RepoRoot $sourceRepo `
        -Edition Personal `
        -Phase PrepareManifestSigning `
        -PlanPath $pilotV2PlanPath `
        -StateRoot $pilotV2State `
        -ExpectFailure `
        -ExpectedMessage 'only be requested after the typed v2 client-signature import')
    [void](Invoke-Orchestrator `
        -ScriptPath $orchestrator `
        -RepoRoot $sourceRepo `
        -Edition Personal `
        -Phase ImportSignedCandidate `
        -PlanPath $pilotV2PlanPath `
        -StateRoot $pilotV2State `
        -ExpectFailure `
        -ExpectedMessage 'only be imported after its typed manifest-publishing request')
    foreach ($phaseBoundary in @(
            [pscustomobject]@{
                Command = 'PrepareInstallerSigning'
                Expected = 'only be prepared after its exact Pilot r5'
            },
            [pscustomobject]@{
                Command = 'ImportInstallerSignature'
                Expected = 'only be imported after its exact r6'
            },
            [pscustomobject]@{
                Command = 'BindPilotEvidence'
                Expected = 'PHASE_NOT_IMPLEMENTED_PILOT_EVIDENCE_BOUND'
            },
            [pscustomobject]@{
                Command = 'Promote'
                Expected = 'Personal Pilot Promote requires exact r7 Installer signature'
            })) {
        [void](Invoke-Orchestrator -ScriptPath $orchestrator -RepoRoot $sourceRepo -Edition Personal -Phase ([string]$phaseBoundary.Command) -PlanPath $pilotV2PlanPath -StateRoot $pilotV2State -ExpectFailure -ExpectedMessage ([string]$phaseBoundary.Expected))
    }

    $pilotV2RequestPath = Join-Path $pilotV2State 'requests\client-signing.v1\signing-request.v1.json'
    $stableV2RequestPath = Join-Path $stableV2State 'requests\client-signing.v1\signing-request.v1.json'
    $pilotV2ResponsePath = New-ResponseFixture -RequestPath $pilotV2RequestPath -OutputRoot (Join-Path $fixtureRoot 'personal-pilot-v2-response') -Signer $responseSigner
    $stableV2ResponsePath = New-ResponseFixture -RequestPath $stableV2RequestPath -OutputRoot (Join-Path $fixtureRoot 'enterprise-stable-v2-response') -Signer $responseSigner
    $pilotV2Request = Read-Json -Path $pilotV2RequestPath
    $stableV2Request = Read-Json -Path $stableV2RequestPath
    $pilotV2Response = Read-Json -Path $pilotV2ResponsePath
    $stableV2Response = Read-Json -Path $stableV2ResponsePath
    Assert-True ([string]$pilotV2Response.authentication.keyId -ceq [string]$pilotV2Request.responseAuthentication.keyId) 'Plan v2 Pilot response fixture did not use the request-declared authentication key.'
    Assert-True ([string]$stableV2Response.authentication.keyId -ceq [string]$stableV2Request.responseAuthentication.keyId) 'Plan v2 Stable response fixture did not use the request-declared authentication key.'
    foreach ($v2Exchange in @(
            [pscustomobject]@{ Request = $pilotV2Request; Response = $pilotV2Response },
            [pscustomobject]@{ Request = $stableV2Request; Response = $stableV2Response })) {
        Assert-True ([string]$v2Exchange.Request.responseAuthentication.purpose -ceq 'client-signing-response') 'Plan v2 request did not bind the client-signing purpose.'
        Assert-True ([string]$v2Exchange.Request.responseAuthentication.payloadType -ceq 'ensou-dsh-launcher-external-signing-response-authentication-v2') 'Plan v2 request did not bind the v2 authentication payload domain.'
        Assert-True ([string]$v2Exchange.Response.authentication.purpose -ceq [string]$v2Exchange.Request.responseAuthentication.purpose) 'Plan v2 response purpose differs from its request.'
        Assert-True ([string]$v2Exchange.Response.authentication.payloadType -ceq [string]$v2Exchange.Request.responseAuthentication.payloadType) 'Plan v2 response payload domain differs from its request.'
    }
    $highSClientResponsePath = New-ResponseFixture `
        -RequestPath $pilotV2RequestPath `
        -OutputRoot (Join-Path $fixtureRoot 'personal-pilot-v2-high-s-response') `
        -Signer $responseSigner `
        -HighS
    $highSClientState = Join-Path $fixtureRoot 'personal-pilot-v2-high-s-state'
    Copy-State -Source $pilotV2State -Destination $highSClientState
    $highSClientSnapshotBefore = Get-StateTreeSnapshot -Path $highSClientState
    [void](Invoke-Orchestrator `
        -ScriptPath $orchestrator `
        -RepoRoot $sourceRepo `
        -Edition Personal `
        -Phase ImportClientSignatures `
        -PlanPath $pilotV2PlanPath `
        -StateRoot $highSClientState `
        -ResponsePath $highSClientResponsePath `
        -ExpectedHeadSha256 (Get-Sha256 -Path (Join-Path $highSClientState 'head.json')) `
        -ExpectFailure `
        -ExpectedMessage 'not canonical low-S P1363')
    Assert-True ((Get-StateTreeSnapshot -Path $highSClientState) -ceq $highSClientSnapshotBefore) 'Plan v2 high-S client-signing response changed state before admission.'

    $keyIdReplay = $pilotV2Response | ConvertTo-Json -Depth 64 -Compress | ConvertFrom-Json -Depth 64 -DateKind String
    $keyIdReplayTrust = $pilotV2Plan.externalResponseTrusts.clientSigning | ConvertTo-Json -Depth 64 -Compress | ConvertFrom-Json -Depth 64 -DateKind String
    $keyIdReplay.authentication.keyId = 'rewritten-client-signing-key'
    $keyIdReplayTrust.keyId = 'rewritten-client-signing-key'
    Assert-Throws -Label 'Plan v2 authentication keyId replay' -ExpectedMessage 'signature is invalid' -Action {
        Assert-ProductionReleaseSigningResponseAuthentication -Response $keyIdReplay -Trust $keyIdReplayTrust
    }
    $purposeReplay = $pilotV2Response | ConvertTo-Json -Depth 64 -Compress | ConvertFrom-Json -Depth 64 -DateKind String
    $purposeReplayTrust = $pilotV2Plan.externalResponseTrusts.clientSigning | ConvertTo-Json -Depth 64 -Compress | ConvertFrom-Json -Depth 64 -DateKind String
    $purposeReplay.authentication.purpose = 'manifest-publishing-response'
    $purposeReplayTrust.purpose = 'manifest-publishing-response'
    Assert-Throws -Label 'Plan v2 authentication purpose replay' -ExpectedMessage 'signature is invalid' -Action {
        Assert-ProductionReleaseSigningResponseAuthentication -Response $purposeReplay -Trust $purposeReplayTrust
    }
    $payloadTypeReplay = $pilotV2Response | ConvertTo-Json -Depth 64 -Compress | ConvertFrom-Json -Depth 64 -DateKind String
    $payloadTypeReplay.authentication.payloadType = 'ensou-dsh-launcher-external-signing-response-authentication-v2-rewritten'
    $payloadTypeReplayPayload = Get-ProductionReleaseSigningResponseAuthenticationPayload -Response $payloadTypeReplay
    $encodedReplaySignature = [string]$payloadTypeReplay.authentication.value
    $paddedReplaySignature = $encodedReplaySignature.Replace('-', '+').Replace('_', '/') + '=='
    $replaySignature = [Convert]::FromBase64String($paddedReplaySignature)
    Assert-True (-not $responseSigner.VerifyData(
            $payloadTypeReplayPayload,
            $replaySignature,
            [Security.Cryptography.HashAlgorithmName]::SHA256,
            [Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)) 'Plan v2 authentication payloadType rewrite replayed a valid signature.'
    $semanticReplayRoot = Join-Path $fixtureRoot 'personal-pilot-v2-keyid-replay'
    [IO.Directory]::CreateDirectory($semanticReplayRoot) | Out-Null
    [IO.Directory]::CreateDirectory((Join-Path $semanticReplayRoot 'signed')) | Out-Null
    foreach ($signedFile in @(Get-ChildItem -LiteralPath (Join-Path ([IO.Path]::GetDirectoryName($pilotV2ResponsePath)) 'signed') -File)) {
        [IO.File]::Copy($signedFile.FullName, (Join-Path (Join-Path $semanticReplayRoot 'signed') $signedFile.Name), $false)
    }
    $semanticReplayResponsePath = Join-Path $semanticReplayRoot 'signing-response.v1.json'
    $semanticReplayResponse = Read-Json -Path $pilotV2ResponsePath
    $semanticReplayResponse.authentication.keyId = 'rewritten-client-signing-key'
    Write-Json -Path $semanticReplayResponsePath -Value $semanticReplayResponse
    $semanticReplayState = Join-Path $fixtureRoot 'personal-pilot-v2-keyid-replay-state'
    Copy-State -Source $pilotV2State -Destination $semanticReplayState
    $semanticReplaySnapshotBefore = Get-StateTreeSnapshot -Path $semanticReplayState
    [void](Invoke-Orchestrator -ScriptPath $orchestrator -RepoRoot $sourceRepo -Edition Personal -Phase ImportClientSignatures -PlanPath $pilotV2PlanPath -StateRoot $semanticReplayState -ResponsePath $semanticReplayResponsePath -ExpectedHeadSha256 (Get-Sha256 -Path (Join-Path $semanticReplayState 'head.json')) -ExpectFailure -ExpectedMessage 'exact request nonce and plan')
    Assert-True ((Get-StateTreeSnapshot -Path $semanticReplayState) -ceq $semanticReplaySnapshotBefore) 'Plan v2 rewritten response keyId changed state inventory or bytes.'
    $pilotV2ImportStagingPrefix = '.ensou-launcher-production-staging-' +
        ([Guid]::Parse([string]$pilotV2Plan.orchestrationId)).ToString('N') +
        '-import-'
    Assert-True (@(Get-ChildItem -LiteralPath $fixtureRoot -Directory -Force -Filter ($pilotV2ImportStagingPrefix + '*')).Count -eq 0) 'Rejected v2 keyId replay left import staging residue.'

    $v2AuthenticationImportNegatives = @(
        [pscustomobject]@{
            Label = 'payload-type-schema-rewrite'
            ExpectedMessage = 'not valid with the schema'
            Mutate = {
                param($response)
                $response.authentication.payloadType = 'ensou-dsh-launcher-external-signing-response-authentication-v1'
            }
        },
        [pscustomobject]@{
            Label = 'purpose-schema-rewrite'
            ExpectedMessage = 'not valid with the schema'
            Mutate = {
                param($response)
                $response.authentication.purpose = 'manifest-publishing-response'
            }
        },
        [pscustomobject]@{
            Label = 'v2-to-v1-shape-downgrade'
            ExpectedMessage = 'exact request nonce and plan'
            Mutate = {
                param($response)
                $response.authentication = [pscustomobject][ordered]@{
                    algorithm = [string]$response.authentication.algorithm
                    keyId = [string]$response.authentication.keyId
                    value = [string]$response.authentication.value
                }
            }
        },
        [pscustomobject]@{
            Label = 'schema-and-semantic-valid-signature-rewrite'
            ExpectedMessage = 'signature is invalid'
            Mutate = {
                param($response)
                $value = [string]$response.authentication.value
                $replacement = if ($value[0] -ceq 'A') { 'B' } else { 'A' }
                $response.authentication.value = $replacement + $value.Substring(1)
            }
        }
    )
    foreach ($authenticationNegative in $v2AuthenticationImportNegatives) {
        $negativeResponseRoot = Join-Path $fixtureRoot ("personal-pilot-v2-" + [string]$authenticationNegative.Label + '-response')
        $negativeResponsePath = New-MutatedResponseBundle -SourceResponsePath $pilotV2ResponsePath -OutputRoot $negativeResponseRoot -Mutate $authenticationNegative.Mutate
        $negativeState = Join-Path $fixtureRoot ("personal-pilot-v2-" + [string]$authenticationNegative.Label + '-state')
        Copy-State -Source $pilotV2State -Destination $negativeState
        $negativeStateSnapshotBefore = Get-StateTreeSnapshot -Path $negativeState
        [void](Invoke-Orchestrator -ScriptPath $orchestrator -RepoRoot $sourceRepo -Edition Personal -Phase ImportClientSignatures -PlanPath $pilotV2PlanPath -StateRoot $negativeState -ResponsePath $negativeResponsePath -ExpectedHeadSha256 (Get-Sha256 -Path (Join-Path $negativeState 'head.json')) -ExpectFailure -ExpectedMessage ([string]$authenticationNegative.ExpectedMessage))
        Assert-True ((Get-StateTreeSnapshot -Path $negativeState) -ceq $negativeStateSnapshotBefore) "Plan v2 authentication negative '$($authenticationNegative.Label)' changed state before admission."
        Assert-True (@(Get-ChildItem -LiteralPath $fixtureRoot -Directory -Force -Filter ($pilotV2ImportStagingPrefix + '*')).Count -eq 0) "Plan v2 authentication negative '$($authenticationNegative.Label)' left import staging residue."
    }

    # Each CI shard owns a fresh fixture. The foundation block mutates copies,
    # while the import/tamper tail below consumes the untouched original r2.
    if ($Shard -in @('All', 'FoundationR8')) {
    $pilotV2FoundationState = Join-Path $fixtureRoot 'personal-pilot-v2-foundation-state-contract'
    $stableV2FoundationState = Join-Path $fixtureRoot 'enterprise-stable-v2-foundation-state-contract'
    Copy-State -Source $pilotV2State -Destination $pilotV2FoundationState
    Copy-State -Source $stableV2State -Destination $stableV2FoundationState
    Write-Output 'FOUNDATION-STATE-CONTRACT-ONLY: artificial r3 client evidence feeds real typed r4/r5 request/response/CAS tests and cannot substitute for production client-import admission.'
    & {
        param($pilotV2State, $stableV2State)

        [void](Add-V2FoundationStateContractClientEvidence -StateRoot $pilotV2State -StateSchemaPath $stateV2SchemaPath)
        [void](Add-V2FoundationStateContractClientEvidence -StateRoot $stableV2State -StateSchemaPath $stateV2SchemaPath)
        $pilotR3Source = Join-Path $fixtureRoot 'personal-pilot-v2-r3-foundation-source'
        $stableR3Source = Join-Path $fixtureRoot 'enterprise-stable-v2-r3-foundation-source'
        Copy-State -Source $pilotV2State -Destination $pilotR3Source
        Copy-State -Source $stableV2State -Destination $stableR3Source

        $casPublisherInput = New-PublisherInputFixture `
            -PlanPath $pilotV2PlanPath `
            -StateRoot $pilotR3Source `
            -OutputRoot (Join-Path $fixtureRoot 'personal-pilot-v2-r4-cas-publisher-input')
        Assert-ManifestFoundationFailurePreservesState `
            -Label 'Pilot manifest request missing exact r3 CAS' `
            -ScriptPath $orchestrator `
            -RepoRoot $sourceRepo `
            -Edition Personal `
            -Phase PrepareManifestSigning `
            -PlanPath $pilotV2PlanPath `
            -StateRoot $pilotR3Source `
            -PublisherInputPath $casPublisherInput `
            -ExpectedMessage 'requires -ExpectedHeadSha256'
        Assert-ManifestFoundationFailurePreservesState `
            -Label 'Pilot manifest request stale r3 CAS' `
            -ScriptPath $orchestrator `
            -RepoRoot $sourceRepo `
            -Edition Personal `
            -Phase PrepareManifestSigning `
            -PlanPath $pilotV2PlanPath `
            -StateRoot $pilotR3Source `
            -PublisherInputPath $casPublisherInput `
            -ExpectedHeadSha256 ('0' * 64) `
            -ExpectedMessage 'stale production state head'

        $pilotR4Source = Join-Path $fixtureRoot 'personal-pilot-v2-r4-foundation-source'
        Copy-State -Source $pilotR3Source -Destination $pilotR4Source
        $r4SourcePublisherInput = New-PublisherInputFixture `
            -PlanPath $pilotV2PlanPath `
            -StateRoot $pilotR4Source `
            -OutputRoot (Join-Path $fixtureRoot 'personal-pilot-v2-r4-source-publisher-input')
        $pilotR3HeadSha256 = Get-Sha256 -Path (Join-Path $pilotR4Source 'head.json')
        [void](Invoke-Orchestrator `
            -ScriptPath $orchestrator `
            -RepoRoot $sourceRepo `
            -Edition Personal `
            -Phase PrepareManifestSigning `
            -PlanPath $pilotV2PlanPath `
            -StateRoot $pilotR4Source `
            -PublisherInputPath $r4SourcePublisherInput `
            -ExpectedHeadSha256 $pilotR3HeadSha256)
        $pilotR4HeadSha256 = Get-Sha256 -Path (Join-Path $pilotR4Source 'head.json')
        $pilotManifestRequestPath = Join-Path `
            $pilotR4Source `
            'requests\pilot-manifest-publishing.v1\manifest-publishing-request.v1.json'
        $pilotManifestResponsePath = New-ManifestPublishingResponseFixture `
            -RequestPath $pilotManifestRequestPath `
            -AdmissionHeadSha256 $pilotR4HeadSha256 `
            -OutputRoot (Join-Path $fixtureRoot 'personal-pilot-v2-r5-source-response') `
            -Signer $manifestResponseSigner `
            -ReleaseSigner $releaseManifestSigner
        Assert-ManifestFoundationFailurePreservesState `
            -Label 'Pilot signed-candidate import missing exact r4 CAS' `
            -ScriptPath $orchestrator `
            -RepoRoot $sourceRepo `
            -Edition Personal `
            -Phase ImportSignedCandidate `
            -PlanPath $pilotV2PlanPath `
            -StateRoot $pilotR4Source `
            -ResponsePath $pilotManifestResponsePath `
            -ExpectedMessage 'requires -ExpectedHeadSha256'
        Assert-ManifestFoundationFailurePreservesState `
            -Label 'Pilot signed-candidate import stale r4 CAS' `
            -ScriptPath $orchestrator `
            -RepoRoot $sourceRepo `
            -Edition Personal `
            -Phase ImportSignedCandidate `
            -PlanPath $pilotV2PlanPath `
            -StateRoot $pilotR4Source `
            -ResponsePath $pilotManifestResponsePath `
            -ExpectedHeadSha256 ('0' * 64) `
            -ExpectedMessage 'stale production state head'

        foreach ($faultPoint in @(
                'AfterManifestRequestBundle',
                'AfterManifestRequestReceipt')) {
            $faultState = Join-Path $fixtureRoot ('personal-pilot-v2-' + $faultPoint + '-state')
            Copy-State -Source $pilotR3Source -Destination $faultState
            $faultPublisherInput = New-PublisherInputFixture `
                -PlanPath $pilotV2PlanPath `
                -StateRoot $faultState `
                -OutputRoot (Join-Path $fixtureRoot ('personal-pilot-v2-' + $faultPoint + '-publisher-input'))
            $faultHead = Get-Sha256 -Path (Join-Path $faultState 'head.json')
            [void](Invoke-Orchestrator `
                -ScriptPath $orchestrator `
                -RepoRoot $sourceRepo `
                -Edition Personal `
                -Phase PrepareManifestSigning `
                -PlanPath $pilotV2PlanPath `
                -StateRoot $faultState `
                -PublisherInputPath $faultPublisherInput `
                -ExpectedHeadSha256 $faultHead `
                -FaultPoint $faultPoint `
                -ExpectFailure `
                -ExpectedMessage 'INJECTED-CRASH')
            Assert-True ([int]((Read-Json -Path (Join-Path $faultState 'head.json')).revision) -eq 3) "r4 fault $faultPoint advanced the head before recovery."
            [void](Invoke-Orchestrator `
                -ScriptPath $orchestrator `
                -RepoRoot $sourceRepo `
                -Edition Personal `
                -Phase PrepareManifestSigning `
                -PlanPath $pilotV2PlanPath `
                -StateRoot $faultState `
                -PublisherInputPath $faultPublisherInput `
                -ExpectedHeadSha256 $faultHead)
            Assert-True ([int]((Read-Json -Path (Join-Path $faultState 'head.json')).revision) -eq 4) "r4 fault $faultPoint did not recover to r4."
            Assert-True (@(Get-ChildItem -LiteralPath (Join-Path $faultState 'receipts') -Force).Count -eq 4) "r4 fault $faultPoint duplicated a receipt."
        }
        foreach ($faultPoint in @(
                'AfterSignedCandidateBundle',
                'AfterSignedCandidateReceipt')) {
            $faultState = Join-Path $fixtureRoot ('personal-pilot-v2-' + $faultPoint + '-state')
            Copy-State -Source $pilotR4Source -Destination $faultState
            [void](Invoke-Orchestrator `
                -ScriptPath $orchestrator `
                -RepoRoot $sourceRepo `
                -Edition Personal `
                -Phase ImportSignedCandidate `
                -PlanPath $pilotV2PlanPath `
                -StateRoot $faultState `
                -ResponsePath $pilotManifestResponsePath `
                -ExpectedHeadSha256 $pilotR4HeadSha256 `
                -FaultPoint $faultPoint `
                -ExpectFailure `
                -ExpectedMessage 'INJECTED-CRASH')
            Assert-True ([int]((Read-Json -Path (Join-Path $faultState 'head.json')).revision) -eq 4) "r5 fault $faultPoint advanced the head before recovery."
            [void](Invoke-Orchestrator `
                -ScriptPath $orchestrator `
                -RepoRoot $sourceRepo `
                -Edition Personal `
                -Phase ImportSignedCandidate `
                -PlanPath $pilotV2PlanPath `
                -StateRoot $faultState `
                -ResponsePath $pilotManifestResponsePath `
                -ExpectedHeadSha256 $pilotR4HeadSha256)
            Assert-True ([int]((Read-Json -Path (Join-Path $faultState 'head.json')).revision) -eq 5) "r5 fault $faultPoint did not recover to r5."
            Assert-True (@(Get-ChildItem -LiteralPath (Join-Path $faultState 'receipts') -Force).Count -eq 5) "r5 fault $faultPoint duplicated a receipt."
        }

        $publisherInputNegativeCases = @(
            [pscustomobject]@{
                Label = 'noncanonical-json'
                ExpectedMessage = 'canonical UTF-8 JSON'
                Mutate = {
                    param($root)
                    $path = Join-Path $root 'publisher-input.v1.json'
                    Write-Json -Path $path -Value (Read-Json -Path $path)
                }
            },
            [pscustomobject]@{
                Label = 'unknown-member'
                ExpectedMessage = ''
                Mutate = {
                    param($root)
                    $path = Join-Path $root 'publisher-input.v1.json'
                    $value = Read-Json -Path $path
                    $value | Add-Member -NotePropertyName privateKeyPath -NotePropertyValue 'forbidden.pem'
                    Write-CanonicalJson -Path $path -Value $value
                }
            },
            [pscustomobject]@{
                Label = 'missing-component-release-id'
                ExpectedMessage = ''
                Mutate = {
                    param($root)
                    $path = Join-Path $root 'publisher-input.v1.json'
                    $value = Read-Json -Path $path
                    $value.componentReleaseIds.PSObject.Properties.Remove('clientBundle')
                    Write-CanonicalJson -Path $path -Value $value
                }
            },
            [pscustomobject]@{
                Label = 'unknown-component-release-id'
                ExpectedMessage = ''
                Mutate = {
                    param($root)
                    $path = Join-Path $root 'publisher-input.v1.json'
                    $value = Read-Json -Path $path
                    $value.componentReleaseIds | Add-Member -NotePropertyName extra -NotePropertyValue 'extra+release'
                    Write-CanonicalJson -Path $path -Value $value
                }
            },
            [pscustomobject]@{
                Label = 'component-release-id-property-case'
                ExpectedMessage = ''
                Mutate = {
                    param($root)
                    $path = Join-Path $root 'publisher-input.v1.json'
                    $value = Read-Json -Path $path
                    $clientBundle = [string]$value.componentReleaseIds.clientBundle
                    $value.componentReleaseIds.PSObject.Properties.Remove('clientBundle')
                    $value.componentReleaseIds | Add-Member -NotePropertyName ClientBundle -NotePropertyValue $clientBundle
                    Write-CanonicalJson -Path $path -Value $value
                }
            },
            [pscustomobject]@{
                Label = 'component-release-id-property-order'
                ExpectedMessage = 'noncanonical JSON member order'
                Mutate = {
                    param($root)
                    $path = Join-Path $root 'publisher-input.v1.json'
                    $value = Read-Json -Path $path
                    $clientBundle = [string]$value.componentReleaseIds.clientBundle
                    $value.componentReleaseIds.PSObject.Properties.Remove('clientBundle')
                    $value.componentReleaseIds | Add-Member -NotePropertyName clientBundle -NotePropertyValue $clientBundle
                    Write-CanonicalJson -Path $path -Value $value
                }
            },
            [pscustomobject]@{
                Label = 'component-release-id-colon'
                ExpectedMessage = ''
                Mutate = {
                    param($root)
                    $path = Join-Path $root 'publisher-input.v1.json'
                    $value = Read-Json -Path $path
                    $value.componentReleaseIds.clientBundle = 'client:release'
                    Write-CanonicalJson -Path $path -Value $value
                }
            },
            [pscustomobject]@{
                Label = 'runtime-component-release-id-mismatch'
                ExpectedMessage = 'runtime release ID does not equal'
                Mutate = {
                    param($root)
                    $path = Join-Path $root 'publisher-input.v1.json'
                    $value = Read-Json -Path $path
                    $value.componentReleaseIds.runtime = 'wrong+runtime'
                    Write-CanonicalJson -Path $path -Value $value
                }
            },
            [pscustomobject]@{
                Label = 'duplicate-member'
                ExpectedMessage = 'duplicate JSON member'
                Mutate = {
                    param($root)
                    $path = Join-Path $root 'publisher-input.v1.json'
                    $text = [IO.File]::ReadAllText($path, [Text.UTF8Encoding]::new($false, $true))
                    $text = $text.Replace(
                        '{"schemaVersion":1,',
                        '{"schemaVersion":1,"schemaVersion":1,')
                    [IO.File]::WriteAllText($path, $text, $utf8)
                }
            },
            [pscustomobject]@{
                Label = 'payload-tamper'
                ExpectedMessage = 'differs from its descriptor'
                Mutate = {
                    param($root)
                    $path = Join-Path $root 'payload\Ensou.Dsh.Launcher.exe'
                    $bytes = [IO.File]::ReadAllBytes($path)
                    $bytes[$bytes.Length - 1] = $bytes[$bytes.Length - 1] -bxor 1
                    [IO.File]::WriteAllBytes($path, $bytes)
                }
            },
            [pscustomobject]@{
                Label = 'extra-payload-file'
                ExpectedMessage = 'exact descriptor inventory'
                Mutate = {
                    param($root)
                    [IO.File]::WriteAllText(
                        (Join-Path $root 'payload\unexpected.bin'),
                        'unexpected',
                        $utf8)
                }
            }
        )
        foreach ($negativeCase in $publisherInputNegativeCases) {
            $negativeRoot = Join-Path $fixtureRoot ('personal-pilot-v2-publisher-' + $negativeCase.Label)
            Copy-State `
                -Source ([IO.Path]::GetDirectoryName($casPublisherInput)) `
                -Destination $negativeRoot
            & $negativeCase.Mutate $negativeRoot
            Assert-ManifestFoundationFailurePreservesState `
                -Label ('Publisher input ' + $negativeCase.Label) `
                -ScriptPath $orchestrator `
                -RepoRoot $sourceRepo `
                -Edition Personal `
                -Phase PrepareManifestSigning `
                -PlanPath $pilotV2PlanPath `
                -StateRoot $pilotR3Source `
                -PublisherInputPath (Join-Path $negativeRoot 'publisher-input.v1.json') `
                -ExpectedHeadSha256 (Get-Sha256 -Path (Join-Path $pilotR3Source 'head.json')) `
                -ExpectedMessage ([string]$negativeCase.ExpectedMessage)
        }

        $manifestResponseNegatives = @(
            [pscustomobject]@{
                Label = 'cross-edition'
                ExpectedMessage = ''
                Resign = $true
                HighS = $false
                NonCanonical = $false
                Mutate = { param($response, $candidateRoot) $response.edition = 'Enterprise' }
            },
            [pscustomobject]@{
                Label = 'cross-channel'
                ExpectedMessage = ''
                Resign = $true
                HighS = $false
                NonCanonical = $false
                Mutate = { param($response, $candidateRoot) $response.channel = 'stable' }
            },
            [pscustomobject]@{
                Label = 'cross-nonce'
                ExpectedMessage = 'not bound to the exact request'
                Resign = $true
                HighS = $false
                NonCanonical = $false
                Mutate = { param($response, $candidateRoot) $response.requestNonce = 'A' * 43 }
            },
            [pscustomobject]@{
                Label = 'cross-plan'
                ExpectedMessage = 'not bound to the exact request'
                Resign = $true
                HighS = $false
                NonCanonical = $false
                Mutate = { param($response, $candidateRoot) $response.planSha256 = '0' * 64 }
            },
            [pscustomobject]@{
                Label = 'cross-admission-head'
                ExpectedMessage = 'not bound to the exact request'
                Resign = $true
                HighS = $false
                NonCanonical = $false
                Mutate = { param($response, $candidateRoot) $response.admissionHeadSha256 = '0' * 64 }
            },
            [pscustomobject]@{
                Label = 'cross-expiry'
                ExpectedMessage = 'not bound to the exact request'
                Resign = $true
                HighS = $false
                NonCanonical = $false
                Mutate = { param($response, $candidateRoot) $response.requestExpiresAtUtc = '2099-01-01T00:00:00Z' }
            },
            [pscustomobject]@{
                Label = 'cross-key'
                ExpectedMessage = 'isolated plan trust domain'
                Resign = $false
                HighS = $false
                NonCanonical = $false
                Mutate = {
                    param($response, $candidateRoot)
                    $response.authentication.keyId = 'launcher-installer-signing-response-test'
                }
            },
            [pscustomobject]@{
                Label = 'cross-purpose'
                ExpectedMessage = ''
                Resign = $false
                HighS = $false
                NonCanonical = $false
                Mutate = {
                    param($response, $candidateRoot)
                    $response.authentication.purpose = 'installer-signing-response'
                }
            },
            [pscustomobject]@{
                Label = 'cross-payload-type'
                ExpectedMessage = ''
                Resign = $false
                HighS = $false
                NonCanonical = $false
                Mutate = {
                    param($response, $candidateRoot)
                    $response.authentication.payloadType =
                        'ensou-dsh-launcher-external-signing-response-authentication-v2'
                }
            },
            [pscustomobject]@{
                Label = 'cross-revision'
                ExpectedMessage = ''
                Resign = $false
                HighS = $false
                NonCanonical = $false
                Mutate = { param($response, $candidateRoot) $response.admissionRevision = 5 }
            },
            [pscustomobject]@{
                Label = 'signature-tamper'
                ExpectedMessage = 'signature is invalid'
                Resign = $false
                HighS = $false
                NonCanonical = $false
                Mutate = {
                    param($response, $candidateRoot)
                    $value = [string]$response.authentication.value
                    $response.authentication.value =
                        $(if ($value[0] -ceq 'A') { 'B' } else { 'A' }) +
                        $value.Substring(1)
                }
            },
            [pscustomobject]@{
                Label = 'high-s'
                ExpectedMessage = 'low-S'
                Resign = $false
                HighS = $true
                NonCanonical = $false
                Mutate = { param($response, $candidateRoot) }
            },
            [pscustomobject]@{
                Label = 'release-manifest-high-s'
                ExpectedMessage = 'not canonical low-S P1363'
                Resign = $true
                HighS = $false
                NonCanonical = $false
                Mutate = {
                    param($response, $candidateRoot)
                    $manifestPath = Join-Path $candidateRoot 'release-set.v2.json'
                    $manifest = Read-Json -Path $manifestPath
                    $low = ConvertFrom-Base64UrlFixture `
                        -Value ([string]$manifest.signature.value)
                    $manifest.signature.value = ConvertTo-Base64Url -Bytes (
                        ConvertTo-HighSP256Signature -LowSignature $low)
                    Write-CanonicalJson -Path $manifestPath -Value $manifest
                    $manifestItem = Get-Item -LiteralPath $manifestPath -Force
                    $response.files[0].sizeBytes = [int64]$manifestItem.Length
                    $response.files[0].sha256 = Get-Sha256 -Path $manifestPath
                }
            },
            [pscustomobject]@{
                Label = 'noncanonical-json'
                ExpectedMessage = 'canonical UTF-8 JSON'
                Resign = $false
                HighS = $false
                NonCanonical = $true
                Mutate = { param($response, $candidateRoot) }
            },
            [pscustomobject]@{
                Label = 'unknown-member'
                ExpectedMessage = ''
                Resign = $false
                HighS = $false
                NonCanonical = $false
                Mutate = {
                    param($response, $candidateRoot)
                    $response | Add-Member -NotePropertyName externalEvidenceData -NotePropertyValue 'forbidden'
                }
            },
            [pscustomobject]@{
                Label = 'candidate-tamper'
                ExpectedMessage = 'differs from its authenticated descriptor'
                Resign = $false
                HighS = $false
                NonCanonical = $false
                Mutate = {
                    param($response, $candidateRoot)
                    $path = Join-Path $candidateRoot 'release-set.v2.json'
                    $bytes = [IO.File]::ReadAllBytes($path)
                    $bytes[$bytes.Length - 1] = $bytes[$bytes.Length - 1] -bxor 1
                    [IO.File]::WriteAllBytes($path, $bytes)
                }
            },
            [pscustomobject]@{
                Label = 'extra-candidate-file'
                ExpectedMessage = 'exact expected inventory'
                Resign = $false
                HighS = $false
                NonCanonical = $false
                Mutate = {
                    param($response, $candidateRoot)
                    [IO.File]::WriteAllText(
                        (Join-Path $candidateRoot 'unexpected.bin'),
                        'unexpected',
                        $utf8)
                }
            }
        )
        foreach ($negativeCase in $manifestResponseNegatives) {
            $negativeResponsePath = New-MutatedManifestPublishingResponseBundle `
                -SourceResponsePath $pilotManifestResponsePath `
                -OutputRoot (Join-Path $fixtureRoot ('personal-pilot-v2-r5-' + $negativeCase.Label)) `
                -Mutate $negativeCase.Mutate `
                -Signer $manifestResponseSigner `
                -Resign:([bool]$negativeCase.Resign) `
                -HighS:([bool]$negativeCase.HighS) `
                -NonCanonical:([bool]$negativeCase.NonCanonical)
            Assert-ManifestFoundationFailurePreservesState `
                -Label ('Manifest response ' + $negativeCase.Label) `
                -ScriptPath $orchestrator `
                -RepoRoot $sourceRepo `
                -Edition Personal `
                -Phase ImportSignedCandidate `
                -PlanPath $pilotV2PlanPath `
                -StateRoot $pilotR4Source `
                -ResponsePath $negativeResponsePath `
                -ExpectedHeadSha256 $pilotR4HeadSha256 `
                -ExpectedMessage ([string]$negativeCase.ExpectedMessage)
        }
        $personalManifestPolicyNegatives = @(
            [pscustomobject]@{
                Label = 'schema-version-string'
                ExpectedMessage = 'Signed release manifest does not match the exact edition'
                Mutate = { param($manifest, $response, $candidateRoot) $manifest.schemaVersion = '2' }
            },
            [pscustomobject]@{
                Label = 'generation-string'
                ExpectedMessage = 'safe JSON integers'
                Mutate = { param($manifest, $response, $candidateRoot) $manifest.generation = '1' }
            },
            [pscustomobject]@{
                Label = 'sequence-fractional'
                ExpectedMessage = 'safe JSON integers'
                Mutate = { param($manifest, $response, $candidateRoot) $manifest.sequence = 1.5 }
            },
            [pscustomobject]@{
                Label = 'generation-unsafe-integer'
                ExpectedMessage = 'safe JSON integers'
                Mutate = { param($manifest, $response, $candidateRoot) $manifest.generation = 9007199254740992L }
            },
            [pscustomobject]@{
                Label = 'min-accepted-after-sequence'
                ExpectedMessage = 'safe JSON integers'
                Mutate = { param($manifest, $response, $candidateRoot) $manifest.minAcceptedSequence = 2L }
            },
            [pscustomobject]@{
                Label = 'validity-expired'
                ExpectedMessage = 'validity window'
                Mutate = {
                    param($manifest, $response, $candidateRoot)
                    $now = [DateTimeOffset]::ParseExact([string]$response.completedAtUtc, 'yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
                    $manifest.issuedAtUtc = $now.AddDays(-2).ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", [Globalization.CultureInfo]::InvariantCulture)
                    $manifest.expiresAtUtc = $now.AddHours(-1).ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", [Globalization.CultureInfo]::InvariantCulture)
                }
            },
            [pscustomobject]@{
                Label = 'validity-future'
                ExpectedMessage = 'validity window'
                Mutate = {
                    param($manifest, $response, $candidateRoot)
                    $now = [DateTimeOffset]::ParseExact([string]$response.completedAtUtc, 'yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
                    $manifest.issuedAtUtc = $now.AddMinutes(3).ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", [Globalization.CultureInfo]::InvariantCulture)
                    $manifest.expiresAtUtc = $now.AddDays(1).ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", [Globalization.CultureInfo]::InvariantCulture)
                }
            },
            [pscustomobject]@{
                Label = 'validity-reversed'
                ExpectedMessage = 'validity window'
                Mutate = {
                    param($manifest, $response, $candidateRoot)
                    $manifest.expiresAtUtc = [string]$manifest.issuedAtUtc
                }
            },
            [pscustomobject]@{
                Label = 'timestamp-not-seven-fractional-z'
                ExpectedMessage = 'seven fractional digits and Z'
                Mutate = {
                    param($manifest, $response, $candidateRoot)
                    $manifest.issuedAtUtc = ([DateTimeOffset]::UtcNow).ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
                }
            },
            [pscustomobject]@{
                Label = 'self-revocation'
                ExpectedMessage = 'revocation list'
                Mutate = { param($manifest, $response, $candidateRoot) $manifest.revokedReleaseSetIds = @([string]$manifest.releaseSetId) }
            },
            [pscustomobject]@{
                Label = 'duplicate-revocation'
                ExpectedMessage = 'revocation list'
                Mutate = { param($manifest, $response, $candidateRoot) $manifest.revokedReleaseSetIds = @('revoked-a', 'revoked-a') }
            },
            [pscustomobject]@{
                Label = 'unsorted-revocation'
                ExpectedMessage = 'revocation list'
                Mutate = { param($manifest, $response, $candidateRoot) $manifest.revokedReleaseSetIds = @('revoked-b', 'revoked-a') }
            },
            [pscustomobject]@{
                Label = 'revocation-count-over-limit'
                ExpectedMessage = 'revocation list exceeds'
                Mutate = {
                    param($manifest, $response, $candidateRoot)
                    $manifest.revokedReleaseSetIds = @(0..1000 | ForEach-Object { 'revoked-' + $_.ToString('D4') })
                }
            },
            [pscustomobject]@{
                Label = 'offline-grace-too-small'
                ExpectedMessage = 'release compatibility or source commit'
                Mutate = { param($manifest, $response, $candidateRoot) $manifest.maximumOfflineGraceSeconds = 3599L }
            },
            [pscustomobject]@{
                Label = 'launcher-provenance-mismatch'
                ExpectedMessage = 'source commit'
                Mutate = { param($manifest, $response, $candidateRoot) $manifest.provenance.launcherRepositoryCommit = '0' * 40 }
            },
            [pscustomobject]@{
                Label = 'runtime-tag-provenance-mismatch'
                ExpectedMessage = 'source commit'
                Mutate = { param($manifest, $response, $candidateRoot) $manifest.provenance.harnessSourceTag = 'wrong-runtime-tag' }
            },
            [pscustomobject]@{
                Label = 'runtime-commit-provenance-mismatch'
                ExpectedMessage = 'source commit'
                Mutate = { param($manifest, $response, $candidateRoot) $manifest.provenance.harnessSourceCommit = '0' * 40 }
            },
            [pscustomobject]@{
                Label = 'client-component-release-id-mismatch'
                ExpectedMessage = 'violates its exact edition'
                Mutate = { param($manifest, $response, $candidateRoot) $manifest.artifacts[0].releaseId = 'wrong+client' }
            },
            [pscustomobject]@{
                Label = 'runtime-component-release-id-mismatch'
                ExpectedMessage = 'violates its exact edition'
                Mutate = { param($manifest, $response, $candidateRoot) $manifest.artifacts[1].releaseId = 'wrong+runtime' }
            },
            [pscustomobject]@{
                Label = 'client-artifact-too-large'
                ExpectedMessage = 'violates its exact edition'
                Mutate = { param($manifest, $response, $candidateRoot) $manifest.artifacts[0].sizeBytes = 1073741825L }
            },
            [pscustomobject]@{
                Label = 'runtime-artifact-too-large'
                ExpectedMessage = 'violates its exact edition'
                Mutate = { param($manifest, $response, $candidateRoot) $manifest.artifacts[1].sizeBytes = 8589934593L }
            },
            [pscustomobject]@{
                Label = 'manifest-key-id-rewrite'
                ExpectedMessage = 'plan release-manifest trust'
                Mutate = { param($manifest, $response, $candidateRoot) $manifest.signature.keyId = 'rewritten-release-key' }
            },
            [pscustomobject]@{
                Label = 'artifact-uri-query'
                ExpectedMessage = 'Signed release-manifest artifact index 0 URI must be one absolute HTTPS artifact URI'
                Mutate = { param($manifest, $response, $candidateRoot) $manifest.artifacts[0].uri = [string]$manifest.artifacts[0].uri + '?replay=1' }
            },
            [pscustomobject]@{
                Label = 'artifact-file-name-case-collision'
                ExpectedMessage = 'case-insensitive candidate file-name collision'
                Mutate = {
                    param($manifest, $response, $candidateRoot)
                    $current = [string]$manifest.artifacts[0].uri
                    $base = $current.Substring(0, $current.LastIndexOf('/') + 1)
                    $manifest.artifacts[0].uri = $base + 'Collision.zip'
                    $manifest.artifacts[1].uri = $base + 'collision.zip'
                }
            },
            [pscustomobject]@{
                Label = 'manifest-over-512-kib'
                ExpectedMessage = '512 KiB'
                Mutate = {
                    param($manifest, $response, $candidateRoot)
                    $manifest.artifacts[0].uri = 'https://artifacts.example.invalid/' + ('a' * 530000) + '.zip'
                }
            }
        )
        foreach ($negativeCase in $personalManifestPolicyNegatives) {
            $negativeResponsePath = New-MutatedSignedCandidateManifestBundle `
                -SourceResponsePath $pilotManifestResponsePath `
                -OutputRoot (Join-Path $fixtureRoot ('personal-pilot-v2-policy-' + [string]$negativeCase.Label)) `
                -Mutate $negativeCase.Mutate `
                -ReleaseSigner $releaseManifestSigner `
                -ResponseSigner $manifestResponseSigner
            Assert-ManifestFoundationFailurePreservesState `
                -Label ('Personal manifest policy ' + [string]$negativeCase.Label) `
                -ScriptPath $orchestrator `
                -RepoRoot $sourceRepo `
                -Edition Personal `
                -Phase ImportSignedCandidate `
                -PlanPath $pilotV2PlanPath `
                -StateRoot $pilotR4Source `
                -ResponsePath $negativeResponsePath `
                -ExpectedHeadSha256 $pilotR4HeadSha256 `
                -ExpectedMessage ([string]$negativeCase.ExpectedMessage)
        }
        $artifactHighSResponsePath = New-MutatedSignedCandidateManifestBundle `
            -SourceResponsePath $pilotManifestResponsePath `
            -OutputRoot (Join-Path $fixtureRoot 'personal-pilot-v2-policy-artifact-high-s') `
            -Mutate { param($manifest, $response, $candidateRoot) } `
            -ReleaseSigner $releaseManifestSigner `
            -ResponseSigner $manifestResponseSigner `
            -HighSArtifactIndex 0
        Assert-ManifestFoundationFailurePreservesState `
            -Label 'Personal manifest artifact high-S malleation' `
            -ScriptPath $orchestrator `
            -RepoRoot $sourceRepo `
            -Edition Personal `
            -Phase ImportSignedCandidate `
            -PlanPath $pilotV2PlanPath `
            -StateRoot $pilotR4Source `
            -ResponsePath $artifactHighSResponsePath `
            -ExpectedHeadSha256 $pilotR4HeadSha256 `
            -ExpectedMessage 'not canonical low-S P1363'
        $wrongReleasePointResponsePath = New-MutatedSignedCandidateManifestBundle `
            -SourceResponsePath $pilotManifestResponsePath `
            -OutputRoot (Join-Path $fixtureRoot 'personal-pilot-v2-policy-wrong-release-point') `
            -Mutate { param($manifest, $response, $candidateRoot) } `
            -ReleaseSigner $manifestResponseSigner `
            -ResponseSigner $manifestResponseSigner
        Assert-ManifestFoundationFailurePreservesState `
            -Label 'Personal manifest wrong release signing point' `
            -ScriptPath $orchestrator `
            -RepoRoot $sourceRepo `
            -Edition Personal `
            -Phase ImportSignedCandidate `
            -PlanPath $pilotV2PlanPath `
            -StateRoot $pilotR4Source `
            -ResponsePath $wrongReleasePointResponsePath `
            -ExpectedHeadSha256 $pilotR4HeadSha256 `
            -ExpectedMessage 'artifact signature index 0 is invalid'
        $wrongTrustResponsePath = New-MutatedManifestPublishingResponseBundle `
            -SourceResponsePath $pilotManifestResponsePath `
            -OutputRoot (Join-Path $fixtureRoot 'personal-pilot-v2-r5-wrong-trust-signature') `
            -Mutate { param($response, $candidateRoot) } `
            -Signer $responseSigner `
            -Resign
        Assert-ManifestFoundationFailurePreservesState `
            -Label 'Manifest response signed by client-signing trust' `
            -ScriptPath $orchestrator `
            -RepoRoot $sourceRepo `
            -Edition Personal `
            -Phase ImportSignedCandidate `
            -PlanPath $pilotV2PlanPath `
            -StateRoot $pilotR4Source `
            -ResponsePath $wrongTrustResponsePath `
            -ExpectedHeadSha256 $pilotR4HeadSha256 `
            -ExpectedMessage 'signature is invalid'
        $duplicateResponseRoot = Join-Path $fixtureRoot 'personal-pilot-v2-r5-duplicate-member'
        $duplicateResponsePath = New-MutatedManifestPublishingResponseBundle `
            -SourceResponsePath $pilotManifestResponsePath `
            -OutputRoot $duplicateResponseRoot `
            -Mutate { param($response, $candidateRoot) }
        $duplicateResponseText = [IO.File]::ReadAllText(
            $duplicateResponsePath,
            [Text.UTF8Encoding]::new($false, $true))
        $duplicateResponseText = $duplicateResponseText.Replace(
            '{"schemaVersion":1,',
            '{"schemaVersion":1,"schemaVersion":1,')
        [IO.File]::WriteAllText($duplicateResponsePath, $duplicateResponseText, $utf8)
        Assert-ManifestFoundationFailurePreservesState `
            -Label 'Manifest response duplicate member' `
            -ScriptPath $orchestrator `
            -RepoRoot $sourceRepo `
            -Edition Personal `
            -Phase ImportSignedCandidate `
            -PlanPath $pilotV2PlanPath `
            -StateRoot $pilotR4Source `
            -ResponsePath $duplicateResponsePath `
            -ExpectedHeadSha256 $pilotR4HeadSha256 `
            -ExpectedMessage 'duplicate JSON member'

        $stableR4PolicySource = Join-Path $fixtureRoot 'enterprise-stable-v2-r4-policy-source'
        Copy-State -Source $stableR3Source -Destination $stableR4PolicySource
        $stablePolicyPublisherInput = New-PublisherInputFixture `
            -PlanPath $stableV2PlanPath `
            -StateRoot $stableR4PolicySource `
            -OutputRoot (Join-Path $fixtureRoot 'enterprise-stable-v2-r4-policy-publisher-input')
        $stablePolicyR3HeadSha256 = Get-Sha256 -Path (Join-Path $stableR4PolicySource 'head.json')
        [void](Invoke-Orchestrator `
            -ScriptPath $orchestrator `
            -RepoRoot $sourceRepo `
            -Edition Enterprise `
            -Phase PrepareManifestSigning `
            -PlanPath $stableV2PlanPath `
            -StateRoot $stableR4PolicySource `
            -PublisherInputPath $stablePolicyPublisherInput `
            -ExpectedHeadSha256 $stablePolicyR3HeadSha256)
        $stablePolicyR4HeadSha256 = Get-Sha256 -Path (Join-Path $stableR4PolicySource 'head.json')
        $stablePolicyRequestPath = Join-Path `
            $stableR4PolicySource `
            'requests\stable-manifest-publishing.v1\manifest-publishing-request.v1.json'
        $stablePolicyResponsePath = New-ManifestPublishingResponseFixture `
            -RequestPath $stablePolicyRequestPath `
            -AdmissionHeadSha256 $stablePolicyR4HeadSha256 `
            -OutputRoot (Join-Path $fixtureRoot 'enterprise-stable-v2-r5-policy-source-response') `
            -Signer $manifestResponseSigner `
            -ReleaseSigner $releaseManifestSigner
        $enterpriseManifestPolicyNegatives = @(
            [pscustomobject]@{
                Label = 'timestamp-not-seven-fractional-offset'
                ExpectedMessage = 'seven fractional digits and +00:00'
                Mutate = { param($manifest, $response, $candidateRoot) $manifest.issuedAtUtc = ([DateTimeOffset]::UtcNow).ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", [Globalization.CultureInfo]::InvariantCulture) }
            },
            [pscustomobject]@{
                Label = 'duplicate-revocation'
                ExpectedMessage = 'revocation list'
                Mutate = { param($manifest, $response, $candidateRoot) $manifest.revokedReleaseSetIds = @('revoked-a', 'revoked-a') }
            },
            [pscustomobject]@{
                Label = 'self-revocation'
                ExpectedMessage = 'revocation list'
                Mutate = { param($manifest, $response, $candidateRoot) $manifest.revokedReleaseSetIds = @([string]$manifest.releaseSetId) }
            },
            [pscustomobject]@{
                Label = 'launcher-component-release-id-mismatch'
                ExpectedMessage = 'violates its exact edition'
                Mutate = { param($manifest, $response, $candidateRoot) $manifest.artifacts[0].releaseId = 'wrong+launcher' }
            },
            [pscustomobject]@{
                Label = 'runtime-component-release-id-mismatch'
                ExpectedMessage = 'violates its exact edition'
                Mutate = { param($manifest, $response, $candidateRoot) $manifest.artifacts[1].releaseId = 'wrong+runtime' }
            },
            [pscustomobject]@{
                Label = 'plugin-policy-component-release-id-mismatch'
                ExpectedMessage = 'violates its exact edition'
                Mutate = { param($manifest, $response, $candidateRoot) $manifest.artifacts[2].releaseId = 'wrong+plugin' }
            },
            [pscustomobject]@{
                Label = 'launcher-artifact-too-large'
                ExpectedMessage = 'violates its exact edition'
                Mutate = { param($manifest, $response, $candidateRoot) $manifest.artifacts[0].sizeBytes = 1073741825L }
            },
            [pscustomobject]@{
                Label = 'runtime-artifact-too-large'
                ExpectedMessage = 'violates its exact edition'
                Mutate = { param($manifest, $response, $candidateRoot) $manifest.artifacts[1].sizeBytes = 8589934593L }
            },
            [pscustomobject]@{
                Label = 'plugin-policy-artifact-too-large'
                ExpectedMessage = 'violates its exact edition'
                Mutate = { param($manifest, $response, $candidateRoot) $manifest.artifacts[2].sizeBytes = 536870913L }
            },
            [pscustomobject]@{
                Label = 'startup-protocol-string'
                ExpectedMessage = 'Startup Stub protocol'
                Mutate = { param($manifest, $response, $candidateRoot) $manifest.startupStub.minimumProtocol = '1' }
            }
        )
        foreach ($negativeCase in $enterpriseManifestPolicyNegatives) {
            $negativeResponsePath = New-MutatedSignedCandidateManifestBundle `
                -SourceResponsePath $stablePolicyResponsePath `
                -OutputRoot (Join-Path $fixtureRoot ('enterprise-stable-v2-policy-' + [string]$negativeCase.Label)) `
                -Mutate $negativeCase.Mutate `
                -ReleaseSigner $releaseManifestSigner `
                -ResponseSigner $manifestResponseSigner `
                -UseGenericEnterprisePayloadForInvalidTimestampFixture:(
                    [string]$negativeCase.Label -ceq
                    'timestamp-not-seven-fractional-offset')
            Assert-ManifestFoundationFailurePreservesState `
                -Label ('Enterprise manifest policy ' + [string]$negativeCase.Label) `
                -ScriptPath $orchestrator `
                -RepoRoot $sourceRepo `
                -Edition Enterprise `
                -Phase ImportSignedCandidate `
                -PlanPath $stableV2PlanPath `
                -StateRoot $stableR4PolicySource `
                -ResponsePath $negativeResponsePath `
                -ExpectedHeadSha256 $stablePolicyR4HeadSha256 `
                -ExpectedMessage ([string]$negativeCase.ExpectedMessage)
        }
        $enterpriseInventoryNegatives = @(
            [pscustomobject]@{
                Label = 'missing-response-file'
                ExpectedMessage = ''
                Mutate = { param($response, $candidateRoot) $response.files = @($response.files | Select-Object -First 4) }
            },
            [pscustomobject]@{
                Label = 'role-case-rewrite'
                ExpectedMessage = ''
                Mutate = { param($response, $candidateRoot) $response.files[2].role = 'Launcher' }
            },
            [pscustomobject]@{
                Label = 'file-name-case-rewrite'
                ExpectedMessage = 'manifest-derived edition-fixed role'
                Mutate = {
                    param($response, $candidateRoot)
                    $response.files[2].fileName = ([string]$response.files[2].fileName).ToUpperInvariant()
                    $response.files[2].relativePath = 'candidate/' + [string]$response.files[2].fileName
                }
            },
            [pscustomobject]@{
                Label = 'response-file-name-collision'
                ExpectedMessage = 'Target-channel signed-candidate response repeats a file identity'
                Mutate = {
                    param($response, $candidateRoot)
                    $response.files[3].fileName = ([string]$response.files[2].fileName).ToUpperInvariant()
                    $response.files[3].relativePath = 'candidate/' + [string]$response.files[3].fileName
                }
            },
            [pscustomobject]@{
                Label = 'missing-candidate-file'
                ExpectedMessage = ''
                Mutate = { param($response, $candidateRoot) [IO.File]::Delete((Join-Path $candidateRoot ([string]$response.files[-1].fileName))) }
            },
            [pscustomobject]@{
                Label = 'nested-candidate-directory'
                ExpectedMessage = 'exact expected inventory'
                Mutate = {
                    param($response, $candidateRoot)
                    [IO.Directory]::CreateDirectory((Join-Path $candidateRoot 'nested')) | Out-Null
                }
            },
            [pscustomobject]@{
                Label = 'reparse-candidate-directory'
                ExpectedMessage = 'contains unexpected or linked entry'
                Mutate = {
                    param($response, $candidateRoot)
                    $replacedName = [string]$response.files[-1].fileName
                    [IO.File]::Delete((Join-Path $candidateRoot $replacedName))
                    $externalTarget = Join-Path ([IO.Path]::GetDirectoryName([IO.Path]::GetDirectoryName($candidateRoot))) ('junction-target-' + [Guid]::NewGuid().ToString('N'))
                    [IO.Directory]::CreateDirectory($externalTarget) | Out-Null
                    [void](New-Item -ItemType Junction -Path (Join-Path $candidateRoot $replacedName) -Target $externalTarget)
                }
            },
            [pscustomobject]@{
                Label = 'hardlinked-candidate-file'
                ExpectedMessage = 'Production-release files must be ordinary'
                Mutate = {
                    param($response, $candidateRoot)
                    $externalLink = Join-Path ([IO.Path]::GetDirectoryName([IO.Path]::GetDirectoryName($candidateRoot))) ('candidate-hardlink-' + [Guid]::NewGuid().ToString('N') + '.json')
                    [void](New-Item -ItemType HardLink -Path $externalLink -Target (Join-Path $candidateRoot 'release-set.v2.json'))
                }
            },
            [pscustomobject]@{
                Label = 'release-public-key-mismatch'
                ExpectedMessage = 'Enterprise signed-candidate release public key does not equal'
                Mutate = {
                    param($response, $candidateRoot)
                    $keyPath = Join-Path $candidateRoot 'release-public-key.v2.json'
                    $key = Read-Json -Path $keyPath
                    $key.keyId = 'rewritten-release-key'
                    Write-CanonicalJson -Path $keyPath -Value $key
                    $item = Get-Item -LiteralPath $keyPath -Force
                    $response.files[1].sizeBytes = [int64]$item.Length
                    $response.files[1].sha256 = Get-Sha256 -Path $keyPath
                }
            }
        )
        foreach ($negativeCase in $enterpriseInventoryNegatives) {
            $negativeResponsePath = New-MutatedManifestPublishingResponseBundle `
                -SourceResponsePath $stablePolicyResponsePath `
                -OutputRoot (Join-Path $fixtureRoot ('enterprise-stable-v2-inventory-' + [string]$negativeCase.Label)) `
                -Mutate $negativeCase.Mutate `
                -Signer $manifestResponseSigner `
                -Resign
            try {
                Assert-ManifestFoundationFailurePreservesState `
                    -Label ('Enterprise signed-candidate inventory ' + [string]$negativeCase.Label) `
                    -ScriptPath $orchestrator `
                    -RepoRoot $sourceRepo `
                    -Edition Enterprise `
                    -Phase ImportSignedCandidate `
                    -PlanPath $stableV2PlanPath `
                    -StateRoot $stableR4PolicySource `
                    -ResponsePath $negativeResponsePath `
                    -ExpectedHeadSha256 $stablePolicyR4HeadSha256 `
                    -ExpectedMessage ([string]$negativeCase.ExpectedMessage)
            }
            finally {
                if ([string]$negativeCase.Label -ceq 'reparse-candidate-directory') {
                    $negativeCandidateRoot = Join-Path `
                        ([IO.Path]::GetDirectoryName($negativeResponsePath)) `
                        'candidate'
                    foreach ($entry in @(Get-ChildItem -LiteralPath $negativeCandidateRoot -Force)) {
                        if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                            [IO.Directory]::Delete($entry.FullName)
                        }
                    }
                }
            }
        }

        Assert-NoManifestFoundationStaging `
            -StateParent $fixtureRoot `
            -OrchestrationId ([string]$pilotV2Plan.orchestrationId) `
            -Label 'Rejected and recovered typed r4/r5 operations'

        $pilotFoundationExchange = Invoke-TestPilotManifestFoundation `
            -ScriptPath $orchestrator `
            -RepoRoot $sourceRepo `
            -Edition Personal `
            -PlanPath $pilotV2PlanPath `
            -StateRoot $pilotV2State `
            -FixtureRoot (Join-Path $fixtureRoot 'personal-pilot-v2-foundation-exchange') `
            -Signer $manifestResponseSigner `
            -ReleaseSigner $releaseManifestSigner
        $stableFoundationExchange = Invoke-TestPilotManifestFoundation `
            -ScriptPath $orchestrator `
            -RepoRoot $sourceRepo `
            -Edition Enterprise `
            -PlanPath $stableV2PlanPath `
            -StateRoot $stableV2State `
            -FixtureRoot (Join-Path $fixtureRoot 'enterprise-stable-v2-foundation-exchange') `
            -Signer $manifestResponseSigner `
            -ReleaseSigner $releaseManifestSigner
        $productValidatorRunner = New-ProductReleaseManifestValidatorRunner `
            -RepositoryRoot $RepositoryRoot `
            -OutputRoot (Join-Path $fixtureRoot 'product-release-manifest-validator-runner')
        $pilotProductManifestPath = Join-Path `
            (Join-Path ([IO.Path]::GetDirectoryName(
                        [string]$pilotFoundationExchange.ResponsePath)) 'candidate') `
            'release-set.v2.json'
        $stableProductManifestPath = Join-Path `
            (Join-Path ([IO.Path]::GetDirectoryName(
                        [string]$stableFoundationExchange.ResponsePath)) 'candidate') `
            'release-set.v2.json'
        Assert-ProductReleaseManifestPayloadParity `
            -RunnerPath $productValidatorRunner `
            -Edition Personal `
            -ManifestPath $pilotProductManifestPath
        Assert-ProductReleaseManifestPayloadParity `
            -RunnerPath $productValidatorRunner `
            -Edition Enterprise `
            -ManifestPath $stableProductManifestPath
        $enterprisePlusManifest = Read-Json -Path $stableProductManifestPath
        $enterprisePlusManifest.issuedAtUtc = '2026-08-31T01:02:03.1200000+00:00'
        $enterprisePlusManifest.expiresAtUtc = '2026-09-01T01:02:03.1200000+00:00'
        $enterpriseArtifactUri = [Uri]::new(
            [string]$enterprisePlusManifest.artifacts[0].uri,
            [UriKind]::Absolute)
        $enterpriseArtifactUriPrefix = $enterpriseArtifactUri.AbsoluteUri.Substring(
            0,
            $enterpriseArtifactUri.AbsoluteUri.LastIndexOf('/') + 1)
        $enterprisePlusManifest.artifacts[0].uri =
            $enterpriseArtifactUriPrefix + 'canonical+payload-parity.exe'
        $enterprisePlusManifestPath = Join-Path `
            $fixtureRoot `
            'enterprise-canonical-payload-plus-parity.release-set.v2.json'
        Write-CanonicalJson `
            -Path $enterprisePlusManifestPath `
            -Value $enterprisePlusManifest
        Assert-ProductReleaseManifestPayloadParity `
            -RunnerPath $productValidatorRunner `
            -Edition Enterprise `
            -ManifestPath $enterprisePlusManifestPath
        Assert-ProductReleaseManifestAccepted `
            -RunnerPath $productValidatorRunner `
            -PlanPath $pilotV2PlanPath `
            -ResponsePath ([string]$pilotFoundationExchange.ResponsePath)
        Assert-ProductReleaseManifestAccepted `
            -RunnerPath $productValidatorRunner `
            -PlanPath $stableV2PlanPath `
            -ResponsePath ([string]$stableFoundationExchange.ResponsePath)
        foreach ($foundationCase in @(
                [pscustomobject]@{
                    StateRoot = $pilotV2State
                    Channel = 'pilot'
                    Phase = 'PILOT_SIGNED_CANDIDATE_IMPORTED'
                },
                [pscustomobject]@{
                    StateRoot = $stableV2State
                    Channel = 'stable'
                    Phase = 'STABLE_SIGNED_CANDIDATE_IMPORTED'
                })) {
            $foundationState = [string]$foundationCase.StateRoot
            $foundationSummary = Get-ProductionReleaseStateSummary `
                -StateRoot $foundationState `
                -StateSchemaPath $stateV2SchemaPath
            Assert-True ([int]$foundationSummary.Revision -eq 5 -and [string]$foundationSummary.Phase -ceq [string]$foundationCase.Phase) 'Typed target-channel manifest foundation did not reach its exact r5 phase.'
            Assert-True ([string]$foundationSummary.NoGoCode -ceq 'PHASE_NOT_IMPLEMENTED_INSTALLER_SIGNING_REQUESTED') 'Typed target-channel manifest foundation did not retain the downstream installer-signing NO-GO.'
            Assert-True (-not [bool]$foundationSummary.PilotReady -and -not [bool]$foundationSummary.StableReady) 'Typed target-channel manifest foundation incorrectly claimed production readiness.'
            $requestReceipt = Read-Json -Path (Join-Path $foundationState ("receipts\0004-{0}-manifest-signing-requested.json" -f [string]$foundationCase.Channel))
            $candidateReceipt = Read-Json -Path (Join-Path $foundationState ("receipts\0005-{0}-signed-candidate-imported.json" -f [string]$foundationCase.Channel))
            Assert-True ($null -eq $requestReceipt.data.PSObject.Properties['externalEvidenceData'] -and $null -eq $candidateReceipt.data.PSObject.Properties['externalEvidenceData']) 'Typed r4/r5 receipts regressed to generic externalEvidenceData.'
            Assert-True ([string]$requestReceipt.data.compiledReleaseTrustStatus -ceq 'VERIFIED') 'Typed r4 receipt lost compiled release-manifest trust-probe verification status.'
            Assert-True ([string]$candidateReceipt.data.compiledReleaseTrustStatus -ceq 'VERIFIED' -and [string]$candidateReceipt.data.productionAdmission -ceq 'NO_GO') 'Typed r5 receipt lost exact trust-probe status or explicit downstream production NO-GO.'
            $typedStateText = @(
                Get-ChildItem -LiteralPath $foundationState -File -Recurse -Filter '*.json' |
                    Sort-Object FullName |
                    ForEach-Object {
                        [IO.File]::ReadAllText(
                            $_.FullName,
                            [Text.UTF8Encoding]::new($false, $true))
                    }
            ) -join [char]10
            Assert-True (-not $typedStateText.Contains('privateKey', [StringComparison]::OrdinalIgnoreCase)) 'Typed r4/r5 persisted private-key material or a private-key path.'
        }

        $personalR5Snapshot = Get-StateTreeSnapshot -Path $pilotV2State
        [void](Invoke-Orchestrator `
            -ScriptPath $orchestrator `
            -RepoRoot $sourceRepo `
            -Edition Personal `
            -Phase PrepareInstallerSigning `
            -PlanPath $pilotV2PlanPath `
            -StateRoot $pilotV2State `
            -ExpectFailure `
            -ExpectedMessage 'missing or stale Personal r5 compare-and-swap head')
        Assert-True ((Get-StateTreeSnapshot -Path $pilotV2State) -ceq
            $personalR5Snapshot) `
            'Personal r6 missing-CAS rejection changed state.'
        [void](Invoke-Orchestrator `
            -ScriptPath $orchestrator `
            -RepoRoot $sourceRepo `
            -Edition Personal `
            -Phase PrepareInstallerSigning `
            -PlanPath $pilotV2PlanPath `
            -StateRoot $pilotV2State `
            -ExpectedHeadSha256 (Get-Sha256 -Path `
                (Join-Path $pilotV2State 'head.json')) `
            -ExpectFailure `
            -ExpectedMessage 'requires -PersonalInstallerPayloadPath')
        Assert-True ((Get-StateTreeSnapshot -Path $pilotV2State) -ceq
            $personalR5Snapshot) `
            'Personal r6 missing trusted-build input rejection changed state.'
        [void](Invoke-Orchestrator `
            -ScriptPath $orchestrator `
            -RepoRoot $sourceRepo `
            -Edition Personal `
            -Phase ImportInstallerSignature `
            -PlanPath $pilotV2PlanPath `
            -StateRoot $pilotV2State `
            -ExpectFailure `
            -ExpectedMessage 'only be imported after its exact r6')
        Assert-True ((Get-StateTreeSnapshot -Path $pilotV2State) -ceq
            $personalR5Snapshot) `
            'Personal r7 pre-r6 rejection changed state.'

        $stableR5Snapshot = Get-StateTreeSnapshot -Path $stableV2State
        [void](Invoke-Orchestrator `
            -ScriptPath $orchestrator `
            -RepoRoot $sourceRepo `
            -Edition Enterprise `
            -Phase PrepareInstallerSigning `
            -PlanPath $stableV2PlanPath `
            -StateRoot $stableV2State `
            -ExpectFailure `
            -ExpectedMessage 'requires -ExpectedHeadSha256')
        Assert-True ((Get-StateTreeSnapshot -Path $stableV2State) -ceq $stableR5Snapshot) 'Enterprise r6 missing-CAS rejection changed state.'
        [void](Invoke-Orchestrator `
            -ScriptPath $orchestrator `
            -RepoRoot $sourceRepo `
            -Edition Enterprise `
            -Phase PrepareInstallerSigning `
            -PlanPath $stableV2PlanPath `
            -StateRoot $stableV2State `
            -ExpectedHeadSha256 (Get-Sha256 -Path (Join-Path $stableV2State 'head.json')) `
            -ExpectFailure `
            -ExpectedMessage 'requires -EnterpriseInstallerPayloadPath')
        Assert-True ((Get-StateTreeSnapshot -Path $stableV2State) -ceq $stableR5Snapshot) 'Enterprise r6 missing trusted-build input rejection changed state.'
        [void](Invoke-Orchestrator `
            -ScriptPath $orchestrator `
            -RepoRoot $sourceRepo `
            -Edition Enterprise `
            -Phase ImportInstallerSignature `
            -PlanPath $stableV2PlanPath `
            -StateRoot $stableV2State `
            -ExpectFailure `
            -ExpectedMessage 'only be imported after r6')
        Assert-True ((Get-StateTreeSnapshot -Path $stableV2State) -ceq $stableR5Snapshot) 'Enterprise r7 pre-r6 rejection changed state.'

        $stableR6ReplayState = Join-Path $fixtureRoot 'enterprise-stable-v2-r6-replay-state'
        Copy-State -Source $stableV2State -Destination $stableR6ReplayState
        $stableR5State = Get-ProductionReleaseState `
            -StateRoot $stableR6ReplayState `
            -StateSchemaPath $stateV2SchemaPath
        $stableR6Data = New-EnterpriseV2FoundationInstallerTransition `
            -State $stableR5State `
            -Revision 6
        [void](Add-V2FoundationTransition `
            -StateRoot $stableR6ReplayState `
            -StateSchemaPath $stateV2SchemaPath `
            -Phase 'INSTALLER_SIGNING_REQUESTED' `
            -Data $stableR6Data)
        $stableR6Head = Get-Sha256 -Path (Join-Path $stableR6ReplayState 'head.json')
        [void](Add-V2FoundationTransition `
            -StateRoot $stableR6ReplayState `
            -StateSchemaPath $stateV2SchemaPath `
            -Phase 'INSTALLER_SIGNING_REQUESTED' `
            -Data $stableR6Data)
        Assert-True ((Get-Sha256 -Path (Join-Path $stableR6ReplayState 'head.json')) -ceq $stableR6Head) 'Typed Enterprise r6 exact replay changed the CAS head.'
        Assert-True (@(Get-ChildItem -LiteralPath (Join-Path $stableR6ReplayState 'receipts') -Force).Count -eq 6) 'Typed Enterprise r6 exact replay duplicated its receipt.'
        $tamperedR6Data = $stableR6Data |
            ConvertTo-Json -Depth 64 -Compress |
            ConvertFrom-Json -Depth 64 -DateKind String
        $tamperedR6Data.r5LauncherSha256 = 'f' * 64
        $stableR6Snapshot = Get-StateTreeSnapshot -Path $stableR6ReplayState
        Assert-Throws `
            -Label 'Typed Enterprise r6 altered replay' `
            -ExpectedMessage 'conflicts with the requested idempotent transition' `
            -Action {
                [void](Add-V2FoundationTransition `
                    -StateRoot $stableR6ReplayState `
                    -StateSchemaPath $stateV2SchemaPath `
                    -Phase 'INSTALLER_SIGNING_REQUESTED' `
                    -Data $tamperedR6Data)
            }
        Assert-True ((Get-StateTreeSnapshot -Path $stableR6ReplayState) -ceq $stableR6Snapshot) 'Typed Enterprise r6 altered replay changed state.'

        $stableR6State = Get-ProductionReleaseState `
            -StateRoot $stableR6ReplayState `
            -StateSchemaPath $stateV2SchemaPath
        $stableR7Data = New-EnterpriseV2FoundationInstallerTransition `
            -State $stableR6State `
            -Revision 7
        [void](Add-V2FoundationTransition `
            -StateRoot $stableR6ReplayState `
            -StateSchemaPath $stateV2SchemaPath `
            -Phase 'INSTALLER_SIGNATURE_IMPORTED' `
            -Data $stableR7Data)
        $stableR7Head = Get-Sha256 -Path (Join-Path $stableR6ReplayState 'head.json')
        [void](Add-V2FoundationTransition `
            -StateRoot $stableR6ReplayState `
            -StateSchemaPath $stateV2SchemaPath `
            -Phase 'INSTALLER_SIGNATURE_IMPORTED' `
            -Data $stableR7Data)
        Assert-True ((Get-Sha256 -Path (Join-Path $stableR6ReplayState 'head.json')) -ceq $stableR7Head) 'Typed Enterprise r7 exact replay changed the CAS head.'
        Assert-True (@(Get-ChildItem -LiteralPath (Join-Path $stableR6ReplayState 'receipts') -Force).Count -eq 7) 'Typed Enterprise r7 exact replay duplicated its receipt.'
        $typedR7Receipt = Read-Json -Path (Join-Path $stableR6ReplayState 'receipts\0007-installer-signature-imported.json')
        Assert-True (
            [string]$typedR7Receipt.data.responseSha256 -ceq [string]$stableR7Data.responseSha256 -and
            [string]$typedR7Receipt.data.signedInstaller.fileName -ceq 'Ensou.Dsh.Enterprise.Installer.exe' -and
            [string]$typedR7Receipt.data.signedInstaller.relativePath -ceq 'imports/installer-signing.v1/signed/Ensou.Dsh.Enterprise.Installer.exe' -and
            [int64]$typedR7Receipt.data.signedInstaller.sizeBytes -gt 0 -and
            [string]$typedR7Receipt.data.signedInstaller.sha256 -match '^[0-9a-f]{64}$' -and
            [string]$typedR7Receipt.data.signedInstaller.peContentSha256 -match '^[0-9a-f]{64}$' -and
            [string]$typedR7Receipt.data.timestampProtocol -ceq 'RFC3161' -and
            [string]$typedR7Receipt.data.authenticationPurpose -ceq 'installer-signing-response' -and
            [string]$typedR7Receipt.data.r5LauncherSha256 -ceq [string]$stableR6Data.r5LauncherSha256 -and
            [string]$typedR7Receipt.data.r5RuntimeSha256 -ceq [string]$stableR6Data.r5RuntimeSha256 -and
            [int]$typedR7Receipt.data.requestSchemaVersion -eq 2 -and
            [string]$typedR7Receipt.data.requestSha256 -ceq [string]$stableR6Data.requestSha256 -and
            [string]$typedR7Receipt.data.trustedBuildEvidenceSha256 -ceq [string]$stableR6Data.trustedBuildEvidenceSha256 -and
            [string]$typedR7Receipt.data.resourceBindingSha256 -ceq [string]$stableR6Data.resourceBindingSha256 -and
            [string]$typedR7Receipt.data.sdkFileClosureStatus -ceq [string]$stableR6Data.sdkFileClosureStatus -and
            [string]$typedR7Receipt.data.signingRequestEligibilityStatus -ceq [string]$stableR6Data.signingRequestEligibilityStatus -and
            [string]$typedR7Receipt.data.sourceBuildInputSetSha256 -ceq [string]$stableR6Data.sourceBuildInputSetSha256 -and
            [string]$typedR7Receipt.data.targetBuildIdentitySha256 -ceq [string]$stableR6Data.targetBuildIdentitySha256 -and
            [string]$typedR7Receipt.data.payloadSetSha256 -ceq [string]$stableR6Data.payloadSetSha256 -and
            [string]$typedR7Receipt.data.sdkFileClosureStatus -ceq 'VERIFIED' -and
            [string]$typedR7Receipt.data.admissionReason -ceq 'INSTALLER_SIGNING_RESPONSE_REQUIRED' -and
            [string]$typedR7Receipt.data.productionAdmission -ceq 'NO_GO') 'Typed Enterprise r7 receipt lost the exact r8 handoff identity, signer/timestamp domain, r5 hashes, or explicit NO-GO.'
        $tamperedR7Data = $stableR7Data |
            ConvertTo-Json -Depth 64 -Compress |
            ConvertFrom-Json -Depth 64 -DateKind String
        $tamperedR7Data.responseSha256 = 'e' * 64
        $stableR7Snapshot = Get-StateTreeSnapshot -Path $stableR6ReplayState
        Assert-Throws `
            -Label 'Typed Enterprise r7 altered replay' `
            -ExpectedMessage 'conflicts with the requested idempotent transition' `
            -Action {
                [void](Add-V2FoundationTransition `
                    -StateRoot $stableR6ReplayState `
                    -StateSchemaPath $stateV2SchemaPath `
                    -Phase 'INSTALLER_SIGNATURE_IMPORTED' `
                    -Data $tamperedR7Data)
            }
        Assert-True ((Get-StateTreeSnapshot -Path $stableR6ReplayState) -ceq $stableR7Snapshot) 'Typed Enterprise r7 altered replay changed state.'

        $r8MissingCasSnapshot = Get-StateTreeSnapshot -Path $stableR6ReplayState
        [void](Invoke-Orchestrator `
            -ScriptPath $orchestrator `
            -RepoRoot $sourceRepo `
            -Edition Enterprise `
            -Phase BindPilotEvidence `
            -PlanPath $stableV2PlanPath `
            -StateRoot $stableR6ReplayState `
            -ExpectFailure `
            -ExpectedMessage 'requires -ExpectedHeadSha256')
        Assert-True `
            ((Get-StateTreeSnapshot -Path $stableR6ReplayState) -ceq
                $r8MissingCasSnapshot) `
            'Enterprise r8 missing-CAS rejection changed state.'

        # The production adapter's cryptographic evidence validation has its
        # own focused suite. This isolated committed adapter double exercises
        # the real orchestrator process/argument/output boundary and permits
        # deterministic bundle-first and receipt-first crash recovery without
        # claiming synthetic evidence as production Pilot admission.
        $r8AdapterRepo = Join-Path $fixtureRoot 'enterprise-r8-adapter-repo'
        [void](Invoke-Git `
            -Root $fixtureRoot `
            -Arguments @('clone', '--quiet', $sourceRepo, $r8AdapterRepo))
        [void](Invoke-Git `
            -Root $r8AdapterRepo `
            -Arguments @('config', '--local', 'core.autocrlf', 'false'))
        [void](Invoke-Git `
            -Root $r8AdapterRepo `
            -Arguments @('config', 'user.email', 'launcher-test@ensou.invalid'))
        [void](Invoke-Git `
            -Root $r8AdapterRepo `
            -Arguments @('config', 'user.name', 'ensou-launcher-test'))
        $r8AdapterDoublePath = Join-Path `
            $r8AdapterRepo `
            'release\scripts\New-EnterpriseProductionPilotEvidenceInput.ps1'
        $r8AdapterDoubleText = @'
#requires -Version 7.2
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$StateRoot,
    [Parameter(Mandatory = $true)][string]$ExpectedR7HeadSha256,
    [Parameter(Mandatory = $true)][string]$WindowsPilotEvidenceEnvelopePath,
    [Parameter(Mandatory = $true)][string]$WindowsPilotEvidenceBodyPath,
    [Parameter(Mandatory = $true)][string]$WindowsPilotVerificationReportPath,
    [Parameter(Mandatory = $true)][string]$WindowsPilotReadinessConfigPath,
    [ValidateSet(1, 2)][int]$WindowsPilotReadinessSchemaVersion = 1,
    [Parameter(Mandatory = $true)][string]$WindowsPilotStoredReadinessReportPath,
    [Parameter(Mandatory = $true)][string]$WindowsPilotReplayedReadinessReportPath,
    [Parameter(Mandatory = $true)][string]$LocalDataCertificationReceiptPath,
    [Parameter(Mandatory = $true)][string]$StablePrivatePilotObservationPath,
    [Parameter(Mandatory = $true)][string]$PilotTrustPolicyPath,
    [Parameter(Mandatory = $true)][string]$OutputPath
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
[byte[]]$bytes = [IO.File]::ReadAllBytes($PilotTrustPolicyPath)
$stream = [IO.FileStream]::new(
    $OutputPath,
    [IO.FileMode]::CreateNew,
    [IO.FileAccess]::Write,
    [IO.FileShare]::None)
try {
    $stream.Write($bytes, 0, $bytes.Length)
    $stream.Flush($true)
}
finally {
    $stream.Dispose()
}
$sha256 = [Convert]::ToHexString(
    [Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
Write-Output ([pscustomobject]@{
    Status = 'PILOT_EVIDENCE_INPUT_READY_NO_GO'
    ProductionAdmission = 'NO_GO'
    NextRequiredGate = 'PILOT_EVIDENCE_BOUND'
    OutputPath = [IO.Path]::GetFullPath($OutputPath)
    OutputSha256 = $sha256
})
'@
        [IO.File]::WriteAllText(
            $r8AdapterDoublePath,
            $r8AdapterDoubleText,
            $utf8)
        [void](Invoke-Git `
            -Root $r8AdapterRepo `
            -Arguments @(
                'add',
                'release/scripts/New-EnterpriseProductionPilotEvidenceInput.ps1'))
        [void](Invoke-Git `
            -Root $r8AdapterRepo `
            -Arguments @(
                'commit',
                '--quiet',
                '-m',
                'r8 orchestration adapter boundary test double'))
        $r8AdapterCommit = [string]@(Invoke-Git `
            -Root $r8AdapterRepo `
            -Arguments @('rev-parse', 'HEAD'))[0]
        $r8AdapterOrchestrator = Join-Path `
            $r8AdapterRepo `
            'release\scripts\Invoke-LauncherProductionRelease.ps1'
        $r8AdapterPlanPath = Join-Path `
            $evidenceRoot `
            'enterprise-stable-r8-adapter-plan-v2.json'
        $r8AdapterPlan = $stableV2Plan |
            ConvertTo-Json -Depth 64 -Compress |
            ConvertFrom-Json -Depth 64 -DateKind String
        $r8AdapterPlan.orchestrationId = [Guid]::NewGuid().ToString()
        $r8AdapterPlan.sourceCommit = $r8AdapterCommit
        Write-Json -Path $r8AdapterPlanPath -Value $r8AdapterPlan
        $r8AdapterR7State = Join-Path `
            $fixtureRoot `
            'enterprise-stable-r8-adapter-r7-state'
        [void](Invoke-Orchestrator `
            -ScriptPath $r8AdapterOrchestrator `
            -RepoRoot $r8AdapterRepo `
            -Edition Enterprise `
            -Phase Prepare `
            -PlanPath $r8AdapterPlanPath `
            -StateRoot $r8AdapterR7State)
        [void](Add-V2FoundationStateContractClientEvidence `
            -StateRoot $r8AdapterR7State `
            -StateSchemaPath $stateV2SchemaPath)
        $r8AdapterR3Snapshot = Get-StateTreeSnapshot `
            -Path $r8AdapterR7State
        Assert-Throws `
            -Label 'Generic foundation r4/r5 fast-forward rejection' `
            -ExpectedMessage 'require the typed manifest publishing request/import fixture' `
            -Action {
                [void](Advance-V2FoundationState `
                    -StateRoot $r8AdapterR7State `
                    -StateSchemaPath $stateV2SchemaPath `
                    -TargetRevision 5)
            }
        Assert-True `
            ((Get-StateTreeSnapshot -Path $r8AdapterR7State) -ceq
                $r8AdapterR3Snapshot) `
            'Rejected generic foundation r4/r5 fast-forward changed state.'
        [void](Invoke-TestPilotManifestFoundation `
            -ScriptPath $r8AdapterOrchestrator `
            -RepoRoot $r8AdapterRepo `
            -Edition Enterprise `
            -PlanPath $r8AdapterPlanPath `
            -StateRoot $r8AdapterR7State `
            -FixtureRoot (Join-Path `
                $fixtureRoot `
                'enterprise-r8-adapter-manifest-foundation') `
            -Signer $manifestResponseSigner `
            -ReleaseSigner $releaseManifestSigner)
        foreach ($typedManifestReceiptName in @(
                '0004-stable-manifest-signing-requested.json',
                '0005-stable-signed-candidate-imported.json')) {
            $typedManifestReceiptJson = [IO.File]::ReadAllText(
                (Join-Path `
                    (Join-Path $r8AdapterR7State 'receipts') `
                    $typedManifestReceiptName),
                [Text.UTF8Encoding]::new($false, $true))
            Assert-True `
                (Test-Json `
                    -Json $typedManifestReceiptJson `
                    -SchemaFile $stateV2SchemaPath `
                    -ErrorAction Stop) `
                "Typed adapter fixture receipt '$typedManifestReceiptName' did not satisfy state v2."
        }
        [void](Advance-V2FoundationState `
            -StateRoot $r8AdapterR7State `
            -StateSchemaPath $stateV2SchemaPath `
            -TargetRevision 7)
        $r8AdapterR7 = Get-ProductionReleaseState `
            -StateRoot $r8AdapterR7State `
            -StateSchemaPath $stateV2SchemaPath
        [void](New-EnterpriseV2FoundationPilotEvidenceTransition `
            -State $r8AdapterR7)
        $r8AdapterTemplateRoot = Join-Path `
            $evidenceRoot `
            'enterprise-r8-adapter-template'
        [IO.Directory]::CreateDirectory($r8AdapterTemplateRoot) | Out-Null
        $r8AdapterTemplatePath = Join-Path `
            $r8AdapterTemplateRoot `
            'pilot-evidence-input.v1.json'
        [IO.File]::Copy(
            (Join-Path `
                $r8AdapterR7State `
                'imports\pilot-evidence.v1\pilot-evidence-input.v1.json'),
            $r8AdapterTemplatePath,
            $false)
        [byte[]]$r8AdapterTemplateBytes =
            [IO.File]::ReadAllBytes($r8AdapterTemplatePath)
        $r8AdapterTemplateInput = [pscustomobject]@{
            Value = Read-Json -Path $r8AdapterTemplatePath
            Bytes = $r8AdapterTemplateBytes
            Sha256 = Get-Sha256 -Path $r8AdapterTemplatePath
        }
        $r8AdapterBinding =
            ProductionReleaseState\Assert-EnterpriseProductionPilotEvidenceInputBinding `
                -PilotEvidenceInput $r8AdapterTemplateInput `
                -Plan $r8AdapterR7.Plan `
                -Identity $r8AdapterR7.Identity `
                -IdentitySha256 ([string]$r8AdapterR7.IdentitySha256) `
                -Receipts $r8AdapterR7.Receipts `
                -StateRoot $r8AdapterR7.StateRoot `
                -ExpectedR7HeadSha256 ([string]$r8AdapterR7.HeadSha256)
        Assert-True `
            ([string]$r8AdapterBinding.R7HeadSha256 -ceq
                [string]$r8AdapterR7.HeadSha256) `
            'Module-level Enterprise r8 binding rejected the exact authoritative r7 head.'
        $r8ModuleWrongExpectedHead =
            if ([string]$r8AdapterR7.HeadSha256 -cne ('f' * 64)) {
                'f' * 64
            }
            else {
                'e' * 64
            }
        Assert-Throws `
            -Label 'Module-level Enterprise r8 caller-selected head rejection' `
            -ExpectedMessage 'R8_BINDING_R7_HEAD_MISMATCH' `
            -Action {
                [void](ProductionReleaseState\Assert-EnterpriseProductionPilotEvidenceInputBinding `
                    -PilotEvidenceInput $r8AdapterTemplateInput `
                    -Plan $r8AdapterR7.Plan `
                    -Identity $r8AdapterR7.Identity `
                    -IdentitySha256 ([string]$r8AdapterR7.IdentitySha256) `
                    -Receipts $r8AdapterR7.Receipts `
                    -StateRoot $r8AdapterR7.StateRoot `
                    -ExpectedR7HeadSha256 $r8ModuleWrongExpectedHead)
            }
        Remove-Item `
            -LiteralPath (Join-Path `
                $r8AdapterR7State `
                'imports\pilot-evidence.v1') `
            -Recurse `
            -Force
        $r8AdapterR7HeadSha256 = Get-Sha256 `
            -Path (Join-Path $r8AdapterR7State 'head.json')
        $r8BundleCrashState = Join-Path `
            $fixtureRoot `
            'enterprise-r8-adapter-bundle-crash-state'
        $r8ReceiptCrashState = Join-Path `
            $fixtureRoot `
            'enterprise-r8-adapter-receipt-crash-state'
        $r8MismatchCrashState = Join-Path `
            $fixtureRoot `
            'enterprise-r8-adapter-mismatch-crash-state'
        Copy-State `
            -Source $r8AdapterR7State `
            -Destination $r8BundleCrashState
        Copy-State `
            -Source $r8AdapterR7State `
            -Destination $r8ReceiptCrashState
        Copy-State `
            -Source $r8AdapterR7State `
            -Destination $r8MismatchCrashState
        $r8AdapterCommon = @{
            ScriptPath = $r8AdapterOrchestrator
            RepoRoot = $r8AdapterRepo
            Edition = 'Enterprise'
            Phase = 'BindPilotEvidence'
            PlanPath = $r8AdapterPlanPath
            ExpectedHeadSha256 = $r8AdapterR7HeadSha256
            WindowsPilotEvidenceEnvelopePath = $r8AdapterTemplatePath
            WindowsPilotEvidenceBodyPath = $r8AdapterTemplatePath
            WindowsPilotVerificationReportPath = $r8AdapterTemplatePath
            WindowsPilotReadinessConfigPath = $r8AdapterTemplatePath
            WindowsPilotStoredReadinessReportPath = $r8AdapterTemplatePath
            WindowsPilotReplayedReadinessReportPath = $r8AdapterTemplatePath
            LocalDataCertificationReceiptPath = $r8AdapterTemplatePath
            StablePrivatePilotObservationPath = $r8AdapterTemplatePath
            PilotTrustPolicyPath = $r8AdapterTemplatePath
        }
        $r8MoveRaceState = Join-Path `
            $fixtureRoot `
            'enterprise-r8-adapter-validated-move-race-state'
        Copy-State `
            -Source $r8AdapterR7State `
            -Destination $r8MoveRaceState
        $r8MoveRaceArguments = @{} + $r8AdapterCommon
        [void]$r8MoveRaceArguments.Remove('ScriptPath')
        [void]$r8MoveRaceArguments.Remove('RepoRoot')
        $r8MoveRaceArguments.StateRoot = $r8MoveRaceState
        $r8MoveRaceStateBefore = Get-StateTreeSnapshot -Path $r8MoveRaceState
        $r8MoveRaceTemplateBefore = Get-StateTreeSnapshot `
            -Path $r8AdapterTemplateRoot
        [void](Invoke-OrchestratorValidatedMoveMutationRace `
            -ScriptPath $r8AdapterOrchestrator `
            -RepoRoot $r8AdapterRepo `
            -Arguments $r8MoveRaceArguments `
            -Purpose pilot-evidence-import `
            -BundleRelativeFile `
                'imports\pilot-evidence.v1\pilot-evidence-input.v1.json')
        Assert-True `
            ((Get-StateTreeSnapshot -Path $r8MoveRaceState) -ceq
                $r8MoveRaceStateBefore) `
            'Validated-move Pilot mutation changed state/head/receipts.'
        Assert-True `
            ((Get-StateTreeSnapshot -Path $r8AdapterTemplateRoot) -ceq
                $r8MoveRaceTemplateBefore) `
            'Validated-move Pilot mutation changed external evidence/feed inputs.'
        Assert-True `
            (-not (Test-Path -LiteralPath (Join-Path `
                    $r8MoveRaceState `
                    'imports\pilot-evidence.v1'))) `
            'Validated-move Pilot mutation left an unreceipted canonical bundle.'

        $r8InstallerMoveRaceState = Join-Path `
            $fixtureRoot `
            'enterprise-r8-adapter-installer-shaped-move-race-state'
        Copy-State `
            -Source $r8AdapterR7State `
            -Destination $r8InstallerMoveRaceState
        $r8InstallerMoveRaceArguments = @{} + $r8AdapterCommon
        [void]$r8InstallerMoveRaceArguments.Remove('ScriptPath')
        [void]$r8InstallerMoveRaceArguments.Remove('RepoRoot')
        $r8InstallerMoveRaceArguments.StateRoot = $r8InstallerMoveRaceState
        $r8InstallerMoveRaceStateBefore = Get-StateTreeSnapshot `
            -Path $r8InstallerMoveRaceState
        $r8InstallerMoveRaceTemplateBefore = Get-StateTreeSnapshot `
            -Path $r8AdapterTemplateRoot
        $r8InstallerMoveRace =
            Invoke-OrchestratorValidatedMoveMutationRace `
                -ScriptPath $r8AdapterOrchestrator `
                -RepoRoot $r8AdapterRepo `
                -Arguments $r8InstallerMoveRaceArguments `
                -Purpose pilot-evidence-import `
                -BundleRelativeFile `
                    'imports\pilot-evidence.v1\signed\Ensou.Dsh.Enterprise.Installer.exe' `
                -MutationSourcePath $foundationSyntheticPath `
                -InventoryOnlyMutation
        Assert-True `
            ((Get-StateTreeSnapshot -Path $r8InstallerMoveRaceState) -ceq
                $r8InstallerMoveRaceStateBefore) `
            'Installer-shaped validated-move inventory mutation changed state/head/receipts.'
        Assert-True `
            ((Get-StateTreeSnapshot -Path $r8AdapterTemplateRoot) -ceq
                $r8InstallerMoveRaceTemplateBefore) `
            'Installer-shaped validated-move inventory mutation changed external evidence/feed inputs.'
        Assert-True `
            (-not (Test-Path -LiteralPath (Join-Path `
                    $r8InstallerMoveRaceState `
                    'imports\pilot-evidence.v1'))) `
            'Installer-shaped validated-move inventory mutation left an unreceipted canonical bundle.'
        $r8RejectedInstallerPath = Join-Path `
            ([string]$r8InstallerMoveRace.RejectedPath) `
            'signed\Ensou.Dsh.Enterprise.Installer.exe'
        Assert-True `
            ((Test-Path -LiteralPath $r8RejectedInstallerPath -PathType Leaf) -and
             (Get-Sha256 -Path $r8RejectedInstallerPath) -ceq
                $foundationSyntheticSha256) `
            'Installer-shaped mutation was not preserved only in its diagnostic quarantine.'
        Write-Output `
            'VALIDATED-MOVE-FINAL-INVENTORY-ONLY-PASS: an unexpected signed-installer-shaped synthetic PE was rejected and quarantined before head commit; this does not prove real Authenticode/RFC3161 admission.'

        $r8MismatchTemplateRoot = Join-Path `
            $evidenceRoot `
            'enterprise-r8-adapter-valid-mismatch-template'
        [IO.Directory]::CreateDirectory($r8MismatchTemplateRoot) | Out-Null
        $r8MismatchTemplatePath = Join-Path `
            $r8MismatchTemplateRoot `
            'pilot-evidence-input.v1.json'
        [IO.File]::Copy(
            $r8AdapterTemplatePath,
            $r8MismatchTemplatePath,
            $false)
        $r8MismatchTemplate = Read-Json -Path $r8MismatchTemplatePath
        $r8MismatchCreatedAt = [DateTimeOffset]::Parse(
            [string]$r8MismatchTemplate.createdAtUtc,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AssumeUniversal)
        $r8MismatchTemplate.createdAtUtc = ConvertTo-ProductionUtc `
            -Value $r8MismatchCreatedAt.AddSeconds(-1)
        Write-CanonicalJson `
            -Path $r8MismatchTemplatePath `
            -Value $r8MismatchTemplate
        Assert-True `
            ((Get-Sha256 -Path $r8MismatchTemplatePath) -cne
                (Get-Sha256 -Path $r8AdapterTemplatePath)) `
            'Fresh mismatch fixture did not change canonical identity.'
        $r8MismatchCrashArguments = @{} + $r8AdapterCommon
        $r8MismatchCrashArguments.StateRoot = $r8MismatchCrashState
        [void](Invoke-Orchestrator `
            @r8MismatchCrashArguments `
            -FaultPoint AfterPilotEvidenceBundle `
            -ExpectFailure `
            -ExpectedMessage 'INJECTED-CRASH-AFTER-PILOT-EVIDENCE-BUNDLE')
        $r8MismatchCanonicalRoot = Join-Path `
            $r8MismatchCrashState `
            'imports\pilot-evidence.v1'
        $r8MismatchCanonicalBefore = Get-StateTreeSnapshot `
            -Path $r8MismatchCanonicalRoot
        $r8MismatchStateHeadBefore = Get-Sha256 `
            -Path (Join-Path $r8MismatchCrashState 'head.json')
        $r8MismatchStateReceiptsBefore = Get-StateTreeSnapshot `
            -Path (Join-Path $r8MismatchCrashState 'receipts')
        $r8MismatchExternalBefore = Get-StateTreeSnapshot `
            -Path $r8MismatchTemplateRoot
        $r8MismatchArguments = @{} + $r8MismatchCrashArguments
        foreach ($evidencePathArgument in @(
                'WindowsPilotEvidenceEnvelopePath',
                'WindowsPilotEvidenceBodyPath',
                'WindowsPilotVerificationReportPath',
                'WindowsPilotReadinessConfigPath',
                'WindowsPilotStoredReadinessReportPath',
                'WindowsPilotReplayedReadinessReportPath',
                'LocalDataCertificationReceiptPath',
                'StablePrivatePilotObservationPath',
                'PilotTrustPolicyPath')) {
            $r8MismatchArguments[$evidencePathArgument] =
                $r8MismatchTemplatePath
        }
        $r8MismatchRejectedPrefix =
            '.ensou-launcher-production-rejected-' +
            ([Guid]::Parse(
                [string]$r8AdapterPlan.orchestrationId).ToString('N')) +
            '-pilot-evidence-orphan-'
        $r8MismatchRejectedBefore = @(
            Get-ChildItem -LiteralPath $fixtureRoot -Directory -Force `
                -Filter ($r8MismatchRejectedPrefix + '*') `
                -ErrorAction SilentlyContinue |
                ForEach-Object { [string]$_.FullName })
        [void](Invoke-Orchestrator `
            @r8MismatchArguments `
            -ExpectFailure `
            -ExpectedMessage 'R8_ORPHAN_CANONICAL_QUARANTINED')
        $r8MismatchRejectedAfter = @(
            Get-ChildItem -LiteralPath $fixtureRoot -Directory -Force `
                -Filter ($r8MismatchRejectedPrefix + '*') `
                -ErrorAction SilentlyContinue |
                Where-Object {
                    [string]$_.FullName -notin $r8MismatchRejectedBefore
                })
        Assert-True `
            ($r8MismatchRejectedAfter.Count -eq 1 -and
             -not (Test-Path -LiteralPath $r8MismatchCanonicalRoot) -and
             (Get-StateTreeSnapshot -Path $r8MismatchRejectedAfter[0].FullName) -ceq
                $r8MismatchCanonicalBefore -and
             (Get-Sha256 -Path (Join-Path `
                    $r8MismatchCrashState 'head.json')) -ceq
                $r8MismatchStateHeadBefore -and
             (Get-StateTreeSnapshot -Path (Join-Path `
                    $r8MismatchCrashState 'receipts')) -ceq
                $r8MismatchStateReceiptsBefore -and
             (Get-StateTreeSnapshot -Path $r8MismatchTemplateRoot) -ceq
                $r8MismatchExternalBefore) `
            'Fresh valid mismatch did not preserve only the old canonical in one quarantine while keeping head/receipts/feed unchanged.'
        [void](Invoke-Orchestrator @r8MismatchArguments)
        $r8MismatchCommittedSnapshot = Get-StateTreeSnapshot `
            -Path $r8MismatchCrashState
        $r8CommittedBindOutput = @(Invoke-Orchestrator `
            -ScriptPath $r8AdapterOrchestrator `
            -RepoRoot $r8AdapterRepo `
            -Edition Enterprise `
            -Phase BindPilotEvidence `
            -PlanPath $r8AdapterPlanPath `
            -StateRoot $r8MismatchCrashState)
        Assert-True `
            ($r8CommittedBindOutput.Count -eq 1 -and
             [int]$r8CommittedBindOutput[0].ExitCode -eq 0 -and
             @($r8CommittedBindOutput[0].Output).Count -gt 0 -and
             (Get-StateTreeSnapshot -Path $r8MismatchCrashState) -ceq
                $r8MismatchCommittedSnapshot) `
            'Committed r8 Bind replay required raw evidence, reran mutation, or changed state.'

        $r8BundleCrashArguments = @{} + $r8AdapterCommon
        $r8BundleCrashArguments.StateRoot = $r8BundleCrashState
        [void](Invoke-Orchestrator `
            @r8BundleCrashArguments `
            -FaultPoint AfterPilotEvidenceBundle `
            -ExpectFailure `
            -ExpectedMessage 'INJECTED-CRASH-AFTER-PILOT-EVIDENCE-BUNDLE')
        Assert-True `
            ([int]((Read-Json -Path (Join-Path `
                        $r8BundleCrashState 'head.json')).revision) -eq 7 -and
             (Test-Path -LiteralPath (Join-Path `
                    $r8BundleCrashState `
                    'imports\pilot-evidence.v1\pilot-evidence-input.v1.json')) -and
             -not (Test-Path -LiteralPath (Join-Path `
                    $r8BundleCrashState `
                    'receipts\0008-pilot-evidence-bound.json'))) `
            'AfterPilotEvidenceBundle did not leave the exact recoverable bundle-first state.'
        $r8StaleRawTemplateState = Join-Path `
            $fixtureRoot `
            'enterprise-r8-adapter-stale-raw-template-state'
        Copy-State `
            -Source $r8AdapterR7State `
            -Destination $r8StaleRawTemplateState
        $r8StaleRawTemplateSource = Get-ProductionReleaseState `
            -StateRoot $r8StaleRawTemplateState `
            -StateSchemaPath $stateV2SchemaPath
        [void](New-EnterpriseV2FoundationPilotEvidenceTransition `
            -State $r8StaleRawTemplateSource `
            -LifetimeSeconds 1)
        $r8StaleRawTemplatePath = Join-Path `
            $r8StaleRawTemplateState `
            'imports\pilot-evidence.v1\pilot-evidence-input.v1.json'
        Start-Sleep -Seconds 2
        $r8StaleRawArguments = @{} + $r8BundleCrashArguments
        foreach ($evidencePathArgument in @(
                'WindowsPilotEvidenceEnvelopePath',
                'WindowsPilotEvidenceBodyPath',
                'WindowsPilotVerificationReportPath',
                'WindowsPilotReadinessConfigPath',
                'WindowsPilotStoredReadinessReportPath',
                'WindowsPilotReplayedReadinessReportPath',
                'LocalDataCertificationReceiptPath',
                'StablePrivatePilotObservationPath',
                'PilotTrustPolicyPath')) {
            $r8StaleRawArguments[$evidencePathArgument] =
                $r8StaleRawTemplatePath
        }
        $r8StaleRawReplayBefore = Get-StateTreeSnapshot `
            -Path $r8BundleCrashState
        $r8StaleRawQuarantinesBefore = @(
            Get-ChildItem -LiteralPath $fixtureRoot -Directory -Force `
                -Filter '.ensou-launcher-production-rejected-*' `
                -ErrorAction SilentlyContinue |
                Sort-Object FullName |
                ForEach-Object { [string]$_.FullName }) -join "`n"
        [void](Invoke-Orchestrator `
            @r8StaleRawArguments `
            -ExpectFailure `
            -ExpectedMessage 'R8_BINDING_EXPIRED')
        $r8StaleRawQuarantinesAfter = @(
            Get-ChildItem -LiteralPath $fixtureRoot -Directory -Force `
                -Filter '.ensou-launcher-production-rejected-*' `
                -ErrorAction SilentlyContinue |
                Sort-Object FullName |
                ForEach-Object { [string]$_.FullName }) -join "`n"
        Assert-True `
            ((Get-StateTreeSnapshot -Path $r8BundleCrashState) -ceq
                $r8StaleRawReplayBefore -and
             $r8StaleRawQuarantinesAfter -ceq
                $r8StaleRawQuarantinesBefore) `
            'Stale nine-input rebuild evicted or changed a valid recoverable canonical.'
        $r8WrongStateTemplateRoot = Join-Path `
            $evidenceRoot `
            'enterprise-r8-adapter-wrong-state-template'
        [IO.Directory]::CreateDirectory($r8WrongStateTemplateRoot) | Out-Null
        $r8WrongStateTemplatePath = Join-Path `
            $r8WrongStateTemplateRoot `
            'pilot-evidence-input.v1.json'
        [IO.File]::Copy(
            $r8AdapterTemplatePath,
            $r8WrongStateTemplatePath,
            $false)
        $r8WrongStateInput = Read-Json -Path $r8WrongStateTemplatePath
        $r8WrongStateInput.r7.headSha256 = 'f' * 64
        Write-CanonicalJson `
            -Path $r8WrongStateTemplatePath `
            -Value $r8WrongStateInput
        $r8WrongStateArguments = @{} + $r8BundleCrashArguments
        foreach ($evidencePathArgument in @(
                'WindowsPilotEvidenceEnvelopePath',
                'WindowsPilotEvidenceBodyPath',
                'WindowsPilotVerificationReportPath',
                'WindowsPilotReadinessConfigPath',
                'WindowsPilotStoredReadinessReportPath',
                'WindowsPilotReplayedReadinessReportPath',
                'LocalDataCertificationReceiptPath',
                'StablePrivatePilotObservationPath',
                'PilotTrustPolicyPath')) {
            $r8WrongStateArguments[$evidencePathArgument] =
                $r8WrongStateTemplatePath
        }
        $r8WrongStateReplayBefore = Get-StateTreeSnapshot `
            -Path $r8BundleCrashState
        [void](Invoke-Orchestrator `
            @r8WrongStateArguments `
            -ExpectFailure `
            -ExpectedMessage 'R8_BINDING_AUTHORITY_MISMATCH')
        Assert-True `
            ((Get-StateTreeSnapshot -Path $r8BundleCrashState) -ceq
                $r8WrongStateReplayBefore) `
            'Wrong-state nine-input rebuild evicted or changed a valid recoverable canonical.'
        $r8WrongExpectedHeadArguments = @{} + $r8BundleCrashArguments
        $r8WrongExpectedHeadArguments.ExpectedHeadSha256 =
            if ($r8AdapterR7HeadSha256 -cne ('f' * 64)) {
                'f' * 64
            }
            else {
                'e' * 64
            }
        $r8WrongExpectedHeadReplayBefore = Get-StateTreeSnapshot `
            -Path $r8BundleCrashState
        [void](Invoke-Orchestrator `
            @r8WrongExpectedHeadArguments `
            -ExpectFailure `
            -ExpectedMessage 'R8_BINDING_R7_HEAD_MISMATCH')
        Assert-True `
            ((Get-StateTreeSnapshot -Path $r8BundleCrashState) -ceq
                $r8WrongExpectedHeadReplayBefore) `
            'Wrong caller-selected r7 head changed the recoverable canonical or state tree.'
        $r8MissingRawReplayArguments = @{} + $r8BundleCrashArguments
        [void]$r8MissingRawReplayArguments.Remove('PilotTrustPolicyPath')
        $r8MissingRawReplayBefore = Get-StateTreeSnapshot `
            -Path $r8BundleCrashState
        [void](Invoke-Orchestrator `
            @r8MissingRawReplayArguments `
            -ExpectFailure `
            -ExpectedMessage 'requires -PilotTrustPolicyPath')
        Assert-True `
            ((Get-StateTreeSnapshot -Path $r8BundleCrashState) -ceq
                $r8MissingRawReplayBefore) `
            'Bundle-first r8 recovery without all nine raw evidence paths changed state.'
        [void](Invoke-Orchestrator @r8BundleCrashArguments)
        $r8BundleRecovered = Get-ProductionReleaseState `
            -StateRoot $r8BundleCrashState `
            -StateSchemaPath $stateV2SchemaPath
        Assert-True `
            ([int]$r8BundleRecovered.Head.revision -eq 8 -and
             [string]$r8BundleRecovered.Head.phase -ceq
                'PILOT_EVIDENCE_BOUND' -and
             @($r8BundleRecovered.Receipts).Count -eq 8) `
            'AfterPilotEvidenceBundle replay did not commit exactly one r8 receipt.'

        $r8ExpiryTemplateState = Join-Path `
            $fixtureRoot `
            'enterprise-r8-adapter-expiry-template-state'
        Copy-State `
            -Source $r8AdapterR7State `
            -Destination $r8ExpiryTemplateState
        $r8ExpiryTemplateSource = Get-ProductionReleaseState `
            -StateRoot $r8ExpiryTemplateState `
            -StateSchemaPath $stateV2SchemaPath
        [void](New-EnterpriseV2FoundationPilotEvidenceTransition `
            -State $r8ExpiryTemplateSource `
            -LifetimeSeconds 120)
        $r8ExpiryTemplateRoot = Join-Path `
            $evidenceRoot `
            'enterprise-r8-adapter-expiring-template'
        [IO.Directory]::CreateDirectory($r8ExpiryTemplateRoot) | Out-Null
        $r8ExpiryTemplatePath = Join-Path `
            $r8ExpiryTemplateRoot `
            'pilot-evidence-input.v1.json'
        [IO.File]::Copy(
            (Join-Path `
                $r8ExpiryTemplateState `
                'imports\pilot-evidence.v1\pilot-evidence-input.v1.json'),
            $r8ExpiryTemplatePath,
            $false)
        $r8ExpiryTemplateInput = Read-Json -Path $r8ExpiryTemplatePath
        $r8ExpiryUtc = [DateTimeOffset]::Parse(
            [string]$r8ExpiryTemplateInput.expiresAtUtc,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AssumeUniversal)

        $r8ExpiredBundleCrashState = Join-Path `
            $fixtureRoot `
            'enterprise-r8-adapter-expired-bundle-crash-state'
        Copy-State `
            -Source $r8AdapterR7State `
            -Destination $r8ExpiredBundleCrashState
        $r8ExpiredHeadBefore = Get-Sha256 `
            -Path (Join-Path $r8ExpiredBundleCrashState 'head.json')
        $r8ExpiredReceiptsBefore = Get-StateTreeSnapshot `
            -Path (Join-Path $r8ExpiredBundleCrashState 'receipts')
        $r8ExpiryArguments = @{} + $r8AdapterCommon
        $r8ExpiryArguments.StateRoot = $r8ExpiredBundleCrashState
        foreach ($evidencePathArgument in @(
                'WindowsPilotEvidenceEnvelopePath',
                'WindowsPilotEvidenceBodyPath',
                'WindowsPilotVerificationReportPath',
                'WindowsPilotReadinessConfigPath',
                'WindowsPilotStoredReadinessReportPath',
                'WindowsPilotReplayedReadinessReportPath',
                'LocalDataCertificationReceiptPath',
                'StablePrivatePilotObservationPath',
                'PilotTrustPolicyPath')) {
            $r8ExpiryArguments[$evidencePathArgument] = $r8ExpiryTemplatePath
        }
        [void](Invoke-Orchestrator `
            @r8ExpiryArguments `
            -FaultPoint AfterPilotEvidenceBundle `
            -ExpectFailure `
            -ExpectedMessage 'INJECTED-CRASH-AFTER-PILOT-EVIDENCE-BUNDLE')
        $r8ExpiredCanonicalRoot = Join-Path `
            $r8ExpiredBundleCrashState `
            'imports\pilot-evidence.v1'
        $r8ExpiredCanonicalPath = Join-Path `
            $r8ExpiredCanonicalRoot `
            'pilot-evidence-input.v1.json'
        Assert-True `
            ((Get-Sha256 -Path (Join-Path `
                        $r8ExpiredBundleCrashState 'head.json')) -ceq
                    $r8ExpiredHeadBefore -and
             (Get-StateTreeSnapshot -Path (Join-Path `
                        $r8ExpiredBundleCrashState 'receipts')) -ceq
                    $r8ExpiredReceiptsBefore -and
             (Test-Path -LiteralPath $r8ExpiredCanonicalPath) -and
             -not (Test-Path -LiteralPath (Join-Path `
                    $r8ExpiredBundleCrashState `
                    'receipts\0008-pilot-evidence-bound.json'))) `
            'Expiring r8 bundle crash changed head/receipts or failed to leave only the canonical bundle.'
        $r8ExpiredCanonicalBefore = Get-StateTreeSnapshot `
            -Path $r8ExpiredCanonicalRoot
        $r8ExpiredCanonicalShaBefore = Get-Sha256 `
            -Path $r8ExpiredCanonicalPath
        $r8ExpiryExternalBefore = Get-StateTreeSnapshot `
            -Path $r8ExpiryTemplateRoot
        $r8ExpiryRejectedPrefix =
            '.ensou-launcher-production-rejected-' +
            ([Guid]::Parse(
                [string]$r8AdapterPlan.orchestrationId).ToString('N')) +
            '-pilot-evidence-orphan-'
        $r8ExpiryRejectedBefore = @(
            Get-ChildItem -LiteralPath $fixtureRoot -Directory -Force `
                -Filter ($r8ExpiryRejectedPrefix + '*') `
                -ErrorAction SilentlyContinue |
                ForEach-Object { [string]$_.FullName })
        $expiryWaitMilliseconds = [int][Math]::Max(
            0,
            [Math]::Ceiling(
                ($r8ExpiryUtc - [DateTimeOffset]::UtcNow).TotalMilliseconds +
                    250))
        if ($expiryWaitMilliseconds -gt 0) {
            Start-Sleep -Milliseconds $expiryWaitMilliseconds
        }
        Assert-True `
            ([DateTimeOffset]::UtcNow -gt $r8ExpiryUtc) `
            'Expiring r8 crash-recovery fixture did not reach its declared expiry.'
        [void](Invoke-Orchestrator `
            @r8ExpiryArguments `
            -ExpectFailure `
            -ExpectedMessage 'R8_BINDING_EXPIRED')
        $r8ExpiryRejectedAfter = @(
            Get-ChildItem -LiteralPath $fixtureRoot -Directory -Force `
                -Filter ($r8ExpiryRejectedPrefix + '*') `
                -ErrorAction SilentlyContinue |
                Where-Object {
                    [string]$_.FullName -notin $r8ExpiryRejectedBefore
                })
        Assert-True `
            ($r8ExpiryRejectedAfter.Count -eq 1 -and
             -not (Test-Path -LiteralPath $r8ExpiredCanonicalRoot) -and
             (Get-StateTreeSnapshot -Path $r8ExpiryRejectedAfter[0].FullName) -ceq
                $r8ExpiredCanonicalBefore -and
             (Get-Sha256 -Path (Join-Path `
                    $r8ExpiryRejectedAfter[0].FullName `
                    'pilot-evidence-input.v1.json')) -ceq
                $r8ExpiredCanonicalShaBefore) `
            'Expired bundle-only r8 canonical was not retained in exactly one identity-bound quarantine.'
        Assert-True `
            ((Get-Sha256 -Path (Join-Path `
                        $r8ExpiredBundleCrashState 'head.json')) -ceq
                    $r8ExpiredHeadBefore -and
             (Get-StateTreeSnapshot -Path (Join-Path `
                        $r8ExpiredBundleCrashState 'receipts')) -ceq
                    $r8ExpiredReceiptsBefore -and
             (Get-StateTreeSnapshot -Path $r8ExpiryTemplateRoot) -ceq
                    $r8ExpiryExternalBefore) `
            'Expired bundle-only quarantine changed head, receipts, or external feed inputs.'

        $r8FreshRetryTemplateState = Join-Path `
            $fixtureRoot `
            'enterprise-r8-adapter-fresh-retry-template-state'
        Copy-State `
            -Source $r8AdapterR7State `
            -Destination $r8FreshRetryTemplateState
        $r8FreshRetrySource = Get-ProductionReleaseState `
            -StateRoot $r8FreshRetryTemplateState `
            -StateSchemaPath $stateV2SchemaPath
        [void](New-EnterpriseV2FoundationPilotEvidenceTransition `
            -State $r8FreshRetrySource)
        $r8FreshRetryTemplateRoot = Join-Path `
            $evidenceRoot `
            'enterprise-r8-adapter-fresh-retry-template'
        [IO.Directory]::CreateDirectory($r8FreshRetryTemplateRoot) | Out-Null
        $r8FreshRetryTemplatePath = Join-Path `
            $r8FreshRetryTemplateRoot `
            'pilot-evidence-input.v1.json'
        [IO.File]::Copy(
            (Join-Path $r8FreshRetryTemplateState `
                'imports\pilot-evidence.v1\pilot-evidence-input.v1.json'),
            $r8FreshRetryTemplatePath,
            $false)
        $r8FreshRetryArguments = @{} + $r8AdapterCommon
        $r8FreshRetryArguments.StateRoot = $r8ExpiredBundleCrashState
        foreach ($evidencePathArgument in @(
                'WindowsPilotEvidenceEnvelopePath',
                'WindowsPilotEvidenceBodyPath',
                'WindowsPilotVerificationReportPath',
                'WindowsPilotReadinessConfigPath',
                'WindowsPilotStoredReadinessReportPath',
                'WindowsPilotReplayedReadinessReportPath',
                'LocalDataCertificationReceiptPath',
                'StablePrivatePilotObservationPath',
                'PilotTrustPolicyPath')) {
            $r8FreshRetryArguments[$evidencePathArgument] =
                $r8FreshRetryTemplatePath
        }
        [void](Invoke-Orchestrator @r8FreshRetryArguments)
        $r8ExpiredBundleRecovered = Get-ProductionReleaseState `
            -StateRoot $r8ExpiredBundleCrashState `
            -StateSchemaPath $stateV2SchemaPath
        $r8FreshCanonicalPath = Join-Path `
            $r8ExpiredBundleCrashState `
            'imports\pilot-evidence.v1\pilot-evidence-input.v1.json'
        Assert-True `
            ([int]$r8ExpiredBundleRecovered.Head.revision -eq 8 -and
             [string]$r8ExpiredBundleRecovered.Head.phase -ceq
                'PILOT_EVIDENCE_BOUND' -and
             @($r8ExpiredBundleRecovered.Receipts).Count -eq 8 -and
             (Get-Sha256 -Path $r8FreshCanonicalPath) -ceq
                (Get-Sha256 -Path $r8FreshRetryTemplatePath) -and
             (Get-StateTreeSnapshot -Path $r8ExpiryRejectedAfter[0].FullName) -ceq
                $r8ExpiredCanonicalBefore) `
            'Fresh nine-input retry after expired quarantine did not commit exactly one new r8 receipt while preserving the rejected bytes.'

        $r8ReceiptCrashArguments = @{} + $r8AdapterCommon
        $r8ReceiptCrashArguments.StateRoot = $r8ReceiptCrashState
        [void](Invoke-Orchestrator `
            @r8ReceiptCrashArguments `
            -FaultPoint AfterPilotEvidenceReceipt `
            -ExpectFailure `
            -ExpectedMessage 'INJECTED-CRASH')
        Assert-True `
            ([int]((Read-Json -Path (Join-Path `
                        $r8ReceiptCrashState 'head.json')).revision) -eq 7 -and
             (Test-Path -LiteralPath (Join-Path `
                    $r8ReceiptCrashState `
                    'receipts\0008-pilot-evidence-bound.json'))) `
            'AfterPilotEvidenceReceipt did not leave the exact recoverable orphan receipt.'
        [void](Invoke-Orchestrator @r8ReceiptCrashArguments)
        $r8ReceiptRecovered = Get-ProductionReleaseState `
            -StateRoot $r8ReceiptCrashState `
            -StateSchemaPath $stateV2SchemaPath
        Assert-True `
            ([int]$r8ReceiptRecovered.Head.revision -eq 8 -and
             @($r8ReceiptRecovered.Receipts).Count -eq 8) `
            'AfterPilotEvidenceReceipt replay did not consume exactly one orphan receipt.'

        $r8ExpiringLedgerTemplateState = Join-Path `
            $fixtureRoot `
            'enterprise-r8-adapter-expiring-ledger-template-state'
        Copy-State `
            -Source $r8AdapterR7State `
            -Destination $r8ExpiringLedgerTemplateState
        $r8ExpiringLedgerSource = Get-ProductionReleaseState `
            -StateRoot $r8ExpiringLedgerTemplateState `
            -StateSchemaPath $stateV2SchemaPath
        [void](New-EnterpriseV2FoundationPilotEvidenceTransition `
            -State $r8ExpiringLedgerSource `
            -LifetimeSeconds 120)
        $r8ExpiringLedgerTemplateRoot = Join-Path `
            $evidenceRoot `
            'enterprise-r8-adapter-expiring-ledger-template'
        [IO.Directory]::CreateDirectory(
            $r8ExpiringLedgerTemplateRoot) | Out-Null
        $r8ExpiringLedgerTemplatePath = Join-Path `
            $r8ExpiringLedgerTemplateRoot `
            'pilot-evidence-input.v1.json'
        [IO.File]::Copy(
            (Join-Path $r8ExpiringLedgerTemplateState `
                'imports\pilot-evidence.v1\pilot-evidence-input.v1.json'),
            $r8ExpiringLedgerTemplatePath,
            $false)
        $r8ExpiringLedgerInput = Read-Json `
            -Path $r8ExpiringLedgerTemplatePath
        $r8ExpiringLedgerUtc = [DateTimeOffset]::Parse(
            [string]$r8ExpiringLedgerInput.expiresAtUtc,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AssumeUniversal)
        $r8ExpiredLedgerState = Join-Path `
            $fixtureRoot `
            'enterprise-r8-adapter-expired-ledger-state'
        Copy-State `
            -Source $r8AdapterR7State `
            -Destination $r8ExpiredLedgerState
        $r8ExpiredLedgerArguments = @{} + $r8AdapterCommon
        $r8ExpiredLedgerArguments.StateRoot = $r8ExpiredLedgerState
        foreach ($evidencePathArgument in @(
                'WindowsPilotEvidenceEnvelopePath',
                'WindowsPilotEvidenceBodyPath',
                'WindowsPilotVerificationReportPath',
                'WindowsPilotReadinessConfigPath',
                'WindowsPilotStoredReadinessReportPath',
                'WindowsPilotReplayedReadinessReportPath',
                'LocalDataCertificationReceiptPath',
                'StablePrivatePilotObservationPath',
                'PilotTrustPolicyPath')) {
            $r8ExpiredLedgerArguments[$evidencePathArgument] =
                $r8ExpiringLedgerTemplatePath
        }
        [void](Invoke-Orchestrator `
            @r8ExpiredLedgerArguments `
            -FaultPoint AfterPilotEvidenceReceipt `
            -ExpectFailure `
            -ExpectedMessage 'INJECTED-CRASH')
        $r8ExpiredLedgerReceiptPath = Join-Path `
            $r8ExpiredLedgerState `
            'receipts\0008-pilot-evidence-bound.json'
        $r8ExpiredLedgerReceipt = Read-Json `
            -Path $r8ExpiredLedgerReceiptPath
        $r8ExpiredLedgerIdentity = Read-Json `
            -Path (Join-Path $r8ExpiredLedgerState 'identity.json')
        $r8ExpiredLedgerPendingHead = [ordered]@{
            schemaVersion = 2
            stateType = 'ensou-dsh-launcher-production-release-head'
            orchestrationId = [string]$r8ExpiredLedgerIdentity.orchestrationId
            edition = 'Enterprise'
            planSha256 = [string]$r8ExpiredLedgerIdentity.planSha256
            identitySha256 = Get-Sha256 `
                -Path (Join-Path $r8ExpiredLedgerState 'identity.json')
            revision = 8
            phase = 'PILOT_EVIDENCE_BOUND'
            receiptFileName = '0008-pilot-evidence-bound.json'
            receiptSha256 = Get-Sha256 -Path $r8ExpiredLedgerReceiptPath
            updatedAtUtc = [string]$r8ExpiredLedgerReceipt.recordedAtUtc
            targetChannel = 'stable'
        }
        Write-CanonicalJson `
            -Path (Join-Path $r8ExpiredLedgerState 'head.json.pending') `
            -Value $r8ExpiredLedgerPendingHead
        $r8FreshLedgerMismatchArguments = @{} + $r8FreshRetryArguments
        $r8FreshLedgerMismatchArguments.StateRoot = $r8ExpiredLedgerState
        $r8FreshLedgerMismatchBefore = Get-StateTreeSnapshot `
            -Path $r8ExpiredLedgerState
        [void](Invoke-Orchestrator `
            @r8FreshLedgerMismatchArguments `
            -ExpectFailure `
            -ExpectedMessage 'R8_ORPHAN_LEDGER_RESTART_REQUIRED')
        Assert-True `
            ((Get-StateTreeSnapshot -Path $r8ExpiredLedgerState) -ceq
                $r8FreshLedgerMismatchBefore) `
            'Fresh mismatched nine-input rebuild mutated an uncommitted r8 ledger.'
        $r8ExpiredMissingCanonicalState = Join-Path `
            $fixtureRoot `
            'enterprise-r8-adapter-expired-ledger-missing-canonical-state'
        Copy-State `
            -Source $r8ExpiredLedgerState `
            -Destination $r8ExpiredMissingCanonicalState
        Remove-Item `
            -LiteralPath (Join-Path $r8ExpiredMissingCanonicalState `
                'imports\pilot-evidence.v1') `
            -Recurse `
            -Force
        $r8ExpiredMissingCanonicalArguments = @{} +
            $r8ExpiredLedgerArguments
        $r8ExpiredMissingCanonicalArguments.StateRoot =
            $r8ExpiredMissingCanonicalState
        $ledgerExpiryWaitMilliseconds = [int][Math]::Max(
            0,
            [Math]::Ceiling(
                ($r8ExpiringLedgerUtc - [DateTimeOffset]::UtcNow).TotalMilliseconds +
                    250))
        if ($ledgerExpiryWaitMilliseconds -gt 0) {
            Start-Sleep -Milliseconds $ledgerExpiryWaitMilliseconds
        }
        $r8ExpiredLedgerBefore = Get-StateTreeSnapshot `
            -Path $r8ExpiredLedgerState
        [void](Invoke-Orchestrator `
            @r8ExpiredLedgerArguments `
            -ExpectFailure `
            -ExpectedMessage 'R8_ORPHAN_LEDGER_RESTART_REQUIRED')
        Assert-True `
            ((Get-StateTreeSnapshot -Path $r8ExpiredLedgerState) -ceq
                $r8ExpiredLedgerBefore) `
            'Expired canonical with orphan receipt/pending head was mutated instead of requiring a new StateRoot.'
        $r8ExpiredMissingCanonicalBefore = Get-StateTreeSnapshot `
            -Path $r8ExpiredMissingCanonicalState
        [void](Invoke-Orchestrator `
            @r8ExpiredMissingCanonicalArguments `
            -ExpectFailure `
            -ExpectedMessage 'R8_ORPHAN_LEDGER_RESTART_REQUIRED')
        Assert-True `
            ((Get-StateTreeSnapshot -Path $r8ExpiredMissingCanonicalState) -ceq
                $r8ExpiredMissingCanonicalBefore) `
            'Expired orphan r8 ledger without a canonical was mutated or reported as retryable.'

        $r8LedgerRestartState = Join-Path `
            $fixtureRoot `
            'enterprise-r8-adapter-ledger-restart-state'
        Copy-State `
            -Source $r8AdapterR7State `
            -Destination $r8LedgerRestartState
        $r8LedgerRestartArguments = @{} + $r8FreshRetryArguments
        $r8LedgerRestartArguments.StateRoot = $r8LedgerRestartState
        [void](Invoke-Orchestrator @r8LedgerRestartArguments)
        Assert-True `
            ([int]((Read-Json -Path (Join-Path `
                        $r8LedgerRestartState 'head.json')).revision) -eq 8 -and
             (Get-StateTreeSnapshot -Path $r8ExpiredLedgerState) -ceq
                $r8ExpiredLedgerBefore) `
            'Fresh new-StateRoot restart did not reach r8 or altered the retained expired ledger diagnostics.'
        Write-Output `
            'R8-ORCHESTRATION-ADAPTER-BOUNDARY-PASS: committed test double exercised process invocation, deterministic bundle replay, and receipt recovery; production evidence cryptography remains separately gated.'

        $stableR8RecoveryState = Join-Path `
            $fixtureRoot `
            'enterprise-stable-v2-r8-orphan-recovery-state'
        Copy-State `
            -Source $stableR6ReplayState `
            -Destination $stableR8RecoveryState
        $stableR8Source = Get-ProductionReleaseState `
            -StateRoot $stableR8RecoveryState `
            -StateSchemaPath $stateV2SchemaPath
        $stableR8Data =
            New-EnterpriseV2FoundationPilotEvidenceTransition `
                -State $stableR8Source
        Assert-Throws `
            -Label 'Enterprise r8 orphan receipt injection' `
            -ExpectedMessage 'INJECTED-CRASH' `
            -Action {
                [void](Add-V2FoundationTransition `
                    -StateRoot $stableR8RecoveryState `
                    -StateSchemaPath $stateV2SchemaPath `
                    -Phase 'PILOT_EVIDENCE_BOUND' `
                    -Data $stableR8Data `
                    -FaultAfterReceipt)
            }
        Assert-True `
            ([int]((Read-Json -Path (Join-Path `
                        $stableR8RecoveryState 'head.json')).revision) -eq 7) `
            'Enterprise r8 orphan receipt advanced the state head.'
        $stableR8PathOnlySnapshot = Get-StateTreeSnapshot `
            -Path $stableR8RecoveryState
        [void](Invoke-Orchestrator `
            -ScriptPath $orchestrator `
            -RepoRoot $sourceRepo `
            -Edition Enterprise `
            -Phase BindPilotEvidence `
            -PlanPath $stableV2PlanPath `
            -StateRoot $stableR8RecoveryState `
            -ExpectedHeadSha256 ([string]$stableR8Source.HeadSha256) `
            -ExpectFailure `
            -ExpectedMessage 'requires -WindowsPilotEvidenceEnvelopePath')
        Assert-True `
            ((Get-StateTreeSnapshot -Path $stableR8RecoveryState) -ceq
                $stableR8PathOnlySnapshot) `
            'Enterprise r8 path-only orphan recovery changed state.'
        # This fixture advances the already schema-validated synthetic state
        # directly so later state-reader negatives stay independent of the
        # production adapter. It does not model production r7-to-r8 admission.
        [void](Add-V2FoundationTransition `
            -StateRoot $stableR8RecoveryState `
            -StateSchemaPath $stateV2SchemaPath `
            -Phase 'PILOT_EVIDENCE_BOUND' `
            -Data $stableR8Data)
        $stableR8Recovered = Get-ProductionReleaseState `
            -StateRoot $stableR8RecoveryState `
            -StateSchemaPath $stateV2SchemaPath
        Assert-True `
            ([int]$stableR8Recovered.Head.revision -eq 8 -and
             [string]$stableR8Recovered.Head.phase -ceq
                'PILOT_EVIDENCE_BOUND' -and
             @($stableR8Recovered.Receipts).Count -eq 8) `
            'Enterprise r8 orphan recovery did not reach the exact typed phase.'
        $stableR8Summary = Get-ProductionReleaseStateSummary `
            -StateRoot $stableR8RecoveryState `
            -StateSchemaPath $stateV2SchemaPath
        Assert-True `
            ([string]$stableR8Summary.NoGoCode -ceq
                'PHASE_NOT_IMPLEMENTED_STABLE_PROMOTION_REQUESTED' -and
             -not [bool]$stableR8Summary.StableReady) `
            'Enterprise r8 binding did not retain the r9 NO-GO boundary.'
        $stableR8TamperedState = Join-Path `
            $fixtureRoot `
            'enterprise-stable-v2-r8-tampered-state'
        Copy-State `
            -Source $stableR8RecoveryState `
            -Destination $stableR8TamperedState
        $stableR8InputPath = Join-Path `
            $stableR8TamperedState `
            'imports\pilot-evidence.v1\pilot-evidence-input.v1.json'
        $stableR8Input = Read-Json -Path $stableR8InputPath
        $stableR8Input.stablePrivatePilot.targetObjectSetSha256 = 'f' * 64
        Write-CanonicalJson -Path $stableR8InputPath -Value $stableR8Input
        [void](Invoke-Orchestrator `
            -ScriptPath $orchestrator `
            -RepoRoot $sourceRepo `
            -Edition Enterprise `
            -Phase Status `
            -PlanPath $stableV2PlanPath `
            -StateRoot $stableR8TamperedState `
            -ExpectFailure `
            -ExpectedMessage 'differs from its typed r8 receipt')

        $stableR8ExpiredState = Join-Path `
            $fixtureRoot `
            'enterprise-stable-v2-r8-expired-state'
        Copy-State `
            -Source $stableR6ReplayState `
            -Destination $stableR8ExpiredState
        $stableR8ExpirySource = Get-ProductionReleaseState `
            -StateRoot $stableR8ExpiredState `
            -StateSchemaPath $stateV2SchemaPath
        $stableR8ExpiryData =
            New-EnterpriseV2FoundationPilotEvidenceTransition `
                -State $stableR8ExpirySource `
                -LifetimeSeconds 3
        [void](Add-V2FoundationTransition `
            -StateRoot $stableR8ExpiredState `
            -StateSchemaPath $stateV2SchemaPath `
            -Phase 'PILOT_EVIDENCE_BOUND' `
            -Data $stableR8ExpiryData)
        Start-Sleep -Seconds 4
        $stableR8ExpiredSnapshot =
            Get-StateTreeSnapshot -Path $stableR8ExpiredState
        $stableR8ExpiredSummary = Get-ProductionReleaseStateSummary `
            -StateRoot $stableR8ExpiredState `
            -StateSchemaPath $stateV2SchemaPath
        Assert-True `
            ([string]$stableR8ExpiredSummary.PilotEvidenceStatus -ceq 'STALE' -and
             [string]$stableR8ExpiredSummary.NoGoCode -ceq
                'R8_BINDING_EXPIRED' -and
             -not [bool]$stableR8ExpiredSummary.PilotReady -and
             -not [bool]$stableR8ExpiredSummary.StableReady -and
             -not [string]::IsNullOrWhiteSpace(
                [string]$stableR8ExpiredSummary.PilotEvidenceExpiresAtUtc)) `
            'Expired committed r8 status did not remain historical-only, stale, and not ready.'
        [void](Invoke-Orchestrator `
            -ScriptPath $orchestrator `
            -RepoRoot $sourceRepo `
            -Edition Enterprise `
            -Phase Status `
            -PlanPath $stableV2PlanPath `
            -StateRoot $stableR8ExpiredState)
        Assert-True `
            ((Get-StateTreeSnapshot -Path $stableR8ExpiredState) -ceq
                $stableR8ExpiredSnapshot) `
            'Historical Status replay changed expired committed r8 state.'
        [void](Invoke-Orchestrator `
            -ScriptPath $orchestrator `
            -RepoRoot $sourceRepo `
            -Edition Enterprise `
            -Phase Promote `
            -PlanPath $stableV2PlanPath `
            -StateRoot $stableR8ExpiredState `
            -ExpectFailure `
            -ExpectedMessage 'R8_BINDING_EXPIRED')
        Assert-True `
            ((Get-StateTreeSnapshot -Path $stableR8ExpiredState) -ceq
                $stableR8ExpiredSnapshot) `
            'Expired committed r8 Promote rejection changed state or feed eligibility.'

        [void](Advance-V2FoundationState -StateRoot $pilotV2State -StateSchemaPath $stateV2SchemaPath -TargetRevision 7)
        # Enterprise Stable r9 now requires the exact state-owned five-file
        # feed-promotion admission bundle. This foundation replay has no
        # authenticated promoter response and must remain at typed r8.
        [void](Advance-V2FoundationState -StateRoot $stableV2State -StateSchemaPath $stateV2SchemaPath -TargetRevision 8)

        $pilotBeforeGeneric = Get-StateTreeSnapshot -Path $pilotV2State
        Assert-Throws -Label 'Personal foundation cannot invent publication' -ExpectedMessage 'foundation evidence is not publication' -Action {
            [void](Advance-V2FoundationState -StateRoot $pilotV2State -StateSchemaPath $stateV2SchemaPath -TargetRevision 9)
        }
        Assert-Throws -Label 'Personal generic r8 refuses before receipt write' -ExpectedMessage 'generic evidence cannot advance' -Action {
            [void](Add-V2FoundationTransition -StateRoot $pilotV2State -StateSchemaPath $stateV2SchemaPath -Phase 'PILOT_PROMOTION_REQUESTED' -Data (New-V2FoundationEvidenceData -Revision 8 -Phase 'PILOT_PROMOTION_REQUESTED'))
        }
        Assert-True ((Get-StateTreeSnapshot -Path $pilotV2State) -ceq $pilotBeforeGeneric) 'Rejected Personal generic publication evidence changed state.'

        $pilotTerminalSummary = Get-ProductionReleaseStateSummary -StateRoot $pilotV2State -StateSchemaPath $stateV2SchemaPath
        $stableR8FoundationSummary = Get-ProductionReleaseStateSummary -StateRoot $stableV2State -StateSchemaPath $stateV2SchemaPath
        Assert-True ([int]$pilotTerminalSummary.Revision -eq 7 -and -not [bool]$pilotTerminalSummary.LifecycleTerminal) 'Personal foundation bypassed authenticated feed publication.'
        Assert-True (-not [bool]$pilotTerminalSummary.PilotReady -and -not [bool]$pilotTerminalSummary.StableReady) 'Plan v2 foundation-only Pilot terminal state claimed readiness.'
        Assert-True ([string]$pilotTerminalSummary.NoGo -like 'NO-GO:*') 'Personal unpromoted foundation lost its explicit NO-GO message.'
        Assert-True `
            ([int]$stableR8FoundationSummary.Revision -eq 8 -and
             [string]$stableR8FoundationSummary.Phase -ceq 'PILOT_EVIDENCE_BOUND' -and
             -not [bool]$stableR8FoundationSummary.LifecycleTerminal -and
             -not [bool]$stableR8FoundationSummary.StableReady -and
             [string]$stableR8FoundationSummary.NoGoCode -ceq
                'PHASE_NOT_IMPLEMENTED_STABLE_PROMOTION_REQUESTED') `
            'Enterprise Stable foundation replay did not remain fail-closed at typed r8 pending authenticated r9 promotion.'
        Assert-True `
            (-not (Test-Path -LiteralPath (Join-Path `
                        $stableV2State `
                        'requests\stable-feed-promotion.v1'))) `
            'Enterprise Stable foundation replay invented an unauthenticated r9 admission bundle.'
        # Full r9 success is not part of this unsigned foundation fixture.
    } $pilotV2FoundationState $stableV2FoundationState
    }

    if ($Shard -in @('All', 'ImportAndPersonal')) {
    if ($useProductRoleFixture) {
        [void](Invoke-Orchestrator -ScriptPath $orchestrator -RepoRoot $sourceRepo -Edition Personal -Phase ImportClientSignatures -PlanPath $pilotV2PlanPath -StateRoot $pilotV2State -ResponsePath $pilotV2ResponsePath -ExpectedHeadSha256 (Get-Sha256 -Path (Join-Path $pilotV2State 'head.json')))
        [void](Invoke-Orchestrator -ScriptPath $orchestrator -RepoRoot $sourceRepo -Edition Enterprise -Phase ImportClientSignatures -PlanPath $stableV2PlanPath -StateRoot $stableV2State -ResponsePath $stableV2ResponsePath -ExpectedHeadSha256 (Get-Sha256 -Path (Join-Path $stableV2State 'head.json')))
        Assert-True ([int]((Read-Json -Path (Join-Path $pilotV2State 'head.json')).revision) -eq 3 -and [string]((Read-Json -Path (Join-Path $pilotV2State 'head.json')).phase) -ceq 'CLIENT_SIGNATURES_IMPORTED') 'Plan v2 Pilot did not pass authenticated PE and RFC3161 client-signing import.'
        Assert-True ([int]((Read-Json -Path (Join-Path $stableV2State 'head.json')).revision) -eq 3 -and [string]((Read-Json -Path (Join-Path $stableV2State 'head.json')).phase) -ceq 'CLIENT_SIGNATURES_IMPORTED') 'Plan v2 Stable did not pass authenticated PE and RFC3161 client-signing import.'
        [void](Invoke-TestPilotManifestFoundation `
            -ScriptPath $orchestrator `
            -RepoRoot $sourceRepo `
            -Edition Personal `
            -PlanPath $pilotV2PlanPath `
            -StateRoot $pilotV2State `
            -FixtureRoot (Join-Path `
                $fixtureRoot `
                'personal-real-rfc3161-manifest-foundation') `
            -Signer $manifestResponseSigner `
            -ReleaseSigner $releaseManifestSigner)
        [void](Invoke-TestPilotManifestFoundation `
            -ScriptPath $orchestrator `
            -RepoRoot $sourceRepo `
            -Edition Enterprise `
            -PlanPath $stableV2PlanPath `
            -StateRoot $stableV2State `
            -FixtureRoot (Join-Path `
                $fixtureRoot `
                'enterprise-real-rfc3161-manifest-foundation') `
            -Signer $manifestResponseSigner `
            -ReleaseSigner $releaseManifestSigner)
        [void](Advance-V2FoundationState -StateRoot $pilotV2State -StateSchemaPath $stateV2SchemaPath -TargetRevision 7)
        Assert-Throws -Label 'Authenticated client import cannot invent Personal publication' -ExpectedMessage 'foundation evidence is not publication' -Action {
            [void](Advance-V2FoundationState -StateRoot $pilotV2State -StateSchemaPath $stateV2SchemaPath -TargetRevision 9)
        }
        [void](Advance-V2FoundationState -StateRoot $stableV2State -StateSchemaPath $stateV2SchemaPath -TargetRevision 8)
        $pilotV2ImportedTerminal = Get-ProductionReleaseStateSummary -StateRoot $pilotV2State -StateSchemaPath $stateV2SchemaPath
        $stableV2ImportedR8 = Get-ProductionReleaseStateSummary -StateRoot $stableV2State -StateSchemaPath $stateV2SchemaPath
        Assert-True ([int]$pilotV2ImportedTerminal.Revision -eq 7 -and -not [bool]$pilotV2ImportedTerminal.LifecycleTerminal) 'Authenticated client import bypassed Personal feed evidence.'
        Assert-True (-not [bool]$pilotV2ImportedTerminal.PilotReady -and -not [bool]$pilotV2ImportedTerminal.StableReady) 'Foundation-only Personal continuation after authenticated v2 import claimed readiness.'
        Assert-True ([string]$pilotV2ImportedTerminal.NoGo -like 'NO-GO:*') 'Personal unpromoted state lost its NO-GO status.'
        Assert-True `
            ([int]$stableV2ImportedR8.Revision -eq 8 -and
             [string]$stableV2ImportedR8.Phase -ceq 'PILOT_EVIDENCE_BOUND' -and
             -not [bool]$stableV2ImportedR8.StableReady -and
             [string]$stableV2ImportedR8.NoGoCode -ceq
                'PHASE_NOT_IMPLEMENTED_STABLE_PROMOTION_REQUESTED') `
            'Authenticated v2 Enterprise import bypassed the exact r9 feed-promotion admission boundary.'
        Write-Output 'V2-PRODUCTION-IMPORT-INTEGRATION-PASS: authenticated client import remains distinct from completed feed publication.'
    }
    else {
        $expectedV2ImportFailure = 'Signed PE does not have Windows Authenticode Status=Valid'
        $pilotV2RejectedSnapshotBefore = Get-StateTreeSnapshot -Path $pilotV2State
        $stableV2RejectedSnapshotBefore = Get-StateTreeSnapshot -Path $stableV2State
        [void](Invoke-Orchestrator -ScriptPath $orchestrator -RepoRoot $sourceRepo -Edition Personal -Phase ImportClientSignatures -PlanPath $pilotV2PlanPath -StateRoot $pilotV2State -ResponsePath $pilotV2ResponsePath -ExpectedHeadSha256 (Get-Sha256 -Path (Join-Path $pilotV2State 'head.json')) -ExpectFailure -ExpectedMessage $expectedV2ImportFailure)
        [void](Invoke-Orchestrator -ScriptPath $orchestrator -RepoRoot $sourceRepo -Edition Enterprise -Phase ImportClientSignatures -PlanPath $stableV2PlanPath -StateRoot $stableV2State -ResponsePath $stableV2ResponsePath -ExpectedHeadSha256 (Get-Sha256 -Path (Join-Path $stableV2State 'head.json')) -ExpectFailure -ExpectedMessage $expectedV2ImportFailure)
        Assert-True ((Get-StateTreeSnapshot -Path $pilotV2State) -ceq $pilotV2RejectedSnapshotBefore) 'Rejected v2 Pilot response changed state inventory or bytes.'
        Assert-True ((Get-StateTreeSnapshot -Path $stableV2State) -ceq $stableV2RejectedSnapshotBefore) 'Rejected v2 Stable response changed state inventory or bytes.'
        foreach ($blockedV2State in @($pilotV2State, $stableV2State)) {
            $blockedV2Summary = Get-ProductionReleaseStateSummary -StateRoot $blockedV2State -StateSchemaPath $stateV2SchemaPath
            Assert-True ([int]$blockedV2Summary.Revision -eq 2 -and [string]$blockedV2Summary.Phase -ceq 'CLIENT_SIGNING_REQUESTED') 'Untrusted v2 client-signing response advanced state.'
            Assert-True (@(Get-ChildItem -LiteralPath (Join-Path $blockedV2State 'receipts') -Force).Count -eq 2) 'Rejected v2 client-signing response appended a receipt.'
            Assert-True (-not [bool]$blockedV2Summary.PilotReady -and -not [bool]$blockedV2Summary.StableReady) 'Rejected v2 client-signing response claimed readiness.'
        }
        Write-Output 'V2-PRODUCTION-IMPORT-INTEGRATION-NOT-EXECUTED: explicit signed product-role fixtures were not supplied. Unsigned negative responses remained at revision 2; foundation and checkout/CAS checks do not substitute for signed-product admission.'
    }

    $personalHeadShaBefore = Get-Sha256 -Path $personalHeadPath
    [void](Invoke-Orchestrator -ScriptPath $orchestrator -RepoRoot $sourceRepo -Edition Personal -Phase Prepare -PlanPath $personalPlanPath -StateRoot $personalState)
    Assert-True ((Get-Sha256 -Path $personalHeadPath) -ceq $personalHeadShaBefore) 'Prepare idempotency changed the admitted state head.'
    Assert-True (@(Get-ChildItem -LiteralPath (Join-Path $personalState 'receipts') -Force).Count -eq 2) 'Prepare idempotency appended a duplicate receipt.'

    foreach ($crash in @(
            'AfterInitializationRoot',
            'AfterPlanPending',
            'AfterPlanSnapshot',
            'AfterIdentityPending',
            'AfterIdentity',
            'AfterPlanReceipt',
            'AfterRequestFile',
            'AfterClientRequestReceipt')) {
        $crashState = Join-Path $fixtureRoot ('crash-' + $crash)
        [void](Invoke-Orchestrator -ScriptPath $orchestrator -RepoRoot $sourceRepo -Edition Personal -Phase Prepare -PlanPath $personalPlanPath -StateRoot $crashState -FaultPoint $crash -ExpectFailure -ExpectedMessage 'INJECTED-CRASH')
        if ($crash -in @(
                'AfterInitializationRoot',
                'AfterPlanPending',
                'AfterPlanSnapshot',
                'AfterIdentityPending',
                'AfterIdentity')) {
            $incompleteSnapshotBefore = Get-StateTreeSnapshot -Path $crashState
            [void](Invoke-Orchestrator `
                -ScriptPath $orchestrator `
                -RepoRoot $sourceRepo `
                -Edition Personal `
                -Phase ImportClientSignatures `
                -PlanPath $personalPlanPath `
                -StateRoot $crashState `
                -ExpectFailure `
                -ExpectedMessage 'cannot recover an incomplete production state root')
            Assert-True ((Get-StateTreeSnapshot -Path $crashState) -ceq $incompleteSnapshotBefore) "Non-Prepare phase mutated incomplete initialization after $crash."
        }
        [void](Invoke-Orchestrator -ScriptPath $orchestrator -RepoRoot $sourceRepo -Edition Personal -Phase Prepare -PlanPath $personalPlanPath -StateRoot $crashState)
        $crashHead = Read-Json -Path (Join-Path $crashState 'head.json')
        Assert-True ([string]$crashHead.phase -ceq 'CLIENT_SIGNING_REQUESTED') "Crash recovery failed for $crash."
        Assert-True (@(Get-ChildItem -LiteralPath (Join-Path $crashState 'receipts') -Force).Count -eq 2) "Crash recovery duplicated receipts for $crash."
    }

    $unknownState = Join-Path $fixtureRoot 'unknown-preexisting-state'
    [IO.Directory]::CreateDirectory($unknownState) | Out-Null
    [IO.File]::WriteAllText(
        (Join-Path $unknownState 'operator-sentinel.txt'),
        'PRESERVE-UNKNOWN-STATE',
        $utf8)
    $unknownSnapshotBefore = Get-StateTreeSnapshot -Path $unknownState
    [void](Invoke-Orchestrator `
        -ScriptPath $orchestrator `
        -RepoRoot $sourceRepo `
        -Edition Personal `
        -Phase Prepare `
        -PlanPath $personalPlanPath `
        -StateRoot $unknownState `
        -ExpectFailure `
        -ExpectedMessage 'lock file is missing')
    Assert-True ((Get-StateTreeSnapshot -Path $unknownState) -ceq $unknownSnapshotBefore) 'Prepare mutated an unknown pre-existing state root.'

    $unownedState = Join-Path $fixtureRoot 'unowned-lock-shaped-state'
    [IO.Directory]::CreateDirectory($unownedState) | Out-Null
    [IO.File]::WriteAllBytes((Join-Path $unownedState 'state.lock'), [byte[]]::new(0))
    $unownedSnapshotBefore = Get-StateTreeSnapshot -Path $unownedState
    [void](Invoke-Orchestrator `
        -ScriptPath $orchestrator `
        -RepoRoot $sourceRepo `
        -Edition Personal `
        -Phase Prepare `
        -PlanPath $personalPlanPath `
        -StateRoot $unownedState `
        -ExpectFailure `
        -ExpectedMessage 'not bound to an initialization owner')
    Assert-True ((Get-StateTreeSnapshot -Path $unownedState) -ceq $unownedSnapshotBefore) 'Prepare adopted an unowned lock-shaped state root.'

    $admissionRetryRoot = Join-Path $evidenceRoot 'admission-retry-runtime'
    [IO.Directory]::CreateDirectory($admissionRetryRoot) | Out-Null
    $admissionRetryArchive = Join-Path $admissionRetryRoot $runtimeName
    $admissionRetryPlan = $personalPlan | ConvertTo-Json -Depth 64 -Compress | ConvertFrom-Json -Depth 64 -DateKind String
    $admissionRetryPlan.orchestrationId = [Guid]::NewGuid().ToString()
    $admissionRetryPlan.runtimeCandidate.archive.path = $admissionRetryArchive
    $admissionRetryPlanPath = Join-Path $evidenceRoot 'personal-admission-retry-plan.json'
    Write-Json -Path $admissionRetryPlanPath -Value $admissionRetryPlan
    $admissionRetryState = Join-Path $fixtureRoot 'input-admission-retry-state'
    [void](Invoke-Orchestrator `
        -ScriptPath $orchestrator `
        -RepoRoot $sourceRepo `
        -Edition Personal `
        -Phase Prepare `
        -PlanPath $admissionRetryPlanPath `
        -StateRoot $admissionRetryState `
        -ExpectFailure)
    Assert-True (
        (Test-Path -LiteralPath (Join-Path $admissionRetryState 'initialization.json') -PathType Leaf) -and
        (Test-Path -LiteralPath (Join-Path $admissionRetryState 'identity.json') -PathType Leaf) -and
        -not (Test-Path -LiteralPath (Join-Path $admissionRetryState 'head.json'))) 'Failed input admission did not leave an exact recoverable pre-admission state.'
    [IO.File]::Copy($runtimeArchivePath, $admissionRetryArchive, $false)
    [void](Invoke-Orchestrator `
        -ScriptPath $orchestrator `
        -RepoRoot $sourceRepo `
        -Edition Personal `
        -Phase Prepare `
        -PlanPath $admissionRetryPlanPath `
        -StateRoot $admissionRetryState)
    Assert-True ([string]((Read-Json -Path (Join-Path $admissionRetryState 'head.json')).phase) -ceq 'CLIENT_SIGNING_REQUESTED') 'Exact input restoration did not recover the pre-admission state.'

    foreach ($pendingCase in @('recover', 'extra-property')) {
        $pendingState = Join-Path $fixtureRoot ('pending-head-' + $pendingCase)
        [void](Invoke-Orchestrator -ScriptPath $orchestrator -RepoRoot $sourceRepo -Edition Personal -Phase Prepare -PlanPath $personalPlanPath -StateRoot $pendingState -FaultPoint AfterPlanReceipt -ExpectFailure -ExpectedMessage 'INJECTED-CRASH')
        $pendingIdentityPath = Join-Path $pendingState 'identity.json'
        $pendingReceiptPath = Join-Path $pendingState 'receipts\0001-plan-admitted.json'
        $pendingIdentity = Read-Json -Path $pendingIdentityPath
        $pendingReceipt = Read-Json -Path $pendingReceiptPath
        $pendingHeadValue = [ordered]@{
            schemaVersion = 2
            stateType = 'ensou-dsh-launcher-production-release-head'
            orchestrationId = [string]$pendingIdentity.orchestrationId
            edition = [string]$pendingIdentity.edition
            planSha256 = [string]$pendingIdentity.planSha256
            identitySha256 = Get-Sha256 -Path $pendingIdentityPath
            revision = 1
            phase = 'PLAN_ADMITTED'
            receiptFileName = '0001-plan-admitted.json'
            receiptSha256 = Get-Sha256 -Path $pendingReceiptPath
            updatedAtUtc = [string]$pendingReceipt.recordedAtUtc
            targetChannel = 'pilot'
        }
        if ($pendingCase -ceq 'extra-property') {
            $pendingHeadValue['extra'] = $true
        }
        [IO.File]::WriteAllBytes(
            (Join-Path $pendingState 'head.json.pending'),
            (ConvertTo-ProductionJsonBytes -Value $pendingHeadValue))
        if ($pendingCase -ceq 'recover') {
            [void](Invoke-Orchestrator -ScriptPath $orchestrator -RepoRoot $sourceRepo -Edition Personal -Phase Prepare -PlanPath $personalPlanPath -StateRoot $pendingState)
            Assert-True ([string]((Read-Json -Path (Join-Path $pendingState 'head.json')).phase) -ceq 'CLIENT_SIGNING_REQUESTED') 'Exact pending head did not resume through compare-and-swap recovery.'
        }
        else {
            [void](Invoke-Orchestrator -ScriptPath $orchestrator -RepoRoot $sourceRepo -Edition Personal -Phase Status -PlanPath $personalPlanPath -StateRoot $pendingState -ExpectFailure)
            Assert-True (-not (Test-Path -LiteralPath (Join-Path $pendingState 'head.json'))) 'Tampered pending head advanced production state.'
        }
    }

    $personalRequestPath = Join-Path $personalState 'requests\client-signing.v1\signing-request.v1.json'
    $enterpriseRequestPath = Join-Path $enterpriseState 'requests\client-signing.v1\signing-request.v1.json'
    $personalResponsePath = New-ResponseFixture -RequestPath $personalRequestPath -OutputRoot (Join-Path $fixtureRoot 'personal-response') -Signer $responseSigner
    $personalResponse = Read-Json -Path $personalResponsePath
    $v1CompatibilityResponse = $personalResponse |
        ConvertTo-Json -Depth 64 -Compress |
        ConvertFrom-Json -Depth 64 -DateKind String
    $v1CompatibilityResponse.authentication.PSObject.Properties.Remove('purpose')
    $v1CompatibilityResponse.authentication.PSObject.Properties.Remove('payloadType')
    $frozenV1Payload = Get-FrozenV1SigningAuthenticationPayload -Response $v1CompatibilityResponse
    $currentV1Payload = Get-ProductionReleaseSigningResponseAuthenticationPayload -Response $v1CompatibilityResponse
    Assert-True ([Convert]::ToHexString($frozenV1Payload) -ceq [Convert]::ToHexString($currentV1Payload)) 'Plan v1 external-response authentication payload bytes changed.'
    if ($useProductRoleFixture) {
        $enterpriseResponsePath = New-ResponseFixture -RequestPath $enterpriseRequestPath -OutputRoot (Join-Path $fixtureRoot 'enterprise-response') -Signer $responseSigner
        [void](Invoke-Orchestrator -ScriptPath $orchestrator -RepoRoot $sourceRepo -Edition Personal -Phase ImportClientSignatures -PlanPath $personalPlanPath -StateRoot $personalState -ResponsePath $personalResponsePath -ExpectedHeadSha256 (Get-Sha256 -Path $personalHeadPath))
        [void](Invoke-Orchestrator -ScriptPath $orchestrator -RepoRoot $sourceRepo -Edition Enterprise -Phase ImportClientSignatures -PlanPath $enterprisePlanPath -StateRoot $enterpriseState -ResponsePath $enterpriseResponsePath -ExpectedHeadSha256 (Get-Sha256 -Path $enterpriseHeadPath))
        Assert-True ([string]((Read-Json -Path $personalHeadPath).phase) -ceq 'CLIENT_SIGNATURES_IMPORTED') 'Personal signed response was not imported.'
        Assert-True ([string]((Read-Json -Path $enterpriseHeadPath).phase) -ceq 'CLIENT_SIGNATURES_IMPORTED') 'Enterprise signed response was not imported.'
        $importedHeadSha = Get-Sha256 -Path $personalHeadPath
        [void](Invoke-Orchestrator -ScriptPath $orchestrator -RepoRoot $sourceRepo -Edition Personal -Phase ImportClientSignatures -PlanPath $personalPlanPath -StateRoot $personalState -ResponsePath $personalResponsePath -ExpectedHeadSha256 $personalHeadShaBefore)
        Assert-True ((Get-Sha256 -Path $personalHeadPath) -ceq $importedHeadSha) 'Import idempotency changed the admitted state head.'
        Assert-True (@(Get-ChildItem -LiteralPath (Join-Path $personalState 'receipts') -Force).Count -eq 3) 'Import idempotency appended a duplicate receipt.'

        $preparedSource = Join-Path $fixtureRoot 'crash-AfterRequestFile'
        $importCrashState = Join-Path $fixtureRoot 'crash-import-receipt'
        Copy-State -Source $preparedSource -Destination $importCrashState
        $preparedHeadSha = Get-Sha256 -Path (Join-Path $importCrashState 'head.json')
        [void](Invoke-Orchestrator -ScriptPath $orchestrator -RepoRoot $sourceRepo -Edition Personal -Phase ImportClientSignatures -PlanPath $personalPlanPath -StateRoot $importCrashState -ResponsePath $personalResponsePath -ExpectedHeadSha256 $preparedHeadSha -FaultPoint AfterImportReceipt -ExpectFailure -ExpectedMessage 'INJECTED-CRASH')
        [void](Invoke-Orchestrator -ScriptPath $orchestrator -RepoRoot $sourceRepo -Edition Personal -Phase ImportClientSignatures -PlanPath $personalPlanPath -StateRoot $importCrashState -ResponsePath $personalResponsePath -ExpectedHeadSha256 $preparedHeadSha)
        Assert-True ([string]((Read-Json -Path (Join-Path $importCrashState 'head.json')).phase) -ceq 'CLIENT_SIGNATURES_IMPORTED') 'Import receipt crash did not resume.'
    }
    else {
        $expectedImportFailure = 'Signed PE does not have Windows Authenticode Status=Valid'
        $personalRejectedSnapshotBefore = Get-StateTreeSnapshot -Path $personalState
        [void](Invoke-Orchestrator -ScriptPath $orchestrator -RepoRoot $sourceRepo -Edition Personal -Phase ImportClientSignatures -PlanPath $personalPlanPath -StateRoot $personalState -ResponsePath $personalResponsePath -ExpectedHeadSha256 (Get-Sha256 -Path $personalHeadPath) -ExpectFailure -ExpectedMessage $expectedImportFailure)
        Assert-True ((Get-StateTreeSnapshot -Path $personalState) -ceq $personalRejectedSnapshotBefore) 'Legacy/non-RFC3161 response changed Personal state inventory or bytes.'
    }

    $preparedState = Join-Path $fixtureRoot 'crash-AfterClientRequestReceipt'
    $preparedHead = Join-Path $preparedState 'head.json'
    $responseCases = @(
        [pscustomobject]@{ Name = 'wrong-nonce'; Args = @{ NonceOverride = ('A' * 43) } },
        [pscustomobject]@{ Name = 'stale'; Args = @{ CompletedOffsetMinutes = -180 } },
        [pscustomobject]@{ Name = 'future'; Args = @{ CompletedOffsetMinutes = 10 } },
        [pscustomobject]@{ Name = 'wrong-hash'; Args = @{ CorruptHashIndex = 0 } },
        [pscustomobject]@{ Name = 'unsigned'; Args = @{ UnsignedRoleIndex = 0 } },
        [pscustomobject]@{ Name = 'missing-role'; Args = @{ MissingRole = $true } },
        [pscustomobject]@{ Name = 'extra-role'; Args = @{ ExtraRole = $true } }
    )
    foreach ($case in $responseCases) {
        $caseState = Join-Path $fixtureRoot ('response-state-' + $case.Name)
        Copy-State -Source $preparedState -Destination $caseState
        $caseResponseRoot = Join-Path $fixtureRoot ('response-' + $case.Name)
        $caseArguments = $case.Args
        $caseResponse = New-ResponseFixture -RequestPath (Join-Path $caseState 'requests\client-signing.v1\signing-request.v1.json') -OutputRoot $caseResponseRoot -Signer $responseSigner @caseArguments
        $caseStateSnapshotBefore = Get-StateTreeSnapshot -Path $caseState
        [void](Invoke-Orchestrator -ScriptPath $orchestrator -RepoRoot $sourceRepo -Edition Personal -Phase ImportClientSignatures -PlanPath $personalPlanPath -StateRoot $caseState -ResponsePath $caseResponse -ExpectedHeadSha256 (Get-Sha256 -Path (Join-Path $caseState 'head.json')) -ExpectFailure)
        Assert-True ((Get-StateTreeSnapshot -Path $caseState) -ceq $caseStateSnapshotBefore) "Negative response '$($case.Name)' changed state inventory or bytes."
        $personalImportStagingPrefix = '.ensou-launcher-production-staging-' +
            ([Guid]::Parse([string]$personalPlan.orchestrationId)).ToString('N') +
            '-import-'
        Assert-True (@(Get-ChildItem -LiteralPath $fixtureRoot -Directory -Force -Filter ($personalImportStagingPrefix + '*')).Count -eq 0) "Negative response '$($case.Name)' left import staging residue."
    }

    $staleCasState = Join-Path $fixtureRoot 'stale-cas-state'
    Copy-State -Source $preparedState -Destination $staleCasState
    $staleCasSnapshotBefore = Get-StateTreeSnapshot -Path $staleCasState
    [void](Invoke-Orchestrator -ScriptPath $orchestrator -RepoRoot $sourceRepo -Edition Personal -Phase ImportClientSignatures -PlanPath $personalPlanPath -StateRoot $staleCasState -ResponsePath $personalResponsePath -ExpectedHeadSha256 ('0' * 64) -ExpectFailure -ExpectedMessage 'stale production state head')
    Assert-True ((Get-StateTreeSnapshot -Path $staleCasState) -ceq $staleCasSnapshotBefore) 'Stale CAS changed state inventory or bytes.'

    $expectedManifestPreparationFailure = if ($useProductRoleFixture) {
        'requires -ExpectedHeadSha256'
    }
    else {
        'typed v2 client-signature import'
    }
    [void](Invoke-Orchestrator -ScriptPath $orchestrator -RepoRoot $sourceRepo -Edition Personal -Phase PrepareManifestSigning -PlanPath $personalPlanPath -StateRoot $personalState -ExpectFailure -ExpectedMessage $expectedManifestPreparationFailure)

    $wrongHeadPlanPath = Join-Path $evidenceRoot 'wrong-head-plan.json'
    $wrongHeadPlan = Read-Json -Path $personalPlanPath
    $wrongHeadPlan.sourceCommit = '0' * 40
    Write-Json -Path $wrongHeadPlanPath -Value $wrongHeadPlan
    [void](Invoke-Orchestrator -ScriptPath $orchestrator -RepoRoot $sourceRepo -Edition Personal -Phase Prepare -PlanPath $wrongHeadPlanPath -StateRoot (Join-Path $fixtureRoot 'wrong-head-state') -ExpectFailure -ExpectedMessage 'HEAD differs')

    $dirtyRepo = Join-Path $fixtureRoot 'dirty-repo'
    [void](Invoke-Git -Root $fixtureRoot -Arguments @('clone', '--quiet', $sourceRepo, $dirtyRepo))
    [void](Invoke-Git -Root $dirtyRepo -Arguments @(
        'config', '--local', 'core.autocrlf', 'false'))
    [IO.File]::WriteAllText((Join-Path $dirtyRepo 'untracked.txt'), 'dirty', $utf8)
    [void](Invoke-Orchestrator -ScriptPath (Join-Path $dirtyRepo 'release\scripts\Invoke-LauncherProductionRelease.ps1') -RepoRoot $dirtyRepo -Edition Personal -Phase Prepare -PlanPath $personalPlanPath -StateRoot (Join-Path $fixtureRoot 'dirty-state') -ExpectFailure -ExpectedMessage 'clean tracked and untracked')

    $modifiedRepo = Join-Path $fixtureRoot 'modified-module-repo'
    [void](Invoke-Git -Root $fixtureRoot -Arguments @('clone', '--quiet', $sourceRepo, $modifiedRepo))
    [void](Invoke-Git -Root $modifiedRepo -Arguments @(
        'config', '--local', 'core.autocrlf', 'false'))
    [IO.File]::AppendAllText(
        (Join-Path $modifiedRepo 'release\scripts\ProductionReleaseState.psm1'),
        [char]10 + '# modified module',
        $utf8)
    [void](Invoke-Orchestrator -ScriptPath (Join-Path $modifiedRepo 'release\scripts\Invoke-LauncherProductionRelease.ps1') -RepoRoot $modifiedRepo -Edition Personal -Phase Prepare -PlanPath $personalPlanPath -StateRoot (Join-Path $fixtureRoot 'modified-module-state') -ExpectFailure -ExpectedMessage 'clean tracked and untracked')

    $schemaRepo = Join-Path $fixtureRoot 'schema-swap-repo'
    [void](Invoke-Git -Root $fixtureRoot -Arguments @('clone', '--quiet', $sourceRepo, $schemaRepo))
    [void](Invoke-Git -Root $schemaRepo -Arguments @(
        'config', '--local', 'core.autocrlf', 'false'))
    [IO.File]::AppendAllText(
        (Join-Path $schemaRepo 'release\schemas\launcher-production-release-plan-v2.schema.json'),
        [char]10,
        $utf8)
    [void](Invoke-Orchestrator -ScriptPath (Join-Path $schemaRepo 'release\scripts\Invoke-LauncherProductionRelease.ps1') -RepoRoot $schemaRepo -Edition Personal -Phase Prepare -PlanPath $personalPlanPath -StateRoot (Join-Path $fixtureRoot 'schema-swap-state') -ExpectFailure -ExpectedMessage 'clean tracked and untracked')

    $externalScript = Join-Path $fixtureRoot 'external-orchestrator.ps1'
    [IO.File]::Copy($orchestrator, $externalScript, $false)
    [void](Invoke-Orchestrator -ScriptPath $externalScript -RepoRoot $sourceRepo -Edition Personal -Phase Prepare -PlanPath $personalPlanPath -StateRoot (Join-Path $fixtureRoot 'external-script-state') -ExpectFailure -ExpectedMessage 'canonical tracked repository path')

    $shadowWrapper = Join-Path $fixtureRoot 'shadow-wrapper.ps1'
    $wrapperText = @'
param($ScriptPath, $RepoRoot, $PlanPath, $StateRoot)
function Get-AuthenticodeSignature {
    [pscustomobject]@{
        Status = [Management.Automation.SignatureStatus]::Valid
        SignerCertificate = [pscustomobject]@{ RawData = [byte[]]::new(1) }
        TimeStamperCertificate = [pscustomobject]@{}
    }
}
& $ScriptPath -RepositoryRoot $RepoRoot -Edition Personal -Phase Prepare -PlanPath $PlanPath -StateRoot $StateRoot
'@
    [IO.File]::WriteAllText($shadowWrapper, $wrapperText, $utf8)
    $shadowOutput = @(& pwsh -NoLogo -NoProfile -NonInteractive -File $shadowWrapper $orchestrator $sourceRepo $personalPlanPath (Join-Path $fixtureRoot 'shadow-state') 2>&1 | ForEach-Object { [string]$_ })
    Assert-True ($LASTEXITCODE -ne 0) 'Caller Authenticode shadow unexpectedly succeeded.'
    Assert-True (($shadowOutput -join ' ').Contains('rejects a caller override', [StringComparison]::OrdinalIgnoreCase)) 'Caller Authenticode shadow failed for the wrong reason.'

    $pathShadowWrapper = Join-Path $fixtureRoot 'path-shadow-wrapper.ps1'
    $pathWrapperText = @'
param($ScriptPath, $RepoRoot, $PlanPath, $StateRoot)
function Test-Path { $true }
& $ScriptPath -RepositoryRoot $RepoRoot -Edition Personal -Phase Prepare -PlanPath $PlanPath -StateRoot $StateRoot
'@
    [IO.File]::WriteAllText($pathShadowWrapper, $pathWrapperText, $utf8)
    $pathShadowOutput = @(& pwsh -NoLogo -NoProfile -NonInteractive -File $pathShadowWrapper $orchestrator $sourceRepo $personalPlanPath (Join-Path $fixtureRoot 'path-shadow-state') 2>&1 | ForEach-Object { [string]$_ })
    Assert-True ($LASTEXITCODE -ne 0) 'Caller filesystem-cmdlet shadow unexpectedly succeeded.'
    Assert-True (($pathShadowOutput -join ' ').Contains('rejects a caller override of Test-Path', [StringComparison]::OrdinalIgnoreCase)) 'Caller filesystem-cmdlet shadow failed for the wrong reason.'

    $stateNegativeSource = $preparedState
    Assert-StateFailure -Label 'identity-extra' -SourceState $stateNegativeSource -ScriptPath $orchestrator -RepoRoot $sourceRepo -PlanPath $personalPlanPath -VariantRoot (Join-Path $fixtureRoot 'state-identity-extra') -Mutate {
        param($root)
        $path = Join-Path $root 'identity.json'
        $value = Read-Json -Path $path
        $value | Add-Member -NotePropertyName extra -NotePropertyValue $true
        Write-Json -Path $path -Value $value
    }
    Assert-StateFailure -Label 'receipt-extra' -SourceState $stateNegativeSource -ScriptPath $orchestrator -RepoRoot $sourceRepo -PlanPath $personalPlanPath -VariantRoot (Join-Path $fixtureRoot 'state-receipt-extra') -Mutate {
        param($root)
        $path = Join-Path $root 'receipts\0002-client-signing-requested.json'
        $value = Read-Json -Path $path
        $value | Add-Member -NotePropertyName extra -NotePropertyValue $true
        Write-Json -Path $path -Value $value
    }
    Assert-StateFailure -Label 'head-extra' -SourceState $stateNegativeSource -ScriptPath $orchestrator -RepoRoot $sourceRepo -PlanPath $personalPlanPath -VariantRoot (Join-Path $fixtureRoot 'state-head-extra') -Mutate {
        param($root)
        $path = Join-Path $root 'head.json'
        $value = Read-Json -Path $path
        $value | Add-Member -NotePropertyName extra -NotePropertyValue $true
        Write-Json -Path $path -Value $value
    }
    Assert-StateFailure -Label 'timestamp-tamper' -SourceState $stateNegativeSource -ScriptPath $orchestrator -RepoRoot $sourceRepo -PlanPath $personalPlanPath -VariantRoot (Join-Path $fixtureRoot 'state-time-tamper') -Mutate {
        param($root)
        $path = Join-Path $root 'head.json'
        $value = Read-Json -Path $path
        $value.updatedAtUtc = '2026-99-99T99:99:99Z'
        Write-Json -Path $path -Value $value
    }
    Assert-StateFailure -Label 'receipt-nested-directory' -SourceState $stateNegativeSource -ScriptPath $orchestrator -RepoRoot $sourceRepo -PlanPath $personalPlanPath -VariantRoot (Join-Path $fixtureRoot 'state-receipt-nested') -Mutate {
        param($root)
        [IO.Directory]::CreateDirectory((Join-Path $root 'receipts\0003-nested.json')) | Out-Null
    }
    Assert-StateFailure -Label 'request-extra-file' -SourceState $stateNegativeSource -ScriptPath $orchestrator -RepoRoot $sourceRepo -PlanPath $personalPlanPath -VariantRoot (Join-Path $fixtureRoot 'state-request-extra') -Mutate {
        param($root)
        [IO.File]::WriteAllText((Join-Path $root 'requests\client-signing.v1\unsigned\extra.exe'), 'extra')
    }
    Assert-StateFailure -Label 'import-nested-directory' -SourceState $stateNegativeSource -ScriptPath $orchestrator -RepoRoot $sourceRepo -PlanPath $personalPlanPath -VariantRoot (Join-Path $fixtureRoot 'state-import-nested') -Mutate {
        param($root)
        [IO.Directory]::CreateDirectory((Join-Path $root 'imports\nested')) | Out-Null
    }
    Assert-StateFailure -Label 'request-hardlink' -SourceState $stateNegativeSource -ScriptPath $orchestrator -RepoRoot $sourceRepo -PlanPath $personalPlanPath -VariantRoot (Join-Path $fixtureRoot 'state-request-hardlink') -Mutate {
        param($root)
        $path = Join-Path $root 'requests\client-signing.v1\unsigned\Ensou.Dsh.Launcher.exe'
        $target = $root + '-hardlink-target.exe'
        [IO.File]::Move($path, $target)
        New-Item -ItemType HardLink -Path $path -Target $target | Out-Null
    }
    Assert-StateFailure -Label 'request-content-tamper' -SourceState $stateNegativeSource -ScriptPath $orchestrator -RepoRoot $sourceRepo -PlanPath $personalPlanPath -VariantRoot (Join-Path $fixtureRoot 'state-request-content-tamper') -Mutate {
        param($root)
        $path = Join-Path $root 'requests\client-signing.v1\unsigned\Ensou.Dsh.Launcher.exe'
        $length = [int](Get-Item -LiteralPath $path -Force).Length
        [IO.File]::WriteAllBytes($path, [Text.Encoding]::ASCII.GetBytes('X' * $length))
    }
    Assert-StateFailure -Label 'verification-workspace-residue' -SourceState $stateNegativeSource -ScriptPath $orchestrator -RepoRoot $sourceRepo -PlanPath $personalPlanPath -VariantRoot (Join-Path $fixtureRoot 'state-verification-residue') -Mutate {
        param($root)
        $verification = Join-Path $root '.verification'
        [IO.Directory]::CreateDirectory($verification) | Out-Null
        [IO.File]::WriteAllText((Join-Path $verification 'swapped.exe'), 'namespace-swap')
    }

    }
    Write-Output "ORCHESTRATION-CONTRACT-ASSERTIONS=$script:AssertionCount EXPECTED-FAILURES=$script:ExpectedFailureCount SHARD=$Shard"
    if ($Shard -ceq 'FoundationR8') {
        Write-Output 'SIGNED-PRODUCT-IMPORT-ACCEPTANCE-NOT-EXECUTED: foundation-only CI shard; the import shard and required full signed-product suite are separate gates.'
    }
    elseif ($useProductRoleFixture) {
        Write-Output 'SIGNED-PRODUCT-IMPORT-ACCEPTANCE-PASS: both editions completed real product-role import; this is not feed publication or distribution approval.'
    }
    else {
        Write-Output 'SIGNED-PRODUCT-IMPORT-ACCEPTANCE-NOT-EXECUTED: contract-only run; release acceptance must use -RequireProductRoleFixture with actual signed DSH role inputs.'
    }
    if ($Shard -ceq 'All') {
        Write-Output 'LAUNCHER-PRODUCTION-RELEASE-ORCHESTRATION-CONTRACT-PASS'
    }
    else {
        Write-Output "LAUNCHER-PRODUCTION-RELEASE-ORCHESTRATION-SHARD-PASS $Shard"
    }
}
finally {
    if ($null -ne $codeSigningFixture) {
        $codeSigningFixture.Certificate.Dispose()
        $codeSigningFixture.Key.Dispose()
    }
    if ($null -ne $timestampSigningFixture) {
        $timestampSigningFixture.Certificate.Dispose()
        $timestampSigningFixture.Key.Dispose()
    }
    $responseSigner.Dispose()
    $manifestResponseSigner.Dispose()
    if ($null -ne $releaseManifestSigner) {
        $releaseManifestSigner.Dispose()
    }
    if (Test-Path -LiteralPath $fixtureRoot) {
        $resolved = [IO.Path]::GetFullPath($fixtureRoot)
        $prefix = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd(
            [IO.Path]::DirectorySeparatorChar) +
            [IO.Path]::DirectorySeparatorChar +
            'ensou-launcher-production-orchestration-'
        if (-not $resolved.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Refusing to remove an unexpected production orchestration fixture.'
        }
        foreach ($entry in Get-ChildItem -LiteralPath $resolved -Force -Recurse) {
            if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'Refusing to remove a linked production orchestration fixture.'
            }
            if (-not $entry.PSIsContainer) {
                [IO.File]::SetAttributes($entry.FullName, [IO.FileAttributes]::Normal)
            }
        }
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
