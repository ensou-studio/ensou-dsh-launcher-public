[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function ConvertFrom-WorkflowPwshLiteralBlock {
    param(
        [Parameter(Mandatory)]
        [string]$IndentedBody,

        [int]$Indent = 10
    )

    $prefix = ' ' * $Indent
    $lines = [regex]::Split($IndentedBody, '\r?\n')
    $result = [System.Collections.Generic.List[string]]::new()
    foreach ($line in $lines) {
        if ($line.Length -eq 0) {
            $result.Add('')
            continue
        }
        if (-not $line.StartsWith($prefix, [StringComparison]::Ordinal)) {
            return $null
        }
        $result.Add($line.Substring($Indent))
    }
    return [string]::Join([Environment]::NewLine, $result)
}

function Test-ExactWorkflowOrchestrationScript {
    param(
        [AllowNull()]
        [string]$ScriptText,

        [Parameter(Mandatory)]
        [string]$ExpectedCommand
    )

    if ([string]::IsNullOrWhiteSpace($ScriptText)) {
        return $false
    }
    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput(
        $ScriptText,
        [ref]$tokens,
        [ref]$parseErrors)
    if ($parseErrors.Count -ne 0 -or
        $null -eq $ast.EndBlock -or
        $ast.EndBlock.Statements.Count -ne 2) {
        return $false
    }
    $preference = $ast.EndBlock.Statements[0]
    if ($preference -isnot
            [System.Management.Automation.Language.AssignmentStatementAst] -or
        $preference.Left.Extent.Text -cne '$ErrorActionPreference' -or
        $preference.Right.Extent.Text -cne "'Stop'") {
        return $false
    }
    if ($ast.EndBlock.Statements[1] -isnot
        [System.Management.Automation.Language.PipelineAst]) {
        return $false
    }
    $commands = @($ast.FindAll(
        {
            param($node)
            $node -is [System.Management.Automation.Language.CommandAst]
        },
        $true))
    return $commands.Count -eq 1 -and
        $commands[0].CommandElements.Count -eq 1 -and
        $commands[0].GetCommandName() -ceq $ExpectedCommand
}

function Test-WorkflowParseInventoryBinding {
    param(
        [AllowNull()]
        [string]$ScriptText,

        [Parameter(Mandatory)]
        [string]$ExpectedPath
    )

    if ([string]::IsNullOrWhiteSpace($ScriptText)) {
        return $false
    }
    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput(
        $ScriptText,
        [ref]$tokens,
        [ref]$parseErrors)
    if ($parseErrors.Count -ne 0 -or $null -eq $ast.EndBlock) {
        return $false
    }
    $assignments = @($ast.FindAll(
        {
            param($node)
            $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                $node.Left.Extent.Text -ceq '$files'
        },
        $true))
    if ($assignments.Count -ne 1 -or
        @($ast.EndBlock.Statements | Where-Object {
                [object]::ReferenceEquals($_, $assignments[0])
            }).Count -ne 1) {
        return $false
    }
    $entries = @($assignments[0].Right.FindAll(
        {
            param($node)
            $node -is [System.Management.Automation.Language.StringConstantExpressionAst]
        },
        $true) | ForEach-Object Value)
    return @($entries | Where-Object { $_ -ceq $ExpectedPath }).Count -eq 1
}

$workflowRoot = Join-Path $RepositoryRoot '.github\workflows'
$workflowFiles = @(Get-ChildItem -LiteralPath $workflowRoot -File | Where-Object { $_.Extension -in @('.yml', '.yaml') })
if ($workflowFiles.Count -eq 0) {
    throw "No workflow files were found in $workflowRoot"
}

$violations = [System.Collections.Generic.List[string]]::new()
foreach ($file in $workflowFiles) {
    $text = Get-Content -Raw -LiteralPath $file.FullName
    if ($text -match '(?m)^\s*pull_request_target\s*:') {
        $violations.Add("$($file.Name): pull_request_target is forbidden.")
    }
    if ($text -match '(?m)^\s*permissions\s*:\s*write-all\s*$') {
        $violations.Add("$($file.Name): write-all permissions are forbidden.")
    }
    if ($text -notmatch '(?m)^permissions\s*:') {
        $violations.Add("$($file.Name): an explicit top-level permissions block is required.")
    }

    foreach ($line in (Get-Content -LiteralPath $file.FullName)) {
        if ($line -match '^\s*-?\s*uses:\s*([^\s#]+)') {
            $reference = $Matches[1]
            if ($reference.StartsWith('./')) {
                continue
            }
            if ($reference -notmatch '@[0-9a-f]{40}$') {
                $violations.Add("$($file.Name): action is not pinned to a lowercase 40-character commit SHA: $reference")
            }
        }
    }
}

$buildCandidatePath = Join-Path $workflowRoot 'build-candidate.yml'
$buildCandidate = Get-Content -Raw -LiteralPath $buildCandidatePath
foreach ($required in @(
    'branch-gate:',
    'name: Reject non-main candidate dispatch',
    "if (`$env:DISPATCH_REF -cne 'refs/heads/main')",
    'reserve:',
    'contents: write',
    'group: build-source-candidate-${{ inputs.release_id }}',
    "if: github.ref == 'refs/heads/main'",
    'name: Publish immutable source candidate reservation',
    'needs: reserve',
    'name: Reject workflow reruns',
    'RUN_ATTEMPT: ${{ github.run_attempt }}',
    "if (`$env:RUN_ATTEMPT -cne '1')",
    'ensou-dsh-source-candidate/$env:RELEASE_ID',
    'https://api.github.com/repos/$env:REPOSITORY/releases',
    "'X-GitHub-Api-Version' = '2026-03-10'",
    'prerelease = $true',
    'foreach ($attempt in 1..30)',
    'Start-Sleep -Seconds 2',
    '[int64]$confirmedReservation.id -ne $reservationId',
    '@($confirmedReservation.assets).Count -ne 0',
    '-not [bool]$confirmedReservation.immutable',
    '$encodedTagName = [Uri]::EscapeDataString($tagName)',
    '-Uri "$uri/tags/$encodedTagName"',
    '[int64]$byTag.id -ne $reservationId',
    '@($byTag.assets).Count -ne 0',
    '-not [bool]$byTag.immutable',
    'git/ref/tags/$encodedTagName',
    "[string]`$tagRef.object.type -cne 'commit'",
    '[string]$tagRef.object.sha -cne $env:SOURCE_COMMIT',
    'This release_id is burned; use a new id after repairing the conflicting tag.',
    'Candidate ids are create-once and must never be reused.',
    'A later failure burns this release id; retry with a new id.',
    '$sourceMetadata.promotionEligible -ne $true',
    'promotionEligible = [bool]$sourceMetadata.promotionEligible',
    'id: candidate-upload',
    'actions_artifact_id: ${{ steps.candidate-upload.outputs.artifact-id }}',
    'publish:',
    'name: Publish exact immutable artifact-bearing Release',
    'actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.0',
    'artifact-ids: ${{ needs.build.outputs.actions_artifact_id }}',
    '.\release\scripts\Publish-SourceRuntimeCandidate.ps1',
    '-RunAttempt $env:RUN_ATTEMPT'
)) {
    if (-not $buildCandidate.Contains($required, [StringComparison]::Ordinal)) {
        $violations.Add("build-candidate.yml: immutable release-id reservation is missing: $required")
    }
}

$buildJob = [Text.RegularExpressions.Regex]::Match(
    $buildCandidate,
    '(?ms)^  build:\r?\n(?<body>.*?)(?=^  publish:\r?$)')
$publishJob = [Text.RegularExpressions.Regex]::Match(
    $buildCandidate,
    '(?ms)^  publish:\r?\n(?<body>.*)\z')
if (-not $buildJob.Success -or
    $buildJob.Groups['body'].Value -notmatch
        '(?m)^    permissions:\r?$\n^      contents: read\r?$' -or
    $buildJob.Groups['body'].Value -match
        '(?m)^      contents: write\r?$|GH_TOKEN:|GITHUB_TOKEN:' -or
    -not $publishJob.Success -or
    $publishJob.Groups['body'].Value -notmatch
        '(?m)^    permissions:\r?$\n^      contents: write\r?$') {
    $violations.Add(
        'build-candidate.yml: source build must remain contents:read/token-free and publication must be an isolated contents:write job.')
}
if ($buildCandidate.Contains('-LocalLab', [StringComparison]::Ordinal)) {
    $violations.Add('build-candidate.yml: production candidate workflow must never enable LocalLab mode.')
}

$publisherPath = Join-Path $RepositoryRoot `
    'release\scripts\Publish-SourceRuntimeCandidate.ps1'
if (-not (Test-Path -LiteralPath $publisherPath -PathType Leaf)) {
    $violations.Add('Immutable source-runtime candidate publisher is missing.')
}
else {
    $publisher = Get-Content -Raw -LiteralPath $publisherPath
    foreach ($required in @(
        'promotionEligible -ne $true',
        'ensou-dsh-source-candidate/$ReleaseId',
        'target_commitish = $LauncherSourceCommit',
        'draft = $true',
        'Assert-ExactReleaseAssets',
        'application/octet-stream',
        'Test-SourceRuntimeMetadata.ps1',
        'draft = $false',
        '-not [bool]$immutableRelease.immutable',
        'Final artifact-bearing Release tag',
        'this workflow must not be rerun')) {
        if (-not $publisher.Contains($required, [StringComparison]::Ordinal)) {
            $violations.Add("Immutable source-runtime publisher is missing: $required")
        }
    }
    if ($publisher -match 'Expand-Archive|ZipArchive|node\.exe|Start-Process') {
        $violations.Add(
            'Immutable source-runtime publisher must validate opaque bytes and metadata without extracting or executing the runtime.')
    }
}

$promotionPath = Join-Path $workflowRoot 'promote.yml'
$promotion = Get-Content -Raw -LiteralPath $promotionPath
foreach ($required in @(
    '$metadata.promotionEligible -ne $true',
    '@($release.assets).Count -ne 3',
    'ensou-dsh-source-candidate/$env:RELEASE_ID',
    'releases/tags/$reservationTag',
    '@($reservationRelease.assets).Count -ne 0',
    '-not [bool]$reservationRelease.immutable',
    '[string]$reservationRelease.target_commitish -cne',
    '[string]$reservationRef.object.sha -or',
    '[string]$release.target_commitish -cne [string]$finalRef.object.sha')) {
    if (-not $promotion.Contains($required, [StringComparison]::Ordinal)) {
        $violations.Add("promote.yml: production admission is missing: $required")
    }
}

$enterpriseWorkflowPath = Join-Path $workflowRoot 'enterprise-managed-release-v2.yml'
$enterpriseWorkflow = Get-Content -Raw -LiteralPath $enterpriseWorkflowPath
foreach ($required in @(
    'publish_feed_promoter_production_bundle:',
    'expected_production_trust_sha256:',
    'feed-promoter-production-contract:',
    'feed-promoter-production-bundle:',
    "github.event_name == 'workflow_dispatch'",
    "github.ref == 'refs/heads/main'",
    'environment: enterprise-feed-production-release',
    'ENSOU_ENTERPRISE_FEED_PRODUCTION_TRUST_BASE64',
    'EXPECTED_PRODUCTION_TRUST_SHA256: ${{ inputs.expected_production_trust_sha256 }}',
    '-ExpectedProductionTrustSha256 $env:EXPECTED_PRODUCTION_TRUST_SHA256',
    'Validate Enterprise Installer remains Pilot-only NO-GO',
    '.\release\scripts\Test-PortableDotNetSdkClosure.ps1',
    'ProductionAdmissionClaimed',
    '.\release\scripts\Test-NewPortableDotNetSdkLock.ps1',
    'sdkLockGeneratorResults',
    '[int]$sdkLockGeneratorResults[0].TestCount -lt 15',
    '[int]$sdkLockGeneratorResults[0].AssertionCount -lt 43',
    '.\release\scripts\Test-InstallerSigningContracts.ps1',
    '.\release\scripts\Test-EnterpriseInstallerTrustedBuild.ps1',
    '-DotNetSdkArchivePath $sdkArchive',
    'https://builds.dotnet.microsoft.com/dotnet/Sdk/10.0.302/dotnet-sdk-10.0.302-win-x64.zip',
    '7d170ed75fa9af34c00646621d92011dbd71943952e2787cd15df9be78e6452b55dadef34d7eff77b802e6af4959e071a55855ac649afeac70901c3a2a258716',
    'INSTALLER_SIGNING_RESPONSE_REQUIRED',
    'SdkFileClosureStatus',
    'SdkTrackedLockSha256',
    'cd49ac2a5c73e227f20e266372d2514d9400df1bf17dbbf942218862d5bc92ad',
    'SdkInventorySha256',
    'actions/upload-artifact@b7c566a772e6b6bfb58ed0dc250532a479d7789f # v6.0.0',
    'if-no-files-found: error',
    'compression-level: 0'
)) {
    if (-not $enterpriseWorkflow.Contains($required, [StringComparison]::Ordinal)) {
        $violations.Add("enterprise-managed-release-v2.yml: protected FeedPromoter bundle publication is missing: $required")
    }
}
$feedPromoterContractJob = [Text.RegularExpressions.Regex]::Match(
    $enterpriseWorkflow,
    '(?ms)^  feed-promoter-production-contract:\r?\n(?<body>.*?)(?=^  feed-promoter-production-bundle:\r?$)')
$feedPromoterProductionJob = [Text.RegularExpressions.Regex]::Match(
    $enterpriseWorkflow,
    '(?ms)^  feed-promoter-production-bundle:\r?\n(?<body>.*)\z')
if (-not $feedPromoterContractJob.Success -or
    -not $feedPromoterProductionJob.Success -or
    $feedPromoterContractJob.Groups['body'].Value -match
        'actions/upload-artifact|ENSOU_ENTERPRISE_FEED_PRODUCTION_TRUST_BASE64' -or
    [regex]::Matches(
        $feedPromoterProductionJob.Groups['body'].Value,
        [regex]::Escape('actions/upload-artifact@')).Count -ne 1 -or
    $feedPromoterProductionJob.Groups['body'].Value -notmatch
        '(?m)^    permissions:\r?$\n^      contents: read\r?$') {
    $violations.Add(
        'enterprise-managed-release-v2.yml: disposable trust fixtures must be token-free and isolated from the one protected upload job.')
}

$personalFreezePath = Join-Path $workflowRoot 'personal-release-freeze.yml'
$personalFreeze = Get-Content -Raw -LiteralPath $personalFreezePath
$personalOrchestrationTest =
    '.\release\scripts\Test-LauncherProductionReleaseOrchestration.ps1'
$personalContractsJob = [Text.RegularExpressions.Regex]::Match(
    $personalFreeze,
    '(?ms)^  contracts:\r?\n(?<header>.*?)(?=^    steps:\r?$)')
$workflowRunBlockPattern =
    '(?m)^        run: \|\r?\n(?<body>(?:(?:^[ \t]{10,}.*|^[ \t]*)(?:\r?\n|\z))*)'
$personalParseStep = [Text.RegularExpressions.Regex]::Match(
    $personalFreeze,
    '(?ms)^      - name: Parse Personal release freeze scripts\r?\n(?<body>.*?)(?=^      - name:|\z)')
$personalParseRunBlock = [Text.RegularExpressions.Regex]::Match(
    $personalParseStep.Groups['body'].Value,
    $workflowRunBlockPattern)
$personalParseScript = ConvertFrom-WorkflowPwshLiteralBlock `
    -IndentedBody $personalParseRunBlock.Groups['body'].Value
if (-not $personalParseStep.Success -or
    -not $personalParseRunBlock.Success -or
    -not (Test-WorkflowParseInventoryBinding `
        -ScriptText $personalParseScript `
        -ExpectedPath $personalOrchestrationTest)) {
    $violations.Add(
        'personal-release-freeze.yml: the main-CI-owned production orchestration script must remain in the parse inventory.')
}
if (-not $personalContractsJob.Success -or
    $personalContractsJob.Groups['header'].Value -notmatch
        '(?m)^    timeout-minutes: 75\r?$' -or
    $personalFreeze -match ('(?m)^\s*' +
        [regex]::Escape($personalOrchestrationTest) + '\s*(?:$|#)')) {
    $violations.Add(
        'personal-release-freeze.yml: Personal gates must retain their reviewed budget without duplicating main CI orchestration shards.')
}

$ciPath = Join-Path $workflowRoot 'ci.yml'
$ci = Get-Content -Raw -LiteralPath $ciPath
$ciCoreContractsJob = [Text.RegularExpressions.Regex]::Match(
    $ci,
    '(?ms)^  core-contracts:\r?\n(?<header>.*?)(?=^    steps:\r?$)')
$ciOrchestrationJob = [Text.RegularExpressions.Regex]::Match(
    $ci,
    '(?ms)^  orchestration:\r?\n(?<body>.*?)(?=^  [A-Za-z0-9_-]+:\r?$|\z)')
$ciAggregateJob = [Text.RegularExpressions.Regex]::Match(
    $ci,
    '(?ms)^  contracts:\r?\n(?<body>.*?)(?=^  [A-Za-z0-9_-]+:\r?$|\z)')
$ciOrchestrationBody = $ciOrchestrationJob.Groups['body'].Value
$ciAggregateBody = $ciAggregateJob.Groups['body'].Value
$ciAggregateStep = [Text.RegularExpressions.Regex]::Match(
    $ciAggregateBody,
    '(?ms)^      - name: Require all release and workflow contract jobs\r?\n(?<body>.*?)(?=^      - name:|\z)')
$expectedCiAggregateStepBody = [string]::Join(
    "`n",
    @(
        '        shell: bash',
        '        run: |',
        '          if [[ "${{ needs.core-contracts.result }}" != "success" || "${{ needs.orchestration.result }}" != "success" ]]; then',
        '            echo "core-contracts=${{ needs.core-contracts.result }} orchestration=${{ needs.orchestration.result }}"',
        '            exit 1',
        '          fi',
        ''))
$ciMatrixInvocationPattern = '(?m)^        run: ' +
    [regex]::Escape($personalOrchestrationTest + ' -Shard ${{ matrix.shard }}') + '[ \t]*\r?$'
if (-not $ciCoreContractsJob.Success -or
    $ciCoreContractsJob.Groups['header'].Value -notmatch
        '(?m)^    timeout-minutes: 75\r?$' -or
    -not $ciOrchestrationJob.Success -or
    $ciOrchestrationBody -notmatch '(?m)^    timeout-minutes: 75\r?$' -or
    $ciOrchestrationBody -notmatch '(?m)^      fail-fast: false\r?$' -or
    $ciOrchestrationBody -notmatch '(?m)^        shard: \[FoundationR8, ImportAndPersonal\]\r?$' -or
    [regex]::Matches(
        $ciOrchestrationBody,
        $ciMatrixInvocationPattern).Count -ne 1 -or
    $ciOrchestrationBody.Contains(
        'continue-on-error:',
        [StringComparison]::OrdinalIgnoreCase) -or
    -not $ciAggregateJob.Success -or
    $ciAggregateBody -notmatch
        '(?m)^    name: Release and workflow contracts\r?$' -or
    $ciAggregateBody -notmatch
        '(?m)^    if: \$\{\{ always\(\) \}\}\r?$' -or
    $ciAggregateBody -notmatch
        '(?m)^    needs: \[core-contracts, orchestration\]\r?$' -or
    $ciAggregateBody.Contains(
        'continue-on-error:',
        [StringComparison]::OrdinalIgnoreCase) -or
    -not $ciAggregateStep.Success -or
    $ciAggregateStep.Groups['body'].Value.Replace("`r`n", "`n") -cne
        $expectedCiAggregateStepBody) {
    $violations.Add(
        'ci.yml: both fail-closed orchestration matrix shards and the Release and workflow contracts aggregate must remain enabled.')
}

if ($violations.Count -gt 0) {
    throw ($violations -join [Environment]::NewLine)
}

Write-Host 'Workflow action pin validation passed.'
