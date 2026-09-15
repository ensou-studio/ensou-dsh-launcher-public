#requires -Version 7.2
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$publisherPath = Join-Path $PSScriptRoot 'Publish-SourceRuntimeCandidate.ps1'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    $publisherPath, [ref]$tokens, [ref]$errors)
if ($errors.Count -ne 0) { throw 'Source publisher does not parse.' }

foreach ($name in @(
        'Assert-ExactLocalReviewedMembers',
        'ConvertFrom-LocalReviewedPublicationInput')) {
    $functions = @($ast.FindAll({ param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq $name
    }, $false))
    if ($functions.Count -ne 1) { throw "Missing local-reviewed validator $name." }
    . ([scriptblock]::Create($functions[0].Extent.Text))
}

$script:checks = 0
function Assert-LocalReviewed([bool]$Condition, [string]$Label) {
    if (-not $Condition) { throw $Label }
    $script:checks++
}
function Assert-LocalReviewedRejected([scriptblock]$Action, [string]$Label) {
    $rejected = $false
    try { [void](& $Action) } catch { $rejected = $true }
    Assert-LocalReviewed $rejected $Label
}
function Copy-LocalReviewed($Value) {
    $Value | ConvertTo-Json -Depth 20 | ConvertFrom-Json
}
function New-MockedPublisherClone([string]$CloneRoot, [bool]$CorruptReadback, [string]$TracePath) {
    $cloneScriptRoot = Join-Path $CloneRoot 'release\scripts'
    [void][IO.Directory]::CreateDirectory($cloneScriptRoot)
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'ProductionReleaseState.psm1') `
        -Destination (Join-Path $cloneScriptRoot 'ProductionReleaseState.psm1') -ErrorAction Stop
    [IO.File]::WriteAllText((Join-Path $cloneScriptRoot 'Test-SourceRuntimeMetadata.ps1'), @'
param([string]$MetadataPath, [string]$ArtifactPath, [string]$ExpectedReleaseId, [string]$ExpectedArtifactFileName, [string]$ExpectedArtifactSha256, [string]$ExpectedRuntimeProfile = 'enterprise-managed')
$artifact = Get-Item -LiteralPath $ArtifactPath -ErrorAction Stop
return [pscustomobject]@{
    promotionEligible = $true
    sourceTag = 'dsh-v0.1.2-rc.1'
    sourceCommit = ('b' * 40)
    sourceTree = ('c' * 40)
    runtimeWebAuthProtocol = 'browser-launch-cookie-v1'
    artifact = [pscustomobject]@{ fileName=$ExpectedArtifactFileName; sizeBytes=[int64]$artifact.Length; sha256=$ExpectedArtifactSha256 }
    managedPatch = [pscustomobject]@{}
    managedPolicy = [pscustomobject]@{}
}
'@, [Text.UTF8Encoding]::new($false))

    $source = Get-Content -LiteralPath $publisherPath -Raw
    $sendFunction = @($ast.FindAll({ param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Send-LockedReleaseAsset'
    }, $false))
    if ($sendFunction.Count -ne 1) { throw 'Could not isolate publisher upload boundary for fixture clone.' }
    $mockSend = @'
function Send-LockedReleaseAsset($HttpClient, [Uri]$Uri, [hashtable]$Headers, $Descriptor, [Collections.Generic.List[IDisposable]]$Leases) {
    $name = [Uri]::UnescapeDataString(($Uri.Query -replace '\A\?name=', ''))
    $id = 1000 + $script:MockUploads.Count
    $asset = [pscustomobject]@{ id=[int64]$id; name=$name; size=[int64]$Descriptor.Length; state='uploaded'; url=("https://fixture.invalid/assets/$id") }
    $script:MockUploads.Add($asset)
    $script:MockSources[$asset.url] = $Descriptor.FullName
    [IO.File]::AppendAllText($script:MockTracePath, "upload:$name`n", [Text.Encoding]::UTF8)
    return $asset
}
'@
    $source = $source.Substring(0, $sendFunction[0].Extent.StartOffset) + $mockSend +
        $source.Substring($sendFunction[0].Extent.EndOffset)
    $mainOffset = $source.IndexOf('$inputLeases = [Collections.Generic.List[IDisposable]]::new()', [StringComparison]::Ordinal)
    if ($mainOffset -lt 0) { throw 'Could not isolate publisher main flow for fixture clone.' }
    $preamble = @'
$script:MockUploads = [Collections.Generic.List[object]]::new()
$script:MockSources = @{}
$script:MockPublished = $false
$script:MockCorruptReadback = __CORRUPT__
$script:MockTracePath = '__TRACE__'
$script:MockResultPath = '__RESULT__'
function New-MockRelease([bool]$Draft, [bool]$Immutable) {
    return [pscustomobject]@{
        id = [int64]101; tag_name = $ReleaseId; target_commitish = $LauncherSourceCommit
        draft = $Draft; prerelease = $true; immutable = $Immutable
        upload_url = 'https://fixture.invalid/uploads/101{?name,label}'
        html_url = 'https://fixture.invalid/releases/101'; assets = @($script:MockUploads.ToArray())
    }
}
function Invoke-RestMethod {
    param([string]$Method, [string]$Uri, [hashtable]$Headers, [string]$ContentType, [string]$Body)
    if ($Method -ceq 'Get' -and $Uri -like '*/releases/tags/*') {
        if ($Uri -match 'source-candidate') {
            return [pscustomobject]@{ id=[int64]99; tag_name=("ensou-dsh-source-candidate/$ReleaseId"); target_commitish=$LauncherSourceCommit; draft=$false; immutable=$true; assets=@() }
        }
        if ($Uri -match [Text.RegularExpressions.Regex]::Escape($ReleaseId)) {
            if ($script:MockPublished) { return New-MockRelease $false $true }
            return $null
        }
        throw "Unexpected simulated GitHub release lookup: $Uri"
    }
    if ($Method -ceq 'Get' -and $Uri -like '*/git/ref/tags/*') {
        if ($Uri -match [Text.RegularExpressions.Regex]::Escape($ReleaseId) -and $Uri -notmatch 'source-candidate') {
            if (-not $script:MockPublished) { return $null }
        }
        return [pscustomobject]@{ object=[pscustomobject]@{ type='commit'; sha=$LauncherSourceCommit } }
    }
    if ($Method -ceq 'Get' -and $Uri -like '*/releases?per_page=100&page=*') { return @() }
    if ($Method -ceq 'Post' -and $Uri -like '*/releases') { return New-MockRelease $true $false }
    if ($Method -ceq 'Get' -and $Uri -like '*/releases/101') { return New-MockRelease $true $false }
    if ($Method -ceq 'Patch' -and $Uri -like '*/releases/101') { $script:MockPublished = $true; return New-MockRelease $false $true }
    throw "Unexpected simulated GitHub call: $Method $Uri"
}
function Invoke-WebRequest {
    param([string]$Method, [string]$Uri, [hashtable]$Headers, [string]$OutFile)
    if ($Method -cne 'Get' -or -not $script:MockSources.ContainsKey($Uri)) { throw "Unexpected simulated GitHub download: $Method $Uri" }
    $name = [IO.Path]::GetFileName($OutFile)
    [IO.File]::AppendAllText($script:MockTracePath, "download:$name`n", [Text.Encoding]::UTF8)
    if ($script:MockCorruptReadback -and $script:MockUploads.Count -eq 3 -and $name -ceq $script:MockUploads[0].name) {
        [IO.File]::WriteAllBytes($OutFile, [byte[]](255, 0, 255)); return [pscustomobject]@{}
    }
    [IO.File]::Copy($script:MockSources[$Uri], $OutFile, $false)
    return [pscustomobject]@{}
}
'@
    $preamble = $preamble.Replace('__CORRUPT__', ($(if ($CorruptReadback) { '$true' } else { '$false' }))).Replace('__TRACE__', $TracePath.Replace("'", "''")).Replace('__RESULT__', (Join-Path $CloneRoot 'result.json').Replace("'", "''"))
    $source = $source.Insert($mainOffset, $preamble)
    $localResultReturn = '    return [pscustomobject]$localResult'
    $localResultAdapter = @'
    $fixtureResult = [pscustomobject]$localResult
    [IO.File]::WriteAllText($script:MockResultPath, ($fixtureResult | ConvertTo-Json -Depth 32 -Compress), [Text.UTF8Encoding]::new($false))
    return $fixtureResult
'@
    if ($source.IndexOf($localResultReturn, [StringComparison]::Ordinal) -lt 0) {
        throw 'Could not isolate LocalReviewed result adapter for fixture clone.'
    }
    $source = $source.Replace($localResultReturn, $localResultAdapter)
    $fixtureCatch = $source.LastIndexOf("catch {", [StringComparison]::Ordinal)
    if ($fixtureCatch -lt 0) { throw 'Could not isolate publisher failure boundary for fixture clone.' }
    $fixtureCatchLineEnd = $source.IndexOf("`n", $fixtureCatch, [StringComparison]::Ordinal)
    $source = $source.Insert($fixtureCatchLineEnd + 1, '    Write-Output ("fixture-only stack: " + $_.ScriptStackTrace)' + "`n")
    $clonePath = Join-Path $cloneScriptRoot 'Publish-SourceRuntimeCandidate.ps1'
    [IO.File]::WriteAllText($clonePath, $source, [Text.UTF8Encoding]::new($false))
    return [pscustomobject]@{ PublisherPath=$clonePath; ResultPath=(Join-Path $CloneRoot 'result.json') }
}

$releaseId = 'managed-v2026.09.12.1'
$commit = 'a' * 40
$names = @(
    "EnsouDshRuntime-$releaseId-win-x64.zip",
    "EnsouDshRuntime-$releaseId-win-x64.metadata.json",
    "EnsouDshRuntime-$releaseId-win-x64.zip.sha256",
    'managed-candidate.json')
$roles = @('archive', 'metadata', 'hash-evidence', 'managed-candidate')
$sizes = @([long]100, [long]200, [long]64, [long]300)
$input = [pscustomobject][ordered]@{
    schemaVersion = 1
    authority = 'UNSIGNED_REVIEW_INPUT_ONLY'
    repository = 'ensou-studio/ensou-dsh-launcher'
    releaseId = $releaseId
    launcherSourceCommit = $commit
    immutableReservationTag = "ensou-dsh-source-candidate/$releaseId"
    inputs = @(for ($index = 0; $index -lt 4; $index++) {
        [pscustomobject][ordered]@{
            role = $roles[$index]
            fileName = $names[$index]
            path = "C:\controlled-source\$($names[$index])"
            sizeBytes = $sizes[$index]
            sha256 = ([string]($index + 1)) * 64
        }
    })
}

$normalized = ConvertFrom-LocalReviewedPublicationInput $input
Assert-LocalReviewed ($normalized.Repository -ceq $input.repository) 'Repository was not retained.'
Assert-LocalReviewed ($normalized.ReleaseId -ceq $releaseId) 'Release id was not retained.'
Assert-LocalReviewed ($normalized.LauncherSourceCommit -ceq $commit) 'Clean build source commit was not retained.'
Assert-LocalReviewed ($normalized.ImmutableReservationTag -ceq $input.immutableReservationTag) 'Immutable reservation requirement was not retained.'
Assert-LocalReviewed (@($normalized.Inputs).Count -eq 4) 'Exact four input descriptors were not retained.'
for ($index = 0; $index -lt 4; $index++) {
    Assert-LocalReviewed ($normalized.Inputs[$index].Role -ceq $roles[$index] -and
        $normalized.Inputs[$index].FileName -ceq $names[$index] -and
        $normalized.Inputs[$index].SizeBytes -eq $sizes[$index]) 'Descriptor order or binding changed.'
}

foreach ($mutation in @(
        { param($value) $value.authority = 'PRODUCTION_ADMISSION' },
        { param($value) $value.schemaVersion = $true },
        { param($value) $value.schemaVersion = '1' },
        { param($value) $value.schemaVersion = 1.0 },
        { param($value) $value.immutableReservationTag = 'other' },
        { param($value) $value.launcherSourceCommit = 'A' * 40 },
        { param($value) $value.repository = $true },
        { param($value) $value.inputs[0].path = 'relative.zip' },
        { param($value) $value.inputs[0].sha256 = 'A' * 64 },
        { param($value) $value.inputs[1].fileName = 'wrong.json' },
        { param($value) $value.inputs[2].role = 'metadata' },
        { param($value) $value.inputs = @($value.inputs[0..2]) },
        { param($value) $value | Add-Member -NotePropertyName unexpected -NotePropertyValue $true }
    )) {
    $changed = Copy-LocalReviewed $input
    & $mutation $changed
    Assert-LocalReviewedRejected {
        ConvertFrom-LocalReviewedPublicationInput $changed
    } 'Malformed LocalReviewed input was accepted.'
}

$parameterNames = @($ast.ParamBlock.Parameters | ForEach-Object {
    $_.Name.VariablePath.UserPath
})
Assert-LocalReviewed ($parameterNames -contains 'LocalReviewedPublicationInputPath' -and
    $parameterNames -contains 'ExpectedLocalReviewedPublicationInputSha256' -and
    $parameterNames -contains 'LocalVerificationWorkspace' -and
    $parameterNames -contains 'ActionsArtifactId' -and
    $parameterNames -contains 'RunAttempt') 'Publisher parameter routing lost one supported mode.'
$actionParameters = @(
    'Repository', 'ReleaseId', 'LauncherSourceCommit', 'ActionsArtifactId',
    'ArtifactPath', 'MetadataPath', 'HashEvidencePath', 'ManagedCandidatePath',
    'ExpectedArtifactFileName', 'ExpectedMetadataFileName', 'ExpectedHashFileName',
    'ExpectedArtifactSha256', 'ExpectedArtifactSizeBytes', 'RunAttempt')
foreach ($name in $actionParameters) {
    $parameter = @($ast.ParamBlock.Parameters | Where-Object {
        $_.Name.VariablePath.UserPath -ceq $name
    })
    $actionAttributeText = if ($parameter.Count -eq 1) {
        [string]::Join(' ', @($parameter[0].Attributes | ForEach-Object { $_.Extent.Text }))
    }
    else { '' }
    Assert-LocalReviewed ($parameter.Count -eq 1 -and
        $actionAttributeText -match "ParameterSetName\s*=\s*'Actions'") "Existing Actions parameter contract changed: $name"
}
$text = Get-Content -LiteralPath $publisherPath -Raw
Assert-LocalReviewed ($text -match "DefaultParameterSetName\s*=\s*'Actions'") 'Actions is no longer the default publisher parameter set.'
$localBranch = $text.IndexOf("ParameterSetName -ceq 'LocalReviewed'", [StringComparison]::Ordinal)
$networkBoundary = $text.IndexOf('$apiBase = "https://api.github.com/repos/$Repository"', [StringComparison]::Ordinal)
Assert-LocalReviewed ($localBranch -ge 0 -and $networkBoundary -gt $localBranch) 'LocalReviewed validation does not precede the network boundary.'
$readbackAllocation = $text.IndexOf('$readbackWorkspace = New-LocalReviewedVerificationWorkspace', [StringComparison]::Ordinal)
Assert-LocalReviewed ($readbackAllocation -ge 0 -and $readbackAllocation -lt $networkBoundary -and
    $text.IndexOf('LocalReviewedPublicationInputSha256', [StringComparison]::Ordinal) -ge 0) 'LocalReviewed readback allocation or reproducible record pin is missing.'

$missingInput = Join-Path ([IO.Path]::GetTempPath()) ('missing-local-reviewed-' + [Guid]::NewGuid().ToString('N') + '.json')
$missingWorkspace = Join-Path ([IO.Path]::GetTempPath()) ('missing-local-reviewed-work-' + [Guid]::NewGuid().ToString('N'))
$child = & pwsh -NoProfile -File $publisherPath `
    -LocalReviewedPublicationInputPath $missingInput `
    -ExpectedLocalReviewedPublicationInputSha256 ('0' * 64) `
    -LocalVerificationWorkspace $missingWorkspace 2>&1
Assert-LocalReviewed ($LASTEXITCODE -ne 0 -and
    (($child -join "`n") -match 'local-reviewed-source-runtime-publication\.v1\.json|Cannot find path') -and
    -not [IO.Directory]::Exists($missingWorkspace)) 'Invalid LocalReviewed input did not fail before the network and workspace-write boundaries.'

$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) ('local-reviewed-source-runtime-' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($fixtureRoot)
$ownedFullFlowWorkspaces = [Collections.Generic.List[string]]::new()
try {
    $artifactPath = Join-Path $fixtureRoot $names[0]
    $metadataPath = Join-Path $fixtureRoot $names[1]
    $hashPath = Join-Path $fixtureRoot $names[2]
    $managedPath = Join-Path $fixtureRoot $names[3]
    [IO.File]::WriteAllBytes($artifactPath, [byte[]](1..16))
    [IO.File]::WriteAllText($metadataPath, '{}', [Text.UTF8Encoding]::new($false))
    $artifactHash = (Get-FileHash -LiteralPath $artifactPath -Algorithm SHA256).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText($hashPath, "$artifactHash  $($names[0])`n", [Text.Encoding]::ASCII)
    [IO.File]::WriteAllText($managedPath, '{}', [Text.UTF8Encoding]::new($false))

    function New-DiskLocalReviewedInput([string]$RecordPath, [string]$ArchiveSha256) {
        $records = @(
            [pscustomobject][ordered]@{ role='archive'; fileName=$names[0]; path=$artifactPath; sizeBytes=[IO.FileInfo]::new($artifactPath).Length; sha256=$ArchiveSha256 },
            [pscustomobject][ordered]@{ role='metadata'; fileName=$names[1]; path=$metadataPath; sizeBytes=[IO.FileInfo]::new($metadataPath).Length; sha256=(Get-FileHash -LiteralPath $metadataPath -Algorithm SHA256).Hash.ToLowerInvariant() },
            [pscustomobject][ordered]@{ role='hash-evidence'; fileName=$names[2]; path=$hashPath; sizeBytes=[IO.FileInfo]::new($hashPath).Length; sha256=(Get-FileHash -LiteralPath $hashPath -Algorithm SHA256).Hash.ToLowerInvariant() },
            [pscustomobject][ordered]@{ role='managed-candidate'; fileName=$names[3]; path=$managedPath; sizeBytes=[IO.FileInfo]::new($managedPath).Length; sha256=(Get-FileHash -LiteralPath $managedPath -Algorithm SHA256).Hash.ToLowerInvariant() })
        [IO.File]::WriteAllText($RecordPath, (([ordered]@{
            schemaVersion=1; authority='UNSIGNED_REVIEW_INPUT_ONLY'; repository='ensou-studio/ensou-dsh-launcher'
            releaseId=$releaseId; launcherSourceCommit=$commit
            immutableReservationTag="ensou-dsh-source-candidate/$releaseId"; inputs=$records
        }) | ConvertTo-Json -Depth 8 -Compress), [Text.UTF8Encoding]::new($false))
    }
    function Invoke-DiskLocalReviewed([string]$RecordPath, [string]$ExpectedHash, [string]$Workspace) {
        $oldRunnerTemp = [Environment]::GetEnvironmentVariable('RUNNER_TEMP', 'Process')
        try {
            [Environment]::SetEnvironmentVariable('RUNNER_TEMP', $null, 'Process')
            $captured = @(& pwsh -NoProfile -File $publisherPath -LocalReviewedPublicationInputPath $RecordPath `
                -ExpectedLocalReviewedPublicationInputSha256 $ExpectedHash `
                -LocalVerificationWorkspace $Workspace 2>&1)
            return [pscustomobject]@{ Output=$captured; ExitCode=$LASTEXITCODE }
        }
        finally {
            [Environment]::SetEnvironmentVariable('RUNNER_TEMP', $oldRunnerTemp, 'Process')
        }
    }

    $recordPath = Join-Path $fixtureRoot 'local-reviewed-source-runtime-publication.v1.json'
    New-DiskLocalReviewedInput $recordPath $artifactHash
    $recordHash = (Get-FileHash -LiteralPath $recordPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $tamperWorkspace = Join-Path $fixtureRoot 'tampered-record-workspace'
    $tamper = Invoke-DiskLocalReviewed $recordPath ('0' * 64) $tamperWorkspace
    Assert-LocalReviewed ($tamper.ExitCode -ne 0 -and -not [IO.Directory]::Exists($tamperWorkspace) -and
        (($tamper.Output -join "`n") -match 'expected SHA-256')) 'Record SHA-256 tamper was not rejected before workspace creation.'

    New-DiskLocalReviewedInput $recordPath ('f' * 64)
    $badSourceRecordHash = (Get-FileHash -LiteralPath $recordPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $sourceWorkspace = Join-Path $fixtureRoot 'changed-source-workspace'
    $sourceChanged = Invoke-DiskLocalReviewed $recordPath $badSourceRecordHash $sourceWorkspace
    Assert-LocalReviewed ($sourceChanged.ExitCode -ne 0 -and -not [IO.Directory]::Exists($sourceWorkspace) -and
        (($sourceChanged.Output -join "`n") -match 'differs from its declared descriptor')) 'Changed source bytes were not rejected before workspace creation.'

    New-DiskLocalReviewedInput $recordPath $artifactHash
    $validRecordHash = (Get-FileHash -LiteralPath $recordPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $partialWorkspace = Join-Path $fixtureRoot 'partial-output-workspace'
    $partial = Invoke-DiskLocalReviewed $recordPath $validRecordHash $partialWorkspace
    [string[]]$partialNames = @(Get-ChildItem -LiteralPath (Join-Path $partialWorkspace 'inputs') -File -Force | ForEach-Object Name)
    [Array]::Sort($partialNames, [StringComparer]::Ordinal)
    [string[]]$expectedPartialNames = @($names); [Array]::Sort($expectedPartialNames, [StringComparer]::Ordinal)
    Assert-LocalReviewed ($partial.ExitCode -ne 0 -and [IO.Directory]::Exists($partialWorkspace) -and
        [IO.Directory]::Exists((Join-Path $partialWorkspace 'readback')) -and
        @(Get-ChildItem -LiteralPath (Join-Path $partialWorkspace 'readback') -Force).Count -eq 0 -and
        [string]::Join("`n", $partialNames) -ceq [string]::Join("`n", $expectedPartialNames) -and
        (($partial.Output -join "`n") -notmatch 'api\.github\.com')) 'Four-file disk verification or partial-output preservation failed before the network boundary.'

    # The publisher clone replaces only the external validator and GitHub
    # transport boundaries. It exercises the original LocalReviewed main flow
    # through draft upload, re-download, publication, and immutability checks.
    [IO.File]::WriteAllText($metadataPath, '{"promotionEligible":true}', [Text.UTF8Encoding]::new($false))
    $managedRecord = [ordered]@{
        artifact = [ordered]@{ fileName=$names[0]; sizeBytes=[IO.FileInfo]::new($artifactPath).Length; sha256=(Get-FileHash -LiteralPath $artifactPath -Algorithm SHA256).Hash.ToLowerInvariant() }
        launcherRepositoryCommit = $commit; launcherVersion = '1.2.3'; managedPatch = [ordered]@{}; managedPolicy = [ordered]@{}
        minimumBootstrapperVersion = '1.2.3'; promotionEligible = $true; releaseId = $releaseId
        remainingGates = @('Ensou application code signing', 'release manifest signing', 'Lab', 'Pilot', 'legal review')
        runtimeWebAuthProtocol = 'browser-launch-cookie-v1'; schemaVersion = 1; sourceBuilt = $true; stableEligible = $false
        upstreamCommit = ('b' * 40); upstreamTag = 'dsh-v0.1.2-rc.1'; upstreamTree = ('c' * 40)
    }
    [IO.File]::WriteAllText($managedPath, ($managedRecord | ConvertTo-Json -Depth 8 -Compress), [Text.UTF8Encoding]::new($false))
    $artifactHash = (Get-FileHash -LiteralPath $artifactPath -Algorithm SHA256).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText($hashPath, "$artifactHash  $($names[0])`n", [Text.Encoding]::ASCII)
    New-DiskLocalReviewedInput $recordPath $artifactHash
    $fullRecordHash = (Get-FileHash -LiteralPath $recordPath -Algorithm SHA256).Hash.ToLowerInvariant()

    function Invoke-MockedFullLocalReviewed([bool]$CorruptReadback, [string]$Workspace) {
        $mockRoot = Join-Path $fixtureRoot ('mocked-publisher-' + [Guid]::NewGuid().ToString('N'))
        $trace = Join-Path $mockRoot 'transport.trace'
        $clone = New-MockedPublisherClone $mockRoot $CorruptReadback $trace
        $oldRunnerTemp = [Environment]::GetEnvironmentVariable('RUNNER_TEMP', 'Process')
        $oldToken = [Environment]::GetEnvironmentVariable('GH_TOKEN', 'Process')
        try {
            [Environment]::SetEnvironmentVariable('RUNNER_TEMP', $null, 'Process')
            [Environment]::SetEnvironmentVariable('GH_TOKEN', 'fixture-only-no-network-token', 'Process')
            $output = @(& pwsh -NoProfile -File $clone.PublisherPath -LocalReviewedPublicationInputPath $recordPath `
                -ExpectedLocalReviewedPublicationInputSha256 $fullRecordHash `
                -LocalVerificationWorkspace $Workspace 2>&1)
            return [pscustomobject]@{ Output=$output; ExitCode=$LASTEXITCODE; Trace=$trace; ResultPath=$clone.ResultPath }
        }
        finally {
            [Environment]::SetEnvironmentVariable('RUNNER_TEMP', $oldRunnerTemp, 'Process')
            [Environment]::SetEnvironmentVariable('GH_TOKEN', $oldToken, 'Process')
        }
    }

    $fullWorkspace = Join-Path ([IO.Path]::GetTempPath()) ('local-reviewed-shared-flow-' + [Guid]::NewGuid().ToString('N'))
    $ownedFullFlowWorkspaces.Add($fullWorkspace)
    $full = Invoke-MockedFullLocalReviewed $false $fullWorkspace
    Assert-LocalReviewed ([IO.File]::Exists($full.Trace)) "Simulated publisher clone did not reach its transport boundary: $($full.Output -join "`n")"
    Assert-LocalReviewed ([IO.File]::Exists($full.ResultPath)) 'Simulated publisher clone did not emit its fixture-only LocalReviewed result.'
    $fullResult = Get-Content -LiteralPath $full.ResultPath -Raw | ConvertFrom-Json -Depth 64
    [string[]]$transportTrace = @([IO.File]::ReadAllLines($full.Trace, [Text.Encoding]::UTF8))
    [string[]]$expectedTransportTrace = @(
        "upload:$($names[0])", "upload:$($names[1])", "upload:$($names[2])",
        "download:$($names[0])", "download:$($names[1])", "download:$($names[2])")
    Assert-LocalReviewed ($full.ExitCode -eq 0 -and $null -ne $fullResult -and
        [string]$fullResult.InputMode -ceq 'LocalReviewed' -and
        -not ($fullResult.PSObject.Properties.Name -contains 'ActionsArtifactId') -and
        [string]$fullResult.LocalReviewedPublicationInputSha256 -ceq $fullRecordHash -and
        [string]::Join("`n", $transportTrace) -ceq [string]::Join("`n", $expectedTransportTrace)) 'Simulated LocalReviewed shared publication flow did not complete exact upload/readback/finalization with RUNNER_TEMP absent.'

    $corruptWorkspace = Join-Path ([IO.Path]::GetTempPath()) ('local-reviewed-corrupt-readback-' + [Guid]::NewGuid().ToString('N'))
    $ownedFullFlowWorkspaces.Add($corruptWorkspace)
    $corrupt = Invoke-MockedFullLocalReviewed $true $corruptWorkspace
    Assert-LocalReviewed ($corrupt.ExitCode -ne 0 -and
        (($corrupt.Output -join "`n") -match 'Re-downloaded draft assets') -and
        @(Get-ChildItem -LiteralPath (Join-Path $corruptWorkspace 'readback') -File -Force).Count -eq 3) 'Changed simulated re-download was not rejected in the shared LocalReviewed flow.'
}
finally {
    foreach ($workspace in @($ownedFullFlowWorkspaces)) {
        $fullWorkspacePath = [IO.Path]::GetFullPath($workspace)
        $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
        if ($fullWorkspacePath.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -and
            [IO.Directory]::Exists($fullWorkspacePath)) {
            $workspaceInfo = [IO.DirectoryInfo]::new($fullWorkspacePath)
            if (($workspaceInfo.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'Fixture cleanup refuses a reparse-point workspace.'
            }
            Remove-Item -LiteralPath $fullWorkspacePath -Recurse -Force
        }
    }
    if ([IO.Directory]::Exists($fixtureRoot)) { Remove-Item -LiteralPath $fixtureRoot -Recurse -Force }
}

Write-Output "PASS LocalReviewed source-runtime publication: $script:checks checks; no publication or network mutation performed."
