#requires -Version 7.2

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# This is deliberately source/parameter-set plumbing coverage.  It does not
# claim a genuine signed-Installer or real-device acceptance replay; those
# require the controlled Windows evidence inputs and are exercised separately.
$adapterPath = Join-Path $PSScriptRoot 'New-EnterpriseProductionPilotEvidenceInput.ps1'

function Assert-R8RevalidationTest {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )

    if (-not $Condition) {
        throw $Message
    }
}

$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    $adapterPath,
    [ref]$tokens,
    [ref]$parseErrors)
Assert-R8RevalidationTest `
    (@($parseErrors).Count -eq 0) `
    ('r8 revalidation adapter has PowerShell parse errors: ' +
     (@($parseErrors | ForEach-Object Message) -join '; '))

# Load exact production temporal functions from their AST, without executing
# the adapter's file, signing or device workflow. Deterministic time arguments
# exercise boundaries without changing the system clock or environment.
foreach ($functionName in @('Get-R8EvidencePolicyValidUntilUtc', 'Assert-R8FinalEvidenceLifetime')) {
    $functionAst = @($ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq $functionName
    }, $true))
    Assert-R8RevalidationTest ($functionAst.Count -eq 1) "Missing exact temporal function '$functionName'."
    . ([ScriptBlock]::Create($functionAst[0].Extent.Text))
}

$parameterNames = @($ast.ParamBlock.Parameters | ForEach-Object {
    $_.Name.VariablePath.UserPath
})
foreach ($name in @(
        'ExpectedR7HeadSha256',
        'RevalidateOnly',
        'ExpectedHeadSha256',
        'WindowsPilotEvidenceEnvelopePath',
        'WindowsPilotEvidenceBodyPath',
        'WindowsPilotVerificationReportPath',
        'WindowsPilotReadinessConfigPath',
        'WindowsPilotStoredReadinessReportPath',
        'WindowsPilotReplayedReadinessReportPath',
        'WindowsPilotReadinessSchemaVersion',
        'LocalDataCertificationReceiptPath',
        'StablePrivatePilotObservationPath',
        'PilotTrustPolicyPath')) {
    Assert-R8RevalidationTest `
        ($parameterNames -ccontains $name) `
        "r8 revalidation is missing '$name'."
}

$text = [IO.File]::ReadAllText($adapterPath)
foreach ($required in @(
        "DefaultParameterSetName = 'Create'",
        "ParameterSetName = 'Revalidate'",
        'R8_REVALIDATION_STATE_REJECTED',
        "8 = 'PILOT_EVIDENCE_BOUND'",
        "9 = 'STABLE_PROMOTION_REQUESTED'",
        "10 = 'STABLE_FEED_PROMOTED'",
        '[string]$state.Identity.edition -cne ''Enterprise''',
        '[string]$state.TargetChannel -cne ''stable''',
        '$null -ne $state.OrphanReceipt',
        "'current head orchestration ID'",
        'Get-R8HistoricalHeadSha256',
        'committed r8 Pilot evidence input',
        'Assert-EnterpriseProductionPilotEvidence',
        '-WindowsPilotReadinessSchemaVersion',
        'Assert-EnterpriseProductionPilotEvidenceInputBinding',
        'R8_REVALIDATION_SUMMARY_MISMATCH',
        'SequenceEqual',
        'R8_EVIDENCE_REVALIDATED_NO_GO',
        'CurrentHeadSha256',
        'R7HeadSha256',
        'PilotEvidenceInputSha256',
        'PolicyValidUntilUtc',
        'ValidatedAtUtc')) {
    Assert-R8RevalidationTest `
        $text.Contains($required, [StringComparison]::Ordinal) `
        "r8 revalidation source is missing '$required'."
}

# These are the three accepted Enterprise Stable lifecycle positions.  A
# Personal r9 name is intentionally absent: it must not become an alias for
# the Enterprise stable promotion request phase.
foreach ($phase in @(
        'PILOT_EVIDENCE_BOUND',
        'STABLE_PROMOTION_REQUESTED',
        'STABLE_FEED_PROMOTED')) {
    Assert-R8RevalidationTest `
        ($text.Contains($phase, [StringComparison]::Ordinal)) `
        "r8 revalidation does not admit the required Enterprise phase '$phase'."
}
Assert-R8RevalidationTest `
    (-not $text.Contains('PILOT_FEED_PROMOTED', [StringComparison]::Ordinal)) `
    'r8 revalidation accepted the Personal r9 phase as an Enterprise Stable phase.'

# Execute the actual admission block extracted from the adapter source.  This
# isolates only lifecycle/parameter gating; it deliberately does not mock the
# subsequent cryptographic or Installer validation.
$admissionStart = $text.IndexOf(
    '    $baseStateRejected =',
    [StringComparison]::Ordinal)
$admissionEnd = $text.IndexOf(
    '    $stateRootFull =',
    $admissionStart,
    [StringComparison]::Ordinal)
Assert-R8RevalidationTest `
    ($admissionStart -ge 0 -and $admissionEnd -gt $admissionStart) `
    'Could not locate the adapter actual r8 revalidation admission block.'
$actualAdmissionBlock = [ScriptBlock]::Create(
    $text.Substring($admissionStart, $admissionEnd - $admissionStart))

function New-R8AdmissionStateFixture {
    param(
        [int]$Revision,
        [string]$Phase,
        [string]$Edition = 'Enterprise',
        [string]$Channel = 'stable',
        [bool]$Orphan = $false
    )

    return [pscustomobject]@{
        SchemaVersion = 2
        Identity = [pscustomobject]@{ edition = $Edition }
        TargetChannel = $Channel
        Head = [pscustomobject]@{ revision = $Revision; phase = $Phase }
        HeadSha256 = 'a' * 64
        OrphanReceipt = if ($Orphan) { [pscustomobject]@{} } else { $null }
        Receipts = @(1..10)
    }
}

function Invoke-ActualR8AdmissionBlock {
    param(
        [Parameter(Mandatory = $true)]$StateFixture,
        [Parameter(Mandatory = $true)][string]$ExpectedHead
    )

    $state = $StateFixture
    $RevalidateOnly = $true
    $ExpectedHeadSha256 = $ExpectedHead
    & $actualAdmissionBlock
}

foreach ($positive in @(
        [pscustomobject]@{ Revision = 8; Phase = 'PILOT_EVIDENCE_BOUND' },
        [pscustomobject]@{ Revision = 9; Phase = 'STABLE_PROMOTION_REQUESTED' },
        [pscustomobject]@{ Revision = 10; Phase = 'STABLE_FEED_PROMOTED' })) {
    Invoke-ActualR8AdmissionBlock `
        -StateFixture (New-R8AdmissionStateFixture `
            -Revision $positive.Revision -Phase $positive.Phase) `
        -ExpectedHead ('a' * 64)
}
foreach ($negative in @(
        [pscustomobject]@{ Name = 'stale head'; State = (New-R8AdmissionStateFixture -Revision 8 -Phase 'PILOT_EVIDENCE_BOUND'); ExpectedHead = ('b' * 64) },
        [pscustomobject]@{ Name = 'wrong phase'; State = (New-R8AdmissionStateFixture -Revision 9 -Phase 'PILOT_FEED_PROMOTED'); ExpectedHead = ('a' * 64) },
        [pscustomobject]@{ Name = 'r7'; State = (New-R8AdmissionStateFixture -Revision 7 -Phase 'INSTALLER_SIGNATURE_IMPORTED'); ExpectedHead = ('a' * 64) },
        [pscustomobject]@{ Name = 'orphan'; State = (New-R8AdmissionStateFixture -Revision 8 -Phase 'PILOT_EVIDENCE_BOUND' -Orphan $true); ExpectedHead = ('a' * 64) },
        [pscustomobject]@{ Name = 'Personal'; State = (New-R8AdmissionStateFixture -Revision 9 -Phase 'PILOT_FEED_PROMOTED' -Edition 'Personal'); ExpectedHead = ('a' * 64) })) {
    $rejected = $false
    try {
        Invoke-ActualR8AdmissionBlock `
            -StateFixture $negative.State -ExpectedHead $negative.ExpectedHead
    }
    catch {
        $rejected = $_.Exception.Message.Contains(
            'R8_REVALIDATION_STATE_REJECTED',
            [StringComparison]::Ordinal)
    }
    Assert-R8RevalidationTest $rejected `
        "The actual adapter admission block accepted $($negative.Name)."
}

# Parameter metadata is checked from the adapter AST, not from a duplicated
# declaration.  The nine raw proofs deliberately have no parameter-set name,
# so they remain mandatory in both mutually exclusive Create/Revalidate sets.
$parameterAstByName = @{}
foreach ($parameterAst in $ast.ParamBlock.Parameters) {
    $parameterAstByName[$parameterAst.Name.VariablePath.UserPath] = $parameterAst
}
function Get-R8ParameterAttributeText {
    param([Parameter(Mandatory = $true)]$ParameterAst)
    return @($ParameterAst.Attributes | ForEach-Object Extent | ForEach-Object Text) -join "`n"
}
foreach ($spec in @(
        [pscustomobject]@{ Name = 'ExpectedR7HeadSha256'; Set = 'Create' },
        [pscustomobject]@{ Name = 'OutputPath'; Set = 'Create' },
        [pscustomobject]@{ Name = 'RevalidateOnly'; Set = 'Revalidate' },
        [pscustomobject]@{ Name = 'ExpectedHeadSha256'; Set = 'Revalidate' })) {
    $attributeText = Get-R8ParameterAttributeText $parameterAstByName[$spec.Name]
    Assert-R8RevalidationTest `
        ($attributeText.Contains('Mandatory = $true', [StringComparison]::Ordinal) -and
         $attributeText.Contains("ParameterSetName = '$($spec.Set)'", [StringComparison]::Ordinal)) `
        "Adapter parameter '$($spec.Name)' is not mandatory in only $($spec.Set)."
}
foreach ($rawName in @(
        'PilotTrustPolicyPath',
        'WindowsPilotEvidenceEnvelopePath',
        'WindowsPilotEvidenceBodyPath',
        'WindowsPilotVerificationReportPath',
        'WindowsPilotReadinessConfigPath',
        'WindowsPilotStoredReadinessReportPath',
        'WindowsPilotReplayedReadinessReportPath',
        'LocalDataCertificationReceiptPath',
        'StablePrivatePilotObservationPath')) {
    $attributeText = Get-R8ParameterAttributeText $parameterAstByName[$rawName]
    Assert-R8RevalidationTest `
        ($attributeText.Contains('Mandatory = $true', [StringComparison]::Ordinal) -and
         -not $attributeText.Contains('ParameterSetName', [StringComparison]::Ordinal)) `
        "Raw proof '$rawName' is not mandatory in both adapter parameter sets."
}
$schemaVersionParameter = $parameterAstByName[
    'WindowsPilotReadinessSchemaVersion']
$schemaVersionAttributeText = Get-R8ParameterAttributeText `
    $schemaVersionParameter
Assert-R8RevalidationTest `
    ([string]$schemaVersionParameter.DefaultValue.Extent.Text -ceq '1' -and
     -not $schemaVersionAttributeText.Contains(
        'Mandatory',
        [StringComparison]::Ordinal) -and
     -not $schemaVersionAttributeText.Contains(
        'ParameterSetName',
        [StringComparison]::Ordinal) -and
     (($schemaVersionAttributeText -replace '\s', '').Contains(
        'ValidateSet(1,2)',
        [StringComparison]::Ordinal))) `
    'Readiness schema selector is not optional in both paths, v1-defaulted, and restricted to v1/v2.'

# Execute the exact source segments that bind the committed typed r8 receipt,
# invoke the existing binding hook, and compare reconstructed bytes/SHA.  The
# local module is a plumbing sentinel only; it does not simulate cryptography.
$receiptAssignments = @($ast.FindAll({
    param($node)
    $node -is [Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left -is [Management.Automation.Language.VariableExpressionAst] -and
        $node.Left.VariablePath.UserPath -ceq 'committedR8Receipt'
}, $true))
$bindingCalls = @($ast.FindAll({
    param($node)
    $node -is [Management.Automation.Language.CommandAst] -and
        $node.GetCommandName() -ceq
            'ProductionReleaseState\Assert-EnterpriseProductionPilotEvidenceInputBinding'
}, $true))
$summaryEqualityIfs = @($ast.FindAll({
    param($node)
    if ($node -isnot [Management.Automation.Language.IfStatementAst]) {
        return $false
    }
    $directThrows = @($node.Clauses | ForEach-Object {
        $_.Item2.Statements | Where-Object {
            $_ -is [Management.Automation.Language.ThrowStatementAst]
        }
    })
    return @($directThrows | Where-Object {
        $_.Extent.Text.Contains(
            'R8_REVALIDATION_SUMMARY_MISMATCH',
            [StringComparison]::Ordinal)
    }).Count -eq 1
}, $true))
Assert-R8RevalidationTest `
    ($receiptAssignments.Count -eq 1 -and $bindingCalls.Count -eq 1 -and
     $summaryEqualityIfs.Count -eq 1) `
    'Could not locate the adapter actual committed-r8 receipt/equality blocks.'
$receiptStart = $receiptAssignments[0].Extent.StartOffset
$bindingStart = $bindingCalls[0].Extent.StartOffset
$equalityStart = $summaryEqualityIfs[0].Extent.StartOffset
$equalityEnd = $summaryEqualityIfs[0].Extent.EndOffset
Assert-R8RevalidationTest `
    ($receiptAssignments[0].Parent -eq $summaryEqualityIfs[0].Parent -and
     $bindingStart -gt $receiptStart -and $equalityStart -gt $bindingStart) `
    'The adapter committed-r8 receipt/equality statements are not in the expected semantic order.'
$actualReceiptEqualityBlock = [ScriptBlock]::Create(
    $text.Substring($receiptStart, $equalityEnd - $receiptStart))

$returnStart = $text.IndexOf(
    '    $completedAtUtc = [DateTimeOffset]::UtcNow',
    $equalityEnd,
    [StringComparison]::Ordinal)
$writerStart = $text.IndexOf(
    '    Write-R8CreateNewOutput',
    $returnStart,
    [StringComparison]::Ordinal)
$writerEnd = $text.IndexOf(
    '        -DirectoryDescriptor $outputDirectory',
    $writerStart,
    [StringComparison]::Ordinal)
Assert-R8RevalidationTest `
    ($returnStart -ge 0 -and $writerStart -gt $returnStart -and
     $writerEnd -gt $writerStart) `
    'Could not locate the adapter actual final revalidation/creator block.'
$actualReturnBlock = [ScriptBlock]::Create(
    $text.Substring($returnStart, $writerEnd - $returnStart +
        '        -DirectoryDescriptor $outputDirectory'.Length))

$global:R8RevalidationBindingCalls = 0
$global:R8RevalidationWriterCalls = 0
$testStateModule = $null
try {
$testStateModule = New-Module -Name ProductionReleaseState -ScriptBlock {
    function Assert-EnterpriseProductionPilotEvidenceInputBinding {
        param($Input, $Plan, $Identity, $IdentitySha256, $Receipts, $StateRoot, $ExpectedR7HeadSha256, [switch]$EnforceCurrentLifetime)
        $global:R8RevalidationBindingCalls++
    }
    function Get-ProductionSha256Bytes {
        param([byte[]]$Bytes)
        return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Bytes)).ToLowerInvariant()
    }
    function ConvertTo-ProductionUtc {
        param([DateTimeOffset]$Value)
        return $Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
    }
    function ConvertFrom-ProductionUtc {
        param([string]$Value, [string]$Label)
        return [DateTimeOffset]::ParseExact($Value, 'yyyy-MM-ddTHH:mm:ssZ',
            [Globalization.CultureInfo]::InvariantCulture,
            ([Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal))
    }
    Export-ModuleMember -Function @(
        'Assert-EnterpriseProductionPilotEvidenceInputBinding',
        'Get-ProductionSha256Bytes',
        'ConvertTo-ProductionUtc',
        'ConvertFrom-ProductionUtc')
}
Import-Module $testStateModule -Force
function global:Write-R8CreateNewOutput {
    param($Path, $Bytes, $DirectoryDescriptor)
    $global:R8RevalidationWriterCalls++
    throw 'Writer sentinel was invoked by a RevalidateOnly return.'
}

function Invoke-ActualR8ReceiptEqualityBlock {
    param(
        [Parameter(Mandatory = $true)][byte[]]$OutputBytes,
        [Parameter(Mandatory = $true)][byte[]]$CommittedBytes,
        [Parameter(Mandatory = $true)][string]$CommittedSha256,
        [Parameter(Mandatory = $true)][string]$ReceiptSha256
    )

    $outputBytes = $OutputBytes
    $committedR8Input = [pscustomobject]@{
        Bytes = $CommittedBytes
        Sha256 = $CommittedSha256
    }
    $state = [pscustomobject]@{
        Identity = [pscustomobject]@{}
        IdentitySha256 = 'd' * 64
        Receipts = @(
            $null, $null, $null, $null, $null, $null, $null,
            [pscustomobject]@{
                revision = 8
                phase = 'PILOT_EVIDENCE_BOUND'
                data = [pscustomobject]@{
                    evidenceType = 'PILOT_EVIDENCE_BOUND'
                    relativePath = 'imports/pilot-evidence.v1/pilot-evidence-input.v1.json'
                    sha256 = $ReceiptSha256
                }
            })
    }
    $plan = [pscustomobject]@{}
    $stateRootFull = 'C:\fixture-state'
    $r7HeadSha256 = 'e' * 64
    & $actualReceiptEqualityBlock
}

$sameBytes = [byte[]](1, 2, 3)
$sameSha256 = [Convert]::ToHexString(
    [Security.Cryptography.SHA256]::HashData($sameBytes)).ToLowerInvariant()
Invoke-ActualR8ReceiptEqualityBlock `
    -OutputBytes $sameBytes -CommittedBytes $sameBytes `
    -CommittedSha256 $sameSha256 -ReceiptSha256 $sameSha256
Assert-R8RevalidationTest `
    ($global:R8RevalidationBindingCalls -eq 1) `
    'The actual committed-r8 block did not invoke its binding hook.'
foreach ($case in @(
        [pscustomobject]@{ Name = 'byte mismatch'; Output = [byte[]](1, 2, 4); Committed = $sameBytes; InputSha = $sameSha256; ReceiptSha = $sameSha256; Code = 'R8_REVALIDATION_SUMMARY_MISMATCH' },
        [pscustomobject]@{ Name = 'SHA mismatch'; Output = $sameBytes; Committed = $sameBytes; InputSha = ('f' * 64); ReceiptSha = ('f' * 64); Code = 'R8_REVALIDATION_SUMMARY_MISMATCH' },
        [pscustomobject]@{ Name = 'typed receipt SHA mismatch'; Output = $sameBytes; Committed = $sameBytes; InputSha = $sameSha256; ReceiptSha = ('0' * 64); Code = 'R8_REVALIDATION_STATE_REJECTED' })) {
    $rejected = $false
    try {
        Invoke-ActualR8ReceiptEqualityBlock -OutputBytes $case.Output `
            -CommittedBytes $case.Committed -CommittedSha256 $case.InputSha `
            -ReceiptSha256 $case.ReceiptSha
    }
    catch {
        $rejected = $_.Exception.Message.Contains($case.Code, [StringComparison]::Ordinal)
    }
    Assert-R8RevalidationTest $rejected `
        "The actual committed-r8 block accepted $($case.Name)."
}

function Invoke-ActualR8ReturnBlock {
    param(
        [Parameter(Mandatory = $true)][DateTimeOffset]$Expiry,
        [DateTimeOffset]$PolicyDeadline = $Expiry,
        [switch]$Create
    )

    $RevalidateOnly = -not $Create
    $expiresAt = $Expiry
    $policyValidUntilUtc = $PolicyDeadline
    $state = [pscustomobject]@{ HeadSha256 = 'a' * 64 }
    $r7HeadSha256 = 'b' * 64
    $committedR8Input = [pscustomobject]@{ Sha256 = 'c' * 64 }
    $outputPathFull = 'C:\must-not-write.json'
    $outputBytes = [byte[]](1)
    $outputDirectory = [pscustomobject]@{}
    return (& $actualReturnBlock)
}

$returnResult = Invoke-ActualR8ReturnBlock `
    -Expiry ([DateTimeOffset]::UtcNow.AddMinutes(1))
Assert-R8RevalidationTest `
    ([string]$returnResult.Status -ceq 'R8_EVIDENCE_REVALIDATED_NO_GO' -and
     [string]$returnResult.ProductionAdmission -ceq 'NO_GO' -and
     [string]$returnResult.PolicyValidUntilUtc -cmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$' -and
     $global:R8RevalidationWriterCalls -eq 0) `
    'Successful actual RevalidateOnly return wrote output or reported admission.'
$expiredRejected = $false
try {
    [void](Invoke-ActualR8ReturnBlock -Expiry ([DateTimeOffset]::UtcNow.AddSeconds(-1)))
}
catch {
    $expiredRejected = $_.Exception.Message.Contains(
        'R8_EVIDENCE_EXPIRED',
        [StringComparison]::Ordinal)
}
Assert-R8RevalidationTest $expiredRejected `
    'The actual final revalidation block accepted expired evidence.'
Assert-R8RevalidationTest `
    ($global:R8RevalidationWriterCalls -eq 0) `
    'The expired actual RevalidateOnly path invoked the create-only writer.'

$policyRejected = $false
try {
    [void](Invoke-ActualR8ReturnBlock -Expiry ([DateTimeOffset]::UtcNow.AddHours(1)) `
        -PolicyDeadline ([DateTimeOffset]::UtcNow.AddSeconds(-1)))
}
catch { $policyRejected = $_.Exception.Message -like 'R8_EVIDENCE_POLICY_EXPIRED:*' }
Assert-R8RevalidationTest $policyRejected 'The actual return block accepted a lapsed policy deadline while absolute expiry remained valid.'
Assert-R8RevalidationTest ($global:R8RevalidationWriterCalls -eq 0) 'A rejected policy deadline reached the create-only writer.'
$createPolicyRejected = $false
try {
    [void](Invoke-ActualR8ReturnBlock -Expiry ([DateTimeOffset]::UtcNow.AddHours(1)) `
        -PolicyDeadline ([DateTimeOffset]::UtcNow.AddSeconds(-1)) -Create)
}
catch { $createPolicyRejected = $_.Exception.Message -like 'R8_EVIDENCE_POLICY_EXPIRED:*' }
Assert-R8RevalidationTest $createPolicyRejected 'The Create path accepted an expired policy deadline before writing.'
Assert-R8RevalidationTest ($global:R8RevalidationWriterCalls -eq 0) 'The expired Create policy path reached its writer.'

$temporalBase = [DateTimeOffset]::Parse('2026-01-01T12:00:00Z', [Globalization.CultureInfo]::InvariantCulture)
$timestampSources = @(
    @{ Path='EnterpriseProductionPilotEvidence.psm1'; Name='ConvertFrom-R8FractionalUtc' },
    @{ Path='ProductionReleaseState.psm1'; Name='ConvertFrom-ProductionUtc' }
)
foreach ($source in $timestampSources) {
    $sourceAst = [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $source.Path), [ref]$null, [ref]$null)
    $timestampFunction = @($sourceAst.FindAll({ param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $source.Name
    }, $true))
    Assert-R8RevalidationTest ($timestampFunction.Count -eq 1) "Missing actual timestamp parser '$($source.Name)'."
    . ([ScriptBlock]::Create($timestampFunction[0].Extent.Text))
}
$script:WholeSecondUtcFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'"
$canonicalWindowsTimestamp = '2025-12-31T13:00:00.1234567Z'
$parsedWindowsTimestamp = ConvertFrom-R8FractionalUtc -Value $canonicalWindowsTimestamp -Label 'actual Windows evidence timestamp'
$originalParserRejected = $false
try { [void](ConvertFrom-ProductionUtc -Value $canonicalWindowsTimestamp -Label 'original incorrect Windows timestamp path') }
catch { $originalParserRejected = $_.Exception.Message -like '*exact whole-second UTC*' }
Assert-R8RevalidationTest $originalParserRejected 'RED reproduction did not reproduce the original parser incompatibility.'
Write-Output 'PASS RED reproduction: original whole-second parser rejects canonical seven-digit Windows evidence.'
$temporalCases = 0
foreach ($limiter in @('windows-age', 'local-age', 'stable-age', 'local-remaining', 'allowlist-remaining')) {
    $trustFixture = [pscustomobject]@{ maximumEvidenceAgeHours=24; minimumRemainingValidityMinutes=30 }
    $windowsCompletedFixture = $temporalBase.AddHours(-1)
    $localFixture = [pscustomobject]@{ issuedAtUnixSeconds=$temporalBase.AddHours(-1).ToUnixTimeSeconds(); expiresAtUnixSeconds=$temporalBase.AddHours(10).ToUnixTimeSeconds() }
    $stableFixture = [pscustomobject]@{ collectedAtUtc=(ProductionReleaseState\ConvertTo-ProductionUtc $temporalBase.AddHours(-1)); privatePilot=[pscustomobject]@{allowlist=[pscustomobject]@{activeUntilUtc=(ProductionReleaseState\ConvertTo-ProductionUtc $temporalBase.AddHours(10))}} }
    switch ($limiter) {
        'windows-age' { $windowsCompletedFixture=$parsedWindowsTimestamp }
        'local-age' { $localFixture.issuedAtUnixSeconds=$temporalBase.AddHours(-23).ToUnixTimeSeconds() }
        'stable-age' { $stableFixture.collectedAtUtc=ProductionReleaseState\ConvertTo-ProductionUtc $temporalBase.AddHours(-23) }
        'local-remaining' { $localFixture.expiresAtUnixSeconds=$temporalBase.AddMinutes(90).ToUnixTimeSeconds() }
        'allowlist-remaining' { $stableFixture.privatePilot.allowlist.activeUntilUtc=ProductionReleaseState\ConvertTo-ProductionUtc $temporalBase.AddMinutes(90) }
    }
    $deadline = @(Get-R8EvidencePolicyValidUntilUtc -Trust $trustFixture -WindowsCompletedAtUtc $windowsCompletedFixture `
        -LocalDataReceipt $localFixture -StableObservation $stableFixture)
    $expectedDeadline = if ($limiter -eq 'windows-age') { $parsedWindowsTimestamp.AddHours(24) } else { $temporalBase.AddHours(1) }
    Assert-R8RevalidationTest ($deadline.Count -eq 1 -and $deadline[0] -is [DateTimeOffset] -and
        $deadline[0] -eq $expectedDeadline) "Exact AST policy calculation missed '$limiter'."
    $absoluteExpiry = [DateTimeOffset]::FromUnixTimeSeconds($localFixture.expiresAtUnixSeconds)
    $allowExpiry = ProductionReleaseState\ConvertFrom-ProductionUtc $stableFixture.privatePilot.allowlist.activeUntilUtc
    if ($allowExpiry -lt $absoluteExpiry) { $absoluteExpiry = $allowExpiry }
    foreach ($offsetTicks in @(-1,0,1)) {
        $checkAt=$deadline[0].AddTicks($offsetTicks)
        Assert-R8RevalidationTest ($checkAt -lt $absoluteExpiry) 'Temporal fixture must remain absolutely unexpired.'
        $caught=$null
        try { Assert-R8FinalEvidenceLifetime -PolicyValidUntilUtc $deadline[0] -ExpiresAtUtc $absoluteExpiry -ValidationTimeUtc $checkAt }
        catch { $caught=$_.Exception.Message }
        if ($offsetTicks -gt 0) {
            Assert-R8RevalidationTest ($caught -like 'R8_EVIDENCE_POLICY_EXPIRED:*') "'$limiter' accepted a crossed policy boundary."
        } else {
            Assert-R8RevalidationTest ($null -eq $caught) "'$limiter' rejected the verifier-compatible inclusive boundary."
        }
        $temporalCases++
    }
    Write-Output "PASS exact AST temporal policy $limiter before/equal/after boundary"
}
foreach ($offsetTicks in @(-1,0,1)) {
    $caught=$null
    try { Assert-R8FinalEvidenceLifetime -PolicyValidUntilUtc $temporalBase.AddHours(1) `
        -ExpiresAtUtc $temporalBase -ValidationTimeUtc $temporalBase.AddTicks($offsetTicks) }
    catch { $caught=$_.Exception.Message }
    Assert-R8RevalidationTest (($offsetTicks -lt 0 -and $null -eq $caught) -or
        ($offsetTicks -ge 0 -and $caught -like 'R8_EVIDENCE_EXPIRED:*')) 'Absolute expiry boundary semantics changed.'
    $temporalCases++
}
Write-Output "PASS exact AST final evidence lifetime: $temporalCases deterministic temporal boundaries; no clock changes or real-device acceptance."

# Execute the actual creation-time assignment with the verifier's parsed
# fractional result. The persisted schema deliberately remains whole seconds.
$creationAssignment = @($ast.FindAll({ param($node)
    $node -is [Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left.Extent.Text -ceq '$createdAtUtc'
}, $true))
Assert-R8RevalidationTest ($creationAssignment.Count -eq 1) 'Missing actual canonical r8 creation assignment.'
$verified = [pscustomobject]@{Windows=[pscustomobject]@{BodyCompletedAtUtc=$parsedWindowsTimestamp}}
. ([ScriptBlock]::Create($creationAssignment[0].Extent.Text))
Assert-R8RevalidationTest ($createdAtUtc -ceq '2025-12-31T13:00:00Z') 'Canonical r8 creation did not use the verified fractional Windows completion.'
$fractionalDeadline=$parsedWindowsTimestamp.AddHours(24)
$fractionalReturn=Invoke-ActualR8ReturnBlock -Expiry ([DateTimeOffset]::UtcNow.AddYears(10)) `
    -PolicyDeadline ([DateTimeOffset]::UtcNow.AddYears(1).AddTicks(1234567))
$exportedDeadline=ProductionReleaseState\ConvertTo-ProductionUtc -Value $fractionalDeadline
Assert-R8RevalidationTest ($exportedDeadline -ceq '2026-01-01T13:00:00Z') 'Fractional policy deadline did not conservatively floor to whole seconds.'
Assert-R8RevalidationTest ([string]$fractionalReturn.PolicyValidUntilUtc -cmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$') 'Actual revalidation return changed its timestamp contract.'
Write-Output 'PASS GREEN verified fractional Windows timestamp preserves ticks internally and canonical whole-second outputs.'

$revalidateReturn = $text.IndexOf(
    "Status = 'R8_EVIDENCE_REVALIDATED_NO_GO'",
    [StringComparison]::Ordinal)
$createWrite = $text.LastIndexOf('Write-R8CreateNewOutput', [StringComparison]::Ordinal)
Assert-R8RevalidationTest `
    ($revalidateReturn -ge 0 -and $createWrite -gt $revalidateReturn) `
    'The revalidation path can reach create-only output writing.'

$rawInputOpeners = @(
    '$PilotTrustPolicyPath',
    '$WindowsPilotEvidenceEnvelopePath',
    '$WindowsPilotEvidenceBodyPath',
    '$WindowsPilotVerificationReportPath',
    '$WindowsPilotReadinessConfigPath',
    '$WindowsPilotStoredReadinessReportPath',
    '$WindowsPilotReplayedReadinessReportPath',
    '$LocalDataCertificationReceiptPath',
    '$StablePrivatePilotObservationPath')
foreach ($rawInput in $rawInputOpeners) {
    Assert-R8RevalidationTest `
        ($text.IndexOf($rawInput, [StringComparison]::Ordinal) -ge 0) `
        "r8 revalidation no longer opens required raw proof '$rawInput'."
}

foreach ($forbidden in @(
        "ProductionAdmission = 'GO'",
        "productionAdmission = 'GO'",
        'Write-R8CreateNewOutput -Path $outputPathFull')) {
    Assert-R8RevalidationTest `
        (-not $text.Contains($forbidden, [StringComparison]::Ordinal)) `
        "r8 revalidation contains forbidden admission/write shortcut '$forbidden'."
}

Write-Output 'ENTERPRISE-PRODUCTION-PILOT-EVIDENCE-REVALIDATION-PLUMBING-PASS'
}
finally {
    if ($null -ne $testStateModule) {
        Microsoft.PowerShell.Core\Remove-Module `
            -ModuleInfo $testStateModule -Force -ErrorAction SilentlyContinue
    }
}
