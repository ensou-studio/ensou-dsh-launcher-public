#requires -Version 7.2
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# This is a component-integration test of the revalidation decision boundary.
# Its in-memory verifiers do not constitute a release, network publish, or employee acceptance.
$repositoryRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$orchestratorPath = Join-Path $PSScriptRoot 'Invoke-LauncherProductionRelease.ps1'
$orchestratorText = [IO.File]::ReadAllText($orchestratorPath)
$tokens = $null
$parseErrors = $null
$orchestratorAst = [Management.Automation.Language.Parser]::ParseInput(
    $orchestratorText, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -ne 0) {
    throw ('Orchestrator parse failed: ' + (($parseErrors | ForEach-Object Message) -join '; '))
}

function Assert-True {
    param([bool]$Value, [string]$Message)
    if (-not $Value) { throw $Message }
}

function Assert-Rejected {
    param([scriptblock]$Action, [string]$ExpectedMessage, [string]$Label)
    try { & $Action }
    catch {
        if ($_.Exception.Message -notlike "*$ExpectedMessage*") {
            throw "$Label expected '$ExpectedMessage', got '$($_.Exception.Message)'."
        }
        return
    }
    throw "$Label was accepted."
}

$functionAst = @($orchestratorAst.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Get-EnterpriseRevalidatedProductionStatus'
}, $true))
Assert-True ($functionAst.Count -eq 1) 'Expected exactly one production revalidation function.'

# Execute the precise current production function source; do not duplicate its readiness calculation here.
Invoke-Expression $functionAst[0].Extent.Text

$script:head = 'a' * 64
$script:responseSha256 = 'b' * 64
$script:pilotEvidenceSha256 = 'c' * 64

$clientModule = $null
$stateModule = $null
try {
$clientModule = New-Module -Name InstallerSigningContracts -ScriptBlock {
    function Assert-ProductionClientSigningHistory {
        param($State, $Plan)
        return $global:EnterpriseReadinessTestClientResults
    }
    Export-ModuleMember -Function Assert-ProductionClientSigningHistory
}
Microsoft.PowerShell.Core\Import-Module -ModuleInfo $clientModule -Force

$stateModule = New-Module -Name ProductionReleaseState -ScriptBlock {
    function Get-ProductionReleaseStateSummary {
        param([string]$StateRoot, [string]$StateSchemaPath)
        return $global:EnterpriseReadinessTestSummary
    }
    function ConvertFrom-ProductionUtc {
        param([string]$Value, [string]$Label)
        $parsed = [DateTimeOffset]::MinValue
        if (-not [DateTimeOffset]::TryParse(
                $Value,
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::AssumeUniversal,
                [ref]$parsed)) {
            throw "$Label must be a UTC timestamp."
        }
        return $parsed
    }
    function ConvertTo-ProductionUtc {
        param([DateTimeOffset]$Value)
        return $Value.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
    }
    function Assert-ProductionRuntimeSourceReleaseHistory {
        param($State, $Plan)
        return $global:EnterpriseReadinessTestSourceResults
    }
    Export-ModuleMember -Function Get-ProductionReleaseStateSummary, ConvertFrom-ProductionUtc, ConvertTo-ProductionUtc, Assert-ProductionRuntimeSourceReleaseHistory
}
Microsoft.PowerShell.Core\Import-Module -ModuleInfo $stateModule -Force

function Test-PilotRevalidationAdapter {
    param(
        [string]$StateRoot,
        [switch]$RevalidateOnly,
        [string]$ExpectedHeadSha256,
        [string]$WindowsPilotEvidenceEnvelopePath,
        [string]$WindowsPilotEvidenceBodyPath,
        [string]$WindowsPilotVerificationReportPath,
        [string]$WindowsPilotReadinessConfigPath,
        [string]$WindowsPilotStoredReadinessReportPath,
        [string]$WindowsPilotReplayedReadinessReportPath,
        [string]$LocalDataCertificationReceiptPath,
        [string]$StablePrivatePilotObservationPath,
        [string]$PilotTrustPolicyPath
    )
    $global:EnterpriseReadinessTestPilotInvocation = $PSBoundParameters
    return $global:EnterpriseReadinessTestPilotResults
}

function New-EvidencePaths {
    return @{
        WindowsPilotEvidenceEnvelopePath = 'evidence-envelope.json'
        WindowsPilotEvidenceBodyPath = 'evidence-body.json'
        WindowsPilotVerificationReportPath = 'verification-report.json'
        WindowsPilotReadinessConfigPath = 'readiness-config.json'
        WindowsPilotStoredReadinessReportPath = 'stored-readiness.json'
        WindowsPilotReplayedReadinessReportPath = 'replayed-readiness.json'
        LocalDataCertificationReceiptPath = 'local-data.json'
        StablePrivatePilotObservationPath = 'pilot-observation.json'
        PilotTrustPolicyPath = 'pilot-trust.json'
    }
}

function New-State {
    param([int]$Revision = 10, [string]$Edition = 'Enterprise', [string]$Head = $script:head)
    $receipts = @(0..7 | ForEach-Object { [pscustomobject]@{ data = [pscustomobject]@{} } })
    $receipts[2].data | Add-Member -NotePropertyName responseSha256 -NotePropertyValue $script:responseSha256
    $receipts[7].data | Add-Member -NotePropertyName sha256 -NotePropertyValue $script:pilotEvidenceSha256
    return [pscustomobject]@{
        SchemaVersion = 2
        Identity = [pscustomobject]@{ edition = $Edition }
        TargetChannel = 'stable'
        Head = [pscustomobject]@{ revision = $Revision }
        OrphanReceipt = $null
        HeadSha256 = $Head
        StateRoot = 'C:\\component-integration-state'
        Receipts = $receipts
    }
}

function New-Summary {
    param(
        [int]$Revision = 10,
        [string]$Phase = 'STABLE_FEED_PROMOTED',
        [bool]$LifecycleTerminal = $true,
        [string]$Head = $script:head,
        [DateTimeOffset]$Expiry = ([DateTimeOffset]::UtcNow.AddMinutes(5))
    )
    return [pscustomobject]@{
        HeadSha256 = $Head
        Edition = 'Enterprise'
        TargetChannel = 'stable'
        Revision = $Revision
        Phase = $Phase
        LifecycleTerminal = $LifecycleTerminal
        PilotEvidenceExpiresAtUtc = $Expiry.UtcDateTime.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
        PilotEvidenceStatus = 'BOUND'
        StableReady = $false
        FeedPublicationEvidence = ''
        NoGoCode = ''
        NoGo = ''
    }
}

function Set-ValidVerifierResults {
    $global:EnterpriseReadinessTestClientResults = @([pscustomobject]@{
        Status = 'CLIENT_SIGNING_HISTORY_REVALIDATED'
        CurrentHeadSha256 = $script:head
        ResponseSha256 = $script:responseSha256
        VerifiedFileCount = 4
    })
    $global:EnterpriseReadinessTestPilotResults = @([pscustomobject]@{
        Status = 'R8_EVIDENCE_REVALIDATED_NO_GO'
        ProductionAdmission = 'NO_GO'
        CurrentHeadSha256 = $script:head
        PilotEvidenceInputSha256 = $script:pilotEvidenceSha256
        # Safely before the current revalidation time and before fixture evidence expiry.
        PolicyValidUntilUtc = [DateTimeOffset]::UtcNow.AddMinutes(4).ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
    })
    # The default represents a historical plan without an immutable-source
    # anchor. This explicit stub is plumbing only, not an issuer substitute.
    $global:EnterpriseReadinessTestSourceResults = @([pscustomobject]@{
        Status = 'IMMUTABLE_SOURCE_RELEASE_UNVERIFIED'
        SourceReleaseVerified = $false
        CurrentHeadSha256 = $script:head
    })
}

function Set-AuthenticatedSourceHistoryFixture {
    $global:EnterpriseReadinessTestSourceResults = @([pscustomobject]@{
        Status = 'RUNTIME_SOURCE_RELEASE_AUTHENTICATED'
        SourceReleaseVerified = $true
        CurrentHeadSha256 = $script:head
        ReceiptSha256 = ('d' * 64)
        Repository = 'ensou-example/runtime'
        TagName = 'runtime-source-admission-fixture'
        TargetCommit = ('b' * 40)
    })
}

function Invoke-Readiness {
    param($State, $EvidencePaths = (New-EvidencePaths))
    return Get-EnterpriseRevalidatedProductionStatus -State $State -Plan ([pscustomobject]@{}) `
        -ExpectedHeadSha256 $script:head -StateSchemaPath 'state.schema.json' `
        -PilotAdapterPath 'Test-PilotRevalidationAdapter' -EvidencePaths $EvidencePaths
}

# r8/r9 remain deliberate NO_GO states.  A terminal r10 proves the signed local
# release chain only; immutable source-release admission remains an independent NO_GO.
Set-ValidVerifierResults
$global:EnterpriseReadinessTestSummary = New-Summary -Revision 8 -Phase 'PILOT_EVIDENCE_BOUND' -LifecycleTerminal $false
$r8 = Invoke-Readiness -State (New-State -Revision 8)
Assert-True (-not $r8.StableReady -and $r8.NoGoCode -ceq 'STABLE_PROMOTION_REQUIRED') 'r8 must remain NO_GO.'

Set-ValidVerifierResults
$global:EnterpriseReadinessTestSummary = New-Summary -Revision 9 -Phase 'STABLE_FEED_PROMOTION_AUTHORIZED' -LifecycleTerminal $false
$r9 = Invoke-Readiness -State (New-State -Revision 9)
Assert-True (-not $r9.StableReady -and $r9.NoGoCode -ceq 'STABLE_PUBLICATION_RESULT_REQUIRED') 'r9 must remain NO_GO.'

Set-ValidVerifierResults
$global:EnterpriseReadinessTestSummary = New-Summary
$r10 = Invoke-Readiness -State (New-State)
Assert-True (-not $r10.StableReady -and
    $r10.NoGoCode -ceq 'IMMUTABLE_SOURCE_RELEASE_UNVERIFIED' -and
    $r10.RevalidatedReleaseEvidence -and
    $r10.RuntimeSourceAdmissionStatus -ceq 'IMMUTABLE_SOURCE_RELEASE_UNVERIFIED' -and
    $r10.ReadinessScope -ceq 'AUTHENTICATED_RELEASE_STATE_ONLY' -and
    $r10.FeedPublicationEvidence -ceq 'AUTHENTICATED_COMPLETED_FEED_OPERATION_ONLY') 'Terminal r10 signed/local proof must remain an immutable-source-release NO_GO.'
Assert-True ($global:EnterpriseReadinessTestPilotInvocation.RevalidateOnly -and
    $global:EnterpriseReadinessTestPilotInvocation.ExpectedHeadSha256 -ceq $script:head) 'Pilot adapter must be called as an exact-head revalidation.'

# Only an explicit authenticated source-history result can advance the
# read-only r10 readiness signal; it never changes the committed NO_GO state.
Set-ValidVerifierResults
Set-AuthenticatedSourceHistoryFixture
$global:EnterpriseReadinessTestSummary = New-Summary
$authenticatedR10 = Invoke-Readiness -State (New-State)
Assert-True ($authenticatedR10.StableReady -and
    $authenticatedR10.NoGoCode -ceq 'AUTHENTICATED_RELEASE_STATE_ONLY' -and
    $authenticatedR10.RuntimeSourceAdmissionStatus -ceq 'RUNTIME_SOURCE_RELEASE_AUTHENTICATED' -and
    $authenticatedR10.ReadinessScope -ceq 'AUTHENTICATED_RELEASE_STATE_ONLY') 'Authenticated source history must be required for, and may only yield, read-only r10 readiness.'

Set-ValidVerifierResults
$global:EnterpriseReadinessTestSourceResults = @()
$global:EnterpriseReadinessTestSummary = New-Summary
Assert-Rejected { Invoke-Readiness -State (New-State) } 'ENTERPRISE_STATUS_SOURCE_REVALIDATION_REJECTED' 'Missing source history tuple'

Set-ValidVerifierResults
$global:EnterpriseReadinessTestSourceResults = @($global:EnterpriseReadinessTestSourceResults[0], $global:EnterpriseReadinessTestSourceResults[0])
$global:EnterpriseReadinessTestSummary = New-Summary
Assert-Rejected { Invoke-Readiness -State (New-State) } 'ENTERPRISE_STATUS_SOURCE_REVALIDATION_REJECTED' 'Extra source history tuple'

Set-ValidVerifierResults
$global:EnterpriseReadinessTestSourceResults[0].CurrentHeadSha256 = ('e' * 64)
$global:EnterpriseReadinessTestSummary = New-Summary
Assert-Rejected { Invoke-Readiness -State (New-State) } 'ENTERPRISE_STATUS_SOURCE_REVALIDATION_REJECTED' 'Source history head mismatch'

Set-ValidVerifierResults
$global:EnterpriseReadinessTestSourceResults[0].SourceReleaseVerified = 'true'
$global:EnterpriseReadinessTestSummary = New-Summary
Assert-Rejected { Invoke-Readiness -State (New-State) } 'ENTERPRISE_STATUS_SOURCE_REVALIDATION_REJECTED' 'Nonscalar source-history verification claim'

Set-ValidVerifierResults
$global:EnterpriseReadinessTestSourceResults[0].Status = 'RUNTIME_SOURCE_RELEASE_AUTHENTICATED'
$global:EnterpriseReadinessTestSummary = New-Summary
Assert-Rejected { Invoke-Readiness -State (New-State) } 'ENTERPRISE_STATUS_SOURCE_REVALIDATION_REJECTED' 'Inconsistent source history status'

Set-ValidVerifierResults
$global:EnterpriseReadinessTestSummary = New-Summary -Revision 10 -Phase 'WRONG_PHASE'
$wrongPhase = Invoke-Readiness -State (New-State)
Assert-True (-not $wrongPhase.StableReady -and $wrongPhase.NoGoCode -ceq 'STABLE_PUBLICATION_RESULT_REQUIRED') 'Wrong r10 terminal phase must not be reported ready.'

Set-ValidVerifierResults
$global:EnterpriseReadinessTestSummary = New-Summary
Assert-Rejected { Invoke-Readiness -State (New-State -Head ('d' * 64)) } 'ENTERPRISE_STATUS_REVALIDATION_STATE_REJECTED' 'Wrong initial head'
Assert-Rejected { Invoke-Readiness -State (New-State -Edition 'Personal') } 'ENTERPRISE_STATUS_REVALIDATION_STATE_REJECTED' 'Wrong edition'
Assert-Rejected { Invoke-Readiness -State (New-State -Revision 7) } 'ENTERPRISE_STATUS_REVALIDATION_STATE_REJECTED' 'Unsupported phase revision'

Set-ValidVerifierResults
$global:EnterpriseReadinessTestSummary = New-Summary -Head ('d' * 64)
Assert-Rejected { Invoke-Readiness -State (New-State) } 'ENTERPRISE_STATUS_REVALIDATION_HEAD_CHANGED' 'Changed final state head'

Set-ValidVerifierResults
$global:EnterpriseReadinessTestSummary = New-Summary -Expiry ([DateTimeOffset]::UtcNow.AddSeconds(-1))
Assert-Rejected { Invoke-Readiness -State (New-State) } 'R8_BINDING_EXPIRED' 'Expired Pilot evidence'

Set-ValidVerifierResults
$global:EnterpriseReadinessTestPilotResults[0].PolicyValidUntilUtc = [DateTimeOffset]::UtcNow.AddSeconds(-1).ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
$global:EnterpriseReadinessTestSummary = New-Summary -Expiry ([DateTimeOffset]::UtcNow.AddMinutes(5))
Assert-Rejected { Invoke-Readiness -State (New-State) } 'R8_EVIDENCE_POLICY_EXPIRED' 'Expired Pilot policy deadline with still-valid absolute evidence expiry'

Set-ValidVerifierResults
$global:EnterpriseReadinessTestPilotResults[0].PolicyValidUntilUtc = $null
$global:EnterpriseReadinessTestSummary = New-Summary
Assert-Rejected { Invoke-Readiness -State (New-State) } 'Revalidated Pilot policy deadline' 'Missing Pilot policy deadline'

Set-ValidVerifierResults
$global:EnterpriseReadinessTestPilotResults[0].PolicyValidUntilUtc = 'not-a-timestamp'
$global:EnterpriseReadinessTestSummary = New-Summary
Assert-Rejected { Invoke-Readiness -State (New-State) } 'Revalidated Pilot policy deadline' 'Malformed Pilot policy deadline'

Set-ValidVerifierResults
$global:EnterpriseReadinessTestSummary = New-Summary
$missingPaths = New-EvidencePaths
[void]$missingPaths.Remove('PilotTrustPolicyPath')
Assert-Rejected { Invoke-Readiness -State (New-State) -EvidencePaths $missingPaths } 'ENTERPRISE_STATUS_REVALIDATION_INPUTS_REQUIRED' 'Missing raw evidence path'
$extraPaths = New-EvidencePaths
$extraPaths['UnexpectedPath'] = 'unexpected'
Assert-Rejected { Invoke-Readiness -State (New-State) -EvidencePaths $extraPaths } 'ENTERPRISE_STATUS_REVALIDATION_INPUTS_REQUIRED' 'Extra raw evidence path'

$global:EnterpriseReadinessTestClientResults = @()
$global:EnterpriseReadinessTestPilotResults = @()
$global:EnterpriseReadinessTestSummary = New-Summary
Assert-Rejected { Invoke-Readiness -State (New-State) } 'ENTERPRISE_STATUS_CLIENT_REVALIDATION_REJECTED' 'Missing client verifier tuple'

Set-ValidVerifierResults
$global:EnterpriseReadinessTestClientResults = @($global:EnterpriseReadinessTestClientResults[0], $global:EnterpriseReadinessTestClientResults[0])
$global:EnterpriseReadinessTestSummary = New-Summary
Assert-Rejected { Invoke-Readiness -State (New-State) } 'ENTERPRISE_STATUS_CLIENT_REVALIDATION_REJECTED' 'Extra client verifier tuple'

Set-ValidVerifierResults
$global:EnterpriseReadinessTestPilotResults = @([pscustomobject]@{
    Status = 'WRONG'
    ProductionAdmission = 'NO_GO'
    CurrentHeadSha256 = $script:head
    PilotEvidenceInputSha256 = $script:pilotEvidenceSha256
})
$global:EnterpriseReadinessTestSummary = New-Summary
Assert-Rejected { Invoke-Readiness -State (New-State) } 'ENTERPRISE_STATUS_PILOT_REVALIDATION_REJECTED' 'Wrong Pilot verifier tuple'

Set-ValidVerifierResults
$global:EnterpriseReadinessTestPilotResults = @($global:EnterpriseReadinessTestPilotResults[0], $global:EnterpriseReadinessTestPilotResults[0])
$global:EnterpriseReadinessTestSummary = New-Summary
Assert-Rejected { Invoke-Readiness -State (New-State) } 'ENTERPRISE_STATUS_PILOT_REVALIDATION_REJECTED' 'Extra Pilot verifier tuple'

# Caller shape: mutation phases reject the hook before any lock/module bootstrap; Status takes a read lock then invokes it.
Assert-True ($orchestratorText.Contains("if (`$RevalidatePilotEvidence -and `$Phase -cne 'Status')", [StringComparison]::Ordinal) -and
    $orchestratorText.Contains("throw 'ENTERPRISE_STATUS_REVALIDATION_PHASE_REJECTED", [StringComparison]::Ordinal)) 'Revalidation hook must reject every non-Status phase.'
$statusOffset = $orchestratorText.IndexOf("if (`$Phase -eq 'Status')", [StringComparison]::Ordinal)
$readLockOffset = $orchestratorText.IndexOf('Enter-ProductionReleaseStateReadLock -StateRoot $StateRoot', $statusOffset, [StringComparison]::Ordinal)
$hookOffset = $orchestratorText.IndexOf('Get-EnterpriseRevalidatedProductionStatus -State $statusState', $statusOffset, [StringComparison]::Ordinal)
Assert-True ($statusOffset -ge 0 -and $readLockOffset -gt $statusOffset -and $hookOffset -gt $readLockOffset) 'Status hook must retain the production state read lock before revalidation.'

Write-Output 'PASS Test-EnterpriseProductionReleaseReadiness: component-integration stubs only; no release or employee acceptance exercised.'
}
finally {
    if ($null -ne $stateModule) {
        Microsoft.PowerShell.Core\Remove-Module `
            -ModuleInfo $stateModule -Force -ErrorAction SilentlyContinue
    }
    if ($null -ne $clientModule) {
        Microsoft.PowerShell.Core\Remove-Module `
            -ModuleInfo $clientModule -Force -ErrorAction SilentlyContinue
    }
}
