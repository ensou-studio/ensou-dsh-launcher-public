#requires -Version 7.2

[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [switch]$IncludePublicationContract,
    [switch]$IncludePublicationResult,
    [switch]$PublicationContextOnly,
    [switch]$PublicationResultOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($PublicationContextOnly -or $PublicationResultOnly -or $IncludePublicationResult) { $IncludePublicationContract = $true }
$utf8 = [Text.UTF8Encoding]::new($false)
$script:UnsignedPeFixturePath = ''
$script:ProductRoleFixtureContract = $null
$script:AssertionCount = 0
$script:ExpectedFailureCount = 0
$script:PublicationFeedIdentitySha256 = 'b' * 64

# Reuse only the function definitions from the broad orchestration test. Its
# body is deliberately not dot-sourced, so this focused test remains one
# bounded, offline r8-to-r9 process integration lane.
$referenceTestPath = Join-Path `
    $PSScriptRoot `
    'Test-LauncherProductionReleaseOrchestration.ps1'
$referenceTokens = $null
$referenceErrors = $null
$referenceAst = [Management.Automation.Language.Parser]::ParseFile(
    $referenceTestPath,
    [ref]$referenceTokens,
    [ref]$referenceErrors)
if ($referenceErrors.Count -ne 0) {
    throw 'Reference orchestration test did not parse.'
}
$referenceFunctions = @(
    'Assert-True',
    'Assert-Throws',
    'ConvertTo-Base64Url',
    'ConvertTo-OrchestrationDiagnosticText',
    'Write-Json',
    'Read-Json',
    'Get-Sha256',
    'Get-StateTreeSnapshot',
    'Invoke-Git',
    'Invoke-Orchestrator',
    'Get-PeSecurityLayout',
    'New-UnsignedPeFixture',
    'New-FoundationSignedPeFixture',
    'Copy-State',
    'Add-V2FoundationStateContractClientEvidence',
    'New-V2FoundationEvidenceData',
    'New-EnterpriseV2FoundationPilotEvidenceTransition',
    'New-EnterpriseV2FoundationInstallerTransition',
    'Add-V2FoundationTransition',
    'Advance-V2FoundationState',
    'New-PlanFixture',
    'Write-CanonicalJson',
    'New-PublisherInputFixture',
    'ConvertTo-LowSP256Signature',
    'New-ManifestPublishingResponseFixture',
    'Invoke-TestPilotManifestFoundation'
)
foreach ($functionName in $referenceFunctions) {
    $definitions = @($referenceAst.FindAll({
                param($node)
                $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                    $node.Name -ceq $functionName
            }, $true))
    if ($definitions.Count -ne 1) {
        throw "Reference helper '$functionName' is missing or ambiguous."
    }
    . ([scriptblock]::Create([string]$definitions[0].Extent.Text))
}

$stateModulePath = Join-Path $PSScriptRoot 'ProductionReleaseState.psm1'
$installerContractsPath = Join-Path $PSScriptRoot 'InstallerSigningContracts.psm1'
$feedPromotionModulePath = Join-Path $PSScriptRoot 'ProductionFeedPromotion.psm1'
Import-Module $stateModulePath -Force -DisableNameChecking
Import-Module $installerContractsPath -Force -DisableNameChecking
Import-Module $feedPromotionModulePath -Force -DisableNameChecking
# Nested module imports can replace unqualified shared commands. Restore the
# same final order used by the production orchestrator.
Import-Module $installerContractsPath -Force -DisableNameChecking
Import-Module $stateModulePath -Force -DisableNameChecking

function New-FeedPromotionAuthorizationResponse {
    param(
        [Parameter(Mandatory = $true)][string]$PromotionRoot,
        [Parameter(Mandatory = $true)][string]$OutputPath,
        [Parameter(Mandatory = $true)][Security.Cryptography.ECDsa]$Signer,
        [AllowNull()][scriptblock]$Mutate = $null
    )

    $requestPath = Join-Path $PromotionRoot 'request\request.v1.json'
    $headPath = Join-Path $PromotionRoot 'head.json'
    $request = Read-Json -Path $requestPath
    $response = [ordered]@{
        schemaVersion = 1
        responseType = 'ensou-dsh-launcher-offline-feed-promotion-response'
        operationId = [string]$request.operationId
        orchestrationId = [string]$request.orchestrationId
        edition = 'Enterprise'
        exposureRing = 'stable'
        feedChannel = 'stable'
        publishScope = 'public-stable'
        releaseSetId = [string]$request.releaseSetId
        requestSha256 = Get-Sha256 -Path $requestPath
        requestNonce = [string]$request.requestNonce
        basePromotionHeadSha256 = Get-Sha256 -Path $headPath
        sourceStateHeadSha256 = [string]$request.sourceState.headSha256
        payloadSetSha256 = [string]$request.payloadSetSha256
        feedCasSha256 = [string]$request.feedCasSha256
        decision = 'AUTHORIZE_OFFLINE_BUNDLE'
        completedAtUtc = ConvertTo-ProductionUtc -Value ([DateTimeOffset]::UtcNow)
        requestExpiresAtUtc = [string]$request.expiresAtUtc
        productionAdmission = 'OFFLINE_BUNDLE_ONLY'
        networkPublishPerformed = $false
        authentication = [ordered]@{
            algorithm = 'ES256'
            keyId = [string]$request.authorizationTrust.keyId
            purpose = 'feed-promotion-response'
            payloadType =
                'ensou-dsh-launcher-feed-promotion-response-authentication-v1'
        }
    }
    if ($null -ne $Mutate) {
        [void](& $Mutate $response)
    }
    $payload = Get-ProductionFeedPromotionResponseAuthenticationPayload `
        -Response ([pscustomobject]$response)
    $signature = ConvertTo-LowSP256Signature -Signature (
        $Signer.SignData(
            $payload,
            [Security.Cryptography.HashAlgorithmName]::SHA256,
            [Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation))
    $response.authentication.value = ConvertTo-Base64Url -Bytes $signature
    [IO.Directory]::CreateDirectory(
        [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($OutputPath))) |
        Out-Null
    [IO.File]::WriteAllBytes(
        $OutputPath,
        (ConvertTo-ProductionJsonBytes -Value $response))
    return $OutputPath
}

function Invoke-StablePromotion {
    param(
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$PlanPath,
        [Parameter(Mandatory = $true)][string]$StateRoot,
        [Parameter(Mandatory = $true)][string]$ExpectedHeadSha256,
        [string]$PromotionRoot = '',
        [string]$ResponsePath = '',
        [string]$FaultPoint = '',
        [switch]$ExpectFailure,
        [string]$ExpectedMessage = ''
    )

    $arguments = @{
        ScriptPath = $ScriptPath
        RepoRoot = $RepoRoot
        Edition = 'Enterprise'
        Phase = 'Promote'
        PlanPath = $PlanPath
        StateRoot = $StateRoot
        ExpectedHeadSha256 = $ExpectedHeadSha256
        ExpectFailure = $ExpectFailure
        ExpectedMessage = $ExpectedMessage
    }
    if ($PromotionRoot) {
        $arguments.PromotionRoot = $PromotionRoot
        $arguments.ExpectedFeedIdentitySha256 = $script:PublicationFeedIdentitySha256
        $arguments.ExpectedChannelHead = 'missing'
        $arguments.ExpectedJournalHead = 'missing'
    }
    if ($ResponsePath) {
        $arguments.FeedPromotionResponsePath = $ResponsePath
    }
    if ($FaultPoint) {
        $arguments.FaultPoint = $FaultPoint
    }
    return Invoke-Orchestrator @arguments
}

function New-PromotionExchange {
    param(
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$PlanPath,
        [Parameter(Mandatory = $true)][string]$StateRoot,
        [Parameter(Mandatory = $true)][string]$PromotionRoot,
        [Parameter(Mandatory = $true)][string]$ResponsePath,
        [Parameter(Mandatory = $true)][Security.Cryptography.ECDsa]$Signer,
        [AllowNull()][scriptblock]$MutateResponse = $null
    )

    $r8HeadSha256 = Get-Sha256 -Path (Join-Path $StateRoot 'head.json')
    $stateBefore = Get-StateTreeSnapshot -Path $StateRoot
    [void](Invoke-StablePromotion `
        -ScriptPath $ScriptPath `
        -RepoRoot $RepoRoot `
        -PlanPath $PlanPath `
        -StateRoot $StateRoot `
        -PromotionRoot $PromotionRoot `
        -ExpectedHeadSha256 $r8HeadSha256)
    Assert-True `
        ((Get-StateTreeSnapshot -Path $StateRoot) -ceq $stateBefore) `
        'Generating a Stable promotion request changed production state.'
    Assert-True `
        ((Test-Path -LiteralPath (Join-Path $PromotionRoot `
                    'request\request.v1.json') -PathType Leaf) -and
         (Test-Path -LiteralPath (Join-Path $PromotionRoot 'head.json') `
            -PathType Leaf)) `
        'Stable promotion request did not create its exact external handoff.'
    [void](New-FeedPromotionAuthorizationResponse `
        -PromotionRoot $PromotionRoot `
        -OutputPath $ResponsePath `
        -Signer $Signer `
        -Mutate $MutateResponse)
    return [pscustomobject]@{
        R8HeadSha256 = $r8HeadSha256
        StateBefore = $stateBefore
        PromotionRoot = $PromotionRoot
        ResponsePath = $ResponsePath
    }
}

function Assert-R9NoGoState {
    param(
        [Parameter(Mandatory = $true)][string]$StateRoot,
        [Parameter(Mandatory = $true)][string]$StateSchemaPath
    )

    $state = Get-ProductionReleaseState `
        -StateRoot $StateRoot `
        -StateSchemaPath $StateSchemaPath
    $admissionPath = Join-Path $StateRoot `
        'requests\stable-feed-promotion.v1\promotion-admission.v1.json'
    $admission = Read-Json -Path $admissionPath
    $bundleHead = Read-Json -Path (Join-Path $StateRoot `
        'requests\stable-feed-promotion.v1\bundle-head.v1.json')
    $summary = Get-ProductionReleaseStateSummary `
        -StateRoot $StateRoot `
        -StateSchemaPath $StateSchemaPath
    Assert-True `
        ([int]$state.Head.revision -eq 9 -and
         [string]$state.Head.phase -ceq 'STABLE_PROMOTION_REQUESTED' -and
         @($state.Receipts).Count -eq 9 -and
         $null -eq $state.OrphanReceipt) `
        'Stable promotion did not commit exactly one r9 transition.'
    Assert-True `
        ([string]$admission.productionAdmission -ceq 'NO_GO' -and
         -not [bool]$admission.networkPublishPerformed -and
         [string]$bundleHead.productionAdmission -ceq 'NO_GO' -and
         -not [bool]$bundleHead.networkPublishPerformed) `
        'Stable promotion state claimed GO or a network publication.'
    Assert-True `
        (-not [bool]$summary.StableReady -and
         [string]$summary.NoGoCode -ceq
            'PHASE_NOT_IMPLEMENTED_STABLE_FEED_PROMOTED') `
        'Committed r9 did not retain its explicit r10 NO-GO boundary.'
    return $state
}

function Start-StablePromotionRaceProcess {
    param(
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$PlanPath,
        [Parameter(Mandatory = $true)][string]$StateRoot,
        [Parameter(Mandatory = $true)][string]$PromotionRoot,
        [Parameter(Mandatory = $true)][string]$ResponsePath,
        [Parameter(Mandatory = $true)][string]$ExpectedHeadSha256
    )

    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = (Get-Command pwsh -ErrorAction Stop).Source
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in @(
            '-NoLogo', '-NoProfile', '-NonInteractive', '-File', $ScriptPath,
            '-RepositoryRoot', $RepoRoot,
            '-Edition', 'Enterprise',
            '-Phase', 'Promote',
            '-PlanPath', $PlanPath,
            '-StateRoot', $StateRoot,
            '-PromotionRoot', $PromotionRoot,
            '-FeedPromotionResponsePath', $ResponsePath,
            '-ExpectedFeedIdentitySha256', $script:PublicationFeedIdentitySha256,
            '-ExpectedChannelHead', 'missing',
            '-ExpectedJournalHead', 'missing',
            '-ExpectedHeadSha256', $ExpectedHeadSha256,
            '-FaultPoint',
            'TestOnlyWaitBeforeStablePromotionCheckoutAdmission')) {
        [void]$startInfo.ArgumentList.Add([string]$argument)
    }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    if (-not $process.Start()) {
        $process.Dispose()
        throw 'Failed to start Stable promotion race process.'
    }
    return [pscustomobject]@{
        Process = $process
        StandardOutput = $process.StandardOutput.ReadToEndAsync()
        StandardError = $process.StandardError.ReadToEndAsync()
    }
}

function Complete-StablePromotionRaceProcess {
    param([Parameter(Mandatory = $true)]$Running)

    $process = $Running.Process
    try {
        if (-not $process.WaitForExit(30000)) {
            $process.Kill($true)
            [void]$process.WaitForExit(10000)
            throw 'Stable promotion race process timed out.'
        }
        $process.WaitForExit()
        return [pscustomobject]@{
            ExitCode = $process.ExitCode
            Output = $Running.StandardOutput.GetAwaiter().GetResult() +
                $Running.StandardError.GetAwaiter().GetResult()
        }
    }
    finally {
        if (-not $process.HasExited) {
            $process.Kill($true)
        }
        $process.Dispose()
    }
}

function Get-StablePromotionRaceProcessDiagnostic {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)]$Running
    )

    $process = $Running.Process
    if (-not $process.HasExited) {
        try {
            $process.Kill($true)
        }
        catch [InvalidOperationException] {
            if (-not $process.HasExited) {
                throw
            }
        }
        [void]$process.WaitForExit(10000)
    }
    $stdoutCaptured = $Running.StandardOutput.Wait(10000)
    $stderrCaptured = $Running.StandardError.Wait(10000)
    return [ordered]@{
        label = $Label
        processId = $process.Id
        exitCode = if ($process.HasExited) { $process.ExitCode } else { $null }
        stdout = if ($stdoutCaptured) {
            $Running.StandardOutput.GetAwaiter().GetResult()
        }
        else {
            '<stdout capture timed out>'
        }
        stderr = if ($stderrCaptured) {
            $Running.StandardError.GetAwaiter().GetResult()
        }
        else {
            '<stderr capture timed out>'
        }
    }
}

$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) (
    'ensou-stable-promotion-orchestration-' +
        [Guid]::NewGuid().ToString('N'))
$feedSigner = [Security.Cryptography.ECDsa]::Create(
    [Security.Cryptography.ECCurve+NamedCurves]::nistP256)
$clientSigner = [Security.Cryptography.ECDsa]::Create(
    [Security.Cryptography.ECCurve+NamedCurves]::nistP256)
$manifestSigner = [Security.Cryptography.ECDsa]::Create(
    [Security.Cryptography.ECCurve+NamedCurves]::nistP256)
$releaseSigner = [Security.Cryptography.ECDsa]::Create(
    [Security.Cryptography.ECCurve+NamedCurves]::nistP256)
$publicationSigner = [Security.Cryptography.ECDsa]::Create(
    [Security.Cryptography.ECCurve+NamedCurves]::nistP256)

try {
    [IO.Directory]::CreateDirectory($fixtureRoot) | Out-Null
    [byte[]]$publicationFeedIdentityBytes = ConvertTo-ProductionJsonBytes ([ordered]@{
        schemaVersion=2; product='ensou-dsh-enterprise'; environment='production';
        feedInstanceId=[Guid]::NewGuid().ToString('N')
    })
    if ($PublicationResultOnly -or $IncludePublicationResult) {
        $script:PublicationFeedIdentitySha256 = Get-ProductionSha256Bytes -Bytes $publicationFeedIdentityBytes
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
        $source = Join-Path $RepositoryRoot $relativePath.Replace(
            '/', [IO.Path]::DirectorySeparatorChar)
        $destination = Join-Path $sourceRepo $relativePath.Replace(
            '/', [IO.Path]::DirectorySeparatorChar)
        [IO.Directory]::CreateDirectory(
            [IO.Path]::GetDirectoryName($destination)) | Out-Null
        [IO.File]::Copy($source, $destination, $false)
    }
    [void](Invoke-Git -Root $sourceRepo -Arguments @('init', '--quiet'))
    [void](Invoke-Git -Root $sourceRepo -Arguments @(
            'config', 'user.email', 'stable-promotion-test@ensou.invalid'))
    [void](Invoke-Git -Root $sourceRepo -Arguments @(
            'config', 'user.name', 'ensou-stable-promotion-test'))
    [void](Invoke-Git -Root $sourceRepo -Arguments @('add', '--all'))
    [void](Invoke-Git -Root $sourceRepo -Arguments @(
            'commit', '--quiet', '-m', 'stable promotion test checkout'))
    $sourceCommit = [string]@(Invoke-Git `
        -Root $sourceRepo `
        -Arguments @('rev-parse', 'HEAD'))[0]
    $orchestrator = Join-Path $sourceRepo `
        'release\scripts\Invoke-LauncherProductionRelease.ps1'
    $stateSchemaPath = Join-Path $sourceRepo `
        'release\schemas\launcher-production-release-state-v2.schema.json'

    $script:UnsignedPeFixturePath = Join-Path $fixtureRoot `
        'unsigned-client-fixture.dll'
    Add-Type -TypeDefinition @'
namespace Ensou.Launcher.StablePromotionTests
{
    public static class UnsignedClientFixture
    {
        public static int Value => 9;
    }
}
'@ -Language CSharp -OutputAssembly $script:UnsignedPeFixturePath `
        -OutputType Library

    $evidenceRoot = Join-Path $fixtureRoot 'evidence'
    [IO.Directory]::CreateDirectory($evidenceRoot) | Out-Null
    $runtimeName = 'EnsouDshRuntime-managed-v2026.08.30.1-win-x64.zip'
    $runtimeArchivePath = Join-Path $evidenceRoot $runtimeName
    [IO.File]::WriteAllBytes(
        $runtimeArchivePath,
        $utf8.GetBytes('OFFLINE-STABLE-PROMOTION-TEST-RUNTIME'))
    $runtimeSha256 = Get-Sha256 -Path $runtimeArchivePath
    $metadata = Read-Json -Path (Join-Path $RepositoryRoot `
        'release\examples\source-runtime.metadata.json')
    $metadata.releaseId = 'managed-v2026.08.30.1'
    $metadata.promotionEligible = $true
    $metadata.artifact.fileName = $runtimeName
    $metadata.artifact.sizeBytes =
        [int64](Get-Item -LiteralPath $runtimeArchivePath).Length
    $metadata.artifact.sha256 = $runtimeSha256
    $runtimeMetadataPath = $runtimeArchivePath + '.metadata.json'
    Write-Json -Path $runtimeMetadataPath -Value $metadata
    $runtimeHashPath = $runtimeArchivePath + '.sha256'
    [IO.File]::WriteAllText(
        $runtimeHashPath,
        $runtimeSha256 + '  ' + $runtimeName + [char]10,
        $utf8)

    $planPath = Join-Path $evidenceRoot 'enterprise-stable-plan-v2.json'
    $plan = New-PlanFixture `
        -Edition Enterprise `
        -Path $planPath `
        -Commit $sourceCommit `
        -RuntimeArchivePath $runtimeArchivePath `
        -RuntimeMetadataPath $runtimeMetadataPath `
        -RuntimeHashPath $runtimeHashPath `
        -UnsignedRoot (Join-Path $evidenceRoot 'unsigned') `
        -SignerSha256 ('a' * 64) `
        -ResponsePublic ($clientSigner.ExportParameters($false)) `
        -ManifestResponsePublic ($manifestSigner.ExportParameters($false)) `
        -ReleaseManifestPublic ($releaseSigner.ExportParameters($false)) `
        -SchemaVersion 2 `
        -TargetChannel stable
    $feedPublic = $feedSigner.ExportParameters($false)
    $plan.externalResponseTrusts.feedPromotion = [ordered]@{
        algorithm = 'ES256'
        keyId = 'launcher-feed-promotion-response-test'
        purpose = 'feed-promotion-response'
        x = ConvertTo-Base64Url -Bytes $feedPublic.Q.X
        y = ConvertTo-Base64Url -Bytes $feedPublic.Q.Y
    }
    $plan.externalResponseTrusts.installerSigning.keyId =
        'foundation-only-installer-signing'
    if ($IncludePublicationContract) {
        $publicationPoint = $publicationSigner.ExportParameters($false).Q
        $plan.stablePublicationTrust = [ordered]@{
            algorithm = 'ES256'
            keyId = 'test-stable-publication-attestation'
            purpose = 'stable-public-promotion-attestation'
            x = ConvertTo-Base64Url -Bytes $publicationPoint.X
            y = ConvertTo-Base64Url -Bytes $publicationPoint.Y
        }
    }
    Write-Json -Path $planPath -Value $plan

    $baselineState = Join-Path $fixtureRoot 'r8-baseline-state'
    [void](Invoke-Orchestrator `
        -ScriptPath $orchestrator `
        -RepoRoot $sourceRepo `
        -Edition Enterprise `
        -Phase Prepare `
        -PlanPath $planPath `
        -StateRoot $baselineState)
    [void](Add-V2FoundationStateContractClientEvidence `
        -StateRoot $baselineState `
        -StateSchemaPath $stateSchemaPath)
    [void](Invoke-TestPilotManifestFoundation `
        -ScriptPath $orchestrator `
        -RepoRoot $sourceRepo `
        -Edition Enterprise `
        -PlanPath $planPath `
        -StateRoot $baselineState `
        -FixtureRoot (Join-Path $fixtureRoot 'manifest-foundation') `
        -Signer $manifestSigner `
        -ReleaseSigner $releaseSigner)
    [void](Advance-V2FoundationState `
        -StateRoot $baselineState `
        -StateSchemaPath $stateSchemaPath `
        -TargetRevision 8)
    $baseline = Get-ProductionReleaseState `
        -StateRoot $baselineState `
        -StateSchemaPath $stateSchemaPath
    Assert-True `
        ([int]$baseline.Head.revision -eq 8 -and
         [string]$baseline.Head.phase -ceq 'PILOT_EVIDENCE_BOUND') `
        'Focused Stable promotion fixture did not reach exact r8.'

    $happyState = Join-Path $fixtureRoot 'happy-state'
    Copy-State -Source $baselineState -Destination $happyState
    $happyExchange = New-PromotionExchange `
        -ScriptPath $orchestrator `
        -RepoRoot $sourceRepo `
        -PlanPath $planPath `
        -StateRoot $happyState `
        -PromotionRoot (Join-Path $fixtureRoot 'happy-promotion') `
        -ResponsePath (Join-Path $evidenceRoot 'happy-response.json') `
        -Signer $feedSigner
    [void](Invoke-StablePromotion `
        -ScriptPath $orchestrator `
        -RepoRoot $sourceRepo `
        -PlanPath $planPath `
        -StateRoot $happyState `
        -PromotionRoot $happyExchange.PromotionRoot `
        -ResponsePath $happyExchange.ResponsePath `
        -ExpectedHeadSha256 $happyExchange.R8HeadSha256)
    [void](Assert-R9NoGoState `
        -StateRoot $happyState `
        -StateSchemaPath $stateSchemaPath)

    if ($IncludePublicationContract) {
        # Exercise the real subprocess exporter from the exact fixture r9 state.
        # The earlier phases use development-only foundation evidence, not a release approval.
        $publicationContextPath = Join-Path $evidenceRoot 'stable-publication-context.json'
        $r9HeadSha256 = Get-Sha256 -Path (Join-Path $happyState 'head.json')
        $r9Before = Get-StateTreeSnapshot -Path $happyState
        [void](Invoke-Orchestrator -ScriptPath $orchestrator -RepoRoot $sourceRepo `
            -Edition Enterprise -Phase Promote -PlanPath $planPath -StateRoot $happyState `
            -ExpectedHeadSha256 $r9HeadSha256 `
            -EnterpriseStablePublicationContextPath $publicationContextPath)
        $context = Read-Json -Path $publicationContextPath
        Assert-True ($context.sourceR9HeadSha256 -ceq $r9HeadSha256) 'Exported context did not pin exact r9 head bytes.'
        Assert-True ($context.planSha256 -ceq (Get-Sha256 -Path $planPath)) 'Exported context did not pin original plan bytes.'
        Assert-True ($context.trust.keyId -ceq $plan.stablePublicationTrust.keyId) 'Context lost the original independent publication trust.'
        Assert-True ($context.sourceIdentitySha256 -cne $context.expectedFeedIdentitySha256) 'Fixture must exercise distinct Windows state and Linux feed identity hashes.'
        Assert-True ((Get-StateTreeSnapshot -Path $happyState) -ceq $r9Before) 'Context export changed immutable r9 state.'
        [void](Invoke-Orchestrator -ScriptPath $orchestrator -RepoRoot $sourceRepo `
            -Edition Enterprise -Phase Promote -PlanPath $planPath -StateRoot $happyState `
            -ExpectedHeadSha256 $r9HeadSha256 `
            -EnterpriseStablePublicationContextPath $publicationContextPath -ExpectFailure)
        Assert-True ((Get-StateTreeSnapshot -Path $happyState) -ceq $r9Before) 'Duplicate context output changed state.'
        Assert-Throws -Action {
            [void](Add-ProductionReleaseReceipt -StateRoot $happyState -StateSchemaPath $stateSchemaPath `
                -Phase STABLE_FEED_PROMOTED -ExpectedPreviousPhase STABLE_PROMOTION_REQUESTED `
                -ExpectedHeadSha256 $r9HeadSha256 -Data ([ordered]@{evidenceType='generic';relativePath='ignored';sha256=('a' * 64)}))
        } -Label 'Generic evidence cannot fabricate an Enterprise r10 transition' -ExpectedMessage 'authenticated publication result'
        Assert-True ((Get-StateTreeSnapshot -Path $happyState) -ceq $r9Before) 'Rejected generic r10 transition changed state.'
        if ($PublicationResultOnly -or $IncludePublicationResult) {
            . (Join-Path $PSScriptRoot 'Test-EnterpriseStablePublicationStateFixture.ps1')
            $fixtureResult = New-EnterpriseStablePublicationStateFixture -StateRoot $happyState `
                -Context $context -PublicationSigner $publicationSigner `
                -FeedIdentityBytes $publicationFeedIdentityBytes `
                -OutputBundleRoot (Join-Path $evidenceRoot 'synthetic-publication-result')
            Assert-True ($fixtureResult.Synthetic -ceq $true) 'State integration fixture must not claim an actual Linux publication.'
            # r9 has no orphan: a fresh retained canonical rejects a different fresh
            # result, but an expired one is quarantined before a fresh r10 import.
            $expiredRecoveryState = Join-Path $fixtureRoot 'publication-expired-recovery-state'
            Copy-State -Source $happyState -Destination $expiredRecoveryState
            $publicationA = New-EnterpriseStablePublicationStateFixture -StateRoot $expiredRecoveryState `
                -Context $context -PublicationSigner $publicationSigner -FeedIdentityBytes $publicationFeedIdentityBytes `
                -OutputBundleRoot (Join-Path $evidenceRoot 'publication-expired-a') -LifetimeSeconds 60
            $publicationB = New-EnterpriseStablePublicationStateFixture -StateRoot $expiredRecoveryState `
                -Context $context -PublicationSigner $publicationSigner -FeedIdentityBytes $publicationFeedIdentityBytes `
                -OutputBundleRoot (Join-Path $evidenceRoot 'publication-expired-b') -ObservedAtUtc ([DateTimeOffset]::UtcNow.AddSeconds(1))
            [void](Invoke-Orchestrator -ScriptPath $orchestrator -RepoRoot $sourceRepo -Edition Enterprise -Phase Promote `
                -PlanPath $planPath -StateRoot $expiredRecoveryState -ExpectedHeadSha256 $r9HeadSha256 `
                -EnterpriseStablePublicationResultBundlePath $publicationA.BundleRoot -FaultPoint AfterStablePublicationBundle `
                -ExpectFailure -ExpectedMessage 'INJECTED-CRASH-AFTER-STABLE-PUBLICATION-BUNDLE')
            $retainedBeforeExpiry = Get-StateTreeSnapshot -Path $expiredRecoveryState
            [void](Invoke-Orchestrator -ScriptPath $orchestrator -RepoRoot $sourceRepo -Edition Enterprise -Phase Promote `
                -PlanPath $planPath -StateRoot $expiredRecoveryState -ExpectedHeadSha256 $r9HeadSha256 `
                -EnterpriseStablePublicationResultBundlePath $publicationB.BundleRoot -ExpectFailure `
                -ExpectedMessage 'Fresh Stable publication result conflicts with retained evidence.')
            Assert-True ((Get-StateTreeSnapshot -Path $expiredRecoveryState) -ceq $retainedBeforeExpiry) 'Fresh conflicting publication result changed retained r9 evidence.'
            $expiryWait = [DateTimeOffset]::Parse([string]$publicationA.ExpiresAtUtc).AddSeconds(1)
            if (($expiryWait - [DateTimeOffset]::UtcNow).TotalSeconds -gt 65) { throw 'Test publication expiry wait exceeded its 65-second bound.' }
            Write-Output ("Waiting until {0:O} for the test-only publication attestation to expire." -f $expiryWait)
            while ([DateTimeOffset]::UtcNow -lt $expiryWait) { Start-Sleep -Milliseconds 250 }
            [void](Invoke-Orchestrator -ScriptPath $orchestrator -RepoRoot $sourceRepo -Edition Enterprise -Phase Promote `
                -PlanPath $planPath -StateRoot $expiredRecoveryState -ExpectedHeadSha256 $r9HeadSha256 `
                -EnterpriseStablePublicationResultBundlePath $publicationB.BundleRoot)
            $expiredRecoveryR10 = Get-ProductionReleaseState -StateRoot $expiredRecoveryState -StateSchemaPath $stateSchemaPath
            Assert-True ([int]$expiredRecoveryR10.Head.revision -eq 10) 'Expired r9 canonical was not quarantined before fresh r10 import.'
            $quarantines = @(Get-ChildItem -LiteralPath (Split-Path -Parent $expiredRecoveryState) -Force | Where-Object { $_.Name -like '.ensou-launcher-production-expired-*-stable-feed-result-*' })
            Assert-True ($quarantines.Count -eq 1) 'Expired r9 publication canonical was not identity-bound quarantined.'

            # r10 orphan binds the original result at its receipt instant; expiry
            # cannot authorize replacement, but exact replay remains recoverable.
            $orphanRecoveryState = Join-Path $fixtureRoot 'publication-orphan-recovery-state'
            Copy-State -Source $happyState -Destination $orphanRecoveryState
            $orphanA = New-EnterpriseStablePublicationStateFixture -StateRoot $orphanRecoveryState `
                -Context $context -PublicationSigner $publicationSigner -FeedIdentityBytes $publicationFeedIdentityBytes `
                -OutputBundleRoot (Join-Path $evidenceRoot 'publication-orphan-a') -LifetimeSeconds 60
            $orphanB = New-EnterpriseStablePublicationStateFixture -StateRoot $orphanRecoveryState `
                -Context $context -PublicationSigner $publicationSigner -FeedIdentityBytes $publicationFeedIdentityBytes `
                -OutputBundleRoot (Join-Path $evidenceRoot 'publication-orphan-b') -ObservedAtUtc ([DateTimeOffset]::UtcNow.AddSeconds(1))
            [void](Invoke-Orchestrator -ScriptPath $orchestrator -RepoRoot $sourceRepo -Edition Enterprise -Phase Promote `
                -PlanPath $planPath -StateRoot $orphanRecoveryState -ExpectedHeadSha256 $r9HeadSha256 `
                -EnterpriseStablePublicationResultBundlePath $orphanA.BundleRoot -FaultPoint AfterStablePublicationReceipt `
                -ExpectFailure -ExpectedMessage 'INJECTED-CRASH-AFTER-STABLE_FEED_PROMOTED-RECEIPT')
            $orphanReceipt = @(Get-ChildItem -LiteralPath (Join-Path $orphanRecoveryState 'receipts') -File |
                Where-Object { $_.Name -like '*-stable-feed-promoted.json' })
            Assert-True ($orphanReceipt.Count -eq 1) 'Receipt fault did not leave exactly one orphan r10 receipt.'
            $orphanReceiptPath = $orphanReceipt[0].FullName
            $orphanReceiptSha256 = Get-Sha256 -Path $orphanReceiptPath
            $orphanReceiptRecordedAtUtc = [string](Read-Json -Path $orphanReceiptPath).recordedAtUtc
            $orphanQuarantinesBeforeRecovery = @(
                Get-ChildItem -LiteralPath (Split-Path -Parent $orphanRecoveryState) -Force |
                    Where-Object { $_.Name -like '.ensou-launcher-production-expired-*-stable-feed-result-*' })
            $orphanBeforeRecovery = Get-StateTreeSnapshot -Path $orphanRecoveryState
            [void](Invoke-Orchestrator -ScriptPath $orchestrator -RepoRoot $sourceRepo -Edition Enterprise -Phase Promote `
                -PlanPath $planPath -StateRoot $orphanRecoveryState -ExpectedHeadSha256 $r9HeadSha256 `
                -EnterpriseStablePublicationResultBundlePath $orphanB.BundleRoot -ExpectFailure `
                -ExpectedMessage 'Stable publication result conflicts with its orphan r10 receipt.')
            Assert-True ((Get-StateTreeSnapshot -Path $orphanRecoveryState) -ceq $orphanBeforeRecovery) 'Conflicting orphan r10 result changed state before recovery.'
            $orphanExpiryWait = [DateTimeOffset]::Parse([string]$orphanA.ExpiresAtUtc).AddSeconds(1)
            if (($orphanExpiryWait - [DateTimeOffset]::UtcNow).TotalSeconds -gt 65) { throw 'Test orphan expiry wait exceeded its 65-second bound.' }
            Write-Output ("Waiting until {0:O} for the orphan-bound test attestation to expire." -f $orphanExpiryWait)
            while ([DateTimeOffset]::UtcNow -lt $orphanExpiryWait) { Start-Sleep -Milliseconds 250 }
            [void](Invoke-Orchestrator -ScriptPath $orchestrator -RepoRoot $sourceRepo -Edition Enterprise -Phase Promote `
                -PlanPath $planPath -StateRoot $orphanRecoveryState -ExpectedHeadSha256 $r9HeadSha256 `
                -EnterpriseStablePublicationResultBundlePath $orphanA.BundleRoot)
            $orphanR10 = Get-ProductionReleaseState -StateRoot $orphanRecoveryState -StateSchemaPath $stateSchemaPath
            Assert-True ([int]$orphanR10.Head.revision -eq 10) 'Exact orphan r10 replay did not commit after expiry.'
            Assert-True ((Get-Sha256 -Path $orphanReceiptPath) -ceq $orphanReceiptSha256) 'Exact orphan recovery rewrote the committed r10 receipt.'
            Assert-True (([string](Read-Json -Path $orphanReceiptPath).recordedAtUtc) -ceq $orphanReceiptRecordedAtUtc) 'Exact orphan recovery changed the original receipt timestamp.'
            $orphanQuarantinesAfterRecovery = @(
                Get-ChildItem -LiteralPath (Split-Path -Parent $orphanRecoveryState) -Force |
                    Where-Object { $_.Name -like '.ensou-launcher-production-expired-*-stable-feed-result-*' })
            Assert-True ($orphanQuarantinesAfterRecovery.Count -eq $orphanQuarantinesBeforeRecovery.Count) 'Exact orphan recovery unexpectedly quarantined retained evidence.'
            [void](Invoke-Orchestrator -ScriptPath $orchestrator -RepoRoot $sourceRepo `
                -Edition Enterprise -Phase Promote -PlanPath $planPath -StateRoot $happyState `
                -ExpectedHeadSha256 $r9HeadSha256 `
                -EnterpriseStablePublicationResultBundlePath $fixtureResult.BundleRoot)
            $r10 = Get-ProductionReleaseState -StateRoot $happyState -StateSchemaPath $stateSchemaPath
            Assert-True ([int]$r10.Head.revision -eq 10 -and $r10.Head.phase -ceq 'STABLE_FEED_PROMOTED') 'Authenticated result did not advance exact Enterprise r9 to r10.'
            $r10Before = Get-StateTreeSnapshot -Path $happyState
            [void](Invoke-Orchestrator -ScriptPath $orchestrator -RepoRoot $sourceRepo `
                -Edition Enterprise -Phase Promote -PlanPath $planPath -StateRoot $happyState `
                -ExpectedHeadSha256 $r10.HeadSha256 `
                -EnterpriseStablePublicationResultBundlePath $fixtureResult.BundleRoot)
            Assert-True ((Get-StateTreeSnapshot -Path $happyState) -ceq $r10Before) 'Identical r10 import replay changed state.'
            [void](Invoke-Orchestrator -ScriptPath $orchestrator -RepoRoot $sourceRepo `
                -Edition Enterprise -Phase Promote -PlanPath $planPath -StateRoot $happyState `
                -ExpectedHeadSha256 $r9HeadSha256 `
                -EnterpriseStablePublicationResultBundlePath $fixtureResult.BundleRoot -ExpectFailure `
                -ExpectedMessage 'exact current-state CAS')
            Assert-True ((Get-StateTreeSnapshot -Path $happyState) -ceq $r10Before) 'Stale r10 CAS rejection changed state.'
            $storedResultPath = Join-Path $happyState 'imports/stable-feed-result.v1/evidence/context.json'
            [byte[]]$storedBytes = [IO.File]::ReadAllBytes($storedResultPath)
            try {
                [IO.File]::WriteAllBytes($storedResultPath, [byte[]]($storedBytes + [byte]32))
                [void](Invoke-Orchestrator -ScriptPath $orchestrator -RepoRoot $sourceRepo `
                    -Edition Enterprise -Phase Status -PlanPath $planPath -StateRoot $happyState `
                    -ExpectFailure -ExpectedMessage 'raw bytes differ')
            } finally { [IO.File]::WriteAllBytes($storedResultPath, $storedBytes) }
            Assert-True ((Get-StateTreeSnapshot -Path $happyState) -ceq $r10Before) 'Historical tamper test did not restore its fixture bytes.'
            Write-Output ("Enterprise Stable authenticated r9-to-r10 state integration tests passed ({0} assertions; {1} expected failures). Synthetic publication statement; not production approval." -f $script:AssertionCount, $script:ExpectedFailureCount)
            if ($PublicationResultOnly) { return }
        }
        if ($PublicationContextOnly) {
            Write-Output ("Enterprise Stable r9 publication context and generic-r10 rejection tests passed ({0} assertions; {1} expected failures). Not an r10 import or production acceptance." -f $script:AssertionCount, $script:ExpectedFailureCount)
            return
        }
    }

    $bundleCrashState = Join-Path $fixtureRoot 'bundle-crash-state'
    Copy-State -Source $baselineState -Destination $bundleCrashState
    $bundleCrashExchange = New-PromotionExchange `
        -ScriptPath $orchestrator `
        -RepoRoot $sourceRepo `
        -PlanPath $planPath `
        -StateRoot $bundleCrashState `
        -PromotionRoot (Join-Path $fixtureRoot 'bundle-crash-promotion') `
        -ResponsePath (Join-Path $evidenceRoot 'bundle-crash-response.json') `
        -Signer $feedSigner
    [void](Invoke-StablePromotion `
        -ScriptPath $orchestrator `
        -RepoRoot $sourceRepo `
        -PlanPath $planPath `
        -StateRoot $bundleCrashState `
        -PromotionRoot $bundleCrashExchange.PromotionRoot `
        -ResponsePath $bundleCrashExchange.ResponsePath `
        -ExpectedHeadSha256 $bundleCrashExchange.R8HeadSha256 `
        -FaultPoint AfterStablePromotionStateBundle `
        -ExpectFailure `
        -ExpectedMessage 'INJECTED-CRASH-AFTER-STABLE-PROMOTION-STATE-BUNDLE')
    Assert-True `
        (([int](Read-Json -Path (Join-Path $bundleCrashState `
                        'head.json')).revision) -eq 8 -and
         (Test-Path -LiteralPath (Join-Path $bundleCrashState `
                'requests\stable-feed-promotion.v1') -PathType Container) -and
         -not (Test-Path -LiteralPath (Join-Path $bundleCrashState `
                'receipts\0009-stable-promotion-requested.json'))) `
        'Bundle crash did not leave the exact recoverable pre-receipt state.'
    [void](Invoke-StablePromotion `
        -ScriptPath $orchestrator `
        -RepoRoot $sourceRepo `
        -PlanPath $planPath `
        -StateRoot $bundleCrashState `
        -ExpectedHeadSha256 $bundleCrashExchange.R8HeadSha256)
    [void](Assert-R9NoGoState `
        -StateRoot $bundleCrashState `
        -StateSchemaPath $stateSchemaPath)

    $receiptCrashState = Join-Path $fixtureRoot 'receipt-crash-state'
    Copy-State -Source $baselineState -Destination $receiptCrashState
    $receiptCrashExchange = New-PromotionExchange `
        -ScriptPath $orchestrator `
        -RepoRoot $sourceRepo `
        -PlanPath $planPath `
        -StateRoot $receiptCrashState `
        -PromotionRoot (Join-Path $fixtureRoot 'receipt-crash-promotion') `
        -ResponsePath (Join-Path $evidenceRoot 'receipt-crash-response.json') `
        -Signer $feedSigner
    [void](Invoke-StablePromotion `
        -ScriptPath $orchestrator `
        -RepoRoot $sourceRepo `
        -PlanPath $planPath `
        -StateRoot $receiptCrashState `
        -PromotionRoot $receiptCrashExchange.PromotionRoot `
        -ResponsePath $receiptCrashExchange.ResponsePath `
        -ExpectedHeadSha256 $receiptCrashExchange.R8HeadSha256 `
        -FaultPoint AfterStablePromotionReceipt `
        -ExpectFailure `
        -ExpectedMessage 'INJECTED-CRASH-AFTER-STABLE_PROMOTION_REQUESTED-RECEIPT')
    Assert-True `
        (([int](Read-Json -Path (Join-Path $receiptCrashState `
                        'head.json')).revision) -eq 8 -and
         (Test-Path -LiteralPath (Join-Path $receiptCrashState `
                'receipts\0009-stable-promotion-requested.json') `
            -PathType Leaf)) `
        'Receipt crash did not leave the exact recoverable r9 orphan.'
    [void](Invoke-StablePromotion `
        -ScriptPath $orchestrator `
        -RepoRoot $sourceRepo `
        -PlanPath $planPath `
        -StateRoot $receiptCrashState `
        -ExpectedHeadSha256 $receiptCrashExchange.R8HeadSha256)
    [void](Assert-R9NoGoState `
        -StateRoot $receiptCrashState `
        -StateSchemaPath $stateSchemaPath)

    $tamperState = Join-Path $fixtureRoot 'tamper-state'
    Copy-State -Source $baselineState -Destination $tamperState
    $tamperExchange = New-PromotionExchange `
        -ScriptPath $orchestrator `
        -RepoRoot $sourceRepo `
        -PlanPath $planPath `
        -StateRoot $tamperState `
        -PromotionRoot (Join-Path $fixtureRoot 'tamper-promotion') `
        -ResponsePath (Join-Path $evidenceRoot 'tamper-response.json') `
        -Signer $feedSigner
    $tamperedResponse = Read-Json -Path $tamperExchange.ResponsePath
    $signatureText = [string]$tamperedResponse.authentication.value
    $tamperedResponse.authentication.value =
        $(if ($signatureText[0] -ceq 'A') { 'B' } else { 'A' }) +
            $signatureText.Substring(1)
    Write-CanonicalJson `
        -Path $tamperExchange.ResponsePath `
        -Value $tamperedResponse
    [void](Invoke-StablePromotion `
        -ScriptPath $orchestrator `
        -RepoRoot $sourceRepo `
        -PlanPath $planPath `
        -StateRoot $tamperState `
        -PromotionRoot $tamperExchange.PromotionRoot `
        -ResponsePath $tamperExchange.ResponsePath `
        -ExpectedHeadSha256 $tamperExchange.R8HeadSha256 `
        -ExpectFailure)
    Assert-True `
        ((Get-StateTreeSnapshot -Path $tamperState) -ceq
            $tamperExchange.StateBefore) `
        'Tampered Stable authorization changed production state.'

    $digestState = Join-Path $fixtureRoot 'digest-state'
    Copy-State -Source $baselineState -Destination $digestState
    $digestExchange = New-PromotionExchange `
        -ScriptPath $orchestrator `
        -RepoRoot $sourceRepo `
        -PlanPath $planPath `
        -StateRoot $digestState `
        -PromotionRoot (Join-Path $fixtureRoot 'digest-promotion') `
        -ResponsePath (Join-Path $evidenceRoot 'digest-response.json') `
        -Signer $feedSigner `
        -MutateResponse {
            param($response)
            $response.requestSha256 = 'f' * 64
        }
    [void](Invoke-StablePromotion `
        -ScriptPath $orchestrator `
        -RepoRoot $sourceRepo `
        -PlanPath $planPath `
        -StateRoot $digestState `
        -PromotionRoot $digestExchange.PromotionRoot `
        -ResponsePath $digestExchange.ResponsePath `
        -ExpectedHeadSha256 $digestExchange.R8HeadSha256 `
        -ExpectFailure)
    Assert-True `
        ((Get-StateTreeSnapshot -Path $digestState) -ceq
            $digestExchange.StateBefore) `
        'Validly signed response with a wrong request digest changed state.'

    $expiredState = Join-Path $fixtureRoot 'expired-state'
    Copy-State -Source $baselineState -Destination $expiredState
    $expiredSource = Get-ProductionReleaseState `
        -StateRoot $expiredState `
        -StateSchemaPath $stateSchemaPath
    $expiredPromotionRoot = Join-Path $fixtureRoot 'expired-promotion'
    [void](New-ProductionFeedPromotionRequest `
        -PromotionRoot $expiredPromotionRoot `
        -SourceStateRoot $expiredState `
        -CandidateRoot (Join-Path $expiredState `
            'imports\stable-signed-candidate.v1\candidate') `
        -ExposureRing stable `
        -ExpectedChannelHead ([ordered]@{ state = 'missing' }) `
        -ExpectedJournalHead ([ordered]@{ state = 'missing' }) `
        -ExpectedFeedIdentitySha256 $script:PublicationFeedIdentitySha256 `
        -ExpectedSourcePlanSha256 ([string]$expiredSource.Identity.planSha256) `
        -ExpectedSourceIdentitySha256 ([string]$expiredSource.IdentitySha256) `
        -ExpectedSourceHeadSha256 ([string]$expiredSource.HeadSha256) `
        -ResponseLifetimeMinutes 1 `
        -NowUtc ([DateTimeOffset]::UtcNow.AddMinutes(-2)))
    $expiredBefore = Get-StateTreeSnapshot -Path $expiredState
    [void](Invoke-StablePromotion `
        -ScriptPath $orchestrator `
        -RepoRoot $sourceRepo `
        -PlanPath $planPath `
        -StateRoot $expiredState `
        -PromotionRoot $expiredPromotionRoot `
        -ExpectedHeadSha256 ([string]$expiredSource.HeadSha256) `
        -ExpectFailure `
        -ExpectedMessage 'expired')
    Assert-True `
        ((Get-StateTreeSnapshot -Path $expiredState) -ceq $expiredBefore) `
        'Expired Stable authorization request changed production state.'

    $raceState = Join-Path $fixtureRoot 'race-state'
    Copy-State -Source $baselineState -Destination $raceState
    $raceExchangeA = New-PromotionExchange `
        -ScriptPath $orchestrator `
        -RepoRoot $sourceRepo `
        -PlanPath $planPath `
        -StateRoot $raceState `
        -PromotionRoot (Join-Path $fixtureRoot 'race-promotion-a') `
        -ResponsePath (Join-Path $evidenceRoot 'race-response-a.json') `
        -Signer $feedSigner
    $raceExchangeB = New-PromotionExchange `
        -ScriptPath $orchestrator `
        -RepoRoot $sourceRepo `
        -PlanPath $planPath `
        -StateRoot $raceState `
        -PromotionRoot (Join-Path $fixtureRoot 'race-promotion-b') `
        -ResponsePath (Join-Path $evidenceRoot 'race-response-b.json') `
        -Signer $feedSigner
    $operationId = ([Guid]::Parse(
            [string]$plan.orchestrationId)).ToString('N')
    $stagingPrefix =
        ".ensou-launcher-production-staging-$operationId-stable-feed-promotion-"
    $existingStaging = @(
        Get-ChildItem -LiteralPath $fixtureRoot -Directory -Force `
            -Filter ($stagingPrefix + '*') -ErrorAction SilentlyContinue |
            ForEach-Object { [string]$_.FullName })
    $runningA = $null
    $runningB = $null
    try {
        $runningA = Start-StablePromotionRaceProcess `
            -ScriptPath $orchestrator `
            -RepoRoot $sourceRepo `
            -PlanPath $planPath `
            -StateRoot $raceState `
            -PromotionRoot $raceExchangeA.PromotionRoot `
            -ResponsePath $raceExchangeA.ResponsePath `
            -ExpectedHeadSha256 $raceExchangeA.R8HeadSha256
        $runningB = Start-StablePromotionRaceProcess `
            -ScriptPath $orchestrator `
            -RepoRoot $sourceRepo `
            -PlanPath $planPath `
            -StateRoot $raceState `
            -PromotionRoot $raceExchangeB.PromotionRoot `
            -ResponsePath $raceExchangeB.ResponsePath `
            -ExpectedHeadSha256 $raceExchangeB.R8HeadSha256
        # Cold process startup precedes the unchanged 30-second test-only child gate.
        $racePreparationTimeoutSeconds = 120
        $racePreparationClock = [Diagnostics.Stopwatch]::StartNew()
        $observedReadyFiles = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase)
        Write-Host "STABLE-RACE-PREPARATION-START budgetSeconds=$racePreparationTimeoutSeconds"
        $readyFiles = @()
        $childExitedBeforeContinuation = $false
        do {
            $readyFiles = @(
                Get-ChildItem -LiteralPath $fixtureRoot -Directory -Force `
                    -Filter ($stagingPrefix + '*') `
                    -ErrorAction SilentlyContinue |
                    Where-Object {
                        [string]$_.FullName -notin $existingStaging -and
                            (Test-Path -LiteralPath (Join-Path $_.FullName `
                                    'checkout-admission.ready') -PathType Leaf)
                    } |
                    ForEach-Object {
                        Join-Path $_.FullName 'checkout-admission.ready'
                    })
            foreach ($readyPath in $readyFiles) {
                if ($observedReadyFiles.Add($readyPath)) {
                    Write-Host ("STABLE-RACE-READY ordinal={0} elapsedMs={1}" -f
                        $observedReadyFiles.Count, $racePreparationClock.ElapsedMilliseconds)
                }
            }
            $childExitedBeforeContinuation =
                $runningA.Process.HasExited -or $runningB.Process.HasExited
            if ($readyFiles.Count -lt 2 -and -not $childExitedBeforeContinuation) {
                Start-Sleep -Milliseconds 25
            }
        } while ($readyFiles.Count -lt 2 -and
            -not $childExitedBeforeContinuation -and
            $racePreparationClock.Elapsed.TotalSeconds -lt $racePreparationTimeoutSeconds)
        $racePreparationClock.Stop()
        Write-Host ("STABLE-RACE-PREPARATION-END ready={0} elapsedMs={1} earlyExit={2}" -f
            $readyFiles.Count, $racePreparationClock.ElapsedMilliseconds,
            $childExitedBeforeContinuation)
        if ($readyFiles.Count -ne 2 -or $childExitedBeforeContinuation -or
            $runningA.Process.HasExited -or $runningB.Process.HasExited) {
            $raceDiagnostics = @(
                (Get-StablePromotionRaceProcessDiagnostic `
                    -Label 'A' `
                    -Running $runningA)
                (Get-StablePromotionRaceProcessDiagnostic `
                    -Label 'B' `
                    -Running $runningB)
            )
            throw (
                'Concurrent Stable promotion processes did not both reach the pre-writer gate: ' +
                ($raceDiagnostics | ConvertTo-Json -Compress -Depth 4))
        }
        $script:AssertionCount++
        foreach ($readyPath in $readyFiles) {
            [IO.File]::WriteAllBytes(
                (Join-Path ([IO.Path]::GetDirectoryName($readyPath)) `
                    'checkout-admission.continue'),
                [IO.File]::ReadAllBytes($readyPath))
        }
        $raceResultA = Complete-StablePromotionRaceProcess -Running $runningA
        $runningA = $null
        $raceResultB = Complete-StablePromotionRaceProcess -Running $runningB
        $runningB = $null
        Assert-True `
            (-not ($raceResultA.Output + $raceResultB.Output).Contains(
                'Test-only production checkout admission gate timed out.',
                [StringComparison]::Ordinal)) `
            'An expired test-only rendezvous must not count as the losing CAS writer.'
        $raceExitCodes = @($raceResultA.ExitCode, $raceResultB.ExitCode)
        Assert-True `
            (@($raceExitCodes | Where-Object { $_ -eq 0 }).Count -eq 1 -and
             @($raceExitCodes | Where-Object { $_ -ne 0 }).Count -eq 1) `
            ("Concurrent Stable CAS did not select exactly one writer: A={0} B={1}; {2} {3}" -f
                $raceResultA.ExitCode,
                $raceResultB.ExitCode,
                $raceResultA.Output,
                $raceResultB.Output)
    }
    finally {
        foreach ($running in @($runningA, $runningB)) {
            if ($null -ne $running) {
                try {
                    if (-not $running.Process.HasExited) {
                        $running.Process.Kill($true)
                        [void]$running.Process.WaitForExit(10000)
                    }
                }
                finally {
                    $running.Process.Dispose()
                }
            }
        }
    }
    [void](Assert-R9NoGoState `
        -StateRoot $raceState `
        -StateSchemaPath $stateSchemaPath)

    Write-Output (
        "Launcher Stable promotion orchestration tests passed ({0} assertions; {1} expected failures)." -f
            $script:AssertionCount,
            $script:ExpectedFailureCount)
}
finally {
    $publicationSigner.Dispose()
    $releaseSigner.Dispose()
    $manifestSigner.Dispose()
    $clientSigner.Dispose()
    $feedSigner.Dispose()
    if (Test-Path -LiteralPath $fixtureRoot) {
        $resolvedFixtureRoot = [IO.Path]::GetFullPath($fixtureRoot)
        $resolvedTempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
        if (-not $resolvedFixtureRoot.StartsWith(
                $resolvedTempRoot,
                [StringComparison]::OrdinalIgnoreCase) -or
            [IO.Path]::GetPathRoot($resolvedFixtureRoot) -ceq
                $resolvedFixtureRoot) {
            throw 'Refusing to clean an unexpected Stable promotion fixture path.'
        }
        Remove-Item -LiteralPath $resolvedFixtureRoot -Recurse -Force
    }
}
