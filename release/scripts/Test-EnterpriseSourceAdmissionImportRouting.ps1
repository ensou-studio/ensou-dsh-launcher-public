#requires -Version 7.2
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Focused routing regression, not a production publisher or device acceptance.
# Execute the actual import function AST and real source binding, schema, file
# locks, hashes and r5 ES256 verification. The original organization signature
# is a shape-only fixture: compiled organization-trust verification has its own
# C# tests. Stop at a write spy before the large candidate import begins.
$modulePath = Join-Path $PSScriptRoot 'ProductionReleaseState.psm1'
$invokePath = Join-Path $PSScriptRoot 'Invoke-LauncherProductionRelease.ps1'
Import-Module $modulePath -Force
$manifestResponseSchemaPath = Join-Path $PSScriptRoot '..\schemas\launcher-manifest-publishing-response-v1.schema.json'
function Assert-Test([bool]$Condition, [string]$Message) { if (-not $Condition) { throw "FAIL: $Message" } }
function B64([byte[]]$Bytes) { [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+','-').Replace('/','_') }
function Json-Bytes($Value) { return ,(ProductionReleaseState\ConvertTo-ProductionJsonBytes -Value $Value) }
function Sha([byte[]]$Bytes) { ProductionReleaseState\Get-ProductionSha256Bytes -Bytes $Bytes }

$tokens = $null; $parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($invokePath, [ref]$tokens, [ref]$parseErrors)
Assert-Test ($parseErrors.Count -eq 0) 'actual orchestrator parses'
function Find-Function([string]$Name) {
    $matches = @($ast.FindAll({ param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $Name
    }.GetNewClosure(), $true))
    Assert-Test ($matches.Count -eq 1) "exactly one actual $Name function"
    return $matches[0].Extent.Text
}
. ([scriptblock]::Create((Find-Function 'Assert-ExactProductionDirectoryInventory')))
$importSource = Find-Function 'Import-PilotSignedCandidateResponse'
$binding = '-Plan $Plan -Request $request -Response $response -StateRoot $StateRoot'
Assert-Test ($importSource.Contains($binding)) 'actual import uses a distinct state input parameter'
$oldSource = $importSource.Replace($binding, '-Plan $Plan -Request $request -Response $response -StateRoot $Root')
Assert-Test ($oldSource -cne $importSource) 'old wrong-root mutation is active'
$callSites = @($ast.FindAll({ param($node)
    $node -is [Management.Automation.Language.CommandAst] -and
    $node.GetCommandName() -ceq 'Import-PilotSignedCandidateResponse'
}, $true))
Assert-Test ($callSites.Count -eq 1) 'exactly one production import call site'
$callerSource = $callSites[0].Extent.Text

$script:writeCalls = [Collections.Generic.List[string]]::new()
function Write-ProductionStateFile {
    param([string]$Path, [byte[]]$Bytes)
    $script:writeCalls.Add($Path)
    throw 'TEST_IMPORT_WRITE_BOUNDARY'
}

$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) ('source-admission-routing-' + [Guid]::NewGuid().ToString('N'))
$key = [Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve+NamedCurves]::nistP256)
try {
    [void][IO.Directory]::CreateDirectory($fixtureRoot)
    $stateRoot = [IO.Directory]::CreateDirectory((Join-Path $fixtureRoot 'actual-state')).FullName
    $externalRoot = [IO.Directory]::CreateDirectory((Join-Path $fixtureRoot 'external-response')).FullName
    $candidateRoot = [IO.Directory]::CreateDirectory((Join-Path $externalRoot 'candidate')).FullName
    $channel = Get-ProductionManifestChannelContract -TargetChannel stable
    $payloadRoot = [IO.Directory]::CreateDirectory((Join-Path $stateRoot ('requests/' + $channel.RequestBundleName + '/payload'))).FullName
    $receiptPath = Join-Path $payloadRoot 'runtime-organization-admission.json'
    $responsePath = Join-Path $externalRoot 'manifest-publishing-response.v1.json'
    $public = $key.ExportParameters($false)
    $trust = [pscustomobject][ordered]@{algorithm='ES256';keyId='routing-r5';purpose='manifest-publishing-response';x=(B64 $public.Q.X);y=(B64 $public.Q.Y)}
    $tag = 'managed-v2026.09.10.1'
    $assets = @(
        [ordered]@{role='archive';githubAssetId=101L;fileName='runtime.zip';sizeBytes=3L;sha256=('1'*64)},
        [ordered]@{role='metadata';githubAssetId=102L;fileName='runtime.json';sizeBytes=4L;sha256=('2'*64)},
        [ordered]@{role='hash-evidence';githubAssetId=103L;fileName='runtime.zip.sha256';sizeBytes=78L;sha256=('3'*64)})
    $source = [ordered]@{repository='ensou/runtime';githubReleaseId=100L;tagName=$tag;targetCommit=('a'*40);immutable=$true;assets=$assets}
    $plan = [pscustomobject][ordered]@{
        schemaVersion=2;edition='Enterprise';targetChannel='stable'
        runtimeCandidate=[pscustomobject][ordered]@{githubRepository='ensou/runtime';githubReleaseCommit=('a'*40);githubReleaseTag=$tag;releaseId=$tag;archive=$assets[0];metadata=$assets[1];hashEvidence=$assets[2]}
        externalResponseTrusts=[pscustomobject]@{manifestPublishing=$trust}
    }
    # Deliberately reorder raw external fields, including every asset and the
    # signature. Existing canonical-signature receipt parsing permits this.
    $reorderedAssets = @($assets | ForEach-Object {
        [ordered]@{sha256=$_.sha256;sizeBytes=$_.sizeBytes;fileName=$_.fileName;githubAssetId=$_.githubAssetId;role=$_.role}
    })
    $receipt = [ordered]@{
        sourceRelease=[ordered]@{assets=$reorderedAssets;immutable=$true;targetCommit=$source.targetCommit;tagName=$tag;githubReleaseId=100L;repository=$source.repository}
        signature=[ordered]@{value=('A'*86);keyId='_existing.runtime';algorithm='ES256'}
        reviewedAtUnixSeconds=[string][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        decision='admitted';sourceRuntimeMetadataSha256=('2'*64);releaseId=$tag
        receiptType='ensou-dsh-runtime-organization-admission';schemaVersion=2
    }
    $receiptBytes = Json-Bytes $receipt
    [IO.File]::WriteAllBytes($receiptPath, $receiptBytes)
    $now = [DateTimeOffset]::UtcNow
    $request = [pscustomobject][ordered]@{
        orchestrationId='12345678-1234-4123-8123-123456789abc';edition='Enterprise';releaseSetId='routing-r5';channel='stable'
        planSha256=('b'*64);requestNonce=('A'*43);baseHeadSha256=('c'*64)
        createdAtUtc=(ConvertTo-ProductionUtc $now.AddMinutes(-5));expiresAtUtc=(ConvertTo-ProductionUtc $now.AddMinutes(30))
        publisherInput=[pscustomobject]@{files=@([pscustomobject][ordered]@{role='edition-runtime-organization-admission';fileName='runtime-organization-admission.json';relativePath='payload/runtime-organization-admission.json';sizeBytes=$receiptBytes.LongLength;sha256=(Sha $receiptBytes)})}
        runtimeSourceReleaseExpectation=(Get-ProductionRuntimeSourceReleaseExpectation -Plan $plan)
    }
    $requestInput = [pscustomobject]@{Value=$request;Sha256=('d'*64)}
    $files = @(
        @('release-manifest','release-set.v2.json'), @('release-public-key','release-public-key.v2.json'),
        @('launcher','launcher.zip'), @('runtime','runtime.zip'), @('plugin-policy','policy.zip')
    ) | ForEach-Object {
        $bytes = [Text.Encoding]::UTF8.GetBytes('fixture-' + $_[1])
        [IO.File]::WriteAllBytes((Join-Path $candidateRoot $_[1]), $bytes)
        [ordered]@{role=$_[0];fileName=$_[1];relativePath=('candidate/'+$_[1]);sizeBytes=$bytes.LongLength;sha256=(Sha $bytes)}
    }
    $response = [ordered]@{
        schemaVersion=1;responseType=$channel.ResponseType;orchestrationId=$request.orchestrationId;edition='Enterprise';releaseSetId=$request.releaseSetId;channel='stable'
        planSha256=$request.planSha256;requestSha256=$requestInput.Sha256;requestNonce=$request.requestNonce;baseHeadSha256=$request.baseHeadSha256
        admissionHeadSha256=('e'*64);admissionRevision=4;requestExpiresAtUtc=$request.expiresAtUtc;completedAtUtc=(ConvertTo-ProductionUtc $now)
        files=@($files);authentication=[ordered]@{algorithm='ES256';keyId=$trust.keyId;purpose=$trust.purpose;payloadType='ensou-dsh-launcher-manifest-publishing-response-authentication-v1';value=('A'*86)}
        runtimeSourceReleaseAdmission=[ordered]@{receiptSha256=(Sha $receiptBytes);sourceRelease=$source}
    }
    function Write-SignedResponse {
        # Retrying fixture signatures until low-S leaves the production
        # canonical payload and strict cryptographic verifier in the path.
        $payload = Get-ProductionReleaseManifestPublishingResponseAuthenticationPayload -Response ([pscustomobject]$response)
        $signed = $false
        for ($attempt=0; $attempt -lt 100; $attempt++) {
            $response.authentication.value = B64 ($key.SignData($payload, [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation))
            try {
                Assert-ProductionReleaseManifestPublishingResponseAuthentication -Response ([pscustomobject]$response) -Trust $trust
                $signed=$true;break
            } catch { if ($_.Exception.Message -notmatch 'low-S|high-S') { throw } }
        }
        Assert-Test $signed 'generated fixture r5 signature verifies under real low-S ES256 gate'
        [IO.File]::WriteAllBytes($responsePath, (Json-Bytes $response))
    }
    Write-SignedResponse

    function Invoke-RoutingCase([string]$Name, [string]$FunctionSource, [bool]$ExpectWriteBoundary, [string]$ExpectedError) {
        . ([scriptblock]::Create($FunctionSource))
        $stagingRoot = [IO.Directory]::CreateDirectory((Join-Path $fixtureRoot $Name)).FullName
        $script:writeCalls.Clear()
        $failure = ''
        # Execute the actual orchestration call AST as well: a caller regression
        # routing StateRoot to bundleStaging.Root must fail this same test.
        $bundleStaging = [pscustomobject]@{Root=$stagingRoot}
        $stateLock = [pscustomobject]@{StateRoot=$stateRoot}
        $manifestRequestInput = $requestInput
        $admissionHeadSha256 = 'e'*64
        $state = [pscustomobject]@{Head=[pscustomobject]@{phase=$channel.RequestPhase}}
        $manifestChannelContract = $channel
        try {
            & ([scriptblock]::Create($callerSource))
        } catch { $failure = $_.Exception.Message }
        Assert-Test ($failure -match $ExpectedError) "$Name fails at its expected boundary; actual: $failure"
        $expectedImport = Join-Path $stagingRoot ('imports/' + $channel.CandidateBundleName)
        if ($ExpectWriteBoundary) {
            Assert-Test ($script:writeCalls.Count -eq 1) "$Name reaches exactly the first import write"
            Assert-Test ($script:writeCalls[0] -ceq (Join-Path $expectedImport 'manifest-publishing-response.v1.json')) "$Name writes only beneath staging, not actual state"
            Assert-Test ([IO.Directory]::Exists((Join-Path $expectedImport 'candidate'))) "$Name reaches actual prewrite directory creation after source proof"
        } else {
            Assert-Test ($script:writeCalls.Count -eq 0) "$Name does not attempt a write before source proof"
            Assert-Test (-not [IO.Directory]::Exists((Join-Path $stagingRoot 'imports'))) "$Name does not create import directories before source proof"
        }
        Assert-Test (-not [IO.Directory]::Exists((Join-Path $stateRoot 'imports'))) "$Name never writes imports to actual state"
        # All original receipt leases must be released on success and failure.
        $exclusive = [IO.File]::Open($receiptPath, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        $exclusive.Dispose()
        Write-Host "PASS: $Name"
    }
    Invoke-RoutingCase 'RED-old-staging-source-lookup' $oldSource $false 'does not exist|Cannot find path|Could not find|cannot find|not found'
    Invoke-RoutingCase 'GREEN-real-state-source-before-staging-write' $importSource $true 'TEST_IMPORT_WRITE_BOUNDARY'

    [IO.File]::WriteAllBytes($receiptPath, [Text.Encoding]::UTF8.GetBytes('tampered'))
    Invoke-RoutingCase 'tampered-state-receipt-no-import-writes' $importSource $false 'RUNTIME_SOURCE_RECEIPT_MISMATCH'
    [IO.File]::WriteAllBytes($receiptPath, $receiptBytes)

    # The outer signature remains genuine and binds these updated raw bytes.
    # A numeric-looking v2 schema string must still fail the real source helper.
    $receipt.schemaVersion = '2'
    $badBytes = Json-Bytes $receipt
    [IO.File]::WriteAllBytes($receiptPath, $badBytes)
    $request.publisherInput.files[0].sizeBytes=$badBytes.LongLength
    $request.publisherInput.files[0].sha256=Sha $badBytes
    $response.runtimeSourceReleaseAdmission.receiptSha256=Sha $badBytes
    Write-SignedResponse
    Invoke-RoutingCase 'string-schemaVersion-no-import-writes' $importSource $false 'RUNTIME_SOURCE_RECEIPT_REJECTED'
    Write-Host 'PASS: actual import AST routing, reordered raw receipt compatibility, existing key token, real r5 ES256, prewrite rejection and lease disposal.'
} finally {
    $key.Dispose()
    # Keep this uniquely created fixture for isolated runner evidence; no user
    # files, certificates, production state, or repository files are removed.
    Write-Host "Fixture: $fixtureRoot"
}
