#requires -Version 7.2
[CmdletBinding()]
param(
    # This must be the create-only bundle emitted by the Linux attest-publication command.
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$BundleRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$stateModulePath = Join-Path $PSScriptRoot 'ProductionReleaseState.psm1'
$resultModulePath = Join-Path $PSScriptRoot 'EnterpriseStablePublicationResult.psm1'
Microsoft.PowerShell.Core\Import-Module $stateModulePath -Force
Microsoft.PowerShell.Core\Import-Module $resultModulePath -Force

function Assert-TestTrue {
    param([bool]$Value, [string]$Message)
    if (-not $Value) { throw $Message }
}

function Assert-Rejected {
    param([scriptblock]$Action, [string]$ExpectedMessage, [string]$Message)
    try { & $Action }
    catch {
        if ($_.Exception.Message -notlike "*$ExpectedMessage*") {
            throw "$Message Expected error containing '$ExpectedMessage'; got '$($_.Exception.Message)'."
        }
        return
    }
    throw $Message
}

function ConvertTo-TestBase64Url {
    param([byte[]]$Bytes)
    [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Copy-TestValue {
    param($Value)
    $Value | ConvertTo-Json -Depth 64 | ConvertFrom-Json -Depth 64 -DateKind String
}

function New-TestTrust {
    param([string]$Purpose)
    $signer = [Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve+NamedCurves]::nistP256)
    try {
        $point = $signer.ExportParameters($false).Q
        return [pscustomobject][ordered]@{
            algorithm = 'ES256'
            keyId = ('test-' + [Guid]::NewGuid().ToString('N').Substring(0, 12))
            purpose = $Purpose
            x = ConvertTo-TestBase64Url $point.X
            y = ConvertTo-TestBase64Url $point.Y
        }
    }
    finally { $signer.Dispose() }
}

function New-SyntheticPlanForDecoder {
    param($PublicationTrust)
    # This plan only supplies distinct public keys needed to exercise the decoder.
    # It is deliberately not presented as an r9-derived production plan.
    return [pscustomobject][ordered]@{
        schemaVersion = 2
        edition = 'Enterprise'
        targetChannel = 'stable'
        stablePublicationTrust = $PublicationTrust
        releaseManifestTrust = New-TestTrust 'release-manifest-signing'
        externalResponseTrusts = [pscustomobject][ordered]@{
            clientSigning = New-TestTrust 'client-signing-response'
            manifestPublishing = New-TestTrust 'manifest-publishing-response'
            installerSigning = New-TestTrust 'installer-signing-response'
            feedPromotion = New-TestTrust 'feed-promotion-response'
        }
    }
}

function Open-TestAdmission {
    param([string]$Path)
    EnterpriseStablePublicationResult\Open-EnterpriseStablePublicationResult -BundleRoot $Path
}

function Close-TestAdmission {
    param($Admission)
    if ($null -ne $Admission) {
        EnterpriseStablePublicationResult\Close-EnterpriseStablePublicationResult $Admission
    }
}

function New-TamperCopy {
    param([string]$Source, [string]$Destination)
    [void][IO.Directory]::CreateDirectory($Destination)
    foreach ($item in Get-ChildItem -LiteralPath $Source -Force) {
        Copy-Item -LiteralPath $item.FullName -Destination $Destination -Recurse
    }
}

function Assert-SafeScratchRoot {
    param([string]$Path, [string]$TempRoot)
    $fullPath = [IO.Path]::GetFullPath($Path)
    $fullTemp = [IO.Path]::GetFullPath($TempRoot).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    if (-not $fullPath.StartsWith($fullTemp, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Verifier scratch path escapes the process temporary directory.'
    }
    foreach ($item in @(Get-Item -LiteralPath $fullPath -Force) + @(Get-ChildItem -LiteralPath $fullPath -Force -Recurse)) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Verifier scratch tree contains a reparse point and will not be cleaned.'
        }
    }
}

$fullBundleRoot = [IO.Path]::GetFullPath($BundleRoot)
if (-not (Test-Path -LiteralPath $fullBundleRoot -PathType Container)) {
    throw "Linux publication bundle does not exist: $fullBundleRoot"
}

$admission = $null
$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$scratch = Join-Path $tempRoot ('ensou-r10-publication-test-' + [Guid]::NewGuid().ToString('N'))
try {
    [void][IO.Directory]::CreateDirectory($scratch)
    Assert-SafeScratchRoot -Path $scratch -TempRoot $tempRoot
    $admission = Open-TestAdmission $fullBundleRoot
    $context = $admission.Values['context.json']
    $plan = New-SyntheticPlanForDecoder -PublicationTrust $context.trust
    $expectedContext = Copy-TestValue $context

    # This is the cross-language positive: C# produced payload/signature/eight raw files;
    # PowerShell decodes and verifies all in-bundle bindings.  ExpectedContext is the signed
    # context itself, so r9 state reconstruction is intentionally outside this decoder test.
    EnterpriseStablePublicationResult\Assert-EnterpriseStablePublicationBinding `
        -Admission $admission -ExpectedContext $expectedContext -Plan $plan
    Write-Output 'PASS real Linux bundle: PowerShell decoder verifies C# P1363 low-S signature and 8-file binding.'

    $observed = ProductionReleaseState\ConvertFrom-ProductionUtc `
        -Value $admission.Statement.observedAtUtc -Label 'test publication observation'
    EnterpriseStablePublicationResult\Assert-EnterpriseStablePublicationBinding `
        -Admission $admission -ExpectedContext $expectedContext -Plan $plan -Fresh `
        -NowUtc $observed.AddSeconds(1)
    Write-Output 'PASS fresh first admission accepted at observed plus one second.'

    $wrongTrustPlan = Copy-TestValue $plan
    $wrongTrustPlan.stablePublicationTrust.keyId = 'wrong-publication-trust'
    Assert-Rejected {
        EnterpriseStablePublicationResult\Assert-EnterpriseStablePublicationBinding `
            -Admission $admission -ExpectedContext $expectedContext -Plan $wrongTrustPlan
    } 'Publication envelope trust or signature purpose differs' 'Decoder accepted a bundle under the wrong pinned publication trust.'
    Write-Output 'PASS wrong trust key ID rejected.'

    $wrongPointPlan = Copy-TestValue $plan
    $wrongPoint = New-TestTrust 'stable-public-promotion-attestation'
    $wrongPointPlan.stablePublicationTrust.x = $wrongPoint.x
    $wrongPointPlan.stablePublicationTrust.y = $wrongPoint.y
    Assert-Rejected {
        EnterpriseStablePublicationResult\Assert-EnterpriseStablePublicationBinding `
            -Admission $admission -ExpectedContext $expectedContext -Plan $wrongPointPlan
    } 'Stable publication signature is invalid' 'Decoder accepted the right key ID with a different P-256 point.'
    Write-Output 'PASS wrong trust P-256 point rejected.'

    $wrongContext = Copy-TestValue $expectedContext
    $wrongContext.candidateManifestSha256 = 'b' * 64
    Assert-Rejected {
        EnterpriseStablePublicationResult\Assert-EnterpriseStablePublicationBinding `
            -Admission $admission -ExpectedContext $wrongContext -Plan $plan
    } 'Publication immutable context candidateManifestSha256 differs from r9' 'Decoder accepted a bundle under the wrong immutable context.'
    Write-Output 'PASS wrong context rejected.'

    $expires = ProductionReleaseState\ConvertFrom-ProductionUtc `
        -Value $admission.Statement.expiresAtUtc -Label 'test publication expiry'
    Assert-Rejected {
        EnterpriseStablePublicationResult\Assert-EnterpriseStablePublicationBinding `
            -Admission $admission -ExpectedContext $expectedContext -Plan $plan -Fresh `
            -NowUtc $expires.AddSeconds(1)
    } 'Publication attestation is stale, future dated or outside its lifetime bound' 'Decoder accepted an expired first r10 admission.'
    Write-Output 'PASS expired first admission rejected.'

    # Historic verification intentionally does not apply a freshness window: receipt/hash replay
    # is the state machine's responsibility.  This must remain valid after the 10-minute window.
    EnterpriseStablePublicationResult\Assert-EnterpriseStablePublicationBinding `
        -Admission $admission -ExpectedContext $expectedContext -Plan $plan `
        -NowUtc $expires.AddDays(1)
    Write-Output 'PASS historical expiry does not invalidate an already authenticated bundle.'
    Close-TestAdmission $admission
    $admission = $null

    $tamperedPayloadRoot = Join-Path $scratch 'payload'
    New-TamperCopy -Source $fullBundleRoot -Destination $tamperedPayloadRoot
    $envelopePath = Join-Path $tamperedPayloadRoot 'publication-result.v1.json'
    $envelope = Get-Content -Raw -LiteralPath $envelopePath | ConvertFrom-Json -Depth 32 -DateKind String
    $payloadText = [Text.UTF8Encoding]::new($false, $true).GetString(
        [Convert]::FromBase64String(($envelope.payload.Replace('-', '+').Replace('_', '/') + ('=' * ((4 - $envelope.payload.Length % 4) % 4)))))
    $changedPayloadText = $payloadText -replace '"observedAtUtc"\s*:\s*"([0-9])', '"observedAtUtc": "9'
    Assert-TestTrue ($changedPayloadText -cne $payloadText) 'Could not construct signature-preserving payload tamper test.'
    $envelope.payload = ConvertTo-TestBase64Url ([Text.UTF8Encoding]::new($false, $true).GetBytes($changedPayloadText))
    [IO.File]::WriteAllText($envelopePath, ($envelope | ConvertTo-Json -Depth 32 -Compress), [Text.UTF8Encoding]::new($false))
    $tampered = Open-TestAdmission $tamperedPayloadRoot
    try {
        Assert-Rejected {
            EnterpriseStablePublicationResult\Assert-EnterpriseStablePublicationBinding `
                -Admission $tampered -ExpectedContext $expectedContext -Plan $plan
        } 'Stable publication signature is invalid' 'Decoder accepted a payload changed without a replacement signature.'
    }
    finally { Close-TestAdmission $tampered }
    Write-Output 'PASS signed payload tamper rejected.'

    $tamperedEvidenceRoot = Join-Path $scratch 'evidence'
    New-TamperCopy -Source $fullBundleRoot -Destination $tamperedEvidenceRoot
    $evidenceRoot = Join-Path $tamperedEvidenceRoot 'evidence'
    $contextPath = Join-Path $evidenceRoot 'context.json'
    $contextBytes = [IO.File]::ReadAllBytes($contextPath)
    $contextBytes[0] = $contextBytes[0] -bxor 1
    [IO.File]::WriteAllBytes($contextPath, $contextBytes)
    Assert-Rejected { Open-TestAdmission $tamperedEvidenceRoot } 'Publication context.json raw bytes differ' 'Decoder accepted evidence bytes inconsistent with the signed statement.'
    Write-Output 'PASS evidence tamper rejected.'
}
finally {
    Close-TestAdmission $admission
    if (Test-Path -LiteralPath $scratch) {
        Assert-SafeScratchRoot -Path $scratch -TempRoot $tempRoot
        Remove-Item -LiteralPath $scratch -Recurse -Force
    }
}
