#requires -Version 7.2

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$executionModulePath = Join-Path $PSScriptRoot 'WindowsPilotSigningExecution.psm1'
$pilotSigningModulePath = Join-Path $PSScriptRoot 'WindowsPilotSigning.psm1'
$stateModulePath = Join-Path $PSScriptRoot '..\scripts\ProductionReleaseState.psm1'
$contractsModulePath = Join-Path $PSScriptRoot '..\scripts\InstallerSigningContracts.psm1'
$policySchemaPath = Join-Path $PSScriptRoot '..\schemas\windows-pilot-signing-policy-v1.schema.json'
$personalPolicyPath = Join-Path $PSScriptRoot 'windows-pilot-signing-policy.example.json'
$enterprisePolicyPath = Join-Path $PSScriptRoot 'windows-enterprise-pilot-signing-policy.example.json'
$clientAdapterPath = Join-Path $PSScriptRoot 'Invoke-EnterprisePilotClientSigning.ps1'
$installerAdapterPath = Join-Path $PSScriptRoot 'Invoke-EnterprisePilotInstallerSigning.ps1'
$installerSelfCheckModulePath = Join-Path $PSScriptRoot '..\scripts\EnterpriseInstallerProductionPayloadSelfCheck.psm1'
$initializerPath = Join-Path $PSScriptRoot 'Initialize-WindowsPilotResponseSigningKey.ps1'

$executionModule = Microsoft.PowerShell.Core\Import-Module `
    $executionModulePath -Force -PassThru -ErrorAction Stop
Microsoft.PowerShell.Core\Import-Module $contractsModulePath -Force -ErrorAction Stop
Microsoft.PowerShell.Core\Import-Module $pilotSigningModulePath -Force -ErrorAction Stop
Microsoft.PowerShell.Core\Import-Module $stateModulePath -Force -ErrorAction Stop

function Assert-True {
    param([Parameter(Mandatory = $true)][bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

function Assert-Fails {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Action,
        [Parameter(Mandatory = $true)][string]$Pattern,
        [Parameter(Mandatory = $true)][string]$Message
    )
    try { & $Action }
    catch {
        if ($_.Exception.Message -notmatch $Pattern) {
            throw "$Message Unexpected failure: $($_.Exception.Message)"
        }
        return
    }
    throw $Message
}

function Assert-SourceOrder {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string[]]$Needles,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $cursor = -1
    foreach ($needle in $Needles) {
        $index = $Source.IndexOf($needle, [StringComparison]::Ordinal)
        Assert-True ($index -gt $cursor) `
            "$Label must import '$needle' after the prior direct dependency."
        $cursor = $index
    }
}

function Test-PolicyJson {
    param([Parameter(Mandatory = $true)][psobject]$Policy)
    $json = $Policy | ConvertTo-Json -Depth 64 -Compress
    return [bool](Microsoft.PowerShell.Utility\Test-Json `
        -Json $json -SchemaFile $policySchemaPath -ErrorAction SilentlyContinue)
}

function Get-TestSha256 {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    return ProductionReleaseState\Get-ProductionSha256Bytes -Bytes $Bytes
}

foreach ($qualifiedCommand in @(
        'ProductionReleaseState\Open-ProductionReleaseInput',
        'InstallerSigningContracts\Get-InstallerSigningObjectSha256',
        'WindowsPilotSigning\Get-WindowsNoFollowPathObservation')) {
    Assert-True ($null -ne (Get-Command $qualifiedCommand `
            -ErrorAction SilentlyContinue)) `
        "Enterprise adapters must expose direct module dependency '$qualifiedCommand'."
}

foreach ($examplePath in @($personalPolicyPath, $enterprisePolicyPath)) {
    $json = [IO.File]::ReadAllText($examplePath, [Text.Encoding]::UTF8)
    Assert-True `
        ([bool](Microsoft.PowerShell.Utility\Test-Json `
            -Json $json -SchemaFile $policySchemaPath -ErrorAction Stop)) `
        "$examplePath must satisfy the strict two-device policy schema."
    $example = $json | ConvertFrom-Json -Depth 64
    Assert-True ([string]$example.executionAdmission -ceq 'NO_GO_EXAMPLE') `
        "$examplePath must remain non-executable."
}

$enterprisePolicy = [IO.File]::ReadAllText(
    $enterprisePolicyPath, [Text.Encoding]::UTF8) | ConvertFrom-Json -Depth 64
$enterprisePolicy.executionAdmission = 'ENTERPRISE_PILOT_SIGNING'
Assert-True (Test-PolicyJson -Policy $enterprisePolicy) `
    'EnterpriseTwoDevice must admit only the Enterprise execution token.'
$crossLanePolicy = [IO.File]::ReadAllText(
    $enterprisePolicyPath, [Text.Encoding]::UTF8) | ConvertFrom-Json -Depth 64
$crossLanePolicy.executionAdmission = 'PERSONAL_PILOT_SIGNING'
Assert-True (-not (Test-PolicyJson -Policy $crossLanePolicy)) `
    'EnterpriseTwoDevice must reject the Personal execution token at schema import.'
$bothInstallerKeys = [IO.File]::ReadAllText(
    $enterprisePolicyPath, [Text.Encoding]::UTF8) | ConvertFrom-Json -Depth 64
$bothInstallerKeys.responseKeys | Add-Member `
    -NotePropertyName personalInstallerSigning `
    -NotePropertyValue $bothInstallerKeys.responseKeys.enterpriseInstallerSigning
Assert-True (-not (Test-PolicyJson -Policy $bothInstallerKeys)) `
    'Enterprise policy must reject the Personal Installer response-key role.'

$lane = WindowsPilotSigningExecution\Assert-WindowsPilotPolicyLane `
    -Policy $enterprisePolicy `
    -ExpectedExecutionAdmission 'ENTERPRISE_PILOT_SIGNING' `
    -ExpectedProfile 'EnterpriseTwoDevice'
Assert-True (
    [string]$lane.InstallerKeyProperty -ceq 'enterpriseInstallerSigning' -and
    [string]$lane.InstallerPurpose -ceq 'installer-signing-response') `
    'Enterprise lane must resolve the isolated Enterprise Installer response role.'
Assert-Fails `
    -Action {
        [void](WindowsPilotSigningExecution\Assert-WindowsPilotPolicyLane `
            -Policy $enterprisePolicy `
            -ExpectedExecutionAdmission 'PERSONAL_PILOT_SIGNING' `
            -ExpectedProfile 'PersonalTwoDevice')
    } `
    -Pattern 'outside the requested lane' `
    -Message 'Enterprise policy must never enter the Personal signing lane.'
$profileAdmissionMismatch = [pscustomobject]@{
    profile = 'EnterpriseTwoDevice'
    executionAdmission = 'PERSONAL_PILOT_SIGNING'
}
Assert-Fails `
    -Action {
        [void](WindowsPilotSigningExecution\Assert-WindowsPilotPolicyLane `
            -Policy $profileAdmissionMismatch)
    } `
    -Pattern 'not the same lane' `
    -Message 'Profile/admission mismatch must fail closed.'

foreach ($scriptPath in @($clientAdapterPath, $installerAdapterPath, $initializerPath)) {
    $tokens = $null
    $errors = $null
    [void][Management.Automation.Language.Parser]::ParseFile(
        [IO.Path]::GetFullPath($scriptPath), [ref]$tokens, [ref]$errors)
    Assert-True ($errors.Count -eq 0) "$scriptPath must parse without errors."
    $source = [IO.File]::ReadAllText($scriptPath)
    foreach ($forbidden in @(
            '(?i)\bStart-Process\b',
            '(?i)\bNew-SelfSignedCertificate\b',
            '(?i)\bImport-Certificate\b',
            '(?i)\bInvoke-(?:WebRequest|RestMethod)\b',
            '(?i)\b(?:HttpClient|WebClient)\b')) {
        Assert-True ($source -notmatch $forbidden) `
            "$scriptPath must not create certificates, alter trust, use shell-style process launch, or call the network."
    }
}

foreach ($scriptPath in @($clientAdapterPath, $installerAdapterPath)) {
    $source = [IO.File]::ReadAllText($scriptPath)
    foreach ($required in @(
            'ENTERPRISE_PILOT_SIGNING', 'EnterpriseTwoDevice',
            'ExpectedExecutionAdmission', 'ExpectedProfile',
            'Get-WindowsNoFollowPathObservation',
            'Assert-ProductionReleaseInputStillLocked', 'RFC3161')) {
        Assert-True ($source.Contains($required)) `
            "$scriptPath must retain strict Enterprise boundary '$required'."
    }
}
$initializerSource = [IO.File]::ReadAllText($initializerPath)
foreach ($required in @(
        'EnterpriseInstallerSigningResponse', 'EnterpriseTwoDevice',
        'installer-signing-response',
        'Installer response-key purpose must match its exact two-device Pilot profile.')) {
    Assert-True ($initializerSource.Contains($required)) `
        "Response-key initializer must retain Enterprise isolation '$required'."
}

$clientSource = [IO.File]::ReadAllText($clientAdapterPath)
Assert-SourceOrder `
    -Source $clientSource `
    -Needles @(
        '$executionModulePath -Force -ErrorAction Stop',
        '$contractsModulePath -Force -ErrorAction Stop',
        '$pilotSigningModulePath -Force -ErrorAction Stop',
        '$stateModulePath -Force -ErrorAction Stop') `
    -Label 'Enterprise client adapter'
foreach ($required in @(
        'client-signing.v1', 'signing-request.v1.json',
        'Ensou.Dsh.Enterprise.Bootstrapper.exe',
        'Ensou.Dsh.Enterprise.Launcher.exe',
        'Ensou.Dsh.Enterprise.ClientBootstrapper.exe',
        'Ensou.Dsh.Enterprise.Maintenance.exe',
        'Get-ExactPeAuthenticodeEvidence',
        'LegacyCounterSignaturePresent')) {
    Assert-True ($clientSource.Contains($required)) `
        "Enterprise client adapter must retain '$required'."
}
$installerSource = [IO.File]::ReadAllText($installerAdapterPath)
Assert-SourceOrder `
    -Source $installerSource `
    -Needles @(
        '$executionModulePath -Force -ErrorAction Stop',
        '$contractsModulePath -Force -ErrorAction Stop',
        '$pilotSigningModulePath -Force -ErrorAction Stop',
        '$stateModulePath -Force -ErrorAction Stop') `
    -Label 'Enterprise Installer adapter'
foreach ($required in @(
        'installer-signing.v2', 'installer-signing-request.v2.json',
        'Ensou.Dsh.Enterprise.Installer.exe',
        'trusted-build-evidence.v1.json',
        'Assert-InstallerSigningRequestContract',
        'Assert-InstallerSigningResponseContract',
        'Assert-SignedInstallerAuthenticode',
        'EnterpriseInstallerProductionPayloadSelfCheck.psm1',
        'EnterpriseInstallerProductionPayloadSelfCheck\Invoke-EnterpriseInstallerProductionPayloadSelfCheck',
        '-ExpectedSignerCertificateSha256')) {
    Assert-True ($installerSource.Contains($required)) `
        "Enterprise Installer adapter must retain '$required'."
}
$installerSelfCheckSource = [IO.File]::ReadAllText($installerSelfCheckModulePath)
foreach ($required in @(
        '--production-payload-self-check',
        'ProductionBoundedProcess\Invoke-ProductionBoundedProcessCapture',
        'UseShellExecute = $false', 'CreateNoWindow = $true',
        'Get-ExactPeAuthenticodeEvidence',
        'Assert-ProductionReleaseInputStillLocked')) {
    Assert-True ($installerSelfCheckSource.Contains($required)) `
        "Shared Enterprise Installer self-check must retain '$required'."
}
Assert-True (-not $installerSelfCheckSource.Contains('WindowsPilotSigningExecution')) `
    'Shared Enterprise Installer self-check must not depend on Pilot signing keys or execution.'

# Exercise the Enterprise transaction boundary with synthetic bytes and injected
# operations only. This copies bytes and appends a test marker; it never creates
# or uses a key/certificate, invokes SignTool, or contacts a timestamp service.
$controlledRoot = [IO.Path]::GetFullPath((Join-Path `
    $PSScriptRoot '..\..\.test-out\enterprise-pilot-signing-lane'))
if (-not (Test-Path -LiteralPath $controlledRoot)) {
    [void][IO.Directory]::CreateDirectory($controlledRoot)
}
$runRoot = Join-Path $controlledRoot ('run-' + [Guid]::NewGuid().ToString('N'))
$requestRoot = Join-Path $runRoot 'requests'
$transactionRoot = Join-Path $runRoot 'transactions'
$outputRoot = Join-Path $runRoot 'responses'
[void][IO.Directory]::CreateDirectory($requestRoot)
[void][IO.Directory]::CreateDirectory($transactionRoot)
[void][IO.Directory]::CreateDirectory($outputRoot)
$policyInput = $null
try {
    $policyPath = Join-Path $runRoot 'enterprise-policy.bin'
    [IO.File]::WriteAllBytes($policyPath, [byte[]](1..32))
    $policyInput = ProductionReleaseState\Open-ProductionReleaseInput `
        -Path $policyPath -Label 'Synthetic Enterprise policy' -MaximumBytes 1KB
    $policyInput | Add-Member -NotePropertyName Value -NotePropertyValue (
        [pscustomobject]@{
            profile = 'EnterpriseTwoDevice'
            executionAdmission = 'ENTERPRISE_PILOT_SIGNING'
            roots = [pscustomobject]@{
                requestRoot = $requestRoot
                transactionRoot = $transactionRoot
                outputRoot = $outputRoot
            }
            authenticode = [pscustomobject]@{
                certificateSha256 = ('a' * 64)
            }
            tsa = [pscustomobject]@{
                canonicalUriSha256 = ('9' * 64)
                trustedSignerChains = @([pscustomobject]@{
                        chainId = 'enterprise-test-tsa'
                        validFromUtc = '2026-01-01T00:00:00Z'
                        validUntilUtc = '2027-01-01T00:00:00Z'
                        leafCertificateSha256 = ('b' * 64)
                        intermediateCertificateSha256s = @(('c' * 64))
                        rootCertificateSha256 = ('d' * 64)
                    })
            }
        })
    $whatIfKeyName = 'ensou-dsh-enterprise-response-whatif-' +
        [Guid]::NewGuid().ToString('N')
    $whatIfKeyId = 'enterprise-response-whatif-' +
        [Guid]::NewGuid().ToString('N')
    $whatIfPublicPath = Join-Path $runRoot 'enterprise-response-public.json'
    & $initializerPath `
        -PilotOnlyConfirmation `
            'I UNDERSTAND THIS CREATES A NON-EXPORTABLE PILOT RESPONSE KEY' `
        -PilotProfile EnterpriseTwoDevice `
        -Purpose EnterpriseInstallerSigningResponse `
        -KeyName $whatIfKeyName `
        -KeyId $whatIfKeyId `
        -OutputPath $whatIfPublicPath `
        -WhatIf
    $softwareKsp =
        [Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider
    Assert-True (-not (Test-Path -LiteralPath $whatIfPublicPath)) `
        'Enterprise response-key initializer WhatIf must not create public output.'
    Assert-True (-not [Security.Cryptography.CngKey]::Exists(
            $whatIfKeyName, $softwareKsp,
            [Security.Cryptography.CngKeyOpenOptions]::UserKey)) `
        'Enterprise response-key initializer WhatIf must not create a CNG key.'
    Assert-Fails `
        -Action {
            & $initializerPath `
                -PilotOnlyConfirmation `
                    'I UNDERSTAND THIS CREATES A NON-EXPORTABLE PILOT RESPONSE KEY' `
                -PilotProfile EnterpriseTwoDevice `
                -Purpose PersonalInstallerSigningResponse `
                -KeyName ('ensou-dsh-cross-lane-whatif-' +
                    [Guid]::NewGuid().ToString('N')) `
                -KeyId 'cross-lane-whatif' `
                -OutputPath (Join-Path $runRoot 'cross-lane-public.json') `
                -WhatIf
        } `
        -Pattern 'purpose must match its exact two-device Pilot profile' `
        -Message 'Enterprise profile must reject the Personal Installer response-key role.'
    $sourcePath = Join-Path $requestRoot 'Ensou.Dsh.Enterprise.Installer.exe'
    [byte[]]$sourceBytes = 1..255
    [IO.File]::WriteAllBytes($sourcePath, $sourceBytes)
    $sourceSha256 = Get-TestSha256 -Bytes $sourceBytes
    $peSha256 = ('e' * 64)
    $target = [pscustomobject]@{
        role = 'installer'
        fileName = 'Ensou.Dsh.Enterprise.Installer.exe'
        sourcePath = $sourcePath
        sizeBytes = $sourceBytes.Length
        sha256 = $sourceSha256
        peContentSha256 = $peSha256
    }
    $operations = @{
        PolicyInput = $policyInput
        Targets = @($target)
        ResponseFileName = 'enterprise-response.json'
        ResponseBuilder = {
            param([object[]]$evidence, [string]$transactionPath)
            return [ordered]@{
                schemaVersion = 1
                responseType = 'synthetic-enterprise-signing-test'
                signedFileSha256 = [string]$evidence[0].SignedFileSha256
            }
        }
        ResponseValidator = {
            param($responseInput, [object[]]$evidence)
            return [string]$responseInput.Value.signedFileSha256 -ceq
                [string]$evidence[0].SignedFileSha256
        }
        CertificateAdmissionOperation = {
            param($policy)
            return [IO.MemoryStream]::new()
        }
        SourceAdmissionOperation = {
            param($descriptor, $item)
            return [string]$item.peContentSha256
        }
        SignOperation = {
            param($policy, $targetPath)
            $stream = [IO.File]::Open(
                $targetPath, [IO.FileMode]::Append,
                [IO.FileAccess]::Write, [IO.FileShare]::None)
            try {
                [byte[]]$marker = [Text.Encoding]::ASCII.GetBytes(
                    'synthetic-enterprise-signature-marker')
                $stream.Write($marker, 0, $marker.Length)
                $stream.Flush($true)
            }
            finally { $stream.Dispose() }
            return [pscustomobject]@{ exitCode = 0; synthetic = $true }
        }
        EvidenceOperation = {
            param($policy, $targetPath, $item)
            $input = ProductionReleaseState\Open-ProductionReleaseInput `
                -Path $targetPath -Label 'Synthetic Enterprise signed copy' `
                -MaximumBytes 1MB
            try {
                return [pscustomobject]@{
                    FileName = $input.FileName
                    SizeBytes = $input.SizeBytes
                    SignedFileSha256 = $input.Sha256
                    PeContentSha256 = [string]$item.peContentSha256
                    SignerCertificateSha256 = [string]$policy.authenticode.certificateSha256
                    PrimarySignerCount = 1
                    TimestampProtocol = 'RFC3161'
                    TimestampSignerCertificateSha256 = ('b' * 64)
                    TimestampUtc = '2026-09-01T00:00:00Z'
                    LegacyCounterSignaturePresent = $false
                    TsaTrustEvidence = [pscustomobject]@{
                        fileName = $input.FileName
                        signedFileSha256 = $input.Sha256
                        chainId = 'enterprise-test-tsa'
                        timestampUtc = '2026-09-01T00:00:00Z'
                        leafCertificateSha256 = ('b' * 64)
                        intermediateCertificateSha256s = @(('c' * 64))
                        rootCertificateSha256 = ('d' * 64)
                        timeStampingEkuOid = '1.3.6.1.5.5.7.3.8'
                        timeStampingEkuExact = $true
                        timeStampingEkuCritical = $true
                        chainApplicationPolicyOid = '1.3.6.1.5.5.7.3.8'
                        chainTrusted = $true
                        revocationMode = 'Online'
                        revocationFlag = 'ExcludeRoot'
                        onlineRevocationChecked = $true
                        policyTsaUriSha256 = ('9' * 64)
                    }
                }
            }
            finally { $input.Stream.Dispose() }
        }
    }
    $rejectedOutput = Join-Path $outputRoot 'personal-cross-lane'
    Assert-Fails `
        -Action {
            & $executionModule {
                param($parameters)
                Invoke-WindowsPilotSigningTransactionCore @parameters
            } ($operations + @{
                    FinalOutputPath = $rejectedOutput
                    ExpectedExecutionAdmission = 'PERSONAL_PILOT_SIGNING'
                    ExpectedProfile = 'PersonalTwoDevice'
                })
        } `
        -Pattern 'outside the requested lane' `
        -Message 'Enterprise transaction must reject a Personal expected lane before mutation.'
    Assert-True (-not (Test-Path -LiteralPath $rejectedOutput)) `
        'Cross-lane rejection must not create output.'
    Assert-True (@(Get-ChildItem -LiteralPath $transactionRoot -Force).Count -eq 0) `
        'Cross-lane rejection must not create a transaction.'

    $committedOutput = Join-Path $outputRoot 'enterprise-committed'
    $result = & $executionModule {
        param($parameters)
        Invoke-WindowsPilotSigningTransactionCore @parameters
    } ($operations + @{
            FinalOutputPath = $committedOutput
            ExpectedExecutionAdmission = 'ENTERPRISE_PILOT_SIGNING'
            ExpectedProfile = 'EnterpriseTwoDevice'
        })
    Assert-True ([string]$result.status -ceq 'COMMITTED') `
        'Synthetic Enterprise signing transaction must atomically commit.'
    Assert-True ($result.signedFileCount -eq 1 -and
        @($result.tsaTrustEvidence).Count -eq 1) `
        'Committed Enterprise transaction must retain one exact RFC3161 TSA proof.'
    Assert-True ((Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash.ToLowerInvariant() -ceq
        $sourceSha256) 'Enterprise transaction must not mutate its source bytes.'
    Assert-True (Test-Path -LiteralPath (Join-Path `
        $committedOutput 'enterprise-response.json')) `
        'Committed Enterprise transaction must contain its authenticated response artifact.'
    Assert-True (@(Get-ChildItem -LiteralPath $transactionRoot -Force).Count -eq 0) `
        'Atomic Enterprise commit must leave no transaction directory.'
}
finally {
    if ($null -ne $policyInput) { $policyInput.Stream.Dispose() }
    if (Test-Path -LiteralPath $runRoot) {
        $runItem = Get-Item -LiteralPath $runRoot -Force
        if (-not $runItem.PSIsContainer -or
            ($runItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            [IO.Path]::GetDirectoryName($runItem.FullName) -cne $controlledRoot) {
            throw 'Refusing Enterprise test cleanup outside its exact ordinary run directory.'
        }
        [IO.Directory]::Delete($runItem.FullName, $true)
    }
}

Write-Output 'ENTERPRISE-PILOT-SIGNING-LANE-PASS'
Write-Output 'ENTERPRISE-CLIENT-AND-INSTALLER-CONTRACTS-PASS'
Write-Output 'NO-REAL-KEY-CERTIFICATE-SIGNING-TRUST-INSTALL-TSA-OR-NETWORK-PERFORMED'
