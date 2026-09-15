#requires -Version 7.2

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$executionModulePath = Join-Path $PSScriptRoot 'WindowsPilotSigningExecution.psm1'
$stateModulePath = Join-Path $PSScriptRoot '..\scripts\ProductionReleaseState.psm1'
$schemaPath = Join-Path $PSScriptRoot '..\schemas\windows-pilot-signing-policy-v1.schema.json'
$examplePath = Join-Path $PSScriptRoot 'windows-pilot-signing-policy.example.json'
$clientAdapterPath = Join-Path $PSScriptRoot 'Invoke-PersonalPilotClientSigning.ps1'
$installerAdapterPath = Join-Path $PSScriptRoot 'Invoke-PersonalPilotInstallerSigning.ps1'
$initializerPath = Join-Path $PSScriptRoot 'Initialize-WindowsPilotResponseSigningKey.ps1'
$executionModule = Microsoft.PowerShell.Core\Import-Module `
    $executionModulePath -Force -PassThru -ErrorAction Stop
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

function Get-TestSha256 {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    return ProductionReleaseState\Get-ProductionSha256Bytes -Bytes $Bytes
}

function New-TestSource {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][byte]$Seed
    )
    $bytes = [byte[]]::new(320)
    for ($index = 0; $index -lt $bytes.Length; $index++) {
        $bytes[$index] = [byte](($Seed + $index) % 251)
    }
    [IO.File]::WriteAllBytes($Path, $bytes)
    return [pscustomobject]@{
        Bytes = $bytes
        Sha256 = Get-TestSha256 -Bytes $bytes
        PeContentSha256 = Get-TestSha256 -Bytes ([byte[]]@($Seed, 1, 2, 3))
    }
}

$exampleText = [IO.File]::ReadAllText($examplePath, [Text.Encoding]::UTF8)
Assert-True `
    ([bool](Microsoft.PowerShell.Utility\Test-Json `
        -Json $exampleText -SchemaFile $schemaPath -ErrorAction Stop)) `
    'Signing policy example must satisfy the strict schema.'
$example = $exampleText | ConvertFrom-Json -Depth 32
Assert-True `
    ([string]$example.executionAdmission -ceq 'NO_GO_EXAMPLE') `
    'Repository signing policy example must remain non-executable.'

$approvedTsa = & $executionModule {
    WindowsPilotSigning\Get-WindowsPilotTsaObservation `
        -TsaUri 'http://timestamp.digicert.com/' `
        -ExpectedTsaUriSha256 `
            '9a44be2d0f498a8bfd2dd1a5e5cced2135e9c4ada9bb5a04eed4c6c5beba1a33'
}
Assert-True `
    ([bool]$approvedTsa.repositoryPinApproved -and
        [bool]$approvedTsa.sha256Matches) `
    'Canonical repository-approved TSA URI must match its actual sha256Matches field.'
$wrongTsaDigest = & $executionModule {
    WindowsPilotSigning\Get-WindowsPilotTsaObservation `
        -TsaUri 'http://timestamp.digicert.com/' `
        -ExpectedTsaUriSha256 ('0' * 64)
}
Assert-True (-not [bool]$wrongTsaDigest.sha256Matches) `
    'An incorrect TSA URI digest must fail the actual sha256Matches observation.'

$syntheticTsaPolicy = [pscustomobject]@{
    trustedSignerChains = @(
        [pscustomobject]@{
            chainId = 'tsa-current'
            validFromUtc = '2026-01-01T00:00:00Z'
            validUntilUtc = '2026-10-01T00:00:00Z'
            leafCertificateSha256 = ('1' * 64)
            intermediateCertificateSha256s = @(('2' * 64))
            rootCertificateSha256 = ('3' * 64)
        },
        [pscustomobject]@{
            chainId = 'tsa-rotation'
            validFromUtc = '2026-09-01T00:00:00Z'
            validUntilUtc = '2027-09-01T00:00:00Z'
            leafCertificateSha256 = ('4' * 64)
            intermediateCertificateSha256s = @(('5' * 64))
            rootCertificateSha256 = ('6' * 64)
        })
}
$tsaPolicyAccepted = & $executionModule {
    param($tsaPolicy)
    return Assert-WindowsPilotTsaTrustPolicy -TsaPolicy $tsaPolicy
} $syntheticTsaPolicy
Assert-True ([bool]$tsaPolicyAccepted) `
    'TSA policy must support explicit overlapping signer-chain identities for controlled rotation.'
$duplicateTsaPinPolicy = [pscustomobject]@{
    trustedSignerChains = @(
        [pscustomobject]@{
            chainId = 'tsa-duplicate-pin'
            validFromUtc = '2026-01-01T00:00:00Z'
            validUntilUtc = '2027-01-01T00:00:00Z'
            leafCertificateSha256 = ('1' * 64)
            intermediateCertificateSha256s = @(('2' * 64))
            rootCertificateSha256 = ('1' * 64)
        })
}
Assert-Fails `
    -Action {
        & $executionModule {
            param($tsaPolicy)
            [void](Assert-WindowsPilotTsaTrustPolicy -TsaPolicy $tsaPolicy)
        } $duplicateTsaPinPolicy
    } `
    -Pattern 'distinct, non-placeholder' `
    -Message 'A TSA chain with repeated leaf/root identity must fail closed.'

$policyForArguments = [pscustomobject]@{
    authenticode = [pscustomobject]@{
        certificateThumbprintSha1 = 'abcdefabcdefabcdefabcdefabcdefabcdefabcd'
    }
    tsa = [pscustomobject]@{ uri = 'http://timestamp.digicert.com/' }
}
$startInfo = WindowsPilotSigningExecution\New-WindowsPilotSignToolStartInfo `
    -SignToolPath 'C:\fixed\signtool.exe' `
    -Policy $policyForArguments `
    -TargetPath 'C:\transaction\signed\target.exe'
$arguments = @($startInfo.ArgumentList)
Assert-True `
    (($arguments -join '|') -ceq
        'sign|/fd|SHA256|/sha1|ABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD|/tr|http://timestamp.digicert.com/|/td|SHA256|C:\transaction\signed\target.exe') `
    'SignTool must receive the exact digest, SHA1 selector, RFC3161 URI, timestamp digest, and target arguments.'
Assert-True `
    (-not $startInfo.UseShellExecute -and $startInfo.CreateNoWindow -and
        $startInfo.WindowStyle -eq [Diagnostics.ProcessWindowStyle]::Hidden -and
        $startInfo.RedirectStandardOutput -and $startInfo.RedirectStandardError) `
    'SignTool execution must not use a shell or visible window and must capture both streams.'

$highSignature = [byte[]]::new(64)
$highSignature[31] = 1
$highS = [Convert]::FromHexString(
    'FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632550')
[Array]::Copy($highS, 0, $highSignature, 32, 32)
$lowSignature =
    WindowsPilotSigningExecution\ConvertTo-WindowsPilotLowSP256Signature `
        -Signature $highSignature
Assert-True `
    ($lowSignature.Length -eq 64 -and $lowSignature[31] -eq 1 -and
        $lowSignature[63] -eq 1) `
    'High-S P-256 signatures must normalize to the equivalent low-S scalar.'
Assert-Fails `
    -Action {
        [void](WindowsPilotSigningExecution\ConvertTo-WindowsPilotLowSP256Signature `
            -Signature ([byte[]]::new(64)))
    } `
    -Pattern 'zero P1363 scalar|out-of-range' `
    -Message 'Zero-scalar P1363 signatures must fail closed.'

foreach ($scriptPath in @($clientAdapterPath, $installerAdapterPath, $initializerPath)) {
    $tokens = $null
    $errors = $null
    [void][Management.Automation.Language.Parser]::ParseFile(
        [IO.Path]::GetFullPath($scriptPath), [ref]$tokens, [ref]$errors)
    Assert-True ($errors.Count -eq 0) "$scriptPath must parse without errors."
}
$executionSource = [IO.File]::ReadAllText($executionModulePath)
$initializerSource = [IO.File]::ReadAllText($initializerPath)
foreach ($required in @(
        'ProcessStartInfo', 'ArgumentList', 'CreateNoWindow',
        'UseShellExecute = $false', 'StrictProcessCapture',
        'Invoke-WindowsPinnedExecutableOperation',
        'Get-ExactPeAuthenticodeEvidence',
        'Move-ProductionReleaseDirectoryLease',
        'Assert-WindowsPilotExactEnhancedKeyUsage',
        'Assert-WindowsPilotExactDigitalSignatureKeyUsage',
        'Assert-WindowsPilotTsaTrustEvidence',
        '1.3.6.1.5.5.7.3.3', '1.3.6.1.5.5.7.3.8',
        'ApplicationPolicy.Add',
        'X509RevocationMode]::Online',
        'onlineRevocationChecked = $true')) {
    Assert-True ($executionSource.Contains($required)) `
        "Execution module must retain '$required'."
}
Assert-True (-not $executionSource.Contains('Start-Process')) `
    'Execution module must not use shell-like Start-Process invocation.'
Assert-True ($executionSource.Contains('$tsa.sha256Matches')) `
    'Execution policy admission must use the TSA observation actual sha256Matches field.'
Assert-True (-not $executionSource.Contains('digestMatchesExpected')) `
    'Execution policy admission must not reference a nonexistent TSA observation field.'
foreach ($required in @(
        "ConfirmImpact = 'High'", 'CngKeyCreationParameters',
        'MicrosoftSoftwareKeyStorageProvider',
        'ExportPolicy = [Security.Cryptography.CngExportPolicies]::None',
        'CngKeyOpenOptions]::UserKey', 'ExportParameters($false)')) {
    Assert-True ($initializerSource.Contains($required)) `
        "Response-key initializer must retain '$required'."
}
Assert-True (-not $initializerSource.Contains('ExportParameters($true)')) `
    'Response-key initializer must never export private parameters.'

$controlledTestRoot = [IO.Path]::GetFullPath((Join-Path `
    $PSScriptRoot '..\..\.test-out\windows-pilot-signing-execution'))
if (Test-Path -LiteralPath $controlledTestRoot) {
    $controlledRootItem = Get-Item -LiteralPath $controlledTestRoot -Force
    Assert-True ($controlledRootItem.PSIsContainer -and
        ($controlledRootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) `
        'Dedicated signing test root must be an ordinary non-linked directory.'
}
else {
    [void][IO.Directory]::CreateDirectory($controlledTestRoot)
}
$temporaryRoot = Join-Path $controlledTestRoot `
    ('run-' + [Guid]::NewGuid().ToString('N'))
$requestRoot = Join-Path $temporaryRoot 'requests'
$transactionRoot = Join-Path $temporaryRoot 'transactions'
$outputRoot = Join-Path $temporaryRoot 'responses'
[void][IO.Directory]::CreateDirectory($requestRoot)
[void][IO.Directory]::CreateDirectory($transactionRoot)
[void][IO.Directory]::CreateDirectory($outputRoot)
$policyPath = Join-Path $temporaryRoot 'test-policy.bin'
[IO.File]::WriteAllBytes($policyPath, [byte[]](1..32))
$policyInput = $null
try {
    $policyInput = ProductionReleaseState\Open-ProductionReleaseInput `
        -Path $policyPath -Label 'Synthetic transaction policy' -MaximumBytes 1024
    $policyInput | Add-Member -NotePropertyName Value -NotePropertyValue (
        [pscustomobject]@{
            executionAdmission = 'PERSONAL_PILOT_SIGNING'
            roots = [pscustomobject]@{
                requestRoot = $requestRoot
                transactionRoot = $transactionRoot
                outputRoot = $outputRoot
            }
            authenticode = [pscustomobject]@{
                certificateSha256 = ('a' * 64)
            }
            tsa = [pscustomobject]@{
                canonicalUriSha256 =
                    '9a44be2d0f498a8bfd2dd1a5e5cced2135e9c4ada9bb5a04eed4c6c5beba1a33'
                trustedSignerChains = @([pscustomobject]@{
                        chainId = 'synthetic-tsa-chain'
                        validFromUtc = '2026-01-01T00:00:00Z'
                        validUntilUtc = '2027-01-01T00:00:00Z'
                        leafCertificateSha256 = ('b' * 64)
                        intermediateCertificateSha256s = @(('c' * 64))
                        rootCertificateSha256 = ('d' * 64)
                    })
            }
        })
    $sourceAPath = Join-Path $requestRoot 'one.exe'
    $sourceBPath = Join-Path $requestRoot 'two.exe'
    $sourceA = New-TestSource -Path $sourceAPath -Seed 11
    $sourceB = New-TestSource -Path $sourceBPath -Seed 29
    $targets = @(
        [pscustomobject]@{
            role = 'one'; fileName = 'one.exe'; sourcePath = $sourceAPath
            sizeBytes = $sourceA.Bytes.Length; sha256 = $sourceA.Sha256
            peContentSha256 = $sourceA.PeContentSha256
        },
        [pscustomobject]@{
            role = 'two'; fileName = 'two.exe'; sourcePath = $sourceBPath
            sizeBytes = $sourceB.Bytes.Length; sha256 = $sourceB.Sha256
            peContentSha256 = $sourceB.PeContentSha256
        })
    $certificateAdmission = { param($policy) return [IO.MemoryStream]::new() }
    $sourceAdmission = {
        param($descriptor, $target)
        return [string]$target.peContentSha256
    }
    $fakeSign = {
        param($policy, $targetPath)
        $stream = [IO.File]::Open(
            $targetPath, [IO.FileMode]::Append,
            [IO.FileAccess]::Write, [IO.FileShare]::None)
        try {
            $marker = [Text.Encoding]::ASCII.GetBytes('synthetic-signature')
            $stream.Write($marker, 0, $marker.Length)
            $stream.Flush($true)
        }
        finally { $stream.Dispose() }
        return [pscustomobject]@{ exitCode = 0 }
    }
    $fakeEvidence = {
        param($policy, $targetPath, $target)
        $input = ProductionReleaseState\Open-ProductionReleaseInput `
            -Path $targetPath -Label 'Synthetic signed output' -MaximumBytes 1MB
        try {
            return [pscustomobject]@{
                FileName = $input.FileName
                SizeBytes = $input.SizeBytes
                SignedFileSha256 = $input.Sha256
                PeContentSha256 = [string]$target.peContentSha256
                SignerCertificateSha256 = [string]$policy.authenticode.certificateSha256
                PrimarySignerCount = 1
                TimestampProtocol = 'RFC3161'
                TimestampSignerCertificateSha256 = ('b' * 64)
                TimestampUtc = '2026-09-01T00:00:00Z'
                LegacyCounterSignaturePresent = $false
                TsaTrustEvidence = [pscustomobject][ordered]@{
                    fileName = $input.FileName
                    signedFileSha256 = $input.Sha256
                    chainId = 'synthetic-tsa-chain'
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
                    policyTsaUriSha256 =
                        '9a44be2d0f498a8bfd2dd1a5e5cced2135e9c4ada9bb5a04eed4c6c5beba1a33'
                }
            }
        }
        finally { $input.Stream.Dispose() }
    }
    $responseBuilder = {
        param([object[]]$evidence, [string]$transactionPath)
        return [ordered]@{
            schemaVersion = 1
            responseType = 'synthetic-transaction-test'
            fileCount = $evidence.Count
        }
    }
    $responseValidator = {
        param($responseInput, [object[]]$evidence)
        return [int]$responseInput.Value.fileCount -eq 2 -and
            $evidence.Count -eq 2
    }
    $successOutput = Join-Path $outputRoot 'success'
    $result = & $executionModule {
        param($parameters)
        Invoke-WindowsPilotSigningTransactionCore @parameters
    } @{
        PolicyInput = $policyInput
        Targets = $targets
        FinalOutputPath = $successOutput
        ResponseFileName = 'response.json'
        ResponseBuilder = $responseBuilder
        ResponseValidator = $responseValidator
        CertificateAdmissionOperation = $certificateAdmission
        SourceAdmissionOperation = $sourceAdmission
        SignOperation = $fakeSign
        EvidenceOperation = $fakeEvidence
    }
    Assert-True ([string]$result.status -ceq 'COMMITTED') `
        'Synthetic signing transaction must atomically commit.'
    Assert-True (@($result.tsaTrustEvidence).Count -eq 2) `
        'Committed transaction must return one policy-bound TSA proof per target.'
    Assert-True ((Get-TestSha256 -Bytes ([IO.File]::ReadAllBytes($sourceAPath))) -ceq
        $sourceA.Sha256) 'Signing transaction must not mutate source one.'
    Assert-True ((Get-TestSha256 -Bytes ([IO.File]::ReadAllBytes($sourceBPath))) -ceq
        $sourceB.Sha256) 'Signing transaction must not mutate source two.'
    Assert-True (Test-Path -LiteralPath (Join-Path $successOutput 'response.json')) `
        'Committed transaction must contain its response.'
    Assert-True (@(Get-ChildItem -LiteralPath $transactionRoot -Force).Count -eq 0) `
        'Successful atomic move must leave no transaction directory.'

    $failureState = [pscustomobject]@{ Count = 0 }
    $failingSign = {
        param($policy, $targetPath)
        $failureState.Count++
        if ($failureState.Count -eq 2) { throw 'synthetic second target failure' }
        & $fakeSign $policy $targetPath
    }.GetNewClosure()
    $failedOutput = Join-Path $outputRoot 'failed'
    Assert-Fails `
        -Action {
            & $executionModule {
                param($parameters)
                Invoke-WindowsPilotSigningTransactionCore @parameters
            } @{
                PolicyInput = $policyInput
                Targets = $targets
                FinalOutputPath = $failedOutput
                ResponseFileName = 'response.json'
                ResponseBuilder = $responseBuilder
                ResponseValidator = $responseValidator
                CertificateAdmissionOperation = $certificateAdmission
                SourceAdmissionOperation = $sourceAdmission
                SignOperation = $failingSign
                EvidenceOperation = $fakeEvidence
            }
        } `
        -Pattern 'synthetic second target failure' `
        -Message 'A later target failure must fail the complete batch.'
    Assert-True (-not (Test-Path -LiteralPath $failedOutput)) `
        'Failed signing batch must not create final output.'
    Assert-True (@(Get-ChildItem -LiteralPath $transactionRoot -Force).Count -eq 0) `
        'Failed signing batch must remove only its generated transaction.'
    Assert-True ((Get-TestSha256 -Bytes ([IO.File]::ReadAllBytes($sourceAPath))) -ceq
        $sourceA.Sha256) 'Failed signing batch must not mutate source one.'
    Assert-True ((Get-TestSha256 -Bytes ([IO.File]::ReadAllBytes($sourceBPath))) -ceq
        $sourceB.Sha256) 'Failed signing batch must not mutate source two.'

    $mismatchedTsaEvidence = {
        param($policy, $targetPath, $target)
        $value = & $fakeEvidence $policy $targetPath $target
        $value.TsaTrustEvidence.rootCertificateSha256 = ('e' * 64)
        return $value
    }.GetNewClosure()
    $untrustedTsaOutput = Join-Path $outputRoot 'untrusted-tsa'
    Assert-Fails `
        -Action {
            & $executionModule {
                param($parameters)
                Invoke-WindowsPilotSigningTransactionCore @parameters
            } @{
                PolicyInput = $policyInput
                Targets = $targets
                FinalOutputPath = $untrustedTsaOutput
                ResponseFileName = 'response.json'
                ResponseBuilder = $responseBuilder
                ResponseValidator = $responseValidator
                CertificateAdmissionOperation = $certificateAdmission
                SourceAdmissionOperation = $sourceAdmission
                SignOperation = $fakeSign
                EvidenceOperation = $mismatchedTsaEvidence
            }
        } `
        -Pattern 'TSA evidence is not bound|TSA identity' `
        -Message 'A TSA root-pin mismatch must fail the complete signing batch.'
    Assert-True (-not (Test-Path -LiteralPath $untrustedTsaOutput)) `
        'A TSA trust failure must not create final output.'
    Assert-True (@(Get-ChildItem -LiteralPath $transactionRoot -Force).Count -eq 0) `
        'A TSA trust failure must remove only its generated transaction.'
}
finally {
    if ($null -ne $policyInput) { $policyInput.Stream.Dispose() }
    if (Test-Path -LiteralPath $temporaryRoot) {
        $cleanupPath = [IO.Path]::GetFullPath($temporaryRoot)
        Assert-True `
            ([IO.Path]::GetDirectoryName($cleanupPath) -ceq $controlledTestRoot -and
                [IO.Path]::GetFileName($cleanupPath) -cmatch '^run-[0-9a-f]{32}$') `
            'Signing execution test cleanup must stay inside its exact generated root.'
        [IO.Directory]::Delete($cleanupPath, $true)
    }
}

Write-Output 'WINDOWS-PILOT-SIGNING-EXECUTION-PASS'
Write-Output 'TRANSACTION-COPY-ONLY-AND-ALL-OR-NOTHING-PASS'
Write-Output 'NO-REAL-KEY-CERTIFICATE-SIGNING-TIMESTAMP-OR-NETWORK-PERFORMED'
