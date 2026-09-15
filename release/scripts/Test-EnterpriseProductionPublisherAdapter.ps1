#requires -Version 7.2

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptPath = Join-Path $PSScriptRoot 'New-EnterpriseProductionPublisherInput.ps1'
$schemaPath = Join-Path `
    $PSScriptRoot `
    '..\schemas\enterprise-production-publisher-policy-v1.schema.json'
$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$stateModulePath = Join-Path $PSScriptRoot 'ProductionReleaseState.psm1'
$stateSchemaPath = Join-Path `
    $repositoryRoot `
    'release\schemas\launcher-production-release-state-v2.schema.json'
$planSchemaPath = Join-Path `
    $repositoryRoot `
    'release\schemas\launcher-production-release-plan-v2.schema.json'
$payloadModulePath = Join-Path $repositoryRoot 'scripts\EnterpriseProductionPayload.psm1'

Microsoft.PowerShell.Core\Import-Module -Name $stateModulePath -Force -ErrorAction Stop

function Assert-True {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )

    if (-not $Condition) {
        throw $Message
    }
}

function Assert-Throws {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Action,
        [Parameter(Mandatory = $true)][string]$Message
    )

    $threw = $false
    try {
        & $Action
    }
    catch {
        $threw = $true
    }
    if (-not $threw) {
        throw $Message
    }
}

foreach ($path in @($scriptPath, $schemaPath, $payloadModulePath)) {
    Assert-True `
        -Condition (Test-Path -LiteralPath $path -PathType Leaf) `
        -Message "Enterprise production Publisher adapter contract is missing: $path"
}

$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    $scriptPath,
    [ref]$tokens,
    [ref]$parseErrors)
Assert-True `
    -Condition (@($parseErrors).Count -eq 0) `
    -Message 'Enterprise production Publisher input adapter has a PowerShell parse error.'

$parameters = @($ast.ParamBlock.Parameters | ForEach-Object {
    $_.Name.VariablePath.UserPath
})
$requiredParameters = @(
    'PlanPath',
    'StateRoot',
    'PublisherPolicyPath',
    'RuntimeOrganizationAdmissionReceiptPath',
    'PluginPolicyArchivePath',
    'PluginPolicyMetadataPath',
    'PluginPromotionHandoffPath',
    'PluginHarnessCompatibilityReceiptPath',
    'PluginGenerationReservationPath',
    'PluginGenerationLedgerPath',
    'PluginOrganizationAdmissionReceiptPath',
    'PluginPromotionJournalAuthorizationPath',
    'OutputDirectory')
Assert-True `
    -Condition (@(Compare-Object $requiredParameters $parameters -CaseSensitive).Count -eq 0) `
    -Message 'Enterprise production Publisher input adapter parameter boundary drifted.'

$scriptText = [IO.File]::ReadAllText($scriptPath)
foreach ($required in @(
    'Enter-ProductionReleaseStateReadLock',
    'Get-ProductionReleaseState',
    "'CLIENT_SIGNATURES_IMPORTED'",
    'Assert-ProductionPublisherInputFileSet',
    'ConvertTo-ProductionJsonBytes',
    '[IO.FileMode]::CreateNew',
    '[IO.Directory]::Move',
    'EnterpriseProductionPayload\New-EnterpriseProductionLauncherArchive',
    "'edition-launcher-archive'",
    "'edition-plugin-policy-archive'",
    "'edition-runtime-organization-admission'")) {
    Assert-True `
        -Condition $scriptText.Contains($required, [StringComparison]::Ordinal) `
        -Message "Enterprise production Publisher adapter lost required fail-closed behavior: $required"
}
foreach ($forbidden in @(
    'New-DeterministicLauncherArchive',
    'ZipArchiveMode',
    'CreateEntry(',
    'PrivateKey',
    'ImportPkcs8PrivateKey',
    'SignData(',
    'New-SelfSignedCertificate',
    'developmentRuntimeAdmissionTrust')) {
    Assert-True `
        -Condition (-not $scriptText.Contains($forbidden, [StringComparison]::OrdinalIgnoreCase)) `
        -Message "Enterprise production Publisher input adapter must not handle or invent signing trust: $forbidden"
}

$schemaText = [IO.File]::ReadAllText($schemaPath)
Assert-True `
    -Condition (Test-Json -Json $schemaText -ErrorAction Stop) `
    -Message 'Enterprise production Publisher policy schema is not valid JSON Schema.'

$valid = [ordered]@{
    schemaVersion = 1
    policyType = 'ensou-dsh-enterprise-production-publisher-policy'
    launcherReleaseId = 'launcher-enterprise-2026.09.01.1'
    pluginPolicyReleaseId = 'plugins-enterprise-2026.09.01.1'
    generation = 2
    sequence = 7
    minAcceptedSequence = 5
    expiresAtUtc = '2026-09-20T00:00:00.0000000Z'
    revokedReleaseSetIds = @('enterprise-2026.08.01.1')
    pluginGenerationLedgerNamespace = 'enterprise-production'
}
$validJson = $valid | ConvertTo-Json -Depth 8 -Compress
Assert-True `
    -Condition (Test-Json -Json $validJson -SchemaFile $schemaPath -ErrorAction Stop) `
    -Message 'Canonical Enterprise production Publisher policy did not satisfy its schema.'

$negativeCases = [Collections.Generic.List[object]]::new()
$case = $validJson | ConvertFrom-Json
$case | Add-Member -NotePropertyName unexpected -NotePropertyValue $true
$negativeCases.Add($case)
$case = $validJson | ConvertFrom-Json
$case.generation = 0
$negativeCases.Add($case)
$case = $validJson | ConvertFrom-Json
$case.expiresAtUtc = '2026-09-20T00:00:00Z'
$negativeCases.Add($case)
$case = $validJson | ConvertFrom-Json
$case.revokedReleaseSetIds = @(
    'enterprise-2026.08.01.1',
    'enterprise-2026.08.01.1')
$negativeCases.Add($case)
$case = $validJson | ConvertFrom-Json
$case.pluginGenerationLedgerNamespace = '../escape'
$negativeCases.Add($case)

foreach ($negative in $negativeCases) {
    $negativeJson = $negative | ConvertTo-Json -Depth 8 -Compress
    Assert-True `
        -Condition (-not (Test-Json `
                -Json $negativeJson `
                -SchemaFile $schemaPath `
                -ErrorAction SilentlyContinue)) `
        -Message 'Enterprise production Publisher policy schema admitted a negative fixture.'
}

function ConvertTo-TestBase64Url {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    return [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Write-TestCanonicalJson {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Value
    )

    Write-ProductionStateFile `
        -Path $Path `
        -Bytes (ConvertTo-ProductionJsonBytes -Value $Value)
}

function Get-TestFileIdentity {
    param([Parameter(Mandatory = $true)][string]$Path)

    $input = Open-ProductionReleaseInput `
        -Path $Path `
        -Label 'Enterprise Publisher adapter fixture input' `
        -MaximumBytes 512MB
    try {
        return [pscustomobject]@{
            FileName = [string]$input.FileName
            Path = [string]$input.Path
            SizeBytes = [int64]$input.SizeBytes
            Sha256 = [string]$input.Sha256
        }
    }
    finally {
        $input.Stream.Dispose()
    }
}

function New-TestTrust {
    param(
        [Parameter(Mandatory = $true)][string]$KeyId,
        [Parameter(Mandatory = $true)][string]$Purpose,
        [Parameter(Mandatory = $true)][string]$X,
        [Parameter(Mandatory = $true)][string]$Y
    )

    return [ordered]@{
        algorithm = 'ES256'
        keyId = $KeyId
        purpose = $Purpose
        x = $X
        y = $Y
    }
}

function New-EnterprisePublisherR3Fixture {
    param([Parameter(Mandatory = $true)][string]$Root)

    [IO.Directory]::CreateDirectory($Root) | Out-Null
    $inputRoot = Join-Path $Root 'inputs'
    [IO.Directory]::CreateDirectory($inputRoot) | Out-Null
    $peSource = Join-Path $PSHOME 'pwsh.exe'
    if (-not (Test-Path -LiteralPath $peSource -PathType Leaf)) {
        throw 'Enterprise Publisher adapter integration fixture requires native pwsh.exe.'
    }

    $clientDefinitions = @(
        [pscustomobject]@{ Role = 'bootstrapper'; FileName = 'Ensou.Dsh.Enterprise.Bootstrapper.exe' },
        [pscustomobject]@{ Role = 'launcher'; FileName = 'Ensou.Dsh.Enterprise.Launcher.exe' },
        [pscustomobject]@{ Role = 'client-bootstrapper'; FileName = 'Ensou.Dsh.Enterprise.ClientBootstrapper.exe' },
        [pscustomobject]@{ Role = 'maintenance'; FileName = 'Ensou.Dsh.Enterprise.Maintenance.exe' })
    $clientInputs = [Collections.Generic.List[object]]::new()
    foreach ($definition in $clientDefinitions) {
        $path = Join-Path $inputRoot $definition.FileName
        [IO.File]::Copy($peSource, $path, $false)
        $identity = Get-TestFileIdentity -Path $path
        [byte[]]$peBytes = [IO.File]::ReadAllBytes($path)
        $clientInputs.Add([ordered]@{
            role = [string]$definition.Role
            fileName = [string]$definition.FileName
            path = $path
            sizeBytes = [int64]$identity.SizeBytes
            sha256 = [string]$identity.Sha256
            peContentSha256 = Get-PeContentSha256 -Bytes $peBytes
        })
    }

    $runtimeArchivePath = Join-Path $inputRoot 'runtime.zip'
    $runtimeMetadataPath = Join-Path $inputRoot 'runtime-metadata.json'
    $runtimeHashPath = Join-Path $inputRoot 'runtime-sha256.txt'
    [IO.File]::WriteAllBytes(
        $runtimeArchivePath,
        [Text.UTF8Encoding]::new($false).GetBytes('enterprise-runtime-fixture'))
    Write-TestCanonicalJson `
        -Path $runtimeMetadataPath `
        -Value ([ordered]@{
            sourceTag = 'dsh-v0.1.2-rc.1'
            sourceCommit = 'd' * 40
        })
    [IO.File]::WriteAllText(
        $runtimeHashPath,
        ((Get-TestFileIdentity -Path $runtimeArchivePath).Sha256 + "  runtime.zip`n"),
        [Text.UTF8Encoding]::new($false))
    $runtimeArchive = Get-TestFileIdentity -Path $runtimeArchivePath
    $runtimeMetadata = Get-TestFileIdentity -Path $runtimeMetadataPath
    $runtimeHash = Get-TestFileIdentity -Path $runtimeHashPath

    $key = [Security.Cryptography.ECDsa]::Create(
        [Security.Cryptography.ECCurve+NamedCurves]::nistP256)
    try {
        $public = $key.ExportParameters($false)
        $x = ConvertTo-TestBase64Url -Bytes $public.Q.X
        $y = ConvertTo-TestBase64Url -Bytes $public.Q.Y
    }
    finally {
        $key.Dispose()
    }
    $planValue = [ordered]@{
        schemaVersion = 2
        planType = 'ensou-dsh-launcher-production-release'
        orchestrationId = [Guid]::NewGuid().ToString()
        edition = 'Enterprise'
        releaseSetId = 'enterprise-publisher-fixture-v1'
        targetChannel = 'stable'
        sourceCommit = 'b' * 40
        manifestUri = 'https://updates.ensou.example/v2/channels/stable/release-set.v2.json'
        artifactBaseUri = 'https://artifacts.ensou.example/launcher/'
        pilotEvidenceTrustPolicySha256 = 'd' * 64
        runtimeCandidate = [ordered]@{
            releaseId = 'runtime-enterprise-fixture-v1'
            githubReleaseTag = 'dsh-v0.1.2-rc.1'
            archive = [ordered]@{
                fileName = $runtimeArchive.FileName
                path = $runtimeArchive.Path
                sizeBytes = $runtimeArchive.SizeBytes
                sha256 = $runtimeArchive.Sha256
            }
            metadata = [ordered]@{
                fileName = $runtimeMetadata.FileName
                path = $runtimeMetadata.Path
                sizeBytes = $runtimeMetadata.SizeBytes
                sha256 = $runtimeMetadata.Sha256
            }
            hashEvidence = [ordered]@{
                fileName = $runtimeHash.FileName
                path = $runtimeHash.Path
                sizeBytes = $runtimeHash.SizeBytes
                sha256 = $runtimeHash.Sha256
            }
        }
        authenticodePolicy = [ordered]@{
            signerSha256Thumbprint = 'a' * 64
            requireTrustedTimestamp = $true
            maximumResponseAgeMinutes = 120
        }
        releaseManifestTrust = New-TestTrust `
            -KeyId 'enterprise-release-manifest-fixture' `
            -Purpose 'release-manifest-signing' `
            -X $x `
            -Y $y
        releaseCompatibility = [ordered]@{ startupStubProtocol = 1 }
        externalResponseTrusts = [ordered]@{
            clientSigning = New-TestTrust -KeyId 'enterprise-client-signing-fixture' -Purpose 'client-signing-response' -X $x -Y $y
            manifestPublishing = New-TestTrust -KeyId 'enterprise-manifest-publishing-fixture' -Purpose 'manifest-publishing-response' -X $x -Y $y
            installerSigning = New-TestTrust -KeyId 'enterprise-installer-signing-fixture' -Purpose 'installer-signing-response' -X $x -Y $y
            feedPromotion = New-TestTrust -KeyId 'enterprise-feed-promotion-fixture' -Purpose 'feed-promotion-response' -X $x -Y $y
        }
        clientSigningInputs = @($clientInputs)
    }
    $planBytes = ConvertTo-ProductionJsonBytes -Value $planValue
    $plan = ConvertFrom-StrictProductionJsonBytes `
        -Bytes $planBytes `
        -Label 'Enterprise Publisher adapter fixture plan' `
        -SchemaPath $planSchemaPath
    $planPath = Join-Path $Root 'plan.v2.json'
    Write-ProductionStateFile -Path $planPath -Bytes $planBytes

    $stateRoot = Join-Path $Root 'state'
    $stateLock = Enter-ProductionReleaseStateLock `
        -StateRoot $stateRoot `
        -PlanBytes $planBytes `
        -Plan $plan
    try {
        [void](Initialize-ProductionReleaseState `
            -Lock $stateLock `
            -PlanBytes $planBytes `
            -Plan $plan `
            -StateSchemaPath $stateSchemaPath)
        $clientReceiptFiles = @($plan.clientSigningInputs | ForEach-Object {
            [ordered]@{
                role = [string]$_.role
                fileName = [string]$_.fileName
                sizeBytes = [int64]$_.sizeBytes
                sha256 = [string]$_.sha256
                peContentSha256 = [string]$_.peContentSha256
            }
        })
        $planReceiptData = [ordered]@{
            releaseSetId = [string]$plan.releaseSetId
            targetChannel = 'stable'
            sourceCommit = [string]$plan.sourceCommit
            sourceTree = 'c' * 40
            manifestUri = [string]$plan.manifestUri
            artifactBaseUri = [string]$plan.artifactBaseUri
            releaseManifestTrustSha256 = Get-ProductionSha256Bytes `
                -Bytes (ConvertTo-ProductionJsonBytes -Value $plan.releaseManifestTrust)
            releaseCompatibilitySha256 = Get-ProductionSha256Bytes `
                -Bytes (ConvertTo-ProductionJsonBytes -Value $plan.releaseCompatibility)
            runtimeCandidate = [ordered]@{
                releaseId = [string]$plan.runtimeCandidate.releaseId
                githubReleaseTag = [string]$plan.runtimeCandidate.githubReleaseTag
                harnessSourceTag = 'dsh-v0.1.2-rc.1'
                harnessSourceCommit = 'd' * 40
                archiveSha256 = [string]$plan.runtimeCandidate.archive.sha256
                metadataSha256 = [string]$plan.runtimeCandidate.metadata.sha256
                hashEvidenceSha256 = [string]$plan.runtimeCandidate.hashEvidence.sha256
                localMetadataPromotionEligible = $true
                publicationStatus = 'IMMUTABLE_SOURCE_RELEASE_UNVERIFIED'
            }
            clientInputs = $clientReceiptFiles
        }
        $state = Add-ProductionReleaseReceipt `
            -StateRoot $stateRoot `
            -StateSchemaPath $stateSchemaPath `
            -Phase 'PLAN_ADMITTED' `
            -ExpectedPreviousPhase $null `
            -ExpectedHeadSha256 '' `
            -Data $planReceiptData

        $requestRoot = Join-Path $stateRoot 'requests\client-signing.v1'
        $unsignedRoot = Join-Path $requestRoot 'unsigned'
        [IO.Directory]::CreateDirectory($unsignedRoot) | Out-Null
        foreach ($input in @($plan.clientSigningInputs)) {
            [IO.File]::Copy(
                [string]$input.path,
                (Join-Path $unsignedRoot ([string]$input.fileName)),
                $false)
        }
        $requestPath = Join-Path $requestRoot 'signing-request.v1.json'
        Write-TestCanonicalJson `
            -Path $requestPath `
            -Value ([ordered]@{
                fixtureType = 'enterprise-publisher-adapter-r3-request'
                releaseSetId = [string]$plan.releaseSetId
            })
        $requestIdentity = Get-TestFileIdentity -Path $requestPath
        $createdAtUtc = ConvertTo-ProductionUtc -Value ([DateTimeOffset]::UtcNow)
        $expiresAtUtc = ConvertTo-ProductionUtc -Value ([DateTimeOffset]::UtcNow.AddHours(1))
        $state = Add-ProductionReleaseReceipt `
            -StateRoot $stateRoot `
            -StateSchemaPath $stateSchemaPath `
            -Phase 'CLIENT_SIGNING_REQUESTED' `
            -ExpectedPreviousPhase 'PLAN_ADMITTED' `
            -ExpectedHeadSha256 ([string]$state.HeadSha256) `
            -Data ([ordered]@{
                requestRelativePath = 'requests/client-signing.v1/signing-request.v1.json'
                requestSha256 = [string]$requestIdentity.Sha256
                nonce = 'A' * 43
                createdAtUtc = $createdAtUtc
                expiresAtUtc = $expiresAtUtc
                files = @($clientReceiptFiles | ForEach-Object {
                    [ordered]@{
                        role = [string]$_.role
                        fileName = [string]$_.fileName
                        sha256 = [string]$_.sha256
                        peContentSha256 = [string]$_.peContentSha256
                    }
                })
            })

        $importRoot = Join-Path $stateRoot 'imports\client-signing.v1'
        $signedRoot = Join-Path $importRoot 'signed'
        [IO.Directory]::CreateDirectory($signedRoot) | Out-Null
        $signedFiles = [Collections.Generic.List[object]]::new()
        foreach ($input in @($plan.clientSigningInputs)) {
            $signedPath = Join-Path $signedRoot ([string]$input.fileName)
            [IO.File]::Copy([string]$input.path, $signedPath, $false)
            $signedIdentity = Get-TestFileIdentity -Path $signedPath
            $signedBytes = [IO.File]::ReadAllBytes($signedPath)
            $signedFiles.Add([ordered]@{
                role = [string]$input.role
                fileName = [string]$input.fileName
                sizeBytes = [int64]$signedIdentity.SizeBytes
                sha256 = [string]$signedIdentity.Sha256
                peContentSha256 = Get-PeContentSha256 -Bytes $signedBytes
                timestampProtocol = 'RFC3161'
            })
        }
        $responsePath = Join-Path $importRoot 'signing-response.v1.json'
        Write-TestCanonicalJson `
            -Path $responsePath `
            -Value ([ordered]@{
                fixtureType = 'enterprise-publisher-adapter-r3-response'
                productionImportAdmission = $false
            })
        $responseIdentity = Get-TestFileIdentity -Path $responsePath
        $probeFiles = @($signedFiles[0..2] | ForEach-Object {
            [ordered]@{
                role = [string]$_.role
                fileName = [string]$_.fileName
                probeSha256 = Get-ProductionSha256Bytes `
                    -Bytes ([Text.UTF8Encoding]::new($false).GetBytes([string]$_.role))
            }
        })
        $state = Add-ProductionReleaseReceipt `
            -StateRoot $stateRoot `
            -StateSchemaPath $stateSchemaPath `
            -Phase 'CLIENT_SIGNATURES_IMPORTED' `
            -ExpectedPreviousPhase 'CLIENT_SIGNING_REQUESTED' `
            -ExpectedHeadSha256 ([string]$state.HeadSha256) `
            -Data ([ordered]@{
                responseRelativePath = 'imports/client-signing.v1/signing-response.v1.json'
                responseSha256 = [string]$responseIdentity.Sha256
                completedAtUtc = ConvertTo-ProductionUtc -Value ([DateTimeOffset]::UtcNow)
                authenticationKeyId = [string]$plan.externalResponseTrusts.clientSigning.keyId
                authenticationPurpose = 'client-signing-response'
                authenticationPayloadType = 'ensou-dsh-launcher-external-signing-response-authentication-v2'
                releaseManifestTrustProbeStatus = 'VERIFIED'
                releaseManifestTrustProbes = $probeFiles
                files = @($signedFiles)
            })
        Assert-True `
            -Condition ([int]$state.Head.revision -eq 3) `
            -Message 'Enterprise Publisher adapter fixture did not reach r3.'
    }
    finally {
        $stateLock.Stream.Dispose()
    }

    $policyPath = Join-Path $Root 'enterprise-publisher-policy.v1.json'
    $expiry = [DateTimeOffset]::UtcNow.AddDays(10)
    $expiry = [DateTimeOffset]::new(
        $expiry.Year, $expiry.Month, $expiry.Day,
        $expiry.Hour, $expiry.Minute, $expiry.Second,
        [TimeSpan]::Zero)
    Write-TestCanonicalJson `
        -Path $policyPath `
        -Value ([ordered]@{
            schemaVersion = 1
            policyType = 'ensou-dsh-enterprise-production-publisher-policy'
            launcherReleaseId = 'launcher-enterprise-fixture-v1'
            pluginPolicyReleaseId = 'plugins-enterprise-fixture-v1'
            generation = 2
            sequence = 7
            minAcceptedSequence = 5
            expiresAtUtc = $expiry.ToString(
                "yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'",
                [Globalization.CultureInfo]::InvariantCulture)
            revokedReleaseSetIds = @()
            pluginGenerationLedgerNamespace = 'enterprise-production'
        })

    $evidenceNames = [ordered]@{
        RuntimeOrganizationAdmissionReceiptPath = 'runtime-org-admission.json'
        PluginPolicyArchivePath = 'plugin-policy.zip'
        PluginPolicyMetadataPath = 'plugin-metadata.json'
        PluginPromotionHandoffPath = 'plugin-handoff.json'
        PluginHarnessCompatibilityReceiptPath = 'plugin-compatibility.json'
        PluginGenerationReservationPath = 'plugin-reservation.json'
        PluginGenerationLedgerPath = 'plugin-ledger.json'
        PluginOrganizationAdmissionReceiptPath = 'plugin-org-admission.json'
        PluginPromotionJournalAuthorizationPath = 'plugin-journal-authorization.json'
    }
    $arguments = @{
        PlanPath = $planPath
        StateRoot = $stateRoot
        PublisherPolicyPath = $policyPath
    }
    foreach ($entry in $evidenceNames.GetEnumerator()) {
        $evidencePath = Join-Path $inputRoot ([string]$entry.Value)
        [IO.File]::WriteAllBytes(
            $evidencePath,
            [Text.UTF8Encoding]::new($false).GetBytes([string]$entry.Key))
        $arguments[[string]$entry.Key] = $evidencePath
    }
    return [pscustomobject]@{
        Arguments = $arguments
        StateRoot = $stateRoot
        RuntimeArchivePath = $runtimeArchivePath
        ResponsePath = Join-Path $stateRoot 'imports\client-signing.v1\signing-response.v1.json'
        ReceiptPath = Join-Path $stateRoot 'receipts\0003-client-signatures-imported.json'
    }
}

$testParent = Join-Path ([IO.Path]::GetTempPath()) 'ensou-enterprise-publisher-adapter-tests'
[IO.Directory]::CreateDirectory($testParent) | Out-Null
$testRoot = Join-Path $testParent ([Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($testRoot) | Out-Null
try {
    $positive = New-EnterprisePublisherR3Fixture -Root (Join-Path $testRoot 'positive')
    $positiveOutput = Join-Path $testRoot 'positive-output'
    $positive.Arguments.OutputDirectory = $positiveOutput
    $positiveArguments = $positive.Arguments
    $result = & $scriptPath @positiveArguments
    Assert-True `
        -Condition (Test-Path -LiteralPath $result.PublisherInputPath -PathType Leaf) `
        -Message 'Enterprise Publisher adapter full r3 fixture produced no descriptor.'
    Assert-True `
        -Condition (Test-Path -LiteralPath $result.LauncherArchivePath -PathType Leaf) `
        -Message 'Enterprise Publisher adapter full r3 fixture produced no canonical Launcher archive.'
    $descriptor = Read-StrictProductionJsonFile `
        -Path $result.PublisherInputPath `
        -Label 'Enterprise Publisher adapter positive descriptor' `
        -SchemaPath (Join-Path $repositoryRoot 'release\schemas\launcher-production-publisher-input-v1.schema.json')
    $runtimePayload = $descriptor.Value.files[4]
    Assert-True `
        -Condition ([string]$runtimePayload.sha256 -ceq
            (Get-TestFileIdentity -Path $positive.RuntimeArchivePath).Sha256) `
        -Message 'Enterprise Publisher adapter did not preserve the exact runtime candidate hash for r6.'

    $repeatOutput = Join-Path $testRoot 'positive-repeat-output'
    $positive.Arguments.OutputDirectory = $repeatOutput
    $repeat = & $scriptPath @positiveArguments
    Assert-True `
        -Condition ((Get-TestFileIdentity -Path $result.LauncherArchivePath).Sha256 -ceq
            (Get-TestFileIdentity -Path $repeat.LauncherArchivePath).Sha256) `
        -Message 'Canonical Enterprise Launcher archive is not deterministic across r5 adapter runs.'

    $responseMutation = New-EnterprisePublisherR3Fixture `
        -Root (Join-Path $testRoot 'response-mutation')
    [IO.File]::AppendAllText($responseMutation.ResponsePath, ' ', [Text.UTF8Encoding]::new($false))
    $responseMutation.Arguments.OutputDirectory = Join-Path $testRoot 'response-mutation-output'
    $responseMutationArguments = $responseMutation.Arguments
    Assert-Throws `
        -Action { & $scriptPath @responseMutationArguments | Out-Null } `
        -Message 'Enterprise Publisher adapter admitted a response mutated after its r3 receipt.'

    $receiptMutation = New-EnterprisePublisherR3Fixture `
        -Root (Join-Path $testRoot 'receipt-mutation')
    $receipt = Read-StrictProductionJsonFile `
        -Path $receiptMutation.ReceiptPath `
        -Label 'Enterprise Publisher adapter receipt mutation fixture' `
        -SchemaPath $stateSchemaPath
    $receipt.Value.data.responseSha256 = 'f' * 64
    [IO.File]::Delete($receiptMutation.ReceiptPath)
    Write-TestCanonicalJson -Path $receiptMutation.ReceiptPath -Value $receipt.Value
    $receiptMutation.Arguments.OutputDirectory = Join-Path $testRoot 'receipt-mutation-output'
    $receiptMutationArguments = $receiptMutation.Arguments
    Assert-Throws `
        -Action { & $scriptPath @receiptMutationArguments | Out-Null } `
        -Message 'Enterprise Publisher adapter admitted a mutated r3 transition receipt.'

    $inputMutation = New-EnterprisePublisherR3Fixture `
        -Root (Join-Path $testRoot 'input-mutation')
    [IO.File]::AppendAllText(
        $inputMutation.RuntimeArchivePath,
        'mutation',
        [Text.UTF8Encoding]::new($false))
    $inputMutation.Arguments.OutputDirectory = Join-Path $testRoot 'input-mutation-output'
    $inputMutationArguments = $inputMutation.Arguments
    Assert-Throws `
        -Action { & $scriptPath @inputMutationArguments | Out-Null } `
        -Message 'Enterprise Publisher adapter admitted a runtime input whose hash differs from the plan.'
}
finally {
    $resolvedTestRoot = [IO.Path]::GetFullPath($testRoot)
    $resolvedTestParent = [IO.Path]::GetFullPath($testParent)
    if ($resolvedTestRoot.StartsWith(
            $resolvedTestParent + [IO.Path]::DirectorySeparatorChar,
            [StringComparison]::OrdinalIgnoreCase) -and
        [IO.Path]::GetFileName($resolvedTestRoot) -match '^[0-9a-f]{32}$' -and
        (Test-Path -LiteralPath $resolvedTestRoot -PathType Container)) {
        [IO.Directory]::Delete($resolvedTestRoot, $true)
    }
}

Write-Host 'Enterprise production Publisher adapter contract tests passed.'
