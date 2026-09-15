#requires -Version 7.2

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$modulePath = Join-Path $PSScriptRoot 'EnterpriseProductionPilotEvidence.psm1'
$stateModulePath = Join-Path $PSScriptRoot 'ProductionReleaseState.psm1'
$trustSchemaPath = Join-Path `
    $repositoryRoot `
    'release\schemas\enterprise-production-pilot-evidence-trust-v1.schema.json'
$verificationReportSchemaPath = Join-Path `
    $repositoryRoot `
    'release\schemas\enterprise-windows-pilot-verification-report-v2.schema.json'
$stableObservationSchemaPath = Join-Path `
    $repositoryRoot `
    'release\schemas\enterprise-production-stable-private-pilot-observation-v1.schema.json'
$stableFoundationFixturePath = Join-Path `
    $repositoryRoot `
    'release\fixtures\stable-private-pilot-promotion-v2\synthetic.no-go.json'
Microsoft.PowerShell.Core\Import-Module `
    -Name $modulePath `
    -Force `
    -ErrorAction Stop
Microsoft.PowerShell.Core\Import-Module `
    -Name $stateModulePath `
    -Force `
    -ErrorAction Stop

function Assert-CryptoTest {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )

    if (-not $Condition) {
        throw $Message
    }
}

function Copy-CryptoTestValue {
    param([Parameter(Mandatory = $true)]$Value)

    $bytes = [Text.UTF8Encoding]::new($false, $true).GetBytes(
        ($Value | ConvertTo-Json -Depth 100 -Compress))
    return ProductionReleaseState\ConvertFrom-StrictProductionJsonBytes `
        -Bytes $bytes `
        -Label 'Cryptography fixture copy'
}

function New-StableTestAttestation {
    param(
        [Parameter(Mandatory = $true)][string]$Purpose,
        [Parameter(Mandatory = $true)][string]$KeyId
    )

    return [pscustomobject][ordered]@{
        verificationStatus = 'VERIFIED'
        algorithm = 'ES256'
        encoding = 'IEEE-P1363'
        canonicalization = 'ENSOU-R8-CANONICAL-JSON-V1'
        lowS = $true
        purpose = $Purpose
        keyId = $KeyId
        payloadSha256 = '0' * 64
        signature = 'A' * 86
    }
}

function ConvertTo-LowS {
    param([Parameter(Mandatory = $true)][byte[]]$Signature)

    $halfOrder = [Convert]::FromHexString(
        '7FFFFFFF800000007FFFFFFFFFFFFFFFDE737D56D38BCF4279DCE5617E3192A8')
    $curveOrder = [Convert]::FromHexString(
        'FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551')
    $isHigh = $false
    for ($index = 0; $index -lt 32; $index++) {
        if ($Signature[$index + 32] -gt $halfOrder[$index]) {
            $isHigh = $true
            break
        }
        if ($Signature[$index + 32] -lt $halfOrder[$index]) {
            break
        }
    }
    if (-not $isHigh) {
        return $Signature
    }
    $low = [byte[]]$Signature.Clone()
    $borrow = 0
    for ($index = 31; $index -ge 0; $index--) {
        $difference = [int]$curveOrder[$index] -
            [int]$Signature[$index + 32] - $borrow
        if ($difference -lt 0) {
            $difference += 256
            $borrow = 1
        }
        else {
            $borrow = 0
        }
        $low[$index + 32] = [byte]$difference
    }
    return $low
}

function New-TestKey {
    param(
        [Parameter(Mandatory = $true)][string]$KeyId,
        [Parameter(Mandatory = $true)][string]$Purpose
    )

    $signer = [Security.Cryptography.ECDsa]::Create(
        [Security.Cryptography.ECCurve+NamedCurves]::nistP256)
    $point = $signer.ExportParameters($false).Q
    return [pscustomobject]@{
        Signer = $signer
        Public = [pscustomobject][ordered]@{
            algorithm = 'ES256'
            purpose = $Purpose
            keyId = $KeyId
            x = EnterpriseProductionPilotEvidence\ConvertTo-R8Base64Url `
                -Bytes $point.X
            y = EnterpriseProductionPilotEvidence\ConvertTo-R8Base64Url `
                -Bytes $point.Y
        }
    }
}

function New-TestSignature {
    param(
        [Parameter(Mandatory = $true)][Security.Cryptography.ECDsa]$Signer,
        [Parameter(Mandatory = $true)][byte[]]$Payload
    )

    $signature = $Signer.SignData(
        $Payload,
        [Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.DSASignatureFormat]::
            IeeeP1363FixedFieldConcatenation)
    return EnterpriseProductionPilotEvidence\ConvertTo-R8Base64Url `
        -Bytes (ConvertTo-LowS -Signature $signature)
}

function Assert-SignatureAccepts {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Payload,
        [Parameter(Mandatory = $true)][string]$Signature,
        [Parameter(Mandatory = $true)][psobject]$Key,
        [Parameter(Mandatory = $true)][string]$Purpose,
        [Parameter(Mandatory = $true)][string]$Label
    )

    EnterpriseProductionPilotEvidence\Assert-R8Es256Signature `
        -Payload $Payload `
        -SignatureValue $Signature `
        -Key $Key `
        -ExpectedKeyId ([string]$Key.keyId) `
        -ExpectedPurpose $Purpose `
        -Label $Label
}

function Assert-SignatureRejects {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Payload,
        [Parameter(Mandatory = $true)][string]$Signature,
        [Parameter(Mandatory = $true)][psobject]$Key,
        [Parameter(Mandatory = $true)][string]$Purpose,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $rejected = $false
    try {
        Assert-SignatureAccepts `
            -Payload $Payload `
            -Signature $Signature `
            -Key $Key `
            -Purpose $Purpose `
            -Label $Label
    }
    catch {
        $rejected = $true
    }
    Assert-CryptoTest $rejected "$Label was not rejected."
}

$keys = @()
try {
    $windowsKey = New-TestKey `
        'r8-windows' `
        'enterprise-windows-pilot-evidence-attestation'
    $verifierKey = New-TestKey `
        'r8-windows-verifier' `
        'enterprise-windows-pilot-verifier-report'
    $localKey = New-TestKey `
        'r8-local' `
        'enterprise-local-data-certification'
    $serverKey = New-TestKey `
        'r8-server' `
        'stable-private-pilot-server-attestation'
    $freshKey = New-TestKey `
        'r8-fresh' `
        'stable-private-pilot-device-attestation'
    $upgradeKey = New-TestKey `
        'r8-upgrade' `
        'stable-private-pilot-device-attestation'
    $controlKey = New-TestKey `
        'r8-control' `
        'stable-private-pilot-control-attestation'
    $installerKey = New-TestKey `
        'r8-installer-response' `
        'installer-signing-response'
    $keys = @(
        $windowsKey,
        $verifierKey,
        $localKey,
        $serverKey,
        $freshKey,
        $upgradeKey,
        $controlKey,
        $installerKey)

    $trust = [pscustomobject][ordered]@{
        schemaVersion = 1
        policyType =
            'ensou-dsh-enterprise-production-pilot-evidence-trust'
        environment = 'production'
        orchestrationId = '12345678-1234-4123-8123-123456789abc'
        maximumEvidenceAgeHours = 24
        minimumRemainingValidityMinutes = 30
        windowsPilotEvidence = $windowsKey.Public
        windowsPilotVerifier = $verifierKey.Public
        localDataCertification = $localKey.Public
        stablePrivatePilotKeys = [pscustomobject][ordered]@{
            server = $serverKey.Public
            freshInstallDevice = $freshKey.Public
            onlineUpgradeDevice = $upgradeKey.Public
            unauthorizedControl = $controlKey.Public
        }
    }
    $trustJson = $trust | ConvertTo-Json -Depth 20 -Compress
    Assert-CryptoTest `
        (Test-Json -Json $trustJson -SchemaFile $trustSchemaPath) `
        'Real public-key trust fixture does not satisfy the trust schema.'
    EnterpriseProductionPilotEvidence\Assert-R8PurposeSeparatedKeys `
        -Trust $trust `
        -InstallerSigningTrust $installerKey.Public

    $bodyBytes = [Text.UTF8Encoding]::new($false, $true).
        GetBytes('{"real":"windows-pilot"}')
    $bodySha = ([Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($bodyBytes))).
        ToLowerInvariant()
    $envelope = [pscustomobject][ordered]@{
        schemaVersion = 2
        evidenceType =
            'ensou-dsh-enterprise-windows-pilot-evidence-envelope'
        body = [pscustomobject][ordered]@{
            schemaVersion = 2
            evidenceType =
                'ensou-dsh-enterprise-windows-pilot-evidence-body'
            sizeBytes = $bodyBytes.Length
            sha256 = $bodySha
        }
        attestation = [pscustomobject][ordered]@{
            algorithm = 'ES256'
            keyId = $windowsKey.Public.keyId
            value = ''
        }
    }
    $windowsPayload =
        EnterpriseProductionPilotEvidence\Get-EnterpriseWindowsPilotAttestationPayload `
            -Envelope $envelope
    $windowsSignature = New-TestSignature `
        -Signer $windowsKey.Signer `
        -Payload $windowsPayload
    Assert-SignatureAccepts `
        -Payload $windowsPayload `
        -Signature $windowsSignature `
        -Key $windowsKey.Public `
        -Purpose 'enterprise-windows-pilot-evidence-attestation' `
        -Label 'Real Windows Pilot attestation'
    $tamperedWindows = [byte[]]$windowsPayload.Clone()
    $tamperedWindows[$tamperedWindows.Length - 1] =
        $tamperedWindows[$tamperedWindows.Length - 1] -bxor 1
    Assert-SignatureRejects `
        -Payload $tamperedWindows `
        -Signature $windowsSignature `
        -Key $windowsKey.Public `
        -Purpose 'enterprise-windows-pilot-evidence-attestation' `
        -Label 'Tampered Windows Pilot payload'

    $requiredVerifierChecks = @(
        'schema-set',
        'output-parent-lock',
        'strict-attested-body',
        'release-chain',
        'gate-time-and-tuples',
        'local-data-and-device-lanes',
        'readiness-schema-and-binding',
        'publisher-authenticode-and-compiled-trust',
        'signed-executable-inventory',
        'fresh-readiness-replay',
        'independent-attestation',
        'five-release-manifest-signatures',
        'live-pilot-head-signature')
    $verificationReport = [pscustomobject][ordered]@{
        schemaVersion = 2
        reportType =
            'ensou-dsh-enterprise-windows-pilot-verification-receipt'
        decision = 'VERIFIED'
        standaloneAdmissionEvidence = $false
        generatedAtUtc = '2026-09-02T00:00:00.0000000Z'
        evidenceEnvelopeSha256 = 'a' * 64
        evidenceBodySha256 = 'b' * 64
        pilotEvidenceKeyId = $windowsKey.Public.keyId
        publisherExecutableSha256 = 'c' * 64
        readinessReplayReportSha256 = 'd' * 64
        testRunId = '42345678-1234-4123-8123-123456789abc'
        customerAudienceId = '52345678-1234-4123-8123-123456789abc'
        targetReleaseSetId = 'enterprise-pilot-contract-5'
        targetGeneration = 5
        targetSequence = 104
        livePilotManifestSha256 = 'e' * 64
        verifiedReleaseManifestSha256 = @(
            ('1' * 64),
            ('2' * 64),
            ('3' * 64),
            ('4' * 64),
            ('5' * 64))
        checks = @($requiredVerifierChecks | ForEach-Object {
            [pscustomobject][ordered]@{
                id = $_
                status = 'PASS'
                evidence = "verified $_"
            }
        })
        failureCode = $null
        failureMessage = $null
        authentication = [pscustomobject][ordered]@{
            algorithm = 'ES256'
            purpose = 'enterprise-windows-pilot-verifier-report'
            keyId = $verifierKey.Public.keyId
            encoding = 'IEEE-P1363'
            canonicalization = 'ENSOU-R8-CANONICAL-JSON-V1'
            lowS = $true
            value = ''
        }
    }
    $verificationReport.authentication.value = New-TestSignature `
        -Signer $verifierKey.Signer `
        -Payload (EnterpriseProductionPilotEvidence\Get-EnterpriseWindowsPilotVerificationReportPayload `
            -Report $verificationReport)
    $verificationReportJson =
        $verificationReport | ConvertTo-Json -Depth 20 -Compress
    Assert-CryptoTest `
        (Test-Json `
            -Json $verificationReportJson `
            -SchemaFile $verificationReportSchemaPath) `
        'Authenticated VERIFIED report does not satisfy its exact schema.'
    EnterpriseProductionPilotEvidence\Assert-R8WindowsVerificationReportAuthentication `
        -Report $verificationReport `
        -Trust $trust

    $tamperedReport = Copy-CryptoTestValue -Value $verificationReport
    $tamperedReport.targetSequence++
    $tamperedReportRejected = $false
    try {
        EnterpriseProductionPilotEvidence\Assert-R8WindowsVerificationReportAuthentication `
            -Report $tamperedReport `
            -Trust $trust
    }
    catch {
        $tamperedReportRejected = $true
    }
    Assert-CryptoTest `
        $tamperedReportRejected `
        'A tampered Windows verifier report was not rejected.'

    $wrongVerifierTrust = $trustJson | ConvertFrom-Json -Depth 20
    $wrongVerifierTrust.windowsPilotVerifier = $serverKey.Public
    $wrongVerifierRejected = $false
    try {
        EnterpriseProductionPilotEvidence\Assert-R8WindowsVerificationReportAuthentication `
            -Report $verificationReport `
            -Trust $wrongVerifierTrust
    }
    catch {
        $wrongVerifierRejected = $true
    }
    Assert-CryptoTest `
        $wrongVerifierRejected `
        'A Windows verifier report accepted the wrong trust key.'

    $unsignedReport = Copy-CryptoTestValue -Value $verificationReport
    $unsignedReport.PSObject.Properties.Remove('authentication')
    $unsignedReportRejected = $false
    try {
        EnterpriseProductionPilotEvidence\Assert-R8WindowsVerificationReportAuthentication `
            -Report $unsignedReport `
            -Trust $trust
    }
    catch {
        $unsignedReportRejected = $true
    }
    Assert-CryptoTest `
        $unsignedReportRejected `
        'A missing Windows verifier report authentication was not rejected.'
    Assert-CryptoTest `
        (-not (Test-Json `
            -Json ($unsignedReport | ConvertTo-Json -Depth 20 -Compress) `
            -SchemaFile $verificationReportSchemaPath `
            -ErrorAction SilentlyContinue)) `
        'The report schema accepted a missing authentication.'

    $localReceipt = [pscustomobject][ordered]@{
        schemaVersion = 1
        receiptType =
            'ensou-dsh-enterprise-local-data-compatibility-certification'
        certificationId = '22345678-1234-4123-8123-123456789abc'
        decision = 'PASS'
        environment = 'production'
        channel = 'pilot'
        distributionScope = 'named-customer-pilot'
        certificationAudienceId = '32345678-1234-4123-8123-123456789abc'
        fromUpstreamTag = 'dsh-v1.0.0'
        toUpstreamTag = 'dsh-v1.1.0'
        sourceRuntimeZipSha256 = '1' * 64
        targetRuntimeZipSha256 = '2' * 64
        evidenceReportSha256 = '3' * 64
        runnerSha256 = '4' * 64
        issuedAtUnixSeconds = 1700000000
        expiresAtUnixSeconds = 1700086400
        signature = [pscustomobject][ordered]@{
            algorithm = 'ES256'
            keyId = $localKey.Public.keyId
            value = ''
        }
    }
    $localPayload =
        EnterpriseProductionPilotEvidence\Get-EnterpriseLocalDataCertificationPayload `
            -Receipt $localReceipt
    $localSignature = New-TestSignature `
        -Signer $localKey.Signer `
        -Payload $localPayload
    Assert-SignatureAccepts `
        -Payload $localPayload `
        -Signature $localSignature `
        -Key $localKey.Public `
        -Purpose 'enterprise-local-data-certification' `
        -Label 'Real local-data certification'
    $localReceipt.targetRuntimeZipSha256 = '5' * 64
    $tamperedLocalPayload =
        EnterpriseProductionPilotEvidence\Get-EnterpriseLocalDataCertificationPayload `
            -Receipt $localReceipt
    Assert-SignatureRejects `
        -Payload $tamperedLocalPayload `
        -Signature $localSignature `
        -Key $localKey.Public `
        -Purpose 'enterprise-local-data-certification' `
        -Label 'Tampered local-data receipt'

    $stableFoundation =
        ProductionReleaseState\ConvertFrom-StrictProductionJsonBytes `
            -Bytes ([IO.File]::ReadAllBytes($stableFoundationFixturePath)) `
            -Label 'Stable foundation fixture'
    $stableInstaller = Copy-CryptoTestValue `
        -Value $stableFoundation.r7.signedInstaller
    $stableInstaller.PSObject.Properties.Remove(
        'immutableInstallerIdentitySha256')
    $sourceBaseline = Copy-CryptoTestValue `
        -Value $stableFoundation.sourceBaseline
    $sourceBaseline.authenticode.verificationStatus = 'VERIFIED'
    $sourceBaseline.authenticode.status = 'Valid'
    $sourceBaseline.capabilityProbe = [pscustomobject][ordered]@{
        verificationStatus = 'VERIFIED'
        command = '--authenticated-stable-update-capability-self-check'
        arguments = @('--authenticated-stable-update-capability-self-check')
        exitCode = 0
        stdoutSizeBytes = 651
        stdoutSha256 =
            '5216e34e0a76cc1c20a8d23dd24ea69a2186c58c3044c20b5f912a4e13bcf005'
        sideEffectContract = 'no-secrets-no-network-no-mutation'
        networkRequests = 0
        filesWritten = 0
        persistentStateChanged = $false
        secretsEmitted = $false
        extraArgumentRejected = $true
    }
    $pluginPolicyObject = [pscustomobject][ordered]@{
        role = 'plugin-policy'
        fileName = 'enterprise-plugin-policy.zip'
        uri =
            'https://updates.ensou.example/v2/releases/stable-v2026.08.31.1/enterprise-plugin-policy.zip'
        objectVersionId = 'target-plugin-policy-v10'
        etag = '"target-plugin-policy-v10"'
        sizeBytes = 524288
        sha256 = '2828282828282828282828282828282828282828282828282828282828282828'
    }
    $targetRelease = Copy-CryptoTestValue `
        -Value $stableFoundation.targetRelease
    $targetRelease.signedInstaller = Copy-CryptoTestValue -Value $stableInstaller
    $targetRelease.artifacts = @($targetRelease.artifacts) +
        @(Copy-CryptoTestValue -Value $pluginPolicyObject)
    $devices = @(Copy-CryptoTestValue -Value $stableFoundation.privatePilot.devices)
    foreach ($device in $devices) {
        if ($null -ne $device.installerUsed) {
            $device.installerUsed.PSObject.Properties.Remove(
                'immutableInstallerIdentitySha256')
        }
        $device.observedObjects = @($device.observedObjects) +
            @(Copy-CryptoTestValue -Value $pluginPolicyObject)
    }
    $unauthorizedControl = [pscustomobject][ordered]@{
        deviceIdentitySha256 =
            [string]$stableFoundation.privatePilot.unauthorizedControl.deviceIdentitySha256
        inventorySha256 =
            [string]$stableFoundation.privatePilot.unauthorizedControl.inventorySha256
        authorized = $false
        canonicalManifestUri =
            [string]$stableFoundation.canonicalStableManifestUri
        authorizationDecision = 'prior-public-stable'
        httpStatus = 200
        observedReleaseSetId = [string]$sourceBaseline.releaseSetId
        observedManifestSha256 = [string]$sourceBaseline.manifest.sha256
        candidateBytesDisclosed = $false
        cacheControl = 'public, max-age=60'
        beforeObservedAtUtc = '2026-08-31T00:30:00Z'
        afterObservedAtUtc = '2026-08-31T03:30:00Z'
    }
    $observation = [pscustomobject][ordered]@{
        schemaVersion = 1
        observationType =
            'ensou-dsh-enterprise-stable-private-pilot-observation'
        observationMode = 'real-device-observation'
        orchestrationId = $trust.orchestrationId
        edition = 'Enterprise'
        product = 'ensou-dsh-enterprise'
        targetChannel = 'stable'
        exposureRing = 'private-pilot'
        canonicalStableManifestUri =
            [string]$stableFoundation.canonicalStableManifestUri
        r7 = [pscustomobject][ordered]@{
            revision = 7
            phase = 'INSTALLER_SIGNATURE_IMPORTED'
            headSha256 = [string]$stableFoundation.r7.headSha256
            receiptRelativePath =
                'receipts/0007-installer-signature-imported.json'
            receiptSha256 = [string]$stableFoundation.r7.receiptSha256
            signedInstaller = Copy-CryptoTestValue -Value $stableInstaller
        }
        sourceBaseline = $sourceBaseline
        targetRelease = $targetRelease
        privatePilot = [pscustomobject][ordered]@{
            allowlist = Copy-CryptoTestValue `
                -Value $stableFoundation.privatePilot.allowlist
            devices = $devices
            unauthorizedControl = $unauthorizedControl
        }
        attestations = [pscustomobject][ordered]@{
            server = New-StableTestAttestation `
                -Purpose 'stable-private-pilot-server-attestation' `
                -KeyId $serverKey.Public.keyId
            devices = @(
                (New-StableTestAttestation `
                    -Purpose 'stable-private-pilot-device-attestation' `
                    -KeyId $freshKey.Public.keyId),
                (New-StableTestAttestation `
                    -Purpose 'stable-private-pilot-device-attestation' `
                    -KeyId $upgradeKey.Public.keyId))
            unauthorizedControl = New-StableTestAttestation `
                -Purpose 'stable-private-pilot-control-attestation' `
                -KeyId $controlKey.Public.keyId
        }
        verificationStatus = [pscustomobject][ordered]@{
            authenticode = 'VERIFIED'
            rfc3161Timestamp = 'VERIFIED'
            baselineCapabilityProbe = 'VERIFIED'
            twoWindowsDevices = 'VERIFIED'
            authenticatedHttps = 'VERIFIED'
            deviceAttestations = 'VERIFIED'
            serverAttestation = 'VERIFIED'
            unauthorizedControl = 'VERIFIED'
        }
        collectedAtUtc = '2026-08-31T04:10:00Z'
        productionAdmission = 'NO_GO'
        nextRequiredGate = 'PILOT_EVIDENCE_BOUND'
    }
    EnterpriseProductionPilotEvidence\Assert-R8StableVerificationStatus `
        -VerificationStatus $observation.verificationStatus
    foreach ($verificationGate in @(
            'authenticode',
            'rfc3161Timestamp',
            'baselineCapabilityProbe',
            'twoWindowsDevices',
            'authenticatedHttps',
            'deviceAttestations',
            'serverAttestation',
            'unauthorizedControl')) {
        $tamperedStatus = $observation.verificationStatus.PSObject.Copy()
        $tamperedStatus.$verificationGate = 'REJECT'
        $tamperedStatusRejected = $false
        try {
            EnterpriseProductionPilotEvidence\Assert-R8StableVerificationStatus `
                -VerificationStatus $tamperedStatus
        }
        catch {
            $tamperedStatusRejected = $true
        }
        Assert-CryptoTest `
            $tamperedStatusRejected `
            "Stable verification gate '$verificationGate' was not rejected."
    }
    foreach ($canonicalField in @(
            'r7',
            'sourceBaseline',
            'targetRelease',
            'privatePilot',
            'attestations',
            'verificationStatus')) {
        try {
            [void](EnterpriseProductionPilotEvidence\ConvertTo-R8CanonicalJsonBytes `
                -Value $observation.$canonicalField)
        }
        catch {
            if ($canonicalField -ceq 'sourceBaseline') {
                foreach ($sourceProperty in $sourceBaseline.PSObject.Properties) {
                    try {
                        [void](EnterpriseProductionPilotEvidence\ConvertTo-R8CanonicalJsonBytes `
                            -Value $sourceProperty.Value)
                    }
                    catch {
                        throw "Stable source field '$($sourceProperty.Name)' failed: $($_.Exception.Message)"
                    }
                }
            }
            throw "Stable canonical field '$canonicalField' failed: $($_.Exception.Message)"
        }
    }
    $stableSubsetSha256 =
        EnterpriseProductionPilotEvidence\Get-EnterpriseStablePilotSubsetSha256 `
            -Observation $observation
    Assert-CryptoTest `
        ($stableSubsetSha256 -cmatch '^[0-9a-f]{64}$') `
        'Structured Stable verification status was not included in a canonical subset.'
    $stableCases = @(
        [pscustomobject]@{
            Role = 'server'
            Key = $serverKey
            Purpose = 'stable-private-pilot-server-attestation'
            Attestation = $observation.attestations.server
        },
        [pscustomobject]@{
            Role = 'fresh-install'
            Key = $freshKey
            Purpose = 'stable-private-pilot-device-attestation'
            Attestation = $observation.attestations.devices[0]
        },
        [pscustomobject]@{
            Role = 'online-upgrade'
            Key = $upgradeKey
            Purpose = 'stable-private-pilot-device-attestation'
            Attestation = $observation.attestations.devices[1]
        },
        [pscustomobject]@{
            Role = 'unauthorized-control'
            Key = $controlKey
            Purpose = 'stable-private-pilot-control-attestation'
            Attestation = $observation.attestations.unauthorizedControl
        })
    foreach ($case in $stableCases) {
        $payload =
            EnterpriseProductionPilotEvidence\Get-EnterpriseStablePilotAttestationPayload `
                -Observation $observation `
                -Role $case.Role
        $signature = New-TestSignature `
            -Signer $case.Key.Signer `
            -Payload $payload
        $case.Attestation.payloadSha256 = ([Convert]::ToHexString(
            [Security.Cryptography.SHA256]::HashData($payload))).
            ToLowerInvariant()
        $case.Attestation.signature = $signature
        EnterpriseProductionPilotEvidence\Assert-R8StableAttestation `
            -Attestation $case.Attestation `
            -Payload $payload `
            -Key $case.Key.Public `
            -Purpose $case.Purpose `
            -Label "Real Stable $($case.Role) attestation"
        Assert-SignatureAccepts `
            -Payload $payload `
            -Signature $signature `
            -Key $case.Key.Public `
            -Purpose $case.Purpose `
            -Label "Real Stable $($case.Role) attestation"
        $wrongKey = if ($case.Role -ceq 'server') {
            $freshKey.Public
        }
        else {
            $serverKey.Public
        }
        Assert-SignatureRejects `
            -Payload $payload `
            -Signature $signature `
            -Key $wrongKey `
            -Purpose ([string]$wrongKey.purpose) `
            -Label "Wrong-key Stable $($case.Role) attestation"
    }

    $stableObservationJson =
        $observation | ConvertTo-Json -Depth 100 -Compress
    Assert-CryptoTest `
        (Test-Json `
            -Json $stableObservationJson `
            -SchemaFile $stableObservationSchemaPath) `
        'Real signed Stable observation does not satisfy its exact schema.'

    $stableModule = Get-Module EnterpriseProductionPilotEvidence
    $stableTargetObjects = @($observation.targetRelease.manifest) +
        @($observation.targetRelease.artifacts)
    foreach ($mutation in @(
            [pscustomobject]@{
                Label = 'canonical endpoint'
                Apply = {
                    param($Value)
                    $Value.canonicalManifestUri =
                        'https://other.ensou.example/v2/channels/stable/release-set.v2.json'
                }
            },
            [pscustomobject]@{
                Label = 'object URI'
                Apply = {
                    param($Value)
                    $Value.observedObjects[2].uri =
                        'https://other.ensou.example/v2/releases/stable-v2026.08.31.1/enterprise-launcher.zip'
                }
            },
            [pscustomobject]@{
                Label = 'object version'
                Apply = {
                    param($Value)
                    $Value.observedObjects[2].objectVersionId =
                        'other-launcher-version'
                }
            },
            [pscustomobject]@{
                Label = 'object ETag'
                Apply = {
                    param($Value)
                    $Value.observedObjects[2].etag = '"other-launcher-etag"'
                }
            })) {
        $mutatedDevice = Copy-CryptoTestValue `
            -Value $observation.privatePilot.devices[0]
        & $mutation.Apply $mutatedDevice
        $stableDeviceCase = [pscustomobject]@{
            Device = $mutatedDevice
            Observation = $observation
            TargetObjects = $stableTargetObjects
            Installer = $observation.r7.signedInstaller
        }
        $mutationRejected = & $stableModule {
            param($Case)
            try {
                Assert-R8StableDevice `
                    -Device $Case.Device `
                    -ExpectedLane 'fresh-install' `
                    -Observation $Case.Observation `
                    -TargetObjects @($Case.TargetObjects) `
                    -InstallerAuthority $Case.Installer `
                    -Label 'Mutated Stable device'
                return $false
            }
            catch {
                return $true
            }
        } $stableDeviceCase
        Assert-CryptoTest `
            $mutationRejected `
            "Stable $($mutation.Label) metadata drift was not rejected."
    }

    $reusedTrust = $trust.PSObject.Copy()
    $reusedStableKeys = $trust.stablePrivatePilotKeys.PSObject.Copy()
    $reusedStableKeys.onlineUpgradeDevice = $freshKey.Public
    $reusedTrust.stablePrivatePilotKeys = $reusedStableKeys
    $reusedRejected = $false
    try {
        EnterpriseProductionPilotEvidence\Assert-R8PurposeSeparatedKeys `
            -Trust $reusedTrust `
            -InstallerSigningTrust $installerKey.Public
    }
    catch {
        $reusedRejected = $true
    }
    Assert-CryptoTest `
        $reusedRejected `
        'A reused fresh/upgrade Pilot key was not rejected.'

    $reusedVerifierTrust = $trustJson | ConvertFrom-Json -Depth 20
    $reusedVerifierTrust.windowsPilotVerifier = $windowsKey.Public
    $reusedVerifierRejected = $false
    try {
        EnterpriseProductionPilotEvidence\Assert-R8PurposeSeparatedKeys `
            -Trust $reusedVerifierTrust `
            -InstallerSigningTrust $installerKey.Public
    }
    catch {
        $reusedVerifierRejected = $true
    }
    Assert-CryptoTest `
        $reusedVerifierRejected `
        'A reused Windows evidence/verifier key was not rejected.'
}
finally {
    foreach ($key in $keys) {
        $key.Signer.Dispose()
    }
}

Write-Output 'ENTERPRISE-PRODUCTION-PILOT-EVIDENCE-CRYPTOGRAPHY-PASS'
