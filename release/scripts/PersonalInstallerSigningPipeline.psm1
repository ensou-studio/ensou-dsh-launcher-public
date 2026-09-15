#requires -Version 7.2

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:RepositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$script:SchemaRoot = Join-Path $script:RepositoryRoot 'release\schemas'
$script:StateModulePath = Join-Path $PSScriptRoot 'ProductionReleaseState.psm1'
$script:ContractsModulePath = Join-Path $PSScriptRoot 'InstallerSigningContracts.psm1'
$script:SelfCheckModulePath = Join-Path `
    $PSScriptRoot `
    'PersonalInstallerProductionPayloadSelfCheck.psm1'
$script:PlanSchemaPath = Join-Path `
    $script:SchemaRoot `
    'launcher-production-release-plan-v2.schema.json'
$script:StateSchemaPath = Join-Path `
    $script:SchemaRoot `
    'launcher-production-release-state-v2.schema.json'
$script:PersonalRequestSchemaPath = Join-Path `
    $script:SchemaRoot `
    'personal-installer-signing-request-v2.schema.json'
$script:PersonalEvidenceSchemaPath = Join-Path `
    $script:SchemaRoot `
    'personal-installer-trusted-build-evidence-v1.schema.json'
$script:SharedRequestSchemaPath = Join-Path `
    $script:SchemaRoot `
    'launcher-installer-signing-request-v2.schema.json'
$script:PersonalResponseSchemaPath = Join-Path `
    $script:SchemaRoot `
    'personal-installer-signing-response-v2.schema.json'
$script:TrustedBuildDraftBlocker =
    'INSTALLER_SIGNING_RESPONSE_REQUIRED'
$script:SharedRequestCompatibilityBlocker =
    'PERSONAL_R6_SHARED_REQUEST_CONTRACT_NOT_COMPATIBLE'
$script:SharedRequestPath =
    'requests/installer-signing.v2/installer-signing-request.v2.json'
$script:R6ReceiptPath = 'receipts/0006-installer-signing-requested.json'
$script:MaximumJsonBytes = 64MB
$script:MaximumInstallerBytes = 1GB
$script:Utf8Strict = [Text.UTF8Encoding]::new($false, $true)

Microsoft.PowerShell.Core\Import-Module `
    $script:ContractsModulePath -Force -ErrorAction Stop
Microsoft.PowerShell.Core\Import-Module `
    $script:SelfCheckModulePath -Force -ErrorAction Stop
Microsoft.PowerShell.Core\Import-Module `
    $script:StateModulePath -Force -ErrorAction Stop

function Throw-PersonalSigningPipelineFailure {
    param(
        [Parameter(Mandatory = $true)][string]$Code,
        [Parameter(Mandatory = $true)][string]$Message,
        [Exception]$InnerException
    )

    $fullMessage = "${Code}: $Message"
    if ($null -eq $InnerException) {
        throw [IO.InvalidDataException]::new($fullMessage)
    }
    throw [IO.InvalidDataException]::new($fullMessage, $InnerException)
}

function Test-PersonalSigningPipelineSha256 {
    param([AllowNull()]$Value)

    return $Value -is [string] -and
        [string]$Value -cmatch '^[0-9a-f]{64}$'
}

function Assert-PersonalSigningPipelineHost {
    if (-not $IsWindows -or
        [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -ne
            [Runtime.InteropServices.Architecture]::X64) {
        Throw-PersonalSigningPipelineFailure `
            -Code 'PERSONAL_SIGNING_PIPELINE_HOST_INVALID' `
            -Message 'Personal Installer signing admission requires Windows x64.'
    }
}

function Assert-PersonalSigningPipelineDescriptor {
    param(
        [Parameter(Mandatory = $true)]$Descriptor,
        [Parameter(Mandatory = $true)][string]$Label,
        [int64]$MaximumBytes = $script:MaximumJsonBytes
    )

    foreach ($name in @(
            'Path', 'FileName', 'SizeBytes', 'Sha256', 'Stream',
            'VolumeSerialNumber', 'FileIndex')) {
        if ($null -eq $Descriptor.PSObject.Properties[$name]) {
            Throw-PersonalSigningPipelineFailure `
                -Code 'PERSONAL_SIGNING_PIPELINE_INPUT_NOT_HELD' `
                -Message "$Label has no held-input member '$name'."
        }
    }
    if (-not [IO.Path]::IsPathFullyQualified([string]$Descriptor.Path) -or
        [int64]$Descriptor.SizeBytes -le 0 -or
        [int64]$Descriptor.SizeBytes -gt $MaximumBytes -or
        -not (Test-PersonalSigningPipelineSha256 -Value $Descriptor.Sha256) -or
        $Descriptor.Stream -isnot [IO.Stream] -or
        -not $Descriptor.Stream.CanRead -or
        -not $Descriptor.Stream.CanSeek) {
        Throw-PersonalSigningPipelineFailure `
            -Code 'PERSONAL_SIGNING_PIPELINE_INPUT_NOT_HELD' `
            -Message "$Label is not one bounded, locked ordinary-file descriptor."
    }
    try {
        [void](ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
                -Descriptor $Descriptor `
                -Label $Label)
    }
    catch {
        Throw-PersonalSigningPipelineFailure `
            -Code 'PERSONAL_SIGNING_PIPELINE_INPUT_CHANGED' `
            -Message "$Label changed or lost its immutable file lease." `
            -InnerException $_.Exception
    }
}

function Read-PersonalSigningPipelineHeldJson {
    param(
        [Parameter(Mandatory = $true)]$Descriptor,
        [Parameter(Mandatory = $true)][string]$SchemaPath,
        [Parameter(Mandatory = $true)][string]$Label
    )

    Assert-PersonalSigningPipelineDescriptor `
        -Descriptor $Descriptor `
        -Label $Label `
        -MaximumBytes $script:MaximumJsonBytes
    try {
        [byte[]]$bytes =
            ProductionReleaseState\Read-ProductionReleaseInputBytes `
                -Descriptor $Descriptor `
                -Label $Label
        $value = ProductionReleaseState\ConvertFrom-StrictProductionJsonBytes `
            -Bytes $bytes `
            -SchemaPath $SchemaPath `
            -Label $Label
        $input = [pscustomobject]@{
            Value = $value
            Bytes = $bytes
            Sha256 = [string]$Descriptor.Sha256
        }
        [void](ProductionReleaseState\Assert-CanonicalProductionJsonInput `
                -JsonInput $input `
                -Label $Label)
        [void](ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
                -Descriptor $Descriptor `
                -Label $Label)
        return $input
    }
    catch {
        if ($_.Exception.Message -cmatch '^PERSONAL_SIGNING_PIPELINE_') {
            throw
        }
        Throw-PersonalSigningPipelineFailure `
            -Code 'PERSONAL_SIGNING_PIPELINE_JSON_INVALID' `
            -Message "$Label is not exact canonical schema-valid JSON held by the caller." `
            -InnerException $_.Exception
    }
}

function Test-PersonalSigningPipelineObjectEqual {
    param(
        [Parameter(Mandatory = $true)]$Left,
        [Parameter(Mandatory = $true)]$Right
    )

    return (InstallerSigningContracts\Get-InstallerSigningObjectSha256 `
            -Value $Left) -ceq
        (InstallerSigningContracts\Get-InstallerSigningObjectSha256 `
            -Value $Right)
}

function Get-PersonalSigningPipelineOrigin {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $uri = $null
    if (-not [Uri]::TryCreate($Value, [UriKind]::Absolute, [ref]$uri) -or
        $uri.Scheme -cne 'https' -or $uri.IsLoopback -or
        -not [string]::IsNullOrEmpty($uri.UserInfo) -or
        -not [string]::IsNullOrEmpty($uri.Fragment)) {
        Throw-PersonalSigningPipelineFailure `
            -Code 'PERSONAL_SIGNING_PIPELINE_PLAN_BINDING_INVALID' `
            -Message "$Label is not one production HTTPS URI."
    }
    return $uri.GetLeftPart([UriPartial]::Authority) + '/'
}

function Get-PersonalSigningPipelinePayloadFile {
    param(
        [Parameter(Mandatory = $true)][object[]]$Files,
        [Parameter(Mandatory = $true)][string]$Role,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $matches = @($Files | Where-Object { [string]$_.role -ceq $Role })
    if ($matches.Count -ne 1) {
        Throw-PersonalSigningPipelineFailure `
            -Code 'PERSONAL_SIGNING_PIPELINE_CLOSURE_INVALID' `
            -Message "$Label does not contain exactly one '$Role' file."
    }
    return $matches[0]
}

function Assert-PersonalSigningPipelineTrustedBuild {
    param([Parameter(Mandatory = $true)]$TrustedBuildResult)

    foreach ($name in @(
            'Status', 'Blocker', 'ProductionAdmission', 'OutputDirectory',
            'Request', 'RequestInput', 'Evidence', 'EvidenceInput',
            'UnsignedInstallerInput', 'LockedOutputs')) {
        if ($null -eq $TrustedBuildResult.PSObject.Properties[$name]) {
            Throw-PersonalSigningPipelineFailure `
                -Code 'PERSONAL_SIGNING_PIPELINE_TRUSTED_BUILD_INVALID' `
                -Message "Trusted build result omits '$name'."
        }
    }
    if ([string]$TrustedBuildResult.Status -cne
            'SIGNING_REQUEST_READY_NO_GO' -or
        [string]$TrustedBuildResult.Blocker -cne
            $script:TrustedBuildDraftBlocker -or
        [string]$TrustedBuildResult.ProductionAdmission -cne 'NO_GO') {
        Throw-PersonalSigningPipelineFailure `
            -Code 'PERSONAL_SIGNING_PIPELINE_TRUSTED_BUILD_INVALID' `
            -Message 'Trusted build result is not the exact fail-closed Personal builder output.'
    }

    $requestInput = Read-PersonalSigningPipelineHeldJson `
        -Descriptor $TrustedBuildResult.RequestInput `
        -SchemaPath $script:PersonalRequestSchemaPath `
        -Label 'Personal Installer signing request draft v2'
    $evidenceInput = Read-PersonalSigningPipelineHeldJson `
        -Descriptor $TrustedBuildResult.EvidenceInput `
        -SchemaPath $script:PersonalEvidenceSchemaPath `
        -Label 'Personal Installer trusted-build evidence v1'
    $request = $requestInput.Value
    $evidence = $evidenceInput.Value

    if (-not (Test-PersonalSigningPipelineObjectEqual `
            -Left $TrustedBuildResult.Request `
            -Right $request) -or
        -not (Test-PersonalSigningPipelineObjectEqual `
            -Left $TrustedBuildResult.Evidence `
            -Right $evidence)) {
        Throw-PersonalSigningPipelineFailure `
            -Code 'PERSONAL_SIGNING_PIPELINE_TRUSTED_BUILD_INVALID' `
            -Message 'Trusted build in-memory values differ from their held canonical files.'
    }

    if ([string]$request.admission.status -cne 'READY' -or
        [string]$request.admission.blocker -cne
            $script:TrustedBuildDraftBlocker -or
        [string]$request.admission.productionAdmission -cne 'NO_GO' -or
        [string]$evidence.signingRequestEligibility.status -cne 'READY' -or
        [string]$evidence.signingRequestEligibility.blocker -cne
            $script:TrustedBuildDraftBlocker -or
        [string]$evidence.signingRequestEligibility.productionAdmission -cne
            'NO_GO' -or
        [string]$request.channel -cne 'pilot' -or
        [string]$evidence.channel -cne 'pilot' -or
        [string]$request.basePhase -cne
            'PILOT_SIGNED_CANDIDATE_IMPORTED' -or
        [string]$request.buildExecution.unsignedArtifactExecution -cne
            'FORBIDDEN_AND_NOT_PERFORMED' -or
        [string]$evidence.buildExecution.unsignedArtifactExecution -cne
            'FORBIDDEN_AND_NOT_PERFORMED') {
        Throw-PersonalSigningPipelineFailure `
            -Code 'PERSONAL_SIGNING_PIPELINE_TRUSTED_BUILD_INVALID' `
            -Message 'Trusted build no longer carries its exact NO_GO and unsigned zero-execution evidence.'
    }

    foreach ($pair in @(
            [pscustomobject]@{ Left = $request.source; Right = $evidence.source },
            [pscustomobject]@{ Left = $request.payload; Right = $evidence.payload },
            [pscustomobject]@{ Left = $request.compiledTrust; Right = $evidence.compiledTrust },
            [pscustomobject]@{ Left = $request.toolchain.packageClosure; Right = $evidence.packageClosure },
            [pscustomobject]@{ Left = $request.toolchain.sdkClosure; Right = $evidence.sdkClosure },
            [pscustomobject]@{ Left = $request.buildExecution; Right = $evidence.buildExecution },
            [pscustomobject]@{ Left = $request.unsignedInstaller; Right = $evidence.unsignedInstaller },
            [pscustomobject]@{ Left = $request.resourceBinding; Right = $evidence.resourceBinding })) {
        if (-not (Test-PersonalSigningPipelineObjectEqual `
                -Left $pair.Left `
                -Right $pair.Right)) {
            Throw-PersonalSigningPipelineFailure `
                -Code 'PERSONAL_SIGNING_PIPELINE_TRUSTED_BUILD_INVALID' `
                -Message 'Personal request and trusted-build evidence do not close the same source, payload, trust, toolchain, build, and unsigned-byte tuple.'
        }
    }
    if ([int64]$request.trustedBuildEvidence.sizeBytes -ne
            [int64]$evidenceInput.Bytes.LongLength -or
        [string]$request.trustedBuildEvidence.sha256 -cne
            [string]$evidenceInput.Sha256 -or
        [string]$request.resourceBinding.unsignedInstallerSha256 -cne
            [string]$request.unsignedInstaller.sha256 -or
        [string]$request.toolchain.toolchainIdentitySha256 -cne
            (InstallerSigningContracts\Get-InstallerSigningObjectSha256 `
                -Value ([ordered]@{
                    packageClosure = $request.toolchain.packageClosure
                    sdkClosure = $request.toolchain.sdkClosure
                }))) {
        Throw-PersonalSigningPipelineFailure `
            -Code 'PERSONAL_SIGNING_PIPELINE_TRUSTED_BUILD_INVALID' `
            -Message 'Trusted-build evidence, resource, or toolchain identity is not exact.'
    }

    $outputRoot = [IO.Path]::GetFullPath(
        [string]$TrustedBuildResult.OutputDirectory)
    $expectedRequestPath = Join-Path `
        $outputRoot `
        'personal-installer-signing-request.v2.json'
    $expectedEvidencePath = Join-Path `
        (Join-Path $outputRoot 'trusted-build') `
        'trusted-build-evidence.v1.json'
    $expectedUnsignedPath = Join-Path `
        (Join-Path $outputRoot 'unsigned') `
        'Ensou.Dsh.Personal.Installer.exe'
    if (-not ([string]$TrustedBuildResult.RequestInput.Path).Equals(
            $expectedRequestPath, [StringComparison]::OrdinalIgnoreCase) -or
        -not ([string]$TrustedBuildResult.EvidenceInput.Path).Equals(
            $expectedEvidencePath, [StringComparison]::OrdinalIgnoreCase) -or
        -not ([string]$TrustedBuildResult.UnsignedInstallerInput.Path).Equals(
            $expectedUnsignedPath, [StringComparison]::OrdinalIgnoreCase)) {
        Throw-PersonalSigningPipelineFailure `
            -Code 'PERSONAL_SIGNING_PIPELINE_TRUSTED_BUILD_INVALID' `
            -Message 'Trusted build outputs escape their exact private Personal bundle paths.'
    }

    Assert-PersonalSigningPipelineDescriptor `
        -Descriptor $TrustedBuildResult.UnsignedInstallerInput `
        -Label 'Held unsigned Personal Installer' `
        -MaximumBytes $script:MaximumInstallerBytes
    try {
        [void](InstallerSigningContracts\Assert-UnsignedInstallerSigningInput `
                -Path ([string]$TrustedBuildResult.UnsignedInstallerInput.Path) `
                -Descriptor $request.unsignedInstaller)
    }
    catch {
        Throw-PersonalSigningPipelineFailure `
            -Code 'PERSONAL_SIGNING_PIPELINE_UNSIGNED_INVALID' `
            -Message 'Held Personal Installer is not the exact unsigned request input.' `
            -InnerException $_.Exception
    }
    foreach ($descriptor in @($TrustedBuildResult.LockedOutputs)) {
        Assert-PersonalSigningPipelineDescriptor `
            -Descriptor $descriptor `
            -Label "Personal trusted-build output '$($descriptor.FileName)'" `
            -MaximumBytes 8GB
    }

    return [pscustomobject]@{
        RequestInput = $requestInput
        EvidenceInput = $evidenceInput
        Request = $request
        Evidence = $evidence
    }
}

function Assert-PersonalSigningPipelinePlanBinding {
    param(
        [Parameter(Mandatory = $true)]$PlanInput,
        [Parameter(Mandatory = $true)][psobject]$Request
    )

    $plan = $PlanInput.Value
    $installerTrust = $plan.externalResponseTrusts.installerSigning
    $releaseTrust = $plan.releaseManifestTrust
    $manifestOrigin = Get-PersonalSigningPipelineOrigin `
        -Value ([string]$plan.manifestUri) `
        -Label 'Personal plan manifest URI'
    $artifactOrigin = Get-PersonalSigningPipelineOrigin `
        -Value ([string]$plan.artifactBaseUri) `
        -Label 'Personal plan artifact URI'
    $releasePublicIdentity = [ordered]@{
        algorithm = [string]$releaseTrust.algorithm
        keyId = [string]$releaseTrust.keyId
        x = [string]$releaseTrust.x
        y = [string]$releaseTrust.y
    }
    if ([string]$plan.edition -cne 'Personal' -or
        [string]$plan.targetChannel -cne 'pilot' -or
        [string]$Request.edition -cne 'Personal' -or
        [string]$Request.channel -cne 'pilot' -or
        [string]$Request.planSha256 -cne [string]$PlanInput.Sha256 -or
        [string]$Request.orchestrationId -cne [string]$plan.orchestrationId -or
        [string]$Request.releaseSetId -cne [string]$plan.releaseSetId -or
        [string]$Request.channel -cne [string]$plan.targetChannel -or
        [string]$Request.source.commit -cne [string]$plan.sourceCommit -or
        [string]$Request.compiledTrust.channel -cne [string]$plan.targetChannel -or
        [string]$Request.compiledTrust.manifestOrigin -cne $manifestOrigin -or
        [string]$Request.compiledTrust.artifactOrigin -cne $artifactOrigin -or
        [string]$Request.compiledTrust.releaseKeyId -cne
            [string]$releaseTrust.keyId -or
        [string]$Request.compiledTrust.releaseKeyIdentitySha256 -cne
            (InstallerSigningContracts\Get-InstallerSigningObjectSha256 `
                -Value $releasePublicIdentity) -or
        [string]$Request.compiledTrust.authenticodeSignerSha256Thumbprint -cne
            [string]$plan.authenticodePolicy.signerSha256Thumbprint -or
        [int]$Request.responseAuthentication.maximumResponseAgeMinutes -ne
            [int]$plan.authenticodePolicy.maximumResponseAgeMinutes -or
        [string]$Request.responseAuthentication.algorithm -cne 'ES256' -or
        [string]$Request.responseAuthentication.keyId -cne
            [string]$installerTrust.keyId -or
        [string]$installerTrust.purpose -cne
            'personal-installer-signing-response' -or
        [string]$Request.responseAuthentication.purpose -cne
            'personal-installer-signing-response' -or
        [string]$Request.responseAuthentication.payloadType -cne
            'ensou-dsh-personal-installer-signing-response-authentication-v2' -or
        [string]$Request.responseAuthentication.trustSha256 -cne
            (InstallerSigningContracts\Get-InstallerSigningObjectSha256 `
                -Value $installerTrust)) {
        Throw-PersonalSigningPipelineFailure `
            -Code 'PERSONAL_SIGNING_PIPELINE_PLAN_BINDING_INVALID' `
            -Message 'Personal builder request differs from the exact plan, compiled trust, or isolated Installer response trust.'
    }

    try {
        $installerPoint =
            ProductionReleaseState\Get-ProductionReleaseP256PublicKeyIdentity `
                -Trust $installerTrust `
                -Label 'Personal Installer-signing response trust'
        $releasePoint =
            ProductionReleaseState\Get-ProductionReleaseP256PublicKeyIdentity `
                -Trust $releaseTrust `
                -Label 'Personal release-manifest trust'
        if ([string]$installerTrust.keyId -ceq [string]$releaseTrust.keyId -or
            [string]$installerPoint -ceq [string]$releasePoint) {
            throw 'Installer response and release-manifest trust domains are not independent.'
        }
    }
    catch {
        Throw-PersonalSigningPipelineFailure `
            -Code 'PERSONAL_SIGNING_PIPELINE_PLAN_BINDING_INVALID' `
            -Message 'Personal response trust is not a valid isolated P-256 domain.' `
            -InnerException $_.Exception
    }

    try {
        $created = ProductionReleaseState\ConvertFrom-ProductionUtc `
            -Value ([string]$Request.createdAtUtc) `
            -Label 'Personal Installer request creation time'
        $expires = ProductionReleaseState\ConvertFrom-ProductionUtc `
            -Value ([string]$Request.expiresAtUtc) `
            -Label 'Personal Installer request expiry time'
        $buildStarted = ProductionReleaseState\ConvertFrom-ProductionUtc `
            -Value ([string]$Request.buildExecution.startedAtUtc) `
            -Label 'Personal Installer build start time'
        $buildCompleted = ProductionReleaseState\ConvertFrom-ProductionUtc `
            -Value ([string]$Request.buildExecution.completedAtUtc) `
            -Label 'Personal Installer build completion time'
        if ($expires -le $created -or
            ($expires - $created) -ne [TimeSpan]::FromMinutes(
                [int]$Request.responseAuthentication.maximumResponseAgeMinutes) -or
            $buildStarted -gt $buildCompleted -or
            $buildCompleted -gt $created -or
            [DateTimeOffset]::UtcNow -gt $expires) {
            throw 'Request or build time is stale or outside its exact window.'
        }
    }
    catch {
        Throw-PersonalSigningPipelineFailure `
            -Code 'PERSONAL_SIGNING_PIPELINE_REQUEST_LIFETIME_INVALID' `
            -Message 'Personal signing request does not have one live exact response window.' `
            -InnerException $_.Exception
    }
    return $true
}

function Assert-PersonalSigningPipelineR5CasBinding {
    param(
        [Parameter(Mandatory = $true)][psobject]$PlanInput,
        [Parameter(Mandatory = $true)][psobject]$HeadInput,
        [Parameter(Mandatory = $true)][psobject]$ReceiptInput,
        [Parameter(Mandatory = $true)][psobject]$Request,
        [Parameter(Mandatory = $true)][string]$ExpectedR5HeadSha256
    )

    if (-not (Test-PersonalSigningPipelineSha256 `
            -Value $ExpectedR5HeadSha256)) {
        Throw-PersonalSigningPipelineFailure `
            -Code 'PERSONAL_SIGNING_PIPELINE_R5_CAS_INVALID' `
            -Message 'Expected r5 head is not one lowercase SHA-256 value.'
    }
    $plan = $PlanInput.Value
    $head = $HeadInput.Value
    $receipt = $ReceiptInput.Value
    $channel = [string]$plan.targetChannel
    if ($channel -cne 'pilot' -or [string]$Request.channel -cne 'pilot') {
        Throw-PersonalSigningPipelineFailure `
            -Code 'PERSONAL_SIGNING_PIPELINE_STABLE_NOT_SUPPORTED' `
            -Message 'The current Personal signing pipeline supports Pilot only.'
    }
    $expectedPhase = 'PILOT_SIGNED_CANDIDATE_IMPORTED'
    $expectedReceiptFileName = '0005-pilot-signed-candidate-imported.json'
    if ([string]$HeadInput.Sha256 -cne $ExpectedR5HeadSha256 -or
        [string]$Request.baseHeadSha256 -cne $ExpectedR5HeadSha256 -or
        [int]$Request.baseRevision -ne 5 -or
        [string]$Request.basePhase -cne $expectedPhase -or
        [int]$Request.requestedRevision -ne 6 -or
        [int]$head.schemaVersion -ne 2 -or
        [string]$head.stateType -cne
            'ensou-dsh-launcher-production-release-head' -or
        [string]$head.orchestrationId -cne [string]$plan.orchestrationId -or
        [string]$head.edition -cne 'Personal' -or
        [string]$head.targetChannel -cne $channel -or
        [string]$head.planSha256 -cne [string]$PlanInput.Sha256 -or
        [int]$head.revision -ne 5 -or
        [string]$head.phase -cne $expectedPhase -or
        [string]$head.receiptFileName -cne $expectedReceiptFileName -or
        [string]$head.receiptSha256 -cne [string]$ReceiptInput.Sha256 -or
        [int]$receipt.schemaVersion -ne 2 -or
        [string]$receipt.receiptType -cne
            'ensou-dsh-launcher-production-release-transition' -or
        [string]$receipt.orchestrationId -cne [string]$plan.orchestrationId -or
        [string]$receipt.edition -cne 'Personal' -or
        [string]$receipt.targetChannel -cne $channel -or
        [string]$receipt.planSha256 -cne [string]$PlanInput.Sha256 -or
        [int]$receipt.revision -ne 5 -or
        [string]$receipt.phase -cne $expectedPhase -or
        [string]$receipt.recordedAtUtc -cne [string]$head.updatedAtUtc) {
        Throw-PersonalSigningPipelineFailure `
            -Code 'PERSONAL_SIGNING_PIPELINE_R5_CAS_INVALID' `
            -Message 'Personal request is not bound to the exact r5 head, receipt, plan, phase, and compare-and-swap hash.'
    }

    $candidateFiles = @($receipt.data.files)
    $payloadFiles = @($Request.payload.files)
    $expectedRoles = @('release-manifest', 'client-bundle', 'runtime')
    if ($candidateFiles.Count -ne $expectedRoles.Count) {
        Throw-PersonalSigningPipelineFailure `
            -Code 'PERSONAL_SIGNING_PIPELINE_R5_CLOSURE_INVALID' `
            -Message 'Personal r5 candidate does not contain its exact three-file closure.'
    }
    foreach ($index in 0..($expectedRoles.Count - 1)) {
        $role = $expectedRoles[$index]
        $candidate = $candidateFiles[$index]
        $payload = Get-PersonalSigningPipelinePayloadFile `
            -Files $payloadFiles `
            -Role $role `
            -Label 'Personal trusted-build payload'
        if ([string]$candidate.role -cne $role -or
            [string]$candidate.fileName -cne [string]$payload.fileName -or
            [string]$candidate.relativePath -cne
                "imports/$channel-signed-candidate.v1/candidate/$($payload.fileName)" -or
            [int64]$candidate.sizeBytes -ne [int64]$payload.sizeBytes -or
            [string]$candidate.sha256 -cne [string]$payload.sha256) {
            Throw-PersonalSigningPipelineFailure `
                -Code 'PERSONAL_SIGNING_PIPELINE_R5_CLOSURE_INVALID' `
                -Message "Personal r5 candidate role '$role' differs from the exact embedded payload bytes."
        }
    }
    $manifest = Get-PersonalSigningPipelinePayloadFile `
        -Files $payloadFiles `
        -Role 'release-manifest' `
        -Label 'Personal trusted-build payload'
    if ([string]$receipt.data.manifestSha256 -cne
            [string]$manifest.sha256 -or
        [string]$receipt.data.releaseManifestTrustSha256 -cne
            (InstallerSigningContracts\Get-InstallerSigningObjectSha256 `
                -Value $plan.releaseManifestTrust) -or
        [string]$receipt.data.compiledReleaseTrustStatus -cne 'VERIFIED' -or
        [string]$receipt.data.productionAdmission -cne 'NO_GO') {
        Throw-PersonalSigningPipelineFailure `
            -Code 'PERSONAL_SIGNING_PIPELINE_R5_CLOSURE_INVALID' `
            -Message 'Personal r5 receipt does not preserve the exact manifest trust and fail-closed candidate evidence.'
    }
    return $true
}

function Get-PersonalSigningPipelineSharedRequestCapability {
    try {
        $schemaPath = ProductionReleaseState\Resolve-OrdinaryProductionFile `
            -Path $script:SharedRequestSchemaPath `
            -Label 'Shared Installer request v2 schema'
        [byte[]]$schemaBytes = [IO.File]::ReadAllBytes($schemaPath)
        $schema = ProductionReleaseState\ConvertFrom-StrictProductionJsonBytes `
            -Bytes $schemaBytes `
            -Label 'Shared Installer request v2 schema'
        $personalIdentities = [Collections.Generic.List[object]]::new()
        foreach ($branch in @($schema.oneOf)) {
            if ($null -eq $branch.PSObject.Properties['allOf']) { continue }
            foreach ($clause in @($branch.allOf)) {
                if ($null -ne $clause.PSObject.Properties['properties'] -and
                    [string]$clause.properties.edition.const -ceq 'Personal') {
                    $personalIdentities.Add($clause.properties)
                }
            }
        }
        $schemaPersonalPilot = $personalIdentities.Count -eq 1 -and
            [string]$personalIdentities[0].edition.const -ceq 'Personal' -and
            [string]$personalIdentities[0].channel.const -ceq 'pilot'
        $schemaRejectsPersonalStable = @($personalIdentities | Where-Object {
                [string]$_.channel.const -ceq 'stable'
            }).Count -eq 0
        $validatorPersonalPilot = $true
        try {
            [void](InstallerSigningContracts\Assert-InstallerSigningRequestContract `
                    -Request ([pscustomobject]@{
                        schemaVersion = 2
                        edition = 'Personal'
                        channel = 'pilot'
                    }))
        }
        catch {
            if ($_.Exception.Message -ceq
                'Installer-signing request edition/channel identity is invalid.') {
                $validatorPersonalPilot = $false
            }
        }
        $validatorRejectsPersonalStable = $false
        try {
            [void](InstallerSigningContracts\Assert-InstallerSigningRequestContract `
                    -Request ([pscustomobject]@{
                        schemaVersion = 2
                        edition = 'Personal'
                        channel = 'stable'
                    }))
        }
        catch {
            if ($_.Exception.Message -ceq
                'Installer-signing request edition/channel identity is invalid.') {
                $validatorRejectsPersonalStable = $true
            }
        }
        return [pscustomobject][ordered]@{
            IsCompatible = [bool]($schemaPersonalPilot -and
                $schemaRejectsPersonalStable -and
                $validatorPersonalPilot -and
                $validatorRejectsPersonalStable)
            SchemaAllowsPersonal = [bool]$schemaPersonalPilot
            SchemaAllowsPilot = [bool]$schemaPersonalPilot
            SchemaRejectsPersonalStable = [bool]$schemaRejectsPersonalStable
            ValidatorAllowsPersonalV2 = [bool]$validatorPersonalPilot
            ValidatorRejectsPersonalStable = [bool]$validatorRejectsPersonalStable
        }
    }
    catch {
        Throw-PersonalSigningPipelineFailure `
            -Code 'PERSONAL_SIGNING_PIPELINE_SHARED_CONTRACT_UNREADABLE' `
            -Message 'Shared Installer request-v2 capability could not be inspected safely.' `
            -InnerException $_.Exception
    }
}

function New-PersonalSigningPipelineBlockedResult {
    param(
        [Parameter(Mandatory = $true)][string]$Stage,
        [string]$RequestSha256 = '',
        [string]$R5HeadSha256 = '',
        [string]$R5ReceiptSha256 = '',
        [psobject]$Capability,
        [string]$Blocker = $script:SharedRequestCompatibilityBlocker,
        [string]$SharedRequestV2Status =
            'INCOMPATIBLE_NOT_EXTERNAL_SIGNER_ELIGIBLE',
        [string[]]$DependencyBlockers = @()
    )

    return [pscustomobject][ordered]@{
        Status = "PERSONAL_INSTALLER_SIGNING_${Stage}_BLOCKED_NO_GO"
        Blocker = $Blocker
        ProductionAdmission = 'NO_GO'
        SharedRequestV2Status = $SharedRequestV2Status
        RequestDraftSha256 = $RequestSha256
        R5HeadSha256 = $R5HeadSha256
        R5ReceiptSha256 = $R5ReceiptSha256
        SchemaAllowsPersonal = if ($null -eq $Capability) { $false } else {
            [bool]$Capability.SchemaAllowsPersonal
        }
        ValidatorAllowsPersonalV2 = if ($null -eq $Capability) { $false } else {
            [bool]$Capability.ValidatorAllowsPersonalV2
        }
        DependencyBlockers = @($DependencyBlockers)
        UnsignedArtifactExecution = 'FORBIDDEN_AND_NOT_PERFORMED'
        SignedArtifactExecution = 'NOT_PERFORMED'
        ExternalSigningRequestEligible = $false
    }
}

function Prepare-PersonalInstallerSigningPipeline {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$TrustedBuildResult,
        [Parameter(Mandatory = $true)]$PlanInput,
        [Parameter(Mandatory = $true)]$R5HeadInput,
        [Parameter(Mandatory = $true)]$R5ReceiptInput,
        [Parameter(Mandatory = $true)][string]$ExpectedR5HeadSha256
    )

    Assert-PersonalSigningPipelineHost
    $trusted = Assert-PersonalSigningPipelineTrustedBuild `
        -TrustedBuildResult $TrustedBuildResult
    $plan = Read-PersonalSigningPipelineHeldJson `
        -Descriptor $PlanInput `
        -SchemaPath $script:PlanSchemaPath `
        -Label 'Personal production release plan v2'
    $head = Read-PersonalSigningPipelineHeldJson `
        -Descriptor $R5HeadInput `
        -SchemaPath $script:StateSchemaPath `
        -Label 'Personal r5 production head'
    $receipt = Read-PersonalSigningPipelineHeldJson `
        -Descriptor $R5ReceiptInput `
        -SchemaPath $script:StateSchemaPath `
        -Label 'Personal r5 signed-candidate receipt'
    if ([string]$R5HeadInput.FileName -cne 'head.json' -or
        [string]$R5ReceiptInput.FileName -cne
            "0005-$($trusted.Request.channel)-signed-candidate-imported.json") {
        Throw-PersonalSigningPipelineFailure `
            -Code 'PERSONAL_SIGNING_PIPELINE_R5_CAS_INVALID' `
            -Message 'Personal r5 head or receipt uses a noncanonical file name.'
    }
    [void](Assert-PersonalSigningPipelinePlanBinding `
            -PlanInput $plan `
            -Request $trusted.Request)
    [void](Assert-PersonalSigningPipelineR5CasBinding `
            -PlanInput $plan `
            -HeadInput $head `
            -ReceiptInput $receipt `
            -Request $trusted.Request `
            -ExpectedR5HeadSha256 $ExpectedR5HeadSha256)

    $capability = Get-PersonalSigningPipelineSharedRequestCapability
    if (-not $capability.IsCompatible) {
        return New-PersonalSigningPipelineBlockedResult `
            -Stage 'PREPARE' `
            -RequestSha256 ([string]$trusted.RequestInput.Sha256) `
            -R5HeadSha256 ([string]$head.Sha256) `
            -R5ReceiptSha256 ([string]$receipt.Sha256) `
            -Capability $capability
    }

    try {
        $sharedRequestInput =
            InstallerSigningContracts\Read-InstallerSigningContractInput `
                -Path ([string]$TrustedBuildResult.RequestInput.Path) `
                -SchemaPath $script:SharedRequestSchemaPath `
                -Label 'Shared Personal Installer signing request v2'
        [void](InstallerSigningContracts\Assert-InstallerSigningRequestContract `
                -Request $sharedRequestInput.Value `
                -InstallerSigningTrust `
                    $plan.Value.externalResponseTrusts.installerSigning `
                -ReleaseManifestTrust $plan.Value.releaseManifestTrust)
    }
    catch {
        return New-PersonalSigningPipelineBlockedResult `
            -Stage 'PREPARE' `
            -RequestSha256 ([string]$trusted.RequestInput.Sha256) `
            -R5HeadSha256 ([string]$head.Sha256) `
            -R5ReceiptSha256 ([string]$receipt.Sha256) `
            -Capability $capability `
            -Blocker 'PERSONAL_R6_SHARED_REQUEST_VALIDATION_FAILED' `
            -SharedRequestV2Status 'VALIDATION_FAILED_NOT_EXTERNAL_SIGNER_ELIGIBLE'
    }

    return [pscustomobject][ordered]@{
        Status = 'PERSONAL_SHARED_REQUEST_V2_VALIDATED_NO_GO'
        Blocker = 'INSTALLER_SIGNING_RESPONSE_REQUIRED'
        ProductionAdmission = 'NO_GO'
        SharedRequestV2Status =
            'VALIDATED_PERSONAL_PILOT_EXTERNAL_SIGNER_ELIGIBLE'
        RequestInput = $sharedRequestInput
        RequestDraftSha256 = [string]$sharedRequestInput.Sha256
        R5HeadSha256 = [string]$head.Sha256
        R5ReceiptSha256 = [string]$receipt.Sha256
        DependencyBlockers = @()
        PayloadExpectation = Get-PersonalSigningPipelinePayloadExpectation `
            -Request $sharedRequestInput.Value
        UnsignedArtifactExecution = 'FORBIDDEN_AND_NOT_PERFORMED'
        SignedArtifactExecution = 'NOT_PERFORMED'
        ExternalSigningRequestEligible = $true
    }
}

function Get-PersonalSigningPipelinePayloadExpectation {
    param([Parameter(Mandatory = $true)][psobject]$Request)

    $files = if ($null -ne $Request.PSObject.Properties['installerPayload']) {
        @($Request.installerPayload.files)
    }
    else {
        @($Request.payload.files)
    }
    $manifest = Get-PersonalSigningPipelinePayloadFile `
        -Files $files -Role 'release-manifest' -Label 'Personal Installer payload'
    $startup = Get-PersonalSigningPipelinePayloadFile `
        -Files $files -Role 'startup-stub' -Label 'Personal Installer payload'
    $client = Get-PersonalSigningPipelinePayloadFile `
        -Files $files -Role 'client-bundle' -Label 'Personal Installer payload'
    $runtime = Get-PersonalSigningPipelinePayloadFile `
        -Files $files -Role 'runtime' -Label 'Personal Installer payload'
    return [pscustomobject][ordered]@{
        releaseSetId = [string]$Request.releaseSetId
        manifestSha256 = [string]$manifest.sha256
        manifestSizeBytes = [int64]$manifest.sizeBytes
        startupStubSha256 = [string]$startup.sha256
        startupStubSizeBytes = [int64]$startup.sizeBytes
        clientBundleSha256 = [string]$client.sha256
        clientBundleSizeBytes = [int64]$client.sizeBytes
        runtimeSha256 = [string]$runtime.sha256
        runtimeSizeBytes = [int64]$runtime.sizeBytes
    }
}

function Assert-PersonalSigningPipelineR6CasBinding {
    param(
        [Parameter(Mandatory = $true)][psobject]$RequestInput,
        [Parameter(Mandatory = $true)][psobject]$ReceiptInput,
        [Parameter(Mandatory = $true)][psobject]$R5ReceiptInput,
        [Parameter(Mandatory = $true)][string]$ExpectedR6HeadSha256
    )

    if (-not (Test-PersonalSigningPipelineSha256 -Value $ExpectedR6HeadSha256)) {
        Throw-PersonalSigningPipelineFailure `
            -Code 'PERSONAL_SIGNING_PIPELINE_R6_CAS_INVALID' `
            -Message 'Expected r6 head is not one lowercase SHA-256 value.'
    }
    $request = $RequestInput.Value
    $receipt = $ReceiptInput.Value
    $r5Receipt = $R5ReceiptInput.Value
    $bindings = Get-PersonalInstallerSigningRequestBindings -Request $request
    $historicalR5Head = [ordered]@{
        schemaVersion = 2
        stateType = 'ensou-dsh-launcher-production-release-head'
        orchestrationId = [string]$r5Receipt.orchestrationId
        edition = 'Personal'
        planSha256 = [string]$r5Receipt.planSha256
        identitySha256 = [string]$r5Receipt.identitySha256
        revision = 5
        phase = 'PILOT_SIGNED_CANDIDATE_IMPORTED'
        receiptFileName = '0005-pilot-signed-candidate-imported.json'
        receiptSha256 = [string]$R5ReceiptInput.Sha256
        updatedAtUtc = [string]$r5Receipt.recordedAtUtc
        targetChannel = 'pilot'
    }
    $historicalR5HeadSha256 =
        ProductionReleaseState\Get-ProductionSha256Bytes -Bytes (
            ProductionReleaseState\ConvertTo-ProductionJsonBytes `
                -Value $historicalR5Head)
    $historicalR6Head = [ordered]@{
        schemaVersion = 2
        stateType = 'ensou-dsh-launcher-production-release-head'
        orchestrationId = [string]$receipt.orchestrationId
        edition = 'Personal'
        planSha256 = [string]$receipt.planSha256
        identitySha256 = [string]$receipt.identitySha256
        revision = 6
        phase = 'INSTALLER_SIGNING_REQUESTED'
        receiptFileName = '0006-installer-signing-requested.json'
        receiptSha256 = [string]$ReceiptInput.Sha256
        updatedAtUtc = [string]$receipt.recordedAtUtc
        targetChannel = 'pilot'
    }
    $historicalR6HeadSha256 =
        ProductionReleaseState\Get-ProductionSha256Bytes -Bytes (
            ProductionReleaseState\ConvertTo-ProductionJsonBytes `
                -Value $historicalR6Head)
    if ($historicalR6HeadSha256 -cne $ExpectedR6HeadSha256 -or
        [string]$ReceiptInput.FileName -cne
            '0006-installer-signing-requested.json' -or
        [int]$receipt.schemaVersion -ne 2 -or
        [string]$receipt.edition -cne 'Personal' -or
        [string]$receipt.orchestrationId -cne [string]$request.orchestrationId -or
        [string]$receipt.targetChannel -cne [string]$request.channel -or
        [string]$receipt.planSha256 -cne [string]$request.planSha256 -or
        [string]$receipt.identitySha256 -cne
            [string]$r5Receipt.identitySha256 -or
        [string]$receipt.previousReceiptSha256 -cne
            [string]$R5ReceiptInput.Sha256 -or
        [string]$receipt.data.requestRelativePath -cne
            $script:SharedRequestPath -or
        [string]$receipt.data.requestSha256 -cne
            [string]$RequestInput.Sha256 -or
        [string]$receipt.data.baseHeadSha256 -cne
            [string]$request.baseHeadSha256 -or
        [string]$receipt.data.baseReceiptSha256 -cne
            [string]$R5ReceiptInput.Sha256 -or
        [string]$request.baseHeadSha256 -cne $historicalR5HeadSha256 -or
        [int]$r5Receipt.schemaVersion -ne 2 -or
        [string]$r5Receipt.edition -cne 'Personal' -or
        [string]$r5Receipt.targetChannel -cne 'pilot' -or
        [string]$r5Receipt.orchestrationId -cne
            [string]$request.orchestrationId -or
        [string]$r5Receipt.planSha256 -cne [string]$request.planSha256 -or
        [int]$r5Receipt.revision -ne 5 -or
        [string]$r5Receipt.phase -cne
            'PILOT_SIGNED_CANDIDATE_IMPORTED' -or
        [string]$R5ReceiptInput.FileName -cne
            '0005-pilot-signed-candidate-imported.json' -or
        [int]$receipt.revision -ne 6 -or
        [string]$receipt.phase -cne 'INSTALLER_SIGNING_REQUESTED' -or
        [string]$receipt.data.sourceSha256 -cne
            [string]$bindings.sourceSha256 -or
        [string]$receipt.data.payloadSha256 -cne
            [string]$bindings.payloadSha256 -or
        [string]$receipt.data.compiledTrustSha256 -cne
            [string]$bindings.compiledTrustSha256 -or
        [string]$receipt.data.toolchainSha256 -cne
            [string]$bindings.toolchainSha256 -or
        [string]$receipt.data.buildExecutionSha256 -cne
            [string]$bindings.buildExecutionSha256 -or
        [string]$receipt.data.resourceBindingSha256 -cne
            [string]$bindings.resourceBindingSha256 -or
        [string]$receipt.data.trustedBuildEvidenceSha256 -cne
            [string]$bindings.trustedBuildEvidenceSha256 -or
        [string]$receipt.data.admissionSha256 -cne
            [string]$bindings.admissionSha256 -or
        [string]$receipt.data.authenticationKeyId -cne
            [string]$request.responseAuthentication.keyId -or
        [string]$receipt.data.authenticationPurpose -cne
            'personal-installer-signing-response' -or
        [string]$receipt.data.authenticationPayloadType -cne
            'ensou-dsh-personal-installer-signing-response-authentication-v2' -or
        [string]$receipt.data.admissionReason -cne
            'INSTALLER_SIGNING_RESPONSE_REQUIRED' -or
        [string]$receipt.data.productionAdmission -cne 'NO_GO') {
        Throw-PersonalSigningPipelineFailure `
            -Code 'PERSONAL_SIGNING_PIPELINE_R6_CAS_INVALID' `
            -Message 'Personal import is not bound to the exact r6 request head, receipt, and compare-and-swap hash.'
    }
    return $true
}

function Assert-PersonalSigningPipelineSignedIdentity {
    param(
        [Parameter(Mandatory = $true)]$SignedInstallerInput,
        [Parameter(Mandatory = $true)][psobject]$Response
    )

    Assert-PersonalSigningPipelineDescriptor `
        -Descriptor $SignedInstallerInput `
        -Label 'Held externally signed Personal Installer' `
        -MaximumBytes $script:MaximumInstallerBytes
    if ([string]$SignedInstallerInput.FileName -cne
            'Ensou.Dsh.Personal.Installer.exe' -or
        [string]$SignedInstallerInput.FileName -cne
            [string]$Response.signedInstaller.fileName -or
        [int64]$SignedInstallerInput.SizeBytes -ne
            [int64]$Response.signedInstaller.sizeBytes -or
        [string]$SignedInstallerInput.Sha256 -cne
            [string]$Response.signedInstaller.sha256) {
        Throw-PersonalSigningPipelineFailure `
            -Code 'PERSONAL_SIGNING_PIPELINE_SIGNED_IDENTITY_INVALID' `
            -Message 'Held signed Personal Installer differs from the authenticated response identity.'
    }
    return $true
}

function Assert-PersonalSigningPipelineResponseWindow {
    param(
        [Parameter(Mandatory = $true)][psobject]$Request,
        [Parameter(Mandatory = $true)][psobject]$Response,
        [switch]$EnforceCurrentLifetime
    )

    try {
        $created = ProductionReleaseState\ConvertFrom-ProductionUtc `
            -Value ([string]$Request.createdAtUtc) `
            -Label 'Personal request creation time'
        $expires = ProductionReleaseState\ConvertFrom-ProductionUtc `
            -Value ([string]$Request.expiresAtUtc) `
            -Label 'Personal request expiry time'
        $completed = ProductionReleaseState\ConvertFrom-ProductionUtc `
            -Value ([string]$Response.completedAtUtc) `
            -Label 'Personal response completion time'
        $timestamp = ProductionReleaseState\ConvertFrom-ProductionUtc `
            -Value ([string]$Response.authenticode.timestampUtc) `
            -Label 'Personal response RFC3161 timestamp'
        $selfCheckCompleted = ProductionReleaseState\ConvertFrom-ProductionUtc `
            -Value ([string]$Response.payloadSelfCheck.completedAtUtc) `
            -Label 'Personal response payload self-check time'
        $now = [DateTimeOffset]::UtcNow
        if ($completed -lt $created -or $completed -gt $expires -or
            $completed -gt $now.AddMinutes(5) -or
            $timestamp -lt $created -or $timestamp -gt $completed -or
            $timestamp -gt $expires -or
            $selfCheckCompleted -lt $timestamp -or
            $selfCheckCompleted -gt $completed -or
            ($EnforceCurrentLifetime -and $now -gt $expires)) {
            throw 'Response window ordering is invalid.'
        }
    }
    catch {
        Throw-PersonalSigningPipelineFailure `
            -Code 'PERSONAL_SIGNING_PIPELINE_RESPONSE_LIFETIME_INVALID' `
            -Message 'External response, RFC3161 timestamp, or payload self-check is stale, future-dated, or outside the exact request lifetime.' `
            -InnerException $_.Exception
    }
    return $true
}

function ConvertFrom-PersonalSigningPipelineBase64UrlStrict {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ($Value -cnotmatch '^[A-Za-z0-9_-]+$') {
        Throw-PersonalSigningPipelineFailure `
            -Code 'PERSONAL_SIGNING_PIPELINE_RESPONSE_AUTH_INVALID' `
            -Message "$Label is not canonical base64url."
    }
    $padding = switch ($Value.Length % 4) {
        0 { '' }
        2 { '==' }
        3 { '=' }
        default {
            Throw-PersonalSigningPipelineFailure `
                -Code 'PERSONAL_SIGNING_PIPELINE_RESPONSE_AUTH_INVALID' `
                -Message "$Label has an invalid base64url length."
        }
    }
    try {
        [byte[]]$bytes = [Convert]::FromBase64String(
            $Value.Replace('-', '+').Replace('_', '/') + $padding)
    }
    catch {
        Throw-PersonalSigningPipelineFailure `
            -Code 'PERSONAL_SIGNING_PIPELINE_RESPONSE_AUTH_INVALID' `
            -Message "$Label is not valid base64url." `
            -InnerException $_.Exception
    }
    $canonical = [Convert]::ToBase64String($bytes).TrimEnd('=').
        Replace('+', '-').Replace('/', '_')
    if ($canonical -cne $Value) {
        Throw-PersonalSigningPipelineFailure `
            -Code 'PERSONAL_SIGNING_PIPELINE_RESPONSE_AUTH_INVALID' `
            -Message "$Label is not canonically encoded."
    }
    return $bytes
}

function Get-PersonalInstallerSigningResponseAuthenticationPayload {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][psobject]$Response)

    $body = [ordered]@{}
    foreach ($property in $Response.PSObject.Properties) {
        if ($property.Name -cne 'authentication') {
            $body[$property.Name] = $property.Value
        }
    }
    $body['authentication'] = [ordered]@{
        algorithm = [string]$Response.authentication.algorithm
        keyId = [string]$Response.authentication.keyId
        purpose = [string]$Response.authentication.purpose
        payloadType = [string]$Response.authentication.payloadType
    }
    [byte[]]$domain = $script:Utf8Strict.GetBytes(
        'personal-installer-signing-response-v2' + [char]10)
    [byte[]]$json =
        ProductionReleaseState\ConvertTo-ProductionJsonBytes -Value $body
    [byte[]]$payload = [byte[]]::new($domain.Length + $json.Length)
    [Array]::Copy($domain, 0, $payload, 0, $domain.Length)
    [Array]::Copy($json, 0, $payload, $domain.Length, $json.Length)
    return $payload
}

function Assert-PersonalInstallerSigningResponseAuthentication {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][psobject]$Response,
        [Parameter(Mandatory = $true)][psobject]$Request,
        [Parameter(Mandatory = $true)][psobject]$InstallerSigningTrust
    )

    $expectedPurpose = 'personal-installer-signing-response'
    $expectedPayloadType =
        'ensou-dsh-personal-installer-signing-response-authentication-v2'
    if ([string]$InstallerSigningTrust.algorithm -cne 'ES256' -or
        [string]$InstallerSigningTrust.purpose -cne $expectedPurpose -or
        [string]$Request.responseAuthentication.algorithm -cne 'ES256' -or
        [string]$Request.responseAuthentication.keyId -cne
            [string]$InstallerSigningTrust.keyId -or
        [string]$Request.responseAuthentication.purpose -cne $expectedPurpose -or
        [string]$Request.responseAuthentication.payloadType -cne
            $expectedPayloadType -or
        [string]$Request.responseAuthentication.trustSha256 -cne
            (InstallerSigningContracts\Get-InstallerSigningObjectSha256 `
                -Value $InstallerSigningTrust) -or
        [string]$Response.authentication.algorithm -cne 'ES256' -or
        [string]$Response.authentication.keyId -cne
            [string]$InstallerSigningTrust.keyId -or
        [string]$Response.authentication.purpose -cne $expectedPurpose -or
        [string]$Response.authentication.payloadType -cne
            $expectedPayloadType) {
        Throw-PersonalSigningPipelineFailure `
            -Code 'PERSONAL_SIGNING_PIPELINE_RESPONSE_AUTH_INVALID' `
            -Message 'Personal response is outside its dedicated v2 trust and payload domain.'
    }
    try {
        [void](ProductionReleaseState\Get-ProductionReleaseP256PublicKeyIdentity `
            -Trust $InstallerSigningTrust `
            -Label 'Personal Installer response v2 trust')
        [byte[]]$x = ConvertFrom-PersonalSigningPipelineBase64UrlStrict `
            -Value ([string]$InstallerSigningTrust.x) -Label 'Response key X'
        [byte[]]$y = ConvertFrom-PersonalSigningPipelineBase64UrlStrict `
            -Value ([string]$InstallerSigningTrust.y) -Label 'Response key Y'
        [byte[]]$signature = ConvertFrom-PersonalSigningPipelineBase64UrlStrict `
            -Value ([string]$Response.authentication.value) `
            -Label 'Response signature'
        if ($x.Length -ne 32 -or $y.Length -ne 32 -or
            $signature.Length -ne 64) {
            throw 'Personal response P-256 or P1363 length is invalid.'
        }
        ProductionReleaseState\Assert-ProductionEs256P1363LowS `
            -Signature $signature -Label 'Personal Installer response v2 signature'
        $parameters = [Security.Cryptography.ECParameters]::new()
        $parameters.Curve =
            [Security.Cryptography.ECCurve+NamedCurves]::nistP256
        $parameters.Q = [Security.Cryptography.ECPoint]@{ X = $x; Y = $y }
        $ecdsa = [Security.Cryptography.ECDsa]::Create()
        try {
            $ecdsa.ImportParameters($parameters)
            if (-not $ecdsa.VerifyData(
                    (Get-PersonalInstallerSigningResponseAuthenticationPayload `
                        -Response $Response),
                    $signature,
                    [Security.Cryptography.HashAlgorithmName]::SHA256,
                    [Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)) {
                throw 'Personal response v2 signature is invalid.'
            }
        }
        finally {
            $ecdsa.Dispose()
        }
    }
    catch {
        if ($_.Exception.Message -like
            'PERSONAL_SIGNING_PIPELINE_RESPONSE_AUTH_INVALID:*') {
            throw
        }
        Throw-PersonalSigningPipelineFailure `
            -Code 'PERSONAL_SIGNING_PIPELINE_RESPONSE_AUTH_INVALID' `
            -Message 'Personal response v2 authentication is invalid.' `
            -InnerException $_.Exception
    }
    return $true
}

function Get-PersonalInstallerSigningRequestBindings {
    param([Parameter(Mandatory = $true)][psobject]$Request)

    return [ordered]@{
        sourceSha256 = InstallerSigningContracts\Get-InstallerSigningObjectSha256 `
            -Value $Request.source
        payloadSha256 = InstallerSigningContracts\Get-InstallerSigningObjectSha256 `
            -Value $Request.payload
        compiledTrustSha256 = InstallerSigningContracts\Get-InstallerSigningObjectSha256 `
            -Value $Request.compiledTrust
        toolchainSha256 = InstallerSigningContracts\Get-InstallerSigningObjectSha256 `
            -Value $Request.toolchain
        buildExecutionSha256 = InstallerSigningContracts\Get-InstallerSigningObjectSha256 `
            -Value $Request.buildExecution
        resourceBindingSha256 = InstallerSigningContracts\Get-InstallerSigningObjectSha256 `
            -Value $Request.resourceBinding
        trustedBuildEvidenceSha256 = InstallerSigningContracts\Get-InstallerSigningObjectSha256 `
            -Value $Request.trustedBuildEvidence
        admissionSha256 = InstallerSigningContracts\Get-InstallerSigningObjectSha256 `
            -Value $Request.admission
    }
}

function Assert-PersonalInstallerSigningResponseV2Contract {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$RequestInput,
        [Parameter(Mandatory = $true)]$ResponseInput,
        [Parameter(Mandatory = $true)][string]$R6HeadSha256,
        [Parameter(Mandatory = $true)][string]$R6ReceiptSha256,
        [Parameter(Mandatory = $true)][psobject]$InstallerSigningTrust,
        [switch]$EnforceCurrentLifetime
    )

    $request = $RequestInput.Value
    $response = $ResponseInput.Value
    try {
        [void](InstallerSigningContracts\Assert-InstallerSigningRequestContract `
            -Request $request `
            -InstallerSigningTrust $InstallerSigningTrust)
    }
    catch {
        Throw-PersonalSigningPipelineFailure `
            -Code 'PERSONAL_SIGNING_PIPELINE_RESPONSE_INVALID' `
            -Message 'Personal response does not reference a valid dedicated request-v2.' `
            -InnerException $_.Exception
    }
    if ([int]$response.schemaVersion -ne 2 -or
        [string]$response.responseType -cne
            'ensou-dsh-personal-installer-signing-response' -or
        [string]$response.edition -cne 'Personal' -or
        [string]$response.orchestrationId -cne [string]$request.orchestrationId -or
        [string]$response.releaseSetId -cne [string]$request.releaseSetId -or
        [string]$response.channel -cne 'pilot' -or
        [string]$response.channel -cne [string]$request.channel -or
        [string]$response.planSha256 -cne [string]$request.planSha256 -or
        [string]$response.requestRelativePath -cne
            'requests/installer-signing.v2/installer-signing-request.v2.json' -or
        [string]$response.requestSha256 -cne [string]$RequestInput.Sha256 -or
        [string]$response.requestNonce -cne [string]$request.requestNonce -or
        [string]$response.baseHeadSha256 -cne [string]$request.baseHeadSha256 -or
        [string]$response.admissionHeadSha256 -cne $R6HeadSha256 -or
        [int]$response.admissionRevision -ne 6 -or
        [string]$response.r6ReceiptRelativePath -cne
            'receipts/0006-installer-signing-requested.json' -or
        [string]$response.r6ReceiptSha256 -cne $R6ReceiptSha256 -or
        [string]$response.requestCreatedAtUtc -cne [string]$request.createdAtUtc -or
        [string]$response.requestExpiresAtUtc -cne [string]$request.expiresAtUtc) {
        Throw-PersonalSigningPipelineFailure `
            -Code 'PERSONAL_SIGNING_PIPELINE_RESPONSE_INVALID' `
            -Message 'Personal response v2 is not bound to the exact request and r6 CAS tuple.'
    }
    [void](Assert-PersonalSigningPipelineResponseWindow `
        -Request $request -Response $response `
        -EnforceCurrentLifetime:$EnforceCurrentLifetime)
    $expectedBindings = Get-PersonalInstallerSigningRequestBindings `
        -Request $request
    if (-not (Test-PersonalSigningPipelineObjectEqual `
            -Left $response.requestBindings -Right $expectedBindings) -or
        -not (Test-PersonalSigningPipelineObjectEqual `
            -Left $response.unsignedInstaller -Right $request.unsignedInstaller)) {
        Throw-PersonalSigningPipelineFailure `
            -Code 'PERSONAL_SIGNING_PIPELINE_RESPONSE_CLOSURE_INVALID' `
            -Message 'Personal response v2 changed the source, payload, compiled trust, toolchain, resource binding, evidence, admission, or unsigned Installer closure.'
    }
    if ([string]$response.signedInstaller.fileName -cne
            'Ensou.Dsh.Personal.Installer.exe' -or
        [string]$response.signedInstaller.relativePath -cne
            'signed/Ensou.Dsh.Personal.Installer.exe' -or
        [string]$response.signedInstaller.peContentSha256 -cne
            [string]$request.unsignedInstaller.peContentSha256 -or
        [string]$response.signedInstaller.sha256 -ceq
            [string]$request.unsignedInstaller.sha256 -or
        [int64]$response.signedInstaller.sizeBytes -le
            [int64]$request.unsignedInstaller.sizeBytes -or
        -not [bool]$response.signedInstaller.fullHashChangedFromUnsigned -or
        [string]$response.authenticode.spcPeContentSha256 -cne
            [string]$request.unsignedInstaller.peContentSha256) {
        Throw-PersonalSigningPipelineFailure `
            -Code 'PERSONAL_SIGNING_PIPELINE_RESPONSE_CLOSURE_INVALID' `
            -Message 'Personal signed Installer is not the exact Authenticode-only transform of the r6 unsigned PE content.'
    }
    $expectation = Get-PersonalSigningPipelinePayloadExpectation -Request $request
    $selfCheck = $response.payloadSelfCheck
    if ([string]$selfCheck.inspectedInstallerSha256 -cne
            [string]$response.signedInstaller.sha256 -or
        [string]$selfCheck.releaseSetId -cne [string]$expectation.releaseSetId -or
        [string]$selfCheck.manifestSha256 -cne [string]$expectation.manifestSha256 -or
        [int64]$selfCheck.manifestSizeBytes -ne [int64]$expectation.manifestSizeBytes -or
        [string]$selfCheck.startupStubSha256 -cne [string]$expectation.startupStubSha256 -or
        [int64]$selfCheck.startupStubSizeBytes -ne [int64]$expectation.startupStubSizeBytes -or
        [string]$selfCheck.clientBundleSha256 -cne [string]$expectation.clientBundleSha256 -or
        [int64]$selfCheck.clientBundleSizeBytes -ne [int64]$expectation.clientBundleSizeBytes -or
        [string]$selfCheck.runtimeSha256 -cne [string]$expectation.runtimeSha256 -or
        [int64]$selfCheck.runtimeSizeBytes -ne [int64]$expectation.runtimeSizeBytes) {
        Throw-PersonalSigningPipelineFailure `
            -Code 'PERSONAL_SIGNING_PIPELINE_RESPONSE_CLOSURE_INVALID' `
            -Message 'Personal response payload self-check does not replay the exact request-v2 payload closure.'
    }
    [void](Assert-PersonalInstallerSigningResponseAuthentication `
        -Response $response -Request $request `
        -InstallerSigningTrust $InstallerSigningTrust)
    return $true
}

function Import-PersonalInstallerSigningPipelineResponse {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Preparation,
        $RequestInput,
        $ResponseInput,
        $R6ReceiptInput,
        $R5ReceiptInput,
        [string]$ExpectedR6HeadSha256 = '',
        [psobject]$InstallerSigningTrust,
        [psobject]$ReleaseManifestTrust,
        [string]$ExpectedSignerCertificateSha256 = '',
        $SignedInstallerInput,
        [psobject]$PayloadExpectation,
        [ValidateRange(100, 300000)][int]$SelfCheckTimeoutMilliseconds = 300000,
        [switch]$EnforceCurrentLifetime
    )

    Assert-PersonalSigningPipelineHost
    if ([string]$Preparation.ProductionAdmission -cne 'NO_GO' -or
        [string]$Preparation.UnsignedArtifactExecution -cne
            'FORBIDDEN_AND_NOT_PERFORMED') {
        Throw-PersonalSigningPipelineFailure `
            -Code 'PERSONAL_SIGNING_PIPELINE_PREPARATION_INVALID' `
            -Message 'Import did not receive one exact fail-closed Personal preparation result.'
    }
    if ([string]$Preparation.Blocker -in @(
            $script:SharedRequestCompatibilityBlocker,
            'PERSONAL_R6_SHARED_REQUEST_VALIDATION_FAILED')) {
        if ([bool]$Preparation.ExternalSigningRequestEligible -or
            [string]$Preparation.SignedArtifactExecution -cne 'NOT_PERFORMED') {
            Throw-PersonalSigningPipelineFailure `
                -Code 'PERSONAL_SIGNING_PIPELINE_PREPARATION_INVALID' `
                -Message 'Blocked Personal preparation cannot be externally signable or execute signed bytes.'
        }
        $capability = Get-PersonalSigningPipelineSharedRequestCapability
        [string[]]$dependencies = if ($null -eq
            $Preparation.PSObject.Properties['DependencyBlockers']) {
            @()
        }
        else {
            @($Preparation.DependencyBlockers)
        }
        return New-PersonalSigningPipelineBlockedResult `
            -Stage 'IMPORT' `
            -RequestSha256 ([string]$Preparation.RequestDraftSha256) `
            -R5HeadSha256 ([string]$Preparation.R5HeadSha256) `
            -R5ReceiptSha256 ([string]$Preparation.R5ReceiptSha256) `
            -Capability $capability `
            -Blocker ([string]$Preparation.Blocker) `
            -SharedRequestV2Status ([string]$Preparation.SharedRequestV2Status) `
            -DependencyBlockers $dependencies
    }
    if ([string]$Preparation.Status -cne
            'PERSONAL_SHARED_REQUEST_V2_VALIDATED_NO_GO' -or
        [string]$Preparation.Blocker -cne 'INSTALLER_SIGNING_RESPONSE_REQUIRED' -or
        [string]$Preparation.SharedRequestV2Status -cne
            'VALIDATED_PERSONAL_PILOT_EXTERNAL_SIGNER_ELIGIBLE' -or
        @($Preparation.DependencyBlockers).Count -ne 0 -or
        [string]$Preparation.SignedArtifactExecution -cne 'NOT_PERFORMED' -or
        -not [bool]$Preparation.ExternalSigningRequestEligible) {
        Throw-PersonalSigningPipelineFailure `
            -Code 'PERSONAL_SIGNING_PIPELINE_PREPARATION_INVALID' `
            -Message 'Personal preparation has no shared request-v2 admission.'
    }
    if ($null -eq $ResponseInput) {
        return [pscustomobject][ordered]@{
            Status = 'PERSONAL_INSTALLER_SIGNING_RESPONSE_REQUIRED_NO_GO'
            Blocker = 'INSTALLER_SIGNING_RESPONSE_REQUIRED'
            ProductionAdmission = 'NO_GO'
            SharedRequestV2Status = [string]$Preparation.SharedRequestV2Status
            RequestDraftSha256 = [string]$Preparation.RequestDraftSha256
            R5HeadSha256 = [string]$Preparation.R5HeadSha256
            R5ReceiptSha256 = [string]$Preparation.R5ReceiptSha256
            DependencyBlockers = @()
            UnsignedArtifactExecution = 'FORBIDDEN_AND_NOT_PERFORMED'
            SignedArtifactExecution = 'NOT_PERFORMED'
            ExternalSigningRequestEligible = $true
        }
    }
    foreach ($required in @(
            [pscustomobject]@{ Name = 'RequestInput'; Value = $RequestInput },
            [pscustomobject]@{ Name = 'ResponseInput'; Value = $ResponseInput },
            [pscustomobject]@{ Name = 'R6ReceiptInput'; Value = $R6ReceiptInput },
            [pscustomobject]@{ Name = 'R5ReceiptInput'; Value = $R5ReceiptInput },
            [pscustomobject]@{ Name = 'InstallerSigningTrust'; Value = $InstallerSigningTrust },
            [pscustomobject]@{ Name = 'ReleaseManifestTrust'; Value = $ReleaseManifestTrust },
            [pscustomobject]@{ Name = 'SignedInstallerInput'; Value = $SignedInstallerInput },
            [pscustomobject]@{ Name = 'PayloadExpectation'; Value = $PayloadExpectation })) {
        if ($null -eq $required.Value) {
            Throw-PersonalSigningPipelineFailure `
                -Code 'PERSONAL_SIGNING_PIPELINE_IMPORT_INPUT_MISSING' `
                -Message "Import requires $($required.Name) after shared request admission."
        }
    }

    $request = Read-PersonalSigningPipelineHeldJson `
        -Descriptor $RequestInput `
        -SchemaPath $script:SharedRequestSchemaPath `
        -Label 'Admitted shared Personal Installer request v2'
    if ([int]$request.Value.schemaVersion -ne 2 -or
        [string]$request.Value.edition -cne 'Personal' -or
        [string]$request.Value.channel -cne 'pilot' -or
        [string]$request.Value.basePhase -cne
            'PILOT_SIGNED_CANDIDATE_IMPORTED' -or
        [string]$request.Sha256 -cne [string]$Preparation.RequestDraftSha256) {
        Throw-PersonalSigningPipelineFailure `
            -Code 'PERSONAL_SIGNING_PIPELINE_SHARED_REQUEST_INVALID' `
            -Message 'Import request is not the exact prepared Personal shared request-v2 bytes.'
    }
    try {
        [void](InstallerSigningContracts\Assert-InstallerSigningRequestContract `
                -Request $request.Value `
                -InstallerSigningTrust $InstallerSigningTrust `
                -ReleaseManifestTrust $ReleaseManifestTrust)
    }
    catch {
        Throw-PersonalSigningPipelineFailure `
            -Code 'PERSONAL_SIGNING_PIPELINE_SHARED_REQUEST_INVALID' `
            -Message 'Shared request-v2 validator rejected the prepared Personal request.' `
            -InnerException $_.Exception
    }

    $r6Receipt = Read-PersonalSigningPipelineHeldJson `
        -Descriptor $R6ReceiptInput `
        -SchemaPath $script:StateSchemaPath `
        -Label 'Personal r6 Installer-signing receipt'
    $r5Receipt = Read-PersonalSigningPipelineHeldJson `
        -Descriptor $R5ReceiptInput `
        -SchemaPath $script:StateSchemaPath `
        -Label 'Personal r5 signed-candidate receipt'
    if ([string]$R6ReceiptInput.FileName -cne
            '0006-installer-signing-requested.json') {
        Throw-PersonalSigningPipelineFailure `
            -Code 'PERSONAL_SIGNING_PIPELINE_R6_CAS_INVALID' `
            -Message 'Personal r6 head or receipt uses a noncanonical file name.'
    }
    [void](Assert-PersonalSigningPipelineR6CasBinding `
            -RequestInput $request `
            -ReceiptInput $r6Receipt `
            -R5ReceiptInput $r5Receipt `
            -ExpectedR6HeadSha256 $ExpectedR6HeadSha256)

    $response = Read-PersonalSigningPipelineHeldJson `
        -Descriptor $ResponseInput `
        -SchemaPath $script:PersonalResponseSchemaPath `
        -Label 'External Personal Installer signing response v2'
    if ([string]$ResponseInput.FileName -cne
        'personal-installer-signing-response.v2.json') {
        Throw-PersonalSigningPipelineFailure `
            -Code 'PERSONAL_SIGNING_PIPELINE_RESPONSE_INVALID' `
            -Message 'External Personal signing response uses a noncanonical file name.'
    }
    [void](Assert-PersonalSigningPipelineResponseWindow `
            -Request $request.Value `
            -Response $response.Value `
            -EnforceCurrentLifetime:$EnforceCurrentLifetime)
    try {
        [void](Assert-PersonalInstallerSigningResponseV2Contract `
                -RequestInput $request `
                -ResponseInput $response `
                -R6HeadSha256 $ExpectedR6HeadSha256 `
                -R6ReceiptSha256 ([string]$r6Receipt.Sha256) `
                -InstallerSigningTrust $InstallerSigningTrust `
                -EnforceCurrentLifetime:$EnforceCurrentLifetime)
    }
    catch {
        Throw-PersonalSigningPipelineFailure `
            -Code 'PERSONAL_SIGNING_PIPELINE_RESPONSE_INVALID' `
                -Message 'External Personal response-v2 failed its dedicated canonical ES256, lifetime, request-closure, and r6 CAS validation.' `
            -InnerException $_.Exception
    }

    [void](Assert-PersonalSigningPipelineSignedIdentity `
            -SignedInstallerInput $SignedInstallerInput `
            -Response $response.Value)
    try {
        $authenticode =
            InstallerSigningContracts\Assert-SignedInstallerAuthenticode `
                -Path ([string]$SignedInstallerInput.Path) `
                -Response $response.Value `
                -ExpectedSignerCertificateSha256 `
                    $ExpectedSignerCertificateSha256
    }
    catch {
        Throw-PersonalSigningPipelineFailure `
            -Code 'PERSONAL_SIGNING_PIPELINE_AUTHENTICODE_INVALID' `
            -Message 'Held signed Personal Installer failed pinned Authenticode signer and RFC3161 admission.' `
            -InnerException $_.Exception
    }
    Assert-PersonalSigningPipelineDescriptor `
        -Descriptor $SignedInstallerInput `
        -Label 'Held externally signed Personal Installer after Authenticode' `
        -MaximumBytes $script:MaximumInstallerBytes

    try {
        $selfCheck =
            PersonalInstallerProductionPayloadSelfCheck\Invoke-PersonalInstallerProductionPayloadSelfCheck `
                -InstallerInput $SignedInstallerInput `
                -Response $response.Value `
                -ExpectedSignerCertificateSha256 `
                    $ExpectedSignerCertificateSha256 `
                -Expectation $PayloadExpectation `
                -TimeoutMilliseconds $SelfCheckTimeoutMilliseconds
    }
    catch {
        Throw-PersonalSigningPipelineFailure `
            -Code 'PERSONAL_SIGNING_PIPELINE_PAYLOAD_SELF_CHECK_INVALID' `
            -Message 'Authenticated signed Personal Installer did not replay its production payload self-check.' `
            -InnerException $_.Exception
    }
    if ([string]$selfCheck.status -cne 'VERIFIED' -or
        [string]$selfCheck.inspectedInstallerSha256 -cne
            [string]$SignedInstallerInput.Sha256 -or
        [string]$selfCheck.canonicalJsonSha256 -cne
            [string]$response.Value.payloadSelfCheck.canonicalJsonSha256 -or
        [int64]$selfCheck.canonicalJsonSizeBytes -ne
            [int64]$response.Value.payloadSelfCheck.canonicalJsonSizeBytes -or
        [string]$selfCheck.canonicalLineSha256 -cne
            [string]$response.Value.payloadSelfCheck.canonicalLineSha256 -or
        [int64]$selfCheck.canonicalLineSizeBytes -ne
            [int64]$response.Value.payloadSelfCheck.canonicalLineSizeBytes) {
        Throw-PersonalSigningPipelineFailure `
            -Code 'PERSONAL_SIGNING_PIPELINE_PAYLOAD_SELF_CHECK_INVALID' `
            -Message 'Local Personal payload replay differs from the authenticated signer response.'
    }
    Assert-PersonalSigningPipelineDescriptor `
        -Descriptor $SignedInstallerInput `
        -Label 'Held externally signed Personal Installer after self-check' `
        -MaximumBytes $script:MaximumInstallerBytes
    Assert-PersonalSigningPipelineDescriptor `
        -Descriptor $R6ReceiptInput `
        -Label 'Held Personal r6 receipt after self-check'

    return [pscustomobject][ordered]@{
        Status = 'PERSONAL_SIGNING_RESPONSE_VERIFIED_R7_READY_NO_GO'
        Blocker = 'PERSONAL_R7_STATE_TRANSITION_REQUIRED'
        ProductionAdmission = 'NO_GO'
        RequestSha256 = [string]$request.Sha256
        ResponseSha256 = [string]$response.Sha256
        SignedInstallerSha256 = [string]$authenticode.SignedInstallerSha256
        PeContentSha256 = [string]$authenticode.PeContentSha256
        AuthenticodeStatus = [string]$authenticode.AuthenticodeStatus
        Rfc3161TimestampUtc = [string]$authenticode.TimestampUtc
        PayloadSelfCheck = $selfCheck
        UnsignedArtifactExecution = 'FORBIDDEN_AND_NOT_PERFORMED'
        SignedArtifactExecution = 'PRODUCTION_PAYLOAD_SELF_CHECK_ONLY'
    }
}

Export-ModuleMember -Function @(
    'Assert-PersonalInstallerSigningResponseV2Contract',
    'Get-PersonalInstallerSigningRequestBindings',
    'Get-PersonalInstallerSigningResponseAuthenticationPayload',
    'Get-PersonalSigningPipelinePayloadExpectation',
    'Prepare-PersonalInstallerSigningPipeline',
    'Import-PersonalInstallerSigningPipelineResponse'
)
