#requires -Version 7.2

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$StateRoot,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$ExpectedHeadSha256,
    [Parameter(Mandatory = $true)][string]$SignedInstallerPath,
    [Parameter(Mandatory = $true)][string]$ResponsePrivateKeyPath,
    [Parameter(Mandatory = $true)][string]$OutputRoot,
    [ValidateRange(100, 300000)]
    [int]$SelfCheckTimeoutMilliseconds = 300000
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$schemaRoot = Join-Path $repositoryRoot 'release\schemas'
$planSchemaPath = Join-Path $schemaRoot 'launcher-production-release-plan-v2.schema.json'
$stateSchemaPath = Join-Path $schemaRoot 'launcher-production-release-state-v2.schema.json'
$requestSchemaPath = Join-Path $schemaRoot 'launcher-installer-signing-request-v2.schema.json'
$personalResponseSchemaPath = Join-Path $schemaRoot 'personal-installer-signing-response-v2.schema.json'
$enterpriseResponseSchemaPath = Join-Path $schemaRoot 'launcher-installer-signing-response-v1.schema.json'
$personalEvidenceSchemaPath = Join-Path $schemaRoot 'personal-installer-trusted-build-evidence-v1.schema.json'
$enterpriseEvidenceSchemaPath = Join-Path $schemaRoot 'enterprise-installer-trusted-build-evidence-v1.schema.json'

Microsoft.PowerShell.Core\Import-Module `
    (Join-Path $PSScriptRoot 'InstallerSigningContracts.psm1') -Force
Microsoft.PowerShell.Core\Import-Module `
    (Join-Path $PSScriptRoot 'PersonalInstallerSigningPipeline.psm1') -Force
Microsoft.PowerShell.Core\Import-Module `
    (Join-Path $PSScriptRoot 'PersonalInstallerProductionPayloadSelfCheck.psm1') -Force
Microsoft.PowerShell.Core\Import-Module `
    (Join-Path $PSScriptRoot 'EnterpriseInstallerProductionPayloadSelfCheck.psm1') -Force
# Nested imports load the state module in private scopes. Import it last so its
# module-qualified contracts remain stable in this issuer scope.
Microsoft.PowerShell.Core\Import-Module `
    (Join-Path $PSScriptRoot 'ProductionReleaseState.psm1') -Force

$p256Order = [Convert]::FromHexString(
    'FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551')
$p256HalfOrder = [Convert]::FromHexString(
    '7FFFFFFF800000007FFFFFFFFFFFFFFFDE737D56D38BCF4279DCE5617E3192A8')

function ConvertTo-ProductionInstallerBase64Url {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    return [Convert]::ToBase64String($Bytes).
        TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Compare-ProductionInstallerUnsigned {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Left,
        [Parameter(Mandatory = $true)][byte[]]$Right
    )
    if ($Left.Length -ne $Right.Length) {
        throw 'Unsigned comparison requires equal-length values.'
    }
    for ($index = 0; $index -lt $Left.Length; $index++) {
        if ($Left[$index] -lt $Right[$index]) { return -1 }
        if ($Left[$index] -gt $Right[$index]) { return 1 }
    }
    return 0
}

function ConvertTo-ProductionInstallerLowS {
    param([Parameter(Mandatory = $true)][byte[]]$Signature)

    if ($Signature.Length -ne 64) {
        throw 'Installer-signing response must use a 64-byte P1363 signature.'
    }
    $r = [byte[]]::new(32)
    $s = [byte[]]::new(32)
    [Array]::Copy($Signature, 0, $r, 0, 32)
    [Array]::Copy($Signature, 32, $s, 0, 32)
    $zero = [byte[]]::new(32)
    if ((Compare-ProductionInstallerUnsigned $r $zero) -eq 0 -or
        (Compare-ProductionInstallerUnsigned $r $p256Order) -ge 0 -or
        (Compare-ProductionInstallerUnsigned $s $zero) -eq 0 -or
        (Compare-ProductionInstallerUnsigned $s $p256Order) -ge 0) {
        throw 'Installer-signing response signature contains an invalid scalar.'
    }
    if ((Compare-ProductionInstallerUnsigned $s $p256HalfOrder) -gt 0) {
        $normalized = [byte[]]::new(32)
        $borrow = 0
        for ($index = 31; $index -ge 0; $index--) {
            $value = [int]$p256Order[$index] - [int]$s[$index] - $borrow
            if ($value -lt 0) {
                $value += 256
                $borrow = 1
            }
            else { $borrow = 0 }
            $normalized[$index] = [byte]$value
        }
        if ($borrow -ne 0) { throw 'Installer response low-S normalization underflowed.' }
        $s = $normalized
    }
    $result = [byte[]]::new(64)
    [Array]::Copy($r, 0, $result, 0, 32)
    [Array]::Copy($s, 0, $result, 32, 32)
    ProductionReleaseState\Assert-ProductionEs256P1363LowS `
        -Signature $result -Label 'Installer-signing response signature'
    return ,$result
}

function Resolve-ProductionInstallerExternalPath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )
    if (-not [IO.Path]::IsPathFullyQualified($Path) -or
        $Path.StartsWith('\\', [StringComparison]::Ordinal) -or
        $Path.StartsWith('//', [StringComparison]::Ordinal)) {
        throw "$Label must use an absolute local path."
    }
    $full = [IO.Path]::GetFullPath($Path)
    $boundary = $repositoryRoot.TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    if ($full.Equals($boundary, [StringComparison]::OrdinalIgnoreCase) -or
        $full.StartsWith(
            $boundary + [IO.Path]::DirectorySeparatorChar,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label must remain outside the source repository."
    }
    return $full
}

function Test-ProductionInstallerSameOrChild {
    param([string]$Path, [string]$Root)
    $pathFull = [IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
    return $pathFull.Equals($rootFull, [StringComparison]::OrdinalIgnoreCase) -or
        $pathFull.StartsWith(
            $rootFull + [IO.Path]::DirectorySeparatorChar,
            [StringComparison]::OrdinalIgnoreCase)
}

function Test-ProductionInstallerPathsOverlap {
    param([string]$Left, [string]$Right)
    return (Test-ProductionInstallerSameOrChild $Left $Right) -or
        (Test-ProductionInstallerSameOrChild $Right $Left)
}

function Get-ProductionInstallerHttpsOrigin {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $uri = $null
    if (-not [Uri]::TryCreate($Value, [UriKind]::Absolute, [ref]$uri) -or
        $uri.Scheme -cne 'https' -or $uri.IsLoopback -or
        -not [string]::IsNullOrEmpty($uri.UserInfo) -or
        -not [string]::IsNullOrEmpty($uri.Fragment)) {
        throw "$Label is not one production HTTPS URI."
    }
    return $uri.GetLeftPart([UriPartial]::Authority) + '/'
}

function Open-ProductionInstallerLockedJson {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][string]$SchemaPath,
        [int64]$MaximumBytes = 64MB
    )
    $input = ProductionReleaseState\Open-ProductionReleaseInput `
        -Path $Path -Label $Label -MaximumBytes $MaximumBytes
    try {
        [byte[]]$bytes = ProductionReleaseState\Read-ProductionReleaseInputBytes `
            -Descriptor $input -Label $Label
        $value = ProductionReleaseState\ConvertFrom-StrictProductionJsonBytes `
            -Bytes $bytes -Label $Label -SchemaPath $SchemaPath
        $input | Add-Member -NotePropertyName Bytes -NotePropertyValue $bytes
        $input | Add-Member -NotePropertyName Value -NotePropertyValue $value
        [void](ProductionReleaseState\Assert-CanonicalProductionJsonInput `
            -Input $input -Label $Label)
        return $input
    }
    catch {
        $input.Stream.Dispose()
        throw
    }
}

function Assert-ProductionInstallerExactInventory {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][Collections.IDictionary]$Expected,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $entries = @(Get-ChildItem -LiteralPath $Path -Force)
    if ($entries.Count -ne $Expected.Count) {
        throw "$Label does not contain its exact expected inventory."
    }
    foreach ($entry in $entries) {
        $matches = @($Expected.Keys | Where-Object {
                [string]$_ -ceq [string]$entry.Name
            })
        if ($matches.Count -ne 1 -or
            ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            [bool]$entry.PSIsContainer -ne [bool]$Expected[$matches[0]]) {
            throw "$Label contains an unexpected, linked, or mistyped entry."
        }
    }
}

function Assert-ProductionInstallerTrustSeparation {
    param([Parameter(Mandatory = $true)][psobject]$Plan)
    $domains = @(
        $Plan.releaseManifestTrust,
        $Plan.externalResponseTrusts.clientSigning,
        $Plan.externalResponseTrusts.manifestPublishing,
        $Plan.externalResponseTrusts.installerSigning,
        $Plan.externalResponseTrusts.feedPromotion)
    $ids = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $points = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($domain in $domains) {
        if (-not $ids.Add([string]$domain.keyId)) {
            throw 'Plan v2 trust domains must retain five distinct key IDs.'
        }
        $point = ProductionReleaseState\Get-ProductionReleaseP256PublicKeyIdentity `
            -Trust $domain `
            -Label ("Plan v2 trust domain '" + [string]$domain.purpose + "'")
        if (-not $points.Add($point)) {
            throw 'Plan v2 trust domains must retain five distinct P-256 public keys.'
        }
    }
}

function Get-ProductionInstallerR5HeadSha256 {
    param(
        [Parameter(Mandatory = $true)]$R5ReceiptInput,
        [Parameter(Mandatory = $true)][string]$Edition,
        [Parameter(Mandatory = $true)][string]$TargetChannel
    )
    $receipt = $R5ReceiptInput.Value
    $head = [ordered]@{
        schemaVersion = 2
        stateType = 'ensou-dsh-launcher-production-release-head'
        orchestrationId = [string]$receipt.orchestrationId
        edition = $Edition
        planSha256 = [string]$receipt.planSha256
        identitySha256 = [string]$receipt.identitySha256
        revision = 5
        phase = if ($TargetChannel -ceq 'pilot') {
            'PILOT_SIGNED_CANDIDATE_IMPORTED'
        }
        else { 'STABLE_SIGNED_CANDIDATE_IMPORTED' }
        receiptFileName = [string]$R5ReceiptInput.FileName
        receiptSha256 = [string]$R5ReceiptInput.Sha256
        updatedAtUtc = [string]$receipt.recordedAtUtc
        targetChannel = $TargetChannel
    }
    return ProductionReleaseState\Get-ProductionSha256Bytes `
        -Bytes (ProductionReleaseState\ConvertTo-ProductionJsonBytes -Value $head)
}

function Invoke-ProductionInstallerPayloadSelfCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Edition,
        [Parameter(Mandatory = $true)]$InstallerInput,
        [Parameter(Mandatory = $true)][psobject]$Request,
        [Parameter(Mandatory = $true)][psobject]$DraftResponse,
        [Parameter(Mandatory = $true)][string]$ExpectedSignerCertificateSha256,
        [Parameter(Mandatory = $true)][int]$TimeoutMilliseconds,
        [AllowNull()][psobject]$InstallManifest
    )
    if ($Edition -ceq 'Personal') {
        $expectation =
            PersonalInstallerSigningPipeline\Get-PersonalSigningPipelinePayloadExpectation `
                -Request $Request
        return PersonalInstallerProductionPayloadSelfCheck\Invoke-PersonalInstallerProductionPayloadSelfCheck `
            -InstallerInput $InstallerInput `
            -Response $DraftResponse `
            -ExpectedSignerCertificateSha256 $ExpectedSignerCertificateSha256 `
            -Expectation $expectation `
            -TimeoutMilliseconds $TimeoutMilliseconds
    }
    if ($Edition -ceq 'Enterprise' -and $null -ne $InstallManifest) {
        return EnterpriseInstallerProductionPayloadSelfCheck\Invoke-EnterpriseInstallerProductionPayloadSelfCheck `
            -InstallerInput $InstallerInput `
            -Request $Request `
            -InstallManifest $InstallManifest `
            -ExpectedSignerCertificateSha256 $ExpectedSignerCertificateSha256 `
            -TimeoutMilliseconds $TimeoutMilliseconds `
            -MaximumOutputBytes 65536
    }
    throw 'Installer payload self-check received an unsupported edition or missing Enterprise manifest.'
}

function Copy-ProductionInstallerLockedInput {
    param(
        [Parameter(Mandatory = $true)]$Descriptor,
        [Parameter(Mandatory = $true)][string]$DestinationPath
    )
    $output = [IO.File]::Open(
        $DestinationPath, [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        [void][EnsouLauncherProduction.NativeFileIdentity]::
            RequireOrdinarySingleLink($output.SafeFileHandle)
        $Descriptor.Stream.Position = 0
        $Descriptor.Stream.CopyTo($output)
        $output.Flush($true)
        if ($output.Length -ne [int64]$Descriptor.SizeBytes) {
            throw 'Signed Installer copy did not preserve its exact byte length.'
        }
    }
    finally {
        $output.Dispose()
        $Descriptor.Stream.Position = 0
    }
}

function Write-ProductionInstallerCreateNewBytes {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][byte[]]$Bytes
    )
    $output = [IO.File]::Open(
        $Path, [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        [void][EnsouLauncherProduction.NativeFileIdentity]::
            RequireOrdinarySingleLink($output.SafeFileHandle)
        $output.Write($Bytes, 0, $Bytes.Length)
        $output.Flush($true)
        if ($output.Length -ne [int64]$Bytes.LongLength) {
            throw 'Installer response write did not preserve its exact byte length.'
        }
    }
    finally { $output.Dispose() }
}

function Remove-ProductionInstallerOwnedStage {
    param(
        [Parameter(Mandatory = $true)][string]$StagePath,
        [Parameter(Mandatory = $true)][string]$OutputPath,
        [Parameter(Mandatory = $true)][string]$ResponseFileName,
        [Parameter(Mandatory = $true)][string]$InstallerFileName,
        [Parameter(Mandatory = $true)]$OwnerLease
    )
    if (-not (Test-Path -LiteralPath $StagePath)) { return }
    $stage = [IO.Path]::GetFullPath($StagePath)
    $output = [IO.Path]::GetFullPath($OutputPath)
    $prefix = [IO.Path]::GetFileName($output) + '.pending-'
    if ([IO.Path]::GetDirectoryName($stage) -cne
            [IO.Path]::GetDirectoryName($output) -or
        -not [IO.Path]::GetFileName($stage).StartsWith(
            $prefix, [StringComparison]::Ordinal) -or
        [IO.Path]::GetFileName($stage).Length -ne $prefix.Length + 32) {
        throw 'Refusing to clean a staging path not owned by this Installer response issuer.'
    }
    $root = Get-Item -LiteralPath $stage -Force -ErrorAction Stop
    if (-not $root.PSIsContainer -or
        ($root.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Refusing to clean a replaced or linked Installer response staging root.'
    }
    [void](ProductionReleaseState\Assert-ProductionReleaseDirectoryStillLocked `
        -Descriptor $OwnerLease -Label 'Owned Installer response staging directory')
    $allowed = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    foreach ($relative in @(
            'signed', $ResponseFileName, ('signed\' + $InstallerFileName))) {
        [void]$allowed.Add($relative)
    }
    foreach ($entry in @(Get-ChildItem -LiteralPath $stage -Force -Recurse)) {
        if (-not $allowed.Contains([IO.Path]::GetRelativePath($stage, $entry.FullName)) -or
            ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Refusing to clean a changed or linked Installer response staging tree.'
        }
    }
    $OwnerLease.Handle.Dispose()
    [IO.Directory]::Delete($stage, $true)
}

function Invoke-ProductionInstallerSigningResponse {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$StateRoot,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9a-f]{64}$')]
        [string]$ExpectedHeadSha256,
        [Parameter(Mandatory = $true)][string]$SignedInstallerPath,
        [Parameter(Mandatory = $true)][string]$ResponsePrivateKeyPath,
        [Parameter(Mandatory = $true)][string]$OutputRoot,
        [ValidateRange(100, 300000)]
        [int]$SelfCheckTimeoutMilliseconds = 300000
    )

    $stateLock = $null
    $outputParentLease = $null
    $stageOwnerLease = $null
    $stageMoveLease = $null
    $planInput = $null
    $requestInput = $null
    $r5Input = $null
    $r6Input = $null
    $keyInput = $null
    $signedInput = $null
    $bundleInputs = [Collections.Generic.List[object]]::new()
    $bundleDirectories = [Collections.Generic.List[object]]::new()
    $keyBytes = $null
    $signer = $null
    $stagePath = $null
    $stageOwned = $false
    $committed = $false
    $responseFileName = ''
    $installerFileName = ''

    try {
        $stateRoot = Resolve-ProductionInstallerExternalPath `
            $StateRoot 'Production state root'
        $signedPath = Resolve-ProductionInstallerExternalPath `
            $SignedInstallerPath 'Externally signed Installer'
        $keyPath = Resolve-ProductionInstallerExternalPath `
            $ResponsePrivateKeyPath 'Installer response-attestation private key'
        $outputRoot = Resolve-ProductionInstallerExternalPath `
            $OutputRoot 'Installer-signing response output'
        if (-not (Test-Path -LiteralPath $stateRoot -PathType Container)) {
            throw 'Production state root must exist.'
        }
        if (Test-Path -LiteralPath $outputRoot) {
            throw 'Installer-signing response output is create-only and already exists.'
        }
        if ((Test-ProductionInstallerSameOrChild $signedPath $stateRoot) -or
            (Test-ProductionInstallerSameOrChild $keyPath $stateRoot) -or
            (Test-ProductionInstallerPathsOverlap $outputRoot $stateRoot) -or
            (Test-ProductionInstallerPathsOverlap $outputRoot $signedPath) -or
            (Test-ProductionInstallerPathsOverlap $outputRoot $keyPath) -or
            $signedPath.Equals($keyPath, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'State, signed Installer, response key, and output paths must not overlap.'
        }
        $outputParent = [IO.Path]::GetDirectoryName($outputRoot)
        $outputParentLease = ProductionReleaseState\Open-ProductionReleaseDirectoryLease `
            -Path $outputParent -Label 'Installer response output parent'
        $stateLock = ProductionReleaseState\Enter-ProductionReleaseStateReadLock `
            -StateRoot $stateRoot
        $state = ProductionReleaseState\Get-ProductionReleaseState `
            -StateRoot $stateRoot -StateSchemaPath $stateSchemaPath
        if ([int]$state.SchemaVersion -ne 2 -or
            [string]$state.Identity.edition -notin @('Personal', 'Enterprise') -or
            $null -eq $state.Head -or [int]$state.Head.revision -ne 6 -or
            [string]$state.Head.phase -cne 'INSTALLER_SIGNING_REQUESTED' -or
            [string]$state.HeadSha256 -cne $ExpectedHeadSha256 -or
            $null -ne $state.OrphanReceipt -or @($state.Receipts).Count -ne 6) {
            throw 'NO-GO: issuer requires the exact committed v2 INSTALLER_SIGNING_REQUESTED r6 head without an orphan transition.'
        }

        $planInput = Open-ProductionInstallerLockedJson `
            -Path (Join-Path $stateRoot 'plan.json') `
            -Label 'Committed production plan snapshot' `
            -SchemaPath $planSchemaPath
        $plan = $planInput.Value
        $edition = [string]$plan.edition
        $targetChannel = [string]$plan.targetChannel
        if ([string]$planInput.Sha256 -cne [string]$state.Identity.planSha256 -or
            [string]$plan.orchestrationId -cne [string]$state.Identity.orchestrationId -or
            $edition -cne [string]$state.Identity.edition -or
            $targetChannel -cne [string]$state.TargetChannel -or
            ($edition -ceq 'Personal' -and $targetChannel -cne 'pilot') -or
            ($edition -ceq 'Enterprise' -and $targetChannel -cne 'stable')) {
            throw 'Committed production plan differs from the current Personal Pilot or Enterprise Stable state identity.'
        }
        Assert-ProductionInstallerTrustSeparation -Plan $plan

        $installerFileName = if ($edition -ceq 'Personal') {
            'Ensou.Dsh.Personal.Installer.exe'
        }
        else { 'Ensou.Dsh.Enterprise.Installer.exe' }
        if ([IO.Path]::GetFileName($signedPath) -cne $installerFileName) {
            throw 'Externally signed Installer uses a noncanonical edition filename.'
        }
        $responseFileName = if ($edition -ceq 'Personal') {
            'personal-installer-signing-response.v2.json'
        }
        else { 'installer-signing-response.v1.json' }
        $responseSchemaPath = if ($edition -ceq 'Personal') {
            $personalResponseSchemaPath
        }
        else { $enterpriseResponseSchemaPath }

        $requestRoot = Join-Path $stateRoot 'requests\installer-signing.v2'
        $payloadRoot = Join-Path $requestRoot 'payload'
        $trustedRoot = Join-Path $requestRoot 'trusted-build'
        $unsignedRoot = Join-Path $requestRoot 'unsigned'
        $requestInput = Open-ProductionInstallerLockedJson `
            -Path (Join-Path $requestRoot 'installer-signing-request.v2.json') `
            -Label 'Committed Installer-signing r6 request' `
            -SchemaPath $requestSchemaPath
        $request = $requestInput.Value
        $r5Name = if ($targetChannel -ceq 'pilot') {
            '0005-pilot-signed-candidate-imported.json'
        }
        else { '0005-stable-signed-candidate-imported.json' }
        $r5Input = Open-ProductionInstallerLockedJson `
            -Path (Join-Path (Join-Path $stateRoot 'receipts') $r5Name) `
            -Label 'Committed r5 signed-candidate receipt' `
            -SchemaPath $stateSchemaPath
        $r6Input = Open-ProductionInstallerLockedJson `
            -Path (Join-Path $stateRoot 'receipts\0006-installer-signing-requested.json') `
            -Label 'Committed r6 Installer-signing receipt' `
            -SchemaPath $stateSchemaPath
        $r6 = $r6Input.Value
        $r6Data = $r6.data
        $trust = $plan.externalResponseTrusts.installerSigning
        $purpose = if ($edition -ceq 'Personal') {
            'personal-installer-signing-response'
        }
        else { 'installer-signing-response' }
        $payloadType = if ($edition -ceq 'Personal') {
            'ensou-dsh-personal-installer-signing-response-authentication-v2'
        }
        else {
            'ensou-dsh-launcher-installer-signing-response-authentication-v1'
        }
        $r5HeadSha256 = Get-ProductionInstallerR5HeadSha256 `
            -R5ReceiptInput $r5Input -Edition $edition `
            -TargetChannel $targetChannel
        if ([string]$r6Input.FileName -cne
                '0006-installer-signing-requested.json' -or
            [int]$r6.schemaVersion -ne 2 -or
            [string]$r6.receiptType -cne
                'ensou-dsh-launcher-production-release-transition' -or
            [string]$r6.orchestrationId -cne [string]$plan.orchestrationId -or
            [string]$r6.edition -cne $edition -or
            [string]$r6.targetChannel -cne $targetChannel -or
            [string]$r6.planSha256 -cne [string]$planInput.Sha256 -or
            [string]$r6.identitySha256 -cne [string]$state.Head.identitySha256 -or
            [int]$r6.revision -ne 6 -or
            [string]$r6.phase -cne 'INSTALLER_SIGNING_REQUESTED' -or
            [string]$state.Head.receiptFileName -cne
                '0006-installer-signing-requested.json' -or
            [string]$r6Data.evidenceType -cne 'INSTALLER_SIGNING_REQUESTED' -or
            [int]$r6Data.requestSchemaVersion -ne 2 -or
            [string]$r6Data.requestRelativePath -cne
                'requests/installer-signing.v2/installer-signing-request.v2.json' -or
            [string]$r6Data.admissionReason -cne
                'INSTALLER_SIGNING_RESPONSE_REQUIRED' -or
            [string]$r6Data.productionAdmission -cne 'NO_GO' -or
            [string]$request.schemaVersion -ne '2' -or
            [string]$request.orchestrationId -cne [string]$plan.orchestrationId -or
            [string]$request.edition -cne $edition -or
            [string]$request.releaseSetId -cne [string]$plan.releaseSetId -or
            [string]$request.channel -cne $targetChannel -or
            [string]$request.planSha256 -cne [string]$planInput.Sha256 -or
            [string]$request.baseHeadSha256 -cne $r5HeadSha256 -or
            [string]$r6Input.Sha256 -cne [string]$state.Head.receiptSha256 -or
            [string]$r6.previousReceiptSha256 -cne [string]$r5Input.Sha256 -or
            [string]$r6Data.requestSha256 -cne [string]$requestInput.Sha256 -or
            [string]$r6Data.baseHeadSha256 -cne $r5HeadSha256 -or
            [string]$r6Data.baseReceiptSha256 -cne [string]$r5Input.Sha256 -or
            [string]$r6Data.createdAtUtc -cne [string]$request.createdAtUtc -or
            [string]$r6Data.expiresAtUtc -cne [string]$request.expiresAtUtc -or
            [string]$r6Data.authenticationKeyId -cne [string]$trust.keyId -or
            [string]$r6Data.authenticationPurpose -cne $purpose -or
            [string]$request.responseAuthentication.algorithm -cne 'ES256' -or
            [string]$request.responseAuthentication.keyId -cne [string]$trust.keyId -or
            [string]$request.responseAuthentication.purpose -cne $purpose -or
            [string]$request.responseAuthentication.payloadType -cne $payloadType -or
            [int]$request.responseAuthentication.maximumResponseAgeMinutes -ne
                [int]$plan.authenticodePolicy.maximumResponseAgeMinutes) {
            throw 'Committed Installer-signing request is not bound to its exact plan, r5 base, r6 receipt, and purpose-specific trust.'
        }
        [void](InstallerSigningContracts\Assert-InstallerSigningRequestContract `
            -Request $request -InstallerSigningTrust $trust `
            -ReleaseManifestTrust $plan.releaseManifestTrust)

        $releaseTrustSha256 =
            InstallerSigningContracts\Get-InstallerSigningObjectSha256 `
                -Value $plan.releaseManifestTrust
        if ($plan.authenticodePolicy.requireTrustedTimestamp -ne $true) {
            throw 'Production plan does not require the exact trusted RFC3161 timestamp policy.'
        }
        if ($edition -ceq 'Personal') {
            $releasePublicIdentity = [ordered]@{
                algorithm = [string]$plan.releaseManifestTrust.algorithm
                keyId = [string]$plan.releaseManifestTrust.keyId
                x = [string]$plan.releaseManifestTrust.x
                y = [string]$plan.releaseManifestTrust.y
            }
            if ([string]$request.source.commit -cne [string]$plan.sourceCommit -or
                [string]$request.compiledTrust.channel -cne $targetChannel -or
                [string]$request.compiledTrust.manifestOrigin -cne
                    (Get-ProductionInstallerHttpsOrigin `
                        -Value ([string]$plan.manifestUri) `
                        -Label 'Personal plan manifest URI') -or
                [string]$request.compiledTrust.artifactOrigin -cne
                    (Get-ProductionInstallerHttpsOrigin `
                        -Value ([string]$plan.artifactBaseUri) `
                        -Label 'Personal plan artifact URI') -or
                [string]$request.compiledTrust.releaseKeyId -cne
                    [string]$plan.releaseManifestTrust.keyId -or
                [string]$request.compiledTrust.releaseKeyIdentitySha256 -cne
                    (InstallerSigningContracts\Get-InstallerSigningObjectSha256 `
                        -Value $releasePublicIdentity) -or
                [string]$request.compiledTrust.authenticodeSignerSha256Thumbprint -cne
                    [string]$plan.authenticodePolicy.signerSha256Thumbprint) {
                throw 'Personal Installer request differs from the exact plan source and compiled trust policy.'
            }
        }
        elseif ([string]$request.sourceCommit -cne [string]$plan.sourceCommit -or
            [string]$request.r5Evidence.releaseManifestTrustSha256 -cne
                $releaseTrustSha256 -or
            [string]$request.r5Evidence.releaseCompatibilitySha256 -cne
                (InstallerSigningContracts\Get-InstallerSigningObjectSha256 `
                    -Value $plan.releaseCompatibility)) {
            throw 'Enterprise Installer request differs from the exact stable plan and r5 release policy.'
        }

        if ($edition -ceq 'Personal') {
            $bindings =
                PersonalInstallerSigningPipeline\Get-PersonalInstallerSigningRequestBindings `
                    -Request $request
            foreach ($name in $bindings.Keys) {
                if ([string]$r6Data.$name -cne [string]$bindings[$name]) {
                    throw "Personal r6 request binding '$name' differs from its receipt."
                }
            }
            if ([string]$r6Data.authenticationPayloadType -cne $payloadType) {
                throw 'Personal r6 receipt does not bind the dedicated response payload type.'
            }
        }
        else {
            if ([string]$request.sourceCommit -cne [string]$plan.sourceCommit -or
                [string]$r6Data.sourceBuildInputSetSha256 -cne
                    [string]$request.sourceBuildInputSetSha256 -or
                [string]$r6Data.targetBuildIdentitySha256 -cne
                    [string]$request.buildExecution.targetBuildIdentitySha256 -or
                [string]$r6Data.payloadSetSha256 -cne
                    [string]$request.installerPayload.inventorySha256 -or
                [string]$r6Data.trustedBuildEvidenceSha256 -cne
                    [string]$request.trustedBuildEvidence.sha256 -or
                [string]$r6Data.resourceBindingSha256 -cne
                    [string]$request.trustedBuildEvidence.resourceBindingSha256) {
                throw 'Enterprise r6 receipt does not bind the exact source, build, payload, and trusted evidence request closure.'
            }
        }

        $created = ProductionReleaseState\ConvertFrom-ProductionUtc `
            -Value ([string]$request.createdAtUtc) `
            -Label 'Installer-signing request creation time'
        $expires = ProductionReleaseState\ConvertFrom-ProductionUtc `
            -Value ([string]$request.expiresAtUtc) `
            -Label 'Installer-signing request expiry time'
        $now = [DateTimeOffset]::UtcNow
        if ($expires -le $created -or $now -lt $created -or $now -gt $expires) {
            throw 'Installer-signing request is outside its exact current lifetime.'
        }

        $rootInventory = [ordered]@{
            'installer-signing-request.v2.json' = $false
            'payload' = $true
            'trusted-build' = $true
            'unsigned' = $true
        }
        $trustedInventory = [ordered]@{'trusted-build-evidence.v1.json' = $false}
        $unsignedInventory = [ordered]@{$installerFileName = $false}
        Assert-ProductionInstallerExactInventory $requestRoot $rootInventory `
            'Committed Installer-signing request bundle'
        Assert-ProductionInstallerExactInventory $trustedRoot $trustedInventory `
            'Committed Installer trusted-build evidence'
        Assert-ProductionInstallerExactInventory $unsignedRoot $unsignedInventory `
            'Committed unsigned Installer payload'
        $payloadInventory = [ordered]@{}
        $payloadFiles = if ($edition -ceq 'Personal') {
            @($request.payload.files)
        }
        else { @($request.installerPayload.files) }
        foreach ($file in $payloadFiles) {
            if ($payloadInventory.Contains([string]$file.fileName)) {
                throw 'Installer request payload repeats a filename.'
            }
            $payloadInventory[[string]$file.fileName] = $false
        }
        Assert-ProductionInstallerExactInventory $payloadRoot $payloadInventory `
            'Committed Installer payload'

        $evidenceSchema = if ($edition -ceq 'Personal') {
            $personalEvidenceSchemaPath
        }
        else { $enterpriseEvidenceSchemaPath }
        $trustedInput = Open-ProductionInstallerLockedJson `
            -Path (Join-Path $trustedRoot 'trusted-build-evidence.v1.json') `
            -Label 'Committed Installer trusted-build evidence' `
            -SchemaPath $evidenceSchema
        $bundleInputs.Add($trustedInput)
        if ([int64]$trustedInput.SizeBytes -ne
                [int64]$request.trustedBuildEvidence.sizeBytes -or
            [string]$trustedInput.Sha256 -cne
                [string]$request.trustedBuildEvidence.sha256) {
            throw 'Installer trusted-build evidence differs from its request descriptor.'
        }
        $unsignedInput = ProductionReleaseState\Open-ProductionReleaseInput `
            -Path (Join-Path $unsignedRoot $installerFileName) `
            -Label 'Committed unsigned Installer' -MaximumBytes 1GB
        $bundleInputs.Add($unsignedInput)
        [void](InstallerSigningContracts\Assert-UnsignedInstallerSigningInput `
            -Path $unsignedInput.Path -Descriptor $request.unsignedInstaller)
        if ([int64]$unsignedInput.SizeBytes -ne
                [int64]$r6Data.unsignedInstaller.sizeBytes -or
            [string]$unsignedInput.Sha256 -cne
                [string]$r6Data.unsignedInstaller.sha256) {
            throw 'Committed unsigned Installer differs from the r6 receipt.'
        }

        $installManifest = $null
        foreach ($file in $payloadFiles) {
            if ($edition -ceq 'Personal' -and
                [string]$file.relativePath -cne
                    ('payload/' + [string]$file.fileName)) {
                throw "Installer payload role '$($file.role)' uses a noncanonical request path."
            }
            $payloadInput = ProductionReleaseState\Open-ProductionReleaseInput `
                -Path (Join-Path $payloadRoot ([string]$file.fileName)) `
                -Label "Committed Installer payload role $($file.role)" `
                -MaximumBytes 8GB
            $bundleInputs.Add($payloadInput)
            if ([int64]$payloadInput.SizeBytes -ne [int64]$file.sizeBytes -or
                [string]$payloadInput.Sha256 -cne [string]$file.sha256) {
                throw "Installer payload role '$($file.role)' differs from its request descriptor."
            }
            if ($edition -ceq 'Enterprise' -and
                [string]$file.role -ceq 'install-manifest') {
                [byte[]]$manifestBytes =
                    ProductionReleaseState\Read-ProductionReleaseInputBytes `
                        -Descriptor $payloadInput `
                        -Label 'Enterprise install manifest payload'
                $installManifest =
                    ProductionReleaseState\ConvertFrom-StrictProductionJsonBytes `
                        -Bytes $manifestBytes `
                        -Label 'Enterprise install manifest payload'
                [void](ProductionReleaseState\Assert-CanonicalProductionJsonInput `
                    -Input ([pscustomobject]@{
                        Value = $installManifest
                        Bytes = $manifestBytes
                        Sha256 = [string]$payloadInput.Sha256
                    }) -Label 'Enterprise install manifest payload')
            }
        }
        if ($edition -ceq 'Enterprise') {
            if ($null -eq $installManifest) {
                throw 'Enterprise Installer payload lacks its exact install manifest.'
            }
            ProductionReleaseState\Assert-ExactProductionJsonMembers `
                -Value $installManifest `
                -Expected @(
                    'schemaVersion', 'layoutProfile', 'launcherReleaseId',
                    'runtimeReleaseId', 'launcherArchive',
                    'launcherArchiveSizeBytes', 'launcherArchiveSha256',
                    'runtimeArchive', 'runtimeArchiveSizeBytes',
                    'runtimeArchiveSha256', 'bootstrapperFile',
                    'bootstrapperSizeBytes', 'bootstrapperSha256',
                    'publishedAtUtc') `
                -Label 'Enterprise install manifest payload'
            $launcherPayload = @($payloadFiles | Where-Object {
                    [string]$_.role -ceq 'launcher'
                })
            $runtimePayload = @($payloadFiles | Where-Object {
                    [string]$_.role -ceq 'runtime'
                })
            $bootstrapperPayload = @($payloadFiles | Where-Object {
                    [string]$_.role -ceq 'bootstrapper'
                })
            if ($launcherPayload.Count -ne 1 -or
                $runtimePayload.Count -ne 1 -or
                $bootstrapperPayload.Count -ne 1 -or
                [int]$installManifest.schemaVersion -ne 1 -or
                [string]$installManifest.layoutProfile -cne 'enterprise' -or
                [string]$installManifest.launcherArchive -cne
                    [string]$launcherPayload[0].fileName -or
                [string]$installManifest.launcherArchiveSha256 -cne
                    [string]$launcherPayload[0].sha256 -or
                [int64]$installManifest.launcherArchiveSizeBytes -ne
                    [int64]$launcherPayload[0].sizeBytes -or
                [string]$installManifest.runtimeArchive -cne
                    [string]$runtimePayload[0].fileName -or
                [string]$installManifest.runtimeArchiveSha256 -cne
                    [string]$runtimePayload[0].sha256 -or
                [int64]$installManifest.runtimeArchiveSizeBytes -ne
                    [int64]$runtimePayload[0].sizeBytes -or
                [string]$installManifest.bootstrapperFile -cne
                    [string]$bootstrapperPayload[0].fileName -or
                [string]$installManifest.bootstrapperSha256 -cne
                    [string]$bootstrapperPayload[0].sha256 -or
                [int64]$installManifest.bootstrapperSizeBytes -ne
                    [int64]$bootstrapperPayload[0].sizeBytes) {
                throw 'Enterprise install manifest does not bind the exact production payload request.'
            }
        }
        foreach ($directory in @($requestRoot, $payloadRoot, $trustedRoot, $unsignedRoot)) {
            $bundleDirectories.Add(
                (ProductionReleaseState\Open-ProductionReleaseDirectoryLease `
                    -Path $directory `
                    -Label 'Committed Installer request directory'))
        }

        $signedInput = ProductionReleaseState\Open-ProductionReleaseInput `
            -Path $signedPath -Label 'Externally signed Installer' `
            -MaximumBytes 1GB
        $authenticode = InstallerSigningContracts\Get-ExactPeAuthenticodeEvidence `
            -Path $signedInput.Path `
            -ExpectedSignerCertificateSha256 `
                ([string]$plan.authenticodePolicy.signerSha256Thumbprint) `
            -ExpectedPeContentSha256 `
                ([string]$request.unsignedInstaller.peContentSha256)
        [void](ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
            -Descriptor $signedInput -Label 'Externally signed Installer')
        if ([string]$authenticode.FileName -cne $installerFileName -or
            [int64]$authenticode.SizeBytes -ne [int64]$signedInput.SizeBytes -or
            [string]$authenticode.SignedFileSha256 -cne [string]$signedInput.Sha256 -or
            [string]$authenticode.PeContentSha256 -cne
                [string]$request.unsignedInstaller.peContentSha256 -or
            [int64]$signedInput.SizeBytes -le [int64]$unsignedInput.SizeBytes -or
            [string]$signedInput.Sha256 -ceq [string]$unsignedInput.Sha256 -or
            [string]$authenticode.AuthenticodeStatus -cne 'Valid' -or
            [string]$authenticode.TimestampProtocol -cne 'RFC3161' -or
            [int]$authenticode.PrimarySignerCount -ne 1 -or
            [bool]$authenticode.LegacyCounterSignaturePresent) {
            throw 'Externally signed Installer is not the exact size-grown pinned Authenticode and RFC3161 transform of the r6 unsigned PE.'
        }
        $timestamp = ProductionReleaseState\ConvertFrom-ProductionUtc `
            -Value ([string]$authenticode.TimestampUtc) `
            -Label 'Installer RFC3161 timestamp'
        if ($timestamp -lt $created -or $timestamp -gt $expires -or
            $timestamp -gt [DateTimeOffset]::UtcNow) {
            throw 'Installer RFC3161 timestamp is outside the exact r6 request lifetime.'
        }
        $signedInstaller = [ordered]@{
            role = 'installer'; fileName = $installerFileName
            relativePath = 'signed/' + $installerFileName
            sizeBytes = [int64]$authenticode.SizeBytes
            sha256 = [string]$authenticode.SignedFileSha256
            peContentSha256 = [string]$authenticode.PeContentSha256
            fullHashChangedFromUnsigned = $true
        }
        $authenticodeResponse = [ordered]@{
            status = 'Valid'; signatureType = 'Authenticode'; primarySignerCount = 1
            signerCertificateSha256 = [string]$authenticode.SignerCertificateSha256
            signerDigestAlgorithmOid = [string]$authenticode.SignerDigestAlgorithmOid
            spcIndirectDataContentTypeOid = [string]$authenticode.SpcIndirectDataContentTypeOid
            spcPeImageDataTypeOid = [string]$authenticode.SpcPeImageDataTypeOid
            spcDigestAlgorithmOid = [string]$authenticode.SpcDigestAlgorithmOid
            spcPeContentSha256 = [string]$authenticode.SpcPeContentSha256
            timestampProtocol = 'RFC3161'
            timestampTokenOid = [string]$authenticode.TimestampTokenOid
            timestampContentTypeOid = [string]$authenticode.TimestampContentTypeOid
            timestampSignerCertificateSha256 =
                [string]$authenticode.TimestampSignerCertificateSha256
            timestampUtc = [string]$authenticode.TimestampUtc
            rfc3161PrimarySignerBound = $true
        }
        $draft = [pscustomobject][ordered]@{
            unsignedInstaller = $request.unsignedInstaller
            signedInstaller = [pscustomobject]$signedInstaller
            authenticode = [pscustomobject]$authenticodeResponse
        }
        $payloadSelfCheck = Invoke-ProductionInstallerPayloadSelfCheck `
            -Edition $edition -InstallerInput $signedInput `
            -Request $request -DraftResponse $draft `
            -ExpectedSignerCertificateSha256 `
                ([string]$plan.authenticodePolicy.signerSha256Thumbprint) `
            -TimeoutMilliseconds $SelfCheckTimeoutMilliseconds `
            -InstallManifest $installManifest
        [void](ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
            -Descriptor $signedInput `
            -Label 'Externally signed Installer after production payload self-check')

        $keyInput = ProductionReleaseState\Open-ProductionReleaseInput `
            -Path $keyPath `
            -Label 'Installer response-attestation private key' `
            -MaximumBytes 64KB
        [byte[]]$keyBytes = ProductionReleaseState\Read-ProductionReleaseInputBytes `
            -Descriptor $keyInput `
            -Label 'Installer response-attestation private key'
        $signer = [Security.Cryptography.ECDsa]::Create()
        $consumed = 0
        try { $signer.ImportPkcs8PrivateKey($keyBytes, [ref]$consumed) }
        catch { throw 'Installer response-attestation private key is not valid PKCS8.' }
        if ($consumed -ne $keyBytes.Length) {
            throw 'Installer response-attestation private key has trailing bytes.'
        }
        $public = $signer.ExportParameters($false)
        if ($signer.KeySize -ne 256 -or
            [string]$public.Curve.Oid.Value -cne '1.2.840.10045.3.1.7' -or
            $public.Q.X.Length -ne 32 -or $public.Q.Y.Length -ne 32 -or
            (ConvertTo-ProductionInstallerBase64Url $public.Q.X) -cne
                [string]$trust.x -or
            (ConvertTo-ProductionInstallerBase64Url $public.Q.Y) -cne
                [string]$trust.y) {
            throw 'Installer response-attestation private key is not the exact P-256 key pinned by plan.externalResponseTrusts.installerSigning.'
        }

        $completed = [DateTimeOffset]::UtcNow
        if ($completed -gt $expires) {
            throw 'Installer response completion is outside the r6 request lifetime.'
        }
        if ($edition -ceq 'Personal') {
            $response = [ordered]@{
                schemaVersion = 2
                responseType = 'ensou-dsh-personal-installer-signing-response'
                orchestrationId = [string]$request.orchestrationId
                edition = 'Personal'; releaseSetId = [string]$request.releaseSetId
                channel = 'pilot'; planSha256 = [string]$request.planSha256
                requestRelativePath = 'requests/installer-signing.v2/installer-signing-request.v2.json'
                requestSha256 = [string]$requestInput.Sha256
                requestNonce = [string]$request.requestNonce
                baseHeadSha256 = [string]$request.baseHeadSha256
                admissionHeadSha256 = $ExpectedHeadSha256
                admissionRevision = 6
                r6ReceiptRelativePath = 'receipts/0006-installer-signing-requested.json'
                r6ReceiptSha256 = [string]$r6Input.Sha256
                requestCreatedAtUtc = [string]$request.createdAtUtc
                requestExpiresAtUtc = [string]$request.expiresAtUtc
                completedAtUtc = ProductionReleaseState\ConvertTo-ProductionUtc $completed
                requestBindings = $bindings
                unsignedInstaller = $request.unsignedInstaller
                signedInstaller = $signedInstaller
                authenticode = $authenticodeResponse
                payloadSelfCheck = $payloadSelfCheck
                authentication = [ordered]@{
                    algorithm = 'ES256'; keyId = [string]$trust.keyId
                    purpose = $purpose; payloadType = $payloadType; value = ''
                }
            }
            [byte[]]$authenticationPayload =
                PersonalInstallerSigningPipeline\Get-PersonalInstallerSigningResponseAuthenticationPayload `
                    -Response ([pscustomobject]$response)
        }
        else {
            $response = [ordered]@{
                schemaVersion = 1
                responseType = 'ensou-dsh-launcher-installer-signing-response'
                orchestrationId = [string]$request.orchestrationId
                edition = 'Enterprise'; releaseSetId = [string]$request.releaseSetId
                channel = 'stable'; planSha256 = [string]$request.planSha256
                sourceTree = [string]$request.sourceTree
                sourceBuildInputSetSha256 = [string]$request.sourceBuildInputSetSha256
                requestRelativePath = 'requests/installer-signing.v2/installer-signing-request.v2.json'
                requestSha256 = [string]$requestInput.Sha256
                requestNonce = [string]$request.requestNonce
                baseHeadSha256 = [string]$request.baseHeadSha256
                admissionHeadSha256 = $ExpectedHeadSha256
                admissionRevision = 6
                r6ReceiptRelativePath = 'receipts/0006-installer-signing-requested.json'
                r6ReceiptSha256 = [string]$r6Input.Sha256
                requestCreatedAtUtc = [string]$request.createdAtUtc
                requestExpiresAtUtc = [string]$request.expiresAtUtc
                completedAtUtc = ProductionReleaseState\ConvertTo-ProductionUtc $completed
                candidateSetSha256 = [string]$request.candidate.inventorySha256
                payloadSetSha256 = [string]$request.installerPayload.inventorySha256
                r3SignedClientSetSha256 = [string]$request.r3Evidence.signedClientSetSha256
                releaseManifestTrustSha256 = [string]$request.r3Evidence.releaseManifestTrustSha256
                releaseManifestTrustProbeSetSha256 = [string]$request.r3Evidence.releaseManifestTrustProbeSetSha256
                toolchainLockSha256 = [string]$request.toolchainLockSha256
                targetBuildIdentitySha256 = [string]$request.buildExecution.targetBuildIdentitySha256
                unsignedInstaller = $request.unsignedInstaller
                signedInstaller = $signedInstaller
                authenticode = $authenticodeResponse
                payloadSelfCheck = $payloadSelfCheck
                authentication = [ordered]@{
                    algorithm = 'ES256'; keyId = [string]$trust.keyId
                    purpose = $purpose; payloadType = $payloadType; value = ''
                }
            }
            [byte[]]$authenticationPayload =
                InstallerSigningContracts\Get-InstallerSigningResponseAuthenticationPayload `
                    -Response ([pscustomobject]$response)
        }
        $rawSignature = $signer.SignData(
            $authenticationPayload,
            [Security.Cryptography.HashAlgorithmName]::SHA256,
            [Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)
        $signature = ConvertTo-ProductionInstallerLowS $rawSignature
        if (-not $signer.VerifyData(
                $authenticationPayload, $signature,
                [Security.Cryptography.HashAlgorithmName]::SHA256,
                [Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)) {
            throw 'Installer-signing response signature self-check failed.'
        }
        $response.authentication.value =
            ConvertTo-ProductionInstallerBase64Url $signature
        [byte[]]$responseBytes =
            ProductionReleaseState\ConvertTo-ProductionJsonBytes $response
        $parsed = ProductionReleaseState\ConvertFrom-StrictProductionJsonBytes `
            -Bytes $responseBytes -Label 'Generated Installer-signing response' `
            -SchemaPath $responseSchemaPath
        $responseInput = [pscustomobject]@{
            Value = $parsed; Bytes = $responseBytes
            Sha256 = ProductionReleaseState\Get-ProductionSha256Bytes $responseBytes
        }
        [void](ProductionReleaseState\Assert-CanonicalProductionJsonInput `
            -Input $responseInput -Label 'Generated Installer-signing response')
        if ($edition -ceq 'Personal') {
            [void](PersonalInstallerSigningPipeline\Assert-PersonalInstallerSigningResponseV2Contract `
                -RequestInput $requestInput -ResponseInput $responseInput `
                -R6HeadSha256 $ExpectedHeadSha256 `
                -R6ReceiptSha256 ([string]$r6Input.Sha256) `
                -InstallerSigningTrust $trust -EnforceCurrentLifetime)
        }
        else {
            [void](InstallerSigningContracts\Assert-InstallerSigningResponseContract `
                -RequestInput $requestInput -ResponseInput $responseInput `
                -R6HeadSha256 $ExpectedHeadSha256 `
                -R6ReceiptSha256 ([string]$r6Input.Sha256) `
                -InstallerSigningTrust $trust -EnforceCurrentLifetime)
            if ([string]$payloadSelfCheck.resultSha256 -cne
                (EnterpriseInstallerProductionPayloadSelfCheck\Get-EnterpriseInstallerProductionPayloadSelfCheckResultSha256 `
                    -SelfCheck $payloadSelfCheck)) {
                throw 'Enterprise Installer payload self-check result digest is invalid.'
            }
        }
        $verified = InstallerSigningContracts\Assert-SignedInstallerAuthenticode `
            -Path $signedInput.Path -Response $parsed `
            -ExpectedSignerCertificateSha256 `
                ([string]$plan.authenticodePolicy.signerSha256Thumbprint)
        if ([string]$verified.SignedInstallerSha256 -cne
                [string]$signedInput.Sha256 -or
            [string]$payloadSelfCheck.inspectedInstallerSha256 -cne
                [string]$signedInput.Sha256) {
            throw 'Generated Installer response failed exact Authenticode or payload self-check identity verification.'
        }

        $stagePath = $outputRoot + '.pending-' + [Guid]::NewGuid().ToString('N')
        [IO.Directory]::CreateDirectory($stagePath) | Out-Null
        $stageOwned = $true
        $stageOwnerLease = ProductionReleaseState\Open-ProductionReleaseDirectoryLease `
            -Path $stagePath -Label 'Owned Installer response staging directory'
        [IO.Directory]::CreateDirectory((Join-Path $stagePath 'signed')) | Out-Null
        Write-ProductionInstallerCreateNewBytes `
            -Path (Join-Path $stagePath $responseFileName) `
            -Bytes $responseBytes
        Copy-ProductionInstallerLockedInput `
            -Descriptor $signedInput `
            -DestinationPath (Join-Path (Join-Path $stagePath 'signed') $installerFileName)
        $rootOutputInventory = [ordered]@{
            $responseFileName = $false; 'signed' = $true
        }
        $signedOutputInventory = [ordered]@{$installerFileName = $false}
        Assert-ProductionInstallerExactInventory $stagePath $rootOutputInventory `
            'Staged Installer-signing response bundle'
        Assert-ProductionInstallerExactInventory (Join-Path $stagePath 'signed') `
            $signedOutputInventory 'Staged signed Installer payload'
        $stagedResponse = Open-ProductionInstallerLockedJson `
            -Path (Join-Path $stagePath $responseFileName) `
            -Label 'Staged Installer-signing response' `
            -SchemaPath $responseSchemaPath
        try {
            if ([string]$stagedResponse.Sha256 -cne [string]$responseInput.Sha256) {
                throw 'Staged Installer-signing response differs from generated bytes.'
            }
            $stageContractInput = [pscustomobject]@{
                Value = $stagedResponse.Value; Bytes = $stagedResponse.Bytes
                Sha256 = [string]$stagedResponse.Sha256
            }
            if ($edition -ceq 'Personal') {
                [void](PersonalInstallerSigningPipeline\Assert-PersonalInstallerSigningResponseV2Contract `
                    -RequestInput $requestInput -ResponseInput $stageContractInput `
                    -R6HeadSha256 $ExpectedHeadSha256 `
                    -R6ReceiptSha256 ([string]$r6Input.Sha256) `
                    -InstallerSigningTrust $trust -EnforceCurrentLifetime)
            }
            else {
                [void](InstallerSigningContracts\Assert-InstallerSigningResponseContract `
                    -RequestInput $requestInput -ResponseInput $stageContractInput `
                    -R6HeadSha256 $ExpectedHeadSha256 `
                    -R6ReceiptSha256 ([string]$r6Input.Sha256) `
                    -InstallerSigningTrust $trust -EnforceCurrentLifetime)
            }
        }
        finally { $stagedResponse.Stream.Dispose() }
        $stagedInstaller = ProductionReleaseState\Open-ProductionReleaseInput `
            -Path (Join-Path (Join-Path $stagePath 'signed') $installerFileName) `
            -Label 'Staged signed Installer' -MaximumBytes 1GB
        try {
            if ([int64]$stagedInstaller.SizeBytes -ne [int64]$signedInput.SizeBytes -or
                [string]$stagedInstaller.Sha256 -cne [string]$signedInput.Sha256) {
                throw 'Staged signed Installer differs from its verified source bytes.'
            }
        }
        finally { $stagedInstaller.Stream.Dispose() }

        foreach ($input in @($planInput, $requestInput, $r5Input, $r6Input, $keyInput, $signedInput)) {
            [void](ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
                -Descriptor $input -Label 'Installer response issuer input')
        }
        foreach ($input in $bundleInputs) {
            [void](ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
                -Descriptor $input -Label 'Committed Installer request input')
        }
        foreach ($directory in $bundleDirectories) {
            [void](ProductionReleaseState\Assert-ProductionReleaseDirectoryStillLocked `
                -Descriptor $directory -Label 'Committed Installer request directory')
        }
        [void](ProductionReleaseState\Assert-ProductionReleaseDirectoryStillLocked `
            -Descriptor $outputParentLease -Label 'Installer response output parent')
        $current = ProductionReleaseState\Get-ProductionReleaseState `
            -StateRoot $stateRoot -StateSchemaPath $stateSchemaPath
        if ([string]$current.HeadSha256 -cne $ExpectedHeadSha256 -or
            [int]$current.Head.revision -ne 6 -or
            [string]$current.Head.phase -cne 'INSTALLER_SIGNING_REQUESTED' -or
            $null -ne $current.OrphanReceipt) {
            throw 'Production state changed before Installer response publication.'
        }
        if ([DateTimeOffset]::UtcNow -gt $expires) {
            throw 'Installer-signing request expired before response publication.'
        }
        if (Test-Path -LiteralPath $outputRoot) {
            throw 'Installer-signing response output appeared before atomic publication.'
        }
        $stageMoveLease = ProductionReleaseState\Open-ProductionReleaseDirectoryMoveLease `
            -Path $stagePath -Label 'Owned Installer response staging directory'
        [void](ProductionReleaseState\Assert-ProductionReleaseDirectoryStillLocked `
            -Descriptor $stageOwnerLease -Label 'Owned Installer response staging directory')
        $parentVolume = $outputParentLease.VolumeSerialNumber
        $parentIndex = $outputParentLease.FileIndex
        $outputParentLease.Handle.Dispose()
        $outputParentLease = $null
        [void](ProductionReleaseState\Move-ProductionReleaseDirectoryLease `
            -Descriptor $stageMoveLease -DestinationPath $outputRoot `
            -Label 'Owned Installer response staging directory')
        $committed = $true
        $stageOwned = $false
        $stagePath = $null
        $outputParentLease = ProductionReleaseState\Open-ProductionReleaseDirectoryLease `
            -Path $outputParent -Label 'Installer response output parent'
        if ($outputParentLease.VolumeSerialNumber -ne $parentVolume -or
            $outputParentLease.FileIndex -ne $parentIndex) {
            throw 'Installer response output parent identity changed during atomic publication.'
        }
        Assert-ProductionInstallerExactInventory $outputRoot $rootOutputInventory `
            'Committed Installer-signing response bundle'
        Assert-ProductionInstallerExactInventory (Join-Path $outputRoot 'signed') `
            $signedOutputInventory 'Committed signed Installer payload'

        return [pscustomobject][ordered]@{
            OutputRoot = $outputRoot
            ResponseSha256 = [string]$responseInput.Sha256
            RequestSha256 = [string]$requestInput.Sha256
            AdmissionHeadSha256 = $ExpectedHeadSha256
            Edition = $edition
            VerifiedInstallerCount = 1
            ProductionAdmission = 'OFFLINE_RESPONSE_ONLY'
            AuthenticodeSigningPerformed = $false
            NetworkPublicationPerformed = $false
            ReleaseStateChanged = $false
        }
    }
    finally {
        if ($null -ne $keyBytes) { [Array]::Clear($keyBytes, 0, $keyBytes.Length) }
        if ($null -ne $signer) { $signer.Dispose() }
        if ($null -ne $stageMoveLease) { $stageMoveLease.Handle.Dispose() }
        foreach ($input in @($signedInput, $keyInput, $r6Input, $r5Input, $requestInput, $planInput)) {
            if ($null -ne $input) { $input.Stream.Dispose() }
        }
        for ($index = $bundleInputs.Count - 1; $index -ge 0; $index--) {
            $bundleInputs[$index].Stream.Dispose()
        }
        for ($index = $bundleDirectories.Count - 1; $index -ge 0; $index--) {
            $bundleDirectories[$index].Handle.Dispose()
        }
        if ($null -ne $outputParentLease) { $outputParentLease.Handle.Dispose() }
        if ($null -ne $stateLock) { $stateLock.Stream.Dispose() }
        if ($stageOwned -and -not $committed -and $null -ne $stagePath -and
            $null -ne $stageOwnerLease -and (Test-Path -LiteralPath $stagePath)) {
            try {
                Remove-ProductionInstallerOwnedStage `
                    -StagePath $stagePath -OutputPath $outputRoot `
                    -ResponseFileName $responseFileName `
                    -InstallerFileName $installerFileName `
                    -OwnerLease $stageOwnerLease
                $stageOwnerLease = $null
            }
            finally {
                if ($null -ne $stageOwnerLease) {
                    $stageOwnerLease.Handle.Dispose()
                    $stageOwnerLease = $null
                }
            }
        }
        elseif ($null -ne $stageOwnerLease) {
            $stageOwnerLease.Handle.Dispose()
        }
    }
}

Invoke-ProductionInstallerSigningResponse @PSBoundParameters
