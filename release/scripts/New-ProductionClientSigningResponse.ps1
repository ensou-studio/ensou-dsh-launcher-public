#requires -Version 7.2

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$StateRoot,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$ExpectedHeadSha256,
    [Parameter(Mandatory = $true)][string]$SignedClientRoot,
    [Parameter(Mandatory = $true)][string]$ResponsePrivateKeyPath,
    [Parameter(Mandatory = $true)][string]$OutputRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$schemaRoot = Join-Path $repositoryRoot 'release\schemas'
$planSchemaPath = Join-Path $schemaRoot 'launcher-production-release-plan-v2.schema.json'
$stateSchemaPath = Join-Path $schemaRoot 'launcher-production-release-state-v2.schema.json'
$requestSchemaPath = Join-Path $schemaRoot 'launcher-external-signing-request-v1.schema.json'
$responseSchemaPath = Join-Path $schemaRoot 'launcher-external-signing-response-v1.schema.json'

Microsoft.PowerShell.Core\Import-Module `
    (Join-Path $PSScriptRoot 'InstallerSigningContracts.psm1') -Force
# InstallerSigningContracts imports the shared state module into its private
# scope. Import state last so both module-qualified contracts remain stable in
# this issuer scope.
Microsoft.PowerShell.Core\Import-Module `
    (Join-Path $PSScriptRoot 'ProductionReleaseState.psm1') -Force

$p256Order = [Convert]::FromHexString(
    'FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551')
$p256HalfOrder = [Convert]::FromHexString(
    '7FFFFFFF800000007FFFFFFFFFFFFFFFDE737D56D38BCF4279DCE5617E3192A8')

function ConvertTo-ProductionClientBase64Url {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    return [Convert]::ToBase64String($Bytes).
        TrimEnd('=').
        Replace('+', '-').
        Replace('/', '_')
}

function Compare-ProductionClientUnsignedBigEndian {
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

function Subtract-ProductionClientUnsignedBigEndian {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Left,
        [Parameter(Mandatory = $true)][byte[]]$Right
    )

    if ($Left.Length -ne $Right.Length -or
        (Compare-ProductionClientUnsignedBigEndian `
            -Left $Left -Right $Right) -lt 0) {
        throw 'Unsigned subtraction requires equal-length ordered values.'
    }
    $result = [byte[]]::new($Left.Length)
    $borrow = 0
    for ($index = $Left.Length - 1; $index -ge 0; $index--) {
        $value = [int]$Left[$index] - [int]$Right[$index] - $borrow
        if ($value -lt 0) {
            $value += 256
            $borrow = 1
        }
        else {
            $borrow = 0
        }
        $result[$index] = [byte]$value
    }
    if ($borrow -ne 0) {
        throw 'Unsigned subtraction underflowed.'
    }
    return ,$result
}

function ConvertTo-ProductionClientLowS {
    param([Parameter(Mandatory = $true)][byte[]]$Signature)

    if ($Signature.Length -ne 64) {
        throw 'Client-signing response must use a 64-byte P1363 signature.'
    }
    $r = [byte[]]::new(32)
    $s = [byte[]]::new(32)
    [Array]::Copy($Signature, 0, $r, 0, 32)
    [Array]::Copy($Signature, 32, $s, 0, 32)
    $zero = [byte[]]::new(32)
    if ((Compare-ProductionClientUnsignedBigEndian -Left $r -Right $zero) -eq 0 -or
        (Compare-ProductionClientUnsignedBigEndian -Left $r -Right $p256Order) -ge 0 -or
        (Compare-ProductionClientUnsignedBigEndian -Left $s -Right $zero) -eq 0 -or
        (Compare-ProductionClientUnsignedBigEndian -Left $s -Right $p256Order) -ge 0) {
        throw 'Client-signing response signature contains an invalid scalar.'
    }
    if ((Compare-ProductionClientUnsignedBigEndian `
            -Left $s -Right $p256HalfOrder) -gt 0) {
        $s = Subtract-ProductionClientUnsignedBigEndian `
            -Left $p256Order -Right $s
    }
    $normalized = [byte[]]::new(64)
    [Array]::Copy($r, 0, $normalized, 0, 32)
    [Array]::Copy($s, 0, $normalized, 32, 32)
    ProductionReleaseState\Assert-ProductionEs256P1363LowS `
        -Signature $normalized `
        -Label 'Client-signing response signature'
    return ,$normalized
}

function Resolve-ProductionClientExternalPath {
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

function Test-ProductionClientSameOrDescendantPath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Root
    )

    $fullPath = [IO.Path]::GetFullPath($Path).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    $fullRoot = [IO.Path]::GetFullPath($Root).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    return $fullPath.Equals($fullRoot, [StringComparison]::OrdinalIgnoreCase) -or
        $fullPath.StartsWith(
            $fullRoot + [IO.Path]::DirectorySeparatorChar,
            [StringComparison]::OrdinalIgnoreCase)
}

function Test-ProductionClientPathsOverlap {
    param(
        [Parameter(Mandatory = $true)][string]$Left,
        [Parameter(Mandatory = $true)][string]$Right
    )

    return (Test-ProductionClientSameOrDescendantPath -Path $Left -Root $Right) -or
        (Test-ProductionClientSameOrDescendantPath -Path $Right -Root $Left)
}

function Open-ProductionClientLockedJson {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][string]$SchemaPath
    )

    $input = ProductionReleaseState\Open-ProductionReleaseInput `
        -Path $Path -Label $Label -MaximumBytes 16MB
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

function Assert-ProductionClientExactDirectoryInventory {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][Collections.IDictionary]$Expected,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $entries = @(Microsoft.PowerShell.Management\Get-ChildItem `
        -LiteralPath $Path -Force)
    if ($entries.Count -ne $Expected.Count) {
        throw "$Label does not contain its exact expected inventory."
    }
    foreach ($entry in $entries) {
        $property = @($Expected.Keys | Where-Object {
                [string]$_ -ceq [string]$entry.Name
            })
        if ($property.Count -ne 1 -or
            ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            [bool]$entry.PSIsContainer -ne [bool]$Expected[$property[0]]) {
            throw "$Label contains an unexpected, linked, or mistyped entry."
        }
    }
}

function Assert-ProductionClientTrustSeparation {
    param([Parameter(Mandatory = $true)][psobject]$Plan)

    $domains = @(
        $Plan.releaseManifestTrust,
        $Plan.externalResponseTrusts.clientSigning,
        $Plan.externalResponseTrusts.manifestPublishing,
        $Plan.externalResponseTrusts.installerSigning,
        $Plan.externalResponseTrusts.feedPromotion)
    $keyIds = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
    $points = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
    foreach ($domain in $domains) {
        if (-not $keyIds.Add([string]$domain.keyId)) {
            throw 'Plan v2 trust domains must retain five distinct key IDs.'
        }
        $point = ProductionReleaseState\Get-ProductionReleaseP256PublicKeyIdentity `
            -Trust $domain `
            -Label ("Plan v2 trust domain '" + [string]$domain.purpose + "'")
        if (-not $points.Add($point)) {
            throw 'Plan v2 trust domains must retain five distinct P-256 public keys.'
        }
    }
    $trust = $Plan.externalResponseTrusts.clientSigning
    if ([string]$trust.algorithm -cne 'ES256' -or
        [string]$trust.purpose -cne 'client-signing-response') {
        throw 'Plan client-signing response trust domain is not purpose-fixed.'
    }
}

function Copy-ProductionClientLockedInput {
    param(
        [Parameter(Mandatory = $true)]$Descriptor,
        [Parameter(Mandatory = $true)][string]$DestinationPath,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $output = [IO.File]::Open(
        $DestinationPath,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None)
    try {
        [void][EnsouLauncherProduction.NativeFileIdentity]::
            RequireOrdinarySingleLink($output.SafeFileHandle)
        $Descriptor.Stream.Position = 0
        $Descriptor.Stream.CopyTo($output)
        $output.Flush($true)
        if ($output.Length -ne [int64]$Descriptor.SizeBytes) {
            throw "$Label copy did not preserve its exact byte length."
        }
    }
    finally {
        $output.Dispose()
        $Descriptor.Stream.Position = 0
    }
}

function Remove-ProductionClientOwnedStage {
    param(
        [Parameter(Mandatory = $true)][string]$StagePath,
        [Parameter(Mandatory = $true)][string]$OutputPath,
        [Parameter(Mandatory = $true)][string[]]$ExpectedFileNames,
        [Parameter(Mandatory = $true)]$OwnerLease
    )

    if (-not (Test-Path -LiteralPath $StagePath)) { return }
    $stage = [IO.Path]::GetFullPath($StagePath)
    $output = [IO.Path]::GetFullPath($OutputPath)
    $parent = [IO.Path]::GetDirectoryName($output)
    $leaf = [IO.Path]::GetFileName($output)
    $expectedPrefix = $leaf + '.pending-'
    if ([IO.Path]::GetDirectoryName($stage) -cne $parent -or
        -not [IO.Path]::GetFileName($stage).StartsWith(
            $expectedPrefix, [StringComparison]::Ordinal) -or
        [IO.Path]::GetFileName($stage).Length -ne $expectedPrefix.Length + 32) {
        throw 'Refusing to clean a staging path not owned by this response issuer.'
    }
    $stageItem = Get-Item -LiteralPath $stage -Force -ErrorAction Stop
    if (-not $stageItem.PSIsContainer -or
        ($stageItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Refusing to clean a replaced or linked response staging root.'
    }
    for ($ancestor = $stageItem.Parent;
        $null -ne $ancestor -and
        -not $ancestor.FullName.Equals(
            $parent, [StringComparison]::OrdinalIgnoreCase);
        $ancestor = $ancestor.Parent) {
        if (($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Refusing to clean a response staging path crossing a filesystem link.'
        }
    }
    [void](ProductionReleaseState\Assert-ProductionReleaseDirectoryStillLocked `
        -Descriptor $OwnerLease `
        -Label 'Owned client-signing response staging directory')
    $allowed = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    [void]$allowed.Add('signed')
    [void]$allowed.Add('signing-response.v1.json')
    foreach ($name in $ExpectedFileNames) {
        [void]$allowed.Add('signed\' + $name)
    }
    foreach ($entry in @(Get-ChildItem -LiteralPath $stage -Force -Recurse)) {
        $relative = [IO.Path]::GetRelativePath($stage, $entry.FullName)
        if (-not $allowed.Contains($relative) -or
            ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Refusing to clean a changed or linked response staging tree.'
        }
    }
    # Keep the identity-bearing lease through the final inventory check. The
    # handle itself must be released for the owned directory deletion.
    $OwnerLease.Handle.Dispose()
    [IO.Directory]::Delete($stage, $true)
}

function Invoke-ProductionClientSigningResponse {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$StateRoot,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9a-f]{64}$')]
        [string]$ExpectedHeadSha256,
        [Parameter(Mandatory = $true)][string]$SignedClientRoot,
        [Parameter(Mandatory = $true)][string]$ResponsePrivateKeyPath,
        [Parameter(Mandatory = $true)][string]$OutputRoot
    )

    $stateLock = $null
    $signedRootLease = $null
    $outputParentLease = $null
    $stageOwnerLease = $null
    $stageMoveLease = $null
    $planInput = $null
    $requestInput = $null
    $keyInput = $null
    $unsignedInputs = [Collections.Generic.List[object]]::new()
    $signedInputs = [Collections.Generic.List[object]]::new()
    $keyBytes = $null
    $signer = $null
    $stagePath = $null
    $stageOwned = $false
    $committed = $false
    $expectedFileNames = @()

    try {
        $stateRoot = Resolve-ProductionClientExternalPath `
            -Path $StateRoot -Label 'Production state root'
        $signedRoot = Resolve-ProductionClientExternalPath `
            -Path $SignedClientRoot -Label 'Externally signed client root'
        $keyPath = Resolve-ProductionClientExternalPath `
            -Path $ResponsePrivateKeyPath `
            -Label 'Client-signing response-attestation private key'
        $outputRoot = Resolve-ProductionClientExternalPath `
            -Path $OutputRoot -Label 'Client-signing response output'

        if (-not (Test-Path -LiteralPath $stateRoot -PathType Container) -or
            -not (Test-Path -LiteralPath $signedRoot -PathType Container)) {
            throw 'Production state root and externally signed client root must exist.'
        }
        if (Test-Path -LiteralPath $outputRoot) {
            throw 'Client-signing response output is create-only and already exists.'
        }
        if ((Test-ProductionClientPathsOverlap -Left $stateRoot -Right $signedRoot) -or
            (Test-ProductionClientPathsOverlap -Left $outputRoot -Right $stateRoot) -or
            (Test-ProductionClientPathsOverlap -Left $outputRoot -Right $signedRoot) -or
            (Test-ProductionClientSameOrDescendantPath -Path $keyPath -Root $stateRoot) -or
            (Test-ProductionClientSameOrDescendantPath -Path $keyPath -Root $signedRoot) -or
            (Test-ProductionClientSameOrDescendantPath -Path $keyPath -Root $outputRoot)) {
            throw 'State, signed-client, response-key, and output paths must not overlap.'
        }
        $outputParent = [IO.Path]::GetDirectoryName($outputRoot)
        if ([string]::IsNullOrWhiteSpace($outputParent)) {
            throw 'Client-signing response output must have an existing parent directory.'
        }

        $signedRootLease = ProductionReleaseState\Open-ProductionReleaseDirectoryLease `
            -Path $signedRoot -Label 'Externally signed client root'
        $outputParentLease = ProductionReleaseState\Open-ProductionReleaseDirectoryLease `
            -Path $outputParent -Label 'Client-signing response output parent'
        $stateLock = ProductionReleaseState\Enter-ProductionReleaseStateReadLock `
            -StateRoot $stateRoot
        $state = ProductionReleaseState\Get-ProductionReleaseState `
            -StateRoot $stateRoot -StateSchemaPath $stateSchemaPath
        if ([int]$state.SchemaVersion -ne 2 -or
            [string]$state.Identity.edition -notin @('Personal', 'Enterprise') -or
            $null -eq $state.Head -or
            [int]$state.Head.revision -ne 2 -or
            [string]$state.Head.phase -cne 'CLIENT_SIGNING_REQUESTED' -or
            [string]$state.HeadSha256 -cne $ExpectedHeadSha256 -or
            $null -ne $state.OrphanReceipt -or
            @($state.Receipts).Count -ne 2) {
            throw 'NO-GO: issuer requires the exact committed v2 CLIENT_SIGNING_REQUESTED r2 head without an orphan transition.'
        }

        $planInput = Open-ProductionClientLockedJson `
            -Path (Join-Path $stateRoot 'plan.json') `
            -Label 'Committed production plan snapshot' `
            -SchemaPath $planSchemaPath
        $plan = $planInput.Value
        if ([string]$planInput.Sha256 -cne [string]$state.Identity.planSha256 -or
            [string]$plan.orchestrationId -cne [string]$state.Identity.orchestrationId -or
            [string]$plan.edition -cne [string]$state.Identity.edition -or
            [string]$plan.targetChannel -cne [string]$state.TargetChannel) {
            throw 'Committed production plan differs from the current state identity.'
        }
        Assert-ProductionClientTrustSeparation -Plan $plan

        $requestRoot = Join-Path $stateRoot 'requests\client-signing.v1'
        $unsignedRoot = Join-Path $requestRoot 'unsigned'
        $requestInput = Open-ProductionClientLockedJson `
            -Path (Join-Path $requestRoot 'signing-request.v1.json') `
            -Label 'Committed client-signing r2 request' `
            -SchemaPath $requestSchemaPath
        $request = $requestInput.Value
        $r2 = $state.Receipts[1]
        $trust = $plan.externalResponseTrusts.clientSigning
        if ([int]$r2.revision -ne 2 -or
            [string]$r2.phase -cne 'CLIENT_SIGNING_REQUESTED' -or
            [string]$r2.data.requestRelativePath -cne
                'requests/client-signing.v1/signing-request.v1.json' -or
            [string]$r2.data.requestSha256 -cne [string]$requestInput.Sha256 -or
            [string]$r2.data.nonce -cne [string]$request.nonce -or
            [string]$r2.data.createdAtUtc -cne [string]$request.createdAtUtc -or
            [string]$r2.data.expiresAtUtc -cne [string]$request.expiresAtUtc -or
            [string]$request.orchestrationId -cne [string]$plan.orchestrationId -or
            [string]$request.edition -cne [string]$plan.edition -or
            [string]$request.releaseSetId -cne [string]$plan.releaseSetId -or
            [string]$request.planSha256 -cne [string]$planInput.Sha256 -or
            [string]$request.responseAuthentication.algorithm -cne 'ES256' -or
            [string]$request.responseAuthentication.keyId -cne [string]$trust.keyId -or
            [string]$request.responseAuthentication.purpose -cne
                'client-signing-response' -or
            [string]$request.responseAuthentication.payloadType -cne
                'ensou-dsh-launcher-external-signing-response-authentication-v2' -or
            [string]$request.authenticode.signerSha256Thumbprint -cne
                [string]$plan.authenticodePolicy.signerSha256Thumbprint -or
            $request.authenticode.requireTrustedTimestamp -ne $true -or
            $plan.authenticodePolicy.requireTrustedTimestamp -ne $true) {
            throw 'Committed client-signing request is not bound to its exact r2 receipt, plan, and purpose-specific trust.'
        }

        $created = ProductionReleaseState\ConvertFrom-ProductionUtc `
            -Value ([string]$request.createdAtUtc) `
            -Label 'Client-signing request creation time'
        $expires = ProductionReleaseState\ConvertFrom-ProductionUtc `
            -Value ([string]$request.expiresAtUtc) `
            -Label 'Client-signing request expiry time'
        $now = [DateTimeOffset]::UtcNow
        if ($expires -le $created -or
            ($expires - $created) -ne [TimeSpan]::FromMinutes(
                [int]$plan.authenticodePolicy.maximumResponseAgeMinutes) -or
            $now -lt $created -or
            $now -gt $expires) {
            throw 'Client-signing request lifetime is not exact or currently valid.'
        }

        $expectedRoles = if ([string]$plan.edition -ceq 'Personal') {
            @('startup-stub', 'client-bootstrapper', 'launcher', 'maintenance')
        }
        else {
            @('bootstrapper', 'launcher', 'client-bootstrapper', 'maintenance')
        }
        $expectedNames = if ([string]$plan.edition -ceq 'Personal') {
            @(
                'Ensou.Dsh.Bootstrapper.exe',
                'Ensou.Dsh.ClientBootstrapper.exe',
                'Ensou.Dsh.Launcher.exe',
                'Ensou.Dsh.Personal.Maintenance.exe')
        }
        else {
            @(
                'Ensou.Dsh.Enterprise.Bootstrapper.exe',
                'Ensou.Dsh.Enterprise.Launcher.exe',
                'Ensou.Dsh.Enterprise.ClientBootstrapper.exe',
                'Ensou.Dsh.Enterprise.Maintenance.exe')
        }
        $plannedFiles = @($plan.clientSigningInputs)
        $requestFiles = @($request.files)
        $receiptFiles = @($r2.data.files)
        if ($plannedFiles.Count -ne 4 -or
            $requestFiles.Count -ne 4 -or
            $receiptFiles.Count -ne 4) {
            throw 'Client-signing request must contain exactly four canonical client roles.'
        }

        $requestInventory = [ordered]@{
            'signing-request.v1.json' = $false
            'unsigned' = $true
        }
        Assert-ProductionClientExactDirectoryInventory `
            -Path $requestRoot -Expected $requestInventory `
            -Label 'Committed client-signing request bundle'
        $unsignedInventory = [ordered]@{}
        $signedInventory = [ordered]@{}
        $targets = [Collections.Generic.List[object]]::new()
        for ($index = 0; $index -lt 4; $index++) {
            $planned = $plannedFiles[$index]
            $requested = $requestFiles[$index]
            $received = $receiptFiles[$index]
            if ([string]$planned.role -cne $expectedRoles[$index] -or
                [string]$requested.role -cne $expectedRoles[$index] -or
                [string]$received.role -cne $expectedRoles[$index] -or
                [string]$planned.fileName -cne $expectedNames[$index] -or
                [string]$requested.fileName -cne [string]$planned.fileName -or
                [string]$received.fileName -cne [string]$planned.fileName -or
                [string]$requested.relativePath -cne
                    ('unsigned/' + [string]$planned.fileName) -or
                [int64]$requested.sizeBytes -ne [int64]$planned.sizeBytes -or
                [string]$requested.sha256 -cne [string]$planned.sha256 -or
                [string]$received.sha256 -cne [string]$planned.sha256 -or
                [string]$requested.peContentSha256 -cne
                    [string]$planned.peContentSha256 -or
                [string]$received.peContentSha256 -cne
                    [string]$planned.peContentSha256) {
                throw "Client-signing role index $index differs across the plan, request, and r2 receipt."
            }
            $unsignedInventory[[string]$planned.fileName] = $false
            $signedInventory[[string]$planned.fileName] = $false
            $targets.Add([pscustomobject][ordered]@{
                Role = [string]$planned.role
                FileName = [string]$planned.fileName
                InputSizeBytes = [int64]$planned.sizeBytes
                InputSha256 = [string]$planned.sha256
                PeContentSha256 = [string]$planned.peContentSha256
            })
        }
        $expectedFileNames = @($targets | ForEach-Object FileName)
        Assert-ProductionClientExactDirectoryInventory `
            -Path $unsignedRoot -Expected $unsignedInventory `
            -Label 'Committed unsigned client payload'
        Assert-ProductionClientExactDirectoryInventory `
            -Path $signedRoot -Expected $signedInventory `
            -Label 'Externally signed client payload'

        $evidence = [Collections.Generic.List[object]]::new()
        for ($index = 0; $index -lt 4; $index++) {
            $target = $targets[$index]
            $unsignedInput = ProductionReleaseState\Open-ProductionReleaseInput `
                -Path (Join-Path $unsignedRoot ([string]$target.FileName)) `
                -Label "Committed unsigned client role $($target.Role)" `
                -MaximumBytes 512MB
            $unsignedInputs.Add($unsignedInput)
            [byte[]]$unsignedBytes =
                ProductionReleaseState\Read-ProductionReleaseInputBytes `
                    -Descriptor $unsignedInput `
                    -Label "Committed unsigned client role $($target.Role)"
            if ([int64]$unsignedInput.SizeBytes -ne [int64]$target.InputSizeBytes -or
                [string]$unsignedInput.Sha256 -cne [string]$target.InputSha256 -or
                (ProductionReleaseState\Get-PeContentSha256 `
                    -Bytes $unsignedBytes) -cne [string]$target.PeContentSha256) {
                throw "Committed unsigned client role '$($target.Role)' differs from its r2 request identity."
            }

            $signedInput = ProductionReleaseState\Open-ProductionReleaseInput `
                -Path (Join-Path $signedRoot ([string]$target.FileName)) `
                -Label "Externally signed client role $($target.Role)" `
                -MaximumBytes 512MB
            $signedInputs.Add($signedInput)
            $signedEvidence =
                InstallerSigningContracts\Get-ExactPeAuthenticodeEvidence `
                    -Path $signedInput.Path `
                    -ExpectedSignerCertificateSha256 `
                        ([string]$plan.authenticodePolicy.signerSha256Thumbprint) `
                    -ExpectedPeContentSha256 ([string]$target.PeContentSha256)
            [void](ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
                -Descriptor $signedInput `
                -Label "Externally signed client role $($target.Role)")
            if ([string]$signedEvidence.AuthenticodeStatus -cne 'Valid' -or
                [string]$signedEvidence.TimestampProtocol -cne 'RFC3161' -or
                [int]$signedEvidence.PrimarySignerCount -ne 1 -or
                [bool]$signedEvidence.LegacyCounterSignaturePresent -or
                [int64]$signedEvidence.SizeBytes -ne [int64]$signedInput.SizeBytes -or
                [string]$signedEvidence.SignedFileSha256 -cne
                    [string]$signedInput.Sha256 -or
                [string]$signedEvidence.PeContentSha256 -cne
                    [string]$target.PeContentSha256 -or
                [int64]$signedInput.SizeBytes -le [int64]$target.InputSizeBytes -or
                [string]$signedInput.Sha256 -ceq [string]$target.InputSha256) {
                throw "Externally signed client role '$($target.Role)' is not an exact size-grown Authenticode and RFC3161 transformation of the requested PE."
            }
            $evidence.Add($signedEvidence)
        }

        $keyInput = ProductionReleaseState\Open-ProductionReleaseInput `
            -Path $keyPath `
            -Label 'Client-signing response-attestation private key' `
            -MaximumBytes 64KB
        [byte[]]$keyBytes =
            ProductionReleaseState\Read-ProductionReleaseInputBytes `
                -Descriptor $keyInput `
                -Label 'Client-signing response-attestation private key'
        $signer = [Security.Cryptography.ECDsa]::Create()
        $consumed = 0
        try {
            $signer.ImportPkcs8PrivateKey($keyBytes, [ref]$consumed)
        }
        catch {
            throw 'Client-signing response-attestation private key is not valid PKCS8.'
        }
        if ($consumed -ne $keyBytes.Length) {
            throw 'Client-signing response-attestation private key has trailing bytes.'
        }
        $public = $signer.ExportParameters($false)
        if ($signer.KeySize -ne 256 -or
            [string]$public.Curve.Oid.Value -cne '1.2.840.10045.3.1.7' -or
            $public.Q.X.Length -ne 32 -or
            $public.Q.Y.Length -ne 32 -or
            (ConvertTo-ProductionClientBase64Url -Bytes $public.Q.X) -cne
                [string]$trust.x -or
            (ConvertTo-ProductionClientBase64Url -Bytes $public.Q.Y) -cne
                [string]$trust.y) {
            throw 'Client-signing response-attestation private key is not the exact P-256 key pinned by plan.externalResponseTrusts.clientSigning.'
        }

        $completed = [DateTimeOffset]::UtcNow
        if ($completed -lt $created -or $completed -gt $expires) {
            throw 'Client-signing response completion is outside the request lifetime.'
        }
        $files = [Collections.Generic.List[object]]::new()
        for ($index = 0; $index -lt 4; $index++) {
            $target = $targets[$index]
            $signedEvidence = $evidence[$index]
            $files.Add([ordered]@{
                role = [string]$target.Role
                fileName = [string]$target.FileName
                relativePath = 'signed/' + [string]$target.FileName
                inputSha256 = [string]$target.InputSha256
                inputPeContentSha256 = [string]$target.PeContentSha256
                sizeBytes = [int64]$signedEvidence.SizeBytes
                sha256 = [string]$signedEvidence.SignedFileSha256
                signedPeContentSha256 = [string]$signedEvidence.PeContentSha256
            })
        }
        $response = [ordered]@{
            schemaVersion = 1
            responseType =
                'ensou-dsh-launcher-client-authenticode-signing-response'
            orchestrationId = [string]$request.orchestrationId
            edition = [string]$request.edition
            releaseSetId = [string]$request.releaseSetId
            planSha256 = [string]$request.planSha256
            requestSha256 = [string]$requestInput.Sha256
            requestNonce = [string]$request.nonce
            completedAtUtc = ProductionReleaseState\ConvertTo-ProductionUtc `
                -Value $completed
            files = $files
            authentication = [ordered]@{
                algorithm = 'ES256'
                keyId = [string]$trust.keyId
                purpose = 'client-signing-response'
                payloadType =
                    'ensou-dsh-launcher-external-signing-response-authentication-v2'
            }
        }
        [byte[]]$payload =
            ProductionReleaseState\Get-ProductionReleaseSigningResponseAuthenticationPayload `
                -Response ([pscustomobject]$response)
        $rawSignature = $signer.SignData(
            $payload,
            [Security.Cryptography.HashAlgorithmName]::SHA256,
            [Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)
        $signature = ConvertTo-ProductionClientLowS -Signature $rawSignature
        if (-not $signer.VerifyData(
                $payload,
                $signature,
                [Security.Cryptography.HashAlgorithmName]::SHA256,
                [Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)) {
            throw 'Client-signing response signature self-check failed.'
        }
        $response.authentication.value =
            ConvertTo-ProductionClientBase64Url -Bytes $signature
        [byte[]]$responseBytes =
            ProductionReleaseState\ConvertTo-ProductionJsonBytes `
                -Value $response
        $parsedResponse =
            ProductionReleaseState\ConvertFrom-StrictProductionJsonBytes `
                -Bytes $responseBytes `
                -Label 'Generated client-signing response' `
                -SchemaPath $responseSchemaPath
        [void](ProductionReleaseState\Assert-CanonicalProductionJsonInput `
            -Input ([pscustomobject]@{
                Value = $parsedResponse
                Bytes = $responseBytes
                Sha256 = ProductionReleaseState\Get-ProductionSha256Bytes `
                    -Bytes $responseBytes
            }) `
            -Label 'Generated client-signing response')
        [void](ProductionReleaseState\Assert-ProductionReleaseSigningResponseAuthentication `
            -Response $parsedResponse -Trust $trust)

        $stagePath = $outputRoot + '.pending-' + [Guid]::NewGuid().ToString('N')
        [IO.Directory]::CreateDirectory($stagePath) | Out-Null
        $stageOwned = $true
        $stageOwnerLease = ProductionReleaseState\Open-ProductionReleaseDirectoryLease `
            -Path $stagePath `
            -Label 'Owned client-signing response staging directory'
        [IO.Directory]::CreateDirectory((Join-Path $stagePath 'signed')) | Out-Null
        $responseOutput = [IO.File]::Open(
            (Join-Path $stagePath 'signing-response.v1.json'),
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None)
        try {
            [void][EnsouLauncherProduction.NativeFileIdentity]::
                RequireOrdinarySingleLink($responseOutput.SafeFileHandle)
            $responseOutput.Write($responseBytes, 0, $responseBytes.Length)
            $responseOutput.Flush($true)
        }
        finally {
            $responseOutput.Dispose()
        }
        for ($index = 0; $index -lt 4; $index++) {
            Copy-ProductionClientLockedInput `
                -Descriptor $signedInputs[$index] `
                -DestinationPath (Join-Path `
                    (Join-Path $stagePath 'signed') `
                    ([string]$targets[$index].FileName)) `
                -Label "Signed client role $($targets[$index].Role)"
        }

        $stageInventory = [ordered]@{
            'signing-response.v1.json' = $false
            'signed' = $true
        }
        Assert-ProductionClientExactDirectoryInventory `
            -Path $stagePath -Expected $stageInventory `
            -Label 'Staged client-signing response bundle'
        Assert-ProductionClientExactDirectoryInventory `
            -Path (Join-Path $stagePath 'signed') -Expected $signedInventory `
            -Label 'Staged signed-client payload'
        $stagedResponse = Open-ProductionClientLockedJson `
            -Path (Join-Path $stagePath 'signing-response.v1.json') `
            -Label 'Staged client-signing response' `
            -SchemaPath $responseSchemaPath
        try {
            if ([string]$stagedResponse.Sha256 -cne
                (ProductionReleaseState\Get-ProductionSha256Bytes `
                    -Bytes $responseBytes)) {
                throw 'Staged client-signing response differs from generated bytes.'
            }
            [void](ProductionReleaseState\Assert-ProductionReleaseSigningResponseAuthentication `
                -Response $stagedResponse.Value -Trust $trust)
        }
        finally {
            $stagedResponse.Stream.Dispose()
        }
        for ($index = 0; $index -lt 4; $index++) {
            $stagedFile = ProductionReleaseState\Open-ProductionReleaseInput `
                -Path (Join-Path `
                    (Join-Path $stagePath 'signed') `
                    ([string]$targets[$index].FileName)) `
                -Label "Staged signed client role $($targets[$index].Role)" `
                -MaximumBytes 512MB
            try {
                [byte[]]$stagedBytes =
                    ProductionReleaseState\Read-ProductionReleaseInputBytes `
                        -Descriptor $stagedFile `
                        -Label "Staged signed client role $($targets[$index].Role)"
                if ([int64]$stagedFile.SizeBytes -ne
                        [int64]$evidence[$index].SizeBytes -or
                    [string]$stagedFile.Sha256 -cne
                        [string]$evidence[$index].SignedFileSha256 -or
                    (ProductionReleaseState\Get-PeContentSha256 `
                        -Bytes $stagedBytes) -cne
                        [string]$targets[$index].PeContentSha256) {
                    throw "Staged signed client role '$($targets[$index].Role)' differs from the verified source bytes."
                }
            }
            finally {
                $stagedFile.Stream.Dispose()
            }
        }

        foreach ($input in @($planInput, $requestInput, $keyInput)) {
            [void](ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
                -Descriptor $input -Label 'Client-signing response issuer input')
        }
        foreach ($input in $unsignedInputs) {
            [void](ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
                -Descriptor $input -Label 'Committed unsigned client input')
        }
        foreach ($input in $signedInputs) {
            [void](ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
                -Descriptor $input -Label 'Externally signed client input')
        }
        [void](ProductionReleaseState\Assert-ProductionReleaseDirectoryStillLocked `
            -Descriptor $signedRootLease `
            -Label 'Externally signed client root')
        [void](ProductionReleaseState\Assert-ProductionReleaseDirectoryStillLocked `
            -Descriptor $outputParentLease `
            -Label 'Client-signing response output parent')
        Assert-ProductionClientExactDirectoryInventory `
            -Path $signedRoot -Expected $signedInventory `
            -Label 'Externally signed client payload before commit'
        $currentState = ProductionReleaseState\Get-ProductionReleaseState `
            -StateRoot $stateRoot -StateSchemaPath $stateSchemaPath
        if ([string]$currentState.HeadSha256 -cne $ExpectedHeadSha256 -or
            [int]$currentState.Head.revision -ne 2 -or
            [string]$currentState.Head.phase -cne 'CLIENT_SIGNING_REQUESTED' -or
            $null -ne $currentState.OrphanReceipt) {
            throw 'Production state changed before client-signing response publication.'
        }
        if ([DateTimeOffset]::UtcNow -gt $expires) {
            throw 'Client-signing request expired before response publication.'
        }
        if (Test-Path -LiteralPath $outputRoot) {
            throw 'Client-signing response output appeared before atomic publication.'
        }

        $stageMoveLease =
            ProductionReleaseState\Open-ProductionReleaseDirectoryMoveLease `
                -Path $stagePath `
                -Label 'Owned client-signing response staging directory'
        [void](ProductionReleaseState\Assert-ProductionReleaseDirectoryStillLocked `
            -Descriptor $stageOwnerLease `
            -Label 'Owned client-signing response staging directory')
        $parentVolume = $outputParentLease.VolumeSerialNumber
        $parentIndex = $outputParentLease.FileIndex
        # The parent read lease intentionally denies a child rename. Release it
        # only for the handle-bound create-only move, then prove the same parent
        # directory identity still owns the path.
        $outputParentLease.Handle.Dispose()
        $outputParentLease = $null
        [void](ProductionReleaseState\Move-ProductionReleaseDirectoryLease `
            -Descriptor $stageMoveLease `
            -DestinationPath $outputRoot `
            -Label 'Owned client-signing response staging directory')
        $committed = $true
        $stageOwned = $false
        $stagePath = $null
        $outputParentLease = ProductionReleaseState\Open-ProductionReleaseDirectoryLease `
            -Path $outputParent -Label 'Client-signing response output parent'
        if ($outputParentLease.VolumeSerialNumber -ne $parentVolume -or
            $outputParentLease.FileIndex -ne $parentIndex) {
            throw 'Client-signing response output parent identity changed during atomic publication.'
        }

        Assert-ProductionClientExactDirectoryInventory `
            -Path $outputRoot -Expected $stageInventory `
            -Label 'Committed client-signing response bundle'
        Assert-ProductionClientExactDirectoryInventory `
            -Path (Join-Path $outputRoot 'signed') -Expected $signedInventory `
            -Label 'Committed signed-client payload'
        $committedResponse = ProductionReleaseState\Open-ProductionReleaseInput `
            -Path (Join-Path $outputRoot 'signing-response.v1.json') `
            -Label 'Committed client-signing response' `
            -MaximumBytes 16MB
        try {
            if ([int64]$committedResponse.SizeBytes -ne
                    [int64]$responseBytes.LongLength -or
                [string]$committedResponse.Sha256 -cne
                    (ProductionReleaseState\Get-ProductionSha256Bytes `
                        -Bytes $responseBytes)) {
                throw 'Committed client-signing response differs from the authenticated bytes.'
            }
        }
        finally {
            $committedResponse.Stream.Dispose()
        }
        for ($index = 0; $index -lt 4; $index++) {
            $committedFile = ProductionReleaseState\Open-ProductionReleaseInput `
                -Path (Join-Path `
                    (Join-Path $outputRoot 'signed') `
                    ([string]$targets[$index].FileName)) `
                -Label "Committed signed client role $($targets[$index].Role)" `
                -MaximumBytes 512MB
            try {
                if ([int64]$committedFile.SizeBytes -ne
                        [int64]$evidence[$index].SizeBytes -or
                    [string]$committedFile.Sha256 -cne
                        [string]$evidence[$index].SignedFileSha256) {
                    throw "Committed signed client role '$($targets[$index].Role)' differs from the verified bytes."
                }
            }
            finally {
                $committedFile.Stream.Dispose()
            }
        }

        return [pscustomobject][ordered]@{
            OutputRoot = $outputRoot
            ResponseSha256 = ProductionReleaseState\Get-ProductionSha256Bytes `
                -Bytes $responseBytes
            RequestSha256 = [string]$requestInput.Sha256
            AdmissionHeadSha256 = $ExpectedHeadSha256
            Edition = [string]$plan.edition
            VerifiedFileCount = 4
            ProductionAdmission = 'OFFLINE_RESPONSE_ONLY'
            AuthenticodeSigningPerformed = $false
            NetworkPublicationPerformed = $false
            ReleaseStateChanged = $false
        }
    }
    finally {
        if ($null -ne $keyBytes) {
            [Array]::Clear($keyBytes, 0, $keyBytes.Length)
        }
        if ($null -ne $signer) {
            $signer.Dispose()
        }
        if ($null -ne $stageMoveLease) {
            $stageMoveLease.Handle.Dispose()
        }
        for ($index = $signedInputs.Count - 1; $index -ge 0; $index--) {
            $signedInputs[$index].Stream.Dispose()
        }
        for ($index = $unsignedInputs.Count - 1; $index -ge 0; $index--) {
            $unsignedInputs[$index].Stream.Dispose()
        }
        foreach ($input in @($keyInput, $requestInput, $planInput)) {
            if ($null -ne $input) {
                $input.Stream.Dispose()
            }
        }
        if ($null -ne $outputParentLease) {
            $outputParentLease.Handle.Dispose()
        }
        if ($null -ne $signedRootLease) {
            $signedRootLease.Handle.Dispose()
        }
        if ($null -ne $stateLock) {
            $stateLock.Stream.Dispose()
        }
        if ($stageOwned -and -not $committed -and
            $null -ne $stagePath -and
            $null -ne $stageOwnerLease -and
            (Test-Path -LiteralPath $stagePath)) {
            try {
                Remove-ProductionClientOwnedStage `
                    -StagePath $stagePath `
                    -OutputPath $outputRoot `
                    -ExpectedFileNames $expectedFileNames `
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

Invoke-ProductionClientSigningResponse @PSBoundParameters
