#requires -Version 7.2
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'ProductionFeedPromotion.psm1') -DisableNameChecking
$script:ResultModule = Import-Module (Join-Path $PSScriptRoot 'PersonalFeedPromotionResult.psm1') -DisableNameChecking -PassThru
Import-Module (Join-Path $PSScriptRoot 'ProductionReleaseState.psm1') -DisableNameChecking

# An offline signing bridge, not a feed writer. The signer is explicitly supplied
# by the authorized executor; this module never discovers or creates keys.
function Assert-PersonalExecutionPathSeparation {
    param([string]$First,[string]$Second)
    if (-not [IO.Path]::IsPathFullyQualified($First) -or -not [IO.Path]::IsPathFullyQualified($Second)) {
        throw 'Personal execution paths must be absolute.'
    }
    $a=[IO.Path]::GetFullPath($First).TrimEnd([IO.Path]::DirectorySeparatorChar,[IO.Path]::AltDirectorySeparatorChar)
    $b=[IO.Path]::GetFullPath($Second).TrimEnd([IO.Path]::DirectorySeparatorChar,[IO.Path]::AltDirectorySeparatorChar)
    $comparison=[StringComparison]::OrdinalIgnoreCase
    if ($a.Equals($b,$comparison) -or $a.StartsWith($b+[IO.Path]::DirectorySeparatorChar,$comparison) -or $b.StartsWith($a+[IO.Path]::DirectorySeparatorChar,$comparison)) {
        throw 'Personal execution output, snapshot, state, and authorization directories must not overlap.'
    }
    foreach($path in @($a,$b)) {
        $existing=if(Test-Path -LiteralPath $path){$path}else{[IO.Path]::GetDirectoryName($path)}
        $entry=Get-Item -LiteralPath $existing -Force
        if(-not $entry.PSIsContainer){throw 'Personal execution input/output parent is not a directory.'}
        for(;$null -ne $entry;$entry=$entry.Parent){
            if(($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Personal execution path crosses a link.'}
        }
    }
}
function Copy-PersonalExecutionInput {
    param($InputFile, [string]$Destination)
    ProductionReleaseState\Assert-ProductionReleaseInputStillLocked -Descriptor $InputFile -Label 'Personal execution signing input'
    $output = [IO.File]::Open($Destination,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $InputFile.Stream.Position=0; $InputFile.Stream.CopyTo($output); $output.Flush($true) }
    finally { $output.Dispose() }
}

function New-PersonalExecutionResultFromSnapshot {
    param([string]$SnapshotRoot,[string]$OutputRoot,[hashtable]$Context,$Offline,
        [scriptblock]$Signer,[DateTimeOffset]$ExpiresAtUtc,[string[]]$PreviousHeadPaths=@())
    if (Test-Path -LiteralPath $OutputRoot) { throw 'Personal execution result output must be create-only.' }
    $parent=Get-Item -LiteralPath ([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($OutputRoot))) -Force
    for ($entry=$parent;$null -ne $entry;$entry=$entry.Parent) {
        if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Personal execution result output crosses a link.' }
    }
    $snapshot=ProductionReleaseState\Open-ProductionReleaseInput -Path (Join-Path $SnapshotRoot 'snapshot.v1.json') -Label 'Completed Linux snapshot' -MaximumBytes 1MB
    $held=[Collections.Generic.List[object]]::new(); $held.Add($snapshot)
    $staging=Join-Path $parent.FullName ('.personal-result-' + [Guid]::NewGuid().ToString('N'))
    $opened=$null
    try {
        $value=ProductionReleaseState\ConvertFrom-StrictProductionJsonBytes -Bytes (ProductionReleaseState\Read-ProductionReleaseInputBytes $snapshot 'Completed Linux snapshot') -Label 'Completed Linux snapshot'
        if ($value.schemaVersion -ne 1 -or $value.snapshotType -cne 'ensou-dsh-personal-completed-operation-snapshot' -or
            $value.scope -cne 'unsigned-completed-operation-snapshot-not-release-admission' -or
            $value.operationId -cne $Offline.OperationId -or @($value.files).Count -ne 10) { throw 'Personal completed Linux snapshot identity conflicts.' }
        if (@(Get-ChildItem -LiteralPath $SnapshotRoot -Force).Count -ne 2 -or
            @(Get-ChildItem -LiteralPath (Join-Path $SnapshotRoot 'evidence') -Force).Count -ne 10) { throw 'Personal completed Linux snapshot inventory conflicts.' }
        [void][IO.Directory]::CreateDirectory((Join-Path $staging 'evidence'))
        $files=[Collections.Generic.List[object]]::new(); $roles=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($record in $value.files) {
            $role=[string]$record.role
            if ($role -cnotin @('feed-identity','operation-request','operation-result','trust-configuration','channel-head','journal-head','journal-entry','release-manifest','launcher','runtime') -or -not $roles.Add($role)) { throw 'Personal snapshot role conflicts.' }
            $input=ProductionReleaseState\Open-ProductionReleaseInput -Path (Join-Path (Join-Path $SnapshotRoot 'evidence') $role) -Label "Completed snapshot $role" -MaximumBytes 8GB
            $held.Add($input)
            if ($record.sha256 -cne $input.Sha256 -or $record.sizeBytes -ne $input.SizeBytes) { throw 'Personal completed snapshot raw bytes drifted.' }
            Copy-PersonalExecutionInput $input (Join-Path (Join-Path $staging 'evidence') $role)
            $files.Add([ordered]@{role=$role;sizeBytes=$input.SizeBytes;sha256=$input.Sha256})
        }
        foreach ($role in @('offline-request','offline-authorization')) {
            $input=if($role -ceq 'offline-request'){$Offline.RequestInput}else{$Offline.ResponseInput}
            Copy-PersonalExecutionInput $input (Join-Path (Join-Path $staging 'evidence') $role)
            $files.Add([ordered]@{role=$role;sizeBytes=$input.SizeBytes;sha256=$input.Sha256})
        }
        # Non-genesis imports require the original CAS head bytes, not a current
        # head read after publication. Their signed request hashes are checked.
        foreach ($path in $PreviousHeadPaths) {
            $role=[IO.Path]::GetFileName($path)
            if ($role -cnotin @('previous-channel-head','previous-journal-head') -or -not $roles.Add($role)) { throw 'Personal previous head role conflicts.' }
            $input=ProductionReleaseState\Open-ProductionReleaseInput -Path $path -Label $role -MaximumBytes 1MB; $held.Add($input)
            Copy-PersonalExecutionInput $input (Join-Path (Join-Path $staging 'evidence') $role)
            $files.Add([ordered]@{role=$role;sizeBytes=$input.SizeBytes;sha256=$input.Sha256})
        }
        $trust=$Context.Plan.externalResponseTrusts.feedPromotion
        $result=[ordered]@{schemaVersion=1;resultType='ensou-dsh-personal-feed-execution-result';operationId=$Offline.OperationId;
            orchestrationId=$Context.Identity.orchestrationId;releaseSetId=$Context.Plan.releaseSetId;planSha256=$Context.Identity.planSha256;
            sourceIdentitySha256=$Context.IdentitySha256;sourceR7HeadSha256=$Context.R7HeadSha256;sourceR8HeadSha256=$Context.R8HeadSha256;
            requestSha256=$Context.SealedRequestSha256;authorizationSha256=$Offline.ResponseSha256;promotionHeadSha256=$Offline.PromotionHeadSha256;
            bundleHeadSha256=$Offline.BundleHeadSha256;bundleSetSha256=$Offline.BundleSetSha256;
            completedAtUtc=[DateTimeOffset]::UtcNow.AddSeconds(1).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'");expiresAtUtc=$ExpiresAtUtc.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'");files=@($files.ToArray());
            authentication=[ordered]@{algorithm='ES256';keyId=$trust.keyId;purpose='feed-promotion-response';payloadType='ensou-dsh-personal-feed-execution-result-v1';value=('A'*86)}}
        $resultPath=Join-Path $staging 'result.v1.json'
        [IO.File]::WriteAllBytes($resultPath,(ProductionReleaseState\ConvertTo-ProductionJsonBytes $result))
        $opened=PersonalFeedPromotionResult\Open-PersonalFeedPromotionResult $staging
        # Validate every semantic binding and the offline authorization before
        # asking the external signer to attest the completed operation.
        & $script:ResultModule {param($a,$c) Assert-PersonalFeedPromotionResultBindingCore -Admission $a @c -Fresh -UnsignedPreparation} $opened $Context
        $payload=PersonalFeedPromotionResult\Get-PersonalFeedPromotionResultAuthenticationPayload $opened.Result
        foreach($input in @($held.ToArray()) + @($Offline.HeldDescriptors)) {
            ProductionReleaseState\Assert-ProductionReleaseInputStillLocked -Descriptor $input -Label 'Personal result signing snapshot'
        }
        $signature=& $Signer $payload
        if ($signature -isnot [string] -or $signature -cnotmatch '^[A-Za-z0-9_-]{86}$') { throw 'External Personal executor signer must return one canonical low-S ES256 P1363 base64url signature.' }
        PersonalFeedPromotionResult\Close-PersonalFeedPromotionResult $opened; $opened=$null
        $result.authentication.value=$signature
        [IO.File]::WriteAllBytes($resultPath,(ProductionReleaseState\ConvertTo-ProductionJsonBytes $result))
        $opened=PersonalFeedPromotionResult\Open-PersonalFeedPromotionResult $staging
        PersonalFeedPromotionResult\Assert-PersonalFeedPromotionResultBinding -Admission $opened @Context -Fresh
        PersonalFeedPromotionResult\Close-PersonalFeedPromotionResult $opened; $opened=$null
        [IO.Directory]::Move($staging,[IO.Path]::GetFullPath($OutputRoot))
        return [pscustomobject]@{ResultPath=(Join-Path ([IO.Path]::GetFullPath($OutputRoot)) 'result.v1.json');Scope='AUTHENTICATED_COMPLETED_FEED_OPERATION_ONLY';NetworkPublishPerformed=$false}
    } finally {
        PersonalFeedPromotionResult\Close-PersonalFeedPromotionResult $opened
        foreach($input in $held){$input.Stream.Dispose()}
        # A failed private staging directory is preserved for diagnosis; it is
        # never moved to the requested output or admitted as a completed bundle.
    }
}

function New-PersonalFeedExecutionResultBundle {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$StateRoot,[Parameter(Mandatory)][string]$PromotionRoot,
        [Parameter(Mandatory)][string]$SnapshotRoot,[Parameter(Mandatory)][string]$OutputRoot,
        [Parameter(Mandatory)][string]$ExpectedHeadSha256,[Parameter(Mandatory)][scriptblock]$Signer,
        [Parameter(Mandatory)][DateTimeOffset]$ExpiresAtUtc,[string[]]$PreviousHeadPaths=@())
    $checkout=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
    foreach($external in @($OutputRoot,$SnapshotRoot,$StateRoot,$PromotionRoot)) {
        Assert-PersonalExecutionPathSeparation $external $checkout
    }
    foreach($path in $PreviousHeadPaths) {
        if(-not [IO.Path]::IsPathFullyQualified($path)){throw 'Personal execution paths must be absolute.'}
        Assert-PersonalExecutionPathSeparation ([IO.Path]::GetDirectoryName($path)) $checkout
    }
    foreach($pair in @(@($OutputRoot,$StateRoot),@($OutputRoot,$PromotionRoot),@($SnapshotRoot,$StateRoot),@($SnapshotRoot,$PromotionRoot),@($SnapshotRoot,$OutputRoot),@($StateRoot,$PromotionRoot))) {
        Assert-PersonalExecutionPathSeparation $pair[0] $pair[1]
    }
    $schema=Join-Path $PSScriptRoot '../schemas/launcher-production-release-state-v2.schema.json'
    $read=ProductionReleaseState\Enter-ProductionReleaseStateReadLock $StateRoot
    try {
        $state=ProductionReleaseState\Get-ProductionReleaseState $StateRoot $schema
        if ($state.Head.revision -ne 8 -or $state.Head.phase -cne 'PILOT_PROMOTION_REQUESTED' -or $state.HeadSha256 -cne $ExpectedHeadSha256) { throw 'Personal executor signing requires exact r8 source state.' }
        $context=PersonalFeedPromotionResult\Get-PersonalFeedPromotionStateContext -StateRoot $StateRoot -Plan $state.Plan -Identity $state.Identity -IdentitySha256 $state.IdentitySha256 -Receipts $state.Receipts
    } finally { $read.Stream.Dispose() }
    $head=ProductionReleaseState\Read-StrictProductionJsonFile -Path (Join-Path $PromotionRoot 'head.json') -Label 'Promotion head'
    $bundle=ProductionReleaseState\Read-StrictProductionJsonFile -Path (Join-Path $PromotionRoot 'bundle/head.v1.json') -Label 'Offline bundle head'
    $offline=ProductionFeedPromotion\Open-ProductionFeedPromotionBundleAdmission -PromotionRoot $PromotionRoot -ExpectedEdition Personal `
        -ExpectedPromotionHeadSha256 $head.Sha256 -ExpectedBundleHeadSha256 $bundle.Sha256 -ExpectedSourceHeadSha256 $context.R7HeadSha256 `
        -ExpectedRequestSha256 $context.SealedRequestSha256 -ExpectedResponseSha256 $bundle.Value.responseSha256 -ExpectedBundleSetSha256 $bundle.Value.bundleSetSha256
    $read=$null
    try {
        $read=ProductionReleaseState\Enter-ProductionReleaseStateReadLock $StateRoot
        $current=ProductionReleaseState\Get-ProductionReleaseState $StateRoot $schema
        if($current.HeadSha256 -cne $ExpectedHeadSha256){throw 'Personal executor source state drifted before signing.'}
        New-PersonalExecutionResultFromSnapshot -SnapshotRoot $SnapshotRoot -OutputRoot $OutputRoot -Context $context -Offline $offline -Signer $Signer -ExpiresAtUtc $ExpiresAtUtc -PreviousHeadPaths $PreviousHeadPaths
    } finally {
        if($null -ne $read){$read.Stream.Dispose()}
        ProductionFeedPromotion\Close-ProductionFeedPromotionBundleAdmission $offline
    }
}
Export-ModuleMember -Function New-PersonalFeedExecutionResultBundle
