#requires -Version 7.2
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:PublicationPurpose = 'stable-public-promotion-attestation'
$script:PublicationDomain = 'ensou-dsh-enterprise-stable-publication-result-v1'
$script:PublicationRoles = @('context.json', 'feed-identity.json',
    'operation-request.json', 'operation-result.json', 'trust-configuration.json',
    'channel-head.json', 'journal-head.json', 'journal-entry.json')

function ConvertFrom-EnterprisePublicationBase64Url {
    param([string]$Value)
    if ($Value -cnotmatch '^[A-Za-z0-9_-]+$') { throw 'Publication base64url is invalid.' }
    $bytes = [Convert]::FromBase64String($Value.Replace('-', '+').Replace('_', '/') +
        ('=' * ((4 - $Value.Length % 4) % 4)))
    if ([Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_') -cne $Value) {
        throw 'Publication base64url must be canonical.'
    }
    return ,$bytes
}

function Assert-EnterpriseStablePublicationTrust {
    param([Parameter(Mandatory)]$Plan)
    $property = $Plan.PSObject.Properties['stablePublicationTrust']
    if ([int]$Plan.schemaVersion -ne 2 -or $Plan.edition -cne 'Enterprise' -or
        $Plan.targetChannel -cne 'stable' -or $null -eq $property) {
        throw 'Enterprise r10 requires a distinct publication trust pinned in its original immutable Stable plan.'
    }
    $trust = $property.Value
    ProductionReleaseState\Assert-ExactProductionJsonMembers -Value $trust `
        -Expected @('algorithm', 'keyId', 'purpose', 'x', 'y') -Label 'Stable publication trust'
    if ($trust.algorithm -cne 'ES256' -or $trust.purpose -cne $script:PublicationPurpose -or
        $trust.keyId -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$') {
        throw 'Stable publication trust has the wrong algorithm, purpose or key ID.'
    }
    $point = ProductionReleaseState\Get-ProductionReleaseP256PublicKeyIdentity -Trust $trust -Label 'Stable publication trust'
    foreach ($other in @($Plan.releaseManifestTrust) + @($Plan.externalResponseTrusts.PSObject.Properties.Value)) {
        if ($other.keyId -ceq $trust.keyId -or
            (ProductionReleaseState\Get-ProductionReleaseP256PublicKeyIdentity -Trust $other -Label 'Existing plan trust') -ceq $point) {
            throw 'Stable publication attestation must not reuse an existing signing key ID or P-256 point.'
        }
    }
    return $trust
}

function Get-EnterpriseStablePublicationContext {
    param([string]$StateRoot, $Plan, $Identity, [string]$IdentitySha256, $Receipts)
    $trust = Assert-EnterpriseStablePublicationTrust -Plan $Plan
    if (@($Receipts).Count -lt 9 -or $Receipts[8].phase -cne 'STABLE_PROMOTION_REQUESTED') {
        throw 'Stable publication requires the authenticated r9 offline bundle.'
    }
    $receiptName = '0009-stable-promotion-requested.json'
    $receipt = ProductionReleaseState\Read-StrictProductionJsonFile -Path (Join-Path $StateRoot "receipts/$receiptName") -Label 'Stable r9 receipt'
    $head = [ordered]@{schemaVersion=2;stateType='ensou-dsh-launcher-production-release-head';
        orchestrationId=$Identity.orchestrationId;edition='Enterprise';planSha256=$Identity.planSha256;
        identitySha256=$IdentitySha256;revision=9;phase='STABLE_PROMOTION_REQUESTED';
        receiptFileName=$receiptName;receiptSha256=$receipt.Sha256;
        updatedAtUtc=$Receipts[8].recordedAtUtc;targetChannel='stable'}
    $admission = ProductionReleaseState\Read-StrictProductionJsonFile -Path (Join-Path $StateRoot 'requests/stable-feed-promotion.v1/promotion-admission.v1.json') -Label 'Stable r9 admission'
    if ($Receipts[8].data.relativePath -cne 'requests/stable-feed-promotion.v1/promotion-admission.v1.json' -or
        $Receipts[8].data.sha256 -cne $admission.Sha256) { throw 'Stable r9 admission differs from its receipt.' }
    $a = $admission.Value
    $manifest = @($Receipts[4].data.files | Where-Object role -CEQ 'release-manifest')
    if ($manifest.Count -ne 1) { throw 'Stable signed candidate must contain one manifest.' }
    return [pscustomobject][ordered]@{
        schemaVersion=1;contextType='ensou-dsh-enterprise-stable-publication-context';
        operationId=[string]$a.operationId;orchestrationId=[string]$Plan.orchestrationId;
        releaseSetId=[string]$Plan.releaseSetId;planSha256=[string]$Identity.planSha256;
        sourceIdentitySha256=$IdentitySha256;
        sourceR9HeadSha256=(ProductionReleaseState\Get-ProductionSha256Bytes -Bytes (ProductionReleaseState\ConvertTo-ProductionJsonBytes $head));
        offlinePromotionRequestSha256=[string]$a.request.sha256;offlineAuthorizationSha256=[string]$a.response.sha256;
        bundleSetSha256=[string]$a.bundleHead.bundleSetSha256;
        expectedFeedIdentitySha256=[string]$a.feedFoundation.expectedFeedIdentitySha256;
        expectedChannelHead=$a.feedFoundation.expectedChannelHead;expectedJournalHead=$a.feedFoundation.expectedJournalHead;
        candidateManifestSha256=[string]$manifest[0].sha256;channelManifestUri=[string]$Plan.manifestUri;trust=$trust
    }
}

function Close-EnterpriseStablePublicationResult {
    param($Admission)
    if ($null -ne $Admission) {
        foreach ($input in $Admission.HeldDescriptors) { $input.Stream.Dispose() }
        foreach ($directory in $Admission.DirectoryLeases) { $directory.Handle.Dispose() }
    }
}

function Open-EnterpriseStablePublicationResult {
    param([Parameter(Mandatory)][string]$BundleRoot)
    $held = [Collections.Generic.List[object]]::new()
    $directories = [Collections.Generic.List[object]]::new()
    try {
        foreach ($directory in @($BundleRoot, (Join-Path $BundleRoot 'evidence'))) {
            $item = Get-Item -LiteralPath $directory -Force
            if (-not $item.PSIsContainer) { throw 'Publication evidence directory is missing.' }
            for ($parent = $item; $null -ne $parent; $parent = $parent.Parent) {
                if (($parent.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Publication bundle crosses a link.' }
            }
            $directories.Add((ProductionReleaseState\Open-ProductionReleaseDirectoryLease -Path $directory -Label 'Stable publication directory'))
        }
        $top = @(Get-ChildItem -LiteralPath $BundleRoot -Force)
        if ($top.Count -ne 2 -or @($top.Name | Where-Object { $_ -cnotin @('publication-result.v1.json', 'evidence') }).Count) {
            throw 'Publication bundle contains unexpected entries.'
        }
        $envelope = ProductionReleaseState\Open-ProductionReleaseInput -Path (Join-Path $BundleRoot 'publication-result.v1.json') -Label 'Stable publication envelope' -MaximumBytes 1MB
        $held.Add($envelope)
        $e = ProductionReleaseState\ConvertFrom-StrictProductionJsonBytes -Bytes (ProductionReleaseState\Read-ProductionReleaseInputBytes -Descriptor $envelope -Label 'Stable publication envelope') -Label 'Stable publication envelope' -SchemaPath (Join-Path $PSScriptRoot '../schemas/enterprise-stable-publication-result-v1.schema.json')
        $payload = ConvertFrom-EnterprisePublicationBase64Url $e.payload
        if ($payload.Length -gt 512KB) { throw 'Stable publication statement exceeds its bound.' }
        $statement = ProductionReleaseState\ConvertFrom-StrictProductionJsonBytes -Bytes $payload -Label 'Stable publication statement' -SchemaPath (Join-Path $PSScriptRoot '../schemas/enterprise-stable-publication-statement-v1.schema.json')
        $entries = @(Get-ChildItem -LiteralPath (Join-Path $BundleRoot 'evidence') -Force)
        if ($entries.Count -ne $script:PublicationRoles.Count -or @($statement.files).Count -ne $script:PublicationRoles.Count) { throw 'Publication evidence inventory differs.' }
        $files = @{}; $values = @{}
        for ($i = 0; $i -lt $script:PublicationRoles.Count; $i++) {
            $role = $script:PublicationRoles[$i]
            $record = $statement.files[$i]
            if ($record.role -cne $role -or @($entries | Where-Object { $_.Name -ceq $role -and -not $_.PSIsContainer }).Count -ne 1) { throw 'Publication evidence role or ordering differs.' }
            $input = ProductionReleaseState\Open-ProductionReleaseInput -Path (Join-Path (Join-Path $BundleRoot 'evidence') $role) -Label $role -MaximumBytes 1MB
            $held.Add($input)
            if ($input.Sha256 -cne $record.sha256 -or $input.SizeBytes -ne $record.sizeBytes) { throw "Publication $role raw bytes differ." }
            $schema = if ($role -ceq 'context.json') { Join-Path $PSScriptRoot '../schemas/enterprise-stable-publication-context-v1.schema.json' } else { '' }
            $files[$role] = $input
            $values[$role] = ProductionReleaseState\ConvertFrom-StrictProductionJsonBytes -Bytes (ProductionReleaseState\Read-ProductionReleaseInputBytes -Descriptor $input -Label $role) -Label $role -SchemaPath $schema
        }
        return [pscustomobject]@{Root=[IO.Path]::GetFullPath($BundleRoot);Envelope=$envelope;Authentication=$e;
            PayloadBytes=$payload;Statement=$statement;Files=$files;Values=$values;HeldDescriptors=@($held);DirectoryLeases=@($directories)}
    } catch {
        foreach ($input in $held) { $input.Stream.Dispose() }
        foreach ($directory in $directories) { $directory.Handle.Dispose() }
        throw
    }
}

function Assert-EnterprisePublicationRawState {
    param($Actual, $Expected, [string]$Label)
    if ($Actual.state -cne $Expected.state) { throw "Publication $Label state differs." }
    foreach ($name in @('sizeBytes', 'sha256')) {
        $a = $Actual.PSObject.Properties[$name]; $e = $Expected.PSObject.Properties[$name]
        $av = if ($null -eq $a) { $null } else { $a.Value }
        $ev = if ($null -eq $e) { $null } else { $e.Value }
        if ($av -cne $ev) { throw "Publication $Label $name differs." }
    }
}

function Assert-EnterprisePublicationFinalHead {
    param($Expected, $Descriptor, [string]$Label)
    if ($Expected.state -cne 'present' -or $Expected.sha256 -cne $Descriptor.Sha256 -or
        $Expected.sizeBytes -ne $Descriptor.SizeBytes) { throw "Publication $Label final raw head differs." }
}

function Assert-EnterpriseStablePublicationBinding {
    param([Parameter(Mandatory)]$Admission, [Parameter(Mandatory)]$ExpectedContext,
        [Parameter(Mandatory)]$Plan, [switch]$Fresh, [DateTimeOffset]$NowUtc = [DateTimeOffset]::UtcNow)
    $trust = Assert-EnterpriseStablePublicationTrust $Plan
    $e = $Admission.Authentication; $s = $Admission.Statement; $v = $Admission.Values; $f = $Admission.Files
    if ($e.algorithm -cne 'ES256' -or $e.purpose -cne $script:PublicationPurpose -or $e.keyId -cne $trust.keyId) { throw 'Publication envelope trust or signature purpose differs.' }
    $signature = ConvertFrom-EnterprisePublicationBase64Url $e.signature
    if ($signature.Length -ne 64) { throw 'Publication signature must be P1363 ES256.' }
    ProductionReleaseState\Assert-ProductionEs256P1363LowS -Signature $signature -Label 'Stable publication signature'
    $parameters = [Security.Cryptography.ECParameters]::new(); $parameters.Curve = [Security.Cryptography.ECCurve+NamedCurves]::nistP256
    $point = [Security.Cryptography.ECPoint]::new(); $point.X = ConvertFrom-EnterprisePublicationBase64Url $trust.x; $point.Y = ConvertFrom-EnterprisePublicationBase64Url $trust.y
    $parameters.Q = $point; $key = [Security.Cryptography.ECDsa]::Create($parameters)
    try {
        $signed = [byte[]]([Text.Encoding]::UTF8.GetBytes($script:PublicationDomain + [char]10 + $e.keyId + [char]10) + $Admission.PayloadBytes)
        if (-not $key.VerifyData($signed, $signature, [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)) { throw 'Stable publication signature is invalid.' }
    } finally { $key.Dispose() }
    $context = $v['context.json']
    foreach ($name in @('schemaVersion', 'contextType', 'operationId', 'orchestrationId', 'releaseSetId', 'planSha256',
        'sourceIdentitySha256', 'sourceR9HeadSha256', 'offlinePromotionRequestSha256', 'offlineAuthorizationSha256',
        'bundleSetSha256', 'expectedFeedIdentitySha256', 'candidateManifestSha256', 'channelManifestUri')) {
        if ($context.$name -cne $ExpectedContext.$name) { throw "Publication immutable context $name differs from r9." }
    }
    foreach ($name in @('algorithm', 'purpose', 'keyId', 'x', 'y')) {
        if ($context.trust.$name -cne $trust.$name) { throw 'Publication context trust differs from the plan.' }
    }
    Assert-EnterprisePublicationRawState $context.expectedChannelHead $ExpectedContext.expectedChannelHead 'r9 pre-channel'
    Assert-EnterprisePublicationRawState $context.expectedJournalHead $ExpectedContext.expectedJournalHead 'r9 pre-journal'
    if ($s.contextSha256 -cne $f['context.json'].Sha256 -or $s.operationId -cne $context.operationId) { throw 'Publication statement context binding differs.' }
    $observed = ProductionReleaseState\ConvertFrom-ProductionUtc $s.observedAtUtc 'Publication observation time'
    $expires = ProductionReleaseState\ConvertFrom-ProductionUtc $s.expiresAtUtc 'Publication expiry time'
    if ($expires -le $observed -or ($expires - $observed).TotalSeconds -gt 600 -or
        ($Fresh -and ($observed -gt $NowUtc.AddSeconds(120) -or $expires -le $NowUtc))) { throw 'Publication attestation is stale, future dated or outside its lifetime bound.' }
    $request = $v['operation-request.json']; $result = $v['operation-result.json']; $identity = $v['feed-identity.json']
    foreach ($value in @($request, $result, $identity, $v['trust-configuration.json'], $v['channel-head.json'])) {
        if ($value.product -cne 'ensou-dsh-enterprise' -or $value.environment -cne 'production') { throw 'Publication feed identity is not Enterprise production.' }
    }
    if ($identity.schemaVersion -ne 2 -or $f['feed-identity.json'].Sha256 -cne $context.expectedFeedIdentitySha256 -or
        $request.feedIdentitySha256 -cne $context.expectedFeedIdentitySha256 -or $request.schemaVersion -ne 1 -or
        $request.channel -cne 'stable' -or $request.operationId -cne $context.operationId -or
        $request.requestSha256 -cne $s.feedOperationRequestSha256 -or $request.trustConfigurationSha256 -cne $f['trust-configuration.json'].Sha256) { throw 'Publication operation request identity differs.' }
    # The Linux request self-digest is distinct from the offline r9 request SHA.
    $requestBytes = ProductionReleaseState\Read-ProductionReleaseInputBytes -Descriptor $f['operation-request.json'] -Label 'Publication operation request'
    $requestText = [Text.UTF8Encoding]::new($false, $true).GetString($requestBytes)
    $pattern = '"requestSha256"\s*:\s*"[0-9a-f]{64}"'
    $matches = [regex]::Matches($requestText, $pattern)
    if ($matches.Count -ne 1) { throw 'Publication operation self-digest field is invalid.' }
    $zeroed = [regex]::Replace($matches[0].Value, '[0-9a-f]{64}', ('0' * 64))
    $zeroText = $requestText.Substring(0, $matches[0].Index) + $zeroed + $requestText.Substring($matches[0].Index + $matches[0].Length)
    if ((ProductionReleaseState\Get-ProductionSha256Bytes -Bytes ([Text.Encoding]::UTF8.GetBytes($zeroText))) -cne $request.requestSha256) { throw 'Publication Linux operation self-digest differs.' }
    Assert-EnterprisePublicationRawState $request.expectedChannelHead $context.expectedChannelHead 'operation pre-channel'
    Assert-EnterprisePublicationRawState $request.expectedJournalHead $context.expectedJournalHead 'operation pre-journal'
    if ($result.schemaVersion -ne 1 -or $result.channel -cne 'stable' -or $result.operationId -cne $context.operationId -or
        $result.requestSha256 -cne $request.requestSha256 -or $result.releaseSetId -cne $context.releaseSetId -or
        $result.manifestSha256 -cne $context.candidateManifestSha256 -or $result.channelManifestUri -cne $context.channelManifestUri -or
        $result.channelManifestRelativePath -cne 'public/channels/stable/release-set.v2.json' -or
        $result.channelHeadChanged -cne $true -or $result.immutableReleaseCreated -cne $true) { throw 'Publication operation result differs from the exact r9 candidate.' }
    Assert-EnterprisePublicationFinalHead $result.channelHead $f['channel-head.json'] 'channel'
    Assert-EnterprisePublicationFinalHead $result.journalHead $f['journal-head.json'] 'journal'
    if ($f['channel-head.json'].Sha256 -cne $context.candidateManifestSha256 -or
        $request.candidateManifestSha256 -cne $f['channel-head.json'].Sha256 -or
        $request.candidateManifestSizeBytes -ne $f['channel-head.json'].SizeBytes) { throw 'Publication raw manifest is not the admitted candidate.' }
    $manifest = $v['channel-head.json']; $journal = $v['journal-head.json']; $entry = $v['journal-entry.json']
    if ($journal.schemaVersion -ne 1 -or $entry.schemaVersion -ne 1 -or $journal.channel -cne 'stable' -or $entry.channel -cne 'stable' -or
        $journal.entrySha256 -cne $f['journal-entry.json'].Sha256 -or $result.promotionJournalSha256 -cne $f['journal-entry.json'].Sha256 -or
        $journal.entryFileName -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]*\.json$' -or
        $result.promotionJournalEntryRelativePath -cne ('journal/stable/' + $journal.entryFileName)) { throw 'Publication journal raw chain differs.' }
    foreach ($name in @('releaseSetId', 'sequence')) {
        if ($journal.$name -cne $manifest.$name) { throw 'Publication journal head identity differs.' }
    }
    foreach ($name in @('releaseSetId', 'generation', 'sequence', 'minAcceptedSequence')) {
        if ($entry.$name -cne $manifest.$name -or $result.$name -cne $manifest.$name) { throw 'Publication result/journal version differs.' }
    }
    if ($entry.manifestSha256 -cne $context.candidateManifestSha256 -or $entry.publishedAtUtc -cne $result.publishedAtUtc -or
        (ProductionReleaseState\ConvertFrom-ProductionUtc $result.publishedAtUtc 'Publication commit time') -gt $observed.AddSeconds(120)) { throw 'Publication commit time or manifest differs.' }
    $artifacts = @($manifest.artifacts)
    if (@($s.publishedArtifacts).Count -ne $artifacts.Count -or @($entry.artifacts).Count -ne $artifacts.Count) { throw 'Publication artifact closure count differs.' }
    for ($i = 0; $i -lt $artifacts.Count; $i++) {
        foreach ($name in @('component', 'releaseId', 'fileName', 'sizeBytes', 'sha256')) {
            if ($s.publishedArtifacts[$i].$name -cne $entry.artifacts[$i].$name) { throw 'Publication observed artifacts differ from the journal.' }
        }
        foreach ($name in @('component', 'releaseId', 'sizeBytes', 'sha256')) {
            if ($s.publishedArtifacts[$i].$name -cne $artifacts[$i].$name) { throw 'Publication artifact differs from its signed manifest.' }
        }
        if ([Uri]::UnescapeDataString(([Uri]$artifacts[$i].uri).Segments[-1]) -cne $s.publishedArtifacts[$i].fileName) { throw 'Publication artifact filename differs.' }
    }
    foreach ($descriptor in $Admission.HeldDescriptors) {
        ProductionReleaseState\Assert-ProductionReleaseInputStillLocked -Descriptor $descriptor -Label 'Stable publication evidence'
    }
    foreach ($directory in $Admission.DirectoryLeases) {
        ProductionReleaseState\Assert-ProductionReleaseDirectoryStillLocked -Descriptor $directory -Label 'Stable publication directory'
    }
    $top = @(Get-ChildItem -LiteralPath $Admission.Root -Force)
    $evidence = @(Get-ChildItem -LiteralPath (Join-Path $Admission.Root 'evidence') -Force)
    if ($top.Count -ne 2 -or @($top.Name | Where-Object { $_ -cnotin @('publication-result.v1.json', 'evidence') }).Count -ne 0 -or
        $evidence.Count -ne $script:PublicationRoles.Count -or @($evidence | Where-Object { $_.PSIsContainer -or $_.Name -cnotin $script:PublicationRoles }).Count -ne 0) {
        throw 'Publication directory inventory changed during admission.'
    }
}

function Assert-EnterpriseStablePublicationHistoricalState {
    param([string]$StateRoot, $Plan, $Identity, [string]$IdentitySha256, $Receipts,
        [int]$CommittedRevision, [int]$AdmittedRevision)
    $root = Join-Path $StateRoot 'imports/stable-feed-result.v1'
    $exists = Test-Path -LiteralPath $root
    if (($exists -and $CommittedRevision -lt 9) -or ($AdmittedRevision -ge 10 -and -not $exists)) {
        throw 'Enterprise publication result is missing or precedes r9.'
    }
    if (-not $exists) { return }
    $expected = Get-EnterpriseStablePublicationContext -StateRoot $StateRoot -Plan $Plan -Identity $Identity -IdentitySha256 $IdentitySha256 -Receipts $Receipts
    $admission = Open-EnterpriseStablePublicationResult -BundleRoot $root
    try {
        Assert-EnterpriseStablePublicationBinding -Admission $admission -ExpectedContext $expected -Plan $Plan
        if ($AdmittedRevision -ge 10 -and ($Receipts[9].data.evidenceType -cne 'STABLE_FEED_PROMOTED' -or
            $Receipts[9].data.relativePath -cne 'imports/stable-feed-result.v1/publication-result.v1.json' -or
            $Receipts[9].data.sha256 -cne $admission.Envelope.Sha256)) {
            throw 'Enterprise r10 receipt differs from its authenticated publication result.'
        }
        if ($AdmittedRevision -ge 10) {
            $recordedAt = ProductionReleaseState\ConvertFrom-ProductionUtc $Receipts[9].recordedAtUtc 'Stable publication receipt time'
            Assert-EnterpriseStablePublicationBinding -Admission $admission -ExpectedContext $expected -Plan $Plan -Fresh -NowUtc $recordedAt
        }
    } finally { Close-EnterpriseStablePublicationResult $admission }
}

function Assert-EnterpriseStablePublicationTransition {
    param($State, $Data)
    if ($Data.evidenceType -cne 'STABLE_FEED_PROMOTED' -or
        $Data.relativePath -cne 'imports/stable-feed-result.v1/publication-result.v1.json') {
        throw 'Enterprise r10 requires its exact authenticated publication result, not generic evidence.'
    }
    $expected = Get-EnterpriseStablePublicationContext -StateRoot $State.StateRoot -Plan $State.Plan -Identity $State.Identity -IdentitySha256 $State.IdentitySha256 -Receipts $State.Receipts
    $admission = Open-EnterpriseStablePublicationResult -BundleRoot (Join-Path $State.StateRoot 'imports/stable-feed-result.v1')
    try {
        if ($Data.sha256 -cne $admission.Envelope.Sha256) { throw 'Enterprise publication transition hash differs.' }
        $effectiveAt = [DateTimeOffset]::UtcNow
        if ($null -ne $State.OrphanReceipt) {
            $orphan = $State.OrphanReceipt
            $orphanDataSha = ProductionReleaseState\Get-ProductionSha256Bytes -Bytes (ProductionReleaseState\ConvertTo-ProductionJsonBytes $orphan.data)
            $requestedDataSha = ProductionReleaseState\Get-ProductionSha256Bytes -Bytes (ProductionReleaseState\ConvertTo-ProductionJsonBytes $Data)
            if ([int]$orphan.revision -ne 10 -or $orphan.phase -cne 'STABLE_FEED_PROMOTED' -or
                $orphanDataSha -cne $requestedDataSha) {
                throw 'Stable publication orphan conflicts with the exact requested transition.'
            }
            # Recover only the already authenticated receipt, not a new authorization.
            $effectiveAt = ProductionReleaseState\ConvertFrom-ProductionUtc $orphan.recordedAtUtc 'Stable publication orphan receipt time'
        }
        Assert-EnterpriseStablePublicationBinding -Admission $admission -ExpectedContext $expected -Plan $State.Plan -Fresh -NowUtc $effectiveAt
    } finally { Close-EnterpriseStablePublicationResult $admission }
}

Export-ModuleMember -Function @('Assert-EnterpriseStablePublicationTrust', 'Get-EnterpriseStablePublicationContext',
    'Open-EnterpriseStablePublicationResult', 'Close-EnterpriseStablePublicationResult', 'Assert-EnterpriseStablePublicationBinding',
    'Assert-EnterpriseStablePublicationHistoricalState', 'Assert-EnterpriseStablePublicationTransition')
