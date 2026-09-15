#requires -Version 7.2
# Test-only fixture helper. Dot-source this file, then call the exported function explicitly.

function New-EnterpriseStablePublicationStateFixture {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$StateRoot,
        [Parameter(Mandatory = $true)]$Context,
        [Parameter(Mandatory = $true)][Security.Cryptography.ECDsa]$PublicationSigner,
        [Parameter(Mandatory = $true)][byte[]]$FeedIdentityBytes,
        [Parameter(Mandatory = $true)][string]$OutputBundleRoot,
        [Nullable[DateTimeOffset]]$ObservedAtUtc = $null,
        [ValidateRange(1, 600)][int]$LifetimeSeconds = 600
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'
    $utf8 = [Text.UTF8Encoding]::new($false, $true)
    $stateModule = Join-Path $PSScriptRoot 'ProductionReleaseState.psm1'
    if ($null -eq (Get-Module -Name ProductionReleaseState)) {
        Microsoft.PowerShell.Core\Import-Module $stateModule
    }

    function Bytes($Value) {
        return ,([byte[]]$utf8.GetBytes(($Value | ConvertTo-Json -Depth 64)) )
    }
    function Sha([byte[]]$Value) {
        return ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Value))).ToLowerInvariant()
    }
    function B64([byte[]]$Value) {
        return [Convert]::ToBase64String($Value).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    }
    function Write-NewBytes([string]$Path, [byte[]]$Value) {
        $stream = [IO.FileStream]::new($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $stream.Write($Value, 0, $Value.Length); $stream.Flush($true) } finally { $stream.Dispose() }
    }
    function Normalize-LowS([byte[]]$Signature) {
        $order = [Convert]::FromHexString('FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551')
        $half = [Convert]::FromHexString('7FFFFFFF800000007FFFFFFFFFFFFFFFDE737D56D38BCF4279DCE5617E3192A8')
        if ($Signature.Length -ne 64) { throw 'Test publication signer did not produce a P-256 P1363 signature.' }
        $compare = 0
        for ($i = 0; $i -lt 32; $i++) { if ($Signature[32 + $i] -ne $half[$i]) { $compare = if ($Signature[32 + $i] -gt $half[$i]) { 1 } else { -1 }; break } }
        if ($compare -le 0) { return }
        $borrow = 0
        for ($i = 31; $i -ge 0; $i--) {
            $value = [int]$order[$i] - [int]$Signature[32 + $i] - $borrow
            if ($value -lt 0) { $value += 256; $borrow = 1 } else { $borrow = 0 }
            $Signature[32 + $i] = [byte]$value
        }
        if ($borrow -ne 0) { throw 'Test publication low-S normalization underflowed.' }
    }

    $root = [IO.Path]::GetFullPath($StateRoot)
    $output = [IO.Path]::GetFullPath($OutputBundleRoot)
    $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    $outputParent = [IO.Path]::GetDirectoryName($output)
    $rootPrefix = $root.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    if (-not (Test-Path -LiteralPath $root -PathType Container) -or
        (Test-Path -LiteralPath $output) -or $output -eq $tempRoot.TrimEnd([IO.Path]::DirectorySeparatorChar) -or
        -not $output.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -or
        [string]::IsNullOrWhiteSpace($outputParent) -or -not (Test-Path -LiteralPath $outputParent -PathType Container) -or
        $output.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase) -or
        $root.StartsWith(($output.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar), [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Test publication fixture requires a new non-overlapping output beneath an existing process temporary-directory parent.'
    }
    for ($item = Get-Item -LiteralPath $outputParent -Force; $null -ne $item; $item = $item.Parent) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Test publication fixture output parent crosses a reparse point.'
        }
        if ($item.FullName.TrimEnd([IO.Path]::DirectorySeparatorChar) -ceq $tempRoot.TrimEnd([IO.Path]::DirectorySeparatorChar)) { break }
    }
    $stateSchema = Join-Path (Split-Path -Parent $PSScriptRoot) 'schemas/launcher-production-release-state-v2.schema.json'
    $state = ProductionReleaseState\Get-ProductionReleaseState -StateRoot $root -StateSchemaPath $stateSchema
    if ([int]$state.Head.revision -ne 9 -or [string]$state.Head.phase -cne 'STABLE_PROMOTION_REQUESTED') {
        throw 'Test publication fixture requires an exact Enterprise Stable r9 state.'
    }
    if ([string]$Context.operationId -notmatch '^[0-9a-f]{32}$' -or
        [string]$Context.releaseSetId -cne [string]$state.Plan.releaseSetId) {
        throw 'Test publication context does not match the supplied r9 state identity.'
    }
    if ((Sha $FeedIdentityBytes) -cne [string]$Context.expectedFeedIdentitySha256) {
        throw 'Test feed identity bytes do not match the r9 publication context.'
    }
    $public = $PublicationSigner.ExportParameters($false).Q
    if ((B64 $public.X) -cne [string]$Context.trust.x -or (B64 $public.Y) -cne [string]$Context.trust.y -or
        [string]$Context.trust.algorithm -cne 'ES256' -or [string]$Context.trust.purpose -cne 'stable-public-promotion-attestation') {
        throw 'Test publication signer does not match the supplied publication context trust.'
    }

    $manifestDescriptor = @($state.Receipts[4].data.files | Where-Object { $_.role -ceq 'release-manifest' })
    if ($manifestDescriptor.Count -ne 1 -or [string]::IsNullOrWhiteSpace([string]$manifestDescriptor[0].relativePath)) {
        throw 'r5 signed candidate receipt does not contain one manifest descriptor.'
    }
    $manifestPath = Join-Path (Join-Path $root 'imports/stable-signed-candidate.v1') ([string]$manifestDescriptor[0].relativePath)
    $manifestBytes = [IO.File]::ReadAllBytes($manifestPath)
    $manifestSha256 = Sha $manifestBytes
    if ($manifestSha256 -cne [string]$Context.candidateManifestSha256 -or
        $manifestSha256 -cne [string]$manifestDescriptor[0].sha256) {
        throw 'r5 signed manifest bytes do not match the r9 publication context.'
    }
    $manifest = $utf8.GetString($manifestBytes) | ConvertFrom-Json -Depth 64 -DateKind String
    if ([string]$manifest.product -cne 'ensou-dsh-enterprise' -or [string]$manifest.environment -cne 'production' -or
        [string]$manifest.channel -cne 'stable' -or [string]$manifest.releaseSetId -cne [string]$Context.releaseSetId) {
        throw 'r5 signed manifest is not the expected Enterprise Stable candidate.'
    }

    # These test-only feed artifacts are structurally compatible evidence, not Linux publisher output.
    $observed = if ($null -ne $ObservedAtUtc) { $ObservedAtUtc } else { [DateTimeOffset]::UtcNow }
    $now = [DateTimeOffset]::FromUnixTimeSeconds($observed.ToUnixTimeSeconds()).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")
    $manifestOrigin = ([Uri][string]$Context.channelManifestUri).GetLeftPart([UriPartial]::Authority) + '/'
    $releaseTrust = $state.Plan.releaseManifestTrust
    $certificationTrust = $state.Plan.externalResponseTrusts.feedPromotion
    $trustBytes = Bytes ([ordered]@{
        schemaVersion=1;product='ensou-dsh-enterprise';environment='production'
        manifestOrigin=$manifestOrigin;artifactOrigin=[string]$state.Plan.artifactBaseUri
        releaseKeys=@([ordered]@{keyId=[string]$releaseTrust.keyId;x=[string]$releaseTrust.x;y=[string]$releaseTrust.y})
        certificationKeys=@([ordered]@{keyId=[string]$certificationTrust.keyId;x=[string]$certificationTrust.x;y=[string]$certificationTrust.y})
        allowedClockSkewSeconds=120;maximumOfflineGraceHours=168
    })
    $identity = $utf8.GetString($FeedIdentityBytes) | ConvertFrom-Json -Depth 32 -DateKind String
    if ([int]$identity.schemaVersion -ne 2 -or [string]$identity.product -cne 'ensou-dsh-enterprise' -or [string]$identity.environment -cne 'production') {
        throw 'Test feed identity bytes are not an Enterprise production feed identity document.'
    }
    $zero = '0' * 64
    $requestWithoutDigest = [ordered]@{
        schemaVersion=1;operationId=[string]$Context.operationId;requestSha256=$zero
        product='ensou-dsh-enterprise';environment='production';channel='stable'
        feedIdentitySha256=[string]$Context.expectedFeedIdentitySha256
        candidateManifestSizeBytes=[int64]$manifestBytes.LongLength;candidateManifestSha256=$manifestSha256
        trustConfigurationSha256=(Sha $trustBytes)
        expectedChannelHead=$Context.expectedChannelHead;expectedJournalHead=$Context.expectedJournalHead
    }
    # The raw document used for this zero-digest calculation is also the output document's order.
    $requestZeroBytes = Bytes $requestWithoutDigest
    $requestSha256 = Sha $requestZeroBytes
    $request = [ordered]@{}
    foreach ($key in $requestWithoutDigest.Keys) {
        $request[$key] = if ($key -ceq 'requestSha256') { $requestSha256 } else { $requestWithoutDigest[$key] }
    }
    $requestBytes = Bytes $request
    $publishedArtifacts = @($manifest.artifacts | ForEach-Object {
        [ordered]@{
            component=$_.component;releaseId=$_.releaseId
            fileName=([Uri]::UnescapeDataString(([Uri]$_.uri).Segments[-1]))
            sizeBytes=[int64]$_.sizeBytes;sha256=$_.sha256
        }
    })
    $entry = [ordered]@{
        schemaVersion=1;channel='stable';releaseSetId=[string]$manifest.releaseSetId
        generation=[int64]$manifest.generation;sequence=[int64]$manifest.sequence;minAcceptedSequence=[int64]$manifest.minAcceptedSequence
        manifestSha256=$manifestSha256;previousEntrySha256=$zero;artifacts=$publishedArtifacts;publishedAtUtc=$now
    }
    $entryBytes = Bytes $entry
    $entrySha256 = Sha $entryBytes
    $entryName = ('{0:D20}-{1}-{2}.json' -f [int64]$manifest.sequence, [string]$manifest.releaseSetId, $manifestSha256)
    $journalHead = [ordered]@{schemaVersion=1;channel='stable';releaseSetId=[string]$manifest.releaseSetId;sequence=[int64]$manifest.sequence;entryFileName=$entryName;entrySha256=$entrySha256}
    $journalHeadBytes = Bytes $journalHead
    $result = [ordered]@{
        schemaVersion=1;operationId=[string]$Context.operationId;requestSha256=$requestSha256
        product='ensou-dsh-enterprise';environment='production';channel='stable';releaseSetId=[string]$manifest.releaseSetId
        generation=[int64]$manifest.generation;sequence=[int64]$manifest.sequence;minAcceptedSequence=[int64]$manifest.minAcceptedSequence
        manifestSha256=$manifestSha256;channelManifestRelativePath='public/channels/stable/release-set.v2.json';channelManifestUri=[string]$Context.channelManifestUri
        promotionJournalEntryRelativePath=('journal/stable/' + $entryName);promotionJournalSha256=$entrySha256
        channelHead=[ordered]@{state='present';sizeBytes=[int64]$manifestBytes.LongLength;sha256=$manifestSha256}
        journalHead=[ordered]@{state='present';sizeBytes=[int64]$journalHeadBytes.LongLength;sha256=(Sha $journalHeadBytes)}
        publishedAtUtc=$now;channelHeadChanged=$true;immutableReleaseCreated=$true
    }
    $resultBytes = Bytes $result
    $contextBytes = Bytes $Context
    $copies = [ordered]@{
        'context.json'=$contextBytes;'feed-identity.json'=$FeedIdentityBytes;'operation-request.json'=$requestBytes
        'operation-result.json'=$resultBytes;'trust-configuration.json'=$trustBytes;'channel-head.json'=$manifestBytes
        'journal-head.json'=$journalHeadBytes;'journal-entry.json'=$entryBytes
    }
    $files = @($copies.Keys | ForEach-Object { [ordered]@{role=$_;sizeBytes=[int64]$copies[$_].LongLength;sha256=(Sha $copies[$_])} })
    $statement = [ordered]@{
        schemaVersion=1;resultType='ensou-dsh-enterprise-stable-publication-result';contextSha256=(Sha $contextBytes)
        operationId=[string]$Context.operationId;feedOperationRequestSha256=$requestSha256
        observedAtUtc=$now;expiresAtUtc=([DateTimeOffset]::Parse($now).AddSeconds($LifetimeSeconds).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"))
        files=$files;publishedArtifacts=$publishedArtifacts
    }
    $payload = Bytes $statement
    $prefix = $utf8.GetBytes('ensou-dsh-enterprise-stable-publication-result-v1' + [char]10 + [string]$Context.trust.keyId + [char]10)
    $signed = [byte[]]::new($prefix.Length + $payload.Length)
    [Array]::Copy($prefix, 0, $signed, 0, $prefix.Length); [Array]::Copy($payload, 0, $signed, $prefix.Length, $payload.Length)
    $signature = $PublicationSigner.SignData($signed, [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)
    Normalize-LowS $signature
    ProductionReleaseState\Assert-ProductionEs256P1363LowS -Signature $signature -Label 'Synthetic test publication signature'
    $envelope = [ordered]@{schemaVersion=1;algorithm='ES256';keyId=[string]$Context.trust.keyId;purpose='stable-public-promotion-attestation';payload=(B64 $payload);signature=(B64 $signature)}

    [void][IO.Directory]::CreateDirectory($output)
    $evidence = Join-Path $output 'evidence'
    [void][IO.Directory]::CreateDirectory($evidence)
    foreach ($role in $copies.Keys) { Write-NewBytes (Join-Path $evidence $role) $copies[$role] }
    Write-NewBytes (Join-Path $output 'publication-result.v1.json') (Bytes $envelope)
    return [pscustomobject]@{BundleRoot=$output;Synthetic=$true;ManifestSha256=$manifestSha256;OperationRequestSha256=$requestSha256;ExpiresAtUtc=[string]$statement.expiresAtUtc}
}
