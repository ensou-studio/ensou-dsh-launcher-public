#requires -Version 7.2

[CmdletBinding()]
param([string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function ConvertTo-Base64Url([byte[]]$Bytes) { [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+','-').Replace('/','_') }
function ConvertFrom-Base64Url([string]$Value) { [Convert]::FromBase64String($Value.Replace('-','+').Replace('_','/') + '==') }
function Hash([string]$Character) { ($Character * 64) -join '' }
function Assert-Throws([scriptblock]$Action, [string]$Label) { try { & $Action } catch { return }; throw "$Label did not fail closed." }
function Write-Json([string]$Path, $Value) { [IO.File]::WriteAllText($Path, ($Value | ConvertTo-Json -Depth 12) + "`n", [Text.UTF8Encoding]::new($false)) }

function New-Artifact([string]$Component, [string]$ReleaseId, [string]$Uri) {
    [ordered]@{ component = $Component; releaseId = $ReleaseId; uri = $Uri; sizeBytes = 1; sha256 = Hash '1'; completeTreeSha256 = Hash '2' }
}
function New-Intent {
    [ordered]@{
        environment = 'production'; channel = 'pilot'; releaseSetId = 'enterprise-2026.08.27.1'; releaseSigningKeyId = 'release-key'; generation = 1; sequence = 1; minAcceptedSequence = 0
        launcher = New-Artifact 'launcher' 'launcher-1' 'https://updates.example.test/launcher.zip'
        runtime = New-Artifact 'runtime' 'runtime-1' 'https://updates.example.test/runtime.zip'
        pluginPolicy = New-Artifact 'plugin-policy' 'plugins-1' 'https://updates.example.test/plugin.zip'
        policyId = '11111111-2222-4333-8444-555555555555'; policyGeneration = 1
        pluginMetadataSha256 = Hash 'a'; rawPolicySha256 = Hash 'b'; promotionHandoffSha256 = Hash 'c'; compatibilityReceiptSha256 = Hash 'd'
        reservationSha256 = Hash 'e'; runtimeSourceMetadataSha256 = Hash '6'; generationLedgerNamespace = 'publisher-production'; generationLedgerPathSha256 = Hash '7'; generationLedgerSha256 = Hash 'f'; organizationAdmissionReceiptSha256 = Hash '0'
    }
}
function New-Challenge([DateTimeOffset]$Issued, [DateTimeOffset]$Expires, [int64]$Revision = 0, [string]$Head = $null) {
    if ([string]::IsNullOrEmpty($Head)) { [void]($Head = ('0' * 64) -join '') }
    [ordered]@{ schemaVersion = 1; challengeType = 'managed-plugin-promotion-journal-challenge'; journalInstanceId = '22222222-2222-4222-8222-222222222222'; expectedStateRevision = $Revision; expectedHeadSha256 = $Head; issuedAtUtc = $Issued.ToString('O',[Globalization.CultureInfo]::InvariantCulture); expiresAtUtc = $Expires.ToString('O',[Globalization.CultureInfo]::InvariantCulture) }
}
function Get-IntentPayload($Intent) {
    $artifact = { param($v) "$($v.component)|$($v.releaseId)|$($v.uri)|$($v.sizeBytes.ToString([Globalization.CultureInfo]::InvariantCulture))|$($v.sha256)|$($v.completeTreeSha256)" }
    [Text.Encoding]::UTF8.GetBytes((@('ensou-dsh-enterprise-plugin-promotion-intent-v1',$Intent.environment,$Intent.channel,$Intent.releaseSetId,$Intent.releaseSigningKeyId,$Intent.generation.ToString([Globalization.CultureInfo]::InvariantCulture),$Intent.sequence.ToString([Globalization.CultureInfo]::InvariantCulture),$Intent.minAcceptedSequence.ToString([Globalization.CultureInfo]::InvariantCulture),(& $artifact $Intent.launcher),(& $artifact $Intent.runtime),(& $artifact $Intent.pluginPolicy),$Intent.policyId,$Intent.policyGeneration.ToString([Globalization.CultureInfo]::InvariantCulture),$Intent.pluginMetadataSha256,$Intent.rawPolicySha256,$Intent.promotionHandoffSha256,$Intent.compatibilityReceiptSha256,$Intent.reservationSha256,$Intent.runtimeSourceMetadataSha256,$Intent.generationLedgerNamespace,$Intent.generationLedgerPathSha256,$Intent.generationLedgerSha256,$Intent.organizationAdmissionReceiptSha256) -join "`n"))
}
function Assert-AuthorizationSignature([string]$Path, [Security.Cryptography.ECDsa]$Verifier, [string]$ExpectedKeyId) {
    $raw = [IO.File]::ReadAllText($Path, [Text.UTF8Encoding]::new($false,$true))
    $value = $raw | ConvertFrom-Json -Depth 16 -DateKind String
    if ($value.signature.algorithm -cne 'ES256' -or $value.signature.keyId -cne $ExpectedKeyId) { throw 'Authorization signature identity is invalid.' }
    $intentBytes = Get-IntentPayload $value.intent
    try { $intentHash = ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($intentBytes))).ToLowerInvariant() } finally { [Array]::Clear($intentBytes,0,$intentBytes.Length) }
    $issuedText = [string]$value.issuedAtUtc
    $expiresText = [string]$value.expiresAtUtc
    $payload = [Text.Encoding]::UTF8.GetBytes((@('ensou-dsh-enterprise-plugin-promotion-journal-authorization-v1','1','managed-plugin-promotion-journal-authorization',$value.authorizationId,$value.journalInstanceId,$value.expectedStateRevision.ToString([Globalization.CultureInfo]::InvariantCulture),$value.expectedHeadSha256,$issuedText,$expiresText,$intentHash) -join "`n"))
    try {
        $signature = ConvertFrom-Base64Url $value.signature.value
        if ($signature.Length -ne 64 -or -not $Verifier.VerifyData($payload,$signature,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)) { throw "Authorization signature verification failed: $(([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($payload))).ToLowerInvariant())" }
    } finally { [Array]::Clear($payload,0,$payload.Length) }
    return $value
}

$root = Join-Path ([IO.Path]::GetTempPath()) ('ensou-plugin-promotion-journal-authorization-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($root) | Out-Null
$signer = [Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve+NamedCurves]::nistP256)
try {
    $script = Join-Path $PSScriptRoot 'New-EnterprisePluginPromotionJournalAuthorization.ps1'
    $intentPath = Join-Path $root 'intent.json'; $challengePath = Join-Path $root 'challenge.json'; $keyPath = Join-Path $root 'authority.pk8'; $outputPath = Join-Path $root 'authorization.json'
    $intent = New-Intent; Write-Json $intentPath $intent
    $now = [DateTimeOffset]::UtcNow; Write-Json $challengePath (New-Challenge $now.AddMinutes(-1) $now.AddHours(8))
    [IO.File]::WriteAllBytes($keyPath, $signer.ExportPkcs8PrivateKey())
    $output = @(& $script -ChallengePath $challengePath -IntentPath $intentPath -PrivateKeyPath $keyPath -KeyId 'journal-authority-test' -AuthorizationId '33333333-3333-4333-8333-333333333333' -OutputPath $outputPath -RepositoryRoot $RepositoryRoot)
    if ($output.Count -ne 1 -or $output[0] -notmatch '^PLUGIN-PROMOTION-JOURNAL-AUTHORIZATION-PASS ') { throw 'Positive signer output is invalid.' }
    $schema = Join-Path $RepositoryRoot 'release\schemas\enterprise-plugin-promotion-journal-authorization-v1.schema.json'
    if (-not (Test-Json -Json ([IO.File]::ReadAllText($outputPath)) -SchemaFile $schema -ErrorAction Stop)) { throw 'Positive authorization does not satisfy its schema.' }
    $verification = Assert-AuthorizationSignature $outputPath $signer 'journal-authority-test'
    if ($verification.intent.pluginPolicy.releaseId -cne 'plugins-1') { throw 'Positive authorization lost an exact plugin identity.' }

    $tampered = $verification | ConvertTo-Json -Depth 16 | ConvertFrom-Json -Depth 16; $tampered.intent.channel = 'stable'; $tamperedPath = Join-Path $root 'tampered.json'; Write-Json $tamperedPath $tampered
    Assert-Throws { [void](Assert-AuthorizationSignature $tamperedPath $signer 'journal-authority-test') } 'Signed intent tampering'
    $wrong = [Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve+NamedCurves]::nistP256)
    try { Assert-Throws { [void](Assert-AuthorizationSignature $outputPath $wrong 'journal-authority-test') } 'Wrong verification key' } finally { $wrong.Dispose() }

    $cases = @(
        [pscustomobject]@{ Label='Expired challenge'; Challenge=(New-Challenge $now.AddHours(-3) $now.AddHours(-2)); Intent=$intent },
        [pscustomobject]@{ Label='Future challenge'; Challenge=(New-Challenge $now.AddMinutes(10) $now.AddHours(2)); Intent=$intent },
        [pscustomobject]@{ Label='Negative old revision'; Challenge=(New-Challenge $now.AddMinutes(-1) $now.AddHours(2) -1); Intent=$intent },
        [pscustomobject]@{ Label='Malformed old head'; Challenge=(New-Challenge $now.AddMinutes(-1) $now.AddHours(2) 2 (('f' * 63) -join '')); Intent=$intent })
    foreach ($case in $cases) {
        $caseChallenge = Join-Path $root ($case.Label.Replace(' ','-') + '.challenge.json'); $caseOutput = Join-Path $root ($case.Label.Replace(' ','-') + '.authorization.json')
        Write-Json $caseChallenge $case.Challenge
        Assert-Throws { & $script -ChallengePath $caseChallenge -IntentPath $intentPath -PrivateKeyPath $keyPath -KeyId 'journal-authority-test' -OutputPath $caseOutput -RepositoryRoot $RepositoryRoot } $case.Label
    }

    $reordered = [ordered]@{ channel = $intent.channel; environment = $intent.environment; releaseSetId = $intent.releaseSetId; releaseSigningKeyId = $intent.releaseSigningKeyId; generation = $intent.generation; sequence = $intent.sequence; minAcceptedSequence = $intent.minAcceptedSequence; launcher = $intent.launcher; runtime = $intent.runtime; pluginPolicy = $intent.pluginPolicy; policyId = $intent.policyId; policyGeneration = $intent.policyGeneration; pluginMetadataSha256 = $intent.pluginMetadataSha256; rawPolicySha256 = $intent.rawPolicySha256; promotionHandoffSha256 = $intent.promotionHandoffSha256; compatibilityReceiptSha256 = $intent.compatibilityReceiptSha256; reservationSha256 = $intent.reservationSha256; runtimeSourceMetadataSha256 = $intent.runtimeSourceMetadataSha256; generationLedgerNamespace = $intent.generationLedgerNamespace; generationLedgerPathSha256 = $intent.generationLedgerPathSha256; generationLedgerSha256 = $intent.generationLedgerSha256; organizationAdmissionReceiptSha256 = $intent.organizationAdmissionReceiptSha256 }
    $reorderedPath = Join-Path $root 'reordered-intent.json'; Write-Json $reorderedPath $reordered
    Assert-Throws { & $script -ChallengePath $challengePath -IntentPath $reorderedPath -PrivateKeyPath $keyPath -KeyId 'journal-authority-test' -OutputPath (Join-Path $root 'reordered-output.json') -RepositoryRoot $RepositoryRoot } 'Reordered intent'
    $unknown = [ordered]@{ environment = $intent.environment; unknown = $true; channel = $intent.channel; releaseSetId = $intent.releaseSetId; releaseSigningKeyId = $intent.releaseSigningKeyId; generation = $intent.generation; sequence = $intent.sequence; minAcceptedSequence = $intent.minAcceptedSequence; launcher = $intent.launcher; runtime = $intent.runtime; pluginPolicy = $intent.pluginPolicy; policyId = $intent.policyId; policyGeneration = $intent.policyGeneration; pluginMetadataSha256 = $intent.pluginMetadataSha256; rawPolicySha256 = $intent.rawPolicySha256; promotionHandoffSha256 = $intent.promotionHandoffSha256; compatibilityReceiptSha256 = $intent.compatibilityReceiptSha256; reservationSha256 = $intent.reservationSha256; runtimeSourceMetadataSha256 = $intent.runtimeSourceMetadataSha256; generationLedgerNamespace = $intent.generationLedgerNamespace; generationLedgerPathSha256 = $intent.generationLedgerPathSha256; generationLedgerSha256 = $intent.generationLedgerSha256; organizationAdmissionReceiptSha256 = $intent.organizationAdmissionReceiptSha256 }
    $unknownPath = Join-Path $root 'unknown-intent.json'; Write-Json $unknownPath $unknown
    Assert-Throws { & $script -ChallengePath $challengePath -IntentPath $unknownPath -PrivateKeyPath $keyPath -KeyId 'journal-authority-test' -OutputPath (Join-Path $root 'unknown-output.json') -RepositoryRoot $RepositoryRoot } 'Unknown intent field'
    $duplicatePath = Join-Path $root 'duplicate-challenge.json'; $challengeRaw = [IO.File]::ReadAllText($challengePath); $duplicate = $challengeRaw -replace '^\{', '{"schemaVersion":1,'; [IO.File]::WriteAllText($duplicatePath,$duplicate,[Text.UTF8Encoding]::new($false))
    Assert-Throws { & $script -ChallengePath $duplicatePath -IntentPath $intentPath -PrivateKeyPath $keyPath -KeyId 'journal-authority-test' -OutputPath (Join-Path $root 'duplicate-output.json') -RepositoryRoot $RepositoryRoot } 'Duplicate challenge field'
    Write-Output 'ENTERPRISE-PLUGIN-PROMOTION-JOURNAL-AUTHORIZATION-CONTRACT-PASS'
}
finally {
    $signer.Dispose()
    if ([IO.Directory]::Exists($root)) { [IO.Directory]::Delete($root,$true) }
}
