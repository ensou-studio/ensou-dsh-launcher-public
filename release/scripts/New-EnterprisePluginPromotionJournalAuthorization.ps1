#requires -Version 7.2

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ChallengePath,
    [Parameter(Mandatory)][string]$IntentPath,
    [Parameter(Mandatory)][string]$PrivateKeyPath,
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')][string]$KeyId,
    [ValidatePattern('^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')][string]$AuthorizationId,
    [ValidateRange(1, 24)][int]$ValidHours = 4,
    [Parameter(Mandatory)][string]$OutputPath,
    [string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function ConvertTo-Base64Url([byte[]]$Bytes) {
    return [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function ConvertFrom-Base64Url([string]$Value, [string]$Label) {
    if ($Value -cnotmatch '^[A-Za-z0-9_-]{86}$') { throw "$Label is not canonical 64-byte base64url." }
    $text = $Value.Replace('-', '+').Replace('_', '/') + '=='
    $bytes = [Convert]::FromBase64String($text)
    if ($bytes.Length -ne 64 -or (ConvertTo-Base64Url $bytes) -cne $Value) { throw "$Label is not canonical base64url." }
    Write-Output -NoEnumerate $bytes
}

function Assert-OrdinaryPathChain([string]$Path, [string]$Label, [bool]$RequireFile) {
    if (-not [IO.Path]::IsPathFullyQualified($Path)) { throw "$Label must be absolute." }
    $full = [IO.Path]::GetFullPath($Path)
    if ($RequireFile -and -not [IO.File]::Exists($full)) { throw "$Label does not exist as a file." }
    if ($RequireFile -and (([IO.File]::GetAttributes($full) -band [IO.FileAttributes]::ReparsePoint) -ne 0)) { throw "$Label is a reparse point." }
    $directory = [IO.DirectoryInfo]([IO.Path]::GetDirectoryName($full))
    while ($null -ne $directory) {
        if ($directory.Exists -and (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) { throw "$Label has a reparse-point ancestor." }
        $directory = $directory.Parent
    }
    return $full
}

function Open-LockedInput([string]$Path, [string]$Label, [int]$MaximumBytes, [Collections.Generic.List[IDisposable]]$Leases) {
    $full = Assert-OrdinaryPathChain $Path $Label $true
    $stream = [IO.FileStream]::new($full, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read, 4096, [IO.FileOptions]::SequentialScan)
    try {
        if ($stream.Length -le 0 -or $stream.Length -gt $MaximumBytes) { throw "$Label size is invalid." }
        $Leases.Add($stream)
        return [pscustomobject]@{ Path = $full; Label = $Label; Stream = $stream; Length = [int]$stream.Length }
    }
    catch { $stream.Dispose(); throw }
}

function Read-LockedBytes($Descriptor) {
    $stream = $Descriptor.Stream
    if ($stream.Length -ne $Descriptor.Length) { throw "$($Descriptor.Label) changed while locked." }
    [void]($stream.Position = 0)
    $bytes = [byte[]]::new($Descriptor.Length)
    $offset = 0
    while ($offset -lt $bytes.Length) {
        $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
        if ($read -le 0) { throw "$($Descriptor.Label) ended while locked." }
        [void]($offset += $read)
    }
    if ($stream.Length -ne $Descriptor.Length) { throw "$($Descriptor.Label) changed while locked." }
    return ,$bytes
}

function Read-StrictJson($Descriptor) {
    $bytes = Read-LockedBytes $Descriptor
    try {
        if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) { throw "$($Descriptor.Label) must not have a UTF-8 BOM." }
        $text = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
        return [Text.Json.JsonDocument]::Parse($text, [Text.Json.JsonDocumentOptions]@{ AllowTrailingCommas = $false; CommentHandling = [Text.Json.JsonCommentHandling]::Disallow; MaxDepth = 32 })
    }
    finally { [Array]::Clear($bytes, 0, $bytes.Length) }
}

function Assert-NoDuplicateMembers([Text.Json.JsonElement]$Element, [string]$Label) {
    if ($Element.ValueKind -eq [Text.Json.JsonValueKind]::Object) {
        $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($property in $Element.EnumerateObject()) {
            if (-not $names.Add($property.Name)) { throw "$Label contains duplicate property $($property.Name)." }
            Assert-NoDuplicateMembers $property.Value $Label
        }
    } elseif ($Element.ValueKind -eq [Text.Json.JsonValueKind]::Array) {
        foreach ($item in $Element.EnumerateArray()) { Assert-NoDuplicateMembers $item $Label }
    }
}

function Assert-Properties([Text.Json.JsonElement]$Element, [string[]]$Expected, [string]$Label) {
    if ($Element.ValueKind -ne [Text.Json.JsonValueKind]::Object) { throw "$Label must be an object." }
    $actual = @($Element.EnumerateObject() | ForEach-Object Name)
    if (($actual -join ',') -cne ($Expected -join ',')) { throw "$Label has missing, unknown, or reordered properties." }
}

function Require-String([Text.Json.JsonElement]$Object, [string]$Name, [string]$Label) {
    $value = $Object.GetProperty($Name)
    if ($value.ValueKind -ne [Text.Json.JsonValueKind]::String) { throw "$Label.$Name must be a string." }
    return $value.GetString()
}

function Require-Int64([Text.Json.JsonElement]$Object, [string]$Name, [string]$Label) {
    $value = $Object.GetProperty($Name)
    if ($value.ValueKind -ne [Text.Json.JsonValueKind]::Number) { throw "$Label.$Name must be an integer." }
    try { return $value.GetInt64() } catch { throw "$Label.$Name must be an Int64." }
}

function Assert-Sha256([string]$Value, [string]$Label) { if ($Value -cnotmatch '^[0-9a-f]{64}$') { throw "$Label must be lowercase SHA-256." } }
function Assert-ReleaseId([string]$Value, [string]$Label) { if ($Value -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$') { throw "$Label is invalid." } }
function Assert-CanonicalUuid([string]$Value, [string]$Label) { if ($Value -cnotmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$') { throw "$Label must be lowercase canonical UUID." } }

function Convert-Artifact([Text.Json.JsonElement]$Element, [string]$ExpectedComponent, [string]$Label) {
    Assert-Properties $Element @('component','releaseId','uri','sizeBytes','sha256','completeTreeSha256') $Label
    $component = Require-String $Element 'component' $Label
    $releaseId = Require-String $Element 'releaseId' $Label
    $uri = Require-String $Element 'uri' $Label
    $sizeBytes = Require-Int64 $Element 'sizeBytes' $Label
    $sha256 = Require-String $Element 'sha256' $Label
    $tree = Require-String $Element 'completeTreeSha256' $Label
    $parsedUri = $null
    if ($component -cne $ExpectedComponent -or -not [Uri]::TryCreate($uri, [UriKind]::Absolute, [ref]$parsedUri) -or $parsedUri.Scheme -cne 'https' -or $sizeBytes -le 0) { throw "$Label identity is invalid." }
    Assert-ReleaseId $releaseId "$Label.releaseId"; Assert-Sha256 $sha256 "$Label.sha256"; Assert-Sha256 $tree "$Label.completeTreeSha256"
    return [ordered]@{ component = $component; releaseId = $releaseId; uri = $uri; sizeBytes = $sizeBytes; sha256 = $sha256; completeTreeSha256 = $tree }
}

function Convert-Intent([Text.Json.JsonElement]$Intent) {
    Assert-Properties $Intent @('environment','channel','releaseSetId','releaseSigningKeyId','generation','sequence','minAcceptedSequence','launcher','runtime','pluginPolicy','policyId','policyGeneration','pluginMetadataSha256','rawPolicySha256','promotionHandoffSha256','compatibilityReceiptSha256','reservationSha256','runtimeSourceMetadataSha256','generationLedgerNamespace','generationLedgerPathSha256','generationLedgerSha256','organizationAdmissionReceiptSha256') 'intent'
    $environment = Require-String $Intent 'environment' 'intent'
    $channel = Require-String $Intent 'channel' 'intent'
    $releaseSetId = Require-String $Intent 'releaseSetId' 'intent'
    $releaseKey = Require-String $Intent 'releaseSigningKeyId' 'intent'
    $generation = Require-Int64 $Intent 'generation' 'intent'; $sequence = Require-Int64 $Intent 'sequence' 'intent'; $minAcceptedSequence = Require-Int64 $Intent 'minAcceptedSequence' 'intent'
    $policyId = Require-String $Intent 'policyId' 'intent'; $policyGeneration = Require-Int64 $Intent 'policyGeneration' 'intent'
    $generationLedgerNamespace = Require-String $Intent 'generationLedgerNamespace' 'intent'
    if ($environment -cne 'production' -or [string]::IsNullOrWhiteSpace($channel) -or $channel.Length -gt 64 -or $releaseKey -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$' -or $generation -le 0 -or $sequence -le 0 -or $minAcceptedSequence -lt 0 -or $minAcceptedSequence -gt $sequence -or $policyGeneration -le 0 -or $generationLedgerNamespace -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$') { throw 'intent production tuple is invalid.' }
    Assert-ReleaseId $releaseSetId 'intent.releaseSetId'; Assert-CanonicalUuid $policyId 'intent.policyId'
    $hashes = @{}
    foreach ($name in @('pluginMetadataSha256','rawPolicySha256','promotionHandoffSha256','compatibilityReceiptSha256','reservationSha256','runtimeSourceMetadataSha256','generationLedgerPathSha256','generationLedgerSha256','organizationAdmissionReceiptSha256')) { $hashes[$name] = Require-String $Intent $name 'intent'; Assert-Sha256 $hashes[$name] "intent.$name" }
    return [ordered]@{
        environment = $environment; channel = $channel; releaseSetId = $releaseSetId; releaseSigningKeyId = $releaseKey; generation = $generation; sequence = $sequence; minAcceptedSequence = $minAcceptedSequence
        launcher = Convert-Artifact $Intent.GetProperty('launcher') 'launcher' 'intent.launcher'
        runtime = Convert-Artifact $Intent.GetProperty('runtime') 'runtime' 'intent.runtime'
        pluginPolicy = Convert-Artifact $Intent.GetProperty('pluginPolicy') 'plugin-policy' 'intent.pluginPolicy'
        policyId = $policyId; policyGeneration = $policyGeneration
        pluginMetadataSha256 = $hashes.pluginMetadataSha256; rawPolicySha256 = $hashes.rawPolicySha256; promotionHandoffSha256 = $hashes.promotionHandoffSha256
        compatibilityReceiptSha256 = $hashes.compatibilityReceiptSha256; reservationSha256 = $hashes.reservationSha256; runtimeSourceMetadataSha256 = $hashes.runtimeSourceMetadataSha256
        generationLedgerNamespace = $generationLedgerNamespace; generationLedgerPathSha256 = $hashes.generationLedgerPathSha256; generationLedgerSha256 = $hashes.generationLedgerSha256
        organizationAdmissionReceiptSha256 = $hashes.organizationAdmissionReceiptSha256
    }
}

function Get-IntentPayload([Collections.Specialized.OrderedDictionary]$Intent) {
    $artifact = { param($Value) "$($Value.component)|$($Value.releaseId)|$($Value.uri)|$($Value.sizeBytes.ToString([Globalization.CultureInfo]::InvariantCulture))|$($Value.sha256)|$($Value.completeTreeSha256)" }
    $lines = @('ensou-dsh-enterprise-plugin-promotion-intent-v1', $Intent.environment, $Intent.channel, $Intent.releaseSetId, $Intent.releaseSigningKeyId,
        $Intent.generation.ToString([Globalization.CultureInfo]::InvariantCulture), $Intent.sequence.ToString([Globalization.CultureInfo]::InvariantCulture), $Intent.minAcceptedSequence.ToString([Globalization.CultureInfo]::InvariantCulture),
        (& $artifact $Intent.launcher), (& $artifact $Intent.runtime), (& $artifact $Intent.pluginPolicy), $Intent.policyId,
        $Intent.policyGeneration.ToString([Globalization.CultureInfo]::InvariantCulture), $Intent.pluginMetadataSha256, $Intent.rawPolicySha256,
        $Intent.promotionHandoffSha256, $Intent.compatibilityReceiptSha256, $Intent.reservationSha256, $Intent.runtimeSourceMetadataSha256, $Intent.generationLedgerNamespace, $Intent.generationLedgerPathSha256, $Intent.generationLedgerSha256, $Intent.organizationAdmissionReceiptSha256)
    return [Text.Encoding]::UTF8.GetBytes($lines -join "`n")
}

$leases = [Collections.Generic.List[IDisposable]]::new(); $privateKey = $null; $signer = $null; $challengeDocument = $null; $intentDocument = $null
try {
    if ([string]::IsNullOrWhiteSpace($AuthorizationId)) { $AuthorizationId = [Guid]::NewGuid().ToString('D') }
    Assert-CanonicalUuid $AuthorizationId 'AuthorizationId'
    if (-not [IO.Path]::IsPathFullyQualified($OutputPath) -or (Test-Path -LiteralPath $OutputPath)) { throw 'OutputPath must be a new absolute file.' }
    $outputFull = [IO.Path]::GetFullPath($OutputPath)
    $outputParent = [IO.Path]::GetDirectoryName($outputFull)
    if (-not [IO.Directory]::Exists($outputParent)) { throw 'OutputPath parent must already exist.' }
    [void](Assert-OrdinaryPathChain (Join-Path $outputParent 'output-probe') 'OutputPath parent' $false)
    $challengeInput = Open-LockedInput $ChallengePath 'ChallengePath' (128KB) $leases
    $intentInput = Open-LockedInput $IntentPath 'IntentPath' (128KB) $leases
    $keyInput = Open-LockedInput $PrivateKeyPath 'PrivateKeyPath' (64KB) $leases
    $challengeDocument = Read-StrictJson $challengeInput; $intentDocument = Read-StrictJson $intentInput
    Assert-NoDuplicateMembers $challengeDocument.RootElement 'challenge'; Assert-NoDuplicateMembers $intentDocument.RootElement 'intent'
    $challenge = $challengeDocument.RootElement
    Assert-Properties $challenge @('schemaVersion','challengeType','journalInstanceId','expectedStateRevision','expectedHeadSha256','issuedAtUtc','expiresAtUtc') 'challenge'
    if ((Require-Int64 $challenge 'schemaVersion' 'challenge') -ne 1 -or (Require-String $challenge 'challengeType' 'challenge') -cne 'managed-plugin-promotion-journal-challenge') { throw 'Challenge type is invalid.' }
    $journalInstanceId = Require-String $challenge 'journalInstanceId' 'challenge'; Assert-CanonicalUuid $journalInstanceId 'challenge.journalInstanceId'
    $revision = Require-Int64 $challenge 'expectedStateRevision' 'challenge'; if ($revision -lt 0) { throw 'Challenge revision is invalid.' }
    $head = Require-String $challenge 'expectedHeadSha256' 'challenge'; Assert-Sha256 $head 'challenge.expectedHeadSha256'
    $challengeIssued = [DateTimeOffset]::ParseExact((Require-String $challenge 'issuedAtUtc' 'challenge'), 'O', [Globalization.CultureInfo]::InvariantCulture); $challengeExpires = [DateTimeOffset]::ParseExact((Require-String $challenge 'expiresAtUtc' 'challenge'), 'O', [Globalization.CultureInfo]::InvariantCulture)
    $now = [DateTimeOffset]::UtcNow
    if ($challengeIssued.Offset -ne [TimeSpan]::Zero -or $challengeExpires.Offset -ne [TimeSpan]::Zero -or $challengeExpires -le $challengeIssued -or $challengeExpires -gt $challengeIssued.AddHours(24) -or $now -lt $challengeIssued.AddMinutes(-5) -or $now -gt $challengeExpires) { throw 'Challenge is expired, future-dated, or has invalid validity.' }
    $intent = Convert-Intent $intentDocument.RootElement
    $issued = $now; $expires = $issued.AddHours($ValidHours); if ($expires -gt $challengeExpires) { $expires = $challengeExpires }
    if ($expires -le $issued) { throw 'Challenge expires before the authorization can be issued.' }
    $issuedText = $issued.ToString('O', [Globalization.CultureInfo]::InvariantCulture); $expiresText = $expires.ToString('O', [Globalization.CultureInfo]::InvariantCulture)
    $intentPayload = Get-IntentPayload $intent; $intentHash = ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($intentPayload))).ToLowerInvariant(); [Array]::Clear($intentPayload, 0, $intentPayload.Length)
    $payload = [Text.Encoding]::UTF8.GetBytes((@('ensou-dsh-enterprise-plugin-promotion-journal-authorization-v1','1','managed-plugin-promotion-journal-authorization',$AuthorizationId,$journalInstanceId,$revision.ToString([Globalization.CultureInfo]::InvariantCulture),$head,$issuedText,$expiresText,$intentHash) -join "`n"))
    $privateKey = Read-LockedBytes $keyInput; $signer = [Security.Cryptography.ECDsa]::Create(); $consumed = 0; $signer.ImportPkcs8PrivateKey($privateKey, [ref]$consumed)
    if ($consumed -ne $privateKey.Length) { throw 'PKCS8 private key has trailing bytes.' }
    $point = $signer.ExportParameters($false).Q; if ($point.X.Length -ne 32 -or $point.Y.Length -ne 32) { throw 'Private key must use P-256.' }
    $signature = $signer.SignData($payload, [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)
    if ($signature.Length -ne 64 -or -not $signer.VerifyData($payload, $signature, [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)) { throw 'Authorization signature self-check failed.' }
    [void](Read-LockedBytes $challengeInput); [void](Read-LockedBytes $intentInput); [void](Read-LockedBytes $keyInput)
    $authorization = [ordered]@{ schemaVersion = 1; authorizationType = 'managed-plugin-promotion-journal-authorization'; authorizationId = $AuthorizationId; journalInstanceId = $journalInstanceId; expectedStateRevision = $revision; expectedHeadSha256 = $head; issuedAtUtc = $issuedText; expiresAtUtc = $expiresText; intent = $intent; signature = [ordered]@{ algorithm = 'ES256'; keyId = $KeyId; value = ConvertTo-Base64Url $signature } }
    $json = $authorization | ConvertTo-Json -Depth 10
    $schema = Join-Path $RepositoryRoot 'release\schemas\enterprise-plugin-promotion-journal-authorization-v1.schema.json'
    if (-not (Test-Json -Json $json -SchemaFile $schema -ErrorAction Stop)) { throw 'Generated plugin promotion journal authorization failed its schema.' }
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json + "`n")
    $output = [IO.FileStream]::new($outputFull, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None, 4096, [IO.FileOptions]::WriteThrough)
    try { $output.Write($bytes, 0, $bytes.Length); $output.Flush($true) } finally { $output.Dispose() }
    Write-Output "PLUGIN-PROMOTION-JOURNAL-AUTHORIZATION-PASS $AuthorizationId $intentHash"
}
finally {
    if ($null -ne $privateKey) { [Array]::Clear($privateKey, 0, $privateKey.Length) }
    if ($null -ne $signer) { $signer.Dispose() }
    if ($null -ne $challengeDocument) { $challengeDocument.Dispose() }
    if ($null -ne $intentDocument) { $intentDocument.Dispose() }
    for ($index = $leases.Count - 1; $index -ge 0; $index--) { $leases[$index].Dispose() }
}
