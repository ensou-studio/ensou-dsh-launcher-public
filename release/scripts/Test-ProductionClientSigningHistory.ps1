#requires -Version 7.2
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'InstallerSigningContracts.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'ProductionReleaseState.psm1') -Force
$contracts = Get-Module InstallerSigningContracts
$fixtureRoot = [IO.Directory]::CreateTempSubdirectory('client-signing-history-').FullName
$signer = [Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve+NamedCurves]::nistP256)
$otherSigner = [Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve+NamedCurves]::nistP256)
$script:caseNumber = 0
$script:passed = 0
$script:pinnedSigner = 'c' * 64

function Assert-Test([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "ASSERT: $Message" }
}
function ConvertTo-TestBase64Url([byte[]]$Bytes) {
    [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+','-').Replace('/','_')
}
function Copy-TestObject($Value) {
    [Text.Encoding]::UTF8.GetString((ProductionReleaseState\ConvertTo-ProductionJsonBytes -Value $Value)) |
        ConvertFrom-Json -Depth 64 -DateKind String
}
function Write-TestJson([string]$Path, $Value) {
    [IO.File]::WriteAllBytes($Path, (ProductionReleaseState\ConvertTo-ProductionJsonBytes -Value $Value))
}
function Set-TestSignature($Response) {
    $payload = ProductionReleaseState\Get-ProductionReleaseSigningResponseAuthenticationPayload -Response $Response
    # Generate a real P1363 signature; retry until S is certainly below half order.
    do {
        $signature = $signer.SignData($payload, [Security.Cryptography.HashAlgorithmName]::SHA256,
            [Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)
    } while ($signature[32] -ge 0x7f)
    $Response.authentication.value = ConvertTo-TestBase64Url $signature
}
function Save-TestFixture($Fixture) {
    Write-TestJson $Fixture.RequestPath $Fixture.Request
    $Fixture.State.Receipts[1].data.requestSha256 = (Get-FileHash -LiteralPath $Fixture.RequestPath).Hash.ToLowerInvariant()
    $Fixture.Response.requestSha256 = $Fixture.State.Receipts[1].data.requestSha256
    Set-TestSignature $Fixture.Response
    Write-TestJson $Fixture.ResponsePath $Fixture.Response
    $Fixture.State.Receipts[2].data.responseSha256 = (Get-FileHash -LiteralPath $Fixture.ResponsePath).Hash.ToLowerInvariant()
}
function New-TestFixture {
    $script:caseNumber++
    $root = Join-Path $fixtureRoot ([string]$script:caseNumber)
    $requestRoot = [IO.Directory]::CreateDirectory((Join-Path $root 'requests/client-signing.v1')).FullName
    $responseRoot = [IO.Directory]::CreateDirectory((Join-Path $root 'imports/client-signing.v1')).FullName
    $signedRoot = [IO.Directory]::CreateDirectory((Join-Path $responseRoot 'signed')).FullName
    $plannedFiles = @(); $requestFiles = @(); $responseFiles = @(); $r2Files = @(); $r3Files = @(); $paths = @()
    foreach ($role in @('bootstrapper','launcher','client-bootstrapper','maintenance')) {
        # Inert synthetic PE data, never executed and never an employee installer.
        $bytes = [byte[]]::new(512)
        $bytes[0]=0x4d; $bytes[1]=0x5a
        [BitConverter]::GetBytes([int]0x80).CopyTo($bytes,0x3c)
        $bytes[0x80]=0x50; $bytes[0x81]=0x45
        [BitConverter]::GetBytes([uint16]0xe0).CopyTo($bytes,0x80+20)
        [BitConverter]::GetBytes([uint16]0x10b).CopyTo($bytes,0x80+24)
        $bytes[500]=[byte]($plannedFiles.Count+1)
        $sha = ProductionReleaseState\Get-ProductionSha256Bytes -Bytes $bytes
        $pe = ProductionReleaseState\Get-PeContentSha256 -Bytes $bytes
        $name = $role + '.exe'; $path = Join-Path $signedRoot $name
        [IO.File]::WriteAllBytes($path,$bytes); $paths += $path
        $plannedFiles += [ordered]@{role=$role;fileName=$name;path=$path;sizeBytes=512;sha256=$sha;peContentSha256=$pe}
        $requestFiles += [ordered]@{role=$role;fileName=$name;relativePath=('unsigned/'+$name);sizeBytes=512;sha256=$sha;peContentSha256=$pe}
        $responseFiles += [ordered]@{role=$role;fileName=$name;relativePath=('signed/'+$name);inputSha256=$sha;inputPeContentSha256=$pe;sizeBytes=512;sha256=$sha;signedPeContentSha256=$pe}
        $r2Files += [ordered]@{role=$role;fileName=$name;sha256=$sha;peContentSha256=$pe}
        $r3Files += [ordered]@{role=$role;fileName=$name;sizeBytes=512;sha256=$sha;peContentSha256=$pe;timestampProtocol='RFC3161'}
    }
    $public = $signer.ExportParameters($false)
    $trust = [ordered]@{algorithm='ES256';keyId='focused-client-signing';purpose='client-signing-response';x=(ConvertTo-TestBase64Url $public.Q.X);y=(ConvertTo-TestBase64Url $public.Q.Y)}
    $plan = Copy-TestObject ([ordered]@{schemaVersion=2;edition='Enterprise';targetChannel='stable';orchestrationId='11111111-1111-4111-8111-111111111111';releaseSetId='focused-history';authenticodePolicy=[ordered]@{signerSha256Thumbprint=$script:pinnedSigner;requireTrustedTimestamp=$true;maximumResponseAgeMinutes=120};externalResponseTrusts=[ordered]@{clientSigning=$trust};clientSigningInputs=$plannedFiles})
    $payloadType = 'ensou-dsh-launcher-external-signing-response-authentication-v2'
    $request = Copy-TestObject ([ordered]@{schemaVersion=1;requestType='ensou-dsh-launcher-client-authenticode-signing';orchestrationId=$plan.orchestrationId;edition='Enterprise';releaseSetId=$plan.releaseSetId;planSha256=('a'*64);nonce=('N'*43);createdAtUtc='2020-01-01T00:00:00Z';expiresAtUtc='2020-01-01T04:00:00Z';responseAuthentication=[ordered]@{algorithm='ES256';keyId=$trust.keyId;purpose=$trust.purpose;payloadType=$payloadType};authenticode=[ordered]@{signerSha256Thumbprint=$script:pinnedSigner;requireTrustedTimestamp=$true};files=$requestFiles})
    $response = Copy-TestObject ([ordered]@{schemaVersion=1;responseType='ensou-dsh-launcher-client-authenticode-signing-response';orchestrationId=$plan.orchestrationId;edition='Enterprise';releaseSetId=$plan.releaseSetId;planSha256=$request.planSha256;requestSha256=('a'*64);requestNonce=$request.nonce;completedAtUtc='2020-01-01T01:00:00Z';files=$responseFiles;authentication=[ordered]@{algorithm='ES256';keyId=$trust.keyId;purpose=$trust.purpose;payloadType=$payloadType;value=('A'*86)}})
    $r2 = [ordered]@{revision=2;phase='CLIENT_SIGNING_REQUESTED';recordedAtUtc=$request.createdAtUtc;data=[ordered]@{requestRelativePath='requests/client-signing.v1/signing-request.v1.json';requestSha256=('a'*64);nonce=$request.nonce;createdAtUtc=$request.createdAtUtc;expiresAtUtc=$request.expiresAtUtc;files=$r2Files}}
    $r3 = [ordered]@{revision=3;phase='CLIENT_SIGNATURES_IMPORTED';recordedAtUtc='2020-01-01T01:01:00Z';data=[ordered]@{responseRelativePath='imports/client-signing.v1/signing-response.v1.json';responseSha256=('a'*64);completedAtUtc=$response.completedAtUtc;authenticationKeyId=$trust.keyId;authenticationPurpose=$trust.purpose;authenticationPayloadType=$payloadType;files=$r3Files}}
    # The caller already replays and locks state; this focused test supplies its
    # replay result, not a substitute test of the full state replay or acceptance.
    $state = Copy-TestObject ([ordered]@{StateRoot=$root;HeadSha256=('b'*64);Head=[ordered]@{revision=3};Identity=[ordered]@{planSha256=$request.planSha256;orchestrationId=$plan.orchestrationId;edition='Enterprise';targetChannel='stable'};Receipts=@([ordered]@{revision=1},$r2,$r3)})
    $fixture = [pscustomobject]@{Plan=$plan;State=$state;Request=$request;Response=$response;RequestPath=(Join-Path $requestRoot 'signing-request.v1.json');ResponsePath=(Join-Path $responseRoot 'signing-response.v1.json');Paths=$paths}
    Save-TestFixture $fixture
    & $contracts { param($Paths,$Pinned) $script:HistoryTestPaths=$Paths; $script:HistoryTestPinned=$Pinned; $script:HistoryTestMode=''; $script:HistoryTestCalls=0 } (@($fixture.RequestPath,$fixture.ResponsePath)+$paths) $script:pinnedSigner
    return $fixture
}

# The only replaced production function is the Windows Authenticode evidence
# boundary. Its replacement keeps real file opening, hashing, PE parsing and
# pin arguments. This is NOT real Authenticode or employee-release acceptance.
& $contracts {
    function script:Get-ExactPeAuthenticodeEvidence {
        param([string]$Path,[string]$ExpectedSignerCertificateSha256,[string]$ExpectedPeContentSha256)
        if ($ExpectedSignerCertificateSha256 -cne $script:HistoryTestPinned) { throw 'Test signer pin mismatch.' }
        $script:HistoryTestCalls++
        if ($script:HistoryTestCalls -eq 4) {
            foreach ($lockedPath in $script:HistoryTestPaths) {
                $writeHandle = $null
                try { $writeHandle=[IO.File]::Open($lockedPath,[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::ReadWrite) }
                catch [IO.IOException] { continue }
                finally { if ($null -ne $writeHandle) { $writeHandle.Dispose() } }
                throw 'Test observed an unlocked history input before final validation.'
            }
        }
        $descriptor=ProductionReleaseState\Open-ProductionReleaseInput -Path $Path -Label 'Focused PE evidence' -MaximumBytes 512MB
        try {
            $bytes=ProductionReleaseState\Read-ProductionReleaseInputBytes -Descriptor $descriptor -Label 'Focused PE evidence'
            $pe=ProductionReleaseState\Get-PeContentSha256 -Bytes $bytes
            if ($pe -cne $ExpectedPeContentSha256) { throw 'Test PE content mismatch.' }
            $evidence=[pscustomobject]@{SizeBytes=$descriptor.SizeBytes;SignedFileSha256=$descriptor.Sha256;PeContentSha256=$pe;AuthenticodeStatus='Valid';TimestampProtocol='RFC3161';PrimarySignerCount=1;LegacyCounterSignaturePresent=$false}
            switch ($script:HistoryTestMode) {
                'status' { $evidence.AuthenticodeStatus='NotTrusted' }
                'timestamp' { $evidence.TimestampProtocol='Legacy' }
                'signer-count' { $evidence.PrimarySignerCount=2 }
                'legacy' { $evidence.LegacyCounterSignaturePresent=$true }
                'pe-evidence' { $evidence.PeContentSha256='f'*64 }
            }
            return $evidence
        } finally { $descriptor.Stream.Dispose() }
    }
}
function Invoke-TestCase([string]$Name,[scriptblock]$Mutate,[string]$ExpectedError='') {
    $fixture=New-TestFixture
    try {
        if ($null -ne $Mutate) { & $Mutate $fixture }
        $caught=$null; $result=@()
        try { $result=@(InstallerSigningContracts\Assert-ProductionClientSigningHistory -Plan $fixture.Plan -State $fixture.State) }
        catch { $caught=$_.Exception.Message }
        if ($ExpectedError) { Assert-Test ($null -ne $caught -and $caught -like "*$ExpectedError*") "$Name expected '$ExpectedError', got '$caught'" }
        else {
            Assert-Test ($null -eq $caught) "$Name unexpected '$caught'"
            Assert-Test ($result.Count -eq 1) "$Name leaked assertion output"
            Assert-Test ($result[0].Status -ceq 'CLIENT_SIGNING_HISTORY_REVALIDATED') "$Name result status"
            Assert-Test ($result[0].CurrentHeadSha256 -ceq $fixture.State.HeadSha256) "$Name current head"
            Assert-Test ($result[0].ResponseSha256 -ceq $fixture.State.Receipts[2].data.responseSha256) "$Name response hash"
            Assert-Test ($result[0].VerifiedFileCount -is [int] -and $result[0].VerifiedFileCount -eq 4) "$Name verified count"
        }
        $script:passed++; Write-Output "PASS $Name"
    } finally {
        # Every success and failure must release all six descriptors.
        foreach ($path in (@($fixture.RequestPath,$fixture.ResponsePath)+$fixture.Paths)) {
            $handle=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
            $handle.Dispose()
        }
    }
}
try {
    Invoke-TestCase 'historical import remains valid years after maximum age' $null
    Invoke-TestCase 'historical raw response whitespace preserved' { param($f) [IO.File]::WriteAllText($f.ResponsePath,($f.Response | ConvertTo-Json -Depth 64)); $f.State.Receipts[2].data.responseSha256=(Get-FileHash $f.ResponsePath).Hash.ToLowerInvariant() }
    Invoke-TestCase 'original five-minute future skew accepted' { param($f) $f.State.Receipts[2].recordedAtUtc='2020-01-01T00:55:00Z' }
    Invoke-TestCase 'original maximum-age boundary accepted' { param($f) $f.State.Receipts[2].recordedAtUtc='2020-01-01T03:00:00Z' }
    Invoke-TestCase 'original stale response rejected' { param($f) $f.State.Receipts[2].recordedAtUtc='2020-01-01T03:00:01Z' } 'stale, future-dated'
    Invoke-TestCase 'original excessive future skew rejected' { param($f) $f.State.Receipts[2].recordedAtUtc='2020-01-01T00:54:59Z' } 'stale, future-dated'
    Invoke-TestCase 'original response outside request expiry rejected' { param($f) $f.Request.expiresAtUtc='2020-01-01T00:59:59Z'; $f.State.Receipts[1].data.expiresAtUtc=$f.Request.expiresAtUtc; Save-TestFixture $f } 'original r2 lifetime'
    Invoke-TestCase 'wrong ES256 signature rejected' { param($f) $f.Response.authentication.value='A'*86; Write-TestJson $f.ResponsePath $f.Response; $f.State.Receipts[2].data.responseSha256=(Get-FileHash $f.ResponsePath).Hash.ToLowerInvariant() } 'signature'
    Invoke-TestCase 'wrong ES256 trusted key rejected' { param($f) $p=$otherSigner.ExportParameters($false); $f.Plan.externalResponseTrusts.clientSigning.x=ConvertTo-TestBase64Url $p.Q.X; $f.Plan.externalResponseTrusts.clientSigning.y=ConvertTo-TestBase64Url $p.Q.Y } 'signature is invalid'
    Invoke-TestCase 'wrong signer certificate pin rejected' { param($f) $f.Plan.authenticodePolicy.signerSha256Thumbprint='f'*64; $f.Request.authenticode.signerSha256Thumbprint='f'*64; Save-TestFixture $f } 'signer pin mismatch'
    Invoke-TestCase 'wrong request nonce rejected' { param($f) $f.Response.requestNonce='X'*43; Save-TestFixture $f } 'receipt or identity'
    Invoke-TestCase 'wrong authenticated request SHA rejected' { param($f) $f.Response.requestSha256='f'*64; Set-TestSignature $f.Response; Write-TestJson $f.ResponsePath $f.Response; $f.State.Receipts[2].data.responseSha256=(Get-FileHash $f.ResponsePath).Hash.ToLowerInvariant() } 'receipt or identity'
    Invoke-TestCase 'wrong response plan rejected' { param($f) $f.Response.planSha256='d'*64; Save-TestFixture $f } 'receipt or identity'
    Invoke-TestCase 'wrong response identity rejected' { param($f) $f.Response.releaseSetId='other-release'; Save-TestFixture $f } 'receipt or identity'
    Invoke-TestCase 'wrong request authentication domain rejected' { param($f) $f.Request.responseAuthentication.keyId='other-key'; Save-TestFixture $f } 'policy or receipt binding'
    Invoke-TestCase 'wrong plan role rejected' { param($f) $f.Plan.clientSigningInputs[0].role='other' } 'differs across plan/r2/r3'
    Invoke-TestCase 'wrong plan order rejected' { param($f) $old=$f.Plan.clientSigningInputs[0]; $f.Plan.clientSigningInputs[0]=$f.Plan.clientSigningInputs[1]; $f.Plan.clientSigningInputs[1]=$old } 'differs across plan/r2/r3'
    Invoke-TestCase 'wrong authenticated response order rejected' { param($f) $old=$f.Response.files[0]; $f.Response.files[0]=$f.Response.files[1]; $f.Response.files[1]=$old; Save-TestFixture $f } 'differs across plan/r2/r3'
    Invoke-TestCase 'wrong plan filename rejected' { param($f) $f.Plan.clientSigningInputs[0].fileName='other.exe' } 'differs across plan/r2/r3'
    Invoke-TestCase 'wrong plan size rejected' { param($f) $f.Plan.clientSigningInputs[0].sizeBytes++ } 'differs across plan/r2/r3'
    Invoke-TestCase 'wrong plan hash rejected' { param($f) $f.Plan.clientSigningInputs[0].sha256='e'*64 } 'differs across plan/r2/r3'
    Invoke-TestCase 'wrong plan PE hash rejected' { param($f) $f.Plan.clientSigningInputs[0].peContentSha256='e'*64 } 'differs across plan/r2/r3'
    Invoke-TestCase 'signed file changed size rejected' { param($f) $b=[IO.File]::ReadAllBytes($f.Paths[3]); [IO.File]::WriteAllBytes($f.Paths[3],($b+[byte]1)) } 'PE content mismatch'
    Invoke-TestCase 'signed checksum changed exact bytes rejected' { param($f) $b=[IO.File]::ReadAllBytes($f.Paths[3]); $b[0xd8]=7; [IO.File]::WriteAllBytes($f.Paths[3],$b) } 'locked bytes or r3 receipt'
    Invoke-TestCase 'signed PE content changed rejected' { param($f) $b=[IO.File]::ReadAllBytes($f.Paths[3]); $b[500]=9; [IO.File]::WriteAllBytes($f.Paths[3],$b) } 'PE content mismatch'
    Invoke-TestCase 'authenticated signed PE differs from unsigned rejected' { param($f) $f.Response.files[0].signedPeContentSha256='f'*64; Save-TestFixture $f } 'differs across plan/r2/r3'
    Invoke-TestCase 'r2 receipt hash rejected' { param($f) $f.State.Receipts[1].data.requestSha256='f'*64 } 'receipt or identity'
    Invoke-TestCase 'r2 receipt file hash rejected' { param($f) $f.State.Receipts[1].data.files[0].sha256='f'*64 } 'differs across plan/r2/r3'
    Invoke-TestCase 'r3 receipt hash rejected' { param($f) $f.State.Receipts[2].data.responseSha256='f'*64 } 'receipt or identity'
    Invoke-TestCase 'r3 receipt completion rejected' { param($f) $f.State.Receipts[2].data.completedAtUtc='2020-01-01T01:02:00Z' } 'policy or receipt binding'
    Invoke-TestCase 'r3 receipt file hash rejected' { param($f) $f.State.Receipts[2].data.files[3].sha256='f'*64 } 'locked bytes or r3 receipt'
    Invoke-TestCase 'strict JSON extra member rejected' { param($f) $f.Request | Add-Member extra 1; Save-TestFixture $f } 'schema'
    Invoke-TestCase 'noncanonical request rejected' { param($f) [IO.File]::AppendAllText($f.RequestPath,"`n") } 'canonical'
    foreach ($mode in @('status','timestamp','signer-count','legacy','pe-evidence')) {
        $expected = if ($mode -eq 'pe-evidence') { 'locked bytes or r3 receipt' } else { 'lacks exact Authenticode' }
        Invoke-TestCase "invalid Authenticode evidence $mode rejected" { param($f) & $contracts { param($Mode) $script:HistoryTestMode=$Mode } $mode } $expected
    }
    Write-Output "PASS Production client signing history: $script:passed focused cases; real ES256, JSON/schema, locked bytes and PE hashing; mocked Windows Authenticode boundary only. No employee acceptance."
} finally {
    $signer.Dispose(); $otherSigner.Dispose()
    # Restore the module for callers that dot-source the test. Fixture files are
    # retained under this process's isolated temp directory for diagnostics.
    Import-Module (Join-Path $PSScriptRoot 'InstallerSigningContracts.psm1') -Force
}
