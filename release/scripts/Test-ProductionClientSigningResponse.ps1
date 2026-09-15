#requires -Version 7.2
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Focused issuer integration. Windows Authenticode and the complete state replay
# are the only test seams. The product function still owns exact locks, strict
# request/state binding, PKCS8 import, low-S ES256, publication, and cleanup.
$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$issuerPath = Join-Path $PSScriptRoot 'New-ProductionClientSigningResponse.ps1'
$stateModulePath = Join-Path $PSScriptRoot 'ProductionReleaseState.psm1'
$contractsModulePath = Join-Path $PSScriptRoot 'InstallerSigningContracts.psm1'
$schemaRoot = Join-Path $repositoryRoot 'release\schemas'
$planSchemaPath = Join-Path $schemaRoot 'launcher-production-release-plan-v2.schema.json'
$stateSchemaPath = Join-Path $schemaRoot 'launcher-production-release-state-v2.schema.json'
$requestSchemaPath = Join-Path $schemaRoot 'launcher-external-signing-request-v1.schema.json'
$responseSchemaPath = Join-Path $schemaRoot 'launcher-external-signing-response-v1.schema.json'
$p256Order = [Convert]::FromHexString(
    'FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551')
$p256HalfOrder = [Convert]::FromHexString(
    '7FFFFFFF800000007FFFFFFFFFFFFFFFDE737D56D38BCF4279DCE5617E3192A8')

Microsoft.PowerShell.Core\Import-Module $contractsModulePath -Force
Microsoft.PowerShell.Core\Import-Module $stateModulePath -Force
$stateModule = Get-Module ProductionReleaseState
$contractsModule = Get-Module InstallerSigningContracts

function Assert-Test([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "ASSERT: $Message" }
}

function ConvertTo-TestBase64Url([byte[]]$Bytes) {
    return [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Get-TestSha([byte[]]$Bytes) {
    return ProductionReleaseState\Get-ProductionSha256Bytes -Bytes $Bytes
}

function Copy-TestValue($Value) {
    $bytes = ProductionReleaseState\ConvertTo-ProductionJsonBytes -Value $Value
    return [Text.Encoding]::UTF8.GetString($bytes) |
        ConvertFrom-Json -Depth 64 -DateKind String
}

function Write-TestJson([string]$Path, $Value) {
    [IO.File]::WriteAllBytes(
        $Path,
        (ProductionReleaseState\ConvertTo-ProductionJsonBytes -Value $Value))
}

function New-TestUnsignedPe([byte]$Marker) {
    # Inert synthetic PE bytes. No fixture is ever executed.
    $bytes = [byte[]]::new(512)
    $bytes[0] = 0x4d
    $bytes[1] = 0x5a
    [BitConverter]::GetBytes([int]0x80).CopyTo($bytes, 0x3c)
    $bytes[0x80] = 0x50
    $bytes[0x81] = 0x45
    [BitConverter]::GetBytes([uint16]0xe0).CopyTo($bytes, 0x80 + 20)
    [BitConverter]::GetBytes([uint16]0x10b).CopyTo($bytes, 0x80 + 24)
    $bytes[500] = $Marker
    return ,$bytes
}

function New-TestSignedPe([byte[]]$UnsignedBytes) {
    # Add a 16-byte inert fake certificate table at offset 512. The security
    # directory and certificate table are excluded by Authenticode PE hashing.
    $bytes = [byte[]]::new(528)
    [Array]::Copy($UnsignedBytes, $bytes, $UnsignedBytes.Length)
    $securityDirectoryOffset = 0x80 + 24 + 96 + 32
    [BitConverter]::GetBytes([uint32]512).CopyTo($bytes, $securityDirectoryOffset)
    [BitConverter]::GetBytes([uint32]16).CopyTo($bytes, $securityDirectoryOffset + 4)
    for ($index = 512; $index -lt 528; $index++) {
        $bytes[$index] = [byte](0xa0 + ($index - 512))
    }
    return ,$bytes
}

function Assert-TestPathUnlocked([string]$Path) {
    $stream = [IO.File]::Open(
        $Path,
        [IO.FileMode]::Open,
        [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::None)
    $stream.Dispose()
}

function Set-TestRequest($Fixture, [switch]$BindReceiptHash) {
    Write-TestJson -Path $Fixture.RequestPath -Value $Fixture.Request
    if ($BindReceiptHash) {
        $Fixture.State.Receipts[1].data.requestSha256 =
            (Get-FileHash -LiteralPath $Fixture.RequestPath).Hash.ToLowerInvariant()
    }
    & $stateModule { param($State) $script:ClientIssuerTestState = $State } $Fixture.State
}

function New-TestFixture([ValidateSet('Enterprise', 'Personal')][string]$Edition) {
    $script:caseNumber++
    $root = [IO.Directory]::CreateDirectory(
        (Join-Path $fixtureRoot ([string]$script:caseNumber))).FullName
    $stateRoot = [IO.Directory]::CreateDirectory((Join-Path $root 'state')).FullName
    $requestRoot = [IO.Directory]::CreateDirectory(
        (Join-Path $stateRoot 'requests\client-signing.v1')).FullName
    $unsignedRoot = [IO.Directory]::CreateDirectory((Join-Path $requestRoot 'unsigned')).FullName
    $signedRoot = [IO.Directory]::CreateDirectory((Join-Path $root 'signed-input')).FullName
    $outputRoot = Join-Path $root 'output'
    [IO.File]::WriteAllBytes((Join-Path $stateRoot 'state.lock'), [byte[]](1))

    $key = [Security.Cryptography.ECDsa]::Create(
        [Security.Cryptography.ECCurve+NamedCurves]::nistP256)
    $wrongKey = [Security.Cryptography.ECDsa]::Create(
        [Security.Cryptography.ECCurve+NamedCurves]::nistP256)
    $domainKeys = [Collections.Generic.List[Security.Cryptography.ECDsa]]::new()
    $domainKeys.Add($key)
    for ($index = 0; $index -lt 4; $index++) {
        $domainKeys.Add([Security.Cryptography.ECDsa]::Create(
                [Security.Cryptography.ECCurve+NamedCurves]::nistP256))
    }
    $keyPath = Join-Path $root 'response-key.pk8'
    $wrongKeyPath = Join-Path $root 'wrong-response-key.pk8'
    [IO.File]::WriteAllBytes($keyPath, $key.ExportPkcs8PrivateKey())
    [IO.File]::WriteAllBytes($wrongKeyPath, $wrongKey.ExportPkcs8PrivateKey())
    $purposes = @(
        'client-signing-response', 'release-manifest-signing',
        'manifest-publishing-response', 'installer-signing-response',
        'feed-promotion-response')
    $trusts = [Collections.Generic.List[object]]::new()
    for ($index = 0; $index -lt $domainKeys.Count; $index++) {
        $public = $domainKeys[$index].ExportParameters($false)
        $trusts.Add([ordered]@{
                algorithm = 'ES256'
                keyId = 'focused-domain-' + [string]$index
                purpose = $purposes[$index]
                x = ConvertTo-TestBase64Url $public.Q.X
                y = ConvertTo-TestBase64Url $public.Q.Y
            })
    }
    $trust = $trusts[0]
    $roleFiles = if ($Edition -ceq 'Enterprise') {
        [ordered]@{
            bootstrapper = 'Ensou.Dsh.Enterprise.Bootstrapper.exe'
            launcher = 'Ensou.Dsh.Enterprise.Launcher.exe'
            'client-bootstrapper' = 'Ensou.Dsh.Enterprise.ClientBootstrapper.exe'
            maintenance = 'Ensou.Dsh.Enterprise.Maintenance.exe'
        }
    }
    else {
        [ordered]@{
            'startup-stub' = 'Ensou.Dsh.Bootstrapper.exe'
            'client-bootstrapper' = 'Ensou.Dsh.ClientBootstrapper.exe'
            launcher = 'Ensou.Dsh.Launcher.exe'
            maintenance = 'Ensou.Dsh.Personal.Maintenance.exe'
        }
    }
    $roles = @($roleFiles.Keys)
    $planFiles = [Collections.Generic.List[object]]::new()
    $requestFiles = [Collections.Generic.List[object]]::new()
    $r2Files = [Collections.Generic.List[object]]::new()
    $signedPaths = [Collections.Generic.List[string]]::new()
    for ($index = 0; $index -lt $roles.Count; $index++) {
        $name = [string]$roleFiles[$roles[$index]]
        [byte[]]$unsignedBytes = New-TestUnsignedPe -Marker ([byte]($index + 1))
        [byte[]]$signedBytes = New-TestSignedPe -UnsignedBytes $unsignedBytes
        $unsignedSha = Get-TestSha $unsignedBytes
        $peSha = ProductionReleaseState\Get-PeContentSha256 -Bytes $unsignedBytes
        Assert-Test (
            (ProductionReleaseState\Get-PeContentSha256 -Bytes $signedBytes) -ceq $peSha) `
            'synthetic certificate table leaves PE content unchanged'
        [IO.File]::WriteAllBytes((Join-Path $unsignedRoot $name), $unsignedBytes)
        $signedPath = Join-Path $signedRoot $name
        [IO.File]::WriteAllBytes($signedPath, $signedBytes)
        $signedPaths.Add($signedPath)
        $planFiles.Add([ordered]@{
            role = $roles[$index]; fileName = $name; path = $signedPath
            sizeBytes = 512; sha256 = $unsignedSha; peContentSha256 = $peSha
        })
        $requestFiles.Add([ordered]@{
            role = $roles[$index]; fileName = $name; relativePath = 'unsigned/' + $name
            sizeBytes = 512; sha256 = $unsignedSha; peContentSha256 = $peSha
        })
        $r2Files.Add([ordered]@{
            role = $roles[$index]; fileName = $name
            sha256 = $unsignedSha; peContentSha256 = $peSha
        })
    }
    $now = [DateTimeOffset]::UtcNow
    $releaseCompatibility = if ($Edition -ceq 'Enterprise') {
        [ordered]@{ startupStubProtocol = 1 }
    }
    else {
        [ordered]@{ startupStubVersion = '1.2.0'; canonicalLowSFromSequence = 1 }
    }
    $planValue = [ordered]@{
        schemaVersion = 2
        planType = 'ensou-dsh-launcher-production-release'
        edition = $Edition
        targetChannel = 'stable'
        orchestrationId = '12345678-1234-4123-8123-123456789abc'
        releaseSetId = ('focused-' + $Edition.ToLowerInvariant())
        sourceCommit = ('a' * 40)
        manifestUri = 'https://updates.example.invalid/stable/release-set.v2.json'
        artifactBaseUri = 'https://updates.example.invalid/stable/'
        runtimeCandidate = [ordered]@{
            releaseId = 'runtime-fixture'
            githubReleaseTag = 'runtime-fixture'
            archive = [ordered]@{ fileName = 'runtime.zip'; path = 'C:\fixture\runtime.zip'; sizeBytes = 1; sha256 = ('1' * 64) }
            metadata = [ordered]@{ fileName = 'runtime.json'; path = 'C:\fixture\runtime.json'; sizeBytes = 1; sha256 = ('2' * 64) }
            hashEvidence = [ordered]@{ fileName = 'runtime.zip.sha256'; path = 'C:\fixture\runtime.zip.sha256'; sizeBytes = 1; sha256 = ('3' * 64) }
        }
        authenticodePolicy = [ordered]@{
            signerSha256Thumbprint = ('c' * 64)
            requireTrustedTimestamp = $true
            maximumResponseAgeMinutes = 120
        }
        releaseManifestTrust = $trusts[1]
        releaseCompatibility = $releaseCompatibility
        externalResponseTrusts = [ordered]@{
            clientSigning = $trusts[0]
            manifestPublishing = $trusts[2]
            installerSigning = $trusts[3]
            feedPromotion = $trusts[4]
        }
        clientSigningInputs = @($planFiles)
    }
    if ($Edition -ceq 'Enterprise') {
        $planValue.Insert(13, 'pilotEvidenceTrustPolicySha256', ('4' * 64))
    }
    else {
        $planValue.Insert(8, 'personalAccountOrigin', 'https://account.example.invalid/')
        $planValue.externalResponseTrusts.installerSigning.purpose =
            'personal-installer-signing-response'
    }
    $plan = Copy-TestValue $planValue
    $planPath = Join-Path $stateRoot 'plan.json'
    Write-TestJson -Path $planPath -Value $plan
    $planSha = (Get-FileHash -LiteralPath $planPath).Hash.ToLowerInvariant()
    $requestCreated = $now.AddMinutes(-2)
    $request = Copy-TestValue ([ordered]@{
        schemaVersion = 1
        requestType = 'ensou-dsh-launcher-client-authenticode-signing'
        orchestrationId = $plan.orchestrationId
        edition = $Edition
        releaseSetId = $plan.releaseSetId
        planSha256 = $planSha
        nonce = ('N' * 43)
        createdAtUtc = ProductionReleaseState\ConvertTo-ProductionUtc -Value $requestCreated
        expiresAtUtc = ProductionReleaseState\ConvertTo-ProductionUtc -Value $requestCreated.AddMinutes(120)
        responseAuthentication = [ordered]@{
            algorithm = 'ES256'; keyId = $trust.keyId
            purpose = 'client-signing-response'
            payloadType = 'ensou-dsh-launcher-external-signing-response-authentication-v2'
        }
        authenticode = [ordered]@{
            signerSha256Thumbprint = ('c' * 64); requireTrustedTimestamp = $true
        }
        files = @($requestFiles)
    })
    $requestPath = Join-Path $requestRoot 'signing-request.v1.json'
    Write-TestJson -Path $requestPath -Value $request
    $r2 = [pscustomobject][ordered]@{
        revision = 2
        phase = 'CLIENT_SIGNING_REQUESTED'
        recordedAtUtc = ProductionReleaseState\ConvertTo-ProductionUtc -Value $now.AddMinutes(-1)
        data = [pscustomobject][ordered]@{
            requestRelativePath = 'requests/client-signing.v1/signing-request.v1.json'
            requestSha256 = (Get-FileHash -LiteralPath $requestPath).Hash.ToLowerInvariant()
            nonce = $request.nonce
            createdAtUtc = $request.createdAtUtc
            expiresAtUtc = $request.expiresAtUtc
            files = @($r2Files)
        }
    }
    $state = [pscustomobject][ordered]@{
        StateRoot = $stateRoot
        SchemaVersion = 2
        TargetChannel = 'stable'
        Plan = $plan
        Identity = [pscustomobject][ordered]@{
            planSha256 = $planSha; orchestrationId = $plan.orchestrationId
            edition = $Edition; targetChannel = 'stable'; releaseSetId = $plan.releaseSetId
        }
        Head = [pscustomobject][ordered]@{ revision = 2; phase = 'CLIENT_SIGNING_REQUESTED' }
        HeadSha256 = ('d' * 64)
        Receipts = @([pscustomobject]@{ revision = 1 }, $r2)
        OrphanReceipt = $null
    }
    $fixture = [pscustomobject]@{
        Root = $root; StateRoot = $stateRoot; SignedRoot = $signedRoot
        OutputRoot = $outputRoot; KeyPath = $keyPath; WrongKeyPath = $wrongKeyPath
        Key = $key; WrongKey = $wrongKey; DomainKeys = @($domainKeys)
        Trust = [pscustomobject]$trust
        Plan = $plan; Request = $request; RequestPath = $requestPath
        State = $state; SignedPaths = @($signedPaths)
    }
    & $stateModule {
        param($State)
        $script:ClientIssuerTestState = $State
        $script:ClientIssuerTestStateReplayMode = ''
        $script:ClientIssuerTestStateReplayCalls = 0
    } $state
    & $contractsModule {
        param($Paths, $RequestPath, $KeyPath, $Pin)
        $script:ClientIssuerTestPaths = $Paths
        $script:ClientIssuerTestRequestPath = $RequestPath
        $script:ClientIssuerTestKeyPath = $KeyPath
        $script:ClientIssuerTestPin = $Pin
        $script:ClientIssuerTestEvidenceMode = ''
        $script:ClientIssuerTestEvidenceCalls = 0
    } $fixture.SignedPaths $requestPath $keyPath ('c' * 64)
    return $fixture
}

function Set-EvidenceMode([string]$Mode) {
    & $contractsModule {
        param($Value)
        $script:ClientIssuerTestEvidenceMode = $Value
        $script:ClientIssuerTestEvidenceCalls = 0
    } $Mode
}

function Set-StateReplayMode([string]$Mode) {
    & $stateModule {
        param($Value)
        $script:ClientIssuerTestStateReplayMode = $Value
        $script:ClientIssuerTestStateReplayCalls = 0
    } $Mode
}

function Assert-NoPartialOutput($Fixture) {
    if (Test-Path -LiteralPath $Fixture.OutputRoot) {
        $entries = @(Get-ChildItem -LiteralPath $Fixture.OutputRoot -Force)
        if ($entries.Count -eq 1 -and $entries[0].Name -ceq 'sentinel') {
            Assert-Test ([IO.File]::ReadAllText($entries[0].FullName) -ceq 'preserve') `
                'existing output sentinel bytes are preserved'
        }
        else {
            Assert-Test ($entries.Count -eq 0) 'failed issuance leaves no output content'
        }
    }
    Assert-Test (@(Get-ChildItem -LiteralPath (Split-Path $Fixture.OutputRoot) -Force |
            Where-Object Name -Like ((Split-Path $Fixture.OutputRoot -Leaf) + '.pending-*')).Count -eq 0) `
        'failed issuance removes staging output'
}

function Assert-FixtureReleased($Fixture) {
    foreach ($path in @($Fixture.RequestPath, $Fixture.KeyPath) + $Fixture.SignedPaths) {
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            Assert-TestPathUnlocked -Path $path
        }
    }
    Assert-TestPathUnlocked -Path (Join-Path $Fixture.StateRoot 'state.lock')
}

function Invoke-TestCase(
    [string]$Name,
    [ValidateSet('Enterprise', 'Personal')][string]$Edition = 'Enterprise',
    [scriptblock]$Mutate = $null,
    [string]$ExpectedError = '',
    [scriptblock]$OverrideInvoke = $null) {
    $fixture = New-TestFixture -Edition $Edition
    try {
        if ($null -ne $Mutate) { & $Mutate $fixture }
        $observed = [Collections.Generic.List[object]]::new()
        $failure = ''
        try {
            if ($null -ne $OverrideInvoke) {
                & $OverrideInvoke $fixture | ForEach-Object { $observed.Add($_) }
            }
            else {
                Invoke-ProductionClientSigningResponse `
                    -StateRoot $fixture.StateRoot `
                    -ExpectedHeadSha256 ([string]$fixture.State.HeadSha256) `
                    -SignedClientRoot $fixture.SignedRoot `
                    -ResponsePrivateKeyPath $fixture.KeyPath `
                    -OutputRoot $fixture.OutputRoot |
                    ForEach-Object { $observed.Add($_) }
            }
        }
        catch { $failure = $_.Exception.Message }
        if ($ExpectedError) {
            Assert-Test (-not [string]::IsNullOrWhiteSpace($failure) -and $failure -match $ExpectedError) `
                "$Name expected '$ExpectedError', got '$failure'"
            Assert-Test ($observed.Count -eq 0) "$Name emits no success object"
            Assert-NoPartialOutput -Fixture $fixture
        }
        else {
            Assert-Test ([string]::IsNullOrWhiteSpace($failure)) "$Name succeeds; actual: $failure"
            Assert-Test ($observed.Count -eq 1) "$Name emits exactly one result"
            Assert-Test ($observed[0].OutputRoot -ceq $fixture.OutputRoot) "$Name returns exact output root"
            Assert-Test ([int]$observed[0].VerifiedFileCount -eq 4) "$Name reports four verified files"
            Assert-Test ([bool]$observed[0].AuthenticodeSigningPerformed -eq $false) "$Name never claims signing"
            Assert-Test ([bool]$observed[0].ReleaseStateChanged -eq $false) "$Name never claims state mutation"
            $responsePath = Join-Path $fixture.OutputRoot 'signing-response.v1.json'
            $responseBytes = [IO.File]::ReadAllBytes($responsePath)
            $response = ProductionReleaseState\ConvertFrom-StrictProductionJsonBytes `
                -Bytes $responseBytes -Label 'Actual client signing response' -SchemaPath $responseSchemaPath
            ProductionReleaseState\Assert-ProductionReleaseSigningResponseAuthentication `
                -Response $response -Trust $fixture.Trust
            Assert-Test ((Get-TestSha $responseBytes) -ceq [string]$observed[0].ResponseSha256) `
                "$Name result binds exact response bytes"
            Assert-Test ($response.edition -ceq $Edition -and
                $response.requestSha256 -ceq $fixture.State.Receipts[1].data.requestSha256 -and
                $response.requestNonce -ceq $fixture.Request.nonce) "$Name response binds request identity"
            Assert-Test (@(Get-ChildItem -LiteralPath $fixture.OutputRoot -Force).Count -eq 2) `
                "$Name output has response plus signed directory only"
            Assert-Test (@(Get-ChildItem -LiteralPath (Join-Path $fixture.OutputRoot 'signed') -File).Count -eq 4) `
                "$Name output has exactly four signed PEs"
            foreach ($file in @($response.files)) {
                $copiedPath = Join-Path $fixture.OutputRoot ([string]$file.relativePath)
                Assert-Test ((Get-FileHash -LiteralPath $copiedPath).Hash.ToLowerInvariant() -ceq [string]$file.sha256) `
                    "$Name response binds copied signed bytes"
            }
            $response.planSha256 = ('f' * 64)
            $rejected = $false
            try {
                ProductionReleaseState\Assert-ProductionReleaseSigningResponseAuthentication `
                    -Response $response -Trust $fixture.Trust
            }
            catch { $rejected = $true }
            Assert-Test $rejected "$Name generated real ES256 rejects authenticated mutation"
        }
        Assert-FixtureReleased -Fixture $fixture
        $script:passed++
        Write-Host "PASS: actual client response issuer $Name"
    }
    finally {
        foreach ($domainKey in $fixture.DomainKeys) { $domainKey.Dispose() }
        $fixture.WrongKey.Dispose()
    }
}

Assert-Test ([IO.File]::Exists($issuerPath)) 'client signing response issuer exists'
$tokens = $null
$parseErrors = $null
$issuerAst = [Management.Automation.Language.Parser]::ParseFile(
    $issuerPath,
    [ref]$tokens,
    [ref]$parseErrors)
Assert-Test ($parseErrors.Count -eq 0) 'client signing response issuer parses'
$functionNodes = @($issuerAst.FindAll({
            param($Node)
            $Node -is [Management.Automation.Language.FunctionDefinitionAst]
        }, $false))
Assert-Test (@($functionNodes | Where-Object Name -ceq 'Invoke-ProductionClientSigningResponse').Count -eq 1) `
    'issuer exposes one product entry function'

# Preserve any caller functions with the same names, then load the exact product
# function bodies without executing the script entrypoint.
$loadedFunctions = [Collections.Generic.List[object]]::new()
foreach ($node in $functionNodes) {
    $name = [string]$node.Name
    $existing = Get-Item -LiteralPath ('Function:' + $name) -ErrorAction SilentlyContinue
    $loadedFunctions.Add([pscustomobject]@{
            Name = $name
            Existed = $null -ne $existing
            ScriptBlock = if ($null -eq $existing) { $null } else { $existing.ScriptBlock }
        })
    . ([scriptblock]::Create($node.Extent.Text))
}

$originalStateReplay = & $stateModule {
    (Get-Item Function:Get-ProductionReleaseState).ScriptBlock
}
$originalAuthenticodeEvidence = & $contractsModule {
    (Get-Item Function:Get-ExactPeAuthenticodeEvidence).ScriptBlock
}

& $stateModule {
    function script:Get-ProductionReleaseState {
        param([string]$StateRoot, [string]$StateSchemaPath)
        if ($StateRoot -cne [string]$script:ClientIssuerTestState.StateRoot) {
            throw 'TEST: issuer replayed the wrong StateRoot.'
        }
        $script:ClientIssuerTestStateReplayCalls++
        if ($script:ClientIssuerTestStateReplayMode -ceq 'second-head-change' -and
            $script:ClientIssuerTestStateReplayCalls -eq 2) {
            $script:ClientIssuerTestState.HeadSha256 = '9' * 64
        }
        return $script:ClientIssuerTestState
    }
}

& $contractsModule {
    function script:Get-ExactPeAuthenticodeEvidence {
        param(
            [string]$Path,
            [string]$ExpectedSignerCertificateSha256,
            [string]$ExpectedPeContentSha256 = '')
        if ($ExpectedSignerCertificateSha256 -cne $script:ClientIssuerTestPin) {
            throw 'TEST: Authenticode signer pin mismatch.'
        }
        $script:ClientIssuerTestEvidenceCalls++
        if ($script:ClientIssuerTestEvidenceMode -ceq 'reject') {
            throw 'TEST_AUTHENTICODE_REJECTED'
        }
        if ($script:ClientIssuerTestEvidenceCalls -eq 4) {
            # The response key is intentionally opened only after all signed
            # inputs pass Authenticode admission. At this boundary, assert the
            # request and all four signed-file leases that must already exist.
            foreach ($lockedPath in @($script:ClientIssuerTestRequestPath) +
                @($script:ClientIssuerTestPaths)) {
                $write = $null
                try {
                    $write = [IO.File]::Open(
                        $lockedPath, [IO.FileMode]::Open, [IO.FileAccess]::Write,
                        [IO.FileShare]::ReadWrite)
                }
                catch [IO.IOException] { continue }
                finally { if ($null -ne $write) { $write.Dispose() } }
                throw "TEST: issuer did not retain deny-write lease: $lockedPath"
            }
        }
        $descriptor = ProductionReleaseState\Open-ProductionReleaseInput `
            -Path $Path -Label 'Focused signed PE evidence' -MaximumBytes 512MB
        try {
            $bytes = ProductionReleaseState\Read-ProductionReleaseInputBytes `
                -Descriptor $descriptor -Label 'Focused signed PE evidence'
            $pe = ProductionReleaseState\Get-PeContentSha256 -Bytes $bytes
            if ($pe -cne $ExpectedPeContentSha256) {
                throw 'Signed PE content identity differs from the expected unsigned PE content.'
            }
            $status = if ($script:ClientIssuerTestEvidenceMode -ceq 'status') { 'NotTrusted' } else { 'Valid' }
            return [pscustomobject][ordered]@{
                FileName = $descriptor.FileName
                SizeBytes = $descriptor.SizeBytes
                SignedFileSha256 = $descriptor.Sha256
                PeContentSha256 = $pe
                AuthenticodeStatus = $status
                SignatureType = 'Authenticode'
                PrimarySignerCount = 1
                PrimarySignedCmsSha256 = ('1' * 64)
                SignerCertificateSha256 = $ExpectedSignerCertificateSha256
                SignerDigestAlgorithmOid = '2.16.840.1.101.3.4.2.1'
                SpcIndirectDataContentTypeOid = '1.3.6.1.4.1.311.2.1.4'
                SpcPeImageDataTypeOid = '1.3.6.1.4.1.311.2.1.15'
                SpcDigestAlgorithmOid = '2.16.840.1.101.3.4.2.1'
                SpcPeContentSha256 = $pe
                TimestampProtocol = 'RFC3161'
                TimestampTokenOid = '1.2.840.113549.1.9.16.2.14'
                TimestampContentTypeOid = '1.2.840.113549.1.9.16.1.4'
                TimestampSignerCertificateSha256 = ('2' * 64)
                TimestampUtc = ProductionReleaseState\ConvertTo-ProductionUtc -Value ([DateTimeOffset]::UtcNow.AddMinutes(-1))
                Rfc3161PrimarySignerBound = $true
                LegacyCounterSignaturePresent = $false
            }
        }
        finally { $descriptor.Stream.Dispose() }
    }
}

$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) (
    'production-client-response-' + [Guid]::NewGuid().ToString('N'))
$script:caseNumber = 0
$script:passed = 0

try {
    [void][IO.Directory]::CreateDirectory($fixtureRoot)
    Invoke-TestCase -Name 'enterprise-success' -Edition Enterprise
    Invoke-TestCase -Name 'personal-success' -Edition Personal
    Invoke-TestCase -Name 'stale-head' -ExpectedError 'stale|exact committed|head' -OverrideInvoke {
        param($f)
        Invoke-ProductionClientSigningResponse -StateRoot $f.StateRoot -ExpectedHeadSha256 ('9' * 64) `
            -SignedClientRoot $f.SignedRoot -ResponsePrivateKeyPath $f.KeyPath -OutputRoot $f.OutputRoot
    }
    Invoke-TestCase -Name 'wrong-phase' -ExpectedError 'revision 2|CLIENT_SIGNING_REQUESTED|phase' -Mutate {
        param($f) $f.State.Head.phase = 'PLAN_ADMITTED'
    }
    Invoke-TestCase -Name 'wrong-schema' -ExpectedError 'schema.*2|v2' -Mutate {
        param($f) $f.State.SchemaVersion = 1
    }
    Invoke-TestCase -Name 'orphan-receipt' -ExpectedError 'orphan' -Mutate {
        param($f) $f.State.OrphanReceipt = [pscustomobject]@{ revision = 3 }
    }
    Invoke-TestCase -Name 'wrong-request-nonce' -ExpectedError 'nonce|receipt' -Mutate {
        param($f) $f.Request.nonce = 'X' * 43; Set-TestRequest $f -BindReceiptHash
    }
    Invoke-TestCase -Name 'wrong-request-plan' -ExpectedError 'plan|identity|bound' -Mutate {
        param($f) $f.Request.planSha256 = '9' * 64; Set-TestRequest $f -BindReceiptHash
    }
    Invoke-TestCase -Name 'wrong-request-hash' -ExpectedError 'hash|sha256|receipt' -Mutate {
        param($f) $f.State.Receipts[1].data.requestSha256 = '9' * 64
    }
    Invoke-TestCase -Name 'wrong-request-role' -ExpectedError 'role|receipt|plan' -Mutate {
        param($f) $f.Request.files[0].role = 'other'; Set-TestRequest $f -BindReceiptHash
    }
    Invoke-TestCase -Name 'wrong-request-purpose' -ExpectedError 'schema|subschema|purpose|trust|plan' -Mutate {
        param($f) $f.Request.responseAuthentication.purpose = 'wrong-purpose'; Set-TestRequest $f -BindReceiptHash
    }
    Invoke-TestCase -Name 'request-schema-extra-member' -ExpectedError 'schema|additional|unexpected' -Mutate {
        param($f) $f.Request | Add-Member unexpected 1; Set-TestRequest $f -BindReceiptHash
    }
    Invoke-TestCase -Name 'expired-request' -ExpectedError 'expired|lifetime|expiry|outside' -Mutate {
        param($f)
        $f.Request.expiresAtUtc = ProductionReleaseState\ConvertTo-ProductionUtc -Value ([DateTimeOffset]::UtcNow.AddSeconds(-1))
        $f.State.Receipts[1].data.expiresAtUtc = $f.Request.expiresAtUtc
        Set-TestRequest $f -BindReceiptHash
    }
    Invoke-TestCase -Name 'missing-signed-file' -ExpectedError 'inventory|missing|four' -Mutate {
        param($f) [IO.File]::Delete($f.SignedPaths[3])
    }
    Invoke-TestCase -Name 'extra-signed-file' -ExpectedError 'inventory|unexpected|extra' -Mutate {
        param($f) [IO.File]::WriteAllBytes((Join-Path $f.SignedRoot 'extra.exe'), (New-TestSignedPe (New-TestUnsignedPe 9)))
    }
    Invoke-TestCase -Name 'signed-pe-content-changed' -ExpectedError 'PE content|unsigned' -Mutate {
        param($f) $bytes = [IO.File]::ReadAllBytes($f.SignedPaths[0]); $bytes[500]++; [IO.File]::WriteAllBytes($f.SignedPaths[0], $bytes)
    }
    Invoke-TestCase -Name 'signed-file-unchanged' -ExpectedError 'unchanged|same|signing|size-grown|transformation' -Mutate {
        param($f)
        $name = [string]$f.Request.files[0].fileName
        [IO.File]::WriteAllBytes(
            $f.SignedPaths[0],
            [IO.File]::ReadAllBytes((Join-Path $f.StateRoot ('requests\client-signing.v1\unsigned\' + $name))))
    }
    Invoke-TestCase -Name 'wrong-response-key' -ExpectedError 'key|trust|match' -OverrideInvoke {
        param($f)
        Invoke-ProductionClientSigningResponse -StateRoot $f.StateRoot -ExpectedHeadSha256 $f.State.HeadSha256 `
            -SignedClientRoot $f.SignedRoot -ResponsePrivateKeyPath $f.WrongKeyPath -OutputRoot $f.OutputRoot
    }
    Invoke-TestCase -Name 'trailing-key-bytes' -ExpectedError 'trailing|PKCS8|private key' -Mutate {
        param($f) [IO.File]::WriteAllBytes($f.KeyPath, ([IO.File]::ReadAllBytes($f.KeyPath) + [byte]0))
    }
    Invoke-TestCase -Name 'existing-output' -ExpectedError 'create-only|already exists|output' -Mutate {
        param($f) [void][IO.Directory]::CreateDirectory($f.OutputRoot); [IO.File]::WriteAllText((Join-Path $f.OutputRoot 'sentinel'), 'preserve')
    }
    Invoke-TestCase -Name 'state-output-overlap' -ExpectedError 'overlap|outside|output' -OverrideInvoke {
        param($f)
        Invoke-ProductionClientSigningResponse -StateRoot $f.StateRoot -ExpectedHeadSha256 $f.State.HeadSha256 `
            -SignedClientRoot $f.SignedRoot -ResponsePrivateKeyPath $f.KeyPath `
            -OutputRoot (Join-Path $f.StateRoot 'issuer-output')
    }
    Invoke-TestCase -Name 'signed-output-overlap' -ExpectedError 'overlap|outside|output' -OverrideInvoke {
        param($f)
        Invoke-ProductionClientSigningResponse -StateRoot $f.StateRoot -ExpectedHeadSha256 $f.State.HeadSha256 `
            -SignedClientRoot $f.SignedRoot -ResponsePrivateKeyPath $f.KeyPath `
            -OutputRoot (Join-Path $f.SignedRoot 'issuer-output')
    }
    Invoke-TestCase -Name 'authenticode-rejected' -ExpectedError 'TEST_AUTHENTICODE_REJECTED' -Mutate {
        param($f) Set-EvidenceMode 'reject'
    }
    Invoke-TestCase -Name 'authenticode-status-rejected' -ExpectedError 'Authenticode|Status|Valid|evidence' -Mutate {
        param($f) Set-EvidenceMode 'status'
    }
    Invoke-TestCase -Name 'second-replay-head-change-cleans-stage' -ExpectedError 'state changed|publication' -Mutate {
        param($f) Set-StateReplayMode 'second-head-change'
    }
    Write-Host "PASS: Production client signing response issuer $script:passed focused cases; actual product function, real locks/request/schema/PKCS8/low-S/publication, two explicit seams only. No Authenticode signing claim."
}
finally {
    # Restore exactly the two overridden module functions. Do not remove modules
    # by name: callers may own imports with the same module name.
    & $stateModule {
        param($Original)
        Set-Item Function:script:Get-ProductionReleaseState $Original
        foreach ($name in @(
                'ClientIssuerTestState', 'ClientIssuerTestStateReplayMode',
                'ClientIssuerTestStateReplayCalls')) {
            Remove-Variable $name -Scope Script -ErrorAction SilentlyContinue
        }
    } $originalStateReplay
    & $contractsModule {
        param($Original)
        Set-Item Function:script:Get-ExactPeAuthenticodeEvidence $Original
        foreach ($name in @(
                'ClientIssuerTestPaths', 'ClientIssuerTestRequestPath',
                'ClientIssuerTestKeyPath', 'ClientIssuerTestPin',
                'ClientIssuerTestEvidenceMode', 'ClientIssuerTestEvidenceCalls')) {
            Remove-Variable $name -Scope Script -ErrorAction SilentlyContinue
        }
    } $originalAuthenticodeEvidence
    foreach ($entry in @($loadedFunctions)) {
        if ($entry.Existed) {
            Set-Item -LiteralPath ('Function:' + $entry.Name) -Value $entry.ScriptBlock
        }
        else {
            Remove-Item -LiteralPath ('Function:' + $entry.Name) -ErrorAction SilentlyContinue
        }
    }
    if (Test-Path -LiteralPath $fixtureRoot) {
        $resolved = [IO.Path]::GetFullPath($fixtureRoot)
        $tempBoundary = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd(
            [IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
        if (-not $resolved.StartsWith($tempBoundary, [StringComparison]::OrdinalIgnoreCase) -or
            [IO.Path]::GetFileName($resolved) -notmatch '^production-client-response-[0-9a-f]{32}$') {
            throw 'Unsafe client-response fixture cleanup target.'
        }
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
