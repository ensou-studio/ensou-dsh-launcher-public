#requires -Version 7.2

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$stateModulePath = Join-Path $PSScriptRoot 'ProductionReleaseState.psm1'
$promotionModulePath = Join-Path $PSScriptRoot 'ProductionFeedPromotion.psm1'
$signerPath = Join-Path `
    $PSScriptRoot `
    'New-ProductionFeedPromotionAuthorizationResponse.ps1'
$requestSchemaPath = Join-Path `
    $repositoryRoot `
    'release\schemas\launcher-feed-promotion-request-v1.schema.json'
$headSchemaPath = Join-Path `
    $repositoryRoot `
    'release\schemas\launcher-feed-promotion-state-v1.schema.json'
$responseSchemaPath = Join-Path `
    $repositoryRoot `
    'release\schemas\launcher-feed-promotion-response-v1.schema.json'

Import-Module $promotionModulePath -Force
Import-Module $stateModulePath -Force

$assertions = 0

function Assert-True {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )

    $script:assertions++
    if (-not $Condition) { throw $Message }
}

function Assert-Throws {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Action,
        [Parameter(Mandatory = $true)][string]$Pattern,
        [Parameter(Mandatory = $true)][string]$Message
    )

    $script:assertions++
    try {
        & $Action
    }
    catch {
        if ($_.Exception.Message -notmatch $Pattern) {
            throw "$Message Unexpected error: $($_.Exception.Message)"
        }
        return
    }
    throw $Message
}

function ConvertTo-TestBase64Url {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    return [Convert]::ToBase64String($Bytes).
        TrimEnd('=').
        Replace('+', '-').
        Replace('/', '_')
}

function Write-TestCanonicalJson {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Value
    )

    [IO.File]::WriteAllBytes(
        $Path,
        (ProductionReleaseState\ConvertTo-ProductionJsonBytes -Value $Value))
}

function New-TestRequest {
    param(
        [Parameter(Mandatory = $true)]$PublicKey,
        [Parameter(Mandatory = $true)][string]$CreatedAtUtc,
        [Parameter(Mandatory = $true)][string]$ExpiresAtUtc
    )

    $files = [Collections.Generic.List[object]]::new()
    $roles = @(
        'release-manifest',
        'release-public-key',
        'launcher',
        'runtime',
        'plugin-policy')
    for ($index = 0; $index -lt $roles.Count; $index++) {
        $name = "artifact-$index.bin"
        $files.Add([ordered]@{
            role = $roles[$index]
            fileName = $name
            relativePath = "payload/$name"
            sizeBytes = $index + 1
            sha256 = ([string]($index + 1)) * 64
        })
    }
    return [ordered]@{
        schemaVersion = 1
        requestType = 'ensou-dsh-launcher-offline-feed-promotion-request'
        operationId = [Guid]::NewGuid().ToString('N')
        orchestrationId = [Guid]::NewGuid().ToString('D')
        edition = 'Enterprise'
        exposureRing = 'stable'
        feedChannel = 'stable'
        publishScope = 'public-stable'
        releaseSetId = 'enterprise-v1.2.3'
        sourceState = [ordered]@{
            schemaVersion = 2
            targetChannel = 'stable'
            revision = 8
            phase = 'PILOT_EVIDENCE_BOUND'
            planSizeBytes = 100
            planSha256 = 'a' * 64
            identitySizeBytes = 101
            identitySha256 = 'b' * 64
            headSizeBytes = 102
            headSha256 = 'c' * 64
            receiptChainStartRevision = 1
            receiptChainSha256 = 'd' * 64
            candidateReceiptSha256 = 'e' * 64
        }
        expectedFeedIdentitySha256 = 'f' * 64
        feedCas = [ordered]@{
            channelHead = [ordered]@{ state = 'missing' }
            journalHead = [ordered]@{ state = 'missing' }
        }
        feedCasSha256 = '1' * 64
        payloadSetSha256 = '2' * 64
        files = @($files)
        authorizationTrust = [ordered]@{
            algorithm = 'ES256'
            keyId = 'enterprise-feed-promotion-response-2026'
            purpose = 'feed-promotion-response'
            x = ConvertTo-TestBase64Url -Bytes $PublicKey.Q.X
            y = ConvertTo-TestBase64Url -Bytes $PublicKey.Q.Y
        }
        requestNonce = ConvertTo-TestBase64Url -Bytes ([byte[]](1..32))
        createdAtUtc = $CreatedAtUtc
        expiresAtUtc = $ExpiresAtUtc
        productionAdmission = 'NO_GO'
        networkPublishPerformed = $false
    }
}

function New-TestHead {
    param(
        [Parameter(Mandatory = $true)]$Request,
        [Parameter(Mandatory = $true)][string]$RequestSha256
    )

    return [ordered]@{
        schemaVersion = 1
        stateType = 'ensou-dsh-launcher-offline-feed-promotion-state'
        operationId = [string]$Request.operationId
        requestSha256 = $RequestSha256
        requestNonce = [string]$Request.requestNonce
        sourceStateHeadSha256 = [string]$Request.sourceState.headSha256
        payloadSetSha256 = [string]$Request.payloadSetSha256
        status = 'PROMOTION_REQUEST_READY'
        productionAdmission = 'NO_GO'
        networkPublishPerformed = $false
        updatedAtUtc = [string]$Request.createdAtUtc
    }
}

$fixtureRoot = Join-Path `
    ([IO.Path]::GetTempPath()) `
    ('ensou-feed-promotion-authorization-test-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($fixtureRoot) | Out-Null
$signer = $null
$wrongSigner = $null
try {
    $signer = [Security.Cryptography.ECDsa]::Create(
        [Security.Cryptography.ECCurve+NamedCurves]::nistP256)
    $wrongSigner = [Security.Cryptography.ECDsa]::Create(
        [Security.Cryptography.ECCurve+NamedCurves]::nistP256)
    $keyPath = Join-Path $fixtureRoot 'authorization-key.pk8'
    $wrongKeyPath = Join-Path $fixtureRoot 'wrong-authorization-key.pk8'
    [IO.File]::WriteAllBytes($keyPath, $signer.ExportPkcs8PrivateKey())
    [IO.File]::WriteAllBytes($wrongKeyPath, $wrongSigner.ExportPkcs8PrivateKey())

    $now = [DateTimeOffset]::UtcNow
    $createdAt = $now.AddSeconds(-10).ToString(
        "yyyy-MM-dd'T'HH:mm:ss'Z'",
        [Globalization.CultureInfo]::InvariantCulture)
    $expiresAt = $now.AddMinutes(20).ToString(
        "yyyy-MM-dd'T'HH:mm:ss'Z'",
        [Globalization.CultureInfo]::InvariantCulture)
    $request = New-TestRequest `
        -PublicKey ($signer.ExportParameters($false)) `
        -CreatedAtUtc $createdAt `
        -ExpiresAtUtc $expiresAt
    $requestPath = Join-Path $fixtureRoot 'request.v1.json'
    Write-TestCanonicalJson -Path $requestPath -Value $request
    $requestInput = ProductionReleaseState\Read-StrictProductionJsonFile `
        -Path $requestPath `
        -Label 'Test feed-promotion request' `
        -SchemaPath $requestSchemaPath
    $head = New-TestHead `
        -Request $request `
        -RequestSha256 ([string]$requestInput.Sha256)
    $headPath = Join-Path $fixtureRoot 'head.json'
    Write-TestCanonicalJson -Path $headPath -Value $head
    $outputPath = Join-Path $fixtureRoot 'response.v1.json'

    $result = & $signerPath `
        -RequestPath $requestPath `
        -PromotionHeadPath $headPath `
        -AuthorizationPrivateKeyPath $keyPath `
        -AuthorizationKeyId 'enterprise-feed-promotion-response-2026' `
        -OutputPath $outputPath
    Assert-True `
        ($result.Count -eq 1 -and
         [string]$result.ProductionAdmission -ceq 'OFFLINE_BUNDLE_ONLY' -and
         -not [bool]$result.NetworkPublishPerformed) `
        'Authorization signer did not return the exact offline-only result.'
    Assert-True `
        (Test-Path -LiteralPath $outputPath -PathType Leaf) `
        'Authorization signer did not create its response.'

    $responseInput = ProductionReleaseState\Read-StrictProductionJsonFile `
        -Path $outputPath `
        -Label 'Generated feed-promotion response' `
        -SchemaPath $responseSchemaPath
    [void](ProductionReleaseState\Assert-CanonicalProductionJsonInput `
        -Input $responseInput `
        -Label 'Generated feed-promotion response')
    $headInput = ProductionReleaseState\Read-StrictProductionJsonFile `
        -Path $headPath `
        -Label 'Test feed-promotion head' `
        -SchemaPath $headSchemaPath
    $promotionModule = Get-Module ProductionFeedPromotion
    & $promotionModule {
        param($Response, $Trust, $RequestInput, $HeadInput)

        Assert-FeedPromotionResponseAuthentication `
            -Response $Response.Value `
            -Trust $Trust
        Assert-FeedPromotionResponseBinding `
            -Response $Response.Value `
            -RequestInput $RequestInput `
            -Head ([pscustomobject]@{
                Value = $HeadInput.Value
                Sha256 = [string]$HeadInput.Sha256
            }) `
            -NowUtc ([DateTimeOffset]::UtcNow)
    } $responseInput $request.authorizationTrust $requestInput $headInput
    Assert-True $true `
        'Generated response failed the same verifier used by the import boundary.'
    $signature = [Convert]::FromBase64String(
        ([string]$responseInput.Value.authentication.value).
            Replace('-', '+').Replace('_', '/') + '==')
    ProductionReleaseState\Assert-ProductionEs256P1363LowS `
        -Signature $signature `
        -Label 'Test generated feed-promotion response signature'
    Assert-True $true 'Generated response did not use canonical low-S ES256.'
    Assert-True `
        ([string]$responseInput.Value.requestSha256 -ceq
            [string]$requestInput.Sha256 -and
         [string]$responseInput.Value.basePromotionHeadSha256 -ceq
            [string]$headInput.Sha256) `
        'Generated response omitted the exact request/head byte anchors.'

    $beforeOutputSha256 = [string]$responseInput.Sha256
    Assert-Throws `
        -Action {
            & $signerPath `
                -RequestPath $requestPath `
                -PromotionHeadPath $headPath `
                -AuthorizationPrivateKeyPath $keyPath `
                -AuthorizationKeyId 'enterprise-feed-promotion-response-2026' `
                -OutputPath $outputPath | Out-Null
        } `
        -Pattern 'create-only' `
        -Message 'Authorization signer overwrote an existing response.'
    Assert-True `
        ((Get-FileHash -LiteralPath $outputPath -Algorithm SHA256).Hash.
            ToLowerInvariant() -ceq $beforeOutputSha256) `
        'Rejected output replay changed the committed response bytes.'

    $wrongOutput = Join-Path $fixtureRoot 'wrong-key-response.json'
    Assert-Throws `
        -Action {
            & $signerPath `
                -RequestPath $requestPath `
                -PromotionHeadPath $headPath `
                -AuthorizationPrivateKeyPath $wrongKeyPath `
                -AuthorizationKeyId 'enterprise-feed-promotion-response-2026' `
                -OutputPath $wrongOutput | Out-Null
        } `
        -Pattern 'does not match the request trust anchor' `
        -Message 'A private key outside the request trust anchor signed a response.'
    Assert-True `
        (-not (Test-Path -LiteralPath $wrongOutput)) `
        'Wrong-key rejection created an output file.'

    $wrongHead = $head | ConvertTo-Json -Depth 64 -Compress |
        ConvertFrom-Json -Depth 64 -DateKind String
    $wrongHead.requestSha256 = '9' * 64
    $wrongHeadPath = Join-Path $fixtureRoot 'wrong-head.json'
    Write-TestCanonicalJson -Path $wrongHeadPath -Value $wrongHead
    $wrongHeadOutput = Join-Path $fixtureRoot 'wrong-head-response.json'
    Assert-Throws `
        -Action {
            & $signerPath `
                -RequestPath $requestPath `
                -PromotionHeadPath $wrongHeadPath `
                -AuthorizationPrivateKeyPath $keyPath `
                -AuthorizationKeyId 'enterprise-feed-promotion-response-2026' `
                -OutputPath $wrongHeadOutput | Out-Null
        } `
        -Pattern 'not bound to the exact request bytes' `
        -Message 'A stale promotion CAS head authorized another request.'
    Assert-True `
        (-not (Test-Path -LiteralPath $wrongHeadOutput)) `
        'Stale-head rejection created an output file.'

    $staleCreatedAt = $now.AddHours(-2).ToString(
        "yyyy-MM-dd'T'HH:mm:ss'Z'",
        [Globalization.CultureInfo]::InvariantCulture)
    $staleExpiresAt = $now.AddHours(-1).ToString(
        "yyyy-MM-dd'T'HH:mm:ss'Z'",
        [Globalization.CultureInfo]::InvariantCulture)
    $staleRequest = New-TestRequest `
        -PublicKey ($signer.ExportParameters($false)) `
        -CreatedAtUtc $staleCreatedAt `
        -ExpiresAtUtc $staleExpiresAt
    $staleRequestPath = Join-Path $fixtureRoot 'stale-request.json'
    Write-TestCanonicalJson -Path $staleRequestPath -Value $staleRequest
    $staleRequestInput = ProductionReleaseState\Read-StrictProductionJsonFile `
        -Path $staleRequestPath `
        -Label 'Stale feed-promotion request' `
        -SchemaPath $requestSchemaPath
    $staleHeadPath = Join-Path $fixtureRoot 'stale-head.json'
    Write-TestCanonicalJson `
        -Path $staleHeadPath `
        -Value (New-TestHead `
            -Request $staleRequest `
            -RequestSha256 ([string]$staleRequestInput.Sha256))
    $staleOutput = Join-Path $fixtureRoot 'stale-response.json'
    Assert-Throws `
        -Action {
            & $signerPath `
                -RequestPath $staleRequestPath `
                -PromotionHeadPath $staleHeadPath `
                -AuthorizationPrivateKeyPath $keyPath `
                -AuthorizationKeyId 'enterprise-feed-promotion-response-2026' `
                -OutputPath $staleOutput | Out-Null
        } `
        -Pattern 'expired' `
        -Message 'An expired request received a fresh authorization.'
    Assert-True `
        (-not (Test-Path -LiteralPath $staleOutput)) `
        'Expired-request rejection created an output file.'

    $repositoryOutput = Join-Path `
        $repositoryRoot `
        'feed-promotion-response-must-not-exist.json'
    Assert-Throws `
        -Action {
            & $signerPath `
                -RequestPath $requestPath `
                -PromotionHeadPath $headPath `
                -AuthorizationPrivateKeyPath $keyPath `
                -AuthorizationKeyId 'enterprise-feed-promotion-response-2026' `
                -OutputPath $repositoryOutput | Out-Null
        } `
        -Pattern 'outside the source repository' `
        -Message 'Offline authorization bytes were allowed inside the source repository.'
    Assert-True `
        (-not (Test-Path -LiteralPath $repositoryOutput)) `
        'Repository-bound output rejection created a response.'

    $pendingOutput = Join-Path $fixtureRoot 'pending-response.json'
    $pendingPath = $pendingOutput + '.pending'
    [IO.File]::WriteAllBytes($pendingPath, [byte[]](1, 2, 3))
    $pendingSha256 = (Get-FileHash `
        -LiteralPath $pendingPath `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    Assert-Throws `
        -Action {
            & $signerPath `
                -RequestPath $requestPath `
                -PromotionHeadPath $headPath `
                -AuthorizationPrivateKeyPath $keyPath `
                -AuthorizationKeyId 'enterprise-feed-promotion-response-2026' `
                -OutputPath $pendingOutput | Out-Null
        } `
        -Pattern 'unresolved pending bytes' `
        -Message 'An unresolved signer crash residue was overwritten.'
    Assert-True `
        ((Get-FileHash -LiteralPath $pendingPath -Algorithm SHA256).Hash.
            ToLowerInvariant() -ceq $pendingSha256 -and
         -not (Test-Path -LiteralPath $pendingOutput)) `
        'Pending-residue rejection changed or promoted untrusted bytes.'

    $signerCommand = Get-Command $signerPath
    Assert-True `
        (-not $signerCommand.Parameters.ContainsKey('NowUtc')) `
        'Production authorization signer exposes a caller-controlled clock.'
    $signerText = [IO.File]::ReadAllText($signerPath)
    foreach ($forbidden in @(
            'Invoke-WebRequest',
            'Invoke-RestMethod',
            'HttpClient',
            'Start-BitsTransfer',
            'curl.exe',
            'wget.exe')) {
        Assert-True `
            ($signerText.IndexOf(
                    $forbidden,
                    [StringComparison]::OrdinalIgnoreCase) -lt 0) `
            "Offline authorization signer contains network primitive '$forbidden'."
    }

    "Production feed-promotion authorization response tests passed ($assertions assertions)."
}
finally {
    if ($null -ne $signer) { $signer.Dispose() }
    if ($null -ne $wrongSigner) { $wrongSigner.Dispose() }
    if (Test-Path -LiteralPath $fixtureRoot) {
        Remove-Item -LiteralPath $fixtureRoot -Recurse -Force
    }
}
