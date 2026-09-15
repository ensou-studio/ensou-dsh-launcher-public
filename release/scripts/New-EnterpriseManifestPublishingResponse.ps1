#requires -Version 7.2
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$StateRoot,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$ExpectedHeadSha256,
    [Parameter(Mandatory)][string]$CandidateRoot,
    [Parameter(Mandatory)][string]$PublisherVerifierPath,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$ExpectedPublisherVerifierSha256,
    [Parameter(Mandatory)][string]$ResponsePrivateKeyPath,
    [Parameter(Mandatory)][string]$OutputRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$schemaRoot = Join-Path $repositoryRoot 'release\schemas'
$stateSchemaPath = Join-Path $schemaRoot 'launcher-production-release-state-v2.schema.json'
$requestSchemaPath = Join-Path $schemaRoot 'launcher-manifest-publishing-request-v1.schema.json'
$responseSchemaPath = Join-Path $schemaRoot 'launcher-manifest-publishing-response-v1.schema.json'
Microsoft.PowerShell.Core\Import-Module (Join-Path $PSScriptRoot 'ProductionReleaseState.psm1') -Force

$p256Order = [byte[]](
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
    0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51)
$p256HalfOrder = [byte[]](
    0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00,
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42,
    0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8)

function ConvertTo-Base64Url([byte[]]$Bytes) {
    return [Convert]::ToBase64String($Bytes).
        TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Compare-Unsigned([byte[]]$A, [byte[]]$B) {
    for ($i = 0; $i -lt $A.Length; $i++) {
        if ($A[$i] -lt $B[$i]) {
            return -1
        }
        if ($A[$i] -gt $B[$i]) {
            return 1
        }
    }
    return 0
}

function ConvertTo-LowS([byte[]]$Signature) {
    if ($Signature.Length -ne 64) {
        throw 'Manifest-publishing response must use a 64-byte P1363 signature.'
    }
    $r = [byte[]]::new(32)
    $s = [byte[]]::new(32)
    [Array]::Copy($Signature, 0, $r, 0, 32)
    [Array]::Copy($Signature, 32, $s, 0, 32)
    if ((Compare-Unsigned $s $p256HalfOrder) -gt 0) {
        $borrow = 0
        $normalizedS = [byte[]]::new(32)
        for ($i = 31; $i -ge 0; $i--) {
            $value = [int]$p256Order[$i] - [int]$s[$i] - $borrow
            if ($value -lt 0) {
                $value += 256
                $borrow = 1
            }
            else {
                $borrow = 0
            }
            $normalizedS[$i] = [byte]$value
        }
        $s = $normalizedS
    }
    $normalized = [byte[]]::new(64)
    [Array]::Copy($r, 0, $normalized, 0, 32)
    [Array]::Copy($s, 0, $normalized, 32, 32)
    ProductionReleaseState\Assert-ProductionEs256P1363LowS -Signature $normalized -Label 'Manifest-publishing response signature'
    return ,$normalized
}
function Get-ExternalPath([string]$Path, [string]$Label, [switch]$MustExist) {
    if (-not [IO.Path]::IsPathFullyQualified($Path) -or
        $Path.StartsWith('\\') -or
        $Path.StartsWith('//')) {
        throw "$Label must be an absolute local path."
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
    if ($MustExist -and -not (Test-Path -LiteralPath $full)) {
        throw "$Label does not exist."
    }
    return $full
}

function Test-IsSameOrChildPath([string]$Path, [string]$Root) {
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

function Open-LockedJson([string]$Path, [string]$Label, [string]$Schema) {
    $descriptor = ProductionReleaseState\Open-ProductionReleaseInput `
        -Path $Path -Label $Label -MaximumBytes 4MB
    try {
        $bytes = ProductionReleaseState\Read-ProductionReleaseInputBytes `
            -Descriptor $descriptor -Label $Label
        $value = ProductionReleaseState\ConvertFrom-StrictProductionJsonBytes `
            -Bytes $bytes -Label $Label -SchemaPath $Schema
        $descriptor | Add-Member Bytes $bytes
        $descriptor | Add-Member Value $value
        [void](ProductionReleaseState\Assert-CanonicalProductionJsonInput `
            -Input $descriptor -Label $Label)
        return $descriptor
    }
    catch {
        $descriptor.Stream.Dispose()
        throw
    }
}

function Invoke-PinnedVerifier([string]$Exe, [string[]]$Arguments) {
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $Exe
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in $Arguments) {
        [void]$startInfo.ArgumentList.Add($argument)
    }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) {
            throw 'Approved Publisher verifier did not start.'
        }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(60000)) {
            try {
                $process.Kill($true)
            }
            catch {}
            [void]$process.WaitForExit()
            throw 'Approved Publisher verifier exceeded its 60-second bound.'
        }
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        $exitCode = $process.ExitCode
        if ($exitCode -ne 0 -or -not [string]::IsNullOrWhiteSpace($stderr)) {
            throw 'Approved Publisher verifier rejected the runtime source-admission proof.'
        }
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes(
            $stdout.TrimEnd("`r", "`n"))
        return ProductionReleaseState\ConvertFrom-StrictProductionJsonBytes `
            -Bytes $bytes -Label 'Approved Publisher verifier output'
    }
    finally {
        $process.Dispose()
    }
}

function Invoke-EnterpriseManifestPublishingResponse {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$StateRoot,
        [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$ExpectedHeadSha256,
        [Parameter(Mandatory)][string]$CandidateRoot,
        [Parameter(Mandatory)][string]$PublisherVerifierPath,
        [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$ExpectedPublisherVerifierSha256,
        [Parameter(Mandatory)][string]$ResponsePrivateKeyPath,
        [Parameter(Mandatory)][string]$OutputRoot
    )
    $stateLock = $null
    $outputParentLease = $null
    $requestInput = $null
    $sourceReceiptInput = $null
    $runtimePayloadInputs = [Collections.Generic.List[object]]::new()
    $verifierInput = $null
    $keyInput = $null
    $candidateInputs = [Collections.Generic.List[object]]::new()
    $keyBytes = $null
    $signer = $null
    $stage = $null

    try {
        if (-not [IO.Path]::IsPathFullyQualified($StateRoot) -or
            -not [IO.Path]::IsPathFullyQualified($CandidateRoot)) {
            throw 'Production state root and signed candidate root must be absolute local paths.'
        }
        $stateRoot = [IO.Path]::GetFullPath($StateRoot)
        $candidateRoot = [IO.Path]::GetFullPath($CandidateRoot)
        if (-not (Test-Path -LiteralPath $stateRoot -PathType Container) -or
            -not (Test-Path -LiteralPath $candidateRoot -PathType Container)) {
            throw 'Production state root and signed candidate root must exist.'
        }
        $candidateItem = Get-Item -LiteralPath $candidateRoot -Force -ErrorAction Stop
        if (($candidateItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Signed candidate root must be an ordinary directory.'
        }
        $verifierPath = Get-ExternalPath `
            $PublisherVerifierPath 'Approved Publisher verifier' -MustExist
        $keyPath = Get-ExternalPath `
            $ResponsePrivateKeyPath 'Manifest-publishing private key' -MustExist
        $outputRoot = Get-ExternalPath `
            $OutputRoot 'Manifest-publishing response output'
        if (Test-Path -LiteralPath $outputRoot) {
            throw 'Manifest-publishing response output is create-only and already exists.'
        }
        if ((Test-IsSameOrChildPath $outputRoot $stateRoot) -or
            (Test-IsSameOrChildPath $outputRoot $candidateRoot)) {
            throw 'Manifest-publishing response output must be separate from state and candidate inputs.'
        }
        $parent = [IO.Path]::GetDirectoryName($outputRoot)
        $parentItem = Get-Item -LiteralPath $parent -Force -ErrorAction Stop
        if (-not $parentItem.PSIsContainer -or
            ($parentItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Manifest-publishing response output parent must be an ordinary directory.'
        }
        for ($ancestor = $parentItem; $null -ne $ancestor; $ancestor = $ancestor.Parent) {
            if (($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'Manifest-publishing response output parent crosses a filesystem link.'
            }
        }
        $outputParentLease = ProductionReleaseState\Open-ProductionReleaseDirectoryLease `
            -Path $parent -Label 'Manifest-publishing response output parent'
        $stateLock = ProductionReleaseState\Enter-ProductionReleaseStateReadLock `
            -StateRoot $stateRoot
        $state = ProductionReleaseState\Get-ProductionReleaseState `
            -StateRoot $stateRoot -StateSchemaPath $stateSchemaPath
        $contract = ProductionReleaseState\Get-ProductionManifestChannelContract `
            -TargetChannel 'stable'
        if ([int]$state.SchemaVersion -ne 2 -or
            [string]$state.Plan.edition -cne 'Enterprise' -or
            [string]$state.TargetChannel -cne 'stable' -or
            $null -eq $state.Head -or
            [int]$state.Head.revision -ne 4 -or
            [string]$state.Head.phase -cne [string]$contract.RequestPhase -or
            [string]$state.HeadSha256 -cne $ExpectedHeadSha256) {
            throw 'NO-GO: issuer requires the exact committed Enterprise Stable manifest-publishing r4 head.'
        }
        $requestPath = Join-Path `
            (Join-Path (Join-Path $stateRoot 'requests') $contract.RequestBundleName) `
            'manifest-publishing-request.v1.json'
        $requestInput = Open-LockedJson `
            $requestPath 'Committed manifest-publishing r4 request' $requestSchemaPath
        $request = $requestInput.Value
        if ([string]$request.planSha256 -cne [string]$state.Identity.planSha256 -or
            [string]$state.Receipts[3].data.requestSha256 -cne [string]$requestInput.Sha256 -or
            [string]$state.Receipts[3].data.baseHeadSha256 -cne [string]$request.baseHeadSha256) {
            throw 'Committed r4 request is not bound to its admitted state history.'
        }
        ProductionReleaseState\Assert-ProductionRuntimeSourceReleaseExpectation `
            -Plan $state.Plan -Value $request
        $expectation = ProductionReleaseState\Get-ProductionRuntimeSourceReleaseExpectation `
            -Plan $state.Plan
        if ($null -eq $expectation) {
            throw 'NO-GO: historical unanchored plans cannot issue source-admitted responses.'
        }
        $requiredPayloadRoles = @(
            'runtime-archive',
            'runtime-metadata',
            'runtime-hash-evidence',
            'edition-runtime-organization-admission'
        )
        $payloadByRole = @{}
        foreach ($role in $requiredPayloadRoles) {
            $matches = @($request.publisherInput.files | Where-Object {
                [string]$_.role -ceq $role
            })
            if ($matches.Count -ne 1 -or
                [string]$matches[0].relativePath -cne ('payload/' + [string]$matches[0].fileName)) {
                throw "NO-GO: r4 request lacks its exact '$role' payload descriptor."
            }
            $payloadByRole[$role] = $matches[0]
        }
        $receiptFile = @($payloadByRole['edition-runtime-organization-admission'])
        $receiptPath = Join-Path `
            (Join-Path `
                (Join-Path `
                    (Join-Path $stateRoot 'requests') `
                    $contract.RequestBundleName) `
                'payload') `
            ([string]$receiptFile[0].fileName)
        $verifierInput = ProductionReleaseState\Open-ProductionReleaseInput `
            -Path $verifierPath -Label 'Approved Publisher verifier' -MaximumBytes 256MB
        if ([string]$verifierInput.Sha256 -cne $ExpectedPublisherVerifierSha256) {
            throw 'Approved Publisher verifier digest does not match the operator-pinned prerequisite.'
        }
        $payloadRoot = Join-Path `
            (Join-Path `
                (Join-Path $stateRoot 'requests') $contract.RequestBundleName) `
            'payload'
        foreach ($role in @('runtime-archive', 'runtime-metadata', 'runtime-hash-evidence')) {
            $file = $payloadByRole[$role]
            $maximumBytes = if ($role -ceq 'runtime-archive') { 8GB } else { 4MB }
            $input = ProductionReleaseState\Open-ProductionReleaseInput `
                -Path (Join-Path $payloadRoot ([string]$file.fileName)) `
                -Label "State-owned r4 $role" -MaximumBytes $maximumBytes
            if ([long]$input.SizeBytes -ne [long]$file.sizeBytes -or
                [string]$input.Sha256 -cne [string]$file.sha256) {
                $input.Stream.Dispose()
                throw "State-owned r4 $role differs from its descriptor."
            }
            $runtimePayloadInputs.Add($input)
        }
        $sourceReceiptInput = ProductionReleaseState\Open-ProductionReleaseInput `
            -Path $receiptPath `
            -Label 'State-owned runtime organization receipt' `
            -MaximumBytes 4MB
        [byte[]]$receiptBytes = ProductionReleaseState\Read-ProductionReleaseInputBytes `
            -Descriptor $sourceReceiptInput `
            -Label 'State-owned runtime organization receipt'
        if ([long]$sourceReceiptInput.SizeBytes -ne [long]$receiptFile[0].sizeBytes -or
            [string]$sourceReceiptInput.Sha256 -cne [string]$receiptFile[0].sha256) {
            throw 'Runtime organization receipt changed from r4 descriptor.'
        }
        $proof = Invoke-PinnedVerifier $verifierPath @(
            '--verify-runtime-source-admission',
            '--archive', $runtimePayloadInputs[0].Path,
            '--metadata', $runtimePayloadInputs[1].Path,
            '--hash-evidence', $runtimePayloadInputs[2].Path,
            '--receipt', $receiptPath,
            '--repository', [string]$expectation.repository,
            '--tag', [string]$expectation.tagName,
            '--build-commit', [string]$expectation.targetCommit
        )
        ProductionReleaseState\Assert-ExactProductionJsonMembers `
            -Value $proof `
            -Expected @('receiptSha256', 'sourceRelease') `
            -Label 'Approved Publisher verifier output'
        $admission = [ordered]@{
            receiptSha256 = [string]$proof.receiptSha256
            sourceRelease = $proof.sourceRelease
        }
        [void](ProductionReleaseState\Assert-ProductionRuntimeSourceReleaseAdmission `
            -Admission ([pscustomobject]$admission) `
            -Plan $state.Plan `
            -OrganizationAdmissionReceiptInput ([pscustomobject]@{
                Bytes = $receiptBytes
                Sha256 = [string]$sourceReceiptInput.Sha256
            }))
        $manifestPath = Join-Path $candidateRoot 'release-set.v2.json'
        $manifestInput = Open-LockedJson `
            $manifestPath `
            'Signed Enterprise release manifest candidate' `
            (Join-Path $schemaRoot 'enterprise-release-set-v2.schema.json')
        $candidateInputs.Add($manifestInput)
        $files = [Collections.Generic.List[object]]::new()
        $manifest = $manifestInput.Value
        $names = @('release-set.v2.json', 'release-public-key.v2.json') + @(
            $manifest.artifacts | ForEach-Object {
                [IO.Path]::GetFileName(([Uri]$_.uri).AbsolutePath)
            }
        )
    $candidateNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($name in $names) {
        if (-not $candidateNames.Add($name)) { throw 'Signed candidate repeats a filename.' }
    }
    $candidateEntries = @(Get-ChildItem -LiteralPath $candidateRoot -Force)
    if ($candidateEntries.Count -ne $candidateNames.Count) { throw 'Signed candidate has an unexpected file inventory.' }
    foreach ($entry in $candidateEntries) {
        if ($entry.PSIsContainer -or ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            -not $candidateNames.Contains($entry.Name)) {
            throw 'Signed candidate has an unexpected file, directory or linked entry.'
        }
    }
        foreach ($name in $names) {
            $descriptor = if ($name -ceq 'release-set.v2.json') {
                $manifestInput
            }
            else {
                ProductionReleaseState\Open-ProductionReleaseInput `
                    -Path (Join-Path $candidateRoot $name) `
                    -Label "Signed candidate '$name'" `
                    -MaximumBytes 8GB
            }
            if ($descriptor -ne $manifestInput) {
                $candidateInputs.Add($descriptor)
            }
            $role = if ($name -ceq 'release-set.v2.json') {
                'release-manifest'
            }
            elseif ($name -ceq 'release-public-key.v2.json') {
                'release-public-key'
            }
            else {
                [string](@($manifest.artifacts | Where-Object {
                    [IO.Path]::GetFileName(([Uri]$_.uri).AbsolutePath) -ceq $name
                })[0].component)
            }
            $files.Add([ordered]@{
                role = $role
                fileName = $name
                relativePath = 'candidate/' + $name
                sizeBytes = [int64]$descriptor.SizeBytes
                sha256 = [string]$descriptor.Sha256
            })
        }
        $now = [DateTimeOffset]::UtcNow
        $created = ProductionReleaseState\ConvertFrom-ProductionUtc `
            -Value ([string]$request.createdAtUtc) -Label 'r4 request creation'
        $expires = ProductionReleaseState\ConvertFrom-ProductionUtc `
            -Value ([string]$request.expiresAtUtc) -Label 'r4 request expiry'
        if ($now -lt $created -or $now -gt $expires) {
            throw 'Manifest-publishing r4 request is outside its lifetime.'
        }
        [void]@(ProductionReleaseState\Assert-ProductionReleaseManifestCandidate `
            -Plan $state.Plan `
            -ManifestInput $manifestInput `
            -CandidateRoot $candidateRoot `
            -Files @($files) `
            -ComponentReleaseIds $request.componentReleaseIds `
            -RuntimeProvenance $request.runtimeProvenance `
            -ValidationTimeUtc $now)
    $keyInput = ProductionReleaseState\Open-ProductionReleaseInput `
        -Path $keyPath -Label 'Manifest-publishing private key' -MaximumBytes 64KB
    [byte[]]$keyBytes = ProductionReleaseState\Read-ProductionReleaseInputBytes `
        -Descriptor $keyInput -Label 'Manifest-publishing private key'
    $signer = [Security.Cryptography.ECDsa]::Create()
    $used = 0
    $signer.ImportPkcs8PrivateKey($keyBytes, [ref]$used)
    if ($used -ne $keyBytes.Length) { throw 'Manifest-publishing private key has trailing bytes.' }
    $pub = $signer.ExportParameters($false)
    $responseTrust = $state.Plan.externalResponseTrusts.manifestPublishing
    if ((ConvertTo-Base64Url $pub.Q.X) -cne [string]$responseTrust.x -or
        (ConvertTo-Base64Url $pub.Q.Y) -cne [string]$responseTrust.y) {
        throw 'Manifest-publishing private key does not match plan response trust.'
    }
        $response = [ordered]@{
            schemaVersion = 1
            responseType = [string]$contract.ResponseType
            orchestrationId = [string]$request.orchestrationId
            edition = 'Enterprise'
            releaseSetId = [string]$request.releaseSetId
            channel = 'stable'
            planSha256 = [string]$request.planSha256
            requestSha256 = [string]$requestInput.Sha256
            requestNonce = [string]$request.requestNonce
            baseHeadSha256 = [string]$request.baseHeadSha256
            admissionHeadSha256 = $ExpectedHeadSha256
            admissionRevision = 4
            requestExpiresAtUtc = [string]$request.expiresAtUtc
            completedAtUtc = ProductionReleaseState\ConvertTo-ProductionUtc -Value $now
            files = @($files)
            authentication = [ordered]@{
                algorithm = 'ES256'
                keyId = [string]$request.responseAuthentication.keyId
                purpose = 'manifest-publishing-response'
                payloadType = 'ensou-dsh-launcher-manifest-publishing-response-authentication-v1'
            }
            runtimeSourceReleaseAdmission = $admission
        }
        $payload = ProductionReleaseState\Get-ProductionReleaseManifestPublishingResponseAuthenticationPayload `
            -Response ([pscustomobject]$response)
        $signature = ConvertTo-LowS ($signer.SignData(
            $payload,
            [Security.Cryptography.HashAlgorithmName]::SHA256,
            [Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation))
        if (-not $signer.VerifyData(
                $payload,
                $signature,
                [Security.Cryptography.HashAlgorithmName]::SHA256,
                [Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)) {
            throw 'Manifest-publishing response signature self-check failed.'
        }
        $response.authentication.value = ConvertTo-Base64Url $signature
        $responseBytes = ProductionReleaseState\ConvertTo-ProductionJsonBytes -Value $response
        $parsedResponse = ProductionReleaseState\ConvertFrom-StrictProductionJsonBytes `
            -Bytes $responseBytes `
            -Label 'Generated manifest-publishing response' `
            -SchemaPath $responseSchemaPath
        ProductionReleaseState\Assert-ProductionReleaseManifestPublishingResponseAuthentication `
            -Response $parsedResponse -Trust $responseTrust

        foreach ($input in $candidateInputs) {
            ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
                -Descriptor $input -Label 'Signed candidate input'
        }
        foreach ($input in $runtimePayloadInputs) {
            ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
                -Descriptor $input -Label 'State-owned r4 runtime payload'
        }
        ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
            -Descriptor $requestInput -Label 'Committed manifest-publishing r4 request'
        ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
            -Descriptor $sourceReceiptInput -Label 'State-owned runtime organization receipt'
        ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
            -Descriptor $verifierInput -Label 'Approved Publisher verifier'
        ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
            -Descriptor $keyInput -Label 'Manifest-publishing private key'
        if ([DateTimeOffset]::UtcNow -gt $expires) {
            throw 'Manifest-publishing r4 request expired before response publication.'
        }
        ProductionReleaseState\Assert-ProductionReleaseDirectoryStillLocked `
            -Descriptor $outputParentLease `
            -Label 'Manifest-publishing response output parent'

        $stage = $outputRoot + '.pending-' + [Guid]::NewGuid().ToString('N')
        [IO.Directory]::CreateDirectory((Join-Path $stage 'candidate')) | Out-Null
        [IO.File]::WriteAllBytes(
            (Join-Path $stage 'manifest-publishing-response.v1.json'),
            $responseBytes)
        foreach ($input in $candidateInputs) {
            [IO.File]::Copy(
                $input.Path,
                (Join-Path (Join-Path $stage 'candidate') $input.FileName),
                $false)
        }
        ProductionReleaseState\Assert-ProductionReleaseDirectoryStillLocked `
            -Descriptor $outputParentLease `
            -Label 'Manifest-publishing response output parent'
        $outputVolume = $outputParentLease.VolumeSerialNumber
        $outputIndex = $outputParentLease.FileIndex
        $outputParentLease.Handle.Dispose()
        $outputParentLease = $null
        [IO.Directory]::Move($stage, $outputRoot)
        $stage = $null
        $outputParentLease = ProductionReleaseState\Open-ProductionReleaseDirectoryLease `
            -Path $parent -Label 'Manifest-publishing response output parent'
        if ($outputParentLease.VolumeSerialNumber -ne $outputVolume -or
            $outputParentLease.FileIndex -ne $outputIndex) {
            throw 'Manifest-publishing response output parent changed during publication.'
        }
        [pscustomobject]@{
            OutputRoot = $outputRoot
            ResponseSha256 = ProductionReleaseState\Get-ProductionSha256Bytes `
                -Bytes $responseBytes
            AdmissionHeadSha256 = $ExpectedHeadSha256
            NetworkPublishPerformed = $false
        }
    }
    finally {
        if ($null -ne $keyBytes) {
            [Array]::Clear($keyBytes, 0, $keyBytes.Length)
        }
        if ($null -ne $signer) {
            $signer.Dispose()
        }
        if ($null -ne $stage -and (Test-Path -LiteralPath $stage)) {
            Remove-Item -LiteralPath $stage -Recurse -Force
        }
        for ($index = $candidateInputs.Count - 1; $index -ge 0; $index--) {
            $candidateInputs[$index].Stream.Dispose()
        }
        for ($index = $runtimePayloadInputs.Count - 1; $index -ge 0; $index--) {
            $runtimePayloadInputs[$index].Stream.Dispose()
        }
        foreach ($input in @($keyInput, $verifierInput, $sourceReceiptInput, $requestInput)) {
            if ($null -ne $input) {
                $input.Stream.Dispose()
            }
        }
        if ($null -ne $outputParentLease) {
            $outputParentLease.Handle.Dispose()
        }
        if ($null -ne $stateLock) {
            $stateLock.Stream.Dispose()
        }
    }
}

Invoke-EnterpriseManifestPublishingResponse @PSBoundParameters
