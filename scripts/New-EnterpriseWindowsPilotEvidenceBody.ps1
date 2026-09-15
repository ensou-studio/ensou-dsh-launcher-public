[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$CollectionPath,
    [Parameter(Mandatory = $true)][string]$BodyPath,
    [Parameter(Mandatory = $true)][string]$AttestationRequestPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($PSVersionTable.PSEdition -ne 'Core' -or $PSVersionTable.PSVersion -lt [version]'7.4') {
    throw 'Enterprise Windows Pilot evidence collection requires PowerShell 7.4 or newer.'
}
if (-not $IsWindows -or
    [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -ne
        [Runtime.InteropServices.Architecture]::X64) {
    throw 'Enterprise Windows Pilot evidence collection requires native Windows x64.'
}

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$collectionSchemaPath = Join-Path $repositoryRoot 'release\schemas\enterprise-windows-pilot-evidence-collection-v1.schema.json'
$bodySchemaPath = Join-Path $repositoryRoot 'release\schemas\enterprise-windows-pilot-evidence-body-v2.schema.json'
$gateSchemaPath = Join-Path $repositoryRoot 'release\schemas\enterprise-windows-pilot-gate-receipt-v2.schema.json'
$gateContractPath = Join-Path $repositoryRoot 'release\enterprise-windows-pilot-gate-contract-v2.json'
$gateContractSchemaPath = Join-Path $repositoryRoot 'release\schemas\enterprise-windows-pilot-gate-contract-v2.schema.json'
$requestSchemaPath = Join-Path $repositoryRoot 'release\schemas\enterprise-windows-pilot-attestation-request-v1.schema.json'
$releaseSchemaPath = Join-Path $repositoryRoot 'release\schemas\enterprise-release-set-v2.schema.json'
$readinessConfigSchemaPath = Join-Path $repositoryRoot 'release\schemas\enterprise-pilot-readiness-v1.schema.json'
$readinessReportSchemaPath = Join-Path $repositoryRoot 'release\schemas\enterprise-pilot-readiness-report-v1.schema.json'
$expectedGateContractCanonicalSha256 = 'a7fff40aad6690d12042d62ba1a8deb80e36431abdd62bc4874fa04388d26331'
. (Join-Path $PSScriptRoot 'EnterpriseWindowsPilotPathGuard.ps1')

$requiredExecutableNames = [ordered]@{
    'release-publisher' = 'Ensou.Dsh.Enterprise.ReleasePublisher.exe'
    'installer' = 'Ensou.Dsh.Enterprise.Installer.exe'
    'bootstrapper' = 'Ensou.Dsh.Enterprise.Bootstrapper.exe'
    'launcher' = 'Ensou.Dsh.Enterprise.Launcher.exe'
    'client-bootstrapper' = 'Ensou.Dsh.Enterprise.ClientBootstrapper.exe'
    'maintenance' = 'Ensou.Dsh.Enterprise.Maintenance.exe'
}

$locks = [Collections.Generic.List[IDisposable]]::new()
$snapshots = @{}
$directoryGuards = @{}

function Get-Sha256Bytes {
    param([byte[]]$Bytes)
    [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Bytes)).ToLowerInvariant()
}

function ConvertTo-Base64Url {
    param([byte[]]$Bytes)
    [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Open-VerifiedDirectoryGuard {
    param([string]$Path)
    Initialize-EnterpriseWindowsPilotPathGuard
    if (-not [IO.Path]::IsPathFullyQualified($Path)) {
        throw 'Pilot collector directory path must be absolute.'
    }
    $resolved = [IO.Path]::TrimEndingDirectorySeparator([IO.Path]::GetFullPath($Path))
    if ($directoryGuards.ContainsKey($resolved)) { return $directoryGuards[$resolved] }
    $guard = [Ensou.Dsh.PilotEvidence.PathGuard]::OpenDirectory($resolved)
    $directoryGuards[$resolved] = $guard
    $locks.Add($guard)
    $guard
}

function Assert-DirectoryGuardPathIdentity {
    param([string]$Path)
    Initialize-EnterpriseWindowsPilotPathGuard
    $resolved = [IO.Path]::TrimEndingDirectorySeparator([IO.Path]::GetFullPath($Path))
    if (-not $directoryGuards.ContainsKey($resolved)) {
        throw 'Pilot collector directory has no locked identity.'
    }
    $guard = $directoryGuards[$resolved]
    [Ensou.Dsh.PilotEvidence.PathGuard]::AssertDirectoryIdentity(
        $resolved,
        [string]$guard.FinalPath,
        [string]$guard.Identity)
}

function Resolve-CreateOnlyPath {
    param([string]$Path)
    if (-not [IO.Path]::IsPathFullyQualified($Path)) {
        throw 'Pilot collector output path must be absolute.'
    }
    $resolved = [IO.Path]::GetFullPath($Path)
    $parent = Split-Path -Parent $resolved
    $leaf = Split-Path -Leaf $resolved
    if ([string]::IsNullOrWhiteSpace($leaf)) {
        throw 'Pilot collector output path must name a file.'
    }
    $parentGuard = Open-VerifiedDirectoryGuard $parent
    $canonical = [IO.Path]::Combine([string]$parentGuard.FinalPath, $leaf)
    if (Test-Path -LiteralPath $canonical) {
        throw 'Pilot collector output must be a new create-only file.'
    }
    $canonical
}

function Open-LockedSnapshot {
    param([string]$Path, [long]$MaximumBytes, [switch]$IncludeBytes)
    if (-not [IO.Path]::IsPathFullyQualified($Path)) {
        throw 'Pilot collector input path must be absolute.'
    }
    $resolved = [IO.Path]::GetFullPath($Path)
    if ($snapshots.ContainsKey($resolved)) { return $snapshots[$resolved] }
    Open-VerifiedDirectoryGuard (Split-Path -Parent $resolved) | Out-Null
    Initialize-EnterpriseWindowsPilotPathGuard
    $opened = [Ensou.Dsh.PilotEvidence.PathGuard]::OpenReadFile($resolved)
    $stream = $opened.Stream
    try {
        if ($stream.Length -le 0 -or $stream.Length -gt $MaximumBytes) {
            throw "Pilot collector input size is invalid: $resolved"
        }
        $length = $stream.Length
        if ($IncludeBytes) {
            if ($length -gt [int]::MaxValue) {
                throw "Pilot collector JSON input is too large: $resolved"
            }
            $bytes = [byte[]]::new([int]$length)
            $offset = 0
            while ($offset -lt $bytes.Length) {
                $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
                if ($read -eq 0) { throw "Pilot collector input ended early: $resolved" }
                $offset += $read
            }
            $sha256 = Get-Sha256Bytes $bytes
        }
        else {
            $hasher = [Security.Cryptography.SHA256]::Create()
            try { $sha256 = [Convert]::ToHexString($hasher.ComputeHash($stream)).ToLowerInvariant() }
            finally { $hasher.Dispose() }
            $bytes = $null
        }
        if ($stream.Length -ne $length) {
            throw "Pilot collector input length changed while locked: $resolved"
        }
        $stream.Position = 0
        $snapshot = [pscustomobject]@{
            Path = $opened.FinalPath
            Identity = $opened.Identity
            Length = $length
            Sha256 = $sha256
            Bytes = $bytes
        }
        $snapshots[$resolved] = $snapshot
        $locks.Add($opened)
        $snapshot
    }
    catch {
        $opened.Dispose()
        throw
    }
}

function Assert-SnapshotPathIdentity {
    param($Snapshot)
    Initialize-EnterpriseWindowsPilotPathGuard
    [Ensou.Dsh.PilotEvidence.PathGuard]::AssertFileIdentity(
        [string]$Snapshot.Path,
        [string]$Snapshot.Path,
        [string]$Snapshot.Identity)
}

function Get-FileReference {
    param([string]$Path, [long]$MaximumBytes, [switch]$IncludeBytes)
    $snapshot = Open-LockedSnapshot $Path $MaximumBytes -IncludeBytes:$IncludeBytes
    [ordered]@{
        path = [string]$snapshot.Path
        sizeBytes = [long]$snapshot.Length
        sha256 = [string]$snapshot.Sha256
    }
}

function Assert-NoDuplicateMembers {
    param([Text.Json.JsonElement]$Element, [string]$Label)
    if ($Element.ValueKind -eq [Text.Json.JsonValueKind]::Object) {
        $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($property in $Element.EnumerateObject()) {
            if (-not $names.Add($property.Name)) { throw "$Label contains a duplicate JSON member." }
            Assert-NoDuplicateMembers $property.Value $Label
        }
    }
    elseif ($Element.ValueKind -eq [Text.Json.JsonValueKind]::Array) {
        foreach ($entry in $Element.EnumerateArray()) {
            Assert-NoDuplicateMembers $entry $Label
        }
    }
}

function ConvertFrom-StrictJsonElement {
    param([Text.Json.JsonElement]$Element)
    switch ($Element.ValueKind) {
        ([Text.Json.JsonValueKind]::Object) {
            $result = [ordered]@{}
            foreach ($property in $Element.EnumerateObject()) {
                $result[$property.Name] = ConvertFrom-StrictJsonElement $property.Value
            }
            return $result
        }
        ([Text.Json.JsonValueKind]::Array) {
            $items = [Collections.Generic.List[object]]::new()
            foreach ($entry in $Element.EnumerateArray()) {
                $items.Add((ConvertFrom-StrictJsonElement $entry))
            }
            return ,$items.ToArray()
        }
        ([Text.Json.JsonValueKind]::String) { return $Element.GetString() }
        ([Text.Json.JsonValueKind]::Number) {
            [long]$integer = 0
            if ($Element.TryGetInt64([ref]$integer)) { return $integer }
            [decimal]$decimal = 0
            if ($Element.TryGetDecimal([ref]$decimal)) { return $decimal }
            return $Element.GetDouble()
        }
        ([Text.Json.JsonValueKind]::True) { return $true }
        ([Text.Json.JsonValueKind]::False) { return $false }
        ([Text.Json.JsonValueKind]::Null) { return $null }
        default { throw 'Pilot collector JSON contains an unsupported value kind.' }
    }
}

function Convert-StrictJson {
    param([byte[]]$Bytes, [string]$SchemaPath, [string]$Label)
    $json = [Text.UTF8Encoding]::new($false, $true).GetString($Bytes)
    if (-not (Test-Json -Json $json -SchemaFile $SchemaPath -ErrorAction Stop)) {
        throw "$Label does not satisfy its exact JSON schema."
    }
    $options = [Text.Json.JsonDocumentOptions]::new()
    $options.AllowTrailingCommas = $false
    $options.CommentHandling = [Text.Json.JsonCommentHandling]::Disallow
    $options.MaxDepth = 64
    $memory = [IO.MemoryStream]::new($Bytes, $false)
    try {
        $document = [Text.Json.JsonDocument]::Parse($memory, $options)
        try {
            Assert-NoDuplicateMembers $document.RootElement $Label
            return ConvertFrom-StrictJsonElement $document.RootElement
        }
        finally { $document.Dispose() }
    }
    finally { $memory.Dispose() }
}

function Assert-CollectionArraySemantics {
    param($Collection)

    $lanes = @($Collection.deviceLanes)
    $expectedLanes = @('clean-install', 'legacy-migration')
    if ($lanes.Count -ne $expectedLanes.Count) {
        throw 'Pilot collection must contain exactly two device lanes.'
    }
    for ($index = 0; $index -lt $expectedLanes.Count; $index++) {
        $lane = $lanes[$index]
        if ([string]$lane.lane -cne $expectedLanes[$index] -or
            [string]$lane.osFamily -cne 'windows' -or
            [string]$lane.nativeArchitecture -cne 'x64' -or
            $lane.standardUser -ne $true) {
            throw 'Pilot collection device lanes must be ordered clean-install then legacy-migration and be native Windows x64 standard-user lanes.'
        }
    }

    $releaseChain = @($Collection.releaseChain)
    $expectedStages = @(
        'baseline',
        'first-update',
        'second-update',
        'failed-health-probe',
        'recovery-target')
    if ($releaseChain.Count -ne $expectedStages.Count) {
        throw 'Pilot collection must contain exactly five release stages.'
    }
    for ($index = 0; $index -lt $expectedStages.Count; $index++) {
        if ([string]$releaseChain[$index].stage -cne $expectedStages[$index]) {
            throw 'Pilot collection release stages are not in the exact contract order.'
        }
    }

    $executables = @($Collection.signedExecutables)
    $expectedRoles = @(
        'release-publisher',
        'installer',
        'bootstrapper',
        'launcher',
        'client-bootstrapper',
        'maintenance')
    if ($executables.Count -ne $expectedRoles.Count) {
        throw 'Pilot collection must contain exactly six signed executable roles.'
    }
    $roles = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    for ($index = 0; $index -lt $expectedRoles.Count; $index++) {
        $role = [string]$executables[$index].role
        if ($role -cne $expectedRoles[$index] -or -not $roles.Add($role)) {
            throw 'Pilot collection signed executable roles must be unique and in the exact contract order.'
        }
    }

    $gateReceiptPaths = @($Collection.gateReceiptPaths)
    if ($gateReceiptPaths.Count -ne 21) {
        throw 'Pilot collection must contain exactly 21 gate receipt paths.'
    }
    $normalizedGatePaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($gateReceiptPath in $gateReceiptPaths) {
        $path = [string]$gateReceiptPath
        if (-not [IO.Path]::IsPathFullyQualified($path)) {
            throw 'Pilot gate receipt paths must be absolute.'
        }
        $normalized = [IO.Path]::GetFullPath($path)
        if ($normalized.StartsWith('\\?\UNC\', [StringComparison]::OrdinalIgnoreCase)) {
            $normalized = '\\' + $normalized.Substring(8)
        }
        elseif ($normalized.StartsWith('\\?\', [StringComparison]::OrdinalIgnoreCase)) {
            $normalized = $normalized.Substring(4)
        }
        $normalized = [IO.Path]::GetFullPath($normalized)
        if (-not $normalizedGatePaths.Add($normalized)) {
            throw 'Pilot gate receipt paths must be distinct under Windows path semantics.'
        }
    }
}

function Assert-PilotManifestUri {
    param([string]$Value)
    $uri = $null
    if (-not [Uri]::TryCreate($Value, [UriKind]::Absolute, [ref]$uri) -or
        -not $uri.IsAbsoluteUri -or
        $uri.Scheme -cne [Uri]::UriSchemeHttps -or
        [string]::IsNullOrWhiteSpace($uri.Host) -or
        -not [string]::IsNullOrEmpty($uri.UserInfo) -or
        -not [string]::IsNullOrEmpty($uri.Fragment) -or
        -not [string]::IsNullOrEmpty($uri.Query) -or
        $uri.AbsolutePath -cne '/v2/channels/pilot/release-set.v2.json') {
        throw 'Pilot manifest URI must be an absolute HTTPS URI without userinfo, query, or fragment and with the exact Pilot manifest path.'
    }
}

function Assert-NonZeroDigests {
    param([AllowNull()]$Value)
    if ($null -eq $Value -or $Value -is [ValueType]) { return }
    if ($Value -is [string]) {
        if ($Value -ceq ('0' * 64)) { throw 'Pilot collector input contains an all-zero digest.' }
        return
    }
    if ($Value -is [Collections.IEnumerable] -and $Value -isnot [Collections.IDictionary]) {
        foreach ($entry in $Value) { Assert-NonZeroDigests $entry }
        return
    }
    $properties = if ($Value -is [Collections.IDictionary]) {
        @($Value.Keys | ForEach-Object {
            [pscustomobject]@{ Name = [string]$_; Value = $Value[$_] }
        })
    }
    else { @($Value.PSObject.Properties) }
    foreach ($property in $properties) { Assert-NonZeroDigests $property.Value }
}

function Get-CanonicalReleaseIdentity {
    param($Value)
    [ordered]@{
        releaseSetId = [string]$Value.releaseSetId
        generation = [long]$Value.generation
        sequence = [long]$Value.sequence
        manifestSha256 = [string]$Value.manifestSha256
        runtimeEntryPointSha256 = [string]$Value.runtimeEntryPointSha256
    }
}

function Assert-ReleaseIdentity {
    param($Actual, $Expected, [string]$Label)
    if ([string]$Actual.releaseSetId -cne [string]$Expected.releaseSetId -or
        [long]$Actual.generation -ne [long]$Expected.generation -or
        [long]$Actual.sequence -ne [long]$Expected.sequence -or
        [string]$Actual.manifestSha256 -cne [string]$Expected.manifestSha256 -or
        [string]$Actual.runtimeEntryPointSha256 -cne [string]$Expected.runtimeEntryPointSha256) {
        throw "$Label does not match the exact release identity."
    }
}

function Assert-OptionalReleaseIdentity {
    param($Actual, $Expected, [string]$Label)
    if ($null -eq $Expected) {
        if ($null -ne $Actual) { throw "$Label must be null." }
        return
    }
    if ($null -eq $Actual) { throw "$Label is missing." }
    Assert-ReleaseIdentity $Actual $Expected $Label
}

function ConvertTo-CanonicalGateReceipt {
    param($Gate)
    $externalEvidence = @($Gate.externalEvidence | ForEach-Object {
        [ordered]@{
            evidenceClass = [string]$_.evidenceClass
            mediaType = [string]$_.mediaType
            sizeBytes = [long]$_.sizeBytes
            sha256 = [string]$_.sha256
            custodianIdSha256 = [string]$_.custodianIdSha256
        }
    })
    [ordered]@{
        schemaVersion = 2
        receiptType = 'ensou-dsh-enterprise-windows-pilot-gate-receipt'
        sequenceNumber = [int]$Gate.sequenceNumber
        testRunId = [string]$Gate.testRunId
        customerAudienceId = [string]$Gate.customerAudienceId
        gate = [string]$Gate.gate
        status = 'PASS'
        deviceLane = [string]$Gate.deviceLane
        startedAtUtc = [string]$Gate.startedAtUtc
        completedAtUtc = [string]$Gate.completedAtUtc
        observedProcess = [ordered]@{
            role = [string]$Gate.observedProcess.role
            state = [string]$Gate.observedProcess.state
            executableSha256 = [string]$Gate.observedProcess.executableSha256
        }
        networkMode = [string]$Gate.networkMode
        resultCode = [string]$Gate.resultCode
        releaseTuple = [ordered]@{
            active = Get-CanonicalReleaseIdentity $Gate.releaseTuple.active
            rollbackTarget = if ($null -eq $Gate.releaseTuple.rollbackTarget) {
                $null
            }
            else { Get-CanonicalReleaseIdentity $Gate.releaseTuple.rollbackTarget }
            attempted = if ($null -eq $Gate.releaseTuple.attempted) {
                $null
            }
            else { Get-CanonicalReleaseIdentity $Gate.releaseTuple.attempted }
        }
        externalEvidence = $externalEvidence
    }
}

function ConvertTo-CanonicalJsonBytes {
    param($Value)
    $json = $Value | ConvertTo-Json -Depth 64 -Compress
    [Text.UTF8Encoding]::new($false, $true).GetBytes($json)
}

function Write-CreateOnlyOutputPair {
    param(
        [string]$RequestPath,
        [byte[]]$RequestBytes,
        [string]$BodyPath,
        [byte[]]$BodyBytes)
    if ($RequestBytes.Length -le 0 -or $RequestBytes.Length -gt 1MB -or
        $BodyBytes.Length -le 0 -or $BodyBytes.Length -gt 16MB) {
        throw 'Pilot collector output byte count is invalid.'
    }

    Initialize-EnterpriseWindowsPilotOutputGuard
    $requestParent = Split-Path -Parent $RequestPath
    $bodyParent = Split-Path -Parent $BodyPath
    $requestOutput = $null
    $bodyOutput = $null
    $published = $false
    try {
        Assert-DirectoryGuardPathIdentity $requestParent
        $requestOutput = [Ensou.Dsh.PilotEvidence.OutputGuard]::Create($RequestPath)
        Assert-DirectoryGuardPathIdentity $requestParent
        [Ensou.Dsh.PilotEvidence.OutputGuard]::AssertPathIdentity(
            $RequestPath,
            [string]$requestOutput.FinalPath,
            [string]$requestOutput.Identity)
        $requestOutput.Stream.Write($RequestBytes)
        $requestOutput.Stream.Flush($true)
        Assert-DirectoryGuardPathIdentity $requestParent
        [Ensou.Dsh.PilotEvidence.OutputGuard]::AssertPathIdentity(
            $RequestPath,
            [string]$requestOutput.FinalPath,
            [string]$requestOutput.Identity)

        Assert-DirectoryGuardPathIdentity $bodyParent
        $bodyOutput = [Ensou.Dsh.PilotEvidence.OutputGuard]::Create($BodyPath)
        Assert-DirectoryGuardPathIdentity $bodyParent
        [Ensou.Dsh.PilotEvidence.OutputGuard]::AssertPathIdentity(
            $BodyPath,
            [string]$bodyOutput.FinalPath,
            [string]$bodyOutput.Identity)
        $bodyOutput.Stream.Write($BodyBytes)
        $bodyOutput.Stream.Flush($true)
        Assert-DirectoryGuardPathIdentity $bodyParent
        [Ensou.Dsh.PilotEvidence.OutputGuard]::AssertPathIdentity(
            $BodyPath,
            [string]$bodyOutput.FinalPath,
            [string]$bodyOutput.Identity)
        $published = $true
    }
    catch {
        $publicationError = $_
        $cleanupFailed = $false
        foreach ($output in @($bodyOutput, $requestOutput)) {
            if ($null -eq $output) { continue }
            try { $output.DeleteOnClose() }
            catch { $cleanupFailed = $true }
        }
        if ($cleanupFailed) {
            throw [IO.IOException]::new(
                'Pilot output publication failed and a create-only output could not be safely cleaned up.',
                $publicationError.Exception)
        }
        throw $publicationError
    }
    finally {
        if ($null -ne $bodyOutput) { $bodyOutput.Dispose() }
        if ($null -ne $requestOutput) { $requestOutput.Dispose() }
    }
    if (-not $published) { throw 'Pilot output publication did not complete.' }
    [pscustomobject]@{
        RequestSha256 = Get-Sha256Bytes $RequestBytes
        BodySha256 = Get-Sha256Bytes $BodyBytes
    }
}

try {
    foreach ($schemaPath in @(
            $collectionSchemaPath,
            $bodySchemaPath,
            $gateSchemaPath,
            $gateContractSchemaPath,
            $requestSchemaPath,
            $releaseSchemaPath,
            $readinessConfigSchemaPath,
            $readinessReportSchemaPath)) {
        if (-not (Test-Json -Json (Get-Content -Raw -LiteralPath $schemaPath) -ErrorAction Stop)) {
            throw "Pilot collector schema is invalid JSON: $schemaPath"
        }
    }

    $bodyFullPath = Resolve-CreateOnlyPath $BodyPath
    $requestFullPath = Resolve-CreateOnlyPath $AttestationRequestPath
    if ([StringComparer]::OrdinalIgnoreCase.Equals($bodyFullPath, $requestFullPath)) {
        throw 'Pilot evidence body and attestation request paths must differ.'
    }

    $collectionSnapshot = Open-LockedSnapshot $CollectionPath 4MB -IncludeBytes
    $collection = Convert-StrictJson $collectionSnapshot.Bytes $collectionSchemaPath 'Pilot evidence collection'
    Assert-CollectionArraySemantics $collection
    Assert-PilotManifestUri ([string]$collection.pilotManifestUri)
    Assert-NonZeroDigests $collection

    $gateContractSnapshot = Open-LockedSnapshot $gateContractPath 256KB -IncludeBytes
    $gateContract = Convert-StrictJson $gateContractSnapshot.Bytes $gateContractSchemaPath 'Pilot gate contract'
    if ((Get-Sha256Bytes (ConvertTo-CanonicalJsonBytes $gateContract)) -cne
        $expectedGateContractCanonicalSha256) {
        throw 'Pilot gate contract does not match the pinned canonical contract.'
    }
    $gateExpectations = @($gateContract.gates)
    for ($index = 0; $index -lt $gateExpectations.Count; $index++) {
        if ([int]$gateExpectations[$index].sequenceNumber -ne $index + 1) {
            throw 'Pilot gate contract sequence is not exact.'
        }
    }

    $releaseChain = @()
    for ($index = 0; $index -lt 5; $index++) {
        $inputRelease = @($collection.releaseChain)[$index]
        $manifestReference = Get-FileReference $inputRelease.manifestPath 512KB -IncludeBytes
        $manifestSnapshot = Open-LockedSnapshot $inputRelease.manifestPath 512KB -IncludeBytes
        $manifest = Convert-StrictJson $manifestSnapshot.Bytes $releaseSchemaPath "Pilot release manifest $($index + 1)"
        if ([string]$manifest.product -cne 'ensou-dsh-enterprise' -or
            [string]$manifest.environment -cne 'production' -or
            [string]$manifest.channel -cne 'pilot' -or
            [string]$manifest.releaseSetId -cne [string]$inputRelease.releaseSetId -or
            [long]$manifest.generation -ne [long]$inputRelease.generation -or
            [long]$manifest.sequence -ne [long]$inputRelease.sequence) {
            throw "Pilot release manifest $($index + 1) does not match its declared production Pilot identity."
        }
        $releaseChain += [ordered]@{
            stage = [string]$inputRelease.stage
            releaseSetId = [string]$inputRelease.releaseSetId
            generation = [long]$inputRelease.generation
            sequence = [long]$inputRelease.sequence
            manifestSha256 = [string]$manifestReference.sha256
            runtimeEntryPointSha256 = [string]$inputRelease.runtimeEntryPointSha256
            manifest = $manifestReference
        }
        if ($index -gt 0 -and
            ([long]$releaseChain[$index].sequence -le [long]$releaseChain[$index - 1].sequence -or
             [long]$releaseChain[$index].generation -lt [long]$releaseChain[$index - 1].generation)) {
            throw 'Pilot release-chain sequence must strictly increase and generation may not decrease.'
        }
    }
    if (@($releaseChain.releaseSetId | Select-Object -Unique).Count -ne 5) {
        throw 'Pilot release-chain releaseSetId values must be distinct.'
    }
    Assert-ReleaseIdentity $collection.readiness.target $releaseChain[4] 'Pilot readiness target'

    $signedExecutables = @()
    $executableHashes = @{}
    $executableSnapshots = @{}
    foreach ($inputExecutable in @($collection.signedExecutables)) {
        $role = [string]$inputExecutable.role
        $reference = Get-FileReference $inputExecutable.path 1GB
        $executableSnapshots[$role] = Open-LockedSnapshot $inputExecutable.path 1GB
        if ((Split-Path -Leaf ([string]$reference.path)) -cne $requiredExecutableNames[$role]) {
            throw "Pilot executable filename is invalid for role '$role'."
        }
        $executableHashes[$role] = [string]$reference.sha256
        $signedExecutables += [ordered]@{ role = $role; file = $reference }
    }

    $observerReference = Get-FileReference $collection.pilotObserverExecutablePath 1GB
    if ($executableHashes.Values -contains [string]$observerReference.sha256) {
        throw 'Pilot observer executable must be independent from the six signed product executables.'
    }

    $deviceLanes = @()
    $deviceInventorySnapshots = @()
    foreach ($inputLane in @($collection.deviceLanes)) {
        $inventoryReference = Get-FileReference $inputLane.deviceInventoryPath 16MB
        $deviceInventorySnapshots += Open-LockedSnapshot $inputLane.deviceInventoryPath 16MB
        $deviceLanes += [ordered]@{
            lane = [string]$inputLane.lane
            osFamily = 'windows'
            osBuild = [string]$inputLane.osBuild
            nativeArchitecture = 'x64'
            standardUser = $true
            installationIdSha256 = [string]$inputLane.installationIdSha256
            deviceInventorySha256 = [string]$inventoryReference.sha256
        }
    }
    if ([string]$deviceLanes[0].installationIdSha256 -ceq [string]$deviceLanes[1].installationIdSha256) {
        throw 'Clean and legacy Pilot lanes must bind distinct installation identities.'
    }
    if ([string]$deviceInventorySnapshots[0].Path -ceq [string]$deviceInventorySnapshots[1].Path -or
        [string]$deviceInventorySnapshots[0].Identity -ceq [string]$deviceInventorySnapshots[1].Identity -or
        [string]$deviceInventorySnapshots[0].Sha256 -ceq [string]$deviceInventorySnapshots[1].Sha256) {
        throw 'Clean and legacy Pilot lanes must use distinct device inventory paths, identities, and bytes.'
    }

    $legacyInventoryReference = Get-FileReference $collection.legacySource.inventoryPath 10MB
    $legacyInventorySnapshot = Open-LockedSnapshot $collection.legacySource.inventoryPath 10MB
    foreach ($deviceInventorySnapshot in $deviceInventorySnapshots) {
        if ([string]$legacyInventorySnapshot.Path -ceq [string]$deviceInventorySnapshot.Path -or
            [string]$legacyInventorySnapshot.Identity -ceq [string]$deviceInventorySnapshot.Identity -or
            [string]$legacyInventorySnapshot.Sha256 -ceq [string]$deviceInventorySnapshot.Sha256) {
            throw 'Legacy source inventory must be independent from both device-lane inventories.'
        }
    }
    if ([string]$collection.weComAdmission.installationIdSha256 -cne
        [string]$deviceLanes[0].installationIdSha256) {
        throw 'WeCom admission must bind the clean-install lane identity.'
    }
    if ([string]$collection.weComAdmission.authorizedEmployeeSubjectSha256 -ceq
        [string]$collection.weComAdmission.unregisteredEmployeeSubjectSha256) {
        throw 'Authorized and unregistered employee subject digests must differ.'
    }
    if ([string]$collection.localDataWitness.historyTreeBeforeSha256 -cne
            [string]$collection.localDataWitness.historyTreeAfterSha256 -or
        [string]$collection.localDataWitness.workspaceTreeBeforeSha256 -cne
            [string]$collection.localDataWitness.workspaceTreeAfterSha256) {
        throw 'History or workspace witness changed during Pilot replay.'
    }

    $readinessConfigReference = Get-FileReference $collection.readiness.configPath 1MB -IncludeBytes
    $readinessConfigSnapshot = Open-LockedSnapshot $collection.readiness.configPath 1MB -IncludeBytes
    $readinessConfig = Convert-StrictJson $readinessConfigSnapshot.Bytes $readinessConfigSchemaPath 'Pilot readiness config'
    $readinessReportReference = Get-FileReference $collection.readiness.reportPath 4MB -IncludeBytes
    $readinessReportSnapshot = Open-LockedSnapshot $collection.readiness.reportPath 4MB -IncludeBytes
    $readinessReport = Convert-StrictJson $readinessReportSnapshot.Bytes $readinessReportSchemaPath 'Pilot readiness report'
    $readinessExecutablePaths = [ordered]@{
        installer = [string]$readinessConfig.installerExecutablePath
        bootstrapper = [string]$readinessConfig.bootstrapperExecutablePath
        launcher = [string]$readinessConfig.launcherExecutablePath
        'client-bootstrapper' = [string]$readinessConfig.clientBootstrapperExecutablePath
        maintenance = [string]$readinessConfig.maintenanceExecutablePath
    }
    foreach ($role in $readinessExecutablePaths.Keys) {
        $readinessExecutableSnapshot = Open-LockedSnapshot $readinessExecutablePaths[$role] 1GB
        $collectedExecutableSnapshot = $executableSnapshots[$role]
        if ([string]$readinessExecutableSnapshot.Path -cne [string]$collectedExecutableSnapshot.Path -or
            [string]$readinessExecutableSnapshot.Identity -cne [string]$collectedExecutableSnapshot.Identity -or
            [string]$readinessExecutableSnapshot.Sha256 -cne [string]$collectedExecutableSnapshot.Sha256) {
            throw "Pilot executable '$role' does not match the exact file admitted by readiness."
        }
    }
    if ([string]$readinessConfig.launcherTrust.updateManifestUri -cne [string]$collection.pilotManifestUri -or
        [string]$readinessConfig.releaseSetId -cne [string]$releaseChain[4].releaseSetId -or
        [long]$readinessConfig.generation -ne [long]$releaseChain[4].generation -or
        [long]$readinessConfig.sequence -ne [long]$releaseChain[4].sequence -or
        [string]$readinessConfig.brandAuthorization.distributionAudienceId -cne [string]$collection.customerAudienceId -or
        [string]$readinessConfig.localDataCompatibilityEvidence.certification.certificationAudienceId -cne [string]$collection.customerAudienceId -or
        [string]$readinessReport.decision -cne 'ADMIT' -or
        [string]$readinessReport.publisherExecutableSha256 -cne [string]$executableHashes['release-publisher'] -or
        [string]$readinessReport.releaseSetId -cne [string]$releaseChain[4].releaseSetId -or
        [long]$readinessReport.generation -ne [long]$releaseChain[4].generation -or
        [long]$readinessReport.sequence -ne [long]$releaseChain[4].sequence -or
        @($readinessReport.checks | Where-Object { $_.status -cne 'PASS' }).Count -ne 0) {
        throw 'Pilot readiness config/report does not bind the audience and recovery target.'
    }

    $runStart = ([DateTimeOffset]$collection.startedAtUtc).ToUniversalTime()
    $runEnd = ([DateTimeOffset]$collection.completedAtUtc).ToUniversalTime()
    if ($runEnd -le $runStart -or
        $runEnd - $runStart -lt [TimeSpan]::FromMinutes(15) -or
        $runEnd -gt [DateTimeOffset]::UtcNow.AddMinutes(5)) {
        throw 'Pilot collection run window is invalid or shorter than fifteen minutes.'
    }

    $gatePaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $primaryExternalHashes = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $previousCompleted = $runStart
    $gates = @()
    for ($index = 0; $index -lt 21; $index++) {
        $gatePath = [IO.Path]::GetFullPath([string]@($collection.gateReceiptPaths)[$index])
        if (-not $gatePaths.Add($gatePath)) { throw 'Pilot gate receipt paths must be distinct.' }
        $gateSnapshot = Open-LockedSnapshot $gatePath 1MB -IncludeBytes
        $gate = Convert-StrictJson $gateSnapshot.Bytes $gateSchemaPath "Pilot gate receipt $($index + 1)"
        Assert-NonZeroDigests $gate
        $expectation = $gateExpectations[$index]
        if ([int]$gate.sequenceNumber -ne $index + 1 -or
            [string]$gate.gate -cne [string]$expectation.gate -or
            [string]$gate.status -cne 'PASS' -or
            [string]$gate.testRunId -cne [string]$collection.testRunId -or
            [string]$gate.customerAudienceId -cne [string]$collection.customerAudienceId -or
            [string]$gate.deviceLane -cne [string]$expectation.deviceLane -or
            [string]$gate.observedProcess.role -cne [string]$expectation.role -or
            [string]$gate.observedProcess.state -cne [string]$expectation.state -or
            [string]$gate.networkMode -cne [string]$expectation.networkMode -or
            [string]$gate.resultCode -cne [string]$expectation.resultCode) {
            throw "Pilot gate '$($expectation.gate)' does not match the exact operational contract."
        }
        $started = ([DateTimeOffset]$gate.startedAtUtc).ToUniversalTime()
        $completed = ([DateTimeOffset]$gate.completedAtUtc).ToUniversalTime()
        if ($started -le $previousCompleted -or $completed -le $started -or $completed -gt $runEnd) {
            throw "Pilot gate '$($expectation.gate)' timestamps are not strictly monotonic."
        }
        if ([string]$expectation.gate -ceq 'no-visible-console-window' -and
            $completed - $started -lt [TimeSpan]::FromMinutes(15)) {
            throw 'No-visible-console-window gate must cover at least fifteen minutes.'
        }
        $previousCompleted = $completed

        $activeExpected = $releaseChain[[int]$expectation.activeReleaseIndex]
        $rollbackExpected = if ($null -eq $expectation.rollbackReleaseIndex) {
            $null
        }
        else { $releaseChain[[int]$expectation.rollbackReleaseIndex] }
        $attemptedExpected = if ($null -eq $expectation.attemptedReleaseIndex) {
            $null
        }
        else { $releaseChain[[int]$expectation.attemptedReleaseIndex] }
        Assert-ReleaseIdentity $gate.releaseTuple.active $activeExpected "$($expectation.gate) active tuple"
        Assert-OptionalReleaseIdentity $gate.releaseTuple.rollbackTarget $rollbackExpected "$($expectation.gate) rollback tuple"
        Assert-OptionalReleaseIdentity $gate.releaseTuple.attempted $attemptedExpected "$($expectation.gate) attempted tuple"

        $expectedProcessSha256 = switch ([string]$expectation.role) {
            'runtime' { [string]$activeExpected.runtimeEntryPointSha256 }
            'previous-runtime' { [string]$activeExpected.runtimeEntryPointSha256 }
            'pilot-observer' { [string]$observerReference.sha256 }
            default { [string]$executableHashes[[string]$expectation.role] }
        }
        if ([string]$gate.observedProcess.executableSha256 -cne $expectedProcessSha256) {
            throw "Pilot gate '$($expectation.gate)' does not bind expected process bytes."
        }
        if (-not $primaryExternalHashes.Add([string]@($gate.externalEvidence)[0].sha256)) {
            throw 'Every Pilot gate needs a distinct primary external observation hash.'
        }
        $gates += ConvertTo-CanonicalGateReceipt $gate
    }

    $body = [ordered]@{
        schemaVersion = 2
        evidenceType = 'ensou-dsh-enterprise-windows-pilot-evidence-body'
        pilotDecision = 'ADMIT'
        product = 'ensou-dsh-enterprise'
        environment = 'production'
        channel = 'pilot'
        runtimeIdentifier = 'win-x64'
        layoutProfile = 'enterprise'
        testRunId = [string]$collection.testRunId
        customerAudienceId = [string]$collection.customerAudienceId
        startedAtUtc = [string]$collection.startedAtUtc
        completedAtUtc = [string]$collection.completedAtUtc
        pilotManifestUri = [string]$collection.pilotManifestUri
        readiness = [ordered]@{
            config = $readinessConfigReference
            report = $readinessReportReference
            target = Get-CanonicalReleaseIdentity $releaseChain[4]
        }
        deviceLanes = $deviceLanes
        pilotObserverExecutableSha256 = [string]$observerReference.sha256
        weComAdmission = [ordered]@{
            authorizationMethod = 'WECOM'
            adminInviteFallbackEnabled = $false
            authorizedEmployeeSubjectSha256 = [string]$collection.weComAdmission.authorizedEmployeeSubjectSha256
            unregisteredEmployeeSubjectSha256 = [string]$collection.weComAdmission.unregisteredEmployeeSubjectSha256
            installationIdSha256 = [string]$collection.weComAdmission.installationIdSha256
            deviceProofPublicKeySha256 = [string]$collection.weComAdmission.deviceProofPublicKeySha256
            boundDeviceCount = 1
            restartRequiredQr = $false
            unregisteredDenialErrorCode = 'WECOM_IDENTITY_NOT_PREREGISTERED'
            contactAdministratorMessageVisible = $true
            secondDeviceDenialErrorCode = 'DEVICE_ALREADY_BOUND'
            revocationClientState = 'DEVICE_REVOKED_RESET_REQUIRED'
            apiPolicyRevocationClientState = 'API_DISABLED'
        }
        legacySource = [ordered]@{
            sourceType = 'prior-ensou-dsh-enterprise-installation'
            version = [string]$collection.legacySource.version
            inventorySha256 = [string]$legacyInventoryReference.sha256
            inventorySizeBytes = [long]$legacyInventoryReference.sizeBytes
        }
        localDataWitness = [ordered]@{
            historyTreeBeforeSha256 = [string]$collection.localDataWitness.historyTreeBeforeSha256
            historyTreeAfterSha256 = [string]$collection.localDataWitness.historyTreeAfterSha256
            workspaceTreeBeforeSha256 = [string]$collection.localDataWitness.workspaceTreeBeforeSha256
            workspaceTreeAfterSha256 = [string]$collection.localDataWitness.workspaceTreeAfterSha256
        }
        releaseChain = $releaseChain
        signedExecutables = $signedExecutables
        gates = $gates
    }

    Assert-NonZeroDigests $body
    $bodyBytes = ConvertTo-CanonicalJsonBytes $body
    $bodyJson = [Text.UTF8Encoding]::new($false, $true).GetString($bodyBytes)
    if (-not (Test-Json -Json $bodyJson -SchemaFile $bodySchemaPath -ErrorAction Stop)) {
        throw 'Generated Pilot evidence body does not satisfy its exact v2 schema.'
    }
    $bodySha256 = Get-Sha256Bytes $bodyBytes
    $signingPayloadBytes = [Text.UTF8Encoding]::new($false, $true).GetBytes((@(
            'ensou-dsh-enterprise-windows-pilot-evidence-attestation-v2',
            '2',
            'ensou-dsh-enterprise-windows-pilot-evidence-envelope',
            '2',
            'ensou-dsh-enterprise-windows-pilot-evidence-body',
            [string]$bodyBytes.Length,
            $bodySha256) -join "`n"))
    $request = [ordered]@{
        schemaVersion = 1
        requestType = 'ensou-dsh-enterprise-windows-pilot-attestation-request'
        algorithm = 'ES256'
        standaloneAdmissionEvidence = $false
        privateKeyUsed = $false
        body = [ordered]@{
            schemaVersion = 2
            evidenceType = 'ensou-dsh-enterprise-windows-pilot-evidence-body'
            sizeBytes = [long]$bodyBytes.Length
            sha256 = $bodySha256
        }
        signingPayload = [ordered]@{
            domain = 'ensou-dsh-enterprise-windows-pilot-evidence-attestation-v2'
            encoding = 'utf-8'
            lineEnding = 'LF'
            sizeBytes = [long]$signingPayloadBytes.Length
            sha256 = Get-Sha256Bytes $signingPayloadBytes
            base64Url = ConvertTo-Base64Url $signingPayloadBytes
        }
    }
    $requestBytes = ConvertTo-CanonicalJsonBytes $request
    $requestJson = [Text.UTF8Encoding]::new($false, $true).GetString($requestBytes)
    if (-not (Test-Json -Json $requestJson -SchemaFile $requestSchemaPath -ErrorAction Stop)) {
        throw 'Generated Pilot attestation request does not satisfy its exact schema.'
    }

    foreach ($snapshot in @($snapshots.Values)) { Assert-SnapshotPathIdentity $snapshot }
    foreach ($directoryPath in @($directoryGuards.Keys)) {
        Assert-DirectoryGuardPathIdentity $directoryPath
    }

    $publishedOutputs = Write-CreateOnlyOutputPair `
        -RequestPath $requestFullPath `
        -RequestBytes $requestBytes `
        -BodyPath $bodyFullPath `
        -BodyBytes $bodyBytes
    $requestSha256 = [string]$publishedOutputs.RequestSha256

    [pscustomobject]@{
        Decision = 'BODY_CREATED'
        StandaloneAdmissionEvidence = $false
        PrivateKeyUsed = $false
        BodyPath = $bodyFullPath
        BodySizeBytes = [long]$bodyBytes.Length
        BodySha256 = $bodySha256
        AttestationRequestPath = $requestFullPath
        AttestationRequestSha256 = $requestSha256
        GateCount = $gates.Count
        DeviceLanes = @($deviceLanes.lane)
    }
}
finally {
    for ($index = $locks.Count - 1; $index -ge 0; $index--) {
        $locks[$index].Dispose()
    }
}
