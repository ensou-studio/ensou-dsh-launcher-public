#requires -Version 7.2

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PlanPath,

    [Parameter(Mandatory = $true)]
    [string]$EvidencePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$planSchemaPath = Join-Path $repositoryRoot `
    'release\schemas\launcher-production-release-plan-v2.schema.json'
$evidenceSchemaPath = Join-Path $repositoryRoot `
    'release\schemas\personal-dual-device-pilot-evidence-v1.schema.json'
$reproducibleBuildSchemaPath = Join-Path $repositoryRoot `
    'release\schemas\personal-two-clean-build-evidence-v1.schema.json'
$buildIntentSchemaPath = Join-Path $repositoryRoot `
    'release\schemas\personal-two-clean-build-intent-v1.schema.json'
$lanePreconditionSchemaPath = Join-Path $repositoryRoot `
    'release\schemas\personal-pilot-lane-precondition-v1.schema.json'
$lockPath = Join-Path $repositoryRoot 'versions\locked.json'
$stateModulePath = Join-Path $repositoryRoot `
    'release\scripts\ProductionReleaseState.psm1'
Import-Module $stateModulePath -Force
$utf8Strict = [Text.UTF8Encoding]::new($false, $true)

function Get-Sha256([string]$Path) {
    $stream = [IO.File]::Open(
        $Path,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    try {
        return ([Convert]::ToHexString(
            [Security.Cryptography.SHA256]::HashData($stream))).ToLowerInvariant()
    }
    finally {
        $stream.Dispose()
    }
}

function Test-PlaceholderSha256([string]$Value) {
    return $Value -match '^([0-9a-f])\1{63}$'
}

function Assert-ProductionSha256([string]$Value, [string]$Label) {
    if ($Value -notmatch '^[0-9a-f]{64}$' -or
        (Test-PlaceholderSha256 $Value)) {
        throw "$Label is absent, malformed, zero, or an obvious placeholder SHA-256."
    }
}

function Assert-ProductionGitObject([string]$Value, [string]$Label) {
    if ($Value -notmatch '^(?:[0-9a-f]{40}|[0-9a-f]{64})$' -or
        $Value -match '^([0-9a-f])\1{39}(?:\1{24})?$') {
        throw "$Label is absent, malformed, or an obvious placeholder Git object."
    }
}

function Assert-RealInstallationId([string]$Value, [string]$Label) {
    if ($Value -notmatch
            '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' -or
        $Value -match '^(?:00000000|11111111|aaaaaaaa|ffffffff)-') {
        throw "$Label is not a real canonical UUID v4 installation identity."
    }
}

function Assert-NoDuplicateMembers([Text.Json.JsonElement]$Element, [string]$Path) {
    if ($Element.ValueKind -eq [Text.Json.JsonValueKind]::Object) {
        $members = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::Ordinal)
        foreach ($property in $Element.EnumerateObject()) {
            if (-not $members.Add($property.Name)) {
                throw "$Path contains duplicate JSON member '$($property.Name)'."
            }
            Assert-NoDuplicateMembers `
                -Element $property.Value `
                -Path "$Path.$($property.Name)"
        }
    }
    elseif ($Element.ValueKind -eq [Text.Json.JsonValueKind]::Array) {
        $index = 0
        foreach ($item in $Element.EnumerateArray()) {
            Assert-NoDuplicateMembers -Element $item -Path "$Path[$index]"
            $index++
        }
    }
}

function Read-StrictJson([string]$Path, [string]$Label, [int64]$MaximumBytes) {
    $fullPath = [IO.Path]::GetFullPath($Path)
    $item = Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $item.Length -le 0 -or
        $item.Length -gt $MaximumBytes) {
        throw "$Label must be one bounded, non-linked file."
    }
    $bytes = [IO.File]::ReadAllBytes($fullPath)
    try {
        $text = $utf8Strict.GetString($bytes)
        $options = [Text.Json.JsonDocumentOptions]::new()
        $options.AllowTrailingCommas = $false
        $options.CommentHandling = [Text.Json.JsonCommentHandling]::Disallow
        $options.MaxDepth = 64
        $document = [Text.Json.JsonDocument]::Parse($text, $options)
        try {
            Assert-NoDuplicateMembers -Element $document.RootElement -Path '$'
        }
        finally {
            $document.Dispose()
        }
        return [pscustomobject]@{
            Path = $fullPath
            Text = $text
            Value = $text | ConvertFrom-Json -Depth 64 -DateKind String
            SizeBytes = [int64]$bytes.Length
            Sha256 = ([Convert]::ToHexString(
                [Security.Cryptography.SHA256]::HashData($bytes))).ToLowerInvariant()
        }
    }
    finally {
        [Array]::Clear($bytes, 0, $bytes.Length)
    }
}

function Assert-CanonicalUtc([string]$Value, [string]$Label) {
    $parsed = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParseExact(
            $Value,
            'yyyy-MM-ddTHH:mm:ss.fffffffZ',
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AssumeUniversal,
            [ref]$parsed) -or
        $parsed.Offset -ne [TimeSpan]::Zero) {
        throw "$Label is not a canonical UTC timestamp."
    }
    return $parsed
}

function Assert-CanonicalIdentityUtc([string]$Value, [string]$Label) {
    $parsed = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParseExact(
            $Value,
            'yyyy-MM-ddTHH:mm:ss.fffffffzzz',
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::None,
            [ref]$parsed) -or
        -not $Value.EndsWith('+00:00', [StringComparison]::Ordinal) -or
        $parsed.Offset -ne [TimeSpan]::Zero -or
        $parsed -le [DateTimeOffset]::UnixEpoch) {
        throw "$Label is not the canonical positive UTC identity timestamp."
    }
    return $parsed
}

function Assert-ExactMembers($Value, [string[]]$Expected, [string]$Label) {
    $actual = @($Value.PSObject.Properties.Name)
    if ($actual.Count -ne $Expected.Count) {
        throw "$Label has an unexpected JSON member count."
    }
    $actualSet = [Collections.Generic.HashSet[string]]::new(
        [string[]]$actual,
        [StringComparer]::Ordinal)
    foreach ($member in $Expected) {
        if (-not $actualSet.Contains($member)) {
            throw "$Label is missing exact JSON member '$member'."
        }
    }
}

function Get-CandidateClosureSha256([psobject]$Evidence) {
    $closure = $Evidence.candidateClosure
    $canonical = @(
        "releaseSetId=$([string]$Evidence.releaseSetId)",
        "installer=$([string]$closure.installer.fileName)|$([string]$closure.installer.relativePath)|$([int64]$closure.installer.sizeBytes)|$([string]$closure.installer.sha256)",
        "manifest=$([string]$closure.manifest.fileName)|$([string]$closure.manifest.relativePath)|$([int64]$closure.manifest.sizeBytes)|$([string]$closure.manifest.sha256)",
        "client=$([string]$closure.client.fileName)|$([string]$closure.client.relativePath)|$([int64]$closure.client.sizeBytes)|$([string]$closure.client.sha256)",
        "runtime=$([string]$closure.runtime.fileName)|$([string]$closure.runtime.relativePath)|$([int64]$closure.runtime.sizeBytes)|$([string]$closure.runtime.sha256)"
    ) -join "`n"
    $bytes = $utf8Strict.GetBytes($canonical + "`n")
    try {
        return ([Convert]::ToHexString(
            [Security.Cryptography.SHA256]::HashData($bytes))).ToLowerInvariant()
    }
    finally {
        [Array]::Clear($bytes, 0, $bytes.Length)
    }
}

function Assert-EvidenceFile(
    [psobject]$Descriptor,
    [string]$EvidenceRoot,
    [string]$ExpectedRelativePath,
    [string]$Label
) {
    if ([string]$Descriptor.relativePath -cne $ExpectedRelativePath) {
        throw "$Label must use '$ExpectedRelativePath'."
    }
    Assert-ProductionSha256 -Value ([string]$Descriptor.sha256) `
        -Label "$Label descriptor"
    $nativeRelative = ([string]$Descriptor.relativePath).Replace(
        '/',
        [IO.Path]::DirectorySeparatorChar)
    $fullPath = [IO.Path]::GetFullPath((Join-Path $EvidenceRoot $nativeRelative))
    $rootBoundary = $EvidenceRoot.TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar) +
        [IO.Path]::DirectorySeparatorChar
    if (-not $fullPath.StartsWith(
            $rootBoundary,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label escapes the evidence root."
    }
    $item = Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Label is not an ordinary evidence file."
    }
    for ($current = $item.Directory;
         $null -ne $current -and
         -not $current.FullName.Equals(
            $EvidenceRoot,
            [StringComparison]::OrdinalIgnoreCase);
         $current = $current.Parent) {
        if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Label crosses a linked directory."
        }
    }
    $held = ProductionReleaseState\Open-ProductionReleaseInput `
        -Path $fullPath -Label $Label -MaximumBytes 8GB
    try {
        if ([int64]$held.SizeBytes -ne [int64]$Descriptor.sizeBytes -or
            [string]$held.Sha256 -cne [string]$Descriptor.sha256) {
            throw "$Label bytes differ from their descriptor."
        }
    }
    finally {
        $held.Stream.Dispose()
    }
    return $fullPath
}

. (Join-Path $PSScriptRoot 'PersonalTwoCleanBuildValidation.ps1')

$planInput = Read-StrictJson -Path $PlanPath -Label 'Personal Pilot plan' `
    -MaximumBytes 8MB
$evidenceInput = Read-StrictJson -Path $EvidencePath `
    -Label 'Personal dual-device Pilot evidence' -MaximumBytes 8MB
$plan = $planInput.Value
$evidence = $evidenceInput.Value

if (-not (Test-Json -Json $planInput.Text -SchemaFile $planSchemaPath `
        -ErrorAction Stop)) {
    throw 'Personal Pilot plan does not satisfy release plan v2.'
}
if (-not (Test-Json -Json $evidenceInput.Text -SchemaFile $evidenceSchemaPath `
        -ErrorAction Stop)) {
    throw 'Personal dual-device Pilot evidence does not satisfy its production schema.'
}
if ([string]$plan.edition -cne 'Personal' -or
    [string]$plan.targetChannel -cne 'pilot') {
    throw 'Dual-device Pilot evidence requires one Personal Pilot plan.'
}
if ($plan.PSObject.Properties.Name -ccontains 'personalPilotTemplateStatus') {
    throw 'NO-GO: the example plan is a template; replace all release inputs and remove personalPilotTemplateStatus.'
}
$sourceCommit = [string]$plan.sourceCommit
Assert-ProductionGitObject -Value $sourceCommit -Label 'Plan sourceCommit'
$lock = Get-Content -LiteralPath $lockPath -Raw | ConvertFrom-Json
if ($sourceCommit -ceq [string]$lock.officialCommit) {
    throw 'Plan sourceCommit incorrectly binds the upstream Harness commit instead of the Launcher commit.'
}
if ([string]$plan.runtimeCandidate.githubReleaseTag -cne
        [string]$plan.runtimeCandidate.releaseId) {
    throw 'Plan runtime candidate tag differs from its reserved managed releaseId.'
}
$runtimeArchiveName =
    "EnsouDshRuntime-$([string]$plan.runtimeCandidate.releaseId)-win-x64.zip"
if ([string]$plan.runtimeCandidate.archive.fileName -cne $runtimeArchiveName -or
    [string]$plan.runtimeCandidate.metadata.fileName -cne
        ($runtimeArchiveName -replace '[.]zip$', '.metadata.json') -or
    [string]$plan.runtimeCandidate.hashEvidence.fileName -cne
        ($runtimeArchiveName + '.sha256')) {
    throw 'Plan runtimeCandidate is not the exact source-runtime input closure expected by Prepare.'
}
foreach ($descriptor in @(
    $plan.runtimeCandidate.archive,
    $plan.runtimeCandidate.metadata,
    $plan.runtimeCandidate.hashEvidence
)) {
    Assert-ProductionSha256 -Value ([string]$descriptor.sha256) `
        -Label "Plan runtime input '$([string]$descriptor.fileName)'"
}
Assert-ProductionSha256 `
    -Value ([string]$plan.authenticodePolicy.signerSha256Thumbprint) `
    -Label 'Plan Authenticode signer certificate'
foreach ($input in @($plan.clientSigningInputs)) {
    Assert-ProductionSha256 -Value ([string]$input.sha256) `
        -Label "Plan client input '$([string]$input.role)'"
    Assert-ProductionSha256 -Value ([string]$input.peContentSha256) `
        -Label "Plan client input '$([string]$input.role)' PE content"
}
if ([string]$evidence.planSha256 -cne [string]$planInput.Sha256) {
    throw 'Evidence does not bind the exact Personal Pilot plan bytes.'
}
if ([string]$evidence.releaseSetId -cne [string]$plan.releaseSetId) {
    throw 'Evidence releaseSetId differs from the Personal Pilot plan.'
}

foreach ($componentName in @('installer', 'manifest', 'client', 'runtime')) {
    Assert-ProductionSha256 `
        -Value ([string]$evidence.candidateClosure.$componentName.sha256) `
        -Label "Candidate $componentName"
}
$computedClosureSha256 = Get-CandidateClosureSha256 -Evidence $evidence
Assert-ProductionSha256 -Value ([string]$evidence.candidateClosureSha256) `
    -Label 'Candidate closure'
if ([string]$evidence.candidateClosureSha256 -cne $computedClosureSha256) {
    throw 'Candidate closure SHA-256 differs from the exact four candidate hashes.'
}
if ([string]$evidence.candidateClosure.runtime.fileName -cne
        [string]$plan.runtimeCandidate.archive.fileName -or
    [string]$evidence.candidateClosure.runtime.sha256 -cne
        [string]$plan.runtimeCandidate.archive.sha256) {
    throw 'Candidate closure Runtime differs from the exact plan.runtimeCandidate archive.'
}

$evidenceRoot = [IO.Path]::GetDirectoryName($evidenceInput.Path)
$evidenceRootItem = Get-Item -LiteralPath $evidenceRoot -Force
if (-not $evidenceRootItem.PSIsContainer -or
    ($evidenceRootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'Personal Pilot evidence root must be one ordinary non-linked directory.'
}
[void](Assert-ReproducibleBuild -Evidence $evidence -Plan $plan `
    -PlanInput $planInput -EvidenceRoot $evidenceRoot)

$candidateNames = [Collections.Generic.HashSet[string]]::new(
    [StringComparer]::Ordinal)
$candidatePaths = [Collections.Generic.Dictionary[string,string]]::new(
    [StringComparer]::Ordinal)
foreach ($componentName in @('installer', 'manifest', 'client', 'runtime')) {
    $component = $evidence.candidateClosure.$componentName
    $expectedRelativePath = "candidate/$([string]$component.fileName)"
    if (-not $candidateNames.Add([string]$component.fileName)) {
        throw 'Candidate closure contains a duplicate file name.'
    }
    $candidatePath = Assert-EvidenceFile -Descriptor $component `
        -EvidenceRoot $evidenceRoot `
        -ExpectedRelativePath $expectedRelativePath `
        -Label "Candidate $componentName"
    $candidatePaths.Add($componentName, $candidatePath)
}
if ([int64]$evidence.candidateClosure.runtime.sizeBytes -ne
        [int64]$plan.runtimeCandidate.archive.sizeBytes) {
    throw 'Candidate closure Runtime size differs from the exact plan.runtimeCandidate archive.'
}
$candidateManifest = Read-StrictJson `
    -Path $candidatePaths['manifest'] -Label 'Candidate release manifest' `
    -MaximumBytes 8MB
if ([int64]$candidateManifest.SizeBytes -ne
        [int64]$evidence.candidateClosure.manifest.sizeBytes -or
    [string]$candidateManifest.Sha256 -cne
        [string]$evidence.candidateClosure.manifest.sha256) {
    throw 'Candidate release manifest changed between byte admission and strict parsing.'
}
if (-not ($candidateManifest.Value.PSObject.Properties.Name -ccontains
        'releaseSetId') -or
    [string]$candidateManifest.Value.releaseSetId -cne
        [string]$plan.releaseSetId) {
    throw 'Candidate release manifest does not name the exact Personal plan releaseSetId.'
}
$installationIds = [Collections.Generic.HashSet[string]]::new(
    [StringComparer]::Ordinal)
$stateBindings = [Collections.Generic.HashSet[string]]::new(
    [StringComparer]::Ordinal)
$latestObservation = [DateTimeOffset]::MinValue
$now = [DateTimeOffset]::UtcNow
$earliestAcceptedObservation = $now.AddDays(-30)
$latestAcceptedObservation = $now.AddMinutes(5)
for ($deviceIndex = 0; $deviceIndex -lt 2; $deviceIndex++) {
    $device = $evidence.devices[$deviceIndex]
    $plannedDevice = $plan.personalPilotDevices[$deviceIndex]
    if ([string]$device.deviceId -cne [string]$plannedDevice.deviceId -or
        [string]$device.hostLabel -cne [string]$plannedDevice.hostLabel -or
        [string]$device.lane -cne [string]$plannedDevice.lane) {
        throw "Evidence device $deviceIndex differs from its exact planned lane."
    }
    $laneRelativePath =
        "devices/$([string]$device.deviceId)/lane-precondition.v1.json"
    $lanePath = Assert-EvidenceFile -Descriptor $device.lanePrecondition `
        -EvidenceRoot $evidenceRoot -ExpectedRelativePath $laneRelativePath `
        -Label "Device '$([string]$device.deviceId)' lane precondition"
    $laneInput = ProductionReleaseState\Read-StrictProductionJsonFile `
        -Path $lanePath `
        -Label "Device '$([string]$device.deviceId)' lane precondition" `
        -SchemaPath $lanePreconditionSchemaPath
    if ([int64]$laneInput.Bytes.LongLength -ne
            [int64]$device.lanePrecondition.sizeBytes -or
        [string]$laneInput.Sha256 -cne
            [string]$device.lanePrecondition.sha256) {
        throw "Device '$([string]$device.deviceId)' lane precondition changed between byte admission and strict parsing."
    }
    [void](ProductionReleaseState\Assert-CanonicalProductionJsonInput `
        -JsonInput $laneInput `
        -Label "Device '$([string]$device.deviceId)' lane precondition")
    ProductionReleaseState\Assert-ExactProductionJsonMembers `
        -Value $laneInput.Value -Expected @(
            'schemaVersion',
            'evidenceType',
            'deviceId',
            'lane',
            'capturedAtUtc',
            'managedRootState',
            'currentPointerPresent',
            'startupRegistrationPresent',
            'baselineReleaseSetId',
            'baselineCurrentPointerSha256',
            'source',
            'result'
        ) -Label "Device '$([string]$device.deviceId)' lane precondition"
    $lane = $laneInput.Value
    if ([string]$lane.deviceId -cne [string]$device.deviceId -or
        [string]$lane.lane -cne [string]$device.lane) {
        throw "Device '$([string]$device.deviceId)' lane precondition is not bound to its planned device and lane."
    }
    $laneCapturedAt = Assert-CanonicalUtc `
        -Value ([string]$lane.capturedAtUtc) `
        -Label "Device '$([string]$device.deviceId)' lane capturedAtUtc"
    if ($laneCapturedAt -lt $earliestAcceptedObservation -or
        $laneCapturedAt -gt $latestAcceptedObservation) {
        throw "Device '$([string]$device.deviceId)' lane precondition falls outside the production freshness window."
    }
    if ($deviceIndex -eq 0) {
        Assert-ProductionSha256 `
            -Value ([string]$lane.baselineCurrentPointerSha256) `
            -Label 'PILOT-DESKTOP existing-install baseline pointer'
    }
    $installationId = [string]$device.installationId
    Assert-RealInstallationId -Value $installationId `
        -Label "Device '$([string]$device.deviceId)' installationId"
    if (-not $installationIds.Add($installationId)) {
        throw 'PILOT-DESKTOP and PilotNotebook must have distinct installation UUIDs.'
    }
    $identityRelativePath =
        "devices/$([string]$device.deviceId)/installation-identity.v1.json"
    $identityPath = Assert-EvidenceFile -Descriptor $device.identityReceipt `
        -EvidenceRoot $evidenceRoot -ExpectedRelativePath $identityRelativePath `
        -Label "Device '$([string]$device.deviceId)' identity receipt"
    $identityInput = Read-StrictJson -Path $identityPath `
        -Label "Device '$([string]$device.deviceId)' identity receipt" `
        -MaximumBytes 64KB
    if ([int64]$identityInput.SizeBytes -ne
            [int64]$device.identityReceipt.sizeBytes -or
        [string]$identityInput.Sha256 -cne
            [string]$device.identityReceipt.sha256) {
        throw "Device '$([string]$device.deviceId)' identity receipt changed between byte admission and strict parsing."
    }
    $identity = $identityInput.Value
    $identityMembers = @(
        'schemaVersion',
        'receiptType',
        'product',
        'installationId',
        'createdAtUtc',
        'stateBindingSha256'
    )
    Assert-ExactMembers -Value $identity -Expected $identityMembers `
        -Label "Device '$([string]$device.deviceId)' identity receipt"
    if ([int]$identity.schemaVersion -ne 1 -or
        [string]$identity.receiptType -cne
            'ensou-dsh-personal-installation-identity' -or
        [string]$identity.product -cne 'ensou-dsh-personal') {
        throw "Device '$([string]$device.deviceId)' identity receipt contract is invalid."
    }
    Assert-RealInstallationId -Value ([string]$identity.installationId) `
        -Label "Device '$([string]$device.deviceId)' receipt installationId"
    if ([string]$identity.installationId -cne $installationId) {
        throw "Device '$([string]$device.deviceId)' evidence installationId differs from its copied identity receipt."
    }
    $identityCreatedAt = Assert-CanonicalIdentityUtc `
        -Value ([string]$identity.createdAtUtc) `
        -Label "Device '$([string]$device.deviceId)' receipt createdAtUtc"
    if ($identityCreatedAt -gt $latestAcceptedObservation) {
        throw "Device '$([string]$device.deviceId)' identity receipt is future-dated."
    }
    if ($deviceIndex -eq 1 -and $laneCapturedAt -gt $identityCreatedAt) {
        throw 'PilotNotebook clean-install identity predates its absent-install lane precondition.'
    }
    Assert-ProductionSha256 -Value ([string]$identity.stateBindingSha256) `
        -Label "Device '$([string]$device.deviceId)' state binding"
    if (-not $stateBindings.Add([string]$identity.stateBindingSha256)) {
        throw 'PILOT-DESKTOP and PilotNotebook must have distinct state bindings.'
    }
    $canonicalIdentity =
        '{"schemaVersion":1,"receiptType":"ensou-dsh-personal-installation-identity","product":"ensou-dsh-personal","installationId":"' +
        [string]$identity.installationId + '","createdAtUtc":"' +
        [string]$identity.createdAtUtc + '","stateBindingSha256":"' +
        [string]$identity.stateBindingSha256 + '"}'
    if ([string]$identityInput.Text -cne $canonicalIdentity) {
        throw "Device '$([string]$device.deviceId)' identity receipt is not exact canonical product JSON."
    }
    foreach ($result in @($device.results)) {
        if ([string]$result.deviceId -cne [string]$device.deviceId -or
            [string]$result.installationId -cne $installationId -or
            [string]$result.identityReceiptSha256 -cne
                [string]$device.identityReceipt.sha256 -or
            [string]$result.candidateClosureSha256 -cne
                $computedClosureSha256) {
            throw "Check '$([string]$result.checkId)' is not bound to its device identity and exact candidate closure."
        }
        Assert-ProductionSha256 -Value ([string]$result.identityReceiptSha256) `
            -Label "Check '$([string]$result.checkId)' identity receipt"
        Assert-ProductionSha256 -Value ([string]$result.evidence.sha256) `
            -Label "Check '$([string]$result.checkId)' evidence"
        $observation = Assert-CanonicalUtc `
            -Value ([string]$result.observedAtUtc) `
            -Label "Check '$([string]$result.checkId)' observedAtUtc"
        if ($observation -lt $earliestAcceptedObservation -or
            $observation -gt $latestAcceptedObservation) {
            throw "Check '$([string]$result.checkId)' observation falls outside the 30-day/five-minute production window."
        }
        if ($observation -lt $laneCapturedAt) {
            throw "Check '$([string]$result.checkId)' predates its device lane precondition."
        }
        if ($observation -lt $identityCreatedAt) {
            throw "Check '$([string]$result.checkId)' predates its installation identity."
        }
        if ($observation -gt $latestObservation) {
            $latestObservation = $observation
        }
        $checkRelativePath =
            "devices/$([string]$device.deviceId)/checks/$([string]$result.checkId).json"
        $checkEvidencePath = Assert-EvidenceFile -Descriptor $result.evidence `
            -EvidenceRoot $evidenceRoot -ExpectedRelativePath $checkRelativePath `
            -Label "Check '$([string]$result.checkId)'"
        $checkInput = Read-StrictJson -Path $checkEvidencePath `
            -Label "Check '$([string]$result.checkId)' observation" `
            -MaximumBytes 1MB
        if ([int64]$checkInput.SizeBytes -ne
                [int64]$result.evidence.sizeBytes -or
            [string]$checkInput.Sha256 -cne
                [string]$result.evidence.sha256) {
            throw "Check '$([string]$result.checkId)' evidence changed between byte admission and strict parsing."
        }
        $check = $checkInput.Value
        $checkMembers = @(
            'schemaVersion',
            'evidenceType',
            'deviceId',
            'installationId',
            'identityReceiptSha256',
            'checkId',
            'candidateClosureSha256',
            'observedAtUtc',
            'source',
            'result'
        )
        Assert-ExactMembers -Value $check -Expected $checkMembers `
            -Label "Check '$([string]$result.checkId)' observation"
        if ([int]$check.schemaVersion -ne 1 -or
            [string]$check.evidenceType -cne
                'ensou-dsh-personal-pilot-check-observation' -or
            [string]$check.deviceId -cne [string]$result.deviceId -or
            [string]$check.installationId -cne
                [string]$result.installationId -or
            [string]$check.identityReceiptSha256 -cne
                [string]$result.identityReceiptSha256 -or
            [string]$check.checkId -cne [string]$result.checkId -or
            [string]$check.candidateClosureSha256 -cne
                [string]$result.candidateClosureSha256 -or
            [string]$check.observedAtUtc -cne
                [string]$result.observedAtUtc -or
            [string]$check.source -cne 'real-device' -or
            [string]$check.result -cne 'PASS') {
            throw "Check '$([string]$result.checkId)' file is not self-bound to its evidence record."
        }
        $canonicalCheck =
            '{"schemaVersion":1,"evidenceType":"ensou-dsh-personal-pilot-check-observation","deviceId":"' +
            [string]$check.deviceId + '","installationId":"' +
            [string]$check.installationId + '","identityReceiptSha256":"' +
            [string]$check.identityReceiptSha256 + '","checkId":"' +
            [string]$check.checkId + '","candidateClosureSha256":"' +
            [string]$check.candidateClosureSha256 + '","observedAtUtc":"' +
            [string]$check.observedAtUtc +
            '","source":"real-device","result":"PASS"}'
        if ([string]$checkInput.Text -cne $canonicalCheck) {
            throw "Check '$([string]$result.checkId)' observation is not exact canonical product JSON."
        }
    }
}
$completedAt = Assert-CanonicalUtc -Value ([string]$evidence.completedAtUtc) `
    -Label 'completedAtUtc'
if ($completedAt -lt $latestObservation -or
    $completedAt -lt $earliestAcceptedObservation -or
    $completedAt -gt $latestAcceptedObservation) {
    throw 'completedAtUtc predates a device observation or falls outside the production freshness window.'
}

[pscustomobject]@{
    Result = 'PASS'
    ReleaseSetId = [string]$evidence.releaseSetId
    CandidateClosureSha256 = $computedClosureSha256
    DeviceCount = 2
    CheckCount = 16
    ReproducibleBuildCount = 2
    CandidateFileCount = 4
    ExistingUpgradeLane = 'PILOT-DESKTOP'
    CleanInstallLane = 'PilotNotebook notebook'
    InstallationIdsDistinct = $true
    StateBindingsDistinct = $true
    Source = 'real-device'
    Authority = 'local-consistency-preflight'
}
