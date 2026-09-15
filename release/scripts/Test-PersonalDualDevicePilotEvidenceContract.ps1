#requires -Version 7.2

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$validator = Join-Path $PSScriptRoot `
    'Test-PersonalDualDevicePilotEvidence.ps1'
$planTemplatePath = Join-Path $repositoryRoot `
    'release\examples\personal-pilot-release-plan.example.json'
$evidenceTemplatePath = Join-Path $repositoryRoot `
    'release\examples\personal-dual-device-pilot-evidence.template.json'
$tempParent = [IO.Path]::GetTempPath()
$testRoot = Join-Path $tempParent `
    ('ensou-personal-dual-pilot-' + [Guid]::NewGuid().ToString('N'))
$utf8 = [Text.UTF8Encoding]::new($false)
$completed = $false
$assertions = 0

function Assert-True([bool]$Condition, [string]$Message) {
    $script:assertions++
    if (-not $Condition) { throw $Message }
}

function Get-Sha256([string]$Path) {
    $stream = [IO.File]::OpenRead($Path)
    try {
        return ([Convert]::ToHexString(
            [Security.Cryptography.SHA256]::HashData($stream))).ToLowerInvariant()
    }
    finally {
        $stream.Dispose()
    }
}

function Get-TextSha256([string]$Value) {
    $bytes = $utf8.GetBytes($Value)
    try {
        return ([Convert]::ToHexString(
            [Security.Cryptography.SHA256]::HashData($bytes))).ToLowerInvariant()
    }
    finally {
        [Array]::Clear($bytes, 0, $bytes.Length)
    }
}

function Write-Json([string]$Path, $Value) {
    $parent = [IO.Path]::GetDirectoryName($Path)
    [IO.Directory]::CreateDirectory($parent) | Out-Null
    [IO.File]::WriteAllText(
        $Path,
        ($Value | ConvertTo-Json -Depth 64),
        $utf8)
}

function Copy-JsonValue($Value) {
    return $Value | ConvertTo-Json -Depth 64 -Compress |
        ConvertFrom-Json -Depth 64 -DateKind String
}

function New-FileDescriptor(
    [string]$Root,
    [string]$RelativePath,
    [string]$Content
) {
    $path = Join-Path $Root `
        $RelativePath.Replace('/', [IO.Path]::DirectorySeparatorChar)
    [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($path)) |
        Out-Null
    [IO.File]::WriteAllText($path, $Content, $utf8)
    $item = Get-Item -LiteralPath $path -Force
    return [pscustomobject]@{
        relativePath = $RelativePath
        sizeBytes = [int64]$item.Length
        sha256 = Get-Sha256 $path
    }
}

function Set-IdentityDescriptorFromPath($Evidence, [int]$DeviceIndex, [string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force
    $descriptor = $Evidence.devices[$DeviceIndex].identityReceipt
    $descriptor.sizeBytes = [int64]$item.Length
    $descriptor.sha256 = Get-Sha256 $Path
    foreach ($check in @($Evidence.devices[$DeviceIndex].results)) {
        $check.identityReceiptSha256 = [string]$descriptor.sha256
    }
}

function Set-RunDescriptorFromPath(
    $Evidence,
    [string]$Path
) {
    $item = Get-Item -LiteralPath $Path -Force
    $descriptor = $Evidence.reproducibleBuild.receipt
    $descriptor.sizeBytes = [int64]$item.Length
    $descriptor.sha256 = Get-Sha256 $Path
}

function Set-LaneDescriptorFromPath(
    $Evidence,
    [int]$DeviceIndex,
    [string]$Path
) {
    $item = Get-Item -LiteralPath $Path -Force
    $descriptor = $Evidence.devices[$DeviceIndex].lanePrecondition
    $descriptor.sizeBytes = [int64]$item.Length
    $descriptor.sha256 = Get-Sha256 $Path
}

function Get-ClosureSha256($Evidence) {
    $closure = $Evidence.candidateClosure
    $text = @(
        "releaseSetId=$([string]$Evidence.releaseSetId)",
        "installer=$([string]$closure.installer.fileName)|$([string]$closure.installer.relativePath)|$([int64]$closure.installer.sizeBytes)|$([string]$closure.installer.sha256)",
        "manifest=$([string]$closure.manifest.fileName)|$([string]$closure.manifest.relativePath)|$([int64]$closure.manifest.sizeBytes)|$([string]$closure.manifest.sha256)",
        "client=$([string]$closure.client.fileName)|$([string]$closure.client.relativePath)|$([int64]$closure.client.sizeBytes)|$([string]$closure.client.sha256)",
        "runtime=$([string]$closure.runtime.fileName)|$([string]$closure.runtime.relativePath)|$([int64]$closure.runtime.sizeBytes)|$([string]$closure.runtime.sha256)"
    ) -join "`n"
    return Get-TextSha256 ($text + "`n")
}

# Synthetic bytes and self-authored receipts below exercise the validator only.
# They are NOT production build or real-device evidence.
function New-ReproducibleBuildEvidence($Plan, [string]$SourceTree) {
    Import-Module (Join-Path $PSScriptRoot 'ProductionReleaseState.psm1') -Force
    . (Join-Path $PSScriptRoot 'PersonalTwoCleanBuildValidation.ps1')
    $intent = [ordered]@{
        schemaVersion = 1
        intentType = 'ensou-dsh-personal-two-clean-production-build-intent'
        buildIntentId = [Guid]::NewGuid().ToString()
        sourceCommit = $Plan.sourceCommit
        sourceTree = $SourceTree
        version = '1.1.0'
        configuration = 'Release'
        runtimeIdentifier = 'win-x64'
        selfContained = $true
        publishSingleFile = $true
        enableCompressionInSingleFile = $true
        manifestOrigin = ([uri]$Plan.manifestUri).GetLeftPart([UriPartial]::Authority) + '/'
        artifactOrigin = ([uri]$Plan.artifactBaseUri).GetLeftPart([UriPartial]::Authority) + '/'
        personalAccountOrigin = [string]$Plan.personalAccountOrigin
        channel = $Plan.targetChannel
        releaseManifestTrust = $Plan.releaseManifestTrust
        startupStubVersion = $Plan.releaseCompatibility.startupStubVersion
        canonicalLowSFromSequence = $Plan.releaseCompatibility.canonicalLowSFromSequence
        authenticodeSignerSha256Thumbprint = $Plan.authenticodePolicy.signerSha256Thumbprint
    }
    $intentDescriptor = New-FileDescriptor $testRoot 'builds/build-intent.v1.json' (
        $intent | ConvertTo-Json -Depth 64 -Compress)
    $runs = [Collections.Generic.List[object]]::new()
    $projects = @('Ensou.Dsh.Bootstrapper', 'Ensou.Dsh.ClientBootstrapper', 'Ensou.Dsh.Launcher', 'Ensou.Dsh.Personal.Maintenance')
    $commandDigest = ''
    foreach ($label in @('isolated-a', 'isolated-b')) {
        $source = Join-Path $testRoot "work/$label/source"
        $run = [ordered]@{
            runLabel = $label
            buildId = [Guid]::NewGuid().ToString()
            checkoutPath = Join-Path $testRoot "pristine/$label"
            checkoutPhysicalIdentitySha256 = Get-TextSha256 "pristine-$label"
            materializedCheckoutPath = $source
            materializedCheckoutPhysicalIdentitySha256 = Get-TextSha256 "materialized-$label"
            intermediateRootPath = $source
            intermediateRootPhysicalIdentitySha256 = Get-TextSha256 "materialized-$label"
            outputRootPath = Join-Path $testRoot "build-artifacts/$label"
            outputRootPhysicalIdentitySha256 = Get-TextSha256 "output-$label"
            sourceStatusBefore = 'CLEAN_TRACKED_HEAD'
            sourceStatusAfter = 'CLEAN_TRACKED_HEAD'
            startedAtUtc = '2026-09-01T00:00:00Z'
            completedAtUtc = '2026-09-01T00:00:01Z'
            sourceDateEpoch = 123456
            restore = $null
            invocations = @()
            outputClosureSha256 = ''
        }
        $commands = [Collections.Generic.List[object]]::new()
        $invocations = [Collections.Generic.List[object]]::new()
        $assets = [Collections.Generic.List[object]]::new()
        $commandLines = [Collections.Generic.List[string]]::new()
        $restoreLines = [Collections.Generic.List[string]]::new()
        $outputLines = [Collections.Generic.List[string]]::new()
        $assetLines = [Collections.Generic.List[string]]::new()
        $cache = Join-Path $testRoot 'packages'
        $config = Join-Path $testRoot "work/$label/NuGet.Config"
        for ($i = 0; $i -lt 4; $i++) {
            $planned = $Plan.clientSigningInputs[$i]
            $project = "src/$($projects[$i])/$($projects[$i]).csproj"
            $base = [ordered]@{
                ordinal = $i + 1
                role = $planned.role
                projectRelativePath = $project
                arguments = @()
                startedAtUtc = '2026-09-01T00:00:00Z'
                completedAtUtc = '2026-09-01T00:00:00Z'
                exitCode = 0
                stdoutBytes = 0
                stdoutSha256 = Get-TextSha256 ''
                stderrBytes = 0
                stderrSha256 = Get-TextSha256 ''
            }
            $base.arguments = @('restore', (Join-Path $source $project.Replace('/', [IO.Path]::DirectorySeparatorChar)),
                '--locked-mode', '--disable-parallel', '--configfile', $config, '--packages', $cache)
            $publishArguments = @(Get-PersonalPublishContractArguments $run $intent $project $planned.role)
            $base.arguments += @('-p:Configuration=Release')
            $base.arguments += @($publishArguments | Where-Object {
                $_.StartsWith('-p:', [StringComparison]::Ordinal) -and
                $_ -cne '-p:PublishSingleFile=true'
            })
            $commands.Add((Copy-JsonValue $base))
            $normalized = @($base.arguments | ForEach-Object {
                ([string]$_).Replace($source, '<SOURCE>').Replace($cache, '<OFFLINE_PACKAGE_CACHE>').Replace($config, '<OFFLINE_NUGET_CONFIG>')
            })
            $restoreLines.Add("$($i + 1)|$($planned.role)|$project|$($normalized -join [char]0x1f)")
            $base.arguments = $publishArguments
            $normalized = @($base.arguments | ForEach-Object {
                ([string]$_).Replace($source, '<SOURCE>').Replace([string]$run.outputRootPath, '<OUTPUT>')
            })
            $commandLines.Add("$($i + 1)|$($planned.role)|$project|$($normalized -join [char]0x1f)")
            # Minimal PE-shaped fixture, deliberately not an executable release.
            $bytes = [byte[]]::new(512)
            $bytes[0] = 0x4d; $bytes[1] = 0x5a; $bytes[0x3c] = 0x80
            $bytes[0x80] = 0x50; $bytes[0x81] = 0x45
            $bytes[0x94] = 0xf0; $bytes[0x98] = 0x0b; $bytes[0x99] = 0x02
            $bytes[511] = $i + 1
            $relative = "build-artifacts/$label/$($planned.role)/$($planned.fileName)"
            $path = Join-Path $testRoot $relative
            [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($path)) | Out-Null
            [IO.File]::WriteAllBytes($path, $bytes)
            $output = [ordered]@{
                role = $planned.role
                fileName = $planned.fileName
                relativePath = $relative
                sizeBytes = $bytes.LongLength
                sha256 = Get-Sha256 $path
                peContentSha256 = ProductionReleaseState\Get-PeContentSha256 -Bytes $bytes
                authenticodeStatus = 'NotSigned'
            }
            if ($label -ceq 'isolated-a') {
                $planned.path = $path
                foreach ($name in @('sizeBytes', 'sha256', 'peContentSha256')) { $planned.$name = $output.$name }
            }
            $base['output'] = $output
            $invocations.Add((Copy-JsonValue $base))
            $outputLines.Add("$($output.role)|$($output.fileName)|$($output.sizeBytes)|$($output.sha256)|$($output.peContentSha256)")
            $assets.Add((New-FileDescriptor $testRoot "work/$label/source/src/$($projects[$i])/obj/project.assets.json" '{"syntheticOnly":true}'))
        }
        $sortedAssets = @($assets | Sort-Object relativePath)
        foreach ($asset in $sortedAssets) { $assetLines.Add("$($asset.relativePath)|$($asset.sizeBytes)|$($asset.sha256)") }
        $run.restore = [ordered]@{
            packageCacheRootPath = $cache
            packageCacheRootPhysicalIdentitySha256 = Get-TextSha256 'controlled-package-cache'
            commands = @($commands)
            commandContractSha256 = Get-PersonalBuildDigest @($restoreLines)
            assets = $sortedAssets
            assetsClosureSha256 = Get-PersonalBuildDigest @($assetLines)
        }
        $run.invocations = @($invocations)
        $accountSelfCheckJson =
            '{"schemaVersion":1,"product":"ensou-dsh-personal","component":"launcher","personalAccountOrigin":"' +
            [string]$intent.personalAccountOrigin + '"}'
        $accountSelfCheckDescriptor = New-FileDescriptor `
            -Root $testRoot `
            -RelativePath "builds/$label-personal-account-self-check.json" `
            -Content $accountSelfCheckJson
        $run.personalAccountSelfCheck = [ordered]@{
            command = '--personal-account-self-check'
            executableSha256 = [string]$invocations[2].output.sha256
            startedAtUtc = '2026-09-01T00:00:01Z'
            completedAtUtc = '2026-09-01T00:00:01Z'
            exitCode = 0
            stdout = $accountSelfCheckDescriptor
            stderrBytes = 0
            stderrSha256 = Get-TextSha256 ''
        }
        $run.outputClosureSha256 = Get-PersonalBuildDigest @($outputLines)
        $commandDigest = Get-PersonalBuildDigest @($commandLines)
        $runs.Add((Copy-JsonValue $run))
    }
    return [ordered]@{
        schemaVersion = 1
        evidenceType = 'ensou-dsh-personal-two-clean-production-build-evidence'
        unsignedProductionCandidate = $true
        productionAdmission = 'NO_GO'
        producerScriptSha256 = Get-TextSha256 'synthetic-producer'
        buildIntent = $intentDescriptor
        sourceCommit = $Plan.sourceCommit
        sourceTree = $SourceTree
        sourceInventorySha256 = Get-TextSha256 'source-inventory'
        dependencyClosureSha256 = Get-TextSha256 'dependency-closure'
        sdk = [ordered]@{ path = 'C:\controlled\dotnet.exe'; version = '10.0.302'; sizeBytes = 512; sha256 = (Get-TextSha256 'sdk') }
        commandContractSha256 = $commandDigest
        runs = @($runs)
        restoreClosureSha256 = Get-PersonalRestoreDigest @($runs)
        outputsByteIdentical = $true
        combinedOutputClosureSha256 = $runs[0].outputClosureSha256
        result = 'PASS'
    }
}

function Assert-Rejected($Evidence, [string]$Name, [string]$MessagePattern = '') {
    $path = Join-Path $testRoot "$Name.json"
    Write-Json -Path $path -Value $Evidence
    $failed = $false
    $failure = ''
    try {
        & $validator -PlanPath $script:planPath -EvidencePath $path | Out-Null
    }
    catch {
        $failed = $true
        $failure = $_.ToString()
    }
    Assert-True $failed "$Name was accepted unexpectedly."
    if ($MessagePattern) {
        Assert-True ($failure -match $MessagePattern) `
            "$Name failed for the wrong reason: $failure"
    }
}

try {
    [IO.Directory]::CreateDirectory($testRoot) | Out-Null

    $plan = Get-Content -LiteralPath $planTemplatePath -Raw |
        ConvertFrom-Json -Depth 64 -DateKind String
    $plan.PSObject.Properties.Remove('personalPilotTemplateStatus')
    if ($null -eq $plan.PSObject.Properties['personalAccountOrigin']) {
        $plan | Add-Member -NotePropertyName personalAccountOrigin `
            -NotePropertyValue 'https://personal.example.invalid/'
    }
    else {
        $plan.personalAccountOrigin = 'https://personal.example.invalid/'
    }
    $plan.sourceCommit = Get-TextSha256 'launcher-source-commit'
    $plan.runtimeCandidate.metadata.sha256 = Get-TextSha256 'runtime-metadata'
    $plan.runtimeCandidate.hashEvidence.sha256 = Get-TextSha256 'runtime-hash-evidence'
    $plan.authenticodePolicy.signerSha256Thumbprint =
        Get-TextSha256 'personal-pilot-signer-certificate'
    for ($inputIndex = 0;
         $inputIndex -lt $plan.clientSigningInputs.Count;
         $inputIndex++) {
        $input = $plan.clientSigningInputs[$inputIndex]
        $input.sizeBytes = 512 + $inputIndex
        $input.sha256 = Get-TextSha256 ("client-input-$([string]$input.role)")
        $input.peContentSha256 =
            Get-TextSha256 ("client-pe-content-$([string]$input.role)")
    }

    $evidence = Get-Content -LiteralPath $evidenceTemplatePath -Raw |
        ConvertFrom-Json -Depth 64 -DateKind String
    $candidateContents = [ordered]@{
        installer = 'exact-signed-personal-installer-candidate'
        manifest = '{"schemaVersion":2,"releaseSetId":"personal-pilot-2026.09.04.2"}'
        client = 'exact-signed-personal-client-candidate'
        runtime = 'exact-source-runtime-candidate'
    }
    $evidence.candidateClosure.client.fileName =
        'EnsouDshPersonalClient-personal-pilot-2026.09.04.2-win-x64.zip'
    $evidence.candidateClosure.client.relativePath =
        'candidate/EnsouDshPersonalClient-personal-pilot-2026.09.04.2-win-x64.zip'
    $evidence.candidateClosure.runtime.fileName =
        [string]$plan.runtimeCandidate.archive.fileName
    $evidence.candidateClosure.runtime.relativePath =
        "candidate/$([string]$plan.runtimeCandidate.archive.fileName)"
    foreach ($componentName in @('installer', 'manifest', 'client', 'runtime')) {
        $component = $evidence.candidateClosure.$componentName
        $descriptor = New-FileDescriptor -Root $testRoot `
            -RelativePath ([string]$component.relativePath) `
            -Content ([string]$candidateContents[$componentName])
        $component.sizeBytes = [int64]$descriptor.sizeBytes
        $component.sha256 = [string]$descriptor.sha256
    }
    $plan.runtimeCandidate.archive.sizeBytes =
        [int64]$evidence.candidateClosure.runtime.sizeBytes
    $plan.runtimeCandidate.archive.sha256 =
        [string]$evidence.candidateClosure.runtime.sha256
    $script:planPath = Join-Path $testRoot 'personal-pilot-plan.json'
    Write-Json -Path $script:planPath -Value $plan

    $evidence.planSha256 = Get-Sha256 $script:planPath
    $evidence.overallResult = 'PASS'
    $sourceTree = Get-TextSha256 'launcher-source-tree'
    $evidence.reproducibleBuild.sourceCommit = [string]$plan.sourceCommit
    $evidence.reproducibleBuild.sourceTree = $sourceTree
    $evidence.reproducibleBuild.result = 'PASS'
    $buildReceipt = New-ReproducibleBuildEvidence -Plan $plan -SourceTree $sourceTree
    $evidence.reproducibleBuild.receipt = New-FileDescriptor $testRoot 'builds/two-clean-build-evidence.v1.json' (
        $buildReceipt | ConvertTo-Json -Depth 64 -Compress)
    Write-Json -Path $script:planPath -Value $plan
    $evidence.planSha256 = Get-Sha256 $script:planPath
    $evidence.candidateClosureSha256 = Get-ClosureSha256 $evidence
    $observedAt = [DateTimeOffset]::UtcNow.AddMinutes(-1).ToString(
        'yyyy-MM-ddTHH:mm:ss.fffffffZ',
        [Globalization.CultureInfo]::InvariantCulture)
    $identityCreatedAt = [DateTimeOffset]::UtcNow.AddMinutes(-2).ToString(
        'yyyy-MM-ddTHH:mm:ss.fffffffzzz',
        [Globalization.CultureInfo]::InvariantCulture)
    $laneCapturedAt = [DateTimeOffset]::UtcNow.AddMinutes(-3).ToString(
        'yyyy-MM-ddTHH:mm:ss.fffffffZ',
        [Globalization.CultureInfo]::InvariantCulture)
    $evidence.completedAtUtc = [DateTimeOffset]::UtcNow.ToString(
        'yyyy-MM-ddTHH:mm:ss.fffffffZ',
        [Globalization.CultureInfo]::InvariantCulture)

    foreach ($device in @($evidence.devices)) {
        $isExistingLane = [string]$device.deviceId -ceq 'pilot-desktop-desktop'
        $laneReceipt = [ordered]@{
            schemaVersion = 1
            evidenceType = 'ensou-dsh-personal-pilot-lane-precondition'
            deviceId = [string]$device.deviceId
            lane = [string]$device.lane
            capturedAtUtc = $laneCapturedAt
            managedRootState = if ($isExistingLane) {
                'EXISTING_INSTALL_PRESENT'
            } else {
                'ABSENT'
            }
            currentPointerPresent = $isExistingLane
            startupRegistrationPresent = $isExistingLane
            baselineReleaseSetId = if ($isExistingLane) {
                'personal-existing-baseline-v1'
            } else {
                $null
            }
            baselineCurrentPointerSha256 = if ($isExistingLane) {
                Get-TextSha256 'pilot-desktop-existing-current-pointer'
            } else {
                $null
            }
            source = 'real-device'
            result = 'PASS'
        }
        $lanePath =
            "devices/$([string]$device.deviceId)/lane-precondition.v1.json"
        $device.lanePrecondition = New-FileDescriptor `
            -Root $testRoot -RelativePath $lanePath `
            -Content ($laneReceipt | ConvertTo-Json -Depth 16 -Compress)
        $device.installationId = [Guid]::NewGuid().ToString().ToLowerInvariant()
        $stateBindingSha256 = Get-TextSha256 `
            ("state-binding-$([string]$device.deviceId)")
        $identityPath =
            "devices/$([string]$device.deviceId)/installation-identity.v1.json"
        $device.identityReceipt = New-FileDescriptor `
            -Root $testRoot -RelativePath $identityPath `
            -Content ('{"schemaVersion":1,"receiptType":"ensou-dsh-personal-installation-identity","product":"ensou-dsh-personal","installationId":"' +
                [string]$device.installationId + '","createdAtUtc":"' +
                $identityCreatedAt + '","stateBindingSha256":"' +
                $stateBindingSha256 + '"}')
        foreach ($result in @($device.results)) {
            $result.installationId = [string]$device.installationId
            $result.identityReceiptSha256 =
                [string]$device.identityReceipt.sha256
            $result.candidateClosureSha256 =
                [string]$evidence.candidateClosureSha256
            $result.observedAtUtc = $observedAt
            $result.source = 'real-device'
            $result.result = 'PASS'
            $checkPath =
                "devices/$([string]$device.deviceId)/checks/$([string]$result.checkId).json"
            $result.evidence = New-FileDescriptor `
                -Root $testRoot -RelativePath $checkPath `
                -Content ('{"schemaVersion":1,"evidenceType":"ensou-dsh-personal-pilot-check-observation","deviceId":"' +
                    [string]$device.deviceId + '","installationId":"' +
                    [string]$device.installationId +
                    '","identityReceiptSha256":"' +
                    [string]$device.identityReceipt.sha256 +
                    '","checkId":"' + [string]$result.checkId +
                    '","candidateClosureSha256":"' +
                    [string]$evidence.candidateClosureSha256 +
                    '","observedAtUtc":"' + $observedAt +
                    '","source":"real-device","result":"PASS"}')
        }
    }
    $evidencePath = Join-Path $testRoot 'personal-dual-pilot-evidence.json'
    Write-Json -Path $evidencePath -Value $evidence
    $result = @(& $validator -PlanPath $script:planPath `
        -EvidencePath $evidencePath)
    Assert-True ($result.Count -eq 1 -and $result[0].Result -ceq 'PASS') `
        'Valid dual-device evidence did not return one PASS record.'
    Assert-True ($result[0].DeviceCount -eq 2 -and
        $result[0].CheckCount -eq 16 -and
        $result[0].ReproducibleBuildCount -eq 2 -and
        $result[0].CandidateFileCount -eq 4 -and
        $result[0].ExistingUpgradeLane -ceq 'PILOT-DESKTOP' -and
        $result[0].CleanInstallLane -ceq 'PilotNotebook notebook' -and
        $result[0].InstallationIdsDistinct -eq $true) `
        'Valid dual-device evidence summary is incomplete.'

    $sameIdentity = Copy-JsonValue $evidence
    $sameIdentity.devices[1].installationId =
        [string]$sameIdentity.devices[0].installationId
    foreach ($check in @($sameIdentity.devices[1].results)) {
        $check.installationId = [string]$sameIdentity.devices[1].installationId
    }
    Assert-Rejected $sameIdentity 'same-installation-id' 'distinct installation UUIDs'

    $placeholderIdentity = Copy-JsonValue $evidence
    $placeholderIdentity.devices[0].installationId =
        '00000000-0000-4000-8000-000000000001'
    foreach ($check in @($placeholderIdentity.devices[0].results)) {
        $check.installationId =
            [string]$placeholderIdentity.devices[0].installationId
    }
    Assert-Rejected $placeholderIdentity 'placeholder-installation-id' `
        'not a real canonical UUID v4'

    $wrongClosure = Copy-JsonValue $evidence
    $wrongClosure.devices[1].results[3].candidateClosureSha256 =
        Get-TextSha256 'different-candidate-closure'
    Assert-Rejected $wrongClosure 'mixed-candidate-closure' `
        'exact candidate closure'

    $wrongRuntime = Copy-JsonValue $evidence
    $wrongRuntime.candidateClosure.runtime.sha256 =
        Get-TextSha256 'runtime-not-in-the-plan'
    $wrongRuntime.candidateClosureSha256 = Get-ClosureSha256 $wrongRuntime
    foreach ($device in @($wrongRuntime.devices)) {
        foreach ($check in @($device.results)) {
            $check.candidateClosureSha256 =
                [string]$wrongRuntime.candidateClosureSha256
        }
    }
    Assert-Rejected $wrongRuntime 'runtime-not-bound-to-plan' `
        'differs from the exact plan.runtimeCandidate archive'

    $zeroHash = Copy-JsonValue $evidence
    $zeroHash.devices[0].results[2].evidence.sha256 = '0' * 64
    Assert-Rejected $zeroHash 'zero-evidence-hash'

    $notRealDevice = Copy-JsonValue $evidence
    $notRealDevice.devices[0].results[0].source = 'template'
    Assert-Rejected $notRealDevice 'non-real-device-source'

    $wrongRole = Copy-JsonValue $evidence
    $wrongRole.devices[0].results[0].checkId = 'first-install'
    Assert-Rejected $wrongRole 'role-check-on-wrong-device'

    $existingLanePath = Join-Path $testRoot `
        'devices\pilot-desktop-desktop\lane-precondition.v1.json'
    $existingLaneOriginal = [IO.File]::ReadAllBytes($existingLanePath)
    try {
        $falseExistingLane = Copy-JsonValue $evidence
        $laneReceipt = Get-Content -LiteralPath $existingLanePath -Raw |
            ConvertFrom-Json -Depth 16 -DateKind String
        $laneReceipt.managedRootState = 'ABSENT'
        $laneReceipt.currentPointerPresent = $false
        [IO.File]::WriteAllText(
            $existingLanePath,
            ($laneReceipt | ConvertTo-Json -Depth 16 -Compress),
            $utf8)
        Set-LaneDescriptorFromPath -Evidence $falseExistingLane `
            -DeviceIndex 0 -Path $existingLanePath
        Assert-Rejected $falseExistingLane `
            'pilot-desktop-without-existing-install-precondition'
    }
    finally {
        [IO.File]::WriteAllBytes($existingLanePath, $existingLaneOriginal)
        [Array]::Clear(
            $existingLaneOriginal,
            0,
            $existingLaneOriginal.Length)
    }

    $cleanLanePath = Join-Path $testRoot `
        'devices\pilot-notebook\lane-precondition.v1.json'
    $cleanLaneOriginal = [IO.File]::ReadAllBytes($cleanLanePath)
    try {
        $falseCleanLane = Copy-JsonValue $evidence
        $laneReceipt = Get-Content -LiteralPath $cleanLanePath -Raw |
            ConvertFrom-Json -Depth 16 -DateKind String
        $laneReceipt.currentPointerPresent = $true
        [IO.File]::WriteAllText(
            $cleanLanePath,
            ($laneReceipt | ConvertTo-Json -Depth 16 -Compress),
            $utf8)
        Set-LaneDescriptorFromPath -Evidence $falseCleanLane `
            -DeviceIndex 1 -Path $cleanLanePath
        Assert-Rejected $falseCleanLane `
            'example-notebook-with-existing-pointer-precondition'
    }
    finally {
        [IO.File]::WriteAllBytes($cleanLanePath, $cleanLaneOriginal)
        [Array]::Clear(
            $cleanLaneOriginal,
            0,
            $cleanLaneOriginal.Length)
    }

    $identityReceiptPath = Join-Path $testRoot `
        'devices\pilot-desktop-desktop\installation-identity.v1.json'
    $identityReceiptOriginal = [IO.File]::ReadAllBytes($identityReceiptPath)
    try {
        $wrongReceiptId = Copy-JsonValue $evidence
        $otherInstallationId = [Guid]::NewGuid().ToString().ToLowerInvariant()
        [IO.File]::WriteAllText(
            $identityReceiptPath,
            ('{"schemaVersion":1,"receiptType":"ensou-dsh-personal-installation-identity","product":"ensou-dsh-personal","installationId":"' +
                $otherInstallationId + '","createdAtUtc":"' +
                $identityCreatedAt + '","stateBindingSha256":"' +
                (Get-TextSha256 'state-binding-pilot-desktop-desktop') + '"}'),
            $utf8)
        Set-IdentityDescriptorFromPath -Evidence $wrongReceiptId `
            -DeviceIndex 0 -Path $identityReceiptPath
        Assert-Rejected $wrongReceiptId 'receipt-installation-id-mismatch' `
            'differs from its copied identity receipt'
    }
    finally {
        [IO.File]::WriteAllBytes($identityReceiptPath, $identityReceiptOriginal)
    }

    try {
        $wrongReceiptProduct = Copy-JsonValue $evidence
        [IO.File]::WriteAllText(
            $identityReceiptPath,
            ('{"schemaVersion":1,"receiptType":"ensou-dsh-personal-installation-identity","product":"wrong-product","installationId":"' +
                [string]$evidence.devices[0].installationId +
                '","createdAtUtc":"' + $identityCreatedAt +
                '","stateBindingSha256":"' +
                (Get-TextSha256 'state-binding-pilot-desktop-desktop') + '"}'),
            $utf8)
        Set-IdentityDescriptorFromPath -Evidence $wrongReceiptProduct `
            -DeviceIndex 0 -Path $identityReceiptPath
        Assert-Rejected $wrongReceiptProduct 'receipt-wrong-product' `
            'identity receipt contract is invalid'
    }
    finally {
        [IO.File]::WriteAllBytes($identityReceiptPath, $identityReceiptOriginal)
    }

    try {
        $nonCanonicalReceipt = Copy-JsonValue $evidence
        [IO.File]::AppendAllText($identityReceiptPath, "`n", $utf8)
        Set-IdentityDescriptorFromPath -Evidence $nonCanonicalReceipt `
            -DeviceIndex 0 -Path $identityReceiptPath
        Assert-Rejected $nonCanonicalReceipt 'receipt-noncanonical-bytes' `
            'not exact canonical product JSON'
    }
    finally {
        [IO.File]::WriteAllBytes($identityReceiptPath, $identityReceiptOriginal)
        [Array]::Clear(
            $identityReceiptOriginal,
            0,
            $identityReceiptOriginal.Length)
    }

    $pilotNotebookIdentityPath = Join-Path $testRoot `
        'devices\pilot-notebook\installation-identity.v1.json'
    $pilotNotebookIdentityOriginal = [IO.File]::ReadAllBytes(
        $pilotNotebookIdentityPath)
    try {
        $sameStateBinding = Copy-JsonValue $evidence
        [IO.File]::WriteAllText(
            $pilotNotebookIdentityPath,
            ('{"schemaVersion":1,"receiptType":"ensou-dsh-personal-installation-identity","product":"ensou-dsh-personal","installationId":"' +
                [string]$evidence.devices[1].installationId +
                '","createdAtUtc":"' + $identityCreatedAt +
                '","stateBindingSha256":"' +
                (Get-TextSha256 'state-binding-pilot-desktop-desktop') + '"}'),
            $utf8)
        Set-IdentityDescriptorFromPath -Evidence $sameStateBinding `
            -DeviceIndex 1 -Path $pilotNotebookIdentityPath
        Assert-Rejected $sameStateBinding 'same-state-binding' `
            'distinct state bindings'
    }
    finally {
        [IO.File]::WriteAllBytes(
            $pilotNotebookIdentityPath,
            $pilotNotebookIdentityOriginal)
        [Array]::Clear(
            $pilotNotebookIdentityOriginal,
            0,
            $pilotNotebookIdentityOriginal.Length)
    }

    $templatePlan = Get-Content -LiteralPath $planTemplatePath -Raw |
        ConvertFrom-Json -Depth 64 -DateKind String
    $templatePlanPath = Join-Path $testRoot 'no-go-template-plan.json'
    Write-Json -Path $templatePlanPath -Value $templatePlan
    $templateRejected = $false
    try {
        & $validator -PlanPath $templatePlanPath -EvidencePath $evidencePath |
            Out-Null
    }
    catch {
        $templateRejected = $_.ToString() -match 'NO-GO.*template'
    }
    Assert-True $templateRejected `
        'Production evidence validator accepted the NO_GO plan template.'

    $zeroClientPlan = Copy-JsonValue $plan
    $zeroClientPlan.clientSigningInputs[0].sha256 = '0' * 64
    $zeroClientPlanPath = Join-Path $testRoot 'zero-client-plan.json'
    Write-Json -Path $zeroClientPlanPath -Value $zeroClientPlan
    $zeroClientPlanRejected = $false
    try {
        & $validator -PlanPath $zeroClientPlanPath `
            -EvidencePath $evidencePath | Out-Null
    }
    catch {
        $zeroClientPlanRejected =
            $_.ToString() -match 'Plan client input.*placeholder SHA-256'
    }
    Assert-True $zeroClientPlanRejected `
        'Production evidence validator accepted a zero client-input hash.'

    $placeholderSourcePlan = Copy-JsonValue $plan
    $placeholderSourcePlan.sourceCommit = '0' * 40
    $placeholderSourcePlanPath = Join-Path $testRoot `
        'placeholder-source-plan.json'
    Write-Json -Path $placeholderSourcePlanPath -Value $placeholderSourcePlan
    $placeholderSourceRejected = $false
    try {
        & $validator -PlanPath $placeholderSourcePlanPath `
            -EvidencePath $evidencePath | Out-Null
    }
    catch {
        $placeholderSourceRejected =
            $_.ToString() -match 'placeholder Git object'
    }
    Assert-True $placeholderSourceRejected `
        'Production evidence validator accepted a placeholder source commit.'

    $receiptPath = Join-Path $testRoot 'builds/two-clean-build-evidence.v1.json'
    $receiptOriginal = [IO.File]::ReadAllBytes($receiptPath)
    $mutations = @(
        @{ Name = 'reused-reproducible-build-id'; Pattern = 'two distinct build IDs'; Change = { param($r) $r.runs[1].buildId = $r.runs[0].buildId } },
        @{ Name = 'different-reproducible-build-output'; Pattern = 'produced different.*sha256'; Change = { param($r) $r.runs[1].invocations[2].output.sha256 = Get-TextSha256 'different-isolated-launcher-output' } },
        @{ Name = 'reused-materialized-checkout'; Pattern = 'two distinct build IDs'; Change = { param($r) $r.runs[1].materializedCheckoutPhysicalIdentitySha256 = $r.runs[0].materializedCheckoutPhysicalIdentitySha256 } },
        @{ Name = 'restore-not-locked'; Pattern = 'restore command argument'; Change = { param($r) $r.runs[0].restore.commands[0].arguments[2] = '--force' } },
        @{ Name = 'restore-global-publish-leak'; Pattern = ''; Change = { param($r) $r.runs[0].restore.commands[0].arguments += @('--runtime', 'win-x64', '-p:SelfContained=true', '-p:PublishSingleFile=true') } },
        @{ Name = 'publish-development-bypass'; Pattern = 'publish command argument'; Change = { param($r) $r.runs[0].invocations[0].arguments[17] = '-p:PersonalDevelopmentPublish=true' } },
        @{ Name = 'publish-account-origin-omitted'; Pattern = 'publish command argument'; Change = { param($r) $r.runs[0].invocations[2].arguments = @($r.runs[0].invocations[2].arguments | Where-Object { $_ -cne '-p:PersonalAccountOrigin=https://personal.example.invalid/' }) } },
        @{ Name = 'restore-account-origin-omitted'; Pattern = ''; Change = { param($r) $r.runs[0].restore.commands[2].arguments = @($r.runs[0].restore.commands[2].arguments | Where-Object { $_ -cne '-p:PersonalAccountOrigin=https://personal.example.invalid/' }) } },
        @{ Name = 'wrong-account-probe-pe-binding'; Pattern = 'account self-check does not bind'; Change = { param($r) $r.runs[0].personalAccountSelfCheck.executableSha256 = Get-TextSha256 'different-launcher-pe' } },
        @{ Name = 'account-probe-before-publish'; Pattern = 'account self-check chronology'; Change = { param($r) $r.runs[0].personalAccountSelfCheck.startedAtUtc = '2026-08-31T23:59:59Z'; $r.runs[0].personalAccountSelfCheck.completedAtUtc = '2026-08-31T23:59:59Z' } },
        @{ Name = 'missing-account-probe'; Pattern = ''; Change = { param($r) $r.runs[0].PSObject.Properties.Remove('personalAccountSelfCheck') } },
        @{ Name = 'wrong-output-closure'; Pattern = 'closure digest differs'; Change = { param($r) $r.combinedOutputClosureSha256 = Get-TextSha256 'wrong-output-closure' } },
        @{ Name = 'wrong-restore-closure'; Pattern = 'restore closure digest differs'; Change = { param($r) $r.restoreClosureSha256 = Get-TextSha256 'wrong-restore-closure' } },
        @{ Name = 'missing-restore-assets'; Pattern = ''; Change = { param($r) $r.runs[0].restore.PSObject.Properties.Remove('assets') } },
        @{ Name = 'legacy-installer-output'; Pattern = ''; Change = { param($r) $r.runs[0].invocations += Copy-JsonValue $r.runs[0].invocations[3] } }
    )
    foreach ($mutation in $mutations) {
        try {
            $changedEvidence = Copy-JsonValue $evidence
            $receipt = $utf8.GetString($receiptOriginal) | ConvertFrom-Json -Depth 64 -DateKind String
            & $mutation.Change $receipt
            [IO.File]::WriteAllText($receiptPath, ($receipt | ConvertTo-Json -Depth 64 -Compress), $utf8)
            Set-RunDescriptorFromPath -Evidence $changedEvidence -Path $receiptPath
            Assert-Rejected $changedEvidence $mutation.Name $mutation.Pattern
        } finally { [IO.File]::WriteAllBytes($receiptPath, $receiptOriginal) }
    }

    $accountProbePath = Join-Path $testRoot `
        'builds\isolated-a-personal-account-self-check.json'
    $accountProbeOriginal = [IO.File]::ReadAllBytes($accountProbePath)
    $accountProbeMutations = @(
        @{
            Name = 'account-probe-wrong-origin'
            Pattern = 'self-check metadata is invalid'
            Content = '{"schemaVersion":1,"product":"ensou-dsh-personal","component":"launcher","personalAccountOrigin":"https://other.example.invalid/"}'
        },
        @{
            Name = 'account-probe-duplicate-property'
            Pattern = 'self-check metadata is invalid'
            Content = '{"schemaVersion":1,"product":"ensou-dsh-personal","component":"launcher","personalAccountOrigin":"https://personal.example.invalid/","personalAccountOrigin":"https://personal.example.invalid/"}'
        },
        @{
            Name = 'account-probe-noncanonical-newline'
            Pattern = 'self-check metadata is invalid'
            Content = '{"schemaVersion":1,"product":"ensou-dsh-personal","component":"launcher","personalAccountOrigin":"https://personal.example.invalid/"}' + "`n"
        }
    )
    foreach ($mutation in $accountProbeMutations) {
        try {
            $changedEvidence = Copy-JsonValue $evidence
            [IO.File]::WriteAllText($accountProbePath, $mutation.Content, $utf8)
            $receipt = $utf8.GetString($receiptOriginal) |
                ConvertFrom-Json -Depth 64 -DateKind String
            $receipt.runs[0].personalAccountSelfCheck.stdout.sizeBytes =
                (Get-Item -LiteralPath $accountProbePath).Length
            $receipt.runs[0].personalAccountSelfCheck.stdout.sha256 =
                Get-Sha256 $accountProbePath
            [IO.File]::WriteAllText(
                $receiptPath,
                ($receipt | ConvertTo-Json -Depth 64 -Compress),
                $utf8)
            Set-RunDescriptorFromPath -Evidence $changedEvidence -Path $receiptPath
            Assert-Rejected $changedEvidence $mutation.Name $mutation.Pattern
        }
        finally {
            [IO.File]::WriteAllBytes($accountProbePath, $accountProbeOriginal)
            [IO.File]::WriteAllBytes($receiptPath, $receiptOriginal)
        }
    }
    [Array]::Clear($accountProbeOriginal, 0, $accountProbeOriginal.Length)

    $legacy = Copy-JsonValue $evidence
    $legacy.reproducibleBuild.contract = 'two-clean-isolated-builds-v1'
    $legacy.reproducibleBuild | Add-Member -NotePropertyName runA -NotePropertyValue $legacy.reproducibleBuild.receipt
    $legacy.reproducibleBuild | Add-Member -NotePropertyName runB -NotePropertyValue $legacy.reproducibleBuild.receipt
    $legacy.reproducibleBuild.PSObject.Properties.Remove('receipt')
    Assert-Rejected $legacy 'legacy-five-file-receipts-rejected'

    $assetPath = Join-Path $testRoot $buildReceipt.runs[0].restore.assets[0].relativePath
    $assetOriginal = [IO.File]::ReadAllBytes($assetPath)
    try {
        [IO.File]::AppendAllText($assetPath, 'tampered', $utf8)
        Assert-Rejected (Copy-JsonValue $evidence) 'tampered-restore-assets' 'restore asset bytes differ'
    } finally { [IO.File]::WriteAllBytes($assetPath, $assetOriginal) }

    $unsignedPath = Join-Path $testRoot $buildReceipt.runs[0].invocations[0].output.relativePath
    $unsignedOriginal = [IO.File]::ReadAllBytes($unsignedPath)
    try {
        [IO.File]::AppendAllText($unsignedPath, 'tampered', $utf8)
        Assert-Rejected (Copy-JsonValue $evidence) 'tampered-unsigned-output' 'unsigned startup-stub bytes differ'
    } finally { [IO.File]::WriteAllBytes($unsignedPath, $unsignedOriginal) }

    $intentPath = Join-Path $testRoot 'builds/build-intent.v1.json'
    $intentOriginal = [IO.File]::ReadAllBytes($intentPath)
    $intentOriginMutations = @(
        @{
            Name = 'intent-missing-account-origin'
            Pattern = ''
            Change = {
                param($value)
                $value.PSObject.Properties.Remove('personalAccountOrigin')
            }
        },
        @{
            Name = 'intent-account-origin-differs-from-plan'
            Pattern = 'differs from the exact plan'
            Change = {
                param($value)
                $value.personalAccountOrigin = 'https://other.example.invalid/'
            }
        }
    )
    foreach ($mutation in $intentOriginMutations) {
        try {
            $changedEvidence = Copy-JsonValue $evidence
            $changedIntent = $utf8.GetString($intentOriginal) |
                ConvertFrom-Json -Depth 64 -DateKind String
            & $mutation.Change $changedIntent
            [IO.File]::WriteAllText(
                $intentPath,
                ($changedIntent | ConvertTo-Json -Depth 64 -Compress),
                $utf8)
            $receipt = $utf8.GetString($receiptOriginal) |
                ConvertFrom-Json -Depth 64 -DateKind String
            $receipt.buildIntent.sha256 = Get-Sha256 $intentPath
            $receipt.buildIntent.sizeBytes =
                (Get-Item -LiteralPath $intentPath).Length
            [IO.File]::WriteAllText(
                $receiptPath,
                ($receipt | ConvertTo-Json -Depth 64 -Compress),
                $utf8)
            Set-RunDescriptorFromPath -Evidence $changedEvidence -Path $receiptPath
            Assert-Rejected $changedEvidence $mutation.Name $mutation.Pattern
        }
        finally {
            [IO.File]::WriteAllBytes($intentPath, $intentOriginal)
            [IO.File]::WriteAllBytes($receiptPath, $receiptOriginal)
        }
    }

    try {
        $changedEvidence = Copy-JsonValue $evidence
        $intent = $utf8.GetString($intentOriginal) | ConvertFrom-Json -Depth 64 -DateKind String
        $intent.releaseManifestTrust.keyId = 'different-valid-key'
        [IO.File]::WriteAllText($intentPath, ($intent | ConvertTo-Json -Depth 64 -Compress), $utf8)
        $receipt = $utf8.GetString($receiptOriginal) | ConvertFrom-Json -Depth 64 -DateKind String
        $receipt.buildIntent.sha256 = Get-Sha256 $intentPath
        $receipt.buildIntent.sizeBytes = (Get-Item -LiteralPath $intentPath).Length
        [IO.File]::WriteAllText($receiptPath, ($receipt | ConvertTo-Json -Depth 64 -Compress), $utf8)
        Set-RunDescriptorFromPath -Evidence $changedEvidence -Path $receiptPath
        Assert-Rejected $changedEvidence 'intent-trust-differs-from-plan' 'release trust differs'
    } finally {
        [IO.File]::WriteAllBytes($intentPath, $intentOriginal)
        [IO.File]::WriteAllBytes($receiptPath, $receiptOriginal)
    }

    $candidateClientPath = Join-Path $testRoot `
        'candidate\EnsouDshPersonalClient-personal-pilot-2026.09.04.2-win-x64.zip'
    $candidateClientOriginal = [IO.File]::ReadAllBytes($candidateClientPath)
    try {
        [IO.File]::AppendAllText($candidateClientPath, 'tampered', $utf8)
        Assert-Rejected (Copy-JsonValue $evidence) `
            'tampered-candidate-file' 'Candidate client bytes differ'
    }
    finally {
        [IO.File]::WriteAllBytes($candidateClientPath, $candidateClientOriginal)
        [Array]::Clear(
            $candidateClientOriginal,
            0,
            $candidateClientOriginal.Length)
    }

    $tamperedEvidence = Copy-JsonValue $evidence
    $tamperedDescriptor = $tamperedEvidence.devices[1].results[7].evidence
    $tamperedPath = Join-Path $testRoot `
        ([string]$tamperedDescriptor.relativePath).Replace(
            '/',
            [IO.Path]::DirectorySeparatorChar)
    [IO.File]::AppendAllText($tamperedPath, 'tampered', $utf8)
    Assert-Rejected $tamperedEvidence 'tampered-evidence-file' `
        'bytes differ'

    $completed = $true
    Write-Output "PASS Personal dual-device Pilot evidence contract assertions=$assertions (synthetic fixtures only)."
}
finally {
    if ($completed -and (Test-Path -LiteralPath $testRoot)) {
        $resolved = [IO.Path]::GetFullPath($testRoot)
        $boundary = [IO.Path]::GetFullPath($tempParent).TrimEnd(
            [IO.Path]::DirectorySeparatorChar,
            [IO.Path]::AltDirectorySeparatorChar) +
            [IO.Path]::DirectorySeparatorChar
        if (-not $resolved.StartsWith(
                $boundary,
                [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Refusing to clean a test directory outside the temp root.'
        }
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
    elseif (Test-Path -LiteralPath $testRoot) {
        Write-Warning "Failed fixture retained at $testRoot"
    }
}
