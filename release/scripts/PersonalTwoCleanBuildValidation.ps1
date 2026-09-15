#requires -Version 7.2
# Internal consumer helpers. Dot-sourced only by the Pilot gate and contract tests.
Import-Module (Join-Path $PSScriptRoot 'PersonalAccountReleaseConfiguration.psm1') -Force

function Get-PersonalBuildDigest([string[]]$Lines) {
    return ProductionReleaseState\Get-ProductionSha256Bytes -Bytes (
        [Text.UTF8Encoding]::new($false, $true).GetBytes(($Lines -join "`n") + "`n"))
}

function Get-PersonalPublishContractArguments($Run, $Intent, [string]$Project, [string]$Role) {
    $source = [string]$Run.materializedCheckoutPath
    return @(
        'publish', (Join-Path $source $Project.Replace('/', [IO.Path]::DirectorySeparatorChar)),
        '--configuration', 'Release', '--runtime', 'win-x64',
        '--self-contained', 'true', '--no-restore',
        '-p:PublishSingleFile=true', '-p:EnableCompressionInSingleFile=true',
        '-p:IncludeNativeLibrariesForSelfExtract=true',
        '-p:PublishTrimmed=false', '-p:PublishAot=false',
        '-p:ContinuousIntegrationBuild=true', '-p:Deterministic=true',
        '-p:PersonalProductionBuild=true', '-p:PersonalDevelopmentPublish=false',
        "-p:Version=$($Intent.version)", "-p:PathMap=$source=/_/src",
        "-p:PersonalManifestOrigin=$($Intent.manifestOrigin)",
        "-p:PersonalArtifactOrigin=$($Intent.artifactOrigin)",
        "-p:PersonalAccountOrigin=$($Intent.personalAccountOrigin)",
        "-p:PersonalChannel=$($Intent.channel)",
        "-p:PersonalReleaseKeyId=$($Intent.releaseManifestTrust.keyId)",
        "-p:PersonalReleaseKeyX=$($Intent.releaseManifestTrust.x)",
        "-p:PersonalReleaseKeyY=$($Intent.releaseManifestTrust.y)",
        "-p:PersonalStartupStubVersion=$($Intent.startupStubVersion)",
        "-p:PersonalCanonicalLowSFromSequence=$($Intent.canonicalLowSFromSequence)",
        "-p:PersonalAuthenticodeSignerSha256Thumbprint=$($Intent.authenticodeSignerSha256Thumbprint)",
        '--output', (Join-Path ([string]$Run.outputRootPath) $Role)
    )
}

function Get-PersonalRestoreDigest([object[]]$Runs) {
    $lines = [Collections.Generic.List[string]]::new()
    foreach ($run in $Runs) {
        $restore = $run.restore
        $lines.Add("run|$($run.runLabel)|$($run.materializedCheckoutPhysicalIdentitySha256)|$($run.intermediateRootPhysicalIdentitySha256)|$($restore.packageCacheRootPhysicalIdentitySha256)|$($restore.commandContractSha256)|$($restore.assetsClosureSha256)")
        foreach ($command in @($restore.commands)) {
            $lines.Add("command|$($run.runLabel)|$($command.ordinal)|$($command.role)|$($command.projectRelativePath)|$(@($command.arguments) -join [char]0x1f)|$($command.exitCode)|$($command.stdoutBytes)|$($command.stdoutSha256)|$($command.stderrBytes)|$($command.stderrSha256)")
        }
        foreach ($asset in @($restore.assets)) {
            $lines.Add("asset|$($run.runLabel)|$($asset.relativePath)|$($asset.sizeBytes)|$($asset.sha256)")
        }
    }
    return Get-PersonalBuildDigest @($lines)
}

function Assert-PersonalBuildArguments([object[]]$Actual, [string[]]$Expected, [string]$Label) {
    if ($Actual.Count -ne $Expected.Count) { throw "$Label command argument count differs." }
    for ($i = 0; $i -lt $Expected.Count; $i++) {
        if ([string]$Actual[$i] -cne $Expected[$i]) { throw "$Label command argument $i differs." }
    }
}

function Read-PersonalBoundBuildJson($Descriptor, [string]$Root, [string]$RelativePath, [string]$Schema, [string]$Label) {
    $path = Assert-EvidenceFile -Descriptor $Descriptor -EvidenceRoot $Root -ExpectedRelativePath $RelativePath -Label $Label
    $input = ProductionReleaseState\Read-StrictProductionJsonFile -Path $path -Label $Label -SchemaPath $Schema
    if ($input.Bytes.LongLength -ne $Descriptor.sizeBytes -or $input.Sha256 -cne $Descriptor.sha256) {
        throw "$Label changed between byte admission and strict parsing."
    }
    [void](ProductionReleaseState\Assert-CanonicalProductionJsonInput -JsonInput $input -Label $Label)
    return $input.Value
}

function Assert-PersonalBuildTime([string]$Value, [string]$Label) {
    $parsed = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParseExact($Value, 'yyyy-MM-ddTHH:mm:ssZ',
        [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal,
        [ref]$parsed) -or $parsed -le [DateTimeOffset]::UnixEpoch -or
        $parsed -gt [DateTimeOffset]::UtcNow.AddMinutes(5)) { throw "$Label has an invalid build timestamp." }
    return $parsed
}

function Assert-ReproducibleBuild($Evidence, $Plan, $PlanInput, [string]$EvidenceRoot) {
    $wrapper = $Evidence.reproducibleBuild
    foreach ($name in @('sourceCommit', 'sourceTree')) {
        Assert-ProductionGitObject -Value ([string]$wrapper.$name) -Label "Reproducible build $name"
    }
    if ($wrapper.sourceCommit -cne $Plan.sourceCommit) {
        throw 'Reproducible build source commit differs from the Personal Pilot plan.'
    }
    $receipt = Read-PersonalBoundBuildJson $wrapper.receipt $EvidenceRoot 'builds/two-clean-build-evidence.v1.json' $reproducibleBuildSchemaPath 'Personal two-clean build receipt'
    $intent = Read-PersonalBoundBuildJson $receipt.buildIntent $EvidenceRoot 'builds/build-intent.v1.json' $buildIntentSchemaPath 'Personal two-clean build intent'
    [void](PersonalAccountReleaseConfiguration\Assert-PersonalAccountOrigin `
        -Value ([string]$intent.personalAccountOrigin) -Label 'Personal build intent account origin')
    [void](PersonalAccountReleaseConfiguration\Assert-PersonalAccountOrigin `
        -Value ([string]$Plan.personalAccountOrigin) -Label 'Personal plan account origin')
    foreach ($name in @('sourceCommit', 'sourceTree')) {
        if ($receipt.$name -cne $wrapper.$name -or $intent.$name -cne $wrapper.$name) {
            throw "Personal build intent and receipt disagree with the evidence on $name."
        }
    }
    if ($receipt.sdk.version -cne $wrapper.sdkVersion -or
        $intent.manifestOrigin -cne (([uri]$Plan.manifestUri).GetLeftPart([UriPartial]::Authority) + '/') -or
        $intent.artifactOrigin -cne (([uri]$Plan.artifactBaseUri).GetLeftPart([UriPartial]::Authority) + '/') -or
        $intent.personalAccountOrigin -cne $Plan.personalAccountOrigin -or
        $intent.channel -cne $Plan.targetChannel -or
        $intent.startupStubVersion -cne $Plan.releaseCompatibility.startupStubVersion -or
        $intent.canonicalLowSFromSequence -ne $Plan.releaseCompatibility.canonicalLowSFromSequence -or
        $intent.authenticodeSignerSha256Thumbprint -cne $Plan.authenticodePolicy.signerSha256Thumbprint) {
        throw 'Personal build intent trust, origin, channel, compatibility, or SDK differs from the exact plan.'
    }
    foreach ($name in @('algorithm', 'keyId', 'purpose', 'x', 'y')) {
        if ($intent.releaseManifestTrust.$name -cne $Plan.releaseManifestTrust.$name) {
            throw "Personal build intent release trust differs from the exact plan on $name."
        }
    }
    foreach ($name in @('producerScriptSha256', 'sourceInventorySha256', 'dependencyClosureSha256',
        'commandContractSha256', 'combinedOutputClosureSha256', 'restoreClosureSha256')) {
        Assert-ProductionSha256 ([string]$receipt.$name) "Personal two-clean receipt $name"
    }
    Assert-ProductionSha256 ([string]$receipt.sdk.sha256) 'Personal SDK hash'
    Assert-RealInstallationId ([string]$intent.buildIntentId) 'Personal build intent ID'
    $runs = @($receipt.runs)
    foreach ($name in @('buildId', 'checkoutPhysicalIdentitySha256', 'materializedCheckoutPhysicalIdentitySha256',
        'intermediateRootPhysicalIdentitySha256', 'outputRootPhysicalIdentitySha256',
        'checkoutPath', 'materializedCheckoutPath', 'intermediateRootPath', 'outputRootPath')) {
        if ([string]$runs[0].$name -ieq [string]$runs[1].$name) {
            throw 'Reproducible proof requires two distinct build IDs, clean checkouts, intermediates, and output roots.'
        }
    }
    if ($runs[0].sourceDateEpoch -ne $runs[1].sourceDateEpoch -or
        $runs[0].restore.packageCacheRootPhysicalIdentitySha256 -cne $runs[1].restore.packageCacheRootPhysicalIdentitySha256 -or
        $runs[0].restore.packageCacheRootPath -cne $runs[1].restore.packageCacheRootPath) {
        throw 'Personal clean builds disagree on source epoch or controlled package cache.'
    }
    # Compare the two result sets before opening files so drift is diagnosed explicitly.
    for ($i = 0; $i -lt 4; $i++) {
        $first = $runs[0].invocations[$i].output
        $second = $runs[1].invocations[$i].output
        foreach ($name in @('role', 'fileName', 'sizeBytes', 'sha256', 'peContentSha256')) {
            if ([string]$first.$name -cne [string]$second.$name) {
                throw "Two isolated builds produced different '$name' for Personal output $i."
            }
        }
        $planned = $Plan.clientSigningInputs[$i]
        foreach ($name in @('role', 'fileName', 'sizeBytes', 'sha256', 'peContentSha256')) {
            if ([string]$first.$name -cne [string]$planned.$name) {
                throw "Reproducible output '$($first.role)' differs from the exact Personal plan client input."
            }
        }
    }
    $projects = @(
        'src/Ensou.Dsh.Bootstrapper/Ensou.Dsh.Bootstrapper.csproj',
        'src/Ensou.Dsh.ClientBootstrapper/Ensou.Dsh.ClientBootstrapper.csproj',
        'src/Ensou.Dsh.Launcher/Ensou.Dsh.Launcher.csproj',
        'src/Ensou.Dsh.Personal.Maintenance/Ensou.Dsh.Personal.Maintenance.csproj'
    )
    foreach ($run in $runs) {
        $label = [string]$run.runLabel
        Assert-RealInstallationId ([string]$run.buildId) "$label build ID"
        foreach ($name in @('checkoutPhysicalIdentitySha256', 'materializedCheckoutPhysicalIdentitySha256',
            'intermediateRootPhysicalIdentitySha256', 'outputRootPhysicalIdentitySha256', 'outputClosureSha256')) {
            Assert-ProductionSha256 ([string]$run.$name) "$label $name"
        }
        Assert-ProductionSha256 ([string]$run.restore.packageCacheRootPhysicalIdentitySha256) "$label package cache"
        if ($run.checkoutPhysicalIdentitySha256 -ceq $run.materializedCheckoutPhysicalIdentitySha256 -or
            $run.intermediateRootPath -cne $run.materializedCheckoutPath -or
            $run.intermediateRootPhysicalIdentitySha256 -cne $run.materializedCheckoutPhysicalIdentitySha256) {
            throw "$label does not describe an isolated materialized checkout and intermediate root."
        }
        $started = Assert-PersonalBuildTime $run.startedAtUtc "$label start"
        $completed = Assert-PersonalBuildTime $run.completedAtUtc "$label completion"
        if ($completed -lt $started) { throw "$label completed before it started." }
        $commandLines = [Collections.Generic.List[string]]::new()
        $restoreCommandLines = [Collections.Generic.List[string]]::new()
        $outputLines = [Collections.Generic.List[string]]::new()
        $previousRestoreEnd = [DateTimeOffset]::UnixEpoch
        $previousPublishEnd = $started
        for ($i = 0; $i -lt 4; $i++) {
            $call = $run.invocations[$i]
            $restore = $run.restore.commands[$i]
            $planned = $Plan.clientSigningInputs[$i]
            foreach ($invocation in @($call, $restore)) {
                if ($invocation.ordinal -ne ($i + 1) -or $invocation.role -cne $planned.role -or
                    $invocation.projectRelativePath -cne $projects[$i]) {
                    throw "$label invocation does not bind the canonical four-client order."
                }
                Assert-ProductionSha256 ([string]$invocation.stdoutSha256) "$label stdout"
                Assert-ProductionSha256 ([string]$invocation.stderrSha256) "$label stderr"
            }
            $expected = Get-PersonalPublishContractArguments $run $intent $projects[$i] $planned.role
            Assert-PersonalBuildArguments @($call.arguments) $expected "$label publish"
            $source = [string]$run.materializedCheckoutPath
            $restoreExpected = @('restore', (Join-Path $source $projects[$i].Replace('/', [IO.Path]::DirectorySeparatorChar)),
                '--locked-mode', '--disable-parallel', '--configfile',
                (Join-Path ([IO.Path]::GetDirectoryName($source)) 'NuGet.Config'),
                '--packages', [string]$run.restore.packageCacheRootPath)
            $restoreExpected += @('-p:Configuration=Release')
            $restoreExpected += @($expected | Where-Object {
                $_.StartsWith('-p:', [StringComparison]::Ordinal) -and
                $_ -cne '-p:PublishSingleFile=true'
            })
            Assert-PersonalBuildArguments @($restore.arguments) $restoreExpected "$label restore"
            $restoreNormalized = @($restore.arguments | ForEach-Object {
                ([string]$_).Replace($source, '<SOURCE>', [StringComparison]::OrdinalIgnoreCase).
                    Replace([string]$run.restore.packageCacheRootPath, '<OFFLINE_PACKAGE_CACHE>', [StringComparison]::OrdinalIgnoreCase).
                    Replace([string]$restoreExpected[5], '<OFFLINE_NUGET_CONFIG>', [StringComparison]::OrdinalIgnoreCase)
            })
            $restoreCommandLines.Add("$($i + 1)|$($restore.role)|$($restore.projectRelativePath)|$($restoreNormalized -join [char]0x1f)")
            $rs = Assert-PersonalBuildTime $restore.startedAtUtc "$label restore start"
            $re = Assert-PersonalBuildTime $restore.completedAtUtc "$label restore end"
            $ps = Assert-PersonalBuildTime $call.startedAtUtc "$label publish start"
            $pe = Assert-PersonalBuildTime $call.completedAtUtc "$label publish end"
            if ($rs -lt $previousRestoreEnd -or $re -lt $rs -or $re -gt $started -or
                $ps -lt $previousPublishEnd -or $pe -lt $ps -or $pe -gt $completed) {
                throw "$label restore/publish chronology is invalid."
            }
            $previousRestoreEnd = $re
            $previousPublishEnd = $pe
            $normalized = @($call.arguments | ForEach-Object {
                ([string]$_).Replace($source, '<SOURCE>', [StringComparison]::OrdinalIgnoreCase).
                    Replace([string]$run.outputRootPath, '<OUTPUT>', [StringComparison]::OrdinalIgnoreCase)
            })
            $commandLines.Add("$($i + 1)|$($call.role)|$($call.projectRelativePath)|$($normalized -join [char]0x1f)")
            $output = $call.output
            $relative = "build-artifacts/$label/$($planned.role)/$($planned.fileName)"
            $path = Assert-EvidenceFile $output $EvidenceRoot $relative "$label unsigned $($planned.role)"
            $held = ProductionReleaseState\Open-ProductionReleaseInput -Path $path -Label "$label unsigned PE" -MaximumBytes 1GB
            try {
                if ($held.Sha256 -cne $output.sha256 -or $held.SizeBytes -ne $output.sizeBytes) {
                    throw "$label unsigned output changed before PE validation."
                }
                [byte[]]$bytes = ProductionReleaseState\Read-ProductionReleaseInputBytes -Descriptor $held -Label "$label unsigned PE"
                try {
                    if ((ProductionReleaseState\Get-PeContentSha256 -Bytes $bytes) -cne $output.peContentSha256) {
                        throw "$label unsigned PE content differs from its descriptor."
                    }
                } finally { [Security.Cryptography.CryptographicOperations]::ZeroMemory($bytes) }
            } finally { $held.Stream.Dispose() }
            $outputLines.Add("$($output.role)|$($output.fileName)|$($output.sizeBytes)|$($output.sha256)|$($output.peContentSha256)")
        }
        $probe = $run.personalAccountSelfCheck
        if ($probe.command -cne '--personal-account-self-check' -or $probe.exitCode -ne 0 -or
            $probe.executableSha256 -cne $run.invocations[2].output.sha256 -or
            $probe.stderrBytes -ne 0 -or $probe.stderrSha256 -cne
                (ProductionReleaseState\Get-ProductionSha256Bytes -Bytes ([byte[]]::new(0)))) {
            throw "$label account self-check does not bind the exact Launcher and clean process result."
        }
        $probeStarted = Assert-PersonalBuildTime $probe.startedAtUtc "$label account self-check start"
        $probeCompleted = Assert-PersonalBuildTime $probe.completedAtUtc "$label account self-check end"
        if ($probeStarted -lt $previousPublishEnd -or $probeCompleted -lt $probeStarted -or
            $probeCompleted -gt $completed) {
            throw "$label account self-check chronology is invalid."
        }
        $probePath = Assert-EvidenceFile $probe.stdout $EvidenceRoot `
            "builds/$label-personal-account-self-check.json" "$label account self-check stdout"
        $probeInput = ProductionReleaseState\Open-ProductionReleaseInput `
            -Path $probePath -Label "$label account self-check stdout" -MaximumBytes 16384
        try {
            if ($probeInput.Sha256 -cne $probe.stdout.sha256 -or
                $probeInput.SizeBytes -ne $probe.stdout.sizeBytes) {
                throw "$label account self-check output changed before parsing."
            }
            [byte[]]$probeBytes = ProductionReleaseState\Read-ProductionReleaseInputBytes `
                -Descriptor $probeInput -Label "$label account self-check stdout"
            try {
                [void](PersonalAccountReleaseConfiguration\ConvertFrom-PersonalAccountSelfCheck `
                    -Bytes $probeBytes -ExpectedOrigin ([string]$intent.personalAccountOrigin))
            } finally { [Security.Cryptography.CryptographicOperations]::ZeroMemory($probeBytes) }
        } finally { $probeInput.Stream.Dispose() }
        if ((Get-PersonalBuildDigest @($restoreCommandLines)) -cne $run.restore.commandContractSha256 -or
            (Get-PersonalBuildDigest @($commandLines)) -cne $receipt.commandContractSha256 -or
            (Get-PersonalBuildDigest @($outputLines)) -cne $run.outputClosureSha256 -or
            $run.outputClosureSha256 -cne $receipt.combinedOutputClosureSha256) {
            throw "$label command or output closure digest differs."
        }
        $assetLines = [Collections.Generic.List[string]]::new()
        $lastPath = ''
        foreach ($asset in @($run.restore.assets)) {
            $relative = [string]$asset.relativePath
            if ($relative -notmatch "^work/$label/source/(?:[^/]+/)*obj/" -or
                $relative -match '(^|/)[.][.]?(/|$)' -or
                $relative -notmatch '/(?:project[.]assets[.]json|project[.]nuget[.]cache|[^/]+[.]nuget[.](?:g[.]props|g[.]targets|dgspec[.]json))$' -or
                ($lastPath -ne '' -and [StringComparer]::OrdinalIgnoreCase.Compare($lastPath, $relative) -ge 0)) {
                throw "$label restore assets contain an invalid, duplicate, or unordered path."
            }
            [void](Assert-EvidenceFile $asset $EvidenceRoot $relative "$label restore asset")
            $assetLines.Add("$relative|$($asset.sizeBytes)|$($asset.sha256)")
            $lastPath = $relative
        }
        if ($assetLines.Count -eq 0 -or (Get-PersonalBuildDigest @($assetLines)) -cne $run.restore.assetsClosureSha256) {
            throw "$label restore assets closure digest differs."
        }
    }
    if ((Get-PersonalRestoreDigest $runs) -cne $receipt.restoreClosureSha256) {
        throw 'Personal combined restore closure digest differs.'
    }
    return $runs
}
