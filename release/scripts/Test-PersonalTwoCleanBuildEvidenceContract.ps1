#requires -Version 7.2

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$producerPath = Join-Path $PSScriptRoot 'New-PersonalTwoCleanBuildEvidence.ps1'
$consumerPath = Join-Path $PSScriptRoot 'PersonalTwoCleanBuildValidation.ps1'
$intentSchemaPath = Join-Path $repositoryRoot `
    'release\schemas\personal-two-clean-build-intent-v1.schema.json'
$evidenceSchemaPath = Join-Path $repositoryRoot `
    'release\schemas\personal-two-clean-build-evidence-v1.schema.json'
$assertions = 0

function Assert-True([bool]$Condition, [string]$Message) {
    $script:assertions++
    if (-not $Condition) { throw $Message }
}

function Test-ValueAgainstSchema($Value, [string]$SchemaPath) {
    $json = $Value | ConvertTo-Json -Depth 64 -Compress
    try {
        return Microsoft.PowerShell.Utility\Test-Json -Json $json `
            -SchemaFile $SchemaPath -ErrorAction Stop
    }
    catch {
        return $false
    }
}

function Assert-SequenceEqual([object[]]$Actual, [object[]]$Expected, [string]$Label) {
    Assert-True ($Actual.Count -eq $Expected.Count) "$Label argument count differs."
    for ($index = 0; $index -lt $Expected.Count; $index++) {
        Assert-True ([string]$Actual[$index] -ceq [string]$Expected[$index]) `
            "$Label argument $index differs."
    }
}

function Get-TestDigest([string[]]$Lines) {
    [byte[]]$bytes = [Text.UTF8Encoding]::new($false, $true).GetBytes(
        (($Lines -join "`n") + "`n"))
    try {
        return ([Convert]::ToHexString(
            [Security.Cryptography.SHA256]::HashData($bytes))).ToLowerInvariant()
    }
    finally {
        [Security.Cryptography.CryptographicOperations]::ZeroMemory($bytes)
    }
}

function Get-NormalizedRestoreTestDigest(
    [string[]]$Arguments,
    [string]$SourceRoot,
    [string]$PackageCacheRoot,
    [string]$NuGetConfig,
    [string]$Role,
    [string]$Project
) {
    $normalized = foreach ($argument in $Arguments) {
        $argument.Replace($SourceRoot, '<SOURCE>',
                [StringComparison]::OrdinalIgnoreCase).
            Replace($PackageCacheRoot, '<OFFLINE_PACKAGE_CACHE>',
                [StringComparison]::OrdinalIgnoreCase).
            Replace($NuGetConfig, '<OFFLINE_NUGET_CONFIG>',
                [StringComparison]::OrdinalIgnoreCase)
    }
    return Get-TestDigest @(
        "1|$Role|$Project|$($normalized -join [char]0x1f)")
}

function New-Invocation([int]$Ordinal, [string]$Role, [string]$FileName) {
    return [ordered]@{
        ordinal = $Ordinal
        role = $Role
        projectRelativePath = "src/$Role/$Role.csproj"
        arguments = @('publish') + @('argument') * 19
        startedAtUtc = '2026-09-07T00:00:00Z'
        completedAtUtc = '2026-09-07T00:00:01Z'
        exitCode = 0
        stdoutBytes = 0
        stdoutSha256 = 'a' * 64
        stderrBytes = 0
        stderrSha256 = 'b' * 64
        output = [ordered]@{
            role = $Role
            fileName = $FileName
            relativePath = "build-artifacts/isolated-a/$Role/$FileName"
            sizeBytes = 256
            sha256 = 'c' * 64
            peContentSha256 = 'd' * 64
            authenticodeStatus = 'NotSigned'
        }
    }
}

function New-RestoreCommand([int]$Ordinal, [string]$Role) {
    $productionProperties = @(
        '-p:EnableCompressionInSingleFile=true',
        '-p:IncludeNativeLibrariesForSelfExtract=true', '-p:PublishTrimmed=false',
        '-p:PublishAot=false', '-p:ContinuousIntegrationBuild=true',
        '-p:Deterministic=true', '-p:PersonalProductionBuild=true',
        '-p:PersonalDevelopmentPublish=false', '-p:Version=1.2.3',
        '-p:PathMap=C:\work\source=/_/src',
        '-p:PersonalManifestOrigin=https://updates.example.invalid/',
        '-p:PersonalArtifactOrigin=https://artifacts.example.invalid/',
        '-p:PersonalAccountOrigin=https://personal.example.invalid/',
        '-p:PersonalChannel=pilot', '-p:PersonalReleaseKeyId=release-key-1',
        '-p:PersonalReleaseKeyX=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        '-p:PersonalReleaseKeyY=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        '-p:PersonalStartupStubVersion=1.1.0',
        '-p:PersonalCanonicalLowSFromSequence=1',
        '-p:PersonalAuthenticodeSignerSha256Thumbprint=2222222222222222222222222222222222222222222222222222222222222222')
    return [ordered]@{
        ordinal = $Ordinal
        role = $Role
        projectRelativePath = "src/$Role/$Role.csproj"
        arguments = @(
            'restore', "C:\work\source\src\$Role\$Role.csproj",
            '--locked-mode', '--disable-parallel', '--configfile',
            'C:\work\NuGet.Config', '--packages', 'C:\offline-packages',
            '-p:Configuration=Release') + $productionProperties
        startedAtUtc = '2026-09-07T00:00:00Z'
        completedAtUtc = '2026-09-07T00:00:01Z'
        exitCode = 0
        stdoutBytes = 0
        stdoutSha256 = 'a' * 64
        stderrBytes = 0
        stderrSha256 = 'b' * 64
    }
}

function New-Run([string]$Label, [string]$BuildId) {
    $roles = @(
        @('startup-stub', 'Ensou.Dsh.Bootstrapper.exe'),
        @('client-bootstrapper', 'Ensou.Dsh.ClientBootstrapper.exe'),
        @('launcher', 'Ensou.Dsh.Launcher.exe'),
        @('maintenance', 'Ensou.Dsh.Personal.Maintenance.exe'))
    $invocations = for ($index = 0; $index -lt $roles.Count; $index++) {
        New-Invocation -Ordinal ($index + 1) -Role $roles[$index][0] `
            -FileName $roles[$index][1]
    }
    $restoreCommands = for ($index = 0; $index -lt $roles.Count; $index++) {
        New-RestoreCommand -Ordinal ($index + 1) -Role $roles[$index][0]
    }
    return [ordered]@{
        runLabel = $Label
        buildId = $BuildId
        checkoutPath = "C:\controlled\$Label"
        checkoutPhysicalIdentitySha256 = 'e' * 64
        materializedCheckoutPath = "C:\evidence\work\$Label\source"
        materializedCheckoutPhysicalIdentitySha256 = 'a' * 64
        intermediateRootPath = "C:\evidence\work\$Label\source"
        intermediateRootPhysicalIdentitySha256 = 'a' * 64
        outputRootPath = "C:\evidence\$Label"
        outputRootPhysicalIdentitySha256 = 'f' * 64
        sourceStatusBefore = 'CLEAN_TRACKED_HEAD'
        sourceStatusAfter = 'CLEAN_TRACKED_HEAD'
        startedAtUtc = '2026-09-07T00:00:00Z'
        completedAtUtc = '2026-09-07T00:00:01Z'
        sourceDateEpoch = 1
        restore = [ordered]@{
            packageCacheRootPath = 'C:\offline-packages'
            packageCacheRootPhysicalIdentitySha256 = 'b' * 64
            commands = @($restoreCommands)
            commandContractSha256 = 'c' * 64
            assets = @([ordered]@{
                relativePath = "work/$Label/source/src/$($roles[0][0])/obj/project.assets.json"
                sizeBytes = 1
                sha256 = 'd' * 64
            })
            assetsClosureSha256 = 'e' * 64
        }
        invocations = @($invocations)
        personalAccountSelfCheck = [ordered]@{
            command = '--personal-account-self-check'
            executableSha256 = 'c' * 64
            startedAtUtc = '2026-09-07T00:00:01Z'
            completedAtUtc = '2026-09-07T00:00:01Z'
            exitCode = 0
            stdout = [ordered]@{
                relativePath = "builds/$Label-personal-account-self-check.json"
                sizeBytes = 135
                sha256 = 'd' * 64
            }
            stderrBytes = 0
            stderrSha256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
        }
        outputClosureSha256 = '1' * 64
    }
}

$intent = [ordered]@{
    schemaVersion = 1
    intentType = 'ensou-dsh-personal-two-clean-production-build-intent'
    buildIntentId = '11111111-1111-4111-8111-111111111111'
    sourceCommit = '0' * 40
    sourceTree = '1' * 40
    version = '1.2.3'
    configuration = 'Release'
    runtimeIdentifier = 'win-x64'
    selfContained = $true
    publishSingleFile = $true
    enableCompressionInSingleFile = $true
    manifestOrigin = 'https://updates.example.invalid/'
    artifactOrigin = 'https://artifacts.example.invalid/'
    personalAccountOrigin = 'https://personal.example.invalid/'
    channel = 'pilot'
    releaseManifestTrust = [ordered]@{
        algorithm = 'ES256'
        keyId = 'release-key-1'
        purpose = 'release-manifest-signing'
        x = 'a' * 43
        y = 'b' * 43
    }
    startupStubVersion = '1.1.0'
    canonicalLowSFromSequence = 1
    authenticodeSignerSha256Thumbprint = '2' * 64
}

Assert-True (Test-ValueAgainstSchema -Value $intent -SchemaPath $intentSchemaPath) `
    'Four-client two-clean intent did not satisfy its strict schema.'
$missingAccountOriginIntent = $intent | ConvertTo-Json -Depth 64 -Compress |
    ConvertFrom-Json -Depth 64 -DateKind String
$missingAccountOriginIntent.PSObject.Properties.Remove('personalAccountOrigin')
Assert-True (-not (Test-ValueAgainstSchema -Value $missingAccountOriginIntent `
        -SchemaPath $intentSchemaPath)) `
    'Two-clean intent without the immutable Personal account origin was accepted.'
$legacyIntent = $intent | ConvertTo-Json -Depth 64 -Compress |
    ConvertFrom-Json -Depth 64 -DateKind String
$legacyIntent | Add-Member -NotePropertyName installerPayload `
    -NotePropertyValue ([ordered]@{})
Assert-True (-not (Test-ValueAgainstSchema -Value $legacyIntent `
        -SchemaPath $intentSchemaPath)) `
    'Two-clean intent still accepts an Installer payload precondition.'

$evidence = [ordered]@{
    schemaVersion = 1
    evidenceType = 'ensou-dsh-personal-two-clean-production-build-evidence'
    unsignedProductionCandidate = $true
    productionAdmission = 'NO_GO'
    producerScriptSha256 = '3' * 64
    buildIntent = [ordered]@{
        relativePath = 'builds/build-intent.v1.json'
        sizeBytes = 1
        sha256 = '4' * 64
    }
    sourceCommit = '0' * 40
    sourceTree = '1' * 40
    sourceInventorySha256 = '5' * 64
    dependencyClosureSha256 = '6' * 64
    sdk = [ordered]@{
        path = 'C:\dotnet\dotnet.exe'
        version = '10.0.302'
        sizeBytes = 1
        sha256 = '7' * 64
    }
    commandContractSha256 = '8' * 64
    runs = @(
        (New-Run -Label 'isolated-a' -BuildId '22222222-2222-4222-8222-222222222222'),
        (New-Run -Label 'isolated-b' -BuildId '33333333-3333-4333-8333-333333333333'))
    restoreClosureSha256 = '9' * 64
    outputsByteIdentical = $true
    combinedOutputClosureSha256 = '1' * 64
    result = 'PASS'
}

$preRestoreEvidence = $evidence | ConvertTo-Json -Depth 64 -Compress |
    ConvertFrom-Json -Depth 64 -DateKind String
$preRestoreEvidence.runs[0].restore.psobject.Properties.Remove('assetsClosureSha256')
Assert-True (-not (Test-ValueAgainstSchema -Value $preRestoreEvidence `
        -SchemaPath $evidenceSchemaPath)) `
    'Evidence without a locked restore asset closure was unexpectedly accepted.'
Assert-True (Test-ValueAgainstSchema -Value $evidence -SchemaPath $evidenceSchemaPath) `
    'Four-client two-clean evidence with locked offline restore did not satisfy its strict schema.'
$missingAccountProbeEvidence = $evidence | ConvertTo-Json -Depth 64 -Compress |
    ConvertFrom-Json -Depth 64 -DateKind String
$missingAccountProbeEvidence.runs[0].PSObject.Properties.Remove('personalAccountSelfCheck')
Assert-True (-not (Test-ValueAgainstSchema -Value $missingAccountProbeEvidence `
        -SchemaPath $evidenceSchemaPath)) `
    'Two-clean evidence without a Personal account self-check was accepted.'
$globalRestoreEvidence = $evidence | ConvertTo-Json -Depth 64 -Compress |
    ConvertFrom-Json -Depth 64 -DateKind String
$globalRestoreEvidence.runs[0].restore.commands[0].arguments += @(
    '--runtime', 'win-x64', '-p:SelfContained=true', '-p:PublishSingleFile=true')
Assert-True (-not (Test-ValueAgainstSchema -Value $globalRestoreEvidence -SchemaPath $evidenceSchemaPath)) `
    'Evidence still accepts global publish properties that corrupt portable library restore graphs.'
$legacyEvidence = $evidence | ConvertTo-Json -Depth 64 -Compress |
    ConvertFrom-Json -Depth 64 -DateKind String
$legacyEvidence | Add-Member -NotePropertyName payloadRootPhysicalIdentitySha256 `
    -NotePropertyValue ('9' * 64)
Assert-True (-not (Test-ValueAgainstSchema -Value $legacyEvidence `
        -SchemaPath $evidenceSchemaPath)) `
    'Two-clean evidence still accepts an Installer payload root.'

$producer = Get-Content -LiteralPath $producerPath -Raw
Assert-True ($producer -notmatch 'Ensou\.Dsh\.Personal\.Installer\.exe') `
    'The pre-sign two-clean producer still builds the Installer.'
Assert-True ($producer -notmatch 'installerPayload|PayloadClosure|PayloadRoot') `
    'The pre-sign two-clean producer still consumes a post-sign payload.'
Assert-True (($producer | Select-String -AllMatches "Ordinal = [1-4]" ).Matches.Count -eq 4) `
    'The pre-sign two-clean producer does not contain exactly four client roles.'
Assert-True ($producer -match '\[string\]\$OfflinePackageCacheRoot') `
    'The producer does not require an explicit controlled offline package cache.'
Assert-True ($producer -match 'New-MaterializedCheckout' -and
    $producer -match 'New-OfflineNuGetConfig' -and
    $producer -match "'--locked-mode'") `
    'The producer does not materialize a clean checkout for locked offline restore.'
Assert-True ($producer -match "'clone', '--no-hardlinks'" -and
    $producer -match "'--configfile'" -and
    $producer -match "'--packages'" -and
    $producer -match "'--no-restore'" -and
    $producer -match 'Assert-RestoreAssetClosureStillLocked') `
    'The producer does not keep restore and no-restore publish inside one locked closure.'
Assert-True ($producer -match '\$cloneEnvironment\s*=\s*\[ordered\]@\{\}' -and
    $producer -match 'foreach\s*\(\$name in \$Environment\.Keys\)' -and
    $producer.Contains('$cloneEnvironment[''GIT_CONFIG_NOSYSTEM''] = ''1''') -and
    $producer.Contains('$cloneEnvironment[''GIT_CONFIG_GLOBAL''] = ''NUL''') -and
    $producer.Contains('$cloneEnvironment[''GIT_OPTIONAL_LOCKS''] = ''0''') -and
    $producer.Contains('$cloneEnvironment[''LC_ALL''] = ''C''') -and
    $producer -match '-Environment \$cloneEnvironment') `
    'The materialized clone can inherit system or global Git conversion policy.'
Assert-True ($producer.Contains("`$environment['DOTNET_GENERATE_ASPNET_CERTIFICATE'] = 'false'")) `
    'The fixed build environment can generate an ASP.NET development certificate.'
Assert-True ($producer -match 'contains pre-existing obj intermediates before restore' -and
    $producer -match 'materializedCheckoutPhysicalIdentitySha256' -and
    $producer -match 'intermediateRootPhysicalIdentitySha256') `
    'The producer does not record isolated intermediate provenance.'
$tokens = $null
$parseErrors = $null
$producerAst = [System.Management.Automation.Language.Parser]::ParseFile(
    $producerPath, [ref]$tokens, [ref]$parseErrors)
Assert-True ($parseErrors.Count -eq 0) `
    'The producer cannot be parsed for its restore/publish contract.'
$functions = @($producerAst.FindAll({ param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
    }, $true))
$restoreFunction = @($functions | Where-Object { $_.Name -ceq 'Get-RestoreArguments' })
$publishFunction = @($functions | Where-Object { $_.Name -ceq 'Get-PublishArguments' })
$propertyFunction = @($functions | Where-Object { $_.Name -ceq 'Get-PersonalProductionPropertyArguments' })
$nuGetEnvironmentFunction = @($functions | Where-Object {
        $_.Name -ceq 'Initialize-PersonalNuGetEnvironment'
    })
$failureDiagnosticFunction = @($functions | Where-Object {
        $_.Name -ceq 'Get-PersonalBuildFailureDiagnostic'
    })
Assert-True ($restoreFunction.Count -eq 1 -and $publishFunction.Count -eq 1 -and
    $propertyFunction.Count -eq 1) `
    'The producer does not expose one shared restore/publish production-property helper.'
Assert-True ($nuGetEnvironmentFunction.Count -eq 1 -and
    $failureDiagnosticFunction.Count -eq 1) `
    'The producer does not expose both isolated NuGet-environment and failure-diagnostic helpers.'
Assert-True ($restoreFunction[0].Extent.Text -match "'-p:Configuration=Release'" -and
    $restoreFunction[0].Extent.Text -notmatch "'-p:SelfContained=true'" -and
    $restoreFunction[0].Extent.Text -notmatch "'--runtime'" -and
    $restoreFunction[0].Extent.Text -match 'Get-PersonalProductionPropertyArguments' -and
    $publishFunction[0].Extent.Text -match 'Get-PersonalProductionPropertyArguments') `
    'Restore must keep Release/trust properties while taking RID and self-contained settings from the executable project.'
$producerFunctionText = @(
    $propertyFunction[0].Extent.Text,
    $restoreFunction[0].Extent.Text,
    $publishFunction[0].Extent.Text,
    $nuGetEnvironmentFunction[0].Extent.Text,
    $failureDiagnosticFunction[0].Extent.Text) -join "`n`n"
. ([scriptblock]::Create($producerFunctionText))
. $consumerPath
$nuGetTestTempRoot = [IO.Path]::TrimEndingDirectorySeparator(
    [IO.Path]::GetFullPath([IO.Path]::GetTempPath()))
$nuGetTestParent = [IO.Path]::GetFullPath((Join-Path $nuGetTestTempRoot (
    'ensou-personal-nuget-environment-contract-' + [Guid]::NewGuid().ToString('N'))))
if (Test-Path -LiteralPath $nuGetTestParent) { throw 'NuGet test root already exists.' }
try {
    $firstWorkRoot = Join-Path $nuGetTestParent 'first-work'
    $secondWorkRoot = Join-Path $nuGetTestParent 'second-work'
    $firstEnvironment = [ordered]@{ UnrelatedKey = 'must-survive' }
    $secondEnvironment = [ordered]@{ UnrelatedKey = 'must-survive-too' }
    Initialize-PersonalNuGetEnvironment -Environment $firstEnvironment `
        -WorkRoot $firstWorkRoot
    Initialize-PersonalNuGetEnvironment -Environment $secondEnvironment `
        -WorkRoot $secondWorkRoot
    $nuGetDefaultRoots = @(
        'ProgramFiles', 'ProgramFiles(x86)', 'ProgramW6432', 'PROGRAMDATA',
        'ALLUSERSPROFILE', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA')
    Assert-True ($firstEnvironment['UnrelatedKey'] -ceq 'must-survive' -and
        $secondEnvironment['UnrelatedKey'] -ceq 'must-survive-too') `
        'NuGet environment initialization changed unrelated fixed-environment values.'
    foreach ($name in $nuGetDefaultRoots) {
        $firstExpected = [IO.Path]::GetFullPath(
            (Join-Path (Join-Path $firstWorkRoot 'environment') $name))
        $secondExpected = [IO.Path]::GetFullPath(
            (Join-Path (Join-Path $secondWorkRoot 'environment') $name))
        Assert-True ([string]$firstEnvironment[$name] -ceq $firstExpected -and
            [IO.Directory]::Exists($firstExpected)) `
            "First isolated NuGet root '$name' is not an existing work-root-local directory."
        Assert-True ([string]$secondEnvironment[$name] -ceq $secondExpected -and
            [IO.Directory]::Exists($secondExpected) -and
            [string]$firstEnvironment[$name] -cne [string]$secondEnvironment[$name]) `
            "NuGet root '$name' is not independently isolated per work root."
    }
    $stdoutOnlyDiagnostic = Get-PersonalBuildFailureDiagnostic -Result ([pscustomobject]@{
            Stdout = ('x' * 5000) + "`nNU1004 stdout-only restore cause"
            Stderr = ''
        })
    Assert-True ($stdoutOnlyDiagnostic -match '^Stdout: \[tail\] ' -and
        $stdoutOnlyDiagnostic -match 'NU1004 stdout-only restore cause' -and
        $stdoutOnlyDiagnostic.Length -le ('Stdout: '.Length + '[tail] '.Length + 4096)) `
        'Bounded failure diagnostics dropped the stdout-only MSBuild/NuGet cause.'
    $dualChannelDiagnostic = Get-PersonalBuildFailureDiagnostic -Result ([pscustomobject]@{
            Stderr = 'stderr evidence'
            Stdout = 'stdout evidence'
        })
    Assert-True ($dualChannelDiagnostic -ceq "Stderr: stderr evidence`nStdout: stdout evidence") `
        'Failure diagnostics do not preserve both stderr and stdout in a deterministic order.'
}
finally {
    if ([IO.Directory]::Exists($nuGetTestParent)) {
        if ([IO.Path]::GetDirectoryName($nuGetTestParent) -cne $nuGetTestTempRoot -or
            [IO.Path]::GetFileName($nuGetTestParent) -notmatch '^ensou-personal-nuget-environment-contract-[a-f0-9]{32}$') {
            throw 'Refusing cleanup outside the exact owned NuGet test root.'
        }
        [IO.Directory]::Delete($nuGetTestParent, $true)
    }
}
$sampleSource = 'C:\Evidence Root\work\isolated-a\source'
$sampleOutput = 'C:\Evidence Root\build-artifacts\isolated-a'
$sampleCache = 'C:\Controlled Packages\cache'
$sampleNuGetConfig = 'C:\Evidence Root\work\isolated-a\NuGet.Config'
$sampleRun = [pscustomobject]@{
    materializedCheckoutPath = $sampleSource
    outputRootPath = $sampleOutput
}
$sampleProject = 'src/Ensou.Dsh.Bootstrapper/Ensou.Dsh.Bootstrapper.csproj'
$sampleRole = 'startup-stub'
$sampleProjectContract = [pscustomobject]@{ Project = $sampleProject }
$producerPublish = @(Get-PublishArguments -SourceRoot $sampleSource `
    -OutputDirectory (Join-Path $sampleOutput $sampleRole) -Intent $intent `
    -Project $sampleProjectContract)
$consumerPublish = @(Get-PersonalPublishContractArguments -Run $sampleRun `
    -Intent $intent -Project $sampleProject -Role $sampleRole)
Assert-SequenceEqual -Actual $producerPublish -Expected $consumerPublish `
    -Label 'Producer/consumer publish'
$producerRestore = @(Get-RestoreArguments -SourceRoot $sampleSource `
    -OfflineNuGetConfig $sampleNuGetConfig -OfflinePackageCacheRoot $sampleCache `
    -Intent $intent -Project $sampleProjectContract)
$consumerProductionProperties = @($consumerPublish | Where-Object {
        $_.StartsWith('-p:', [StringComparison]::Ordinal) -and
        $_ -cne '-p:PublishSingleFile=true'
    })
$expectedRestore = @(
    'restore', (Join-Path $sampleSource $sampleProject.Replace(
            '/', [IO.Path]::DirectorySeparatorChar)),
    '--locked-mode', '--disable-parallel', '--configfile', $sampleNuGetConfig,
    '--packages', $sampleCache, '-p:Configuration=Release'
) + $consumerProductionProperties
Assert-SequenceEqual -Actual $producerRestore -Expected $expectedRestore `
    -Label 'Producer restore/consumer production properties'
Assert-True ($producerRestore.Count -eq 29 -and
    $producerRestore -cnotcontains '--runtime' -and
    $producerRestore -cnotcontains '-p:SelfContained=true' -and
    $producerRestore -cnotcontains '-p:PublishSingleFile=true' -and
    $producerRestore -ccontains '-p:PersonalProductionBuild=true' -and
    $producerRestore -ccontains '-p:PersonalAccountOrigin=https://personal.example.invalid/' -and
    $producerRestore -ccontains '-p:PublishTrimmed=false') `
    'Restore lost production inputs or still propagates executable-only properties into library locks.'
$missingAccountPublishArgument = @($producerPublish | Where-Object {
        $_ -cne '-p:PersonalAccountOrigin=https://personal.example.invalid/'
    })
Assert-True ($missingAccountPublishArgument.Count -eq ($producerPublish.Count - 1)) `
    'The publish contract does not expose an independently removable Personal account origin argument.'
try {
    Assert-SequenceEqual -Actual $missingAccountPublishArgument -Expected $consumerPublish `
        -Label 'Publish missing account origin'
    throw 'A publish contract missing PersonalAccountOrigin was accepted.'
}
catch {
    Assert-True ($_.ToString() -match 'argument count differs') `
        'The missing PersonalAccountOrigin negative failed for the wrong reason.'
}
Assert-True ((Get-NormalizedRestoreTestDigest -Arguments $producerRestore `
        -SourceRoot $sampleSource -PackageCacheRoot $sampleCache `
        -NuGetConfig $sampleNuGetConfig -Role $sampleRole `
        -Project $sampleProject) -ceq
    (Get-NormalizedRestoreTestDigest -Arguments $expectedRestore `
        -SourceRoot $sampleSource -PackageCacheRoot $sampleCache `
        -NuGetConfig $sampleNuGetConfig -Role $sampleRole `
        -Project $sampleProject)) `
    'Producer restore normalized contract digest differs from the consumer property contract.'
$consumerTokens = $null
$consumerParseErrors = $null
$consumerAst = [System.Management.Automation.Language.Parser]::ParseFile(
    $consumerPath, [ref]$consumerTokens, [ref]$consumerParseErrors)
Assert-True ($consumerParseErrors.Count -eq 0) `
    'The consumer cannot be parsed for its restore contract.'
$consumerValidationFunction = @($consumerAst.FindAll({ param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Assert-ReproducibleBuild'
    }, $true))
Assert-True ($consumerValidationFunction.Count -eq 1) `
    'The consumer does not expose exactly one reproducible-build validator.'
$consumerBody = $consumerValidationFunction[0].Extent.Text
Assert-True ($consumerBody -match [Regex]::Escape(
        "`$restoreExpected += @('-p:Configuration=Release')") -and
    $consumerBody -match [Regex]::Escape('$expected | Where-Object {') -and
    $consumerBody -match [Regex]::Escape("`$_ -cne '-p:PublishSingleFile=true'")) `
    'Consumer restore validation does not require the exact project-scoped production property sequence.'

Write-Output "PASS Personal two-clean build evidence contract assertions=$assertions"
