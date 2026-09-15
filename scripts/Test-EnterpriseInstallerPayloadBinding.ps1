[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($PSVersionTable.PSVersion -lt [Version]'7.2') {
    throw 'Enterprise Installer payload-binding tests require PowerShell 7.2 or newer.'
}

$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$installerProject = Join-Path `
    $repositoryRoot `
    'src\Ensou.Dsh.Enterprise.Installer\Ensou.Dsh.Enterprise.Installer.csproj'
$installerProgram = Join-Path `
    $repositoryRoot `
    'src\Ensou.Dsh.Enterprise.Installer\Program.cs'
$publishedGate = Join-Path `
    $repositoryRoot `
    'scripts\Test-EnterprisePublishedArtifacts.ps1'
$testRoot = Join-Path `
    ([IO.Path]::GetTempPath()) `
    ("ensou-enterprise-installer-payload-binding-{0}" -f
        [Guid]::NewGuid().ToString('N'))

function Get-FileDescriptor {
    param([Parameter(Mandatory = $true)][string]$Path)

    $bytes = [IO.File]::ReadAllBytes($Path)
    try {
        return [pscustomobject]@{
            SizeBytes = [long]$bytes.LongLength
            Sha256 = [Convert]::ToHexString(
                [Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
        }
    } finally {
        [Security.Cryptography.CryptographicOperations]::ZeroMemory($bytes)
    }
}

function New-PayloadFixture {
    param(
        [Parameter(Mandatory = $true)][string]$Directory,
        [Parameter(Mandatory = $true)][string]$Identity,
        [ValidateSet('enterprise', 'development-e2e')]
        [string]$LayoutProfile = 'enterprise'
    )

    [IO.Directory]::CreateDirectory($Directory) | Out-Null
    $launcherPath = Join-Path $Directory 'launcher.zip'
    $runtimePath = Join-Path $Directory 'runtime.zip'
    $bootstrapperPath = Join-Path `
        $Directory `
        'Ensou.Dsh.Enterprise.Bootstrapper.exe'
    [IO.File]::WriteAllBytes(
        $launcherPath,
        [Text.Encoding]::UTF8.GetBytes("launcher-$Identity"))
    [IO.File]::WriteAllBytes(
        $runtimePath,
        [Text.Encoding]::UTF8.GetBytes("runtime-$Identity-$Identity"))
    [IO.File]::WriteAllBytes(
        $bootstrapperPath,
        [Text.Encoding]::UTF8.GetBytes("bootstrapper-$Identity-$Identity-$Identity"))
    $launcher = Get-FileDescriptor $launcherPath
    $runtime = Get-FileDescriptor $runtimePath
    $bootstrapper = Get-FileDescriptor $bootstrapperPath
    $manifestValue = [ordered]@{
        schemaVersion = 1
        layoutProfile = $LayoutProfile
        launcherReleaseId = "launcher-$Identity"
        runtimeReleaseId = "runtime-$Identity"
        launcherArchive = 'launcher.zip'
        launcherArchiveSizeBytes = $launcher.SizeBytes
        launcherArchiveSha256 = $launcher.Sha256
        runtimeArchive = 'runtime.zip'
        runtimeArchiveSizeBytes = $runtime.SizeBytes
        runtimeArchiveSha256 = $runtime.Sha256
        bootstrapperFile = 'Ensou.Dsh.Enterprise.Bootstrapper.exe'
        bootstrapperSizeBytes = $bootstrapper.SizeBytes
        bootstrapperSha256 = $bootstrapper.Sha256
        publishedAtUtc = [DateTimeOffset]::UtcNow.ToString(
            'O',
            [Globalization.CultureInfo]::InvariantCulture)
    }
    $manifestPath = Join-Path $Directory 'enterprise-install-manifest.json'
    $manifestValue |
        ConvertTo-Json -Depth 3 |
        Set-Content -LiteralPath $manifestPath -Encoding utf8NoBOM
    return [pscustomobject]@{
        Directory = $Directory
        Manifest = Get-FileDescriptor $manifestPath
        Launcher = $launcher
        Runtime = $runtime
        Bootstrapper = $bootstrapper
        LauncherReleaseId = $manifestValue.launcherReleaseId
        RuntimeReleaseId = $manifestValue.runtimeReleaseId
    }
}

function Get-SelfCheckArguments {
    param([Parameter(Mandatory = $true)]$Payload)

    return @(
        $Payload.LauncherReleaseId,
        $Payload.RuntimeReleaseId,
        $Payload.Manifest.Sha256,
        [string]$Payload.Manifest.SizeBytes,
        $Payload.Launcher.Sha256,
        [string]$Payload.Launcher.SizeBytes,
        $Payload.Runtime.Sha256,
        [string]$Payload.Runtime.SizeBytes,
        $Payload.Bootstrapper.Sha256,
        [string]$Payload.Bootstrapper.SizeBytes)
}

function Invoke-BoundedProcess {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][int]$ExpectedExitCode,
        [int]$TimeoutMilliseconds = 300000
    )

    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $FilePath
    $start.WorkingDirectory = $repositoryRoot
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.StandardOutputEncoding = [Text.UTF8Encoding]::new($false, $true)
    $start.StandardErrorEncoding = [Text.UTF8Encoding]::new($false, $true)
    foreach ($argument in $Arguments) {
        [void]$start.ArgumentList.Add($argument)
    }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    try {
        if (-not $process.Start()) {
            throw "Could not start payload-binding test process: $FilePath"
        }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutMilliseconds)) {
            $process.Kill($true)
            if (-not $process.WaitForExit(5000)) {
                throw "Payload-binding test process tree did not exit: $FilePath"
            }
            throw "Payload-binding test process timed out: $FilePath"
        }
        $process.WaitForExit()
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        if ($stdout.Length -gt 1MB -or $stderr.Length -gt 1MB) {
            throw "Payload-binding test process emitted unbounded output: $FilePath"
        }
        if ($process.ExitCode -ne $ExpectedExitCode) {
            throw "Payload-binding test process returned $($process.ExitCode), expected $ExpectedExitCode.`nSTDOUT: $stdout`nSTDERR: $stderr"
        }
        return [pscustomobject]@{
            ExitCode = $process.ExitCode
            Stdout = $stdout
            Stderr = $stderr
        }
    } finally {
        $process.Dispose()
    }
}

function Invoke-InstallerSelfCheck {
    param(
        [Parameter(Mandatory = $true)][string]$Installer,
        [Parameter(Mandatory = $true)][string[]]$Expected,
        [Parameter(Mandatory = $true)][int]$ExpectedExitCode,
        [ValidateSet(
            '--production-payload-self-check',
            '--development-production-payload-self-check')]
        [string]$Command = '--development-production-payload-self-check'
    )

    $result = Invoke-BoundedProcess `
        -FilePath $Installer `
        -Arguments (@($Command) + $Expected) `
        -ExpectedExitCode $ExpectedExitCode
    if ($ExpectedExitCode -eq 0) {
        if (-not [string]::IsNullOrEmpty($result.Stderr)) {
            throw 'Successful Installer payload self-check emitted stderr.'
        }
        $resultLine = $result.Stdout.TrimEnd([char[]]@("`r", "`n"))
        if ([string]::IsNullOrWhiteSpace($resultLine) -or
            $resultLine.Contains("`r", [StringComparison]::Ordinal) -or
            $resultLine.Contains("`n", [StringComparison]::Ordinal)) {
            throw 'Successful Installer payload self-check did not emit one JSON line.'
        }
        $selfCheck = $resultLine |
            ConvertFrom-Json -Depth 16 -DateKind String
        $expectedMembers = @(
            'schemaVersion',
            'resultType',
            'command',
            'status',
            'installerSha256',
            'launcherReleaseId',
            'runtimeReleaseId',
            'manifestSha256',
            'manifestSizeBytes',
            'launcherArchiveSha256',
            'launcherArchiveSizeBytes',
            'runtimeArchiveSha256',
            'runtimeArchiveSizeBytes',
            'bootstrapperSha256',
            'bootstrapperSizeBytes')
        if (@($selfCheck.PSObject.Properties.Name).Count -ne $expectedMembers.Count -or
            @(Compare-Object `
                -ReferenceObject $expectedMembers `
                -DifferenceObject @($selfCheck.PSObject.Properties.Name) `
                -CaseSensitive `
                -SyncWindow 0).Count -ne 0 -or
            ($selfCheck | ConvertTo-Json -Depth 16 -Compress) -cne $resultLine) {
            throw 'Successful Installer payload self-check output is not exact canonical JSON.'
        }
        $installerIdentity = Get-FileDescriptor -Path $Installer
        if ([int]$selfCheck.schemaVersion -ne 1 -or
            [string]$selfCheck.resultType -cne
                'ensou-dsh-enterprise-installer-production-payload-self-check' -or
            [string]$selfCheck.command -cne $Command -or
            [string]$selfCheck.status -cne 'VERIFIED' -or
            [string]$selfCheck.installerSha256 -cne
                [string]$installerIdentity.Sha256 -or
            [string]$selfCheck.launcherReleaseId -cne $Expected[0] -or
            [string]$selfCheck.runtimeReleaseId -cne $Expected[1] -or
            [string]$selfCheck.manifestSha256 -cne $Expected[2] -or
            [int64]$selfCheck.manifestSizeBytes -ne [int64]$Expected[3] -or
            [string]$selfCheck.launcherArchiveSha256 -cne $Expected[4] -or
            [int64]$selfCheck.launcherArchiveSizeBytes -ne [int64]$Expected[5] -or
            [string]$selfCheck.runtimeArchiveSha256 -cne $Expected[6] -or
            [int64]$selfCheck.runtimeArchiveSizeBytes -ne [int64]$Expected[7] -or
            [string]$selfCheck.bootstrapperSha256 -cne $Expected[8] -or
            [int64]$selfCheck.bootstrapperSizeBytes -ne [int64]$Expected[9]) {
            throw 'Successful Installer payload self-check JSON differs from its exact executable and expected payload.'
        }
    } else {
        $expectedStderr =
            'Ensou DSH Enterprise Installer machine command failed.'
        if (-not [string]::IsNullOrEmpty($result.Stdout) -or
            $result.Stderr.TrimEnd([char[]]@("`r", "`n")) -cne $expectedStderr) {
            throw 'Rejected Installer payload self-check escaped its fixed machine boundary.'
        }
    }
}

function Invoke-InstallerArgumentRejection {
    param(
        [Parameter(Mandatory = $true)][string]$Installer,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    if (-not $Arguments.Contains('--quiet')) {
        throw 'Installer argument-rejection probes must be quiet.'
    }
    $result = Invoke-BoundedProcess `
        -FilePath $Installer `
        -Arguments $Arguments `
        -ExpectedExitCode 1
    if (-not [string]::IsNullOrEmpty($result.Stdout) -or
        -not [string]::IsNullOrEmpty($result.Stderr)) {
        throw 'Quiet Installer argument rejection emitted output.'
    }
}

function Invoke-ProductionPublishValidation {
    param(
        [string]$PayloadDirectory,
        [Parameter(Mandatory = $true)][int]$ExpectedExitCode,
        [string]$ExpectedFailure
    )

    $arguments = @(
        'msbuild',
        $installerProject,
        '-t:ValidateEnterpriseInstallerPublish',
        '-p:EnterpriseDevelopmentE2E=false',
        ('-p:EnterpriseAuthenticodeSignerSha256Thumbprint=' + ('0' * 64)),
        '-p:RuntimeIdentifier=win-x64',
        '-p:SelfContained=true',
        '-p:PublishSingleFile=true',
        '-v:minimal')
    if (-not [string]::IsNullOrEmpty($PayloadDirectory)) {
        $arguments += "-p:EnterprisePayloadDirectory=$PayloadDirectory"
    }
    $result = Invoke-BoundedProcess `
        -FilePath 'dotnet' `
        -Arguments $arguments `
        -ExpectedExitCode $ExpectedExitCode `
        -TimeoutMilliseconds 60000
    if ($ExpectedExitCode -ne 0 -and
        -not ($result.Stdout + $result.Stderr).Contains(
            $ExpectedFailure,
            [StringComparison]::Ordinal)) {
        throw "Production publish validation failed for an unexpected reason: $ExpectedFailure`nSTDOUT: $($result.Stdout)`nSTDERR: $($result.Stderr)"
    }
}

function Copy-PayloadFixture {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    [IO.Directory]::CreateDirectory($Destination) | Out-Null
    foreach ($entry in [IO.Directory]::EnumerateFiles($Source)) {
        [IO.File]::Copy($entry, (Join-Path $Destination ([IO.Path]::GetFileName($entry))))
    }
}

function Import-GateFunction {
    param([Parameter(Mandatory = $true)][string]$Name)

    $tokens = $null
    $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile(
        $publishedGate,
        [ref]$tokens,
        [ref]$errors)
    if ($errors.Count -ne 0) {
        throw 'Published-artifact gate does not parse.'
    }
    $function = $ast.Find(
        {
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -ceq $Name
        },
        $true)
    if ($null -eq $function) {
        throw "Published-artifact gate function is missing: $Name"
    }
    Set-Item `
        -Path ("Function:\global:{0}" -f $Name) `
        -Value $function.Body.GetScriptBlock()
}

function Import-GateNativeIdentity {
    $tokens = $null
    $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile(
        $publishedGate,
        [ref]$tokens,
        [ref]$errors)
    if ($errors.Count -ne 0) {
        throw 'Published-artifact gate does not parse.'
    }
    $identityInitializer = $ast.Find(
        {
            param($node)
            $node -is [Management.Automation.Language.IfStatementAst] -and
                $node.Extent.Text.Contains(
                    'EnsouEnterprisePublishedGate.NativeFileIdentity',
                    [StringComparison]::Ordinal)
        },
        $true)
    if ($null -eq $identityInitializer) {
        throw 'Published-artifact gate native identity initialization is missing.'
    }
    & ([scriptblock]::Create($identityInitializer.Extent.Text))
}

[IO.Directory]::CreateDirectory($testRoot) | Out-Null
try {
    $installerProgramText = Get-Content -Raw -LiteralPath $installerProgram
    foreach ($requiredFlavorGuard in @(
        'if (!developmentSelfCheck && DevelopmentE2EEnabled)',
        'Development-E2E Installer cannot satisfy production payload checks.',
        'if (developmentSelfCheck && !DevelopmentE2EEnabled)',
        'Production Installer does not admit development payload checks.')) {
        if (-not $installerProgramText.Contains(
                $requiredFlavorGuard,
                [StringComparison]::Ordinal)) {
            throw "Installer payload self-check lost its symmetric flavor guard: $requiredFlavorGuard"
        }
    }

    [void](Invoke-BoundedProcess `
        -FilePath 'dotnet' `
        -Arguments @(
            'restore',
            $installerProject,
            '--locked-mode',
            '-p:Configuration=Release',
            '-p:EnterpriseDevelopmentE2E=true') `
        -ExpectedExitCode 0)

    $payloadA = New-PayloadFixture `
        -Directory (Join-Path $testRoot 'payload-a') `
        -Identity 'a'
    $payloadB = New-PayloadFixture `
        -Directory (Join-Path $testRoot 'payload-b') `
        -Identity 'bbbb'
    $developmentPayload = New-PayloadFixture `
        -Directory (Join-Path $testRoot 'payload-development') `
        -Identity 'development' `
        -LayoutProfile 'development-e2e'

    Import-GateFunction -Name 'Assert-ExactEnterprisePayloadInventory'
    Import-GateFunction -Name 'Assert-ExactArtifactBinding'
    Import-GateFunction -Name 'Assert-PayloadDescriptorBinding'
    Import-GateFunction -Name 'Read-StrictEnterprisePayloadManifest'
    Import-GateFunction -Name 'Resolve-SafeFile'
    Import-GateFunction -Name 'Open-LockedArtifact'
    Import-GateFunction -Name 'Get-LockedArtifactDescriptor'
    Import-GateFunction -Name 'Assert-LockedArtifactUnchanged'
    Import-GateNativeIdentity
    Assert-ExactEnterprisePayloadInventory `
        -Directory $payloadA.Directory `
        -LayoutProfile 'enterprise'
    Assert-ExactArtifactBinding `
        -Payload $payloadA.Bootstrapper `
        -Published $payloadA.Bootstrapper `
        -FailureMessage 'A/A Bootstrapper binding failed.'
    $bootstrapperMismatchRejected = $false
    try {
        Assert-ExactArtifactBinding `
            -Payload $payloadA.Bootstrapper `
            -Published $payloadB.Bootstrapper `
            -FailureMessage 'BOOTSTRAPPER-MISMATCH'
    } catch {
        if ($_.Exception.Message -cne 'BOOTSTRAPPER-MISMATCH') {
            throw
        }
        $bootstrapperMismatchRejected = $true
    }
    if (-not $bootstrapperMismatchRejected) {
        throw 'Published-artifact gate admitted an A/B Bootstrapper mismatch.'
    }

    $manifestPathA = Join-Path `
        $payloadA.Directory `
        'enterprise-install-manifest.json'
    $manifestLease = Open-LockedArtifact $manifestPathA
    try {
        $lockedManifestDescriptor = Get-LockedArtifactDescriptor $manifestLease
        if ($lockedManifestDescriptor.SizeBytes -ne $payloadA.Manifest.SizeBytes -or
            $lockedManifestDescriptor.Sha256 -cne $payloadA.Manifest.Sha256) {
            throw 'Gate locked manifest descriptor differs from the source bytes.'
        }
        $parsedManifest = Read-StrictEnterprisePayloadManifest `
            -Stream $manifestLease `
            -ExpectedLayoutProfile 'enterprise'
        if ($parsedManifest.LauncherReleaseId -cne $payloadA.LauncherReleaseId -or
            $parsedManifest.RuntimeReleaseId -cne $payloadA.RuntimeReleaseId) {
            throw 'Gate strict manifest parser changed release identity.'
        }
        Assert-PayloadDescriptorBinding `
            -Descriptor $payloadA.Launcher `
            -ExpectedSizeBytes $parsedManifest.LauncherArchiveSizeBytes `
            -ExpectedSha256 $parsedManifest.LauncherArchiveSha256 `
            -Name 'launcher.zip'
        $replacement = Join-Path $testRoot 'manifest-replacement.json'
        [IO.File]::WriteAllText($replacement, '{}')
        $replacementRejected = $false
        try {
            [IO.File]::Move($replacement, $manifestPathA, $true)
        } catch [IO.IOException] {
            $replacementRejected = $true
        } catch [UnauthorizedAccessException] {
            $replacementRejected = $true
        }
        if (-not $replacementRejected) {
            throw 'Gate manifest lease allowed path replacement.'
        }
        $lateHardlink = Join-Path $testRoot 'manifest-late-hardlink.json'
        New-Item `
            -ItemType HardLink `
            -Path $lateHardlink `
            -Target $manifestPathA | Out-Null
        try {
            $lateHardlinkRejected = $false
            try {
                Assert-LockedArtifactUnchanged `
                    -Stream $manifestLease `
                    -Expected $lockedManifestDescriptor `
                    -Name $manifestPathA
            } catch [IO.InvalidDataException] {
                $lateHardlinkRejected = $true
            }
            if (-not $lateHardlinkRejected) {
                throw 'Gate admitted a hardlink added after the locked snapshot opened.'
            }
        } finally {
            [IO.File]::Delete($lateHardlink)
        }
        Assert-LockedArtifactUnchanged `
            -Stream $manifestLease `
            -Expected $lockedManifestDescriptor `
            -Name $manifestPathA
    } finally {
        $manifestLease.Dispose()
    }

    $hardlink = Join-Path $testRoot 'launcher-hardlink.zip'
    New-Item `
        -ItemType HardLink `
        -Path $hardlink `
        -Target (Join-Path $payloadA.Directory 'launcher.zip') | Out-Null
    try {
        $hardlinkRejected = $false
        try {
            $unsafeLease = Open-LockedArtifact `
                (Join-Path $payloadA.Directory 'launcher.zip')
            $unsafeLease.Dispose()
        } catch [IO.InvalidDataException] {
            $hardlinkRejected = $true
        }
        if (-not $hardlinkRejected) {
            throw 'Gate admitted a pre-existing payload hardlink.'
        }
    } finally {
        [IO.File]::Delete($hardlink)
    }

    $junction = Join-Path $testRoot 'payload-junction'
    New-Item `
        -ItemType Junction `
        -Path $junction `
        -Target $payloadA.Directory | Out-Null
    try {
        $reparseRejected = $false
        try {
            $null = Resolve-SafeFile `
                (Join-Path $junction 'enterprise-install-manifest.json')
        } catch {
            if ($_.Exception.Message.Contains(
                    'filesystem link',
                    [StringComparison]::Ordinal)) {
                $reparseRejected = $true
            } else {
                throw
            }
        }
        if (-not $reparseRejected) {
            throw 'Gate admitted a payload path through a reparse ancestor.'
        }
    } finally {
        [IO.Directory]::Delete($junction)
    }

    Invoke-ProductionPublishValidation `
        -ExpectedExitCode 1 `
        -ExpectedFailure 'requires EnterprisePayloadDirectory'
    Invoke-ProductionPublishValidation `
        -PayloadDirectory $payloadA.Directory `
        -ExpectedExitCode 0
    foreach ($missingName in @(
        'enterprise-install-manifest.json',
        'launcher.zip',
        'runtime.zip',
        'Ensou.Dsh.Enterprise.Bootstrapper.exe')) {
        $missingRoot = Join-Path `
            $testRoot `
            ("missing-{0}" -f $missingName.Replace('.', '-'))
        Copy-PayloadFixture -Source $payloadA.Directory -Destination $missingRoot
        [IO.File]::Delete((Join-Path $missingRoot $missingName))
        $gateMissingRejected = $false
        try {
            Assert-ExactEnterprisePayloadInventory `
                -Directory $missingRoot `
                -LayoutProfile 'enterprise'
        } catch {
            if ($_.Exception.Message -cne
                'Enterprise payload directory does not contain its exact fixed ordinary-file inventory.') {
                throw
            }
            $gateMissingRejected = $true
        }
        if (-not $gateMissingRejected) {
            throw "Published-artifact gate admitted a missing payload file: $missingName"
        }
        Invoke-ProductionPublishValidation `
            -PayloadDirectory $missingRoot `
            -ExpectedExitCode 1 `
            -ExpectedFailure "payload is missing $missingName"
    }
    $extraRoot = Join-Path $testRoot 'extra-payload'
    Copy-PayloadFixture -Source $payloadA.Directory -Destination $extraRoot
    [IO.File]::WriteAllText((Join-Path $extraRoot 'extra.bin'), 'extra')
    $gateExtraRejected = $false
    try {
        Assert-ExactEnterprisePayloadInventory `
            -Directory $extraRoot `
            -LayoutProfile 'enterprise'
    } catch {
        if ($_.Exception.Message -cne
            'Enterprise payload directory does not contain its exact fixed ordinary-file inventory.') {
            throw
        }
        $gateExtraRejected = $true
    }
    if (-not $gateExtraRejected) {
        throw 'Published-artifact gate admitted an extra payload entry.'
    }
    Invoke-ProductionPublishValidation `
        -PayloadDirectory $extraRoot `
        -ExpectedExitCode 1 `
        -ExpectedFailure 'must contain exactly its four fixed files'
    $nestedRoot = Join-Path $testRoot 'nested-payload'
    Copy-PayloadFixture -Source $payloadA.Directory -Destination $nestedRoot
    [IO.Directory]::CreateDirectory((Join-Path $nestedRoot 'empty')) | Out-Null
    $gateNestedRejected = $false
    try {
        Assert-ExactEnterprisePayloadInventory `
            -Directory $nestedRoot `
            -LayoutProfile 'enterprise'
    } catch {
        if ($_.Exception.Message -cne
            'Enterprise payload directory does not contain its exact fixed ordinary-file inventory.') {
            throw
        }
        $gateNestedRejected = $true
    }
    if (-not $gateNestedRejected) {
        throw 'Published-artifact gate admitted a nested payload directory.'
    }
    Invoke-ProductionPublishValidation `
        -PayloadDirectory $nestedRoot `
        -ExpectedExitCode 1 `
        -ExpectedFailure 'must not contain subdirectories'

    $publishRoot = Join-Path $testRoot 'installer-publish'
    $publishResult = Invoke-BoundedProcess `
        -FilePath 'dotnet' `
        -Arguments @(
            'publish',
            $installerProject,
            '-c', 'Release',
            '-r', 'win-x64',
            '--self-contained', 'true',
            '--no-restore',
            '-p:PublishSingleFile=true',
            '-p:EnterpriseDevelopmentE2E=true',
            "-p:EnterprisePayloadDirectory=$($developmentPayload.Directory)",
            '--output', $publishRoot) `
        -ExpectedExitCode 0
    $installer = Join-Path `
        $publishRoot `
        'Ensou.Dsh.Enterprise.Installer.exe'
    if (-not (Test-Path -LiteralPath $installer -PathType Leaf)) {
        throw 'Development fixture Installer publish produced no executable.'
    }

    $installerLease = [IO.File]::Open(
        $installer,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    try {
        $expectedDevelopment = [string[]](Get-SelfCheckArguments $developmentPayload)
        Invoke-InstallerSelfCheck `
            -Installer $installer `
            -Expected $expectedDevelopment `
            -ExpectedExitCode 0
        Invoke-InstallerSelfCheck `
            -Installer $installer `
            -Expected $expectedDevelopment `
            -ExpectedExitCode 1 `
            -Command '--production-payload-self-check'
        Invoke-InstallerSelfCheck `
            -Installer $installer `
            -Expected ([string[]](Get-SelfCheckArguments $payloadB)) `
            -ExpectedExitCode 1

        foreach ($field in @(
            [pscustomobject]@{ Name = 'manifest-hash'; Index = 2; Hash = $true },
            [pscustomobject]@{ Name = 'manifest-size'; Index = 3; Hash = $false },
            [pscustomobject]@{ Name = 'launcher-hash'; Index = 4; Hash = $true },
            [pscustomobject]@{ Name = 'launcher-size'; Index = 5; Hash = $false },
            [pscustomobject]@{ Name = 'runtime-hash'; Index = 6; Hash = $true },
            [pscustomobject]@{ Name = 'runtime-size'; Index = 7; Hash = $false },
            [pscustomobject]@{ Name = 'bootstrapper-hash'; Index = 8; Hash = $true },
            [pscustomobject]@{ Name = 'bootstrapper-size'; Index = 9; Hash = $false })) {
            $mutated = [string[]]$expectedDevelopment.Clone()
            $mutated[$field.Index] = if ($field.Hash) {
                if ($mutated[$field.Index][0] -ceq '0') {
                    '1' + $mutated[$field.Index].Substring(1)
                } else {
                    '0' + $mutated[$field.Index].Substring(1)
                }
            } else {
                ([long]$mutated[$field.Index] + 1).ToString(
                    [Globalization.CultureInfo]::InvariantCulture)
            }
            Invoke-InstallerSelfCheck `
                -Installer $installer `
                -Expected $mutated `
                -ExpectedExitCode 1
        }

        $bootstrapperOnlyMismatch = [string[]]$expectedDevelopment.Clone()
        $bootstrapperOnlyMismatch[8] = $payloadB.Bootstrapper.Sha256
        $bootstrapperOnlyMismatch[9] = [string]$payloadB.Bootstrapper.SizeBytes
        Invoke-InstallerSelfCheck `
            -Installer $installer `
            -Expected $bootstrapperOnlyMismatch `
            -ExpectedExitCode 1

        $argumentRoot = Join-Path $testRoot 'argument-rejection'
        $localRoot = Join-Path $argumentRoot 'local-app-data'
        $profileRoot = Join-Path $argumentRoot 'profile'
        $completeArguments = @(
            '--install',
            '--quiet',
            '--dev-unsigned',
            '--dev-e2e-layout',
            '--dev-e2e-no-shell-registration',
            '--dev-e2e-local-app-data-root', $localRoot,
            '--dev-e2e-user-profile-root', $profileRoot)
        foreach ($omittedOption in @(
            '--dev-unsigned',
            '--dev-e2e-layout',
            '--dev-e2e-no-shell-registration',
            '--dev-e2e-local-app-data-root',
            '--dev-e2e-user-profile-root')) {
            $rejectedArguments = [Collections.Generic.List[string]]::new()
            for ($index = 0; $index -lt $completeArguments.Count; $index++) {
                if ($completeArguments[$index] -ceq $omittedOption) {
                    if ($omittedOption -in @(
                            '--dev-e2e-local-app-data-root',
                            '--dev-e2e-user-profile-root')) {
                        $index++
                    }
                    continue
                }
                $rejectedArguments.Add($completeArguments[$index])
            }
            Invoke-InstallerArgumentRejection `
                -Installer $installer `
                -Arguments $rejectedArguments.ToArray()
            if ([IO.Directory]::Exists($argumentRoot)) {
                throw "Rejected embedded development arguments wrote isolation state: $omittedOption"
            }
        }
    } finally {
        $installerLease.Dispose()
    }

    $productionPublishRoot = Join-Path `
        $testRoot `
        'installer-production-unsigned-publish'
    $productionPublishResult = Invoke-BoundedProcess `
        -FilePath 'dotnet' `
        -Arguments @(
            'publish',
            $installerProject,
            '-c', 'Release',
            '-r', 'win-x64',
            '--self-contained', 'true',
            '--no-restore',
            '-p:PublishSingleFile=true',
            '-p:EnterpriseDevelopmentE2E=false',
            ('-p:EnterpriseAuthenticodeSignerSha256Thumbprint=' + ('0' * 64)),
            "-p:EnterprisePayloadDirectory=$($payloadA.Directory)",
            '--output', $productionPublishRoot) `
        -ExpectedExitCode 0
    $productionInstaller = Join-Path `
        $productionPublishRoot `
        'Ensou.Dsh.Enterprise.Installer.exe'
    if (-not (Test-Path -LiteralPath $productionInstaller -PathType Leaf)) {
        throw 'Unsigned production fixture Installer publish produced no executable.'
    }
    $productionInstallerLease = [IO.File]::Open(
        $productionInstaller,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    try {
        $expectedA = [string[]](Get-SelfCheckArguments $payloadA)
        Invoke-InstallerSelfCheck `
            -Installer $productionInstaller `
            -Expected $expectedA `
            -ExpectedExitCode 1 `
            -Command '--development-production-payload-self-check'
        Invoke-InstallerSelfCheck `
            -Installer $productionInstaller `
            -Expected $expectedA `
            -ExpectedExitCode 1 `
            -Command '--production-payload-self-check'
        Invoke-InstallerArgumentRejection `
            -Installer $productionInstaller `
            -Arguments @(
                '--install',
                '--quiet',
                '--dev-unsigned',
                '--dev-e2e-layout',
                '--dev-e2e-no-shell-registration',
                '--dev-e2e-local-app-data-root',
                (Join-Path $testRoot 'production-rejection-local'),
                '--dev-e2e-user-profile-root',
                (Join-Path $testRoot 'production-rejection-profile'))
    }
    finally {
        $productionInstallerLease.Dispose()
    }

    'ENTERPRISE-INSTALLER-PAYLOAD-BINDING-PASS'
} finally {
    $resolvedTestRoot = [IO.Path]::GetFullPath($testRoot)
    $expectedPrefix = [IO.Path]::TrimEndingDirectorySeparator(
        [IO.Path]::GetFullPath([IO.Path]::GetTempPath())) +
        [IO.Path]::DirectorySeparatorChar +
        'ensou-enterprise-installer-payload-binding-'
    if (-not $resolvedTestRoot.StartsWith(
            $expectedPrefix,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Refusing to remove an unexpected payload-binding test directory.'
    }
    if ([IO.Directory]::Exists($resolvedTestRoot)) {
        [GC]::Collect()
        [GC]::WaitForPendingFinalizers()
        [GC]::Collect()
        for ($attempt = 0; $attempt -lt 50; $attempt++) {
            try {
                [IO.Directory]::Delete($resolvedTestRoot, $true)
                break
            }
            catch [IO.IOException], [UnauthorizedAccessException] {
                if ($attempt -eq 49) {
                    throw
                }
                [GC]::Collect()
                [GC]::WaitForPendingFinalizers()
                Start-Sleep -Milliseconds 100
            }
        }
    }
}
