#requires -Version 7.2

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$stateModulePath = Join-Path $PSScriptRoot 'ProductionReleaseState.psm1'
Microsoft.PowerShell.Core\Import-Module $stateModulePath -Force -ErrorAction Stop
$signingContractsPath = Join-Path $PSScriptRoot 'InstallerSigningContracts.psm1'
Microsoft.PowerShell.Core\Import-Module `
    $signingContractsPath `
    -Force `
    -ErrorAction Stop
$portableDotNetSdkClosurePath =
    Join-Path $PSScriptRoot 'PortableDotNetSdkClosure.psm1'
Microsoft.PowerShell.Core\Import-Module `
    $portableDotNetSdkClosurePath `
    -Force `
    -ErrorAction Stop
# InstallerSigningContracts imports the state module into its own scope. Import
# both dependency modules before importing the state contract last so all three
# qualified module names remain available here.
Microsoft.PowerShell.Core\Import-Module $stateModulePath -Force -ErrorAction Stop

$script:RepositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$script:RootProjectRelativePath =
    'src/Ensou.Dsh.Enterprise.Installer/Ensou.Dsh.Enterprise.Installer.csproj'
$script:InstallerFileName = 'Ensou.Dsh.Enterprise.Installer.exe'
$script:PackageLockRelativePath =
    'installer/enterprise-publish-runtime-packs.lock.json'
$script:PortableDotNetSdkLockRelativePath =
    'release/locks/dotnet-sdk-10.0.302-win-x64.files.lock.json'
$script:PortableDotNetSdkArchiveFileName =
    'dotnet-sdk-10.0.302-win-x64.zip'
$script:SubprocessEnvironmentPolicy =
    'clear-all-inherited-then-explicit-allowlist-and-msbuild-property-pins-v1'
$script:TrustedProcessEnvironmentOverrideNames =
    [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
foreach ($name in @(
        'DOTNET_CLI_HOME',
        'DOTNET_CLI_TELEMETRY_OPTOUT',
        'DOTNET_CLI_USE_MSBUILD_SERVER',
        'DOTNET_ROOT',
        'DOTNET_ROOT_X64',
        'DOTNET_MULTILEVEL_LOOKUP',
        'DOTNET_NOLOGO',
        'DOTNET_SKIP_FIRST_TIME_EXPERIENCE',
        'NUGET_PACKAGES',
        'MSBUILDDISABLENODEREUSE',
        'LOCALAPPDATA',
        'APPDATA',
        'USERPROFILE',
        'HOME',
        'HTTP_PROXY',
        'HTTPS_PROXY',
        'ALL_PROXY',
        'NO_PROXY',
        'TEMP',
        'TMP')) {
    [void]$script:TrustedProcessEnvironmentOverrideNames.Add($name)
}
$script:PayloadDefinitions = @(
    [pscustomobject]@{
        Role = 'install-manifest'
        FileName = 'enterprise-install-manifest.json'
        LogicalName =
            'Ensou.Dsh.Enterprise.Installer.Payload.enterprise-install-manifest.json'
        SourceKind = 'generated-descriptor'
        SourceRole = 'install-manifest'
    },
    [pscustomobject]@{
        Role = 'launcher'
        FileName = 'launcher.zip'
        LogicalName = 'Ensou.Dsh.Enterprise.Installer.Payload.launcher.zip'
        SourceKind = 'r5-candidate'
        SourceRole = 'launcher'
    },
    [pscustomobject]@{
        Role = 'runtime'
        FileName = 'runtime.zip'
        LogicalName = 'Ensou.Dsh.Enterprise.Installer.Payload.runtime.zip'
        SourceKind = 'r5-candidate'
        SourceRole = 'runtime'
    },
    [pscustomobject]@{
        Role = 'bootstrapper'
        FileName = 'Ensou.Dsh.Enterprise.Bootstrapper.exe'
        LogicalName =
            'Ensou.Dsh.Enterprise.Installer.Payload.Ensou.Dsh.Enterprise.Bootstrapper.exe'
        SourceKind = 'r3-signed-client'
        SourceRole = 'bootstrapper'
    })

function Assert-EnterpriseTrustedBuildHost {
    if (-not $IsWindows -or
        $PSVersionTable.PSEdition -ne 'Core' -or
        $PSVersionTable.PSVersion -lt [version]'7.2' -or
        [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -ne
            [Runtime.InteropServices.Architecture]::X64) {
        throw 'Enterprise Installer trusted build requires native Windows x64 and PowerShell 7.2 or newer.'
    }
}

function Resolve-EnterpriseTrustedDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if (-not [IO.Path]::IsPathFullyQualified($Path) -or
        $Path.StartsWith('\\', [StringComparison]::Ordinal) -or
        $Path.StartsWith('//', [StringComparison]::Ordinal)) {
        throw "$Label must be an absolute local path."
    }
    $fullPath = [IO.Path]::GetFullPath($Path)
    $item = Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Label must be one ordinary non-linked directory: $fullPath"
    }
    for ($current = $item; $null -ne $current; $current = $current.Parent) {
        if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Label crosses a filesystem link: $fullPath"
        }
    }
    return $fullPath
}

function Test-EnterpriseTrustedSameOrDescendant {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Root
    )

    $candidate = [IO.Path]::TrimEndingDirectorySeparator(
        [IO.Path]::GetFullPath($Path))
    $boundary = [IO.Path]::TrimEndingDirectorySeparator(
        [IO.Path]::GetFullPath($Root))
    return $candidate.Equals($boundary, [StringComparison]::OrdinalIgnoreCase) -or
        $candidate.StartsWith(
            $boundary + [IO.Path]::DirectorySeparatorChar,
            [StringComparison]::OrdinalIgnoreCase)
}

function ConvertTo-EnterpriseTrustedRelativePath {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $relative = [IO.Path]::GetRelativePath($Root, $Path).Replace('\', '/')
    if ($relative -cnotmatch
        '^[A-Za-z0-9._+-]+(?:/[A-Za-z0-9._+-]+)*$' -or
        @($relative.Split('/') | Where-Object { $_ -in @('', '.', '..') }).Count -ne 0) {
        throw "Trusted build input has a noncanonical identity path: $relative"
    }
    return $relative
}

function Get-EnterpriseTrustedUtcNow {
    return [DateTimeOffset]::UtcNow.ToString(
        "yyyy-MM-dd'T'HH:mm:ss'Z'",
        [Globalization.CultureInfo]::InvariantCulture)
}

function ConvertTo-EnterpriseTrustedBase64Url {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    return [Convert]::ToBase64String($Bytes).TrimEnd('=').
        Replace('+', '-').Replace('/', '_')
}

function Get-EnterpriseTrustedEvidenceFile {
    param(
        [Parameter(Mandatory = $true)][object[]]$Files,
        [Parameter(Mandatory = $true)][string]$Role,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $matches = @($Files | Where-Object { [string]$_.role -ceq $Role })
    if ($matches.Count -ne 1) {
        throw "$Label must contain exactly one role '$Role'."
    }
    return $matches[0]
}

function Get-EnterpriseTrustedSha256FromPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    $stream = [IO.File]::Open(
        $Path,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    try {
        return [Convert]::ToHexString(
            [Security.Cryptography.SHA256]::HashData($stream)).ToLowerInvariant()
    }
    finally {
        $stream.Dispose()
    }
}

function Get-EnterpriseTrustedSha512Base64 {
    param([Parameter(Mandatory = $true)]$Descriptor)

    $Descriptor.Stream.Position = 0
    $algorithm = [Security.Cryptography.SHA512]::Create()
    try {
        $result = [Convert]::ToBase64String(
            $algorithm.ComputeHash($Descriptor.Stream))
        $Descriptor.Stream.Position = 0
        return $result
    }
    finally {
        $algorithm.Dispose()
    }
}

function Copy-EnterpriseTrustedDescriptor {
    param(
        [Parameter(Mandatory = $true)]$Descriptor,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )

    ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
        -Descriptor $Descriptor `
        -Label $Label
    $parent = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($Path))
    [IO.Directory]::CreateDirectory($parent) | Out-Null
    $output = [IO.FileStream]::new(
        $Path,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None,
        1MB,
        [IO.FileOptions]::WriteThrough)
    try {
        $Descriptor.Stream.Position = 0
        $Descriptor.Stream.CopyTo($output)
        $output.Flush($true)
        $Descriptor.Stream.Position = 0
    }
    finally {
        $output.Dispose()
    }
    if ((Get-Item -LiteralPath $Path -Force).Length -ne
            [int64]$Descriptor.SizeBytes -or
        (Get-EnterpriseTrustedSha256FromPath -Path $Path) -cne
            [string]$Descriptor.Sha256) {
        throw "$Label snapshot differs from the locked input."
    }
}

function Invoke-EnterpriseTrustedProcess {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [hashtable]$Environment = @{},
        [string]$StandardOutputFile = '',
        [int]$TimeoutMilliseconds = 600000
    )

    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $FilePath
    $start.WorkingDirectory = $WorkingDirectory
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.WindowStyle = [Diagnostics.ProcessWindowStyle]::Hidden
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.StandardOutputEncoding = [Text.UTF8Encoding]::new($false, $true)
    $start.StandardErrorEncoding = [Text.UTF8Encoding]::new($false, $true)
    # Environment variables with MSBuild property names are global properties.
    # A denylist is therefore incomplete: clear the complete inherited process
    # environment before adding only the OS bootstrap values and exact internal
    # build values admitted below.
    $start.Environment.Clear()
    $windowsDirectory = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::Windows)
    $systemDirectory = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::System)
    if ([string]::IsNullOrWhiteSpace($windowsDirectory) -or
        [string]::IsNullOrWhiteSpace($systemDirectory)) {
        throw 'Trusted build could not resolve the Windows system directories.'
    }
    $executableDirectory = [IO.Path]::GetDirectoryName(
        [IO.Path]::GetFullPath($FilePath))
    foreach ($entry in ([ordered]@{
            SystemRoot = $windowsDirectory
            WINDIR = $windowsDirectory
            ComSpec = Join-Path $systemDirectory 'cmd.exe'
            OS = 'Windows_NT'
            PATHEXT = '.COM;.EXE;.BAT;.CMD'
            PATH = ($executableDirectory + ';' + $systemDirectory + ';' +
                $windowsDirectory)
        }).GetEnumerator()) {
        $start.Environment[[string]$entry.Key] = [string]$entry.Value
    }
    $programFiles = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::ProgramFiles)
    $programFilesX86 = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::ProgramFilesX86)
    $commonProgramFiles = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::CommonProgramFiles)
    $commonProgramFilesX86 = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::CommonProgramFilesX86)
    $commonApplicationData = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::CommonApplicationData)
    foreach ($entry in ([ordered]@{
            ProgramFiles = $programFiles
            'ProgramFiles(x86)' = $programFilesX86
            ProgramW6432 = $programFiles
            CommonProgramFiles = $commonProgramFiles
            'CommonProgramFiles(x86)' = $commonProgramFilesX86
            CommonProgramW6432 = $commonProgramFiles
            ProgramData = $commonApplicationData
            ALLUSERSPROFILE = $commonApplicationData
        }).GetEnumerator()) {
        if (-not [string]::IsNullOrWhiteSpace([string]$entry.Value)) {
            $start.Environment[[string]$entry.Key] = [string]$entry.Value
        }
    }
    foreach ($argument in $Arguments) {
        [void]$start.ArgumentList.Add($argument)
    }
    foreach ($name in $Environment.Keys) {
        if (-not $script:TrustedProcessEnvironmentOverrideNames.Contains(
                [string]$name)) {
            throw "Trusted build process environment override is not allowed: $name"
        }
        $start.Environment[[string]$name] = [string]$Environment[$name]
    }
    if (-not [string]::IsNullOrEmpty($StandardOutputFile)) {
        if (-not [IO.Path]::IsPathFullyQualified($StandardOutputFile) -or
            [IO.File]::Exists($StandardOutputFile) -or
            -not [IO.Directory]::Exists(
                [IO.Path]::GetDirectoryName($StandardOutputFile))) {
            throw 'Trusted build binary process output must be a new file in an existing directory.'
        }
    }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    $stdoutFile = $null
    try {
        if (-not $process.Start()) {
            throw "Trusted build could not start $FilePath."
        }
        if ([string]::IsNullOrEmpty($StandardOutputFile)) {
            $stdoutTask = $process.StandardOutput.ReadToEndAsync()
            $stdoutCopyTask = $null
        }
        else {
            $stdoutFile = [IO.FileStream]::new(
                $StandardOutputFile,
                [IO.FileMode]::CreateNew,
                [IO.FileAccess]::Write,
                [IO.FileShare]::None,
                1MB,
                [IO.FileOptions]::WriteThrough)
            $stdoutTask = $null
            $stdoutCopyTask =
                $process.StandardOutput.BaseStream.CopyToAsync($stdoutFile)
        }
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutMilliseconds)) {
            $process.Kill($true)
            [void]$process.WaitForExit(5000)
            throw "Trusted build process timed out: $FilePath"
        }
        $process.WaitForExit()
        if ($null -ne $stdoutTask) {
            $stdout = $stdoutTask.GetAwaiter().GetResult()
        }
        else {
            $stdoutCopyTask.GetAwaiter().GetResult()
            $stdoutFile.Flush($true)
            $stdoutFile.Dispose()
            $stdoutFile = $null
            $stdout = ''
        }
        $stderr = $stderrTask.GetAwaiter().GetResult()
        if ($stdout.Length -gt 4MB -or $stderr.Length -gt 4MB -or
            (-not [string]::IsNullOrEmpty($StandardOutputFile) -and
                (Get-Item -LiteralPath $StandardOutputFile -Force).Length -gt
                    1GB)) {
            throw "Trusted build process exceeded its output bound: $FilePath"
        }
        if ($process.ExitCode -ne 0) {
            throw "Trusted build process failed with exit code $($process.ExitCode): $FilePath`nSTDOUT: $stdout`nSTDERR: $stderr"
        }
        return [pscustomobject]@{
            ExitCode = $process.ExitCode
            Stdout = $stdout
            Stderr = $stderr
        }
    }
    finally {
        if ($null -ne $stdoutFile) {
            $stdoutFile.Dispose()
        }
        $process.Dispose()
    }
}

function Get-EnterpriseTrustedGitValue {
    param(
        [Parameter(Mandatory = $true)][string]$GitPath,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    $effectiveArguments = @(
        '-C', $script:RepositoryRoot,
        "--work-tree=$script:RepositoryRoot") + $Arguments
    $result = Invoke-EnterpriseTrustedProcess `
        -FilePath $GitPath `
        -Arguments $effectiveArguments `
        -WorkingDirectory $script:RepositoryRoot `
        -TimeoutMilliseconds 60000
    return $result.Stdout.TrimEnd([char[]]@("`r", "`n"))
}

function Get-EnterpriseTrustedTrackedEntries {
    param([Parameter(Mandatory = $true)][string]$GitPath)

    $output = Get-EnterpriseTrustedGitValue `
        -GitPath $GitPath `
        -Arguments @('-c', 'core.quotepath=false', 'ls-files', '--stage')
    $entries = [Collections.Generic.List[object]]::new()
    $names = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    foreach ($line in @($output -split "`n")) {
        $canonicalLine = $line.TrimEnd("`r")
        if ($canonicalLine -notmatch
            '^(?<mode>[0-9]{6}) (?<object>[0-9a-f]{40,64}) 0\t(?<path>.+)$') {
            throw 'Git tracked inventory contains a noncanonical stage entry.'
        }
        $mode = [string]$Matches.mode
        $objectId = [string]$Matches.object
        $relative = [string]$Matches.path
        if ($mode -notin @('100644', '100755') -or
            $relative -cnotmatch
                '^[A-Za-z0-9._+-]+(?:/[A-Za-z0-9._+-]+)*$' -or
            -not $names.Add($relative)) {
            throw "Git tracked inventory contains a link, submodule, collision, or unsafe path: $relative"
        }
        $entries.Add([pscustomobject]@{
            Mode = $mode
            ObjectId = $objectId
            RelativePath = $relative
        })
    }
    if ($entries.Count -eq 0) {
        throw 'Git tracked inventory is empty.'
    }
    return @($entries)
}

function Assert-EnterpriseTrustedGitBlobBinding {
    param(
        [Parameter(Mandatory = $true)]$Descriptor,
        [Parameter(Mandatory = $true)][string]$ExpectedObjectId,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $algorithm = if ($ExpectedObjectId.Length -eq 40) {
        [Security.Cryptography.HashAlgorithmName]::SHA1
    }
    elseif ($ExpectedObjectId.Length -eq 64) {
        [Security.Cryptography.HashAlgorithmName]::SHA256
    }
    else {
        throw "$Label has an unsupported Git object identifier."
    }
    $hash = [Security.Cryptography.IncrementalHash]::CreateHash($algorithm)
    try {
        $header = [Text.Encoding]::ASCII.GetBytes(
            "blob $([int64]$Descriptor.SizeBytes)$([char]0)")
        $hash.AppendData($header)
        $Descriptor.Stream.Position = 0
        $buffer = [byte[]]::new(1MB)
        while (($read = $Descriptor.Stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $hash.AppendData($buffer, 0, $read)
        }
        $actualObjectId = [Convert]::ToHexString(
            $hash.GetHashAndReset()).ToLowerInvariant()
    }
    finally {
        $Descriptor.Stream.Position = 0
        $hash.Dispose()
    }
    if ($actualObjectId -cne $ExpectedObjectId) {
        throw "$Label bytes do not match the admitted Git blob object."
    }
}

function Copy-EnterpriseTrustedGitBlob {
    param(
        [Parameter(Mandatory = $true)][string]$GitPath,
        [Parameter(Mandatory = $true)][string]$ObjectId,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $parent = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($Path))
    [IO.Directory]::CreateDirectory($parent) | Out-Null
    [void](Invoke-EnterpriseTrustedProcess `
            -FilePath $GitPath `
            -Arguments @(
                '-C', $script:RepositoryRoot,
                "--work-tree=$script:RepositoryRoot",
                'cat-file', 'blob', $ObjectId) `
            -WorkingDirectory $script:RepositoryRoot `
            -StandardOutputFile $Path `
            -TimeoutMilliseconds 60000)
}

function Get-EnterpriseTrustedProjectClosure {
    param([Parameter(Mandatory = $true)][string]$SnapshotRoot)

    $queue = [Collections.Generic.Queue[string]]::new()
    $queue.Enqueue($script:RootProjectRelativePath)
    $seen = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    $projects = [Collections.Generic.List[string]]::new()
    while ($queue.Count -gt 0) {
        $relative = $queue.Dequeue()
        if (-not $seen.Add($relative)) {
            continue
        }
        $path = Join-Path $SnapshotRoot $relative.Replace('/', '\')
        if (-not [IO.File]::Exists($path)) {
            throw "Transitive project is missing from the tracked snapshot: $relative"
        }
        $projects.Add($relative)
        [xml]$projectXml = [IO.File]::ReadAllText(
            $path,
            [Text.UTF8Encoding]::new($false, $true))
        foreach ($reference in @($projectXml.SelectNodes('//ProjectReference'))) {
            $include = [string]$reference.Include
            if ([string]::IsNullOrWhiteSpace($include)) {
                throw "ProjectReference has no Include value: $relative"
            }
            $resolved = [IO.Path]::GetFullPath(
                (Join-Path ([IO.Path]::GetDirectoryName($path)) $include))
            if (-not (Test-EnterpriseTrustedSameOrDescendant `
                    -Path $resolved `
                    -Root $SnapshotRoot)) {
                throw "ProjectReference escapes the tracked snapshot: $relative"
            }
            $child = ConvertTo-EnterpriseTrustedRelativePath `
                -Root $SnapshotRoot `
                -Path $resolved
            if (-not $child.EndsWith('.csproj', [StringComparison]::Ordinal)) {
                throw "ProjectReference is not an exact C# project: $child"
            }
            $queue.Enqueue($child)
        }
    }
    $array = $projects.ToArray()
    [Array]::Sort($array, [StringComparer]::OrdinalIgnoreCase)
    foreach ($projectPath in $array) {
        $lock = $projectPath.Substring(0, $projectPath.LastIndexOf('/') + 1) +
            'packages.lock.json'
        if (-not [IO.File]::Exists(
                (Join-Path $SnapshotRoot $lock.Replace('/', '\')))) {
            throw "Transitive project has no tracked packages.lock.json: $projectPath"
        }
    }
    return $array
}

function New-EnterpriseTrustedInputRecord {
    param(
        [Parameter(Mandatory = $true)][string]$Kind,
        [Parameter(Mandatory = $true)][string]$IdentityPath,
        [Parameter(Mandatory = $true)][string]$SnapshotPath,
        [Parameter(Mandatory = $true)][string]$OutputRoot
    )

    $item = Get-Item -LiteralPath $SnapshotPath -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $item.Length -le 0 -or $item.Length -gt 1GB) {
        throw "Trusted build snapshot is not one bounded ordinary file: $IdentityPath"
    }
    return [ordered]@{
        kind = $Kind
        identityPath = $IdentityPath
        snapshotRelativePath = ConvertTo-EnterpriseTrustedRelativePath `
            -Root $OutputRoot `
            -Path $SnapshotPath
        sizeBytes = [int64]$item.Length
        sha256 = Get-EnterpriseTrustedSha256FromPath -Path $SnapshotPath
    }
}

function Sort-EnterpriseTrustedInputRecords {
    param([Parameter(Mandatory = $true)][object[]]$Records)

    $array = @($Records)
    [Array]::Sort(
        $array,
        [Collections.Generic.Comparer[object]]::Create({
                param($left, $right)
                return [string]::Compare(
                    [string]$left.identityPath,
                    [string]$right.identityPath,
                    [StringComparison]::OrdinalIgnoreCase)
            }))
    return $array
}

function Assert-EnterpriseTrustedContext {
    param(
        [Parameter(Mandatory = $true)]$PlanInput,
        [Parameter(Mandatory = $true)][psobject]$ProductionState,
        [Parameter(Mandatory = $true)]$BaseHeadInput,
        [Parameter(Mandatory = $true)]$R5ReceiptInput,
        [Parameter(Mandatory = $true)]$R3ReceiptInput,
        [Parameter(Mandatory = $true)][object[]]$PayloadInputs,
        [Parameter(Mandatory = $true)][psobject]$PayloadAdmission
    )

    foreach ($binding in @(
            [pscustomobject]@{ Value = $PlanInput; Label = 'Plan input' },
            [pscustomobject]@{ Value = $BaseHeadInput; Label = 'r5 head input' },
            [pscustomobject]@{ Value = $R5ReceiptInput; Label = 'r5 receipt input' },
            [pscustomobject]@{ Value = $R3ReceiptInput; Label = 'r3 receipt input' })) {
        if ($null -eq $binding.Value.PSObject.Properties['Value'] -or
            $null -eq $binding.Value.PSObject.Properties['Sha256'] -or
            [string]$binding.Value.Sha256 -cnotmatch '^[0-9a-f]{64}$') {
            throw "$($binding.Label) is not an authenticated JSON descriptor."
        }
    }
    $plan = $PlanInput.Value
    $head = $BaseHeadInput.Value
    $r5 = $R5ReceiptInput.Value
    if ([string]$plan.edition -cne 'Enterprise' -or
        [string]$plan.targetChannel -cne 'stable' -or
        [string]$plan.sourceCommit -cnotmatch '^[0-9a-f]{40,64}$' -or
        [string]$plan.authenticodePolicy.signerSha256Thumbprint -cnotmatch
            '^[0-9a-f]{64}$' -or
        [int]$head.revision -ne 5 -or
        [string]$head.phase -cne 'STABLE_SIGNED_CANDIDATE_IMPORTED' -or
        [string]$head.receiptSha256 -cne [string]$R5ReceiptInput.Sha256 -or
        [int]$r5.revision -ne 5 -or
        [string]$r5.phase -cne 'STABLE_SIGNED_CANDIDATE_IMPORTED' -or
        [string]$r5.orchestrationId -cne [string]$plan.orchestrationId -or
        [string]$r5.planSha256 -cne [string]$PlanInput.Sha256 -or
        [int]$R3ReceiptInput.Value.revision -ne 3 -or
        [string]$R3ReceiptInput.Value.phase -cne 'CLIENT_SIGNATURES_IMPORTED' -or
        [string]$R3ReceiptInput.Value.orchestrationId -cne
            [string]$plan.orchestrationId -or
        [string]$R3ReceiptInput.Value.planSha256 -cne
            [string]$PlanInput.Sha256 -or
        [string]$ProductionState.HeadSha256 -cne [string]$BaseHeadInput.Sha256) {
        throw 'Trusted build context does not close the Enterprise stable r5 plan/head/receipt tuple.'
    }
    if ([string]$PayloadAdmission.Decision -cne 'PASS' -or
        [string]$PayloadAdmission.LauncherArchiveSha256 -cnotmatch
            '^[0-9a-f]{64}$' -or
        [string]$PayloadAdmission.RuntimeArchiveSha256 -cnotmatch
            '^[0-9a-f]{64}$' -or
        [string]$PayloadAdmission.BootstrapperSha256 -cnotmatch
            '^[0-9a-f]{64}$') {
        throw 'Trusted build requires a successful in-process production payload admission.'
    }
    if ($PayloadInputs.Count -ne $script:PayloadDefinitions.Count) {
        throw 'Trusted build requires exactly four locked payload inputs.'
    }
}

function Get-EnterpriseTrustedPayloadClosure {
    param(
        [Parameter(Mandatory = $true)][object[]]$PayloadInputs,
        [Parameter(Mandatory = $true)][psobject]$PayloadAdmission,
        [Parameter(Mandatory = $true)][psobject]$ProductionState,
        [Parameter(Mandatory = $true)]$R5ReceiptInput,
        [Parameter(Mandatory = $true)]$R3ReceiptInput,
        [Parameter(Mandatory = $true)][string]$PayloadRoot
    )

    $byRole = @{}
    foreach ($entry in $PayloadInputs) {
        if ($null -eq $entry.PSObject.Properties['Role'] -or
            $null -eq $entry.PSObject.Properties['Descriptor'] -or
            $byRole.ContainsKey([string]$entry.Role)) {
            throw 'Locked payload inputs contain a missing or repeated role.'
        }
        $byRole[[string]$entry.Role] = $entry.Descriptor
    }
    $r5Files = @($R5ReceiptInput.Value.data.files)
    $r3Files = @($R3ReceiptInput.Value.data.files)
    $result = [Collections.Generic.List[object]]::new()
    foreach ($definition in $script:PayloadDefinitions) {
        if (-not $byRole.ContainsKey([string]$definition.Role)) {
            throw "Locked payload input is missing role '$($definition.Role)'."
        }
        $descriptor = $byRole[[string]$definition.Role]
        if ([string]$descriptor.FileName -cne [string]$definition.FileName) {
            throw "Locked payload role '$($definition.Role)' has a noncanonical filename."
        }
        ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
            -Descriptor $descriptor `
            -Label "Enterprise Installer payload role '$($definition.Role)'"
        $expectedSha = switch ([string]$definition.Role) {
            'launcher' { [string]$PayloadAdmission.LauncherArchiveSha256 }
            'runtime' { [string]$PayloadAdmission.RuntimeArchiveSha256 }
            'bootstrapper' { [string]$PayloadAdmission.BootstrapperSha256 }
            default { [string]$PayloadAdmission.ManifestSha256 }
        }
        if ([string]$descriptor.Sha256 -cne $expectedSha) {
            throw "Locked payload role '$($definition.Role)' differs from payload admission."
        }
        if ($definition.SourceKind -ceq 'r5-candidate') {
            $source = @($r5Files | Where-Object {
                    [string]$_.role -ceq [string]$definition.SourceRole
                })
        }
        elseif ($definition.SourceKind -ceq 'r3-signed-client') {
            $source = @($r3Files | Where-Object {
                    [string]$_.role -ceq [string]$definition.SourceRole
                })
        }
        else {
            $source = @()
        }
        if ($definition.SourceKind -cne 'generated-descriptor' -and
            ($source.Count -ne 1 -or
             [string]$source[0].sha256 -cne [string]$descriptor.Sha256 -or
             [int64]$source[0].sizeBytes -ne [int64]$descriptor.SizeBytes)) {
            throw "Locked payload role '$($definition.Role)' differs from authenticated r3/r5 evidence."
        }
        $destination = Join-Path $PayloadRoot $definition.FileName
        Copy-EnterpriseTrustedDescriptor `
            -Descriptor $descriptor `
            -Path $destination `
            -Label "Enterprise Installer payload role '$($definition.Role)'"
        $result.Add([ordered]@{
            role = [string]$definition.Role
            fileName = [string]$definition.FileName
            embeddedLogicalName = [string]$definition.LogicalName
            sourceKind = [string]$definition.SourceKind
            sourceRole = [string]$definition.SourceRole
            sourceSha256 = [string]$descriptor.Sha256
            sizeBytes = [int64]$descriptor.SizeBytes
            sha256 = [string]$descriptor.Sha256
        })
    }

    $manifestDescriptor = $byRole['install-manifest']
    $manifestBytes = ProductionReleaseState\Read-ProductionReleaseInputBytes `
        -Descriptor $manifestDescriptor `
        -Label 'Enterprise install manifest payload'
    try {
        $manifest = ProductionReleaseState\ConvertFrom-StrictProductionJsonBytes `
            -Bytes $manifestBytes `
            -Label 'Enterprise install manifest payload'
        ProductionReleaseState\Assert-ExactProductionJsonMembers `
            -Value $manifest `
            -Expected @(
                'schemaVersion', 'layoutProfile', 'launcherReleaseId',
                'runtimeReleaseId', 'launcherArchive',
                'launcherArchiveSizeBytes', 'launcherArchiveSha256',
                'runtimeArchive', 'runtimeArchiveSizeBytes',
                'runtimeArchiveSha256', 'bootstrapperFile',
                'bootstrapperSizeBytes', 'bootstrapperSha256',
                'publishedAtUtc') `
            -Label 'Enterprise install manifest payload'
        if ([int]$manifest.schemaVersion -ne 1 -or
            [string]$manifest.layoutProfile -cne 'enterprise' -or
            [string]$manifest.launcherArchive -cne 'launcher.zip' -or
            [string]$manifest.runtimeArchive -cne 'runtime.zip' -or
            [string]$manifest.bootstrapperFile -cne
                'Ensou.Dsh.Enterprise.Bootstrapper.exe' -or
            [string]$manifest.launcherArchiveSha256 -cne
                [string]$byRole.launcher.Sha256 -or
            [int64]$manifest.launcherArchiveSizeBytes -ne
                [int64]$byRole.launcher.SizeBytes -or
            [string]$manifest.runtimeArchiveSha256 -cne
                [string]$byRole.runtime.Sha256 -or
            [int64]$manifest.runtimeArchiveSizeBytes -ne
                [int64]$byRole.runtime.SizeBytes -or
            [string]$manifest.bootstrapperSha256 -cne
                [string]$byRole.bootstrapper.Sha256 -or
            [int64]$manifest.bootstrapperSizeBytes -ne
                [int64]$byRole.bootstrapper.SizeBytes -or
            [string]$manifest.publishedAtUtc -cne
                [string]$R5ReceiptInput.Value.data.completedAtUtc) {
            throw 'Enterprise install manifest does not close exact payload and authenticated r5 completion bindings.'
        }
    }
    finally {
        [Array]::Clear($manifestBytes, 0, $manifestBytes.Length)
    }
    return @($result)
}

function Get-EnterpriseTrustedPackageClosure {
    param(
        [Parameter(Mandatory = $true)][string]$PackageDirectory,
        [Parameter(Mandatory = $true)][string]$SnapshotRoot,
        [Parameter(Mandatory = $true)]$PackageLockDescriptor
    )

    $packageRoot = Resolve-EnterpriseTrustedDirectory `
        -Path $PackageDirectory `
        -Label 'Enterprise offline package directory'
    $lockBytes = ProductionReleaseState\Read-ProductionReleaseInputBytes `
        -Descriptor $PackageLockDescriptor `
        -Label 'Enterprise runtime-pack lock'
    try {
        $lock = ProductionReleaseState\ConvertFrom-StrictProductionJsonBytes `
            -Bytes $lockBytes `
            -Label 'Enterprise runtime-pack lock'
    }
    finally {
        [Array]::Clear($lockBytes, 0, $lockBytes.Length)
    }
    ProductionReleaseState\Assert-ExactProductionJsonMembers `
        -Value $lock `
        -Expected @(
            'schemaVersion', 'dotnetSdkVersion', 'runtimeIdentifier',
            'selfContained', 'source', 'packages') `
        -Label 'Enterprise runtime-pack lock'
    if ([int]$lock.schemaVersion -ne 1 -or
        [string]$lock.dotnetSdkVersion -cne '10.0.302' -or
        [string]$lock.runtimeIdentifier -cne 'win-x64' -or
        -not [bool]$lock.selfContained -or
        [string]$lock.source -cne 'https://api.nuget.org/v3/index.json' -or
        @($lock.packages).Count -ne 4) {
        throw 'Enterprise runtime-pack lock metadata is not the exact production contract.'
    }
    $entries = @(Get-ChildItem -LiteralPath $packageRoot -Force)
    if ($entries.Count -ne 4 -or @($entries | Where-Object {
                $_.PSIsContainer -or
                ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                -not $_.Name.EndsWith('.nupkg', [StringComparison]::OrdinalIgnoreCase)
            }).Count -ne 0) {
        throw 'Enterprise offline package directory must contain only its exact four ordinary nupkg files.'
    }

    $records = [Collections.Generic.List[object]]::new()
    $packages = [Collections.Generic.List[object]]::new()
    foreach ($package in @($lock.packages)) {
        ProductionReleaseState\Assert-ExactProductionJsonMembers `
            -Value $package `
            -Expected @('kind', 'id', 'version', 'bytes', 'sha512') `
            -Label 'Enterprise runtime-pack lock package'
        $fileName =
            "$(([string]$package.id).ToLowerInvariant()).$($package.version).nupkg"
        $path = Join-Path $packageRoot $fileName
        $descriptor = ProductionReleaseState\Open-ProductionReleaseInput `
            -Path $path `
            -Label "Enterprise offline package '$fileName'" `
            -MaximumBytes 512MB
        try {
            if ([int64]$descriptor.SizeBytes -ne [int64]$package.bytes -or
                (Get-EnterpriseTrustedSha512Base64 -Descriptor $descriptor) -cne
                    [string]$package.sha512) {
                throw "Enterprise offline package differs from its lock: $fileName"
            }
            $snapshot = Join-Path $SnapshotRoot $fileName
            Copy-EnterpriseTrustedDescriptor `
                -Descriptor $descriptor `
                -Path $snapshot `
                -Label "Enterprise offline package '$fileName'"
            $packageSizeBytes = [int64]$descriptor.SizeBytes
            $packageSha256 = [string]$descriptor.Sha256
        }
        finally {
            $descriptor.Stream.Dispose()
        }
        $records.Add((New-EnterpriseTrustedInputRecord `
                -Kind 'runtime-pack' `
                -IdentityPath "runtime-pack/$fileName" `
                -SnapshotPath $snapshot `
                -OutputRoot ([IO.Path]::GetFullPath((Join-Path $SnapshotRoot '..\..')))))
        $packages.Add([ordered]@{
            kind = [string]$package.kind
            id = [string]$package.id
            version = [string]$package.version
            fileName = $fileName
            sizeBytes = $packageSizeBytes
            sha256 = $packageSha256
            sha512 = [string]$package.sha512
        })
    }
    return [pscustomobject]@{
        Lock = $lock
        InputRecords = @($records)
        Packages = @($packages)
        FeedRoot = $SnapshotRoot
    }
}

function Get-EnterpriseTrustedResourceBindings {
    param(
        [Parameter(Mandatory = $true)][string]$ManagedAssemblyPath,
        [Parameter(Mandatory = $true)][object[]]$PayloadFiles
    )

    [byte[]]$assemblyBytes = [IO.File]::ReadAllBytes($ManagedAssemblyPath)
    $assemblyStream = [IO.MemoryStream]::new($assemblyBytes, $false)
    $context = [Runtime.Loader.AssemblyLoadContext]::new(
        ('enterprise-installer-inspector-' + [Guid]::NewGuid().ToString('N')),
        $true)
    try {
        $assembly = $context.LoadFromStream($assemblyStream)
        $actualNames = @($assembly.GetManifestResourceNames())
        $bindings = [Collections.Generic.List[object]]::new()
        foreach ($payload in $PayloadFiles) {
            $logicalName = [string]$payload.embeddedLogicalName
            if (@($actualNames | Where-Object { $_ -ceq $logicalName }).Count -ne 1) {
                throw "Managed Installer assembly omits exact payload resource '$logicalName'."
            }
            $stream = $assembly.GetManifestResourceStream($logicalName)
            if ($null -eq $stream) {
                throw "Managed Installer resource could not be opened: $logicalName"
            }
            try {
                $sha256 = [Convert]::ToHexString(
                    [Security.Cryptography.SHA256]::HashData($stream)).ToLowerInvariant()
                if ([int64]$stream.Length -ne [int64]$payload.sizeBytes -or
                    $sha256 -cne [string]$payload.sha256) {
                    throw "Managed Installer resource differs from locked payload bytes: $logicalName"
                }
                $bindings.Add([ordered]@{
                    role = [string]$payload.role
                    embeddedLogicalName = $logicalName
                    sizeBytes = [int64]$stream.Length
                    sha256 = $sha256
                    status = 'VERIFIED'
                })
            }
            finally {
                $stream.Dispose()
            }
        }
        return @($bindings)
    }
    finally {
        $context.Unload()
        $assemblyStream.Dispose()
        [Array]::Clear($assemblyBytes, 0, $assemblyBytes.Length)
    }
}

function New-EnterpriseInstallerTrustedBuild {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$PlanInput,
        [Parameter(Mandatory = $true)][psobject]$ProductionState,
        [Parameter(Mandatory = $true)]$BaseHeadInput,
        [Parameter(Mandatory = $true)]$R5ReceiptInput,
        [Parameter(Mandatory = $true)]$R3ReceiptInput,
        [Parameter(Mandatory = $true)][object[]]$PayloadInputs,
        [Parameter(Mandatory = $true)][psobject]$PayloadAdmission,
        [Parameter(Mandatory = $true)][string]$PackageDirectory,
        [Parameter(Mandatory = $true)][string]$DotNetSdkArchivePath,
        [Parameter(Mandatory = $true)][string]$OutputDirectory
    )

    Assert-EnterpriseTrustedBuildHost
    Assert-EnterpriseTrustedContext `
        -PlanInput $PlanInput `
        -ProductionState $ProductionState `
        -BaseHeadInput $BaseHeadInput `
        -R5ReceiptInput $R5ReceiptInput `
        -R3ReceiptInput $R3ReceiptInput `
        -PayloadInputs $PayloadInputs `
        -PayloadAdmission $PayloadAdmission

    $programFiles = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::ProgramFiles)
    if ([string]::IsNullOrWhiteSpace($programFiles)) {
        throw 'Trusted build could not resolve the native Program Files directory.'
    }
    $gitPath = [IO.Path]::GetFullPath(
        (Join-Path $programFiles 'Git\cmd\git.exe'))
    if (-not [IO.File]::Exists($gitPath)) {
        throw 'Trusted build requires Git in its native Program Files location.'
    }
    $repositoryRoot = Resolve-EnterpriseTrustedDirectory `
        -Path $script:RepositoryRoot `
        -Label 'Trusted build source checkout'
    $packageRoot = Resolve-EnterpriseTrustedDirectory `
        -Path $PackageDirectory `
        -Label 'Enterprise offline package directory'
    if (-not [IO.Path]::IsPathFullyQualified($OutputDirectory) -or
        $OutputDirectory.StartsWith('\\', [StringComparison]::Ordinal) -or
        $OutputDirectory.StartsWith('//', [StringComparison]::Ordinal)) {
        throw 'Trusted build output must be an absolute local path.'
    }
    $outputRoot = [IO.Path]::GetFullPath($OutputDirectory)
    if (Test-Path -LiteralPath $outputRoot) {
        throw 'Trusted build output must be one nonexistent create-only directory.'
    }
    $outputParent = Resolve-EnterpriseTrustedDirectory `
        -Path ([IO.Path]::GetDirectoryName($outputRoot)) `
        -Label 'Trusted build output parent'
    foreach ($inputRoot in @($repositoryRoot, $packageRoot)) {
        if ((Test-EnterpriseTrustedSameOrDescendant -Path $outputRoot -Root $inputRoot) -or
            (Test-EnterpriseTrustedSameOrDescendant -Path $inputRoot -Root $outputRoot)) {
            throw 'Trusted build output may not overlap source or package inputs.'
        }
    }

    $heldInputs = [Collections.Generic.List[object]]::new()
    $outputLocks = [Collections.Generic.List[object]]::new()
    $portableSdkClosure = $null
    $privateSdkClosure = $null
    $privateSdkToolchain = $null
    $createdOutput = $false
    try {
        $status = Get-EnterpriseTrustedGitValue `
            -GitPath $gitPath `
            -Arguments @('status', '--porcelain=v1', '--untracked-files=all')
        if (-not [string]::IsNullOrEmpty($status)) {
            throw 'Trusted build source checkout is dirty or contains untracked files.'
        }
        $sourceCommit = Get-EnterpriseTrustedGitValue `
            -GitPath $gitPath `
            -Arguments @('rev-parse', 'HEAD')
        $sourceTree = Get-EnterpriseTrustedGitValue `
            -GitPath $gitPath `
            -Arguments @('rev-parse', 'HEAD^{tree}')
        if ($sourceCommit -cne [string]$PlanInput.Value.sourceCommit -or
            $sourceCommit -cnotmatch '^[0-9a-f]{40,64}$' -or
            $sourceTree -cnotmatch '^[0-9a-f]{40,64}$') {
            throw 'Trusted build checkout HEAD does not equal the exact production plan source commit.'
        }

        [IO.Directory]::CreateDirectory($outputRoot) | Out-Null
        $createdOutput = $true
        $workRoot = Join-Path $outputRoot '.work'
        $sourceSnapshot = Join-Path $workRoot 'source'
        $publishRoot = Join-Path $workRoot 'publish'
        $portableSdkExtractionRoot =
            Join-Path $workRoot 'portable-dotnet-sdk-reviewed'
        $privateSdkRoot = Join-Path $workRoot 'portable-dotnet-sdk-private'
        $packageCache = Join-Path $workRoot 'packages'
        $cliHome = Join-Path $workRoot 'dotnet-home'
        $localAppData = Join-Path $workRoot 'local-app-data'
        $roamingAppData = Join-Path $workRoot 'roaming-app-data'
        $userProfile = Join-Path $workRoot 'user-profile'
        $processTemp = Join-Path $workRoot 'process-temp'
        $payloadRoot = Join-Path $outputRoot 'payload'
        $unsignedRoot = Join-Path $outputRoot 'unsigned'
        $buildInputsRoot = Join-Path $outputRoot 'build-inputs'
        $repoEvidenceRoot = Join-Path $buildInputsRoot 'repo'
        $packageEvidenceRoot = Join-Path $buildInputsRoot 'runtime-pack'
        $generatedRoot = Join-Path $buildInputsRoot 'generated'
        $toolchainRoot = Join-Path $outputRoot 'toolchain'
        foreach ($directory in @(
                $sourceSnapshot, $publishRoot, $packageCache, $cliHome,
                $localAppData, $roamingAppData, $userProfile, $processTemp,
                $payloadRoot, $unsignedRoot, $repoEvidenceRoot,
                $packageEvidenceRoot, $generatedRoot, $toolchainRoot)) {
            [IO.Directory]::CreateDirectory($directory) | Out-Null
        }

        $trackedEntries = Get-EnterpriseTrustedTrackedEntries -GitPath $gitPath
        $trackedByPath = @{}
        $gitBlobBindings = [Collections.Generic.List[object]]::new()
        foreach ($entry in $trackedEntries) {
            $relative = [string]$entry.RelativePath
            $evidencePath =
                Join-Path $repoEvidenceRoot $relative.Replace('/', '\')
            Copy-EnterpriseTrustedGitBlob `
                -GitPath $gitPath `
                -ObjectId ([string]$entry.ObjectId) `
                -Path $evidencePath
            $descriptor = ProductionReleaseState\Open-ProductionReleaseInput `
                -Path $evidencePath `
                -Label "Tracked Git blob '$relative'" `
                -MaximumBytes 1GB
            try {
                Assert-EnterpriseTrustedGitBlobBinding `
                    -Descriptor $descriptor `
                    -ExpectedObjectId ([string]$entry.ObjectId) `
                    -Label "Tracked source '$relative'"
                Copy-EnterpriseTrustedDescriptor `
                    -Descriptor $descriptor `
                    -Path (Join-Path $sourceSnapshot $relative.Replace('/', '\')) `
                    -Label "Tracked source '$relative'"
                $trackedByPath[$relative] = [pscustomobject]@{
                    Path = $evidencePath
                    SizeBytes = [int64]$descriptor.SizeBytes
                    Sha256 = [string]$descriptor.Sha256
                    ObjectId = [string]$entry.ObjectId
                }
                $gitBlobBindings.Add([ordered]@{
                        identityPath = "repo/$relative"
                        mode = [string]$entry.Mode
                        objectId = [string]$entry.ObjectId
                        sizeBytes = [int64]$descriptor.SizeBytes
                        sha256 = [string]$descriptor.Sha256
                    })
            }
            finally {
                $descriptor.Stream.Dispose()
            }
        }
        $gitBlobBindingManifestPath =
            Join-Path $generatedRoot 'git-blob-bindings.v1.json'
        [IO.File]::WriteAllBytes(
            $gitBlobBindingManifestPath,
            (ProductionReleaseState\ConvertTo-ProductionJsonBytes -Value ([ordered]@{
                        schemaVersion = 1
                        bindingType =
                            'ensou-dsh-enterprise-installer-git-blob-bindings'
                        sourceCommit = $sourceCommit
                        sourceTree = $sourceTree
                        files = @($gitBlobBindings)
                    })))
        if (-not $trackedByPath.ContainsKey('global.json') -or
            -not $trackedByPath.ContainsKey('Directory.Build.props') -or
            -not $trackedByPath.ContainsKey($script:RootProjectRelativePath) -or
            -not $trackedByPath.ContainsKey($script:PackageLockRelativePath) -or
            -not $trackedByPath.ContainsKey(
                $script:PortableDotNetSdkLockRelativePath)) {
            throw 'Trusted source snapshot omits a required global/project/package-lock/portable-SDK-lock input.'
        }
        if ($trackedByPath.ContainsKey('Directory.Build.targets') -ne
            [IO.File]::Exists((Join-Path $repositoryRoot 'Directory.Build.targets'))) {
            throw 'Directory.Build.targets presence changed during source admission.'
        }

        $projects = Get-EnterpriseTrustedProjectClosure `
            -SnapshotRoot $sourceSnapshot
        $projectSet = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase)
        $packageLockSet = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase)
        foreach ($project in $projects) {
            [void]$projectSet.Add($project)
            [void]$packageLockSet.Add(
                $project.Substring(0, $project.LastIndexOf('/') + 1) +
                'packages.lock.json')
        }

        $sourceRecords = [Collections.Generic.List[object]]::new()
        foreach ($entry in $trackedEntries) {
            $relative = [string]$entry.RelativePath
            $kind = if ($projectSet.Contains($relative)) {
                'project'
            }
            elseif ($packageLockSet.Contains($relative)) {
                'packages-lock'
            }
            elseif ($relative -ceq 'Directory.Build.props') {
                'directory-build-props'
            }
            elseif ($relative -ceq 'Directory.Build.targets') {
                'directory-build-targets'
            }
            elseif ($relative -ceq 'global.json') {
                'global-json'
            }
            else {
                'source'
            }
            $sourceRecords.Add((New-EnterpriseTrustedInputRecord `
                    -Kind $kind `
                    -IdentityPath "repo/$relative" `
                    -SnapshotPath (Join-Path $repoEvidenceRoot $relative.Replace('/', '\')) `
                    -OutputRoot $outputRoot))
        }
        $sourceRecords.Add((New-EnterpriseTrustedInputRecord `
                -Kind 'generated-input' `
                -IdentityPath 'generated/git-blob-bindings.v1.json' `
                -SnapshotPath $gitBlobBindingManifestPath `
                -OutputRoot $outputRoot))
        if (-not $trackedByPath.ContainsKey('Directory.Build.targets')) {
            $sourceRecords.Add([ordered]@{
                kind = 'directory-build-targets-absent'
                identityPath = 'repo/Directory.Build.targets'
                absenceStatus = 'VERIFIED_ABSENT'
            })
        }

        $payloadFiles = Get-EnterpriseTrustedPayloadClosure `
            -PayloadInputs $PayloadInputs `
            -PayloadAdmission $PayloadAdmission `
            -ProductionState $ProductionState `
            -R5ReceiptInput $R5ReceiptInput `
            -R3ReceiptInput $R3ReceiptInput `
            -PayloadRoot $payloadRoot
        $payloadInventorySha256 =
            InstallerSigningContracts\Get-InstallerSigningObjectSha256 `
                -Value $payloadFiles

        $packageLockDescriptor =
            ProductionReleaseState\Open-ProductionReleaseInput `
                -Path $trackedByPath[$script:PackageLockRelativePath].Path `
                -Label 'Enterprise runtime-pack lock snapshot' `
                -MaximumBytes 64MB
        try {
            $packageClosure = Get-EnterpriseTrustedPackageClosure `
                -PackageDirectory $packageRoot `
                -SnapshotRoot $packageEvidenceRoot `
                -PackageLockDescriptor $packageLockDescriptor
        }
        finally {
            $packageLockDescriptor.Stream.Dispose()
        }
        foreach ($record in $packageClosure.InputRecords) {
            $sourceRecords.Add($record)
        }

        $portableSdkClosure =
            PortableDotNetSdkClosure\Open-PortableDotNetSdkArchiveClosure `
                -ArchivePath $DotNetSdkArchivePath `
                -LockPath $trackedByPath[
                    $script:PortableDotNetSdkLockRelativePath].Path `
                -ExtractionDirectory $portableSdkExtractionRoot `
                -ExpectedSdkVersion '10.0.302'
        $privateSdkClosure =
            PortableDotNetSdkClosure\New-PortableDotNetSdkPrivateCopy `
                -SourceClosure $portableSdkClosure `
                -DestinationDirectory $privateSdkRoot
        $privateSdkToolchain =
            PortableDotNetSdkClosure\Get-PortableDotNetSdkPrivateToolchain `
                -Closure $privateSdkClosure
        if ([string]$privateSdkToolchain.SdkVersion -cne '10.0.302' -or
            [string]$privateSdkToolchain.LockSha256 -cne
                [string]$trackedByPath[
                    $script:PortableDotNetSdkLockRelativePath].Sha256 -or
            [string]$privateSdkToolchain.ArchiveBindingStatus -cne
                'ZIP_SHA512_AND_FILE_INVENTORY_VERIFIED' -or
            [int]$privateSdkToolchain.FileCount -le 0 -or
            [int64]$privateSdkToolchain.TotalSizeBytes -le 0) {
            throw 'Trusted build portable .NET SDK private toolchain differs from its reviewed Git lock and verified ZIP closure.'
        }
        $dotnetPath = [IO.Path]::GetFullPath(
            [string]$privateSdkToolchain.DotnetPath)
        $privateDotNetRoot = [IO.Path]::GetFullPath(
            [string]$privateSdkToolchain.RootPath)

        $controlledEnvironment = @{
            DOTNET_CLI_HOME = $cliHome
            DOTNET_CLI_TELEMETRY_OPTOUT = '1'
            DOTNET_CLI_USE_MSBUILD_SERVER = '0'
            DOTNET_ROOT = $privateDotNetRoot
            DOTNET_ROOT_X64 = $privateDotNetRoot
            DOTNET_MULTILEVEL_LOOKUP = '0'
            DOTNET_NOLOGO = '1'
            DOTNET_SKIP_FIRST_TIME_EXPERIENCE = '1'
            NUGET_PACKAGES = $packageCache
            MSBUILDDISABLENODEREUSE = '1'
            LOCALAPPDATA = $localAppData
            APPDATA = $roamingAppData
            USERPROFILE = $userProfile
            HOME = $userProfile
            HTTP_PROXY = 'http://127.0.0.1:9'
            HTTPS_PROXY = 'http://127.0.0.1:9'
            ALL_PROXY = 'http://127.0.0.1:9'
            NO_PROXY = ''
            TEMP = $processTemp
            TMP = $processTemp
        }
        $sdkVersionResult = Invoke-EnterpriseTrustedProcess `
            -FilePath $dotnetPath `
            -Arguments @('--version') `
            -WorkingDirectory $sourceSnapshot `
            -Environment $controlledEnvironment `
            -TimeoutMilliseconds 60000
        $sdkVersion = $sdkVersionResult.Stdout.Trim()
        if ($sdkVersion -cne '10.0.302') {
            throw "Trusted build requires .NET SDK 10.0.302; actual is '$sdkVersion'."
        }
        $sdkInfo = [ordered]@{
            schemaVersion = 1
            sdkVersion = $sdkVersion
            hostFileName = [IO.Path]::GetFileName($dotnetPath)
            hostSizeBytes =
                [int64](Get-Item -LiteralPath $dotnetPath -Force).Length
            hostSha256 = Get-EnterpriseTrustedSha256FromPath -Path $dotnetPath
            hostOrigin = 'verified-private-portable-sdk-byte-closure'
            processArchitecture = [string][Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture
            osArchitecture = [string][Runtime.InteropServices.RuntimeInformation]::OSArchitecture
            frameworkDescription = [Runtime.InteropServices.RuntimeInformation]::FrameworkDescription
        }
        $sdkInfoPath = Join-Path $generatedRoot 'dotnet-sdk-info.v1.json'
        [IO.File]::WriteAllBytes(
            $sdkInfoPath,
            (ProductionReleaseState\ConvertTo-ProductionJsonBytes -Value $sdkInfo))
        $sourceRecords.Add((New-EnterpriseTrustedInputRecord `
                -Kind 'generated-input' `
                -IdentityPath 'generated/dotnet-sdk-info.v1.json' `
                -SnapshotPath $sdkInfoPath `
                -OutputRoot $outputRoot))

        $nugetConfigPath = Join-Path $generatedRoot 'NuGet.Config'
        $escapedFeed = [Security.SecurityElement]::Escape($packageEvidenceRoot)
        $nugetConfig =
            "<?xml version=`"1.0`" encoding=`"utf-8`"?><configuration>" +
            "<packageSources><clear/><add key=`"offline`" value=`"$escapedFeed`" />" +
            '</packageSources><config><add key="globalPackagesFolder" value="' +
            [Security.SecurityElement]::Escape($packageCache) +
            '" /></config></configuration>'
        [IO.File]::WriteAllText(
            $nugetConfigPath,
            $nugetConfig,
            [Text.UTF8Encoding]::new($false, $true))
        $sourceRecords.Add((New-EnterpriseTrustedInputRecord `
                -Kind 'generated-input' `
                -IdentityPath 'generated/NuGet.Config' `
                -SnapshotPath $nugetConfigPath `
                -OutputRoot $outputRoot))

        $directoryBuildPropsPath =
            Join-Path $sourceSnapshot 'Directory.Build.props'
        $directoryBuildTargetsPath = if (
            $trackedByPath.ContainsKey('Directory.Build.targets')) {
            Join-Path $sourceSnapshot 'Directory.Build.targets'
        }
        else {
            ''
        }
        $directoryBuildTargetsEvidence = if (
            $trackedByPath.ContainsKey('Directory.Build.targets')) {
            'repo/Directory.Build.targets'
        }
        else {
            ''
        }
        $msbuildPropertyPinsEvidence = @(
            '-p:DirectoryBuildPropsPath=repo/Directory.Build.props',
            "-p:DirectoryBuildTargetsPath=$directoryBuildTargetsEvidence",
            '-p:CustomBeforeMicrosoftCommonProps=',
            '-p:CustomAfterMicrosoftCommonProps=',
            '-p:CustomBeforeMicrosoftCommonTargets=',
            '-p:CustomAfterMicrosoftCommonTargets=')
        $msbuildPropertyPins = @(
            "-p:DirectoryBuildPropsPath=$directoryBuildPropsPath",
            "-p:DirectoryBuildTargetsPath=$directoryBuildTargetsPath",
            '-p:CustomBeforeMicrosoftCommonProps=',
            '-p:CustomAfterMicrosoftCommonProps=',
            '-p:CustomBeforeMicrosoftCommonTargets=',
            '-p:CustomAfterMicrosoftCommonTargets=')
        $restoreArgumentsEvidence = @(
            'restore',
            "repo/$script:RootProjectRelativePath",
            '--locked-mode', '--no-cache', '--disable-parallel',
            '--configfile', 'generated/NuGet.Config',
            '-p:NuGetAudit=false', '-p:RestoreIgnoreFailedSources=false',
            '-m:1', '-nodeReuse:false', '-p:UseSharedCompilation=false') +
            $msbuildPropertyPinsEvidence
        $restoreArguments = @(
            'restore',
            (Join-Path $sourceSnapshot $script:RootProjectRelativePath.Replace('/', '\')),
            '--locked-mode', '--no-cache', '--disable-parallel',
            '--configfile', $nugetConfigPath,
            '-p:NuGetAudit=false', '-p:RestoreIgnoreFailedSources=false',
            '-m:1', '-nodeReuse:false', '-p:UseSharedCompilation=false') +
            $msbuildPropertyPins
        $restoreArgumentsPath = Join-Path $generatedRoot 'restore-arguments.v1.json'
        [IO.File]::WriteAllBytes(
            $restoreArgumentsPath,
            (ProductionReleaseState\ConvertTo-ProductionJsonBytes `
                -Value $restoreArgumentsEvidence))
        $sourceRecords.Add((New-EnterpriseTrustedInputRecord `
                -Kind 'generated-input' `
                -IdentityPath 'generated/restore-arguments.v1.json' `
                -SnapshotPath $restoreArgumentsPath `
                -OutputRoot $outputRoot))

        [void](Invoke-EnterpriseTrustedProcess `
            -FilePath $dotnetPath `
            -Arguments $restoreArguments `
            -WorkingDirectory $sourceSnapshot `
            -Environment $controlledEnvironment)

        foreach ($project in $projects) {
            $projectName = [IO.Path]::GetFileNameWithoutExtension($project)
            $assetsPath = Join-Path `
                (Join-Path $sourceSnapshot (
                    $project.Substring(0, $project.LastIndexOf('/')).Replace('/', '\'))) `
                'obj\project.assets.json'
            if (-not [IO.File]::Exists($assetsPath)) {
                throw "Offline restore omitted project.assets.json for $project"
            }
            $identity = if ($project -ceq $script:RootProjectRelativePath) {
                'generated/project.assets.json'
            }
            else {
                "generated/restore/$projectName.project.assets.json"
            }
            $snapshot = Join-Path $outputRoot ('build-inputs\' + $identity.Replace('/', '\'))
            [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($snapshot)) |
                Out-Null
            [IO.File]::Copy($assetsPath, $snapshot, $false)
            $sourceRecords.Add((New-EnterpriseTrustedInputRecord `
                    -Kind 'restore-graph' `
                    -IdentityPath $identity `
                    -SnapshotPath $snapshot `
                    -OutputRoot $outputRoot))
        }

        $publishArgumentsEvidence = @(
            'publish', "repo/$script:RootProjectRelativePath",
            '--configuration', 'Release', '--runtime', 'win-x64',
            '--self-contained', 'true', '--no-restore',
            '--output', 'private-create-only-publish',
            '-p:PublishSingleFile=true',
            '-p:IncludeNativeLibrariesForSelfExtract=true',
            '-p:PublishTrimmed=false', '-p:Deterministic=true',
            '-p:ContinuousIntegrationBuild=true',
            '-m:1', '-nodeReuse:false', '-p:UseSharedCompilation=false',
            '-p:DebugType=None', '-p:DebugSymbols=false',
            '-p:EnterpriseDevelopmentE2E=false',
            '-p:EnterprisePayloadDirectory=locked-payload',
            ('-p:EnterpriseAuthenticodeSignerSha256Thumbprint=' +
                [string]$PlanInput.Value.authenticodePolicy.signerSha256Thumbprint)) +
            $msbuildPropertyPinsEvidence
        $publishArgumentsPath = Join-Path $generatedRoot 'publish-arguments.v1.json'
        [IO.File]::WriteAllBytes(
            $publishArgumentsPath,
            (ProductionReleaseState\ConvertTo-ProductionJsonBytes `
                -Value $publishArgumentsEvidence))
        $sourceRecords.Add((New-EnterpriseTrustedInputRecord `
                -Kind 'generated-input' `
                -IdentityPath 'generated/publish-arguments.v1.json' `
                -SnapshotPath $publishArgumentsPath `
                -OutputRoot $outputRoot))

        $sourceInputFiles = Sort-EnterpriseTrustedInputRecords `
            -Records @($sourceRecords)
        $sourceInventorySha256 =
            InstallerSigningContracts\Get-InstallerSigningObjectSha256 `
                -Value $sourceInputFiles
        $buildStartedAtUtc = Get-EnterpriseTrustedUtcNow
        $publishArguments = @(
            'publish',
            (Join-Path $sourceSnapshot $script:RootProjectRelativePath.Replace('/', '\')),
            '--configuration', 'Release', '--runtime', 'win-x64',
            '--self-contained', 'true', '--no-restore',
            '--output', $publishRoot,
            '-p:PublishSingleFile=true',
            '-p:IncludeNativeLibrariesForSelfExtract=true',
            '-p:PublishTrimmed=false', '-p:Deterministic=true',
            '-p:ContinuousIntegrationBuild=true',
            '-m:1', '-nodeReuse:false', '-p:UseSharedCompilation=false',
            '-p:DebugType=None', '-p:DebugSymbols=false',
            '-p:EnterpriseDevelopmentE2E=false',
            "-p:EnterprisePayloadDirectory=$payloadRoot",
            ('-p:EnterpriseAuthenticodeSignerSha256Thumbprint=' +
                [string]$PlanInput.Value.authenticodePolicy.signerSha256Thumbprint)) +
            $msbuildPropertyPins
        [void](Invoke-EnterpriseTrustedProcess `
            -FilePath $dotnetPath `
            -Arguments $publishArguments `
            -WorkingDirectory $sourceSnapshot `
            -Environment $controlledEnvironment)
        $buildCompletedAtUtc = Get-EnterpriseTrustedUtcNow

        $publishedEntries = @(Get-ChildItem -LiteralPath $publishRoot -Force)
        if ($publishedEntries.Count -ne 1 -or
            $publishedEntries[0].PSIsContainer -or
            [string]$publishedEntries[0].Name -cne $script:InstallerFileName) {
            throw 'Enterprise Installer publish output is not exactly one single-file executable.'
        }
        $unsignedPath = Join-Path $unsignedRoot $script:InstallerFileName
        [IO.File]::Copy($publishedEntries[0].FullName, $unsignedPath, $false)
        $unsignedInput = ProductionReleaseState\Open-ProductionReleaseInput `
            -Path $unsignedPath `
            -Label 'Trusted-build unsigned Enterprise Installer' `
            -MaximumBytes 1GB
        $outputLocks.Add($unsignedInput)
        $signature = Microsoft.PowerShell.Security\Get-AuthenticodeSignature `
            -LiteralPath $unsignedPath
        if ([string]$signature.Status -cne 'NotSigned') {
            throw 'Trusted-build Installer must be an unsigned PE reserved for isolated signing.'
        }
        $unsignedBytes = ProductionReleaseState\Read-ProductionReleaseInputBytes `
            -Descriptor $unsignedInput `
            -Label 'Trusted-build unsigned Enterprise Installer'
        try {
            $peContentSha256 = ProductionReleaseState\Get-PeContentSha256 `
                -Bytes $unsignedBytes
        }
        finally {
            [Array]::Clear($unsignedBytes, 0, $unsignedBytes.Length)
        }

        $managedAssemblyPath = Join-Path `
            $sourceSnapshot `
            'src\Ensou.Dsh.Enterprise.Installer\bin\Release\net10.0-windows\win-x64\Ensou.Dsh.Enterprise.Installer.dll'
        if (-not [IO.File]::Exists($managedAssemblyPath)) {
            throw 'Trusted build cannot inspect the exact managed assembly supplied to the single-file bundler.'
        }
        $resourceBindings = Get-EnterpriseTrustedResourceBindings `
            -ManagedAssemblyPath $managedAssemblyPath `
            -PayloadFiles $payloadFiles
        $managedAssemblyDescriptor = [ordered]@{
            fileName = 'Ensou.Dsh.Enterprise.Installer.dll'
            sizeBytes = [int64](Get-Item -LiteralPath $managedAssemblyPath -Force).Length
            sha256 = Get-EnterpriseTrustedSha256FromPath -Path $managedAssemblyPath
        }

        foreach ($descriptor in $heldInputs) {
            ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
                -Descriptor $descriptor `
                -Label "Trusted build held input '$($descriptor.FileName)'"
        }
        foreach ($entry in $PayloadInputs) {
            ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
                -Descriptor $entry.Descriptor `
                -Label "Trusted build payload '$($entry.Role)'"
        }
        foreach ($record in $sourceInputFiles) {
            if ([string]$record.kind -ceq 'directory-build-targets-absent') {
                continue
            }
            $snapshotPath = Join-Path $outputRoot (
                ([string]$record.snapshotRelativePath).Replace('/', '\'))
            if ((Get-Item -LiteralPath $snapshotPath -Force).Length -ne
                    [int64]$record.sizeBytes -or
                (Get-EnterpriseTrustedSha256FromPath -Path $snapshotPath) -cne
                    [string]$record.sha256) {
                throw "Trusted build input snapshot changed during build: $($record.identityPath)"
            }
        }
        $postStatus = Get-EnterpriseTrustedGitValue `
            -GitPath $gitPath `
            -Arguments @('status', '--porcelain=v1', '--untracked-files=all')
        $postCommit = Get-EnterpriseTrustedGitValue `
            -GitPath $gitPath `
            -Arguments @('rev-parse', 'HEAD')
        $postTree = Get-EnterpriseTrustedGitValue `
            -GitPath $gitPath `
            -Arguments @('rev-parse', 'HEAD^{tree}')
        if (-not [string]::IsNullOrEmpty($postStatus) -or
            $postCommit -cne $sourceCommit -or $postTree -cne $sourceTree) {
            throw 'Trusted build checkout changed during source-to-binary production.'
        }
        [void](PortableDotNetSdkClosure\Assert-PortableDotNetSdkClosureUnchanged `
                -Closure $privateSdkClosure)
        [void](PortableDotNetSdkClosure\Assert-PortableDotNetSdkClosureUnchanged `
                -Closure $portableSdkClosure)
        $verifiedPrivateSdkToolchain =
            PortableDotNetSdkClosure\Get-PortableDotNetSdkPrivateToolchain `
                -Closure $privateSdkClosure
        foreach ($property in @(
                'RootPath', 'DotnetPath', 'SdkVersion', 'LockSha256',
                'ArchiveSourceUrl', 'ArchiveSha512', 'InventorySha256',
                'FileCount', 'TotalSizeBytes', 'ArchiveBindingStatus')) {
            if ([string]$verifiedPrivateSdkToolchain.$property -cne
                [string]$privateSdkToolchain.$property) {
                throw "Trusted build portable .NET SDK closure changed during process execution: $property"
            }
        }
        $privateSdkToolchain = $verifiedPrivateSdkToolchain

        $runtimePackInputs = @($sourceInputFiles | Where-Object {
                [string]$_.kind -ceq 'runtime-pack'
            })
        $dependencyInputs = @($sourceInputFiles | Where-Object {
                [string]$_.kind -in @(
                    'project', 'packages-lock', 'restore-graph', 'runtime-pack')
            })
        $requestToolchainLock = [ordered]@{
            sdkVersion = '10.0.302'
            globalJsonRelativePath = 'toolchain/global.json'
            globalJsonSha256 = [string]$trackedByPath['global.json'].Sha256
            projectFileName = 'Ensou.Dsh.Enterprise.Installer.csproj'
            projectRelativePath =
                'toolchain/Ensou.Dsh.Enterprise.Installer.csproj'
            projectSha256 =
                [string]$trackedByPath[$script:RootProjectRelativePath].Sha256
            restoreGraphRelativePath = 'toolchain/project.assets.json'
            restoreGraphSha256 = [string](@($sourceInputFiles | Where-Object {
                        [string]$_.identityPath -ceq 'generated/project.assets.json'
                    })[0].sha256)
            packagesLockRelativePath = 'toolchain/packages.lock.json'
            packagesLockSha256 = [string]$trackedByPath[
                'src/Ensou.Dsh.Enterprise.Installer/packages.lock.json'].Sha256
            packagesLockStatus = 'VERIFIED'
            dependencyClosureSha256 =
                InstallerSigningContracts\Get-InstallerSigningObjectSha256 `
                    -Value $dependencyInputs
            runtimePackSetSha256 =
                InstallerSigningContracts\Get-InstallerSigningObjectSha256 `
                    -Value $runtimePackInputs
            sdkInfoRelativePath = 'toolchain/dotnet-sdk-info.v1.json'
            sdkInfoSha256 = Get-EnterpriseTrustedSha256FromPath -Path $sdkInfoPath
            publishArgumentsSha256 =
                Get-EnterpriseTrustedSha256FromPath -Path $publishArgumentsPath
            configuration = 'Release'
            runtimeIdentifier = 'win-x64'
            selfContained = $true
            publishSingleFile = $true
            deterministic = $true
            continuousIntegrationBuild = $true
            restoreMode = 'packages-lock-locked-offline'
            networkAccess = 'disabled'
        }
        $toolchainLock = [ordered]@{
            requestContract = $requestToolchainLock
            requestContractSha256 =
                InstallerSigningContracts\Get-InstallerSigningObjectSha256 `
                    -Value $requestToolchainLock
            restoreArgumentsSha256 =
                Get-EnterpriseTrustedSha256FromPath -Path $restoreArgumentsPath
            networkEnforcement =
                'local-source-clear-plus-loopback-proxy-sink'
            subprocessEnvironmentPolicy =
                $script:SubprocessEnvironmentPolicy
            sdkFileClosureStatus = 'VERIFIED'
            archiveFileName = $script:PortableDotNetSdkArchiveFileName
            archiveSourceUrl =
                [string]$privateSdkToolchain.ArchiveSourceUrl
            archiveSha512 = [string]$privateSdkToolchain.ArchiveSha512
            archiveBindingStatus =
                [string]$privateSdkToolchain.ArchiveBindingStatus
            trackedLockRelativePath =
                "repo/$script:PortableDotNetSdkLockRelativePath"
            trackedLockSha256 = [string]$privateSdkToolchain.LockSha256
            inventorySha256 = [string]$privateSdkToolchain.InventorySha256
            fileCount = [int]$privateSdkToolchain.FileCount
            totalSizeBytes = [int64]$privateSdkToolchain.TotalSizeBytes
            privateCopyPolicy =
                'create-only-output-work-copy-held-open-through-version-restore-publish-v1'
            dotnetRootPolicy =
                'private-root-only-multilevel-lookup-disabled-v1'
        }
        [int64]$sourceInputTotalSizeBytes = 0
        foreach ($sourceInputFile in $sourceInputFiles) {
            if ($sourceInputFile -is [Collections.IDictionary] -and
                $sourceInputFile.Contains('sizeBytes')) {
                $sourceInputTotalSizeBytes += [int64]$sourceInputFile['sizeBytes']
            }
            elseif ($null -ne $sourceInputFile.PSObject.Properties['sizeBytes']) {
                $sourceInputTotalSizeBytes += [int64]$sourceInputFile.sizeBytes
            }
        }
        $candidateFiles = @($R5ReceiptInput.Value.data.files)
        $candidateInventorySha256 =
            InstallerSigningContracts\Get-InstallerSigningObjectSha256 `
                -Value $candidateFiles
        $r3SignedClients = [Collections.Generic.List[object]]::new()
        foreach ($file in @($R3ReceiptInput.Value.data.files)) {
            $r3SignedClients.Add([ordered]@{
                role = [string]$file.role
                fileName = [string]$file.fileName
                relativePath = 'imports/client-signing.v1/signed/' +
                    [string]$file.fileName
                sizeBytes = [int64]$file.sizeBytes
                sha256 = [string]$file.sha256
                peContentSha256 = [string]$file.peContentSha256
            })
        }
        $r3SignedClientSetSha256 =
            InstallerSigningContracts\Get-InstallerSigningObjectSha256 `
                -Value @($r3SignedClients)
        $r3TrustProbes = @(
            $R3ReceiptInput.Value.data.releaseManifestTrustProbes)
        $r3TrustProbeSetSha256 =
            InstallerSigningContracts\Get-InstallerSigningObjectSha256 `
                -Value $r3TrustProbes
        $releaseManifestTrustSha256 =
            InstallerSigningContracts\Get-InstallerSigningObjectSha256 `
                -Value $PlanInput.Value.releaseManifestTrust
        $r5Evidence = [ordered]@{
            headRelativePath = 'head.json'
            headSha256 = [string]$BaseHeadInput.Sha256
            receiptRelativePath =
                'receipts/0005-stable-signed-candidate-imported.json'
            receiptSha256 = [string]$R5ReceiptInput.Sha256
            manifestPublishingRequestSha256 =
                [string]$ProductionState.Receipts[3].data.requestSha256
            manifestPublishingResponseSha256 =
                [string]$R5ReceiptInput.Value.data.responseSha256
            manifestRelativePath =
                'imports/stable-signed-candidate.v1/candidate/release-set.v2.json'
            manifestSha256 =
                [string]$R5ReceiptInput.Value.data.manifestSha256
            releaseManifestTrustSha256 =
                [string]$R5ReceiptInput.Value.data.releaseManifestTrustSha256
            releaseCompatibilitySha256 =
                [string]$R5ReceiptInput.Value.data.releaseCompatibilitySha256
            productionAdmission = 'NO_GO'
        }
        if ([string]$r5Evidence.releaseManifestTrustSha256 -cne
            $releaseManifestTrustSha256) {
            throw 'Trusted build r5 receipt differs from the exact plan release-manifest trust.'
        }
        $requestSourceBuildInputs = [ordered]@{
            contract = 'tracked-clean-ordinary-single-link-exact-msbuild-graph-v1'
            sourceTree = $sourceTree
            rootProjectIdentityPath = "repo/$script:RootProjectRelativePath"
            inventorySha256 = $sourceInventorySha256
            preBuildInventorySha256 = $sourceInventorySha256
            postBuildInventorySha256 = $sourceInventorySha256
            totalSizeBytes = $sourceInputTotalSizeBytes
            trackedClean = $true
            dirtyPathCount = 0
            untrackedPathCount = 0
            linkedInputCount = 0
            raceCheckStatus = 'VERIFIED_UNCHANGED'
            files = $sourceInputFiles
        }
        $resourceSetSha256 =
            InstallerSigningContracts\Get-InstallerSigningObjectSha256 `
                -Value $resourceBindings
        $resourceBinding = [ordered]@{
            verificationType =
                'managed-assembly-resource-to-single-file-build-input-v1'
            verificationMethod =
                'collectible-load-context-manifest-resource-inspection-no-entrypoint'
            status = 'VERIFIED'
            managedAssembly = $managedAssemblyDescriptor
            resourceSetSha256 = $resourceSetSha256
            resources = $resourceBindings
            unsignedInstallerSha256 = [string]$unsignedInput.Sha256
        }
        $resourceBindingSha256 =
            InstallerSigningContracts\Get-InstallerSigningObjectSha256 `
                -Value $resourceBinding
        $requestToolchainLockSha256 =
            InstallerSigningContracts\Get-InstallerSigningObjectSha256 `
                -Value $requestToolchainLock
        $buildId = [Guid]::NewGuid().ToString()
        $targetIdentityInput = [pscustomobject]@{
            orchestrationId = [string]$PlanInput.Value.orchestrationId
            edition = 'Enterprise'
            releaseSetId = [string]$PlanInput.Value.releaseSetId
            channel = 'stable'
            planSha256 = [string]$PlanInput.Sha256
            sourceCommit = $sourceCommit
            sourceTree = $sourceTree
            sourceBuildInputSetSha256 = $sourceInventorySha256
            r5Evidence = [pscustomobject]$r5Evidence
            candidate = [pscustomobject]@{
                inventorySha256 = $candidateInventorySha256
            }
            r3Evidence = [pscustomobject]@{
                signedClientSetSha256 = $r3SignedClientSetSha256
                releaseManifestTrustProbeSetSha256 = $r3TrustProbeSetSha256
            }
            installerPayload = [pscustomobject]@{
                inventorySha256 = $payloadInventorySha256
            }
            toolchainLockSha256 = $requestToolchainLockSha256
        }
        $targetBuildIdentitySha256 =
            InstallerSigningContracts\Get-InstallerTargetBuildIdentitySha256 `
                -Request $targetIdentityInput
        $reservation = [ordered]@{
            schemaVersion = 1
            reservationType =
                'ensou-dsh-enterprise-installer-trusted-build-reservation'
            buildId = $buildId
            targetBuildIdentitySha256 = $targetBuildIdentitySha256
            sourceBuildInputSetSha256 = $sourceInventorySha256
            unsignedInstallerSha256 = [string]$unsignedInput.Sha256
        }
        $reservationSha256 =
            InstallerSigningContracts\Get-InstallerSigningObjectSha256 `
                -Value $reservation
        $buildExecution = [ordered]@{
            buildId = $buildId
            targetBuildIdentitySha256 = $targetBuildIdentitySha256
            reservationSha256 = $reservationSha256
            buildOrdinal = 1
            buildCountForTarget = 1
            outputCreationMode = 'create-new'
            rebuildPolicy =
                'rebuild-forbidden-exact-reserved-unsigned-bytes-replay-only'
            startedAtUtc = $buildStartedAtUtc
            completedAtUtc = $buildCompletedAtUtc
            exitCode = 0
        }
        $evidence = [ordered]@{
            schemaVersion = 1
            evidenceType = 'ensou-dsh-enterprise-installer-trusted-build'
            orchestrationId = [string]$PlanInput.Value.orchestrationId
            releaseSetId = [string]$PlanInput.Value.releaseSetId
            edition = 'Enterprise'
            channel = 'stable'
            planSha256 = [string]$PlanInput.Sha256
            baseHeadSha256 = [string]$BaseHeadInput.Sha256
            r5ReceiptSha256 = [string]$R5ReceiptInput.Sha256
            sourceCommit = $sourceCommit
            sourceTree = $sourceTree
            sourceBuildInputs = [ordered]@{
                contract = 'tracked-clean-ordinary-single-link-exact-msbuild-graph-v1'
                sourceTree = $sourceTree
                rootProjectIdentityPath =
                    "repo/$script:RootProjectRelativePath"
                trackedClean = $true
                dirtyPathCount = 0
                untrackedPathCount = 0
                linkedInputCount = 0
                raceCheckStatus = 'VERIFIED_UNCHANGED'
                inventorySha256 = $sourceInventorySha256
                preBuildInventorySha256 = $sourceInventorySha256
                postBuildInventorySha256 = $sourceInventorySha256
                totalSizeBytes = $sourceInputTotalSizeBytes
                transitiveProjects = @($projects)
                files = $sourceInputFiles
            }
            packageClosure = [ordered]@{
                lockRelativePath = "repo/$script:PackageLockRelativePath"
                lockSha256 = [string]$trackedByPath[
                    $script:PackageLockRelativePath].Sha256
                packageCount = @($packageClosure.Packages).Count
                packages = @($packageClosure.Packages)
            }
            installerPayload = [ordered]@{
                inventorySha256 = $payloadInventorySha256
                files = $payloadFiles
            }
            toolchainLock = $toolchainLock
            toolchainLockSha256 =
                InstallerSigningContracts\Get-InstallerSigningObjectSha256 `
                    -Value $toolchainLock
            buildExecution = $buildExecution
            unsignedInstaller = [ordered]@{
                role = 'installer'
                fileName = $script:InstallerFileName
                relativePath = "unsigned/$script:InstallerFileName"
                sizeBytes = [int64]$unsignedInput.SizeBytes
                sha256 = [string]$unsignedInput.Sha256
                peContentSha256 = $peContentSha256
                authenticodeStatus = 'NotSigned'
            }
            resourceBinding = $resourceBinding
            signingRequestEligibility = [ordered]@{
                status = 'ELIGIBLE_FOR_PILOT_SIGNING'
                requestSchemaVersion = 2
                productionAdmission = 'NO_GO'
                blocker = 'INSTALLER_SIGNING_RESPONSE_REQUIRED'
                reason =
                    'The four embedded payload resources and the exact private portable SDK byte closure are verified. The unsigned Installer is eligible for isolated Pilot signing, but production remains NO_GO until the authenticated Authenticode and RFC3161 signing response is imported and later real-device Pilot evidence is bound.'
            }
        }
        $trustedBuildRoot = Join-Path $outputRoot 'trusted-build'
        [IO.Directory]::CreateDirectory($trustedBuildRoot) | Out-Null
        $evidencePath = Join-Path $trustedBuildRoot 'trusted-build-evidence.v1.json'
        [IO.File]::WriteAllBytes(
            $evidencePath,
            (ProductionReleaseState\ConvertTo-ProductionJsonBytes -Value $evidence))
        $schemaPath = Join-Path `
            ([IO.Path]::GetDirectoryName($PSScriptRoot)) `
            'schemas\enterprise-installer-trusted-build-evidence-v1.schema.json'
        $evidenceInput = ProductionReleaseState\Read-StrictProductionJsonFile `
            -Path $evidencePath `
            -SchemaPath $schemaPath `
            -Label 'Enterprise Installer trusted-build evidence'
        [void](ProductionReleaseState\Assert-CanonicalProductionJsonInput `
            -JsonInput $evidenceInput `
            -Label 'Enterprise Installer trusted-build evidence')

        [byte[]]$nonceBytes = [byte[]]::new(32)
        [Security.Cryptography.RandomNumberGenerator]::Fill($nonceBytes)
        try {
            $requestNonce = ConvertTo-EnterpriseTrustedBase64Url `
                -Bytes $nonceBytes
        }
        finally {
            [Array]::Clear($nonceBytes, 0, $nonceBytes.Length)
        }
        $createdAtUtc = Get-EnterpriseTrustedUtcNow
        $created = ProductionReleaseState\ConvertFrom-ProductionUtc `
            -Value $createdAtUtc `
            -Label 'Trusted-build signing request creation time'
        $expiresAtUtc = ProductionReleaseState\ConvertTo-ProductionUtc `
            -Value $created.AddMinutes(
                [int]$PlanInput.Value.authenticodePolicy.maximumResponseAgeMinutes)
        $request = [ordered]@{
            schemaVersion = 2
            requestType = 'ensou-dsh-launcher-installer-signing-request'
            orchestrationId = [string]$PlanInput.Value.orchestrationId
            edition = 'Enterprise'
            releaseSetId = [string]$PlanInput.Value.releaseSetId
            channel = 'stable'
            planSha256 = [string]$PlanInput.Sha256
            sourceCommit = $sourceCommit
            sourceTree = $sourceTree
            sourceBuildInputSetSha256 = $sourceInventorySha256
            sourceBuildInputs = $requestSourceBuildInputs
            baseHeadSha256 = [string]$BaseHeadInput.Sha256
            baseRevision = 5
            basePhase = 'STABLE_SIGNED_CANDIDATE_IMPORTED'
            requestedRevision = 6
            requestNonce = $requestNonce
            createdAtUtc = $createdAtUtc
            expiresAtUtc = $expiresAtUtc
            r5Evidence = $r5Evidence
            candidate = [ordered]@{
                inventorySha256 = $candidateInventorySha256
                files = $candidateFiles
            }
            r3Evidence = [ordered]@{
                receiptRelativePath =
                    'receipts/0003-client-signatures-imported.json'
                receiptSha256 = [string]$R3ReceiptInput.Sha256
                signedClientSetSha256 = $r3SignedClientSetSha256
                signedClients = @($r3SignedClients)
                releaseManifestTrustSha256 = $releaseManifestTrustSha256
                releaseManifestTrustProbeSetSha256 = $r3TrustProbeSetSha256
                releaseManifestTrustProbes = $r3TrustProbes
            }
            installerPayload = [ordered]@{
                inventorySha256 = $payloadInventorySha256
                files = $payloadFiles
            }
            toolchainLock = $requestToolchainLock
            toolchainLockSha256 = $requestToolchainLockSha256
            buildExecution = $buildExecution
            unsignedInstaller = [ordered]@{
                role = 'installer'
                fileName = $script:InstallerFileName
                relativePath = "unsigned/$script:InstallerFileName"
                sizeBytes = [int64]$unsignedInput.SizeBytes
                sha256 = [string]$unsignedInput.Sha256
                peContentSha256 = $peContentSha256
            }
            resourceBinding = $resourceBinding
            trustedBuildEvidence = [ordered]@{
                role = 'trusted-build-evidence'
                fileName = 'trusted-build-evidence.v1.json'
                relativePath =
                    'trusted-build/trusted-build-evidence.v1.json'
                schemaVersion = 1
                evidenceType =
                    'ensou-dsh-enterprise-installer-trusted-build'
                sizeBytes = [int64]$evidenceInput.Bytes.LongLength
                sha256 = [string]$evidenceInput.Sha256
                resourceBindingSha256 = $resourceBindingSha256
                sdkFileClosureStatus = 'VERIFIED'
                productionAdmission = 'NO_GO'
            }
            responseAuthentication = [ordered]@{
                algorithm = 'ES256'
                keyId = [string]$PlanInput.Value.externalResponseTrusts.installerSigning.keyId
                purpose = 'installer-signing-response'
                payloadType =
                    'ensou-dsh-launcher-installer-signing-response-authentication-v1'
                trustSha256 =
                    InstallerSigningContracts\Get-InstallerSigningObjectSha256 `
                        -Value $PlanInput.Value.externalResponseTrusts.installerSigning
                maximumResponseAgeMinutes =
                    [int]$PlanInput.Value.authenticodePolicy.maximumResponseAgeMinutes
            }
        }
        $requestPath = Join-Path $outputRoot 'installer-signing-request.v2.json'
        [IO.File]::WriteAllBytes(
            $requestPath,
            (ProductionReleaseState\ConvertTo-ProductionJsonBytes -Value $request))
        $requestSchemaPath = Join-Path `
            ([IO.Path]::GetDirectoryName($PSScriptRoot)) `
            'schemas\launcher-enterprise-installer-signing-request-v2.schema.json'
        $requestDocument = ProductionReleaseState\Read-StrictProductionJsonFile `
            -Path $requestPath `
            -SchemaPath $requestSchemaPath `
            -Label 'Enterprise Installer signing request v2'
        [void](ProductionReleaseState\Assert-CanonicalProductionJsonInput `
            -JsonInput $requestDocument `
            -Label 'Enterprise Installer signing request v2')
        [void](InstallerSigningContracts\Assert-InstallerSigningRequestContract `
            -Request $requestDocument.Value `
            -InstallerSigningTrust $PlanInput.Value.externalResponseTrusts.installerSigning `
            -ReleaseManifestTrust $PlanInput.Value.releaseManifestTrust)

        foreach ($definition in $script:PayloadDefinitions) {
            $locked = ProductionReleaseState\Open-ProductionReleaseInput `
                -Path (Join-Path $payloadRoot $definition.FileName) `
                -Label "Trusted-build output payload '$($definition.Role)'" `
                -MaximumBytes 8GB
            Add-Member `
                -InputObject $locked `
                -NotePropertyName Role `
                -NotePropertyValue ([string]$definition.Role)
            $outputLocks.Add($locked)
        }
        $evidenceLock = ProductionReleaseState\Open-ProductionReleaseInput `
            -Path $evidencePath `
            -Label 'Trusted-build evidence output' `
            -MaximumBytes 64MB
        $outputLocks.Add($evidenceLock)
        $requestLock = ProductionReleaseState\Open-ProductionReleaseInput `
            -Path $requestPath `
            -Label 'Trusted-build signing request v2 output' `
            -MaximumBytes 64MB
        Add-Member -InputObject $requestLock -NotePropertyName Value `
            -NotePropertyValue $requestDocument.Value
        $outputLocks.Add($requestLock)

        PortableDotNetSdkClosure\Close-PortableDotNetSdkClosure `
            -Closure $privateSdkClosure
        $privateSdkClosure = $null
        PortableDotNetSdkClosure\Close-PortableDotNetSdkClosure `
            -Closure $portableSdkClosure
        $portableSdkClosure = $null
        Remove-Item -LiteralPath $workRoot -Recurse -Force
        $createdOutput = $false
        $result = [pscustomobject]@{
            Status = 'SIGNING_REQUEST_READY_NO_GO'
            Blocker = 'INSTALLER_SIGNING_RESPONSE_REQUIRED'
            ProductionAdmission = 'NO_GO'
            OutputDirectory = $outputRoot
            Request = $requestDocument.Value
            RequestInput = $requestLock
            Evidence = $evidenceInput.Value
            EvidenceInput = $evidenceLock
            UnsignedInstallerInput = $unsignedInput
            PayloadInputs = @($outputLocks | Where-Object {
                    $null -ne $_.PSObject.Properties['Role']
                })
            LockedOutputs = $outputLocks
        }
        Add-Member -InputObject $result -MemberType ScriptMethod -Name Dispose -Value {
            foreach ($descriptor in @($this.LockedOutputs)) {
                if ($null -ne $descriptor.Stream) {
                    $descriptor.Stream.Dispose()
                }
            }
        }
        return $result
    }
    catch {
        if ($null -ne $privateSdkClosure) {
            try {
                PortableDotNetSdkClosure\Close-PortableDotNetSdkClosure `
                    -Closure $privateSdkClosure
            }
            catch {
                # Preserve the original build failure while continuing cleanup.
            }
            $privateSdkClosure = $null
        }
        if ($null -ne $portableSdkClosure) {
            try {
                PortableDotNetSdkClosure\Close-PortableDotNetSdkClosure `
                    -Closure $portableSdkClosure
            }
            catch {
                # Preserve the original build failure while continuing cleanup.
            }
            $portableSdkClosure = $null
        }
        for ($index = $outputLocks.Count - 1; $index -ge 0; $index--) {
            $outputLocks[$index].Stream.Dispose()
        }
        if ($createdOutput -and [IO.Directory]::Exists($outputRoot) -and
            [IO.Path]::GetDirectoryName($outputRoot) -ceq $outputParent) {
            Remove-Item -LiteralPath $outputRoot -Recurse -Force
        }
        throw
    }
    finally {
        for ($index = $heldInputs.Count - 1; $index -ge 0; $index--) {
            $heldInputs[$index].Stream.Dispose()
        }
    }
}

Export-ModuleMember -Function @('New-EnterpriseInstallerTrustedBuild')
