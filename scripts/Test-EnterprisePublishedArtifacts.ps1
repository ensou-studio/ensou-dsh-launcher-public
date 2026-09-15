[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$InstallerPublishDirectory,

    [Parameter(Mandatory = $true)]
    [string]$BootstrapperPublishDirectory,

    [Parameter(Mandatory = $true)]
    [string]$LauncherPublishDirectory,

    [Parameter(Mandatory = $true)]
    [string]$ClientBootstrapperPublishDirectory,

    [Parameter(Mandatory = $true)]
    [string]$MaintenancePublishDirectory,

    [Parameter(Mandatory = $true)]
    [string]$PayloadDirectory,

    [ValidateSet('enterprise', 'development-e2e')]
    [string]$ExpectedLayoutProfile = 'enterprise',

    [switch]$RequireAuthenticode,

    [ValidatePattern('^[0-9A-Fa-f]{64}$')]
    [string]$SignerSha256Thumbprint
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$productionReleaseStateModule = [IO.Path]::GetFullPath((Join-Path `
    $PSScriptRoot `
    '..\release\scripts\ProductionReleaseState.psm1'))
Microsoft.PowerShell.Core\Import-Module `
    -Name $productionReleaseStateModule `
    -Force `
    -ErrorAction Stop

if ($ExpectedLayoutProfile -ceq 'enterprise' -and -not $RequireAuthenticode) {
    throw 'Enterprise production published artifacts require Authenticode verification.'
}
if ($RequireAuthenticode -and
    [string]::IsNullOrWhiteSpace($SignerSha256Thumbprint)) {
    throw '-RequireAuthenticode also requires -SignerSha256Thumbprint.'
}

if (-not ('EnsouEnterprisePublishedGate.NativeFileIdentity' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace EnsouEnterprisePublishedGate
{
    public readonly struct ExactFileIdentity
    {
        public ExactFileIdentity(uint volume, ulong index)
        {
            VolumeSerialNumber = volume;
            FileIndex = index;
        }

        public uint VolumeSerialNumber { get; }
        public ulong FileIndex { get; }
    }

    public static class NativeFileIdentity
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct ByHandleFileInformation
        {
            public uint FileAttributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
            public uint VolumeSerialNumber;
            public uint FileSizeHigh;
            public uint FileSizeLow;
            public uint NumberOfLinks;
            public uint FileIndexHigh;
            public uint FileIndexLow;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandle(
            SafeFileHandle handle,
            out ByHandleFileInformation information);

        public static ExactFileIdentity RequireOrdinarySingleLink(
            SafeFileHandle handle)
        {
            if (handle == null || handle.IsInvalid || handle.IsClosed)
            {
                throw new InvalidDataException("Artifact descriptor handle is invalid.");
            }
            if (!GetFileInformationByHandle(handle, out var information))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "Could not inspect artifact descriptor identity.");
            }
            const uint directory = 0x10;
            const uint reparsePoint = 0x400;
            if (information.NumberOfLinks != 1
                || (information.FileAttributes & (directory | reparsePoint)) != 0)
            {
                throw new InvalidDataException(
                    "Artifact descriptor must be one ordinary single-link file.");
            }
            return new ExactFileIdentity(
                information.VolumeSerialNumber,
                ((ulong)information.FileIndexHigh << 32) | information.FileIndexLow);
        }
    }
}
'@
}

function Resolve-SafeDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)

    if ($Path.StartsWith('\\', [StringComparison]::Ordinal) -or
        $Path.StartsWith('//', [StringComparison]::Ordinal)) {
        throw "Network and device directories are not accepted: $Path"
    }
    $resolved = [IO.Path]::GetFullPath($Path)
    $item = Get-Item -LiteralPath $resolved -Force
    if (-not $item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Expected an ordinary local directory: $resolved"
    }
    for ($current = $item; $null -ne $current; $current = $current.Parent) {
        if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Directory path crosses a filesystem link: $resolved"
        }
    }

    return $resolved
}

function Resolve-SafeFile {
    param([Parameter(Mandatory = $true)][string]$Path)

    $resolved = [IO.Path]::GetFullPath($Path)
    $item = Get-Item -LiteralPath $resolved -Force
    if ($item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $item.Length -le 0) {
        throw "Expected an ordinary non-empty local artifact file: $resolved"
    }
    for ($current = $item.Directory; $null -ne $current; $current = $current.Parent) {
        if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Artifact path crosses a filesystem link: $resolved"
        }
    }
    return $resolved
}

function Assert-ExactEnterprisePayloadInventory {
    param(
        [Parameter(Mandatory = $true)][string]$Directory,
        [Parameter(Mandatory = $true)][string]$LayoutProfile
    )

    $expectedNames = @(
        'Ensou.Dsh.Enterprise.Bootstrapper.exe',
        'enterprise-install-manifest.json',
        'launcher.zip',
        'runtime.zip')
    if ($LayoutProfile -ceq 'development-e2e') {
        $expectedNames += 'ALLOW-UNSIGNED-DEVELOPMENT-PAYLOAD.txt'
    }
    $entries = @(Get-ChildItem -LiteralPath $Directory -Force)
    $names = @($entries | ForEach-Object Name)
    if ($entries.Count -ne $expectedNames.Count -or
        @($entries | Where-Object {
            $_.PSIsContainer -or
            ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            $_.Length -le 0
        }).Count -ne 0 -or
        @(Compare-Object $expectedNames $names -CaseSensitive).Count -ne 0) {
        throw 'Enterprise payload directory does not contain its exact fixed ordinary-file inventory.'
    }
}

function Assert-NoFrameworkOrToolchainSidecars {
    param(
        [Parameter(Mandatory = $true)][string]$Directory,
        [Parameter(Mandatory = $true)][string]$ExecutableName
    )

    $executable = Join-Path $Directory $ExecutableName
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
        throw "Published executable is missing: $executable"
    }

    $forbidden = Get-ChildItem -LiteralPath $Directory -Recurse -Force |
        Where-Object {
            $_.PSIsContainer -and $_.Name -in @('node_modules', '.fnm', 'fnm') -or
            -not $_.PSIsContainer -and (
                $_.Extension -ieq '.dll' -or
                $_.Name -like '*.deps.json' -or
                $_.Name -like '*.runtimeconfig.json' -or
                $_.Name -in @('node.exe', 'npm.exe', 'npm.cmd', 'pnpm.exe', 'pnpm.cmd', 'fnm.exe'))
        } |
        Select-Object -First 1
    if ($forbidden) {
        throw "Published client unexpectedly depends on a framework/toolchain sidecar: $($forbidden.FullName)"
    }

    return $executable
}

function Assert-ProfileMarker {
    param(
        [Parameter(Mandatory = $true)][string]$Directory,
        [Parameter(Mandatory = $true)][string]$Expected
    )

    $path = Join-Path $Directory 'enterprise-build-profile.json'
    $marker = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    $properties = @($marker.PSObject.Properties.Name | Sort-Object)
    if (($properties -join ',') -ne 'layoutProfile,schemaVersion' -or
        $marker.schemaVersion -ne 1 -or
        $marker.layoutProfile -cne $Expected) {
        throw "Published binary profile marker mismatch: $path"
    }
}

function Invoke-WithoutSystemDotNet {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string]$Arguments,
        [Parameter(Mandatory = $true)][IO.FileStream]$Stream,
        [Parameter(Mandatory = $true)]$Descriptor
    )

    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $Executable
    $start.Arguments = $Arguments
    $start.WorkingDirectory = Split-Path -Parent $Executable
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.Environment['PATH'] = Join-Path $env:SystemRoot 'System32'
    $start.Environment['DOTNET_ROOT'] = Join-Path $env:TEMP 'ensou-no-system-dotnet'
    $start.Environment['DOTNET_MULTILEVEL_LOOKUP'] = '0'
    Assert-LockedArtifactUnchanged `
        -Stream $Stream `
        -Expected $Descriptor `
        -Name $Executable
    $process = [Diagnostics.Process]::Start($start)
    if (-not $process) {
        throw "Could not start published self-check: $Executable"
    }

    try {
        if (-not $process.WaitForExit(30000)) {
            $process.Kill($true)
            throw "Published self-check timed out: $Executable"
        }

        if ($process.ExitCode -ne 0) {
            throw "Published self-check failed with exit $($process.ExitCode): $Executable"
        }
    } finally {
        $process.Dispose()
    }
}

function Open-AdmittedArtifactCopy {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][IO.FileStream]$SourceStream,
        [Parameter(Mandatory = $true)]$Expected,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    Assert-LockedArtifactUnchanged `
        -Stream $SourceStream `
        -Expected $Expected `
        -Name $Source
    Copy-Item -LiteralPath $Source -Destination $Destination
    $copyStream = Open-LockedArtifact $Destination
    try {
        $copyDescriptor = Get-LockedArtifactDescriptor $copyStream
        if ($copyDescriptor.SizeBytes -ne $Expected.SizeBytes -or
            $copyDescriptor.Sha256 -cne $Expected.Sha256) {
            throw "Executable probe copy differs from its admitted locked bytes: $Destination"
        }
        return $copyStream
    }
    catch {
        $copyStream.Dispose()
        throw
    }
}

function Assert-NonInteractiveInstallerFailure {
    param(
        [Parameter(Mandatory = $true)][string]$Installer,
        [Parameter(Mandatory = $true)][IO.FileStream]$Stream,
        [Parameter(Mandatory = $true)]$Descriptor
    )

    $expectedStderr =
        'Ensou DSH Enterprise Installer machine command failed.'
    $probeRoot = Join-Path `
        ([IO.Path]::GetTempPath()) `
        ("ensou-enterprise-installer-machine-failure-" +
            [Guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($probeRoot) | Out-Null
    $probeInstaller = Join-Path `
        $probeRoot `
        'Ensou.Dsh.Enterprise.Installer.exe'
    $probes = @(
        [pscustomobject]@{
            Name = 'binary-extra-argument'
            Arguments = @('--binary-self-check', 'extra')
        },
        [pscustomobject]@{
            Name = 'brand-missing-argument'
            Arguments = @('--brand-self-check')
        },
        [pscustomobject]@{
            Name = 'payload-missing-argument'
            Arguments = @('--production-payload-self-check', 'launcher', 'runtime')
        }
    )

    $probeLock = $null
    try {
        $probeLock = Open-AdmittedArtifactCopy `
            -Source $Installer `
            -SourceStream $Stream `
            -Expected $Descriptor `
            -Destination $probeInstaller
        foreach ($probe in $probes) {
            $start = [Diagnostics.ProcessStartInfo]::new()
            $start.FileName = $probeInstaller
            $start.WorkingDirectory = $probeRoot
            $start.UseShellExecute = $false
            $start.CreateNoWindow = $true
            $start.RedirectStandardOutput = $true
            $start.RedirectStandardError = $true
            foreach ($argument in $probe.Arguments) {
                [void]$start.ArgumentList.Add([string]$argument)
            }
            $process = [Diagnostics.Process]::new()
            $process.StartInfo = $start
            try {
                Assert-LockedArtifactUnchanged `
                    -Stream $probeLock `
                    -Expected $Descriptor `
                    -Name $probeInstaller
                if (-not $process.Start()) {
                    throw "Could not start Enterprise Installer regression '$($probe.Name)'."
                }
                $stdoutTask = $process.StandardOutput.ReadToEndAsync()
                $stderrTask = $process.StandardError.ReadToEndAsync()
                if (-not $process.WaitForExit(30000)) {
                    $process.Kill($true)
                    if (-not $process.WaitForExit(5000)) {
                        throw 'Enterprise Installer process tree did not exit after termination.'
                    }
                    throw "Enterprise Installer regression '$($probe.Name)' blocked on interactive UI."
                }
                $process.WaitForExit()
                $stdout = $stdoutTask.GetAwaiter().GetResult()
                $stderr = $stderrTask.GetAwaiter().GetResult()
                if ($process.ExitCode -ne 1 -or
                    -not [string]::IsNullOrEmpty($stdout) -or
                    $stderr.TrimEnd([char[]]@("`r", "`n")) -cne $expectedStderr) {
                    throw "Enterprise Installer regression '$($probe.Name)' escaped its process boundary."
                }
            }
            finally {
                $process.Dispose()
            }
        }
    }
    finally {
        if ($null -ne $probeLock) {
            $probeLock.Dispose()
        }
        $fullProbeRoot = [IO.Path]::GetFullPath($probeRoot)
        $tempPrefix = [IO.Path]::TrimEndingDirectorySeparator(
            [IO.Path]::GetFullPath([IO.Path]::GetTempPath())) +
            [IO.Path]::DirectorySeparatorChar +
            'ensou-enterprise-installer-machine-failure-'
        if (-not $fullProbeRoot.StartsWith(
                $tempPrefix,
                [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Refusing to remove an unexpected Enterprise Installer regression directory.'
        }
        Remove-Item -LiteralPath $probeRoot -Recurse -Force `
            -ErrorAction SilentlyContinue
    }
}

function Invoke-InstallerPayloadSelfCheckWithoutSystemDotNet {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][object[]]$Expected,
        [Parameter(Mandatory = $true)][IO.FileStream]$Stream,
        [Parameter(Mandatory = $true)]$Descriptor
    )

    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $Executable
    [void]$start.ArgumentList.Add('--production-payload-self-check')
    foreach ($value in $Expected) {
        [void]$start.ArgumentList.Add(
            [Convert]::ToString(
                $value,
                [Globalization.CultureInfo]::InvariantCulture))
    }
    $start.WorkingDirectory = Split-Path -Parent $Executable
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.StandardOutputEncoding = [Text.UTF8Encoding]::new($false, $true)
    $start.StandardErrorEncoding = [Text.UTF8Encoding]::new($false, $true)
    $start.Environment['PATH'] = Join-Path $env:SystemRoot 'System32'
    $start.Environment['DOTNET_ROOT'] = Join-Path $env:TEMP 'ensou-no-system-dotnet'
    $start.Environment['DOTNET_ROOT_X64'] = Join-Path $env:TEMP 'ensou-no-system-dotnet-x64'
    $start.Environment['DOTNET_MULTILEVEL_LOOKUP'] = '0'
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    try {
        Assert-LockedArtifactUnchanged `
            -Stream $Stream `
            -Expected $Descriptor `
            -Name $Executable
        if (-not $process.Start()) {
            throw "Could not start Enterprise Installer payload self-check: $Executable"
        }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(300000)) {
            $process.Kill($true)
            if (-not $process.WaitForExit(5000)) {
                throw 'Enterprise Installer payload self-check process tree did not exit after termination.'
            }
            throw "Enterprise Installer payload self-check timed out: $Executable"
        }
        $process.WaitForExit()
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        if ($stdout.Length -gt 32768 -or $stderr.Length -gt 32768) {
            throw 'Enterprise Installer payload self-check emitted unbounded output.'
        }
        if ($process.ExitCode -ne 0 -or
            -not [string]::IsNullOrEmpty($stdout) -or
            -not [string]::IsNullOrEmpty($stderr)) {
            throw "Enterprise Installer payload self-check failed with exit $($process.ExitCode): $Executable"
        }
    } finally {
        $process.Dispose()
    }
}

function Assert-NonInteractiveBootstrapperFailure {
    param(
        [Parameter(Mandatory = $true)][string]$Bootstrapper,
        [Parameter(Mandatory = $true)][IO.FileStream]$Stream,
        [Parameter(Mandatory = $true)]$Descriptor
    )

    $expectedStderr = 'Ensou DSH Enterprise Bootstrapper machine command failed.'
    $probeRoot = Join-Path `
        ([IO.Path]::GetTempPath()) `
        ("ensou-bootstrapper-machine-failure-" + [Guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($probeRoot) | Out-Null
    $probeBootstrapper = Join-Path $probeRoot 'Ensou.Dsh.Enterprise.Bootstrapper.exe'

    $probes = @(
        [pscustomobject]@{ Stage = 'self-check'; Arguments = @('--self-check') },
        [pscustomobject]@{ Stage = 'binary-self-check'; Arguments = @('--binary-self-check') },
        [pscustomobject]@{
            Stage = 'brand-self-check'
            Arguments = @('--brand-self-check', ('0' * 64))
        },
        [pscustomobject]@{ Stage = 'rollback'; Arguments = @('--rollback') },
        [pscustomobject]@{
            Stage = 'quiet-maintenance-uninstall'
            Arguments = @('--maintenance-uninstall', '--quiet')
        }
    )

    $probeLock = $null
    try {
        $probeLock = Open-AdmittedArtifactCopy `
            -Source $Bootstrapper `
            -SourceStream $Stream `
            -Expected $Descriptor `
            -Destination $probeBootstrapper
        foreach ($probe in $probes) {
            $start = [Diagnostics.ProcessStartInfo]::new()
            $start.FileName = $probeBootstrapper
            $start.WorkingDirectory = $probeRoot
            $start.UseShellExecute = $false
            $start.CreateNoWindow = $true
            $start.RedirectStandardOutput = $true
            $start.RedirectStandardError = $true
            $start.Environment['PATH'] = Join-Path $env:SystemRoot 'System32'
            $start.Environment['DOTNET_ROOT'] = Join-Path $env:TEMP 'ensou-no-system-dotnet'
            $start.Environment['DOTNET_MULTILEVEL_LOOKUP'] = '0'
            foreach ($name in @(
                'ENSOU_DSH_ENTERPRISE_ALLOW_DEVELOPMENT_BOOTSTRAPPER',
                'ENSOU_DSH_E2E_LOCAL_APP_DATA_ROOT',
                'ENSOU_DSH_E2E_USER_PROFILE_ROOT',
                'ENSOU_DSH_E2E_ISOLATION_ID')) {
                [void]$start.Environment.Remove($name)
            }
            foreach ($argument in $probe.Arguments) {
                [void]$start.ArgumentList.Add([string]$argument)
            }

            $process = [Diagnostics.Process]::new()
            $process.StartInfo = $start
            try {
                Assert-LockedArtifactUnchanged `
                    -Stream $probeLock `
                    -Expected $Descriptor `
                    -Name $probeBootstrapper
                if (-not $process.Start()) {
                    throw "Could not start Bootstrapper failure regression at stage '$($probe.Stage)'."
                }
                $stdoutTask = $process.StandardOutput.ReadToEndAsync()
                $stderrTask = $process.StandardError.ReadToEndAsync()
                if (-not $process.WaitForExit(30000)) {
                    try {
                        $process.Kill($true)
                        if (-not $process.WaitForExit(5000)) {
                            throw 'Process tree did not exit after termination.'
                        }
                    }
                    catch {
                        throw "Bootstrapper machine-command failure regression timed out at stage '$($probe.Stage)', and process-tree termination did not complete."
                    }
                    throw "Bootstrapper machine-command failure regression timed out at stage '$($probe.Stage)'; the process tree was terminated."
                }
                $process.WaitForExit()
                $stdout = $stdoutTask.GetAwaiter().GetResult()
                $stderr = $stderrTask.GetAwaiter().GetResult()
                $normalizedStderr = $stderr.TrimEnd([char[]]@("`r", "`n"))
                if ($process.ExitCode -ne 1) {
                    throw "Bootstrapper machine-command failure regression returned the wrong exit code at stage '$($probe.Stage)'."
                }
                if (-not [string]::IsNullOrEmpty($stdout)) {
                    throw "Bootstrapper machine-command failure regression emitted unexpected stdout at stage '$($probe.Stage)'."
                }
                if ($normalizedStderr -cne $expectedStderr) {
                    throw "Bootstrapper machine-command failure regression emitted unexpected stderr at stage '$($probe.Stage)'."
                }
            }
            finally {
                $process.Dispose()
            }
        }
    }
    finally {
        if ($null -ne $probeLock) {
            $probeLock.Dispose()
        }
        $fullProbeRoot = [IO.Path]::GetFullPath($probeRoot)
        $tempPrefix = [IO.Path]::TrimEndingDirectorySeparator(
            [IO.Path]::GetFullPath([IO.Path]::GetTempPath())) +
            [IO.Path]::DirectorySeparatorChar +
            'ensou-bootstrapper-machine-failure-'
        if (-not $fullProbeRoot.StartsWith($tempPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Refusing to remove an unexpected Bootstrapper regression directory.'
        }
        Remove-Item -LiteralPath $probeRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Assert-NonInteractiveClientBootstrapperHealthFailure {
    param(
        [Parameter(Mandatory = $true)][string]$ClientBootstrapper,
        [Parameter(Mandatory = $true)][IO.FileStream]$Stream,
        [Parameter(Mandatory = $true)]$Descriptor
    )

    $expectedStderr =
        'Ensou DSH Enterprise ClientBootstrapper machine command failed.'
    $probeRoot = Join-Path `
        ([IO.Path]::GetTempPath()) `
        ("ensou-enterprise-client-bootstrapper-failure-" +
            [Guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($probeRoot) | Out-Null
    $probeExecutable = Join-Path `
        $probeRoot `
        'Ensou.Dsh.Enterprise.ClientBootstrapper.exe'

    $probeLock = $null
    try {
        $probeLock = Open-AdmittedArtifactCopy `
            -Source $ClientBootstrapper `
            -SourceStream $Stream `
            -Expected $Descriptor `
            -Destination $probeExecutable
        $healthToken = ('A' * 43) -join ''
        $probeCases = @(
            [pscustomobject]@{
                Name = 'valid-shape-runtime-failure'
                Arguments = @('--release-health-token', $healthToken)
            },
            [pscustomobject]@{
                Name = 'missing-token'
                Arguments = @('--release-health-token')
            },
            [pscustomobject]@{
                Name = 'extra-token-argument'
                Arguments = @('--release-health-token', $healthToken, 'extra')
            },
            [pscustomobject]@{
                Name = 'extra-self-check-argument'
                Arguments = @('--binary-self-check', 'extra')
            },
            [pscustomobject]@{
                Name = 'extra-installation-check-argument'
                Arguments = @('--installation-self-check', 'extra')
            }
        )
        foreach ($probeCase in $probeCases) {
            $start = [Diagnostics.ProcessStartInfo]::new()
            $start.FileName = $probeExecutable
            $start.WorkingDirectory = $probeRoot
            $start.UseShellExecute = $false
            $start.CreateNoWindow = $true
            $start.RedirectStandardOutput = $true
            $start.RedirectStandardError = $true
            $start.StandardOutputEncoding = [Text.UTF8Encoding]::new($false, $true)
            $start.StandardErrorEncoding = [Text.UTF8Encoding]::new($false, $true)
            $start.Environment['PATH'] = Join-Path $env:SystemRoot 'System32'
            $start.Environment['DOTNET_ROOT'] =
                Join-Path $env:TEMP 'ensou-no-system-dotnet'
            $start.Environment['DOTNET_ROOT_X64'] =
                Join-Path $env:TEMP 'ensou-no-system-dotnet-x64'
            $start.Environment['DOTNET_MULTILEVEL_LOOKUP'] = '0'
            foreach ($name in @(
                'ENSOU_DSH_ENTERPRISE_ALLOW_DEVELOPMENT_BOOTSTRAPPER',
                'ENSOU_DSH_E2E_LOCAL_APP_DATA_ROOT',
                'ENSOU_DSH_E2E_USER_PROFILE_ROOT',
                'ENSOU_DSH_E2E_ISOLATION_ID')) {
                [void]$start.Environment.Remove($name)
            }
            foreach ($argument in @($probeCase.Arguments)) {
                $start.ArgumentList.Add([string]$argument)
            }

            $process = [Diagnostics.Process]::new()
            $process.StartInfo = $start
            try {
                Assert-LockedArtifactUnchanged `
                    -Stream $probeLock `
                    -Expected $Descriptor `
                    -Name $probeExecutable
                if (-not $process.Start()) {
                    throw "Could not start Enterprise ClientBootstrapper regression '$($probeCase.Name)'."
                }
                $stdoutTask = $process.StandardOutput.ReadToEndAsync()
                $stderrTask = $process.StandardError.ReadToEndAsync()
                if (-not $process.WaitForExit(30000)) {
                    $process.Kill($true)
                    if (-not $process.WaitForExit(5000)) {
                        throw 'Enterprise ClientBootstrapper process tree did not exit after termination.'
                    }
                    throw "Enterprise ClientBootstrapper regression '$($probeCase.Name)' blocked on interactive UI."
                }
                $process.WaitForExit()
                $stdout = $stdoutTask.GetAwaiter().GetResult()
                $stderr = $stderrTask.GetAwaiter().GetResult()
                if ($stdout.Length -gt 32768 -or $stderr.Length -gt 32768) {
                    throw "Enterprise ClientBootstrapper regression '$($probeCase.Name)' emitted unbounded output."
                }
                if ($process.ExitCode -ne 1) {
                    throw "Enterprise ClientBootstrapper regression '$($probeCase.Name)' returned the wrong exit code."
                }
                if (-not [string]::IsNullOrEmpty($stdout)) {
                    throw "Enterprise ClientBootstrapper regression '$($probeCase.Name)' emitted unexpected stdout."
                }
                if ($stderr.TrimEnd([char[]]@("`r", "`n")) -cne $expectedStderr) {
                    throw "Enterprise ClientBootstrapper regression '$($probeCase.Name)' emitted unexpected stderr."
                }
            }
            finally {
                $process.Dispose()
            }
        }
    }
    finally {
        if ($null -ne $probeLock) {
            $probeLock.Dispose()
        }
        $fullProbeRoot = [IO.Path]::GetFullPath($probeRoot)
        $tempPrefix = [IO.Path]::TrimEndingDirectorySeparator(
            [IO.Path]::GetFullPath([IO.Path]::GetTempPath())) +
            [IO.Path]::DirectorySeparatorChar +
            'ensou-enterprise-client-bootstrapper-failure-'
        if (-not $fullProbeRoot.StartsWith(
                $tempPrefix,
                [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Refusing to remove an unexpected Enterprise ClientBootstrapper regression directory.'
        }
        Remove-Item -LiteralPath $probeRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Assert-Authenticode {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [AllowNull()][IO.FileStream]$Stream,
        [AllowNull()]$Descriptor
    )

    if (-not $RequireAuthenticode) {
        return [pscustomobject]@{
            status = 'NotRequired'
            signatureType = $null
            signerSha256 = $null
            timestamped = $false
            timestampProtocol = $null
            timestampSignerSha256 = $null
        }
    }

    $signature = Get-AuthenticodeSignature -LiteralPath $Executable
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
        -not $signature.SignerCertificate) {
        throw "Authenticode signature is not valid: $Executable ($($signature.Status))"
    }
    if ([string]$signature.SignatureType -cne 'Authenticode') {
        throw "Executable must carry an embedded Authenticode signature, not a catalog signature: $Executable"
    }

    $actual = $signature.SignerCertificate.GetCertHashString(
        [Security.Cryptography.HashAlgorithmName]::SHA256)
    if ($actual -cne $SignerSha256Thumbprint.ToUpperInvariant()) {
        throw "Authenticode signer mismatch: $Executable"
    }
    if ($null -eq $signature.TimeStamperCertificate) {
        throw "Enterprise production executable has no trusted Authenticode timestamp: $Executable"
    }

    if ($null -eq $Stream -or $null -eq $Descriptor) {
        throw "Enterprise production executable lacks its locked descriptor admission: $Executable"
    }
    [byte[]]$lockedBytes = Read-LockedArtifactBytes `
        -Stream $Stream `
        -Expected $Descriptor `
        -Name $Executable
    try {
        $timestampAdmission = ProductionReleaseState\Assert-PeRfc3161Timestamp `
            -Bytes $lockedBytes `
            -SignerCertificate $signature.SignerCertificate `
            -TimeStamperCertificate $signature.TimeStamperCertificate
    }
    finally {
        [Security.Cryptography.CryptographicOperations]::ZeroMemory($lockedBytes)
    }
    if ([string]$timestampAdmission.TimestampProtocol -cne 'RFC3161') {
        throw "Enterprise production executable did not pass canonical RFC3161 admission: $Executable"
    }
    $timestamped = $true

    return [pscustomobject]@{
        status = [string]$signature.Status
        signatureType = [string]$signature.SignatureType
        signerSha256 = $actual.ToLowerInvariant()
        timestamped = $timestamped
        timestampProtocol = [string]$timestampAdmission.TimestampProtocol
        timestampSignerSha256 = [string]$timestampAdmission.TimestampSignerSha256
    }
}

function Open-LockedArtifact {
    param([Parameter(Mandatory = $true)][string]$Path)

    $resolved = Resolve-SafeFile $Path
    $stream = [IO.FileStream]::new(
        $resolved,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read,
        1MB,
        [IO.FileOptions]::SequentialScan)
    try {
        $identity = [EnsouEnterprisePublishedGate.NativeFileIdentity]::RequireOrdinarySingleLink(
            $stream.SafeFileHandle)
        $postOpenPath = Resolve-SafeFile $resolved
        $pathStream = [IO.File]::Open(
            $postOpenPath,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read)
        try {
            $pathIdentity = [EnsouEnterprisePublishedGate.NativeFileIdentity]::RequireOrdinarySingleLink(
                $pathStream.SafeFileHandle)
            if ($pathIdentity.VolumeSerialNumber -ne $identity.VolumeSerialNumber -or
                $pathIdentity.FileIndex -ne $identity.FileIndex) {
                throw "Artifact path no longer names its locked descriptor: $resolved"
            }
        } finally {
            $pathStream.Dispose()
        }
        if ($stream.Length -le 0) {
            throw "Published artifact is empty: $resolved"
        }
        return $stream
    } catch {
        $stream.Dispose()
        throw
    }
}

function Get-LockedArtifactDescriptor {
    param([Parameter(Mandatory = $true)][IO.FileStream]$Stream)

    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        $Stream.Position = 0
        $digest = $hasher.ComputeHash($Stream)
        return [pscustomobject]@{
            SizeBytes = $Stream.Length
            Sha256 = [Convert]::ToHexString($digest).ToLowerInvariant()
        }
    } finally {
        $Stream.Position = 0
        $hasher.Dispose()
    }
}

function Read-LockedArtifactBytes {
    param(
        [Parameter(Mandatory = $true)][IO.FileStream]$Stream,
        [Parameter(Mandatory = $true)]$Expected,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ($Stream.Length -ne $Expected.SizeBytes -or
        $Expected.SizeBytes -gt [int]::MaxValue) {
        throw "Locked executable has an unsupported or changed length: $Name"
    }
    [byte[]]$bytes = [byte[]]::new([int]$Expected.SizeBytes)
    $savedPosition = $Stream.Position
    try {
        $Stream.Position = 0
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $Stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($read -le 0) {
                throw "Locked executable ended before its admitted length: $Name"
            }
            $offset += $read
        }
        if ($Stream.ReadByte() -ne -1) {
            throw "Locked executable grew after descriptor admission: $Name"
        }
        $sha256 = [Convert]::ToHexString(
            [Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
        if ($sha256 -cne $Expected.Sha256) {
            throw "Locked executable differs from its admitted descriptor: $Name"
        }
        return ,$bytes
    }
    catch {
        [Security.Cryptography.CryptographicOperations]::ZeroMemory($bytes)
        throw
    }
    finally {
        $Stream.Position = $savedPosition
    }
}

function Read-StrictEnterprisePayloadManifest {
    param(
        [Parameter(Mandatory = $true)][IO.FileStream]$Stream,
        [Parameter(Mandatory = $true)][string]$ExpectedLayoutProfile
    )

    if ($Stream.Length -le 0 -or $Stream.Length -gt 128KB) {
        throw 'Enterprise install manifest is empty or exceeds its bounded size.'
    }
    $Stream.Position = 0
    $document = [Text.Json.JsonDocument]::Parse($Stream)
    try {
        $root = $document.RootElement
        if ($root.ValueKind -ne [Text.Json.JsonValueKind]::Object) {
            throw 'Enterprise install manifest root must be an object.'
        }
        $expectedNames = @(
            'bootstrapperFile',
            'bootstrapperSha256',
            'bootstrapperSizeBytes',
            'launcherArchive',
            'launcherArchiveSha256',
            'launcherArchiveSizeBytes',
            'launcherReleaseId',
            'layoutProfile',
            'publishedAtUtc',
            'runtimeArchive',
            'runtimeArchiveSha256',
            'runtimeArchiveSizeBytes',
            'runtimeReleaseId',
            'schemaVersion')
        $properties = @($root.EnumerateObject())
        $propertyNames = @($properties | ForEach-Object Name)
        if ($properties.Count -ne $expectedNames.Count -or
            @(Compare-Object $expectedNames $propertyNames -CaseSensitive).Count -ne 0) {
            throw 'Enterprise install manifest must contain exactly its canonical properties.'
        }

        $manifest = [pscustomobject]@{
            SchemaVersion = $root.GetProperty('schemaVersion').GetInt32()
            LayoutProfile = $root.GetProperty('layoutProfile').GetString()
            LauncherReleaseId = $root.GetProperty('launcherReleaseId').GetString()
            RuntimeReleaseId = $root.GetProperty('runtimeReleaseId').GetString()
            LauncherArchive = $root.GetProperty('launcherArchive').GetString()
            LauncherArchiveSizeBytes = $root.GetProperty('launcherArchiveSizeBytes').GetInt64()
            LauncherArchiveSha256 = $root.GetProperty('launcherArchiveSha256').GetString()
            RuntimeArchive = $root.GetProperty('runtimeArchive').GetString()
            RuntimeArchiveSizeBytes = $root.GetProperty('runtimeArchiveSizeBytes').GetInt64()
            RuntimeArchiveSha256 = $root.GetProperty('runtimeArchiveSha256').GetString()
            BootstrapperFile = $root.GetProperty('bootstrapperFile').GetString()
            BootstrapperSizeBytes = $root.GetProperty('bootstrapperSizeBytes').GetInt64()
            BootstrapperSha256 = $root.GetProperty('bootstrapperSha256').GetString()
            PublishedAtUtc = $root.GetProperty('publishedAtUtc').GetString()
        }
    } finally {
        $document.Dispose()
        $Stream.Position = 0
    }

    if ($manifest.SchemaVersion -ne 1 -or
        $manifest.LayoutProfile -cne $ExpectedLayoutProfile -or
        $manifest.LauncherReleaseId -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$' -or
        $manifest.RuntimeReleaseId -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$' -or
        $manifest.LauncherArchive -cne 'launcher.zip' -or
        $manifest.RuntimeArchive -cne 'runtime.zip' -or
        $manifest.BootstrapperFile -cne 'Ensou.Dsh.Enterprise.Bootstrapper.exe' -or
        $manifest.LauncherArchiveSizeBytes -le 0 -or
        $manifest.LauncherArchiveSizeBytes -gt 1GB -or
        $manifest.RuntimeArchiveSizeBytes -le 0 -or
        $manifest.RuntimeArchiveSizeBytes -gt 8GB -or
        $manifest.BootstrapperSizeBytes -le 0 -or
        $manifest.BootstrapperSizeBytes -gt 512MB -or
        $manifest.LauncherArchiveSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $manifest.RuntimeArchiveSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $manifest.BootstrapperSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]::IsNullOrWhiteSpace($manifest.PublishedAtUtc)) {
        throw 'Enterprise install manifest violates its canonical payload contract.'
    }
    return $manifest
}

function Assert-PayloadDescriptorBinding {
    param(
        [Parameter(Mandatory = $true)][pscustomobject]$Descriptor,
        [Parameter(Mandatory = $true)][long]$ExpectedSizeBytes,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ($Descriptor.SizeBytes -ne $ExpectedSizeBytes -or
        $Descriptor.Sha256 -cne $ExpectedSha256) {
        throw "Enterprise payload file differs from its manifest descriptor: $Name"
    }
}

function Assert-ExactArtifactBinding {
    param(
        [Parameter(Mandatory = $true)][pscustomobject]$Payload,
        [Parameter(Mandatory = $true)][pscustomobject]$Published,
        [Parameter(Mandatory = $true)][string]$FailureMessage
    )

    if ($Payload.SizeBytes -ne $Published.SizeBytes -or
        $Payload.Sha256 -cne $Published.Sha256) {
        throw $FailureMessage
    }
}

function Get-ExactRootArchiveEntry {
    param(
        [Parameter(Mandatory = $true)][IO.Compression.ZipArchive]$Archive,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $matches = @($Archive.Entries | Where-Object {
        $normalized = $_.FullName.Replace('\', '/')
        [string]::Equals($normalized, $Name, [StringComparison]::OrdinalIgnoreCase)
    })
    if ($matches.Count -ne 1 -or
        -not [string]::Equals(
            $matches[0].FullName.Replace('\', '/'),
            $Name,
            [StringComparison]::Ordinal)) {
        throw "Client-bundle ZIP must contain exactly one root entry with exact casing: $Name"
    }
    return $matches[0]
}

function Assert-ArchiveEntryBinding {
    param(
        [Parameter(Mandatory = $true)][IO.Compression.ZipArchiveEntry]$Entry,
        [Parameter(Mandatory = $true)][pscustomobject]$Published
    )

    if ($Entry.Length -ne $Published.SizeBytes) {
        throw "Client-bundle entry size does not match its locked published bytes: $($Entry.FullName)"
    }
    $entryStream = $Entry.Open()
    try {
        $hasher = [Security.Cryptography.SHA256]::Create()
        try {
            $actual = [Convert]::ToHexString(
                $hasher.ComputeHash($entryStream)).ToLowerInvariant()
        } finally {
            $hasher.Dispose()
        }
    } finally {
        $entryStream.Dispose()
    }
    if ($actual -cne $Published.Sha256) {
        throw "Client-bundle entry SHA-256 does not match its locked published bytes: $($Entry.FullName)"
    }
}

function Assert-LockedArtifactUnchanged {
    param(
        [Parameter(Mandatory = $true)][IO.FileStream]$Stream,
        [Parameter(Mandatory = $true)][pscustomobject]$Expected,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $lockedIdentity =
        [EnsouEnterprisePublishedGate.NativeFileIdentity]::RequireOrdinarySingleLink(
            $Stream.SafeFileHandle)
    $resolved = Resolve-SafeFile $Name
    $pathStream = [IO.File]::Open(
        $resolved,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    try {
        $pathIdentity =
            [EnsouEnterprisePublishedGate.NativeFileIdentity]::RequireOrdinarySingleLink(
                $pathStream.SafeFileHandle)
        if ($pathIdentity.VolumeSerialNumber -ne $lockedIdentity.VolumeSerialNumber -or
            $pathIdentity.FileIndex -ne $lockedIdentity.FileIndex) {
            throw "Artifact path no longer names its locked descriptor: $resolved"
        }
    } finally {
        $pathStream.Dispose()
    }
    $actual = Get-LockedArtifactDescriptor $Stream
    if ($actual.SizeBytes -ne $Expected.SizeBytes -or
        $actual.Sha256 -cne $Expected.Sha256) {
        throw "Published artifact changed through a pre-existing writable handle: $resolved"
    }
}

$installerRoot = Resolve-SafeDirectory $InstallerPublishDirectory
$bootstrapperRoot = Resolve-SafeDirectory $BootstrapperPublishDirectory
$launcherRoot = Resolve-SafeDirectory $LauncherPublishDirectory
$clientBootstrapperRoot = Resolve-SafeDirectory $ClientBootstrapperPublishDirectory
$maintenanceRoot = Resolve-SafeDirectory $MaintenancePublishDirectory
$payloadRoot = Resolve-SafeDirectory $PayloadDirectory
Assert-ExactEnterprisePayloadInventory `
    -Directory $payloadRoot `
    -LayoutProfile $ExpectedLayoutProfile

$installer = Assert-NoFrameworkOrToolchainSidecars `
    -Directory $installerRoot `
    -ExecutableName 'Ensou.Dsh.Enterprise.Installer.exe'
$bootstrapper = Assert-NoFrameworkOrToolchainSidecars `
    -Directory $bootstrapperRoot `
    -ExecutableName 'Ensou.Dsh.Enterprise.Bootstrapper.exe'
$launcher = Assert-NoFrameworkOrToolchainSidecars `
    -Directory $launcherRoot `
    -ExecutableName 'Ensou.Dsh.Enterprise.Launcher.exe'
$clientBootstrapper = Assert-NoFrameworkOrToolchainSidecars `
    -Directory $clientBootstrapperRoot `
    -ExecutableName 'Ensou.Dsh.Enterprise.ClientBootstrapper.exe'
$maintenance = Assert-NoFrameworkOrToolchainSidecars `
    -Directory $maintenanceRoot `
    -ExecutableName 'Ensou.Dsh.Enterprise.Maintenance.exe'

Assert-ProfileMarker -Directory $bootstrapperRoot -Expected $ExpectedLayoutProfile
Assert-ProfileMarker -Directory $launcherRoot -Expected $ExpectedLayoutProfile
Assert-ProfileMarker -Directory $clientBootstrapperRoot -Expected $ExpectedLayoutProfile

$runtimeArchive = Join-Path $payloadRoot 'runtime.zip'
$clientBundleArchive = Join-Path $payloadRoot 'launcher.zip'
$payloadManifest = Join-Path $payloadRoot 'enterprise-install-manifest.json'
$payloadBootstrapper = Join-Path `
    $payloadRoot `
    'Ensou.Dsh.Enterprise.Bootstrapper.exe'
$launcherProfileMarker = Join-Path $launcherRoot 'enterprise-build-profile.json'

Add-Type -AssemblyName System.IO.Compression
$locks = [Collections.Generic.List[IDisposable]]::new()
try {
    $installerLock = Open-LockedArtifact $installer
    $locks.Add($installerLock)
    $bootstrapperLock = Open-LockedArtifact $bootstrapper
    $locks.Add($bootstrapperLock)
    $launcherLock = Open-LockedArtifact $launcher
    $locks.Add($launcherLock)
    $clientBootstrapperLock = Open-LockedArtifact $clientBootstrapper
    $locks.Add($clientBootstrapperLock)
    $maintenanceLock = Open-LockedArtifact $maintenance
    $locks.Add($maintenanceLock)
    $launcherProfileMarkerLock = Open-LockedArtifact $launcherProfileMarker
    $locks.Add($launcherProfileMarkerLock)
    $clientBundleLock = Open-LockedArtifact $clientBundleArchive
    $locks.Add($clientBundleLock)
    $runtimeArchiveLock = Open-LockedArtifact $runtimeArchive
    $locks.Add($runtimeArchiveLock)
    $payloadManifestLock = Open-LockedArtifact $payloadManifest
    $locks.Add($payloadManifestLock)
    $payloadBootstrapperLock = Open-LockedArtifact $payloadBootstrapper
    $locks.Add($payloadBootstrapperLock)

    $installerDescriptor = Get-LockedArtifactDescriptor $installerLock
    $bootstrapperDescriptor = Get-LockedArtifactDescriptor $bootstrapperLock
    $launcherDescriptor = Get-LockedArtifactDescriptor $launcherLock
    $clientBootstrapperDescriptor = Get-LockedArtifactDescriptor $clientBootstrapperLock
    $maintenanceDescriptor = Get-LockedArtifactDescriptor $maintenanceLock
    $launcherProfileMarkerDescriptor = Get-LockedArtifactDescriptor `
        $launcherProfileMarkerLock
    $clientBundleDescriptor = Get-LockedArtifactDescriptor $clientBundleLock
    $runtimeArchiveDescriptor = Get-LockedArtifactDescriptor $runtimeArchiveLock
    $payloadManifestDescriptor = Get-LockedArtifactDescriptor $payloadManifestLock
    $payloadBootstrapperDescriptor = Get-LockedArtifactDescriptor `
        $payloadBootstrapperLock

    $payloadManifestValue = Read-StrictEnterprisePayloadManifest `
        -Stream $payloadManifestLock `
        -ExpectedLayoutProfile $ExpectedLayoutProfile
    Assert-PayloadDescriptorBinding `
        -Descriptor $clientBundleDescriptor `
        -ExpectedSizeBytes $payloadManifestValue.LauncherArchiveSizeBytes `
        -ExpectedSha256 $payloadManifestValue.LauncherArchiveSha256 `
        -Name $clientBundleArchive
    Assert-PayloadDescriptorBinding `
        -Descriptor $runtimeArchiveDescriptor `
        -ExpectedSizeBytes $payloadManifestValue.RuntimeArchiveSizeBytes `
        -ExpectedSha256 $payloadManifestValue.RuntimeArchiveSha256 `
        -Name $runtimeArchive
    Assert-PayloadDescriptorBinding `
        -Descriptor $payloadBootstrapperDescriptor `
        -ExpectedSizeBytes $payloadManifestValue.BootstrapperSizeBytes `
        -ExpectedSha256 $payloadManifestValue.BootstrapperSha256 `
        -Name $payloadBootstrapper
    Assert-ExactArtifactBinding `
        -Payload $payloadBootstrapperDescriptor `
        -Published $bootstrapperDescriptor `
        -FailureMessage 'Enterprise Installer payload Bootstrapper differs from the independently validated Bootstrapper publish.'

    $clientBundle = [IO.Compression.ZipArchive]::new(
        $clientBundleLock,
        [IO.Compression.ZipArchiveMode]::Read,
        $true)
    try {
        $launcherEntry = Get-ExactRootArchiveEntry `
            -Archive $clientBundle `
            -Name 'Ensou.Dsh.Enterprise.Launcher.exe'
        $clientBootstrapperEntry = Get-ExactRootArchiveEntry `
            -Archive $clientBundle `
            -Name 'Ensou.Dsh.Enterprise.ClientBootstrapper.exe'
        $maintenanceEntry = Get-ExactRootArchiveEntry `
            -Archive $clientBundle `
            -Name 'Ensou.Dsh.Enterprise.Maintenance.exe'
        $profileMarkerEntry = Get-ExactRootArchiveEntry `
            -Archive $clientBundle `
            -Name 'enterprise-build-profile.json'
        Assert-ArchiveEntryBinding `
            -Entry $launcherEntry `
            -Published $launcherDescriptor
        Assert-ArchiveEntryBinding `
            -Entry $clientBootstrapperEntry `
            -Published $clientBootstrapperDescriptor
        Assert-ArchiveEntryBinding `
            -Entry $maintenanceEntry `
            -Published $maintenanceDescriptor
        Assert-ArchiveEntryBinding `
            -Entry $profileMarkerEntry `
            -Published $launcherProfileMarkerDescriptor
    } finally {
        $clientBundle.Dispose()
    }

    $archive = [IO.Compression.ZipArchive]::new(
        $runtimeArchiveLock,
        [IO.Compression.ZipArchiveMode]::Read,
        $true)
    try {
        $entryNames = @(
            $archive.Entries | ForEach-Object { $_.FullName.Replace('\', '/') }
        )
        if ($entryNames -notcontains 'node.exe' -or
            $entryNames -notcontains 'node_modules/@deepseek-ai/dsh/lib/bin.js' -or
            ($entryNames | Where-Object { $_ -in @('npm.exe', 'npm.cmd', 'pnpm.exe', 'pnpm.cmd', 'fnm.exe') })) {
            throw 'Runtime ZIP does not contain the exact bundled Node/DSH boundary.'
        }
    } finally {
        $archive.Dispose()
    }

    $authenticodeEvidence = [ordered]@{}
    foreach ($productionPe in @(
        [pscustomobject]@{
            Name = 'Installer'
            Path = $installer
            Stream = $installerLock
            Descriptor = $installerDescriptor
        },
        [pscustomobject]@{
            Name = 'Bootstrapper'
            Path = $bootstrapper
            Stream = $bootstrapperLock
            Descriptor = $bootstrapperDescriptor
        },
        [pscustomobject]@{
            Name = 'Launcher'
            Path = $launcher
            Stream = $launcherLock
            Descriptor = $launcherDescriptor
        },
        [pscustomobject]@{
            Name = 'ClientBootstrapper'
            Path = $clientBootstrapper
            Stream = $clientBootstrapperLock
            Descriptor = $clientBootstrapperDescriptor
        },
        [pscustomobject]@{
            Name = 'Maintenance'
            Path = $maintenance
            Stream = $maintenanceLock
            Descriptor = $maintenanceDescriptor
        }
    )) {
        $authenticodeEvidence[$productionPe.Name] = Assert-Authenticode `
            -Executable $productionPe.Path `
            -Stream $productionPe.Stream `
            -Descriptor $productionPe.Descriptor
    }

    Invoke-WithoutSystemDotNet `
        -Executable $installer `
        -Arguments '--binary-self-check' `
        -Stream $installerLock `
        -Descriptor $installerDescriptor
    Invoke-WithoutSystemDotNet `
        -Executable $bootstrapper `
        -Arguments '--binary-self-check' `
        -Stream $bootstrapperLock `
        -Descriptor $bootstrapperDescriptor
    Invoke-WithoutSystemDotNet `
        -Executable $launcher `
        -Arguments '--self-check' `
        -Stream $launcherLock `
        -Descriptor $launcherDescriptor
    Invoke-WithoutSystemDotNet `
        -Executable $clientBootstrapper `
        -Arguments '--binary-self-check' `
        -Stream $clientBootstrapperLock `
        -Descriptor $clientBootstrapperDescriptor
    Invoke-WithoutSystemDotNet `
        -Executable $maintenance `
        -Arguments '--binary-self-check' `
        -Stream $maintenanceLock `
        -Descriptor $maintenanceDescriptor
    Assert-NonInteractiveInstallerFailure `
        -Installer $installer `
        -Stream $installerLock `
        -Descriptor $installerDescriptor
    Assert-NonInteractiveBootstrapperFailure `
        -Bootstrapper $bootstrapper `
        -Stream $bootstrapperLock `
        -Descriptor $bootstrapperDescriptor
    Assert-NonInteractiveClientBootstrapperHealthFailure `
        -ClientBootstrapper $clientBootstrapper `
        -Stream $clientBootstrapperLock `
        -Descriptor $clientBootstrapperDescriptor

    if ($ExpectedLayoutProfile -ceq 'enterprise') {
        Invoke-InstallerPayloadSelfCheckWithoutSystemDotNet `
            -Executable $installer `
            -Expected @(
                $payloadManifestValue.LauncherReleaseId,
                $payloadManifestValue.RuntimeReleaseId,
                $payloadManifestDescriptor.Sha256,
                $payloadManifestDescriptor.SizeBytes,
                $clientBundleDescriptor.Sha256,
                $clientBundleDescriptor.SizeBytes,
                $runtimeArchiveDescriptor.Sha256,
                $runtimeArchiveDescriptor.SizeBytes,
                $payloadBootstrapperDescriptor.Sha256,
                $payloadBootstrapperDescriptor.SizeBytes) `
            -Stream $installerLock `
            -Descriptor $installerDescriptor
    }

    foreach ($lockedSnapshot in @(
        [pscustomobject]@{ Stream = $installerLock; Expected = $installerDescriptor; Name = $installer },
        [pscustomobject]@{ Stream = $bootstrapperLock; Expected = $bootstrapperDescriptor; Name = $bootstrapper },
        [pscustomobject]@{ Stream = $launcherLock; Expected = $launcherDescriptor; Name = $launcher },
        [pscustomobject]@{ Stream = $clientBootstrapperLock; Expected = $clientBootstrapperDescriptor; Name = $clientBootstrapper },
        [pscustomobject]@{ Stream = $maintenanceLock; Expected = $maintenanceDescriptor; Name = $maintenance },
        [pscustomobject]@{ Stream = $launcherProfileMarkerLock; Expected = $launcherProfileMarkerDescriptor; Name = $launcherProfileMarker },
        [pscustomobject]@{ Stream = $clientBundleLock; Expected = $clientBundleDescriptor; Name = $clientBundleArchive },
        [pscustomobject]@{ Stream = $runtimeArchiveLock; Expected = $runtimeArchiveDescriptor; Name = $runtimeArchive },
        [pscustomobject]@{ Stream = $payloadManifestLock; Expected = $payloadManifestDescriptor; Name = $payloadManifest },
        [pscustomobject]@{ Stream = $payloadBootstrapperLock; Expected = $payloadBootstrapperDescriptor; Name = $payloadBootstrapper }
    )) {
        Assert-LockedArtifactUnchanged `
            -Stream $lockedSnapshot.Stream `
            -Expected $lockedSnapshot.Expected `
            -Name $lockedSnapshot.Name
    }
    Assert-ExactEnterprisePayloadInventory `
        -Directory $payloadRoot `
        -LayoutProfile $ExpectedLayoutProfile

    [pscustomobject]@{
        RuntimeIdentifier = 'win-x64'
        SelfContainedExecution = $true
        ManagedRuntimeSingleExecutable = $true
        SystemDotNetRequired = $false
        FnmRequired = $false
        SystemNodeRequired = $false
        BundledNodeLocation = 'runtime.zip:/node.exe'
        LayoutProfile = $ExpectedLayoutProfile
        InstallerPayloadBinding = $ExpectedLayoutProfile -ceq 'enterprise'
        InstallerPayloadManifestSha256 = $payloadManifestDescriptor.Sha256
        LauncherReleaseId = $payloadManifestValue.LauncherReleaseId
        RuntimeReleaseId = $payloadManifestValue.RuntimeReleaseId
        AuthenticodeRequired = [bool]$RequireAuthenticode
        AuthenticodeEvidence = [pscustomobject]$authenticodeEvidence
    }
} finally {
    for ($index = $locks.Count - 1; $index -ge 0; $index--) {
        $locks[$index].Dispose()
    }
}
