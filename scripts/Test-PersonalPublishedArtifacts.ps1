[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$StartupStubPublishDirectory,

    [Parameter(Mandatory = $true)]
    [string]$ClientBootstrapperPublishDirectory,

    [Parameter(Mandatory = $true)]
    [string]$LauncherPublishDirectory,

    [Parameter(Mandatory = $true)]
    [string]$MaintenancePublishDirectory,

    [Parameter(Mandatory = $true)]
    [string]$ClientBundleArchivePath,

    [string]$InstallerPublishDirectory,

    [string]$InstallerPayloadDirectory,

    [string]$ProductionGateEvidencePath,

    [switch]$ExerciseLockedReplacementRace,

    [switch]$ProductionDistributionGate,

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

if (-not ('EnsouPersonalGate.NativeFileIdentity' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace EnsouPersonalGate
{
    public readonly struct ExactFileIdentity
    {
        public ExactFileIdentity(uint volume, ulong index, uint links, uint attributes)
        {
            VolumeSerialNumber = volume;
            FileIndex = index;
            NumberOfLinks = links;
            FileAttributes = attributes;
        }

        public uint VolumeSerialNumber { get; }
        public ulong FileIndex { get; }
        public uint NumberOfLinks { get; }
        public uint FileAttributes { get; }
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

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CreateHardLink(
            string newFileName,
            string existingFileName,
            IntPtr securityAttributes);

        public static ExactFileIdentity RequireOrdinarySingleLink(SafeFileHandle handle)
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
            var index = ((ulong)information.FileIndexHigh << 32)
                | information.FileIndexLow;
            return new ExactFileIdentity(
                information.VolumeSerialNumber,
                index,
                information.NumberOfLinks,
                information.FileAttributes);
        }
    }
}
'@
}

if ($ProductionDistributionGate -and
    [string]::IsNullOrWhiteSpace($InstallerPublishDirectory)) {
    throw 'Personal production distribution requires an independent signed Personal Installer.'
}
if ([string]::IsNullOrWhiteSpace($InstallerPublishDirectory) -xor
    [string]::IsNullOrWhiteSpace($InstallerPayloadDirectory)) {
    throw 'Personal Installer validation requires both its publish directory and the independent four-file payload directory.'
}
if ($ProductionDistributionGate -and -not $RequireAuthenticode) {
    throw 'Personal production distribution requires Authenticode verification.'
}
if ($ProductionDistributionGate -and
    [string]::IsNullOrWhiteSpace($ProductionGateEvidencePath)) {
    throw 'Personal production distribution requires a create-only machine gate evidence path.'
}
if ($ProductionDistributionGate -and $ExerciseLockedReplacementRace) {
    throw 'The destructive replacement race probe is restricted to development validation.'
}
if ($RequireAuthenticode -and
    [string]::IsNullOrWhiteSpace($SignerSha256Thumbprint)) {
    throw '-RequireAuthenticode requires -SignerSha256Thumbprint.'
}

function Resolve-OrdinaryDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)

    $resolved = [IO.Path]::GetFullPath($Path)
    $item = Get-Item -LiteralPath $resolved -Force
    if (-not $item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Expected an ordinary publish directory: $resolved"
    }
    for ($current = $item; $null -ne $current; $current = $current.Parent) {
        if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Publish directory crosses a filesystem link: $resolved"
        }
    }
    return $resolved
}

function Resolve-OrdinaryFile {
    param([Parameter(Mandatory = $true)][string]$Path)

    $resolved = [IO.Path]::GetFullPath($Path)
    $item = Get-Item -LiteralPath $resolved -Force
    if ($item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $item.Length -le 0) {
        throw "Expected one ordinary non-empty file: $resolved"
    }
    for ($current = $item.Directory; $null -ne $current; $current = $current.Parent) {
        if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "File path crosses a filesystem link: $resolved"
        }
    }
    return $resolved
}

function Assert-WinX64Pe {
    param([Parameter(Mandatory = $true)][string]$Executable)

    $stream = [IO.File]::Open(
        $Executable,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    try {
        $reader = [Reflection.PortableExecutable.PEReader]::new($stream)
        try {
            if ($reader.PEHeaders.CoffHeader.Machine -ne
                    [Reflection.PortableExecutable.Machine]::Amd64) {
                throw "Published executable is not a win-x64 PE: $Executable"
            }
        } finally {
            $reader.Dispose()
        }
    } finally {
        $stream.Dispose()
    }
}

function Assert-ExactSingleExecutable {
    param(
        [Parameter(Mandatory = $true)][string]$Directory,
        [Parameter(Mandatory = $true)][string]$ExecutableName
    )

    $root = Resolve-OrdinaryDirectory $Directory
    $entries = @(Get-ChildItem -LiteralPath $root -Force -Recurse)
    $executable = Join-Path $root $ExecutableName
    if ($entries.Count -ne 1 -or
        $entries[0].PSIsContainer -or
        $entries[0].FullName -cne $executable -or
        ($entries[0].Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $entries[0].Length -le 0) {
        throw "Publish directory must contain exactly one ordinary executable: $executable"
    }
    Assert-WinX64Pe $executable
    return $executable
}

function Invoke-BinarySelfCheckWithoutSystemDotNet {
    param([Parameter(Mandatory = $true)]$Descriptor)

    $Executable = [string]$Descriptor.Path
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $Executable
    $start.ArgumentList.Add('--binary-self-check')
    $start.WorkingDirectory = Split-Path -Parent $Executable
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.StandardOutputEncoding = [Text.UTF8Encoding]::new($false, $true)
    $start.StandardErrorEncoding = [Text.UTF8Encoding]::new($false, $true)
    $start.Environment['PATH'] = Join-Path $env:SystemRoot 'System32'
    $start.Environment['DOTNET_ROOT'] = Join-Path $env:TEMP 'ensou-personal-no-dotnet'
    $start.Environment['DOTNET_ROOT_X64'] = Join-Path $env:TEMP 'ensou-personal-no-dotnet-x64'
    $start.Environment['DOTNET_MULTILEVEL_LOOKUP'] = '0'
    $start.Environment['ENSOU_DSH_PERSONAL_BINARY_SELF_CHECK_PROTOCOL'] =
        'ensou-personal-binary-self-check/v1'
    Assert-ExactFileDescriptorUnchanged $Descriptor
    $process = [Diagnostics.Process]::Start($start)
    if (-not $process) {
        throw "Could not start personal binary self-check: $Executable"
    }
    try {
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(30000)) {
            $process.Kill($true)
            throw "Personal binary self-check timed out: $Executable"
        }
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        if ($stdout.Length -gt 32768 -or $stderr.Length -gt 32768) {
            throw "Personal binary self-check output is unbounded: $Executable"
        }
        if ($process.ExitCode -ne 0) {
            throw "Personal binary self-check failed with exit $($process.ExitCode): $Executable $stderr"
        }
        $fingerprint = $stdout | ConvertFrom-Json
        $expectedProperties = @(
            'artifactOrigin',
            'authenticodeSignerSha256Thumbprint',
            'canonicalLowSFromSequence',
            'channel',
            'environment',
            'manifestOrigin',
            'productionBuild',
            'product',
            'releaseKeyId',
            'releaseKeyX',
            'releaseKeyY',
            'schemaVersion',
            'startupStubVersion'
        )
        if ((@($fingerprint.PSObject.Properties.Name | Sort-Object) -join ',') -cne
                (@($expectedProperties | Sort-Object) -join ',') -or
            $fingerprint.schemaVersion -ne 2 -or
            $fingerprint.canonicalLowSFromSequence -lt 1 -or
            $fingerprint.product -cne 'ensou-dsh-personal' -or
            $fingerprint.environment -cne 'production') {
            throw "Personal binary self-check returned an invalid trust fingerprint: $Executable"
        }
        $bytes = [Text.Encoding]::UTF8.GetBytes($stdout)
        try {
            $sha256 = [Convert]::ToHexString(
                [Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
        } finally {
            [Security.Cryptography.CryptographicOperations]::ZeroMemory($bytes)
        }
        return [pscustomobject]@{
            Raw = $stdout
            Sha256 = $sha256
            Value = $fingerprint
        }
    } finally {
        $process.Dispose()
    }
}

function Assert-BinarySelfCheckProtocolRequired {
    param([Parameter(Mandatory = $true)]$Descriptor)

    foreach ($case in @(
        [pscustomobject]@{ Name = 'missing'; Value = $null },
        [pscustomobject]@{
            Name = 'wrong'
            Value = 'ensou-personal-binary-self-check/v1-extra'
        }
    )) {
        $start = [Diagnostics.ProcessStartInfo]::new()
        $start.FileName = [string]$Descriptor.Path
        $start.ArgumentList.Add('--binary-self-check')
        $start.WorkingDirectory = Split-Path -Parent $Descriptor.Path
        $start.UseShellExecute = $false
        $start.CreateNoWindow = $true
        $start.RedirectStandardOutput = $true
        $start.RedirectStandardError = $true
        $start.StandardOutputEncoding = [Text.UTF8Encoding]::new($false, $true)
        $start.StandardErrorEncoding = [Text.UTF8Encoding]::new($false, $true)
        $start.Environment['PATH'] = Join-Path $env:SystemRoot 'System32'
        $start.Environment['DOTNET_ROOT'] = Join-Path $env:TEMP 'ensou-personal-no-dotnet'
        $start.Environment['DOTNET_ROOT_X64'] = Join-Path $env:TEMP 'ensou-personal-no-dotnet-x64'
        $start.Environment['DOTNET_MULTILEVEL_LOOKUP'] = '0'
        [void]$start.Environment.Remove(
            'ENSOU_DSH_PERSONAL_BINARY_SELF_CHECK_PROTOCOL')
        if ($null -ne $case.Value) {
            $start.Environment['ENSOU_DSH_PERSONAL_BINARY_SELF_CHECK_PROTOCOL'] =
                [string]$case.Value
        }
        Assert-ExactFileDescriptorUnchanged $Descriptor
        $process = [Diagnostics.Process]::Start($start)
        if (-not $process) {
            throw "Could not start Personal binary protocol negative case: $($Descriptor.Path)"
        }
        try {
            $stdoutTask = $process.StandardOutput.ReadToEndAsync()
            $stderrTask = $process.StandardError.ReadToEndAsync()
            if (-not $process.WaitForExit(30000)) {
                $process.Kill($true)
                throw "Personal binary $($case.Name)-protocol case blocked on UI: $($Descriptor.Path)"
            }
            $stdout = $stdoutTask.GetAwaiter().GetResult()
            $stderr = $stderrTask.GetAwaiter().GetResult()
            if ($process.ExitCode -eq 0 -or
                $stdout.Length -ne 0 -or
                $stderr.Length -gt 32768) {
                throw "Personal binary $($case.Name)-protocol case did not fail canonically: $($Descriptor.Path)"
            }
            Assert-ExactFileDescriptorUnchanged $Descriptor
        } finally {
            $process.Dispose()
        }
    }
}

function Assert-NonInteractiveStartupStubMachineFailure {
    param([Parameter(Mandatory = $true)]$Descriptor)

    $expectedStderr =
        'Ensou DSH Personal Startup Stub machine command failed.'
    $probeRoot = Join-Path `
        ([IO.Path]::GetTempPath()) `
        ("ensou-personal-startup-stub-failure-" +
            [Guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($probeRoot) | Out-Null
    $probeExecutable = Join-Path $probeRoot 'Ensou.Dsh.Bootstrapper.exe'
    $probeCases = @(
        [pscustomobject]@{
            Name = 'extra-binary-self-check-argument'
            Arguments = @('--binary-self-check', 'extra')
        },
        [pscustomobject]@{
            Name = 'extra-installer-health-argument'
            Arguments = @('--installer-health', 'extra')
        },
        [pscustomobject]@{
            Name = 'extra-self-check-argument'
            Arguments = @('--self-check', 'extra')
        },
        [pscustomobject]@{
            Name = 'extra-maintenance-repair-argument'
            Arguments = @('--maintenance-repair', 'extra')
        }
    )

    $probeLeases = [Collections.Generic.List[IDisposable]]::new()
    try {
        $probeDescriptor = Open-AdmittedDescriptorCopy `
            -SourceDescriptor $Descriptor `
            -Destination $probeExecutable `
            -Leases $probeLeases
        foreach ($probeCase in $probeCases) {
            $start = [Diagnostics.ProcessStartInfo]::new()
            $start.FileName = $probeExecutable
            $start.WorkingDirectory = $probeRoot
            $start.UseShellExecute = $false
            $start.CreateNoWindow = $true
            $start.RedirectStandardOutput = $true
            $start.RedirectStandardError = $true
            $start.Environment['PATH'] = Join-Path $env:SystemRoot 'System32'
            $start.Environment['DOTNET_ROOT'] =
                Join-Path $env:TEMP 'ensou-personal-no-dotnet'
            $start.Environment['DOTNET_ROOT_X64'] =
                Join-Path $env:TEMP 'ensou-personal-no-dotnet-x64'
            $start.Environment['DOTNET_MULTILEVEL_LOOKUP'] = '0'
            [void]$start.Environment.Remove(
                'ENSOU_DSH_ALLOW_DEVELOPMENT_LAUNCHER')
            foreach ($argument in @($probeCase.Arguments)) {
                [void]$start.ArgumentList.Add([string]$argument)
            }

            $process = [Diagnostics.Process]::new()
            $process.StartInfo = $start
            try {
                Assert-ExactFileDescriptorUnchanged $probeDescriptor
                if (-not $process.Start()) {
                    throw "Could not start Personal Startup Stub regression '$($probeCase.Name)'."
                }
                $stdoutTask = $process.StandardOutput.ReadToEndAsync()
                $stderrTask = $process.StandardError.ReadToEndAsync()
                if (-not $process.WaitForExit(30000)) {
                    $process.Kill($true)
                    if (-not $process.WaitForExit(5000)) {
                        throw 'Personal Startup Stub process tree did not exit after termination.'
                    }
                    throw "Personal Startup Stub regression '$($probeCase.Name)' blocked on interactive UI."
                }
                $process.WaitForExit()
                $stdout = $stdoutTask.GetAwaiter().GetResult()
                $stderr = $stderrTask.GetAwaiter().GetResult()
                if ($process.ExitCode -ne 1 -or
                    -not [string]::IsNullOrEmpty($stdout) -or
                    $stderr.TrimEnd([char[]]@("`r", "`n")) -cne $expectedStderr) {
                    throw "Personal Startup Stub regression '$($probeCase.Name)' escaped its noninteractive failure contract."
                }
            }
            finally {
                $process.Dispose()
            }
        }
    }
    finally {
        foreach ($lease in $probeLeases) {
            $lease.Dispose()
        }
        $fullProbeRoot = [IO.Path]::GetFullPath($probeRoot)
        $tempPrefix = [IO.Path]::TrimEndingDirectorySeparator(
            [IO.Path]::GetFullPath([IO.Path]::GetTempPath())) +
            [IO.Path]::DirectorySeparatorChar +
            'ensou-personal-startup-stub-failure-'
        if (-not $fullProbeRoot.StartsWith(
                $tempPrefix,
                [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Refusing to remove an unexpected Personal Startup Stub regression directory.'
        }
        Remove-Item -LiteralPath $probeRoot -Recurse -Force `
            -ErrorAction SilentlyContinue
    }
}

function Assert-NonInteractiveClientBootstrapperHealthFailure {
    param([Parameter(Mandatory = $true)]$Descriptor)

    $expectedStderr =
        'Ensou DSH Personal ClientBootstrapper machine command failed.'
    $probeRoot = Join-Path `
        ([IO.Path]::GetTempPath()) `
        ("ensou-personal-client-bootstrapper-failure-" +
            [Guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($probeRoot) | Out-Null
    $probeExecutable = Join-Path `
        $probeRoot `
        'Ensou.Dsh.ClientBootstrapper.exe'

    $probeLeases = [Collections.Generic.List[IDisposable]]::new()
    try {
        $probeDescriptor = Open-AdmittedDescriptorCopy `
            -SourceDescriptor $Descriptor `
            -Destination $probeExecutable `
            -Leases $probeLeases
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
                Join-Path $env:TEMP 'ensou-personal-no-dotnet'
            $start.Environment['DOTNET_ROOT_X64'] =
                Join-Path $env:TEMP 'ensou-personal-no-dotnet-x64'
            $start.Environment['DOTNET_MULTILEVEL_LOOKUP'] = '0'
            [void]$start.Environment.Remove('ENSOU_DSH_ALLOW_DEVELOPMENT_LAUNCHER')
            foreach ($argument in @($probeCase.Arguments)) {
                $start.ArgumentList.Add([string]$argument)
            }

            $process = [Diagnostics.Process]::new()
            $process.StartInfo = $start
            try {
                Assert-ExactFileDescriptorUnchanged $probeDescriptor
                if (-not $process.Start()) {
                    throw "Could not start Personal ClientBootstrapper regression '$($probeCase.Name)'."
                }
                $stdoutTask = $process.StandardOutput.ReadToEndAsync()
                $stderrTask = $process.StandardError.ReadToEndAsync()
                if (-not $process.WaitForExit(30000)) {
                    $process.Kill($true)
                    if (-not $process.WaitForExit(5000)) {
                        throw 'Personal ClientBootstrapper process tree did not exit after termination.'
                    }
                    throw "Personal ClientBootstrapper regression '$($probeCase.Name)' blocked on interactive UI."
                }
                $process.WaitForExit()
                $stdout = $stdoutTask.GetAwaiter().GetResult()
                $stderr = $stderrTask.GetAwaiter().GetResult()
                if ($stdout.Length -gt 32768 -or $stderr.Length -gt 32768) {
                    throw "Personal ClientBootstrapper regression '$($probeCase.Name)' emitted unbounded output."
                }
                if ($process.ExitCode -ne 1) {
                    throw "Personal ClientBootstrapper regression '$($probeCase.Name)' returned the wrong exit code."
                }
                if (-not [string]::IsNullOrEmpty($stdout)) {
                    throw "Personal ClientBootstrapper regression '$($probeCase.Name)' emitted unexpected stdout."
                }
                if ($stderr.TrimEnd([char[]]@("`r", "`n")) -cne $expectedStderr) {
                    throw "Personal ClientBootstrapper regression '$($probeCase.Name)' emitted unexpected stderr."
                }
            }
            finally {
                $process.Dispose()
            }
        }
    }
    finally {
        foreach ($lease in $probeLeases) {
            $lease.Dispose()
        }
        $fullProbeRoot = [IO.Path]::GetFullPath($probeRoot)
        $tempPrefix = [IO.Path]::TrimEndingDirectorySeparator(
            [IO.Path]::GetFullPath([IO.Path]::GetTempPath())) +
            [IO.Path]::DirectorySeparatorChar +
            'ensou-personal-client-bootstrapper-failure-'
        if (-not $fullProbeRoot.StartsWith(
                $tempPrefix,
                [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Refusing to remove an unexpected Personal ClientBootstrapper regression directory.'
        }
        Remove-Item -LiteralPath $probeRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-PayloadSelfCheckWithoutSystemDotNet {
    param(
        [Parameter(Mandatory = $true)]$Descriptor,
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $true)][object[]]$Expected
    )

    $Executable = [string]$Descriptor.Path
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $Executable
    $start.ArgumentList.Add($Command)
    foreach ($value in $Expected) {
        $start.ArgumentList.Add([string]$value)
    }
    $start.WorkingDirectory = Split-Path -Parent $Executable
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.Environment['PATH'] = Join-Path $env:SystemRoot 'System32'
    $start.Environment['DOTNET_ROOT'] = Join-Path $env:TEMP 'ensou-personal-no-dotnet'
    $start.Environment['DOTNET_ROOT_X64'] = Join-Path $env:TEMP 'ensou-personal-no-dotnet-x64'
    $start.Environment['DOTNET_MULTILEVEL_LOOKUP'] = '0'
    Assert-ExactFileDescriptorUnchanged $Descriptor
    $process = [Diagnostics.Process]::Start($start)
    if (-not $process) {
        throw "Could not start Personal Installer payload self-check: $Executable"
    }
    try {
        if (-not $process.WaitForExit(300000)) {
            $process.Kill($true)
            throw "Personal Installer payload self-check timed out: $Executable"
        }
        if ($process.ExitCode -ne 0) {
            throw "Personal Installer payload self-check failed with exit $($process.ExitCode): $Executable"
        }
    } finally {
        $process.Dispose()
    }
}

function Assert-InvalidInstallerSelfCheckIsNonInteractive {
    param([Parameter(Mandatory = $true)]$Descriptor)

    $Executable = [string]$Descriptor.Path
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $Executable
    $start.ArgumentList.Add('--binary-self-check')
    $start.ArgumentList.Add('unexpected')
    $start.WorkingDirectory = Split-Path -Parent $Executable
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    Assert-ExactFileDescriptorUnchanged $Descriptor
    $process = [Diagnostics.Process]::Start($start)
    if (-not $process) {
        throw "Could not start negative Personal Installer self-check: $Executable"
    }
    try {
        if (-not $process.WaitForExit(10000)) {
            $process.Kill($true)
            throw 'Invalid Personal Installer self-check blocked on interactive UI.'
        }
        if ($process.ExitCode -eq 0) {
            throw 'Invalid Personal Installer self-check unexpectedly succeeded.'
        }
    } finally {
        $process.Dispose()
    }
}

function Open-ExactFileDescriptor {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [Collections.Generic.List[IDisposable]]$Leases,
        [scriptblock]$BeforeOpenObserver
    )

    $resolved = Resolve-OrdinaryFile $Path
    if ($null -ne $BeforeOpenObserver) {
        & $BeforeOpenObserver $resolved
    }
    $stream = [IO.File]::Open(
        $resolved,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    try {
        $identity = [EnsouPersonalGate.NativeFileIdentity]::RequireOrdinarySingleLink(
            $stream.SafeFileHandle)
        $postOpenPath = Resolve-OrdinaryFile $resolved
        $pathStream = [IO.File]::Open(
            $postOpenPath,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read)
        try {
            $pathIdentity = [EnsouPersonalGate.NativeFileIdentity]::RequireOrdinarySingleLink(
                $pathStream.SafeFileHandle)
            if ($pathIdentity.VolumeSerialNumber -ne $identity.VolumeSerialNumber -or
                $pathIdentity.FileIndex -ne $identity.FileIndex) {
                throw "Artifact path no longer names its locked descriptor: $resolved"
            }
        } finally {
            $pathStream.Dispose()
        }
        $sha256 = Get-StreamSha256 $stream
        $length = $stream.Length
        $stream.Position = 0
        $Leases.Add($stream)
        return [pscustomobject]@{
            Path = $resolved
            SizeBytes = $length
            Sha256 = $sha256
            Stream = $stream
            VolumeSerialNumber = $identity.VolumeSerialNumber
            FileIndex = $identity.FileIndex
        }
    } catch {
        $stream.Dispose()
        throw
    }
}

function Assert-ExactFileDescriptorUnchanged {
    param([Parameter(Mandatory = $true)]$Descriptor)

    $lockedIdentity =
        [EnsouPersonalGate.NativeFileIdentity]::RequireOrdinarySingleLink(
            $Descriptor.Stream.SafeFileHandle)
    if ($lockedIdentity.VolumeSerialNumber -ne $Descriptor.VolumeSerialNumber -or
        $lockedIdentity.FileIndex -ne $Descriptor.FileIndex) {
        throw "Locked artifact handle changed identity: $($Descriptor.Path)"
    }
    $resolved = Resolve-OrdinaryFile $Descriptor.Path
    $pathStream = [IO.File]::Open(
        $resolved,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    try {
        $pathIdentity =
            [EnsouPersonalGate.NativeFileIdentity]::RequireOrdinarySingleLink(
                $pathStream.SafeFileHandle)
        if ($pathIdentity.VolumeSerialNumber -ne $Descriptor.VolumeSerialNumber -or
            $pathIdentity.FileIndex -ne $Descriptor.FileIndex) {
            throw "Artifact path no longer names its locked descriptor: $resolved"
        }
    }
    finally {
        $pathStream.Dispose()
    }
    $Descriptor.Stream.Position = 0
    $actualSha256 = Get-StreamSha256 $Descriptor.Stream
    if ($Descriptor.Stream.Length -ne $Descriptor.SizeBytes -or
        $actualSha256 -cne $Descriptor.Sha256) {
        throw "Artifact changed through a pre-existing writable handle: $resolved"
    }
    $Descriptor.Stream.Position = 0
}

function Open-AdmittedDescriptorCopy {
    param(
        [Parameter(Mandatory = $true)]$SourceDescriptor,
        [Parameter(Mandatory = $true)][string]$Destination,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [Collections.Generic.List[IDisposable]]$Leases
    )

    Assert-ExactFileDescriptorUnchanged $SourceDescriptor
    Copy-Item -LiteralPath $SourceDescriptor.Path -Destination $Destination
    $copyDescriptor = Open-ExactFileDescriptor `
        -Path $Destination `
        -Leases $Leases
    if ($copyDescriptor.SizeBytes -ne $SourceDescriptor.SizeBytes -or
        $copyDescriptor.Sha256 -cne $SourceDescriptor.Sha256) {
        throw "Executable probe copy differs from its admitted locked bytes: $Destination"
    }
    return $copyDescriptor
}

function Assert-LockedReplacementRejected {
    param([Parameter(Mandatory = $true)]$Descriptor)

    $replacement = Join-Path `
        ([IO.Path]::GetTempPath()) `
        ("ensou-personal-lease-probe-{0}.tmp" -f [Guid]::NewGuid().ToString('N'))
    [IO.File]::WriteAllBytes(
        $replacement,
        [Text.Encoding]::UTF8.GetBytes('replacement-probe'))
    try {
        $blocked = $false
        try {
            [IO.File]::Move($replacement, $Descriptor.Path, $true)
        } catch [IO.IOException] {
            $blocked = $true
        } catch [UnauthorizedAccessException] {
            $blocked = $true
        }
        if (-not $blocked) {
            throw "Locked artifact replacement unexpectedly succeeded: $($Descriptor.Path)"
        }
        $Descriptor.Stream.Position = 0
        $after = Get-StreamSha256 $Descriptor.Stream
        if ($Descriptor.Stream.Length -ne $Descriptor.SizeBytes -or
            $after -cne $Descriptor.Sha256) {
            throw "Locked artifact identity changed during race probe: $($Descriptor.Path)"
        }
    } finally {
        if (Test-Path -LiteralPath $replacement -PathType Leaf) {
            Remove-Item -LiteralPath $replacement -Force
        }
    }
}

function Assert-UnsafeDescriptorNegatives {
    $root = Join-Path `
        ([IO.Path]::GetTempPath()) `
        ("ensou-personal-descriptor-negatives-{0}" -f [Guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($root) | Out-Null
    try {
        $source = Join-Path $root 'source.bin'
        $hardlink = Join-Path $root 'source-hardlink.bin'
        [IO.File]::WriteAllBytes($source, [Text.Encoding]::UTF8.GetBytes('hardlink-source'))
        if (-not [EnsouPersonalGate.NativeFileIdentity]::CreateHardLink(
                $hardlink,
                $source,
                [IntPtr]::Zero)) {
            throw "Could not create descriptor hardlink negative fixture: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
        }
        $leases = [Collections.Generic.List[IDisposable]]::new()
        try {
            $rejected = $false
            try {
                $null = Open-ExactFileDescriptor -Path $source -Leases $leases
            } catch [IO.InvalidDataException] {
                $rejected = $true
            }
            if (-not $rejected) {
                throw 'Pre-existing artifact hardlink was not rejected.'
            }
        } finally {
            foreach ($lease in $leases) {
                $lease.Dispose()
            }
        }

        [IO.File]::Delete($source)
        [IO.File]::Delete($hardlink)
        $victim = Join-Path $root 'victim.bin'
        $saved = Join-Path $root 'victim-saved.bin'
        $target = Join-Path $root 'race-target.bin'
        [IO.File]::WriteAllBytes($victim, [Text.Encoding]::UTF8.GetBytes('victim'))
        [IO.File]::WriteAllBytes($target, [Text.Encoding]::UTF8.GetBytes('race-target'))
        $raceLeases = [Collections.Generic.List[IDisposable]]::new()
        try {
            $raceRejected = $false
            try {
                $null = Open-ExactFileDescriptor `
                    -Path $victim `
                    -Leases $raceLeases `
                    -BeforeOpenObserver {
                        param($resolved)
                        [IO.File]::Move($resolved, $saved)
                        if (-not [EnsouPersonalGate.NativeFileIdentity]::CreateHardLink(
                                $resolved,
                                $target,
                                [IntPtr]::Zero)) {
                            throw "Could not create descriptor race fixture: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
                        }
                    }
            } catch [IO.InvalidDataException] {
                $raceRejected = $true
            }
            if (-not $raceRejected) {
                throw 'Artifact path-open hardlink race was not rejected.'
            }
        } finally {
            foreach ($lease in $raceLeases) {
                $lease.Dispose()
            }
        }
    } finally {
        if (Test-Path -LiteralPath $root -PathType Container) {
            $rootItem = Get-Item -LiteralPath $root -Force
            if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                -not $rootItem.FullName.StartsWith(
                    [IO.Path]::GetFullPath([IO.Path]::GetTempPath()),
                    [StringComparison]::OrdinalIgnoreCase)) {
                throw 'Descriptor negative fixture cleanup path is unsafe.'
            }
            [IO.Directory]::Delete($rootItem.FullName, $true)
        }
    }
}

function Read-LockedDescriptorBytes {
    param([Parameter(Mandatory = $true)]$Descriptor)

    if ($Descriptor.Stream.Length -ne $Descriptor.SizeBytes -or
        $Descriptor.SizeBytes -gt [int]::MaxValue) {
        throw "Locked executable has an unsupported or changed length: $($Descriptor.Path)"
    }
    [byte[]]$bytes = [byte[]]::new([int]$Descriptor.SizeBytes)
    $savedPosition = $Descriptor.Stream.Position
    try {
        $Descriptor.Stream.Position = 0
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $Descriptor.Stream.Read(
                $bytes,
                $offset,
                $bytes.Length - $offset)
            if ($read -le 0) {
                throw "Locked executable ended before its admitted length: $($Descriptor.Path)"
            }
            $offset += $read
        }
        if ($Descriptor.Stream.ReadByte() -ne -1) {
            throw "Locked executable grew after descriptor admission: $($Descriptor.Path)"
        }
        return ,$bytes
    }
    finally {
        $Descriptor.Stream.Position = $savedPosition
    }
}

function Assert-Authenticode {
    param([Parameter(Mandatory = $true)]$Descriptor)

    $signature = Microsoft.PowerShell.Security\Get-AuthenticodeSignature `
        -LiteralPath $Descriptor.Path
    $signer = if ($signature.SignerCertificate) {
        $signature.SignerCertificate.GetCertHashString(
            [Security.Cryptography.HashAlgorithmName]::SHA256).ToLowerInvariant()
    }
    else {
        $null
    }
    $timestamped = $null -ne $signature.TimeStamperCertificate

    if ($RequireAuthenticode) {
        if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
            -not $signature.SignerCertificate) {
            throw "Authenticode signature is not valid: $($Descriptor.Path) ($($signature.Status))"
        }
        if ([string]$signature.SignatureType -cne 'Authenticode') {
            throw "Executable must carry an embedded Authenticode signature, not a catalog signature: $($Descriptor.Path)"
        }
        if ($signer -cne $SignerSha256Thumbprint.ToLowerInvariant()) {
            throw "Authenticode signer mismatch: $($Descriptor.Path)"
        }
        if ($ProductionDistributionGate) {
            if (-not $signature.TimeStamperCertificate) {
                throw "Personal production executable has no trusted Authenticode timestamp: $($Descriptor.Path)"
            }
            [byte[]]$lockedBytes = Read-LockedDescriptorBytes $Descriptor
            $timestampAdmission = ProductionReleaseState\Assert-PeRfc3161Timestamp `
                -Bytes $lockedBytes `
                -SignerCertificate $signature.SignerCertificate `
                -TimeStamperCertificate $signature.TimeStamperCertificate
            if ([string]$timestampAdmission.TimestampProtocol -cne 'RFC3161') {
                throw "Personal production executable did not pass canonical RFC3161 admission: $($Descriptor.Path)"
            }
            $timestamped = $true
        }
    }

    return [pscustomobject]@{
        Status = [string]$signature.Status
        SignatureType = [string]$signature.SignatureType
        SignerSha256 = $signer
        Timestamped = $timestamped
    }
}

function Get-StreamSha256 {
    param([Parameter(Mandatory = $true)][IO.Stream]$Stream)

    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return [Convert]::ToHexString($sha.ComputeHash($Stream)).ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

$stub = Assert-ExactSingleExecutable `
    -Directory $StartupStubPublishDirectory `
    -ExecutableName 'Ensou.Dsh.Bootstrapper.exe'
$clientBootstrapper = Assert-ExactSingleExecutable `
    -Directory $ClientBootstrapperPublishDirectory `
    -ExecutableName 'Ensou.Dsh.ClientBootstrapper.exe'
$launcher = Assert-ExactSingleExecutable `
    -Directory $LauncherPublishDirectory `
    -ExecutableName 'Ensou.Dsh.Launcher.exe'
$maintenance = Assert-ExactSingleExecutable `
    -Directory $MaintenancePublishDirectory `
    -ExecutableName 'Ensou.Dsh.Personal.Maintenance.exe'

$installer = $null
$installerPayloadRoot = $null
if (-not [string]::IsNullOrWhiteSpace($InstallerPublishDirectory)) {
    $installer = Assert-ExactSingleExecutable `
        -Directory $InstallerPublishDirectory `
        -ExecutableName 'Ensou.Dsh.Personal.Installer.exe'
    $installerPayloadRoot = Resolve-OrdinaryDirectory $InstallerPayloadDirectory
    $expectedPayloadNames = @(
        'Ensou.Dsh.Bootstrapper.exe',
        'client-bundle.zip',
        'release-set.v2.json',
        'runtime.zip'
    )
    $payloadEntries = @(Get-ChildItem -LiteralPath $installerPayloadRoot -Force)
    $payloadNames = @($payloadEntries | ForEach-Object Name)
    if ($payloadEntries.Count -ne 4 -or
        @($payloadEntries | Where-Object {
            $_.PSIsContainer -or
            ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            $_.Length -le 0
        }).Count -ne 0 -or
        @(Compare-Object $expectedPayloadNames $payloadNames -CaseSensitive).Count -ne 0) {
        throw 'Personal Installer payload directory must contain exactly manifest, Startup Stub, client-bundle.zip, and runtime.zip.'
    }
}

$archivePath = [IO.Path]::GetFullPath($ClientBundleArchivePath)
$archiveItem = Get-Item -LiteralPath $archivePath -Force
if ($archiveItem.PSIsContainer -or
    ($archiveItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
    $archiveItem.Length -le 0) {
    throw "Personal client-bundle archive is missing, empty, or linked: $archivePath"
}

$artifactLeases = [Collections.Generic.List[IDisposable]]::new()
try {
$stubDescriptor = Open-ExactFileDescriptor -Path $stub -Leases $artifactLeases
$clientBootstrapperDescriptor = Open-ExactFileDescriptor `
    -Path $clientBootstrapper `
    -Leases $artifactLeases
$launcherDescriptor = Open-ExactFileDescriptor -Path $launcher -Leases $artifactLeases
$maintenanceDescriptor = Open-ExactFileDescriptor `
    -Path $maintenance `
    -Leases $artifactLeases
$clientArchiveDescriptor = Open-ExactFileDescriptor `
    -Path $archivePath `
    -Leases $artifactLeases
if ($ExerciseLockedReplacementRace) {
    Assert-UnsafeDescriptorNegatives
    foreach ($descriptor in @(
        $stubDescriptor,
        $clientBootstrapperDescriptor,
        $launcherDescriptor,
        $maintenanceDescriptor,
        $clientArchiveDescriptor
    )) {
        Assert-LockedReplacementRejected $descriptor
    }
}

Add-Type -AssemblyName System.IO.Compression
$requiredExecutables = [ordered]@{
    'Ensou.Dsh.ClientBootstrapper.exe' = $clientBootstrapperDescriptor
    'Ensou.Dsh.Launcher.exe' = $launcherDescriptor
    'Ensou.Dsh.Personal.Maintenance.exe' = $maintenanceDescriptor
}
$treeEntryName = '.ensou-complete-tree.v1.json'
$archive = [IO.Compression.ZipFile]::OpenRead($archivePath)
try {
    $entries = @($archive.Entries | Where-Object { -not $_.FullName.EndsWith('/') })
    $expectedEntryNames = @($requiredExecutables.Keys) + $treeEntryName
    $entryNames = @($entries | ForEach-Object FullName)
    if ($entries.Count -ne 4 -or
        @(Compare-Object $expectedEntryNames $entryNames -CaseSensitive).Count -ne 0 -or
        @($entryNames | Where-Object {
            $_ -match '[/\\:]' -or $_ -in @('.', '..')
        }).Count -ne 0) {
        throw 'Personal client-bundle ZIP must contain exactly the three client executables and one complete-tree manifest.'
    }

    $treeEntry = $entries | Where-Object FullName -CEQ $treeEntryName
    if ($treeEntry.Length -le 0 -or $treeEntry.Length -gt 16777216) {
        throw 'Personal client-bundle complete-tree manifest is empty or unbounded.'
    }
    $treeStream = $treeEntry.Open()
    try {
        $reader = [IO.StreamReader]::new(
            $treeStream,
            [Text.UTF8Encoding]::new($false, $true),
            $true,
            4096,
            $false)
        try {
            $tree = $reader.ReadToEnd() | ConvertFrom-Json
        } finally {
            $reader.Dispose()
        }
    } finally {
        $treeStream.Dispose()
    }
    if ($tree.schemaVersion -ne 1 -or
        $tree.component -cne 'client-bundle' -or
        $tree.releaseId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$') {
        throw 'Personal client-bundle complete-tree identity is invalid.'
    }
    $descriptors = @($tree.files)
    $descriptorNames = @($descriptors | ForEach-Object path)
    if ($descriptors.Count -ne 3 -or
        (@($descriptorNames | Sort-Object -CaseSensitive) -join "`n") -cne
            (@($requiredExecutables.Keys | Sort-Object -CaseSensitive) -join "`n")) {
        throw 'Personal client-bundle complete-tree must bind exactly the three client executables.'
    }
    foreach ($descriptor in $descriptors) {
        if ((@($descriptor.PSObject.Properties.Name | Sort-Object) -join ',') -cne
                'path,sha256,sizeBytes' -or
            $descriptor.sha256 -notmatch '^[0-9a-f]{64}$' -or
            $descriptor.sizeBytes -le 0) {
            throw "Personal complete-tree descriptor is invalid: $($descriptor.path)"
        }
        $entry = $entries | Where-Object FullName -CEQ $descriptor.path
        if ($entry.Length -ne $descriptor.sizeBytes) {
            throw "Personal client-bundle entry size mismatch: $($descriptor.path)"
        }
        $stream = $entry.Open()
        try {
            $archiveSha256 = Get-StreamSha256 $stream
        } finally {
            $stream.Dispose()
        }
        $published = $requiredExecutables[$descriptor.path]
        if ($archiveSha256 -cne $descriptor.sha256 -or
            $published.Sha256 -cne $descriptor.sha256 -or
            $published.SizeBytes -ne $descriptor.sizeBytes) {
            throw "Personal client-bundle hash mismatch: $($descriptor.path)"
        }
    }
} finally {
    $archive.Dispose()
}

$clientExecutableDescriptors = @(
    $stubDescriptor,
    $clientBootstrapperDescriptor,
    $launcherDescriptor,
    $maintenanceDescriptor
)
$clientAuthenticode = [ordered]@{}
$clientCompiledTrust = [ordered]@{}
$expectedCompiledTrust = $null
$installerDescriptor = $null
$installerTimestamped = $false
$installerCompiledTrust = $null
$productionEvidenceDescriptor = $null
if ($null -ne $installer) {
    $installerDescriptor = Open-ExactFileDescriptor `
        -Path $installer `
        -Leases $artifactLeases
    $installerAuthenticode = Assert-Authenticode $installerDescriptor
    $installerTimestamped = $installerAuthenticode.Timestamped
}
foreach ($descriptor in $clientExecutableDescriptors) {
    $executableName = [IO.Path]::GetFileName($descriptor.Path)
    $clientAuthenticode[$executableName] =
        Assert-Authenticode $descriptor
}
foreach ($descriptor in $clientExecutableDescriptors) {
    $fingerprint = Invoke-BinarySelfCheckWithoutSystemDotNet $descriptor
    Assert-BinarySelfCheckProtocolRequired $descriptor
    if ($null -eq $expectedCompiledTrust) {
        $expectedCompiledTrust = $fingerprint
    } elseif ($fingerprint.Raw -cne $expectedCompiledTrust.Raw) {
        throw "Personal client executables have different compiled release trust: $($descriptor.Path)"
    }
    $executableName = [IO.Path]::GetFileName($descriptor.Path)
    $clientCompiledTrust[$executableName] = $fingerprint
}
Assert-NonInteractiveStartupStubMachineFailure $stubDescriptor
Assert-NonInteractiveClientBootstrapperHealthFailure `
    $clientBootstrapperDescriptor
if ($null -ne $installer) {
    $payloadLeases = [Collections.Generic.List[IDisposable]]::new()
    try {
        $installerCompiledTrust = Invoke-BinarySelfCheckWithoutSystemDotNet `
            $installerDescriptor
        Assert-BinarySelfCheckProtocolRequired $installerDescriptor
        if ($installerCompiledTrust.Raw -cne $expectedCompiledTrust.Raw) {
            throw 'Personal Installer compiled release trust differs from its four client executables.'
        }
        Assert-InvalidInstallerSelfCheckIsNonInteractive $installerDescriptor

        $manifestDescriptor = Open-ExactFileDescriptor `
            -Path (Join-Path $installerPayloadRoot 'release-set.v2.json') `
            -Leases $payloadLeases
        $payloadStubDescriptor = Open-ExactFileDescriptor `
            -Path (Join-Path $installerPayloadRoot 'Ensou.Dsh.Bootstrapper.exe') `
            -Leases $payloadLeases
        $payloadClientDescriptor = Open-ExactFileDescriptor `
            -Path (Join-Path $installerPayloadRoot 'client-bundle.zip') `
            -Leases $payloadLeases
        $runtimeDescriptor = Open-ExactFileDescriptor `
            -Path (Join-Path $installerPayloadRoot 'runtime.zip') `
            -Leases $payloadLeases
        $publishedStubDescriptor = $stubDescriptor
        $publishedClientDescriptor = $clientArchiveDescriptor
        if ($payloadStubDescriptor.SizeBytes -ne $publishedStubDescriptor.SizeBytes -or
            $payloadStubDescriptor.Sha256 -cne $publishedStubDescriptor.Sha256) {
            throw 'Personal Installer embedded-payload Stub input differs from the independently validated Stub publish.'
        }
        if ($payloadClientDescriptor.SizeBytes -ne $publishedClientDescriptor.SizeBytes -or
            $payloadClientDescriptor.Sha256 -cne $publishedClientDescriptor.Sha256) {
            throw 'Personal Installer embedded client-bundle input differs from the independently validated client archive.'
        }

        $manifestReader = [IO.StreamReader]::new(
            $manifestDescriptor.Stream,
            [Text.UTF8Encoding]::new($false, $true),
            $true,
            4096,
            $true)
        try {
            $manifest = $manifestReader.ReadToEnd() | ConvertFrom-Json
        } finally {
            $manifestReader.Dispose()
        }
        if ($manifest.releaseSetId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$') {
            throw 'Personal Installer payload manifest has no valid releaseSetId.'
        }
        $selfCheckCommand = if ($ProductionDistributionGate) {
            '--production-payload-self-check'
        } else {
            '--development-payload-self-check'
        }
        Invoke-PayloadSelfCheckWithoutSystemDotNet `
            -Descriptor $installerDescriptor `
            -Command $selfCheckCommand `
            -Expected @(
                $manifest.releaseSetId,
                $manifestDescriptor.Sha256,
                $manifestDescriptor.SizeBytes,
                $payloadStubDescriptor.Sha256,
                $payloadStubDescriptor.SizeBytes,
                $payloadClientDescriptor.Sha256,
                $payloadClientDescriptor.SizeBytes,
                $runtimeDescriptor.Sha256,
                $runtimeDescriptor.SizeBytes)
        $installerDescriptor.Stream.Position = 0
        $installerSha256AfterSelfCheck = Get-StreamSha256 $installerDescriptor.Stream
        if ($installerDescriptor.Stream.Length -ne $installerDescriptor.SizeBytes -or
            $installerSha256AfterSelfCheck -cne $installerDescriptor.Sha256) {
            throw 'Personal Installer changed while its locked payload self-check snapshot was active.'
        }
        foreach ($descriptor in $clientExecutableDescriptors) {
            $descriptor.Stream.Position = 0
            $after = Get-StreamSha256 $descriptor.Stream
            if ($descriptor.Stream.Length -ne $descriptor.SizeBytes -or
                $after -cne $descriptor.Sha256) {
                throw "Personal client executable changed while its locked gate snapshot was active: $($descriptor.Path)"
            }
        }
        $clientArchiveDescriptor.Stream.Position = 0
        if ((Get-StreamSha256 $clientArchiveDescriptor.Stream) -cne
                $clientArchiveDescriptor.Sha256) {
            throw 'Personal client-bundle changed while its locked gate snapshot was active.'
        }

        if ($ProductionDistributionGate) {
            if (-not [IO.Path]::IsPathFullyQualified($ProductionGateEvidencePath)) {
                throw 'Personal production gate evidence path must be absolute.'
            }
            $evidencePath = [IO.Path]::GetFullPath($ProductionGateEvidencePath)
            $evidenceParent = Resolve-OrdinaryDirectory (Split-Path -Parent $evidencePath)
            if (Test-Path -LiteralPath $evidencePath) {
                throw 'Personal production gate evidence is create-only and already exists.'
            }
            foreach ($root in @(
                (Resolve-OrdinaryDirectory $InstallerPublishDirectory),
                $installerPayloadRoot,
                (Resolve-OrdinaryDirectory $StartupStubPublishDirectory),
                (Resolve-OrdinaryDirectory $ClientBootstrapperPublishDirectory),
                (Resolve-OrdinaryDirectory $LauncherPublishDirectory),
                (Resolve-OrdinaryDirectory $MaintenancePublishDirectory)
            )) {
                $prefix = $root.TrimEnd([IO.Path]::DirectorySeparatorChar) +
                    [IO.Path]::DirectorySeparatorChar
                if ($evidencePath.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
                    throw 'Personal production gate evidence must be outside all immutable publish and payload roots.'
                }
            }
            $clientEvidence = @()
            foreach ($descriptor in $clientExecutableDescriptors) {
                $name = [IO.Path]::GetFileName($descriptor.Path)
                $signature = $clientAuthenticode[$name]
                $clientEvidence += [ordered]@{
                    fileName = $name
                    sizeBytes = $descriptor.SizeBytes
                    sha256 = $descriptor.Sha256
                    authenticodeStatus = $signature.Status
                    signatureType = $signature.SignatureType
                    signerSha256Thumbprint = $signature.SignerSha256
                    timestamped = $signature.Timestamped
                    compiledTrustSha256 = $clientCompiledTrust[$name].Sha256
                }
            }
            $validatedAt = [DateTimeOffset]::UtcNow.ToString(
                'yyyy-MM-ddTHH:mm:ss.fffffffZ',
                [Globalization.CultureInfo]::InvariantCulture)
            $evidence = [ordered]@{
                schemaVersion = 1
                evidenceType = 'ensou-dsh-personal-production-artifact-gate'
                product = 'ensou-dsh-personal'
                releaseSetId = [string]$manifest.releaseSetId
                productionDistributionGate = $true
                compiledTrust = $expectedCompiledTrust.Value
                compiledTrustSha256 = $expectedCompiledTrust.Sha256
                installer = [ordered]@{
                    fileName = [IO.Path]::GetFileName($installerDescriptor.Path)
                    sizeBytes = $installerDescriptor.SizeBytes
                    sha256 = $installerDescriptor.Sha256
                    authenticodeStatus = $installerAuthenticode.Status
                    signatureType = $installerAuthenticode.SignatureType
                    signerSha256Thumbprint = $installerAuthenticode.SignerSha256
                    timestamped = $installerAuthenticode.Timestamped
                    compiledTrustSha256 = $installerCompiledTrust.Sha256
                }
                clientExecutables = $clientEvidence
                clientBundle = [ordered]@{
                    fileName = 'client-bundle.zip'
                    sizeBytes = $clientArchiveDescriptor.SizeBytes
                    sha256 = $clientArchiveDescriptor.Sha256
                }
                payload = [ordered]@{
                    manifest = [ordered]@{
                        fileName = 'release-set.v2.json'
                        sizeBytes = $manifestDescriptor.SizeBytes
                        sha256 = $manifestDescriptor.Sha256
                    }
                    startupStub = [ordered]@{
                        fileName = 'Ensou.Dsh.Bootstrapper.exe'
                        sizeBytes = $payloadStubDescriptor.SizeBytes
                        sha256 = $payloadStubDescriptor.Sha256
                    }
                    clientBundle = [ordered]@{
                        fileName = 'client-bundle.zip'
                        sizeBytes = $payloadClientDescriptor.SizeBytes
                        sha256 = $payloadClientDescriptor.Sha256
                    }
                    runtime = [ordered]@{
                        fileName = 'runtime.zip'
                        sizeBytes = $runtimeDescriptor.SizeBytes
                        sha256 = $runtimeDescriptor.Sha256
                    }
                }
                validatedAtUtc = $validatedAt
            }
            $evidenceBytes = [Text.Encoding]::UTF8.GetBytes(
                ($evidence | ConvertTo-Json -Depth 10 -Compress))
            $evidenceStream = [IO.File]::Open(
                $evidencePath,
                [IO.FileMode]::CreateNew,
                [IO.FileAccess]::ReadWrite,
                [IO.FileShare]::Read)
            try {
                $evidenceStream.Write($evidenceBytes)
                $evidenceStream.Flush($true)
                $evidenceIdentity = [EnsouPersonalGate.NativeFileIdentity]::RequireOrdinarySingleLink(
                    $evidenceStream.SafeFileHandle)
                $postCreatePath = Resolve-OrdinaryFile $evidencePath
                $postCreateStream = [IO.File]::Open(
                    $postCreatePath,
                    [IO.FileMode]::Open,
                    [IO.FileAccess]::Read,
                    [IO.FileShare]::Read)
                try {
                    $postCreateIdentity = [EnsouPersonalGate.NativeFileIdentity]::RequireOrdinarySingleLink(
                        $postCreateStream.SafeFileHandle)
                    if ($postCreateIdentity.VolumeSerialNumber -ne
                            $evidenceIdentity.VolumeSerialNumber -or
                        $postCreateIdentity.FileIndex -ne $evidenceIdentity.FileIndex) {
                        throw 'Production gate evidence path does not name its create-only handle.'
                    }
                } finally {
                    $postCreateStream.Dispose()
                }
                $evidenceStream.Position = 0
                $evidenceSha256 = Get-StreamSha256 $evidenceStream
                $evidenceSizeBytes = $evidenceStream.Length
                $evidenceStream.Position = 0
                $payloadLeases.Add($evidenceStream)
                $productionEvidenceDescriptor = [pscustomobject]@{
                    Path = $evidencePath
                    SizeBytes = $evidenceSizeBytes
                    Sha256 = $evidenceSha256
                    Stream = $evidenceStream
                    VolumeSerialNumber = $evidenceIdentity.VolumeSerialNumber
                    FileIndex = $evidenceIdentity.FileIndex
                }
                $evidenceStream = $null
            } finally {
                if ($null -ne $evidenceStream) {
                    $evidenceStream.Dispose()
                }
                [Security.Cryptography.CryptographicOperations]::ZeroMemory($evidenceBytes)
            }
        }
    } finally {
        foreach ($lease in $payloadLeases) {
            $lease.Dispose()
        }
    }
}

[pscustomobject]@{
    RuntimeIdentifier = 'win-x64'
    ExactSingleFilePublishes = $true
    SystemDotNetRequired = $false
    SystemPowerShellRequiredByClients = $false
    ClientBundleCompleteTree = $true
    ClientBundleExecutableCount = 3
    InstallerPresent = $null -ne $installer
    InstallerPayloadSelfCheck = $null -ne $installer
    InstallerSha256 = if ($null -eq $installerDescriptor) {
        $null
    } else {
        $installerDescriptor.Sha256
    }
    InstallerSizeBytes = if ($null -eq $installerDescriptor) {
        $null
    } else {
        $installerDescriptor.SizeBytes
    }
    InstallerTimestamped = $installerTimestamped
    ProductionGateEvidencePath = if ($null -eq $productionEvidenceDescriptor) {
        $null
    } else {
        $productionEvidenceDescriptor.Path
    }
    ProductionGateEvidenceSha256 = if ($null -eq $productionEvidenceDescriptor) {
        $null
    } else {
        $productionEvidenceDescriptor.Sha256
    }
    ProductionGateEvidenceSizeBytes = if ($null -eq $productionEvidenceDescriptor) {
        $null
    } else {
        $productionEvidenceDescriptor.SizeBytes
    }
    ProductionDistributionGate = [bool]$ProductionDistributionGate
    AuthenticodeRequired = [bool]$RequireAuthenticode
}
} finally {
    foreach ($lease in $artifactLeases) {
        $lease.Dispose()
    }
}
