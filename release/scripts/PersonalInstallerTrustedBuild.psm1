#requires -Version 7.2

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$stateModulePath = Join-Path $PSScriptRoot 'ProductionReleaseState.psm1'
$signingModulePath = Join-Path $PSScriptRoot 'InstallerSigningContracts.psm1'
$sdkModulePath = Join-Path $PSScriptRoot 'PortableDotNetSdkClosure.psm1'
Microsoft.PowerShell.Core\Import-Module $stateModulePath -Force -ErrorAction Stop
Microsoft.PowerShell.Core\Import-Module $signingModulePath -Force -ErrorAction Stop
Microsoft.PowerShell.Core\Import-Module $sdkModulePath -Force -ErrorAction Stop
# Keep the state module's qualified name available after both dependent imports.
Microsoft.PowerShell.Core\Import-Module $stateModulePath -Force -ErrorAction Stop

$script:DefaultRepositoryRoot =
    [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$script:RootProjectRelativePath =
    'src/Ensou.Dsh.Personal.Installer/Ensou.Dsh.Personal.Installer.csproj'
$script:PackageLockRelativePath =
    'installer/personal-publish-runtime-packs.lock.json'
$script:SdkLockRelativePath =
    'release/locks/dotnet-sdk-10.0.302-win-x64.files.lock.json'
$script:InstallerFileName = 'Ensou.Dsh.Personal.Installer.exe'
$script:ResourceVerificationMethod =
    'pe-metadata-embedded-resource-inspection-no-assembly-load-v1'
$script:AllowedPackageClosure = @(
    [pscustomobject]@{
        Kind = 'runtime-pack'
        Id = 'Microsoft.NETCore.App.Runtime.win-x64'
        Version = '10.0.10'
    },
    [pscustomobject]@{
        Kind = 'runtime-pack'
        Id = 'Microsoft.WindowsDesktop.App.Runtime.win-x64'
        Version = '10.0.10'
    },
    [pscustomobject]@{
        Kind = 'runtime-pack'
        Id = 'Microsoft.AspNetCore.App.Runtime.win-x64'
        Version = '10.0.10'
    },
    [pscustomobject]@{
        Kind = 'publish-tool'
        Id = 'Microsoft.NET.ILLink.Tasks'
        Version = '10.0.10'
    })
$script:AllowedEnvironmentOverrides =
    [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
foreach ($name in @(
        'DOTNET_CLI_HOME', 'DOTNET_CLI_TELEMETRY_OPTOUT',
        'DOTNET_CLI_USE_MSBUILD_SERVER', 'DOTNET_ROOT', 'DOTNET_ROOT_X64',
        'DOTNET_MULTILEVEL_LOOKUP', 'DOTNET_NOLOGO',
        'DOTNET_SKIP_FIRST_TIME_EXPERIENCE', 'NUGET_PACKAGES',
        'MSBUILDDISABLENODEREUSE', 'LOCALAPPDATA', 'APPDATA', 'USERPROFILE',
        'HOME', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY',
        'TEMP', 'TMP')) {
    [void]$script:AllowedEnvironmentOverrides.Add($name)
}

if ($null -eq ('EnsouLauncherPersonalBuild.DirectoryLease' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Concurrent;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace EnsouLauncherPersonalBuild
{
    public readonly struct DirectoryIdentity
    {
        public DirectoryIdentity(uint volume, ulong index)
        {
            VolumeSerialNumber = volume;
            FileIndex = index;
        }

        public uint VolumeSerialNumber { get; }
        public ulong FileIndex { get; }
    }

    public sealed class DirectoryLease : IDisposable
    {
        private const uint FileReadAttributes = 0x80;
        private const uint FileShareRead = 0x1;
        private const uint FileShareWrite = 0x2;
        private const uint OpenExisting = 3;
        private const uint FileFlagBackupSemantics = 0x02000000;
        private const uint FileFlagOpenReparsePoint = 0x00200000;
        private const uint DirectoryAttribute = 0x10;
        private const uint ReparsePointAttribute = 0x400;

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

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFileW(
            string fileName,
            uint desiredAccess,
            uint shareMode,
            IntPtr securityAttributes,
            uint creationDisposition,
            uint flagsAndAttributes,
            IntPtr templateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandle(
            SafeFileHandle handle,
            out ByHandleFileInformation information);

        private DirectoryLease(string path, SafeFileHandle handle, DirectoryIdentity identity)
        {
            Path = path;
            Handle = handle;
            Identity = identity;
        }

        public string Path { get; }
        public SafeFileHandle Handle { get; }
        public DirectoryIdentity Identity { get; }

        public static DirectoryLease Open(string path)
        {
            var fullPath = System.IO.Path.GetFullPath(path);
            var handle = CreateFileW(
                fullPath,
                FileReadAttributes,
                FileShareRead | FileShareWrite,
                IntPtr.Zero,
                OpenExisting,
                FileFlagBackupSemantics | FileFlagOpenReparsePoint,
                IntPtr.Zero);
            if (handle.IsInvalid)
            {
                var error = Marshal.GetLastWin32Error();
                handle.Dispose();
                throw new Win32Exception(error, "Could not lease Personal build directory.");
            }
            try
            {
                var identity = ReadIdentity(handle);
                return new DirectoryLease(fullPath, handle, identity);
            }
            catch
            {
                handle.Dispose();
                throw;
            }
        }

        public void AssertPathIdentity()
        {
            if (Handle == null || Handle.IsInvalid || Handle.IsClosed)
            {
                throw new InvalidDataException("Personal build directory lease is closed.");
            }
            using var current = CreateFileW(
                Path,
                FileReadAttributes,
                FileShareRead | FileShareWrite,
                IntPtr.Zero,
                OpenExisting,
                FileFlagBackupSemantics | FileFlagOpenReparsePoint,
                IntPtr.Zero);
            if (current.IsInvalid)
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "Could not reopen leased Personal build directory.");
            }
            var actual = ReadIdentity(current);
            if (actual.VolumeSerialNumber != Identity.VolumeSerialNumber ||
                actual.FileIndex != Identity.FileIndex)
            {
                throw new InvalidDataException(
                    "Personal build directory path no longer names its leased identity.");
            }
        }

        private static DirectoryIdentity ReadIdentity(SafeFileHandle handle)
        {
            if (!GetFileInformationByHandle(handle, out var information))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "Could not inspect Personal build directory identity.");
            }
            if ((information.FileAttributes & DirectoryAttribute) == 0 ||
                (information.FileAttributes & ReparsePointAttribute) != 0)
            {
                throw new InvalidDataException(
                    "Personal build directory lease requires one ordinary non-linked directory.");
            }
            var index = ((ulong)information.FileIndexHigh << 32) |
                information.FileIndexLow;
            return new DirectoryIdentity(information.VolumeSerialNumber, index);
        }

        public void Dispose()
        {
            Handle?.Dispose();
        }
    }

    public sealed class SourceMutationMonitor : IDisposable
    {
        private readonly FileSystemWatcher watcher;
        private readonly ConcurrentQueue<string> changes = new ConcurrentQueue<string>();
        private volatile bool overflowed;

        public SourceMutationMonitor(string path)
        {
            watcher = new FileSystemWatcher(System.IO.Path.GetFullPath(path));
            watcher.IncludeSubdirectories = true;
            watcher.InternalBufferSize = 64 * 1024;
            watcher.NotifyFilter = NotifyFilters.FileName |
                NotifyFilters.DirectoryName |
                NotifyFilters.LastWrite |
                NotifyFilters.Size |
                NotifyFilters.Attributes |
                NotifyFilters.Security;
            watcher.Changed += Record;
            watcher.Created += Record;
            watcher.Deleted += Record;
            watcher.Renamed += RecordRename;
            watcher.Error += RecordError;
            watcher.EnableRaisingEvents = true;
        }

        public bool Overflowed => overflowed;
        public string[] Changes => changes.ToArray();

        private void Record(object sender, FileSystemEventArgs args)
        {
            changes.Enqueue(args.ChangeType + ":" + args.FullPath);
        }

        private void RecordRename(object sender, RenamedEventArgs args)
        {
            changes.Enqueue("Renamed:" + args.OldFullPath + "->" + args.FullPath);
        }

        private void RecordError(object sender, ErrorEventArgs args)
        {
            overflowed = true;
            changes.Enqueue("WatcherError:" + args.GetException().GetType().FullName);
        }

        public void Dispose()
        {
            watcher.EnableRaisingEvents = false;
            watcher.Dispose();
        }
    }
}
'@
}
$script:PayloadDefinitions = @(
    [pscustomobject]@{
        Role = 'release-manifest'
        FileName = 'release-set.v2.json'
        LogicalName =
            'Ensou.Dsh.Personal.Installer.Payload.release-set.v2.json'
        MaximumBytes = 512KB
    },
    [pscustomobject]@{
        Role = 'startup-stub'
        FileName = 'Ensou.Dsh.Bootstrapper.exe'
        LogicalName =
            'Ensou.Dsh.Personal.Installer.Payload.Ensou.Dsh.Bootstrapper.exe'
        MaximumBytes = 1GB
    },
    [pscustomobject]@{
        Role = 'client-bundle'
        FileName = 'client-bundle.zip'
        LogicalName =
            'Ensou.Dsh.Personal.Installer.Payload.client-bundle.zip'
        MaximumBytes = 8GB
    },
    [pscustomobject]@{
        Role = 'runtime'
        FileName = 'runtime.zip'
        LogicalName =
            'Ensou.Dsh.Personal.Installer.Payload.runtime.zip'
        MaximumBytes = 8GB
    })

function Assert-PersonalTrustedBuildHost {
    if (-not $IsWindows -or
        $PSVersionTable.PSEdition -ne 'Core' -or
        $PSVersionTable.PSVersion -lt [version]'7.2' -or
        [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -ne
            [Runtime.InteropServices.Architecture]::X64) {
        throw 'Personal Installer trusted build requires native Windows x64 and PowerShell 7.2 or newer.'
    }
}

function Resolve-PersonalTrustedDirectory {
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
            throw "$Label path crosses a filesystem link: $fullPath"
        }
    }
    return $fullPath
}

function Test-PersonalTrustedSameOrDescendant {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Root
    )

    $fullPath = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $fullRoot = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    return $fullPath.Equals($fullRoot, [StringComparison]::OrdinalIgnoreCase) -or
        $fullPath.StartsWith($fullRoot + '\', [StringComparison]::OrdinalIgnoreCase)
}

function New-PersonalTrustedDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)

    [EnsouLauncherProduction.NativeDirectoryCreation]::CreateNew($Path)
    return Resolve-PersonalTrustedDirectory -Path $Path -Label 'Create-only directory'
}

function Open-PersonalTrustedDirectoryLease {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $fullPath = Resolve-PersonalTrustedDirectory -Path $Path -Label $Label
    return [EnsouLauncherPersonalBuild.DirectoryLease]::Open($fullPath)
}

function Open-PersonalTrustedSourceFileLease {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Record,
        [Parameter(Mandatory = $true)][string]$SnapshotRoot
    )

    $fullPath = [IO.Path]::GetFullPath($Path)
    if (-not (Test-PersonalTrustedSameOrDescendant `
            -Path $fullPath `
            -Root $SnapshotRoot)) {
        throw 'Personal source file path escapes its private snapshot.'
    }
    $item = Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Personal source lease requires an ordinary file: $fullPath"
    }
    $stream = [IO.File]::Open(
        $fullPath,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    try {
        $identity =
            [EnsouLauncherProduction.NativeFileIdentity]::RequireOrdinarySingleLink(
                $stream.SafeFileHandle)
        $sha256 = [Convert]::ToHexString(
            [Security.Cryptography.SHA256]::HashData($stream)).ToLowerInvariant()
        $stream.Position = 0
        if ([int64]$stream.Length -ne [int64]$Record.sizeBytes -or
            $sha256 -cne [string]$Record.sha256 -or
            (Get-PersonalTrustedGitBlobObjectId `
                -Path $fullPath `
                -ExpectedObjectId ([string]$Record.gitObjectId)) -cne
                [string]$Record.gitObjectId) {
            throw "Personal source file differs before its build lease: $($Record.relativePath)"
        }
        return [pscustomobject]@{
            Path = $fullPath
            RelativePath = [string]$Record.relativePath
            SizeBytes = [int64]$stream.Length
            Sha256 = $sha256
            GitObjectId = [string]$Record.gitObjectId
            Stream = $stream
            VolumeSerialNumber = $identity.VolumeSerialNumber
            FileIndex = $identity.FileIndex
        }
    }
    catch {
        $stream.Dispose()
        throw
    }
}

function Assert-PersonalTrustedSourceFileLease {
    param([Parameter(Mandatory = $true)]$Descriptor)

    if ($Descriptor.Stream.SafeFileHandle.IsClosed -or
        -not $Descriptor.Stream.CanRead) {
        throw "Personal source lease was closed during build: $($Descriptor.RelativePath)"
    }
    $pathStream = [IO.File]::Open(
        $Descriptor.Path,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    try {
        $identity =
            [EnsouLauncherProduction.NativeFileIdentity]::RequireOrdinarySingleLink(
                $pathStream.SafeFileHandle)
        $sha256 = [Convert]::ToHexString(
            [Security.Cryptography.SHA256]::HashData($pathStream)).ToLowerInvariant()
        if ($identity.VolumeSerialNumber -ne $Descriptor.VolumeSerialNumber -or
            $identity.FileIndex -ne $Descriptor.FileIndex -or
            [int64]$pathStream.Length -ne [int64]$Descriptor.SizeBytes -or
            $sha256 -cne [string]$Descriptor.Sha256) {
            throw "Personal source lease changed during build: $($Descriptor.RelativePath)"
        }
    }
    finally {
        $pathStream.Dispose()
    }
}

function Open-PersonalTrustedSourceGuard {
    param(
        [Parameter(Mandatory = $true)][string]$SnapshotRoot,
        [Parameter(Mandatory = $true)]$Source,
        [Parameter(Mandatory = $true)][string]$WorkRoot
    )

    $directoryLeases = [Collections.Generic.List[object]]::new()
    $fileLeases = [Collections.Generic.List[object]]::new()
    $monitor = $null
    try {
        $workLease = Open-PersonalTrustedDirectoryLease `
            -Path $WorkRoot `
            -Label 'Personal private build work root'
        $directoryLeases.Add($workLease)
        $directories = @(
            Get-ChildItem -LiteralPath $SnapshotRoot -Directory -Recurse -Force |
                Sort-Object FullName -CaseSensitive)
        foreach ($directory in @((Get-Item -LiteralPath $SnapshotRoot -Force)) +
                $directories) {
            $directoryLeases.Add((Open-PersonalTrustedDirectoryLease `
                    -Path $directory.FullName `
                    -Label 'Personal private source snapshot directory'))
        }
        foreach ($record in @($Source.Files)) {
            $path = Join-Path `
                $SnapshotRoot `
                ([string]$record.relativePath).Replace('/', '\')
            $fileLeases.Add((Open-PersonalTrustedSourceFileLease `
                    -Path $path `
                    -Record $record `
                    -SnapshotRoot $SnapshotRoot))
        }
        $monitor =
            [EnsouLauncherPersonalBuild.SourceMutationMonitor]::new($SnapshotRoot)
        return [pscustomobject]@{
            SnapshotRoot = $SnapshotRoot
            Source = $Source
            DirectoryLeases = $directoryLeases
            FileLeases = $fileLeases
            Monitor = $monitor
        }
    }
    catch {
        if ($null -ne $monitor) { $monitor.Dispose() }
        foreach ($lease in @($fileLeases)) { $lease.Stream.Dispose() }
        foreach ($lease in @($directoryLeases)) { $lease.Dispose() }
        throw
    }
}

function Assert-PersonalTrustedSourceGuardUnchanged {
    param([Parameter(Mandatory = $true)]$Guard)

    foreach ($lease in @($Guard.FileLeases)) {
        Assert-PersonalTrustedSourceFileLease -Descriptor $lease
    }
    foreach ($lease in @($Guard.DirectoryLeases)) {
        $lease.AssertPathIdentity()
    }
    Assert-PersonalTrustedSourceSnapshotUnchanged `
        -SnapshotRoot ([string]$Guard.SnapshotRoot) `
        -Source $Guard.Source
    [Threading.Thread]::Sleep(100)
    $changes = @($Guard.Monitor.Changes)
    if ($Guard.Monitor.Overflowed -or $changes.Count -ne 0) {
        $sample = if ($changes.Count -eq 0) {
            'watcher-overflow'
        }
        else {
            ($changes | Select-Object -First 3) -join '; '
        }
        throw "Personal source snapshot was mutated during build: $sample"
    }
}

function Close-PersonalTrustedSourceGuard {
    param([AllowNull()]$Guard)

    if ($null -eq $Guard) { return }
    if ($null -ne $Guard.Monitor) { $Guard.Monitor.Dispose() }
    foreach ($lease in @($Guard.FileLeases)) {
        if ($null -ne $lease.Stream) { $lease.Stream.Dispose() }
    }
    foreach ($lease in @($Guard.DirectoryLeases)) {
        $lease.Dispose()
    }
}

function Get-PersonalTrustedUtcNow {
    return [DateTimeOffset]::UtcNow.ToString(
        'yyyy-MM-ddTHH:mm:ssZ',
        [Globalization.CultureInfo]::InvariantCulture)
}

function Get-PersonalTrustedFileSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)

    $stream = [IO.FileStream]::new(
        $Path, [IO.FileMode]::Open, [IO.FileAccess]::Read,
        [IO.FileShare]::Read, 1MB, [IO.FileOptions]::SequentialScan)
    try {
        return [Convert]::ToHexString(
            [Security.Cryptography.SHA256]::HashData($stream)).ToLowerInvariant()
    }
    finally {
        $stream.Dispose()
    }
}

function Get-PersonalTrustedGitBlobObjectId {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedObjectId
    )

    $algorithm = if ($ExpectedObjectId.Length -eq 40) {
        [Security.Cryptography.HashAlgorithmName]::SHA1
    }
    elseif ($ExpectedObjectId.Length -eq 64) {
        [Security.Cryptography.HashAlgorithmName]::SHA256
    }
    else {
        throw 'Personal trusted Git object ID uses an unsupported hash length.'
    }
    $file = [IO.FileStream]::new(
        $Path, [IO.FileMode]::Open, [IO.FileAccess]::Read,
        [IO.FileShare]::Read, 1MB, [IO.FileOptions]::SequentialScan)
    $hash = [Security.Cryptography.IncrementalHash]::CreateHash($algorithm)
    try {
        $header = [Text.Encoding]::ASCII.GetBytes("blob $($file.Length)`0")
        $hash.AppendData($header)
        [byte[]]$buffer = [byte[]]::new(1MB)
        try {
            while (($read = $file.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $hash.AppendData($buffer, 0, $read)
            }
        }
        finally {
            [Array]::Clear($buffer, 0, $buffer.Length)
        }
        return [Convert]::ToHexString($hash.GetHashAndReset()).ToLowerInvariant()
    }
    finally {
        $hash.Dispose()
        $file.Dispose()
    }
}

function Get-PersonalTrustedStreamSha512Base64 {
    param([Parameter(Mandatory = $true)]$Descriptor)

    $Descriptor.Stream.Position = 0
    try {
        return [Convert]::ToBase64String(
            [Security.Cryptography.SHA512]::HashData($Descriptor.Stream))
    }
    finally {
        $Descriptor.Stream.Position = 0
    }
}

function Copy-PersonalTrustedInput {
    param(
        [Parameter(Mandatory = $true)]$Descriptor,
        [Parameter(Mandatory = $true)][string]$DestinationPath,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $parent = [IO.Path]::GetDirectoryName($DestinationPath)
    if (-not [IO.Directory]::Exists($parent)) {
        [IO.Directory]::CreateDirectory($parent) | Out-Null
    }
    $output = [IO.FileStream]::new(
        $DestinationPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write,
        [IO.FileShare]::None, 1MB, [IO.FileOptions]::WriteThrough)
    try {
        $Descriptor.Stream.Position = 0
        $Descriptor.Stream.CopyTo($output)
        $output.Flush($true)
        $Descriptor.Stream.Position = 0
    }
    finally {
        $output.Dispose()
    }
    if ((Get-Item -LiteralPath $DestinationPath -Force).Length -ne
            [int64]$Descriptor.SizeBytes -or
        (Get-PersonalTrustedFileSha256 -Path $DestinationPath) -cne
            [string]$Descriptor.Sha256) {
        throw "$Label copy differs from its locked input."
    }
}

function Invoke-PersonalTrustedProcess {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [hashtable]$Environment = @{},
        [int]$TimeoutMilliseconds = 600000
    )

    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = [IO.Path]::GetFullPath($FilePath)
    $start.WorkingDirectory = [IO.Path]::GetFullPath($WorkingDirectory)
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.WindowStyle = [Diagnostics.ProcessWindowStyle]::Hidden
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.StandardOutputEncoding = [Text.UTF8Encoding]::new($false, $true)
    $start.StandardErrorEncoding = [Text.UTF8Encoding]::new($false, $true)
    $start.Environment.Clear()
    $windowsDirectory = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::Windows)
    $systemDirectory = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::System)
    if ([string]::IsNullOrWhiteSpace($windowsDirectory) -or
        [string]::IsNullOrWhiteSpace($systemDirectory)) {
        throw 'Personal trusted build could not resolve Windows system directories.'
    }
    $executableDirectory = [IO.Path]::GetDirectoryName($start.FileName)
    foreach ($entry in ([ordered]@{
            SystemRoot = $windowsDirectory
            WINDIR = $windowsDirectory
            ComSpec = Join-Path $systemDirectory 'cmd.exe'
            OS = 'Windows_NT'
            PATHEXT = '.COM;.EXE;.BAT;.CMD'
            PATH = $executableDirectory + ';' + $systemDirectory + ';' +
                $windowsDirectory
        }).GetEnumerator()) {
        $start.Environment[[string]$entry.Key] = [string]$entry.Value
    }
    foreach ($folder in @(
            [pscustomobject]@{ Name = 'ProgramFiles'; Value =
                [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles) },
            [pscustomobject]@{ Name = 'ProgramFiles(x86)'; Value =
                [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFilesX86) },
            [pscustomobject]@{ Name = 'ProgramData'; Value =
                [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData) })) {
        if (-not [string]::IsNullOrWhiteSpace([string]$folder.Value)) {
            $start.Environment[[string]$folder.Name] = [string]$folder.Value
        }
    }
    foreach ($argument in $Arguments) {
        [void]$start.ArgumentList.Add($argument)
    }
    foreach ($name in $Environment.Keys) {
        if (-not $script:AllowedEnvironmentOverrides.Contains([string]$name)) {
            throw "Personal trusted process environment override is not allowed: $name"
        }
        $start.Environment[[string]$name] = [string]$Environment[$name]
    }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    try {
        if (-not $process.Start()) {
            throw "Personal trusted build could not start $FilePath."
        }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutMilliseconds)) {
            $process.Kill($true)
            [void]$process.WaitForExit(5000)
            throw "Personal trusted build process timed out: $FilePath"
        }
        $process.WaitForExit()
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        if ($stdout.Length -gt 4MB -or $stderr.Length -gt 4MB) {
            throw "Personal trusted build process output is unbounded: $FilePath"
        }
        if ($process.ExitCode -ne 0) {
            throw "Personal trusted build process failed with exit code $($process.ExitCode): $FilePath`nSTDOUT: $stdout`nSTDERR: $stderr"
        }
        return [pscustomobject]@{
            ExitCode = [int]$process.ExitCode
            Stdout = $stdout
            Stderr = $stderr
        }
    }
    finally {
        $process.Dispose()
    }
}

function Invoke-PersonalTrustedGit {
    param(
        [Parameter(Mandatory = $true)][string]$GitPath,
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    $safeDirectory = $RepositoryRoot.Replace('\', '/')
    return Invoke-PersonalTrustedProcess `
        -FilePath $GitPath `
        -Arguments (@(
                '-c', "safe.directory=$safeDirectory", '-C', $RepositoryRoot) +
            $Arguments) `
        -WorkingDirectory $RepositoryRoot `
        -TimeoutMilliseconds 120000
}

function Assert-PersonalTrustedContext {
    param(
        [Parameter(Mandatory = $true)]$Context,
        [Parameter(Mandatory = $true)]$CompiledTrust,
        [Parameter(Mandatory = $true)]$ResponseTrust
    )

    ProductionReleaseState\Assert-ExactProductionJsonMembers `
        -Value $Context `
        -Expected @(
            'orchestrationId', 'channel', 'expectedReleaseSetId', 'planSha256',
            'baseHeadSha256', 'maximumResponseAgeMinutes') `
        -Label 'Personal trusted-build context'
    ProductionReleaseState\Assert-ExactProductionJsonMembers `
        -Value $CompiledTrust `
        -Expected @(
            'manifestOrigin', 'artifactOrigin', 'releaseKeyId', 'releaseKeyX',
            'releaseKeyY', 'startupStubVersion', 'canonicalLowSFromSequence',
            'authenticodeSignerSha256Thumbprint') `
        -Label 'Personal compiled trust'
    ProductionReleaseState\Assert-ExactProductionJsonMembers `
        -Value $ResponseTrust `
        -Expected @('algorithm', 'purpose', 'keyId', 'x', 'y') `
        -Label 'Personal Installer response trust'
    if ([string]$Context.orchestrationId -cnotmatch
            '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' -or
        [string]$Context.channel -cne 'pilot' -or
        [string]$Context.expectedReleaseSetId -cnotmatch
            '^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$' -or
        [string]$Context.planSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$Context.baseHeadSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [int]$Context.maximumResponseAgeMinutes -lt 1 -or
        [int]$Context.maximumResponseAgeMinutes -gt 1440) {
        throw 'Personal trusted-build context is not canonical.'
    }
    foreach ($originName in @('manifestOrigin', 'artifactOrigin')) {
        $origin = $null
        $value = [string]$CompiledTrust.$originName
        if (-not [Uri]::TryCreate($value, [UriKind]::Absolute, [ref]$origin) -or
            $origin.Scheme -cne 'https' -or $origin.AbsoluteUri -cne $value -or
            -not $origin.AbsolutePath.EndsWith('/', [StringComparison]::Ordinal) -or
            -not [string]::IsNullOrEmpty($origin.UserInfo) -or
            -not [string]::IsNullOrEmpty($origin.Query) -or
            -not [string]::IsNullOrEmpty($origin.Fragment) -or $origin.IsLoopback) {
            throw "Personal compiled $originName must be a canonical production HTTPS origin."
        }
    }
    if ([string]$CompiledTrust.releaseKeyId -cnotmatch
            '^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$' -or
        [string]$CompiledTrust.startupStubVersion -cnotmatch
            '^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$' -or
        [int64]$CompiledTrust.canonicalLowSFromSequence -lt 1 -or
        [int64]$CompiledTrust.canonicalLowSFromSequence -gt 9007199254740991 -or
        [string]$CompiledTrust.authenticodeSignerSha256Thumbprint -cnotmatch
            '^[0-9a-f]{64}$') {
        throw 'Personal compiled trust contains a noncanonical value.'
    }
    if ([string]$ResponseTrust.algorithm -cne 'ES256' -or
        [string]$ResponseTrust.purpose -cne
            'personal-installer-signing-response' -or
        [string]$ResponseTrust.keyId -cnotmatch
            '^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$') {
        throw 'Personal Installer response trust domain is invalid.'
    }
    foreach ($trustPoint in @(
            [pscustomobject]@{ Label = 'Personal release key'; X =
                [string]$CompiledTrust.releaseKeyX; Y = [string]$CompiledTrust.releaseKeyY },
            [pscustomobject]@{ Label = 'Personal Installer response key'; X =
                [string]$ResponseTrust.x; Y = [string]$ResponseTrust.y })) {
        if ($trustPoint.X -cnotmatch '^[A-Za-z0-9_-]{43}$' -or
            $trustPoint.Y -cnotmatch '^[A-Za-z0-9_-]{43}$') {
            throw "$($trustPoint.Label) is not a canonical P-256 public point."
        }
        $paddingX = $trustPoint.X.Replace('-', '+').Replace('_', '/') + '='
        $paddingY = $trustPoint.Y.Replace('-', '+').Replace('_', '/') + '='
        try {
            $x = [Convert]::FromBase64String($paddingX)
            $y = [Convert]::FromBase64String($paddingY)
            if ($x.Length -ne 32 -or $y.Length -ne 32) {
                throw 'wrong point length'
            }
            $ecdsa = [Security.Cryptography.ECDsa]::Create(
                [Security.Cryptography.ECParameters]@{
                    Curve =
                        [Security.Cryptography.ECCurve+NamedCurves]::nistP256
                    Q = [Security.Cryptography.ECPoint]@{ X = $x; Y = $y }
                })
            $ecdsa.Dispose()
        }
        catch {
            throw "$($trustPoint.Label) is not a valid P-256 public point."
        }
    }
}

function New-PersonalTrustedSourceSnapshot {
    param(
        [Parameter(Mandatory = $true)][string]$GitPath,
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [Parameter(Mandatory = $true)][string]$SnapshotRoot,
        [Parameter(Mandatory = $true)][string]$WorkRoot
    )

    $status = Invoke-PersonalTrustedGit `
        -GitPath $GitPath `
        -RepositoryRoot $RepositoryRoot `
        -Arguments @('status', '--porcelain=v1', '--untracked-files=all')
    if (-not [string]::IsNullOrEmpty($status.Stdout)) {
        throw 'Personal trusted build requires a clean tracked and untracked Git checkout.'
    }
    $commit = (Invoke-PersonalTrustedGit `
            -GitPath $GitPath `
            -RepositoryRoot $RepositoryRoot `
            -Arguments @('rev-parse', '--verify', 'HEAD^{commit}')).Stdout.Trim()
    $tree = (Invoke-PersonalTrustedGit `
            -GitPath $GitPath `
            -RepositoryRoot $RepositoryRoot `
            -Arguments @('rev-parse', '--verify', 'HEAD^{tree}')).Stdout.Trim()
    if ($commit -cnotmatch '^(?:[0-9a-f]{40}|[0-9a-f]{64})$' -or
        $tree -cnotmatch '^(?:[0-9a-f]{40}|[0-9a-f]{64})$') {
        throw 'Personal trusted build could not resolve one canonical Git HEAD.'
    }
    $treeText = (Invoke-PersonalTrustedGit `
            -GitPath $GitPath `
            -RepositoryRoot $RepositoryRoot `
            -Arguments @('-c', 'core.quotepath=false', 'ls-tree', '-r',
                '--full-tree', $commit)).Stdout
    $expected = [ordered]@{}
    foreach ($line in @($treeText -split "`n" | Where-Object { $_ })) {
        $line = $line.TrimEnd("`r")
        if ($line -cnotmatch
            '^(?<mode>[0-9]{6}) (?<type>blob) (?<oid>[0-9a-f]{40,64})\t(?<path>.+)$') {
            throw 'Personal trusted build encountered a noncanonical Git tree entry.'
        }
        $relative = [string]$Matches.path
        $mode = [string]$Matches.mode
        $objectId = [string]$Matches.oid
        if ($mode -notin @('100644', '100755') -or
            $relative -cnotmatch
                '^(?![.]{1,2}(?:/|$))(?!.*[/][.]{1,2}(?:/|$))[A-Za-z0-9._+-]+(?:/[A-Za-z0-9._+-]+)*$' -or
            $expected.Contains($relative)) {
            throw "Personal trusted build rejects linked, special, or noncanonical Git path '$relative'."
        }
        $expected[$relative] = $objectId
    }
    if ($expected.Count -le 0 -or $expected.Count -gt 4096) {
        throw 'Personal trusted build Git source inventory is empty or unbounded.'
    }
    foreach ($required in @(
            'global.json', 'Directory.Build.props',
            $script:RootProjectRelativePath,
            'src/Ensou.Dsh.Personal.Installer/packages.lock.json',
            'src/Ensou.Dsh.UpdateEngine/Ensou.Dsh.UpdateEngine.csproj',
            'src/Ensou.Dsh.UpdateEngine/packages.lock.json',
            'src/Ensou.Dsh.Contracts/Ensou.Dsh.Contracts.csproj',
            'src/Ensou.Dsh.Contracts/packages.lock.json',
            $script:PackageLockRelativePath,
            $script:SdkLockRelativePath)) {
        if (-not $expected.Contains($required)) {
            throw "Personal trusted source HEAD omits required tracked input '$required'."
        }
    }

    $archivePath = Join-Path $WorkRoot 'source-head.zip'
    [void](Invoke-PersonalTrustedGit `
            -GitPath $GitPath `
            -RepositoryRoot $RepositoryRoot `
            -Arguments @('archive', '--format=zip', "--output=$archivePath", $commit))
    $archiveInput = ProductionReleaseState\Open-ProductionReleaseInput `
        -Path $archivePath `
        -Label 'Personal trusted Git HEAD archive' `
        -MaximumBytes 2GB
    try {
        New-PersonalTrustedDirectory -Path $SnapshotRoot | Out-Null
        $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        $records = [Collections.Generic.List[object]]::new()
        [int64]$totalSizeBytes = 0
        $zip = [IO.Compression.ZipArchive]::new(
            $archiveInput.Stream,
            [IO.Compression.ZipArchiveMode]::Read,
            $true)
        try {
            if ($zip.Entries.Count -lt $expected.Count -or
                $zip.Entries.Count -gt ($expected.Count * 3)) {
                throw 'Personal trusted Git archive entry count is invalid.'
            }
            foreach ($entry in $zip.Entries) {
                $relative = $entry.FullName
                if ($relative.EndsWith('/', [StringComparison]::Ordinal)) {
                    continue
                }
                if (-not $expected.Contains($relative) -or -not $seen.Add($relative) -or
                    $entry.Length -lt 0 -or $entry.Length -gt 1GB -or
                    $entry.CompressedLength -lt 0) {
                    throw "Personal trusted Git archive contains unexpected entry '$relative'."
                }
                $destination = Join-Path $SnapshotRoot $relative.Replace('/', '\')
                $parent = [IO.Path]::GetDirectoryName($destination)
                if (-not [IO.Directory]::Exists($parent)) {
                    [IO.Directory]::CreateDirectory($parent) | Out-Null
                }
                $input = $entry.Open()
                $output = [IO.FileStream]::new(
                    $destination, [IO.FileMode]::CreateNew,
                    [IO.FileAccess]::Write, [IO.FileShare]::None,
                    1MB, [IO.FileOptions]::WriteThrough)
                try {
                    $input.CopyTo($output)
                    $output.Flush($true)
                }
                finally {
                    $output.Dispose()
                    $input.Dispose()
                }
                $size = [int64](Get-Item -LiteralPath $destination -Force).Length
                if ($size -ne [int64]$entry.Length) {
                    throw "Personal trusted Git archive extraction changed '$relative'."
                }
                if ((Get-PersonalTrustedGitBlobObjectId `
                        -Path $destination `
                        -ExpectedObjectId ([string]$expected[$relative])) -cne
                    [string]$expected[$relative]) {
                    throw "Personal trusted Git archive bytes differ from HEAD blob '$relative'."
                }
                $totalSizeBytes += $size
                if ($totalSizeBytes -gt 4GB) {
                    throw 'Personal trusted source snapshot exceeds its total byte bound.'
                }
                $records.Add([ordered]@{
                        relativePath = $relative
                        gitObjectId = [string]$expected[$relative]
                        sizeBytes = $size
                        sha256 = Get-PersonalTrustedFileSha256 -Path $destination
                    })
            }
        }
        finally {
            $zip.Dispose()
        }
        if ($seen.Count -ne $expected.Count) {
            throw 'Personal trusted Git archive does not contain the exact HEAD file closure.'
        }
        $records = @($records | Sort-Object { [string]$_.relativePath } -CaseSensitive)
        $inventorySha256 =
            InstallerSigningContracts\Get-InstallerSigningObjectSha256 `
                -Value $records
        return [pscustomobject]@{
            Commit = $commit
            Tree = $tree
            FileCount = $records.Count
            TotalSizeBytes = $totalSizeBytes
            InventorySha256 = $inventorySha256
            Files = $records
        }
    }
    finally {
        $archiveInput.Stream.Dispose()
    }
}

function Assert-PersonalTrustedSourceSnapshotUnchanged {
    param(
        [Parameter(Mandatory = $true)][string]$SnapshotRoot,
        [Parameter(Mandatory = $true)]$Source
    )

    $actualFiles = @(Get-ChildItem -LiteralPath $SnapshotRoot -File -Recurse -Force)
    if ($actualFiles.Count -ne @($Source.Files).Count) {
        throw 'Personal trusted source snapshot file closure changed during build.'
    }
    $actualRelativePaths = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
    foreach ($actual in $actualFiles) {
        $relative = [IO.Path]::GetRelativePath($SnapshotRoot, $actual.FullName).
            Replace('\', '/')
        if (-not $actualRelativePaths.Add($relative)) {
            throw "Personal trusted source snapshot repeats '$relative'."
        }
    }
    foreach ($record in @($Source.Files)) {
        if (-not $actualRelativePaths.Contains([string]$record.relativePath)) {
            throw "Personal trusted source snapshot omits: $($record.relativePath)"
        }
        $path = Join-Path $SnapshotRoot ([string]$record.relativePath).Replace('/', '\')
        $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
        if ($item.PSIsContainer -or
            ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            [int64]$item.Length -ne [int64]$record.sizeBytes -or
            (Get-PersonalTrustedFileSha256 -Path $path) -cne
                [string]$record.sha256) {
            throw "Personal trusted source snapshot changed during build: $($record.relativePath)"
        }
    }
}

function Assert-PersonalTrustedPackageLockContract {
    param([Parameter(Mandatory = $true)]$Lock)

    ProductionReleaseState\Assert-ExactProductionJsonMembers `
        -Value $Lock `
        -Expected @(
            'schemaVersion', 'dotnetSdkVersion', 'runtimeIdentifier',
            'selfContained', 'source', 'packages') `
        -Label 'Personal runtime-pack lock'
    if ([int]$Lock.schemaVersion -ne 1 -or
        [string]$Lock.dotnetSdkVersion -cne '10.0.302' -or
        [string]$Lock.runtimeIdentifier -cne 'win-x64' -or
        -not [bool]$Lock.selfContained -or
        [string]$Lock.source -cne 'https://api.nuget.org/v3/index.json' -or
        @($Lock.packages).Count -ne $script:AllowedPackageClosure.Count) {
        throw 'Personal runtime-pack lock is not the exact production contract.'
    }
    for ($index = 0; $index -lt $script:AllowedPackageClosure.Count; $index++) {
        $package = @($Lock.packages)[$index]
        $allowed = $script:AllowedPackageClosure[$index]
        ProductionReleaseState\Assert-ExactProductionJsonMembers `
            -Value $package `
            -Expected @('kind', 'id', 'version', 'bytes', 'sha512') `
            -Label 'Personal runtime-pack lock package'
        if ([string]$package.kind -cne [string]$allowed.Kind -or
            [string]$package.id -cne [string]$allowed.Id -or
            [string]$package.version -cne [string]$allowed.Version -or
            [string]$package.id -cnotmatch '^[A-Za-z0-9]+(?:[.][A-Za-z0-9-]+)+$' -or
            [string]$package.version -cnotmatch '^[0-9]+[.][0-9]+[.][0-9]+$' -or
            [int64]$package.bytes -le 0 -or
            [int64]$package.bytes -gt 512MB -or
            [string]$package.sha512 -cnotmatch
                '^[A-Za-z0-9+/]{86}==$') {
            throw "Personal runtime-pack lock entry $index is not its fixed kind/id/version/byte contract."
        }
        try {
            $sha512 = [Convert]::FromBase64String([string]$package.sha512)
            if ($sha512.Length -ne 64) { throw 'wrong SHA-512 length' }
        }
        catch {
            throw "Personal runtime-pack lock entry $index has invalid SHA-512."
        }
    }
    return $true
}

function Get-PersonalTrustedPackageClosure {
    param(
        [Parameter(Mandatory = $true)][string]$PackageDirectory,
        [Parameter(Mandatory = $true)][string]$PackageLockPath,
        [Parameter(Mandatory = $true)][string]$SnapshotRoot
    )

    $packageRoot = Resolve-PersonalTrustedDirectory `
        -Path $PackageDirectory `
        -Label 'Personal offline package directory'
    $lockInput = ProductionReleaseState\Read-StrictProductionJsonFile `
        -Path $PackageLockPath `
        -Label 'Personal runtime-pack lock'
    $lock = $lockInput.Value
    [void](Assert-PersonalTrustedPackageLockContract -Lock $lock)
    $entries = @(Get-ChildItem -LiteralPath $packageRoot -Force)
    if ($entries.Count -ne 4 -or @($entries | Where-Object {
                $_.PSIsContainer -or
                ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                -not $_.Name.EndsWith('.nupkg', [StringComparison]::OrdinalIgnoreCase)
            }).Count -ne 0) {
        throw 'Personal offline package directory must contain only four locked nupkg files.'
    }
    $expectedFileNames = @($script:AllowedPackageClosure | ForEach-Object {
            "$(([string]$_.Id).ToLowerInvariant()).$($_.Version).nupkg"
        })
    foreach ($entry in $entries) {
        if (@($expectedFileNames | Where-Object {
                    $_ -ceq [string]$entry.Name
                }).Count -ne 1 -or
            -not (Test-PersonalTrustedSameOrDescendant `
                -Path $entry.FullName `
                -Root $packageRoot)) {
            throw "Personal offline package directory contains a non-allowlisted path: $($entry.Name)"
        }
    }
    New-PersonalTrustedDirectory -Path $SnapshotRoot | Out-Null
    $packages = [Collections.Generic.List[object]]::new()
    $locks = [Collections.Generic.List[object]]::new()
    try {
        foreach ($package in @($lock.packages)) {
            $fileName = "$(([string]$package.id).ToLowerInvariant()).$($package.version).nupkg"
            $packagePath = [IO.Path]::GetFullPath((Join-Path $packageRoot $fileName))
            if (-not (Test-PersonalTrustedSameOrDescendant `
                    -Path $packagePath `
                    -Root $packageRoot) -or
                -not ([IO.Path]::GetFileName($packagePath)).Equals(
                    $fileName,
                    [StringComparison]::Ordinal)) {
                throw "Personal offline package path escapes its fixed closure: $fileName"
            }
            $input = ProductionReleaseState\Open-ProductionReleaseInput `
                -Path $packagePath `
                -Label "Personal offline package '$fileName'" `
                -MaximumBytes 512MB
            try {
                if ([int64]$input.SizeBytes -ne [int64]$package.bytes -or
                    (Get-PersonalTrustedStreamSha512Base64 -Descriptor $input) -cne
                        [string]$package.sha512) {
                    throw "Personal offline package differs from its lock: $fileName"
                }
                $snapshotPath = [IO.Path]::GetFullPath(
                    (Join-Path $SnapshotRoot $fileName))
                if (-not (Test-PersonalTrustedSameOrDescendant `
                        -Path $snapshotPath `
                        -Root $SnapshotRoot)) {
                    throw "Personal offline snapshot path escapes its private feed: $fileName"
                }
                Copy-PersonalTrustedInput `
                    -Descriptor $input `
                    -DestinationPath $snapshotPath `
                    -Label "Personal offline package '$fileName'"
            }
            finally {
                $input.Stream.Dispose()
            }
            $snapshotInput = ProductionReleaseState\Open-ProductionReleaseInput `
                -Path $snapshotPath `
                -Label "Personal locked offline package '$fileName'" `
                -MaximumBytes 512MB
            $locks.Add($snapshotInput)
            $packages.Add([ordered]@{
                    kind = [string]$package.kind
                    id = [string]$package.id
                    version = [string]$package.version
                    fileName = $fileName
                    sizeBytes = [int64]$snapshotInput.SizeBytes
                    sha256 = [string]$snapshotInput.Sha256
                    sha512 = [string]$package.sha512
                })
        }
    }
    catch {
        foreach ($locked in @($locks)) {
            $locked.Stream.Dispose()
        }
        throw
    }
    return [pscustomobject]@{
        LockSha256 = [string]$lockInput.Sha256
        Packages = @($packages)
        Locks = $locks
        InventorySha256 =
            InstallerSigningContracts\Get-InstallerSigningObjectSha256 `
                -Value @($packages)
    }
}

function Get-PersonalTrustedPayloadClosure {
    param(
        [Parameter(Mandatory = $true)][string]$PayloadDirectory,
        [Parameter(Mandatory = $true)][string]$OutputPayloadRoot,
        [Parameter(Mandatory = $true)]$Context,
        [Parameter(Mandatory = $true)]$CompiledTrust,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [Collections.Generic.List[object]]$LockedOutputs
    )

    $payloadRoot = Resolve-PersonalTrustedDirectory `
        -Path $PayloadDirectory `
        -Label 'Personal production Installer payload'
    $entries = @(Get-ChildItem -LiteralPath $payloadRoot -Force)
    if ($entries.Count -ne 4) {
        throw 'Personal production Installer payload must contain exactly four files.'
    }
    $expectedNames = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
    foreach ($definition in $script:PayloadDefinitions) {
        [void]$expectedNames.Add([string]$definition.FileName)
    }
    foreach ($entry in $entries) {
        if ($entry.PSIsContainer -or
            ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            -not $expectedNames.Contains([string]$entry.Name)) {
            throw "Personal production payload contains unexpected or linked entry '$($entry.Name)'."
        }
    }
    New-PersonalTrustedDirectory -Path $OutputPayloadRoot | Out-Null
    $files = [Collections.Generic.List[object]]::new()
    foreach ($definition in $script:PayloadDefinitions) {
        $input = ProductionReleaseState\Open-ProductionReleaseInput `
            -Path (Join-Path $payloadRoot $definition.FileName) `
            -Label "Personal payload '$($definition.Role)'" `
            -MaximumBytes ([int64]$definition.MaximumBytes)
        $destination = Join-Path $OutputPayloadRoot $definition.FileName
        try {
            Copy-PersonalTrustedInput `
                -Descriptor $input `
                -DestinationPath $destination `
                -Label "Personal payload '$($definition.Role)'"
        }
        finally {
            $input.Stream.Dispose()
        }
        $locked = ProductionReleaseState\Open-ProductionReleaseInput `
            -Path $destination `
            -Label "Personal trusted-build payload '$($definition.Role)'" `
            -MaximumBytes ([int64]$definition.MaximumBytes)
        Add-Member -InputObject $locked -NotePropertyName Role `
            -NotePropertyValue ([string]$definition.Role)
        $LockedOutputs.Add($locked)
        $files.Add([ordered]@{
                role = [string]$definition.Role
                fileName = [string]$definition.FileName
                relativePath = 'payload/' + [string]$definition.FileName
                sizeBytes = [int64]$locked.SizeBytes
                sha256 = [string]$locked.Sha256
                embeddedLogicalName = [string]$definition.LogicalName
            })
    }

    $manifestPath = Join-Path $OutputPayloadRoot 'release-set.v2.json'
    $manifestInput = ProductionReleaseState\Read-StrictProductionJsonFile `
        -Path $manifestPath `
        -Label 'Personal signed payload manifest'
    [void](ProductionReleaseState\Assert-CanonicalProductionJsonInput `
            -JsonInput $manifestInput `
            -Label 'Personal signed payload manifest')
    $manifest = $manifestInput.Value
    ProductionReleaseState\Assert-ExactProductionJsonMembers `
        -Value $manifest `
        -Expected @(
            'schemaVersion', 'product', 'environment', 'channel', 'releaseSetId',
            'provenance', 'generation', 'sequence', 'minAcceptedSequence',
            'issuedAtUtc', 'expiresAtUtc', 'maximumOfflineGraceSeconds',
            'startupStub', 'revokedReleaseSetIds', 'artifacts', 'signature') `
        -Label 'Personal signed payload manifest'
    if ([int]$manifest.schemaVersion -ne 2 -or
        [string]$manifest.product -cne 'ensou-dsh-personal' -or
        [string]$manifest.environment -cne 'production' -or
        [string]$manifest.channel -cne [string]$Context.channel -or
        [string]$manifest.releaseSetId -cne
            [string]$Context.expectedReleaseSetId -or
        [int64]$manifest.generation -lt 1 -or
        [int64]$manifest.generation -gt 9007199254740991 -or
        [int64]$manifest.sequence -lt 1 -or
        [int64]$manifest.sequence -gt 9007199254740991 -or
        [int64]$manifest.minAcceptedSequence -lt 0 -or
        [int64]$manifest.minAcceptedSequence -gt [int64]$manifest.sequence -or
        [int64]$manifest.maximumOfflineGraceSeconds -lt 3600 -or
        [int64]$manifest.maximumOfflineGraceSeconds -gt 1209600 -or
        @($manifest.artifacts).Count -ne 2) {
        throw 'Personal signed payload manifest identity or bounds are invalid.'
    }
    ProductionReleaseState\Assert-ExactProductionJsonMembers `
        -Value $manifest.provenance `
        -Expected @(
            'launcherRepositoryCommit', 'harnessSourceTag',
            'harnessSourceCommit') `
        -Label 'Personal signed payload provenance'
    ProductionReleaseState\Assert-ExactProductionJsonMembers `
        -Value $manifest.startupStub `
        -Expected @('minimumVersion', 'maximumVersion') `
        -Label 'Personal signed payload Startup Stub range'
    foreach ($value in @(
            [string]$manifest.provenance.launcherRepositoryCommit,
            [string]$manifest.provenance.harnessSourceCommit)) {
        if ($value -cnotmatch '^(?:[0-9a-f]{40}|[0-9a-f]{64})$') {
            throw 'Personal signed payload provenance commit is invalid.'
        }
    }
    if ([string]$manifest.provenance.harnessSourceTag -cnotmatch
            '^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$' -or
        [string]::IsNullOrWhiteSpace([string]$manifest.startupStub.minimumVersion) -or
        [string]::IsNullOrWhiteSpace([string]$manifest.startupStub.maximumVersion)) {
        throw 'Personal signed payload provenance or Startup Stub range is invalid.'
    }
    foreach ($time in @('issuedAtUtc', 'expiresAtUtc')) {
        [DateTimeOffset]$parsed = [DateTimeOffset]::MinValue
        if (-not [DateTimeOffset]::TryParseExact(
                [string]$manifest.$time,
                'yyyy-MM-ddTHH:mm:ss.fffffffZ',
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::AssumeUniversal,
                [ref]$parsed) -or $parsed.Offset -ne [TimeSpan]::Zero) {
            throw "Personal signed payload $time is not canonical UTC."
        }
    }
    if ([DateTimeOffset]::Parse([string]$manifest.expiresAtUtc) -le
        [DateTimeOffset]::Parse([string]$manifest.issuedAtUtc)) {
        throw 'Personal signed payload manifest expiry does not follow issuance.'
    }
    ProductionReleaseState\Assert-ExactProductionJsonMembers `
        -Value $manifest.signature `
        -Expected @('algorithm', 'keyId', 'value') `
        -Label 'Personal signed payload manifest signature'
    if ([string]$manifest.signature.algorithm -cne 'ES256' -or
        [string]$manifest.signature.keyId -cne
            [string]$CompiledTrust.releaseKeyId -or
        [string]$manifest.signature.value -cnotmatch '^[A-Za-z0-9_-]{86}$') {
        throw 'Personal signed payload manifest signature envelope is invalid.'
    }
    $artifactByComponent = @{}
    foreach ($artifact in @($manifest.artifacts)) {
        ProductionReleaseState\Assert-ExactProductionJsonMembers `
            -Value $artifact `
            -Expected @(
                'component', 'releaseId', 'uri', 'sizeBytes', 'sha256',
                'completeTreeSha256', 'signature') `
            -Label 'Personal signed payload artifact'
        ProductionReleaseState\Assert-ExactProductionJsonMembers `
            -Value $artifact.signature `
            -Expected @('algorithm', 'keyId', 'value') `
            -Label 'Personal signed payload artifact signature'
        $component = [string]$artifact.component
        if ($component -notin @('client-bundle', 'runtime') -or
            $artifactByComponent.ContainsKey($component) -or
            [string]$artifact.releaseId -cnotmatch
                '^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$' -or
            [string]$artifact.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [string]$artifact.completeTreeSha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [string]$artifact.signature.algorithm -cne 'ES256' -or
            [string]$artifact.signature.keyId -cne
                [string]$CompiledTrust.releaseKeyId -or
            [string]$artifact.signature.value -cnotmatch '^[A-Za-z0-9_-]{86}$') {
            throw 'Personal signed payload artifact descriptor is invalid.'
        }
        $uri = $null
        if (-not [Uri]::TryCreate(
                [string]$artifact.uri, [UriKind]::Absolute, [ref]$uri) -or
            $uri.Scheme -cne 'https' -or
            -not $uri.AbsoluteUri.StartsWith(
                [string]$CompiledTrust.artifactOrigin,
                [StringComparison]::Ordinal)) {
            throw 'Personal signed payload artifact URI escapes compiled trust.'
        }
        $artifactByComponent[$component] = $artifact
    }
    foreach ($binding in @(
            [pscustomobject]@{ Component = 'client-bundle'; FileIndex = 2 },
            [pscustomobject]@{ Component = 'runtime'; FileIndex = 3 })) {
        $artifact = $artifactByComponent[[string]$binding.Component]
        $file = $files[[int]$binding.FileIndex]
        if ([int64]$artifact.sizeBytes -ne [int64]$file.sizeBytes -or
            [string]$artifact.sha256 -cne [string]$file.sha256) {
            throw "Personal signed manifest differs from payload $($binding.Component) bytes."
        }
    }
    $publicIdentity = [ordered]@{
        algorithm = 'ES256'
        keyId = [string]$CompiledTrust.releaseKeyId
        x = [string]$CompiledTrust.releaseKeyX
        y = [string]$CompiledTrust.releaseKeyY
    }
    return [pscustomobject]@{
        Files = @($files)
        InventorySha256 =
            InstallerSigningContracts\Get-InstallerSigningObjectSha256 `
                -Value @($files | ForEach-Object {
                        [ordered]@{
                            role = $_.role
                            fileName = $_.fileName
                            relativePath = $_.relativePath
                            sizeBytes = $_.sizeBytes
                            sha256 = $_.sha256
                        }
                    })
        ReleaseKeyIdentitySha256 =
            InstallerSigningContracts\Get-InstallerSigningObjectSha256 `
                -Value $publicIdentity
    }
}

function Get-PersonalTrustedResourceBinding {
    param(
        [Parameter(Mandatory = $true)][string]$ManagedAssemblyPath,
        [Parameter(Mandatory = $true)][object[]]$PayloadFiles,
        [Parameter(Mandatory = $true)][string]$UnsignedInstallerSha256
    )

    $assemblyInput = ProductionReleaseState\Open-ProductionReleaseInput `
        -Path $ManagedAssemblyPath `
        -Label 'Personal managed Installer resource carrier' `
        -MaximumBytes 1GB
    $peReader = $null
    try {
        $peReader = [Reflection.PortableExecutable.PEReader]::new(
            $assemblyInput.Stream,
            [Reflection.PortableExecutable.PEStreamOptions]::LeaveOpen)
        if (-not $peReader.HasMetadata -or
            $null -eq $peReader.PEHeaders.CorHeader -or
            $peReader.PEHeaders.CorHeader.ResourcesDirectory.Size -le 0) {
            throw 'Personal managed Installer is not one metadata-bearing PE with embedded resources.'
        }
        $metadataReader =
            [Reflection.Metadata.PEReaderExtensions]::GetMetadataReader(
                $peReader)
        $resourcesByName = [Collections.Generic.Dictionary[string, object]]::new(
            [StringComparer]::Ordinal)
        foreach ($handle in $metadataReader.ManifestResources) {
            $manifestResource = $metadataReader.GetManifestResource($handle)
            $name = $metadataReader.GetString($manifestResource.Name)
            if (-not $manifestResource.Implementation.IsNil -or
                [string]::IsNullOrWhiteSpace($name) -or
                -not $resourcesByName.TryAdd($name, $manifestResource)) {
                throw 'Personal managed Installer contains an external, unnamed, or duplicate manifest resource.'
            }
        }
        if ($resourcesByName.Count -ne $PayloadFiles.Count) {
            throw 'Personal managed Installer manifest resource set is not the exact payload closure.'
        }
        $resourceDirectory = $peReader.PEHeaders.CorHeader.ResourcesDirectory
        [int64]$resourceBaseOffset = -1
        foreach ($section in $peReader.PEHeaders.SectionHeaders) {
            [int64]$sectionStart = [int64]$section.VirtualAddress
            [int64]$sectionSpan = [Math]::Max(
                [int64]$section.VirtualSize,
                [int64]$section.SizeOfRawData)
            [int64]$resourceRva =
                [int64]$resourceDirectory.RelativeVirtualAddress
            if ($resourceRva -ge $sectionStart -and
                $resourceRva -lt ($sectionStart + $sectionSpan)) {
                [int64]$delta = $resourceRva - $sectionStart
                if ($delta -ge [int64]$section.SizeOfRawData) {
                    throw 'Personal managed resource directory is outside PE raw section bytes.'
                }
                $resourceBaseOffset = [int64]$section.PointerToRawData + $delta
                break
            }
        }
        if ($resourceBaseOffset -lt 0 -or
            $resourceBaseOffset + [int64]$resourceDirectory.Size -gt
                [int64]$assemblyInput.SizeBytes) {
            throw 'Personal managed resource directory escapes the held PE file.'
        }
        $resources = [Collections.Generic.List[object]]::new()
        foreach ($payload in $PayloadFiles) {
            $logicalName = [string]$payload.embeddedLogicalName
            if (-not $resourcesByName.ContainsKey($logicalName)) {
                throw "Personal Installer managed assembly omits '$logicalName'."
            }
            $manifestResource = $resourcesByName[$logicalName]
            [int64]$resourceOffset = [int64]$manifestResource.Offset
            if ($resourceOffset -lt 0 -or
                $resourceOffset + 4 -gt [int64]$resourceDirectory.Size) {
                throw "Personal Installer resource offset is invalid: $logicalName"
            }
            $assemblyInput.Stream.Position = $resourceBaseOffset + $resourceOffset
            [byte[]]$lengthBytes = [byte[]]::new(4)
            try {
                $assemblyInput.Stream.ReadExactly($lengthBytes)
                [uint64]$resourceLength =
                    [uint64]$lengthBytes[0] -bor
                    ([uint64]$lengthBytes[1] -shl 8) -bor
                    ([uint64]$lengthBytes[2] -shl 16) -bor
                    ([uint64]$lengthBytes[3] -shl 24)
                if ($resourceLength -ne [uint64]$payload.sizeBytes -or
                    $resourceLength -gt 1GB -or
                    $resourceOffset + 4 + [int64]$resourceLength -gt
                        [int64]$resourceDirectory.Size -or
                    $assemblyInput.Stream.Position + [int64]$resourceLength -gt
                        [int64]$assemblyInput.SizeBytes) {
                    throw "Personal Installer resource length is invalid: $logicalName"
                }
                $hash = [Security.Cryptography.IncrementalHash]::CreateHash(
                    [Security.Cryptography.HashAlgorithmName]::SHA256)
                [byte[]]$buffer = [byte[]]::new(1MB)
                try {
                    [int64]$remaining = [int64]$resourceLength
                    while ($remaining -gt 0) {
                        $requested = [int][Math]::Min(
                            [int64]$buffer.Length,
                            $remaining)
                        $read = $assemblyInput.Stream.Read(
                            $buffer,
                            0,
                            $requested)
                        if ($read -le 0) {
                            throw "Personal Installer resource ended early: $logicalName"
                        }
                        $hash.AppendData($buffer, 0, $read)
                        $remaining -= $read
                    }
                    $sha256 = [Convert]::ToHexString(
                        $hash.GetHashAndReset()).ToLowerInvariant()
                }
                finally {
                    [Array]::Clear($buffer, 0, $buffer.Length)
                    $hash.Dispose()
                }
                if ($sha256 -cne [string]$payload.sha256) {
                    throw "Personal Installer resource differs from '$logicalName'."
                }
                $resources.Add([ordered]@{
                        role = [string]$payload.role
                        logicalName = $logicalName
                        sizeBytes = [int64]$resourceLength
                        sha256 = $sha256
                        status = 'VERIFIED'
                    })
            }
            finally {
                [Array]::Clear($lengthBytes, 0, $lengthBytes.Length)
            }
        }
        [void](ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
                -Descriptor $assemblyInput `
                -Label 'Personal managed Installer resource carrier')
        return [ordered]@{
            verificationMethod = $script:ResourceVerificationMethod
            status = 'VERIFIED'
            resourceSetSha256 =
                InstallerSigningContracts\Get-InstallerSigningObjectSha256 `
                    -Value @($resources)
            resources = @($resources)
            unsignedInstallerSha256 = $UnsignedInstallerSha256
        }
    }
    finally {
        if ($null -ne $peReader) { $peReader.Dispose() }
        $assemblyInput.Stream.Dispose()
    }
}

function New-PersonalInstallerTrustedBuild {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Context,
        [Parameter(Mandatory = $true)]$CompiledTrust,
        [Parameter(Mandatory = $true)]$InstallerSigningResponseTrust,
        [Parameter(Mandatory = $true)][string]$PayloadDirectory,
        [Parameter(Mandatory = $true)][string]$PackageDirectory,
        [Parameter(Mandatory = $true)][string]$DotNetSdkArchivePath,
        [Parameter(Mandatory = $true)][string]$OutputDirectory,
        [string]$RepositoryRoot = $script:DefaultRepositoryRoot,
        [string]$GitPath = ''
    )

    Assert-PersonalTrustedBuildHost
    Assert-PersonalTrustedContext `
        -Context $Context `
        -CompiledTrust $CompiledTrust `
        -ResponseTrust $InstallerSigningResponseTrust
    $repository = Resolve-PersonalTrustedDirectory `
        -Path $RepositoryRoot `
        -Label 'Personal trusted-build source repository'
    $payloadSource = Resolve-PersonalTrustedDirectory `
        -Path $PayloadDirectory `
        -Label 'Personal production payload source'
    $packageSource = Resolve-PersonalTrustedDirectory `
        -Path $PackageDirectory `
        -Label 'Personal offline package source'
    if ([string]::IsNullOrWhiteSpace($GitPath)) {
        $programFiles = [Environment]::GetFolderPath(
            [Environment+SpecialFolder]::ProgramFiles)
        $GitPath = Join-Path $programFiles 'Git\cmd\git.exe'
    }
    $expectedGitPath = [IO.Path]::GetFullPath((Join-Path `
            ([Environment]::GetFolderPath(
                [Environment+SpecialFolder]::ProgramFiles)) `
            'Git\cmd\git.exe'))
    $gitExecutable = ProductionReleaseState\Resolve-OrdinaryProductionFile `
        -Path $GitPath `
        -Label 'Personal trusted-build Git executable'
    if (-not $gitExecutable.Equals(
            $expectedGitPath,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Personal trusted build requires native Git from Program Files.'
    }
    $sdkArchive = ProductionReleaseState\Resolve-OrdinaryProductionFile `
        -Path $DotNetSdkArchivePath `
        -Label 'Personal portable .NET SDK archive'
    if ([IO.Path]::GetFileName($sdkArchive) -cne
        'dotnet-sdk-10.0.302-win-x64.zip') {
        throw 'Personal portable .NET SDK archive has a noncanonical file name.'
    }
    if (-not [IO.Path]::IsPathFullyQualified($OutputDirectory) -or
        $OutputDirectory.StartsWith('\\', [StringComparison]::Ordinal) -or
        $OutputDirectory.StartsWith('//', [StringComparison]::Ordinal)) {
        throw 'Personal trusted-build output must be an absolute local path.'
    }
    $outputRoot = [IO.Path]::GetFullPath($OutputDirectory)
    if (Test-Path -LiteralPath $outputRoot) {
        throw 'Personal trusted-build output must be a nonexistent create-only directory.'
    }
    $outputParent = Resolve-PersonalTrustedDirectory `
        -Path ([IO.Path]::GetDirectoryName($outputRoot)) `
        -Label 'Personal trusted-build output parent'
    foreach ($inputPath in @(
            $repository, $payloadSource, $packageSource, $sdkArchive)) {
        if ((Test-PersonalTrustedSameOrDescendant -Path $outputRoot -Root $inputPath) -or
            (Test-PersonalTrustedSameOrDescendant -Path $inputPath -Root $outputRoot)) {
            throw 'Personal trusted-build output may not overlap any source input.'
        }
    }

    $lockedOutputs = [Collections.Generic.List[object]]::new()
    $packageLocks = @()
    $sdkSourceClosure = $null
    $sdkPrivateClosure = $null
    $sourceGuard = $null
    $buildPropsInput = $null
    $createdOutput = $false
    try {
        New-PersonalTrustedDirectory -Path $outputRoot | Out-Null
        $createdOutput = $true
        $workRoot = Join-Path $outputRoot 'work'
        $sourceSnapshotRoot = Join-Path $workRoot 'repo'
        $sdkExtractionRoot = Join-Path $workRoot 'sdk-extracted'
        $sdkPrivateRoot = Join-Path $workRoot 'sdk-private'
        $offlineFeedRoot = Join-Path $workRoot 'offline-feed'
        $publishRoot = Join-Path $workRoot 'publish'
        $intermediateRoot = Join-Path $workRoot 'obj'
        $managedOutputRoot = Join-Path $workRoot 'bin'
        $buildGuardRoot = Join-Path $workRoot 'build-guard'
        $nugetPackagesRoot = Join-Path $workRoot 'nuget-packages'
        $cliHome = Join-Path $workRoot 'dotnet-home'
        $userProfile = Join-Path $workRoot 'user-profile'
        $localAppData = Join-Path $userProfile 'AppData\Local'
        $roamingAppData = Join-Path $userProfile 'AppData\Roaming'
        $processTemp = Join-Path $workRoot 'temp'
        New-PersonalTrustedDirectory -Path $workRoot | Out-Null
        foreach ($path in @(
                $publishRoot, $intermediateRoot, $managedOutputRoot,
                $buildGuardRoot,
                $nugetPackagesRoot, $cliHome, $userProfile,
                $localAppData, $roamingAppData, $processTemp)) {
            [IO.Directory]::CreateDirectory($path) | Out-Null
        }
        $source = New-PersonalTrustedSourceSnapshot `
            -GitPath $gitExecutable `
            -RepositoryRoot $repository `
            -SnapshotRoot $sourceSnapshotRoot `
            -WorkRoot $workRoot
        $trackedPropsPath = Join-Path $sourceSnapshotRoot 'Directory.Build.props'
        $guardPropsPath = Join-Path $buildGuardRoot 'Directory.Build.props'
        $guardProps = @(
            '<Project>'
            ('  <Import Project="' +
                [Security.SecurityElement]::Escape($trackedPropsPath) + '" />')
            '  <PropertyGroup>'
            ('    <BaseIntermediateOutputPath>' +
                [Security.SecurityElement]::Escape(
                    $intermediateRoot.TrimEnd('\') + '\$(MSBuildProjectName)\') +
                '</BaseIntermediateOutputPath>')
            '    <MSBuildProjectExtensionsPath>$(BaseIntermediateOutputPath)</MSBuildProjectExtensionsPath>'
            ('    <BaseOutputPath>' +
                [Security.SecurityElement]::Escape(
                    $managedOutputRoot.TrimEnd('\') + '\$(MSBuildProjectName)\') +
                '</BaseOutputPath>')
            '  </PropertyGroup>'
            '</Project>'
            '') -join "`n"
        [IO.File]::WriteAllText(
            $guardPropsPath,
            $guardProps,
            [Text.UTF8Encoding]::new($false, $true))
        $buildPropsInput = ProductionReleaseState\Open-ProductionReleaseInput `
            -Path $guardPropsPath `
            -Label 'Personal guarded MSBuild props' `
            -MaximumBytes 1MB
        $sourceGuard = Open-PersonalTrustedSourceGuard `
            -SnapshotRoot $sourceSnapshotRoot `
            -Source $source `
            -WorkRoot $workRoot
        $payloadOutputRoot = Join-Path $outputRoot 'payload'
        $payload = Get-PersonalTrustedPayloadClosure `
            -PayloadDirectory $payloadSource `
            -OutputPayloadRoot $payloadOutputRoot `
            -Context $Context `
            -CompiledTrust $CompiledTrust `
            -LockedOutputs $lockedOutputs
        $packageLockPath = Join-Path $sourceSnapshotRoot (
            $script:PackageLockRelativePath.Replace('/', '\'))
        $packageClosure = Get-PersonalTrustedPackageClosure `
            -PackageDirectory $packageSource `
            -PackageLockPath $packageLockPath `
            -SnapshotRoot $offlineFeedRoot
        $packageLocks = @($packageClosure.Locks)
        $sdkLockPath = Join-Path $sourceSnapshotRoot (
            $script:SdkLockRelativePath.Replace('/', '\'))
        $sdkSourceClosure =
            PortableDotNetSdkClosure\Open-PortableDotNetSdkArchiveClosure `
                -ArchivePath $sdkArchive `
                -LockPath $sdkLockPath `
                -ExtractionDirectory $sdkExtractionRoot `
                -ExpectedSdkVersion '10.0.302'
        $sdkPrivateClosure =
            PortableDotNetSdkClosure\New-PortableDotNetSdkPrivateCopy `
                -SourceClosure $sdkSourceClosure `
                -DestinationDirectory $sdkPrivateRoot
        $sdkToolchain =
            PortableDotNetSdkClosure\Get-PortableDotNetSdkPrivateToolchain `
                -Closure $sdkPrivateClosure
        if ([string]$sdkToolchain.SdkVersion -cne '10.0.302' -or
            [string]$sdkToolchain.ArchiveBindingStatus -cne
                'ZIP_SHA512_AND_FILE_INVENTORY_VERIFIED' -or
            [int]$sdkToolchain.FileCount -le 0 -or
            [int64]$sdkToolchain.TotalSizeBytes -le 0) {
            throw 'Personal private portable .NET SDK differs from its reviewed byte closure.'
        }
        $controlledEnvironment = @{
            DOTNET_CLI_HOME = $cliHome
            DOTNET_CLI_TELEMETRY_OPTOUT = '1'
            DOTNET_CLI_USE_MSBUILD_SERVER = '0'
            DOTNET_ROOT = [string]$sdkToolchain.RootPath
            DOTNET_ROOT_X64 = [string]$sdkToolchain.RootPath
            DOTNET_MULTILEVEL_LOOKUP = '0'
            DOTNET_NOLOGO = '1'
            DOTNET_SKIP_FIRST_TIME_EXPERIENCE = '1'
            NUGET_PACKAGES = $nugetPackagesRoot
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
        $dotnetPath = [string]$sdkToolchain.DotnetPath
        $version = (Invoke-PersonalTrustedProcess `
                -FilePath $dotnetPath `
                -Arguments @('--version') `
                -WorkingDirectory $sourceSnapshotRoot `
                -Environment $controlledEnvironment `
                -TimeoutMilliseconds 60000).Stdout.Trim()
        if ($version -cne '10.0.302') {
            throw "Personal trusted build requires .NET SDK 10.0.302, not '$version'."
        }
        $nugetConfigPath = Join-Path $workRoot 'NuGet.Config'
        $nugetConfig =
            '<?xml version="1.0" encoding="utf-8"?><configuration>' +
            '<packageSources><clear/><add key="offline" value="' +
            [Security.SecurityElement]::Escape($offlineFeedRoot) +
            '" /></packageSources><config><add key="globalPackagesFolder" value="' +
            [Security.SecurityElement]::Escape($nugetPackagesRoot) +
            '" /></config></configuration>'
        [IO.File]::WriteAllText(
            $nugetConfigPath,
            $nugetConfig,
            [Text.UTF8Encoding]::new($false, $true))
        $projectPath = Join-Path $sourceSnapshotRoot (
            $script:RootProjectRelativePath.Replace('/', '\'))
        $propsPath = $guardPropsPath
        $targetsPath = Join-Path $sourceSnapshotRoot 'Directory.Build.targets'
        $effectiveTargetsPath = if ([IO.File]::Exists($targetsPath)) {
            $targetsPath
        }
        else {
            ''
        }
        $propertyPins = @(
            "-p:DirectoryBuildPropsPath=$propsPath",
            "-p:DirectoryBuildTargetsPath=$effectiveTargetsPath",
            '-p:CustomBeforeMicrosoftCommonProps=',
            '-p:CustomAfterMicrosoftCommonProps=',
            '-p:CustomBeforeMicrosoftCommonTargets=',
            '-p:CustomAfterMicrosoftCommonTargets=')
        $restoreArguments = @(
            'restore', $projectPath, '--locked-mode', '--no-cache',
            '--disable-parallel', '--configfile', $nugetConfigPath,
            '-p:NuGetAudit=false', '-p:RestoreIgnoreFailedSources=false',
            '-m:1', '-nodeReuse:false', '-p:UseSharedCompilation=false') +
            $propertyPins
        [void](Invoke-PersonalTrustedProcess `
                -FilePath $dotnetPath `
                -Arguments $restoreArguments `
                -WorkingDirectory $sourceSnapshotRoot `
                -Environment $controlledEnvironment)
        $buildStartedAtUtc = Get-PersonalTrustedUtcNow
        $publishArguments = @(
            'publish', $projectPath,
            '--configuration', 'Release', '--runtime', 'win-x64',
            '--self-contained', 'true', '--no-restore',
            '--output', $publishRoot,
            '-p:PublishSingleFile=true',
            '-p:IncludeNativeLibrariesForSelfExtract=true',
            '-p:PublishTrimmed=false', '-p:Deterministic=true',
            '-p:ContinuousIntegrationBuild=true',
            '-p:DebugType=None', '-p:DebugSymbols=false',
            '-m:1', '-nodeReuse:false', '-p:UseSharedCompilation=false',
            '-p:PersonalProductionBuild=true',
            '-p:PersonalDevelopmentPublish=false',
            "-p:PersonalManifestOrigin=$($CompiledTrust.manifestOrigin)",
            "-p:PersonalArtifactOrigin=$($CompiledTrust.artifactOrigin)",
            "-p:PersonalChannel=$($Context.channel)",
            "-p:PersonalReleaseKeyId=$($CompiledTrust.releaseKeyId)",
            "-p:PersonalReleaseKeyX=$($CompiledTrust.releaseKeyX)",
            "-p:PersonalReleaseKeyY=$($CompiledTrust.releaseKeyY)",
            "-p:PersonalStartupStubVersion=$($CompiledTrust.startupStubVersion)",
            "-p:PersonalCanonicalLowSFromSequence=$($CompiledTrust.canonicalLowSFromSequence)",
            "-p:PersonalAuthenticodeSignerSha256Thumbprint=$($CompiledTrust.authenticodeSignerSha256Thumbprint)",
            "-p:PersonalInstallerPayloadDirectory=$payloadOutputRoot") +
            $propertyPins
        [void](Invoke-PersonalTrustedProcess `
                -FilePath $dotnetPath `
                -Arguments $publishArguments `
                -WorkingDirectory $sourceSnapshotRoot `
                -Environment $controlledEnvironment)
        $buildCompletedAtUtc = Get-PersonalTrustedUtcNow
        $published = @(Get-ChildItem -LiteralPath $publishRoot -Force)
        if ($published.Count -ne 1 -or $published[0].PSIsContainer -or
            [string]$published[0].Name -cne $script:InstallerFileName) {
            throw 'Personal Installer publish output is not exactly one single-file executable.'
        }
        $unsignedRoot = Join-Path $outputRoot 'unsigned'
        New-PersonalTrustedDirectory -Path $unsignedRoot | Out-Null
        $publishedInput = ProductionReleaseState\Open-ProductionReleaseInput `
            -Path $published[0].FullName `
            -Label 'Personal published unsigned Installer' `
            -MaximumBytes 1GB
        try {
            $unsignedPath = Join-Path $unsignedRoot $script:InstallerFileName
            Copy-PersonalTrustedInput `
                -Descriptor $publishedInput `
                -DestinationPath $unsignedPath `
                -Label 'Personal unsigned Installer'
        }
        finally {
            $publishedInput.Stream.Dispose()
        }
        $unsignedInput = ProductionReleaseState\Open-ProductionReleaseInput `
            -Path $unsignedPath `
            -Label 'Personal trusted-build unsigned Installer output' `
            -MaximumBytes 1GB
        $lockedOutputs.Add($unsignedInput)
        [byte[]]$unsignedBytes =
            ProductionReleaseState\Read-ProductionReleaseInputBytes `
                -Descriptor $unsignedInput `
                -Label 'Personal unsigned Installer'
        try {
            $peContentSha256 =
                ProductionReleaseState\Get-PeContentSha256 -Bytes $unsignedBytes
        }
        finally {
            [Array]::Clear($unsignedBytes, 0, $unsignedBytes.Length)
        }
        $unsignedDescriptor = [ordered]@{
            role = 'installer'
            fileName = $script:InstallerFileName
            relativePath = "unsigned/$script:InstallerFileName"
            sizeBytes = [int64]$unsignedInput.SizeBytes
            sha256 = [string]$unsignedInput.Sha256
            peContentSha256 = $peContentSha256
            authenticodeStatus = 'NotSigned'
        }
        [void](InstallerSigningContracts\Assert-UnsignedInstallerSigningInput `
                -Path $unsignedPath `
                -Descriptor ([pscustomobject]$unsignedDescriptor))
        $managedAssemblies = @(Get-ChildItem `
                -LiteralPath $managedOutputRoot `
                -Filter 'Ensou.Dsh.Personal.Installer.dll' `
                -File `
                -Recurse `
                -Force)
        if ($managedAssemblies.Count -ne 1) {
            throw 'Personal trusted build cannot locate the managed Installer resource carrier.'
        }
        $managedAssemblyPath = $managedAssemblies[0].FullName
        $resourceBinding = Get-PersonalTrustedResourceBinding `
            -ManagedAssemblyPath $managedAssemblyPath `
            -PayloadFiles $payload.Files `
            -UnsignedInstallerSha256 ([string]$unsignedInput.Sha256)
        Assert-PersonalTrustedSourceGuardUnchanged -Guard $sourceGuard
        [void](ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
                -Descriptor $buildPropsInput `
                -Label 'Personal guarded MSBuild props through publish')
        [void](PortableDotNetSdkClosure\Assert-PortableDotNetSdkClosureUnchanged `
                -Closure $sdkSourceClosure)
        [void](PortableDotNetSdkClosure\Assert-PortableDotNetSdkClosureUnchanged `
                -Closure $sdkPrivateClosure)
        $postStatus = Invoke-PersonalTrustedGit `
            -GitPath $gitExecutable `
            -RepositoryRoot $repository `
            -Arguments @('status', '--porcelain=v1', '--untracked-files=all')
        $postCommit = (Invoke-PersonalTrustedGit `
                -GitPath $gitExecutable `
                -RepositoryRoot $repository `
                -Arguments @('rev-parse', '--verify', 'HEAD^{commit}')).Stdout.Trim()
        $postTree = (Invoke-PersonalTrustedGit `
                -GitPath $gitExecutable `
                -RepositoryRoot $repository `
                -Arguments @('rev-parse', '--verify', 'HEAD^{tree}')).Stdout.Trim()
        if (-not [string]::IsNullOrEmpty($postStatus.Stdout) -or
            $postCommit -cne [string]$source.Commit -or
            $postTree -cne [string]$source.Tree) {
            throw 'Personal source checkout changed during trusted build.'
        }
        $sourceEvidence = [ordered]@{
            commit = [string]$source.Commit
            tree = [string]$source.Tree
            status = 'CLEAN_TRACKED_HEAD'
            snapshotContract =
                'git-head-archive-held-file-leases-directory-identity-mutation-monitor-v2'
            rootProject = $script:RootProjectRelativePath
            fileCount = [int]$source.FileCount
            totalSizeBytes = [int64]$source.TotalSizeBytes
            inventorySha256 = [string]$source.InventorySha256
        }
        $payloadEvidenceFiles = @($payload.Files | ForEach-Object {
                [ordered]@{
                    role = $_.role
                    fileName = $_.fileName
                    relativePath = $_.relativePath
                    sizeBytes = $_.sizeBytes
                    sha256 = $_.sha256
                }
            })
        $payloadEvidence = [ordered]@{
            status = 'EXACT_FOUR_FILE_BYTE_CLOSURE_VERIFIED'
            authenticationStatus =
                'STRUCTURE_AND_ARTIFACT_HASHES_VERIFIED_SIGNED_MANIFEST_TRUST_NOT_YET_SHARED_R6_ADMITTED'
            inventorySha256 = [string]$payload.InventorySha256
            files = $payloadEvidenceFiles
        }
        $compiledTrustEvidence = [ordered]@{
            manifestOrigin = [string]$CompiledTrust.manifestOrigin
            artifactOrigin = [string]$CompiledTrust.artifactOrigin
            channel = [string]$Context.channel
            releaseKeyId = [string]$CompiledTrust.releaseKeyId
            releaseKeyIdentitySha256 = [string]$payload.ReleaseKeyIdentitySha256
            startupStubVersion = [string]$CompiledTrust.startupStubVersion
            canonicalLowSFromSequence =
                [int64]$CompiledTrust.canonicalLowSFromSequence
            authenticodeSignerSha256Thumbprint =
                [string]$CompiledTrust.authenticodeSignerSha256Thumbprint
        }
        $packageEvidence = [ordered]@{
            lockRelativePath = "repo/$script:PackageLockRelativePath"
            lockSha256 = [string]$packageClosure.LockSha256
            packageCount = 4
            inventorySha256 = [string]$packageClosure.InventorySha256
        }
        $sdkEvidence = [ordered]@{
            sdkVersion = [string]$sdkToolchain.SdkVersion
            archiveFileName = [IO.Path]::GetFileName($sdkArchive)
            archiveSha512 = [string]$sdkToolchain.ArchiveSha512
            lockRelativePath = "repo/$script:SdkLockRelativePath"
            lockSha256 = [string]$sdkToolchain.LockSha256
            inventorySha256 = [string]$sdkToolchain.InventorySha256
            fileCount = [int]$sdkToolchain.FileCount
            totalSizeBytes = [int64]$sdkToolchain.TotalSizeBytes
            status = 'VERIFIED'
            privateCopyPolicy =
                'create-only-private-copy-held-open-through-version-restore-publish-v1'
        }
        $buildExecution = [ordered]@{
            startedAtUtc = $buildStartedAtUtc
            completedAtUtc = $buildCompletedAtUtc
            exitCode = 0
            runtimeIdentifier = 'win-x64'
            selfContained = $true
            singleFile = $true
            offlineRestore = $true
            inheritedEnvironmentCleared = $true
            unsignedArtifactExecution = 'FORBIDDEN_AND_NOT_PERFORMED'
        }
        $admission = [ordered]@{
            status = 'READY'
            blocker = 'INSTALLER_SIGNING_RESPONSE_REQUIRED'
            productionAdmission = 'NO_GO'
            reason =
                'The exact Personal Pilot signing request is ready for shared r6 validation and isolated external signing. A genuine authenticated signing response is still required; execution, publication, and distribution remain forbidden.'
        }
        $buildId = [Guid]::NewGuid().ToString()
        $evidence = [ordered]@{
            schemaVersion = 1
            evidenceType = 'ensou-dsh-personal-installer-trusted-build'
            buildId = $buildId
            edition = 'Personal'
            channel = [string]$Context.channel
            releaseSetId = [string]$Context.expectedReleaseSetId
            source = $sourceEvidence
            payload = $payloadEvidence
            compiledTrust = $compiledTrustEvidence
            packageClosure = $packageEvidence
            sdkClosure = $sdkEvidence
            buildExecution = $buildExecution
            unsignedInstaller = $unsignedDescriptor
            resourceBinding = $resourceBinding
            signingRequestEligibility = $admission
        }
        $trustedBuildRoot = Join-Path $outputRoot 'trusted-build'
        New-PersonalTrustedDirectory -Path $trustedBuildRoot | Out-Null
        $evidencePath = Join-Path $trustedBuildRoot 'trusted-build-evidence.v1.json'
        [IO.File]::WriteAllBytes(
            $evidencePath,
            (ProductionReleaseState\ConvertTo-ProductionJsonBytes -Value $evidence))
        $schemaRoot = Join-Path ([IO.Path]::GetDirectoryName($PSScriptRoot)) 'schemas'
        $evidenceInput = ProductionReleaseState\Read-StrictProductionJsonFile `
            -Path $evidencePath `
            -SchemaPath (Join-Path $schemaRoot `
                'personal-installer-trusted-build-evidence-v1.schema.json') `
            -Label 'Personal Installer trusted-build evidence'
        [void](ProductionReleaseState\Assert-CanonicalProductionJsonInput `
                -JsonInput $evidenceInput `
                -Label 'Personal Installer trusted-build evidence')
        $evidenceLock = ProductionReleaseState\Open-ProductionReleaseInput `
            -Path $evidencePath `
            -Label 'Personal trusted-build evidence output' `
            -MaximumBytes 64MB
        $lockedOutputs.Add($evidenceLock)
        [byte[]]$nonceBytes = [byte[]]::new(32)
        [Security.Cryptography.RandomNumberGenerator]::Fill($nonceBytes)
        try {
            $nonce = [Convert]::ToBase64String($nonceBytes).TrimEnd('=').
                Replace('+', '-').Replace('/', '_')
        }
        finally {
            [Array]::Clear($nonceBytes, 0, $nonceBytes.Length)
        }
        $createdAtUtc = Get-PersonalTrustedUtcNow
        $createdAt = [DateTimeOffset]::ParseExact(
            $createdAtUtc,
            'yyyy-MM-ddTHH:mm:ssZ',
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AssumeUniversal)
        $expiresAtUtc = $createdAt.AddMinutes(
            [int]$Context.maximumResponseAgeMinutes).ToString(
                'yyyy-MM-ddTHH:mm:ssZ',
                [Globalization.CultureInfo]::InvariantCulture)
        $responseTrustSha256 =
            InstallerSigningContracts\Get-InstallerSigningObjectSha256 `
                -Value $InstallerSigningResponseTrust
        $toolchain = [ordered]@{
            packageClosure = $packageEvidence
            sdkClosure = $sdkEvidence
            toolchainIdentitySha256 =
                InstallerSigningContracts\Get-InstallerSigningObjectSha256 `
                    -Value ([ordered]@{
                        packageClosure = $packageEvidence
                        sdkClosure = $sdkEvidence
                    })
        }
        $request = [ordered]@{
            schemaVersion = 2
            requestType = 'ensou-dsh-personal-installer-signing-request'
            orchestrationId = [string]$Context.orchestrationId
            edition = 'Personal'
            releaseSetId = [string]$Context.expectedReleaseSetId
            channel = [string]$Context.channel
            planSha256 = [string]$Context.planSha256
            baseHeadSha256 = [string]$Context.baseHeadSha256
            baseRevision = 5
            basePhase = 'PILOT_SIGNED_CANDIDATE_IMPORTED'
            requestedRevision = 6
            requestNonce = $nonce
            createdAtUtc = $createdAtUtc
            expiresAtUtc = $expiresAtUtc
            source = $sourceEvidence
            payload = $payloadEvidence
            compiledTrust = $compiledTrustEvidence
            toolchain = $toolchain
            buildExecution = $buildExecution
            unsignedInstaller = $unsignedDescriptor
            resourceBinding = $resourceBinding
            trustedBuildEvidence = [ordered]@{
                fileName = 'trusted-build-evidence.v1.json'
                relativePath = 'trusted-build/trusted-build-evidence.v1.json'
                sizeBytes = [int64]$evidenceInput.Bytes.LongLength
                sha256 = [string]$evidenceInput.Sha256
                productionAdmission = 'NO_GO'
            }
            responseAuthentication = [ordered]@{
                algorithm = 'ES256'
                keyId = [string]$InstallerSigningResponseTrust.keyId
                purpose = 'personal-installer-signing-response'
                payloadType =
                    'ensou-dsh-personal-installer-signing-response-authentication-v2'
                trustSha256 = $responseTrustSha256
                maximumResponseAgeMinutes =
                    [int]$Context.maximumResponseAgeMinutes
            }
            admission = $admission
        }
        $requestPath = Join-Path $outputRoot 'personal-installer-signing-request.v2.json'
        [IO.File]::WriteAllBytes(
            $requestPath,
            (ProductionReleaseState\ConvertTo-ProductionJsonBytes -Value $request))
        $requestInput = ProductionReleaseState\Read-StrictProductionJsonFile `
            -Path $requestPath `
            -SchemaPath (Join-Path $schemaRoot `
                'personal-installer-signing-request-v2.schema.json') `
            -Label 'Personal Installer signing request draft v2'
        [void](ProductionReleaseState\Assert-CanonicalProductionJsonInput `
                -JsonInput $requestInput `
                -Label 'Personal Installer signing request draft v2')
        $requestLock = ProductionReleaseState\Open-ProductionReleaseInput `
            -Path $requestPath `
            -Label 'Personal signing request draft output' `
            -MaximumBytes 64MB
        $lockedOutputs.Add($requestLock)

        PortableDotNetSdkClosure\Close-PortableDotNetSdkClosure `
            -Closure $sdkPrivateClosure
        $sdkPrivateClosure = $null
        PortableDotNetSdkClosure\Close-PortableDotNetSdkClosure `
            -Closure $sdkSourceClosure
        $sdkSourceClosure = $null
        foreach ($packageLock in $packageLocks) {
            [void](ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
                    -Descriptor $packageLock `
                    -Label 'Personal offline package through publish')
            $packageLock.Stream.Dispose()
        }
        $packageLocks = @()
        $buildPropsInput.Stream.Dispose()
        $buildPropsInput = $null
        Close-PersonalTrustedSourceGuard -Guard $sourceGuard
        $sourceGuard = $null
        Remove-Item -LiteralPath $workRoot -Recurse -Force
        $createdOutput = $false
        $result = [pscustomobject]@{
            Status = 'SIGNING_REQUEST_READY_NO_GO'
            Blocker = 'INSTALLER_SIGNING_RESPONSE_REQUIRED'
            ProductionAdmission = 'NO_GO'
            OutputDirectory = $outputRoot
            Request = $requestInput.Value
            RequestInput = $requestLock
            Evidence = $evidenceInput.Value
            EvidenceInput = $evidenceLock
            UnsignedInstallerInput = $unsignedInput
            PayloadInputs = @($lockedOutputs | Where-Object {
                    $null -ne $_.PSObject.Properties['Role']
                })
            LockedOutputs = $lockedOutputs
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
        foreach ($descriptor in @($lockedOutputs)) {
            if ($null -ne $descriptor.Stream) {
                $descriptor.Stream.Dispose()
            }
        }
        foreach ($packageLock in $packageLocks) {
            if ($null -ne $packageLock.Stream) {
                $packageLock.Stream.Dispose()
            }
        }
        if ($null -ne $sdkPrivateClosure) {
            PortableDotNetSdkClosure\Close-PortableDotNetSdkClosure `
                -Closure $sdkPrivateClosure
        }
        if ($null -ne $sdkSourceClosure) {
            PortableDotNetSdkClosure\Close-PortableDotNetSdkClosure `
                -Closure $sdkSourceClosure
        }
        if ($null -ne $sourceGuard) {
            Close-PersonalTrustedSourceGuard -Guard $sourceGuard
            $sourceGuard = $null
        }
        if ($null -ne $buildPropsInput) {
            $buildPropsInput.Stream.Dispose()
            $buildPropsInput = $null
        }
        if ($createdOutput -and [IO.Directory]::Exists($outputRoot) -and
            (Test-PersonalTrustedSameOrDescendant `
                -Path $outputRoot `
                -Root $outputParent)) {
            Remove-Item -LiteralPath $outputRoot -Recurse -Force
        }
        throw
    }
}

Export-ModuleMember -Function @('New-PersonalInstallerTrustedBuild')
