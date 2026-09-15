[CmdletBinding(DefaultParameterSetName = 'Production')]
param(
    [Parameter(Mandatory = $true)][string]$EvidenceEnvelopePath,
    [Parameter(Mandatory = $true)][string]$EvidenceBodyPath,
    [Parameter(Mandatory = $true, ParameterSetName = 'Production')][string]$PublisherExecutablePath,
    [Parameter(Mandatory = $true, ParameterSetName = 'Production')]
    [ValidatePattern('^[0-9A-Fa-f]{64}$')][string]$PublisherSignerSha256Thumbprint,
    [Parameter(Mandatory = $true, ParameterSetName = 'Production')]
    [ValidatePattern('^[0-9a-f]{64}$')][string]$PublisherExecutableSha256,
    [Parameter(Mandatory = $true, ParameterSetName = 'Production')][string]$ReadinessReplayReportPath,
    [Parameter(Mandatory = $true, ParameterSetName = 'Production')][string]$ReportPath,
    [Parameter(Mandatory = $true, ParameterSetName = 'Production')]
    [string]$WindowsPilotVerifierPrivateKeyPath,
    [Parameter(Mandatory = $true, ParameterSetName = 'Production')]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')]
    [string]$WindowsPilotVerifierKeyId,
    [Parameter(Mandatory = $true, ParameterSetName = 'Contract')][switch]$ContractOnly,
    [Parameter(Mandatory = $true, ParameterSetName = 'Contract')]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')][string]$ContractPilotEvidenceKeyId,
    [Parameter(Mandatory = $true, ParameterSetName = 'Contract')]
    [ValidatePattern('^[A-Za-z0-9_-]{43}$')][string]$ContractPilotEvidenceKeyX,
    [Parameter(Mandatory = $true, ParameterSetName = 'Contract')]
    [ValidatePattern('^[A-Za-z0-9_-]{43}$')][string]$ContractPilotEvidenceKeyY,
    [Parameter(Mandatory = $true, ParameterSetName = 'Contract')]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')][string]$ContractReleaseKeyId,
    [Parameter(Mandatory = $true, ParameterSetName = 'Contract')]
    [ValidatePattern('^[A-Za-z0-9_-]{43}$')][string]$ContractReleaseKeyX,
    [Parameter(Mandatory = $true, ParameterSetName = 'Contract')]
    [ValidatePattern('^[A-Za-z0-9_-]{43}$')][string]$ContractReleaseKeyY
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($PSVersionTable.PSEdition -ne 'Core' -or $PSVersionTable.PSVersion -lt [version]'7.4') {
    throw 'Enterprise Windows Pilot verification requires PowerShell 7.4 or newer.'
}

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$envelopeSchemaPath = Join-Path $repositoryRoot 'release\schemas\enterprise-windows-pilot-evidence-envelope-v2.schema.json'
$bodySchemaPath = Join-Path $repositoryRoot 'release\schemas\enterprise-windows-pilot-evidence-body-v2.schema.json'
$gateSchemaPath = Join-Path $repositoryRoot 'release\schemas\enterprise-windows-pilot-gate-receipt-v2.schema.json'
$gateContractPath = Join-Path $repositoryRoot 'release\enterprise-windows-pilot-gate-contract-v2.json'
$gateContractSchemaPath = Join-Path $repositoryRoot 'release\schemas\enterprise-windows-pilot-gate-contract-v2.schema.json'
$readinessConfigSchemaPath = Join-Path $repositoryRoot 'release\schemas\enterprise-pilot-readiness-v1.schema.json'
$readinessReportSchemaPath = Join-Path $repositoryRoot 'release\schemas\enterprise-pilot-readiness-report-v1.schema.json'
$verificationReportSchemaPath = Join-Path $repositoryRoot 'release\schemas\enterprise-windows-pilot-verification-report-v2.schema.json'
$pilotEvidenceModulePath = Join-Path $repositoryRoot 'release\scripts\EnterpriseProductionPilotEvidence.psm1'
Microsoft.PowerShell.Core\Import-Module `
    -Name $pilotEvidenceModulePath `
    -Force `
    -ErrorAction Stop
$expectedGateContractCanonicalSha256 = 'a7fff40aad6690d12042d62ba1a8deb80e36431abdd62bc4874fa04388d26331'

$requiredExecutableNames = [ordered]@{
    'release-publisher' = 'Ensou.Dsh.Enterprise.ReleasePublisher.exe'
    'installer' = 'Ensou.Dsh.Enterprise.Installer.exe'
    'bootstrapper' = 'Ensou.Dsh.Enterprise.Bootstrapper.exe'
    'launcher' = 'Ensou.Dsh.Enterprise.Launcher.exe'
    'client-bootstrapper' = 'Ensou.Dsh.Enterprise.ClientBootstrapper.exe'
    'maintenance' = 'Ensou.Dsh.Enterprise.Maintenance.exe'
}
$gateContractText = Get-Content -Raw -LiteralPath $gateContractPath
if (-not (Test-Json -Json $gateContractText -SchemaFile $gateContractSchemaPath -ErrorAction Stop)) {
    throw 'Enterprise Windows Pilot gate contract does not satisfy its exact schema.'
}
$gateContract = $gateContractText | ConvertFrom-Json -Depth 16
$gateContractCanonicalBytes = [Text.UTF8Encoding]::new($false, $true).GetBytes(
    ($gateContract | ConvertTo-Json -Depth 16 -Compress))
$gateContractCanonicalSha256 = [Convert]::ToHexString(
    [Security.Cryptography.SHA256]::HashData($gateContractCanonicalBytes)).ToLowerInvariant()
if ($gateContractCanonicalSha256 -cne $expectedGateContractCanonicalSha256) {
    throw 'Enterprise Windows Pilot gate contract does not match the pinned canonical contract.'
}
$gateExpectations = @($gateContract.gates | ForEach-Object {
    [ordered]@{
        gate = [string]$_.gate
        role = [string]$_.role
        state = [string]$_.state
        network = [string]$_.networkMode
        result = [string]$_.resultCode
        lane = [string]$_.deviceLane
        active = [int]$_.activeReleaseIndex
        rollback = if ($null -eq $_.rollbackReleaseIndex) { $null } else { [int]$_.rollbackReleaseIndex }
        attempted = if ($null -eq $_.attemptedReleaseIndex) { $null } else { [int]$_.attemptedReleaseIndex }
    }
})
for ($index = 0; $index -lt $gateExpectations.Count; $index++) {
    if ([int]$gateContract.gates[$index].sequenceNumber -ne $index + 1) {
        throw 'Enterprise Windows Pilot gate contract sequence is not exact.'
    }
}

$locks = [Collections.Generic.List[IDisposable]]::new()
$snapshots = @{}
$directoryGuards = @{}
$checks = [Collections.Generic.List[object]]::new()
$reportFullPath = $null
$replayFullPath = $null
$envelopeSha256 = '0' * 64
$bodySha256 = '0' * 64
$publisherActualSha256 = $null
$pilotEvidenceKeyId = $null
$replayReportSha256 = $null
$liveManifestSha256 = $null
$verifiedManifestHashes = @()
$body = $null
$verifierSigner = $null
$verifierKeySnapshot = $null

function Add-Check {
    param([string]$Id,[ValidateSet('PASS','FAIL')][string]$Status,[string]$Evidence)
    $bounded = if ($Evidence.Length -le 512) { $Evidence } else { $Evidence.Substring(0,512) }
    $checks.Add([ordered]@{id=$Id;status=$Status;evidence=$bounded})
}

function Initialize-PathGuard {
    if ('Ensou.Dsh.PilotEvidence.PathGuard' -as [type]) { return }
    if (-not $IsWindows) { throw 'Enterprise Windows Pilot path verification requires Windows.' }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Ensou.Dsh.PilotEvidence
{
    public sealed class VerifiedDirectory : IDisposable
    {
        internal VerifiedDirectory(SafeFileHandle handle, string finalPath, string identity)
        {
            Handle = handle;
            FinalPath = finalPath;
            Identity = identity;
        }

        internal SafeFileHandle Handle { get; }
        public string FinalPath { get; }
        public string Identity { get; }
        public void Dispose() => Handle.Dispose();
    }

    public sealed class VerifiedReadFile : IDisposable
    {
        internal VerifiedReadFile(FileStream stream, string finalPath, string identity)
        {
            Stream = stream;
            FinalPath = finalPath;
            Identity = identity;
        }

        public FileStream Stream { get; }
        public string FinalPath { get; }
        public string Identity { get; }
        public void Dispose() => Stream.Dispose();
    }

    public static class PathGuard
    {
        private const uint GenericRead = 0x80000000;
        private const uint FileReadAttributes = 0x00000080;
        private const uint FileShareRead = 0x00000001;
        private const uint FileShareWrite = 0x00000002;
        private const uint OpenExisting = 3;
        private const uint FileAttributeDirectory = 0x00000010;
        private const uint FileAttributeReparsePoint = 0x00000400;
        private const uint FileFlagOpenReparsePoint = 0x00200000;
        private const uint FileFlagBackupSemantics = 0x02000000;
        private const uint FileFlagSequentialScan = 0x08000000;

        [StructLayout(LayoutKind.Sequential)]
        private struct FileAttributeTagInfo
        {
            public uint FileAttributes;
            public uint ReparseTag;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FileId128
        {
            public ulong Low;
            public ulong High;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FileIdInfo
        {
            public ulong VolumeSerialNumber;
            public FileId128 FileId;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFileW(
            string name,
            uint desiredAccess,
            uint shareMode,
            IntPtr securityAttributes,
            uint creationDisposition,
            uint flagsAndAttributes,
            IntPtr templateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandleEx(
            SafeFileHandle handle,
            int informationClass,
            out FileAttributeTagInfo information,
            uint bufferSize);

        [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "GetFileInformationByHandleEx")]
        private static extern bool GetFileIdInformationByHandleEx(
            SafeFileHandle handle,
            int informationClass,
            out FileIdInfo information,
            uint bufferSize);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetFinalPathNameByHandleW(
            SafeFileHandle handle,
            StringBuilder path,
            uint pathLength,
            uint flags);

        public static VerifiedDirectory OpenDirectory(string path)
        {
            string expected = NormalizeExpected(path);
            SafeFileHandle handle = Open(expected, FileReadAttributes, FileShareRead | FileShareWrite,
                FileFlagBackupSemantics | FileFlagOpenReparsePoint, "directory");
            try
            {
                Inspection inspection = Inspect(handle, expected, true);
                return new VerifiedDirectory(handle, inspection.FinalPath, inspection.Identity);
            }
            catch
            {
                handle.Dispose();
                throw;
            }
        }

        public static VerifiedReadFile OpenReadFile(string path)
        {
            string expected = NormalizeExpected(path);
            SafeFileHandle handle = Open(expected, GenericRead, FileShareRead,
                FileFlagOpenReparsePoint | FileFlagSequentialScan, "file");
            try
            {
                Inspection inspection = Inspect(handle, expected, false);
                FileStream stream = new FileStream(handle, FileAccess.Read, 1024 * 1024, false);
                return new VerifiedReadFile(stream, inspection.FinalPath, inspection.Identity);
            }
            catch
            {
                handle.Dispose();
                throw;
            }
        }

        public static void AssertFileIdentity(string path, string expectedFinalPath, string expectedIdentity)
        {
            string expected = NormalizeExpected(path);
            using (SafeFileHandle handle = Open(expected, GenericRead, FileShareRead | FileShareWrite,
                FileFlagOpenReparsePoint, "file identity probe"))
            {
                Inspection inspection = Inspect(handle, expected, false);
                if (!String.Equals(inspection.FinalPath, expectedFinalPath, StringComparison.OrdinalIgnoreCase) ||
                    !String.Equals(inspection.Identity, expectedIdentity, StringComparison.Ordinal))
                {
                    throw new IOException("Pilot input path no longer resolves to the locked file identity.");
                }
            }
        }

        public static void AssertDirectoryIdentity(string path, string expectedFinalPath, string expectedIdentity)
        {
            using (VerifiedDirectory probe = OpenDirectory(path))
            {
                if (!String.Equals(probe.FinalPath, expectedFinalPath, StringComparison.OrdinalIgnoreCase) ||
                    !String.Equals(probe.Identity, expectedIdentity, StringComparison.Ordinal))
                {
                    throw new IOException("Pilot directory path no longer resolves to the locked directory identity.");
                }
            }
        }

        public static string AssertOpenFilePath(SafeFileHandle handle, string expectedPath)
        {
            if (handle == null || handle.IsInvalid || handle.IsClosed)
            {
                throw new IOException("Pilot output file handle is unavailable.");
            }
            Inspection inspection = Inspect(handle, NormalizeExpected(expectedPath), false);
            return inspection.Identity;
        }

        private static SafeFileHandle Open(string path, uint access, uint share, uint flags, string label)
        {
            SafeFileHandle handle = CreateFileW(path, access, share, IntPtr.Zero, OpenExisting, flags, IntPtr.Zero);
            if (handle.IsInvalid)
            {
                int error = Marshal.GetLastWin32Error();
                handle.Dispose();
                throw new IOException("Unable to open Pilot " + label + " safely.", new Win32Exception(error));
            }
            return handle;
        }

        private static Inspection Inspect(SafeFileHandle handle, string expectedPath, bool requireDirectory)
        {
            FileAttributeTagInfo attributes;
            if (!GetFileInformationByHandleEx(handle, 9, out attributes,
                (uint)Marshal.SizeOf(typeof(FileAttributeTagInfo))))
            {
                throw NativeFailure("Unable to inspect Pilot path attributes.");
            }

            bool isDirectory = (attributes.FileAttributes & FileAttributeDirectory) != 0;
            bool isReparsePoint = (attributes.FileAttributes & FileAttributeReparsePoint) != 0;
            if (isDirectory != requireDirectory || isReparsePoint)
            {
                throw new IOException("Pilot path must resolve directly to the expected non-reparse object type.");
            }

            string finalPath = GetFinalPath(handle);
            if (!String.Equals(finalPath, expectedPath, StringComparison.OrdinalIgnoreCase))
            {
                throw new IOException("Pilot path final target differs from the requested absolute path.");
            }

            FileIdInfo information;
            if (!GetFileIdInformationByHandleEx(handle, 18, out information,
                (uint)Marshal.SizeOf(typeof(FileIdInfo))))
            {
                throw NativeFailure("Unable to inspect Pilot path identity.");
            }

            string identity = information.VolumeSerialNumber.ToString("x16") + ":" +
                information.FileId.Low.ToString("x16") + information.FileId.High.ToString("x16");
            return new Inspection(finalPath, identity);
        }

        private static string GetFinalPath(SafeFileHandle handle)
        {
            StringBuilder buffer = new StringBuilder(32768);
            uint length = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Capacity, 0);
            if (length == 0 || length >= buffer.Capacity)
            {
                throw NativeFailure("Unable to resolve the final Pilot path.");
            }

            string path = buffer.ToString();
            if (path.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
            {
                path = @"\\" + path.Substring(8);
            }
            else if (path.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase))
            {
                path = path.Substring(4);
            }
            return NormalizeComparable(path);
        }

        private static string NormalizeExpected(string path)
        {
            if (String.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path))
            {
                throw new IOException("Pilot path must be absolute.");
            }
            return NormalizeComparable(Path.GetFullPath(path));
        }

        private static string NormalizeComparable(string path)
        {
            string fullPath = Path.GetFullPath(path);
            if (fullPath.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
            {
                fullPath = @"\\" + fullPath.Substring(8);
            }
            else if (fullPath.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase))
            {
                fullPath = fullPath.Substring(4);
            }
            return Path.TrimEndingDirectorySeparator(Path.GetFullPath(fullPath));
        }

        private static IOException NativeFailure(string message)
        {
            return new IOException(message, new Win32Exception(Marshal.GetLastWin32Error()));
        }

        private sealed class Inspection
        {
            internal Inspection(string finalPath, string identity)
            {
                FinalPath = finalPath;
                Identity = identity;
            }
            internal string FinalPath { get; }
            internal string Identity { get; }
        }
    }
}
'@
}

function Open-VerifiedDirectoryGuard {
    param([string]$Path)
    Initialize-PathGuard
    if (-not [IO.Path]::IsPathFullyQualified($Path)) { throw 'Pilot directory path must be absolute.' }
    $resolved = [IO.Path]::TrimEndingDirectorySeparator([IO.Path]::GetFullPath($Path))
    if ($directoryGuards.ContainsKey($resolved)) { return $directoryGuards[$resolved] }
    $guard = [Ensou.Dsh.PilotEvidence.PathGuard]::OpenDirectory($resolved)
    $directoryGuards[$resolved] = $guard
    $locks.Add($guard)
    return $guard
}

function Assert-DirectoryGuardPathIdentity {
    param([string]$Path)
    Initialize-PathGuard
    $resolved = [IO.Path]::TrimEndingDirectorySeparator([IO.Path]::GetFullPath($Path))
    if (-not $directoryGuards.ContainsKey($resolved)) { throw 'Pilot directory has no locked identity.' }
    $guard = $directoryGuards[$resolved]
    [Ensou.Dsh.PilotEvidence.PathGuard]::AssertDirectoryIdentity(
        $resolved,
        [string]$guard.FinalPath,
        [string]$guard.Identity)
}

function Resolve-CreateOnlyPath {
    param([string]$Path)
    if (-not [IO.Path]::IsPathFullyQualified($Path)) { throw 'Pilot output path must be absolute.' }
    $resolved = [IO.Path]::GetFullPath($Path)
    $parent = Split-Path -Parent $resolved
    Open-VerifiedDirectoryGuard $parent | Out-Null
    if (Test-Path -LiteralPath $resolved) { throw 'Pilot output must be a new create-only file.' }
    return $resolved
}

function Get-Sha256Bytes {
    param([byte[]]$Bytes)
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Bytes)).ToLowerInvariant()
}

function ConvertTo-LowSP256Signature {
    param([Parameter(Mandatory = $true)][byte[]]$Signature)

    if ($Signature.Length -ne 64) {
        throw 'Windows Pilot verifier P-256 signature must contain 64 bytes.'
    }
    $halfOrder = [Convert]::FromHexString(
        '7FFFFFFF800000007FFFFFFFFFFFFFFFDE737D56D38BCF4279DCE5617E3192A8')
    $curveOrder = [Convert]::FromHexString(
        'FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551')
    $isHigh = $false
    for ($index = 0; $index -lt 32; $index++) {
        if ($Signature[$index + 32] -gt $halfOrder[$index]) {
            $isHigh = $true
            break
        }
        if ($Signature[$index + 32] -lt $halfOrder[$index]) {
            break
        }
    }
    if (-not $isHigh) {
        return [byte[]]$Signature.Clone()
    }
    $low = [byte[]]$Signature.Clone()
    $borrow = 0
    for ($index = 31; $index -ge 0; $index--) {
        $difference = [int]$curveOrder[$index] -
            [int]$Signature[$index + 32] - $borrow
        if ($difference -lt 0) {
            $difference += 256
            $borrow = 1
        }
        else {
            $borrow = 0
        }
        $low[$index + 32] = [byte]$difference
    }
    return $low
}

function Import-WindowsPilotVerifierPrivateKey {
    param([Parameter(Mandatory = $true)][string]$Path)

    $snapshot = Open-LockedSnapshot $Path 64KB -IncludeBytes
    $keyBytes = $snapshot.Bytes
    $signer = [Security.Cryptography.ECDsa]::Create()
    try {
        $consumed = 0
        $signer.ImportPkcs8PrivateKey($keyBytes, [ref]$consumed)
        if ($consumed -ne $keyBytes.Length -or $signer.KeySize -ne 256) {
            throw 'Windows Pilot verifier key must be one exact P-256 PKCS#8 private key.'
        }
        $parameters = $signer.ExportParameters($true)
        if ($null -eq $parameters.D -or $parameters.D.Length -ne 32 -or
            $null -eq $parameters.Q.X -or $parameters.Q.X.Length -ne 32 -or
            $null -eq $parameters.Q.Y -or $parameters.Q.Y.Length -ne 32) {
            throw 'Windows Pilot verifier key does not contain one complete P-256 private key.'
        }
        return [pscustomobject]@{Signer=$signer;Snapshot=$snapshot}
    }
    catch {
        $signer.Dispose()
        throw
    }
    finally {
        if ($null -ne $keyBytes) {
            [Security.Cryptography.CryptographicOperations]::ZeroMemory($keyBytes)
            $snapshot.Bytes = $null
        }
    }
}

function Open-LockedSnapshot {
    param([string]$Path,[long]$MaximumBytes,[switch]$IncludeBytes)
    if (-not [IO.Path]::IsPathFullyQualified($Path)) { throw 'Pilot input path must be absolute.' }
    $resolved = [IO.Path]::GetFullPath($Path)
    if ($snapshots.ContainsKey($resolved)) { return $snapshots[$resolved] }
    Open-VerifiedDirectoryGuard (Split-Path -Parent $resolved) | Out-Null
    Initialize-PathGuard
    $opened = [Ensou.Dsh.PilotEvidence.PathGuard]::OpenReadFile($resolved)
    $stream = $opened.Stream
    try {
        if ($stream.Length -le 0 -or $stream.Length -gt $MaximumBytes) {
            throw "Pilot input size is invalid: $resolved"
        }
        $length = $stream.Length
        if ($IncludeBytes) {
            if ($length -gt [int]::MaxValue) { throw "Pilot JSON input is too large: $resolved" }
            $bytes = [byte[]]::new([int]$length)
            $offset = 0
            while ($offset -lt $bytes.Length) {
                $read = $stream.Read($bytes,$offset,$bytes.Length-$offset)
                if ($read -eq 0) { throw "Pilot input ended early: $resolved" }
                $offset += $read
            }
            $sha256 = Get-Sha256Bytes $bytes
        } else {
            $hasher = [Security.Cryptography.SHA256]::Create()
            try { $sha256 = [Convert]::ToHexString($hasher.ComputeHash($stream)).ToLowerInvariant() }
            finally { $hasher.Dispose() }
            $bytes = $null
        }
        if ($stream.Length -ne $length) { throw "Pilot input length changed while locked: $resolved" }
        $stream.Position = 0
        $snapshot = [pscustomobject]@{Path=$opened.FinalPath;Identity=$opened.Identity;Length=$length;Sha256=$sha256;Bytes=$bytes;Stream=$stream}
        $snapshots[$resolved] = $snapshot
        $locks.Add($opened)
        return $snapshot
    } catch { $opened.Dispose(); throw }
}

function Assert-SnapshotPathIdentity {
    param($Snapshot)
    Initialize-PathGuard
    [Ensou.Dsh.PilotEvidence.PathGuard]::AssertFileIdentity(
        [string]$Snapshot.Path,
        [string]$Snapshot.Path,
        [string]$Snapshot.Identity)
}

function Assert-FileReference {
    param($Reference,[long]$MaximumBytes,[switch]$IncludeBytes)
    $snapshot = Open-LockedSnapshot ([string]$Reference.path) $MaximumBytes -IncludeBytes:$IncludeBytes
    if ($snapshot.Length -ne [long]$Reference.sizeBytes -or $snapshot.Sha256 -cne [string]$Reference.sha256) {
        throw "Pilot file reference does not bind exact bytes: $($snapshot.Path)"
    }
    return $snapshot
}

function Assert-NoDuplicateMembers {
    param([Text.Json.JsonElement]$Element,[string]$Label)
    if ($Element.ValueKind -eq [Text.Json.JsonValueKind]::Object) {
        $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($property in $Element.EnumerateObject()) {
            if (-not $names.Add($property.Name)) { throw "$Label contains a duplicate JSON member." }
            Assert-NoDuplicateMembers $property.Value $Label
        }
    } elseif ($Element.ValueKind -eq [Text.Json.JsonValueKind]::Array) {
        foreach ($entry in $Element.EnumerateArray()) { Assert-NoDuplicateMembers $entry $Label }
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
        default { throw 'Windows Pilot JSON contains an unsupported value kind.' }
    }
}

function Convert-StrictJson {
    param([byte[]]$Bytes,[string]$SchemaPath,[string]$Label)
    $json = [Text.UTF8Encoding]::new($false,$true).GetString($Bytes)
    if (-not (Test-Json -Json $json -SchemaFile $SchemaPath -ErrorAction Stop)) {
        throw "$Label does not satisfy its exact JSON schema."
    }
    $options = [Text.Json.JsonDocumentOptions]::new()
    $options.AllowTrailingCommas=$false; $options.CommentHandling=[Text.Json.JsonCommentHandling]::Disallow; $options.MaxDepth=64
    $memory=[IO.MemoryStream]::new($Bytes,$false)
    try {
        $document=[Text.Json.JsonDocument]::Parse($memory,$options)
        try {
            Assert-NoDuplicateMembers $document.RootElement $Label
            return ConvertFrom-StrictJsonElement $document.RootElement
        }
        finally { $document.Dispose() }
    } finally { $memory.Dispose() }
}

function Assert-PilotManifestUri {
    param([string]$Value)
    $uri=$null
    if(-not[Uri]::TryCreate($Value,[UriKind]::Absolute,[ref]$uri)-or
      -not$uri.IsAbsoluteUri-or$uri.Scheme-cne[Uri]::UriSchemeHttps-or
      [string]::IsNullOrWhiteSpace($uri.Host)-or-not[string]::IsNullOrEmpty($uri.UserInfo)-or
      -not[string]::IsNullOrEmpty($uri.Fragment)-or-not[string]::IsNullOrEmpty($uri.Query)-or
      $uri.AbsolutePath-cne'/v2/channels/pilot/release-set.v2.json') {
        throw 'Pilot manifest URI must be an absolute HTTPS URI without userinfo, query, or fragment and with the exact Pilot manifest path.'
    }
}

function Assert-NoSensitiveMembers {
    param([AllowNull()]$Value)
    $forbidden = @('access_token','accesstoken','refresh_token','refreshtoken','provider_token',
      'providertoken','authorization','cookie','set-cookie','applicationsecret','application_secret',
      'corpsecret','secret','privatekey','private_key','oauthcode','oauth_code','oauthstate','oauth_state',
      'wecomcode','wecom_code','corpid','corp_id','userid','user_id','email','phone','mobile',
      'displayname','display_name','employeename','employee_name','name','password','token')
    if ($null -eq $Value -or $Value -is [string] -or $Value -is [ValueType]) { return }
    if ($Value -is [Collections.IEnumerable] -and $Value -isnot [Collections.IDictionary]) {
        foreach ($entry in $Value) { Assert-NoSensitiveMembers $entry }; return
    }
    $properties = if ($Value -is [Collections.IDictionary]) {
        @($Value.Keys | ForEach-Object {[pscustomobject]@{Name=[string]$_;Value=$Value[$_]}})
    } else { @($Value.PSObject.Properties) }
    foreach ($property in $properties) {
        if ($forbidden -contains $property.Name.ToLowerInvariant()) {
            throw "Pilot evidence contains a forbidden secret or identity member: $($property.Name)"
        }
        Assert-NoSensitiveMembers $property.Value
    }
}

function Assert-NonZeroDigests {
    param([AllowNull()]$Value)
    if ($null -eq $Value -or $Value -is [ValueType]) { return }
    if ($Value -is [string]) { if ($Value -ceq ('0'*64)) { throw 'Pilot evidence contains an all-zero digest.' }; return }
    if ($Value -is [Collections.IEnumerable] -and $Value -isnot [Collections.IDictionary]) {
        foreach ($entry in $Value) { Assert-NonZeroDigests $entry }; return
    }
    $properties = if ($Value -is [Collections.IDictionary]) {
        @($Value.Keys | ForEach-Object {[pscustomobject]@{Name=[string]$_;Value=$Value[$_]}})
    } else { @($Value.PSObject.Properties) }
    foreach ($property in $properties) { Assert-NonZeroDigests $property.Value }
}

function Convert-Base64Url {
    param([string]$Value)
    if ($Value.Contains('=') -or $Value -cnotmatch '^[A-Za-z0-9_-]+$') { throw 'Pilot ES256 value is not canonical base64url.' }
    $normalized=$Value.Replace('-','+').Replace('_','/')
    switch ($normalized.Length % 4) { 0 {} 2 {$normalized+='=='} 3 {$normalized+='='} default {throw 'Pilot ES256 value has invalid length.'} }
    return [Convert]::FromBase64String($normalized)
}

function Assert-ContractAttestation {
    param($Envelope)
    if ([string]$Envelope.attestation.keyId -cne $ContractPilotEvidenceKeyId) {
        throw 'Pilot evidence attestation keyId does not match the independent contract root.'
    }
    $payload=[Text.Encoding]::UTF8.GetBytes((@(
      'ensou-dsh-enterprise-windows-pilot-evidence-attestation-v2',[string]$Envelope.schemaVersion,
      [string]$Envelope.evidenceType,[string]$Envelope.body.schemaVersion,[string]$Envelope.body.evidenceType,
      [string]$Envelope.body.sizeBytes,[string]$Envelope.body.sha256) -join "`n"))
    $parameters=[Security.Cryptography.ECParameters]::new()
    $parameters.Curve=[Security.Cryptography.ECCurve+NamedCurves]::nistP256
    $point=[Security.Cryptography.ECPoint]::new(); $point.X=Convert-Base64Url $ContractPilotEvidenceKeyX; $point.Y=Convert-Base64Url $ContractPilotEvidenceKeyY
    $parameters.Q=$point
    $verifier=[Security.Cryptography.ECDsa]::Create($parameters)
    try {
        $signature=Convert-Base64Url ([string]$Envelope.attestation.value)
        if ($signature.Length -ne 64 -or -not $verifier.VerifyData($payload,$signature,
          [Security.Cryptography.HashAlgorithmName]::SHA256,
          [Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)) {
            throw 'Pilot evidence ES256 attestation verification failed.'
        }
    } finally { $verifier.Dispose() }
}

function Assert-ContractReleaseManifest {
    param($Snapshot,$Release,$ReadinessConfig)
    $manifest=[Ensou.Dsh.Enterprise.Installation.EnterpriseReleaseSetManifest]::Parse($Snapshot.Bytes)
    $key=[Ensou.Dsh.Enterprise.Installation.EnterpriseReleasePublicKey]::new(
        $ContractReleaseKeyId,$ContractReleaseKeyX,$ContractReleaseKeyY)
    $policy=[Ensou.Dsh.Enterprise.Installation.EnterpriseReleaseTrustPolicy]::new()
    $policy.Product=[Ensou.Dsh.Enterprise.Installation.EnterpriseReleaseSetContract]::Product
    $policy.Environment=[Ensou.Dsh.Enterprise.Installation.EnterpriseReleaseSetContract]::ProductionEnvironment
    $policy.ExpectedChannel='pilot'
    $policy.CurrentStartupStubProtocol=[Ensou.Dsh.Enterprise.Installation.EnterpriseReleaseSetContract]::CurrentStartupStubProtocol
    $policy.ManifestOrigin=[Uri]::new([string]$ReadinessConfig.launcherTrust.updateManifestOrigin)
    $policy.ArtifactOrigin=[Uri]::new([string]$ReadinessConfig.launcherTrust.updateArtifactOrigin)
    $policy.TrustedKeys=[Ensou.Dsh.Enterprise.Installation.EnterpriseReleasePublicKey[]]@($key)
    [Ensou.Dsh.Enterprise.Installation.EnterpriseReleaseSetValidator]::Verify(
        $manifest,$policy,[DateTimeOffset]::UtcNow)
    if($manifest.ReleaseSetId -cne [string]$Release.releaseSetId -or
      $manifest.Generation -ne [long]$Release.generation -or
      $manifest.Sequence -ne [long]$Release.sequence -or
      $Snapshot.Sha256 -cne [string]$Release.manifestSha256) {
        throw 'Contract release manifest does not bind the expected tuple.'
    }
}

function Assert-ReleaseIdentity {
    param($Actual,$Expected,[string]$Label)
    if ($null -eq $Actual -or $null -eq $Expected -or [string]$Actual.releaseSetId -cne [string]$Expected.releaseSetId -or
      [long]$Actual.generation -ne [long]$Expected.generation -or [long]$Actual.sequence -ne [long]$Expected.sequence -or
      [string]$Actual.manifestSha256 -cne [string]$Expected.manifestSha256 -or
      [string]$Actual.runtimeEntryPointSha256 -cne [string]$Expected.runtimeEntryPointSha256) {
        throw "$Label does not bind the exact release tuple."
    }
}
function Assert-OptionalReleaseIdentity {
    param($Actual,$Expected,[string]$Label)
    if ($null -eq $Expected) { if ($null -ne $Actual) { throw "$Label must be null." }; return }
    Assert-ReleaseIdentity $Actual $Expected $Label
}

function Invoke-Publisher {
    param(
        $ExecutableSnapshot,
        [string[]]$Arguments,
        [object[]]$InputSnapshots=@(),
        [int]$TimeoutMilliseconds=120000)
    Assert-SnapshotPathIdentity $ExecutableSnapshot
    foreach($snapshot in $InputSnapshots){Assert-SnapshotPathIdentity $snapshot}
    $executable=[string]$ExecutableSnapshot.Path
    $start=[Diagnostics.ProcessStartInfo]::new(); $start.FileName=$executable; $start.WorkingDirectory=Split-Path -Parent $executable
    $start.UseShellExecute=$false; $start.CreateNoWindow=$true; $start.WindowStyle=[Diagnostics.ProcessWindowStyle]::Hidden
    $start.RedirectStandardOutput=$true; $start.RedirectStandardError=$true
    $windowsRoot=[Environment]::GetFolderPath([Environment+SpecialFolder]::Windows); $temporaryRoot=[IO.Path]::GetTempPath()
    $start.Environment.Clear(); $start.Environment['SystemRoot']=$windowsRoot; $start.Environment['WINDIR']=$windowsRoot
    $start.Environment['TEMP']=$temporaryRoot; $start.Environment['TMP']=$temporaryRoot; $start.Environment['PATH']=Join-Path $windowsRoot 'System32'
    $start.Environment['DOTNET_ROOT']=Join-Path $temporaryRoot 'ensou-no-system-dotnet'; $start.Environment['DOTNET_MULTILEVEL_LOOKUP']='0'
    $start.Environment['DOTNET_EnableDiagnostics']='0'; $start.Environment['COMPlus_EnableDiagnostics']='0'
    foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
    $process=[Diagnostics.Process]::Start($start); if (-not $process) { throw 'Signed ReleasePublisher process did not start.' }
    try {
        $stdoutTask=$process.StandardOutput.ReadToEndAsync(); $stderrTask=$process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutMilliseconds)) { $process.Kill($true); throw 'Signed ReleasePublisher verification timed out.' }
        return [pscustomobject]@{ExitCode=$process.ExitCode;Stdout=$stdoutTask.GetAwaiter().GetResult();Stderr=$stderrTask.GetAwaiter().GetResult()}
    } finally { $process.Dispose() }
}
function Convert-PublisherJson {
    param($Run,[string]$Label)
    if ($Run.ExitCode -ne 0) { throw "$Label rejected by signed ReleasePublisher." }
    try { return $Run.Stdout | ConvertFrom-Json -Depth 32 } catch { throw "$Label returned invalid JSON." }
}

function Assert-Authenticode {
    param($Snapshot,[string]$ExpectedSigner)
    Assert-SnapshotPathIdentity $Snapshot
    $path=[string]$Snapshot.Path
    $signature=Get-AuthenticodeSignature -LiteralPath $path
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or -not $signature.SignerCertificate -or
      [string]$signature.SignatureType -cne 'Authenticode' -or $null -eq $signature.TimeStamperCertificate) {
        throw "Pilot executable has no valid embedded timestamped Authenticode signature: $path"
    }
    $actualSigner=$signature.SignerCertificate.GetCertHashString([Security.Cryptography.HashAlgorithmName]::SHA256)
    if ($actualSigner -cne $ExpectedSigner.ToUpperInvariant()) { throw "Pilot executable signer does not match compiled readiness trust: $path" }
}

function Write-CreateOnlyBytes {
    param([string]$Path,[byte[]]$Bytes,[long]$MaximumBytes)
    if($Bytes.Length -le 0 -or $Bytes.Length -gt $MaximumBytes){throw 'Pilot output byte count is invalid.'}
    $parent=Split-Path -Parent $Path
    Assert-DirectoryGuardPathIdentity $parent
    $stream=[IO.FileStream]::new($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read,64KB,[IO.FileOptions]::WriteThrough)
    try{
        $identity=[Ensou.Dsh.PilotEvidence.PathGuard]::AssertOpenFilePath($stream.SafeFileHandle,$Path)
        Assert-DirectoryGuardPathIdentity $parent
        [Ensou.Dsh.PilotEvidence.PathGuard]::AssertFileIdentity($Path,$Path,$identity)
        $stream.Write($Bytes);$stream.Flush($true)
        Assert-DirectoryGuardPathIdentity $parent
        [Ensou.Dsh.PilotEvidence.PathGuard]::AssertFileIdentity($Path,$Path,$identity)
    }finally{$stream.Dispose()}
    return (Get-Sha256Bytes $Bytes)
}

function Write-VerificationReport {
    param([string]$Decision,[string]$Code)
    $report=[ordered]@{
      schemaVersion=2;reportType='ensou-dsh-enterprise-windows-pilot-verification-receipt';decision=$Decision
      standaloneAdmissionEvidence=$false;generatedAtUtc=[DateTimeOffset]::UtcNow.ToString('o')
      evidenceEnvelopeSha256=$envelopeSha256;evidenceBodySha256=$bodySha256;pilotEvidenceKeyId=$pilotEvidenceKeyId
      publisherExecutableSha256=$publisherActualSha256;readinessReplayReportSha256=$replayReportSha256
      testRunId=if($null -ne $body){[string]$body.testRunId}else{$null}
      customerAudienceId=if($null -ne $body){[string]$body.customerAudienceId}else{$null}
      targetReleaseSetId=if($null -ne $body){[string]$body.readiness.target.releaseSetId}else{$null}
      targetGeneration=if($null -ne $body){[long]$body.readiness.target.generation}else{$null}
      targetSequence=if($null -ne $body){[long]$body.readiness.target.sequence}else{$null}
      livePilotManifestSha256=$liveManifestSha256;verifiedReleaseManifestSha256=@($verifiedManifestHashes);checks=@($checks)
      failureCode=if($Decision -ceq 'VERIFIED'){$null}else{$Code}
      failureMessage=if($Decision -ceq 'VERIFIED'){$null}else{"Windows Pilot verification failed closed at '$Code'."}
      authentication=[ordered]@{
        algorithm='ES256';purpose='enterprise-windows-pilot-verifier-report'
        keyId=$WindowsPilotVerifierKeyId;encoding='IEEE-P1363'
        canonicalization='ENSOU-R8-CANONICAL-JSON-V1';lowS=$true;value=''
      }
    }
    if ($null -eq $verifierSigner) {
        throw 'Windows Pilot verifier report cannot be emitted without its private authentication key.'
    }
    $payload = EnterpriseProductionPilotEvidence\Get-EnterpriseWindowsPilotVerificationReportPayload `
        -Report $report
    $signature = ConvertTo-LowSP256Signature -Signature ($verifierSigner.SignData(
        $payload,
        [Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation))
    $report.authentication.value =
        EnterpriseProductionPilotEvidence\ConvertTo-R8Base64Url -Bytes $signature
    $json=$report|ConvertTo-Json -Depth 16
    if (-not(Test-Json -Json $json -SchemaFile $verificationReportSchemaPath -ErrorAction Stop)) {
        throw 'Windows Pilot verification receipt does not satisfy its schema.'
    }
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes($json+[Environment]::NewLine)
    [void](Write-CreateOnlyBytes $reportFullPath $bytes 4MB)
}

try {
    foreach($schemaPath in @($envelopeSchemaPath,$bodySchemaPath,$gateSchemaPath,$gateContractSchemaPath,$readinessConfigSchemaPath,$readinessReportSchemaPath,$verificationReportSchemaPath)) {
        if (-not(Test-Json -Json (Get-Content -Raw -LiteralPath $schemaPath) -ErrorAction Stop)) { throw "Pilot schema is invalid JSON: $schemaPath" }
    }
    Add-Check 'schema-set' 'PASS' 'exact v2 evidence and v1 readiness schemas'

    if (-not $ContractOnly) {
        if (-not $IsWindows -or [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -ne [Runtime.InteropServices.Architecture]::X64) {
            throw 'Production Windows Pilot verification requires native Windows x64.'
        }
        $reportFullPath=Resolve-CreateOnlyPath $ReportPath; $replayFullPath=Resolve-CreateOnlyPath $ReadinessReplayReportPath
        if ($reportFullPath -ceq $replayFullPath) { throw 'Verification and readiness replay report paths must differ.' }
        $verifierKey = Import-WindowsPilotVerifierPrivateKey `
            -Path $WindowsPilotVerifierPrivateKeyPath
        $verifierSigner = $verifierKey.Signer
        $verifierKeySnapshot = $verifierKey.Snapshot
        Add-Check 'output-parent-lock' 'PASS' 'handle-verified parent identities locked against rename/delete'
    }

    $envelopeSnapshot=Open-LockedSnapshot $EvidenceEnvelopePath 256KB -IncludeBytes
    $bodySnapshot=Open-LockedSnapshot $EvidenceBodyPath 16MB -IncludeBytes
    $envelopeSha256=$envelopeSnapshot.Sha256; $bodySha256=$bodySnapshot.Sha256
    $envelope=Convert-StrictJson $envelopeSnapshot.Bytes $envelopeSchemaPath 'Windows Pilot evidence envelope'
    $body=Convert-StrictJson $bodySnapshot.Bytes $bodySchemaPath 'Windows Pilot evidence body'
    Assert-PilotManifestUri ([string]$body.pilotManifestUri)
    if([long]$envelope.body.sizeBytes -ne $bodySnapshot.Length -or [string]$envelope.body.sha256 -cne $bodySnapshot.Sha256) {
        throw 'Windows Pilot evidence envelope does not bind the exact body bytes.'
    }
    Assert-NoSensitiveMembers $envelope; Assert-NoSensitiveMembers $body; Assert-NonZeroDigests $envelope; Assert-NonZeroDigests $body
    $bodyText=[Text.UTF8Encoding]::new($false,$true).GetString($bodySnapshot.Bytes)
    if($bodyText -match '(?i)\bBearer\s+[A-Za-z0-9._~+/-]{8,}' -or $bodyText -match '(?i)(access|refresh|provider)[_-]?token\s*[:=]') {
        throw 'Windows Pilot evidence body appears to contain credential material.'
    }
    Add-Check 'strict-attested-body' 'PASS' $bodySnapshot.Sha256

    $runStart=([DateTimeOffset]$body.startedAtUtc).ToUniversalTime()
    $runEnd=([DateTimeOffset]$body.completedAtUtc).ToUniversalTime()
    if($runEnd -le $runStart -or $runEnd-$runStart -lt [TimeSpan]::FromMinutes(15) -or $runEnd -gt [DateTimeOffset]::UtcNow.AddMinutes(5)) {
        throw 'Windows Pilot run window is invalid or shorter than fifteen minutes.'
    }

    $releaseChain=@($body.releaseChain)
    for($index=0;$index -lt $releaseChain.Count;$index++) {
        $release=$releaseChain[$index]; $manifestSnapshot=Assert-FileReference $release.manifest 512KB -IncludeBytes
        if([string]$release.manifestSha256 -cne $manifestSnapshot.Sha256) { throw 'Release-chain manifest binding is inconsistent.' }
        if($index -gt 0 -and ([long]$release.sequence -le [long]$releaseChain[$index-1].sequence -or [long]$release.generation -lt [long]$releaseChain[$index-1].generation)) {
            throw 'Release-chain sequence must strictly increase and generation may not decrease.'
        }
    }
    if(@($releaseChain.releaseSetId|Select-Object -Unique).Count -ne 5) { throw 'Release-chain releaseSetId values must be distinct.' }
    Assert-ReleaseIdentity $body.readiness.target $releaseChain[4] 'Readiness target'
    Add-Check 'release-chain' 'PASS' 'baseline -> first -> second -> failed -> recovery'

    $executableSnapshots=@{}
    foreach($executable in @($body.signedExecutables)) {
        $role=[string]$executable.role; $snapshot=Assert-FileReference $executable.file 1GB
        if((Split-Path -Leaf $snapshot.Path) -cne $requiredExecutableNames[$role]) { throw "Pilot executable filename is invalid for role '$role'." }
        $executableSnapshots[$role]=$snapshot
    }

    $previousCompleted=$runStart
    $primaryExternalHashes=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    for($index=0;$index -lt $gateExpectations.Count;$index++) {
        $gate=@($body.gates)[$index]; $expectation=$gateExpectations[$index]
        if(-not(Test-Json -Json ($gate|ConvertTo-Json -Depth 32 -Compress) -SchemaFile $gateSchemaPath -ErrorAction Stop)) {
            throw "Gate receipt '$($expectation.gate)' does not satisfy its strict schema."
        }
        if([int]$gate.sequenceNumber -ne $index+1 -or [string]$gate.gate -cne $expectation.gate -or [string]$gate.status -cne 'PASS' -or
          [string]$gate.testRunId -cne [string]$body.testRunId -or [string]$gate.customerAudienceId -cne [string]$body.customerAudienceId -or
          [string]$gate.deviceLane -cne $expectation.lane -or [string]$gate.observedProcess.role -cne $expectation.role -or
          [string]$gate.observedProcess.state -cne $expectation.state -or [string]$gate.networkMode -cne $expectation.network -or
          [string]$gate.resultCode -cne $expectation.result) { throw "Gate '$($expectation.gate)' does not match its exact operational contract." }
        $started=([DateTimeOffset]$gate.startedAtUtc).ToUniversalTime()
        $completed=([DateTimeOffset]$gate.completedAtUtc).ToUniversalTime()
        if($started -le $previousCompleted -or $completed -le $started -or $completed -gt $runEnd) { throw "Gate '$($expectation.gate)' timestamps are not strictly monotonic." }
        if($expectation.gate -ceq 'no-visible-console-window' -and $completed-$started -lt [TimeSpan]::FromMinutes(15)) { throw 'No-visible-console-window gate must cover at least fifteen minutes.' }
        $previousCompleted=$completed
        Assert-ReleaseIdentity $gate.releaseTuple.active $releaseChain[[int]$expectation.active] "$($expectation.gate) active tuple"
        $rollbackExpected=if($null -eq $expectation.rollback){$null}else{$releaseChain[[int]$expectation.rollback]}
        $attemptedExpected=if($null -eq $expectation.attempted){$null}else{$releaseChain[[int]$expectation.attempted]}
        Assert-OptionalReleaseIdentity $gate.releaseTuple.rollbackTarget $rollbackExpected "$($expectation.gate) rollback tuple"
        Assert-OptionalReleaseIdentity $gate.releaseTuple.attempted $attemptedExpected "$($expectation.gate) attempted tuple"
        $expectedProcessSha256=switch($expectation.role) {
          'runtime' {[string]$releaseChain[[int]$expectation.active].runtimeEntryPointSha256}
          'previous-runtime' {[string]$releaseChain[[int]$expectation.active].runtimeEntryPointSha256}
          'pilot-observer' {[string]$body.pilotObserverExecutableSha256}
          default {[string]$executableSnapshots[$expectation.role].Sha256}
        }
        if([string]$gate.observedProcess.executableSha256 -cne $expectedProcessSha256) { throw "Gate '$($expectation.gate)' does not bind expected process bytes." }
        if(-not $primaryExternalHashes.Add([string]@($gate.externalEvidence)[0].sha256)) { throw 'Every gate needs a distinct primary external observation hash.' }
    }
    Add-Check 'gate-time-and-tuples' 'PASS' '21 strictly monotonic tuple-bound gate receipts'

    if([string]$body.localDataWitness.historyTreeBeforeSha256 -cne [string]$body.localDataWitness.historyTreeAfterSha256 -or
      [string]$body.localDataWitness.workspaceTreeBeforeSha256 -cne [string]$body.localDataWitness.workspaceTreeAfterSha256) {
        throw 'History or workspace witness changed during Pilot replay.'
    }
    if([string]$body.weComAdmission.installationIdSha256 -cne [string]@($body.deviceLanes)[0].installationIdSha256 -or
      [string]@($body.deviceLanes)[0].installationIdSha256 -ceq [string]@($body.deviceLanes)[1].installationIdSha256) {
        throw 'WeCom admission and device lanes do not bind distinct expected installation IDs.'
    }
    if([string]@($body.deviceLanes)[0].deviceInventorySha256 -ceq [string]@($body.deviceLanes)[1].deviceInventorySha256 -or
      [string]$body.legacySource.inventorySha256 -ceq [string]@($body.deviceLanes)[0].deviceInventorySha256 -or
      [string]$body.legacySource.inventorySha256 -ceq [string]@($body.deviceLanes)[1].deviceInventorySha256) {
        throw 'Clean, legacy, and legacy-source inventories must bind distinct bytes.'
    }
    if([string]$body.weComAdmission.authorizedEmployeeSubjectSha256 -ceq
      [string]$body.weComAdmission.unregisteredEmployeeSubjectSha256) {
        throw 'Authorized and unregistered employee subject digests must differ.'
    }
    Add-Check 'local-data-and-device-lanes' 'PASS' 'history/workspace equal; two device lanes bound'

    $readinessConfigSnapshot=Assert-FileReference $body.readiness.config 1MB -IncludeBytes
    $storedReadinessSnapshot=Assert-FileReference $body.readiness.report 4MB -IncludeBytes
    $readinessConfig=Convert-StrictJson $readinessConfigSnapshot.Bytes $readinessConfigSchemaPath 'Pilot readiness config'
    $storedReadiness=Convert-StrictJson $storedReadinessSnapshot.Bytes $readinessReportSchemaPath 'Pilot readiness report'
    $readinessExecutablePaths=[ordered]@{
      installer=[string]$readinessConfig.installerExecutablePath
      bootstrapper=[string]$readinessConfig.bootstrapperExecutablePath
      launcher=[string]$readinessConfig.launcherExecutablePath
      'client-bootstrapper'=[string]$readinessConfig.clientBootstrapperExecutablePath
      maintenance=[string]$readinessConfig.maintenanceExecutablePath
    }
    foreach($role in $readinessExecutablePaths.Keys) {
      $readinessExecutableSnapshot=Open-LockedSnapshot $readinessExecutablePaths[$role] 1GB
      $attestedExecutableSnapshot=$executableSnapshots[$role]
      if([string]$readinessExecutableSnapshot.Path -cne [string]$attestedExecutableSnapshot.Path -or
        [string]$readinessExecutableSnapshot.Identity -cne [string]$attestedExecutableSnapshot.Identity -or
        [string]$readinessExecutableSnapshot.Sha256 -cne [string]$attestedExecutableSnapshot.Sha256) {
          throw "Pilot executable '$role' does not match the exact file admitted by readiness."
      }
    }
    if([string]$readinessConfig.launcherTrust.updateManifestUri -cne [string]$body.pilotManifestUri -or
      [string]$readinessConfig.releaseSetId -cne [string]$releaseChain[4].releaseSetId -or [long]$readinessConfig.generation -ne [long]$releaseChain[4].generation -or
      [long]$readinessConfig.sequence -ne [long]$releaseChain[4].sequence -or [string]$storedReadiness.decision -cne 'ADMIT' -or
      [string]$storedReadiness.publisherExecutableSha256 -cne [string]$executableSnapshots['release-publisher'].Sha256 -or
      [string]$readinessConfig.brandAuthorization.distributionAudienceId -cne [string]$body.customerAudienceId -or
      [string]$readinessConfig.localDataCompatibilityEvidence.certification.certificationAudienceId -cne [string]$body.customerAudienceId -or
      [string]$storedReadiness.releaseSetId -cne [string]$releaseChain[4].releaseSetId -or [long]$storedReadiness.generation -ne [long]$releaseChain[4].generation -or
      [long]$storedReadiness.sequence -ne [long]$releaseChain[4].sequence -or @($storedReadiness.checks|Where-Object{$_.status -cne 'PASS'}).Count -ne 0) {
        throw 'Stored readiness config/report does not bind the recovery target.'
    }
    Add-Check 'readiness-schema-and-binding' 'PASS' 'complete config/report schemas and recovery target'

    if($ContractOnly) {
        $releaseContractsAssembly=@(
          (Join-Path $repositoryRoot 'src\Ensou.Dsh.Enterprise.ReleaseContracts\bin\Release\net10.0\Ensou.Dsh.Enterprise.ReleaseContracts.dll'),
          (Join-Path $repositoryRoot 'src\Ensou.Dsh.Enterprise.ReleaseContracts\bin\Debug\net10.0\Ensou.Dsh.Enterprise.ReleaseContracts.dll')
        ) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
        if([string]::IsNullOrWhiteSpace([string]$releaseContractsAssembly)) {
            throw 'Contract verification requires the already-built Enterprise ReleaseContracts assembly.'
        }
        Add-Type -Path $releaseContractsAssembly
        foreach($release in $releaseChain) {
            Assert-ContractReleaseManifest $snapshots[[IO.Path]::GetFullPath([string]$release.manifest.path)] $release $readinessConfig
        }
        Add-Check 'five-release-manifest-signatures' 'PASS' 'five real ES256 contract manifests'
        Assert-ContractAttestation $envelope; $pilotEvidenceKeyId=$ContractPilotEvidenceKeyId
        Add-Check 'independent-attestation' 'PASS' $ContractPilotEvidenceKeyId
        return [pscustomobject]@{schemaVersion=2;decision='CONTRACT_VALID';evidenceBodySha256=$bodySnapshot.Sha256;checks=@($checks)}
    }

    $publisherSnapshot=Open-LockedSnapshot $PublisherExecutablePath 1GB; $publisherActualSha256=$publisherSnapshot.Sha256
    if($publisherActualSha256 -cne $PublisherExecutableSha256 -or $publisherSnapshot.Path -cne $executableSnapshots['release-publisher'].Path -or
      $publisherSnapshot.Sha256 -cne $executableSnapshots['release-publisher'].Sha256) { throw 'Pinned ReleasePublisher bytes do not match attested inventory.' }
    Assert-Authenticode $publisherSnapshot $PublisherSignerSha256Thumbprint
    $trustResult=Convert-PublisherJson (Invoke-Publisher -ExecutableSnapshot $publisherSnapshot -Arguments @('--windows-pilot-trust')) 'Publisher compiled Pilot trust'
    if([int]$trustResult.schemaVersion -ne 1 -or [string]$trustResult.trustType -cne 'ensou-dsh-enterprise-windows-pilot-verification-trust' -or
      [string]$trustResult.authenticodeSignerSha256Thumbprint -cne $PublisherSignerSha256Thumbprint.ToUpperInvariant() -or
      [string]$readinessConfig.launcherTrust.authenticodeSignerSha256Thumbprint -cne $PublisherSignerSha256Thumbprint.ToUpperInvariant()) {
        throw 'ReleasePublisher signer pin is not identical to compiled and readiness trust.'
    }
    $pilotEvidenceKeyId=[string]$trustResult.pilotEvidenceKeyId
    if([string]$envelope.attestation.keyId -cne $pilotEvidenceKeyId) { throw 'Evidence keyId does not match signed Publisher compiled trust.' }
    Add-Check 'publisher-authenticode-and-compiled-trust' 'PASS' $publisherActualSha256

    foreach($role in $requiredExecutableNames.Keys) { Assert-Authenticode $executableSnapshots[$role] $PublisherSignerSha256Thumbprint }
    Add-Check 'signed-executable-inventory' 'PASS' 'six embedded timestamped Authenticode binaries'

    $readinessRun=Invoke-Publisher -ExecutableSnapshot $publisherSnapshot `
      -Arguments @('--pilot-readiness-config',$readinessConfigSnapshot.Path,'--report-stdout') `
      -InputSnapshots @($readinessConfigSnapshot)
    if($readinessRun.ExitCode -ne 0 -or [string]::IsNullOrWhiteSpace([string]$readinessRun.Stdout)) {
        throw 'Fresh signed Publisher readiness replay did not return an admitting machine report.'
    }
    $replayBytes=[Text.UTF8Encoding]::new($false,$true).GetBytes([string]$readinessRun.Stdout)
    if($replayBytes.Length -gt 4MB){throw 'Fresh signed Publisher readiness replay report is too large.'}
    $replayReport=Convert-StrictJson $replayBytes $readinessReportSchemaPath 'Replayed Pilot readiness report'
    $replayReportSha256=Get-Sha256Bytes $replayBytes
    if($readinessRun.ExitCode -ne 0 -or [string]$replayReport.decision -cne 'ADMIT' -or
      [string]$replayReport.publisherExecutableSha256 -cne $publisherActualSha256 -or [string]$replayReport.releaseSetId -cne [string]$releaseChain[4].releaseSetId -or
      [long]$replayReport.generation -ne [long]$releaseChain[4].generation -or [long]$replayReport.sequence -ne [long]$releaseChain[4].sequence -or
      @($replayReport.checks|Where-Object{$_.status -cne 'PASS'}).Count -ne 0) { throw 'Fresh signed Publisher readiness replay did not ADMIT recovery target.' }
    $writtenReplaySha256=Write-CreateOnlyBytes $replayFullPath $replayBytes 4MB
    if($writtenReplaySha256 -cne $replayReportSha256){throw 'Readiness replay output copy does not bind captured Publisher stdout.'}
    Add-Check 'fresh-readiness-replay' 'PASS' $replayReportSha256

    $attestationResult=Convert-PublisherJson (Invoke-Publisher -ExecutableSnapshot $publisherSnapshot `
      -Arguments @('--verify-windows-pilot-attestation','--evidence-envelope',$envelopeSnapshot.Path,
        '--evidence-body',$bodySnapshot.Path,'--pilot-readiness-config',$readinessConfigSnapshot.Path) `
      -InputSnapshots @($envelopeSnapshot,$bodySnapshot,$readinessConfigSnapshot)) 'Windows Pilot evidence attestation'
    if([string]$attestationResult.status -cne 'VERIFIED' -or [string]$attestationResult.pilotEvidenceKeyId -cne $pilotEvidenceKeyId -or
      [string]$attestationResult.bodySha256 -cne $bodySnapshot.Sha256 -or [long]$attestationResult.bodySizeBytes -ne $bodySnapshot.Length) {
        throw 'Signed Publisher did not verify exact attested body.'
    }
    Add-Check 'independent-attestation' 'PASS' $pilotEvidenceKeyId

    $verifiedManifestHashes=@()
    foreach($release in $releaseChain) {
        $manifestSnapshot=$snapshots[[IO.Path]::GetFullPath([string]$release.manifest.path)]
        $manifestRun=Convert-PublisherJson (Invoke-Publisher -ExecutableSnapshot $publisherSnapshot `
          -Arguments @('--verify-windows-pilot-manifest','--pilot-readiness-config',$readinessConfigSnapshot.Path,
            '--release-manifest',$manifestSnapshot.Path) `
          -InputSnapshots @($readinessConfigSnapshot,$manifestSnapshot)) "release manifest $($release.stage)"
        if([string]$manifestRun.status -cne 'VERIFIED' -or [string]$manifestRun.releaseSetId -cne [string]$release.releaseSetId -or
          [long]$manifestRun.generation -ne [long]$release.generation -or [long]$manifestRun.sequence -ne [long]$release.sequence -or
          [string]$manifestRun.manifestSha256 -cne [string]$release.manifestSha256 -or [string]$manifestRun.releaseKeyId -cne [string]$readinessConfig.launcherTrust.releaseKeyId) {
            throw "Release manifest '$($release.stage)' failed exact ES256 tuple verification."
        }
        $verifiedManifestHashes += [string]$manifestRun.manifestSha256
    }
    Add-Check 'five-release-manifest-signatures' 'PASS' 'five ES256 release-set manifests'

    $liveResult=Convert-PublisherJson (Invoke-Publisher -ExecutableSnapshot $publisherSnapshot `
      -Arguments @('--verify-windows-pilot-live-head','--pilot-readiness-config',$readinessConfigSnapshot.Path) `
      -InputSnapshots @($readinessConfigSnapshot)) 'live Pilot head'
    if([string]$liveResult.status -cne 'VERIFIED' -or [string]$liveResult.releaseSetId -cne [string]$releaseChain[4].releaseSetId -or
      [long]$liveResult.generation -ne [long]$releaseChain[4].generation -or [long]$liveResult.sequence -ne [long]$releaseChain[4].sequence -or
      [string]$liveResult.manifestSha256 -cne [string]$releaseChain[4].manifestSha256) { throw 'Live Pilot head is not signed recovery target.' }
    $liveManifestSha256=[string]$liveResult.manifestSha256; Add-Check 'live-pilot-head-signature' 'PASS' $liveManifestSha256

    Write-VerificationReport 'VERIFIED' ''
    Write-Output ([pscustomobject]@{decision='VERIFIED';signedPilotDecision=[string]$body.pilotDecision;reportPath=$reportFullPath;evidenceBodySha256=$bodySnapshot.Sha256})
} catch {
    $code=if($checks.Count -eq 0){'verification-initialization'}else{'verification-failed-closed'}
    Add-Check $code 'FAIL' 'fail-closed'
    if(-not $ContractOnly -and $null -ne $verifierSigner -and
      $null -ne $reportFullPath -and -not(Test-Path -LiteralPath $reportFullPath)) {
        Write-VerificationReport 'REJECT' $code
    }
    throw
} finally {
    if($null -ne $verifierSigner){$verifierSigner.Dispose()}
    for($index=$locks.Count-1;$index -ge 0;$index--){$locks[$index].Dispose()}
}
