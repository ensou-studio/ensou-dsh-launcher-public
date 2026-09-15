#requires -Version 7.2

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:Utf8Strict = [Text.UTF8Encoding]::new($false, $true)
$script:WholeSecondUtcFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'"
$script:MaximumJsonBytes = 4MB
$script:AllowedStateEntries = @(
    'head.json',
    'identity.json',
    'initialization.json',
    'imports',
    'plan.json',
    'receipts',
    'requests',
    'state.lock'
)

function Get-ProductionReleaseLifecycleContract {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet(1, 2)]
        [int]$SchemaVersion,

        [Parameter(Mandatory = $true)]
        [ValidateSet('pilot', 'stable')]
        [string]$TargetChannel
    )

    $phaseNames = if ($SchemaVersion -eq 1) {
        @(
            'PLAN_ADMITTED',
            'CLIENT_SIGNING_REQUESTED',
            'CLIENT_SIGNATURES_IMPORTED'
        )
    }
    elseif ($TargetChannel -ceq 'pilot') {
        @(
            'PLAN_ADMITTED',
            'CLIENT_SIGNING_REQUESTED',
            'CLIENT_SIGNATURES_IMPORTED',
            'PILOT_MANIFEST_SIGNING_REQUESTED',
            'PILOT_SIGNED_CANDIDATE_IMPORTED',
            'INSTALLER_SIGNING_REQUESTED',
            'INSTALLER_SIGNATURE_IMPORTED',
            'PILOT_PROMOTION_REQUESTED',
            'PILOT_FEED_PROMOTED'
        )
    }
    else {
        @(
            'PLAN_ADMITTED',
            'CLIENT_SIGNING_REQUESTED',
            'CLIENT_SIGNATURES_IMPORTED',
            'STABLE_MANIFEST_SIGNING_REQUESTED',
            'STABLE_SIGNED_CANDIDATE_IMPORTED',
            'INSTALLER_SIGNING_REQUESTED',
            'INSTALLER_SIGNATURE_IMPORTED',
            'PILOT_EVIDENCE_BOUND',
            'STABLE_PROMOTION_REQUESTED',
            'STABLE_FEED_PROMOTED'
        )
    }
    $terminalRevision = $phaseNames.Count
    $transitions = [Collections.Generic.List[object]]::new()
    for ($index = 0; $index -lt $terminalRevision; $index++) {
        $transitions.Add([pscustomobject]@{
            Revision = $index + 1
            Phase = [string]$phaseNames[$index]
            PreviousPhase = if ($index -eq 0) { $null } else { [string]$phaseNames[$index - 1] }
            Terminal = ($index + 1 -eq $terminalRevision)
        })
    }
    return [pscustomobject]@{
        SchemaVersion = $SchemaVersion
        TargetChannel = $TargetChannel
        Transitions = @($transitions)
        TerminalRevision = $terminalRevision
        TerminalPhase = [string]$phaseNames[$terminalRevision - 1]
    }
}

function Get-ProductionManifestChannelContract {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('pilot', 'stable')]
        [string]$TargetChannel
    )

    $phasePrefix = $TargetChannel.ToUpperInvariant()
    return [pscustomobject]@{
        TargetChannel = $TargetChannel
        RequestBundleName = "$TargetChannel-manifest-publishing.v1"
        CandidateBundleName = "$TargetChannel-signed-candidate.v1"
        RequestPhase = "${phasePrefix}_MANIFEST_SIGNING_REQUESTED"
        CandidatePhase = "${phasePrefix}_SIGNED_CANDIDATE_IMPORTED"
        RequestType = 'ensou-dsh-launcher-manifest-publishing-request'
        ResponseType = 'ensou-dsh-launcher-manifest-publishing-response'
    }
}

function Assert-ProductionReleaseLifecycleSequence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet(1, 2)]
        [int]$SchemaVersion,

        [Parameter(Mandatory = $true)]
        [ValidateSet('pilot', 'stable')]
        [string]$TargetChannel,

        [AllowEmptyCollection()]
        [string[]]$Phases = @()
    )

    $contract = Get-ProductionReleaseLifecycleContract -SchemaVersion $SchemaVersion -TargetChannel $TargetChannel
    if ($Phases.Count -gt $contract.TerminalRevision) {
        throw "Production lifecycle contains a transition after terminal phase '$($contract.TerminalPhase)'."
    }
    for ($index = 0; $index -lt $Phases.Count; $index++) {
        $expected = $contract.Transitions[$index]
        $actualPrevious = if ($index -eq 0) { $null } else { [string]$Phases[$index - 1] }
        [void](Assert-ProductionReleaseTransitionContract -SchemaVersion $SchemaVersion -TargetChannel $TargetChannel -Revision ($index + 1) -Phase ([string]$Phases[$index]) -PreviousPhase $actualPrevious)
    }
    return $contract
}

function Assert-ProductionReleaseTransitionContract {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateSet(1, 2)][int]$SchemaVersion,
        [Parameter(Mandatory = $true)][ValidateSet('pilot', 'stable')][string]$TargetChannel,
        [Parameter(Mandatory = $true)][int]$Revision,
        [Parameter(Mandatory = $true)][string]$Phase,
        [AllowNull()][string]$PreviousPhase
    )

    $contract = Get-ProductionReleaseLifecycleContract -SchemaVersion $SchemaVersion -TargetChannel $TargetChannel
    if ($Revision -lt 1 -or $Revision -gt [int]$contract.TerminalRevision) {
        throw "Production lifecycle revision $Revision is outside the target lifecycle."
    }
    $expected = $contract.Transitions[$Revision - 1]
    if ($Phase -cne [string]$expected.Phase -or
        [string]$PreviousPhase -cne [string]$expected.PreviousPhase) {
        throw "Production lifecycle revision $Revision requires phase '$($expected.Phase)' after '$($expected.PreviousPhase)', got '$Phase' after '$PreviousPhase'."
    }
    return $expected
}

if (-not $IsWindows) {
    throw 'Launcher production preparation and Authenticode import require Windows.'
}

Add-Type -AssemblyName System.Security.Cryptography.Pkcs

if (-not ('EnsouLauncherProduction.NativeFileIdentity' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace EnsouLauncherProduction
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
        private const uint FileListDirectory = 0x0001;
        private const uint FileReadAttributes = 0x0080;
        private const uint Delete = 0x00010000;
        private const uint FileShareRead = 0x00000001;
        private const uint FileShareDelete = 0x00000004;
        private const uint OpenExisting = 3;
        private const uint FileFlagOpenReparsePoint = 0x00200000;
        private const uint FileFlagBackupSemantics = 0x02000000;
        private const int FileRenameInfo = 3;

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
        private static extern SafeFileHandle CreateFileW(
            string fileName,
            uint desiredAccess,
            uint shareMode,
            IntPtr securityAttributes,
            uint creationDisposition,
            uint flagsAndAttributes,
            IntPtr templateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetFileInformationByHandle(
            SafeFileHandle file,
            int fileInformationClass,
            IntPtr fileInformation,
            uint bufferSize);

        private static string ToExtendedDirectoryPath(string path)
        {
            // Only the native boundary uses extended syntax; callers retain their
            // canonical logical paths for identity, inventory and same-volume checks.
            if (path.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
                path = @"\\" + path.Substring(8);
            else if (path.StartsWith(@"\\?\", StringComparison.Ordinal))
                path = path.Substring(4);
            if (!Path.IsPathFullyQualified(path)
                || path.StartsWith(@"\\.\", StringComparison.Ordinal)
                || path.StartsWith(@"\\?\", StringComparison.Ordinal))
                throw new InvalidDataException("Directory lease requires an absolute DOS or UNC path.");
            var full = Path.GetFullPath(path);
            if (full.StartsWith(@"\\", StringComparison.Ordinal))
                return @"\\?\UNC\" + full.Substring(2);
            if (full.Length >= 3
                && ((full[0] >= 'A' && full[0] <= 'Z')
                    || (full[0] >= 'a' && full[0] <= 'z'))
                && full[1] == ':' && full[2] == '\\')
                return @"\\?\" + full;
            throw new InvalidDataException("Directory lease requires an absolute DOS or UNC path.");
        }

        public static SafeFileHandle OpenDirectoryReadLease(string path)
        {
            var handle = CreateFileW(
                ToExtendedDirectoryPath(path),
                FileListDirectory | FileReadAttributes,
                FileShareRead | FileShareDelete,
                IntPtr.Zero,
                OpenExisting,
                FileFlagBackupSemantics | FileFlagOpenReparsePoint,
                IntPtr.Zero);
            if (handle == null || handle.IsInvalid)
            {
                var error = Marshal.GetLastWin32Error();
                handle?.Dispose();
                throw new Win32Exception(
                    error,
                    "Could not lock production-release directory.");
            }
            try
            {
                RequireOrdinaryDirectory(handle);
                return handle;
            }
            catch
            {
                handle.Dispose();
                throw;
            }
        }

        public static SafeFileHandle OpenDirectoryMoveLease(string path)
        {
            var handle = CreateFileW(
                ToExtendedDirectoryPath(path),
                FileListDirectory | FileReadAttributes | Delete,
                FileShareRead,
                IntPtr.Zero,
                OpenExisting,
                FileFlagBackupSemantics | FileFlagOpenReparsePoint,
                IntPtr.Zero);
            if (handle == null || handle.IsInvalid)
            {
                var error = Marshal.GetLastWin32Error();
                handle?.Dispose();
                throw new Win32Exception(
                    error,
                    "Could not lock production-release directory for atomic publication.");
            }
            try
            {
                RequireOrdinaryDirectory(handle);
                return handle;
            }
            catch
            {
                handle.Dispose();
                throw;
            }
        }

        public static void MoveDirectoryLease(
            SafeFileHandle handle,
            string destinationPath)
        {
            RequireOrdinaryDirectory(handle);
            // FileRenameInfo accepts the absolute extended DOS/UNC target, not
            // an NT object-manager (\??\) name. FileNameLength remains UTF-16 bytes.
            var fileName = System.Text.Encoding.Unicode.GetBytes(
                ToExtendedDirectoryPath(destinationPath));
            var rootOffset = IntPtr.Size == 8 ? 8 : 4;
            var lengthOffset = rootOffset + IntPtr.Size;
            var nameOffset = lengthOffset + sizeof(uint);
            // Reserve the native trailing WCHAR in addition to FileNameLength.
            // Windows consumes FileNameLength bytes, while the terminator keeps
            // older FileRenameInfo implementations from reading past the buffer.
            var bufferSize = checked(nameOffset + fileName.Length + sizeof(char));
            var buffer = Marshal.AllocHGlobal(bufferSize);
            try
            {
                for (var i = 0; i < bufferSize; i++)
                {
                    Marshal.WriteByte(buffer, i, 0);
                }
                Marshal.WriteByte(buffer, 0, 0); // ReplaceIfExists = FALSE.
                Marshal.WriteIntPtr(buffer, rootOffset, IntPtr.Zero);
                Marshal.WriteInt32(buffer, lengthOffset, fileName.Length);
                Marshal.Copy(fileName, 0, IntPtr.Add(buffer, nameOffset), fileName.Length);
                if (!SetFileInformationByHandle(
                        handle,
                        FileRenameInfo,
                        buffer,
                        checked((uint)bufferSize)))
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "Could not atomically publish the locked production-release directory.");
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        public static ExactFileIdentity RequireOrdinaryDirectory(
            SafeFileHandle handle)
        {
            if (handle == null || handle.IsInvalid || handle.IsClosed)
            {
                throw new InvalidDataException(
                    "Production-release directory handle is invalid.");
            }
            if (!GetFileInformationByHandle(handle, out var information))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "Could not inspect production-release directory identity.");
            }
            const uint directory = 0x10;
            const uint reparsePoint = 0x400;
            if ((information.FileAttributes & directory) == 0
                || (information.FileAttributes & reparsePoint) != 0)
            {
                throw new InvalidDataException(
                    "Production-release directory must be ordinary and non-linked.");
            }
            var index = ((ulong)information.FileIndexHigh << 32)
                | information.FileIndexLow;
            return new ExactFileIdentity(information.VolumeSerialNumber, index);
        }

        public static ExactFileIdentity RequireOrdinarySingleLink(SafeFileHandle handle)
        {
            if (handle == null || handle.IsInvalid || handle.IsClosed)
            {
                throw new InvalidDataException("Production-release input handle is invalid.");
            }
            if (!GetFileInformationByHandle(handle, out var information))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "Could not inspect production-release file identity.");
            }
            const uint directory = 0x10;
            const uint reparsePoint = 0x400;
            if (information.NumberOfLinks != 1
                || (information.FileAttributes & (directory | reparsePoint)) != 0)
            {
                throw new InvalidDataException(
                    "Production-release files must be ordinary single-link files.");
            }
            var index = ((ulong)information.FileIndexHigh << 32)
                | information.FileIndexLow;
            return new ExactFileIdentity(information.VolumeSerialNumber, index);
        }
    }
}
'@
}

function ConvertTo-ProductionUtc {
    param([Parameter(Mandatory = $true)][DateTimeOffset]$Value)

    return $Value.ToUniversalTime().ToString(
        $script:WholeSecondUtcFormat,
        [Globalization.CultureInfo]::InvariantCulture)
}

function ConvertFrom-ProductionUtc {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$Label
    )

    [DateTimeOffset]$parsed = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParseExact(
            $Value,
            $script:WholeSecondUtcFormat,
            [Globalization.CultureInfo]::InvariantCulture,
            ([Globalization.DateTimeStyles]::AssumeUniversal -bor
             [Globalization.DateTimeStyles]::AdjustToUniversal),
            [ref]$parsed)) {
        throw "$Label must be an exact whole-second UTC timestamp: '$Value'."
    }
    return $parsed.ToUniversalTime()
}

function Get-ProductionSha256Bytes {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [ValidateNotNull()]
        [byte[]]$Bytes
    )

    return ([Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($Bytes))).ToLowerInvariant()
}

function Get-ProductionStreamSha256 {
    param([Parameter(Mandatory = $true)][IO.Stream]$Stream)

    if (-not $Stream.CanSeek) {
        throw 'Production-release SHA-256 stream must be seekable.'
    }
    $Stream.Position = 0
    $sha256 = ([Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($Stream))).ToLowerInvariant()
    $Stream.Position = 0
    return $sha256
}

function ConvertTo-ProductionJsonBytes {
    param([Parameter(Mandatory = $true)]$Value)

    $json = $Value | Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 64 -Compress
    return $script:Utf8Strict.GetBytes($json)
}

function ConvertTo-ProductionSystemTextJsonBytes {
    param([Parameter(Mandatory = $true)]$Value)

    $sourceBytes = ConvertTo-ProductionJsonBytes -Value $Value
    $sourceStream = [IO.MemoryStream]::new($sourceBytes, $false)
    $document = $null
    $outputStream = [IO.MemoryStream]::new()
    $writer = $null
    try {
        $document = [Text.Json.JsonDocument]::Parse($sourceStream)
        $writer = [Text.Json.Utf8JsonWriter]::new($outputStream)
        $document.RootElement.WriteTo($writer)
        $writer.Flush()
        return $outputStream.ToArray()
    }
    finally {
        if ($null -ne $writer) {
            $writer.Dispose()
        }
        if ($null -ne $document) {
            $document.Dispose()
        }
        $outputStream.Dispose()
        $sourceStream.Dispose()
    }
}

function ConvertTo-ProductionEnterpriseReleaseManifestPayloadBytes {
    param([Parameter(Mandatory = $true)][psobject]$Manifest)

    $issuedAtUtc = ConvertFrom-ProductionReleaseManifestUtc `
        -Value ([string]$Manifest.issuedAtUtc) `
        -Edition Enterprise `
        -Label 'Enterprise release-manifest payload issuedAtUtc'
    $expiresAtUtc = ConvertFrom-ProductionReleaseManifestUtc `
        -Value ([string]$Manifest.expiresAtUtc) `
        -Edition Enterprise `
        -Label 'Enterprise release-manifest payload expiresAtUtc'
    $stream = [IO.MemoryStream]::new()
    $writer = [Text.Json.Utf8JsonWriter]::new($stream)
    try {
        $writer.WriteStartObject()
        $writer.WriteNumber('schemaVersion', [int]$Manifest.schemaVersion)
        $writer.WriteString('product', [string]$Manifest.product)
        $writer.WriteString('environment', [string]$Manifest.environment)
        $writer.WriteString('channel', [string]$Manifest.channel)
        $writer.WriteString('releaseSetId', [string]$Manifest.releaseSetId)
        $writer.WriteNumber('generation', [int64]$Manifest.generation)
        $writer.WriteNumber('sequence', [int64]$Manifest.sequence)
        $writer.WriteNumber(
            'minAcceptedSequence',
            [int64]$Manifest.minAcceptedSequence)
        $writer.WriteString('issuedAtUtc', [DateTimeOffset]$issuedAtUtc)
        $writer.WriteString('expiresAtUtc', [DateTimeOffset]$expiresAtUtc)
        $writer.WritePropertyName('startupStub')
        $writer.WriteStartObject()
        $writer.WriteNumber(
            'minimumProtocol',
            [int]$Manifest.startupStub.minimumProtocol)
        $writer.WriteNumber(
            'maximumProtocol',
            [int]$Manifest.startupStub.maximumProtocol)
        $writer.WriteEndObject()
        $writer.WritePropertyName('revokedReleaseSetIds')
        $writer.WriteStartArray()
        foreach ($revoked in @($Manifest.revokedReleaseSetIds)) {
            $writer.WriteStringValue([string]$revoked)
        }
        $writer.WriteEndArray()
        $writer.WritePropertyName('artifacts')
        $writer.WriteStartArray()
        foreach ($artifact in @($Manifest.artifacts)) {
            $artifactUri = [Uri]::new(
                [string]$artifact.uri,
                [UriKind]::Absolute)
            $writer.WriteStartObject()
            $writer.WriteString('component', [string]$artifact.component)
            $writer.WriteString('releaseId', [string]$artifact.releaseId)
            $writer.WriteString('uri', [string]$artifactUri.AbsoluteUri)
            $writer.WriteNumber('sizeBytes', [int64]$artifact.sizeBytes)
            $writer.WriteString('sha256', [string]$artifact.sha256)
            $writer.WriteString(
                'completeTreeSha256',
                [string]$artifact.completeTreeSha256)
            $writer.WritePropertyName('signature')
            $writer.WriteStartObject()
            $writer.WriteString(
                'algorithm',
                [string]$artifact.signature.algorithm)
            $writer.WriteString('keyId', [string]$artifact.signature.keyId)
            $writer.WriteString('value', [string]$artifact.signature.value)
            $writer.WriteEndObject()
            $writer.WriteEndObject()
        }
        $writer.WriteEndArray()
        $writer.WriteEndObject()
        $writer.Flush()
        return $stream.ToArray()
    }
    finally {
        $writer.Dispose()
        $stream.Dispose()
    }
}

function Assert-NoDuplicateProductionJsonMembers {
    param(
        [Parameter(Mandatory = $true)][Text.Json.JsonElement]$Element,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ($Element.ValueKind -eq [Text.Json.JsonValueKind]::Object) {
        $names = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::Ordinal)
        foreach ($property in $Element.EnumerateObject()) {
            if (-not $names.Add($property.Name)) {
                throw "$Label contains duplicate JSON member '$($property.Name)'."
            }
            Assert-NoDuplicateProductionJsonMembers -Element $property.Value -Label $Label
        }
    }
    elseif ($Element.ValueKind -eq [Text.Json.JsonValueKind]::Array) {
        foreach ($item in $Element.EnumerateArray()) {
            Assert-NoDuplicateProductionJsonMembers -Element $item -Label $Label
        }
    }
}

function ConvertFrom-StrictProductionJsonBytes {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][string]$Label,
        [string]$SchemaPath = ''
    )

    if ($Bytes.Length -le 0 -or $Bytes.Length -gt $script:MaximumJsonBytes) {
        throw "$Label is empty or exceeds the JSON byte bound."
    }
    try {
        $text = $script:Utf8Strict.GetString($Bytes)
    }
    catch {
        throw "$Label is not strict UTF-8."
    }
    $options = [Text.Json.JsonDocumentOptions]::new()
    $options.AllowTrailingCommas = $false
    $options.CommentHandling = [Text.Json.JsonCommentHandling]::Disallow
    try {
        $document = [Text.Json.JsonDocument]::Parse($text, $options)
    }
    catch {
        throw "$Label is not strict JSON."
    }
    try {
        Assert-NoDuplicateProductionJsonMembers -Element $document.RootElement -Label $Label
    }
    finally {
        $document.Dispose()
    }
    if ($SchemaPath) {
        $schema = Resolve-OrdinaryProductionFile -Path $SchemaPath -Label "$Label schema"
        if (-not (Microsoft.PowerShell.Utility\Test-Json -Json $text -SchemaFile $schema -ErrorAction Stop)) {
            throw "$Label does not satisfy its strict schema."
        }
    }
    return $text | Microsoft.PowerShell.Utility\ConvertFrom-Json -Depth 64 -DateKind String
}

function Assert-OrdinaryProductionDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )

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

function Resolve-OrdinaryProductionFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if (-not [IO.Path]::IsPathFullyQualified($Path)) {
        throw "$Label path must be absolute."
    }
    $fullPath = [IO.Path]::GetFullPath($Path)
    $item = Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $item.Length -le 0) {
        throw "$Label must be one ordinary non-empty file: $fullPath"
    }
    [void](Assert-OrdinaryProductionDirectory -Path $item.Directory.FullName -Label "$Label parent")
    return $fullPath
}

function Open-ProductionReleaseInput {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][int64]$MaximumBytes
    )

    $fullPath = Resolve-OrdinaryProductionFile -Path $Path -Label $Label
    $stream = [IO.File]::Open(
        $fullPath,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    try {
        $identity = [EnsouLauncherProduction.NativeFileIdentity]::RequireOrdinarySingleLink(
            $stream.SafeFileHandle)
        if ($stream.Length -le 0 -or $stream.Length -gt $MaximumBytes) {
            throw "$Label is empty or exceeds its byte bound."
        }
        $sha256 = Get-ProductionStreamSha256 -Stream $stream
        $pathStream = [IO.File]::Open(
            (Resolve-OrdinaryProductionFile -Path $fullPath -Label $Label),
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read)
        try {
            $pathIdentity = [EnsouLauncherProduction.NativeFileIdentity]::RequireOrdinarySingleLink(
                $pathStream.SafeFileHandle)
            if ($pathIdentity.VolumeSerialNumber -ne $identity.VolumeSerialNumber -or
                $pathIdentity.FileIndex -ne $identity.FileIndex) {
                throw "$Label path no longer names the locked file."
            }
        }
        finally {
            $pathStream.Dispose()
        }
        return [pscustomobject]@{
            Path = $fullPath
            FileName = [IO.Path]::GetFileName($fullPath)
            SizeBytes = $stream.Length
            Sha256 = $sha256
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

function Assert-ProductionReleaseInputStillLocked {
    param(
        [Parameter(Mandatory = $true)]$Descriptor,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $pathStream = [IO.File]::Open(
        (Resolve-OrdinaryProductionFile -Path $Descriptor.Path -Label $Label),
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    try {
        $identity = [EnsouLauncherProduction.NativeFileIdentity]::RequireOrdinarySingleLink(
            $pathStream.SafeFileHandle)
        if ($identity.VolumeSerialNumber -ne $Descriptor.VolumeSerialNumber -or
            $identity.FileIndex -ne $Descriptor.FileIndex -or
            $pathStream.Length -ne $Descriptor.SizeBytes -or
            (Get-ProductionStreamSha256 -Stream $pathStream) -cne $Descriptor.Sha256) {
            throw "$Label changed after admission."
        }
    }
    finally {
        $pathStream.Dispose()
    }
}

function Read-ProductionReleaseInputBytes {
    param(
        [Parameter(Mandatory = $true)]$Descriptor,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ($Descriptor.SizeBytes -gt [int]::MaxValue) {
        throw "$Label is too large to snapshot in memory."
    }
    $Descriptor.Stream.Position = 0
    $bytes = [byte[]]::new([int]$Descriptor.SizeBytes)
    $offset = 0
    while ($offset -lt $bytes.Length) {
        $read = $Descriptor.Stream.Read($bytes, $offset, $bytes.Length - $offset)
        if ($read -eq 0) {
            throw "$Label ended before its admitted size."
        }
        $offset += $read
    }
    if ($Descriptor.Stream.ReadByte() -ne -1) {
        throw "$Label grew after admission."
    }
    $Descriptor.Stream.Position = 0
    if ((Get-ProductionSha256Bytes -Bytes $bytes) -cne $Descriptor.Sha256) {
        throw "$Label bytes changed after admission."
    }
    return $bytes
}

function Read-StrictProductionJsonFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label,
        [string]$SchemaPath = ''
    )

    $input = Open-ProductionReleaseInput -Path $Path -Label $Label -MaximumBytes $script:MaximumJsonBytes
    try {
        $bytes = Read-ProductionReleaseInputBytes -Descriptor $input -Label $Label
        $value = ConvertFrom-StrictProductionJsonBytes -Bytes $bytes -Label $Label -SchemaPath $SchemaPath
        return [pscustomobject]@{
            Path = $input.Path
            Bytes = $bytes
            Sha256 = $input.Sha256
            Value = $value
        }
    }
    finally {
        $input.Stream.Dispose()
    }
}

function Get-PeContentSha256 {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    if ($Bytes.Length -lt 256 -or $Bytes[0] -ne 0x4d -or $Bytes[1] -ne 0x5a) {
        throw 'Authenticode input is not a bounded Windows PE image.'
    }
    $peOffset = [BitConverter]::ToInt32($Bytes, 0x3c)
    if ($peOffset -lt 0x40 -or $peOffset -gt $Bytes.Length - 256 -or
        $Bytes[$peOffset] -ne 0x50 -or
        $Bytes[$peOffset + 1] -ne 0x45 -or
        $Bytes[$peOffset + 2] -ne 0 -or
        $Bytes[$peOffset + 3] -ne 0) {
        throw 'Authenticode input has an invalid PE header.'
    }
    $optionalSize = [BitConverter]::ToUInt16($Bytes, $peOffset + 20)
    $optionalOffset = $peOffset + 24
    if ($optionalSize -lt 128 -or $optionalOffset + $optionalSize -gt $Bytes.Length) {
        throw 'Authenticode input has an invalid optional header.'
    }
    $magic = [BitConverter]::ToUInt16($Bytes, $optionalOffset)
    if ($magic -eq 0x10b) {
        $dataDirectoryOffset = $optionalOffset + 96
    }
    elseif ($magic -eq 0x20b) {
        $dataDirectoryOffset = $optionalOffset + 112
    }
    else {
        throw 'Authenticode input has an unsupported PE optional header.'
    }
    $checksumOffset = $optionalOffset + 64
    $securityEntryOffset = $dataDirectoryOffset + 32
    if ($checksumOffset + 4 -gt $Bytes.Length -or
        $securityEntryOffset + 8 -gt $optionalOffset + $optionalSize) {
        throw 'Authenticode input has an invalid checksum or security directory.'
    }
    $certificateOffset = [int64][BitConverter]::ToUInt32($Bytes, $securityEntryOffset)
    $certificateSize = [int64][BitConverter]::ToUInt32($Bytes, $securityEntryOffset + 4)
    if (($certificateOffset -eq 0) -xor ($certificateSize -eq 0)) {
        throw 'Authenticode input has an incomplete certificate table.'
    }
    if ($certificateOffset -ne 0 -and
        ($certificateOffset -lt $securityEntryOffset + 8 -or
         $certificateOffset + $certificateSize -gt $Bytes.LongLength)) {
        throw 'Authenticode input certificate table escapes the PE image.'
    }

    $hasher = [Security.Cryptography.IncrementalHash]::CreateHash(
        [Security.Cryptography.HashAlgorithmName]::SHA256)
    try {
        $hasher.AppendData($Bytes, 0, $checksumOffset)
        $hasher.AppendData(
            $Bytes,
            $checksumOffset + 4,
            $securityEntryOffset - ($checksumOffset + 4))
        $afterSecurity = $securityEntryOffset + 8
        if ($certificateOffset -eq 0) {
            $hasher.AppendData($Bytes, $afterSecurity, $Bytes.Length - $afterSecurity)
        }
        else {
            $hasher.AppendData(
                $Bytes,
                $afterSecurity,
                [int]($certificateOffset - $afterSecurity))
            $afterCertificate = [int]($certificateOffset + $certificateSize)
            if ($afterCertificate -lt $Bytes.Length) {
                $hasher.AppendData(
                    $Bytes,
                    $afterCertificate,
                    $Bytes.Length - $afterCertificate)
            }
        }
        return ([Convert]::ToHexString($hasher.GetHashAndReset())).ToLowerInvariant()
    }
    finally {
        $hasher.Dispose()
    }
}

function Open-ProductionReleaseDirectoryLease {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $fullPath = Assert-OrdinaryProductionDirectory -Path $Path -Label $Label
    $handle = [EnsouLauncherProduction.NativeFileIdentity]::OpenDirectoryReadLease(
        $fullPath)
    try {
        $identity =
            [EnsouLauncherProduction.NativeFileIdentity]::RequireOrdinaryDirectory(
                $handle)
        $pathHandle =
            [EnsouLauncherProduction.NativeFileIdentity]::OpenDirectoryReadLease(
                (Assert-OrdinaryProductionDirectory -Path $fullPath -Label $Label))
        try {
            $pathIdentity =
                [EnsouLauncherProduction.NativeFileIdentity]::RequireOrdinaryDirectory(
                    $pathHandle)
            if ($pathIdentity.VolumeSerialNumber -ne
                    $identity.VolumeSerialNumber -or
                $pathIdentity.FileIndex -ne $identity.FileIndex) {
                throw "$Label path no longer names the locked directory."
            }
        }
        finally {
            $pathHandle.Dispose()
        }
        return [pscustomobject]@{
            Path = $fullPath
            Handle = $handle
            VolumeSerialNumber = $identity.VolumeSerialNumber
            FileIndex = $identity.FileIndex
        }
    }
    catch {
        $handle.Dispose()
        throw
    }
}

function Open-ProductionReleaseDirectoryMoveLease {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $fullPath = Assert-OrdinaryProductionDirectory -Path $Path -Label $Label
    $handle = [EnsouLauncherProduction.NativeFileIdentity]::OpenDirectoryMoveLease(
        $fullPath)
    try {
        $identity =
            [EnsouLauncherProduction.NativeFileIdentity]::RequireOrdinaryDirectory(
                $handle)
        $descriptor = [pscustomobject]@{
            Path = $fullPath
            Handle = $handle
            VolumeSerialNumber = $identity.VolumeSerialNumber
            FileIndex = $identity.FileIndex
        }
        Assert-ProductionReleaseDirectoryStillLocked `
            -Descriptor $descriptor -Label $Label
        return $descriptor
    }
    catch {
        $handle.Dispose()
        throw
    }
}

function Move-ProductionReleaseDirectoryLease {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Descriptor,
        [Parameter(Mandatory = $true)][string]$DestinationPath,
        [Parameter(Mandatory = $true)][string]$Label
    )

    Assert-ProductionReleaseDirectoryStillLocked `
        -Descriptor $Descriptor -Label $Label
    $destination = [IO.Path]::GetFullPath($DestinationPath)
    if (Test-Path -LiteralPath $destination) {
        throw "$Label destination already exists."
    }
    if (-not [IO.Path]::GetPathRoot([string]$Descriptor.Path).Equals(
            [IO.Path]::GetPathRoot($destination),
            [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label source and destination must remain on the same volume."
    }
    [EnsouLauncherProduction.NativeFileIdentity]::MoveDirectoryLease(
        $Descriptor.Handle,
        $destination)
    $Descriptor.Path = $destination
    Assert-ProductionReleaseDirectoryStillLocked `
        -Descriptor $Descriptor -Label $Label
    return $destination
}

function Assert-ProductionReleaseDirectoryStillLocked {
    param(
        [Parameter(Mandatory = $true)]$Descriptor,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ($Descriptor.Handle.IsInvalid -or $Descriptor.Handle.IsClosed) {
        throw "$Label immutable directory lease is no longer held."
    }
    $pathHandle =
        [EnsouLauncherProduction.NativeFileIdentity]::OpenDirectoryReadLease(
            (Assert-OrdinaryProductionDirectory `
                -Path $Descriptor.Path `
                -Label $Label))
    try {
        $identity =
            [EnsouLauncherProduction.NativeFileIdentity]::RequireOrdinaryDirectory(
                $pathHandle)
        if ($identity.VolumeSerialNumber -ne $Descriptor.VolumeSerialNumber -or
            $identity.FileIndex -ne $Descriptor.FileIndex) {
            throw "$Label changed after admission."
        }
    }
    finally {
        $pathHandle.Dispose()
    }
}

function Assert-AuthenticodeCmsPeBinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [Security.Cryptography.Pkcs.SignedCms]$Cms,
        [Parameter(Mandatory = $true)][byte[]]$Bytes
    )

    try {
        $Cms.CheckSignature($true)
    }
    catch {
        throw 'Authenticode CMS signature is invalid.'
    }

    $spcIndirectDataOid = '1.3.6.1.4.1.311.2.1.4'
    $spcPeImageDataOid = '1.3.6.1.4.1.311.2.1.15'
    $sha256Oid = '2.16.840.1.101.3.4.2.1'
    if ([string]$Cms.ContentInfo.ContentType.Value -cne $spcIndirectDataOid) {
        throw 'Authenticode CMS content type is not SpcIndirectDataContent.'
    }

    try {
        $reader = [Formats.Asn1.AsnReader]::new(
            [ReadOnlyMemory[byte]]::new($Cms.ContentInfo.Content),
            [Formats.Asn1.AsnEncodingRules]::BER)
        $indirectData = $reader.ReadSequence()
        $data = $indirectData.ReadSequence()
        $dataTypeOid = $data.ReadObjectIdentifier()
        if ($data.HasData) {
            [void]$data.ReadEncodedValue()
        }
        $data.ThrowIfNotEmpty()

        $digestInfo = $indirectData.ReadSequence()
        $algorithm = $digestInfo.ReadSequence()
        $digestAlgorithmOid = $algorithm.ReadObjectIdentifier()
        if ($algorithm.HasData) {
            $algorithm.ReadNull()
        }
        $algorithm.ThrowIfNotEmpty()
        [byte[]]$contentDigest = $digestInfo.ReadOctetString()
        $digestInfo.ThrowIfNotEmpty()
        $indirectData.ThrowIfNotEmpty()
        $reader.ThrowIfNotEmpty()
    }
    catch {
        throw 'Authenticode SpcIndirectDataContent is not canonical: ' +
            $_.Exception.Message
    }

    if ($dataTypeOid -cne $spcPeImageDataOid) {
        throw 'Authenticode SpcIndirectDataContent does not describe a PE image.'
    }
    if ($digestAlgorithmOid -cne $sha256Oid -or $contentDigest.Length -ne 32) {
        throw 'Authenticode SpcIndirectDataContent must use one SHA-256 digest.'
    }
    $expectedDigest = ([Convert]::ToHexString($contentDigest)).ToLowerInvariant()
    $actualDigest = Get-PeContentSha256 -Bytes $Bytes
    if ($expectedDigest -cne $actualDigest) {
        throw 'Authenticode SpcIndirectDataContent digest differs from the locked PE bytes.'
    }
}

function Assert-Rfc3161TimestampTokenBinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][byte[]]$TokenBytes,
        [Parameter(Mandatory = $true)][Security.Cryptography.Pkcs.SignerInfo]$PrimarySigner,
        [Parameter(Mandatory = $true)][Security.Cryptography.X509Certificates.X509Certificate2]$ExpectedTimestampSigner,
        [ValidateSet(
            '1.2.840.113549.1.9.16.2.14',
            '1.3.6.1.4.1.311.3.3.1')][string]$TimestampAttributeOid =
                '1.2.840.113549.1.9.16.2.14'
    )

    $token = $null
    [int]$bytesConsumed = 0
    $encoded = [ReadOnlyMemory[byte]]::new($TokenBytes)
    if (-not [Security.Cryptography.Pkcs.Rfc3161TimestampToken]::TryDecode(
            $encoded,
            [ref]$token,
            [ref]$bytesConsumed) -or
        $null -eq $token -or
        $bytesConsumed -ne $TokenBytes.Length) {
        throw 'RFC3161 timestamp token is not one exact canonical token.'
    }
    $timestampSigner = $null
    if (-not $token.VerifySignatureForSignerInfo(
            $PrimarySigner,
            [ref]$timestampSigner) -or
        $null -eq $timestampSigner) {
        throw 'RFC3161 timestamp token messageImprint is not bound to the Authenticode primary SignerInfo.'
    }
    $timestampSha256 = ([Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData(
            $timestampSigner.RawData))).ToLowerInvariant()
    $expectedTimestampSha256 = ([Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData(
            $ExpectedTimestampSigner.RawData))).ToLowerInvariant()
    if ($timestampSha256 -cne $expectedTimestampSha256) {
        throw 'RFC3161 timestamp token signer differs from the trusted Authenticode timestamper.'
    }
    return [pscustomobject]@{
        TimestampProtocol = 'RFC3161'
        TimestampTokenOid = $TimestampAttributeOid
        TimestampContentTypeOid = '1.2.840.113549.1.9.16.1.4'
        TimestampSignerSha256 = $timestampSha256
    }
}

function Assert-AuthenticodeSignerRfc3161Timestamp {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][Security.Cryptography.Pkcs.SignerInfo]$PrimarySigner,
        [Parameter(Mandatory = $true)][Security.Cryptography.X509Certificates.X509Certificate2]$ExpectedSigner,
        [Parameter(Mandatory = $true)][Security.Cryptography.X509Certificates.X509Certificate2]$ExpectedTimestampSigner
    )

    if ($null -eq $PrimarySigner.Certificate) {
        throw 'Authenticode primary SignerInfo has no embedded signer certificate.'
    }
    $primarySha256 = ([Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData(
            $PrimarySigner.Certificate.RawData))).ToLowerInvariant()
    $expectedSignerSha256 = ([Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData(
            $ExpectedSigner.RawData))).ToLowerInvariant()
    if ($primarySha256 -cne $expectedSignerSha256) {
        throw 'Authenticode primary SignerInfo differs from the trusted signer.'
    }
    # Windows Authenticode RFC3161 uses szOID_RFC3161_counterSign
    # (1.3.6.1.4.1.311.3.3.1), while generic CMS uses id-aa-timeStampToken.
    # Both carry an RFC3161 TimeStampToken and receive the same strict binding
    # checks below; a legacy CMS counterSignature remains forbidden.
    $rfc3161Oids = @(
        '1.2.840.113549.1.9.16.2.14',
        '1.3.6.1.4.1.311.3.3.1')
    $legacyCounterSignatureOid = '1.2.840.113549.1.9.6'
    $legacyPresent = $PrimarySigner.CounterSignerInfos.Count -gt 0
    $bindingErrors = [Collections.Generic.List[string]]::new()
    $bindings = [Collections.Generic.List[object]]::new()
    [int]$rfc3161AttributeCount = 0
    [int]$rfc3161ValueCount = 0
    foreach ($attribute in $PrimarySigner.UnsignedAttributes) {
        if ($attribute.Oid.Value -ceq $legacyCounterSignatureOid) {
            $legacyPresent = $true
        }
        if ([string]$attribute.Oid.Value -notin $rfc3161Oids) {
            continue
        }
        $rfc3161AttributeCount++
        foreach ($encodedValue in $attribute.Values) {
            $rfc3161ValueCount++
            try {
                $binding = Assert-Rfc3161TimestampTokenBinding `
                    -TokenBytes $encodedValue.RawData `
                    -PrimarySigner $PrimarySigner `
                    -ExpectedTimestampSigner $ExpectedTimestampSigner `
                    -TimestampAttributeOid ([string]$attribute.Oid.Value)
                $bindings.Add([pscustomobject]@{
                    TimestampProtocol = [string]$binding.TimestampProtocol
                    TimestampTokenOid = [string]$binding.TimestampTokenOid
                    TimestampContentTypeOid = [string]$binding.TimestampContentTypeOid
                    TimestampSignerSha256 = [string]$binding.TimestampSignerSha256
                })
            }
            catch {
                $bindingErrors.Add($_.Exception.Message)
            }
        }
    }
    if ($legacyPresent) {
        throw 'Authenticode input contains a forbidden legacy counterSignature.'
    }
    if ($rfc3161AttributeCount -ne 1 -or $rfc3161ValueCount -ne 1) {
        throw 'Authenticode input must contain exactly one RFC3161 timestamp attribute with exactly one value.'
    }
    if ($bindingErrors.Count -gt 0) {
        throw 'Authenticode RFC3161 token failed primary SignerInfo binding: ' +
            ($bindingErrors -join ' | ')
    }
    if ($bindings.Count -ne 1) {
        throw 'Authenticode input has no verifiable RFC3161 timestamp token.'
    }
    return [pscustomobject]@{
        TimestampProtocol = [string]$bindings[0].TimestampProtocol
        TimestampTokenOid = [string]$bindings[0].TimestampTokenOid
        TimestampContentTypeOid = [string]$bindings[0].TimestampContentTypeOid
        TimestampSignerSha256 = [string]$bindings[0].TimestampSignerSha256
        LegacyCounterSignaturePresent = $false
    }
}

function Assert-PeRfc3161Timestamp {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][Security.Cryptography.X509Certificates.X509Certificate2]$SignerCertificate,
        [Parameter(Mandatory = $true)][Security.Cryptography.X509Certificates.X509Certificate2]$TimeStamperCertificate
    )

    if ($Bytes.Length -lt 256 -or $Bytes[0] -ne 0x4d -or $Bytes[1] -ne 0x5a) {
        throw 'RFC3161 admission input is not a Windows PE image.'
    }
    $peOffset = [BitConverter]::ToInt32($Bytes, 0x3c)
    if ($peOffset -lt 0x40 -or $peOffset -gt $Bytes.Length - 256) {
        throw 'RFC3161 admission input has an invalid PE header.'
    }
    $optionalOffset = $peOffset + 24
    $optionalSize = [BitConverter]::ToUInt16($Bytes, $peOffset + 20)
    $magic = [BitConverter]::ToUInt16($Bytes, $optionalOffset)
    $dataDirectoryOffset = if ($magic -eq 0x10b) {
        $optionalOffset + 96
    }
    elseif ($magic -eq 0x20b) {
        $optionalOffset + 112
    }
    else {
        throw 'RFC3161 admission input has an unsupported PE optional header.'
    }
    $securityEntryOffset = $dataDirectoryOffset + 32
    if ($optionalSize -lt 128 -or
        $securityEntryOffset + 8 -gt $optionalOffset + $optionalSize) {
        throw 'RFC3161 admission input has an invalid PE security directory.'
    }
    $certificateOffset = [int64][BitConverter]::ToUInt32($Bytes, $securityEntryOffset)
    $certificateSize = [int64][BitConverter]::ToUInt32($Bytes, $securityEntryOffset + 4)
    if ($certificateOffset -le 0 -or
        $certificateSize -lt 8 -or
        $certificateOffset + $certificateSize -gt $Bytes.LongLength) {
        throw 'RFC3161 admission input has no bounded embedded certificate table.'
    }

    $bindingErrors = [Collections.Generic.List[string]]::new()
    $cursor = $certificateOffset
    $certificateEnd = $certificateOffset + $certificateSize
    while ($cursor -lt $certificateEnd) {
        if ($certificateEnd - $cursor -lt 8) {
            throw 'PE certificate table ends with a truncated WIN_CERTIFICATE.'
        }
        $length = [int64][BitConverter]::ToUInt32($Bytes, [int]$cursor)
        $certificateType = [BitConverter]::ToUInt16($Bytes, [int]$cursor + 6)
        if ($length -lt 8 -or $cursor + $length -gt $certificateEnd) {
            throw 'PE certificate table contains an invalid WIN_CERTIFICATE length.'
        }
        $alignedLength = [int64](([int64]$length + 7) -band (-bnot 7))
        if ($alignedLength -le 0) {
            throw 'PE certificate table alignment overflowed.'
        }
        if ($cursor + $alignedLength -gt $certificateEnd) {
            throw 'PE certificate table ends before the aligned WIN_CERTIFICATE boundary.'
        }
        if ($certificateType -eq 0x0002) {
            $cmsBytes = [byte[]]::new([int]$length - 8)
            [Array]::Copy($Bytes, [int]$cursor + 8, $cmsBytes, 0, $cmsBytes.Length)
            $cms = [Security.Cryptography.Pkcs.SignedCms]::new()
            try {
                $cms.Decode($cmsBytes)
            }
            catch {
                throw 'PE Authenticode CMS could not be decoded for RFC3161 admission.'
            }
            try {
                Assert-AuthenticodeCmsPeBinding -Cms $cms -Bytes $Bytes
            }
            catch {
                $bindingErrors.Add($_.Exception.Message)
                $cursor += $alignedLength
                continue
            }
            foreach ($primarySigner in $cms.SignerInfos) {
                try {
                    return Assert-AuthenticodeSignerRfc3161Timestamp -PrimarySigner $primarySigner -ExpectedSigner $SignerCertificate -ExpectedTimestampSigner $TimeStamperCertificate
                }
                catch {
                    $bindingErrors.Add($_.Exception.Message)
                }
            }
        }
        $cursor += $alignedLength
    }
    if ($bindingErrors.Count -gt 0) {
        throw 'Authenticode embedded signature did not admit RFC3161: ' +
            ($bindingErrors -join ' | ')
    }
    throw 'Authenticode input has no verifiable RFC3161 timestamp token.'
}

function ConvertFrom-Base64UrlStrict {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ($Value -notmatch '^[A-Za-z0-9_-]+$') {
        throw "$Label is not canonical base64url."
    }
    $padded = $Value.Replace('-', '+').Replace('_', '/')
    switch ($padded.Length % 4) {
        0 {}
        2 { $padded += '==' }
        3 { $padded += '=' }
        default { throw "$Label has an invalid base64url length." }
    }
    try {
        $bytes = [Convert]::FromBase64String($padded)
    }
    catch {
        throw "$Label is not valid base64url."
    }
    $canonical = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    if ($canonical -cne $Value) {
        throw "$Label is not canonical base64url."
    }
    return $bytes
}

function Assert-CanonicalProductionJsonInput {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][Alias('Input')]$JsonInput,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $canonicalBytes = ConvertTo-ProductionJsonBytes -Value $JsonInput.Value
    if ([int64]$JsonInput.Bytes.LongLength -ne [int64]$canonicalBytes.LongLength -or
        [string]$JsonInput.Sha256 -cne (Get-ProductionSha256Bytes -Bytes $canonicalBytes)) {
        throw "$Label must use the exact canonical UTF-8 JSON serialization."
    }
    return $JsonInput.Value
}

function Assert-ExactProductionJsonMembers {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string[]]$Expected,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $actual = @(
        if ($Value -is [Collections.IDictionary]) {
            $Value.Keys | ForEach-Object { [string]$_ }
        }
        else {
            $Value.PSObject.Properties.Name
        }
    )
    if ($actual.Count -ne $Expected.Count) {
        throw "$Label contains an unknown, missing, or noncanonical JSON member order."
    }
    for ($index = 0; $index -lt $Expected.Count; $index++) {
        if ([string]$actual[$index] -cne [string]$Expected[$index]) {
            throw "$Label contains an unknown, missing, or noncanonical JSON member order."
        }
    }
}

function Get-ProductionReleaseP256PublicKeyIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][psobject]$Trust,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ([string]$Trust.algorithm -cne 'ES256') {
        throw "$Label must use ES256."
    }
    $x = ConvertFrom-Base64UrlStrict -Value ([string]$Trust.x) -Label "$Label X coordinate"
    $y = ConvertFrom-Base64UrlStrict -Value ([string]$Trust.y) -Label "$Label Y coordinate"
    if ($x.Length -ne 32 -or $y.Length -ne 32) {
        throw "$Label must contain two 32-byte P-256 coordinates."
    }

    $parameters = [Security.Cryptography.ECParameters]::new()
    $parameters.Curve = [Security.Cryptography.ECCurve+NamedCurves]::nistP256
    $point = [Security.Cryptography.ECPoint]::new()
    $point.X = $x
    $point.Y = $y
    $parameters.Q = $point
    $ecdsa = [Security.Cryptography.ECDsa]::Create()
    try {
        try {
            $ecdsa.ImportParameters($parameters)
            [void]$ecdsa.ExportParameters($false)
        }
        catch {
            throw "$Label is not a valid P-256 public point."
        }
    }
    finally {
        $ecdsa.Dispose()
    }

    $identity = [byte[]]::new(64)
    [Array]::Copy($x, 0, $identity, 0, 32)
    [Array]::Copy($y, 0, $identity, 32, 32)
    return [Convert]::ToHexString($identity)
}

function Get-ProductionReleaseSigningResponseAuthenticationPayload {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][psobject]$Response)

    $files = [Collections.Generic.List[object]]::new()
    foreach ($file in @($Response.files)) {
        $files.Add([ordered]@{
            role = [string]$file.role
            fileName = [string]$file.fileName
            relativePath = [string]$file.relativePath
            inputSha256 = [string]$file.inputSha256
            inputPeContentSha256 = [string]$file.inputPeContentSha256
            sizeBytes = [int64]$file.sizeBytes
            sha256 = [string]$file.sha256
            signedPeContentSha256 = [string]$file.signedPeContentSha256
        })
    }
    $body = [ordered]@{
        schemaVersion = [int]$Response.schemaVersion
        responseType = [string]$Response.responseType
        orchestrationId = [string]$Response.orchestrationId
        edition = [string]$Response.edition
        releaseSetId = [string]$Response.releaseSetId
        planSha256 = [string]$Response.planSha256
        requestSha256 = [string]$Response.requestSha256
        requestNonce = [string]$Response.requestNonce
        completedAtUtc = [string]$Response.completedAtUtc
        files = $files
    }
    $authenticationProperty = $Response.PSObject.Properties['authentication']
    $authentication = if ($null -eq $authenticationProperty) { $null } else { $authenticationProperty.Value }
    $purposePresent = $false
    $purpose = ''
    if ($null -ne $authentication) {
        if ($authentication -is [Collections.IDictionary]) {
            $purposePresent = $authentication.Contains('purpose')
            if ($purposePresent) {
                $purpose = [string]$authentication['purpose']
            }
        }
        else {
            $purposeProperty = $authentication.PSObject.Properties['purpose']
            $purposePresent = $null -ne $purposeProperty
            if ($purposePresent) {
                $purpose = [string]$purposeProperty.Value
            }
        }
    }
    if (-not $purposePresent) {
        # Frozen v1 payload bytes must remain byte-for-byte compatible.
        $domainName = 'ensou-dsh-launcher-external-signing-response-authentication-v1'
    }
    else {
        $payloadTypePresent = if ($authentication -is [Collections.IDictionary]) {
            $authentication.Contains('payloadType')
        }
        else {
            $null -ne $authentication.PSObject.Properties['payloadType']
        }
        if (-not $payloadTypePresent) {
            throw 'Purpose-bound external response authentication is missing its payload type.'
        }
        $algorithm = if ($authentication -is [Collections.IDictionary]) { [string]$authentication['algorithm'] } else { [string]$authentication.algorithm }
        $keyId = if ($authentication -is [Collections.IDictionary]) { [string]$authentication['keyId'] } else { [string]$authentication.keyId }
        $payloadType = if ($authentication -is [Collections.IDictionary]) { [string]$authentication['payloadType'] } else { [string]$authentication.payloadType }
        $body.Insert(9, 'authentication', [ordered]@{
            algorithm = $algorithm
            keyId = $keyId
            purpose = $purpose
            payloadType = $payloadType
        })
        $domainName = 'ensou-dsh-launcher-external-signing-response-authentication-v2'
    }
    $domain = $script:Utf8Strict.GetBytes($domainName + [char]10)
    $json = ConvertTo-ProductionJsonBytes -Value $body
    $payload = [byte[]]::new($domain.Length + $json.Length)
    [Array]::Copy($domain, 0, $payload, 0, $domain.Length)
    [Array]::Copy($json, 0, $payload, $domain.Length, $json.Length)
    return $payload
}

function Assert-ProductionEs256P1363LowS {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][byte[]]$Signature,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ($Signature.Length -ne 64) {
        throw "$Label must be one 64-byte P-256 P1363 signature."
    }
    $rNonZero = $false
    $sNonZero = $false
    foreach ($index in 0..31) {
        $rNonZero = $rNonZero -or $Signature[$index] -ne 0
        $sNonZero = $sNonZero -or $Signature[$index + 32] -ne 0
    }
    if (-not $rNonZero -or -not $sNonZero) {
        throw "$Label has a zero P1363 scalar."
    }
    $curveOrder = [Convert]::FromHexString(
        'FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551')
    $halfOrder = [Convert]::FromHexString(
        '7FFFFFFF800000007FFFFFFFFFFFFFFFDE737D56D38BCF4279DCE5617E3192A8')
    $rAtLeastOrder = $true
    foreach ($index in 0..31) {
        if ($Signature[$index] -lt $curveOrder[$index]) {
            $rAtLeastOrder = $false
            break
        }
        if ($Signature[$index] -gt $curveOrder[$index]) {
            break
        }
    }
    if ($rAtLeastOrder) {
        throw "$Label has an out-of-range P1363 r scalar."
    }
    foreach ($index in 0..31) {
        if ($Signature[$index + 32] -gt $halfOrder[$index]) {
            throw "$Label is not canonical low-S P1363."
        }
        if ($Signature[$index + 32] -lt $halfOrder[$index]) {
            break
        }
    }
}

function Assert-ProductionReleaseSigningResponseAuthentication {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][psobject]$Response,
        [Parameter(Mandatory = $true)][psobject]$Trust
    )

    $trustPurposeProperty = $Trust.PSObject.Properties['purpose']
    $responsePurposeProperty = $Response.authentication.PSObject.Properties['purpose']
    $responsePayloadTypeProperty = $Response.authentication.PSObject.Properties['payloadType']
    if ([string]$Response.authentication.algorithm -cne 'ES256' -or
        [string]$Trust.algorithm -cne 'ES256' -or
        [string]$Response.authentication.keyId -cne [string]$Trust.keyId) {
        throw 'External signing response authentication policy does not match the plan.'
    }
    if ($null -eq $trustPurposeProperty) {
        if ($null -ne $responsePurposeProperty -or $null -ne $responsePayloadTypeProperty) {
            throw 'External signing response authentication cannot add a purpose to a v1 trust domain.'
        }
    }
    elseif ($null -eq $responsePurposeProperty -or
        $null -eq $responsePayloadTypeProperty -or
        [string]$responsePurposeProperty.Value -cne [string]$trustPurposeProperty.Value -or
        [string]$responsePayloadTypeProperty.Value -cne 'ensou-dsh-launcher-external-signing-response-authentication-v2') {
        throw 'External signing response authentication purpose does not match the plan trust domain.'
    }
    $x = ConvertFrom-Base64UrlStrict -Value ([string]$Trust.x) -Label 'External response key X'
    $y = ConvertFrom-Base64UrlStrict -Value ([string]$Trust.y) -Label 'External response key Y'
    $signature = ConvertFrom-Base64UrlStrict -Value ([string]$Response.authentication.value) -Label 'External response signature'
    if ($x.Length -ne 32 -or $y.Length -ne 32 -or $signature.Length -ne 64) {
        throw 'External signing response authentication uses invalid ES256 sizes.'
    }
    if ($null -ne $trustPurposeProperty) {
        Assert-ProductionEs256P1363LowS `
            -Signature $signature `
            -Label 'Purpose-bound external signing response signature'
    }
    $parameters = [Security.Cryptography.ECParameters]::new()
    $parameters.Curve = [Security.Cryptography.ECCurve+NamedCurves]::nistP256
    $point = [Security.Cryptography.ECPoint]::new()
    $point.X = $x
    $point.Y = $y
    $parameters.Q = $point
    $ecdsa = [Security.Cryptography.ECDsa]::Create()
    try {
        $ecdsa.ImportParameters($parameters)
        $payload = Get-ProductionReleaseSigningResponseAuthenticationPayload -Response $Response
        if (-not $ecdsa.VerifyData(
                $payload,
                $signature,
                [Security.Cryptography.HashAlgorithmName]::SHA256,
                [Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)) {
            throw 'External signing response authentication signature is invalid.'
        }
    }
    finally {
        $ecdsa.Dispose()
    }
}

function Write-ProductionStateFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [switch]$FaultAfterPending
    )

    $fullPath = [IO.Path]::GetFullPath($Path)
    $parent = Assert-OrdinaryProductionDirectory -Path ([IO.Path]::GetDirectoryName($fullPath)) -Label 'State output parent'
    if (Test-Path -LiteralPath $fullPath) {
        $existing = Open-ProductionReleaseInput -Path $fullPath -Label 'Existing state output' -MaximumBytes ([Math]::Max($Bytes.LongLength, 1))
        try {
            if ($existing.SizeBytes -ne $Bytes.LongLength -or
                $existing.Sha256 -cne (Get-ProductionSha256Bytes -Bytes $Bytes)) {
                throw "Existing state output conflicts with the exact requested bytes: $fullPath"
            }
            return
        }
        finally {
            $existing.Stream.Dispose()
        }
    }
    $pending = $fullPath + '.pending'
    if (Test-Path -LiteralPath $pending) {
        $existingPending = Open-ProductionReleaseInput -Path $pending -Label 'Pending state output' -MaximumBytes ([Math]::Max($Bytes.LongLength, 1))
        try {
            if ($existingPending.SizeBytes -ne $Bytes.LongLength -or
                $existingPending.Sha256 -cne (Get-ProductionSha256Bytes -Bytes $Bytes)) {
                throw "Pending state output conflicts with the exact requested bytes: $pending"
            }
        }
        finally {
            $existingPending.Stream.Dispose()
        }
    }
    else {
        $stream = [IO.File]::Open(
            $pending,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None)
        try {
            [void][EnsouLauncherProduction.NativeFileIdentity]::RequireOrdinarySingleLink(
                $stream.SafeFileHandle)
            $stream.Write($Bytes, 0, $Bytes.Length)
            $stream.Flush($true)
        }
        finally {
            $stream.Dispose()
        }
    }
    if ($FaultAfterPending) {
        throw "INJECTED-CRASH-AFTER-PENDING-$([IO.Path]::GetFileName($fullPath))"
    }
    [IO.File]::Move($pending, $fullPath, $false)
    [void]$parent
}

function Get-ProductionRuntimeSourceReleaseExpectation {
    param([Parameter(Mandatory = $true)][psobject]$Plan)

    $repoProperty = $Plan.runtimeCandidate.PSObject.Properties['githubRepository']
    $commitProperty = $Plan.runtimeCandidate.PSObject.Properties['githubReleaseCommit']
    if ($null -eq $repoProperty -and $null -eq $commitProperty) { return $null }
    if ($null -eq $repoProperty -or $null -eq $commitProperty -or
        [int]$Plan.schemaVersion -ne 2 -or [string]$Plan.edition -cne 'Enterprise' -or
        [string]$Plan.targetChannel -cne 'stable' -or
        [string]$repoProperty.Value -cnotmatch '^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9][A-Za-z0-9._-]{0,99}$' -or
        [string]$commitProperty.Value -cnotmatch '^[0-9a-f]{40}$' -or
        [string]$Plan.runtimeCandidate.githubReleaseTag -cne [string]$Plan.runtimeCandidate.releaseId) {
        throw 'RUNTIME_SOURCE_EXPECTATION_REJECTED: Source repository, runtime build commit and tag must be anchored together in an Enterprise Stable plan.'
    }
    # This commit belongs to the independently built runtime candidate. It is
    # intentionally not compared with the later Launcher plan.sourceCommit.
    return [pscustomobject][ordered]@{
        repository = [string]$repoProperty.Value
        tagName = [string]$Plan.runtimeCandidate.githubReleaseTag
        targetCommit = [string]$commitProperty.Value
    }
}

function Assert-ProductionRuntimeSourceReleaseExpectation {
    param(
        [Parameter(Mandatory = $true)][psobject]$Plan,
        [Parameter(Mandatory = $true)][psobject]$Value
    )
    $expected = Get-ProductionRuntimeSourceReleaseExpectation -Plan $Plan
    $property = $Value.PSObject.Properties['runtimeSourceReleaseExpectation']
    if ($null -eq $expected) {
        if ($null -ne $property) { throw 'RUNTIME_SOURCE_EXPECTATION_UNANCHORED: Source expectation is absent from the original plan.' }
        return
    }
    if ($null -eq $property -or $null -eq $property.Value) {
        throw 'RUNTIME_SOURCE_EXPECTATION_REQUIRED: Publisher input/request must retain the original source expectation.'
    }
    Assert-ExactProductionJsonMembers -Value $property.Value `
        -Expected @('repository', 'tagName', 'targetCommit') -Label 'Runtime source expectation'
    if ((Get-ProductionSha256Bytes (ConvertTo-ProductionJsonBytes $expected)) -cne
        (Get-ProductionSha256Bytes (ConvertTo-ProductionJsonBytes $property.Value))) {
        throw 'RUNTIME_SOURCE_EXPECTATION_MISMATCH: Publisher input/request source expectation differs from the plan.'
    }
}

function Assert-ProductionRuntimeSourceReleaseAdmission {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][psobject]$Admission,
        [Parameter(Mandatory = $true)][psobject]$Plan,
        [Parameter(Mandatory = $true)]$OrganizationAdmissionReceiptInput
    )

    # The caller first verifies the r5 publisher's plan-pinned ES256 signature.
    # That publisher attests its compiled-trust validation of the v2 receipt;
    # an unsigned workflow artifact or receipt alone is never this authority.
    $expected = Get-ProductionRuntimeSourceReleaseExpectation -Plan $Plan
    if ($null -eq $expected) { throw 'RUNTIME_SOURCE_EXPECTATION_REQUIRED: Historical plans do not admit immutable source origin.' }
    Assert-ExactProductionJsonMembers -Value $Admission `
        -Expected @('receiptSha256', 'sourceRelease') -Label 'Runtime source admission'
    $receiptBytes = [byte[]]$OrganizationAdmissionReceiptInput.Bytes
    $receiptSha = Get-ProductionSha256Bytes -Bytes $receiptBytes
    if ([string]$Admission.receiptSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$Admission.receiptSha256 -cne $receiptSha -or
        [string]$OrganizationAdmissionReceiptInput.Sha256 -cne $receiptSha) {
        throw 'RUNTIME_SOURCE_RECEIPT_MISMATCH: Source admission does not bind the exact organization receipt bytes.'
    }
    $receipt = ConvertFrom-StrictProductionJsonBytes -Bytes $receiptBytes -Label 'Source-admitted runtime organization receipt'
    Assert-ExactProductionJsonMemberSet -Value $receipt -Expected @(
        'schemaVersion', 'receiptType', 'releaseId', 'sourceRuntimeMetadataSha256',
        'decision', 'reviewedAtUnixSeconds', 'signature', 'sourceRelease') -Label 'Source-admitted runtime organization receipt'
    Assert-ExactProductionJsonMemberSet -Value $receipt.signature `
        -Expected @('algorithm', 'keyId', 'value') -Label 'Runtime organization receipt signature'
    if (($receipt.schemaVersion -isnot [long] -and $receipt.schemaVersion -isnot [int]) -or
        [int]$receipt.schemaVersion -ne 2 -or
        [string]$receipt.receiptType -cne 'ensou-dsh-runtime-organization-admission' -or
        [string]$receipt.releaseId -cne [string]$Plan.runtimeCandidate.releaseId -or
        [string]$receipt.sourceRuntimeMetadataSha256 -cne [string]$Plan.runtimeCandidate.metadata.sha256 -or
        [string]$receipt.decision -cne 'admitted' -or [long]$receipt.reviewedAtUnixSeconds -le 0 -or
        [string]$receipt.signature.algorithm -cne 'ES256' -or
        [string]$receipt.signature.keyId -cnotmatch '^[A-Za-z0-9._-]{1,64}$' -or
        [string]$receipt.signature.value -cnotmatch '^[A-Za-z0-9_-]{86}$') {
        throw 'RUNTIME_SOURCE_RECEIPT_REJECTED: A v2 admitted runtime organization receipt is required.'
    }
    $source = $Admission.sourceRelease
    Assert-ExactProductionJsonMembers -Value $source -Expected @(
        'repository', 'githubReleaseId', 'tagName', 'targetCommit', 'immutable', 'assets') -Label 'Immutable runtime source release'
    if ([string]$source.repository -cne [string]$expected.repository -or
        [string]$source.tagName -cne [string]$expected.tagName -or
        [string]$source.targetCommit -cne [string]$expected.targetCommit -or
        $source.immutable -isnot [bool] -or -not $source.immutable -or
        ($source.githubReleaseId -isnot [long] -and $source.githubReleaseId -isnot [int]) -or
        [long]$source.githubReleaseId -le 0 -or [long]$source.githubReleaseId -gt 9007199254740991) {
        throw 'RUNTIME_SOURCE_RELEASE_REJECTED: Immutable GitHub identity differs from the anchored runtime candidate.'
    }
    $assets = @($source.assets)
    $roles = @('archive', 'metadata', 'hash-evidence')
    $planned = @($Plan.runtimeCandidate.archive, $Plan.runtimeCandidate.metadata, $Plan.runtimeCandidate.hashEvidence)
    if ($assets.Count -ne 3) { throw 'RUNTIME_SOURCE_ASSETS_REJECTED: Exactly three source release assets are required.' }
    $ids = [Collections.Generic.HashSet[long]]::new()
    $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    for ($index = 0; $index -lt 3; $index++) {
        $asset = $assets[$index]; $file = $planned[$index]
        Assert-ExactProductionJsonMembers -Value $asset -Expected @(
            'role', 'githubAssetId', 'fileName', 'sizeBytes', 'sha256') -Label "Immutable source asset $index"
        if ([string]$asset.role -cne $roles[$index] -or
            ($asset.githubAssetId -isnot [long] -and $asset.githubAssetId -isnot [int]) -or
            [long]$asset.githubAssetId -le 0 -or [long]$asset.githubAssetId -gt 9007199254740991 -or
            -not $ids.Add([long]$asset.githubAssetId) -or
            [string]$asset.fileName -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$' -or
            -not $names.Add([string]$asset.fileName) -or
            [string]$asset.fileName -cne [string]$file.fileName -or
            ($asset.sizeBytes -isnot [long] -and $asset.sizeBytes -isnot [int]) -or
            [long]$asset.sizeBytes -le 0 -or [long]$asset.sizeBytes -gt 8589934592 -or
            [long]$asset.sizeBytes -ne [long]$file.sizeBytes -or
            [string]$asset.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [string]$asset.sha256 -cne [string]$file.sha256) {
            throw "RUNTIME_SOURCE_ASSETS_REJECTED: Source asset $index differs from the exact planned bytes or inventory."
        }
    }
    # External organization JSON is signed using its existing canonical payload,
    # not its textual member order. Bind its raw SHA, then compare exact fields
    # in the same typed order as the authenticated r5 extension.
    $sourceFields = @('repository', 'githubReleaseId', 'tagName', 'targetCommit', 'immutable', 'assets')
    $assetFields = @('role', 'githubAssetId', 'fileName', 'sizeBytes', 'sha256')
    Assert-ExactProductionJsonMemberSet -Value $receipt.sourceRelease -Expected $sourceFields -Label 'Original source receipt fields'
    $normalizedSource = [ordered]@{}
    foreach ($field in $sourceFields) { $normalizedSource[$field] = $receipt.sourceRelease.$field }
    $normalizedAssets = [Collections.Generic.List[object]]::new()
    foreach ($asset in @($receipt.sourceRelease.assets)) {
        Assert-ExactProductionJsonMemberSet -Value $asset -Expected $assetFields -Label 'Original source receipt asset'
        $normalizedAsset = [ordered]@{}
        foreach ($field in $assetFields) { $normalizedAsset[$field] = $asset.$field }
        $normalizedAssets.Add($normalizedAsset)
    }
    $normalizedSource.assets = @($normalizedAssets)
    if ((Get-ProductionSha256Bytes (ConvertTo-ProductionJsonBytes $source)) -cne
        (Get-ProductionSha256Bytes (ConvertTo-ProductionJsonBytes $normalizedSource))) {
        throw 'RUNTIME_SOURCE_RECEIPT_MISMATCH: The authenticated publisher claim differs from the original v2 receipt source identity.'
    }
    return [pscustomobject]@{
        Status = 'RUNTIME_SOURCE_RELEASE_AUTHENTICATED'
        ReceiptSha256 = $receiptSha
        Repository = [string]$source.repository
        TagName = [string]$source.tagName
        TargetCommit = [string]$source.targetCommit
    }
}

function Assert-ExactProductionJsonMemberSet {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string[]]$Expected,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $actual = @(if ($Value -is [Collections.IDictionary]) { $Value.Keys } else { $Value.PSObject.Properties.Name })
    $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($name in $actual) { [void]$names.Add([string]$name) }
    if ($actual.Count -ne $Expected.Count -or $names.Count -ne $Expected.Count) {
        throw "$Label contains unknown or missing members."
    }
    foreach ($name in $Expected) {
        if (-not $names.Contains($name)) { throw "$Label contains unknown or missing members." }
    }
}

function Assert-ProductionRuntimeSourceReleaseResponseBinding {
    param(
        [Parameter(Mandatory = $true)][psobject]$Plan,
        [Parameter(Mandatory = $true)][psobject]$Request,
        [Parameter(Mandatory = $true)][psobject]$Response,
        [Parameter(Mandatory = $true)][string]$StateRoot
    )
    Assert-ProductionRuntimeSourceReleaseExpectation -Plan $Plan -Value $Request
    $expected = Get-ProductionRuntimeSourceReleaseExpectation -Plan $Plan
    $property = $Response.PSObject.Properties['runtimeSourceReleaseAdmission']
    if ($null -eq $expected) {
        if ($null -ne $property) { throw 'RUNTIME_SOURCE_EXPECTATION_UNANCHORED: The original plan does not anchor this source admission.' }
        return
    }
    if ($null -eq $property -or $null -eq $property.Value) { throw 'RUNTIME_SOURCE_ADMISSION_REQUIRED: The publisher must authenticate its source admission.' }
    $files = @($Request.publisherInput.files | Where-Object { [string]$_.role -ceq 'edition-runtime-organization-admission' })
    if ($files.Count -ne 1 -or [string]$files[0].relativePath -cne ('payload/' + [string]$files[0].fileName) -or
        [string]$files[0].fileName -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$') {
        throw 'RUNTIME_SOURCE_RECEIPT_REQUIRED: The r4 request must contain exactly one original organization admission receipt.'
    }
    $channel = Get-ProductionManifestChannelContract -TargetChannel ([string]$Plan.targetChannel)
    $path = Join-Path (Join-Path (Join-Path $StateRoot 'requests') $channel.RequestBundleName) $files[0].relativePath
    $lease = Open-ProductionReleaseInput -Path $path -Label 'State-owned runtime organization admission' -MaximumBytes 4MB
    try {
        if ([long]$lease.SizeBytes -ne [long]$files[0].sizeBytes -or [string]$lease.Sha256 -cne [string]$files[0].sha256) {
            throw 'RUNTIME_SOURCE_RECEIPT_MISMATCH: Organization receipt differs from the original r4 request descriptor.'
        }
        $input = [pscustomobject]@{
            Bytes = Read-ProductionReleaseInputBytes -Descriptor $lease -Label 'State-owned runtime organization admission'
            Sha256 = [string]$lease.Sha256
        }
        $result = Assert-ProductionRuntimeSourceReleaseAdmission -Admission $property.Value -Plan $Plan -OrganizationAdmissionReceiptInput $input
        [void](Assert-ProductionReleaseInputStillLocked -Descriptor $lease -Label 'State-owned runtime organization admission')
        return $result
    }
    finally { $lease.Stream.Dispose() }
}

function Assert-ProductionRuntimeSourceReleaseHistory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][psobject]$State,
        [Parameter(Mandatory = $true)][psobject]$Plan
    )

    # State must come from the existing complete state replay. Its caller holds
    # Enter-ProductionReleaseStateReadLock through this check and final summary.
    # Retain request/response/head leases for this check. The nested organization
    # receipt is locked while bound, then re-opened by the final full state replay.
    $expected = Get-ProductionRuntimeSourceReleaseExpectation -Plan $Plan
    if ($null -eq $expected) {
        return [pscustomobject]@{
            Status = 'IMMUTABLE_SOURCE_RELEASE_UNVERIFIED'
            SourceReleaseVerified = $false
            CurrentHeadSha256 = [string]$State.HeadSha256
        }
    }
    $contract = Get-ProductionManifestChannelContract -TargetChannel ([string]$Plan.targetChannel)
    if ([int]$State.Head.revision -lt 5 -or @($State.Receipts).Count -lt 5 -or
        [string]$State.Identity.edition -cne [string]$Plan.edition -or
        [string]$State.Identity.orchestrationId -cne [string]$Plan.orchestrationId) {
        throw 'RUNTIME_SOURCE_HISTORY_REJECTED: A committed, identity-bound Enterprise Stable r5 is required.'
    }
    $r4 = $State.Receipts[3]; $r5 = $State.Receipts[4]
    if ([int]$r4.revision -ne 4 -or [int]$r5.revision -ne 5 -or
        [string]$r4.phase -cne [string]$contract.RequestPhase -or
        [string]$r5.phase -cne [string]$contract.CandidatePhase) {
        throw 'RUNTIME_SOURCE_HISTORY_REJECTED: Exact manifest request/import transition receipts are required.'
    }
    $leases = [Collections.Generic.List[object]]::new()
    try {
        $openJson = {
            param([string]$Path, [string]$Label, [string]$SchemaName)
            $lease = Open-ProductionReleaseInput -Path $Path -Label $Label -MaximumBytes 64MB
            try {
                $bytes = Read-ProductionReleaseInputBytes -Descriptor $lease -Label $Label
                $value = ConvertFrom-StrictProductionJsonBytes -Bytes $bytes -Label $Label `
                    -SchemaPath (Join-Path (Join-Path $PSScriptRoot '..\schemas') $SchemaName)
                $input = [pscustomobject]@{ Bytes=$bytes; Value=$value; Sha256=[string]$lease.Sha256; Descriptor=$lease }
                [void](Assert-CanonicalProductionJsonInput -Input $input -Label $Label)
                $leases.Add($lease); $lease = $null
                return $input
            } finally { if ($null -ne $lease) { $lease.Stream.Dispose() } }
        }
        $requestRoot = Join-Path (Join-Path $State.StateRoot 'requests') $contract.RequestBundleName
        $responseRoot = Join-Path (Join-Path $State.StateRoot 'imports') $contract.CandidateBundleName
        $requestInput = & $openJson (Join-Path $requestRoot 'manifest-publishing-request.v1.json') 'Committed source-admitted r4 request' 'launcher-manifest-publishing-request-v1.schema.json'
        $responseInput = & $openJson (Join-Path $responseRoot 'manifest-publishing-response.v1.json') 'Committed source-admitted r5 response' 'launcher-manifest-publishing-response-v1.schema.json'
        $request = $requestInput.Value; $response = $responseInput.Value
        $r4Head = Get-ProductionHistoricalHeadSha256 -StateRoot $State.StateRoot `
            -Identity $State.Identity -IdentitySha256 ([string]$State.IdentitySha256) -Receipt $r4
        if ([string]$requestInput.Sha256 -cne [string]$r4.data.requestSha256 -or
            [string]$requestInput.Sha256 -cne [string]$r5.data.requestSha256 -or
            [string]$responseInput.Sha256 -cne [string]$r5.data.responseSha256 -or
            [string]$request.planSha256 -cne [string]$State.Identity.planSha256 -or
            [string]$request.orchestrationId -cne [string]$Plan.orchestrationId -or
            [string]$request.edition -cne [string]$Plan.edition -or
            [string]$request.releaseSetId -cne [string]$Plan.releaseSetId -or
            [string]$request.channel -cne [string]$Plan.targetChannel -or
            [string]$response.planSha256 -cne [string]$request.planSha256 -or
            [string]$response.orchestrationId -cne [string]$request.orchestrationId -or
            [string]$response.edition -cne [string]$request.edition -or
            [string]$response.releaseSetId -cne [string]$request.releaseSetId -or
            [string]$response.channel -cne [string]$request.channel -or
            [string]$response.requestSha256 -cne [string]$requestInput.Sha256 -or
            [string]$response.requestNonce -cne [string]$request.requestNonce -or
            [string]$response.baseHeadSha256 -cne [string]$request.baseHeadSha256 -or
            [string]$response.admissionHeadSha256 -cne $r4Head -or
            [int]$response.admissionRevision -ne 4 -or
            [string]$response.requestExpiresAtUtc -cne [string]$request.expiresAtUtc) {
            throw 'RUNTIME_SOURCE_HISTORY_REJECTED: Raw source-admitted request/response bytes differ from their state receipts, identity or historical head.'
        }
        Assert-ProductionReleaseManifestPublishingResponseAuthentication `
            -Response $response -Trust $Plan.externalResponseTrusts.manifestPublishing
        $result = Assert-ProductionRuntimeSourceReleaseResponseBinding `
            -Plan $Plan -Request $request -Response $response -StateRoot $State.StateRoot
        $headLease = Open-ProductionReleaseInput -Path (Join-Path $State.StateRoot 'head.json') `
            -Label 'Source history current state head' -MaximumBytes 4MB
        $leases.Add($headLease)
        if ([string]$headLease.Sha256 -cne [string]$State.HeadSha256) {
            throw 'RUNTIME_SOURCE_HISTORY_REJECTED: The current head changed during historical source admission.'
        }
        foreach ($lease in $leases) {
            [void](Assert-ProductionReleaseInputStillLocked -Descriptor $lease -Label 'Source-admitted history input')
        }
        return [pscustomobject]@{
            Status = [string]$result.Status
            SourceReleaseVerified = $true
            CurrentHeadSha256 = [string]$State.HeadSha256
            ReceiptSha256 = [string]$result.ReceiptSha256
            Repository = [string]$result.Repository
            TagName = [string]$result.TagName
            TargetCommit = [string]$result.TargetCommit
        }
    } finally { for ($index=$leases.Count-1; $index -ge 0; $index--) { $leases[$index].Stream.Dispose() } }
}

function Get-ProductionReleaseManifestPublishingResponseAuthenticationPayload {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][psobject]$Response)

    $files = [Collections.Generic.List[object]]::new()
    foreach ($file in @($Response.files)) {
        $files.Add([ordered]@{
            role = [string]$file.role
            fileName = [string]$file.fileName
            relativePath = [string]$file.relativePath
            sizeBytes = [int64]$file.sizeBytes
            sha256 = [string]$file.sha256
        })
    }
    $body = [ordered]@{
        schemaVersion = [int]$Response.schemaVersion
        responseType = [string]$Response.responseType
        orchestrationId = [string]$Response.orchestrationId
        edition = [string]$Response.edition
        releaseSetId = [string]$Response.releaseSetId
        channel = [string]$Response.channel
        planSha256 = [string]$Response.planSha256
        requestSha256 = [string]$Response.requestSha256
        requestNonce = [string]$Response.requestNonce
        baseHeadSha256 = [string]$Response.baseHeadSha256
        admissionHeadSha256 = [string]$Response.admissionHeadSha256
        admissionRevision = [int]$Response.admissionRevision
        requestExpiresAtUtc = [string]$Response.requestExpiresAtUtc
        completedAtUtc = [string]$Response.completedAtUtc
        files = $files
        authentication = [ordered]@{
            algorithm = [string]$Response.authentication.algorithm
            keyId = [string]$Response.authentication.keyId
            purpose = [string]$Response.authentication.purpose
            payloadType = [string]$Response.authentication.payloadType
        }
    }
    if ($null -ne $Response.PSObject.Properties['runtimeSourceReleaseAdmission']) {
        $body.runtimeSourceReleaseAdmission = $Response.runtimeSourceReleaseAdmission
    }
    $domain = $script:Utf8Strict.GetBytes('manifest-publishing-response' + [char]10)
    $json = ConvertTo-ProductionJsonBytes -Value $body
    $payload = [byte[]]::new($domain.Length + $json.Length)
    [Array]::Copy($domain, 0, $payload, 0, $domain.Length)
    [Array]::Copy($json, 0, $payload, $domain.Length, $json.Length)
    return $payload
}

function Assert-ProductionReleaseManifestPublishingResponseAuthentication {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][psobject]$Response,
        [Parameter(Mandatory = $true)][psobject]$Trust
    )

    if ([string]$Trust.algorithm -cne 'ES256' -or
        [string]$Trust.purpose -cne 'manifest-publishing-response' -or
        [string]$Response.authentication.algorithm -cne 'ES256' -or
        [string]$Response.authentication.keyId -cne [string]$Trust.keyId -or
        [string]$Response.authentication.purpose -cne 'manifest-publishing-response' -or
        [string]$Response.authentication.payloadType -cne
            'ensou-dsh-launcher-manifest-publishing-response-authentication-v1') {
        throw 'Manifest-publishing response authentication does not match its isolated plan trust domain.'
    }
    $x = ConvertFrom-Base64UrlStrict `
        -Value ([string]$Trust.x) `
        -Label 'Manifest-publishing response key X'
    $y = ConvertFrom-Base64UrlStrict `
        -Value ([string]$Trust.y) `
        -Label 'Manifest-publishing response key Y'
    $signature = ConvertFrom-Base64UrlStrict `
        -Value ([string]$Response.authentication.value) `
        -Label 'Manifest-publishing response signature'
    if ($x.Length -ne 32 -or $y.Length -ne 32 -or $signature.Length -ne 64) {
        throw 'Manifest-publishing response authentication uses invalid P-256 P1363 sizes.'
    }
    Assert-ProductionEs256P1363LowS `
        -Signature $signature `
        -Label 'Manifest-publishing response signature'

    $parameters = [Security.Cryptography.ECParameters]::new()
    $parameters.Curve = [Security.Cryptography.ECCurve+NamedCurves]::nistP256
    $point = [Security.Cryptography.ECPoint]::new()
    $point.X = $x
    $point.Y = $y
    $parameters.Q = $point
    $ecdsa = [Security.Cryptography.ECDsa]::Create()
    try {
        try {
            $ecdsa.ImportParameters($parameters)
        }
        catch {
            throw 'Manifest-publishing response trust is not one valid P-256 public point.'
        }
        $payload = Get-ProductionReleaseManifestPublishingResponseAuthenticationPayload `
            -Response $Response
        if (-not $ecdsa.VerifyData(
                $payload,
                $signature,
                [Security.Cryptography.HashAlgorithmName]::SHA256,
                [Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)) {
            throw 'Manifest-publishing response authentication signature is invalid.'
        }
    }
    finally {
        $ecdsa.Dispose()
    }
}

function Get-ProductionManifestArtifactCandidateFileName {
    param(
        [Parameter(Mandatory = $true)][string]$ArtifactUri,
        [Parameter(Mandatory = $true)][string]$ArtifactBaseUri,
        [Parameter(Mandatory = $true)][string]$Label
    )

    [Uri]$baseUri = $null
    [Uri]$uri = $null
    if (-not [Uri]::TryCreate($ArtifactBaseUri, [UriKind]::Absolute, [ref]$baseUri) -or
        -not [Uri]::TryCreate($ArtifactUri, [UriKind]::Absolute, [ref]$uri) -or
        $baseUri.Scheme -cne 'https' -or
        $uri.Scheme -cne 'https' -or
        -not [string]::IsNullOrEmpty($uri.UserInfo) -or
        -not [string]::IsNullOrEmpty($uri.Query) -or
        -not [string]::IsNullOrEmpty($uri.Fragment)) {
        throw "$Label URI must be one absolute HTTPS artifact URI without user info, query, or fragment."
    }
    if ($ArtifactUri -cne $uri.AbsoluteUri) {
        throw "$Label URI must use its exact System.Uri AbsoluteUri serialization."
    }
    $escapedName = [IO.Path]::GetFileName($uri.AbsolutePath)
    if ([string]::IsNullOrWhiteSpace($escapedName)) {
        throw "$Label URI does not name one candidate file."
    }
    try {
        $fileName = [Uri]::UnescapeDataString($escapedName)
    }
    catch {
        throw "$Label URI contains a noncanonical escaped file name."
    }
    if ($fileName -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$' -or
        [IO.Path]::GetFileName($fileName) -cne $fileName -or
        $ArtifactUri -cne ($ArtifactBaseUri + $fileName)) {
        throw "$Label URI is not the exact canonical plan artifact-base URI plus one candidate basename."
    }
    return $fileName
}

function Get-ProductionComponentReleaseIdContract {
    param(
        [Parameter(Mandatory = $true)][psobject]$Plan,
        [Parameter(Mandatory = $true)][psobject]$ComponentReleaseIds,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $expectedMembers = if ([string]$Plan.edition -ceq 'Personal') {
        @('clientBundle', 'runtime')
    }
    else {
        @('launcher', 'runtime', 'pluginPolicy')
    }
    Assert-ExactProductionJsonMembers `
        -Value $ComponentReleaseIds `
        -Expected $expectedMembers `
        -Label $Label
    foreach ($member in $expectedMembers) {
        if ([string]$ComponentReleaseIds.PSObject.Properties[$member].Value -cnotmatch
                '^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$') {
            throw "$Label member '$member' is not one exact production release ID."
        }
    }
    if ([string]$ComponentReleaseIds.runtime -cne
        [string]$Plan.runtimeCandidate.releaseId) {
        throw "$Label runtime release ID does not equal the exact plan runtime candidate release ID."
    }
    if ([string]$Plan.edition -ceq 'Personal') {
        return @(
            [pscustomobject]@{
                Component = 'client-bundle'
                ReleaseId = [string]$ComponentReleaseIds.clientBundle
            },
            [pscustomobject]@{
                Component = 'runtime'
                ReleaseId = [string]$ComponentReleaseIds.runtime
            })
    }
    return @(
        [pscustomobject]@{
            Component = 'launcher'
            ReleaseId = [string]$ComponentReleaseIds.launcher
        },
        [pscustomobject]@{
            Component = 'runtime'
            ReleaseId = [string]$ComponentReleaseIds.runtime
        },
        [pscustomobject]@{
            Component = 'plugin-policy'
            ReleaseId = [string]$ComponentReleaseIds.pluginPolicy
        })
}

function ConvertFrom-ProductionReleaseManifestUtc {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][ValidateSet('Personal', 'Enterprise')]
        [string]$Edition,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $format = if ($Edition -ceq 'Personal') {
        "yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'"
    }
    else {
        "yyyy-MM-dd'T'HH:mm:ss.fffffffzzz"
    }
    [DateTimeOffset]$parsed = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParseExact(
            $Value,
            $format,
            [Globalization.CultureInfo]::InvariantCulture,
            ([Globalization.DateTimeStyles]::AssumeUniversal -bor
             [Globalization.DateTimeStyles]::AdjustToUniversal),
            [ref]$parsed) -or
        $parsed.Offset -ne [TimeSpan]::Zero -or
        $Value -cne $parsed.ToString(
            $format,
            [Globalization.CultureInfo]::InvariantCulture)) {
        $suffix = if ($Edition -ceq 'Personal') {
            'seven fractional digits and Z'
        }
        else {
            'seven fractional digits and +00:00'
        }
        throw "$Label must be exact canonical UTC with $suffix."
    }
    return $parsed
}

function Assert-ProductionReleaseManifestCandidate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][psobject]$Plan,
        [Parameter(Mandatory = $true)]$ManifestInput,
        [Parameter(Mandatory = $true)][string]$CandidateRoot,
        [Parameter(Mandatory = $true)][object[]]$Files,
        [Parameter(Mandatory = $true)][psobject]$ComponentReleaseIds,
        [Parameter(Mandatory = $true)][psobject]$RuntimeProvenance,
        [Parameter(Mandatory = $true)][DateTimeOffset]$ValidationTimeUtc
    )

    [void](Assert-CanonicalProductionJsonInput `
        -Input $ManifestInput `
        -Label 'Target-channel signed release-set candidate')
    if ([int64]$ManifestInput.Bytes.Length -gt 524288) {
        throw 'Target-channel signed release-set candidate exceeds the product 512 KiB manifest bound.'
    }
    $manifest = $ManifestInput.Value
    $manifestMembers = if ([string]$Plan.edition -ceq 'Personal') {
        @(
            'schemaVersion', 'product', 'environment', 'channel',
            'releaseSetId', 'provenance', 'generation', 'sequence',
            'minAcceptedSequence', 'issuedAtUtc', 'expiresAtUtc',
            'maximumOfflineGraceSeconds', 'startupStub',
            'revokedReleaseSetIds', 'artifacts', 'signature')
    }
    else {
        @(
            'schemaVersion', 'product', 'environment', 'channel',
            'releaseSetId', 'generation', 'sequence', 'minAcceptedSequence',
            'issuedAtUtc', 'expiresAtUtc', 'startupStub',
            'revokedReleaseSetIds', 'artifacts', 'signature')
    }
    Assert-ExactProductionJsonMembers `
        -Value $manifest `
        -Expected $manifestMembers `
        -Label 'Target-channel signed release-set candidate'
    Assert-ExactProductionJsonMembers `
        -Value $manifest.signature `
        -Expected @('algorithm', 'keyId', 'value') `
        -Label 'Target-channel release-manifest signature'

    $expectedProduct = if ([string]$Plan.edition -ceq 'Personal') {
        'ensou-dsh-personal'
    }
    else {
        'ensou-dsh-enterprise'
    }
    if ($manifest.schemaVersion -isnot [long] -or
        [int64]$manifest.schemaVersion -ne 2 -or
        $manifest.product -isnot [string] -or
        $manifest.environment -isnot [string] -or
        $manifest.channel -isnot [string] -or
        $manifest.releaseSetId -isnot [string] -or
        [string]$manifest.product -cne $expectedProduct -or
        [string]$manifest.environment -cne 'production' -or
        [string]$manifest.channel -cne [string]$Plan.targetChannel -or
        [string]$manifest.releaseSetId -cne [string]$Plan.releaseSetId) {
        throw 'Signed release manifest does not match the exact edition, target channel, release set, and production identity in the plan.'
    }
    if ($manifest.signature.algorithm -isnot [string] -or
        $manifest.signature.keyId -isnot [string] -or
        $manifest.signature.value -isnot [string] -or
        [string]$manifest.signature.algorithm -cne 'ES256' -or
        [string]$Plan.releaseManifestTrust.algorithm -cne 'ES256' -or
        [string]$Plan.releaseManifestTrust.purpose -cne 'release-manifest-signing' -or
        [string]$manifest.signature.keyId -cne
            [string]$Plan.releaseManifestTrust.keyId) {
        throw 'Signed release manifest does not match the plan release-manifest trust.'
    }
    if ($manifest.generation -isnot [long] -or
        $manifest.sequence -isnot [long] -or
        $manifest.minAcceptedSequence -isnot [long] -or
        [int64]$manifest.generation -lt 1 -or
        [int64]$manifest.generation -gt 9007199254740991L -or
        [int64]$manifest.sequence -lt 1 -or
        [int64]$manifest.sequence -gt 9007199254740991L -or
        [int64]$manifest.minAcceptedSequence -lt 0 -or
        [int64]$manifest.minAcceptedSequence -gt [int64]$manifest.sequence) {
        throw 'Signed release manifest generation, sequence, and minAcceptedSequence must be exact safe JSON integers in product order.'
    }
    if ($manifest.issuedAtUtc -isnot [string] -or
        $manifest.expiresAtUtc -isnot [string]) {
        throw 'Signed release-manifest timestamps must be exact JSON strings.'
    }
    $issuedAtUtc = ConvertFrom-ProductionReleaseManifestUtc `
        -Value ([string]$manifest.issuedAtUtc) `
        -Edition ([string]$Plan.edition) `
        -Label 'Signed release-manifest issuedAtUtc'
    $expiresAtUtc = ConvertFrom-ProductionReleaseManifestUtc `
        -Value ([string]$manifest.expiresAtUtc) `
        -Edition ([string]$Plan.edition) `
        -Label 'Signed release-manifest expiresAtUtc'
    $validationUtc = $ValidationTimeUtc.ToUniversalTime()
    if ($issuedAtUtc -le [DateTimeOffset]::UnixEpoch -or
        $expiresAtUtc -le $issuedAtUtc -or
        $issuedAtUtc -gt $validationUtc.AddMinutes(2) -or
        $expiresAtUtc -lt $validationUtc.AddMinutes(-2) -or
        ($expiresAtUtc - $issuedAtUtc) -gt [TimeSpan]::FromDays(31)) {
        throw 'Signed release manifest validity window is invalid, future-dated, expired, or exceeds 31 days.'
    }
    if ($manifest.revokedReleaseSetIds -isnot [object[]]) {
        throw 'Signed release manifest revokedReleaseSetIds must be one exact JSON array.'
    }
    $revoked = @($manifest.revokedReleaseSetIds)
    if ($revoked.Count -gt 1000) {
        throw 'Signed release manifest revocation list exceeds the product bound.'
    }
    $revokedSet = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
    $lastRevoked = $null
    foreach ($releaseSetId in $revoked) {
        if ($releaseSetId -isnot [string] -or
            [string]$releaseSetId -cnotmatch
                '^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$' -or
            [string]$releaseSetId -ceq [string]$manifest.releaseSetId -or
            -not $revokedSet.Add([string]$releaseSetId) -or
            ([string]$Plan.edition -ceq 'Personal' -and
             $null -ne $lastRevoked -and
             [string]::CompareOrdinal([string]$lastRevoked, [string]$releaseSetId) -ge 0)) {
            throw 'Signed release manifest revocation list is invalid, duplicated, self-revoking, or noncanonical.'
        }
        $lastRevoked = [string]$releaseSetId
    }

    if ([string]$Plan.edition -ceq 'Personal') {
        Assert-ExactProductionJsonMembers `
            -Value $manifest.provenance `
            -Expected @(
                'launcherRepositoryCommit', 'harnessSourceTag',
                'harnessSourceCommit') `
            -Label 'Personal signed release-manifest provenance'
        Assert-ExactProductionJsonMembers `
            -Value $manifest.startupStub `
            -Expected @('minimumVersion', 'maximumVersion') `
            -Label 'Personal signed release-manifest Startup Stub compatibility'
        if ($manifest.provenance.launcherRepositoryCommit -isnot [string] -or
            $manifest.provenance.harnessSourceTag -isnot [string] -or
            $manifest.provenance.harnessSourceCommit -isnot [string] -or
            $manifest.startupStub.minimumVersion -isnot [string] -or
            $manifest.startupStub.maximumVersion -isnot [string] -or
            [string]$manifest.provenance.launcherRepositoryCommit -cne
                [string]$Plan.sourceCommit -or
            [string]$manifest.provenance.harnessSourceTag -cne
                [string]$RuntimeProvenance.harnessSourceTag -or
            [string]$manifest.provenance.harnessSourceCommit -cne
                [string]$RuntimeProvenance.harnessSourceCommit -or
            [string]$manifest.startupStub.minimumVersion -cne
                [string]$Plan.releaseCompatibility.startupStubVersion -or
            [string]$manifest.startupStub.maximumVersion -cne
                [string]$Plan.releaseCompatibility.startupStubVersion -or
            [int64]$manifest.sequence -lt
                [int64]$Plan.releaseCompatibility.canonicalLowSFromSequence -or
            $manifest.maximumOfflineGraceSeconds -isnot [long] -or
            [int64]$manifest.maximumOfflineGraceSeconds -lt 3600 -or
            [int64]$manifest.maximumOfflineGraceSeconds -gt 604800) {
            throw 'Personal signed release manifest does not match the plan release compatibility or source commit.'
        }
    }
    else {
        Assert-ExactProductionJsonMembers `
            -Value $manifest.startupStub `
            -Expected @('minimumProtocol', 'maximumProtocol') `
            -Label 'Enterprise signed release-manifest Startup Stub compatibility'
        $protocol = [int]$Plan.releaseCompatibility.startupStubProtocol
        if ($protocol -ne 1 -or
            $manifest.startupStub.minimumProtocol -isnot [long] -or
            $manifest.startupStub.maximumProtocol -isnot [long] -or
            [int64]$manifest.startupStub.minimumProtocol -lt 1 -or
            [int64]$manifest.startupStub.maximumProtocol -gt [int]::MaxValue -or
            [int64]$manifest.startupStub.maximumProtocol -lt
                [int64]$manifest.startupStub.minimumProtocol -or
            [int]$manifest.startupStub.minimumProtocol -gt $protocol -or
            [int]$manifest.startupStub.maximumProtocol -lt $protocol) {
            throw 'Enterprise signed release manifest does not match the plan Startup Stub protocol.'
        }
    }

    $componentContracts = @(Get-ProductionComponentReleaseIdContract `
        -Plan $Plan `
        -ComponentReleaseIds $ComponentReleaseIds `
        -Label 'Signed-candidate component release IDs')
    $expectedComponents = @($componentContracts | ForEach-Object { $_.Component })
    if ($manifest.artifacts -isnot [object[]]) {
        throw 'Signed release manifest artifacts must be one exact JSON array.'
    }
    $artifacts = @($manifest.artifacts)
    if ($artifacts.Count -ne $expectedComponents.Count) {
        throw 'Signed release manifest does not contain its exact edition-fixed artifact inventory.'
    }
    $artifactFileNames = [Collections.Generic.List[string]]::new()
    $candidateNames = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    [void]$candidateNames.Add('release-set.v2.json')
    if ([string]$Plan.edition -ceq 'Enterprise') {
        [void]$candidateNames.Add('release-public-key.v2.json')
    }
    for ($index = 0; $index -lt $artifacts.Count; $index++) {
        $artifact = $artifacts[$index]
        Assert-ExactProductionJsonMembers `
            -Value $artifact `
            -Expected @(
                'component', 'releaseId', 'uri', 'sizeBytes', 'sha256',
                'completeTreeSha256', 'signature') `
            -Label "Target-channel release-manifest artifact index $index"
        Assert-ExactProductionJsonMembers `
            -Value $artifact.signature `
            -Expected @('algorithm', 'keyId', 'value') `
            -Label "Target-channel release-manifest artifact signature index $index"
        $maximumArtifactBytes = if ([string]$artifact.component -ceq 'runtime') {
            8589934592L
        }
        elseif ([string]$artifact.component -ceq 'plugin-policy') {
            536870912L
        }
        else {
            1073741824L
        }
        if ($artifact.component -isnot [string] -or
            $artifact.releaseId -isnot [string] -or
            $artifact.uri -isnot [string] -or
            $artifact.sha256 -isnot [string] -or
            $artifact.completeTreeSha256 -isnot [string] -or
            $artifact.signature.algorithm -isnot [string] -or
            $artifact.signature.keyId -isnot [string] -or
            $artifact.signature.value -isnot [string] -or
            [string]$artifact.component -cne [string]$expectedComponents[$index] -or
            [string]$artifact.releaseId -cne
                [string]$componentContracts[$index].ReleaseId -or
            $artifact.sizeBytes -isnot [long] -or
            [int64]$artifact.sizeBytes -lt 1 -or
            [int64]$artifact.sizeBytes -gt $maximumArtifactBytes -or
            [string]$artifact.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [string]$artifact.completeTreeSha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [string]$artifact.signature.algorithm -cne 'ES256' -or
            [string]$artifact.signature.keyId -cne
                [string]$Plan.releaseManifestTrust.keyId) {
            throw "Signed release-manifest artifact index $index violates its exact edition, release-set, digest, or trust policy."
        }
        $fileName = Get-ProductionManifestArtifactCandidateFileName `
            -ArtifactUri ([string]$artifact.uri) `
            -ArtifactBaseUri ([string]$Plan.artifactBaseUri) `
            -Label "Signed release-manifest artifact index $index"
        if (-not $candidateNames.Add($fileName)) {
            throw "Signed release manifest contains a case-insensitive candidate file-name collision at '$fileName'."
        }
        $artifactFileNames.Add($fileName)
    }

    $signature = ConvertFrom-Base64UrlStrict `
        -Value ([string]$manifest.signature.value) `
        -Label 'Release-manifest signature'
    Assert-ProductionEs256P1363LowS `
        -Signature $signature `
        -Label 'Release-manifest signature'
    $payloadObject = [ordered]@{}
    foreach ($propertyName in $manifestMembers) {
        if ($propertyName -cne 'signature') {
            $payloadObject[$propertyName] = $manifest.PSObject.Properties[$propertyName].Value
        }
    }
    $payload = if ([string]$Plan.edition -ceq 'Enterprise') {
        ConvertTo-ProductionEnterpriseReleaseManifestPayloadBytes `
            -Manifest $payloadObject
    }
    else {
        ConvertTo-ProductionSystemTextJsonBytes -Value $payloadObject
    }
    $x = ConvertFrom-Base64UrlStrict `
        -Value ([string]$Plan.releaseManifestTrust.x) `
        -Label 'Release-manifest trust key X'
    $y = ConvertFrom-Base64UrlStrict `
        -Value ([string]$Plan.releaseManifestTrust.y) `
        -Label 'Release-manifest trust key Y'
    if ($x.Length -ne 32 -or $y.Length -ne 32) {
        throw 'Release-manifest trust uses invalid P-256 coordinate sizes.'
    }
    $parameters = [Security.Cryptography.ECParameters]::new()
    $parameters.Curve = [Security.Cryptography.ECCurve+NamedCurves]::nistP256
    $point = [Security.Cryptography.ECPoint]::new()
    $point.X = $x
    $point.Y = $y
    $parameters.Q = $point
    $ecdsa = [Security.Cryptography.ECDsa]::Create()
    try {
        try {
            $ecdsa.ImportParameters($parameters)
        }
        catch {
            throw 'Release-manifest trust is not one valid P-256 public point.'
        }
        for ($index = 0; $index -lt $artifacts.Count; $index++) {
            $artifact = $artifacts[$index]
            $artifactSignature = ConvertFrom-Base64UrlStrict `
                -Value ([string]$artifact.signature.value) `
                -Label "Release-manifest artifact signature index $index"
            Assert-ProductionEs256P1363LowS `
                -Signature $artifactSignature `
                -Label "Release-manifest artifact signature index $index"
            $artifactPayloadLines = if ([string]$Plan.edition -ceq 'Personal') {
                @(
                    'ensou-dsh-personal-artifact-v2', [string]$manifest.product,
                    [string]$manifest.environment, [string]$manifest.channel,
                    [string]$manifest.releaseSetId, [string]$manifest.generation,
                    [string]$manifest.sequence, [string]$artifact.component,
                    [string]$artifact.releaseId, [string]$artifact.uri,
                    [string]$artifact.sizeBytes, [string]$artifact.sha256,
                    [string]$artifact.completeTreeSha256)
            }
            else {
                @(
                    'ensou-dsh-enterprise-artifact-v2', [string]$manifest.product,
                    [string]$manifest.environment, [string]$manifest.releaseSetId,
                    [string]$artifact.component, [string]$artifact.releaseId,
                    [string]$artifact.sizeBytes, [string]$artifact.sha256,
                    [string]$artifact.completeTreeSha256, [string]$artifact.uri)
            }
            $artifactPayload = $script:Utf8Strict.GetBytes(
                ($artifactPayloadLines -join [char]10))
            if (-not $ecdsa.VerifyData(
                    $artifactPayload,
                    $artifactSignature,
                    [Security.Cryptography.HashAlgorithmName]::SHA256,
                    [Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)) {
                throw "Release-manifest artifact signature index $index is invalid for the exact plan trust and canonical payload."
            }
        }
        if (-not $ecdsa.VerifyData(
                $payload,
                $signature,
                [Security.Cryptography.HashAlgorithmName]::SHA256,
                [Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)) {
            throw 'Release-manifest signature is invalid for the exact plan trust and canonical payload.'
        }
    }
    finally {
        $ecdsa.Dispose()
    }

    $expectedFiles = [Collections.Generic.List[object]]::new()
    $expectedFiles.Add([pscustomobject]@{
        Role = 'release-manifest'
        FileName = 'release-set.v2.json'
        SizeBytes = [int64]$ManifestInput.Bytes.Length
        Sha256 = [string]$ManifestInput.Sha256
    })
    if ([string]$Plan.edition -ceq 'Enterprise') {
        $releaseKeyInput = Read-StrictProductionJsonFile `
            -Path (Join-Path $CandidateRoot 'release-public-key.v2.json') `
            -Label 'Enterprise signed-candidate release public key'
        [void](Assert-CanonicalProductionJsonInput `
            -Input $releaseKeyInput `
            -Label 'Enterprise signed-candidate release public key')
        Assert-ExactProductionJsonMembers `
            -Value $releaseKeyInput.Value `
            -Expected @('keyId', 'x', 'y') `
            -Label 'Enterprise signed-candidate release public key'
        if ([string]$releaseKeyInput.Value.keyId -cne
                [string]$Plan.releaseManifestTrust.keyId -or
            [string]$releaseKeyInput.Value.x -cne
                [string]$Plan.releaseManifestTrust.x -or
            [string]$releaseKeyInput.Value.y -cne
                [string]$Plan.releaseManifestTrust.y) {
            throw 'Enterprise signed-candidate release public key does not equal the plan release-manifest trust.'
        }
        $expectedFiles.Add([pscustomobject]@{
            Role = 'release-public-key'
            FileName = 'release-public-key.v2.json'
            SizeBytes = [int64]$releaseKeyInput.Bytes.Length
            Sha256 = [string]$releaseKeyInput.Sha256
        })
    }
    for ($index = 0; $index -lt $artifacts.Count; $index++) {
        $expectedFiles.Add([pscustomobject]@{
            Role = [string]$expectedComponents[$index]
            FileName = [string]$artifactFileNames[$index]
            SizeBytes = [int64]$artifacts[$index].sizeBytes
            Sha256 = [string]$artifacts[$index].sha256
        })
    }
    if ($Files.Count -ne $expectedFiles.Count) {
        throw 'Target-channel signed-candidate response does not contain its exact edition-fixed file inventory.'
    }
    $responseNames = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    for ($index = 0; $index -lt $Files.Count; $index++) {
        $actual = $Files[$index]
        $expected = $expectedFiles[$index]
        if (-not $responseNames.Add([string]$actual.fileName)) {
            throw "Target-channel signed-candidate response contains a case-insensitive file-name collision at index $index."
        }
        if ([string]$actual.role -cne [string]$expected.Role -or
            [string]$actual.fileName -cne [string]$expected.FileName -or
            [string]$actual.relativePath -cne
                ('candidate/' + [string]$expected.FileName) -or
            [int64]$actual.sizeBytes -ne [int64]$expected.SizeBytes -or
            [string]$actual.sha256 -cne [string]$expected.Sha256) {
            throw "Target-channel signed-candidate file index $index is not the exact manifest-derived edition-fixed role, basename, size, and digest."
        }
    }
    return $expectedFiles
}

function Get-ProductionInitializationMarkerBytes {
    param(
        [Parameter(Mandatory = $true)][byte[]]$PlanBytes,
        [Parameter(Mandatory = $true)][psobject]$Plan
    )

    $schemaVersion = [int]$Plan.schemaVersion
    $marker = [ordered]@{
        schemaVersion = 1
        ownerType = 'ensou-dsh-launcher-production-state-initialization'
        planSchemaVersion = $schemaVersion
        orchestrationId = [string]$Plan.orchestrationId
        edition = [string]$Plan.edition
        planSha256 = Get-ProductionSha256Bytes -Bytes $PlanBytes
        identityCreatedAtUtc = ConvertTo-ProductionUtc -Value ([DateTimeOffset]::UtcNow)
        initializationNonce = [Guid]::NewGuid().ToString('N')
    }
    if ($schemaVersion -eq 2) {
        $marker.targetChannel = [string]$Plan.targetChannel
    }
    return ConvertTo-ProductionJsonBytes -Value $marker
}

function Open-ProductionInitializationMarker {
    param(
        [Parameter(Mandatory = $true)][string]$StateRoot,
        [Parameter(Mandatory = $true)][byte[]]$PlanBytes,
        [Parameter(Mandatory = $true)][psobject]$Plan
    )

    $marker = Open-ProductionReleaseInput `
        -Path (Join-Path $StateRoot 'initialization.json') `
        -Label 'Production state initialization marker' `
        -MaximumBytes 16KB
    try {
        $bytes = Read-ProductionReleaseInputBytes `
            -Descriptor $marker `
            -Label 'Production state initialization marker'
        $value = ConvertFrom-StrictProductionJsonBytes `
            -Bytes $bytes `
            -Label 'Production state initialization marker'
        $schemaVersion = [int]$Plan.schemaVersion
        $expectedNames = @(
            'schemaVersion',
            'ownerType',
            'planSchemaVersion',
            'orchestrationId',
            'edition',
            'planSha256',
            'identityCreatedAtUtc',
            'initializationNonce'
        )
        if ($schemaVersion -eq 2) {
            $expectedNames += 'targetChannel'
        }
        $actualNames = @($value.PSObject.Properties.Name)
        if ($actualNames.Count -ne $expectedNames.Count -or
            @($actualNames | Where-Object { $_ -notin $expectedNames }).Count -ne 0 -or
            [int]$value.schemaVersion -ne 1 -or
            [string]$value.ownerType -cne 'ensou-dsh-launcher-production-state-initialization' -or
            [int]$value.planSchemaVersion -ne $schemaVersion -or
            [string]$value.orchestrationId -cne [string]$Plan.orchestrationId -or
            [string]$value.edition -cne [string]$Plan.edition -or
            [string]$value.planSha256 -cne (Get-ProductionSha256Bytes -Bytes $PlanBytes) -or
            [string]$value.initializationNonce -cnotmatch '^[0-9a-f]{32}$' -or
            ($schemaVersion -eq 2 -and
             [string]$value.targetChannel -cne [string]$Plan.targetChannel)) {
            throw 'Existing production state initialization marker conflicts with the supplied plan.'
        }
        $createdAt = ConvertFrom-ProductionUtc `
            -Value ([string]$value.identityCreatedAtUtc) `
            -Label 'Production state initialization identity time'
        if ((ConvertTo-ProductionUtc -Value $createdAt) -cne [string]$value.identityCreatedAtUtc) {
            throw 'Production state initialization marker uses a noncanonical identity timestamp.'
        }
        $marker | Add-Member -NotePropertyName Value -NotePropertyValue $value
        return $marker
    }
    catch {
        $marker.Stream.Dispose()
        throw
    }
}

function Assert-ProductionInitializationRecoveryInventory {
    param([Parameter(Mandatory = $true)][string]$StateRoot)

    $allowed = @(
        'identity.json.pending',
        'initialization.json',
        'plan.json',
        'plan.json.pending',
        'state.lock'
    )
    foreach ($entry in Get-ChildItem -LiteralPath $StateRoot -Force) {
        if ($entry.Name -notin $allowed) {
            throw "Incomplete production state root contains unexpected entry '$($entry.Name)'."
        }
        if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Incomplete production state root contains linked entry '$($entry.Name)'."
        }
    }
}

function Assert-FullyInitializedLegacyProductionStateRoot {
    param([Parameter(Mandatory = $true)][string]$StateRoot)

    $requiredFiles = @('identity.json', 'plan.json', 'state.lock')
    $requiredDirectories = @('imports', 'receipts', 'requests')
    $allowed = $requiredFiles + $requiredDirectories + @('head.json', 'head.json.pending')
    $entries = @(Get-ChildItem -LiteralPath $StateRoot -Force)
    foreach ($entry in $entries) {
        if ($entry.Name -notin $allowed -or
            ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Legacy production state root contains unexpected entry '$($entry.Name)'."
        }
    }
    foreach ($fileName in $requiredFiles) {
        if (-not (Test-Path -LiteralPath (Join-Path $StateRoot $fileName) -PathType Leaf)) {
            throw "Legacy production state root is incomplete because '$fileName' is missing."
        }
    }
    foreach ($directoryName in $requiredDirectories) {
        if (-not (Test-Path -LiteralPath (Join-Path $StateRoot $directoryName) -PathType Container)) {
            throw "Legacy production state root is incomplete because '$directoryName' is missing."
        }
    }
}

function Remove-ProductionInitializationStagingRoot {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedParent,
        [Parameter(Mandatory = $true)][string]$ExpectedName
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }
    $fullPath = [IO.Path]::GetFullPath($Path)
    if ([IO.Path]::GetFullPath([IO.Path]::GetDirectoryName($fullPath)) -cne
        [IO.Path]::GetFullPath($ExpectedParent) -or
        [IO.Path]::GetFileName($fullPath) -cne $ExpectedName) {
        throw 'Production initialization staging cleanup escaped its exact parent and name.'
    }
    $directory = Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop
    if (-not $directory.PSIsContainer -or
        ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Production initialization staging cleanup target is not one ordinary directory.'
    }
    $allowed = @('initialization.json', 'initialization.json.pending', 'state.lock')
    $entries = @(Get-ChildItem -LiteralPath $fullPath -Force)
    foreach ($entry in $entries) {
        if ($entry.Name -notin $allowed -or
            ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            $entry.PSIsContainer) {
            throw 'Production initialization staging cleanup found an unexpected entry.'
        }
    }
    foreach ($entry in $entries) {
        [IO.File]::Delete($entry.FullName)
    }
    [IO.Directory]::Delete($fullPath, $false)
}

function Enter-ProductionReleaseStateLock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$StateRoot,
        [Parameter(Mandatory = $true)][byte[]]$PlanBytes,
        [Parameter(Mandatory = $true)][psobject]$Plan
    )

    if (-not [IO.Path]::IsPathFullyQualified($StateRoot)) {
        throw 'Production state root must be absolute.'
    }
    $fullRoot = [IO.Path]::GetFullPath($StateRoot)
    $parentPath = [IO.Path]::GetDirectoryName($fullRoot)
    $rootName = [IO.Path]::GetFileName($fullRoot)
    if ([string]::IsNullOrWhiteSpace($parentPath) -or
        [string]::IsNullOrWhiteSpace($rootName)) {
        throw 'Production state root must name one child directory.'
    }
    $parent = Assert-OrdinaryProductionDirectory `
        -Path $parentPath `
        -Label 'Production state parent'
    $markerBytes = Get-ProductionInitializationMarkerBytes `
        -PlanBytes $PlanBytes `
        -Plan $Plan
    $created = $false
    if (-not (Test-Path -LiteralPath $fullRoot)) {
        $operationId = ([Guid]::Parse([string]$Plan.orchestrationId)).ToString('N')
        $stagingName = ".ensou-launcher-state-init-$operationId-$([Guid]::NewGuid().ToString('N'))"
        $stagingRoot = Join-Path $parent $stagingName
        [IO.Directory]::CreateDirectory($stagingRoot) | Out-Null
        try {
            [void](Assert-OrdinaryProductionDirectory `
                -Path $stagingRoot `
                -Label 'Production state initialization staging root')
            Write-ProductionStateFile `
                -Path (Join-Path $stagingRoot 'initialization.json') `
                -Bytes $markerBytes
            $stagingLock = [IO.File]::Open(
                (Join-Path $stagingRoot 'state.lock'),
                [IO.FileMode]::CreateNew,
                [IO.FileAccess]::ReadWrite,
                [IO.FileShare]::None)
            try {
                [void][EnsouLauncherProduction.NativeFileIdentity]::RequireOrdinarySingleLink(
                    $stagingLock.SafeFileHandle)
                $stagingLock.Flush($true)
            }
            finally {
                $stagingLock.Dispose()
            }
            try {
                [IO.Directory]::Move($stagingRoot, $fullRoot)
                $created = $true
            }
            catch {
                if (-not (Test-Path -LiteralPath $fullRoot)) {
                    throw
                }
            }
        }
        finally {
            if (Test-Path -LiteralPath $stagingRoot) {
                Remove-ProductionInitializationStagingRoot `
                    -Path $stagingRoot `
                    -ExpectedParent $parent `
                    -ExpectedName $stagingName
            }
        }
    }
    $fullRoot = Assert-OrdinaryProductionDirectory -Path $fullRoot -Label 'Production state root'
    $lockPath = Join-Path $fullRoot 'state.lock'
    if (-not (Test-Path -LiteralPath $lockPath -PathType Leaf)) {
        throw 'Existing production state root is not an owned initialization transaction because its lock file is missing.'
    }
    $marker = $null
    try {
        if (Test-Path -LiteralPath (Join-Path $fullRoot 'initialization.json') -PathType Leaf) {
            $marker = Open-ProductionInitializationMarker `
                -StateRoot $fullRoot `
                -PlanBytes $PlanBytes `
                -Plan $Plan
        }
        else {
            if ([int]$Plan.schemaVersion -ne 1) {
                throw 'Existing incomplete production state root is not bound to an initialization owner.'
            }
            Assert-FullyInitializedLegacyProductionStateRoot -StateRoot $fullRoot
        }
        try {
            $stream = [IO.File]::Open(
                $lockPath,
                [IO.FileMode]::Open,
                [IO.FileAccess]::ReadWrite,
                [IO.FileShare]::None)
        }
        catch {
            throw 'Production state root is locked by another orchestration process.'
        }
        try {
            [void][EnsouLauncherProduction.NativeFileIdentity]::RequireOrdinarySingleLink(
                $stream.SafeFileHandle)
            if ($null -ne $marker) {
                Assert-ProductionReleaseInputStillLocked `
                    -Descriptor $marker `
                    -Label 'Production state initialization marker'
            }
            return [pscustomobject]@{
                StateRoot = $fullRoot
                Created = $created
                Stream = $stream
            }
        }
        catch {
            $stream.Dispose()
            throw
        }
    }
    finally {
        if ($null -ne $marker) {
            $marker.Stream.Dispose()
        }
    }
}

function Assert-ProductionStateTopLevel {
    param([Parameter(Mandatory = $true)][string]$StateRoot)

    foreach ($entry in Get-ChildItem -LiteralPath $StateRoot -Force) {
        if ($entry.Name -notin $script:AllowedStateEntries -and
            $entry.Name -cne 'head.json.pending') {
            throw "Production state root contains unexpected entry '$($entry.Name)'."
        }
        if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Production state root contains linked entry '$($entry.Name)'."
        }
    }
}

function Initialize-ProductionReleaseState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Lock,
        [Parameter(Mandatory = $true)][byte[]]$PlanBytes,
        [Parameter(Mandatory = $true)][psobject]$Plan,
        [Parameter(Mandatory = $true)][string]$StateSchemaPath,
        [ValidateSet('', 'AfterPlanPending', 'AfterPlanSnapshot', 'AfterIdentityPending', 'AfterIdentity')]
        [string]$FaultPoint = ''
    )

    $stateRoot = [string]$Lock.StateRoot
    $schemaVersion = [int]$Plan.schemaVersion
    $targetChannel = if ($schemaVersion -eq 1) {
        [string]$Plan.channel
    }
    else {
        [string]$Plan.targetChannel
    }
    [void](Get-ProductionReleaseLifecycleContract -SchemaVersion $schemaVersion -TargetChannel $targetChannel)
    $planSha256 = Get-ProductionSha256Bytes -Bytes $PlanBytes
    $identityPath = Join-Path $stateRoot 'identity.json'
    $planPath = Join-Path $stateRoot 'plan.json'
    $markerPath = Join-Path $stateRoot 'initialization.json'
    $initializationMarker = $null
    if (Test-Path -LiteralPath $markerPath -PathType Leaf) {
        $initializationMarker = Open-ProductionInitializationMarker `
            -StateRoot $stateRoot `
            -PlanBytes $PlanBytes `
            -Plan $Plan
        $initializationMarker.Stream.Dispose()
    }
    if (Test-Path -LiteralPath $identityPath) {
        $identity = Read-StrictProductionJsonFile -Path $identityPath -Label 'Production state identity' -SchemaPath $StateSchemaPath
        $initializationShaProperty = $identity.Value.PSObject.Properties['initializationSha256']
        if ([int]$identity.Value.schemaVersion -ne $schemaVersion -or
            [string]$identity.Value.identityType -cne 'ensou-dsh-launcher-production-release-state' -or
            [string]$identity.Value.orchestrationId -cne [string]$Plan.orchestrationId -or
            [string]$identity.Value.edition -cne [string]$Plan.edition -or
            [string]$identity.Value.planSha256 -cne $planSha256 -or
            ($schemaVersion -eq 2 -and
             [string]$identity.Value.targetChannel -cne $targetChannel)) {
            throw 'Existing production state identity conflicts with the supplied plan.'
        }
        if (($null -eq $initializationShaProperty) -ne ($null -eq $initializationMarker) -or
            ($null -ne $initializationShaProperty -and
             [string]$initializationShaProperty.Value -cne [string]$initializationMarker.Sha256)) {
            throw 'Production state identity and initialization owner binding differ.'
        }
        $snapshot = Open-ProductionReleaseInput -Path $planPath -Label 'Production plan snapshot' -MaximumBytes $script:MaximumJsonBytes
        try {
            if ($snapshot.Sha256 -cne $planSha256) {
                throw 'Production plan changed after state initialization.'
            }
        }
        finally {
            $snapshot.Stream.Dispose()
        }
    }
    else {
        if ($null -eq $initializationMarker) {
            throw 'Incomplete production state root is missing its plan-bound initialization owner.'
        }
        Assert-ProductionInitializationRecoveryInventory -StateRoot $stateRoot
        Write-ProductionStateFile `
            -Path $planPath `
            -Bytes $PlanBytes `
            -FaultAfterPending:($FaultPoint -ceq 'AfterPlanPending')
        if ($FaultPoint -ceq 'AfterPlanSnapshot') {
            throw 'INJECTED-CRASH-AFTER-PLAN-SNAPSHOT'
        }
        $identity = [ordered]@{
            schemaVersion = $schemaVersion
            identityType = 'ensou-dsh-launcher-production-release-state'
            orchestrationId = [string]$Plan.orchestrationId
            edition = [string]$Plan.edition
            planSha256 = $planSha256
            initializationSha256 = [string]$initializationMarker.Sha256
            createdAtUtc = [string]$initializationMarker.Value.identityCreatedAtUtc
        }
        if ($schemaVersion -eq 2) {
            $identity.targetChannel = $targetChannel
        }
        $identityBytes = ConvertTo-ProductionJsonBytes -Value $identity
        [void](ConvertFrom-StrictProductionJsonBytes -Bytes $identityBytes -Label 'Generated production state identity' -SchemaPath $StateSchemaPath)
        Write-ProductionStateFile `
            -Path $identityPath `
            -Bytes $identityBytes `
            -FaultAfterPending:($FaultPoint -ceq 'AfterIdentityPending')
        if ($FaultPoint -ceq 'AfterIdentity') {
            throw 'INJECTED-CRASH-AFTER-IDENTITY'
        }
    }
    foreach ($directoryName in @('receipts', 'requests', 'imports')) {
        $directory = Join-Path $stateRoot $directoryName
        if (-not (Test-Path -LiteralPath $directory)) {
            [IO.Directory]::CreateDirectory($directory) | Out-Null
        }
        [void](Assert-OrdinaryProductionDirectory -Path $directory -Label "Production state $directoryName directory")
    }
    Assert-ProductionStateTopLevel -StateRoot $stateRoot
    return [pscustomobject]@{
        StateRoot = $stateRoot
        PlanSha256 = $planSha256
    }
}

function Get-TransitionSha256 {
    param(
        [Parameter(Mandatory = $true)][ValidateSet(1, 2)][int]$SchemaVersion,
        [Parameter(Mandatory = $true)][ValidateSet('pilot', 'stable')][string]$TargetChannel,
        [Parameter(Mandatory = $true)][string]$OrchestrationId,
        [Parameter(Mandatory = $true)][string]$Edition,
        [Parameter(Mandatory = $true)][string]$PlanSha256,
        [Parameter(Mandatory = $true)][string]$IdentitySha256,
        [Parameter(Mandatory = $true)][int]$Revision,
        [Parameter(Mandatory = $true)][string]$Phase,
        [Parameter(Mandatory = $true)][string]$PreviousReceiptSha256,
        [Parameter(Mandatory = $true)]$Data
    )

    $transition = if ($SchemaVersion -eq 1) {
        [ordered]@{
            transitionType = 'ensou-dsh-launcher-production-release-transition-v1'
            orchestrationId = $OrchestrationId
            edition = $Edition
            planSha256 = $PlanSha256
            identitySha256 = $IdentitySha256
            revision = $Revision
            phase = $Phase
            previousReceiptSha256 = $PreviousReceiptSha256
            data = $Data
        }
    }
    else {
        [ordered]@{
            transitionType = 'ensou-dsh-launcher-production-release-transition-v2'
            schemaVersion = 2
            targetChannel = $TargetChannel
            orchestrationId = $OrchestrationId
            edition = $Edition
            planSha256 = $PlanSha256
            identitySha256 = $IdentitySha256
            revision = $Revision
            phase = $Phase
            previousReceiptSha256 = $PreviousReceiptSha256
            data = $Data
        }
    }
    return Get-ProductionSha256Bytes -Bytes (ConvertTo-ProductionJsonBytes -Value $transition)
}

function Assert-ProductionReceipt {
    param(
        [Parameter(Mandatory = $true)][psobject]$Receipt,
        [Parameter(Mandatory = $true)][ValidateSet(1, 2)][int]$SchemaVersion,
        [Parameter(Mandatory = $true)][ValidateSet('pilot', 'stable')][string]$TargetChannel,
        [Parameter(Mandatory = $true)][int]$Revision,
        [Parameter(Mandatory = $true)][string]$OrchestrationId,
        [Parameter(Mandatory = $true)][string]$Edition,
        [Parameter(Mandatory = $true)][string]$PlanSha256,
        [Parameter(Mandatory = $true)][string]$IdentitySha256,
        [Parameter(Mandatory = $true)][string]$PreviousReceiptSha256
    )

    if ([int]$Receipt.schemaVersion -ne $SchemaVersion -or
        [string]$Receipt.receiptType -cne 'ensou-dsh-launcher-production-release-transition' -or
        [string]$Receipt.orchestrationId -cne $OrchestrationId -or
        [string]$Receipt.edition -cne $Edition -or
        [string]$Receipt.planSha256 -cne $PlanSha256 -or
        [string]$Receipt.identitySha256 -cne $IdentitySha256 -or
        [int]$Receipt.revision -ne $Revision -or
        [string]$Receipt.previousReceiptSha256 -cne $PreviousReceiptSha256 -or
        ($SchemaVersion -eq 2 -and
         [string]$Receipt.targetChannel -cne $TargetChannel)) {
        throw "Production transition receipt revision $Revision is not bound to its state chain."
    }
    [void](ConvertFrom-ProductionUtc -Value ([string]$Receipt.recordedAtUtc) -Label "Receipt $Revision time")
    $expectedTransition = Get-TransitionSha256 -SchemaVersion $SchemaVersion -TargetChannel $TargetChannel -OrchestrationId $OrchestrationId -Edition $Edition -PlanSha256 $PlanSha256 -IdentitySha256 $IdentitySha256 -Revision $Revision -Phase ([string]$Receipt.phase) -PreviousReceiptSha256 $PreviousReceiptSha256 -Data $Receipt.data
    if ([string]$Receipt.transitionSha256 -cne $expectedTransition) {
        throw "Production transition receipt revision $Revision has a non-canonical transition digest."
    }
}

function Assert-ExactProductionStateDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][Collections.IDictionary]$Expected,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $directory = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (-not $directory.PSIsContainer -or
        ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Label must be one ordinary directory."
    }
    $entries = @(Get-ChildItem -LiteralPath $directory.FullName -Force)
    if ($entries.Count -ne $Expected.Count) {
        throw "$Label does not contain its exact expected inventory."
    }
    foreach ($entry in $entries) {
        if (-not $Expected.Contains($entry.Name) -or
            ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            [bool]$entry.PSIsContainer -ne [bool]$Expected[$entry.Name]) {
            throw "$Label contains unexpected, linked, or mistyped entry '$($entry.Name)'."
        }
        if (-not $entry.PSIsContainer) {
            $locked = Open-ProductionReleaseInput -Path $entry.FullName -Label "$Label file $($entry.Name)" -MaximumBytes 512MB
            $locked.Stream.Dispose()
        }
    }
}

function Get-ProductionHistoricalHeadSha256 {
    param(
        [Parameter(Mandatory = $true)][string]$StateRoot,
        [Parameter(Mandatory = $true)][psobject]$Identity,
        [Parameter(Mandatory = $true)][string]$IdentitySha256,
        [Parameter(Mandatory = $true)][psobject]$Receipt
    )

    $revision = [int]$Receipt.revision
    $phase = [string]$Receipt.phase
    $receiptFileName = $revision.ToString('0000') + '-' +
        $phase.ToLowerInvariant().Replace('_', '-') + '.json'
    $receiptInput = Open-ProductionReleaseInput `
        -Path (Join-Path (Join-Path $StateRoot 'receipts') $receiptFileName) `
        -Label "Historical production receipt $revision" `
        -MaximumBytes $script:MaximumJsonBytes
    try {
        $head = [ordered]@{
            schemaVersion = [int]$Identity.schemaVersion
            stateType = 'ensou-dsh-launcher-production-release-head'
            orchestrationId = [string]$Identity.orchestrationId
            edition = [string]$Identity.edition
            planSha256 = [string]$Identity.planSha256
            identitySha256 = $IdentitySha256
            revision = $revision
            phase = $phase
            receiptFileName = $receiptFileName
            receiptSha256 = [string]$receiptInput.Sha256
            updatedAtUtc = [string]$Receipt.recordedAtUtc
        }
        if ([int]$Identity.schemaVersion -eq 2) {
            $head.targetChannel = [string]$Identity.targetChannel
        }
        return Get-ProductionSha256Bytes -Bytes (
            ConvertTo-ProductionJsonBytes -Value $head)
    }
    finally {
        $receiptInput.Stream.Dispose()
    }
}

function Assert-ProductionPublisherInputFileSet {
    param(
        [Parameter(Mandatory = $true)][psobject]$Plan,
        [Parameter(Mandatory = $true)][string]$PlanSha256,
        [Parameter(Mandatory = $true)][psobject]$PlanAdmissionReceipt,
        [Parameter(Mandatory = $true)][psobject]$ClientImportReceipt,
        [Parameter(Mandatory = $true)]$DescriptorInput,
        [Parameter(Mandatory = $true)][string]$PayloadRoot
    )

    [void](Assert-CanonicalProductionJsonInput `
        -Input $DescriptorInput `
        -Label 'Production Publisher input descriptor')
    $descriptor = $DescriptorInput.Value
    $schemaVersion = [int]$Plan.schemaVersion
    $channelContract = if ($schemaVersion -eq 2) {
        Get-ProductionManifestChannelContract `
            -TargetChannel ([string]$Plan.targetChannel)
    }
    else {
        $null
    }
    $descriptorMembers = @(
            'schemaVersion', 'descriptorType', 'orchestrationId', 'edition',
            'releaseSetId', 'channel', 'planSha256', 'sourceCommit',
            'manifestUri', 'artifactBaseUri', 'releaseManifestTrust',
            'releaseCompatibility', 'componentReleaseIds',
            'runtimeProvenance', 'files')
    if ($null -ne $descriptor.PSObject.Properties['runtimeSourceReleaseExpectation']) {
        $descriptorMembers += 'runtimeSourceReleaseExpectation'
    }
    Assert-ExactProductionJsonMembers `
        -Value $descriptor `
        -Expected $descriptorMembers `
        -Label 'Production Publisher input descriptor'
    Assert-ProductionRuntimeSourceReleaseExpectation -Plan $Plan -Value $descriptor
    $sourceExpectation = Get-ProductionRuntimeSourceReleaseExpectation -Plan $Plan
    if ($null -ne $sourceExpectation) {
        $admittedCandidate = $PlanAdmissionReceipt.data.runtimeCandidate
        if ($null -eq $admittedCandidate.PSObject.Properties['githubRepository'] -or
            $null -eq $admittedCandidate.PSObject.Properties['githubReleaseCommit'] -or
            [string]$admittedCandidate.githubRepository -cne [string]$sourceExpectation.repository -or
            [string]$admittedCandidate.githubReleaseCommit -cne [string]$sourceExpectation.targetCommit -or
            [string]$admittedCandidate.githubReleaseTag -cne [string]$sourceExpectation.tagName) {
            throw 'RUNTIME_SOURCE_EXPECTATION_MISMATCH: The original plan admission must retain the independent runtime repository, commit and tag.'
        }
    }
    [void]@(Get-ProductionComponentReleaseIdContract `
        -Plan $Plan `
        -ComponentReleaseIds $descriptor.componentReleaseIds `
        -Label 'Production Publisher component release IDs')
    Assert-ExactProductionJsonMembers `
        -Value $descriptor.runtimeProvenance `
        -Expected @('harnessSourceTag', 'harnessSourceCommit') `
        -Label 'Production Publisher runtime provenance'
    if ([int]$descriptor.schemaVersion -ne 1 -or
        [string]$descriptor.descriptorType -cne
            'ensou-dsh-launcher-production-publisher-input' -or
        [string]$descriptor.orchestrationId -cne [string]$Plan.orchestrationId -or
        [string]$descriptor.edition -cne [string]$Plan.edition -or
        [string]$descriptor.releaseSetId -cne [string]$Plan.releaseSetId -or
        [string]$descriptor.channel -cne [string]$channelContract.TargetChannel -or
        [string]$descriptor.planSha256 -cne $PlanSha256 -or
        [string]$descriptor.sourceCommit -cne [string]$Plan.sourceCommit -or
        [string]$descriptor.manifestUri -cne [string]$Plan.manifestUri -or
        [string]$descriptor.artifactBaseUri -cne [string]$Plan.artifactBaseUri -or
        (Get-ProductionSha256Bytes -Bytes (
                ConvertTo-ProductionJsonBytes -Value $descriptor.releaseManifestTrust)) -cne
            (Get-ProductionSha256Bytes -Bytes (
                ConvertTo-ProductionJsonBytes -Value $Plan.releaseManifestTrust)) -or
        (Get-ProductionSha256Bytes -Bytes (
                ConvertTo-ProductionJsonBytes -Value $descriptor.releaseCompatibility)) -cne
            (Get-ProductionSha256Bytes -Bytes (
                ConvertTo-ProductionJsonBytes -Value $Plan.releaseCompatibility)) -or
        [string]$descriptor.runtimeProvenance.harnessSourceTag -cne
            [string]$PlanAdmissionReceipt.data.runtimeCandidate.harnessSourceTag -or
        [string]$descriptor.runtimeProvenance.harnessSourceCommit -cne
            [string]$PlanAdmissionReceipt.data.runtimeCandidate.harnessSourceCommit) {
        throw 'Production Publisher input descriptor is not bound to the exact target-channel plan.'
    }
    $expectedProbeRoles = if ([string]$Plan.edition -ceq 'Personal') {
        @('startup-stub', 'client-bootstrapper', 'launcher', 'maintenance')
    }
    else {
        @('bootstrapper', 'launcher', 'client-bootstrapper')
    }
    $probes = @($ClientImportReceipt.data.releaseManifestTrustProbes)
    if ([string]$ClientImportReceipt.data.releaseManifestTrustProbeStatus -cne
            'VERIFIED' -or
        $probes.Count -ne $expectedProbeRoles.Count) {
        throw 'Production Publisher input requires verified release-manifest trust probes from every participating signed client.'
    }
    for ($index = 0; $index -lt $expectedProbeRoles.Count; $index++) {
        if ([string]$probes[$index].role -cne $expectedProbeRoles[$index] -or
            [string]$probes[$index].fileName -cne
                [string]$Plan.clientSigningInputs[$index].fileName) {
            throw "Production Publisher input release-manifest trust probe index $index differs from the signed-client plan."
        }
    }
    $files = @($descriptor.files)
    if ($files.Count -lt 7 -or $files.Count -gt 64) {
        throw 'Production Publisher input descriptor has an invalid file count.'
    }
    $roles = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $fileNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $expectedInventory = [ordered]@{}
    $lastEditionRole = ''
    for ($index = 0; $index -lt $files.Count; $index++) {
        $file = $files[$index]
        Assert-ExactProductionJsonMembers `
            -Value $file `
            -Expected @('role', 'fileName', 'relativePath', 'sizeBytes', 'sha256') `
            -Label "Production Publisher input file index $index"
        $role = [string]$file.role
        $fileName = [string]$file.fileName
        if (-not $roles.Add($role) -or -not $fileNames.Add($fileName) -or
            [string]$file.relativePath -cne ('payload/' + $fileName)) {
            throw "Production Publisher input file index $index repeats an identity or has a noncanonical path."
        }
        if ($index -lt 4) {
            $planned = $Plan.clientSigningInputs[$index]
            $imported = $ClientImportReceipt.data.files[$index]
            if ($role -cne ('client-' + [string]$planned.role) -or
                $fileName -cne [string]$planned.fileName -or
                [int64]$file.sizeBytes -ne [int64]$imported.sizeBytes -or
                [string]$file.sha256 -cne [string]$imported.sha256) {
                throw "Production Publisher input client index $index differs from the exact imported signed client."
            }
        }
        elseif ($index -lt 7) {
            $runtimeRole = @('runtime-archive', 'runtime-metadata', 'runtime-hash-evidence')[$index - 4]
            $runtimeDescriptor = @(
                $Plan.runtimeCandidate.archive,
                $Plan.runtimeCandidate.metadata,
                $Plan.runtimeCandidate.hashEvidence)[$index - 4]
            if ($role -cne $runtimeRole -or
                $fileName -cne [string]$runtimeDescriptor.fileName -or
                [int64]$file.sizeBytes -ne [int64]$runtimeDescriptor.sizeBytes -or
                [string]$file.sha256 -cne [string]$runtimeDescriptor.sha256) {
                throw "Production Publisher input runtime index $index differs from the exact plan descriptor."
            }
        }
        else {
            if (-not $role.StartsWith('edition-', [StringComparison]::Ordinal) -or
                ($lastEditionRole -and
                 [string]::CompareOrdinal($lastEditionRole, $role) -ge 0)) {
                throw 'Edition-specific Publisher inputs must use unique ordinal edition-* roles.'
            }
            $lastEditionRole = $role
        }
        $expectedInventory[$fileName] = $false
    }

    $payloadDirectory = Get-Item -LiteralPath $PayloadRoot -Force -ErrorAction Stop
    if (-not $payloadDirectory.PSIsContainer -or
        ($payloadDirectory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Production Publisher payload must be one ordinary directory.'
    }
    $payloadEntries = @(Get-ChildItem -LiteralPath $payloadDirectory.FullName -Force)
    if ($payloadEntries.Count -ne $expectedInventory.Count) {
        throw 'Production Publisher payload does not contain its exact descriptor inventory.'
    }
    foreach ($entry in $payloadEntries) {
        if ($entry.PSIsContainer -or
            ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            -not $expectedInventory.Contains($entry.Name)) {
            throw "Production Publisher payload contains unexpected or linked entry '$($entry.Name)'."
        }
    }
    foreach ($file in $files) {
        $locked = Open-ProductionReleaseInput `
            -Path (Join-Path $payloadDirectory.FullName ([string]$file.fileName)) `
            -Label "Production Publisher payload role $($file.role)" `
            -MaximumBytes (8L * 1024 * 1024 * 1024)
        try {
            if ([int64]$locked.SizeBytes -ne [int64]$file.sizeBytes -or
                [string]$locked.Sha256 -cne [string]$file.sha256) {
                throw "Production Publisher payload role '$($file.role)' differs from its descriptor."
            }
        }
        finally {
            $locked.Stream.Dispose()
        }
    }
    return $descriptor
}

function Assert-ProductionManifestPublishingRequestBundle {
    param(
        [Parameter(Mandatory = $true)][string]$StateRoot,
        [Parameter(Mandatory = $true)][psobject]$Plan,
        [Parameter(Mandatory = $true)][psobject]$Identity,
        [Parameter(Mandatory = $true)][string]$IdentitySha256,
        [Parameter(Mandatory = $true)][Collections.IList]$Receipts
    )

    $schemaVersion = [int]$Plan.schemaVersion
    $channelContract = if ($schemaVersion -eq 2) {
        Get-ProductionManifestChannelContract `
            -TargetChannel ([string]$Plan.targetChannel)
    }
    else {
        $null
    }
    $root = Join-Path `
        (Join-Path $StateRoot 'requests') `
        ([string]$channelContract.RequestBundleName)
    Assert-ExactProductionStateDirectory `
        -Path $root `
        -Expected ([ordered]@{
            'manifest-publishing-request.v1.json' = $false
            'publisher-input.v1.json' = $false
            'payload' = $true
        }) `
        -Label 'Production target-channel manifest-publishing request bundle'
    $requestInput = Read-StrictProductionJsonFile `
        -Path (Join-Path $root 'manifest-publishing-request.v1.json') `
        -Label 'Admitted target-channel manifest-publishing request'
    [void](Assert-CanonicalProductionJsonInput `
        -Input $requestInput `
        -Label 'Admitted target-channel manifest-publishing request')
    $descriptorInput = Read-StrictProductionJsonFile `
        -Path (Join-Path $root 'publisher-input.v1.json') `
        -Label 'Admitted production Publisher input descriptor'
    $descriptor = Assert-ProductionPublisherInputFileSet `
        -Plan $Plan `
        -PlanSha256 ([string]$Identity.planSha256) `
        -PlanAdmissionReceipt $Receipts[0] `
        -ClientImportReceipt $Receipts[2] `
        -DescriptorInput $descriptorInput `
        -PayloadRoot (Join-Path $root 'payload')
    $request = $requestInput.Value
    $requestMembers = @(
            'schemaVersion', 'requestType', 'orchestrationId', 'edition',
            'releaseSetId', 'channel', 'planSha256', 'baseHeadSha256',
            'requestedRevision', 'requestNonce', 'createdAtUtc', 'expiresAtUtc',
            'publisherInput', 'releaseManifestTrust', 'releaseCompatibility',
            'componentReleaseIds', 'runtimeProvenance',
            'responseAuthentication')
    if ($null -ne $request.PSObject.Properties['runtimeSourceReleaseExpectation']) {
        $requestMembers += 'runtimeSourceReleaseExpectation'
    }
    Assert-ExactProductionJsonMembers `
        -Value $request `
        -Expected $requestMembers `
        -Label 'Admitted target-channel manifest-publishing request'
    Assert-ProductionRuntimeSourceReleaseExpectation -Plan $Plan -Value $request
    [void]@(Get-ProductionComponentReleaseIdContract `
        -Plan $Plan `
        -ComponentReleaseIds $request.componentReleaseIds `
        -Label 'Admitted target-channel component release IDs')
    Assert-ExactProductionJsonMembers `
        -Value $request.runtimeProvenance `
        -Expected @('harnessSourceTag', 'harnessSourceCommit') `
        -Label 'Admitted target-channel runtime provenance'
    Assert-ExactProductionJsonMembers `
        -Value $request.publisherInput `
        -Expected @('descriptorRelativePath', 'descriptorSha256', 'files') `
        -Label 'Admitted target-channel manifest-publishing request Publisher input'
    Assert-ExactProductionJsonMembers `
        -Value $request.responseAuthentication `
        -Expected @('algorithm', 'keyId', 'purpose', 'payloadType') `
        -Label 'Admitted target-channel manifest-publishing response policy'
    $baseHeadSha256 = Get-ProductionHistoricalHeadSha256 `
        -StateRoot $StateRoot `
        -Identity $Identity `
        -IdentitySha256 $IdentitySha256 `
        -Receipt $Receipts[2]
    $trust = $Plan.externalResponseTrusts.manifestPublishing
    if ([int]$request.schemaVersion -ne 1 -or
        [string]$request.requestType -cne [string]$channelContract.RequestType -or
        [string]$request.orchestrationId -cne [string]$Plan.orchestrationId -or
        [string]$request.edition -cne [string]$Plan.edition -or
        [string]$request.releaseSetId -cne [string]$Plan.releaseSetId -or
        [string]$request.channel -cne [string]$channelContract.TargetChannel -or
        [string]$request.planSha256 -cne [string]$Identity.planSha256 -or
        [string]$request.baseHeadSha256 -cne $baseHeadSha256 -or
        [int]$request.requestedRevision -ne 4 -or
        [string]$request.publisherInput.descriptorRelativePath -cne
            'publisher-input.v1.json' -or
        [string]$request.publisherInput.descriptorSha256 -cne
            [string]$descriptorInput.Sha256 -or
        (Get-ProductionSha256Bytes -Bytes (
                ConvertTo-ProductionJsonBytes -Value $request.releaseManifestTrust)) -cne
            (Get-ProductionSha256Bytes -Bytes (
                ConvertTo-ProductionJsonBytes -Value $Plan.releaseManifestTrust)) -or
        (Get-ProductionSha256Bytes -Bytes (
                ConvertTo-ProductionJsonBytes -Value $request.releaseCompatibility)) -cne
            (Get-ProductionSha256Bytes -Bytes (
                ConvertTo-ProductionJsonBytes -Value $Plan.releaseCompatibility)) -or
        (Get-ProductionSha256Bytes -Bytes (
                ConvertTo-ProductionJsonBytes -Value $request.componentReleaseIds)) -cne
            (Get-ProductionSha256Bytes -Bytes (
                ConvertTo-ProductionJsonBytes -Value $descriptor.componentReleaseIds)) -or
        (Get-ProductionSha256Bytes -Bytes (
                ConvertTo-ProductionJsonBytes -Value $request.runtimeProvenance)) -cne
            (Get-ProductionSha256Bytes -Bytes (
                ConvertTo-ProductionJsonBytes -Value $descriptor.runtimeProvenance)) -or
        [string]$request.responseAuthentication.algorithm -cne 'ES256' -or
        [string]$request.responseAuthentication.keyId -cne [string]$trust.keyId -or
        [string]$request.responseAuthentication.purpose -cne
            'manifest-publishing-response' -or
        [string]$request.responseAuthentication.payloadType -cne
            'ensou-dsh-launcher-manifest-publishing-response-authentication-v1') {
        throw 'Admitted target-channel manifest-publishing request is not bound to its exact plan, state head, and trust domain.'
    }
    $created = ConvertFrom-ProductionUtc `
        -Value ([string]$request.createdAtUtc) `
        -Label 'Target-channel manifest-publishing request creation time'
    $expires = ConvertFrom-ProductionUtc `
        -Value ([string]$request.expiresAtUtc) `
        -Label 'Target-channel manifest-publishing request expiry time'
    if ($expires -le $created) {
        throw 'Target-channel manifest-publishing request expiry does not follow its creation time.'
    }
    $requestFiles = @($request.publisherInput.files)
    $descriptorFiles = @($descriptor.files)
    if ($requestFiles.Count -ne $descriptorFiles.Count) {
        throw 'Target-channel manifest-publishing request file set differs from its Publisher input descriptor.'
    }
    for ($index = 0; $index -lt $requestFiles.Count; $index++) {
        if ((ConvertTo-ProductionJsonBytes -Value $requestFiles[$index]).Length -le 0 -or
            (Get-ProductionSha256Bytes -Bytes (ConvertTo-ProductionJsonBytes -Value $requestFiles[$index])) -cne
            (Get-ProductionSha256Bytes -Bytes (ConvertTo-ProductionJsonBytes -Value $descriptorFiles[$index]))) {
            throw "Target-channel manifest-publishing request file index $index differs from its Publisher input descriptor."
        }
    }
    if ($Receipts.Count -ge 4) {
        $receipt = $Receipts[3]
        if ([string]$receipt.data.requestSha256 -cne [string]$requestInput.Sha256 -or
            [string]$receipt.data.publisherInputDescriptorSha256 -cne
                [string]$descriptorInput.Sha256 -or
            [string]$receipt.data.baseHeadSha256 -cne $baseHeadSha256 -or
            [string]$receipt.data.requestNonce -cne [string]$request.requestNonce -or
            [string]$receipt.data.createdAtUtc -cne [string]$request.createdAtUtc -or
            [string]$receipt.data.expiresAtUtc -cne [string]$request.expiresAtUtc -or
            [string]$receipt.data.responseAuthenticationKeyId -cne [string]$trust.keyId -or
            [string]$receipt.data.responseAuthenticationPurpose -cne
                'manifest-publishing-response' -or
            [string]$receipt.data.responseAuthenticationPayloadType -cne
                'ensou-dsh-launcher-manifest-publishing-response-authentication-v1' -or
            [string]$receipt.data.releaseManifestTrustSha256 -cne
                (Get-ProductionSha256Bytes -Bytes (
                    ConvertTo-ProductionJsonBytes -Value $Plan.releaseManifestTrust)) -or
            [string]$receipt.data.releaseCompatibilitySha256 -cne
                (Get-ProductionSha256Bytes -Bytes (
                    ConvertTo-ProductionJsonBytes -Value $Plan.releaseCompatibility)) -or
            [string]$receipt.data.componentReleaseIdsSha256 -cne
                (Get-ProductionSha256Bytes -Bytes (
                    ConvertTo-ProductionJsonBytes -Value $descriptor.componentReleaseIds)) -or
            [string]$receipt.data.runtimeProvenanceSha256 -cne
                (Get-ProductionSha256Bytes -Bytes (
                    ConvertTo-ProductionJsonBytes -Value $descriptor.runtimeProvenance)) -or
            [string]$receipt.data.compiledReleaseTrustStatus -cne 'VERIFIED') {
            throw 'Target-channel manifest-publishing request differs from its typed transition receipt.'
        }
        $receiptFiles = @($receipt.data.files)
        if ($receiptFiles.Count -ne $requestFiles.Count) {
            throw 'Target-channel manifest-publishing request inventory differs from its typed transition receipt.'
        }
        for ($index = 0; $index -lt $requestFiles.Count; $index++) {
            if ((Get-ProductionSha256Bytes -Bytes (
                        ConvertTo-ProductionJsonBytes -Value $requestFiles[$index])) -cne
                (Get-ProductionSha256Bytes -Bytes (
                        ConvertTo-ProductionJsonBytes -Value $receiptFiles[$index]))) {
                throw "Target-channel manifest-publishing request file index $index differs from its typed transition receipt."
            }
        }
    }
    return $requestInput
}

function Assert-ProductionSignedCandidateBundle {
    param(
        [Parameter(Mandatory = $true)][string]$StateRoot,
        [Parameter(Mandatory = $true)][psobject]$Plan,
        [Parameter(Mandatory = $true)][psobject]$Identity,
        [Parameter(Mandatory = $true)][string]$IdentitySha256,
        [Parameter(Mandatory = $true)][Collections.IList]$Receipts,
        [Parameter(Mandatory = $true)]$RequestInput
    )

    $channelContract = Get-ProductionManifestChannelContract `
        -TargetChannel ([string]$Plan.targetChannel)
    $root = Join-Path `
        (Join-Path $StateRoot 'imports') `
        ([string]$channelContract.CandidateBundleName)
    Assert-ExactProductionStateDirectory `
        -Path $root `
        -Expected ([ordered]@{
            'manifest-publishing-response.v1.json' = $false
            'candidate' = $true
        }) `
        -Label 'Production target-channel signed-candidate import bundle'
    $responseInput = Read-StrictProductionJsonFile `
        -Path (Join-Path $root 'manifest-publishing-response.v1.json') `
        -Label 'Admitted target-channel signed-candidate response'
    [void](Assert-CanonicalProductionJsonInput `
        -Input $responseInput `
        -Label 'Admitted target-channel signed-candidate response')
    $response = $responseInput.Value
    $responseMembers = @(
            'schemaVersion', 'responseType', 'orchestrationId', 'edition',
            'releaseSetId', 'channel', 'planSha256', 'requestSha256',
            'requestNonce', 'baseHeadSha256', 'admissionHeadSha256',
            'admissionRevision', 'requestExpiresAtUtc', 'completedAtUtc',
            'files', 'authentication')
    if ($null -ne $response.PSObject.Properties['runtimeSourceReleaseAdmission']) {
        $responseMembers += 'runtimeSourceReleaseAdmission'
    }
    Assert-ExactProductionJsonMembers `
        -Value $response `
        -Expected $responseMembers `
        -Label 'Admitted target-channel signed-candidate response'
    Assert-ExactProductionJsonMembers `
        -Value $response.authentication `
        -Expected @('algorithm', 'keyId', 'purpose', 'payloadType', 'value') `
        -Label 'Admitted target-channel signed-candidate response authentication'
    for ($index = 0; $index -lt @($response.files).Count; $index++) {
        Assert-ExactProductionJsonMembers `
            -Value $response.files[$index] `
            -Expected @('role', 'fileName', 'relativePath', 'sizeBytes', 'sha256') `
            -Label "Admitted target-channel signed-candidate response file index $index"
    }
    Assert-ProductionReleaseManifestPublishingResponseAuthentication `
        -Response $response `
        -Trust $Plan.externalResponseTrusts.manifestPublishing
    $request = $RequestInput.Value
    [void](Assert-ProductionRuntimeSourceReleaseResponseBinding `
        -Plan $Plan -Request $request -Response $response -StateRoot $StateRoot)
    $admissionHeadSha256 = Get-ProductionHistoricalHeadSha256 `
        -StateRoot $StateRoot `
        -Identity $Identity `
        -IdentitySha256 $IdentitySha256 `
        -Receipt $Receipts[3]
    if ([int]$response.schemaVersion -ne 1 -or
        [string]$response.responseType -cne [string]$channelContract.ResponseType -or
        [string]$response.channel -cne [string]$channelContract.TargetChannel -or
        [string]$response.orchestrationId -cne [string]$request.orchestrationId -or
        [string]$response.edition -cne [string]$request.edition -or
        [string]$response.releaseSetId -cne [string]$request.releaseSetId -or
        [string]$response.channel -cne [string]$request.channel -or
        [string]$response.planSha256 -cne [string]$request.planSha256 -or
        [string]$response.requestSha256 -cne [string]$RequestInput.Sha256 -or
        [string]$response.requestNonce -cne [string]$request.requestNonce -or
        [string]$response.baseHeadSha256 -cne [string]$request.baseHeadSha256 -or
        [string]$response.admissionHeadSha256 -cne $admissionHeadSha256 -or
        [int]$response.admissionRevision -ne 4 -or
        [string]$response.requestExpiresAtUtc -cne [string]$request.expiresAtUtc) {
        throw 'Target-channel signed-candidate response is not bound to the exact request, revision, and state heads.'
    }
    $completed = ConvertFrom-ProductionUtc `
        -Value ([string]$response.completedAtUtc) `
        -Label 'Target-channel signed-candidate completion time'
    $created = ConvertFrom-ProductionUtc `
        -Value ([string]$request.createdAtUtc) `
        -Label 'Target-channel manifest-publishing request creation time'
    $expires = ConvertFrom-ProductionUtc `
        -Value ([string]$request.expiresAtUtc) `
        -Label 'Target-channel manifest-publishing request expiry time'
    if ($completed -lt $created -or $completed -gt $expires) {
        throw 'Target-channel signed-candidate response completion is outside its exact request lifetime.'
    }
    $files = @($response.files)
    if ($files.Count -lt 1 -or
        [string]$files[0].role -cne 'release-manifest' -or
        [string]$files[0].fileName -cne 'release-set.v2.json' -or
        [string]$files[0].relativePath -cne 'candidate/release-set.v2.json') {
        throw 'Target-channel signed-candidate response does not begin with its canonical release manifest.'
    }
    $roles = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $names = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    $expectedInventory = [ordered]@{}
    foreach ($file in $files) {
        if (-not $roles.Add([string]$file.role) -or
            -not $names.Add([string]$file.fileName) -or
            [string]$file.relativePath -cne ('candidate/' + [string]$file.fileName)) {
            throw 'Target-channel signed-candidate response repeats a file identity or uses a noncanonical path.'
        }
        $expectedInventory[[string]$file.fileName] = $false
    }
    $candidateRoot = Join-Path $root 'candidate'
    $candidateDirectory = Get-Item -LiteralPath $candidateRoot -Force -ErrorAction Stop
    if (-not $candidateDirectory.PSIsContainer -or
        ($candidateDirectory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Target-channel signed-candidate payload must be one ordinary directory.'
    }
    $entries = @(Get-ChildItem -LiteralPath $candidateRoot -Force)
    if ($entries.Count -ne $expectedInventory.Count) {
        throw 'Target-channel signed-candidate payload does not contain its exact authenticated inventory.'
    }
    foreach ($entry in $entries) {
        if ($entry.PSIsContainer -or
            ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            -not $expectedInventory.Contains($entry.Name)) {
            throw "Target-channel signed-candidate payload contains unexpected or linked entry '$($entry.Name)'."
        }
    }
    foreach ($file in $files) {
        $locked = Open-ProductionReleaseInput `
            -Path (Join-Path $candidateRoot ([string]$file.fileName)) `
            -Label "Target-channel signed-candidate role $($file.role)" `
            -MaximumBytes (8L * 1024 * 1024 * 1024)
        try {
            if ([int64]$locked.SizeBytes -ne [int64]$file.sizeBytes -or
                [string]$locked.Sha256 -cne [string]$file.sha256) {
                throw "Target-channel signed-candidate role '$($file.role)' differs from its authenticated descriptor."
            }
        }
        finally {
            $locked.Stream.Dispose()
        }
    }
    $manifestInput = Read-StrictProductionJsonFile `
        -Path (Join-Path $candidateRoot 'release-set.v2.json') `
        -Label 'Target-channel signed release-set candidate'
    [void](Assert-CanonicalProductionJsonInput `
        -Input $manifestInput `
        -Label 'Target-channel signed release-set candidate')
    $expectedCandidateFiles = @(Assert-ProductionReleaseManifestCandidate `
        -Plan $Plan `
        -ManifestInput $manifestInput `
        -CandidateRoot $candidateRoot `
        -Files $files `
        -ComponentReleaseIds $request.componentReleaseIds `
        -RuntimeProvenance $request.runtimeProvenance `
        -ValidationTimeUtc $completed)
    if ($entries.Count -ne $expectedCandidateFiles.Count) {
        throw 'Target-channel signed-candidate payload does not contain its exact manifest-derived edition-fixed inventory.'
    }
    for ($index = 0; $index -lt $expectedCandidateFiles.Count; $index++) {
        $expectedName = [string]$expectedCandidateFiles[$index].FileName
        $exactEntries = @($entries | Where-Object { $_.Name -ceq $expectedName })
        if ($exactEntries.Count -ne 1) {
            throw "Target-channel signed-candidate payload does not contain exact-case manifest-derived file '$expectedName'."
        }
    }
    if ($Receipts.Count -ge 5) {
        $receipt = $Receipts[4]
        if ([string]$receipt.data.responseSha256 -cne [string]$responseInput.Sha256 -or
            [string]$receipt.data.requestSha256 -cne [string]$RequestInput.Sha256 -or
            [string]$receipt.data.requestNonce -cne [string]$request.requestNonce -or
            [string]$receipt.data.baseHeadSha256 -cne [string]$request.baseHeadSha256 -or
            [string]$receipt.data.admissionHeadSha256 -cne $admissionHeadSha256 -or
            [int]$receipt.data.admissionRevision -ne 4 -or
            [string]$receipt.data.requestExpiresAtUtc -cne [string]$request.expiresAtUtc -or
            [string]$receipt.data.completedAtUtc -cne [string]$response.completedAtUtc -or
            [string]$receipt.data.authenticationKeyId -cne
                [string]$Plan.externalResponseTrusts.manifestPublishing.keyId -or
            [string]$receipt.data.authenticationPurpose -cne
                'manifest-publishing-response' -or
            [string]$receipt.data.authenticationPayloadType -cne
                'ensou-dsh-launcher-manifest-publishing-response-authentication-v1' -or
            [string]$receipt.data.manifestSha256 -cne [string]$manifestInput.Sha256 -or
            [string]$receipt.data.releaseManifestTrustSha256 -cne
                (Get-ProductionSha256Bytes -Bytes (
                    ConvertTo-ProductionJsonBytes -Value $Plan.releaseManifestTrust)) -or
            [string]$receipt.data.releaseCompatibilitySha256 -cne
                (Get-ProductionSha256Bytes -Bytes (
                    ConvertTo-ProductionJsonBytes -Value $Plan.releaseCompatibility)) -or
            [string]$receipt.data.componentReleaseIdsSha256 -cne
                (Get-ProductionSha256Bytes -Bytes (
                    ConvertTo-ProductionJsonBytes -Value $request.componentReleaseIds)) -or
            [string]$receipt.data.runtimeProvenanceSha256 -cne
                (Get-ProductionSha256Bytes -Bytes (
                    ConvertTo-ProductionJsonBytes -Value $request.runtimeProvenance)) -or
            [string]$receipt.data.compiledReleaseTrustStatus -cne 'VERIFIED' -or
            [string]$receipt.data.productionAdmission -cne 'NO_GO') {
            throw 'Target-channel signed-candidate response differs from its typed transition receipt.'
        }
        $receiptFiles = @($receipt.data.files)
        if ($receiptFiles.Count -ne $files.Count) {
            throw 'Target-channel signed-candidate inventory differs from its typed transition receipt.'
        }
        for ($index = 0; $index -lt $files.Count; $index++) {
            if ((Get-ProductionSha256Bytes -Bytes (
                        ConvertTo-ProductionJsonBytes -Value $files[$index])) -cne
                (Get-ProductionSha256Bytes -Bytes (
                        ConvertTo-ProductionJsonBytes -Value $receiptFiles[$index]))) {
                throw "Target-channel signed-candidate file index $index differs from its typed transition receipt."
            }
        }
    }
}

function Assert-EnterpriseProductionPilotEvidenceInputBinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][Alias('Input')]$PilotEvidenceInput,
        [Parameter(Mandatory = $true)][psobject]$Plan,
        [Parameter(Mandatory = $true)][psobject]$Identity,
        [Parameter(Mandatory = $true)][string]$IdentitySha256,
        [Parameter(Mandatory = $true)][Collections.IList]$Receipts,
        [Parameter(Mandatory = $true)][string]$StateRoot,
        [string]$ExpectedR7HeadSha256 = '',
        [switch]$EnforceCurrentLifetime
    )

    if ([int]$Plan.schemaVersion -ne 2 -or
        [string]$Identity.edition -cne 'Enterprise' -or
        [string]$Plan.edition -cne 'Enterprise' -or
        [string]$Plan.targetChannel -cne 'stable' -or
        $Receipts.Count -lt 7) {
        throw 'R8_BINDING_ENTERPRISE_STABLE_R7_REQUIRED: Pilot evidence requires the exact Enterprise Stable r7 state.'
    }
    [void](Assert-CanonicalProductionJsonInput `
        -Input $PilotEvidenceInput `
        -Label 'Enterprise Pilot-evidence binding input')

    $value = $PilotEvidenceInput.Value
    $r7ReceiptPath = Join-Path `
        (Join-Path $StateRoot 'receipts') `
        '0007-installer-signature-imported.json'
    $r7ReceiptInput = Open-ProductionReleaseInput `
        -Path $r7ReceiptPath `
        -Label 'Enterprise r7 receipt for Pilot-evidence binding' `
        -MaximumBytes $script:MaximumJsonBytes
    try {
        $r7ReceiptSha256 = [string]$r7ReceiptInput.Sha256
    }
    finally {
        $r7ReceiptInput.Stream.Dispose()
    }
    $r7Receipt = $Receipts[6]
    if ([int]$r7Receipt.revision -ne 7 -or
        [string]$r7Receipt.phase -cne 'INSTALLER_SIGNATURE_IMPORTED' -or
        [string]$r7Receipt.data.productionAdmission -cne 'NO_GO' -or
        [string]$r7Receipt.data.sdkFileClosureStatus -cne 'VERIFIED' -or
        [string]$r7Receipt.data.admissionReason -cne
            'INSTALLER_SIGNING_RESPONSE_REQUIRED') {
        throw 'R8_BINDING_R7_RECEIPT_REJECTED: Pilot evidence cannot replace or upgrade the authoritative r7 admission boundary.'
    }

    $r7Head = [ordered]@{
        schemaVersion = 2
        stateType = 'ensou-dsh-launcher-production-release-head'
        orchestrationId = [string]$Identity.orchestrationId
        edition = 'Enterprise'
        planSha256 = [string]$Identity.planSha256
        identitySha256 = $IdentitySha256
        revision = 7
        phase = 'INSTALLER_SIGNATURE_IMPORTED'
        receiptFileName = '0007-installer-signature-imported.json'
        receiptSha256 = $r7ReceiptSha256
        updatedAtUtc = [string]$r7Receipt.recordedAtUtc
        targetChannel = 'stable'
    }
    $r7HeadSha256 = Get-ProductionSha256Bytes -Bytes (
        ConvertTo-ProductionJsonBytes -Value $r7Head)
    if ($ExpectedR7HeadSha256 -and
        $ExpectedR7HeadSha256 -cne $r7HeadSha256) {
        throw 'R8_BINDING_R7_HEAD_MISMATCH: Expected r7 head is stale or belongs to another state.'
    }

    $r7Data = $r7Receipt.data
    if ([string]$value.orchestrationId -cne [string]$Identity.orchestrationId -or
        [string]$value.edition -cne 'Enterprise' -or
        [string]$value.targetChannel -cne 'stable' -or
        [string]$value.releaseSetId -cne [string]$Plan.releaseSetId -or
        [string]$value.planAnchor.planSha256 -cne
            [string]$Identity.planSha256 -or
        [string]$value.planAnchor.pilotEvidenceTrustPolicySha256 -cne
            [string]$Plan.pilotEvidenceTrustPolicySha256 -or
        [string]$value.trustPolicy.sha256 -cne
            [string]$Plan.pilotEvidenceTrustPolicySha256 -or
        [string]$value.r7.headSha256 -cne $r7HeadSha256 -or
        [string]$value.r7.planSha256 -cne [string]$Identity.planSha256 -or
        [string]$value.r7.receiptSha256 -cne $r7ReceiptSha256 -or
        [string]$value.r7.signingResponseSha256 -cne
            [string]$r7Data.responseSha256 -or
        [string]$value.r7.signingResponseAuthenticationKeyId -cne
            [string]$r7Data.authenticationKeyId -or
        [string]$value.r7.signingResponseAuthenticationPurpose -cne
            [string]$r7Data.authenticationPurpose -or
        [string]$value.r7.signerCertificateSha256 -cne
            [string]$r7Data.signerCertificateSha256 -or
        [string]$value.r7.timestampSignerCertificateSha256 -cne
            [string]$r7Data.timestampSignerCertificateSha256 -or
        [string]$value.r7.timestampUtc -cne [string]$r7Data.timestampUtc -or
        [string]$value.r7.signedInstaller.fileName -cne
            [string]$r7Data.signedInstaller.fileName -or
        [string]$value.r7.signedInstaller.relativePath -cne
            [string]$r7Data.signedInstaller.relativePath -or
        [int64]$value.r7.signedInstaller.sizeBytes -ne
            [int64]$r7Data.signedInstaller.sizeBytes -or
        [string]$value.r7.signedInstaller.sha256 -cne
            [string]$r7Data.signedInstaller.sha256 -or
        [string]$value.r7.signedInstaller.peContentSha256 -cne
            [string]$r7Data.signedInstaller.peContentSha256 -or
        [string]$value.windowsOperationalPilot.installerSha256 -cne
            [string]$r7Data.signedInstaller.sha256 -or
        [string]$value.stablePrivatePilot.installerSha256 -cne
            [string]$r7Data.signedInstaller.sha256) {
        throw 'R8_BINDING_AUTHORITY_MISMATCH: Pilot evidence differs from its immutable plan, r7 receipt, signing response, or Installer identity.'
    }

    $r5Manifest = @($Receipts[4].data.files | Where-Object {
            [string]$_.role -ceq 'release-manifest'
        })
    $r5Runtime = @($Receipts[4].data.files | Where-Object {
            [string]$_.role -ceq 'runtime'
        })
    if ($r5Manifest.Count -ne 1 -or $r5Runtime.Count -ne 1 -or
        [string]$value.stablePrivatePilot.targetManifestSha256 -cne
            [string]$r5Manifest[0].sha256 -or
        [string]$value.localDataCertification.targetRuntimeSha256 -cne
            [string]$r5Runtime[0].sha256 -or
        [string]$value.stablePrivatePilot.freshInstallDeviceIdentitySha256 -ceq
            [string]$value.stablePrivatePilot.onlineUpgradeDeviceIdentitySha256) {
        throw 'R8_BINDING_PILOT_TARGET_MISMATCH: Pilot evidence does not bind the exact Stable manifest/runtime or two distinct devices.'
    }

    $createdAt = ConvertFrom-ProductionUtc `
        -Value ([string]$value.createdAtUtc) `
        -Label 'Enterprise Pilot-evidence binding creation time'
    $expiresAt = ConvertFrom-ProductionUtc `
        -Value ([string]$value.expiresAtUtc) `
        -Label 'Enterprise Pilot-evidence binding expiry time'
    $localDataExpiresAt = ConvertFrom-ProductionUtc `
        -Value ([string]$value.localDataCertification.expiresAtUtc) `
        -Label 'Enterprise Pilot local-data certification expiry time'
    $allowlistExpiresAt = ConvertFrom-ProductionUtc `
        -Value ([string]$value.stablePrivatePilot.allowlistExpiresAtUtc) `
        -Label 'Enterprise Stable private-Pilot allowlist expiry time'
    $expectedExpiry = if ($localDataExpiresAt -lt $allowlistExpiresAt) {
        $localDataExpiresAt
    }
    else {
        $allowlistExpiresAt
    }
    if ($createdAt -ge $expiresAt -or $expiresAt -ne $expectedExpiry) {
        throw 'R8_BINDING_LIFETIME_MISMATCH: Pilot evidence lifetime is empty or not capped by its earliest authenticated prerequisite.'
    }
    if ($EnforceCurrentLifetime) {
        $now = [DateTimeOffset]::UtcNow
        if ($createdAt -gt $now.AddMinutes(5) -or $expiresAt -le $now) {
            throw 'R8_BINDING_EXPIRED: Pilot evidence is expired or has an invalid future creation time.'
        }
    }

    return [pscustomobject]@{
        R7HeadSha256 = $r7HeadSha256
        R7ReceiptSha256 = $r7ReceiptSha256
        PilotEvidenceSha256 = [string]$PilotEvidenceInput.Sha256
    }
}

function Get-ProductionStableFeedPromotionDomainDigest {
    param(
        [Parameter(Mandatory = $true)][string]$Domain,
        [Parameter(Mandatory = $true)]$Value
    )

    $domainBytes = $script:Utf8Strict.GetBytes($Domain + [char]10)
    $valueBytes = ConvertTo-ProductionJsonBytes -Value $Value
    $bytes = [byte[]]::new($domainBytes.Length + $valueBytes.Length)
    [Array]::Copy($domainBytes, 0, $bytes, 0, $domainBytes.Length)
    [Array]::Copy($valueBytes, 0, $bytes, $domainBytes.Length, $valueBytes.Length)
    return Get-ProductionSha256Bytes -Bytes $bytes
}

function Get-ProductionStableFeedPromotionResponseAuthenticationPayload {
    param([Parameter(Mandatory = $true)][psobject]$Response)

    $body = [ordered]@{
        schemaVersion = [int]$Response.schemaVersion
        responseType = [string]$Response.responseType
        operationId = [string]$Response.operationId
        orchestrationId = [string]$Response.orchestrationId
        edition = [string]$Response.edition
        exposureRing = [string]$Response.exposureRing
        feedChannel = [string]$Response.feedChannel
        publishScope = [string]$Response.publishScope
        releaseSetId = [string]$Response.releaseSetId
        requestSha256 = [string]$Response.requestSha256
        requestNonce = [string]$Response.requestNonce
        basePromotionHeadSha256 = [string]$Response.basePromotionHeadSha256
        sourceStateHeadSha256 = [string]$Response.sourceStateHeadSha256
        payloadSetSha256 = [string]$Response.payloadSetSha256
        feedCasSha256 = [string]$Response.feedCasSha256
        decision = [string]$Response.decision
        completedAtUtc = [string]$Response.completedAtUtc
        requestExpiresAtUtc = [string]$Response.requestExpiresAtUtc
        productionAdmission = [string]$Response.productionAdmission
        networkPublishPerformed = [bool]$Response.networkPublishPerformed
        authentication = [ordered]@{
            algorithm = [string]$Response.authentication.algorithm
            keyId = [string]$Response.authentication.keyId
            purpose = [string]$Response.authentication.purpose
            payloadType = [string]$Response.authentication.payloadType
        }
    }
    $domain = $script:Utf8Strict.GetBytes(
        'ensou-dsh-launcher-feed-promotion-response-authentication-v1' + [char]10)
    $json = ConvertTo-ProductionJsonBytes -Value $body
    $payload = [byte[]]::new($domain.Length + $json.Length)
    [Array]::Copy($domain, 0, $payload, 0, $domain.Length)
    [Array]::Copy($json, 0, $payload, $domain.Length, $json.Length)
    return $payload
}

function Assert-ProductionStableFeedPromotionResponseAuthentication {
    param(
        [Parameter(Mandatory = $true)][psobject]$Response,
        [Parameter(Mandatory = $true)][psobject]$Trust
    )

    if ([string]$Trust.algorithm -cne 'ES256' -or
        [string]$Trust.purpose -cne 'feed-promotion-response' -or
        [string]$Response.authentication.algorithm -cne 'ES256' -or
        [string]$Response.authentication.keyId -cne [string]$Trust.keyId -or
        [string]$Response.authentication.purpose -cne 'feed-promotion-response' -or
        [string]$Response.authentication.payloadType -cne
            'ensou-dsh-launcher-feed-promotion-response-authentication-v1') {
        throw 'Stable feed-promotion response authentication does not match the isolated plan trust.'
    }
    $x = ConvertFrom-Base64UrlStrict `
        -Value ([string]$Trust.x) `
        -Label 'Stable feed-promotion response key X'
    $y = ConvertFrom-Base64UrlStrict `
        -Value ([string]$Trust.y) `
        -Label 'Stable feed-promotion response key Y'
    $signature = ConvertFrom-Base64UrlStrict `
        -Value ([string]$Response.authentication.value) `
        -Label 'Stable feed-promotion response signature'
    if ($x.Length -ne 32 -or $y.Length -ne 32 -or $signature.Length -ne 64) {
        throw 'Stable feed-promotion response authentication uses invalid P-256 P1363 sizes.'
    }
    Assert-ProductionEs256P1363LowS `
        -Signature $signature `
        -Label 'Stable feed-promotion response signature'

    $parameters = [Security.Cryptography.ECParameters]::new()
    $parameters.Curve = [Security.Cryptography.ECCurve+NamedCurves]::nistP256
    $point = [Security.Cryptography.ECPoint]::new()
    $point.X = $x
    $point.Y = $y
    $parameters.Q = $point
    $ecdsa = [Security.Cryptography.ECDsa]::Create()
    try {
        try {
            $ecdsa.ImportParameters($parameters)
        }
        catch {
            throw 'Stable feed-promotion response trust is not one valid P-256 public point.'
        }
        if (-not $ecdsa.VerifyData(
                (Get-ProductionStableFeedPromotionResponseAuthenticationPayload `
                    -Response $Response),
                $signature,
                [Security.Cryptography.HashAlgorithmName]::SHA256,
                [Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)) {
            throw 'Stable feed-promotion response authentication signature is invalid.'
        }
    }
    finally {
        $ecdsa.Dispose()
    }
}

function Assert-ProductionStableFeedPromotionFileDescriptor {
    param(
        [Parameter(Mandatory = $true)]$Descriptor,
        [Parameter(Mandatory = $true)]$InputDescriptor,
        [Parameter(Mandatory = $true)][string]$ExpectedFileName,
        [Parameter(Mandatory = $true)][string]$Label
    )

    Assert-ExactProductionJsonMembers `
        -Value $Descriptor `
        -Expected @('fileName', 'sizeBytes', 'sha256') `
        -Label $Label
    if ([string]$Descriptor.fileName -cne $ExpectedFileName -or
        [int64]$Descriptor.sizeBytes -ne [int64]$InputDescriptor.Bytes.LongLength -or
        [string]$Descriptor.sha256 -cne [string]$InputDescriptor.Sha256) {
        throw "$Label differs from the exact canonical state file."
    }
}

function Assert-ProductionStableFeedPromotionAdmission {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$StateRoot,
        [Parameter(Mandatory = $true)][psobject]$Plan,
        [Parameter(Mandatory = $true)][psobject]$Identity,
        [Parameter(Mandatory = $true)][string]$IdentitySha256,
        [Parameter(Mandatory = $true)][Collections.IList]$Receipts,
        [Parameter(Mandatory = $true)][int]$CommittedRevision,
        [Parameter(Mandatory = $true)][int]$AdmittedRevision
    )

    $relativePath =
        'requests/stable-feed-promotion.v1/promotion-admission.v1.json'
    $root = Join-Path (Join-Path $StateRoot 'requests') `
        'stable-feed-promotion.v1'
    $exists = Test-Path -LiteralPath $root
    $isEnterpriseStable =
        [int]$Plan.schemaVersion -eq 2 -and
        [int]$Identity.schemaVersion -eq 2 -and
        [string]$Plan.edition -ceq 'Enterprise' -and
        [string]$Identity.edition -ceq 'Enterprise' -and
        [string]$Plan.targetChannel -ceq 'stable' -and
        [string]$Identity.targetChannel -ceq 'stable'

    if (-not $isEnterpriseStable -or $CommittedRevision -lt 8) {
        if ($exists) {
            throw 'Stable feed-promotion state exists outside the committed Enterprise Stable r8 lifecycle.'
        }
        if ($AdmittedRevision -ge 9) {
            throw 'Stable feed-promotion r9 cannot be admitted without a committed Enterprise Stable r8 state.'
        }
        return $null
    }
    if (-not $exists) {
        if ($AdmittedRevision -ge 9) {
            throw 'Stable feed-promotion r9 is missing its exact state-owned admission bundle.'
        }
        return $null
    }

    Assert-ExactProductionStateDirectory `
        -Path $root `
        -Expected ([ordered]@{
            'request.v1.json' = $false
            'response.v1.json' = $false
            'promotion-head.v1.json' = $false
            'bundle-head.v1.json' = $false
            'promotion-admission.v1.json' = $false
        }) `
        -Label 'Stable feed-promotion state admission bundle'
    $expectedAdmissionFileNames = @(
        'request.v1.json',
        'response.v1.json',
        'promotion-head.v1.json',
        'bundle-head.v1.json',
        'promotion-admission.v1.json')
    $admissionEntries = @(Get-ChildItem -LiteralPath $root -Force)
    for ($index = 0; $index -lt $expectedAdmissionFileNames.Count; $index++) {
        if (@($admissionEntries | Where-Object {
                    $_.Name -ceq $expectedAdmissionFileNames[$index]
                }).Count -ne 1) {
            throw 'Stable feed-promotion state admission bundle uses a noncanonical file-name case.'
        }
    }

    $schemaRoot = Join-Path $PSScriptRoot '..\schemas'
    $requestInput = Read-StrictProductionJsonFile `
        -Path (Join-Path $root 'request.v1.json') `
        -Label 'Stable feed-promotion state request' `
        -SchemaPath (Join-Path $schemaRoot `
            'launcher-feed-promotion-request-v1.schema.json')
    $responseInput = Read-StrictProductionJsonFile `
        -Path (Join-Path $root 'response.v1.json') `
        -Label 'Stable feed-promotion state response' `
        -SchemaPath (Join-Path $schemaRoot `
            'launcher-feed-promotion-response-v1.schema.json')
    $promotionHeadInput = Read-StrictProductionJsonFile `
        -Path (Join-Path $root 'promotion-head.v1.json') `
        -Label 'Stable feed-promotion state request head' `
        -SchemaPath (Join-Path $schemaRoot `
            'launcher-feed-promotion-state-v1.schema.json')
    $bundleHeadInput = Read-StrictProductionJsonFile `
        -Path (Join-Path $root 'bundle-head.v1.json') `
        -Label 'Stable feed-promotion state bundle head'
    $admissionInput = Read-StrictProductionJsonFile `
        -Path (Join-Path $root 'promotion-admission.v1.json') `
        -Label 'Stable feed-promotion state admission' `
        -SchemaPath (Join-Path $schemaRoot `
            'launcher-feed-promotion-admission-v1.schema.json')
    foreach ($input in @(
            $requestInput,
            $responseInput,
            $promotionHeadInput,
            $bundleHeadInput,
            $admissionInput)) {
        [void](Assert-CanonicalProductionJsonInput `
            -Input $input `
            -Label 'Stable feed-promotion state JSON')
    }

    $request = $requestInput.Value
    Assert-ExactProductionJsonMembers `
        -Value $request `
        -Expected @(
            'schemaVersion', 'requestType', 'operationId',
            'orchestrationId', 'edition', 'exposureRing', 'feedChannel',
            'publishScope', 'releaseSetId', 'sourceState',
            'expectedFeedIdentitySha256', 'feedCas', 'feedCasSha256',
            'payloadSetSha256', 'files', 'authorizationTrust',
            'requestNonce', 'createdAtUtc', 'expiresAtUtc',
            'productionAdmission', 'networkPublishPerformed') `
        -Label 'Stable feed-promotion state request'
    Assert-ExactProductionJsonMembers `
        -Value $request.sourceState `
        -Expected @(
            'schemaVersion', 'targetChannel', 'revision', 'phase',
            'planSizeBytes', 'planSha256', 'identitySizeBytes',
            'identitySha256', 'headSizeBytes', 'headSha256',
            'receiptChainStartRevision', 'receiptChainSha256',
            'candidateReceiptSha256') `
        -Label 'Stable feed-promotion source state'
    Assert-ExactProductionJsonMembers `
        -Value $request.feedCas `
        -Expected @('channelHead', 'journalHead') `
        -Label 'Stable feed-promotion feed CAS'
    foreach ($propertyName in @('channelHead', 'journalHead')) {
        $expectation = $request.feedCas.$propertyName
        $members = if ([string]$expectation.state -ceq 'missing') {
            @('state')
        }
        else {
            @('state', 'sizeBytes', 'sha256')
        }
        Assert-ExactProductionJsonMembers `
            -Value $expectation `
            -Expected $members `
            -Label "Stable feed-promotion feed CAS $propertyName"
    }
    Assert-ExactProductionJsonMembers `
        -Value $request.authorizationTrust `
        -Expected @('algorithm', 'keyId', 'purpose', 'x', 'y') `
        -Label 'Stable feed-promotion authorization trust'

    if ([int]$request.schemaVersion -ne 1 -or
        [string]$request.requestType -cne
            'ensou-dsh-launcher-offline-feed-promotion-request' -or
        [string]$request.orchestrationId -cne [string]$Identity.orchestrationId -or
        [string]$request.edition -cne 'Enterprise' -or
        [string]$request.exposureRing -cne 'stable' -or
        [string]$request.feedChannel -cne 'stable' -or
        [string]$request.publishScope -cne 'public-stable' -or
        [string]$request.releaseSetId -cne [string]$Plan.releaseSetId -or
        [string]$request.productionAdmission -cne 'NO_GO' -or
        [bool]$request.networkPublishPerformed) {
        throw 'Stable feed-promotion request is not the exact fail-closed Enterprise Stable request.'
    }
    $planPromotionTrust = $Plan.externalResponseTrusts.feedPromotion
    if ([string]$request.authorizationTrust.algorithm -cne
            [string]$planPromotionTrust.algorithm -or
        [string]$request.authorizationTrust.keyId -cne
            [string]$planPromotionTrust.keyId -or
        [string]$request.authorizationTrust.purpose -cne
            [string]$planPromotionTrust.purpose -or
        [string]$request.authorizationTrust.x -cne
            [string]$planPromotionTrust.x -or
        [string]$request.authorizationTrust.y -cne
            [string]$planPromotionTrust.y) {
        throw 'Stable feed-promotion request trust differs from the isolated plan trust.'
    }

    if ($Receipts.Count -lt 8 -or
        [int]$Receipts[4].revision -ne 5 -or
        [string]$Receipts[4].phase -cne 'STABLE_SIGNED_CANDIDATE_IMPORTED' -or
        [int]$Receipts[7].revision -ne 8 -or
        [string]$Receipts[7].phase -cne 'PILOT_EVIDENCE_BOUND') {
        throw 'Stable feed-promotion request requires the exact r5 candidate and r8 Pilot-evidence receipts.'
    }

    $planDescriptor = Open-ProductionReleaseInput `
        -Path (Join-Path $StateRoot 'plan.json') `
        -Label 'Stable feed-promotion source plan' `
        -MaximumBytes $script:MaximumJsonBytes
    $identityDescriptor = $null
    $receiptDescriptors = [Collections.Generic.List[object]]::new()
    try {
        $identityDescriptor = Open-ProductionReleaseInput `
            -Path (Join-Path $StateRoot 'identity.json') `
            -Label 'Stable feed-promotion source identity' `
            -MaximumBytes $script:MaximumJsonBytes
        $receiptIdentities = [Collections.Generic.List[object]]::new()
        $lifecycle = Get-ProductionReleaseLifecycleContract `
            -SchemaVersion 2 `
            -TargetChannel 'stable'
        for ($revision = 1; $revision -le 8; $revision++) {
            $phase = [string]$lifecycle.Transitions[$revision - 1].Phase
            $fileName = $revision.ToString('0000') + '-' +
                $phase.ToLowerInvariant().Replace('_', '-') + '.json'
            $descriptor = Open-ProductionReleaseInput `
                -Path (Join-Path (Join-Path $StateRoot 'receipts') $fileName) `
                -Label "Stable feed-promotion source receipt $revision" `
                -MaximumBytes $script:MaximumJsonBytes
            $receiptDescriptors.Add($descriptor)
            $receiptIdentities.Add([ordered]@{
                revision = $revision
                fileName = $fileName
                sizeBytes = [int64]$descriptor.SizeBytes
                sha256 = [string]$descriptor.Sha256
            })
        }
        $candidateReceiptDescriptor = $receiptDescriptors[4]
        $r8ReceiptDescriptor = $receiptDescriptors[7]
        $r8Head = [ordered]@{
            schemaVersion = 2
            stateType = 'ensou-dsh-launcher-production-release-head'
            orchestrationId = [string]$Identity.orchestrationId
            edition = 'Enterprise'
            planSha256 = [string]$Identity.planSha256
            identitySha256 = $IdentitySha256
            revision = 8
            phase = 'PILOT_EVIDENCE_BOUND'
            receiptFileName = '0008-pilot-evidence-bound.json'
            receiptSha256 = [string]$r8ReceiptDescriptor.Sha256
            updatedAtUtc = [string]$Receipts[7].recordedAtUtc
            targetChannel = 'stable'
        }
        $r8HeadBytes = ConvertTo-ProductionJsonBytes -Value $r8Head
        $r8HeadSha256 = Get-ProductionSha256Bytes -Bytes $r8HeadBytes
        $receiptChainSha256 = Get-ProductionStableFeedPromotionDomainDigest `
            -Domain 'ensou-dsh-launcher-feed-promotion-source-receipt-chain-v1' `
            -Value @($receiptIdentities)

        if ([int]$request.sourceState.schemaVersion -ne 2 -or
            [string]$request.sourceState.targetChannel -cne 'stable' -or
            [int]$request.sourceState.revision -ne 8 -or
            [string]$request.sourceState.phase -cne 'PILOT_EVIDENCE_BOUND' -or
            [int64]$request.sourceState.planSizeBytes -ne
                [int64]$planDescriptor.SizeBytes -or
            [string]$request.sourceState.planSha256 -cne
                [string]$planDescriptor.Sha256 -or
            [string]$request.sourceState.planSha256 -cne
                [string]$Identity.planSha256 -or
            [int64]$request.sourceState.identitySizeBytes -ne
                [int64]$identityDescriptor.SizeBytes -or
            [string]$request.sourceState.identitySha256 -cne
                [string]$identityDescriptor.Sha256 -or
            [string]$request.sourceState.identitySha256 -cne $IdentitySha256 -or
            [int64]$request.sourceState.headSizeBytes -ne
                [int64]$r8HeadBytes.LongLength -or
            [string]$request.sourceState.headSha256 -cne $r8HeadSha256 -or
            [int]$request.sourceState.receiptChainStartRevision -ne 1 -or
            [string]$request.sourceState.receiptChainSha256 -cne
                $receiptChainSha256 -or
            [string]$request.sourceState.candidateReceiptSha256 -cne
                [string]$candidateReceiptDescriptor.Sha256) {
            throw 'Stable feed-promotion request differs from the exact historical r8 state snapshot.'
        }

        $expectedRoles = @(
            'release-manifest',
            'release-public-key',
            'launcher',
            'runtime',
            'plugin-policy')
        $requestFiles = @($request.files)
        $candidateFiles = @($Receipts[4].data.files)
        if ($requestFiles.Count -ne 5 -or $candidateFiles.Count -ne 5) {
            throw 'Stable feed-promotion request must contain the five Enterprise candidate files.'
        }
        $candidateRoot = Join-Path `
            (Join-Path (Join-Path $StateRoot 'imports') `
                'stable-signed-candidate.v1') `
            'candidate'
        $candidateDirectory = Assert-OrdinaryProductionDirectory `
            -Path $candidateRoot `
            -Label 'Stable feed-promotion source candidate directory'
        $candidateEntries = @(Get-ChildItem -LiteralPath $candidateDirectory -Force)
        if ($candidateEntries.Count -ne 5) {
            throw 'Stable feed-promotion source candidate directory does not contain five exact files.'
        }
        for ($index = 0; $index -lt 5; $index++) {
            $file = $requestFiles[$index]
            $candidateFile = $candidateFiles[$index]
            Assert-ExactProductionJsonMembers `
                -Value $file `
                -Expected @('role', 'fileName', 'relativePath', 'sizeBytes', 'sha256') `
                -Label "Stable feed-promotion request file index $index"
            if ([string]$file.role -cne $expectedRoles[$index] -or
                [string]$file.role -cne [string]$candidateFile.role -or
                [string]$file.fileName -cne [string]$candidateFile.fileName -or
                [string]$file.relativePath -cne
                    ('payload/' + [string]$file.fileName) -or
                [string]$candidateFile.relativePath -cne
                    ('candidate/' + [string]$file.fileName) -or
                [int64]$file.sizeBytes -ne [int64]$candidateFile.sizeBytes -or
                [string]$file.sha256 -cne [string]$candidateFile.sha256) {
                throw "Stable feed-promotion request file index $index differs from the exact r5 candidate receipt."
            }
            $exactEntries = @($candidateEntries | Where-Object {
                    $_.Name -ceq [string]$file.fileName
                })
            if ($exactEntries.Count -ne 1 -or
                $exactEntries[0].PSIsContainer -or
                ($exactEntries[0].Attributes -band
                    [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Stable feed-promotion source candidate file index $index is missing, linked, or mistyped."
            }
            $candidateInput = Open-ProductionReleaseInput `
                -Path $exactEntries[0].FullName `
                -Label "Stable feed-promotion source candidate file index $index" `
                -MaximumBytes (8L * 1024 * 1024 * 1024)
            try {
                if ([int64]$candidateInput.SizeBytes -ne [int64]$file.sizeBytes -or
                    [string]$candidateInput.Sha256 -cne [string]$file.sha256) {
                    throw "Stable feed-promotion source candidate file index $index differs from its request digest."
                }
            }
            finally {
                $candidateInput.Stream.Dispose()
            }
        }
        $payloadSetSha256 = Get-ProductionStableFeedPromotionDomainDigest `
            -Domain 'ensou-dsh-launcher-feed-promotion-payload-set-v1' `
            -Value $requestFiles
        $feedCasSha256 = Get-ProductionStableFeedPromotionDomainDigest `
            -Domain 'ensou-dsh-launcher-feed-promotion-cas-v1' `
            -Value $request.feedCas
        if ([string]$request.payloadSetSha256 -cne $payloadSetSha256 -or
            [string]$request.feedCasSha256 -cne $feedCasSha256) {
            throw 'Stable feed-promotion request contains a noncanonical payload or feed-CAS digest.'
        }

        $promotionHead = $promotionHeadInput.Value
        Assert-ExactProductionJsonMembers `
            -Value $promotionHead `
            -Expected @(
                'schemaVersion', 'stateType', 'operationId', 'requestSha256',
                'requestNonce', 'sourceStateHeadSha256', 'payloadSetSha256',
                'status', 'productionAdmission', 'networkPublishPerformed',
                'updatedAtUtc') `
            -Label 'Stable feed-promotion request head'
        if ([int]$promotionHead.schemaVersion -ne 1 -or
            [string]$promotionHead.stateType -cne
                'ensou-dsh-launcher-offline-feed-promotion-state' -or
            [string]$promotionHead.operationId -cne [string]$request.operationId -or
            [string]$promotionHead.requestSha256 -cne
                [string]$requestInput.Sha256 -or
            [string]$promotionHead.requestNonce -cne
                [string]$request.requestNonce -or
            [string]$promotionHead.sourceStateHeadSha256 -cne $r8HeadSha256 -or
            [string]$promotionHead.payloadSetSha256 -cne $payloadSetSha256 -or
            [string]$promotionHead.status -cne 'PROMOTION_REQUEST_READY' -or
            [string]$promotionHead.productionAdmission -cne 'NO_GO' -or
            [bool]$promotionHead.networkPublishPerformed -or
            [string]$promotionHead.updatedAtUtc -cne
                [string]$request.createdAtUtc) {
            throw 'Stable feed-promotion request head differs from the exact request and r8 state.'
        }

        $response = $responseInput.Value
        Assert-ExactProductionJsonMembers `
            -Value $response `
            -Expected @(
                'schemaVersion', 'responseType', 'operationId',
                'orchestrationId', 'edition', 'exposureRing', 'feedChannel',
                'publishScope', 'releaseSetId', 'requestSha256',
                'requestNonce', 'basePromotionHeadSha256',
                'sourceStateHeadSha256', 'payloadSetSha256', 'feedCasSha256',
                'decision', 'completedAtUtc', 'requestExpiresAtUtc',
                'productionAdmission', 'networkPublishPerformed',
                'authentication') `
            -Label 'Stable feed-promotion state response'
        Assert-ExactProductionJsonMembers `
            -Value $response.authentication `
            -Expected @('algorithm', 'keyId', 'purpose', 'payloadType', 'value') `
            -Label 'Stable feed-promotion response authentication'
        if ([int]$response.schemaVersion -ne 1 -or
            [string]$response.responseType -cne
                'ensou-dsh-launcher-offline-feed-promotion-response' -or
            [string]$response.operationId -cne [string]$request.operationId -or
            [string]$response.orchestrationId -cne
                [string]$request.orchestrationId -or
            [string]$response.edition -cne 'Enterprise' -or
            [string]$response.exposureRing -cne 'stable' -or
            [string]$response.feedChannel -cne 'stable' -or
            [string]$response.publishScope -cne 'public-stable' -or
            [string]$response.releaseSetId -cne [string]$request.releaseSetId -or
            [string]$response.requestSha256 -cne [string]$requestInput.Sha256 -or
            [string]$response.requestNonce -cne [string]$request.requestNonce -or
            [string]$response.basePromotionHeadSha256 -cne
                [string]$promotionHeadInput.Sha256 -or
            [string]$response.sourceStateHeadSha256 -cne $r8HeadSha256 -or
            [string]$response.payloadSetSha256 -cne $payloadSetSha256 -or
            [string]$response.feedCasSha256 -cne $feedCasSha256 -or
            [string]$response.requestExpiresAtUtc -cne
                [string]$request.expiresAtUtc -or
            [string]$response.decision -cne 'AUTHORIZE_OFFLINE_BUNDLE' -or
            [string]$response.productionAdmission -cne 'OFFLINE_BUNDLE_ONLY' -or
            [bool]$response.networkPublishPerformed) {
            throw 'Stable feed-promotion response is not bound to the exact request and append-only request head.'
        }
        $createdAt = ConvertFrom-ProductionUtc `
            -Value ([string]$request.createdAtUtc) `
            -Label 'Stable feed-promotion request creation time'
        $expiresAt = ConvertFrom-ProductionUtc `
            -Value ([string]$request.expiresAtUtc) `
            -Label 'Stable feed-promotion request expiry time'
        $completedAt = ConvertFrom-ProductionUtc `
            -Value ([string]$response.completedAtUtc) `
            -Label 'Stable feed-promotion response completion time'
        if ($expiresAt -le $createdAt -or
            ($expiresAt - $createdAt) -gt [TimeSpan]::FromMinutes(60) -or
            $completedAt -lt $createdAt -or $completedAt -gt $expiresAt) {
            throw 'Stable feed-promotion response is outside the exact request lifetime.'
        }
        Assert-ProductionStableFeedPromotionResponseAuthentication `
            -Response $response `
            -Trust $Plan.externalResponseTrusts.feedPromotion

        $bundleHead = $bundleHeadInput.Value
        Assert-ExactProductionJsonMembers `
            -Value $bundleHead `
            -Expected @(
                'schemaVersion', 'stateType', 'operationId', 'requestSha256',
                'requestNonce', 'sourceStateHeadSha256', 'payloadSetSha256',
                'basePromotionHeadSha256', 'responseSha256',
                'bundleSetSha256', 'status', 'productionAdmission',
                'networkPublishPerformed', 'updatedAtUtc') `
            -Label 'Stable feed-promotion bundle head'
        $bundleInventory = [Collections.Generic.List[object]]::new()
        $bundleInventory.Add([ordered]@{
            role = 'promotion-request'
            fileName = 'request.v1.json'
            relativePath = 'bundle/request.v1.json'
            sizeBytes = [int64]$requestInput.Bytes.LongLength
            sha256 = [string]$requestInput.Sha256
        })
        $bundleInventory.Add([ordered]@{
            role = 'promotion-response'
            fileName = 'response.v1.json'
            relativePath = 'bundle/response.v1.json'
            sizeBytes = [int64]$responseInput.Bytes.LongLength
            sha256 = [string]$responseInput.Sha256
        })
        foreach ($file in $requestFiles) {
            $bundleInventory.Add([ordered]@{
                role = [string]$file.role
                fileName = [string]$file.fileName
                relativePath = 'bundle/payload/' + [string]$file.fileName
                sizeBytes = [int64]$file.sizeBytes
                sha256 = [string]$file.sha256
            })
        }
        $bundleSetSha256 = Get-ProductionStableFeedPromotionDomainDigest `
            -Domain 'ensou-dsh-launcher-feed-promotion-offline-bundle-v1' `
            -Value @($bundleInventory)
        if ([int]$bundleHead.schemaVersion -ne 1 -or
            [string]$bundleHead.stateType -cne
                'ensou-dsh-launcher-offline-feed-promotion-bundle' -or
            [string]$bundleHead.operationId -cne [string]$request.operationId -or
            [string]$bundleHead.requestSha256 -cne
                [string]$requestInput.Sha256 -or
            [string]$bundleHead.requestNonce -cne
                [string]$request.requestNonce -or
            [string]$bundleHead.sourceStateHeadSha256 -cne $r8HeadSha256 -or
            [string]$bundleHead.payloadSetSha256 -cne $payloadSetSha256 -or
            [string]$bundleHead.basePromotionHeadSha256 -cne
                [string]$promotionHeadInput.Sha256 -or
            [string]$bundleHead.responseSha256 -cne
                [string]$responseInput.Sha256 -or
            [string]$bundleHead.bundleSetSha256 -cne $bundleSetSha256 -or
            [string]$bundleHead.status -cne
                'EXTERNAL_PUBLISH_BUNDLE_READY' -or
            [string]$bundleHead.productionAdmission -cne 'NO_GO' -or
            [bool]$bundleHead.networkPublishPerformed -or
            [string]$bundleHead.updatedAtUtc -cne
                [string]$response.completedAtUtc) {
            throw 'Stable feed-promotion bundle head differs from the authenticated offline bundle.'
        }

        $admission = $admissionInput.Value
        Assert-ExactProductionJsonMembers `
            -Value $admission `
            -Expected @(
                'schemaVersion', 'evidenceType', 'orchestrationId', 'edition',
                'targetChannel', 'exposureRing', 'feedChannel', 'publishScope',
                'releaseSetId', 'sourceState', 'operationId', 'feedFoundation',
                'payloadSetSha256', 'request', 'response', 'promotionHead',
                'bundleHead', 'files', 'productionAdmission',
                'networkPublishPerformed') `
            -Label 'Stable feed-promotion state admission'
        Assert-ExactProductionJsonMembers `
            -Value $admission.sourceState `
            -Expected @(
                'revision', 'phase', 'planSha256', 'identitySha256',
                'headSha256', 'r8ReceiptSha256', 'receiptChainSha256',
                'candidateReceiptSha256') `
            -Label 'Stable feed-promotion admission source state'
        Assert-ExactProductionJsonMembers `
            -Value $admission.feedFoundation `
            -Expected @(
                'expectedFeedIdentitySha256', 'expectedChannelHead',
                'expectedJournalHead', 'feedCasSha256') `
            -Label 'Stable feed-promotion admission feed foundation'
        foreach ($propertyName in @('expectedChannelHead', 'expectedJournalHead')) {
            $expectation = $admission.feedFoundation.$propertyName
            $members = if ([string]$expectation.state -ceq 'missing') {
                @('state')
            }
            else {
                @('state', 'sizeBytes', 'sha256')
            }
            Assert-ExactProductionJsonMembers `
                -Value $expectation `
                -Expected $members `
                -Label "Stable feed-promotion admission $propertyName"
        }
        Assert-ProductionStableFeedPromotionFileDescriptor `
            -Descriptor $admission.request `
            -InputDescriptor $requestInput `
            -ExpectedFileName 'request.v1.json' `
            -Label 'Stable feed-promotion admission request descriptor'
        Assert-ProductionStableFeedPromotionFileDescriptor `
            -Descriptor $admission.promotionHead `
            -InputDescriptor $promotionHeadInput `
            -ExpectedFileName 'promotion-head.v1.json' `
            -Label 'Stable feed-promotion admission request-head descriptor'
        Assert-ExactProductionJsonMembers `
            -Value $admission.response `
            -Expected @(
                'fileName', 'sizeBytes', 'sha256', 'keyId', 'purpose',
                'payloadType', 'decision', 'completedAtUtc',
                'requestExpiresAtUtc') `
            -Label 'Stable feed-promotion admission response descriptor'
        if ([string]$admission.response.fileName -cne 'response.v1.json' -or
            [int64]$admission.response.sizeBytes -ne
                [int64]$responseInput.Bytes.LongLength -or
            [string]$admission.response.sha256 -cne
                [string]$responseInput.Sha256 -or
            [string]$admission.response.keyId -cne
                [string]$response.authentication.keyId -or
            [string]$admission.response.purpose -cne
                'feed-promotion-response' -or
            [string]$admission.response.payloadType -cne
                'ensou-dsh-launcher-feed-promotion-response-authentication-v1' -or
            [string]$admission.response.decision -cne
                'AUTHORIZE_OFFLINE_BUNDLE' -or
            [string]$admission.response.completedAtUtc -cne
                [string]$response.completedAtUtc -or
            [string]$admission.response.requestExpiresAtUtc -cne
                [string]$request.expiresAtUtc) {
            throw 'Stable feed-promotion admission response descriptor differs from authenticated response bytes.'
        }
        Assert-ExactProductionJsonMembers `
            -Value $admission.bundleHead `
            -Expected @(
                'fileName', 'sizeBytes', 'sha256', 'bundleSetSha256',
                'status') `
            -Label 'Stable feed-promotion admission bundle-head descriptor'
        if ([string]$admission.bundleHead.fileName -cne
                'bundle-head.v1.json' -or
            [int64]$admission.bundleHead.sizeBytes -ne
                [int64]$bundleHeadInput.Bytes.LongLength -or
            [string]$admission.bundleHead.sha256 -cne
                [string]$bundleHeadInput.Sha256 -or
            [string]$admission.bundleHead.bundleSetSha256 -cne
                $bundleSetSha256 -or
            [string]$admission.bundleHead.status -cne
                'EXTERNAL_PUBLISH_BUNDLE_READY') {
            throw 'Stable feed-promotion admission bundle-head descriptor differs from exact bundle state.'
        }
        if ([int]$admission.schemaVersion -ne 1 -or
            [string]$admission.evidenceType -cne
                'STABLE_PROMOTION_REQUESTED' -or
            [string]$admission.orchestrationId -cne
                [string]$Identity.orchestrationId -or
            [string]$admission.edition -cne 'Enterprise' -or
            [string]$admission.targetChannel -cne 'stable' -or
            [string]$admission.exposureRing -cne 'stable' -or
            [string]$admission.feedChannel -cne 'stable' -or
            [string]$admission.publishScope -cne 'public-stable' -or
            [string]$admission.releaseSetId -cne [string]$Plan.releaseSetId -or
            [int]$admission.sourceState.revision -ne 8 -or
            [string]$admission.sourceState.phase -cne
                'PILOT_EVIDENCE_BOUND' -or
            [string]$admission.sourceState.planSha256 -cne
                [string]$planDescriptor.Sha256 -or
            [string]$admission.sourceState.identitySha256 -cne
                $IdentitySha256 -or
            [string]$admission.sourceState.headSha256 -cne $r8HeadSha256 -or
            [string]$admission.sourceState.r8ReceiptSha256 -cne
                [string]$r8ReceiptDescriptor.Sha256 -or
            [string]$admission.sourceState.receiptChainSha256 -cne
                $receiptChainSha256 -or
            [string]$admission.sourceState.candidateReceiptSha256 -cne
                [string]$candidateReceiptDescriptor.Sha256 -or
            [string]$admission.operationId -cne [string]$request.operationId -or
            [string]$admission.feedFoundation.expectedFeedIdentitySha256 -cne
                [string]$request.expectedFeedIdentitySha256 -or
            (Get-ProductionSha256Bytes -Bytes (
                    ConvertTo-ProductionJsonBytes `
                        -Value $admission.feedFoundation.expectedChannelHead)) -cne
                (Get-ProductionSha256Bytes -Bytes (
                    ConvertTo-ProductionJsonBytes `
                        -Value $request.feedCas.channelHead)) -or
            (Get-ProductionSha256Bytes -Bytes (
                    ConvertTo-ProductionJsonBytes `
                        -Value $admission.feedFoundation.expectedJournalHead)) -cne
                (Get-ProductionSha256Bytes -Bytes (
                    ConvertTo-ProductionJsonBytes `
                        -Value $request.feedCas.journalHead)) -or
            [string]$admission.feedFoundation.feedCasSha256 -cne
                $feedCasSha256 -or
            [string]$admission.payloadSetSha256 -cne $payloadSetSha256 -or
            [string]$admission.productionAdmission -cne 'NO_GO' -or
            [bool]$admission.networkPublishPerformed) {
            throw 'Stable feed-promotion admission is not bound to the exact r8 source and offline bundle.'
        }
        $admissionFiles = @($admission.files)
        if ($admissionFiles.Count -ne 5) {
            throw 'Stable feed-promotion admission must bind five payload files.'
        }
        for ($index = 0; $index -lt 5; $index++) {
            Assert-ExactProductionJsonMembers `
                -Value $admissionFiles[$index] `
                -Expected @('role', 'fileName', 'sizeBytes', 'sha256') `
                -Label "Stable feed-promotion admission file index $index"
            if ([string]$admissionFiles[$index].role -cne
                    $expectedRoles[$index] -or
                [string]$admissionFiles[$index].role -cne
                    [string]$requestFiles[$index].role -or
                [string]$admissionFiles[$index].fileName -cne
                    [string]$requestFiles[$index].fileName -or
                [int64]$admissionFiles[$index].sizeBytes -ne
                    [int64]$requestFiles[$index].sizeBytes -or
                [string]$admissionFiles[$index].sha256 -cne
                    [string]$requestFiles[$index].sha256) {
                throw "Stable feed-promotion admission file index $index differs from the exact payload set."
            }
        }

        if ($AdmittedRevision -ge 9) {
            if ($Receipts.Count -lt 9 -or
                [int]$Receipts[8].revision -ne 9 -or
                [string]$Receipts[8].phase -cne
                    'STABLE_PROMOTION_REQUESTED' -or
                [string]$Receipts[8].data.evidenceType -cne
                    'STABLE_PROMOTION_REQUESTED' -or
                [string]$Receipts[8].data.relativePath -cne $relativePath -or
                [string]$Receipts[8].data.sha256 -cne
                    [string]$admissionInput.Sha256) {
                throw 'Stable feed-promotion admission differs from its r9 receipt or orphan receipt.'
            }
        }

        return [pscustomobject]@{
            RelativePath = $relativePath
            Sha256 = [string]$admissionInput.Sha256
            SizeBytes = [int64]$admissionInput.Bytes.LongLength
            Value = $admission
            RequestSha256 = [string]$requestInput.Sha256
            ResponseSha256 = [string]$responseInput.Sha256
            PromotionHeadSha256 = [string]$promotionHeadInput.Sha256
            BundleHeadSha256 = [string]$bundleHeadInput.Sha256
            BundleSetSha256 = $bundleSetSha256
            SourceR8HeadSha256 = $r8HeadSha256
            SourceR8ReceiptSha256 = [string]$r8ReceiptDescriptor.Sha256
            ReceiptChainSha256 = $receiptChainSha256
            CandidateReceiptSha256 = [string]$candidateReceiptDescriptor.Sha256
            ProductionAdmission = 'NO_GO'
            NetworkPublishPerformed = $false
        }
    }
    finally {
        foreach ($descriptor in $receiptDescriptors) {
            $descriptor.Stream.Dispose()
        }
        if ($null -ne $identityDescriptor) {
            $identityDescriptor.Stream.Dispose()
        }
        $planDescriptor.Stream.Dispose()
    }
}

function Assert-ProductionStatePayloadInventory {
    param(
        [Parameter(Mandatory = $true)][string]$StateRoot,
        [Parameter(Mandatory = $true)][psobject]$Plan,
        [Parameter(Mandatory = $true)][psobject]$Identity,
        [Parameter(Mandatory = $true)][string]$IdentitySha256,
        [Parameter(Mandatory = $true)][int]$CommittedRevision,
        [Parameter(Mandatory = $true)][int]$AdmittedRevision,
        [Parameter(Mandatory = $true)][Collections.IList]$Receipts
    )

    $schemaVersion = [int]$Plan.schemaVersion
    $installerLifecycle = $schemaVersion -eq 2
    $enterpriseInstallerLifecycle = $installerLifecycle -and
        [string]$Identity.edition -ceq 'Enterprise'
    $enterpriseStablePilotEvidenceLifecycle =
        $enterpriseInstallerLifecycle -and
        [string]$Plan.targetChannel -ceq 'stable'
    $personalPilotFeedLifecycle = $schemaVersion -eq 2 -and
        [string]$Identity.edition -ceq 'Personal' -and [string]$Plan.targetChannel -ceq 'pilot'
    $channelContract = if ($schemaVersion -eq 2) {
        Get-ProductionManifestChannelContract `
            -TargetChannel ([string]$Plan.targetChannel)
    }
    else {
        $null
    }
    $fileInventory = [ordered]@{}
    foreach ($input in @($Plan.clientSigningInputs)) {
        $fileName = [string]$input.fileName
        if ($fileInventory.Contains($fileName)) {
            throw "Production plan repeats signing file name '$fileName'."
        }
        $fileInventory[$fileName] = $false
    }
    if ($fileInventory.Count -ne 4) {
        throw 'Production state plan does not define exactly four client files.'
    }

    $requestsRoot = Join-Path $StateRoot 'requests'
    $requestEntries = @(
        if (Test-Path -LiteralPath $requestsRoot) {
            if (-not (Test-Path -LiteralPath $requestsRoot -PathType Container)) {
                throw 'Production requests path is not a directory.'
            }
            $ordinaryRequestsRoot = Assert-OrdinaryProductionDirectory `
                -Path $requestsRoot `
                -Label 'Production requests directory'
            Get-ChildItem -LiteralPath $ordinaryRequestsRoot -Force
        }
        elseif ($schemaVersion -ne 1 -or $AdmittedRevision -ge 2) {
            throw 'Production requests directory is missing for admitted state.'
        }
    )
    $allowedRequestEntries = @('client-signing.v1')
    if ($personalPilotFeedLifecycle) { $allowedRequestEntries += 'pilot-feed-promotion.v1' }
    if ($schemaVersion -eq 2) {
        $allowedRequestEntries += [string]$channelContract.RequestBundleName
        if ($installerLifecycle) {
            $allowedRequestEntries += 'installer-signing.v2'
        }
        if ($enterpriseStablePilotEvidenceLifecycle) {
            $allowedRequestEntries += 'stable-feed-promotion.v1'
        }
    }
    foreach ($entry in $requestEntries) {
        if (($entry.Name -ieq 'stable-feed-promotion.v1' -and
             $entry.Name -cne 'stable-feed-promotion.v1') -or
            $entry.Name -notin $allowedRequestEntries -or
            -not $entry.PSIsContainer -or
            ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Production requests directory contains an unexpected entry.'
        }
    }
    $clientRequestEntries = @($requestEntries | Where-Object { $_.Name -ceq 'client-signing.v1' })
    $manifestRequestEntries = @(
        if ($schemaVersion -eq 2) {
            $requestEntries | Where-Object {
                $_.Name -ceq [string]$channelContract.RequestBundleName
            }
        }
    )
    $installerRequestEntries = @(
        if ($installerLifecycle) {
            $requestEntries | Where-Object { $_.Name -ceq 'installer-signing.v2' }
        }
    )
    $stablePromotionRequestEntries = @(
        if ($enterpriseStablePilotEvidenceLifecycle) {
            $requestEntries | Where-Object {
                $_.Name -ceq 'stable-feed-promotion.v1'
            }
        }
    )
    if ($clientRequestEntries.Count -gt 1 -or
        $manifestRequestEntries.Count -gt 1 -or
        $installerRequestEntries.Count -gt 1 -or
        $stablePromotionRequestEntries.Count -gt 1) {
        throw 'Production requests directory repeats an owned bundle.'
    }
    if ($AdmittedRevision -ge 2 -and $clientRequestEntries.Count -ne 1) {
        throw 'Admitted client signing request bundle is missing.'
    }
    if ($schemaVersion -eq 2 -and
        $AdmittedRevision -lt 3 -and $manifestRequestEntries.Count -ne 0) {
        throw 'Target-channel manifest-publishing request exists before its typed transition.'
    }
    if ($schemaVersion -eq 2 -and
        $AdmittedRevision -ge 4 -and $manifestRequestEntries.Count -ne 1) {
        throw 'Admitted target-channel manifest-publishing request bundle is missing.'
    }
    if ($installerLifecycle -and
        $AdmittedRevision -lt 5 -and $installerRequestEntries.Count -ne 0) {
        throw 'Installer-signing request exists before its typed transition.'
    }
    if ($installerLifecycle -and
        $AdmittedRevision -ge 6 -and $installerRequestEntries.Count -ne 1) {
        throw 'Admitted Installer-signing request bundle is missing.'
    }
    if ($enterpriseStablePilotEvidenceLifecycle -and
        $CommittedRevision -lt 8 -and
        $stablePromotionRequestEntries.Count -ne 0) {
        throw 'Stable feed-promotion state exists before committed Enterprise Stable r8.'
    }
    if ($enterpriseStablePilotEvidenceLifecycle -and
        $AdmittedRevision -ge 9 -and
        $stablePromotionRequestEntries.Count -ne 1) {
        throw 'Admitted stable feed-promotion r9 bundle is missing.'
    }
    if ($clientRequestEntries.Count -eq 1) {
        $requestRoot = $clientRequestEntries[0].FullName
        $requestInventory = [ordered]@{
            'signing-request.v1.json' = $false
            'unsigned' = $true
        }
        Assert-ExactProductionStateDirectory -Path $requestRoot -Expected $requestInventory -Label 'Production client signing request bundle'
        $unsignedRoot = Join-Path $requestRoot 'unsigned'
        Assert-ExactProductionStateDirectory -Path $unsignedRoot -Expected $fileInventory -Label 'Production unsigned client snapshot'
        if ($AdmittedRevision -ge 2) {
            $requestReceipt = $Receipts[1]
            $requestDocument = Open-ProductionReleaseInput -Path (Join-Path $requestRoot 'signing-request.v1.json') -Label 'Admitted signing request document' -MaximumBytes $script:MaximumJsonBytes
            try {
                if ([string]$requestDocument.Sha256 -cne [string]$requestReceipt.data.requestSha256) {
                    throw 'Admitted signing request document differs from its transition receipt.'
                }
            }
            finally {
                $requestDocument.Stream.Dispose()
            }
            for ($index = 0; $index -lt @($Plan.clientSigningInputs).Count; $index++) {
                $planned = $Plan.clientSigningInputs[$index]
                $recorded = $requestReceipt.data.files[$index]
                if ([string]$recorded.role -cne [string]$planned.role -or
                    [string]$recorded.fileName -cne [string]$planned.fileName -or
                    [string]$recorded.sha256 -cne [string]$planned.sha256 -or
                    [string]$recorded.peContentSha256 -cne [string]$planned.peContentSha256) {
                    throw "Admitted unsigned client role index $index differs from the plan and request receipt."
                }
                $unsigned = Open-ProductionReleaseInput -Path (Join-Path $unsignedRoot ([string]$planned.fileName)) -Label "Admitted unsigned client role $($planned.role)" -MaximumBytes 512MB
                try {
                    $unsignedBytes = Read-ProductionReleaseInputBytes -Descriptor $unsigned -Label "Admitted unsigned client role $($planned.role)"
                    if ([int64]$unsigned.SizeBytes -ne [int64]$planned.sizeBytes -or
                        [string]$unsigned.Sha256 -cne [string]$recorded.sha256 -or
                        (Get-PeContentSha256 -Bytes $unsignedBytes) -cne [string]$recorded.peContentSha256) {
                        throw "Admitted unsigned client role '$($planned.role)' differs from its transition receipt."
                    }
                }
                finally {
                    $unsigned.Stream.Dispose()
                }
            }
        }
    }

    $importsRoot = Join-Path $StateRoot 'imports'
    $importEntries = @(
        if (Test-Path -LiteralPath $importsRoot) {
            if (-not (Test-Path -LiteralPath $importsRoot -PathType Container)) {
                throw 'Production imports path is not a directory.'
            }
            $ordinaryImportsRoot = Assert-OrdinaryProductionDirectory `
                -Path $importsRoot `
                -Label 'Production imports directory'
            Get-ChildItem -LiteralPath $ordinaryImportsRoot -Force
        }
        elseif ($schemaVersion -ne 1 -or $AdmittedRevision -ge 3) {
            throw 'Production imports directory is missing for admitted state.'
        }
    )
    $allowedImportEntries = @('client-signing.v1')
    if ($personalPilotFeedLifecycle) { $allowedImportEntries += 'pilot-feed-result.v1' }
    if ($schemaVersion -eq 2) {
        $allowedImportEntries += [string]$channelContract.CandidateBundleName
        if ($installerLifecycle) {
            $allowedImportEntries += if ([string]$Identity.edition -ceq 'Personal') {
                'installer-signing.v2'
            }
            else {
                'installer-signing.v1'
            }
        }
        if ($enterpriseStablePilotEvidenceLifecycle) {
            $allowedImportEntries += 'pilot-evidence.v1'
            $allowedImportEntries += 'stable-feed-result.v1'
        }
    }
    foreach ($entry in $importEntries) {
        if ($entry.Name -notin $allowedImportEntries -or
            -not $entry.PSIsContainer -or
            ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Production imports directory contains an unexpected entry.'
        }
    }
    $clientImportEntries = @($importEntries | Where-Object { $_.Name -ceq 'client-signing.v1' })
    $candidateImportEntries = @(
        if ($schemaVersion -eq 2) {
            $importEntries | Where-Object {
                $_.Name -ceq [string]$channelContract.CandidateBundleName
            }
        }
    )
    $installerImportEntries = @(
        if ($installerLifecycle) {
            $expectedInstallerImportName = if ([string]$Identity.edition -ceq
                'Personal') { 'installer-signing.v2' } else { 'installer-signing.v1' }
            $importEntries | Where-Object {
                $_.Name -ceq $expectedInstallerImportName
            }
        }
    )
    $pilotEvidenceImportEntries = @(
        if ($enterpriseStablePilotEvidenceLifecycle) {
            $importEntries | Where-Object { $_.Name -ceq 'pilot-evidence.v1' }
        }
    )
    if ($clientImportEntries.Count -gt 1 -or
        $candidateImportEntries.Count -gt 1 -or
        $installerImportEntries.Count -gt 1 -or
        $pilotEvidenceImportEntries.Count -gt 1) {
        throw 'Production imports directory repeats an owned bundle.'
    }
    if ($AdmittedRevision -ge 3 -and $clientImportEntries.Count -ne 1) {
        throw 'Admitted client signing response bundle is missing.'
    }
    if ($schemaVersion -eq 2 -and
        $AdmittedRevision -lt 4 -and $candidateImportEntries.Count -ne 0) {
        throw 'Target-channel signed-candidate import exists before its typed transition.'
    }
    if ($schemaVersion -eq 2 -and
        $AdmittedRevision -ge 5 -and $candidateImportEntries.Count -ne 1) {
        throw 'Admitted target-channel signed-candidate import bundle is missing.'
    }
    if ($installerLifecycle -and
        $AdmittedRevision -lt 6 -and $installerImportEntries.Count -ne 0) {
        throw 'Installer-signature import exists before its typed transition.'
    }
    if ($installerLifecycle -and
        $AdmittedRevision -ge 7 -and $installerImportEntries.Count -ne 1) {
        throw 'Admitted Installer-signature import bundle is missing.'
    }
    if ($enterpriseStablePilotEvidenceLifecycle -and
        $CommittedRevision -lt 7 -and $pilotEvidenceImportEntries.Count -ne 0) {
        throw 'Pilot-evidence import exists before the authoritative r7 transition.'
    }
    if ($enterpriseStablePilotEvidenceLifecycle -and
        $CommittedRevision -ge 8 -and $pilotEvidenceImportEntries.Count -ne 1) {
        throw 'Admitted Pilot-evidence import bundle is missing.'
    }
    if ($clientImportEntries.Count -eq 1) {
        $importRoot = $clientImportEntries[0].FullName
        $importInventory = [ordered]@{
            'signing-response.v1.json' = $false
            'signed' = $true
        }
        Assert-ExactProductionStateDirectory -Path $importRoot -Expected $importInventory -Label 'Production client signing import bundle'
        $signedRoot = Join-Path $importRoot 'signed'
        Assert-ExactProductionStateDirectory -Path $signedRoot -Expected $fileInventory -Label 'Production signed client snapshot'
        if ($AdmittedRevision -ge 3) {
            $importReceipt = $Receipts[2]
            $responseDocument = Open-ProductionReleaseInput -Path (Join-Path $importRoot 'signing-response.v1.json') -Label 'Admitted signing response document' -MaximumBytes $script:MaximumJsonBytes
            try {
                if ([string]$responseDocument.Sha256 -cne [string]$importReceipt.data.responseSha256) {
                    throw 'Admitted signing response document differs from its transition receipt.'
                }
            }
            finally {
                $responseDocument.Stream.Dispose()
            }
            for ($index = 0; $index -lt @($Plan.clientSigningInputs).Count; $index++) {
                $planned = $Plan.clientSigningInputs[$index]
                $recorded = $importReceipt.data.files[$index]
                if ([string]$recorded.role -cne [string]$planned.role -or
                    [string]$recorded.fileName -cne [string]$planned.fileName -or
                    [string]$recorded.peContentSha256 -cne [string]$planned.peContentSha256 -or
                    [string]$recorded.timestampProtocol -cne 'RFC3161') {
                    throw "Admitted signed client role index $index differs from the plan and import receipt."
                }
                $signed = Open-ProductionReleaseInput -Path (Join-Path $signedRoot ([string]$planned.fileName)) -Label "Admitted signed client role $($planned.role)" -MaximumBytes 512MB
                try {
                    $signedBytes = Read-ProductionReleaseInputBytes -Descriptor $signed -Label "Admitted signed client role $($planned.role)"
                    if ([int64]$signed.SizeBytes -ne [int64]$recorded.sizeBytes -or
                        [string]$signed.Sha256 -cne [string]$recorded.sha256 -or
                        (Get-PeContentSha256 -Bytes $signedBytes) -cne [string]$recorded.peContentSha256) {
                        throw "Admitted signed client role '$($planned.role)' differs from its transition receipt."
                    }
                }
                finally {
                    $signed.Stream.Dispose()
                }
            }
        }
    }
    if ($installerRequestEntries.Count -eq 1) {
        $installerFileName = "Ensou.Dsh.$([string]$Identity.edition).Installer.exe"
        $installerRequestRoot = $installerRequestEntries[0].FullName
        Assert-ExactProductionStateDirectory `
            -Path $installerRequestRoot `
            -Expected ([ordered]@{
                'installer-signing-request.v2.json' = $false
                'unsigned' = $true
                'payload' = $true
                'trusted-build' = $true
            }) `
            -Label 'Production Installer-signing request bundle'
        $installerUnsignedRoot = Join-Path $installerRequestRoot 'unsigned'
        Assert-ExactProductionStateDirectory `
            -Path $installerUnsignedRoot `
            -Expected ([ordered]@{
                $installerFileName = $false
            }) `
            -Label 'Production unsigned Enterprise Installer bundle'
        $installerPayloadRoot = Join-Path $installerRequestRoot 'payload'
        $installerPayloadInventory = if ([string]$Identity.edition -ceq 'Personal') {
            [ordered]@{
                'release-set.v2.json' = $false
                'Ensou.Dsh.Bootstrapper.exe' = $false
                'client-bundle.zip' = $false
                'runtime.zip' = $false
            }
        }
        else {
            [ordered]@{
                'Ensou.Dsh.Enterprise.Bootstrapper.exe' = $false
                'enterprise-install-manifest.json' = $false
                'launcher.zip' = $false
                'runtime.zip' = $false
            }
        }
        Assert-ExactProductionStateDirectory `
            -Path $installerPayloadRoot `
            -Expected $installerPayloadInventory `
            -Label 'Production Installer payload bundle'
        $installerTrustedBuildRoot = Join-Path `
            $installerRequestRoot `
            'trusted-build'
        Assert-ExactProductionStateDirectory `
            -Path $installerTrustedBuildRoot `
            -Expected ([ordered]@{
                'trusted-build-evidence.v1.json' = $false
            }) `
            -Label 'Production Installer trusted-build evidence bundle'
        if ($AdmittedRevision -ge 6) {
            $installerRequestReceipt = $Receipts[5]
            $installerRequestInput = Read-StrictProductionJsonFile `
                -Path (Join-Path $installerRequestRoot 'installer-signing-request.v2.json') `
                -Label 'Admitted Installer-signing request'
            [void](Assert-CanonicalProductionJsonInput `
                -JsonInput $installerRequestInput `
                -Label 'Admitted Installer-signing request')
            $trustedBuildEvidenceInput = Read-StrictProductionJsonFile `
                -Path (Join-Path $installerTrustedBuildRoot `
                    'trusted-build-evidence.v1.json') `
                -Label 'Admitted Installer trusted-build evidence'
            [void](Assert-CanonicalProductionJsonInput `
                -JsonInput $trustedBuildEvidenceInput `
                -Label 'Admitted Installer trusted-build evidence')
            $request = $installerRequestInput.Value
            $evidence = $trustedBuildEvidenceInput.Value
            if ([string]$Identity.edition -ceq 'Personal') {
                $r6Data = $installerRequestReceipt.data
                $bindingSources = [ordered]@{
                    sourceSha256 = $request.source
                    payloadSha256 = $request.payload
                    compiledTrustSha256 = $request.compiledTrust
                    toolchainSha256 = $request.toolchain
                    buildExecutionSha256 = $request.buildExecution
                    resourceBindingSha256 = $request.resourceBinding
                    trustedBuildEvidenceSha256 = $request.trustedBuildEvidence
                    admissionSha256 = $request.admission
                }
                foreach ($bindingName in $bindingSources.Keys) {
                    $actualBinding = Get-ProductionSha256Bytes -Bytes (
                        ConvertTo-ProductionJsonBytes `
                            -Value $bindingSources[$bindingName])
                    if ([string]$r6Data.$bindingName -cne $actualBinding) {
                        throw "Admitted Personal Installer request binding '$bindingName' differs from its typed r6 receipt."
                    }
                }
                $r5Files = @($Receipts[4].data.files)
                $r5Bindings = [ordered]@{
                    r5ManifestSha256 = 'release-manifest'
                    r5ClientBundleSha256 = 'client-bundle'
                    r5RuntimeSha256 = 'runtime'
                }
                foreach ($bindingName in $r5Bindings.Keys) {
                    $role = [string]$r5Bindings[$bindingName]
                    $candidateMatches = @($r5Files | Where-Object {
                            [string]$_.role -ceq $role
                        })
                    $payloadMatches = @($request.payload.files | Where-Object {
                            [string]$_.role -ceq $role
                        })
                    if ($candidateMatches.Count -ne 1 -or
                        $payloadMatches.Count -ne 1 -or
                        [string]$candidateMatches[0].sha256 -cne
                            [string]$payloadMatches[0].sha256 -or
                        [string]$r6Data.$bindingName -cne
                            [string]$payloadMatches[0].sha256) {
                        throw "Admitted Personal r5 role '$role' differs from its exact r6 request closure."
                    }
                }
                $r5ReceiptInput = Open-ProductionReleaseInput `
                    -Path (Join-Path (Join-Path $StateRoot 'receipts') `
                        '0005-pilot-signed-candidate-imported.json') `
                    -Label 'Admitted Personal r5 receipt' `
                    -MaximumBytes $script:MaximumJsonBytes
                try {
                    $r5ReceiptSha256 = [string]$r5ReceiptInput.Sha256
                }
                finally {
                    $r5ReceiptInput.Stream.Dispose()
                }
                if ([int]$request.schemaVersion -ne 2 -or
                    [string]$request.requestType -cne
                        'ensou-dsh-personal-installer-signing-request' -or
                    [string]$request.edition -cne 'Personal' -or
                    [string]$request.channel -cne 'pilot' -or
                    [int]$r6Data.requestSchemaVersion -ne 2 -or
                    [string]$installerRequestInput.Sha256 -cne
                        [string]$r6Data.requestSha256 -or
                    [string]$request.baseHeadSha256 -cne
                        [string]$r6Data.baseHeadSha256 -or
                    [string]$r6Data.baseReceiptSha256 -cne $r5ReceiptSha256 -or
                    [string]$request.trustedBuildEvidence.sha256 -cne
                        [string]$trustedBuildEvidenceInput.Sha256 -or
                    [int64]$request.trustedBuildEvidence.sizeBytes -ne
                        [int64]$trustedBuildEvidenceInput.Bytes.LongLength -or
                    [string]$request.responseAuthentication.keyId -cne
                        [string]$r6Data.authenticationKeyId -or
                    [string]$request.responseAuthentication.purpose -cne
                        [string]$r6Data.authenticationPurpose -or
                    [string]$request.responseAuthentication.payloadType -cne
                        [string]$r6Data.authenticationPayloadType -or
                    [string]$request.admission.blocker -cne
                        'INSTALLER_SIGNING_RESPONSE_REQUIRED' -or
                    [string]$r6Data.admissionReason -cne
                        'INSTALLER_SIGNING_RESPONSE_REQUIRED' -or
                    [string]$request.admission.productionAdmission -cne 'NO_GO' -or
                    [string]$r6Data.productionAdmission -cne 'NO_GO' -or
                    [string]$evidence.edition -cne 'Personal' -or
                    [string]$evidence.channel -cne 'pilot' -or
                    [string]$evidence.releaseSetId -cne
                        [string]$request.releaseSetId -or
                    (Get-ProductionSha256Bytes -Bytes (
                        ConvertTo-ProductionJsonBytes -Value $evidence.source)) -cne
                        [string]$r6Data.sourceSha256 -or
                    (Get-ProductionSha256Bytes -Bytes (
                        ConvertTo-ProductionJsonBytes -Value $evidence.payload)) -cne
                        [string]$r6Data.payloadSha256 -or
                    (Get-ProductionSha256Bytes -Bytes (
                        ConvertTo-ProductionJsonBytes -Value $evidence.compiledTrust)) -cne
                        [string]$r6Data.compiledTrustSha256 -or
                    (Get-ProductionSha256Bytes -Bytes (
                        ConvertTo-ProductionJsonBytes -Value $evidence.resourceBinding)) -cne
                        [string]$r6Data.resourceBindingSha256 -or
                    [string]$evidence.unsignedInstaller.sha256 -cne
                        [string]$request.unsignedInstaller.sha256) {
                    throw 'Admitted Personal Installer-signing request differs from its typed r6 receipt.'
                }
            }
            else {
            $resourceBindingSha256 = Get-ProductionSha256Bytes -Bytes (
                ConvertTo-ProductionJsonBytes -Value $request.resourceBinding)
            $evidenceResourceBindingSha256 = Get-ProductionSha256Bytes -Bytes (
                ConvertTo-ProductionJsonBytes -Value $evidence.resourceBinding)
            $r5Launcher = @($Receipts[4].data.files | Where-Object {
                    [string]$_.role -ceq 'launcher'
                })
            $r5Runtime = @($Receipts[4].data.files | Where-Object {
                    [string]$_.role -ceq 'runtime'
                })
            if ($r5Launcher.Count -ne 1 -or $r5Runtime.Count -ne 1) {
                throw 'Admitted Enterprise r5 candidate lacks one exact Launcher/runtime identity.'
            }
            $r5ReceiptInput = Open-ProductionReleaseInput `
                -Path (Join-Path (Join-Path $StateRoot 'receipts') `
                    '0005-stable-signed-candidate-imported.json') `
                -Label 'Admitted Enterprise r5 receipt' `
                -MaximumBytes $script:MaximumJsonBytes
            try {
                $r5ReceiptSha256 = [string]$r5ReceiptInput.Sha256
            }
            finally {
                $r5ReceiptInput.Stream.Dispose()
            }
            if ([int]$request.schemaVersion -ne 2 -or
                [int]$installerRequestReceipt.data.requestSchemaVersion -ne 2 -or
                [string]$installerRequestInput.Sha256 -cne
                    [string]$installerRequestReceipt.data.requestSha256 -or
                [string]$request.baseHeadSha256 -cne
                    [string]$installerRequestReceipt.data.baseHeadSha256 -or
                [string]$request.sourceBuildInputSetSha256 -cne
                    [string]$installerRequestReceipt.data.sourceBuildInputSetSha256 -or
                [string]$request.buildExecution.targetBuildIdentitySha256 -cne
                    [string]$installerRequestReceipt.data.targetBuildIdentitySha256 -or
                [string]$request.installerPayload.inventorySha256 -cne
                    [string]$installerRequestReceipt.data.payloadSetSha256 -or
                [string]$request.trustedBuildEvidence.sha256 -cne
                    [string]$trustedBuildEvidenceInput.Sha256 -or
                [int64]$request.trustedBuildEvidence.sizeBytes -ne
                    [int64]$trustedBuildEvidenceInput.Bytes.LongLength -or
                [string]$request.trustedBuildEvidence.sha256 -cne
                    [string]$installerRequestReceipt.data.trustedBuildEvidenceSha256 -or
                [string]$request.trustedBuildEvidence.resourceBindingSha256 -cne
                    $resourceBindingSha256 -or
                [string]$resourceBindingSha256 -cne
                    $evidenceResourceBindingSha256 -or
                [string]$resourceBindingSha256 -cne
                    [string]$installerRequestReceipt.data.resourceBindingSha256 -or
                [string]$request.trustedBuildEvidence.productionAdmission -cne
                    'NO_GO' -or
                [string]$request.trustedBuildEvidence.sdkFileClosureStatus -cne
                    'VERIFIED' -or
                [string]$evidence.toolchainLock.sdkFileClosureStatus -cne
                    'VERIFIED' -or
                [string]$installerRequestReceipt.data.sdkFileClosureStatus -cne
                    'VERIFIED' -or
                [string]$evidence.signingRequestEligibility.status -cne
                    'ELIGIBLE_FOR_PILOT_SIGNING' -or
                [string]$installerRequestReceipt.data.signingRequestEligibilityStatus -cne
                    'ELIGIBLE_FOR_PILOT_SIGNING' -or
                [string]$evidence.signingRequestEligibility.blocker -cne
                    'INSTALLER_SIGNING_RESPONSE_REQUIRED' -or
                [string]$installerRequestReceipt.data.admissionReason -cne
                    'INSTALLER_SIGNING_RESPONSE_REQUIRED' -or
                [string]$installerRequestReceipt.data.productionAdmission -cne
                    'NO_GO' -or
                [string]$request.r5Evidence.receiptSha256 -cne $r5ReceiptSha256 -or
                [string]$installerRequestReceipt.data.baseReceiptSha256 -cne
                    $r5ReceiptSha256 -or
                [string]$installerRequestReceipt.data.r5LauncherSha256 -cne
                    [string]$r5Launcher[0].sha256 -or
                [string]$installerRequestReceipt.data.r5RuntimeSha256 -cne
                    [string]$r5Runtime[0].sha256 -or
                [string]$evidence.orchestrationId -cne
                    [string]$request.orchestrationId -or
                [string]$evidence.planSha256 -cne [string]$request.planSha256 -or
                [string]$evidence.baseHeadSha256 -cne
                    [string]$request.baseHeadSha256 -or
                [string]$evidence.sourceCommit -cne
                    [string]$request.sourceCommit -or
                [string]$evidence.sourceTree -cne [string]$request.sourceTree -or
                [string]$evidence.sourceBuildInputs.inventorySha256 -cne
                    [string]$request.sourceBuildInputSetSha256 -or
                [string]$evidence.buildExecution.targetBuildIdentitySha256 -cne
                    [string]$request.buildExecution.targetBuildIdentitySha256 -or
                [string]$evidence.unsignedInstaller.sha256 -cne
                    [string]$request.unsignedInstaller.sha256) {
                throw 'Admitted Installer-signing request differs from its typed r6 receipt.'
            }
            }
            $unsigned = Open-ProductionReleaseInput `
                -Path (Join-Path $installerUnsignedRoot $installerFileName) `
                -Label 'Admitted unsigned Installer' `
                -MaximumBytes 1GB
            try {
                if ([int64]$unsigned.SizeBytes -ne
                        [int64]$installerRequestReceipt.data.unsignedInstaller.sizeBytes -or
                    [string]$unsigned.Sha256 -cne
                        [string]$installerRequestReceipt.data.unsignedInstaller.sha256) {
                    throw 'Admitted unsigned Installer differs from its typed r6 receipt.'
                }
            }
            finally {
                $unsigned.Stream.Dispose()
            }
            $installerPayloadFiles = if ([string]$Identity.edition -ceq 'Personal') {
                @($installerRequestInput.Value.payload.files)
            }
            else {
                @($installerRequestInput.Value.installerPayload.files)
            }
            foreach ($payload in $installerPayloadFiles) {
                $payloadInput = Open-ProductionReleaseInput `
                    -Path (Join-Path $installerPayloadRoot ([string]$payload.fileName)) `
                    -Label "Admitted Installer payload role $($payload.role)" `
                    -MaximumBytes (8L * 1024 * 1024 * 1024)
                try {
                    if ([int64]$payloadInput.SizeBytes -ne [int64]$payload.sizeBytes -or
                        [string]$payloadInput.Sha256 -cne [string]$payload.sha256) {
                        throw "Admitted Installer payload role '$($payload.role)' differs from r6."
                    }
                }
                finally {
                    $payloadInput.Stream.Dispose()
                }
            }
        }
    }
    if ($installerImportEntries.Count -eq 1) {
        $installerFileName = "Ensou.Dsh.$([string]$Identity.edition).Installer.exe"
        $installerImportRoot = $installerImportEntries[0].FullName
        $installerResponseFileName = if ([string]$Identity.edition -ceq
            'Personal') {
            'personal-installer-signing-response.v2.json'
        }
        else {
            'installer-signing-response.v1.json'
        }
        Assert-ExactProductionStateDirectory `
            -Path $installerImportRoot `
            -Expected ([ordered]@{
                $installerResponseFileName = $false
                'signed' = $true
            }) `
            -Label 'Production Installer-signature import bundle'
        $installerSignedRoot = Join-Path $installerImportRoot 'signed'
        Assert-ExactProductionStateDirectory `
            -Path $installerSignedRoot `
            -Expected ([ordered]@{
                $installerFileName = $false
            }) `
            -Label 'Production signed Enterprise Installer bundle'
        if ($AdmittedRevision -ge 7) {
            $installerImportReceipt = $Receipts[6]
            $installerResponseSchemaPath = if ([string]$Identity.edition -ceq
                'Personal') {
                Join-Path (Join-Path $PSScriptRoot '..\schemas') `
                    'personal-installer-signing-response-v2.schema.json'
            }
            else {
                Join-Path (Join-Path $PSScriptRoot '..\schemas') `
                    'launcher-installer-signing-response-v1.schema.json'
            }
            $installerResponseInput = Read-StrictProductionJsonFile `
                -Path (Join-Path $installerImportRoot $installerResponseFileName) `
                -Label 'Admitted Installer-signing response' `
                -SchemaPath $installerResponseSchemaPath
            [void](Assert-CanonicalProductionJsonInput `
                -JsonInput $installerResponseInput `
                -Label 'Admitted Installer-signing response')
            $r6Data = $Receipts[5].data
            $r7Data = $installerImportReceipt.data
            if ([string]$Identity.edition -ceq 'Personal') {
                foreach ($bindingName in @(
                        'sourceSha256', 'payloadSha256', 'compiledTrustSha256',
                        'toolchainSha256', 'buildExecutionSha256',
                        'resourceBindingSha256', 'trustedBuildEvidenceSha256',
                        'admissionSha256')) {
                    if ([string]$installerResponseInput.Value.requestBindings.$bindingName -cne
                            [string]$r6Data.$bindingName -or
                        [string]$r7Data.$bindingName -cne
                            [string]$r6Data.$bindingName) {
                        throw "Admitted Personal response binding '$bindingName' differs across r6 and r7."
                    }
                }
                if ([string]$installerResponseInput.Sha256 -cne
                        [string]$r7Data.responseSha256 -or
                    [int]$installerResponseInput.Value.schemaVersion -ne 2 -or
                    [string]$installerResponseInput.Value.responseType -cne
                        'ensou-dsh-personal-installer-signing-response' -or
                    [string]$installerResponseInput.Value.requestSha256 -cne
                        [string]$r6Data.requestSha256 -or
                    [string]$r7Data.requestSha256 -cne
                        [string]$r6Data.requestSha256 -or
                    [string]$installerResponseInput.Value.admissionHeadSha256 -cne
                        [string]$r7Data.admissionHeadSha256 -or
                    [string]$installerResponseInput.Value.r6ReceiptSha256 -cne
                        [string]$r7Data.r6ReceiptSha256 -or
                    [int]$r7Data.requestSchemaVersion -ne 2 -or
                    [string]$installerResponseInput.Value.signedInstaller.sha256 -cne
                        [string]$r7Data.signedInstaller.sha256 -or
                    [string]$installerResponseInput.Value.signedInstaller.peContentSha256 -cne
                        [string]$r7Data.signedInstaller.peContentSha256 -or
                    [string]$installerResponseInput.Value.authenticode.signerCertificateSha256 -cne
                        [string]$r7Data.signerCertificateSha256 -or
                    [string]$installerResponseInput.Value.authenticode.timestampSignerCertificateSha256 -cne
                        [string]$r7Data.timestampSignerCertificateSha256 -or
                    [string]$installerResponseInput.Value.authenticode.timestampUtc -cne
                        [string]$r7Data.timestampUtc -or
                    [string]$installerResponseInput.Value.authentication.keyId -cne
                        [string]$r7Data.authenticationKeyId -or
                    [string]$installerResponseInput.Value.authentication.purpose -cne
                        [string]$r7Data.authenticationPurpose -or
                    [string]$installerResponseInput.Value.authentication.payloadType -cne
                        [string]$r7Data.authenticationPayloadType -or
                    [string]$installerResponseInput.Value.payloadSelfCheck.canonicalJsonSha256 -cne
                        [string]$r7Data.payloadSelfCheckCanonicalJsonSha256 -or
                    [string]$r7Data.admissionReason -cne
                        'PERSONAL_SIGNED_WINDOWS_PILOT_REQUIRED' -or
                    [string]$r7Data.productionAdmission -cne 'NO_GO' -or
                    [string]$r6Data.productionAdmission -cne 'NO_GO') {
                    throw 'Admitted Personal Installer-signing response differs from its typed r7 receipt.'
                }
            }
            else {
            if ([string]$installerResponseInput.Sha256 -cne
                    [string]$r7Data.responseSha256 -or
                [string]$installerResponseInput.Value.requestSha256 -cne
                    [string]$r7Data.requestSha256 -or
                [string]$installerResponseInput.Value.admissionHeadSha256 -cne
                    [string]$r7Data.admissionHeadSha256 -or
                [int]$r7Data.requestSchemaVersion -ne 2 -or
                [int]$r7Data.requestSchemaVersion -ne
                    [int]$r6Data.requestSchemaVersion -or
                [string]$r7Data.requestSha256 -cne
                    [string]$r6Data.requestSha256 -or
                [string]$r7Data.trustedBuildEvidenceSha256 -cne
                    [string]$r6Data.trustedBuildEvidenceSha256 -or
                [string]$r7Data.resourceBindingSha256 -cne
                    [string]$r6Data.resourceBindingSha256 -or
                [string]$r7Data.sdkFileClosureStatus -cne
                    [string]$r6Data.sdkFileClosureStatus -or
                [string]$r7Data.signingRequestEligibilityStatus -cne
                    [string]$r6Data.signingRequestEligibilityStatus -or
                [string]$r7Data.sourceBuildInputSetSha256 -cne
                    [string]$r6Data.sourceBuildInputSetSha256 -or
                [string]$r7Data.targetBuildIdentitySha256 -cne
                    [string]$r6Data.targetBuildIdentitySha256 -or
                [string]$r7Data.payloadSetSha256 -cne
                    [string]$r6Data.payloadSetSha256 -or
                [string]$r7Data.sdkFileClosureStatus -cne 'VERIFIED' -or
                [string]$r7Data.admissionReason -cne
                    'INSTALLER_SIGNING_RESPONSE_REQUIRED' -or
                [string]$r7Data.admissionReason -cne
                    [string]$r6Data.admissionReason -or
                [string]$r7Data.productionAdmission -cne 'NO_GO' -or
                [string]$r6Data.productionAdmission -cne 'NO_GO' -or
                [string]$installerResponseInput.Value.sourceBuildInputSetSha256 -cne
                    [string]$r7Data.sourceBuildInputSetSha256 -or
                [string]$installerResponseInput.Value.targetBuildIdentitySha256 -cne
                    [string]$r7Data.targetBuildIdentitySha256 -or
                [string]$installerResponseInput.Value.payloadSetSha256 -cne
                    [string]$r7Data.payloadSetSha256) {
                throw 'Admitted Installer-signing response differs from its typed r7 receipt.'
            }
            }
            $signed = Open-ProductionReleaseInput `
                -Path (Join-Path $installerSignedRoot $installerFileName) `
                -Label 'Admitted signed Installer' `
                -MaximumBytes 1GB
            try {
                [byte[]]$signedBytes = Read-ProductionReleaseInputBytes `
                    -Descriptor $signed `
                    -Label 'Admitted signed Installer'
                if ([int64]$signed.SizeBytes -ne
                        [int64]$installerImportReceipt.data.signedInstaller.sizeBytes -or
                    [string]$signed.Sha256 -cne
                        [string]$installerImportReceipt.data.signedInstaller.sha256 -or
                    (Get-PeContentSha256 -Bytes $signedBytes) -cne
                        [string]$installerImportReceipt.data.signedInstaller.peContentSha256) {
                    throw 'Admitted signed Installer differs from its typed r7 receipt.'
                }
            }
            finally {
                $signed.Stream.Dispose()
            }
        }
    }
    if ($pilotEvidenceImportEntries.Count -eq 1) {
        $pilotEvidenceImportRoot = $pilotEvidenceImportEntries[0].FullName
        Assert-ExactProductionStateDirectory `
            -Path $pilotEvidenceImportRoot `
            -Expected ([ordered]@{
                'pilot-evidence-input.v1.json' = $false
            }) `
            -Label 'Production Pilot-evidence import bundle'
        $pilotEvidenceSchemaPath = Join-Path `
            (Join-Path $PSScriptRoot '..\schemas') `
            'enterprise-production-pilot-evidence-input-v1.schema.json'
        $pilotEvidenceInput = Read-StrictProductionJsonFile `
            -Path (Join-Path $pilotEvidenceImportRoot `
                'pilot-evidence-input.v1.json') `
            -Label 'Admitted Enterprise Pilot-evidence input' `
            -SchemaPath $pilotEvidenceSchemaPath
        [void](Assert-CanonicalProductionJsonInput `
            -Input $pilotEvidenceInput `
            -Label 'Admitted Enterprise Pilot-evidence input')
        [void](Assert-EnterpriseProductionPilotEvidenceInputBinding `
            -Input $pilotEvidenceInput `
            -Plan $Plan `
            -Identity $Identity `
            -IdentitySha256 $IdentitySha256 `
            -Receipts $Receipts `
            -StateRoot $StateRoot)
        if ($CommittedRevision -ge 8) {
            $pilotEvidenceReceipt = $Receipts[7]
            if ([string]$pilotEvidenceReceipt.data.evidenceType -cne
                    'PILOT_EVIDENCE_BOUND' -or
                [string]$pilotEvidenceReceipt.data.relativePath -cne
                    'imports/pilot-evidence.v1/pilot-evidence-input.v1.json' -or
                [string]$pilotEvidenceReceipt.data.sha256 -cne
                    [string]$pilotEvidenceInput.Sha256) {
                throw 'Admitted Pilot-evidence input differs from its typed r8 receipt.'
            }
        }
    }
    if ($manifestRequestEntries.Count -eq 1) {
        $manifestRequestInput = Assert-ProductionManifestPublishingRequestBundle `
            -StateRoot $StateRoot `
            -Plan $Plan `
            -Identity $Identity `
            -IdentitySha256 $IdentitySha256 `
            -Receipts $Receipts
        if ($candidateImportEntries.Count -eq 1) {
            Assert-ProductionSignedCandidateBundle `
                -StateRoot $StateRoot `
                -Plan $Plan `
                -Identity $Identity `
                -IdentitySha256 $IdentitySha256 `
                -Receipts $Receipts `
                -RequestInput $manifestRequestInput
        }
    }
    if ($personalPilotFeedLifecycle) {
        $personalRequest = Join-Path $StateRoot 'requests/pilot-feed-promotion.v1'
        if (Test-Path -LiteralPath $personalRequest) {
            if ($CommittedRevision -lt 7) { throw 'Personal promotion request exists before r7.' }
            Assert-ExactProductionStateDirectory -Path $personalRequest -Expected ([ordered]@{'request.v1.json'=$false}) -Label 'Personal sealed promotion request'
        }
        Microsoft.PowerShell.Core\Import-Module (Join-Path $PSScriptRoot 'PersonalFeedPromotionResult.psm1') -DisableNameChecking
        PersonalFeedPromotionResult\Assert-PersonalFeedPromotionHistoricalState -StateRoot $StateRoot -Plan $Plan -Identity $Identity -IdentitySha256 $IdentitySha256 -Receipts $Receipts -CommittedRevision $CommittedRevision -AdmittedRevision $AdmittedRevision
    }
    if ($enterpriseStablePilotEvidenceLifecycle -and
        ($stablePromotionRequestEntries.Count -eq 1 -or
         $AdmittedRevision -ge 9)) {
        [void](Assert-ProductionStableFeedPromotionAdmission `
            -StateRoot $StateRoot `
            -Plan $Plan `
            -Identity $Identity `
            -IdentitySha256 $IdentitySha256 `
            -Receipts $Receipts `
            -CommittedRevision $CommittedRevision `
            -AdmittedRevision $AdmittedRevision)
    }
    if ($enterpriseStablePilotEvidenceLifecycle) {
        Microsoft.PowerShell.Core\Import-Module (Join-Path $PSScriptRoot 'EnterpriseStablePublicationResult.psm1') -DisableNameChecking
        EnterpriseStablePublicationResult\Assert-EnterpriseStablePublicationHistoricalState -StateRoot $StateRoot -Plan $Plan -Identity $Identity -IdentitySha256 $IdentitySha256 -Receipts $Receipts -CommittedRevision $CommittedRevision -AdmittedRevision $AdmittedRevision
    }
}

function Get-ProductionReleaseState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$StateRoot,
        [Parameter(Mandatory = $true)][string]$StateSchemaPath
    )

    $root = Assert-OrdinaryProductionDirectory -Path $StateRoot -Label 'Production state root'
    Assert-ProductionStateTopLevel -StateRoot $root
    $identityInput = Read-StrictProductionJsonFile -Path (Join-Path $root 'identity.json') -Label 'Production state identity' -SchemaPath $StateSchemaPath
    $identity = $identityInput.Value
    $schemaVersion = [int]$identity.schemaVersion
    if ($schemaVersion -notin @(1, 2) -or
        [string]$identity.identityType -cne 'ensou-dsh-launcher-production-release-state') {
        throw 'Production state identity is invalid.'
    }
    [void](ConvertFrom-ProductionUtc -Value ([string]$identity.createdAtUtc) -Label 'Production state identity time')
    $planInput = Open-ProductionReleaseInput -Path (Join-Path $root 'plan.json') -Label 'Production plan snapshot' -MaximumBytes $script:MaximumJsonBytes
    try {
        if ($planInput.Sha256 -cne [string]$identity.planSha256) {
            throw 'Production plan snapshot differs from the state identity.'
        }
        $planBytes = Read-ProductionReleaseInputBytes -Descriptor $planInput -Label 'Production plan snapshot'
        $plan = ConvertFrom-StrictProductionJsonBytes -Bytes $planBytes -Label 'Production plan snapshot'
    }
    finally {
        $planInput.Stream.Dispose()
    }
    if ([int]$plan.schemaVersion -ne $schemaVersion) {
        throw 'Production plan and state identity schema versions differ.'
    }
    $targetChannel = if ($schemaVersion -eq 1) {
        [string]$plan.channel
    }
    else {
        [string]$plan.targetChannel
    }
    $lifecycle = Get-ProductionReleaseLifecycleContract -SchemaVersion $schemaVersion -TargetChannel $targetChannel
    if ($schemaVersion -eq 2 -and
        [string]$identity.targetChannel -cne $targetChannel) {
        throw 'Production state identity target channel differs from its plan.'
    }
    $initializationShaProperty = $identity.PSObject.Properties['initializationSha256']
    $initializationPath = Join-Path $root 'initialization.json'
    if ($null -ne $initializationShaProperty) {
        if (-not (Test-Path -LiteralPath $initializationPath -PathType Leaf)) {
            throw 'Production state identity-bound initialization owner is missing.'
        }
        $initializationMarker = Open-ProductionInitializationMarker `
            -StateRoot $root `
            -PlanBytes $planBytes `
            -Plan $plan
        try {
            if ([string]$initializationMarker.Sha256 -cne
                [string]$initializationShaProperty.Value -or
                [string]$initializationMarker.Value.identityCreatedAtUtc -cne
                [string]$identity.createdAtUtc) {
                throw 'Production state identity and initialization owner binding differ.'
            }
        }
        finally {
            $initializationMarker.Stream.Dispose()
        }
    }
    elseif (Test-Path -LiteralPath $initializationPath) {
        throw 'Legacy production state identity cannot adopt an unbound initialization owner.'
    }

    $headPath = Join-Path $root 'head.json'
    $head = $null
    $headSha256 = ''
    if (Test-Path -LiteralPath $headPath) {
        $headInput = Read-StrictProductionJsonFile -Path $headPath -Label 'Production state head' -SchemaPath $StateSchemaPath
        $head = $headInput.Value
        $headSha256 = $headInput.Sha256
        if ([int]$head.schemaVersion -ne $schemaVersion -or
            [string]$head.orchestrationId -cne [string]$identity.orchestrationId -or
            [string]$head.edition -cne [string]$identity.edition -or
            [string]$head.planSha256 -cne [string]$identity.planSha256 -or
            [string]$head.identitySha256 -cne [string]$identityInput.Sha256 -or
            ($schemaVersion -eq 2 -and
             [string]$head.targetChannel -cne $targetChannel)) {
            throw 'Production state head is not bound to its identity.'
        }
        [void](ConvertFrom-ProductionUtc -Value ([string]$head.updatedAtUtc) -Label 'Production state head time')
    }

    $receiptDirectory = Assert-OrdinaryProductionDirectory -Path (Join-Path $root 'receipts') -Label 'Production receipt directory'
    $receiptFiles = @(Get-ChildItem -LiteralPath $receiptDirectory -Force | Sort-Object Name)
    foreach ($entry in $receiptFiles) {
        if ($entry.PSIsContainer -or
            ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            $entry.Name -notmatch '^[0-9]{4}-[a-z0-9-]+[.]json$') {
            throw "Production receipt directory contains unexpected entry '$($entry.Name)'."
        }
    }
    $headRevision = if ($null -eq $head) { 0 } else { [int]$head.revision }
    if ($headRevision -gt $lifecycle.TerminalRevision) {
        throw 'Production state head advances beyond the target lifecycle terminal phase.'
    }
    if ($receiptFiles.Count -lt $headRevision -or
        $receiptFiles.Count -gt $headRevision + 1) {
        throw 'Production receipt directory is missing admitted receipts or contains multiple orphan transitions.'
    }
    $previousSha256 = '0' * 64
    $lastReceipt = $null
    $orphanReceipt = $null
    $orphanReceiptSha256 = ''
    $validatedReceipts = [Collections.Generic.List[object]]::new()
    for ($index = 0; $index -lt $headRevision; $index++) {
        $expectedRevision = $index + 1
        $expectedTransition = $lifecycle.Transitions[$index]
        $receiptInput = Read-StrictProductionJsonFile -Path $receiptFiles[$index].FullName -Label "Production receipt $expectedRevision" -SchemaPath $StateSchemaPath
        $receipt = $receiptInput.Value
        Assert-ProductionReceipt -Receipt $receipt -SchemaVersion $schemaVersion -TargetChannel $targetChannel -Revision $expectedRevision -OrchestrationId ([string]$identity.orchestrationId) -Edition ([string]$identity.edition) -PlanSha256 ([string]$identity.planSha256) -IdentitySha256 ([string]$identityInput.Sha256) -PreviousReceiptSha256 $previousSha256
        $expectedFileName = $expectedRevision.ToString('0000') + '-' + ([string]$expectedTransition.Phase).ToLowerInvariant().Replace('_', '-') + '.json'
        if ($receiptFiles[$index].Name -cne $expectedFileName -or
            [string]$receipt.phase -cne [string]$expectedTransition.Phase) {
            throw "Production receipt revision $expectedRevision has an invalid file name or phase."
        }
        $previousSha256 = $receiptInput.Sha256
        $lastReceipt = $receipt
        $validatedReceipts.Add($receipt)
    }
    if ($receiptFiles.Count -eq $headRevision + 1) {
        if ($headRevision -ge $lifecycle.TerminalRevision) {
            throw 'Production state contains an orphan transition after its terminal phase.'
        }
        $orphanRevision = $headRevision + 1
        $expectedOrphanTransition = $lifecycle.Transitions[$headRevision]
        $orphanInput = Read-StrictProductionJsonFile -Path $receiptFiles[$headRevision].FullName -Label "Orphan production receipt $orphanRevision" -SchemaPath $StateSchemaPath
        $orphanReceipt = $orphanInput.Value
        Assert-ProductionReceipt -Receipt $orphanReceipt -SchemaVersion $schemaVersion -TargetChannel $targetChannel -Revision $orphanRevision -OrchestrationId ([string]$identity.orchestrationId) -Edition ([string]$identity.edition) -PlanSha256 ([string]$identity.planSha256) -IdentitySha256 ([string]$identityInput.Sha256) -PreviousReceiptSha256 $previousSha256
        $expectedOrphanFileName = $orphanRevision.ToString('0000') + '-' + ([string]$expectedOrphanTransition.Phase).ToLowerInvariant().Replace('_', '-') + '.json'
        if ($receiptFiles[$headRevision].Name -cne $expectedOrphanFileName -or
            [string]$orphanReceipt.phase -cne [string]$expectedOrphanTransition.Phase) {
            throw 'Production state orphan receipt is not the one exact recoverable next transition.'
        }
        $orphanReceiptSha256 = [string]$orphanInput.Sha256
        $validatedReceipts.Add($orphanReceipt)
    }
    if ($null -ne $head) {
        if ($receiptFiles[$headRevision - 1].Name -cne [string]$head.receiptFileName -or
            $previousSha256 -cne [string]$head.receiptSha256 -or
            [string]$lastReceipt.phase -cne [string]$head.phase -or
            [string]$lastReceipt.recordedAtUtc -cne [string]$head.updatedAtUtc) {
            throw 'Production state head does not name the exact final admitted receipt.'
        }
    }
    $pendingHeadPath = Join-Path $root 'head.json.pending'
    if (Test-Path -LiteralPath $pendingHeadPath) {
        if ($null -eq $orphanReceipt) {
            throw 'Pending production state head has no exact recoverable orphan receipt.'
        }
        $pendingHeadInput = Read-StrictProductionJsonFile -Path $pendingHeadPath -Label 'Pending production state head' -SchemaPath $StateSchemaPath
        $pendingHead = $pendingHeadInput.Value
        if ([int]$pendingHead.schemaVersion -ne $schemaVersion -or
            [string]$pendingHead.orchestrationId -cne [string]$identity.orchestrationId -or
            [string]$pendingHead.edition -cne [string]$identity.edition -or
            [string]$pendingHead.planSha256 -cne [string]$identity.planSha256 -or
            [string]$pendingHead.identitySha256 -cne [string]$identityInput.Sha256 -or
            [int]$pendingHead.revision -ne ($headRevision + 1) -or
            [string]$pendingHead.phase -cne [string]$orphanReceipt.phase -or
            [string]$pendingHead.receiptFileName -cne [string]$receiptFiles[$headRevision].Name -or
            [string]$pendingHead.receiptSha256 -cne $orphanReceiptSha256 -or
            [string]$pendingHead.updatedAtUtc -cne [string]$orphanReceipt.recordedAtUtc -or
            ($schemaVersion -eq 2 -and
             [string]$pendingHead.targetChannel -cne $targetChannel)) {
            throw 'Pending production state head is not bound to the exact recoverable orphan receipt.'
        }
        [void](ConvertFrom-ProductionUtc -Value ([string]$pendingHead.updatedAtUtc) -Label 'Pending production state head time')
    }
    Assert-ProductionStatePayloadInventory `
        -StateRoot $root `
        -Plan $plan `
        -Identity $identity `
        -IdentitySha256 ([string]$identityInput.Sha256) `
        -CommittedRevision $headRevision `
        -AdmittedRevision $receiptFiles.Count `
        -Receipts $validatedReceipts
    return [pscustomobject]@{
        StateRoot = $root
        Identity = $identity
        IdentitySha256 = [string]$identityInput.Sha256
        Head = $head
        HeadSha256 = $headSha256
        ReceiptFiles = $receiptFiles
        Receipts = @($validatedReceipts)
        LastReceipt = $lastReceipt
        Plan = $plan
        SchemaVersion = $schemaVersion
        TargetChannel = $targetChannel
        Lifecycle = $lifecycle
        OrphanReceipt = $orphanReceipt
    }
}

function Enter-ProductionReleaseStateReadLock {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$StateRoot)

    if (-not [IO.Path]::IsPathFullyQualified($StateRoot)) {
        throw 'Production state root must be absolute.'
    }
    $fullRoot = Assert-OrdinaryProductionDirectory -Path ([IO.Path]::GetFullPath($StateRoot)) -Label 'Production state root'
    $lockPath = Join-Path $fullRoot 'state.lock'
    if (-not (Test-Path -LiteralPath $lockPath -PathType Leaf)) {
        throw 'Existing production state lock file is missing.'
    }
    try {
        $stream = [IO.File]::Open(
            $lockPath,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read)
    }
    catch {
        throw 'Production state root is locked by another orchestration process.'
    }
    try {
        [void][EnsouLauncherProduction.NativeFileIdentity]::RequireOrdinarySingleLink(
            $stream.SafeFileHandle)
        return [pscustomobject]@{
            StateRoot = $fullRoot
            Created = $false
            Stream = $stream
        }
    }
    catch {
        $stream.Dispose()
        throw
    }
}

function Write-ProductionHead {
    param(
        [Parameter(Mandatory = $true)][string]$StateRoot,
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$ExpectedCurrentHeadSha256
    )

    $headPath = Join-Path $StateRoot 'head.json'
    $pendingPath = $headPath + '.pending'
    $currentSha256 = ''
    if (Test-Path -LiteralPath $headPath) {
        $current = Open-ProductionReleaseInput -Path $headPath -Label 'Current production state head' -MaximumBytes $script:MaximumJsonBytes
        try {
            $currentSha256 = $current.Sha256
        }
        finally {
            $current.Stream.Dispose()
        }
    }
    if ($currentSha256 -cne $ExpectedCurrentHeadSha256) {
        throw 'Production state head changed before the compare-and-swap commit.'
    }
    if (Test-Path -LiteralPath $pendingPath) {
        $pending = Open-ProductionReleaseInput -Path $pendingPath -Label 'Pending production state head' -MaximumBytes $script:MaximumJsonBytes
        try {
            if ($pending.SizeBytes -ne $Bytes.LongLength -or
                $pending.Sha256 -cne (Get-ProductionSha256Bytes -Bytes $Bytes)) {
                throw 'Pending production state head conflicts with the requested compare-and-swap.'
            }
        }
        finally {
            $pending.Stream.Dispose()
        }
    }
    else {
        $stream = [IO.File]::Open(
            $pendingPath,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None)
        try {
            [void][EnsouLauncherProduction.NativeFileIdentity]::RequireOrdinarySingleLink(
                $stream.SafeFileHandle)
            $stream.Write($Bytes, 0, $Bytes.Length)
            $stream.Flush($true)
        }
        finally {
            $stream.Dispose()
        }
    }
    [IO.File]::Move($pendingPath, $headPath, $true)
}

function Add-ProductionReleaseReceipt {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$StateRoot,
        [Parameter(Mandatory = $true)][string]$StateSchemaPath,
        [Parameter(Mandatory = $true)][string]$Phase,
        [AllowNull()][string]$ExpectedPreviousPhase,
        [AllowEmptyString()][string]$ExpectedHeadSha256 = '',
        [Parameter(Mandatory = $true)]$Data,
        [AllowNull()][scriptblock]$PreCommitValidation = $null,
        [switch]$FaultAfterReceipt
    )

    $state = Get-ProductionReleaseState -StateRoot $StateRoot -StateSchemaPath $StateSchemaPath
    if ($null -ne $state.Head -and [string]$state.Head.phase -ceq $Phase) {
        $receipt = $state.LastReceipt
        $transition = Get-TransitionSha256 -SchemaVersion ([int]$state.SchemaVersion) -TargetChannel ([string]$state.TargetChannel) -OrchestrationId ([string]$state.Identity.orchestrationId) -Edition ([string]$state.Identity.edition) -PlanSha256 ([string]$state.Identity.planSha256) -IdentitySha256 ([string]$state.IdentitySha256) -Revision ([int]$receipt.revision) -Phase $Phase -PreviousReceiptSha256 ([string]$receipt.previousReceiptSha256) -Data $Data
        if ([string]$receipt.transitionSha256 -cne $transition) {
            throw "Committed phase $Phase conflicts with the requested idempotent transition."
        }
        return $state
    }
    $revision = if ($null -eq $state.Head) { 1 } else { [int]$state.Head.revision + 1 }
    if ($revision -gt [int]$state.Lifecycle.TerminalRevision) {
        throw "Production lifecycle is terminal at phase '$($state.Lifecycle.TerminalPhase)'."
    }
    $expectedTransition = $state.Lifecycle.Transitions[$revision - 1]
    [void](Assert-ProductionReleaseTransitionContract -SchemaVersion ([int]$state.SchemaVersion) -TargetChannel ([string]$state.TargetChannel) -Revision $revision -Phase $Phase -PreviousPhase $ExpectedPreviousPhase)
    $actualPreviousPhase = if ($null -eq $state.Head) { $null } else { [string]$state.Head.phase }
    if ([string]$actualPreviousPhase -cne [string]$expectedTransition.PreviousPhase) {
        throw "Phase $Phase requires previous phase '$($expectedTransition.PreviousPhase)', got '$actualPreviousPhase'."
    }
    if ($revision -ge 2 -and [string]::IsNullOrWhiteSpace($ExpectedHeadSha256)) {
        throw "Phase $Phase requires the exact current state head SHA-256 for compare-and-swap."
    }
    if ($state.HeadSha256 -cne $ExpectedHeadSha256) {
        throw "Phase $Phase rejected a stale production state head."
    }

    if ([int]$state.SchemaVersion -eq 2 -and [string]$state.Identity.edition -ceq 'Personal' -and
        [string]$state.TargetChannel -ceq 'pilot' -and $Phase -cin @('PILOT_PROMOTION_REQUESTED','PILOT_FEED_PROMOTED')) {
        Microsoft.PowerShell.Core\Import-Module (Join-Path $PSScriptRoot 'PersonalFeedPromotionResult.psm1') -DisableNameChecking
        # Refuse generic evidence before writing either an orphan receipt or head.
        PersonalFeedPromotionResult\Assert-PersonalFeedPromotionTransition -State $state -Phase $Phase -Data $Data
    }
    if ([int]$state.SchemaVersion -eq 2 -and [string]$state.Identity.edition -ceq 'Enterprise' -and
        [string]$state.TargetChannel -ceq 'stable' -and $Phase -ceq 'STABLE_FEED_PROMOTED') {
        Microsoft.PowerShell.Core\Import-Module (Join-Path $PSScriptRoot 'EnterpriseStablePublicationResult.psm1') -DisableNameChecking
        EnterpriseStablePublicationResult\Assert-EnterpriseStablePublicationTransition -State $state -Data $Data
    }

    $previousReceiptSha256 = if ($null -eq $state.Head) {
        '0' * 64
    }
    else {
        [string]$state.Head.receiptSha256
    }
    $transitionSha256 = Get-TransitionSha256 -SchemaVersion ([int]$state.SchemaVersion) -TargetChannel ([string]$state.TargetChannel) -OrchestrationId ([string]$state.Identity.orchestrationId) -Edition ([string]$state.Identity.edition) -PlanSha256 ([string]$state.Identity.planSha256) -IdentitySha256 ([string]$state.IdentitySha256) -Revision $revision -Phase $Phase -PreviousReceiptSha256 $previousReceiptSha256 -Data $Data
    $phaseSlug = $Phase.ToLowerInvariant().Replace('_', '-')
    $receiptFileName = $revision.ToString('0000') + '-' + $phaseSlug + '.json'
    $receiptPath = Join-Path (Join-Path $StateRoot 'receipts') $receiptFileName
    $recordedAtInstant = [DateTimeOffset]::UtcNow
    if ($null -ne $PreCommitValidation) {
        [void](& $PreCommitValidation $recordedAtInstant)
    }
    $recordedAtUtc = ConvertTo-ProductionUtc -Value $recordedAtInstant
    if (Test-Path -LiteralPath $receiptPath) {
        $existing = Read-StrictProductionJsonFile -Path $receiptPath -Label "Orphan production receipt $revision" -SchemaPath $StateSchemaPath
        Assert-ProductionReceipt -Receipt $existing.Value -SchemaVersion ([int]$state.SchemaVersion) -TargetChannel ([string]$state.TargetChannel) -Revision $revision -OrchestrationId ([string]$state.Identity.orchestrationId) -Edition ([string]$state.Identity.edition) -PlanSha256 ([string]$state.Identity.planSha256) -IdentitySha256 ([string]$state.IdentitySha256) -PreviousReceiptSha256 $previousReceiptSha256
        if ([string]$existing.Value.phase -cne $Phase -or
            [string]$existing.Value.transitionSha256 -cne $transitionSha256) {
            throw "Orphan production receipt revision $revision conflicts with phase $Phase."
        }
        $receiptSha256 = $existing.Sha256
        $recordedAtUtc = [string]$existing.Value.recordedAtUtc
    }
    else {
        if ($state.ReceiptFiles.Count -ne $revision - 1) {
            throw 'Production state contains an unexpected orphan transition.'
        }
        $receipt = [ordered]@{
            schemaVersion = [int]$state.SchemaVersion
            receiptType = 'ensou-dsh-launcher-production-release-transition'
            orchestrationId = [string]$state.Identity.orchestrationId
            edition = [string]$state.Identity.edition
            planSha256 = [string]$state.Identity.planSha256
            identitySha256 = [string]$state.IdentitySha256
            revision = $revision
            phase = $Phase
            previousReceiptSha256 = $previousReceiptSha256
            transitionSha256 = $transitionSha256
            data = $Data
            recordedAtUtc = $recordedAtUtc
        }
        if ([int]$state.SchemaVersion -eq 2) {
            $receipt.targetChannel = [string]$state.TargetChannel
        }
        $receiptBytes = ConvertTo-ProductionJsonBytes -Value $receipt
        [void](ConvertFrom-StrictProductionJsonBytes -Bytes $receiptBytes -Label "Generated production receipt $revision" -SchemaPath $StateSchemaPath)
        Write-ProductionStateFile -Path $receiptPath -Bytes $receiptBytes
        $receiptSha256 = Get-ProductionSha256Bytes -Bytes $receiptBytes
    }
    if ($FaultAfterReceipt) {
        throw "INJECTED-CRASH-AFTER-$Phase-RECEIPT"
    }
    $head = [ordered]@{
        schemaVersion = [int]$state.SchemaVersion
        stateType = 'ensou-dsh-launcher-production-release-head'
        orchestrationId = [string]$state.Identity.orchestrationId
        edition = [string]$state.Identity.edition
        planSha256 = [string]$state.Identity.planSha256
        identitySha256 = [string]$state.IdentitySha256
        revision = $revision
        phase = $Phase
        receiptFileName = $receiptFileName
        receiptSha256 = $receiptSha256
        updatedAtUtc = $recordedAtUtc
    }
    if ([int]$state.SchemaVersion -eq 2) {
        $head.targetChannel = [string]$state.TargetChannel
    }
    $headBytes = ConvertTo-ProductionJsonBytes -Value $head
    [void](ConvertFrom-StrictProductionJsonBytes -Bytes $headBytes -Label "Generated production head $revision" -SchemaPath $StateSchemaPath)
    Write-ProductionHead -StateRoot $StateRoot -Bytes $headBytes -ExpectedCurrentHeadSha256 $state.HeadSha256
    return Get-ProductionReleaseState -StateRoot $StateRoot -StateSchemaPath $StateSchemaPath
}

function Get-ProductionReleaseStateSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$StateRoot,
        [Parameter(Mandatory = $true)][string]$StateSchemaPath
    )

    $state = Get-ProductionReleaseState -StateRoot $StateRoot -StateSchemaPath $StateSchemaPath
    $revision = if ($null -eq $state.Head) { 0 } else { [int]$state.Head.revision }
    $phase = if ($null -eq $state.Head) { 'UNINITIALIZED' } else { [string]$state.Head.phase }
    $nextPhase = if ($revision -lt [int]$state.Lifecycle.TerminalRevision) {
        [string]$state.Lifecycle.Transitions[$revision].Phase
    }
    else {
        ''
    }
    $lifecycleTerminal = $revision -eq [int]$state.Lifecycle.TerminalRevision -and
        $phase -ceq [string]$state.Lifecycle.TerminalPhase
    $pilotEvidenceStatus = 'NOT_BOUND'
    $pilotEvidenceExpiresAtUtc = ''
    if ([int]$state.SchemaVersion -eq 2 -and
        [string]$state.Identity.edition -ceq 'Enterprise' -and
        [string]$state.TargetChannel -ceq 'stable' -and
        $revision -ge 8) {
        $pilotEvidenceSchemaPath = Join-Path `
            (Join-Path $PSScriptRoot '..\schemas') `
            'enterprise-production-pilot-evidence-input-v1.schema.json'
        $pilotEvidenceInput = Read-StrictProductionJsonFile `
            -Path (Join-Path $state.StateRoot `
                'imports\pilot-evidence.v1\pilot-evidence-input.v1.json') `
            -Label 'Committed Enterprise Pilot-evidence status input' `
            -SchemaPath $pilotEvidenceSchemaPath
        $committedR8Receipt = $state.Receipts[7]
        if ([int]$committedR8Receipt.revision -ne 8 -or
            [string]$committedR8Receipt.phase -cne 'PILOT_EVIDENCE_BOUND' -or
            [string]$committedR8Receipt.data.evidenceType -cne
                'PILOT_EVIDENCE_BOUND' -or
            [string]$committedR8Receipt.data.relativePath -cne
                'imports/pilot-evidence.v1/pilot-evidence-input.v1.json' -or
            [string]$committedR8Receipt.data.sha256 -cne
                [string]$pilotEvidenceInput.Sha256) {
            throw 'Committed Enterprise Pilot-evidence status input differs from its typed r8 receipt.'
        }
        $pilotEvidenceExpiresAtUtc =
            [string]$pilotEvidenceInput.Value.expiresAtUtc
        $pilotEvidenceExpiresAt = ConvertFrom-ProductionUtc `
            -Value $pilotEvidenceExpiresAtUtc `
            -Label 'Committed Enterprise Pilot-evidence status expiry time'
        $pilotEvidenceStatus = if (
            [DateTimeOffset]::UtcNow -ge $pilotEvidenceExpiresAt) {
            'STALE'
        }
        else {
            'CURRENT'
        }
    }
    # State v2 currently defines only the append-only lifecycle foundation.
    # Readiness must remain false until every external phase payload is bound to
    # its purpose-specific authenticated artifact and is revalidated on read.
    $externalEvidenceRevalidated = $false
    $pilotReady = $externalEvidenceRevalidated -and
        [int]$state.SchemaVersion -eq 2 -and
        [string]$state.TargetChannel -ceq 'pilot' -and
        $revision -eq 9 -and
        $phase -ceq 'PILOT_FEED_PROMOTED'
    $stableReady = $externalEvidenceRevalidated -and
        [int]$state.SchemaVersion -eq 2 -and
        [string]$state.TargetChannel -ceq 'stable' -and
        $revision -eq 10 -and
        $phase -ceq 'STABLE_FEED_PROMOTED'
    $noGoCode = if ([int]$state.SchemaVersion -eq 1) {
        'IMMUTABLE_SOURCE_RELEASE_UNVERIFIED'
    }
    elseif ($pilotEvidenceStatus -ceq 'STALE') {
        'R8_BINDING_EXPIRED'
    }
    elseif ($lifecycleTerminal) {
        'FOUNDATION_ONLY_EXTERNAL_EVIDENCE_UNVERIFIED'
    }
    elseif ($nextPhase -ceq 'PLAN_ADMITTED') {
        'PLAN_ADMISSION_REQUIRED'
    }
    elseif ($nextPhase -ceq 'CLIENT_SIGNING_REQUESTED') {
        'CLIENT_SIGNING_REQUEST_REQUIRED'
    }
    elseif ($nextPhase -ceq 'CLIENT_SIGNATURES_IMPORTED') {
        'CLIENT_SIGNATURES_REQUIRED'
    }
    else {
        'PHASE_NOT_IMPLEMENTED_' + $nextPhase
    }
    $requestPath = Join-Path (Join-Path (Join-Path $state.StateRoot 'requests') 'client-signing.v1') 'signing-request.v1.json'
    if (-not (Test-Path -LiteralPath $requestPath -PathType Leaf)) {
        $requestPath = ''
    }
    return [pscustomobject]@{
        OrchestrationId = [string]$state.Identity.orchestrationId
        Edition = [string]$state.Identity.edition
        SchemaVersion = [int]$state.SchemaVersion
        TargetChannel = [string]$state.TargetChannel
        PlanSha256 = [string]$state.Identity.planSha256
        Revision = $revision
        Phase = $phase
        HeadSha256 = [string]$state.HeadSha256
        NoGoCode = $noGoCode
        NextPhase = $nextPhase
        ExpectedHeadSha256 = [string]$state.HeadSha256
        RequestPath = $requestPath
        PilotEvidenceStatus = $pilotEvidenceStatus
        PilotEvidenceExpiresAtUtc = $pilotEvidenceExpiresAtUtc
        PilotReady = [bool]$pilotReady
        FeedPublicationEvidence = if ([string]$state.Identity.edition -ceq 'Personal' -and
            [string]$state.TargetChannel -ceq 'pilot' -and $revision -eq 9) {
            'AUTHENTICATED_COMPLETED_FEED_OPERATION_ONLY'
        } else { 'NOT_BOUND' }
        StableReady = [bool]$stableReady
        LifecycleTerminal = [bool]$lifecycleTerminal
        NoGo = if ($pilotEvidenceStatus -ceq 'STALE') {
            'NO-GO: R8_BINDING_EXPIRED; the committed r8 evidence is historical only and cannot authorize a mutating phase.'
        }
        elseif ($noGoCode -ceq 'NONE') {
            ''
        }
        else {
            "NO-GO: $noGoCode; IMMUTABLE_SOURCE_RELEASE_UNVERIFIED remains in force until the exact authenticated external transition is admitted."
        }
    }
}

Export-ModuleMember -Function @(
    'Get-ProductionRuntimeSourceReleaseExpectation',
    'Assert-ProductionRuntimeSourceReleaseExpectation',
    'Assert-ProductionRuntimeSourceReleaseAdmission',
    'Assert-ProductionRuntimeSourceReleaseResponseBinding',
    'Assert-ProductionRuntimeSourceReleaseHistory',
    'Add-ProductionReleaseReceipt',
    'Assert-CanonicalProductionJsonInput',
    'Assert-EnterpriseProductionPilotEvidenceInputBinding',
    'Assert-ExactProductionJsonMembers',
    'Assert-ProductionEs256P1363LowS',
    'Assert-ProductionReleaseInputStillLocked',
    'Assert-ProductionReleaseDirectoryStillLocked',
    'Assert-ProductionReleaseManifestPublishingResponseAuthentication',
    'Assert-ProductionReleaseManifestCandidate',
    'Assert-ProductionReleaseSigningResponseAuthentication',
    'Assert-ProductionStableFeedPromotionAdmission',
    'Assert-ProductionPublisherInputFileSet',
    'ConvertFrom-ProductionUtc',
    'ConvertFrom-StrictProductionJsonBytes',
    'ConvertTo-ProductionJsonBytes',
    'ConvertTo-ProductionEnterpriseReleaseManifestPayloadBytes',
    'ConvertTo-ProductionSystemTextJsonBytes',
    'ConvertTo-ProductionUtc',
    'Enter-ProductionReleaseStateLock',
    'Enter-ProductionReleaseStateReadLock',
    'Get-ProductionReleaseLifecycleContract',
    'Get-ProductionManifestChannelContract',
    'Get-ProductionReleaseManifestPublishingResponseAuthenticationPayload',
    'Get-ProductionReleaseP256PublicKeyIdentity',
    'Get-PeContentSha256',
    'Assert-Rfc3161TimestampTokenBinding',
    'Assert-AuthenticodeSignerRfc3161Timestamp',
    'Assert-PeRfc3161Timestamp',
    'Get-ProductionReleaseSigningResponseAuthenticationPayload',
    'Get-ProductionReleaseState',
    'Get-ProductionReleaseStateSummary',
    'Get-ProductionSha256Bytes',
    'Initialize-ProductionReleaseState',
    'Assert-ProductionReleaseLifecycleSequence',
    'Assert-ProductionReleaseTransitionContract',
    'Open-ProductionReleaseInput',
    'Open-ProductionReleaseDirectoryLease',
    'Open-ProductionReleaseDirectoryMoveLease',
    'Move-ProductionReleaseDirectoryLease',
    'Read-ProductionReleaseInputBytes',
    'Read-StrictProductionJsonFile',
    'Resolve-OrdinaryProductionFile',
    'Write-ProductionStateFile'
)
