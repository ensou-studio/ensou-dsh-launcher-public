[CmdletBinding(DefaultParameterSetName = 'Publish')]
param(
    [Parameter(Mandatory = $true)]
    [string]$TrustPolicyPath,

    [Parameter(Mandatory = $true)]
    [string]$ExpectedProductionTrustSha256,

    [Parameter(Mandatory = $true, ParameterSetName = 'Publish')]
    [string]$OutputDirectory,

    [Parameter(Mandatory = $true, ParameterSetName = 'Publish')]
    [string]$LauncherSourceCommit,

    [Parameter(Mandatory = $true, ParameterSetName = 'ValidateOnly')]
    [switch]$ValidateTrustOnly,

    [string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$BinaryFileName = 'ensou-dsh-enterprise-feed-promoter'
$TrustFileName = 'enterprise-feed-production-trust.json'
$ManifestFileName = 'enterprise-feed-promoter-production-bundle.v1.json'
$SumsFileName = 'SHA256SUMS'
$MaximumTrustBytes = 256KB

if (-not $IsWindows -and -not $IsLinux) {
    throw 'Enterprise FeedPromoter production publishing supports only Windows or Linux build hosts.'
}

if ($IsWindows -and -not ('EnsouFeedPromoterBundle.NativeFileIdentity' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace EnsouFeedPromoterBundle
{
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

        public static string RequireOrdinarySingleLink(SafeFileHandle handle)
        {
            if (handle == null || handle.IsInvalid || handle.IsClosed)
            {
                throw new InvalidDataException("FeedPromoter bundle input handle is invalid.");
            }
            if (!GetFileInformationByHandle(handle, out var information))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "Could not inspect FeedPromoter bundle input identity.");
            }
            const uint directory = 0x10;
            const uint reparsePoint = 0x400;
            if (information.NumberOfLinks != 1
                || (information.FileAttributes & (directory | reparsePoint)) != 0)
            {
                throw new InvalidDataException(
                    "FeedPromoter bundle inputs must be ordinary single-link files.");
            }
            var index = ((ulong)information.FileIndexHigh << 32)
                | information.FileIndexLow;
            return $"{information.VolumeSerialNumber}:{index}:{information.NumberOfLinks}";
        }
    }
}
'@
}

function Assert-OrdinaryDirectoryPath {
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

function Get-LinuxPathIdentity {
    param([Parameter(Mandatory = $true)][string]$Path)

    $identity = @(& stat '--format=%d:%i:%h:%s' '--' $Path)
    if ($LASTEXITCODE -ne 0 -or $identity.Count -ne 1 -or
        $identity[0] -notmatch '^[0-9]+:[0-9]+:1:[0-9]+$') {
        throw 'FeedPromoter bundle inputs must be ordinary single-link files.'
    }
    return [string]$identity[0]
}

function Read-OrdinaryBoundedFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][int64]$MaximumBytes,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if (-not [IO.Path]::IsPathFullyQualified($Path)) {
        throw "$Label path must be absolute."
    }
    $fullPath = [IO.Path]::GetFullPath($Path)
    $item = Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $item.Length -le 0 -or
        $item.Length -gt $MaximumBytes) {
        throw "$Label must be one ordinary non-empty file no larger than $MaximumBytes bytes."
    }
    [void](Assert-OrdinaryDirectoryPath -Path $item.Directory.FullName -Label "$Label parent")

    $beforeIdentity = if ($IsLinux) { Get-LinuxPathIdentity -Path $fullPath } else { $null }
    $stream = [IO.File]::Open(
        $fullPath,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    try {
        $handleIdentity = if ($IsWindows) {
            [EnsouFeedPromoterBundle.NativeFileIdentity]::RequireOrdinarySingleLink(
                $stream.SafeFileHandle)
        }
        else {
            $beforeIdentity
        }
        if ($stream.Length -le 0 -or $stream.Length -gt $MaximumBytes) {
            throw "$Label changed outside its admitted size bound."
        }
        $memory = [IO.MemoryStream]::new()
        try {
            $stream.CopyTo($memory)
            $bytes = $memory.ToArray()
        }
        finally {
            $memory.Dispose()
        }
        if ($bytes.Length -ne $stream.Length) {
            throw "$Label changed while it was read."
        }
    }
    finally {
        $stream.Dispose()
    }

    $afterItem = Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop
    if ($afterItem.PSIsContainer -or
        ($afterItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $afterItem.Length -ne $bytes.Length) {
        throw "$Label identity changed while it was read."
    }
    if ($IsLinux) {
        $afterIdentity = Get-LinuxPathIdentity -Path $fullPath
        if ($afterIdentity -cne $handleIdentity) {
            throw "$Label identity changed while it was read."
        }
    }
    return [pscustomobject]@{
        Path = $fullPath
        Bytes = $bytes
        Sha256 = [Convert]::ToHexStringLower(
            [Security.Cryptography.SHA256]::HashData($bytes))
    }
}

function Assert-NoDuplicateJsonMembers {
    param(
        [Parameter(Mandatory = $true)][Text.Json.JsonElement]$Element,
        [Parameter(Mandatory = $true)][string]$Path
    )

    if ($Element.ValueKind -eq [Text.Json.JsonValueKind]::Object) {
        $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($property in $Element.EnumerateObject()) {
            if (-not $names.Add($property.Name)) {
                throw "Enterprise feed production trust contains duplicate JSON member '$($property.Name)' at $Path."
            }
            Assert-NoDuplicateJsonMembers -Element $property.Value -Path "$Path.$($property.Name)"
        }
    }
    elseif ($Element.ValueKind -eq [Text.Json.JsonValueKind]::Array) {
        $index = 0
        foreach ($value in $Element.EnumerateArray()) {
            Assert-NoDuplicateJsonMembers -Element $value -Path "$Path[$index]"
            $index++
        }
    }
}

function Assert-ExactJsonMembers {
    param(
        [Parameter(Mandatory = $true)][Text.Json.JsonElement]$Element,
        [Parameter(Mandatory = $true)][string[]]$Expected,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ($Element.ValueKind -ne [Text.Json.JsonValueKind]::Object) {
        throw "$Label must be one JSON object."
    }
    $actual = @($Element.EnumerateObject() | ForEach-Object { $_.Name })
    if ($actual.Count -ne $Expected.Count) {
        throw "$Label must contain exactly the production contract members."
    }
    foreach ($name in $Expected) {
        if ($actual -cnotcontains $name) {
            throw "$Label is missing exact member '$name'."
        }
    }
}

function Get-RequiredJsonProperty {
    param(
        [Parameter(Mandatory = $true)][Text.Json.JsonElement]$Element,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][Text.Json.JsonValueKind]$Kind,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $value = [Text.Json.JsonElement]::new()
    if (-not $Element.TryGetProperty($Name, [ref]$value) -or $value.ValueKind -ne $Kind) {
        throw "$Label requires $Kind member '$Name'."
    }
    return $value
}

function Get-CanonicalP256Coordinate {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ($Value -cnotmatch '^[A-Za-z0-9_-]{43}$') {
        throw "$Label must be one canonical 32-byte base64url value."
    }
    try {
        $bytes = [Convert]::FromBase64String(
            $Value.Replace('-', '+').Replace('_', '/') + '=')
    }
    catch {
        throw "$Label must be one canonical 32-byte base64url value."
    }
    if ($bytes.Length -ne 32) {
        throw "$Label must be one canonical 32-byte base64url value."
    }
    $canonical = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    if ($canonical -cne $Value) {
        throw "$Label must be one canonical 32-byte base64url value."
    }
    return $bytes
}

function Assert-ProductionOrigin {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $uri = $null
    if (-not [Uri]::TryCreate($Value, [UriKind]::Absolute, [ref]$uri) -or
        $uri.Scheme -cne 'https' -or
        -not [string]::IsNullOrEmpty($uri.UserInfo) -or
        -not [string]::IsNullOrEmpty($uri.Query) -or
        -not [string]::IsNullOrEmpty($uri.Fragment) -or
        $uri.AbsolutePath -cne '/') {
        throw "$Label must be one canonical HTTPS origin."
    }
    $hostName = $uri.IdnHost.ToLowerInvariant()
    $ipAddress = $null
    if ($uri.IsLoopback -or
        [Net.IPAddress]::TryParse($hostName, [ref]$ipAddress) -or
        -not $hostName.Contains('.') -or
        $hostName -eq 'localhost' -or
        $hostName.EndsWith('.localhost', [StringComparison]::Ordinal) -or
        $hostName.EndsWith('.test', [StringComparison]::Ordinal) -or
        $hostName.EndsWith('.invalid', [StringComparison]::Ordinal) -or
        $hostName.EndsWith('.example', [StringComparison]::Ordinal) -or
        $hostName -in @('example.com', 'example.net', 'example.org') -or
        $hostName.EndsWith('.example.com', [StringComparison]::Ordinal) -or
        $hostName.EndsWith('.example.net', [StringComparison]::Ordinal) -or
        $hostName.EndsWith('.example.org', [StringComparison]::Ordinal) -or
        $hostName.Contains('placeholder', [StringComparison]::OrdinalIgnoreCase) -or
        $hostName.Contains('changeme', [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label must use one non-placeholder production DNS origin."
    }
    return $uri.AbsoluteUri
}

function Read-ProductionKeyRing {
    param(
        [Parameter(Mandatory = $true)][Text.Json.JsonElement]$Element,
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()]
        [Collections.Generic.HashSet[string]]$GlobalKeyIds,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()]
        [Collections.Generic.HashSet[string]]$GlobalPoints
    )

    if ($Element.ValueKind -ne [Text.Json.JsonValueKind]::Array -or
        $Element.GetArrayLength() -lt 1 -or $Element.GetArrayLength() -gt 16) {
        throw "Enterprise $Label key ring must contain between one and sixteen keys."
    }
    $keyIds = [Collections.Generic.List[string]]::new()
    foreach ($key in $Element.EnumerateArray()) {
        Assert-ExactJsonMembers -Element $key -Expected @('keyId', 'x', 'y') -Label "Enterprise $Label key"
        $keyId = (Get-RequiredJsonProperty -Element $key -Name 'keyId' -Kind String -Label "Enterprise $Label key").GetString()
        $x = (Get-RequiredJsonProperty -Element $key -Name 'x' -Kind String -Label "Enterprise $Label key").GetString()
        $y = (Get-RequiredJsonProperty -Element $key -Name 'y' -Kind String -Label "Enterprise $Label key").GetString()
        if ($null -eq $keyId -or $keyId -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$' -or
            $keyId -match '(?i)(^|[-_.])(test|example|placeholder|dummy|sample|fake|changeme|todo|development|e2e|local)([-_.]|$)') {
            throw "Enterprise $Label keyId is invalid or placeholder-like."
        }
        if (-not $GlobalKeyIds.Add($keyId)) {
            throw 'Enterprise production release and certification keyIds must be globally unique.'
        }
        $xBytes = Get-CanonicalP256Coordinate -Value $x -Label "Enterprise $Label public key x"
        $yBytes = Get-CanonicalP256Coordinate -Value $y -Label "Enterprise $Label public key y"
        $pointIdentity = "$x.$y"
        if (-not $GlobalPoints.Add($pointIdentity)) {
            throw 'Enterprise production release and certification P-256 points must be globally unique.'
        }
        $parameters = [Security.Cryptography.ECParameters]::new()
        $parameters.Curve = [Security.Cryptography.ECCurve+NamedCurves]::nistP256
        $point = [Security.Cryptography.ECPoint]::new()
        $point.X = $xBytes
        $point.Y = $yBytes
        $parameters.Q = $point
        try {
            $validator = [Security.Cryptography.ECDsa]::Create($parameters)
            $validator.Dispose()
        }
        catch {
            throw "Enterprise $Label public key is not one valid P-256 point."
        }
        $keyIds.Add($keyId)
    }
    return ,$keyIds.ToArray()
}

function Assert-EnterpriseFeedProductionTrust {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    if ($Bytes.Length -le 0 -or $Bytes.Length -gt $MaximumTrustBytes -or
        ($Bytes.Length -ge 3 -and $Bytes[0] -eq 0xEF -and $Bytes[1] -eq 0xBB -and $Bytes[2] -eq 0xBF)) {
        throw 'Enterprise feed production trust must be non-empty UTF-8 without a BOM and within 256 KiB.'
    }
    if ([Array]::IndexOf($Bytes, [byte]0x0D) -ge 0) {
        throw 'Enterprise feed production trust text must use canonical LF line endings without CR bytes.'
    }
    $utf8 = [Text.UTF8Encoding]::new($false, $true)
    try {
        $text = $utf8.GetString($Bytes)
        $document = [Text.Json.JsonDocument]::Parse(
            $text,
            [Text.Json.JsonDocumentOptions]@{
                AllowTrailingCommas = $false
                CommentHandling = [Text.Json.JsonCommentHandling]::Disallow
                MaxDepth = 32
            })
    }
    catch {
        throw 'Enterprise feed production trust must be strict UTF-8 JSON.'
    }
    try {
        $root = $document.RootElement
        Assert-NoDuplicateJsonMembers -Element $root -Path '$'
        Assert-ExactJsonMembers -Element $root -Expected @(
            'schemaVersion',
            'product',
            'environment',
            'manifestOrigin',
            'artifactOrigin',
            'releaseKeys',
            'certificationKeys',
            'allowedClockSkewSeconds',
            'maximumOfflineGraceHours'
        ) -Label 'Enterprise feed production trust'

        $schemaVersion = (Get-RequiredJsonProperty -Element $root -Name 'schemaVersion' -Kind Number -Label 'Enterprise feed production trust').GetInt32()
        $product = (Get-RequiredJsonProperty -Element $root -Name 'product' -Kind String -Label 'Enterprise feed production trust').GetString()
        $environment = (Get-RequiredJsonProperty -Element $root -Name 'environment' -Kind String -Label 'Enterprise feed production trust').GetString()
        $manifestOriginText = (Get-RequiredJsonProperty -Element $root -Name 'manifestOrigin' -Kind String -Label 'Enterprise feed production trust').GetString()
        $artifactOriginText = (Get-RequiredJsonProperty -Element $root -Name 'artifactOrigin' -Kind String -Label 'Enterprise feed production trust').GetString()
        $allowedClockSkewSeconds = (Get-RequiredJsonProperty -Element $root -Name 'allowedClockSkewSeconds' -Kind Number -Label 'Enterprise feed production trust').GetInt32()
        $maximumOfflineGraceHours = (Get-RequiredJsonProperty -Element $root -Name 'maximumOfflineGraceHours' -Kind Number -Label 'Enterprise feed production trust').GetInt32()
        if ($schemaVersion -ne 1 -or $product -cne 'ensou-dsh-enterprise' -or
            $environment -cne 'production' -or
            $allowedClockSkewSeconds -lt 0 -or $allowedClockSkewSeconds -gt 600 -or
            $maximumOfflineGraceHours -lt 1 -or $maximumOfflineGraceHours -gt 336) {
            throw 'Enterprise feed production trust identity or time policy is invalid.'
        }
        $manifestOrigin = Assert-ProductionOrigin -Value $manifestOriginText -Label 'Enterprise manifestOrigin'
        $artifactOrigin = Assert-ProductionOrigin -Value $artifactOriginText -Label 'Enterprise artifactOrigin'
        $globalKeyIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $globalPoints = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        $releaseKeyIds = Read-ProductionKeyRing `
            -Element (Get-RequiredJsonProperty -Element $root -Name 'releaseKeys' -Kind Array -Label 'Enterprise feed production trust') `
            -Label 'release' `
            -GlobalKeyIds $globalKeyIds `
            -GlobalPoints $globalPoints
        $certificationKeyIds = Read-ProductionKeyRing `
            -Element (Get-RequiredJsonProperty -Element $root -Name 'certificationKeys' -Kind Array -Label 'Enterprise feed production trust') `
            -Label 'certification' `
            -GlobalKeyIds $globalKeyIds `
            -GlobalPoints $globalPoints
        return [pscustomobject]@{
            ManifestOrigin = $manifestOrigin
            ArtifactOrigin = $artifactOrigin
            ReleaseKeyIds = @($releaseKeyIds)
            CertificationKeyIds = @($certificationKeyIds)
        }
    }
    finally {
        $document.Dispose()
    }
}

function Write-NewFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][byte[]]$Bytes
    )

    $stream = [IO.File]::Open(
        $Path,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None)
    try {
        $stream.Write($Bytes)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
}

function Get-FileSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)

    $stream = [IO.File]::OpenRead($Path)
    try {
        return [Convert]::ToHexStringLower(
            [Security.Cryptography.SHA256]::HashData($stream))
    }
    finally {
        $stream.Dispose()
    }
}

function Remove-OwnedDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedParent,
        [Parameter(Mandatory = $true)][string]$ExpectedPrefix
    )

    $fullPath = [IO.Path]::GetFullPath($Path)
    $parent = [IO.Path]::TrimEndingDirectorySeparator(
        [IO.Path]::GetFullPath($ExpectedParent))
    if ([IO.Path]::GetDirectoryName($fullPath) -cne $parent -or
        -not [IO.Path]::GetFileName($fullPath).StartsWith($ExpectedPrefix, [StringComparison]::Ordinal)) {
        throw "Refusing to remove an unexpected publisher directory: $fullPath"
    }
    if ([IO.Directory]::Exists($fullPath)) {
        [IO.Directory]::Delete($fullPath, $true)
    }
}

$trustInput = Read-OrdinaryBoundedFile `
    -Path $TrustPolicyPath `
    -MaximumBytes $MaximumTrustBytes `
    -Label 'Enterprise feed production trust'
if ($ExpectedProductionTrustSha256 -cnotmatch '^[0-9a-f]{64}$') {
    throw 'ExpectedProductionTrustSha256 must be one explicit lowercase SHA-256.'
}
if ($trustInput.Sha256 -cne $ExpectedProductionTrustSha256) {
    throw 'Enterprise feed production trust does not match the explicitly approved SHA-256.'
}
$trustIdentity = Assert-EnterpriseFeedProductionTrust -Bytes $trustInput.Bytes

if ($ValidateTrustOnly) {
    Write-Output (
        'ENTERPRISE-FEED-PRODUCTION-TRUST-PASS sha256={0} releaseKeys={1} certificationKeys={2}' -f
        $trustInput.Sha256,
        @($trustIdentity.ReleaseKeyIds).Count,
        @($trustIdentity.CertificationKeyIds).Count)
    return
}

if ($LauncherSourceCommit -cnotmatch '^[0-9a-f]{40}$') {
    throw 'LauncherSourceCommit must be one lowercase 40-character Git commit.'
}
$repository = Assert-OrdinaryDirectoryPath -Path $RepositoryRoot -Label 'Launcher repository root'
$outputFullPath = [IO.Path]::GetFullPath($OutputDirectory)
$outputParent = [IO.Path]::GetDirectoryName($outputFullPath)
if ([string]::IsNullOrWhiteSpace($outputParent)) {
    throw 'FeedPromoter bundle output must have one existing parent directory.'
}
$outputParent = Assert-OrdinaryDirectoryPath -Path $outputParent -Label 'FeedPromoter bundle output parent'
if ([IO.Directory]::Exists($outputFullPath) -or [IO.File]::Exists($outputFullPath)) {
    throw 'FeedPromoter production bundle output is create-only and must not already exist.'
}

$resolvedCommit = @(& git -C $repository rev-parse --verify "${LauncherSourceCommit}^{commit}" 2>&1)
if ($LASTEXITCODE -ne 0 -or $resolvedCommit.Count -ne 1 -or
    $resolvedCommit[0] -cne $LauncherSourceCommit) {
    throw 'LauncherSourceCommit did not resolve to the exact requested commit.'
}

$temporaryParent = [IO.Path]::TrimEndingDirectorySeparator(
    [IO.Path]::GetFullPath([IO.Path]::GetTempPath()))
$buildRoot = Join-Path $temporaryParent ('ensou-feed-promoter-build-' + [guid]::NewGuid().ToString('N'))
$stagingRoot = Join-Path $outputParent ('.feed-promoter-bundle-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($buildRoot) | Out-Null
[IO.Directory]::CreateDirectory($stagingRoot) | Out-Null
try {
    $sourceArchive = Join-Path $buildRoot 'source.tar'
    $sourceRoot = Join-Path $buildRoot 'source'
    $publishRoot = Join-Path $buildRoot 'publish'
    [IO.Directory]::CreateDirectory($sourceRoot) | Out-Null
    [IO.Directory]::CreateDirectory($publishRoot) | Out-Null
    & git -C $repository archive --format=tar "--output=$sourceArchive" $LauncherSourceCommit
    if ($LASTEXITCODE -ne 0 -or -not [IO.File]::Exists($sourceArchive)) {
        throw 'Could not materialize the exact Launcher source commit.'
    }
    & tar -xf $sourceArchive -C $sourceRoot
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not extract the exact Launcher source archive.'
    }
    foreach ($entry in @(Get-ChildItem -LiteralPath $sourceRoot -Force -Recurse)) {
        if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'The exact Launcher source archive contains a filesystem link.'
        }
    }

    Push-Location $sourceRoot
    try {
        $sdkVersion = @(& dotnet --version)
        if ($LASTEXITCODE -ne 0 -or $sdkVersion.Count -ne 1 -or
            $sdkVersion[0] -cnotmatch '^[0-9]+\.[0-9]+\.[0-9]+$') {
            throw 'Could not resolve one exact .NET SDK version from Launcher global.json.'
        }
        $globalJson = Get-Content -Raw -LiteralPath (Join-Path $sourceRoot 'global.json') |
            ConvertFrom-Json -Depth 8
        if ([string]$globalJson.sdk.version -cne [string]$sdkVersion[0]) {
            throw 'The active .NET SDK does not equal Launcher global.json.'
        }
        $projectPath = Join-Path $sourceRoot `
            'src/Ensou.Dsh.Enterprise.FeedPromoter/Ensou.Dsh.Enterprise.FeedPromoter.csproj'
        $publishLog = @(& dotnet publish $projectPath `
            --configuration Release `
            -p:EnterpriseFeedPromoterProductionBuild=true `
            -p:DebugSymbols=false `
            -p:DebugType=None `
            --output $publishRoot 2>&1)
        if ($LASTEXITCODE -ne 0) {
            $diagnostic = @($publishLog | Select-Object -Last 40) -join [Environment]::NewLine
            throw "Enterprise FeedPromoter linux-x64 publish failed.$([Environment]::NewLine)$diagnostic"
        }
    }
    finally {
        Pop-Location
    }

    $published = @(Get-ChildItem -LiteralPath $publishRoot -Force)
    if ($published.Count -ne 1 -or $published[0].PSIsContainer -or
        ($published[0].Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $published[0].Name -cne 'Ensou.Dsh.Enterprise.FeedPromoter') {
        throw 'Enterprise FeedPromoter publish must contain exactly one ordinary single-file executable.'
    }
    $binaryBytes = [IO.File]::ReadAllBytes($published[0].FullName)
    if ($binaryBytes.Length -le 64 -or
        $binaryBytes[0] -ne 0x7F -or $binaryBytes[1] -ne 0x45 -or
        $binaryBytes[2] -ne 0x4C -or $binaryBytes[3] -ne 0x46 -or
        $binaryBytes[4] -ne 2 -or $binaryBytes[5] -ne 1 -or
        $binaryBytes[16] -ne 3 -or $binaryBytes[17] -ne 0 -or
        $binaryBytes[18] -ne 0x3E -or $binaryBytes[19] -ne 0) {
        throw 'Enterprise FeedPromoter output must be one ELF64 little-endian x86-64 PIE executable.'
    }

    $binaryPath = Join-Path $stagingRoot $BinaryFileName
    $trustPath = Join-Path $stagingRoot $TrustFileName
    Write-NewFile -Path $binaryPath -Bytes $binaryBytes
    Write-NewFile -Path $trustPath -Bytes $trustInput.Bytes
    if ($IsLinux) {
        & chmod 0755 $binaryPath
        if ($LASTEXITCODE -ne 0) {
            throw 'Could not set the FeedPromoter bundle executable mode.'
        }
    }
    $binarySha256 = Get-FileSha256 -Path $binaryPath
    $trustSha256 = Get-FileSha256 -Path $trustPath
    if ($trustSha256 -cne $trustInput.Sha256) {
        throw 'Enterprise production trust bytes changed while the bundle was created.'
    }

    $manifest = [ordered]@{
        schemaVersion = 1
        bundleType = 'ensou-dsh-enterprise-feed-promoter-production-bundle-v1'
        product = 'ensou-dsh-enterprise'
        environment = 'production'
        runtimeIdentifier = 'linux-x64'
        selfContained = $true
        singleFile = $true
        sourceCommit = $LauncherSourceCommit
        dotnetSdkVersion = [string]$sdkVersion[0]
        manifestOrigin = $trustIdentity.ManifestOrigin
        artifactOrigin = $trustIdentity.ArtifactOrigin
        releaseKeyIds = @($trustIdentity.ReleaseKeyIds)
        certificationKeyIds = @($trustIdentity.CertificationKeyIds)
        files = @(
            [ordered]@{
                role = 'feed-promoter'
                fileName = $BinaryFileName
                sizeBytes = [int64]$binaryBytes.Length
                sha256 = $binarySha256
            },
            [ordered]@{
                role = 'production-trust'
                fileName = $TrustFileName
                sizeBytes = [int64]$trustInput.Bytes.Length
                sha256 = $trustSha256
            }
        )
    }
    $manifestText = ($manifest | ConvertTo-Json -Depth 12).Replace("`r`n", "`n").Replace("`r", "`n") + "`n"
    $manifestBytes = [Text.UTF8Encoding]::new($false).GetBytes($manifestText)
    $manifestPath = Join-Path $stagingRoot $ManifestFileName
    Write-NewFile -Path $manifestPath -Bytes $manifestBytes
    $schemaPath = Join-Path $repository `
        'release/schemas/enterprise-feed-promoter-production-bundle-v1.schema.json'
    if (-not (Test-Json -Json $manifestText -SchemaFile $schemaPath -ErrorAction Stop)) {
        throw 'Enterprise FeedPromoter production bundle manifest failed its strict schema.'
    }
    $manifestSha256 = Get-FileSha256 -Path $manifestPath
    $sumsText = @(
        "$binarySha256  $BinaryFileName"
        "$trustSha256  $TrustFileName"
        "$manifestSha256  $ManifestFileName"
    ) -join "`n"
    $sumsText += "`n"
    Write-NewFile `
        -Path (Join-Path $stagingRoot $SumsFileName) `
        -Bytes ([Text.UTF8Encoding]::new($false).GetBytes($sumsText))

    $inventory = @(Get-ChildItem -LiteralPath $stagingRoot -Force | Sort-Object Name)
    $expectedNames = @(
        $SumsFileName,
        $TrustFileName,
        $ManifestFileName,
        $BinaryFileName
    ) | Sort-Object
    if ($inventory.Count -ne 4 -or
        (Compare-Object -ReferenceObject $expectedNames -DifferenceObject @($inventory.Name) -CaseSensitive)) {
        throw 'Enterprise FeedPromoter production bundle inventory is not exact.'
    }
    foreach ($entry in $inventory) {
        if ($entry.PSIsContainer -or
            ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Enterprise FeedPromoter production bundle contains a non-ordinary entry.'
        }
    }

    [IO.Directory]::Move($stagingRoot, $outputFullPath)
    Write-Output (
        'ENTERPRISE-FEED-PROMOTER-PRODUCTION-BUNDLE-PASS path={0} binarySha256={1} trustSha256={2} manifestSha256={3}' -f
        $outputFullPath,
        $binarySha256,
        $trustSha256,
        $manifestSha256)
}
finally {
    Remove-OwnedDirectory -Path $buildRoot -ExpectedParent $temporaryParent -ExpectedPrefix 'ensou-feed-promoter-build-'
    if ([IO.Directory]::Exists($stagingRoot)) {
        Remove-OwnedDirectory -Path $stagingRoot -ExpectedParent $outputParent -ExpectedPrefix '.feed-promoter-bundle-'
    }
}
