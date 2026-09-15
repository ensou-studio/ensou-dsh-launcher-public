[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PublisherExecutablePath,

    [Parameter(Mandatory = $true)]
    [string]$ReadinessConfigPath,

    [Parameter(Mandatory = $true)]
    [string]$ReportPath,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9A-Fa-f]{64}$')]
    [string]$PublisherSignerSha256Thumbprint,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$PublisherExecutableSha256
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($PSVersionTable.PSEdition -ne 'Core' -or $PSVersionTable.PSVersion -lt [version]'7.2') {
    throw 'Enterprise Pilot preflight requires PowerShell 7.2 or newer.'
}
if (-not $IsWindows -or [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -ne
    [Runtime.InteropServices.Architecture]::X64) {
    throw 'Enterprise Pilot preflight requires native Windows x64.'
}

function Resolve-OrdinaryFile {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not [IO.Path]::IsPathFullyQualified($Path)) {
        throw "Pilot preflight path must be absolute: $Path"
    }
    $resolved = [IO.Path]::GetFullPath($Path)
    $item = Get-Item -LiteralPath $resolved -Force
    if ($item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Pilot preflight input must be an ordinary file: $resolved"
    }
    $current = $item.Directory
    while ($null -ne $current) {
        if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Pilot preflight path may not cross a filesystem link: $resolved"
        }
        $current = $current.Parent
    }
    return $resolved
}

function Assert-SafeNewReportPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not [IO.Path]::IsPathFullyQualified($Path)) {
        throw 'Pilot readiness report path must be absolute.'
    }
    $resolved = [IO.Path]::GetFullPath($Path)
    if (Test-Path -LiteralPath $resolved) {
        throw 'Pilot readiness report must be a new create-only file.'
    }
    $current = [IO.DirectoryInfo]::new((Split-Path -Parent $resolved))
    while (-not $current.Exists) {
        $current = $current.Parent
        if ($null -eq $current) {
            throw 'Pilot readiness report has no existing parent directory.'
        }
    }
    while ($null -ne $current) {
        if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Pilot readiness report path may not cross a filesystem link.'
        }
        $current = $current.Parent
    }
    return $resolved
}

function Get-LowerSha256FromLockedStream {
    param([Parameter(Mandatory = $true)][IO.FileStream]$Stream)

    if (-not $Stream.CanRead -or -not $Stream.CanSeek) {
        throw 'Publisher executable lock stream must be readable and seekable.'
    }
    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        $Stream.Position = 0
        $digest = $hasher.ComputeHash($Stream)
        return [Convert]::ToHexString($digest).ToLowerInvariant()
    } finally {
        $Stream.Position = 0
        $hasher.Dispose()
    }
}

$publisher = Resolve-OrdinaryFile $PublisherExecutablePath
$config = Resolve-OrdinaryFile $ReadinessConfigPath
$report = Assert-SafeNewReportPath $ReportPath

$publisherLock = [IO.FileStream]::new(
    $publisher,
    [IO.FileMode]::Open,
    [IO.FileAccess]::Read,
    [IO.FileShare]::Read,
    1MB,
    [IO.FileOptions]::SequentialScan)
try {
$signature = Get-AuthenticodeSignature -LiteralPath $publisher
if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
    -not $signature.SignerCertificate) {
    throw "ReleasePublisher Authenticode signature is not valid: $($signature.Status)"
}
if ([string]$signature.SignatureType -cne 'Authenticode') {
    throw 'ReleasePublisher must carry an embedded Authenticode signature, not a catalog signature.'
}
if ($null -eq $signature.TimeStamperCertificate) {
    throw 'ReleasePublisher Authenticode signature has no trusted timestamp.'
}
$actualSigner = $signature.SignerCertificate.GetCertHashString(
    [Security.Cryptography.HashAlgorithmName]::SHA256)
if ($actualSigner -cne $PublisherSignerSha256Thumbprint.ToUpperInvariant()) {
    throw 'ReleasePublisher Authenticode signer does not match the pinned Pilot signer.'
}
$actualPublisherSha256 = Get-LowerSha256FromLockedStream $publisherLock
if ($actualPublisherSha256 -cne $PublisherExecutableSha256) {
    throw 'ReleasePublisher executable bytes do not match the pinned Pilot SHA-256.'
}

$start = [Diagnostics.ProcessStartInfo]::new()
$start.FileName = $publisher
$start.WorkingDirectory = Split-Path -Parent $publisher
$start.UseShellExecute = $false
$start.CreateNoWindow = $true
$start.RedirectStandardOutput = $true
$start.RedirectStandardError = $true
$systemRoot = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
$temporaryRoot = [IO.Path]::GetTempPath()
$start.Environment.Clear()
$start.Environment['SystemRoot'] = $systemRoot
$start.Environment['WINDIR'] = $systemRoot
$start.Environment['TEMP'] = $temporaryRoot
$start.Environment['TMP'] = $temporaryRoot
$start.Environment['PATH'] = Join-Path $systemRoot 'System32'
$start.Environment['DOTNET_ROOT'] = Join-Path $temporaryRoot 'ensou-no-system-dotnet'
$start.Environment['DOTNET_MULTILEVEL_LOOKUP'] = '0'
$start.Environment['DOTNET_EnableDiagnostics'] = '0'
$start.Environment['COMPlus_EnableDiagnostics'] = '0'
$start.ArgumentList.Add('--pilot-readiness-config')
$start.ArgumentList.Add($config)
$start.ArgumentList.Add('--report-stdout')
$process = [Diagnostics.Process]::Start($start)
if (-not $process) {
    throw 'Enterprise Pilot preflight process did not start.'
}
try {
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit(120000)) {
        $process.Kill($true)
        throw 'Enterprise Pilot preflight exceeded two minutes.'
    }
    $stdout = $stdoutTask.GetAwaiter().GetResult()
    $stderr = $stderrTask.GetAwaiter().GetResult()
    $exitCode = $process.ExitCode
} finally {
    $process.Dispose()
}

if ([string]::IsNullOrWhiteSpace($stdout)) {
    throw 'Enterprise Pilot preflight did not return its machine report.'
}
try {
    $result = $stdout | ConvertFrom-Json -Depth 32
} catch {
    throw 'Enterprise Pilot preflight returned an invalid machine report.'
}
$reportBytes=[Text.UTF8Encoding]::new($false,$true).GetBytes($stdout)
if($reportBytes.Length -le 0 -or $reportBytes.Length -gt 4MB){
    throw 'Enterprise Pilot preflight machine report byte count is invalid.'
}
$reportStream=[IO.FileStream]::new(
    $report,
    [IO.FileMode]::CreateNew,
    [IO.FileAccess]::Write,
    [IO.FileShare]::None,
    64KB,
    [IO.FileOptions]::WriteThrough)
try {
    $reportStream.Write($reportBytes)
    $reportStream.Flush($true)
} finally {
    $reportStream.Dispose()
}
$postRunPublisherSha256 = Get-LowerSha256FromLockedStream $publisherLock
if ($postRunPublisherSha256 -cne $PublisherExecutableSha256) {
    throw 'ReleasePublisher executable bytes changed during Pilot validation.'
}
if ($exitCode -ne 0 -or $result.decision -cne 'ADMIT') {
    throw 'Enterprise Pilot readiness rejected by the signed Publisher.'
}
if ($result.schemaVersion -ne 1 -or
    $result.reportType -cne 'ensou-dsh-enterprise-pilot-readiness' -or
    $result.environment -cne 'production' -or
    $result.channel -cne 'pilot') {
    throw 'Enterprise Pilot readiness report contract is invalid.'
}
if ([string]::IsNullOrWhiteSpace([string]$result.releaseSetId) -or
    [string]$result.publisherExecutableSha256 -cne $PublisherExecutableSha256 -or
    [long]$result.generation -le 0 -or
    [long]$result.sequence -le 0 -or
    [string]::IsNullOrWhiteSpace([string]$result.brandAuthorizationId) -or
    [string]::IsNullOrWhiteSpace([string]$result.brandAuthorizationKeyId) -or
    [string]$result.brandAuthorizationReceiptSha256 -cnotmatch '^[0-9a-f]{64}$' -or
    [DateTimeOffset]$result.brandAuthorizationExpiresAtUtc -le [DateTimeOffset]::UtcNow -or
    [string]$result.localDataCertificationId -cnotmatch
        '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' -or
    [string]$result.localDataCertificationKeyId -cnotmatch
        '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$' -or
    [string]$result.localDataCertificationReceiptSha256 -cnotmatch '^[0-9a-f]{64}$' -or
    [DateTimeOffset]$result.localDataCertificationExpiresAtUtc -le [DateTimeOffset]::UtcNow -or
    $null -ne $result.failureCode -or
    $null -ne $result.failureMessage -or
    @($result.checks).Count -lt 1 -or
    @($result.checks | Where-Object { $_.status -cne 'PASS' }).Count -ne 0) {
    throw 'Enterprise Pilot ADMIT report is incomplete or contains a failed check.'
}

Write-Output $result
} finally {
    $publisherLock.Dispose()
}
