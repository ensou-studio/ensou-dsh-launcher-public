#requires -Version 7.4
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$LauncherAssemblyPath,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$ExpectedLauncherAssemblySha256,
    [Parameter(Mandatory)][string]$InstallationAssemblyPath,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$ExpectedInstallationAssemblySha256,
    [Parameter(Mandatory)][string]$AttemptRoot
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-OrdinaryChain([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force
    while ($null -ne $item) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Linked test input is not admitted.' }
        $item = if ($item -is [IO.DirectoryInfo]) { $item.Parent } else { $item.Directory }
    }
}
function Assert-Pin([string]$Path, [string]$Sha256) {
    Assert-OrdinaryChain $Path
    if ((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Sha256) {
        throw 'Pinned compiled test input differs.'
    }
}
foreach ($path in @($LauncherAssemblyPath, $InstallationAssemblyPath, $AttemptRoot)) {
    if (![IO.Path]::IsPathFullyQualified($path) -or $path.StartsWith('\\') -or
        [IO.Path]::GetFullPath($path) -cne $path) { throw 'Test paths must be absolute canonical local paths.' }
}
Assert-Pin $LauncherAssemblyPath $ExpectedLauncherAssemblySha256
Assert-Pin $InstallationAssemblyPath $ExpectedInstallationAssemblySha256
$parent = [IO.Path]::GetDirectoryName($AttemptRoot)
Assert-OrdinaryChain $parent
if (Test-Path -LiteralPath $AttemptRoot) { throw 'Preserve the existing test attempt.' }
$started = [DateTimeOffset]::Now
[IO.Directory]::CreateDirectory($AttemptRoot) | Out-Null
$local = Join-Path $AttemptRoot 'local'
$profile = Join-Path $AttemptRoot 'profile'
[IO.Directory]::CreateDirectory($local) | Out-Null
[IO.Directory]::CreateDirectory($profile) | Out-Null
$installationAssembly = [Reflection.Assembly]::LoadFrom($InstallationAssemblyPath)
$launcherAssembly = [Reflection.Assembly]::LoadFrom($LauncherAssemblyPath)
$layoutType = $installationAssembly.GetType('Ensou.Dsh.Enterprise.Installation.EnterpriseInstallationLayout', $true)
$layout = $layoutType.GetMethod('CreateDevelopmentE2E', [type[]]@([string], [string])).Invoke($null, [object[]]@([string]$local, [string]$profile))
$diagnosticType = $launcherAssembly.GetType('Ensou.Dsh.Enterprise.Launcher.EnterpriseDevelopmentRestartDiagnostics', $true)
$method = $diagnosticType.GetMethod('ValidateReceiptPath', [Reflection.BindingFlags]'Static,NonPublic')
if ($null -eq $method) { throw 'Exact DevelopmentE2E receipt validator is missing.' }
$cases = [Collections.Generic.List[object]]::new()
function Check-Path([string]$Name, [string]$Path, [bool]$ShouldAccept) {
    $accepted = $false
    $failureType = $null
    try {
        $actual = $method.Invoke($null, @($Path, $layout))
        $accepted = $actual -ceq $Path
    } catch {
        $failureType = $_.Exception.GetBaseException().GetType().Name
        if ($failureType -notin @('InvalidDataException', 'IOException')) { throw }
    }
    $cases.Add([ordered]@{name=$Name;passed=($accepted -eq $ShouldAccept);accepted=$accepted;failureType=$failureType})
}

Check-Path 'direct-child-receipt' (Join-Path $local 'receipt.json') $true
Check-Path 'nested-receipt' (Join-Path $local 'observations/receipt.json') $true
Check-Path 'outside-root' (Join-Path $profile 'receipt.json') $false
Check-Path 'root-is-not-a-file-target' $local $false
$existingFile = Join-Path $local 'existing.json'
$stream = [IO.File]::Open($existingFile, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
$stream.Dispose()
Check-Path 'existing-file' $existingFile $false
$existingDirectory = Join-Path $local 'existing-directory'
[IO.Directory]::CreateDirectory($existingDirectory) | Out-Null
Check-Path 'existing-directory' $existingDirectory $false
Assert-Pin $LauncherAssemblyPath $ExpectedLauncherAssemblySha256
Assert-Pin $InstallationAssemblyPath $ExpectedInstallationAssemblySha256
$ended = [DateTimeOffset]::Now
$passed = @($cases | Where-Object { !$_.passed }).Count -eq 0
$result = [ordered]@{
    status = if ($passed) { 'PASS' } else { 'FAIL' }
    scope = 'EXACT_COMPILED_DEVELOPMENT_RECEIPT_PATH_ONLY_NO_APP_OR_RUNTIME'
    startedAtJst = $started.ToString('o')
    finishedAtJst = $ended.ToString('o')
    elapsedSeconds = ($ended - $started).TotalSeconds
    launcherAssemblySha256 = $ExpectedLauncherAssemblySha256
    installationAssemblySha256 = $ExpectedInstallationAssemblySha256
    checks = $cases.ToArray()
    inputsUnchanged = $true
    existingEvidenceOverwritten = $false
    processesStarted = 0
    dockerCreated = $false
}
$json = $result | ConvertTo-Json -Depth 6
$receipt = [IO.File]::Open((Join-Path $AttemptRoot 'RESULT.json'), [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
try { $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json); $receipt.Write($bytes); $receipt.Flush($true) } finally { $receipt.Dispose() }
$json
if (!$passed) { throw 'Compiled Enterprise receipt path regression failed.' }
