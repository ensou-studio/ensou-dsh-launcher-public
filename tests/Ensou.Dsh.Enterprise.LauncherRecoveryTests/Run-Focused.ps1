[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ResultRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$resultRoot = [System.IO.Path]::GetFullPath($ResultRoot)
if ([System.IO.Directory]::Exists($resultRoot)) {
    throw "ResultRoot must be fresh: $resultRoot"
}
[System.IO.Directory]::CreateDirectory($resultRoot) | Out-Null

$repositoryRoot = [System.IO.Path]::GetFullPath(
    [System.IO.Path]::Combine($PSScriptRoot, '..', '..'))
$binaryRoot = [System.IO.Path]::Combine(
    $PSScriptRoot, 'bin', 'Debug', 'net10.0-windows', 'win-x64')
$executable = [System.IO.Path]::Combine(
    $binaryRoot, 'Ensou.Dsh.Enterprise.LauncherRecoveryTests.exe')
if (-not [System.IO.File]::Exists($executable)) {
    throw "Focused test executable does not exist: $executable"
}
$sources = @(
    'src/Ensou.Dsh.Enterprise.Launcher/MainWindow.AutomaticUpdates.cs',
    'src/Ensou.Dsh.Enterprise.Launcher/MainWindow.xaml.cs',
    'tests/Ensou.Dsh.Enterprise.LauncherRecoveryTests/Program.cs',
    'tests/Ensou.Dsh.Enterprise.LauncherRecoveryTests/Ensou.Dsh.Enterprise.LauncherRecoveryTests.csproj',
    'tests/Ensou.Dsh.Enterprise.LauncherRecoveryTests/Run-Focused.ps1'
)
function Get-Pins([string[]]$RelativePaths) {
    return @($RelativePaths | ForEach-Object {
    $path = [System.IO.Path]::Combine($repositoryRoot, $_)
    $item = [System.IO.FileInfo]::new($path)
    [ordered]@{
        path = $_
        bytes = $item.Length
        sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    })
}

$sourcePinsBefore = Get-Pins $sources
$runtimeFiles = @(
    Get-ChildItem -LiteralPath $binaryRoot -File | Where-Object {
        $_.Name -like 'Ensou*.dll' -or
        $_.Name -ceq 'Ensou.Dsh.Enterprise.LauncherRecoveryTests.exe' -or
        $_.Name -ceq 'Ensou.Dsh.Enterprise.LauncherRecoveryTests.deps.json' -or
        $_.Name -ceq 'Ensou.Dsh.Enterprise.LauncherRecoveryTests.runtimeconfig.json'
    } | Sort-Object -Property Name
)
if ($runtimeFiles.Count -lt 4 -or
    -not ($runtimeFiles.Name -ccontains 'Ensou.Dsh.Enterprise.Launcher.dll') -or
    -not ($runtimeFiles.Name -ccontains 'Ensou.Dsh.Enterprise.LauncherRecoveryTests.dll')) {
    throw 'Focused test runtime closure is incomplete.'
}
$runtimePins = @($runtimeFiles | ForEach-Object {
    [ordered]@{
        path = $_.FullName
        bytes = $_.Length
        sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    }
})

$startedAtUtc = [DateTimeOffset]::UtcNow
$exitCode = -1
$failure = $null
$process = $null
$stdoutPath = [System.IO.Path]::Combine($resultRoot, 'stdout.log')
$stderrPath = [System.IO.Path]::Combine($resultRoot, 'stderr.log')
try {
    $process = Start-Process -FilePath $executable -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
    if (-not $process.WaitForExit(30000)) {
        throw 'Focused test exceeded the 30 second timeout.'
    }
    # Refresh the exited Process object before reading its native exit status.
    # Do not infer success from captured stdout; a missing status is a runner failure.
    $process.Refresh()
    if (-not $process.HasExited) {
        throw 'Focused test reported completion without an exited process.'
    }
    $nativeExitCode = $process.ExitCode
    if ($null -eq $nativeExitCode) {
        throw 'Focused test exited without a readable native exit code.'
    }
    $exitCode = [int]$nativeExitCode
}
catch {
    $failure = $_.Exception.GetType().Name + ': ' + $_.Exception.Message
}
finally {
    if ($null -ne $process -and -not $process.HasExited) {
        $process.Kill($true)
        [void]$process.WaitForExit(5000)
    }
    $completedAtUtc = [DateTimeOffset]::UtcNow
    $sourcePinsAfter = Get-Pins $sources
    $sourceUnchanged = (ConvertTo-Json $sourcePinsBefore -Depth 4 -Compress) -ceq
        (ConvertTo-Json $sourcePinsAfter -Depth 4 -Compress)
    if (-not $sourceUnchanged -and $null -eq $failure) {
        $failure = 'Source pins changed while the focused test was running.'
    }
    $result = [ordered]@{
        schemaVersion = 1
        documentType = 'ensou.dsh.launcher-recovery-focused-test.v1'
        startedAtUtc = $startedAtUtc.ToString('O')
        completedAtUtc = $completedAtUtc.ToString('O')
        timeoutSeconds = 30
        exitCode = $exitCode
        status = if ($exitCode -eq 0 -and $null -eq $failure) { 'PASS' } else { 'FAIL' }
        failure = $failure
        sourcePinsBefore = $sourcePinsBefore
        sourcePinsAfter = $sourcePinsAfter
        sourcePinsUnchanged = $sourceUnchanged
        runtimePins = $runtimePins
    }
    [System.IO.File]::WriteAllText(
        [System.IO.Path]::Combine($resultRoot, 'RESULT.json'),
        ($result | ConvertTo-Json -Depth 6), [System.Text.UTF8Encoding]::new($false))
}
if ([System.IO.File]::Exists($stdoutPath)) { Get-Content -LiteralPath $stdoutPath }
if ([System.IO.File]::Exists($stderrPath)) { Get-Content -LiteralPath $stderrPath | Write-Error }
if ($null -ne $failure) { Write-Error $failure }
exit $exitCode
