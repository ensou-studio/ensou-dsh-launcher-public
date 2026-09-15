#requires -Version 7.2

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = Join-Path $PSScriptRoot 'ProductionBoundedProcess.psm1'
Microsoft.PowerShell.Core\Import-Module $modulePath -Force -ErrorAction Stop

function New-TestProcessStartInfo {
    param(
        [Parameter(Mandatory = $true)][string]$Command
    )

    $pwsh = (Get-Command pwsh -ErrorAction Stop).Source
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $pwsh
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.WindowStyle = [Diagnostics.ProcessWindowStyle]::Hidden
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.Environment.Clear()
    foreach ($name in @('SystemRoot', 'WINDIR', 'TEMP', 'TMP', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA')) {
        $value = [Environment]::GetEnvironmentVariable($name)
        if (-not [string]::IsNullOrWhiteSpace($value)) { $startInfo.Environment[$name] = $value }
    }
    $startInfo.Environment['DOTNET_NOLOGO'] = '1'
    $startInfo.Environment['POWERSHELL_TELEMETRY_OPTOUT'] = '1'
    $startInfo.ArgumentList.Add('-NoLogo')
    $startInfo.ArgumentList.Add('-NoProfile')
    $startInfo.ArgumentList.Add('-NonInteractive')
    $startInfo.ArgumentList.Add('-Command')
    $startInfo.ArgumentList.Add($Command)
    return $startInfo
}

function Invoke-TestCapture {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $true)][int]$TimeoutMilliseconds,
        [int]$MaximumOutputBytes = 4096
    )

    $startInfo = New-TestProcessStartInfo $Command
    return Invoke-ProductionBoundedProcessCapture `
        -StartInfo $startInfo `
        -TimeoutMilliseconds $TimeoutMilliseconds `
        -MaximumOutputBytes $MaximumOutputBytes
}

function Assert-Test {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition
    )

    if (-not $Condition) {
        throw [InvalidOperationException]::new('Bounded process assertion failed.')
    }
}

function Assert-Bytes {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Actual,
        [Parameter(Mandatory = $true)][byte[]]$Expected
    )

    Assert-Test ($Actual.Length -eq $Expected.Length)
    for ($index = 0; $index -lt $Actual.Length; $index++) {
        Assert-Test ($Actual[$index] -eq $Expected[$index])
    }
}

function Test-RawOutput {
    $capture = Invoke-TestCapture `
        -Command '$o=[Console]::OpenStandardOutput();$e=[Console]::OpenStandardError();try{$a=[byte[]](239,187,191,65,0,255);$b=[byte[]](69,82,82,0,254);$o.Write($a,0,$a.Length);$e.Write($b,0,$b.Length)}finally{$o.Dispose();$e.Dispose()}' `
        -TimeoutMilliseconds 5000
    Assert-Test (-not $capture.TimedOut)
    Assert-Test ($capture.ExitCode -eq 0)
    Assert-Bytes $capture.StandardOutput.Bytes ([byte[]](239,187,191,65,0,255))
    Assert-Bytes $capture.StandardError.Bytes ([byte[]](69,82,82,0,254))
}

function Test-StreamOverflow([bool]$StandardError) {
    $streamName = if ($StandardError) { 'OpenStandardError' } else { 'OpenStandardOutput' }
    $command = '$stream=[Console]::' + $streamName + '();$bytes=[byte[]]::new(128);try{$stream.Write($bytes,0,$bytes.Length)}finally{$stream.Dispose()}'
    $capture = Invoke-TestCapture `
        -Command $command `
        -TimeoutMilliseconds 5000 `
        -MaximumOutputBytes 64
    Assert-Test (-not $capture.TimedOut)
    # Overflow deliberately kills the child; a zero exit cannot be required.
    $buffer = if ($StandardError) { $capture.StandardError } else { $capture.StandardOutput }
    Assert-Test $buffer.Overflowed
    Assert-Test ($buffer.Bytes.Length -eq 64)
}

function Test-NonZeroExit {
    $capture = Invoke-TestCapture `
        -Command '[Environment]::Exit(17)' `
        -TimeoutMilliseconds 5000
    Assert-Test (-not $capture.TimedOut)
    Assert-Test ($capture.ExitCode -eq 17)
}

function Test-TimeoutContainsChild {
    $started = [Diagnostics.Stopwatch]::StartNew()
    $capture = Invoke-TestCapture `
        -Command 'Start-Sleep -Seconds 30' `
        -TimeoutMilliseconds 250
    $started.Stop()
    Assert-Test $capture.TimedOut
    Assert-Test ($started.Elapsed -lt [TimeSpan]::FromSeconds(12))
}

function Test-CaptureSourceClosure {
    # The production import must stay pinned, including in both isolated fixtures.
    foreach ($contract in @(
            @{ File = 'Invoke-LauncherProductionRelease.ps1'; Variable = 'relativePaths' },
            @{ File = 'Test-LauncherProductionReleaseOrchestration.ps1'; Variable = 'trackedFiles' },
            @{ File = 'Test-LauncherStablePromotionOrchestration.ps1'; Variable = 'trackedFiles' })) {
        $tokens = $null
        $errors = $null
        $ast = [Management.Automation.Language.Parser]::ParseFile(
            (Join-Path $PSScriptRoot $contract.File), [ref]$tokens, [ref]$errors)
        Assert-Test ($errors.Count -eq 0)
        $assignments = @($ast.FindAll({ param($node)
                $node -is [Management.Automation.Language.AssignmentStatementAst] -and
                $node.Left -is [Management.Automation.Language.VariableExpressionAst] -and
                $node.Left.VariablePath.UserPath -ceq $contract.Variable
            }, $true))
        Assert-Test ($assignments.Count -eq 1)
        $paths = @($assignments[0].Right.FindAll({ param($node)
                $node -is [Management.Automation.Language.StringConstantExpressionAst]
            }, $true) | ForEach-Object { $_.Value })
        Assert-Test ($paths -ccontains 'release/scripts/ProductionBoundedProcess.psm1')
    }
}

$tests = [ordered]@{
    'raw stdout and stderr bytes' = { Test-RawOutput }
    'stdout overflow is bounded' = { Test-StreamOverflow $false }
    'stderr overflow is bounded' = { Test-StreamOverflow $true }
    'nonzero exit is preserved' = { Test-NonZeroExit }
    'timeout terminates the owned child' = { Test-TimeoutContainsChild }
    'capture source is pinned and included in isolated fixtures' = { Test-CaptureSourceClosure }
}

$failures = 0
foreach ($test in $tests.GetEnumerator()) {
    try {
        & $test.Value
        Write-Output "PASS bounded-process $($test.Key)"
    }
    catch {
        $failures++
        Write-Output "FAIL bounded-process $($test.Key): $($_.Exception.GetType().Name)"
    }
}

Write-Output "BOUNDED PROCESS RESULT $($tests.Count - $failures)/$($tests.Count) passed"
if ($failures -ne 0) {
    exit 1
}
