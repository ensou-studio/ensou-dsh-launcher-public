[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ClientBootstrapperPublishDirectory
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$publishRoot = [IO.Path]::GetFullPath($ClientBootstrapperPublishDirectory)
$publishItem = Get-Item -LiteralPath $publishRoot -Force
if (-not $publishItem.PSIsContainer -or
    ($publishItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "Enterprise ClientBootstrapper publish root is not an ordinary directory: $publishRoot"
}
$executable = Join-Path `
    $publishRoot `
    'Ensou.Dsh.Enterprise.ClientBootstrapper.exe'
if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
    throw "Enterprise ClientBootstrapper published executable is missing: $executable"
}
$forbidden = Get-ChildItem -LiteralPath $publishRoot -Recurse -Force |
    Where-Object {
        -not $_.PSIsContainer -and (
            $_.Extension -ieq '.dll' -or
            $_.Name -like '*.deps.json' -or
            $_.Name -like '*.runtimeconfig.json')
    } |
    Select-Object -First 1
if ($forbidden) {
    throw "Enterprise ClientBootstrapper publish has a framework sidecar: $($forbidden.FullName)"
}
$profilePath = Join-Path $publishRoot 'enterprise-build-profile.json'
$profile = Get-Content -LiteralPath $profilePath -Raw | ConvertFrom-Json
if ($profile.schemaVersion -ne 1 -or
    $profile.layoutProfile -cne 'development-e2e') {
    throw "Enterprise ClientBootstrapper CI profile marker is invalid: $profilePath"
}

function New-ProbeStartInfo {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $FilePath
    $start.WorkingDirectory = Split-Path -Parent $FilePath
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.WindowStyle = [Diagnostics.ProcessWindowStyle]::Hidden
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.Environment['PATH'] = Join-Path $env:SystemRoot 'System32'
    $start.Environment['DOTNET_ROOT'] =
        Join-Path $env:TEMP 'ensou-enterprise-ci-no-dotnet'
    $start.Environment['DOTNET_ROOT_X64'] =
        Join-Path $env:TEMP 'ensou-enterprise-ci-no-dotnet-x64'
    $start.Environment['DOTNET_MULTILEVEL_LOOKUP'] = '0'
    foreach ($name in @(
        'ENSOU_DSH_ENTERPRISE_ALLOW_DEVELOPMENT_BOOTSTRAPPER',
        'ENSOU_DSH_E2E_LOCAL_APP_DATA_ROOT',
        'ENSOU_DSH_E2E_USER_PROFILE_ROOT',
        'ENSOU_DSH_E2E_ISOLATION_ID')) {
        [void]$start.Environment.Remove($name)
    }
    foreach ($argument in $Arguments) {
        [void]$start.ArgumentList.Add($argument)
    }
    return $start
}

function Invoke-Probe {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][int]$ExpectedExitCode,
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$ExpectedStderr
    )

    $process = [Diagnostics.Process]::new()
    $process.StartInfo = New-ProbeStartInfo `
        -FilePath $FilePath `
        -Arguments $Arguments
    try {
        if (-not $process.Start()) {
            throw "Enterprise ClientBootstrapper CI probe did not start: $Name"
        }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(30000)) {
            $process.Kill($true)
            if (-not $process.WaitForExit(5000)) {
                throw "Enterprise ClientBootstrapper CI probe could not be terminated: $Name"
            }
            throw "Enterprise ClientBootstrapper CI probe blocked on UI: $Name"
        }
        $process.WaitForExit()
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        if ($stdout.Length -gt 32768 -or $stderr.Length -gt 32768 -or
            $process.ExitCode -ne $ExpectedExitCode -or
            -not [string]::IsNullOrEmpty($stdout) -or
            $stderr.TrimEnd([char[]]@("`r", "`n")) -cne $ExpectedStderr) {
            throw "Enterprise ClientBootstrapper CI probe violated its process contract: $Name"
        }
    }
    finally {
        $process.Dispose()
    }
}

Invoke-Probe `
    -Name 'binary-self-check' `
    -FilePath $executable `
    -Arguments @('--binary-self-check') `
    -ExpectedExitCode 0 `
    -ExpectedStderr ''

$expectedFailure =
    'Ensou DSH Enterprise ClientBootstrapper machine command failed.'
$token = 'A' * 43
$negativeCases = @(
    [pscustomobject]@{
        Name = 'health-missing-token'
        Arguments = @('--release-health-token')
    },
    [pscustomobject]@{
        Name = 'health-extra-argument'
        Arguments = @('--release-health-token', $token, 'extra')
    },
    [pscustomobject]@{
        Name = 'binary-extra-argument'
        Arguments = @('--binary-self-check', 'extra')
    },
    [pscustomobject]@{
        Name = 'installation-extra-argument'
        Arguments = @('--installation-self-check', 'extra')
    }
)
foreach ($negativeCase in $negativeCases) {
    Invoke-Probe `
        -Name $negativeCase.Name `
        -FilePath $executable `
        -Arguments @($negativeCase.Arguments) `
        -ExpectedExitCode 1 `
        -ExpectedStderr $expectedFailure
}

Write-Host 'Enterprise ClientBootstrapper published machine-command gate passed.'
