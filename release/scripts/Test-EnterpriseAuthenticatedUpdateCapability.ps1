#requires -Version 7.2

[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [string]$LauncherPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($LauncherPath)) {
    $LauncherPath = Join-Path $RepositoryRoot `
        'src\Ensou.Dsh.Enterprise.Launcher\bin\Release\net10.0-windows\win-x64\Ensou.Dsh.Enterprise.Launcher.exe'
}
$LauncherPath = [IO.Path]::GetFullPath($LauncherPath)
if (-not [IO.File]::Exists($LauncherPath)) {
    throw "Enterprise Launcher capability test requires a built Launcher: $LauncherPath"
}

$command = '--authenticated-stable-update-capability-self-check'
$failure = 'Ensou DSH Enterprise authenticated update capability probe failed.'
$expected = '{"schemaVersion":1,"probeType":"ensou-dsh-enterprise-authenticated-stable-update-capability-v1","edition":"Enterprise","channel":"stable","manifestPath":"/v2/channels/stable/release-set.v2.json","freshAuthorizationRequired":true,"admittedClientStates":["Ready","UpdateRequired"],"transportContract":"authenticated-dpop-transaction-v1","transactionClientLifetime":"single-check","unauthorizedBehavior":"clear-token-lock-session","forbiddenReadyBehavior":"continue-verified-stable","forbiddenUpdateRequiredBehavior":"remain-locked","bootstrapHealthBehavior":"restart-through-stable-bootstrapper","sideEffectContract":"no-secrets-no-network-no-mutation"}'
$expectedBytes = [Text.Encoding]::UTF8.GetBytes($expected)
$expectedSha256 =
    [Convert]::ToHexStringLower([Security.Cryptography.SHA256]::HashData($expectedBytes))
if ($expectedBytes.Length -ne 651 -or
    $expectedSha256 -cne
        '5216e34e0a76cc1c20a8d23dd24ea69a2186c58c3044c20b5f912a4e13bcf005') {
    throw 'Capability test vector identity is inconsistent.'
}

function Invoke-CapabilityProbe([Parameter(Mandatory = $true)][string[]]$Arguments) {
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $LauncherPath
    $start.WorkingDirectory = [IO.Path]::GetDirectoryName($LauncherPath)
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.WindowStyle = [Diagnostics.ProcessWindowStyle]::Hidden
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in $Arguments) {
        $null = $start.ArgumentList.Add($argument)
    }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    $stdout = [IO.MemoryStream]::new()
    $stderr = [IO.MemoryStream]::new()
    try {
        if (-not $process.Start()) {
            throw 'Enterprise Launcher capability probe did not start.'
        }
        $stdoutTask = $process.StandardOutput.BaseStream.CopyToAsync($stdout)
        $stderrTask = $process.StandardError.BaseStream.CopyToAsync($stderr)
        if (-not $process.WaitForExit(15000)) {
            $process.Kill($true)
            throw 'Enterprise Launcher capability probe exceeded 15 seconds.'
        }
        $null = $stdoutTask.GetAwaiter().GetResult()
        $null = $stderrTask.GetAwaiter().GetResult()
        $result = [pscustomobject]@{
            ExitCode = $process.ExitCode
            StandardOutputBytes = $stdout.ToArray()
            StandardErrorBytes = $stderr.ToArray()
        }
        return $result
    }
    finally {
        $stdout.Dispose()
        $stderr.Dispose()
        $process.Dispose()
    }
}

$strictUtf8 = [Text.UTF8Encoding]::new($false, $true)
$exact = Invoke-CapabilityProbe @($command)
$exactOutput = $strictUtf8.GetString($exact.StandardOutputBytes)
if ($exact.ExitCode -ne 0 -or
    $exact.StandardOutputBytes.Length -ne $expectedBytes.Length -or
    [Convert]::ToHexStringLower(
        [Security.Cryptography.SHA256]::HashData($exact.StandardOutputBytes)) -cne
        $expectedSha256 -or
    $exactOutput -cne $expected -or
    $exact.StandardErrorBytes.Length -ne 0) {
    throw 'Exact Enterprise authenticated update capability command failed.'
}

$extra = Invoke-CapabilityProbe @($command, 'unexpected')
$extraError = $strictUtf8.GetString($extra.StandardErrorBytes)
if ($extra.ExitCode -eq 0 -or
    $extra.StandardOutputBytes.Length -ne 0 -or
    $extraError -cne $failure -or
    $extra.StandardErrorBytes.Length -gt 256) {
    throw 'Enterprise authenticated update capability command accepted extra arguments.'
}

Write-Output 'ENTERPRISE-AUTHENTICATED-UPDATE-CAPABILITY-PASS'
