#requires -Version 7.2
[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [Parameter(Mandatory = $true)][string]$EvidenceRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$utf8 = [Text.UTF8Encoding]::new($false)
$startedAt = [DateTimeOffset]::Now
$assertions = 0
$status = 'FAIL'
$sourcePath = ''
$childExitCode = $null
$childHasSgr = $null
$root = [IO.Path]::GetFullPath($EvidenceRoot)
if (Test-Path -LiteralPath $root) {
    throw 'Diagnostic evidence root must be create-only.'
}
[IO.Directory]::CreateDirectory($root) | Out-Null

function Assert-True {
    param([Parameter(Mandatory = $true)][bool]$Condition,
          [Parameter(Mandatory = $true)][string]$Message)
    $script:assertions++
    if (-not $Condition) { throw $Message }
}

try {
    $sourcePath = Join-Path $RepositoryRoot `
        'release\scripts\Test-LauncherProductionReleaseOrchestration.ps1'
    $tokens = $null
    $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile(
        $sourcePath, [ref]$tokens, [ref]$errors)
    Assert-True ($errors.Count -eq 0) 'Actual orchestration test source did not parse.'
    $helper = @($ast.FindAll({
                param($node)
                $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -ceq 'ConvertTo-OrchestrationDiagnosticText'
            }, $true))
    Assert-True ($helper.Count -eq 1) 'Expected exactly one actual diagnostic helper AST.'
    $helperText = [string]$helper[0].Extent.Text
    . ([scriptblock]::Create($helperText))

    function ConvertTo-OldDiagnosticText {
        param([Parameter(Mandatory = $true)][string]$Text)
        $withoutContinuationMarkers = [regex]::Replace(
            $Text, '(?m)^[\p{Zs}\t]*\|[\p{Zs}\t]?', '')
        return [regex]::Replace($withoutContinuationMarkers, '\s+', ' ').Trim()
    }

    $expected = 'NO-GO: Enterprise Stable promotion can only prepare the authenticated r9 offline bundle from exact r8 Pilot evidence.'
    $plainWrapped = "NO-GO: Enterprise Stable promotion can only prepare the authenticated r9`n| offline bundle from exact r8 Pilot evidence."
    Assert-True ((ConvertTo-OrchestrationDiagnosticText -Text $plainWrapped) -ceq $expected) 'Plain LF continuation did not normalize.'
    Assert-True ((ConvertTo-OrchestrationDiagnosticText -Text ($plainWrapped -replace "`n", "`r`n")) -ceq $expected) 'CRLF continuation did not normalize.'

    $sgrWrapped = "`e[91mNO-GO: Enterprise Stable promotion can only prepare the authenticated r9`e[0m`n`e[38;5;214m| offline bundle from exact r8 Pilot evidence.`e[0m"
    Assert-True ((ConvertTo-OldDiagnosticText -Text $sgrWrapped) -cne $expected) 'Old continuation normalizer unexpectedly joined SGR-prefixed marker.'
    Assert-True ((ConvertTo-OrchestrationDiagnosticText -Text $sgrWrapped) -ceq $expected) 'SGR-prefixed continuation did not normalize.'

    $styledWrapped = "`e[1;31mNO-GO: Enterprise Stable promotion can only prepare the authenticated r9`e[0m`r`n`e[38:2::1:2:3m| offline bundle from exact r8 Pilot evidence.`e[0m"
    Assert-True ((ConvertTo-OrchestrationDiagnosticText -Text $styledWrapped) -ceq $expected) 'Colon-style SGR continuation did not normalize.'
    $literalPipe = "warning: value A | B is literal`n| $expected"
    Assert-True ((ConvertTo-OrchestrationDiagnosticText -Text $literalPipe) -ceq ('warning: value A | B is literal ' + $expected)) 'Literal embedded pipe was altered.'
    $differentError = 'NO-GO: Enterprise Stable promotion requires committed r8 Pilot evidence.'
    Assert-True (-not (ConvertTo-OrchestrationDiagnosticText -Text $differentError).Contains($expected, [StringComparison]::OrdinalIgnoreCase)) 'Different Enterprise NO-GO matched the expected diagnostic.'

    $childPath = Join-Path $root 'throw-enterprise-no-go.ps1'
    [IO.File]::WriteAllText($childPath, @"
Write-Warning 'diagnostic-child-warning'
throw '$expected'
"@, $utf8)
    $pwsh = [string]@(Get-Command pwsh -CommandType Application -ErrorAction Stop |
            Select-Object -First 1).Source
    $child = [Diagnostics.Process]::new()
    $child.StartInfo = [Diagnostics.ProcessStartInfo]::new($pwsh)
    $child.StartInfo.UseShellExecute = $false
    $child.StartInfo.CreateNoWindow = $true
    $child.StartInfo.WindowStyle = 'Hidden'
    $child.StartInfo.RedirectStandardOutput = $true
    $child.StartInfo.RedirectStandardError = $true
    foreach ($argument in @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $childPath)) {
        $child.StartInfo.ArgumentList.Add($argument)
    }
    $childStarted = $false
    try {
        $childStarted = $child.Start()
        if (-not $childStarted) { throw 'Diagnostic child did not start.' }
        $stdoutTask = $child.StandardOutput.ReadToEndAsync()
        $stderrTask = $child.StandardError.ReadToEndAsync()
        if (-not $child.WaitForExit(15000)) { throw 'Diagnostic child exceeded its 15-second bound.' }
        if (-not $stdoutTask.Wait(3000) -or -not $stderrTask.Wait(3000)) { throw 'Diagnostic child output did not drain.' }
        $childExitCode = $child.ExitCode
        $childFormattedOutput = $stdoutTask.Result + $stderrTask.Result
    }
    finally {
        if ($childStarted -and -not $child.HasExited) {
            $child.Kill($true)
            if (-not $child.WaitForExit(5000)) { throw 'Diagnostic child cleanup was not confirmed.' }
        }
        $child.Dispose()
    }
    Assert-True ($childExitCode -ne 0) 'Bounded child did not throw its Enterprise NO-GO.'
    [IO.File]::WriteAllText((Join-Path $root 'child-formatted-output.log'), $childFormattedOutput, $utf8)
    Assert-True ((ConvertTo-OrchestrationDiagnosticText -Text $childFormattedOutput).Contains($expected, [StringComparison]::OrdinalIgnoreCase)) 'Actual helper did not match the bounded child Enterprise NO-GO.'
    $childHasSgr = $childFormattedOutput.Contains([char]27 + '[', [StringComparison]::Ordinal)
    if ($childHasSgr) {
        Assert-True (-not (ConvertTo-OrchestrationDiagnosticText -Text $childFormattedOutput).Contains([char]27, [StringComparison]::Ordinal)) 'Actual helper retained child SGR display bytes.'
    }

    foreach ($name in @('Invoke-Orchestrator', 'Copy-State', 'Assert-StateFailure')) {
        $definitions = @($ast.FindAll({ param($node)
                $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -ceq $name
            }, $true))
        Assert-True ($definitions.Count -eq 1) "Expected one actual timing helper '$name'."
        . ([scriptblock]::Create($definitions[0].Extent.Text))
    }
    $script:AssertionCount = 0
    $script:ExpectedFailureCount = 0
    $successPath = Join-Path $root 'orchestrator-success-fixture.ps1'
    $failurePath = Join-Path $root 'orchestrator-failure-fixture.ps1'
    $fixtureParameters = 'param($RepositoryRoot,$Edition,$Phase,$PlanPath,$StateRoot)'
    [IO.File]::WriteAllText($successPath, $fixtureParameters + "`nWrite-Output 'fixture-result'`nexit 0`n", $utf8)
    [IO.File]::WriteAllText($failurePath, $fixtureParameters + "`nWrite-Output 'fixture-expected-failure'`nexit 9`n", $utf8)
    $successRecords = @(Invoke-Orchestrator -ScriptPath $successPath -RepoRoot $root `
        -Edition Personal -Phase Status -PlanPath 'fixture-plan' -StateRoot 'fixture-state' 6>&1)
    $information = @($successRecords | Where-Object { $_ -is [Management.Automation.InformationRecord] })
    $values = @($successRecords | Where-Object { $_ -isnot [Management.Automation.InformationRecord] })
    Assert-True ($information.Count -eq 2 -and
        [string]$information[0] -ceq 'ORCHESTRATOR-START Personal/Status' -and
        [string]$information[1] -match '^ORCHESTRATOR-END Personal/Status exit=0 elapsedMs=[0-9]+$') `
        'Actual invocation helper lost its ordered elapsed-time information records.'
    Assert-True ($values.Count -eq 1 -and $values[0].ExitCode -eq 0 -and
        ($values[0].Output -join '') -ceq 'fixture-result') `
        'Timing diagnostics contaminated the invocation return value.'
    $failureRecords = @(Invoke-Orchestrator -ScriptPath $failurePath -RepoRoot $root `
        -Edition Personal -Phase Status -PlanPath 'fixture-plan' -StateRoot 'fixture-state' `
        -ExpectFailure -ExpectedMessage 'fixture-expected-failure' 6>&1)
    $failureInformation = @($failureRecords | Where-Object { $_ -is [Management.Automation.InformationRecord] })
    $failureValues = @($failureRecords | Where-Object { $_ -isnot [Management.Automation.InformationRecord] })
    Assert-True ($failureInformation.Count -eq 2 -and
        [string]$failureInformation[1] -match 'exit=9 elapsedMs=[0-9]+$' -and
        $failureValues.Count -eq 1 -and $failureValues[0].ExitCode -eq 9 -and
        $global:LASTEXITCODE -eq 0) 'Expected failure lost its exit/diagnostic contract.'

    $copySource = Join-Path $root 'copy-source'
    $copyDestination = Join-Path $root 'copy-destination'
    [void][IO.Directory]::CreateDirectory($copySource)
    [IO.File]::WriteAllText((Join-Path $copySource 'sample.txt'), 'unchanged fixture bytes', $utf8)
    $copyRecords = @(Copy-State -Source $copySource -Destination $copyDestination 6>&1)
    Assert-True ($copyRecords.Count -eq 2 -and
        [string]$copyRecords[0] -ceq 'STATE-COPY-START copy-destination' -and
        [string]$copyRecords[1] -match '^STATE-COPY-END copy-destination elapsedMs=[0-9]+$') `
        'Copy-state timing records are missing or leak success-stream values.'
    Assert-True ([IO.File]::ReadAllText((Join-Path $copyDestination 'sample.txt')) -ceq 'unchanged fixture bytes') `
        'Copy-state timing changed copied content.'
    $negativeRecords = @(Assert-StateFailure -Label 'timing-fixture' -SourceState $copySource `
        -ScriptPath $failurePath -RepoRoot $root -PlanPath 'fixture-plan' `
        -VariantRoot (Join-Path $root 'negative-variant') -Mutate { param($path) } 6>&1)
    $negativeInformation = @($negativeRecords | Where-Object { $_ -is [Management.Automation.InformationRecord] })
    $negativeValues = @($negativeRecords | Where-Object { $_ -isnot [Management.Automation.InformationRecord] })
    Assert-True ($negativeInformation.Count -eq 6 -and
        [string]$negativeInformation[0] -ceq 'NEGATIVE-START timing-fixture' -and
        [string]$negativeInformation[-1] -match '^NEGATIVE-END timing-fixture elapsedMs=[0-9]+$' -and
        $negativeValues.Count -eq 1 -and $negativeValues[0] -ceq 'NEGATIVE-PASS timing-fixture') `
        'State-negative timing changed existing success output or lost its scope markers.'
    $status = 'PASS'
    $global:LASTEXITCODE = 0
    Write-Output "ORCHESTRATION-DIAGNOSTIC-ASSERTIONS=$assertions CHILD-SGR=$childHasSgr"
}
finally {
    $finishedAt = [DateTimeOffset]::Now
    [IO.File]::WriteAllText((Join-Path $root 'RESULT.json'), ([ordered]@{
                schemaVersion = 1
                status = $status
                startedAt = $startedAt.ToString('o')
                finishedAt = $finishedAt.ToString('o')
                elapsedSeconds = ($finishedAt - $startedAt).TotalSeconds
                assertions = $assertions
                sourceSha256 = if (Test-Path -LiteralPath $sourcePath -PathType Leaf) { (Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash } else { $null }
                testSha256 = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash
                childExitCode = if ($null -eq $childExitCode) { $null } else { $childExitCode }
                childHadSgr = if ($null -eq $childHasSgr) { $null } else { $childHasSgr }
            } | ConvertTo-Json -Depth 8), $utf8)
}
