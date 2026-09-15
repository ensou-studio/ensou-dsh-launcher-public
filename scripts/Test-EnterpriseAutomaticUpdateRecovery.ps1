[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ [System.IO.Path]::IsPathFullyQualified($_) })]
    [string]$LauncherAssemblyPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$assemblyPath = [System.IO.Path]::GetFullPath($LauncherAssemblyPath)
if (-not [System.IO.File]::Exists($assemblyPath)) {
    throw "Launcher assembly does not exist: $assemblyPath"
}

$assemblyDirectory = [System.IO.Path]::GetDirectoryName($assemblyPath)
foreach ($dependency in @(
    'Ensou.Dsh.Contracts.dll',
    'Ensou.Dsh.Enterprise.Contracts.dll',
    'Ensou.Dsh.Enterprise.ReleaseContracts.dll',
    'Ensou.Dsh.Host.dll',
    'Ensou.Dsh.Enterprise.Installation.dll',
    'Ensou.Dsh.Enterprise.Client.dll'
)) {
    $dependencyPath = [System.IO.Path]::Combine($assemblyDirectory, $dependency)
    if (-not [System.IO.File]::Exists($dependencyPath)) {
        throw "Launcher dependency does not exist: $dependencyPath"
    }
    [void][System.Runtime.Loader.AssemblyLoadContext]::Default.LoadFromAssemblyPath($dependencyPath)
}
$assembly = [System.Runtime.Loader.AssemblyLoadContext]::Default.LoadFromAssemblyPath($assemblyPath)
$mainWindow = $assembly.GetType('Ensou.Dsh.Enterprise.Launcher.MainWindow', $true)
$flags = [System.Reflection.BindingFlags]::Static -bor [System.Reflection.BindingFlags]::NonPublic
$recovery = $mainWindow.GetMethod('IsVerifiedAutomaticAuthenticationRecovery', $flags)
$pipeline = $mainWindow.GetMethod('ToAutomaticUpdatePipelineResult', $flags)
if ($null -eq $recovery -or $null -eq $pipeline) {
    throw 'The automatic authentication recovery policy methods are missing.'
}

$clientStateType = $recovery.GetParameters()[3].ParameterType
$dispositionType = $pipeline.GetParameters()[0].ParameterType

function Invoke-RecoveryPolicy {
    param(
        [bool]$HasBinding,
        [bool]$RefreshCompleted,
        [bool]$DecisionMatches,
        [string]$State
    )

    $stateValue = [System.Enum]::Parse($clientStateType, $State, $false)
    return [bool]$recovery.Invoke($null, @($HasBinding, $RefreshCompleted, $DecisionMatches, $stateValue))
}

foreach ($state in @('Ready', 'UpdateRequired')) {
    if (-not (Invoke-RecoveryPolicy $true $true $true $state)) {
        throw "Verified $state refresh did not recover the automatic authentication gate."
    }
}
foreach ($case in @(
    @($false, $true, $true, 'Ready'),
    @($true, $false, $true, 'Ready'),
    @($true, $true, $false, 'Ready'),
    @($true, $true, $true, 'QrRequired'),
    @($true, $true, $true, 'AccountLocked')
)) {
    if (Invoke-RecoveryPolicy @case) {
        throw "An unverified refresh incorrectly recovered the automatic authentication gate: $case"
    }
}

$expectedPipelineResults = @{
    NotEligible = 'Success'
    Completed = 'Success'
    Restarting = 'Success'
    SessionLocked = 'Failure'
    ContinueVerifiedStable = 'Failure'
    UpdateRemainsLocked = 'Failure'
    RequiresExclusiveStage = 'Failure'
}
foreach ($entry in $expectedPipelineResults.GetEnumerator()) {
    $disposition = [System.Enum]::Parse($dispositionType, $entry.Key, $false)
    $actual = $pipeline.Invoke($null, @($disposition)).ToString()
    if ($actual -cne $entry.Value) {
        throw "Disposition $($entry.Key) mapped to $actual instead of $($entry.Value)."
    }
}

Write-Output 'PASS enterprise automatic authentication recovery policy'
