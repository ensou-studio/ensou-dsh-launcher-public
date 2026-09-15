#requires -Version 7.2
[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$expectedProjects = [ordered]@{
    'src/Ensou.Dsh.Enterprise.Installer/Ensou.Dsh.Enterprise.Installer.csproj' = 1
    'src/Ensou.Dsh.Personal.Installer/Ensou.Dsh.Personal.Installer.csproj' = 2
    'src/Ensou.Dsh.Bootstrapper/Ensou.Dsh.Bootstrapper.csproj' = 2
    'src/Ensou.Dsh.ClientBootstrapper/Ensou.Dsh.ClientBootstrapper.csproj' = 2
    'src/Ensou.Dsh.Launcher/Ensou.Dsh.Launcher.csproj' = 3
    'src/Ensou.Dsh.Personal.Maintenance/Ensou.Dsh.Personal.Maintenance.csproj' = 1
    'src/Ensou.Dsh.Enterprise.Bootstrapper/Ensou.Dsh.Enterprise.Bootstrapper.csproj' = 1
    'src/Ensou.Dsh.Enterprise.ClientBootstrapper/Ensou.Dsh.Enterprise.ClientBootstrapper.csproj' = 1
    'src/Ensou.Dsh.Enterprise.Launcher/Ensou.Dsh.Enterprise.Launcher.csproj' = 4
    'src/Ensou.Dsh.Enterprise.Maintenance/Ensou.Dsh.Enterprise.Maintenance.csproj' = 1
}
$expectedIsolation = 'RuntimeIdentifier;SelfContained;PublishSingleFile'
$referenceCount = 0

foreach ($entry in $expectedProjects.GetEnumerator()) {
    $projectPath = Join-Path $RepositoryRoot $entry.Key.Replace(
        '/', [IO.Path]::DirectorySeparatorChar)
    if (-not [IO.File]::Exists($projectPath)) {
        throw "Publish-isolation project is missing: $($entry.Key)"
    }

    [xml]$project = [IO.File]::ReadAllText($projectPath)
    foreach ($property in @(
        @{ Name = 'RuntimeIdentifier'; Value = 'win-x64' },
        @{ Name = 'SelfContained'; Value = 'true' },
        @{ Name = 'PublishSingleFile'; Value = 'true' })) {
        $nodes = @($project.SelectNodes("/Project/PropertyGroup/$($property.Name)"))
        if ($nodes.Count -eq 0 -or
            -not ($nodes | Where-Object { $_.InnerText -ceq $property.Value })) {
            throw "$($entry.Key) does not locally pin $($property.Name)=$($property.Value)."
        }
    }

    $references = @($project.SelectNodes('/Project/ItemGroup/ProjectReference'))
    if ($references.Count -ne [int]$entry.Value) {
        throw "$($entry.Key) has $($references.Count) ProjectReferences; expected $($entry.Value)."
    }
    foreach ($reference in $references) {
        if ([string]$reference.GlobalPropertiesToRemove -cne $expectedIsolation) {
            throw "$($entry.Key) ProjectReference '$($reference.Include)' propagates executable publish properties."
        }
        $referenceCount++
    }
}

if ($referenceCount -ne 18) {
    throw "Publish-isolation contract checked $referenceCount references; expected 18."
}

Write-Output 'EXECUTABLE-PROJECT-REFERENCE-PUBLISH-ISOLATION-PASS'
