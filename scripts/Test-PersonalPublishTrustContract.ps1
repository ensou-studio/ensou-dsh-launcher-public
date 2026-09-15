[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = [IO.Path]::GetFullPath($RepositoryRoot)
$projects = @(
    [pscustomobject]@{
        Path = 'src\Ensou.Dsh.Bootstrapper\Ensou.Dsh.Bootstrapper.csproj'
        Target = 'ValidatePersonalStartupStubPublish'
        RequiresSingleFileCompression = $true
        AdditionalProperties = @()
    },
    [pscustomobject]@{
        Path = 'src\Ensou.Dsh.ClientBootstrapper\Ensou.Dsh.ClientBootstrapper.csproj'
        Target = 'ValidatePersonalClientBootstrapperPublish'
        RequiresSingleFileCompression = $true
        AdditionalProperties = @()
    },
    [pscustomobject]@{
        Path = 'src\Ensou.Dsh.Launcher\Ensou.Dsh.Launcher.csproj'
        Target = 'ValidatePersonalLauncherPublish'
        RequiresSingleFileCompression = $true
        AdditionalProperties = @()
    },
    [pscustomobject]@{
        Path = 'src\Ensou.Dsh.Personal.Maintenance\Ensou.Dsh.Personal.Maintenance.csproj'
        Target = 'ValidatePersonalMaintenancePublish'
        RequiresSingleFileCompression = $true
        AdditionalProperties = @()
    },
    [pscustomobject]@{
        Path = 'src\Ensou.Dsh.Personal.Installer\Ensou.Dsh.Personal.Installer.csproj'
        Target = 'ValidatePersonalInstallerPublish'
        RequiresSingleFileCompression = $true
        AdditionalProperties = @(
            "-p:PersonalInstallerPayloadDirectory=$root"
        )
    },
    [pscustomobject]@{
        Path = 'src\Ensou.Dsh.UpdateEngine\Ensou.Dsh.UpdateEngine.csproj'
        Target = 'ValidatePersonalUpdateEngineCompiledTrust'
        RequiresSingleFileCompression = $false
        AdditionalProperties = @()
    }
)

$requiredTrustProperties = @(
    'PersonalManifestOrigin',
    'PersonalArtifactOrigin',
    'PersonalChannel',
    'PersonalReleaseKeyId',
    'PersonalReleaseKeyX',
    'PersonalReleaseKeyY',
    'PersonalStartupStubVersion',
    'PersonalCanonicalLowSFromSequence'
)

function Invoke-ContractTarget {
    param(
        [Parameter(Mandatory = $true)]$Project,
        [Parameter(Mandatory = $true)][string[]]$Properties,
        [Parameter(Mandatory = $true)][bool]$ExpectSuccess,
        [string]$ExpectedFailure
    )

    $projectPath = Join-Path $root $Project.Path
    $arguments = @(
        'msbuild',
        $projectPath,
        '-nologo',
        "-t:$($Project.Target)",
        '-p:RuntimeIdentifier=win-x64',
        '-p:SelfContained=true',
        '-p:PublishSingleFile=true'
    ) + $Project.AdditionalProperties + $Properties
    $output = (& dotnet @arguments 2>&1 | Out-String)
    $succeeded = $LASTEXITCODE -eq 0
    if ($succeeded -ne $ExpectSuccess) {
        throw "Personal publish trust target '$($Project.Target)' returned an unexpected exit.`n$output"
    }
    if (-not $ExpectSuccess -and
        -not $output.Contains($ExpectedFailure, [StringComparison]::Ordinal)) {
        throw "Personal publish trust target '$($Project.Target)' did not fail for the expected reason.`n$output"
    }
}

$developmentTrustWithAccountOrigin = @(
    '-p:PersonalDevelopmentPublish=true',
    '-p:PersonalAccountOrigin=https://accounts.example.invalid/'
)
$completeDevelopmentTrust = $developmentTrustWithAccountOrigin + @(
    '-p:PersonalManifestOrigin=https://updates.example.test/',
    '-p:PersonalArtifactOrigin=https://updates.example.test/',
    '-p:PersonalChannel=stable',
    '-p:PersonalReleaseKeyId=personal-contract-test',
    '-p:PersonalReleaseKeyX=AA',
    '-p:PersonalReleaseKeyY=AA',
    '-p:PersonalStartupStubVersion=1.1.0',
    '-p:PersonalCanonicalLowSFromSequence=1'
)
$developmentTrustWithoutAccountOrigin = @(
    $completeDevelopmentTrust | Where-Object {
        -not $_.StartsWith(
            '-p:PersonalAccountOrigin=',
            [StringComparison]::Ordinal)
    })

# Keep the Launcher-only account-origin admission separate from the generic
# compiled trust-fingerprint negatives below, so each test reaches its claim.
$launcherProjects = @($projects | Where-Object {
        $_.Target -ceq 'ValidatePersonalLauncherPublish'
    })
if ($launcherProjects.Count -ne 1) {
    throw 'Personal publish trust contract requires exactly one Launcher target.'
}
Invoke-ContractTarget `
    -Project $launcherProjects[0] `
    -Properties $developmentTrustWithoutAccountOrigin `
    -ExpectSuccess $false `
    -ExpectedFailure 'requires an immutable PersonalAccountOrigin'

foreach ($project in $projects) {
    $projectPath = Join-Path $root $project.Path
    $projectText = Get-Content -Raw -LiteralPath $projectPath
    $target = [regex]::Match(
        $projectText,
        '<Target\s+Name="' + [regex]::Escape($project.Target) + '"[^>]*>.*?</Target>',
        [Text.RegularExpressions.RegexOptions]::Singleline)
    if (-not $target.Success) {
        throw "Personal publish trust target is missing: $projectPath"
    }
    foreach ($property in $requiredTrustProperties) {
        $propertyToken = '$(' + $property + ')'
        if (-not $target.Value.Contains($propertyToken, [StringComparison]::Ordinal)) {
            throw "Personal publish trust target omits $property`: $projectPath"
        }
    }
    foreach ($required in @(
        'complete immutable compiled release trust fingerprint',
        'PersonalAuthenticodeSignerSha256Thumbprint',
        'must select exactly one of production or development mode',
        '^[1-9][0-9]{0,15}$',
        '9007199254740991'
    )) {
        if (-not $target.Value.Contains($required, [StringComparison]::Ordinal)) {
            throw "Personal publish trust target is incomplete: $projectPath ($required)"
        }
    }
    if ($project.RequiresSingleFileCompression) {
        foreach ($requiredProperty in @(
            'EnableCompressionInSingleFile',
            'PublishTrimmed',
            'PublishAot'
        )) {
            $requiredToken = '$(' + $requiredProperty + ')'
            if (-not $target.Value.Contains($requiredToken, [StringComparison]::Ordinal)) {
                throw "Personal executable publish target does not enforce $requiredProperty`: $projectPath"
            }
        }
        foreach ($disabledDefault in @(
            '<PublishTrimmed>false</PublishTrimmed>',
            '<PublishAot>false</PublishAot>'
        )) {
            if (-not $projectText.Contains($disabledDefault, [StringComparison]::Ordinal)) {
                throw "Personal executable project does not explicitly disable unsupported publish modes: $projectPath ($disabledDefault)"
            }
        }
    }

    Invoke-ContractTarget `
        -Project $project `
        -Properties $developmentTrustWithAccountOrigin `
        -ExpectSuccess $false `
        -ExpectedFailure 'complete immutable compiled release trust fingerprint'
    Invoke-ContractTarget `
        -Project $project `
        -Properties $completeDevelopmentTrust `
        -ExpectSuccess $true
    if ($project.RequiresSingleFileCompression) {
        Invoke-ContractTarget `
            -Project $project `
            -Properties ($completeDevelopmentTrust + @('-p:EnableCompressionInSingleFile=false')) `
            -ExpectSuccess $false `
            -ExpectedFailure 'compressed single-file'
        Invoke-ContractTarget `
            -Project $project `
            -Properties ($completeDevelopmentTrust + @('-p:PublishTrimmed=true')) `
            -ExpectSuccess $false `
            -ExpectedFailure 'must not enable trimming'
        Invoke-ContractTarget `
            -Project $project `
            -Properties ($completeDevelopmentTrust + @(
                '-p:PublishTrimmed=false',
                '-p:PublishAot=true'
            )) `
            -ExpectSuccess $false `
            -ExpectedFailure 'must not enable NativeAOT'
    }
}

$installerProgramPath = Join-Path $root 'src\Ensou.Dsh.Personal.Installer\Program.cs'
$installerProgramText = Get-Content -Raw -LiteralPath $installerProgramPath
$preflightCall = $installerProgramText.IndexOf(
    'PersonalInstallPreflight.RequireReady(layout)',
    [StringComparison]::Ordinal)
$payloadConstruction = $installerProgramText.IndexOf(
    'new PersonalEmbeddedInstallerPayloadSource(assembly)',
    $preflightCall + 1,
    [StringComparison]::Ordinal)
$migrationConstruction = $installerProgramText.IndexOf(
    'new PersonalInstallMigrationService(layout)',
    $preflightCall + 1,
    [StringComparison]::Ordinal)
if ($preflightCall -lt 0 -or
    $payloadConstruction -le $preflightCall -or
    $migrationConstruction -le $payloadConstruction) {
    throw 'Personal Installer install entrypoint must complete preflight before payload and migration construction.'
}

foreach ($project in $projects) {
    Invoke-ContractTarget `
        -Project $project `
        -Properties ($completeDevelopmentTrust + @(
            '-p:PersonalProductionBuild=true',
            ('-p:PersonalAuthenticodeSignerSha256Thumbprint=' + ('A' * 64))
        )) `
        -ExpectSuccess $false `
        -ExpectedFailure 'must select exactly one of production or development mode'
    Invoke-ContractTarget `
        -Project $project `
        -Properties (@($completeDevelopmentTrust | Where-Object {
                -not $_.StartsWith(
                    '-p:PersonalCanonicalLowSFromSequence=',
                    [StringComparison]::Ordinal)
            }) + @('-p:PersonalCanonicalLowSFromSequence=0')) `
        -ExpectSuccess $false `
        -ExpectedFailure 'canonical positive decimal integer'
}

Write-Host 'Personal publish trust contract validation passed.'
