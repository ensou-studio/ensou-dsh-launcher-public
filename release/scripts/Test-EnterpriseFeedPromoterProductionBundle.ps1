[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [switch]$TrustOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$publisher = Join-Path $PSScriptRoot 'Publish-EnterpriseFeedPromoterProductionBundle.ps1'
$schema = Join-Path $RepositoryRoot `
    'release/schemas/enterprise-feed-promoter-production-bundle-v1.schema.json'
$assertions = 0
$expectedFailures = 0

function Assert-True {
    param(
        [Parameter(Mandatory = $true)][bool]$Value,
        [Parameter(Mandatory = $true)][string]$Message
    )

    $script:assertions++
    if (-not $Value) {
        throw $Message
    }
}

function Assert-ExpectedFailure {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Action,
        [Parameter(Mandatory = $true)][string]$Token,
        [Parameter(Mandatory = $true)][string]$Label
    )

    try {
        & $Action
    }
    catch {
        if (-not $_.Exception.Message.Contains($Token, [StringComparison]::Ordinal)) {
            throw "$Label failed with an unexpected contract: $($_.Exception.Message)"
        }
        $global:LASTEXITCODE = 0
        $script:expectedFailures++
        return
    }
    throw "$Label was not rejected."
}

function Get-PublicKeyObject {
    param(
        [Parameter(Mandatory = $true)][string]$KeyId,
        [Parameter(Mandatory = $true)][Security.Cryptography.ECDsa]$Signer
    )

    $parameters = $Signer.ExportParameters($false)
    return [ordered]@{
        keyId = $KeyId
        x = [Convert]::ToBase64String($parameters.Q.X).TrimEnd('=').Replace('+', '-').Replace('/', '_')
        y = [Convert]::ToBase64String($parameters.Q.Y).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    }
}

function Copy-JsonObject {
    param([Parameter(Mandatory = $true)][object]$Value)

    return ($Value | ConvertTo-Json -Depth 16 | ConvertFrom-Json -Depth 16 -AsHashtable)
}

function Write-TrustDocument {
    param(
        [Parameter(Mandatory = $true)][object]$Value,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $text = ($Value | ConvertTo-Json -Depth 16).Replace("`r`n", "`n").Replace("`r", "`n") + "`n"
    [IO.File]::WriteAllText($Path, $text, [Text.UTF8Encoding]::new($false))
}

function Invoke-TrustValidation {
    param([Parameter(Mandatory = $true)][string]$Path)

    return @(& $publisher `
        -TrustPolicyPath $Path `
        -ExpectedProductionTrustSha256 (Get-FileSha256 -Path $Path) `
        -ValidateTrustOnly)
}

function Get-FileSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)

    return [Convert]::ToHexStringLower(
        [Security.Cryptography.SHA256]::HashData([IO.File]::ReadAllBytes($Path)))
}

$temporaryParent = [IO.Path]::TrimEndingDirectorySeparator(
    [IO.Path]::GetFullPath([IO.Path]::GetTempPath()))
$root = Join-Path $temporaryParent ('ensou-feed-promoter-bundle-test-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($root) | Out-Null
$releaseSigner = [Security.Cryptography.ECDsa]::Create(
    [Security.Cryptography.ECCurve+NamedCurves]::nistP256)
$certificationSigner = [Security.Cryptography.ECDsa]::Create(
    [Security.Cryptography.ECCurve+NamedCurves]::nistP256)
try {
    $validTrust = [ordered]@{
        schemaVersion = 1
        product = 'ensou-dsh-enterprise'
        environment = 'production'
        manifestOrigin = 'https://updates.contract.ensoulabs.com/'
        artifactOrigin = 'https://artifacts.contract.ensoulabs.com/'
        releaseKeys = @(
            Get-PublicKeyObject -KeyId 'release-2026-01' -Signer $releaseSigner
        )
        certificationKeys = @(
            Get-PublicKeyObject -KeyId 'certification-2026-01' -Signer $certificationSigner
        )
        allowedClockSkewSeconds = 120
        maximumOfflineGraceHours = 168
    }
    $trustPath = Join-Path $root 'production-trust.json'
    Write-TrustDocument -Value $validTrust -Path $trustPath
    $validTrustBytes = [IO.File]::ReadAllBytes($trustPath)
    $validTrustSha256 = [Convert]::ToHexStringLower(
        [Security.Cryptography.SHA256]::HashData($validTrustBytes))
    $validationOutput = @(Invoke-TrustValidation -Path $trustPath)
    Assert-True `
        -Value ($validationOutput.Count -eq 1 -and
            $validationOutput[0] -ceq (
                "ENTERPRISE-FEED-PRODUCTION-TRUST-PASS sha256=$validTrustSha256 releaseKeys=1 certificationKeys=1")) `
        -Message 'Valid production trust did not return the exact machine result.'

    Assert-ExpectedFailure `
        -Action {
            & $publisher `
                -TrustPolicyPath $trustPath `
                -ExpectedProductionTrustSha256 ('0' * 64) `
                -ValidateTrustOnly | Out-Null
        } `
        -Token 'explicitly approved SHA-256' `
        -Label 'mismatched expected trust hash'
    Assert-ExpectedFailure `
        -Action {
            & $publisher `
                -TrustPolicyPath $trustPath `
                -ExpectedProductionTrustSha256 $validTrustSha256.ToUpperInvariant() `
                -ValidateTrustOnly | Out-Null
        } `
        -Token 'explicit lowercase SHA-256' `
        -Label 'uppercase expected trust hash'

    $negativeCases = @(
        [pscustomobject]@{
            Label = 'development environment'
            Token = 'identity or time policy'
            Mutate = { param($value) $value.environment = 'development-e2e' }
        },
        [pscustomobject]@{
            Label = 'test origin'
            Token = 'non-placeholder production DNS origin'
            Mutate = { param($value) $value.manifestOrigin = 'https://updates.example.test/' }
        },
        [pscustomobject]@{
            Label = 'invalid origin'
            Token = 'non-placeholder production DNS origin'
            Mutate = { param($value) $value.artifactOrigin = 'https://artifacts.example.invalid/' }
        },
        [pscustomobject]@{
            Label = 'loopback origin'
            Token = 'non-placeholder production DNS origin'
            Mutate = { param($value) $value.manifestOrigin = 'https://127.0.0.1/' }
        },
        [pscustomobject]@{
            Label = 'placeholder key id'
            Token = 'invalid or placeholder-like'
            Mutate = { param($value) $value.releaseKeys[0].keyId = 'release-test' }
        },
        [pscustomobject]@{
            Label = 'cross-ring key id reuse'
            Token = 'keyIds must be globally unique'
            Mutate = { param($value) $value.certificationKeys[0].keyId = $value.releaseKeys[0].keyId }
        },
        [pscustomobject]@{
            Label = 'cross-ring point reuse'
            Token = 'P-256 points must be globally unique'
            Mutate = {
                param($value)
                $value.certificationKeys[0].x = $value.releaseKeys[0].x
                $value.certificationKeys[0].y = $value.releaseKeys[0].y
            }
        },
        [pscustomobject]@{
            Label = 'unknown trust member'
            Token = 'exactly the production contract members'
            Mutate = { param($value) $value.unreviewed = $true }
        },
        [pscustomobject]@{
            Label = 'missing certification ring'
            Token = 'exactly the production contract members'
            Mutate = { param($value) $value.Remove('certificationKeys') }
        },
        [pscustomobject]@{
            Label = 'colon key id'
            Token = 'invalid or placeholder-like'
            Mutate = { param($value) $value.releaseKeys[0].keyId = 'release:2026' }
        }
    )
    $caseIndex = 0
    foreach ($case in $negativeCases) {
        $caseIndex++
        $mutated = Copy-JsonObject -Value $validTrust
        & $case.Mutate $mutated
        $casePath = Join-Path $root ("negative-$caseIndex.json")
        Write-TrustDocument -Value $mutated -Path $casePath
        Assert-ExpectedFailure `
            -Action { [void](Invoke-TrustValidation -Path $casePath) } `
            -Token $case.Token `
            -Label $case.Label
    }

    $duplicatePath = Join-Path $root 'duplicate-member.json'
    $validText = [Text.UTF8Encoding]::new($false, $true).GetString($validTrustBytes)
    $duplicateText = $validText.Replace(
        '  "schemaVersion": 1,',
        "  `"schemaVersion`": 1,`n  `"schemaVersion`": 1,",
        [StringComparison]::Ordinal)
    Assert-True `
        -Value ($duplicateText -cne $validText) `
        -Message 'Could not construct duplicate-member trust fixture.'
    [IO.File]::WriteAllText($duplicatePath, $duplicateText, [Text.UTF8Encoding]::new($false))
    Assert-ExpectedFailure `
        -Action { [void](Invoke-TrustValidation -Path $duplicatePath) } `
        -Token 'duplicate JSON member' `
        -Label 'duplicate trust member'

    $bomPath = Join-Path $root 'bom.json'
    [IO.File]::WriteAllBytes($bomPath, @(0xEF, 0xBB, 0xBF) + $validTrustBytes)
    Assert-ExpectedFailure `
        -Action { [void](Invoke-TrustValidation -Path $bomPath) } `
        -Token 'without a BOM' `
        -Label 'BOM trust'

    $crlfPath = Join-Path $root 'crlf.json'
    $crlfText = $validText.Replace("`n", "`r`n", [StringComparison]::Ordinal)
    [IO.File]::WriteAllText($crlfPath, $crlfText, [Text.UTF8Encoding]::new($false))
    Assert-ExpectedFailure `
        -Action { [void](Invoke-TrustValidation -Path $crlfPath) } `
        -Token 'canonical LF line endings' `
        -Label 'CRLF trust'

    $linkPath = Join-Path $root 'hardlink.json'
    try {
        New-Item -ItemType HardLink -Path $linkPath -Target $trustPath -ErrorAction Stop | Out-Null
        Assert-ExpectedFailure `
            -Action { [void](Invoke-TrustValidation -Path $linkPath) } `
            -Token 'single-link' `
            -Label 'hard-linked trust'
    }
    finally {
        if ([IO.File]::Exists($linkPath)) {
            [IO.File]::Delete($linkPath)
        }
    }

    $symbolicLinkPath = Join-Path $root 'symlink.json'
    try {
        New-Item -ItemType SymbolicLink -Path $symbolicLinkPath -Target $trustPath -ErrorAction Stop | Out-Null
        Assert-ExpectedFailure `
            -Action { [void](Invoke-TrustValidation -Path $symbolicLinkPath) } `
            -Token 'ordinary non-empty file' `
            -Label 'symbolic-linked trust'
    }
    catch [System.UnauthorizedAccessException] {
        if (-not $IsWindows) {
            throw
        }
        Write-Host 'SYMLINK-NEGATIVE-PENDING-WINDOWS-DEVELOPER-MODE'
    }
    finally {
        if ([IO.File]::Exists($symbolicLinkPath)) {
            [IO.File]::Delete($symbolicLinkPath)
        }
    }

    if (-not $TrustOnly) {
        $sourceCommit = @(& git -C $RepositoryRoot rev-parse HEAD)
        if ($LASTEXITCODE -ne 0 -or $sourceCommit.Count -ne 1 -or
            $sourceCommit[0] -cnotmatch '^[0-9a-f]{40}$') {
            throw 'Could not resolve the Launcher source commit for the bundle contract test.'
        }
        $outputDirectory = Join-Path $root 'bundle'
        $publishOutput = @(& $publisher `
            -RepositoryRoot $RepositoryRoot `
            -TrustPolicyPath $trustPath `
            -ExpectedProductionTrustSha256 $validTrustSha256 `
            -OutputDirectory $outputDirectory `
            -LauncherSourceCommit $sourceCommit[0])
        Assert-True `
            -Value ($publishOutput.Count -eq 1 -and
                $publishOutput[0].StartsWith(
                    'ENTERPRISE-FEED-PROMOTER-PRODUCTION-BUNDLE-PASS ',
                    [StringComparison]::Ordinal)) `
            -Message 'Production bundle publisher did not return its exact PASS marker.'

        $expectedNames = @(
            'SHA256SUMS',
            'enterprise-feed-production-trust.json',
            'enterprise-feed-promoter-production-bundle.v1.json',
            'ensou-dsh-enterprise-feed-promoter'
        ) | Sort-Object
        $files = @(Get-ChildItem -LiteralPath $outputDirectory -Force | Sort-Object Name)
        Assert-True `
            -Value ($files.Count -eq 4 -and
                -not (Compare-Object -ReferenceObject $expectedNames -DifferenceObject @($files.Name) -CaseSensitive)) `
            -Message 'Production bundle did not contain its exact four-file inventory.'
        $trustOutputPath = Join-Path $outputDirectory 'enterprise-feed-production-trust.json'
        $outputTrustBytes = [IO.File]::ReadAllBytes($trustOutputPath)
        Assert-True `
            -Value ([Linq.Enumerable]::SequenceEqual[byte](
                $outputTrustBytes,
                $validTrustBytes)) `
            -Message 'Production bundle did not preserve the exact external trust bytes.'

        $manifestPath = Join-Path $outputDirectory `
            'enterprise-feed-promoter-production-bundle.v1.json'
        $manifestText = Get-Content -Raw -LiteralPath $manifestPath
        Assert-True `
            -Value (Test-Json -Json $manifestText -SchemaFile $schema -ErrorAction Stop) `
            -Message 'Production bundle manifest did not satisfy its schema.'
        $manifest = $manifestText | ConvertFrom-Json -Depth 16
        Assert-True `
            -Value ($manifest.sourceCommit -ceq $sourceCommit[0] -and
                $manifest.runtimeIdentifier -ceq 'linux-x64' -and
                $manifest.selfContained -eq $true -and
                $manifest.singleFile -eq $true -and
                @($manifest.files).Count -eq 2 -and
                $manifest.files[1].sha256 -ceq $validTrustSha256) `
            -Message 'Production bundle manifest lost source, RID, single-file, or trust identity.'

        $elfFiles = [Collections.Generic.List[string]]::new()
        foreach ($file in $files) {
            $stream = [IO.File]::OpenRead($file.FullName)
            try {
                $magic = [byte[]]::new(4)
                if ($stream.Read($magic, 0, 4) -eq 4 -and
                    $magic[0] -eq 0x7F -and $magic[1] -eq 0x45 -and
                    $magic[2] -eq 0x4C -and $magic[3] -eq 0x46) {
                    $elfFiles.Add($file.Name)
                }
            }
            finally {
                $stream.Dispose()
            }
        }
        Assert-True `
            -Value ($elfFiles.Count -eq 1 -and
                $elfFiles[0] -ceq 'ensou-dsh-enterprise-feed-promoter') `
            -Message 'Production bundle must contain exactly one canonical ELF executable.'

        $sums = Get-Content -LiteralPath (Join-Path $outputDirectory 'SHA256SUMS')
        Assert-True `
            -Value ($sums.Count -eq 3) `
            -Message 'Production bundle SHA256SUMS must contain exactly three entries.'
        foreach ($line in $sums) {
            if ($line -cnotmatch '^(?<sha>[0-9a-f]{64})  (?<name>[A-Za-z0-9._-]+)$') {
                throw 'Production bundle SHA256SUMS contains a non-canonical line.'
            }
            $sumPath = Join-Path $outputDirectory $Matches.name
            $actual = [Convert]::ToHexStringLower(
                [Security.Cryptography.SHA256]::HashData([IO.File]::ReadAllBytes($sumPath)))
            Assert-True `
                -Value ($actual -ceq $Matches.sha) `
                -Message "Production bundle SHA256SUMS mismatched $($Matches.name)."
        }

        Assert-ExpectedFailure `
            -Action {
                & $publisher `
                    -RepositoryRoot $RepositoryRoot `
                    -TrustPolicyPath $trustPath `
                    -ExpectedProductionTrustSha256 $validTrustSha256 `
                    -OutputDirectory $outputDirectory `
                    -LauncherSourceCommit $sourceCommit[0] | Out-Null
            } `
            -Token 'create-only' `
            -Label 'existing bundle output'
        $wrongCommitOutput = Join-Path $root 'wrong-commit-bundle'
        Assert-ExpectedFailure `
            -Action {
                & $publisher `
                    -RepositoryRoot $RepositoryRoot `
                    -TrustPolicyPath $trustPath `
                    -ExpectedProductionTrustSha256 $validTrustSha256 `
                    -OutputDirectory $wrongCommitOutput `
                    -LauncherSourceCommit ('0' * 40) | Out-Null
            } `
            -Token 'did not resolve' `
            -Label 'unknown source commit'
    }

    Write-Host (
        'ENTERPRISE-FEED-PROMOTER-PRODUCTION-BUNDLE-ASSERTIONS={0} EXPECTED-FAILURES={1}' -f
        $assertions,
        $expectedFailures)
    Write-Host 'ENTERPRISE-FEED-PROMOTER-PRODUCTION-BUNDLE-CONTRACT-PASS'
}
finally {
    $releaseSigner.Dispose()
    $certificationSigner.Dispose()
    $rootFullPath = [IO.Path]::GetFullPath($root)
    if ([IO.Path]::GetDirectoryName($rootFullPath) -cne $temporaryParent -or
        -not [IO.Path]::GetFileName($rootFullPath).StartsWith(
            'ensou-feed-promoter-bundle-test-',
            [StringComparison]::Ordinal)) {
        throw "Refusing to remove an unexpected FeedPromoter test directory: $rootFullPath"
    }
    if ([IO.Directory]::Exists($rootFullPath)) {
        [IO.Directory]::Delete($rootFullPath, $true)
    }
}
