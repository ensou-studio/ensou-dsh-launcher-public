#requires -Version 7.2

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$testOrchestrationPath = Join-Path `
    $PSScriptRoot `
    'Test-LauncherProductionReleaseOrchestration.ps1'
$productionOrchestrationPath = Join-Path `
    $PSScriptRoot `
    'Invoke-LauncherProductionRelease.ps1'
$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    $testOrchestrationPath,
    [ref]$tokens,
    [ref]$parseErrors)
if (@($parseErrors).Count -ne 0) {
    throw ('Production orchestration test has PowerShell parse errors: ' +
        (@($parseErrors | ForEach-Object Message) -join '; '))
}
$helpers = @($ast.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Invoke-Git'
}, $true))
if ($helpers.Count -ne 1) {
    throw 'Expected exactly one production orchestration Invoke-Git helper.'
}

# Execute the production test helper itself. The fixture never changes user,
# system, or product-repository Git configuration.
. ([ScriptBlock]::Create($helpers[0].Extent.Text))

$productionTokens = $null
$productionParseErrors = $null
$productionAst = [Management.Automation.Language.Parser]::ParseFile(
    $productionOrchestrationPath,
    [ref]$productionTokens,
    [ref]$productionParseErrors)
if (@($productionParseErrors).Count -ne 0) {
    throw ('Production orchestrator has PowerShell parse errors: ' +
        (@($productionParseErrors | ForEach-Object Message) -join '; '))
}
$productionGitReaders = @($productionAst.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Invoke-ProductionGitRead'
}, $true))
if ($productionGitReaders.Count -ne 1) {
    throw 'Expected exactly one production Invoke-ProductionGitRead function.'
}
. ([ScriptBlock]::Create($productionGitReaders[0].Extent.Text))

function Get-FixtureSha256 {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    return [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($Bytes)).ToLowerInvariant()
}

$tempParent = [IO.Path]::TrimEndingDirectorySeparator(
    [IO.Path]::GetFullPath([IO.Path]::GetTempPath()))
$ownedLeaf = 'ensou-launcher-git-eol-' + [Guid]::NewGuid().ToString('N')
$tempRoot = [IO.Path]::GetFullPath((Join-Path $tempParent $ownedLeaf))
if (-not $tempRoot.StartsWith(
        $tempParent + [IO.Path]::DirectorySeparatorChar,
        [StringComparison]::OrdinalIgnoreCase) -or
    [IO.Path]::GetFileName($tempRoot) -cne $ownedLeaf) {
    throw 'Git EOL fixture root escaped its exact temporary ownership boundary.'
}

try {
    $sourceRoot = Join-Path $tempRoot 'source'
    $cloneRoot = Join-Path $tempRoot 'clone'
    [IO.Directory]::CreateDirectory($sourceRoot) | Out-Null
    $productionRelativePath =
        'release/scripts/Invoke-LauncherProductionRelease.ps1'
    $fixtures = [ordered]@{
        'pure-lf.ps1' = [byte[]](97, 10, 98, 10)
        'pure-crlf.ps1' = [byte[]](97, 13, 10, 98, 13, 10)
        'mixed.ps1' = [byte[]](97, 10, 98, 13, 10, 99, 10)
        $productionRelativePath =
            [IO.File]::ReadAllBytes($productionOrchestrationPath)
    }
    foreach ($entry in $fixtures.GetEnumerator()) {
        $fixturePath = Join-Path $sourceRoot ([string]$entry.Key)
        [IO.Directory]::CreateDirectory(
            [IO.Path]::GetDirectoryName($fixturePath)) | Out-Null
        [IO.File]::WriteAllBytes($fixturePath, [byte[]]$entry.Value)
    }

    [void](Invoke-Git -Root $sourceRoot -Arguments @('init', '--quiet'))
    [void](Invoke-Git -Root $sourceRoot -Arguments @(
        'config', '--local', 'core.autocrlf', 'false'))
    [void](Invoke-Git -Root $sourceRoot -Arguments @('add', '--all'))
    [void](Invoke-Git -Root $sourceRoot -Arguments @(
        '-c', 'user.email=launcher-eol-test@ensou.invalid',
        '-c', 'user.name=ensou-launcher-eol-test',
        'commit', '--quiet', '-m', 'exact EOL fixture'))
    [void](Invoke-Git -Root $tempRoot -Arguments @(
        'clone', '--quiet', $sourceRoot, $cloneRoot))
    [void](Invoke-Git -Root $cloneRoot -Arguments @(
        'config', '--local', 'core.autocrlf', 'false'))

    $sourceHead = [string]@(Invoke-ProductionGitRead `
        -Root $sourceRoot -Arguments @('rev-parse', 'HEAD') `
        -Label 'EOL source HEAD')[0]
    $cloneHead = [string]@(Invoke-ProductionGitRead `
        -Root $cloneRoot -Arguments @('rev-parse', 'HEAD') `
        -Label 'EOL clone HEAD')[0]
    if ($sourceHead -cne $cloneHead) {
        throw "Git EOL fixture clone HEAD differs: source=$sourceHead clone=$cloneHead."
    }
    foreach ($repository in @($sourceRoot, $cloneRoot)) {
        $localAutoCrlf = @(Invoke-ProductionGitRead `
            -Root $repository `
            -Arguments @('config', '--local', '--get', 'core.autocrlf') `
            -Label 'EOL repository-local policy')
        if ($localAutoCrlf.Count -ne 1 -or
            [string]$localAutoCrlf[0] -cne 'false') {
            throw "Temporary Git repository lacks exact local core.autocrlf=false: $repository."
        }
        $status = @(Invoke-ProductionGitRead `
            -Root $repository `
            -Arguments @('status', '--porcelain=v1', '--untracked-files=all') `
            -Label 'EOL repository clean status')
        if ($status.Count -ne 0) {
            throw ("Production Git reader reports a dirty exact-byte fixture: " +
                "${repository}: $($status -join ' | ')")
        }
    }

    foreach ($entry in $fixtures.GetEnumerator()) {
        $name = [string]$entry.Key
        $sourceBytes = [IO.File]::ReadAllBytes((Join-Path $sourceRoot $name))
        $cloneBytes = [IO.File]::ReadAllBytes((Join-Path $cloneRoot $name))
        $expectedBytes = [byte[]]$entry.Value
        if (-not [Linq.Enumerable]::SequenceEqual[byte](
                $expectedBytes,
                $sourceBytes) -or
            -not [Linq.Enumerable]::SequenceEqual[byte](
                $sourceBytes,
                $cloneBytes)) {
            throw ("Git fixture changed '$name' across source/commit/clone: " +
                "expectedBytes=$($expectedBytes.Length), " +
                "expectedSha256=$(Get-FixtureSha256 $expectedBytes), " +
                "sourceBytes=$($sourceBytes.Length), " +
                "sourceSha256=$(Get-FixtureSha256 $sourceBytes), " +
                "cloneBytes=$($cloneBytes.Length), " +
                "cloneSha256=$(Get-FixtureSha256 $cloneBytes).")
        }
        foreach ($repository in @($sourceRoot, $cloneRoot)) {
            $headBlob = [string]@(Invoke-ProductionGitRead `
                -Root $repository `
                -Arguments @('rev-parse', "HEAD:$name") `
                -Label "EOL HEAD blob $name")[0]
            $workingBlob = [string]@(Invoke-ProductionGitRead `
                -Root $repository `
                -Arguments @('hash-object', "--path=$name", '--',
                    (Join-Path $repository $name)) `
                -Label "EOL working blob $name")[0]
            if ($headBlob -cne $workingBlob) {
                throw ("Production Git reader sees EOL drift for '$name' in " +
                    "${repository}: HEAD=$headBlob working=$workingBlob, " +
                    "sha256=$(Get-FixtureSha256 $cloneBytes).")
            }
        }
    }
}
finally {
    if (Test-Path -LiteralPath $tempRoot) {
        $ownedDirectory = Get-Item -LiteralPath $tempRoot -Force
        if (-not $ownedDirectory.PSIsContainer -or
            (($ownedDirectory.Attributes -band
                [IO.FileAttributes]::ReparsePoint) -ne 0) -or
            -not $ownedDirectory.FullName.StartsWith(
                $tempParent + [IO.Path]::DirectorySeparatorChar,
                [StringComparison]::OrdinalIgnoreCase) -or
            [IO.Path]::GetFileName($ownedDirectory.FullName) -cne $ownedLeaf) {
            throw 'Refusing to clean an unowned or linked Git EOL fixture root.'
        }
        Remove-Item -LiteralPath $ownedDirectory.FullName -Recurse -Force
    }
    if (Test-Path -LiteralPath $tempRoot) {
        throw 'Git EOL fixture cleanup did not remove its exact temporary root.'
    }
}

Write-Output 'LAUNCHER-PRODUCTION-RELEASE-GIT-FIXTURE-EOL-PASS'
