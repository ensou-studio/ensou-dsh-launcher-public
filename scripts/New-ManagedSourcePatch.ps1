#requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$PatchedCheckout,

    [Parameter(Mandatory)]
    [string]$OutputPath,

    [string]$Git = 'git'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-FullPath([string]$Path) {
    return [IO.Path]::GetFullPath(
        $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path))
}

function Invoke-Git([string[]]$Arguments, [string]$Label) {
    $output = @(& $Git '-c' 'core.longpaths=true' '-c' 'core.autocrlf=false' `
        '-c' "safe.directory=$($script:checkout.Replace('\', '/'))" '-C' $script:checkout `
        @Arguments 2>&1)
    if ($LASTEXITCODE -ne 0) {
        $text = ($output | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine
        throw "$Label failed with exit code $LASTEXITCODE.`n$text"
    }
    return $output
}

function Assert-CanonicalPatch([string]$Path) {
    $bytes = [IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -eq 0 -or $bytes[-1] -ne 10) {
        throw 'Generated managed patch must be non-empty and LF-terminated.'
    }
    try {
        $utf8 = [Text.UTF8Encoding]::new($false, $true)
        $text = $utf8.GetString($bytes)
    } catch {
        throw "Generated managed patch is not canonical UTF-8: $($_.Exception.Message)"
    }
    if ($text.Contains("`r")) {
        throw 'Generated managed patch contains a carriage return.'
    }
    if ([Text.RegularExpressions.Regex]::IsMatch(
            $text, '[\x20\x09]+(?=\n|\z)',
            [Text.RegularExpressions.RegexOptions]::CultureInvariant)) {
        throw 'Generated managed patch contains trailing horizontal whitespace.'
    }

    [string[]]$paths = @([Text.RegularExpressions.Regex]::Matches(
        $text, '(?m)^diff --git a/(?<path>.+) b/\k<path>$') |
        ForEach-Object { $_.Groups['path'].Value })
    if ($paths.Count -eq 0) { throw 'Generated managed patch contains no file diffs.' }
    $ordered = [string[]]$paths.Clone()
    [Array]::Sort($ordered, [StringComparer]::Ordinal)
    for ($index = 0; $index -lt $paths.Count; $index++) {
        if ($paths[$index] -cne $ordered[$index]) {
            throw 'Generated managed patch paths are not in ordinal order.'
        }
    }
}

$checkout = Get-FullPath $PatchedCheckout
if (-not (Test-Path -LiteralPath $checkout -PathType Container)) {
    throw "Patched checkout does not exist: $checkout"
}
$output = Get-FullPath $OutputPath
if ($output.StartsWith(
        $checkout.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar,
        [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Managed patch output must be outside the patched checkout.'
}
$outputDirectory = Split-Path -Parent $output
if (-not (Test-Path -LiteralPath $outputDirectory -PathType Container)) {
    throw "Managed patch output directory does not exist: $outputDirectory"
}

$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) (
    'ensou-managed-patch-generator-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($temporaryRoot) | Out-Null
$temporaryIndex = Join-Path $temporaryRoot 'index'
$firstPatch = Join-Path $temporaryRoot 'first.patch'
$secondPatch = Join-Path $temporaryRoot 'second.patch'
$previousIndex = [Environment]::GetEnvironmentVariable('GIT_INDEX_FILE', 'Process')
try {
    [Environment]::SetEnvironmentVariable('GIT_INDEX_FILE', $temporaryIndex, 'Process')
    [void](Invoke-Git @('read-tree', 'HEAD') 'initialize isolated patch index')
    [void](Invoke-Git @('add', '--all', '--') 'snapshot patched source')
    [void](Invoke-Git @('diff', '--cached', '--check', '--') 'validate patched source whitespace')

    foreach ($target in @($firstPatch, $secondPatch)) {
        [void](Invoke-Git @(
            'diff', '--cached', '--binary', '--full-index', '--no-ext-diff',
            '--no-color', '--no-renames', '--unified=0', "--output=$target", '--'
        ) 'generate canonical zero-context patch')
        Assert-CanonicalPatch $target
    }
    $firstBytes = [IO.File]::ReadAllBytes($firstPatch)
    $secondBytes = [IO.File]::ReadAllBytes($secondPatch)
    if ($firstBytes.Length -ne $secondBytes.Length -or
        -not [Collections.StructuralComparisons]::StructuralEqualityComparer.Equals(
            $firstBytes, $secondBytes)) {
        throw 'Managed patch regeneration was not byte-identical.'
    }
    [IO.File]::WriteAllBytes($output, $firstBytes)
} finally {
    [Environment]::SetEnvironmentVariable('GIT_INDEX_FILE', $previousIndex, 'Process')
    if (Test-Path -LiteralPath $temporaryRoot) {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
    }
}

$item = Get-Item -LiteralPath $output
$sha256 = (Get-FileHash -LiteralPath $output -Algorithm SHA256).Hash.ToLowerInvariant()
$lfLines = @([IO.File]::ReadAllBytes($output) | Where-Object { $_ -eq 10 }).Count
Write-Host "Generated canonical managed patch: $output" -ForegroundColor Green
Write-Host "SHA-256=$sha256 bytes=$($item.Length) lfLines=$lfLines"
