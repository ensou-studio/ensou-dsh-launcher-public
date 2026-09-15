#requires -Version 7.2

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$builderPath = Join-Path $PSScriptRoot 'build-source-runtime.ps1'
$builder = [IO.File]::ReadAllText($builderPath)
$null = [scriptblock]::Create($builder)
$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$lockPath = Join-Path $repositoryRoot 'versions\locked.json'
$workflowPath = Join-Path $repositoryRoot '.github\workflows\build-candidate.yml'
$modulePath = Join-Path $PSScriptRoot 'ManagedSourcePatch.psm1'
Import-Module $modulePath -Force -DisableNameChecking
$lock = Get-ManagedSourceLock $lockPath
$workflow = [IO.File]::ReadAllText($workflowPath)

$reviewedRuntimeWebAuthPairs = @{
    'dsh-v0.1.1-rc.2' = 'legacy-clean-root-v1'
    'dsh-v0.1.2-alpha.3' = 'browser-launch-cookie-v1'
    'dsh-v0.1.2-rc.1' = 'browser-launch-cookie-v1'
}
if ([int]$lock.schemaVersion -ne 4 -or
    -not $reviewedRuntimeWebAuthPairs.ContainsKey([string]$lock.officialTag) -or
    [string]$reviewedRuntimeWebAuthPairs[[string]$lock.officialTag] -cne
        [string]$lock.runtimeWebAuthProtocol) {
    throw 'The immutable source lock does not bind a reviewed runtime Web auth protocol.'
}

function Assert-Contains([string]$Needle, [string]$Label) {
    if ($builder.IndexOf($Needle, [StringComparison]::Ordinal) -lt 0) {
        throw "Source-runtime Web auth contract is missing $Label."
    }
}

Assert-Contains "[string]`$RuntimeWebAuthProtocol = ''" 'the legacy-preserving default'
Assert-Contains "'dsh-v0.1.2-alpha.3' = `$BrowserLaunchCookieWebAuthProtocol" 'the historical reviewed alpha tag lock'
Assert-Contains "'dsh-v0.1.2-rc.1' = `$BrowserLaunchCookieWebAuthProtocol" 'the active reviewed rc.1 tag lock'
Assert-Contains "`$BrowserLaunchCookieWebAuthProtocol = 'browser-launch-cookie-v1'" 'the browser-cookie protocol constant'
Assert-Contains 'requires explicit -RuntimeWebAuthProtocol' 'the alpha fail-closed selection gate'
Assert-Contains "function Read-RuntimeWebAuthProtocolMetadata" 'the immutable runtime metadata reader'
Assert-Contains "Write-RuntimeProtocolMetadata `$runtimeRoot -WebAuthProtocol `$effectiveRuntimeWebAuthProtocol" 'the immutable runtime metadata writer'
Assert-Contains "Invoke-PersonalManagedUpdateSmoke `$runtimeRoot" 'the actual Personal capability prerequisite'
Assert-Contains "Invoke-PersonalManagedUpdateSmoke `$extractedRuntimeRoot" 'the extracted Personal capability replay'
Assert-Contains "-PersonalManagedUpdate:`$PersonalManagedUpdate" 'the explicit Personal capability selection'
Assert-Contains "`$assembledRuntimeWebAuthProtocol = Read-RuntimeWebAuthProtocolMetadata `$runtimeRoot" 'the assembled metadata admission'
Assert-Contains "Read-RuntimeWebAuthProtocolMetadata `$extractedRuntimeRoot" 'the extracted metadata admission'
Assert-Contains "runtimeWebAuthProtocol = `$extractedRuntimeWebAuthProtocol" 'the external immutable protocol evidence'

$metadataIndex = $builder.IndexOf(
    "Write-RuntimeProtocolMetadata `$runtimeRoot",
    [StringComparison]::Ordinal)
$hashManifestIndex = $builder.IndexOf(
    "`$hashManifest = Join-Path `$runtimeRoot 'runtime-files.sha256'",
    [StringComparison]::Ordinal)
if ($metadataIndex -lt 0 -or $hashManifestIndex -le $metadataIndex) {
    throw 'Runtime Web auth metadata is not created before runtime-files.sha256.'
}

Assert-Contains 'const maximumDiagnosticCharacters = 16_384' 'the bounded smoke diagnostic'
Assert-Contains "replace(/([?&]token=)[^\s)]+/g, '`$1<redacted>')" 'the token redaction rule'
Assert-Contains 'primaryError = new Error(redactDiagnostic(diagnostic))' 'the final exception redaction gate'
Assert-Contains 'const browserReplayCookie = await exchangeBrowserCookie()' 'the real runtime browser replay smoke'
Assert-Contains "return validateBrowserSetCookie(setCookies[0], ``127.0.0.1:`${webPort}``)" 'the strict real-runtime cookie admission'
Assert-Contains "await assertAlphaSessionList(cleanUrl, hostCookie)" 'the real alpha session/list admission smoke'
Assert-Contains "async function assertAlphaAuthenticationRejected(cleanUrl, cookie, label)" 'the alpha authentication negative smoke'
Assert-Contains "rootResponse.status !== 401" 'the anonymous and forged-cookie root rejection gate'
Assert-Contains "apiResponse.status !== 401" 'the anonymous and forged-cookie API rejection gate'
Assert-Contains "await assertAlphaAuthenticationRejected(cleanUrl, undefined, 'anonymous Host')" 'the anonymous alpha rejection smoke'
Assert-Contains "await assertAlphaAuthenticationRejected(cleanUrl, forgedHostCookie, 'forged-cookie Host')" 'the forged-cookie alpha rejection smoke'
Assert-Contains "method: 'session/list'" 'the exact alpha session/list method'
Assert-Contains "payload: { args: { _request: {} } }" 'the exact alpha session/list payload'
Assert-Contains "html.includes('__DSH_BOOT__')" 'the real WebUI boot marker smoke'
Assert-Contains "launchUrl = ''" 'launch URL memory clearing'
Assert-Contains "output = ''" 'readiness output memory clearing'
if ($builder.Contains('${output}', [StringComparison]::Ordinal)) {
    throw 'Source-runtime smoke still interpolates raw process output into an exception.'
}

$token = 'A' * 43
$diagnostic = [Text.RegularExpressions.Regex]::Replace(
    "failed http://127.0.0.1:3191/?token=$token trailing",
    '([?&]token=)[^\s)]+',
    '$1<redacted>')
if ($diagnostic.Contains($token, [StringComparison]::Ordinal) -or
    -not $diagnostic.Contains('?token=<redacted>', [StringComparison]::Ordinal)) {
    throw 'Source-runtime Web auth token redaction negative test failed.'
}
$bounded = 'x' * 20000
$bounded = $bounded.Substring($bounded.Length - 16384)
if ($bounded.Length -ne 16384) {
    throw 'Source-runtime Web auth diagnostic bound negative test failed.'
}

foreach ($workflowNeedle in @(
    'Get-ManagedSourceLock .\versions\locked.json',
    "'dsh-v0.1.2-rc.1' = 'browser-launch-cookie-v1'",
    'runtime_web_auth_protocol=$($lock.runtimeWebAuthProtocol)',
    'RUNTIME_WEB_AUTH_PROTOCOL: ${{ steps.locked.outputs.runtime_web_auth_protocol }}',
    '-RuntimeWebAuthProtocol $env:RUNTIME_WEB_AUTH_PROTOCOL',
    '$sourceMetadata.runtimeWebAuthProtocol -cne $env:RUNTIME_WEB_AUTH_PROTOCOL',
    'runtimeWebAuthProtocol = $sourceMetadata.runtimeWebAuthProtocol')) {
    if ($workflow.IndexOf($workflowNeedle, [StringComparison]::Ordinal) -lt 0) {
        throw "Candidate workflow does not pass the locked Web auth protocol: $workflowNeedle"
    }
}

Write-Host 'Source-runtime Web auth contract validation passed.' -ForegroundColor Green
