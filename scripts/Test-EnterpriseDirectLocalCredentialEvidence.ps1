[CmdletBinding()]
param(
    [string]$RuntimeDirectory,
    [switch]$ContractOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$sourcePath = Join-Path $PSScriptRoot 'Test-EnterpriseDevelopmentLifecycle.ps1'
$verifierPath = Join-Path $PSScriptRoot 'Test-EnterpriseDirectLocalCredentialValue.mjs'
$parseTokens = $null
$parseErrors = $null
$sourceAst = [Management.Automation.Language.Parser]::ParseFile(
    $sourcePath, [ref]$parseTokens, [ref]$parseErrors)
if ($parseErrors.Count -ne 0) { throw 'Lifecycle helper source does not parse.' }

# Execute the actual helper bodies, without starting the lifecycle or Docker.
foreach ($functionName in @(
        'Resolve-SafeExistingPath',
        'New-DevelopmentDirectLocalCredentialEvidence',
        'Assert-DevelopmentDirectLocalCredentialRetained')) {
    $matches = @($sourceAst.FindAll({ param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq $functionName
    }, $false))
    if ($matches.Count -ne 1) { throw "Expected exactly one helper: $functionName" }
    . ([scriptblock]::Create($matches[0].Extent.Text))
}

if (-not (Test-Path -LiteralPath $verifierPath -PathType Leaf)) {
    throw 'Direct-local native credential verifier is missing.'
}
$verifierText = Get-Content -LiteralPath $verifierPath -Raw
foreach ($requiredText in @(
        'parseCredentialsDocument',
        'timingSafeEqual',
        "REFERENCE_NAME = 'DEEPSEEK_API_KEY'",
        "passed ? 'PASS\n' : 'FAIL\n'")) {
    if (-not $verifierText.Contains($requiredText, [StringComparison]::Ordinal)) {
        throw 'Direct-local native credential verifier contract is incomplete.'
    }
}
if ($ContractOnly) {
    if (-not [string]::IsNullOrWhiteSpace($RuntimeDirectory)) {
        throw 'Credential ContractOnly validation does not accept a RuntimeDirectory.'
    }
    Write-Host 'PASS direct-local credential contract: native parser, value digest and fixed result protocol are present.'
    return
}
if ([string]::IsNullOrWhiteSpace($RuntimeDirectory)) {
    throw 'RuntimeDirectory is required for direct-local credential execution tests.'
}
$runtime = Resolve-SafeExistingPath -Path $RuntimeDirectory -Directory $true

$testId = [Guid]::NewGuid().ToString('N')
$testParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$testRoot = Join-Path $testParent "ensou-dsh-direct-credential-$testId"
$expectedRoot = [IO.Path]::GetFullPath($testRoot)
$credentialPath = Join-Path $expectedRoot '.credentials.yaml'
[IO.Directory]::CreateDirectory($expectedRoot) | Out-Null
try {
    $evidence = New-DevelopmentDirectLocalCredentialEvidence -HarnessHome $expectedRoot
    $evidenceFields = @($evidence.PSObject.Properties.Name)
    if ($evidence.Path -cne $credentialPath -or
        $evidence.ReferenceName -cne 'DEEPSEEK_API_KEY' -or
        $evidence.ValueSha256 -cnotmatch '^[a-f0-9]{64}$' -or
        $evidence.InitialDocumentSizeBytes -le 0 -or
        $evidence.InitialDocumentSha256 -cnotmatch '^[a-f0-9]{64}$' -or
        $evidenceFields -ccontains 'Value' -or
        $evidenceFields -ccontains 'Secret') {
        throw 'Synthetic credential evidence shape is invalid.'
    }
    $initialResult = Assert-DevelopmentDirectLocalCredentialRetained `
        -Evidence $evidence -RuntimeDirectory $runtime -VerifierPath $verifierPath -Stage 'initial'
    if ($initialResult.nativeParserVerified -ne $true -or
        $initialResult.documentBytesUnchanged -ne $true -or
        $initialResult.expectedValueSha256 -cne $evidence.ValueSha256) {
        throw 'Initial native credential verification evidence is invalid.'
    }

    $syntheticText = [IO.File]::ReadAllText($credentialPath)
    if ($syntheticText -cnotmatch '\Aversion: 1\nrefs:\n  DEEPSEEK_API_KEY: [A-Za-z0-9_-]{43}\n\z') {
        throw 'Synthetic credential does not use the native version-1 reference layout.'
    }

    $rejectedExisting = $false
    try { $null = New-DevelopmentDirectLocalCredentialEvidence -HarnessHome $expectedRoot }
    catch { $rejectedExisting = $true }
    if (-not $rejectedExisting) { throw 'Existing credential overwrite was not refused.' }

    # A native browser session and YAML formatting changes are legitimate document mutations.
    $legitimateDocument = $syntheticText.Replace(
        "version: 1`nrefs:`n",
        "# synthetic formatting change`nrecords:`n  client-connection/browser-session:`n    kind: grant`n    payload:`n      version: 1`n      secret: $('A' * 43)`nversion: 1`nrefs:`n")
    [IO.File]::WriteAllText(
        $credentialPath,
        $legitimateDocument,
        [Text.UTF8Encoding]::new($false))
    $legitimateResult = Assert-DevelopmentDirectLocalCredentialRetained `
        -Evidence $evidence -RuntimeDirectory $runtime -VerifierPath $verifierPath `
        -Stage 'legitimate-record-addition'
    if ($legitimateResult.nativeParserVerified -ne $true -or
        $legitimateResult.documentBytesUnchanged -ne $false -or
        $legitimateResult.expectedValueSha256 -cne $evidence.ValueSha256) {
        throw 'Legitimate native credential mutation was not admitted by value.'
    }

    function Assert-SyntheticDocumentRejected {
        param(
            [Parameter(Mandatory)][string]$Document,
            [Parameter(Mandatory)][string]$Label
        )

        [IO.File]::WriteAllText($credentialPath, $Document, [Text.UTF8Encoding]::new($false))
        $rejected = $false
        try {
            $null = Assert-DevelopmentDirectLocalCredentialRetained `
                -Evidence $evidence -RuntimeDirectory $runtime -VerifierPath $verifierPath `
                -Stage 'negative'
        }
        catch { $rejected = $true }
        if (-not $rejected) { throw "Synthetic credential negative case was admitted: $Label" }
    }

    $changedValueDocument = [regex]::Replace(
        $syntheticText,
        '(?m)(^  DEEPSEEK_API_KEY: )[A-Za-z0-9_-]{43}$',
        { param($match) $match.Groups[1].Value + ('B' * 43) })
    Assert-SyntheticDocumentRejected -Document $changedValueDocument -Label 'changed value'
    Assert-SyntheticDocumentRejected `
        -Document "version: 1`nrefs: {}`n" -Label 'missing reference'
    Assert-SyntheticDocumentRejected -Document (
        "version: 1`nrefs:`n  DEEPSEEK_API_KEY: $('A' * 43)`n" +
        "  DEEPSEEK_API_KEY: $('B' * 43)`n") -Label 'duplicate reference'
    Assert-SyntheticDocumentRejected `
        -Document "version: 1`nrefs:`n  DEEPSEEK_API_KEY: [`n" -Label 'malformed yaml'
    Assert-SyntheticDocumentRejected `
        -Document "version: 1`nrefs:`n  DEEPSEEK_API_KEY: 42`n" -Label 'wrong value type'

    [IO.File]::WriteAllText($credentialPath, $legitimateDocument, [Text.UTF8Encoding]::new($false))
    $finalResult = Assert-DevelopmentDirectLocalCredentialRetained `
        -Evidence $evidence -RuntimeDirectory $runtime -VerifierPath $verifierPath -Stage 'final'
    if ($finalResult.nativeParserVerified -ne $true) {
        throw 'Final native credential verification did not pass.'
    }
    Write-Host 'PASS direct-local credential helper: native value retained across legitimate mutation; overwrite, changed, missing, duplicate, malformed and wrong-type inputs rejected; no real Key or model request.'
}
finally {
    $syntheticText = $null
    $legitimateDocument = $null
    $changedValueDocument = $null
    $resolvedRoot = Resolve-SafeExistingPath -Path $expectedRoot -Directory $true
    if ([IO.Path]::GetDirectoryName($resolvedRoot) -cne $testParent.TrimEnd('\', '/') -or
        [IO.Path]::GetFileName($resolvedRoot) -cne "ensou-dsh-direct-credential-$testId") {
        throw 'Refusing cleanup outside the exact credential-test directory.'
    }
    if (Test-Path -LiteralPath $credentialPath) {
        $resolvedFile = Resolve-SafeExistingPath -Path $credentialPath -Directory $false
        if ([IO.Path]::GetDirectoryName($resolvedFile) -cne $resolvedRoot) {
            throw 'Refusing credential cleanup outside the exact test directory.'
        }
        Remove-Item -LiteralPath $resolvedFile -Force
    }
    # Non-recursive removal refuses any unexpected residual contents.
    [IO.Directory]::Delete($resolvedRoot, $false)
}
