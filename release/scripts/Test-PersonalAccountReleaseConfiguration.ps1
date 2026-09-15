#requires -Version 7.2

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$modulePath = Join-Path $PSScriptRoot 'PersonalAccountReleaseConfiguration.psm1'
$producerPath = Join-Path $PSScriptRoot 'New-PersonalPilotBuildIntent.ps1'
$schemaPath = Join-Path $repositoryRoot `
    'release\schemas\personal-two-clean-build-intent-v1.schema.json'
$origin = 'https://personal.example.test/'
$utf8 = [Text.UTF8Encoding]::new($false, $true)

Import-Module -Name $modulePath -Force -ErrorAction Stop

function Require([bool]$Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function Expect-Rejected([scriptblock]$Action, [string]$Label) {
    try {
        & $Action
    }
    catch {
        return
    }

    throw "$Label unexpectedly succeeded."
}

function Bytes([string]$Value) {
    return $utf8.GetBytes($Value)
}

$canonical = PersonalAccountReleaseConfiguration\Assert-PersonalAccountOrigin `
    -Value $origin `
    -Label 'origin'
Require ($canonical -ceq $origin) 'Canonical origin result changed.'

$invalidOrigins = @(
    '',
    'http://personal.example.test/',
    'https://PERSONAL.example.test/',
    'https://personal.example.test:443/',
    'https://127.0.0.1/',
    'https://localhost/',
    'https://user@personal.example.test/',
    'https://personal.example.test/path',
    'https://personal.example.test/?query=1',
    'https://personal.example.test/#fragment',
    'https://personal.example.test%2f/',
    'https://personal.example.test./',
    'https://personal.exämple.test/',
    'https://personal-.example.test/'
)
foreach ($invalidOrigin in $invalidOrigins) {
    Expect-Rejected {
        PersonalAccountReleaseConfiguration\Assert-PersonalAccountOrigin `
            -Value $invalidOrigin `
            -Label 'origin'
    } "origin $invalidOrigin"
}

$validJson = '{"schemaVersion":1,"product":"ensou-dsh-personal","component":"launcher","personalAccountOrigin":"https://personal.example.test/"}'
[byte[]]$validBytes = Bytes $validJson
$parsed = PersonalAccountReleaseConfiguration\ConvertFrom-PersonalAccountSelfCheck `
    -Bytes $validBytes `
    -ExpectedOrigin $origin
Require ($parsed.schemaVersion -eq 1) 'Self-check schema changed.'
Require ($parsed.product -ceq 'ensou-dsh-personal') 'Self-check product changed.'
Require ($parsed.component -ceq 'launcher') 'Self-check component changed.'
Require ($parsed.personalAccountOrigin -ceq $origin) 'Self-check origin changed.'

$invalidDocuments = @(
    "$validJson`n",
    " $validJson",
    '{"schemaVersion":1,"schemaVersion":1,"product":"ensou-dsh-personal","component":"launcher","personalAccountOrigin":"https://personal.example.test/"}',
    '{"schemaVersion":"1","product":"ensou-dsh-personal","component":"launcher","personalAccountOrigin":"https://personal.example.test/"}',
    '{"schemaVersion":1,"product":"ensou-dsh-personal","component":"launcher","extra":true,"personalAccountOrigin":"https://personal.example.test/"}',
    '{"schemaVersion":1,"product":"ensou-dsh-personal","personalAccountOrigin":"https://personal.example.test/"}',
    '{"product":"ensou-dsh-personal","schemaVersion":1,"component":"launcher","personalAccountOrigin":"https://personal.example.test/"}',
    '{"schemaVersion":1,"product":"ensou-dsh-personal","component":"launcher","personalAccountOrigin":"https://other.example.test/"}'
)
foreach ($invalidDocument in $invalidDocuments) {
    [byte[]]$invalidBytes = Bytes $invalidDocument
    Expect-Rejected {
        PersonalAccountReleaseConfiguration\ConvertFrom-PersonalAccountSelfCheck `
            -Bytes $invalidBytes `
            -ExpectedOrigin $origin
    } 'invalid self-check document'
}

Expect-Rejected {
    PersonalAccountReleaseConfiguration\ConvertFrom-PersonalAccountSelfCheck `
        -Bytes ([byte[]](0xc3, 0x28)) `
        -ExpectedOrigin $origin
} 'invalid UTF-8 self-check'

[byte[]]$oversized = [byte[]]::new((16 * 1024) + 1)
Expect-Rejected {
    PersonalAccountReleaseConfiguration\ConvertFrom-PersonalAccountSelfCheck `
        -Bytes $oversized `
        -ExpectedOrigin $origin
} 'oversized self-check'

$schemaJson = [IO.File]::ReadAllText($schemaPath, $utf8)
$schema = ConvertFrom-Json -InputObject $schemaJson -AsHashtable -Depth 32
Require ($schema.required -ccontains 'personalAccountOrigin') 'Intent schema does not require account origin.'
Require ($schema.properties.personalAccountOrigin.'$ref' -ceq '#/definitions/httpsAccountOrigin') `
    'Intent schema does not use its account-origin definition.'

$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    $producerPath,
    [ref]$tokens,
    [ref]$parseErrors)
Require ($parseErrors.Count -eq 0) 'Intent producer has PowerShell parse errors.'
$producerText = $ast.Extent.Text
Require ($producerText -cmatch '\[string\]\$PersonalAccountOrigin') `
    'Intent producer does not declare PersonalAccountOrigin.'
Require ($producerText -cmatch 'personalAccountOrigin\s*=\s*\$canonicalPersonalAccountOrigin') `
    'Intent producer does not persist the validated account origin.'

[pscustomobject][ordered]@{
    status = 'PASS'
    testCount = 5
    executedProduct = $false
    signingOrKeyAccessPerformed = $false
}
