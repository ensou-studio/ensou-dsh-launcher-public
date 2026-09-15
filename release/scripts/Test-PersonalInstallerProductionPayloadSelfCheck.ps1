#requires -Version 7.2

[CmdletBinding()]
param(
    [string]$UnsignedPersonalInstallerPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = Join-Path $PSScriptRoot 'PersonalInstallerProductionPayloadSelfCheck.psm1'
$stateModulePath = Join-Path $PSScriptRoot 'ProductionReleaseState.psm1'
$schemaRoot = Join-Path ([IO.Path]::GetDirectoryName($PSScriptRoot)) 'schemas'
$resultSchemaPath = Join-Path `
    $schemaRoot `
    'personal-installer-production-payload-self-check-result-v1.schema.json'
$evidenceSchemaPath = Join-Path `
    $schemaRoot `
    'personal-installer-production-payload-self-check-evidence-v1.schema.json'
$module = Microsoft.PowerShell.Core\Import-Module `
    $modulePath `
    -Force `
    -PassThru `
    -ErrorAction Stop
Microsoft.PowerShell.Core\Import-Module $stateModulePath -Force -ErrorAction Stop
$utf8 = [Text.UTF8Encoding]::new($false, $true)
$script:AssertionCount = 0

function Assert-True {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $script:AssertionCount++
    if (-not $Condition) {
        throw "Assertion failed: $Label"
    }
}

function Assert-Equal {
    param(
        [AllowNull()][object]$Actual,
        [AllowNull()][object]$Expected,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $script:AssertionCount++
    if ($Actual -cne $Expected) {
        throw "Assertion failed: $Label; expected '$Expected', got '$Actual'."
    }
}

function Assert-ByteSequence {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Actual,
        [Parameter(Mandatory = $true)][byte[]]$Expected,
        [Parameter(Mandatory = $true)][string]$Label
    )

    Assert-Equal $Actual.Length $Expected.Length "$Label length"
    for ($index = 0; $index -lt $Actual.Length; $index++) {
        if ($Actual[$index] -ne $Expected[$index]) {
            throw "Assertion failed: $Label differs at byte $index."
        }
    }
}

function Assert-FailsWithCode {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Action,
        [Parameter(Mandatory = $true)][string]$Code,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $captured = [Collections.Generic.List[object]]::new()
    $failure = $null
    try {
        & $Action | ForEach-Object { $captured.Add($_) }
    }
    catch {
        $failure = $_
    }
    Assert-True ($null -ne $failure) "$Label throws"
    Assert-True `
        ($failure.Exception.Message.StartsWith(
            "${Code}:",
            [StringComparison]::Ordinal)) `
        "$Label uses stable failure code $Code; actual=$($failure.Exception.Message)"
    Assert-Equal $captured.Count 0 "$Label returns zero evidence"
}

function New-Expectation {
    return [pscustomobject][ordered]@{
        releaseSetId = 'personal-v2026.09.03.1'
        manifestSha256 = '1' * 64
        manifestSizeBytes = [int64]4096
        startupStubSha256 = '2' * 64
        startupStubSizeBytes = [int64]8192
        clientBundleSha256 = '3' * 64
        clientBundleSizeBytes = [int64]16384
        runtimeSha256 = '4' * 64
        runtimeSizeBytes = [int64]32768
    }
}

function New-ResultObject {
    param(
        [Parameter(Mandatory = $true)][psobject]$Expectation,
        [string]$InstallerSha256 = ('a' * 64)
    )

    return [pscustomobject][ordered]@{
        schemaVersion = 1
        resultType =
            'ensou-dsh-personal-installer-production-payload-self-check'
        command = '--production-payload-self-check'
        status = 'VERIFIED'
        installerSha256 = $InstallerSha256
        releaseSetId = [string]$Expectation.releaseSetId
        manifestSha256 = [string]$Expectation.manifestSha256
        manifestSizeBytes = [int64]$Expectation.manifestSizeBytes
        startupStubSha256 = [string]$Expectation.startupStubSha256
        startupStubSizeBytes = [int64]$Expectation.startupStubSizeBytes
        clientBundleSha256 = [string]$Expectation.clientBundleSha256
        clientBundleSizeBytes = [int64]$Expectation.clientBundleSizeBytes
        runtimeSha256 = [string]$Expectation.runtimeSha256
        runtimeSizeBytes = [int64]$Expectation.runtimeSizeBytes
    }
}

function ConvertTo-CanonicalLine {
    param([Parameter(Mandatory = $true)][psobject]$Value)

    [byte[]]$json = ProductionReleaseState\ConvertTo-ProductionJsonBytes -Value $Value
    [byte[]]$line = [byte[]]::new($json.Length + 1)
    [Array]::Copy($json, 0, $line, 0, $json.Length)
    $line[$line.Length - 1] = 0x0a
    return ,$line
}

function Copy-JsonObject {
    param([Parameter(Mandatory = $true)][psobject]$Value)

    return ($Value | ConvertTo-Json -Depth 64 -Compress |
        ConvertFrom-Json -Depth 64 -DateKind String)
}

function New-PwshStartInfo {
    param([Parameter(Mandatory = $true)][string]$Command)

    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = (Get-Process -Id $PID).Path
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in @(
            '-NoLogo',
            '-NoProfile',
            '-NonInteractive',
            '-Command',
            $Command)) {
        [void]$start.ArgumentList.Add($argument)
    }
    return $start
}

function Invoke-PrivateCapture {
    param(
        [Parameter(Mandatory = $true)][Diagnostics.ProcessStartInfo]$StartInfo,
        [int]$TimeoutMilliseconds = 10000,
        [int]$MaximumOutputBytes = 4096
    )

    return & $module {
        param($PrivateStartInfo, $PrivateTimeout, $PrivateMaximum)
        Invoke-PersonalInstallerBoundedProcessCapture `
            -StartInfo $PrivateStartInfo `
            -TimeoutMilliseconds $PrivateTimeout `
            -MaximumOutputBytes $PrivateMaximum
    } $StartInfo $TimeoutMilliseconds $MaximumOutputBytes
}

function Get-DefaultUnsignedPersonalInstallerPath {
    $repositoryRoot = [IO.Path]::GetFullPath(
        (Join-Path $PSScriptRoot '..\..'))
    $candidates = @(
        (Join-Path $repositoryRoot `
            'src\Ensou.Dsh.Personal.Installer\bin\Release\net10.0-windows\win-x64\Ensou.Dsh.Personal.Installer.exe'),
        (Join-Path $repositoryRoot `
            'src\Ensou.Dsh.Personal.Installer\bin\Debug\net10.0-windows\win-x64\Ensou.Dsh.Personal.Installer.exe')
    )
    foreach ($candidate in $candidates) {
        if ([IO.File]::Exists($candidate)) {
            return $candidate
        }
    }
    throw 'A real unsigned Personal Installer build is required. Build the focused Personal Installer project first or pass -UnsignedPersonalInstallerPath.'
}

try {
    Assert-True ([IO.File]::Exists($resultSchemaPath)) 'result schema exists'
    Assert-True ([IO.File]::Exists($evidenceSchemaPath)) 'evidence schema exists'
    $exports = @($module.ExportedFunctions.Keys | Sort-Object)
    Assert-Equal $exports.Count 2 'module exports only two public functions'
    Assert-Equal `
        $exports[0] `
        'ConvertFrom-PersonalInstallerProductionPayloadSelfCheckLine' `
        'pure parser export'
    Assert-Equal `
        $exports[1] `
        'Invoke-PersonalInstallerProductionPayloadSelfCheck' `
        'signed invocation export'

    $invokeCommand = Get-Command `
        -Module $module.Name `
        -Name Invoke-PersonalInstallerProductionPayloadSelfCheck
    foreach ($parameterName in @(
            'InstallerInput',
            'Response',
            'ExpectedSignerCertificateSha256',
            'Expectation',
            'TimeoutMilliseconds')) {
        Assert-True `
            $invokeCommand.Parameters.ContainsKey($parameterName) `
            "public Invoke parameter $parameterName"
    }
    Assert-True `
        (-not $invokeCommand.Parameters.ContainsKey('AuthenticodeEvidence')) `
        'public Invoke rejects forgeable Authenticode evidence input'
    Assert-True `
        (-not $invokeCommand.Parameters.ContainsKey('AllowUnsigned')) `
        'public Invoke has no unsigned bypass'

    $expectation = New-Expectation
    $installerSha256 = 'a' * 64
    $result = New-ResultObject `
        -Expectation $expectation `
        -InstallerSha256 $installerSha256
    [byte[]]$line = ConvertTo-CanonicalLine -Value $result
    $completedAtUtc = '2026-09-03T08:00:00Z'
    $evidence =
        ConvertFrom-PersonalInstallerProductionPayloadSelfCheckLine `
            -StandardOutputBytes $line `
            -InstallerSha256 $installerSha256 `
            -Expectation $expectation `
            -CompletedAtUtc $completedAtUtc
    $evidenceMembers = @($evidence.PSObject.Properties.Name)
    $expectedEvidenceMembers = @(
        'schemaVersion',
        'evidenceType',
        'command',
        'status',
        'exitCode',
        'inspectedInstallerSha256',
        'releaseSetId',
        'manifestSha256',
        'manifestSizeBytes',
        'startupStubSha256',
        'startupStubSizeBytes',
        'clientBundleSha256',
        'clientBundleSizeBytes',
        'runtimeSha256',
        'runtimeSizeBytes',
        'canonicalJsonSizeBytes',
        'canonicalJsonSha256',
        'canonicalLineSizeBytes',
        'canonicalLineSha256',
        'completedAtUtc'
    )
    Assert-Equal `
        ($evidenceMembers -join '|') `
        ($expectedEvidenceMembers -join '|') `
        'evidence member set and order'
    Assert-Equal $evidence.status 'VERIFIED' 'verified evidence status'
    Assert-Equal $evidence.exitCode 0 'verified evidence exit code'
    Assert-Equal `
        $evidence.inspectedInstallerSha256 `
        $installerSha256 `
        'verified Installer identity'
    [byte[]]$jsonBytes = [byte[]]::new($line.Length - 1)
    [Array]::Copy($line, 0, $jsonBytes, 0, $jsonBytes.Length)
    Assert-Equal `
        $evidence.canonicalJsonSizeBytes `
        ([int64]$jsonBytes.LongLength) `
        'canonical JSON byte count excludes LF'
    Assert-Equal `
        $evidence.canonicalJsonSha256 `
        (ProductionReleaseState\Get-ProductionSha256Bytes -Bytes $jsonBytes) `
        'canonical JSON SHA-256 excludes LF'
    Assert-Equal `
        $evidence.canonicalLineSizeBytes `
        ([int64]$line.LongLength) `
        'canonical line byte count includes LF'
    Assert-Equal `
        $evidence.canonicalLineSha256 `
        (ProductionReleaseState\Get-ProductionSha256Bytes -Bytes $line) `
        'canonical line SHA-256 includes LF'
    $evidenceJson = $evidence | ConvertTo-Json -Depth 64 -Compress
    Assert-True `
        (Test-Json -Json $evidenceJson -SchemaFile $evidenceSchemaPath) `
        'success evidence satisfies its schema'

    [byte[]]$oversized = [byte[]]::new(4097)
    $oversized[$oversized.Length - 1] = 0x0a
    Assert-FailsWithCode `
        -Code 'PERSONAL_SELF_CHECK_OUTPUT_LIMIT_EXCEEDED' `
        -Label 'oversized stdout' `
        -Action {
            ConvertFrom-PersonalInstallerProductionPayloadSelfCheckLine `
                -StandardOutputBytes $oversized `
                -InstallerSha256 $installerSha256 `
                -Expectation $expectation `
                -CompletedAtUtc $completedAtUtc
        }
    Assert-FailsWithCode `
        -Code 'PERSONAL_SELF_CHECK_LINE_FRAMING_INVALID' `
        -Label 'empty stdout' `
        -Action {
            ConvertFrom-PersonalInstallerProductionPayloadSelfCheckLine `
                -StandardOutputBytes ([byte[]]::new(0)) `
                -InstallerSha256 $installerSha256 `
                -Expectation $expectation `
                -CompletedAtUtc $completedAtUtc
        }
    [byte[]]$bomLine = [byte[]]::new($line.Length + 3)
    $bomLine[0] = 0xef
    $bomLine[1] = 0xbb
    $bomLine[2] = 0xbf
    [Array]::Copy($line, 0, $bomLine, 3, $line.Length)
    Assert-FailsWithCode `
        -Code 'PERSONAL_SELF_CHECK_LINE_FRAMING_INVALID' `
        -Label 'UTF-8 BOM' `
        -Action {
            ConvertFrom-PersonalInstallerProductionPayloadSelfCheckLine `
                -StandardOutputBytes $bomLine `
                -InstallerSha256 $installerSha256 `
                -Expectation $expectation `
                -CompletedAtUtc $completedAtUtc
        }
    [byte[]]$crlf = [byte[]]::new($line.Length + 1)
    [Array]::Copy($line, 0, $crlf, 0, $line.Length - 1)
    $crlf[$crlf.Length - 2] = 0x0d
    $crlf[$crlf.Length - 1] = 0x0a
    Assert-FailsWithCode `
        -Code 'PERSONAL_SELF_CHECK_LINE_FRAMING_INVALID' `
        -Label 'CRLF framing' `
        -Action {
            ConvertFrom-PersonalInstallerProductionPayloadSelfCheckLine `
                -StandardOutputBytes $crlf `
                -InstallerSha256 $installerSha256 `
                -Expectation $expectation `
                -CompletedAtUtc $completedAtUtc
        }
    Assert-FailsWithCode `
        -Code 'PERSONAL_SELF_CHECK_LINE_FRAMING_INVALID' `
        -Label 'missing terminal LF' `
        -Action {
            ConvertFrom-PersonalInstallerProductionPayloadSelfCheckLine `
                -StandardOutputBytes $jsonBytes `
                -InstallerSha256 $installerSha256 `
                -Expectation $expectation `
                -CompletedAtUtc $completedAtUtc
        }
    [byte[]]$doubleLf = [byte[]]::new($line.Length + 1)
    [Array]::Copy($line, 0, $doubleLf, 0, $line.Length)
    $doubleLf[$doubleLf.Length - 1] = 0x0a
    Assert-FailsWithCode `
        -Code 'PERSONAL_SELF_CHECK_LINE_FRAMING_INVALID' `
        -Label 'multiple logical lines' `
        -Action {
            ConvertFrom-PersonalInstallerProductionPayloadSelfCheckLine `
                -StandardOutputBytes $doubleLf `
                -InstallerSha256 $installerSha256 `
                -Expectation $expectation `
                -CompletedAtUtc $completedAtUtc
        }
    [byte[]]$invalidUtf8 = @(0xff, 0x0a)
    Assert-FailsWithCode `
        -Code 'PERSONAL_SELF_CHECK_UTF8_INVALID' `
        -Label 'invalid UTF-8' `
        -Action {
            ConvertFrom-PersonalInstallerProductionPayloadSelfCheckLine `
                -StandardOutputBytes $invalidUtf8 `
                -InstallerSha256 $installerSha256 `
                -Expectation $expectation `
                -CompletedAtUtc $completedAtUtc
        }

    $jsonText = $utf8.GetString($jsonBytes)
    $duplicateText = $jsonText.Replace(
        '{"schemaVersion":1,',
        '{"schemaVersion":1,"schemaVersion":1,')
    Assert-FailsWithCode `
        -Code 'PERSONAL_SELF_CHECK_JSON_INVALID' `
        -Label 'duplicate JSON member' `
        -Action {
            $bytes = $utf8.GetBytes($duplicateText + "`n")
            ConvertFrom-PersonalInstallerProductionPayloadSelfCheckLine `
                -StandardOutputBytes $bytes `
                -InstallerSha256 $installerSha256 `
                -Expectation $expectation `
                -CompletedAtUtc $completedAtUtc
        }
    $commentText = $jsonText.Replace(
        '{"schemaVersion":1,',
        '{/*comment*/"schemaVersion":1,')
    Assert-FailsWithCode `
        -Code 'PERSONAL_SELF_CHECK_JSON_INVALID' `
        -Label 'JSON comment' `
        -Action {
            $bytes = $utf8.GetBytes($commentText + "`n")
            ConvertFrom-PersonalInstallerProductionPayloadSelfCheckLine `
                -StandardOutputBytes $bytes `
                -InstallerSha256 $installerSha256 `
                -Expectation $expectation `
                -CompletedAtUtc $completedAtUtc
        }
    $trailingCommaText = $jsonText.Substring(0, $jsonText.Length - 1) + ',}'
    Assert-FailsWithCode `
        -Code 'PERSONAL_SELF_CHECK_JSON_INVALID' `
        -Label 'trailing JSON comma' `
        -Action {
            $bytes = $utf8.GetBytes($trailingCommaText + "`n")
            ConvertFrom-PersonalInstallerProductionPayloadSelfCheckLine `
                -StandardOutputBytes $bytes `
                -InstallerSha256 $installerSha256 `
                -Expectation $expectation `
                -CompletedAtUtc $completedAtUtc
        }
    Assert-FailsWithCode `
        -Code 'PERSONAL_SELF_CHECK_NONCANONICAL' `
        -Label 'leading JSON whitespace' `
        -Action {
            $bytes = $utf8.GetBytes(' ' + $jsonText + "`n")
            ConvertFrom-PersonalInstallerProductionPayloadSelfCheckLine `
                -StandardOutputBytes $bytes `
                -InstallerSha256 $installerSha256 `
                -Expectation $expectation `
                -CompletedAtUtc $completedAtUtc
        }

    $missing = New-ResultObject -Expectation $expectation
    $missing.PSObject.Properties.Remove('runtimeSizeBytes')
    Assert-FailsWithCode `
        -Code 'PERSONAL_SELF_CHECK_SCHEMA_INVALID' `
        -Label 'missing result member' `
        -Action {
            ConvertFrom-PersonalInstallerProductionPayloadSelfCheckLine `
                -StandardOutputBytes (ConvertTo-CanonicalLine $missing) `
                -InstallerSha256 $installerSha256 `
                -Expectation $expectation `
                -CompletedAtUtc $completedAtUtc
        }
    $additional = New-ResultObject -Expectation $expectation
    Add-Member -InputObject $additional -NotePropertyName unexpected -NotePropertyValue 1
    Assert-FailsWithCode `
        -Code 'PERSONAL_SELF_CHECK_SCHEMA_INVALID' `
        -Label 'additional result member' `
        -Action {
            ConvertFrom-PersonalInstallerProductionPayloadSelfCheckLine `
                -StandardOutputBytes (ConvertTo-CanonicalLine $additional) `
                -InstallerSha256 $installerSha256 `
                -Expectation $expectation `
                -CompletedAtUtc $completedAtUtc
        }
    $reordered = [pscustomobject][ordered]@{
        resultType = [string]$result.resultType
        schemaVersion = 1
        command = [string]$result.command
        status = [string]$result.status
        installerSha256 = [string]$result.installerSha256
        releaseSetId = [string]$result.releaseSetId
        manifestSha256 = [string]$result.manifestSha256
        manifestSizeBytes = [int64]$result.manifestSizeBytes
        startupStubSha256 = [string]$result.startupStubSha256
        startupStubSizeBytes = [int64]$result.startupStubSizeBytes
        clientBundleSha256 = [string]$result.clientBundleSha256
        clientBundleSizeBytes = [int64]$result.clientBundleSizeBytes
        runtimeSha256 = [string]$result.runtimeSha256
        runtimeSizeBytes = [int64]$result.runtimeSizeBytes
    }
    Assert-FailsWithCode `
        -Code 'PERSONAL_SELF_CHECK_NONCANONICAL' `
        -Label 'reordered result member' `
        -Action {
            ConvertFrom-PersonalInstallerProductionPayloadSelfCheckLine `
                -StandardOutputBytes (ConvertTo-CanonicalLine $reordered) `
                -InstallerSha256 $installerSha256 `
                -Expectation $expectation `
                -CompletedAtUtc $completedAtUtc
        }

    foreach ($case in @(
            [pscustomobject]@{
                Label = 'wrong command'
                Name = 'command'
                Value = '--development-payload-self-check'
            },
            [pscustomobject]@{
                Label = 'uppercase SHA-256'
                Name = 'manifestSha256'
                Value = 'A' * 64
            },
            [pscustomobject]@{
                Label = 'noninteger size'
                Name = 'manifestSizeBytes'
                Value = 1.5
            },
            [pscustomobject]@{
                Label = 'invalid releaseSetId'
                Name = 'releaseSetId'
                Value = '../escape'
            })) {
        $invalid = Copy-JsonObject $result
        $invalid.($case.Name) = $case.Value
        Assert-FailsWithCode `
            -Code 'PERSONAL_SELF_CHECK_SCHEMA_INVALID' `
            -Label $case.Label `
            -Action {
                ConvertFrom-PersonalInstallerProductionPayloadSelfCheckLine `
                    -StandardOutputBytes (ConvertTo-CanonicalLine $invalid) `
                    -InstallerSha256 $installerSha256 `
                    -Expectation $expectation `
                    -CompletedAtUtc $completedAtUtc
            }
    }

    $wrongInstaller = New-ResultObject `
        -Expectation $expectation `
        -InstallerSha256 ('b' * 64)
    Assert-FailsWithCode `
        -Code 'PERSONAL_SELF_CHECK_IDENTITY_MISMATCH' `
        -Label 'Installer identity mismatch' `
        -Action {
            ConvertFrom-PersonalInstallerProductionPayloadSelfCheckLine `
                -StandardOutputBytes (ConvertTo-CanonicalLine $wrongInstaller) `
                -InstallerSha256 $installerSha256 `
                -Expectation $expectation `
                -CompletedAtUtc $completedAtUtc
        }
    $wrongRelease = New-ResultObject -Expectation $expectation
    $wrongRelease.releaseSetId = 'personal-v2026.09.03.2'
    Assert-FailsWithCode `
        -Code 'PERSONAL_SELF_CHECK_IDENTITY_MISMATCH' `
        -Label 'release-set identity mismatch' `
        -Action {
            ConvertFrom-PersonalInstallerProductionPayloadSelfCheckLine `
                -StandardOutputBytes (ConvertTo-CanonicalLine $wrongRelease) `
                -InstallerSha256 $installerSha256 `
                -Expectation $expectation `
                -CompletedAtUtc $completedAtUtc
        }
    foreach ($name in @(
            'manifestSha256',
            'manifestSizeBytes',
            'startupStubSha256',
            'startupStubSizeBytes',
            'clientBundleSha256',
            'clientBundleSizeBytes',
            'runtimeSha256',
            'runtimeSizeBytes')) {
        $wrongPayload = New-ResultObject -Expectation $expectation
        if ($name.EndsWith('Sha256', [StringComparison]::Ordinal)) {
            $wrongPayload.$name = 'f' * 64
        }
        else {
            $wrongPayload.$name = [int64]$wrongPayload.$name + 1
        }
        Assert-FailsWithCode `
            -Code 'PERSONAL_SELF_CHECK_PAYLOAD_MISMATCH' `
            -Label "payload mismatch $name" `
            -Action {
                ConvertFrom-PersonalInstallerProductionPayloadSelfCheckLine `
                    -StandardOutputBytes (ConvertTo-CanonicalLine $wrongPayload) `
                    -InstallerSha256 $installerSha256 `
                    -Expectation $expectation `
                    -CompletedAtUtc $completedAtUtc
            }
    }

    $stringSizeExpectation = New-Expectation
    $stringSizeExpectation.manifestSizeBytes = '4096'
    Assert-FailsWithCode `
        -Code 'PERSONAL_SELF_CHECK_EXPECTATION_INVALID' `
        -Label 'string expectation size' `
        -Action {
            ConvertFrom-PersonalInstallerProductionPayloadSelfCheckLine `
                -StandardOutputBytes $line `
                -InstallerSha256 $installerSha256 `
                -Expectation $stringSizeExpectation `
                -CompletedAtUtc $completedAtUtc
        }
    $uppercaseExpectation = New-Expectation
    $uppercaseExpectation.runtimeSha256 = 'F' * 64
    Assert-FailsWithCode `
        -Code 'PERSONAL_SELF_CHECK_EXPECTATION_INVALID' `
        -Label 'uppercase expectation SHA-256' `
        -Action {
            ConvertFrom-PersonalInstallerProductionPayloadSelfCheckLine `
                -StandardOutputBytes $line `
                -InstallerSha256 $installerSha256 `
                -Expectation $uppercaseExpectation `
                -CompletedAtUtc $completedAtUtc
        }
    $oversizedClientExpectation = New-Expectation
    $oversizedClientExpectation.clientBundleSizeBytes = [int64](1GB + 1)
    Assert-FailsWithCode `
        -Code 'PERSONAL_SELF_CHECK_EXPECTATION_INVALID' `
        -Label 'client expectation exceeds signed manifest bound' `
        -Action {
            ConvertFrom-PersonalInstallerProductionPayloadSelfCheckLine `
                -StandardOutputBytes $line `
                -InstallerSha256 $installerSha256 `
                -Expectation $oversizedClientExpectation `
                -CompletedAtUtc $completedAtUtc
        }
    $reorderedExpectation = [pscustomobject][ordered]@{
        manifestSha256 = [string]$expectation.manifestSha256
        releaseSetId = [string]$expectation.releaseSetId
        manifestSizeBytes = [int64]$expectation.manifestSizeBytes
        startupStubSha256 = [string]$expectation.startupStubSha256
        startupStubSizeBytes = [int64]$expectation.startupStubSizeBytes
        clientBundleSha256 = [string]$expectation.clientBundleSha256
        clientBundleSizeBytes = [int64]$expectation.clientBundleSizeBytes
        runtimeSha256 = [string]$expectation.runtimeSha256
        runtimeSizeBytes = [int64]$expectation.runtimeSizeBytes
    }
    Assert-FailsWithCode `
        -Code 'PERSONAL_SELF_CHECK_EXPECTATION_INVALID' `
        -Label 'reordered expectation' `
        -Action {
            ConvertFrom-PersonalInstallerProductionPayloadSelfCheckLine `
                -StandardOutputBytes $line `
                -InstallerSha256 $installerSha256 `
                -Expectation $reorderedExpectation `
                -CompletedAtUtc $completedAtUtc
        }
    Assert-FailsWithCode `
        -Code 'PERSONAL_SELF_CHECK_EXPECTATION_INVALID' `
        -Label 'noncanonical completion time' `
        -Action {
            ConvertFrom-PersonalInstallerProductionPayloadSelfCheckLine `
                -StandardOutputBytes $line `
                -InstallerSha256 $installerSha256 `
                -Expectation $expectation `
                -CompletedAtUtc '2026-09-03T08:00:00.000Z'
        }

    $exactStart = New-PwshStartInfo -Command @'
$bytes = [Text.Encoding]::UTF8.GetBytes("exact`n")
$stream = [Console]::OpenStandardOutput()
$stream.Write($bytes, 0, $bytes.Length)
'@
    $exactCapture = Invoke-PrivateCapture -StartInfo $exactStart
    Assert-Equal $exactCapture.ExitCode 0 'private capture exact exit code'
    Assert-True (-not $exactCapture.TimedOut) 'private capture exact timeout state'
    Assert-True `
        (-not $exactCapture.StandardOutput.Overflowed) `
        'private capture exact stdout bound'
    Assert-Equal `
        $exactCapture.StandardError.Bytes.Length `
        0 `
        'private capture keeps stderr independent'
    Assert-ByteSequence `
        -Actual $exactCapture.StandardOutput.Bytes `
        -Expected ($utf8.GetBytes("exact`n")) `
        -Label 'private capture preserves raw stdout bytes'

    $stderrStart = New-PwshStartInfo -Command @'
$bytes = [byte[]](0x65)
$stream = [Console]::OpenStandardError()
$stream.Write($bytes, 0, $bytes.Length)
'@
    $stderrCapture = Invoke-PrivateCapture -StartInfo $stderrStart
    Assert-Equal $stderrCapture.StandardOutput.Bytes.Length 0 'stderr probe stdout'
    Assert-Equal $stderrCapture.StandardError.Bytes.Length 1 'stderr probe raw byte'

    $stderrOverflowStart = New-PwshStartInfo -Command @'
$bytes = [byte[]]::new(5000)
[Array]::Fill[byte]($bytes, 0x65)
$stream = [Console]::OpenStandardError()
$stream.Write($bytes, 0, $bytes.Length)
'@
    $stderrOverflowCapture = Invoke-PrivateCapture `
        -StartInfo $stderrOverflowStart `
        -MaximumOutputBytes 4096
    Assert-True `
        $stderrOverflowCapture.StandardError.Overflowed `
        'private capture detects stderr overflow'
    Assert-Equal `
        $stderrOverflowCapture.StandardError.Bytes.Length `
        4096 `
        'private capture retains only bounded stderr'

    $overflowStart = New-PwshStartInfo -Command @'
$bytes = [byte[]]::new(5000)
[Array]::Fill[byte]($bytes, 0x78)
$stream = [Console]::OpenStandardOutput()
$stream.Write($bytes, 0, $bytes.Length)
'@
    $overflowCapture = Invoke-PrivateCapture `
        -StartInfo $overflowStart `
        -MaximumOutputBytes 4096
    Assert-True `
        $overflowCapture.StandardOutput.Overflowed `
        'private capture detects stdout overflow'
    Assert-Equal `
        $overflowCapture.StandardOutput.Bytes.Length `
        4096 `
        'private capture retains only bounded stdout'

    $nonzeroStart = New-PwshStartInfo -Command 'exit 19'
    $nonzeroCapture = Invoke-PrivateCapture -StartInfo $nonzeroStart
    Assert-Equal $nonzeroCapture.ExitCode 19 'private capture preserves nonzero exit'
    Assert-Equal `
        $nonzeroCapture.StandardOutput.Bytes.Length `
        0 `
        'nonzero probe stdout remains independent'
    Assert-Equal `
        $nonzeroCapture.StandardError.Bytes.Length `
        0 `
        'nonzero probe stderr remains independent'

    $timeoutStart = New-PwshStartInfo -Command 'Start-Sleep -Seconds 30'
    $stopwatch = [Diagnostics.Stopwatch]::StartNew()
    $timeoutCapture = Invoke-PrivateCapture `
        -StartInfo $timeoutStart `
        -TimeoutMilliseconds 200
    $stopwatch.Stop()
    Assert-True $timeoutCapture.TimedOut 'private capture reports timeout'
    Assert-True `
        ($stopwatch.Elapsed -lt [TimeSpan]::FromSeconds(12)) `
        'private capture kills the timed-out process tree within its drain bound'

    if ([string]::IsNullOrWhiteSpace($UnsignedPersonalInstallerPath)) {
        $UnsignedPersonalInstallerPath = Get-DefaultUnsignedPersonalInstallerPath
    }
    $UnsignedPersonalInstallerPath = [IO.Path]::GetFullPath(
        $UnsignedPersonalInstallerPath)
    $unsignedStatus = Get-AuthenticodeSignature `
        -LiteralPath $UnsignedPersonalInstallerPath
    Assert-Equal `
        ([string]$unsignedStatus.Status) `
        'NotSigned' `
        'real Personal Installer fixture is unsigned'
    $unsignedInput = ProductionReleaseState\Open-ProductionReleaseInput `
        -Path $UnsignedPersonalInstallerPath `
        -Label 'Real unsigned Personal Installer fixture' `
        -MaximumBytes 1GB
    try {
        [byte[]]$unsignedBytes =
            ProductionReleaseState\Read-ProductionReleaseInputBytes `
                -Descriptor $unsignedInput `
                -Label 'Real unsigned Personal Installer fixture'
        $peContentSha256 =
            ProductionReleaseState\Get-PeContentSha256 -Bytes $unsignedBytes
        $unsignedResponse = [pscustomobject][ordered]@{
            signedInstaller = [pscustomobject][ordered]@{
                fileName = 'Ensou.Dsh.Personal.Installer.exe'
                sizeBytes = [int64]$unsignedInput.SizeBytes
                sha256 = [string]$unsignedInput.Sha256
                peContentSha256 = $peContentSha256
            }
            unsignedInstaller = [pscustomobject][ordered]@{
                peContentSha256 = $peContentSha256
            }
            authenticode = [pscustomobject][ordered]@{
                signerCertificateSha256 = 'a' * 64
                timestampSignerCertificateSha256 = 'b' * 64
                signerDigestAlgorithmOid = '2.16.840.1.101.3.4.2.1'
                spcIndirectDataContentTypeOid = '1.3.6.1.4.1.311.2.1.4'
                spcPeImageDataTypeOid = '1.3.6.1.4.1.311.2.1.15'
                spcDigestAlgorithmOid = '2.16.840.1.101.3.4.2.1'
                spcPeContentSha256 = $peContentSha256
                timestampUtc = '2026-09-03T08:00:00Z'
                rfc3161PrimarySignerBound = $true
            }
        }
        Assert-FailsWithCode `
            -Code 'PERSONAL_SELF_CHECK_SIGNED_ADMISSION_INVALID' `
            -Label 'real unsigned Personal Installer invocation' `
            -Action {
                Invoke-PersonalInstallerProductionPayloadSelfCheck `
                    -InstallerInput $unsignedInput `
                    -Response $unsignedResponse `
                    -ExpectedSignerCertificateSha256 ('a' * 64) `
                    -Expectation $expectation `
                    -TimeoutMilliseconds 10000
            }
        [void](ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
            -Descriptor $unsignedInput `
            -Label 'Rejected real unsigned Personal Installer fixture')
    }
    finally {
        $unsignedInput.Stream.Dispose()
    }

    [pscustomobject][ordered]@{
        status = 'PASS'
        assertions = $script:AssertionCount
        strictConsumerKernel = 'VERIFIED'
        realUnsignedInstallerInvocation = 'REJECTED_WITH_ZERO_EVIDENCE'
        realSignedInstallerGate = 'PENDING_REAL_AUTHENTICODE_RFC3161_FIXTURE'
        productionAdmission = 'NO_GO'
    } | ConvertTo-Json -Compress
}
finally {
    if ($null -ne $module) {
        Microsoft.PowerShell.Core\Remove-Module $module -Force -ErrorAction SilentlyContinue
    }
}
