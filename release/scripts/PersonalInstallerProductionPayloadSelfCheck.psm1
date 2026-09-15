#requires -Version 7.2

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$stateModulePath = Join-Path $PSScriptRoot 'ProductionReleaseState.psm1'
$signingModulePath = Join-Path $PSScriptRoot 'InstallerSigningContracts.psm1'
Microsoft.PowerShell.Core\Import-Module $stateModulePath -Force -ErrorAction Stop
Microsoft.PowerShell.Core\Import-Module $signingModulePath -Force -ErrorAction Stop
$captureModulePath = Join-Path $PSScriptRoot 'ProductionBoundedProcess.psm1'
Microsoft.PowerShell.Core\Import-Module $captureModulePath -Force -ErrorAction Stop

$schemaRoot = Join-Path ([IO.Path]::GetDirectoryName($PSScriptRoot)) 'schemas'
$script:ResultSchemaPath = Join-Path `
    $schemaRoot `
    'personal-installer-production-payload-self-check-result-v1.schema.json'
$script:EvidenceSchemaPath = Join-Path `
    $schemaRoot `
    'personal-installer-production-payload-self-check-evidence-v1.schema.json'
$script:Utf8Strict = [Text.UTF8Encoding]::new($false, $true)
$script:MaximumOutputBytes = 4096
$script:MaximumInstallerBytes = 1024MB
$script:ExpectedResultMembers = @(
    'schemaVersion',
    'resultType',
    'command',
    'status',
    'installerSha256',
    'releaseSetId',
    'manifestSha256',
    'manifestSizeBytes',
    'startupStubSha256',
    'startupStubSizeBytes',
    'clientBundleSha256',
    'clientBundleSizeBytes',
    'runtimeSha256',
    'runtimeSizeBytes'
)
$script:ExpectedExpectationMembers = @(
    'releaseSetId',
    'manifestSha256',
    'manifestSizeBytes',
    'startupStubSha256',
    'startupStubSizeBytes',
    'clientBundleSha256',
    'clientBundleSizeBytes',
    'runtimeSha256',
    'runtimeSizeBytes'
)

$script:ResultSchemaPath =
    ProductionReleaseState\Resolve-OrdinaryProductionFile `
        -Path $script:ResultSchemaPath `
        -Label 'Personal Installer production payload self-check result schema'
$script:EvidenceSchemaPath =
    ProductionReleaseState\Resolve-OrdinaryProductionFile `
        -Path $script:EvidenceSchemaPath `
        -Label 'Personal Installer production payload self-check evidence schema'

function Throw-PersonalInstallerSelfCheckFailure {
    param(
        [Parameter(Mandatory = $true)][string]$Code,
        [Parameter(Mandatory = $true)][string]$Message,
        [Exception]$InnerException
    )

    $fullMessage = "${Code}: $Message"
    if ($null -eq $InnerException) {
        throw [IO.InvalidDataException]::new($fullMessage)
    }
    throw [IO.InvalidDataException]::new($fullMessage, $InnerException)
}

function Test-PersonalInstallerSelfCheckFailure {
    param([Parameter(Mandatory = $true)][Exception]$Exception)

    return $Exception.Message -cmatch '^PERSONAL_SELF_CHECK_[A-Z0-9_]+:'
}

function Test-PersonalInstallerSelfCheckSha256 {
    param([AllowNull()][object]$Value)

    return $Value -is [string] -and
        [string]$Value -cmatch '^[0-9a-f]{64}$'
}

function Test-PersonalInstallerSelfCheckInteger {
    param([AllowNull()][object]$Value)

    return $Value -is [byte] -or
        $Value -is [sbyte] -or
        $Value -is [int16] -or
        $Value -is [uint16] -or
        $Value -is [int32] -or
        $Value -is [uint32] -or
        $Value -is [int64] -or
        $Value -is [uint64]
}

function Test-PersonalInstallerSelfCheckByteSequence {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Left,
        [Parameter(Mandatory = $true)][byte[]]$Right
    )

    if ($Left.Length -ne $Right.Length) {
        return $false
    }
    for ($index = 0; $index -lt $Left.Length; $index++) {
        if ($Left[$index] -ne $Right[$index]) {
            return $false
        }
    }
    return $true
}

function Get-PersonalInstallerSelfCheckValidatedExpectation {
    param([Parameter(Mandatory = $true)][psobject]$Expectation)

    try {
        [void](ProductionReleaseState\Assert-ExactProductionJsonMembers `
            -Value $Expectation `
            -Expected $script:ExpectedExpectationMembers `
            -Label 'Personal Installer payload self-check expectation')
    }
    catch {
        Throw-PersonalInstallerSelfCheckFailure `
            -Code 'PERSONAL_SELF_CHECK_EXPECTATION_INVALID' `
            -Message 'Expectation members are missing, additional, or noncanonical.' `
            -InnerException $_.Exception
    }

    if ([string]$Expectation.releaseSetId -cnotmatch
            '^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$') {
        Throw-PersonalInstallerSelfCheckFailure `
            -Code 'PERSONAL_SELF_CHECK_EXPECTATION_INVALID' `
            -Message 'The expected releaseSetId is invalid.'
    }
    foreach ($name in @(
            'manifestSha256',
            'startupStubSha256',
            'clientBundleSha256',
            'runtimeSha256')) {
        if (-not (Test-PersonalInstallerSelfCheckSha256 -Value $Expectation.$name)) {
            Throw-PersonalInstallerSelfCheckFailure `
                -Code 'PERSONAL_SELF_CHECK_EXPECTATION_INVALID' `
                -Message "The expected $name is not one lowercase SHA-256 value."
        }
    }
    $sizeBounds = [ordered]@{
        manifestSizeBytes = 2MB
        startupStubSizeBytes = 512MB
        clientBundleSizeBytes = 1GB
        runtimeSizeBytes = 8GB
    }
    foreach ($name in $sizeBounds.Keys) {
        $value = $Expectation.$name
        if (-not (Test-PersonalInstallerSelfCheckInteger -Value $value) -or
            [decimal]$value -lt 1 -or
            [decimal]$value -gt [decimal]$sizeBounds[$name]) {
            Throw-PersonalInstallerSelfCheckFailure `
                -Code 'PERSONAL_SELF_CHECK_EXPECTATION_INVALID' `
                -Message "The expected $name is outside its exact byte bound."
        }
    }

    return [pscustomobject][ordered]@{
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

function Assert-PersonalInstallerSelfCheckInputLocked {
    param(
        [Parameter(Mandatory = $true)]$InstallerInput,
        [Parameter(Mandatory = $true)][string]$FailureCode,
        [Parameter(Mandatory = $true)][string]$Stage
    )

    try {
        foreach ($name in @(
                'Path',
                'FileName',
                'SizeBytes',
                'Sha256',
                'Stream',
                'VolumeSerialNumber',
                'FileIndex')) {
            if ($null -eq $InstallerInput.PSObject.Properties[$name]) {
                throw "Installer descriptor has no $name member."
            }
        }
        if ([string]$InstallerInput.FileName -cne
                'Ensou.Dsh.Personal.Installer.exe' -or
            -not [IO.Path]::IsPathFullyQualified([string]$InstallerInput.Path) -or
            [int64]$InstallerInput.SizeBytes -le 0 -or
            [int64]$InstallerInput.SizeBytes -gt $script:MaximumInstallerBytes -or
            -not (Test-PersonalInstallerSelfCheckSha256 -Value $InstallerInput.Sha256) -or
            $InstallerInput.Stream -isnot [IO.Stream] -or
            -not $InstallerInput.Stream.CanRead -or
            -not $InstallerInput.Stream.CanSeek) {
            throw 'Installer descriptor identity is invalid.'
        }
        [void](ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
            -Descriptor $InstallerInput `
            -Label "Personal signed Installer $Stage")
    }
    catch {
        Throw-PersonalInstallerSelfCheckFailure `
            -Code $FailureCode `
            -Message "The Personal signed Installer descriptor is invalid or changed $Stage." `
            -InnerException $_.Exception
    }
}

function Open-PersonalInstallerSelfCheckExecutionLock {
    param([Parameter(Mandatory = $true)]$InstallerInput)

    $executionInput = $null
    try {
        $executionInput = ProductionReleaseState\Open-ProductionReleaseInput `
            -Path ([string]$InstallerInput.Path) `
            -Label 'Personal signed Installer execution lock' `
            -MaximumBytes $script:MaximumInstallerBytes
        if ([string]$executionInput.Path -cne [string]$InstallerInput.Path -or
            [string]$executionInput.FileName -cne [string]$InstallerInput.FileName -or
            [int64]$executionInput.SizeBytes -ne [int64]$InstallerInput.SizeBytes -or
            [string]$executionInput.Sha256 -cne [string]$InstallerInput.Sha256 -or
            [uint32]$executionInput.VolumeSerialNumber -ne
                [uint32]$InstallerInput.VolumeSerialNumber -or
            [uint64]$executionInput.FileIndex -ne
                [uint64]$InstallerInput.FileIndex) {
            throw 'The private execution lock differs from the caller-held descriptor.'
        }
        return $executionInput
    }
    catch {
        if ($null -ne $executionInput -and $null -ne $executionInput.Stream) {
            $executionInput.Stream.Dispose()
        }
        Throw-PersonalInstallerSelfCheckFailure `
            -Code 'PERSONAL_SELF_CHECK_INSTALLER_LOCK_INVALID' `
            -Message 'A private immutable execution lock could not be acquired for the Personal signed Installer.' `
            -InnerException $_.Exception
    }
}

function ConvertFrom-PersonalInstallerProductionPayloadSelfCheckLine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$StandardOutputBytes,
        [Parameter(Mandatory = $true)][string]$InstallerSha256,
        [Parameter(Mandatory = $true)][psobject]$Expectation,
        [Parameter(Mandatory = $true)][string]$CompletedAtUtc
    )

    $validatedExpectation =
        Get-PersonalInstallerSelfCheckValidatedExpectation -Expectation $Expectation
    if (-not (Test-PersonalInstallerSelfCheckSha256 -Value $InstallerSha256)) {
        Throw-PersonalInstallerSelfCheckFailure `
            -Code 'PERSONAL_SELF_CHECK_EXPECTATION_INVALID' `
            -Message 'The expected Installer SHA-256 is invalid.'
    }
    try {
        [void](ProductionReleaseState\ConvertFrom-ProductionUtc `
            -Value $CompletedAtUtc `
            -Label 'Personal Installer payload self-check completion time')
    }
    catch {
        Throw-PersonalInstallerSelfCheckFailure `
            -Code 'PERSONAL_SELF_CHECK_EXPECTATION_INVALID' `
            -Message 'The completion time is not exact whole-second UTC.' `
            -InnerException $_.Exception
    }
    if ($StandardOutputBytes.Length -gt $script:MaximumOutputBytes) {
        Throw-PersonalInstallerSelfCheckFailure `
            -Code 'PERSONAL_SELF_CHECK_OUTPUT_LIMIT_EXCEEDED' `
            -Message 'Canonical stdout exceeds 4096 bytes.'
    }
    if ($StandardOutputBytes.Length -lt 2 -or
        ($StandardOutputBytes.Length -ge 3 -and
         $StandardOutputBytes[0] -eq 0xef -and
         $StandardOutputBytes[1] -eq 0xbb -and
         $StandardOutputBytes[2] -eq 0xbf)) {
        Throw-PersonalInstallerSelfCheckFailure `
            -Code 'PERSONAL_SELF_CHECK_LINE_FRAMING_INVALID' `
            -Message 'Canonical stdout is empty, truncated, or starts with a UTF-8 BOM.'
    }
    [int]$lineFeedCount = 0
    for ($index = 0; $index -lt $StandardOutputBytes.Length; $index++) {
        if ($StandardOutputBytes[$index] -eq 0x0d) {
            Throw-PersonalInstallerSelfCheckFailure `
                -Code 'PERSONAL_SELF_CHECK_LINE_FRAMING_INVALID' `
                -Message 'Canonical stdout contains a carriage return.'
        }
        if ($StandardOutputBytes[$index] -eq 0x0a) {
            $lineFeedCount++
            if ($index -ne $StandardOutputBytes.Length - 1) {
                Throw-PersonalInstallerSelfCheckFailure `
                    -Code 'PERSONAL_SELF_CHECK_LINE_FRAMING_INVALID' `
                    -Message 'Canonical stdout contains more than one logical line.'
            }
        }
    }
    if ($lineFeedCount -ne 1 -or
        $StandardOutputBytes[$StandardOutputBytes.Length - 1] -ne 0x0a) {
        Throw-PersonalInstallerSelfCheckFailure `
            -Code 'PERSONAL_SELF_CHECK_LINE_FRAMING_INVALID' `
            -Message 'Canonical stdout must end in one exact LF.'
    }

    [byte[]]$jsonBytes = [byte[]]::new($StandardOutputBytes.Length - 1)
    [Array]::Copy(
        $StandardOutputBytes,
        0,
        $jsonBytes,
        0,
        $jsonBytes.Length)
    try {
        $jsonText = $script:Utf8Strict.GetString($jsonBytes)
    }
    catch {
        Throw-PersonalInstallerSelfCheckFailure `
            -Code 'PERSONAL_SELF_CHECK_UTF8_INVALID' `
            -Message 'Canonical stdout is not strict UTF-8.' `
            -InnerException $_.Exception
    }
    try {
        $result = ProductionReleaseState\ConvertFrom-StrictProductionJsonBytes `
            -Bytes $jsonBytes `
            -Label 'Personal Installer production payload self-check result'
    }
    catch {
        Throw-PersonalInstallerSelfCheckFailure `
            -Code 'PERSONAL_SELF_CHECK_JSON_INVALID' `
            -Message 'Canonical stdout is not strict duplicate-free JSON.' `
            -InnerException $_.Exception
    }
    try {
        $schemaAccepted = Microsoft.PowerShell.Utility\Test-Json `
            -Json $jsonText `
            -SchemaFile $script:ResultSchemaPath `
            -ErrorAction Stop
    }
    catch {
        Throw-PersonalInstallerSelfCheckFailure `
            -Code 'PERSONAL_SELF_CHECK_SCHEMA_INVALID' `
            -Message 'Canonical stdout could not be validated against the result schema.' `
            -InnerException $_.Exception
    }
    if (-not $schemaAccepted) {
        Throw-PersonalInstallerSelfCheckFailure `
            -Code 'PERSONAL_SELF_CHECK_SCHEMA_INVALID' `
            -Message 'Canonical stdout does not satisfy the exact result schema.'
    }
    try {
        [void](ProductionReleaseState\Assert-ExactProductionJsonMembers `
            -Value $result `
            -Expected $script:ExpectedResultMembers `
            -Label 'Personal Installer production payload self-check result')
    }
    catch {
        Throw-PersonalInstallerSelfCheckFailure `
            -Code 'PERSONAL_SELF_CHECK_NONCANONICAL' `
            -Message 'Result member order is not canonical.' `
            -InnerException $_.Exception
    }
    [byte[]]$canonicalBytes =
        ProductionReleaseState\ConvertTo-ProductionJsonBytes -Value $result
    if (-not (Test-PersonalInstallerSelfCheckByteSequence `
            -Left $canonicalBytes `
            -Right $jsonBytes)) {
        Throw-PersonalInstallerSelfCheckFailure `
            -Code 'PERSONAL_SELF_CHECK_NONCANONICAL' `
            -Message 'Result JSON bytes differ from their canonical serialization.'
    }
    if (-not (Test-PersonalInstallerSelfCheckInteger -Value $result.schemaVersion) -or
        [int64]$result.schemaVersion -ne 1 -or
        [string]$result.resultType -cne
            'ensou-dsh-personal-installer-production-payload-self-check' -or
        [string]$result.command -cne '--production-payload-self-check' -or
        [string]$result.status -cne 'VERIFIED' -or
        [string]$result.releaseSetId -cnotmatch
            '^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$') {
        Throw-PersonalInstallerSelfCheckFailure `
            -Code 'PERSONAL_SELF_CHECK_SCHEMA_INVALID' `
            -Message 'Result identity constants are outside the exact protocol.'
    }
    foreach ($name in @(
            'installerSha256',
            'manifestSha256',
            'startupStubSha256',
            'clientBundleSha256',
            'runtimeSha256')) {
        if (-not (Test-PersonalInstallerSelfCheckSha256 -Value $result.$name)) {
            Throw-PersonalInstallerSelfCheckFailure `
                -Code 'PERSONAL_SELF_CHECK_SCHEMA_INVALID' `
                -Message "Result $name is not one lowercase SHA-256 value."
        }
    }
    $resultSizeBounds = [ordered]@{
        manifestSizeBytes = 2MB
        startupStubSizeBytes = 512MB
        clientBundleSizeBytes = 1GB
        runtimeSizeBytes = 8GB
    }
    foreach ($name in $resultSizeBounds.Keys) {
        if (-not (Test-PersonalInstallerSelfCheckInteger -Value $result.$name) -or
            [decimal]$result.$name -lt 1 -or
            [decimal]$result.$name -gt [decimal]$resultSizeBounds[$name]) {
            Throw-PersonalInstallerSelfCheckFailure `
                -Code 'PERSONAL_SELF_CHECK_SCHEMA_INVALID' `
                -Message "Result $name is outside its exact byte bound."
        }
    }
    if ([string]$result.installerSha256 -cne $InstallerSha256 -or
        [string]$result.releaseSetId -cne $validatedExpectation.releaseSetId) {
        Throw-PersonalInstallerSelfCheckFailure `
            -Code 'PERSONAL_SELF_CHECK_IDENTITY_MISMATCH' `
            -Message 'Result Installer or release-set identity differs from the locked expectation.'
    }
    if ([string]$result.manifestSha256 -cne
            $validatedExpectation.manifestSha256 -or
        [int64]$result.manifestSizeBytes -ne
            $validatedExpectation.manifestSizeBytes -or
        [string]$result.startupStubSha256 -cne
            $validatedExpectation.startupStubSha256 -or
        [int64]$result.startupStubSizeBytes -ne
            $validatedExpectation.startupStubSizeBytes -or
        [string]$result.clientBundleSha256 -cne
            $validatedExpectation.clientBundleSha256 -or
        [int64]$result.clientBundleSizeBytes -ne
            $validatedExpectation.clientBundleSizeBytes -or
        [string]$result.runtimeSha256 -cne
            $validatedExpectation.runtimeSha256 -or
        [int64]$result.runtimeSizeBytes -ne
            $validatedExpectation.runtimeSizeBytes) {
        Throw-PersonalInstallerSelfCheckFailure `
            -Code 'PERSONAL_SELF_CHECK_PAYLOAD_MISMATCH' `
            -Message 'Result payload identities differ from the exact expected embedded payload.'
    }

    $evidence = [pscustomobject][ordered]@{
        schemaVersion = 1
        evidenceType =
            'ensou-dsh-personal-installer-production-payload-self-check-consumption'
        command = '--production-payload-self-check'
        status = 'VERIFIED'
        exitCode = 0
        inspectedInstallerSha256 = $InstallerSha256
        releaseSetId = $validatedExpectation.releaseSetId
        manifestSha256 = $validatedExpectation.manifestSha256
        manifestSizeBytes = $validatedExpectation.manifestSizeBytes
        startupStubSha256 = $validatedExpectation.startupStubSha256
        startupStubSizeBytes = $validatedExpectation.startupStubSizeBytes
        clientBundleSha256 = $validatedExpectation.clientBundleSha256
        clientBundleSizeBytes = $validatedExpectation.clientBundleSizeBytes
        runtimeSha256 = $validatedExpectation.runtimeSha256
        runtimeSizeBytes = $validatedExpectation.runtimeSizeBytes
        canonicalJsonSizeBytes = [int64]$jsonBytes.LongLength
        canonicalJsonSha256 =
            ProductionReleaseState\Get-ProductionSha256Bytes -Bytes $jsonBytes
        canonicalLineSizeBytes = [int64]$StandardOutputBytes.LongLength
        canonicalLineSha256 =
            ProductionReleaseState\Get-ProductionSha256Bytes `
                -Bytes $StandardOutputBytes
        completedAtUtc = $CompletedAtUtc
    }
    try {
        $evidenceText = $script:Utf8Strict.GetString(
            (ProductionReleaseState\ConvertTo-ProductionJsonBytes -Value $evidence))
        $evidenceAccepted = Microsoft.PowerShell.Utility\Test-Json `
            -Json $evidenceText `
            -SchemaFile $script:EvidenceSchemaPath `
            -ErrorAction Stop
    }
    catch {
        Throw-PersonalInstallerSelfCheckFailure `
            -Code 'PERSONAL_SELF_CHECK_EVIDENCE_INVALID' `
            -Message 'Verified result could not produce its exact evidence contract.' `
            -InnerException $_.Exception
    }
    if (-not $evidenceAccepted) {
        Throw-PersonalInstallerSelfCheckFailure `
            -Code 'PERSONAL_SELF_CHECK_EVIDENCE_INVALID' `
            -Message 'Verified result does not satisfy its exact evidence contract.'
    }
    return $evidence
}

function New-PersonalInstallerSelfCheckProcessStartInfo {
    param(
        [Parameter(Mandatory = $true)]$InstallerInput,
        [Parameter(Mandatory = $true)][psobject]$Expectation
    )

    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = [string]$InstallerInput.Path
    $start.WorkingDirectory = [IO.Path]::GetDirectoryName(
        [string]$InstallerInput.Path)
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in @(
            '--production-payload-self-check',
            $Expectation.releaseSetId,
            $Expectation.manifestSha256,
            ([int64]$Expectation.manifestSizeBytes).ToString(
                [Globalization.CultureInfo]::InvariantCulture),
            $Expectation.startupStubSha256,
            ([int64]$Expectation.startupStubSizeBytes).ToString(
                [Globalization.CultureInfo]::InvariantCulture),
            $Expectation.clientBundleSha256,
            ([int64]$Expectation.clientBundleSizeBytes).ToString(
                [Globalization.CultureInfo]::InvariantCulture),
            $Expectation.runtimeSha256,
            ([int64]$Expectation.runtimeSizeBytes).ToString(
                [Globalization.CultureInfo]::InvariantCulture))) {
        [void]$start.ArgumentList.Add([string]$argument)
    }

    $start.Environment.Clear()
    $systemRoot = [Environment]::GetEnvironmentVariable('SystemRoot')
    if ([string]::IsNullOrWhiteSpace($systemRoot)) {
        $systemRoot = [Environment]::GetFolderPath(
            [Environment+SpecialFolder]::Windows)
    }
    if ([string]::IsNullOrWhiteSpace($systemRoot)) {
        Throw-PersonalInstallerSelfCheckFailure `
            -Code 'PERSONAL_SELF_CHECK_PROCESS_START_FAILED' `
            -Message 'The native Windows system directory is unavailable.'
    }
    $temporaryRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    $noDotNetRoot = Join-Path $temporaryRoot 'ensou-personal-self-check-no-dotnet'
    $start.Environment['SystemRoot'] = $systemRoot
    $start.Environment['WINDIR'] = $systemRoot
    $start.Environment['PATH'] = Join-Path $systemRoot 'System32'
    $start.Environment['TEMP'] = $temporaryRoot
    $start.Environment['TMP'] = $temporaryRoot
    $start.Environment['DOTNET_ROOT'] = $noDotNetRoot
    $start.Environment['DOTNET_ROOT_X64'] = $noDotNetRoot
    $start.Environment['DOTNET_MULTILEVEL_LOOKUP'] = '0'
    $start.Environment['DOTNET_EnableDiagnostics'] = '0'
    $start.Environment['COMPlus_EnableDiagnostics'] = '0'
    return $start
}

function Invoke-PersonalInstallerBoundedProcessCapture {
    param(
        [Parameter(Mandatory = $true)][Diagnostics.ProcessStartInfo]$StartInfo,
        [Parameter(Mandatory = $true)][int]$TimeoutMilliseconds,
        [int]$MaximumOutputBytes = $script:MaximumOutputBytes
    )

    return ProductionBoundedProcess\Invoke-ProductionBoundedProcessCapture `
        -StartInfo $StartInfo `
        -TimeoutMilliseconds $TimeoutMilliseconds `
        -MaximumOutputBytes $MaximumOutputBytes
}

function Invoke-PersonalInstallerProductionPayloadSelfCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$InstallerInput,
        [Parameter(Mandatory = $true)][psobject]$Response,
        [Parameter(Mandatory = $true)][string]$ExpectedSignerCertificateSha256,
        [Parameter(Mandatory = $true)][psobject]$Expectation,
        [ValidateRange(100, 300000)][int]$TimeoutMilliseconds = 300000
    )

    $validatedExpectation =
        Get-PersonalInstallerSelfCheckValidatedExpectation -Expectation $Expectation
    if (-not (Test-PersonalInstallerSelfCheckSha256 `
            -Value $ExpectedSignerCertificateSha256)) {
        Throw-PersonalInstallerSelfCheckFailure `
            -Code 'PERSONAL_SELF_CHECK_EXPECTATION_INVALID' `
            -Message 'The expected Authenticode signer certificate SHA-256 is invalid.'
    }
    Assert-PersonalInstallerSelfCheckInputLocked `
        -InstallerInput $InstallerInput `
        -FailureCode 'PERSONAL_SELF_CHECK_INSTALLER_LOCK_INVALID' `
        -Stage 'before Authenticode verification'
    $executionInput = Open-PersonalInstallerSelfCheckExecutionLock `
        -InstallerInput $InstallerInput
    try {
        Assert-PersonalInstallerSelfCheckInputLocked `
            -InstallerInput $executionInput `
            -FailureCode 'PERSONAL_SELF_CHECK_INSTALLER_LOCK_INVALID' `
            -Stage 'under the private lock before Authenticode verification'
        try {
            # Response authentication is an importer precondition. This module still
            # performs the complete local Authenticode/RFC3161 check itself before it
            # permits the authenticated response to authorize process execution.
            $authenticodeEvidence =
                InstallerSigningContracts\Assert-SignedInstallerAuthenticode `
                    -Path ([string]$executionInput.Path) `
                    -Response $Response `
                    -ExpectedSignerCertificateSha256 `
                        $ExpectedSignerCertificateSha256
            if ([string]$authenticodeEvidence.AuthenticodeStatus -cne 'Valid' -or
                [string]$authenticodeEvidence.SignedInstallerSha256 -cne
                    [string]$executionInput.Sha256 -or
                [string]$authenticodeEvidence.SignerCertificateSha256 -cne
                    $ExpectedSignerCertificateSha256) {
                throw 'Returned Authenticode evidence differs from the held Installer.'
            }
        }
        catch {
            Throw-PersonalInstallerSelfCheckFailure `
                -Code 'PERSONAL_SELF_CHECK_SIGNED_ADMISSION_INVALID' `
                -Message 'The held Installer did not satisfy the authenticated Authenticode and RFC3161 response.' `
                -InnerException $_.Exception
        }
        Assert-PersonalInstallerSelfCheckInputLocked `
            -InstallerInput $executionInput `
            -FailureCode 'PERSONAL_SELF_CHECK_INSTALLER_CHANGED' `
            -Stage 'after Authenticode verification'

        $start = New-PersonalInstallerSelfCheckProcessStartInfo `
            -InstallerInput $executionInput `
            -Expectation $validatedExpectation
        $capture = $null
        $captureFailure = $null
        try {
            $capture = Invoke-PersonalInstallerBoundedProcessCapture `
                -StartInfo $start `
                -TimeoutMilliseconds $TimeoutMilliseconds `
                -MaximumOutputBytes $script:MaximumOutputBytes
        }
        catch {
            $captureFailure = $_
        }
        Assert-PersonalInstallerSelfCheckInputLocked `
            -InstallerInput $executionInput `
            -FailureCode 'PERSONAL_SELF_CHECK_INSTALLER_CHANGED' `
            -Stage 'after the production payload self-check process attempt'
        if ($null -ne $captureFailure) {
            if (Test-PersonalInstallerSelfCheckFailure `
                    -Exception $captureFailure.Exception) {
                throw $captureFailure
            }
            $code = if (
                $captureFailure.Exception -is [ComponentModel.Win32Exception] -or
                $captureFailure.Exception.InnerException -is
                    [ComponentModel.Win32Exception]) {
                'PERSONAL_SELF_CHECK_PROCESS_START_FAILED'
            }
            else {
                'PERSONAL_SELF_CHECK_PROCESS_CAPTURE_FAILED'
            }
            Throw-PersonalInstallerSelfCheckFailure `
                -Code $code `
                -Message 'The Personal Installer self-check process could not be captured safely.' `
                -InnerException $captureFailure.Exception
        }
        if ([bool]$capture.TimedOut) {
            Throw-PersonalInstallerSelfCheckFailure `
                -Code 'PERSONAL_SELF_CHECK_TIMEOUT' `
                -Message 'The Personal Installer self-check exceeded its bounded execution time.'
        }
        if ([bool]$capture.StandardOutput.Overflowed -or
            [bool]$capture.StandardError.Overflowed) {
            Throw-PersonalInstallerSelfCheckFailure `
                -Code 'PERSONAL_SELF_CHECK_OUTPUT_LIMIT_EXCEEDED' `
                -Message 'The Personal Installer self-check exceeded its redirected output bound.'
        }
        if ([int]$capture.StandardError.Bytes.Length -ne 0) {
            Throw-PersonalInstallerSelfCheckFailure `
                -Code 'PERSONAL_SELF_CHECK_STDERR_NOT_EMPTY' `
                -Message 'The Personal Installer self-check emitted unexpected stderr bytes.'
        }
        if ([int]$capture.ExitCode -ne 0) {
            Throw-PersonalInstallerSelfCheckFailure `
                -Code 'PERSONAL_SELF_CHECK_EXIT_NONZERO' `
                -Message "The Personal Installer self-check exited with code $($capture.ExitCode)."
        }

        $completedAtUtc = ProductionReleaseState\ConvertTo-ProductionUtc `
            -Value ([DateTimeOffset]::UtcNow)
        $evidence =
            ConvertFrom-PersonalInstallerProductionPayloadSelfCheckLine `
                -StandardOutputBytes $capture.StandardOutput.Bytes `
                -InstallerSha256 ([string]$executionInput.Sha256) `
                -Expectation $validatedExpectation `
                -CompletedAtUtc $completedAtUtc
        Assert-PersonalInstallerSelfCheckInputLocked `
            -InstallerInput $executionInput `
            -FailureCode 'PERSONAL_SELF_CHECK_INSTALLER_CHANGED' `
            -Stage 'before returning verified evidence'
        return $evidence
    }
    finally {
        $executionInput.Stream.Dispose()
    }
}

Export-ModuleMember -Function @(
    'ConvertFrom-PersonalInstallerProductionPayloadSelfCheckLine',
    'Invoke-PersonalInstallerProductionPayloadSelfCheck'
)
