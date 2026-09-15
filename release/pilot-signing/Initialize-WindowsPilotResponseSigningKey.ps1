#requires -Version 7.2

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('I UNDERSTAND THIS CREATES A NON-EXPORTABLE PILOT RESPONSE KEY')]
    [string]$PilotOnlyConfirmation,

    [Parameter(Mandatory = $true)]
    [ValidateSet(
        'ClientSigningResponse',
        'PersonalInstallerSigningResponse',
        'EnterpriseInstallerSigningResponse')]
    [string]$Purpose,

    [ValidateSet('PersonalTwoDevice', 'EnterpriseTwoDevice')]
    [string]$PilotProfile = 'PersonalTwoDevice',

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$')]
    [string]$KeyName,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$')]
    [string]$KeyId,

    [Parameter(Mandatory = $true)][string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = Join-Path $PSScriptRoot 'WindowsPilotSigning.psm1'
Microsoft.PowerShell.Core\Import-Module $modulePath -Force -ErrorAction Stop

if (-not [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
        [Runtime.InteropServices.OSPlatform]::Windows) -or
    [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne
        [Runtime.InteropServices.Architecture]::X64 -or
    [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -ne
        [Runtime.InteropServices.Architecture]::X64) {
    throw 'The Pilot response-key initializer requires native Windows x64 and x64 PowerShell.'
}
if (-not (Test-WindowsLocalAbsolutePathShape -Path $OutputPath)) {
    throw 'OutputPath must be one canonical fixed-local absolute file path.'
}

$outputFullPath = [IO.Path]::GetFullPath($OutputPath)
if ([IO.Path]::GetExtension($outputFullPath) -cne '.json') {
    throw 'OutputPath must use the lowercase .json extension.'
}
$parentPath = [IO.Path]::GetDirectoryName($outputFullPath)
$parentObservation = Get-WindowsNoFollowPathObservation `
    -Path $parentPath -ExpectedKind Directory
if (-not [bool]$parentObservation.safe) {
    throw 'OutputPath parent must be one existing no-follow-safe fixed-local directory.'
}
$outputObservation = Get-WindowsNoFollowPathObservation `
    -Path $outputFullPath -ExpectedKind File
if ([bool]$outputObservation.safe -or
    [bool]$outputObservation.reparseDetected -or
    [int]$outputObservation.blockedComponentIndex -ne
        ([int]$outputObservation.totalComponentCount - 1)) {
    throw 'OutputPath must be an absent final component below the safe parent.'
}

$provider = [Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider
if ([Security.Cryptography.CngKey]::Exists(
        $KeyName,
        $provider,
        [Security.Cryptography.CngKeyOpenOptions]::UserKey)) {
    throw 'The requested CurrentUser CNG key name already exists.'
}

$purposeValue = switch ($Purpose) {
    'ClientSigningResponse' { 'client-signing-response' }
    'PersonalInstallerSigningResponse' { 'personal-installer-signing-response' }
    'EnterpriseInstallerSigningResponse' { 'installer-signing-response' }
}
if (($Purpose -ceq 'PersonalInstallerSigningResponse' -and
        $PilotProfile -cne 'PersonalTwoDevice') -or
    ($Purpose -ceq 'EnterpriseInstallerSigningResponse' -and
        $PilotProfile -cne 'EnterpriseTwoDevice')) {
    throw 'Installer response-key purpose must match its exact two-device Pilot profile.'
}
$targetDescription =
    "CurrentUser CNG ECDSA P-256 key '$KeyName' for '$PilotProfile/$purposeValue'; public JSON '$outputFullPath'"
if (-not $PSCmdlet.ShouldProcess(
        $targetDescription,
        'Create a non-exportable isolated Pilot response-signing key')) {
    return
}

$creation = [Security.Cryptography.CngKeyCreationParameters]::new()
$creation.Provider = $provider
$creation.ExportPolicy = [Security.Cryptography.CngExportPolicies]::None
$creation.KeyUsage = [Security.Cryptography.CngKeyUsages]::Signing
$creation.KeyCreationOptions = [Security.Cryptography.CngKeyCreationOptions]::None

$key = $null
$ecdsa = $null
$created = $false
try {
    $key = [Security.Cryptography.CngKey]::Create(
        [Security.Cryptography.CngAlgorithm]::ECDsaP256,
        $KeyName,
        $creation)
    $created = $true
    if ($key.IsMachineKey -or
        $key.Provider.Provider -cne $provider.Provider -or
        $key.Algorithm.Algorithm -cne
            [Security.Cryptography.CngAlgorithm]::ECDsaP256.Algorithm -or
        [int]$key.ExportPolicy -ne
            [int][Security.Cryptography.CngExportPolicies]::None -or
        ($key.KeyUsage -band [Security.Cryptography.CngKeyUsages]::Signing) -eq 0) {
        throw 'Created response key did not preserve the exact CurrentUser non-exportable CNG P-256 policy.'
    }

    $ecdsa = [Security.Cryptography.ECDsaCng]::new($key)
    $public = $ecdsa.ExportParameters($false)
    if ($public.Q.X.Length -ne 32 -or $public.Q.Y.Length -ne 32) {
        throw 'Created response key did not expose one exact P-256 public point.'
    }
    $base64Url = {
        param([byte[]]$Bytes)
        [Convert]::ToBase64String($Bytes).TrimEnd('=').
            Replace('+', '-').Replace('/', '_')
    }
    $result = [ordered]@{
        schemaVersion = 1
        resultType = 'ensou-dsh-windows-pilot-response-signing-key-public'
        status = 'CREATED_PILOT_ONLY'
        productionAdmission = 'NO_GO'
        profile = $PilotProfile
        algorithm = 'ES256'
        provider = $provider.Provider
        storeScope = 'CurrentUser'
        keyName = $KeyName
        keyId = $KeyId
        purpose = $purposeValue
        x = & $base64Url $public.Q.X
        y = & $base64Url $public.Q.Y
        privateKeyExported = $false
        privateKeyExportable = $false
    }
    [byte[]]$bytes = [Text.UTF8Encoding]::new($false, $true).GetBytes(
        (($result | ConvertTo-Json -Depth 8 -Compress) + [char]10))
    $stream = [IO.File]::Open(
        $outputFullPath,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
        [Array]::Clear($bytes, 0, $bytes.Length)
    }
    $result
}
catch {
    if ($created -and $null -ne $key) {
        try { $key.Delete() } catch {}
    }
    throw
}
finally {
    if ($null -ne $ecdsa) { $ecdsa.Dispose() }
    if ($null -ne $key) { $key.Dispose() }
}
