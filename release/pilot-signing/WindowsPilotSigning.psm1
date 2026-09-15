#requires -Version 7.2

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:CodeSigningEkuOid = '1.3.6.1.5.5.7.3.3'
$script:AllowedTargetExtensions = @('.exe', '.dll')
# TSA endpoint approval is a repository-reviewed policy decision, not a value a
# caller may self-assert by supplying both an endpoint and its digest. Keep this
# list empty until the operator has selected and independently approved one
# canonical RFC3161 endpoint. Add only the lowercase SHA-256 of the exact
# canonical `http[s]://host[:port]/path` string; never add the raw URI here.
$script:ApprovedTsaEndpointSha256Pins = @(
    # Canonical Pilot candidate: DigiCert RFC3161 endpoint, trailing `/`.
    '9a44be2d0f498a8bfd2dd1a5e5cced2135e9c4ada9bb5a04eed4c6c5beba1a33'
)

if ([Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
        [Runtime.InteropServices.OSPlatform]::Windows) -and
    $null -eq ('EnsouDshPilotNativeDrive' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class EnsouDshPilotNativeDrive
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode,
        EntryPoint = "GetDriveTypeW", SetLastError = true)]
    public static extern uint GetDriveType(string rootPathName);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode,
        EntryPoint = "QueryDosDeviceW", SetLastError = true)]
    public static extern uint QueryDosDevice(
        string deviceName,
        [Out] char[] targetPath,
        int maximumLength);

    [StructLayout(LayoutKind.Sequential)]
    public struct FileAttributeTagInfo
    {
        public uint FileAttributes;
        public uint ReparseTag;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode,
        EntryPoint = "CreateFileW", SetLastError = true)]
    public static extern SafeFileHandle CreateFile(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetFileInformationByHandleEx(
        SafeFileHandle fileHandle,
        int fileInformationClass,
        out FileAttributeTagInfo fileInformation,
        uint bufferSize);
}
'@
}

function Add-WindowsPilotSigningBlocker {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [Collections.Generic.List[string]]$Blockers,

        [Parameter(Mandatory = $true)]
        [string]$Code
    )

    if (-not $Blockers.Contains($Code)) {
        $Blockers.Add($Code)
    }
}

function Get-RequiredObservationProperty {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Context
    )

    $property = $Value.PSObject.Properties[$Name]
    if ($null -eq $property) {
        throw "Signing observation is missing '$Context.$Name'."
    }
    return $property.Value
}

function Get-StrictObservationBoolean {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Context,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [Collections.Generic.List[string]]$Blockers
    )

    $property = if ($null -eq $Value) {
        $null
    }
    else {
        $Value.PSObject.Properties[$Name]
    }
    if ($null -eq $property) {
        Add-WindowsPilotSigningBlocker `
            $Blockers 'OBSERVATION_BOOLEAN_PROPERTY_MISSING'
        return $false
    }
    $raw = $property.Value
    if ($raw -isnot [bool]) {
        Add-WindowsPilotSigningBlocker `
            $Blockers 'OBSERVATION_BOOLEAN_TYPE_INVALID'
        return $false
    }
    return $raw
}

function Test-WindowsPilotSigningObservation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [psobject]$Observation
    )

    process {
        $networkPolicy = Get-RequiredObservationProperty `
            -Value $Observation -Name 'networkPolicy' -Context 'observation'
        $environment = Get-RequiredObservationProperty `
            -Value $Observation -Name 'environment' -Context 'observation'
        $signTool = Get-RequiredObservationProperty `
            -Value $Observation -Name 'signTool' -Context 'observation'
        $certificate = Get-RequiredObservationProperty `
            -Value $Observation -Name 'certificate' -Context 'observation'
        $tsa = Get-RequiredObservationProperty `
            -Value $Observation -Name 'tsa' -Context 'observation'
        $targetBinding = Get-RequiredObservationProperty `
            -Value $Observation -Name 'targetBinding' -Context 'observation'
        $targets = @(Get-RequiredObservationProperty `
                -Value $Observation -Name 'targets' -Context 'observation')

        $blockers = [Collections.Generic.List[string]]::new()

        if (-not (Get-StrictObservationBoolean `
                    -Value $networkPolicy -Name 'offlineOnly' `
                    -Context 'networkPolicy' -Blockers $blockers)) {
            Add-WindowsPilotSigningBlocker $blockers 'PREFLIGHT_OFFLINE_POLICY_REQUIRED'
        }
        if (-not (Get-StrictObservationBoolean `
                    -Value $networkPolicy -Name 'certificateDownloadsDisabled' `
                    -Context 'networkPolicy' -Blockers $blockers)) {
            Add-WindowsPilotSigningBlocker `
                $blockers 'CERTIFICATE_DOWNLOADS_MUST_BE_DISABLED'
        }
        if ((Get-StrictObservationBoolean `
                -Value $networkPolicy -Name 'winVerifyTrustUsed' `
                -Context 'networkPolicy' -Blockers $blockers)) {
            Add-WindowsPilotSigningBlocker $blockers 'WINVERIFYTRUST_NETWORK_PATH_FORBIDDEN'
        }
        if ([string](Get-RequiredObservationProperty `
                -Value $networkPolicy -Name 'revocationMode' `
                -Context 'networkPolicy') -cne 'NoCheck' -or
            [string](Get-RequiredObservationProperty `
                -Value $networkPolicy -Name 'authenticodeInspection' `
                -Context 'networkPolicy') -cne 'offline-pe-security-directory-v1') {
            Add-WindowsPilotSigningBlocker $blockers 'PREFLIGHT_OFFLINE_IMPLEMENTATION_INVALID'
        }

        if (-not (Get-StrictObservationBoolean `
                    -Value $environment -Name 'isWindows' `
                    -Context 'environment' -Blockers $blockers) -or
            [string](Get-RequiredObservationProperty `
                    -Value $environment -Name 'osArchitecture' -Context 'environment') -cne 'X64') {
            Add-WindowsPilotSigningBlocker $blockers 'NATIVE_WINDOWS_X64_REQUIRED'
        }
        if ([string](Get-RequiredObservationProperty `
                -Value $environment -Name 'processArchitecture' -Context 'environment') -cne 'X64') {
            Add-WindowsPilotSigningBlocker $blockers 'X64_POWERSHELL_REQUIRED'
        }

        if (-not (Get-StrictObservationBoolean `
                    -Value $signTool -Name 'exists' `
                    -Context 'signTool' -Blockers $blockers)) {
            Add-WindowsPilotSigningBlocker $blockers 'SIGNTOOL_NOT_FOUND'
        }
        if (-not (Get-StrictObservationBoolean `
                    -Value $signTool -Name 'absoluteSafePath' `
                    -Context 'signTool' -Blockers $blockers)) {
            Add-WindowsPilotSigningBlocker $blockers 'SIGNTOOL_PATH_NOT_ABSOLUTE_OR_SAFE'
        }
        if (-not (Get-StrictObservationBoolean `
                    -Value $signTool -Name 'fileNameExact' `
                    -Context 'signTool' -Blockers $blockers)) {
            Add-WindowsPilotSigningBlocker $blockers 'SIGNTOOL_FILENAME_NOT_EXACT'
        }
        if (-not (Get-StrictObservationBoolean `
                    -Value $signTool -Name 'versionMatches' `
                    -Context 'signTool' -Blockers $blockers)) {
            Add-WindowsPilotSigningBlocker $blockers 'SIGNTOOL_VERSION_PIN_MISMATCH'
        }
        if (-not (Get-StrictObservationBoolean `
                    -Value $signTool -Name 'sha256Matches' `
                    -Context 'signTool' -Blockers $blockers)) {
            Add-WindowsPilotSigningBlocker $blockers 'SIGNTOOL_SHA256_PIN_MISMATCH'
        }

        if (-not (Get-StrictObservationBoolean `
                    -Value $certificate -Name 'present' `
                    -Context 'certificate' -Blockers $blockers)) {
            Add-WindowsPilotSigningBlocker $blockers 'CODE_SIGNING_CERTIFICATE_NOT_FOUND'
        }
        if (-not (Get-StrictObservationBoolean `
                    -Value $certificate -Name 'hasPrivateKey' `
                    -Context 'certificate' -Blockers $blockers)) {
            Add-WindowsPilotSigningBlocker $blockers 'CODE_SIGNING_PRIVATE_KEY_NOT_AVAILABLE'
        }
        if (-not (Get-StrictObservationBoolean `
                    -Value $certificate -Name 'codeSigningEku' `
                    -Context 'certificate' -Blockers $blockers)) {
            Add-WindowsPilotSigningBlocker $blockers 'CODE_SIGNING_EKU_REQUIRED'
        }
        if (-not (Get-StrictObservationBoolean `
                    -Value $certificate -Name 'digitalSignatureKeyUsage' `
                    -Context 'certificate' -Blockers $blockers)) {
            Add-WindowsPilotSigningBlocker `
                $blockers 'DIGITAL_SIGNATURE_KEY_USAGE_REQUIRED'
        }
        if (-not (Get-StrictObservationBoolean `
                    -Value $certificate -Name 'currentlyValid' `
                    -Context 'certificate' -Blockers $blockers)) {
            Add-WindowsPilotSigningBlocker $blockers 'CERTIFICATE_NOT_CURRENTLY_VALID'
        }
        if (-not (Get-StrictObservationBoolean `
                    -Value $certificate -Name 'validityBufferSatisfied' `
                    -Context 'certificate' -Blockers $blockers)) {
            Add-WindowsPilotSigningBlocker $blockers 'CERTIFICATE_VALIDITY_BUFFER_NOT_SATISFIED'
        }
        if (-not (Get-StrictObservationBoolean `
                    -Value $certificate -Name 'sha256Matches' `
                    -Context 'certificate' -Blockers $blockers)) {
            Add-WindowsPilotSigningBlocker $blockers 'CERTIFICATE_SHA256_PIN_MISMATCH'
        }
        if (-not (Get-StrictObservationBoolean `
                    -Value $certificate -Name 'chainTrusted' `
                    -Context 'certificate' -Blockers $blockers)) {
            Add-WindowsPilotSigningBlocker $blockers 'CERTIFICATE_CHAIN_NOT_TRUSTED'
        }
        if (-not (Get-StrictObservationBoolean `
                    -Value $certificate -Name 'chainApplicationPolicyCodeSigningOnly' `
                    -Context 'certificate' -Blockers $blockers)) {
            Add-WindowsPilotSigningBlocker `
                $blockers 'CERTIFICATE_CHAIN_APPLICATION_POLICY_INVALID'
        }
        if (-not (Get-StrictObservationBoolean `
                    -Value $certificate -Name 'chainTerminatesAtPinnedRoot' `
                    -Context 'certificate' -Blockers $blockers)) {
            Add-WindowsPilotSigningBlocker `
                $blockers 'CERTIFICATE_CHAIN_TERMINAL_ROOT_PIN_MISMATCH'
        }
        if (-not (Get-StrictObservationBoolean `
                    -Value $certificate -Name 'pilotRootPresent' `
                    -Context 'certificate' -Blockers $blockers)) {
            Add-WindowsPilotSigningBlocker $blockers 'PILOT_ROOT_CERTIFICATE_NOT_FOUND'
        }
        if (-not (Get-StrictObservationBoolean `
                    -Value $certificate -Name 'pilotRootSafePath' `
                    -Context 'certificate' -Blockers $blockers)) {
            Add-WindowsPilotSigningBlocker $blockers 'PILOT_ROOT_CERTIFICATE_PATH_NOT_SAFE'
        }
        if (-not (Get-StrictObservationBoolean `
                    -Value $certificate -Name 'pilotRootSha256Matches' `
                    -Context 'certificate' -Blockers $blockers)) {
            Add-WindowsPilotSigningBlocker $blockers 'PILOT_ROOT_CERTIFICATE_SHA256_PIN_MISMATCH'
        }

        $exportability = [string](Get-RequiredObservationProperty `
                -Value $certificate -Name 'privateKeyExportability' -Context 'certificate')
        if ($exportability -ceq 'Exportable') {
            Add-WindowsPilotSigningBlocker $blockers 'PRIVATE_KEY_IS_EXPORTABLE'
        }
        elseif ($exportability -cne 'NonExportable') {
            Add-WindowsPilotSigningBlocker `
                $blockers 'PRIVATE_KEY_EXPORTABILITY_NOT_PROVEN_NON_EXPORTABLE'
        }

        $providerTypeProperty =
            $certificate.PSObject.Properties['privateKeyProviderType']
        if ($null -eq $providerTypeProperty -or
            [string]$providerTypeProperty.Value -cne 'CNG') {
            Add-WindowsPilotSigningBlocker $blockers 'PRIVATE_KEY_PROVIDER_NOT_CNG'
        }
        $providerNameProperty =
            $certificate.PSObject.Properties['privateKeyProviderName']
        if ($null -eq $providerNameProperty -or
            [string]$providerNameProperty.Value -cne
                'Microsoft Software Key Storage Provider') {
            Add-WindowsPilotSigningBlocker `
                $blockers 'PRIVATE_KEY_PROVIDER_NOT_SOFTWARE_KSP'
        }
        $algorithmGroupProperty =
            $certificate.PSObject.Properties['privateKeyAlgorithmGroup']
        if ($null -eq $algorithmGroupProperty -or
            [string]$algorithmGroupProperty.Value -cne 'RSA') {
            Add-WindowsPilotSigningBlocker `
                $blockers 'PRIVATE_KEY_ALGORITHM_GROUP_NOT_RSA'
        }
        $keySizeProperty =
            $certificate.PSObject.Properties['privateKeySizeBits']
        if ($null -eq $keySizeProperty -or
            -not ($keySizeProperty.Value -is [int] -or
                $keySizeProperty.Value -is [long]) -or
            [int]$keySizeProperty.Value -ne 3072) {
            Add-WindowsPilotSigningBlocker `
                $blockers 'PRIVATE_KEY_SIZE_NOT_3072'
        }
        if (Get-StrictObservationBoolean `
                -Value $certificate -Name 'privateKeyIsMachineKey' `
                -Context 'certificate' -Blockers $blockers) {
            Add-WindowsPilotSigningBlocker `
                $blockers 'PRIVATE_KEY_MACHINE_SCOPE_FORBIDDEN'
        }
        if (-not (Get-StrictObservationBoolean `
                    -Value $certificate `
                    -Name 'privateKeyCurrentUserSoftwareKsp' `
                    -Context 'certificate' -Blockers $blockers)) {
            Add-WindowsPilotSigningBlocker `
                $blockers 'PRIVATE_KEY_CURRENT_USER_SOFTWARE_KSP_REQUIRED'
        }

        $revocationStatus = [string](Get-RequiredObservationProperty `
                -Value $certificate -Name 'revocationStatus' -Context 'certificate')
        if ($revocationStatus -ceq 'Revoked') {
            Add-WindowsPilotSigningBlocker $blockers 'CERTIFICATE_REVOKED'
        }
        # This evaluator consumes an explicitly offline observation. Even a
        # caller-supplied string such as "Good" is not online CRL/OCSP evidence
        # and must never clear the revocation blocker.
        Add-WindowsPilotSigningBlocker `
            $blockers 'CERTIFICATE_REVOCATION_STATUS_NOT_PROVEN'

        if (-not (Get-StrictObservationBoolean `
                    -Value $tsa -Name 'absoluteApprovedScheme' `
                    -Context 'tsa' -Blockers $blockers)) {
            Add-WindowsPilotSigningBlocker `
                $blockers 'TSA_URI_MUST_BE_ABSOLUTE_HTTP_OR_HTTPS'
        }
        if (-not (Get-StrictObservationBoolean `
                    -Value $tsa -Name 'componentsClean' `
                    -Context 'tsa' -Blockers $blockers)) {
            Add-WindowsPilotSigningBlocker $blockers 'TSA_URI_MUST_NOT_CONTAIN_CREDENTIALS_QUERY_OR_FRAGMENT'
        }
        if (-not (Get-StrictObservationBoolean `
                    -Value $tsa -Name 'canonicalInput' `
                    -Context 'tsa' -Blockers $blockers)) {
            Add-WindowsPilotSigningBlocker $blockers 'TSA_URI_MUST_BE_CANONICAL'
        }
        if (-not (Get-StrictObservationBoolean `
                    -Value $tsa -Name 'hostShapeAllowed' `
                    -Context 'tsa' -Blockers $blockers)) {
            Add-WindowsPilotSigningBlocker $blockers 'TSA_HOST_SHAPE_NOT_ALLOWED'
        }
        if (-not (Get-StrictObservationBoolean `
                    -Value $tsa -Name 'pathShapeAllowed' `
                    -Context 'tsa' -Blockers $blockers)) {
            Add-WindowsPilotSigningBlocker $blockers 'TSA_PATH_SHAPE_NOT_ALLOWED'
        }
        if (-not (Get-StrictObservationBoolean `
                    -Value $tsa -Name 'repositoryPinApproved' `
                    -Context 'tsa' -Blockers $blockers)) {
            Add-WindowsPilotSigningBlocker $blockers 'TSA_ENDPOINT_PIN_NOT_APPROVED'
        }
        if (-not (Get-StrictObservationBoolean `
                    -Value $tsa -Name 'expectedSha256Valid' `
                    -Context 'tsa' -Blockers $blockers) -or
            -not (Get-StrictObservationBoolean `
                    -Value $tsa -Name 'sha256Matches' `
                    -Context 'tsa' -Blockers $blockers)) {
            Add-WindowsPilotSigningBlocker $blockers 'TSA_URI_SHA256_PIN_MISMATCH'
        }

        if ([string](Get-RequiredObservationProperty `
                -Value $targetBinding -Name 'bindingMode' `
                -Context 'targetBinding') -cne 'ordered-target-path-sha256-pairs-v1') {
            Add-WindowsPilotSigningBlocker $blockers 'TARGET_BINDING_MODE_INVALID'
        }
        if (-not (Get-StrictObservationBoolean `
                    -Value $targetBinding -Name 'nonEmpty' `
                    -Context 'targetBinding' -Blockers $blockers)) {
            Add-WindowsPilotSigningBlocker $blockers 'TARGET_BINDING_EMPTY'
        }
        if (-not (Get-StrictObservationBoolean `
                    -Value $targetBinding -Name 'countWithinLimit' `
                    -Context 'targetBinding' -Blockers $blockers)) {
            Add-WindowsPilotSigningBlocker $blockers 'TARGET_BINDING_COUNT_OUT_OF_RANGE'
        }
        if (-not (Get-StrictObservationBoolean `
                    -Value $targetBinding -Name 'countMatches' `
                    -Context 'targetBinding' -Blockers $blockers)) {
            Add-WindowsPilotSigningBlocker $blockers 'TARGET_BINDING_COUNT_MISMATCH'
        }
        if (-not (Get-StrictObservationBoolean `
                    -Value $targetBinding -Name 'orderedIndexBinding' `
                    -Context 'targetBinding' -Blockers $blockers)) {
            Add-WindowsPilotSigningBlocker $blockers 'TARGET_BINDING_ORDER_INVALID'
        }
        if (-not (Get-StrictObservationBoolean `
                    -Value $targetBinding -Name 'pathsUnique' `
                    -Context 'targetBinding' -Blockers $blockers)) {
            Add-WindowsPilotSigningBlocker $blockers 'TARGET_PATH_DUPLICATE'
        }
        if (-not (Get-StrictObservationBoolean `
                    -Value $targetBinding -Name 'expectedSha256Unique' `
                    -Context 'targetBinding' -Blockers $blockers)) {
            Add-WindowsPilotSigningBlocker $blockers 'TARGET_EXPECTED_SHA256_DUPLICATE'
        }

        if ($targets.Count -eq 0) {
            Add-WindowsPilotSigningBlocker $blockers 'SIGNING_TARGET_REQUIRED'
        }
        foreach ($target in $targets) {
            if (-not (Get-StrictObservationBoolean `
                        -Value $target -Name 'expectedSha256Valid' `
                        -Context 'target' -Blockers $blockers)) {
                Add-WindowsPilotSigningBlocker $blockers 'TARGET_EXPECTED_SHA256_INVALID'
            }
            if (-not (Get-StrictObservationBoolean `
                        -Value $target -Name 'sha256Matches' `
                        -Context 'target' -Blockers $blockers)) {
                Add-WindowsPilotSigningBlocker $blockers 'SIGNING_TARGET_SHA256_PIN_MISMATCH'
            }
            if (-not (Get-StrictObservationBoolean `
                        -Value $target -Name 'exists' `
                        -Context 'target' -Blockers $blockers)) {
                Add-WindowsPilotSigningBlocker $blockers 'SIGNING_TARGET_NOT_FOUND'
            }
            if (-not (Get-StrictObservationBoolean `
                        -Value $target -Name 'absoluteSafePath' `
                        -Context 'target' -Blockers $blockers)) {
                Add-WindowsPilotSigningBlocker $blockers 'SIGNING_TARGET_PATH_NOT_ABSOLUTE_OR_SAFE'
            }
            if (-not (Get-StrictObservationBoolean `
                        -Value $target -Name 'insideAllowedRoot' `
                        -Context 'target' -Blockers $blockers)) {
                Add-WindowsPilotSigningBlocker $blockers 'SIGNING_TARGET_OUTSIDE_ALLOWED_ROOT'
            }
            if (-not (Get-StrictObservationBoolean `
                        -Value $target -Name 'isLeafFile' `
                        -Context 'target' -Blockers $blockers)) {
                Add-WindowsPilotSigningBlocker $blockers 'SIGNING_TARGET_MUST_BE_LEAF_FILE'
            }
            if ((Get-StrictObservationBoolean `
                    -Value $target -Name 'isReparsePoint' `
                    -Context 'target' -Blockers $blockers)) {
                Add-WindowsPilotSigningBlocker $blockers 'SIGNING_TARGET_REPARSE_POINT_FORBIDDEN'
            }
            if (-not (Get-StrictObservationBoolean `
                        -Value $target -Name 'allowedExtension' `
                        -Context 'target' -Blockers $blockers)) {
                Add-WindowsPilotSigningBlocker $blockers 'SIGNING_TARGET_EXTENSION_NOT_ALLOWED'
            }
            if (-not (Get-StrictObservationBoolean `
                        -Value $target -Name 'isPortableExecutable' `
                        -Context 'target' -Blockers $blockers)) {
                Add-WindowsPilotSigningBlocker $blockers 'SIGNING_TARGET_NOT_VALID_PE'
            }
            if (-not (Get-StrictObservationBoolean `
                        -Value $target -Name 'isUnsigned' `
                        -Context 'target' -Blockers $blockers)) {
                Add-WindowsPilotSigningBlocker $blockers 'SIGNING_TARGET_ALREADY_SIGNED_OR_UNVERIFIABLE'
            }
        }

        $uniqueBlockers = @($blockers | Sort-Object -Unique)
        [pscustomobject][ordered]@{
            schemaVersion = 1
            resultType = 'ensou-dsh-windows-pilot-signing-preflight'
            # An offline-only observation cannot prove current revocation. It
            # is diagnostic input to a later controlled online signing gate,
            # never standalone signing or publication admission.
            pilotSigningReadiness = 'NO_GO'
            productionAdmission = 'NO_GO'
            blockers = $uniqueBlockers
            observation = $Observation
        }
    }
}

function Test-WindowsLocalAbsolutePathShape {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Path,
        [switch]$Directory
    )

    # Accept only an ordinary local drive-qualified path below the drive root.
    # This rejects UNC, Win32 device namespaces (\\?\ and \\.\), drive-relative
    # (`C:foo`), root-relative (`\foo`), the drive root itself, ADS colons, and
    # alternate separators before any filesystem access occurs.
    if ([string]::IsNullOrWhiteSpace($Path) -or
        -not $Path.IsNormalized([Text.NormalizationForm]::FormC) -or
        $Path -match '[\x00-\x1f]' -or
        $Path -match '[<>"|?*]' -or
        $Path -match '/' -or
        $Path.StartsWith('\\', [StringComparison]::Ordinal) -or
        $Path -notmatch '^[A-Za-z]:\\[^\\]' -or
        $Path.IndexOf(':', 2) -ge 0 -or
        $Path.Substring(3) -match '\\\\') {
        return $false
    }

    $segments = @($Path.Substring(3).Split(
            [char]'\', [StringSplitOptions]::RemoveEmptyEntries))
    foreach ($segment in $segments) {
        if ($segment -in @('.', '..') -or
            $segment -match '[ .]$' -or
            $segment -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)') {
            return $false
        }
    }

    # GetDriveTypeW and QueryDosDeviceW inspect DOS-device metadata without
    # resolving or opening the supplied path. Do this before GetFullPath and,
    # critically, before any provider/FileSystem Get-Item call.
    if (-not (Test-WindowsFixedLocalDrivePath -Path $Path)) {
        return $false
    }

    try {
        $fullPath = [IO.Path]::GetFullPath($Path)
        if ($Directory) {
            return $fullPath.TrimEnd('\') -ieq $Path.TrimEnd('\')
        }
        return $fullPath -ieq $Path
    }
    catch {
        return $false
    }
}

function Test-WindowsFixedLocalDriveClassification {
    param(
        [Parameter(Mandatory = $true)][uint32]$DriveType,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()][string[]]$DosDeviceTargets
    )

    # Win32 DRIVE_FIXED is 3. Requiring an ordinary local volume device target
    # additionally rejects SUBST (\??\...), MUP/LanmanRedirector mappings, and
    # caller-controlled DOS device aliases that GetDriveTypeW alone can label
    # as fixed.
    return $DriveType -eq 3 -and
        @($DosDeviceTargets).Count -eq 1 -and
        $DosDeviceTargets[0] -cmatch '^\\Device\\HarddiskVolume[0-9]+$'
}

function Test-WindowsFixedLocalDrivePath {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Path
    )

    if (-not [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
            [Runtime.InteropServices.OSPlatform]::Windows) -or
        $Path -notmatch '^[A-Za-z]:\\') {
        return $false
    }

    $driveName = $Path.Substring(0, 2).ToUpperInvariant()
    $driveRoot = $driveName + '\'
    try {
        $driveType = [EnsouDshPilotNativeDrive]::GetDriveType($driveRoot)
        if ($driveType -ne 3) {
            return $false
        }

        $targetBuffer = [char[]]::new(32768)
        $characterCount = [EnsouDshPilotNativeDrive]::QueryDosDevice(
            $driveName, $targetBuffer, $targetBuffer.Length)
        if ($characterCount -eq 0) {
            return $false
        }
        $rawTargets = [string]::new(
            $targetBuffer, 0, [int]$characterCount)
        $dosDeviceTargets = @($rawTargets.Split(
                [char]0, [StringSplitOptions]::RemoveEmptyEntries))
        return Test-WindowsFixedLocalDriveClassification `
            -DriveType $driveType -DosDeviceTargets $dosDeviceTargets
    }
    catch {
        return $false
    }
}

function Invoke-WindowsNoFollowPathOperation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [ValidateSet('Any', 'File', 'Directory')][string]$ExpectedKind = 'Any',
        [scriptblock]$Operation
    )

    $directoryShape = $ExpectedKind -ceq 'Directory'
    if (-not (Test-WindowsLocalAbsolutePathShape `
            -Path $Path -Directory:$directoryShape)) {
        return [pscustomobject][ordered]@{
            safe = $false
            failure = 'PATH_SHAPE_OR_DRIVE_NOT_ALLOWED'
            totalComponentCount = 0
            openedComponentCount = 0
            inspectedComponentCount = 0
            blockedComponentIndex = $null
            reparseDetected = $false
            leafOpened = $false
            finalIsFile = $false
            finalIsDirectory = $false
            operationSucceeded = $false
            value = $null
        }
    }

    $canonicalPath = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $driveRoot = $canonicalPath.Substring(0, 3)
    $segments = @($canonicalPath.Substring(3).Split(
            [char]'\', [StringSplitOptions]::RemoveEmptyEntries))
    $componentPaths = [Collections.Generic.List[string]]::new()
    $componentPaths.Add($driveRoot)
    $currentPath = $driveRoot.TrimEnd('\')
    foreach ($segment in $segments) {
        $currentPath = $currentPath + '\' + $segment
        $componentPaths.Add($currentPath)
    }

    $handles = [Collections.Generic.List[
        Microsoft.Win32.SafeHandles.SafeFileHandle]]::new()
    $openedCount = 0
    $inspectedCount = 0
    $blockedIndex = $null
    $reparseDetected = $false
    $leafOpened = $false
    $finalIsFile = $false
    $finalIsDirectory = $false
    $failure = $null
    $operationSucceeded = $false
    $operationValue = $null

    try {
        for ($index = 0; $index -lt $componentPaths.Count; $index++) {
            $isFinal = $index -eq ($componentPaths.Count - 1)
            $desiredAccess = if ($isFinal -and $ExpectedKind -ceq 'File') {
                [uint32]2147483648 # GENERIC_READ
            }
            else {
                [uint32]0x00000080 # FILE_READ_ATTRIBUTES
            }
            # Share only read: never share write or delete. Retaining every
            # checked parent handle prevents rename/delete replacement during
            # the final leaf read. Any sharing/access failure is fail closed.
            $handle = [EnsouDshPilotNativeDrive]::CreateFile(
                $componentPaths[$index],
                $desiredAccess,
                [uint32]0x00000001,
                [IntPtr]::Zero,
                [uint32]3, # OPEN_EXISTING
                [uint32]0x02200000, # OPEN_REPARSE_POINT | BACKUP_SEMANTICS
                [IntPtr]::Zero)
            if ($null -eq $handle -or $handle.IsInvalid) {
                if ($null -ne $handle) { $handle.Dispose() }
                $failure = 'COMPONENT_OPEN_FAILED'
                $blockedIndex = $index
                break
            }
            else {
                $handles.Add($handle)
                $openedCount++

                $attributeInfo =
                    [EnsouDshPilotNativeDrive+FileAttributeTagInfo]::new()
                $attributeInfoSize = [Runtime.InteropServices.Marshal]::SizeOf(
                    [type][EnsouDshPilotNativeDrive+FileAttributeTagInfo])
                $informationRead =
                    [EnsouDshPilotNativeDrive]::GetFileInformationByHandleEx(
                        $handle, 9, [ref]$attributeInfo,
                        [uint32]$attributeInfoSize)
                if (-not $informationRead) {
                    $failure = 'COMPONENT_ATTRIBUTE_READ_FAILED'
                    $blockedIndex = $index
                    break
                }
                $attributeValue = $attributeInfo.FileAttributes
                $inspectedCount++
            }

            $isReparse =
                ($attributeValue -band [uint32]0x00000400) -ne 0
            $isDirectory =
                ($attributeValue -band [uint32]0x00000010) -ne 0
            if ($isReparse) {
                $failure = 'REPARSE_POINT_FORBIDDEN'
                $blockedIndex = $index
                $reparseDetected = $true
                break
            }
            if (-not $isFinal -and -not $isDirectory) {
                $failure = 'INTERMEDIATE_COMPONENT_NOT_DIRECTORY'
                $blockedIndex = $index
                break
            }
            if ($isFinal) {
                $leafOpened = $true
                $finalIsDirectory = $isDirectory
                $finalIsFile = -not $isDirectory
                if (($ExpectedKind -ceq 'File' -and -not $finalIsFile) -or
                    ($ExpectedKind -ceq 'Directory' -and
                        -not $finalIsDirectory)) {
                    $failure = 'FINAL_COMPONENT_KIND_MISMATCH'
                    $blockedIndex = $index
                    break
                }
            }
        }

        if ($null -eq $failure -and $leafOpened) {
            if ($null -eq $Operation) {
                $operationSucceeded = $true
            }
            else {
                $operationValue = & $Operation `
                    $handles[$handles.Count - 1] $canonicalPath
                $operationSucceeded = $true
            }
        }
    }
    catch {
        # Fail closed without reflecting exception text, path data, or
        # provider-specific details into the observation.
        $failure = 'NO_FOLLOW_OPERATION_FAILED'
        $operationSucceeded = $false
        $operationValue = $null
    }
    finally {
        for ($handleIndex = $handles.Count - 1;
            $handleIndex -ge 0; $handleIndex--) {
            $handles[$handleIndex].Dispose()
        }
    }

    return [pscustomobject][ordered]@{
        safe = $null -eq $failure -and $leafOpened -and $operationSucceeded
        failure = $failure
        totalComponentCount = $componentPaths.Count
        openedComponentCount = $openedCount
        inspectedComponentCount = $inspectedCount
        blockedComponentIndex = $blockedIndex
        reparseDetected = $reparseDetected
        leafOpened = $leafOpened
        finalIsFile = $finalIsFile
        finalIsDirectory = $finalIsDirectory
        operationSucceeded = $operationSucceeded
        value = $operationValue
    }
}

function Invoke-WindowsPinnedExecutableOperation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedFileName,
        [Parameter(Mandatory = $true)][string]$ExpectedFileVersion,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9a-f]{64}$')]
        [string]$ExpectedSha256,
        [Parameter(Mandatory = $true)][scriptblock]$Operation
    )

    if (-not (Test-WindowsLocalAbsolutePathShape -Path $Path) -or
        [IO.Path]::GetFileName($Path) -cne $ExpectedFileName) {
        throw 'Pinned executable path or file name is not canonical.'
    }
    $fullPath = [IO.Path]::GetFullPath($Path)
    return Invoke-WindowsNoFollowPathOperation `
        -Path $fullPath `
        -ExpectedKind File `
        -Operation {
            param($handle, $safePath)
            $observation = Get-OfflinePeTargetFileObservation -Handle $handle
            $actualVersion = [string][Diagnostics.FileVersionInfo]::
                GetVersionInfo($safePath).FileVersion
            if ([string]$observation.sha256 -cne $ExpectedSha256 -or
                $actualVersion -cne $ExpectedFileVersion -or
                -not [bool]$observation.isPortableExecutable) {
                throw 'Pinned executable changed before protected execution.'
            }
            & $Operation $safePath
        }
}

function Test-WindowsPathHasReparsePoint {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$StopAtPath
    )

    if (-not [string]::IsNullOrWhiteSpace($StopAtPath) -and
        -not (Test-WindowsLocalAbsolutePathShape `
            -Path $StopAtPath -Directory)) {
        throw 'StopAtPath must be on an approved fixed local drive.'
    }
    $observation = Invoke-WindowsNoFollowPathOperation `
        -Path $Path -ExpectedKind Any
    if ($observation.reparseDetected) { return $true }
    if (-not $observation.safe) {
        throw 'Path could not be proven free of reparse points.'
    }
    return $false
}

function Get-WindowsNoFollowPathObservation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [ValidateSet('Any', 'File', 'Directory')][string]$ExpectedKind = 'Any'
    )

    return Invoke-WindowsNoFollowPathOperation `
        -Path $Path -ExpectedKind $ExpectedKind
}

function New-WindowsBorrowedFileStream {
    param(
        [Parameter(Mandatory = $true)]
        [Microsoft.Win32.SafeHandles.SafeFileHandle]$Handle
    )

    $borrowedHandle =
        [Microsoft.Win32.SafeHandles.SafeFileHandle]::new(
            $Handle.DangerousGetHandle(), $false)
    return [IO.FileStream]::new($borrowedHandle, [IO.FileAccess]::Read)
}

function Get-WindowsFileBytesFromHandle {
    param(
        [Parameter(Mandatory = $true)]
        [Microsoft.Win32.SafeHandles.SafeFileHandle]$Handle,
        [ValidateRange(1, 16777216)][int]$MaximumBytes = 1048576
    )

    $stream = $null
    try {
        $stream = New-WindowsBorrowedFileStream -Handle $Handle
        if ($stream.Length -lt 1 -or $stream.Length -gt $MaximumBytes) {
            throw 'File size is outside the approved bounded read range.'
        }
        $bytes = [byte[]]::new([int]$stream.Length)
        $stream.ReadExactly($bytes)
        return ,$bytes
    }
    finally {
        if ($null -ne $stream) { $stream.Dispose() }
    }
}

function Get-OfflinePeTargetFileObservation {
    param(
        [Parameter(Mandatory = $true)]
        [Microsoft.Win32.SafeHandles.SafeFileHandle]$Handle
    )

    $stream = $null
    $peReader = $null
    $sha = $null
    try {
        $stream = New-WindowsBorrowedFileStream -Handle $Handle
        $hashAlgorithm = [Security.Cryptography.SHA256]::Create()
        try {
            $sha = [Convert]::ToHexString(
                $hashAlgorithm.ComputeHash($stream)).ToLowerInvariant()
        }
        finally {
            $hashAlgorithm.Dispose()
        }
        $stream.Position = 0
        $peReader = [Reflection.PortableExecutable.PEReader]::new(
            $stream,
            [Reflection.PortableExecutable.PEStreamOptions]::LeaveOpen)
        $header = $peReader.PEHeaders.PEHeader
        if ($null -eq $header) {
            return [pscustomobject][ordered]@{
                sha256 = $sha
                isPortableExecutable = $false
                hasAuthenticodeCertificateTable = $false
                isUnsigned = $false
            }
        }
        $certificateTable = $header.CertificateTableDirectory
        $hasCertificateTable = $certificateTable.RelativeVirtualAddress -ne 0 -or
            $certificateTable.Size -ne 0
        return [pscustomobject][ordered]@{
            sha256 = $sha
            isPortableExecutable = $true
            hasAuthenticodeCertificateTable = $hasCertificateTable
            isUnsigned = -not $hasCertificateTable
        }
    }
    catch {
        return [pscustomobject][ordered]@{
            sha256 = $sha
            isPortableExecutable = $false
            hasAuthenticodeCertificateTable = $false
            isUnsigned = $false
        }
    }
    finally {
        if ($null -ne $peReader) { $peReader.Dispose() }
        if ($null -ne $stream) { $stream.Dispose() }
    }
}

function Test-WindowsPathInsideRoot {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Root
    )

    $relative = [IO.Path]::GetRelativePath(
        [IO.Path]::GetFullPath($Root),
        [IO.Path]::GetFullPath($Path))
    return -not [IO.Path]::IsPathRooted($relative) -and
        $relative -cne '..' -and
        -not $relative.StartsWith(
            '..' + [IO.Path]::DirectorySeparatorChar,
            [StringComparison]::Ordinal) -and
        -not $relative.StartsWith(
            '..' + [IO.Path]::AltDirectorySeparatorChar,
            [StringComparison]::Ordinal)
}

function Get-WindowsPrivateKeyExportability {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    if (-not $Certificate.HasPrivateKey) {
        return 'Unknown'
    }

    $key = $null
    try {
        $key = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::
            GetRSAPrivateKey($Certificate)
        if ($null -ne $key) {
            if ($key -is [Security.Cryptography.RSACng]) {
                $policy = $key.Key.ExportPolicy
                if ([int]$policy -eq 0) { return 'NonExportable' }
                return 'Exportable'
            }
            if ($key -is [Security.Cryptography.RSACryptoServiceProvider]) {
                if ($key.CspKeyContainerInfo.Exportable) { return 'Exportable' }
                return 'NonExportable'
            }
            return 'Unknown'
        }

        $key = [Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::
            GetECDsaPrivateKey($Certificate)
        if ($null -ne $key -and $key -is [Security.Cryptography.ECDsaCng]) {
            $policy = $key.Key.ExportPolicy
            if ([int]$policy -eq 0) { return 'NonExportable' }
            return 'Exportable'
        }
        return 'Unknown'
    }
    catch {
        return 'Unknown'
    }
    finally {
        if ($null -ne $key) {
            $key.Dispose()
        }
    }
}

function Get-WindowsPrivateKeyProviderObservation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    $key = $null
    try {
        $key = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::
            GetRSAPrivateKey($Certificate)
        if ($null -ne $key) {
            if ($key -is [Security.Cryptography.RSACng]) {
                return [pscustomobject][ordered]@{
                    providerType = 'CNG'
                    providerName = [string]$key.Key.Provider.Provider
                    algorithmGroup = [string]$key.Key.AlgorithmGroup.AlgorithmGroup
                    keySizeBits = [int]$key.KeySize
                    isMachineKey = [bool]$key.Key.IsMachineKey
                    currentUserSoftwareKsp =
                        -not [bool]$key.Key.IsMachineKey -and
                        [string]$key.Key.Provider.Provider -ceq
                            'Microsoft Software Key Storage Provider'
                }
            }
            if ($key -is [Security.Cryptography.RSACryptoServiceProvider]) {
                return [pscustomobject][ordered]@{
                    providerType = 'CSP'
                    providerName = [string]$key.CspKeyContainerInfo.ProviderName
                    algorithmGroup = 'RSA'
                    keySizeBits = [int]$key.KeySize
                    isMachineKey = [bool]$key.CspKeyContainerInfo.MachineKeyStore
                    currentUserSoftwareKsp = $false
                }
            }
        }
        if ($null -ne $key) {
            $key.Dispose()
            $key = $null
        }

        $key = [Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::
            GetECDsaPrivateKey($Certificate)
        if ($null -ne $key -and $key -is [Security.Cryptography.ECDsaCng]) {
            return [pscustomobject][ordered]@{
                providerType = 'CNG'
                providerName = [string]$key.Key.Provider.Provider
                algorithmGroup = [string]$key.Key.AlgorithmGroup.AlgorithmGroup
                keySizeBits = [int]$key.KeySize
                isMachineKey = [bool]$key.Key.IsMachineKey
                currentUserSoftwareKsp =
                    -not [bool]$key.Key.IsMachineKey -and
                    [string]$key.Key.Provider.Provider -ceq
                        'Microsoft Software Key Storage Provider'
            }
        }
        return [pscustomobject][ordered]@{
            providerType = 'Unknown'
            providerName = $null
            algorithmGroup = $null
            keySizeBits = 0
            isMachineKey = $false
            currentUserSoftwareKsp = $false
        }
    }
    catch {
        return [pscustomobject][ordered]@{
            providerType = 'Unknown'
            providerName = $null
            algorithmGroup = $null
            keySizeBits = 0
            isMachineKey = $false
            currentUserSoftwareKsp = $false
        }
    }
    finally {
        if ($null -ne $key) {
            $key.Dispose()
        }
    }
}

function Get-WindowsCertificateSha256 {
    param(
        [Parameter(Mandatory = $true)]
        [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    return [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($Certificate.RawData)).
        ToLowerInvariant()
}

function Test-WindowsCertificateCodeSigningEku {
    param(
        [Parameter(Mandatory = $true)]
        [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    $ekuExtension = @($Certificate.Extensions | Where-Object {
            $_.Oid.Value -ceq '2.5.29.37'
        })
    if ($ekuExtension.Count -ne 1) {
        return $false
    }

    $typedExtension = [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new(
        $ekuExtension[0], $ekuExtension[0].Critical)
    $ekuOids = @($typedExtension.EnhancedKeyUsages | ForEach-Object {
            [string]$_.Value
        })
    # Pilot policy is intentionally narrower than generic Authenticode:
    # the leaf carries exactly one EKU, Code Signing, with no extra purposes.
    return $ekuOids.Count -eq 1 -and
        $ekuOids[0] -ceq $script:CodeSigningEkuOid
}

function Test-WindowsCertificateDigitalSignatureKeyUsage {
    param(
        [Parameter(Mandatory = $true)]
        [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    $keyUsageExtensions = @($Certificate.Extensions | Where-Object {
            $_.Oid.Value -ceq '2.5.29.15'
        })
    if ($keyUsageExtensions.Count -ne 1) {
        return $false
    }

    $typedExtension =
        [Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
            $keyUsageExtensions[0], $keyUsageExtensions[0].Critical)
    # The Pilot leaf produced by the helper is deliberately narrower than a
    # generic TLS/key-agreement certificate: DigitalSignature is its only KU.
    return $typedExtension.KeyUsages -eq
        [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature
}

function Get-WindowsCertificateChainObservation {
    param(
        [Parameter(Mandatory = $true)]
        [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [string]$PilotRootCertificatePath
    )

    $chain = [Security.Cryptography.X509Certificates.X509Chain]::new()
    $root = $null
    try {
        $chain.ChainPolicy.VerificationFlags =
            [Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
        $chain.ChainPolicy.DisableCertificateDownloads = $true
        [void]$chain.ChainPolicy.ApplicationPolicy.Add(
            [Security.Cryptography.Oid]::new($script:CodeSigningEkuOid))
        # This is deliberately a structural, local-only chain check. CRL/OCSP is
        # not attempted, and revocation is always reported as unproven.
        $chain.ChainPolicy.RevocationMode =
            [Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        if (-not [string]::IsNullOrWhiteSpace($PilotRootCertificatePath)) {
            $rootPath = [IO.Path]::GetFullPath($PilotRootCertificatePath)
            $root = [Security.Cryptography.X509Certificates.X509Certificate2]::new($rootPath)
            $chain.ChainPolicy.TrustMode =
                [Security.Cryptography.X509Certificates.X509ChainTrustMode]::CustomRootTrust
            [void]$chain.ChainPolicy.CustomTrustStore.Add($root)
            [void]$chain.ChainPolicy.ExtraStore.Add($root)
        }
        $built = $chain.Build($Certificate)
        $statuses = @($chain.ChainStatus | ForEach-Object {
                [string]$_.Status
            } | Sort-Object -Unique)
        $terminalCertificateSha256 = $null
        $providedRootSha256 = Get-WindowsCertificateSha256 $root
        if ($chain.ChainElements.Count -gt 0) {
            $terminalCertificate = $chain.ChainElements[
                $chain.ChainElements.Count - 1].Certificate
            $terminalCertificateSha256 =
                Get-WindowsCertificateSha256 $terminalCertificate
        }
        $chainTerminatesAtProvidedRoot = $chain.ChainElements.Count -ge 2 -and
            $null -ne $terminalCertificateSha256 -and
            $terminalCertificateSha256 -ceq $providedRootSha256
        return [pscustomobject][ordered]@{
            chainTrusted = [bool]$built -and $chainTerminatesAtProvidedRoot
            chainStatuses = $statuses
            chainApplicationPolicyCodeSigningOnly =
                $chain.ChainPolicy.ApplicationPolicy.Count -eq 1 -and
                $chain.ChainPolicy.ApplicationPolicy[0].Value -ceq
                    $script:CodeSigningEkuOid
            chainTerminatesAtProvidedRoot = $chainTerminatesAtProvidedRoot
            terminalCertificateSha256 = $terminalCertificateSha256
            revocationStatus = 'Unknown'
            revocationNote = 'Offline preflight does not prove CRL or OCSP status.'
        }
    }
    catch {
        return [pscustomobject][ordered]@{
            chainTrusted = $false
            chainStatuses = @('ChainEvaluationFailed')
            chainApplicationPolicyCodeSigningOnly = $false
            chainTerminatesAtProvidedRoot = $false
            terminalCertificateSha256 = $null
            revocationStatus = 'Unknown'
            revocationNote = 'Offline preflight could not evaluate the certificate chain.'
        }
    }
    finally {
        if ($null -ne $root) { $root.Dispose() }
        $chain.Dispose()
    }
}

function Get-WindowsPilotTsaObservation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$TsaUri,
        [Parameter(Mandatory = $true)][AllowEmptyString()]
        [string]$ExpectedTsaUriSha256
    )

    $expectedPinValid = $ExpectedTsaUriSha256 -cmatch '^[0-9a-f]{64}$'
    $uri = $null
    $parsed = [Uri]::TryCreate($TsaUri, [UriKind]::Absolute, [ref]$uri)
    $absoluteApprovedScheme = $parsed -and
        $uri.Scheme -cin @('http', 'https')
    $componentsClean = $parsed -and
        [string]::IsNullOrEmpty($uri.UserInfo) -and
        [string]::IsNullOrEmpty($uri.Query) -and
        [string]::IsNullOrEmpty($uri.Fragment)
    $hostShapeAllowed = $false
    $pathShapeAllowed = $false
    $canonicalInput = $false
    $actualSha256 = $null
    try {
        if ($parsed) {
            $host = $uri.IdnHost.ToLowerInvariant()
            $hostShapeAllowed =
                $uri.HostNameType -eq [UriHostNameType]::Dns -and
                $host.Contains('.') -and
                -not $host.EndsWith('.') -and
                $host -notin @('localhost', 'localhost.localdomain') -and
                $host -cmatch
                    '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$'
            # Forbid path ambiguity and escaping. A selected TSA endpoint must
            # be committed using a plain canonical ASCII path (including `/`).
            $pathShapeAllowed =
                $uri.AbsolutePath -cmatch '^/(?:[A-Za-z0-9._~-]+/?)*$' -and
                $uri.AbsolutePath -notmatch '//|(?:^|/)\.{1,2}(?:/|$)|%'
            $scheme = $uri.Scheme.ToLowerInvariant()
            $port = if ($uri.IsDefaultPort) { '' } else { ':' + $uri.Port }
            $canonical = '{0}://{1}{2}{3}' -f `
                $scheme, $host, $port, $uri.AbsolutePath
            $canonicalInput = $TsaUri -ceq $canonical
            if ($absoluteApprovedScheme -and $componentsClean -and
                $hostShapeAllowed -and $pathShapeAllowed -and $canonicalInput) {
                $actualSha256 = [Convert]::ToHexString(
                    [Security.Cryptography.SHA256]::HashData(
                        [Text.Encoding]::UTF8.GetBytes($canonical))).ToLowerInvariant()
            }
        }
    }
    catch {
        # Never echo the supplied URI or any component in output or errors.
        $parsed = $false
        $absoluteApprovedScheme = $false
        $componentsClean = $false
        $hostShapeAllowed = $false
        $pathShapeAllowed = $false
        $canonicalInput = $false
        $actualSha256 = $null
    }

    $repositoryPinApproved = $expectedPinValid -and
        $script:ApprovedTsaEndpointSha256Pins -ccontains $ExpectedTsaUriSha256

    return [pscustomobject][ordered]@{
        binding = 'canonical-http-or-https-origin-and-path-sha256-v1'
        absoluteApprovedScheme = $absoluteApprovedScheme
        componentsClean = $componentsClean
        canonicalInput = $canonicalInput
        hostShapeAllowed = $hostShapeAllowed
        pathShapeAllowed = $pathShapeAllowed
        expectedSha256Valid = $expectedPinValid
        repositoryPinApproved = $repositoryPinApproved
        uriSha256 = $actualSha256
        expectedUriSha256 = if ($expectedPinValid) {
            $ExpectedTsaUriSha256
        }
        else {
            $null
        }
        sha256Matches = $expectedPinValid -and
            $null -ne $actualSha256 -and
            $actualSha256 -ceq $ExpectedTsaUriSha256
    }
}

function Get-WindowsPilotSigningObservation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$SignToolPath,
        [Parameter(Mandatory = $true)][AllowEmptyString()]
        [string]$ExpectedSignToolFileVersion,
        [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-fA-F]{64}$')]
        [string]$ExpectedSignToolSha256,
        [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-fA-F]{40}$')]
        [string]$CertificateStoreThumbprint,
        [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-fA-F]{64}$')]
        [string]$ExpectedCertificateSha256,
        [Parameter(Mandatory = $true)][string]$PilotRootCertificatePath,
        [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-fA-F]{64}$')]
        [string]$ExpectedPilotRootCertificateSha256,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$TsaUri,
        [Parameter(Mandatory = $true)][AllowEmptyString()]
        [string]$ExpectedTsaUriSha256,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$AllowedTargetRoot,
        [AllowEmptyCollection()][string[]]$TargetPath = @(),
        [AllowEmptyCollection()][string[]]$ExpectedTargetSha256 = @(),
        [ValidateRange(1, 365)][int]$MinimumCertificateValidityDays = 30
    )

    $isWindows = [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
        [Runtime.InteropServices.OSPlatform]::Windows)
    $environment = [pscustomobject][ordered]@{
        isWindows = $isWindows
        osArchitecture = [string][Runtime.InteropServices.RuntimeInformation]::OSArchitecture
        processArchitecture = [string][Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture
    }
    $networkPolicy = [pscustomobject][ordered]@{
        offlineOnly = $true
        certificateDownloadsDisabled = $true
        revocationMode = 'NoCheck'
        authenticodeInspection = 'offline-pe-security-directory-v1'
        winVerifyTrustUsed = $false
    }

    $signToolFullPath = $null
    $signToolPathShapeSafe = Test-WindowsLocalAbsolutePathShape $SignToolPath
    $signToolAccess = $null
    if ($signToolPathShapeSafe) {
        $signToolFullPath = [IO.Path]::GetFullPath($SignToolPath)
        $signToolAccess = Invoke-WindowsNoFollowPathOperation `
            -Path $signToolFullPath -ExpectedKind File -Operation {
                param($handle, $safePath)
                $fileObservation =
                    Get-OfflinePeTargetFileObservation -Handle $handle
                [pscustomobject][ordered]@{
                    fileVersion = [string][Diagnostics.FileVersionInfo]::
                        GetVersionInfo($safePath).FileVersion
                    sha256 = [string]$fileObservation.sha256
                }
            }
    }
    $signToolExists = $null -ne $signToolAccess -and
        [bool]$signToolAccess.leafOpened -and
        [bool]$signToolAccess.finalIsFile
    $signToolSafe = $false
    $signToolVersion = $null
    $signToolSha256 = $null
    if ($signToolExists -and $signToolAccess.safe) {
        $signToolSafe = $true
        $signToolVersion = [string]$signToolAccess.value.fileVersion
        $signToolSha256 = [string]$signToolAccess.value.sha256
    }
    $signToolObservation = [pscustomobject][ordered]@{
        path = if ($null -eq $signToolFullPath) { '<invalid>' } else { $signToolFullPath }
        exists = $signToolExists
        absoluteSafePath = $signToolExists -and $signToolSafe
        fileNameExact = $signToolExists -and
            [IO.Path]::GetFileName($signToolFullPath) -ceq 'signtool.exe'
        fileVersion = $signToolVersion
        expectedFileVersion = $ExpectedSignToolFileVersion
        versionMatches = $signToolExists -and
            $signToolVersion -ceq $ExpectedSignToolFileVersion
        sha256 = $signToolSha256
        expectedSha256 = $ExpectedSignToolSha256.ToLowerInvariant()
        sha256Matches = $signToolExists -and
            $signToolSha256 -ceq $ExpectedSignToolSha256.ToLowerInvariant()
    }

    $pilotRootFullPath = $null
    $pilotRoot = $null
    $pilotRootPresent = $false
    $pilotRootSafePath = $false
    $pilotRootSha256 = $null
    $pilotRootPathShapeSafe = Test-WindowsLocalAbsolutePathShape `
        $PilotRootCertificatePath
    if ($pilotRootPathShapeSafe) {
        $pilotRootFullPath = [IO.Path]::GetFullPath($PilotRootCertificatePath)
        if ([IO.Path]::GetExtension($pilotRootFullPath) -ieq '.cer') {
            $pilotRootAccess = Invoke-WindowsNoFollowPathOperation `
                -Path $pilotRootFullPath -ExpectedKind File -Operation {
                    param($handle, $safePath)
                    [byte[]]$certificateBytes =
                        Get-WindowsFileBytesFromHandle -Handle $handle
                    [Security.Cryptography.X509Certificates.X509Certificate2]::new(
                        $certificateBytes)
                }
            $pilotRootPresent = [bool]$pilotRootAccess.leafOpened -and
                [bool]$pilotRootAccess.finalIsFile
            $pilotRootSafePath = [bool]$pilotRootAccess.safe
            if ($pilotRootSafePath) {
                $pilotRoot = $pilotRootAccess.value
                $pilotRootSha256 = Get-WindowsCertificateSha256 $pilotRoot
            }
        }
    }
    $pilotRootSha256Matches = $null -ne $pilotRootSha256 -and
        $pilotRootSha256 -ceq $ExpectedPilotRootCertificateSha256.ToLowerInvariant()

    $certificate = $null
    if ($isWindows) {
        $normalizedStoreThumbprint = $CertificateStoreThumbprint.ToUpperInvariant()
        $matches = @(Get-ChildItem -LiteralPath Cert:\CurrentUser\My -ErrorAction SilentlyContinue |
                Where-Object { $_.Thumbprint -ceq $normalizedStoreThumbprint })
        if ($matches.Count -eq 1) {
            $certificate = $matches[0]
        }
    }

    $certificatePresent = $null -ne $certificate
    $certificateSha256 = $null
    $chainObservation = [pscustomobject]@{
        chainTrusted = $false
        chainStatuses = @('CertificateNotFound')
        chainApplicationPolicyCodeSigningOnly = $false
        chainTerminatesAtProvidedRoot = $false
        terminalCertificateSha256 = $null
        revocationStatus = 'Unknown'
        revocationNote = 'Certificate was not found.'
    }
    $certificateObservation = $null
    if ($certificatePresent) {
        $certificateSha256 = Get-WindowsCertificateSha256 $certificate
        $privateKeyProvider =
            Get-WindowsPrivateKeyProviderObservation -Certificate $certificate
        $chainObservation = if ($pilotRootSha256Matches) {
            Get-WindowsCertificateChainObservation `
                -Certificate $certificate `
                -PilotRootCertificatePath $pilotRootFullPath
        }
        else {
            [pscustomobject][ordered]@{
                chainTrusted = $false
                chainStatuses = @('PinnedPilotRootUnavailable')
                chainApplicationPolicyCodeSigningOnly = $false
                chainTerminatesAtProvidedRoot = $false
                terminalCertificateSha256 = $null
                revocationStatus = 'Unknown'
                revocationNote = 'Pinned Pilot root was unavailable or mismatched.'
            }
        }
        $now = [DateTimeOffset]::UtcNow
        $notBefore = [DateTimeOffset]$certificate.NotBefore.ToUniversalTime()
        $notAfter = [DateTimeOffset]$certificate.NotAfter.ToUniversalTime()
        $certificateObservation = [pscustomobject][ordered]@{
            present = $true
            subject = $certificate.Subject
            issuer = $certificate.Issuer
            sha256Thumbprint = $certificateSha256
            expectedSha256Thumbprint = $ExpectedCertificateSha256.ToLowerInvariant()
            sha256Matches = $certificateSha256 -ceq $ExpectedCertificateSha256.ToLowerInvariant()
            hasPrivateKey = $certificate.HasPrivateKey
            privateKeyExportability = Get-WindowsPrivateKeyExportability $certificate
            privateKeyProviderType = [string]$privateKeyProvider.providerType
            privateKeyProviderName = [string]$privateKeyProvider.providerName
            privateKeyAlgorithmGroup = [string]$privateKeyProvider.algorithmGroup
            privateKeySizeBits = [int]$privateKeyProvider.keySizeBits
            privateKeyIsMachineKey = [bool]$privateKeyProvider.isMachineKey
            privateKeyCurrentUserSoftwareKsp =
                [bool]$privateKeyProvider.currentUserSoftwareKsp
            codeSigningEku = Test-WindowsCertificateCodeSigningEku $certificate
            digitalSignatureKeyUsage =
                Test-WindowsCertificateDigitalSignatureKeyUsage $certificate
            notBeforeUtc = $notBefore.ToString('o')
            notAfterUtc = $notAfter.ToString('o')
            currentlyValid = $now -ge $notBefore -and $now -lt $notAfter
            validityBufferSatisfied = $notAfter -ge $now.AddDays($MinimumCertificateValidityDays)
            chainTrusted = [bool]$chainObservation.chainTrusted
            chainStatuses = @($chainObservation.chainStatuses)
            chainApplicationPolicyCodeSigningOnly =
                [bool]$chainObservation.chainApplicationPolicyCodeSigningOnly
            chainTerminatesAtPinnedRoot = $pilotRootSha256Matches -and
                [bool]$chainObservation.chainTerminatesAtProvidedRoot
            chainTerminalCertificateSha256 =
                $chainObservation.terminalCertificateSha256
            pilotRootPresent = $pilotRootPresent
            pilotRootSafePath = $pilotRootSafePath
            pilotRootSha256 = $pilotRootSha256
            expectedPilotRootSha256 = $ExpectedPilotRootCertificateSha256.ToLowerInvariant()
            pilotRootSha256Matches = $pilotRootSha256Matches
            revocationStatus = [string]$chainObservation.revocationStatus
            revocationNote = [string]$chainObservation.revocationNote
        }
    }
    else {
        $certificateObservation = [pscustomobject][ordered]@{
            present = $false
            subject = $null
            issuer = $null
            sha256Thumbprint = $null
            expectedSha256Thumbprint = $ExpectedCertificateSha256.ToLowerInvariant()
            sha256Matches = $false
            hasPrivateKey = $false
            privateKeyExportability = 'Unknown'
            privateKeyProviderType = 'Unknown'
            privateKeyProviderName = $null
            privateKeyAlgorithmGroup = $null
            privateKeySizeBits = 0
            privateKeyIsMachineKey = $false
            privateKeyCurrentUserSoftwareKsp = $false
            codeSigningEku = $false
            digitalSignatureKeyUsage = $false
            notBeforeUtc = $null
            notAfterUtc = $null
            currentlyValid = $false
            validityBufferSatisfied = $false
            chainTrusted = $false
            chainStatuses = @('CertificateNotFound')
            chainApplicationPolicyCodeSigningOnly = $false
            chainTerminatesAtPinnedRoot = $false
            chainTerminalCertificateSha256 = $null
            pilotRootPresent = $pilotRootPresent
            pilotRootSafePath = $pilotRootSafePath
            pilotRootSha256 = $pilotRootSha256
            expectedPilotRootSha256 = $ExpectedPilotRootCertificateSha256.ToLowerInvariant()
            pilotRootSha256Matches = $pilotRootSha256Matches
            revocationStatus = 'Unknown'
            revocationNote = 'Certificate was not found.'
        }
    }

    $targetRootFullPath = $null
    $targetRootSafe = $false
    $targetRootPathShapeSafe = Test-WindowsLocalAbsolutePathShape `
        -Path $AllowedTargetRoot -Directory
    if ($targetRootPathShapeSafe) {
        $targetRootFullPath = [IO.Path]::GetFullPath($AllowedTargetRoot)
        $targetRootAccess = Invoke-WindowsNoFollowPathOperation `
            -Path $targetRootFullPath -ExpectedKind Directory
        $targetRootSafe = [bool]$targetRootAccess.safe
    }

    $targetCount = @($TargetPath).Count
    $hashCount = @($ExpectedTargetSha256).Count
    $countMatches = $targetCount -eq $hashCount
    $countWithinLimit = $targetCount -ge 1 -and $targetCount -le 32
    $pathIdentities = @($TargetPath | ForEach-Object {
            if (Test-WindowsLocalAbsolutePathShape $_) {
                [IO.Path]::GetFullPath($_).ToLowerInvariant()
            }
            else {
                ([string]$_).ToLowerInvariant()
            }
        })
    $pathsUnique = @($pathIdentities | Sort-Object -Unique).Count -eq $pathIdentities.Count
    $normalizedExpectedHashes = @($ExpectedTargetSha256 | ForEach-Object {
            ([string]$_).ToLowerInvariant()
        })
    $expectedSha256Unique = @($normalizedExpectedHashes | Sort-Object -Unique).Count -eq
        $normalizedExpectedHashes.Count

    $targetObservations = @(for ($index = 0; $index -lt $targetCount; $index++) {
            $requestedPath = [string]$TargetPath[$index]
            $expectedSha256 = if ($index -lt $hashCount) {
                [string]$ExpectedTargetSha256[$index]
            }
            else {
                ''
            }
            $expectedSha256Valid = $expectedSha256 -cmatch '^[0-9a-fA-F]{64}$'
            $normalizedExpectedSha256 = if ($expectedSha256Valid) {
                $expectedSha256.ToLowerInvariant()
            }
            else {
                $null
            }
            $fullPath = $null
            $pathShapeSafe = Test-WindowsLocalAbsolutePathShape $requestedPath
            if ($pathShapeSafe) {
                $fullPath = [IO.Path]::GetFullPath($requestedPath)
            }
            $exists = $false
            $isLeaf = $false
            $insideRoot = $false
            $isReparse = $false
            $absoluteSafe = $false
            $isUnsigned = $false
            $sha256 = $null
            $isPortableExecutable = $false
            $hasAuthenticodeCertificateTable = $false
            if ($pathShapeSafe -and $targetRootSafe) {
                try {
                    $insideRoot = Test-WindowsPathInsideRoot `
                        -Path $fullPath -Root $targetRootFullPath
                    if ($insideRoot) {
                        $targetAccess = Invoke-WindowsNoFollowPathOperation `
                            -Path $fullPath -ExpectedKind File -Operation {
                                param($handle, $safePath)
                                Get-OfflinePeTargetFileObservation -Handle $handle
                            }
                        $exists = [bool]$targetAccess.leafOpened -and
                            [bool]$targetAccess.finalIsFile
                        $isLeaf = $exists
                        $isReparse = [bool]$targetAccess.reparseDetected
                        $absoluteSafe = [bool]$targetAccess.safe
                    }
                    if ($absoluteSafe) {
                        $peObservation = $targetAccess.value
                        $sha256 = [string]$peObservation.sha256
                        $isPortableExecutable = [bool]$peObservation.isPortableExecutable
                        $hasAuthenticodeCertificateTable =
                            [bool]$peObservation.hasAuthenticodeCertificateTable
                        $isUnsigned = [bool]$peObservation.isUnsigned
                    }
                }
                catch {
                    $absoluteSafe = $false
                    $isUnsigned = $false
                }
            }
            [pscustomobject][ordered]@{
                bindingIndex = $index
                path = if ($null -eq $fullPath) { '<invalid>' } else { $fullPath }
                sha256 = $sha256
                expectedSha256 = $normalizedExpectedSha256
                expectedSha256Valid = $expectedSha256Valid
                sha256Matches = $expectedSha256Valid -and
                    $null -ne $sha256 -and
                    $sha256 -ceq $normalizedExpectedSha256
                exists = $exists
                absoluteSafePath = $absoluteSafe
                insideAllowedRoot = $insideRoot
                isLeafFile = $isLeaf
                isReparsePoint = $isReparse
                allowedExtension = $isLeaf -and
                    [IO.Path]::GetExtension($fullPath).ToLowerInvariant() -cin
                        $script:AllowedTargetExtensions
                isPortableExecutable = $isPortableExecutable
                hasAuthenticodeCertificateTable = $hasAuthenticodeCertificateTable
                isUnsigned = $isUnsigned
            }
        })

    $targetBinding = [pscustomobject][ordered]@{
        bindingMode = 'ordered-target-path-sha256-pairs-v1'
        targetCount = $targetCount
        expectedSha256Count = $hashCount
        nonEmpty = $targetCount -gt 0
        countWithinLimit = $countWithinLimit
        countMatches = $countMatches
        orderedIndexBinding = $countMatches
        pathsUnique = $pathsUnique
        expectedSha256Unique = $expectedSha256Unique
    }

    $result = [pscustomobject][ordered]@{
        schemaVersion = 1
        observationType = 'ensou-dsh-windows-pilot-signing-observation'
        collectedAtUtc = [DateTimeOffset]::UtcNow.ToString('o')
        networkAccess = 'disabled-by-construction'
        signingPerformed = $false
        certificateStoreModified = $false
        networkPolicy = $networkPolicy
        environment = $environment
        signTool = $signToolObservation
        certificate = $certificateObservation
        tsa = Get-WindowsPilotTsaObservation `
            -TsaUri $TsaUri `
            -ExpectedTsaUriSha256 $ExpectedTsaUriSha256
        allowedTargetRoot = if ($null -eq $targetRootFullPath) {
            '<invalid>'
        }
        else {
            $targetRootFullPath
        }
        targetBinding = $targetBinding
        targets = $targetObservations
    }
    if ($null -ne $pilotRoot) { $pilotRoot.Dispose() }
    return $result
}

Export-ModuleMember -Function @(
    'Get-WindowsPilotSigningObservation',
    'Get-WindowsPilotTsaObservation',
    'Test-WindowsPilotSigningObservation',
    'Get-WindowsPrivateKeyExportability',
    'Get-WindowsPrivateKeyProviderObservation',
    'Test-WindowsLocalAbsolutePathShape',
    'Test-WindowsFixedLocalDriveClassification',
    'Test-WindowsFixedLocalDrivePath',
    'Test-WindowsPathHasReparsePoint',
    'Get-WindowsNoFollowPathObservation',
    'Invoke-WindowsPinnedExecutableOperation'
)
