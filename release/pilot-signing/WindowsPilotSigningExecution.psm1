#requires -Version 7.2

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$stateModulePath = Join-Path $PSScriptRoot '..\scripts\ProductionReleaseState.psm1'
$signingContractsModulePath = Join-Path $PSScriptRoot '..\scripts\InstallerSigningContracts.psm1'
$pilotSigningModulePath = Join-Path $PSScriptRoot 'WindowsPilotSigning.psm1'
Microsoft.PowerShell.Core\Import-Module $stateModulePath -Force -ErrorAction Stop
Microsoft.PowerShell.Core\Import-Module $signingContractsModulePath -Force -ErrorAction Stop
Microsoft.PowerShell.Core\Import-Module $pilotSigningModulePath -Force -ErrorAction Stop

$script:PolicySchemaPath = [IO.Path]::GetFullPath((Join-Path `
    $PSScriptRoot '..\schemas\windows-pilot-signing-policy-v1.schema.json'))
$script:Utf8Strict = [Text.UTF8Encoding]::new($false, $true)
$script:MaximumPolicyBytes = 1MB
$script:MaximumTargetBytes = 512MB
$script:P256Order = [Convert]::FromHexString(
    'FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551')
$script:P256HalfOrder = [Convert]::FromHexString(
    '7FFFFFFF800000007FFFFFFFFFFFFFFFDE737D56D38BCF4279DCE5617E3192A8')
$script:SoftwareKspName = 'Microsoft Software Key Storage Provider'
$script:CodeSigningEkuOid = '1.3.6.1.5.5.7.3.3'
$script:TimeStampingEkuOid = '1.3.6.1.5.5.7.3.8'

if (-not ('EnsouDshPilotSigning.StrictProcessCapture' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;

namespace EnsouDshPilotSigning
{
    public sealed class StrictCaptureBuffer
    {
        public StrictCaptureBuffer(byte[] bytes, bool overflowed)
        {
            Bytes = bytes ?? throw new ArgumentNullException(nameof(bytes));
            Overflowed = overflowed;
        }
        public byte[] Bytes { get; }
        public bool Overflowed { get; }
    }

    public sealed class StrictCaptureResult
    {
        public StrictCaptureResult(
            int exitCode,
            bool timedOut,
            StrictCaptureBuffer standardOutput,
            StrictCaptureBuffer standardError)
        {
            ExitCode = exitCode;
            TimedOut = timedOut;
            StandardOutput = standardOutput;
            StandardError = standardError;
        }
        public int ExitCode { get; }
        public bool TimedOut { get; }
        public StrictCaptureBuffer StandardOutput { get; }
        public StrictCaptureBuffer StandardError { get; }
    }

    public static class StrictProcessCapture
    {
        private const int DrainTimeoutMilliseconds = 10000;

        public static StrictCaptureResult Run(
            ProcessStartInfo startInfo,
            int timeoutMilliseconds,
            int maximumOutputBytes)
        {
            if (startInfo == null) throw new ArgumentNullException(nameof(startInfo));
            if (timeoutMilliseconds <= 0) throw new ArgumentOutOfRangeException(nameof(timeoutMilliseconds));
            if (maximumOutputBytes <= 0) throw new ArgumentOutOfRangeException(nameof(maximumOutputBytes));
            if (startInfo.UseShellExecute
                || !startInfo.RedirectStandardOutput
                || !startInfo.RedirectStandardError)
            {
                throw new InvalidOperationException(
                    "Strict capture requires two redirected raw output streams and no shell.");
            }
            return RunAsync(startInfo, timeoutMilliseconds, maximumOutputBytes)
                .GetAwaiter().GetResult();
        }

        private static async Task<StrictCaptureResult> RunAsync(
            ProcessStartInfo startInfo,
            int timeoutMilliseconds,
            int maximumOutputBytes)
        {
            using var process = new Process
            {
                StartInfo = startInfo,
                EnableRaisingEvents = true,
            };
            if (!process.Start())
            {
                throw new InvalidOperationException("The signing process did not start.");
            }

            var stdout = ReadBoundedAsync(
                process.StandardOutput.BaseStream,
                maximumOutputBytes,
                () => TryKillTree(process));
            var stderr = ReadBoundedAsync(
                process.StandardError.BaseStream,
                maximumOutputBytes,
                () => TryKillTree(process));
            var exit = process.WaitForExitAsync();
            var timedOut = false;
            if (await Task.WhenAny(exit, Task.Delay(timeoutMilliseconds))
                    .ConfigureAwait(false) != exit)
            {
                timedOut = true;
                TryKillTree(process);
            }

            var completion = Task.WhenAll(exit, stdout, stderr);
            if (await Task.WhenAny(completion, Task.Delay(DrainTimeoutMilliseconds))
                    .ConfigureAwait(false) != completion)
            {
                TryKillTree(process);
                throw new TimeoutException(
                    "The signing process streams did not close after termination.");
            }
            await completion.ConfigureAwait(false);
            return new StrictCaptureResult(
                process.ExitCode,
                timedOut,
                await stdout.ConfigureAwait(false),
                await stderr.ConfigureAwait(false));
        }

        private static async Task<StrictCaptureBuffer> ReadBoundedAsync(
            Stream input,
            int maximumBytes,
            Action overflowAction)
        {
            var retained = new byte[maximumBytes];
            var scratch = new byte[1024];
            var count = 0;
            var overflowed = false;
            while (true)
            {
                var read = await input.ReadAsync(scratch.AsMemory(0, scratch.Length))
                    .ConfigureAwait(false);
                if (read == 0) break;
                var available = maximumBytes - count;
                if (available > 0)
                {
                    var keep = Math.Min(read, available);
                    Buffer.BlockCopy(scratch, 0, retained, count, keep);
                    count += keep;
                }
                if (!overflowed && read > available)
                {
                    overflowed = true;
                    overflowAction();
                }
            }
            var exact = new byte[count];
            Buffer.BlockCopy(retained, 0, exact, 0, count);
            Array.Clear(retained, 0, retained.Length);
            Array.Clear(scratch, 0, scratch.Length);
            return new StrictCaptureBuffer(exact, overflowed);
        }

        private static void TryKillTree(Process process)
        {
            try
            {
                if (!process.HasExited) process.Kill(entireProcessTree: true);
            }
            catch (NotSupportedException)
            {
                try { if (!process.HasExited) process.Kill(); } catch { }
            }
            catch { }
        }
    }
}
'@
}

function Test-WindowsPilotAllZeroHex {
    param([Parameter(Mandatory = $true)][string]$Value)
    return $Value -cmatch '^0+$'
}

function Get-WindowsPilotSha256Bytes {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    return ProductionReleaseState\Get-ProductionSha256Bytes -Bytes $Bytes
}

function Get-WindowsPilotCertificateSha256 {
    param(
        [Parameter(Mandatory = $true)]
        [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    return $Certificate.GetCertHashString(
        [Security.Cryptography.HashAlgorithmName]::SHA256).ToLowerInvariant()
}

function Assert-WindowsPilotExactEnhancedKeyUsage {
    param(
        [Parameter(Mandatory = $true)]
        [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory = $true)][string]$ExpectedOid,
        [Parameter(Mandatory = $true)][string]$Label,
        [switch]$RequireCritical
    )

    $extensions = @($Certificate.Extensions | Where-Object {
            [string]$_.Oid.Value -ceq '2.5.29.37'
        })
    if ($extensions.Count -ne 1) {
        throw "$Label must contain exactly one Enhanced Key Usage extension."
    }
    $typed = [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new(
        $extensions[0], $extensions[0].Critical)
    $oids = @($typed.EnhancedKeyUsages | ForEach-Object { [string]$_.Value })
    if ($oids.Count -ne 1 -or $oids[0] -cne $ExpectedOid -or
        ($RequireCritical -and -not $typed.Critical)) {
        throw "$Label must contain only the approved purpose OID."
    }
    return $true
}

function Assert-WindowsPilotExactDigitalSignatureKeyUsage {
    param(
        [Parameter(Mandatory = $true)]
        [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $extensions = @($Certificate.Extensions | Where-Object {
            [string]$_.Oid.Value -ceq '2.5.29.15'
        })
    if ($extensions.Count -ne 1) {
        throw "$Label must contain exactly one Key Usage extension."
    }
    $typed = [Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
        $extensions[0], $extensions[0].Critical)
    if ($typed.KeyUsages -ne
        [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature) {
        throw "$Label must allow only Digital Signature key usage."
    }
    return $true
}

function Assert-WindowsPilotTsaTrustPolicy {
    param([Parameter(Mandatory = $true)][psobject]$TsaPolicy)

    $chains = @($TsaPolicy.trustedSignerChains)
    if ($chains.Count -lt 1 -or $chains.Count -gt 8) {
        throw 'TSA trust policy must contain between one and eight approved signer chains.'
    }
    $chainIds = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
    $chainIdentities = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
    foreach ($entry in $chains) {
        if (-not $chainIds.Add([string]$entry.chainId)) {
            throw 'TSA trust policy contains a duplicate chain identifier.'
        }
        $validFrom = ProductionReleaseState\ConvertFrom-ProductionUtc `
            -Value ([string]$entry.validFromUtc) `
            -Label 'TSA signer-chain validFromUtc'
        $validUntil = ProductionReleaseState\ConvertFrom-ProductionUtc `
            -Value ([string]$entry.validUntilUtc) `
            -Label 'TSA signer-chain validUntilUtc'
        if ($validFrom -ge $validUntil) {
            throw 'TSA signer-chain validity window must increase.'
        }

        $pins = [Collections.Generic.List[string]]::new()
        $pins.Add([string]$entry.leafCertificateSha256)
        foreach ($pin in @($entry.intermediateCertificateSha256s)) {
            $pins.Add([string]$pin)
        }
        $pins.Add([string]$entry.rootCertificateSha256)
        $uniquePins = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::Ordinal)
        foreach ($pin in $pins) {
            if ($pin -cnotmatch '^[0-9a-f]{64}$' -or
                (Test-WindowsPilotAllZeroHex -Value $pin) -or
                -not $uniquePins.Add($pin)) {
                throw 'TSA signer-chain certificate pins must be distinct, non-placeholder SHA-256 identities.'
            }
        }
        $identity = [string]::Join('|', $pins)
        if (-not $chainIdentities.Add($identity)) {
            throw 'TSA trust policy contains a duplicate signer-chain identity.'
        }
    }
    return $true
}

function ConvertTo-WindowsPilotBase64Url {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    return [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Compare-WindowsPilotUnsignedBigEndian {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Left,
        [Parameter(Mandatory = $true)][byte[]]$Right
    )
    if ($Left.Length -ne $Right.Length) {
        throw 'Unsigned integer widths differ.'
    }
    for ($index = 0; $index -lt $Left.Length; $index++) {
        if ($Left[$index] -lt $Right[$index]) { return -1 }
        if ($Left[$index] -gt $Right[$index]) { return 1 }
    }
    return 0
}

function Subtract-WindowsPilotUnsignedBigEndian {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Left,
        [Parameter(Mandatory = $true)][byte[]]$Right
    )
    if ((Compare-WindowsPilotUnsignedBigEndian -Left $Left -Right $Right) -lt 0) {
        throw 'Unsigned subtraction would be negative.'
    }
    $result = [byte[]]::new($Left.Length)
    $borrow = 0
    for ($index = $Left.Length - 1; $index -ge 0; $index--) {
        $value = [int]$Left[$index] - [int]$Right[$index] - $borrow
        if ($value -lt 0) {
            $value += 256
            $borrow = 1
        }
        else {
            $borrow = 0
        }
        $result[$index] = [byte]$value
    }
    if ($borrow -ne 0) { throw 'Unsigned subtraction underflowed.' }
    return ,$result
}

function ConvertTo-WindowsPilotLowSP256Signature {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][byte[]]$Signature)

    if ($Signature.Length -ne 64) {
        throw 'ES256 signatures must use 64-byte P1363 encoding.'
    }
    $r = [byte[]]::new(32)
    $s = [byte[]]::new(32)
    [Array]::Copy($Signature, 0, $r, 0, 32)
    [Array]::Copy($Signature, 32, $s, 0, 32)
    $zero = [byte[]]::new(32)
    if ((Compare-WindowsPilotUnsignedBigEndian -Left $r -Right $zero) -eq 0 -or
        (Compare-WindowsPilotUnsignedBigEndian -Left $r -Right $script:P256Order) -ge 0 -or
        (Compare-WindowsPilotUnsignedBigEndian -Left $s -Right $zero) -eq 0 -or
        (Compare-WindowsPilotUnsignedBigEndian -Left $s -Right $script:P256Order) -ge 0) {
        throw 'ES256 signature contains an out-of-range P-256 scalar.'
    }
    if ((Compare-WindowsPilotUnsignedBigEndian `
            -Left $s -Right $script:P256HalfOrder) -gt 0) {
        $s = Subtract-WindowsPilotUnsignedBigEndian `
            -Left $script:P256Order -Right $s
    }
    $normalized = [byte[]]::new(64)
    [Array]::Copy($r, 0, $normalized, 0, 32)
    [Array]::Copy($s, 0, $normalized, 32, 32)
    ProductionReleaseState\Assert-ProductionEs256P1363LowS `
        -Signature $normalized `
        -Label 'Windows Pilot signing response signature'
    return ,$normalized
}

function Test-WindowsPilotProtectedPolicyAcl {
    param([Parameter(Mandatory = $true)][string]$Path)

    $acl = Microsoft.PowerShell.Security\Get-Acl -LiteralPath $Path -ErrorAction Stop
    $ownerSid = ([Security.Principal.NTAccount]$acl.Owner).Translate(
        [Security.Principal.SecurityIdentifier]).Value
    if ($ownerSid -cnotin @('S-1-5-18', 'S-1-5-32-544') -or
        -not [bool]$acl.AreAccessRulesProtected) {
        throw 'Signing policy must use a protected SYSTEM-or-Administrators-owned DACL.'
    }
    $writeMask =
        [Security.AccessControl.FileSystemRights]::Write -bor
        [Security.AccessControl.FileSystemRights]::Modify -bor
        [Security.AccessControl.FileSystemRights]::FullControl -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -ne
                [Security.AccessControl.AccessControlType]::Allow -or
            ($rule.FileSystemRights -band $writeMask) -eq 0) {
            continue
        }
        $sid = ([Security.Principal.NTAccount]$rule.IdentityReference).Translate(
            [Security.Principal.SecurityIdentifier]).Value
        if ($sid -cnotin @('S-1-5-18', 'S-1-5-32-544')) {
            throw 'Signing policy grants write-capable access outside SYSTEM and Administrators.'
        }
    }
    return $true
}

function Test-WindowsPilotProtectedSigningRootAcl {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $acl = Microsoft.PowerShell.Security\Get-Acl -LiteralPath $Path -ErrorAction Stop
    $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $ownerSid = ([Security.Principal.NTAccount]$acl.Owner).Translate(
        [Security.Principal.SecurityIdentifier]).Value
    $trustedSids = @('S-1-5-18', 'S-1-5-32-544', $currentSid)
    if ($ownerSid -cnotin $trustedSids -or
        -not [bool]$acl.AreAccessRulesProtected) {
        throw "$Label must use a protected signing-identity, SYSTEM, or Administrators owned DACL."
    }
    $writeMask =
        [Security.AccessControl.FileSystemRights]::Write -bor
        [Security.AccessControl.FileSystemRights]::Modify -bor
        [Security.AccessControl.FileSystemRights]::FullControl -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -ne
                [Security.AccessControl.AccessControlType]::Allow -or
            ($rule.FileSystemRights -band $writeMask) -eq 0) {
            continue
        }
        $sid = ([Security.Principal.NTAccount]$rule.IdentityReference).Translate(
            [Security.Principal.SecurityIdentifier]).Value
        if ($sid -cnotin $trustedSids) {
            throw "$Label grants write-capable access outside the signing identity, SYSTEM, and Administrators."
        }
    }
    return $true
}

function Assert-WindowsPilotOrdinaryRoot {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )
    if (-not (WindowsPilotSigning\Test-WindowsLocalAbsolutePathShape `
            -Path $Path -Directory)) {
        throw "$Label must be one absolute fixed-local-drive path."
    }
    $fullPath = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $observation = WindowsPilotSigning\Get-WindowsNoFollowPathObservation `
        -Path $fullPath -ExpectedKind Directory
    if (-not [bool]$observation.safe -or
        [bool]$observation.reparseDetected -or
        -not [bool]$observation.finalIsDirectory) {
        throw "$Label must be one existing ordinary non-linked directory."
    }
    return $fullPath
}

function Assert-WindowsPilotPolicyLane {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][psobject]$Policy,
        [AllowEmptyString()][string]$ExpectedExecutionAdmission = '',
        [AllowEmptyString()][string]$ExpectedProfile = ''
    )

    $profile = [string]$Policy.profile
    $admission = [string]$Policy.executionAdmission
    $contract = if ($profile -ceq 'PersonalTwoDevice') {
        [pscustomobject][ordered]@{
            Profile = 'PersonalTwoDevice'
            ExecutionAdmission = 'PERSONAL_PILOT_SIGNING'
            InstallerKeyProperty = 'personalInstallerSigning'
            InstallerPurpose = 'personal-installer-signing-response'
        }
    }
    elseif ($profile -ceq 'EnterpriseTwoDevice') {
        [pscustomobject][ordered]@{
            Profile = 'EnterpriseTwoDevice'
            ExecutionAdmission = 'ENTERPRISE_PILOT_SIGNING'
            InstallerKeyProperty = 'enterpriseInstallerSigning'
            InstallerPurpose = 'installer-signing-response'
        }
    }
    else {
        throw 'Windows Pilot signing policy profile is not an approved two-device lane.'
    }
    if ($admission -cne [string]$contract.ExecutionAdmission) {
        throw 'Windows Pilot signing policy profile and execution admission are not the same lane.'
    }
    if (-not [string]::IsNullOrEmpty($ExpectedExecutionAdmission) -and
        $admission -cne $ExpectedExecutionAdmission) {
        throw 'Windows Pilot signing policy execution admission is outside the requested lane.'
    }
    if (-not [string]::IsNullOrEmpty($ExpectedProfile) -and
        $profile -cne $ExpectedProfile) {
        throw 'Windows Pilot signing policy profile is outside the requested lane.'
    }
    return $contract
}

function Read-WindowsPilotSigningPolicy {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)

    $policyInput = ProductionReleaseState\Open-ProductionReleaseInput `
        -Path $Path -Label 'Windows Pilot signing execution policy' `
        -MaximumBytes $script:MaximumPolicyBytes
    try {
        [void](Test-WindowsPilotProtectedPolicyAcl -Path $policyInput.Path)
        [byte[]]$bytes = ProductionReleaseState\Read-ProductionReleaseInputBytes `
            -Descriptor $policyInput -Label 'Windows Pilot signing execution policy'
        $value = ProductionReleaseState\ConvertFrom-StrictProductionJsonBytes `
            -Bytes $bytes `
            -Label 'Windows Pilot signing execution policy' `
            -SchemaPath $script:PolicySchemaPath
        $canonicalBytes = ProductionReleaseState\ConvertTo-ProductionJsonBytes -Value $value
        if ($canonicalBytes.Length -ne $bytes.Length -or
            (Get-WindowsPilotSha256Bytes -Bytes $canonicalBytes) -cne $policyInput.Sha256) {
            throw 'Windows Pilot signing execution policy must use exact canonical UTF-8 JSON.'
        }
        $lane = Assert-WindowsPilotPolicyLane -Policy $value
        foreach ($pin in @(
                [string]$value.signTool.sha256,
                [string]$value.authenticode.certificateThumbprintSha1,
                [string]$value.authenticode.certificateSha256,
                [string]$value.authenticode.pilotRootCertificateSha256)) {
            if (Test-WindowsPilotAllZeroHex -Value $pin) {
                throw 'Windows Pilot signing execution policy contains a placeholder trust pin.'
            }
        }
        $installerKey = $value.responseKeys.(
            [string]$lane.InstallerKeyProperty)
        if ([string]$installerKey.purpose -cne [string]$lane.InstallerPurpose -or
            [string]$value.responseKeys.clientSigning.keyName -ceq
                [string]$installerKey.keyName -or
            [string]$value.responseKeys.clientSigning.keyId -ceq
                [string]$installerKey.keyId -or
            (([string]$value.responseKeys.clientSigning.x -ceq
                    [string]$installerKey.x) -and
                ([string]$value.responseKeys.clientSigning.y -ceq
                    [string]$installerKey.y))) {
            throw 'Client and Installer response keys must be independent and lane-specific.'
        }
        $tsa = WindowsPilotSigning\Get-WindowsPilotTsaObservation `
            -TsaUri ([string]$value.tsa.uri) `
            -ExpectedTsaUriSha256 ([string]$value.tsa.canonicalUriSha256)
        if (-not [bool]$tsa.repositoryPinApproved -or
            -not [bool]$tsa.sha256Matches) {
            throw 'Windows Pilot signing execution policy TSA is not repository-pinned.'
        }
        [void](Assert-WindowsPilotTsaTrustPolicy -TsaPolicy $value.tsa)
        $requestRoot = Assert-WindowsPilotOrdinaryRoot `
            -Path ([string]$value.roots.requestRoot) -Label 'Signing request root'
        $transactionRoot = Assert-WindowsPilotOrdinaryRoot `
            -Path ([string]$value.roots.transactionRoot) -Label 'Signing transaction root'
        $outputRoot = Assert-WindowsPilotOrdinaryRoot `
            -Path ([string]$value.roots.outputRoot) -Label 'Signing output root'
        [void](Test-WindowsPilotProtectedSigningRootAcl `
            -Path $requestRoot -Label 'Signing request root')
        [void](Test-WindowsPilotProtectedSigningRootAcl `
            -Path $transactionRoot -Label 'Signing transaction root')
        [void](Test-WindowsPilotProtectedSigningRootAcl `
            -Path $outputRoot -Label 'Signing output root')
        if (-not [IO.Path]::GetPathRoot($transactionRoot).Equals(
                [IO.Path]::GetPathRoot($outputRoot),
                [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Signing transaction and output roots must use the same volume.'
        }
        $value.roots.requestRoot = $requestRoot
        $value.roots.transactionRoot = $transactionRoot
        $value.roots.outputRoot = $outputRoot
        $policyInput | Add-Member -NotePropertyName Value -NotePropertyValue $value
        [void](ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
            -Descriptor $policyInput -Label 'Windows Pilot signing execution policy')
        return $policyInput
    }
    catch {
        $policyInput.Stream.Dispose()
        throw
    }
}

function New-WindowsPilotSignToolStartInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$SignToolPath,
        [Parameter(Mandatory = $true)][psobject]$Policy,
        [Parameter(Mandatory = $true)][string]$TargetPath
    )

    if (-not [IO.Path]::IsPathFullyQualified($SignToolPath) -or
        -not [IO.Path]::IsPathFullyQualified($TargetPath)) {
        throw 'SignTool and target paths must be absolute.'
    }
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = [IO.Path]::GetFullPath($SignToolPath)
    $start.WorkingDirectory = [IO.Path]::GetDirectoryName(
        [IO.Path]::GetFullPath($TargetPath))
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.WindowStyle = [Diagnostics.ProcessWindowStyle]::Hidden
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in @(
            'sign',
            '/fd', 'SHA256',
            '/sha1', ([string]$Policy.authenticode.certificateThumbprintSha1).ToUpperInvariant(),
            '/tr', [string]$Policy.tsa.uri,
            '/td', 'SHA256',
            [IO.Path]::GetFullPath($TargetPath))) {
        [void]$start.ArgumentList.Add($argument)
    }
    $start.Environment.Clear()
    $systemRoot = [Environment]::GetEnvironmentVariable('SystemRoot')
    if ([string]::IsNullOrWhiteSpace($systemRoot)) {
        $systemRoot = [Environment]::GetFolderPath(
            [Environment+SpecialFolder]::Windows)
    }
    if ([string]::IsNullOrWhiteSpace($systemRoot)) {
        throw 'Native Windows system directory is unavailable.'
    }
    $temporaryRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    $start.Environment['SystemRoot'] = $systemRoot
    $start.Environment['WINDIR'] = $systemRoot
    $start.Environment['PATH'] = Join-Path $systemRoot 'System32'
    $start.Environment['TEMP'] = $temporaryRoot
    $start.Environment['TMP'] = $temporaryRoot
    return $start
}

function Assert-WindowsPilotResponseKey {
    param([Parameter(Mandatory = $true)][psobject]$KeyPolicy)

    if (-not [OperatingSystem]::IsWindows() -or
        [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -ne
            [Runtime.InteropServices.Architecture]::X64) {
        throw 'Response signing requires native Windows x64 PowerShell.'
    }
    $provider = [Security.Cryptography.CngProvider]::new(
        $script:SoftwareKspName)
    $key = [Security.Cryptography.CngKey]::Open(
        [string]$KeyPolicy.keyName,
        $provider,
        [Security.Cryptography.CngKeyOpenOptions]::UserKey)
    try {
        if ([string]$key.Provider.Provider -cne $script:SoftwareKspName -or
            [bool]$key.IsMachineKey -or
            [string]$key.AlgorithmGroup.AlgorithmGroup -cne 'ECDSA' -or
            [int]$key.KeySize -ne 256 -or
            [int]$key.ExportPolicy -ne 0) {
            throw 'Response key is not a non-exportable CurrentUser Software KSP P-256 key.'
        }
        $ecdsa = [Security.Cryptography.ECDsaCng]::new($key)
        try {
            $parameters = $ecdsa.ExportParameters($false)
            if ((ConvertTo-WindowsPilotBase64Url -Bytes $parameters.Q.X) -cne
                    [string]$KeyPolicy.x -or
                (ConvertTo-WindowsPilotBase64Url -Bytes $parameters.Q.Y) -cne
                    [string]$KeyPolicy.y) {
                throw 'Response key public coordinates do not match the protected policy.'
            }
        }
        finally {
            $ecdsa.Dispose()
        }
        return $true
    }
    finally {
        $key.Dispose()
    }
}

function New-WindowsPilotEs256ResponseSignature {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][byte[]]$Payload,
        [Parameter(Mandatory = $true)][psobject]$KeyPolicy
    )

    if ($Payload.Length -le 0 -or $Payload.Length -gt 16MB) {
        throw 'Signing response authentication payload is outside its byte bound.'
    }
    [void](Assert-WindowsPilotResponseKey -KeyPolicy $KeyPolicy)
    $provider = [Security.Cryptography.CngProvider]::new(
        $script:SoftwareKspName)
    $key = [Security.Cryptography.CngKey]::Open(
        [string]$KeyPolicy.keyName,
        $provider,
        [Security.Cryptography.CngKeyOpenOptions]::UserKey)
    $ecdsa = $null
    try {
        $ecdsa = [Security.Cryptography.ECDsaCng]::new($key)
        [byte[]]$raw = $ecdsa.SignData(
            $Payload,
            [Security.Cryptography.HashAlgorithmName]::SHA256,
            [Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)
        [byte[]]$lowS = ConvertTo-WindowsPilotLowSP256Signature -Signature $raw
        if (-not $ecdsa.VerifyData(
                $Payload,
                $lowS,
                [Security.Cryptography.HashAlgorithmName]::SHA256,
                [Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)) {
            throw 'Normalized signing response signature did not verify locally.'
        }
        return ConvertTo-WindowsPilotBase64Url -Bytes $lowS
    }
    finally {
        if ($null -ne $ecdsa) { $ecdsa.Dispose() }
        $key.Dispose()
    }
}

function Get-WindowsPilotSigningCertificate {
    param([Parameter(Mandatory = $true)][psobject]$Policy)

    if (-not [OperatingSystem]::IsWindows()) {
        throw 'Authenticode signing requires Windows.'
    }
    $store = [Security.Cryptography.X509Certificates.X509Store]::new(
        [Security.Cryptography.X509Certificates.StoreName]::My,
        [Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser)
    $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
    try {
        $matches = @($store.Certificates | Where-Object {
            $_.Thumbprint.Replace(' ', '').ToLowerInvariant() -ceq
                [string]$Policy.authenticode.certificateThumbprintSha1
        })
        if ($matches.Count -ne 1) {
            throw 'Protected policy must select exactly one CurrentUser/My certificate.'
        }
        return [Security.Cryptography.X509Certificates.X509Certificate2]::new(
            $matches[0])
    }
    finally {
        $store.Close()
        $store.Dispose()
    }
}

function Assert-WindowsPilotSigningCertificate {
    param([Parameter(Mandatory = $true)][psobject]$Policy)

    $certificate = Get-WindowsPilotSigningCertificate -Policy $Policy
    $rootInput = $null
    $root = $null
    $chain = $null
    try {
        if (-not $certificate.HasPrivateKey -or
            $certificate.GetCertHashString(
                [Security.Cryptography.HashAlgorithmName]::SHA256).
                    ToLowerInvariant() -cne
                [string]$Policy.authenticode.certificateSha256 -or
            (WindowsPilotSigning\Get-WindowsPrivateKeyExportability `
                    -Certificate $certificate) -cne 'NonExportable') {
            throw 'Authenticode certificate identity or private-key policy differs from policy.'
        }
        $provider = WindowsPilotSigning\Get-WindowsPrivateKeyProviderObservation `
            -Certificate $certificate
        if ([string]$provider.providerType -cne 'CNG' -or
            [string]$provider.providerName -cne
                [string]$Policy.authenticode.provider -or
            [string]$provider.algorithmGroup -cne
                [string]$Policy.authenticode.algorithmGroup -or
            [int]$provider.keySizeBits -ne [int]$Policy.authenticode.keySizeBits -or
            [bool]$provider.isMachineKey -or
            -not [bool]$provider.currentUserSoftwareKsp) {
            throw 'Authenticode private key is not the pinned non-exportable CurrentUser CNG key.'
        }
        $now = [DateTimeOffset]::UtcNow
        if ($certificate.NotBefore.ToUniversalTime() -gt $now.UtcDateTime -or
            $certificate.NotAfter.ToUniversalTime() -le
                $now.AddDays([int]$Policy.authenticode.minimumValidityDays).UtcDateTime) {
            throw 'Authenticode certificate is not valid for the minimum policy lifetime.'
        }
        [void](Assert-WindowsPilotExactEnhancedKeyUsage `
            -Certificate $certificate `
            -ExpectedOid $script:CodeSigningEkuOid `
            -Label 'Authenticode certificate')
        [void](Assert-WindowsPilotExactDigitalSignatureKeyUsage `
            -Certificate $certificate `
            -Label 'Authenticode certificate')

        $rootInput = ProductionReleaseState\Open-ProductionReleaseInput `
            -Path ([string]$Policy.authenticode.pilotRootCertificatePath) `
            -Label 'Pinned Pilot root certificate' -MaximumBytes 1MB
        [byte[]]$rootBytes = ProductionReleaseState\Read-ProductionReleaseInputBytes `
            -Descriptor $rootInput -Label 'Pinned Pilot root certificate'
        if ($rootInput.Sha256 -cne
                [string]$Policy.authenticode.pilotRootCertificateSha256) {
            throw 'Pilot root certificate bytes differ from protected policy.'
        }
        $root = [Security.Cryptography.X509Certificates.X509Certificate2]::new($rootBytes)
        $chain = [Security.Cryptography.X509Certificates.X509Chain]::new()
        $chain.ChainPolicy.TrustMode =
            [Security.Cryptography.X509Certificates.X509ChainTrustMode]::CustomRootTrust
        $chain.ChainPolicy.CustomTrustStore.Add($root)
        [void]$chain.ChainPolicy.ApplicationPolicy.Add(
            [Security.Cryptography.Oid]::new($script:CodeSigningEkuOid))
        $chain.ChainPolicy.RevocationMode =
            [Security.Cryptography.X509Certificates.X509RevocationMode]::Online
        $chain.ChainPolicy.RevocationFlag =
            [Security.Cryptography.X509Certificates.X509RevocationFlag]::ExcludeRoot
        $chain.ChainPolicy.VerificationFlags =
            [Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
        $chain.ChainPolicy.DisableCertificateDownloads = $false
        $chain.ChainPolicy.UrlRetrievalTimeout = [TimeSpan]::FromSeconds(20)
        if (-not $chain.Build($certificate) -or $chain.ChainElements.Count -lt 2) {
            throw 'Authenticode certificate chain or online revocation proof is invalid.'
        }
        $terminal = $chain.ChainElements[$chain.ChainElements.Count - 1].Certificate
        if ($terminal.GetCertHashString(
                [Security.Cryptography.HashAlgorithmName]::SHA256).
                    ToLowerInvariant() -cne
                [string]$Policy.authenticode.pilotRootCertificateSha256) {
            throw 'Authenticode certificate chain does not terminate at the pinned Pilot root.'
        }
        [void](ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
            -Descriptor $rootInput -Label 'Pinned Pilot root certificate')
        return $certificate
    }
    catch {
        $certificate.Dispose()
        throw
    }
    finally {
        if ($null -ne $chain) { $chain.Dispose() }
        if ($null -ne $root) { $root.Dispose() }
        if ($null -ne $rootInput) { $rootInput.Stream.Dispose() }
    }
}

function Assert-WindowsPilotTsaTrustEvidence {
    param(
        [Parameter(Mandatory = $true)][psobject]$Policy,
        [Parameter(Mandatory = $true)][string]$TargetPath,
        [Parameter(Mandatory = $true)][psobject]$AuthenticodeEvidence
    )

    [void](Assert-WindowsPilotTsaTrustPolicy -TsaPolicy $Policy.tsa)
    $signature = Microsoft.PowerShell.Security\Get-AuthenticodeSignature `
        -LiteralPath $TargetPath
    if ([string]$signature.Status -cne 'Valid' -or
        $null -eq $signature.TimeStamperCertificate) {
        throw 'Signed output lacks a valid Windows timestamp signer certificate.'
    }

    $timestampCertificate = $signature.TimeStamperCertificate
    $chain = $null
    try {
        $leafSha256 = Get-WindowsPilotCertificateSha256 `
            -Certificate $timestampCertificate
        if ($leafSha256 -cne
            [string]$AuthenticodeEvidence.TimestampSignerCertificateSha256) {
            throw 'RFC3161 timestamp signer identity differs between embedded and Windows evidence.'
        }
        [void](Assert-WindowsPilotExactEnhancedKeyUsage `
            -Certificate $timestampCertificate `
            -ExpectedOid $script:TimeStampingEkuOid `
            -Label 'RFC3161 timestamp signer certificate' `
            -RequireCritical)

        $timestamp = ProductionReleaseState\ConvertFrom-ProductionUtc `
            -Value ([string]$AuthenticodeEvidence.TimestampUtc) `
            -Label 'RFC3161 timestamp evidence'
        $notBefore = [DateTimeOffset]($timestampCertificate.NotBefore.ToUniversalTime())
        $notAfter = [DateTimeOffset]($timestampCertificate.NotAfter.ToUniversalTime())
        if ($timestamp -lt $notBefore -or $timestamp -gt $notAfter) {
            throw 'RFC3161 timestamp lies outside the timestamp signer certificate validity interval.'
        }

        $chain = [Security.Cryptography.X509Certificates.X509Chain]::new()
        $chain.ChainPolicy.VerificationFlags =
            [Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
        $chain.ChainPolicy.VerificationTime = $timestamp.UtcDateTime
        [void]$chain.ChainPolicy.ApplicationPolicy.Add(
            [Security.Cryptography.Oid]::new($script:TimeStampingEkuOid))
        $chain.ChainPolicy.RevocationMode =
            [Security.Cryptography.X509Certificates.X509RevocationMode]::Online
        $chain.ChainPolicy.RevocationFlag =
            [Security.Cryptography.X509Certificates.X509RevocationFlag]::ExcludeRoot
        $chain.ChainPolicy.DisableCertificateDownloads = $false
        $chain.ChainPolicy.UrlRetrievalTimeout = [TimeSpan]::FromSeconds(20)
        if (-not $chain.Build($timestampCertificate) -or
            $chain.ChainElements.Count -lt 2 -or
            @($chain.ChainStatus).Count -ne 0) {
            throw 'RFC3161 timestamp signer chain or online revocation proof is invalid.'
        }

        $chainSha256s = @($chain.ChainElements | ForEach-Object {
                Get-WindowsPilotCertificateSha256 -Certificate $_.Certificate
            })
        if ($chainSha256s[0] -cne $leafSha256) {
            throw 'RFC3161 timestamp signer chain does not begin at the observed signer.'
        }
        $intermediateSha256s = if ($chainSha256s.Count -gt 2) {
            @($chainSha256s[1..($chainSha256s.Count - 2)])
        }
        else {
            @()
        }
        $rootSha256 = [string]$chainSha256s[$chainSha256s.Count - 1]

        $matches = [Collections.Generic.List[object]]::new()
        foreach ($approved in @($Policy.tsa.trustedSignerChains)) {
            $validFrom = ProductionReleaseState\ConvertFrom-ProductionUtc `
                -Value ([string]$approved.validFromUtc) `
                -Label 'TSA signer-chain validFromUtc'
            $validUntil = ProductionReleaseState\ConvertFrom-ProductionUtc `
                -Value ([string]$approved.validUntilUtc) `
                -Label 'TSA signer-chain validUntilUtc'
            if ($timestamp -lt $validFrom -or $timestamp -ge $validUntil -or
                [string]$approved.leafCertificateSha256 -cne $leafSha256 -or
                [string]$approved.rootCertificateSha256 -cne $rootSha256) {
                continue
            }
            $approvedIntermediates = @($approved.intermediateCertificateSha256s)
            if ($approvedIntermediates.Count -ne $intermediateSha256s.Count) {
                continue
            }
            $intermediatesMatch = $true
            for ($index = 0; $index -lt $intermediateSha256s.Count; $index++) {
                if ([string]$approvedIntermediates[$index] -cne
                    [string]$intermediateSha256s[$index]) {
                    $intermediatesMatch = $false
                    break
                }
            }
            if ($intermediatesMatch) { $matches.Add($approved) }
        }
        if ($matches.Count -ne 1) {
            throw 'RFC3161 timestamp signer chain does not match exactly one approved policy identity.'
        }

        return [pscustomobject][ordered]@{
            fileName = [string]$AuthenticodeEvidence.FileName
            signedFileSha256 = [string]$AuthenticodeEvidence.SignedFileSha256
            chainId = [string]$matches[0].chainId
            timestampUtc = [string]$AuthenticodeEvidence.TimestampUtc
            leafCertificateSha256 = $leafSha256
            intermediateCertificateSha256s = [string[]]$intermediateSha256s
            rootCertificateSha256 = $rootSha256
            timeStampingEkuOid = $script:TimeStampingEkuOid
            timeStampingEkuExact = $true
            timeStampingEkuCritical = $true
            chainApplicationPolicyOid = $script:TimeStampingEkuOid
            chainTrusted = $true
            revocationMode = 'Online'
            revocationFlag = 'ExcludeRoot'
            onlineRevocationChecked = $true
            policyTsaUriSha256 = [string]$Policy.tsa.canonicalUriSha256
        }
    }
    finally {
        if ($null -ne $chain) { $chain.Dispose() }
    }
}

function Test-WindowsPilotExactStringArray {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Left,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Right
    )

    if ($Left.Count -ne $Right.Count) { return $false }
    for ($index = 0; $index -lt $Left.Count; $index++) {
        if ([string]$Left[$index] -cne [string]$Right[$index]) { return $false }
    }
    return $true
}

function Assert-WindowsPilotBoundTsaTrustEvidence {
    param(
        [Parameter(Mandatory = $true)][psobject]$Policy,
        [Parameter(Mandatory = $true)][psobject]$AuthenticodeEvidence
    )

    $trust = $AuthenticodeEvidence.TsaTrustEvidence
    if ($null -eq $trust -or
        [string]$trust.fileName -cne [string]$AuthenticodeEvidence.FileName -or
        [string]$trust.signedFileSha256 -cne
            [string]$AuthenticodeEvidence.SignedFileSha256 -or
        [string]$trust.timestampUtc -cne [string]$AuthenticodeEvidence.TimestampUtc -or
        [string]$trust.leafCertificateSha256 -cne
            [string]$AuthenticodeEvidence.TimestampSignerCertificateSha256 -or
        [string]$trust.timeStampingEkuOid -cne $script:TimeStampingEkuOid -or
        -not [bool]$trust.timeStampingEkuExact -or
        -not [bool]$trust.timeStampingEkuCritical -or
        [string]$trust.chainApplicationPolicyOid -cne $script:TimeStampingEkuOid -or
        -not [bool]$trust.chainTrusted -or
        [string]$trust.revocationMode -cne 'Online' -or
        [string]$trust.revocationFlag -cne 'ExcludeRoot' -or
        -not [bool]$trust.onlineRevocationChecked -or
        [string]$trust.policyTsaUriSha256 -cne
            [string]$Policy.tsa.canonicalUriSha256) {
        throw 'Signed output lacks exact TSA identity, EKU, chain, or online revocation evidence.'
    }

    $timestamp = ProductionReleaseState\ConvertFrom-ProductionUtc `
        -Value ([string]$AuthenticodeEvidence.TimestampUtc) `
        -Label 'Bound RFC3161 timestamp evidence'
    $matches = @($Policy.tsa.trustedSignerChains | Where-Object {
            $approved = $_
            $validFrom = ProductionReleaseState\ConvertFrom-ProductionUtc `
                -Value ([string]$approved.validFromUtc) `
                -Label 'TSA signer-chain validFromUtc'
            $validUntil = ProductionReleaseState\ConvertFrom-ProductionUtc `
                -Value ([string]$approved.validUntilUtc) `
                -Label 'TSA signer-chain validUntilUtc'
            return [string]$approved.chainId -ceq [string]$trust.chainId -and
                $timestamp -ge $validFrom -and $timestamp -lt $validUntil -and
                [string]$approved.leafCertificateSha256 -ceq
                    [string]$trust.leafCertificateSha256 -and
                [string]$approved.rootCertificateSha256 -ceq
                    [string]$trust.rootCertificateSha256 -and
                (Test-WindowsPilotExactStringArray `
                    -Left @($approved.intermediateCertificateSha256s) `
                    -Right @($trust.intermediateCertificateSha256s))
        })
    if ($matches.Count -ne 1) {
        throw 'Signed output TSA evidence is not bound to exactly one approved signer-chain window.'
    }
    return $true
}

function Invoke-WindowsPilotPinnedSignTool {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][psobject]$Policy,
        [Parameter(Mandatory = $true)][string]$TargetPath
    )

    $operation = {
        param($safeSignToolPath)
        $start = New-WindowsPilotSignToolStartInfo `
            -SignToolPath $safeSignToolPath -Policy $Policy -TargetPath $TargetPath
        return [EnsouDshPilotSigning.StrictProcessCapture]::Run(
            $start,
            [int]$Policy.limits.signToolTimeoutSeconds * 1000,
            [int]$Policy.limits.maximumProcessOutputBytes)
    }.GetNewClosure()
    $protected = WindowsPilotSigning\Invoke-WindowsPinnedExecutableOperation `
        -Path ([string]$Policy.signTool.path) `
        -ExpectedFileName 'signtool.exe' `
        -ExpectedFileVersion ([string]$Policy.signTool.fileVersion) `
        -ExpectedSha256 ([string]$Policy.signTool.sha256) `
        -Operation $operation
    if (-not [bool]$protected.safe -or $null -eq $protected.value) {
        throw 'Pinned SignTool could not be held and executed under its protected identity.'
    }
    $capture = $protected.value
    if ([bool]$capture.TimedOut -or
        [bool]$capture.StandardOutput.Overflowed -or
        [bool]$capture.StandardError.Overflowed -or
        [int]$capture.ExitCode -ne 0) {
        throw 'Pinned SignTool failed, timed out, or exceeded its output bound.'
    }
    return [pscustomobject][ordered]@{
        exitCode = [int]$capture.ExitCode
        timedOut = [bool]$capture.TimedOut
        stdoutSizeBytes = [int]$capture.StandardOutput.Bytes.Length
        stdoutSha256 = Get-WindowsPilotSha256Bytes -Bytes $capture.StandardOutput.Bytes
        stderrSizeBytes = [int]$capture.StandardError.Bytes.Length
        stderrSha256 = Get-WindowsPilotSha256Bytes -Bytes $capture.StandardError.Bytes
    }
}

function Test-WindowsPilotPathUnderRoot {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Root
    )
    $fullPath = [IO.Path]::GetFullPath($Path)
    $fullRoot = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    return $fullPath.StartsWith(
        $fullRoot + '\', [StringComparison]::OrdinalIgnoreCase)
}

function Assert-WindowsPilotDirectChildPath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $fullPath = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $fullRoot = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    if ([IO.Path]::GetDirectoryName($fullPath) -cne $fullRoot -or
        [IO.Path]::GetFileName($fullPath) -cnotmatch
            '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$') {
        throw "$Label must be one canonical direct child of its protected root."
    }
    return $fullPath
}

function Write-WindowsPilotNewFileBytes {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][byte[]]$Bytes
    )
    $stream = [IO.File]::Open(
        $Path,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None)
    try {
        $stream.Write($Bytes, 0, $Bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
}

function Copy-WindowsPilotLockedInput {
    param(
        [Parameter(Mandatory = $true)]$Source,
        [Parameter(Mandatory = $true)][string]$DestinationPath
    )
    $destination = [IO.File]::Open(
        $DestinationPath,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None)
    try {
        $Source.Stream.Position = 0
        $Source.Stream.CopyTo($destination, 1MB)
        $destination.Flush($true)
        $Source.Stream.Position = 0
    }
    finally {
        $destination.Dispose()
    }
}

function Assert-WindowsPilotUnsignedSource {
    param(
        [Parameter(Mandatory = $true)]$Descriptor,
        [Parameter(Mandatory = $true)][psobject]$Target
    )
    [byte[]]$bytes = ProductionReleaseState\Read-ProductionReleaseInputBytes `
        -Descriptor $Descriptor -Label "Unsigned signing source $($Target.role)"
    $peContentSha256 = ProductionReleaseState\Get-PeContentSha256 -Bytes $bytes
    if ($peContentSha256 -cne [string]$Target.peContentSha256) {
        throw 'Unsigned signing source PE-content identity differs from its request.'
    }
    $signature = Microsoft.PowerShell.Security\Get-AuthenticodeSignature `
        -LiteralPath $Descriptor.Path
    if ([string]$signature.Status -cne 'NotSigned' -or
        $null -ne $signature.SignerCertificate) {
        throw 'Signing source must be an unsigned Windows PE image.'
    }
    return $peContentSha256
}

function Assert-WindowsPilotTransactionInventory {
    param(
        [Parameter(Mandatory = $true)][string]$TransactionPath,
        [Parameter(Mandatory = $true)][string[]]$ExpectedFileNames,
        [Parameter(Mandatory = $true)][string]$ResponseFileName
    )
    $items = @(Get-ChildItem -LiteralPath $TransactionPath -Force -Recurse)
    foreach ($item in $items) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Signing transaction inventory contains a filesystem link.'
        }
    }
    $directories = @($items | Where-Object PSIsContainer)
    if ($directories.Count -ne 1 -or $directories[0].Name -cne 'signed') {
        throw 'Signing transaction contains an unexpected directory.'
    }
    $files = @($items | Where-Object { -not $_.PSIsContainer })
    if ($files.Count -ne $ExpectedFileNames.Count + 1) {
        throw 'Signing transaction contains an unexpected file count.'
    }
    $actualRootFiles = @($files | Where-Object {
        $_.DirectoryName -ceq [IO.Path]::GetFullPath($TransactionPath)
    })
    if ($actualRootFiles.Count -ne 1 -or
        $actualRootFiles[0].Name -cne $ResponseFileName) {
        throw 'Signing transaction response inventory is not exact.'
    }
    $actualSigned = @($files | Where-Object {
        $_.DirectoryName -ceq (Join-Path $TransactionPath 'signed')
    } | ForEach-Object Name | Sort-Object -CaseSensitive)
    $expectedSigned = @($ExpectedFileNames | Sort-Object -CaseSensitive)
    if (($actualSigned -join [char]0) -cne ($expectedSigned -join [char]0)) {
        throw 'Signing transaction signed-file inventory is not exact.'
    }
    return $true
}

function Remove-WindowsPilotFailedTransaction {
    param(
        [Parameter(Mandatory = $true)][string]$TransactionPath,
        [Parameter(Mandatory = $true)][string]$TransactionRoot
    )
    $leaf = [IO.Path]::GetFileName($TransactionPath)
    if ($leaf -cnotmatch '^txn-[0-9a-f]{32}$' -or
        -not (Test-WindowsPilotPathUnderRoot `
            -Path $TransactionPath -Root $TransactionRoot)) {
        throw 'Refusing cleanup outside the exact generated signing transaction.'
    }
    if (Test-Path -LiteralPath $TransactionPath) {
        [IO.Directory]::Delete($TransactionPath, $true)
    }
}

function Invoke-WindowsPilotSigningTransactionCore {
    param(
        [Parameter(Mandatory = $true)]$PolicyInput,
        [Parameter(Mandatory = $true)][object[]]$Targets,
        [Parameter(Mandatory = $true)][string]$FinalOutputPath,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.json$')]
        [string]$ResponseFileName,
        [Parameter(Mandatory = $true)][scriptblock]$ResponseBuilder,
        [Parameter(Mandatory = $true)][scriptblock]$ResponseValidator,
        [Parameter(Mandatory = $true)][scriptblock]$CertificateAdmissionOperation,
        [Parameter(Mandatory = $true)][scriptblock]$SourceAdmissionOperation,
        [Parameter(Mandatory = $true)][scriptblock]$SignOperation,
        [Parameter(Mandatory = $true)][scriptblock]$EvidenceOperation,
        [AllowEmptyString()][string]$ExpectedExecutionAdmission = '',
        [AllowEmptyString()][string]$ExpectedProfile = ''
    )

    $policy = $PolicyInput.Value
    if ([string]$policy.executionAdmission -notin @(
            'PERSONAL_PILOT_SIGNING', 'ENTERPRISE_PILOT_SIGNING')) {
        throw 'Signing transaction requires an execution-admitted policy.'
    }
    if (-not [string]::IsNullOrEmpty($ExpectedExecutionAdmission) -and
        -not [string]::IsNullOrEmpty($ExpectedProfile)) {
        [void](Assert-WindowsPilotPolicyLane `
            -Policy $policy `
            -ExpectedExecutionAdmission $ExpectedExecutionAdmission `
            -ExpectedProfile $ExpectedProfile)
    }
    [void](ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
        -Descriptor $PolicyInput -Label 'Windows Pilot signing execution policy')
    if ($Targets.Count -lt 1 -or $Targets.Count -gt 4) {
        throw 'Signing transaction must contain between one and four PE targets.'
    }
    $finalPath = Assert-WindowsPilotDirectChildPath `
        -Path $FinalOutputPath -Root ([string]$policy.roots.outputRoot) `
        -Label 'Signing final output'
    if (Test-Path -LiteralPath $finalPath) {
        throw 'Signing final output already exists.'
    }

    $roles = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
    $names = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
    $sourceInputs = [Collections.Generic.List[object]]::new()
    $transactionPath = $null
    $directoryLease = $null
    $certificateAdmission = $null
    $committed = $false
    try {
        $certificateAdmission = & $CertificateAdmissionOperation $policy
        if ($null -eq $certificateAdmission) {
            throw 'Signing certificate admission did not return retained proof.'
        }
        foreach ($target in $Targets) {
            if ([string]$target.role -cnotmatch '^[a-z][a-z0-9-]*$' -or
                [string]$target.fileName -cnotmatch
                    '^[A-Za-z0-9][A-Za-z0-9._-]*\.exe$' -or
                -not $roles.Add([string]$target.role) -or
                -not $names.Add([string]$target.fileName) -or
                [IO.Path]::GetFileName([string]$target.sourcePath) -cne
                    [string]$target.fileName -or
                -not (Test-WindowsPilotPathUnderRoot `
                    -Path ([string]$target.sourcePath) `
                    -Root ([string]$policy.roots.requestRoot))) {
                throw 'Signing target identity or request-root binding is invalid.'
            }
            $input = ProductionReleaseState\Open-ProductionReleaseInput `
                -Path ([string]$target.sourcePath) `
                -Label "Unsigned signing source $($target.role)" `
                -MaximumBytes $script:MaximumTargetBytes
            $sourceInputs.Add($input)
            if ($input.FileName -cne [string]$target.fileName -or
                [int64]$input.SizeBytes -ne [int64]$target.sizeBytes -or
                [string]$input.Sha256 -cne [string]$target.sha256) {
                throw 'Unsigned signing source bytes differ from the authenticated request.'
            }
            $admittedPe = & $SourceAdmissionOperation $input $target
            if ([string]$admittedPe -cne [string]$target.peContentSha256) {
                throw 'Unsigned signing source PE admission is inconsistent.'
            }
        }

        $transactionLeaf = 'txn-' + [Guid]::NewGuid().ToString('N')
        $transactionPath = Join-Path `
            ([string]$policy.roots.transactionRoot) $transactionLeaf
        [void][IO.Directory]::CreateDirectory($transactionPath)
        $transactionPath = Assert-WindowsPilotDirectChildPath `
            -Path $transactionPath -Root ([string]$policy.roots.transactionRoot) `
            -Label 'Generated signing transaction'
        [void](Assert-WindowsPilotOrdinaryRoot `
            -Path $transactionPath -Label 'Generated signing transaction')
        $signedRoot = Join-Path $transactionPath 'signed'
        [void][IO.Directory]::CreateDirectory($signedRoot)
        [void](Assert-WindowsPilotOrdinaryRoot `
            -Path $signedRoot -Label 'Signing transaction signed root')

        for ($index = 0; $index -lt $Targets.Count; $index++) {
            $source = $sourceInputs[$index]
            $destination = Join-Path $signedRoot ([string]$Targets[$index].fileName)
            Copy-WindowsPilotLockedInput `
                -Source $source -DestinationPath $destination
            $copy = ProductionReleaseState\Open-ProductionReleaseInput `
                -Path $destination -Label 'Unsigned transaction copy' `
                -MaximumBytes $script:MaximumTargetBytes
            try {
                if ($copy.Sha256 -cne $source.Sha256 -or
                    $copy.SizeBytes -ne $source.SizeBytes -or
                    ($copy.VolumeSerialNumber -eq $source.VolumeSerialNumber -and
                        $copy.FileIndex -eq $source.FileIndex)) {
                    throw 'Signing transaction copy is not an independent byte-identical file.'
                }
            }
            finally {
                $copy.Stream.Dispose()
            }
        }

        $signToolExecutions = [Collections.Generic.List[object]]::new()
        for ($index = 0; $index -lt $Targets.Count; $index++) {
            $destination = Join-Path $signedRoot ([string]$Targets[$index].fileName)
            $signToolExecutions.Add((& $SignOperation $policy $destination))
            [void](ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
                -Descriptor $sourceInputs[$index] `
                -Label "Unsigned signing source $($Targets[$index].role)")
        }

        $evidence = [Collections.Generic.List[object]]::new()
        for ($index = 0; $index -lt $Targets.Count; $index++) {
            $target = $Targets[$index]
            $destination = Join-Path $signedRoot ([string]$target.fileName)
            $itemEvidence = & $EvidenceOperation $policy $destination $target
            if ([string]$itemEvidence.SignedFileSha256 -ceq [string]$target.sha256 -or
                [string]$itemEvidence.PeContentSha256 -cne
                    [string]$target.peContentSha256 -or
                [int64]$itemEvidence.SizeBytes -le [int64]$target.sizeBytes -or
                [string]$itemEvidence.SignerCertificateSha256 -cne
                    [string]$policy.authenticode.certificateSha256 -or
                [int]$itemEvidence.PrimarySignerCount -ne 1 -or
                [string]$itemEvidence.TimestampProtocol -cne 'RFC3161' -or
                [bool]$itemEvidence.LegacyCounterSignaturePresent) {
                throw 'Signed output does not preserve PE content or exact Authenticode/RFC3161 policy.'
            }
            [void](Assert-WindowsPilotBoundTsaTrustEvidence `
                -Policy $policy -AuthenticodeEvidence $itemEvidence)
            $evidence.Add($itemEvidence)
            [void](ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
                -Descriptor $sourceInputs[$index] `
                -Label "Unsigned signing source $($target.role)")
        }

        $response = & $ResponseBuilder ([object[]]$evidence.ToArray()) $transactionPath
        if ($null -eq $response) {
            throw 'Signing response builder did not return a response.'
        }
        [byte[]]$responseBytes =
            ProductionReleaseState\ConvertTo-ProductionJsonBytes -Value $response
        $responsePath = Join-Path $transactionPath $ResponseFileName
        Write-WindowsPilotNewFileBytes -Path $responsePath -Bytes $responseBytes
        $responseInput = ProductionReleaseState\Open-ProductionReleaseInput `
            -Path $responsePath -Label 'Generated signing response' `
            -MaximumBytes $script:MaximumPolicyBytes
        try {
            [byte[]]$heldResponseBytes =
                ProductionReleaseState\Read-ProductionReleaseInputBytes `
                    -Descriptor $responseInput -Label 'Generated signing response'
            $responseInput | Add-Member `
                -NotePropertyName Bytes -NotePropertyValue $heldResponseBytes
            $responseInput | Add-Member `
                -NotePropertyName Value -NotePropertyValue $response
            $validation = & $ResponseValidator $responseInput ([object[]]$evidence.ToArray())
            if ($validation -ne $true) {
                throw 'Signing response validator did not return exact acceptance.'
            }
            [void](ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
                -Descriptor $responseInput -Label 'Generated signing response')
        }
        finally {
            $responseInput.Stream.Dispose()
        }
        [void](Assert-WindowsPilotTransactionInventory `
            -TransactionPath $transactionPath `
            -ExpectedFileNames @($Targets | ForEach-Object { [string]$_.fileName }) `
            -ResponseFileName $ResponseFileName)
        foreach ($source in $sourceInputs) {
            [void](ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
                -Descriptor $source -Label 'Unsigned signing source before commit')
        }
        [void](ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
            -Descriptor $PolicyInput -Label 'Windows Pilot signing execution policy')

        $directoryLease = ProductionReleaseState\Open-ProductionReleaseDirectoryMoveLease `
            -Path $transactionPath -Label 'Complete signing transaction'
        $committedPath = ProductionReleaseState\Move-ProductionReleaseDirectoryLease `
            -Descriptor $directoryLease -DestinationPath $finalPath `
            -Label 'Complete signing transaction'
        $committed = $true
        return [pscustomobject][ordered]@{
            status = 'COMMITTED'
            outputPath = $committedPath
            responsePath = Join-Path $committedPath $ResponseFileName
            responseSha256 = Get-WindowsPilotSha256Bytes -Bytes $responseBytes
            signedFileCount = $Targets.Count
            signToolExecutions = [object[]]$signToolExecutions.ToArray()
            tsaTrustEvidence = [object[]]@($evidence | ForEach-Object {
                    $_.TsaTrustEvidence
                })
        }
    }
    finally {
        if ($null -ne $directoryLease) { $directoryLease.Handle.Dispose() }
        foreach ($source in $sourceInputs) { $source.Stream.Dispose() }
        if ($certificateAdmission -is [IDisposable]) {
            $certificateAdmission.Dispose()
        }
        if (-not $committed -and $null -ne $transactionPath) {
            Remove-WindowsPilotFailedTransaction `
                -TransactionPath $transactionPath `
                -TransactionRoot ([string]$policy.roots.transactionRoot)
        }
    }
}

function Invoke-WindowsPilotSigningTransaction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$PolicyInput,
        [Parameter(Mandatory = $true)][object[]]$Targets,
        [Parameter(Mandatory = $true)][string]$FinalOutputPath,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.json$')]
        [string]$ResponseFileName,
        [Parameter(Mandatory = $true)][scriptblock]$ResponseBuilder,
        [Parameter(Mandatory = $true)][scriptblock]$ResponseValidator,
        [ValidateSet('PERSONAL_PILOT_SIGNING', 'ENTERPRISE_PILOT_SIGNING')]
        [string]$ExpectedExecutionAdmission = 'PERSONAL_PILOT_SIGNING',
        [ValidateSet('PersonalTwoDevice', 'EnterpriseTwoDevice')]
        [string]$ExpectedProfile = 'PersonalTwoDevice'
    )
    return Invoke-WindowsPilotSigningTransactionCore `
        -PolicyInput $PolicyInput `
        -Targets $Targets `
        -FinalOutputPath $FinalOutputPath `
        -ResponseFileName $ResponseFileName `
        -ResponseBuilder $ResponseBuilder `
        -ResponseValidator $ResponseValidator `
        -ExpectedExecutionAdmission $ExpectedExecutionAdmission `
        -ExpectedProfile $ExpectedProfile `
        -CertificateAdmissionOperation {
            param($policy)
            return Assert-WindowsPilotSigningCertificate -Policy $policy
        } `
        -SourceAdmissionOperation {
            param($descriptor, $target)
            return Assert-WindowsPilotUnsignedSource `
                -Descriptor $descriptor -Target $target
        } `
        -SignOperation {
            param($policy, $targetPath)
            return Invoke-WindowsPilotPinnedSignTool `
                -Policy $policy -TargetPath $targetPath
        } `
        -EvidenceOperation {
            param($policy, $targetPath, $target)
            $evidence = InstallerSigningContracts\Get-ExactPeAuthenticodeEvidence `
                -Path $targetPath `
                -ExpectedSignerCertificateSha256 `
                    ([string]$policy.authenticode.certificateSha256) `
                -ExpectedPeContentSha256 ([string]$target.peContentSha256)
            $tsaTrust = Assert-WindowsPilotTsaTrustEvidence `
                -Policy $policy -TargetPath $targetPath `
                -AuthenticodeEvidence $evidence
            $evidence | Add-Member `
                -NotePropertyName TsaTrustEvidence `
                -NotePropertyValue $tsaTrust
            return $evidence
        }
}

Export-ModuleMember -Function @(
    'Assert-WindowsPilotPolicyLane',
    'ConvertTo-WindowsPilotBase64Url',
    'ConvertTo-WindowsPilotLowSP256Signature',
    'Invoke-WindowsPilotPinnedSignTool',
    'Invoke-WindowsPilotSigningTransaction',
    'New-WindowsPilotEs256ResponseSignature',
    'New-WindowsPilotSignToolStartInfo',
    'Read-WindowsPilotSigningPolicy'
)
