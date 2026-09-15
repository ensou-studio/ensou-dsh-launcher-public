#requires -Version 7.2

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:Utf8Strict = [Text.UTF8Encoding]::new($false, $true)

Microsoft.PowerShell.Core\Import-Module `
    (Join-Path $PSScriptRoot 'InstallerSigningContracts.psm1') -Force -ErrorAction Stop
Microsoft.PowerShell.Core\Import-Module `
    (Join-Path $PSScriptRoot 'ProductionBoundedProcess.psm1') -Force -ErrorAction Stop
Microsoft.PowerShell.Core\Import-Module `
    (Join-Path $PSScriptRoot 'ProductionReleaseState.psm1') -Force -ErrorAction Stop

function Get-EnterpriseInstallerProductionPayloadFileByRole {
    param(
        [Parameter(Mandatory = $true)][object[]]$Files,
        [Parameter(Mandatory = $true)][string]$Role
    )

    $matches = @($Files | Where-Object { [string]$_.role -ceq $Role })
    if ($matches.Count -ne 1) {
        throw "Enterprise Installer payload must contain exactly one '$Role' role."
    }
    return $matches[0]
}

function Get-EnterpriseInstallerProductionPayloadSelfCheckResultSha256 {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][psobject]$SelfCheck)

    $identity = [ordered]@{
        schemaVersion = 1
        verificationType =
            'ensou-dsh-launcher-installer-production-payload-self-check'
        command = [string]$SelfCheck.command
        status = [string]$SelfCheck.status
        exitCode = [int]$SelfCheck.exitCode
        inspectedInstallerSha256 = [string]$SelfCheck.inspectedInstallerSha256
        candidateSetSha256 = [string]$SelfCheck.candidateSetSha256
        payloadSetSha256 = [string]$SelfCheck.payloadSetSha256
        r3SignedClientSetSha256 = [string]$SelfCheck.r3SignedClientSetSha256
        releaseManifestTrustSha256 = [string]$SelfCheck.releaseManifestTrustSha256
        releaseManifestTrustProbeSetSha256 =
            [string]$SelfCheck.releaseManifestTrustProbeSetSha256
        completedAtUtc = [string]$SelfCheck.completedAtUtc
    }
    return ProductionReleaseState\Get-ProductionSha256Bytes `
        -Bytes (ProductionReleaseState\ConvertTo-ProductionJsonBytes -Value $identity)
}

function Invoke-EnterpriseInstallerProductionPayloadSelfCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$InstallerInput,
        [Parameter(Mandatory = $true)][psobject]$Request,
        [Parameter(Mandatory = $true)][psobject]$InstallManifest,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9a-f]{64}$')]
        [string]$ExpectedSignerCertificateSha256,
        [Parameter(Mandatory = $true)]
        [ValidateRange(100, 300000)]
        [int]$TimeoutMilliseconds,
        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 16777216)]
        [int]$MaximumOutputBytes
    )

    $authenticodeEvidenceOperation = {
        param($descriptor, [string]$signerSha256, [string]$peContentSha256)
        return InstallerSigningContracts\Get-ExactPeAuthenticodeEvidence `
            -Path ([string]$descriptor.Path) `
            -ExpectedSignerCertificateSha256 $signerSha256 `
            -ExpectedPeContentSha256 $peContentSha256
    }
    $processCaptureOperation = {
        param($startInfo, [int]$timeout, [int]$maximumOutput)
        return ProductionBoundedProcess\Invoke-ProductionBoundedProcessCapture `
            -StartInfo $startInfo `
            -TimeoutMilliseconds $timeout `
            -MaximumOutputBytes $maximumOutput
    }
    return Invoke-EnterpriseInstallerProductionPayloadSelfCheckCore `
        -InstallerInput $InstallerInput `
        -Request $Request `
        -InstallManifest $InstallManifest `
        -ExpectedSignerCertificateSha256 $ExpectedSignerCertificateSha256 `
        -TimeoutMilliseconds $TimeoutMilliseconds `
        -MaximumOutputBytes $MaximumOutputBytes `
        -AuthenticodeEvidenceOperation $authenticodeEvidenceOperation `
        -ProcessCaptureOperation $processCaptureOperation
}

function Invoke-EnterpriseInstallerProductionPayloadSelfCheckCore {
    param(
        [Parameter(Mandatory = $true)]$InstallerInput,
        [Parameter(Mandatory = $true)][psobject]$Request,
        [Parameter(Mandatory = $true)][psobject]$InstallManifest,
        [Parameter(Mandatory = $true)][string]$ExpectedSignerCertificateSha256,
        [Parameter(Mandatory = $true)][int]$TimeoutMilliseconds,
        [Parameter(Mandatory = $true)][int]$MaximumOutputBytes,
        [Parameter(Mandatory = $true)][scriptblock]$AuthenticodeEvidenceOperation,
        [Parameter(Mandatory = $true)][scriptblock]$ProcessCaptureOperation
    )

    $unsignedInstaller = $Request.unsignedInstaller
    if ([string]$Request.edition -cne 'Enterprise' -or
        [string]$Request.channel -cne 'stable' -or
        [string]$InstallerInput.FileName -cne
            'Ensou.Dsh.Enterprise.Installer.exe' -or
        [string]$unsignedInstaller.fileName -cne
            'Ensou.Dsh.Enterprise.Installer.exe' -or
        [string]$InstallerInput.Sha256 -ceq [string]$unsignedInstaller.sha256 -or
        [int64]$InstallerInput.SizeBytes -le [int64]$unsignedInstaller.sizeBytes) {
        throw 'Signed Enterprise Installer does not match the exact request identity.'
    }

    [void](ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
        -Descriptor $InstallerInput `
        -Label 'Signed Enterprise Installer before Authenticode admission')
    $authenticode = & $AuthenticodeEvidenceOperation `
        $InstallerInput `
        $ExpectedSignerCertificateSha256 `
        ([string]$unsignedInstaller.peContentSha256)
    [void](ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
        -Descriptor $InstallerInput `
        -Label 'Signed Enterprise Installer after Authenticode admission')
    if ([string]$authenticode.FileName -cne [string]$InstallerInput.FileName -or
        [int64]$authenticode.SizeBytes -ne [int64]$InstallerInput.SizeBytes -or
        [string]$authenticode.SignedFileSha256 -cne [string]$InstallerInput.Sha256 -or
        [string]$authenticode.PeContentSha256 -cne
            [string]$unsignedInstaller.peContentSha256 -or
        [string]$authenticode.AuthenticodeStatus -cne 'Valid' -or
        [string]$authenticode.TimestampProtocol -cne 'RFC3161' -or
        [int]$authenticode.PrimarySignerCount -ne 1 -or
        [bool]$authenticode.LegacyCounterSignaturePresent) {
        throw 'Signed Enterprise Installer failed exact Authenticode and request PE identity admission.'
    }

    $manifestPayload = Get-EnterpriseInstallerProductionPayloadFileByRole `
        -Files @($Request.installerPayload.files) -Role 'install-manifest'
    $launcherPayload = Get-EnterpriseInstallerProductionPayloadFileByRole `
        -Files @($Request.installerPayload.files) -Role 'launcher'
    $runtimePayload = Get-EnterpriseInstallerProductionPayloadFileByRole `
        -Files @($Request.installerPayload.files) -Role 'runtime'
    $bootstrapperPayload = Get-EnterpriseInstallerProductionPayloadFileByRole `
        -Files @($Request.installerPayload.files) -Role 'bootstrapper'
    $arguments = @(
        '--production-payload-self-check',
        [string]$InstallManifest.launcherReleaseId,
        [string]$InstallManifest.runtimeReleaseId,
        [string]$manifestPayload.sha256,
        [string][int64]$manifestPayload.sizeBytes,
        [string]$launcherPayload.sha256,
        [string][int64]$launcherPayload.sizeBytes,
        [string]$runtimePayload.sha256,
        [string][int64]$runtimePayload.sizeBytes,
        [string]$bootstrapperPayload.sha256,
        [string][int64]$bootstrapperPayload.sizeBytes)
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = [string]$InstallerInput.Path
    $start.WorkingDirectory =
        [IO.Path]::GetDirectoryName([string]$InstallerInput.Path)
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.WindowStyle = [Diagnostics.ProcessWindowStyle]::Hidden
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in $arguments) { [void]$start.ArgumentList.Add($argument) }
    $start.Environment.Clear()
    $systemRoot = [Environment]::GetEnvironmentVariable('SystemRoot')
    if ([string]::IsNullOrWhiteSpace($systemRoot)) {
        throw 'Enterprise Installer payload self-check requires SystemRoot.'
    }
    $temporaryRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    $start.Environment['SystemRoot'] = $systemRoot
    $start.Environment['WINDIR'] = $systemRoot
    $start.Environment['PATH'] = Join-Path $systemRoot 'System32'
    $start.Environment['TEMP'] = $temporaryRoot
    $start.Environment['TMP'] = $temporaryRoot
    [void](ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
        -Descriptor $InstallerInput `
        -Label 'Signed Enterprise Installer before payload self-check')
    $capture = & $ProcessCaptureOperation `
        $start $TimeoutMilliseconds $MaximumOutputBytes
    [void](ProductionReleaseState\Assert-ProductionReleaseInputStillLocked `
        -Descriptor $InstallerInput `
        -Label 'Signed Enterprise Installer after payload self-check')
    if ([bool]$capture.TimedOut -or
        [bool]$capture.StandardOutput.Overflowed -or
        [bool]$capture.StandardError.Overflowed -or
        [int]$capture.ExitCode -ne 0 -or
        $capture.StandardError.Bytes.Length -ne 0) {
        throw 'Signed Enterprise Installer payload self-check failed, timed out, or emitted diagnostics.'
    }
    $text = $script:Utf8Strict.GetString($capture.StandardOutput.Bytes)
    if ($text.EndsWith("`r`n", [StringComparison]::Ordinal)) {
        $text = $text.Substring(0, $text.Length - 2)
    }
    elseif ($text.EndsWith("`n", [StringComparison]::Ordinal)) {
        $text = $text.Substring(0, $text.Length - 1)
    }
    if ([string]::IsNullOrEmpty($text) -or $text.Contains("`r") -or
        $text.Contains("`n")) {
        throw 'Signed Enterprise Installer payload self-check did not emit one JSON line.'
    }
    [byte[]]$resultBytes = $script:Utf8Strict.GetBytes($text)
    $result = ProductionReleaseState\ConvertFrom-StrictProductionJsonBytes `
        -Bytes $resultBytes `
        -Label 'Signed Enterprise Installer payload self-check result'
    ProductionReleaseState\Assert-ExactProductionJsonMembers `
        -Value $result `
        -Expected @(
            'schemaVersion', 'resultType', 'command', 'status',
            'installerSha256', 'launcherReleaseId', 'runtimeReleaseId',
            'manifestSha256', 'manifestSizeBytes',
            'launcherArchiveSha256', 'launcherArchiveSizeBytes',
            'runtimeArchiveSha256', 'runtimeArchiveSizeBytes',
            'bootstrapperSha256', 'bootstrapperSizeBytes') `
        -Label 'Signed Enterprise Installer payload self-check result'
    [byte[]]$canonicalBytes =
        ProductionReleaseState\ConvertTo-ProductionJsonBytes -Value $result
    if ((ProductionReleaseState\Get-ProductionSha256Bytes -Bytes $canonicalBytes) -cne
            (ProductionReleaseState\Get-ProductionSha256Bytes -Bytes $resultBytes) -or
        [int]$result.schemaVersion -ne 1 -or
        [string]$result.resultType -cne
            'ensou-dsh-enterprise-installer-production-payload-self-check' -or
        [string]$result.command -cne '--production-payload-self-check' -or
        [string]$result.status -cne 'VERIFIED' -or
        [string]$result.installerSha256 -cne [string]$InstallerInput.Sha256 -or
        [string]$result.launcherReleaseId -cne
            [string]$InstallManifest.launcherReleaseId -or
        [string]$result.runtimeReleaseId -cne
            [string]$InstallManifest.runtimeReleaseId -or
        [string]$result.manifestSha256 -cne [string]$manifestPayload.sha256 -or
        [int64]$result.manifestSizeBytes -ne [int64]$manifestPayload.sizeBytes -or
        [string]$result.launcherArchiveSha256 -cne [string]$launcherPayload.sha256 -or
        [int64]$result.launcherArchiveSizeBytes -ne [int64]$launcherPayload.sizeBytes -or
        [string]$result.runtimeArchiveSha256 -cne [string]$runtimePayload.sha256 -or
        [int64]$result.runtimeArchiveSizeBytes -ne [int64]$runtimePayload.sizeBytes -or
        [string]$result.bootstrapperSha256 -cne [string]$bootstrapperPayload.sha256 -or
        [int64]$result.bootstrapperSizeBytes -ne [int64]$bootstrapperPayload.sizeBytes) {
        throw 'Signed Enterprise Installer payload self-check result differs from its exact signed bytes and embedded payload request.'
    }
    $completed = [DateTimeOffset]::UtcNow
    $selfCheck = [ordered]@{
        command = '--production-payload-self-check'
        status = 'VERIFIED'
        exitCode = 0
        inspectedInstallerSha256 = [string]$InstallerInput.Sha256
        resultSha256 = ''
        candidateSetSha256 = [string]$Request.candidate.inventorySha256
        payloadSetSha256 = [string]$Request.installerPayload.inventorySha256
        r3SignedClientSetSha256 = [string]$Request.r3Evidence.signedClientSetSha256
        releaseManifestTrustSha256 =
            [string]$Request.r3Evidence.releaseManifestTrustSha256
        releaseManifestTrustProbeSetSha256 =
            [string]$Request.r3Evidence.releaseManifestTrustProbeSetSha256
        completedAtUtc = ProductionReleaseState\ConvertTo-ProductionUtc -Value $completed
    }
    $selfCheck.resultSha256 =
        Get-EnterpriseInstallerProductionPayloadSelfCheckResultSha256 `
            -SelfCheck ([pscustomobject]$selfCheck)
    return [pscustomobject]$selfCheck
}

Export-ModuleMember -Function @(
    'Get-EnterpriseInstallerProductionPayloadSelfCheckResultSha256',
    'Invoke-EnterpriseInstallerProductionPayloadSelfCheck'
)
