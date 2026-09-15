#requires -Version 7.2

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = Join-Path $PSScriptRoot 'EnterpriseInstallerProductionPayloadSelfCheck.psm1'
$pilotAdapterPath = Join-Path `
    $PSScriptRoot '..\pilot-signing\Invoke-EnterprisePilotInstallerSigning.ps1'

function Assert-True {
    param([Parameter(Mandatory = $true)][bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

$tokens = $null
$errors = $null
[void][Management.Automation.Language.Parser]::ParseFile(
    $modulePath, [ref]$tokens, [ref]$errors)
Assert-True ($errors.Count -eq 0) `
    'Enterprise Installer production payload self-check module must parse.'

Microsoft.PowerShell.Core\Import-Module $modulePath -Force -ErrorAction Stop
Microsoft.PowerShell.Core\Import-Module `
    (Join-Path $PSScriptRoot 'ProductionReleaseState.psm1') -Force -ErrorAction Stop
$module = Get-Module EnterpriseInstallerProductionPayloadSelfCheck
$exports = @($module.ExportedFunctions.Keys | Sort-Object)
$expectedExports = @(
    'Get-EnterpriseInstallerProductionPayloadSelfCheckResultSha256',
    'Invoke-EnterpriseInstallerProductionPayloadSelfCheck'
) | Sort-Object
Assert-True `
    (($exports -join ',') -ceq ($expectedExports -join ',')) `
    'Shared module must export only the production self-check hash and runner.'

$selfCheck = [pscustomobject][ordered]@{
    command = '--production-payload-self-check'
    status = 'VERIFIED'
    exitCode = 0
    inspectedInstallerSha256 = '11' * 32
    resultSha256 = ''
    candidateSetSha256 = '22' * 32
    payloadSetSha256 = '33' * 32
    r3SignedClientSetSha256 = '44' * 32
    releaseManifestTrustSha256 = '55' * 32
    releaseManifestTrustProbeSetSha256 = '66' * 32
    completedAtUtc = '2026-09-10T04:00:00Z'
}
$first =
    Get-EnterpriseInstallerProductionPayloadSelfCheckResultSha256 `
        -SelfCheck $selfCheck
$selfCheck.resultSha256 = 'ff' * 32
$second =
    Get-EnterpriseInstallerProductionPayloadSelfCheckResultSha256 `
        -SelfCheck $selfCheck
Assert-True ($first -cmatch '^[0-9a-f]{64}$' -and $first -ceq $second) `
    'Self-check identity hash must be canonical and exclude its resultSha256 field.'

$moduleText = [IO.File]::ReadAllText($modulePath)
foreach ($required in @(
        'ExpectedSignerCertificateSha256',
        'InstallerSigningContracts\Get-ExactPeAuthenticodeEvidence',
        'ExpectedPeContentSha256',
        'ProductionBoundedProcess\Invoke-ProductionBoundedProcessCapture',
        "'--production-payload-self-check'",
        '$start.UseShellExecute = $false',
        '$start.CreateNoWindow = $true',
        '$start.Environment.Clear()',
        'Assert-ProductionReleaseInputStillLocked')) {
    Assert-True ($moduleText.Contains($required)) `
        "Shared production self-check lost required boundary: $required"
}
foreach ($forbidden in @(
        'WindowsPilotSigningExecution',
        'EnsouDshPilotSigning.StrictProcessCapture',
        'Microsoft Software Key Storage Provider',
        'signtool')) {
    Assert-True (-not $moduleText.Contains($forbidden)) `
        "Shared production self-check must not depend on Pilot signing: $forbidden"
}
$authenticodeIndex = $moduleText.IndexOf(
    'InstallerSigningContracts\Get-ExactPeAuthenticodeEvidence',
    [StringComparison]::Ordinal)
$processIndex = $moduleText.IndexOf(
    'ProductionBoundedProcess\Invoke-ProductionBoundedProcessCapture',
    [StringComparison]::Ordinal)
Assert-True ($authenticodeIndex -ge 0 -and $processIndex -gt $authenticodeIndex) `
    'Pinned Authenticode and request PE admission must precede process execution.'

# Exercise the real Authenticode gate against a held PE with a deliberately
# impossible signer pin. The capture sentinel proves rejection occurs before
# any child process can start; this test never executes the copied image.
$testRoot = Join-Path ([IO.Path]::GetTempPath()) (
    'ensou-enterprise-installer-self-check-' + [Guid]::NewGuid().ToString('N'))
$installerInput = $null
$boundedModule = $null
$originalBoundedCapture = $null
try {
    [IO.Directory]::CreateDirectory($testRoot) | Out-Null
    $candidatePath = Join-Path $testRoot 'Ensou.Dsh.Enterprise.Installer.exe'
    [IO.File]::Copy((Join-Path $PSHOME 'pwsh.exe'), $candidatePath, $false)
    $installerInput = ProductionReleaseState\Open-ProductionReleaseInput `
        -Path $candidatePath -Label 'Self-check Authenticode rejection fixture' `
        -MaximumBytes 1GB
    $candidateBytes = ProductionReleaseState\Read-ProductionReleaseInputBytes `
        -Descriptor $installerInput `
        -Label 'Self-check Authenticode rejection fixture'
    $request = [pscustomobject][ordered]@{
        edition = 'Enterprise'
        channel = 'stable'
        unsignedInstaller = [pscustomobject][ordered]@{
            fileName = 'Ensou.Dsh.Enterprise.Installer.exe'
            sizeBytes = [int64]$installerInput.SizeBytes - 1
            sha256 = 'aa' * 32
            peContentSha256 =
                ProductionReleaseState\Get-PeContentSha256 -Bytes $candidateBytes
        }
        candidate = [pscustomobject]@{ inventorySha256 = 'bb' * 32 }
        installerPayload = [pscustomobject][ordered]@{
            inventorySha256 = 'cc' * 32
            files = @(
                [pscustomobject]@{
                    role = 'install-manifest'; sha256 = '01' * 32; sizeBytes = 101
                },
                [pscustomobject]@{
                    role = 'launcher'; sha256 = '02' * 32; sizeBytes = 102
                },
                [pscustomobject]@{
                    role = 'runtime'; sha256 = '03' * 32; sizeBytes = 103
                },
                [pscustomobject]@{
                    role = 'bootstrapper'; sha256 = '04' * 32; sizeBytes = 104
                }
            )
        }
        r3Evidence = [pscustomobject][ordered]@{
            signedClientSetSha256 = 'dd' * 32
            releaseManifestTrustSha256 = 'ee' * 32
            releaseManifestTrustProbeSetSha256 = 'ff' * 32
        }
    }
    $installManifest = [pscustomobject][ordered]@{
        launcherReleaseId = 'launcher-release-test'
        runtimeReleaseId = 'runtime-release-test'
    }
    $boundedModule = @($module.NestedModules | Where-Object {
            $_.Name -ceq 'ProductionBoundedProcess'
        }) | Select-Object -First 1
    if ($null -eq $boundedModule) {
        throw 'ProductionBoundedProcess was not loaded by the shared module.'
    }
    $originalBoundedCapture = & $boundedModule {
        (Get-Item Function:Invoke-ProductionBoundedProcessCapture).ScriptBlock
    }
    & $boundedModule {
        function Invoke-ProductionBoundedProcessCapture {
            throw 'PROCESS-CAPTURE-SENTINEL'
        }
        Export-ModuleMember -Function Invoke-ProductionBoundedProcessCapture
    }
    $failure = $null
    try {
        Invoke-EnterpriseInstallerProductionPayloadSelfCheck `
            -InstallerInput $installerInput `
            -Request $request `
            -InstallManifest ([pscustomobject]@{}) `
            -ExpectedSignerCertificateSha256 ('00' * 32) `
            -TimeoutMilliseconds 100 `
            -MaximumOutputBytes 1 | Out-Null
    }
    catch {
        $failure = $_.Exception.Message
    }
    Assert-True (-not [string]::IsNullOrWhiteSpace($failure)) `
        'Wrong-pinned PE must fail real Authenticode admission.'
    Assert-True ($failure -cnotmatch 'PROCESS-CAPTURE-SENTINEL') `
        'Authenticode rejection must occur before bounded process capture.'
    Assert-True ($failure -cmatch '^Signed PE (Authenticode signer differs from the pinned certificate|does not have Windows Authenticode Status=Valid)') `
        'The real Windows Authenticode gate, not an unrelated fixture error, must reject the PE.'

    # The private core accepts explicit operations solely so this test can prove
    # the complete positive parsing/bounds path without executing an image or
    # weakening the public runner's mandatory real Authenticode operation.
    $seam = [pscustomobject]@{ AuthenticodeCalled = $false; CaptureCalled = $false }
    $authenticodeOperation = {
        param($descriptor, $signerSha256, $peContentSha256)
        $seam.AuthenticodeCalled = $true
        if ($signerSha256 -cne ('00' * 32) -or
            $peContentSha256 -cne [string]$request.unsignedInstaller.peContentSha256) {
            throw 'Positive Authenticode seam received unexpected identity.'
        }
        return [pscustomobject][ordered]@{
            FileName = [string]$descriptor.FileName
            SizeBytes = [int64]$descriptor.SizeBytes
            SignedFileSha256 = [string]$descriptor.Sha256
            PeContentSha256 = [string]$peContentSha256
            AuthenticodeStatus = 'Valid'
            TimestampProtocol = 'RFC3161'
            PrimarySignerCount = 1
            LegacyCounterSignaturePresent = $false
        }
    }.GetNewClosure()
    $resultValue = [ordered]@{
        schemaVersion = 1
        resultType = 'ensou-dsh-enterprise-installer-production-payload-self-check'
        command = '--production-payload-self-check'
        status = 'VERIFIED'
        installerSha256 = [string]$installerInput.Sha256
        launcherReleaseId = [string]$installManifest.launcherReleaseId
        runtimeReleaseId = [string]$installManifest.runtimeReleaseId
        manifestSha256 = '01' * 32
        manifestSizeBytes = 101
        launcherArchiveSha256 = '02' * 32
        launcherArchiveSizeBytes = 102
        runtimeArchiveSha256 = '03' * 32
        runtimeArchiveSizeBytes = 103
        bootstrapperSha256 = '04' * 32
        bootstrapperSizeBytes = 104
    }
    $resultBytes = ProductionReleaseState\ConvertTo-ProductionJsonBytes `
        -Value $resultValue
    $captureOperation = {
        param($startInfo, $timeout, $maximumOutput)
        $seam.CaptureCalled = $true
        if ($startInfo.ArgumentList.Count -ne 11 -or
            [string]$startInfo.ArgumentList[0] -cne
                '--production-payload-self-check' -or
            $startInfo.UseShellExecute -or
            -not $startInfo.CreateNoWindow -or
            -not $startInfo.RedirectStandardOutput -or
            -not $startInfo.RedirectStandardError -or
            $timeout -ne 100 -or $maximumOutput -ne 4096) {
            throw 'Positive capture seam received an unsafe process contract.'
        }
        return [pscustomobject][ordered]@{
            TimedOut = $false
            ExitCode = 0
            StandardOutput = [pscustomobject]@{
                Overflowed = $false
                Bytes = $resultBytes
            }
            StandardError = [pscustomobject]@{
                Overflowed = $false
                Bytes = [byte[]]::new(0)
            }
        }
    }.GetNewClosure()
    $authenticodeProbe = & $authenticodeOperation `
        $installerInput ('00' * 32) ([string]$request.unsignedInstaller.peContentSha256)
    Assert-True (
        [string]$authenticodeProbe.FileName -ceq [string]$installerInput.FileName -and
        [int64]$authenticodeProbe.SizeBytes -eq [int64]$installerInput.SizeBytes -and
        [string]$authenticodeProbe.SignedFileSha256 -ceq [string]$installerInput.Sha256 -and
        [string]$authenticodeProbe.PeContentSha256 -ceq
            [string]$request.unsignedInstaller.peContentSha256) `
        ("Positive Authenticode seam must return the held Installer identity: " +
            "file=$($authenticodeProbe.FileName)/$($installerInput.FileName); " +
            "size=$($authenticodeProbe.SizeBytes)/$($installerInput.SizeBytes); " +
            "sha=$($authenticodeProbe.SignedFileSha256)/$($installerInput.Sha256); " +
            "pe=$($authenticodeProbe.PeContentSha256)/$($request.unsignedInstaller.peContentSha256)")
    $coreParameters = @{
        InstallerInput = $installerInput
        Request = $request
        InstallManifest = $installManifest
        ExpectedSignerCertificateSha256 = '00' * 32
        TimeoutMilliseconds = 100
        MaximumOutputBytes = 4096
        AuthenticodeEvidenceOperation = $authenticodeOperation
        ProcessCaptureOperation = $captureOperation
    }
    $positive = & $module {
        param($parameters)
        Invoke-EnterpriseInstallerProductionPayloadSelfCheckCore @parameters
    } $coreParameters
    Assert-True ($seam.AuthenticodeCalled -and $seam.CaptureCalled) `
        'Positive seams must traverse Authenticode admission before capture.'
    Assert-True (
        [string]$positive.status -ceq 'VERIFIED' -and
        [string]$positive.command -ceq '--production-payload-self-check' -and
        [string]$positive.inspectedInstallerSha256 -ceq
            [string]$installerInput.Sha256 -and
        [string]$positive.resultSha256 -cmatch '^[0-9a-f]{64}$') `
        'Positive bounded-capture seam must return the unchanged self-check contract.'
}
finally {
    # Restore the existing module in place; removing or force-reimporting it can
    # invalidate ModuleInfo objects held by callers in a shared test process.
    if ($null -ne $boundedModule -and $null -ne $originalBoundedCapture) {
        & $boundedModule {
            param($Original)
            Set-Item Function:script:Invoke-ProductionBoundedProcessCapture $Original
            Export-ModuleMember -Function Invoke-ProductionBoundedProcessCapture
        } $originalBoundedCapture
    }
    if ($null -ne $installerInput) { $installerInput.Stream.Dispose() }
    $fullTestRoot = [IO.Path]::GetFullPath($testRoot)
    $expectedPrefix = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()) +
        'ensou-enterprise-installer-self-check-'
    if ($fullTestRoot.StartsWith(
            $expectedPrefix, [StringComparison]::OrdinalIgnoreCase) -and
        [IO.Directory]::Exists($fullTestRoot)) {
        [IO.Directory]::Delete($fullTestRoot, $true)
    }
}

$pilotText = [IO.File]::ReadAllText($pilotAdapterPath)
Assert-True ($pilotText.Contains(
        'EnterpriseInstallerProductionPayloadSelfCheck\Invoke-EnterpriseInstallerProductionPayloadSelfCheck')) `
    'Enterprise Pilot adapter must delegate to the shared production runner.'
Assert-True ($pilotText.Contains(
        'EnterpriseInstallerProductionPayloadSelfCheck\Get-EnterpriseInstallerProductionPayloadSelfCheckResultSha256')) `
    'Enterprise Pilot adapter must delegate to the shared self-check identity hash.'
Assert-True (-not $pilotText.Contains(
        'function Invoke-EnterprisePilotInstallerPayloadSelfCheck')) `
    'Enterprise Pilot adapter must not retain a private runner fork.'

Write-Output 'ENTERPRISE-INSTALLER-PRODUCTION-PAYLOAD-SELF-CHECK-PASS'
Write-Output 'REAL-SIGNED-INSTALLER-EXECUTION-NOT-PERFORMED'
