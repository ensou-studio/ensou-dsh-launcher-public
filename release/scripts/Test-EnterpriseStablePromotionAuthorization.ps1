#requires -Version 7.2

[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'CertifiedDistributionInput.ps1')

function ConvertTo-Base64Url([byte[]]$Bytes) {
    return [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Assert-Throws {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Action,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $threw = $false
    try {
        & $Action
    }
    catch {
        $threw = $true
    }
    if (-not $threw) {
        throw "$Label did not fail closed."
    }
}

function Write-ReceiptAuthentication {
    param(
        [Parameter(Mandatory = $true)][string]$ReceiptPath,
        [Parameter(Mandatory = $true)][string]$AuthenticationPath,
        [Parameter(Mandatory = $true)][string]$Product,
        [Parameter(Mandatory = $true)][string]$ReleaseSetId,
        [Parameter(Mandatory = $true)][Security.Cryptography.ECDsa]$Signer,
        [Parameter(Mandatory = $true)][string]$KeyId
    )

    $receiptSha256 = (Get-FileHash -Algorithm SHA256 `
        -LiteralPath $ReceiptPath).Hash.ToLowerInvariant()
    $payload = [Text.Encoding]::UTF8.GetBytes((@(
        'ensou-dsh-certified-distribution-receipt-authentication-v1',
        $Product,
        $ReleaseSetId,
        $receiptSha256) -join "`n"))
    $signature = $Signer.SignData(
        $payload,
        [Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)
    $authentication = [ordered]@{
        schemaVersion = 1
        authenticationType = 'ensou-dsh-certified-distribution-receipt-authentication'
        product = $Product
        releaseSetId = $ReleaseSetId
        receiptSha256 = $receiptSha256
        signature = [ordered]@{
            algorithm = 'ES256'
            keyId = $KeyId
            value = ConvertTo-Base64Url $signature
        }
    } | ConvertTo-Json -Depth 6
    [IO.File]::WriteAllText(
        $AuthenticationPath,
        $authentication + "`n",
        [Text.UTF8Encoding]::new($false))
    return $receiptSha256
}

$fixtureRoot = Join-Path `
    ([IO.Path]::GetTempPath()) `
    ('ensou-stable-authorization-contract-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($fixtureRoot) | Out-Null
$protectedSnapshotBase = Join-Path `
    (Join-Path $RepositoryRoot 'out') `
    ('enterprise-stable-contract-snapshots-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($protectedSnapshotBase) | Out-Null
$receiptSigner = [Security.Cryptography.ECDsa]::Create(
    [Security.Cryptography.ECCurve+NamedCurves]::nistP256)
$authorizationSigner = [Security.Cryptography.ECDsa]::Create(
    [Security.Cryptography.ECCurve+NamedCurves]::nistP256)
try {
    $releaseSetId = 'managed-v2026.08.27.1'
    $receiptClock = [DateTimeOffset]::UtcNow
    $installerPath = Join-Path $fixtureRoot 'Ensou.Dsh.Enterprise.Installer.exe'
    Copy-Item -LiteralPath (Join-Path $env:SystemRoot 'System32\cmd.exe') `
        -Destination $installerPath
    $installer = Get-Item -LiteralPath $installerPath -Force
    $installerSha256 = (Get-FileHash -Algorithm SHA256 `
        -LiteralPath $installerPath).Hash.ToLowerInvariant()
    $authenticode = Get-AuthenticodeSignature -LiteralPath $installerPath
    if ($authenticode.Status -ne [Management.Automation.SignatureStatus]::Valid -or
        $null -eq $authenticode.SignerCertificate -or
        $null -eq $authenticode.TimeStamperCertificate) {
        throw 'Stable authorization contract fixture requires the signed Windows cmd.exe.'
    }
    $expectedInstallerSigner = ([Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData(
            $authenticode.SignerCertificate.RawData))).ToLowerInvariant()

    $manifestPath = Join-Path $fixtureRoot 'release-set.v2.json'
    [IO.File]::WriteAllText(
        $manifestPath,
        "{`"fixture`":true}`n",
        [Text.UTF8Encoding]::new($false))
    $manifestSha256 = (Get-FileHash -Algorithm SHA256 `
        -LiteralPath $manifestPath).Hash.ToLowerInvariant()

    $receiptPath = Join-Path $fixtureRoot 'certified-distribution-receipt.json'
    $receipt = [ordered]@{
        schemaVersion = 1
        product = 'ensou-dsh-enterprise'
        channel = 'stable'
        releaseSetId = $releaseSetId
        manifestSha256 = $manifestSha256
        installer = [ordered]@{
            fileName = $installer.Name
            sizeBytes = $installer.Length
            sha256 = $installerSha256
            authenticodeStatus = 'Valid'
            signerSha256Thumbprint = $expectedInstallerSigner
            timestamped = $true
        }
        feed = [ordered]@{
            manifestUri = 'https://updates.example.test/v2/channels/pilot/release-set.v2.json'
            externalManifestSha256 = $manifestSha256
            verifiedArtifactCount = 3
            allArtifactSignaturesValid = $true
            allArtifactHashesValid = $true
            immutablePublication = $true
            atomicChannelHead = $true
            verifiedAtUtc = $receiptClock.AddMinutes(-10).ToString(
                'O',
                [Globalization.CultureInfo]::InvariantCulture)
        }
        certification = [ordered]@{
            cleanInstallPassed = $true
            oldInstallUpgradePassed = $true
            actualRuntimeStarted = $true
            webUiOpened = $true
            enterprisePluginLoaded = $true
            wholeHomeRestorePassed = $true
            interruptionMatrixPassed = $true
            weakNetworkResumePassed = $true
            offlineAndReplayMatrixPassed = $true
            sameBytesAsPilot = $true
            pilotSoakPassed = $true
            cleanDeviceEvidenceSha256 = ('1' * 64)
            upgradeDeviceEvidenceSha256 = ('2' * 64)
            failureMatrixEvidenceSha256 = ('3' * 64)
        }
        approvedAtUtc = $receiptClock.AddMinutes(-5).ToString(
            'O',
            [Globalization.CultureInfo]::InvariantCulture)
        distributionAuthorized = $true
    }
    $receiptJson = $receipt | ConvertTo-Json -Depth 10
    [IO.File]::WriteAllText(
        $receiptPath,
        $receiptJson + "`n",
        [Text.UTF8Encoding]::new($false))
    $receiptPublic = $receiptSigner.ExportParameters($false)
    $receiptKeyId = 'independent-distribution-certification-test'
    $authenticationPath = Join-Path $fixtureRoot `
        'certified-distribution-receipt.authentication.json'
    $receiptSha256 = Write-ReceiptAuthentication `
        -ReceiptPath $receiptPath `
        -AuthenticationPath $authenticationPath `
        -Product 'ensou-dsh-enterprise' `
        -ReleaseSetId $releaseSetId `
        -Signer $receiptSigner `
        -KeyId $receiptKeyId

    $receiptKeyX = ConvertTo-Base64Url $receiptPublic.Q.X
    $receiptKeyY = ConvertTo-Base64Url $receiptPublic.Q.Y
    $admission = @(& (Join-Path $PSScriptRoot `
            'Test-CertifiedDistributionReceipt.ps1') `
        -Product 'ensou-dsh-enterprise' `
        -ReleaseSetId $releaseSetId `
        -ReceiptPath $receiptPath `
        -ReceiptAuthenticationPath $authenticationPath `
        -ReceiptAuthenticationKeyId $receiptKeyId `
        -ReceiptAuthenticationKeyX $receiptKeyX `
        -ReceiptAuthenticationKeyY $receiptKeyY `
        -InstallerPath $installerPath `
        -ExpectedInstallerSignerSha256Thumbprint $expectedInstallerSigner `
        -ManifestPath $manifestPath `
        -ProtectedSnapshotBasePath $protectedSnapshotBase `
        -RepositoryRoot $RepositoryRoot `
        -PassThru)
    if ($admission.Count -ne 1 -or
        $admission[0].ReceiptSha256 -cne $receiptSha256 -or
        $admission[0].InstallerSignerSha256Thumbprint -cne $expectedInstallerSigner) {
        throw 'Stable authorization positive admission snapshot is invalid.'
    }

    $authorizationKeyPath = Join-Path $fixtureRoot 'stable-authorization.pk8'
    [IO.File]::WriteAllBytes(
        $authorizationKeyPath,
        $authorizationSigner.ExportPkcs8PrivateKey())
    $authorizationPath = Join-Path $fixtureRoot 'stable-authorization.json'
    & (Join-Path $PSScriptRoot 'New-EnterpriseStablePromotionAuthorization.ps1') `
        -ReleaseSetId $releaseSetId `
        -ReceiptPath $receiptPath `
        -ReceiptAuthenticationPath $authenticationPath `
        -ReceiptAuthenticationKeyId $receiptKeyId `
        -ReceiptAuthenticationKeyX $receiptKeyX `
        -ReceiptAuthenticationKeyY $receiptKeyY `
        -InstallerPath $installerPath `
        -ExpectedInstallerSignerSha256Thumbprint $expectedInstallerSigner `
        -ManifestPath $manifestPath `
        -ProtectedSnapshotBasePath $protectedSnapshotBase `
        -CertificationPrivateKeyPath $authorizationKeyPath `
        -CertificationKeyId 'stable-authorization-test' `
        -OutputPath $authorizationPath `
        -RepositoryRoot $RepositoryRoot
    $authorizationJson = Get-Content -Raw -LiteralPath $authorizationPath
    $authorizationSchema = Join-Path $RepositoryRoot `
        'release\schemas\enterprise-stable-promotion-authorization-v1.schema.json'
    if (-not (Test-Json `
            -Json $authorizationJson `
            -SchemaFile $authorizationSchema `
            -ErrorAction Stop)) {
        throw 'Stable authorization positive output failed its strict schema.'
    }
    $authorization = $authorizationJson | ConvertFrom-Json -Depth 10
    if ($authorization.certificationReceiptSha256 -cne $receiptSha256 -or
        $authorization.installerSha256 -cne $installerSha256) {
        throw 'Stable authorization positive output lost the admitted exact-byte identity.'
    }

    Assert-Throws -Label 'Independent Installer signer pin regression' -Action {
        & (Join-Path $PSScriptRoot 'Test-CertifiedDistributionReceipt.ps1') `
            -Product 'ensou-dsh-enterprise' `
            -ReleaseSetId $releaseSetId `
            -ReceiptPath $receiptPath `
            -ReceiptAuthenticationPath $authenticationPath `
            -ReceiptAuthenticationKeyId $receiptKeyId `
            -ReceiptAuthenticationKeyX $receiptKeyX `
            -ReceiptAuthenticationKeyY $receiptKeyY `
            -InstallerPath $installerPath `
            -ExpectedInstallerSignerSha256Thumbprint ('0' * 64) `
            -ManifestPath $manifestPath `
            -ProtectedSnapshotBasePath $protectedSnapshotBase `
            -RepositoryRoot $RepositoryRoot
    }

    $tamperedReceiptPath = Join-Path $fixtureRoot 'tampered-receipt.json'
    $tamperedReceipt = $receiptJson | ConvertFrom-Json -Depth 32
    $tamperedReceipt.approvedAtUtc = $receiptClock.AddMinutes(-4).ToString(
        'O',
        [Globalization.CultureInfo]::InvariantCulture)
    $tamperedReceipt | ConvertTo-Json -Depth 10 | Set-Content `
        -LiteralPath $tamperedReceiptPath `
        -Encoding utf8NoBOM
    Assert-Throws -Label 'Unsigned receipt substitution regression' -Action {
        & (Join-Path $PSScriptRoot 'Test-CertifiedDistributionReceipt.ps1') `
            -Product 'ensou-dsh-enterprise' `
            -ReleaseSetId $releaseSetId `
            -ReceiptPath $tamperedReceiptPath `
            -ReceiptAuthenticationPath $authenticationPath `
            -ReceiptAuthenticationKeyId $receiptKeyId `
            -ReceiptAuthenticationKeyX $receiptKeyX `
            -ReceiptAuthenticationKeyY $receiptKeyY `
            -InstallerPath $installerPath `
            -ExpectedInstallerSignerSha256Thumbprint $expectedInstallerSigner `
            -ManifestPath $manifestPath `
            -ProtectedSnapshotBasePath $protectedSnapshotBase `
            -RepositoryRoot $RepositoryRoot
    }

    $futureReceiptPath = Join-Path $fixtureRoot 'future-receipt.json'
    $futureAuthenticationPath = Join-Path $fixtureRoot 'future-receipt.authentication.json'
    $futureReceipt = $receiptJson | ConvertFrom-Json -Depth 32
    $futureReceipt.feed.verifiedAtUtc = $receiptClock.AddMinutes(5).ToString(
        'O',
        [Globalization.CultureInfo]::InvariantCulture)
    $futureReceipt.approvedAtUtc = $receiptClock.AddMinutes(10).ToString(
        'O',
        [Globalization.CultureInfo]::InvariantCulture)
    [IO.File]::WriteAllText(
        $futureReceiptPath,
        ($futureReceipt | ConvertTo-Json -Depth 10) + "`n",
        [Text.UTF8Encoding]::new($false))
    [void](Write-ReceiptAuthentication `
        -ReceiptPath $futureReceiptPath `
        -AuthenticationPath $futureAuthenticationPath `
        -Product 'ensou-dsh-enterprise' `
        -ReleaseSetId $releaseSetId `
        -Signer $receiptSigner `
        -KeyId $receiptKeyId)
    Assert-Throws -Label 'Future independently signed receipt regression' -Action {
        & (Join-Path $PSScriptRoot 'Test-CertifiedDistributionReceipt.ps1') `
            -Product 'ensou-dsh-enterprise' `
            -ReleaseSetId $releaseSetId `
            -ReceiptPath $futureReceiptPath `
            -ReceiptAuthenticationPath $futureAuthenticationPath `
            -ReceiptAuthenticationKeyId $receiptKeyId `
            -ReceiptAuthenticationKeyX $receiptKeyX `
            -ReceiptAuthenticationKeyY $receiptKeyY `
            -InstallerPath $installerPath `
            -ExpectedInstallerSignerSha256Thumbprint $expectedInstallerSigner `
            -ManifestPath $manifestPath `
            -ProtectedSnapshotBasePath $protectedSnapshotBase `
            -RepositoryRoot $RepositoryRoot
    }

    $staleReceiptPath = Join-Path $fixtureRoot 'stale-receipt.json'
    $staleAuthenticationPath = Join-Path $fixtureRoot 'stale-receipt.authentication.json'
    $staleReceipt = $receiptJson | ConvertFrom-Json -Depth 32
    $staleReceipt.feed.verifiedAtUtc = $receiptClock.AddHours(-26.5).ToString(
        'O',
        [Globalization.CultureInfo]::InvariantCulture)
    $staleReceipt.approvedAtUtc = $receiptClock.AddHours(-26).ToString(
        'O',
        [Globalization.CultureInfo]::InvariantCulture)
    [IO.File]::WriteAllText(
        $staleReceiptPath,
        ($staleReceipt | ConvertTo-Json -Depth 10) + "`n",
        [Text.UTF8Encoding]::new($false))
    [void](Write-ReceiptAuthentication `
        -ReceiptPath $staleReceiptPath `
        -AuthenticationPath $staleAuthenticationPath `
        -Product 'ensou-dsh-enterprise' `
        -ReleaseSetId $releaseSetId `
        -Signer $receiptSigner `
        -KeyId $receiptKeyId)
    Assert-Throws -Label 'Stale independently signed receipt regression' -Action {
        & (Join-Path $PSScriptRoot 'Test-CertifiedDistributionReceipt.ps1') `
            -Product 'ensou-dsh-enterprise' `
            -ReleaseSetId $releaseSetId `
            -ReceiptPath $staleReceiptPath `
            -ReceiptAuthenticationPath $staleAuthenticationPath `
            -ReceiptAuthenticationKeyId $receiptKeyId `
            -ReceiptAuthenticationKeyX $receiptKeyX `
            -ReceiptAuthenticationKeyY $receiptKeyY `
            -InstallerPath $installerPath `
            -ExpectedInstallerSignerSha256Thumbprint $expectedInstallerSigner `
            -ManifestPath $manifestPath `
            -ProtectedSnapshotBasePath $protectedSnapshotBase `
            -RepositoryRoot $RepositoryRoot
    }

    $reusedKeyPath = Join-Path $fixtureRoot 'reused-receipt-key.pk8'
    [IO.File]::WriteAllBytes($reusedKeyPath, $receiptSigner.ExportPkcs8PrivateKey())
    Assert-Throws -Label 'Receipt/stable key reuse regression' -Action {
        & (Join-Path $PSScriptRoot 'New-EnterpriseStablePromotionAuthorization.ps1') `
            -ReleaseSetId $releaseSetId `
            -ReceiptPath $receiptPath `
            -ReceiptAuthenticationPath $authenticationPath `
            -ReceiptAuthenticationKeyId $receiptKeyId `
            -ReceiptAuthenticationKeyX $receiptKeyX `
            -ReceiptAuthenticationKeyY $receiptKeyY `
            -InstallerPath $installerPath `
            -ExpectedInstallerSignerSha256Thumbprint $expectedInstallerSigner `
            -ManifestPath $manifestPath `
            -ProtectedSnapshotBasePath $protectedSnapshotBase `
            -CertificationPrivateKeyPath $reusedKeyPath `
            -CertificationKeyId 'different-id-same-key' `
            -OutputPath (Join-Path $fixtureRoot 'reused-key-authorization.json') `
            -RepositoryRoot $RepositoryRoot
    }

    $lockLeases = [Collections.Generic.List[IDisposable]]::new()
    try {
        $lockCases = @(
            [pscustomobject]@{
                Path = $receiptPath
                Label = 'TOCTOU receipt fixture'
                MaximumBytes = 512KB
            },
            [pscustomobject]@{
                Path = $authenticationPath
                Label = 'TOCTOU receipt authentication fixture'
                MaximumBytes = 128KB
            },
            [pscustomobject]@{
                Path = $installerPath
                Label = 'TOCTOU Installer fixture'
                MaximumBytes = 8L * 1024 * 1024 * 1024
            },
            [pscustomobject]@{
                Path = $manifestPath
                Label = 'TOCTOU manifest fixture'
                MaximumBytes = 4MB
            })
        foreach ($lockCase in $lockCases) {
            $lockedInput = Open-CertifiedDistributionLockedInput `
                -Path $lockCase.Path `
                -Label $lockCase.Label `
                -MaximumBytes $lockCase.MaximumBytes `
                -Leases $lockLeases
            $replacement = Join-Path `
                $fixtureRoot `
                ('replacement-' + [Guid]::NewGuid().ToString('N'))
            [IO.File]::Copy($lockCase.Path, $replacement, $false)
            $replaceBlocked = $false
            try {
                [IO.File]::Move($replacement, $lockCase.Path, $true)
            }
            catch [IO.IOException] {
                $replaceBlocked = $true
            }
            catch [UnauthorizedAccessException] {
                $replaceBlocked = $true
            }
            if (-not $replaceBlocked) {
                throw "$($lockCase.Label) allowed replacement while admitted."
            }
            Assert-CertifiedDistributionLockedPathStillNamesInput `
                -Descriptor $lockedInput
            Assert-CertifiedDistributionLockedInputUnchanged `
                -Descriptor $lockedInput
        }
    }
    finally {
        for ($index = $lockLeases.Count - 1; $index -ge 0; $index--) {
            $lockLeases[$index].Dispose()
        }
    }

    $snapshotLeases = [Collections.Generic.List[IDisposable]]::new()
    $snapshotContinuityAncestor = Join-Path `
        $protectedSnapshotBase `
        ('snapshot-continuity-ancestor-' + [Guid]::NewGuid().ToString('N'))
    $snapshotContinuityRoot = Join-Path $snapshotContinuityAncestor 'leaf'
    [IO.Directory]::CreateDirectory($snapshotContinuityRoot) | Out-Null
    try {
        $snapshotSource = Open-CertifiedDistributionLockedInput `
            -Path $installerPath `
            -Label 'Snapshot continuity Installer fixture' `
            -MaximumBytes (8L * 1024 * 1024 * 1024) `
            -Leases $snapshotLeases
        $lockedSnapshotDirectory = Open-CertifiedDistributionLockedDirectory `
            -Path $snapshotContinuityRoot `
            -Label 'Snapshot continuity directory chain' `
            -Leases $snapshotLeases
        $lockedSnapshot = Copy-CertifiedDistributionLockedSnapshot `
            -Descriptor $snapshotSource `
            -DirectoryDescriptor $lockedSnapshotDirectory `
            -Destination (Join-Path $snapshotContinuityRoot 'installer.exe') `
            -Leases $snapshotLeases
        foreach ($renameTarget in @(
            [pscustomobject]@{
                Path = $snapshotContinuityRoot
                RenamedPath = $snapshotContinuityRoot + '-renamed'
                Label = 'Snapshot immediate parent'
            },
            [pscustomobject]@{
                Path = $snapshotContinuityAncestor
                RenamedPath = $snapshotContinuityAncestor + '-renamed'
                Label = 'Snapshot higher ancestor'
            })) {
            $firstRenameSucceeded = $false
            $renameBlocked = $false
            try {
                [IO.Directory]::Move($renameTarget.Path, $renameTarget.RenamedPath)
                $firstRenameSucceeded = $true
                [IO.Directory]::Move($renameTarget.RenamedPath, $renameTarget.Path)
            }
            catch [IO.IOException] {
                if ($firstRenameSucceeded) {
                    throw "$($renameTarget.Label) renamed before the restore attempt was blocked."
                }
                $renameBlocked = $true
            }
            catch [UnauthorizedAccessException] {
                if ($firstRenameSucceeded) {
                    throw "$($renameTarget.Label) renamed before the restore attempt was blocked."
                }
                $renameBlocked = $true
            }
            if ($firstRenameSucceeded -or -not $renameBlocked) {
                throw "$($renameTarget.Label) allowed a transient rename-and-restore attack."
            }
        }
        Assert-CertifiedDistributionLockedDirectoryUnchanged `
            -Descriptor $lockedSnapshotDirectory
        Assert-CertifiedDistributionLockedPathStillNamesInput `
            -Descriptor $lockedSnapshot
        Assert-CertifiedDistributionLockedInputUnchanged `
            -Descriptor $lockedSnapshot
    }
    finally {
        for ($index = $snapshotLeases.Count - 1; $index -ge 0; $index--) {
            $snapshotLeases[$index].Dispose()
        }
    }

    Write-Output 'ENTERPRISE-STABLE-PROMOTION-AUTHORIZATION-CONTRACT-PASS'
}
finally {
    $receiptSigner.Dispose()
    $authorizationSigner.Dispose()
    if (Test-Path -LiteralPath $fixtureRoot) {
        $resolved = [IO.Path]::GetFullPath($fixtureRoot)
        $prefix = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd(
            [IO.Path]::DirectorySeparatorChar) +
            [IO.Path]::DirectorySeparatorChar +
            'ensou-stable-authorization-contract-'
        if (-not $resolved.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Refusing to remove an unexpected Stable authorization contract fixture.'
        }
        foreach ($entry in Get-ChildItem -LiteralPath $resolved -Force -Recurse) {
            if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'Refusing to remove a linked Stable authorization contract fixture.'
            }
        }
        [IO.Directory]::Delete($resolved, $true)
    }
    if (Test-Path -LiteralPath $protectedSnapshotBase) {
        $resolvedSnapshotBase = [IO.Path]::GetFullPath($protectedSnapshotBase)
        $expectedSnapshotPrefix = [IO.Path]::GetFullPath(
            (Join-Path $RepositoryRoot 'out')).TrimEnd(
                [IO.Path]::DirectorySeparatorChar) +
            [IO.Path]::DirectorySeparatorChar +
            'enterprise-stable-contract-snapshots-'
        if (-not $resolvedSnapshotBase.StartsWith(
                $expectedSnapshotPrefix,
                [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Refusing to remove an unexpected protected snapshot contract root.'
        }
        foreach ($entry in Get-ChildItem -LiteralPath $resolvedSnapshotBase -Force -Recurse) {
            if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'Refusing to remove a linked protected snapshot contract tree.'
            }
        }
        [IO.Directory]::Delete($resolvedSnapshotBase, $true)
    }
}
