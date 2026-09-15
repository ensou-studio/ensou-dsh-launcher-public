#requires -Version 7.4

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = Join-Path $PSScriptRoot 'WindowsPilotSigning.psm1'
$preflightPath = Join-Path $PSScriptRoot 'Test-WindowsPilotSigningPrerequisites.ps1'
$generatorPath = Join-Path $PSScriptRoot 'New-WindowsInternalPilotCertificates.ps1'
$fixtureRoot = Join-Path $PSScriptRoot 'fixtures'
Microsoft.PowerShell.Core\Import-Module $modulePath -Force

$pilotTsaUri = 'http://timestamp.digicert.com/'
$pilotTsaDigest = [Convert]::ToHexString(
    [Security.Cryptography.SHA256]::HashData(
        [Text.Encoding]::UTF8.GetBytes($pilotTsaUri))).ToLowerInvariant()

function Assert-True {
    param([Parameter(Mandatory = $true)][bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "ASSERT-TRUE failed: $Message" }
}

function Assert-False {
    param([Parameter(Mandatory = $true)][bool]$Condition, [string]$Message)
    if ($Condition) { throw "ASSERT-FALSE failed: $Message" }
}

function Assert-Equal {
    param($Actual, $Expected, [string]$Message)
    if ($Actual -cne $Expected) {
        throw "ASSERT-EQUAL failed: $Message; expected '$Expected', got '$Actual'."
    }
}

$expectedFixtures = [ordered]@{
    'arbitrary-https-tsa.no-go.json' = 'TSA_ENDPOINT_PIN_NOT_APPROVED'
    'duplicate-target-hash.no-go.json' = 'TARGET_EXPECTED_SHA256_DUPLICATE'
    'duplicate-target-path.no-go.json' = 'TARGET_PATH_DUPLICATE'
    'expired-certificate.no-go.json' = 'CERTIFICATE_NOT_CURRENTLY_VALID'
    'exportable-key.no-go.json' = 'PRIVATE_KEY_IS_EXPORTABLE'
    'missing-target-hash.no-go.json' = 'TARGET_BINDING_COUNT_MISMATCH'
    'network-capable-policy.no-go.json' = 'CERTIFICATE_DOWNLOADS_MUST_BE_DISABLED'
    'no-signtool.no-go.json' = 'SIGNTOOL_NOT_FOUND'
    'unsupported-scheme-tsa.no-go.json' =
        'TSA_URI_MUST_BE_ABSOLUTE_HTTP_OR_HTTPS'
    'reordered-target-hashes.no-go.json' = 'SIGNING_TARGET_SHA256_PIN_MISMATCH'
    'reparse-target.no-go.json' = 'SIGNING_TARGET_REPARSE_POINT_FORBIDDEN'
    'revocation-unproven.no-go.json' = 'CERTIFICATE_REVOCATION_STATUS_NOT_PROVEN'
    'string-boolean.no-go.json' = 'OBSERVATION_BOOLEAN_TYPE_INVALID'
    'target-hash-mismatch.no-go.json' = 'SIGNING_TARGET_SHA256_PIN_MISMATCH'
    'target-path-escape.no-go.json' = 'SIGNING_TARGET_OUTSIDE_ALLOWED_ROOT'
    'unknown-key-exportability.no-go.json' =
        'PRIVATE_KEY_EXPORTABILITY_NOT_PROVEN_NON_EXPORTABLE'
    'unpinned-pilot-root.no-go.json' =
        'PILOT_ROOT_CERTIFICATE_SHA256_PIN_MISMATCH'
    'unpinned-tsa.no-go.json' = 'TSA_URI_SHA256_PIN_MISMATCH'
    'wrong-chain-policy.no-go.json' =
        'CERTIFICATE_CHAIN_APPLICATION_POLICY_INVALID'
    'wrong-eku.no-go.json' = 'CODE_SIGNING_EKU_REQUIRED'
    'wrong-key-usage.no-go.json' = 'DIGITAL_SIGNATURE_KEY_USAGE_REQUIRED'
    'wrong-terminal-root.no-go.json' =
        'CERTIFICATE_CHAIN_TERMINAL_ROOT_PIN_MISMATCH'
}

$actualFixtureNames = @(Get-ChildItem -LiteralPath $fixtureRoot -Filter '*.json' -File |
        Sort-Object Name | Select-Object -ExpandProperty Name)
Assert-Equal $actualFixtureNames.Count $expectedFixtures.Count 'fixture count is exact'
foreach ($name in $expectedFixtures.Keys) {
    Assert-True ($name -cin $actualFixtureNames) "fixture '$name' exists"
    $path = Join-Path $fixtureRoot $name
    $fixture = Get-Content -LiteralPath $path -Raw |
        ConvertFrom-Json -Depth 32 -DateKind String
    Assert-True ($fixture.fixture -is [bool] -and $fixture.fixture) `
        "$name is explicitly a strict-Boolean fixture"
    Assert-Equal ([string]$fixture.expectedVerdict) 'NO_GO' `
        "$name has explicit NO_GO expectation"
    $result = Test-WindowsPilotSigningObservation -Observation $fixture.observation
    Assert-Equal ([string]$result.pilotSigningReadiness) 'NO_GO' `
        "$name evaluates NO_GO"
    Assert-Equal ([string]$result.productionAdmission) 'NO_GO' `
        "$name never authorizes production"
    Assert-True ($expectedFixtures[$name] -cin @($result.blockers)) `
        "$name emits $($expectedFixtures[$name])"
    Assert-True ('CERTIFICATE_REVOCATION_STATUS_NOT_PROVEN' -cin @($result.blockers)) `
        "$name retains the unavoidable offline revocation blocker"
}

# Even an otherwise-perfect caller-constructed observation cannot turn the
# deliberately offline check into revocation evidence or release admission.
$otherwisePassing = (Get-Content -LiteralPath (
        Join-Path $fixtureRoot 'no-signtool.no-go.json') -Raw |
    ConvertFrom-Json -Depth 32).observation
$otherwisePassing.signTool.exists = $true
$otherwisePassing.signTool.absoluteSafePath = $true
$otherwisePassing.signTool.fileNameExact = $true
$otherwisePassing.signTool.versionMatches = $true
$otherwisePassing.signTool.sha256Matches = $true
Add-Member -InputObject $otherwisePassing.certificate -Force `
    -NotePropertyName digitalSignatureKeyUsage -NotePropertyValue $true
Add-Member -InputObject $otherwisePassing.certificate -Force `
    -NotePropertyName chainApplicationPolicyCodeSigningOnly -NotePropertyValue $true
Add-Member -InputObject $otherwisePassing.certificate -Force `
    -NotePropertyName chainTerminatesAtPinnedRoot -NotePropertyValue $true
Add-Member -InputObject $otherwisePassing.certificate -Force `
    -NotePropertyName privateKeyProviderType -NotePropertyValue 'CNG'
Add-Member -InputObject $otherwisePassing.certificate -Force `
    -NotePropertyName privateKeyProviderName `
    -NotePropertyValue 'Microsoft Software Key Storage Provider'
Add-Member -InputObject $otherwisePassing.certificate -Force `
    -NotePropertyName privateKeyAlgorithmGroup -NotePropertyValue 'RSA'
Add-Member -InputObject $otherwisePassing.certificate -Force `
    -NotePropertyName privateKeySizeBits -NotePropertyValue ([int]3072)
Add-Member -InputObject $otherwisePassing.certificate -Force `
    -NotePropertyName privateKeyIsMachineKey -NotePropertyValue $false
Add-Member -InputObject $otherwisePassing.certificate -Force `
    -NotePropertyName privateKeyCurrentUserSoftwareKsp -NotePropertyValue $true
Add-Member -InputObject $otherwisePassing.tsa -Force `
    -NotePropertyName pathShapeAllowed -NotePropertyValue $true
Add-Member -InputObject $otherwisePassing.tsa -Force `
    -NotePropertyName repositoryPinApproved -NotePropertyValue $true
Add-Member -InputObject $otherwisePassing.tsa -Force `
    -NotePropertyName absoluteApprovedScheme -NotePropertyValue $true
$otherwisePassingResult =
    Test-WindowsPilotSigningObservation -Observation $otherwisePassing
Assert-Equal $otherwisePassingResult.pilotSigningReadiness 'NO_GO' `
    'offline preflight never claims explicit signing readiness'
Assert-Equal $otherwisePassingResult.productionAdmission 'NO_GO' `
    'offline preflight never authorizes production'
Assert-Equal @($otherwisePassingResult.blockers).Count 1 `
    'otherwise passing observation keeps exactly the revocation blocker'
Assert-True ('CERTIFICATE_REVOCATION_STATUS_NOT_PROVEN' -cin
        @($otherwisePassingResult.blockers)) `
    'caller-supplied Good cannot masquerade as online revocation proof'

$wrongProvider = ($otherwisePassing | ConvertTo-Json -Depth 32 -Compress |
    ConvertFrom-Json -Depth 32)
$wrongProvider.certificate.privateKeyProviderName = 'Legacy Provider'
$wrongProviderResult = Test-WindowsPilotSigningObservation -Observation $wrongProvider
Assert-True ('PRIVATE_KEY_PROVIDER_NOT_SOFTWARE_KSP' -cin
        @($wrongProviderResult.blockers)) `
    'non-Software-KSP private key provider is an explicit blocker'
$wrongProvider.certificate.privateKeyProviderName =
    'Microsoft Software Key Storage Provider'
$wrongProvider.certificate.privateKeyIsMachineKey = $true
$wrongProviderResult = Test-WindowsPilotSigningObservation -Observation $wrongProvider
Assert-True ('PRIVATE_KEY_MACHINE_SCOPE_FORBIDDEN' -cin
        @($wrongProviderResult.blockers)) `
    'machine-scope code-signing key is an explicit blocker'

# The path-shape gate runs before filesystem access and rejects Windows path
# namespaces and ambiguity classes that LiteralPath alone does not make safe.
$unsafePaths = @(
    '\\server\share\app.exe',
    '\\?\C:\release\app.exe',
    '\\.\C:\release\app.exe',
    'C:release\app.exe',
    '\release\app.exe',
    'C:\release\app.exe:payload',
    'C:\release\*.exe',
    'C:\release\bad|name.exe',
    'C:\',
    'C:/release/app.exe',
    'C:\release\\app.exe',
    'C:\release\..\app.exe'
)
foreach ($unsafePath in $unsafePaths) {
    Assert-False (Test-WindowsLocalAbsolutePathShape -Path $unsafePath) `
        'unsafe Windows path shape is rejected'
}
Assert-True (Test-WindowsLocalAbsolutePathShape -Path 'C:\release\app.exe') `
    'ordinary canonical local file path shape is accepted'
Assert-True (Test-WindowsLocalAbsolutePathShape `
        -Path 'C:\release\unsigned' -Directory) `
    'ordinary canonical local directory path shape is accepted'

$realPePath = Join-Path $PSHOME 'pwsh.exe'
# Exercise a real file and directory whose complete ancestor chain permits
# retained no-follow handles. An inaccessible ancestor is intentionally NO_GO.
Assert-True (Test-WindowsFixedLocalDrivePath -Path $realPePath) `
    'real PE file is on an approved fixed local volume'
Assert-False (Test-WindowsPathHasReparsePoint -Path $realPePath) `
    'real ordinary PE file and all ancestors pass no-follow inspection'
Assert-True (Test-WindowsFixedLocalDrivePath -Path $PSHOME) `
    'real PowerShell directory is on an approved fixed local volume'
Assert-False (Test-WindowsPathHasReparsePoint -Path $PSHOME) `
    'real ordinary directory and all ancestors pass no-follow inspection'

$realPeItem = Get-Item -LiteralPath $realPePath
$realPeSha256 = (Get-FileHash -LiteralPath $realPePath -Algorithm SHA256).Hash.
    ToLowerInvariant()
$realPeObservation = Get-WindowsPilotSigningObservation `
    -SignToolPath $realPePath `
    -ExpectedSignToolFileVersion ([string]$realPeItem.VersionInfo.FileVersion) `
    -ExpectedSignToolSha256 $realPeSha256 `
    -CertificateStoreThumbprint ('0' * 40) `
    -ExpectedCertificateSha256 ('0' * 64) `
    -PilotRootCertificatePath 'C:\nonexistent\root.cer' `
    -ExpectedPilotRootCertificateSha256 ('0' * 64) `
    -TsaUri $pilotTsaUri `
    -ExpectedTsaUriSha256 $pilotTsaDigest `
    -AllowedTargetRoot $PSHOME `
    -TargetPath @($realPePath) `
    -ExpectedTargetSha256 @($realPeSha256)
Assert-True $realPeObservation.signTool.exists `
    'real ordinary PE tool path exists'
Assert-True $realPeObservation.signTool.absoluteSafePath `
    'real ordinary PE tool path passes fixed-drive/reparse gate'
Assert-True $realPeObservation.signTool.sha256Matches `
    'real ordinary PE tool hash is collected and matches'
Assert-True $realPeObservation.targets[0].absoluteSafePath `
    'real ordinary PE target passes fixed-drive/reparse gate'
Assert-True $realPeObservation.targets[0].isPortableExecutable `
    'real ordinary PE target is read with local PEReader'
Assert-True $realPeObservation.targets[0].sha256Matches `
    'real ordinary PE target hash is collected and matches'
Assert-False $realPeObservation.targets[0].isReparsePoint `
    'real ordinary PE target is not a reparse point'

# Build a real local junction under the dedicated test root. The component-wise
# walker must stop on the junction itself; it must never open the existing child
# beyond it or invoke the leaf operation. The exact test tree is removed in
# leaf-to-root order without recursive deletion.
$junctionTestBase = 'C:\Temp'
$junctionTestRoot = [IO.Path]::GetFullPath((Join-Path $junctionTestBase (
            'ensou-dsh-pilot-nofollow-' + [Guid]::NewGuid().ToString('N'))))
$junctionTestPrefix = 'C:\Temp\ensou-dsh-pilot-nofollow-'
Assert-True ($junctionTestRoot.StartsWith(
        $junctionTestPrefix, [StringComparison]::OrdinalIgnoreCase)) `
    'junction test root resolves below the exact controlled C:\Temp prefix'
Assert-True (Test-WindowsLocalAbsolutePathShape `
        -Path $junctionTestRoot -Directory) `
    'junction test root has an approved fixed-local path shape'
Assert-False ([IO.Directory]::Exists($junctionTestRoot)) `
    'junction test root starts absent'

$junctionSourceRoot = Join-Path $junctionTestRoot 'source'
$junctionTargetRoot = Join-Path $junctionTestRoot 'target'
$junctionPath = Join-Path $junctionSourceRoot 'blocked-junction'
$junctionMarkerPath = Join-Path $junctionTargetRoot 'marker.exe'
$junctionAttackPath = Join-Path $junctionPath 'marker.exe'
$leafOperationHits = [Collections.Generic.List[string]]::new()
try {
    [void][IO.Directory]::CreateDirectory($junctionSourceRoot)
    [void][IO.Directory]::CreateDirectory($junctionTargetRoot)
    [IO.File]::WriteAllBytes($junctionMarkerPath, [byte[]](0x4d, 0x5a, 0, 0))
    $null = New-Item -ItemType Junction -Path $junctionPath `
        -Target $junctionTargetRoot

    $signingModule = Get-Module -Name WindowsPilotSigning
    $junctionObservation = & $signingModule {
        param([string]$AttackPath, $OperationHits)
        $operation = {
            param($Handle, $SafePath)
            [void]$OperationHits.Add($SafePath)
            return 'UNEXPECTED_LEAF_OPERATION'
        }.GetNewClosure()
        Invoke-WindowsNoFollowPathOperation `
            -Path $AttackPath -ExpectedKind File -Operation $operation
    } $junctionAttackPath $leafOperationHits

    Assert-False $junctionObservation.safe `
        'junction child path is rejected'
    Assert-Equal $junctionObservation.failure 'REPARSE_POINT_FORBIDDEN' `
        'real junction is the rejecting component'
    Assert-True $junctionObservation.reparseDetected `
        'real junction is detected through its no-follow handle'
    Assert-False $junctionObservation.leafOpened `
        'child beyond the junction is never opened'
    Assert-Equal $leafOperationHits.Count 0 `
        'leaf operation is never invoked for the child beyond the junction'
    Assert-Equal $junctionObservation.blockedComponentIndex `
        ($junctionObservation.totalComponentCount - 2) `
        'walker stops exactly at the junction before the final child'
    Assert-True ($junctionObservation.openedComponentCount -lt
            $junctionObservation.totalComponentCount) `
        'walker does not open every component of the hostile path'
}
finally {
    Assert-True ($junctionTestRoot.StartsWith(
            $junctionTestPrefix, [StringComparison]::OrdinalIgnoreCase)) `
        'cleanup remains constrained to the exact controlled test prefix'
    if ([IO.Directory]::Exists($junctionPath)) {
        [IO.Directory]::Delete($junctionPath)
    }
    if ([IO.File]::Exists($junctionMarkerPath)) {
        [IO.File]::Delete($junctionMarkerPath)
    }
    if ([IO.Directory]::Exists($junctionTargetRoot)) {
        [IO.Directory]::Delete($junctionTargetRoot)
    }
    if ([IO.Directory]::Exists($junctionSourceRoot)) {
        [IO.Directory]::Delete($junctionSourceRoot)
    }
    if ([IO.Directory]::Exists($junctionTestRoot)) {
        [IO.Directory]::Delete($junctionTestRoot)
    }
}
Assert-False ([IO.Directory]::Exists($junctionTestRoot)) `
    'junction test tree is fully removed'

# Z: is unavailable on the test host and is the conventional mapped-drive
# attack input; the synthetic classifications make mapped/SUBST rejection
# deterministic even on a host that has no mapped drive at test time.
Assert-False (Test-WindowsLocalAbsolutePathShape -Path 'Z:\remote\app.exe') `
    'unavailable or mapped Z drive is rejected before filesystem access'
Assert-False (Test-WindowsFixedLocalDriveClassification `
        -DriveType 4 -DosDeviceTargets @('\Device\Mup\server\share')) `
    'Win32 DRIVE_REMOTE mapped drive is rejected'
Assert-False (Test-WindowsFixedLocalDriveClassification `
        -DriveType 3 `
        -DosDeviceTargets @('\Device\LanmanRedirector\server\share')) `
    'redirector alias is rejected even if drive type is spoofed fixed'
Assert-False (Test-WindowsFixedLocalDriveClassification `
        -DriveType 3 -DosDeviceTargets @('\??\C:\release')) `
    'SUBST DOS-device alias is rejected even when reported fixed'
Assert-True (Test-WindowsFixedLocalDriveClassification `
        -DriveType 3 -DosDeviceTargets @('\Device\HarddiskVolume3')) `
    'ordinary fixed local volume classification is accepted'
Assert-False (Test-WindowsFixedLocalDriveClassification `
        -DriveType 3 -DosDeviceTargets @(
            '\Device\HarddiskVolume3', '\Device\HarddiskVolume4')) `
    'ambiguous QueryDosDevice MULTI_SZ with multiple targets is rejected'

# A caller cannot approve an arbitrary HTTPS endpoint merely by providing the
# matching digest. Raw URI components are never returned, even on hostile input.
$arbitraryUri = 'https://arbitrary.example/timestamp'
$arbitraryDigest = [Convert]::ToHexString(
    [Security.Cryptography.SHA256]::HashData(
        [Text.Encoding]::UTF8.GetBytes($arbitraryUri))).ToLowerInvariant()
$arbitraryTsa = Get-WindowsPilotTsaObservation `
    -TsaUri $arbitraryUri -ExpectedTsaUriSha256 $arbitraryDigest
Assert-True $arbitraryTsa.absoluteApprovedScheme `
    'canonical arbitrary endpoint uses an RFC3161 transport scheme'
Assert-True $arbitraryTsa.sha256Matches 'canonical arbitrary endpoint matches caller digest'
Assert-False $arbitraryTsa.repositoryPinApproved `
    'caller digest is not repository TSA policy approval'
$arbitraryJson = $arbitraryTsa | ConvertTo-Json -Depth 8 -Compress
Assert-False ($arbitraryJson.Contains('arbitrary.example')) 'TSA host is redacted'
Assert-False ($arbitraryJson.Contains('/timestamp')) 'TSA path is redacted'
Assert-False ($arbitraryJson.Contains($arbitraryUri)) 'raw TSA URI is redacted'

Assert-Equal $pilotTsaDigest `
    '9a44be2d0f498a8bfd2dd1a5e5cced2135e9c4ada9bb5a04eed4c6c5beba1a33' `
    'Pilot TSA canonical endpoint digest is independently recomputed'
$pilotTsa = Get-WindowsPilotTsaObservation `
    -TsaUri $pilotTsaUri -ExpectedTsaUriSha256 $pilotTsaDigest
Assert-True $pilotTsa.absoluteApprovedScheme `
    'approved Pilot TSA uses an allowed transport scheme'
Assert-True $pilotTsa.canonicalInput 'approved Pilot TSA input is canonical'
Assert-True $pilotTsa.repositoryPinApproved `
    'approved Pilot TSA digest is pinned by repository policy'
Assert-True $pilotTsa.sha256Matches `
    'approved Pilot TSA canonical bytes match their pin'
$pilotTsaJson = $pilotTsa | ConvertTo-Json -Depth 8 -Compress
Assert-False ($pilotTsaJson.Contains('timestamp.digicert.com')) `
    'approved TSA host is also redacted'
Assert-False ($pilotTsaJson.Contains($pilotTsaUri)) `
    'approved raw TSA URI is also redacted'

$unsupportedTsa = Get-WindowsPilotTsaObservation `
    -TsaUri 'ftp://tsa.example/timestamp' -ExpectedTsaUriSha256 ('0' * 64)
Assert-False $unsupportedTsa.absoluteApprovedScheme `
    'non-HTTP RFC3161 transport scheme is rejected'

$hostileUri =
    'https://operator:do-not-leak@leak.example/private-path?secret=value#fragment'
$hostileTsa = Get-WindowsPilotTsaObservation `
    -TsaUri $hostileUri -ExpectedTsaUriSha256 ('0' * 64)
$hostileJson = $hostileTsa | ConvertTo-Json -Depth 8 -Compress
foreach ($marker in @(
        'operator', 'do-not-leak', 'leak.example', 'private-path',
        'secret=value', 'fragment', $hostileUri)) {
    Assert-False ($hostileJson.Contains($marker)) `
        'hostile TSA components never appear in serialized output'
}

# Exercise the public preflight boundary with only nonexistent controlled paths.
# It performs no signing or network request, retains NO_GO, and redacts the TSA.
$preflightArguments = @(
    '-NoProfile', '-File', $preflightPath,
    '-SignToolPath', 'C:\nonexistent\signtool.exe',
    '-ExpectedSignToolFileVersion', '0.0.0.0',
    '-ExpectedSignToolSha256', ('0' * 64),
    '-CertificateStoreThumbprint', ('0' * 40),
    '-ExpectedCertificateSha256', ('0' * 64),
    '-PilotRootCertificatePath', 'C:\nonexistent\root.cer',
    '-ExpectedPilotRootCertificateSha256', ('0' * 64),
    '-TsaUri', $pilotTsaUri,
    '-ExpectedTsaUriSha256', $pilotTsaDigest,
    '-AllowedTargetRoot', 'C:\nonexistent\unsigned',
    '-TargetPath', 'C:\nonexistent\unsigned\app.exe',
    '-ExpectedTargetSha256', ('1' * 64)
)
$preflightJson = & (Join-Path $PSHOME 'pwsh.exe') @preflightArguments
$preflightExitCode = $LASTEXITCODE
$preflightResult = $preflightJson | ConvertFrom-Json -Depth 32
Assert-Equal $preflightExitCode 3 'offline public preflight exits NO_GO'
Assert-Equal $preflightResult.pilotSigningReadiness 'NO_GO' `
    'offline public preflight returns NO_GO'
Assert-Equal $preflightResult.productionAdmission 'NO_GO' `
    'offline public preflight never authorizes production'
Assert-True $preflightResult.observation.tsa.repositoryPinApproved `
    'public preflight recognizes only the repository TSA pin'
Assert-False (($preflightJson -join "`n").Contains('timestamp.digicert.com')) `
    'public preflight does not emit the TSA host'
Assert-True ('CERTIFICATE_REVOCATION_STATUS_NOT_PROVEN' -cin
        @($preflightResult.blockers)) `
    'public preflight retains offline revocation blocker'

# Parse and inspect command ASTs so comments do not weaken the network/static
# checks. No test invokes a timestamp service, WinVerifyTrust, or signing.
foreach ($scriptPath in @($modulePath, $preflightPath, $generatorPath)) {
    $tokens = $null
    $parseErrors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile(
        $scriptPath, [ref]$tokens, [ref]$parseErrors)
    Assert-Equal @($parseErrors).Count 0 "$(Split-Path $scriptPath -Leaf) parses"
    $commandNames = @($ast.FindAll({
                param($node)
                $node -is [Management.Automation.Language.CommandAst]
            }, $true) | ForEach-Object { $_.GetCommandName() })
    foreach ($forbiddenCommand in @(
            'Invoke-WebRequest', 'Invoke-RestMethod', 'Start-BitsTransfer',
            'Get-AuthenticodeSignature', 'Resolve-Path')) {
        Assert-False ($forbiddenCommand -cin $commandNames) `
            "$forbiddenCommand is absent from $(Split-Path $scriptPath -Leaf)"
    }
}

$moduleText = Get-Content -LiteralPath $modulePath -Raw
$moduleTokens = $null
$moduleParseErrors = $null
$moduleAst = [Management.Automation.Language.Parser]::ParseFile(
    $modulePath, [ref]$moduleTokens, [ref]$moduleParseErrors)
$moduleCommandNames = @($moduleAst.FindAll({
            param($node)
            $node -is [Management.Automation.Language.CommandAst]
        }, $true) | ForEach-Object { $_.GetCommandName() })
Assert-False ('Get-Item' -cin $moduleCommandNames) `
    'module never reopens an untrusted complete path through Get-Item'
Assert-False ('Get-FileHash' -cin $moduleCommandNames) `
    'module hashes targets only through the retained final handle'
$pathShapeAst = $moduleAst.Find({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Test-WindowsLocalAbsolutePathShape'
    }, $true)
$pathShapeCommands = @($pathShapeAst.FindAll({
            param($node)
            $node -is [Management.Automation.Language.CommandAst]
        }, $true) | ForEach-Object { $_.GetCommandName() })
Assert-False ('Get-Item' -cin $pathShapeCommands) `
    'pre-provider path gate never opens or resolves a filesystem item'
Assert-False ('Resolve-Path' -cin $pathShapeCommands) `
    'pre-provider path gate never resolves an untrusted path'
Assert-True ('Test-WindowsFixedLocalDrivePath' -cin $pathShapeCommands) `
    'path gate requires Win32 fixed-local-drive classification'
$reparseAst = $moduleAst.Find({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Test-WindowsPathHasReparsePoint'
    }, $true)
$reparseCommandNames = @($reparseAst.FindAll({
            param($node)
            $node -is [Management.Automation.Language.CommandAst]
        }, $true) | ForEach-Object { $_.GetCommandName() })
Assert-False ('Get-Item' -cin $reparseCommandNames) `
    'reparse check never follows a full leaf through Get-Item'
Assert-True ('Invoke-WindowsNoFollowPathOperation' -cin $reparseCommandNames) `
    'reparse check delegates to component-wise no-follow handles'
Assert-True ($moduleText -match 'DisableCertificateDownloads\s*=\s*\$true') `
    'certificate-chain downloads are disabled'
Assert-True ($moduleText -match 'X509RevocationMode\]::NoCheck') `
    'offline chain build cannot make an online revocation claim'
Assert-True ($moduleText -match 'PortableExecutable\.PEReader') `
    'PE signature presence is inspected from the local security directory'
Assert-True ($moduleText -match 'Get-WindowsPrivateKeyProviderObservation') `
    'certificate observation records the concrete private-key provider'
Assert-True ($moduleText -match 'Microsoft Software Key Storage Provider') `
    'certificate observation pins the CurrentUser Software KSP provider'
Assert-True ($moduleText -match 'PRIVATE_KEY_PROVIDER_NOT_CNG') `
    'certificate evaluator rejects non-CNG private keys'
Assert-True ($moduleText -match 'PRIVATE_KEY_MACHINE_SCOPE_FORBIDDEN') `
    'certificate evaluator rejects machine-scope private keys'
Assert-False ($moduleText -match '(?i)System\.Net\.Http|WebRequest\s*::') `
    'module has no .NET network client'
Assert-False ($moduleText -match 'GetFileAttributesW') `
    'no access-denied attribute fallback can continue without retained handles'
Assert-True ($moduleText -match '0x02200000') `
    'component opens use OPEN_REPARSE_POINT and BACKUP_SEMANTICS'

$generatorText = Get-Content -LiteralPath $generatorPath -Raw
Assert-True ($generatorText -match [regex]::Escape(
        "[ValidateSet('I UNDERSTAND THIS IS PILOT ONLY')]")) `
    'certificate helper requires exact Pilot-only acknowledgement'
Assert-True ($generatorText -match [regex]::Escape(
        "[ValidateSet('PersonalTwoDevice', 'EnterpriseTwoDevice')]")) `
    'certificate helper requires one exact isolated Pilot profile'
Assert-False ($generatorText -match 'PersonalOneDevice') `
    'certificate helper cannot admit the retired one-device Personal profile'
Assert-True ($generatorText -match
        "two-explicit-personal-test-devices-only") `
    'certificate helper binds the Personal profile to two explicit devices'
Assert-True ($generatorText -match
        "two-explicit-enterprise-test-devices-only") `
    'certificate helper binds the Enterprise profile to two explicit devices'
Assert-True ($generatorText -match
        "personal-two-device-pilot") `
    'Personal certificate filenames are profile-specific'
Assert-True ($generatorText -match
        "enterprise-two-device-pilot") `
    'Enterprise certificate filenames are profile-specific'
Assert-True ($generatorText.Contains(
        '-Subject "CN=$Publisher DSH $($profileDefinition.certificateLabel) Root"')) `
    'Pilot root Subject contains the selected profile label'
Assert-True ($generatorText.Contains(
        '-FriendlyName "$Publisher DSH $($profileDefinition.certificateLabel) Root - NOT PRODUCTION"')) `
    'Pilot root FriendlyName contains the selected profile label'
Assert-True ($generatorText.Contains(
        '-FriendlyName "$Publisher DSH $($profileDefinition.certificateLabel) Code Signing - NOT PRODUCTION"')) `
    'Pilot leaf FriendlyName contains the selected profile label'
Assert-True ($generatorText -match "ConfirmImpact\s*=\s*'High'") `
    'certificate helper uses high-impact confirmation'
Assert-True ($generatorText -match '-KeyExportPolicy NonExportable') `
    'certificate helper requests non-exportable keys'
Assert-True ($generatorText -notmatch 'Export-PfxCertificate') `
    'certificate helper never exports a PFX'
Assert-True ($generatorText -notmatch 'Cert:\\LocalMachine') `
    'certificate helper never mutates LocalMachine stores'
Assert-True ($generatorText -notmatch 'Cert:\\CurrentUser\\Root') `
    'certificate helper never installs trusted roots'
Assert-True ($generatorText -notmatch '(?i)signtool(?:\.exe)?\s+sign') `
    'certificate helper never signs files'

$preflightText = Get-Content -LiteralPath $preflightPath -Raw
Assert-True ($preflightText -notmatch 'New-SelfSignedCertificate') `
    'read-only preflight never creates certificates'
Assert-True ($preflightText -notmatch '(?i)signtool(?:\.exe)?\s+sign') `
    'read-only preflight never signs files'

# WhatIf for both isolated profiles must stop before output-directory or
# certificate-store mutation.
$whatIfProfiles = @('PersonalTwoDevice', 'EnterpriseTwoDevice')
$whatIfOutputPaths = @{}
foreach ($profile in $whatIfProfiles) {
    $whatIfOutputPaths[$profile] = Join-Path $PSHOME (
        "ensou-dsh-$profile-pilot-whatif-" + [Guid]::NewGuid().ToString('N'))
    Assert-False (Test-Path -LiteralPath $whatIfOutputPaths[$profile]) `
        "$profile WhatIf target starts absent"
}
$beforeCertificateThumbprints = @(Get-ChildItem -LiteralPath Cert:\CurrentUser\My |
        Select-Object -ExpandProperty Thumbprint | Sort-Object)
foreach ($profile in $whatIfProfiles) {
    $null = & $generatorPath `
        -PilotOnlyConfirmation 'I UNDERSTAND THIS IS PILOT ONLY' `
        -PilotProfile $profile `
        -Publisher 'Ensou' `
        -OutputDirectory $whatIfOutputPaths[$profile] `
        -CrlDistributionPointUri "https://pilot-signing.example.invalid/$profile.crl" `
        -WhatIf 6>&1 | Out-String
}
$afterCertificateThumbprints = @(Get-ChildItem -LiteralPath Cert:\CurrentUser\My |
        Select-Object -ExpandProperty Thumbprint | Sort-Object)
foreach ($profile in $whatIfProfiles) {
    Assert-False (Test-Path -LiteralPath $whatIfOutputPaths[$profile]) `
        "$profile WhatIf does not create output directory"
}
Assert-Equal ($beforeCertificateThumbprints -join ',') `
    ($afterCertificateThumbprints -join ',') `
    'WhatIf does not change CurrentUser/My certificate store'
'WINDOWS-PILOT-SIGNING-TOOLING-PASS'
'ALL-PERSISTED-ATTACK-FIXTURES-EXPLICIT-NO-GO'
'OFFLINE-REVOCATION-AND-UNAPPROVED-TSA-REMAIN-NO-GO'
'NO-REAL-CERTIFICATE-CREATION-NETWORK-SIGNING-OR-PUBLICATION-PERFORMED'
