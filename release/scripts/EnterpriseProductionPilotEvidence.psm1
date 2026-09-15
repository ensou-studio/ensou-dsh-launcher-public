#requires -Version 7.2

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$stateModulePath = Join-Path $PSScriptRoot 'ProductionReleaseState.psm1'
Microsoft.PowerShell.Core\Import-Module `
    -Name $stateModulePath `
    -Force `
    -ErrorAction Stop

function Get-R8MemberValue {
    param(
        [Parameter(Mandatory = $true)]$Object,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $present = $false
    $value = $null
    if ($Object -is [Collections.IDictionary]) {
        $present = $Object.Contains($Name)
        if ($present) {
            $value = $Object[$Name]
        }
    }
    else {
        $property = $Object.PSObject.Properties[$Name]
        $present = $null -ne $property
        if ($present) {
            $value = $property.Value
        }
    }
    if (-not $present) {
        throw "$Label is missing required member '$Name'."
    }
    return $value
}

function Test-R8ExactMemberPresent {
    param(
        [Parameter(Mandatory = $true)]$Object,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ($Object -is [Collections.IDictionary]) {
        foreach ($key in $Object.Keys) {
            if ([string]$key -ceq $Name) {
                return $true
            }
        }
        return $false
    }
    foreach ($property in $Object.PSObject.Properties) {
        if ([string]$property.Name -ceq $Name) {
            return $true
        }
    }
    return $false
}

function Assert-R8Equal {
    param(
        [AllowNull()][object]$Actual,
        [AllowNull()][object]$Expected,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ([string]$Actual -cne [string]$Expected) {
        throw "$Label differs from its authoritative binding."
    }
}

function Get-R8Sha256Bytes {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    return ProductionReleaseState\Get-ProductionSha256Bytes -Bytes $Bytes
}

function ConvertFrom-R8Base64Url {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ($Value -cnotmatch '^[A-Za-z0-9_-]+$') {
        throw "$Label is not canonical base64url."
    }
    $padded = $Value.Replace('-', '+').Replace('_', '/')
    switch ($padded.Length % 4) {
        0 {}
        2 { $padded += '==' }
        3 { $padded += '=' }
        default { throw "$Label has an invalid base64url length." }
    }
    try {
        $bytes = [Convert]::FromBase64String($padded)
    }
    catch {
        throw "$Label is not valid base64url."
    }
    $canonical = [Convert]::ToBase64String($bytes).
        TrimEnd('=').
        Replace('+', '-').
        Replace('/', '_')
    if ($canonical -cne $Value) {
        throw "$Label is not canonical base64url."
    }
    return $bytes
}

function ConvertTo-R8Base64Url {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    return [Convert]::ToBase64String($Bytes).
        TrimEnd('=').
        Replace('+', '-').
        Replace('/', '_')
}

function ConvertTo-R8CanonicalValue {
    param([AllowNull()]$Value)

    if ($null -eq $Value -or
        $Value -is [string] -or
        $Value -is [bool] -or
        $Value -is [byte] -or
        $Value -is [sbyte] -or
        $Value -is [int16] -or
        $Value -is [uint16] -or
        $Value -is [int32] -or
        $Value -is [uint32] -or
        $Value -is [int64]) {
        return $Value
    }
    if ($Value -is [uint64] -and $Value -le [int64]::MaxValue) {
        return [int64]$Value
    }
    if ($Value -is [Collections.IEnumerable] -and
        $Value -isnot [Collections.IDictionary] -and
        $Value -isnot [string]) {
        $items = [Collections.Generic.List[object]]::new()
        foreach ($item in $Value) {
            $items.Add((ConvertTo-R8CanonicalValue -Value $item))
        }
        return @($items)
    }

    [string[]]$names = @(
        if ($Value -is [Collections.IDictionary]) {
            $Value.Keys | ForEach-Object { [string]$_ }
        }
        else {
            $Value.PSObject.Properties |
                ForEach-Object { [string]$_.Name }
        }
    )
    if ($names.Length -gt 1) {
        [Array]::Sort($names, [StringComparer]::Ordinal)
    }
    $result = [ordered]@{}
    foreach ($name in $names) {
        $member = if ($Value -is [Collections.IDictionary]) {
            $Value[$name]
        }
        else {
            $Value.PSObject.Properties[$name].Value
        }
        $result[$name] = ConvertTo-R8CanonicalValue -Value $member
    }
    return $result
}

function ConvertTo-R8CanonicalJsonBytes {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Value)

    $canonicalValue = ConvertTo-R8CanonicalValue -Value $Value
    return ProductionReleaseState\ConvertTo-ProductionJsonBytes `
        -Value $canonicalValue
}

function Join-R8DomainPayload {
    param(
        [Parameter(Mandatory = $true)][string]$Domain,
        [Parameter(Mandatory = $true)][byte[]]$JsonBytes
    )

    $domainBytes = [Text.UTF8Encoding]::new($false, $true).
        GetBytes($Domain + [char]10)
    $payload = [byte[]]::new($domainBytes.Length + $JsonBytes.Length)
    [Array]::Copy($domainBytes, 0, $payload, 0, $domainBytes.Length)
    [Array]::Copy(
        $JsonBytes,
        0,
        $payload,
        $domainBytes.Length,
        $JsonBytes.Length)
    return $payload
}

function Get-EnterpriseWindowsPilotAttestationPayload {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][psobject]$Envelope)

    $text = @(
        'ensou-dsh-enterprise-windows-pilot-evidence-attestation-v2',
        [string]$Envelope.schemaVersion,
        [string]$Envelope.evidenceType,
        [string]$Envelope.body.schemaVersion,
        [string]$Envelope.body.evidenceType,
        [string]$Envelope.body.sizeBytes,
        [string]$Envelope.body.sha256) -join "`n"
    return [Text.UTF8Encoding]::new($false, $true).GetBytes($text)
}

function Get-EnterpriseWindowsPilotVerificationReportPayload {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][psobject]$Report)

    $projection = [ordered]@{}
    if ($Report -is [Collections.IDictionary]) {
        foreach ($name in @($Report.Keys)) {
            if ([string]$name -cne 'authentication') {
                $projection[[string]$name] = $Report[$name]
            }
        }
    }
    else {
        foreach ($property in @($Report.PSObject.Properties)) {
            if ([string]$property.Name -cne 'authentication') {
                $projection[[string]$property.Name] = $property.Value
            }
        }
    }
    $jsonBytes = ConvertTo-R8CanonicalJsonBytes -Value $projection
    return Join-R8DomainPayload `
        -Domain 'ensou-dsh-enterprise-windows-pilot-verification-report-authentication-v2' `
        -JsonBytes $jsonBytes
}

function Get-EnterpriseLocalDataCertificationPayload {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][psobject]$Receipt)

    $payload = [ordered]@{
        schemaVersion = [int]$Receipt.schemaVersion
        receiptType = [string]$Receipt.receiptType
        certificationId = [string]$Receipt.certificationId
        decision = [string]$Receipt.decision
        environment = [string]$Receipt.environment
        channel = [string]$Receipt.channel
        distributionScope = [string]$Receipt.distributionScope
        certificationAudienceId = [string]$Receipt.certificationAudienceId
        fromUpstreamTag = [string]$Receipt.fromUpstreamTag
        toUpstreamTag = [string]$Receipt.toUpstreamTag
        sourceRuntimeZipSha256 = [string]$Receipt.sourceRuntimeZipSha256
        targetRuntimeZipSha256 = [string]$Receipt.targetRuntimeZipSha256
        evidenceReportSha256 = [string]$Receipt.evidenceReportSha256
        runnerSha256 = [string]$Receipt.runnerSha256
        issuedAtUnixSeconds = [int64]$Receipt.issuedAtUnixSeconds
        expiresAtUnixSeconds = [int64]$Receipt.expiresAtUnixSeconds
    }
    return ProductionReleaseState\ConvertTo-ProductionJsonBytes -Value $payload
}

function Get-EnterpriseStablePilotAttestationPayload {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][psobject]$Observation,
        [Parameter(Mandatory = $true)]
        [ValidateSet('server', 'fresh-install', 'online-upgrade', 'unauthorized-control')]
        [string]$Role
    )

    $common = [ordered]@{
        schemaVersion = [int]$Observation.schemaVersion
        observationType = [string]$Observation.observationType
        orchestrationId = [string]$Observation.orchestrationId
        canonicalStableManifestUri =
            [string]$Observation.canonicalStableManifestUri
        r7 = $Observation.r7
        collectedAtUtc = [string]$Observation.collectedAtUtc
    }
    switch ($Role) {
        'server' {
            $domain =
                'ensou-dsh-enterprise-stable-private-pilot-server-attestation-v1'
            $projection = [ordered]@{
                common = $common
                sourceBaseline = $Observation.sourceBaseline
                targetRelease = $Observation.targetRelease
                allowlist = $Observation.privatePilot.allowlist
            }
        }
        'fresh-install' {
            $domain =
                'ensou-dsh-enterprise-stable-private-pilot-device-attestation-v1'
            $projection = [ordered]@{
                common = $common
                lane = 'fresh-install'
                targetRelease = $Observation.targetRelease
                device = $Observation.privatePilot.devices[0]
            }
        }
        'online-upgrade' {
            $domain =
                'ensou-dsh-enterprise-stable-private-pilot-device-attestation-v1'
            $projection = [ordered]@{
                common = $common
                lane = 'online-upgrade'
                sourceBaseline = $Observation.sourceBaseline
                targetRelease = $Observation.targetRelease
                device = $Observation.privatePilot.devices[1]
            }
        }
        'unauthorized-control' {
            $domain =
                'ensou-dsh-enterprise-stable-private-pilot-control-attestation-v1'
            $projection = [ordered]@{
                common = $common
                sourceBaseline = $Observation.sourceBaseline
                targetRelease = $Observation.targetRelease
                allowlist = $Observation.privatePilot.allowlist
                unauthorizedControl =
                    $Observation.privatePilot.unauthorizedControl
            }
        }
    }
    $jsonBytes = ConvertTo-R8CanonicalJsonBytes -Value $projection
    return Join-R8DomainPayload -Domain $domain -JsonBytes $jsonBytes
}

function Get-EnterpriseStablePilotSubsetSha256 {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][psobject]$Observation)

    $projection = [ordered]@{
        schemaVersion = [int]$Observation.schemaVersion
        observationType = [string]$Observation.observationType
        observationMode = [string]$Observation.observationMode
        orchestrationId = [string]$Observation.orchestrationId
        edition = [string]$Observation.edition
        product = [string]$Observation.product
        targetChannel = [string]$Observation.targetChannel
        exposureRing = [string]$Observation.exposureRing
        canonicalStableManifestUri =
            [string]$Observation.canonicalStableManifestUri
        r7 = $Observation.r7
        sourceBaseline = $Observation.sourceBaseline
        targetRelease = $Observation.targetRelease
        privatePilot = $Observation.privatePilot
        attestations = $Observation.attestations
        verificationStatus = $Observation.verificationStatus
        collectedAtUtc = [string]$Observation.collectedAtUtc
        productionAdmission = [string]$Observation.productionAdmission
        nextRequiredGate = [string]$Observation.nextRequiredGate
    }
    return Get-R8Sha256Bytes `
        -Bytes (ConvertTo-R8CanonicalJsonBytes -Value $projection)
}

function Assert-R8Es256Signature {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Payload,
        [Parameter(Mandatory = $true)][string]$SignatureValue,
        [Parameter(Mandatory = $true)][psobject]$Key,
        [Parameter(Mandatory = $true)][string]$ExpectedKeyId,
        [Parameter(Mandatory = $true)][string]$ExpectedPurpose,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ([string]$Key.algorithm -cne 'ES256' -or
        [string]$Key.keyId -cne $ExpectedKeyId -or
        [string]$Key.purpose -cne $ExpectedPurpose) {
        throw "$Label does not use the independently trusted key and purpose."
    }
    [void](ProductionReleaseState\Get-ProductionReleaseP256PublicKeyIdentity `
        -Trust $Key `
        -Label "$Label public key")
    $signature = ConvertFrom-R8Base64Url `
        -Value $SignatureValue `
        -Label "$Label signature"
    ProductionReleaseState\Assert-ProductionEs256P1363LowS `
        -Signature $signature `
        -Label "$Label signature"
    $x = ConvertFrom-R8Base64Url -Value ([string]$Key.x) -Label "$Label X"
    $y = ConvertFrom-R8Base64Url -Value ([string]$Key.y) -Label "$Label Y"
    $parameters = [Security.Cryptography.ECParameters]::new()
    $parameters.Curve =
        [Security.Cryptography.ECCurve+NamedCurves]::nistP256
    $point = [Security.Cryptography.ECPoint]::new()
    $point.X = $x
    $point.Y = $y
    $parameters.Q = $point
    $verifier = [Security.Cryptography.ECDsa]::Create()
    try {
        $verifier.ImportParameters($parameters)
        if (-not $verifier.VerifyData(
                $Payload,
                $signature,
                [Security.Cryptography.HashAlgorithmName]::SHA256,
                [Security.Cryptography.DSASignatureFormat]::
                    IeeeP1363FixedFieldConcatenation)) {
            throw "$Label signature verification failed."
        }
    }
    finally {
        $verifier.Dispose()
    }
}

function Assert-R8PurposeSeparatedKeys {
    param(
        [Parameter(Mandatory = $true)][psobject]$Trust,
        [Parameter(Mandatory = $true)][psobject]$InstallerSigningTrust
    )

    $keys = @(
        $Trust.windowsPilotEvidence,
        $Trust.windowsPilotVerifier,
        $Trust.localDataCertification,
        $Trust.stablePrivatePilotKeys.server,
        $Trust.stablePrivatePilotKeys.freshInstallDevice,
        $Trust.stablePrivatePilotKeys.onlineUpgradeDevice,
        $Trust.stablePrivatePilotKeys.unauthorizedControl,
        $InstallerSigningTrust)
    $ids = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
    $points = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
    foreach ($key in $keys) {
        if (-not $ids.Add([string]$key.keyId)) {
            throw 'Pilot and Installer response key IDs are not purpose-separated.'
        }
        $pointIdentity =
            ProductionReleaseState\Get-ProductionReleaseP256PublicKeyIdentity `
                -Trust $key `
                -Label "Purpose-separated key '$($key.keyId)'"
        if (-not $points.Add($pointIdentity)) {
            throw 'Pilot and Installer response P-256 public points are not purpose-separated.'
        }
    }
}

function Assert-R8WindowsVerificationReportAuthentication {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][psobject]$Report,
        [Parameter(Mandatory = $true)][psobject]$Trust
    )

    $authentication = $Report.authentication
    if ($null -eq $authentication -or
        [string]$authentication.algorithm -cne 'ES256' -or
        [string]$authentication.purpose -cne
            'enterprise-windows-pilot-verifier-report' -or
        [string]$authentication.keyId -cne
            [string]$Trust.windowsPilotVerifier.keyId -or
        [string]$authentication.encoding -cne 'IEEE-P1363' -or
        [string]$authentication.canonicalization -cne
            'ENSOU-R8-CANONICAL-JSON-V1' -or
        [bool]$authentication.lowS -ne $true) {
        throw 'Windows Pilot verifier report authentication metadata is invalid.'
    }
    Assert-R8Es256Signature `
        -Payload (Get-EnterpriseWindowsPilotVerificationReportPayload `
            -Report $Report) `
        -SignatureValue ([string]$authentication.value) `
        -Key $Trust.windowsPilotVerifier `
        -ExpectedKeyId ([string]$authentication.keyId) `
        -ExpectedPurpose 'enterprise-windows-pilot-verifier-report' `
        -Label 'Windows Pilot verifier report authentication'
}

function ConvertFrom-R8FractionalUtc {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $parsed = [DateTimeOffset]::MinValue
    $styles = [Globalization.DateTimeStyles]::AssumeUniversal -bor
        [Globalization.DateTimeStyles]::AdjustToUniversal
    $parsedZulu = [DateTimeOffset]::TryParseExact(
        $Value,
        "yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'",
        [Globalization.CultureInfo]::InvariantCulture,
        $styles,
        [ref]$parsed)
    $parsedRoundTrip = $false
    if (-not $parsedZulu) {
        $parsedRoundTrip = [DateTimeOffset]::TryParseExact(
            $Value,
            'O',
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::None,
            [ref]$parsed)
    }
    if ((-not $parsedZulu -and -not $parsedRoundTrip) -or
        $parsed.Offset -ne [TimeSpan]::Zero) {
        throw "$Label is not canonical seven-digit UTC."
    }
    return $parsed.ToUniversalTime()
}

function ConvertFrom-R8WholeSecondUtc {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$Label
    )

    return ProductionReleaseState\ConvertFrom-ProductionUtc `
        -Value $Value `
        -Label $Label
}

function Get-R8Descriptor {
    param([Parameter(Mandatory = $true)]$InputObject)

    if ($null -ne $InputObject.PSObject.Properties['Lease']) {
        return $InputObject.Lease
    }
    return $InputObject
}

function Assert-R8FileReference {
    param(
        [Parameter(Mandatory = $true)][psobject]$Reference,
        [Parameter(Mandatory = $true)]$InputObject,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $descriptor = Get-R8Descriptor -InputObject $InputObject
    $referencePath = [IO.Path]::GetFullPath([string]$Reference.path)
    if (-not $referencePath.Equals(
            [string]$descriptor.Path,
            [StringComparison]::OrdinalIgnoreCase) -or
        [int64]$Reference.sizeBytes -ne [int64]$descriptor.SizeBytes -or
        [string]$Reference.sha256 -cne [string]$descriptor.Sha256) {
        throw "$Label does not bind the exact locked file bytes."
    }
}

function Assert-R8InstallerIdentity {
    param(
        [Parameter(Mandatory = $true)][psobject]$Actual,
        [Parameter(Mandatory = $true)][psobject]$Expected,
        [Parameter(Mandatory = $true)][string]$Label
    )

    foreach ($member in @(
            'fileName',
            'relativePath',
            'sizeBytes',
            'sha256',
            'peContentSha256')) {
        Assert-R8Equal $Actual.$member $Expected.$member "$Label $member"
    }
}

function Assert-R8ReleaseIdentity {
    param(
        [Parameter(Mandatory = $true)][psobject]$Actual,
        [Parameter(Mandatory = $true)][psobject]$Expected,
        [Parameter(Mandatory = $true)][string]$Label
    )

    foreach ($member in @(
            'releaseSetId',
            'generation',
            'sequence',
            'manifestSha256',
            'runtimeEntryPointSha256')) {
        Assert-R8Equal $Actual.$member $Expected.$member "$Label $member"
    }
}

function Get-R8RootProjectionSha256 {
    param(
        [Parameter(Mandatory = $true)][psobject]$Value,
        [Parameter(Mandatory = $true)][string[]]$ExcludedMembers
    )

    $projection = [ordered]@{}
    foreach ($property in $Value.PSObject.Properties) {
        if ($ExcludedMembers -cnotcontains [string]$property.Name) {
            $projection[[string]$property.Name] = $property.Value
        }
    }
    return Get-R8Sha256Bytes `
        -Bytes (ConvertTo-R8CanonicalJsonBytes -Value $projection)
}

function Get-R8ObjectSetSha256 {
    param([Parameter(Mandatory = $true)][object[]]$Objects)

    $roles = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
    $normalized = [Collections.Generic.List[object]]::new()
    foreach ($object in @($Objects | Sort-Object { [string]$_.role })) {
        if (-not $roles.Add([string]$object.role)) {
            throw "Stable target object role '$($object.role)' is duplicated."
        }
        $normalized.Add([ordered]@{
            role = [string]$object.role
            fileName = [string]$object.fileName
            uri = [string]$object.uri
            objectVersionId = [string]$object.objectVersionId
            etag = [string]$object.etag
            sizeBytes = [int64]$object.sizeBytes
            sha256 = [string]$object.sha256
        })
    }
    return Get-R8Sha256Bytes `
        -Bytes (ConvertTo-R8CanonicalJsonBytes -Value @($normalized))
}

function Assert-R8ObjectSetEqual {
    param(
        [Parameter(Mandatory = $true)][object[]]$Actual,
        [Parameter(Mandatory = $true)][object[]]$Expected,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ($Actual.Count -ne $Expected.Count) {
        throw "$Label has the wrong object count."
    }
    foreach ($expectedObject in $Expected) {
        $matches = @($Actual | Where-Object {
            [string]$_.role -ceq [string]$expectedObject.role
        })
        if ($matches.Count -ne 1) {
            throw "$Label does not contain one exact '$($expectedObject.role)' object."
        }
        $members = [Collections.Generic.List[string]]::new()
        foreach ($member in @('role', 'fileName', 'sizeBytes', 'sha256')) {
            $members.Add($member)
        }
        foreach ($optionalMember in @('uri', 'objectVersionId', 'etag')) {
            if ($null -ne
                $expectedObject.PSObject.Properties[$optionalMember]) {
                $members.Add($optionalMember)
            }
        }
        foreach ($member in $members) {
            Assert-R8Equal `
                $matches[0].$member `
                $expectedObject.$member `
                "$Label $($expectedObject.role) $member"
        }
    }
}

function Assert-R8ReadinessSchemaContract {
    [CmdletBinding()]
    param(
        [ValidateSet(1, 2)]
        [int]$WindowsPilotReadinessSchemaVersion = 1,
        [Parameter(Mandatory = $true)][psobject]$Config,
        [Parameter(Mandatory = $true)][psobject]$StoredReport,
        [Parameter(Mandatory = $true)][psobject]$ReplayedReport
    )

    foreach ($contract in @(
            [pscustomobject]@{ Value = $Config; Label = 'config' },
            [pscustomobject]@{ Value = $StoredReport; Label = 'stored report' },
            [pscustomobject]@{ Value = $ReplayedReport; Label = 'replayed report' })) {
        if (-not (Test-R8ExactMemberPresent `
                    -Object $contract.Value -Name 'schemaVersion') -or
            [string](Get-R8MemberValue `
                -Object $contract.Value -Name 'schemaVersion' `
                -Label "Windows Pilot readiness $($contract.Label)") -cne
                [string]$WindowsPilotReadinessSchemaVersion) {
            throw "R8_READINESS_SCHEMA_VERSION_MISMATCH: Windows Pilot readiness $($contract.Label) is not schema v$WindowsPilotReadinessSchemaVersion."
        }
    }

    $reports = @($StoredReport, $ReplayedReport)
    foreach ($report in $reports) {
        if (-not (Test-R8ExactMemberPresent -Object $report -Name 'reportType') -or
            [string](Get-R8MemberValue -Object $report -Name 'reportType' `
                -Label 'Windows Pilot readiness report') -cne
                'ensou-dsh-enterprise-pilot-readiness' -or
            -not (Test-R8ExactMemberPresent -Object $report -Name 'updateContractId') -or
            [string](Get-R8MemberValue -Object $report -Name 'updateContractId' `
                -Label 'Windows Pilot readiness report') -cne
                'release-set-v2-startup-check-atomic-health-rollback-offline-7d-plugin-policy-v1') {
            throw 'R8_READINESS_REPORT_CONTRACT_INVALID: Windows Pilot readiness report identity is invalid.'
        }
    }

    $hasLegacyTrust = Test-R8ExactMemberPresent `
        -Object $Config -Name 'launcherTrust'
    $hasDirectTrust = Test-R8ExactMemberPresent `
        -Object $Config -Name 'launcherDirectLocalTrust'
    if ($WindowsPilotReadinessSchemaVersion -eq 1) {
        if (-not $hasLegacyTrust -or $hasDirectTrust) {
            throw 'R8_READINESS_SCHEMA_MIXED: Readiness v1 requires only launcherTrust.'
        }
        $legacyTrust = Get-R8MemberValue `
            -Object $Config -Name 'launcherTrust' -Label 'Readiness v1 config'
        if ($null -eq $legacyTrust -or
            -not (Test-R8ExactMemberPresent `
                -Object $legacyTrust -Name 'gatewayOrigin') -or
            (Test-R8ExactMemberPresent `
                -Object $legacyTrust -Name 'runtimeProfile') -or
            (Test-R8ExactMemberPresent `
                -Object $legacyTrust -Name 'apiProvider')) {
            throw 'R8_READINESS_SCHEMA_MIXED: Readiness v1 trust contains direct-local members or lacks gatewayOrigin.'
        }
        foreach ($report in $reports) {
            foreach ($directMember in @(
                    'productionTrustContractId',
                    'runtimeProfile',
                    'apiProvider')) {
                if (Test-R8ExactMemberPresent `
                        -Object $report -Name $directMember) {
                    throw "R8_READINESS_SCHEMA_MIXED: Readiness v1 report contains direct-local member '$directMember'."
                }
            }
        }
        return
    }

    if ($hasLegacyTrust -or -not $hasDirectTrust) {
        throw 'R8_READINESS_SCHEMA_MIXED: Readiness v2 requires only launcherDirectLocalTrust.'
    }
    $directTrust = Get-R8MemberValue `
        -Object $Config -Name 'launcherDirectLocalTrust' `
        -Label 'Readiness v2 config'
    if ($null -eq $directTrust -or
        (Test-R8ExactMemberPresent `
            -Object $directTrust -Name 'gatewayOrigin') -or
        -not (Test-R8ExactMemberPresent `
            -Object $directTrust -Name 'runtimeProfile') -or
        -not (Test-R8ExactMemberPresent `
            -Object $directTrust -Name 'apiProvider') -or
        [string](Get-R8MemberValue `
            -Object $directTrust -Name 'runtimeProfile' `
            -Label 'Readiness v2 direct-local trust') -cne
            'enterprise-direct-local' -or
        [string](Get-R8MemberValue `
            -Object $directTrust -Name 'apiProvider' `
            -Label 'Readiness v2 direct-local trust') -cne 'deepseek') {
        throw 'R8_READINESS_DIRECT_LOCAL_PROFILE_INVALID: Readiness v2 direct-local trust is invalid.'
    }
    foreach ($report in $reports) {
        if (-not (Test-R8ExactMemberPresent `
                -Object $report -Name 'productionTrustContractId') -or
            -not (Test-R8ExactMemberPresent `
                -Object $report -Name 'runtimeProfile') -or
            -not (Test-R8ExactMemberPresent `
                -Object $report -Name 'apiProvider') -or
            [string](Get-R8MemberValue `
                -Object $report -Name 'productionTrustContractId' `
                -Label 'Readiness v2 report') -cne
                'ensou-dsh-enterprise-production-trust-v2' -or
            [string](Get-R8MemberValue `
                -Object $report -Name 'runtimeProfile' `
                -Label 'Readiness v2 report') -cne
                'enterprise-direct-local' -or
            [string](Get-R8MemberValue `
                -Object $report -Name 'apiProvider' `
                -Label 'Readiness v2 report') -cne 'deepseek') {
            throw 'R8_READINESS_DIRECT_LOCAL_PROFILE_INVALID: Readiness v2 report identity is invalid.'
        }
    }
}

function Assert-R8ReadinessReport {
    param(
        [Parameter(Mandatory = $true)][psobject]$Report,
        [Parameter(Mandatory = $true)][psobject]$Config,
        [Parameter(Mandatory = $true)][psobject]$LocalReceipt,
        [Parameter(Mandatory = $true)][string]$LocalReceiptSha256,
        [Parameter(Mandatory = $true)][string]$LocalKeyId,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ([string]$Report.decision -cne 'ADMIT' -or
        [string]$Report.environment -cne 'production' -or
        [string]$Report.channel -cne 'pilot' -or
        @($Report.checks).Count -lt 1 -or
        @($Report.checks | Where-Object {
            [string]$_.status -cne 'PASS'
        }).Count -ne 0 -or
        $null -ne $Report.failureCode -or
        $null -ne $Report.failureMessage) {
        throw "$Label is not one admitted production Pilot readiness report."
    }
    Assert-R8Equal $Report.releaseSetId $Config.releaseSetId "$Label release set"
    Assert-R8Equal $Report.generation $Config.generation "$Label generation"
    Assert-R8Equal $Report.sequence $Config.sequence "$Label sequence"
    Assert-R8Equal `
        $Report.localDataCertificationId `
        $LocalReceipt.certificationId `
        "$Label local-data certification ID"
    Assert-R8Equal `
        $Report.localDataCertificationKeyId `
        $LocalKeyId `
        "$Label local-data certification key"
    Assert-R8Equal `
        $Report.localDataCertificationReceiptSha256 `
        $LocalReceiptSha256 `
        "$Label local-data receipt SHA-256"
    $expectedExpiry = [DateTimeOffset]::FromUnixTimeSeconds(
        [int64]$LocalReceipt.expiresAtUnixSeconds).ToString('O')
    Assert-R8Equal `
        $Report.localDataCertificationExpiresAtUtc `
        $expectedExpiry `
        "$Label local-data expiry"
}

function Assert-R8WindowsEvidence {
    param(
        [Parameter(Mandatory = $true)][psobject]$Envelope,
        [Parameter(Mandatory = $true)]$EnvelopeInput,
        [Parameter(Mandatory = $true)][psobject]$Body,
        [Parameter(Mandatory = $true)]$BodyInput,
        [Parameter(Mandatory = $true)][psobject]$VerificationReport,
        [Parameter(Mandatory = $true)]$VerificationReportInput,
        [Parameter(Mandatory = $true)][psobject]$ReadinessConfig,
        [Parameter(Mandatory = $true)]$ReadinessConfigInput,
        [Parameter(Mandatory = $true)][psobject]$StoredReadinessReport,
        [Parameter(Mandatory = $true)]$StoredReadinessInput,
        [Parameter(Mandatory = $true)][psobject]$ReplayedReadinessReport,
        [Parameter(Mandatory = $true)]$ReplayedReadinessInput,
        [Parameter(Mandatory = $true)][psobject]$LocalReceipt,
        [Parameter(Mandatory = $true)]$LocalReceiptInput,
        [Parameter(Mandatory = $true)]$InstallerInput,
        [Parameter(Mandatory = $true)][psobject]$Trust,
        [Parameter(Mandatory = $true)][psobject]$GateContract,
        [Parameter(Mandatory = $true)][psobject]$Authority,
        [Parameter(Mandatory = $true)][DateTimeOffset]$ValidationTimeUtc,
        [ValidateSet(1, 2)]
        [int]$WindowsPilotReadinessSchemaVersion = 1
    )

    $bodyDescriptor = Get-R8Descriptor -InputObject $BodyInput
    $envelopeDescriptor = Get-R8Descriptor -InputObject $EnvelopeInput
    $reportDescriptor = Get-R8Descriptor -InputObject $VerificationReportInput
    $replayedDescriptor = Get-R8Descriptor `
        -InputObject $ReplayedReadinessInput
    $localDescriptor = Get-R8Descriptor -InputObject $LocalReceiptInput
    Assert-R8WindowsVerificationReportAuthentication `
        -Report $VerificationReport `
        -Trust $Trust
    if ([int64]$Envelope.body.sizeBytes -ne [int64]$bodyDescriptor.SizeBytes -or
        [string]$Envelope.body.sha256 -cne [string]$bodyDescriptor.Sha256 -or
        [string]$Envelope.attestation.algorithm -cne 'ES256' -or
        [string]$Envelope.attestation.keyId -cne
            [string]$Trust.windowsPilotEvidence.keyId) {
        throw 'Windows Pilot envelope does not bind the exact body and trust key.'
    }
    Assert-R8Es256Signature `
        -Payload (Get-EnterpriseWindowsPilotAttestationPayload `
            -Envelope $Envelope) `
        -SignatureValue ([string]$Envelope.attestation.value) `
        -Key $Trust.windowsPilotEvidence `
        -ExpectedKeyId ([string]$Envelope.attestation.keyId) `
        -ExpectedPurpose 'enterprise-windows-pilot-evidence-attestation' `
        -Label 'Windows Pilot evidence attestation'

    if ([string]$Body.pilotDecision -cne 'ADMIT' -or
        [string]$Body.environment -cne 'production' -or
        [string]$Body.channel -cne 'pilot' -or
        [string]$Body.runtimeIdentifier -cne 'win-x64' -or
        [string]$Body.layoutProfile -cne 'enterprise') {
        throw 'Windows Pilot evidence is synthetic, developmental, or outside the Enterprise win-x64 profile.'
    }

    if ([string]$VerificationReport.decision -cne 'VERIFIED' -or
        [bool]$VerificationReport.standaloneAdmissionEvidence -ne $false -or
        [string]$VerificationReport.evidenceEnvelopeSha256 -cne
            [string]$envelopeDescriptor.Sha256 -or
        [string]$VerificationReport.evidenceBodySha256 -cne
            [string]$bodyDescriptor.Sha256 -or
        [string]$VerificationReport.pilotEvidenceKeyId -cne
            [string]$Trust.windowsPilotEvidence.keyId -or
        [string]$VerificationReport.readinessReplayReportSha256 -cne
            [string]$replayedDescriptor.Sha256 -or
        @($VerificationReport.checks | Where-Object {
            [string]$_.status -cne 'PASS'
        }).Count -ne 0 -or
        $null -ne $VerificationReport.failureCode -or
        $null -ne $VerificationReport.failureMessage) {
        throw 'Windows Pilot production verifier report is rejected or byte-drifted.'
    }
    $requiredVerifierChecks = @(
        'schema-set',
        'output-parent-lock',
        'strict-attested-body',
        'release-chain',
        'gate-time-and-tuples',
        'local-data-and-device-lanes',
        'readiness-schema-and-binding',
        'publisher-authenticode-and-compiled-trust',
        'signed-executable-inventory',
        'fresh-readiness-replay',
        'independent-attestation',
        'five-release-manifest-signatures',
        'live-pilot-head-signature')
    $reportedChecks = @($VerificationReport.checks | ForEach-Object {
        [string]$_.id
    })
    if ($reportedChecks.Count -ne $requiredVerifierChecks.Count -or
        @($reportedChecks | Select-Object -Unique).Count -ne
            $reportedChecks.Count) {
        throw 'Windows Pilot verifier report does not have the exact check set.'
    }
    foreach ($checkId in $requiredVerifierChecks) {
        if ($reportedChecks -cnotcontains $checkId) {
            throw "Windows Pilot verifier report is missing '$checkId'."
        }
    }
    Assert-R8Equal `
        $VerificationReport.testRunId `
        $Body.testRunId `
        'Windows Pilot verifier test run'
    Assert-R8Equal `
        $VerificationReport.customerAudienceId `
        $Body.customerAudienceId `
        'Windows Pilot verifier audience'

    Assert-R8FileReference `
        -Reference $Body.readiness.config `
        -InputObject $ReadinessConfigInput `
        -Label 'Windows Pilot readiness config'
    Assert-R8FileReference `
        -Reference $Body.readiness.report `
        -InputObject $StoredReadinessInput `
        -Label 'Windows Pilot stored readiness report'
    Assert-R8ReadinessSchemaContract `
        -WindowsPilotReadinessSchemaVersion `
            $WindowsPilotReadinessSchemaVersion `
        -Config $ReadinessConfig `
        -StoredReport $StoredReadinessReport `
        -ReplayedReport $ReplayedReadinessReport
    $installerEvidence = @($Body.signedExecutables | Where-Object {
        [string]$_.role -ceq 'installer'
    })
    if ($installerEvidence.Count -ne 1) {
        throw 'Windows Pilot body must contain one exact Installer executable.'
    }
    Assert-R8FileReference `
        -Reference $installerEvidence[0].file `
        -InputObject $InstallerInput `
        -Label 'Windows Pilot signed Installer'
    $publisherEvidence = @($Body.signedExecutables | Where-Object {
        [string]$_.role -ceq 'release-publisher'
    })
    if ($publisherEvidence.Count -ne 1 -or
        [string]$publisherEvidence[0].file.sha256 -cne
            [string]$VerificationReport.publisherExecutableSha256) {
        throw 'Windows Pilot verifier does not bind the observed Publisher executable.'
    }

    $localConfigReceiptPath =
        [string]$ReadinessConfig.localDataCompatibilityEvidence.certification.receiptPath
    $localConfigPath = [IO.Path]::GetFullPath($localConfigReceiptPath)
    if (-not $localConfigPath.Equals(
            [string]$localDescriptor.Path,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Readiness config does not name the exact local-data certification receipt.'
    }
    Assert-R8Equal `
        $ReadinessConfig.localDataCompatibilityEvidence.certification.receiptSha256 `
        $localDescriptor.Sha256 `
        'Readiness local-data certification receipt SHA-256'
    Assert-R8Equal `
        $ReadinessConfig.localDataCompatibilityEvidence.certification.certificationAudienceId `
        $LocalReceipt.certificationAudienceId `
        'Readiness local-data certification audience'
    $configInstallerPath = [IO.Path]::GetFullPath(
        [string]$ReadinessConfig.installerExecutablePath)
    $installerDescriptor = Get-R8Descriptor -InputObject $InstallerInput
    if (-not $configInstallerPath.Equals(
            [string]$installerDescriptor.Path,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Readiness config does not name the exact locked r7 Installer.'
    }

    Assert-R8ReadinessReport `
        -Report $StoredReadinessReport `
        -Config $ReadinessConfig `
        -LocalReceipt $LocalReceipt `
        -LocalReceiptSha256 ([string]$localDescriptor.Sha256) `
        -LocalKeyId ([string]$Trust.localDataCertification.keyId) `
        -Label 'Stored readiness report'
    Assert-R8ReadinessReport `
        -Report $ReplayedReadinessReport `
        -Config $ReadinessConfig `
        -LocalReceipt $LocalReceipt `
        -LocalReceiptSha256 ([string]$localDescriptor.Sha256) `
        -LocalKeyId ([string]$Trust.localDataCertification.keyId) `
        -Label 'Replayed readiness report'
    $storedProjection = Get-R8RootProjectionSha256 `
        -Value $StoredReadinessReport `
        -ExcludedMembers @('generatedAtUtc')
    $replayedProjection = Get-R8RootProjectionSha256 `
        -Value $ReplayedReadinessReport `
        -ExcludedMembers @('generatedAtUtc')
    Assert-R8Equal `
        $replayedProjection `
        $storedProjection `
        'Stored/replayed readiness semantic projection'

    $bodyStarted = ConvertFrom-R8FractionalUtc `
        -Value ([string]$Body.startedAtUtc) `
        -Label 'Windows Pilot start'
    $bodyCompleted = ConvertFrom-R8FractionalUtc `
        -Value ([string]$Body.completedAtUtc) `
        -Label 'Windows Pilot completion'
    $storedGenerated = ConvertFrom-R8FractionalUtc `
        -Value ([string]$StoredReadinessReport.generatedAtUtc) `
        -Label 'Stored readiness generation'
    $replayedGenerated = ConvertFrom-R8FractionalUtc `
        -Value ([string]$ReplayedReadinessReport.generatedAtUtc) `
        -Label 'Replayed readiness generation'
    $verifierGenerated = ConvertFrom-R8FractionalUtc `
        -Value ([string]$VerificationReport.generatedAtUtc) `
        -Label 'Windows Pilot verifier generation'
    $maximumAge = [TimeSpan]::FromHours(
        [int]$Trust.maximumEvidenceAgeHours)
    if ($bodyStarted -ge $bodyCompleted -or
        $bodyCompleted -gt $ValidationTimeUtc.AddMinutes(5) -or
        $bodyCompleted -lt $ValidationTimeUtc.Subtract($maximumAge) -or
        $storedGenerated -gt $replayedGenerated -or
        $replayedGenerated -gt $verifierGenerated -or
        $verifierGenerated -gt $ValidationTimeUtc.AddMinutes(5)) {
        throw 'Windows Pilot/readiness/verifier evidence time order is stale or invalid.'
    }

    $gates = @($Body.gates)
    $expectedGates = @($GateContract.gates)
    if ($gates.Count -ne 21 -or $expectedGates.Count -ne 21) {
        throw 'Windows Pilot body and pinned gate contract must contain 21 gates.'
    }
    $previousGateEnd = $bodyStarted
    for ($index = 0; $index -lt 21; $index++) {
        $gate = $gates[$index]
        $expected = $expectedGates[$index]
        foreach ($member in @(
                'sequenceNumber', 'gate', 'deviceLane', 'networkMode',
                'resultCode')) {
            Assert-R8Equal `
                $gate.$member `
                $expected.$member `
                "Windows Pilot gate $($index + 1) $member"
        }
        Assert-R8Equal `
            $gate.observedProcess.role `
            $expected.role `
            "Windows Pilot gate $($index + 1) process role"
        Assert-R8Equal `
            $gate.observedProcess.state `
            $expected.state `
            "Windows Pilot gate $($index + 1) process state"
        Assert-R8Equal $gate.testRunId $Body.testRunId 'Windows Pilot gate test run'
        Assert-R8Equal `
            $gate.customerAudienceId `
            $Body.customerAudienceId `
            'Windows Pilot gate audience'
        $gateStart = ConvertFrom-R8FractionalUtc `
            -Value ([string]$gate.startedAtUtc) `
            -Label "Windows Pilot gate $($index + 1) start"
        $gateEnd = ConvertFrom-R8FractionalUtc `
            -Value ([string]$gate.completedAtUtc) `
            -Label "Windows Pilot gate $($index + 1) completion"
        if ($gateStart -lt $previousGateEnd -or
            $gateStart -ge $gateEnd -or
            $gateEnd -gt $bodyCompleted) {
            throw "Windows Pilot gate $($index + 1) has invalid time ordering."
        }
        if ([string]$gate.gate -ceq 'no-visible-console-window' -and
            $gateEnd - $gateStart -lt [TimeSpan]::FromMinutes(15)) {
            throw 'No-visible-console-window gate must cover at least fifteen minutes.'
        }
        $previousGateEnd = $gateEnd
        $expectedActive = $Body.releaseChain[[int]$expected.activeReleaseIndex]
        Assert-R8ReleaseIdentity `
            -Actual $gate.releaseTuple.active `
            -Expected $expectedActive `
            -Label "Windows Pilot gate $($index + 1) active release"
        foreach ($tuple in @(
                [pscustomobject]@{
                    Name = 'rollbackTarget'
                    Index = $expected.rollbackReleaseIndex
                },
                [pscustomobject]@{
                    Name = 'attempted'
                    Index = $expected.attemptedReleaseIndex
                })) {
            if ($null -eq $tuple.Index) {
                if ($null -ne $gate.releaseTuple.($tuple.Name)) {
                    throw "Windows Pilot gate $($index + 1) has an unexpected $($tuple.Name)."
                }
            }
            else {
                Assert-R8ReleaseIdentity `
                    -Actual $gate.releaseTuple.($tuple.Name) `
                    -Expected $Body.releaseChain[[int]$tuple.Index] `
                    -Label "Windows Pilot gate $($index + 1) $($tuple.Name)"
            }
        }
    }
    if ([string]$Body.localDataWitness.historyTreeBeforeSha256 -cne
            [string]$Body.localDataWitness.historyTreeAfterSha256 -or
        [string]$Body.localDataWitness.workspaceTreeBeforeSha256 -cne
            [string]$Body.localDataWitness.workspaceTreeAfterSha256) {
        throw 'Windows Pilot local history or workspace witness changed.'
    }

    $target = $Body.readiness.target
    Assert-R8Equal $target.releaseSetId $Authority.Plan.releaseSetId 'Windows target release set'
    Assert-R8Equal $target.manifestSha256 $Authority.R5Data.manifestSha256 'Windows target manifest'
    Assert-R8Equal `
        $VerificationReport.targetReleaseSetId `
        $target.releaseSetId `
        'Windows verifier target release set'
    Assert-R8Equal `
        $VerificationReport.targetGeneration `
        $target.generation `
        'Windows verifier target generation'
    Assert-R8Equal `
        $VerificationReport.targetSequence `
        $target.sequence `
        'Windows verifier target sequence'
    Assert-R8Equal `
        $VerificationReport.livePilotManifestSha256 `
        $target.manifestSha256 `
        'Windows verifier live manifest'
    Assert-R8ReleaseIdentity `
        -Actual $Body.releaseChain[4] `
        -Expected $target `
        -Label 'Windows recovery target/readiness target'
    $verifiedManifestSet = @(
        $VerificationReport.verifiedReleaseManifestSha256 | Sort-Object)
    $releaseChainManifestSet = @(
        $Body.releaseChain.manifestSha256 | Sort-Object)
    if ($verifiedManifestSet.Count -ne 5 -or
        @($verifiedManifestSet | Select-Object -Unique).Count -ne 5) {
        throw 'Windows verifier must bind five distinct signed manifests.'
    }
    for ($index = 0; $index -lt 5; $index++) {
        Assert-R8Equal `
            $verifiedManifestSet[$index] `
            $releaseChainManifestSet[$index] `
            "Windows signed manifest set index $index"
    }

    return [pscustomobject]@{
        BodyCompletedAtUtc = $bodyCompleted
        Target = $target
        TestRunId = [string]$Body.testRunId
        CustomerAudienceId = [string]$Body.customerAudienceId
        EnvelopeSha256 = [string]$envelopeDescriptor.Sha256
        BodySha256 = [string]$bodyDescriptor.Sha256
        VerificationReportSha256 = [string]$reportDescriptor.Sha256
    }
}

function Assert-R8LocalDataEvidence {
    param(
        [Parameter(Mandatory = $true)][psobject]$Receipt,
        [Parameter(Mandatory = $true)]$ReceiptInput,
        [Parameter(Mandatory = $true)][psobject]$ReadinessConfig,
        [Parameter(Mandatory = $true)][psobject]$Trust,
        [Parameter(Mandatory = $true)][psobject]$Authority,
        [Parameter(Mandatory = $true)][DateTimeOffset]$ValidationTimeUtc
    )

    if ([string]$Receipt.signature.algorithm -cne 'ES256' -or
        [string]$Receipt.signature.keyId -cne
            [string]$Trust.localDataCertification.keyId) {
        throw 'Local-data certification does not use the trusted ES256 key.'
    }
    Assert-R8Es256Signature `
        -Payload (Get-EnterpriseLocalDataCertificationPayload `
            -Receipt $Receipt) `
        -SignatureValue ([string]$Receipt.signature.value) `
        -Key $Trust.localDataCertification `
        -ExpectedKeyId ([string]$Receipt.signature.keyId) `
        -ExpectedPurpose 'enterprise-local-data-certification' `
        -Label 'Local-data certification'

    $configEvidence = $ReadinessConfig.localDataCompatibilityEvidence
    Assert-R8Equal `
        $Receipt.certificationAudienceId `
        $configEvidence.certification.certificationAudienceId `
        'Local-data certification audience'
    Assert-R8Equal `
        $Receipt.fromUpstreamTag `
        $configEvidence.fromUpstreamTag `
        'Local-data source upstream tag'
    Assert-R8Equal `
        $Receipt.toUpstreamTag `
        $configEvidence.toUpstreamTag `
        'Local-data target upstream tag'
    if ([string]$Receipt.fromUpstreamTag -ceq
        [string]$Receipt.toUpstreamTag) {
        throw 'Local-data certification does not describe a real runtime transition.'
    }
    Assert-R8Equal `
        $Receipt.sourceRuntimeZipSha256 `
        $configEvidence.sourceRuntimeArchiveSha256 `
        'Local-data source runtime ZIP'
    Assert-R8Equal `
        $Receipt.targetRuntimeZipSha256 `
        $configEvidence.targetRuntimeArchiveSha256 `
        'Local-data target runtime ZIP'
    Assert-R8Equal `
        $Receipt.targetRuntimeZipSha256 `
        $Authority.R7Data.r5RuntimeSha256 `
        'Local-data/r7 target runtime ZIP'
    Assert-R8Equal `
        $Receipt.evidenceReportSha256 `
        $configEvidence.reportSha256 `
        'Local-data evidence report'

    $issuedAt = [DateTimeOffset]::FromUnixTimeSeconds(
        [int64]$Receipt.issuedAtUnixSeconds)
    $expiresAt = [DateTimeOffset]::FromUnixTimeSeconds(
        [int64]$Receipt.expiresAtUnixSeconds)
    $maximumAge = [TimeSpan]::FromHours(
        [int]$Trust.maximumEvidenceAgeHours)
    $minimumRemaining = [TimeSpan]::FromMinutes(
        [int]$Trust.minimumRemainingValidityMinutes)
    if ($issuedAt -gt $ValidationTimeUtc.AddMinutes(5) -or
        $issuedAt -lt $ValidationTimeUtc.Subtract($maximumAge) -or
        $expiresAt -le $issuedAt -or
        $expiresAt -lt $ValidationTimeUtc.Add($minimumRemaining) -or
        $expiresAt - $issuedAt -gt [TimeSpan]::FromHours(72)) {
        throw 'Local-data certification is stale, future-dated, expired, or not short-lived.'
    }
    $descriptor = Get-R8Descriptor -InputObject $ReceiptInput
    return [pscustomobject]@{
        CertificationId = [string]$Receipt.certificationId
        CertificationAudienceId = [string]$Receipt.certificationAudienceId
        KeyId = [string]$Receipt.signature.keyId
        EvidenceReportSha256 = [string]$Receipt.evidenceReportSha256
        TargetRuntimeSha256 = [string]$Receipt.targetRuntimeZipSha256
        ExpiresAtUtc = $expiresAt
        ReceiptSha256 = [string]$descriptor.Sha256
    }
}

function Assert-R8StableAttestation {
    param(
        [Parameter(Mandatory = $true)][psobject]$Attestation,
        [Parameter(Mandatory = $true)][byte[]]$Payload,
        [Parameter(Mandatory = $true)][psobject]$Key,
        [Parameter(Mandatory = $true)][string]$Purpose,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ([string]$Attestation.verificationStatus -cne 'VERIFIED' -or
        [string]$Attestation.algorithm -cne 'ES256' -or
        [string]$Attestation.encoding -cne 'IEEE-P1363' -or
        [string]$Attestation.canonicalization -cne
            'ENSOU-R8-CANONICAL-JSON-V1' -or
        [bool]$Attestation.lowS -ne $true -or
        [string]$Attestation.purpose -cne $Purpose -or
        [string]$Attestation.keyId -cne [string]$Key.keyId -or
        [string]$Attestation.payloadSha256 -cne
            (Get-R8Sha256Bytes -Bytes $Payload)) {
        throw "$Label does not bind the exact canonical payload and trust purpose."
    }
    Assert-R8Es256Signature `
        -Payload $Payload `
        -SignatureValue ([string]$Attestation.signature) `
        -Key $Key `
        -ExpectedKeyId ([string]$Attestation.keyId) `
        -ExpectedPurpose $Purpose `
        -Label $Label
}

function Assert-R8StableDevice {
    param(
        [Parameter(Mandatory = $true)][psobject]$Device,
        [Parameter(Mandatory = $true)][string]$ExpectedLane,
        [Parameter(Mandatory = $true)][psobject]$Observation,
        [Parameter(Mandatory = $true)][object[]]$TargetObjects,
        [Parameter(Mandatory = $true)][psobject]$InstallerAuthority,
        [Parameter(Mandatory = $true)][string]$Label
    )

    Assert-R8Equal $Device.lane $ExpectedLane "$Label lane"
    Assert-R8Equal `
        $Device.targetReleaseSetId `
        $Observation.targetRelease.releaseSetId `
        "$Label target release"
    Assert-R8Equal `
        $Device.canonicalManifestUri `
        $Observation.canonicalStableManifestUri `
        "$Label canonical manifest URI"
    Assert-R8ObjectSetEqual `
        -Actual @($Device.observedObjects) `
        -Expected $TargetObjects `
        -Label "$Label observed object set"
    Assert-R8Equal `
        $Device.bootstrapperHealth.targetReleaseSetId `
        $Observation.targetRelease.releaseSetId `
        "$Label bootstrapper target"
    Assert-R8Equal `
        $Device.updateReceipt.targetReleaseSetId `
        $Observation.targetRelease.releaseSetId `
        "$Label update receipt target"
    if (-not [bool]$Device.workspacePreserved -or
        -not [bool]$Device.historyPreserved) {
        throw "$Label did not preserve local workspace and history."
    }

    if ($ExpectedLane -ceq 'fresh-install') {
        if (-not [bool]$Device.previousInstallAbsent -or
            $null -ne $Device.sourceReleaseSetId -or
            $null -ne $Device.sourceCapabilityProbeSha256 -or
            $null -eq $Device.installerUsed -or
            $null -ne $Device.updateReceipt.sourceReleaseSetId) {
            throw 'Fresh-install lane is not one clean installation.'
        }
        Assert-R8InstallerIdentity `
            -Actual $Device.installerUsed `
            -Expected $InstallerAuthority `
            -Label 'Fresh-install exact r7 Installer'
    }
    else {
        if ([bool]$Device.previousInstallAbsent -or
            $null -ne $Device.installerUsed -or
            [string]$Device.sourceReleaseSetId -cne
                [string]$Observation.sourceBaseline.releaseSetId -or
            [string]$Device.updateReceipt.sourceReleaseSetId -cne
                [string]$Observation.sourceBaseline.releaseSetId -or
            [string]$Device.sourceCapabilityProbeSha256 -cne
                [string]$Observation.sourceBaseline.capabilityProbe.stdoutSha256) {
            throw 'Online-upgrade lane is not bound to the exact older Stable baseline.'
        }
    }
}

function Assert-R8StableVerificationStatus {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][psobject]$VerificationStatus)

    foreach ($verificationGate in @(
            'authenticode',
            'rfc3161Timestamp',
            'baselineCapabilityProbe',
            'twoWindowsDevices',
            'authenticatedHttps',
            'deviceAttestations',
            'serverAttestation',
            'unauthorizedControl')) {
        $gateProperty =
            $VerificationStatus.PSObject.Properties[$verificationGate]
        if ($null -eq $gateProperty -or
            [string]$gateProperty.Value -cne 'VERIFIED') {
            throw "Stable private Pilot verification gate '$verificationGate' is not VERIFIED."
        }
    }
}

function Assert-R8StableEvidence {
    param(
        [Parameter(Mandatory = $true)][psobject]$Observation,
        [Parameter(Mandatory = $true)]$ObservationInput,
        [Parameter(Mandatory = $true)][psobject]$WindowsBody,
        [Parameter(Mandatory = $true)][psobject]$Trust,
        [Parameter(Mandatory = $true)][psobject]$Authority,
        [Parameter(Mandatory = $true)][DateTimeOffset]$ValidationTimeUtc
    )

    if ([string]$Observation.observationMode -cne 'real-device-observation' -or
        [string]$Observation.edition -cne 'Enterprise' -or
        [string]$Observation.product -cne 'ensou-dsh-enterprise' -or
        [string]$Observation.targetChannel -cne 'stable' -or
        [string]$Observation.exposureRing -cne 'private-pilot' -or
        [string]$Observation.productionAdmission -cne 'NO_GO' -or
        [string]$Observation.nextRequiredGate -cne 'PILOT_EVIDENCE_BOUND') {
        throw 'Stable private Pilot evidence is synthetic, developmental, or claims admission.'
    }
    Assert-R8StableVerificationStatus `
        -VerificationStatus $Observation.verificationStatus

    Assert-R8Equal `
        $Observation.canonicalStableManifestUri `
        $Authority.Plan.manifestUri `
        'Stable Pilot canonical manifest URI'

    Assert-R8Equal `
        $Observation.orchestrationId `
        $Authority.OrchestrationId `
        'Stable Pilot orchestration ID'
    Assert-R8Equal $Observation.r7.revision 7 'Stable Pilot r7 revision'
    Assert-R8Equal `
        $Observation.r7.phase `
        'INSTALLER_SIGNATURE_IMPORTED' `
        'Stable Pilot r7 phase'
    Assert-R8Equal `
        $Observation.r7.headSha256 `
        $Authority.HeadSha256 `
        'Stable Pilot r7 head'
    Assert-R8Equal `
        $Observation.r7.receiptSha256 `
        $Authority.R7ReceiptSha256 `
        'Stable Pilot r7 receipt'
    Assert-R8InstallerIdentity `
        -Actual $Observation.r7.signedInstaller `
        -Expected $Authority.InstallerIdentity `
        -Label 'Stable Pilot r7 Installer'
    Assert-R8InstallerIdentity `
        -Actual $Observation.targetRelease.signedInstaller `
        -Expected $Authority.InstallerIdentity `
        -Label 'Stable target r7 Installer'

    Assert-R8Equal `
        $Observation.targetRelease.releaseSetId `
        $Authority.Plan.releaseSetId `
        'Stable target release set'
    if ([string]$Observation.sourceBaseline.releaseSetId -ceq
            [string]$Observation.targetRelease.releaseSetId -or
        [int64]$Observation.sourceBaseline.sequence -ge
            [int64]$Observation.targetRelease.sequence) {
        throw 'Stable online-upgrade source is the target or is not older.'
    }
    Assert-R8Equal `
        $Observation.targetRelease.manifest.sha256 `
        $Authority.R5Data.manifestSha256 `
        'Stable target manifest SHA-256'
    Assert-R8Equal `
        $Observation.targetRelease.releaseManifestTrustSha256 `
        $Authority.R5Data.releaseManifestTrustSha256 `
        'Stable target release-manifest trust'
    Assert-R8Equal `
        $Observation.targetRelease.payloadSetSha256 `
        $Authority.R6Data.payloadSetSha256 `
        'Stable target Installer payload set'

    $targetObjects = @($Observation.targetRelease.manifest) +
        @($Observation.targetRelease.artifacts)
    if ($targetObjects.Count -ne 5 -or
        @($targetObjects | Select-Object -ExpandProperty role -Unique).Count -ne
            5) {
        throw 'Stable target must contain one manifest and four distinct artifacts.'
    }
    $requiredRoles = @(
        'release-manifest',
        'release-public-key',
        'launcher',
        'runtime',
        'plugin-policy')
    foreach ($role in $requiredRoles) {
        if (@($targetObjects | Where-Object {
            [string]$_.role -ceq $role
        }).Count -ne 1) {
            throw "Stable target object role '$role' is missing or duplicated."
        }
    }
    $artifactBaseUri = [Uri]::new(
        [string]$Authority.Plan.artifactBaseUri,
        [UriKind]::Absolute)
    foreach ($targetObject in $targetObjects) {
        $expectedObjectUri = if (
            [string]$targetObject.role -ceq 'release-manifest') {
            [string]$Authority.Plan.manifestUri
        }
        else {
            [Uri]::new(
                $artifactBaseUri,
                [string]$targetObject.fileName).AbsoluteUri
        }
        Assert-R8Equal `
            $targetObject.uri `
            $expectedObjectUri `
            "Stable target $($targetObject.role) URI"
    }
    Assert-R8ObjectSetEqual `
        -Actual $targetObjects `
        -Expected @($Authority.R5Data.files) `
        -Label 'Stable target/r5 candidate object set'
    $targetObjectSetSha256 = Get-R8ObjectSetSha256 -Objects $targetObjects
    Assert-R8Equal `
        $Observation.targetRelease.candidateSetSha256 `
        $targetObjectSetSha256 `
        'Stable target candidate set SHA-256'
    $r3ProbeSetSha256 = Get-R8Sha256Bytes `
        -Bytes (ConvertTo-R8CanonicalJsonBytes `
            -Value @($Authority.R3Data.releaseManifestTrustProbes))
    Assert-R8Equal `
        $Observation.targetRelease.releaseTrustProbeSha256 `
        $r3ProbeSetSha256 `
        'Stable target release-trust probe set'
    $launcherObject = @($targetObjects | Where-Object {
        [string]$_.role -ceq 'launcher'
    })[0]
    $runtimeObject = @($targetObjects | Where-Object {
        [string]$_.role -ceq 'runtime'
    })[0]
    Assert-R8Equal `
        $launcherObject.sha256 `
        $Authority.R7Data.r5LauncherSha256 `
        'Stable target/r7 Launcher'
    Assert-R8Equal `
        $runtimeObject.sha256 `
        $Authority.R7Data.r5RuntimeSha256 `
        'Stable target/r7 runtime'

    $devices = @($Observation.privatePilot.devices)
    if ($devices.Count -ne 2) {
        throw 'Stable Pilot must contain exactly two devices.'
    }
    $fresh = $devices[0]
    $upgrade = $devices[1]
    if ([string]$fresh.deviceIdentitySha256 -ceq
            [string]$upgrade.deviceIdentitySha256 -or
        [string]$fresh.machineIdentitySha256 -ceq
            [string]$upgrade.machineIdentitySha256 -or
        [string]$fresh.installationId -ceq [string]$upgrade.installationId) {
        throw 'Stable fresh-install and online-upgrade devices are not distinct.'
    }
    Assert-R8StableDevice `
        -Device $fresh `
        -ExpectedLane 'fresh-install' `
        -Observation $Observation `
        -TargetObjects $targetObjects `
        -InstallerAuthority $Authority.InstallerIdentity `
        -Label 'Fresh-install device'
    Assert-R8StableDevice `
        -Device $upgrade `
        -ExpectedLane 'online-upgrade' `
        -Observation $Observation `
        -TargetObjects $targetObjects `
        -InstallerAuthority $Authority.InstallerIdentity `
        -Label 'Online-upgrade device'
    Assert-R8Equal `
        $Observation.sourceBaseline.installedDeviceIdentitySha256 `
        $upgrade.deviceIdentitySha256 `
        'Older Stable installed-device identity'

    $allowlistIds = @(
        $Observation.privatePilot.allowlist.authorizedDeviceIdentitySha256 |
            Sort-Object)
    $deviceIds = @(
        [string]$fresh.deviceIdentitySha256,
        [string]$upgrade.deviceIdentitySha256) | Sort-Object
    if ($allowlistIds.Count -ne 2 -or
        $allowlistIds[0] -cne $deviceIds[0] -or
        $allowlistIds[1] -cne $deviceIds[1]) {
        throw 'Stable Pilot allowlist does not close exactly over both devices.'
    }
    $control = $Observation.privatePilot.unauthorizedControl
    if ($deviceIds -ccontains [string]$control.deviceIdentitySha256 -or
        [string]$control.canonicalManifestUri -cne
            [string]$Observation.canonicalStableManifestUri -or
        [string]$control.observedReleaseSetId -cne
            [string]$Observation.sourceBaseline.releaseSetId -or
        [string]$control.observedManifestSha256 -cne
            [string]$Observation.sourceBaseline.manifest.sha256) {
        throw 'Stable unauthorized control is allowlisted or observed candidate bytes.'
    }

    $windowsLanes = @($WindowsBody.deviceLanes)
    if ($windowsLanes.Count -ne 2 -or
        [string]$windowsLanes[0].lane -cne 'clean-install' -or
        [string]$windowsLanes[1].lane -cne 'legacy-migration') {
        throw 'Windows operational Pilot does not contain both required device lanes.'
    }
    Assert-R8Equal `
        $windowsLanes[0].deviceInventorySha256 `
        $fresh.inventorySha256 `
        'Windows/stable fresh-install device inventory'
    Assert-R8Equal `
        $windowsLanes[1].deviceInventorySha256 `
        $upgrade.inventorySha256 `
        'Windows/stable online-upgrade device inventory'
    $utf8 = [Text.UTF8Encoding]::new($false, $true)
    Assert-R8Equal `
        $windowsLanes[0].installationIdSha256 `
        (Get-R8Sha256Bytes -Bytes $utf8.GetBytes([string]$fresh.installationId)) `
        'Windows/stable fresh installation ID'
    Assert-R8Equal `
        $windowsLanes[1].installationIdSha256 `
        (Get-R8Sha256Bytes -Bytes $utf8.GetBytes([string]$upgrade.installationId)) `
        'Windows/stable upgrade installation ID'

    $allowFrom = ConvertFrom-R8WholeSecondUtc `
        -Value ([string]$Observation.privatePilot.allowlist.activeFromUtc) `
        -Label 'Stable allowlist start'
    $allowUntil = ConvertFrom-R8WholeSecondUtc `
        -Value ([string]$Observation.privatePilot.allowlist.activeUntilUtc) `
        -Label 'Stable allowlist expiry'
    $collectedAt = ConvertFrom-R8WholeSecondUtc `
        -Value ([string]$Observation.collectedAtUtc) `
        -Label 'Stable Pilot collection'
    $freshCompleted = ConvertFrom-R8WholeSecondUtc `
        -Value ([string]$fresh.updateReceipt.completedAtUtc) `
        -Label 'Fresh-install completion'
    $upgradeCompleted = ConvertFrom-R8WholeSecondUtc `
        -Value ([string]$upgrade.updateReceipt.completedAtUtc) `
        -Label 'Online-upgrade completion'
    $controlBefore = ConvertFrom-R8WholeSecondUtc `
        -Value ([string]$control.beforeObservedAtUtc) `
        -Label 'Unauthorized control before observation'
    $controlAfter = ConvertFrom-R8WholeSecondUtc `
        -Value ([string]$control.afterObservedAtUtc) `
        -Label 'Unauthorized control after observation'
    $minimumRemaining = [TimeSpan]::FromMinutes(
        [int]$Trust.minimumRemainingValidityMinutes)
    $maximumAge = [TimeSpan]::FromHours(
        [int]$Trust.maximumEvidenceAgeHours)
    if ($allowFrom -ge $allowUntil -or
        $allowFrom -gt $freshCompleted -or
        $allowFrom -gt $upgradeCompleted -or
        $freshCompleted -gt $collectedAt -or
        $upgradeCompleted -gt $collectedAt -or
        $controlBefore -ge $controlAfter -or
        $controlAfter -gt $collectedAt -or
        $collectedAt -gt $ValidationTimeUtc.AddMinutes(5) -or
        $collectedAt -lt $ValidationTimeUtc.Subtract($maximumAge) -or
        $collectedAt -gt $allowUntil -or
        $allowUntil -lt $ValidationTimeUtc.Add($minimumRemaining)) {
        throw 'Stable Pilot observation or allowlist is stale, expired, future-dated, or misordered.'
    }

    Assert-R8StableAttestation `
        -Attestation $Observation.attestations.server `
        -Payload (Get-EnterpriseStablePilotAttestationPayload `
            -Observation $Observation `
            -Role server) `
        -Key $Trust.stablePrivatePilotKeys.server `
        -Purpose 'stable-private-pilot-server-attestation' `
        -Label 'Stable server attestation'
    Assert-R8StableAttestation `
        -Attestation $Observation.attestations.devices[0] `
        -Payload (Get-EnterpriseStablePilotAttestationPayload `
            -Observation $Observation `
            -Role fresh-install) `
        -Key $Trust.stablePrivatePilotKeys.freshInstallDevice `
        -Purpose 'stable-private-pilot-device-attestation' `
        -Label 'Stable fresh-install device attestation'
    Assert-R8StableAttestation `
        -Attestation $Observation.attestations.devices[1] `
        -Payload (Get-EnterpriseStablePilotAttestationPayload `
            -Observation $Observation `
            -Role online-upgrade) `
        -Key $Trust.stablePrivatePilotKeys.onlineUpgradeDevice `
        -Purpose 'stable-private-pilot-device-attestation' `
        -Label 'Stable online-upgrade device attestation'
    Assert-R8StableAttestation `
        -Attestation $Observation.attestations.unauthorizedControl `
        -Payload (Get-EnterpriseStablePilotAttestationPayload `
            -Observation $Observation `
            -Role unauthorized-control) `
        -Key $Trust.stablePrivatePilotKeys.unauthorizedControl `
        -Purpose 'stable-private-pilot-control-attestation' `
        -Label 'Stable unauthorized-control attestation'

    $descriptor = Get-R8Descriptor -InputObject $ObservationInput
    return [pscustomobject]@{
        R8SubsetSha256 = Get-EnterpriseStablePilotSubsetSha256 `
            -Observation $Observation
        CollectedAtUtc = $collectedAt
        AllowlistExpiresAtUtc = $allowUntil
        FreshDeviceIdentitySha256 = [string]$fresh.deviceIdentitySha256
        UpgradeDeviceIdentitySha256 = [string]$upgrade.deviceIdentitySha256
        FreshInventorySha256 = [string]$fresh.inventorySha256
        UpgradeInventorySha256 = [string]$upgrade.inventorySha256
        TargetManifestSha256 = [string]$Observation.targetRelease.manifest.sha256
        TargetObjectSetSha256 = $targetObjectSetSha256
        ObservationSha256 = [string]$descriptor.Sha256
    }
}

function Assert-EnterpriseProductionPilotEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][psobject]$Trust,
        [Parameter(Mandatory = $true)]$TrustInput,
        [Parameter(Mandatory = $true)][psobject]$WindowsEnvelope,
        [Parameter(Mandatory = $true)]$WindowsEnvelopeInput,
        [Parameter(Mandatory = $true)][psobject]$WindowsBody,
        [Parameter(Mandatory = $true)]$WindowsBodyInput,
        [Parameter(Mandatory = $true)][psobject]$WindowsVerificationReport,
        [Parameter(Mandatory = $true)]$WindowsVerificationReportInput,
        [Parameter(Mandatory = $true)][psobject]$ReadinessConfig,
        [Parameter(Mandatory = $true)]$ReadinessConfigInput,
        [Parameter(Mandatory = $true)][psobject]$StoredReadinessReport,
        [Parameter(Mandatory = $true)]$StoredReadinessInput,
        [Parameter(Mandatory = $true)][psobject]$ReplayedReadinessReport,
        [Parameter(Mandatory = $true)]$ReplayedReadinessInput,
        [Parameter(Mandatory = $true)][psobject]$LocalDataReceipt,
        [Parameter(Mandatory = $true)]$LocalDataReceiptInput,
        [Parameter(Mandatory = $true)][psobject]$StableObservation,
        [Parameter(Mandatory = $true)]$StableObservationInput,
        [Parameter(Mandatory = $true)]$InstallerInput,
        [Parameter(Mandatory = $true)][psobject]$GateContract,
        [Parameter(Mandatory = $true)][psobject]$Authority,
        [Parameter(Mandatory = $true)][DateTimeOffset]$ValidationTimeUtc,
        [ValidateSet(1, 2)]
        [int]$WindowsPilotReadinessSchemaVersion = 1
    )

    if ($ValidationTimeUtc.Offset -ne [TimeSpan]::Zero) {
        throw 'r8 Pilot evidence must be evaluated with UTC trusted time.'
    }
    Assert-R8Equal `
        $Trust.orchestrationId `
        $Authority.OrchestrationId `
        'Pilot trust policy orchestration ID'
    Assert-R8PurposeSeparatedKeys `
        -Trust $Trust `
        -InstallerSigningTrust $Authority.InstallerSigningTrust

    $localResult = Assert-R8LocalDataEvidence `
        -Receipt $LocalDataReceipt `
        -ReceiptInput $LocalDataReceiptInput `
        -ReadinessConfig $ReadinessConfig `
        -Trust $Trust `
        -Authority $Authority `
        -ValidationTimeUtc $ValidationTimeUtc
    $windowsResult = Assert-R8WindowsEvidence `
        -Envelope $WindowsEnvelope `
        -EnvelopeInput $WindowsEnvelopeInput `
        -Body $WindowsBody `
        -BodyInput $WindowsBodyInput `
        -VerificationReport $WindowsVerificationReport `
        -VerificationReportInput $WindowsVerificationReportInput `
        -ReadinessConfig $ReadinessConfig `
        -ReadinessConfigInput $ReadinessConfigInput `
        -StoredReadinessReport $StoredReadinessReport `
        -StoredReadinessInput $StoredReadinessInput `
        -ReplayedReadinessReport $ReplayedReadinessReport `
        -ReplayedReadinessInput $ReplayedReadinessInput `
        -WindowsPilotReadinessSchemaVersion `
            $WindowsPilotReadinessSchemaVersion `
        -LocalReceipt $LocalDataReceipt `
        -LocalReceiptInput $LocalDataReceiptInput `
        -InstallerInput $InstallerInput `
        -Trust $Trust `
        -GateContract $GateContract `
        -Authority $Authority `
        -ValidationTimeUtc $ValidationTimeUtc
    $stableResult = Assert-R8StableEvidence `
        -Observation $StableObservation `
        -ObservationInput $StableObservationInput `
        -WindowsBody $WindowsBody `
        -Trust $Trust `
        -Authority $Authority `
        -ValidationTimeUtc $ValidationTimeUtc

    return [pscustomobject]@{
        TrustPolicySha256 = [string](
            (Get-R8Descriptor -InputObject $TrustInput).Sha256)
        LocalData = $localResult
        Windows = $windowsResult
        Stable = $stableResult
    }
}

Export-ModuleMember -Function @(
    'Assert-EnterpriseProductionPilotEvidence',
    'Assert-R8Es256Signature',
    'Assert-R8PurposeSeparatedKeys',
    'Assert-R8StableAttestation',
    'Assert-R8StableVerificationStatus',
    'Assert-R8WindowsVerificationReportAuthentication',
    'ConvertTo-R8Base64Url',
    'ConvertTo-R8CanonicalJsonBytes',
    'Get-EnterpriseLocalDataCertificationPayload',
    'Get-EnterpriseStablePilotAttestationPayload',
    'Get-EnterpriseStablePilotSubsetSha256',
    'Get-EnterpriseWindowsPilotAttestationPayload',
    'Get-EnterpriseWindowsPilotVerificationReportPayload')
