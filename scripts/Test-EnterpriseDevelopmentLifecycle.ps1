[CmdletBinding()]
param(
    [string]$ControlPlaneRepository = 'C:\dev\deepseek\private-management-service',

    [string]$RuntimeArchivePath,

    [string]$RuntimeMetadataPath,

    [string]$PluginPolicyArchivePath,

    [string]$PluginPolicyMetadataPath,

    [string]$ExpectedRuntimeReleaseId,

    [string]$ExpectedRuntimeArchiveFileName,

    [string]$ExpectedRuntimeArchiveSha256,

    [string]$TargetRuntimeArchivePath,

    [string]$TargetRuntimeMetadataPath,

    [string]$ExpectedTargetRuntimeReleaseId,

    [string]$ExpectedTargetRuntimeArchiveFileName,

    [string]$ExpectedTargetRuntimeArchiveSha256,

    [string]$TargetPluginPolicyArchivePath,

    [string]$TargetPluginPolicyMetadataPath,

    [string]$ExpectedLauncherReleaseId,

    [string]$TargetLauncherArchivePath,

    [string]$ExpectedTargetLauncherReleaseId,

    [string]$ExpectedTargetLauncherArchiveSha256,

    [string]$EvidenceDirectory,

    [switch]$AllowLocalLab,

    [switch]$EnterpriseDirectLocal,

    [switch]$AutomaticRuntimeUpdate,

    [switch]$InstalledLauncherUpdate,

    [ValidatePattern('^sha256:[0-9a-f]{64}$')]
    [string]$CachedPostgresImageId,

    [switch]$ContractOnly
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($InstalledLauncherUpdate -and -not $AutomaticRuntimeUpdate) {
    throw 'Installed Launcher acceptance requires the preceding automatic Runtime sequence.'
}
if (Test-Path variable:PSNativeCommandUseErrorActionPreference) {
    $PSNativeCommandUseErrorActionPreference = $false
}

$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$runnerProject = Join-Path $repositoryRoot 'tests\Ensou.Dsh.Enterprise.DevelopmentE2ETests\Ensou.Dsh.Enterprise.DevelopmentE2ETests.csproj'
$runnerSource = Join-Path $repositoryRoot 'tests\Ensou.Dsh.Enterprise.DevelopmentE2ETests\Program.cs'
$installerSource = Join-Path $repositoryRoot 'src\Ensou.Dsh.Enterprise.Installer\Program.cs'
$bootstrapperSource = Join-Path $repositoryRoot 'src\Ensou.Dsh.Enterprise.Bootstrapper\Program.cs'
$launcherProfileSource = Join-Path $repositoryRoot 'src\Ensou.Dsh.Enterprise.Launcher\EnterpriseBuildProfile.cs'
$launcherAppSource = Join-Path $repositoryRoot 'src\Ensou.Dsh.Enterprise.Launcher\App.xaml.cs'
$publishedArtifactGate = Join-Path $repositoryRoot 'scripts\Test-EnterprisePublishedArtifacts.ps1'
$runtimeAdmissionSource = Join-Path $repositoryRoot 'scripts\EnterpriseDevelopmentRuntimeAdmission.ps1'
$runtimeAdmissionTests = Join-Path $repositoryRoot 'scripts\Test-EnterpriseDevelopmentRuntimeAdmission.ps1'
$runtimeMetadataSchema = Join-Path $repositoryRoot $(if ($EnterpriseDirectLocal) {
    'release\schemas\enterprise-development-direct-local-runtime-metadata.schema.json'
} else {
    'release\schemas\enterprise-development-runtime-metadata.schema.json'
})
if (-not (Test-Path -LiteralPath $runtimeAdmissionSource -PathType Leaf)) {
    throw "Enterprise Development runtime admission source is missing: $runtimeAdmissionSource"
}
. $runtimeAdmissionSource

function Assert-ContractText {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string[]]$RequiredText
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required Development E2E contract file is missing: $Path"
    }
    $content = Get-Content -LiteralPath $Path -Raw
    foreach ($text in $RequiredText) {
        if (-not $content.Contains($text, [StringComparison]::Ordinal)) {
            throw "Development E2E contract '$text' is missing from $Path"
        }
    }
}

function ConvertTo-SafeDevelopmentFailureEvidenceType {
    param([Parameter(Mandatory = $true)][Exception]$Exception)

    $value = $Exception.GetType().Name
    if ($value.Length -lt 1 -or
        $value.Length -gt 128 -or
        $value -cnotmatch '^[A-Za-z0-9]+$') {
        return 'Exception'
    }
    return $value
}

function ConvertTo-SafeDevelopmentFailureEvidenceMessage {
    param([AllowNull()][string]$Message)

    if ([string]::IsNullOrWhiteSpace($Message)) {
        return 'No diagnostic message was provided.'
    }
    foreach ($sensitiveLabel in @(
        'api key', 'api_key', 'api-key', 'authorization', 'bearer',
        'cookie', 'password', 'private key', 'secret')) {
        if ($Message.IndexOf(
                $sensitiveLabel,
                [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            return 'Diagnostic message was redacted.'
        }
    }

    $maximumLength = 512
    $normalized = [Text.StringBuilder]::new(
        [Math]::Min($Message.Length, $maximumLength))
    $previousWasSpace = $false
    foreach ($character in $Message.ToCharArray()) {
        if ($normalized.Length -ge $maximumLength) {
            break
        }
        if ([char]::IsControl($character) -or [char]::IsWhiteSpace($character)) {
            if (-not $previousWasSpace -and $normalized.Length -gt 0) {
                [void]$normalized.Append(' ')
            }
            $previousWasSpace = $true
            continue
        }
        [void]$normalized.Append($character)
        $previousWasSpace = $false
    }
    $bounded = $normalized.ToString().Trim()
    if ($bounded.Length -eq 0) {
        return 'No diagnostic message was provided.'
    }
    return [Text.RegularExpressions.Regex]::Replace(
        $bounded,
        '[A-Za-z0-9_+\-=]{32,}',
        '<redacted>',
        [Text.RegularExpressions.RegexOptions]::CultureInvariant)
}

function Test-DevelopmentFailureEvidenceSanitizer {
    $sensitive = 'prefix Bearer abcdefghijklmnopqrstuvwxyz0123456789'
    $longValue = 'A' * 32
    $normalized = ConvertTo-SafeDevelopmentFailureEvidenceMessage `
        -Message ("first`r`n`tsecond " + $longValue + ('x' * 600))
    if ((ConvertTo-SafeDevelopmentFailureEvidenceMessage -Message $sensitive) -cne
            'Diagnostic message was redacted.' -or
        $normalized.Length -gt 512 -or
        $normalized.Contains("`r", [StringComparison]::Ordinal) -or
        $normalized.Contains("`n", [StringComparison]::Ordinal) -or
        $normalized.Contains("`t", [StringComparison]::Ordinal) -or
        $normalized.Contains($longValue, [StringComparison]::Ordinal) -or
        -not $normalized.Contains('<redacted>', [StringComparison]::Ordinal) -or
        (ConvertTo-SafeDevelopmentFailureEvidenceMessage -Message '   ') -cne
            'No diagnostic message was provided.' -or
        (ConvertTo-SafeDevelopmentFailureEvidenceType `
            -Exception ([IO.InvalidDataException]::new('fixture'))) -cne
            'InvalidDataException') {
        throw 'Development E2E failure-evidence sanitizer contract failed.'
    }
}

function ConvertTo-CanonicalHttpsReleaseUri {
    param(
        [Parameter(Mandatory)][string]$Value,
        [Parameter(Mandatory)][string]$FieldName,
        [switch]$Origin
    )

    try {
        $uri = [Uri]::new($Value, [UriKind]::Absolute)
    }
    catch {
        throw [IO.InvalidDataException]::new(
            "Development release update trust $FieldName is not an absolute URI.")
    }
    if ($uri.Scheme -cne [Uri]::UriSchemeHttps -or
        -not [string]::IsNullOrEmpty($uri.UserInfo) -or
        -not [string]::IsNullOrEmpty($uri.Query) -or
        -not [string]::IsNullOrEmpty($uri.Fragment) -or
        $Value -cne $uri.AbsoluteUri) {
        throw [IO.InvalidDataException]::new(
            "Development release update trust $FieldName is not canonical HTTPS.")
    }
    if ($Origin) {
        $canonicalOrigin = $uri.GetLeftPart([UriPartial]::Authority) + '/'
        if ($uri.AbsolutePath -cne '/' -or $Value -cne $canonicalOrigin) {
            throw [IO.InvalidDataException]::new(
                "Development release update trust $FieldName is not a canonical origin.")
        }
    }
    elseif ($uri.AbsolutePath -ceq '/') {
        throw [IO.InvalidDataException]::new(
            "Development release update trust $FieldName has no manifest path.")
    }
    return $uri
}

function Assert-CanonicalP256Coordinate {
    param(
        [Parameter(Mandatory)][string]$Value,
        [Parameter(Mandatory)][string]$FieldName
    )

    if ($Value -cnotmatch '^[A-Za-z0-9_-]{43}$') {
        throw [IO.InvalidDataException]::new(
            "Development release update trust $FieldName is not canonical P-256 base64url.")
    }
    try {
        $bytes = [Convert]::FromBase64String(
            $Value.Replace('-', '+').Replace('_', '/') + '=')
    }
    catch {
        throw [IO.InvalidDataException]::new(
            "Development release update trust $FieldName is not valid base64url.")
    }
    $canonical = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    if ($bytes.Length -ne 32 -or $canonical -cne $Value) {
        throw [IO.InvalidDataException]::new(
            "Development release update trust $FieldName is not a canonical P-256 coordinate.")
    }
}

function Read-DevelopmentReleaseUpdateTrust {
    param([Parameter(Mandatory)][AllowNull()]$Evidence)

    if ($null -eq $Evidence -or $Evidence -isnot [pscustomobject]) {
        throw [IO.InvalidDataException]::new(
            'Development release update trust evidence must be an object.')
    }

    $expectedProperties = @(
        'artifactOrigin',
        'manifestOrigin',
        'manifestUri',
        'releasePolicyKeyId',
        'releasePolicyKeyX',
        'releasePolicyKeyY')
    $actualProperties = @($Evidence.PSObject.Properties.Name | Sort-Object)
    if (($actualProperties -join ',') -cne ($expectedProperties -join ',')) {
        throw [IO.InvalidDataException]::new(
            'Development release update trust evidence shape is not exact.')
    }

    $values = @{}
    foreach ($property in $expectedProperties) {
        $value = $Evidence.$property
        if ($value -isnot [string] -or
            [string]::IsNullOrWhiteSpace($value) -or
            $value -match '[\x00-\x1f\x7f]') {
            throw [IO.InvalidDataException]::new(
                "Development release update trust $property is invalid.")
        }
        $values[$property] = $value
    }

    $manifestUri = ConvertTo-CanonicalHttpsReleaseUri `
        -Value $values['manifestUri'] `
        -FieldName 'manifestUri'
    $manifestOrigin = ConvertTo-CanonicalHttpsReleaseUri `
        -Value $values['manifestOrigin'] `
        -FieldName 'manifestOrigin' `
        -Origin
    $artifactOrigin = ConvertTo-CanonicalHttpsReleaseUri `
        -Value $values['artifactOrigin'] `
        -FieldName 'artifactOrigin' `
        -Origin
    if (($manifestUri.GetLeftPart([UriPartial]::Authority) + '/') -cne
        $manifestOrigin.AbsoluteUri) {
        throw [IO.InvalidDataException]::new(
            'Development release update manifest URI does not match its exact origin.')
    }
    if ($values['releasePolicyKeyId'] -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$') {
        throw [IO.InvalidDataException]::new(
            'Development release update trust key id is invalid.')
    }
    Assert-CanonicalP256Coordinate `
        -Value $values['releasePolicyKeyX'] `
        -FieldName 'releasePolicyKeyX'
    Assert-CanonicalP256Coordinate `
        -Value $values['releasePolicyKeyY'] `
        -FieldName 'releasePolicyKeyY'

    return @{
        ENSOU_DSH_E2E_UPDATE_MANIFEST_URI = $manifestUri.AbsoluteUri
        ENSOU_DSH_E2E_UPDATE_MANIFEST_ORIGIN = $manifestOrigin.AbsoluteUri
        ENSOU_DSH_E2E_UPDATE_ARTIFACT_ORIGIN = $artifactOrigin.AbsoluteUri
        ENSOU_DSH_E2E_UPDATE_KEY_ID = $values['releasePolicyKeyId']
        ENSOU_DSH_E2E_UPDATE_KEY_X = $values['releasePolicyKeyX']
        ENSOU_DSH_E2E_UPDATE_KEY_Y = $values['releasePolicyKeyY']
    }
}

function New-DevelopmentReleaseUpdateTrustFixture {
    param(
        [string]$ManifestUri = 'https://updates.example/v2/channels/lab/release-set.v2.json',
        [string]$ManifestOrigin = 'https://updates.example/',
        [string]$ArtifactOrigin = 'https://artifacts.example/',
        [string]$KeyId = 'lifecycle-key',
        [string]$KeyX = ('A' * 43),
        [string]$KeyY = (('A' * 42) + 'Q')
    )

    return [pscustomobject][ordered]@{
        manifestUri = $ManifestUri
        manifestOrigin = $ManifestOrigin
        artifactOrigin = $ArtifactOrigin
        releasePolicyKeyId = $KeyId
        releasePolicyKeyX = $KeyX
        releasePolicyKeyY = $KeyY
    }
}

function Assert-DevelopmentReleaseUpdateTrustRejected {
    param([Parameter(Mandatory)][AllowNull()]$Evidence)

    $rejected = $false
    try {
        Read-DevelopmentReleaseUpdateTrust -Evidence $Evidence | Out-Null
    }
    catch [IO.InvalidDataException] {
        $rejected = $true
    }
    if (-not $rejected) {
        throw 'Development release update trust negative fixture was accepted.'
    }
}

function Test-DevelopmentReleaseUpdateTrustValidation {
    $valid = New-DevelopmentReleaseUpdateTrustFixture
    $environment = Read-DevelopmentReleaseUpdateTrust -Evidence $valid
    if ($environment.Count -ne 6 -or
        [string]$environment['ENSOU_DSH_E2E_UPDATE_MANIFEST_URI'] -cne $valid.manifestUri -or
        [string]$environment['ENSOU_DSH_E2E_UPDATE_KEY_ID'] -cne $valid.releasePolicyKeyId) {
        throw 'Development release update trust valid fixture was not preserved exactly.'
    }

    Assert-DevelopmentReleaseUpdateTrustRejected -Evidence $null
    Assert-DevelopmentReleaseUpdateTrustRejected -Evidence 'replacement'
    Assert-DevelopmentReleaseUpdateTrustRejected -Evidence ([pscustomobject]@{
        manifestUri = $valid.manifestUri
        manifestOrigin = $valid.manifestOrigin
        artifactOrigin = $valid.artifactOrigin
        releasePolicyKeyId = $valid.releasePolicyKeyId
        releasePolicyKeyX = $valid.releasePolicyKeyX
    })
    $extra = New-DevelopmentReleaseUpdateTrustFixture
    $extra | Add-Member -NotePropertyName privateKey -NotePropertyValue 'forbidden'
    Assert-DevelopmentReleaseUpdateTrustRejected -Evidence $extra
    Assert-DevelopmentReleaseUpdateTrustRejected -Evidence (
        New-DevelopmentReleaseUpdateTrustFixture `
            -ManifestUri 'http://updates.example/v2/channels/lab/release-set.v2.json')
    Assert-DevelopmentReleaseUpdateTrustRejected -Evidence (
        New-DevelopmentReleaseUpdateTrustFixture `
            -ManifestOrigin 'https://updates.example/not-an-origin')
    Assert-DevelopmentReleaseUpdateTrustRejected -Evidence (
        New-DevelopmentReleaseUpdateTrustFixture `
            -ManifestOrigin 'https://replacement.example/')
    Assert-DevelopmentReleaseUpdateTrustRejected -Evidence (
        New-DevelopmentReleaseUpdateTrustFixture -KeyId 'invalid key id')
    Assert-DevelopmentReleaseUpdateTrustRejected -Evidence (
        New-DevelopmentReleaseUpdateTrustFixture -KeyX ('A' * 42))
}

function New-DevelopmentTlsCertificate {
    $key = [Security.Cryptography.RSA]::Create(2048)
    $certificate = $null
    try {
        $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
            'CN=localhost', $key,
            [Security.Cryptography.HashAlgorithmName]::SHA256,
            [Security.Cryptography.RSASignaturePadding]::Pkcs1)
        [void]$request.CertificateExtensions.Add(
            [Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new(
                $false, $false, 0, $true))
        [void]$request.CertificateExtensions.Add(
            [Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
                ([Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature -bor
                    [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyEncipherment), $true))
        $eku = [Security.Cryptography.OidCollection]::new()
        [void]$eku.Add([Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.1'))
        [void]$request.CertificateExtensions.Add(
            [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($eku, $true))
        $san = [Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
        $san.AddDnsName('localhost')
        [void]$request.CertificateExtensions.Add($san.Build($true))
        $certificate = $request.CreateSelfSigned(
            [DateTimeOffset]::UtcNow.AddMinutes(-5), [DateTimeOffset]::UtcNow.AddHours(2))
        return [pscustomobject]@{ Certificate = $certificate; Key = $key }
    }
    catch {
        if ($null -ne $certificate) { $certificate.Dispose() }
        $key.Dispose()
        throw
    }
}

function Get-EnterpriseDevelopmentExpectedLauncherArtifactUri {
    param(
        [Parameter(Mandatory)]$Manifest,
        [Parameter(Mandatory)][string]$ExpectedReleaseId,
        [Parameter(Mandatory)][string]$ExpectedArchiveSha256
    )

    $launcherArtifacts = @($Manifest.artifacts | Where-Object {
        [string]$_.component -ceq 'launcher'
    })
    if ($launcherArtifacts.Count -ne 1) {
        throw 'Signed update manifest must contain exactly one Launcher artifact.'
    }
    $launcherArtifact = $launcherArtifacts[0]
    if ([string]$launcherArtifact.releaseId -cne $ExpectedReleaseId -or
        [string]$launcherArtifact.sha256 -cne $ExpectedArchiveSha256) {
        throw 'Signed update manifest Launcher identity differs from the pinned target.'
    }
    $uri = [string]$launcherArtifact.uri
    if ([string]::IsNullOrWhiteSpace($uri)) {
        throw 'Signed update manifest Launcher URI is missing.'
    }
    return $uri
}

function Test-DevelopmentTlsCertificateContract {
    $material = $null
    $certificate = $null
    $reimported = $null
    $originalPublicKey = $null
    $reimportedPublicKey = $null
    $reimportedPrivateKey = $null
    $pfxBytes = $null
    try {
        $material = New-DevelopmentTlsCertificate
        $certificate = $material.Certificate
        $password = ConvertTo-Base64Url ([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
        $pfxBytes = $certificate.Export(
            [Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $password)
        $reimported = [Security.Cryptography.X509Certificates.X509Certificate2]::new(
            $pfxBytes, $password,
            [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet)
        if (-not [string]::Equals($certificate.Thumbprint, $reimported.Thumbprint,
                [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Development TLS certificate PFX reimport changed the leaf identity.'
        }
        $originalPublicKey = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($certificate)
        $reimportedPrivateKey = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($reimported)
        if ($null -eq $reimportedPrivateKey -or -not $reimported.HasPrivateKey) {
            throw 'Development TLS certificate PFX reimport did not retain its private key.'
        }
        $payload = [Text.Encoding]::UTF8.GetBytes('development-tls-contract')
        $signature = $reimportedPrivateKey.SignData($payload, [Security.Cryptography.HashAlgorithmName]::SHA256,
            [Security.Cryptography.RSASignaturePadding]::Pkcs1)
        if (-not $originalPublicKey.VerifyData($payload, $signature,
                [Security.Cryptography.HashAlgorithmName]::SHA256,
                [Security.Cryptography.RSASignaturePadding]::Pkcs1)) {
            throw 'Development TLS certificate PFX reimport changed the signing key pair.'
        }
        $sanExtension = @($reimported.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' })[0]
        if ($null -eq $sanExtension -or -not (@($sanExtension.EnumerateDnsNames()) -contains 'localhost')) {
            throw 'Development TLS certificate is missing localhost SAN.'
        }
        $ekuExtension = @($reimported.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' })[0]
        if ($null -eq $ekuExtension -or -not (@($ekuExtension.EnhancedKeyUsages | Where-Object { $_.Value -eq '1.3.6.1.5.5.7.3.1' }).Count)) {
            throw 'Development TLS certificate is missing server-auth EKU.'
        }
        $keyUsage = @($reimported.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.15' })[0]
        $basicConstraints = @($reimported.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.19' })[0]
        if ($null -eq $keyUsage -or $null -eq $basicConstraints -or $basicConstraints.CertificateAuthority) {
            throw 'Development TLS certificate has invalid key usage/basic constraints.'
        }
        $keyUsageValue = ([Security.Cryptography.X509Certificates.X509KeyUsageExtension]$keyUsage).KeyUsages
        $requiredKeyUsage = [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature -bor
            [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyEncipherment
        if (($keyUsageValue -band $requiredKeyUsage) -ne $requiredKeyUsage) {
            throw 'Development TLS certificate is missing required key-usage flags.'
        }
        $now = [DateTime]::UtcNow
        if ($certificate.NotBefore.ToUniversalTime() -gt $now.AddMinutes(-4) -or
            $certificate.NotAfter.ToUniversalTime() -lt $now.AddMinutes(119)) {
            throw 'Development TLS certificate validity is outside the required UTC bounds.'
        }
        Write-Host 'PASS  Development TLS certificate is in-memory and PFX-reimportable.'
    }
    finally {
        if ($null -ne $pfxBytes) { [Array]::Clear($pfxBytes, 0, $pfxBytes.Length) }
        if ($null -ne $reimportedPrivateKey) { $reimportedPrivateKey.Dispose() }
        if ($null -ne $originalPublicKey) { $originalPublicKey.Dispose() }
        if ($null -ne $reimported) { $reimported.Dispose() }
        if ($null -ne $certificate) { $certificate.Dispose() }
        if ($null -ne $material) { $material.Key.Dispose() }
    }
}

function Read-DevelopmentEnrollmentConfiguration {
    param(
        [Parameter(Mandatory)]
        [string[]]$Lines
    )

    $configuration = @{}
    foreach ($line in $Lines) {
        if ($line -match '^(ENSOU_[A-Z0-9_]+)=(.+)$') {
            $configuration[$matches[1]] = $matches[2]
        }
    }
    foreach ($required in @(
        'ENSOU_DEVELOPMENTENROLLMENT__BINDINGSECRETKEY',
        'ENSOU_DEVELOPMENTENROLLMENT__RESPONSEPROTECTIONKEY',
        'ENSOU_DEVELOPMENTENROLLMENT__LEASEKEYID',
        'ENSOU_DEVELOPMENTENROLLMENT__LEASEPRIVATED',
        'ENSOU_DEVELOPMENTENROLLMENT__LEASEPUBLICX',
        'ENSOU_DEVELOPMENTENROLLMENT__LEASEPUBLICY')) {
        if (-not $configuration.ContainsKey($required)) {
            throw "Development cryptographic configuration is incomplete: $required"
        }
    }
    return $configuration
}

function Test-DevelopmentEnrollmentConfigurationContract {
    $lines = @(
        'ENSOU_DEVELOPMENTENROLLMENT__BINDINGSECRETKEY=fixture',
        'ENSOU_DEVELOPMENTENROLLMENT__RESPONSEPROTECTIONKEY=fixture',
        'ENSOU_DEVELOPMENTENROLLMENT__LEASEKEYID=fixture',
        'ENSOU_DEVELOPMENTENROLLMENT__LEASEPRIVATED=fixture',
        'ENSOU_DEVELOPMENTENROLLMENT__LEASEPUBLICX=fixture',
        'ENSOU_DEVELOPMENTENROLLMENT__LEASEPUBLICY=fixture')
    $configuration = Read-DevelopmentEnrollmentConfiguration -Lines $lines
    if ($configuration.Count -ne 6 -or
        $configuration.ContainsKey('ENSOU_DEVELOPMENTENROLLMENT__STATESIGNINGKEY')) {
        throw 'Development enrollment configuration accepted an unexpected contract shape.'
    }
    foreach ($required in @($configuration.Keys)) {
        $missingLines = @($lines | Where-Object {
                -not $_.StartsWith($required + '=', [StringComparison]::Ordinal)
            })
        $rejected = $false
        try {
            Read-DevelopmentEnrollmentConfiguration -Lines $missingLines | Out-Null
        }
        catch {
            $rejected = $true
        }
        if (-not $rejected) {
            throw "Development enrollment configuration accepted missing required key: $required"
        }
    }
}

function Get-EmployeeAssignmentSnapshot {
    param([Parameter(Mandatory)]$Employee)

    [string[]]$expectedProperties = @(
        'employee_id', 'employee_ref', 'state', 'auth_epoch',
        'entitlement_epoch', 'created_at', 'updated_at', 'revoked_at')
    [string[]]$actualProperties = @($Employee.PSObject.Properties | ForEach-Object Name)
    # PostgreSQL jsonb does not preserve object member insertion order.
    [Array]::Sort($expectedProperties, [StringComparer]::Ordinal)
    [Array]::Sort($actualProperties, [StringComparer]::Ordinal)
    if ([string]::Join("`n", $actualProperties) -cne
        [string]::Join("`n", $expectedProperties)) {
        throw 'Administrator employee show returned an unexpected assignment snapshot contract.'
    }
    if ([string]$Employee.employee_id -cnotmatch
        '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' -or
        [string]::IsNullOrWhiteSpace([string]$Employee.employee_ref) -or
        [string]$Employee.state -notin @('PRE_REGISTERED', 'ACTIVE') -or
        [long]$Employee.auth_epoch -le 0 -or
        [long]$Employee.entitlement_epoch -le 0) {
        throw 'Administrator employee show returned an invalid assignment snapshot.'
    }
    return [ordered]@{
        employeeId = [string]$Employee.employee_id
        employeeRef = [string]$Employee.employee_ref
        state = [string]$Employee.state
        authEpoch = [long]$Employee.auth_epoch
        entitlementEpoch = [long]$Employee.entitlement_epoch
    }
}

function Assert-EmployeeAssignmentSnapshotUnchanged {
    param(
        [Parameter(Mandatory)]$Before,
        [Parameter(Mandatory)]$After
    )

    foreach ($field in @(
            'employeeId', 'employeeRef', 'state', 'authEpoch',
            'entitlementEpoch')) {
        if ($Before[$field] -cne $After[$field]) {
            throw 'Automatic release update changed the employee assignment or authorization epoch.'
        }
    }
}

function New-DevelopmentDirectLocalCredentialEvidence {
    param([Parameter(Mandatory)][string]$HarnessHome)

    $harnessHomeFull = [IO.Path]::GetFullPath($HarnessHome)
    [IO.Directory]::CreateDirectory($harnessHomeFull) | Out-Null
    $path = Join-Path $harnessHomeFull '.credentials.yaml'
    if (Test-Path -LiteralPath $path) {
        throw 'Direct-local Development credential path must be new.'
    }
    [byte[]]$random = [Security.Cryptography.RandomNumberGenerator]::GetBytes(32)
    [byte[]]$valueBytes = $null
    [byte[]]$bytes = $null
    try {
        $value = [Convert]::ToBase64String($random).TrimEnd('=').Replace('+', '-').Replace('/', '_')
        $valueBytes = [Text.UTF8Encoding]::new($false).GetBytes($value)
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes(
            "version: 1`nrefs:`n  DEEPSEEK_API_KEY: $value`n")
        $stream = [IO.FileStream]::new(
            $path,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None)
        try {
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush($true)
        }
        finally {
            $stream.Dispose()
        }
        $documentSha256 = ([Convert]::ToHexString(
            [Security.Cryptography.SHA256]::HashData($bytes))).ToLowerInvariant()
        $valueSha256 = ([Convert]::ToHexString(
            [Security.Cryptography.SHA256]::HashData($valueBytes))).ToLowerInvariant()
        return [pscustomobject]@{
            Path = $path
            ReferenceName = 'DEEPSEEK_API_KEY'
            ValueSha256 = $valueSha256
            InitialDocumentSizeBytes = [int64]$bytes.Length
            InitialDocumentSha256 = $documentSha256
        }
    }
    finally {
        [Security.Cryptography.CryptographicOperations]::ZeroMemory($random)
        if ($null -ne $valueBytes) {
            [Security.Cryptography.CryptographicOperations]::ZeroMemory($valueBytes)
        }
        if ($null -ne $bytes) {
            [Security.Cryptography.CryptographicOperations]::ZeroMemory($bytes)
        }
        $value = $null
    }
}

function Assert-DevelopmentDirectLocalCredentialRetained {
    param(
        [Parameter(Mandatory)]$Evidence,
        [Parameter(Mandatory)][string]$RuntimeDirectory,
        [Parameter(Mandatory)][string]$VerifierPath,
        [Parameter(Mandatory)][ValidatePattern('^[a-z0-9][a-z0-9-]{0,63}$')]
        [string]$Stage
    )

    $path = Resolve-SafeExistingPath -Path $Evidence.Path -Directory $false
    if ([string]$Evidence.ReferenceName -cne 'DEEPSEEK_API_KEY' -or
        [string]$Evidence.ValueSha256 -cnotmatch '^[a-f0-9]{64}$' -or
        [string]$Evidence.InitialDocumentSha256 -cnotmatch '^[a-f0-9]{64}$' -or
        [int64]$Evidence.InitialDocumentSizeBytes -lt 1) {
        throw 'Direct-local Development synthetic credential evidence is invalid.'
    }
    $runtime = Resolve-SafeExistingPath -Path $RuntimeDirectory -Directory $true
    $node = Resolve-SafeExistingPath -Path (Join-Path $runtime 'node.exe') -Directory $false
    $verifier = Resolve-SafeExistingPath -Path $VerifierPath -Directory $false

    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $node
    $startInfo.WorkingDirectory = $runtime
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.WindowStyle = [Diagnostics.ProcessWindowStyle]::Hidden
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in @(
            $verifier,
            '--credentials-path', $path,
            '--runtime-directory', $runtime,
            '--expected-value-sha256', [string]$Evidence.ValueSha256)) {
        [void]$startInfo.ArgumentList.Add($argument)
    }

    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $stdout = $null
    $stderr = $null
    try {
        if (-not $process.Start()) {
            throw 'Direct-local Development native credential verifier did not start.'
        }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(15000)) {
            try { $process.Kill($true) } catch { }
            [void]$process.WaitForExit(5000)
            throw 'Direct-local Development native credential verifier timed out.'
        }
        $process.WaitForExit()
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0 -or $stdout -cne "PASS`n" -or $stderr.Length -ne 0) {
            throw 'Direct-local Development synthetic credential value was not retained.'
        }
    }
    finally {
        $stdout = $null
        $stderr = $null
        $process.Dispose()
    }

    $item = Get-Item -LiteralPath $path -Force
    $documentSha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    return [pscustomobject][ordered]@{
        stage = $Stage
        runtimeReleaseId = [IO.Path]::GetFileName($runtime.TrimEnd('\', '/'))
        referenceName = 'DEEPSEEK_API_KEY'
        expectedValueSha256 = [string]$Evidence.ValueSha256
        nativeParserVerified = $true
        initialDocumentSizeBytes = [int64]$Evidence.InitialDocumentSizeBytes
        observedDocumentSizeBytes = [int64]$item.Length
        initialDocumentSha256 = [string]$Evidence.InitialDocumentSha256
        observedDocumentSha256 = $documentSha256
        documentBytesUnchanged = [bool](
            $item.Length -eq [int64]$Evidence.InitialDocumentSizeBytes -and
            $documentSha256 -ceq [string]$Evidence.InitialDocumentSha256)
    }
}

function Test-EmployeeAssignmentSnapshotContract {
    $before = Get-EmployeeAssignmentSnapshot -Employee ([pscustomobject][ordered]@{
        employee_id = '12345678-1234-4234-8234-123456789abc'
        employee_ref = 'development-e2e-employee'
        state = 'PRE_REGISTERED'
        auth_epoch = 2
        entitlement_epoch = 2
        created_at = '2026-09-11T00:00:00Z'
        updated_at = '2026-09-11T00:00:00Z'
        revoked_at = $null
    })
    Assert-EmployeeAssignmentSnapshotUnchanged -Before $before -After $before
    $reordered = Get-EmployeeAssignmentSnapshot -Employee ([pscustomobject][ordered]@{
        revoked_at = $null; updated_at = '2026-09-11T00:00:00Z'
        created_at = '2026-09-11T00:00:00Z'; entitlement_epoch = 2
        auth_epoch = 2; state = 'PRE_REGISTERED'
        employee_ref = 'development-e2e-employee'
        employee_id = '12345678-1234-4234-8234-123456789abc'
    })
    Assert-EmployeeAssignmentSnapshotUnchanged -Before $before -After $reordered
    $changed = [ordered]@{}
    foreach ($field in @(
            'employeeId', 'employeeRef', 'state', 'authEpoch',
            'entitlementEpoch')) {
        $changed[$field] = $before[$field]
    }
    $changed['entitlementEpoch'] = 3
    $rejected = $false
    try {
        Assert-EmployeeAssignmentSnapshotUnchanged -Before $before -After $changed
    }
    catch {
        $rejected = $true
    }
    if (-not $rejected) {
        throw 'Employee assignment snapshot accepted an entitlement epoch change.'
    }
}

function New-DevelopmentLauncherPublishArguments {
    param(
        [Parameter(Mandatory)][string]$OutputDirectory,
        [switch]$DirectLocal
    )

    $arguments = @(
        'publish', (Join-Path $repositoryRoot 'src\Ensou.Dsh.Enterprise.Launcher\Ensou.Dsh.Enterprise.Launcher.csproj'),
        '-c', 'Release', '-r', 'win-x64', '--self-contained', 'true',
        '--no-restore', '-p:PublishSingleFile=true', '-p:EnterpriseDevelopmentE2E=true',
        '-p:EnterpriseDirectLocalRuntimeAdmission=false', '-o', $OutputDirectory)
    if ($DirectLocal) {
        $arguments += '-p:EnterpriseDirectLocalDevelopmentE2E=true'
    }
    return $arguments
}

function Test-DevelopmentLauncherPublishArgumentsContract {
    $fixtureOutput = Join-Path $repositoryRoot '.development-launcher-publish-contract'
    $managed = @(New-DevelopmentLauncherPublishArguments -OutputDirectory $fixtureOutput)
    $direct = @(New-DevelopmentLauncherPublishArguments `
        -OutputDirectory $fixtureOutput -DirectLocal)
    $productionDirect = '-p:EnterpriseDirectLocalRuntimeAdmission=true'
    $disabledProductionDirect = '-p:EnterpriseDirectLocalRuntimeAdmission=false'
    $developmentDirect = '-p:EnterpriseDirectLocalDevelopmentE2E=true'

    if ($managed -ccontains $productionDirect -or
        $direct -ccontains $productionDirect -or
        $managed -cnotcontains $disabledProductionDirect -or
        $direct -cnotcontains $disabledProductionDirect -or
        $managed -ccontains $developmentDirect -or
        $direct -cnotcontains $developmentDirect) {
        throw 'Development Launcher publish arguments mixed production and Development direct-local admission modes.'
    }
}

function New-DevelopmentReleasePublisherTestArguments {
    param([switch]$DirectLocal)

    if ($DirectLocal) {
        return @(
            'run', '--project', (Join-Path $repositoryRoot 'tests\Ensou.Dsh.Enterprise.DirectLocalReleasePublisherTests\Ensou.Dsh.Enterprise.DirectLocalReleasePublisherTests.csproj'),
            '-c', 'Release', '--no-restore',
            '-p:EnterpriseDirectLocalRuntimeAdmission=true')
    }

    return @(
        'run', '--project', (Join-Path $repositoryRoot 'tests\Ensou.Dsh.Enterprise.ReleasePublisherTests\Ensou.Dsh.Enterprise.ReleasePublisherTests.csproj'),
        '-c', 'Release', '--no-build')
}

function Test-DevelopmentReleasePublisherTestSelectionContract {
    $managed = @(New-DevelopmentReleasePublisherTestArguments)
    $direct = @(New-DevelopmentReleasePublisherTestArguments -DirectLocal)
    $managedProject = Join-Path $repositoryRoot 'tests\Ensou.Dsh.Enterprise.ReleasePublisherTests\Ensou.Dsh.Enterprise.ReleasePublisherTests.csproj'
    $directProject = Join-Path $repositoryRoot 'tests\Ensou.Dsh.Enterprise.DirectLocalReleasePublisherTests\Ensou.Dsh.Enterprise.DirectLocalReleasePublisherTests.csproj'

    if (-not (Test-Path -LiteralPath $managedProject -PathType Leaf) -or
        -not (Test-Path -LiteralPath $directProject -PathType Leaf) -or
        $managed -cnotcontains $managedProject -or
        $managed -ccontains $directProject -or
        $managed -cnotcontains '--no-build' -or
        $managed -ccontains '-p:EnterpriseDirectLocalRuntimeAdmission=true' -or
        $direct -cnotcontains $directProject -or
        $direct -ccontains $managedProject -or
        $direct -ccontains '--no-build' -or
        $direct -cnotcontains '--no-restore' -or
        $direct -cnotcontains '-p:EnterpriseDirectLocalRuntimeAdmission=true') {
        throw 'Development lifecycle selected a ReleasePublisher test project for the wrong admission mode.'
    }
}

function New-DevelopmentApiProfileCreateArguments {
    param(
        [Parameter(Mandatory)][string]$ProfileName,
        [Parameter(Mandatory)][Guid]$OperationId,
        [switch]$DirectLocal
    )

    $arguments = if ($DirectLocal) {
        @(
            'api-profile', 'create-direct-local',
            '--name', $ProfileName,
            '--provider', 'deepseek')
    } else {
        @(
            'api-profile', 'create',
            '--name', $ProfileName,
            '--provider', 'development-e2e',
            '--secret-reference', 'file:development-vault-reference')
    }
    return @($arguments + @(
        '--operation-id', $OperationId.ToString('D'),
        '--reason-code', 'DEVELOPMENT_E2E_PROFILE_CREATE',
        '--expected-version', '0'))
}

function Test-DevelopmentApiProfileCreateArgumentsContract {
    $profileName = 'development-e2e-profile-contract'
    $operationId = [Guid]'10000000-0000-4000-8000-000000000001'
    $managed = @(New-DevelopmentApiProfileCreateArguments `
        -ProfileName $profileName -OperationId $operationId)
    $direct = @(New-DevelopmentApiProfileCreateArguments `
        -ProfileName $profileName -OperationId $operationId -DirectLocal)
    $managedExpected = @(
        'api-profile', 'create', '--name', $profileName,
        '--provider', 'development-e2e',
        '--secret-reference', 'file:development-vault-reference',
        '--operation-id', $operationId.ToString('D'),
        '--reason-code', 'DEVELOPMENT_E2E_PROFILE_CREATE',
        '--expected-version', '0')
    $directExpected = @(
        'api-profile', 'create-direct-local', '--name', $profileName,
        '--provider', 'deepseek',
        '--operation-id', $operationId.ToString('D'),
        '--reason-code', 'DEVELOPMENT_E2E_PROFILE_CREATE',
        '--expected-version', '0')
    if (($managed -join [char]31) -cne ($managedExpected -join [char]31) -or
        ($direct -join [char]31) -cne ($directExpected -join [char]31) -or
        $direct -ccontains '--secret-reference' -or
        $direct -ccontains 'file:development-vault-reference') {
        throw 'Development direct-local API profile creation did not preserve the no-server-secret contract.'
    }
}

function New-DevelopmentGatewayRunnerArguments {
    param(
        [Parameter(Mandatory)][string]$GatewayOrigin,
        [switch]$DirectLocal
    )

    if ($DirectLocal) {
        return
    }
    return @('--gateway-origin', $GatewayOrigin)
}

function Test-DevelopmentGatewayRunnerArgumentsContract {
    $origin = 'https://127.0.0.1:44443/'
    $managed = @(New-DevelopmentGatewayRunnerArguments -GatewayOrigin $origin)
    $direct = @(New-DevelopmentGatewayRunnerArguments `
        -GatewayOrigin $origin -DirectLocal)
    if ($managed.Count -ne 2 -or
        $managed[0] -cne '--gateway-origin' -or
        $managed[1] -cne $origin -or
        $direct.Count -ne 0) {
        throw 'Development direct-local runner arguments leaked a managed gateway origin.'
    }
}

function Test-StaticContract {
    Test-DevelopmentFailureEvidenceSanitizer
    Test-DevelopmentTlsCertificateContract
    Test-DevelopmentEnrollmentConfigurationContract
    Test-EmployeeAssignmentSnapshotContract
    Test-DevelopmentLauncherSelectionContract
    Test-DevelopmentLauncherPublishArgumentsContract
    Test-DevelopmentReleasePublisherTestSelectionContract
    Test-DevelopmentApiProfileCreateArgumentsContract
    Test-DevelopmentGatewayRunnerArgumentsContract
    Assert-ContractText -Path $PSCommandPath -RequiredText @(
        'RuntimeMetadataPath',
        'ExpectedRuntimeReleaseId',
        'AllowLocalLab',
        'enterprise-development-direct-local-runtime-metadata.schema.json',
        'EnterpriseDirectLocalRuntimeAdmission=true',
        'EnterpriseDirectLocalDevelopmentE2E=true',
        'New-DevelopmentDirectLocalCredentialEvidence',
        'Assert-DevelopmentDirectLocalCredentialRetained',
        'Test-EnterpriseDirectLocalCredentialValue.mjs',
        'directLocalCredentialValueVerifications',
        '.dsh-enterprise-dev-e2e',
        'PluginPolicyArchivePath',
        'PluginPolicyMetadataPath',
        'plugin_policy_sha256=$pluginPolicySha256',
        "'--phase', 'install-plugin-policy'",
        "'db\apply-pending-migrations.psql'",
        "'employee', 'preregister'",
        "'activation', 'issue'",
        'ENSOU_DSH_E2E_ACTIVATION_CODE',
        'Invoke-EnrollmentRunner',
        "'/tmp/ensou-dsh-schema/apply-pending-migrations.psql'",
        "'release-policy', 'import'",
        "'refresh-update-required'",
        "'apply-release-update'",
        "'--promotion-result-receipt'",
        'Read-DeviceUpdateReceipts',
        'Assert-DockerDaemonAvailable',
        'This lifecycle will not start Docker',
        'EvidenceDirectory already exists; choose a new path',
        'if ($null -eq $innerException)',
        "-Stage 'installed-bootstrapper-self-check'",
        "-Stage 'installed-launcher-self-check'",
        '-TimeoutSeconds 30',
        '$process.Kill($true)',
        'Read-DevelopmentReleaseUpdateTrust',
        '$policyInstallEvidence.evidence.PSObject.Properties[''releaseUpdateTrust'']',
        '$releaseUpdateEnvironment = Set-ChildEnvironment',
        'initial-sequence-zero-awaiting-authenticated-enrollment',
        'DEVELOPMENT_E2E_INITIAL_DIRECT_FEED',
        '$enrollmentRunnerEnvironment = Set-ChildEnvironment',
        'ENSOU_DSH_E2E_FEED_INTERNAL_SECRET = $feedInternalSecret',
        'ENSOU_DSH_E2E_UPDATE_MANIFEST_URI',
        'ENSOU_DSH_E2E_UPDATE_KEY_Y',
        'CertificateRequest',
        'EphemeralKeySet',
        'SubjectAlternativeNameBuilder',
        '1.3.6.1.5.5.7.3.1',
        'New-DevelopmentTlsCertificate',
        "ENSOU_DEVELOPMENTENROLLMENT__CORPID = 'ww1234567890abcdef'",
        "ENSOU_DEVELOPMENTENROLLMENT__ADMININVITEFALLBACKENABLED = 'true'",
        "ENSOU_DEVELOPMENTGATEWAY__REQUIRERELEASEUPDATEPOLICY = 'true'",
        "'--phase', 'artifact-fixture-contract'",
        'ReleasePublisherTests')
    Assert-ContractText -Path $runtimeAdmissionSource -RequiredText @(
        'RequireOrdinarySingleLink',
        'Read-EnterpriseDevelopmentRuntimeEvidence',
        'Assert-EnterpriseDevelopmentRuntimeExactJsonProperties',
        'Assert-EnterpriseDevelopmentRuntimeEvidenceUnchanged',
        'Open-EnterpriseDevelopmentRuntimePayloadCopy',
        'runtime-files.sha256 does not bind exact source-build.json bytes',
        'source-build.json differs from external metadata provenance',
        'Enterprise Development runtime metadata is for the wrong selected runtime mode.',
        'Enterprise Development direct-local source smoke differs from external metadata.',
        'MetadataLauncherReleaseIds',
        'Assert-EnterpriseDevelopmentPluginRuntimeCompatibility')
    Assert-ContractText -Path $runtimeAdmissionTests -RequiredText @(
        'ZIP source releaseId mismatch',
        'ZIP sourceTag mismatch',
        'ZIP sourceCommit mismatch',
        'ZIP source-build unknown member',
        'ZIP source-build provenance mismatch',
        'repacked archive bytes',
        'metadata unexpected member',
        'metadata type coercion',
        'metadata archive digest tamper',
        'runtime-files source-build digest mismatch',
        'multi-link runtime archive',
        'plugin compatibility runtime mismatch',
        'plugin compatibility launcher mismatch',
        'plugin raw policy identity mismatch',
        'direct metadata in legacy mode',
        'legacy metadata in direct mode',
        'direct metadata wrong runtime profile',
        'direct metadata invalid extracted smoke receipt')
    Assert-ContractText -Path $runnerSource -RequiredText @(
        '"install-plugin-policy"',
        '"enroll-chat"',
        '"refresh-chat"',
        '"refresh-wait-denied"',
        '"assert-enrollment-required"',
        'EnterpriseLoopbackModelProxy',
        'CreateEnterpriseDirectLocal',
        'RequireDirectLocalNoGatewayTransport',
        'DIRECT_LOCAL_DEVICE_KEY_NOT_EXERCISED',
        'EnterpriseReleaseStartupCoordinator',
        'ReadActivePluginPolicyRequired',
        'DevelopmentHttpsArtifactServer.StartAsync(content, authorization: authorization)',
        'artifactServer.CreateClient()',
        'LOCAL_PINNED_HTTPS',
        'artifactHttpsManifestFetchCount',
        'RequireActivePluginPolicyBinding',
        'alternateRawPolicyBindingRejected',
        'EnterpriseDeviceUpdateManagementClient',
        'EnterpriseInstalledReleaseEvidenceProvider',
        'EnterpriseInitialReleaseDeviceUpdateGate',
        'initialReleaseTrust: initialRelease?.CompiledTrust',
        'RequireAuthenticatedInitialReleaseFeedRequests',
        'Only exact direct-local sequence-zero enrollment may receive initial signed release trust.',
        'EnterpriseFeedPromoter',
        'initial-promotion-result-output',
        'update-promotion-result-output',
        'SendExpectedGatewayUpdateRequiredAsync',
        'releaseUpdateTrust = new',
        'ApplyDevelopmentUpdateTrustEnvironment',
        'ClearDevelopmentControlPlaneTrustEnvironment',
        'RedirectStandardError = true',
        'ReadBoundedStandardErrorAsync',
        'MaximumDevelopmentMachineStandardErrorLength',
        'ENSOU_DSH_E2E_MACHINE_FAILURE_V1',
        'launcherHealthProbeDiagnosticStatus',
        'launcherHealthProbeExceptionType',
        'launcherHealthProbeMessage',
        'launcherHealthFilesystemEnvironmentValidated',
        'SanitizeDevelopmentFailureEvidenceMessage',
        'Diagnostic message was redacted.',
        'ENSOU_DSH_E2E_LOCAL_APP_DATA_ROOT',
        'ENSOU_DSH_E2E_USER_PROFILE_ROOT',
        'ENSOU_DSH_E2E_ISOLATION_ID',
        'ENSOU_DSH_E2E_UPDATE_MANIFEST_URI',
        'ENSOU_DSH_E2E_UPDATE_MANIFEST_ORIGIN',
        'ENSOU_DSH_E2E_UPDATE_ARTIFACT_ORIGIN',
        'ENSOU_DSH_E2E_UPDATE_KEY_ID',
        'ENSOU_DSH_E2E_UPDATE_KEY_X',
        'ENSOU_DSH_E2E_UPDATE_KEY_Y',
        'EnterpriseResetExecutor',
        'ServerCertificateCustomValidationCallback')
    Assert-ContractText -Path $installerSource -RequiredText @(
        '--dev-e2e-local-app-data-root',
        '--dev-e2e-user-profile-root',
        '--dev-e2e-no-shell-registration',
        'if (payload is not null && !developmentConsent)',
        'if (developmentE2ELayout && !developmentConsent)',
        'if (payload is not null && !developmentE2ELayout)',
        'developmentE2ELocalAppDataRoot is null',
        'developmentE2EUserProfileRoot is null',
        'if (skipShellRegistration',
        'var embeddedDevelopmentPayload = developmentConsent && payload is null',
        'if (embeddedDevelopmentPayload',
        '!skipShellRegistration')
    Assert-ContractText -Path $bootstrapperSource -RequiredText @(
        '#if ENTERPRISE_DEVELOPMENT_E2E',
        'ENSOU_DSH_E2E_LOCAL_APP_DATA_ROOT',
        'ENSOU_DSH_E2E_USER_PROFILE_ROOT',
        'MachineCommandFailureMessage',
        'Console.Error.WriteLine(MachineCommandFailureMessage)',
        'IsMachineCommand(args)')
    Assert-ContractText -Path $publishedArtifactGate -RequiredText @(
        'Assert-NonInteractiveBootstrapperFailure',
        'Bootstrapper machine-command failure regression timed out',
        'Ensou DSH Enterprise Bootstrapper machine command failed.')
    Assert-ContractText -Path $launcherProfileSource -RequiredText @(
        '#if ENTERPRISE_DEVELOPMENT_E2E',
        'LoadDevelopmentFilesystemInputs',
        'ENSOU_DSH_E2E_ISOLATION_ID')
    Assert-ContractText -Path $launcherAppSource -RequiredText @(
        'new EnterpriseResetExecutor(paths, deviceKeyStore, protectedStore)',
        'new EnterpriseHarnessSession(',
        'ReadActivePluginPolicyRequired(releaseSetPointer)',
        'ReadActivePluginPolicyRequired(current)',
        'releaseSetStore.ReadActivePluginPolicyRequired(releaseSet)',
        'RunRuntimeInstallationHealthCheckAsync',
        'WriteDevelopmentMachineFailure(exception)',
        'ENSOU_DSH_E2E_MACHINE_FAILURE_V1',
        'SanitizeDevelopmentMachineFailureMessage')
    if (-not (Test-Path -LiteralPath $runnerProject -PathType Leaf)) {
        throw "Development E2E runner project is missing: $runnerProject"
    }
    $scriptContent = Get-Content -LiteralPath $PSCommandPath -Raw
    foreach ($unsafeFailureEvidencePattern in @(
        '(?m)exceptionType\s*=\s*\$failureException\.GetType\(\)\.Name',
        '(?m)failureMessage\s*=\s*\$failureException\.Message',
        '(?s)innerExceptionType\s*=\s*if\s*\([^)]*\)\s*\{\s*\$null\s*\}\s*else\s*\{\s*\$innerException\.GetType\(\)\.Name\s*\}',
        '(?s)innerFailureMessage\s*=\s*if\s*\([^)]*\)\s*\{\s*\$null\s*\}\s*else\s*\{\s*\$innerException\.Message\s*\}')) {
        if ([Text.RegularExpressions.Regex]::IsMatch(
                $scriptContent,
                $unsafeFailureEvidencePattern,
                [Text.RegularExpressions.RegexOptions]::CultureInvariant)) {
            throw 'Development E2E summary must not persist a raw exception type or message.'
        }
    }
    foreach ($safeFailureEvidence in @(
        'exceptionType = ConvertTo-SafeDevelopmentFailureEvidenceType',
        'failureMessage = ConvertTo-SafeDevelopmentFailureEvidenceMessage',
        'innerExceptionType = if ($null -eq $innerException) { $null } else { ConvertTo-SafeDevelopmentFailureEvidenceType',
        'innerFailureMessage = if ($null -eq $innerException) { $null } else { ConvertTo-SafeDevelopmentFailureEvidenceMessage')) {
        if (-not $scriptContent.Contains(
                $safeFailureEvidence,
                [StringComparison]::Ordinal)) {
            throw 'Development E2E summary is missing bounded sanitized failure evidence.'
        }
    }
    $unsafeStrictModeMemberAccess = 'InnerException?' + '.GetType().Name'
    if ($scriptContent.Contains($unsafeStrictModeMemberAccess, [StringComparison]::Ordinal)) {
        throw 'Development E2E failure reporting must explicitly handle a missing inner exception under StrictMode.'
    }
    $unsafeDirectTrustAccess =
        '$policyInstallEvidence.evidence.' + 'releaseUpdateTrust'
    if ($scriptContent.Contains($unsafeDirectTrustAccess, [StringComparison]::Ordinal)) {
        throw 'Development E2E must read the exact nested release-update trust property.'
    }
    $policyInstallIndex = $scriptContent.LastIndexOf(
        '$policyInstallArguments = @(',
        [StringComparison]::Ordinal)
    $bootstrapperSelfCheckIndex = $scriptContent.LastIndexOf(
        "-Stage 'installed-bootstrapper-self-check'",
        [StringComparison]::Ordinal)
    if ($policyInstallIndex -lt 0 -or
        $bootstrapperSelfCheckIndex -lt 0 -or
        $policyInstallIndex -ge $bootstrapperSelfCheckIndex) {
        throw 'Development E2E must establish signed release trust before installed self-checks.'
    }
    $runnerContent = Get-Content -LiteralPath $runnerSource -Raw
    if ($runnerContent.Contains(
        'ENSOU_DSH_E2E_UPDATE_PRIVATE',
        [StringComparison]::Ordinal)) {
        throw 'Development E2E health children must never receive release private-key material.'
    }
    if ($runnerContent.Contains(
            'failureMessage = exception.Message',
            [StringComparison]::Ordinal) -or
        $runnerContent.Contains(
            'innerFailureMessage = exception.InnerException?.Message',
            [StringComparison]::Ordinal)) {
        throw 'Development E2E failure evidence must not persist raw exception messages.'
    }
    $launcherAppContent = Get-Content -LiteralPath $launcherAppSource -Raw
    if ($launcherAppContent -notmatch
        '(?s)#if ENTERPRISE_DEVELOPMENT_E2E\s+else\s*\{\s*WriteDevelopmentMachineFailure\(exception\);\s*\}\s*#endif') {
        throw 'Enterprise Launcher machine diagnostics must remain development-E2E-only.'
    }
    Test-DevelopmentReleaseUpdateTrustValidation
    & $runtimeAdmissionTests
    if ($EnterpriseDirectLocal) {
        & (Join-Path $PSScriptRoot 'Test-EnterpriseDirectLocalCredentialEvidence.ps1') -ContractOnly
    }
    $transportContract = if ($EnterpriseDirectLocal) {
        'direct-local no-server-secret/no-gateway model-traffic boundary'
    } else {
        'managed gateway/SSE boundary'
    }
    Write-Host "PASS  Enterprise Development lifecycle contract: isolated install roots, real plugin-policy release activation and lease binding, exact trust pin, administrator-invite activation/refresh/reset phases, $transportContract, and production compile-time boundary are present."
}

function Resolve-SafeExistingPath {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][bool]$Directory
    )

    if ($Path.StartsWith('\\', [StringComparison]::Ordinal) -or
        $Path.StartsWith('//', [StringComparison]::Ordinal)) {
        throw "Network paths are not accepted: $Path"
    }
    $resolved = [IO.Path]::GetFullPath($Path)
    $item = Get-Item -LiteralPath $resolved -Force
    if ($Directory -ne [bool]$item.PSIsContainer) {
        throw "Path type mismatch: $resolved"
    }
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Filesystem links are not accepted: $resolved"
    }
    $current = if ($item.PSIsContainer) { $item.Parent } else { $item.Directory }
    while ($null -ne $current) {
        if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Filesystem links are not accepted: $resolved"
        }
        $current = $current.Parent
    }
    return $resolved
}

function Assert-NoDuplicateJsonMembers {
    param(
        [Parameter(Mandatory)][Text.Json.JsonElement]$Element,
        [Parameter(Mandatory)][string]$Label
    )

    if ($Element.ValueKind -eq [Text.Json.JsonValueKind]::Object) {
        $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($property in $Element.EnumerateObject()) {
            if (-not $names.Add($property.Name)) {
                throw "$Label contains a duplicate JSON member: $($property.Name)"
            }
            Assert-NoDuplicateJsonMembers -Element $property.Value -Label $Label
        }
    }
    elseif ($Element.ValueKind -eq [Text.Json.JsonValueKind]::Array) {
        foreach ($item in $Element.EnumerateArray()) {
            Assert-NoDuplicateJsonMembers -Element $item -Label $Label
        }
    }
}

function Resolve-DevelopmentLauncherSelection {
    param(
        [Parameter(Mandatory)][string[]]$ReleaseIds,
        [AllowEmptyString()][string]$SelectedReleaseId
    )
    if ($ReleaseIds.Count -lt 1 -or $ReleaseIds.Count -gt 64 -or
        @($ReleaseIds | Where-Object { $_ -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$' }).Count -ne 0 -or
        @($ReleaseIds | Select-Object -Unique).Count -ne $ReleaseIds.Count) {
        throw 'Launcher compatibility requires a bounded unique release identity set.'
    }
    if ([string]::IsNullOrWhiteSpace($SelectedReleaseId)) {
        if ($ReleaseIds.Count -ne 1) {
            throw 'Multiple compatible Launchers require an explicit selected Launcher identity.'
        }
        return $ReleaseIds[0]
    }
    if ($ReleaseIds -cnotcontains $SelectedReleaseId) {
        throw 'Selected Launcher is absent from the exact policy compatibility set.'
    }
    return $SelectedReleaseId
}

function Test-DevelopmentLauncherSelectionContract {
    if ((Resolve-DevelopmentLauncherSelection -ReleaseIds @('launcher-v1') -SelectedReleaseId '') -cne 'launcher-v1' -or
        (Resolve-DevelopmentLauncherSelection -ReleaseIds @('launcher-v1','launcher-v2') -SelectedReleaseId 'launcher-v2') -cne 'launcher-v2') {
        throw 'Explicit Launcher selection positive fixture failed.'
    }
    foreach ($fixture in @(
        @{ids=@('launcher-v1','launcher-v2'); selected=''},
        @{ids=@('launcher-v1','launcher-v2'); selected='launcher-v3'},
        @{ids=@('launcher-v1','launcher-v1'); selected='launcher-v1'},
        @{ids=@('launcher-v1','invalid/id'); selected='launcher-v1'})) {
        $rejected = $false
        try { [void](Resolve-DevelopmentLauncherSelection -ReleaseIds $fixture.ids -SelectedReleaseId $fixture.selected) }
        catch { $rejected = $true }
        if (-not $rejected) { throw 'Explicit Launcher selection negative fixture was accepted.' }
    }
}

function Read-PluginPolicyBuildEvidence {
    param(
        [Parameter(Mandatory)][string]$ArchivePath,
        [Parameter(Mandatory)][string]$MetadataPath,
        [Parameter(Mandatory)][string]$ExpectedRuntimeReleaseId,
        [string]$ExpectedLauncherReleaseId
    )

    $metadataBytes = [IO.File]::ReadAllBytes($MetadataPath)
    if ($metadataBytes.Length -le 0 -or $metadataBytes.Length -gt 4MB) {
        throw 'Managed plugin-policy metadata size is invalid.'
    }
    $metadataDocument = [Text.Json.JsonDocument]::Parse(
        [ReadOnlyMemory[byte]]::new($metadataBytes))
    try {
        Assert-NoDuplicateJsonMembers `
            -Element $metadataDocument.RootElement `
            -Label 'Managed plugin-policy metadata'
    }
    finally {
        $metadataDocument.Dispose()
    }
    $strictUtf8 = [Text.UTF8Encoding]::new($false, $true)
    $metadata = $strictUtf8.GetString($metadataBytes) | ConvertFrom-Json -Depth 32
    $rootProperties = [string[]]$metadata.PSObject.Properties.Name
    $policyProperties = [string[]]$metadata.policy.PSObject.Properties.Name
    $compatibilityProperties = [string[]]$metadata.compatibility.PSObject.Properties.Name
    $artifactProperties = [string[]]$metadata.artifact.PSObject.Properties.Name
    if ([string]::Join("`n", $rootProperties) -cne [string]::Join("`n", @(
            'schemaVersion', 'signingStatus', 'builder', 'policy',
            'compatibility', 'inputs', 'artifact')) -or
        [string]::Join("`n", $policyProperties) -cne [string]::Join("`n", @(
            'policyId', 'generation', 'fileName', 'sizeBytes', 'sha256',
            'critical', 'revoked')) -or
        [string]::Join("`n", $compatibilityProperties) -cne [string]::Join("`n", @(
            'launcherReleaseIds', 'runtimeReleaseIds')) -or
        [string]::Join("`n", $artifactProperties) -cne [string]::Join("`n", @(
            'fileName', 'sizeBytes', 'sha256'))) {
        throw 'Managed plugin-policy metadata properties are absent, unexpected, or reordered.'
    }
    if ([int]$metadata.schemaVersion -ne 1 -or
        [string]$metadata.signingStatus -cne 'UNSIGNED_CANDIDATE' -or
        [string]$metadata.policy.fileName -cne 'plugin-policy.json' -or
        [bool]$metadata.policy.revoked -or
        [long]$metadata.policy.generation -le 0 -or
        [string]$metadata.policy.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$metadata.artifact.sha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'Managed plugin-policy metadata identity or digest contract is invalid.'
    }
    $launcherReleaseIds = @($metadata.compatibility.launcherReleaseIds)
    $runtimeReleaseIds = @($metadata.compatibility.runtimeReleaseIds)
    $selectedLauncher = Resolve-DevelopmentLauncherSelection `
        -ReleaseIds ([string[]]$launcherReleaseIds) -SelectedReleaseId $ExpectedLauncherReleaseId
    if ($runtimeReleaseIds.Count -lt 1 -or
        $runtimeReleaseIds.Count -gt 64 -or
        @($runtimeReleaseIds | Where-Object {
            [string]$_ -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$'
        }).Count -ne 0 -or
        @($runtimeReleaseIds | Select-Object -Unique).Count -ne $runtimeReleaseIds.Count) {
        throw 'Development lifecycle requires a bounded unique runtime compatibility set.'
    }
    $parsedPolicyId = [Guid]::Empty
    $policyId = [string]$metadata.policy.policyId
    if (-not [Guid]::TryParseExact($policyId, 'D', [ref]$parsedPolicyId) -or
        $parsedPolicyId.ToString('D') -cne $policyId) {
        throw 'Managed plugin-policy metadata policyId is not canonical.'
    }

    $archiveItem = Get-Item -LiteralPath $ArchivePath
    $archiveSha256 = (Get-FileHash -LiteralPath $ArchivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $metadataSha256 = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($metadataBytes)).ToLowerInvariant()
    if ([string]$metadata.artifact.fileName -cne $archiveItem.Name -or
        [long]$metadata.artifact.sizeBytes -ne $archiveItem.Length -or
        [string]$metadata.artifact.sha256 -cne $archiveSha256) {
        throw 'Managed plugin-policy metadata does not match the archive bytes.'
    }

    $archive = [IO.Compression.ZipFile]::OpenRead($ArchivePath)
    try {
        $policyEntries = @($archive.Entries | Where-Object {
            $_.FullName -ceq 'plugin-policy.json'
        })
        if ($policyEntries.Count -ne 1) {
            throw 'Managed plugin-policy archive must contain one exact root plugin-policy.json.'
        }
        $policyEntry = $policyEntries[0]
        if ($policyEntry.Length -le 0 -or $policyEntry.Length -gt 4MB -or
            [long]$metadata.policy.sizeBytes -ne $policyEntry.Length) {
            throw 'Managed plugin-policy raw policy size is invalid.'
        }
        $policyStream = $policyEntry.Open()
        try {
            $policyMemory = [IO.MemoryStream]::new([int]$policyEntry.Length)
            try {
                $policyStream.CopyTo($policyMemory)
                if ($policyMemory.Length -ne $policyEntry.Length) {
                    throw 'Managed plugin-policy raw policy length changed while reading.'
                }
                $policyBytes = $policyMemory.ToArray()
                $policySha256 = [Convert]::ToHexString(
                    [Security.Cryptography.SHA256]::HashData($policyBytes)).ToLowerInvariant()
            }
            finally {
                $policyMemory.Dispose()
            }
        }
        finally {
            $policyStream.Dispose()
        }
    }
    finally {
        $archive.Dispose()
    }
    if ($policySha256 -cne [string]$metadata.policy.sha256) {
        throw 'Managed plugin-policy metadata does not match raw plugin-policy.json bytes.'
    }
    Assert-EnterpriseDevelopmentPluginRuntimeCompatibility `
        -MetadataLauncherReleaseIds ([string[]]$launcherReleaseIds) `
        -MetadataRuntimeReleaseIds ([string[]]$runtimeReleaseIds) `
        -PolicyBytes $policyBytes `
        -ExpectedRuntimeReleaseId $ExpectedRuntimeReleaseId `
        -ExpectedPolicyId $policyId `
        -ExpectedGeneration ([long]$metadata.policy.generation) `
        -ExpectedCritical ([bool]$metadata.policy.critical) `
        -ExpectedRevoked ([bool]$metadata.policy.revoked)
    if ((Get-FileHash -LiteralPath $ArchivePath -Algorithm SHA256).Hash.ToLowerInvariant() -cne
            $archiveSha256 -or
        (Get-FileHash -LiteralPath $MetadataPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne
            $metadataSha256) {
        throw 'Managed plugin-policy inputs changed while lifecycle evidence was read.'
    }

    return [pscustomobject]@{
        PolicyId = $policyId
        Generation = [long]$metadata.policy.generation
        PolicySha256 = $policySha256
        ArchiveSha256 = $archiveSha256
        MetadataSha256 = $metadataSha256
        LauncherReleaseId = $selectedLauncher
        RuntimeReleaseId = $ExpectedRuntimeReleaseId
        RuntimeCompatibilityValidated = $true
    }
}

function Test-CompleteTargetRuntimeTuple {
    param([Parameter(Mandatory)][AllowEmptyCollection()][AllowEmptyString()][object[]]$Values)

    if ($Values.Count -ne 7) {
        throw 'The target runtime/plugin tuple must contain exactly seven input fields.'
    }
    $count = @($Values | Where-Object {
        -not [string]::IsNullOrWhiteSpace([string]$_)
    }).Count
    if ($count -ne 0 -and $count -ne $Values.Count) {
        throw 'Target runtime archive/metadata, expected release/file/hash, and target plugin archive/metadata must be supplied together.'
    }
    return $count -eq $Values.Count
}

function Assert-DistinctDevelopmentRuntimeTuple {
    param(
        [Parameter(Mandatory)]$InitialRuntime,
        [Parameter(Mandatory)]$InitialPolicy,
        [Parameter(Mandatory)]$TargetRuntime,
        [Parameter(Mandatory)]$TargetPolicy
    )

    # The source-build document is inside the archive and admitted against the
    # metadata. Its difference excludes a ZIP timestamp-only repack. The runner
    # additionally checks the complete archive tree before making sequence 2.
    if ($TargetRuntime.ReleaseId -ceq $InitialRuntime.ReleaseId -or
        $TargetRuntime.ArchiveSha256 -ceq $InitialRuntime.ArchiveSha256 -or
        $TargetRuntime.SourceBuildSha256 -ceq $InitialRuntime.SourceBuildSha256) {
        throw 'A target runtime requires distinct release, archive, and in-archive source-build identities.'
    }
    if (-not $TargetPolicy.RuntimeCompatibilityValidated -or
        $TargetPolicy.RuntimeReleaseId -cne $TargetRuntime.ReleaseId -or
        $TargetPolicy.LauncherReleaseId -cne $InitialPolicy.LauncherReleaseId -or
        $TargetPolicy.PolicyId -cne $InitialPolicy.PolicyId -or
        $TargetPolicy.Generation -ne $InitialPolicy.Generation -or
        $TargetPolicy.PolicySha256 -cne $InitialPolicy.PolicySha256 -or
        $TargetPolicy.ArchiveSha256 -cne $InitialPolicy.ArchiveSha256) {
        throw 'Runtime-only upgrade requires unchanged Launcher and policy bytes with explicit compatibility for both runtimes.'
    }
}

function Invoke-NativeChecked {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$ArgumentList,
        [string]$FailureMessage = 'Native command failed.'
    )

    & $FilePath @ArgumentList
    if ($LASTEXITCODE -ne 0) {
        throw "$FailureMessage Exit code: $LASTEXITCODE"
    }
}

function Assert-DockerDaemonAvailable {
    $blockingMessage =
        'Docker daemon is unavailable. This lifecycle will not start Docker; start Docker outside this script, then rerun with a new EvidenceDirectory.'
    $dockerCommands = @(Get-Command docker -CommandType Application -ErrorAction SilentlyContinue)
    if ($dockerCommands.Count -eq 0) {
        throw [InvalidOperationException]::new($blockingMessage)
    }

    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $dockerCommands[0].Source
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    [void]$startInfo.ArgumentList.Add('version')
    [void]$startInfo.ArgumentList.Add('--format')
    [void]$startInfo.ArgumentList.Add('{{.Server.Version}}')

    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        try {
            if (-not $process.Start()) {
                throw 'Docker preflight process did not start.'
            }
        }
        catch {
            throw [InvalidOperationException]::new($blockingMessage, $_.Exception)
        }

        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(15000)) {
            try {
                $process.Kill($true)
                $process.WaitForExit(5000) | Out-Null
            }
            catch { }
            throw [InvalidOperationException]::new($blockingMessage)
        }

        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0 -or [string]::IsNullOrWhiteSpace($stdout)) {
            throw [InvalidOperationException]::new($blockingMessage)
        }
        $stdout = [string]::Empty
        $stderr = [string]::Empty
    }
    finally {
        $process.Dispose()
    }
}

function Invoke-HiddenChecked {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$ArgumentList,
        [Parameter(Mandatory)][string]$WorkingDirectory,
        [string]$FailureMessage = 'Hidden process failed.',
        [ValidateRange(0, 86400)][int]$TimeoutSeconds = 0,
        [string]$Stage = 'hidden-process'
    )

    if ($TimeoutSeconds -eq 0) {
        $process = Start-Process `
            -FilePath $FilePath `
            -ArgumentList $ArgumentList `
            -WorkingDirectory $WorkingDirectory `
            -WindowStyle Hidden `
            -PassThru `
            -Wait
        try {
            if ($process.ExitCode -ne 0) {
                throw "$FailureMessage Exit code: $($process.ExitCode)"
            }
        }
        finally {
            $process.Dispose()
        }
        return
    }

    $process = Start-Process `
        -FilePath $FilePath `
        -ArgumentList $ArgumentList `
        -WorkingDirectory $WorkingDirectory `
        -WindowStyle Hidden `
        -PassThru
    try {
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            try {
                $process.Kill($true)
                if (-not $process.WaitForExit(5000)) {
                    throw 'Process tree did not exit after termination.'
                }
            }
            catch {
                throw "$FailureMessage Stage '$Stage' timed out after $TimeoutSeconds seconds, and process-tree termination did not complete."
            }
            throw "$FailureMessage Stage '$Stage' timed out after $TimeoutSeconds seconds; the process tree was terminated."
        }
        if ($process.ExitCode -ne 0) {
            throw "$FailureMessage Stage '$Stage' exited with code $($process.ExitCode)."
        }
    }
    finally {
        $process.Dispose()
    }
}

function Get-FreeTcpPort {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    try {
        $listener.Start()
        return ([Net.IPEndPoint]$listener.LocalEndpoint).Port
    }
    finally {
        $listener.Stop()
    }
}

function ConvertTo-Base64Url {
    param([Parameter(Mandatory)][byte[]]$Bytes)
    return [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Set-ChildEnvironment {
    param([Parameter(Mandatory)][hashtable]$Values)

    $original = @{}
    foreach ($name in $Values.Keys) {
        $original[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
        [Environment]::SetEnvironmentVariable($name, [string]$Values[$name], 'Process')
    }
    return $original
}

function Restore-ChildEnvironment {
    param([Parameter(Mandatory)][hashtable]$Original)

    foreach ($name in $Original.Keys) {
        [Environment]::SetEnvironmentVariable($name, $Original[$name], 'Process')
    }
}

function Wait-HttpsLive {
    param(
        [Parameter(Mandatory)][string]$Origin,
        [Parameter(Mandatory)][Diagnostics.Process]$Process
    )

    $last = $null
    foreach ($attempt in 1..80) {
        if ($Process.HasExited) {
            throw "Control-plane API exited before liveness. Exit code: $($Process.ExitCode)"
        }
        try {
            $response = Invoke-WebRequest `
                -Uri ($Origin + 'health/live') `
                -SkipCertificateCheck `
                -NoProxy `
                -TimeoutSec 2
            if ($response.StatusCode -eq 200) {
                return
            }
        }
        catch {
            $last = $_.Exception.GetType().Name
        }
        Start-Sleep -Milliseconds 250
    }
    throw "Control-plane API did not become live. Last probe: $last"
}

function Wait-TcpLive {
    param(
        [Parameter(Mandatory)][string]$HostName,
        [Parameter(Mandatory)][int]$Port
    )

    foreach ($attempt in 1..60) {
        $client = [Net.Sockets.TcpClient]::new()
        try {
            $connect = $client.ConnectAsync($HostName, $Port)
            if ($connect.Wait(250) -and $client.Connected) {
                return
            }
        }
        catch {
            if ($attempt -eq 60) {
                throw "TCP endpoint $HostName`:$Port did not become reachable."
            }
        }
        finally {
            $client.Dispose()
        }

        Start-Sleep -Milliseconds 250
    }

    throw "TCP endpoint $HostName`:$Port did not become reachable."
}

function Wait-LocalEligibilityClock {
    param([Parameter(Mandatory)][DateTimeOffset]$EligibleAtUtc)

    $deadline = [DateTimeOffset]::UtcNow.AddMinutes(5)
    while ([DateTimeOffset]::UtcNow -lt $EligibleAtUtc) {
        if ([DateTimeOffset]::UtcNow -ge $deadline) {
            throw 'The local API clock did not reach the database entitlement timestamp within five minutes.'
        }
        Start-Sleep -Milliseconds 250
    }
}

function Wait-ExactFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][Diagnostics.Process]$Process,
        [int]$Seconds = 90
    )

    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($Seconds)
    while ([DateTimeOffset]::UtcNow -lt $deadline) {
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            return
        }
        if ($Process.HasExited) {
            throw "Lifecycle runner exited before its ready signal. Exit code: $($Process.ExitCode)"
        }
        Start-Sleep -Milliseconds 100
    }
    throw "Lifecycle runner did not create its ready signal within $Seconds seconds."
}

function Wait-ProcessChecked {
    param(
        [Parameter(Mandatory)][Diagnostics.Process]$Process,
        [int]$Seconds = 120,
        [Parameter(Mandatory)][string]$Description
    )

    if (-not $Process.WaitForExit($Seconds * 1000)) {
        try { $Process.Kill($true) } catch { }
        throw "$Description timed out."
    }
    if ($Process.ExitCode -ne 0) {
        throw "$Description failed with exit code $($Process.ExitCode)."
    }
}

function Invoke-Runner {
    param(
        [Parameter(Mandatory)][string]$RunnerDll,
        [Parameter(Mandatory)][string[]]$Arguments,
        [Parameter(Mandatory)][string]$WorkingDirectory
    )

    Assert-NoActivationEnvironment

    Invoke-NativeChecked `
        -FilePath 'dotnet' `
        -ArgumentList (@($RunnerDll) + $Arguments) `
        -FailureMessage 'Enterprise Development lifecycle runner failed.'
}

function Start-Runner {
    param(
        [Parameter(Mandatory)][string]$RunnerDll,
        [Parameter(Mandatory)][string[]]$Arguments,
        [Parameter(Mandatory)][string]$WorkingDirectory,
        [Parameter(Mandatory)][string]$StdoutPath,
        [Parameter(Mandatory)][string]$StderrPath
    )

    Assert-NoActivationEnvironment

    $process = Start-Process `
        -FilePath 'dotnet' `
        -ArgumentList (@($RunnerDll) + $Arguments) `
        -WorkingDirectory $WorkingDirectory `
        -WindowStyle Hidden `
        -RedirectStandardOutput $StdoutPath `
        -RedirectStandardError $StderrPath `
        -PassThru
    $script:ownedLifecycleRunners.Add($process)
    return $process
}

function Stop-OwnedLifecycleRunners {
    param([Parameter(Mandatory)][AllowEmptyCollection()]
        [Collections.Generic.List[Diagnostics.Process]]$Processes)

    $failures = [Collections.Generic.List[string]]::new()
    $confirmedExited = 0
    foreach ($ownedRunner in $Processes) {
        try {
            if (-not $ownedRunner.HasExited) {
                $ownedRunner.Kill($true)
            }
            if (-not $ownedRunner.WaitForExit(10000)) {
                throw [TimeoutException]::new('An owned lifecycle runner did not exit.')
            }
            $confirmedExited++
        }
        catch {
            $failures.Add($_.Exception.GetType().Name)
        }
        finally {
            $ownedRunner.Dispose()
        }
    }
    return [pscustomobject]@{
        trackedRunnerCount = $Processes.Count
        confirmedExitedRunnerCount = $confirmedExited
        failureTypes = @($failures)
        status = if ($failures.Count -eq 0) { 'passed' } else { 'failed' }
    }
}

function Assert-NoActivationEnvironment {
    if (-not [string]::IsNullOrEmpty(
            [Environment]::GetEnvironmentVariable(
                'ENSOU_DSH_E2E_ACTIVATION_CODE',
                'Process'))) {
        throw 'The one-time activation code leaked into the parent runner environment.'
    }
}

function Invoke-EnrollmentRunner {
    param(
        [Parameter(Mandatory)][string]$RunnerDll,
        [Parameter(Mandatory)][string[]]$Arguments,
        [Parameter(Mandatory)][string]$WorkingDirectory,
        [Parameter(Mandatory)][ref]$ActivationCode
    )

    Assert-NoActivationEnvironment
    $codeForChild = [string]$ActivationCode.Value
    if ($codeForChild -cnotmatch '^[A-Za-z0-9_-]{43}$') {
        throw 'Administrator CLI returned a non-canonical activation code.'
    }

    $process = $null
    try {
        [Environment]::SetEnvironmentVariable(
            'ENSOU_DSH_E2E_ACTIVATION_CODE',
            $codeForChild,
            'Process')
        $process = Start-Process `
            -FilePath 'dotnet' `
            -ArgumentList (@($RunnerDll) + $Arguments) `
            -WorkingDirectory $WorkingDirectory `
            -WindowStyle Hidden `
            -PassThru
    }
    finally {
        [Environment]::SetEnvironmentVariable(
            'ENSOU_DSH_E2E_ACTIVATION_CODE',
            $null,
            'Process')
        $ActivationCode.Value = [string]::Empty
        $codeForChild = [string]::Empty
    }

    Assert-NoActivationEnvironment
    if ($null -eq $process) {
        throw 'Enrollment lifecycle runner did not start.'
    }
    # Direct first enrollment now stages the signed release and runs the real
    # five-minute cold-start health gate before the device-policy receipt. Keep
    # this outer process bound above that nested gate plus staging overhead;
    # the product health deadline and every success check remain unchanged.
    $enrollmentTimeoutSeconds = if ($EnterpriseDirectLocal) { 600 } else { 120 }
    Wait-ProcessChecked `
        -Process $process `
        -Seconds $enrollmentTimeoutSeconds `
        -Description 'Administrator-invite enrollment lifecycle runner'
}

function Invoke-AdminJson {
    param(
        [Parameter(Mandatory)][string]$AdminDll,
        [Parameter(Mandatory)][string[]]$Arguments,
        [Parameter(Mandatory)][string]$ConnectionString
    )

    $previous = [Environment]::GetEnvironmentVariable('ENSOU_DSH_ADMIN_POSTGRES', 'Process')
    try {
        [Environment]::SetEnvironmentVariable(
            'ENSOU_DSH_ADMIN_POSTGRES',
            $ConnectionString,
            'Process')
        $output = & dotnet $AdminDll @Arguments
        if ($LASTEXITCODE -ne 0) {
            throw "Administrator command failed with exit code $LASTEXITCODE."
        }
        return ($output -join [Environment]::NewLine) | ConvertFrom-Json
    }
    finally {
        [Environment]::SetEnvironmentVariable(
            'ENSOU_DSH_ADMIN_POSTGRES',
            $previous,
            'Process')
    }
}

function Read-DeviceUpdateReceipts {
    param(
        [Parameter(Mandatory)][string]$ContainerName,
        [Parameter(Mandatory)][string]$DatabaseName,
        [Parameter(Mandatory)][string]$BindingId
    )

    if ($BindingId -cnotmatch '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$') {
        throw 'Device update receipt query binding id is not canonical.'
    }
    $query = @"
SELECT COALESCE(jsonb_agg(jsonb_build_object(
    'receipt_id', receipt_id,
    'binding_id', binding_id,
    'channel', channel,
    'release_set_id', release_set_id,
    'manifest_sequence', manifest_sequence,
    'manifest_sha256', encode(manifest_sha256, 'hex'),
    'active_sequence', active_sequence,
    'outcome', outcome,
    'client_observed_at', client_observed_at,
    'received_at', received_at)
    ORDER BY receipt_order), '[]'::jsonb)::text
FROM public.device_update_receipts
WHERE binding_id = '$BindingId'::uuid;
"@
    $raw = (& docker exec $ContainerName psql -U postgres -d $DatabaseName `
        -v ON_ERROR_STOP=1 -tA -c $query | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($raw)) {
        throw 'PostgreSQL device update receipt evidence query failed.'
    }
    return @($raw | ConvertFrom-Json -Depth 16)
}

function Write-PassedEvidence {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Evidence
    )

    [ordered]@{
        schemaVersion = 1
        status = 'passed'
        completedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
        evidence = $Evidence
    } | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $Path -Encoding utf8NoBOM
}

function New-AdminActivationCode {
    param(
        [Parameter(Mandatory)][string]$AdminDll,
        [Parameter(Mandatory)][string[]]$Arguments,
        [Parameter(Mandatory)][string]$ConnectionString,
        [Parameter(Mandatory)][Guid]$ExpectedEmployeeId
    )

    Assert-NoActivationEnvironment
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = 'dotnet'
    $startInfo.WorkingDirectory = [IO.Path]::GetDirectoryName($AdminDll)
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    [void]$startInfo.ArgumentList.Add($AdminDll)
    foreach ($argument in $Arguments) {
        [void]$startInfo.ArgumentList.Add($argument)
    }
    $startInfo.Environment['ENSOU_DSH_ADMIN_POSTGRES'] = $ConnectionString
    [void]$startInfo.Environment.Remove('ENSOU_DSH_E2E_ACTIVATION_CODE')

    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $stdout = [string]::Empty
    $stderr = [string]::Empty
    $document = $null
    try {
        if (-not $process.Start()) {
            throw 'Administrator activation issue process did not start.'
        }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) {
            throw "Administrator activation issue failed with exit code $($process.ExitCode)."
        }
        if (-not [string]::IsNullOrWhiteSpace($stderr)) {
            throw 'Administrator activation issue unexpectedly wrote to stderr.'
        }

        $document = [Text.Json.JsonDocument]::Parse($stdout)
        Assert-NoDuplicateJsonMembers `
            -Element $document.RootElement `
            -Label 'Administrator activation issue result'
        $root = $document.RootElement
        $properties = @($root.EnumerateObject() | ForEach-Object Name)
        if ([string]::Join("`n", $properties) -cne [string]::Join("`n", @(
                'activation_id',
                'employee_id',
                'state',
                'expires_at',
                'claim_attempt_limit',
                'activation_code'))) {
            throw 'Administrator activation issue returned an unexpected JSON contract.'
        }
        if ($root.GetProperty('employee_id').GetGuid() -ne $ExpectedEmployeeId -or
            $root.GetProperty('state').GetString() -cne 'ISSUED' -or
            $root.GetProperty('claim_attempt_limit').GetInt32() -ne 5 -or
            $root.GetProperty('expires_at').GetDateTimeOffset() -le [DateTimeOffset]::UtcNow) {
            throw 'Administrator activation issue receipt is invalid.'
        }
        $activationCode = $root.GetProperty('activation_code').GetString()
        if ($activationCode -cnotmatch '^[A-Za-z0-9_-]{43}$') {
            throw 'Administrator CLI returned a non-canonical activation code.'
        }
        return $activationCode
    }
    finally {
        if ($null -ne $document) { $document.Dispose() }
        $stdout = [string]::Empty
        $stderr = [string]::Empty
        $process.Dispose()
        Assert-NoActivationEnvironment
    }
}

function New-CommonRunnerArguments {
    param(
        [Parameter(Mandatory)][string]$Phase,
        [Parameter(Mandatory)][string]$EvidencePath
    )

    $runtimeProfile = if ($EnterpriseDirectLocal) {
        'enterprise-direct-local'
    } else {
        'enterprise-managed'
    }

    $arguments = @(
        '--phase', $Phase,
        '--isolation-id', $runId,
        '--evidence', $EvidencePath,
        '--local-app-data-root', $localAppDataRoot,
        '--user-profile-root', $userProfileRoot,
        '--launcher-release-id', $launcherReleaseId,
        '--runtime-release-id', $runtimeReleaseId,
        '--runtime-profile', $runtimeProfile,
        '--control-origin', $controlOrigin)
    $arguments += @(New-DevelopmentGatewayRunnerArguments `
        -GatewayOrigin $controlOrigin `
        -DirectLocal:$EnterpriseDirectLocal)
    $arguments += @(
        '--lease-key-id', $developmentConfig['ENSOU_DEVELOPMENTENROLLMENT__LEASEKEYID'],
        '--lease-key-x', $developmentConfig['ENSOU_DEVELOPMENTENROLLMENT__LEASEPUBLICX'],
        '--lease-key-y', $developmentConfig['ENSOU_DEVELOPMENTENROLLMENT__LEASEPUBLICY'],
        '--server-cert-sha256', $certificateSha256)
    return $arguments
}

function Read-FeedAuthorizationAudit {
    param(
        [Parameter(Mandatory)][string]$ContainerName,
        [Parameter(Mandatory)][string]$DatabaseName,
        [Parameter(Mandatory)][string]$BindingId
    )

    if ($BindingId -cnotmatch '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$') {
        throw 'Feed authorization audit query binding id is not canonical.'
    }
    $query = @"
SELECT COALESCE(jsonb_agg(jsonb_build_object(
    'requestId', request_id,
    'bindingId', binding_id,
    'originalUri', original_feed_uri,
    'outcome', exposure,
    'policyId', policy_id,
    'policyVersion', policy_version
) ORDER BY decided_at), '[]'::jsonb)::text
FROM public.stable_feed_authorization_decisions
WHERE binding_id = '$BindingId'
"@
    $output = & docker exec $ContainerName psql -X -U postgres -d $DatabaseName `
        -v ON_ERROR_STOP=1 -tAc $query
    if ($LASTEXITCODE -ne 0) {
        throw 'Feed authorization audit query failed.'
    }
    return ($output -join [Environment]::NewLine) | ConvertFrom-Json
}

function New-DevelopmentSignedPolicyHandoff {
    param(
        [Parameter(Mandatory)][string]$PromotionResultPath,
        [Parameter(Mandatory)][string]$HandoffPath
    )
    $promotionResult = Get-Content -Raw -LiteralPath $PromotionResultPath | ConvertFrom-Json -Depth 16
    $promotedManifestPath = [string]$promotionResult.channelManifestPath
    $promotionJournalPath = [string]$promotionResult.promotionJournalEntryPath
    if ([string]$promotionResult.environment -cne 'development-e2e' -or
        -not [IO.Path]::IsPathFullyQualified($promotedManifestPath) -or
        -not [IO.Path]::IsPathFullyQualified($promotionJournalPath) -or
        -not (Test-Path -LiteralPath $promotedManifestPath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $promotionJournalPath -PathType Leaf)) {
        throw 'Development FeedPromoter result does not expose its exact local evidence paths.'
    }
    Invoke-NativeChecked -FilePath 'dotnet' -ArgumentList @(
        $publisherDll, 'release-policy', 'sign-handoff',
        '--promotion-journal-entry', $promotionJournalPath,
        '--channel-manifest', $promotedManifestPath,
        '--promotion-result-receipt', $PromotionResultPath,
        '--environment', 'development-e2e',
        '--private-key-file', $releasePrivateKeyPath,
        '--key-id', $releasePolicyKeyId, '--output', $HandoffPath,
        '--valid-hours', '2', '--grace-hours', '0') `
        -FailureMessage 'Signed Development release-policy handoff creation failed.'
}

Test-StaticContract
$hasTargetRuntime = Test-CompleteTargetRuntimeTuple -Values @(
    $TargetRuntimeArchivePath, $TargetRuntimeMetadataPath,
    $ExpectedTargetRuntimeReleaseId, $ExpectedTargetRuntimeArchiveFileName,
    $ExpectedTargetRuntimeArchiveSha256, $TargetPluginPolicyArchivePath,
    $TargetPluginPolicyMetadataPath)
if ($EnterpriseDirectLocal -and -not $ContractOnly -and
    (-not $AutomaticRuntimeUpdate -or -not $hasTargetRuntime)) {
    throw 'Enterprise direct-local Development rehearsal requires an actual automatic update to a complete target runtime tuple.'
}
$targetLauncherInputs = @($TargetLauncherArchivePath, $ExpectedTargetLauncherReleaseId, $ExpectedTargetLauncherArchiveSha256)
$targetLauncherInputCount = @($targetLauncherInputs | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count
if ($targetLauncherInputCount -ne 0 -and $targetLauncherInputCount -ne 3) {
    throw 'Target Launcher archive, release identity and SHA256 must be supplied together.'
}
$hasTargetLauncher = $targetLauncherInputCount -eq 3
if ($hasTargetLauncher -and (-not $hasTargetRuntime -or -not $AutomaticRuntimeUpdate -or
    [string]::IsNullOrWhiteSpace($ExpectedLauncherReleaseId) -or
    $ExpectedTargetLauncherReleaseId -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$' -or
    $ExpectedTargetLauncherReleaseId -ceq $ExpectedLauncherReleaseId -or
    $ExpectedTargetLauncherArchiveSha256 -cnotmatch '^[0-9a-f]{64}$')) {
    throw 'Consecutive Launcher update requires an explicit distinct identity and hash after the automatic runtime update.'
}
$artifactInputValues = @(
    $RuntimeArchivePath,
    $RuntimeMetadataPath,
    $ExpectedRuntimeReleaseId,
    $ExpectedRuntimeArchiveFileName,
    $ExpectedRuntimeArchiveSha256,
    $PluginPolicyArchivePath,
    $PluginPolicyMetadataPath)
$artifactInputCount = @($artifactInputValues | Where-Object {
    -not [string]::IsNullOrWhiteSpace($_)
}).Count
if ($ContractOnly -and $artifactInputCount -eq 0 -and -not $hasTargetRuntime) {
    return
}
if ($artifactInputCount -ne $artifactInputValues.Count) {
    throw 'RuntimeArchivePath, RuntimeMetadataPath, explicit expected runtime release/file/hash, and plugin-policy archive/metadata must be supplied as one complete tuple.'
}
if (-not $IsWindows) {
    throw 'Enterprise Development artifact admission and the full lifecycle require Windows.'
}

$runtimeArchive = Resolve-SafeExistingPath -Path $RuntimeArchivePath -Directory $false
$runtimeMetadata = Resolve-SafeExistingPath -Path $RuntimeMetadataPath -Directory $false
$pluginPolicyArchive = Resolve-SafeExistingPath -Path $PluginPolicyArchivePath -Directory $false
$pluginPolicyMetadata = Resolve-SafeExistingPath -Path $PluginPolicyMetadataPath -Directory $false
if ($hasTargetRuntime) {
    $targetRuntimeArchive = Resolve-SafeExistingPath -Path $TargetRuntimeArchivePath -Directory $false
    $targetRuntimeMetadata = Resolve-SafeExistingPath -Path $TargetRuntimeMetadataPath -Directory $false
    $targetPluginPolicyArchive = Resolve-SafeExistingPath -Path $TargetPluginPolicyArchivePath -Directory $false
    $targetPluginPolicyMetadata = Resolve-SafeExistingPath -Path $TargetPluginPolicyMetadataPath -Directory $false
}
if ($ContractOnly) {
    $contractLeases = [Collections.Generic.List[IDisposable]]::new()
    try {
        $contractRuntimeEvidence = Read-EnterpriseDevelopmentRuntimeEvidence `
            -ArchivePath $runtimeArchive `
            -MetadataPath $runtimeMetadata `
            -MetadataSchemaPath $runtimeMetadataSchema `
            -ExpectedReleaseId $ExpectedRuntimeReleaseId `
            -ExpectedArchiveFileName $ExpectedRuntimeArchiveFileName `
            -ExpectedArchiveSha256 $ExpectedRuntimeArchiveSha256 `
            -AllowLocalLab:$AllowLocalLab `
            -EnterpriseDirectLocal:$EnterpriseDirectLocal `
            -Leases $contractLeases
        $contractPluginEvidence = Read-PluginPolicyBuildEvidence `
            -ArchivePath $pluginPolicyArchive `
            -MetadataPath $pluginPolicyMetadata `
            -ExpectedRuntimeReleaseId $contractRuntimeEvidence.ReleaseId `
            -ExpectedLauncherReleaseId $ExpectedLauncherReleaseId
        Assert-EnterpriseDevelopmentRuntimeEvidenceUnchanged `
            -Evidence $contractRuntimeEvidence
        if (-not $contractPluginEvidence.RuntimeCompatibilityValidated) {
            throw 'Enterprise Development plugin/runtime compatibility was not validated.'
        }
        if ($hasTargetRuntime) {
            $contractTargetRuntime = Read-EnterpriseDevelopmentRuntimeEvidence `
                -ArchivePath $targetRuntimeArchive -MetadataPath $targetRuntimeMetadata `
                -MetadataSchemaPath $runtimeMetadataSchema `
                -ExpectedReleaseId $ExpectedTargetRuntimeReleaseId `
                -ExpectedArchiveFileName $ExpectedTargetRuntimeArchiveFileName `
                -ExpectedArchiveSha256 $ExpectedTargetRuntimeArchiveSha256 `
                -AllowLocalLab:$AllowLocalLab `
                -EnterpriseDirectLocal:$EnterpriseDirectLocal -Leases $contractLeases
            $contractTargetPolicy = Read-PluginPolicyBuildEvidence `
                -ArchivePath $targetPluginPolicyArchive -MetadataPath $targetPluginPolicyMetadata `
                -ExpectedRuntimeReleaseId $contractTargetRuntime.ReleaseId `
                -ExpectedLauncherReleaseId $contractPluginEvidence.LauncherReleaseId
            Assert-DistinctDevelopmentRuntimeTuple `
                -InitialRuntime $contractRuntimeEvidence -InitialPolicy $contractPluginEvidence `
                -TargetRuntime $contractTargetRuntime -TargetPolicy $contractTargetPolicy
            Assert-EnterpriseDevelopmentRuntimeEvidenceUnchanged -Evidence $contractTargetRuntime
            Assert-EnterpriseDevelopmentRuntimeEvidenceUnchanged -Evidence $contractRuntimeEvidence
        }
        if ($hasTargetLauncher) {
            $contractLauncher = Open-EnterpriseDevelopmentRuntimeLockedInput `
                -Path (Resolve-SafeExistingPath -Path $TargetLauncherArchivePath -Directory $false) `
                -MaximumBytes 512MB -Leases $contractLeases
            if ($contractLauncher.Sha256 -cne $ExpectedTargetLauncherArchiveSha256) {
                throw 'Target Launcher contract archive hash differs from the explicit input.'
            }
            [void](Read-PluginPolicyBuildEvidence -ArchivePath $pluginPolicyArchive `
                -MetadataPath $pluginPolicyMetadata -ExpectedRuntimeReleaseId $contractTargetRuntime.ReleaseId `
                -ExpectedLauncherReleaseId $ExpectedTargetLauncherReleaseId)
        }
        Write-Host (
            'PASS  Enterprise Development explicit runtime/plugin input tuple: ' +
            "$($contractRuntimeEvidence.ReleaseId) / $($contractPluginEvidence.PolicyId)")
    }
    finally {
        for ($index = $contractLeases.Count - 1; $index -ge 0; $index--) {
            $contractLeases[$index].Dispose()
        }
    }
    return
}

$controlRoot = Resolve-SafeExistingPath -Path $ControlPlaneRepository -Directory $true
$runtimeInputLeases = [Collections.Generic.List[IDisposable]]::new()
$runtimeEvidence = $null
$runtimePayloadEvidence = $null
$pluginPolicyEvidence = $null
$targetRuntimeEvidence = $null
$targetRuntimePayloadEvidence = $null
$targetPluginPolicyEvidence = $null
$targetRunnerArguments = @()
$directCredentialEvidence = $null
$directCredentialVerificationStages = [Collections.Generic.List[object]]::new()

$runId = [Guid]::NewGuid().ToString('N')
$tempParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$tempRoot = Join-Path $tempParent "ensou-dsh-enterprise-lifecycle-$runId"
$localAppDataRoot = Join-Path $tempRoot 'LocalAppData'
$userProfileRoot = Join-Path $tempRoot 'UserProfile'
$publishRoot = Join-Path $tempRoot 'publish'
$payloadRoot = Join-Path $tempRoot 'payload'
$logRoot = Join-Path $tempRoot 'logs'
if ([string]::IsNullOrWhiteSpace($EvidenceDirectory)) {
    $EvidenceDirectory = Join-Path $repositoryRoot "out\enterprise-development-e2e-evidence\$runId"
}
$evidenceRoot = [IO.Path]::GetFullPath($EvidenceDirectory)
if ($evidenceRoot.StartsWith('\\', [StringComparison]::Ordinal) -or
    $evidenceRoot.StartsWith('//', [StringComparison]::Ordinal)) {
    throw 'EvidenceDirectory must be a local path.'
}
if (Test-Path -LiteralPath $evidenceRoot) {
    throw "EvidenceDirectory already exists; choose a new path: $evidenceRoot"
}
$evidenceParent = [IO.Path]::GetDirectoryName($evidenceRoot)
if ([string]::IsNullOrWhiteSpace($evidenceParent)) {
    throw 'EvidenceDirectory must have an absolute parent directory.'
}
[IO.Directory]::CreateDirectory($evidenceParent) | Out-Null
try {
    New-Item -ItemType Directory -Path $evidenceRoot -ErrorAction Stop | Out-Null
}
catch {
    throw [IO.IOException]::new(
        "EvidenceDirectory must be new and could not be created: $evidenceRoot",
        $_.Exception)
}
foreach ($directory in @(
    $tempRoot, $localAppDataRoot, $userProfileRoot, $publishRoot,
    $payloadRoot, $logRoot)) {
    [IO.Directory]::CreateDirectory($directory) | Out-Null
}

$containerName = "ensou-dsh-e2e-$runId"
$databaseName = "dsh_e2e_$runId"
$postgresPort = Get-FreeTcpPort
$controlPort = Get-FreeTcpPort
$controlOrigin = "https://localhost:$controlPort/"
$postgresPassword = ConvertTo-Base64Url ([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
$postgresEnvFile = Join-Path $tempRoot 'postgres.env'
$pfxPath = Join-Path $tempRoot 'control-plane.pfx'
$certificate = $null
$certificateKey = $null
$pfxBytes = $null
$apiProcess = $null
$script:ownedLifecycleRunners = [Collections.Generic.List[Diagnostics.Process]]::new()
$containerStarted = $false
$succeeded = $false
$developmentConfig = @{}
$feedInternalSecret = $null
$feedPolicySetPublicReceipt = $null
$realFeedAuthorizationAuditVerified = $false
$certificateSha256 = $null
$runnerDll = $null
$policyInstallEvidence = $null
$initialPolicyImport = $null
$updatePolicyImport = $null
$releasePolicyKeyId = $null
$releasePolicyKeyX = $null
$releasePolicyKeyY = $null

$employeeRef = "development-e2e-$runId"
$employeeId = $null
$pluginPolicyId = $null
$pluginPolicyGeneration = $null
$pluginPolicySha256 = $null
$apiProfileId = $null
$activationCode = [string]::Empty
$entitlementEligibleAtUtc = $null
$releasePrivateKeyPath = Join-Path $tempRoot 'release-policy-e2e.pk8'
$initialManifestPath = Join-Path $evidenceRoot '00a-release-set-sequence-1.json'
$initialJournalPath = Join-Path $evidenceRoot '00b-promotion-journal-sequence-1.json'
$initialPromotionResultPath = Join-Path $evidenceRoot '00b1-promotion-result-sequence-1.json'
$initialHandoffPath = Join-Path $evidenceRoot '00c-release-policy-handoff-sequence-1.json'
$updateManifestPath = Join-Path $evidenceRoot '02a-release-set-sequence-2.json'
$updateJournalPath = Join-Path $evidenceRoot '02b-promotion-journal-sequence-2.json'
$updatePromotionResultPath = Join-Path $evidenceRoot '02b1-promotion-result-sequence-2.json'
$updateHandoffPath = Join-Path $evidenceRoot '02c-release-policy-handoff-sequence-2.json'

try {
    $runtimeEvidence = Read-EnterpriseDevelopmentRuntimeEvidence `
        -ArchivePath $runtimeArchive `
        -MetadataPath $runtimeMetadata `
        -MetadataSchemaPath $runtimeMetadataSchema `
        -ExpectedReleaseId $ExpectedRuntimeReleaseId `
        -ExpectedArchiveFileName $ExpectedRuntimeArchiveFileName `
        -ExpectedArchiveSha256 $ExpectedRuntimeArchiveSha256 `
        -AllowLocalLab:$AllowLocalLab `
        -EnterpriseDirectLocal:$EnterpriseDirectLocal `
        -Leases $runtimeInputLeases
    $pluginPolicyEvidence = Read-PluginPolicyBuildEvidence `
        -ArchivePath $pluginPolicyArchive `
        -MetadataPath $pluginPolicyMetadata `
        -ExpectedRuntimeReleaseId $runtimeEvidence.ReleaseId `
        -ExpectedLauncherReleaseId $ExpectedLauncherReleaseId
    Assert-EnterpriseDevelopmentRuntimeEvidenceUnchanged -Evidence $runtimeEvidence
    $pluginPolicyId = [string]$pluginPolicyEvidence.PolicyId
    $pluginPolicyGeneration = [long]$pluginPolicyEvidence.Generation
    $pluginPolicySha256 = [string]$pluginPolicyEvidence.PolicySha256
    if ($hasTargetRuntime) {
        $targetRuntimeEvidence = Read-EnterpriseDevelopmentRuntimeEvidence `
            -ArchivePath $targetRuntimeArchive -MetadataPath $targetRuntimeMetadata `
            -MetadataSchemaPath $runtimeMetadataSchema `
            -ExpectedReleaseId $ExpectedTargetRuntimeReleaseId `
            -ExpectedArchiveFileName $ExpectedTargetRuntimeArchiveFileName `
            -ExpectedArchiveSha256 $ExpectedTargetRuntimeArchiveSha256 `
            -AllowLocalLab:$AllowLocalLab `
            -EnterpriseDirectLocal:$EnterpriseDirectLocal -Leases $runtimeInputLeases
        $targetPluginPolicyEvidence = Read-PluginPolicyBuildEvidence `
            -ArchivePath $targetPluginPolicyArchive -MetadataPath $targetPluginPolicyMetadata `
            -ExpectedRuntimeReleaseId $targetRuntimeEvidence.ReleaseId `
            -ExpectedLauncherReleaseId $pluginPolicyEvidence.LauncherReleaseId
        Assert-DistinctDevelopmentRuntimeTuple `
            -InitialRuntime $runtimeEvidence -InitialPolicy $pluginPolicyEvidence `
            -TargetRuntime $targetRuntimeEvidence -TargetPolicy $targetPluginPolicyEvidence
    }
    if ($hasTargetLauncher) {
        $targetLauncherArchive = Resolve-SafeExistingPath -Path $TargetLauncherArchivePath -Directory $false
        $targetLauncherLock = Open-EnterpriseDevelopmentRuntimeLockedInput `
            -Path $targetLauncherArchive -MaximumBytes 512MB -Leases $runtimeInputLeases
        if ($targetLauncherLock.Sha256 -cne $ExpectedTargetLauncherArchiveSha256) {
            throw 'Target Launcher input hash differs from its reviewed build.'
        }
        [void](Read-PluginPolicyBuildEvidence -ArchivePath $pluginPolicyArchive `
            -MetadataPath $pluginPolicyMetadata -ExpectedRuntimeReleaseId $targetRuntimeEvidence.ReleaseId `
            -ExpectedLauncherReleaseId $ExpectedTargetLauncherReleaseId)
    }

    $configLines = & (Join-Path $controlRoot 'scripts\New-DevelopmentEnrollmentConfig.ps1') `
        -WarningAction SilentlyContinue
    $developmentConfig = Read-DevelopmentEnrollmentConfiguration -Lines @($configLines)
    if ($InstalledLauncherUpdate -or $EnterpriseDirectLocal) {
        # This secret is independent of the six-field enrollment configuration
        # and is supplied only to the isolated Development feed API/runner.
        $feedInternalSecret = ConvertTo-Base64Url (
            [Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
    }

    Assert-DockerDaemonAvailable

    $solutionBuildArguments = @(
        'build', (Join-Path $repositoryRoot 'Ensou.Dsh.slnx'), '-c', 'Release', '--no-restore')
    if ($EnterpriseDirectLocal) {
        $solutionBuildArguments += '-p:EnterpriseDirectLocalRuntimeAdmission=true'
    }
    Invoke-NativeChecked -FilePath 'dotnet' -ArgumentList $solutionBuildArguments `
        -FailureMessage 'Launcher solution build failed.'
    Invoke-NativeChecked -FilePath 'dotnet' -ArgumentList @(
        'build', (Join-Path $controlRoot 'Ensou.Dsh.Enterprise.ControlPlane.slnx'), '-c', 'Release', '--no-restore') `
        -FailureMessage 'Control-plane solution build failed.'

    # Keep the ordinary solution outputs production-shaped. The lifecycle
    # runner alone needs the compile-gated Lab URI and pinned loopback transport
    # implemented by Enterprise.Client's Development-E2E build.
    $runnerOutput = Join-Path $tempRoot 'runner'
    Invoke-NativeChecked -FilePath 'dotnet' -ArgumentList @(
        'build', (Join-Path $repositoryRoot 'tests\Ensou.Dsh.Enterprise.DevelopmentE2ETests\Ensou.Dsh.Enterprise.DevelopmentE2ETests.csproj'),
        '-c', 'Release', '--no-restore',
        '-p:EnterpriseDevelopmentE2E=true',
        '-p:EnterpriseDirectLocalRuntimeAdmission=false',
        '-o', $runnerOutput) `
        -FailureMessage 'Isolated Development E2E runner build failed.'
    $runnerDll = Join-Path $runnerOutput 'Ensou.Dsh.Enterprise.DevelopmentE2ETests.dll'
    if (-not (Test-Path -LiteralPath $runnerDll -PathType Leaf)) {
        throw "Isolated Development E2E runner DLL is missing: $runnerDll"
    }
    Invoke-Runner `
        -RunnerDll $runnerDll `
        -Arguments @(
            '--phase', 'artifact-fixture-contract',
            '--isolation-id', $runId,
            '--evidence', (Join-Path $evidenceRoot '00-artifact-fixture-contract.json')) `
        -WorkingDirectory $repositoryRoot
    Invoke-Runner `
        -RunnerDll $runnerDll `
        -Arguments @(
            '--phase', 'https-artifact-fixture-contract',
            '--isolation-id', $runId,
            '--evidence', (Join-Path $evidenceRoot '00a-https-artifact-fixture-contract.json')) `
        -WorkingDirectory $repositoryRoot

    Invoke-NativeChecked -FilePath 'dotnet' -ArgumentList @(
        'run', '--project', (Join-Path $repositoryRoot 'tests\Ensou.Dsh.Enterprise.InstallationTests\Ensou.Dsh.Enterprise.InstallationTests.csproj'),
        '-c', 'Release', '--no-build') -FailureMessage 'Installation checks failed.'
    Invoke-NativeChecked -FilePath 'dotnet' -ArgumentList @(
        'run', '--project', (Join-Path $repositoryRoot 'tests\Ensou.Dsh.Enterprise.UpdateTests\Ensou.Dsh.Enterprise.UpdateTests.csproj'),
        '-c', 'Release', '--no-build') -FailureMessage 'Signed release-set/plugin rollback checks failed.'
    Invoke-NativeChecked -FilePath 'dotnet' `
        -ArgumentList @(New-DevelopmentReleasePublisherTestArguments `
            -DirectLocal:$EnterpriseDirectLocal) `
        -FailureMessage 'Release publisher admission-mode checks failed.'

    $launcherPublish = Join-Path $publishRoot 'launcher'
    $clientBootstrapperPublish = Join-Path $publishRoot 'client-bootstrapper'
    $maintenancePublish = Join-Path $publishRoot 'maintenance'
    $bootstrapperPublish = Join-Path $publishRoot 'bootstrapper'
    $installerPublish = Join-Path $publishRoot 'installer'
    $launcherPublishArguments = @(New-DevelopmentLauncherPublishArguments `
        -OutputDirectory $launcherPublish `
        -DirectLocal:$EnterpriseDirectLocal)
    Invoke-NativeChecked -FilePath 'dotnet' -ArgumentList $launcherPublishArguments `
        -FailureMessage 'Development E2E Launcher publish failed.'
    Invoke-NativeChecked -FilePath 'dotnet' -ArgumentList @(
        'publish', (Join-Path $repositoryRoot 'src\Ensou.Dsh.Enterprise.ClientBootstrapper\Ensou.Dsh.Enterprise.ClientBootstrapper.csproj'),
        '-c', 'Release', '-r', 'win-x64', '--self-contained', 'true',
        '--no-restore', '-p:PublishSingleFile=true', '-p:EnterpriseDevelopmentE2E=true', '-o', $clientBootstrapperPublish) `
        -FailureMessage 'Development E2E versioned Bootstrapper publish failed.'
    Invoke-NativeChecked -FilePath 'dotnet' -ArgumentList @(
        'publish', (Join-Path $repositoryRoot 'src\Ensou.Dsh.Enterprise.Maintenance\Ensou.Dsh.Enterprise.Maintenance.csproj'),
        '-c', 'Release', '-r', 'win-x64', '--self-contained', 'true',
        '--no-restore', '-p:PublishSingleFile=true', '-p:EnterpriseDevelopmentE2E=true', '-o', $maintenancePublish) `
        -FailureMessage 'Development E2E Maintenance publish failed.'
    Invoke-NativeChecked -FilePath 'dotnet' -ArgumentList @(
        'publish', (Join-Path $repositoryRoot 'src\Ensou.Dsh.Enterprise.Bootstrapper\Ensou.Dsh.Enterprise.Bootstrapper.csproj'),
        '-c', 'Release', '-r', 'win-x64', '--self-contained', 'true',
        '--no-restore', '-p:PublishSingleFile=true', '-p:EnterpriseDevelopmentE2E=true', '-o', $bootstrapperPublish) `
        -FailureMessage 'Development E2E Bootstrapper publish failed.'
    Invoke-NativeChecked -FilePath 'dotnet' -ArgumentList @(
        'publish', (Join-Path $repositoryRoot 'src\Ensou.Dsh.Enterprise.Installer\Ensou.Dsh.Enterprise.Installer.csproj'),
        '-c', 'Release', '-r', 'win-x64', '--self-contained', 'true',
        '--no-restore', '-p:PublishSingleFile=true', '-p:EnterpriseDevelopmentE2E=true', '-o', $installerPublish) `
        -FailureMessage 'Development E2E Installer publish failed.'

    $launcherReleaseId = [string]$pluginPolicyEvidence.LauncherReleaseId
    $runtimeReleaseId = [string]$runtimeEvidence.ReleaseId
    if ([string]$pluginPolicyEvidence.RuntimeReleaseId -cne $runtimeReleaseId) {
        throw 'Plugin-policy compatibility does not match admitted runtime metadata identity.'
    }
    $pluginPolicyReleaseId = "plugin-policy-g$pluginPolicyGeneration-$runId"
    Assert-EnterpriseDevelopmentRuntimeEvidenceUnchanged -Evidence $runtimeEvidence
    & (Join-Path $repositoryRoot 'scripts\New-EnterpriseDevelopmentPayload.ps1') `
        -LauncherReleaseId $launcherReleaseId `
        -RuntimeReleaseId $runtimeReleaseId `
        -LauncherPublishDirectory $launcherPublish `
        -ClientBootstrapperPublishDirectory $clientBootstrapperPublish `
        -MaintenancePublishDirectory $maintenancePublish `
        -RuntimeArchivePath $runtimeArchive `
        -BootstrapperPath (Join-Path $bootstrapperPublish 'Ensou.Dsh.Enterprise.Bootstrapper.exe') `
        -OutputDirectory $payloadRoot `
        -DevelopmentE2E | Out-Null
    $runtimePayloadEvidence = Open-EnterpriseDevelopmentRuntimePayloadCopy `
        -Path (Join-Path $payloadRoot 'runtime.zip') `
        -ExpectedSizeBytes $runtimeEvidence.ArchiveSizeBytes `
        -ExpectedSha256 $runtimeEvidence.ArchiveSha256 `
        -Leases $runtimeInputLeases
    Assert-EnterpriseDevelopmentRuntimeEvidenceUnchanged -Evidence $runtimeEvidence
    if ($hasTargetRuntime) {
        $targetRuntimeCopy = Join-Path $payloadRoot 'target-runtime.zip'
        [IO.File]::Copy($targetRuntimeArchive, $targetRuntimeCopy, $false)
        $targetRuntimePayloadEvidence = Open-EnterpriseDevelopmentRuntimePayloadCopy `
            -Path $targetRuntimeCopy `
            -ExpectedSizeBytes $targetRuntimeEvidence.ArchiveSizeBytes `
            -ExpectedSha256 $targetRuntimeEvidence.ArchiveSha256 `
            -Leases $runtimeInputLeases
        Assert-EnterpriseDevelopmentRuntimeEvidenceUnchanged -Evidence $targetRuntimeEvidence
        $targetPolicyLock = Open-EnterpriseDevelopmentRuntimeLockedInput `
            -Path $targetPluginPolicyArchive -MaximumBytes 64MB -Leases $runtimeInputLeases
        $targetPolicyMetadataLock = Open-EnterpriseDevelopmentRuntimeLockedInput `
            -Path $targetPluginPolicyMetadata -MaximumBytes 4MB -Leases $runtimeInputLeases
        if ($targetPolicyLock.Sha256 -cne $targetPluginPolicyEvidence.ArchiveSha256 -or
            $targetPolicyMetadataLock.Sha256 -cne $targetPluginPolicyEvidence.MetadataSha256) {
            throw 'Target plugin-policy inputs changed before their immutable-use lease.'
        }
        $targetPluginPolicyReleaseId = $pluginPolicyReleaseId
        $targetRunnerArguments = @(
            '--target-runtime-release-id', [string]$targetRuntimeEvidence.ReleaseId,
            '--target-runtime-archive', $targetRuntimeCopy,
            '--target-plugin-policy-release-id', $targetPluginPolicyReleaseId,
            '--target-plugin-policy-archive', $targetPluginPolicyArchive,
            '--target-plugin-policy-id', [string]$targetPluginPolicyEvidence.PolicyId,
            '--target-plugin-policy-generation', [string]$targetPluginPolicyEvidence.Generation,
            '--target-plugin-policy-sha256', [string]$targetPluginPolicyEvidence.PolicySha256,
            '--target-plugin-archive-sha256', [string]$targetPluginPolicyEvidence.ArchiveSha256)
    }

    Invoke-HiddenChecked `
        -FilePath (Join-Path $installerPublish 'Ensou.Dsh.Enterprise.Installer.exe') `
        -ArgumentList @(
            '--install', '--quiet', '--payload', $payloadRoot, '--dev-unsigned',
            '--dev-e2e-layout', '--dev-e2e-no-shell-registration',
            '--dev-e2e-local-app-data-root', $localAppDataRoot,
            '--dev-e2e-user-profile-root', $userProfileRoot) `
        -WorkingDirectory $installerPublish `
        -FailureMessage 'Isolated Development E2E installation failed.'

    $managedRoot = Join-Path $localAppDataRoot 'Ensou\DshEnterpriseLauncherDevE2E'
    if ($EnterpriseDirectLocal) {
        $directCredentialEvidence = New-DevelopmentDirectLocalCredentialEvidence `
            -HarnessHome (Join-Path $userProfileRoot '.dsh-enterprise-dev-e2e')
        $credentialVerification = Assert-DevelopmentDirectLocalCredentialRetained `
            -Evidence $directCredentialEvidence `
            -RuntimeDirectory (Join-Path (Join-Path $managedRoot 'runtimes') $runtimeReleaseId) `
            -VerifierPath (Join-Path $PSScriptRoot 'Test-EnterpriseDirectLocalCredentialValue.mjs') `
            -Stage 'initial-installed-runtime'
        $directCredentialVerificationStages.Add($credentialVerification)
        Write-PassedEvidence `
            -Path (Join-Path $evidenceRoot '00d-direct-local-credential-value.json') `
            -Evidence $credentialVerification
    }
    $layoutEnvironment = Set-ChildEnvironment -Values @{
        ENSOU_DSH_E2E_LOCAL_APP_DATA_ROOT = $localAppDataRoot
        ENSOU_DSH_E2E_USER_PROFILE_ROOT = $userProfileRoot
        ENSOU_DSH_E2E_ISOLATION_ID = $runId
    }
    try {
        $policyInstallArguments = @(
            '--phase', 'install-plugin-policy',
            '--isolation-id', $runId,
            '--evidence', (Join-Path $evidenceRoot '00-plugin-policy-installation.json'),
            '--local-app-data-root', $localAppDataRoot,
            '--user-profile-root', $userProfileRoot,
            '--launcher-release-id', $launcherReleaseId,
            '--runtime-release-id', $runtimeReleaseId,
            '--plugin-policy-release-id', $pluginPolicyReleaseId,
            '--launcher-archive', (Join-Path $payloadRoot 'launcher.zip'),
            '--runtime-archive', (Join-Path $payloadRoot 'runtime.zip'),
            '--plugin-policy-archive', $pluginPolicyArchive,
            '--plugin-policy-id', $pluginPolicyId,
            '--plugin-policy-generation', [string]$pluginPolicyGeneration,
            '--plugin-policy-sha256', $pluginPolicySha256,
            '--plugin-archive-sha256', [string]$pluginPolicyEvidence.ArchiveSha256,
            '--release-private-key', $releasePrivateKeyPath,
            '--initial-manifest-output', $initialManifestPath,
            '--initial-journal-output', $initialJournalPath,
            '--initial-promotion-result-output', $initialPromotionResultPath,
            '--update-manifest-output', $updateManifestPath,
            '--update-journal-output', $updateJournalPath,
            '--update-promotion-result-output', $updatePromotionResultPath)
        if ($EnterpriseDirectLocal) {
            $policyInstallArguments += @(
                '--runtime-profile', 'enterprise-direct-local')
        }
        $policyInstallArguments += $targetRunnerArguments
        Invoke-Runner `
            -RunnerDll $runnerDll `
            -Arguments $policyInstallArguments `
            -WorkingDirectory $repositoryRoot
        $policyInstallEvidence = Get-Content `
            -LiteralPath (Join-Path $evidenceRoot '00-plugin-policy-installation.json') `
            -Raw | ConvertFrom-Json -Depth 16
        if ([string]$policyInstallEvidence.status -cne 'passed' -or
            [string]$policyInstallEvidence.evidence.rawPolicySha256 -cne $pluginPolicySha256 -or
            [string]$policyInstallEvidence.evidence.manifestSha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [string]$policyInstallEvidence.evidence.updateManifestSha256 -cnotmatch '^[0-9a-f]{64}$') {
            throw 'Initial plugin-policy fixture evidence does not match the reviewed signed release inputs.'
        }
        if ($EnterpriseDirectLocal) {
            if ([string]$policyInstallEvidence.evidence.releaseSetState -cne
                    'initial-sequence-zero-awaiting-authenticated-enrollment' -or
                [string]$policyInstallEvidence.evidence.healthState -cne 'healthy' -or
                [long]$policyInstallEvidence.evidence.activeReleaseSequence -ne 0 -or
                [bool]$policyInstallEvidence.evidence.signedInitialReleaseStaged -or
                [bool]$policyInstallEvidence.evidence.signedInitialReleaseHealthy -or
                [bool]$policyInstallEvidence.evidence.activePolicyAvailable -or
                $null -ne $policyInstallEvidence.evidence.skillsTreeSha256 -or
                [bool]$policyInstallEvidence.evidence.alternateRawPolicyBindingRejected) {
                throw 'Direct-local initial fixture must remain healthy sequence zero until real enrollment commits its signed lease.'
            }
        }
        elseif ([string]$policyInstallEvidence.evidence.healthState -cne 'healthy') {
            throw 'Managed initial plugin-policy evidence does not match the reviewed healthy policy.'
        }
        $releaseUpdateTrustProperty =
            $policyInstallEvidence.evidence.PSObject.Properties['releaseUpdateTrust']
        if ($null -eq $releaseUpdateTrustProperty) {
            throw [IO.InvalidDataException]::new(
                'Development release update trust evidence is missing.')
        }
        $releaseUpdateEnvironment = Read-DevelopmentReleaseUpdateTrust `
            -Evidence $releaseUpdateTrustProperty.Value
        $releasePolicyKeyId = [string]$releaseUpdateEnvironment['ENSOU_DSH_E2E_UPDATE_KEY_ID']
        $releasePolicyKeyX = [string]$releaseUpdateEnvironment['ENSOU_DSH_E2E_UPDATE_KEY_X']
        $releasePolicyKeyY = [string]$releaseUpdateEnvironment['ENSOU_DSH_E2E_UPDATE_KEY_Y']
        if ($releasePolicyKeyId -cne 'lifecycle-key') {
            throw 'Development release-policy key id is not the exact runner identity.'
        }

        $releaseUpdateEnvironmentOriginal = Set-ChildEnvironment `
            -Values $releaseUpdateEnvironment
        try {
            Invoke-HiddenChecked `
                -FilePath (Join-Path $managedRoot 'Ensou.Dsh.Enterprise.Bootstrapper.exe') `
                -ArgumentList @('--self-check') `
                -WorkingDirectory $managedRoot `
                -FailureMessage 'Installed stable Bootstrapper self-check failed.' `
                -TimeoutSeconds 30 `
                -Stage 'installed-bootstrapper-self-check'
            if (-not $EnterpriseDirectLocal) {
                $releasePointer = Get-Content `
                    -LiteralPath (Join-Path $managedRoot 'state\release-set-current.v2.json') `
                    -Raw | ConvertFrom-Json
                $activeLauncher = Join-Path `
                    ([string]$releasePointer.current.launcher.directory) `
                    'Ensou.Dsh.Enterprise.Launcher.exe'
                Invoke-HiddenChecked `
                    -FilePath $activeLauncher `
                    -ArgumentList @('--installation-self-check') `
                    -WorkingDirectory ([IO.Path]::GetDirectoryName($activeLauncher)) `
                    -FailureMessage 'Installed active Launcher self-check failed.' `
                    -TimeoutSeconds 30 `
                    -Stage 'installed-launcher-self-check'
            }
        }
        finally {
            Restore-ChildEnvironment -Original $releaseUpdateEnvironmentOriginal
        }
    }
    finally {
        Restore-ChildEnvironment -Original $layoutEnvironment
    }

    $adminProject = Join-Path $controlRoot 'src\Ensou.Dsh.Enterprise.ControlPlane.AdminCli\Ensou.Dsh.Enterprise.ControlPlane.AdminCli.csproj'
    Invoke-NativeChecked -FilePath 'dotnet' -ArgumentList @(
        'build', $adminProject, '-c', 'Release', '--no-restore',
        '-p:EnterpriseDevelopmentE2E=true',
        "-p:EnterpriseReleasePolicyKeyId=$releasePolicyKeyId",
        "-p:EnterpriseReleasePolicyKeyX=$releasePolicyKeyX",
        "-p:EnterpriseReleasePolicyKeyY=$releasePolicyKeyY") `
        -FailureMessage 'Development E2E Admin CLI trust-root build failed.'
    $publisherDll = Join-Path $repositoryRoot 'src\Ensou.Dsh.Enterprise.ReleasePublisher\bin\Release\net10.0-windows\Ensou.Dsh.Enterprise.ReleasePublisher.dll'
    if (-not (Test-Path -LiteralPath $publisherDll -PathType Leaf)) {
        throw "Exact Development E2E Publisher DLL is missing: $publisherDll"
    }
    foreach ($handoff in @(
        @($initialPromotionResultPath, $initialHandoffPath),
        @($updatePromotionResultPath, $updateHandoffPath))) {
        New-DevelopmentSignedPolicyHandoff -PromotionResultPath $handoff[0] -HandoffPath $handoff[1]
    }

    "POSTGRES_PASSWORD=$postgresPassword" | Set-Content `
        -LiteralPath $postgresEnvFile `
        -Encoding ascii `
        -NoNewline
    $postgresImageArguments = if ($CachedPostgresImageId) {
        @('--pull', 'never', $CachedPostgresImageId)
    } else {
        @('postgres:17')
    }
    Invoke-NativeChecked -FilePath 'docker' -ArgumentList (@(
        'run', '--detach', '--name', $containerName,
        '--label', 'ensou.dsh.task=enterprise-development-lifecycle',
        '--label', "ensou.dsh.run=$runId",
        '--env-file', $postgresEnvFile,
        '--publish', "127.0.0.1:${postgresPort}:5432") + $postgresImageArguments) `
        -FailureMessage 'Isolated PostgreSQL container failed to start.'
    $containerStarted = $true
    # The image entrypoint starts a temporary PostgreSQL server while it
    # initializes the data directory, stops it, and only then execs the final
    # server as PID 1. A first pg_isready success can therefore be transient.
    # Admit the database only after PID 1 is the final postgres process and a
    # real SQL round trip succeeds against that same server.
    foreach ($attempt in 1..120) {
        $pidOne = (& docker exec $containerName cat /proc/1/comm 2>$null | Out-String).Trim()
        $pidOneExit = $LASTEXITCODE
        if ($pidOneExit -eq 0 -and $pidOne -ceq 'postgres') {
            & docker exec $containerName pg_isready -U postgres -d postgres *> $null
            $readyExit = $LASTEXITCODE
            if ($readyExit -eq 0) {
                & docker exec $containerName psql -U postgres -d postgres -v ON_ERROR_STOP=1 -tAc 'SELECT 1' *> $null
                if ($LASTEXITCODE -eq 0) { break }
            }
        }
        if ($attempt -eq 120) { throw 'Isolated PostgreSQL final server did not become ready.' }
        Start-Sleep -Milliseconds 250
    }

    Invoke-NativeChecked -FilePath 'docker' -ArgumentList @(
        'exec', $containerName, 'psql', '-U', 'postgres', '-d', 'postgres',
        '-v', 'ON_ERROR_STOP=1', '-c', "CREATE DATABASE $databaseName")
    Invoke-NativeChecked -FilePath 'docker' -ArgumentList @(
        'exec', $containerName, 'psql', '-U', 'postgres', '-d', 'postgres',
        '-v', 'ON_ERROR_STOP=1', '-c', "ALTER DATABASE $databaseName SET ensou.deployment_mode = 'development'")
    # Use the server release's authoritative migration runner. A duplicated
    # client-side list previously stopped at v7 and omitted newer enrollment
    # columns. The canonical runner checks every applied version, owns the
    # advisory lock, and requires the exact current ledger before returning.
    $migrationRunner = Join-Path $controlRoot 'db\apply-pending-migrations.psql'
    if (-not (Test-Path -LiteralPath $migrationRunner -PathType Leaf)) {
        throw 'The Control Plane canonical migration runner is required.'
    }
    Invoke-NativeChecked -FilePath 'docker' -ArgumentList @(
        'cp', (Join-Path $controlRoot 'db'), "${containerName}:/tmp/ensou-dsh-schema")
    Invoke-NativeChecked -FilePath 'docker' -ArgumentList @(
        'exec', $containerName, 'psql', '-X', '-U', 'postgres', '-d', $databaseName,
        '-v', 'ON_ERROR_STOP=1', '-f', '/tmp/ensou-dsh-schema/apply-pending-migrations.psql')
    # docker exec proves PostgreSQL is ready inside the container; the API uses
    # the Windows-published loopback port, so admit the lifecycle only after
    # that separate transport is reachable as well.
    Wait-TcpLive -HostName '127.0.0.1' -Port $postgresPort

    $connectionString = "Host=127.0.0.1;Port=$postgresPort;Database=$databaseName;Username=postgres;Password=$postgresPassword;SSL Mode=Disable;Timeout=5"
    $adminDll = Join-Path $controlRoot 'src\Ensou.Dsh.Enterprise.ControlPlane.AdminCli\bin\Release\net10.0\ensou-dsh-admin.dll'

    $initialPolicyImport = Invoke-AdminJson -AdminDll $adminDll -Arguments @(
        'release-policy', 'import',
        '--handoff-document', $initialHandoffPath,
        '--operation-id', [Guid]::NewGuid().ToString('D'),
        '--reason-code', 'DEVELOPMENT_E2E_RELEASE_SEQUENCE_1',
        '--expected-version', '0') -ConnectionString $connectionString
    if ([string]$initialPolicyImport.channel -cne 'lab' -or
        [string]$initialPolicyImport.release_set_id -cne [string]$policyInstallEvidence.evidence.releaseSetId -or
        [long]$initialPolicyImport.sequence -ne 1 -or
        [string]$initialPolicyImport.manifest_sha256 -cne [string]$policyInstallEvidence.evidence.manifestSha256 -or
        [string]$initialPolicyImport.outcome -cne 'CREATED') {
        throw 'Signed initial release-policy handoff was not imported exactly.'
    }

    $null = Invoke-AdminJson -AdminDll $adminDll -Arguments @(
        'plugin-policy', 'supply',
        '--plugin-policy-id', $pluginPolicyId,
        '--policy-version', [string]$pluginPolicyGeneration,
        '--policy-sha256', $pluginPolicySha256,
        '--state', 'ACTIVE',
        '--operation-id', [Guid]::NewGuid().ToString('D'),
        '--reason-code', 'DEVELOPMENT_E2E_POLICY_SUPPLY',
        '--expected-version', '0') -ConnectionString $connectionString

    $profile = Invoke-AdminJson -AdminDll $adminDll -Arguments @(
        New-DevelopmentApiProfileCreateArguments `
            -ProfileName "development-e2e-$runId" `
            -OperationId ([Guid]::NewGuid()) `
            -DirectLocal:$EnterpriseDirectLocal) -ConnectionString $connectionString
    $apiProfileId = [string]$profile.api_profile_id
    if ($apiProfileId -cnotmatch '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' -or
        [string]$profile.state -cne 'DRAFT' -or
        [long]$profile.policy_version -ne 1) {
        throw 'Administrator API profile creation receipt is invalid.'
    }
    if ($EnterpriseDirectLocal -and (
            [string]$profile.provider -cne 'deepseek' -or
            [string]$profile.execution_mode -cne 'ENTERPRISE_DIRECT_LOCAL' -or
            [string]$profile.runtime_profile -cne 'enterprise-direct-local' -or
            [string]$profile.local_key_setup_state -cne 'LOCAL_KEY_SETUP_PENDING' -or
            $profile.PSObject.Properties.Name -ccontains 'secret_reference')) {
        throw 'Administrator direct-local profile receipt violated the local-Key-only contract.'
    }
    $activatedProfile = Invoke-AdminJson -AdminDll $adminDll -Arguments @(
        'api-profile', 'activate',
        '--api-profile-id', $apiProfileId,
        '--operation-id', [Guid]::NewGuid().ToString('D'),
        '--reason-code', 'DEVELOPMENT_E2E_PROFILE_ACTIVATE',
        '--expected-version', '1') -ConnectionString $connectionString
    if ([string]$activatedProfile.api_profile_id -cne $apiProfileId -or
        [string]$activatedProfile.state -cne 'ACTIVE' -or
        [long]$activatedProfile.policy_version -ne 2) {
        throw 'Administrator API profile activation receipt is invalid.'
    }

    $preregisteredEmployee = Invoke-AdminJson -AdminDll $adminDll -Arguments @(
        'employee', 'preregister',
        '--employee-ref', $employeeRef,
        '--operation-id', [Guid]::NewGuid().ToString('D'),
        '--reason-code', 'DEVELOPMENT_E2E_PREREGISTER',
        '--expected-version', '0') -ConnectionString $connectionString
    $employeeId = [string]$preregisteredEmployee.employee_id
    if ($employeeId -cnotmatch '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' -or
        [string]$preregisteredEmployee.employee_ref -cne $employeeRef -or
        [string]$preregisteredEmployee.state -cne 'PRE_REGISTERED' -or
        [long]$preregisteredEmployee.entitlement_epoch -ne 1) {
        throw 'Administrator employee preregistration receipt is invalid.'
    }
    $confirmedEmployees = @(Invoke-AdminJson -AdminDll $adminDll -Arguments @(
        'employee', 'list', '--employee-ref', $employeeRef,
        '--limit', '2', '--offset', '0') -ConnectionString $connectionString)
    if ($confirmedEmployees.Count -ne 1 -or
        [string]$confirmedEmployees[0].employee_id -cne $employeeId -or
        [string]$confirmedEmployees[0].employee_ref -cne $employeeRef -or
        [string]$confirmedEmployees[0].state -cne 'PRE_REGISTERED') {
        throw 'Administrator employee_ref confirmation did not return one exact pre-registered employee.'
    }
    $assignment = Invoke-AdminJson -AdminDll $adminDll -Arguments @(
        'employee', 'assign',
        '--employee-id', $employeeId,
        '--api-profile-id', $apiProfileId,
        '--plugin-policy-id', $pluginPolicyId,
        '--rollout-channel', 'LAB',
        '--quota-policy', 'development-e2e',
        '--operation-id', [Guid]::NewGuid().ToString('D'),
        '--reason-code', 'DEVELOPMENT_E2E_ASSIGN',
        '--expected-version', '1') -ConnectionString $connectionString
    if ([string]$assignment.employee_id -cne $employeeId -or
        [long]$assignment.entitlement_epoch -ne 2 -or
        [long]$assignment.allocation_epoch -ne 1) {
        throw 'Administrator employee assignment receipt is invalid.'
    }
    $assignedEmployees = @(Invoke-AdminJson -AdminDll $adminDll -Arguments @(
        'employee', 'show', '--employee-id', $employeeId) `
        -ConnectionString $connectionString)
    if ($assignedEmployees.Count -ne 1 -or
        [string]$assignedEmployees[0].employee_id -cne $employeeId -or
        [long]$assignedEmployees[0].entitlement_epoch -ne 2) {
        throw 'Administrator employee assignment confirmation is invalid.'
    }
    $employeeAssignmentBeforeEnrollment = Get-EmployeeAssignmentSnapshot `
        -Employee $assignedEmployees[0]
    $entitlementEligibleAtUtc = [DateTimeOffset]$assignedEmployees[0].updated_at

    if ($EnterpriseDirectLocal) {
        # The first signed release is fetched only after the verified binding
        # has installed its DPoP access token. A real active feed policy is
        # still required; PUBLIC_STABLE never removes employee/device checks.
        $feedPolicyValidFrom = [DateTimeOffset]::UtcNow.AddMinutes(-1).ToString(
            "yyyy-MM-dd'T'HH:mm:ss'Z'")
        $feedPolicyValidUntil = [DateTimeOffset]::UtcNow.AddHours(4).ToString(
            "yyyy-MM-dd'T'HH:mm:ss'Z'")
        $feedPolicySetPublicReceipt = Invoke-AdminJson -AdminDll $adminDll -Arguments @(
            'feed-policy', 'set-public',
            '--policy-id', "stable-public-$runId",
            '--valid-from', $feedPolicyValidFrom,
            '--valid-until', $feedPolicyValidUntil,
            '--operation-id', [Guid]::NewGuid().ToString('D'),
            '--reason-code', 'DEVELOPMENT_E2E_INITIAL_DIRECT_FEED',
            '--expected-version', '0') -ConnectionString $connectionString
        if ([string]$feedPolicySetPublicReceipt.state -cne 'PUBLIC_STABLE' -or
            [string]$feedPolicySetPublicReceipt.policy_id -cne "stable-public-$runId" -or
            [long]$feedPolicySetPublicReceipt.policy_version -ne 1) {
            throw 'Development initial direct-local feed policy was not persisted as PUBLIC_STABLE.'
        }
    }

    $pfxPasswordText = ConvertTo-Base64Url ([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
    $tlsCertificate = New-DevelopmentTlsCertificate
    $certificate = $tlsCertificate.Certificate
    $certificateKey = $tlsCertificate.Key
    $pfxBytes = $certificate.Export(
        [Security.Cryptography.X509Certificates.X509ContentType]::Pfx,
        $pfxPasswordText)
    [IO.File]::WriteAllBytes($pfxPath, $pfxBytes)
    [Array]::Clear($pfxBytes, 0, $pfxBytes.Length)
    $pfxBytes = $null
    $certificateSha256 = $certificate.GetCertHashString(
        [Security.Cryptography.HashAlgorithmName]::SHA256).ToLowerInvariant()

    $apiEnvironment = @{
        ASPNETCORE_ENVIRONMENT = 'Development'
        ASPNETCORE_URLS = $controlOrigin
        ASPNETCORE_Kestrel__Certificates__Default__Path = $pfxPath
        ASPNETCORE_Kestrel__Certificates__Default__Password = $pfxPasswordText
        ENSOU_ENROLLMENT__MODE = 'Development'
        ENSOU_CONNECTIONSTRINGS__POSTGRES = $connectionString
        ENSOU_CONTROLPLANE__PUBLICORIGIN = $controlOrigin
        ENSOU_CONTROLPLANE__GATEWAYORIGIN = $controlOrigin
        ENSOU_CONTROLPLANE__ARTIFACTORIGIN = $controlOrigin
        ENSOU_CONTROLPLANE__SUPPORTDISPLAY = 'Development lifecycle administrator'
        # Development mode still constructs its dev-only deterministic identity
        # adapter even though this lifecycle never invokes that callback path.
        # These two placeholders satisfy host construction only; employee
        # identity is established exclusively by the administrator invite.
        ENSOU_DEVELOPMENTENROLLMENT__CORPID = 'ww1234567890abcdef'
        ENSOU_DEVELOPMENTENROLLMENT__WECOMUSERID = 'unused-admin-invite-adapter'
        ENSOU_DEVELOPMENTENROLLMENT__ADMININVITEFALLBACKENABLED = 'true'
        ENSOU_DEVELOPMENTGATEWAY__MODE = 'DeterministicSse'
        ENSOU_DEVELOPMENTGATEWAY__REQUIRERELEASEUPDATEPOLICY = 'true'
    }
    foreach ($name in $developmentConfig.Keys) {
        $apiEnvironment[$name] = $developmentConfig[$name]
    }
    if ($null -ne $feedInternalSecret) {
        $apiEnvironment['DevelopmentFeedAuthorization__InternalSecret'] = $feedInternalSecret
    }
    $originalApiEnvironment = Set-ChildEnvironment -Values $apiEnvironment
    try {
        $apiDll = Join-Path $controlRoot 'src\Ensou.Dsh.Enterprise.ControlPlane.Api\bin\Release\net10.0\Ensou.Dsh.Enterprise.ControlPlane.Api.dll'
        $apiProcess = Start-Process `
            -FilePath 'dotnet' `
            -ArgumentList @($apiDll, '--urls', $controlOrigin) `
            -WorkingDirectory $controlRoot `
            -WindowStyle Hidden `
            -RedirectStandardOutput (Join-Path $logRoot 'control-plane.stdout.log') `
            -RedirectStandardError (Join-Path $logRoot 'control-plane.stderr.log') `
            -PassThru
    }
    finally {
        Restore-ChildEnvironment -Original $originalApiEnvironment
    }
    Wait-HttpsLive -Origin $controlOrigin -Process $apiProcess
    # A local Docker VM clock can be ahead of the Windows API clock. The
    # administrator assignment uses the database timestamp as valid_from, so
    # wait for the API clock to reach that exact confirmed timestamp before
    # issuing the short-lived activation code.
    Wait-LocalEligibilityClock -EligibleAtUtc $entitlementEligibleAtUtc

    try {
        $activationCode = New-AdminActivationCode -AdminDll $adminDll -Arguments @(
            'activation', 'issue',
            '--employee-id', $employeeId,
            '--operation-id', [Guid]::NewGuid().ToString('D'),
            '--reason-code', 'DEVELOPMENT_E2E_ACTIVATION',
            '--expected-version', '0') `
            -ConnectionString $connectionString `
            -ExpectedEmployeeId ([Guid]$employeeId)
        $enrollmentArguments = New-CommonRunnerArguments `
            -Phase 'enroll-chat' `
            -EvidencePath (Join-Path $evidenceRoot '01-enroll-chat.json')
        $enrollmentRunnerEnvironment = $null
        $directEnrollmentEnvironment = $null
        if ($EnterpriseDirectLocal) {
            $enrollmentArguments += @(
                '--update-manifest', $initialManifestPath,
                '--launcher-archive', (Join-Path $payloadRoot 'launcher.zip'),
                '--runtime-archive', (Join-Path $payloadRoot 'runtime.zip'),
                '--plugin-policy-release-id', $pluginPolicyReleaseId,
                '--plugin-policy-archive', $pluginPolicyArchive,
                '--plugin-policy-id', $pluginPolicyId,
                '--plugin-policy-generation', [string]$pluginPolicyGeneration,
                '--plugin-policy-sha256', $pluginPolicySha256,
                '--plugin-archive-sha256', [string]$pluginPolicyEvidence.ArchiveSha256)
            $directEnrollmentEnvironment = @{
                ENSOU_DSH_E2E_FEED_INTERNAL_SECRET = $feedInternalSecret
            }
            foreach ($name in $releaseUpdateEnvironment.Keys) {
                $directEnrollmentEnvironment[$name] = $releaseUpdateEnvironment[$name]
            }
            $enrollmentRunnerEnvironment = Set-ChildEnvironment `
                -Values $directEnrollmentEnvironment
        }
        try {
            Invoke-EnrollmentRunner `
                -RunnerDll $runnerDll `
                -Arguments $enrollmentArguments `
                -WorkingDirectory $repositoryRoot `
                -ActivationCode ([ref]$activationCode)
        }
        finally {
            if ($null -ne $enrollmentRunnerEnvironment) {
                Restore-ChildEnvironment -Original $enrollmentRunnerEnvironment
            }
            if ($null -ne $directEnrollmentEnvironment) {
                foreach ($name in @($directEnrollmentEnvironment.Keys)) {
                    $directEnrollmentEnvironment[$name] = $null
                }
                $directEnrollmentEnvironment = $null
            }
        }
    }
    finally {
        [Environment]::SetEnvironmentVariable(
            'ENSOU_DSH_E2E_ACTIVATION_CODE',
            $null,
            'Process')
        $activationCode = [string]::Empty
    }
    $enrollmentEvidence = Get-Content -LiteralPath (Join-Path $evidenceRoot '01-enroll-chat.json') `
        -Raw | ConvertFrom-Json -Depth 16
    if ([string]$enrollmentEvidence.status -cne 'passed' -or
        [string]$enrollmentEvidence.evidence.clientState -cne 'READY' -or
        [string]$enrollmentEvidence.evidence.runtimeProfile -cne $(if ($EnterpriseDirectLocal) {
            'enterprise-direct-local'
        } else {
            'enterprise-managed'
        })) {
        throw 'Enrollment did not produce an exact READY result for the selected runtime profile.'
    }
    if ($EnterpriseDirectLocal) {
        if ([bool]$enrollmentEvidence.evidence.hostStarted -or
            -not [bool]$enrollmentEvidence.evidence.launcherRestartRequired -or
            [string]$enrollmentEvidence.evidence.releaseSetId -cne
                [string]$policyInstallEvidence.evidence.releaseSetId -or
            [long]$enrollmentEvidence.evidence.releaseGeneration -ne 1 -or
            [long]$enrollmentEvidence.evidence.releaseSequence -ne 1 -or
            [string]$enrollmentEvidence.evidence.healthState -cne 'healthy' -or
            [string]$enrollmentEvidence.evidence.policyReleaseId -cne $pluginPolicyReleaseId -or
            [string]$enrollmentEvidence.evidence.policyId -cne $pluginPolicyId -or
            [long]$enrollmentEvidence.evidence.policyGeneration -ne $pluginPolicyGeneration -or
            [string]$enrollmentEvidence.evidence.policySha256 -cne $pluginPolicySha256 -or
            [string]$enrollmentEvidence.evidence.skillsTreeSha256 -cnotmatch '^[0-9a-f]{64}$' -or
            -not [bool]$enrollmentEvidence.evidence.alternateRawPolicyBindingRejected -or
            [long]$enrollmentEvidence.evidence.authenticatedInitialFeedRequestCount -lt 2 -or
            [string]$enrollmentEvidence.evidence.modelTransport -cne
                'DIRECT_LOCAL_DEVICE_KEY_NOT_EXERCISED') {
            throw 'Direct-local enrollment did not close seq0 through the signed release, health, policy, and restart gate.'
        }
    }
    elseif (-not [bool]$enrollmentEvidence.evidence.hostStarted -or
        [bool]$enrollmentEvidence.evidence.launcherRestartRequired -or
        [string]$enrollmentEvidence.evidence.modelTransport -cne 'MANAGED_LOOPBACK_GATEWAY') {
        throw 'Managed enrollment did not start its authorized Host and gateway path.'
    }
    $updateBindingId = [string]$enrollmentEvidence.evidence.bindingId
    if ($EnterpriseDirectLocal) {
        $initialFeedAuditRows = @(Read-FeedAuthorizationAudit `
            -ContainerName $containerName `
            -DatabaseName $databaseName `
            -BindingId $updateBindingId)
        $expectedInitialFeedRequestCount =
            [long]$enrollmentEvidence.evidence.authenticatedInitialFeedRequestCount
        if ($initialFeedAuditRows.Count -ne $expectedInitialFeedRequestCount -or
            $initialFeedAuditRows.Count -lt 2 -or
            @($initialFeedAuditRows | Where-Object {
                [string]$_.bindingId -cne $updateBindingId -or
                [string]$_.outcome -cne 'PUBLIC_STABLE' -or
                [string]$_.policyId -cne [string]$feedPolicySetPublicReceipt.policy_id -or
                [long]$_.policyVersion -ne [long]$feedPolicySetPublicReceipt.policy_version
            }).Count -ne 0) {
            throw 'Direct-local initial release feed requests lack exact real Control Plane authorization audits.'
        }
        $realFeedAuthorizationAuditVerified = $true
    }
    $initialSequence1Receipts = @(Read-DeviceUpdateReceipts `
        -ContainerName $containerName `
        -DatabaseName $databaseName `
        -BindingId $updateBindingId)
    $initialExactSequence1Receipts = @($initialSequence1Receipts | Where-Object {
        [long]$_.manifest_sequence -eq 1 -and
        [string]$_.release_set_id -ceq [string]$policyInstallEvidence.evidence.releaseSetId -and
        [string]$_.manifest_sha256 -ceq [string]$policyInstallEvidence.evidence.manifestSha256 -and
        [string]$_.outcome -ceq 'INSTALLED'
    })
    if ($initialSequence1Receipts.Count -ne 1 -or
        $initialExactSequence1Receipts.Count -ne 1) {
        throw 'Initial binding did not persist exactly one sequence-1 INSTALLED receipt.'
    }

    Invoke-Runner -RunnerDll $runnerDll `
        -Arguments (New-CommonRunnerArguments -Phase 'refresh-chat' -EvidencePath (Join-Path $evidenceRoot '02-restart-refresh-chat.json')) `
        -WorkingDirectory $repositoryRoot

    $sequence1ReceiptsAfterCleanRefresh = @(Read-DeviceUpdateReceipts `
        -ContainerName $containerName `
        -DatabaseName $databaseName `
        -BindingId $updateBindingId)
    $exactSequence1ReceiptsAfterCleanRefresh = @(
        $sequence1ReceiptsAfterCleanRefresh | Where-Object {
            [long]$_.manifest_sequence -eq 1 -and
            [string]$_.release_set_id -ceq [string]$policyInstallEvidence.evidence.releaseSetId -and
            [string]$_.manifest_sha256 -ceq [string]$policyInstallEvidence.evidence.manifestSha256 -and
            [string]$_.outcome -ceq 'INSTALLED'
        })
    if ($sequence1ReceiptsAfterCleanRefresh.Count -ne 1 -or
        $exactSequence1ReceiptsAfterCleanRefresh.Count -ne 1 -or
        [string]$exactSequence1ReceiptsAfterCleanRefresh[0].receipt_id -cne
            [string]$initialExactSequence1Receipts[0].receipt_id) {
        throw 'Clean refresh did not preserve the exact acknowledged sequence-1 receipt without duplication.'
    }
    Write-PassedEvidence `
        -Path (Join-Path $evidenceRoot '02a-sequence-1-update-receipts.json') `
        -Evidence ([ordered]@{
            bindingId = $updateBindingId
            initialBindingExactInstalledReceiptCount = $initialExactSequence1Receipts.Count
            afterCleanRefreshExactInstalledReceiptCount = $exactSequence1ReceiptsAfterCleanRefresh.Count
            cleanRefreshDuplicateSuppressed = $true
            initialBindingReceipts = $initialSequence1Receipts
            receiptsAfterCleanRefresh = $sequence1ReceiptsAfterCleanRefresh
        })

    # Enrollment legitimately moves PRE_REGISTERED to ACTIVE. Establish the
    # update baseline after that transition, while retaining assignment epochs.
    $employeesBeforeUpdate = @(Invoke-AdminJson -AdminDll $adminDll `
        -Arguments @('employee', 'show', '--employee-id', $employeeId) `
        -ConnectionString $connectionString)
    if ($employeesBeforeUpdate.Count -ne 1) {
        throw 'Pre-update employee readback did not return exactly one employee.'
    }
    $employeeAssignmentBeforeUpdate = Get-EmployeeAssignmentSnapshot `
        -Employee $employeesBeforeUpdate[0]
    if ($employeeAssignmentBeforeUpdate['state'] -cne 'ACTIVE') {
        throw 'Enrollment did not activate the employee before automatic update.'
    }
    foreach ($field in @('employeeId', 'employeeRef', 'authEpoch', 'entitlementEpoch')) {
        if ($employeeAssignmentBeforeUpdate[$field] -cne $employeeAssignmentBeforeEnrollment[$field]) {
            throw 'Enrollment changed an employee assignment identity or epoch.'
        }
    }

    $updateReady = Join-Path $tempRoot 'signals\update.ready'
    $updateContinue = Join-Path $tempRoot 'signals\update.continue'
    $updateToken = ConvertTo-Base64Url ([Security.Cryptography.RandomNumberGenerator]::GetBytes(24))
    $updatePhase = if ($AutomaticRuntimeUpdate) { 'automatic-release-update' } else { 'refresh-update-required' }
    $updateEvidenceName = if ($AutomaticRuntimeUpdate) { '02d-real-runtime-automatic-update.json' } else { '02d-old-release-update-required.json' }
    $updateRequiredArguments = New-CommonRunnerArguments `
        -Phase $updatePhase `
        -EvidencePath (Join-Path $evidenceRoot $updateEvidenceName)
    $updateRequiredArguments += @(
        '--ready-signal', $updateReady,
        '--continue-signal', $updateContinue,
        '--signal-token', $updateToken)
    if ($AutomaticRuntimeUpdate) {
        $updateRequiredArguments += @(
            '--launcher-archive', (Join-Path $payloadRoot 'launcher.zip'),
            '--runtime-archive', (Join-Path $payloadRoot 'runtime.zip'),
            '--plugin-policy-archive', $pluginPolicyArchive,
            '--release-private-key', $releasePrivateKeyPath,
            '--update-manifest', $updateManifestPath)
        $updateRequiredArguments += $targetRunnerArguments
    }
    $updateRequiredProcess = Start-Runner `
        -RunnerDll $runnerDll `
        -Arguments $updateRequiredArguments `
        -WorkingDirectory $repositoryRoot `
        -StdoutPath (Join-Path $logRoot 'update-required-runner.stdout.log') `
        -StderrPath (Join-Path $logRoot 'update-required-runner.stderr.log')
    # A real-runtime run measured 40 seconds for context validation and 26
    # seconds for authorization before Host admission even began. Keep the
    # probe-host bound, but allow the real Host's separately bounded admission.
    Wait-ExactFile -Path $updateReady -Process $updateRequiredProcess `
        -Seconds $(if ($AutomaticRuntimeUpdate) { 240 } else { 90 })
    $updatePolicyImport = Invoke-AdminJson -AdminDll $adminDll -Arguments @(
        'release-policy', 'import',
        '--handoff-document', $updateHandoffPath,
        '--operation-id', [Guid]::NewGuid().ToString('D'),
        '--reason-code', 'DEVELOPMENT_E2E_RELEASE_SEQUENCE_2',
        '--expected-version', '0') -ConnectionString $connectionString
    if ([string]$updatePolicyImport.channel -cne 'lab' -or
        [string]$updatePolicyImport.release_set_id -cne [string]$policyInstallEvidence.evidence.updateReleaseSetId -or
        [long]$updatePolicyImport.sequence -ne 2 -or
        [long]$updatePolicyImport.min_accepted_sequence -ne 1 -or
        [string]$updatePolicyImport.manifest_sha256 -cne [string]$policyInstallEvidence.evidence.updateManifestSha256 -or
        [string]$updatePolicyImport.outcome -cne 'CREATED') {
        throw 'Signed sequence-2 release-policy handoff was not imported exactly.'
    }
    $updateToken | Set-Content -LiteralPath $updateContinue -Encoding ascii -NoNewline
    Wait-ProcessChecked `
        -Process $updateRequiredProcess `
        -Seconds $(if ($AutomaticRuntimeUpdate) { 600 } else { 120 }) `
        -Description $(if ($AutomaticRuntimeUpdate) { 'Real managed-runtime automatic update runner' } else { 'Grace-expired old-release update gate runner' })

    if ($AutomaticRuntimeUpdate) {
        $automaticTransportEvidence = Get-Content -LiteralPath `
            (Join-Path $evidenceRoot $updateEvidenceName) -Raw | ConvertFrom-Json
        if ($automaticTransportEvidence.status -cne 'passed' -or
            $automaticTransportEvidence.evidence.artifactTransport -cne 'LOCAL_PINNED_HTTPS' -or
            $automaticTransportEvidence.evidence.artifactTransportPubliclyReachable -ne $false -or
            $automaticTransportEvidence.evidence.artifactHttpsManifestFetchCount -lt 1) {
            throw 'Automatic update did not prove its exact manifest fetch over local pinned HTTPS.'
        }
        if ([string]$automaticTransportEvidence.evidence.bindingId -cne $updateBindingId) {
            throw 'Automatic update did not preserve the enrolled device binding.'
        }
        if ($hasTargetRuntime -and
            ($automaticTransportEvidence.evidence.runtimeDownloaded -ne $true -or
             $automaticTransportEvidence.evidence.distinctRuntimeActivated -ne $true -or
             $automaticTransportEvidence.evidence.targetRuntimeHttpsFetchCount -lt 1)) {
            throw 'Automatic update did not prove a distinct target runtime download and healthy activation.'
        }
        if ($EnterpriseDirectLocal) {
            $credentialRuntimeReleaseId = if ($hasTargetRuntime) {
                [string]$targetRuntimeEvidence.ReleaseId
            } else {
                $runtimeReleaseId
            }
            $credentialVerification = Assert-DevelopmentDirectLocalCredentialRetained `
                -Evidence $directCredentialEvidence `
                -RuntimeDirectory (Join-Path (Join-Path $managedRoot 'runtimes') $credentialRuntimeReleaseId) `
                -VerifierPath (Join-Path $PSScriptRoot 'Test-EnterpriseDirectLocalCredentialValue.mjs') `
                -Stage 'automatic-runtime-update'
            $directCredentialVerificationStages.Add($credentialVerification)
            Write-PassedEvidence `
                -Path (Join-Path $evidenceRoot '02d-direct-local-credential-value-runtime-update.json') `
                -Evidence $credentialVerification
        }
    }

    if (-not $AutomaticRuntimeUpdate) {
        $applyUpdateArguments = @(
            '--phase', 'apply-release-update',
            '--isolation-id', $runId,
            '--evidence', (Join-Path $evidenceRoot '02e-sequence-2-release-installation.json'),
            '--local-app-data-root', $localAppDataRoot,
            '--user-profile-root', $userProfileRoot,
            '--launcher-archive', (Join-Path $payloadRoot 'launcher.zip'),
            '--runtime-archive', (Join-Path $payloadRoot 'runtime.zip'),
            '--plugin-policy-archive', $pluginPolicyArchive,
            '--release-private-key', $releasePrivateKeyPath,
            '--update-manifest', $updateManifestPath)
        $applyUpdateArguments += $targetRunnerArguments
        Invoke-Runner `
            -RunnerDll $runnerDll `
            -Arguments $applyUpdateArguments `
            -WorkingDirectory $repositoryRoot
    }
    if ($hasTargetRuntime) {
        # The policy was admitted for both runtimes before initial enrollment.
        # No administrator reassignment or credential reset may help recovery.
        $runtimeReleaseId = [string]$targetRuntimeEvidence.ReleaseId
    }
    Invoke-Runner -RunnerDll $runnerDll `
        -Arguments (New-CommonRunnerArguments `
            -Phase 'refresh-chat' `
            -EvidencePath (Join-Path $evidenceRoot '02f-update-recovered-refresh-chat.json')) `
        -WorkingDirectory $repositoryRoot
    if ($EnterpriseDirectLocal) {
        $credentialVerification = Assert-DevelopmentDirectLocalCredentialRetained `
            -Evidence $directCredentialEvidence `
            -RuntimeDirectory (Join-Path (Join-Path $managedRoot 'runtimes') $runtimeReleaseId) `
            -VerifierPath (Join-Path $PSScriptRoot 'Test-EnterpriseDirectLocalCredentialValue.mjs') `
            -Stage 'post-runtime-update-refresh'
        $directCredentialVerificationStages.Add($credentialVerification)
        Write-PassedEvidence `
            -Path (Join-Path $evidenceRoot '02e-direct-local-credential-value-refresh.json') `
            -Evidence $credentialVerification
    }

    $sequence2Receipts = @(Read-DeviceUpdateReceipts `
        -ContainerName $containerName `
        -DatabaseName $databaseName `
        -BindingId $updateBindingId)
    $exactSequence2Receipts = @($sequence2Receipts | Where-Object {
        [long]$_.manifest_sequence -eq 2 -and
        [string]$_.release_set_id -ceq [string]$policyInstallEvidence.evidence.updateReleaseSetId -and
        [string]$_.manifest_sha256 -ceq [string]$policyInstallEvidence.evidence.updateManifestSha256 -and
        [string]$_.outcome -ceq 'INSTALLED'
    })
    if ($exactSequence2Receipts.Count -ne 1) {
        throw 'Updated client did not persist exactly one sequence-2 INSTALLED receipt before authorization recovery.'
    }
    Write-PassedEvidence `
        -Path (Join-Path $evidenceRoot '02g-sequence-2-update-receipts.json') `
        -Evidence ([ordered]@{
            bindingId = $updateBindingId
            exactInstalledReceiptCount = $exactSequence2Receipts.Count
            receipts = $sequence2Receipts
            authorizationRecovered = $true
            gatewayRecovered = [bool](-not $EnterpriseDirectLocal)
        })

    if ($hasTargetLauncher) {
        # Continue on the enrolled device after sequence 2; only Launcher changes.
        $launcherManifestPath = Join-Path $evidenceRoot '02h-release-set-sequence-3.json'
        $launcherJournalPath = Join-Path $evidenceRoot '02h1-promotion-journal-sequence-3.json'
        $launcherPromotionPath = Join-Path $evidenceRoot '02h2-promotion-result-sequence-3.json'
        $launcherHandoffPath = Join-Path $evidenceRoot '02h3-release-policy-handoff-sequence-3.json'
        $launcherPreparationPath = Join-Path $evidenceRoot '02h4-launcher-update-prepared.json'
        $launcherTargetArguments = @(
            '--target-launcher-release-id', $ExpectedTargetLauncherReleaseId,
            '--target-launcher-archive', $targetLauncherArchive)
        $launcherArchiveArguments = @(
            '--launcher-archive', (Join-Path $payloadRoot 'launcher.zip'),
            '--runtime-archive', $targetRuntimeCopy,
            '--plugin-policy-archive', $pluginPolicyArchive,
            '--release-private-key', $releasePrivateKeyPath)
        $prepareArguments = New-CommonRunnerArguments `
            -Phase 'prepare-launcher-update' -EvidencePath $launcherPreparationPath
        $prepareArguments += $launcherArchiveArguments + $launcherTargetArguments + @(
            '--plugin-policy-release-id', $pluginPolicyReleaseId,
            '--plugin-policy-id', $pluginPolicyId,
            '--plugin-policy-generation', [string]$pluginPolicyGeneration,
            '--plugin-policy-sha256', $pluginPolicySha256,
            '--plugin-archive-sha256', [string]$pluginPolicyEvidence.ArchiveSha256,
            '--update-manifest-output', $launcherManifestPath,
            '--update-journal-output', $launcherJournalPath,
            '--update-promotion-result-output', $launcherPromotionPath)
        Assert-EnterpriseDevelopmentRuntimeLockedInputUnchanged -Descriptor $targetLauncherLock
        Invoke-Runner -RunnerDll $runnerDll -Arguments $prepareArguments -WorkingDirectory $repositoryRoot
        $launcherPrepared = Get-Content -LiteralPath $launcherPreparationPath -Raw | ConvertFrom-Json
        if ($launcherPrepared.status -cne 'passed' -or
            $launcherPrepared.evidence.activationDeferred -ne $true -or
            $launcherPrepared.evidence.sequence -ne 3 -or
            $launcherPrepared.evidence.minAcceptedSequence -ne 2 -or
            $launcherPrepared.evidence.currentSequence -ne 2 -or
            $launcherPrepared.evidence.targetLauncherReleaseId -cne $ExpectedTargetLauncherReleaseId -or
            $launcherPrepared.evidence.targetLauncherArchiveSha256 -cne $ExpectedTargetLauncherArchiveSha256) {
            throw 'Launcher-only update preparation did not preserve the healthy sequence-2 input and exact target.'
        }
        New-DevelopmentSignedPolicyHandoff -PromotionResultPath $launcherPromotionPath -HandoffPath $launcherHandoffPath
        $launcherUpdateReady = Join-Path $tempRoot 'signals\launcher-update.ready'
        $launcherUpdateContinue = Join-Path $tempRoot 'signals\launcher-update.continue'
        $launcherUpdateToken = ConvertTo-Base64Url ([Security.Cryptography.RandomNumberGenerator]::GetBytes(24))
        $launcherUpdateEvidencePath = Join-Path $evidenceRoot '02i-real-launcher-automatic-update.json'
        $launcherUpdatePhase = if ($InstalledLauncherUpdate) { 'installed-launcher-update' } else { 'automatic-release-update' }
        $launcherUpdateArguments = New-CommonRunnerArguments `
            -Phase $launcherUpdatePhase -EvidencePath $launcherUpdateEvidencePath
        $launcherUpdateArguments += $launcherArchiveArguments + $launcherTargetArguments + @(
            '--update-manifest', $launcherManifestPath,
            '--ready-signal', $launcherUpdateReady,
            '--continue-signal', $launcherUpdateContinue,
            '--signal-token', $launcherUpdateToken)
        $launcherRunnerEnvironment = $null
        if ($InstalledLauncherUpdate) {
            $launcherRunnerEnvironment = Set-ChildEnvironment -Values @{
                ENSOU_DSH_E2E_FEED_INTERNAL_SECRET = $feedInternalSecret
            }
        }
        try {
            $launcherUpdateProcess = Start-Runner -RunnerDll $runnerDll -Arguments $launcherUpdateArguments `
                -WorkingDirectory $repositoryRoot `
                -StdoutPath (Join-Path $logRoot 'launcher-update-runner.stdout.log') `
                -StderrPath (Join-Path $logRoot 'launcher-update-runner.stderr.log')
        }
        finally {
            if ($null -ne $launcherRunnerEnvironment) {
                Restore-ChildEnvironment -Original $launcherRunnerEnvironment
            }
        }
        Wait-ExactFile -Path $launcherUpdateReady -Process $launcherUpdateProcess -Seconds 240
        $launcherUpdateImport = Invoke-AdminJson -AdminDll $adminDll -Arguments @(
            'release-policy', 'import', '--handoff-document', $launcherHandoffPath,
            '--operation-id', [Guid]::NewGuid().ToString('D'),
            '--reason-code', 'DEVELOPMENT_E2E_RELEASE_SEQUENCE_3', '--expected-version', '0') `
            -ConnectionString $connectionString
        if ($launcherUpdateImport.channel -cne 'lab' -or
            $launcherUpdateImport.release_set_id -cne $launcherPrepared.evidence.releaseSetId -or
            $launcherUpdateImport.sequence -ne 3 -or $launcherUpdateImport.min_accepted_sequence -ne 2 -or
            $launcherUpdateImport.manifest_sha256 -cne $launcherPrepared.evidence.manifestSha256 -or
            $launcherUpdateImport.outcome -cne 'CREATED') {
            throw 'Signed sequence-3 release-policy handoff was not imported exactly.'
        }
        if ($InstalledLauncherUpdate -and $null -eq $feedPolicySetPublicReceipt) {
            $feedPolicyValidFrom = [DateTimeOffset]::UtcNow.AddMinutes(-1).ToString(
                "yyyy-MM-dd'T'HH:mm:ss'Z'")
            $feedPolicyValidUntil = [DateTimeOffset]::UtcNow.AddHours(2).ToString(
                "yyyy-MM-dd'T'HH:mm:ss'Z'")
            $feedPolicySetPublicReceipt = Invoke-AdminJson -AdminDll $adminDll -Arguments @(
                'feed-policy', 'set-public',
                '--policy-id', "stable-public-$runId",
                '--valid-from', $feedPolicyValidFrom,
                '--valid-until', $feedPolicyValidUntil,
                '--operation-id', [Guid]::NewGuid().ToString('D'),
                '--reason-code', 'DEVELOPMENT_E2E_PUBLIC_FEED',
                '--expected-version', '0') -ConnectionString $connectionString
            if ([string]$feedPolicySetPublicReceipt.state -cne 'PUBLIC_STABLE' -or
                [string]$feedPolicySetPublicReceipt.policy_id -cne "stable-public-$runId" -or
                [long]$feedPolicySetPublicReceipt.policy_version -ne 1) {
                throw 'Development public feed policy was not persisted as PUBLIC_STABLE.'
            }
        }
        [IO.File]::WriteAllText($launcherUpdateContinue, $launcherUpdateToken, [Text.Encoding]::ASCII)
        # Staging and the unchanged five-minute product health window are sequential.
        Wait-ProcessChecked -Process $launcherUpdateProcess -Seconds 600 -Description 'Launcher-only automatic update runner'
        $launcherUpdateEvidence = Get-Content -LiteralPath $launcherUpdateEvidencePath -Raw | ConvertFrom-Json
        if ($InstalledLauncherUpdate -and (
            $launcherUpdateEvidence.evidence.actualInstalledLauncherRestart -ne $true -or
            $launcherUpdateEvidence.evidence.backgroundTakeover -ne $true -or
            $launcherUpdateEvidence.evidence.ownedProcessTreeTerminated -ne $true)) {
            throw 'Installed Launcher lane did not prove actual background restart and owned cleanup.'
        }
        if ($launcherUpdateEvidence.status -cne 'passed' -or
            $launcherUpdateEvidence.evidence.sequence -ne 3 -or
            $launcherUpdateEvidence.evidence.healthState -cne 'healthy' -or
            $launcherUpdateEvidence.evidence.artifactTransport -cne 'LOCAL_PINNED_HTTPS' -or
            $launcherUpdateEvidence.evidence.artifactTransportPubliclyReachable -ne $false -or
            $launcherUpdateEvidence.evidence.bindingId -cne $updateBindingId -or
            $launcherUpdateEvidence.evidence.launcherDownloaded -ne $true -or
            $launcherUpdateEvidence.evidence.distinctLauncherActivated -ne $true -or
            $launcherUpdateEvidence.evidence.launcherOnlyComponentsUnchanged -ne $true -or
            $launcherUpdateEvidence.evidence.runtimeDownloaded -ne $false -or
            $launcherUpdateEvidence.evidence.targetLauncherHttpsFetchCount -lt 1 -or
            $launcherUpdateEvidence.evidence.unchangedRuntimeHttpsFetchCount -ne 0 -or
            $launcherUpdateEvidence.evidence.unchangedPluginPolicyHttpsFetchCount -ne 0) {
            throw 'Launcher-only automatic update did not prove exact download, healthy activation and unchanged runtime/policy/binding.'
        }
        if ($InstalledLauncherUpdate) {
            if ([string]$launcherUpdateEvidence.evidence.feedAuthorization.source -cne
                'REAL_CONTROL_API_DPOP_AND_DATABASE') {
                throw 'Installed Launcher feed authorization evidence did not come from the real Control API/database path.'
            }
            $acceptedFeedObservations = @(
                $launcherUpdateEvidence.evidence.feedAuthorization.accepted)
            if ($acceptedFeedObservations.Count -lt 2) {
                throw 'Installed Launcher evidence did not contain manifest and Launcher feed authorizations.'
            }
            $feedAuditRows = @(Read-FeedAuthorizationAudit `
                -ContainerName $containerName -DatabaseName $databaseName -BindingId $updateBindingId)
            $expectedFeedPolicyId = [string]$feedPolicySetPublicReceipt.policy_id
            $expectedFeedPolicyVersion = [long]$feedPolicySetPublicReceipt.policy_version
            $launcherManifest = Get-Content -LiteralPath $launcherManifestPath -Raw |
                ConvertFrom-Json
            $expectedLauncherArtifactUri =
                Get-EnterpriseDevelopmentExpectedLauncherArtifactUri `
                    -Manifest $launcherManifest `
                    -ExpectedReleaseId $ExpectedTargetLauncherReleaseId `
                    -ExpectedArchiveSha256 $ExpectedTargetLauncherArchiveSha256
            $manifestObservation = $false
            $launcherObservation = $false
            foreach ($observation in $acceptedFeedObservations) {
                if ([string]$observation.bindingId -cne [string]$updateBindingId -or
                    [string]$observation.policyId -cne $expectedFeedPolicyId -or
                    [long]$observation.policyVersion -ne $expectedFeedPolicyVersion) {
                    throw 'Installed Launcher decision identity or policy differs from the persisted test policy.'
                }
                $matchingRows = @($feedAuditRows | Where-Object {
                    [string]$_.requestId -ceq [string]$observation.requestId -and
                    [string]$_.bindingId -ceq [string]$updateBindingId -and
                    [string]$_.originalUri -ceq [string]$observation.uri -and
                    [string]$_.outcome -ceq 'PUBLIC_STABLE' -and
                    [string]$_.policyId -ceq $expectedFeedPolicyId -and
                    [long]$_.policyVersion -eq $expectedFeedPolicyVersion
                })
                if ($matchingRows.Count -ne 1) {
                    throw 'Installed Launcher feed authorization evidence did not correlate to exactly one audited decision.'
                }
                if ([string]$observation.uri -ceq
                    'https://updates.example/v2/channels/lab/release-set.v2.json') {
                    $manifestObservation = $true
                }
                if ([string]$observation.uri -ceq $expectedLauncherArtifactUri) {
                    $launcherObservation = $true
                }
            }
            if (-not $manifestObservation -or -not $launcherObservation) {
                throw 'Installed Launcher feed audit did not prove manifest and Launcher authorization.'
            }
            $realFeedAuthorizationAuditVerified = $true
        }
        $launcherReleaseId = $ExpectedTargetLauncherReleaseId
        Invoke-Runner -RunnerDll $runnerDll -Arguments (New-CommonRunnerArguments `
            -Phase 'refresh-chat' -EvidencePath (Join-Path $evidenceRoot '02j-launcher-update-recovered-chat.json')) `
            -WorkingDirectory $repositoryRoot
        $sequence3Receipts = @(Read-DeviceUpdateReceipts -ContainerName $containerName `
            -DatabaseName $databaseName -BindingId $updateBindingId)
        $exactSequence3Receipts = @($sequence3Receipts | Where-Object {
            $_.manifest_sequence -eq 3 -and $_.release_set_id -ceq $launcherPrepared.evidence.releaseSetId -and
            $_.manifest_sha256 -ceq $launcherPrepared.evidence.manifestSha256 -and $_.outcome -ceq 'INSTALLED'
        })
        if ($exactSequence3Receipts.Count -ne 1) {
            throw 'Launcher update did not persist exactly one sequence-3 INSTALLED receipt after authorization recovery.'
        }
        Write-PassedEvidence -Path (Join-Path $evidenceRoot '02k-sequence-3-update-receipts.json') -Evidence ([ordered]@{
            bindingId = $updateBindingId; exactInstalledReceiptCount = $exactSequence3Receipts.Count
            receipts = $sequence3Receipts; authorizationRecovered = $true
            gatewayRecovered = [bool](-not $EnterpriseDirectLocal)
        })
        Assert-EnterpriseDevelopmentRuntimeLockedInputUnchanged -Descriptor $targetLauncherLock
        if ($EnterpriseDirectLocal) {
            $credentialVerification = Assert-DevelopmentDirectLocalCredentialRetained `
                -Evidence $directCredentialEvidence `
                -RuntimeDirectory (Join-Path (Join-Path $managedRoot 'runtimes') $runtimeReleaseId) `
                -VerifierPath (Join-Path $PSScriptRoot 'Test-EnterpriseDirectLocalCredentialValue.mjs') `
                -Stage 'launcher-only-update'
            $directCredentialVerificationStages.Add($credentialVerification)
            Write-PassedEvidence `
                -Path (Join-Path $evidenceRoot '02l-direct-local-credential-value-launcher-update.json') `
                -Evidence $credentialVerification
        }
    }

    $employeesAfterAutomaticUpdate = @(Invoke-AdminJson -AdminDll $adminDll `
        -Arguments @('employee', 'show', '--employee-id', $employeeId) `
        -ConnectionString $connectionString)
    if ($employeesAfterAutomaticUpdate.Count -ne 1) {
        throw 'Automatic update employee assignment readback did not return exactly one employee.'
    }
    $employee = $employeesAfterAutomaticUpdate[0]
    Assert-EmployeeAssignmentSnapshotUnchanged `
        -Before $employeeAssignmentBeforeUpdate `
        -After (Get-EmployeeAssignmentSnapshot -Employee $employee)
    $employeeAssignmentUnchangedAfterUpdate = $true
    $employeeEpoch = [long]$employee.auth_epoch
    $suspendReady = Join-Path $tempRoot 'signals\suspend.ready'
    $suspendContinue = Join-Path $tempRoot 'signals\suspend.continue'
    $suspendToken = ConvertTo-Base64Url ([Security.Cryptography.RandomNumberGenerator]::GetBytes(24))
    $suspendArgs = New-CommonRunnerArguments `
        -Phase 'refresh-wait-denied' `
        -EvidencePath (Join-Path $evidenceRoot '03-employee-suspend.json')
    $suspendArgs += @(
        '--expected-error-code', 'EMPLOYEE_SUSPENDED',
        '--expected-reset-scope', 'MANAGED_CONFIG',
        '--ready-signal', $suspendReady,
        '--continue-signal', $suspendContinue,
        '--signal-token', $suspendToken)
    $suspendProcess = Start-Runner -RunnerDll $runnerDll -Arguments $suspendArgs `
        -WorkingDirectory $repositoryRoot `
        -StdoutPath (Join-Path $logRoot 'suspend-runner.stdout.log') `
        -StderrPath (Join-Path $logRoot 'suspend-runner.stderr.log')
    # Preparing a fresh post-update probe includes the retained release trees,
    # authorization refresh and a streaming request. Full10 measured 93 seconds
    # in the neighboring restart phase; this is not a revocation-response SLA.
    Wait-ExactFile -Path $suspendReady -Process $suspendProcess -Seconds 180
    $suspendReceipt = Invoke-AdminJson -AdminDll $adminDll -Arguments @(
        'employee', 'suspend', '--employee-id', $employeeId,
        '--operation-id', [Guid]::NewGuid().ToString('D'),
        '--reason-code', 'DEVELOPMENT_E2E_SUSPEND',
        '--expected-version', [string]$employeeEpoch) -ConnectionString $connectionString
    $suspendToken | Set-Content -LiteralPath $suspendContinue -Encoding ascii -NoNewline
    Wait-ProcessChecked -Process $suspendProcess -Description 'Employee suspension lifecycle runner'

    $resumeReceipt = Invoke-AdminJson -AdminDll $adminDll -Arguments @(
        'employee', 'resume', '--employee-id', $employeeId,
        '--operation-id', [Guid]::NewGuid().ToString('D'),
        '--reason-code', 'DEVELOPMENT_E2E_RESUME',
        '--expected-version', [string]$suspendReceipt.auth_epoch) -ConnectionString $connectionString
    Invoke-Runner -RunnerDll $runnerDll `
        -Arguments (New-CommonRunnerArguments -Phase 'refresh-chat' -EvidencePath (Join-Path $evidenceRoot '04-resume-refresh-chat.json')) `
        -WorkingDirectory $repositoryRoot

    $devices = @(Invoke-AdminJson -AdminDll $adminDll `
        -Arguments @('device', 'list', '--employee-id', $employeeId) `
        -ConnectionString $connectionString)
    if ($devices.Count -ne 1 -or $devices[0].state -cne 'ACTIVE') {
        throw 'Development lifecycle expected exactly one active device binding.'
    }
    $bindingId = [string]$devices[0].binding_id
    $bindingEpoch = [long]$devices[0].binding_epoch
    $revokeReady = Join-Path $tempRoot 'signals\revoke.ready'
    $revokeContinue = Join-Path $tempRoot 'signals\revoke.continue'
    $revokeToken = ConvertTo-Base64Url ([Security.Cryptography.RandomNumberGenerator]::GetBytes(24))
    $revokeArgs = New-CommonRunnerArguments `
        -Phase 'refresh-wait-denied' `
        -EvidencePath (Join-Path $evidenceRoot '05-device-revoke.json')
    $revokeArgs += @(
        '--expected-error-code', 'DEVICE_BINDING_REVOKED',
        '--expected-reset-scope', 'SECURITY_CREDENTIALS',
        '--ready-signal', $revokeReady,
        '--continue-signal', $revokeContinue,
        '--signal-token', $revokeToken)
    $revokeProcess = Start-Runner -RunnerDll $runnerDll -Arguments $revokeArgs `
        -WorkingDirectory $repositoryRoot `
        -StdoutPath (Join-Path $logRoot 'revoke-runner.stdout.log') `
        -StderrPath (Join-Path $logRoot 'revoke-runner.stderr.log')
    Wait-ExactFile -Path $revokeReady -Process $revokeProcess -Seconds 180
    $revokeReceipt = Invoke-AdminJson -AdminDll $adminDll -Arguments @(
        'device', 'revoke', '--binding-id', $bindingId,
        '--operation-id', [Guid]::NewGuid().ToString('D'),
        '--reason-code', 'DEVELOPMENT_E2E_DEVICE_REVOKE',
        '--expected-version', [string]$bindingEpoch,
        '--confirm', 'DEVICE_REVOKE') -ConnectionString $connectionString
    $revokeToken | Set-Content -LiteralPath $revokeContinue -Encoding ascii -NoNewline
    Wait-ProcessChecked -Process $revokeProcess -Description 'Device revocation lifecycle runner'

    $assertArguments = @(
        '--phase', 'assert-enrollment-required',
        '--isolation-id', $runId,
        '--evidence', (Join-Path $evidenceRoot '06-security-reset-qr-required.json'),
        '--local-app-data-root', $localAppDataRoot,
        '--user-profile-root', $userProfileRoot)
    Invoke-Runner -RunnerDll $runnerDll -Arguments $assertArguments -WorkingDirectory $repositoryRoot
    if ($EnterpriseDirectLocal) {
        $credentialVerification = Assert-DevelopmentDirectLocalCredentialRetained `
            -Evidence $directCredentialEvidence `
            -RuntimeDirectory (Join-Path (Join-Path $managedRoot 'runtimes') $runtimeReleaseId) `
            -VerifierPath (Join-Path $PSScriptRoot 'Test-EnterpriseDirectLocalCredentialValue.mjs') `
            -Stage 'post-security-reset'
        $directCredentialVerificationStages.Add($credentialVerification)
        Write-PassedEvidence `
            -Path (Join-Path $evidenceRoot '06a-direct-local-credential-value-after-reset.json') `
            -Evidence $credentialVerification
    }

    Assert-EnterpriseDevelopmentRuntimeEvidenceUnchanged -Evidence $runtimeEvidence
    Assert-EnterpriseDevelopmentRuntimeLockedInputUnchanged `
        -Descriptor $runtimePayloadEvidence
    if ($hasTargetRuntime) {
        Assert-EnterpriseDevelopmentRuntimeEvidenceUnchanged -Evidence $targetRuntimeEvidence
        Assert-EnterpriseDevelopmentRuntimeLockedInputUnchanged -Descriptor $targetRuntimePayloadEvidence
        Assert-EnterpriseDevelopmentRuntimeLockedInputUnchanged -Descriptor $targetPolicyLock
        Assert-EnterpriseDevelopmentRuntimeLockedInputUnchanged -Descriptor $targetPolicyMetadataLock
    }
    $summary = [ordered]@{
        schemaVersion = 1
        status = 'passed'
        runId = $runId
        completedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
        real = @(
            'isolated external-payload Installer process',
            'signed three-component release-set plugin-policy installation, atomic activation, and installed Launcher process that starts the candidate Runtime and verifies the real WebUI',
            'installed stable Bootstrapper and active Launcher self-check processes',
            'PostgreSQL 17 migrations, invariant checks, and administrator-managed development provisioning',
            'HTTPS Control API with exact leaf-certificate pin in the runner',
            'administrator invite, one-time activation claim, poll and device binding',
            'normalized device display name and validated hashed confirmation-code evidence',
            'DPoP, signed lease verification, DPAPI credential commit and refresh rotation',
            'Publisher-signed release-policy handoffs verified by the compiled-trust Admin CLI and imported into PostgreSQL',
            'DPoP policy GET and exact INSTALLED receipt POST on initial binding and post-update recovery, with duplicate suppression on clean refresh',
            $(if ($EnterpriseDirectLocal) {
                'signed enterprise-direct-local lease v2 authorization after grace with no credential or Harness-home reset'
            } else {
                'gateway CLIENT_UPDATE_REQUIRED enforcement after grace with no credential or Harness-home reset'
            }),
            $(if ($EnterpriseDirectLocal) {
                'device-local Key ownership retained without a server secret reference, gateway proxy, or model request'
            } else {
                'loopback bearer proxy and incrementally produced SSE gateway response'
            }),
            'separate process restart, employee suspend/resume, device revoke and exact resets',
            'workspace preservation across update and reset')
        simulated = @(
            $(if ($AutomaticRuntimeUpdate) {
                $(if ($EnterpriseDirectLocal) {
                    'initial enrollment keeps its sequence-zero Host probe stopped and requires a stable restart; later authorization/reset phases use the probe, while the combined automatic-update phase uses the production adapter and real direct-local DSH process'
                } else {
                    'enrollment, gateway-only and reset phases still use a stateful Host probe; the combined automatic-update phase alone uses the production adapter and real managed DSH process'
                })
            } else {
                $(if ($EnterpriseDirectLocal) {
                    'authorization lifecycle phases use a stateful IEnterpriseHarnessHost probe without gateway traffic; candidate DSH Runtime/WebUI startup is executed separately by the installed release health process'
                } else {
                    'authorization and gateway lifecycle phases use a stateful IEnterpriseHarnessHost probe; candidate DSH Runtime/WebUI startup is executed separately by the installed release health process'
                })
            }),
            $(if ($AutomaticRuntimeUpdate) {
                $(if ($EnterpriseDirectLocal) {
                    'initial signed release and automatic release transport use real Control-Plane-authorized pinned loopback HTTPS, not a public update server; the initial stable restart requirement and later bootstrap restart callbacks are observed rather than relaunching the tray UI'
                } else {
                    'initial installation uses an in-memory handler; automatic release transport uses real pinned loopback HTTPS, not a public update server; bootstrap restart callbacks are observed rather than relaunching the tray UI'
                })
            } else {
                'the signed lifecycle release-set transport uses an in-memory exact HTTPS handler; artifact validation, installation, pointer activation, and installed Launcher health are real'
            }))
        uiOnly = @(
            'The WPF activation-code entry and confirmation click are not driven; the runner invokes and validates the exact device-bound activation claim over HTTPS.')
        signedUpdateChecks = 'Ensou.Dsh.Enterprise.UpdateTests passed in this run.'
        runtime = [ordered]@{
            releaseId = [string]$runtimeEvidence.ReleaseId
            archiveFileName = [string]$runtimeEvidence.ArchiveFileName
            archiveSizeBytes = [int64]$runtimeEvidence.ArchiveSizeBytes
            archiveSha256 = [string]$runtimeEvidence.ArchiveSha256
            metadataSha256 = [string]$runtimeEvidence.MetadataSha256
            sourceBuildSha256 = [string]$runtimeEvidence.SourceBuildSha256
            sourceTag = [string]$runtimeEvidence.SourceTag
            sourceCommit = [string]$runtimeEvidence.SourceCommit
            lockedBeforeAndAfterUse = $true
            mode = if ($EnterpriseDirectLocal) { 'enterprise-direct-local' } else { 'enterprise-managed' }
            syntheticDirectLocalCredentialRetained = [bool]$EnterpriseDirectLocal
            directLocalCredentialValueVerifications = @($directCredentialVerificationStages)
        }
        pluginPolicy = [ordered]@{
            policyId = $pluginPolicyId
            generation = $pluginPolicyGeneration
            rawPolicySha256 = $pluginPolicySha256
            archiveSha256 = [string]$pluginPolicyEvidence.ArchiveSha256
            metadataSha256 = [string]$pluginPolicyEvidence.MetadataSha256
            releaseId = $pluginPolicyReleaseId
            launcherReleaseId = $launcherReleaseId
            runtimeReleaseId = [string]$runtimeEvidence.ReleaseId
            healthState = [string]$(if ($EnterpriseDirectLocal) {
                $enrollmentEvidence.evidence.healthState
            } else {
                $policyInstallEvidence.evidence.healthState
            })
            skillsTreeSha256 = [string]$(if ($EnterpriseDirectLocal) {
                $enrollmentEvidence.evidence.skillsTreeSha256
            } else {
                $policyInstallEvidence.evidence.skillsTreeSha256
            })
            incompatibleArchiveRejected = [bool]$policyInstallEvidence.evidence.incompatibleArchiveRejected
            alternateRawPolicyBindingRejected = [bool]$(if ($EnterpriseDirectLocal) {
                $enrollmentEvidence.evidence.alternateRawPolicyBindingRejected
            } else {
                $policyInstallEvidence.evidence.alternateRawPolicyBindingRejected
            })
            runtimeCompatibilityValidated = [bool]$pluginPolicyEvidence.RuntimeCompatibilityValidated
        }
        automaticUpdateGate = [ordered]@{
            actualInstalledLauncherRestart = [bool]($InstalledLauncherUpdate -and $launcherUpdateEvidence.evidence.actualInstalledLauncherRestart)
            realFeedAuthorizationAuditVerified = [bool]$realFeedAuthorizationAuditVerified
            distinctLauncherArchiveUpgrade = [bool]($hasTargetLauncher -and $launcherUpdateEvidence.evidence.distinctLauncherActivated)
            consecutiveIndependentUpdates = [bool]($hasTargetLauncher -and $exactSequence3Receipts.Count -eq 1)
            realManagedRuntimeAutomaticFlow = [bool]($AutomaticRuntimeUpdate -and -not $EnterpriseDirectLocal)
            realDirectLocalRuntimeAutomaticFlow = [bool]($AutomaticRuntimeUpdate -and $EnterpriseDirectLocal)
            distinctRuntimeArchiveUpgrade = [bool]($hasTargetRuntime -and $AutomaticRuntimeUpdate -and
                $automaticTransportEvidence.evidence.distinctRuntimeActivated)
            transportIsPublicHttps = $false
            transportIsLocalPinnedHttps = [bool]$AutomaticRuntimeUpdate
            channel = 'lab'
            initialReleaseSetId = [string]$initialPolicyImport.release_set_id
            initialSequence = [long]$initialPolicyImport.sequence
            initialManifestSha256 = [string]$initialPolicyImport.manifest_sha256
            initialInstalledReceiptCount = $initialExactSequence1Receipts.Count
            cleanRefreshInstalledReceiptCount = $exactSequence1ReceiptsAfterCleanRefresh.Count
            cleanRefreshDuplicateSuppressed = $true
            requiredReleaseSetId = [string]$updatePolicyImport.release_set_id
            requiredSequence = [long]$updatePolicyImport.sequence
            requiredManifestSha256 = [string]$updatePolicyImport.manifest_sha256
            recoveredInstalledReceiptCount = $exactSequence2Receipts.Count
            graceExpiredOldReleaseBlocked = $true
            resetScope = 'NONE'
            localHomeAndHistoryPreserved = $true
            gatewayRecovered = [bool](-not $EnterpriseDirectLocal)
        }
        targetRuntime = if ($hasTargetRuntime) { [ordered]@{
            releaseId = [string]$targetRuntimeEvidence.ReleaseId
            archiveFileName = [string]$targetRuntimeEvidence.ArchiveFileName
            archiveSizeBytes = [int64]$targetRuntimeEvidence.ArchiveSizeBytes
            archiveSha256 = [string]$targetRuntimeEvidence.ArchiveSha256
            metadataSha256 = [string]$targetRuntimeEvidence.MetadataSha256
            sourceBuildSha256 = [string]$targetRuntimeEvidence.SourceBuildSha256
            sourceTag = [string]$targetRuntimeEvidence.SourceTag
            sourceCommit = [string]$targetRuntimeEvidence.SourceCommit
            upstreamSourceVersionChanged = [bool]($targetRuntimeEvidence.SourceCommit -cne $runtimeEvidence.SourceCommit)
            launcherAndPolicyUnchanged = $true
            employeeReassignmentAfterUpdate = -not $employeeAssignmentUnchangedAfterUpdate
            lockedBeforeAndAfterUse = $true
            pluginPolicyId = [string]$targetPluginPolicyEvidence.PolicyId
            pluginPolicyGeneration = [long]$targetPluginPolicyEvidence.Generation
            pluginPolicySha256 = [string]$targetPluginPolicyEvidence.PolicySha256
        } } else { $null }
        employeeSuspendAuthEpoch = [long]$suspendReceipt.auth_epoch
        employeeResumeAuthEpoch = [long]$resumeReceipt.auth_epoch
        revokedBindingId = [string]$revokeReceipt.binding_id
        evidenceFiles = @(Get-ChildItem -LiteralPath $evidenceRoot -Filter '*.json' -File |
            Select-Object -ExpandProperty Name | Sort-Object)
    }
    $summary | ConvertTo-Json -Depth 6 | Set-Content `
        -LiteralPath (Join-Path $evidenceRoot 'summary.json') `
        -Encoding utf8NoBOM
    $succeeded = $true
    Write-Host "PASS  Full enterprise Development lifecycle. Evidence: $evidenceRoot"
}
catch {
    $failureRecord = $_
    $failureException = $failureRecord.Exception
    $innerException = $failureException.InnerException
    [ordered]@{
        schemaVersion = 1
        status = 'failed'
        runId = $runId
        failedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
        exceptionType = ConvertTo-SafeDevelopmentFailureEvidenceType `
            -Exception $failureException
        failureMessage = ConvertTo-SafeDevelopmentFailureEvidenceMessage `
            -Message $failureException.Message
        innerExceptionType = if ($null -eq $innerException) { $null } else { ConvertTo-SafeDevelopmentFailureEvidenceType -Exception $innerException }
        innerFailureMessage = if ($null -eq $innerException) { $null } else { ConvertTo-SafeDevelopmentFailureEvidenceMessage -Message $innerException.Message }
        retainedDiagnosticsRoot = $tempRoot
    } | ConvertTo-Json -Depth 4 | Set-Content `
        -LiteralPath (Join-Path $evidenceRoot 'summary.json') `
        -Encoding utf8NoBOM
    throw $failureRecord
}
finally {
    # Retained Process handles identify only runners started by this lifecycle.
    # Stop them before their API/database disappear, including ready-signal failures.
    $runnerCleanup = Stop-OwnedLifecycleRunners -Processes $script:ownedLifecycleRunners
    if ($null -ne $apiProcess -and -not $apiProcess.HasExited) {
        try { $apiProcess.Kill($true); $apiProcess.WaitForExit(10000) | Out-Null } catch { }
    }
    for ($index = $runtimeInputLeases.Count - 1; $index -ge 0; $index--) {
        try { $runtimeInputLeases[$index].Dispose() } catch { }
    }
    if ($containerStarted) {
        & docker rm --force --volumes $containerName | Out-Null
    }
    if ($null -ne $pfxBytes) { [Array]::Clear($pfxBytes, 0, $pfxBytes.Length) }
    if ($null -ne $certificate) { $certificate.Dispose() }
    if ($null -ne $certificateKey) { $certificateKey.Dispose() }
    Remove-Item -LiteralPath $postgresEnvFile, $pfxPath, $releasePrivateKeyPath `
        -Force -ErrorAction SilentlyContinue
    $postgresPassword = $null
    foreach ($name in @($developmentConfig.Keys)) { $developmentConfig[$name] = $null }
    $feedInternalSecret = $null
    $feedPolicySetPublicReceipt = $null
    $cleanupReceiptWriteFailed = $false
    try {
        $runnerCleanup | ConvertTo-Json -Depth 3 | Set-Content `
            -LiteralPath (Join-Path $evidenceRoot 'owned-runner-cleanup.json') `
            -Encoding utf8NoBOM
    }
    catch { $cleanupReceiptWriteFailed = $true }
    if ($runnerCleanup.status -cne 'passed') {
        throw 'Owned lifecycle runner cleanup failed; retain the exact run evidence.'
    }
    $developmentKeyName = 'Ensou.Dsh.Enterprise.DeviceKey.DevE2E.v1.' +
        [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData(
            [Text.Encoding]::UTF8.GetBytes($runId))).ToLowerInvariant()
    $developmentKeyProvider = [Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider
    if ([Security.Cryptography.CngKey]::Exists($developmentKeyName, $developmentKeyProvider,
            [Security.Cryptography.CngKeyOpenOptions]::UserKey)) {
        $developmentKey = [Security.Cryptography.CngKey]::Open($developmentKeyName,
            $developmentKeyProvider, [Security.Cryptography.CngKeyOpenOptions]::UserKey)
        try { $developmentKey.Delete() } finally { $developmentKey.Dispose() }
    }
    if ([Security.Cryptography.CngKey]::Exists($developmentKeyName, $developmentKeyProvider,
            [Security.Cryptography.CngKeyOpenOptions]::UserKey)) {
        throw 'The exact isolated lifecycle device key remains after cleanup.'
    }
    if ($cleanupReceiptWriteFailed) {
        throw 'Lifecycle resources were processed but the cleanup receipt could not be written.'
    }
    if ($succeeded) {
        $expectedPrefix = $tempParent.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
        $resolvedTemp = [IO.Path]::GetFullPath($tempRoot)
        if (-not $resolvedTemp.StartsWith($expectedPrefix, [StringComparison]::OrdinalIgnoreCase) -or
            [IO.Path]::GetFileName($resolvedTemp) -cne "ensou-dsh-enterprise-lifecycle-$runId") {
            throw "Refusing to clean an unexpected Development E2E root: $resolvedTemp"
        }
        Remove-Item -LiteralPath $resolvedTemp -Recurse -Force
    }
    else {
        Write-Warning "Development E2E failed; non-secret diagnostics retained at $tempRoot"
    }
}
