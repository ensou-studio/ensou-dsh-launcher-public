#requires -Version 7.2

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$MetadataPath,

    [string]$ArtifactPath = '',
    [string]$ExpectedReleaseId = '',
    [string]$ExpectedArtifactFileName = '',
    [string]$ExpectedArtifactSha256 = '',
    [ValidateSet('enterprise-managed', 'enterprise-direct-local')]
    [string]$ExpectedRuntimeProfile = 'enterprise-managed',
    [switch]$AllowLocalLab
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-NoDuplicateJsonProperties(
    [Text.Json.JsonElement]$Element,
    [string]$JsonPath
) {
    if ($Element.ValueKind -eq [Text.Json.JsonValueKind]::Object) {
        $names = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::Ordinal)
        foreach ($property in $Element.EnumerateObject()) {
            if (-not $names.Add($property.Name)) {
                throw "Source-runtime metadata contains a duplicate JSON member at $JsonPath.$($property.Name)."
            }
            Assert-NoDuplicateJsonProperties `
                -Element $property.Value `
                -JsonPath "$JsonPath.$($property.Name)"
        }
        return
    }
    if ($Element.ValueKind -eq [Text.Json.JsonValueKind]::Array) {
        $index = 0
        foreach ($item in $Element.EnumerateArray()) {
            Assert-NoDuplicateJsonProperties `
                -Element $item `
                -JsonPath "$JsonPath[$index]"
            $index++
        }
    }
}

$metadataFile = (Resolve-Path -LiteralPath $MetadataPath -ErrorAction Stop).Path
$json = Get-Content -Raw -LiteralPath $metadataFile
try {
    $jsonDocument = [Text.Json.JsonDocument]::Parse($json)
}
catch [Text.Json.JsonException] {
    throw "Source-runtime metadata is not valid JSON: $metadataFile"
}
try {
    if ($jsonDocument.RootElement.ValueKind -ne [Text.Json.JsonValueKind]::Object) {
        throw "Source-runtime metadata must be one JSON object: $metadataFile"
    }
    Assert-NoDuplicateJsonProperties `
        -Element $jsonDocument.RootElement `
        -JsonPath '$'

    $schemaVersionElement = [Text.Json.JsonElement]::new()
    if (-not $jsonDocument.RootElement.TryGetProperty(
            'schemaVersion', [ref]$schemaVersionElement) -or
        $schemaVersionElement.ValueKind -ne [Text.Json.JsonValueKind]::Number) {
        throw 'Source-runtime metadata schemaVersion must be one supported numeric version.'
    }
    [int]$schemaVersion = 0
    if (-not $schemaVersionElement.TryGetInt32([ref]$schemaVersion)) {
        throw 'Source-runtime metadata schemaVersion must be one supported numeric version.'
    }
}
finally {
    $jsonDocument.Dispose()
}

$schemaPath = switch ($schemaVersion) {
    2 { Join-Path $PSScriptRoot '..\schemas\source-runtime-metadata.schema.json' }
    3 { Join-Path $PSScriptRoot '..\schemas\enterprise-direct-local-source-runtime-metadata.schema.json' }
    default {
        throw "Unsupported source-runtime metadata schemaVersion: $schemaVersion."
    }
}
$expectedSchemaVersion = switch ($ExpectedRuntimeProfile) {
    'enterprise-managed' { 2 }
    'enterprise-direct-local' { 3 }
}
if ($schemaVersion -ne $expectedSchemaVersion) {
    throw "Source-runtime metadata schemaVersion $schemaVersion does not match expected runtime profile $ExpectedRuntimeProfile."
}
if (-not (Test-Path -LiteralPath $schemaPath -PathType Leaf)) {
    throw "Source-runtime metadata schema is missing: $schemaPath"
}

if (-not (Test-Json -Json $json -SchemaFile $schemaPath -ErrorAction Stop)) {
    throw "Source-runtime metadata does not satisfy the schema: $metadataFile"
}

$metadata = $json | ConvertFrom-Json -Depth 20
if (-not [bool]$metadata.promotionEligible -and -not $AllowLocalLab) {
    throw 'Source-runtime metadata is a local Lab build and is not promotion eligible.'
}
if ($ExpectedReleaseId -and $metadata.releaseId -cne $ExpectedReleaseId) {
    throw "Metadata releaseId mismatch. Expected $ExpectedReleaseId, got $($metadata.releaseId)."
}
if ($ExpectedArtifactFileName -and $metadata.artifact.fileName -cne $ExpectedArtifactFileName) {
    throw "Metadata artifact file name mismatch. Expected $ExpectedArtifactFileName, got $($metadata.artifact.fileName)."
}
if ($ExpectedArtifactSha256 -and $metadata.artifact.sha256 -cne $ExpectedArtifactSha256) {
    throw "Metadata artifact SHA-256 mismatch. Expected $ExpectedArtifactSha256, got $($metadata.artifact.sha256)."
}

if ($ArtifactPath) {
    $artifactFile = (Resolve-Path -LiteralPath $ArtifactPath -ErrorAction Stop).Path
    $artifact = Get-Item -LiteralPath $artifactFile
    if ($metadata.artifact.fileName -cne $artifact.Name) {
        throw "Metadata artifact name does not match the downloaded file: $($artifact.Name)."
    }
    if ([int64]$metadata.artifact.sizeBytes -ne $artifact.Length) {
        throw "Metadata artifact size mismatch. Expected $($metadata.artifact.sizeBytes), got $($artifact.Length)."
    }
    $actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $artifactFile).Hash.ToLowerInvariant()
    if ($metadata.artifact.sha256 -cne $actualHash) {
        throw "Metadata artifact SHA-256 mismatch. Expected $($metadata.artifact.sha256), got $actualHash."
    }
}

$metadata
