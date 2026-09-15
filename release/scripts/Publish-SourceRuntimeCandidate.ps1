#requires -Version 7.2

[CmdletBinding(DefaultParameterSetName = 'Actions')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Actions')][string]$Repository,
    [Parameter(Mandatory = $true, ParameterSetName = 'Actions')][string]$ReleaseId,
    [Parameter(Mandatory = $true, ParameterSetName = 'Actions')][string]$LauncherSourceCommit,
    [Parameter(Mandatory = $true, ParameterSetName = 'Actions')][string]$ActionsArtifactId,
    [Parameter(Mandatory = $true, ParameterSetName = 'Actions')][string]$ArtifactPath,
    [Parameter(Mandatory = $true, ParameterSetName = 'Actions')][string]$MetadataPath,
    [Parameter(Mandatory = $true, ParameterSetName = 'Actions')][string]$HashEvidencePath,
    [Parameter(Mandatory = $true, ParameterSetName = 'Actions')][string]$ManagedCandidatePath,
    [Parameter(Mandatory = $true, ParameterSetName = 'Actions')][string]$ExpectedArtifactFileName,
    [Parameter(Mandatory = $true, ParameterSetName = 'Actions')][string]$ExpectedMetadataFileName,
    [Parameter(Mandatory = $true, ParameterSetName = 'Actions')][string]$ExpectedHashFileName,
    [Parameter(Mandatory = $true, ParameterSetName = 'Actions')][string]$ExpectedArtifactSha256,
    [Parameter(Mandatory = $true, ParameterSetName = 'Actions')][int64]$ExpectedArtifactSizeBytes,
    [Parameter(Mandatory = $true, ParameterSetName = 'Actions')][string]$RunAttempt,

    [Parameter(Mandatory = $true, ParameterSetName = 'LocalReviewed')]
    [string]$LocalReviewedPublicationInputPath,

    [Parameter(Mandatory = $true, ParameterSetName = 'LocalReviewed')]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$ExpectedLocalReviewedPublicationInputSha256,

    [Parameter(Mandatory = $true, ParameterSetName = 'LocalReviewed')]
    [string]$LocalVerificationWorkspace,

    [ValidateSet('enterprise-managed', 'enterprise-direct-local')]
    [string]$RuntimeProfile = 'enterprise-managed'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-OrdinaryReleaseInput(
    [string]$Path,
    [string]$ExpectedFileName,
    [int64]$MaximumBytes,
    [Collections.Generic.List[IDisposable]]$Leases
) {
    $full = [IO.Path]::GetFullPath($Path)
    $item = Get-Item -LiteralPath $full -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $item.Name -cne $ExpectedFileName -or
        $item.Length -le 0 -or $item.Length -gt $MaximumBytes) {
        throw "Release publication input is not one exact bounded ordinary file: $full"
    }
    for ($parent = $item.Directory; $null -ne $parent; $parent = $parent.Parent) {
        if (($parent.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Release publication input crosses a filesystem link: $full"
        }
    }
    $stream = [IO.File]::Open(
        $full,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    try {
        if ($stream.Length -ne $item.Length) {
            throw "Release publication input changed while acquiring its lease: $full"
        }
        $descriptor = [pscustomobject]@{
            FullName = $full
            Name = $item.Name
            Length = [int64]$stream.Length
            DirectoryName = $item.DirectoryName
            Stream = $stream
        }
        $Leases.Add($stream)
        return $descriptor
    }
    catch {
        $stream.Dispose()
        throw
    }
}

function Get-LockedReleaseInputSha256($Descriptor) {
    $Descriptor.Stream.Position = 0
    $sha256 = ([Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData(
            $Descriptor.Stream))).ToLowerInvariant()
    $Descriptor.Stream.Position = 0
    return $sha256
}

function Read-LockedReleaseInputBytes(
    $Descriptor,
    [string]$Label,
    [int64]$MaximumBytes
) {
    if ($null -eq $Descriptor.Stream -or
        -not $Descriptor.Stream.CanRead -or
        -not $Descriptor.Stream.CanSeek -or
        $Descriptor.Stream.Length -le 0 -or
        $Descriptor.Stream.Length -gt $MaximumBytes -or
        $Descriptor.Stream.Length -gt [int]::MaxValue) {
        throw "$Label is not one exact bounded locked input."
    }
    $bytes = [byte[]]::new([int]$Descriptor.Stream.Length)
    $Descriptor.Stream.Position = 0
    try {
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $Descriptor.Stream.Read(
                $bytes,
                $offset,
                $bytes.Length - $offset)
            if ($read -le 0) {
                throw "$Label ended before its locked length."
            }
            $offset += $read
        }
        if ($Descriptor.Stream.ReadByte() -ne -1) {
            throw "$Label exceeded its locked length."
        }
        return ,$bytes
    }
    catch {
        [Array]::Clear($bytes, 0, $bytes.Length)
        throw
    }
    finally {
        $Descriptor.Stream.Position = 0
    }
}

function Assert-LockedReleaseInputUnchanged(
    $Descriptor,
    [int64]$ExpectedSizeBytes,
    [string]$ExpectedSha256
) {
    if ($Descriptor.Stream.Length -ne $ExpectedSizeBytes -or
        (Get-LockedReleaseInputSha256 $Descriptor) -cne $ExpectedSha256) {
        throw "Locked release publication input changed: $($Descriptor.FullName)"
    }
    $pathItem = Get-Item -LiteralPath $Descriptor.FullName -Force -ErrorAction Stop
    if ($pathItem.PSIsContainer -or
        ($pathItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $pathItem.Length -ne $ExpectedSizeBytes) {
        throw "Release publication path no longer names its leased ordinary file: $($Descriptor.FullName)"
    }
}

function Send-LockedReleaseAsset(
    [Net.Http.HttpClient]$HttpClient,
    [Uri]$Uri,
    [hashtable]$Headers,
    $Descriptor,
    [Collections.Generic.List[IDisposable]]$Leases
) {
    if ($null -eq $HttpClient -or
        $null -eq $Descriptor.Stream -or
        -not $Descriptor.Stream.CanRead -or
        -not $Descriptor.Stream.CanSeek -or
        $Descriptor.Stream.Length -ne $Descriptor.Length) {
        throw 'Release asset upload requires one exact readable locked stream.'
    }

    $request = [Net.Http.HttpRequestMessage]::new(
        [Net.Http.HttpMethod]::Post,
        $Uri)
    $requestLeased = $false
    $response = $null
    try {
        foreach ($header in $Headers.GetEnumerator()) {
            $headerName = [string]$header.Key
            $headerValue = [string]$header.Value
            if ([string]::IsNullOrWhiteSpace($headerName) -or
                [string]::IsNullOrWhiteSpace($headerValue) -or
                $headerValue.IndexOf("`r", [StringComparison]::Ordinal) -ge 0 -or
                $headerValue.IndexOf("`n", [StringComparison]::Ordinal) -ge 0 -or
                -not $request.Headers.TryAddWithoutValidation(
                    $headerName,
                    $headerValue)) {
                throw "Release asset upload header is invalid: $headerName"
            }
        }

        $Descriptor.Stream.Position = 0
        $content = [Net.Http.StreamContent]::new($Descriptor.Stream)
        $content.Headers.ContentType =
            [Net.Http.Headers.MediaTypeHeaderValue]::new(
                'application/octet-stream')
        $content.Headers.ContentLength = [int64]$Descriptor.Length
        $request.Content = $content

        # HttpRequestMessage owns StreamContent, which owns the locked stream.
        # Keep that complete request graph alive until all later locked-input
        # checks finish; final lease cleanup disposes it before the file lease.
        $Leases.Add($request)
        $requestLeased = $true

        $response = $HttpClient.SendAsync(
            $request,
            [Net.Http.HttpCompletionOption]::ResponseHeadersRead).
                GetAwaiter().GetResult()
        if ($null -eq $response -or
            $response.StatusCode -ne [Net.HttpStatusCode]::Created) {
            $statusCode = if ($null -eq $response) {
                'no response'
            }
            else {
                [string][int]$response.StatusCode
            }
            throw "GitHub asset upload returned unexpected HTTP status: $statusCode"
        }

        $responseJson = $response.Content.ReadAsStringAsync().
            GetAwaiter().GetResult()
        if ([string]::IsNullOrWhiteSpace($responseJson)) {
            throw 'GitHub asset upload returned no JSON response.'
        }
        return $responseJson | ConvertFrom-Json -Depth 64 -ErrorAction Stop
    }
    finally {
        if ($null -ne $response) {
            $response.Dispose()
        }
        if (-not $requestLeased) {
            $request.Dispose()
        }
        if ($null -ne $Descriptor.Stream -and
            $Descriptor.Stream.CanSeek) {
            $Descriptor.Stream.Position = 0
        }
    }
}

function Assert-NoDuplicateJsonMembers(
    [Text.Json.JsonElement]$Element,
    [string]$Label
) {
    if ($Element.ValueKind -eq [Text.Json.JsonValueKind]::Object) {
        $names = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::Ordinal)
        foreach ($property in $Element.EnumerateObject()) {
            if (-not $names.Add($property.Name)) {
                throw "$Label contains a duplicate JSON member: $($property.Name)"
            }
            Assert-NoDuplicateJsonMembers $property.Value $Label
        }
    }
    elseif ($Element.ValueKind -eq [Text.Json.JsonValueKind]::Array) {
        foreach ($item in $Element.EnumerateArray()) {
            Assert-NoDuplicateJsonMembers $item $Label
        }
    }
}

function Read-StrictJsonObject($Descriptor, [string]$Label) {
    $bytes = Read-LockedReleaseInputBytes $Descriptor $Label (4MB)
    try {
        if ($bytes.Length -ge 3 -and
            $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and
            $bytes[2] -eq 0xBF) {
            throw "$Label must be UTF-8 without a byte-order mark."
        }
        $utf8 = [Text.UTF8Encoding]::new($false, $true)
        $text = $utf8.GetString($bytes)
        $document = [Text.Json.JsonDocument]::Parse(
            [ReadOnlyMemory[byte]]::new($bytes))
        try {
            if ($document.RootElement.ValueKind -ne
                [Text.Json.JsonValueKind]::Object) {
                throw "$Label must be one JSON object."
            }
            Assert-NoDuplicateJsonMembers $document.RootElement $Label
        }
        finally {
            $document.Dispose()
        }
        return $text | ConvertFrom-Json -Depth 64
    }
    finally {
        [Array]::Clear($bytes, 0, $bytes.Length)
    }
}

function Read-LockedAsciiText($Descriptor, [string]$Label) {
    $bytes = Read-LockedReleaseInputBytes $Descriptor $Label (4KB)
    try {
        if (@($bytes | Where-Object { $_ -gt 0x7F }).Count -ne 0) {
            throw "$Label must contain ASCII bytes only."
        }
        return [Text.Encoding]::ASCII.GetString($bytes)
    }
    finally {
        [Array]::Clear($bytes, 0, $bytes.Length)
    }
}

function Get-GitHubStatusCode($ErrorRecord) {
    try {
        if ($null -ne $ErrorRecord.Exception.Response) {
            return [int]$ErrorRecord.Exception.Response.StatusCode
        }
    }
    catch {
        return 0
    }
    return 0
}

function Get-GitHubJsonOrNull([string]$Uri, [hashtable]$Headers) {
    try {
        return Invoke-RestMethod -Method Get -Uri $Uri -Headers $Headers
    }
    catch {
        if ((Get-GitHubStatusCode $_) -eq 404) {
            return $null
        }
        throw
    }
}

function Assert-LightweightTagAtCommit(
    [string]$ApiBase,
    [string]$Tag,
    [string]$Commit,
    [hashtable]$Headers,
    [string]$Label
) {
    $encodedTag = [Uri]::EscapeDataString($Tag)
    $tagRef = Get-GitHubJsonOrNull `
        "$ApiBase/git/ref/tags/$encodedTag" $Headers
    if ($null -eq $tagRef -or
        [string]$tagRef.object.type -cne 'commit' -or
        [string]$tagRef.object.sha -cne $Commit) {
        throw "$Label is not a lightweight tag at the exact Launcher source commit."
    }
}

function Assert-ExactReleaseAssets($Release, [object[]]$ExpectedAssets) {
    $actual = @($Release.assets)
    if ($actual.Count -ne $ExpectedAssets.Count) {
        throw 'GitHub Release does not contain the exact expected asset count.'
    }
    foreach ($expected in $ExpectedAssets) {
        $matches = @($actual | Where-Object {
            [string]$_.name -ceq [string]$expected.Name
        })
        if ($matches.Count -ne 1 -or
            [int64]$matches[0].size -ne [int64]$expected.SizeBytes -or
            ($null -ne $expected.PSObject.Properties['Id'] -and
                [int64]$matches[0].id -ne [int64]$expected.Id)) {
            throw "GitHub Release asset identity differs: $($expected.Name)"
        }
    }
}

function New-SourceRuntimeReviewEvidence(
    [string]$SourceRepository,
    $ImmutableRelease,
    [string]$RuntimeBuildCommit,
    [object[]]$UploadedAssets,
    [object[]]$AssetInputs
) {
    # These facts are emitted after authenticated GitHub checks and download
    # verification. This unsigned handoff is NOT an organization admission.
    if ($SourceRepository -cnotmatch '^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9][A-Za-z0-9._-]{0,99}$' -or
        $RuntimeBuildCommit -cnotmatch '^[0-9a-f]{40}$' -or
        [string]$ImmutableRelease.target_commitish -cne $RuntimeBuildCommit -or
        [string]$ImmutableRelease.tag_name -cnotmatch '^managed-v[0-9]{4}\.[0-9]{2}\.[0-9]{2}\.[0-9]+$' -or
        $ImmutableRelease.immutable -isnot [bool] -or -not $ImmutableRelease.immutable -or
        [bool]$ImmutableRelease.draft -or [long]$ImmutableRelease.id -le 0 -or
        [long]$ImmutableRelease.id -gt 9007199254740991 -or
        $UploadedAssets.Count -ne 3 -or $AssetInputs.Count -ne 3) {
        throw 'Immutable source review evidence requires the verified release, build commit and three exact assets.'
    }
    Assert-ExactReleaseAssets $ImmutableRelease $UploadedAssets
    $roles = @('archive', 'metadata', 'hash-evidence')
    $assets = [Collections.Generic.List[object]]::new()
    $ids = [Collections.Generic.HashSet[long]]::new()
    $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    for ($index=0; $index -lt 3; $index++) {
        $uploaded = $UploadedAssets[$index]; $input = $AssetInputs[$index]
        if ([long]$uploaded.Id -le 0 -or [long]$uploaded.Id -gt 9007199254740991 -or
            -not $ids.Add([long]$uploaded.Id) -or
            [string]$uploaded.Name -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$' -or
            -not $names.Add([string]$uploaded.Name) -or
            [string]$uploaded.Name -cne [string]$input.Name -or
            [long]$uploaded.SizeBytes -ne [long]$input.File.Length -or
            [long]$uploaded.SizeBytes -le 0 -or [long]$uploaded.SizeBytes -gt 8589934592 -or
            [string]$input.Sha256 -cnotmatch '^[0-9a-f]{64}$') {
            throw "Source review asset $index is not the exact verified bounded asset."
        }
        $assets.Add([ordered]@{
            role=$roles[$index]; githubAssetId=[long]$uploaded.Id
            fileName=[string]$uploaded.Name; sizeBytes=[long]$uploaded.SizeBytes
            sha256=[string]$input.Sha256
        })
    }
    return [pscustomobject][ordered]@{
        schemaVersion = 1
        evidenceType = 'ensou-dsh-runtime-source-release-review-input'
        authority = 'UNSIGNED_REVIEW_INPUT_ONLY'
        sourceRelease = [ordered]@{
            repository=$SourceRepository; githubReleaseId=[long]$ImmutableRelease.id
            tagName=[string]$ImmutableRelease.tag_name; targetCommit=$RuntimeBuildCommit
            immutable=$true; assets=@($assets)
        }
    }
}

function Assert-ExactLocalReviewedMembers($Value, [string[]]$Expected, [string]$Label) {
    if ($null -eq $Value -or $Value -isnot [pscustomobject]) {
        throw "$Label must be one object."
    }
    [string[]]$actual = @($Value.PSObject.Properties | ForEach-Object Name)
    [Array]::Sort($actual, [StringComparer]::Ordinal)
    [Array]::Sort($Expected, [StringComparer]::Ordinal)
    if ($actual.Count -ne $Expected.Count -or
        [string]::Join("`n", $actual) -cne [string]::Join("`n", $Expected)) {
        throw "$Label has an unexpected member set."
    }
}

function ConvertFrom-LocalReviewedPublicationInput($Value) {
    Assert-ExactLocalReviewedMembers $Value @(
        'authority', 'immutableReservationTag', 'inputs', 'launcherSourceCommit',
        'releaseId', 'repository', 'schemaVersion') 'Local reviewed publication input'
    if (($Value.schemaVersion -isnot [int] -and $Value.schemaVersion -isnot [long]) -or
        [int64]$Value.schemaVersion -ne 1 -or
        $Value.authority -isnot [string] -or
        $Value.repository -isnot [string] -or
        $Value.releaseId -isnot [string] -or
        $Value.launcherSourceCommit -isnot [string] -or
        $Value.immutableReservationTag -isnot [string] -or
        [string]$Value.authority -cne 'UNSIGNED_REVIEW_INPUT_ONLY' -or
        [string]$Value.repository -cnotmatch '^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9][A-Za-z0-9._-]{0,99}$' -or
        [string]$Value.releaseId -cnotmatch '^managed-v[0-9]{4}\.[0-9]{2}\.[0-9]{2}\.[1-9][0-9]*$' -or
        [string]$Value.launcherSourceCommit -cnotmatch '^[0-9a-f]{40}$' -or
        [string]$Value.immutableReservationTag -cne
            ('ensou-dsh-source-candidate/' + [string]$Value.releaseId)) {
        throw 'Local reviewed publication identity is not canonical.'
    }
    $expected = @(
        [pscustomobject]@{ role = 'archive'; fileName = "EnsouDshRuntime-$($Value.releaseId)-win-x64.zip"; maximumBytes = 8L * 1024 * 1024 * 1024 },
        [pscustomobject]@{ role = 'metadata'; fileName = "EnsouDshRuntime-$($Value.releaseId)-win-x64.metadata.json"; maximumBytes = 4MB },
        [pscustomobject]@{ role = 'hash-evidence'; fileName = "EnsouDshRuntime-$($Value.releaseId)-win-x64.zip.sha256"; maximumBytes = 4KB },
        [pscustomobject]@{ role = 'managed-candidate'; fileName = 'managed-candidate.json'; maximumBytes = 1MB })
    $inputs = @($Value.inputs)
    if ($inputs.Count -ne $expected.Count) {
        throw 'Local reviewed publication input must bind exactly four source-build files.'
    }
    $normalized = [Collections.Generic.List[object]]::new()
    for ($index = 0; $index -lt $expected.Count; $index++) {
        $input = $inputs[$index]
        Assert-ExactLocalReviewedMembers $input @('fileName', 'path', 'role', 'sha256', 'sizeBytes') "Local reviewed input $index"
        $contract = $expected[$index]
        if ([string]$input.role -cne [string]$contract.role -or
            [string]$input.fileName -cne [string]$contract.fileName -or
            $input.path -isnot [string] -or
            -not [IO.Path]::IsPathFullyQualified([string]$input.path) -or
            ([string]$input.path).StartsWith('\\') -or
            [IO.Path]::GetFileName([string]$input.path) -cne [string]$contract.fileName -or
            ($input.sizeBytes -isnot [long] -and $input.sizeBytes -isnot [int]) -or
            [int64]$input.sizeBytes -le 0 -or
            [int64]$input.sizeBytes -gt [int64]$contract.maximumBytes -or
            $input.sha256 -isnot [string] -or
            [string]$input.sha256 -cnotmatch '^[0-9a-f]{64}$') {
            throw "Local reviewed input $index is not one canonical bounded descriptor."
        }
        $normalized.Add([pscustomobject]@{
            Role = [string]$contract.role
            FileName = [string]$contract.fileName
            Path = [IO.Path]::GetFullPath([string]$input.path)
            SizeBytes = [int64]$input.sizeBytes
            Sha256 = [string]$input.sha256
            MaximumBytes = [int64]$contract.maximumBytes
        })
    }
    return [pscustomobject]@{
        Repository = [string]$Value.repository
        ReleaseId = [string]$Value.releaseId
        LauncherSourceCommit = [string]$Value.launcherSourceCommit
        ImmutableReservationTag = [string]$Value.immutableReservationTag
        Inputs = @($normalized)
    }
}

function Copy-LockedLocalReviewedInput($Descriptor, [string]$DestinationPath) {
    $output = $null
    try {
        $Descriptor.Stream.Position = 0
        $output = [IO.File]::Open($DestinationPath, [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write, [IO.FileShare]::None)
        $Descriptor.Stream.CopyTo($output)
        $output.Flush($true)
    }
    finally {
        if ($null -ne $output) { $output.Dispose() }
        if ($null -ne $Descriptor.Stream -and $Descriptor.Stream.CanSeek) {
            $Descriptor.Stream.Position = 0
        }
    }
}

function New-LocalReviewedVerificationWorkspace {
    param([string]$Path, [Collections.Generic.List[IDisposable]]$Leases)

    if ($null -eq ('EnsouLauncherProduction.LocalReviewedDirectoryCreation' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
namespace EnsouLauncherProduction {
  public static class LocalReviewedDirectoryCreation {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool CreateDirectoryW(string path, IntPtr securityAttributes);
    public static void CreateNew(string path) {
      if (!CreateDirectoryW(@"\\?\" + path, IntPtr.Zero)) throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not atomically create LocalReviewed verification workspace.");
    }
  }
}
'@ -ErrorAction Stop
    }
    [EnsouLauncherProduction.LocalReviewedDirectoryCreation]::CreateNew($Path)
    $stateModulePath = Join-Path $PSScriptRoot 'ProductionReleaseState.psm1'
    Microsoft.PowerShell.Core\Import-Module -Name $stateModulePath -Force -ErrorAction Stop
    $directoryLease = ProductionReleaseState\Open-ProductionReleaseDirectoryLease `
        -Path $Path -Label 'Local reviewed verification workspace'
    $Leases.Add($directoryLease.Handle)
    return $directoryLease.Path
}

function Open-LocalReviewedPublicationInputs {
    param(
        [string]$InputPath,
        [string]$ExpectedInputSha256,
        [string]$VerificationWorkspace,
        [Collections.Generic.List[IDisposable]]$Leases)

    $inputDescriptor = Get-OrdinaryReleaseInput `
        $InputPath 'local-reviewed-source-runtime-publication.v1.json' 64KB $Leases
    $inputDescriptorSha256 = Get-LockedReleaseInputSha256 $inputDescriptor
    if ($inputDescriptorSha256 -cne $ExpectedInputSha256) {
        throw 'Local reviewed publication input differs from its expected SHA-256.'
    }
        $local = ConvertFrom-LocalReviewedPublicationInput `
            (Read-StrictJsonObject $inputDescriptor 'Local reviewed publication input')
        $workspace = [IO.Path]::GetFullPath($VerificationWorkspace)
        $repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
        if (-not [IO.Path]::IsPathFullyQualified($VerificationWorkspace) -or
            $VerificationWorkspace.StartsWith('\\') -or
            [IO.Directory]::Exists($workspace) -or [IO.File]::Exists($workspace) -or
            $workspace.StartsWith($repositoryRoot + [IO.Path]::DirectorySeparatorChar,
                [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Local reviewed verification workspace must be one absent external local directory.'
        }
        $workspaceParent = [IO.Path]::GetDirectoryName($workspace)
        if ([string]::IsNullOrWhiteSpace($workspaceParent) -or
            -not [IO.Directory]::Exists($workspaceParent)) {
            throw 'Local reviewed verification workspace parent must already exist.'
        }
        for ($parent = [IO.DirectoryInfo]::new($workspaceParent); $null -ne $parent; $parent = $parent.Parent) {
            if (($parent.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'Local reviewed verification workspace parent crosses a filesystem link.'
            }
        }

    $sourceInputs = [Collections.Generic.List[object]]::new()
    foreach ($input in @($local.Inputs)) {
        $descriptor = Get-OrdinaryReleaseInput $input.Path $input.FileName $input.MaximumBytes $Leases
            if ($descriptor.Length -ne $input.SizeBytes -or
                (Get-LockedReleaseInputSha256 $descriptor) -cne $input.Sha256) {
                throw "Local reviewed input differs from its declared descriptor: $($input.Role)"
            }
        $sourceInputs.Add([pscustomobject]@{ Contract = $input; Descriptor = $descriptor })
    }
    $workspace = New-LocalReviewedVerificationWorkspace -Path $workspace -Leases $Leases
    # Keep the four immutable inputs isolated from the re-download area.  Both
    # child directories are created and leased before the publication API is
    # contacted, so LocalReviewed never depends on a CI runner temporary path.
    $inputWorkspace = New-LocalReviewedVerificationWorkspace `
        -Path (Join-Path $workspace 'inputs') -Leases $Leases
    $readbackWorkspace = New-LocalReviewedVerificationWorkspace `
        -Path (Join-Path $workspace 'readback') -Leases $Leases
    $copies = [Collections.Generic.List[object]]::new()
    foreach ($input in @($sourceInputs)) {
            $destination = Join-Path $inputWorkspace $input.Contract.FileName
            Copy-LockedLocalReviewedInput $input.Descriptor $destination
            Assert-LockedReleaseInputUnchanged $input.Descriptor $input.Contract.SizeBytes $input.Contract.Sha256
        $copy = Get-OrdinaryReleaseInput $destination $input.Contract.FileName $input.Contract.MaximumBytes $Leases
            if ($copy.Length -ne $input.Contract.SizeBytes -or
                (Get-LockedReleaseInputSha256 $copy) -cne $input.Contract.Sha256) {
                throw "Local reviewed verification copy differs: $($input.Contract.Role)"
            }
        $copies.Add([pscustomobject]@{ Contract = $input.Contract; Descriptor = $copy })
    }
    foreach ($input in @($sourceInputs)) {
        Assert-LockedReleaseInputUnchanged $input.Descriptor $input.Contract.SizeBytes $input.Contract.Sha256
    }
    $byRole = @{}
    foreach ($copy in @($copies)) { $byRole[$copy.Contract.Role] = $copy }
    return [pscustomobject]@{
        Repository = $local.Repository
        ReleaseId = $local.ReleaseId
        LauncherSourceCommit = $local.LauncherSourceCommit
        ImmutableReservationTag = $local.ImmutableReservationTag
        VerificationWorkspace = $workspace
        InputWorkspace = $inputWorkspace
        ReadbackWorkspace = $readbackWorkspace
        PublicationInputDescriptor = $inputDescriptor
        PublicationInputSha256 = $inputDescriptorSha256
        OriginalInputs = @($sourceInputs)
        Artifact = $byRole['archive']
        Metadata = $byRole['metadata']
        HashEvidence = $byRole['hash-evidence']
        ManagedCandidate = $byRole['managed-candidate']
    }
}

$inputLeases = [Collections.Generic.List[IDisposable]]::new()
try {
    if (-not $IsWindows) {
        throw 'Immutable source-runtime publication requires native Windows.'
    }
    if ($PSCmdlet.ParameterSetName -ceq 'LocalReviewed') {
        $localReviewed = Open-LocalReviewedPublicationInputs `
            -InputPath $LocalReviewedPublicationInputPath `
            -ExpectedInputSha256 $ExpectedLocalReviewedPublicationInputSha256 `
            -VerificationWorkspace $LocalVerificationWorkspace -Leases $inputLeases
    }
    if ($PSCmdlet.ParameterSetName -ceq 'Actions' -and $RunAttempt -cne '1') {
        throw 'Artifact-bearing candidate publication cannot be rerun. Use a new release_id.'
    }
    if ($PSCmdlet.ParameterSetName -ceq 'LocalReviewed') {
        $Repository = $localReviewed.Repository
        $ReleaseId = $localReviewed.ReleaseId
        $LauncherSourceCommit = $localReviewed.LauncherSourceCommit
        $ArtifactPath = $localReviewed.Artifact.Descriptor.FullName
        $MetadataPath = $localReviewed.Metadata.Descriptor.FullName
        $HashEvidencePath = $localReviewed.HashEvidence.Descriptor.FullName
        $ManagedCandidatePath = $localReviewed.ManagedCandidate.Descriptor.FullName
        $ExpectedArtifactFileName = $localReviewed.Artifact.Contract.FileName
        $ExpectedMetadataFileName = $localReviewed.Metadata.Contract.FileName
        $ExpectedHashFileName = $localReviewed.HashEvidence.Contract.FileName
        $ExpectedArtifactSha256 = $localReviewed.Artifact.Contract.Sha256
        $ExpectedArtifactSizeBytes = $localReviewed.Artifact.Contract.SizeBytes
    }
    if ($Repository -cnotmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$' -or
        $ReleaseId -cnotmatch
            '^managed-v[0-9]{4}\.[0-9]{2}\.[0-9]{2}\.[1-9][0-9]*$' -or
        $LauncherSourceCommit -cnotmatch '^[0-9a-f]{40}$' -or
        $ExpectedArtifactSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $ExpectedArtifactSizeBytes -le 0 -or
        $ExpectedArtifactSizeBytes -gt (8L * 1024 * 1024 * 1024)) {
        throw 'Candidate publication identity tuple is not canonical.'
    }
    if ($PSCmdlet.ParameterSetName -ceq 'Actions' -and
        $ActionsArtifactId -cnotmatch '^[1-9][0-9]*$') {
        throw 'Actions publication artifact identity is not canonical.'
    }
    $canonicalArtifactName = "EnsouDshRuntime-$ReleaseId-win-x64.zip"
    $canonicalMetadataName =
        "EnsouDshRuntime-$ReleaseId-win-x64.metadata.json"
    $canonicalHashName = "$canonicalArtifactName.sha256"
    if ($ExpectedArtifactFileName -cne $canonicalArtifactName -or
        $ExpectedMetadataFileName -cne $canonicalMetadataName -or
        $ExpectedHashFileName -cne $canonicalHashName) {
        throw 'Build outputs do not use the canonical release-bound asset names.'
    }

    if ($PSCmdlet.ParameterSetName -ceq 'Actions') {
        $artifact = Get-OrdinaryReleaseInput `
            $ArtifactPath $ExpectedArtifactFileName `
            (8L * 1024 * 1024 * 1024) $inputLeases
        $metadataFile = Get-OrdinaryReleaseInput `
            $MetadataPath $ExpectedMetadataFileName (4MB) $inputLeases
        $hashFile = Get-OrdinaryReleaseInput `
            $HashEvidencePath $ExpectedHashFileName (4KB) $inputLeases
        $managedFile = Get-OrdinaryReleaseInput `
            $ManagedCandidatePath 'managed-candidate.json' (1MB) $inputLeases
    }
    else {
        $artifact = $localReviewed.Artifact.Descriptor
        $metadataFile = $localReviewed.Metadata.Descriptor
        $hashFile = $localReviewed.HashEvidence.Descriptor
        $managedFile = $localReviewed.ManagedCandidate.Descriptor
    }
    $inputRoots = @(
        @(
            $artifact.DirectoryName,
            $metadataFile.DirectoryName,
            $hashFile.DirectoryName,
            $managedFile.DirectoryName) | Select-Object -Unique
    )
    if ($inputRoots.Count -ne 1) {
        throw 'Downloaded candidate inputs do not share one exact artifact root.'
    }
    [string[]]$expectedInputNames = @(
        $ExpectedArtifactFileName,
        $ExpectedMetadataFileName,
        $ExpectedHashFileName,
        'managed-candidate.json')
    [Array]::Sort($expectedInputNames, [StringComparer]::Ordinal)
    $inputItems = @(Get-ChildItem -LiteralPath $inputRoots[0] -Force)
    [string[]]$actualInputNames = @($inputItems | ForEach-Object Name)
    [Array]::Sort($actualInputNames, [StringComparer]::Ordinal)
    if ($inputItems.Count -ne 4 -or
        @($inputItems | Where-Object {
            -not ($_ -is [IO.FileInfo]) -or
            ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
        }).Count -ne 0 -or
        [string]::Join("`n", $actualInputNames) -cne
            [string]::Join("`n", $expectedInputNames)) {
        throw 'Candidate input directory is not the exact four-file build output.'
    }

    $artifactSha256 = Get-LockedReleaseInputSha256 $artifact
    if ($artifact.Length -ne $ExpectedArtifactSizeBytes -or
        $artifactSha256 -cne $ExpectedArtifactSha256) {
        throw 'Downloaded runtime ZIP differs from the exact build outputs.'
    }
    $hashEvidence = Read-LockedAsciiText `
        $hashFile 'Runtime SHA-256 evidence'
    $expectedHashEvidence = "$ExpectedArtifactSha256  $ExpectedArtifactFileName"
    if ($hashEvidence -cnotmatch (
            '\A' + [Text.RegularExpressions.Regex]::Escape($expectedHashEvidence) +
            '(?:\r\n|\n)\z')) {
        throw 'Downloaded runtime SHA-256 evidence is not one canonical record.'
    }

    $strictMetadata = Read-StrictJsonObject `
        $metadataFile 'Source-runtime metadata'
    $metadata = & (Join-Path $PSScriptRoot 'Test-SourceRuntimeMetadata.ps1') `
        -MetadataPath $metadataFile.FullName `
        -ArtifactPath $artifact.FullName `
        -ExpectedReleaseId $ReleaseId `
        -ExpectedArtifactFileName $ExpectedArtifactFileName `
        -ExpectedArtifactSha256 $ExpectedArtifactSha256 `
        -ExpectedRuntimeProfile $RuntimeProfile
    if ($strictMetadata.promotionEligible -ne $true -or
        $metadata.promotionEligible -ne $true) {
        throw 'Local Lab source-runtime metadata cannot be published as a production candidate.'
    }

    $managed = Read-StrictJsonObject $managedFile 'Managed candidate metadata'
    $expectedManagedProperties = @(
        'artifact', 'launcherRepositoryCommit', 'launcherVersion',
        'managedPatch', 'managedPolicy', 'minimumBootstrapperVersion',
        'promotionEligible', 'releaseId', 'remainingGates',
        'runtimeWebAuthProtocol', 'schemaVersion', 'sourceBuilt',
        'stableEligible', 'upstreamCommit', 'upstreamTag', 'upstreamTree')
    if ((@($managed.PSObject.Properties.Name | Sort-Object) -join ',') -cne
            (@($expectedManagedProperties | Sort-Object) -join ',') -or
        [int]$managed.schemaVersion -ne 1 -or
        $managed.sourceBuilt -ne $true -or
        $managed.promotionEligible -ne $true -or
        $managed.stableEligible -ne $false -or
        [string]$managed.releaseId -cne $ReleaseId -or
        [string]$managed.launcherRepositoryCommit -cne $LauncherSourceCommit -or
        [string]$managed.upstreamTag -cne [string]$metadata.sourceTag -or
        [string]$managed.upstreamCommit -cne [string]$metadata.sourceCommit -or
        [string]$managed.upstreamTree -cne [string]$metadata.sourceTree -or
        [string]$managed.runtimeWebAuthProtocol -cne
            [string]$metadata.runtimeWebAuthProtocol -or
        [string]$managed.launcherVersion -cnotmatch
            '^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$' -or
        [string]$managed.minimumBootstrapperVersion -cnotmatch
            '^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$' -or
        [string]::Join("`n", @($managed.remainingGates)) -cne
            [string]::Join("`n", @(
                'Ensou application code signing',
                'release manifest signing',
                'Lab',
                'Pilot',
                'legal review')) -or
        ($managed.artifact | ConvertTo-Json -Depth 10 -Compress) -cne
            ($metadata.artifact | ConvertTo-Json -Depth 10 -Compress) -or
        ($managed.managedPatch | ConvertTo-Json -Depth 10 -Compress) -cne
            ($metadata.managedPatch | ConvertTo-Json -Depth 10 -Compress) -or
        ($managed.managedPolicy | ConvertTo-Json -Depth 10 -Compress) -cne
            ($metadata.managedPolicy | ConvertTo-Json -Depth 10 -Compress)) {
        throw 'Managed candidate metadata does not bind the exact build and source metadata.'
    }

    $localMetadataSha256 = Get-LockedReleaseInputSha256 $metadataFile
    $localHashEvidenceSha256 = Get-LockedReleaseInputSha256 $hashFile
    $localManagedSha256 = Get-LockedReleaseInputSha256 $managedFile

    if ([string]::IsNullOrWhiteSpace($env:GH_TOKEN)) {
        throw 'GH_TOKEN is required only for the controlled candidate publication transaction.'
    }
    $apiBase = "https://api.github.com/repos/$Repository"
    $headers = @{
        Authorization = "Bearer $env:GH_TOKEN"
        Accept = 'application/vnd.github+json'
        'X-GitHub-Api-Version' = '2026-03-10'
        'User-Agent' = 'ensou-dsh-source-candidate-publisher'
    }
    $uploadHttpClient = [Net.Http.HttpClient]::new()
    $uploadHttpClient.Timeout = [Threading.Timeout]::InfiniteTimeSpan
    $inputLeases.Add($uploadHttpClient)
    $reservationTag = "ensou-dsh-source-candidate/$ReleaseId"
    if ($PSCmdlet.ParameterSetName -ceq 'LocalReviewed' -and
        $reservationTag -cne $localReviewed.ImmutableReservationTag) {
        throw 'Local reviewed publication input does not require the exact immutable release reservation tag.'
    }
    $encodedReservationTag = [Uri]::EscapeDataString($reservationTag)
    $reservation = Get-GitHubJsonOrNull `
        "$apiBase/releases/tags/$encodedReservationTag" $headers
    if ($null -eq $reservation -or
        [int64]$reservation.id -le 0 -or
        [string]$reservation.tag_name -cne $reservationTag -or
        [string]$reservation.target_commitish -cne $LauncherSourceCommit -or
        [bool]$reservation.draft -or
        -not ($reservation.PSObject.Properties.Name -contains 'immutable') -or
        -not [bool]$reservation.immutable -or
        @($reservation.assets).Count -ne 0) {
        throw 'The permanent release-id reservation is absent, mutable, draft, or non-empty.'
    }
    Assert-LightweightTagAtCommit `
        $apiBase $reservationTag $LauncherSourceCommit $headers `
        'Release-id reservation tag'

    $encodedReleaseId = [Uri]::EscapeDataString($ReleaseId)
    if ($null -ne (Get-GitHubJsonOrNull `
            "$apiBase/git/ref/tags/$encodedReleaseId" $headers)) {
        throw 'The final release tag already exists; this release_id is burned.'
    }
    for ($page = 1; $page -le 100; $page++) {
        $releases = @(Invoke-RestMethod -Method Get `
            -Uri "$apiBase/releases?per_page=100&page=$page" `
            -Headers $headers)
        if (@($releases | Where-Object {
                [string]$_.tag_name -ceq $ReleaseId
            }).Count -ne 0) {
            throw 'A final or draft Release already uses this release_id; it is burned.'
        }
        if ($releases.Count -lt 100) { break }
        if ($page -eq 100) {
            throw 'Release inventory exceeded the bounded pre-publication duplicate scan.'
        }
    }

    $publicationSource = if ($PSCmdlet.ParameterSetName -ceq 'Actions') {
        "Actions artifact $ActionsArtifactId"
    }
    else {
        'the verified LocalReviewed four-file workspace'
    }
    $draftBody = @{
        tag_name = $ReleaseId
        target_commitish = $LauncherSourceCommit
        name = "Ensou DSH source runtime $ReleaseId"
        body = "Unsigned source-derived candidate from $publicationSource. Lab/Pilot, signing, and legal gates remain."
        draft = $true
        prerelease = $true
        make_latest = 'false'
    } | ConvertTo-Json -Compress
    $draft = Invoke-RestMethod -Method Post -Uri "$apiBase/releases" `
        -Headers $headers -ContentType 'application/json' -Body $draftBody
    if ([int64]$draft.id -le 0 -or
        [string]$draft.tag_name -cne $ReleaseId -or
        [string]$draft.target_commitish -cne $LauncherSourceCommit -or
        -not [bool]$draft.draft -or -not [bool]$draft.prerelease -or
        @($draft.assets).Count -ne 0) {
        throw 'GitHub did not create the exact empty draft final Release.'
    }

    $uploadBase = [string]$draft.upload_url -replace '\{\?name,label\}\z', ''
    $uploadInputs = @(
        [pscustomobject]@{
            File = $artifact
            Name = $ExpectedArtifactFileName
            Sha256 = $ExpectedArtifactSha256
        },
        [pscustomobject]@{
            File = $metadataFile
            Name = $ExpectedMetadataFileName
            Sha256 = $localMetadataSha256
        },
        [pscustomobject]@{
            File = $hashFile
            Name = $ExpectedHashFileName
            Sha256 = $localHashEvidenceSha256
        })
    $uploadedAssets = [Collections.Generic.List[object]]::new()
    foreach ($input in $uploadInputs) {
        Assert-LockedReleaseInputUnchanged `
            $input.File $input.File.Length $input.Sha256
        $encodedName = [Uri]::EscapeDataString([string]$input.Name)
        $uploaded = Send-LockedReleaseAsset `
            $uploadHttpClient `
            ([Uri]"${uploadBase}?name=$encodedName") `
            $headers `
            $input.File `
            $inputLeases
        if ([string]$uploaded.name -cne [string]$input.Name -or
            [string]$uploaded.state -cne 'uploaded' -or
            [int64]$uploaded.size -ne [int64]$input.File.Length -or
            [int64]$uploaded.id -le 0) {
            throw "GitHub did not confirm the exact uploaded asset: $($input.Name)"
        }
        $uploadedAssets.Add([pscustomobject]@{
            Name = [string]$uploaded.name
            SizeBytes = [int64]$uploaded.size
            Id = [int64]$uploaded.id
            Url = [string]$uploaded.url
        })
    }

    $draft = Invoke-RestMethod -Method Get `
        -Uri "$apiBase/releases/$($draft.id)" -Headers $headers
    if (-not [bool]$draft.draft -or [string]$draft.tag_name -cne $ReleaseId) {
        throw 'Draft Release identity changed after asset upload.'
    }
    Assert-ExactReleaseAssets $draft @($uploadedAssets)
    Assert-LockedReleaseInputUnchanged `
        $artifact $ExpectedArtifactSizeBytes $ExpectedArtifactSha256
    Assert-LockedReleaseInputUnchanged `
        $metadataFile $metadataFile.Length $localMetadataSha256
    Assert-LockedReleaseInputUnchanged `
        $hashFile $hashFile.Length $localHashEvidenceSha256
    Assert-LockedReleaseInputUnchanged `
        $managedFile $managedFile.Length $localManagedSha256

    if ($PSCmdlet.ParameterSetName -ceq 'LocalReviewed') {
        $verificationRoot = $localReviewed.ReadbackWorkspace
    }
    else {
        $verificationRoot = Join-Path $env:RUNNER_TEMP `
            "source-candidate-release-verify-$ReleaseId"
        [IO.Directory]::CreateDirectory($verificationRoot) | Out-Null
    }
    if (@(Get-ChildItem -LiteralPath $verificationRoot -Force).Count -ne 0) {
        throw 'Release verification directory was not empty.'
    }
    $downloadHeaders = @{
        Authorization = "Bearer $env:GH_TOKEN"
        Accept = 'application/octet-stream'
        'X-GitHub-Api-Version' = '2026-03-10'
        'User-Agent' = 'ensou-dsh-source-candidate-publisher'
    }
    foreach ($asset in $uploadedAssets) {
        Invoke-WebRequest -Method Get -Uri $asset.Url `
            -Headers $downloadHeaders `
            -OutFile (Join-Path $verificationRoot $asset.Name)
    }
    $downloadedArtifact = Join-Path $verificationRoot $ExpectedArtifactFileName
    $downloadedMetadata = Join-Path $verificationRoot $ExpectedMetadataFileName
    $downloadedHash = Join-Path $verificationRoot $ExpectedHashFileName
    if ((Get-FileHash -LiteralPath $downloadedArtifact -Algorithm SHA256).
            Hash.ToLowerInvariant() -cne $ExpectedArtifactSha256 -or
        (Get-FileHash -LiteralPath $downloadedMetadata -Algorithm SHA256).
            Hash.ToLowerInvariant() -cne $localMetadataSha256 -or
        (Get-FileHash -LiteralPath $downloadedHash -Algorithm SHA256).
            Hash.ToLowerInvariant() -cne $localHashEvidenceSha256 -or
        (Get-LockedReleaseInputSha256 $managedFile) -cne $localManagedSha256) {
        throw 'Re-downloaded draft assets or the local managed-candidate evidence changed.'
    }
    $downloadedMetadataRecord = & (Join-Path $PSScriptRoot `
        'Test-SourceRuntimeMetadata.ps1') `
        -MetadataPath $downloadedMetadata `
        -ArtifactPath $downloadedArtifact `
        -ExpectedReleaseId $ReleaseId `
        -ExpectedArtifactFileName $ExpectedArtifactFileName `
        -ExpectedArtifactSha256 $ExpectedArtifactSha256 `
        -ExpectedRuntimeProfile $RuntimeProfile
    if ($downloadedMetadataRecord.promotionEligible -ne $true -or
        [IO.File]::ReadAllText($downloadedHash, [Text.Encoding]::ASCII) `
            -cnotmatch (
                '\A' + [Text.RegularExpressions.Regex]::Escape(
                    $expectedHashEvidence) + '(?:\r\n|\n)\z')) {
        throw 'Re-downloaded draft metadata or SHA-256 evidence failed publication admission.'
    }

    $possibleTag = Get-GitHubJsonOrNull `
        "$apiBase/git/ref/tags/$encodedReleaseId" $headers
    if ($null -ne $possibleTag -and
        ([string]$possibleTag.object.type -cne 'commit' -or
            [string]$possibleTag.object.sha -cne $LauncherSourceCommit)) {
        throw 'The final tag appeared at a different object before publication.'
    }
    Assert-LightweightTagAtCommit `
        $apiBase $reservationTag $LauncherSourceCommit $headers `
        'Release-id reservation tag before publication'

    $publishBody = @{
        draft = $false
        prerelease = $true
        make_latest = 'false'
    } | ConvertTo-Json -Compress
    $published = Invoke-RestMethod -Method Patch `
        -Uri "$apiBase/releases/$($draft.id)" `
        -Headers $headers -ContentType 'application/json' -Body $publishBody
    if ([int64]$published.id -ne [int64]$draft.id -or
        [string]$published.tag_name -cne $ReleaseId -or
        [bool]$published.draft) {
        throw 'GitHub did not publish the exact verified draft Release.'
    }

    $immutableRelease = $null
    foreach ($attempt in 1..30) {
        $immutableRelease = Get-GitHubJsonOrNull `
            "$apiBase/releases/tags/$encodedReleaseId" $headers
        if ($null -ne $immutableRelease -and
            $immutableRelease.PSObject.Properties.Name -contains 'immutable' -and
            [bool]$immutableRelease.immutable) {
            break
        }
        if ($attempt -lt 30) {
            Start-Sleep -Seconds 2
        }
    }
    if ($null -eq $immutableRelease -or
        [int64]$immutableRelease.id -ne [int64]$draft.id -or
        [string]$immutableRelease.tag_name -cne $ReleaseId -or
        [string]$immutableRelease.target_commitish -cne $LauncherSourceCommit -or
        [bool]$immutableRelease.draft -or
        -not ($immutableRelease.PSObject.Properties.Name -contains 'immutable') -or
        -not [bool]$immutableRelease.immutable) {
        throw 'Published final Release was not confirmed immutable at the exact source commit.'
    }
    Assert-ExactReleaseAssets $immutableRelease @($uploadedAssets)
    Assert-LightweightTagAtCommit `
        $apiBase $ReleaseId $LauncherSourceCommit $headers `
        'Final artifact-bearing Release tag'
    Assert-LightweightTagAtCommit `
        $apiBase $reservationTag $LauncherSourceCommit $headers `
        'Release-id reservation tag after publication'
    foreach ($input in $uploadInputs) {
        Assert-LockedReleaseInputUnchanged $input.File $input.File.Length $input.Sha256
    }
    if ($PSCmdlet.ParameterSetName -ceq 'LocalReviewed') {
        foreach ($input in @($localReviewed.OriginalInputs)) {
            Assert-LockedReleaseInputUnchanged `
                $input.Descriptor $input.Contract.SizeBytes $input.Contract.Sha256
        }
        Assert-LockedReleaseInputUnchanged `
            $localReviewed.PublicationInputDescriptor `
            $localReviewed.PublicationInputDescriptor.Length `
            $localReviewed.PublicationInputSha256
    }
    $reviewEvidence = New-SourceRuntimeReviewEvidence `
        -SourceRepository $Repository -ImmutableRelease $immutableRelease `
        -RuntimeBuildCommit $LauncherSourceCommit `
        -UploadedAssets @($uploadedAssets) -AssetInputs $uploadInputs

    $actionsResult = [ordered]@{
        ReleaseId = $ReleaseId
        ReleaseUrl = [string]$immutableRelease.html_url
        LauncherSourceCommit = $LauncherSourceCommit
        ActionsArtifactId = $ActionsArtifactId
        ArtifactFileName = $ExpectedArtifactFileName
        ArtifactSha256 = $ExpectedArtifactSha256
        Immutable = $true
        SourceReleaseReviewInput = $reviewEvidence
    }
    if ($PSCmdlet.ParameterSetName -ceq 'Actions') {
        return [pscustomobject]$actionsResult
    }
    $localResult = [ordered]@{}
    foreach ($entry in $actionsResult.GetEnumerator()) { $localResult[$entry.Key] = $entry.Value }
    $localResult.Remove('ActionsArtifactId')
    $localResult['InputMode'] = 'LocalReviewed'
    $localResult['LocalVerificationWorkspace'] = $localReviewed.VerificationWorkspace
    $localResult['LocalReviewedPublicationInputSha256'] = $localReviewed.PublicationInputSha256
    return [pscustomobject]$localResult
}
catch {
    throw "Candidate publication failed. Release id $ReleaseId is burned and this workflow must not be rerun; dispatch a new release_id after diagnosis. $($_.Exception.Message)"
}
finally {
    for ($index = $inputLeases.Count - 1; $index -ge 0; $index--) {
        $inputLeases[$index].Dispose()
    }
}
