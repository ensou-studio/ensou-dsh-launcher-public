#requires -Version 7.2

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:CanonicalManagedSourceRepository = 'https://github.com/deepseek-ai/deepseek-harness.git'
$script:EnterpriseManagedPatchVariant = 'enterprise-managed-v1'
$script:EnterpriseDirectLocalPatchVariant = 'enterprise-direct-local-v1'
$script:ApprovedManagedSourceBases = [Collections.Generic.Dictionary[string, object]]::new(
    [StringComparer]::Ordinal)
$script:ApprovedManagedSourceBases.Add(
    'dsh-v0.1.1-rc.2|b150a551b8d465e31e418e1b2eaf5e79bbb7d28e',
    [pscustomobject]@{
        Tag = 'dsh-v0.1.1-rc.2'
        Commit = 'b150a551b8d465e31e418e1b2eaf5e79bbb7d28e'
        Tree = '53915efe4e2126cc7779b73dfc8a3bcec5318c44'
        DshVersion = '0.1.1-rc.2'
        RuntimeWebAuthProtocol = 'legacy-clean-root-v1'
        BaseLockfileSha256 = '6f20c268e76df1294c16f016ab10a7fa1271608b4db0f4fafe8f7c21ec90013e'
        BaseLockfileGitBlob = '737a21eea64d9ab25ed35258719442ae55376710'
        BaseLockfileBytes = [int64]698644
        ChangedFiles = 41
        AddedFiles = 8
        ModifiedFiles = 33
    })
$script:ApprovedManagedSourceBases.Add(
    'dsh-v0.1.2-alpha.3|dd6322d604e00eec1ba5e0c8541159906a21094a',
    [pscustomobject]@{
        Tag = 'dsh-v0.1.2-alpha.3'
        Commit = 'dd6322d604e00eec1ba5e0c8541159906a21094a'
        Tree = '86be9091c78528b5ef0866ae6d58b01d4a53582e'
        DshVersion = '0.1.2-alpha.3'
        RuntimeWebAuthProtocol = 'browser-launch-cookie-v1'
        BaseLockfileSha256 = '17bbd38216e31a8b821957f77d2e3f57b859046cc3a18076ad16e94ca952a8da'
        BaseLockfileGitBlob = '51de950c3e3c9dcdf118206888d05e8b3fba9ed5'
        BaseLockfileBytes = [int64]769826
        ChangedFiles = 43
        AddedFiles = 8
        ModifiedFiles = 35
    })
$script:ApprovedManagedSourceBases.Add(
    'dsh-v0.1.2-rc.1|a66e4702047846cdaa10c66c9d3df3951f5ea70d',
    [pscustomobject]@{
        Tag = 'dsh-v0.1.2-rc.1'
        Commit = 'a66e4702047846cdaa10c66c9d3df3951f5ea70d'
        Tree = '27ab636bb3d77e698f5637e518db44ae1f61e262'
        DshVersion = '0.1.2-rc.1'
        RuntimeWebAuthProtocol = 'browser-launch-cookie-v1'
        BaseLockfileSha256 = 'e12083149a77f790d39b64d018b6b8745c6a7aa95777ecb73e0a2f5ed5fdd0d9'
        BaseLockfileGitBlob = '4521b1bbf42de10ad2c19e85523b56661d19d8f7'
        BaseLockfileBytes = [int64]742793
        ChangedFiles = 43
        AddedFiles = 8
        ModifiedFiles = 35
    })

function Get-ApprovedManagedSourceBase([string]$Tag, [string]$Commit) {
    $approved = $null
    $key = $Tag + '|' + $Commit
    if (-not $script:ApprovedManagedSourceBases.TryGetValue($key, [ref]$approved)) {
        return $null
    }
    return $approved
}

function Get-ApprovedManagedSourcePatchContract(
    [object]$Base,
    [string]$Tag,
    [string]$Commit,
    [string]$PatchVariant
) {
    if ($PatchVariant -ceq $script:EnterpriseManagedPatchVariant) {
        return [pscustomobject]@{
            ChangedFiles = [int]$Base.ChangedFiles
            AddedFiles = [int]$Base.AddedFiles
            ModifiedFiles = [int]$Base.ModifiedFiles
            PatchSha256 = $null
            PatchBytes = $null
            PatchLfLines = $null
            PatchedLockfileSha256 = $null
            PatchedLockfileGitBlob = $null
            PatchedLockfileBytes = $null
        }
    }
    if ($PatchVariant -ceq $script:EnterpriseDirectLocalPatchVariant -and
        $Tag -ceq 'dsh-v0.1.2-rc.1' -and
        $Commit -ceq 'a66e4702047846cdaa10c66c9d3df3951f5ea70d') {
        return [pscustomobject]@{
            ChangedFiles = 112
            AddedFiles = 26
            ModifiedFiles = 86
            PatchSha256 = '7f10ec9492b399cede422428013b0c77bc932699fa3a14fa7ced158454272b6f'
            PatchBytes = [int64]415878
            PatchLfLines = 7453
            PatchedLockfileSha256 = '07974704247ec18915df8fdf117c682bba2d861aafe7059ea4bca4aab1677080'
            PatchedLockfileGitBlob = '68ad6b76b1577112091beaa532667ac02ddcbccf'
            PatchedLockfileBytes = [int64]743966
        }
    }
    return $null
}

function Get-FullPath([string]$Path, [switch]$MustExist) {
    $full = [IO.Path]::GetFullPath(
        $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path))
    if ($MustExist -and -not (Test-Path -LiteralPath $full)) {
        throw "Path does not exist: $full"
    }
    if ($full -ceq [IO.Path]::GetPathRoot($full)) { return $full }
    return $full.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
}

function Test-IsWithin([string]$Parent, [string]$Child) {
    $relative = [IO.Path]::GetRelativePath((Get-FullPath $Parent), (Get-FullPath $Child))
    return $relative -ceq '.' -or (
        $relative -cne '..' -and
        -not $relative.StartsWith('..' + [IO.Path]::DirectorySeparatorChar, [StringComparison]::Ordinal) -and
        -not [IO.Path]::IsPathRooted($relative))
}

function Assert-NoReparsePath([string]$Path) {
    $item = Get-Item -LiteralPath (Get-FullPath $Path -MustExist) -Force
    while ($null -ne $item) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "Managed patch path must not traverse a reparse point: $($item.FullName)"
        }
        $item = if ($item -is [IO.DirectoryInfo]) { $item.Parent } else { $item.Directory }
    }
}

function Assert-NoReparseTree([string]$Root) {
    $queue = [Collections.Generic.Queue[string]]::new()
    $queue.Enqueue((Get-FullPath $Root -MustExist))
    while ($queue.Count -gt 0) {
        $directory = $queue.Dequeue()
        foreach ($item in Get-ChildItem -LiteralPath $directory -Force) {
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw "Managed patched source contains a reparse point: $($item.FullName)"
            }
            if ($item.PSIsContainer) { $queue.Enqueue($item.FullName) }
        }
    }
}

function Assert-ExactProperties([object]$Value, [string[]]$Expected, [string]$Label) {
    if ($null -eq $Value) { throw "$Label must be a JSON object." }
    $actual = @($Value.PSObject.Properties.Name)
    $expectedSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($name in $Expected) {
        if (-not $expectedSet.Add($name)) { throw "Internal duplicate expected property for ${Label}: $name" }
    }
    $actualSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($name in $actual) {
        if (-not $actualSet.Add($name)) { throw "$Label repeats property $name." }
    }
    $missing = @($Expected | Where-Object { -not $actualSet.Contains($_) })
    $extra = @($actual | Where-Object { -not $expectedSet.Contains($_) })
    if ($missing.Count -ne 0 -or $extra.Count -ne 0) {
        throw "$Label property mismatch. Missing=[$($missing -join ', ')]; extra=[$($extra -join ', ')]."
    }
}

function Assert-NoDuplicateJsonProperties([Text.Json.JsonElement]$Element, [string]$Label) {
    switch ($Element.ValueKind) {
        ([Text.Json.JsonValueKind]::Object) {
            $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
            foreach ($property in $Element.EnumerateObject()) {
                if (-not $names.Add($property.Name)) {
                    throw "$Label repeats JSON property $($property.Name)."
                }
                Assert-NoDuplicateJsonProperties $property.Value "$Label.$($property.Name)"
            }
        }
        ([Text.Json.JsonValueKind]::Array) {
            $index = 0
            foreach ($child in $Element.EnumerateArray()) {
                Assert-NoDuplicateJsonProperties $child "${Label}[$index]"
                $index++
            }
        }
    }
}

function Read-StrictJson([string]$Path, [string]$Label) {
    $full = Get-FullPath $Path -MustExist
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { throw "$Label is not a file: $full" }
    Assert-NoReparsePath $full
    $raw = [IO.File]::ReadAllText($full)
    try {
        $document = [Text.Json.JsonDocument]::Parse($raw)
        try {
            if ($document.RootElement.ValueKind -ne [Text.Json.JsonValueKind]::Object) {
                throw "$Label root must be a JSON object."
            }
            Assert-NoDuplicateJsonProperties $document.RootElement $Label
        } finally {
            $document.Dispose()
        }
        return $raw | ConvertFrom-Json -Depth 64
    } catch {
        throw "Cannot parse strict $Label JSON at ${full}: $($_.Exception.Message)"
    }
}

function Assert-ExactJsonElementProperties(
    [Text.Json.JsonElement]$Element,
    [string[]]$Expected,
    [string]$Label
) {
    if ($Element.ValueKind -ne [Text.Json.JsonValueKind]::Object) {
        throw "$Label must be a JSON object."
    }
    $expectedSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($name in $Expected) {
        if (-not $expectedSet.Add($name)) {
            throw "Internal duplicate expected JSON property for ${Label}: $name"
        }
    }
    $actualSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($property in $Element.EnumerateObject()) {
        if (-not $actualSet.Add($property.Name)) {
            throw "$Label repeats JSON property $($property.Name)."
        }
    }
    $missing = @($Expected | Where-Object { -not $actualSet.Contains($_) })
    $extra = @($actualSet | Where-Object { -not $expectedSet.Contains($_) })
    if ($missing.Count -ne 0 -or $extra.Count -ne 0) {
        throw "$Label property mismatch. Missing=[$($missing -join ', ')]; extra=[$($extra -join ', ')]."
    }
}

function Get-RequiredJsonStringProperty(
    [Text.Json.JsonElement]$Element,
    [string]$Name,
    [string]$Label,
    [int]$MaximumLength = 4096
) {
    $property = $Element.GetProperty($Name)
    if ($property.ValueKind -ne [Text.Json.JsonValueKind]::String) {
        throw "$Label.$Name must be a JSON string."
    }
    $value = $property.GetString()
    if ([string]::IsNullOrWhiteSpace($value) -or $value.Length -gt $MaximumLength) {
        throw "$Label.$Name must be one bounded non-empty string."
    }
    return $value
}

function Get-ManagedSourceLock([string]$Path) {
    $label = 'managed source lock'
    $full = Get-FullPath $Path -MustExist
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
        throw "$label is not a file: $full"
    }
    Assert-NoReparsePath $full
    try {
        $raw = [Text.UTF8Encoding]::new($false, $true).GetString(
            [IO.File]::ReadAllBytes($full))
    } catch {
        throw "$label is not strict UTF-8: $($_.Exception.Message)"
    }
    try {
        $document = [Text.Json.JsonDocument]::Parse($raw)
        try {
            $root = $document.RootElement
            Assert-NoDuplicateJsonProperties $root $label
            Assert-ExactJsonElementProperties $root @(
                'schemaVersion', 'product', 'buildMode', 'runtimeWebAuthProtocol',
                'dshVersion', 'officialCommit', 'officialTag', 'officialTree',
                'nodeVersion', 'pnpmVersion', 'baseLockfileSha256', 'lockfileSha256',
                'managedPatch', 'harnessCheckout', 'verifiedAt', 'promotionStatus', 'notes') $label

            $schemaVersion = 0
            $schemaProperty = $root.GetProperty('schemaVersion')
            if ($schemaProperty.ValueKind -ne [Text.Json.JsonValueKind]::Number -or
                -not $schemaProperty.TryGetInt32([ref]$schemaVersion) -or
                $schemaVersion -ne 4) {
                throw "$label.schemaVersion must be the JSON number 4."
            }

            $product = Get-RequiredJsonStringProperty $root 'product' $label 128
            $buildMode = Get-RequiredJsonStringProperty $root 'buildMode' $label 128
            $protocol = Get-RequiredJsonStringProperty $root 'runtimeWebAuthProtocol' $label 64
            $dshVersion = Get-RequiredJsonStringProperty $root 'dshVersion' $label 128
            $commit = Get-RequiredJsonStringProperty $root 'officialCommit' $label 40
            $tag = Get-RequiredJsonStringProperty $root 'officialTag' $label 128
            $tree = Get-RequiredJsonStringProperty $root 'officialTree' $label 40
            $nodeVersion = Get-RequiredJsonStringProperty $root 'nodeVersion' $label 64
            $pnpmVersion = Get-RequiredJsonStringProperty $root 'pnpmVersion' $label 64
            $baseLock = Get-RequiredJsonStringProperty $root 'baseLockfileSha256' $label 64
            $patchedLock = Get-RequiredJsonStringProperty $root 'lockfileSha256' $label 64
            $null = Get-RequiredJsonStringProperty $root 'harnessCheckout' $label 1024
            $null = Get-RequiredJsonStringProperty $root 'promotionStatus' $label 128
            $null = Get-RequiredJsonStringProperty $root 'notes' $label 8192

            $verifiedAt = $root.GetProperty('verifiedAt')
            if ($verifiedAt.ValueKind -notin @(
                    [Text.Json.JsonValueKind]::Null,
                    [Text.Json.JsonValueKind]::String)) {
                throw "$label.verifiedAt must be JSON null or a timestamp string."
            }
            if ($verifiedAt.ValueKind -eq [Text.Json.JsonValueKind]::String) {
                $verifiedAtValue = $verifiedAt.GetString()
                $parsedVerifiedAt = [DateTimeOffset]::MinValue
                if ([string]::IsNullOrWhiteSpace($verifiedAtValue) -or
                    -not [DateTimeOffset]::TryParse(
                        $verifiedAtValue,
                        [Globalization.CultureInfo]::InvariantCulture,
                        [Globalization.DateTimeStyles]::RoundtripKind,
                        [ref]$parsedVerifiedAt)) {
                    throw "$label.verifiedAt is not a round-trip timestamp."
                }
            }

            $patch = $root.GetProperty('managedPatch')
            Assert-ExactJsonElementProperties $patch @(
                'id', 'manifestSha256', 'patchSha256') "$label.managedPatch"
            $patchId = Get-RequiredJsonStringProperty $patch 'id' "$label.managedPatch" 192
            $manifestSha = Get-RequiredJsonStringProperty `
                $patch 'manifestSha256' "$label.managedPatch" 64
            $patchSha = Get-RequiredJsonStringProperty `
                $patch 'patchSha256' "$label.managedPatch" 64

            $approvedBase = Get-ApprovedManagedSourceBase $tag $commit
            if ($product -cne 'ensou-dsh-launcher' -or
                $buildMode -cne 'official-source' -or
                $null -eq $approvedBase -or
                [string]$approvedBase.Tree -cne $tree -or
                [string]$approvedBase.DshVersion -cne $dshVersion -or
                [string]$approvedBase.RuntimeWebAuthProtocol -cne $protocol -or
                [string]$approvedBase.BaseLockfileSha256 -cne $baseLock -or
                $commit -cnotmatch '^[0-9a-f]{40}$' -or
                $tree -cnotmatch '^[0-9a-f]{40}$' -or
                $nodeVersion -cnotmatch '^[0-9]+\.[0-9]+\.[0-9]+$' -or
                $pnpmVersion -cnotmatch '^[0-9]+\.[0-9]+\.[0-9]+$' -or
                $baseLock -cnotmatch '^[0-9a-f]{64}$' -or
                $patchedLock -cnotmatch '^[0-9a-f]{64}$' -or
                $patchId -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]+$' -or
                $manifestSha -cnotmatch '^[0-9a-f]{64}$' -or
                $patchSha -cnotmatch '^[0-9a-f]{64}$') {
                throw "$label does not contain one exact reviewed source tuple."
            }
        } finally {
            $document.Dispose()
        }
        return $raw | ConvertFrom-Json -Depth 64
    } catch {
        throw "Cannot parse strict $label JSON at ${full}: $($_.Exception.Message)"
    }
}

function Assert-LowerHex([string]$Value, [int]$Length, [string]$Label) {
    if ($Value -cnotmatch "^[0-9a-f]{$Length}$") {
        throw "$Label must be exactly $Length lowercase hexadecimal characters."
    }
}

function Assert-SafeRelativePath([string]$Value, [string]$Label, [switch]$FileNameOnly) {
    if (-not $Value -or $Value.Contains('\') -or $Value.Contains(':') -or
        [IO.Path]::IsPathRooted($Value)) {
        throw "$Label is not a canonical forward-slash relative path: $Value"
    }
    $segments = @($Value.Split('/'))
    if ($FileNameOnly -and $segments.Count -ne 1) { throw "$Label must be a file name: $Value" }
    foreach ($segment in $segments) {
        if (-not $segment -or $segment -ceq '.' -or $segment -ceq '..' -or
            $segment.IndexOfAny([IO.Path]::GetInvalidFileNameChars()) -ge 0) {
            throw "$Label contains an unsafe path segment: $Value"
        }
    }
}

function Get-FileSha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Assert-CanonicalManagedPatchBytes([byte[]]$Bytes) {
    if ($Bytes.Length -eq 0 -or $Bytes[-1] -ne 10) {
        throw 'Managed patch must be non-empty and LF-terminated.'
    }
    try {
        $utf8 = [Text.UTF8Encoding]::new($false, $true)
        $text = $utf8.GetString($Bytes)
    } catch {
        throw "Managed patch is not canonical UTF-8: $($_.Exception.Message)"
    }
    if ($text.Contains("`r")) {
        throw 'Managed patch must use LF line endings only.'
    }
    if ([Text.RegularExpressions.Regex]::IsMatch(
            $text, '[\x20\x09]+(?=\n|\z)',
            [Text.RegularExpressions.RegexOptions]::CultureInvariant)) {
        throw 'Managed patch contains trailing horizontal whitespace.'
    }
}

function Invoke-GitText([string]$Git, [string]$Checkout, [string[]]$Arguments, [string]$Label) {
    $full = Get-FullPath $Checkout -MustExist
    $safeDirectory = $full.Replace('\', '/')
    $output = @(& $Git '-c' 'core.longpaths=true' '-c' "safe.directory=$safeDirectory" '-C' $full @Arguments 2>&1)
    $exitCode = $LASTEXITCODE
    $text = ($output | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine
    if ($exitCode -ne 0) { throw "$Label failed with exit code $exitCode.`n$text" }
    return $text.Trim()
}

function Invoke-GitExit([string]$Git, [string]$Checkout, [string[]]$Arguments) {
    $full = Get-FullPath $Checkout -MustExist
    $safeDirectory = $full.Replace('\', '/')
    & $Git '-c' 'core.longpaths=true' '-c' "safe.directory=$safeDirectory" '-C' $full @Arguments *> $null
    return $LASTEXITCODE
}

function Get-ManagedSourcePatchBundle(
    [string]$IndexPath,
    [string]$Repository,
    [string]$Tag,
    [string]$Commit,
    [string]$Tree,
    [ValidateSet('enterprise-managed-v1', 'enterprise-direct-local-v1')]
    [string]$PatchVariant = 'enterprise-managed-v1'
) {
    Assert-LowerHex $Commit 40 'requested commit'
    Assert-LowerHex $Tree 40 'requested tree'
    $approvedBase = Get-ApprovedManagedSourceBase $Tag $Commit
    $approvedPatch = if ($null -eq $approvedBase) {
        $null
    } else {
        Get-ApprovedManagedSourcePatchContract $approvedBase $Tag $Commit $PatchVariant
    }
    if ($Repository -cne $script:CanonicalManagedSourceRepository -or
        $null -eq $approvedBase -or
        $null -eq $approvedPatch -or
        [string]$approvedBase.Tree -cne $Tree) {
        throw "No unique reviewed managed patch matches exact repository/tag/commit/tree/variant ($Repository / $Tag / $Commit / $Tree / $PatchVariant)."
    }
    $expectedChangedFiles = [int]$approvedPatch.ChangedFiles
    $expectedAddedFiles = [int]$approvedPatch.AddedFiles
    $expectedModifiedFiles = [int]$approvedPatch.ModifiedFiles
    $indexFull = Get-FullPath $IndexPath -MustExist
    $patchRoot = Split-Path -Parent $indexFull
    $index = Read-StrictJson $indexFull 'managed patch index'
    Assert-ExactProperties $index @('schema', 'entries') 'managed patch index'
    $expectedIndexSchema = if ($PatchVariant -ceq $script:EnterpriseManagedPatchVariant) {
        'ensou.dsh.upstream-patch-index.v1'
    } else {
        'ensou.dsh.upstream-patch-index.v2'
    }
    if ([string]$index.schema -cne $expectedIndexSchema) {
        throw "Unsupported managed patch index schema: $($index.schema)"
    }
    [object[]]$entries = @($index.entries)
    if ($entries.Count -eq 0) { throw 'Managed patch index has no entries.' }
    $ids = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $directories = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $entries) {
        $expectedEntryProperties = @(
            'id', 'directory', 'repository', 'tag', 'commit', 'tree',
            'manifestSha256', 'patchSha256')
        if ($PatchVariant -ceq $script:EnterpriseDirectLocalPatchVariant) {
            $expectedEntryProperties += 'patchVariant'
        }
        Assert-ExactProperties $entry $expectedEntryProperties "managed patch index entry $($entry.id)"
        if ([string]$entry.id -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$') {
            throw "Invalid managed patch id: $($entry.id)"
        }
        if (-not $ids.Add([string]$entry.id)) { throw "Repeated managed patch id: $($entry.id)" }
        Assert-SafeRelativePath ([string]$entry.directory) 'managed patch directory'
        if (-not $directories.Add([string]$entry.directory)) {
            throw "Repeated managed patch directory: $($entry.directory)"
        }
        Assert-LowerHex ([string]$entry.commit) 40 "managed patch $($entry.id) commit"
        Assert-LowerHex ([string]$entry.tree) 40 "managed patch $($entry.id) tree"
        Assert-LowerHex ([string]$entry.manifestSha256) 64 "managed patch $($entry.id) manifest SHA-256"
        Assert-LowerHex ([string]$entry.patchSha256) 64 "managed patch $($entry.id) patch SHA-256"
        if ($PatchVariant -ceq $script:EnterpriseDirectLocalPatchVariant -and
            [string]$entry.patchVariant -cne $script:EnterpriseDirectLocalPatchVariant) {
            throw "Unsupported managed patch index entry variant: $($entry.patchVariant)"
        }
    }
    $matches = @($entries | Where-Object {
        [string]$_.repository -ceq $Repository -and
        [string]$_.tag -ceq $Tag -and
        [string]$_.commit -ceq $Commit -and
        [string]$_.tree -ceq $Tree -and
        ($PatchVariant -ceq $script:EnterpriseManagedPatchVariant -or
            [string]$_.patchVariant -ceq $PatchVariant)
    })
    if ($matches.Count -ne 1) {
        throw "No unique reviewed managed patch matches exact repository/tag/commit/tree/variant ($Repository / $Tag / $Commit / $Tree / $PatchVariant)."
    }
    $selected = $matches[0]
    $bundleDirectory = Get-FullPath (Join-Path $patchRoot (([string]$selected.directory) -replace '/', '\')) -MustExist
    if (-not (Test-IsWithin $patchRoot $bundleDirectory) -or
        -not (Test-Path -LiteralPath $bundleDirectory -PathType Container)) {
        throw "Managed patch directory escapes the installation-owned patch root: $bundleDirectory"
    }
    Assert-NoReparsePath $bundleDirectory
    $manifestPath = Join-Path $bundleDirectory 'manifest.json'
    $manifestSha256 = Get-FileSha256 $manifestPath
    if ($manifestSha256 -cne [string]$selected.manifestSha256) {
        throw "Managed patch manifest SHA-256 mismatch. Expected $($selected.manifestSha256), got $manifestSha256."
    }

    $manifest = Read-StrictJson $manifestPath 'managed patch manifest'
    $expectedManifestSchema = if ($PatchVariant -ceq $script:EnterpriseManagedPatchVariant) {
        'ensou.dsh.upstream-patch-manifest.v3'
    } else {
        'ensou.dsh.upstream-patch-manifest.v4'
    }
    $expectedManifestProperties = @(
        'schema', 'generator', 'base', 'patch', 'counts', 'managedPolicy',
        'requiredLauncherCoupling', 'files', 'changes')
    if ($PatchVariant -ceq $script:EnterpriseDirectLocalPatchVariant) {
        $expectedManifestProperties += 'patchVariant'
    }
    Assert-ExactProperties $manifest $expectedManifestProperties 'managed patch manifest'
    if ([string]$manifest.schema -cne $expectedManifestSchema) {
        throw "Unsupported managed patch manifest schema: $($manifest.schema)"
    }
    if ($PatchVariant -ceq $script:EnterpriseDirectLocalPatchVariant -and
        [string]$manifest.patchVariant -cne $PatchVariant) {
        throw 'Managed patch manifest variant does not match the explicit requested variant.'
    }
    Assert-ExactProperties $manifest.generator @(
        'version', 'pathOrder', 'lineEndings', 'coreAutocrlf',
        'contextLines', 'trailingWhitespace') 'managed patch generator'
    if ([int]$manifest.generator.version -ne 2 -or
        [string]$manifest.generator.pathOrder -cne 'Unicode code-point ascending' -or
        [string]$manifest.generator.lineEndings -cne 'LF' -or
        $manifest.generator.coreAutocrlf -ne $false -or
        [int]$manifest.generator.contextLines -ne 0 -or
        [string]$manifest.generator.trailingWhitespace -cne 'reject') {
        throw 'Managed patch generator contract is not the reviewed deterministic form.'
    }
    Assert-ExactProperties $manifest.base @('repository', 'tag', 'commit', 'tree', 'modifiedPreimages') 'managed patch base'
    foreach ($property in @('repository', 'tag', 'commit', 'tree')) {
        if ([string]$manifest.base.$property -cne [string]$selected.$property) {
            throw "Managed patch manifest base.$property does not match the index."
        }
    }
    Assert-ExactProperties $manifest.patch @('file', 'bytes', 'lfLines', 'sha256') 'managed patch file record'
    Assert-SafeRelativePath ([string]$manifest.patch.file) 'managed patch file' -FileNameOnly
    Assert-LowerHex ([string]$manifest.patch.sha256) 64 'managed patch manifest patch SHA-256'
    if ([string]$manifest.patch.sha256 -cne [string]$selected.patchSha256) {
        throw 'Managed patch digest differs between index and manifest.'
    }
    $patchPath = Join-Path $bundleDirectory ([string]$manifest.patch.file)
    if (-not (Test-Path -LiteralPath $patchPath -PathType Leaf)) { throw "Managed patch file is missing: $patchPath" }
    Assert-NoReparsePath $patchPath
    $patchItem = Get-Item -LiteralPath $patchPath
    if ($patchItem.Length -ne [int64]$manifest.patch.bytes) {
        throw "Managed patch byte length mismatch. Expected $($manifest.patch.bytes), got $($patchItem.Length)."
    }
    $patchSha256 = Get-FileSha256 $patchPath
    if ($patchSha256 -cne [string]$manifest.patch.sha256) {
        throw "Managed patch SHA-256 mismatch. Expected $($manifest.patch.sha256), got $patchSha256."
    }
    $patchBytes = [IO.File]::ReadAllBytes($patchPath)
    Assert-CanonicalManagedPatchBytes $patchBytes
    $actualLfLines = @($patchBytes | Where-Object { $_ -eq 10 }).Count
    if ($actualLfLines -ne [int]$manifest.patch.lfLines -or
        $patchBytes.Length -eq 0 -or $patchBytes[-1] -ne 10) {
        throw 'Managed patch LF line contract does not match its bytes.'
    }
    if ($PatchVariant -ceq $script:EnterpriseDirectLocalPatchVariant -and
        ($patchSha256 -cne [string]$approvedPatch.PatchSha256 -or
            $patchItem.Length -ne [int64]$approvedPatch.PatchBytes -or
            $actualLfLines -ne [int]$approvedPatch.PatchLfLines)) {
        throw 'Enterprise direct-local patch bytes are not the exact frozen reviewed candidate.'
    }

    Assert-ExactProperties $manifest.counts @(
        'changedFiles', 'addedFiles', 'modifiedFiles') 'managed patch counts'
    if ([int]$manifest.counts.changedFiles -ne $expectedChangedFiles -or
        [int]$manifest.counts.addedFiles -ne $expectedAddedFiles -or
        [int]$manifest.counts.modifiedFiles -ne $expectedModifiedFiles) {
        throw "Managed patch reviewed file counts changed for $Tag."
    }

    $expectedPolicyProperties = @(
        'signal', 'profile', 'webArguments', 'model', 'maxTokens',
        'managedSkillsRootEnvironment', 'sandboxMode', 'sandboxMaximumMode',
        'approvalPolicy', 'permissionPresets', 'workspaceRootSource',
        'restoredSessionCwdPolicy', 'hostCompositionCanonicalSha256',
        'presetCompositionCanonicalSha256', 'presetMetadataCanonicalSha256',
        'loaderRootCanonicalSha256', 'pluginResolutionPolicy')
    $expectedPolicy = [ordered]@{
        signal = 'DSH_ENTERPRISE_MANAGED_BOOT=ensou-dsh-launcher/v1'
        profile = 'enterprise-managed'
        webArguments = '--host 127.0.0.1 --port <canonical 1..65535>'
        model = 'deepseek-v4-flash'
        maxTokens = 8192
        managedSkillsRootEnvironment = 'ENSOU_DSH_ENTERPRISE_SKILLS_ROOT'
        sandboxMode = 'workspace-write'
        sandboxMaximumMode = 'workspace-write'
        approvalPolicy = 'ask'
        workspaceRootSource = 'process.cwd()'
        restoredSessionCwdPolicy = 'must-equal-workspace-root'
        pluginResolutionPolicy = 'frozen exact installation map from managed base/web bundles; no ambient fallback'
    }
    if ($PatchVariant -ceq $script:EnterpriseManagedPatchVariant) {
        $expectedPolicyProperties += @('gatewayAllowedModel', 'gatewayMaxTokens')
        $expectedPolicy.gatewayAllowedModel = 'deepseek-v4-flash'
        $expectedPolicy.gatewayMaxTokens = 8192
    } else {
        $expectedPolicyProperties += @(
            'modelBaseUrl', 'searchBaseUrl', 'credentialEnvironment', 'credentialSource',
            'launchEnvironmentProviderOverrides', 'settingsProvider')
        $expectedPolicy.profile = 'enterprise-direct-local'
        $expectedPolicy.modelBaseUrl = 'https://api.deepseek.com'
        $expectedPolicy.searchBaseUrl = 'https://api.deepseek.com/anthropic/v1'
        $expectedPolicy.credentialEnvironment = 'DEEPSEEK_API_KEY'
        $expectedPolicy.credentialSource = '@deepseek-ai/dsh-credentials-local writable local credential store'
        $expectedPolicy.settingsProvider = '@deepseek-ai/dsh-settings-file/composition-only'
    }
    Assert-ExactProperties $manifest.managedPolicy $expectedPolicyProperties 'managed policy'
    foreach ($key in $expectedPolicy.Keys) {
        if ([string]$manifest.managedPolicy.$key -cne [string]$expectedPolicy[$key]) {
            throw "Managed policy $key is not the reviewed value."
        }
    }
    if ($PatchVariant -ceq $script:EnterpriseDirectLocalPatchVariant) {
        [string[]]$providerOverrides = @($manifest.managedPolicy.launchEnvironmentProviderOverrides)
        [string[]]$expectedProviderOverrides = @(
            'DEEPSEEK_BASE_URL', 'DEEPSEEK_SEARCH_BASE_URL', 'DEEPSEEK_API_KEY')
        if ($providerOverrides.Count -ne $expectedProviderOverrides.Count) {
            throw 'Direct-local launch-environment provider override refusal list changed.'
        }
        for ($position = 0; $position -lt $expectedProviderOverrides.Count; $position++) {
            if ($providerOverrides[$position] -cne $expectedProviderOverrides[$position]) {
                throw 'Direct-local launch-environment provider override refusal list changed.'
            }
        }
    }
    [object[]]$permissionPresets = @($manifest.managedPolicy.permissionPresets)
    if ($permissionPresets.Count -ne 1 -or [string]$permissionPresets[0] -cne 'workspace-write') {
        throw 'Managed policy permissionPresets must contain only workspace-write.'
    }
    foreach ($digestProperty in @(
        'hostCompositionCanonicalSha256', 'presetCompositionCanonicalSha256',
        'presetMetadataCanonicalSha256', 'loaderRootCanonicalSha256')) {
        Assert-LowerHex ([string]$manifest.managedPolicy.$digestProperty) 64 "managed policy $digestProperty"
    }
    Assert-ExactProperties $manifest.requiredLauncherCoupling @('childEnvironmentMustUnset', 'note') 'required Launcher coupling'
    [string[]]$requiredUnset = @($manifest.requiredLauncherCoupling.childEnvironmentMustUnset)
    [string[]]$expectedUnset = @('NODE_OPTIONS', 'NODE_PATH', 'NODE_EXTRA_CA_CERTS')
    if ($requiredUnset.Count -ne $expectedUnset.Count) { throw 'Required child-environment unset list changed.' }
    for ($indexPosition = 0; $indexPosition -lt $expectedUnset.Count; $indexPosition++) {
        if ($requiredUnset[$indexPosition] -cne $expectedUnset[$indexPosition]) {
            throw 'Required child-environment unset list changed.'
        }
    }

    [object[]]$files = @($manifest.files)
    [object[]]$changes = @($manifest.changes)
    if ($files.Count -ne $expectedChangedFiles -or $changes.Count -ne $expectedChangedFiles) {
        throw "Reviewed managed patch must contain exactly $expectedChangedFiles files/changes for $Tag; got $($files.Count)/$($changes.Count)."
    }
    $filesByPath = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
    foreach ($file in $files) {
        Assert-ExactProperties $file @('path', 'bytes', 'sha256', 'gitBlob') "managed patch file $($file.path)"
        $path = [string]$file.path
        Assert-SafeRelativePath $path 'managed patch file path'
        if (-not $filesByPath.TryAdd($path, $file)) { throw "Repeated managed patch file path: $path" }
        if ([int64]$file.bytes -lt 0) { throw "Negative managed patch file size: $path" }
        Assert-LowerHex ([string]$file.sha256) 64 "managed patch file SHA-256 $path"
        Assert-LowerHex ([string]$file.gitBlob) 40 "managed patch file Git blob $path"
    }
    $changesByPath = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
    $modifiedPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($change in $changes) {
        Assert-ExactProperties $change @('path', 'status', 'preimage', 'postimage') "managed patch change $($change.path)"
        $path = [string]$change.path
        Assert-SafeRelativePath $path 'managed patch change path'
        if (-not $changesByPath.TryAdd($path, $change)) { throw "Repeated managed patch change path: $path" }
        if (-not $filesByPath.ContainsKey($path)) { throw "Change has no file record: $path" }
        if ([string]$change.status -cne 'A' -and [string]$change.status -cne 'M') {
            throw "Unsupported managed patch change status for ${path}: $($change.status)"
        }
        if ([string]$change.status -ceq 'A') {
            if ($null -ne $change.preimage) { throw "Added managed patch file has a preimage: $path" }
        } else {
            if ($null -eq $change.preimage) { throw "Modified managed patch file has no preimage: $path" }
            Assert-ExactProperties $change.preimage @('gitBlob', 'bytes', 'sha256') "managed patch preimage $path"
            Assert-LowerHex ([string]$change.preimage.gitBlob) 40 "managed patch preimage Git blob $path"
            Assert-LowerHex ([string]$change.preimage.sha256) 64 "managed patch preimage SHA-256 $path"
            if ([int64]$change.preimage.bytes -lt 0) { throw "Negative managed patch preimage size: $path" }
            [void]$modifiedPaths.Add($path)
        }
        Assert-ExactProperties $change.postimage @('gitBlob', 'bytes', 'sha256') "managed patch postimage $path"
        $file = $filesByPath[$path]
        foreach ($property in @('gitBlob', 'bytes', 'sha256')) {
            if ([string]$change.postimage.$property -cne [string]$file.$property) {
                throw "Managed patch file/postimage $property mismatch: $path"
            }
        }
    }
    if ($modifiedPaths.Count -ne $expectedModifiedFiles) {
        throw "Reviewed managed patch must contain exactly $expectedModifiedFiles modified preimages for $Tag; got $($modifiedPaths.Count)."
    }
    if (@($changes | Where-Object { [string]$_.status -ceq 'A' }).Count -ne $expectedAddedFiles -or
        [int]$manifest.counts.changedFiles -ne $files.Count -or
        [int]$manifest.counts.modifiedFiles -ne $modifiedPaths.Count) {
        throw 'Managed patch manifest counts do not match its change records.'
    }
    $preimageProperties = @($manifest.base.modifiedPreimages.PSObject.Properties)
    if ($preimageProperties.Count -ne $modifiedPaths.Count) {
        throw 'base.modifiedPreimages count does not match modified changes.'
    }
    foreach ($property in $preimageProperties) {
        $path = [string]$property.Name
        if (-not $modifiedPaths.Contains($path)) { throw "Unexpected modified preimage path: $path" }
        Assert-LowerHex ([string]$property.Value) 40 "modified preimage Git blob $path"
        if ([string]$property.Value -cne [string]$changesByPath[$path].preimage.gitBlob) {
            throw "Modified preimage Git blob differs from change record: $path"
        }
    }
    if (-not $changesByPath.ContainsKey('pnpm-lock.yaml') -or
        [string]$changesByPath['pnpm-lock.yaml'].status -cne 'M') {
        throw 'Managed patch must modify the approved upstream pnpm-lock.yaml preimage.'
    }
    $baseLockfile = $changesByPath['pnpm-lock.yaml'].preimage
    if ([string]$baseLockfile.sha256 -cne [string]$approvedBase.BaseLockfileSha256 -or
        [string]$baseLockfile.gitBlob -cne [string]$approvedBase.BaseLockfileGitBlob -or
        [int64]$baseLockfile.bytes -ne [int64]$approvedBase.BaseLockfileBytes) {
        throw 'Managed patch base pnpm-lock.yaml is not the exact approved SHA-256, Git blob, and byte length.'
    }
    if ($PatchVariant -ceq $script:EnterpriseDirectLocalPatchVariant) {
        $patchedLockfile = $filesByPath['pnpm-lock.yaml']
        if ([string]$patchedLockfile.sha256 -cne [string]$approvedPatch.PatchedLockfileSha256 -or
            [string]$patchedLockfile.gitBlob -cne [string]$approvedPatch.PatchedLockfileGitBlob -or
            [int64]$patchedLockfile.bytes -ne [int64]$approvedPatch.PatchedLockfileBytes) {
            throw 'Enterprise direct-local patched pnpm-lock.yaml is not the exact frozen SHA-256, Git blob, and byte length.'
        }
    }

    return [pscustomobject]@{
        Id = [string]$selected.id
        Directory = $bundleDirectory
        DirectoryRelative = [string]$selected.directory
        ManifestPath = $manifestPath
        ManifestSha256 = $manifestSha256
        PatchPath = $patchPath
        PatchSha256 = $patchSha256
        Manifest = $manifest
        Files = $files
        Changes = $changes
        FilesByPath = $filesByPath
        ChangesByPath = $changesByPath
    }
}

function Assert-ManagedSourcePreimages([object]$Bundle, [string]$Checkout, [string]$Git) {
    $source = Get-FullPath $Checkout -MustExist
    foreach ($change in $Bundle.Changes) {
        $path = [string]$change.path
        $nativePath = Join-Path $source ($path -replace '/', '\')
        if ([string]$change.status -ceq 'A') {
            if ((Invoke-GitExit $Git $source @('cat-file', '-e', "$($Bundle.Manifest.base.commit):$path")) -eq 0 -or
                (Test-Path -LiteralPath $nativePath)) {
                throw "Managed patch added path already exists in the exact base: $path"
            }
            continue
        }
        if (-not (Test-Path -LiteralPath $nativePath -PathType Leaf)) {
            throw "Managed patch preimage is missing: $path"
        }
        $item = Get-Item -LiteralPath $nativePath -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "Managed patch preimage is a reparse point: $path"
        }
        $preimage = $change.preimage
        $baseBlob = Invoke-GitText $Git $source @('rev-parse', "$($Bundle.Manifest.base.commit):$path") "resolve base blob $path"
        $workingBlob = Invoke-GitText $Git $source @('hash-object', '--', $path) "hash working preimage $path"
        $actualSha = Get-FileSha256 $nativePath
        if ($baseBlob -cne [string]$preimage.gitBlob -or $workingBlob -cne [string]$preimage.gitBlob -or
            $item.Length -ne [int64]$preimage.bytes -or $actualSha -cne [string]$preimage.sha256) {
            throw "Managed patch preimage identity mismatch: $path"
        }
    }
}

function Get-ManagedChangedState([object]$Bundle, [string]$Checkout, [string]$Git) {
    $source = Get-FullPath $Checkout -MustExist
    $state = [Collections.Generic.Dictionary[string, string]]::new([StringComparer]::Ordinal)
    $tracked = Invoke-GitText $Git $source @('diff', '--name-status', '--no-renames', '--') 'enumerate patched tracked paths'
    foreach ($line in ($tracked -split "`r?`n")) {
        if (-not $line) { continue }
        if ($line -notmatch '^(?<status>[A-Z])\s+(?<path>.+)$') { throw "Unexpected git diff status line: $line" }
        if (-not $state.TryAdd($Matches.path, $Matches.status)) { throw "Repeated changed path: $($Matches.path)" }
    }
    $untracked = Invoke-GitText $Git $source @('ls-files', '--others', '--exclude-standard', '--') 'enumerate patched added paths'
    foreach ($path in ($untracked -split "`r?`n")) {
        if (-not $path) { continue }
        if (-not $state.TryAdd($path, 'A')) { throw "Repeated changed path: $path" }
    }
    return $state
}

function Assert-ManagedSourcePostimages([object]$Bundle, [string]$Checkout, [string]$Git) {
    $source = Get-FullPath $Checkout -MustExist
    $state = Get-ManagedChangedState $Bundle $source $Git
    if ($state.Count -ne $Bundle.Changes.Count) {
        throw "Patched source changed-path count mismatch. Expected $($Bundle.Changes.Count), got $($state.Count)."
    }
    foreach ($change in $Bundle.Changes) {
        $path = [string]$change.path
        if (-not $state.ContainsKey($path) -or $state[$path] -cne [string]$change.status) {
            throw "Patched source changed-path status mismatch: $path"
        }
        $nativePath = Join-Path $source ($path -replace '/', '\')
        if (-not (Test-Path -LiteralPath $nativePath -PathType Leaf)) { throw "Managed patch postimage is missing: $path" }
        $item = Get-Item -LiteralPath $nativePath -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Managed patch postimage is a reparse point: $path" }
        $postimage = $change.postimage
        $actualSha = Get-FileSha256 $nativePath
        $actualBlob = Invoke-GitText $Git $source @('hash-object', '--', $path) "hash managed postimage $path"
        if ($item.Length -ne [int64]$postimage.bytes -or $actualSha -cne [string]$postimage.sha256 -or
            $actualBlob -cne [string]$postimage.gitBlob) {
            throw "Managed patch postimage identity mismatch: $path"
        }
    }
    $diffCheck = Invoke-GitExit $Git $source @('diff', '--check', '--')
    if ($diffCheck -ne 0) { throw 'Managed patched source failed git diff --check.' }
}

function Apply-ManagedSourcePatch([object]$Bundle, [string]$Checkout, [string]$Git) {
    $source = Get-FullPath $Checkout -MustExist
    Assert-NoReparseTree $source
    Assert-ManagedSourcePreimages $Bundle $source $Git
    [void](Invoke-GitText $Git $source @(
        '-c', 'core.whitespace=-blank-at-eof',
        'apply', '--check', '--unidiff-zero', '--whitespace=error-all',
        $Bundle.PatchPath) 'managed patch apply check')
    [void](Invoke-GitText $Git $source @(
        '-c', 'core.whitespace=-blank-at-eof',
        'apply', '--unidiff-zero', '--whitespace=error-all',
        $Bundle.PatchPath) 'managed patch apply')
    Assert-ManagedSourcePostimages $Bundle $source $Git
    Assert-NoReparseTree $source
}

Export-ModuleMember -Function @(
    'Assert-CanonicalManagedPatchBytes',
    'Get-ManagedSourceLock',
    'Get-ManagedSourcePatchBundle',
    'Assert-ManagedSourcePreimages',
    'Assert-ManagedSourcePostimages',
    'Apply-ManagedSourcePatch'
)
