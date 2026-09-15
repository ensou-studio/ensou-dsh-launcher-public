#requires -Version 7.2

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $IsWindows -or
    $PSVersionTable.PSEdition -ne 'Core' -or
    [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -ne
        [Runtime.InteropServices.Architecture]::X64) {
    throw 'Portable .NET SDK lock-generator tests require native Windows x64 PowerShell 7.2 or newer.'
}

$generatorPath = Join-Path $PSScriptRoot 'New-PortableDotNetSdkLock.ps1'
$schemaPath = [IO.Path]::GetFullPath((Join-Path `
        $PSScriptRoot '..\schemas\portable-dotnet-sdk-byte-closure-v1.schema.json'))
$officialUrl =
    'https://builds.dotnet.microsoft.com/dotnet/Sdk/10.0.302/' +
    'dotnet-sdk-10.0.302-win-x64.zip'
$archiveName = 'dotnet-sdk-10.0.302-win-x64.zip'
$utf8 = [Text.UTF8Encoding]::new($false, $true)
$script:AssertionCount = 0
$script:PassedTests = [Collections.Generic.List[string]]::new()

$temporaryBase = [IO.Path]::TrimEndingDirectorySeparator(
    [IO.Path]::GetFullPath([IO.Path]::GetTempPath()))
$temporaryLeaf =
    'ensou-dsh-new-portable-sdk-lock-test-' + [guid]::NewGuid().ToString('N')
$temporaryRoot = [IO.Path]::GetFullPath((Join-Path $temporaryBase $temporaryLeaf))
if ([IO.Path]::GetDirectoryName($temporaryRoot) -cne $temporaryBase -or
    -not [IO.Path]::GetFileName($temporaryRoot).StartsWith(
        'ensou-dsh-new-portable-sdk-lock-test-',
        [StringComparison]::Ordinal)) {
    throw 'Portable .NET SDK lock-generator test root is unsafe.'
}
[IO.Directory]::CreateDirectory($temporaryRoot) | Out-Null

function Assert-TestTrue {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if (-not $Condition) {
        throw "Assertion failed: $Label"
    }
    $script:AssertionCount++
}

function Assert-TestThrows {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Body,
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][string]$ExpectedMessageLike
    )

    $caught = $null
    try {
        $null = & $Body
    }
    catch {
        $caught = $_.Exception
    }
    if ($null -eq $caught) {
        throw "Assertion failed: $Label did not throw."
    }
    if ($caught.Message -notlike $ExpectedMessageLike) {
        throw "Assertion failed: $Label threw '$($caught.Message)', expected '$ExpectedMessageLike'."
    }
    $script:AssertionCount++
    return $caught
}

function Invoke-TestCase {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Body
    )

    try {
        $null = & $Body
        $script:PassedTests.Add($Name)
    }
    catch {
        throw "Portable .NET SDK lock-generator test '$Name' failed: $($_.Exception.Message)"
    }
}

function New-TestScenario {
    param([Parameter(Mandatory = $true)][string]$Name)

    $root = [IO.Path]::GetFullPath((Join-Path $temporaryRoot $Name))
    [IO.Directory]::CreateDirectory($root) | Out-Null
    return [pscustomobject]@{
        Root = $root
        ArchivePath = [IO.Path]::GetFullPath((Join-Path $root $archiveName))
        OutputPath = [IO.Path]::GetFullPath((Join-Path $root 'sdk.lock.json'))
    }
}

function Convert-HexUInt32ToInt32 {
    param([Parameter(Mandatory = $true)][string]$Hex)

    $unsigned = [uint32]::Parse(
        $Hex,
        [Globalization.NumberStyles]::HexNumber,
        [Globalization.CultureInfo]::InvariantCulture)
    return [BitConverter]::ToInt32([BitConverter]::GetBytes($unsigned), 0)
}

function New-TestArchive {
    param(
        [Parameter(Mandatory = $true)]$Scenario,
        [Parameter(Mandatory = $true)][object[]]$Entries
    )

    $stream = [IO.FileStream]::new(
        $Scenario.ArchivePath,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None)
    $archive = [IO.Compression.ZipArchive]::new(
        $stream,
        [IO.Compression.ZipArchiveMode]::Create,
        $false)
    try {
        foreach ($specification in $Entries) {
            $entry = $archive.CreateEntry(
                [string]$specification.Name,
                [IO.Compression.CompressionLevel]::Optimal)
            $entry.ExternalAttributes = [int32]$specification.ExternalAttributes
            $entryStream = $entry.Open()
            try {
                $bytes = [byte[]]$specification.Bytes
                if ($bytes.Length -gt 0) {
                    $entryStream.Write($bytes, 0, $bytes.Length)
                }
            }
            finally {
                $entryStream.Dispose()
            }
        }
    }
    finally {
        $archive.Dispose()
    }
}

function New-LargeLockArchive {
    param([Parameter(Mandatory = $true)]$Scenario)

    $stream = [IO.FileStream]::new(
        $Scenario.ArchivePath,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None)
    $archive = [IO.Compression.ZipArchive]::new(
        $stream,
        [IO.Compression.ZipArchiveMode]::Create,
        $false)
    try {
        $padding = 'x' * 240
        for ($index = 0; $index -lt 16384; $index++) {
            $name = 'bulk/{0:D5}-{1}.bin' -f $index, $padding
            $entry = $archive.CreateEntry(
                $name,
                [IO.Compression.CompressionLevel]::NoCompression)
            $entry.ExternalAttributes = 0
            $entryStream = $entry.Open()
            try {
                if ($index -eq 0) {
                    $entryStream.WriteByte(1)
                }
            }
            finally {
                $entryStream.Dispose()
            }
        }
    }
    finally {
        $archive.Dispose()
    }
}

function Get-TestArchiveSha512 {
    param([Parameter(Mandatory = $true)][string]$Path)

    return (Get-FileHash -LiteralPath $Path -Algorithm SHA512).Hash
}

function Invoke-TestGenerator {
    param(
        [Parameter(Mandatory = $true)]$Scenario,
        [string]$Url = $officialUrl,
        [string]$ExpectedSha512 = '',
        [switch]$TestOnly
    )

    if ([string]::IsNullOrEmpty($ExpectedSha512)) {
        $ExpectedSha512 = Get-TestArchiveSha512 -Path $Scenario.ArchivePath
    }
    $arguments = @{
        ArchivePath = $Scenario.ArchivePath
        ArchiveUrl = $Url
        ExpectedArchiveSha512 = $ExpectedSha512
        OutputPath = $Scenario.OutputPath
    }
    if ($TestOnly) {
        $arguments.TestOnly = $true
    }
    return & $generatorPath @arguments
}

function New-Specification {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [byte[]]$Bytes = [byte[]]::new(0),
        [int32]$ExternalAttributes = 0
    )

    return [pscustomobject]@{
        Name = $Name
        Bytes = $Bytes
        ExternalAttributes = $ExternalAttributes
    }
}

function Assert-FailedOutputAbsent {
    param(
        [Parameter(Mandatory = $true)]$Scenario,
        [Parameter(Mandatory = $true)][string]$Label
    )

    Assert-TestTrue `
        -Condition (-not [IO.File]::Exists($Scenario.OutputPath)) `
        -Label "$Label did not create an output"
}

try {
    Invoke-TestCase -Name 'positive canonical lock with zero-byte file' -Body {
        $scenario = New-TestScenario -Name 'positive'
        New-TestArchive -Scenario $scenario -Entries @(
            (New-Specification -Name 'sdk/'),
            (New-Specification `
                -Name 'sdk/10.0.302/_._'),
            (New-Specification `
                -Name 'dotnet.exe' `
                -Bytes $utf8.GetBytes('fixture-dotnet')))
        $result = Invoke-TestGenerator -Scenario $scenario -TestOnly
        $bytes = [IO.File]::ReadAllBytes($scenario.OutputPath)
        $json = $utf8.GetString($bytes)
        $lock = $json | ConvertFrom-Json -Depth 16

        Assert-TestTrue ($result.TestOnly -eq $true) 'positive fixture reports TestOnly'
        Assert-TestTrue ($bytes.LongLength -le 4MB) 'positive lock is within 4 MiB'
        Assert-TestTrue `
            (Microsoft.PowerShell.Utility\Test-Json `
                -Json $json `
                -SchemaFile $schemaPath `
                -ErrorAction Stop) `
            'positive lock validates against schema'
        Assert-TestTrue `
            (($lock.PSObject.Properties.Name -join ',') -ceq
                'contract,sdkVersion,os,architecture,archiveSource,archiveSha512,fileCount,totalSizeBytes,inventorySha256,files') `
            'top-level canonical member order'
        Assert-TestTrue `
            (($lock.archiveSource.PSObject.Properties.Name -join ',') -ceq
                'url,officialMicrosoft') `
            'archive-source canonical member order'
        Assert-TestTrue ($lock.fileCount -eq 2) 'directory entry is not inventoried'
        Assert-TestTrue ($lock.totalSizeBytes -eq 14) 'positive total size is exact'
        Assert-TestTrue `
            ([string]$lock.files[0].relativePath -ceq 'dotnet.exe') `
            'first path uses OrdinalIgnoreCase order'
        Assert-TestTrue `
            ([string]$lock.files[1].relativePath -ceq 'sdk/10.0.302/_._') `
            'second path uses OrdinalIgnoreCase order'
        Assert-TestTrue `
            ([int64]$lock.files[1].sizeBytes -eq 0) `
            'zero-byte entry remains present'
        Assert-TestTrue `
            ([string]$lock.files[1].sha256 -ceq
                'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855') `
            'zero-byte SHA-256 is exact'
        foreach ($file in @($lock.files)) {
            Assert-TestTrue `
                (($file.PSObject.Properties.Name -join ',') -ceq
                    'relativePath,sizeBytes,sha256') `
                "file '$($file.relativePath)' canonical member order"
        }
        $filesJson = Microsoft.PowerShell.Utility\ConvertTo-Json `
            -InputObject @($lock.files) `
            -Depth 64 `
            -Compress
        $inventorySha256 = [Convert]::ToHexString(
            [Security.Cryptography.SHA256]::HashData(
                $utf8.GetBytes($filesJson))).ToLowerInvariant()
        Assert-TestTrue `
            ($inventorySha256 -ceq [string]$lock.inventorySha256) `
            'inventory SHA-256 covers canonical files JSON'
        $canonical = Microsoft.PowerShell.Utility\ConvertTo-Json `
            -InputObject $lock `
            -Depth 64 `
            -Compress
        Assert-TestTrue ($canonical -ceq $json) 'lock bytes are canonical JSON'
    }

    Invoke-TestCase -Name 'archive SHA-512 mismatch rejection' -Body {
        $scenario = New-TestScenario -Name 'hash-mismatch'
        New-TestArchive -Scenario $scenario -Entries @(
            (New-Specification -Name 'dotnet.exe' -Bytes ([byte[]]@(1))))
        [void](Assert-TestThrows `
                -Body {
                    Invoke-TestGenerator `
                        -Scenario $scenario `
                        -ExpectedSha512 ('0' * 128)
                } `
                -Label 'archive SHA-512 mismatch' `
                -ExpectedMessageLike '*SHA-512 differs*')
        Assert-FailedOutputAbsent -Scenario $scenario -Label 'hash mismatch'
    }

    Invoke-TestCase -Name 'official URL rejection' -Body {
        $scenario = New-TestScenario -Name 'url-rejection'
        New-TestArchive -Scenario $scenario -Entries @(
            (New-Specification -Name 'dotnet.exe' -Bytes ([byte[]]@(1))))
        [void](Assert-TestThrows `
                -Body {
                    Invoke-TestGenerator `
                        -Scenario $scenario `
                        -Url ('https://evil.example/' + $archiveName)
                } `
                -Label 'non-Microsoft URL' `
                -ExpectedMessageLike '*official Microsoft HTTPS URL*')
        Assert-FailedOutputAbsent -Scenario $scenario -Label 'URL rejection'
    }

    Invoke-TestCase -Name 'TestOnly traversal rejection' -Body {
        $scenario = New-TestScenario -Name 'traversal'
        New-TestArchive -Scenario $scenario -Entries @(
            (New-Specification -Name '../evil.txt' -Bytes ([byte[]]@(1))))
        [void](Assert-TestThrows `
                -Body { Invoke-TestGenerator -Scenario $scenario -TestOnly } `
                -Label 'TestOnly traversal' `
                -ExpectedMessageLike '*non-round-trippable Windows segment*')
        Assert-FailedOutputAbsent -Scenario $scenario -Label 'TestOnly traversal'
    }

    Invoke-TestCase -Name 'backslash path rejection' -Body {
        $scenario = New-TestScenario -Name 'backslash'
        New-TestArchive -Scenario $scenario -Entries @(
            (New-Specification -Name 'sdk\evil.txt' -Bytes ([byte[]]@(1))))
        [void](Assert-TestThrows `
                -Body { Invoke-TestGenerator -Scenario $scenario } `
                -Label 'backslash path' `
                -ExpectedMessageLike '*path is unsafe*')
        Assert-FailedOutputAbsent -Scenario $scenario -Label 'backslash path'
    }

    Invoke-TestCase -Name 'reserved Windows device rejection' -Body {
        $scenario = New-TestScenario -Name 'reserved-device'
        New-TestArchive -Scenario $scenario -Entries @(
            (New-Specification -Name 'sdk/CON.txt' -Bytes ([byte[]]@(1))))
        [void](Assert-TestThrows `
                -Body { Invoke-TestGenerator -Scenario $scenario } `
                -Label 'reserved device path' `
                -ExpectedMessageLike '*reserved Windows device segment*')
        Assert-FailedOutputAbsent -Scenario $scenario -Label 'reserved device'
    }

    Invoke-TestCase -Name 'trailing-dot path rejection' -Body {
        $scenario = New-TestScenario -Name 'trailing-dot'
        New-TestArchive -Scenario $scenario -Entries @(
            (New-Specification -Name 'sdk/file.' -Bytes ([byte[]]@(1))))
        [void](Assert-TestThrows `
                -Body { Invoke-TestGenerator -Scenario $scenario } `
                -Label 'trailing-dot path' `
                -ExpectedMessageLike '*non-round-trippable Windows segment*')
        Assert-FailedOutputAbsent -Scenario $scenario -Label 'trailing-dot path'
    }

    Invoke-TestCase -Name '256-character path segment rejection' -Body {
        $scenario = New-TestScenario -Name 'segment-too-long'
        New-TestArchive -Scenario $scenario -Entries @(
            (New-Specification `
                -Name ('x' * 256) `
                -Bytes ([byte[]]@(1))))
        [void](Assert-TestThrows `
                -Body { Invoke-TestGenerator -Scenario $scenario } `
                -Label '256-character path segment' `
                -ExpectedMessageLike '*longer than 255 characters*')
        Assert-FailedOutputAbsent `
            -Scenario $scenario `
            -Label '256-character path segment'
    }

    Invoke-TestCase -Name 'Unix symlink attribute rejection' -Body {
        $scenario = New-TestScenario -Name 'unix-symlink'
        $symlink = Convert-HexUInt32ToInt32 -Hex 'A1FF0000'
        New-TestArchive -Scenario $scenario -Entries @(
            (New-Specification `
                -Name 'sdk-link' `
                -Bytes $utf8.GetBytes('target') `
                -ExternalAttributes $symlink))
        [void](Assert-TestThrows `
                -Body { Invoke-TestGenerator -Scenario $scenario } `
                -Label 'Unix symlink attribute' `
                -ExpectedMessageLike '*symbolic link or reparse point*')
        Assert-FailedOutputAbsent -Scenario $scenario -Label 'Unix symlink'
    }

    Invoke-TestCase -Name 'DOS reparse attribute rejection' -Body {
        $scenario = New-TestScenario -Name 'dos-reparse'
        New-TestArchive -Scenario $scenario -Entries @(
            (New-Specification `
                -Name 'reparse' `
                -Bytes ([byte[]]@(1)) `
                -ExternalAttributes ([int][IO.FileAttributes]::ReparsePoint)))
        [void](Assert-TestThrows `
                -Body { Invoke-TestGenerator -Scenario $scenario } `
                -Label 'DOS reparse attribute' `
                -ExpectedMessageLike '*symbolic link or reparse point*')
        Assert-FailedOutputAbsent -Scenario $scenario -Label 'DOS reparse'
    }

    Invoke-TestCase -Name 'exact duplicate rejection' -Body {
        $scenario = New-TestScenario -Name 'exact-duplicate'
        New-TestArchive -Scenario $scenario -Entries @(
            (New-Specification -Name 'same.txt' -Bytes ([byte[]]@(1))),
            (New-Specification -Name 'same.txt' -Bytes ([byte[]]@(2))))
        [void](Assert-TestThrows `
                -Body { Invoke-TestGenerator -Scenario $scenario } `
                -Label 'exact duplicate' `
                -ExpectedMessageLike '*duplicate*')
        Assert-FailedOutputAbsent -Scenario $scenario -Label 'exact duplicate'
    }

    Invoke-TestCase -Name 'OrdinalIgnoreCase collision rejection' -Body {
        $scenario = New-TestScenario -Name 'case-collision'
        New-TestArchive -Scenario $scenario -Entries @(
            (New-Specification -Name 'A.txt' -Bytes ([byte[]]@(1))),
            (New-Specification -Name 'a.txt' -Bytes ([byte[]]@(2))))
        [void](Assert-TestThrows `
                -Body { Invoke-TestGenerator -Scenario $scenario } `
                -Label 'OrdinalIgnoreCase collision' `
                -ExpectedMessageLike '*OrdinalIgnoreCase-colliding*')
        Assert-FailedOutputAbsent -Scenario $scenario -Label 'case collision'
    }

    Invoke-TestCase -Name 'file-directory conflict rejection' -Body {
        $scenario = New-TestScenario -Name 'file-directory-conflict'
        New-TestArchive -Scenario $scenario -Entries @(
            (New-Specification -Name 'node' -Bytes ([byte[]]@(1))),
            (New-Specification -Name 'node/child.dll' -Bytes ([byte[]]@(2))))
        [void](Assert-TestThrows `
                -Body { Invoke-TestGenerator -Scenario $scenario } `
                -Label 'file-directory conflict' `
                -ExpectedMessageLike '*descends through a file path*')
        Assert-FailedOutputAbsent `
            -Scenario $scenario `
            -Label 'file-directory conflict'
    }

    Invoke-TestCase -Name 'CreateNew preserves existing output' -Body {
        $scenario = New-TestScenario -Name 'create-new'
        New-TestArchive -Scenario $scenario -Entries @(
            (New-Specification -Name 'dotnet.exe' -Bytes ([byte[]]@(1))))
        $sentinel = $utf8.GetBytes('do-not-overwrite')
        $output = [IO.FileStream]::new(
            $scenario.OutputPath,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None)
        try {
            $output.Write($sentinel, 0, $sentinel.Length)
            $output.Flush($true)
        }
        finally {
            $output.Dispose()
        }
        [void](Assert-TestThrows `
                -Body { Invoke-TestGenerator -Scenario $scenario } `
                -Label 'CreateNew existing output' `
                -ExpectedMessageLike '*must not already exist*')
        $after = [IO.File]::ReadAllBytes($scenario.OutputPath)
        Assert-TestTrue `
            ([Security.Cryptography.CryptographicOperations]::FixedTimeEquals(
                $sentinel,
                $after)) `
            'existing output bytes remain unchanged'
    }

    Invoke-TestCase -Name 'canonical JSON 4 MiB bound rejection' -Body {
        $scenario = New-TestScenario -Name 'lock-byte-bound'
        New-LargeLockArchive -Scenario $scenario
        [void](Assert-TestThrows `
                -Body { Invoke-TestGenerator -Scenario $scenario -TestOnly } `
                -Label 'canonical lock byte bound' `
                -ExpectedMessageLike '*exceeds the 4 MiB canonical JSON byte bound*')
        Assert-FailedOutputAbsent -Scenario $scenario -Label '4 MiB lock bound'
    }

    [pscustomobject]@{
        Status = 'PASS'
        TestCount = $script:PassedTests.Count
        AssertionCount = $script:AssertionCount
        Tests = @($script:PassedTests)
    }
}
finally {
    if ([IO.Directory]::Exists($temporaryRoot)) {
        $resolvedRoot = [IO.Path]::GetFullPath($temporaryRoot)
        if ([IO.Path]::GetDirectoryName($resolvedRoot) -cne $temporaryBase -or
            -not [IO.Path]::GetFileName($resolvedRoot).StartsWith(
                'ensou-dsh-new-portable-sdk-lock-test-',
                [StringComparison]::Ordinal)) {
            throw 'Refusing unsafe recursive lock-generator test cleanup.'
        }
        Remove-Item -LiteralPath $resolvedRoot -Recurse -Force
    }
}
