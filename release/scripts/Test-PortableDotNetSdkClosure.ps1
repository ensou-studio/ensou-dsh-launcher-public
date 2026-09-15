#requires -Version 7.2

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $IsWindows -or
    $PSVersionTable.PSEdition -ne 'Core' -or
    [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -ne
        [Runtime.InteropServices.Architecture]::X64) {
    throw 'Portable .NET SDK closure tests require native Windows x64 PowerShell 7.2 or newer.'
}

$modulePath = Join-Path $PSScriptRoot 'PortableDotNetSdkClosure.psm1'
$stateModulePath = Join-Path $PSScriptRoot 'ProductionReleaseState.psm1'
Microsoft.PowerShell.Core\Import-Module $modulePath -Force -ErrorAction Stop
Microsoft.PowerShell.Core\Import-Module $stateModulePath -Force -ErrorAction Stop

$script:SdkVersion = '10.0.302'
$script:AssertionCount = 0
$script:PassedTests = [Collections.Generic.List[string]]::new()
$script:SkippedTests = [Collections.Generic.List[string]]::new()
$script:TrackedClosures = [Collections.Generic.List[object]]::new()
$script:TrackedReparsePoints = [Collections.Generic.List[string]]::new()
$script:TrackedVerbatimFiles = [Collections.Generic.List[string]]::new()

$temporaryBase = [IO.Path]::TrimEndingDirectorySeparator(
    [IO.Path]::GetFullPath([IO.Path]::GetTempPath()))
$temporaryLeaf = 'ensou-dsh-portable-sdk-closure-test-' + [Guid]::NewGuid().ToString('N')
$temporaryRoot = [IO.Path]::GetFullPath((Join-Path $temporaryBase $temporaryLeaf))
if ([IO.Path]::GetDirectoryName($temporaryRoot) -cne $temporaryBase -or
    -not [IO.Path]::GetFileName($temporaryRoot).StartsWith(
        'ensou-dsh-portable-sdk-closure-test-',
        [StringComparison]::Ordinal)) {
    throw 'Portable .NET SDK test temporary-root boundary is unsafe.'
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
        [string]$ExpectedMessageLike = ''
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
    if ($ExpectedMessageLike -and
        $caught.Message -notlike $ExpectedMessageLike) {
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
        throw "Portable .NET SDK closure test '$Name' failed: $($_.Exception.Message)"
    }
}

function Register-TestClosure {
    param([Parameter(Mandatory = $true)]$Closure)

    $script:TrackedClosures.Add($Closure)
    return $Closure
}

function Copy-TestClosureShallow {
    param([Parameter(Mandatory = $true)]$Closure)

    $properties = [ordered]@{}
    foreach ($property in $Closure.PSObject.Properties) {
        $properties[$property.Name] = $property.Value
    }
    return [pscustomobject]$properties
}

function New-TestForgedClosure {
    param([Parameter(Mandatory = $true)]$Scenario)

    return [pscustomobject][ordered]@{
        ClosureType = 'PortableDotNetSdkByteClosure'
        RootPath = $Scenario.Capsule
        Lock = [pscustomobject]@{}
        LockInput = [pscustomobject]@{}
        LockDescriptor = $null
        Files = @()
        InventorySha256 = '0' * 64
        FileCount = 0
        TotalSizeBytes = [int64]0
        Descriptors = @()
        OwnsLockDescriptor = $false
        IsPrivateCopy = $false
        MaximumFileCount = 16384
        MaximumFileBytes = [int64]512MB
        MaximumTotalBytes = [int64]4GB
        Disposed = $false
    }
}

function Get-TestSha256 {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [byte[]]$Bytes
    )

    return [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($Bytes)).ToLowerInvariant()
}

function ConvertTo-TestBytes {
    param([Parameter(Mandatory = $true)][string]$Value)

    return [Text.UTF8Encoding]::new($false, $true).GetBytes($Value)
}

function New-TestScenario {
    param([Parameter(Mandatory = $true)][string]$Name)

    $root = Join-Path $temporaryRoot $Name
    $capsule = Join-Path $root 'capsule'
    [IO.Directory]::CreateDirectory($capsule) | Out-Null
    return [pscustomobject]@{
        Name = $Name
        Root = [IO.Path]::GetFullPath($root)
        Capsule = [IO.Path]::GetFullPath($capsule)
        LockPath = [IO.Path]::GetFullPath((Join-Path $root 'sdk-closure.lock.json'))
    }
}

function Add-TestCapsuleFile {
    param(
        [Parameter(Mandatory = $true)]$Scenario,
        [Parameter(Mandatory = $true)][string]$RelativePath,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [byte[]]$Bytes
    )

    $nativeRelativePath = $RelativePath.Replace(
        '/', [IO.Path]::DirectorySeparatorChar)
    $path = [IO.Path]::GetFullPath((Join-Path $Scenario.Capsule $nativeRelativePath))
    $parent = [IO.Path]::GetDirectoryName($path)
    [IO.Directory]::CreateDirectory($parent) | Out-Null
    $stream = [IO.File]::Open(
        $path,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None)
    try {
        $stream.Write($Bytes, 0, $Bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
    return [pscustomobject]@{
        relativePath = $RelativePath
        sizeBytes = [int64]$Bytes.Length
        sha256 = Get-TestSha256 -Bytes $Bytes
    }
}

function Add-VerbatimTestCapsuleFile {
    param(
        [Parameter(Mandatory = $true)]$Scenario,
        [Parameter(Mandatory = $true)][string]$RelativePath,
        [Parameter(Mandatory = $true)][byte[]]$Bytes
    )

    if ($RelativePath.Contains('/') -or $RelativePath.Contains('\')) {
        throw 'Verbatim-path test helper accepts one leaf name only.'
    }
    $ordinaryPath = $Scenario.Capsule.TrimEnd(
        [IO.Path]::DirectorySeparatorChar) +
        [IO.Path]::DirectorySeparatorChar + $RelativePath
    $verbatimPath = '\\?\' + $ordinaryPath
    [IO.File]::WriteAllBytes($verbatimPath, $Bytes)
    if (-not [IO.File]::Exists($verbatimPath)) {
        throw "Could not create verbatim-path test file '$RelativePath'."
    }
    $script:TrackedVerbatimFiles.Add($verbatimPath)
    return [pscustomobject]@{
        Record = [pscustomobject][ordered]@{
            relativePath = $RelativePath
            sizeBytes = [int64]$Bytes.Length
            sha256 = Get-TestSha256 -Bytes $Bytes
        }
        OrdinaryPath = $ordinaryPath
        VerbatimPath = $verbatimPath
    }
}

function Write-TestLock {
    param(
        [Parameter(Mandatory = $true)]$Scenario,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Files,
        [string]$SdkVersion = $script:SdkVersion,
        [string]$ArchiveUrl = 'https://builds.dotnet.microsoft.com/dotnet/Sdk/10.0.302/dotnet-sdk-10.0.302-win-x64.zip',
        [bool]$OfficialMicrosoft = $true,
        [string]$ArchiveSha512 = ('a' * 128)
    )

    $fileArray = @($Files)
    $inventoryBytes = if ($fileArray.Count -eq 0) {
        [Text.UTF8Encoding]::new($false, $true).GetBytes('[]')
    }
    else {
        ProductionReleaseState\ConvertTo-ProductionJsonBytes -Value $fileArray
    }
    try {
        $inventorySha256 = ProductionReleaseState\Get-ProductionSha256Bytes `
            -Bytes $inventoryBytes
    }
    finally {
        [Array]::Clear($inventoryBytes, 0, $inventoryBytes.Length)
    }
    [int64]$totalSizeBytes = 0
    foreach ($file in $fileArray) {
        $totalSizeBytes += [int64]$file.sizeBytes
    }
    $lock = [pscustomobject][ordered]@{
        contract = 'portable-dotnet-sdk-byte-closure-v1'
        sdkVersion = $SdkVersion
        os = 'windows'
        architecture = 'x64'
        archiveSource = [pscustomobject][ordered]@{
            url = $ArchiveUrl
            officialMicrosoft = $OfficialMicrosoft
        }
        archiveSha512 = $ArchiveSha512
        fileCount = [int]$fileArray.Count
        totalSizeBytes = $totalSizeBytes
        inventorySha256 = $inventorySha256
        files = $fileArray
    }
    $lockBytes = ProductionReleaseState\ConvertTo-ProductionJsonBytes -Value $lock
    try {
        [IO.File]::WriteAllBytes($Scenario.LockPath, $lockBytes)
    }
    finally {
        [Array]::Clear($lockBytes, 0, $lockBytes.Length)
    }
    return $lock
}

function New-TestZipSpecification {
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

function Convert-TestHexUInt32ToInt32 {
    param([Parameter(Mandatory = $true)][string]$Hex)

    $unsigned = [uint32]::Parse(
        $Hex,
        [Globalization.NumberStyles]::HexNumber,
        [Globalization.CultureInfo]::InvariantCulture)
    return [BitConverter]::ToInt32([BitConverter]::GetBytes($unsigned), 0)
}

function Write-TestZipArchive {
    param(
        [Parameter(Mandatory = $true)]$Scenario,
        [Parameter(Mandatory = $true)][object[]]$Entries
    )

    $archivePath = Join-Path `
        $Scenario.Root `
        'dotnet-sdk-10.0.302-win-x64.zip'
    $stream = [IO.FileStream]::new(
        $archivePath,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None)
    $zip = [IO.Compression.ZipArchive]::new(
        $stream,
        [IO.Compression.ZipArchiveMode]::Create,
        $false)
    try {
        foreach ($specification in $Entries) {
            $entry = $zip.CreateEntry(
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
        $zip.Dispose()
    }
    $Scenario | Add-Member `
        -NotePropertyName ArchivePath `
        -NotePropertyValue ([IO.Path]::GetFullPath($archivePath))
    $Scenario | Add-Member `
        -NotePropertyName ArchiveSha512 `
        -NotePropertyValue (
            (Get-FileHash -LiteralPath $archivePath -Algorithm SHA512).
                Hash.ToLowerInvariant())
    $Scenario | Add-Member `
        -NotePropertyName ExtractionPath `
        -NotePropertyValue ([IO.Path]::GetFullPath((
                Join-Path $Scenario.Root 'archive-extraction')))
    return $Scenario
}

function New-ValidTestArchiveScenario {
    param([Parameter(Mandatory = $true)][string]$Name)

    $scenario = New-TestScenario -Name $Name
    $dotnetBytes = ConvertTo-TestBytes -Value 'locked-root-dotnet-executable'
    $sdkBytes = ConvertTo-TestBytes -Value 'locked-sdk-component'
    [void](Write-TestZipArchive `
            -Scenario $scenario `
            -Entries @(
                (New-TestZipSpecification `
                    -Name 'dotnet.exe' `
                    -Bytes $dotnetBytes),
                (New-TestZipSpecification `
                    -Name 'sdk/10.0.302/component.dll' `
                    -Bytes $sdkBytes)))
    $files = @(
        [pscustomobject][ordered]@{
            relativePath = 'dotnet.exe'
            sizeBytes = [int64]$dotnetBytes.Length
            sha256 = Get-TestSha256 -Bytes $dotnetBytes
        },
        [pscustomobject][ordered]@{
            relativePath = 'sdk/10.0.302/component.dll'
            sizeBytes = [int64]$sdkBytes.Length
            sha256 = Get-TestSha256 -Bytes $sdkBytes
        })
    [void](Write-TestLock `
            -Scenario $scenario `
            -Files $files `
            -ArchiveSha512 $scenario.ArchiveSha512)
    $scenario | Add-Member -NotePropertyName Files -NotePropertyValue $files
    return $scenario
}

function New-TestArchiveScenario {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][object[]]$Entries,
        [Parameter(Mandatory = $true)][object[]]$LockFiles
    )

    $scenario = New-TestScenario -Name $Name
    [void](Write-TestZipArchive -Scenario $scenario -Entries $Entries)
    [void](Write-TestLock `
            -Scenario $scenario `
            -Files $LockFiles `
            -ArchiveSha512 $scenario.ArchiveSha512)
    $scenario | Add-Member -NotePropertyName Files -NotePropertyValue $LockFiles
    return $scenario
}

function Open-TestArchiveScenario {
    param(
        [Parameter(Mandatory = $true)]$Scenario,
        [int]$MaximumArchiveEntryCount = 32768,
        [int64]$MaximumArchiveBytes = 4GB,
        [int]$MaximumFileCount = 16384,
        [int64]$MaximumFileBytes = 512MB,
        [int64]$MaximumTotalBytes = 4GB
    )

    return Open-PortableDotNetSdkArchiveClosure `
        -ArchivePath $Scenario.ArchivePath `
        -LockPath $Scenario.LockPath `
        -ExtractionDirectory $Scenario.ExtractionPath `
        -ExpectedSdkVersion $script:SdkVersion `
        -MaximumArchiveEntryCount $MaximumArchiveEntryCount `
        -MaximumArchiveBytes $MaximumArchiveBytes `
        -MaximumFileCount $MaximumFileCount `
        -MaximumFileBytes $MaximumFileBytes `
        -MaximumTotalBytes $MaximumTotalBytes
}

function New-ValidTestScenario {
    param([Parameter(Mandatory = $true)][string]$Name)

    $scenario = New-TestScenario -Name $Name
    $files = @(
        Add-TestCapsuleFile `
            -Scenario $scenario `
            -RelativePath 'bin/dotnet.exe' `
            -Bytes (ConvertTo-TestBytes -Value 'not-a-real-dotnet-executable')
        Add-TestCapsuleFile `
            -Scenario $scenario `
            -RelativePath 'shared/Microsoft.NETCore.App.dll' `
            -Bytes (ConvertTo-TestBytes -Value 'small-test-runtime-payload')
    )
    [void](Write-TestLock -Scenario $scenario -Files $files)
    $largest = [int64](
        $files | Measure-Object -Property sizeBytes -Maximum).Maximum
    $total = [int64](
        $files | Measure-Object -Property sizeBytes -Sum).Sum
    $scenario | Add-Member -NotePropertyName Files -NotePropertyValue $files
    $scenario | Add-Member -NotePropertyName LargestFileBytes -NotePropertyValue $largest
    $scenario | Add-Member -NotePropertyName TotalSizeBytes -NotePropertyValue $total
    return $scenario
}

function Open-TestScenario {
    param(
        [Parameter(Mandatory = $true)]$Scenario,
        [int]$MaximumFileCount = 16384,
        [int64]$MaximumFileBytes = 512MB,
        [int64]$MaximumTotalBytes = 4GB
    )

    return Open-PortableDotNetSdkClosure `
        -CapsuleDirectory $Scenario.Capsule `
        -LockPath $Scenario.LockPath `
        -ExpectedSdkVersion $script:SdkVersion `
        -MaximumFileCount $MaximumFileCount `
        -MaximumFileBytes $MaximumFileBytes `
        -MaximumTotalBytes $MaximumTotalBytes
}

function Assert-NoProductionAdmissionClaim {
    param([Parameter(Mandatory = $true)]$Value)

    $forbiddenProperties = @(
        'Admission', 'Go', 'ProductionAdmission', 'ProductionGo', 'ReadyForProduction')
    foreach ($name in $forbiddenProperties) {
        Assert-TestTrue `
            -Condition ($null -eq $Value.PSObject.Properties[$name]) `
            -Label "closure does not expose a production-admission property '$name'"
    }
}

try {
    Invoke-TestCase -Name 'verified ZIP to self-contained private toolchain' -Body {
        $scenario = New-ValidTestArchiveScenario -Name 'archive-positive'
        [int64]$totalBytes = (
            $scenario.Files | Measure-Object -Property sizeBytes -Sum).Sum
        [int64]$largestBytes = (
            $scenario.Files | Measure-Object -Property sizeBytes -Maximum).Maximum
        $source = Register-TestClosure -Closure (
            Open-TestArchiveScenario `
                -Scenario $scenario `
                -MaximumArchiveEntryCount 2 `
                -MaximumFileCount 2 `
                -MaximumFileBytes $largestBytes `
                -MaximumTotalBytes $totalBytes)
        Assert-TestTrue -Condition ([IO.Directory]::Exists($scenario.ExtractionPath)) `
            -Label 'verified ZIP creates its extraction root'
        foreach ($file in $scenario.Files) {
            $path = Join-Path `
                $scenario.ExtractionPath `
                ([string]$file.relativePath).Replace('/', '\')
            Assert-TestTrue -Condition ([IO.File]::Exists($path)) `
                -Label "verified ZIP extracts '$($file.relativePath)'"
            Assert-TestTrue -Condition (
                (Get-TestSha256 -Bytes ([IO.File]::ReadAllBytes($path))) -ceq
                    [string]$file.sha256) `
                -Label "extracted '$($file.relativePath)' bytes match the lock"
        }
        Assert-TestTrue -Condition (
            Assert-PortableDotNetSdkClosureUnchanged -Closure $source) `
            -Label 'original ZIP and extracted source remain locked and unchanged'
        [void](Assert-TestThrows `
                -Label 'archive source closure cannot be used directly as a toolchain' `
                -ExpectedMessageLike '*self-contained private-copy*' `
                -Body { Get-PortableDotNetSdkPrivateToolchain -Closure $source })
        [void](Assert-TestThrows `
                -Label 'locked original ZIP cannot be opened for writing' `
                -Body {
                    [IO.File]::Open(
                        $scenario.ArchivePath,
                        [IO.FileMode]::Open,
                        [IO.FileAccess]::Write,
                        [IO.FileShare]::Read).Dispose()
                })
        [void](Assert-TestThrows `
                -Label 'locked original ZIP cannot be deleted' `
                -Body { [IO.File]::Delete($scenario.ArchivePath) })

        $privatePath = Join-Path $scenario.Root 'private-toolchain'
        $private = Register-TestClosure -Closure (
            New-PortableDotNetSdkPrivateCopy `
                -SourceClosure $source `
                -DestinationDirectory $privatePath)
        $expectedDotnetPath = [IO.Path]::GetFullPath((
                Join-Path $privatePath 'dotnet.exe'))
        $expectedLockSha256 = (
            Get-FileHash -LiteralPath $scenario.LockPath -Algorithm SHA256).
                Hash.ToLowerInvariant()

        $private.RootPath = 'C:\forged-public-root'
        $private.InventorySha256 = '0' * 64
        $private.FileCount = 999
        $private.TotalSizeBytes = [int64]999
        $private.IsPrivateCopy = $false
        $private.Disposed = $true
        $toolchain = Get-PortableDotNetSdkPrivateToolchain -Closure $private
        Assert-TestTrue -Condition (
            [string]$toolchain.RootPath -ceq [IO.Path]::GetFullPath($privatePath)) `
            -Label 'toolchain root comes from the private record, not public properties'
        Assert-TestTrue -Condition (
            [string]$toolchain.DotnetPath -ceq $expectedDotnetPath) `
            -Label 'dotnet executable comes from the private descriptor'
        Assert-TestTrue -Condition ([IO.File]::Exists($toolchain.DotnetPath)) `
            -Label 'private-record dotnet executable exists'
        Assert-TestTrue -Condition (
            [string]$toolchain.LockSha256 -ceq $expectedLockSha256) `
            -Label 'toolchain exposes the independently locked reviewed-lock digest'
        Assert-TestTrue -Condition (
            [string]$toolchain.ArchiveSha512 -ceq $scenario.ArchiveSha512) `
            -Label 'toolchain exposes the verified original-ZIP SHA-512'
        Assert-TestTrue -Condition (
            [string]$toolchain.ArchiveBindingStatus -ceq
                'ZIP_SHA512_AND_FILE_INVENTORY_VERIFIED') `
            -Label 'toolchain requires explicit original-ZIP byte binding'
        Assert-TestTrue -Condition (
            Assert-PortableDotNetSdkClosureUnchanged -Closure $private) `
            -Label 'public-property forgery cannot affect private closure validation'
        Assert-NoProductionAdmissionClaim -Value $toolchain

        $shallow = Copy-TestClosureShallow -Closure $private
        [void](Assert-TestThrows `
                -Label 'toolchain getter rejects a shallow-cloned handle' `
                -ExpectedMessageLike '*authentic*' `
                -Body { Get-PortableDotNetSdkPrivateToolchain -Closure $shallow })

        Close-PortableDotNetSdkClosure -Closure $source
        Assert-TestTrue -Condition (
            [string](Get-PortableDotNetSdkPrivateToolchain -Closure $private).
                DotnetPath -ceq $expectedDotnetPath) `
            -Label 'private toolchain remains self-contained after source closure closes'
        [void](Assert-TestThrows `
                -Label 'private toolchain independently keeps the reviewed lock immutable' `
                -Body {
                    [IO.File]::Open(
                        $scenario.LockPath,
                        [IO.FileMode]::Open,
                        [IO.FileAccess]::Write,
                        [IO.FileShare]::Read).Dispose()
                })
        $archiveProbe = [IO.File]::Open(
            $scenario.ArchivePath,
            [IO.FileMode]::Open,
            [IO.FileAccess]::ReadWrite,
            [IO.FileShare]::None)
        $archiveProbe.Dispose()

        Close-PortableDotNetSdkClosure -Closure $private
        Assert-TestTrue -Condition ([IO.Directory]::Exists($privatePath)) `
            -Label 'closing a private toolchain does not delete caller-owned bytes'
        Assert-TestTrue -Condition ([IO.Directory]::Exists($scenario.ExtractionPath)) `
            -Label 'closing an archive closure does not delete extracted bytes'
        [void](Assert-TestThrows `
                -Label 'disposed private toolchain cannot be retrieved' `
                -ExpectedMessageLike '*already disposed*' `
                -Body { Get-PortableDotNetSdkPrivateToolchain -Closure $private })
        $lockProbe = [IO.File]::Open(
            $scenario.LockPath,
            [IO.FileMode]::Open,
            [IO.FileAccess]::ReadWrite,
            [IO.FileShare]::None)
        $lockProbe.Dispose()
    }

    Invoke-TestCase -Name 'directory-only private copy is not ZIP-bound' -Body {
        $scenario = New-ValidTestScenario -Name 'lock-only-toolchain'
        $source = Register-TestClosure -Closure (
            Open-TestScenario -Scenario $scenario)
        $private = Register-TestClosure -Closure (
            New-PortableDotNetSdkPrivateCopy `
                -SourceClosure $source `
                -DestinationDirectory (
                    Join-Path $scenario.Root 'lock-only-private-copy'))
        [void](Assert-TestThrows `
                -Label 'directory-only private copy cannot become a production toolchain' `
                -ExpectedMessageLike '*verified original-ZIP byte closure*' `
                -Body { Get-PortableDotNetSdkPrivateToolchain -Closure $private })
        Close-PortableDotNetSdkClosure -Closure $private
        Close-PortableDotNetSdkClosure -Closure $source
    }

    Invoke-TestCase -Name 'archive and reviewed-lock mismatches fail before extraction' -Body {
        $wrongArchive = New-ValidTestArchiveScenario -Name 'archive-wrong-sha512'
        [void](Write-TestLock `
                -Scenario $wrongArchive `
                -Files $wrongArchive.Files `
                -ArchiveSha512 ('f' * 128))
        [void](Assert-TestThrows `
                -Label 'wrong original-ZIP SHA-512 is rejected' `
                -ExpectedMessageLike '*ZIP SHA-512 differs*' `
                -Body { Open-TestArchiveScenario -Scenario $wrongArchive })
        Assert-TestTrue -Condition (
            -not [IO.Directory]::Exists($wrongArchive.ExtractionPath)) `
            -Label 'wrong ZIP SHA-512 creates no extraction directory'

        $wrongInventory = New-ValidTestArchiveScenario `
            -Name 'archive-wrong-inventory'
        $forgedFiles = @(
            foreach ($file in $wrongInventory.Files) {
                [pscustomobject][ordered]@{
                    relativePath = [string]$file.relativePath
                    sizeBytes = [int64]$file.sizeBytes
                    sha256 = if ([string]$file.relativePath -ceq 'dotnet.exe') {
                        '0' * 64
                    }
                    else {
                        [string]$file.sha256
                    }
                }
            })
        [void](Write-TestLock `
                -Scenario $wrongInventory `
                -Files $forgedFiles `
                -ArchiveSha512 $wrongInventory.ArchiveSha512)
        [void](Assert-TestThrows `
                -Label 'matching ZIP digest cannot conceal a forged file inventory' `
                -ExpectedMessageLike '*file inventory differs*' `
                -Body { Open-TestArchiveScenario -Scenario $wrongInventory })
        Assert-TestTrue -Condition (
            -not [IO.Directory]::Exists($wrongInventory.ExtractionPath)) `
            -Label 'forged inventory creates no extraction directory'
    }

    Invoke-TestCase -Name 'hostile ZIP namespaces fail before extraction' -Body {
        $payload = ConvertTo-TestBytes -Value 'hostile-zip-entry'
        $lockFiles = @([pscustomobject][ordered]@{
                relativePath = 'dotnet.exe'
                sizeBytes = [int64]$payload.Length
                sha256 = Get-TestSha256 -Bytes $payload
            })
        $symlinkAttributes = Convert-TestHexUInt32ToInt32 -Hex 'A1FF0000'
        $dosReparseAttributes = Convert-TestHexUInt32ToInt32 -Hex '00000400'
        $attacks = @(
            [pscustomobject]@{
                Name = 'zip-traversal'
                Entries = @(
                    (New-TestZipSpecification -Name '../escape.dll' -Bytes $payload))
                ExpectedMessageLike = '*reserved Windows path segment*'
            },
            [pscustomobject]@{
                Name = 'zip-backslash'
                Entries = @(
                    (New-TestZipSpecification -Name 'bin\evil.dll' -Bytes $payload))
                ExpectedMessageLike = '*ZIP entry path is unsafe*'
            },
            [pscustomobject]@{
                Name = 'zip-alternate-data-stream'
                Entries = @(
                    (New-TestZipSpecification -Name 'bin/evil:ads' -Bytes $payload))
                ExpectedMessageLike =
                    '*ZIP entry path is not one canonical Windows relative path*'
            },
            [pscustomobject]@{
                Name = 'zip-case-collision'
                Entries = @(
                    (New-TestZipSpecification -Name 'dotnet.exe' -Bytes $payload),
                    (New-TestZipSpecification -Name 'DOTNET.exe' -Bytes $payload))
                ExpectedMessageLike = '*duplicate or case-colliding entry*'
            },
            [pscustomobject]@{
                Name = 'zip-symlink'
                Entries = @(
                    (New-TestZipSpecification `
                        -Name 'dotnet.exe' `
                        -Bytes $payload `
                        -ExternalAttributes $symlinkAttributes))
                ExpectedMessageLike = '*symbolic link or reparse point*'
            },
            [pscustomobject]@{
                Name = 'zip-dos-reparse-point'
                Entries = @(
                    (New-TestZipSpecification `
                        -Name 'dotnet.exe' `
                        -Bytes $payload `
                        -ExternalAttributes $dosReparseAttributes))
                ExpectedMessageLike = '*symbolic link or reparse point*'
            },
            [pscustomobject]@{
                Name = 'zip-file-directory-conflict'
                Entries = @(
                    (New-TestZipSpecification -Name 'sdk' -Bytes $payload),
                    (New-TestZipSpecification `
                        -Name 'sdk/component.dll' `
                        -Bytes $payload))
                ExpectedMessageLike = '*descends through a file path*'
            },
            [pscustomobject]@{
                Name = 'zip-reserved-device-name'
                Entries = @(
                    (New-TestZipSpecification -Name 'CON' -Bytes $payload))
                ExpectedMessageLike = '*reserved Windows path segment*'
            })
        foreach ($attack in $attacks) {
            $scenario = New-TestArchiveScenario `
                -Name ([string]$attack.Name) `
                -Entries @($attack.Entries) `
                -LockFiles $lockFiles
            [void](Assert-TestThrows `
                    -Label "hostile ZIP '$($attack.Name)' is rejected" `
                    -ExpectedMessageLike ([string]$attack.ExpectedMessageLike) `
                    -Body { Open-TestArchiveScenario -Scenario $scenario })
            Assert-TestTrue -Condition (
                -not [IO.Directory]::Exists($scenario.ExtractionPath)) `
                -Label "hostile ZIP '$($attack.Name)' creates no extraction root"
            Assert-TestTrue -Condition (
                -not [IO.File]::Exists((Join-Path $scenario.Root 'escape.dll'))) `
                -Label "hostile ZIP '$($attack.Name)' writes no traversal target"
        }
    }

    Invoke-TestCase -Name 'archive bounds and create-only destination fail closed' -Body {
        $entryBound = New-ValidTestArchiveScenario -Name 'archive-entry-bound'
        [void](Assert-TestThrows `
                -Label 'archive entry-count bound is enforced' `
                -ExpectedMessageLike '*entry count*' `
                -Body {
                    Open-TestArchiveScenario `
                        -Scenario $entryBound `
                        -MaximumArchiveEntryCount 1
                })
        Assert-TestTrue -Condition (
            -not [IO.Directory]::Exists($entryBound.ExtractionPath)) `
            -Label 'entry-count rejection creates no extraction directory'

        $byteBound = New-ValidTestArchiveScenario -Name 'archive-byte-bound'
        $archiveLength = (Get-Item -LiteralPath $byteBound.ArchivePath).Length
        [void](Assert-TestThrows `
                -Label 'compressed archive byte bound is enforced' `
                -ExpectedMessageLike '*exceeds its byte bound*' `
                -Body {
                    Open-TestArchiveScenario `
                        -Scenario $byteBound `
                        -MaximumArchiveBytes ($archiveLength - 1)
                })
        Assert-TestTrue -Condition (
            -not [IO.Directory]::Exists($byteBound.ExtractionPath)) `
            -Label 'archive-byte rejection creates no extraction directory'

        $entryPayload = ConvertTo-TestBytes `
            -Value 'expanded-entry-exceeds-reviewed-byte-bound'
        $entryLockPayload = ConvertTo-TestBytes -Value 'lock'
        $expandedEntryBound = New-TestArchiveScenario `
            -Name 'archive-expanded-entry-bound' `
            -Entries @(
                (New-TestZipSpecification `
                    -Name 'oversized-component.dll' `
                    -Bytes $entryPayload)) `
            -LockFiles @(
                [pscustomobject][ordered]@{
                    relativePath = 'dotnet.exe'
                    sizeBytes = [int64]$entryLockPayload.Length
                    sha256 = Get-TestSha256 -Bytes $entryLockPayload
                })
        $entryByteBound = [int64]$entryPayload.Length - 1
        Assert-TestTrue -Condition (
            [int64]$entryLockPayload.Length -le $entryByteBound) `
            -Label 'entry-bound lock fixture remains within the tested limit'
        [void](Assert-TestThrows `
                -Label 'expanded ZIP entry byte bound is enforced before inventory comparison' `
                -ExpectedMessageLike '*ZIP file exceeds its byte bound*' `
                -Body {
                    Open-TestArchiveScenario `
                        -Scenario $expandedEntryBound `
                        -MaximumFileBytes $entryByteBound
                })
        Assert-TestTrue -Condition (
            -not [IO.Directory]::Exists($expandedEntryBound.ExtractionPath)) `
            -Label 'expanded-entry rejection creates no extraction directory'

        $aggregatePartA = ConvertTo-TestBytes -Value 'aggregate-A'
        $aggregatePartB = ConvertTo-TestBytes -Value 'aggregate-B'
        $aggregateLockPayload = ConvertTo-TestBytes -Value 'lock-total'
        $expandedTotalBound = New-TestArchiveScenario `
            -Name 'archive-expanded-total-bound' `
            -Entries @(
                (New-TestZipSpecification `
                    -Name 'component-a.dll' `
                    -Bytes $aggregatePartA),
                (New-TestZipSpecification `
                    -Name 'component-b.dll' `
                    -Bytes $aggregatePartB)) `
            -LockFiles @(
                [pscustomobject][ordered]@{
                    relativePath = 'dotnet.exe'
                    sizeBytes = [int64]$aggregateLockPayload.Length
                    sha256 = Get-TestSha256 -Bytes $aggregateLockPayload
                })
        $aggregateByteBound = [int64]$aggregatePartA.Length + 1
        Assert-TestTrue -Condition (
            [int64]$aggregateLockPayload.Length -le $aggregateByteBound -and
            [int64]$aggregatePartA.Length -le $aggregateByteBound -and
            [int64]$aggregatePartB.Length -le $aggregateByteBound -and
            ([int64]$aggregatePartA.Length + [int64]$aggregatePartB.Length) -gt
                $aggregateByteBound) `
            -Label 'aggregate-bound fixture isolates the expanded total-byte limit'
        [void](Assert-TestThrows `
                -Label 'expanded ZIP aggregate byte bound is enforced before inventory comparison' `
                -ExpectedMessageLike '*expands beyond its total byte bound*' `
                -Body {
                    Open-TestArchiveScenario `
                        -Scenario $expandedTotalBound `
                        -MaximumFileBytes $aggregateByteBound `
                        -MaximumTotalBytes $aggregateByteBound
                })
        Assert-TestTrue -Condition (
            -not [IO.Directory]::Exists($expandedTotalBound.ExtractionPath)) `
            -Label 'expanded-total rejection creates no extraction directory'

        $existing = New-ValidTestArchiveScenario `
            -Name 'archive-existing-destination'
        [IO.Directory]::CreateDirectory($existing.ExtractionPath) | Out-Null
        $sentinelPath = Join-Path $existing.ExtractionPath 'owner-sentinel.txt'
        $sentinelBytes = ConvertTo-TestBytes -Value 'preserve-existing-owner-data'
        [IO.File]::WriteAllBytes($sentinelPath, $sentinelBytes)
        [void](Assert-TestThrows `
                -Label 'existing extraction root is rejected create-only' `
                -ExpectedMessageLike '*atomically create*' `
                -Body { Open-TestArchiveScenario -Scenario $existing })
        Assert-TestTrue -Condition ([IO.File]::Exists($sentinelPath)) `
            -Label 'existing extraction sentinel remains present'
        Assert-TestTrue -Condition (
            (Get-TestSha256 -Bytes ([IO.File]::ReadAllBytes($sentinelPath))) -ceq
                (Get-TestSha256 -Bytes $sentinelBytes)) `
            -Label 'existing extraction sentinel remains byte-exact'
        Assert-TestTrue -Condition (
            @(Get-ChildItem -LiteralPath $existing.ExtractionPath -Force).Count -eq 1) `
            -Label 'create-only rejection writes nothing into an existing directory'
    }

    Invoke-TestCase -Name 'positive source closure and private copy' -Body {
        $scenario = New-ValidTestScenario -Name 'positive'
        $source = Register-TestClosure -Closure (Open-TestScenario `
                -Scenario $scenario `
                -MaximumFileCount $scenario.Files.Count `
                -MaximumFileBytes $scenario.LargestFileBytes `
                -MaximumTotalBytes $scenario.TotalSizeBytes)
        Assert-TestTrue -Condition (-not [bool]$source.IsPrivateCopy) `
            -Label 'source closure is not a private copy'
        Assert-TestTrue -Condition ([int]$source.FileCount -eq 2) `
            -Label 'source closure admits the exact file count'
        Assert-TestTrue -Condition (
            [int64]$source.TotalSizeBytes -eq $scenario.TotalSizeBytes) `
            -Label 'source closure admits the exact total byte count'
        Assert-TestTrue -Condition (
            Assert-PortableDotNetSdkClosureUnchanged -Closure $source) `
            -Label 'source closure is unchanged immediately after admission'
        Assert-NoProductionAdmissionClaim -Value $source

        $copyPath = Join-Path $scenario.Root 'private-copy'
        $private = Register-TestClosure -Closure (
            New-PortableDotNetSdkPrivateCopy `
                -SourceClosure $source `
                -DestinationDirectory $copyPath)
        Assert-TestTrue -Condition ([bool]$private.IsPrivateCopy) `
            -Label 'private-copy closure is marked as a private copy'
        Assert-TestTrue -Condition (
            [string]$private.InventorySha256 -ceq [string]$source.InventorySha256) `
            -Label 'private copy preserves the source inventory digest'
        Assert-TestTrue -Condition (
            Assert-PortableDotNetSdkClosureUnchanged -Closure $private) `
            -Label 'private-copy closure is unchanged immediately after creation'
        Assert-NoProductionAdmissionClaim -Value $private

        Close-PortableDotNetSdkClosure -Closure $private
        Assert-TestTrue -Condition ([IO.Directory]::Exists($copyPath)) `
            -Label 'closing a private copy does not claim ownership of its directory'
        Assert-TestTrue -Condition ([bool]$private.Disposed) `
            -Label 'closing a private copy disposes its closure'
        Close-PortableDotNetSdkClosure -Closure $source
        Close-PortableDotNetSdkClosure -Closure $source
        Assert-TestTrue -Condition ([bool]$source.Disposed) `
            -Label 'source closure close is idempotent'
        [void](Assert-TestThrows `
                -Label 'disposed closure cannot be asserted unchanged' `
                -ExpectedMessageLike '*already disposed*' `
                -Body {
                    Assert-PortableDotNetSdkClosureUnchanged -Closure $source
                })
    }

    Invoke-TestCase -Name 'forged and shallow-cloned closures are rejected' -Body {
        $scenario = New-ValidTestScenario -Name 'closure-authenticity'
        $source = Register-TestClosure -Closure (
            Open-TestScenario -Scenario $scenario)

        $forged = New-TestForgedClosure -Scenario $scenario
        [void](Assert-TestThrows `
                -Label 'Assert rejects a forged closure before field traversal' `
                -ExpectedMessageLike '*authentic*' `
                -Body {
                    Assert-PortableDotNetSdkClosureUnchanged -Closure $forged
                })
        Assert-TestTrue -Condition (-not [bool]$forged.Disposed) `
            -Label 'failed forged Assert does not mutate the forged object'
        $forgedDestination = Join-Path $scenario.Root 'forged-private-copy'
        [void](Assert-TestThrows `
                -Label 'NewPrivateCopy rejects a forged source closure' `
                -ExpectedMessageLike '*authentic*' `
                -Body {
                    New-PortableDotNetSdkPrivateCopy `
                        -SourceClosure $forged `
                        -DestinationDirectory $forgedDestination
                })
        Assert-TestTrue -Condition (
            -not [IO.Directory]::Exists($forgedDestination)) `
            -Label 'forged source cannot create a private-copy destination'
        [void](Assert-TestThrows `
                -Label 'Close rejects a forged closure' `
                -ExpectedMessageLike '*authentic*' `
                -Body {
                    Close-PortableDotNetSdkClosure -Closure $forged
                })
        Assert-TestTrue -Condition (-not [bool]$forged.Disposed) `
            -Label 'failed forged Close does not mark the object disposed'

        $shallow = Copy-TestClosureShallow -Closure $source
        [void](Assert-TestThrows `
                -Label 'Assert rejects a shallow clone with genuine descriptor references' `
                -ExpectedMessageLike '*authentic*' `
                -Body {
                    Assert-PortableDotNetSdkClosureUnchanged -Closure $shallow
                })
        $shallowDestination = Join-Path $scenario.Root 'shallow-private-copy'
        [void](Assert-TestThrows `
                -Label 'NewPrivateCopy rejects a shallow-cloned source closure' `
                -ExpectedMessageLike '*authentic*' `
                -Body {
                    New-PortableDotNetSdkPrivateCopy `
                        -SourceClosure $shallow `
                        -DestinationDirectory $shallowDestination
                })
        Assert-TestTrue -Condition (
            -not [IO.Directory]::Exists($shallowDestination)) `
            -Label 'shallow clone cannot create a private-copy destination'
        [void](Assert-TestThrows `
                -Label 'Close rejects a shallow clone before disposing shared streams' `
                -ExpectedMessageLike '*authentic*' `
                -Body {
                    Close-PortableDotNetSdkClosure -Closure $shallow
                })
        Assert-TestTrue -Condition (-not [bool]$source.Disposed) `
            -Label 'shallow-clone Close cannot dispose the authentic closure'
        Assert-TestTrue -Condition (
            Assert-PortableDotNetSdkClosureUnchanged -Closure $source) `
            -Label 'authentic source survives all forged and shallow-clone calls'
        Close-PortableDotNetSdkClosure -Closure $source
    }

    Invoke-TestCase -Name 'missing capsule file' -Body {
        $scenario = New-ValidTestScenario -Name 'missing-file'
        $missingPath = Join-Path $scenario.Capsule 'shared/Microsoft.NETCore.App.dll'
        [IO.File]::Delete($missingPath)
        [void](Assert-TestThrows `
                -Label 'missing file is rejected' `
                -ExpectedMessageLike '*inventory differs from its lock*' `
                -Body { Open-TestScenario -Scenario $scenario })
    }

    Invoke-TestCase -Name 'extra capsule file' -Body {
        $scenario = New-ValidTestScenario -Name 'extra-file'
        [IO.File]::WriteAllBytes(
            (Join-Path $scenario.Capsule 'unexpected.dll'),
            (ConvertTo-TestBytes -Value 'unexpected'))
        [void](Assert-TestThrows `
                -Label 'extra file is rejected' `
                -ExpectedMessageLike '*inventory differs from its lock*' `
                -Body { Open-TestScenario -Scenario $scenario })
    }

    Invoke-TestCase -Name 'case-insensitive lock collision' -Body {
        $scenario = New-TestScenario -Name 'case-collision'
        $payload = ConvertTo-TestBytes -Value 'collision'
        [void](Add-TestCapsuleFile `
                -Scenario $scenario `
                -RelativePath 'bin/tool.dll' `
                -Bytes $payload)
        $digest = Get-TestSha256 -Bytes $payload
        $files = @(
            [pscustomobject][ordered]@{
                relativePath = 'bin/tool.dll'
                sizeBytes = [int64]$payload.Length
                sha256 = $digest
            }
            [pscustomobject][ordered]@{
                relativePath = 'BIN/TOOL.DLL'
                sizeBytes = [int64]$payload.Length
                sha256 = $digest
            }
        )
        [void](Write-TestLock -Scenario $scenario -Files $files)
        [void](Assert-TestThrows `
                -Label 'case-insensitive duplicate lock paths are rejected' `
                -ExpectedMessageLike '*unsafe, duplicated, unsorted, or out of bounds*' `
                -Body { Open-TestScenario -Scenario $scenario })
    }

    Invoke-TestCase -Name 'capsule content tamper before admission' -Body {
        $scenario = New-ValidTestScenario -Name 'content-tamper'
        $path = Join-Path $scenario.Capsule 'bin/dotnet.exe'
        $bytes = [IO.File]::ReadAllBytes($path)
        $bytes[0] = $bytes[0] -bxor 0x7f
        [IO.File]::WriteAllBytes($path, $bytes)
        [void](Assert-TestThrows `
                -Label 'same-length content tamper is rejected' `
                -ExpectedMessageLike '*differs from its lock*' `
                -Body { Open-TestScenario -Scenario $scenario })
    }

    Invoke-TestCase -Name 'source changes after admission' -Body {
        $scenario = New-ValidTestScenario -Name 'source-change'
        $source = Register-TestClosure -Closure (
            Open-TestScenario -Scenario $scenario)
        $extraPath = Join-Path $scenario.Capsule 'added-after-admission.dll'
        [IO.File]::WriteAllBytes(
            $extraPath,
            (ConvertTo-TestBytes -Value 'namespace-change'))
        [void](Assert-TestThrows `
                -Label 'source namespace mutation is detected' `
                -ExpectedMessageLike '*file count changed after admission*' `
                -Body {
                    Assert-PortableDotNetSdkClosureUnchanged -Closure $source
                })
        [IO.File]::Delete($extraPath)

        $sourcePath = Join-Path $scenario.Capsule 'bin/dotnet.exe'
        [void](Assert-TestThrows `
                -Label 'admitted source bytes remain locked against writers' `
                -Body {
                    $writer = [IO.File]::Open(
                        $sourcePath,
                        [IO.FileMode]::Open,
                        [IO.FileAccess]::Write,
                        [IO.FileShare]::Read)
                    try {
                        $writer.WriteByte(0x41)
                    }
                    finally {
                        $writer.Dispose()
                    }
                })
        [void](Assert-TestThrows `
                -Label 'admitted lock bytes remain locked against writers' `
                -Body {
                    $writer = [IO.File]::Open(
                        $scenario.LockPath,
                        [IO.FileMode]::Open,
                        [IO.FileAccess]::Write,
                        [IO.FileShare]::Read)
                    try {
                        $writer.WriteByte(0x41)
                    }
                    finally {
                        $writer.Dispose()
                    }
                })
        Assert-TestTrue -Condition (
            Assert-PortableDotNetSdkClosureUnchanged -Closure $source) `
            -Label 'source closure remains valid after blocked mutation attempts'
        Close-PortableDotNetSdkClosure -Closure $source
    }

    Invoke-TestCase -Name 'private-copy changes after creation' -Body {
        $scenario = New-ValidTestScenario -Name 'private-change'
        $source = Register-TestClosure -Closure (
            Open-TestScenario -Scenario $scenario)
        $private = Register-TestClosure -Closure (
            New-PortableDotNetSdkPrivateCopy `
                -SourceClosure $source `
                -DestinationDirectory (Join-Path $scenario.Root 'private-copy'))
        $extraPath = Join-Path $private.RootPath 'added-after-copy.dll'
        [IO.File]::WriteAllBytes(
            $extraPath,
            (ConvertTo-TestBytes -Value 'namespace-change'))
        [void](Assert-TestThrows `
                -Label 'private-copy namespace mutation is detected' `
                -ExpectedMessageLike '*file count changed after admission*' `
                -Body {
                    Assert-PortableDotNetSdkClosureUnchanged -Closure $private
                })
        [IO.File]::Delete($extraPath)

        $privatePath = Join-Path $private.RootPath 'bin/dotnet.exe'
        [void](Assert-TestThrows `
                -Label 'private-copy bytes remain locked against writers' `
                -Body {
                    $writer = [IO.File]::Open(
                        $privatePath,
                        [IO.FileMode]::Open,
                        [IO.FileAccess]::Write,
                        [IO.FileShare]::Read)
                    try {
                        $writer.WriteByte(0x42)
                    }
                    finally {
                        $writer.Dispose()
                    }
                })
        Assert-TestTrue -Condition (
            Assert-PortableDotNetSdkClosureUnchanged -Closure $private) `
            -Label 'private-copy closure remains valid after blocked mutation attempt'
        Close-PortableDotNetSdkClosure -Closure $private
        Assert-TestTrue -Condition ([IO.Directory]::Exists($private.RootPath)) `
            -Label 'private-copy bytes remain for the test-owned parent cleanup'
        Close-PortableDotNetSdkClosure -Closure $source
    }

    Invoke-TestCase -Name 'file and aggregate boundaries' -Body {
        $scenario = New-ValidTestScenario -Name 'boundaries'
        [void](Assert-TestThrows `
                -Label 'file count below the lock count is rejected' `
                -Body {
                    Open-TestScenario -Scenario $scenario -MaximumFileCount 1
                })
        [void](Assert-TestThrows `
                -Label 'file byte bound below the largest file is rejected' `
                -Body {
                    Open-TestScenario `
                        -Scenario $scenario `
                        -MaximumFileBytes ($scenario.LargestFileBytes - 1)
                })
        [void](Assert-TestThrows `
                -Label 'aggregate byte bound below the exact total is rejected' `
                -Body {
                    Open-TestScenario `
                        -Scenario $scenario `
                        -MaximumTotalBytes ($scenario.TotalSizeBytes - 1)
                })
        [void](Assert-TestThrows `
                -Label 'zero file-count parameter is rejected' `
                -Body {
                    Open-TestScenario -Scenario $scenario -MaximumFileCount 0
                })
        [void](Assert-TestThrows `
                -Label 'zero per-file byte parameter is rejected' `
                -Body {
                    Open-TestScenario -Scenario $scenario -MaximumFileBytes 0
                })
        [void](Assert-TestThrows `
                -Label 'zero total byte parameter is rejected' `
                -Body {
                    Open-TestScenario -Scenario $scenario -MaximumTotalBytes 0
                })

        $empty = New-TestScenario -Name 'empty-boundary'
        [void](Write-TestLock -Scenario $empty -Files @())
        [void](Assert-TestThrows `
                -Label 'empty closure inventory is rejected' `
                -Body { Open-TestScenario -Scenario $empty })

        $zero = New-TestScenario -Name 'zero-total-boundary'
        $zeroRecord = Add-TestCapsuleFile `
            -Scenario $zero `
            -RelativePath 'zero.bin' `
            -Bytes ([byte[]]::new(0))
        [void](Write-TestLock -Scenario $zero -Files @($zeroRecord))
        [void](Assert-TestThrows `
                -Label 'zero-total closure inventory is rejected' `
                -Body { Open-TestScenario -Scenario $zero })
    }

    Invoke-TestCase -Name 'create-only destination preserves existing sentinel' -Body {
        $scenario = New-ValidTestScenario -Name 'existing-destination-sentinel'
        $source = Register-TestClosure -Closure (
            Open-TestScenario -Scenario $scenario)
        $destination = Join-Path $scenario.Root 'already-exists'
        [IO.Directory]::CreateDirectory($destination) | Out-Null
        $sentinelPath = Join-Path $destination 'owner-sentinel.txt'
        $sentinelBytes = ConvertTo-TestBytes -Value 'must-not-be-deleted-or-replaced'
        [IO.File]::WriteAllBytes($sentinelPath, $sentinelBytes)

        [void](Assert-TestThrows `
                -Label 'create-only private-copy target rejects an existing directory' `
                -ExpectedMessageLike '*atomically create*private SDK directory*' `
                -Body {
                    New-PortableDotNetSdkPrivateCopy `
                        -SourceClosure $source `
                        -DestinationDirectory $destination
                })
        Assert-TestTrue -Condition ([IO.Directory]::Exists($destination)) `
            -Label 'existing destination remains after create-only rejection'
        Assert-TestTrue -Condition ([IO.File]::Exists($sentinelPath)) `
            -Label 'existing destination sentinel remains after rejection'
        Assert-TestTrue -Condition (
            (Get-TestSha256 -Bytes ([IO.File]::ReadAllBytes($sentinelPath))) -ceq
                (Get-TestSha256 -Bytes $sentinelBytes)) `
            -Label 'existing destination sentinel bytes remain exact'
        Assert-TestTrue -Condition (
            Assert-PortableDotNetSdkClosureUnchanged -Closure $source) `
            -Label 'create-only rejection leaves the source closure unchanged'
        Close-PortableDotNetSdkClosure -Closure $source
    }

    Invoke-TestCase -Name 'matching capsule files with reserved Windows paths' -Body {
        $reservedNames = @('CON', 'NUL', 'AUX.txt', 'trailing.')
        for ($index = 0; $index -lt $reservedNames.Count; $index++) {
            $name = $reservedNames[$index]
            $scenario = New-TestScenario -Name "reserved-path-$index"
            $payload = ConvertTo-TestBytes -Value "reserved-path-payload-$index"
            $verbatim = Add-VerbatimTestCapsuleFile `
                -Scenario $scenario `
                -RelativePath $name `
                -Bytes $payload
            try {
                [void](Write-TestLock `
                        -Scenario $scenario `
                        -Files @($verbatim.Record))
                [void](Assert-TestThrows `
                        -Label "matching capsule file '$name' is rejected by Windows path semantics" `
                        -ExpectedMessageLike '*reserved Windows path segment*' `
                        -Body {
                            $unexpected = Open-TestScenario -Scenario $scenario
                            if ($null -ne $unexpected) {
                                Close-PortableDotNetSdkClosure -Closure $unexpected
                            }
                        })
                Assert-TestTrue -Condition (
                    [IO.File]::Exists($verbatim.VerbatimPath)) `
                    -Label "rejection leaves reserved test file '$name' present"
                Assert-TestTrue -Condition (
                    (Get-TestSha256 -Bytes (
                            [IO.File]::ReadAllBytes($verbatim.VerbatimPath))) -ceq
                        (Get-TestSha256 -Bytes $payload)) `
                    -Label "rejection leaves reserved test file '$name' unchanged"
            }
            finally {
                if ([IO.File]::Exists($verbatim.VerbatimPath)) {
                    [IO.File]::Delete($verbatim.VerbatimPath)
                }
            }
        }
    }

    Invoke-TestCase -Name 'hostile paths and private-copy boundaries' -Body {
        $scenario = New-TestScenario -Name 'hostile-lock-paths'
        $payload = ConvertTo-TestBytes -Value 'hostile-path-record'
        $digest = Get-TestSha256 -Bytes $payload
        $hostilePaths = @(
            '', '.', '..', '../escape.dll', '/rooted.dll', 'C:/drive.dll',
            'bin\evil.dll', 'bin//evil.dll', 'bin/evil:ads',
            'bin/evil name.dll', 'CON', 'bin/trailing.')
        foreach ($relativePath in $hostilePaths) {
            $record = [pscustomobject][ordered]@{
                relativePath = $relativePath
                sizeBytes = [int64]$payload.Length
                sha256 = $digest
            }
            [void](Write-TestLock -Scenario $scenario -Files @($record))
            [void](Assert-TestThrows `
                    -Label "hostile lock path '$relativePath' is rejected" `
                    -Body { Open-TestScenario -Scenario $scenario })
        }

        $valid = New-ValidTestScenario -Name 'hostile-api-paths'
        [void](Assert-TestThrows `
                -Label 'relative capsule path is rejected' `
                -Body {
                    Open-PortableDotNetSdkClosure `
                        -CapsuleDirectory 'capsule' `
                        -LockPath $valid.LockPath `
                        -ExpectedSdkVersion $script:SdkVersion
                })
        [void](Assert-TestThrows `
                -Label 'relative lock path is rejected' `
                -Body {
                    Open-PortableDotNetSdkClosure `
                        -CapsuleDirectory $valid.Capsule `
                        -LockPath 'sdk.lock.json' `
                        -ExpectedSdkVersion $script:SdkVersion
                })

        $source = Register-TestClosure -Closure (
            Open-TestScenario -Scenario $valid)
        [void](Assert-TestThrows `
                -Label 'UNC private-copy path is rejected before access' `
                -ExpectedMessageLike '*absolute local path*' `
                -Body {
                    New-PortableDotNetSdkPrivateCopy `
                        -SourceClosure $source `
                        -DestinationDirectory '\\server\share\private-copy'
                })
        [void](Assert-TestThrows `
                -Label 'private copy may not overlap source capsule' `
                -ExpectedMessageLike '*may not overlap*' `
                -Body {
                    New-PortableDotNetSdkPrivateCopy `
                        -SourceClosure $source `
                        -DestinationDirectory (
                            Join-Path $valid.Capsule 'nested-private-copy')
                })
        $existingDestination = Join-Path $valid.Root 'existing-private-copy'
        [IO.Directory]::CreateDirectory($existingDestination) | Out-Null
        [void](Assert-TestThrows `
                -Label 'existing private-copy destination is rejected' `
                -ExpectedMessageLike '*create-only*' `
                -Body {
                    New-PortableDotNetSdkPrivateCopy `
                        -SourceClosure $source `
                        -DestinationDirectory $existingDestination
                })
        Close-PortableDotNetSdkClosure -Closure $source
    }

    $reparseScenario = New-ValidTestScenario -Name 'reparse-point'
    $reparseTarget = Join-Path $reparseScenario.Root 'junction-target'
    $reparsePath = Join-Path $reparseScenario.Capsule 'linked-directory'
    [IO.Directory]::CreateDirectory($reparseTarget) | Out-Null
    $reparseAvailable = $false
    try {
        New-Item `
            -ItemType Junction `
            -Path $reparsePath `
            -Target $reparseTarget `
            -ErrorAction Stop | Out-Null
        $reparseAvailable = (Get-Item -LiteralPath $reparsePath -Force).Attributes `
            -band [IO.FileAttributes]::ReparsePoint
        if ($reparseAvailable) {
            $script:TrackedReparsePoints.Add($reparsePath)
        }
    }
    catch {
        $script:SkippedTests.Add(
            "reparse-point rejection (capability unavailable: $($_.Exception.Message))")
    }
    if ($reparseAvailable) {
        Invoke-TestCase -Name 'reparse-point rejection' -Body {
            [void](Assert-TestThrows `
                    -Label 'child reparse point is rejected' `
                    -ExpectedMessageLike '*contains a filesystem link*' `
                    -Body { Open-TestScenario -Scenario $reparseScenario })
            [IO.Directory]::Delete($reparsePath)
            Assert-TestTrue -Condition (-not [IO.Directory]::Exists($reparsePath)) `
                -Label 'test junction is removed without touching its target'
            $recovered = Register-TestClosure -Closure (
                Open-TestScenario -Scenario $reparseScenario)
            Close-PortableDotNetSdkClosure -Closure $recovered
        }
    }

    $hardlinkScenario = New-ValidTestScenario -Name 'hardlink'
    $hardlinkTarget = Join-Path $hardlinkScenario.Capsule 'bin/dotnet.exe'
    $hardlinkAlias = Join-Path $hardlinkScenario.Root 'dotnet-hardlink-alias.exe'
    $hardlinkAvailable = $false
    try {
        New-Item `
            -ItemType HardLink `
            -Path $hardlinkAlias `
            -Target $hardlinkTarget `
            -ErrorAction Stop | Out-Null
        $hardlinkAvailable = [IO.File]::Exists($hardlinkAlias)
    }
    catch {
        $script:SkippedTests.Add(
            "hardlink rejection (capability unavailable: $($_.Exception.Message))")
    }
    if ($hardlinkAvailable) {
        Invoke-TestCase -Name 'hardlink rejection' -Body {
            try {
                [void](Assert-TestThrows `
                        -Label 'multiply-linked capsule file is rejected' `
                        -ExpectedMessageLike '*ordinary single-link files*' `
                        -Body { Open-TestScenario -Scenario $hardlinkScenario })
            }
            finally {
                if ([IO.File]::Exists($hardlinkAlias)) {
                    [IO.File]::Delete($hardlinkAlias)
                }
            }
            $recovered = Register-TestClosure -Closure (
                Open-TestScenario -Scenario $hardlinkScenario)
            Close-PortableDotNetSdkClosure -Closure $recovered
        }
    }

    [pscustomobject]@{
        TestScript = [IO.Path]::GetFileName($PSCommandPath)
        Result = 'PASS'
        Assertions = $script:AssertionCount
        PassedTests = @($script:PassedTests)
        SkippedCapabilityTests = @($script:SkippedTests)
        FixtureBytes = [int64]((Get-ChildItem `
                    -LiteralPath $temporaryRoot `
                    -File `
                    -Recurse `
                    -Force | Measure-Object -Property Length -Sum).Sum)
        ProductionAdmissionClaimed = $false
    }
}
finally {
    for ($index = $script:TrackedClosures.Count - 1; $index -ge 0; $index--) {
        $closure = $script:TrackedClosures[$index]
        try {
            if ($null -ne $closure -and
                $null -ne $closure.PSObject.Properties['ClosureType'] -and
                [string]$closure.ClosureType -ceq 'PortableDotNetSdkByteClosure') {
                Close-PortableDotNetSdkClosure -Closure $closure
            }
        }
        catch {
            Write-Warning "Could not close test closure during cleanup: $($_.Exception.Message)"
        }
    }
    foreach ($path in $script:TrackedVerbatimFiles) {
        if ([IO.File]::Exists($path)) {
            try {
                [IO.File]::Delete($path)
            }
            catch {
                Write-Warning "Could not remove verbatim test file '$path': $($_.Exception.Message)"
            }
        }
    }
    $remainingVerbatimFiles = @(
        $script:TrackedVerbatimFiles |
            Where-Object { [IO.File]::Exists($_) })
    if ($remainingVerbatimFiles.Count -gt 0) {
        throw 'Refusing recursive test cleanup while a verbatim test file remains.'
    }
    foreach ($path in $script:TrackedReparsePoints) {
        if ([IO.Directory]::Exists($path)) {
            try {
                $item = Get-Item -LiteralPath $path -Force
                if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                    [IO.Directory]::Delete($path)
                }
            }
            catch {
                Write-Warning "Could not remove test reparse point '$path': $($_.Exception.Message)"
            }
        }
    }
    $remainingReparsePoints = @(
        $script:TrackedReparsePoints |
            Where-Object { [IO.Directory]::Exists($_) })
    if ($remainingReparsePoints.Count -gt 0) {
        throw 'Refusing recursive test cleanup while a tracked reparse point remains.'
    }
    if ([IO.Directory]::Exists($temporaryRoot)) {
        [GC]::Collect()
        [GC]::WaitForPendingFinalizers()
        $removed = $false
        for ($attempt = 0; $attempt -lt 5 -and -not $removed; $attempt++) {
            try {
                Remove-Item -LiteralPath $temporaryRoot -Recurse -Force -ErrorAction Stop
                $removed = $true
            }
            catch {
                if ($attempt -eq 4) {
                    throw
                }
                Start-Sleep -Milliseconds 100
            }
        }
    }
}
