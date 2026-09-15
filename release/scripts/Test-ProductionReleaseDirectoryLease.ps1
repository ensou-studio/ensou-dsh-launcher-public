#requires -Version 7.2
[CmdletBinding()]
param(
    [string]$ModulePath = (Join-Path $PSScriptRoot 'ProductionReleaseState.psm1'),
    [string]$EvidenceRoot = ''
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $IsWindows) { throw 'Directory lease tests require Windows.' }
$preserve = -not [string]::IsNullOrWhiteSpace($EvidenceRoot)
$root = if ($preserve) { [IO.Path]::GetFullPath($EvidenceRoot) } else {
    Join-Path ([IO.Path]::GetTempPath()) ('ensou-dirlease-' + [Guid]::NewGuid().ToString('N'))
}
if (Test-Path -LiteralPath $root) { throw 'Directory lease test root must be create-only.' }
for ($cursor = Get-Item -LiteralPath ([IO.Path]::GetDirectoryName($root)); $null -ne $cursor; $cursor = $cursor.Parent) {
    if ($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Linked test ancestor.' }
}
[IO.Directory]::CreateDirectory($root) | Out-Null
$moduleHash = (Get-FileHash -LiteralPath $ModulePath).Hash
Import-Module -Name $ModulePath -Force
$results = [Collections.Generic.List[object]]::new()
$handles = [Collections.Generic.List[object]]::new()
$junctions = [Collections.Generic.List[string]]::new()
function Check([bool]$condition, [string]$label) { if (!$condition) { throw $label } }
function Read-Lease([string]$path) {
    $handle = [EnsouLauncherProduction.NativeFileIdentity]::OpenDirectoryReadLease($path)
    $handles.Add($handle)
    return $handle
}
function Move-Lease([string]$path) {
    $handle = [EnsouLauncherProduction.NativeFileIdentity]::OpenDirectoryMoveLease($path)
    $handles.Add($handle)
    return $handle
}
function Long-Path([string]$name, [int]$length) {
    $parent = Join-Path $root $name
    [IO.Directory]::CreateDirectory($parent) | Out-Null
    while ($length - $parent.Length - 1 -gt 200) {
        $parent = Join-Path $parent ('p' * 80)
        [IO.Directory]::CreateDirectory($parent) | Out-Null
    }
    $count = $length - $parent.Length - 1
    Check ($count -ge 1) 'Test root is too long for the exact boundary.'
    return Join-Path $parent ('d' * $count)
}
function Rejected([scriptblock]$action, [string]$type, [int[]]$codes = @()) {
    try { & $action } catch {
        $ex = $_.Exception
        while ($null -ne $ex.InnerException -and $ex.GetType().FullName -cne $type) { $ex = $ex.InnerException }
        Check ($ex.GetType().FullName -ceq $type) 'Rejection exception type differs.'
        if ($codes.Count) { Check ($ex.NativeErrorCode -in $codes) 'Rejection Win32 code differs.' }
        return
    }
    throw 'Expected rejection did not occur.'
}
function Case([string]$name, [scriptblock]$action) {
    $row = [ordered]@{ name=$name; passed=$false; exceptionType=$null; nativeErrorCode=$null }
    try { & $action; $row.passed=$true } catch {
        $ex=$_.Exception
        while ($null -ne $ex.InnerException) { $ex=$ex.InnerException }
        $row.exceptionType=$ex.GetType().FullName
        if ($ex -is [ComponentModel.Win32Exception]) { $row.nativeErrorCode=$ex.NativeErrorCode }
    } finally {
        foreach ($handle in $handles) { $handle.Dispose() }
        $results.Add($row)
    }
}
try {
    foreach ($length in @(259,260,261,270)) {
        Case "read-$length" {
            $path=Long-Path "read-$length" $length
            [IO.Directory]::CreateDirectory($path) | Out-Null
            $read=Read-Lease $path
            Check (!$read.IsInvalid) 'Read lease invalid.'
        }
    }
    foreach ($length in @(0,270)) {
        Case "read-move-read-$length" {
            $path=if($length){Long-Path 'combined-long' $length}else{Join-Path $root 'combined-short'}
            [IO.Directory]::CreateDirectory($path) | Out-Null
            $one=Read-Lease $path; $move=Move-Lease $path; $two=Read-Lease $path
            $ids=@($one,$move,$two | ForEach-Object {[EnsouLauncherProduction.NativeFileIdentity]::RequireOrdinaryDirectory($_)})
            Check (@($ids|Where-Object {$_.FileIndex -ne $ids[0].FileIndex -or $_.VolumeSerialNumber -ne $ids[0].VolumeSerialNumber}).Count -eq 0) 'Lease identity mismatch.'
            Rejected { $unexpected=Move-Lease $path } 'System.ComponentModel.Win32Exception' @(32)
        }
    }
    # This separately verifies FILE_RENAME_INFO accepting an extended DOS target,
    # including on the unchanged pre-fix module. It is not inferred from CreateFileW.
    foreach ($explicitExtended in @($true,$false)) {
        Case "long-rename-extended-$explicitExtended" {
            $source=Long-Path "source-$explicitExtended" 270
            $destination=Long-Path "dest-$explicitExtended" 280
            [IO.Directory]::CreateDirectory($source) | Out-Null
            $nativeSource=if($explicitExtended){'\\?\'+$source}else{$source}
            $nativeDestination=if($explicitExtended){'\\?\'+$destination}else{$destination}
            $move=Move-Lease $nativeSource
            $before=[EnsouLauncherProduction.NativeFileIdentity]::RequireOrdinaryDirectory($move)
            [EnsouLauncherProduction.NativeFileIdentity]::MoveDirectoryLease($move,$nativeDestination)
            $probe=Read-Lease $nativeDestination
            $after=[EnsouLauncherProduction.NativeFileIdentity]::RequireOrdinaryDirectory($probe)
            Check ($before.FileIndex -eq $after.FileIndex -and $before.VolumeSerialNumber -eq $after.VolumeSerialNumber) 'Moved identity differs.'
            Check (![IO.Directory]::Exists($source) -and [IO.Directory]::Exists($destination)) 'Move paths differ.'
        }
    }
    Case 'duplicate-target-no-overwrite' {
        $source=Join-Path $root 'duplicate-source';$destination=Join-Path $root 'duplicate-target'
        [IO.Directory]::CreateDirectory($source)|Out-Null;[IO.Directory]::CreateDirectory($destination)|Out-Null
        $move=Move-Lease $source
        $target=Read-Lease $destination
        $identity=[EnsouLauncherProduction.NativeFileIdentity]::RequireOrdinaryDirectory($target)
        Rejected { [EnsouLauncherProduction.NativeFileIdentity]::MoveDirectoryLease($move,$destination) } 'System.ComponentModel.Win32Exception' @(5,183)
        $probe=Read-Lease $destination
        $after=[EnsouLauncherProduction.NativeFileIdentity]::RequireOrdinaryDirectory($probe)
        Check ($identity.FileIndex -eq $after.FileIndex -and [IO.Directory]::Exists($source)) 'Duplicate target was overwritten.'
    }
    Case 'non-directory-rejected' {
        $file=Join-Path $root 'ordinary-file';[IO.File]::WriteAllText($file,'test')
        Rejected { $unexpected=Read-Lease $file } 'System.IO.InvalidDataException'
        Rejected { $unexpected=Move-Lease $file } 'System.IO.InvalidDataException'
    }
    Case 'junction-rejected-no-follow' {
        $target=Join-Path $root 'junction-target';$link=Join-Path $root 'junction-link'
        [IO.Directory]::CreateDirectory($target)|Out-Null
        New-Item -ItemType Junction -Path $link -Target $target | Out-Null
        $junctions.Add($link)
        Rejected { $unexpected=Read-Lease $link } 'System.IO.InvalidDataException'
        Rejected { $unexpected=Move-Lease $link } 'System.IO.InvalidDataException'
        Check ([IO.Directory]::Exists($target)) 'Junction target changed.'
    }
} finally {
    foreach ($handle in $handles) { $handle.Dispose() }
    foreach ($link in $junctions) { [IO.Directory]::Delete($link) }
    $receipt=[ordered]@{schemaVersion=1;pid=$PID;moduleSha256=$moduleHash;sourceUnchanged=((Get-FileHash -LiteralPath $ModulePath).Hash -ceq $moduleHash);passed=@($results|Where-Object passed).Count;failed=@($results|Where-Object {!$_.passed}).Count;handlesClosed=(@($handles|Where-Object {!$_.IsClosed}).Count -eq 0);cases=$results.ToArray()}
    if($preserve){[IO.File]::WriteAllText((Join-Path $root 'RESULT.json'),($receipt|ConvertTo-Json -Depth 6))}
    else {
        $resolved=[IO.Path]::GetFullPath($root)
        Check ([IO.Path]::GetFileName($resolved) -match '^ensou-dirlease-[0-9a-f]{32}$') 'Cleanup target invalid.'
        Check ([IO.Path]::GetDirectoryName($resolved) -eq [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')) 'Cleanup parent invalid.'
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
$receipt|ConvertTo-Json -Depth 6
if($receipt.failed -or !$receipt.handlesClosed -or !$receipt.sourceUnchanged){throw 'Production directory lease regression failed.'}
