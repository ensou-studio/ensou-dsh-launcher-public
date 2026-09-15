#requires -Version 7.2
[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [Parameter(Mandatory = $true)][string]$EvidenceRoot,
    [string]$DotnetPath = '',
    [string]$NuGetPackagesRoot = '',
    [switch]$IncludeLabSelfCheck
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (!$IsWindows) { throw 'Release probe tests require Windows.' }
$utf8Strict = [Text.UTF8Encoding]::new($false,$true)
$labOutputs = [Collections.Generic.List[string]]::new()
$labOutputDigests = [Collections.Generic.List[object]]::new()
$root = [IO.Path]::GetFullPath($EvidenceRoot)
if (Test-Path -LiteralPath $root) { throw 'Probe evidence root must be create-only.' }
for ($cursor = Get-Item -LiteralPath ([IO.Path]::GetDirectoryName($root)) -Force; $null -ne $cursor; $cursor = $cursor.Parent) {
    if ($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Linked evidence ancestor.' }
}
$nativeSource = Join-Path $RepositoryRoot 'src/Ensou.Dsh.Host/WindowsJobObject.cs'
$facadeSource = Join-Path $RepositoryRoot 'release/scripts/ProductionReleaseProbeProcess.cs'
$stateModule = Join-Path $RepositoryRoot 'release/scripts/ProductionReleaseState.psm1'
$orchestratorSource = Join-Path $RepositoryRoot 'release/scripts/Invoke-LauncherProductionRelease.ps1'
$fixtureProjectSource = Join-Path $RepositoryRoot 'tests/Ensou.Dsh.ReleaseProbeFixture/Ensou.Dsh.ReleaseProbeFixture.csproj'
$fixtureProgramSource = Join-Path $RepositoryRoot 'tests/Ensou.Dsh.ReleaseProbeFixture/Program.cs'
$fixtureSdkSource = Join-Path $RepositoryRoot 'global.json'
if (!$DotnetPath) { $DotnetPath = (Get-Command dotnet -CommandType Application -ErrorAction Stop).Source }
if (!$NuGetPackagesRoot) { $NuGetPackagesRoot = [Environment]::GetEnvironmentVariable('NUGET_PACKAGES') }
if (!$NuGetPackagesRoot) { throw 'NuGetPackagesRoot is required when NUGET_PACKAGES is not configured.' }
$DotnetPath = [IO.Path]::GetFullPath($DotnetPath)
$NuGetPackagesRoot = [IO.Path]::GetFullPath($NuGetPackagesRoot)
foreach ($path in @($nativeSource,$facadeSource,$stateModule,$orchestratorSource,$fixtureProjectSource,$fixtureProgramSource,$fixtureSdkSource,$DotnetPath)) {
    if (!(Test-Path -LiteralPath $path -PathType Leaf)) { throw 'A required probe test input is absent.' }
    for ($cursor = Get-Item -LiteralPath $path -Force; $null -ne $cursor; $cursor = if ($cursor -is [IO.FileInfo]) { $cursor.Directory } else { $cursor.Parent }) {
        if ($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Linked probe test input.' }
    }
}
$inputHashes = @{}
foreach ($path in @($nativeSource,$facadeSource,$stateModule,$orchestratorSource,$fixtureProjectSource,$fixtureProgramSource,$fixtureSdkSource,$DotnetPath)) { $inputHashes[$path] = (Get-FileHash -LiteralPath $path).Hash }
[IO.Directory]::CreateDirectory($root) | Out-Null
$cases = [Collections.Generic.List[object]]::new()
$owned = [Collections.Generic.List[object]]::new()
$links = [Collections.Generic.List[string]]::new()
$sourceDescriptors = [Collections.Generic.List[object]]::new()
$status = 'FAIL'
function Check([bool]$condition, [string]$label) { if (!$condition) { throw $label } }
function New-LengthDirectory([string]$label,[int]$length) {
    $path = Join-Path $root $label
    while ($length - $path.Length - 1 -gt 120) { $path = Join-Path $path ('d' * 80) }
    Check ($length - $path.Length - 1 -ge 1) 'Evidence root is too long for the exact boundary.'
    $path = Join-Path $path ('d' * ($length - $path.Length - 1))
    [IO.Directory]::CreateDirectory($path) | Out-Null
    return $path
}
$script:fixturePublishedExe = ''
function Assert-PrivateFixturePath([string]$path,[string]$label) {
    $full=[IO.Path]::GetFullPath($path);$prefix=$root.TrimEnd('\')+'\'
    Check ($full.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)) "$label is outside the create-only fixture root."
    return $full
}
function Invoke-PrivateFixtureDotnet([string[]]$arguments,[string]$label) {
    $work=Join-Path $root 'fixture-toolchain';$info=[Diagnostics.ProcessStartInfo]::new($DotnetPath)
    $info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.WindowStyle='Hidden';$info.WorkingDirectory=$work
    $info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
    $info.Environment.Clear();foreach($name in @('SystemRoot','WINDIR','SystemDrive','ProgramFiles(x86)','ProgramFiles','ProgramW6432','ProgramData','ALLUSERSPROFILE','ComSpec','PATHEXT','NUMBER_OF_PROCESSORS','PROCESSOR_ARCHITECTURE')){$value=[Environment]::GetEnvironmentVariable($name);if($value){$info.Environment[$name]=$value}}
    foreach($name in @('USERPROFILE','HOME','APPDATA','LOCALAPPDATA','TEMP','TMP','DOTNET_CLI_HOME','DOTNET_BUNDLE_EXTRACT_BASE_DIR')){$value=Join-Path $work ('environment\\'+$name);[IO.Directory]::CreateDirectory($value)|Out-Null;$info.Environment[$name]=$value}
    $sdkDirectory=[IO.Path]::GetDirectoryName($DotnetPath);$info.Environment['PATH']=$sdkDirectory+';'+[Environment]::SystemDirectory;$info.Environment['DOTNET_ROOT']=$sdkDirectory;$info.Environment['NUGET_PACKAGES']=$NuGetPackagesRoot
    $info.Environment['DOTNET_GENERATE_ASPNET_CERTIFICATE']='false';$info.Environment['DOTNET_MULTILEVEL_LOOKUP']='0';$info.Environment['DOTNET_NOLOGO']='1';$info.Environment['DOTNET_SKIP_FIRST_TIME_EXPERIENCE']='1';$info.Environment['DOTNET_CLI_TELEMETRY_OPTOUT']='1';$info.Environment['DOTNET_ADD_GLOBAL_TOOLS_TO_PATH']='false'
    foreach($argument in $arguments){$info.ArgumentList.Add($argument)}
    $process=[Diagnostics.Process]::new();$process.StartInfo=$info;$started=$false
    try{$started=$process.Start();Check $started "$label did not start.";$record=[ordered]@{kind='fixture-toolchain';label=$label;pid=$process.Id;startFileTime=$process.StartTime.ToUniversalTime().ToFileTimeUtc();exitCode=$null;exited=$false};$owned.Add($record);$output=$process.StandardOutput.ReadToEndAsync();$errors=$process.StandardError.ReadToEndAsync();Check ($process.WaitForExit(120000)) "$label timed out.";Check ($output.Wait(5000)-and$errors.Wait(5000)) "$label output did not close.";$record.exitCode=$process.ExitCode;[IO.File]::WriteAllText((Join-Path $work ($label+'.stdout.log')),$output.Result);[IO.File]::WriteAllText((Join-Path $work ($label+'.stderr.log')),$errors.Result);Check ($process.ExitCode-eq0) "$label failed: $($errors.Result)"}finally{if($started){if(!$process.HasExited){$process.Kill($true);Check($process.WaitForExit(10000)) "$label cleanup could not be confirmed."};$record.exited=$process.HasExited};$process.Dispose()}
}
function Initialize-ReleaseProbeFixture {
    $work=Join-Path $root 'fixture-toolchain';$source=Join-Path $work 'source';$publish=Join-Path $work 'publish';[IO.Directory]::CreateDirectory($source)|Out-Null;[IO.Directory]::CreateDirectory((Join-Path $work 'temp'))|Out-Null
    # Keep exact SDK selection when the private workspace is outside the checkout.
    $privateSdk=Join-Path $work 'global.json';[IO.File]::Copy($fixtureSdkSource,$privateSdk,$false)
    Check ((Get-FileHash -LiteralPath $privateSdk -Algorithm SHA256).Hash -ceq $inputHashes[$fixtureSdkSource]) 'Private fixture SDK selection copy hash mismatch.'
    $privateProject=Join-Path $source 'Ensou.Dsh.ReleaseProbeFixture.csproj';$privateProgram=Join-Path $source 'Program.cs';[IO.File]::Copy($fixtureProjectSource,$privateProject,$false);[IO.File]::Copy($fixtureProgramSource,$privateProgram,$false)
    Check ((Get-FileHash -LiteralPath $fixtureProjectSource -Algorithm SHA256).Hash -eq (Get-FileHash -LiteralPath $privateProject -Algorithm SHA256).Hash) 'Private fixture project copy hash mismatch.';Check ((Get-FileHash -LiteralPath $fixtureProgramSource -Algorithm SHA256).Hash -eq (Get-FileHash -LiteralPath $privateProgram -Algorithm SHA256).Hash) 'Private fixture program copy hash mismatch.'
    [IO.File]::WriteAllText((Join-Path $work 'NuGet.Config'),"<configuration><packageSources><clear /></packageSources></configuration>",[Text.UTF8Encoding]::new($false))
    $project=$privateProject;Invoke-PrivateFixtureDotnet -arguments @('restore',$project,'--packages',$NuGetPackagesRoot,'--configfile',(Join-Path $work 'NuGet.Config'),'--nologo','--verbosity','quiet') -label 'fixture-restore'
    # Pin to the Windows release runtime in installer/personal-publish-runtime-packs.lock.json.
    Invoke-PrivateFixtureDotnet -arguments @('publish',$project,'-c','Release','--no-restore','-r','win-x64','--self-contained','true','-p:PublishSingleFile=true','-p:RuntimeFrameworkVersion=10.0.10','--output',$publish,'--nologo','--verbosity','quiet') -label 'fixture-publish'
    $script:fixturePublishedExe=Join-Path $publish 'Ensou.Dsh.ReleaseProbeFixture.exe';Check (Test-Path -LiteralPath $script:fixturePublishedExe -PathType Leaf) 'Fixture publish did not emit its exact single-file executable.'
}
function New-Fixture([string]$label,[string]$behavior,[bool]$personal=$true,[string]$directory='') {
    Check ($behavior-cin@('success','stdout','stderr','timeout','child-survives-root')) 'Unknown fixture behavior.';Check (![string]::IsNullOrEmpty($script:fixturePublishedExe)) 'Fixture publish was not initialized.'
    if(!$directory){$directory=Join-Path $root $label};$directory=Assert-PrivateFixturePath $directory 'Fixture directory';[IO.Directory]::CreateDirectory($directory)|Out-Null
    $exe=Join-Path $directory 'fixture.exe';$marker=Assert-PrivateFixturePath (Join-Path $directory 'entered.json') 'Fixture marker';$childMarker=Assert-PrivateFixturePath (Join-Path $directory 'child.json') 'Fixture child marker';$config=Join-Path $directory 'fixture.config.json'
    [IO.File]::Copy($script:fixturePublishedExe,$exe,$false);$argument=if($personal){'--binary-self-check'}else{'--release-manifest-trust-probe'};$protocol=if($personal){'ensou-personal-binary-self-check/v1'}else{$null}
    [IO.File]::WriteAllText($config,([ordered]@{mode=$behavior;markerPath=$marker;childMarkerPath=if($behavior-ceq'child-survives-root'){$childMarker}else{$null};expectedArgument=$argument;expectedProtocol=$protocol}|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
    return [pscustomobject]@{exe=$exe;marker=$marker;childMarker=$childMarker;config=$config;personal=$personal}
}
function Open-Input([string]$path) { return [EnsouLauncherProbeTests.FileLease]::Open($path) }
function Check-Exited([string]$marker) {
    if (!(Test-Path -LiteralPath $marker)) { return }
    $identity=Get-Content -LiteralPath $marker -Raw|ConvertFrom-Json
    $process=$null
    $record=[ordered]@{kind='fixture';pid=[int]$identity.pid;startFileTime=[long]$identity.startFileTime;exited=$false;testCleanupRequired=$false}
    try {
        try { $process=[Diagnostics.Process]::GetProcessById([int]$identity.pid) } catch [ArgumentException] { $record.exited=$true;return }
        if (!$process.HasExited -and $process.StartTime.ToUniversalTime().ToFileTimeUtc() -eq [long]$identity.startFileTime) {
            # Contain only the exact synthetic process if a product cleanup regression occurs.
            $record.testCleanupRequired=$true
            $process.Kill($true);Check ($process.WaitForExit(10000)) 'Fixture cleanup could not be confirmed.'
            $record.exited=$true
            throw 'Probe facade returned while its exact fixture process was still running.'
        }
        $record.exited=$true
    } finally { $owned.Add($record);if ($null-ne$process) { $process.Dispose() } }
}
function Read-ExactFixtureIdentity([string]$marker,[string]$label) {
    Check (Test-Path -LiteralPath $marker -PathType Leaf) "$label identity marker is absent."
    try { $identity=Get-Content -LiteralPath $marker -Raw|ConvertFrom-Json } catch { throw "$label identity marker is incomplete or invalid." }
    Check ($null-ne$identity.PSObject.Properties['pid'] -and $null-ne$identity.PSObject.Properties['startFileTime']) "$label identity marker shape is invalid."
    $fixtureProcessId=[int]$identity.pid;$startFileTime=[long]$identity.startFileTime
    Check ($fixtureProcessId-gt0 -and $startFileTime-gt0) "$label identity marker values are invalid."
    return [pscustomobject]@{pid=$fixtureProcessId;startFileTime=$startFileTime;label=$label}
}
function Get-ExactFixtureProcess($identity) {
    $process=$null
    try { try { $process=[Diagnostics.Process]::GetProcessById([int]$identity.pid) } catch [ArgumentException] { return $null }
        if ($process.HasExited -or $process.StartTime.ToUniversalTime().ToFileTimeUtc()-ne[long]$identity.startFileTime) { $process.Dispose();return $null }
        return $process
    } catch { if($null-ne$process){$process.Dispose()};throw }
}
function Assert-ExactFixtureExited($identity) {
    $process=Get-ExactFixtureProcess $identity
    try { Check ($null-eq$process) "$($identity.label) exact fixture process remained alive." } finally { if($null-ne$process){$process.Dispose()} }
}
function Invoke-ExactFixtureFallbackCleanup($identity) {
    $process=Get-ExactFixtureProcess $identity
    $record=[ordered]@{kind='fixture-fallback';label=$identity.label;pid=[int]$identity.pid;startFileTime=[long]$identity.startFileTime;exited=$false;testCleanupRequired=$false}
    try {
        if($null-ne$process){
            $record.testCleanupRequired=$true
            $process.Kill($true);Check ($process.WaitForExit(10000)) "$($identity.label) fallback cleanup could not be confirmed."
        }
        $record.exited=$true
    } finally { $owned.Add($record);if($null-ne$process){$process.Dispose()} }
    Check (!$record.testCleanupRequired) "$($identity.label) required supplemental test cleanup."
}
function Case([string]$name,[scriptblock]$action) {
    $row=[ordered]@{name=$name;passed=$false;exceptionType=$null;elapsedMilliseconds=0}
    $clock=[Diagnostics.Stopwatch]::StartNew()
    try { &$action;$row.passed=$true } catch {
        $row.exceptionType=$_.Exception.GetType().FullName
        [IO.File]::AppendAllText((Join-Path $root 'error.log'),("CASE: $name`n"+$_.ToString()+"`n"+$_.ScriptStackTrace+"`n"))
    }
    finally {$row.elapsedMilliseconds=$clock.ElapsedMilliseconds;$cases.Add($row)}
}
function Reject([scriptblock]$action,[string]$expectedType='',[string]$expectedMessage='',[string]$requiredStack='') {
    $rejected=$false
    try { &$action | Out-Null } catch {
        $originalError=$_
        $types=[Collections.Generic.List[string]]::new();$messages=[Collections.Generic.List[string]]::new()
        for($exception=$_.Exception;$null-ne$exception;$exception=$exception.InnerException){$types.Add($exception.GetType().FullName);$messages.Add($exception.Message)}
        try {
            if($expectedType){Check ($types-ccontains$expectedType) 'Probe rejection exception classification differs.'}
            if($expectedMessage){Check ($messages-ccontains$expectedMessage) 'Probe rejection message classification differs.'}
            if($requiredStack){Check ($originalError.ScriptStackTrace.Contains($requiredStack,[StringComparison]::Ordinal)) 'Probe rejection did not originate from its expected boundary.'}
        } catch {
            [IO.File]::AppendAllText((Join-Path $root 'error.log'),("UNEXPECTED REJECTION`n"+$originalError.ToString()+"`n"+$originalError.ScriptStackTrace+"`n"))
            throw
        }
        $rejected=$true
    }
    Check $rejected 'Expected probe rejection did not occur.'
}
try {
    Import-Module -Name $stateModule -Force
    $orchestratorDescriptor=Open-ProductionReleaseInput -Path $orchestratorSource -Label 'LAB initializer source' -MaximumBytes 2097152
    $sourceDescriptors.Add($orchestratorDescriptor)
    $sourceBytes=Read-ProductionReleaseInputBytes -Descriptor $orchestratorDescriptor -Label 'LAB initializer source'
    $parseErrors=$null;$tokens=$null
    $ast=[Management.Automation.Language.Parser]::ParseInput($utf8Strict.GetString($sourceBytes),[ref]$tokens,[ref]$parseErrors)
    Check ($parseErrors.Count-eq0) 'Orchestrator AST has errors.'
    $initializers=@($ast.FindAll({param($node) $node-is[Management.Automation.Language.FunctionDefinitionAst] -and $node.Name-ceq'Initialize-ProductionReleaseProbeProcess'},$true))
    Check ($initializers.Count-eq1) 'Expected one real release probe initializer.'
    . ([scriptblock]::Create($initializers[0].Extent.Text))
    foreach($path in @($nativeSource,$facadeSource)) {
        $sourceDescriptors.Add((Open-ProductionReleaseInput -Path $path -Label 'LAB locked compilation input' -MaximumBytes 2097152))
    }
    $compileDescriptors=@($sourceDescriptors|Where-Object {$_.Path-cne$orchestratorDescriptor.Path})
    foreach($missing in @($nativeSource,$facadeSource)) {
        Case ('initializer-missing-'+[IO.Path]::GetFileName($missing)) {
            $incomplete=[pscustomobject]@{Descriptors=@($compileDescriptors|Where-Object {$_.Path-cne$missing})}
            $relative=if($missing-ceq$nativeSource){'src/Ensou.Dsh.Host/WindowsJobObject.cs'}else{'release/scripts/ProductionReleaseProbeProcess.cs'}
            Reject { Initialize-ProductionReleaseProbeProcess -Admission $incomplete -CheckoutRoot $RepositoryRoot } -expectedMessage "Release probe code is not in the exact locked checkout closure: $relative"
        }
    }
    Case 'initializer-closed-source-handle' {
        $closed=Open-ProductionReleaseInput -Path $nativeSource -Label 'LAB closed compilation input' -MaximumBytes 2097152
        $closed.Stream.Dispose()
        $invalid=[pscustomobject]@{Descriptors=@($closed)+@($compileDescriptors|Where-Object {$_.Path-ceq$facadeSource})}
        Reject { Initialize-ProductionReleaseProbeProcess -Admission $invalid -CheckoutRoot $RepositoryRoot } -expectedType 'System.ObjectDisposedException' -requiredStack 'Read-ProductionReleaseInputBytes'
    }
    # These descriptors are a LAB file-identity fixture, not release admission.
    $labAdmission=[pscustomobject]@{Descriptors=$compileDescriptors}
    $probeProcessType=Initialize-ProductionReleaseProbeProcess -Admission $labAdmission -CheckoutRoot $RepositoryRoot
    Check ($probeProcessType.FullName-match'^EnsouReleaseProbe_[0-9a-f]{32}\.EnsouLauncherProductionProbe\.ReleaseProbeProcess$') 'Initializer returned the wrong scoped type.'
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace EnsouLauncherProbeTests {
 public static class FileLease {
  [DllImport("kernel32.dll", EntryPoint="CreateFileW",CharSet=CharSet.Unicode,SetLastError=true)]
  private static extern SafeFileHandle CreateFile(string p,uint a,uint s,IntPtr x,uint d,uint f,IntPtr t);
  [DllImport("kernel32.dll", EntryPoint="MoveFileExW",CharSet=CharSet.Unicode,SetLastError=true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  private static extern bool MoveFileEx(string source,string destination,uint flags);
  private static string Extended(string path) { return @"\\?\"+System.IO.Path.GetFullPath(path); }
  public static SafeFileHandle Open(string p) {
   var h=CreateFile(Extended(p),0x80000000,1,IntPtr.Zero,3,0x00200000,IntPtr.Zero);
   if(h.IsInvalid){var e=Marshal.GetLastWin32Error();h.Dispose();throw new Win32Exception(e);}return h;
  }
  public static int TryOpenDelete(string p) {
   using(var h=CreateFile(Extended(p),0x00010000,0x00000007,IntPtr.Zero,3,0x02200000,IntPtr.Zero)){
    return h.IsInvalid ? Marshal.GetLastWin32Error() : 0;
   }
  }
  public static int TryRename(string source,string destination) {
   return MoveFileEx(Extended(source),Extended(destination),0) ? 0 : Marshal.GetLastWin32Error();
  }
 }
}
'@
    $directoryLeaseType=$probeProcessType.GetNestedType('DirectoryLease',[Reflection.BindingFlags]::NonPublic)
    Check ($null-ne$directoryLeaseType) 'Production DirectoryLease nested type is absent.'
    $directoryLeaseOpen=$directoryLeaseType.GetMethod(
        'Open',
        ([Reflection.BindingFlags]::Static -bor [Reflection.BindingFlags]::NonPublic),
        $null,
        [type[]]@([string]),
        $null)
    Check ($null-ne$directoryLeaseOpen) 'Production DirectoryLease.Open(string) is absent.'
    Initialize-ReleaseProbeFixture
    Case 'directory-lease-denies-delete-and-rename' {
        $source=Join-Path $root 'directory-lease-regression'
        $destination=$source+'-renamed'
        [IO.Directory]::CreateDirectory($source)|Out-Null
        $lease=$null
        $heldRenameSucceeded=$false
        try {
            $lease=$directoryLeaseOpen.Invoke($null,[object[]]@([string]"$source"))
            Check ($lease-is[IDisposable]) 'Production DirectoryLease is not disposable.'
            $heldDeleteError=[EnsouLauncherProbeTests.FileLease]::TryOpenDelete($source)
            Check ($heldDeleteError-eq32) ("Held DirectoryLease DELETE open returned native error $heldDeleteError; expected 32.")
            $heldRenameError=[EnsouLauncherProbeTests.FileLease]::TryRename($source,$destination)
            $heldRenameSucceeded=($heldRenameError-eq0)
            Check ($heldRenameError-eq32) ("Held DirectoryLease rename returned native error $heldRenameError; expected 32.")
            Check ((Test-Path -LiteralPath $source)-and!(Test-Path -LiteralPath $destination)) 'Held rename changed the exact test directory.'
        } finally {
            if($null-ne$lease){([IDisposable]$lease).Dispose()}
            if($heldRenameSucceeded){
                $restoreError=[EnsouLauncherProbeTests.FileLease]::TryRename($destination,$source)
                Check ($restoreError-eq0) ("Unexpected held rename could not be restored; native error $restoreError.")
            }
        }
        $releasedDeleteError=[EnsouLauncherProbeTests.FileLease]::TryOpenDelete($source)
        Check ($releasedDeleteError-eq0) ("Released DirectoryLease DELETE open returned native error $releasedDeleteError; expected 0.")
        $releasedRenameSucceeded=$false
        try {
            $releasedRenameError=[EnsouLauncherProbeTests.FileLease]::TryRename($source,$destination)
            $releasedRenameSucceeded=($releasedRenameError-eq0)
            Check ($releasedRenameError-eq0) ("Released DirectoryLease rename returned native error $releasedRenameError; expected 0.")
        } finally {
            if($releasedRenameSucceeded){
                $restoreError=[EnsouLauncherProbeTests.FileLease]::TryRename($destination,$source)
                Check ($restoreError-eq0) ("Control rename could not be restored; native error $restoreError.")
            }
        }
    }
    foreach ($personal in @($true,$false)) {
        $fixture=New-Fixture ('success-'+$personal) 'success' $personal
        Case ('fixed-arguments-'+$personal) {
            $handle=Open-Input $fixture.exe
            try { $output=$probeProcessType::Execute($fixture.exe,$handle,$personal);Check ($output -ceq '{"probe":"fixed-safe-fixture"}') 'Fixed protocol output differs.' }
            finally {$handle.Dispose();Check-Exited $fixture.marker}
        }
    }
    foreach ($length in @(284,286,300)) {
        $directory=New-LengthDirectory ('exact-'+$length) ($length-'fixture.exe'.Length-1)
        $fixture=New-Fixture ('long-'+$length) 'success' $true $directory
        $exe=$fixture.exe
        Case ('long-executable-'+$length) {
            $handle=Open-Input $exe
            try { Check ($exe.Length-eq$length) 'Wrong long executable length.'; $output=$probeProcessType::Execute($exe,$handle,$true);Check ($output -ceq '{"probe":"fixed-safe-fixture"}') 'Long output differs from short baseline.' }
            finally {$handle.Dispose();Check-Exited $fixture.marker}
        }
    }
    $wrong=New-Fixture 'wrong-image' 'success'
    # Equal bytes are not the same file identity.
    $unrelated=Join-Path $root 'same-bytes-other-identity.exe';[IO.File]::Copy($wrong.exe,$unrelated,$false)
    Case 'wrong-image-handle-before-resume' {
        $handle=Open-Input $unrelated
        try { Reject { $probeProcessType::Execute($wrong.exe,$handle,$true) } -expectedMessage 'Release probe process failed: image-identity-mismatch.';Check (!(Test-Path -LiteralPath $wrong.marker)) 'Rejected image reached entrypoint.' }
        finally {$handle.Dispose();Check-Exited $wrong.marker}
    }
    foreach ($behavior in @('stdout','stderr','timeout')) {
        $fixture=New-Fixture $behavior $behavior
        Case ('bounded-'+$behavior) {
            $handle=Open-Input $fixture.exe
            try {
                $elapsed=[Diagnostics.Stopwatch]::StartNew()
                $expectedCode=if($behavior-ceq'timeout'){'timeout'}else{'output-limit'}
                Reject { $probeProcessType::Execute($fixture.exe,$handle,$true) } -expectedMessage "Release probe process failed: $expectedCode."
                Check (Test-Path -LiteralPath $fixture.marker) 'Negative fixture never reached its tested behavior.'
                if($behavior-cne'timeout'){Check ($elapsed.Elapsed.TotalSeconds-lt25) 'Output overflow was not rejected before the process deadline.'}
                else{Check ($elapsed.Elapsed.TotalSeconds-ge29 -and $elapsed.Elapsed.TotalSeconds-lt45) 'Timeout did not honor the single bounded process budget.'}
            }
            finally {$handle.Dispose();Check-Exited $fixture.marker}
        }
    }
    $childFixture=New-Fixture 'child-survives-root' 'child-survives-root'
    Case 'descendant-retained-child-survives-root' {
        $handle=Open-Input $childFixture.exe
        $parentIdentity=$null;$childIdentity=$null
        try {
            $elapsed=[Diagnostics.Stopwatch]::StartNew()
            Reject { $probeProcessType::Execute($childFixture.exe,$handle,$true) } -expectedMessage 'Release probe process failed: descendant-retained.'
            Check ($elapsed.Elapsed.TotalMilliseconds-ge900 -and $elapsed.Elapsed.TotalMilliseconds-lt7000) 'Descendant retention did not honor the 1000ms grace plus bounded cleanup allowance.'
            $parentIdentity=Read-ExactFixtureIdentity $childFixture.marker 'Child fixture parent'
            $childIdentity=Read-ExactFixtureIdentity $childFixture.childMarker 'Child fixture child'
            Assert-ExactFixtureExited $childIdentity
            Assert-ExactFixtureExited $parentIdentity
        } finally {
            try {
                if($null-eq$childIdentity -and (Test-Path -LiteralPath $childFixture.childMarker -PathType Leaf)){$childIdentity=Read-ExactFixtureIdentity $childFixture.childMarker 'Child fixture child'}
                if($null-ne$childIdentity){Invoke-ExactFixtureFallbackCleanup $childIdentity}
            } finally {
                try {
                    if($null-eq$parentIdentity -and (Test-Path -LiteralPath $childFixture.marker -PathType Leaf)){$parentIdentity=Read-ExactFixtureIdentity $childFixture.marker 'Child fixture parent'}
                    if($null-ne$parentIdentity){Invoke-ExactFixtureFallbackCleanup $parentIdentity}
                } finally { $handle.Dispose() }
            }
        }
    }
    $linked=New-Fixture 'linked-target' 'success'
    $link=Join-Path $root 'linked-parent';New-Item -ItemType Junction -Path $link -Target ([IO.Path]::GetDirectoryName($linked.exe))|Out-Null;$links.Add($link)
    Case 'linked-executable-ancestor-rejected' {
        $handle=Open-Input $linked.exe
        try { Reject { $probeProcessType::Execute((Join-Path $link 'fixture.exe'),$handle,$true) } -expectedMessage 'Release probe process failed: path-directory-identity-invalid.';Check (!(Test-Path -LiteralPath $linked.marker)) 'Linked ancestor reached entrypoint.' }
        finally {$handle.Dispose();Check-Exited $linked.marker}
    }
    $redirectDirectory=Join-Path $root 'redirect-target';[IO.Directory]::CreateDirectory($redirectDirectory)|Out-Null
    $redirectExe=Join-Path $redirectDirectory 'fixture.exe';[IO.File]::Copy($linked.exe,$redirectExe,$false)
    $redirectLink=Join-Path $root 'redirect-parent';New-Item -ItemType Junction -Path $redirectLink -Target $redirectDirectory|Out-Null;$links.Add($redirectLink)
    Case 'linked-same-bytes-different-object-rejected' {
        $handle=Open-Input $linked.exe
        try { Reject { $probeProcessType::Execute((Join-Path $redirectLink 'fixture.exe'),$handle,$true) } -expectedMessage 'Release probe process failed: path-directory-identity-invalid.';Check (!(Test-Path -LiteralPath $linked.marker)) 'Redirected image reached entrypoint.' }
        finally {$handle.Dispose();Check-Exited $linked.marker}
    }
    if ($IncludeLabSelfCheck) {
        $lab=Join-Path ([IO.Directory]::GetParent($RepositoryRoot).FullName) '.tmp/goal-personal-path-budget-package-20260908/run-01/build/payload/Ensou.Dsh.Bootstrapper.exe'
        Check ((Get-Item -LiteralPath $lab).Length-eq75787869 -and (Get-FileHash -LiteralPath $lab).Hash-ceq'429BF5CB737CA861FA7F8CD264FF96670170A791914BFA2E91857CA592569520') 'LAB candidate pin differs.'
        foreach ($length in @(0,286,300)) {
            $name='Ensou.Dsh.Bootstrapper.exe'
            $directory=if($length){New-LengthDirectory ('lab-'+$length) ($length-$name.Length-1)}else{Join-Path $root 'lab-short'}
            [IO.Directory]::CreateDirectory($directory)|Out-Null;$exe=Join-Path $directory $name;[IO.File]::Copy($lab,$exe,$false)
            Case ('lab-selfcheck-'+$length) {
                $handle=Open-Input $exe
                try {
                    $output=$probeProcessType::Execute($exe,$handle,$true)
                    $fingerprint=$output|ConvertFrom-Json
                    Check ($fingerprint.schemaVersion-eq2 -and !$fingerprint.productionBuild -and $fingerprint.startupStubVersion-ceq'1.2.0') 'LAB compiled trust shape differs.'
                    $labOutputs.Add($output);Check ($output-ceq$labOutputs[0]) 'LAB compiled trust differs.'
                    $bytes=$utf8Strict.GetBytes($output)
                    $labOutputDigests.Add([ordered]@{exeLength=$exe.Length;outputLength=$bytes.Length;sha256=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes))})
                }
                finally {$handle.Dispose()}
            }
        }
    }
    Check (@($cases|Where-Object {!$_.passed}).Count-eq0) 'Probe process regression failed.'
    $status='PASS'
} catch {
    [IO.File]::AppendAllText((Join-Path $root 'error.log'),("TOP LEVEL`n"+$_.ToString()+"`n"+$_.ScriptStackTrace+"`n"))
    throw
} finally {
    foreach ($descriptor in $sourceDescriptors) { $descriptor.Stream.Dispose() }
    foreach ($link in $links) { [IO.Directory]::Delete($link) }
    $unchanged=$true
    foreach ($path in $inputHashes.Keys) { if((Get-FileHash -LiteralPath $path).Hash-cne$inputHashes[$path]){$unchanged=$false} }
    if(!$unchanged){$status='FAIL_SOURCE_DRIFT'}
    $receipt=[ordered]@{schemaVersion=1;status=$status;labOnly=$true;productionSignatureAdmissionTested=$false;cwdAncestorReplacementTested=$false;sourceUnchanged=$unchanged;inputHashes=$inputHashes;passed=@($cases|Where-Object passed).Count;failed=@($cases|Where-Object {!$_.passed}).Count;ownedProcesses=$owned.ToArray();labOutputDigests=$labOutputDigests.ToArray();cases=$cases.ToArray()}
    [IO.File]::WriteAllText((Join-Path $root 'RESULT.json'),($receipt|ConvertTo-Json -Depth 8))
}
$receipt|ConvertTo-Json -Depth 8
if(!$receipt.sourceUnchanged){throw 'Probe test inputs changed.'}
