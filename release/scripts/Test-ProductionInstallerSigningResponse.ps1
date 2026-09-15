#requires -Version 7.2
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Focused offline issuer integration. Complete state replay, Windows
# Authenticode, and production payload execution are the only explicit seams.
# All JSON/schema closure, file/directory identity and locks, PKCS8/low-S,
# response validators, create-only publication, and cleanup stay product code.
$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$schemaRoot = Join-Path $repositoryRoot 'release\schemas'
$issuerPath = Join-Path $PSScriptRoot 'New-ProductionInstallerSigningResponse.ps1'
$fixtureFactoryPath = Join-Path $PSScriptRoot 'Test-InstallerSigningContracts.ps1'
$stateModulePath = Join-Path $PSScriptRoot 'ProductionReleaseState.psm1'
$contractsModulePath = Join-Path $PSScriptRoot 'InstallerSigningContracts.psm1'
$personalModulePath = Join-Path $PSScriptRoot 'PersonalInstallerSigningPipeline.psm1'
$enterpriseSelfCheckModulePath = Join-Path $PSScriptRoot 'EnterpriseInstallerProductionPayloadSelfCheck.psm1'
$planSchemaPath = Join-Path $schemaRoot 'launcher-production-release-plan-v2.schema.json'
$stateSchemaPath = Join-Path $schemaRoot 'launcher-production-release-state-v2.schema.json'
$requestSchemaPath = Join-Path $schemaRoot 'launcher-installer-signing-request-v2.schema.json'
$personalResponseSchemaPath = Join-Path $schemaRoot 'personal-installer-signing-response-v2.schema.json'
$enterpriseResponseSchemaPath = Join-Path $schemaRoot 'launcher-installer-signing-response-v1.schema.json'
$personalEvidenceSchemaPath = Join-Path $schemaRoot 'personal-installer-trusted-build-evidence-v1.schema.json'
$enterpriseEvidenceSchemaPath = Join-Path $schemaRoot 'enterprise-installer-trusted-build-evidence-v1.schema.json'
$p256Order = [Convert]::FromHexString('FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551')
$p256HalfOrder = [Convert]::FromHexString('7FFFFFFF800000007FFFFFFFFFFFFFFFDE737D56D38BCF4279DCE5617E3192A8')
$script:Utf8 = [Text.UTF8Encoding]::new($false, $true)

Microsoft.PowerShell.Core\Import-Module $contractsModulePath -Force
Microsoft.PowerShell.Core\Import-Module $personalModulePath -Force
Microsoft.PowerShell.Core\Import-Module $enterpriseSelfCheckModulePath -Force
$contractsModule = Microsoft.PowerShell.Core\Import-Module $contractsModulePath -Force -PassThru
$stateModule = Microsoft.PowerShell.Core\Import-Module $stateModulePath -Force -PassThru
$personalModule = @(Get-Module PersonalInstallerSigningPipeline | Where-Object { $_.Path -ieq [IO.Path]::GetFullPath($personalModulePath) })[-1]

function Assert-Test([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "ASSERT: $Message" }
}
function ConvertTo-TestBase64Url([byte[]]$Bytes) {
    [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+','-').Replace('/','_')
}
function ConvertTo-WholeSecondUtc([DateTimeOffset]$Value) {
    ProductionReleaseState\ConvertTo-ProductionUtc -Value $Value
}
function Get-TestSha256([string]$Value) {
    ProductionReleaseState\Get-ProductionSha256Bytes -Bytes $script:Utf8.GetBytes($Value)
}
function Write-TestJson([string]$Path, $Value) {
    [IO.File]::WriteAllBytes($Path, (ProductionReleaseState\ConvertTo-ProductionJsonBytes -Value $Value))
}
function Get-InstallerSigningObjectSha256($Value) {
    InstallerSigningContracts\Get-InstallerSigningObjectSha256 -Value $Value
}
function Get-InstallerTargetBuildIdentitySha256($Request) {
    InstallerSigningContracts\Get-InstallerTargetBuildIdentitySha256 -Request $Request
}
function New-TestUnsignedPe([byte]$Marker) {
    $bytes=[byte[]]::new(512);$bytes[0]=0x4d;$bytes[1]=0x5a
    [BitConverter]::GetBytes([int]0x80).CopyTo($bytes,0x3c)
    $bytes[0x80]=0x50;$bytes[0x81]=0x45
    [BitConverter]::GetBytes([uint16]0xe0).CopyTo($bytes,0x80+20)
    [BitConverter]::GetBytes([uint16]0x10b).CopyTo($bytes,0x80+24)
    $bytes[500]=$Marker; return ,$bytes
}
function New-TestSignedPe([byte[]]$Unsigned) {
    $bytes=[byte[]]::new(528);[Array]::Copy($Unsigned,$bytes,$Unsigned.Length)
    $security=0x80+24+96+32
    [BitConverter]::GetBytes([uint32]512).CopyTo($bytes,$security)
    [BitConverter]::GetBytes([uint32]16).CopyTo($bytes,$security+4)
    for($i=512;$i-lt528;$i++){$bytes[$i]=[byte](0xa0+$i-512)}
    return ,$bytes
}
function New-TestTrust([Security.Cryptography.ECDsa]$Key,[string]$Id,[string]$Purpose) {
    $p=$Key.ExportParameters($false)
    [pscustomobject][ordered]@{algorithm='ES256';keyId=$Id;purpose=$Purpose;x=(ConvertTo-TestBase64Url $p.Q.X);y=(ConvertTo-TestBase64Url $p.Q.Y)}
}
function Copy-TestObject($Value) {
    $bytes=ProductionReleaseState\ConvertTo-ProductionJsonBytes -Value $Value
    $script:Utf8.GetString($bytes)|ConvertFrom-Json -Depth 100 -DateKind String
}
function Assert-PathUnlocked([string]$Path) {
    if(-not(Test-Path -LiteralPath $Path -PathType Leaf)){return}
    $s=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None);$s.Dispose()
}

# Reuse only the canonical fixture-object factories from the existing contract
# suite. Product behavior is never copied or rewritten here.
$loadedFunctions=[Collections.Generic.List[object]]::new()
function Add-TestFunctionAst([string]$Path,[string[]]$Names) {
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tokens,[ref]$errors)
    Assert-Test ($errors.Count-eq0) "fixture factory parses: $Path"
    foreach($name in $Names){
        $nodes=@($ast.FindAll({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-ceq$name},$false))
        Assert-Test ($nodes.Count-eq1) "one fixture helper $name"
        $existing=Get-Item -LiteralPath ('Function:'+$name) -ErrorAction SilentlyContinue
        $loadedFunctions.Add([pscustomobject]@{Name=$name;Existed=$null-ne$existing;ScriptBlock=if($null-eq$existing){$null}else{$existing.ScriptBlock}})
        $bodyText=$nodes[0].Body.Extent.Text
        Set-Item -Path ('Function:script:'+$name) -Value ([scriptblock]::Create($bodyText.Substring(1,$bodyText.Length-2)))
    }
}
Add-TestFunctionAst $fixtureFactoryPath @(
    'New-TestFile','New-TestSignedClient','New-TestPayloadFile','New-TestBuildInput',
    'New-TestRequest','ConvertTo-TestEnterpriseRequestV2','New-TestPersonalRequestV2')

function New-TestPlan([string]$Edition,[object[]]$Trusts,[object[]]$ClientInputs) {
    $target=if($Edition-ceq'Personal'){'pilot'}else{'stable'}
    $value=[ordered]@{
        schemaVersion=2;planType='ensou-dsh-launcher-production-release'
        orchestrationId=if($Edition-ceq'Personal'){'12345678-1234-4abc-8def-1234567890ab'}else{'22222222-2222-4222-8222-222222222222'}
        edition=$Edition;releaseSetId=if($Edition-ceq'Personal'){'personal-2026.09.03.1'}else{'enterprise-2026.08.31.1'}
        targetChannel=$target;sourceCommit=('a'*40)
        manifestUri="https://updates.example.test/$target/release-set.v2.json"
        artifactBaseUri="https://artifacts.example.test/$target/"
        runtimeCandidate=[ordered]@{
            releaseId='runtime-fixture';githubReleaseTag='runtime-fixture'
            archive=[ordered]@{fileName='runtime.zip';path='C:\fixture\runtime.zip';sizeBytes=1;sha256=('1'*64)}
            metadata=[ordered]@{fileName='runtime.json';path='C:\fixture\runtime.json';sizeBytes=1;sha256=('2'*64)}
            hashEvidence=[ordered]@{fileName='runtime.zip.sha256';path='C:\fixture\runtime.zip.sha256';sizeBytes=1;sha256=('3'*64)}
        }
        authenticodePolicy=[ordered]@{signerSha256Thumbprint=(Get-TestSha256 "$Edition-authenticode-pin");requireTrustedTimestamp=$true;maximumResponseAgeMinutes=30}
        releaseManifestTrust=$Trusts[1]
        releaseCompatibility=if($Edition-ceq'Personal'){[ordered]@{startupStubVersion='1.2.0';canonicalLowSFromSequence=1}}else{[ordered]@{startupStubProtocol=1}}
        externalResponseTrusts=[ordered]@{clientSigning=$Trusts[2];manifestPublishing=$Trusts[3];installerSigning=$Trusts[0];feedPromotion=$Trusts[4]}
        clientSigningInputs=$ClientInputs
    }
    if($Edition-ceq'Personal'){
        $accept=@('startup-update-detection','runtime-only-update','launcher-only-update','failed-update-rollback','offline-last-known-good','local-chat-and-workspace-unchanged','no-command-window')
        $value.Insert(8,'personalAccountOrigin','https://account.example.test/')
        $value.Insert(9,'personalPilotDevices',@(
            [ordered]@{deviceId='pilot-desktop-desktop';hostLabel='PILOT-DESKTOP';architecture='win-x64';lane='existing-install-upgrade';installationIdentity='separate-device-identity';tokenOrSecretIncluded=$false;roleAcceptance='existing-version-upgrade';perDeviceAcceptance=$accept},
            [ordered]@{deviceId='pilot-notebook';hostLabel='PilotNotebook notebook';architecture='win-x64';lane='clean-first-install';installationIdentity='separate-device-identity';tokenOrSecretIncluded=$false;roleAcceptance='first-install';perDeviceAcceptance=$accept}))
    }else{$value.Insert(14,'pilotEvidenceTrustPolicySha256',('4'*64))}
    Copy-TestObject $value
}

function New-TestReceipt([string]$Edition,[string]$Channel,[int]$Revision,[string]$Phase,[string]$PlanSha,[string]$IdentitySha,[string]$PreviousSha,$Data,[DateTimeOffset]$When) {
    [pscustomobject][ordered]@{
        schemaVersion=2;receiptType='ensou-dsh-launcher-production-release-transition'
        orchestrationId=if($Edition-ceq'Personal'){'12345678-1234-4abc-8def-1234567890ab'}else{'22222222-2222-4222-8222-222222222222'}
        edition=$Edition;targetChannel=$Channel;planSha256=$PlanSha;identitySha256=$IdentitySha
        revision=$Revision;phase=$Phase;previousReceiptSha256=$PreviousSha;transitionSha256=(Get-TestSha256 "$Edition-transition-$Revision")
        data=$Data;recordedAtUtc=(ConvertTo-WholeSecondUtc $When)
    }
}

function New-TestEnterpriseEvidence($Request,[string]$R5Sha) {
    $source=Copy-TestObject $Request.sourceBuildInputs
    $source|Add-Member transitiveProjects @('src/Shared/Support.csproj')
    $generated=@($source.files|Where-Object kind -CEQ 'generated-input')[0];$generated.identityPath='generated/installer-payload-set.v1.json';$generated.snapshotRelativePath='build-inputs/generated/installer-payload-set.v1.json'
    $packages=@('microsoft.netcore.app.host.win-x64','microsoft.netcore.app.runtime.win-x64','microsoft.aspnetcore.app.runtime.win-x64','microsoft.windowsdesktop.app.runtime.win-x64')|ForEach-Object{
        [ordered]@{kind='runtime-pack';id=$_;version='10.0.10';fileName=($_+'.10.0.10.nupkg');sizeBytes=1;sha256=(Get-TestSha256 $_);sha512=([Convert]::ToBase64String([byte[]]::new(64)))}
    }
    $requestLock=$Request.toolchainLock
    $fullLock=[ordered]@{
        requestContract=$requestLock;requestContractSha256=(Get-InstallerSigningObjectSha256 $requestLock);restoreArgumentsSha256=(Get-TestSha256 'restore')
        networkEnforcement='local-source-clear-plus-loopback-proxy-sink';subprocessEnvironmentPolicy='clear-all-inherited-then-explicit-allowlist-and-msbuild-property-pins-v1'
        sdkFileClosureStatus='VERIFIED';archiveFileName='dotnet-sdk-10.0.302-win-x64.zip';archiveSourceUrl='https://builds.dotnet.microsoft.com/dotnet/Sdk/10.0.302/dotnet-sdk-10.0.302-win-x64.zip'
        archiveSha512=('c'*128);archiveBindingStatus='ZIP_SHA512_AND_FILE_INVENTORY_VERIFIED';trackedLockRelativePath='repo/release/locks/dotnet-sdk-10.0.302-win-x64.files.lock.json'
        trackedLockSha256=(Get-TestSha256 'sdk-lock');inventorySha256=(Get-TestSha256 'sdk-inventory');fileCount=1;totalSizeBytes=1
        privateCopyPolicy='create-only-output-work-copy-held-open-through-version-restore-publish-v1';dotnetRootPolicy='private-root-only-multilevel-lookup-disabled-v1'
    }
    [ordered]@{
        schemaVersion=1;evidenceType='ensou-dsh-enterprise-installer-trusted-build';orchestrationId=$Request.orchestrationId;releaseSetId=$Request.releaseSetId
        edition='Enterprise';channel='stable';planSha256=$Request.planSha256;baseHeadSha256=$Request.baseHeadSha256;r5ReceiptSha256=$R5Sha
        sourceCommit=$Request.sourceCommit;sourceTree=$Request.sourceTree;sourceBuildInputs=$source
        packageClosure=[ordered]@{lockRelativePath='repo/installer/enterprise-publish-runtime-packs.lock.json';lockSha256=(Get-TestSha256 'package-lock');packageCount=4;packages=@($packages)}
        installerPayload=$Request.installerPayload;toolchainLock=$fullLock;toolchainLockSha256=(Get-InstallerSigningObjectSha256 $fullLock)
        buildExecution=$Request.buildExecution;unsignedInstaller=([ordered]@{role='installer';fileName=$Request.unsignedInstaller.fileName;relativePath=$Request.unsignedInstaller.relativePath;sizeBytes=$Request.unsignedInstaller.sizeBytes;sha256=$Request.unsignedInstaller.sha256;peContentSha256=$Request.unsignedInstaller.peContentSha256;authenticodeStatus='NotSigned'})
        resourceBinding=$Request.resourceBinding
        signingRequestEligibility=[ordered]@{status='ELIGIBLE_FOR_PILOT_SIGNING';requestSchemaVersion=2;productionAdmission='NO_GO';blocker='INSTALLER_SIGNING_RESPONSE_REQUIRED';reason='All synthetic trusted-build closure checks are complete; the exact external Installer signing response remains required.'}
    }
}

function New-TestFixture([ValidateSet('Personal','Enterprise')][string]$Edition) {
    $script:caseNumber++;$root=[IO.Directory]::CreateDirectory((Join-Path $fixtureRoot ([string]$script:caseNumber))).FullName
    $stateRoot=[IO.Directory]::CreateDirectory((Join-Path $root 'state')).FullName
    $requestRoot=[IO.Directory]::CreateDirectory((Join-Path $stateRoot 'requests\installer-signing.v2')).FullName
    $payloadRoot=[IO.Directory]::CreateDirectory((Join-Path $requestRoot 'payload')).FullName
    $trustedRoot=[IO.Directory]::CreateDirectory((Join-Path $requestRoot 'trusted-build')).FullName
    $unsignedRoot=[IO.Directory]::CreateDirectory((Join-Path $requestRoot 'unsigned')).FullName
    $receiptsRoot=[IO.Directory]::CreateDirectory((Join-Path $stateRoot 'receipts')).FullName
    [IO.File]::WriteAllBytes((Join-Path $stateRoot 'state.lock'),[byte[]](1))
    $keys=[Collections.Generic.List[Security.Cryptography.ECDsa]]::new();for($i=0;$i-lt5;$i++){$keys.Add([Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve+NamedCurves]::nistP256))}
    $wrong=[Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve+NamedCurves]::nistP256)
    $purposes=@(if($Edition-ceq'Personal'){'personal-installer-signing-response'}else{'installer-signing-response'},'release-manifest-signing','client-signing-response','manifest-publishing-response','feed-promotion-response')
    $trusts=@(for($i=0;$i-lt5;$i++){New-TestTrust $keys[$i] "fixture-$Edition-$i" $purposes[$i]})
    $clientNames=if($Edition-ceq'Personal'){@('Ensou.Dsh.Bootstrapper.exe','Ensou.Dsh.ClientBootstrapper.exe','Ensou.Dsh.Launcher.exe','Ensou.Dsh.Personal.Maintenance.exe')}else{@('Ensou.Dsh.Enterprise.Bootstrapper.exe','Ensou.Dsh.Enterprise.Launcher.exe','Ensou.Dsh.Enterprise.ClientBootstrapper.exe','Ensou.Dsh.Enterprise.Maintenance.exe')}
    $clientRoles=if($Edition-ceq'Personal'){@('startup-stub','client-bootstrapper','launcher','maintenance')}else{@('bootstrapper','launcher','client-bootstrapper','maintenance')}
    $clientInputs=@(for($i=0;$i-lt4;$i++){[ordered]@{role=$clientRoles[$i];fileName=$clientNames[$i];path="C:\fixture\$($clientNames[$i])";sizeBytes=512;sha256=(Get-TestSha256 "$Edition-client-$i");peContentSha256=(Get-TestSha256 "$Edition-client-pe-$i")}})
    $plan=New-TestPlan $Edition $trusts $clientInputs;$planPath=Join-Path $stateRoot 'plan.json';Write-TestJson $planPath $plan;$planSha=(Get-FileHash $planPath).Hash.ToLowerInvariant()
    $now=[DateTimeOffset]::UtcNow.AddMinutes(-2)
    $request=if($Edition-ceq'Personal'){New-TestPersonalRequestV2 -InstallerTrust $trusts[0] -ReleaseTrust $trusts[1] -Now $now}else{ConvertTo-TestEnterpriseRequestV2 (New-TestRequest -Edition Enterprise -Channel stable -InstallerTrust $trusts[0] -ReleaseTrust $trusts[1] -Now $now)}
    $request.planSha256=$planSha
    if($Edition-ceq'Enterprise'){$request.sourceCommit=$plan.sourceCommit;$request.r5Evidence.releaseManifestTrustSha256=Get-InstallerSigningObjectSha256 $plan.releaseManifestTrust;$request.r5Evidence.releaseCompatibilitySha256=Get-InstallerSigningObjectSha256 $plan.releaseCompatibility}else{$request.source.commit=$plan.sourceCommit;$request.compiledTrust.manifestOrigin='https://updates.example.test/';$request.compiledTrust.artifactOrigin='https://artifacts.example.test/';$request.compiledTrust.releaseKeyId=$plan.releaseManifestTrust.keyId;$request.compiledTrust.releaseKeyIdentitySha256=Get-InstallerSigningObjectSha256 ([ordered]@{algorithm=$plan.releaseManifestTrust.algorithm;keyId=$plan.releaseManifestTrust.keyId;x=$plan.releaseManifestTrust.x;y=$plan.releaseManifestTrust.y});$request.compiledTrust.authenticodeSignerSha256Thumbprint=$plan.authenticodePolicy.signerSha256Thumbprint;$request.compiledTrust.startupStubVersion=$plan.releaseCompatibility.startupStubVersion;$request.compiledTrust.canonicalLowSFromSequence=$plan.releaseCompatibility.canonicalLowSFromSequence}
    [byte[]]$unsigned=New-TestUnsignedPe ([byte]$script:caseNumber);[byte[]]$signed=New-TestSignedPe $unsigned
    $installerName=if($Edition-ceq'Personal'){'Ensou.Dsh.Personal.Installer.exe'}else{'Ensou.Dsh.Enterprise.Installer.exe'}
    $unsignedPath=Join-Path $unsignedRoot $installerName;[IO.File]::WriteAllBytes($unsignedPath,$unsigned)
    $signedPath=Join-Path $root $installerName;[IO.File]::WriteAllBytes($signedPath,$signed)
    $unsignedSha=ProductionReleaseState\Get-ProductionSha256Bytes $unsigned;$peSha=ProductionReleaseState\Get-PeContentSha256 $unsigned
    $request.unsignedInstaller.sizeBytes=512;$request.unsignedInstaller.sha256=$unsignedSha;$request.unsignedInstaller.peContentSha256=$peSha
    if($Edition-ceq'Personal'){$request.compiledTrust.authenticodeSignerSha256Thumbprint=$plan.authenticodePolicy.signerSha256Thumbprint;$request.resourceBinding.unsignedInstallerSha256=$unsignedSha}
    else{$request.resourceBinding.unsignedInstallerSha256=$unsignedSha;$request.buildExecution.targetBuildIdentitySha256=Get-InstallerTargetBuildIdentitySha256 $request;$reservation=[ordered]@{schemaVersion=1;reservationType='ensou-dsh-enterprise-installer-trusted-build-reservation';buildId=$request.buildExecution.buildId;targetBuildIdentitySha256=$request.buildExecution.targetBuildIdentitySha256;sourceBuildInputSetSha256=$request.sourceBuildInputSetSha256;unsignedInstallerSha256=$unsignedSha};$request.buildExecution.reservationSha256=Get-InstallerSigningObjectSha256 $reservation}
    foreach($file in @(if($Edition-ceq'Personal'){$request.payload.files}else{@($request.installerPayload.files|Where-Object role -CNE 'install-manifest')})){
        $bytes=$script:Utf8.GetBytes("inert-$Edition-$($file.role)")
        [IO.File]::WriteAllBytes((Join-Path $payloadRoot $file.fileName),$bytes);$file.sizeBytes=$bytes.LongLength;$file.sha256=ProductionReleaseState\Get-ProductionSha256Bytes $bytes
        if($file.PSObject.Properties['sourceSha256']){$file.sourceSha256=$file.sha256}
        if($Edition-ceq'Enterprise'-and$file.sourceKind-ceq'r5-candidate'){$source=@($request.candidate.files|Where-Object role -CEQ $file.sourceRole)[0];$source.sizeBytes=$file.sizeBytes;$source.sha256=$file.sha256}
        if($Edition-ceq'Enterprise'-and$file.sourceKind-ceq'r3-signed-client'){$source=@($request.r3Evidence.signedClients|Where-Object role -CEQ $file.sourceRole)[0];$source.sizeBytes=$file.sizeBytes;$source.sha256=$file.sha256}
    }
    if($Edition-ceq'Enterprise'){
        $launcher=@($request.installerPayload.files|Where-Object role -CEQ 'launcher')[0];$runtime=@($request.installerPayload.files|Where-Object role -CEQ 'runtime')[0];$bootstrapper=@($request.installerPayload.files|Where-Object role -CEQ 'bootstrapper')[0]
        $manifest=[ordered]@{schemaVersion=1;layoutProfile='enterprise';launcherReleaseId='launcher-fixture';runtimeReleaseId='runtime-fixture';launcherArchive=$launcher.fileName;launcherArchiveSizeBytes=$launcher.sizeBytes;launcherArchiveSha256=$launcher.sha256;runtimeArchive=$runtime.fileName;runtimeArchiveSizeBytes=$runtime.sizeBytes;runtimeArchiveSha256=$runtime.sha256;bootstrapperFile=$bootstrapper.fileName;bootstrapperSizeBytes=$bootstrapper.sizeBytes;bootstrapperSha256=$bootstrapper.sha256;publishedAtUtc=ConvertTo-WholeSecondUtc ([DateTimeOffset]::UtcNow.AddMinutes(-4))}
        $manifestFile=@($request.installerPayload.files|Where-Object role -CEQ 'install-manifest')[0];$manifestBytes=ProductionReleaseState\ConvertTo-ProductionJsonBytes $manifest;[IO.File]::WriteAllBytes((Join-Path $payloadRoot $manifestFile.fileName),$manifestBytes);$manifestFile.sizeBytes=$manifestBytes.LongLength;$manifestFile.sha256=ProductionReleaseState\Get-ProductionSha256Bytes $manifestBytes;$manifestFile.sourceSha256=$manifestFile.sha256
    }
    $payloadFiles=@(if($Edition-ceq'Personal'){$request.payload.files}else{$request.installerPayload.files})
    if($Edition-ceq'Personal'){$request.payload.inventorySha256=Get-InstallerSigningObjectSha256 $payloadFiles;for($i=0;$i-lt4;$i++){$request.resourceBinding.resources[$i].sizeBytes=$payloadFiles[$i].sizeBytes;$request.resourceBinding.resources[$i].sha256=$payloadFiles[$i].sha256};$request.resourceBinding.resourceSetSha256=Get-InstallerSigningObjectSha256 $request.resourceBinding.resources}
    else{$request.candidate.inventorySha256=Get-InstallerSigningObjectSha256 $request.candidate.files;$request.r3Evidence.signedClientSetSha256=Get-InstallerSigningObjectSha256 $request.r3Evidence.signedClients;$request.installerPayload.inventorySha256=Get-InstallerSigningObjectSha256 $payloadFiles;for($i=0;$i-lt4;$i++){$request.resourceBinding.resources[$i].sizeBytes=$payloadFiles[$i].sizeBytes;$request.resourceBinding.resources[$i].sha256=$payloadFiles[$i].sha256};$request.resourceBinding.resourceSetSha256=Get-InstallerSigningObjectSha256 $request.resourceBinding.resources;$request.buildExecution.targetBuildIdentitySha256=Get-InstallerTargetBuildIdentitySha256 $request;$reservation=[ordered]@{schemaVersion=1;reservationType='ensou-dsh-enterprise-installer-trusted-build-reservation';buildId=$request.buildExecution.buildId;targetBuildIdentitySha256=$request.buildExecution.targetBuildIdentitySha256;sourceBuildInputSetSha256=$request.sourceBuildInputSetSha256;unsignedInstallerSha256=$unsignedSha};$request.buildExecution.reservationSha256=Get-InstallerSigningObjectSha256 $reservation}

    $identitySha=Get-TestSha256 "$Edition-identity"
    $r5Source=if($Edition-ceq'Personal'){New-TestRequest -Edition Personal -Channel pilot -InstallerTrust $trusts[0] -ReleaseTrust $trusts[1] -Now $now}else{$request}
    $r5Data=[ordered]@{responseRelativePath="imports/$($plan.targetChannel)-signed-candidate.v1/manifest-publishing-response.v1.json";responseSha256=(Get-TestSha256 'r5-response');requestSha256=(Get-TestSha256 'r4-request');requestNonce=('R'*43);baseHeadSha256=(Get-TestSha256 'r3-head');admissionHeadSha256=(Get-TestSha256 'r4-head');admissionRevision=4;requestExpiresAtUtc=(ConvertTo-WholeSecondUtc ([DateTimeOffset]::UtcNow.AddMinutes(20)));completedAtUtc=(ConvertTo-WholeSecondUtc ([DateTimeOffset]::UtcNow.AddMinutes(-3)));authenticationKeyId=$trusts[3].keyId;authenticationPurpose='manifest-publishing-response';authenticationPayloadType='ensou-dsh-launcher-manifest-publishing-response-authentication-v1';manifestRelativePath="imports/$($plan.targetChannel)-signed-candidate.v1/candidate/release-set.v2.json";manifestSha256=$r5Source.r5Evidence.manifestSha256;releaseManifestTrustSha256=(Get-InstallerSigningObjectSha256 $trusts[1]);releaseCompatibilitySha256=(Get-InstallerSigningObjectSha256 $plan.releaseCompatibility);componentReleaseIdsSha256=(Get-TestSha256 'components');runtimeProvenanceSha256=(Get-TestSha256 'runtime-provenance');compiledReleaseTrustStatus='VERIFIED';productionAdmission='NO_GO';files=@($r5Source.candidate.files|ForEach-Object{[ordered]@{role=$_.role;fileName=$_.fileName;relativePath=([string]$_.relativePath).Substring(([string]$_.relativePath).IndexOf('candidate/'));sizeBytes=$_.sizeBytes;sha256=$_.sha256}})}
    $r5=New-TestReceipt $Edition $plan.targetChannel 5 $(if($plan.targetChannel-ceq'pilot'){'PILOT_SIGNED_CANDIDATE_IMPORTED'}else{'STABLE_SIGNED_CANDIDATE_IMPORTED'}) $planSha $identitySha (Get-TestSha256 'r4-receipt') $r5Data ([DateTimeOffset]::UtcNow.AddMinutes(-3))
    $r5Name=if($Edition-ceq'Personal'){'0005-pilot-signed-candidate-imported.json'}else{'0005-stable-signed-candidate-imported.json'};$r5Path=Join-Path $receiptsRoot $r5Name;Write-TestJson $r5Path $r5;$r5Sha=(Get-FileHash $r5Path).Hash.ToLowerInvariant()
    $r5Head=[ordered]@{schemaVersion=2;stateType='ensou-dsh-launcher-production-release-head';orchestrationId=$plan.orchestrationId;edition=$Edition;planSha256=$planSha;identitySha256=$identitySha;revision=5;phase=$r5.phase;receiptFileName=$r5Name;receiptSha256=$r5Sha;updatedAtUtc=$r5.recordedAtUtc;targetChannel=$plan.targetChannel}
    $request.baseHeadSha256=ProductionReleaseState\Get-ProductionSha256Bytes (ProductionReleaseState\ConvertTo-ProductionJsonBytes $r5Head)
    if($Edition-ceq'Enterprise'){$request.r5Evidence.headSha256=$request.baseHeadSha256;$request.r5Evidence.receiptSha256=$r5Sha}
    if($Edition-ceq'Enterprise'){$request.buildExecution.targetBuildIdentitySha256=Get-InstallerTargetBuildIdentitySha256 $request;$reservation=[ordered]@{schemaVersion=1;reservationType='ensou-dsh-enterprise-installer-trusted-build-reservation';buildId=$request.buildExecution.buildId;targetBuildIdentitySha256=$request.buildExecution.targetBuildIdentitySha256;sourceBuildInputSetSha256=$request.sourceBuildInputSetSha256;unsignedInstallerSha256=$unsignedSha};$request.buildExecution.reservationSha256=Get-InstallerSigningObjectSha256 $reservation}
    $evidence=if($Edition-ceq'Personal'){[ordered]@{schemaVersion=1;evidenceType='ensou-dsh-personal-installer-trusted-build';buildId='66666666-6666-4666-8666-666666666666';edition='Personal';channel='pilot';releaseSetId=$request.releaseSetId;source=$request.source;payload=$request.payload;compiledTrust=$request.compiledTrust;packageClosure=$request.toolchain.packageClosure;sdkClosure=$request.toolchain.sdkClosure;buildExecution=$request.buildExecution;unsignedInstaller=$request.unsignedInstaller;resourceBinding=$request.resourceBinding;signingRequestEligibility=$request.admission}}else{New-TestEnterpriseEvidence $request $r5Sha}
    $evidencePath=Join-Path $trustedRoot 'trusted-build-evidence.v1.json';Write-TestJson $evidencePath $evidence;$request.trustedBuildEvidence.sizeBytes=(Get-Item $evidencePath).Length;$request.trustedBuildEvidence.sha256=(Get-FileHash $evidencePath).Hash.ToLowerInvariant()
    if($Edition-ceq'Enterprise'){$request.trustedBuildEvidence.resourceBindingSha256=Get-InstallerSigningObjectSha256 $request.resourceBinding}
    $requestPath=Join-Path $requestRoot 'installer-signing-request.v2.json';Write-TestJson $requestPath $request;$requestSha=(Get-FileHash $requestPath).Hash.ToLowerInvariant()
    $bindings=if($Edition-ceq'Personal'){PersonalInstallerSigningPipeline\Get-PersonalInstallerSigningRequestBindings -Request $request}else{$null}
    $r6Data=if($Edition-ceq'Personal'){[ordered]@{evidenceType='INSTALLER_SIGNING_REQUESTED';requestSchemaVersion=2;requestRelativePath='requests/installer-signing.v2/installer-signing-request.v2.json';requestSha256=$requestSha;baseHeadSha256=$request.baseHeadSha256;baseReceiptSha256=$r5Sha;sourceSha256=$bindings.sourceSha256;payloadSha256=$bindings.payloadSha256;compiledTrustSha256=$bindings.compiledTrustSha256;toolchainSha256=$bindings.toolchainSha256;buildExecutionSha256=$bindings.buildExecutionSha256;resourceBindingSha256=$bindings.resourceBindingSha256;trustedBuildEvidenceSha256=$bindings.trustedBuildEvidenceSha256;admissionSha256=$bindings.admissionSha256;r5ManifestSha256=$request.payload.files[0].sha256;r5ClientBundleSha256=$request.payload.files[2].sha256;r5RuntimeSha256=$request.payload.files[3].sha256;unsignedInstaller=[ordered]@{fileName=$installerName;relativePath="requests/installer-signing.v2/unsigned/$installerName";sizeBytes=512;sha256=$unsignedSha;peContentSha256=$peSha};createdAtUtc=$request.createdAtUtc;expiresAtUtc=$request.expiresAtUtc;authenticationKeyId=$trusts[0].keyId;authenticationPurpose='personal-installer-signing-response';authenticationPayloadType='ensou-dsh-personal-installer-signing-response-authentication-v2';admissionReason='INSTALLER_SIGNING_RESPONSE_REQUIRED';productionAdmission='NO_GO'}}else{[ordered]@{evidenceType='INSTALLER_SIGNING_REQUESTED';requestSchemaVersion=2;requestRelativePath='requests/installer-signing.v2/installer-signing-request.v2.json';requestSha256=$requestSha;baseHeadSha256=$request.baseHeadSha256;baseReceiptSha256=$r5Sha;sourceBuildInputSetSha256=$request.sourceBuildInputSetSha256;targetBuildIdentitySha256=$request.buildExecution.targetBuildIdentitySha256;payloadSetSha256=$request.installerPayload.inventorySha256;r5LauncherSha256=$request.candidate.files[2].sha256;r5RuntimeSha256=$request.candidate.files[3].sha256;trustedBuildEvidenceRelativePath='requests/installer-signing.v2/trusted-build/trusted-build-evidence.v1.json';trustedBuildEvidenceSha256=$request.trustedBuildEvidence.sha256;resourceBindingSha256=$request.trustedBuildEvidence.resourceBindingSha256;sdkFileClosureStatus='VERIFIED';signingRequestEligibilityStatus='ELIGIBLE_FOR_PILOT_SIGNING';unsignedInstaller=[ordered]@{fileName=$installerName;relativePath="requests/installer-signing.v2/unsigned/$installerName";sizeBytes=512;sha256=$unsignedSha;peContentSha256=$peSha};createdAtUtc=$request.createdAtUtc;expiresAtUtc=$request.expiresAtUtc;authenticationKeyId=$trusts[0].keyId;authenticationPurpose='installer-signing-response';admissionReason='INSTALLER_SIGNING_RESPONSE_REQUIRED';productionAdmission='NO_GO'}}
    $r6=New-TestReceipt $Edition $plan.targetChannel 6 'INSTALLER_SIGNING_REQUESTED' $planSha $identitySha $r5Sha $r6Data ([DateTimeOffset]::UtcNow.AddMinutes(-1));$r6Path=Join-Path $receiptsRoot '0006-installer-signing-requested.json';Write-TestJson $r6Path $r6;$r6Sha=(Get-FileHash $r6Path).Hash.ToLowerInvariant()
    $headSha=Get-TestSha256 "$Edition-r6-head";$state=[pscustomobject]@{StateRoot=$stateRoot;SchemaVersion=2;TargetChannel=$plan.targetChannel;Plan=$plan;Identity=[pscustomobject]@{planSha256=$planSha;orchestrationId=$plan.orchestrationId;edition=$Edition};Head=[pscustomobject]@{revision=6;phase='INSTALLER_SIGNING_REQUESTED';identitySha256=$identitySha;receiptFileName='0006-installer-signing-requested.json';receiptSha256=$r6Sha};HeadSha256=$headSha;Receipts=@(1..5|ForEach-Object{[pscustomobject]@{revision=$_}})+@($r6);OrphanReceipt=$null}
    $keyPath=Join-Path $root 'response-key.pk8';$wrongPath=Join-Path $root 'wrong-key.pk8';[IO.File]::WriteAllBytes($keyPath,$keys[0].ExportPkcs8PrivateKey());[IO.File]::WriteAllBytes($wrongPath,$wrong.ExportPkcs8PrivateKey())
    $fixture=[pscustomobject]@{Root=$root;StateRoot=$stateRoot;State=$state;Plan=$plan;Request=$request;RequestPath=$requestPath;R6=$r6;R6Path=$r6Path;SignedPath=$signedPath;UnsignedPath=$unsignedPath;KeyPath=$keyPath;WrongKeyPath=$wrongPath;OutputRoot=(Join-Path $root 'output');Keys=@($keys);WrongKey=$wrong;Trust=$trusts[0];EvidencePath=$evidencePath;PayloadRoot=$payloadRoot;InstallerName=$installerName}
    & $stateModule { param($s) $script:InstallerIssuerTestState=$s; $script:InstallerIssuerReplayMode=''; $script:InstallerIssuerReplayCalls=0 } $state
    & $contractsModule { param($t) $script:InstallerIssuerTimestampUtc=$t } (ConvertTo-WholeSecondUtc ([DateTimeOffset]::Parse($request.createdAtUtc).AddMinutes(1)))
    return $fixture
}

function Rewrite-R6($f){Write-TestJson $f.R6Path $f.R6;$sha=(Get-FileHash $f.R6Path).Hash.ToLowerInvariant();$f.State.Head.receiptSha256=$sha}
function Assert-Released($f){foreach($p in @($f.RequestPath,$f.R6Path,$f.SignedPath,$f.KeyPath,(Join-Path $f.StateRoot 'state.lock'))){Assert-PathUnlocked $p}}
function Assert-NoStage($f){if(Test-Path $f.OutputRoot){$items=@(Get-ChildItem $f.OutputRoot -Force);Assert-Test($items.Count-eq1-and$items[0].Name-ceq'sentinel')'failure preserves only pre-existing output'};Assert-Test(@(Get-ChildItem $f.Root -Force|Where-Object Name -Like 'output.pending-*').Count-eq0)'failure cleans owned stage'}

$tokens=$null;$errors=$null;$issuerAst=[Management.Automation.Language.Parser]::ParseFile($issuerPath,[ref]$tokens,[ref]$errors);Assert-Test($errors.Count-eq0)'issuer parses'
foreach($name in @('$p256Order','$p256HalfOrder')){$nodes=@($issuerAst.FindAll({param($n)$n-is[Management.Automation.Language.AssignmentStatementAst]-and$n.Left.Extent.Text-ceq$name},$false));foreach($n in $nodes){.([scriptblock]::Create($n.Extent.Text))}}
foreach($node in @($issuerAst.FindAll({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]},$false))){$existing=Get-Item ('Function:'+$node.Name)-ErrorAction SilentlyContinue;$loadedFunctions.Add([pscustomobject]@{Name=$node.Name;Existed=$null-ne$existing;ScriptBlock=if($existing){$existing.ScriptBlock}else{$null}});.([scriptblock]::Create($node.Extent.Text))}
$originalState = & $stateModule { (Get-Item Function:Get-ProductionReleaseState).ScriptBlock }; $originalAuth = & $contractsModule { (Get-Item Function:Get-ExactPeAuthenticodeEvidence).ScriptBlock }; $originalSelfCheck=(Get-Item Function:Invoke-ProductionInstallerPayloadSelfCheck).ScriptBlock
& $stateModule { function script:Get-ProductionReleaseState{param([string]$StateRoot,[string]$StateSchemaPath);$script:InstallerIssuerReplayCalls++;if($script:InstallerIssuerReplayMode-ceq'second-change'-and$script:InstallerIssuerReplayCalls-eq2){$script:InstallerIssuerTestState.HeadSha256='9'*64};return $script:InstallerIssuerTestState} }
& $contractsModule { function script:Get-ExactPeAuthenticodeEvidence{param([string]$Path,[string]$ExpectedSignerCertificateSha256,[string]$ExpectedPeContentSha256='');if($script:InstallerIssuerAuthMode-ceq'reject'){throw'TEST_AUTH_REJECTED'};$d=ProductionReleaseState\Open-ProductionReleaseInput $Path 'Focused signed Installer' 1GB;try{$b=ProductionReleaseState\Read-ProductionReleaseInputBytes $d 'Focused signed Installer';$pe=ProductionReleaseState\Get-PeContentSha256 $b;if($pe-cne$ExpectedPeContentSha256){throw'Focused signed PE content mismatch'};[pscustomobject][ordered]@{FileName=$d.FileName;SizeBytes=$d.SizeBytes;SignedFileSha256=$d.Sha256;PeContentSha256=$pe;AuthenticodeStatus='Valid';SignatureType='Authenticode';PrimarySignerCount=1;PrimarySignedCmsSha256=('1'*64);SignerCertificateSha256=$ExpectedSignerCertificateSha256;SignerDigestAlgorithmOid='2.16.840.1.101.3.4.2.1';SpcIndirectDataContentTypeOid='1.3.6.1.4.1.311.2.1.4';SpcPeImageDataTypeOid='1.3.6.1.4.1.311.2.1.15';SpcDigestAlgorithmOid='2.16.840.1.101.3.4.2.1';SpcPeContentSha256=$pe;TimestampProtocol='RFC3161';TimestampTokenOid='1.2.840.113549.1.9.16.2.14';TimestampContentTypeOid='1.2.840.113549.1.9.16.1.4';TimestampSignerCertificateSha256=('2'*64);TimestampUtc=$script:InstallerIssuerTimestampUtc;Rfc3161PrimarySignerBound=$true;LegacyCounterSignaturePresent=$false}}finally{$d.Stream.Dispose()}} }
function Invoke-ProductionInstallerPayloadSelfCheck{param([string]$Edition,$InstallerInput,$Request,$DraftResponse,[string]$ExpectedSignerCertificateSha256,[int]$TimeoutMilliseconds,$InstallManifest);if($script:InstallerIssuerSelfCheckMode-ceq'reject'){throw'TEST_SELFCHECK_REJECTED'};$done=ProductionReleaseState\ConvertTo-ProductionUtc([DateTimeOffset]::UtcNow);if($Edition-ceq'Personal'){$f=@($Request.payload.files);return [pscustomobject][ordered]@{schemaVersion=1;evidenceType='ensou-dsh-personal-installer-production-payload-self-check-consumption';command='--production-payload-self-check';status='VERIFIED';exitCode=0;inspectedInstallerSha256=$InstallerInput.Sha256;releaseSetId=$Request.releaseSetId;manifestSha256=$f[0].sha256;manifestSizeBytes=$f[0].sizeBytes;startupStubSha256=$f[1].sha256;startupStubSizeBytes=$f[1].sizeBytes;clientBundleSha256=$f[2].sha256;clientBundleSizeBytes=$f[2].sizeBytes;runtimeSha256=$f[3].sha256;runtimeSizeBytes=$f[3].sizeBytes;canonicalJsonSizeBytes=1;canonicalJsonSha256=('3'*64);canonicalLineSizeBytes=2;canonicalLineSha256=('4'*64);completedAtUtc=$done}};$s=[pscustomobject][ordered]@{command='--production-payload-self-check';status='VERIFIED';exitCode=0;inspectedInstallerSha256=$InstallerInput.Sha256;resultSha256=('0'*64);candidateSetSha256=$Request.candidate.inventorySha256;payloadSetSha256=$Request.installerPayload.inventorySha256;r3SignedClientSetSha256=$Request.r3Evidence.signedClientSetSha256;releaseManifestTrustSha256=$Request.r3Evidence.releaseManifestTrustSha256;releaseManifestTrustProbeSetSha256=$Request.r3Evidence.releaseManifestTrustProbeSetSha256;completedAtUtc=$done};$s.resultSha256=EnterpriseInstallerProductionPayloadSelfCheck\Get-EnterpriseInstallerProductionPayloadSelfCheckResultSha256 $s;return $s}

function Invoke-Case([string]$Name,[string]$Edition='Enterprise',[scriptblock]$Mutate=$null,[string]$Error='',[scriptblock]$Custom=$null){
    $f=New-TestFixture $Edition
    try {
        & $contractsModule { $script:InstallerIssuerAuthMode='' }
        $script:InstallerIssuerSelfCheckMode=''
        if($Mutate){ & $Mutate $f }
        $failure='';$failureStack='';$out=@()
        try { if($Custom){$out=@(& $Custom $f)}else{$out=@(Invoke-ProductionInstallerSigningResponse $f.StateRoot $f.State.HeadSha256 $f.SignedPath $f.KeyPath $f.OutputRoot 1000)} } catch {$failure=$_.Exception.Message;$failureStack=$_.ScriptStackTrace}
        if($Error){
            Assert-Test ($failure-match$Error) "$Name expected $Error got $failure"
            Assert-Test ($out.Count-eq0) 'no success result'
            Assert-NoStage $f
        } else {
            Assert-Test (-not$failure) "$Name success: $failure`n$failureStack"
            Assert-Test ($out.Count-eq1) 'one result';Assert-Test ($out[0].Edition-ceq$Edition) 'result edition';Assert-Test ($out[0].VerifiedInstallerCount-eq1) 'one installer'
            Assert-Test (-not$out[0].AuthenticodeSigningPerformed-and-not$out[0].NetworkPublicationPerformed-and-not$out[0].ReleaseStateChanged) 'offline response flags'
            $responseName=if($Edition-ceq'Personal'){'personal-installer-signing-response.v2.json'}else{'installer-signing-response.v1.json'};$schema=if($Edition-ceq'Personal'){$personalResponseSchemaPath}else{$enterpriseResponseSchemaPath}
            $ri=ProductionReleaseState\Read-StrictProductionJsonFile (Join-Path $f.OutputRoot $responseName) 'actual response' $schema
            $requestInfo=[pscustomobject]@{Value=$f.Request;Sha256=(Get-FileHash $f.RequestPath).Hash.ToLowerInvariant()}
            if($Edition-ceq'Personal'){PersonalInstallerSigningPipeline\Assert-PersonalInstallerSigningResponseV2Contract $requestInfo $ri $f.State.HeadSha256 $f.State.Head.receiptSha256 $f.Trust|Out-Null}else{InstallerSigningContracts\Assert-InstallerSigningResponseContract $requestInfo $ri $f.State.HeadSha256 $f.State.Head.receiptSha256 $f.Trust|Out-Null}
            $ri.Value.planSha256='f'*64;$rejected=$false
            try {if($Edition-ceq'Personal'){PersonalInstallerSigningPipeline\Assert-PersonalInstallerSigningResponseAuthentication $ri.Value $f.Request $f.Trust|Out-Null}else{InstallerSigningContracts\Assert-InstallerSigningResponseAuthentication $ri.Value $f.Request $f.Trust|Out-Null}}catch{$rejected=$true}
            Assert-Test $rejected 'authenticated mutation rejected'
        }
        Assert-Released $f;$script:passed++;Write-Host "PASS: actual Installer issuer $Name"
    } finally {foreach($k in $f.Keys){$k.Dispose()};$f.WrongKey.Dispose()}
}

$fixtureRoot=Join-Path([IO.Path]::GetTempPath())('production-installer-response-'+[Guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($fixtureRoot);$script:caseNumber=0;$script:passed=0
try{
    Invoke-Case 'enterprise-success' Enterprise;Invoke-Case 'personal-success' Personal
    Invoke-Case 'wrong-purpose' Enterprise {param($f)$f.Request.responseAuthentication.purpose='personal-installer-signing-response';Write-TestJson $f.RequestPath $f.Request} 'schema|purpose|trust'
    Invoke-Case 'wrong-key' Enterprise $null 'exact P-256 key|pinned' {param($f)Invoke-ProductionInstallerSigningResponse $f.StateRoot $f.State.HeadSha256 $f.SignedPath $f.WrongKeyPath $f.OutputRoot 1000}
    Invoke-Case 'wrong-request-hash' Enterprise {param($f)$f.R6.data.requestSha256='9'*64;Rewrite-R6 $f} 'exact plan|r6 receipt|purpose-specific trust'
    Invoke-Case 'wrong-r6-closure' Enterprise {param($f)$f.R6.data.payloadSetSha256='9'*64;Rewrite-R6 $f} 'Enterprise r6 receipt|closure'
    Invoke-Case 'expired' Personal {param($f)$now=[DateTimeOffset]::UtcNow;$f.Request.buildExecution.startedAtUtc=ConvertTo-WholeSecondUtc($now.AddMinutes(-33));$f.Request.buildExecution.completedAtUtc=ConvertTo-WholeSecondUtc($now.AddMinutes(-32));$f.Request.createdAtUtc=ConvertTo-WholeSecondUtc($now.AddMinutes(-31));$f.Request.expiresAtUtc=ConvertTo-WholeSecondUtc($now.AddMinutes(-1));$f.R6.data.createdAtUtc=$f.Request.createdAtUtc;$f.R6.data.expiresAtUtc=$f.Request.expiresAtUtc;$bindings=PersonalInstallerSigningPipeline\Get-PersonalInstallerSigningRequestBindings $f.Request;foreach($name in $bindings.Keys){$f.R6.data.$name=$bindings[$name]};Write-TestJson $f.RequestPath $f.Request;$f.R6.data.requestSha256=(Get-FileHash $f.RequestPath).Hash.ToLowerInvariant();Rewrite-R6 $f} 'expired|outside'
    Invoke-Case 'signed-pe-mismatch' Enterprise {param($f)$b=[IO.File]::ReadAllBytes($f.SignedPath);$b[500]++;[IO.File]::WriteAllBytes($f.SignedPath,$b)} 'PE content|transform'
    Invoke-Case 'existing-output' Enterprise {param($f)[void][IO.Directory]::CreateDirectory($f.OutputRoot);[IO.File]::WriteAllText((Join-Path $f.OutputRoot 'sentinel'),'preserve')} 'create-only|already exists'
    Invoke-Case 'overlap-output' Enterprise $null 'overlap' {param($f)Invoke-ProductionInstallerSigningResponse $f.StateRoot $f.State.HeadSha256 $f.SignedPath $f.KeyPath (Join-Path $f.StateRoot 'output') 1000}
    Invoke-Case 'auth-rejected' Enterprise {param($f) & $contractsModule { $script:InstallerIssuerAuthMode='reject' }} 'TEST_AUTH_REJECTED'
    Invoke-Case 'self-check-rejected' Personal {param($f)$script:InstallerIssuerSelfCheckMode='reject'} 'TEST_SELFCHECK_REJECTED'
    Invoke-Case 'post-stage-state-change' Enterprise {param($f) & $stateModule { $script:InstallerIssuerReplayMode='second-change';$script:InstallerIssuerReplayCalls=0 }} 'state changed|publication'
    Write-Host "PASS: Production Installer signing response issuer $script:passed focused cases; two response formats, real schemas/r6 locks/PKCS8/low-S/output cleanup, three explicit seams only. No Authenticode signing claim."
}finally{
    & $stateModule { param($o) Set-Item Function:script:Get-ProductionReleaseState $o; Remove-Variable InstallerIssuerTestState,InstallerIssuerReplayMode,InstallerIssuerReplayCalls -Scope Script -ErrorAction SilentlyContinue } $originalState
    & $contractsModule { param($o) Set-Item Function:script:Get-ExactPeAuthenticodeEvidence $o;Remove-Variable InstallerIssuerAuthMode,InstallerIssuerTimestampUtc -Scope Script -ErrorAction SilentlyContinue } $originalAuth
    Set-Item Function:Invoke-ProductionInstallerPayloadSelfCheck $originalSelfCheck
    foreach($entry in @($loadedFunctions)){if($entry.Existed){Set-Item('Function:'+$entry.Name)$entry.ScriptBlock}else{Remove-Item('Function:'+$entry.Name)-ErrorAction SilentlyContinue}}
    if (Test-Path $fixtureRoot) { $resolved=[IO.Path]::GetFullPath($fixtureRoot);$boundary=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([IO.Path]::DirectorySeparatorChar)+[IO.Path]::DirectorySeparatorChar;if(-not$resolved.StartsWith($boundary,[StringComparison]::OrdinalIgnoreCase)-or[IO.Path]::GetFileName($resolved)-notmatch'^production-installer-response-[0-9a-f]{32}$'){throw'Unsafe fixture cleanup target'}; Remove-Item $resolved -Recurse -Force }
}
