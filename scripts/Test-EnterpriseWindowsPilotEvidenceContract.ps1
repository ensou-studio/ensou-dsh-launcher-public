[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($PSVersionTable.PSEdition -ne 'Core' -or $PSVersionTable.PSVersion -lt [version]'7.4') {
    throw 'Enterprise Windows Pilot contract validation requires PowerShell 7.4 or newer.'
}

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$verifier = Join-Path $PSScriptRoot 'Test-EnterpriseWindowsPilotEvidence.ps1'
$collector = Join-Path $PSScriptRoot 'New-EnterpriseWindowsPilotEvidenceBody.ps1'
$gateContractPath = Join-Path $repositoryRoot 'release\enterprise-windows-pilot-gate-contract-v2.json'
$gateContractSchemaPath = Join-Path $repositoryRoot 'release\schemas\enterprise-windows-pilot-gate-contract-v2.schema.json'
$verificationReportSchemaPath = Join-Path $repositoryRoot 'release\schemas\enterprise-windows-pilot-verification-report-v2.schema.json'
$pilotEvidenceModulePath = Join-Path $repositoryRoot 'release\scripts\EnterpriseProductionPilotEvidence.psm1'
Microsoft.PowerShell.Core\Import-Module `
    -Name $pilotEvidenceModulePath `
    -Force `
    -ErrorAction Stop
$expectedGateContractCanonicalSha256 = 'a7fff40aad6690d12042d62ba1a8deb80e36431abdd62bc4874fa04388d26331'
$releaseContractsAssembly = @(
    (Join-Path $repositoryRoot 'src\Ensou.Dsh.Enterprise.ReleaseContracts\bin\Release\net10.0\Ensou.Dsh.Enterprise.ReleaseContracts.dll'),
    (Join-Path $repositoryRoot 'src\Ensou.Dsh.Enterprise.ReleaseContracts\bin\Debug\net10.0\Ensou.Dsh.Enterprise.ReleaseContracts.dll')
) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if ([string]::IsNullOrWhiteSpace([string]$releaseContractsAssembly)) {
    throw 'Build the solution before running the Windows Pilot evidence contract.'
}
Add-Type -Path $releaseContractsAssembly

$tempParent = [IO.Path]::TrimEndingDirectorySeparator([IO.Path]::GetFullPath([IO.Path]::GetTempPath()))
$tempRoot = Join-Path $tempParent ('ensou-enterprise-windows-pilot-v2-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($tempRoot) | Out-Null

$gateContractText = Get-Content -Raw -LiteralPath $gateContractPath
if (-not (Test-Json -Json $gateContractText -SchemaFile $gateContractSchemaPath -ErrorAction Stop)) {
    throw 'Enterprise Windows Pilot gate contract does not satisfy its exact schema.'
}
$gateContract = $gateContractText | ConvertFrom-Json -Depth 16
$gateContractCanonicalBytes = [Text.UTF8Encoding]::new($false, $true).GetBytes(
    ($gateContract | ConvertTo-Json -Depth 16 -Compress))
$gateContractCanonicalSha256 = [Convert]::ToHexString(
    [Security.Cryptography.SHA256]::HashData($gateContractCanonicalBytes)).ToLowerInvariant()
if ($gateContractCanonicalSha256 -cne $expectedGateContractCanonicalSha256) {
    throw 'Enterprise Windows Pilot gate contract does not match the pinned canonical contract.'
}
$gateExpectations = @($gateContract.gates | ForEach-Object {
    ,@(
        [string]$_.gate,
        [string]$_.role,
        [string]$_.state,
        [string]$_.networkMode,
        [string]$_.resultCode,
        [string]$_.deviceLane,
        [int]$_.activeReleaseIndex,
        $(if ($null -eq $_.rollbackReleaseIndex) { $null } else { [int]$_.rollbackReleaseIndex }),
        $(if ($null -eq $_.attemptedReleaseIndex) { $null } else { [int]$_.attemptedReleaseIndex })
    )
})
for ($index = 0; $index -lt $gateExpectations.Count; $index++) {
    if ([int]$gateContract.gates[$index].sequenceNumber -ne $index + 1) {
        throw 'Enterprise Windows Pilot gate contract sequence is not exact.'
    }
}

function Write-JsonFile {
    param([string]$Path,$Value)
    $json = $Value | ConvertTo-Json -Depth 64
    [IO.File]::WriteAllText($Path,$json+[Environment]::NewLine,[Text.UTF8Encoding]::new($false))
    return $Path
}
function Write-BytesFile { param([string]$Path,[byte[]]$Bytes) [IO.File]::WriteAllBytes($Path,$Bytes); return $Path }
function Get-Sha256Bytes { param([byte[]]$Bytes) [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Bytes)).ToLowerInvariant() }
function Get-FileReference {
    param([string]$Path)
    $item=Get-Item -LiteralPath $Path
    return [ordered]@{path=$item.FullName;sizeBytes=$item.Length;sha256=(Get-FileHash -Algorithm SHA256 -LiteralPath $item.FullName).Hash.ToLowerInvariant()}
}
function Copy-JsonValue { param($Value) return ($Value|ConvertTo-Json -Depth 64)|ConvertFrom-Json -Depth 64 }
function Convert-Base64Url {
    param([byte[]]$Bytes)
    return [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+','-').Replace('/','_')
}
function New-Signature {
    param([Security.Cryptography.ECDsa]$Signer,[string]$KeyId,[byte[]]$Payload)
    return [ordered]@{algorithm='ES256';keyId=$KeyId;value=Convert-Base64Url ($Signer.SignData(
        $Payload,[Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation))}
}
function New-ReleaseSignature {
    param([Security.Cryptography.ECDsa]$Signer,[string]$KeyId,[byte[]]$Payload)
    $signature=[Ensou.Dsh.Enterprise.Installation.EnterpriseReleaseSignature]::new()
    $signature.Algorithm='ES256';$signature.KeyId=$KeyId
    $signature.Value=Convert-Base64Url ($Signer.SignData($Payload,
        [Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation))
    return $signature
}
function New-ReleaseManifest {
    param([int]$Index,[Security.Cryptography.ECDsa]$Signer,[string]$KeyId,[string]$KeyX,[string]$KeyY)
    $releaseSetId="enterprise-pilot-contract-$($Index+1)"
    $unsigned=[Ensou.Dsh.Enterprise.Installation.EnterpriseReleaseSignature]::new()
    $unsigned.Algorithm='ES256';$unsigned.KeyId=$KeyId;$unsigned.Value=Convert-Base64Url ([byte[]]::new(64))
    $manifest=[Ensou.Dsh.Enterprise.Installation.EnterpriseReleaseSetManifest]::new()
    $manifest.SchemaVersion=2;$manifest.Product='ensou-dsh-enterprise';$manifest.Environment='production';$manifest.Channel='pilot'
    $manifest.ReleaseSetId=$releaseSetId;$manifest.Generation=$Index+1;$manifest.Sequence=100+$Index;$manifest.MinAcceptedSequence=0
    $manifest.IssuedAtUtc=[DateTimeOffset]::UtcNow.AddMinutes(-2);$manifest.ExpiresAtUtc=[DateTimeOffset]::UtcNow.AddDays(7)
    $stub=[Ensou.Dsh.Enterprise.Installation.EnterpriseStartupStubCompatibility]::new();$stub.MinimumProtocol=1;$stub.MaximumProtocol=1
    $manifest.StartupStub=$stub;$manifest.RevokedReleaseSetIds=[string[]]@();$manifest.Signature=$unsigned
    $artifacts=[Collections.Generic.List[Ensou.Dsh.Enterprise.Installation.EnterpriseReleaseArtifact]]::new()
    foreach($component in @('launcher','runtime','plugin-policy')) {
        $artifact=[Ensou.Dsh.Enterprise.Installation.EnterpriseReleaseArtifact]::new()
        $artifact.Component=$component;$artifact.ReleaseId="$component-contract-$($Index+1)"
        $artifact.Uri=[Uri]"https://artifacts.contoso.cn/releases/$releaseSetId/$component.zip"
        $artifact.SizeBytes=1;$artifact.Sha256=('a'*64);$artifact.CompleteTreeSha256=('b'*64);$artifact.Signature=$unsigned
        $artifacts.Add($artifact)
    }
    $manifest.Artifacts=[Ensou.Dsh.Enterprise.Installation.EnterpriseReleaseArtifact[]]$artifacts.ToArray()
    foreach($artifact in $manifest.Artifacts) {
        $artifact.Signature=New-ReleaseSignature $Signer $KeyId ([Ensou.Dsh.Enterprise.Installation.EnterpriseReleaseCanonicalJson]::ArtifactPayload($manifest,$artifact))
    }
    $manifest.Signature=New-ReleaseSignature $Signer $KeyId ([Ensou.Dsh.Enterprise.Installation.EnterpriseReleaseCanonicalJson]::ManifestPayload($manifest))
    $options=[Text.Json.JsonSerializerOptions]::new([Text.Json.JsonSerializerDefaults]::Web)
    $options.WriteIndented=$true;$options.IgnoreReadOnlyProperties=$true
    $bytes=[Text.Json.JsonSerializer]::SerializeToUtf8Bytes([object]$manifest,$manifest.GetType(),$options)
    $path=Join-Path $tempRoot "$releaseSetId.release-set.v2.json";Write-BytesFile $path $bytes|Out-Null
    $runtimeHash=Get-Sha256Bytes ([Text.Encoding]::UTF8.GetBytes("runtime-entry-$Index"))
    $file=Get-FileReference $path
    return [ordered]@{stage=@('baseline','first-update','second-update','failed-health-probe','recovery-target')[$Index]
      releaseSetId=$releaseSetId;generation=$Index+1;sequence=100+$Index;manifestSha256=$file.sha256
      runtimeEntryPointSha256=$runtimeHash;manifest=$file}
}
function Get-ReleaseIdentity {
    param($Release)
    return [ordered]@{releaseSetId=$Release.releaseSetId;generation=$Release.generation;sequence=$Release.sequence
      manifestSha256=$Release.manifestSha256;runtimeEntryPointSha256=$Release.runtimeEntryPointSha256}
}
function Write-SignedEvidence {
    param($Body,[string]$Name,[Security.Cryptography.ECDsa]$Signer,[string]$KeyId)
    $bodyPath=Join-Path $tempRoot "$Name.body.v2.json";Write-JsonFile $bodyPath $Body|Out-Null
    $bodyBytes=[IO.File]::ReadAllBytes($bodyPath);$bodySha=Get-Sha256Bytes $bodyBytes
    $envelope=[ordered]@{schemaVersion=2;evidenceType='ensou-dsh-enterprise-windows-pilot-evidence-envelope'
      body=[ordered]@{schemaVersion=2;evidenceType='ensou-dsh-enterprise-windows-pilot-evidence-body';sizeBytes=$bodyBytes.Length;sha256=$bodySha}
      attestation=[ordered]@{algorithm='ES256';keyId=$KeyId;value=Convert-Base64Url ([byte[]]::new(64))}}
    $payload=[Text.Encoding]::UTF8.GetBytes((@('ensou-dsh-enterprise-windows-pilot-evidence-attestation-v2','2',
      $envelope.evidenceType,'2',$envelope.body.evidenceType,[string]$envelope.body.sizeBytes,$bodySha)-join"`n"))
    $envelope.attestation=New-Signature $Signer $KeyId $payload
    $envelopePath=Join-Path $tempRoot "$Name.envelope.v2.json";Write-JsonFile $envelopePath $envelope|Out-Null
    return [pscustomobject]@{BodyPath=$bodyPath;EnvelopePath=$envelopePath;Envelope=$envelope}
}
function Write-SignedBodyFileEvidence {
    param([string]$BodyPath,[string]$Name,[Security.Cryptography.ECDsa]$Signer,[string]$KeyId)
    $bodyBytes=[IO.File]::ReadAllBytes($BodyPath);$bodySha=Get-Sha256Bytes $bodyBytes
    $envelope=[ordered]@{schemaVersion=2;evidenceType='ensou-dsh-enterprise-windows-pilot-evidence-envelope'
      body=[ordered]@{schemaVersion=2;evidenceType='ensou-dsh-enterprise-windows-pilot-evidence-body';sizeBytes=$bodyBytes.Length;sha256=$bodySha}
      attestation=[ordered]@{algorithm='ES256';keyId=$KeyId;value=Convert-Base64Url ([byte[]]::new(64))}}
    $payload=[Text.Encoding]::UTF8.GetBytes((@('ensou-dsh-enterprise-windows-pilot-evidence-attestation-v2','2',
      $envelope.evidenceType,'2',$envelope.body.evidenceType,[string]$envelope.body.sizeBytes,$bodySha)-join"`n"))
    $envelope.attestation=New-Signature $Signer $KeyId $payload
    $envelopePath=Join-Path $tempRoot "$Name.envelope.v2.json";Write-JsonFile $envelopePath $envelope|Out-Null
    return [pscustomobject]@{BodyPath=$BodyPath;EnvelopePath=$envelopePath;Envelope=$envelope}
}
function Invoke-CollectorProcess {
    param([string]$CollectionPath,[string]$BodyPath,[string]$RequestPath)
    $start=[Diagnostics.ProcessStartInfo]::new()
    $start.FileName=Join-Path $PSHOME 'pwsh.exe';$start.UseShellExecute=$false;$start.CreateNoWindow=$true
    $start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
    foreach($argument in @('-NoProfile','-File',$collector,'-CollectionPath',$CollectionPath,
      '-BodyPath',$BodyPath,'-AttestationRequestPath',$RequestPath)){$start.ArgumentList.Add($argument)}
    $process=[Diagnostics.Process]::Start($start)
    if($null-eq$process){throw 'Pilot collector test process did not start.'}
    try {
      $stdoutTask=$process.StandardOutput.ReadToEndAsync();$stderrTask=$process.StandardError.ReadToEndAsync()
      if(-not$process.WaitForExit(120000)){$process.Kill($true);throw 'Pilot collector test process timed out.'}
      $stdout=$stdoutTask.GetAwaiter().GetResult();$stderr=$stderrTask.GetAwaiter().GetResult()
      if($process.ExitCode-ne0){throw "Pilot collector process rejected the fixture (exit $($process.ExitCode)): $stderr"}
      return $stdout
    } finally {$process.Dispose()}
}
function Invoke-Collector {
    param($Collection,[string]$Name)
    $collectionPath=Join-Path $tempRoot "$Name.collection.v1.json"
    $bodyPath=Join-Path $tempRoot "$Name.collected.body.v2.json"
    $requestPath=Join-Path $tempRoot "$Name.attestation-request.v1.json"
    Write-JsonFile $collectionPath $Collection|Out-Null
    Invoke-CollectorProcess $collectionPath $bodyPath $requestPath|Out-Null
    return [pscustomobject]@{CollectionPath=$collectionPath;BodyPath=$bodyPath;RequestPath=$requestPath}
}
function Invoke-ContractVerifier {
    param($Fixture,[string]$EvidenceKeyId,[string]$EvidenceKeyX,[string]$EvidenceKeyY)
    return & $verifier -EvidenceEnvelopePath $Fixture.EnvelopePath -EvidenceBodyPath $Fixture.BodyPath `
      -ContractOnly -ContractPilotEvidenceKeyId $EvidenceKeyId -ContractPilotEvidenceKeyX $EvidenceKeyX `
      -ContractPilotEvidenceKeyY $EvidenceKeyY -ContractReleaseKeyId $releaseKeyId `
      -ContractReleaseKeyX $releaseKeyX -ContractReleaseKeyY $releaseKeyY
}
function Assert-Rejected {
    param([string]$Name,$Fixture)
    $rejected=$false
    try { Invoke-ContractVerifier $Fixture $evidenceKeyId $evidenceKeyX $evidenceKeyY|Out-Null }
    catch { $rejected=$true }
    if(-not $rejected){throw "$Name was not rejected."}
}
function Assert-CollectorRejected {
    param([string]$Name,$Collection,[string]$FixtureName)
    $rejected=$false
    try { Invoke-Collector $Collection $FixtureName|Out-Null }
    catch { $rejected=$true }
    if(-not $rejected){throw "$Name was not rejected by the Pilot collector."}
}

function Assert-CollectorCodeLevelArraySemantics {
    param($ValidCollection)
    $tokens=$null;$parseErrors=$null
    $collectorAst=[Management.Automation.Language.Parser]::ParseFile(
      $collector,[ref]$tokens,[ref]$parseErrors)
    if($parseErrors.Count-ne0){throw 'Pilot collector source did not parse for compatibility validation.'}
    $validatorDefinitions=@($collectorAst.FindAll({
      param($node)
      $node-is[Management.Automation.Language.FunctionDefinitionAst]-and
        $node.Name-ceq'Assert-CollectionArraySemantics'
    },$true))
    if($validatorDefinitions.Count-ne1){throw 'Pilot collector must define exactly one code-level array validator.'}
    $validatorText=$validatorDefinitions[0].Body.Extent.Text
    if($validatorText-match'(?i)Test-Json'){throw 'Code-level array validation may not delegate to the JSON-schema engine.'}
    $validator=[scriptblock]::Create($validatorText.Substring(1,$validatorText.Length-2))
    try{&$validator $ValidCollection}catch{throw "Code-level array validator rejected the valid fixture: $_"}

    $invalidFixtures=[Collections.Generic.List[object]]::new()
    $wrongLaneOrder=Copy-JsonValue $ValidCollection
    $wrongLaneOrder.deviceLanes=@($wrongLaneOrder.deviceLanes[1],$wrongLaneOrder.deviceLanes[0])
    $invalidFixtures.Add($wrongLaneOrder)
    $wrongStageOrder=Copy-JsonValue $ValidCollection
    $stage=$wrongStageOrder.releaseChain[0];$wrongStageOrder.releaseChain[0]=$wrongStageOrder.releaseChain[1];$wrongStageOrder.releaseChain[1]=$stage
    $invalidFixtures.Add($wrongStageOrder)
    $duplicateRole=Copy-JsonValue $ValidCollection
    $duplicateRole.signedExecutables[1].role=$duplicateRole.signedExecutables[0].role
    $invalidFixtures.Add($duplicateRole)
    $shortGateList=Copy-JsonValue $ValidCollection
    $shortGateList.gateReceiptPaths=@($shortGateList.gateReceiptPaths|Select-Object -First 20)
    $invalidFixtures.Add($shortGateList)
    $caseAliasGatePath=Copy-JsonValue $ValidCollection
    $caseAliasGatePath.gateReceiptPaths[1]=([string]$caseAliasGatePath.gateReceiptPaths[0]).ToUpperInvariant()
    $invalidFixtures.Add($caseAliasGatePath)

    foreach($invalidFixture in $invalidFixtures){
      $rejected=$false
      try{&$validator $invalidFixture}catch{$rejected=$true}
      if(-not$rejected){throw 'Code-level array validator accepted incompatible draft-2020-12 array semantics.'}
    }
}

function Assert-PathGuardRaceProtection {
    $raceRoot=Join-Path $tempRoot 'path-identity-race'
    $lockedAncestor=Join-Path $raceRoot 'locked-ancestor'
    $lockedParent=Join-Path $lockedAncestor 'parent'
    $lockedMoved=Join-Path $raceRoot 'locked-ancestor-moved'
    [IO.Directory]::CreateDirectory($lockedParent)|Out-Null
    $lockedFile=Join-Path $lockedParent 'pilot.json'
    [IO.File]::WriteAllText($lockedFile,'{"trusted":true}',[Text.UTF8Encoding]::new($false))

    $directoryGuard=[Ensou.Dsh.PilotEvidence.PathGuard]::OpenDirectory($lockedParent)
    try {
        if([string]::IsNullOrWhiteSpace($directoryGuard.Identity) -or
          [string]$directoryGuard.FinalPath -cne [IO.Path]::TrimEndingDirectorySeparator([IO.Path]::GetFullPath($lockedParent))) {
            throw 'Directory guard did not bind a final path and volume/file identity.'
        }
        $opened=[Ensou.Dsh.PilotEvidence.PathGuard]::OpenReadFile($lockedFile)
        try {
            [Ensou.Dsh.PilotEvidence.PathGuard]::AssertFileIdentity($lockedFile,$opened.FinalPath,$opened.Identity)
            $identityMismatchRejected=$false
            try{[Ensou.Dsh.PilotEvidence.PathGuard]::AssertFileIdentity($lockedFile,$opened.FinalPath,('0'*49))}catch{$identityMismatchRejected=$true}
            if(-not $identityMismatchRejected){throw 'Pilot identity probe accepted a different volume/file identity.'}

            $ancestorSwapDenied=$false
            try{[IO.Directory]::Move($lockedAncestor,$lockedMoved)}catch{$ancestorSwapDenied=$true}
            if($ancestorSwapDenied) {
                [Ensou.Dsh.PilotEvidence.PathGuard]::AssertDirectoryIdentity($lockedParent,$directoryGuard.FinalPath,$directoryGuard.Identity)
                [Ensou.Dsh.PilotEvidence.PathGuard]::AssertFileIdentity($lockedFile,$opened.FinalPath,$opened.Identity)
            } else {
                [IO.Directory]::CreateDirectory($lockedParent)|Out-Null
                [IO.File]::WriteAllText($lockedFile,'{"trusted":false}',[Text.UTF8Encoding]::new($false))
                $directorySwapRejected=$false
                try{[Ensou.Dsh.PilotEvidence.PathGuard]::AssertDirectoryIdentity($lockedParent,$directoryGuard.FinalPath,$directoryGuard.Identity)}catch{$directorySwapRejected=$true}
                if(-not $directorySwapRejected){throw 'Directory identity probe accepted a replaced ancestor.'}
                $fileSwapRejected=$false
                try{[Ensou.Dsh.PilotEvidence.PathGuard]::AssertFileIdentity($lockedFile,$opened.FinalPath,$opened.Identity)}catch{$fileSwapRejected=$true}
                if(-not $fileSwapRejected){throw 'File identity probe accepted a replaced ancestor.'}
            }
        } finally {$opened.Dispose()}
    } finally {$directoryGuard.Dispose()}

    $precheckedParent=Join-Path $raceRoot 'prechecked-parent'
    $precheckedMoved=Join-Path $raceRoot 'prechecked-parent-moved'
    $attackerParent=Join-Path $raceRoot 'attacker-parent'
    [IO.Directory]::CreateDirectory($precheckedParent)|Out-Null
    [IO.Directory]::CreateDirectory($attackerParent)|Out-Null
    $precheckedFile=Join-Path $precheckedParent 'pilot.json'
    [IO.File]::WriteAllText($precheckedFile,'{"trusted":true}',[Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $attackerParent 'pilot.json'),'{"trusted":false}',[Text.UTF8Encoding]::new($false))
    $legacyPrecheck=Get-Item -LiteralPath $precheckedFile -Force
    if($legacyPrecheck.PSIsContainer -or ($legacyPrecheck.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne 0){throw 'Race fixture precheck failed.'}
    [IO.Directory]::Move($precheckedParent,$precheckedMoved)
    $junction=$null
    try {
        $junction=New-Item -ItemType Junction -Path $precheckedParent -Target $attackerParent -Force
        $preOpenRaceRejected=$false
        $raceOpened=$null
        try{$raceOpened=[Ensou.Dsh.PilotEvidence.PathGuard]::OpenReadFile($precheckedFile)}catch{$preOpenRaceRejected=$true}
        finally{if($null-ne $raceOpened){$raceOpened.Dispose()}}
        if(-not $preOpenRaceRejected){throw 'Handle-first guard accepted a reparse/ancestor swap after legacy precheck.'}
    } finally {
        if($null-ne $junction -and (Test-Path -LiteralPath $precheckedParent)) {[IO.Directory]::Delete($precheckedParent)}
    }

    $outputParent=Join-Path $raceRoot 'output-parent'
    $outputMoved=Join-Path $raceRoot 'output-parent-moved'
    $outputAttacker=Join-Path $raceRoot 'output-attacker'
    [IO.Directory]::CreateDirectory($outputParent)|Out-Null
    [IO.Directory]::CreateDirectory($outputAttacker)|Out-Null
    $outputPrecheck=Get-Item -LiteralPath $outputParent -Force
    if(-not $outputPrecheck.PSIsContainer){throw 'Output race fixture precheck failed.'}
    [IO.Directory]::Move($outputParent,$outputMoved)
    $outputJunction=$null
    try {
        $outputJunction=New-Item -ItemType Junction -Path $outputParent -Target $outputAttacker -Force
        $outputSwapRejected=$false
        $outputGuard=$null
        try{$outputGuard=[Ensou.Dsh.PilotEvidence.PathGuard]::OpenDirectory($outputParent)}catch{$outputSwapRejected=$true}
        finally{if($null-ne $outputGuard){$outputGuard.Dispose()}}
        if(-not $outputSwapRejected){throw 'Handle-first output guard accepted a reparse/ancestor swap.'}
        if(Test-Path -LiteralPath (Join-Path $outputAttacker 'verification.json')){throw 'Rejected output swap created a report in the attacker directory.'}
    } finally {
        if($null-ne $outputJunction -and (Test-Path -LiteralPath $outputParent)){[IO.Directory]::Delete($outputParent)}
    }

    $extendedPath='\\?\'+(Join-Path $precheckedMoved 'pilot.json')
    $extendedOpened=[Ensou.Dsh.PilotEvidence.PathGuard]::OpenReadFile($extendedPath)
    try {
        if([string]$extendedOpened.FinalPath -cne [IO.Path]::GetFullPath((Join-Path $precheckedMoved 'pilot.json'))){
            throw 'Extended-length path normalization changed the bound file.'
        }
    } finally {$extendedOpened.Dispose()}
}

try {
    $evidenceSigner=[Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve+NamedCurves]::nistP256)
    $releaseSigner=[Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve+NamedCurves]::nistP256)
    $attackerSigner=[Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve+NamedCurves]::nistP256)
    $verifierSigner=[Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve+NamedCurves]::nistP256)
    try {
        $evidenceKeyId='contract-pilot-evidence-key';$releaseKeyId='contract-release-key';$attackerKeyId='attacker-selected-key';$verifierKeyId='contract-windows-verifier-key'
        $evidenceParams=$evidenceSigner.ExportParameters($false);$releaseParams=$releaseSigner.ExportParameters($false);$attackerParams=$attackerSigner.ExportParameters($false);$verifierParams=$verifierSigner.ExportParameters($false)
        $evidenceKeyX=Convert-Base64Url $evidenceParams.Q.X;$evidenceKeyY=Convert-Base64Url $evidenceParams.Q.Y
        $releaseKeyX=Convert-Base64Url $releaseParams.Q.X;$releaseKeyY=Convert-Base64Url $releaseParams.Q.Y
        $attackerKeyX=Convert-Base64Url $attackerParams.Q.X;$attackerKeyY=Convert-Base64Url $attackerParams.Q.Y
        $verifierKeyX=Convert-Base64Url $verifierParams.Q.X;$verifierKeyY=Convert-Base64Url $verifierParams.Q.Y
        $verifierKeyPath=Join-Path $tempRoot 'windows-pilot-verifier.pkcs8'
        $verifierKeyBytes=$verifierSigner.ExportPkcs8PrivateKey()
        try { Write-BytesFile $verifierKeyPath $verifierKeyBytes | Out-Null }
        finally { [Security.Cryptography.CryptographicOperations]::ZeroMemory($verifierKeyBytes) }
        $hashA='a'*64;$hashB='b'*64;$hashC='c'*64;$testRunId=[Guid]::NewGuid().ToString('D');$audienceId=[Guid]::NewGuid().ToString('D')

        $releaseChain=@();for($index=0; $index -lt 5; $index++){$releaseChain+=New-ReleaseManifest $index $releaseSigner $releaseKeyId $releaseKeyX $releaseKeyY}
        $executableNames=[ordered]@{'release-publisher'='Ensou.Dsh.Enterprise.ReleasePublisher.exe';installer='Ensou.Dsh.Enterprise.Installer.exe';bootstrapper='Ensou.Dsh.Enterprise.Bootstrapper.exe';launcher='Ensou.Dsh.Enterprise.Launcher.exe';'client-bootstrapper'='Ensou.Dsh.Enterprise.ClientBootstrapper.exe';maintenance='Ensou.Dsh.Enterprise.Maintenance.exe'}
        $signedExecutables=@();$executableHashes=@{}
        foreach($role in $executableNames.Keys){$dir=Join-Path $tempRoot $role;[IO.Directory]::CreateDirectory($dir)|Out-Null
          $path=Join-Path $dir $executableNames[$role];Write-BytesFile $path ([Text.Encoding]::UTF8.GetBytes("contract executable $role"))|Out-Null
          $file=Get-FileReference $path;$executableHashes[$role]=$file.sha256;$signedExecutables+=[ordered]@{role=$role;file=$file}}

        $dummyPaths=@{};foreach($name in @('ledger','runtime-metadata','runtime-admission','plugin-metadata','brand-receipt','brand-evidence','migration-report','local-cert')){
          $path=Join-Path $tempRoot "$name.json";Write-JsonFile $path ([ordered]@{schemaVersion=1;kind=$name;sha256=$hashA})|Out-Null;$dummyPaths[$name]=$path}
        $readinessConfigPath=Join-Path $tempRoot 'readiness.config.v1.json'
        $readinessConfig=[ordered]@{schemaVersion=1;environment='production';channel='pilot';runtimeIdentifier='win-x64';layoutProfile='enterprise';artifactAuthorization='SIGNED_RELEASE_SET'
          releaseSetId=$releaseChain[4].releaseSetId;generation=$releaseChain[4].generation;sequence=$releaseChain[4].sequence;minAcceptedSequence=0
          releaseDirectory=$tempRoot;publisherLedgerPath=$dummyPaths.ledger;publisherLedgerSha256=$hashA
          installerExecutablePath=$signedExecutables[1].file.path;bootstrapperExecutablePath=$signedExecutables[2].file.path;launcherExecutablePath=$signedExecutables[3].file.path
          clientBootstrapperExecutablePath=$signedExecutables[4].file.path;maintenanceExecutablePath=$signedExecutables[5].file.path
          runtimeSourceMetadataPath=$dummyPaths.'runtime-metadata';runtimeAdmissionReceiptPath=$dummyPaths.'runtime-admission';pluginPolicyMetadataPath=$dummyPaths.'plugin-metadata'
          launcherTrust=[ordered]@{updateManifestUri='https://pilot.contoso.cn/v2/channels/pilot/release-set.v2.json';updateManifestOrigin='https://pilot.contoso.cn/'
            updateArtifactOrigin='https://artifacts.contoso.cn/';releaseKeyId=$releaseKeyId;releaseKeyX=$releaseKeyX;releaseKeyY=$releaseKeyY
            controlPlaneOrigin='https://control.contoso.cn/';authorizationOrigin='https://auth.contoso.cn/';gatewayOrigin='https://gateway.contoso.cn/'
            managedArtifactOrigin='https://managed.contoso.cn/';leaseKeyId='contract-lease-key';leaseKeyX=$evidenceKeyX;leaseKeyY=$evidenceKeyY
            authenticodeSignerSha256Thumbprint=$hashA}
          runtimeAdmissionKey=[ordered]@{keyId='contract-runtime-key';x=$evidenceKeyX;y=$evidenceKeyY};brandAuthorizationKey=[ordered]@{keyId='contract-brand-key';x=$evidenceKeyX;y=$evidenceKeyY}
          brandAuthorization=[ordered]@{receiptPath=$dummyPaths.'brand-receipt';receiptSha256=$hashA;evidencePath=$dummyPaths.'brand-evidence';evidenceSha256=$hashB;distributionAudienceId=$audienceId}
          startupUpdateContract=[ordered]@{checkOnEveryStartup=$true;atomicReleaseSetActivation=$true;bootstrapHealthRollback=$true;maximumOfflineGraceHours=168}
          localDataCompatibilityEvidence=[ordered]@{fromUpstreamTag='dsh-v0.1.1-rc.1';toUpstreamTag='dsh-v0.1.1-rc.2';sourceRuntimeArchiveSha256=$hashA;targetRuntimeArchiveSha256=$hashB
            reportPath=$dummyPaths.'migration-report';reportSha256=$hashA;certification=[ordered]@{receiptPath=$dummyPaths.'local-cert';receiptSha256=$hashB;certificationAudienceId=$audienceId}}}
        Write-JsonFile $readinessConfigPath $readinessConfig|Out-Null
        $readinessReportPath=Join-Path $tempRoot 'readiness.report.v1.json'
        $readinessReport=[ordered]@{schemaVersion=1;reportType='ensou-dsh-enterprise-pilot-readiness';decision='ADMIT';generatedAtUtc=[DateTimeOffset]::UtcNow.ToString('o')
          environment='production';channel='pilot';publisherExecutableSha256=$executableHashes['release-publisher'];releaseSetId=$releaseChain[4].releaseSetId
          generation=$releaseChain[4].generation;sequence=$releaseChain[4].sequence;updateContractId='release-set-v2-startup-check-atomic-health-rollback-offline-7d-plugin-policy-v1'
          brandAuthorizationId=[Guid]::NewGuid().ToString('D');brandAuthorizationKeyId='contract-brand-key';brandAuthorizationReceiptSha256=$hashA;brandAuthorizationExpiresAtUtc=[DateTimeOffset]::UtcNow.AddDays(1).ToString('o')
          localDataCertificationId=[Guid]::NewGuid().ToString('D');localDataCertificationKeyId='contract-local-data-key';localDataCertificationReceiptSha256=$hashB
          localDataCertificationExpiresAtUtc=[DateTimeOffset]::UtcNow.AddDays(1).ToString('o');checks=@([ordered]@{id='contract-fixture';status='PASS';evidence='strict fixture'})
          failureCode=$null;failureMessage=$null}
        Write-JsonFile $readinessReportPath $readinessReport|Out-Null

        $runStart=[DateTimeOffset]::UtcNow.AddMinutes(-20);$cursor=$runStart.AddSeconds(1);$observerHash=Get-Sha256Bytes ([Text.Encoding]::UTF8.GetBytes('independent pilot observer'))
        $gates=@()
        for($index=0; $index -lt $gateExpectations.Count; $index++){
          $expectation=$gateExpectations[$index];$started=$cursor;$duration=if($index -eq 1){[TimeSpan]::FromMinutes(15)}else{[TimeSpan]::FromSeconds(1)}
          $completed=$started+$duration;$cursor=$completed.AddSeconds(1)
          $active=Get-ReleaseIdentity $releaseChain[[int]$expectation[6]]
          $rollback=if($null -eq $expectation[7]){$null}else{Get-ReleaseIdentity $releaseChain[[int]$expectation[7]]}
          $attempted=if($null -eq $expectation[8]){$null}else{Get-ReleaseIdentity $releaseChain[[int]$expectation[8]]}
          $processHash=switch([string]$expectation[1]){'runtime'{$active.runtimeEntryPointSha256}'previous-runtime'{$active.runtimeEntryPointSha256}'pilot-observer'{$observerHash}default{$executableHashes[[string]$expectation[1]]}}
          $externalHash=Get-Sha256Bytes ([Text.Encoding]::UTF8.GetBytes("external $index $($expectation[0])"))
          $gates+=[ordered]@{schemaVersion=2;receiptType='ensou-dsh-enterprise-windows-pilot-gate-receipt';sequenceNumber=$index+1
            testRunId=$testRunId;customerAudienceId=$audienceId;gate=$expectation[0];status='PASS';deviceLane=$expectation[5]
            startedAtUtc=$started.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ');completedAtUtc=$completed.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')
            observedProcess=[ordered]@{role=$expectation[1];state=$expectation[2];executableSha256=$processHash};networkMode=$expectation[3];resultCode=$expectation[4]
            releaseTuple=[ordered]@{active=$active;rollbackTarget=$rollback;attempted=$attempted}
            externalEvidence=@([ordered]@{evidenceClass='process-inventory';mediaType='application/vnd.ensou.redacted-structured-evidence+json';sizeBytes=128
              sha256=$externalHash;custodianIdSha256=$hashC})}
        }
        $runEnd=$cursor.AddSeconds(1)
        $body=[ordered]@{schemaVersion=2;evidenceType='ensou-dsh-enterprise-windows-pilot-evidence-body';pilotDecision='ADMIT';product='ensou-dsh-enterprise'
          environment='production';channel='pilot';runtimeIdentifier='win-x64';layoutProfile='enterprise';testRunId=$testRunId;customerAudienceId=$audienceId
          startedAtUtc=$runStart.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ');completedAtUtc=$runEnd.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')
          pilotManifestUri='https://pilot.contoso.cn/v2/channels/pilot/release-set.v2.json'
          readiness=[ordered]@{config=Get-FileReference $readinessConfigPath;report=Get-FileReference $readinessReportPath;target=Get-ReleaseIdentity $releaseChain[4]}
          deviceLanes=@([ordered]@{lane='clean-install';osFamily='windows';osBuild='11.26100.1';nativeArchitecture='x64';standardUser=$true;installationIdSha256=$hashA;deviceInventorySha256=$hashB},
            [ordered]@{lane='legacy-migration';osFamily='windows';osBuild='10.19045.1';nativeArchitecture='x64';standardUser=$true;installationIdSha256=$hashB;deviceInventorySha256=$hashC})
          pilotObserverExecutableSha256=$observerHash
          weComAdmission=[ordered]@{authorizationMethod='WECOM';adminInviteFallbackEnabled=$false;authorizedEmployeeSubjectSha256=$hashA;unregisteredEmployeeSubjectSha256=$hashB
            installationIdSha256=$hashA;deviceProofPublicKeySha256=$hashC;boundDeviceCount=1;restartRequiredQr=$false
            unregisteredDenialErrorCode='WECOM_IDENTITY_NOT_PREREGISTERED';contactAdministratorMessageVisible=$true;secondDeviceDenialErrorCode='DEVICE_ALREADY_BOUND'
            revocationClientState='DEVICE_REVOKED_RESET_REQUIRED';apiPolicyRevocationClientState='API_DISABLED'}
          legacySource=[ordered]@{sourceType='prior-ensou-dsh-enterprise-installation';version='legacy-v1';inventorySha256=$hashA;inventorySizeBytes=128}
          localDataWitness=[ordered]@{historyTreeBeforeSha256=$hashA;historyTreeAfterSha256=$hashA;workspaceTreeBeforeSha256=$hashB;workspaceTreeAfterSha256=$hashB}
          releaseChain=$releaseChain;signedExecutables=$signedExecutables;gates=$gates}

        $observerPath=Join-Path $tempRoot 'controlled-pilot-observer.exe'
        Write-BytesFile $observerPath ([Text.Encoding]::UTF8.GetBytes('independent pilot observer'))|Out-Null
        $cleanInventoryPath=Join-Path $tempRoot 'clean-device-inventory.json'
        $legacyDeviceInventoryPath=Join-Path $tempRoot 'legacy-device-inventory.json'
        $legacySourceInventoryPath=Join-Path $tempRoot 'legacy-source-inventory.json'
        Write-JsonFile $cleanInventoryPath ([ordered]@{schemaVersion=1;lane='clean-install';platform='windows-x64'})|Out-Null
        Write-JsonFile $legacyDeviceInventoryPath ([ordered]@{schemaVersion=1;lane='legacy-migration';platform='windows-x64'})|Out-Null
        Write-JsonFile $legacySourceInventoryPath ([ordered]@{schemaVersion=1;source='prior-ensou-dsh-enterprise-installation'})|Out-Null
        $gateReceiptPaths=@()
        for($index=0;$index -lt $gates.Count;$index++){
          $gatePath=Join-Path $tempRoot ('gate-{0:D2}.receipt.v2.json' -f ($index+1))
          Write-JsonFile $gatePath $gates[$index]|Out-Null;$gateReceiptPaths+=$gatePath
        }
        $collectorReleaseChain=@($releaseChain|ForEach-Object{[ordered]@{stage=$_.stage;releaseSetId=$_.releaseSetId
          generation=$_.generation;sequence=$_.sequence;runtimeEntryPointSha256=$_.runtimeEntryPointSha256;manifestPath=$_.manifest.path}})
        $collectorExecutables=@($signedExecutables|ForEach-Object{[ordered]@{role=$_.role;path=$_.file.path}})
        $collection=[ordered]@{schemaVersion=1;collectionType='ensou-dsh-enterprise-windows-pilot-evidence-collection'
          testRunId=$testRunId;customerAudienceId=$audienceId
          startedAtUtc=$runStart.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ');completedAtUtc=$runEnd.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')
          pilotManifestUri='https://pilot.contoso.cn/v2/channels/pilot/release-set.v2.json'
          readiness=[ordered]@{configPath=$readinessConfigPath;reportPath=$readinessReportPath;target=Get-ReleaseIdentity $releaseChain[4]}
          deviceLanes=@([ordered]@{lane='clean-install';osFamily='windows';osBuild='11.26100.1';nativeArchitecture='x64';standardUser=$true
              installationIdSha256=$hashA;deviceInventoryPath=$cleanInventoryPath},
            [ordered]@{lane='legacy-migration';osFamily='windows';osBuild='10.19045.1';nativeArchitecture='x64';standardUser=$true
              installationIdSha256=$hashB;deviceInventoryPath=$legacyDeviceInventoryPath})
          pilotObserverExecutablePath=$observerPath
          weComAdmission=[ordered]@{authorizedEmployeeSubjectSha256=$hashA;unregisteredEmployeeSubjectSha256=$hashB
            installationIdSha256=$hashA;deviceProofPublicKeySha256=$hashC}
          legacySource=[ordered]@{version='legacy-v1';inventoryPath=$legacySourceInventoryPath}
          localDataWitness=[ordered]@{historyTreeBeforeSha256=$hashA;historyTreeAfterSha256=$hashA
            workspaceTreeBeforeSha256=$hashB;workspaceTreeAfterSha256=$hashB}
          releaseChain=$collectorReleaseChain;signedExecutables=$collectorExecutables;gateReceiptPaths=$gateReceiptPaths}

        Assert-CollectorCodeLevelArraySemantics $collection
        $collected=Invoke-Collector $collection 'collector-valid-a'
        $alternateCollection=[ordered]@{gateReceiptPaths=$collection.gateReceiptPaths;signedExecutables=$collection.signedExecutables
          releaseChain=$collection.releaseChain;localDataWitness=$collection.localDataWitness;legacySource=$collection.legacySource
          weComAdmission=$collection.weComAdmission;pilotObserverExecutablePath=$collection.pilotObserverExecutablePath
          deviceLanes=$collection.deviceLanes;readiness=$collection.readiness;pilotManifestUri=$collection.pilotManifestUri
          completedAtUtc=$collection.completedAtUtc;startedAtUtc=$collection.startedAtUtc;customerAudienceId=$collection.customerAudienceId
          testRunId=$collection.testRunId;collectionType=$collection.collectionType;schemaVersion=$collection.schemaVersion}
        $alternateCollection.readiness.configPath=Join-Path (Split-Path -Parent $readinessConfigPath) ('.\'+(Split-Path -Leaf $readinessConfigPath))
        $collectedAlternate=Invoke-Collector $alternateCollection 'collector-valid-b'
        $collectedBytes=[IO.File]::ReadAllBytes($collected.BodyPath)
        $alternateBytes=[IO.File]::ReadAllBytes($collectedAlternate.BodyPath)
        if($collectedBytes.Length-ne$alternateBytes.Length){throw 'Pilot collector output is not deterministic.'}
        for($byteIndex=0;$byteIndex-lt$collectedBytes.Length;$byteIndex++){
          if($collectedBytes[$byteIndex]-ne$alternateBytes[$byteIndex]){throw 'Pilot collector output is not deterministic.'}
        }
        if(($collectedBytes.Length-ge3-and$collectedBytes[0]-eq0xef-and$collectedBytes[1]-eq0xbb-and$collectedBytes[2]-eq0xbf)-or
          $collectedBytes[$collectedBytes.Length-1]-in@(10,13)){
          throw 'Pilot collector body must be compact UTF-8 without BOM or trailing newline.'
        }
        $collectedText=[Text.UTF8Encoding]::new($false,$true).GetString($collectedBytes)
        if(-not $collectedText.Contains(('"startedAtUtc":"'+$collection.startedAtUtc+'"'))-or
          -not $collectedText.Contains(('"completedAtUtc":"'+$collection.completedAtUtc+'"'))){
          throw 'Pilot collector did not preserve exact UTC timestamp strings.'
        }
        $collectedBody=$collectedText|ConvertFrom-Json -Depth 64
        if(@($collectedBody.gates).Count-ne21-or[string]$collectedBody.deviceLanes[0].lane-cne'clean-install'-or
          [string]$collectedBody.deviceLanes[1].lane-cne'legacy-migration'){
          throw 'Pilot collector did not preserve both exact device lanes and all 21 gates.'
        }
        $attestationRequest=Get-Content -Raw -LiteralPath $collected.RequestPath|ConvertFrom-Json -Depth 16
        $payloadBase64=[string]$attestationRequest.signingPayload.base64Url
        $normalizedPayload=$payloadBase64.Replace('-','+').Replace('_','/')
        switch($normalizedPayload.Length%4){0{}2{$normalizedPayload+='=='}3{$normalizedPayload+='='}default{throw 'Collector signing payload is not canonical base64url.'}}
        $actualPayload=[Convert]::FromBase64String($normalizedPayload)
        $expectedPayload=[Text.Encoding]::UTF8.GetBytes((@('ensou-dsh-enterprise-windows-pilot-evidence-attestation-v2','2',
          'ensou-dsh-enterprise-windows-pilot-evidence-envelope','2','ensou-dsh-enterprise-windows-pilot-evidence-body',
          [string]$collectedBytes.Length,(Get-Sha256Bytes $collectedBytes))-join"`n"))
        if((Get-Sha256Bytes $actualPayload)-cne(Get-Sha256Bytes $expectedPayload)-or
          [string]$attestationRequest.body.sha256-cne(Get-Sha256Bytes $collectedBytes)-or
          $attestationRequest.standaloneAdmissionEvidence-ne$false-or$attestationRequest.privateKeyUsed-ne$false-or
          $attestationRequest.PSObject.Properties.Name-contains'keyId'){
          throw 'Pilot collector attestation request does not bind the exact detached signing payload.'
        }
        $collectedFixture=Write-SignedBodyFileEvidence $collected.BodyPath 'collector-round-trip' $evidenceSigner $evidenceKeyId
        $collectedResult=Invoke-ContractVerifier $collectedFixture $evidenceKeyId $evidenceKeyX $evidenceKeyY
        if([string]$collectedResult.decision-cne'CONTRACT_VALID'){throw 'Collected Pilot body failed verifier round-trip.'}
        $collectorOverwriteRejected=$false
        try { Invoke-CollectorProcess $collected.CollectionPath $collected.BodyPath $collected.RequestPath|Out-Null }
        catch { $collectorOverwriteRejected=$true }
        if(-not $collectorOverwriteRejected){throw 'Pilot collector overwrote an existing body or attestation request.'}

        $aliasCollectionPath=Join-Path $tempRoot 'collector-case-alias.collection.v1.json'
        Write-JsonFile $aliasCollectionPath $collection|Out-Null
        $aliasBodyPath=Join-Path $tempRoot 'collector-case-alias-output.json'
        $aliasRequestPath=Join-Path $tempRoot 'COLLECTOR-CASE-ALIAS-OUTPUT.JSON'
        $caseAliasRejected=$false
        try{Invoke-CollectorProcess $aliasCollectionPath $aliasBodyPath $aliasRequestPath|Out-Null}catch{$caseAliasRejected=$true}
        if(-not$caseAliasRejected-or(Test-Path -LiteralPath $aliasBodyPath)-or(Test-Path -LiteralPath $aliasRequestPath)){
          throw 'Pilot collector accepted case-aliased body/request targets or created an aliased output.'
        }

        $bodyPublishFailureCollectionPath=Join-Path $tempRoot 'collector-body-publish-failure.collection.v1.json'
        Write-JsonFile $bodyPublishFailureCollectionPath $collection|Out-Null
        $bodyPublishFailureRequestPath=Join-Path $tempRoot 'collector-body-publish-failure.request.json'
        $reservedBodyPath=Join-Path $tempRoot 'NUL'
        $bodyPublishFailureRejected=$false
        try{Invoke-CollectorProcess $bodyPublishFailureCollectionPath $reservedBodyPath $bodyPublishFailureRequestPath|Out-Null}catch{$bodyPublishFailureRejected=$true}
        if(-not$bodyPublishFailureRejected-or(Test-Path -LiteralPath $bodyPublishFailureRequestPath)-or(Test-Path -LiteralPath $reservedBodyPath)){
          throw 'Pilot collector left a request/body after injected final body publication failure.'
        }

        foreach($invalidManifestUri in @(
          'https://operator:secret@pilot.contoso.cn/v2/channels/pilot/release-set.v2.json',
          'https://pilot.contoso.cn/v2/channels/pilot/release-set.v2.json?candidate=1',
          'https://pilot.contoso.cn/v2/channels/pilot/release-set.v2.json#fragment',
          'http://pilot.contoso.cn/v2/channels/pilot/release-set.v2.json')){
          $invalidUriCollection=Copy-JsonValue $collection
          $invalidUriCollection.pilotManifestUri=$invalidManifestUri
          Assert-CollectorRejected 'Invalid Pilot manifest URI' $invalidUriCollection ('collector-invalid-uri-'+[Guid]::NewGuid().ToString('N'))
        }

        $missingGateCollection=Copy-JsonValue $collection
        $missingGateCollection.gateReceiptPaths=@($missingGateCollection.gateReceiptPaths|Select-Object -First 20)
        Assert-CollectorRejected 'Missing gate receipt' $missingGateCollection 'collector-missing-gate'
        $wrongArchitectureCollection=Copy-JsonValue $collection;$wrongArchitectureCollection.deviceLanes[1].nativeArchitecture='x86'
        Assert-CollectorRejected 'Non-x64 legacy lane' $wrongArchitectureCollection 'collector-wrong-architecture'
        $sameSubjectCollection=Copy-JsonValue $collection
        $sameSubjectCollection.weComAdmission.unregisteredEmployeeSubjectSha256=$sameSubjectCollection.weComAdmission.authorizedEmployeeSubjectSha256
        Assert-CollectorRejected 'Equal employee subject digests' $sameSubjectCollection 'collector-equal-subjects'
        $secretCollection=Copy-JsonValue $collection
        $secretCollection|Add-Member -NotePropertyName access_token -NotePropertyValue 'must-not-enter-pilot-evidence'
        Assert-CollectorRejected 'Raw secret member' $secretCollection 'collector-secret-member'
        $wrongLaneGate=Copy-JsonValue $gates[15];$wrongLaneGate.deviceLane='clean-install'
        $wrongLaneGatePath=Join-Path $tempRoot 'wrong-lane-gate.receipt.v2.json';Write-JsonFile $wrongLaneGatePath $wrongLaneGate|Out-Null
        $wrongLaneCollection=Copy-JsonValue $collection;$wrongLaneCollection.gateReceiptPaths[15]=$wrongLaneGatePath
        Assert-CollectorRejected 'Wrong legacy gate lane' $wrongLaneCollection 'collector-wrong-lane'

        $shortObservationGate=Copy-JsonValue $gates[1]
        $shortObservationStart=[DateTimeOffset]$shortObservationGate.startedAtUtc
        $shortObservationGate.completedAtUtc=$shortObservationStart.AddMinutes(14).ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')
        $shortObservationPath=Join-Path $tempRoot 'short-observation-gate.receipt.v2.json'
        Write-JsonFile $shortObservationPath $shortObservationGate|Out-Null
        $shortObservationCollection=Copy-JsonValue $collection;$shortObservationCollection.gateReceiptPaths[1]=$shortObservationPath
        Assert-CollectorRejected 'Short no-window observation' $shortObservationCollection 'collector-short-observation'

        $wrongProcessGate=Copy-JsonValue $gates[2];$wrongProcessGate.observedProcess.executableSha256=$hashC
        $wrongProcessPath=Join-Path $tempRoot 'wrong-process-gate.receipt.v2.json'
        Write-JsonFile $wrongProcessPath $wrongProcessGate|Out-Null
        $wrongProcessCollection=Copy-JsonValue $collection;$wrongProcessCollection.gateReceiptPaths[2]=$wrongProcessPath
        Assert-CollectorRejected 'Wrong observed process hash' $wrongProcessCollection 'collector-wrong-process'

        $wrongTupleGate=Copy-JsonValue $gates[10];$wrongTupleGate.releaseTuple.active=Get-ReleaseIdentity $releaseChain[0]
        $wrongTuplePath=Join-Path $tempRoot 'wrong-tuple-gate.receipt.v2.json'
        Write-JsonFile $wrongTuplePath $wrongTupleGate|Out-Null
        $wrongTupleCollection=Copy-JsonValue $collection;$wrongTupleCollection.gateReceiptPaths[10]=$wrongTuplePath
        Assert-CollectorRejected 'Wrong release tuple' $wrongTupleCollection 'collector-wrong-tuple'

        $missingInventoryCollection=Copy-JsonValue $collection
        $missingInventoryCollection.deviceLanes[0].deviceInventoryPath=Join-Path $tempRoot 'missing-clean-device-inventory.json'
        Assert-CollectorRejected 'Missing clean device inventory' $missingInventoryCollection 'collector-missing-inventory'

        $sameInventoryCollection=Copy-JsonValue $collection
        $sameInventoryCollection.deviceLanes[1].deviceInventoryPath=$sameInventoryCollection.deviceLanes[0].deviceInventoryPath
        Assert-CollectorRejected 'Reused clean/legacy inventory file' $sameInventoryCollection 'collector-reused-inventory'

        $duplicateInventoryPath=Join-Path $tempRoot 'duplicate-clean-inventory.json'
        Write-BytesFile $duplicateInventoryPath ([IO.File]::ReadAllBytes($cleanInventoryPath))|Out-Null
        $sameInventoryBytesCollection=Copy-JsonValue $collection
        $sameInventoryBytesCollection.deviceLanes[1].deviceInventoryPath=$duplicateInventoryPath
        Assert-CollectorRejected 'Duplicated clean/legacy inventory bytes' $sameInventoryBytesCollection 'collector-duplicated-inventory-bytes'

        $reusedLegacySourceCollection=Copy-JsonValue $collection
        $reusedLegacySourceCollection.legacySource.inventoryPath=$legacyDeviceInventoryPath
        Assert-CollectorRejected 'Reused legacy source/device inventory' $reusedLegacySourceCollection 'collector-reused-legacy-source'

        $alternateLauncherDirectory=Join-Path $tempRoot 'readiness-mismatch-launcher'
        [IO.Directory]::CreateDirectory($alternateLauncherDirectory)|Out-Null
        $alternateLauncherPath=Join-Path $alternateLauncherDirectory $executableNames.launcher
        Write-BytesFile $alternateLauncherPath ([Text.Encoding]::UTF8.GetBytes('different readiness launcher bytes'))|Out-Null
        $wrongReadinessExecutableConfig=Copy-JsonValue $readinessConfig
        $wrongReadinessExecutableConfig.launcherExecutablePath=$alternateLauncherPath
        $wrongReadinessExecutableConfigPath=Join-Path $tempRoot 'wrong-executable.readiness.config.json'
        Write-JsonFile $wrongReadinessExecutableConfigPath $wrongReadinessExecutableConfig|Out-Null
        $wrongReadinessExecutableCollection=Copy-JsonValue $collection
        $wrongReadinessExecutableCollection.readiness.configPath=$wrongReadinessExecutableConfigPath
        Assert-CollectorRejected 'Readiness executable mismatch' $wrongReadinessExecutableCollection 'collector-readiness-executable-mismatch'

        $wrongPublisherReadinessReport=Copy-JsonValue $readinessReport
        $wrongPublisherReadinessReport.publisherExecutableSha256=$hashC
        $wrongPublisherReadinessReportPath=Join-Path $tempRoot 'wrong-publisher.readiness.report.json'
        Write-JsonFile $wrongPublisherReadinessReportPath $wrongPublisherReadinessReport|Out-Null
        $wrongPublisherReadinessCollection=Copy-JsonValue $collection
        $wrongPublisherReadinessCollection.readiness.reportPath=$wrongPublisherReadinessReportPath
        Assert-CollectorRejected 'Readiness publisher hash mismatch' $wrongPublisherReadinessCollection 'collector-readiness-publisher-mismatch'

        $valid=Write-SignedEvidence $body 'valid' $evidenceSigner $evidenceKeyId
        $validResult=Invoke-ContractVerifier $valid $evidenceKeyId $evidenceKeyX $evidenceKeyY
        if([string]$validResult.decision -cne 'CONTRACT_VALID'){throw 'Valid v2 Pilot evidence was not accepted.'}
        Assert-PathGuardRaceProtection

        $forgedPass=Copy-JsonValue $body;$forgedPass.gates[0].resultCode='SECOND_UPDATE_APPLIED'
        Assert-Rejected 'Forged PASS content' (Write-SignedEvidence $forgedPass 'forged-pass' $evidenceSigner $evidenceKeyId)

        $attackerFixture=Write-SignedEvidence $body 'attacker-key' $attackerSigner $attackerKeyId
        Assert-Rejected 'Self-selected evidence key' $attackerFixture

        $selfKeyEnvelope=Copy-JsonValue $valid.Envelope
        $selfKeyEnvelope|Add-Member -NotePropertyName publicKey -NotePropertyValue ([ordered]@{keyId=$attackerKeyId;x=$attackerKeyX;y=$attackerKeyY})
        $selfKeyEnvelopePath=Join-Path $tempRoot 'self-key.envelope.v2.json';Write-JsonFile $selfKeyEnvelopePath $selfKeyEnvelope|Out-Null
        Assert-Rejected 'Evidence-embedded public key' ([pscustomobject]@{EnvelopePath=$selfKeyEnvelopePath;BodyPath=$valid.BodyPath})

        $fakeReport=Copy-JsonValue $readinessReport;$fakeReport.releaseSetId=$releaseChain[0].releaseSetId
        $fakeReportPath=Join-Path $tempRoot 'fake-readiness.report.json';Write-JsonFile $fakeReportPath $fakeReport|Out-Null
        $fakeReadiness=Copy-JsonValue $body;$fakeReadiness.readiness.report=Get-FileReference $fakeReportPath
        Assert-Rejected 'Fake readiness ADMIT' (Write-SignedEvidence $fakeReadiness 'fake-readiness' $evidenceSigner $evidenceKeyId)

        $wrongReadinessExecutableBody=Copy-JsonValue $body
        $wrongReadinessExecutableBody.readiness.config=Get-FileReference $wrongReadinessExecutableConfigPath
        Assert-Rejected 'Attested/readiness executable mismatch' (Write-SignedEvidence $wrongReadinessExecutableBody 'attested-readiness-executable-mismatch' $evidenceSigner $evidenceKeyId)

        $wrongPublisherReadinessBody=Copy-JsonValue $body
        $wrongPublisherReadinessBody.readiness.report=Get-FileReference $wrongPublisherReadinessReportPath
        Assert-Rejected 'Attested/readiness Publisher mismatch' (Write-SignedEvidence $wrongPublisherReadinessBody 'attested-readiness-publisher-mismatch' $evidenceSigner $evidenceKeyId)

        $reusedInventoryBody=Copy-JsonValue $body
        $reusedInventoryBody.deviceLanes[1].deviceInventorySha256=$reusedInventoryBody.deviceLanes[0].deviceInventorySha256
        Assert-Rejected 'Reused device inventory hash' (Write-SignedEvidence $reusedInventoryBody 'reused-device-inventory-hash' $evidenceSigner $evidenceKeyId)

        $userinfoManifestBody=Copy-JsonValue $body
        $userinfoManifestBody.pilotManifestUri='https://operator:secret@pilot.contoso.cn/v2/channels/pilot/release-set.v2.json'
        Assert-Rejected 'Pilot manifest URI userinfo' (Write-SignedEvidence $userinfoManifestBody 'manifest-uri-userinfo' $evidenceSigner $evidenceKeyId)
        $queryManifestBody=Copy-JsonValue $body
        $queryManifestBody.pilotManifestUri='https://pilot.contoso.cn/v2/channels/pilot/release-set.v2.json?candidate=1'
        Assert-Rejected 'Pilot manifest URI query' (Write-SignedEvidence $queryManifestBody 'manifest-uri-query' $evidenceSigner $evidenceKeyId)
        $fragmentManifestBody=Copy-JsonValue $body
        $fragmentManifestBody.pilotManifestUri='https://pilot.contoso.cn/v2/channels/pilot/release-set.v2.json#fragment'
        Assert-Rejected 'Pilot manifest URI fragment' (Write-SignedEvidence $fragmentManifestBody 'manifest-uri-fragment' $evidenceSigner $evidenceKeyId)
        $httpManifestBody=Copy-JsonValue $body
        $httpManifestBody.pilotManifestUri='http://pilot.contoso.cn/v2/channels/pilot/release-set.v2.json'
        Assert-Rejected 'Pilot manifest URI non-HTTPS' (Write-SignedEvidence $httpManifestBody 'manifest-uri-http' $evidenceSigner $evidenceKeyId)

        $wrongBrandAudienceConfig=Copy-JsonValue $readinessConfig
        $wrongBrandAudienceConfig.brandAuthorization.distributionAudienceId=[Guid]::NewGuid().ToString('D')
        $wrongBrandAudiencePath=Join-Path $tempRoot 'wrong-brand-audience.readiness.config.json'
        Write-JsonFile $wrongBrandAudiencePath $wrongBrandAudienceConfig|Out-Null
        $wrongBrandAudienceBody=Copy-JsonValue $body
        $wrongBrandAudienceBody.readiness.config=Get-FileReference $wrongBrandAudiencePath
        Assert-Rejected 'Readiness brand audience mismatch' (Write-SignedEvidence $wrongBrandAudienceBody 'wrong-brand-audience' $evidenceSigner $evidenceKeyId)

        $wrongLocalAudienceConfig=Copy-JsonValue $readinessConfig
        $wrongLocalAudienceConfig.localDataCompatibilityEvidence.certification.certificationAudienceId=[Guid]::NewGuid().ToString('D')
        $wrongLocalAudiencePath=Join-Path $tempRoot 'wrong-local-audience.readiness.config.json'
        Write-JsonFile $wrongLocalAudiencePath $wrongLocalAudienceConfig|Out-Null
        $wrongLocalAudienceBody=Copy-JsonValue $body
        $wrongLocalAudienceBody.readiness.config=Get-FileReference $wrongLocalAudiencePath
        Assert-Rejected 'Readiness local-data audience mismatch' (Write-SignedEvidence $wrongLocalAudienceBody 'wrong-local-audience' $evidenceSigner $evidenceKeyId)

        $equalSubjectBody=Copy-JsonValue $body
        $equalSubjectBody.weComAdmission.unregisteredEmployeeSubjectSha256=$equalSubjectBody.weComAdmission.authorizedEmployeeSubjectSha256
        Assert-Rejected 'Equal employee subject hashes' (Write-SignedEvidence $equalSubjectBody 'equal-employee-subjects' $evidenceSigner $evidenceKeyId)

        $forgedManifest=Get-Content -Raw -LiteralPath $releaseChain[3].manifest.path|ConvertFrom-Json -Depth 32
        $forgedManifest.signature.value='A'*86;$forgedManifestPath=Join-Path $tempRoot 'forged-release-set.v2.json';Write-JsonFile $forgedManifestPath $forgedManifest|Out-Null
        $manifestTamper=Copy-JsonValue $body;$manifestRef=Get-FileReference $forgedManifestPath
        $manifestTamper.releaseChain[3].manifest=$manifestRef;$manifestTamper.releaseChain[3].manifestSha256=$manifestRef.sha256
        foreach($gate in $manifestTamper.gates){if($null -ne $gate.releaseTuple.attempted -and $gate.releaseTuple.attempted.releaseSetId -ceq $releaseChain[3].releaseSetId){$gate.releaseTuple.attempted.manifestSha256=$manifestRef.sha256}}
        Assert-Rejected 'Forged manifest ES256 signature' (Write-SignedEvidence $manifestTamper 'forged-manifest' $evidenceSigner $evidenceKeyId)

        $sameTime=Copy-JsonValue $body;$sameTime.gates[2].startedAtUtc=$sameTime.gates[1].completedAtUtc
        Assert-Rejected 'Non-monotonic equal timestamp' (Write-SignedEvidence $sameTime 'same-time' $evidenceSigner $evidenceKeyId)

        $wrongTuple=Copy-JsonValue $body;$wrongTuple.gates[10].releaseTuple.active=Get-ReleaseIdentity $releaseChain[0]
        Assert-Rejected 'Wrong update tuple' (Write-SignedEvidence $wrongTuple 'wrong-tuple' $evidenceSigner $evidenceKeyId)

        $secretBody=Copy-JsonValue $body;$secretBody|Add-Member -NotePropertyName access_token -NotePropertyValue 'contract-secret-must-reject'
        Assert-Rejected 'Secret field' (Write-SignedEvidence $secretBody 'secret-field' $evidenceSigner $evidenceKeyId)

        $replacementPath=Join-Path $tempRoot 'replacement.json';Write-JsonFile $replacementPath ([ordered]@{replacement=$true})|Out-Null
        $lock=[IO.FileStream]::new($valid.BodyPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        try{$replacementDenied=$false;try{[IO.File]::Move($replacementPath,$valid.BodyPath,$true)}catch{$replacementDenied=$true}
          if(-not $replacementDenied){throw 'Locked evidence allowed concurrent replacement.'}}finally{$lock.Dispose()}

        $missingSignerReport=Join-Path $tempRoot 'missing-signer.reject.v2.json';$missingSignerReplay=Join-Path $tempRoot 'missing-signer-readiness-replay.json'
        $missingSignerRejected=$false
        try{& $verifier -EvidenceEnvelopePath $valid.EnvelopePath -EvidenceBodyPath $valid.BodyPath `
          -PublisherExecutablePath $signedExecutables[0].file.path -PublisherSignerSha256Thumbprint $hashA `
          -PublisherExecutableSha256 $executableHashes['release-publisher'] -ReadinessReplayReportPath $missingSignerReplay -ReportPath $missingSignerReport `
          -WindowsPilotVerifierPrivateKeyPath (Join-Path $tempRoot 'missing-verifier.pkcs8') -WindowsPilotVerifierKeyId $verifierKeyId|Out-Null}
        catch{$missingSignerRejected=$true}
        if(-not $missingSignerRejected -or (Test-Path -LiteralPath $missingSignerReport)){
          throw 'Production verification emitted an unsigned report without its verifier key.'}

        $productionReport=Join-Path $tempRoot 'authenticated-production.reject.v2.json';$replayPath=Join-Path $tempRoot 'authenticated-readiness-replay.json'
        $productionRejected=$false
        try{& $verifier -EvidenceEnvelopePath $valid.EnvelopePath -EvidenceBodyPath $valid.BodyPath `
          -PublisherExecutablePath $signedExecutables[0].file.path -PublisherSignerSha256Thumbprint $hashA `
          -PublisherExecutableSha256 $executableHashes['release-publisher'] -ReadinessReplayReportPath $replayPath -ReportPath $productionReport `
          -WindowsPilotVerifierPrivateKeyPath $verifierKeyPath -WindowsPilotVerifierKeyId $verifierKeyId|Out-Null}
        catch{$productionRejected=$true}
        if(-not $productionRejected -or -not(Test-Path -LiteralPath $productionReport)){throw 'Unsigned/self-asserted Publisher production fixture was not rejected.'}
        $productionReceipt=Get-Content -Raw -LiteralPath $productionReport|ConvertFrom-Json -Depth 32 -DateKind String
        if([string]$productionReceipt.decision -cne 'REJECT'){throw 'Production rejection receipt is invalid.'}
        if(-not(Test-Json -Json (Get-Content -Raw -LiteralPath $productionReport) -SchemaFile $verificationReportSchemaPath -ErrorAction Stop)){
          throw 'Production rejection receipt does not satisfy the authenticated report schema.'}
        $verifierTrust=[pscustomobject]@{windowsPilotVerifier=[pscustomobject]@{
          algorithm='ES256';purpose='enterprise-windows-pilot-verifier-report';keyId=$verifierKeyId;x=$verifierKeyX;y=$verifierKeyY}}
        EnterpriseProductionPilotEvidence\Assert-R8WindowsVerificationReportAuthentication `
          -Report $productionReceipt -Trust $verifierTrust

        Write-Host 'Enterprise Windows Pilot v2 evidence contract validation passed.'
    } finally {$evidenceSigner.Dispose();$releaseSigner.Dispose();$attackerSigner.Dispose();$verifierSigner.Dispose()}
} finally {
    $resolved=[IO.Path]::GetFullPath($tempRoot)
    if((Split-Path -Parent $resolved)-cne $tempParent -or (Split-Path -Leaf $resolved)-cnotmatch '^ensou-enterprise-windows-pilot-v2-[0-9a-f]{32}$') {
        throw "Refusing unsafe fixture cleanup: $resolved"
    }
    if(Test-Path -LiteralPath $resolved){[IO.Directory]::Delete($resolved,$true)}
}
