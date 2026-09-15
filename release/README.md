# Release contracts

This directory contains machine-readable contracts and release-control scripts. It does not contain production packages or signing keys.

Enterprise release-set v2 manifests require a signed `startupStub` protocol
range. The current production and Development-E2E Startup Stub protocol is `1`;
publishers and feed promotion reject a range that excludes it.

## Enterprise FeedPromoter production bundle

`scripts/Publish-EnterpriseFeedPromoterProductionBundle.ps1` materializes one
exact Git commit, publishes the Enterprise FeedPromoter as a self-contained,
single-file `linux-x64` ELF, and pairs it with an externally supplied production
trust document. The command never creates a signing key, trust root, signature,
or fallback fixture. Both the absolute trust path and its independently approved
lowercase SHA-256 are mandatory. Trust bytes must be strict LF-only UTF-8 JSON,
declare `environment=production`, use non-placeholder HTTPS DNS origins, contain
valid P-256 public points, and keep release and certification key IDs and points
globally separate.

The output directory is create-only and contains exactly four ordinary files:

- `ensou-dsh-enterprise-feed-promoter`
- `enterprise-feed-production-trust.json` (byte-for-byte identical to input)
- `enterprise-feed-promoter-production-bundle.v1.json`
- `SHA256SUMS`

The first two names are the two independent offline inputs consumed by the
Control first-customer installer. The strict bundle manifest binds their sizes
and hashes to the Launcher source commit, exact SDK, RID, origins, and public key
IDs. `SHA256SUMS` covers the binary, raw trust, and manifest with lowercase
SHA-256 lines and LF endings.

Production publication is available only through the protected, main-branch
manual job in `enterprise-managed-release-v2.yml`. The protected environment
provides `ENSOU_ENTERPRISE_FEED_PRODUCTION_TRUST_BASE64`; the dispatcher supplies
its independently reviewed `expected_production_trust_sha256`. Pull-request and
push jobs use only disposable, generated public-key fixtures for contract tests
and never upload those bytes.

```powershell
./release/scripts/Publish-EnterpriseFeedPromoterProductionBundle.ps1 `
  -TrustPolicyPath C:\release-input\enterprise-feed-production-trust.json `
  -ExpectedProductionTrustSha256 <approved-lowercase-sha256> `
  -OutputDirectory C:\release-output\enterprise-feed-promoter-production-bundle `
  -LauncherSourceCommit <reviewed-40-character-commit>
```

## Enterprise Stable r8-to-r9 offline feed-promotion authorization

The Launcher release state never owns credentials that can publish an employee
feed. For an Enterprise schema-v2 Stable state at exact r8
`PILOT_EVIDENCE_BOUND`, the main orchestrator now creates a network-free,
create-only request and CAS head. The request binds the r8 state, signed candidate
bytes, expected feed identity, and prior raw channel/journal heads:

```powershell
./release/scripts/Invoke-LauncherProductionRelease.ps1 `
  -RepositoryRoot C:\path\to\launcher-enterprise-wecom `
  -Edition Enterprise `
  -Phase Promote `
  -PlanPath C:\release-input\enterprise-stable-plan.v2.json `
  -StateRoot C:\release-state\enterprise-stable `
  -PromotionRoot C:\release-work\enterprise-stable-promotion `
  -ExpectedFeedIdentitySha256 <64-lowercase-hex-feed-identity> `
  -ExpectedChannelHead 'missing' `
  -ExpectedJournalHead 'missing' `
  -ExpectedHeadSha256 <r8-head-sha256-from-Status>
```

`PromotionRoot` must be absolute and disjoint from the checkout and state root.
`ExpectedHeadSha256` is the r8 Launcher release-state CAS. Each feed CAS argument
is exactly `missing` or
`present:<size>:<sha256>`; `size` is the positive decimal raw byte length and
`sha256` is lowercase. Use `present` only with the exact raw file size and hash
observed from the current feed foundation.

The first call omits `FeedPromotionResponsePath` and does not append r9. A
separate offline authorization workstation signs the generated request with the
independent `feed-promotion-response` P-256 key:

```powershell
./release/scripts/New-ProductionFeedPromotionAuthorizationResponse.ps1 `
  -RequestPath C:\release-work\enterprise-stable-promotion\request\request.v1.json `
  -PromotionHeadPath C:\release-work\enterprise-stable-promotion\head.json `
  -AuthorizationPrivateKeyPath C:\offline-keys\feed-promotion-response.pk8 `
  -AuthorizationKeyId <plan-fixed-feed-promotion-response-key-id> `
  -OutputPath C:\offline-response\response.v1.json
```

The signer accepts only strict canonical request/head JSON, keeps all three
inputs locked until its create-only output is durable, requires its private key
to match the public point already fixed in the release plan, rejects stale or
future requests, and emits canonical low-S ES256. Its response remains
`OFFLINE_BUNDLE_ONLY` with `networkPublishPerformed=false`: authorization does
not itself publish, modify the release state, or contact the Ubuntu feed host.
Re-run the same main-orchestrator command with the same `PromotionRoot`,
`ExpectedFeedIdentitySha256`, `ExpectedChannelHead`, `ExpectedJournalHead`, and
`ExpectedHeadSha256`, adding:

```powershell
  -FeedPromotionResponsePath C:\offline-response\response.v1.json
```

The response path must be absolute and outside the checkout, production state,
and promotion workspace. Successful admission appends r9
`STABLE_PROMOTION_REQUESTED` and stores exactly five JSON files:

```text
<StateRoot>/requests/stable-feed-promotion.v1/
  request.v1.json
  response.v1.json
  promotion-head.v1.json
  bundle-head.v1.json
  promotion-admission.v1.json
```

r9 is always `productionAdmission=NO_GO` and every network-publication flag is
false. It does not contact the Ubuntu host or make an employee-visible update.
The root-owned Linux FeedPromoter execution/result import and r10
`STABLE_FEED_PROMOTED` exact channel/journal-head observation are not connected
to the main orchestrator yet.

Run both network-free contract suites before moving an authorization response:

```powershell
./release/scripts/Test-ProductionFeedPromotion.ps1
./release/scripts/Test-ProductionFeedPromotionAuthorizationResponse.ps1
./release/scripts/Test-ProductionStableFeedPromotionState.ps1
./release/scripts/Test-LauncherStablePromotionOrchestration.ps1
```

## Version 1 channel manifest

`schemas/channel-manifest.schema.json` defines the exact document accepted by the version 1 Launcher contract. Unknown top-level and nested properties are rejected. `examples/` contains structurally valid, deliberately non-production examples; their key id and zero signature must never be trusted.

The signed payload uses a deliberately narrow contract shared with the .NET implementation:

1. Exclude the top-level `signature` property.
2. Emit compact JSON in this fixed property order: `schemaVersion`, `releaseId`, `channel`, `launcherVersion`, `dshVersion`, `publishedAtUtc`, `minimumBootstrapperVersion`, `artifact`.
3. Emit `artifact` in this fixed property order: `url`, `fileName`, `sizeBytes`, `sha256`.
4. Format `publishedAtUtc` exactly as `yyyy-MM-ddTHH:mm:ss.fffffffZ`: UTC `Z` and exactly seven fractional digits. Producers must not preserve a shorter input timestamp.
5. Encode `schemaVersion` and `sizeBytes` as base-10 JSON integers with no quotes, leading zeroes, exponent, or decimal point.
6. All version 1 string values are restricted to printable ASCII by the schema/client. The artifact URL additionally rejects quotes, backslashes, whitespace, user information, and fragments. Consequently the canonical payload contains no JSON escape sequences; a producer must reject rather than normalize a value outside this set.
7. Emit no whitespace before, between, or after tokens, and no trailing newline. Encode the compact JSON as UTF-8 with no BOM.
8. Sign with ECDSA P-256 and SHA-256.
9. Encode the fixed-width 64-byte IEEE-P1363 `r || s` signature as unpadded Base64URL in `signature.value`.

`examples/canonical-payload-v1.vector.json` contains the exact payload bytes as Base64, their SHA-256 digest, a test-only public key, and a fixed IEEE-P1363 signature. Signer implementations must reproduce and verify that vector before they can be used for a release.

The client verifies the signature before reading the artifact URL or making an artifact request.

In manifest v1, `launcherVersion` means the minimum Launcher version compatible with this DSH runtime. The single `artifact` is always a DSH runtime package. Launcher self-update uses a separate Bootstrapper feed and must complete before this manifest can be installed. `minimumBootstrapperVersion` applies the same fail-closed compatibility gate to Bootstrapper.

## Source-runtime metadata

`schemas/source-runtime-metadata.schema.json` and `scripts/Test-SourceRuntimeMetadata.ps1` are the shared builder-to-promotion contract. Metadata schema v2 binds the exact reviewed upstream tag to its runtime Web authentication protocol in addition to the locked source proof, toolchain, smoke gates, licensing flags, artifact name, byte count, and SHA-256. Required Boolean `promotionEligible` is inseparable from the release-ID class: `true` requires `managed-vYYYY.MM.DD.N`; `false` requires `lab-*`. The validator rejects `false` by default. Only local development tooling may explicitly pass `-AllowLocalLab`; candidate publication, promotion, and production ReleasePublisher paths never do. The current production-candidate lane admits only the reviewed `dsh-v0.1.2-rc.1` tuple and its `browser-launch-cookie-v1` evidence; the former rc.2, alpha.1, and alpha.3 tuples are retained only as historical bundle evidence and are not accepted by current release admission.

This is an intentional breaking **pre-production** revision of metadata v2, ZIP `source-build.json` v3, and the Personal source-runtime artifact descriptor v1. None of those shapes had entered a distributable production release. Historical bytes that omit `promotionEligible` are retired evidence and are never admitted again; they must not be relabeled or retrofitted. The versions remain unchanged to preserve the already selected pre-production v2/v3 contract boundary, while the required member and contract tests make the break explicit and fail closed.

Production plugin-policy publishing additionally consumes the strict
`managed-plugin-promotion-handoff-v2` contract plus its hash-bound external
Harness compatibility receipt, exclusive generation reservation, namespaced
generation ledger v2, and ES256 organization admission receipt. The handoff is
never used as publisher config: release ID, HTTPS URI, and seven signer-local
absolute evidence paths remain independent operations inputs. The compatibility
receipt is produced before signing by
`Ensou.Dsh.EnterprisePluginCompatibilityRunner`, binds exact Launcher/runtime
bytes, its own compiled/pinned executable SHA-256, `dsh-v0.1.2-rc.1`, every
declared plugin tree, and nine PASS observations, and is not produced by
Pilot-readiness. Before executing a required per-skill `compatibility-test.mjs`,
the Runner requires the independently signed
`schemas/managed-plugin-execution-admission-receipt-v1.schema.json`. The same
single-file Runner performs the nonce-bound internal probe; compatibility
reporters embedded in the candidate runtime are rejected.

The organization receipt uses the independent compiled
`EnterprisePluginAdmissionKeyId/X/Y` public key. It must not reuse the release,
lease, runtime-admission, or brand-authorization key ID or P-256 public point;
publisher config cannot inject or replace it. The ReleasePublisher build also
requires the Launcher's public `EnterpriseLeaseKeyId/X/Y` so this comparison is
performed against compiled signer-host trust rather than receipt-controlled
data.

Named-customer Pilot readiness additionally requires the independent compiled
`EnterpriseLocalDataCertificationKeyId/X/Y` root. A short-lived ES256 receipt
must bind the exact local-data report, its captured test-runner SHA-256, both
runtime ZIP hashes, both upstream tags, and the opaque Pilot audience. This
Publisher-only root is checked against release, runtime, plugin, brand, and
lease roots and is deliberately excluded from the employee Launcher trust
fingerprint. Production ReleasePublisher publish is self-contained single-file;
the wrapper pins its post-Authenticode EXE SHA-256 and the Pilot report records
the same identity.

The production publisher now consumes a short-lived, independently ES256-signed
`managed-plugin-promotion-journal-authorization` before it can sign a Release
Set containing a plugin policy. The authorization binds the exact publication
intent plus the current journal instance, revision, and head. The journal uses
`CreateNew` hash-chained entries, an atomically replaced head, a separate
CurrentUser-DPAPI high-water anchor, and an authenticated pending transaction.
Initialization is explicit; missing, deleted, replayed, expired, reordered, or
tampered state fails closed and never falls back to generation ledger v1.

Use the production ReleasePublisher itself to initialize the journal once or
emit its current 15-minute challenge:

```powershell
& $Publisher --initialize-plugin-promotion-journal |
  Set-Content -LiteralPath $ChallengePath -Encoding utf8NoBOM
& $Publisher --plugin-promotion-journal-challenge |
  Set-Content -LiteralPath $ChallengePath -Encoding utf8NoBOM
```

The independent authorization service signs that challenge and the exact
camelCase publication intent with
`release/scripts/New-EnterprisePluginPromotionJournalAuthorization.ps1`. Put
the resulting new file in the plugin artifact's
`pluginPromotionJournalAuthorizationPath`. Direct replay is rejected; an
in-progress crash transaction can recover only the same still-valid signed
authorization, old state, and intent.

CurrentUser DPAPI and local ACLs cannot detect a coordinated rollback of both
the journal and its anchor by the signer identity. Customer production remains
`NO-GO` until the deployment adds an issuer-side authorization/high-water
record or an approved WORM/TPM monotonic anchor. Run the signer under a dedicated
Windows identity and retain the journal on restrictive, backed-up storage.

The build workflow compares newly produced metadata with the lock used for that build. Its first run permanently burns the ID with an empty immutable `ensou-dsh-source-candidate/<releaseId>` reservation. The source build remains in a separate `contents: read` job. An isolated `contents: write` publish job downloads that same run's exact immutable Actions artifact by artifact ID, validates the four-file build output without extracting or executing the runtime, creates a draft Release at tag `<releaseId>` and the exact Launcher commit, uploads only ZIP, metadata, and SHA-256 evidence, re-downloads and verifies all three assets, then publishes and requires both final and reservation tags to be lightweight refs to the same commit and the final Release to be immutable. Any failure burns the ID; workflow reruns are rejected. Later promotion validates the immutable Release metadata and artifact bytes themselves; it deliberately does not compare an older candidate with the repository's current `versions/locked.json`. This allows the same reviewed bytes to continue from Lab to Pilot and Stable after the source lock moves forward.

## Build once, promote many

Lab, Pilot, and Stable point to the same immutable `releaseId`, file name, byte count, and SHA-256. Promotion creates and signs a channel-specific manifest; it never rebuilds or overwrites the package.

Anti-rollback generations, expiry, upstream commit provenance, and multi-artifact component plans are intentionally deferred to a version 2 contract. They must not be added to a version 1 manifest because the version 1 client rejects unknown fields.

## Personal Stable lifecycle evidence

### Personal production Installer: build once, sign, certify, promote

The Personal Installer is a separate, timestamped, single-file executable. A
development publish, including the CI payload generated by
`scripts/New-PersonalDevelopmentInstallerPayload.ps1`, is never distributable.
Production requires these external inputs before the first command runs:

- canonical company HTTPS origins ending in `/` for both manifest and artifact
  trust (not a channel-manifest path);
- one offline P-256 release key ID/public point and its separately protected
  PKCS#8 private key for `Ensou.Dsh.Personal.ReleasePublisher`;
- the organization Authenticode certificate, its SHA-256 thumbprint, and a
  reachable trusted RFC3161 timestamp service;
- the exact source-built Runtime ZIP plus complete-tree manifest; and
- immutable empty output directories on the release workstation.

Set the production trust once and pass the same global properties to every
publish. `PersonalProductionBuild=true` is mandatory: the `false`/`stable`
defaults only make ordinary development builds deterministic, and no Personal
project can publish unless it explicitly selects production or development.

```powershell
$ErrorActionPreference = 'Stop'
$ManifestOrigin = 'https://downloads.example.com/'
$ArtifactOrigin = 'https://downloads.example.com/'
$ReleaseKeyId = '<production-key-id>'
$ReleaseKeyX = '<p256-x-base64url>'
$ReleaseKeyY = '<p256-y-base64url>'
$StubVersion = '<reviewed-stub-protocol-version>'
$CanonicalLowSFromSequence = 1 # first certified feed; imported legacy feed uses audited N+1
$SignerSha256 = '<64-hex-authenticode-certificate-sha256-thumbprint>'
$PublishRoot = 'C:\release\personal\publish-once'
$GateEvidenceRoot = 'C:\release\personal\gate-evidence-once'
if (Test-Path -LiteralPath $GateEvidenceRoot) {
  throw 'Personal production gate evidence root must be new.'
}
New-Item -ItemType Directory -Path $GateEvidenceRoot | Out-Null
$ProductionGateEvidence = Join-Path $GateEvidenceRoot 'production-artifact-gate.json'

$TrustProperties = @(
  '-p:PersonalProductionBuild=true',
  "-p:PersonalManifestOrigin=$ManifestOrigin",
  "-p:PersonalArtifactOrigin=$ArtifactOrigin",
  '-p:PersonalChannel=stable',
  "-p:PersonalReleaseKeyId=$ReleaseKeyId",
  "-p:PersonalReleaseKeyX=$ReleaseKeyX",
  "-p:PersonalReleaseKeyY=$ReleaseKeyY",
  "-p:PersonalStartupStubVersion=$StubVersion",
  "-p:PersonalCanonicalLowSFromSequence=$CanonicalLowSFromSequence",
  "-p:PersonalAuthenticodeSignerSha256Thumbprint=$SignerSha256"
)

$ClientPublishes = [ordered]@{
  Stub = @('.\src\Ensou.Dsh.Bootstrapper\Ensou.Dsh.Bootstrapper.csproj', "$PublishRoot\stub")
  ClientBootstrapper = @('.\src\Ensou.Dsh.ClientBootstrapper\Ensou.Dsh.ClientBootstrapper.csproj', "$PublishRoot\client-bootstrapper")
  Launcher = @('.\src\Ensou.Dsh.Launcher\Ensou.Dsh.Launcher.csproj', "$PublishRoot\launcher")
  Maintenance = @('.\src\Ensou.Dsh.Personal.Maintenance\Ensou.Dsh.Personal.Maintenance.csproj', "$PublishRoot\maintenance")
}
foreach ($publish in $ClientPublishes.Values) {
  dotnet publish $publish[0] -c Release -r win-x64 --self-contained true `
    -p:PublishSingleFile=true -p:EnableCompressionInSingleFile=true `
    @TrustProperties --output $publish[1]
  if ($LASTEXITCODE -ne 0) { throw "Production publish failed: $($publish[0])" }
}
```

All five Personal WinExe projects enforce single-file compression in their
publish targets. Disabling it is a contract failure; trimming,
framework-dependent deployment, and NativeAOT remain outside this release
contract.

Timestamp-sign those four exact executables before constructing
`client-bundle.zip`. With a Windows certificate-store signer, the equivalent
SignTool contract is shown below; an HSM or signing service must produce the
same valid Authenticode and RFC3161 result without exporting its private key.

```powershell
$SignTool = '<absolute-path-to-reviewed-signtool.exe>'
$CertificateSha1 = '<certificate-store-sha1-selector>'
$TimestampUrl = 'https://<approved-rfc3161-service>/'
$ClientExecutables = @(
  "$PublishRoot\stub\Ensou.Dsh.Bootstrapper.exe",
  "$PublishRoot\client-bootstrapper\Ensou.Dsh.ClientBootstrapper.exe",
  "$PublishRoot\launcher\Ensou.Dsh.Launcher.exe",
  "$PublishRoot\maintenance\Ensou.Dsh.Personal.Maintenance.exe"
)
foreach ($executable in $ClientExecutables) {
  & $SignTool sign /fd SHA256 /td SHA256 /tr $TimestampUrl /sha1 $CertificateSha1 $executable
  if ($LASTEXITCODE -ne 0) { throw "Authenticode signing failed: $executable" }
}
```

Create the complete-tree-bound client ZIP with
`CompressionLevel.Optimal`; do not use the historical uncompressed CI path.
Before initializing or publishing on a signer workstation, run the read-only
upgrade check:

```powershell
& $PersonalReleasePublisher `
  --check-signing-ledger-upgrade-ready `
  --config $AbsoluteProductionConfig
if ($LASTEXITCODE -ne 0) { throw 'Personal signing-ledger upgrade check failed.' }
```

For a reviewed first-use ledger only, initialize the independent anchor once
with `--initialize-signing-ledger-anchor --config
<absolute-production-config>`. Then run
`Ensou.Dsh.Personal.ReleasePublisher --config
<absolute-production-config>` against the client ZIP and source-built Runtime
ZIP. The config must bind their external complete-tree manifests, the offline
release key, generation/sequence, expiry, provenance, and immutable HTTPS URIs.

The independent anchor uses schema v2 as a durable downgrade fence. New
initialization writes schema v2. When an authenticated schema-v1 anchor is
encountered, the Publisher takes the independent anchor lock and the channel
ledger lock, validates the current ledger or authenticated `.pending.v2`
transaction, and atomically persists the equivalent schema-v2 anchor before it
repairs or creates any v2 transaction state. An older schema-v1 Publisher takes
the same anchor lock and then rejects that anchor before it can advance N+1.
A `.pending.v2` created by the immediately preceding Publisher with schema-v1
nested anchors remains recoverable only when its authenticated previous/next
identity is exactly equivalent after the schema upgrade.

Publisher crash recovery uses only the authenticated `.pending.v2` transaction.
After the anchor, ledger head, immutable output, and DPAPI-protected
`.publication.v2` receipt have committed and read back, repeating the command is
idempotent only when the complete config, canonical output path, verified signed
manifest, current ledger head, and all four current artifact/complete-tree input
files are identical. Any changed config, path, input, manifest, receipt, or
ledger state fails closed. Each of those four inputs is held through commit by
the same ordinary single-link Windows file handle; its volume/file identity,
length, and SHA-256 are checked again against a fresh open of the configured path
after archive/tree validation and immediately before commit.

An exact retry does not re-sign: the supplied `ECDsa` object is unused on that
branch. Authorization instead comes from the DPAPI receipt, independent
anchor/head, canonical signed manifest, and an explicit requirement that the
manifest signature key ID equals the config signing key ID. The production CLI
still loads the configured private-key file before calling this API, so loss of
that file remains an operational availability blocker, not an authorization
bypass. Cancellation is honored until the final commit boundary. Before that
boundary the signed manifest exists only in memory: no plaintext staging file is
created, so there is nothing that can be copied or hard-linked into an
uncommitted valid release. The first transaction-specific persistent write after
that boundary is the DPAPI-protected `.pending.v2` intent. Manifest publication,
receipt persistence, pending cleanup, and readback then finish without
cancellation.

The authenticated receipt plus immutable manifest readback is the publication
commit boundary. Failure to delete `.pending.v2` after that point does not turn
the committed publication into a CLI failure. While cleanup remains blocked,
the same config/input/output may use the authenticated receipt for an exact
retry without re-signing, but every N+1 or otherwise different publication is
rejected before signing. A later invocation may proceed only after it
authenticates the pending transaction and receipt and successfully removes the
ordinary single-link pending marker. An unauthenticated, linked, or conflicting
pending marker always fails closed. Do not manually rename, replace, or delete a
cleanup-blocked marker. Release only the diagnosed transient handle or ACL
blocker, then repeat the exact committed command so the Publisher authenticates
and removes its own marker. If that still fails, quarantine the signer state and
open a release-security incident before any further sequence.

The legacy sibling `.pending` is deliberately not a supported recovery format.
The current Publisher never parses, renames, deletes, or converts it, and it
blocks both initialization and publication. Controlled recovery is:

1. Stop every Publisher process. Preserve byte-for-byte backups and SHA-256
   inventory for the production config, artifact/tree inputs, output manifest,
   whole signing-ledger root, independent anchor directory, and both pending
   marker names. Preserve the signer Windows identity and ACLs.
2. Run the read-only upgrade check above and retain its output. Never rename or
   copy `.pending` to `.pending.v2`, and never delete either marker to make the
   check pass.
3. If a regular legacy `.pending` exists, use only the exact previously approved
   Publisher binary that created it, under the same Windows identity and exact
   config/output/input bytes, to finish its legacy recovery. Verify that its
   ledger head, independent anchor, and output agree before it removes its own
   marker.
4. Rerun the new read-only check. Proceed only after it reports `READY` and the
   retained inventory shows no unauthorized change.
5. If the matching legacy binary is unavailable, the marker is linked, both old
   and v2 markers exist, or recovery does not close cleanly, quarantine that
   signer state and require an explicit release-security incident decision;
   do not initialize a replacement anchor or continue publishing.

After publication, assemble a new ordinary payload directory containing exactly:

```text
release-set.v2.json
Ensou.Dsh.Bootstrapper.exe
client-bundle.zip
runtime.zip
```

The first file is the ReleasePublisher output, the second is the already
timestamp-signed Stub, and the two ZIPs are the exact bytes named by the signed
manifest. Publish the Installer from that directory, then timestamp-sign the
result. Do not rebuild any client or payload byte after this point.

```powershell
$PayloadRoot = 'C:\release\personal\payload-exact-four-files'
$InstallerPublish = "$PublishRoot\installer"
dotnet publish `
  .\src\Ensou.Dsh.Personal.Installer\Ensou.Dsh.Personal.Installer.csproj `
  -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true `
  -p:EnableCompressionInSingleFile=true `
  @TrustProperties "-p:PersonalInstallerPayloadDirectory=$PayloadRoot" `
  --output $InstallerPublish
if ($LASTEXITCODE -ne 0) { throw 'Production Personal Installer publish failed.' }

$Installer = "$InstallerPublish\Ensou.Dsh.Personal.Installer.exe"
& $SignTool sign /fd SHA256 /td SHA256 /tr $TimestampUrl /sha1 $CertificateSha1 $Installer
if ($LASTEXITCODE -ne 0) { throw 'Production Personal Installer signing failed.' }

$Gate = .\scripts\Test-PersonalPublishedArtifacts.ps1 `
  -StartupStubPublishDirectory $ClientPublishes.Stub[1] `
  -ClientBootstrapperPublishDirectory $ClientPublishes.ClientBootstrapper[1] `
  -LauncherPublishDirectory $ClientPublishes.Launcher[1] `
  -MaintenancePublishDirectory $ClientPublishes.Maintenance[1] `
  -ClientBundleArchivePath "$PayloadRoot\client-bundle.zip" `
  -InstallerPublishDirectory $InstallerPublish `
  -InstallerPayloadDirectory $PayloadRoot `
  -ProductionDistributionGate `
  -RequireAuthenticode `
  -SignerSha256Thumbprint $SignerSha256 `
  -ProductionGateEvidencePath $ProductionGateEvidence
$Gate | ConvertTo-Json -Depth 4
```

The production gate runs the Installer's stateless
`--production-payload-self-check` while holding the exact Installer file open,
checks the signed manifest and all four embedded resource size/hash values,
validates both archives' complete trees and the embedded Stub signature, and
re-hashes the same locked Installer handle afterward. It fails unless every
executable has valid Authenticode and a trusted timestamp. The create-only
`$ProductionGateEvidence` file is the machine-produced source for the
distribution receipt and Stable promotion. Do not transcribe its Installer
hash, size, signer, timestamp, or compiled-trust fields by hand.

That output is necessary but not sufficient. The same immutable Installer and
release bytes must complete the exact PILOT-DESKTOP existing-upgrade and PilotNotebook
clean-install matrix in
[`docs/personal-dual-device-pilot.md`](../docs/personal-dual-device-pilot.md),
including seven shared checks on each device. Only the exact certified Pilot
bytes may enter the signed Personal distribution receipt and Stable
authorization; Stable promotion never rebuilds or re-signs them. Missing
signing, timestamp, receipt, Pilot, or promotion evidence is a hard `NO-GO`.

Personal Stable promotion is admitted only from the exact immutable bytes already
committed to Pilot. The certification matrix in
`personal-certified-distribution-receipt-v2.schema.json` contains exact
raw-byte references to three canonical sidecar receipts governed by
`personal-lifecycle-evidence-receipt-v1.schema.json`:

- `clean-device-lifecycle` covers clean install, Launcher self-update, actual
  Runtime/WebUI startup, client restart, offline repair, Pilot soak, and local
  history/workspace preservation.
- `two-update-upgrade-lifecycle` proves an old-install upgrade followed by a
  second consecutive update, actual Runtime restart, and preservation.
- `failure-recovery-lifecycle` proves whole-home restore, startup of the
  previous Runtime, interruption/weak-network/offline-replay recovery, offline
  repair, and preservation.

Each sidecar fixes its test-run UUID, target release set generation/sequence,
exact Pilot manifest SHA-256, both artifact tuples, completion time, ordered
required gates, gate evidence SHA-256, observed process role/state/executable
SHA-256, and the canonical local-data witness SHA-256. The sidecar must be
strict canonical JSON with no duplicate or unknown members. Its exact size and
raw SHA-256 are recorded in the distribution receipt. The independent ES256
Stable authorization continues to sign the raw distribution-receipt SHA-256,
forming the chain `authorization -> distribution receipt -> lifecycle
sidecars -> gate/process/local-data evidence`.

Evidence producers must construct the public receipt contract and call its
`SerializeCanonical()` method; hand-written JSON or a serializer with different
property ordering, whitespace, or timestamp formatting is not an admitted
production receipt.

Create the canonical distribution receipt with the FeedPromoter contract
producer. It consumes the same machine gate evidence directly:

```text
Ensou.Dsh.Personal.FeedPromoter certify-distribution
  --trust-policy <absolute-json>
  --pilot-manifest <absolute-json>
  --stable-manifest <absolute-json>
  --production-gate-evidence <absolute-json>
  --external-pilot-feed-evidence <absolute-json>
  --clean-device-lifecycle <absolute-json>
  --two-update-upgrade-lifecycle <absolute-json>
  --failure-recovery-lifecycle <absolute-json>
  --output <absolute-new-json>
```

The Stable FeedPromoter CLI therefore requires all six evidence inputs in
addition to the candidate, feed root, trust policy, and `--channel stable`:

```text
--certified-distribution-receipt <absolute-json>
--stable-authorization <absolute-json>
--clean-device-lifecycle <absolute-json>
--two-update-upgrade-lifecycle <absolute-json>
--failure-recovery-lifecycle <absolute-json>
--production-gate-evidence <absolute-json>
```

The promoter snapshots, bounds, hashes, strictly parses, and exact-compares
these receipts before creating a staging directory or changing public feed
state. Feed initialization creates the persistent publication/channel lock
files; promotion opens those existing locks and never creates them as part of
admission. Real Windows clean-device, two-update, and failure-recovery Pilot
runs remain an external production gate: the promoter and unit fixtures do not
manufacture production evidence.

### Enterprise Stable certification authorization

The Enterprise Stable authorization signer accepts a certified distribution
receipt only with a detached
`certified-distribution-receipt-authentication-v1.schema.json` document. An
independent certification workflow signs the lowercase SHA-256 of the exact
receipt bytes with its own P-256 key. The canonical signature payload is four
UTF-8 lines with no trailing newline: the domain
`ensou-dsh-certified-distribution-receipt-authentication-v1`, product,
release-set ID, and receipt SHA-256. The receipt-authentication public key and
the expected Installer certificate SHA-256 are signer-controlled inputs; they
must not be copied from the receipt. The receipt-authentication key must differ
from the Stable-authorization key by both key ID and public point.

`Test-CertifiedDistributionReceipt.ps1` retains deny-write/delete handles for
every ordinary single-link input, copies the Installer into a randomized
isolated snapshot below an operator-selected protected base, locks the
snapshot's complete directory chain against rename or deletion, and keeps
file-handle continuity through exact-byte hashing and
Authenticode verification. It authenticates the exact receipt and returns one
in-memory admission snapshot. The Stable signer consumes only that snapshot and
never reopens the receipt, manifest, or Installer path after validation.

Both `approvedAtUtc` and `feed.verifiedAtUtc` must be UTC, no later than the
current UTC time, and no older than `MaximumReceiptAgeHours` (24 hours by
default, hard-capped at 168). Re-signing the same immutable receipt does not
refresh those receipt timestamps, so a stale receipt remains rejected.

```powershell
pwsh -NoProfile -File .\release\scripts\New-EnterpriseStablePromotionAuthorization.ps1 `
  -ReleaseSetId <managed-release-id> `
  -ReceiptPath <absolute-certified-receipt-json> `
  -ReceiptAuthenticationPath <absolute-detached-authentication-json> `
  -ReceiptAuthenticationKeyId <independent-certification-key-id> `
  -ReceiptAuthenticationKeyX <unpadded-base64url-p256-x> `
  -ReceiptAuthenticationKeyY <unpadded-base64url-p256-y> `
  -InstallerPath <absolute-signed-installer-exe> `
  -ExpectedInstallerSignerSha256Thumbprint <trusted-64-hex-certificate-sha256> `
  -ManifestPath <absolute-pilot-manifest-json> `
  -ProtectedSnapshotBasePath <existing-absolute-protected-local-directory> `
  -CertificationPrivateKeyPath <absolute-stable-authorization-pkcs8> `
  -CertificationKeyId <stable-authorization-key-id> `
  -MaximumReceiptAgeHours 24 `
  -OutputPath <new-absolute-authorization-json>
```

## Plugin promotion journal authorization

The production plugin-policy publish is a three-step, fail-closed exchange. The
controlled Publisher first emits the current journal challenge and an exact
intent from the same locked release inputs that publishing will consume. The
independent authorization signer then signs those two files; the resulting new
authorization file is configured as `pluginPromotionJournalAuthorizationPath`
for the one production publish.

```powershell
& $Publisher --plugin-promotion-journal-challenge |
  Set-Content -LiteralPath $ChallengePath -Encoding utf8NoBOM
& $Publisher --plugin-promotion-journal-intent --config $ConfigPath |
  Set-Content -LiteralPath $IntentPath -Encoding utf8NoBOM
pwsh -NoProfile -File .\release\scripts\New-EnterprisePluginPromotionJournalAuthorization.ps1 `
  -ChallengePath $ChallengePath `
  -IntentPath $IntentPath `
  -PrivateKeyPath $JournalAuthorizationPrivateKeyPath `
  -KeyId <independent-journal-authorization-key-id> `
  -OutputPath $JournalAuthorizationPath
```

`--plugin-promotion-journal-intent` never opens the release private key and
does not initialize, read, or consume the signer-local journal. It still
strictly snapshots and validates the production config, artifacts, and all
promotion evidence. The first journal initialization is a separate, explicit
one-time `--initialize-plugin-promotion-journal` operation.

Consumption is idempotent only for the exact latest authorization bytes and
the exact bound intent. This read-only retry returns the already committed
journal entry without advancing the head, closing the crash window between the
journal commit and creation of the Publisher publication transaction. Once the
journal records an in-window `consumedAtUtc`, that exact recovery may finish
after the authorization expiry time; a reformatted authorization, changed
intent, older authorization, or competing head is still rejected.

## Offline Publisher-to-Control handoff

Enterprise release signing remains an offline-signer responsibility. After the
root-owned Linux FeedPromoter has accepted a production candidate, operations
transfers only its machine result receipt, the exact promoted channel manifest,
and the exact immutable promotion journal entry back to the offline signer. The
`release-policy sign-handoff` command requires `--promotion-result-receipt`,
locks the result, manifest, journal, and private key together, and re-verifies
their exact identity, raw-byte hashes, canonical Site feed paths, and publication
time before signing a short-lived Control policy handoff. The signed payload
commits `promotionResultSha256` as well as the manifest and journal hashes. The
offline signer's local evidence-copy paths may differ from the canonical Linux
paths recorded by FeedPromoter. Only the signed handoff returns to the Site
server. The release private key is never uploaded to the Site, included with a
candidate, or passed as raw argv/environment material.

The Control Admin CLI then performs its own production-compiled-trust preflight
over all four exact evidence files before the idempotent database import. The
preflight checks expiry margin and exactly `launcher`, `runtime`, and
`plugin-policy`; it does not replace the FeedPromoter's manifest/artifact
signature verification. These operation contracts do not replace the
signer-side journal, its independent authorization, the required external
monotonic high-water control, or the named-customer evidence described above.

## Personal v2 production distribution preflight

Run the Linux FeedPromoter as root with `preflight-distribution` before creating
a Personal Stable distribution receipt. The command is read-only: it does not
write a receipt, move a feed head, or authorize distribution. Its
`receipt-preview` digest identifies only the in-memory receipt candidate checked
during that invocation. `certify-distribution` uses a new UTC approval time, so
its final receipt digest normally differs even when every other input is
unchanged.

```text
Ensou.Dsh.Personal.FeedPromoter preflight-distribution \
  --trust-policy /root/ensou/personal-feed-trust.json \
  --pilot-manifest /root/ensou/release/pilot/release-set.v2.json \
  --stable-manifest /root/ensou/release/stable/release-set.v2.json \
  --production-gate-evidence /root/ensou/evidence/production-gate.json \
  --external-pilot-feed-evidence /root/ensou/evidence/external-pilot-feed.json \
  --clean-device-lifecycle /root/ensou/evidence/clean-device.json \
  --two-update-upgrade-lifecycle /root/ensou/evidence/two-update-upgrade.json \
  --failure-recovery-lifecycle /root/ensou/evidence/failure-recovery.json
```

The preflight fails closed unless all of these form one exact distribution
closure:

1. the root-owned trust policy has canonical HTTPS manifest and artifact
   origins, independent production release/certification P-256 keys, and one
   pinned Authenticode signer thumbprint. It also records
   `canonicalLowSFromSequence`: signatures below that audited feed cutover may
   use the legacy schema-v2 ECDSA representation, while that sequence and every
   later release must use canonical low-S P1363 signatures. The first certified
   Ensou Personal feed uses cutover sequence `1`; an imported legacy feed must
   inventory its immutable head and compile the same explicit `N+1` cutover
   into every client before promotion;
2. the canonical Pilot and Stable manifests have valid signatures and match in
   release identity, immutable artifacts, ordering, compatibility, revocations,
   timestamps, and launcher/Harness source provenance;
3. the Stable manifest signature uses the same release key identity captured by
   the production clients' compiled-trust evidence;
4. the production artifact gate binds the exact Stable manifest, payload,
   client bundle, Installer, four client executables, compiled trust, valid
   Authenticode status, pinned signer, and timestamps. The Windows gate producer
   performs the direct binary inspection; this Linux preflight validates its
   strict canonical, hash-bound evidence;
5. external Pilot evidence names the exact HTTPS channel head and proves the
   same manifest and immutable artifacts; and
6. clean-device, two-update upgrade, and failure-recovery receipts are three
   distinct canonical runs targeting the exact Pilot/Stable closure and local
   data witnesses.

After a PASS, `certify-distribution --output <absolute-new-json>` reruns the same
validation and performs a create-only write. Stable promotion still requires
that receipt plus a separate, short-lived certification-key authorization. A
preflight PASS by itself is never a distributable receipt or a promotion
authorization.

## Local validation

```powershell
pwsh -NoProfile -File .\release\scripts\Test-ReleaseContracts.ps1
pwsh -NoProfile -File .\release\scripts\Test-PortableDotNetSdkClosure.ps1
pwsh -NoProfile -File .\release\scripts\Test-NewPortableDotNetSdkLock.ps1
pwsh -NoProfile -File .\release\scripts\Test-EnterprisePluginPromotionJournalAuthorization.ps1
pwsh -NoProfile -File .\release\scripts\Test-WorkflowPins.ps1
pwsh -NoProfile -File .\release\scripts\Test-SourceRuntimeMetadata.ps1 -MetadataPath .\release\examples\source-runtime.metadata.json
```
