# Launcher production release orchestration v1

This document describes the operator-facing, fail-closed contract implemented by `release/scripts/Invoke-LauncherProductionRelease.ps1`. It applies to both Personal and Enterprise editions. Typed manifest-publishing r4/r5, Installer-signing r6/r7, Enterprise Stable Pilot-evidence binding r8, offline promotion authorization r9, and authenticated Linux publication-result import r10 are connected. This is not release approval: committed state remains `productionAdmission=NO_GO`, r9 never contacts a feed, and r10 authenticates a completed operation without deploying the shared server or proving employee acceptance.

### Personal Pilot requires two independent Windows lanes

The Personal Pilot is not complete until the same signed candidate has been
tested on both required Windows x64 devices: the existing PILOT-DESKTOP desktop
(upgrade/coexistence lane) and the clean PilotNotebook notebook (first-install
lane). They must use independent installation/device identities; no token,
secret, or credential is stored in the plan or transferred between devices.

The offline acceptance matrix is mandatory for both lanes: first install,
existing-version upgrade, startup update discovery, runtime-only update,
Launcher-only update, failed-update rollback, offline last-known-good startup,
unchanged local chat/workspace data, and no visible command window. The plan
example and validator encode these requirements; they are gates, not synthetic
device evidence. Real device evidence remains required before distribution.

## Entry point and required inputs

Run the entry point from its canonical path in the exact Launcher Git top-level checkout:

```powershell
pwsh -NoProfile -File release/scripts/Invoke-LauncherProductionRelease.ps1 `
  -RepositoryRoot C:\path\to\launcher-enterprise-wecom `
  -Edition Personal `
  -Phase Prepare `
  -PlanPath C:\release-input\plan.json `
  -StateRoot C:\release-state\personal-v2026.08.30.1
```

`-Edition` is `Personal` or `Enterprise`. The plan, state root, runtime evidence, client inputs, and signing response must be absolute paths outside the Launcher checkout. Every state-changing phase requires a plan validated by `launcher-production-release-plan-v2.schema.json`; schema v1 is retired from mutation and is accepted only by the read-only `Status` phase for historical replay. Plan v2 binds:

- orchestration, edition, release-set, channel, manifest URI, and artifact-base URI;
- exact Launcher `sourceCommit`;
- local runtime archive, metadata, and SHA-256 evidence descriptors;
- the edition-specific four unsigned client roles in canonical order;
- the required Authenticode signer SHA-256 certificate digest and response lifetime;
- a purpose-specific ES256 public key and key ID for authenticating the external signing response.

The checkout must be clean, including untracked files, and `HEAD` must equal `plan.sourceCommit`. The entry point, shared module, both edition adapters, four orchestration schemas, runtime metadata validator, and runtime metadata schema must all be canonical tracked files whose working bytes equal their `HEAD` blobs. These code bytes remain locked while a transition is admitted. An external or modified copy of the entry point is rejected.

The local runtime candidate is checked for exact file names, sizes, hashes, canonical SHA-256 line, and `promotionEligible=true` metadata. This is descriptor validation only. Until an authenticated receipt proves the immutable GitHub Release/tag and its exact three assets, the persisted boundary is:

```text
IMMUTABLE_SOURCE_RELEASE_UNVERIFIED
```

It must never be interpreted as production source-release admission.

## Implemented phases

### `Prepare`

`Prepare` creates or resumes a state root, appends `PLAN_ADMITTED`, snapshots the edition-specific unsigned client files, and appends `CLIENT_SIGNING_REQUESTED`. The resulting request bundle is:

```text
requests/client-signing.v1/
  signing-request.v1.json
  unsigned/<exact four edition-specific PE files>
```

`signing-request.v1.json` is validated by `launcher-external-signing-request-v1.schema.json`. It binds the plan hash, orchestration identity, release-set identity, fresh random nonce, creation and expiry times, response-attestation key ID, Authenticode signer policy, and each role's exact input SHA-256 and PE-content identity.

Successful `Prepare` still prints a `NO-GO` summary containing `IMMUTABLE_SOURCE_RELEASE_UNVERIFIED`.

### `ImportClientSignatures`

#### Assemble a response from externally signed client files

When an approved external signer returns only the four signed client PEs, use
`release/scripts/New-ProductionClientSigningResponse.ps1` to assemble the
existing authenticated response bundle. This local tool works with both
Personal and Enterprise plan v2; it does not select or call a CA, sign Windows
executables, install trust, upload artifacts, or advance release state.
Windows certificate and revocation validation may consult network services;
the tool does not guarantee an entirely network-free execution.

Prerequisites are the exact committed r2 `CLIENT_SIGNING_REQUESTED` state,
the four correctly named files in a separate flat signed-input directory,
and the existing approved PKCS8 P-256 **response-attestation** private key
matching `plan.externalResponseTrusts.clientSigning`. That key is separate
from the vendor-held Authenticode key. Do not place private keys inside the
checkout, state, signed input, output bundle, or a command-line value.

```powershell
pwsh -NoProfile -File release/scripts/New-ProductionClientSigningResponse.ps1 `
  -StateRoot C:\release-state\enterprise-candidate `
  -ExpectedHeadSha256 <exact-r2-head-from-Status> `
  -SignedClientRoot C:\signer-return\enterprise-client-files `
  -ResponsePrivateKeyPath C:\protected-response-keys\client-response.pk8 `
  -OutputRoot C:\signer-return\authenticated-enterprise-client-response
```

The output directory must not exist, and its parent must already exist.
The tool locks the state and inputs, checks the request's plan/receipt/nonce,
role order and lifetime, verifies actual Windows Authenticode and exact
RFC3161 evidence with unchanged PE content, signs the existing response
payload, and validates it before publishing a create-only bundle. A wrong
key, stale head, expired request, unexpected file or invalid signature fails
without advancing state. Never repair a rejected bundle by editing JSON.
Inspect the error, correct the external input, then use a fresh output path;
an expired or advanced request must be handled by the existing release-state
workflow, not by changing its timestamps or receipts.

This command supplies only the **client signing** response. It does not
replace the separate Installer r6/r7 signing response, vendor account setup,
release approval, real HTTPS update tests or named-device acceptance. Its
output is not a distributable release. Import the generated response below.

The operator supplies `-ResponsePath <bundle>/signing-response.v1.json` and the exact current `-ExpectedHeadSha256` printed by `Status` or `Prepare`. A stale head is rejected before response admission. The external bundle has exact inventory:

```text
<bundle>/
  signing-response.v1.json
  signed/<exact four edition-specific PE files>
```

The response is validated by `launcher-external-signing-response-v1.schema.json`. Its purpose-specific ES256 attestation must bind the request hash, plan hash, nonce, orchestration/release identity, completion time, canonical role order, input hashes, returned hashes, and PE-content identities. The private attestation key and Authenticode signing key remain outside this repository and state tree. An HSM or approved signing service returns only the signed PEs and authenticated response document; operators must not insert private key material into a plan, request, state directory, or command line.

For every returned PE, import requires all of the following:

- exact role, file name, input hash, output hash, and unchanged PE-content identity;
- module-qualified `Microsoft.PowerShell.Security\Get-AuthenticodeSignature` status `Valid`;
- signer certificate SHA-256 equal to the plan policy;
- a trusted timestamp certificate;
- an RFC3161 timestamp-token unsigned attribute with OID `1.2.840.113549.1.9.16.2.14`;
- `.NET Rfc3161TimestampToken.VerifySignatureForSignerInfo` success against the exact primary Authenticode `SignerInfo`, which proves the token `messageImprint` is not from another signature;
- the RFC3161 token signer certificate SHA-256 equal to `Get-AuthenticodeSignature.TimeStamperCertificate`.

A legacy Authenticode `counterSignature` OID `1.2.840.113549.1.9.6`, an unrelated but valid RFC3161 token, a missing timestamp, or a caller-shadowed security cmdlet is rejected. Accepted bytes are copied to `imports/client-signing.v1`, and `CLIENT_SIGNATURES_IMPORTED` is appended. This phase remains `NO-GO` for production publication.

### `Status`

`Status` validates the complete state inventory and receipt chain, then prints the orchestration identity, edition, revision, phase, head SHA-256, and current `NO-GO` reason. It never creates a usable release state.
It is the only phase that accepts a historical schema-v1 plan/state. `Prepare`,
all import/request/binding phases, and `Promote` reject schema v1 before opening
or changing the supplied state root.

Enterprise Stable schema-v2 states at committed r8, r9, or r10 also support an
explicit read-only `-RevalidatePilotEvidence` switch. Pass the exact current
`-ExpectedHeadSha256` and all nine original evidence paths listed in
[`production-pilot-evidence-r8-v1.md`](production-pilot-evidence-r8-v1.md).
The switch is rejected with every phase other than `Status`.

This opt-in path reauthenticates the four imported client PEs and their original
signing response, replays the independently signed Pilot evidence, requires its
rebuilt canonical summary to equal the committed r8 bytes, then replays the
state again under the retained read lock. Original client response age is
evaluated at its original import time; Pilot policy age, minimum remaining
validity, and absolute expiry must still pass at final status time. It writes
no output bundle, receipt, state head, or feed and does not refresh evidence.

A successful check reports `RevalidatedReleaseEvidence=true`,
`ClientSigningEvidence=REVALIDATED`, and
`ReadinessScope=AUTHENTICATED_RELEASE_STATE_ONLY`. At r10 it can also report
`FeedPublicationEvidence=AUTHENTICATED_COMPLETED_FEED_OPERATION_ONLY`.
**`StableReady` remains false:** the immutable GitHub source-release admission
is not yet consumed by the signed release chain, so r10 retains
`IMMUTABLE_SOURCE_RELEASE_UNVERIFIED`. r8/r9 additionally still require the
promotion/publication transition. Neither ordinary nor opt-in `Status` is
permission to distribute a synthetic candidate.

### Enterprise Stable `Promote`: r8 to r9, offline only

For an Enterprise schema-v2 plan whose target channel is `stable`, `Promote` is
implemented only as the network-free r8-to-r9 transition. The source must be the
exact committed r8 `PILOT_EVIDENCE_BOUND` state, its Pilot evidence must still be
current, and `-ExpectedHeadSha256` must equal the r8 release-state head printed by
`Status`. This value is the Launcher orchestration CAS; it is not the separate
offline promotion-workspace head.

The first call creates or exactly resumes an external, create-only promotion
workspace and returns the request path and promotion-head SHA-256. Omit
`-FeedPromotionResponsePath` on this call:

```powershell
pwsh -NoProfile -File release/scripts/Invoke-LauncherProductionRelease.ps1 `
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

`-PromotionRoot` must be absolute, external to the checkout and production state,
and disjoint from both. `-ExpectedFeedIdentitySha256` is the independently
verified production-feed identity, not a channel-head hash. Both feed CAS
arguments use exactly one of these forms:

```text
missing
present:<size>:<sha256>
```

Use `missing` only when that raw feed file does not exist. For an existing file,
`size` is its positive decimal byte length and `sha256` is its lowercase digest;
both cover the exact current bytes. The channel head is bounded
to 512 KiB and the journal head to 128 KiB. Empty strings, zero sizes, uppercase
hashes, JSON-semantic hashes, and guessed state are rejected.

Move `request/request.v1.json` and a verified copy of `head.json` from the
promotion workspace to the offline authorization workstation. The signer writes
its create-only response outside the checkout, state root, and promotion root:

```powershell
pwsh -NoProfile -File release/scripts/New-ProductionFeedPromotionAuthorizationResponse.ps1 `
  -RequestPath C:\release-work\enterprise-stable-promotion\request\request.v1.json `
  -PromotionHeadPath C:\release-work\enterprise-stable-promotion\head.json `
  -AuthorizationPrivateKeyPath C:\offline-keys\feed-promotion-response.pk8 `
  -AuthorizationKeyId <plan-fixed-feed-promotion-response-key-id> `
  -OutputPath C:\offline-response\response.v1.json
```

The signed response has `productionAdmission=OFFLINE_BUNDLE_ONLY` and
`networkPublishPerformed=false`. Re-run the same Enterprise Stable `Promote`
command with the same five workspace/admission/CAS values and add the sixth
parameter, the response path:

```powershell
  -FeedPromotionResponsePath C:\offline-response\response.v1.json
```

After exact response admission, the orchestrator snapshots this five-JSON,
state-owned package and appends r9 `STABLE_PROMOTION_REQUESTED`:

```text
<StateRoot>/requests/stable-feed-promotion.v1/
  request.v1.json
  response.v1.json
  promotion-head.v1.json
  bundle-head.v1.json
  promotion-admission.v1.json
```

The package binds the exact r8 state, five Enterprise candidate payload
descriptors, feed identity, both raw-file CAS expectations, signed authorization,
promotion-workspace heads, and bundle-set hash. The request, both heads,
promotion admission, and r9 receipt remain `productionAdmission=NO_GO`; the
embedded signed response remains `OFFLINE_BUNDLE_ONLY`. Every network-publication
flag is false. Exact replay and supported crash recovery are idempotent, while
stale r8 heads, expired Pilot/authorization evidence, changed paths or bytes,
links, unexpected inventory, and mismatched CAS values fail closed.

## State, receipts, and recovery

The persistent state root contains only:

```text
state.lock
identity.json
plan.json
head.json
receipts/
requests/
imports/
```

Identity, head, and transition receipts use strict schemas with no additional properties. Each receipt binds the identity hash, plan hash, prior receipt hash, revision, phase data, and whole-second UTC time. `head.json` binds the final receipt and is replaced with a compare-and-swap commit through `head.json.pending`. Every admitted request/response document and client payload is rehashed from its state snapshot and compared with its receipt whenever state is read. Receipts are append-only; unexpected files, directories, links, hard links, wrong role inventories, orphan transitions, malformed times, payload changes, or chain changes fail closed.

`Prepare` is idempotent and resumes the supported receipt/request crash points without appending duplicates. `ImportClientSignatures` is idempotent only for the exact already-imported response. A caller must retain the last observed head SHA-256 and pass it for a new import; concurrent or stale work cannot advance the state.

Path-based validators never inspect the original caller-controlled path after trusting only its handle. Locked input bytes are copied to a CreateNew `.verification` workspace under the locked state root, reopened as an ordinary single-link read lock, checked for the same size and SHA-256, validated through that private path, and checked again before removal. A stale `.verification` workspace or any namespace/inventory change is a hard failure; it is never auto-admitted.

## Later phases and current hard boundaries

Enterprise Stable `BindPilotEvidence` is implemented. It accepts exactly nine
external Pilot inputs, invokes the purpose-specific adapter without a shell,
admits only its canonical typed bundle, keeps the r7 head as an explicit CAS,
revalidates the independently anchored trust policy and current evidence
lifetime at commit time, and appends r8 `PILOT_EVIDENCE_BOUND`. Exact replay is
idempotent; stale, changed, expired, orphaned, linked, or differently trusted
evidence fails closed. This is an evidence-binding transition, not proof that a
synthetic fixture represents a real Pilot.

The remaining hard `NO-GO` boundaries include Personal Stable
`BindPilotEvidence`, authenticated immutable source-release admission, and
unfulfilled real signing, hosting, identity, and named-device acceptance.
Personal Pilot promotion and Enterprise Stable r10 import are implemented
transitions, not substitutes for those external facts.

Personal `PrepareInstallerSigning` / `ImportInstallerSignature` are now implemented with the same exact state CAS, create-only bundle replay, and typed receipt boundary as the Enterprise path. Personal r6 produces an external signing request from the locked source/payload closure; Personal r7 accepts only an authenticated response bound to that exact request. The trusted builder deliberately returns `productionAdmission=NO_GO` with `admissionReason=INSTALLER_SIGNING_RESPONSE_REQUIRED`; real certificate/RFC3161 evidence, DNS/TLS publication, and device Pilot evidence remain required before distribution. Enterprise Stable r4/r5 and r6/r7 retain their purpose-specific adapters and remain independently gated. See [`../installer-signing-r6-r7-v1.md`](../installer-signing-r6-r7-v1.md) for the shared signing boundary.

Enterprise Stable `Promote` now uses the network-free promotion module to create
the immutable r8-bound request, admit the independently signed
`OFFLINE_BUNDLE_ONLY` response, preserve the exact five-JSON package, and append
r9 `STABLE_PROMOTION_REQUESTED`. This implemented r9 is deliberately still
`NO_GO`: the main orchestrator does not invoke the root-owned Linux FeedPromoter.
From committed r9 it can export a publication context and import a separately
authorized, independently signed completed publication bundle as r10. See
[`ADR 0007`](../adr/0007-enterprise-stable-publication-result.md) for the exact
Linux attestor, plan-fixed key, raw-file observation, import, and recovery
contract. A successful import alone does not establish overall readiness.

None of these boundaries can be bypassed by manufacturing local files or editing state. Until the trusted in-process source-build producer, real signing evidence, Pilot evidence, and promotion authorization are all independently admitted, this orchestration produces no employee-visible update.

## Operator handoff boundary

Before a real Linux publication handoff, the exact r1 through r7 chain must
contain real Authenticode/RFC3161 evidence, the nine r8 inputs must come from the
real two-device private Pilot, and the r9 response must be produced by the
independent offline authorization key. Preserve the state, original Pilot
evidence files, promotion workspace, offline response, and five-JSON package.
Without those facts, r5/r7/r8/r9/r10 tests remain contract or synthetic evidence.
An r9 offline bundle is not employee feed publication; an authenticated r10
operation is not global release approval. Real HTTPS download/update tests and
named-device acceptance still apply. Synthetic CMS or typed-state replay proves
only verifier/CAS behavior and is never production evidence.
