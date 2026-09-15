# Enterprise customer Pilot readiness

`EnterprisePilotReadiness` is the final technical admission check between a
production release-set publication and delivery to a named employee Pilot. It
does not sign, rebuild, upload, install, or deploy anything. It consumes only
public trust inputs and already-produced local artifacts, then writes one
machine-readable `ADMIT` or `REJECT` report.

An `ADMIT` report is necessary but not sufficient for customer delivery. It
does prove that an independent brand-authorization signer approved the exact
written evidence and final branded bytes, and that a separately trusted
local-data certifier signed the exact compatibility report and captured runner.
Current upstream review, company
service deployment, named Pilot authorization, and clean-machine operational
replay remain separate release gates.

## Fail-closed boundary

The preflight accepts exactly:

- native Windows `win-x64`, production layout `enterprise`, and channel
  `pilot`;
- artifact authorization `SIGNED_RELEASE_SET`;
- complete organization HTTPS update, artifact, control, authorization, and
  gateway origins;
- one release key, one lease key, and separately compiled runtime-admission,
  plugin-admission, plugin-promotion-journal, brand-authorization, and local-data
  certification keys. The local-data certification root is checked independently against all six other
  P-256 roots and is Publisher-only; it is not added to the employee Launcher's
  public-trust fingerprint;
- one 64-hex Authenticode signer SHA-256 thumbprint;
- a signed production `release-set.v2.json` with exactly Launcher, runtime, and
  plugin-policy artifacts whose local bytes match signed size and SHA-256. The
  top-level Launcher, ClientBootstrapper, and Maintenance executables are
  immutable snapshot inputs and must match the size and SHA-256 of their exact,
  uniquely named root entries in the signed Launcher archive. The archive's
  production profile marker is likewise byte-bound to the marker captured
  alongside the top-level Launcher;
- the protected production publisher ledger, hash-bound by the readiness input,
  whose current generation, sequence, minimum sequence, release-set id, and
  canonical manifest digest exactly identify that signed release. A stale or
  subsequently superseded release therefore cannot self-admit;
- a signed runtime organization-admission receipt bound to the exact pinned
  source metadata and runtime ZIP;
- a plugin-policy ZIP whose strict policy, compatibility, inventory, bytes, and
  builder metadata match the signed artifact;
- signed Installer, stable Bootstrapper, and Launcher executables. Their
  isolated no-system-.NET self-checks must pass; the Launcher additionally
  proves its compiled update/control public trust fingerprint matches the
  preflight input. The Installer must hash every embedded payload and prove its
  launcher/runtime digests equal the signed release-set while its embedded
  Bootstrapper digest equals the separately signed Bootstrapper under test;
- an independently ES256-signed brand-authorization receipt for one opaque
  customer-audience UUID. It binds the exact signed release-set manifest,
  Launcher archive, post-Authenticode Launcher/Bootstrapper/Installer bytes,
  product and developer names, visible presentation profile, official whale
  SVG plus exact PNG/ICO derivatives, and the SHA-256/size/media type of the
  retained written permission. The authorization review must be newer than 30
  days, cannot last more than 90 days, and must cover the release-set expiry;
- all three production executables must pass `--brand-self-check` against the
  authorized profile. The check verifies the component Product metadata,
  `ensou studio` Company metadata, and separately embedded exact SVG/PNG/ICO
  bytes; merely setting the Windows application icon is insufficient;
- the exact startup update contract: check on every start, atomic release-set
  activation, Bootstrapper health rollback, seven-day offline grace, and
  managed plugin-policy v1.
- a SHA-256-bound local-data compatibility report for the exact source and
  target upstream tags and runtime ZIP hashes. It must prove credentials
  migration, JSONL/Zstandard session resume and append through the public API,
  a loopback-provider conversation, attachment retrieval, the deployed query
  policy semantics, workspace preservation, and byte-exact whole-home restore.
- a short-lived independently ES256-signed local-data certification receipt.
  It binds the exact report SHA-256, captured `testRunner.sha256`, source and
  target runtime ZIP hashes, upstream tags, and one opaque named-customer
  certification-audience UUID. The receipt is snapshotted and re-hashed before
  validation; missing, altered, wrong-audience, or wrong-runner receipts fail
  closed.

Any missing, empty, development-E2E, placeholder, unexpected, incorrectly
signed, stale-sequence, revoked, incompatible, or byte-drifted input produces a
non-zero exit and a `REJECT` report. The readiness config itself rejects the
literal development and unsigned-candidate states and placeholder production
hosts. Pre-publication builder metadata is evidence only; it never authorizes
delivery. Runtime and plugin delivery authorization comes from each artifact's
verified ES256 signature inside the final release-set.

The exact input and report contracts are:

- `release/schemas/enterprise-pilot-readiness-v1.schema.json`
- `release/schemas/enterprise-pilot-readiness-report-v1.schema.json`
- `release/schemas/enterprise-brand-authorization-receipt-v1.schema.json`
- `release/schemas/enterprise-local-data-compatibility-evidence-v1.schema.json`
- `release/schemas/enterprise-local-data-forward-result-v1.schema.json`
- `release/schemas/enterprise-local-data-rollback-result-v1.schema.json`
- `release/schemas/enterprise-local-data-api-lane-result-v1.schema.json`
- `release/schemas/enterprise-local-data-compatibility-certification-receipt-v1.schema.json`
- `release/schemas/enterprise-plugin-promotion-journal-authorization-v1.schema.json`

`release/examples/enterprise-pilot-readiness.config.example.json` shows the
complete shape with deliberate non-production placeholders. Replace every
path, origin, public key, audience UUID, and SHA-256 from controlled evidence;
the example itself is not admissible.

## Signing and secret boundary

Build and Authenticode-sign the production ReleasePublisher on the controlled
release machine. Its publish must receive the public runtime-admission and
brand-authorization keys plus the public signer thumbprint:

```powershell
dotnet publish .\src\Ensou.Dsh.Enterprise.ReleasePublisher\Ensou.Dsh.Enterprise.ReleasePublisher.csproj `
  -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true `
  -p:EnterpriseRuntimeAdmissionKeyId=<public-key-id> `
  -p:EnterpriseRuntimeAdmissionKeyX=<public-p256-x> `
  -p:EnterpriseRuntimeAdmissionKeyY=<public-p256-y> `
  -p:EnterprisePluginAdmissionKeyId=<independent-plugin-public-key-id> `
  -p:EnterprisePluginAdmissionKeyX=<independent-plugin-public-p256-x> `
  -p:EnterprisePluginAdmissionKeyY=<independent-plugin-public-p256-y> `
  -p:EnterprisePluginPromotionJournalKeyId=<independent-journal-public-key-id> `
  -p:EnterprisePluginPromotionJournalKeyX=<independent-journal-public-p256-x> `
  -p:EnterprisePluginPromotionJournalKeyY=<independent-journal-public-p256-y> `
  -p:EnterpriseBrandAuthorizationKeyId=<independent-public-key-id> `
  -p:EnterpriseBrandAuthorizationKeyX=<independent-public-p256-x> `
  -p:EnterpriseBrandAuthorizationKeyY=<independent-public-p256-y> `
  -p:EnterpriseLeaseKeyId=<launcher-lease-public-key-id> `
  -p:EnterpriseLeaseKeyX=<launcher-lease-public-p256-x> `
  -p:EnterpriseLeaseKeyY=<launcher-lease-public-p256-y> `
  -p:EnterpriseLocalDataCertificationKeyId=<independent-certification-public-key-id> `
  -p:EnterpriseLocalDataCertificationKeyX=<independent-certification-public-p256-x> `
  -p:EnterpriseLocalDataCertificationKeyY=<independent-certification-public-p256-y> `
  -p:EnterprisePilotEvidenceKeyId=<independent-pilot-evidence-public-key-id> `
  -p:EnterprisePilotEvidenceKeyX=<independent-pilot-evidence-public-p256-x> `
  -p:EnterprisePilotEvidenceKeyY=<independent-pilot-evidence-public-p256-y> `
  -p:EnterpriseAuthenticodeSignerSha256Thumbprint=<64-hex-sha256>
```

The publish target rejects a framework-dependent or multi-file Publisher. This
makes `Environment.ProcessPath` the exact signed self-contained Publisher EXE,
whose SHA-256 is pinned by the wrapper and recorded in every Pilot report.

The release-signing, runtime-admission, plugin-admission,
plugin-promotion-journal, brand-authorization, lease, local-data-certification,
Windows-Pilot-evidence attestation, and code-signing private keys, activation-grant secret,
model-provider key, customer token, and access token must never appear in the
readiness JSON, report, repository, or command line. The brand-authorization private key belongs to the designated
brand/legal approver; its signature attests that the retained written evidence
was reviewed. It does not pretend to be a DeepSeek signature.

The Windows Pilot evidence root is another independent P-256 authority. The
signed Publisher rejects reuse of the release, runtime-admission,
plugin-admission, plugin-journal, brand, lease, or local-data-certification key
as the Pilot evidence key. Only its public coordinates are compiled; its
private key stays with the controlled Pilot observer/attestation service.

The local plugin-promotion journal and its CurrentUser-DPAPI anchor close direct
replay and partial-state rollback, but cannot detect a coordinated restore of a
complete historical copy by the signer identity. Customer production delivery
therefore remains `NO-GO` until every publish also checks an issuer-side atomic
authorization-id/high-water record, or an approved WORM/TPM monotonic anchor.
Local ACLs, DPAPI, and backup retention remain required defense in depth but do
not replace that external monotonic control.

Keep the filled readiness JSON, signed brand receipt, original written evidence,
and report in the controlled release evidence store, not in Git. They may
contain public keys, an opaque audience UUID, and local release-machine paths,
but no secret or customer name is required. The config must bind the exact
release-set id, generation, sequence,
minimum accepted sequence, protected publisher-ledger path, and lowercase
ledger SHA-256 so a different or stale signed release cannot be admitted
accidentally. The ledger and release directory must be the immutable snapshot
that was actually published as the Pilot feed head, not merely a local draft.

## Run the preflight

Invoke the signed production ReleasePublisher through the wrapper:

```powershell
pwsh -NoProfile -File .\scripts\Test-EnterprisePilotReadiness.ps1 `
  -PublisherExecutablePath C:\controlled-tools\Ensou.Dsh.Enterprise.ReleasePublisher.exe `
  -ReadinessConfigPath C:\release-evidence\pilot-readiness.v1.json `
  -ReportPath C:\release-evidence\pilot-readiness.report.v1.json `
  -PublisherSignerSha256Thumbprint <64-hex-sha256> `
  -PublisherExecutableSha256 <lowercase-64-hex-sha256>
```

The wrapper first verifies the ReleasePublisher embedded Authenticode signature,
trusted timestamp, signer, and exact
EXE SHA-256, invokes
`--pilot-readiness-config ... --report-stdout`, captures the Publisher's exact
machine JSON directly, and independently requires a v1 production/Pilot
`ADMIT` report. The requested report path receives that captured byte sequence
as a create-only audit copy; it is not reread as the admission source. A
rejected run still writes its captured report before returning non-zero.

Place the Publisher below a controlled-tools directory whose ACL grants write,
rename, and delete only to designated release administrators; ordinary users
and the Pilot operator need read/execute only. The wrapper opens the exact EXE
with a long-lived read-only `FileStream` that shares only read access, hashes
that locked handle, and keeps it open across Authenticode verification, process
start, and process completion. This closes the pathname replacement window;
the directory ACL remains required defense in depth.

The report contains release identity, contract id, PASS/FAIL check ids, public
hash/key evidence, the Publisher EXE SHA-256, brand authorization
id/key/receipt/expiry, local-data certification id/key/receipt/expiry, and a
bounded failure reason. It omits the written evidence contents and path,
customer identity, private material, access tokens, and raw authorization
codes.

The readiness input binds `localDataCompatibilityEvidence.reportPath`, the
exact lowercase SHA-256 of that report, and both source and target runtime ZIP
hashes. Its required `certification` object binds the receipt path, exact
lowercase receipt SHA-256, and opaque audience UUID. The target tag and ZIP SHA-256 must equal the signed, organization-
admitted runtime in the release-set. Evidence older than 30 days is rejected.
All evidence references are canonical paths relative to the report directory;
the publisher snapshots and re-hashes every referenced artifact and rejects
path traversal, links, missing inventory rows, conflicting duplicate paths,
byte drift, or a deferred coverage lane.

The forward result must prove the actual Harness authoritative data families:
JSONL/Zstandard sessions, workspace-v2 JSON, content-addressed attachments,
workspace files, and the flat-to-v1 credentials migration. Three public-API
lanes run the source runtime before update, the target runtime after update,
and the restored source runtime after whole-home rollback. They must prove
resume/append, a loopback-only fake-provider turn, attachment byte round-trip,
and identical deployed `session.search` policy semantics. The enterprise
profile keeps query SQLite memory-only with `openAt: never`; the gate therefore
requires no durable SQLite artifacts rather than inventing a database integrity
check. Local-data v1 is intentionally limited to the managed text-only
`deepseek-v4-flash` route: all three lanes must record
`not-applicable-managed-text-only-policy` with a public policy refusal and an
empty `requestImageFiles`; the report and forward summary must record
`not-applicable-managed-text-only-policy-public-refusal-proven`. Any future
vision route requires a new contract version. The query refusal is exactly
`internal` / `session-query-open-at-never`. Image-policy evidence accepts only
the exact `select-model` / `model-unavailable` /
`managed-text-only-model-selection-refusal` tuple or the exact `image-prompt` /
`attachment-error` / `managed-text-only-image-prompt-refusal` tuple, always for
provider `deepseek-official` and model `deepseek-v4-flash-vision-exp`; generic
non-empty strings are not evidence. Historical rc.7-to-rc.2 evidence already
proved that a credentials-layout change can make release-set pointer rollback
unsafe. The current rc.2-to-alpha transition therefore requires its own exact
compatibility and whole-home restore evidence; restore the complete pre-upgrade
home before starting an older runtime.

## First-customer release gates

The source-runtime admission receipt must be created only after a fresh upstream
watch and independent source review. The current repository lock selects exact
`dsh-v0.1.2-rc.1`; it remains `promotionStatus: not-built`, while the rc.7
and rc.2 artifacts are historical evidence only. This selection is
time-sensitive: re-check the official repository immediately before each Pilot,
rebuild from the selected exact tag/commit/tree, and issue a new organization
admission receipt. The readiness implementation deliberately does not hardcode
or endorse a managed runtime release id. Any first-customer update remains
blocked until the exact baseline-to-alpha transition, public-API compatibility,
and whole-home backup/restore report pass this preflight.

Use of the official DeepSeek Harness name and whale logo remains a legal
decision, but it is no longer an unstructured checkbox: the designated approver
must retain the exact written evidence and issue the independently signed v1
receipt only after Authenticode signing, payload embedding, and release-set
publication. The receipt binds the post-signing full-file hashes; no executable,
ZIP, PE checksum, signature timestamp, or manifest may change afterward. Missing
real permission or a receipt for different bytes fails closed before `ADMIT`.
This repository intentionally contains neither real written permission nor a
customer brand receipt. Therefore repository code and candidate whale bytes by
themselves remain **NO-GO** for formal customer delivery and do not imply
DeepSeek endorsement.

Finally replay install, first launch, two consecutive startup updates,
failed-health rollback, the higher-sequence recovery update, offline repair,
authorization revocation, and local-data preservation on a clean standard-user
Windows 10/11 x64 machine. Preserve the
machine report and the replay evidence together; neither substitutes for the
other.

The same exact signed bytes must also pass the active
[`Windows background-runtime Pilot gate`](../windows-background-runtime-pilot.md).
Root `CreateNoWindow` and kill-on-close Job Object tests do not prove that
upstream DSH, a plugin, or a tool never asks Windows to create a visible
descendant. An available descendant-spawn path that was not exercised keeps
delivery `NO-GO`.

The required Windows employee replay is now a separate, machine-verifiable
gate. Follow [`windows-employee-pilot.md`](windows-employee-pilot.md), then run
`scripts/Test-EnterpriseWindowsPilotEvidence.ps1`. A technical readiness
`ADMIT` without a Publisher-verified, independently attested v2 body whose
signed `pilotDecision` is `ADMIT` remains **NO-GO** for employee distribution.
The create-only verification receipt is deliberately non-standalone and says
`VERIFIED`, not `ADMIT`.

The pinned Publisher EXE hash closes accidental tool substitution, but it is
not a complete supply-chain authorization receipt. Until that wider signer-host
authorization and all external first-customer evidence exist, the formal
customer delivery decision remains NO-GO.
