# Enterprise release-set update v2

This employee update path is separate from the personal Launcher runtime-v1
feed. It never reads, writes, stops, or migrates a personal installation.

## Startup behavior

### Background update admission

`EnterpriseAutomaticReleaseUpdateCoordinator` first performs a read-only signed
feed probe under fresh authorization. An unchanged feed does not stop DSH. A
verified change requires another current-authorization check, graceful drain of
the exact owned Runtime, the independent loopback guard, and the existing
exclusive stage with a fresh authenticated feed verification. The probe does not
create security state or advance trusted time. Payload download remains in the
exclusive stage, after drain; it is not background prefetch.

Ordinary cancellation before shutdown resumes the same authenticated Runtime
cycle. After shutdown is sent, Host observes its exit independently of caller
cancellation for up to ten seconds; a separately authorized security stop still
has priority. A typed failed-stop outcome proves the exact process has exited,
so the client can attempt recovery without treating the failure as installation
permission. Recovery always uses current enterprise authorization, never direct
Host start, and does not start a Runtime that was already off. Window shutdown
suppresses recovery; a successful Bootstrapper handoff owns the successor launch.

Focused Client ordering and real Host/Node stop tests cover these interactions.
They do not replace complete managed-profile boot, file/home lease admission,
signed HTTPS two-version update, or the native Windows Pilot gates.

### Process startup

Every normal Enterprise Launcher start calls the signed feed through
`EnterpriseReleaseStartupCoordinator`. Production manifest/control origins and
P-256 public keys are compiled into the Launcher as assembly metadata. They are
never read from user-writable config or environment variables. The separately
compiled Development-E2E product may use the complete
`ENSOU_DSH_E2E_UPDATE_*` set and an exact localhost certificate SHA-256 pin.

The client verifies schema v2, product, environment, expiry, generation,
sequence, monotonic minimum sequence, cumulative revocations, the manifest
ES256 signature, and every artifact ES256 signature. Each signed artifact binds
its release ID, download byte count, archive SHA-256, and deterministic
`completeTreeSha256`. The signed canonical
manifest also includes the required `startupStub.minimumProtocol` and
`startupStub.maximumProtocol` integers. Production and Development-E2E clients
currently compile protocol `1`; a signed range that excludes `1` is rejected
before update security state advances or any artifact request is made. The
manifest request has a fixed ten-second startup timeout. Artifact downloads retain a long overall
timeout plus a 30-second read-idle limit. ZIP staging enforces exact size and
SHA-256, pinned HTTPS origin, safe paths, entry count, and expanded size. The
employee machine never invokes Git, FNM, npm, pnpm, or system Node as fallback.

Launcher, runtime, and optional plugin policy go into immutable version
directories. One atomic `release-set-current.v2.json` pointer selects the
complete tuple; its strict schema-3 current and previous references retain the
signed Startup Stub protocol range and each component's archive/tree identity.
Only an exact component tuple already named by authenticated Current or Previous
may be reused. Reuse repeats the complete-tree, receipt, runtime-manifest, and
Launcher Authenticode checks; a metadata-only release performs no artifact GET,
and a changed component downloads only that component. A collision or tamper
fails closed instead of silently falling back to download. The stable Stub checks its compiled
protocol before self-check, pending health, maintenance, or normal tuple
launch. A pre-range pointer is rejected by the new Stub, while an older strict
Stub rejects the new pointer's required field. Legacy component pointers are
repair metadata only. Runtime
archives must contain the source builder's `runtime-files.sha256`. Installation
and every startup recheck the manifest digest, every listed hash, missing and
unexpected files, and reparse points. The signed artifact receipt binds the
hash-manifest digest, but the user-writable receipt is only local evidence: the
signed `completeTreeSha256` and protected accepted-release identity are the
authorization root. Production Launcher and stable Bootstrapper executables
also require the compiled Authenticode signer identity on each start.

Activation is initially `pending`. The stable Bootstrapper starts a hidden new
Launcher installation self-check with a one-use 256-bit token. Timeout, nonzero
exit, missing signal, or failed self-check atomically restores the previous
healthy tuple. A valid signal marks the new tuple healthy before UI startup.
The handshake has a bounded five-minute cold-start window because a newly
published self-contained single-file Launcher may first require .NET bundle
extraction and endpoint-security scanning. Expiry still fails closed and rolls
back the complete tuple.
The failed release-set ID is persisted in a bounded, fail-closed health
quarantine before rollback. The same signed candidate is never executed again:
an optional update keeps the old healthy tuple, while a mandatory candidate
blocks until operations publishes a new release-set ID and sequence. Receipts
and the Launcher footer expose the resulting update state.

When the feed is unavailable, a healthy last-known-good tuple continues only
inside the fixed seven-day update-offline grace. Initial sequence-0 installs use
the same bound from activation. Verified releases are bounded by both their last
verification and signed metadata expiry. Persisted minimum sequence and
revocation always win. This update grace never extends the separate, typically
shorter control-plane authorization lease.

Conversation history, workspaces, and Harness home are outside managed program
roots. Update, rollback, revocation, repair, and managed-program uninstall do
not delete them.

## Production build inputs

The production publish target rejects a missing value from either public trust
set. No provider/API/app secret belongs in these properties.

Update trust:

- `EnterpriseUpdateManifestUri`
- `EnterpriseUpdateManifestOrigin`
- `EnterpriseUpdateArtifactOrigin`
- `EnterpriseUpdateReleaseKeyId`
- `EnterpriseUpdateReleaseKeyX`
- `EnterpriseUpdateReleaseKeyY`

Control-plane trust:

- `EnterpriseControlPlaneOrigin`
- `EnterpriseAuthorizationOrigin`
- `EnterpriseGatewayOrigin`
- `EnterpriseManagedArtifactOrigin`
- `EnterpriseLeaseKeyId`
- `EnterpriseLeaseKeyX`
- `EnterpriseLeaseKeyY`

Executable trust additionally requires
`EnterpriseAuthenticodeSignerSha256Thumbprint`. `X` and `Y` are 32-byte P-256
coordinates in unpadded base64url form.

The production ReleasePublisher has a separate, independently controlled
runtime-admission trust root compiled into its own assembly metadata:

- `EnterpriseRuntimeAdmissionKeyId`
- `EnterpriseRuntimeAdmissionKeyX`
- `EnterpriseRuntimeAdmissionKeyY`

This key must not be the release-signing key; the publisher compares the actual
P-256 public coordinates and rejects key reuse. Production publisher config
cannot add, replace, or override the trust root, and the publisher fails closed
when any value is absent. `development-e2e` config has a deliberately isolated
`developmentRuntimeAdmissionTrust` test key; that property is rejected for a
production publish.

A ReleasePublisher binary that can admit a production plugin policy also
compiles the employee Launcher's lease-verification public key as
`EnterpriseLeaseKeyId/X/Y`, alongside the independent
`EnterprisePluginAdmissionKeyId/X/Y` and
`EnterpriseBrandAuthorizationKeyId/X/Y` roots. Named-customer Pilot validation
also compiles the Publisher-only
`EnterpriseLocalDataCertificationKeyId/X/Y` root. These values are publisher
build inputs, never publisher JSON inputs. Before accepting an organization
plugin receipt, the publisher compares both key IDs and P-256 public points and
rejects any plugin-admission key reused for release signing, runtime admission,
brand authorization, or lease verification. Before accepting a local-data
certification, it rejects reuse with release, runtime, plugin, brand, or lease
trust. Publisher-only roots are not added to the employee Launcher fingerprint.

## Publishing a static release

The publisher is operations-only and is not referenced by an employee binary.
Start with
`release/examples/enterprise-release-publisher.config.example.json`. Keep the
PKCS8 P-256 private key in an ACL-restricted path or mounted secret volume. The
CLI accepts only a file reference and never prints private key material.

```powershell
dotnet run --project src/Ensou.Dsh.Enterprise.ReleasePublisher -- `
  --config C:\release-input\publisher.json `
  --private-key-file C:\release-secrets\release-private.pk8 `
  --ledger C:\release-state\pilot-sequence.v2.json `
  --output C:\release-output\enterprise-2026.08.24.1
```

The output contains copied artifacts, `release-set.v2.json`, and
`release-public-key.v2.json` and can be uploaded unchanged to the HTTPS static
origins. The CLI computes archive size/SHA-256 plus the deterministic complete
installed-tree SHA-256 directly from each locked ZIP snapshot, signs every
value in each artifact, signs the canonical manifest, and self-verifies it.
Publisher config must explicitly declare the
signed Startup Stub protocol range; current releases use `1..1`.

A `runtime` input additionally requires absolute
`sourceRuntimeMetadataPath` and `organizationAdmissionReceiptPath` values. The
publisher snapshots the config, runtime ZIP, source metadata, detached receipt,
plugin metadata, and signing key before content validation. It then strictly
parses the source metadata and requires the exact release ID, archive filename,
byte count, SHA-256, pinned official tag/commit/tree, managed patch and policy,
toolchain, source-build verification gates, and
`organizationReviewRequired: true`.

The current runtime-admission lane is pinned to `dsh-v0.1.2-rc.1`, but its
lock remains `promotionStatus: not-built`; no signed rc.1 artifact identity or
organization receipt is admitted yet. The former rc.2
`managed-v2026.08.25.3` ZIP (99,871,003 bytes, SHA-256
`ebb4f366dc007da78a1d9168324afd2c0bd4a4da7fcd46e3d0f7d3cb13e22a73`)
is retained only as historical candidate evidence and is not accepted by the
current source-runtime admission tuple. The receipt below documents that
historical shape; an alpha build requires a new immutable release ID, artifact
identity, metadata digest, review, and signature.

The independent organization reviewer signs this exact detached receipt with
the runtime-admission key:

```json
{
  "schemaVersion": 1,
  "receiptType": "ensou-dsh-runtime-organization-admission",
  "releaseId": "managed-v2026.08.25.3",
  "sourceRuntimeMetadataSha256": "<64 lowercase hex characters>",
  "decision": "admitted",
  "reviewedAtUnixSeconds": 1787616000,
  "signature": {
    "algorithm": "ES256",
    "keyId": "runtime-admission-2026-01",
    "value": "<unpadded base64url P1363 r||s signature>"
  }
}
```

The signed canonical payload is UTF-8 JSON with no whitespace and exactly the
first six fields above, in that order, excluding `signature`. The metadata
digest is over the exact metadata file bytes. Any unknown or duplicate JSON
member, missing receipt, wrong digest, wrong key, non-canonical signature, or
runtime/source mismatch blocks release signing.

A production `plugin-policy` input additionally requires absolute
`policyMetadataPath`, `pluginPromotionHandoffPath`,
`pluginHarnessCompatibilityReceiptPath`, `pluginGenerationReservationPath`,
`pluginGenerationLedgerPath`, and `pluginOrganizationAdmissionReceiptPath`
values, plus a trusted `pluginGenerationLedgerNamespace`. The schema-v2 unsigned
handoff emitted by the managed plugin repository is evidence, not directly
consumable publisher config. Its generator-machine paths are informational;
the publisher config supplies the signer-machine paths independently and exact
basenames, hashes, sizes, and identities must agree. Development-E2E continues
to require metadata but deliberately rejects all production promotion inputs.

Before signing anything, the publisher snapshots the policy ZIP, metadata,
handoff, external Harness compatibility receipt, exclusive generation
reservation, protected generation ledger, and signed organization admission
receipt into locked private staging. It
rejects reparse points in every source path or existing ancestor and re-hashes
bytes when reading the immutable snapshot. The publisher validates the ZIP root
and every entry, parses root `plugin-policy.json`, verifies every declared skill
byte/size/hash, and compares policy identity, raw-policy SHA-256, archive
SHA-256, sizes, and every input provenance record with metadata and handoff.

The handoff must remain `templateOnly=true`, `directlyConsumable=false`, and
must keep `releaseId` and `uri` null. Operations supplies those two values
independently in publisher config; the URI must be HTTPS. Production accepts
exactly one immutable Launcher/runtime tuple and requires source tag
`dsh-v0.1.2-rc.1`. The external receipt must name the independent pre-sign
`Ensou.Dsh.EnterprisePluginCompatibilityRunner` producer with a canonical UUID,
bind its own compiled/pinned executable SHA-256, the exact Launcher archive
bytes, runtime archive bytes, runtime source metadata digest, and every declared
skill tree, be no older than 168 hours, and report all nine startup,
installation, execution, managed-policy, update, rollback, conversation, and
workspace observations as `PASS`. Before any plugin JavaScript executes, the
Runner also requires the independent ES256
`managed-plugin-execution-admission-receipt-v1` over the exact policy archive,
metadata, raw policy, Launcher/runtime compatibility tuple, and per-skill tree
hashes. Each skill must declare `compatibility-test.mjs`; an absent test is an
explicit external NO-GO, not an inferred PASS.

The Runner is a self-contained single executable. Its parent holds its own file
identity while launching the same executable with a nonce-bound private probe
request; candidate runtime archives are forbidden from carrying a compatibility
reporter. Both processes copy already-locked inputs by handle into create-new
private snapshots, keep the snapshots and extracted execution trees locked, and
then independently verify runtime organization admission, Launcher `--self-check`,
real managed DSH boot plus `session.list`, exact plugin installation and command
execution, complete-tree revalidation, and product Harness-home rollback with
history/workspace byte preservation. Pilot-readiness runs only after a signed
Release Set exists and is not the compatibility-receipt producer.

The signer-local reservation path is deterministically derived beside the
signer-local trusted generation ledger,
uses the exclusive unsigned-candidate status, and binds archive, metadata,
raw-policy, receipt, policy ID, generation, and production environment. Its
exact bytes/hash/size must match the handoff. Production accepts only the
namespaced ledger-v2 shape; ledger-v1 is Development-E2E-only. The live ledger
hash and observed highest generation must also match, and the candidate
generation must be strictly greater. A standalone skill candidate ZIP, a wrapped policy, metadata
drift, stale receipt, reused generation, altered reservation, or revoked policy
is rejected. The raw policy hash is over the ZIP entry bytes exactly; it is not
the ZIP hash and is never recomputed from reserialized JSON. The exact evidence
contracts are under `release/schemas/managed-plugin-*.schema.json`.

An organization-controlled ES256 admission receipt then authenticates the exact
plugin, Launcher, runtime, compatibility receipt, handoff, reservation, trusted
ledger namespace/path/bytes, and observed generation tuple. Its receipt type and
canonical payload are domain-separated from runtime admission. Production
configuration cannot replace the compiled `EnterprisePluginAdmissionKeyId/X/Y`
trust. That P-256 key must differ by both key ID and public point from release,
lease, runtime-admission, and brand-authorization trust; its private key remains
only in the independent organization plugin-review workflow.

The organization receipt signature covers compact UTF-8 JSON with no BOM or
whitespace and excludes `signature`. Its exact ordinal member sequence is:
`schemaVersion`, `receiptType`, `decision`, `reviewedAtUnixSeconds`,
`compatibilityTestRunId`, `policyId`, `generation`, `critical`,
`pluginReleaseId`, `archiveSha256`, `archiveSizeBytes`, `metadataSha256`,
`metadataSizeBytes`, `rawPolicySha256`, `rawPolicySizeBytes`,
`launcherReleaseId`, `launcherArchiveSha256`, `launcherArchiveSizeBytes`,
`runtimeReleaseId`, `runtimeArchiveSha256`, `runtimeArchiveSizeBytes`,
`runtimeSourceMetadataSha256`, `harnessSourceTag`,
`compatibilityReceiptSha256`, `compatibilityReceiptSizeBytes`,
`compatibilityObservedAtUtc`, `promotionHandoffSha256`,
`promotionHandoffSizeBytes`, `reservationSha256`, `reservationSizeBytes`,
`generationLedgerNamespace`, `generationLedgerPathSha256`,
`generationLedgerSha256`, `observedHighestPromotedGeneration`. ES256 uses the
fixed 64-byte IEEE-P1363 `r || s` form encoded as unpadded base64url. The ledger
path digest is lowercase SHA-256 over UTF-8 bytes of
`ensou-dsh-plugin-ledger-path-v1\n` followed by the signer-local
`Path.GetFullPath` result with the platform alternate separator replaced by the
primary separator and the complete path converted with invariant uppercase.
This deliberately binds the receipt to the signer-local trusted ledger rather
than a generator-machine path embedded in the handoff.

The ReleasePublisher now atomically consumes an independently ES256-signed
`managed-plugin-promotion-journal-authorization` before signing any production
Release Set containing a plugin policy. Its exact intent additionally binds the
release-set generation/sequence/minimum sequence, all three artifact identities,
runtime source metadata, plugin policy and compatibility evidence, reservation,
trusted ledger namespace/path/bytes, and organization receipt. The authorization
also binds one random journal instance plus its expected revision and head, is
valid for at most 24 hours, and is accepted only once while still current.

The fixed signer-local journal is
`%LOCALAPPDATA%\Ensou\Dsh\EnterpriseReleasePublisher\PluginPromotionJournal\v1`.
Its independent CurrentUser-DPAPI anchor is under the sibling
`PluginPromotionJournalAnchors` root. Entries are immutable `CreateNew` files;
the complete chain is revalidated against an atomic head and the protected
high-water anchor. A protected pending transaction supports crash recovery only
when the caller presents the same still-valid external authorization, exact
intent, old journal instance, revision, and head. Direct replay, missing state,
deletion, truncation, reordering, substitution, expiry, or trust-key reuse fails
closed. Initialization is an explicit ReleasePublisher command and is never an
automatic reset.

The production build compiles an independent
`EnterprisePluginPromotionJournalKeyId/X/Y` public root. The ReleasePublisher
command `--plugin-promotion-journal-challenge` emits the strict current
challenge. `--plugin-promotion-journal-intent --config <absolute-json>` emits
the exact intent from the same locked config, artifacts, and promotion evidence
used by publishing without opening a private key or touching the journal. The
independent signer supplies both files to
`release/scripts/New-EnterprisePluginPromotionJournalAuthorization.ps1`, and
the resulting new file is supplied as
`pluginPromotionJournalAuthorizationPath`. Journal creation remains the
separate explicit `--initialize-plugin-promotion-journal` command.

Local DPAPI plus ACLs cannot detect a coordinated rollback of both journal and
anchor by the signer identity. Production therefore remains `NO-GO` until the
issuer atomically records consumed authorization IDs/high-water, or operations
provide an approved WORM/TPM monotonic anchor checked before every publication.
A dedicated signer identity, restrictive ACLs, immutable retention, and backup
are mandatory deployment controls, not substitutes for that external high-water.

Operations supplies that same metadata `policy.sha256` to the Control Plane
before assigning the policy to an employee. `artifact.sha256` belongs only to
release-set download verification. Swapping the two hashes is a release-blocking
error; the Control lease and Launcher active-policy check intentionally fail
closed.

The ledger rejects generation rollback, sequence reuse/rollback, and minimum
sequence rollback. It consumes the sequence before copying output. This is an
intentional fail-closed choice: an I/O failure can burn a sequence but cannot
create an unledgered published release that could later be equivocated. Advance
to a new sequence after such failure; never edit the ledger backward. Config,
private-key, artifact, ledger, lock, and output paths reject reparse points in
the file or any existing ancestor.

The wire schema is
`release/schemas/enterprise-release-set-v2.schema.json`; do not reinterpret the
personal/runtime-v1 manifest as this contract.

## External production inputs still required

1. organization-controlled HTTPS update and control-plane origins;
2. P-256 release and lease signing public keys, with private keys held only by
   their server/publisher;
3. an Authenticode signing certificate and its compiled SHA-256 signer
   thumbprint;
4. signed artifacts, including a runtime built with complete
   `runtime-files.sha256`.
