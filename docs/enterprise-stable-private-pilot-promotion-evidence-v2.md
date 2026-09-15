# Enterprise Stable private Pilot and promotion evidence v2

## Operator decision: foundation GO, production NO-GO

Release operators may use this contract to prepare and review the shape of a future r8 private-Pilot evidence bundle and its r9/r10 exact-byte promotion closure. It is **not** production admission and does not prove that a Pilot, Authenticode verification, RFC3161 timestamp, authenticated HTTPS exchange, two-device run, attestation, or public promotion occurred.

The checked-in fixture is deliberately `evidenceMode=synthetic-fixture`, every real verification member is `PENDING`, and `productionAdmission=NO_GO`. Changing those labels does not create evidence; the schema rejects a synthetic fixture that claims `VERIFIED` or `GO`.

Use these sources together:

- [strict v2 schema](../release/schemas/launcher-enterprise-stable-private-pilot-promotion-evidence-v2.schema.json)
- [synthetic NO-GO fixture](../release/fixtures/stable-private-pilot-promotion-v2/synthetic.no-go.json)
- [schema and cross-field contract test](../release/scripts/Test-StablePrivatePilotPromotionEvidenceV2.ps1)
- [Launcher capability command test](../release/scripts/Test-EnterpriseAuthenticatedUpdateCapability.ps1)

The existing [Stable private Pilot evidence v1](stable-private-pilot-evidence-v1.md) remains unchanged. V2 adds the signed source-baseline capability proof and the later private-to-public exact-byte closure; it does not reinterpret historical Enterprise Pilot readiness or Personal dual-manifest receipts.

## Source baseline bootstrap requirement

The online-upgrade device must start from an already installed, healthy, signed Stable release whose Launcher contains the authenticated Stable update path. A same-build fetch, no-op update, fresh installation on both devices, or an older Launcher that performs anonymous update requests cannot satisfy r8.

The signed source Launcher exposes exactly one machine command:

```text
--authenticated-stable-update-capability-self-check
```

It emits one bounded canonical JSON value describing:

- Stable manifest route `/v2/channels/stable/release-set.v2.json`;
- fresh binding or refresh as the admission prerequisite;
- both `Ready` and `UpdateRequired` as admitted check states;
- one DPoP-authenticated transaction client per check;
- 401 token-clear and session-lock behavior;
- 403 behavior that continues an already verified Stable version only for `Ready`, while `UpdateRequired` stays locked;
- Stable Bootstrapper restart for health confirmation;
- the `no-secrets-no-network-no-mutation` side-effect contract.

The command rejects every additional argument with nonzero exit, empty stdout, and a bounded diagnostic. It does not inspect certificate stores or contact a revocation service. The evidence collector must first lock and independently verify the exact Launcher bytes with Authenticode, signer certificate SHA-256, primary SHA-256 signature, RFC3161 timestamp, and PE-content identity, then invoke the command on those same bytes. The command output alone is not a signature proof.

## Required two-device private Pilot

The evidence contains exactly two distinct Windows x64 device inventories and exactly two allowlist identities:

1. `fresh-install` starts without a prior installation, consumes the exact r7 signed Installer, observes the exact target objects, and completes both the target Bootstrapper health receipt and the acknowledged installation/update receipt.
2. `online-upgrade` starts from the signed source baseline above, binds the exact capability-probe SHA-256, performs a real artifact download through the canonical Stable URI, and completes both target receipts.

Device identity, installation ID, machine identity, and inventory SHA-256 must all be distinct. Both devices must bind the same target release-set and exact manifest/artifact object versions, strong ETags, sizes, and SHA-256 values. Workspace and local conversation history preservation are required on both lanes.

## Unauthorized control identity

A third, non-allowlisted device identity must query the same canonical Stable URI before and after the private run. It must receive HTTP 200 for the prior public Stable lane, observe the source-baseline release-set and manifest, and receive none of the target candidate bytes. A 403-only probe is insufficient because it does not prove that ordinary employees still see the existing public Stable lane.

The third identity must be distinct from both Pilot identities. Its observations and the allowlisted observations require signed, independently verified server/device envelopes in real evidence.

## Exact private-to-public promotion

The target manifest and every target artifact are identified by role, filename, canonical HTTPS URI, immutable object version, strong ETag, byte length, and SHA-256. The later public promotion must reuse those exact object identities and bytes. Rebuilding, resigning, recompressing, copying to a different immutable version, changing an ETag, or changing any byte requires a new orchestration.

The contract records:

- r7 `INSTALLER_SIGNATURE_IMPORTED` exact Installer identity;
- r8 `PILOT_EVIDENCE_BOUND` evidence binding;
- r9 `STABLE_PROMOTION_REQUESTED` compare-and-swap request;
- r10 `STABLE_FEED_PROMOTED` receipt and public head;
- prior public head equal to the source baseline;
- promoted public head equal to the target release;
- promoted objects exactly equal to the privately observed target objects.

Structural validation still reports `productionAdmission=NO_GO`. A future orchestration importer must cryptographically verify the evidence and atomically consume it before any production transition.

## What remains PENDING

Real admission remains pending until an independent verifier establishes all of the following from original bytes and logs:

- valid Authenticode chain/status, exact signer certificate SHA-256, SHA-256 primary signature, and RFC3161 timestamp bound to the primary signer;
- a real signed source Stable Launcher containing the capability command;
- two physical or independently administered Windows x64 devices with distinct inventories;
- device-bound DPoP access to the real canonical HTTPS Stable URI;
- both target Bootstrapper health receipts and acknowledged update receipts;
- a distinct unauthorized identity receiving the prior public Stable lane without target leakage;
- trusted ES256 P1363 low-S server, device, control, and promotion attestations;
- r9 compare-and-swap and r10 public observation reusing the exact target bytes.

The repository schema cannot establish these facts, validate certificate revocation, reject forged operator booleans, or verify a live server. A production verifier must also reject duplicate JSON members, require canonical payload bytes, recompute all hashes, validate trusted-time ordering, and resolve every attestation key by its independent purpose.

## Focused local checks

Build the Enterprise Launcher, then run:

```powershell
pwsh -NoProfile -File release/scripts/Test-EnterpriseAuthenticatedUpdateCapability.ps1
pwsh -NoProfile -File release/scripts/Test-StablePrivatePilotPromotionEvidenceV2.ps1
```

Expected final markers are:

```text
ENTERPRISE-AUTHENTICATED-UPDATE-CAPABILITY-PASS
STABLE-PRIVATE-PILOT-PROMOTION-EVIDENCE-V2-PASS
```

These checks prove only local implementation and contract behavior. They never convert the fixture into real Pilot evidence.
