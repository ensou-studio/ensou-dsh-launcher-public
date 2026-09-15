# ADR 0006: Direct-target production orchestration and Stable private-pilot evidence

- Status: Accepted
- Date: 2026-08-31
- Deciders: ensou, Ensou Studio

## Context

The signed release manifest contains its channel. A workflow that signs a Pilot
manifest, validates it, and later signs a second Stable manifest has tested a
different manifest from the one it publishes. This is especially incompatible
with Enterprise production clients, whose compiled release policy accepts only
the Stable channel. An Enterprise "pilot" is therefore a private audience for
the exact Stable candidate, not an Enterprise Pilot-channel build.

Production state must also survive retries, concurrent operators, and crashes
without accepting a response under a different channel, edition, plan, signing
purpose, public key, component identity, or state head. Plan/state v1 is already
hash-bound and remains frozen at its implemented three revisions.

## Decision

Production plan/state v2 is a direct-target lifecycle. `targetChannel` is signed
into the plan and every downstream request, receipt, and candidate:

- Personal permits `targetChannel: pilot|stable`.
- Enterprise permits only `targetChannel: stable`.
- Enterprise plan v2 fixes the independent Pilot evidence trust-policy
  SHA-256 before r1; a later r8 adapter may not accept a caller-selected trust
  root.
- A Pilot plan creates a Pilot candidate and publishes it to the Pilot feed.
- A Stable plan creates a Stable candidate at r4. After Installer signing, the
  exact signed Stable Installer and manifest are exposed through the canonical
  Stable URI to a private two-device allowlist. The same manifest and Installer
  bytes are then made public. There is no second manifest.

Plan v2 deliberately has no Pilot-to-Stable continuation. A future continuation
capability would require a new plan/state schema that binds the earlier terminal
head and all exact artifact bytes. Plan v2 remains strict and rejects such
continuation fields.

The Personal Pilot lifecycle is:

1. `PLAN_ADMITTED`
2. `CLIENT_SIGNING_REQUESTED`
3. `CLIENT_SIGNATURES_IMPORTED`
4. `PILOT_MANIFEST_SIGNING_REQUESTED`
5. `PILOT_SIGNED_CANDIDATE_IMPORTED`
6. `INSTALLER_SIGNING_REQUESTED`
7. `INSTALLER_SIGNATURE_IMPORTED`
8. `PILOT_PROMOTION_REQUESTED`
9. `PILOT_FEED_PROMOTED` (terminal)

The Personal or Enterprise Stable lifecycle is:

1. `PLAN_ADMITTED`
2. `CLIENT_SIGNING_REQUESTED`
3. `CLIENT_SIGNATURES_IMPORTED`
4. `STABLE_MANIFEST_SIGNING_REQUESTED`
5. `STABLE_SIGNED_CANDIDATE_IMPORTED`
6. `INSTALLER_SIGNING_REQUESTED`
7. `INSTALLER_SIGNATURE_IMPORTED`
8. `PILOT_EVIDENCE_BOUND`
9. `STABLE_PROMOTION_REQUESTED`
10. `STABLE_FEED_PROMOTED` (terminal)

`PrepareManifestSigning` and `ImportSignedCandidate` are channel-neutral command
verbs. Their create-only bundle names are
`<channel>-manifest-publishing.v1` and `<channel>-signed-candidate.v1`. The
request/response purpose is channel-neutral but includes the exact
`targetChannel`; cross-channel, cross-edition, and cross-purpose replay fails.

### Release trust and compatibility

Plan v2 contains a mandatory edition-neutral `releaseManifestTrust` with
algorithm `ES256`, purpose `release-manifest-signing`, key ID, and P-256 public
point. Its key ID and public point must each be distinct from all four external
response-authentication trust domains. The candidate cannot supply a key that
self-authorizes its own signature.

The four signed Personal executables must project their existing canonical
binary self-check onto the plan trust and compatibility. The three signed
Enterprise release roles use `--release-manifest-trust-probe`; Maintenance is
not a release role. Exact probe bytes are validated against
`launcher-release-manifest-trust-probe-v1.schema.json`, compared with the plan,
and hashed into the r3 receipt. Enterprise probes also bind the canonical
manifest/artifact origins and lowercase Authenticode signer thumbprint.

Plan v2 also carries edition-conditional `releaseCompatibility`: Personal binds
`startupStubVersion` and `canonicalLowSFromSequence`; Enterprise binds current
`startupStubProtocol: 1`. r4 and r5 bind both trust and compatibility. Every v2
client-signing or manifest-publishing response, artifact signature, and manifest
signature uses P-256 P1363 with nonzero in-range scalars and canonical low-S.

### Exact Publisher and candidate closure

The typed Publisher descriptor and r4 request contain exact ordered
`componentReleaseIds`:

- Personal: `clientBundle`, `runtime`.
- Enterprise: `launcher`, `runtime`, `pluginPolicy`.

Component IDs follow the product release-ID grammar; the runtime ID must also
equal the admitted runtime candidate ID. The r1 receipt persists the verified
runtime metadata provenance. r4 binds its exact source tag and commit, and a
Personal manifest must bind Launcher source commit plus both runtime provenance
fields.

r5 accepts only the product inventory in manifest order:

- Personal: release manifest, client bundle, runtime.
- Enterprise: release manifest, release public key, launcher, runtime,
  plugin policy.

Artifact filenames and exact URIs derive from the signed manifest. Extra,
missing, reordered, renamed, case-colliding, nested, reparse-point, or hardlinked
files fail closed. The Enterprise public-key file must equal the plan trust.
The manifest admission reproduces the actual client policy: 512 KiB manifest
bound, strict safe JSON integers, canonical edition-specific UTC format,
validity window, revocation rules, compatibility, provenance, artifact limits,
canonical URI closure, and every signature. Contract tests additionally pass
the admitted exact bytes through `PersonalReleaseSetValidator` and
`EnterpriseReleaseSetValidator`.

### State and evidence

Every mutation requires the exact current head SHA-256. Requests, responses,
bundles, receipts, and inventory are create-only. Exact replay is idempotent;
semantic conflict, missing or stale CAS, and pre/post atomic-publication crash
windows fail closed or recover to the same bytes.

`PersonalDistributionCertification` v2 retains its historical, read-only
meaning: it certifies distinct Pilot and Stable manifests. It cannot satisfy
the new direct-Stable lifecycle, and a Stable manifest must never be relabeled
as Pilot. Stable r8 requires a new direct-target evidence contract that binds
the exact Stable manifest, Installer, canonical Stable URI exposure, allowlist,
and two-device results.

## Consequences

- Stable private testing and public promotion use one manifest and one Installer
  byte sequence.
- Enterprise never builds or signs a Pilot-channel production client.
- A Pilot terminal cannot be silently continued as Stable.
- A green contract gate is not production readiness; real Authenticode/RFC3161,
  canonical HTTPS exposure, two-device evidence, and authenticated promotion
  remain required.
- v1 plan/state remains readable and fail-closed through `Status` only; every
  mutating orchestration phase requires v2 and never reinterprets v1 as v2.
