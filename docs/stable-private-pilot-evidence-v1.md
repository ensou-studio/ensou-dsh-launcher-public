# Stable private Pilot evidence v1

## Operator decision: foundation GO, production NO-GO

The schema and its isolated contract tests are a **GO only as the foundation for a future Stable r8 evidence importer**. They are a **NO-GO for production admission, employee rollout, Stable feed promotion, or any claim that a private Pilot has occurred**.

Real evidence remains `PENDING` until all of the following exist and are independently verified:

- an exact r7 signed Installer and its authenticated transition receipt;
- an authenticated, device-bound Enterprise update-feed transport available before the startup update check;
- a deployed canonical Stable URI with an exact two-device allowlist, private cache partition, and signed server audit;
- one real clean Windows fresh-install device and a different Windows device with a real older Stable installation;
- a real old-Stable-to-candidate online update, failed-health rollback, same-candidate recovery, and local workspace/history preservation;
- trusted server and device attestation keys plus cryptographic verification of their canonical payloads.

The schema is [launcher-stable-private-pilot-evidence-v1.schema.json](../release/schemas/launcher-stable-private-pilot-evidence-v1.schema.json). Its isolated executable specification is [Test-StablePrivatePilotEvidenceContract.ps1](../release/scripts/Test-StablePrivatePilotEvidenceContract.ps1).

## What this contract means

This contract represents a Stable-channel candidate exposed to a private Pilot ring. `targetChannel` is always `stable`; `exposureRing` is `private-pilot`. A Pilot-channel build is not promoted to Stable.

The same exact closure must survive every later step:

- r7 head and receipt;
- signed Installer full SHA-256, PE-content SHA-256, and immutable identity SHA-256;
- signed Stable manifest SHA-256;
- candidate-set, Installer payload-set, canonical release-trust probe, and release-manifest trust hashes;
- every versioned manifest, candidate artifact, and Installer server object;
- the privately observed device bytes and the bytes later admitted for public Stable promotion.

Changing, rebuilding, or resigning any member requires a new orchestration. The evidence document deliberately remains `productionAdmission: NO_GO`; a later r9 promotion request and feed-head compare-and-swap must consume it.

## Required private exposure

The evidence has exactly two device lanes:

1. `freshInstall` executes the exact r7 signed Installer on a clean Windows x64 device. It records the exact Installer identity, a canonical Stable manifest fetch, payload self-check, installation, background/no-visible-CMD behavior, tray, WebUI, restart, and local-data persistence.
2. `onlineUpgrade` starts from a genuinely older Stable release and fetches the candidate through the same canonical Stable manifest URI. It must download the exact candidate artifacts, suffer a controlled health failure without modifying production bytes, roll back to the old Stable release, then retry the same candidate and complete health confirmation.

Two embedded fresh installs, two same-version fetches, or a no-op update do not satisfy the contract. Device identity hashes must be distinct and must exactly close the server allowlist and allowlisted request audit.

## Required server proof

The server section binds:

- deployment and configuration IDs, revisions, and SHA-256 values;
- allowlist policy ID, version, SHA-256, validity window, identity mechanism, and exactly two authorized device identity hashes;
- the canonical URI `https://<host>/v2/channels/stable/release-set.v2.json`;
- immutable object version ID, strong ETag, size, and SHA-256 for the manifest, every edition-specific candidate object, and the signed Installer; weak private ETags are rejected because Range/If-Range recovery needs a strong validator;
- `Cache-Control: private, no-store`, authorization variance, shared-cache bypass, and a dedicated private candidate partition;
- every allowlisted manifest/artifact/Installer fetch, including request ID, device, lane, authorization decision, URI, object version, ETag, size, SHA-256, status, and time;
- non-allowlisted control probes before and after the test that do not disclose candidate bytes;
- a public Stable head observed before and after the private Pilot with the exact same head, release-set, manifest, and ETag.

Personal evidence may use a dedicated VPN or network-egress allowlist. Enterprise evidence requires device authorization. A shared CDN or cache that can expose private candidate bytes is not admissible.

## Current Enterprise blocker

The desired Enterprise device allowlist is not implemented by the current runtime:

- `EnterpriseControlPlaneTransportFactory.CreateUpdate()` creates a plain `HttpClient` without device proof, access token, or authorization handler.
- `EnterpriseReleaseSetUpdateService` sends bare manifest and artifact `GET` requests.
- the Launcher runs its update check before it creates the device key store, token vault, refresh lifecycle, QR enrollment, and device-binding clients.
- a `403` from `EnsureSuccessStatusCode()` becomes `HttpRequestException`; the update service classifies that as availability failure and follows its ordinary offline path.

Therefore an Enterprise server cannot yet distinguish the two authorized employee devices at the canonical Stable URI. Before real r8 evidence can exist, the product needs an authenticated device-bound update transport, a startup order that makes durable device credentials available before update, and an explicit fail-closed authorization-denial result rather than treating denial as ordinary offline availability.

This document and schema do not modify those runtime files and do not claim that the missing transport exists.

## Historical contracts are not substitutes

Existing contracts remain valid only for their original historical semantics:

- `EnterprisePilotReadiness` is a Pilot-channel readiness flow whose configuration requires `channel=pilot`.
- `PersonalDistributionCertification` and Personal certified distribution receipt v2 require a separate Pilot manifest and Stable manifest and bind `SourceChannel=pilot`.

Neither can prove this direct-Stable, single-manifest, private-allowlist r8 transition. New orchestration must not manufacture a Pilot manifest, copy the Stable manifest into both fields, reinterpret `SourceChannel`, or weaken the old verifiers.

Keep all existing v2 parse/verify behavior unchanged for historical data. A future integration should add a parallel direct-target/v3 C# receipt and verifier that consumes this evidence shape, then explicitly wire that new verifier into r8 and the edition feed promoters. This v1 schema is only that integration foundation; the current Publishers and FeedPromoters do not consume it.

## Schema versus admission verification

The JSON Schema validates bounded structure, exact constants, edition-specific inventory sizes, required lanes, fixed success claims, URI shapes, hashes, and strict unknown-field rejection. The isolated test also demonstrates the cross-field invariants that a production verifier must implement, including:

- edition/product/Installer binding;
- exact r7 Installer reuse;
- device identity and allowlist closure;
- exact server object and fetch-audit closure;
- public head equality;
- old-version forward update, rollback target, and recovered candidate identity;
- canonical Stable URI equality across root, server, devices, and fetches.

JSON Schema cannot by itself compare arbitrary values in different branches or establish that a hash or signature is genuine. Production integration must additionally:

- reject duplicate JSON properties and require the selected canonical UTF-8 encoding;
- recompute every file, object, candidate-set, payload-set, trust, receipt, and attested-payload hash;
- verify ES256 IEEE-P1363 signatures, key purpose separation, trusted key lookup, and canonical low-S policy;
- verify device attestations against enrolled device keys and server attestations against an independently pinned audit key;
- validate time ordering and trusted-time freshness;
- obtain evidence from real devices and server logs rather than operator-authored booleans.

Attestation envelopes bind hashes of canonical server or device sub-payloads. They do not contain a hash of the evidence document itself, avoiding a signature/hash self-reference cycle.

## Isolated contract check

From the repository root, run:

```powershell
pwsh -NoProfile -File release/scripts/Test-StablePrivatePilotEvidenceContract.ps1
```

Success prints:

```text
STABLE-PRIVATE-PILOT-EVIDENCE-CONTRACT-PASS
```

The test accepts structurally and semantically consistent Personal and Enterprise fixtures. It rejects missing or duplicated devices, two fresh-install lanes, same-version/no-op updates, wrong canonical URIs, candidate leakage, public-head changes, wrong Installer or object hashes, duplicate candidate roles, unknown fields, missing health-failure rollback evidence, and Pilot-channel substitution.
