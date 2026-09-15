# ADR 0008: Authenticated runtime source-release admission

**Status:** Accepted for implementation; not a release approval
**Date:** 2026-09-10
**Deciders:** Ensou DSH Launcher implementation team, within the approved Enterprise Stable scope

## Context

The Launcher production plan previously identified runtime archive, metadata and
hash-evidence bytes without proving which immutable GitHub Release supplied
them. A workflow run, tag name or unsigned Release API response is insufficient:
each can be copied, retargeted or replaced outside the authenticated production
release history.

The runtime organization-admission receipt already has a compiled, independent
ES256 trust root in ReleasePublisher. The r5 manifest-publishing response also
has a plan-pinned ES256 trust domain and is retained with the raw r4 request,
raw r5 response and append-only state receipts. Adding another key or a separate
unsigned workflow proof would create competing authorities without improving
the byte binding.

This first integration is Enterprise Stable only. The shared receipt parser can
support a future Personal decision, but Personal source readiness is not
implemented or implied by this ADR.

## Decision

Extend the existing runtime organization-admission receipt backward compatibly:

- receipt v1 remains valid and has no source-origin meaning;
- receipt v2 is signed by the same existing organization-admission trust and
  must contain one exact `sourceRelease` object;
- `sourceRelease` binds repository, positive GitHub Release ID, managed tag,
  exact 40-character target commit, GitHub immutable status, and exactly three
  ordered assets: archive, metadata and hash evidence;
- asset IDs, names, sizes and SHA-256 digests must match the locked production
  inputs, and hash evidence must describe exactly the archive checksum record.

An Enterprise Stable plan that opts into source-ready admission must anchor the
repository and runtime build commit together. The expected tag is the runtime
candidate's managed Release ID. The runtime build commit is deliberately
independent from the later Launcher `sourceCommit`; equality is neither required
nor inferred. Plan and r1 schemas reject this pair for Personal or non-Stable
flows, while historical plans without the pair remain valid and explicitly
unverified for immutable source origin.

The publisher input and r4 request carry the exact plan-derived
`runtimeSourceReleaseExpectation`. ReleasePublisher verifies the locked runtime
files and signed v2 organization receipt, then places
`runtimeSourceReleaseAdmission` in its r5 response. That object binds both the
raw organization-receipt SHA-256 and its exact source-release tuple. The existing
manifest-publishing response signature authenticates the complete optional
field; no new signature protocol or trust root is introduced.

The source-publication workflow may emit and upload an unsigned review handoff
that preserves the observed Release ID, runtime build commit and three asset
identities. Its declared authority is `UNSIGNED_REVIEW_INPUT_ONLY`: it is an
operator review input, not an admission receipt, and cannot replace either
signature. Promotion persists the runtime build commit from this source identity
separately from the later Launcher source commit.

During r5 import, the state-owned organization receipt remains locked while its
raw bytes are bound to the signed response; that focused lease is released
before the later candidate-staging work. Final historical verification, under
the caller's state read lock, reopens the raw r4 request, raw r5 response,
organization receipt and current head for a complete replay. It checks schema,
canonical bytes, typed receipt SHA-256 bindings, the historical r4 head, r5
signature, source tuple and locked file identity. Missing or changed evidence
fails closed. A standalone workflow artifact, GitHub API result or unsigned
receipt never establishes source admission.

## Options considered

| Option | Complexity | Trust quality | Decision |
| --- | --- | --- | --- |
| Accept a workflow artifact or Release API response | Low | Unsigned and replayable | Rejected |
| Add a new source-release signing key and protocol | High | Creates a competing authority | Rejected |
| Extend the existing organization receipt and bind it into signed r5 | Medium | Reuses independent compiled trust and append-only history | Selected |

## Trade-off analysis

The selected design adds strict tuple and historical-file checks, but avoids key
distribution and protocol migration. Backward compatibility is explicit: v1
receipts remain readable yet cannot produce source-ready status. GitHub Release
IDs and immutable status improve source identity, while exact asset hashes remain
the security boundary for bytes.

## Consequences

- Enterprise Stable source readiness requires the anchor in the original plan,
  a signed v2 organization receipt, a signed r5 response and intact state files.
- Existing plans and v1 receipts remain readable but report immutable source
  release as unverified.
- Runtime and Launcher commits may differ because they identify separate builds.
- Personal support requires a later explicit architecture and contract decision;
  parser reuse alone is not readiness.
- Synthetic and focused checks prove contract behavior only. They do not create
  a GitHub Release, authorize publication or constitute production acceptance.

## Action items

Implementation boundary: the compiled Publisher now exposes the read-only
`--verify-runtime-source-admission` command, which verifies all four original
runtime inputs against its compiled organization trust. It does not issue the
organization receipt or sign r5. The offline r5 issuer is a separate tool,
`New-EnterpriseManifestPublishingResponse.ps1`, which accepts the exact r4 head,
the already signed candidate, an independently operator-approved verifier binary
SHA-256, and the existing plan-matched response signing key. It has no network or
deployment operation and creates a new response bundle without overwriting one.
The operator-approved binary identity must not come from an untrusted receipt.

Its function-level execution tests use real file locks, PKCS8/r5 ES256 and output
copying but explicitly substitute state replay, the compiled-verifier invocation
and full candidate validation. Separate tests cover process transport and the
compiled source verifier. This evidence does not establish that a production
signing service, authorized keys, an actual immutable candidate Release or a
real device acceptance exists.

1. Keep the focused source-release test in the Enterprise managed-release CI.
2. Preserve frozen v1 canonical-signature compatibility tests.
3. Validate the exact real immutable GitHub Release and customer acceptance
   evidence before any production GO decision.
