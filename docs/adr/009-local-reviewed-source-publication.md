# ADR 0009: Local-reviewed source publication without Actions

**Status:** Accepted for implementation; not publication approval
**Date:** 2026-09-12
**Deciders:** Ensou DSH Launcher implementation team, within the requested no-Actions delivery workflow

## Context

GitHub Actions quota is unavailable. The source builder already distinguishes
managed candidates from non-promotable local Lab fixtures, but the publisher
requires an Actions artifact ID even when real candidate bytes were built on an
operator-controlled Windows host. Inventing that ID would misrepresent provenance.

The publishing-job origin is not the source-admission authority. ADR 0008 binds
the actual immutable GitHub Release and its three exact assets through the
existing signed organization receipt and manifest-publishing history. This
decision does not replace that authority or introduce a new storage provider.

## Decision

Keep the existing Actions invocation unchanged. Add a separate, explicit
local-reviewed invocation to the same publisher. It consumes a versioned,
SHA-256-pinned local publication input which identifies the repository, managed
release ID, exact source commit and all four existing input files (archive,
metadata, hash evidence and managed candidate). The input's authority is
`UNSIGNED_REVIEW_INPUT_ONLY`; it is an operator review record, not proof that a
trusted build ran and not a signing or publication authorization.

Local invocation must not accept an Actions artifact ID or spoof Actions runner
variables. It uses an explicit, new verification directory outside its inputs.
Input files remain leased and checked before and after publication. Managed
candidate admission, exact inventory, source identities, immutable reservation,
duplicate-release rejection, upload and re-download checks all remain shared.
Lab candidates remain ineligible. A local record cannot make Lab bytes promotable.

Both routes continue to require an independently created immutable reservation
at the exact source commit and produce the same immutable GitHub Release with
the same three ordered assets. The local publishing record is not an extra
release asset. Neither route issues the organization-admission receipt, signs
the release response, installs Windows trust or establishes employee readiness.
Existing downstream schemas, trust roots and replay checks remain unchanged.

## Options considered

- Wait for Actions quota: no implementation cost, but blocks the requested
  local delivery workflow.
- Invent an Actions ID or relabel Lab outputs: rejected; loses truthful origin
  and candidate eligibility.
- Add a local-reviewed entrypoint while retaining immutable GitHub storage and
  signed admission: selected; reuses the existing publication and trust path.
- Introduce a new artifact store and source trust protocol: unnecessary scope
  for this release and would require a separate architecture decision.

## Consequences and verification

Local preparation no longer requires a billed Actions job. Actual GitHub writes
still require explicit operator approval and credentials outside the record.
The source must be reviewed and committed before production preparation; this
entrypoint does not bypass the production orchestrator's clean-checkout policy.

Focused tests must reject mixed invocation modes, tampered or malformed local
records, wrong identities, changed files and existing verification directories.
They must also preserve the existing Actions parameter contract. Offline tests
prove local input/routing behavior only: no test fixture establishes actual
publication, immutable-source admission, signature trust or device acceptance.
