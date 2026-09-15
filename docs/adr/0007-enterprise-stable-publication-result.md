# ADR 0007: Authenticated Enterprise Stable publication results

**Status:** Accepted for implementation; not a release approval
**Date:** 2026-09-10
**Deciders:** Ensou DSH Launcher implementation team, within the approved enterprise-first release scope

## Context

Enterprise production clients consume Stable, not the Personal Pilot channel.
The existing r9 transition seals an independently authorized offline bundle;
it does not prove that the Linux FeedPromoter published it. The Linux operation
receipt already binds the operation, request, feed identity, pre-publication CAS,
candidate manifest and final channel/journal heads, but that receipt is unsigned.
An arbitrary copied JSON receipt must not advance the production release to r10.

The distributor is a shared Ubuntu host. This implementation does not install
software, authorize remote publication, move customer identity/token services,
or modify an existing feed. Conversation/workspace data remains on Windows.

## Decision

Use a separate root-only `attest-publication` operation after successful
publication. It opens existing global and Stable channel locks in that order,
reads the committed operation without calling the mutating operation-store
`Begin` method, verifies the current raw manifest/journal heads and immutable
artifact bytes, and exports a create-only signed evidence bundle outside the
feed and all input paths. Missing locks or incomplete operation state fail;
the attestor never creates a lock or repairs the feed.

Plan v2 has an optional `stablePublicationTrust` with purpose
`stable-public-promotion-attestation`. Its key ID and P-256 point must differ
from the release-manifest key and every existing response-authentication key.
The original immutable plan must already contain this trust before r10 can
run. Historical plans lacking it remain readable through r9; operators cannot
append trust to an existing plan or provide a replacement key during import.
This is an application protocol key, not a Windows code-signing certificate.

### Wire and byte binding

`publication-result.v1.json` contains exactly `schemaVersion`, `algorithm`,
`keyId`, `purpose`, `payload`, and `signature`. The payload is base64url of the
original UTF-8 statement bytes. ES256 signs the following exact bytes, using
low-S, 64-byte P1363 signatures:

```text
UTF8("ensou-dsh-enterprise-stable-publication-result-v1\n" + keyId + "\n")
  || decodedPayloadBytes
```

This avoids cross-language JSON reserialization when verifying signatures.
Every JSON document still rejects duplicate and unknown members under its
applicable schema/type. The statement binds the original context SHA, operation
ID, Linux operation-request digest, observation/expiry times, eight ordered raw
file descriptors and the actually observed artifact digests. The original
offline promotion-request SHA and the Linux operation-request digest are
different domains; equality between them is never required.

The bundle contains the envelope and `evidence/` with exactly:

```text
context.json                 trust-configuration.json
feed-identity.json           channel-head.json
operation-request.json      journal-head.json
operation-result.json       journal-entry.json
```

The existing immutable release directory contains archives, not a second
`release-set.v2.json`. `channel-head.json` therefore preserves the actual signed
manifest snapshot and is bound to the original r9 candidate digest. The attestor
must hash the real immutable archives and compare them with the manifest and
journal; it must not manufacture an extra manifest path for its verifier.

### Import and historical state

`Promote -EnterpriseStablePublicationContextPath <external-new-file>` exports
the exact r9 context under its read lock. It requires `-ExpectedHeadSha256` and
does not run Linux commands. After an authorized operator publishes and runs
the Linux attestor, `Promote -EnterpriseStablePublicationResultBundlePath
<external-bundle>` imports the signed result.

The importer opens the external evidence first, then acquires the production
writer lock, revalidates r9 and its original plan, verifies the distinct result
signature and all byte/identity/CAS bindings, copies held inputs create-only,
reopens the copied bundle and rechecks before appending r10. Fresh admission
requires an unexpired result with a maximum ten-minute lifetime and current
Pilot evidence. Historical reads verify persisted signatures and bindings;
exact r10 replay requires the same envelope digest and cannot substitute a new
result. Generic typed evidence cannot bypass the importer.

An interrupted import at r9 without an r10 receipt can retain an expired result.
A fresh result for the same immutable context may replace that expired import
only under the state writer lock, after full historical authentication. The
old, identity-pinned directory is moved create-only to a unique same-volume
sibling diagnostic quarantine; it is never deleted. A still-fresh conflicting
result is rejected without changing the state.

An orphan r10 receipt must never be replaced or quarantined. Exact recovery
uses the same envelope, transition data and original receipt timestamp, and
proves that the attestation and Pilot evidence were valid at that timestamp.
Current expiry does not prevent finishing that already recorded transition.
Historical r10 reads also verify freshness at the original receipt timestamp;
this is not permission to backdate a new admission.

## Options considered

| Option | Assessment |
| --- | --- |
| Import the existing unsigned JSON receipt | Small change, but no authenticated source; rejected. |
| Invoke SSH/publication directly from the Windows orchestrator | Couples credentials and remote mutation to release-state repair; rejected for this scope. |
| Separate read-only attestor and authenticated importer | Reuses the existing Linux publisher and state locks; selected. |

## Consequences

- One additional protocol key must be pinned before the release plan begins.
  The Linux private key is owner-only PKCS#8; it is never exported in evidence.
- Authentication of server observations is distinct from offline permission
  to publish and from Authenticode signing of Windows files.
- A stale or changed feed is rejected rather than silently repaired.
- This work closes a source implementation gap; it does not replace actual
  authorized hosting, HTTPS, customer identity or Windows-device acceptance.
  Readiness must not be inferred from synthetic fixture signatures.

## Action items

1. Implement the attestor, strict schemas, importer and historical-state checks.
2. Execute the real isolated Linux producer and cross-language verifier tests.
3. Verify r9-to-r10 CAS, replay and interrupted-import recovery with the exact
   source candidate before calling the implementation complete.
4. Obtain the separate hosting/signing/device approvals and test the real feed.
