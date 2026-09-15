# Personal Pilot completed feed execution import

This slice authenticates an already completed Personal Pilot feed operation. It
does not add a lifecycle phase, authorize public distribution, or certify two
employee devices. `OFFLINE_BUNDLE_ONLY` remains offline authorization, not proof
of publication. `PilotReady` and `StableReady` remain false.

## Executor handoff

1. Execute the existing Personal FeedPromoter operation with the operation ID,
   feed identity and both raw CAS expectations from the sealed r8 request. Keep
   the original pre-publication head bytes for a non-genesis operation.
2. On that Linux feed host, export the committed operation using the existing
   root-owned publication lock:

   ```text
   Ensou.Dsh.Personal.FeedPromoter export-completed-operation --feed-root <feed> --trust-policy <trust.json> --operation-id <exact-operation-id> --output-directory <separate-empty-directory>
   ```

   Export is read-only with respect to the feed. It refuses pending operations,
   changed current heads, changed trust/identity, invalid journal chains, changed
   artifacts and nonempty output. It copies actual raw operation request/result,
   identity, trust, current heads, journal entry, signed manifest and the two
   immutable archives. It writes `snapshot.v1.json` only after all checks/copies
   complete. This snapshot is unsigned and is **not** an admission receipt.
3. Transfer the snapshot through the executor's controlled offline workflow.
   Load `PersonalFeedExecutionResultProducer.psm1`, then call
   `New-PersonalFeedExecutionResultBundle` with the exact `StateRoot`,
   `PromotionRoot`, `SnapshotRoot`, a new separate `OutputRoot`, the r8
   `ExpectedHeadSha256`, `ExpiresAtUtc` (at most 24 hours after result completion),
   and an explicit `Signer` callback. The callback receives authentication payload
   bytes and must return one canonical base64url 64-byte low-S ES256/P1363
   signature. No key is generated, selected or loaded from a certificate store.
   The signing authority must be the plan's existing
   `externalResponseTrusts.feedPromotion` authority, acting as the authorized
   executor attesting the measured completed operation.

   For non-genesis requests, `PreviousHeadPaths` must contain the original raw
   files named `previous-channel-head` / `previous-journal-head` when the respective
   request CAS state is `present`. Their bytes must match the sealed expectations.
   New current heads cannot substitute for these historical preconditions.
4. Import through the existing orchestrator `Promote` phase with
   `-PersonalFeedPromotionResultPath <bundle>/result.v1.json`, `-PromotionRoot`,
   and exact r8 `-ExpectedHeadSha256`, alongside normal Personal plan/state inputs.
   The importer locks the authorized offline bundle before taking the state writer
   lock, verifies the completed result, snapshots it into
   `imports/pilot-feed-result.v1`, and only then CAS-appends `PILOT_FEED_PROMOTED`.

The execution signature uses payload type/domain
`ensou-dsh-personal-feed-execution-result-v1`, separate from the existing offline
authorization signature. The immutable state-owned bundle is revalidated on
historical reads; those reads do not access a later live feed or apply a new
wall-clock expiration to an already committed operation. Exact completed-result
replay is idempotent; a different envelope cannot replace it.

All public producer paths and the imported result path must be absolute. Output,
snapshot, state and authorization workspaces are disjoint from the checkout
(including `.git`), and from one another; an ancestor of the checkout is not an
acceptable output workspace either. These checks run before signing or staging.

The trusted executor/signing authority is responsible for running reviewed code
and for attesting a truthful, lock-measured completed operation. The importer's
existing tracked clean-checkout admission includes the producer module, but this
is an import-time code-source check, not remote execution attestation. The
standalone producer does not independently prove which code previously executed
on the feed host. Adding a self-reported source commit or module hash to the signed
envelope would not prove that execution; no such new attestation protocol is
introduced. Public producer/CLI positive admission remains unverified below.

## Verified scope (2026-09-07)

- Real isolated Linux Personal FeedPromoter operation and read-only export passed,
  including unchanged feed, exact operation replay, lock conflict and artifact
  drift rejection. No host ports or container network were enabled.
- Its real serialized operation/head/journal/archive bytes passed the result
  verifier and the offline signing **core** with ephemeral fixture signatures.
- Wrong signature, operation, r8, offline bundle, edition and file digests,
  expired new result, unsafe role paths, overlapping public producer paths, and
  generic r8 evidence are rejected. Historical result verification remains valid
  after its import freshness window.
- Public producer success and the complete production CLI r8-to-r9 CAS remain
  **UNVERIFIED**: this workspace has no authentic Personal r7/r8 fixture with its
  required signed Installer closure. Synthetic state context tests do not replace
  that prerequisite. No production publication, customer installation, real
  signing key or certificate-store modification was performed.
- Old orchestration foundation tests now explicitly reject synthetic Personal
  r8/r9 continuation. The whole orchestration suite was not claimed green; its
  existing earlier Bootstrapper/PE fixture blocker is separate from this slice.

Re-run the focused test with an exported Linux fixture:

```powershell
./release/scripts/Test-PersonalFeedPromotionResult.ps1 -CompletedLinuxSnapshot <snapshot-directory>
```

The test writes a unique task-local `*-verification.json`, explicitly recording
the unverified public producer/CLI boundaries. The C# fixture selector is
`--export-completed-fixture <new-root>` and requires Linux plus
`ENSOU_DEVELOPMENT_LINUX_FIXTURE=1`; it is not a production export/signing service.
