# Enterprise production Pilot evidence r8 v1

## Purpose and admission boundary

`New-EnterpriseProductionPilotEvidenceInput.ps1` imports independently signed
two-device Pilot observations into one canonical, create-new r8 input. It does
not mutate production state, publish a feed, or promote Stable.

Both the authoritative r7 receipt and the r8 result remain
`productionAdmission=NO_GO`. r8 accepts exactly one pre-Pilot NO_GO reason:

```text
INSTALLER_SIGNING_RESPONSE_REQUIRED
```

That reason is preserved from the request-v2 trusted build before signing.
The actual signed r7 response must already be admitted, with the exact portable
SDK closure and source/build evidence verified. It is not permission to omit
the response or leave an SDK prerequisite unchecked. Any other NO_GO reason is rejected with
`R7_PRODUCTION_ADMISSION_REASON_REJECTED`. Pilot observations cannot compensate
for missing source, build, request, signature, or Installer authority.

The successful output has
`nextRequiredGate=PILOT_EVIDENCE_BOUND`; a later locked state transition must
import and hash-bind those exact bytes. Historical private-pilot promotion v2
evidence is not an r8 prerequisite because it contains later promotion closure.

## Authoritative state and build binding

In default create mode, the adapter accepts a state root plus an independently
expected exact r7 head SHA-256. While holding the state read lock it replays the
complete r1-r7 chain with the state schema and requires:

- an Enterprise plan v2 that fixed
  `pilotEvidenceTrustPolicySha256` before r1; the caller cannot replace this
  plan anchor with a command-line expected hash;
- Enterprise Stable at exactly r7 `INSTALLER_SIGNATURE_IMPORTED`, seven
  receipts, and no orphan;
- locked plan, head, r3, r5, r6, r7, response, trusted-build evidence, and
  signed Installer bytes;
- request-v2, trusted-build evidence, resource binding, source-build input set,
  target-build identity, payload set, and verified SDK closure equality across r6/r7;
- canonical signing response ES256 replay against the plan public key;
- Windows Authenticode, PE-content, signer certificate, and bound RFC3161
  timestamp replay; and
- exact full-file Installer SHA-256, PE-content SHA-256, response SHA-256, and
  receipt/head bindings.

Missing trusted build provenance stops with
`R7_TRUSTED_BUILD_SOURCE_MISSING`. The output path must be outside the state
root, on one ordinary local Windows directory chain with no junction or other
reparse ancestor. The adapter locks and rechecks the parent-directory identity
before and after create/move, and the canonical output records both the locked
plan SHA-256 and its Pilot trust-policy SHA-256. Existing output bytes are never
accepted or overwritten.

## Independent Pilot cryptography

The trust policy carries separate P-256 public coordinates (`x` and `y`) for
Windows evidence, the Windows verifier report, local-data certification, the
Stable server, fresh-install device, online-upgrade device, and unauthorized
control. Those seven Pilot keys and the Installer response key must all have
distinct public points and purpose-bound key IDs.

The verifier replays low-S ES256 IEEE-P1363 signatures over:

- the existing Windows evidence-envelope canonical attestation payload;
- a canonical Windows verifier report projection that excludes only its
  `authentication` member and is domain-separated with
  `ensou-dsh-enterprise-windows-pilot-verification-report-authentication-v2`;
- the existing local-data certification canonical unsigned payload; and
- purpose-domain canonical projections for the Stable server, fresh-install,
  online-upgrade, and unauthorized-control observations.

The r8 verifier authenticates that report before reading its decision, checks,
hashes, audience, release tuple, or other admission claims. It also binds stored and replayed
readiness reports, the pinned 21-gate contract, the 15-minute no-visible-console
gate, rollback/recovery/revocation gates, local history and workspace
preservation, two distinct Windows device identities, separate clean-install
and online-upgrade lanes, an unauthorized device control, exact r3/r5/r6/r7
objects, and short-lived evidence windows.

## Revalidate an existing committed r8 summary

Use `-RevalidateOnly` with `-ExpectedHeadSha256` for the current committed r8,
r9, or r10 head; do not supply create-mode `-OutputPath` or
`-ExpectedR7HeadSha256`. The adapter reconstructs the historical r7 head from
the committed chain and retains a state read lock. Supply the same nine
original proof files at their original bound locations; the r8 summary is not
a portable archive of those signed files.

```powershell
pwsh -NoProfile -File release/scripts/New-EnterpriseProductionPilotEvidenceInput.ps1 `
  -StateRoot C:\release-state\enterprise-stable `
  -RevalidateOnly -ExpectedHeadSha256 <current-head-sha256> `
  -PilotTrustPolicyPath C:\pilot-evidence\trust.json `
  -WindowsPilotEvidenceEnvelopePath C:\pilot-evidence\envelope.json `
  -WindowsPilotEvidenceBodyPath C:\pilot-evidence\body.json `
  -WindowsPilotVerificationReportPath C:\pilot-evidence\verification.json `
  -WindowsPilotReadinessConfigPath C:\pilot-evidence\readiness-config.json `
  -WindowsPilotStoredReadinessReportPath C:\pilot-evidence\stored-readiness.json `
  -WindowsPilotReplayedReadinessReportPath C:\pilot-evidence\replayed-readiness.json `
  -LocalDataCertificationReceiptPath C:\pilot-evidence\local-data.json `
  -StablePrivatePilotObservationPath C:\pilot-evidence\stable-observation.json
```

Successful replay returns `R8_EVIDENCE_REVALIDATED_NO_GO`, the current head,
historical r7 head, exact committed summary SHA, verification time, and
`PolicyValidUntilUtc`. It never writes a bundle or advances state. Maximum
evidence age and minimum remaining validity are rechecked at final return;
revalidation cannot extend the signed evidence lifetime. Expired or changed
proof must not be replaced by editing the committed summary.

For complete client-signature plus Pilot plus final-state replay, use the main
orchestrator's `-Edition Enterprise -Phase Status -RevalidatePilotEvidence`,
with `-PlanPath`, `-StateRoot`, `-ExpectedHeadSha256`, and the same nine input
parameters. This result remains `NO_GO` until the separate release gates are
satisfied; see the [orchestration contract](production-release-orchestration-v1.md#status).

## Focused checks

Run from the repository root:

```powershell
pwsh -NoProfile -File release/scripts/Test-EnterpriseProductionPilotEvidenceCryptography.ps1
pwsh -NoProfile -File release/scripts/Test-EnterpriseProductionPilotEvidenceAdapter.ps1
pwsh -NoProfile -File release/scripts/Test-EnterpriseProductionPilotEvidenceRevalidation.ps1
pwsh -NoProfile -File release/scripts/Test-ProductionClientSigningHistory.ps1
pwsh -NoProfile -File release/scripts/Test-EnterpriseProductionReleaseReadiness.ps1
```

Success prints:

```text
ENTERPRISE-PRODUCTION-PILOT-EVIDENCE-CRYPTOGRAPHY-PASS
ENTERPRISE-PRODUCTION-PILOT-EVIDENCE-ADAPTER-PASS
```

The cryptography test generates real P-256 keys and signatures and covers the
body, independently authenticated verifier report, local-data and Stable
purpose domains, tampering, missing signatures, wrong-key use, key reuse, a
schema-valid real-observation Stable fixture, and endpoint/object-metadata
drift. The
adapter test covers the full-state contract, the unique allowed NO_GO reason,
missing trusted-build fields, the plan trust anchor, immutable output behavior,
direct state-root and junction path rejection, and no output on a rejected
state.

The revalidation and readiness tests execute exact implementation blocks with
explicitly labelled component stubs. Client history uses real ES256, JSON,
file-lock and hash checks, but mocks the Windows Authenticode query. None of
these focused tests claims real certificate trust or employee device acceptance.
