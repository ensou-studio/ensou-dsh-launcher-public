# Local-reviewed runtime publication

This is an operator workflow for publishing reviewed managed runtime candidates
without a GitHub Actions job. It is **not** an employee installation guide,
automatic publication approval or a way to promote Lab fixtures.

The implementation shares the existing immutable GitHub reservation, exact
three-asset upload, re-download and final immutable-release checks. It changes
the source of the publishing inputs, not the signed admission authority.
See [ADR 0009](adr/009-local-reviewed-source-publication.md).

## Prerequisites

- An operator-approved, clean and committed source build producing a canonical
  `managed-vYYYY.MM.DD.N` candidate. Existing `lab-*` artifacts remain ineligible;
  do not edit their metadata to claim eligibility.
- Exactly identified archive, metadata, archive checksum and
  `managed-candidate.json` inputs from that build, with their original bytes.
- The separately approved immutable, empty reservation Release/tag at the exact
  runtime build commit. This tool does not create a reservation.
- Explicit approval for actual publication to the intended repository and
  least-privilege GitHub credentials supplied through the existing operator
  environment, never through an input record or command-line secret.
- A new external local verification directory whose parent already exists.
  Failed workspaces are retained; choose a new attempt directory after diagnosis.

## Local input

The file must be named `local-reviewed-source-runtime-publication.v1.json`.
It is ordinary JSON data, not executable configuration. Its exact top-level
members are:

| Member | Meaning |
| --- | --- |
| `schemaVersion` | Integer `1` |
| `authority` | Literal `UNSIGNED_REVIEW_INPUT_ONLY` |
| `repository` | Exact GitHub owner/repository |
| `releaseId` | Canonical managed candidate ID |
| `launcherSourceCommit` | Exact 40-character lowercase runtime-build repository commit; not necessarily the later Launcher build commit |
| `immutableReservationTag` | `ensou-dsh-source-candidate/` followed by the exact release ID |
| `inputs` | Four descriptors in the order below |

Each descriptor has exactly `role`, `fileName`, `path`, `sizeBytes` and `sha256`.
Paths are absolute local file paths; sizes are positive integers and digests
are lowercase SHA-256. The required order and names are:

1. `archive`: `EnsouDshRuntime-<releaseId>-win-x64.zip`
2. `metadata`: `EnsouDshRuntime-<releaseId>-win-x64.metadata.json`
3. `hash-evidence`: `EnsouDshRuntime-<releaseId>-win-x64.zip.sha256`
4. `managed-candidate`: `managed-candidate.json`

Review the record and retain its SHA-256 independently before invocation. A
record hash pins the bytes reviewed; it does not turn that unsigned record into
proof of a trusted build or a release authorization. The publisher verifies and
holds the original inputs while the shared publication path operates.

## Invocation after approval

```powershell
pwsh -NoProfile -File release/scripts/Publish-SourceRuntimeCandidate.ps1 `
  -LocalReviewedPublicationInputPath C:\release-input\local-reviewed-source-runtime-publication.v1.json `
  -ExpectedLocalReviewedPublicationInputSha256 <reviewed-record-sha256> `
  -LocalVerificationWorkspace C:\release-verification\new-attempt
```

This is a **publishing command**, not a dry run. Do not execute it merely to
check the JSON. Do not pass `ActionsArtifactId`, `RunAttempt` or fabricated
runner variables with this invocation. The existing Actions invocation remains
separate and unchanged. A failed or partially published release identity is
not reused by editing timestamps, tags, metadata or verification files.

### Explicit runtime profile

Existing invocations default to `enterprise-managed` and accept only complete
schema-version-2 metadata. For a reviewed `enterprise-direct-local` source build,
add `-RuntimeProfile enterprise-direct-local` to the publishing invocation above.
Both the original input and the downloaded copy must satisfy the complete
production schema-version-3 contract; changing only a profile label is rejected.
The shared metadata validator requires the corresponding explicit
`-ExpectedRuntimeProfile enterprise-direct-local` selection.

When preparing that runtime with `Invoke-LauncherProductionRelease.ps1`, pass
`-Edition Enterprise -EnterpriseRuntimeProfile enterprise-direct-local` on the
relevant orchestration phases. Personal rejects that selection and retains its
existing runtime contract. These switches do not waive source publication,
organization admission, signing, or real-device acceptance.

The runtime-build commit must have been fixed before the build. A later commit
that resembles an earlier dirty build does not retrospectively prove that build's
source. Generate `managed-candidate.json` from the actual clean build and its
chosen compatibility versions; do not backfill a different commit into old
candidate metadata.

## What a successful publication does not prove

Publication produces the same immutable GitHub source Release and unsigned
source-review facts as the Actions path. It does not issue the existing signed
organization-admission receipt, sign the manifest-publishing response, change
Windows certificate trust or close a production release gate on its own.

The existing Enterprise source-admission chain, signing steps, real HTTPS
updates, identity authorization and named Windows-device acceptance still apply.
Personal source-readiness behavior is not broadened by this entrypoint.

For development, run `release/scripts/Test-LocalReviewedSourceRuntimePublication.ps1`
and `release/scripts/Test-SourceRuntimeReviewHandoff.ps1`. Their fixtures are not
an actual GitHub publication or production-source admission.
