# Enterprise local-data compatibility runner

`scripts/Test-EnterpriseLocalDataCompatibility.ps1` is the executable compatibility gate for an
enterprise-managed runtime update whose local data must remain recoverable. It is deliberately
independent from the release publisher and pilot-readiness validator: the runner produces
evidence; a release policy can consume that evidence separately.

## What it proves

The runner uses the exact source and target runtime ZIPs supplied by the caller. It verifies each
outer ZIP SHA-256 and every file listed by the runtime's `runtime-files.sha256` before executing
either runtime. It then:

1. Creates an isolated enterprise-managed home containing a valid pre-release flat
   `.credentials.yaml`, a checksummed Zstandard session-v0 stream with a durable user/image event,
   a separate header-only session-v0 artifact, workspace-v2 JSON storage, a content-addressed
   attachment object, and a real workspace file tree.
2. Starts the source runtime and uses the public `session.create`, `session.history`,
   `session.prompt`, `session.search`, `session.attachment`, and `session.selectModel` routes. A
   controlled loopback provider returns unique source markers, so the backed-up fixture contains a
   real rc7 conversation produced through the public API rather than only hand-authored session bytes.
3. Creates a whole-home ZIP backup and canonical file/directory manifests. Canonical tree hashes
   intentionally exclude timestamps and include every relative path, file length, and file SHA-256.
4. Starts the target runtime with `--profile enterprise-managed`, waits for a real unary API route,
   resumes the rc7 session, appends an rc2 prompt/provider response, and verifies both old and new
   markers through `session.history`. Runtime initialization is the minimal path that triggers the
   flat-to-version-1 credentials migration; the conversation is additional compatibility evidence,
   not a prerequisite for migration.
5. Verifies that the credentials document changed to `version: 1` + `refs`; that expected session
   appends retain earlier markers; and that workspace storage, the original attachment object, and
   workspace files remain byte-identical. `session.attachment` must return the exact fixture bytes
   and metadata in every runtime phase.
6. Boots the source runtime against that same migrated home and requires a non-zero
   credentials-layout refusal. This proves that an in-place binary rollback is unsafe.
7. Replaces the entire generated home from the pre-upgrade backup, requires an exact canonical-tree
   match, and then reruns the source public-API lane. The restored source must preserve the rc7
   markers, exclude the target-only marker, append a restored-source marker, and complete another
   loopback provider response.

The runner also fails if a `.db`, `.sqlite`, or `.sqlite3` file appears in the managed home. In these
exact managed builds, public `session.search` is disabled because the session-query index uses
`openAt: "never"`. Each phase nevertheless calls the public route with real conversation markers and
must return the same `internal` error code, `session-query-open-at-never` diagnostic class, and message
SHA-256. This is managed-policy semantic parity, not a claim that search result items were produced.
Query SQLite is derived rather than authoritative local data for this profile.

## Run the current rc7 to rc2 lane

Use a new evidence directory for every invocation; the runner refuses to overwrite one.

```powershell
pwsh -NoProfile -File .\scripts\Test-EnterpriseLocalDataCompatibility.ps1 `
  -SourceRuntimeArchivePath .\out\source-runtime\managed-v2026.08.25.2\EnsouDshRuntime-managed-v2026.08.25.2-win-x64.zip `
  -SourceRuntimeSha256 701e692cdf7d46733cf200e7ef87eafe73c6f075aab5bbc0d155184316ed9c2f `
  -TargetRuntimeArchivePath .\out\source-runtime\managed-v2026.08.25.3\EnsouDshRuntime-managed-v2026.08.25.3-win-x64.zip `
  -TargetRuntimeSha256 ebb4f366dc007da78a1d9168324afd2c0bd4a4da7fcd46e3d0f7d3cb13e22a73 `
  -EvidenceRoot .\out\local-data-compatibility\rc7-to-rc2-001
```

The single stdout object is machine-readable JSON. A passing directory contains:

- `local-data-compatibility-evidence.json`: top-level decision and hashes for the evidence set;
- `runner-transcript.jsonl`: ordered machine-readable phase events;
- `results/forward-result.json`: exact runtimes, migration, preservation, and coverage result;
- `results/rollback-result.json`: in-place refusal, byte-exact restore, and restored source boot;
- `results/source-seed-api-lane.json`, `target-forward-api-lane.json`, and
  `source-restored-api-lane.json`: per-runtime public API, provider, attachment, and query evidence;
- `manifests/*.json`: runtime identities and canonical local-data trees;
- `artifacts/Test-EnterpriseLocalDataCompatibility.ps1`: the exact runner bytes used for the test;
- `artifacts/local-data-compatibility-api-lane.mjs`: the exact API/provider driver bytes used;
- `artifacts/historical-rc7-home-fixture.zip`: an immutable copy of the synthetic input fixture;
- `artifacts/pre-upgrade-home-backup.zip`: the tested recovery artifact;
- `logs/*`: sanitized runtime and driver stdout/stderr for all API phases and the in-place rollback.

Exit code `0`, all three API-lane decisions `PASS`, and both forward/rollback decisions `PASS` are
required. A target boot failure, missing migration, lost prior marker, provider round-trip failure,
attachment byte mismatch, query-policy drift, authoritative-data rewrite, unexpected SQLite file,
source in-place acceptance, non-exact restore, retained target-only marker after restore, or failed
source API lane after restore is a hard failure.

## Current coverage boundary

The forward result has no deferred lanes for this managed-profile compatibility contract. Full
session resume/append, controlled provider conversation, attachment public byte round-trip, and the
deployed query-policy semantics are covered.

Local-data evidence schema v1 recognizes only the managed `deepseek-official/deepseek-v4-flash`
text-only route. Its negative policy probe requests the non-admissible
`deepseek-v4-flash-vision-exp` candidate; that candidate never becomes v1 coverage. The exact rc7
source and restored-source phases must refuse it at `session.selectModel` with `model-unavailable`.
The exact rc2 target currently selects the candidate but must then refuse the image-bearing
`session.prompt` with `attachment-error`. The runner uses this phase-specific tuple allowlist and
rejects any other stage, code, diagnostic class, provider, or model. Each API result records the
observed refusal as
`requestImageNormalization.status = not-applicable-managed-text-only-policy` with a unified
`publicPolicyRefusal` object (`stage`, `code`, `diagnosticClass`, `messageSha256`, `provider`, and
`model`) and requires an empty request-image cache. The top-level coverage value is
`not-applicable-managed-text-only-policy-public-refusal-proven`. A successful image prompt, a
request-image artifact, or any vision-success coverage state is a hard v1 failure. Vision-capable
conversation and normalization evidence requires a future schema v2 plus an explicitly versioned
producer and consumer; it cannot be admitted by reinterpreting a v1 result.
