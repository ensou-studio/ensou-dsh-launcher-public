# Personal account client

Online transport for the Personal email-account API. It has no dependency on
Enterprise employee/device policy and imposes no fixed two-device limit.
The Windows Launcher now wires this transport through an authorization
coordinator into email login, normal start/open actions, and a runtime monitor.
The separate Personal.Windows adapter persists sessions with CurrentUser DPAPI.
The integration compiles and its component tests pass; actual interactive
login, production deployment, and distribution acceptance are still pending.

## Implemented contract

| Method | Behavior |
| --- | --- |
| `RequestEmailAsync` | Canonicalize the email, obtain an issue nonce, sign a device proof, request an OTP challenge. A submitted challenge does not prove approval or mail delivery. |
| `SignInAsync` | Obtain a redeem nonce, submit the six-digit code, validate the exact installation and grant fields. |
| `ValidateAccessAsync` | Bind the complete access-token digest to a fresh proof and verify the exact session/account/installation response and expiry. This is an online snapshot, not an offline runtime lease. |
| `RefreshAsync` | Use a fresh refresh proof, preserve the session/account/installation identities, and accept only newly rotated credentials. |

The production constructor owns its HTTPS transport. Redirects, cookies,
automatic decompression and default credentials are disabled. An internal
friend-assembly constructor exists for test transport only; it is not a user
configuration switch. The origin must be a canonical, non-loopback HTTPS DNS
origin at the default port. No origin is chosen or compiled into this library.

All operations on one client instance are serialized without a waiting queue.
A concurrent operation fails `Busy`. Each operation's nonce and action share
a 15-second cancellation deadline. Response headers and bodies are bounded;
successful responses require JSON, `no-store`, exact fields and UTC timestamps.
The client neither sends the reverse-proxy secret nor handles model API tokens.

Device proofs independently implement the server's four operations, purposes,
exact consumption routes and length-prefixed SHA-256 binding. Access/refresh
nonces receive the **complete token**, not a caller-selected digest. The signer
uses ES256/P1363 and verifies its signature against the public key captured for
that proof, so a key replacement between read and sign is rejected.

`WindowsPersonalDeviceProofKey` uses an origin-and-installation-specific
CurrentUser Windows CNG signing key. Construction does not create it;
`EnsureCreated` is an explicit first-enrollment operation. Reading or signing
never silently recreates a missing key. Keys must be P-256, signing-only,
non-exportable and user-scoped. This is not hardware attestation, and it does
not make the same Windows user incapable of invoking the key.

Enrollment uses atomic create-only semantics. Only the provider's explicit
`NTE_EXISTS` result is treated as an existing key; other creation errors are
not hidden by an existence check. A newly created key is validated before its
handle is returned, and validation failure removes only that newly created
key through its own handle. Normal enrollment disposes the handle without
deleting the persisted key. Existing keys are validated, never overwritten.
This follows the Windows provider's
[create-only contract](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey);
it does not use the overwrite-existing-key flag.

## Integration contract

- Obtain the origin from authenticated release configuration, not a mutable
  user text box or environment variable. Launcher reads its own immutable
  `PersonalAccountOrigin` assembly metadata and requires exactly one canonical
  HTTPS origin. Missing metadata prevents publishing and normal account access,
  without removing recovery/update entry points. No production origin is chosen.
  Authenticode and signed artifact hashes protect the Launcher bytes. Build
  intent and two-clean-build receipts now require this same origin; the
  per-artifact metadata CLI checks its compiled value before acceptance.
  Actual clean production builds and signing acceptance remain required.
  Other binaries do not choose this endpoint, so their existing
  update trust fingerprint is not being expanded merely to carry this field.
- Read the already-verified managed installation identity without creating a
  replacement during login. Keep credentials and their device/origin binding
  in dedicated CurrentUser-protected state outside `.dsh` and update journals.
- Persist only an accepted complete session. Clear the durable old session
  before submitting refresh, then atomically save and online-validate its
  accepted replacement. Clear again after an uncertain save or submission.
  Never reuse the old object or refresh token:
  the server deliberately revokes a session on valid historical-token reuse.
- On `ReauthenticationRequired`, discard the uncertain credential state and
  require a fresh email login. Do not automatically replay a submitted sign-in
  or refresh, including after transport cancellation or malformed success.
  `Denied` and `RateLimited` are explicit HTTP refusals, not authorization.
- Use one client/coordinator per installation. The in-memory operation gate is
  not a durable transaction lock and does not coordinate separate processes.
  The normal Launcher entry point's single-instance admission remains required.
- Require online authorization before and after normal runtime startup, then
  monitor its bounded validity. Stop only the Launcher-owned runtime when
  authorization is lost; do not delete chats/workspaces or revoke model API
  tokens merely by deleting local login credentials.
- The UI polls every 15 seconds while a normally admitted owned runtime is
  active, including during downloads. It renews access near expiry and stops
  owned runtime on failed online authorization. Monotonic deadlines prevent
  contention or repeated checks from extending one access credential's expiry.
  The polling interval is not proof of an exact end-to-end revocation deadline;
  dispatcher delay, request/stop duration, and server limits require real tests.
  Successful update health checks stop their candidate before interactive use.
- Keep independently signed updates, rollback and recovery available when
  logged out. Do not put network authentication in shared Host launch callbacks:
  `DshHostService.EnsureStartedAsync` can return `AlreadyHealthy` before those
  callbacks, and update-health operations also need the raw Host.

`PersonalAccountSession` and challenge string representations are redacted.
Request/response byte buffers and intermediate cryptographic material are
cleared where owned; managed credential strings still exist in process memory.
Do not log or serialize these objects into ordinary settings, diagnostics or
support bundles.

## Evidence and remaining acceptance

Latest 2026-09-09 native Windows snapshot: 109 source inputs were unchanged,
all WPF/dependency/test projects compiled in Release with zero warnings/errors,
and client **16/16 groups** plus actual DPAPI storage **5/5** passed. Missing
CNG test opt-in returned exit 2 without creating a key; the explicit owned-key
test then passed on the actual Windows software key storage provider:

- Construction, public-key reading and signing did not create a missing key.
- Atomic creation returned an ownership handle for one random test origin and
  installation. Duplicate creation refused without replacing the public key;
  normal `EnsureCreated` preserved the existing key.
- A new object and a separate hidden process reopened the persisted user key;
  P-256/P1363 signatures verified against the same public key.
- Signing-only/user-scope/non-exportable policy was checked, and private-key
  export was rejected. Different origins and installations did not reuse it.
- The test deleted only its original creation handle and confirmed absence.
  A separate native read-only check of that exact key also found it absent.

The missing-origin publishing guard refused as intended; the actual compiled
WPF metadata CLI returned the exact 133-byte test-origin response without
launching a window or Host. All eight runner steps and the outer runner exited
as expected. The storage and metadata temporary directories were empty after
testing. Receipt `.tmp/personal-account-integration-20260909/run-08/RESULT.json`,
SHA-256 `b42044e48abdf6cd35c944cb5ab3a17da44806fc1c1c87c559b24fe62074a419`.
This README was updated after the snapshot; no tested product source changed.

The earlier run-06 normal-path receipt is retained. Independent review then
found that the reopen child inherited stdin and that a non-race `Kill` failure
could skip bounded exit confirmation. The test now redirects and immediately
closes stdin inside its guarded operation, records termination failures, and
still attempts bounded exit/output confirmation before failing. These fixes
were independently reviewed and the normal path rerun; an actual OS refusal
to terminate the child was not induced, and is not claimed as executed evidence.

Run-07 stopped before any CNG test because the coordinator test fixture mixed
fixed session timestamps with the real wall clock. Its refresh threshold was
2026-09-09 00:03 UTC; run-06 began before it and run-07 began after it. The
test helper now defaults to its own fixed-epoch clock while preserving
explicitly supplied clocks. Product expiry/refresh behavior and the machine
clock were not changed. Failed receipt:
`.tmp/personal-account-integration-20260909/run-07/RESULT.json`, SHA-256
`0d22deb9db1d6cfe5c8a0a891d98bf50d32294115e57324923b805d842c1759c`.

The CNG executable requires `ENSOU_PERSONAL_CNG_TESTS=authorized-v1` explicitly,
and uses a random `*.personal-cng-test.invalid` origin plus installation UUID.
Its reopen-only child has a 20-second process deadline, bounded output, and
five-second termination/output cleanup limits. It does not enumerate or delete
keys by prefix. A crash or uncertain cleanup must be investigated using the
reported exact test key name, not by deleting other keys. The parent retains
its original creation handle during the child test: this proves cross-process
reopening, not reopening after reboot, another Windows user, or a hardware/TPM
guarantee. No actual customer identity, model token, or DSH state was used.

Earlier 2026-09-09 private snapshot: all WPF/dependency projects compiled in
Release with zero warnings/errors. Client suite **15/15 groups** includes the
original 13 transport cases, **17 coordinator cases**, and the compiled-origin
matrix. Windows storage tests **5/5** executed actual CurrentUser DPAPI and
exact-handle file operations in an explicitly owned temporary directory; they
cover save/load/replace/clear, binding/copy rejection, tamper, duplicate JSON,
and cancellation. The missing-origin publish guard failed for its intended
reason. Five child processes exited and drained; the temporary state tree was
removed. No product window, DSH runtime, real account, or CNG key was started.
Receipt `.tmp/personal-account-integration-20260909/run-03/RESULT.json`, SHA-256
`4b8af5c616a1cbb1153d1944418481ce71822a824df30c69ccfc259819a4ff2c`.
The snapshot pinned 103 inputs; this README was updated after the run.
The failed parallel-build run-02 is retained; the successful integration build
serializes shared project outputs without disabling compiler/analyzer checks.

The following earlier receipts cover transport/interoperability only:

2026-09-09 pinned private Windows build: zero warnings/errors and **13/13**
client contract tests. These tests use an ephemeral signer and fake HTTP
handler, independently checking proof signatures and wire bindings, malformed
responses, foreign identities, uncertain submissions and non-queued concurrency.
Workspace receipt `.tmp/personal-client-check-20260909/run-02/RESULT.json`, SHA-256
`ebdb30ea461e830fa45687aeb9f4e4d0b3f2e9fe8422e5a4570636b1261a5d94`.

A separate private integration build also passed a complete client-to-server
flow: email request, sign-in, access, refresh, access with the new token, denial
of the old access token, and unknown-email no-mail behavior. This ran the real
HTTP handler, proof verifier, OTP and session services behind a test loopback
proxy. Workspace receipt
`.tmp/personal-client-api-interop-20260909/run-01/RESULT.json`, SHA-256
`bb53f3784b746fa08fcb96f87bbcae130ddcb3459e35b949bf2e5cf1bbd4fd0f`.
Its private API fixture copy only gained a partial-class declaration and two
read-only fixture accessors; the source and production handler were unchanged.

The earlier transport/interoperability tests use ephemeral signers; actual
CNG evidence is separately scoped above. Neither proves durable PostgreSQL/replay
transactions, SMTP inbox delivery, Nginx/TLS deployment, interactive WPF
enforcement or crash recovery, production signing, or distribution readiness.
The workflow is added for future CI; it has not been pushed or executed remotely.
