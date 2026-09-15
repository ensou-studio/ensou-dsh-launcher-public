# Personal Windows session storage

`WindowsPersonalAccountSessionStore` is the Windows-only durable adapter for an
already-authorized Personal account session. It stores one strict canonical JSON
document encrypted with DPAPI `CurrentUser` beneath the verified managed state
root at `personal-account/session.v1.dpapi`.

DPAPI optional entropy is domain-separated and binds the canonical account
origin, installed UUID, verified state root, and exact state-file path. File I/O
uses the shared exact-handle, no-reparse, bounded atomic-replace helper. Missing
state returns `null`; malformed, copied, tampered, or cross-binding state fails
closed. The adapter never reads, writes, or deletes the Harness `.dsh` home.

This component does not create account sessions, refresh tokens, installation
identity, or device keys. The authorization coordinator owns refresh ordering and
clears uncertain refresh state before attempting a rotation.

The shared file helper does not set owner-only ACLs: it relies on the caller's
verified managed-root permissions and inherited Windows ACLs. DPAPI provides
CurrentUser encryption and origin/install/path binding; it is not protection
against the same Windows user or an administrator invoking the application.

2026-09-09: five isolated Windows tests passed using real DPAPI and file I/O.
No CNG key, product runtime, or real user data was touched. The test-owned tree
was removed and the process exited. Receipt:
`.tmp/personal-account-integration-20260909/run-03/RESULT.json` (workspace path),
SHA-256 `4b8af5c616a1cbb1153d1944418481ce71822a824df30c69ccfc259819a4ff2c`.
This is adapter evidence, not a complete desktop-login/crash-recovery acceptance.
