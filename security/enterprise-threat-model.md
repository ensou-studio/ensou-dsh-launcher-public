# Enterprise identity and managed-access threat model

This threat model covers the employee Launcher, administrator-issued activation enrollment, device authorization, company model gateway, and managed plugin delivery. It does not claim that an employee-controlled Windows administrator or a fully compromised endpoint can be made trustworthy by Launcher code alone.

## Assets

- employee authorization and the one-active-device invariant;
- device private keys, refresh families, short-lived access tokens, and signed leases;
- one-time activation grants and upstream model-provider keys;
- release, policy, and plugin signing keys;
- local conversations, Harness state, attachments, skills, and workspaces;
- plugin source/build provenance and immutable artifacts;
- audit integrity without collecting employee content.

## Trust boundaries

```text
administrator roster -> single-use activation grant -> authorization database
employee Windows account -> enterprise Launcher -> local DSH process
enterprise Launcher -> company control API / model gateway / artifact origin
private GitHub + CI -> offline/KMS signer -> immutable company artifact origin
```

TLS authenticates transport but is not the artifact trust root. Release, policy, lease, and plugin objects are verified against pinned production public keys. Provider and signing private keys remain in KMS/HSM/Vault-controlled server boundaries.

## Threats and required controls

| Threat | Required controls |
|---|---|
| Enrollment/session hijack or phishing | 120-second session, high-entropy nonce/poll secret, device-public-key binding, 32-byte single-use activation grant, DPoP nonce plus activation `ath`, and device confirmation display |
| Employee impersonation | Activation grant only from a reasoned administrator operation against an exact pre-registered employee; short TTL, one-time plaintext return, hash-only storage, single consumption, and audit |
| Device/token replay | Non-exportable CNG P-256 key, proof of possession, rotating refresh family, replay detection, one active binding, authorization epoch |
| Concurrent first binding | Database transaction plus partial unique indexes for employee and device |
| Server committed, client crashed | DPAPI exact-request/idempotency journal before POST; committed response replay precedes consumed/expiry checks; partial local credentials remain recovery-locked and are never treated as unbound; expired replay may recover refresh state but cannot authorize `Ready` before refresh |
| Unauthorized replacement | Admin-only, reasoned, expiring, old-binding-bound replacement authorization; atomic old revoke/new activate |
| Offline revocation evasion | Gateway online authorization with at most 60-second positive cache; signed 15-minute local-only offline lease; no model calls while control plane is unavailable; fail closed for unknown connectivity, clock rollback, or expiry |
| Provider-key extraction | Key only in KMS/Vault and gateway; no direct-provider fallback; process-only local proxy credential |
| Local proxy abuse, identity-header smuggling, or search-key egress | Random loopback bearer, exact query-free `POST /v1/chat/completions`, request-header allowlist limited to `Accept`/`Content-Type`, Launcher-injected access token/DPoP, forced loopback search sink with denied `/v1/messages`, and a signed locked agent preset with `tool-web` search/fetch disabled |
| GitHub/CDN/npm compromise | Employees use no GitHub/npm; pinned signing roots, immutable digest/size, expiry, monotonic generation, compatibility and rollback protection |
| Malicious or vulnerable plugin | Private reviewed source, lockfile, tests, SBOM/license/malware checks, offline signing, permission policy, staged health check, rollout rings, kill list, LKG rollback |
| Reset path traversal/data loss | Fixed enum-driven allowlist, canonical paths, no-reparse checks, protected-root deny rules, before/after fixture hashes; no caller-supplied delete path |
| Prompt/content leakage | Disable body/header/exception/request-replay logging; redact secrets before logging; metadata-only audit; no raw DSH output upload |
| Service uncertainty | Database/cache/Vault/signature/policy unknown means deny; never fall back to a cached provider key or direct upstream access |
| Compromised local administrator | Document residual risk; use BitLocker, EDR, Windows least privilege, code signing, gateway revocation, and audit; do not claim non-extractability |

## Security invariants

1. A client cannot assert its employee identity; only an administrator-issued grant tied to an exact pre-registration can create the enrollment identity fact.
2. Possession of a session or installation ID is not authorization; the single-use activation grant and exact pre-registration remain mandatory.
3. An installation ID or hardware fingerprint never authenticates a device without private-key proof.
4. No valid signed lease means no new managed Harness start.
5. No online valid gateway authorization means no model request reaches the provider.
6. No signature plus matching SHA-256/size/compatibility/monotonic generation means no runtime or plugin activation; the authorization lease also binds the exact raw root `plugin-policy.json` SHA-256, preventing same-ID/generation byte substitution on first install.
7. No employee device executes Git, npm, pnpm, FNM, or system Node as a recovery path.
8. Provider, activation, signing, refresh, access, QR, and poll secrets never enter URLs, artifacts, ordinary settings, telemetry, command lines, or logs. Raw activation codes are never persisted by the Launcher or server.
9. `MANAGED_CONFIG` and `SECURITY_CREDENTIALS` are the only destructive reset scopes. Neither can address protected user-data roots.
10. Suspension, revocation, replacement, update, rollback, reset, repair, and uninstall never delete or move conversations, Harness stores, attachments, user skills, or workspaces.
11. Every privileged admin mutation requires a reason and an append-only audit event.
12. A runtime/plugin last-known-good is retained unless it is explicitly security-revoked; a critical revocation blocks start instead of silently activating an unknown fallback.
13. A binding response cannot produce `Ready` until its pinned-key lease, exact claims, response consistency, durable commit, and memory-only access token are all installed; uncertain failure never deletes a server-committed one-device binding.
14. The DSH child receives only a random loopback model credential; no local query, Harness user/session header, arbitrary route, company access token, or upstream provider key crosses that boundary.
15. An ambiguous activation claim or unavailable poll retains only DPAPI-protected session recovery material. A restart must resume and poll the same installation/device-bound session before creating another; the activation code itself is never journaled.

## Residual privacy boundary

Conversation history remains local, but model request bodies necessarily leave the PC and transit the company gateway before the upstream provider. “Local data” therefore means no server-side conversation/workspace persistence, not that prompts never traverse company infrastructure. If the business rejects gateway transit, the alternative is a provider key on the client, which weakens revocation and extraction resistance and is not the Phase 1 design.

## Required adversarial tests

- replay an activation code/claim, poll secret, bind grant, old refresh credential, lease, and device proof;
- race two first bindings and an enrollment against replacement/revocation;
- replace the public key, installation ID, session nonce, or activation `ath` between session issue, claim, poll, and completion;
- submit an invalid, expired, consumed, or different employee's grant, or target a suspended employee, missing entitlement, or existing active device;
- simulate PostgreSQL, Redis, Vault, policy, DNS, TLS, and clock failures independently;
- tamper, truncate, downgrade, expire, or permission-escalate each signed manifest/artifact;
- attack reset paths with junctions, reparse points, `..`, case changes, aliases, and locked files;
- verify protected fixtures byte-for-byte after every denial/reset/update/rollback path;
- probe loopback query strings, alternate methods/paths, percent encoding, duplicate headers, local identity/session headers, invalid bearers, disconnect cancellation, and streaming responses;
- scan logs, crashes, traces, metrics, and audit rows for all credential and content canaries.
