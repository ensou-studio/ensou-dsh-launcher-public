# Enterprise Phase 1 architecture

> Routing decision updated 2026-09-14: [ADR 0010](../adr/0010-local-direct-model-and-browser-network.md)
> requires model and browser traffic to go directly from the employee PC, not
> through an Ensou gateway. The gateway, search-denial, server-only provider-key,
> and per-request gateway-revocation passages below describe the previous
> implementation. They are not requirements for the new direct-mode release.
> No direct-mode implementation or acceptance is claimed by this notice.

This document records the previous executable design and implementation baseline for the first employee pilot. Read it with [ADR 0004](../adr/0004-enterprise-client-and-control-plane-boundary.md), [ADR 0005](../adr/0005-enterprise-wecom-enrollment.md), and the superseding routing decision above; it is not evidence that production infrastructure or credentials already exist.

> ADR 0005 supersedes the Admin Invite-first enrollment passages below. WeCom
> schema v2 is the employee-facing path; the activation-code material remains
> applicable only to the default-disabled administrator fallback.

## Required outcome

An administrator pre-registers an employee's exact WeCom CorpID/UserID, assigns an API/plugin policy, and enables the employee for the first customer. The employee installs and opens the enterprise Launcher, scans with WeCom, confirms the displayed device name/code, and binds exactly one Windows installation. Later launches require no scan while the device credential remains valid. Administrators can suspend API access, revoke the employee, or authorize one replacement device without deleting local Harness data or workspaces. A one-time activation code may be enabled only as a separate emergency fallback.

The employee does not install Git, FNM, Node.js, pnpm, plugins, or updates. The client never reads a private GitHub repository and never receives the upstream model-provider key.

## Product and repository split

| Concern | Repository / deployment unit | Employee dependency |
|---|---|---|
| Personal and enterprise Windows client foundations | `ensou-dsh-launcher` | Enterprise EXE and Bootstrapper only |
| Identity, device policy, admin UI, model gateway | `private-management-service` | Company HTTPS API |
| Enterprise plugin source and builds | `ensou-dsh-plugins` | None directly |
| Runtime and plugin artifacts | Company object storage / CDN | Signed HTTPS manifests and packages |
| Source, review, CI, immutable release ledger | Private GitHub repositories | None |

The enterprise client is a distinct composition root, not a runtime setting in the personal EXE. The endpoint, tenant identifier, trust keys, and product flavor are signed build inputs and cannot be changed through `launcher.settings.json`.

## Current implementation checkpoint

The repository now contains a production-named enterprise WPF composition root, local device-enrollment primitives, and strict activation-session plus device-binding protocol clients. This checkpoint is intentionally fail-closed, not an employee pilot build:

- `Ensou.Dsh.Enterprise.Launcher.exe` opens the enterprise window and tray under a separate product identity;
- an ordinary unprovisioned production build starts `QrRequired`; a provisioned build hydrates only a verified committed binding and never accepts command-line, environment, settings, loopback, or development-stub trust overrides;
- the window and tray reach the local Host only through `EnterpriseHarnessSession`;
- every start, health, and WebUI operation re-evaluates the access lease before and after Host work, and a transition from allowed to denied stops the owned Harness process;
- each accepted signed lease is capped by a monotonic deadline that repeated or older snapshots and wall-clock rollback cannot extend; a background timer enforces expiry and notifies the window/tray;
- the process applies its enterprise AppUserModelID through the Windows Shell API instead of only declaring a constant;
- `--self-check` validates the initial closed state without constructing or starting a Host;
- a persistent installation ID and a signing-only CNG ECDSA P-256 key are created under the enterprise product identity; existing keys are accepted only when their export policy is exactly `None`;
- QR, binding-recovery, and refresh-recovery artifacts use CurrentUser DPAPI with artifact-specific entropy, fixed paths, bounded files, atomic writes, and parent-directory reparse checks;
- the client creates a short-lived schema v2 device-bound session with exact authorization method `WECOM` or `ADMIN_INVITE`; WeCom opens only an origin-pinned HTTPS authorization URL, while the fallback submits its one-time code only to the fixed claim route with original-nonce ES256 DPoP and activation `ath`;
- strict response schemas, bounded and user-cancellable polling, stable terminal errors, disabled redirects/cookies, a fixed fallback activation route, and authorization-origin validation keep the enrollment client fail closed;
- an `APPROVED` enrollment result requires an in-memory bind grant, distinct binding challenge, and whole-second expiry;
- the binding client signs the exact seven-line `ENSOU-DSH-BINDING-V1` payload with the non-exportable device key, uses IEEE P1363 ES256, sends challenge-bound DPoP plus an exact 32-byte idempotency key, and strictly parses the binding response and compact `ensou-dsh-lease+jwt` structure;
- production composition must give every enrollment/binding client an HTTP handler with automatic redirects disabled before any secret-bearing request is sent; the client's post-response URI check is defense in depth, not a substitute for `AllowAutoRedirect=false`;
- the composition root now continues an approved enrollment through exact-request binding completion, build-pinned ES256 verification, all 27 exact lease claims, response/local-device consistency, durable credential commit, in-memory access-token installation, and only then an exact `Ready` decision;
- before the binding POST it writes a CurrentUser-DPAPI pending transaction containing the exact serialized body and a random idempotency key; uncertain server/local failures remain locked in `Binding` and replay those exact bytes instead of creating another binding;
- authorization lease and receipt projections are hash-bound to a protected refresh-token commit marker; partial state is recovery-required, never interpreted as unbound and never automatically deleted;
- access tokens are memory-only; the current access-token expiry is used as the earlier runtime gate deadline and the token is cleared when the session can no longer call the managed API;
- a delayed committed replay is still verified and may durably recover its refresh credential after the original challenge/token/lease has expired; clean restart hydration then uses the frozen refresh endpoint to obtain current authorization;
- refresh uses an exact DPAPI journal, `Authorization: Refresh`, nonce-free DPoP with `ath`, strict HTTP `200`, pinned lease verification, marker-first atomic credential rotation, repairable projections, and access-token-memory-only `Ready` ordering;
- a gateway authorization handler enforces the exact pinned origin, query-free Phase 1 `POST /v1/chat/completions` route, live session gate, usable in-memory token, and fresh DPoP; HTTP `401` clears the token and locks the session for refresh;
- the enterprise composition root starts a native proxy on a random `127.0.0.1` port and gives DSH only its loopback `/v1` model/search URLs plus a process-random local bearer; the proxy accepts only the exact chat-completions route, forwards only `Accept`/`Content-Type`, strips Harness identity/session and arbitrary local headers, streams bodies without logging, and propagates cancellation; `DshRuntimeOptions` accepts exactly `DEEPSEEK_BASE_URL`, `DEEPSEEK_SEARCH_BASE_URL`, and `DEEPSEEK_API_KEY`, requires both URLs to be the same loopback endpoint, and overwrites inherited values;
- enterprise Host startup uses only `<entry> --profile enterprise-managed --host 127.0.0.1 --port <fixed-port>`, with no `web` alias, equals-form, duplicate, or extra argument. Its working directory is the validated `%USERPROFILE%\.dsh-enterprise\workspaces` root; inherited Node/FNM/npm/pnpm/DSH/DeepSeek/proxy/OpenSSL injection variables are removed before the exact managed environment and bundled-runtime-first Windows PATH are installed;
- production control/login/gateway/artifact origins and lease public keys are empty compile-time inputs, so an ordinary repository build remains unprovisioned and closed.

Development E2E is a separate compile-time flavor (`-p:EnterpriseDevelopmentE2E=true`), not a production runtime flag. Only that binary reads the complete public set `ENSOU_DSH_E2E_CONTROL_ORIGIN`, `ENSOU_DSH_E2E_AUTH_ORIGIN`, `ENSOU_DSH_E2E_GATEWAY_ORIGIN`, `ENSOU_DSH_E2E_ARTIFACT_ORIGIN`, `ENSOU_DSH_E2E_LEASE_KEY_ID`, `ENSOU_DSH_E2E_LEASE_KEY_X`, and `ENSOU_DSH_E2E_LEASE_KEY_Y`; it uses a distinct LocalAppData root, Harness home, AppUserModelID, mutex/event, CNG device key, DPAPI entropy identity, and port. Missing or partial E2E inputs fail closed. The production binary never reads these variables.

The reset executor now accepts only the fixed scope and artifact enums below. It checks every existing parent directory for reparse points before reading or deleting managed state, preserves installation identity and all Harness/user-data roots, and never accepts a caller-supplied path.

The administrator activation-grant fallback, PostgreSQL authorization core, refresh/gateway endpoints,
enterprise Bootstrapper/Installer, signed release-set verifier, managed runtime/plugin
contracts, and official-DSH loopback/SSE smoke are now implemented and exercised by
the isolated Development lifecycle. The production WeCom provider/callback is still
being completed. This is not yet a production employee package:
the first customer must supply its employee roster and provider credentials, production TLS,
Authenticode and release signing keys, an immutable company artifact origin, a clean
runner reproduction, server deployment evidence, and visible activation/WPF Pilot acceptance.

## Enterprise client isolation

| Item | Enterprise value |
|---|---|
| Product | `Ensou DSH Enterprise Launcher` |
| Executable | `Ensou.Dsh.Enterprise.Launcher.exe` |
| Per-user managed root | `%LOCALAPPDATA%\Ensou\DshEnterpriseLauncher` |
| Harness home | `%USERPROFILE%\.dsh-enterprise` |
| Default local workspace root | `%USERPROFILE%\.dsh-enterprise\workspaces` |
| Runtime root | `%LOCALAPPDATA%\Ensou\DshEnterpriseLauncher\runtimes` |
| Plugin cache | `%LOCALAPPDATA%\Ensou\DshEnterpriseLauncher\plugins` |
| Local WebUI port | `3081` |
| Single-instance mutex | `Local\Ensou.Dsh.EnterpriseLauncher.SingleInstance` |
| Activation event | `Local\Ensou.Dsh.EnterpriseLauncher.Activate` |
| AppUserModelID | `studio.ensou.dsh.enterprise.launcher` |
| Trust | Enterprise production release, policy, and plugin public keys |
| Network | Company control API, model gateway, and artifact origin only |

Personal and enterprise launchers may be installed on one Windows account, but they cannot concurrently own the same port or Harness home. They use separate runtime state and separate Harness homes. An optional import from `.dsh` is copy-only, validates source/destination canonical paths, and leaves the source unchanged.

The following are protected user data and are outside every update, rollback, revocation, reset, repair, and uninstall deletion scope:

- Harness conversations, sessions, stores, attachments, and user-created skills;
- the default `%USERPROFILE%\.dsh-enterprise\workspaces` tree and any workspace outside the Harness home;
- the source `.dsh` directory used by an optional migration.

The only resettable local objects are fixed, canonical, non-reparse enterprise credential/config locations owned by the Launcher and the managed `enterprise-web` profile. Reset code accepts an enum, never a caller-supplied path.

`MANAGED_CONFIG` selects only the authorization lease, API allocation cache, and plugin-policy cache. `SECURITY_CREDENTIALS` additionally selects the device-binding receipt, DPAPI refresh token, DPAPI enrollment session, DPAPI pending-binding transaction, DPAPI pending-refresh transaction, and the fixed CurrentUser CNG device-key name. Installation identity, runtimes, packages, plugins, logs, Harness home, and workspaces are outside both plans.

## First enrollment (legacy Admin Invite fallback)

The primary WeCom sequence and server-first schema rollout are defined in
[ADR 0005](../adr/0005-enterprise-wecom-enrollment.md). The sequence below is
retained for the separately enabled emergency fallback.

```text
Administrator         Launcher                  Control plane             Database
   | preregister + issue grant ------------------------>|--------------------->|
   |<-- one-time activation code -----------------------|                     |
   | deliver through approved channel ->|               |                     |
   |                            |-- create session/JWK ->|                     |
   |                            |<-- id/poll secret -----|                     |
   |                            |-- activation claim --->|-- grant + roster -->|
   |                            |<-- 204 No Content -----|                     |
   |                            |-- poll + device proof->|                     |
   |                            |<-- one-time bind grant-|                     |
   |                            |-- complete + signature --------------------->|
   |                            |<-- refresh credential + signed lease --------|
```

Rules:

1. The Launcher creates a non-exportable CNG ECDSA P-256 key before enrollment.
2. A QR session lasts 120 seconds and is bound to the installation ID, public-key thumbprint, state, nonce, and a hashed poll secret.
3. An administrator issues a 32-byte CSPRNG activation grant only for an exact active pre-registration with an entitlement and an available device slot. Plaintext is returned once; only its hash is stored.
4. The employee pastes the code into the Launcher's masked field. The UI may trim surrounding paste whitespace once, then requires the canonical 43-character unpadded base64url form and clears the field before network work begins.
5. `POST /v1/auth/activation/claim` sends the code only in the strict three-field JSON body. A fresh device DPoP proof carries the original session nonce and `ath=base64url(SHA-256(ASCII(raw activation_code)))`; the code is never placed in a URL, log, environment file, or persisted enrollment record.
6. The server atomically verifies and consumes the grant against the pre-registered employee, session, device proof, entitlement, and device slot. Success is exactly empty HTTP `204`; the Launcher then continues the existing poll/bind flow. The legacy `CALLBACK_VERIFIED` state name remains an internal v1 compatibility detail.
7. The Launcher DPAPI-protects the session recovery material before claim, never the activation code. An ambiguous claim result or poll outage retains that exact journal, and the next attempt for the same installation/device resumes and polls it before any new session is created.
8. A bind grant lasts 60 seconds, is single-use, and is redeemable only with a signature from the enrolled device key.
9. A database transaction and partial unique constraints ensure at most one active binding for an employee and for a device.
10. The activation input, request URL, enrollment persistence, and Launcher logs never contain a refresh credential, employee model token, activation code, upstream model key, or raw confirmation code outside its intended masked/display surface.

WeCom schema v2 now supersedes this Admin Invite-first sequence for employees.
The `qr_sessions` route/storage names remain for compatibility; schema v1 is
interpreted as `ADMIN_INVITE`, while schema v2 explicitly carries `WECOM` or
`ADMIN_INVITE`. A v2 Launcher must not be distributed before the compatible
server, migration, provider/callback, and customer tenant configuration are live.

## State machines

### Employee

```text
PRE_REGISTERED -> ACTIVE <-> SUSPENDED
       |            |            |
       +------------+------------+-> REVOKED (terminal)
```

- `PRE_REGISTERED`: an exact company-roster employee and entitlement exist; no device is bound.
- `SUSPENDED`: temporary admin action; no lease, start, refresh, or model request is allowed.
- `REVOKED`: terminal record. Re-admission creates a new employee authorization record.

### QR session

```text
ISSUED -> CALLBACK_VERIFIED -> ELIGIBILITY_VERIFIED -> APPROVED -> CONSUMED
   +-----------> EXPIRED / CANCELLED / DENIED_* (terminal)
```

`DENIED_*` includes not pre-registered, employee suspended, employee revoked, non-member identity, missing entitlement, already bound, and explicit user rejection of the displayed device confirmation.

### Device binding

```text
PENDING -> ACTIVE -> REVOKED_REPLACED / REVOKED_ADMIN /
                     REVOKED_EMPLOYEE / QUARANTINED_COMPROMISE
```

All revoked/quarantined states are terminal. Reinstalling Windows or losing the CNG key is a new device and requires an administrator replacement authorization.

### Client authorization

```text
UNINITIALIZED -> QR_REQUIRED -> BINDING -> READY
                                      READY -> OFFLINE_GRACE -> LEASE_EXPIRED_LOCKED
                                      READY -> ACCOUNT_LOCKED
                                      READY -> DEVICE_REVOKED_RESET_REQUIRED
                                      READY -> API_DISABLED
                                      READY -> UPDATE_REQUIRED
                                      READY -> SECURITY_QUARANTINED
```

`READY`, or explicit `OFFLINE_GRACE` with an unexpired valid signed lease, can start a managed Harness process. A lease lasts 15 minutes and is refreshed every 60 seconds with jitter. If the control plane is confirmed unavailable, the already-issued lease is the entire offline grace: local Harness/history may open, but managed model API calls are denied. Unknown connectivity, an untrusted/rolled-back clock, or lease expiry fails closed. After expiry the Launcher stops its managed Harness process. It does not delete local data.

### API allocation

```text
UNASSIGNED -> ACTIVE <-> SUSPENDED
                    \-> REVOKED
```

Suspension or provider-key rotation causes `MANAGED_CONFIG`: stop managed DSH and clear only cached API/policy material. The device binding remains, so reactivation resumes without another activation code. Employee/device revocation or refresh-token reuse causes `SECURITY_CREDENTIALS`: revoke and remove enterprise credentials and require an authorized enrollment. Both scopes exclude user data.

## Credential and revocation timing

| Object | Lifetime / check |
|---|---|
| Administrator activation grant | Short-lived and single-use; exact expiry belongs to the issued grant |
| QR session | 120 seconds |
| Bind grant | 60 seconds, one use |
| Gateway access token | 10 minutes, proof-of-possession bound |
| Client bootstrap lease | 15 minutes, signed, refresh every 60 seconds |
| Refresh family | Rotate every use; 180-day inactivity and 365-day absolute expiry |
| Gateway authorization cache | At most 60 seconds; unknown state denies |
| Replacement authorization | 10 minutes, one use, bound to old binding and employee |

The gateway checks employee, device binding, allocation, authorization epochs, and quota on every model request, with a maximum 60-second positive cache. Consequently model access revocation takes effect within 60 seconds under normal service availability. A disconnected local process may remain visible only until its 15-minute lease expires; the company model gateway is unavailable while disconnected.

## Device replacement

There is no self-service replacement in Phase 1. An administrator issues a reasoned, 10-minute one-time replacement authorization bound to the employee and old binding. Completion takes row locks and performs one transaction:

1. verify the replacement authorization and new-device proof;
2. revoke the old binding, refresh family, access tokens, and leases;
3. increment `auth_epoch`;
4. activate the new binding;
5. consume the replacement authorization;
6. append an audit event.

Any failure rolls back the whole transaction. The old machine keeps its Harness home and workspaces, but cannot obtain a lease or call the gateway.

## Model gateway

The control plane owns the upstream API profile and secret reference. The secret is resolved inside the gateway from KMS/Vault and is never returned by an API. The Launcher-owned loopback model proxy obtains short-lived device-bound authorization and supplies DSH a process-only local secret.

Phase 1 exposes only query-free `POST /v1/chat/completions`; streaming is selected in the JSON body. Web Search is disabled in two layers: the Launcher forces its separate endpoint to the loopback proxy where `/v1/messages` is denied, and the signed enterprise distribution owns the allowed agent preset with `tool-web` `search: false` and `fetch: false`. The pinned rc.2 Web preset is outside ordinary profile-patch semantics, so a two-line profile patch alone is not a sufficient control and employee-selected presets remain forbidden. An official-runtime E2E must prove the local bearer and query never reach a public endpoint before employee release.

Prompts and model responses transit this proxy and the gateway, as they must transit a model endpoint, but body logging, tracing capture, exception dumping, and request replay are disabled. Operational records may contain request ID, employee/device opaque IDs, provider/model, token counts, latency, status, and quota consumption; they may not contain message bodies, headers, file contents, conversation IDs, or workspace paths.

If the gateway, database, revocation cache, or Vault cannot determine authorization, it returns a retryable failure and never instructs the client to bypass the gateway or use a cached provider key.

## Managed plugins

Phase 1 supports one administrator-selected policy, not a marketplace. A plugin release manifest contains:

- plugin ID and semantic version;
- immutable artifact URL, byte size, SHA-256, signing key ID, and signature;
- source commit and SBOM reference;
- DSH runtime range and minimum Launcher version;
- declared permissions;
- monotonic generation, expiry, rollout ring, and revocation state.

The pack contains an offline dependency closure and a complete managed `enterprise-managed` DSH profile. The Launcher stages it, verifies signature/hash/compatibility/permissions, performs an atomic profile-generation switch, boots a health check, and retains the last-known-good generation. It never executes `git`, `npm`, `pnpm`, or FNM as a network fallback on an employee machine.

For the pinned rc.2 runtime, the pack also owns the only permitted agent preset. Its preset entry keeps `@deepseek-ai/dsh-tool-web` present only with both `search: false` and `fetch: false`, or removes the entry completely. A profile-level `disabled: true` overlay does not by itself remove the Web preset's model-facing tool schema.

Plugin source requires private-repository review, locked dependencies, tests, license/SBOM checks, malware scanning, immutable build output, offline signing, Lab/Pilot/Stable promotion of identical bytes, and a signed kill list. A revoked critical plugin blocks a new Harness start until a safe generation is active.

## Durable data model

The initial PostgreSQL schema contains:

- `employees`: unique company-scoped administrator-roster identity, status, authorization epochs, and audit ownership;
- `activation_grants`: employee binding, expiry, one-time hash, status, approver, reason, and consumption audit reference;
- `employee_entitlements`: one current API profile, plugin policy, channel, quota policy, and validity window;
- `devices`: unique installation ID and public-key thumbprint; fingerprint is risk metadata only;
- `device_bindings`: partial unique active employee and active device constraints;
- `replacement_authorizations`: old binding, expiry, approver, reason, and consumed binding;
- `qr_sessions`: hashes of poll/state/nonce secrets, device binding fields, TTL, status, and denial code;
- `refresh_token_families`: only token hashes, rotation sequence, status, and reuse evidence;
- `api_profiles` and `api_allocations`: secret reference, version/revocation epoch, quota, and assignment;
- `plugin_releases` and `plugin_policies`: immutable digest/signature/compatibility and desired generation;
- append-only `audit_events`: actor, action, target, reason, request ID, and before/after hashes, without secrets or content.

Redis is not a durable authorization source. Losing Redis must not create access; the service rebuilds positive cache only from PostgreSQL and otherwise denies until the durable state is known.

## Failure behavior

- An update or plugin verification failure keeps the last-known-good runtime/profile.
- A control-plane outage never causes GitHub/npm fallback or direct provider access.
- An unknown signature key, expired lease, epoch mismatch, backward clock anomaly, or required incompatible update blocks a new start.
- Explicit control-plane unavailability permits only local offline grace under the remaining signed lease; unknown connectivity permits neither start nor model calls.
- An API suspension does not invalidate the device binding.
- A security revocation does not delete local user data.
- A server restart can resume or expire QR sessions without issuing two bindings.
- All mutation APIs require an idempotency key and write one correlated audit result.

## Phase 1 release gates

1. An invalid, expired, consumed, or unregistered activation attempt receives `ENROLLMENT_ACTIVATION_INVALID` and the support contact; no employee, device, binding, or credential is created.
2. A registered employee creates exactly one active binding; the activation code, session, and bind grant cannot be replayed or used by another key.
3. Two concurrent enrollments for one employee produce one success and one `DEVICE_ALREADY_BOUND` result at the database constraint.
4. Replacement without admin authorization fails; authorized replacement atomically disables every old credential before activating the new binding.
5. Refresh-token reuse revokes the family and enters security reset without changing byte hashes under protected data/workspace fixtures.
6. API suspension stops model access within 60 seconds, keeps the binding and protected data, and resumes without another activation code after reactivation.
7. Database, Redis authorization cache, Vault, signature, or policy uncertainty fails closed.
8. Tampered, expired, downgraded, incompatible, or over-permission runtime/plugin artifacts are rejected and last-known-good remains active.
9. Reset path tests include junctions/reparse points, `..`, case variants, and hidden files; path escape is rejected.
10. Logs and audit records are scanned for activation/access/refresh/provider keys, QR secrets, request bodies, prompts, responses, file contents, and workspace paths.
11. Employee machines never execute Git, npm, pnpm, FNM, or system Node as an update/plugin fallback.

## Inputs needed before an employee pilot

- administrator roster ownership, activation-grant issuance/distribution procedure, approver roles, and support contact;
- company HTTPS domains for control API, gateway, and artifact delivery;
- production Windows code-signing plus release/policy/plugin signing keys and custody process;
- model API credential in KMS/Vault and the initial employee quota/API profile;
- support display name and contact channel used by stable client error messages.
