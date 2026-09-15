# Enterprise control API enrollment v1/v2

This document describes the Launcher-facing and administrator-facing HTTP boundary. The server-owned machine-readable contract lives in the separate private `private-management-service` repository. Schema v1 enrollment remains frozen for installed Admin Invite clients; schema v2 adds the explicit `WECOM` / `ADMIN_INVITE` authorization method for the server-first migration defined by [ADR 0005](../adr/0005-enterprise-wecom-enrollment.md). A route is not live merely because it is documented.

## Common rules

- Base path: `/v1`.
- Each strict enrollment schema uses non-zero lowercase UUID D strings and exact uppercase-`Z`, whole-second UTC timestamps. Unknown JSON properties are rejected; a v1 request may not carry v2 fields.
- Mutating requests require `Idempotency-Key`, exactly the canonical unpadded base64url encoding of 32 CSPRNG bytes (43 characters), except the one-time activation claim defined below. The server scopes an idempotency key to the authenticated principal and operation and fingerprints SHA-256 of the exact JSON body bytes. Volatile headers such as DPoP and request IDs are excluded, while every retry still requires a fresh verified DPoP proof with a unique `jti`; reusing a key with different body bytes returns `409 IDEMPOTENCY_KEY_REUSED`.
- Every response carries `X-Request-ID`; every mutation writes an append-only correlated audit event.
- Secrets are accepted only in headers or bodies and are redacted before logging. They never appear in a URL, process argument, artifact, ordinary setting, telemetry, or persistent client state.
- Access and refresh credentials are proof-of-possession bound to the enrolled device key.
- Client and gateway authorization fail closed when employee, device, allocation, epoch, lease, or secret state cannot be determined.

Error response:

```json
{
  "error": {
    "code": "ENROLLMENT_ACTIVATION_INVALID",
    "message": "一次性激活码无效、已过期或已使用，请联系 IT 管理员。",
    "client_state": "QR_REQUIRED",
    "retryable": false,
    "contact_display": "IT 管理员",
    "request_id": "01J...",
    "reset_scope": "NONE"
  }
}
```

`reset_scope` is exactly `NONE`, `MANAGED_CONFIG`, or `SECURITY_CREDENTIALS`. A server must never instruct a client to delete or mutate user data.

## Enrollment and device sessions

### `POST /v1/auth/qr-sessions`

Creates a 120-second enrollment session. The compatible server must be deployed
before any schema v2 Launcher.

Schema v1 request fields remain exactly `schema_version`, `install_id`, public
P-256 `device_jwk`, `device_key_thumbprint`, canonical `device_display_name`,
`launcher_version`, `runtime_version`, `platform`, and client `nonce`; the server
interprets that exact legacy shape as `ADMIN_INVITE`. Schema v2 contains the same
fields plus the required exact `authorization_method`, whose value is `WECOM` or
`ADMIN_INVITE`. The selected method is immutable and must be enabled by server
policy. The public key and thumbprint must agree. The device name is NFC, trims
and collapses Unicode whitespace, rejects control/format/surrogate/private-use/
line/paragraph-separator runes, and is limited to 1 through 64 runes and 80
UTF-16 code units.

Response fields: `session_id`, `poll_secret`, company `authorization_url`, exact
echoed `device_display_name`, six-character `confirmation_code`, `expires_at`,
and `poll_after_seconds` (2 through 15). The confirmation code uses only
`23456789ABCDEFGHJKLMNPQRSTUVWXYZ`; the Launcher displays it but never logs it.
The poll secret is reusable only for that session's polls until a terminal result
or expiry; it is not rotated per poll. For a `WECOM` session, the Launcher opens
the origin-pinned HTTPS authorization URL in the Windows system browser. An
`ADMIN_INVITE` session never opens that URL and instead uses the claim route.

### `GET /v1/auth/qr-sessions/{session_id}`

Requires `Authorization: QR-Poll <poll_secret>` and a device proof header. Returns one of:

The device proof is an ES256 DPoP JWT with embedded public JWK and exact
`htm`, canonical absolute `htu`, UTC `iat`, unique `jti`, and the QR session
`nonce`. Poll proofs also contain `ath`, the base64url SHA-256 of the raw poll
secret. Redirects are not followed.

- `ISSUED`, `CALLBACK_VERIFIED`, or `ELIGIBILITY_VERIFIED` with next poll interval;
- `APPROVED` with distinct 32-byte canonical base64url `bind_grant` and `binding_challenge` values plus `binding_challenge_expires_at`; the grant and challenge are single-use and expire together within 60 seconds;
- a terminal status and stable error. Every valid business terminal result remains HTTP `200`; non-200 responses are reserved for protocol, authentication, rate-limit, and availability failures.

The frozen terminal mapping is exact:

| Status | `error.code` | `client_state` | `retryable` |
|---|---|---|---|
| `CONSUMED` | `QR_SESSION_CONSUMED` | `QR_REQUIRED` | `false` |
| `EXPIRED` | `QR_SESSION_EXPIRED` | `QR_REQUIRED` | `true` |
| `CANCELLED` | `QR_SESSION_CANCELLED` | `QR_REQUIRED` | `true` |
| `DENIED_NOT_PREREGISTERED` | `WECOM_IDENTITY_NOT_PREREGISTERED` for `WECOM`; `ENROLLMENT_ACTIVATION_INVALID` for `ADMIN_INVITE` | `QR_REQUIRED` | `false` |
| `DENIED_EMPLOYEE_SUSPENDED` | `EMPLOYEE_SUSPENDED` | `ACCOUNT_LOCKED` | `false` |
| `DENIED_EMPLOYEE_REVOKED` | `EMPLOYEE_REVOKED` | `ACCOUNT_LOCKED` | `false` |
| `DENIED_ALREADY_BOUND` | `DEVICE_ALREADY_BOUND` | `QR_REQUIRED` | `false` |
| `DENIED_ENTERPRISE_MEMBER_REQUIRED` | `WECOM_ENTERPRISE_MEMBER_REQUIRED` for `WECOM`; frozen v1 `ENROLLMENT_ACTIVATION_INVALID` for `ADMIN_INVITE` | `QR_REQUIRED` | `false` |
| `DENIED_ENTITLEMENT_MISSING` | `EMPLOYEE_ENTITLEMENT_MISSING` | `QR_REQUIRED` | `false` |
| `DENIED_USER_REJECTED` | `DEVICE_CONFIRMATION_REJECTED` | `QR_REQUIRED` | `true` |

For these unauthenticated enrollment errors, `reset_scope` is always `NONE`.

### WeCom callback and device confirmation

The production control plane owns the WeCom code exchange and never sends the
ApplicationSecret, provider token, OAuth code, or raw state to the Launcher. It
generates a 32-byte random state (43 canonical base64url characters), stores only
its SHA-256, and accepts it once before the 120-second session expiry.

`GET /v1/auth/wecom/callback?code=...&state=...` resolves the session by state
hash, exchanges the code server-side, and accepts only the configured CorpID plus
a non-empty internal WeCom UserID. It does not auto-create or approve an
employee. The returned HTML is `no-store` and `no-referrer`, uses a restrictive
CSP, and displays only the device name and confirmation code.

`POST /v1/auth/wecom/device-confirmation` is same-origin and one-time. It
confirms or rejects the displayed device, then performs exact WeCom
pre-registration, entitlement, API/policy, and complete device-history checks.
Only a confirmed eligible session may advance to the existing poll/bind flow.
Callback query strings and provider secrets are forbidden from access logs.

### `POST /v1/auth/activation/claim`

Claims an administrator-issued one-time activation grant for the already-created session. The exact JSON object has three fields and rejects additions, duplicates, alternate casing, and coercion:

```json
{
  "schema_version": 1,
  "session_id": "01234567-89ab-cdef-0123-456789abcdef",
  "activation_code": "oKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr8"
}
```

`activation_code` is the canonical unpadded base64url encoding of exactly 32 CSPRNG bytes: 43 characters from `[A-Za-z0-9_-]`, with no trimming, case conversion, padding, grouping, or alternate representation at the protocol boundary. The WPF input may trim surrounding paste whitespace once before validation. The code exists only in the masked input, transient process/request memory, and this JSON body. It is forbidden in URLs, headers, logs, exceptions, evidence, command lines, environment files, DPAPI enrollment sessions, database plaintext, or any other persistence.

The request uses the same device key and original session nonce in a fresh ES256 DPoP proof. It additionally carries `ath=base64url(SHA-256(ASCII(raw activation_code)))`. Success is exactly HTTP `204 No Content`, with no `Content-Type` and zero response bytes. Alternate success statuses or any response body are rejected. The server atomically verifies the grant, pre-registered employee, unbound device slot, session, nonce, and device proof, then consumes or advances the grant without returning a credential. The Launcher continues the existing poll/bind flow.

Before the claim, the Launcher DPAPI-protects the session identifier, poll secret, nonce, expiry, installation ID, and device-key thumbprint, but never the activation code. If the claim request has a provable network failure after it may have reached the server, the Launcher first polls the same session. `CALLBACK_VERIFIED`, `ELIGIBILITY_VERIFIED`, `APPROVED`, or an authoritative terminal result resumes the existing flow; a still-`ISSUED` session does not prove acceptance and the network error is surfaced. A poll outage or ambiguous timeout retains this journal. On the next activation attempt for the same installation and device key, the Launcher resumes and polls that exact session before creating another one; if it is still `ISSUED`, the newly entered code is claimed against the original session. Authoritative terminal state or local expiry deletes the journal. Business denial, malformed response, and caller cancellation never create a new recovery path.

The journal schema v2 also stores the exact authorization method. A legacy v1
journal is `ADMIN_INVITE`. A live cross-method retry is rejected without deleting
the journal; a canonical expired journal is deleted before method-conflict
evaluation. Stopping local polling preserves the session and never claims to
cancel it on the server.

### `POST /v1/device-bindings/complete`

Requires `Idempotency-Key` and challenge-bound DPoP. DPoP uses `nonce=<binding_challenge>` and `ath=base64url(SHA-256(ASCII(raw bind_grant)))`.

The strict request fields are `schema_version`, `binding_payload_version`, `bind_grant`, `session_id`, `install_id`, `device_key_thumbprint`, `device_label`, `binding_challenge`, `binding_challenge_expires_at`, and `device_signature`. The device signature is ES256 over the exact seven-line `ENSOU-DSH-BINDING-V1` payload, encoded as the canonical unpadded base64url of the 64-byte IEEE P1363 `r||s` value; DER signatures are rejected. A transaction rechecks employee/entitlement/device eligibility and the unique active-binding constraints.

The strict response fields are `schema_version`, `binding_id`, `refresh_token`, `access_token`, `access_token_expires_at`, `authorization_lease`, `lease_expires_at`, and `server_time`. The authorization lease is a compact ES256 JWS with exact `typ=ensou-dsh-lease+jwt`; its payload binds the employee, binding, and installation identities, raw authorization states and epochs, assigned policy versions, allowed HTTPS origins, and a maximum 15-minute lifetime. Its `plugin_policy_sha256` is the lowercase SHA-256 of the root `plugin-policy.json` raw UTF-8 bytes, not the policy ZIP, so a newly installed client cannot accept different policy bytes under the same ID and generation. The access token lasts at most 10 minutes and cannot outlive that lease. The upstream model key is never a response field.

Before the first POST, the Launcher DPAPI-protects a random idempotency key and the exact serialized request bytes, including the original randomized device signature. If the server may have committed but local verification or persistence fails, the client remains in binding recovery and replays only those exact bytes and key with a fresh DPoP proof. The server-side contract must replay the encrypted committed `201` before rechecking consumed/expired QR, grant, or challenge state, and must retain that replay for at least seven days. A replay whose original access token or lease is no longer current may restore the verified refresh credential, but it remains recovery-locked until a refresh succeeds; an expired replay never produces `Ready`. Access tokens are never written to this journal or any other file.

### `POST /v1/auth/refresh`

Success is exactly HTTP `200`. The request uses `Authorization: Refresh <raw refresh token>`, plus a fresh ES256 DPoP proof whose embedded JWK is the bound device key. The DPoP payload contains exact `htm`, `htu`, whole-second `iat`, a unique `jti`, and `ath=base64url(SHA-256(ASCII(raw refresh token)))`; refresh proofs do not contain a nonce. Redirects, cookies, ambient credentials, and alternate success statuses are rejected.

The exact JSON request has seven fields and no extensions:

```json
{
  "schema_version": 1,
  "binding_id": "22222222-2222-4222-8222-222222222222",
  "install_id": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
  "previous_lease_id": "bbbbbbbb-0000-4000-8000-000000000001",
  "auth_epoch": 1,
  "entitlement_epoch": 1,
  "binding_epoch": 1
}
```

The three request epochs are consistency/audit evidence only; the server derives authorization from its own current records. The strict response reuses the eight device-binding completion fields: `schema_version`, `binding_id`, rotated `refresh_token`, memory-only `access_token`, `access_token_expires_at`, pinned signed `authorization_lease`, `lease_expires_at`, and `server_time`.

Before sending, the Launcher CurrentUser-DPAPI protects the exact body bytes and a canonical 32-byte random `Idempotency-Key`. A retry uses the same old refresh credential, key, and exact body, but a fresh DPoP proof. The server must return the exact committed `200` for that tuple before old-token-reuse checks. Reuse of the old refresh credential with another idempotency key revokes the family and returns `REFRESH_TOKEN_REUSED` with `SECURITY_CREDENTIALS`.

The client verifies the new pinned lease against `response.server_time`, identity, installation, device thumbprint, subject, origins, and non-regressing authorization epochs. It then atomically replaces the authoritative DPAPI credential before rebuilding the plaintext lease/receipt projections. Only after that durable commit and journal deletion does it install the access token in memory and apply `Ready`. A process crash therefore leaves either the old complete credential plus replay journal, or a new authoritative credential from which projections can be repaired.

### `POST /v1/auth/logout`

Revokes the current refresh family and clears local enterprise credentials. It does not revoke the device binding unless `revoke_device=true` is authorized by an administrator.

### `GET /v1/client/bootstrap`

Returns a signed policy envelope containing `binding_id`, `auth_epoch`, `entitlement_epoch`, API profile reference/version/status, minimum/desired Launcher and runtime versions, plugin-policy ID/generation/raw-policy SHA-256, rollout channel, gateway URL, artifact-origin URLs, support display, issue/expiry timestamps, and policy signing key ID. It contains no activation code or model-provider secret.

### `POST /v1/devices/heartbeat`

Accepts opaque device/binding/lease identifiers, Launcher/runtime/plugin versions, health state, and failure codes. Prompts, responses, session names, file content, workspace paths, command output, API headers, and raw DSH stdout/stderr are forbidden.

## Model gateway

The frozen Phase 1 DSH route is exactly `POST /v1/chat/completions`, with no query string. The client does not accept a `/v1/llm/*` wildcard, alternate method/path, percent-encoded path, or caller-selected gateway origin. Streaming remains a JSON body concern (`stream: true`), not a query parameter. The wider gateway route/status/provider-error contract remains server-owned and must be added explicitly in a later version rather than inferred by the Launcher.

The local proxy binds one random IPv4 `127.0.0.1` port and requires a process-random local bearer. It streams the exact allowed request to the build-pinned gateway origin through the session gate, replacing the local bearer with the current memory-only device-bound access token and a fresh ES256 DPoP proof. On the request side it forwards only `Accept` and `Content-Type`; it strips caller-controlled authorization, DPoP, Harness user/session IDs, arbitrary local headers, and hop-by-hop headers. It propagates response streaming and disconnect cancellation and never logs or durably buffers request/response bodies. DSH receives the loopback model URL, matching loopback search sink, and local bearer through the three controlled keys `DEEPSEEK_BASE_URL`, `DEEPSEEK_SEARCH_BASE_URL`, and `DEEPSEEK_API_KEY`; the company access token and upstream provider key never enter the child environment.

This proxy/Host boundary is connected in the enterprise composition root whenever the build carries a complete trusted control/gateway/artifact profile and lease key set. An ordinary repository build has no such production inputs and remains enrollment-locked. A real gateway plus official-DSH streaming E2E is still required before employee release.

Web Search is disabled in the Phase 1 enterprise profile. The Launcher overwrites even an inherited public `DEEPSEEK_SEARCH_BASE_URL` with the same loopback `/v1` URL; the search provider's appended `/messages` route is absent from both proxy and gateway allowlists and fails locally. Because the pinned rc.2 Web profile mounts `tool-web` from an agent preset tree outside ordinary profile-patch semantics, the signed enterprise distribution must also own the allowed preset, set `tool-web` `search: false` and `fetch: false`, and reject employee-selected presets. Employee release still requires an official-DSH E2E proving the process-local bearer and search query never reach a public endpoint.

## Signed update and plugin feeds

- `GET /v1/updates/launcher/{channel}`
- `GET /v1/updates/runtime/{channel}`
- `GET /v1/updates/plugins/{policy_id}`

Each feed is signed, expires, has a monotonic generation, binds immutable URLs/digests/sizes, declares minimum compatible versions, and supports explicit revocation/kill state. The artifact origin may be separate, but GitHub/npm URLs are never returned to an employee client.

## Administrator API

- `POST /v1/admin/employees`: pre-register an exact stable employee record from the administrator's trusted roster.
- `POST /v1/admin/employees/{id}/activation-grants`: issue one short-lived, single-use activation code; plaintext is returned once and only its hash is stored.
- `PUT /v1/admin/employees/{id}/entitlement`: assign API profile, plugin policy, channel, quota, and validity.
- `POST /v1/admin/employees/{id}/suspend|reactivate|revoke`: reason required.
- `POST /v1/admin/employees/{id}/replacement-authorizations`: old binding, ten-minute TTL, reason, approver; one use.
- `POST /v1/admin/devices/{id}/revoke|quarantine`: reason required.
- `POST /v1/admin/api-profiles` and `/activate|suspend|rotate|revoke`: secret accepted only into KMS/Vault.
- `POST /v1/admin/plugin-releases` and `/{id}/promote|revoke`: immutable digest/signature and reasoned promotion.
- `GET /v1/admin/audit-events`: filtered metadata only; secrets and content do not exist in the audit schema.

## Stable error registry

The QR poll terminal mappings are the HTTP `200` business results frozen above. The table below applies to non-terminal transport failures and the remaining Phase 1 APIs; it must not be used to remap a valid QR terminal poll to a non-200 response.

| HTTP | Code | Client action |
|---|---|---|
| 403 | `ENROLLMENT_ACTIVATION_INVALID` | Keep unbound; request a new administrator-issued code |
| 400 | `QR_STATE_INVALID`, `DEVICE_PROOF_INVALID` | Deny; restart enrollment if directed |
| 401 | `TOKEN_EXPIRED`, `TOKEN_REVOKED`, `LEASE_EXPIRED` | Refresh or lock |
| 401 | `REFRESH_TOKEN_REUSED` | `SECURITY_CREDENTIALS`; contact support |
| 403 | `EMPLOYEE_SUSPENDED`, `EMPLOYEE_REVOKED` | Lock; no data deletion |
| 403 | `DEVICE_REPLACEMENT_NOT_AUTHORIZED`, `DEVICE_BINDING_REVOKED` | Require administrator action |
| 403 | `API_PROFILE_UNASSIGNED`, `API_PROFILE_DISABLED` | `MANAGED_CONFIG`; keep binding |
| 403 | `PLUGIN_POLICY_DENIED` | Keep last-known-good and lock if critical |
| 409 | `DEVICE_ALREADY_BOUND`, `IDEMPOTENCY_KEY_REUSED` | Do not retry unchanged request |
| 409 | `PLUGIN_INCOMPATIBLE`, `ROLLBACK_PROTECTION_TRIGGERED` | Keep last-known-good |
| 410 | `REPLACEMENT_AUTHORIZATION_EXPIRED` | Start a new administrator-authorized replacement flow |
| 403 | `EMPLOYEE_ENTITLEMENT_MISSING` | Show configured support contact; create no binding |
| 422 | `MANIFEST_SIGNATURE_INVALID`, `ARTIFACT_HASH_MISMATCH` | Fail closed and report request ID |
| 426 | `CLIENT_UPDATE_REQUIRED`, `RUNTIME_UPDATE_REQUIRED`, `CRITICAL_PLUGIN_UPDATE_REQUIRED` | Complete signed required update first |
| 429 | `API_QUOTA_EXCEEDED`, `RATE_LIMITED` | Show quota/retry state |
| 503 | `CONTROL_PLANE_UNAVAILABLE`, `UPSTREAM_API_UNAVAILABLE`, `UPDATE_SERVICE_UNAVAILABLE` | Retry; never bypass gateway/feed |

`LEASE_SIGNATURE_INVALID`, `AUTHORIZATION_EPOCH_MISMATCH`, `CLOCK_UNTRUSTED`,
`CLOCK_ROLLBACK_DETECTED`, and `DEVICE_SECURITY_QUARANTINED` are client-local
fail-closed codes. They are not accepted from an unauthenticated QR response.

Messages are localized by the client from stable codes. `contact_display` is a signed policy value and is displayed as text, not executable markup or a URL unless it matches the signed allowed support origin.

## Database invariants

The service must enforce these in PostgreSQL, not only application code:

- unique stable employee identity defined by the administrator roster;
- at most one `ACTIVE` binding per employee and per device using partial unique indexes;
- unique installation ID and device-key thumbprint;
- terminal QR, revoked binding, consumed replacement, and rotated refresh records cannot return to active states;
- refresh, binding, authorization-epoch, replacement, and audit changes commit atomically;
- only hashes of activation, QR/poll/state/nonce/refresh secrets are stored;
- API profiles store a Vault/KMS reference, never a plaintext provider key;
- audit events are append-only and cannot contain prompt/body/header/workspace fields.
