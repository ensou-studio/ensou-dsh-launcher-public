# ADR 0005: WeCom-first enterprise enrollment

- Status: Accepted; production provider rollout incomplete
- Date: 2026-08-29
- Supersedes: the Admin Invite-first enrollment portion of [ADR 0004](0004-enterprise-client-and-control-plane-boundary.md)

## Context

The first customer wants an employee to install the Windows Launcher, scan with
their company WeCom account, and use DSH only when that exact employee has been
pre-registered and assigned an entitlement. DeepSeek Harness, conversations,
and workspaces remain local. The customer does not require a business UI in the
WeCom workbench, but the control plane still needs a customer-owned WeCom
self-built application for OAuth identity, callback-domain configuration,
visibility, and trusted-server IP configuration.

The existing strict enrollment request is schema v1 and supports only an
administrator-issued one-time activation code. Unknown v1 fields are rejected,
so adding a method field to v1 would break deployed clients and servers.

## Decision

WeCom is the employee-facing default. Admin Invite remains a separately
authorized emergency fallback and is disabled by default for the first
customer. Each enrollment session has exactly one immutable authorization
method: `WECOM` or `ADMIN_INVITE`. One method cannot claim a session created for
the other method.

The rollout is server-first:

1. Schema v1 create requests keep their exact original field set and are
   interpreted as `ADMIN_INVITE`.
2. Schema v2 create requests add the required exact field
   `authorization_method`, whose value is `WECOM` or `ADMIN_INVITE`.
3. The server accepts a method only when its production allowlist enables that
   method. The Example first-customer profile enables `WECOM`; fallback remains
   off until an administrator explicitly enables it.
4. Only after a server version accepting v1 and v2 is deployed may a v2 Launcher
   be distributed.

## WeCom flow

1. The Launcher creates a 120-second schema v2 `WECOM` session bound to its
   installation ID, non-exportable P-256 device key, DPoP nonce, and device
   display name.
2. The server creates a 32-byte CSPRNG OAuth state. Its canonical unpadded
   base64url form is 43 characters; only its SHA-256 is stored. State is unique,
   one-time, and cannot outlive the session.
3. The server returns a pinned-origin HTTPS authorization URL for WeCom's
   `qrConnect` surface. The Launcher opens it through the Windows system browser
   and continues device-bound polling. No `cmd.exe` window is created.
4. The callback exchanges the authorization code on the Ubuntu control plane.
   It accepts only the configured CorpID and a non-empty internal `userid`.
   `openid`, external identity, display name, email, or phone number never
   create or match an employee dynamically.
5. The callback does not approve or bind a device. It presents the exact device
   display name and six-character confirmation code. A same-origin, one-time
   confirmation advances the session only after the exact `(CorpID, UserID)`
   pre-registration, entitlement, API policy, and complete device history have
   passed.
6. Polling returns a one-time bind grant and binding challenge. Existing
   device-signature, DPoP, refresh rotation, signed lease, and one-device rules
   remain unchanged.

The WeCom ApplicationSecret and provider access token are root-owned server
secrets. They never enter the Launcher, release manifest, logs, command line,
ordinary setup JSON, or employee DSH process. The callback path must log only a
normalized path without query parameters and return `no-store`, `no-referrer`,
and restrictive CSP headers.

## Local recovery

The DPAPI enrollment journal schema v2 stores the exact authorization method;
legacy journal schema v1 is interpreted as `ADMIN_INVITE`. The journal contains
session recovery material but no activation code, WeCom code, OAuth state,
provider token, or employee identity.

- Retrying the same method resumes the exact session before creating another.
- Switching methods while a live session exists fails visibly and preserves the
  journal. It never silently discards an ambiguously committed activation.
- A canonical expired journal is deleted before method-conflict evaluation, so
  an old v1 session cannot permanently block WeCom.
- “Stop waiting” cancels local polling and preserves the live journal. It does
  not claim to revoke the server session.
- Authoritative terminal state or local expiry removes the journal. User data,
  Harness history, and workspaces are outside every reset path.

## Consequences

- A customer must provide CorpID, AgentID, ApplicationSecret, callback origin,
  application visibility, and trusted-server IP during server initialization.
- The Launcher may show WeCom as the primary action while keeping the emergency
  activation control under an administrator-only expander.
- A Launcher-only build is not an employee pilot. Production requires the v2
  server contract, provider/callback implementation, migration 009, exact roster
  pre-registration, HTTPS/TLS, Authenticode and manifest signing, and a real
  customer-tenant end-to-end test.
