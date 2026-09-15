# ADR 0004: Enterprise client, control-plane, and plugin-supply boundary

- Status: Partially superseded; enrollment by [ADR 0005](0005-enterprise-wecom-enrollment.md), model/browser routing and provider-key control by [ADR 0010](0010-local-direct-model-and-browser-network.md)
- Date: 2026-08-24

> The gateway and server-only provider-key passages below describe the previous
> design and existing implementation, not the current delivery target. ADR 0010
> requires direct model and browser access from the employee PC. Direct-mode
> implementation and release acceptance remain outstanding.

## Context

The personal Launcher is a working local baseline. The enterprise edition adds employee enrollment, one-person/one-device authorization, centrally revocable model access, and managed plugins for employees who should not need Git, Node.js, FNM, pnpm, or a command line.

DeepSeek Harness still runs on each employee's Windows account. Conversations, Harness state, and workspaces remain local. Enterprise administration must therefore control access and distribution without treating local user data as remotely managed cache.

## Decision

Keep this repository as the shared Windows client and release foundation. Do not fork or copy the personal Launcher. Add an independent enterprise composition root with separate product identity and state, while reusing the reviewed Host, update engine, immutable-runtime, Bootstrapper, tray, and release-signature components.

Create two private repositories outside this client repository:

- `private-management-service` for administrator-issued activation grants, employee/device authorization, the admin UI, model gateway, audit, and policy APIs;
- `ensou-dsh-plugins` for reviewed plugin source, locks, tests, and immutable plugin-pack production.

Employees never clone any of these repositories. GitHub remains the source/review/build authority. Enterprise Launchers download signed immutable artifacts from a company-controlled HTTPS origin that is reachable from employee networks.

```text
Administrator --> pre-register employee + issue one-time activation code
                         |
                         v
Enterprise Launcher --> Control Plane ------> signed lease/policy
        |                   |                            |
        |                   | poll + device proof        v
        +--> local DSH --> local model proxy --> company LLM gateway
        |                   |                                           |
        |                   +--> local conversations/workspaces         v
        +--> signed runtime/plugin origin                         upstream model API
```

The first binding flow is administrator-invite activation. The Launcher creates a short-lived enrollment session bound to a device public key, submits the administrator-issued one-time activation code to `POST /v1/auth/activation/claim`, and polls the control plane. The code is canonical unpadded base64url for 32 random bytes and appears only in the masked WPF input, request memory, and JSON request body. The server independently verifies the pre-registration, unconsumed activation grant, device proof, and single-active-device constraint. No browser or external identity-provider callback is required.

The enterprise client has its own executable, AppUserModelID, mutex/event names, Bootstrapper state, installation identity, LocalAppData root, update feed, production trust keys, caches, logs, and managed-plugin directory. Production builds do not honor development runtime/key overrides. The enterprise Harness home defaults to `%USERPROFILE%\.dsh-enterprise`; importing an existing `%USERPROFILE%\.dsh` is a separate, copy-only, verified migration and never removes the source.

The control plane is a modular monolith for Phase 1. PostgreSQL is the durable identity/device/policy store; Redis may hold short-lived enrollment, revocation-cache, and rate-limit state; KMS/Vault holds upstream model credentials; object storage/CDN serves signed artifacts. Unknown identity, policy, signing, database, cache, or secret state fails closed.

An explicitly detected control-plane outage is distinct from unknown state. While a previously verified signed lease remains valid, the Launcher may open local Harness/history in offline-grace mode but must deny managed model API calls. Unknown connectivity, clock rollback, or lease expiry permits neither. The lease is the maximum offline window.

The Launcher generates a non-exportable ECDSA P-256 device key through Windows CNG under the current user. Installation identifiers and hardware fingerprints are risk signals, never credentials. Access tokens are short lived, refresh credentials rotate and are proof-of-possession bound, and an access lease is required before starting the managed Harness process.

Model-provider keys never reach the employee computer. A Launcher-owned loopback proxy gives the DSH child a process-scoped local credential, refreshes device-bound access to the company gateway, and never logs request bodies. Prompts necessarily transit the gateway on their way to the model, but the gateway stores neither prompt/response bodies nor conversation history.

Revocation has explicit scopes:

- `MANAGED_CONFIG` clears cached API/policy state and stops managed DSH; reactivation on the same device needs no new activation code.
- `SECURITY_CREDENTIALS` clears enterprise access/refresh material and the enterprise device key, then requires a new authorized enrollment.
- neither scope may delete, move, overwrite, or recursively traverse the enterprise Harness home or any workspace.

One employee has at most one active device binding, enforced by a database unique constraint. Device replacement is admin-only: one transaction revokes the old binding, refresh family, and leases, increments the authorization epoch, consumes a short-lived replacement authorization, and activates the new binding. The old computer retains its local data but loses managed access.

Runtime, Launcher, and plugin packs use separate signed manifests and independent versions. Plugin installation is allowlist-only and uses immutable, signed, SHA-256-addressed packs with runtime compatibility, required permissions, monotonic generation, staged activation, last-known-good rollback, and a kill list. Employees receive no arbitrary npm, URL, or GitHub installation surface.

## Phase 1 scope

Phase 1 includes pre-registration, administrator-issued one-time activation, first device binding, a single active device, admin suspension/revocation/replacement authorization, a company model gateway, one fixed managed plugin policy, signed artifact delivery, and a minimal audit trail.

Phase 1 excludes self-service device replacement, multiple active devices, a plugin marketplace, chat synchronization, employee behavior analytics, MDM/SYSTEM execution, and replacing the local Launcher with any web workbench.

## Consequences

- The personal edition remains usable and has no enterprise-service dependency.
- Enterprise identity and distribution can evolve without duplicating the reviewed local runtime manager.
- Revocation is reliable for company API access, but cannot make already-local files inaccessible; endpoint security and Windows account controls remain separate responsibilities.
- Four deployment inputs are required before an employee pilot: a production control-plane HTTPS origin with administrator activation-grant operations, a company HTTPS artifact origin, production code/manifest signing, and a model-provider credential held by the gateway.

## Enrollment decision superseded

[ADR 0005](0005-enterprise-wecom-enrollment.md) replaces the Admin Invite-first
decision above with WeCom-first schema v2 enrollment. The activation-grant flow
remains a separately authorized, default-disabled emergency fallback. The
repository, local-data, one-device, signing, and plugin-supply boundaries in
this ADR remain in force. ADR 0010 separately supersedes the gateway and
server-only provider-key requirements; management revocation must not be
described as provider-side API Key revocation in the direct topology.
