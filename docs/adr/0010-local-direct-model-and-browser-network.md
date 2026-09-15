# ADR 0010: Local direct model and browser networking

- Status: Accepted product decision; implementation and release acceptance outstanding
- Date: 2026-09-14
- Decider: ensou, by explicit user instruction
- Follow-up confirmed: administrator-entered per-user Key delivery and continued use during management outages, 2026-09-14
- First-pilot scope amended: owner-assisted per-device DSH UI Key entry; automatic backend Key delivery deferred, 2026-09-14
- Supersedes: the model-gateway routing, provider-key confinement, and gateway-based revocation requirements in ADR 0004 and the Phase 1 architecture

## Context

The owner explicitly requires model requests and browsing to use each employee's computer and network. Ensou supplies the Launcher, DSH versions, and their upgrades, not an inference or browsing proxy. The previously implemented enterprise composition sends DSH model traffic through a local proxy to the company gateway and deliberately denies search. That implementation does not meet this decision.

This instruction changes traffic routing. The previously requested WeCom identity, administrator approval, manual per-person official DeepSeek API Key allocation, and one active managed device remain management requirements unless separately withdrawn. They must not be used to reintroduce model-traffic forwarding. The owner subsequently approved administrator entry and assignment in the backend, automatic HTTPS retrieval by Launcher, and continued direct use on already activated devices during management outages. Implementation of that protected provisioning flow is authorized; opening server ports, importing device trust certificates, or using actual credentials is not performed or implied by this record.

## Decision

Both editions use the same local provider-configuration and network behavior. Enterprise identity and administration are an additional composition, not a separate model-transport implementation.

### First-pilot amendment: administrator-assisted local Key entry

The owner explicitly accepted configuring each approved employee's distinct official Key directly through DSH's local configuration UI to accelerate the first approximately seven-person pilot. Automatic backend Key entry/delivery/rotation and the detailed professional UI are later iterations, not first-pilot release blockers. The prior sections describing automatic backend provisioning remain the subsequent target, not an assertion that this first pilot implements it.

For this pilot, Launcher must not inject a model bearer, a proxy URL, or the official Key into the DSH process environment. DSH resolves the locally configured credential from its dedicated enterprise Harness home. Keep identity/device controls, loopback WebUI authentication, managed workspace/plugin boundaries, process-environment sanitization, separate signed update identities, recovery and local-data preservation. Do not relabel an existing Personal or test artifact as Enterprise or claim the WeCom approval chain is accepted before it is actually tested.

The inspected pinned RC's native store writes `<DSH_HOME>/.credentials.yaml`; this is not the proposed Launcher DPAPI credential store. Its Windows implementation does not enforce a POSIX owner-mode check. Do not promise encrypted-at-rest or same-user/agent secrecy from that implementation; verify the installed Windows user-data access boundary. No credential file, secret value, or local `.env` may enter installers, archives, update staging, diagnostics, or source control. The administrator alone performs this first-pilot setup, so ordinary employees still need no command line or configuration-file editing.

Local credential configuration must survive Launcher-only and DSH-only updates and verified rollback without being copied into artifacts. Existing unrelated settings and credentials are not erased. When suspension is observed, stop the managed runtime and retain the deny barrier; a native DSH credential file is not proof of a Launcher-owned secret allocation and must not be indiscriminately deleted. The administrator still revokes the actual Key in DeepSeek Platform. Future backend-managed provisioning requires an explicit credential-ownership transition, not silent replacement of the locally entered Key.

First-pilot acceptance is installation, actual direct model/browsing use, automatic independent Launcher and DSH updates, and failed-update recovery with local history/workspace/credential preservation. Professional diagnostics, the full admin onboarding wizard, and backend automatic Key delivery are not required to accept that slice. Missing real update origins, signer/trust inputs, or actually required identity acceptance cannot be replaced by QA values.

### Confirmed publisher and experience baseline

The owner accepted the simulated first-use, daily-use, independent-update, management-outage, and suspension journeys on 2026-09-14 as the target experience, not evidence of implementation or release acceptance.

The shared [simple default and optional detailed UI contract](../ui/shared-launcher-experience.md) records the owner's requirement that ordinary users can operate the product while professional users can inspect its actual state. This is progressive disclosure over the same state and authority, not separate beginner/professional runtimes.

Both Personal and Enterprise are developed, published, and maintained under the **Ensou Studio** brand. The product family remains **Ensou DSH Launcher**, with Personal and Enterprise as edition labels. Customer names identify the managed organization, not a different software publisher. User-facing credits use **Developed and maintained by Ensou Studio**. Preserve DeepSeek Harness's upstream attribution and notices; Ensou Studio's Launcher branding does not claim authorship of the upstream runtime or official endorsement.

This display-brand decision does not change package identifiers, installation/data paths, update origins, trust policies, or certificate pins. A Windows verified-publisher identity must reflect the actual signing certificate; changing display metadata is not proof of that identity. This decision neither purchases a certificate nor authorizes a trust-store change.

### Runtime routing

```text
Windows PC: DSH --------------------------> DeepSeek official API
Windows PC: browsing/search/fetch --------> external websites/search provider
Windows PC: Launcher --------------------> Ensou update/artifact service
Windows PC: retained account management -> Ensou identity/administration service
```

The first two paths use the employee's network, including any explicitly configured employee/company proxy or VPN. No Ensou cloud component receives or forwards model prompts, generated output, tool-result bodies, or browsing bodies. This does not mean those contents remain on the PC: the selected model provider or destination website receives what the operation requires. Conversations and workspaces remain stored locally and are outside update/reset deletion scopes.

### Provider credential configuration

- Each user receives the distinct official DeepSeek API Key assigned by the administrator. Do not replace it with a shared key or mistake a WebUI/management token for a provider key.
- Launcher owns the local setup experience; the employee must not edit YAML, a command line, or a machine-wide environment variable. Direct-model setup must not require an Ensou model gateway.
- The administrator manually enters the official Key in the protected backend and selects its employee allocation. After identity approval and committed device binding, Launcher retrieves only that employee's assigned Key through an authenticated, device-proof-bound HTTPS operation. This is management traffic, not inference forwarding. New retrieval or rotation requires current online authorization.
- The administrator separately annotates the owner in DeepSeek Platform. That human-maintained remark is bookkeeping, not a system identifier or authorization signal. Ensou maintains its own employee/device/allocation/credential-version mapping and does not assume, scrape, or require an API for platform remarks.
- Use a shared current-user protected credential store and a bounded in-memory handoff into the owned DSH process. Never put an official Key in an installer, runtime archive, update manifest, diagnostic log, URL, or command-line argument.
- The DSH integration must use a supported credential reference, such as `DEEPSEEK_API_KEY`, and the official provider address. The old local-proxy token validator is not an official-key validator and must not be weakened into an arbitrary-environment escape hatch.
- Preserve unrelated existing DSH credentials and settings. Do not silently overwrite an existing credential during installation or change another Harness home. A protected local store is not an additional plaintext copy in `.env` or `.credentials.yaml`.
- Windows current-user encryption protects stored bytes, not secrets from the same user, an administrator, or a running agent with that user's authority. DSH must obtain the plaintext to authenticate. Do not promise that a locally usable provider key is unextractable or cryptographically device-bound.
- An environment-sourced credential is a startup snapshot in the inspected official DSH. Rotation therefore requires a safe owned-runtime restart or a separately verified provider integration; do not claim a running process observes an external environment change.

The credential-reference inspection used official DSH `v0.1.1-rc.2`, commit `b150a551b8d465e31e418e1b2eaf5e79bbb7d28e`. Its credential order is inherited environment, managed `.credentials.yaml`, project `.env`, and Harness-home `.env`. This is not the current release lock: `versions/locked.json` selects `dsh-v0.1.2-rc.1`, commit `a66e4702047846cdaa10c66c9d3df3951f5ea70d`, whose existing `enterprise-managed-v1` patch still requires the local proxy and disables web/search tools. Direct-mode work must revise and test that locked patch and its admission metadata. Compatibility must be tested for every admitted official runtime update, not inferred from the older reference or a version label.

### Browsing and network configuration

- Remove the enterprise search sink and gateway-only model-route restriction from the direct-mode composition. Browse/search/fetch use their supported local DSH providers.
- Do not claim that a Windows browser proxy setting automatically configures every Node/DSH provider. Test direct access and explicitly supported local proxy settings independently.
- Preserve the loopback-only WebUI and its authentication. The local WebUI token is unrelated to the official model API Key.
- Keep trusted endpoint validation, tool approval, bundled-runtime provenance, and protections against executable/environment injection. Do not enable `NODE_TLS_REJECT_UNAUTHORIZED=0`, arbitrary `NODE_OPTIONS`, or an unverified CA as a shortcut to normal browsing.
- An update-service outage is not a model-provider failure. Do not carry gateway reachability or gateway access-token checks into individual direct model requests. Apply the confirmed management-outage policy below rather than the previous gateway lease's request-time dependency.

### Confirmed management-outage policy

- An already activated device with a matching, committed, current-user protected local Key can continue direct provider use when Ensou management is temporarily unreachable. Provider rejection or Key revocation at DeepSeek remains a separate provider failure; Launcher cannot guarantee provider availability or balance.
- New devices, unapproved employees, and incomplete credential installation do not become activated offline. Missing, unreadable, corrupt, mismatched, or partially committed enrollment/credential state requires activation or recovery, not an inferred authorization.
- Management-session expiry blocks authenticated management operations and new Key retrieval until reauthentication; it does not by itself invalidate an existing official provider Key. UI and status must distinguish management connectivity/session state from provider configuration and response state.
- A previously received authoritative suspension, employee/device/allocation revocation, or mandatory artifact withdrawal remains effective during an outage and after restart. Persist a deny barrier before stopping the managed runtime and clearing an applicable managed credential. An older cached allow, clock rollback, or connectivity failure cannot erase that barrier.
- Recovery of connectivity resumes management synchronization and update checks. Keep received denies authoritative and use bounded retry; do not clear local history, restart an active task merely because a poll failed, or install an unverified update.
- This is a new direct-mode authorization policy, not permission to ignore signature checks or expiry on the old gateway lease. Introduce explicit versioned activation evidence and tests; existing gateway-only state does not automatically grant the new offline behavior.

### Revocation and updates

- Management-side suspension/revocation controls the managed Launcher and future management operations as the client observes policy. It cannot invalidate a copied official Key at DeepSeek or guarantee immediate enforcement on an offline/modified client.
- Actual provider access must be revoked by the administrator at DeepSeek Platform. Device replacement therefore includes provider-side revocation of the old Key and issuance of a different Key; a local deletion receipt is not evidence of provider revocation.
- Ensou is not the authoritative per-request spending meter in this topology. Do not claim gateway quotas, per-request auditing, or immediate provider revocation.
- Retain separate signed Launcher and DSH artifacts, integrity/origin verification, independent activation and recovery, and update notifications/policy. No check may be bypassed merely to enable direct networking.
- Existing gateway-only production artifacts are not direct-mode artifacts. Admission metadata, readiness checks, and compatibility evidence must describe the new composition before it is distributable. No unattended in-place migration may guess how to convert a gateway credential into an official Key.

## Options considered

1. **Company inference gateway:** reuses the current enterprise code and enables request-time control, but forwards user model data through Ensou. Rejected by the owner's explicit routing requirement.
2. **Local direct provider access:** selected. Keeps model and browser traffic on the employee's network and removes Ensou inference bandwidth/dependency, but requires local key protection and honest provider-side revocation procedures.
3. **Raw Key in a shared package or global environment:** easy distribution but leaks or misassigns credentials across users and updates. Rejected.

## Consequences

Existing signed update, installation, local-state, and WeCom components remain reusable. Enterprise model/search composition, credential provisioning, gateway-bound admission fields, and gateway-derived access claims require changes. This decision is not a passing runtime test, completed migration, or release approval.

## Action items

1. [ ] Add protected administrator entry/assignment and device-proof-bound HTTPS Key retrieval, followed by shared local official-key configuration. Test redaction, employee/device/version isolation, restart/rotation, and preservation of unrelated local state without reading real credentials.
2. [ ] Replace the enterprise gateway-dependent runtime composition with explicit direct-provider configuration; test model streaming, cancellation, browsing/search, and supported employee-side proxy behavior.
3. [ ] Revise management/server readiness and release metadata so a direct-mode release does not require or expose an inference gateway; remove the model proxy API/nginx/OpenAPI route from the new server composition and retain identity, signing, and update checks. A production configuration change alone is not this migration.
4. [ ] Verify installed Launcher-only and DSH-only updates, rollback, local-data preservation, and the absence of model/browser traffic at Ensou endpoints. Use one explicitly approved real-key laptop acceptance only after isolated tests pass.
5. [ ] Test activated-device management outage and reconnect, management-session expiry, never-activated devices, corrupt/partial local state, observed revocation across restart, stale-allow replay, and provider-side rejection independently.

### Provisioning acceptance criteria

First activation is usable only after online identity/approval/device proof, exact employee/allocation/credential-version checks, protected local commit, and read-back verification. Interrupted retrieval or commit must recover idempotently without installing another employee's Key or writing plaintext into recovery journals. Secret responses use `Cache-Control: no-store`, a verified configured HTTPS origin, and no automatic redirects.

Ensou-owned installers, runtime archives, manifests, receipts, URLs, command-line arguments, logs, audit records, crash/support exports, and update staging must not contain the raw Key. Store it only in the protected backend/local credential stores and expose it in bounded memory for authenticated delivery and the owned DSH provider handoff. DSH necessarily sends it to the official provider over TLS for authentication; same-user access to a running process remains the limitation stated above. Launcher and DSH updates preserve the protected store without copying secrets into their artifact directories.

## Versioned production trust for the direct-local composition

The implementation contract uses `ensou-dsh-enterprise-production-trust-v2` for direct-local Launchers. Existing `ensou-dsh-enterprise-production-trust-v1`, its type, canonical payload and gateway requirement remain unchanged. Reusing v1 with an empty or invented gateway was rejected because it would either fail existing validation or attest to a different runtime topology. Removing v1's gateway field in place was rejected because it would silently change historical fingerprints.

The separate direct input type contains exact `runtimeProfile=enterprise-direct-local` and `apiProvider=deepseek`, update manifest URI/origin and artifact origin, independent release and lease public-key identities/coordinates, control and authorization origins, managed-artifact origin, and the Authenticode signer SHA-256 thumbprint. It has no gateway or provider-credential field. Canonical hashing is UTF-8, LF-separated without a terminal LF, in this order: v2 contract ID; existing Pilot update contract ID; runtime profile; API provider; manifest URI; manifest origin; update artifact origin; release key ID/X/Y; control origin; authorization origin; managed-artifact origin; lease key ID/X/Y; lowercase signer thumbprint. URI normalization and public-key/endpoint/signature-identity validation reuse the unchanged v1 rules.

The benefit is explicit topology binding while retaining existing product/update identity and rollback layout. The cost is separately versioning Launcher self-check and Publisher/Pilot configuration/evidence readers. Completing this hash primitive alone does not admit a production package: those consumers must reject mixed v1/v2 inputs, exact signed lease mode must be verified, and actual installation/update/rollback still requires acceptance. No system trust installation or actual signing is authorized by this code contract.

### Publisher configuration and evidence

The direct-compiled Publisher reads only [Pilot configuration v2](../../release/schemas/enterprise-pilot-readiness-v2.schema.json), with a required `launcherDirectLocalTrust` object. The legacy `launcherTrust` property is rejected even when null; duplicate, case-aliased, missing, gateway and provider-credential fields are rejected before input staging. Common binary verification, endpoint, release-key and lease-key checks consume the actual direct input type through a non-serialized accessor. No legacy trust record or gateway value is synthesized. The default Publisher continues to read only the unchanged v1 input.

The direct [readiness report v2](../../release/schemas/enterprise-pilot-readiness-report-v2.schema.json) identifies the v2 production trust contract, direct-local runtime profile and DeepSeek provider. The public-trust check records the canonical v2 fingerprint. Report admission still requires the existing real signatures, independent admission/brand/lease keys, immutable artifact snapshot and local-data evidence. The direct type's brand-key comparison uses the same key-identity and EC-point independence checks as v1. Existing v1 PowerShell Pilot-evidence producers and release orchestration remain incompatible with v2 until separately migrated and verified; passing configuration tests does not constitute distribution approval.

Focused tests compile the entire project graph with one explicit `EnterpriseDirectLocalRuntimeAdmission` value and separate artifact directories for each value. This prevents differently configured references from compiling concurrently into the same output path. Tests exercise both exact readers, cross-version rejection, malformed direct trust and unchanged v1 fingerprints without network calls, system trust changes or real signing.

## Source reference

[Official DSH credential storage and precedence](https://github.com/deepseek-ai/deepseek-harness/blob/b150a551b8d465e31e418e1b2eaf5e79bbb7d28e/packages/credentials/credentials-local/README.md).
