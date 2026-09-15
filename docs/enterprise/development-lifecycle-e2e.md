# Enterprise Development lifecycle E2E

`scripts/Test-EnterpriseDevelopmentLifecycle.ps1` is the single local gate for
the employee Development profile. It never changes the Production profile and
does not read or write the normal `%LOCALAPPDATA%\Ensou\DshLauncher` tree.

## CI-safe contract gate

Run the static contract on any Windows CI worker:

```powershell
pwsh -NoProfile -File .\scripts\Test-EnterpriseDevelopmentLifecycle.ps1 -ContractOnly
```

This mode needs neither Docker nor a runtime archive. It verifies that the
runner phases, isolated installer roots, exact TLS leaf pinning hook, real
three-component release-set activation, active plugin-policy lease binding, and
the compile-time-only Launcher/Bootstrapper Development E2E inputs remain
present.

## Full local lifecycle

The full gate requires Windows, PowerShell 7.2+, .NET from `global.json`, Docker
with the pinned PostgreSQL image available, an already reviewed immutable
enterprise-managed runtime ZIP, and the managed plugin builder's exact policy
ZIP plus `.artifact.json` metadata:

```powershell
pwsh -NoProfile -File .\scripts\Test-EnterpriseDevelopmentLifecycle.ps1 `
  -RuntimeArchivePath C:\controlled\EnsouDshRuntime-managed-v2026.08.25.1-win-x64.zip `
  -RuntimeMetadataPath C:\controlled\EnsouDshRuntime-managed-v2026.08.25.1-win-x64.metadata.json `
  -ExpectedRuntimeReleaseId managed-v2026.08.25.1 `
  -ExpectedRuntimeArchiveFileName EnsouDshRuntime-managed-v2026.08.25.1-win-x64.zip `
  -ExpectedRuntimeArchiveSha256 5a3cc1b384f2a11234dae1a654540eba63e6ba959631c49df3c95bc515900d9d `
  -PluginPolicyArchivePath C:\controlled\managed-plugin-policy-<policy-id>-g1.zip `
  -PluginPolicyMetadataPath C:\controlled\managed-plugin-policy-<policy-id>-g1.artifact.json
```

The caller must provide the complete explicit runtime release/file/hash tuple;
the script has no runtime identity defaults. It keeps ordinary single-link
handles open for the runtime ZIP and metadata, binds the ZIP's root
`source-build.json` through `runtime-files.sha256`, and requires the external
metadata, ZIP provenance, archive bytes, and plugin-policy compatibility to name
the same runtime release. The `.1`/g1 tuple above is a historical compatibility
fixture for lifecycle update-mechanism certification. It does not admit the
current `.3` distribution candidate: `.3` remains fail-closed until the plugin
repository publishes a separately reviewed policy artifact that explicitly
includes `managed-v2026.08.25.3`.

A local full build identified by `lab-*` and
`promotionEligible: false` is rejected by default. To exercise those exact
bytes through this Development-E2E lifecycle, add `-AllowLocalLab` and provide
a plugin-policy artifact whose compatibility list names that exact Lab runtime
ID. The switch affects only this isolated Development profile; evidence retains
the Lab identity, and production candidate publication, ReleasePublisher, and
promotion do not expose or pass it.

The policy metadata and archive must agree on filename, size, archive SHA-256,
policy identity/generation, Launcher compatibility, runtime compatibility, and
the SHA-256 of the exact raw root `plugin-policy.json` bytes. The runner captures
the supplied Launcher, runtime, and policy bytes, creates an ephemeral signed
three-component release set, and applies it through the real startup update
coordinator. It then runs the installed Launcher's health probe against the
activated policy tree and receipt before the enterprise service is allowed to
start.

The exact raw policy hash is supplied to PostgreSQL and therefore appears in the
signed authorization lease. Before host start and again before loopback chat,
the runner rereads the active policy pointer and requires the lease's policy ID,
generation, and raw byte hash to match it exactly. A valid policy document with
the same ID and generation but different raw bytes is a required negative case.
The evidence summary records policy identity, compatibility, archive hash,
metadata hash, raw policy hash, activated tree hash, and health state.

The script creates a unique owned tree under the current user's temporary
directory, publishes Development-E2E-only Launcher artifacts, builds an unsigned
Development payload, and runs the real quiet Installer, Bootstrapper self-check,
signed three-component update, installed Launcher self-check, isolated
PostgreSQL container, HTTPS control plane, administrator-issued activation
enrollment coordinator, device
proof, binding, lease refresh, loopback proxy, and SSE chat. It then crosses
process boundaries for refresh rotation, employee suspension/resume, and device
revocation, checking the exact error code, client state, reset scope, credential
removal, and preservation of the local DSH workspace. The existing installation,
signed release-set update, and release-publisher suites run in the same gate;
those tests include plugin-policy archive/metadata validation, lease byte-hash
binding, tamper rejection, rollback to last-known-good, and preservation of
local Harness data.

All child console processes are started hidden. The HTTPS service uses a
run-scoped self-signed leaf certificate; the runner accepts only that exact
SHA-256 leaf and still rejects name mismatch or other certificate-policy errors.
The certificate is not added to a machine or user trust store.

On success, the product's device-revocation reset removes the exact run-owned
device-proof key, and the script removes only its exact run-owned temporary
tree, container, certificate, and environment file. On failure it removes the
container, certificate, and environment secrets, but retains the isolated run
tree and run-scoped device-proof key for diagnosis. The script never invokes a
second reset or directly deletes that credential during cleanup, so a partial
or failed product reset remains observable and retryable. The retained key is
isolated from the normal product key and must be removed only after the failed
run has been diagnosed. Supply `-EvidenceDirectory` to retain redacted JSON
evidence outside the temporary tree even on success.

## Deliberate automation boundary

The Development lifecycle uses the production enrollment semantics: it
pre-registers the run-owned employee, issues a real short-lived activation grant
through the Admin CLI, and captures the one-time plaintext without printing or
persisting it. Only the Launcher runner child process receives the code as
`ENSOU_DSH_E2E_ACTIVATION_CODE`; the runner clears that variable immediately after
reading it. The code never enters the lifecycle environment file, command line,
report, or retained evidence. The runner then exercises the strict activation
claim, device DPoP, poll, and bind paths and records only non-secret outcome flags.

No deterministic callback or identity-provider bypass exists. A manual UI
acceptance remains: launch the Development-E2E build, paste a freshly issued code
into the masked activation field, and confirm the Launcher window/tray affordances
display the Ready and denied states without opening a browser.

The lifecycle runner uses a stateful probe implementation of `IHarnessHost` for
start/stop assertions. It does not claim to execute a real DSH chat process in
that phase; the real gateway HTTP/SSE path, token/DPOP authorization, and
Launcher host-control coordinator are exercised independently. The captured
release artifacts are served to the update coordinator by an in-memory HTTP
transport; artifact verification, staging, activation, health checks, and
rollback are the product paths, while CDN/DNS/TLS delivery remains outside this
local gate. A release report must keep the host adapter item labelled
`simulated` until a reviewed runtime-backed host adapter lane replaces it.
