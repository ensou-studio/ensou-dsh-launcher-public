# Runtime build scripts

The employee Development lifecycle has one bounded entrypoint:
`Test-EnterpriseDevelopmentLifecycle.ps1`. Use `-ContractOnly` in CI, or provide
an immutable runtime ZIP, its explicit metadata path and expected
release/file/hash tuple, plus the exact compatible plugin policy for the
isolated local lifecycle. There are no default runtime identity inputs. See
`docs/enterprise/development-lifecycle-e2e.md` for prerequisites, evidence, and
the explicit UI/Host automation boundary.

There are two intentionally different runtime builders:

- `build-runtime.ps1` installs the published `@deepseek-ai/dsh` npm package. It is a Lab-only transition path and must not be described as a source build.
- `build-source-runtime.ps1` verifies a pinned official DeepSeek Harness base, independently copies its Git metadata and tracked files into a unique short Windows-temp staging tree, applies the one indexed installation-owned enterprise-managed patch only in that copy, and creates a separate movable Windows runtime closure. `OutDir` holds only the release reservation, same-volume publication staging, and final immutable release. This is the only enterprise candidate path; the resulting ZIP is not an upstream-published binary.

`New-PersonalDevelopmentInstallerPayload.ps1` signs only its explicit
non-distributable fixture through the already-built Personal update-test
harness. Each invocation explicitly initializes a DPAPI signing-ledger anchor
below that invocation's ordinary `WorkDirectory` and uses the same isolated
authority for publishing. It never reads, deletes, replaces, or initializes the
CurrentUser production Publisher anchor. The production ReleasePublisher keeps
its independent default anchor authority, explicit one-time initialization,
anti-rollback ledger, and fail-closed recovery rules unchanged.
`New-PersonalSourceRuntimeArtifact.ps1` and the verified-runtime parameter set
of `New-PersonalDevelopmentInstallerPayload.ps1` reject local Lab artifacts by
default. A developer must pass `-AllowLocalLab` explicitly at each boundary;
the artifact and final development payload retain `promotionEligible: false`
and `nonDistributableDevelopment: true`. No production publisher or candidate
workflow passes this switch.

`New-EnterpriseDevelopmentPayload.ps1` is a later packaging step. It combines
already published Enterprise Launcher, ClientBootstrapper, Maintenance, and
Bootstrapper outputs with an already verified runtime into the fixed installer
payload shape. It accepts either a verified unpacked runtime directory or the exact
immutable runtime ZIP via `-RuntimeArchivePath`. The archive path preserves the
already reviewed runtime bytes instead of recompressing them. It refuses links,
unsafe archive names and non-empty output directories and writes an explicit
unsigned-development consent marker. It does not build DSH, sign anything, or
turn a Lab candidate into an employee release; see `installer/README.md`.
Use `-DevelopmentE2E` only with Launcher and Bootstrapper outputs both compiled
with `-p:EnterpriseDevelopmentE2E=true`; the script rejects profile-marker
mismatches before creating the payload.
Run it with PowerShell 7.2 or newer (`pwsh`), not Windows PowerShell 5.1.

`New-EnterpriseProductionPayload.ps1` is the separate production-only packager.
It emits exactly the four Installer inputs and has no development, unsigned,
skip, or bypass switch. It requires the four client PEs to carry valid embedded
Authenticode signatures from the pinned SHA-256 signer and canonical RFC3161
timestamps. It also requires the caller to supply the exact r5 candidate
Launcher and runtime archive SHA-256 values; the generated/copied bytes must
match those hashes. The authenticated r5 admission receipt remains the
authority for the runtime's complete `runtime-files.sha256` closure, and the r6
Installer contract must preserve the same two candidate hashes. Run
`Test-EnterpriseProductionPayload.ps1` with those same expected hashes as an
independent pre-publish check.

Enterprise client publishing uses the exact SDK and NuGet package hashes in
`installer/enterprise-publish-runtime-packs.lock.json`. Before restore, run
`Test-EnterprisePublishPackageLock.ps1 -PackageDirectory <controlled-feed>`;
it rejects missing, extra, linked, wrong-size, or SHA-512-mismatched packages.
After publishing, `Test-EnterprisePublishedArtifacts.ps1` accepts six explicit
directories (Installer, Bootstrapper, Launcher, ClientBootstrapper, Maintenance,
and payload) and locks the five top-level executables plus both payload ZIPs
against write/delete/replacement,
requires embedded (not catalog-only) Authenticode signatures and trusted
timestamps, and size/SHA-256 binds the exact root Launcher, ClientBootstrapper,
and Maintenance entries to the corresponding top-level publishes. It verifies
the archive profile marker against the marker locked alongside Launcher, then
verifies all three client executables without system .NET on `PATH`, rejects
framework/Node/FNM sidecars, and confirms that only `runtime.zip:/node.exe`
supplies Node.

For a named customer Pilot, the final production-only entrypoint is
`Test-EnterprisePilotReadiness.ps1`. It invokes an Authenticode-signed
ReleasePublisher that was compiled with the public runtime-admission key and
signer thumbprint, verifies the signed production release-set plus exact
Launcher/runtime/plugin bytes, checks the Launcher's compiled release/lease/origin
fingerprint and startup-update/rollback contract, and writes a machine-readable
admission report. It also requires hash-bound evidence for the exact source and
target runtime ZIPs proving JSONL/Zstandard session resume/append, credentials
migration, attachments, workspace files, deployed query-policy parity, and a
byte-exact whole-home restore; pointer rollback alone is not accepted. The
report is not admissible until a separately compiled local-data certification
root verifies a short-lived receipt bound to the exact report and captured
runner SHA-256. The wrapper also pins the signed self-contained ReleasePublisher
EXE SHA-256 and records it in the Pilot report.
Development-E2E, unsigned-candidate readiness configs,
placeholder origins, empty trust, unsigned artifacts, and incomplete tuples are
rejected. See `docs/enterprise/pilot-readiness.md`.

`New-EnterpriseWindowsPilotEvidenceBody.ps1` validates the fixed shared 21-gate
contract, two native Windows x64 device lanes, five production release
manifests, six final executables, readiness audience/target bindings, and
handle-locked inventory/receipt inputs. It emits deterministic compact body
bytes plus a detached signing-service request; it never accepts a private key,
the request contains no key selector, and it is explicitly not standalone
admission evidence. Real-device
observation and external ES256 signing remain controlled inputs.

The Publisher-side collector, verifier, and contract replay require native
Windows x64 PowerShell 7.4 or newer. They are controlled release tools, not
employee-client dependencies.

`Test-EnterpriseWindowsPilotEvidence.ps1` is the separate operational gate that
runs after production readiness. Its strict v2 body embeds 21 tuple/process/time
bound gate receipts and is authenticated by an independent ES256 key compiled
into the Authenticode-pinned ReleasePublisher. The same Publisher reruns full
readiness, verifies all five release manifests plus the live HTTPS head with the
readiness release key, and enforces key separation. Fresh readiness is captured
as strict Publisher stdout JSON rather than trusted from a child-written path;
the requested replay file is only a byte-identical create-only convenience copy.
All path inputs are handle-first and rebound by final path plus Windows
`FILE_ID_INFO` before path-based use. Arbitrary evidence content
is never parsed into admission: externally retained observations are referenced
only by redacted type, custodian hash, byte count, and SHA-256. The create-only
verification receipt says `VERIFIED` or `REJECT` and is explicitly not
standalone admission evidence. A purpose-separated low-S ES256 verifier key
authenticates the canonical receipt before r8 trusts any claim; the separately
signed v2 body carries `pilotDecision: ADMIT`. CI calls
`Test-EnterpriseWindowsPilotEvidenceContract.ps1`, including
real ephemeral-test ES256 signatures and negative forgery tests. See
`docs/enterprise/windows-employee-pilot.md`.

## Enterprise-managed source builder

The controlled build machine requires Windows x64, PowerShell 7.2+, Git and HTTPS access to verify the reviewed upstream tag, registry/store access needed by the frozen install, an exact Node distribution (including `npm.cmd`), and the exact pnpm version declared by the pinned Harness `package.json`. The employee ZIP includes `node.exe`; employee computers do not need Node, npm, pnpm, Git, GitHub access, a patch tool, or a source checkout.

Example for the current reviewed rc.1 lock. `$NewReleaseId` must be a newly
allocated immutable `managed-vYYYY.MM.DD.N` value; never reuse the historical
rc.2 release ID:

```powershell
pwsh -NoProfile -File .\scripts\build-source-runtime.ps1 `
  -ReleaseId $NewReleaseId `
  -OfficialTag dsh-v0.1.2-rc.1 `
  -OfficialCommit a66e4702047846cdaa10c66c9d3df3951f5ea70d `
  -NodeVersion 24.19.0 `
  -RuntimeWebAuthProtocol browser-launch-cookie-v1 `
  -HarnessCheckout C:\build\dsh-official-v0.1.2-rc.1
```

For a local full-build diagnostic, use a canonical `lab-*` ID and explicitly
select the non-promotable mode:

```powershell
pwsh -NoProfile -File .\scripts\build-source-runtime.ps1 `
  -ReleaseId lab-rc1-local-20260904 `
  -OfficialTag dsh-v0.1.2-rc.1 `
  -OfficialCommit a66e4702047846cdaa10c66c9d3df3951f5ea70d `
  -NodeVersion 24.19.0 `
  -RuntimeWebAuthProtocol browser-launch-cookie-v1 `
  -HarnessCheckout C:\build\dsh-official-v0.1.2-rc.1 `
  -LocalLab
```

Without `-LocalLab`, only `managed-vYYYY.MM.DD.N` is accepted and both metadata
records contain `promotionEligible: true`. With it, only `lab-*` is accepted and
both records contain `false`; the GitHub candidate/publish/promotion path rejects
those bytes.

Add `-ValidateOnly` to check the remote tag and toolchain, create a temporary independent tracked-file copy below the validated Windows temp directory, verify the selected rc.1 patch index/manifest and all 35 modified preimages, run `git apply --check`, apply the patch, and verify all 43 postimages. It then removes source and publication staging without installing, testing, building, deploying, or producing an employee artifact.

The full build never retries with `--no-frozen-lockfile`, never installs or
builds in the official checkout, and never substitutes an npm-published DSH.
If the controlled registry/store is incomplete, the frozen lock is inconsistent,
or any managed test/gate fails, no candidate directory is published. The exact
failed short source-staging path is retained in the Windows temp directory and
printed with the release id; any partial publication staging is separately
retained and printed below `OutDir`. Both remain ineligible for installer/update
packaging.

The current verified source inputs are:

- repository: `https://github.com/deepseek-ai/deepseek-harness.git`
- tag/commit/tree: `dsh-v0.1.2-rc.1` / `a66e4702047846cdaa10c66c9d3df3951f5ea70d` / `27ab636bb3d77e698f5637e518db44ae1f61e262`
- runtime Web auth protocol: `browser-launch-cookie-v1`
- base `pnpm-lock.yaml` SHA-256: `e12083149a77f790d39b64d018b6b8745c6a7aa95777ecb73e0a2f5ed5fdd0d9`
- managed patch ID: `dsh-v0.1.2-rc.1-enterprise-managed-v1`
- managed patch manifest / patch SHA-256: `6e420ee233436fe5ce4974d630142320ca039297ccc9c3261a87e512332994e5` / `c5945fb046e4cb3d7897c99dc9f68404bcd5ab3352a322ce9063ae4d00723518`
- managed patch: 252,249 bytes, 43 changed files (8 added, 35 modified)
- patched `pnpm-lock.yaml` SHA-256: `0cc4aba6915e0221cf65f806c5ab932849137d5aa4f8f8d129afd6501b8bef7f`
- managed policy canonical SHA-256 values (host / preset / metadata / loader): `fff23b1e6602c2125408f4ce609662d301c5a3633ef5acaf9a14edfa918a6efb` / `22044243781ab948f0c649843181835ab2b0b676246583ef675db4ad0f51b3b9` / `4cb4661afe8d79f3687d1c58b401a2c072131dfd83a4c7389cec9e948f3d5eea` / `4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945`
- Node runtime: `24.19.0`
- package manager: `pnpm@11.7.0`
- upstream Node engine: `^22.19.0 || >=24.0.0`

These values remain pinned inputs rather than `latest`. Earlier rc.7, rc.2, alpha.1, and alpha.3 outputs are historical source-builder evidence only and are not eligible for this active release lane. The rc.1 lock remains `not-built`; the locally generated unsigned candidate does not satisfy release admission and must still pass lifecycle replay, independent review, production signing, and controlled promotion gates. A later upstream release requires a new exact tag/commit/tree, patch rebase, security review, composition digests, manifest, tests, Node version, and `releaseId`; an old patch is never applied automatically to a new base.

`versions/locked.json` schema v4 is parsed through the shared strict `JsonDocument` gate before both candidate builds and the read-only upstream watcher. Duplicate members, scalar/array coercions, unknown members, unreviewed tag/auth-protocol pairs, and malformed hashes are rejected before any value is written to workflow outputs.

## What the source builder proves

Before producing an artifact, the script:

1. requires the canonical upstream origin, exact HEAD/tree, exact local tag-to-commit match, the same tag/commit from the DeepSeek Harness GitHub HTTPS endpoint, and a clean checkout including untracked files; this checks a remote ref but does not claim a cryptographically signed tag;
2. selects exactly one reviewed zero-context patch for the locked tuple from `upstream-patches/index.json`, verifies strict JSON fields, deterministic generator and trailing-whitespace policy, tuple-specific manifest and patch digests/length, all 35 alpha preimage blobs, and then copies the official `.git` metadata plus tracked files into an independent link-free `edsh-<32 hex>\s` tree below the validated, non-reparse Windows temp directory (ignored `node_modules` is not copied); the official checkout is never installed, cleaned, built, or patched;
3. runs apply-check/application only in that staging copy, requires exactly 43 alpha changed paths and exact postimage bytes/SHA-256/Git blobs, requires each focused-test JSONL helper to remain a devDependency rather than a runtime dependency or peer, and compares the official checkout's identity plus filesystem inventory before and after;
4. requires the exact pnpm version from `packageManager`, the exact requested Windows x64 Node version, and the upstream engine contract;
5. requires the reviewed tsgolint path and every installed native executable path to remain below 240 characters, then runs frozen install, the four normal Windows managed focused files plus the exact two-file/three-pass Windows-excluded lane, changed-package/CLI type build, CLI bundle, changed-TypeScript lint, generated configuration/API/translation gates, release/notices gates, clean, full source build, and built-package invariants only in patched staging;
6. uses pnpm's non-legacy dedicated-lockfile deploy in offline mode; accepts a deploy result that skipped lifecycle execution only after asserting the exact reviewed ignored-build set, computes transitive non-optional workspace-peer roots missing from the deploy, restores each from the exact `pnpm pack --dry-run --json --ignore-workspace` publish list after rejecting lifecycle scripts and unsafe paths, runs the one reviewed Windows postinstall explicitly, removes staging-only pnpm metadata and virtual-store content, materializes links, normalizes only the reviewed `dsh-css` region and generated command-shim target comments, and rejects every remaining reparse point or embedded checkout/staging path;
7. walks every required dependency and peer from the CLI, requires the reachable closure to equal every physical package root in the runtime, checks workspace versions against the exact source, and checks every external `name@version` against the pinned root lockfile;
8. runs the four Windows-supported managed focused files plus a separate narrow Vitest lane for the normally Windows-excluded bash/terminal maximum and real-JSONL restored-cwd cases; those excluded tests must execute and may not be silently omitted by the upstream Windows config;
9. smoke-tests the assembled runtime with a restricted `PATH` and no inherited `NODE_PATH`, `NODE_OPTIONS`, or `NODE_EXTRA_CA_CERTS`: bundled Node, DSH version, `node-pty`, `koffi`, ordinary config dump, refusal of missing signal/wrong profile/extra args, and a real managed `--profile enterprise-managed --host 127.0.0.1 --port <canonical>` HTTP 200 boot from a local workspace cwd;
10. creates the ZIP, extracts it to a fresh isolated directory, verifies every per-file SHA-256, rejects reparse points again, and repeats the runtime and loopback Web smoke before publishing the immutable release directory.

The smoke uses only a loopback URL, but the process is not placed in an OS-level network sandbox. Metadata therefore records loopback scope and `externalNetworkIsolation: false`; it does not claim that external network access was technically blocked.

No package-manager command runs in the official checkout. `pnpm deploy` creates a separate staging closure from the patched clone; the script copies and dereferences that closure. The final runtime rejects `.git`, patch inputs, patch/Git/npm/pnpm executables, source/build paths, and reparse points.

## Output and promotion

Each build creates a new directory below `out/source-runtime/<releaseId>/` containing:

```text
EnsouDshRuntime-<releaseId>-win-x64.zip
EnsouDshRuntime-<releaseId>-win-x64.zip.sha256
EnsouDshRuntime-<releaseId>-win-x64.metadata.json
```

An existing `releaseId` is never deleted or overwritten. The ZIP contains `node.exe`, the source-built CLI and Web artifacts, a symlink-free production dependency closure, `LICENSE`, `THIRD_PARTY_NOTICES.md`, runtime dependency license inventory, source provenance, and a per-file SHA-256 inventory. Promotion must reuse these exact ZIP bytes; it must not rebuild them for Pilot or Stable.

The metadata is Ensou build provenance, not an upstream attestation and not a signed Launcher channel manifest. External metadata schema v2 and the ZIP's `source-build.json` schema v3 record the base tree, base and patched lock digests, patch/manifest digests, exact tag-bound `runtimeWebAuthProtocol`, managed model/token/sandbox policy, tests, smokes, and the required `promotionEligible` identity. Adding that member is an intentional breaking pre-production revision: historical v2/v3 bytes without it are retired and remain inadmissible, rather than being relabeled. The ZIP also carries canonical `ensou-runtime-metadata.json`; both assembled and extracted runtime smokes read that file rather than trusting a workflow parameter. `sourceBuilt: true` is emitted only after the real build; `-ValidateOnly` never emits it. Publishing still requires the separate signed-manifest flow, immutable retention, clean-runner replay, and independent review.

The metadata must satisfy `release/schemas/source-runtime-metadata.schema.json` and `release/scripts/Test-SourceRuntimeMetadata.ps1`. `build-candidate.yml` publishes production-candidate bytes only on the first workflow attempt: an empty immutable reservation burns the ID, a read-only job builds and uploads an exact four-file Actions artifact, and an isolated write job downloads it by artifact ID, validates it without runtime extraction, uploads the three public evidence assets to a draft Release, re-downloads them, then publishes and confirms immutability plus exact lightweight tag/commit binding. Promotion validates this immutable candidate record rather than comparing it with whatever upstream lock is current at promotion time.

## Runtime protocol metadata

`RuntimeProtocolMetadata.psm1` reads and writes the exact Host protocol descriptor. Schema 1 describes Web authentication; schema 2 adds Personal managed updates. The explicit `-EnterpriseDirectLocal` writer switch requires `browser-launch-cookie-v1`, excludes `-PersonalManagedUpdate`, and emits schema 3 with `managedUpdateProtocol=enterprise-direct-local-v1` and `runtimeProfile=enterprise-direct-local`. Unknown or duplicate fields and mixed protocols are rejected. The descriptor alone does not authorize publication: the source patch, complete runtime tree, release signer and distribution admission remain separate checks.

`Test-RuntimeProtocolMetadata.ps1` exercises the four supported writer round trips and rejection cases using task-owned temporary directories; it does not run DSH or import trust.

### Explicit Enterprise direct-local source candidates

`build-source-runtime.ps1 -EnterpriseDirectLocal` selects only the reviewed rc.1 base, the separate `upstream-patches/direct-local-index.v1.json` index and manifest v4. It does not alter the default legacy index or `versions/locked.json`. Personal and direct-local capability switches cannot be combined. The direct-local patch has 76 changed paths (21 added, 55 modified); the same preimage, postimage, frozen-lockfile and full-build checks remain required. Direct-local mode also type-builds the changed client modules, model-settings UI and settings-file provider and includes their focused tests and changed TSX lint.

The assembled and freshly extracted runtime must each pass `Test-EnterpriseDirectLocalRuntimeSmoke.mjs`: authenticated Web boot including an actual client-kernel asset fetch, read-only provider settings, writable synthetic local credentials, refusal/anonymous-request checks and two private update cycles with exact child exit. The builder rejects incomplete, duplicate, unknown, mistyped or negative smoke receipts and requires zero model requests. This smoke does not prove an installed Launcher's remote update or a real user's API access.

Direct-local output uses artifact type `ensou-dsh-enterprise-direct-local-source-runtime`, external metadata schema 3 and internal `source-build.json` schema 4, with the exact runtime profile, update capability and both smoke receipts. These are new candidate formats, not legacy metadata with a changed label. A successful local build alone does not admit an installer, select this mode in a production Launcher, sign an artifact or authorize distribution.

## License boundary

DeepSeek Harness itself declares MIT and the builder includes the upstream license and generated third-party notices. That does not automatically approve every dependency or optional platform payload for redistribution by another organization. `RUNTIME_DEPENDENCY_LICENSES.json` is an inventory, not legal advice or legal approval. Ensou must complete its own review before enterprise distribution, especially when a dependency reports `SEE LICENSE IN ...`, a private license marker, or version-specific platform terms.
