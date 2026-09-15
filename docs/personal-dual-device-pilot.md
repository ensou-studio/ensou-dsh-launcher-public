# Personal dual-device Pilot gate

Personal distribution is `NO_GO` until the same immutable candidate completes
the two-device matrix below with real-device evidence. The Pilot has exactly two
independent Windows x64 installation identities:

Before either lane starts, the first Pilot Installer must raise the stable
Startup Stub and client on both PILOT-DESKTOP and the PilotNotebook notebook to `1.2.0`.
The old `1.0.0` compiled policy rejects a no-home manifest before download or
activation, so it cannot prove the required Launcher-only update lane.

| Device | Lane-only check | Seven checks also required on this device |
| --- | --- | --- |
| `PILOT-DESKTOP` desktop (`pilot-desktop-desktop`) | `existing-version-upgrade` | startup update detection, Runtime-only update, Launcher-only update, failed-update rollback, offline last-known-good, unchanged local chat/workspace, and no command window |
| PilotNotebook notebook (`pilot-notebook`) | `first-install` | the same seven checks |

This is 8 checks per device and 16 real results in total. It is deliberately
not a 9-by-2 matrix: the desktop does not claim a clean first install and the
notebook does not claim an existing-version upgrade.

## Immutable bindings

[`personal-pilot-release-plan.example.json`](../release/examples/personal-pilot-release-plan.example.json)
is a visible `NO_GO` template. Its `sourceCommit` is the Launcher repository
commit, not `versions/locked.json`'s upstream Harness commit. The checked-in
example deliberately uses forty zeroes instead of a historical real commit;
the production validator rejects that placeholder after the template marker is
removed. Its Runtime input names follow the production `Prepare` contract
exactly:

```text
EnsouDshRuntime-<managed-releaseId>-win-x64.zip
EnsouDshRuntime-<managed-releaseId>-win-x64.metadata.json
EnsouDshRuntime-<managed-releaseId>-win-x64.zip.sha256
```

Before release preparation, copy the template outside the Launcher checkout,
replace every file descriptor and trust placeholder with the exact controlled
input, update `sourceCommit` to the clean release checkout HEAD, and remove
`personalPilotTemplateStatus`. The example itself must never be passed to
production orchestration.

## Two isolated pre-sign reproducible builds

Before client signing, build the same plan twice from two different clean
checkouts and two different output roots. Both runs must use `CI=true`, the
exact SDK in `global.json`, Release, `win-x64`, self-contained, single-file
output, and the locked Personal dependency closure. Assemble exactly these four
unsigned client files in each output root:

```text
Ensou.Dsh.Bootstrapper.exe
Ensou.Dsh.ClientBootstrapper.exe
Ensou.Dsh.Launcher.exe
Ensou.Dsh.Personal.Maintenance.exe
```

The Installer is deliberately outside this pre-sign proof. It embeds the
already signed Pilot manifest, Stub, client bundle, and Runtime payload, so it
is built only by the existing r6 trusted Installer path after the exact r5
candidate is available. A two-clean proof must never accept that later payload
as an input in order to claim it preceded client signing.

The four-client producer is
`release/scripts/New-PersonalTwoCleanBuildEvidence.ps1`, with its dedicated
two-clean intent/evidence schemas. It emits one combined two-run receipt.
It requires a controlled offline package cache, creates a fresh detached clone
for each run, and rejects any pre-existing `obj` directory in that clone.
Restore uses locked dependencies, a package-source-free NuGet configuration,
and the same Release, production and trust inputs as the subsequent
`--no-restore` publish. RID, self-contained and single-file settings come from
the executable project during restore, not command-line globals: NuGet would
otherwise propagate them into portable library dependency graphs. Publish
still passes those settings explicitly; project references remove only those
three globals at the executable/library boundary. Both phases use the same
clone and cache; every admitted restore asset is held and rechecked around publish.
`intermediateRootPath` names the fresh clone containing all project-local
intermediates, not one shared `obj` directory.

The dual-device validator consumes the combined receipt through
`reproducibleBuild.contract = two-clean-four-client-builds-v1` and
`reproducibleBuild.receipt`. It rejects the old `runA`/`runB` contract. The
legacy five-PE receipt producer is not part of this path: do not feed its
receipts to this validator or include the later Installer in the pre-sign proof.

The consumer verifies the canonical build intent against the exact plan's
source, trust, origins, channel and compatibility. It compares both four-client
outputs to the planned signing inputs, reopens their actual bytes and PE hashes,
checks distinct build/checkout/intermediate/output identities, and recomputes
the publish-command, restore-command, restore-assets and output closure hashes.
All restore assets listed in the receipt must remain in the evidence archive.
These checks validate evidence consistency; synthetic contract tests are not
proof of a successful production build or a real-device install. A real
two-clean run and signed candidate/device acceptance remain required.
Existing production signing gates must
separately prove that Authenticode changed only the allowed signature region.

### Personal account endpoint binding

The Personal plan and `New-PersonalPilotBuildIntent.ps1` require an explicit
`personalAccountOrigin` / `-PersonalAccountOrigin`: one canonical HTTPS DNS
origin, lowercase, ending in `/`, with no explicit port, path, query or fragment.
The example `https://accounts.example.invalid/` is not a deployment address.
No production account hostname has been selected; there is no default or mutable
configuration fallback. Enterprise plans must not contain this Personal field.

Both fixed restore/publish argument contracts carry that value. Only the
Launcher consumes it as assembly metadata. After each isolated build, the
producer holds the exact unsigned Launcher and runs
`--personal-account-self-check` in a private profile, without starting Host,
showing the application, creating an account key or contacting a server. Raw
stdout is bounded to 16 KiB and must be exactly the canonical four-field JSON;
stderr, nonzero exit, timeout and origin mismatch reject the build receipt.
Each receipt binds the executable hash, process result and archived stdout.
The Pilot consumer verifies these against the intent and plan as well as both
Launcher outputs. Older receipts without this binding are rejected.

This metadata observation does **not** assert Authenticode trust or a successful
login. The signed executable/package integrity gates, live account-service
acceptance, and real-device update checks are still required. The authentication
endpoint remains separate from the shared Launcher/DSH update source, and neither
endpoint relocates local conversations or workspaces.

Every device receives a canonical UUID v4 installation identity generated on
that device. Do not copy an identity receipt between computers. Every check
record directly repeats and therefore binds:

- its planned `deviceId` and real `installationId`;
- the exact installation-identity receipt SHA-256;
- the same computed candidate-closure SHA-256;
- a canonical UTC observation time, `real-device` source, and `PASS` result;
- a bounded evidence file's relative path, byte count, and SHA-256.

The candidate closure contains the exact signed Installer, Pilot manifest,
client bundle, and planned Runtime input descriptors. Each descriptor binds its
file name, archive-relative path, byte count, and SHA-256. The validator opens
and hashes the four real candidate files, rejects links and hard links, verifies
the manifest's `releaseSetId`, and requires the Runtime name, size, and SHA-256
to equal `plan.runtimeCandidate.archive`. It recomputes the closure hash from
all four complete descriptors and requires all 16 results to use it, so evidence
from a different Runtime or candidate build cannot be combined.

Immediately before either installation, archive one canonical lane-precondition
receipt from the real device. PILOT-DESKTOP must report an existing managed install,
a current pointer, a non-placeholder baseline release ID, and the baseline
pointer SHA-256. The PilotNotebook receipt must report an absent managed root,
absent current pointer, absent startup registration, and null baseline values.
Both receipts must precede their device observations; the PilotNotebook receipt must
also precede creation of its new installation identity.

## Collection layout and validation

Start from
[`personal-dual-device-pilot-evidence.template.json`](../release/examples/personal-dual-device-pilot-evidence.template.json).
It intentionally contains placeholder UUIDs, zero hashes, `template` sources,
and `NO_GO` results, so the production validator rejects it.

Place the completed evidence document beside this exact tree:

```text
personal-dual-device-pilot-evidence.json
builds/
  build-intent.v1.json
  two-clean-build-evidence.v1.json
  isolated-a-personal-account-self-check.json
  isolated-b-personal-account-self-check.json
build-artifacts/
  isolated-a/<role>/<canonical-client-file>.exe
  isolated-b/<role>/<canonical-client-file>.exe
work/
  isolated-a/source/<project-path>/obj/<admitted-restore-assets>
  isolated-b/source/<project-path>/obj/<admitted-restore-assets>
candidate/
  Ensou.Dsh.Personal.Installer.exe
  release-set.v2.json
  <exact-client-bundle-name>.zip
  <exact-runtime-name>.zip
devices/
  pilot-desktop-desktop/
    lane-precondition.v1.json
    installation-identity.v1.json
    checks/<check-id>.json
  pilot-notebook/
    lane-precondition.v1.json
    installation-identity.v1.json
    checks/<check-id>.json
```

Copy each device's generated `personal-installation-identity.v1.json` into its
shown `installation-identity.v1.json` archive path byte-for-byte; do not edit or
reformat it. The validator strictly parses the six-member product receipt,
requires its UUID to equal the device and all eight results, and requires the
two devices to have different UUIDs and state-binding hashes. Every check JSON
is also canonical and self-describing: it repeats its device, installation,
identity receipt, check, candidate closure, UTC time, `real-device` source, and
`PASS` result.

Then run:

```powershell
pwsh ./release/scripts/Test-PersonalDualDevicePilotEvidence.ps1 `
  -PlanPath C:\controlled\personal-pilot-plan.json `
  -EvidencePath C:\controlled\pilot-evidence\personal-dual-device-pilot-evidence.json
```

The validator fails closed on a template plan, invalid or reused installation
identity, a malformed/copied-mismatch identity receipt, identical state
bindings, a false existing/clean lane precondition, placeholder/zero hashes,
non-real-device sources, non-reproducible build outputs, unverified candidate
bytes, a mixed candidate closure, wrong device role, missing shared check,
stale/future observations, path escape/link/hard-link, or evidence bytes that
differ from their descriptor. A single returned `PASS` summary is a local
consistency preflight only, not a signed promotion authorization. The
observations and completion time must be within the previous 30 days and no
more than five minutes in the future. Until the preflight and the existing
signed release gates both pass, Personal remains `NO_GO` for family or wider
distribution.
