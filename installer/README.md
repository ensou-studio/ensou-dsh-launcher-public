# Windows enterprise installer boundary

The employee update path is defined in
[`release-set-update-v2.md`](../docs/enterprise/release-set-update-v2.md). The
installer establishes sequence 0; later component advances must use the signed
release-set feed rather than rerunning an older installer.

The repository now contains the per-user enterprise installation chain. It is a
working development baseline, not an employee distribution artifact until the
production trust inputs and Authenticode signatures described below are present.

## Installed layout

Employee shortcuts always target the stable, no-console Bootstrapper. They never
target a versioned Launcher or DSH executable.

```text
%LOCALAPPDATA%\Ensou\DshEnterpriseLauncher\
  Ensou.Dsh.Enterprise.Bootstrapper.exe
  Ensou.Dsh.Enterprise.Installer.exe
  launcher-versions\<launcherReleaseId>\
  runtimes\<runtimeReleaseId>\
  packages\
  state\
    launcher-current.json
    runtime-current.json
    installation-receipt.json
  cache\
  security\
  plugins\
  logs\

%USERPROFILE%\.dsh-enterprise\  # conversations, workspaces, and Harness settings
```

The Launcher and runtime pointers contain `current` and `previous` releases and
are replaced atomically. Every read derives the only allowed version directory,
rejects traversal and filesystem links, checks the install receipt, and hashes
the primary executable or DSH entry point again. A missing or invalid runtime
pointer leaves the UI available for authentication but disables DSH/WebUI start
with an explicit repair message.

Uninstall removes the managed `%LOCALAPPDATA%` tree, current-user shortcuts, and
the HKCU uninstall registration. It deliberately preserves
`%USERPROFILE%\.dsh-enterprise`; deleting local conversations or workspaces is a
separate, explicit future action.

## Development install/repair test

Publish the four executables as Windows x64 self-contained single files and
obtain a complete source-derived DSH runtime directory. Then create a clearly
marked unsigned development payload:

```powershell
.\scripts\New-EnterpriseDevelopmentPayload.ps1 `
  -LauncherReleaseId launcher-dev-2026.08.24.1 `
  -RuntimeReleaseId managed-v2026.08.24.2 `
  -LauncherPublishDirectory C:\path\to\enterprise-launcher-publish `
  -ClientBootstrapperPublishDirectory C:\path\to\client-bootstrapper-publish `
  -MaintenancePublishDirectory C:\path\to\maintenance-publish `
  -RuntimeArchivePath C:\path\to\verified-runtime.zip `
  -BootstrapperPath C:\path\to\Ensou.Dsh.Enterprise.Bootstrapper.exe `
  -OutputDirectory C:\path\to\enterprise-dev-payload `
  -DevelopmentE2E

Ensou.Dsh.Enterprise.Installer.exe --install `
  --payload C:\path\to\enterprise-dev-payload `
  --dev-unsigned `
  --dev-e2e-layout
```

Both the command-line flag and the exact consent marker inside the payload are
required. The installation receipt records `developmentUnsignedPayload: true`.
This path exists only for local integration testing and must never be sent to an
employee.

For this recommended isolated path, publish both the Enterprise Launcher and
Enterprise Bootstrapper with `-p:EnterpriseDevelopmentE2E=true`. The payload
manifest, both binary build-profile markers, and `--dev-e2e-layout` must all say
`development-e2e`; a mismatch is rejected before the default enterprise root is
created. The isolated files live below
`%LOCALAPPDATA%\Ensou\DshEnterpriseLauncherDevE2E` and
`%USERPROFILE%\.dsh-enterprise-dev-e2e`. No test path uses the personal
`%LOCALAPPDATA%\Ensou\DshLauncher` root.

The offline installation test harness exercises installation, same-version
repair, current/previous rollback, path escape rejection, ZIP traversal,
filesystem-link rejection, and default user-data preservation:

```powershell
dotnet run --project .\tests\Ensou.Dsh.Enterprise.InstallationTests\Ensou.Dsh.Enterprise.InstallationTests.csproj -c Release
```

## Employee runtime dependency boundary

The Installer, Bootstrapper, and Launcher are all fixed to `win-x64`,
`SelfContained=true`, and `PublishSingleFile=true`. Their project publish
targets reject a different RID, a framework-dependent publish, or managed
runtime sidecars. All three executables also require both the Windows OS and
current process architecture to be native x64; x64 emulation on ARM64 or
LoongArch, UOS, Kylin, and other platforms fail before install or launch. An
employee computer therefore does not need .NET 10, FNM,
Node, npm, pnpm, Git, or a command line.

The Installer and Bootstrapper publish as one executable each. The Launcher
also publishes its managed application and .NET runtime as one executable; its
version directory deliberately retains non-runtime data sidecars such as the
build-profile marker and upstream license. Node is separate only inside the
signed and hash-locked `runtime.zip`, at `runtime.zip:/node.exe`. No system Node
or version manager is consulted.

Production `runtime.zip` must have `artifactType` equal to
`ensou-dsh-enterprise-managed-source-runtime`. The candidate metadata locks the
official base tag/commit/tree, reviewed patch and manifest digests, base and
patched lockfile digests, managed model/token/sandbox policy, focused tests,
exact managed startup/refusal smokes, and the complete `runtime-files.sha256`
tree. The archive must not contain `.git`, patch files, Git/patch/npm/pnpm
tooling, or build-machine paths. Employee installation and update never clone
GitHub and never fall back to source/package-manager operations.

Release restore is a build-machine action, never an employee-machine action.
`enterprise-publish-runtime-packs.lock.json` pins SDK `10.0.302`, RID
`win-x64`, the exact four NuGet package versions, byte lengths, and official
NuGet SHA-512 hashes. Validate the controlled local feed, then publish and run
the isolated executable checks:

```powershell
pwsh -NoProfile -File .\scripts\Test-EnterprisePublishPackageLock.ps1 `
  -PackageDirectory C:\path\to\controlled-nuget-feed

pwsh -NoProfile -File .\scripts\Test-EnterprisePublishedArtifacts.ps1 `
  -InstallerPublishDirectory C:\path\to\installer-publish `
  -BootstrapperPublishDirectory C:\path\to\bootstrapper-publish `
  -LauncherPublishDirectory C:\path\to\launcher-publish `
  -ClientBootstrapperPublishDirectory C:\path\to\client-bootstrapper-publish `
  -MaintenancePublishDirectory C:\path\to\maintenance-publish `
  -PayloadDirectory C:\path\to\payload `
  -ExpectedLayoutProfile enterprise `
  -RequireAuthenticode `
  -SignerSha256Thumbprint <64-hex-SHA256-thumbprint>
```

The artifact check replaces `PATH` with Windows `System32`, points
`DOTNET_ROOT` at a nonexistent directory, disables multilevel lookup, executes
all three published binaries' no-UI self-checks, and rejects `.dll`,
`*.deps.json`, `*.runtimeconfig.json`, Node/npm/pnpm/FNM executables, or their
toolchain directories outside `runtime.zip`.

For an installed tree, the stable Bootstrapper `--self-check` validates both
active pointers and their receipts/hashes without launching the UI. The active
Launcher `--installation-self-check` additionally verifies that it is running
from the exact current version directory, its compiled layout marker matches,
and the real Node/DSH entrypoint hashes still match the runtime receipt.

## Production payload and signature boundary

The production generator is a Windows x64 signing-station step. It accepts only
production-profile publish trees, requires the Launcher, ClientBootstrapper,
Maintenance, and Bootstrapper to have valid embedded Authenticode signatures
from one pinned signer plus canonical RFC3161 timestamps, and rejects the
development consent marker. The two expected archive hashes are mandatory and
must be copied mechanically from the authenticated r5
`STABLE_SIGNED_CANDIDATE_IMPORTED` receipt for this candidate:

```powershell
pwsh -NoProfile -File .\scripts\New-EnterpriseProductionPayload.ps1 `
  -LauncherReleaseId launcher-2026.09.01.1 `
  -RuntimeReleaseId managed-v2026.09.01.1 `
  -LauncherPublishDirectory C:\path\to\launcher-publish `
  -ClientBootstrapperPublishDirectory C:\path\to\client-bootstrapper-publish `
  -MaintenancePublishDirectory C:\path\to\maintenance-publish `
  -BootstrapperPublishDirectory C:\path\to\bootstrapper-publish `
  -RuntimeArchivePath C:\path\to\r5-candidate-runtime.zip `
  -ExpectedLauncherArchiveSha256 <exact-r5-launcher-sha256> `
  -ExpectedRuntimeArchiveSha256 <exact-r5-runtime-sha256> `
  -OutputDirectory C:\path\to\new-production-payload `
  -SignerSha256Thumbprint <64-hex-SHA256-thumbprint> `
  -PublishedAtUtc 2026-09-01T00:00:00Z

pwsh -NoProfile -File .\scripts\Test-EnterpriseProductionPayload.ps1 `
  -PayloadDirectory C:\path\to\new-production-payload `
  -SignerSha256Thumbprint <64-hex-SHA256-thumbprint> `
  -ExpectedLauncherArchiveSha256 <exact-r5-launcher-sha256> `
  -ExpectedRuntimeArchiveSha256 <exact-r5-runtime-sha256>
```

The output is exactly four ordinary files: `launcher.zip`, `runtime.zip`, the
Bootstrapper, and `enterprise-install-manifest.json`. The generator checks the
safe runtime/source-build shape, but the authenticated r5 admission receipt is
the authority for the complete `runtime-files.sha256` closure; exact runtime
archive binding prevents a different archive from substituting its own inner
claim. The payload Launcher and runtime hashes must remain byte-for-byte equal
to the r5 candidate through the r6 Installer contract.

Production installation does not accept a runtime-supplied external payload
directory. These four files are embedded into the Installer by setting
`EnterprisePayloadDirectory` at publish time. The signed Installer is therefore
the trust envelope for the embedded manifest and its SHA-256/size-locked payload
files.

```powershell
dotnet publish .\src\Ensou.Dsh.Enterprise.Installer\Ensou.Dsh.Enterprise.Installer.csproj `
  -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=true `
  -p:EnterprisePayloadDirectory=C:\path\to\production-payload `
  -p:EnterpriseAuthenticodeSignerSha256Thumbprint=<64-hex-SHA256-thumbprint>
```

The same signer thumbprint is compiled into the installation core. Before an
embedded production payload is opened, Windows `WinVerifyTrust` must accept the
Installer and its leaf signer must match that exact compiled SHA-256
thumbprint. With no thumbprint, an unsigned file, a different signer, or a
missing embedded payload, production installation fails closed.

The Installer, installed Installer, Bootstrapper, and Enterprise Launcher must
be published self-contained and signed by Ensou. Bundled third-party runtime
files keep their upstream bytes; they are authorized by the signed container
manifest, exact archive SHA-256/size, safe extraction, install receipts, and the
separate source-runtime release review. Do not re-sign third-party runtime
files.

## Remaining employee-release gates

- Acquire and protect the Ensou Windows code-signing identity, then record the
  compiled signer thumbprint.
- Produce the embedded production payload from one independently reviewed DSH
  candidate and sign the final Installer/Bootstrapper/Launcher binaries.
- Complete the real company control-plane activation-grant issuance, refresh, gateway,
  revocation, and model-provider configuration.
- Replay installation, repair, update, rollback, revocation, and uninstall on a
  clean standard-user Windows 10/11 x64 machine.
- Preserve `licenses/DeepSeek-Harness-LICENSE.txt`, the visible third-party
  product statement, and written Logo/legal approval in the final package.
- Run the production-only Pilot preflight in
  `docs/enterprise/pilot-readiness.md` and retain its machine-readable `ADMIT`
  report with the clean-machine install/update/rollback replay evidence.
- Re-check the current official DeepSeek Harness release immediately before
  runtime admission. The historical rc.7 and locally built rc.2 candidates are
  not current admission inputs. The exact `dsh-v0.1.2-rc.1` lock remains
  `not-built`; its locally built unsigned bytes must pass independent replay, migration, organization
  admission, signing, and Pilot gates before any first-customer use.
- Attach the exact local-data compatibility evidence required by the Pilot
  preflight for the actual baseline-to-alpha transition. Historical rc.7 to
  rc.2 credentials-layout evidence cannot substitute for current public-API
  compatibility and a byte-exact whole-home restore bound to the exact
  source/target ZIP hashes.

Until every gate is recorded, distribute only to named development testers and
do not label the build employee-ready.
