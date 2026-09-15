# Installer signing r6/r7 contract v1

## Operator decision

**NO-GO for production release.** Enterprise Stable r6/r7 is now connected to
the production state machine with create-only bundles, state locking, exact CAS
replay, typed receipts, isolated ES256 response authentication, and Windows
Authenticode/RFC3161 verification. Personal r6/r7 is implemented through the
same in-process trusted-build, exact request/response binding, CAS, and
fail-closed NO-GO boundary; real certificates, RFC3161 responses, and Pilot
evidence remain external prerequisites.

Enterprise r6 now invokes the trusted build producer in-process while the
orchestrator holds its code, checkout, and state locks. The producer snapshots
every tracked source input, performs the locked offline restore and publish in a
private create-only staging root, and returns locked descriptors for request v2,
the reserved unsigned Installer, its four payload files, and trusted-build
evidence. Operator-supplied request-v2 bundles are rejected.

The r6 trusted builder now admits the exact official .NET SDK 10.0.302 ZIP
against the reviewed Git lock, extracts it create-only, makes a second private
create-only copy, and keeps both byte closures locked through `--version`,
restore, and publish. It obtains `dotnet.exe` only from that private closure and
records the ZIP SHA-512, tracked-lock SHA-256, inventory SHA-256, file count,
and total bytes. The next honest r6 blocker is therefore
`INSTALLER_SIGNING_RESPONSE_REQUIRED`, while `productionAdmission=NO_GO`
continues until real signing and Pilot gates pass.

The repository also has no real Authenticode certificate/RFC3161 response pair
or real signed Enterprise Installer fixture for this orchestration path.

The trusted-builder tests are **GO for producing a controlled Pilot signing
request only**. They never authorize publication. Real certificate/TSA/Installer
checks remain `PENDING`, and every normalized admission remains
`productionAdmission=NO_GO`.

## Purpose and boundary

### Assemble an externally signed Installer response

`release/scripts/New-ProductionInstallerSigningResponse.ps1` accepts the
approved CA-signed Installer for an existing committed r6 request. It does not
call a CA or sign the Windows executable. The operator must already hold the
separate approved P-256 PKCS8 response-attestation key pinned by the plan's
Installer-signing trust. Neither private key material nor vendor credentials
belong in the repository, release state, output bundle, or command-line values.

```powershell
pwsh -NoProfile -File release/scripts/New-ProductionInstallerSigningResponse.ps1 `
  -StateRoot C:\release-state\enterprise-candidate `
  -ExpectedHeadSha256 <exact-current-r6-head> `
  -SignedInstallerPath C:\signer-return\Ensou.Dsh.Enterprise.Installer.exe `
  -ResponsePrivateKeyPath C:\protected-response-keys\installer-response.pk8 `
  -OutputRoot C:\signer-return\authenticated-enterprise-installer-response
```

The output must not exist and its parent must already exist. The command
locks and checks the exact r6 state, request, unsigned input, signed input and
key. It verifies the pinned Authenticode signer, RFC3161 timestamp, unchanged
PE content and the existing edition-specific response contract. Only after
signature admission does it invoke the held signed Installer's bounded,
hidden `--production-payload-self-check`; this is not an installation command.
Windows certificate and revocation checks may access network services.

The existing formats remain unchanged:

- Personal: `personal-installer-signing-response.v2.json` and
  `signed/Ensou.Dsh.Personal.Installer.exe`, using the dedicated Personal
  response purpose and the current request-v2 `pilot` lane.
- Enterprise: `installer-signing-response.v1.json` and
  `signed/Ensou.Dsh.Enterprise.Installer.exe`, using the Enterprise response
  purpose and `stable` lane.

Pass the generated response to the existing `ImportInstallerSignature` phase
with its exact expected state head. Creating the response does not advance
state or approve a release. Expired requests and changed heads must be
handled through the release workflow, never by editing receipt timestamps.
Do not upload this response bundle as the employee download: real release
approval, HTTPS update validation and named-device acceptance still apply.

Revision 6 reserves one exact unsigned Installer and emits an external signing
request. Revision 7 imports one authenticated response and admits the exact
signed Installer bytes. The target channel is compiled before r6:

- Personal permits `pilot` or `stable`.
- Enterprise permits `stable` only.
- There is no Pilot-to-Stable channel promotion in this contract.

These files define the current r6 producer and r6/r7 contracts:

- [`launcher-installer-signing-request-v2.schema.json`](../release/schemas/launcher-installer-signing-request-v2.schema.json)
- [`enterprise-installer-trusted-build-evidence-v1.schema.json`](../release/schemas/enterprise-installer-trusted-build-evidence-v1.schema.json)
- [`EnterpriseInstallerTrustedBuild.psm1`](../release/scripts/EnterpriseInstallerTrustedBuild.psm1)
- [`launcher-installer-signing-response-v1.schema.json`](../release/schemas/launcher-installer-signing-response-v1.schema.json)
- [`launcher-installer-signing-admission-v1.schema.json`](../release/schemas/launcher-installer-signing-admission-v1.schema.json)
- [`InstallerSigningContracts.psm1`](../release/scripts/InstallerSigningContracts.psm1)
- [`Assert-InstallerSigningBundle.ps1`](../release/scripts/Assert-InstallerSigningBundle.ps1)
- [`Test-InstallerSigningContracts.ps1`](../release/scripts/Test-InstallerSigningContracts.ps1)
- [`fixture-status.v1.json`](../release/fixtures/installer-signing-contract-v1/fixture-status.v1.json)

The production orchestrator calls these contracts for Enterprise Stable r6/r7.
Historical v1 state and evidence contracts keep their existing meaning; this
work does not reinterpret or regenerate them.

## Exact inventories

The r5 signed-candidate inventory and Installer payload inventory are distinct
closures. “Not embedded” never means “not bound.”

| Edition | r5 candidate roles, exact order | Installer payload roles, exact order |
| --- | --- | --- |
| Personal | `release-manifest`, `client-bundle`, `runtime` | `release-manifest`, `startup-stub`, `client-bundle`, `runtime` |
| Enterprise | `release-manifest`, `release-public-key`, `launcher`, `runtime`, `plugin-policy` | `install-manifest`, `launcher`, `runtime`, `bootstrapper` |

The r3 signed-client and compiled release-trust probe closures are:

| Edition | Signed clients, exact order | Roles that must emit canonical release-trust probes |
| --- | --- | --- |
| Personal | `startup-stub`, `client-bootstrapper`, `launcher`, `maintenance` | all four roles |
| Enterprise | `bootstrapper`, `launcher`, `client-bootstrapper`, `maintenance` | `bootstrapper`, `launcher`, `client-bootstrapper` only |

Enterprise Maintenance is still Authenticode/binary-identity bound, but it does
not compile update trust and therefore must not fabricate a release-trust probe.

## r6 operator invariants

The request is admitted only after all of the following are exact:

1. r5 `head.json`, lowercase kebab-case r5 receipt filename, r5 receipt hash,
   candidate manifest request/response, candidate inventory, and target channel.
2. r3 receipt, signed-client inventory, release-manifest trust, and canonical
   trust-probe inventory.
3. Installer payload inventory and a typed byte-binding proof for all four
   managed resources embedded in the exact managed assembly supplied to the
   single-file bundler. r6 neither executes the unsigned Installer nor records a
   fabricated self-check. `--production-payload-self-check` is reserved for r7,
   after Authenticode and RFC3161 verification.
4. One independent plan trust with purpose `installer-signing-response`. Its
   P-256 point and key ID cannot equal release-manifest signing trust. The exact
   request lifetime must equal the plan's maximum response age.
5. Full unsigned file SHA-256 and Authenticode PE-content SHA-256.
6. One create-only build reservation. `buildOrdinal=1`,
   `buildCountForTarget=1`, and the rebuild policy permits only replay of the
   exact previously reserved unsigned bytes after a crash.

The target build identity includes plan, edition, release set, channel, source
commit, source tree, r3/r5 closures, payload closure, toolchain lock, and the
exact source-build input-set hash.

### Source-build closure

`sourceBuildInputs.files` is ordered using Windows `OrdinalIgnoreCase` identity
semantics. Identity paths that differ only by case are duplicates. Every present
input has a snapshot path, size, and SHA-256; the complete list is hashed before
and after build and must remain unchanged. The hashed generated input
`git-blob-bindings.v1.json` records every tracked path, mode, Git blob object ID,
size, and SHA-256. The producer independently recomputes each Git blob hash from
the already locked descriptor bytes before copying them. Git is resolved from
its native Program Files location. .NET is never resolved from Program Files or
inherited `PATH`; it comes only from the reviewed private portable-SDK closure.

The list covers all transitive `.cs`, `.csproj`, `Directory.Build.props`,
`global.json`, real `packages.lock.json`, restore graph, runtime packs, payload or
other generated inputs, and any other transitive MSBuild input. It also binds
`repo/Directory.Build.targets` as either exact present bytes or one explicit
`VERIFIED_ABSENT` entry. A future file cannot appear silently.

Every transitive project descriptor has exactly one sibling `packages.lock.json`
descriptor; a root-only lock is not a complete graph closure. The current real
fixture closes three Installer projects and four exact offline runtime packages.

The producer must reject dirty or untracked paths, filesystem links, multiple
hard links, path races, and build-time mutations. Each source input is at most
1 GiB and the entire snapshot is at most 1 GiB. `project.assets.json` records a
restore result; it is not a substitute for a committed package lock. The trusted
producer captures these bytes and completes restore/publish without a network
source. Every child process starts from an empty inherited environment and then
receives only an explicit OS/build allowlist; restore and publish additionally
pin the admitted `Directory.Build.props`/`Directory.Build.targets` paths and
clear all `CustomBefore*`/`CustomAfter*` MSBuild import hooks. The child
environment sets `DOTNET_ROOT` and `DOTNET_ROOT_X64` to the private copy and
sets `DOTNET_MULTILEVEL_LOOKUP=0`. Production admission remains NO-GO for the
independent signing-response and real-device Pilot gates.

## r7 operator invariants

The response is canonical JSON authenticated in the isolated
`installer-signing-response` domain using ES256, IEEE P1363 encoding, and
canonical low-S. It binds the exact request bytes and nonce, r5 base head, r6
admission head and receipt, source tree, source-build set, time window, candidate
set, payload set, r3 set/probes, toolchain, build identity, and unsigned Installer.

The signed full-file SHA-256 must change because Authenticode appends signature
material. The PE-content SHA-256 must remain exactly equal to r6. The admitted
bytes are copied once into a create-only private verification path and held by
an ordinary-file read lock while Authenticode/RFC3161 validation and execution
both use that same snapshot. After execution the snapshot and original admitted
input are rehashed through their locked descriptors. The signed Installer emits
one canonical JSON self-check result that binds its own exact full-file SHA-256,
the two release IDs, and every embedded payload hash and size; exit code zero
alone is not admission evidence. This is the first phase that may run the
production self-check command.

On Windows, admission additionally requires:

- module-qualified `Get-AuthenticodeSignature` returning `Status=Valid`, with
  signer and timestamper certificates;
- exactly one primary Authenticode `SignedCms` signature whose cryptographic
  signature validates and whose signer digest is SHA-256;
- exact signer-certificate SHA-256 matching the production plan;
- `SpcIndirectDataContent` for a PE image with its SHA-256 digest equal to the
  shared PE-content hash;
- exactly one RFC3161 unsigned attribute containing exactly one decodable and
  valid token bound to that primary signer and exact trusted timestamper;
- no PKCS#9 legacy `counterSignature` attribute; and
- an RFC3161 timestamp within the exact r6 request window, no later than r7
  response completion, followed by the signed payload self-check.

The implementation reuses the production module's
`Get-PeContentSha256` and `Assert-PeRfc3161Timestamp` functions. The standalone
module does not fork those security decisions.

## Running the foundation checks

Run the synthetic strict-contract suite from the repository root:

```powershell
pwsh -NoProfile -File release/scripts/Test-InstallerSigningContracts.ps1
```

Expected markers are:

```text
INSTALLER-SIGNING-CONTRACTS-PASS
REAL-AUTHENTICODE-RFC3161-INSTALLER-FIXTURES-PENDING
```

Run the real locked/offline request-v2 producer fixture on Windows x64:

```powershell
pwsh -NoProfile -File release/scripts/Test-EnterpriseInstallerTrustedBuild.ps1 `
  -DotNetSdkArchivePath C:\reviewed-inputs\dotnet-sdk-10.0.302-win-x64.zip
```

Its expected decision is `PASS` with
`BuildStatus=SIGNING_REQUEST_READY_NO_GO`, four verified embedded resources,
verified SDK closure fields, and blocker `INSTALLER_SIGNING_RESPONSE_REQUIRED`.

The Windows `enterprise-managed-release` workflow downloads only the fixed
official ZIP URL into runner-temporary storage, verifies its reviewed SHA-512,
and passes that explicit path into the trusted builder. The builder repeats ZIP
and per-file verification; `actions/setup-dotnet` is not a fallback for this
trusted build. A green workflow proves the source, SDK, and contract boundaries
remain fail-closed; it does not claim that a real Authenticode certificate,
RFC3161 response, signed Installer, Pilot, or employee deployment exists.

For a real r7 import, use the read-only bundle validator on Windows. Supply the
actual canonical plan, request, response, unsigned and signed Installers, r6 head
and receipt, plus the exact Git tree SHA recorded by state identity:

```powershell
pwsh -NoProfile -File release/scripts/Assert-InstallerSigningBundle.ps1 `
  -PlanPath C:\release-state\plan.json `
  -RequestPath C:\release-state\requests\installer-signing.v1\installer-signing-request.v1.json `
  -ResponsePath C:\release-state\imports\installer-signing.v1\installer-signing-response.v1.json `
  -UnsignedInstallerPath C:\release-state\requests\installer-signing.v1\unsigned\Ensou.Dsh.Personal.Installer.exe `
  -SignedInstallerPath C:\release-state\imports\installer-signing.v1\signed\Ensou.Dsh.Personal.Installer.exe `
  -R6HeadPath C:\release-state\head.json `
  -R6ReceiptPath C:\release-state\receipts\0006-installer-signing-requested.json `
  -ExpectedSourceTree 0123456789abcdef0123456789abcdef01234567
```

Even a `status=VERIFIED` result reports `productionAdmission=NO_GO` until the
trusted source-build producer, real signer/TSA, and later real-device gates are
independently complete.

## Exact replay and crash recovery

An interrupted r6 must reopen the reservation and compare the complete canonical
request plus exact unsigned Installer bytes. It must not rebuild. An interrupted
r7 must compare the complete canonical response plus exact signed Installer
bytes. A changed response, signature, timestamp, full-file hash, or Installer byte
is a new artifact and cannot be replayed into the reserved transition.

Pilot and Stable evidence must reference the same signed Installer object bytes
that were admitted at r7. Re-signing for publication is forbidden.

## Remaining PENDING gates

Production remains blocked on all of these independently observable fixtures and
integrations:

- one production Authenticode signing certificate with a valid Windows chain,
  trust, and revocation result;
- one trusted, single-value RFC3161 TSA response bound to the primary signer,
  within the request/completion window and with no legacy counterSignature;
- real signed Personal and Enterprise Installer fixtures and payload self-checks;
- a real positive signed r7 fixture; focused tests exercise the real trusted r6
  source snapshot/offline build and typed state/CAS boundaries, while real r7
  certificate/TSA bytes remain pending;
- independent Windows verification against the real signer certificate and TSA;
- r8 private Stable evidence and later feed promotion.

The r8 online-upgrade lane needs an older signed Stable baseline that already
contains authenticated, device-bound update transport. A same-build/no-op fetch
cannot prove update or rollback. The authenticated Enterprise Stable update path
and DPoP-capable transport code exist, but the real server policy, an eligible
older signed baseline, and end-to-end upgrade/rollback evidence have not yet been
verified.

## Integration status and ownership

The integration now owns lifecycle naming, receipt serialization, and replay
inventory in:

- `release/scripts/ProductionReleaseState.psm1`
- `release/scripts/Invoke-LauncherProductionRelease.ps1`
- `release/schemas/launcher-production-release-state-v2.schema.json`
- the combined orchestration tests.

Receipts use lowercase kebab-case filenames. The integrated path sources
`sourceTree` from the locked checkout/state identity and preserves backward
parsing for historical v1 evidence without generating new releases under the old
semantics.

## Security references

- [Microsoft PE/COFF specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [SignedCms class](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.pkcs.signedcms)
- [RFC3161 signer binding](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.pkcs.rfc3161timestamptoken.verifysignatureforsignerinfo)
- [SPC_INDIRECT_DATA_CONTENT](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-spc_indirect_data_content)
- [Authenticode timestamping](https://learn.microsoft.com/en-us/windows/win32/seccrypto/time-stamping-authenticode-signatures)
- [Get-AuthenticodeSignature](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-authenticodesignature)
