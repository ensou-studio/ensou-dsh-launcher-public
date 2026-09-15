# Windows isolated internal Pilot signing preparation

## Decision and boundary

This package contains a read-only preflight and separate execution adapters for
the named `PersonalTwoDevice` and `EnterpriseTwoDevice` Pilots. The Enterprise
adapter consumes the exact stable-channel production request/state closure, but
does not authorize publication. The two profiles use separate roots, leaves,
response keys, request roots, transaction roots, and output roots; they must
never trust or enter each other's lane. No command in this package authorizes
production publication. Both repository policy examples are `NO_GO_EXAMPLE`
and cannot be used to sign.

`EnterpriseTwoDevice` authorizes only its two named acceptance devices. A
seven-employee first cohort does not automatically widen that scope, even if
additional Windows machines could technically trust the same root. Wider
internal-certificate distribution requires a separately reviewed signing and
device-trust scope; no such change is implied by these tools. For an approved
external signer, the provider-independent client-response assembly command is
documented in [production release orchestration](../../docs/enterprise/production-release-orchestration-v1.md#assemble-a-response-from-externally-signed-client-files).

The default preflight remains read-only: it does not create a certificate,
change a certificate store, contact a timestamp service, or sign a file. The
response-key initializer and Personal/Enterprise execution adapters are
separate high-impact commands. Unit and contract tests never invoke their
mutating branches.

The recommended sequence for this week's controlled Pilot is:

1. Select exactly one profile: `PersonalTwoDevice` for PILOT-DESKTOP and the named
   PilotNotebook laptop, or `EnterpriseTwoDevice` for the two named customer test
   devices.
   Create a short-lived internal Pilot signing leaf under that profile's
   dedicated root. Never reuse either root or leaf across profiles.
   Provide the final profile-specific HTTP(S) CRL address when creating the
   certificates; it is embedded in the leaf. Publish the generated public CRL
   at exactly that address before signing. Creation alone does not prove online
   revocation. The initial CRL expires after seven days; arrange renewal with
   increasing CRL numbers and retained revoked entries before using this CA
   beyond that interval. Do not rerun initial-CRL creation as renewal.
2. After verifying both public-certificate SHA-256 values out of band, install
   the root into `LocalMachine\Root` and the leaf into
   `LocalMachine\TrustedPublisher` only on the selected profile's authorized
   device or devices, through an explicit administrator-controlled action
   outside these scripts. Never silently install trust from the Launcher or
   Installer.
3. Select one RFC3161 endpoint, independently approve its canonical form, and
   commit only its lowercase SHA-256 to the repository TSA policy allowlist.
   A caller-provided URL and matching caller-provided digest do not constitute
   approval.
4. Sign every shipped PE/Installer with Authenticode using SHA-256 (`/fd
   SHA256`) and a real RFC3161 timestamp using SHA-256 (`/tr <approved-url> /td
   SHA256`). Do not use legacy `/t` countersignatures.
5. Import the exact signed bytes through the repository r7 validator, then run
   the signed two-device Pilot gates. A preflight result is not r7 or r8
   evidence.
6. Replace the internal Pilot certificate with an organization-validated public
   code-signing certificate before distribution outside the controlled devices.

The visible product identity is `DeepSeek Harness Launcher`; the proposed
developer/publisher label is `Ensou`. The legal certificate subject must be
confirmed before purchasing a public certificate.

## Keep the trust domains separate

These keys and certificates are not interchangeable:

| Purpose | Trust material | Location | Must not be reused for |
| --- | --- | --- | --- |
| Windows binary identity | Authenticode code-signing private key and certificate | controlled Windows signer | HTTPS, update manifests, leases |
| Timestamp proof | RFC3161 TSA certificate and response | external or enterprise TSA | Authenticode publisher identity |
| Server transport | HTTPS/TLS certificate | Ubuntu reverse proxy/server | binary or manifest signing |
| Offline update authenticity | pinned release-manifest signing key | release signer/client trust pin | TLS, Authenticode, device leases |
| Device authorization | device/lease or token signing key | enterprise control service/HSM or secret store | binaries, TLS, update manifests |

Compromise or rotation of one domain must not silently grant authority in
another. Revoking an employee API/device token must block future remote use and
reauthorization; it must not delete the employee's local conversations or
workspace.

## Read-only preflight

First pin the exact Windows SDK `signtool.exe` file version and SHA-256, and pin
the candidate certificate by both its CurrentUser store thumbprint and SHA-256
fingerprint. Then run:

```powershell
pwsh -NoProfile -File release/pilot-signing/Test-WindowsPilotSigningPrerequisites.ps1 `
  -SignToolPath 'C:\Program Files (x86)\Windows Kits\10\bin\<sdk>\x64\signtool.exe' `
  -ExpectedSignToolFileVersion '<exact-file-version>' `
  -ExpectedSignToolSha256 '<64-lowercase-hex>' `
  -CertificateStoreThumbprint '<40-hex-store-thumbprint>' `
  -ExpectedCertificateSha256 '<64-lowercase-hex>' `
  -PilotRootCertificatePath 'C:\controlled-inputs\ensou-dsh-personal-two-device-pilot-root-public.cer' `
  -ExpectedPilotRootCertificateSha256 '<64-lowercase-hex>' `
  -TsaUri 'http://timestamp.digicert.com/' `
  -ExpectedTsaUriSha256 '9a44be2d0f498a8bfd2dd1a5e5cced2135e9c4ada9bb5a04eed4c6c5beba1a33' `
  -AllowedTargetRoot 'C:\controlled-release\unsigned' `
  -TargetPath @('C:\controlled-release\unsigned\Ensou.Dsh.Personal.Installer.exe') `
  -ExpectedTargetSha256 @('<sha256-of-exact-unsigned-installer>')
```

The TSA result contains only validation booleans and SHA-256 values: it never
returns the raw TSA host, path, user information, query, fragment, or URI. The
broader diagnostic does contain local tool and target paths and must remain in
the controlled release workspace. It contains no private key, password, PFX,
or API token.

This offline-only command intentionally exits `3` with `NO_GO`, including when
all structural checks pass, because current revocation cannot be proven without
an online CRL/OCSP evidence step. `productionAdmission` is always `NO_GO`.

The preflight requires native Windows x64 and x64 PowerShell. It checks an exact
SignTool path, file version and SHA-256; a leaf containing exactly the Code
Signing EKU and DigitalSignature key usage; current validity and a validity
buffer; a local chain built with the Code Signing application policy and ending
at the exact pinned Pilot root; SHA-256 certificate identity; private-key
availability/export policy; a canonical HTTP or HTTPS TSA endpoint whose exact
origin-and-path digest is in the repository-reviewed allowlist; and unsigned,
ordinary PE targets contained
below one allowed root. `TargetPath` and `ExpectedTargetSha256` are equal-length,
ordered, unique one-to-one arrays; any count, order, duplication, or byte-hash
mismatch is `NO_GO`.

UNC paths, mapped/network drives, SUBST/device aliases, Win32 device namespaces,
drive-relative and root-relative paths, alternate data streams, drive roots,
traversal segments, and reparse-point ancestors are rejected before target
bytes are inspected. The gate uses Win32 drive metadata before any filesystem
provider access and requires `QueryDosDeviceW` to return exactly one canonical
local `\Device\HarddiskVolumeN` target. It never calls `Resolve-Path` on an
untrusted input. From the drive root through the final leaf, it opens and
inspects one component at a time with `FILE_FLAG_OPEN_REPARSE_POINT`, retains
every successful handle without write/delete sharing until the final read is
complete, and fails closed on every access, sharing, or attribute error. There
is no attributes-only fallback.
Authenticode presence is determined only from the local PE security directory;
the preflight never calls WinVerifyTrust or a network client.
Certificate-chain downloads are disabled explicitly.

This check narrows the path-validation-to-read race inside the preflight, but it
does not turn an arbitrary writable directory into a secure signing boundary or
remove the timing boundary between this process and a later external SignTool
process. An administrator must pre-create an ACL-controlled staging root such as
`C:\EnsouSigning`, grant modification only to the signing identity and trusted
administrators, and prevent untrusted rename/reparse/write access. Stage the
exact inputs there, rerun the no-follow preflight and exact SHA-256 comparison
immediately before signing, then re-hash and validate the resulting signed bytes
with the repository r7 importer. Any inability to retain every component handle
is `NO_GO`, even if ordinary path metadata appears readable.

The first repository-pinned Pilot candidate is the canonical DigiCert RFC3161
endpoint `http://timestamp.digicert.com/` (including the trailing slash), with
UTF-8 SHA-256
`9a44be2d0f498a8bfd2dd1a5e5cced2135e9c4ada9bb5a04eed4c6c5beba1a33`.
HTTP exposes the non-secret RFC3161 message imprint to the network and permits
blocking or denial of service. It does not make an unverified response trusted:
the later signing/verification step must have SignTool validate the returned
imprint and TSA certificate chain. Never place credentials, user information,
query parameters, fragments, or path tokens in a TSA URI.

The preflight deliberately does not make network requests. Therefore it cannot
prove current CRL/OCSP state and always returns
`CERTIFICATE_REVOCATION_STATUS_NOT_PROVEN`. Do not suppress or reinterpret that
blocker. A separate controlled online certificate validation/TSA/signing step
must produce the real evidence. Some key providers also do not expose reliable
export policy; those return
`PRIVATE_KEY_EXPORTABILITY_NOT_PROVEN_NON_EXPORTABLE` instead of guessing.

## Optional Pilot certificate helper

Use PowerShell 7.4 or later for certificate/CRL generation and its tests. These
entry points require the newer .NET CRL APIs and reject PowerShell 7.2 before
execution; the rest of the signing tools retain their own declared requirements.

`New-WindowsInternalPilotCertificates.ps1` supports two explicit, isolated
profiles: two named Personal test devices or two named Enterprise test devices.
Merely reading or testing this repository does not execute it. It creates the
selected profile's root and short-lived leaf only in `Cert:\CurrentUser\My`, requests
non-exportable RSA-3072 keys, and exports public CER files only. It never exports
a PFX/private key and never installs the root into a trusted-root store.
The output directory must be absent, and its immediate parent must already be an
ACL-controlled, fixed-local, no-follow-safe directory; the helper fails closed
if any ancestor handle cannot be retained. Because directory creation and the
subsequent certificate cmdlets are separate operations, the controlled ACL is
part of the security boundary rather than an optional hardening step.

Use it only after the operator approves the exact Pilot scope:

```powershell
pwsh -NoProfile -File release/pilot-signing/New-WindowsInternalPilotCertificates.ps1 `
  -PilotOnlyConfirmation 'I UNDERSTAND THIS IS PILOT ONLY' `
  -PilotProfile PersonalTwoDevice `
  -Publisher 'Ensou' `
  -OutputDirectory 'C:\controlled-release\personal-pilot-public-certificates' `
  -CrlDistributionPointUri 'https://replace-with-your-update-host.example/pki/personal-pilot-root.crl'
```

For the customer Pilot, use `-PilotProfile EnterpriseTwoDevice` and a separate,
absent output directory. Never place Personal and Enterprise public
certificates in the same output directory or import both roots on one device.
Use a different CRL URL for the Enterprise root. The URL above is a placeholder,
not an available update service. A leaf created by the previous helper without
a CRL distribution point cannot acquire one after issuance; recreate that
certificate through the authorized Pilot procedure if applicable.

The helper now exports the initial CA-signed CRL alongside the two public CER
files. These three public files do not contain private keys. It does not upload
the CRL, install trust, or change online revocation checks. The CRL is built using
Microsoft's [CertificateRevocationListBuilder](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.certificaterevocationlistbuilder.build?view=net-10.0).

The command has `ConfirmImpact=High` and prompts before changing
`CurrentUser\My`. Do not use `-Confirm:$false` in the operator runbook. If the
provider cannot prove both keys non-exportable, the helper removes only the
certificates it just created and fails. Public CER files are not secrets, but
they still require integrity-controlled delivery. The private keys remain on
the signing workstation, which also means there is no backup/transfer path;
loss requires a new profile-specific Pilot CA/leaf and removal of old trust on
every device in that profile.

## Personal Pilot signing execution lane

`WindowsPilotSigningExecution.psm1` is the only SignTool execution boundary.
It reads an exact canonical policy satisfying
`windows-pilot-signing-policy-v1.schema.json`. The policy file must be owned by
`SYSTEM` or `Administrators`, have inheritance disabled, and grant write-like
rights only to those two identities. Its SignTool absolute path, file version,
and SHA-256 are checked while no-follow handles to the full path remain open.
The child process uses `ProcessStartInfo.ArgumentList`, no shell, no visible
window, a cleared/minimal environment, a fixed timeout, and bounded stdout and
stderr. Its arguments are exactly:

```text
sign /fd SHA256 /sha1 <UPPERCASE-SHA1-THUMBPRINT> /tr <PINNED-URI> /td SHA256 <TRANSACTION-COPY>
```

The execution certificate must be exactly one CurrentUser/My RSA-3072 CNG key
in Microsoft Software Key Storage Provider, user scoped and non-exportable. Its
DER SHA-256 and SHA-1 store selector are pinned; it must have exactly one EKU,
Code Signing (`1.3.6.1.5.5.7.3.3`), and exactly one Key Usage value,
DigitalSignature. Chain evaluation adds only the Code Signing application
policy, performs online revocation for every non-root element, and terminates at
the locked, hash-pinned Pilot root public CER. This online check and the RFC3161
request are expected network operations only when an operator deliberately
invokes the real execution adapter.

The policy also pre-approves each TSA identity as an ordered certificate chain:
a unique `chainId`, a half-open UTC admission window, the leaf DER SHA-256, zero
or more ordered intermediate DER SHA-256 pins, and the root DER SHA-256. Up to
eight distinct entries permit controlled overlapping rotation; duplicate IDs,
duplicate complete chains, placeholder pins, or a repeated certificate within
one chain are rejected. After SignTool returns, the timestamp signer must have
one critical, exact-only Time Stamping EKU (`1.3.6.1.5.5.7.3.8`). The execution
lane rebuilds that chain at the embedded RFC3161 time with the Time Stamping
application policy and online revocation for every non-root element, then
requires its ordered identities and policy window to match exactly one approved
entry. The returned per-file evidence binds the signed file hash, timestamp,
leaf/intermediates/root pins, TSA URI digest, application policy, and revocation
mode. A valid Windows status or a matching TSA URL alone is never sufficient.

The adapter locks every authenticated unsigned input, copies it to a new
same-volume transaction directory, and invokes SignTool only on the copy. It
then requires Windows `AuthenticodeStatus=Valid`, exactly one primary SignedCms
signer, exactly one RFC3161 value bound to that signer, no legacy
counterSignature, the pinned signer DER SHA-256, a changed full-file hash, a
larger signed file, and an unchanged PE-content SHA-256. All files and the
authenticated response move to the absent final output directory in one atomic
directory rename. A failure in any file, timestamp, response signature,
payload self-check, or import-side validator produces no final output and does
not alter any source file.

### Response authentication keys

Create the client and Installer response keys separately. Each invocation has
`ConfirmImpact=High`, creates one non-exportable CurrentUser CNG P-256 key in
Microsoft Software Key Storage Provider, and writes only its public X/Y point:

```powershell
pwsh -NoProfile -File release/pilot-signing/Initialize-WindowsPilotResponseSigningKey.ps1 `
  -PilotOnlyConfirmation 'I UNDERSTAND THIS CREATES A NON-EXPORTABLE PILOT RESPONSE KEY' `
  -PilotProfile PersonalTwoDevice `
  -Purpose ClientSigningResponse `
  -KeyName '<unique-client-response-key-name>' `
  -KeyId '<approved-client-response-key-id>' `
  -OutputPath 'C:\EnsouSigning\policy\client-response-public.json'

pwsh -NoProfile -File release/pilot-signing/Initialize-WindowsPilotResponseSigningKey.ps1 `
  -PilotOnlyConfirmation 'I UNDERSTAND THIS CREATES A NON-EXPORTABLE PILOT RESPONSE KEY' `
  -PilotProfile PersonalTwoDevice `
  -Purpose PersonalInstallerSigningResponse `
  -KeyName '<unique-installer-response-key-name>' `
  -KeyId '<approved-installer-response-key-id>' `
  -OutputPath 'C:\EnsouSigning\policy\installer-response-public.json'
```

For Enterprise, run the same initializer twice with
`-PilotProfile EnterpriseTwoDevice`: once with `ClientSigningResponse`, and
once with `EnterpriseInstallerSigningResponse`. Use new names and IDs; do not
reuse either Personal key.

Copy only `keyName`, `keyId`, `purpose`, `x`, and `y` into the protected signing
policy. The same key ID and public coordinates must already be pinned in the
matching v2 production plan trust domain. The two key names, IDs, and public
points must differ. The execution module opens the named key as `UserKey`,
re-proves provider, curve, scope, and non-exportability, emits a 64-byte P1363
ES256 signature, normalizes it to low-S, verifies it locally, and then invokes
the existing import-side response validator.

### Protected policy and adapters

Start from `windows-pilot-signing-policy.example.json` for Personal or
`windows-enterprise-pilot-signing-policy.example.json` for Enterprise. Replace
every zero or placeholder pin, preserve the selected profile, and set
`executionAdmission` to `PERSONAL_PILOT_SIGNING` or
`ENTERPRISE_PILOT_SIGNING` respectively. Serialize it as compact UTF-8 JSON
without a BOM or trailing newline, then apply the ACL described above.
`requestRoot`, `transactionRoot`, and `outputRoot` must already exist on fixed
local drives without reparse-point ancestors; transaction and output roots must
share a volume. Do not edit the protected policy while an adapter is running.

Before changing `executionAdmission`, capture the exact TSA leaf, ordered
intermediate chain, and terminal root from an independently reviewed online
validation on the controlled signer. Populate `tsa.trustedSignerChains`; never
copy the zero-hash example. To rotate a TSA certificate, add the new distinct
chain with an explicit validity window, allow only the reviewed overlap, deploy
the protected policy, and remove the expired entry in a later reviewed policy
revision. A policy pin does not replace live chain trust or online revocation.

For the exact four-file Personal client request:

```powershell
pwsh -NoProfile -File release/pilot-signing/Invoke-PersonalPilotClientSigning.ps1 `
  -PolicyPath 'C:\EnsouSigning\policy\personal-pilot-signing-policy.v1.json' `
  -PlanPath '<absolute-canonical-personal-plan-v2-path>' `
  -RequestPath '<absolute-client-signing.v1\signing-request.v1.json-path>' `
  -OutputDirectoryName '<new-client-response-directory>'
```

For the dedicated Personal Installer request at r6:

```powershell
pwsh -NoProfile -File release/pilot-signing/Invoke-PersonalPilotInstallerSigning.ps1 `
  -PolicyPath 'C:\EnsouSigning\policy\personal-pilot-signing-policy.v1.json' `
  -PlanPath '<absolute-canonical-personal-plan-v2-path>' `
  -RequestPath '<absolute-installer-signing.v2\installer-signing-request.v2.json-path>' `
  -R6ReceiptPath '<absolute-0006-installer-signing-requested.json-path>' `
  -R6HeadSha256 '<64-lowercase-hex-r6-head>' `
  -OutputDirectoryName '<new-installer-response-directory>'
```

The Installer adapter reconstructs the exact r6 CAS head from the canonical r6
receipt, verifies all request-closure hashes, runs the signed Installer's
`--production-payload-self-check`, creates a purpose-bound low-S ES256 response,
and replays the existing Personal response and exact Authenticode validators
before commit. It never executes the unsigned Installer.

For the exact Enterprise client request and the Enterprise Installer request at
r6, use the isolated Enterprise policy and adapters:

```powershell
pwsh -NoProfile -File release/pilot-signing/Invoke-EnterprisePilotClientSigning.ps1 `
  -PolicyPath 'C:\EnsouSigning\policy\enterprise-pilot-signing-policy.v1.json' `
  -PlanPath '<absolute-canonical-enterprise-plan-v2-path>' `
  -RequestPath '<absolute-client-signing.v1\signing-request.v1.json-path>' `
  -OutputDirectoryName '<new-enterprise-client-response-directory>'

pwsh -NoProfile -File release/pilot-signing/Invoke-EnterprisePilotInstallerSigning.ps1 `
  -PolicyPath 'C:\EnsouSigning\policy\enterprise-pilot-signing-policy.v1.json' `
  -PlanPath '<absolute-canonical-enterprise-plan-v2-path>' `
  -RequestPath '<absolute-installer-signing.v2\installer-signing-request.v2.json-path>' `
  -R6ReceiptPath '<absolute-0006-installer-signing-requested.json-path>' `
  -R6HeadSha256 '<64-lowercase-hex-r6-head>' `
  -OutputDirectoryName '<new-enterprise-installer-response-directory>'
```

The Enterprise client adapter requires the canonical ordered Bootstrapper,
Launcher, ClientBootstrapper, and Maintenance inputs. The Enterprise Installer
adapter additionally requires the exact published v2 request bundle, trusted
build evidence, r6 receipt/head, payload inventory, signed Installer self-check,
and import-side Authenticode plus RFC3161 verification before atomic commit.

The real positive certificate-chain, SignTool, and RFC3161 path remains
`PENDING` until it is exercised on the controlled signing workstation with the
approved Pilot certificate and TSA. Passing the simulation tests below does not
clear that operational gate.

## Pilot deploy checklist

### Before signing

- [ ] Record the two test-device names, Windows versions, and `x64-based
  processor` system type.
- [ ] Record the exact publisher string and internal-Pilot approval.
- [ ] Pin SignTool path, file version, and SHA-256.
- [ ] Pin leaf certificate SHA-256 and public root CER SHA-256.
- [ ] Resolve private-key exportability and revocation blockers honestly.
- [ ] Approve one canonical HTTP or HTTPS RFC3161 TSA, pin its URI SHA-256, and
  record the reviewed leaf, ordered intermediate, and root SHA-256 identities
  with an explicit admission window in the protected policy.
- [ ] Record one expected unsigned SHA-256 for every target in the same order;
  reject duplicates and byte mismatches.
- [ ] Keep TLS, release-manifest, and device/lease keys separate.
- [ ] Preserve the exact unsigned and signed hashes in create-only release state.

### Sign and verify

- [ ] Sign with `/fd SHA256 /tr <approved-url> /td SHA256` on the controlled signer.
- [ ] Verify with a separate SignTool invocation and the repository r7 validator.
- [ ] Confirm there is one RFC3161 timestamp and no legacy countersignature.
- [ ] Confirm the signed PE-content identity still binds the exact unsigned input.
- [ ] Confirm both devices trust only the intended Pilot root/publisher.

### Personal two-device Pilot

- [ ] Use exactly PILOT-DESKTOP for `existing-version-upgrade` and the named
  PilotNotebook laptop for `first-install`.
- [ ] On both devices verify startup update detection, runtime-only update,
  launcher-only update, failed-update rollback, offline last-known-good,
  unchanged local conversations/workspaces, and no command window.
- [ ] Bind every result to that device's installation UUID, the exact candidate
  hashes, observation time, and PASS result; never substitute one device's
  receipt or global acceptance for the other.
- [ ] Confirm that the Enterprise Pilot root and leaf are absent.
- [ ] Remove Personal Pilot trust when the test ends or the key is replaced.

### Enterprise two-device Pilot

- [ ] Install first on the clean Windows x64 device.
- [ ] Upgrade the legacy-device fixture without losing local history/workspace.
- [ ] Verify background start, tray/WebUI access, update notification, rollback,
  token revocation, and relogin behavior.
- [ ] Roll back if install/update fails, signing trust differs, unexpected
  console/crash dialogs recur, or local data changes outside the approved path.
- [ ] Remove Pilot trust from both devices when the Pilot ends or the key is
  replaced.

## Tests

```powershell
pwsh -NoProfile -File release/pilot-signing/Test-WindowsPilotSigningTooling.ps1
pwsh -NoProfile -File release/pilot-signing/Test-WindowsPilotSigningExecution.ps1
pwsh -NoProfile -File release/pilot-signing/Test-PersonalPilotSigningAdapters.ps1
pwsh -NoProfile -File release/pilot-signing/Test-WindowsPilotSigningContracts.ps1
```

Every persisted fixture is intentionally marked `NO_GO`; there is no fake
signed or production-ready fixture.
