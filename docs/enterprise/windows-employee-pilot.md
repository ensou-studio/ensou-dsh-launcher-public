# Enterprise Windows employee Pilot

This is the operational distribution gate for a named customer employee. It
does not replace technical readiness: a signed ReleasePublisher reruns the
complete production readiness contract during verification. Distribution is
`NO-GO` unless that replay admits, the independent Windows evidence
attestation verifies, all five release manifests and the live Pilot head verify,
and the attested 21-gate body says `pilotDecision: ADMIT`.

The verifier does not build, sign, upload, install, enroll, revoke, or move a
feed. It never creates a production certificate or private key.

## Independent trust roots

The production ReleasePublisher is a signed, timestamped, self-contained
`win-x64` executable pinned by both SHA-256 and Authenticode signer. Its build
must compile these additional public inputs:

```text
EnterprisePilotEvidenceKeyId
EnterprisePilotEvidenceKeyX
EnterprisePilotEvidenceKeyY
```

The corresponding ES256 private key belongs to the controlled Pilot
observer/attestation service. It is separate from release signing,
runtime-admission, plugin-admission, plugin-journal, brand-authorization,
lease, local-data-certification, and code signing. The Publisher checks this
separation before accepting evidence. Evidence contains only the attestation
key ID and signature; it cannot supply or replace the trusted public key.

The detached v2 envelope signs this exact domain-separated UTF-8 payload:

```text
ensou-dsh-enterprise-windows-pilot-evidence-attestation-v2
2
ensou-dsh-enterprise-windows-pilot-evidence-envelope
2
ensou-dsh-enterprise-windows-pilot-evidence-body
<body-size-bytes>
<lowercase-body-sha256>
```

The body hash covers the test-run ID, opaque customer audience ID, two device
lanes, readiness references, all five release tuples, all executable/process
hashes, local-data witnesses, and all 21 receipts. Replacing a PASS, tuple,
timestamp, process hash, or referenced file invalidates the attestation.

## Exact signed inventory

Use one pinned Authenticode signer and trusted timestamp on these final
executables:

1. `Ensou.Dsh.Enterprise.ReleasePublisher.exe`
2. `Ensou.Dsh.Enterprise.Installer.exe`
3. `Ensou.Dsh.Enterprise.Bootstrapper.exe`
4. `Ensou.Dsh.Enterprise.Launcher.exe`
5. `Ensou.Dsh.Enterprise.ClientBootstrapper.exe`
6. `Ensou.Dsh.Enterprise.Maintenance.exe`

Sign Launcher, ClientBootstrapper, and Maintenance before creating the client
archive. Embed that exact archive and the signed stable Bootstrapper into the
Installer, then sign the final Installer. Sign ReleasePublisher last. Do not
re-sign an executable after its digest enters readiness or Pilot evidence.

## Release and device lanes

Retain the exact `release-set.v2.json` bytes for this strictly increasing
sequence:

1. `baseline`
2. `first-update`
3. `second-update`
4. `failed-health-probe`
5. `recovery-target`

Every manifest, including the failed candidate and live recovery head, must
pass real ES256 manifest and artifact-signature verification using the release
key in the freshly replayed readiness config. The five release-set IDs are
distinct, sequence strictly increases, and generation never decreases. Do not
move the feed backwards to recover.

Use two native Windows x64 standard-user lanes: a clean installation and an
isolated legacy enterprise installation. Do not touch Personal Launcher roots.
Employee machines need no .NET, FNM, Node, npm, pnpm, Git, GitHub access, or
command line.

## The 21 receipts

Receipts are embedded, strict-schema structures in this order:

1. clean standard-user install
2. no visible console/application-error window for at least 15 minutes
3. tray surface open
4. real runtime start
5. WebUI open
6. unregistered WeCom employee denied
7. pre-registered employee scan reaches `READY`
8. exactly one device bound
9. second device denied
10. restart without another QR scan
11. first Pilot feed update
12. second consecutive update on the same installation
13. failed candidate health rollback
14. restored previous runtime restart
15. higher-sequence recovery target update
16. legacy enterprise migration
17. offline repair
18. device revocation lockout
19. API-policy revocation lockout
20. history preservation
21. workspace preservation

Receipt start/end times are strictly monotonic. The overall run and the
no-window observation each cover at least 15 minutes. Every receipt repeats the
test run, customer audience, device lane, exact active/rollback-target/attempted
release tuple, observed process executable SHA-256, state, network mode, and
result code. This proves both successful upgrades and that the failed candidate
returned to the previously healthy tuple before the recovery target advanced.

Receipt 2 is an active subprocess exercise, not a passive idle observation.
Follow the exact
[`Windows background-runtime Pilot gate`](../windows-background-runtime-pilot.md)
on both device lanes while starting DSH, opening WebUI, invoking a real shipped
plugin/tool descendant path, forcing a controlled runtime failure, restarting,
and exercising update health plus rollback. Any visible console, shell,
`dotnet.exe - Application Error`, unhandled-exception/Windows Error Reporting
dialog, repeated crash dialog, missing observation, or unexercised available
spawn path is `FAIL` or `BLOCKED`; it cannot be attested as `PASS`. The
Launcher root's `CreateNoWindow` flags and Job Object prove only root launch and
process-tree lifetime ownership, not descendant window suppression.

Raw logs, screenshots, video, and control-plane exports remain in a controlled
evidence store. The signed body contains only their evidence class, approved
redacted media type, byte count, SHA-256, and opaque custodian SHA-256. It does
not ingest arbitrary JSON/text and never relies on a secret-field blacklist as
the trust decision. The explicit denylist remains defense in depth.

## Contracts and verification

- `release/enterprise-windows-pilot-gate-contract-v2.json`
- `release/schemas/enterprise-windows-pilot-gate-contract-v2.schema.json`
- `release/schemas/enterprise-windows-pilot-evidence-collection-v1.schema.json`
- `release/schemas/enterprise-windows-pilot-attestation-request-v1.schema.json`
- `release/schemas/enterprise-windows-pilot-evidence-envelope-v2.schema.json`
- `release/schemas/enterprise-windows-pilot-evidence-body-v2.schema.json`
- `release/schemas/enterprise-windows-pilot-gate-receipt-v2.schema.json`
- `release/schemas/enterprise-windows-pilot-verification-report-v2.schema.json`
- `release/schemas/enterprise-pilot-readiness-v1.schema.json`
- `release/schemas/enterprise-pilot-readiness-report-v1.schema.json`

All input files are opened handle-first with no-follow semantics, bound to their
final DOS path and `FILE_ID_INFO` volume/file identity, read once, and held with
deny-write/delete sharing through Publisher execution. Every later path-based
consumer probes the same identity again. The signed Publisher returns its fresh
readiness replay as captured stdout JSON, so admission never trusts a child-
written pathname. The verifier writes that exact captured byte sequence as a
create-only convenience copy only after strict schema/tuple validation. Output
parents and newly created file handles are checked again by final path and
identity; output files are described only as **create-only**, not immutable.

The controlled observer supplies the two Windows x64 device inventories and 21
strict gate receipts as real-device inputs. After the observer custodian has
reviewed the retained raw evidence, assemble the exact canonical body and the
detached signing-service request with:

Run the Publisher-side collector and verifier with native Windows x64
PowerShell 7.4 or newer. These are controlled release tools; employee machines
do not run them.

```powershell
pwsh -NoProfile -File .\scripts\New-EnterpriseWindowsPilotEvidenceBody.ps1 `
  -CollectionPath C:\release-evidence\pilot\collection.v1.json `
  -BodyPath C:\release-evidence\pilot\evidence.body.v2.json `
  -AttestationRequestPath C:\release-evidence\pilot\attestation-request.v1.json
```

The collection schema admits only fixed release/executable paths, strict
clean-install and legacy-migration metadata, opaque lowercase SHA-256 values,
and the 21 receipt paths in the shared contract order. It has no token,
conversation, workspace-content, raw-log, free-text, or private-key field.
Missing lanes, receipts, tuples, hashes, the 15-minute observation, or readiness
audience/executable binding fail closed. Clean, legacy, and legacy-source
inventories must have distinct final paths, file identities, and SHA-256 values.
The body is compact UTF-8 without BOM or trailing newline, so the same inputs
produce identical bytes.

The request contains the exact seven-line signing payload and body hash. It has
`standaloneAdmissionEvidence: false` and `privateKeyUsed: false`; it is neither
an envelope nor an admission result, and contains no key ID or private-key
selector. The independent attestation service must use its configured Pilot
evidence key, then emit that configured key ID in the detached envelope. It must
validate the controlled raw observations and collection custody before signing
that payload with the external Pilot evidence private key. The repository
collector never accepts or uses that private key and does not fabricate device
observations.

```powershell
pwsh -NoProfile -File .\scripts\Test-EnterpriseWindowsPilotEvidence.ps1 `
  -EvidenceEnvelopePath C:\release-evidence\pilot\evidence.envelope.v2.json `
  -EvidenceBodyPath C:\release-evidence\pilot\evidence.body.v2.json `
  -PublisherExecutablePath C:\controlled-tools\Ensou.Dsh.Enterprise.ReleasePublisher.exe `
  -PublisherSignerSha256Thumbprint <64-hex-sha256> `
  -PublisherExecutableSha256 <lowercase-64-hex-sha256> `
  -ReadinessReplayReportPath C:\release-evidence\pilot\readiness.replay.v1.json `
  -ReportPath C:\release-evidence\pilot\verification.receipt.v2.json `
  -WindowsPilotVerifierPrivateKeyPath C:\controlled-keys\windows-pilot-verifier.pkcs8 `
  -WindowsPilotVerifierKeyId <configured-verifier-key-id>
```

The create-only receipt says `VERIFIED` or `REJECT` and declares
`standaloneAdmissionEvidence: false`. It has its own low-S ES256 IEEE-P1363
authentication over a domain-separated canonical report payload, using a
dedicated Windows-verifier P-256 key that is distinct from the Pilot evidence,
Stable, local-data, and Installer response keys. This authentication protects
the verifier's claims but does not make the receipt standalone admission
evidence. The key input is one locked, ordinary, non-reparse PKCS#8 P-256 file;
its bytes are cleared after import and are never written to the report or logs.
The independent ES256 envelope separately authenticates the body containing
`pilotDecision: ADMIT`. If verifier authentication, compiled trust, Publisher authenticity, readiness,
any manifest signature, live head, time window, tuple, process hash, or strict
schema cannot be established, production verification rejects.

Repository CI uses ephemeral test keys only. Its negative contract requires
rejection of forged PASS content, self-selected/embedded keys, fake readiness,
forged manifest signatures, equal timestamps, wrong tuples, secret fields,
concurrent replacement, pre-open reparse/ancestor replacement, output-parent
redirection, identity mismatch, and unsigned/self-asserted Publisher inputs.
