# Release-signing policy

## Two independent signatures

1. Windows Authenticode signs Ensou-authored executable files and installers so Windows can identify the publisher. Bundled third-party runtime files retain their upstream signatures and are not re-signed as Ensou software.
2. The ES256 manifest signature authorizes an exact channel document and artifact digest for Launcher consumption.

One signature does not replace the other.

## Manifest-signing key

- Generate and retain the private key in an enterprise KMS, HSM, or equivalent non-exportable signing service.
- Embed only public trust keys in the Bootstrapper/Launcher.
- Do not export the private key into a repository or GitHub Actions secret.
- Require a protected release identity and an immutable artifact digest for every signing request.
- Log key id, source repository, source commit, release id, channel, artifact SHA-256, approver, and signing time. Do not log tokens or user data.

## Signing procedure

1. Verify that the release id has never been used for different bytes.
2. Verify the source and upstream provenance gates.
3. Verify Authenticode signatures for Ensou-authored executable content, preserve any upstream signatures on bundled third-party files, and verify the runtime per-file hash inventory.
4. Verify package SHA-256 and byte count.
5. Construct the exact version 1 unsigned payload in the fixed field order from ADR 0002.
6. Sign its compact UTF-8 bytes with ECDSA P-256/SHA-256.
7. Convert the IEEE-P1363 64-byte signature to unpadded Base64URL.
8. Add the three-field `signature` object.
9. Re-parse and independently verify the final document before publication.

## Key rotation

Ship the next public key in a signed Launcher update before using it to sign manifests. Keep the old key trusted during an overlap window. Stop using the old private key, then remove the old public key only after supported clients have received the new trust set.

If a private key may be compromised, stop channel publication, remove the affected manifest at the company origin, block the key server-side, and ship a separately trusted Launcher/Bootstrapper recovery update. A version 2 delegated-root design should replace this manual process before external distribution.

## Test keys

`example-key-not-for-production` and the all-zero signature in `release/examples` are schema fixtures only. Production code must reject that key id.
