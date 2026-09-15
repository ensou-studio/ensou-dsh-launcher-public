# ADR 0002: Version 1 signed channel-manifest contract

- Status: Accepted
- Date: 2026-08-23

## Context

The Launcher and release service need one exact signature contract. Competing canonicalization rules or permissive JSON parsing would allow producer/client drift and ambiguous verification.

## Decision

Version 1 accepts only the fields declared by `release/schemas/channel-manifest.schema.json`. Unknown fields are rejected.

The artifact in this contract is a DSH runtime only. `launcherVersion` is the minimum compatible Launcher version, not a second artifact version and not an instruction to install the DSH ZIP as Launcher. Launcher self-update is an independent Bootstrapper transaction. `minimumBootstrapperVersion` is likewise a compatibility floor.

The top-level serialization order for the signed payload is fixed:

```text
schemaVersion
releaseId
channel
launcherVersion
dshVersion
publishedAtUtc
minimumBootstrapperVersion
artifact
```

The nested artifact order is fixed:

```text
url
fileName
sizeBytes
sha256
```

The `signature` property is excluded. `publishedAtUtc` is normalized to exactly `yyyy-MM-ddTHH:mm:ss.fffffffZ`, including seven fractional digits and UTC `Z`. JSON integers are base-10 digits without quotes, leading zeroes, exponent, or decimal point.

Every version 1 string field is constrained to printable ASCII. In addition, the artifact URL rejects quotes, backslashes, whitespace, user information, and fragments. These constraints mean canonical string values require no JSON escape sequences; a producer must reject, not normalize, an out-of-contract value. The remaining document is emitted as compact UTF-8 JSON without BOM, whitespace, or trailing newline.

The signature algorithm is ES256: ECDSA P-256 with SHA-256. The signature representation is fixed-width IEEE-P1363 `r || s` (64 bytes) encoded as unpadded Base64URL. `release/examples/canonical-payload-v1.vector.json` is the cross-language payload/digest/public-key/signature test vector and is part of this decision.

The `signature` object contains only:

```json
{
  "algorithm": "ES256",
  "keyId": "release-key-id",
  "value": "base64url-signature"
}
```

The client rejects duplicate JSON properties, invalid field order during canonical payload production, unknown properties, unknown algorithms, unknown key ids, padded Base64, non-64-byte signatures, non-HTTPS URLs, unsafe file names, and malformed lowercase SHA-256 values.

Signature verification occurs before the artifact URL is used. Artifact SHA-256 and byte size are then verified before extraction or activation.

## Version 2 backlog

Anti-rollback generation counters, manifest expiry, upstream commit provenance, key-delegation metadata, and multi-component artifact plans are desirable but intentionally omitted from version 1. They require a coordinated schema and client version increment; adding them to a version 1 document would correctly fail closed.

## Consequences

- The .NET client and signer have one small deterministic contract.
- Example manifests can be shared as cross-language signature fixtures once a test key is introduced.
- Version 1 does not independently prevent an update origin from replaying an older correctly signed manifest. The Launcher must retain last-good state, and version 2 anti-rollback work is required before a hostile-origin threat is considered closed.

## References

- https://www.rfc-editor.org/rfc/rfc7518#section-3.4
