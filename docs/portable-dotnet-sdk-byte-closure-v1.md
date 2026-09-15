# Portable .NET SDK byte closure v1

This contract records the exact file bytes of the portable Microsoft .NET SDK used by the Windows production builder. Its only admitted target is .NET SDK `10.0.302` for `windows` `x64`.

The closure removes an external SDK installation from the build trust boundary. It does not authorize signing, Pilot distribution, Stable promotion, or employee/customer deployment. Production admission remains `NO_GO` until the resulting installer is signed and the required Pilot evidence is accepted.

## Contract

Instances must validate against `release/schemas/portable-dotnet-sdk-byte-closure-v1.schema.json`. Unknown fields are rejected at every object level.

| Field | Required value or meaning |
| --- | --- |
| `contract` | Exact value `portable-dotnet-sdk-byte-closure-v1`. |
| `sdkVersion` | Exact value `10.0.302`. |
| `os` | Exact value `windows`. |
| `architecture` | Exact value `x64`. |
| `archiveSource.url` | Final HTTPS URL on `builds.dotnet.microsoft.com` or `download.visualstudio.microsoft.com`; user information, query strings, fragments, redirects, and non-canonical path forms are not admitted. |
| `archiveSource.officialMicrosoft` | Exact value `true`. This is an assertion that must be independently checked during source review. |
| `archiveSha512` | Lowercase 128-character hexadecimal SHA-512 of the original ZIP bytes. |
| `fileCount` | Exact number of regular files in `files`; from 1 through 16,384. Directory marker entries do not count. |
| `totalSizeBytes` | Exact sum of all `files[].sizeBytes`; from 1 byte through 4 GiB (`4294967296`). |
| `inventorySha256` | Lowercase hexadecimal SHA-256 of the canonical `files` array described below. |
| `files` | Complete ordered inventory of the uncompressed regular files. Each object contains only `relativePath`, `sizeBytes`, and `sha256`. |

The schema validates shape and scalar limits. The trusted builder must also enforce the cross-field, ordering, archive, and filesystem rules in this document. Schema validation alone is not byte-closure evidence.

## Official ZIP source review

The networked acquisition step must establish that the URL and SHA-512 belong to Microsoft's official release metadata for exactly SDK `10.0.302`, Windows, and x64. The reviewer must inspect the final URL rather than trusting a shortened URL or redirect. The `officialMicrosoft: true` marker records the completed review; it is not evidence by itself.

The original downloaded ZIP is hashed before extraction. A SHA-512 mismatch, a different SDK version, a different operating system or architecture, a redirect-only source, or a source outside the admitted Microsoft hosts fails closed.

After review, copy the exact verified ZIP and its closure document into a private, access-controlled, create-new temporary location. Do not publish this temporary copy as a launcher payload or treat a mutable download cache as production input. The copied ZIP must retain the exact `archiveSha512` before it crosses into the offline production build boundary.

## File inventory rules

Each `relativePath` is the ZIP entry's logical file path after changing separators to `/`. It must be relative, must not contain a drive or UNC prefix, `\`, empty segments, `.` or `..` segments, NUL characters, alternate-data-stream syntax, any segment longer than 255 characters, or a form that aliases another Windows path. A verifier must reject symbolic links, reparse-point entries, device names, and case-only or Windows-normalization collisions.

Only regular files appear in `files`. Empty files are valid and use `sizeBytes: 0`; the SDK contains intentional zero-byte files. `sha256` is calculated over the exact uncompressed file bytes, including for empty files.

Sort `files` by `relativePath` using ordinal, case-insensitive comparison. The order must be strictly increasing, so paths that compare equal under `OrdinalIgnoreCase` are invalid even when their spelling or file bytes differ. `fileCount` must equal the array length, and `totalSizeBytes` must equal the checked sum of every `sizeBytes` value without overflow.

To calculate `inventorySha256`, serialize only the `files` array as UTF-8 without a byte-order mark or trailing newline. Use a compact JSON array, preserve the validated array order, and emit each object's properties in this exact order: `relativePath`, `sizeBytes`, `sha256`. JSON strings use RFC 8259 escaping, integers use base-10 digits without leading zeroes, and hashes remain lowercase. Hash those exact UTF-8 bytes with SHA-256.

## Production offline use

The production builder must operate with network access disabled and use only the private verified copy. It must:

1. Validate the document against the schema and enforce every semantic rule above.
2. Recompute `archiveSha512` from the copied ZIP before reading any entry.
3. Inspect the ZIP without trusting entry paths, reject unsafe or non-regular entries, and recompute the complete uncompressed inventory.
4. Recompute `fileCount`, `totalSizeBytes`, and `inventorySha256` and require exact equality.
5. Extract into a new private directory without overwriting existing paths, then verify the extracted tree has the same path, size, and SHA-256 inventory.
6. Invoke only the closed SDK bytes for restore and publish; a machine-installed SDK, mutable SDK cache, fallback resolver, or network restore is forbidden.

Any missing, additional, reordered, renamed, case-colliding, or changed file fails closed. A valid byte closure closes only the portable SDK prerequisite. The release remains `NO_GO` until installer signing and timestamp validation succeed, the exact signed bytes complete the required Windows Pilot, and the later promotion gate accepts those exact receipts.

## Offline module handoff

`release/scripts/PortableDotNetSdkClosure.psm1` separates directory-only compatibility from the original-ZIP production path:

- `Open-PortableDotNetSdkClosure` verifies a pre-existing directory against a lock, but records `LOCK_ONLY`. It cannot authorize SDK executable access for a production build.
- `Open-PortableDotNetSdkArchiveClosure` opens and locks the reviewed lock and exact `dotnet-sdk-10.0.302-win-x64.zip`, recomputes the ZIP SHA-512 and every uncompressed file digest, and creates the extraction directory only after the full inventory matches. The extraction destination must not exist and its ordinary local parent must already exist. The caller must provision that parent as an access-controlled work location with no concurrent writer; ordinary-path validation does not establish ACL ownership.
- `New-PortableDotNetSdkPrivateCopy` creates a second create-only directory, copies the locked files, verifies every copied byte, and owns a separate read handle for the reviewed lock. The returned closure therefore remains usable after the archive-source closure is closed.
- `Get-PortableDotNetSdkPrivateToolchain` accepts only an authentic ZIP-bound private-copy closure. It obtains the root `dotnet.exe` and all evidence from module-private records rather than caller-mutable public properties.

The production caller must keep the private closure open for the entire restore/publish child-process lifetime and use only `DotnetPath` returned by `Get-PortableDotNetSdkPrivateToolchain`. The module performs no download and must be called only after the ZIP and reviewed lock have crossed into the offline build boundary.

```powershell
Import-Module .\release\scripts\PortableDotNetSdkClosure.psm1 -Force

$source = Open-PortableDotNetSdkArchiveClosure `
    -ArchivePath C:\offline-input\dotnet-sdk-10.0.302-win-x64.zip `
    -LockPath C:\offline-input\portable-dotnet-sdk-10.0.302-win-x64.lock.json `
    -ExtractionDirectory C:\offline-work\sdk-source
try {
    $private = New-PortableDotNetSdkPrivateCopy `
        -SourceClosure $source `
        -DestinationDirectory C:\offline-work\sdk-private
    try {
        $toolchain = Get-PortableDotNetSdkPrivateToolchain -Closure $private
        # Pass only $toolchain.DotnetPath to the trusted offline builder.
    }
    finally {
        Close-PortableDotNetSdkClosure -Closure $private
    }
}
finally {
    Close-PortableDotNetSdkClosure -Closure $source
}
```

Closing a closure releases file handles but never deletes caller-owned directories. If extraction or copying fails after a create-only directory was made, the partial directory is deliberately retained and cannot be reused; an owning caller may remove it only after independently proving the cleanup path is its exact private work location.
