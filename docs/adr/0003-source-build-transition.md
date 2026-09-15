# ADR 0003: Source-derived runtime candidate gate

- Status: Accepted
- Date: 2026-08-23

## Context

The existing runtime packaging script installs the published `@deepseek-ai/dsh` package and its dependency closure. This is useful for quickly reproducing a known version, but it is not evidence that a package was built from the reviewed official source commit.

The managed product is expected to distribute a source-derived Harness runtime while employees remain free of build tools.

## Decision

The managed candidate workflow uses only the enterprise-managed source-builder path. It must:

1. fetch the reviewed upstream commit and tag from the canonical HTTPS repository and verify the exact 40-character commit and tree;
2. select one installation-owned patch only through `upstream-patches/index.json`, verify its exact manifest/patch digests, 33 modified preimages, apply-check, exact 41-path delta, and all postimage byte/SHA-256/Git-blob identities;
3. copy the clean official checkout's `.git` metadata and tracked files into an independent, link-free, disjoint `OutDir` staging directory (never its ignored `node_modules`); never install, clean, build, or apply a patch in the official checkout, and compare its Git identity plus filesystem inventory before and after;
4. require the managed workspace root to come from `process.cwd()` and reject a restored session whose recorded cwd differs, then install with the patched frozen lockfile and run managed boot/sandbox/capability tests, changed-package/CLI type and bundle gates, generated contracts, release/license gates, and the full CLI/Web build only in patched staging;
5. deploy a non-legacy, lockfile-backed production closure in offline mode and reject every unresolved required dependency or peer;
6. prove that every workspace package has the reviewed patched-source version and every external package identity exists in the patched lockfile;
7. fully materialize the runtime and reject reparse points, build paths, Git/patch/npm/pnpm tooling, or patch inputs;
8. extract the completed ZIP into a disjoint directory with ambient Node injection removed, then repeat version, native-module, exact managed environment/profile/no-Web-alias/workspace-cwd HTTP health, and missing-signal/wrong-profile/extra-argument refusal smokes.

The legacy `build-runtime.ps1` npm-package assembler remains available only for engineering diagnosis. It is not called by the managed candidate workflow and cannot be promoted to Pilot or Stable.

Employees receive only the signed finished runtime through the company update origin. They never clone GitHub and never receive FNM, npm, pnpm, Git, patch tooling, patch inputs, the source checkout, build paths, or build credentials.

## Consequences

- The repository now has a fail-closed enterprise-managed source-candidate implementation instead of labeling either an npm package or an unpatched upstream build as an enterprise candidate.
- Any upstream tag/commit/tree change fails closed until a new patch rebase, manifest, policy digest, tests, and security review are indexed. No compatibility fallback applies an old patch to a new upstream base.
- A script or workflow definition is not build evidence. Stable remains blocked until a clean Windows runner completes the full build, the resulting ZIP passes independent verification, and Lab/Pilot evidence exists.
- The first candidate workflow run publishes the source runtime ZIP, metadata, and SHA evidence as an immutable GitHub prerelease in an isolated write-token job after re-downloading the exact read-only build output. Authenticode for Ensou-authored Launcher/Bootstrapper/installer files, redistribution review, channel signing, and company-origin publication remain separate gates. The source runtime ZIP is already the final runtime byte identity: third-party runtime files are not re-signed after its per-file and ZIP hashes are established.

## References

- https://github.com/deepseek-ai/deepseek-harness/blob/master/package.json
- https://github.com/deepseek-ai/deepseek-harness/blob/master/docs/development.md
