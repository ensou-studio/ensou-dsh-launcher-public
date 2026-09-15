# Enterprise managed DSH patch handoff

This directory contains the three deterministic inputs for the Launcher runtime build pipeline. It is not a fork, and the patch must not be applied to an arbitrary upstream revision. The patch is generated with zero context so its stored bytes contain no structural context-marker whitespace; the exact preimage and postimage gates provide the application boundary.

Patch SHA-256: `e4f9e5166b9081247359fe796ae626b31eceda1d438777a6e4a9d0c14096e673` (219488 bytes, 3804 LF-terminated lines). Exact preimage and postimage byte lengths, SHA-256 values, and Git blob ids for all 41 changed files (8 added and 33 modified) are in `manifest.json`.

## Apply gate

1. Use an otherwise clean `deepseek-ai/deepseek-harness` checkout at tag `dsh-v0.1.0-rc.7`.
2. Verify that `HEAD` is exactly `99f6f02fecdb7dff40c3fbc9470f5907c29f74ca` and its tree is exactly `3bc8f89fe494a4755c188be354add4e8b1e7b188`.
3. Verify `manifest.json`, the patch byte length, LF line count, and patch SHA-256.
4. Verify every modified-file preimage in the manifest.
5. Run `git -c core.autocrlf=false -c core.whitespace=-blank-at-eof apply --check --index --unidiff-zero --whitespace=error-all 0001-ensou-enterprise-managed-boot.patch`. Disabling only `blank-at-eof` avoids zero-context false positives; canonical generation and postimage `diff --check` still reject actual trailing whitespace.
6. Apply with `git -c core.autocrlf=false -c core.whitespace=-blank-at-eof apply --index --unidiff-zero --whitespace=error-all 0001-ensou-enterprise-managed-boot.patch`.
7. Verify every postimage byte length, SHA-256, and Git blob id from the manifest.
8. Run `pnpm install --frozen-lockfile` with pnpm 11.7.0 and Node.js 24.19.0, then build only after the repository checks pass.

Any upstream tag, commit, tree, preimage, patch, or postimage mismatch must stop the build. An upstream update requires a fresh rebase, review, test run, and regenerated handoff.

## Required Launcher coupling

The managed runtime advertises and selects only `deepseek-v4-flash`, with a fixed output budget of 8192. The control Gateway must allow that exact model id and enforce `max_tokens <= 8192`; the Harness catalog is not an authorization boundary.

The Launcher must supply the exact inherited-process signal `DSH_ENTERPRISE_MANAGED_BOOT=ensou-dsh-launcher/v1`, matching exact `DEEPSEEK_BASE_URL=http://127.0.0.1:<port>/v1` and `DEEPSEEK_SEARCH_BASE_URL=http://127.0.0.1:<port>/v1`, one canonical 32-byte base64url `DEEPSEEK_API_KEY`, and one canonical non-reparse managed skills root in `ENSOU_DSH_ENTERPRISE_SKILLS_ROOT`.

The exact CLI argument sequence is `dsh --profile enterprise-managed --host 127.0.0.1 --port <port>`, where `port` is a canonical decimal integer from 1 through 65535. There is no `web` positional token. The Launcher must not pass `--trusted-host`, duplicate or aliased Web flags, extra Web arguments, or user-editable patch, plugin, dump, model, provider, or preset arguments.

Before creating the managed Node child, remove `NODE_OPTIONS`, `NODE_PATH`, and `NODE_EXTRA_CA_CERTS` from that child's environment. This Launcher integration remains outside the DSH patch.

## Enforced managed composition

The managed runtime fixes sandbox default and hard maximum to `workspace-write`, approval to `ask`, and the permission table to the single `workspace-write` preset. Model and permission selectors are disabled. Restored legacy sessions and per-call danger requests remain capped at `workspace-write`.

The workspace root is locked to Launcher-owned `process.cwd()`. A restored session whose canonical cwd differs from that root fails closed before filesystem, shell, terminal, or replacement execution. Ordinary profiles retain their existing per-session cwd behavior.

Managed plugin imports use a deeply frozen exact specifier-to-installation map created from the installation-owned base and Web bundles. Unknown, equivocal, outside-installation, reparse-point, shadow, cwd, user, and project fallback resolution fails closed. The managed preset exposes only the Launcher-supplied skills root; ambient user, agent, bundled, project, and cwd skill roots are not searched.

The manifest records separate canonical SHA-256 values for host composition, preset composition, preset metadata, and the Loader root. These semantic digests and directory inventories fail on unexpected managed content.

## Security boundary

The exact signal and reserved profile select the managed path; they do not protect against the same local Windows user directly invoking an ordinary profile or replacing an unprotected runtime. Managed guarantees apply only to the verified release set launched through the controlled Launcher path. The installer must protect release artifacts with appropriate operating-system controls. Local conversations and workspaces remain local and writable by design.

## Verification checklist

- Focused managed CLI, composition, trusted plugin-resolution, preset-tree, managed-skill, ordinary-profile, Web-argument, sandbox-policy, and capability tests.
- Node.js 24.19.0 TypeScript checks, pnpm 11.7.0 package checks, host bundle, repository lint, generated-contract checks, and `git diff --check`.
- Exact pinned-base preimage verification, `git apply --check`, isolated indexed application, postimage verification, and byte-identical regeneration check.
