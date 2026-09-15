# Enterprise managed DSH patch handoff

This directory is a deterministic reviewed-input candidate for the Launcher runtime build pipeline. It is not a fork, and the patch must never be applied to an arbitrary upstream revision.

Patch SHA-256: 726a72a09cab53c62991223e65744e1100cdb96df31790190f9cd124fb186e0c (222970 bytes, 3851 LF-terminated lines). Exact preimage and postimage byte lengths, SHA-256 values, and Git blob ids for all 41 changed files (8 added and 33 modified) are in manifest.json.

## Apply gate

1. Use an otherwise clean deepseek-ai/deepseek-harness checkout at tag dsh-v0.1.1-rc.2.
2. Verify that HEAD is exactly b150a551b8d465e31e418e1b2eaf5e79bbb7d28e and its tree is exactly 53915efe4e2126cc7779b73dfc8a3bcec5318c44.
3. Verify manifest.json, the patch byte length, LF line count, patch SHA-256, and every modified-file preimage.
4. Apply only with zero-context support and whitespace errors enabled: git -c core.autocrlf=false -c core.whitespace=-blank-at-eof apply --check --index --unidiff-zero --whitespace=error-all 0001-ensou-enterprise-managed-boot.patch, then repeat without --check.
5. Verify every postimage byte length, SHA-256, and Git blob id from the manifest before installing dependencies or building.

Any upstream tag, commit, tree, preimage, patch, postimage, path set, or semantic digest mismatch must stop the build. An upstream update requires a fresh rebase, review, test run, and regenerated handoff. This directory is not admitted merely because it was generated; signing, independent review, runtime tests, and controlled promotion remain separate gates.

## Required Launcher coupling

The Launcher must provide the exact managed signal, loopback proxy tuple, canonical bearer, managed skills root, fixed profile and Web arguments recorded in the manifest. It must remove NODE_OPTIONS, NODE_PATH, and NODE_EXTRA_CA_CERTS before starting the managed Node child. The Gateway must allow only deepseek-v4-flash for this profile and enforce max_tokens <= 8192.

Local conversations and workspaces remain local and writable by design. The managed guarantees apply only to a verified release set launched through the controlled Launcher path.
