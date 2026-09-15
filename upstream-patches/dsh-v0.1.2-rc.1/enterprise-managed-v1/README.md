# Enterprise managed DSH patch handoff

This directory is a deterministic reviewed-input candidate for the Launcher runtime build pipeline. It is not a fork, and the patch must never be applied to an arbitrary upstream revision.

Patch SHA-256: c5945fb046e4cb3d7897c99dc9f68404bcd5ab3352a322ce9063ae4d00723518 (252249 bytes, 4456 LF-terminated lines). Exact preimage and postimage byte lengths, SHA-256 values, and Git blob ids for all 43 changed files (8 added and 35 modified) are in manifest.json.

## Apply gate

1. Use an otherwise clean deepseek-ai/deepseek-harness checkout at tag dsh-v0.1.2-rc.1.
2. Verify that HEAD is exactly a66e4702047846cdaa10c66c9d3df3951f5ea70d and its tree is exactly 27ab636bb3d77e698f5637e518db44ae1f61e262.
3. Verify manifest.json, the patch byte length, LF line count, patch SHA-256, and every modified-file preimage.
4. Apply only with zero-context support and whitespace errors enabled: git -c core.autocrlf=false -c core.whitespace=-blank-at-eof apply --check --index --unidiff-zero --whitespace=error-all 0001-ensou-enterprise-managed-boot.patch, then repeat without --check.
5. Verify every postimage byte length, SHA-256, and Git blob id from the manifest before installing dependencies or building.

Any upstream tag, commit, tree, preimage, patch, postimage, path set, or semantic digest mismatch must stop the build. An upstream update requires a fresh rebase, review, test run, and regenerated handoff. This directory is not admitted merely because it was generated; signing, independent review, runtime tests, and controlled promotion remain separate gates.

## Required Launcher coupling

The Launcher must provide the exact managed signal, loopback proxy tuple, canonical bearer, managed skills root, fixed profile and Web arguments recorded in the manifest. It must remove NODE_OPTIONS, NODE_PATH, and NODE_EXTRA_CA_CERTS before starting the managed Node child. The Gateway must allow only deepseek-v4-flash for this profile and enforce max_tokens <= 8192.

Local conversations and workspaces remain local and writable by design. The managed guarantees apply only to a verified release set launched through the controlled Launcher path.

## Local data upgrade gate

The managed composition uses session-persistence-jsonl. It does not include session-persistence-sqlite; the remaining session-query-sqlite row is in-memory query support and is not a persistent store. The modern 0.1.2 source line removed the former optional SQLite persistence package. Before automatic upgrade, Launcher must detect evidence that an older installation used that optional persistent SQLite backend. If such evidence exists, automatic upgrade must stop and an operator must export the data with the old version first. This handoff does not claim or implement automatic SQLite-to-JSONL migration.
