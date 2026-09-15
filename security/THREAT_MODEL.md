# Managed-update threat model

## Protected assets

- Employee local conversations and workspaces
- Company API credentials and authorization tokens
- Signing keys and code-signing identity
- Launcher, Harness runtime, and plugin package integrity
- Channel assignment and last-good state

## Trust boundaries

```text
Untrusted upstream/network
        |
        v
Reviewed GitHub source and candidate build
        |
        v
External signer + immutable release + approval
        |
        v
Company update origin
        |
        v
Employee Launcher -> local Harness
```

An approved Harness or plugin executes as the employee's Windows user and is therefore trusted code. Signing proves approved origin and integrity, not safety.

## Primary threats and controls

| Threat | Control |
|---|---|
| Upstream branch changes after review | Pin exact official tag and full commit; verify their relationship |
| Compromised Action tag | Pin Actions to reviewed full commit SHAs |
| PR exfiltrates secrets | Read-only PR jobs; no signing/deployment secrets; no `pull_request_target` |
| Candidate reaches employees accidentally | Candidate artifacts are ephemeral and explicitly not Stable-eligible |
| Release asset overwritten | Immutable GitHub Release and never-reused release id |
| Package modified in transit | HTTPS plus signed manifest, SHA-256, and byte-count verification |
| Malicious artifact path | Basename-only file names and safe extraction rules |
| Bad release prevents startup | Side-by-side immutable versions, health check, and last-good rollback |
| Runtime update destroys local data | Runtime/state separation and pre-migration snapshots |
| Old signed manifest replayed | Open risk in v1; add generation/expiry in v2 |
| Employee receives GitHub/API credentials | Client uses company update origin; no GitHub or provider keys in package |

## Fail-closed rules

- Reject unknown manifest fields, algorithms, key ids, channels, and schema versions.
- Reject signature failure before following the artifact URL.
- Reject a digest, size, file-name, or release-id mismatch.
- Reject archive traversal, absolute paths, links, and unexpected executable locations.
- Never delete current or last-good before the new runtime passes health checks.
- Continue the current verified runtime when the update origin is temporarily unavailable.
- Do not treat an API-provider outage as a reason to reset or delete the client or local data.
