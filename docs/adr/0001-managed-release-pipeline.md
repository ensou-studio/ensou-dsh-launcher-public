# ADR 0001: Managed release pipeline and update-source boundary

- Status: Accepted
- Date: 2026-08-23

## Context

Employees run DeepSeek Harness locally on Windows and should not need Git, FNM, Node, pnpm, PowerShell, or GitHub credentials. Upstream releases are frequent and may include incompatible storage changes. Directly cloning or pulling upstream on employee devices therefore produces inconsistent environments and unsafe updates.

## Decision

Use a private GitHub repository as the source, CI, review, and immutable-release authority. Employees never clone it. A separate company download origin serves signed channel manifests and immutable packages to Launcher clients.

```text
Official DSH release
        |
        v
Pinned review PR -> Candidate build -> Immutable GitHub Release
                                         |
                          Lab -> Pilot -> Stable approval
                                         |
                                         v
                              Company download origin
                                         |
                                         v
                               Employee Launcher/client
```

The release unit is an immutable `managed-vYYYY.MM.DD.N` identifier. Lab, Pilot, and Stable reuse the same package bytes and SHA-256. Promotion creates a newly signed channel manifest; it does not rebuild or overwrite an artifact.

The candidate's source/runtime metadata is captured with those immutable bytes. Promotion validates that captured metadata and never rebinds an existing candidate to the repository's current upstream lock; advancing `versions/locked.json` therefore cannot strand a candidate already moving through Lab/Pilot/Stable.

Git branches do not represent deployment channels. `main` is the only long-lived source branch. Channel state lives at the download origin and is changed only through a separately authorized deployment operation.

## Repository automation boundary

- `ci.yml` validates contracts, workflow pins, and later the .NET solution.
- `build-candidate.yml` permanently reserves the release ID, builds with `contents: read`, and in a separate first-run-only `contents: write` job publishes the exact re-downloaded and verified ZIP/metadata/SHA assets as an immutable GitHub prerelease. It never publishes an employee channel update.
- `promote.yml` validates an immutable GitHub Release and creates a short-lived validation receipt. It intentionally has no download-origin mutation capability.
- `upstream-watch.yml` is read-only. It reports a newer official release but never edits a lock, opens a PR, builds, or promotes.

The production deployment adapter is intentionally absent until the company download origin, approval authority, and signing service are explicitly authorized and configured.

## Data boundary

Runtime releases are replaceable. User-owned Harness state and workspaces are not release assets and must remain outside the runtime tree. Installing, updating, rolling back, revoking access, or repairing the runtime must not delete local conversations or workspaces.

## Consequences

- Employees receive a game-launcher-like update experience without GitHub access.
- A bad candidate cannot reach employees from the current workflow skeleton.
- The immutable artifact-bearing GitHub candidate is created in the same first workflow run. Application/channel signing and company-origin publication remain separate authorization gates before employee promotion.
- Full source-built Stable releases require the source-build transition described in ADR 0003.

## References

- https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases
- https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets
