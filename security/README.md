# Release security boundary

This directory defines the security boundary for Launcher builds and managed updates. It is not evidence that production signing or deployment is configured.

## Required repository controls

Configure a Ruleset for `main`:

- require pull requests and required CI checks;
- block branch deletion and force pushes;
- require signed commits when the contributor workflow supports it;
- require resolved review conversations;
- use one independent approval when a second maintainer is available;
- permit no broad administrator bypass for `main`.

The repository **must have GitHub Immutable Releases enabled** before
`build-candidate.yml` is admitted. Under the current GitHub plan,
the release chain does not rely on tag rulesets; they are not a prerequisite
for this private repository. A tag ruleset may still be added later as defense
in depth.

`build-candidate.yml` publishes an asset-free immutable prerelease that
permanently consumes only the create-once `release_id`. That reservation
Release is not an artifact publication and never receives build assets. The
signed, artifact-bearing immutable Release is a separate later gate and
publication.

All workflow jobs declare minimum permissions. Third-party Actions must use a reviewed full 40-character commit SHA. `pull_request_target` and `write-all` are prohibited by CI.

## Current workflow capabilities

| Workflow | Reads | Persistent mutation | Employee impact |
|---|---|---|---|
| CI | Repository checkout | None | None |
| Build candidate | Official upstream and package registry during frozen install | Asset-free immutable reservation Release plus 14-day unsigned source-candidate artifact | None |
| Validate promotion | Immutable GitHub Release ZIP plus matching source-build metadata | 14-day validation receipt | None |
| Upstream watch | Official GitHub Release API | None | None |

The production signer, immutable artifact-bearing Release publisher, company download-origin uploader, and channel-pointer writer are intentionally absent. Adding any of them requires an explicit authorization and threat review.

## Secrets

Never store any of the following in Git, workflow YAML, build artifacts, logs, Launcher configuration, or employee packages:

- manifest-signing private keys;
- Windows code-signing private keys;
- DeepSeek API keys;
- GitHub personal access tokens;
- company download-origin administration credentials;
- employee identity or device tokens.

Prefer an external KMS/HSM-backed signing service and short-lived GitHub OIDC identity. A production signer must validate repository, workflow, protected environment, ref, source commit, release id, and artifact digest claims before signing.

## Employee-client boundary

The employee Launcher must not contain GitHub credentials or call GitHub private-repository APIs. It reads HTTPS manifests from the company update origin, verifies the embedded trust key and package digest, and keeps using last-good when update discovery or download is unavailable.

Conversations, prompts, responses, file contents, API headers, and user workspace paths must not be included in release telemetry or diagnostic uploads.

## Known open risks

- Manifest version 1 has no generation counter or expiry. Replay resistance is deferred to version 2.
- A local Windows source-candidate build has completed, but a clean ephemeral or production-equivalent runner replay and independent release review have not.
- No production signer, code-signing service, download origin, or deployment adapter is configured.
- No employee installer or Launcher self-update feed is implemented.
- Per-user program directories are writable by that same Windows user; machine-managed ACL and repair policy remain an enterprise hardening decision.
- Bundled third-party runtime files are authenticated as one immutable package by the signed manifest and per-file inventory; they are not re-signed with the Ensou Authenticode identity.
- The example manifest signature is intentionally invalid and must never be trusted.
