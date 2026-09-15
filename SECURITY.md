# Security Policy

## Project status

Ensou DSH Launcher is currently a paused engineering and learning project. This repository does not designate a production-certified or supported Stable/Pilot binary. Historical channel names, test reports and successful local checks must not be interpreted as a production support commitment.

Do not deploy a source build with real employee credentials or sensitive workspaces merely because it compiles. Example domains, test keys and synthetic identities are not production configuration.

## Reporting a vulnerability

Use GitHub Private Vulnerability Reporting when it is available:

https://github.com/ensou-studio/ensou-dsh-launcher-public/security/advisories/new

If private reporting is unavailable, open an Issue containing only a request for a private security contact. Do not include the vulnerability details until a private channel is established.

Never publish API Keys, signing private keys, activation codes, employee information, conversation contents, prompts, responses or workspace files. Test only systems and devices for which you have authorization.

## Safety boundaries

- Public source and GitHub Actions output do not certify an installer or update feed.
- Release artifacts require their own authentic provenance and signature verification.
- Repository examples must not be substituted for a production trust configuration.
- Updating, recovery and uninstall operations must preserve user-owned conversations and workspaces.
- Enterprise server operations and real customer deployments are outside this public repository's support scope.

Historical threat models and release-design notes are retained under `security/` and `docs/`; evaluate them against the particular branch and commit being studied.
