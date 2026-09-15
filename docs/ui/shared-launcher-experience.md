# Shared Launcher experience: simple by default, inspectable on demand

- Status: Accepted product requirement; implementation and real UI acceptance pending
- Confirmed: 2026-09-14, by ensou
- Publisher: Ensou Studio, for both Personal and Enterprise
- Architecture: [Local direct model and browser networking](../adr/0010-local-direct-model-and-browser-network.md)

## Product rule

First-pilot amendment, 2026-09-14: the owner prioritizes working DSH, independent automatic updates, and recovery, and accepts personally entering each employee's Key in the native DSH UI. The professional details surface and full administrator setup wizard below remain subsequent UI targets, not first-pilot blockers. Keep the first-pilot primary actions understandable, usable and accurately labeled; no new simulated-success UI is required to ship.

Use one state model and one interface with progressive disclosure, not separate beginner/professional products. The default surface answers: Can I use it now? What is happening? What should I do next? A collapsed details section explains the same state without changing authorization or update policy.

Personal and Enterprise share runtime, update, recovery, diagnostic semantics, and interaction components. Edition-specific identity and organization administration must not fork those semantics. Preserve upstream attribution and use Ensou Studio consistently as the Launcher publisher.

## Employee default surface

Show identity/organization when relevant, one plain-language status, one primary next action, and concise support guidance. Do not require a terminal, FNM installation, editing configuration, or copying an official Key. Hide ports, lease internals, file paths, certificate fingerprints, and protocol names from the ordinary start screen.

| Observed state | Plain-language presentation | Primary action |
| --- | --- | --- |
| Not signed in | Sign in to confirm who you are | Sign in using the edition's identity method |
| Approval pending | Your application is waiting for the administrator | View contact/help; continue bounded automatic polling |
| Credential configuration incomplete | Preparing this computer; not ready yet | Automatic recovery, or a safe retry if needed |
| Activated and ready | Ready to use | Start and open the local DSH WebUI |
| Managed runtime running | DSH is running on this computer | Open DSH |
| Verified update available | Preparing an update automatically | Continue current task while awaiting a safe switch |
| Management unavailable, existing valid activation | Management connection unavailable; current local use can continue | Open DSH if no observed deny prevents it |
| Provider request rejected | DeepSeek could not accept the request | Show actionable provider guidance; contact administrator for Key issues |
| Authoritative suspension already observed | Access stopped; contact your administrator | Contact/help, not a cached-start bypass |
| Update failed and recovery verified | The previous version was restored | Open DSH only if the restored version remains admitted |

Progress must reflect actual download/configuration/switch phases. Use an indeterminate indicator where no reliable fraction exists. Never display fabricated percentages, premature success, or a generic online status that conflates management, model-provider, and local-runtime health.

Closing the window explains tray behavior. Tray actions reopen Launcher/DSH without a command window. Exit, sign-out, credential changes, and actions that may interrupt a task need an explanation and appropriate confirmation; opening details must never interrupt work.

## Optional details and support

- Show Launcher and DSH versions separately, their admitted channel, last update-check time, download/switch/recovery phase, and verified rollback outcome.
- Distinguish identity approval, committed device activation, management connectivity, credential-configuration status, local-runtime health, and observed provider response. Unmeasured provider availability is unknown, not inferred from management connectivity or Key presence.
- Show the local WebUI address and workspace location only as useful details; never include credentials in a URL. Opening a workspace does not modify or relocate it.
- Explain direct model/browser routing and the configured update/management origin without query strings or secrets.
- Offer a human-readable error plus a stable error code and next action. Detailed error/support data must use a reviewed allowlist with redaction, not arbitrary exception text or raw log upload.
- A diagnostic summary may contain component versions, timestamps, state names, correlation identifiers, and sanitized error codes. Never export provider Keys, session tokens, activation codes, secrets, conversations, or workspace content. Copy/export must be user-initiated and previewable; no automatic support upload.
- Details are primarily read-only. They must not expose bypasses for signature checks, activation, observed suspension, or mandatory artifact withdrawal.

## Administrator surface

The normal task order is: select/register employee, record that employee's official Key securely, review device activation, approve, then inspect readiness. Distinguish assignment, delivery, protected local commit, and actual provider acceptance rather than calling them all 'configured'. A Key is not returned in employee-list/detail/readiness responses after submission.

Use ordinary labels and predefined reason choices where appropriate; generate operation identifiers automatically and move protocol identifiers into read-only details. Keep employee counts data-driven: a two-device acceptance test is not a two-employee product limit. Suspension must explain that actual official Key revocation is a separate administrator action in DeepSeek Platform.

## Full UI acceptance for the subsequent enhanced experience

1. Exercise real first activation, pending approval, interrupted configuration/recovery, daily reopening, update waiting/switch/failure, management outage/reconnect, and observed suspension. Simulated screens do not satisfy this acceptance.
2. Verify the same state in simple and detailed views; changing views cannot change authority or mask a failure.
3. Verify keyboard operation, readable focus, descriptive labels, and status announcements. Essential actions must not require hover.
4. On supported Windows 11 hardware, test window resizing and 100%, 125%, 150%, and 200% scaling. Wrap/stack controls and provide usable scrolling where necessary; do not clip primary actions or error/help text. Verify admin pages on a narrow mobile viewport as well.
5. With an owner-approved novice tester, verify installation, sign-in, pending-approval understanding, and opening DSH without developer coaching or a command line. Time-to-completion is measured during the test, not guaranteed by a mockup.
6. Inspect diagnostic displays/copy/export using synthetic sensitive inputs; verify secret redaction and local-data preservation. Re-run independent Launcher/DSH update acceptance after changing their runtime integration.

This document defines the required experience. It does not assert those controls, diagnostic exports, or the direct-mode integration have already been implemented.
