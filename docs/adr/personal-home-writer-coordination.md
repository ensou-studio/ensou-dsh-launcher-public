# Personal Harness-home writer coordination

Status: Accepted for implementation; installer and update acceptance pending

Date: 2026-09-07

## Context

The pre-change Personal installer rejects every Node process on the computer. The real development installer probe confirmed that this blocks ordinary development desktops even when those processes do not use the Personal Harness home. The existing threat model trusts approved runtime/plugin code sharing the user identity; this change does not establish isolation against arbitrary same-user programs.

The bounded change coordinates managed writers of one canonical home. It retains signed release admission, exact runtime inventory checks, complete home snapshots and measurements, write-denying handles, same-volume rename, health nonce verification, and rollback.

## Decision

`PersonalHarnessHomeCoordinator` uses a fixed sibling directory, `<canonical-home-parent>/.ensou-dsh-home-coordination/<sha256(user-sid + canonical-home)>`. This location is independent of the managed installation layout and outside the renameable home and program trees. Relative paths, network paths, filesystem links, and the reserved sidecar name are rejected. Existing ancestors are retained with directory handles that deny deletion; native leaf opens reject reparse points and linked lock files. Native calls use extended local paths to support long private installation paths.

An exclusive `home.lock` and strict `state.v1.json` record cooperate across processes. Empty homes enroll directly; a previously nonempty unenrolled home requires an explicit one-time conservative admission callback. After enrollment the caller uses a scoped port check and this lease, rather than enumerating all Node process names.

`AcquireLease` returns `PersonalHarnessHomeLease`. `RequireMutationAdmission(home)` checks the held lease's canonical destination and writer quiescence. `BeginRuntimeSession` retains a separate reference, so disposing the caller's reference does not release admission while the runtime session exists. A health caller can retain its outer lease across Host stop, candidate measurement, and health signaling.

The Host receives an optional `Func<IDshHomeWriterSession>` and acquires it before creating runtime data/log directories. With no callback supplied, Enterprise admission remains on its existing path. A generation is durably recorded before process creation. The runtime is created suspended, assigned to its exact unique named Job, recorded, and validated before resume. Name collisions are rejected before applying Job settings or assigning a process.

`WindowsJobObject.Dispose` closes further assignment, terminates its exact owned members when necessary, verifies zero active members, and then records `owned-job-empty`. Disposal of a session alone never records clean termination. A failure before `CreateProcess` is called can explicitly record `never-started`. The existing retained containment resources also retain the home session until cleanup completes.

## Cross-process handoff

Lock order is update-operation lease, home lease, existing transaction lock. A normal runtime takes only the home lease. The updating owner stops its runtime before acquiring home mutation admission.

Prepare and pending-pointer activation occur under the home lease. The update coordinator releases that lease before waiting for the health child. The child independently acquires the home lease and validates the pointer, transaction, and token; it never reacquires its parent's update-operation lease. Pending state fences normal launches during this handoff. The parent reacquires the home lease before consuming health, committing, or restoring.

`AdmitHealthAttempt` binds a transaction and token digest once. `BeginRuntimeSession` binds its generation. `CompleteHealthAttempt` and `RequireCompletedHealthAttempt` require the same generation, an assigned runtime PID, and specifically `owned-job-empty` evidence. Recovery-only evidence cannot manufacture completed health. An admitted unfinished attempt cannot be overwritten. An old completed attempt may be replaced for a different transaction. After actual restore or commit, `AbortHealthAttempt(transactionId)` clears only that transaction; no attempt and a different completed attempt are no-ops, while a different admitted attempt is rejected.

Launcher-only release changes retain the existing no-home branch and do not acquire this coordinator.

## Crash recovery and boundary

A parent-held lock disappearing is not proof that Job children have finished exiting. Root-Node handle inheritance would also not prove that every plugin descendant retained the handle. Neither assumption is used.

An obtainable exact named Job with zero active members permits recovery. Missing or inaccessible Job names remain unknown. Windows documentation describes kill-on-close and Job destruction, but this implementation does not infer completed child exit from name lookup failure. See [Microsoft Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects).

The state seals native `kernel32!GetTickCount64` as an unsigned value before runtime admission. A current value strictly smaller than the saved value is sufficient one-way evidence of an ended kernel uptime epoch. Equal or larger values prove nothing; an unconfirmed recovery attempt may seal the larger current value for a subsequent retry. No UTC comparison, WMI boot-time estimate, experimental boot identifier, or user assertion of reboot clears state. Native tick time includes sleep and hibernation. See [Windows Time](https://learn.microsoft.com/en-us/windows/win32/sysinfo/windows-time) and [Microsoft timing guidance](https://learn.microsoft.com/en-us/windows/win32/sysinfo/acquiring-high-resolution-time-stamps).

A very early crash followed by a late retry, Fast Startup, inaccessible Job state, or insufficient reset evidence can still require maintenance after a Windows restart. This is deliberately conservative and is not a claim that every restart is recognized automatically. Recovery records `epoch-reset` or `recovered-job-empty`, distinct from owned health completion.

Supported simultaneous writers are Launcher-managed runtimes and approved descendants contained by their Job. Manually started DSH against the same home must remain stopped during migration/update. Existing file exclusions and measurements remain safeguards, but arbitrary manual same-user writes are outside the cooperative guarantee.

## Validation and remaining delivery work

The dedicated `Ensou.Dsh.HomeCoordinationTests` executable runs only its own hidden child processes and homes underneath a private build directory. It covers contention and canonical case identity, independent homes, one-time enrollment, retained session references, unclean disposal, one-way tick evidence, exact health attempt matching, Job collisions, surviving descendants, parent crash, and pre-process Host validation failure.

The 2026-09-07 private SDK 10.0.302 run passed eight grouped tests with zero build warnings/errors. Test fixture tick modification verifies comparison semantics; it does not certify an actual Windows reboot, suspend, or Fast Startup transition. Production entrypoint integration, complete installer/update probes, and end-to-end history/workspace survival remain separate delivery gates. The earlier real installer failure remains RED evidence and is not rewritten by these focused tests.
