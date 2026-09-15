# Windows Pilot Observer

`Ensou.Dsh.WindowsPilotObserver` is a passive evidence collector for the real
Windows Personal pilot and later Enterprise pilots. It does not install,
launch, update, click, dismiss, or repair DSH. Its public result always carries
`standaloneAdmissionEvidence: false`; a reviewer or an independently controlled
release custodian must decide whether the evidence is sufficient.

The first Personal gate is the required two-device Pilot: PILOT-DESKTOP exercises
the existing-version upgrade lane and the old PilotNotebook Windows laptop
exercises the clean first-install lane. Each device runs the exact candidate
for at least 15 uninterrupted minutes and supplies its own installation
identity and evidence set described in
[`personal-dual-device-pilot.md`](personal-dual-device-pilot.md). Automated
tests build a transient-window fixture but never start it. Both real 900-second
device runs are deliberately manual Pilot evidence, not CI simulations.

## Build and execution profile

The observer is a `net10.0-windows`, `win-x64`, self-contained, single-file
`WinExe` with an `asInvoker` manifest and no third-party package dependency.
Publish it with the repository-pinned .NET SDK, then record the published EXE's
SHA-256 in the observation plan. The observer rejects a plan whose pinned
observer hash does not match its own running bytes.

The observer must run with an unelevated token whose integrity RID is exactly
medium (`0x2000`); medium-plus (`0x2100`) is rejected. A Windows
account that belongs to the local Administrators group is acceptable for the
Personal pilot when UAC supplies a filtered medium-integrity token. The summary
records token elevation type, integrity RID, and whether the Administrators SID
is absent, enabled, or deny-only. It rejects elevated/full, high-integrity, and
system-integrity execution. Enterprise admission policy may later impose a
stricter account-membership rule without changing the observer's evidence.

The observer also captures its own platform identity before a run is admitted.
Both the process and operating system must be native x64, `IsWow64Process2`
must report no WOW/emulation layer and an AMD64 native machine, and
`RtlGetVersion` must report a Windows 10 or Windows 11 Workstation build.
Windows Server, ARM64, WOW64, and other architectures are rejected. Only these
non-sensitive platform facts appear in the public summary.

## Exact candidate plan

The strict plan schema is
`release/schemas/windows-pilot-observation-plan-v1.schema.json`. The runtime
also rejects duplicate or unknown JSON properties, non-canonical identifiers,
reordered role/action catalogs, reparse-point paths, hard-linked candidate
files, and byte hashes that do not match.

Each plan binds the exact release tuple and provenance plus these ordered byte
identities:

1. release manifest;
2. installer;
3. launcher;
4. bootstrapper;
5. maintenance executable;
6. Node executable;
7. runtime entry point.

The manifest and installer normally use `requiredAtStart: true`; files that are
created by the clean install can use `false`. Every role must exist and match
again at finalization. The observer does not keep handles across an updater's
legitimate replacement transaction, but detects identity changes through
initial observation, running-image evidence, and final re-hashing.

## Passive capture

While active, the collector uses four out-of-context Windows event hooks for
`CREATE`, `SHOW`, `DIALOG`, and `FOREGROUND`. This is the primary path for a
short-lived error or console window. A separate 250 ms `EnumWindows` and
Toolhelp process scan provides a loss-resistant delta stream. Enriched relevant
process/window snapshots are scheduled every 750 ms so that their allowed
maximum gap is one second. Process identity is always PID plus process creation
time, which prevents PID reuse from joining two processes.

Candidate, observer, recorder, and hook preflight is completed before the
900-second monotonic boundary begins. The hooks are active before the baseline
capture, closing the startup race. Ending performs gap checks and a final
enriched snapshot while the hooks remain active; hooks are released only during
finalization. A slow or failed startup/baseline, tail snapshot, or hook teardown
therefore blocks the run instead of silently shortening its evidence window.

The relevant rich snapshot includes candidate processes and descendants, the
fixed recorder process, and console/crash helpers such as `cmd.exe`,
`powershell.exe`, `pwsh.exe`, `dotnet.exe`, `conhost.exe`, `OpenConsole.exe`,
and `WerFault.exe`. It never reads process command lines or environments.
The probe may scan the current desktop process table in memory, but JSONL
persistence is allowlisted to those relevant processes/windows plus an
otherwise-unexpected window. Ordinary application inventories are never written.
Every relevant process and window must have a nonzero process creation time;
missing creation time blocks the run so PID reuse cannot fail open.

A new visible console, common dialog, application-error dialog, unhandled-error
dialog, security prompt, or otherwise unapproved top-level window makes the
result sticky `FAIL`. The observer records it but never clicks or closes it.
Loss of event hooks, a sampling gap, overlapping sampling, lock/disconnect,
sleep, an exception, an interrupted recorder process, early close, insufficient
duration, or incomplete required action makes the result sticky `BLOCKED`.
`FAIL` dominates `BLOCKED` and neither state can return to eligible.

The operator marks these ordered exercises in the visible observer UI:

1. first launcher start;
2. tray hide/show;
3. DSH start;
4. WebUI open;
5. a real subprocess path;
6. workspace/terminal path when available;
7. controlled failure and recovery;
8. update rollback/recovery;
9. launcher restart.

## External screen recording

The MVP intentionally does not embed a video encoder. The plan pins an external
recorder by absolute path and SHA-256 and requires exactly one process with that
path and a stable PID-plus-creation-time identity throughout observation. Audio
must be disabled.

The operator flow is:

1. start the approved external recorder;
2. keep the observer's `START` challenge visible and begin observation;
3. exercise every required action for at least 900 monotonic seconds;
4. end observation and keep the new `END` challenge visible for several seconds;
5. stop the external recorder and wait for it to finish writing;
6. finalize evidence.

The private event log contains both random challenges. The public summary
contains only their SHA-256 values plus the final recording media type, byte
size, SHA-256, and observation-duration claim. A reviewer must confirm that the
same continuous recording visibly contains both challenges and covers the
test-run ID. Process continuity and challenge hashes strengthen the binding but
do not make the observer a trusted video custodian.

## Evidence and privacy

Each run gets a new directory under
`%LOCALAPPDATA%\Ensou\DshPilotObserver\runs\<testRunId>`. The event file and
summary are opened with create-new semantics. Every JSONL record contains its
predecessor's SHA-256 and a domain-separated record SHA-256; the summary pins
the event file size, file hash, terminal record hash, and record count.

The private JSONL log may contain redacted paths such as `<user-profile>` but
never plaintext window titles. Window titles are reduced in memory to a
category, length, and SHA-256. Neither output may contain command lines,
environment values, API keys, access/refresh/bearer tokens, usernames, MAC
addresses, or device serial numbers. The strict public summary schema is
`release/schemas/windows-pilot-observation-summary-v1.schema.json`; it has no
path field and no plaintext title field.

Evidence is locally tamper-evident, not locally authoritative. The MVP does not
add AES-GCM, RSA wrapping, an embedded CA, or automatic Enterprise admission.
If Enterprise evidence later leaves the device, confidentiality and independent
custodian authentication must be layered outside this observer. In particular,
encryption alone would not prove who produced the evidence.

## Review outcome

`ELIGIBLE_FOR_REVIEW` means only that the observer found no local fail/block
condition and produced structurally complete evidence. Before writing the
summary, a runtime verifier and the summary schema independently require at
least 900 seconds, zero lost events, bounded sampling gaps, all nine ordered
actions, all seven exact candidate roles observed with nonempty bytes, a
nonempty continuous recording that covers the run, and no unexpected windows.
It is not `PASS` and not
`ADMIT`. `BLOCKED` means the run must be repeated. `FAIL` means the candidate
showed prohibited behavior, such as the persistent or transient console/error
window this pilot is intended to catch.
