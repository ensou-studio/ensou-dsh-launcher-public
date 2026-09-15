# Windows background-runtime Pilot gate

This is a mandatory real-machine release gate for both Personal and Enterprise
Launcher builds. A release is `NO-GO` until the exact signed candidate and the
exact bundled DeepSeek Harness release pass this gate on native Windows x64 as
a standard user.

## What the implementation proves

The Launcher starts its owned `node.exe` root with `UseShellExecute: false`,
`CreateNoWindow: true`, and `WindowStyle: Hidden`. It assigns that root to a
kill-on-close Job Object so shutdown owns the process lifetime. Automated tests
lock those root-process flags and the direct, no-console Launcher restart path.

Those controls do **not** force every future process created by upstream
DeepSeek Harness to remain hidden. A Job Object propagates lifetime ownership;
it does not rewrite a descendant's Windows creation flags. Upstream DSH, a
managed plugin, or a tool can still explicitly request a new console or launch
`cmd.exe`, `powershell.exe`, `pwsh.exe`, `dotnet.exe`, `conhost.exe`,
`OpenConsole.exe`, or another UI process. Passing source tests is therefore not
evidence that every upstream spawn path is invisible.

## Mandatory real-machine exercise

Observe each lane continuously for at least 15 minutes, starting before the
employee launches the client. Exercise all of these paths during the same
observation:

1. clean install or repair, first Launcher start, tray hide/show, DSH start,
   WebUI open, DSH stop, and Launcher restart;
2. one real production plugin or tool action that makes upstream DSH create a
   descendant process through its shipped subprocess path;
3. one workspace or terminal/tool path, when the shipped upstream version
   exposes one;
4. a controlled DSH failure followed by recovery and another DSH start;
5. update health validation, one failed-candidate rollback, and the recovered
   Launcher/runtime start.

If the selected upstream release has a descendant-spawn path but the Pilot
cannot exercise it safely, the result is `BLOCKED`, never an inferred `PASS`.
If it has no such feature, record that exact tag/commit and the reviewed source
locations that establish non-applicability; a later upstream update must rerun
the gate.

Enterprise runs this exercise on both the clean-install and isolated
legacy-migration device lanes required by
[`enterprise/windows-employee-pilot.md`](enterprise/windows-employee-pilot.md).
Personal runs it on both exact Windows x64 lanes required by
[`personal-dual-device-pilot.md`](personal-dual-device-pilot.md): PILOT-DESKTOP is
the existing-install upgrade lane and the PilotNotebook notebook is the clean first
install lane. Both devices must independently prove the seven shared checks;
neither device may stand in for the other.

## Evidence and fail conditions

The controlled observer retains a continuous screen recording plus a
timestamped process/window inventory sampled at least once per second. The
inventory must include process image path, PID, parent PID, signer/hash for the
shipped executables, top-level visible-window handle/title/class, and the exact
action being exercised. Record the signed Launcher/runtime hashes and upstream
tag/commit with the observation.

Do not close or suppress a window during the run. Any visible console, shell,
`dotnet.exe - Application Error`, .NET unhandled-exception dialog, Windows
Error Reporting dialog, repeated crash dialog, or unexpected application
window is an immediate `FAIL`, even when it later disappears. A missing sample,
observer interruption, unexercised required spawn path, or evidence from
different bytes is `BLOCKED`.

Only a complete observation with zero unexpected visible windows is `PASS`.
The result is bound to the exact upstream and Launcher bytes and expires when
either changes. It never authorizes the statement that the Launcher controls
all present or future upstream descendant creation flags.
