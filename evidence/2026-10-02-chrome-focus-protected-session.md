# Chrome focus regression investigation and repair — 2026-10-02

Status: PARTIAL. Source repair and automated verification pass. Physical unlocked
desktop acceptance is blocked by the Mac's locked session. No current Chrome
active-window screenshot or 20/20 physical cycles are claimed. The running
production release and installed permission identity have not been replaced.

## Root cause established by current reproduction

The physical host is macOS arm64. The production MCP health and inventory calls
passed. Production Chrome focus reproduced the ticket's PRECONDITION_FAILED.
Independent native diagnostics then established:

```json
{
  "frontmost_bundle": "com.apple.loginwindow",
  "screen_locked": true,
  "on_console": true,
  "login_done": true
}
```

Activation returned true, but both Workspace and system-wide AX continued to
identify loginwindow (PID 176), not Chrome (PID 485). The existing run-loop
poll took 3308 ms; a separate NSApplication event-pump diagnostic took 3300 ms
and produced the same result. This disproves an immediate-read race as the
cause of this reproduction. The locked desktop prevents Chrome receiving focus.
Production LaunchServices permission readback was Accessibility=true and
Screen Recording=true, so permission denial was not the cause of this failure.
Only bounded session booleans and process identities were read, not lock-screen
content, credentials, TCC databases or browser private data.

The supplied historical focus/observe request IDs did not include session-lock
readback. Their exact historical desktop state cannot be established from their
error message alone. Current reproduction verifies the locked-session cause;
it does not prove a separate unlocked-desktop activation defect.

The earlier focus-success/observe-TARGET_NOT_FOUND failure was a different bug:
AX/CG titles differed for the same PID and geometry. Its PID/generation/CGWindowID
repair remains in the source and active release. Earlier acceptance did not
record 20 repeated transitions from another application. The current failure
occurs before window correlation and is not evidence that title matching
returned. See [earlier identity evidence](2026-10-02-chrome-window-resolution.md).

## Exact source change

- `packages/broker/native/gui_window.h`: reject loginwindow/system-authorization
  frontmost sessions before activation; select and check the requested AX window
  before activating; check activation/raise return values; use one three-second
  uptime deadline for application/window propagation; independently confirm
  Workspace bundle/PID/launch generation and system-wide AX application PID;
  verify the exact focused AX window belongs to that process; recheck focus after
  geometry correlation. A timer maintains the run loop during bounded polling.
- `packages/broker/native/gui_vision.m`: after ScreenCaptureKit capture, re-resolve
  the same native identity and focused window before returning the image.
- `packages/broker/src/gui-window.ts`: preserve the existing public error enum
  and add safe diagnostic prefixes for protected session, activation rejection,
  frontmost timeout, independent app mismatch, missing focused window, ambiguous
  window, and missing AX/screenshot permissions. Timeout is TIMEOUT/retryable;
  protected session is SECRET_BOUNDARY_DENIED. Neither becomes focus success.
- `packages/broker/src/gui-window.test.ts` and
  `scripts/gui-focus-regression.test.mjs`: new error mapping and native resolver
  regression tests. Existing title/correlation/capture tests remain.
- `docs/gui-computer-use.md`, this evidence, and an additive progress record:
  describe deterministic selection, diagnostics and current acceptance limits.

No dependencies, scopes, policy allowlists, consent storage, approval classes,
schema migrations or per-focus/click prompts were added. Without a hint, the
last AXFocusedWindow is selected regardless of array order. An exact hint selects
one matching AX window; duplicate hints and ambiguous geometry deny. Observation
uses the same resolver and identity, and does not activate a background app.

The old attempt-count loop used wall-clock run-loop dates rather than one
monotonic transition deadline. Apple's [runUntilDate documentation](https://developer.apple.com/documentation/foundation/runloop/run(until:)?language=objc)
also permits immediate exit when no sources/timers exist. This potential weakness
is now bounded explicitly; it was not observed as the cause of the locked-host
failure. No unconditional sleep workaround was introduced.

## Regression and automated results

New native fixtures compile the actual production `gui_window.h`, substituting
OS boundary observations rather than reimplementing the resolver. They cover:

1. Locked/protected focus and observe reject before any activation.
2. Activation rejection has its own cause, not missing-window discovery.
3. Accepted activation without a transition expires within 2.9–3.5 seconds.
4. Workspace success with mismatched system-wide AX application denies.
5. A hinted second window is raised and independently verified after propagation;
   duplicate hints deny.
6. Twenty delayed background-to-Chrome focus/observe cycles pass, maintaining the
   same window identity through changed titles and reversed enumeration order.
7. Missing AX permission denies before activation.

These are simulated OS-boundary tests and are not physical GUI acceptance.
Existing tests cover actual native PID/geometry correlation, title differences,
ambiguous/hidden/absent/wrong-process windows, strict booleans, secure labels,
identity-bound active capture, grant/session/operation limits and policy denial.

- Native focus plus window-resolution slice: 14/14 passed.
- `npm test`: 1657 total, 1639 passed, 18 existing opt-in skips, zero failures.
  This includes native compilation, TypeScript build, Broker/Auth security and
  approval regression tests.
- Style, documentation links, verification matrix and diff whitespace passed.

## Current physical production MCP evidence

| Call | Request ID | Result |
| --- | --- | --- |
| mac_health | `3152c638-2726-4c59-85a9-000536ff7e5a` | healthy |
| mac_app_list | `cd37d71b-4ff0-4a1f-a9de-f91dee6d1bfa` | Chrome running |
| mac_app_focus Chrome, installed baseline | `24f632d8-6c75-4d92-ba53-3e51e21346d7` | PRECONDITION_FAILED; 3514 ms |
| mac_ui_observe System Settings | `b8397af1-a298-4288-9d17-d87d84f596f3` | SECRET_BOUNDARY_DENIED |
| mac_app_focus Finder | `d63fbf6b-b992-4ed7-9682-1c087053710f` | POLICY_DENIED |

Direct execution of the newly built adapter returns
`{"status":"error","error":"protected_session"}` on the locked host.
That is a diagnostic check, not acceptance of the production LaunchServices
route or of an unlocked desktop. Production permission checks used the current
installed app via `gui_launcher`, both permissions true.

Supplied ticket request IDs retained for correlation:
focus `4ba333ae-5f76-4215-92a2-1986e82ff27d`;
observe `66adb6db-849c-4674-b459-089519014aba`.

## Physical acceptance dependency and next executable step

The owner must unlock the physical Mac and keep its desktop available. A request
for that handoff was made while independent source/test work continued. The
agent must not unlock it, handle its password, bypass loginwindow or weaken any
permission/policy boundary.

After desktop availability is confirmed:

1. Preserve the active `personal-20261002-gui-window-c` release, exact installed
   GUI app, startup configuration and private state references for rollback.
2. Deploy the prepared source/build using a new immutable release; retain the
   existing V2/O1 modules, OAuth state, signed policy and GUI launcher.
3. Replace only the exact installed native app. Verify its signature and
   production-launcher AX/Screen Recording permissions. If ad-hoc code identity
   renewal is necessary, the owner must renew only this app through System
   Settings; do not rebuild after renewal.
4. Run health/inventory, put another normal app frontmost through the fixture
   setup, focus Chrome via actual production MCP and observe active_window.
   Independently check Workspace/system AX and the returned stable window ID.
5. Repeat twenty times. Exercise title changes, hinted multiple windows and
   stable no-hint selection. Keep sensitive UI/unauthorized-app denial intact.
6. Record a current JPEG representing the resolved Chrome window, AX nodes,
   `mode=active_window`, and positive window/capture/image width and height.

The task remains PARTIAL until those physical checks pass. No screenshot from
the earlier repair is reused as current acceptance. Current active_window image,
AX snapshot, multiple-window physical behavior and 20/20 live cycles are pending.
No runtime rollout, TCC replacement, grant change or database rollback happened
in this repair turn. The final response provides the source commit hash and
focused diff summary; pre-existing task-enablement edits remain excluded.
