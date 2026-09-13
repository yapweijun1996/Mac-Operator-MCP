# Governed App Focus Boundary Evidence

- Date: 2026-09-13
- Source commit: `53a6550`
- Repository state: dirty after the source commit because documentation updates are pending; no production policy change
- Host: macOS arm64 development host
- Scope: disabled-by-default app/window focus mutation; no user application was focused during verification
- Policy state: `mac_app_focus` is implemented but disabled by default; it requires `mac.app.control`, an exact app-window target, and `trusted_gui` approval

## Boundary implemented

`mac_app_focus` accepts only a stable `bundle:<bundle_id>` identity and an optional bounded exact window title. The Broker binds the `app_window` target `window:<bundle_id>`, consumes a matching GUI approval, records mutation intent, creates a principal/session-bound Job with a lease, and rechecks authority before dispatch and terminal success. Tool arguments cannot select an executable, script, process ID, or another target.

The adapter invokes only fixed Broker-owned `/usr/bin/osascript -l JavaScript` code with `/` cwd, an empty environment, a 10-second timeout, and a 128 KiB output cap. The script checks Accessibility trust, resolves the exact running bundle and optional exact window title, sets frontmost/focus, and returns only bounded identity metadata. The adapter and Broker require a focused-window reobservation before completing the Job. Sensitive system/security applications and password, credential, security, privacy, sign-in, and verification-code window hints or returned titles are denied at the Broker, adapter, and parser boundaries.

## Verification performed

- App-control tests cover stable app/window validation, control-character and budget rejection, fixed executable/arguments/cwd/environment, bounded output, focused-window metadata parsing, opaque window identity derivation, unverified result rejection, sensitive-target denial, and permission-denied mapping.
- Broker integration verifies exact app-window target authorization, `trusted_gui` approval consumption, mutation intent, Job lease linkage, focus readback, completion audit, and active session revocation mapping to cancellation with an unknown Job. Runtime contract-conformance validates the successful result against the versioned `mac_app_focus` output schema.
- UI parser tests verify sensitive application denial in parser readback as well as sensitive window hints and returned titles; GUI kill-switch persistence coverage applies to the tool's `gui` family.
- The full suite passes with 274 tests; `npm run typecheck`, `npm run verify:contracts`, `npm audit --omit=dev --audit-level=high`, and `git diff --check` also pass.
- No real app was focused during verification. The existing real-host Finder Accessibility probe remains permission-denied and was read-only.

## Limits and remaining release work

This is bounded command-wiring and fake-adapter evidence, not real GUI release evidence. Snapshot-bound stale-reference/focus-race action targets, structured native automation, broader credential/clipboard/cross-app policy, permission-granted real-app evidence, packaging, and final release-gate evidence remain open under `MOP-050` through `MOP-055` and `VT-UI-01`/`VT-UI-02`.
