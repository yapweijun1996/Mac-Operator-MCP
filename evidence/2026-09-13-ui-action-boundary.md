# Governed UI Action Boundary Evidence

- Date: 2026-09-13
- Source commit: `9bba3cd`
- Host: macOS arm64 development host
- Scope: disabled-by-default `mac_ui_action`; no user application was mutated during verification
- Policy state: `mac_ui_action` is implemented but disabled by default; it requires `mac.ui.control`, an exact parent `app_window` rule, and `trusted_gui` approval

## Boundary implemented

`mac_ui_action` accepts only a Broker-issued opaque `element:<hex>` reference from a recent Accessibility observation and one fixed action: `press`, `select`, `increment`, `decrement`, `show_menu`, or `focus`. The Broker resolves a 30-second snapshot bound to the requesting principal and session, rejects stale/foreign/secure/redacted/sensitive elements, authorizes the parent app window independently, consumes an exact GUI approval, records mutation intent, and creates a principal/session-bound Job. A Job ID is returned for status lookup.

The adapter invokes only fixed Broker-owned `/usr/bin/osascript -l JavaScript` code with `/` cwd, an empty environment, a 10-second timeout, and a 256 KiB output cap. The script resolves the exact bundle, window title/index, element index, role, and safe label; it performs only the allowlisted Accessibility action and reobserves the same identity. Broker completion requires verified accepted output and matching post-action role/enabled/focused readback. No caller-supplied script, executable, target path, window search expression, or credential surface is accepted.

## Verification performed

- UI adapter tests cover fixed command wiring, script-size bounds, empty environment, timeout/output limits, exact identity readback, permission-denied mapping, stale/secure/malformed targets, owner/session binding, and sensitive-target denial.
- Broker integration verifies snapshot ownership/TTL, parent app-window authorization, `trusted_gui` approval consumption, mutation intent, Job linkage/status ID, post-action reobservation, and active session revocation mapping to cancellation with an unknown Job.
- Contract conformance validates the versioned `mac_ui_action` success and stable-error envelopes. The GUI kill switch covers the `mac_ui_*` family.
- The full suite passes with 278 tests; `npm run typecheck`, `npm run verify:contracts`, `npm audit --omit=dev --audit-level=high`, and `git diff --check` pass.
- No real app action was executed. The existing real-host Finder Accessibility probe remains permission-denied and read-only.

## Limits and remaining release work

This is bounded command-wiring and fake-adapter evidence, not real GUI release evidence. Permission-granted real-app action, focus-race/adversarial dialog evidence, broader sensitive-surface classification, credential typing, structured automation, packaging, and final release-gate readback remain open under `MOP-050` through `MOP-055` and `VT-UI-01`/`VT-UI-02`.
