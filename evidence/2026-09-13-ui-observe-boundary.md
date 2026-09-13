# Accessibility observation boundary evidence

- Date: 2026-09-13
- Scope: `mac_ui_observe` only; read-only and disabled in the production policy.
- Source revision: working revision after the `mac_ui_observe` implementation; final commit recorded in `PROGRESS.md`.

## Implemented boundary

- Broker authorization requires the independent `mac.ui.observe` scope and an exact `window:bundle:<bundle_id>` target rule.
- The adapter invokes only `/usr/bin/osascript -l JavaScript` with a Broker-owned constant script, `/` working directory, empty environment, a 10-second timeout cap, a 512 KiB output cap, and a 2,000-node cap.
- The script checks `AXIsProcessTrusted`, resolves the requested running bundle and optional exact window title, and never accepts caller code or reads Accessibility element values.
- The parser validates every returned field, denies sensitive application/window titles, masks secure/password-like nodes, redacts labels, bounds text, and derives opaque snapshot-bound window/element references.
- Cancellation, timeout, output overflow, malformed output, missing app/window, and missing Accessibility permission map to stable fail-closed outcomes.

## Automated evidence

- Accessibility parser, malformed-result, sensitive-target, secure-node, secret-redaction, input-budget, fixed-command, Broker authority, GUI kill-switch, and contract-envelope tests pass.
- Full suite after this boundary: 270 passing tests.
- `npm run typecheck` passed.
- `npm run verify:contracts` passed: 44 unique tool contracts.
- `npm audit --omit=dev --audit-level=high` reported 0 vulnerabilities.
- `git diff --check` passed.

## Host evidence

- A real read-only Finder probe on the Mac host was attempted through the adapter with a 3-second timeout and 20-node cap.
- Result: `POLICY_DENIED` — Accessibility permission was not granted.
- No application was launched, focused, clicked, typed into, or otherwise mutated.

## Remaining release gate

This does not close VT-UI-01 or VT-UI-02. Freshness-bound action reobservation, focus-race handling, sensitive-surface policy, permission-granted real-app evidence, and all UI mutation tools remain disabled or planned.
