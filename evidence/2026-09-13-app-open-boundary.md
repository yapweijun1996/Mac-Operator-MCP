# Governed App Launch Boundary Evidence

- Date: 2026-09-13
- Source commit: `85d1e96`
- Repository state: dirty after the source commit because documentation updates are pending; no production policy change
- Host: macOS arm64 development host
- Scope: disabled-by-default app launch mutation; no user application was launched during verification
- Policy state: `mac_app_open` is implemented but disabled by default; it requires `mac.app.control`, an exact app target, and `trusted_gui` approval

## Boundary implemented

`mac_app_open` accepts a stable `bundle:<bundle_id>` identity. The Broker binds the exact `app:<app_id>` target, consumes a matching GUI approval, records mutation intent, creates a principal/session-bound Job with a lease, and rechecks authority before dispatch and before terminal success. Requests cannot select an executable, script, process arguments, or a different target through tool arguments.

The adapter first confirms the requested identity in the bounded Broker-owned app inventory. It then invokes only `/usr/bin/open -b <bundle_id>` with `/` cwd, an empty environment, fixed timeout/output limits, no shell, and ProcessSupervisor cancellation. It reobserves the exact Bundle ID as running before committing a completed Job. Already-running apps are reported distinctly. A launch error or lost authority leaves the Job unresolved/unknown rather than publishing success. Document and URL inputs are rejected until independent filesystem/network target authorization and target-swap proofs are released.

## Verification performed

- App-control tests cover stable Bundle ID validation, traversal-like identity rejection, unsupported document/URL rejection, fixed executable/arguments/cwd/environment, absent-target denial, launch-state reobservation, already-running state, and one global deadline across all launch phases.
- Broker integration verifies exact app target authorization, `trusted_gui` approval consumption, mutation intent, Job lease linkage, completion audit, stable result data, and active session revocation mapping to cancellation with an unknown Job. Runtime contract-conformance also validates the successful result against the versioned `mac_app_open` output schema.
- Policy schema and loader checks reject app target references that are not stable `bundle:<bundle_id>` identities; persistence tests cancel queued GUI jobs when the GUI kill switch is enabled.
- The full suite passes with 263 tests; `npm run typecheck`, `npm run verify:contracts`, `npm audit --omit=dev --audit-level=high`, and `git diff --check` also pass.
- No real app was launched during verification. Real-host app inventory evidence is recorded separately in `evidence/2026-09-13-app-inventory-boundary.md`.

## Limits and remaining release work

This is bounded command-wiring and fake-adapter evidence, not real GUI release evidence. Document/URL opening, focus, app/window freshness, Accessibility observation, sensitive-surface and credential-UI policy, permission recovery, real-app launch, GUI cancellation/readback, packaging, and final release-gate evidence remain open under `MOP-050` through `MOP-055` and `VT-UI-01`/`VT-UI-02`.
