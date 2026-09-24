# Production Task Exposure Gate

Date: 2026-09-22
Host: Darwin arm64 physical Mac, current process UID 501
Status: `implemented` as a production-startup guard; production task execution remains unavailable

## Boundary

`TaskRunner` now exposes an explicit `publicEnablement` state:

- `unavailable` — no task boundary can execute;
- `staging-only` — physical or synthetic evidence is available for canaries;
- `production` — release provenance and the selected production boundary are accepted.

The deprecated `sandbox-exec` runner and the current Virtualization.framework
seam are always staging-only. The App Sandbox and Root Helper runners become
production only when their exact native helper has passed the production
release gate with Developer ID/notarization evidence. The staging state is
not supplied by MCP request data.

Production Broker startup now checks the signed active policy against the
selected task runner before exposing the service. If `mac_task_run` is enabled
while an available runner is only staging-only, startup fails before the
listener is made available. An unavailable runner remains fail-closed and is
reported as runtime-unavailable rather than being treated as a release.

This guard separates canary execution from public capability exposure. It does
not enable D1, alter the live R1 deployment, or replace the underlying
sandbox, signing, installation, rollback, and independent-review gates.

## Verification

- `npm run typecheck` passed.
- `npm run build` passed.
- The full repository regression passes 1,042/1,057 tests with 15 explicit
  skips and 0 failures.
- Focused task-runner, root-helper package-plan, and root-helper package-executor
  tests passed: 22/22.
- The negative test proves an available `staging-only` runner cannot satisfy
  the production task exposure check.
- No live policy, OAuth grant, LaunchDaemon, LaunchAgent, permission, or
  process state changed.

## Remaining gates

The current host still has no valid Developer ID identity, Accessibility is
denied, target launchd labels are absent, and the live R1 service remains the
protected read-only PM2 snapshot. Production D1/G1/P1 enablement therefore
remains open.
