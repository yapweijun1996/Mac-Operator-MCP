# Active Task Revocation Evidence

- Source commit: `e866c261c7413836d9e44df6656d42c70fb4d16c`
- Capture state: clean implementation revision before this evidence addendum
- Captured: 2026-09-13 (Asia/Kuala_Lumpur)
- Host: macOS 26.2 (25C56), `Mac16,10`
- Contract version: `0.1`
- Policy version used by tests: `policy-0.1`

## Verification

- `npm test` — 200 tests passed, 0 failed
- `npm run typecheck` — pass as part of the build/test path
- Focused case: `mac_task_run does not publish success after active session revocation`

## Observed invariant

The injected TaskRunner revoked the active Broker session and then returned a syntactically successful, verified result. The Broker control callback observed cancellation, the post-run authority readback rejected publication, the request completed as `CANCELLED`, and the linked Broker Job was persisted as `unknown`. The result payload did not expose the runner's success output.

This is a local control-flow and persistence test, not proof of OS-level process termination. A real sandbox runner must still prove credential isolation, process-tree ownership, network restrictions, cleanup, and restart recovery before `mac_task_run` can be enabled.
