# Task Runner Boundary Evidence

- Source commit: `10b7327d2de63122cafaf70b0302b9c207d75f2b`
- Capture state: clean implementation revision before this evidence addendum
- Captured: 2026-09-13 (Asia/Kuala_Lumpur)
- Host: macOS 26.2 (25C56), `Mac16,10`
- Runtime: Node `v25.5.0`, npm `11.8.0`
- Contract version: `0.1`
- Policy version used by tests: `policy-0.1`

## Verification

- `npm run typecheck` — pass
- `npm test` — 199 tests passed, 0 failed
- `npm run verify:contracts` — 44 unique tool contracts validated
- `npm audit --omit=dev --audit-level=high` — 0 vulnerabilities
- `git diff --check` — pass

## Boundary results

- `mac_task_run` is implemented in the Broker as a synchronous, approval-bound Job operation, but the default policy keeps it disabled.
- Named profiles resolve the executable, canonical cwd, fixed environment, filesystem/network declarations, argument allowlist, sandbox profile identifier, timeout, and output budget. Request arguments cannot choose an executable or inject environment values.
- The Broker rejects admission before approval consumption when no `TaskRunner` isolation boundary is available (`POLICY_DENIED`).
- An explicitly supplied runner is still subordinate to Broker authority: the Broker requires an exact `task_profile` target rule, a single-use `trusted_profile` approval, a running Broker-owned Job, bounded redacted output, verified completion, and active-authority readback before publishing success.
- Runner failures, malformed results, cancellation, timeout, verification failure, output limits, and untrusted terminal persistence do not become success; unresolved active work is recorded as `unknown` for status lookup.
- The test runner is a fake injected boundary only. No real sandbox, credential-isolation, Docker isolation, process-tree ownership, or production task profile is enabled by this evidence.

## Release status

This evidence does not close `VT-SBX-01`, `VT-SBX-02`, `MOP-043`, or `MOP-045`. Production task execution remains fail-closed until a real-Mac hostile sandbox and credential-isolation proof is accepted.
