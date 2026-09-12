# Task admission evidence — 2026-09-13

## Scope

This record covers the committed task-job admission boundary in `219414d`.
The Broker now commits approval consumption, the redacted intent audit event,
the queued Broker-owned Job, and the request linkage in one SQLite transaction
after the authorization decision. The admission path binds the principal,
session, tool, policy revision, target, approval payload digest, Job payload
digest, and non-decreasing timestamps. The task path uses one admission-time
clock sample for both the Job and intent event.

## Verification

- Repository state: clean after commit `219414d`.
- `npm test`: 200 passed, 0 failed.
- `npm run typecheck`: passed.
- `npm run verify:contracts`: passed; 44 unique tool contracts validated.
- `npm audit --omit=dev --audit-level=high`: 0 vulnerabilities.
- The task integration tests cover approval binding, Job creation/start/terminal
  readback, profile timeout/output budgets, active-session revocation, and
  refusal to publish a late success.

## Limits

This is local prototype evidence only. It does not prove a production sandbox,
credential isolation, process-owned task cancellation, installed service
packaging, remote OAuth deployment, or physical-Mac task execution.
