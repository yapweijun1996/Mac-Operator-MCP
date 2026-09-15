# Job Ledger Startup Integrity

Status: PARTIAL MOP-071 evidence; capability enablement remains gated

Date: 2026-09-15

## Scope

Broker startup now validates every persisted Job row before restart
reconciliation can inspect or mutate queued or running work. The check reuses
the durable Job state machine and parser, and therefore fails closed on
malformed terminal rows as well as active recovery rows.

Persisted Job identity is required to use the bounded Broker formats for the
Job ID, owner principal/session, tool, target, policy version, payload digest,
and idempotency key. Lease ownership is required to use the bounded Broker
owner/token formats. Lease acquisition, heartbeat, and expiry timestamps must
be ordered; heartbeat cannot outlive expiry, and the persisted lease window
cannot exceed the Broker maximum. A Job cannot carry both local process
ownership metadata and virtualization guest recovery metadata, and those
descriptors are accepted only for `mac_task_run` Jobs in `running` or `unknown`
state.

## Verification

- Focused Job-state and startup-integrity tests: 6 passed, 0 failed.
- Non-overlapping package regression: 586 total, 580 passed, 6 skipped, 0 failed.
- `npm run build`: passed.
- `npm run lint`: passed for 592 tracked files.
- `git diff --check`: passed.

The long-running `broker.test.js` and `persistence.test.js` suites were already
active in another process and were intentionally not restarted or terminated.

## Remaining limits

This is persisted-ledger and old-writer fencing evidence only. It does not
prove physical crash recovery, OS process-tree ownership after an unobserved
Broker crash, credential rotation on an installed host, disk/remount
durability, or production task-runner enablement.
