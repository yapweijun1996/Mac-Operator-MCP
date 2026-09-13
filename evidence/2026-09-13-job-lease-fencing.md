# Job lease fencing evidence

Date: 2026-09-13
Host: macOS arm64 development host
Scope: local synthetic Job Ledger and Broker worker fixtures; no production task runner or user data

## Boundary exercised

Each Broker-started mutation Job now receives a per-Broker owner ID and a
random lease token. The Job Ledger persists the owner, token, acquisition time,
heartbeat time, and bounded expiry. A cancellable worker renews the lease while
it runs; a terminal transition must present the matching lease, and an expired
lease may only be closed as `UNKNOWN`, never as success.

Restart reconciliation clears lease fields while fencing running Jobs to
`UNKNOWN`. A stale worker that retained its old token therefore cannot publish
a terminal result after restart. Lease tokens are internal persistence facts;
they are not returned through `mac_job_status` or audit evidence.

## Tests

- Heartbeat renewal persists the owner/token and updated expiry in SQLite.
- A wrong token cannot commit a terminal result.
- An expired lease cannot commit success, but can conservatively close as
  `UNKNOWN`.
- Reopening the Job Ledger fences a running leased Job and rejects its stale
  completion attempt.
- Broker filesystem and task paths pass lease ownership to execution controls,
  renew during active polling, and use the lease for terminal persistence.
- The full suite passes with 247 tests.

## Limits and next gate

This proves durable fencing and lease freshness, not that a real macOS process
tree is owned or killed. A production task runner still needs a sandbox,
credential isolation, native process-group identity, independent termination
readback, lease-backed recovery, and multi-Broker startup exclusion before
`mac_task_run` can be enabled.
