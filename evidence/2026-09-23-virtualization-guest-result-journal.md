# Authenticated Virtualization Guest Result Journal — 2026-09-23

Status: IMPLEMENTED AND FOCUSED-TESTED AT SOURCE LEVEL. The fake-adapter
task-cycle model is now tested; no native guest VM was booted, no native
per-task hard-stop was exercised, and no production task gate changed.

## Change

- Schema version 19 adds a bounded Job column for the authenticated terminal
  guest result. The journal duplicates and verifies the exact persisted guest
  admission identity so a result cannot be attached to a different task.
- `VirtualizationGuestTransportExecutor` invokes the Broker callback only
  after the response has passed the transport's authentication and the
  executor's response mapping/verification checks.
- BrokerStore writes the normalized, secret-redacted result and an audit
  intent/completion pair in one transaction under the active Job lease. At
  startup, every journal is checked against its admission and both audit
  records before it can influence recovery.
- Restart reconciliation rechecks current policy plus principal, session,
  Edge, and Edge-key revocation. It uses a bounded verified local result
  before a guest status lookup; it never replays task execution. Results that
  are uncertain, unverified, truncated, or over the admitted time/output
  budget remain `UNKNOWN`.
- Encrypted terminal ledger archives retain the journal for an unresolved
  `UNKNOWN` Job. Known terminal settlement clears the temporary journal.

## Verification

- `npm run typecheck` — passed.
- `npm run build` — passed, including the repository's native build steps.
- `node --test --test-timeout=120000 packages/broker/dist/persistence.test.js packages/broker/dist/broker.test.js packages/broker/dist/task-runner.test.js packages/broker/dist/ledger-export.test.js` — 182 tests: 176 passed, 6 skipped, 0 failed. Skips are opt-in physical sandbox cases.
- `npm run lint` — passed for 821 tracked files.
- `npm run verify:docs` — passed for 33 README links and 8 required runbooks.
- `npm run verify:matrix` — passed for 29 targets, 25 threats, 31 tasks, and 20 evidence references.
- `npm run verify:process-boundaries` — passed with 0 unreviewed script entries.
- `npm test` — 1,217 tests: 1,201 passed, 16 skipped, 0 failed.
- `npm run verify:completion` — accurately reports partial at 92% (2 PASS, 23 OPEN, 4 BLOCKED, 0 FAIL); it exits nonzero because production acceptance gates remain open.
- `git diff --check` — passed after final documentation edits.

The focused tests cover result callback ordering/rejection, atomic persistence,
restart readback and audit binding, local recovery without a second guest
lookup, migration from version 17, and encrypted archive inclusion.

## Remaining gate

This closes the Broker's memory-only-result recovery gap in source; it does
not prove Virtualization isolation or establish that per-task hard-stop is a
safe accepted control. A source-level serialized VM boot-cycle candidate is now
implemented; see
[`evidence/2026-09-23-virtualization-task-scoped-lifecycle.md`](2026-09-23-virtualization-task-scoped-lifecycle.md).
The host still lacks an approved bootable guest image,
and no VM start/run/stop or hostile descendant cycle has been tested. The
observed App Sandbox double-fork/`setsid` escape remains unresolved. Public
`mac_task_run` and VT-SBX-01/02 remain disabled; the overall completion score
remains 92%.
