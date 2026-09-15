# Process Request Snapshot Evidence

Date: 2026-09-15
Source revision: `aa8040e`
Host: physical macOS host used by the repository test harness

## Finding and fix

ProcessSupervisor performs filesystem-backed executable and cwd identity
checks asynchronously. Before this change, the caller-owned request remained
the source of truth after those awaits, leaving a local time-of-check/time-of-
use window. A caller could mutate a target, argument, or environment while the
identity checks were in flight.

The Broker boundary now validates the request shape synchronously and copies
all data fields before the first `await`. The copied request is used for
capacity accounting, environment construction, spawn arguments, path
stability checks, ownership callbacks, cancellation, and final observation.
Callback references remain explicit control hooks; they cannot add fields or
change the copied target data.

## Verification

Focused command:

```text
node --test packages/broker/dist/process-supervisor.test.js packages/broker/dist/task-profile.test.js packages/broker/dist/task-runner.test.js
```

Result: 50 tests passed, 0 failed, 0 skipped. The hostile mutation test
changes executable, args, cwd, and environment immediately after `run()` is
called; the observed result still comes from the original `/usr/bin/printf`
request and no active process remains.

Non-overlapping package regression (excluding the two pre-existing long-lived
broker/persistence test processes): 515 tests total, 509 passed, 6 skipped,
0 failed.

## Boundary status

This is local request TOCTOU evidence. It does not prove kernel sandboxing,
credential or persistence isolation, VM/guest attestation, production
resource-exhaustion behavior, or `mac_task_run` enablement. Those gates remain
fail-closed and disabled.
