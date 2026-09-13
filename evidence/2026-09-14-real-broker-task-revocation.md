# Real Broker Task Revocation Evidence

Date: 2026-09-14
Host: physical Darwin arm64 development host
Scope: opt-in integration only; no production capability enablement

## Command

```text
npm run build
MOPS_REAL_SANDBOX=1 node --test packages/broker/dist/broker.test.js
MOPS_REAL_SANDBOX=1 npm test
```

## Observed result

- Focused Broker suite: 70/70 passed.
- Full real-sandbox suite: 444/445 passed, 0 failed, 1 explicit host-boundary/opt-in skip.
- The revocation test ran only with `MOPS_REAL_SANDBOX=1` on Darwin.

## Boundary exercised

The test signs and approves a `mac_task_run` request for the Broker-owned
`tests.sleep` profile. The profile fixes `/bin/sleep`, a canonical temporary
working root, an empty environment, no network, a single-process sandbox
policy, a five-second timeout, and bounded output. While the child is running,
the test revokes `session-1` in the BrokerStore.

The Broker control callback observes the revocation. `ProcessSupervisor` sends
termination to the detached process group and waits for group disappearance.
The Broker returns stable `CANCELLED`, marks the request cancelled, and leaves
the Job `unknown` because the authority loss means a successful terminal
postcondition cannot be trusted. The audit ledger retains `decision`, `intent`,
and `completion` events for the request.

## What this proves

- Active session revocation reaches a real Broker task, not only a fake runner.
- Cancellation is coupled to process-group drain and does not publish a late
  success after authority loss.
- Unknown outcomes remain inspectable through the owner-bound Job record.

## What this does not prove

This does not close production task isolation. The experimental runner uses
deprecated `sandbox-exec`; crash/restart attribution, post-snapshot descendant
ownership, remount resistance, real credential-content isolation, and signed
production packaging remain unresolved under MOP-086. The default policy and
production `mac_task_run` capability remain disabled.
