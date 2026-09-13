# Real Broker Task Process Kill-Switch Evidence

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

- Focused Broker suite: 71/71 passed.
- Full real-sandbox suite: 445/446 passed, 0 failed, 1 explicit host-boundary/opt-in skip.
- The kill-switch test ran only with `MOPS_REAL_SANDBOX=1` on Darwin.

## Boundary exercised

The test signs and approves a Broker-owned `mac_task_run` request for a
temporary `tests.sleep` profile. The profile fixes `/bin/sleep`, canonical cwd,
empty environment, no network, a single-process sandbox policy, a five-second
timeout, and bounded output. While the child is running, the test calls the
durable BrokerStore `setSwitch("process", true, ...)` operation.

The Broker execution control callback observes the switch because
`authorizeTool` maps the task's process capability to the `process` switch.
`ProcessSupervisor` sends termination to the detached process group and waits
for group disappearance. Broker returns stable `CANCELLED`, marks the request
cancelled, and leaves the Job `unknown` because authority loss prevents a
trusted successful postcondition.

## What this proves

- The process kill switch reaches an active real task, not only admission.
- Cancellation is coupled to process-group drain and cannot publish a late
  success after the switch changes.
- The unknown Job remains owner-bound and inspectable for recovery.

## What this does not prove

This does not close production task isolation. The experimental runner uses
deprecated `sandbox-exec`; crash/restart attribution, post-snapshot descendant
ownership, remount resistance, real credential-content isolation, and signed
production packaging remain unresolved under MOP-086. The default policy and
production `mac_task_run` capability remain disabled.
