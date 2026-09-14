# Process-Identity Exit-Window Evidence

Date: 2026-09-14
Host: physical Darwin arm64 development host
Scope: short-lived child startup identity capture; no production capability enablement

## Commands

```text
npm run build
for i in 1 2 3 4 5; do
  MOPS_REAL_SANDBOX=1 node --test --test-name-pattern='real macOS Broker task path preserves sandbox|real macOS Broker task crash keeps the Job unknown' packages/broker/dist/broker.test.js
done
MOPS_REAL_SANDBOX=1 npm test
```

## Observed result

- Five consecutive targeted runs passed 2/2 each for the short-lived Broker
  task and crash paths.
- Full real-sandbox suite: 458 tests, 457 passed, 0 failed, 1 explicit
  host-boundary/opt-in skip.
- A task that exits while native process-table visibility is settling no
  longer fails solely because the child-close event arrived first.

## Boundary

`ProcessSupervisor` keeps retrying native root PID/start-time capture for the
bounded 100ms startup window even after a child-close signal. It never invents
an identity. If the identity remains unavailable, startup cleanup and the
existing fail-closed error path still apply; active ownership is not registered
without a verified identity.

## Limitations

This closes a timing race observed on the tested host. It does not prove
kernel-held mount namespaces, in-syscall remount resistance, credential-store
isolation, post-snapshot descendant ownership, or production sandbox
selection. `mac_task_run` remains disabled by default.
