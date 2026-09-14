# Real Broker Task Edge-Revocation Evidence

Date: 2026-09-14
Host: physical Darwin arm64 development host
Scope: opt-in integration only; no production capability enablement

## Command

```text
npm run build
MOPS_REAL_SANDBOX=1 node --test --test-name-pattern='^real macOS Broker task cancellation drains the process after Edge revocation$' packages/broker/dist/broker.test.js
```

## Observed result

- Focused Edge-revocation integration: 1/1 passed.
- The test ran only with `MOPS_REAL_SANDBOX=1` on Darwin.

## Boundary exercised

The test signs and approves a Broker-owned `mac_task_run` request for the
temporary `tests.sleep` profile. While `/bin/sleep` is running, the Broker's
host-only `revokeEdge("edge-1", ...)` operation persists Edge revocation.

The active execution control observes the revoked Edge identity,
`ProcessSupervisor` drains the detached process group, and the Broker returns
stable `CANCELLED`. The Request is cancelled and the linked Job remains
`unknown`; no late success is published after Edge authority loss.

## Limits

This proves active Edge revocation propagation on the experimental Darwin
runner only. It does not prove production sandbox credential isolation,
post-snapshot descendant containment, remount resistance, or signed
production packaging; the default policy and `mac_task_run` capability remain
disabled.
