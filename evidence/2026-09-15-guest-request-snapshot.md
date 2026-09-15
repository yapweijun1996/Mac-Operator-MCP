# Guest Request Snapshot Evidence

Date: 2026-09-15
Source revision: `31dc880`
Host: physical macOS host used by the repository test harness

## Finding and fix

The guest profile registry performs asynchronous executable and cwd readback.
`VirtualizationGuestProfileExecutor` previously retained the caller-owned
request after that await, so a mutation could alter the ledger key, adapter
limits, or response identity after digest admission.

The executor now validates and snapshots the plain request and nested guest
identity before checking availability, capacity, or awaiting profile
resolution. Every later ledger, adapter, budget, cancellation, response, and
recovery path uses the snapshot. Nested identity fields are copied as well;
the caller cannot change the bound image/runtime identity in place.

## Verification

Focused command:

```text
node --test packages/broker/dist/virtualization-guest-executor.test.js
```

Result: 11 tests passed, 0 failed, 0 skipped. The hostile mutation test
changes request ID, nonce, task digest, timeout, and guest image identity
immediately after `execute()`; the captured adapter input and returned result
retain the original authenticated values.

Non-overlapping package regression (excluding the two pre-existing long-lived
broker/persistence test processes): 517 tests total, 511 passed, 6 skipped,
0 failed.

## Boundary status

This is local guest-request TOCTOU evidence. It does not prove a native
attestation producer, private-key distribution, VM boot, guest isolation,
credential/persistence protection, production resource limits, or
`mac_task_run` enablement. Those gates remain fail-closed and disabled.
