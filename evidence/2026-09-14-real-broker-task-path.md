# Real Broker Task-Path Evidence

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

- Focused Broker suite: 69/69 passed.
- Full real-sandbox suite: 443/444 passed, 0 failed, 1 explicit host-boundary/opt-in skip.
- The new integration test passed only with `MOPS_REAL_SANDBOX=1` on Darwin.

## Boundary exercised

The test signs a `mac_task_run` request with the test Edge key, persists a
single-use `trusted_profile` approval, and sends the request through the real
Broker handler. Broker-owned profile resolution supplies `/bin/echo`, a
temporary canonical working root, fixed `LANG=C` environment, bounded args,
no network, and the `deny-default-v0.1` sandbox profile. The Broker creates and
owns the Job, dispatches through `SandboxExecTaskRunner`, verifies the
`sandbox-readback` output, and reads the completed Job plus decision/intent/
completion audit events.

## What this proves

- Signed request, approval digest, target, policy, and Job linkage are checked
  by the Broker before execution.
- The experimental sandbox runner is reached through the Broker boundary and
  its verified output is returned only after a successful postcondition.
- The default policy is still fail-closed: `mac_task_run` remains disabled
  unless a test explicitly enables it and supplies host evidence.

## What this does not prove

This does not establish production task isolation or release readiness. The
runner uses deprecated `sandbox-exec`; real credential contents, durable
remount resistance, post-snapshot descendant ownership, crash attribution,
and signed production packaging remain unresolved under MOP-086, MOP-043, and
MOP-045. No persistent service, remote Edge, privileged helper, or production
capability was enabled.
