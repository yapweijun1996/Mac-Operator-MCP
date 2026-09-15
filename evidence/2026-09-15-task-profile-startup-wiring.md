# Task-profile startup wiring evidence

Date: 2026-09-15
Source revision: `52a8e91` (`test: prove startup task profile execution`)

## Boundary

`createBrokerServiceFromStartupConfig` accepts an explicit host-owned
`TaskProfileRegistry` and passes it into the Broker factory. The option is
valid only when an explicit sandbox or virtualization task runner is also
configured. A missing runner or a registry without the required `resolve` and
`names` methods fails closed before startup directories, sockets, policy, or
the Job Ledger are touched. The default packaged assembly supplies neither
option, so it retains an empty registry and the fail-closed task runner.

With the explicit physical-Darwin test gate enabled, the startup fixture also
reopens persisted authority, injects a named profile and sandbox runner, issues
a single-use trusted-profile approval, sends a signed request over native UDS,
and verifies the authenticated response plus completed Job readback. The test
profile is fixed to `/usr/bin/printf`, an empty environment, one temporary task
root, and a 5-second/1 KiB budget.

## Verification

Commands run from the repository root:

```text
npm run build
node --test --test-concurrency=1 packages/broker/dist/service-startup.test.js
MOPS_REAL_SANDBOX=1 node --test --test-concurrency=1 packages/broker/dist/service-startup.test.js
```

Results:

- Service-startup tests: 7 passed, 0 failed, 0 skipped.
- The physical-Darwin run also passed 7/7 and completed the signed
  `mac_task_run` startup path through native UDS, sandbox execution, approval,
  and Job readback.
- The tests cover runnerless registry rejection, malformed registry
  rejection, protected-root derivation, competing runner rejection, strict
  startup configuration, protected-file loading, and signed authority
  restoration on physical Darwin.

## Limits

This proves a host startup smoke, not an installed production service. It does
not establish credential, process-tree, remount, descriptor/fexec, Docker, or
external network isolation, nor Developer ID/signing provenance. The test
policy is temporary and `mac_task_run` remains disabled in the packaged
default until those host evidence and release gates are satisfied.
