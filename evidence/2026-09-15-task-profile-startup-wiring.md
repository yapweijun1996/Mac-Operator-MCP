# Task-profile startup wiring evidence

Date: 2026-09-15
Source revision: `a9a5de6` (`test: prove startup protected-root denial`)

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
and verifies the authenticated response plus completed Job readback. A second
approved profile attempts to read the Broker database beneath the protected
data root; Seatbelt denies the read, the authenticated response is the stable
`VERIFICATION_FAILED` class, and the Job readback is `failed`. The test profile
is fixed to `/usr/bin/printf`, an empty environment, one temporary task root,
and a 5-second/1 KiB budget.

## Verification

Commands run from the repository root:

```text
npm run build
node --test --test-concurrency=1 packages/broker/dist/service-startup.test.js
MOPS_REAL_SANDBOX=1 node --test --test-concurrency=1 packages/broker/dist/service-startup.test.js
MOPS_REAL_SANDBOX=1 node --test --test-concurrency=1 packages/broker/dist/sandbox-profile.test.js
```

Results:

- Service-startup tests: 7 passed, 0 failed, 0 skipped.
- The physical-Darwin run also passed 7/7 and completed the signed
  `mac_task_run` startup path through native UDS, sandbox execution, approval,
  and Job readback; the protected-database profile was denied with
  `VERIFICATION_FAILED` and a failed Job.
- Sandbox-profile tests: 16 passed, 0 failed, 0 skipped, including the real
  protected-root, process-tree, cancellation, and UDP loopback checks.
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
