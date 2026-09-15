# Task-profile startup wiring evidence

Date: 2026-09-15
Source revision: `d410631` (`feat: wire task profiles through service startup`)

## Boundary

`createBrokerServiceFromStartupConfig` accepts an explicit host-owned
`TaskProfileRegistry` and passes it into the Broker factory. The option is
valid only when an explicit sandbox or virtualization task runner is also
configured. A missing runner or a registry without the required `resolve` and
`names` methods fails closed before startup directories, sockets, policy, or
the Job Ledger are touched. The default packaged assembly supplies neither
option, so it retains an empty registry and the fail-closed task runner.

## Verification

Commands run from the repository root:

```text
npm run build
node --test --test-concurrency=1 packages/broker/dist/service-startup.test.js
```

Results:

- Service-startup tests: 7 passed, 0 failed, 0 skipped.
- The tests cover runnerless registry rejection, malformed registry
  rejection, protected-root derivation, competing runner rejection, strict
  startup configuration, protected-file loading, and signed authority
  restoration on physical Darwin.

## Limits

This proves only the startup composition seam. It does not prove that a named
profile has been executed through an installed service, nor does it establish
credential, process-tree, remount, descriptor/fexec, Docker, or external
network isolation. `mac_task_run` remains disabled until those host evidence
and release gates are satisfied.
