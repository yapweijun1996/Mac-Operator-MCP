# Descriptor-required process admission boundary

Date: 2026-09-16
Source revision: `a05cce8`
Host: Darwin 25.2.0, arm64, Node v25.5.0

## Boundary

`ProcessSupervisor` now has a Broker-owned `requireDescriptorExecution` option.
After the request has passed shape, path, argument, environment, and budget
validation, the supervisor requires the host-owned descriptor-execution
capability before registering capacity or calling Node `spawn`. Missing or
malformed native support produces the stable `POLICY_DENIED` error
`Kernel descriptor executable launch is unavailable`. The option is not part
of the MCP request and cannot be changed by tool arguments.

The default `SandboxExecTaskRunner` supervisor enables this option. Injected
supervisors remain available to unit tests as explicit test doubles; they do
not represent production host evidence.

## Verification

```text
node --test packages/broker/dist/process-supervisor.test.js
tests 38
pass 38
fail 0

node --test packages/broker/dist/process-launch-capability.test.js packages/broker/dist/sandbox-profile.test.js packages/broker/dist/task-runner.test.js
tests 71
pass 66
fail 0
skipped 5

npm run build
npm run typecheck
npm run lint
npm run verify:docs
npm run verify:matrix
```

The new regression supplies an `onStarted` callback and confirms it is not
called when descriptor-required admission is denied. No child process is
started and the supervisor active count remains zero. The physical native
adapter still exports no descriptor launcher or capability attestation, so the
gate is denied on this host.

## Remaining gate

This change wires an existing fail-closed capability contract into the real
process admission boundary; it is not a kernel descriptor-execution
implementation. `VT-FS-02` remains open until a supported native descriptor
primitive or an independently verified immutable executable snapshot with
close-on-exec and lifecycle proof is available.

## Rollback

Revert commit `a05cce8`; no installed service or host configuration was
changed.
