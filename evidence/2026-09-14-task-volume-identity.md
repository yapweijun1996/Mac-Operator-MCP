# Task Volume-Identity Evidence

Date: 2026-09-14
Host: physical Darwin arm64 development host
Scope: experimental task runner; no production capability enablement

## Commands

```text
npm run typecheck
npm run build
MOPS_REAL_SANDBOX=1 node --test packages/broker/dist/task-profile.test.js packages/broker/dist/task-runner.test.js packages/broker/dist/sandbox-profile.test.js
MOPS_REAL_SANDBOX=1 npm test
```

## Observed result

- Focused TaskProfile/runner/sandbox suite: 20/20 passed.
- Full real-sandbox suite: 449/450 passed, 0 failed, 1 explicit host-boundary/opt-in skip.
- The volume-swap tests changed the observed root identity during preflight, at
  process start, and after the supervisor returned; the runner rejected each
  result with `POLICY_DENIED`.

## Boundary

Before launch, `SandboxExecTaskRunner` asks the protected native adapter twice
for a bounded `{ rootPath, id }` identity for every resolved filesystem root.
The process-start callback repeats the check after spawn and before Broker
ownership persistence; after the supervisor returns, it asks again and requires
the same canonical root and volume ID. Malformed, missing, reordered, or changed
identities fail closed; Broker therefore cannot publish a task result whose
authorized root has been replaced or remounted at those execution boundaries.

## Limitations

The check is a pre/post readback guard. It does not hold a kernel mount
namespace or descriptor-backed root open for the entire child lifetime, so a
mount swap that occurs during a child syscall could still affect that syscall
and will only be detected before result publication. The runner remains
deprecated `sandbox-exec` evidence and `mac_task_run` remains disabled by
default.
