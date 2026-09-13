# ProcessSupervisor close and Broker task-runner drain evidence

Date: 2026-09-13 (Asia/Kuala_Lumpur)
Source commit: `889ccdf` (`feat: drain broker-owned OS task processes`)
Working tree: clean before this evidence document was added
Host: Mac mini M4, `Darwin yaps-Mac-mini.local 25.2.0`, arm64
Runtime: Node `v25.5.0`; macOS platform reported by Node as `darwin`
Contract/policy: tool contracts `0.1`; Broker policy fixtures `policy-0.1`

## Scope

This addendum covers the lifecycle boundary for Broker-owned OS processes used
by the disabled `SandboxExecTaskRunner`. It does not enable `mac_task_run` and
does not claim crash-restart ownership after the Broker process itself exits.

## Implemented boundary

- `ProcessSupervisor.close()` closes admission before request execution,
  rejects valid new work with stable `CANCELLED`, sends cancellation to every
  active owned process group, and waits for each tracked process tree to drain.
- The existing PID/start-time checks, descendant signalling, group-drain
  polling, and `UNKNOWN_OUTCOME` path remain authoritative; close does not
  convert an unobserved termination into success.
- `SandboxExecTaskRunner.close()` forwards the ownership boundary to its
  supervisor, and `Broker.close()` includes the task runner after transport
  shutdown.
- The runner remains unavailable unless explicit host evidence, profile proof,
  and the macOS opt-in are supplied; `owned_group` remains disabled.

## Verification

- `process supervisor close drains owned processes and rejects new work` passes:
  an active `/bin/sleep` is cancelled, `terminationObserved` is true, capacity
  returns to zero, and the same supervisor rejects a subsequent valid request.
- `SandboxExecTaskRunner exposes its supervisor close boundary` passes with an
  injected supervisor close spy.
- Default regression: `npm test` — 380 total, 377 passed, 3 opt-in sandbox
  tests skipped.
- Opt-in host regression: `MOPS_REAL_SANDBOX=1 npm test` — 380/380 passed.
- `npm run typecheck -- --pretty false` and `git diff --check` pass.

## Remaining limits

This is graceful shutdown evidence for a live Broker instance. A crashed
Broker's OS descendants, post-snapshot `setsid` races, credential isolation,
and production task-runner enablement still require separate host evidence and
remain disabled.

Source hashes at capture:

```text
30bc97cf43e3474e48332bdffcab424d18656385826150f828df160e3b9ab780  packages/broker/src/process-supervisor.ts
e96ab4329b44ab57d8bbda599a26f9fd27ebbb9da6f37d4bda73d02fcef83409  packages/broker/src/process-supervisor.test.ts
f29f425023301ea3d22380ad1f428568e2109f2e3c615c257c26b8d6bf7882cb  packages/broker/src/task-runner.ts
8a21d0e0422fc40372dc32b5110879e81e9bd91838c990dd25524b0a23ddead9  packages/broker/src/sandbox-profile.test.ts
3577c329c529d4b3384cfdd74709faecd2246fe718c67d8d5325daa93273a95c  packages/broker/src/broker.ts
```
