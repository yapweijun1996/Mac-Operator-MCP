# Sandbox startup wiring evidence

Date: 2026-09-15
Source revision: `2e605ea` (`feat: wire sandbox runner through service startup`)

## Boundary

`createBrokerServiceFromStartupConfig` now accepts an explicit host-only
`sandboxTaskRunner` option. Before constructing the runner it derives the
validated `packageRoot`, `dataRoot`, and `runtimeRoot`, merges them with any
additional host protected roots, and passes the result into
`SandboxExecTaskRunner`. The runner is injected into the Broker only when the
virtualization runner option is absent. Supplying both isolation mechanisms is
rejected before startup state is touched. The default startup path supplies
neither option, so the Broker still uses its fail-closed task runner and
`mac_task_run` remains disabled.

## Verification

Commands run from the repository root:

```text
npm run lint
npm run build
node --test packages/broker/dist/service-startup.test.js
MOPS_REAL_SANDBOX=1 node --test packages/broker/dist/sandbox-profile.test.js
npm run verify:contracts
npm run verify:canonical:native
git diff --check
```

Results:

- Service-startup tests: 5 passed, 0 failed.
- Sandbox-profile tests: 16 passed, 0 failed.
- The previous complete serial physical-Darwin run passed 607/607; a fresh
  full run during this change was affected by an unrelated long-running test
  process and is not used as evidence for this seam.
- Style, build, contract, native canonical-vector, and diff checks passed.

## Limits

This is an explicit composition boundary, not production capability
enablement. The packaged entrypoint still passes no sandbox runner by default;
host evidence, a valid isolation proof, real installed Broker-path checks,
credential/Docker isolation, process-tree ownership, and descriptor/remount
resistance remain required before enabling `mac_task_run`.
