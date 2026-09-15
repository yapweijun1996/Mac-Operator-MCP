# Resolved Task Profile Snapshot Evidence

- Source revision: `45e1472`
- Working tree: clean before this evidence-only documentation update
- Captured: `2026-09-15T19:22:46Z`
- Host: Darwin `25.2.0`, arm64; macOS `26.2` build `25C56`
- Boundary: `TaskProfileRegistry.resolve()` recursively freezes the resolved
  Broker-owned task profile before it crosses into a task adapter. The
  executable, cwd, explicit environment, filesystem roots, network allowlist,
  process-tree policy, verification strategy, and process budgets are one
  immutable authorization snapshot.
- Source artifact SHA-256:
  - `packages/broker/src/task-profile.ts`:
    `d7c9718cc59d3e8a836dcf58591d5fb130668888cc6ce1d1fcd67dd790105030`
  - `packages/broker/src/task-profile.test.ts`:
    `212dea24e2c3e65093df9edacdf23a505ff84074a31ea20e37746384694217f0`

## Verification

```text
npm run build
node --test packages/broker/dist/task-profile.test.js \
  packages/broker/dist/task-runner.test.js \
  packages/broker/dist/sandbox-profile.test.js
tests 37
pass 32
fail 0
skipped 5

npm run typecheck
npm run lint

MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 \
  node --test --test-concurrency=1 <all dist tests except the three
  pre-existing long-running suites>
tests 667
pass 662
fail 0
skipped 5
```

The five skips are explicit descriptor-capability real-sandbox probes. The
three pre-existing long-running suites were excluded and left untouched:
`broker.test.js`, `persistence.test.js`, and
`privileged-helper-authority-ipc.test.js`.

## Remaining gate

This closes post-resolution mutation of the in-memory task profile only. It
does not prove kernel-held descriptor execution, immutable executable
selection, remount resistance, production credential/process isolation,
installed provenance, or `mac_task_run` enablement.

## Rollback

Revert commit `45e1472`. No installed service, policy, signing key, or
credential store was changed.
