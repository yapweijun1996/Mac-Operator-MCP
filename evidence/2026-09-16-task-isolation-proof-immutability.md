# Task Isolation Proof Immutability Evidence

- Source revision: `d179132`
- Working tree: clean before this evidence-only documentation update
- Captured: `2026-09-15T19:18:43Z`
- Host: Darwin `25.2.0`, arm64; macOS `26.2` build `25C56`
- Boundary: `validateTaskIsolationProof` now recursively freezes the returned
  proof graph before a runner retains it. This covers top-level sandbox and
  process-tree claims and nested virtualization guest identity, preventing a
  later runtime mutation from changing the host's isolation authorization
  snapshot.
- Source artifact SHA-256:
  - `packages/broker/src/task-runner.ts`:
    `b3fa4b38f7f868435031fc3273fc0e20112edbaf56c040332aa4198325bd2a28`
  - `packages/broker/src/task-runner.test.ts`:
    `d4461dcc43aa7bce3170b4729d27841ac4a8083cd47318def0052aa2c9d0c7c8`

## Verification

```text
npm run build
node --test packages/broker/dist/task-runner.test.js \
  packages/broker/dist/sandbox-profile.test.js \
  packages/broker/dist/virtualization-guest-attestation.test.js
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

This closes post-validation mutation of the in-memory isolation proof only. It
does not prove native descriptor execution, close-on-exec, immutable
executable snapshots, remount resistance, production credential/process
isolation, installed provenance, or `mac_task_run` enablement.

## Rollback

Revert commit `d179132`. No installed service, policy, signing key, or
credential store was changed.
