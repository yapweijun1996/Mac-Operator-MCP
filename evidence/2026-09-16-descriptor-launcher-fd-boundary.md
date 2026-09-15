# Descriptor launcher FD-boundary evidence

- Source revision: `2c2b10d`
- Working tree: clean before this evidence-only documentation update
- Captured: `2026-09-15T18:42:22Z`
- Tool contract version: `0.1`
- Policy version: `policy-0.1`
- Host: Darwin `25.2.0`, arm64; macOS `26.2` build `25C56`
- Boundary: descriptor-required `ProcessSupervisor` execution opens the
  Broker-validated executable with `O_NOFOLLOW`, rechecks the descriptor's
  device/inode/owner/group/mode/size/mtime/ctime against the validated
  identity, and passes only the borrowed descriptor FD to the native adapter.
  The adapter receives no executable pathname and must consume or duplicate
  the FD before returning; pathname spawn remains unavailable as a fallback.
- Source artifact SHA-256:
  - `packages/broker/src/process-supervisor.ts`: `55df46cfc2196f865827a15b13acd6cd349f7fbb6c40dd66084c76da45f1d16b`
  - `packages/broker/src/process-launch-capability.ts`: `db46533accbd7e39a609329ac6a039a7bd4e51b5798e0a4ac0db2e42721e09d5`
  - `packages/broker/src/process-supervisor.test.ts`: `4f0d24ba1920680bde0fac6e872764ff07a863015fa6800e5477fe4da8ff2b4d`
  - `packages/broker/src/process-launch-capability.test.ts`: `d4e866539c15f95b12e4902ec403e2a384ee1c56d4ef03de585c02e92890e91a`

## Verification

```text
npm run typecheck
npm run lint
node --test packages/broker/dist/process-supervisor.test.js \
  packages/broker/dist/process-launch-capability.test.js
tests 42
pass 42
fail 0

MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 \
  node --test --test-concurrency=1 <all dist tests except the three
  pre-existing long-running suites>
tests 662
pass 657
fail 0
skipped 5
```

The host still reports no complete native descriptor launcher, so the five
descriptor-capability real-sandbox probes remain explicit skips. The three
pre-existing long-running suites were excluded and left untouched:
`broker.test.js`, `persistence.test.js`, and
`privileged-helper-authority-ipc.test.js`.

## Remaining gate

This proves the Broker-to-adapter contract is descriptor-bound and fails closed
without native support. It does not prove that a native adapter exists,
consumes the FD atomically, enforces close-on-exec, snapshots immutable bytes,
resists remounts, or enables production task execution.

## Rollback

Revert commit `2c2b10d`. No installed service, host configuration, signing
key, or credential store was changed.
