# Descriptor launcher seam evidence

- Source revision: `b228089`
- Working tree: clean before the evidence-only documentation update
- Host: Darwin `25.2.0`, arm64; macOS `26.2` build `25C56`
- Boundary: `ProcessSupervisor` now accepts a Broker-owned
  `DescriptorProcessSpawnAdapter` only when descriptor execution is required.
  Descriptor-required admission first requires the host capability and then
  requires the concrete launcher seam; an absent seam returns stable
  `POLICY_DENIED` instead of invoking pathname `spawn`. When a seam is wired,
  only that adapter is selected, so capability metadata cannot silently become
  a pathname fallback.

## Verification

```text
npm run typecheck
npm run lint
node --test packages/broker/dist/process-supervisor.test.js packages/broker/dist/process-launch-capability.test.js
tests 42
pass 42
fail 0

MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 \
  node --test --test-concurrency=1 <all dist tests except the three
  pre-existing long-running suites>
tests 654
pass 649
fail 0
skipped 5
```

The five skips remain the explicit descriptor-capability real-sandbox probes;
the host still has no verified native descriptor executable launcher. The
three pre-existing long-running suites were excluded and left untouched:
`broker.test.js`, `persistence.test.js`, and
`privileged-helper-authority-ipc.test.js`.

## Remaining gate

This closes a latent pathname-fallback condition in the Broker admission
boundary. It does not implement the native descriptor launcher, prove
immutable executable selection or remount resistance, or enable production
task execution.

## Rollback

Revert commit `b228089`. No installed service, host configuration, signing
key, or credential store was changed.
