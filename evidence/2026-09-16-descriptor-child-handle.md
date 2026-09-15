# Descriptor child-handle validation evidence

- Source revision: `537bb37`
- Working tree: clean before the evidence-only documentation update
- Captured: `2026-09-15T18:18:46Z`
- Tool contract version: `0.1`
- Policy version: `policy-0.1`
- Host: Darwin `25.2.0`, arm64; macOS `26.2` build `25C56`
- Source artifact SHA-256: `packages/broker/src/process-supervisor.ts`
  `4a3ec576c189c08ed2849b6f34eb1bad6158e52a2d21020446bd6343560eab34`;
  `packages/broker/src/process-supervisor.test.ts`
  `4f0d24ba1920680bde0fac6e872764ff07a863015fa6800e5477fe4da8ff2b4d`
- Boundary: a Broker-owned descriptor launcher result is validated as a
  ChildProcess-like handle before output capture, identity observation, or
  cleanup. Invalid native return shapes map to bounded `EXECUTION_FAILED`;
  they cannot enter the process-ownership path as unchecked objects.

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

The five skips remain explicit descriptor-capability real-sandbox probes. The
three pre-existing long-running suites were excluded and left untouched:
`broker.test.js`, `persistence.test.js`, and
`privileged-helper-authority-ipc.test.js`.

## Remaining gate

This validates the native-launcher return boundary only. It does not provide
the native descriptor launcher, prove immutable executable selection or
remount resistance, or enable production task execution.

## Rollback

Revert commit `537bb37`. No installed service, host configuration, signing
key, or credential store was changed.
