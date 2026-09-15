# Descriptor child-handle validation evidence

- Source revision: `537bb37`
- Working tree: clean before the evidence-only documentation update
- Host: Darwin `25.2.0`, arm64; macOS `26.2` build `25C56`
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
