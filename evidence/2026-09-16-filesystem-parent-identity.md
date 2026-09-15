# Filesystem Parent Directory Identity Evidence

- Source revision: `bba64c1`
- Working tree: clean before this evidence-only documentation update
- Captured: `2026-09-15T19:10:06Z`
- Host: Darwin `25.2.0`, arm64; macOS `26.2` build `25C56`
- Boundary: native filesystem write, unlink, and unlink-recovery operations
  now compare the canonical parent directory's device/inode with the opened
  parent descriptor before acting on a child name. A parent replacement after
  canonicalization therefore fails closed instead of silently mutating a
  different same-root directory.
- Source artifact SHA-256:
  - `packages/broker/native/peer_credentials.cc`:
    `366ed93d0503b83709a527ed97b76a84c7d88138ea24ce3906c2c8467b245fae`
  - `packages/broker/src/filesystem-inspector.test.ts`:
    `4b236af84330776e5b40d33744f35fb410be37b62f1e2e46c544081795cb3432`

## Verification

```text
npm run build:native --workspace @mac-operator/broker
npm run typecheck
npm run lint
node --test packages/broker/dist/filesystem-inspector.test.js
tests 37
pass 37
fail 0

npm run build
MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 \
  node --test --test-concurrency=1 <all dist tests except the three
  pre-existing long-running suites>
tests 666
pass 661
fail 0
skipped 5
```

The five skips are explicit descriptor-capability real-sandbox probes. The
three pre-existing long-running suites were excluded and left untouched:
`broker.test.js`, `persistence.test.js`, and
`privileged-helper-authority-ipc.test.js`.

## Remaining gate

This closes the parent-directory replacement check for implemented native
filesystem mutations and recovery. It does not provide kernel-held
descriptor execution for task children, in-syscall remount resistance,
production task isolation, installed package provenance, or capability
enablement.

## Rollback

Revert commit `bba64c1`. No installed service, policy, signing key, or
credential store was changed.
