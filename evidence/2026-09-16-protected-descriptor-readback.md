# Protected descriptor readback evidence

- Source revision: `ea50824`
- Working tree: clean before the evidence-only documentation update
- Captured: `2026-09-15T18:30:08Z`
- Tool contract version: `0.1`
- Policy version: `policy-0.1`
- Host: Darwin `25.2.0`, arm64; macOS `26.2` build `25C56`
- Boundary: policy, Edge-key, approval-key, policy-signer, authority-control,
  privileged-helper, and guest-attestation protected readers now read through
  an already-open descriptor and compare device, inode, owner, mode, size,
  mtime, and ctime after reading. Changed or oversized content is wiped and
  rejected before parsing or key activation.
- Source artifact SHA-256: `packages/broker/src/protected-file.ts`
  `063c674758e9676c66924771f2809e630dfcaee66e9e33e2b608c7599e74b43d`;
  `packages/broker/src/protected-file.test.ts`
  `67bc3f5ecd3a2bd95506b25811d131ef075685a2b96a4d04e392e9c17a8081b2`;
  `packages/broker/src/policy-loader.ts`
  `05888eb60f542b1dad7641a39afa214cc23f17cd59c8f49e5cf988ad91131413`.

## Verification

```text
npm run typecheck
npm run lint
node --test packages/broker/dist/protected-file.test.js \
  packages/broker/dist/policy-loader.test.js \
  packages/broker/dist/policy-signer-keyring.test.js \
  packages/broker/dist/authority-control-keyring.test.js \
  packages/broker/dist/privileged-helper-keyring.test.js \
  packages/broker/dist/virtualization-guest-attestation-keyring.test.js \
  packages/broker/dist/edge-keyring-config.test.js
tests 38
pass 38
fail 0

MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 \
  node --test --test-concurrency=1 <all dist tests except the three
  pre-existing long-running suites>
tests 657
pass 652
fail 0
skipped 5
```

The five skips are the explicit descriptor-capability real-sandbox probes.
The three pre-existing long-running suites were excluded and left untouched:
`broker.test.js`, `persistence.test.js`, and
`privileged-helper-authority-ipc.test.js`.

## Remaining gate

This closes the protected descriptor readback window for the listed readers.
It does not prove atomic executable selection, remount resistance, production
credential/process isolation, installed launchd/helper signing, or capability
enablement.

## Rollback

Revert commit `ea50824`. No installed service, host configuration, signing
key, or credential store was changed.
