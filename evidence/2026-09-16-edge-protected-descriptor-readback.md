# Edge protected descriptor readback evidence

- Source revision: `a01f540`
- Working tree: clean before this evidence-only documentation update
- Captured: `2026-09-15T18:36:28Z`
- Tool contract version: `0.1`
- Policy version: `policy-0.1`
- Host: Darwin `25.2.0`, arm64; macOS `26.2` build `25C56`
- Boundary: Edge authentication-key, TLS certificate/private-key, startup
  configuration, and tool-contract readers now compare device, inode, owner,
  group, mode, size, mtime, and ctime after reading through the opened
  descriptor. Changed or oversized bytes are wiped before rejection; the
  authentication-key loader also wipes its temporary source bytes after key
  derivation. Broker protected readers now wipe bytes when the post-read stat
  itself fails.
- Source artifact SHA-256:
  - `packages/edge/src/protected-file.ts`: `e932119127613d8a14737b3fae5f320787de9a4dfc3c32f1c6b4c841ce26a46a`
  - `packages/edge/src/protected-file.test.ts`: `dde492063362329f52ab832da3bb6bcea18aafae198ebc2145e9eeaaf9bbbb12`
  - `packages/edge/src/authentication-key.ts`: `be017bcdd131e4f134a27df9e987cfd43d0d714aa665f22f43a418f3cf29039f`
  - `packages/edge/src/tls-material.ts`: `c80c7e6134e3f362ab974e8f9af5c7fa27b398ee8331e9eed248d22ece0d09e0`
  - `packages/edge/src/service-startup.ts`: `b96fe18c1d76af2f821dfd5bef78166ea2509301d7b1a1bc3199af4e9534b202`
  - `packages/edge/src/contract-registry.ts`: `7323ba6c2ece9b3939bdc652a1c259ed59a28eb397f640edb0093de6c74c0997`
  - `packages/broker/src/protected-file.ts`: `73610d1f87064ee4e9340b18648e619613138bb917575161cc8e22d17e3af855`
  - `packages/broker/src/protected-file.test.ts`: `2811b2dfe2dcc9092e52ec75548b390ea583b1fe4b8484f0d14eeac49cba9f9e`

## Verification

```text
npm run typecheck
npm run lint
git diff --check
node --test packages/edge/dist/authentication-key.test.js \
  packages/edge/dist/tls-material.test.js \
  packages/edge/dist/service-startup.test.js \
  packages/edge/dist/contract-registry.test.js \
  packages/edge/dist/protected-file.test.js \
  packages/broker/dist/protected-file.test.js
tests 32
pass 32
fail 0

MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 \
  node --test --test-concurrency=1 <all dist tests except the three
  pre-existing long-running suites>
tests 662
pass 657
fail 0
skipped 5
```

The five skips are the explicit descriptor-capability real-sandbox probes.
The three pre-existing long-running suites were excluded and left untouched:
`broker.test.js`, `persistence.test.js`, and
`privileged-helper-authority-ipc.test.js`.

## Remaining gate

This closes Edge-side protected-file read-window checks only. It does not
prove atomic executable selection, remount resistance, production
credential/process isolation, installed launchd/helper signing, or capability
enablement.

## Rollback

Revert commit `a01f540`. No installed service, host configuration, signing
key, or credential store was changed.
