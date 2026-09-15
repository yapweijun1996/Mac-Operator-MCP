# Edge contract ownership evidence

- Source revision: `1500196`
- Working tree: clean before this evidence-only documentation update
- Captured: `2026-09-15T18:50:02Z`
- Tool contract version: `0.1`
- Policy version: `policy-0.1`
- Host: Darwin `25.2.0`, arm64; macOS `26.2` build `25C56`
- Boundary: the Edge contract directory and each contract file must be owned
  by the Edge UID, regular, non-symlink, and not group/other writable before
  any contract is parsed or advertised. Opened-file metadata is still checked
  before and after reading.
- Source artifact SHA-256:
  - `packages/edge/src/contract-registry.ts`: `123c428669d9580bab275b8a724cfaf38c1a743e44a017d2689a6c1344de259a`

## Verification

```text
npm run typecheck
npm run lint
node --test packages/edge/dist/contract-registry.test.js \
  packages/edge/dist/protected-file.test.js
tests 14
pass 14
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

This closes Edge contract owner-integrity admission only. It does not prove
installed package provenance, code signing, native descriptor execution,
remote issuer deployment, or capability enablement.

## Rollback

Revert commit `1500196`. No installed service, host configuration, signing
key, or credential store was changed.
