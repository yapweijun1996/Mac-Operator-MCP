# Edge contract foreign-owner regression evidence

- Source revision: `edd2cff`
- Working tree: clean before this evidence-only documentation update
- Captured: `2026-09-15T18:51:49Z`
- Tool contract version: `0.1`
- Policy version: `policy-0.1`
- Host: Darwin `25.2.0`, arm64; macOS `26.2` build `25C56`
- Boundary: a foreign-owner simulation is rejected before the Edge contract
  directory is parsed. The test temporarily presents a mismatched UID and
  restores the process identity function in a `finally` block; no host file
  ownership is changed.
- Source artifact SHA-256:
  - `packages/edge/src/contract-registry.ts`: `123c428669d9580bab275b8a724cfaf38c1a743e44a017d2689a6c1344de259a`
  - `packages/edge/src/contract-registry.test.ts`: `bb8d0b017b0386daf432d4482f08c3afc7a4f300e265477235bb5f3195507fe1`

## Verification

```text
npm run typecheck
npm run lint
node --test packages/edge/dist/contract-registry.test.js \
  packages/edge/dist/protected-file.test.js
tests 15
pass 15
fail 0

MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 \
  node --test --test-concurrency=1 <all dist tests except the three
  pre-existing long-running suites>
tests 663
pass 658
fail 0
skipped 5
```

The five skips are the explicit descriptor-capability real-sandbox probes.
The three pre-existing long-running suites were excluded and left untouched:
`broker.test.js`, `persistence.test.js`, and
`privileged-helper-authority-ipc.test.js`.

## Remaining gate

This adds direct negative coverage for Edge contract owner integrity. It does
not prove installed package provenance, code signing, native descriptor
execution, remote issuer deployment, or capability enablement.

## Rollback

Revert commit `edd2cff`. No installed service, host configuration, signing
key, or credential store was changed.
