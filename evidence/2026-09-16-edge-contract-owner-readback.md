# Edge contract owner readback evidence

- Source revision: `32c277e`
- Working tree: clean before this evidence-only documentation update
- Captured: `2026-09-15T19:28:00Z`
- Tool contract version: `0.1`
- Policy version: `policy-0.1`
- Host: Darwin `25.2.0`, arm64; macOS `26.2` build `25C56`
- Boundary: the Edge contract registry now rechecks the contract directory's
  owner UID after all contract files have been read. A simulated owner change
  during loading is rejected at final readback, before the registry is
  returned. The test restores the process identity function in a `finally`
  block; no host ownership is changed.
- Source artifact SHA-256:
  - `packages/edge/src/contract-registry.ts`: `69289ad8d7908e125301ea73f3cb034bbbfadd0d32e99122459883eecdaaf6a7`
  - `packages/edge/src/contract-registry.test.ts`: `7787aae840aed4d0e3ceda80ca7580348b0c7170a74d13803bc79ec0001e71a9`

## Verification

```text
npm run typecheck
npm run lint
node --test packages/edge/dist/contract-registry.test.js \
  packages/edge/dist/protected-file.test.js
tests 16
pass 16
fail 0

MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 \
  node --test --test-concurrency=1 <all dist tests except the three
  pre-existing long-running suites>
tests 664
pass 659
fail 0
skipped 5
```

The five skips are the explicit descriptor-capability real-sandbox probes.
The three pre-existing long-running suites were excluded and left untouched:
`broker.test.js`, `persistence.test.js`, and
`privileged-helper-authority-ipc.test.js`.

## Remaining gate

This closes the contract-directory owner readback window in the Edge loader.
It does not prove installed package provenance, code signing, native descriptor
execution, remote issuer deployment, or capability enablement.

## Rollback

Revert commit `32c277e`. No installed service, host configuration, signing
key, or credential store was changed.
