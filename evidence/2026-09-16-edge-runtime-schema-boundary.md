# Edge runtime functional-schema boundary evidence

- Source revision: `e1c10a2`
- Working tree: clean before this evidence-only documentation update
- Captured: `2026-09-15T19:02:32Z`
- Tool contract version: `0.1`
- Policy version: `policy-0.1`
- Host: Darwin `25.2.0`, arm64; macOS `26.2` build `25C56`
- Boundary: the Edge runtime contract loader now recursively checks
  model-editable input schemas for forbidden authority-shaped property names
  and enforces bounded schema depth, node count, array size, and property
  count. This mirrors the build-time contract verifier before schemas reach
  the MCP SDK.
- Source artifact SHA-256:
  - `packages/edge/src/contract-registry.ts`: `44cd4b427ee72dd246a52104233b8743176ca8ea091a3fd8a808310b89f43e83`
  - `packages/edge/src/contract-registry.test.ts`: `ec5e47899aa161c45d10e88815499c7f6de9290de02fef2c56797dfe290e0c78`

## Verification

```text
npm run typecheck
npm run lint
node --test packages/edge/dist/contract-registry.test.js \
  packages/edge/dist/protected-file.test.js
tests 18
pass 18
fail 0

MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 \
  node --test --test-concurrency=1 <all dist tests except the three
  pre-existing long-running suites>
tests 666
pass 661
fail 0
skipped 5
```

The five skips are the explicit descriptor-capability real-sandbox probes.
The three pre-existing long-running suites were excluded and left untouched:
`broker.test.js`, `persistence.test.js`, and
`privileged-helper-authority-ipc.test.js`.

## Remaining gate

This closes the runtime Edge input-schema authority-field and structural
budget gap. It does not prove installed package provenance, code signing,
native descriptor execution, remote issuer deployment, or capability
enablement.

## Rollback

Revert commit `e1c10a2`. No installed service, host configuration, signing
key, or credential store was changed.
