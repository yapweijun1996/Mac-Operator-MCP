# Edge contract canonical path evidence

- Source revision: `a688bfb`
- Working tree: clean before this evidence-only documentation update
- Captured: `2026-09-15T18:58:33Z`
- Tool contract version: `0.1`
- Policy version: `policy-0.1`
- Host: Darwin `25.2.0`, arm64; macOS `26.2` build `25C56`
- Boundary: `ToolContractRegistry.load()` now requires a canonical absolute
  directory and rejects a parent-directory symlink before contract parsing.
  Final directory readback also rechecks canonicality, owner UID, device, and
  inode. The test uses the realpath of macOS's temporary directory so the
  system `/var` alias is not mistaken for an attacker-controlled path.
- Source artifact SHA-256:
  - `packages/edge/src/contract-registry.ts`: `14b07286a674407f9af9782358e83a4df3e5ba6bd280201ba09f81e798be6282`
  - `packages/edge/src/contract-registry.test.ts`: `284eb91b1005abd441e09e08a3db53ab48c58ddef40e692ea04f8a6d9c1a649b`

## Verification

```text
npm run typecheck
npm run lint
node --test packages/edge/dist/contract-registry.test.js \
  packages/edge/dist/protected-file.test.js
tests 17
pass 17
fail 0

MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 \
  node --test --test-concurrency=1 <all dist tests except the three
  pre-existing long-running suites>
tests 665
pass 660
fail 0
skipped 5
```

The five skips are the explicit descriptor-capability real-sandbox probes.
The three pre-existing long-running suites were excluded and left untouched:
`broker.test.js`, `persistence.test.js`, and
`privileged-helper-authority-ipc.test.js`.

## Remaining gate

This closes the exported Edge contract loader's relative-path and parent
symlink admission gap. It does not prove installed package provenance, code
signing, native descriptor execution, remote issuer deployment, or capability
enablement.

## Rollback

Revert commit `a688bfb`. No installed service, host configuration, signing
key, or credential store was changed.
