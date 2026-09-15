# Edge Contract Immutable Snapshot Evidence

- Source revision: `1bedb5d`
- Working tree: clean before this evidence-only documentation update
- Captured: `2026-09-15T19:14:25Z`
- Host: Darwin `25.2.0`, arm64; macOS `26.2` build `25C56`
- Boundary: the Edge contract registry recursively freezes each validated
  contract graph before retaining it or passing it to MCP registration. The
  required-scope list and nested functional input schema are part of the same
  immutable snapshot, so later callers cannot alter authorization or schema
  data after validation.
- Source artifact SHA-256:
  - `packages/edge/src/contract-registry.ts`:
    `fa369ea3ba7e867ce85dd99c446a88445becf9f6399a21addda5ab709b4bfced`
  - `packages/edge/src/contract-registry.test.ts`:
    `889e078ee3ec75a6dcfd891bd9eefcd3b22ed32455a12b102955ef7133a76920`

## Verification

```text
npm run typecheck
npm run lint
node --test packages/edge/dist/contract-registry.test.js \
  packages/edge/dist/protected-file.test.js
tests 19
pass 19
fail 0

npm run build
MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 \
  node --test --test-concurrency=1 <all dist tests except the three
  pre-existing long-running suites>
tests 667
pass 662
fail 0
skipped 5
```

The five skips are explicit descriptor-capability real-sandbox probes. The
three pre-existing long-running suites were excluded and left untouched:
`broker.test.js`, `persistence.test.js`, and
`privileged-helper-authority-ipc.test.js`.

## Remaining gate

This closes post-validation mutation of the in-memory Edge contract graph. It
does not provide installed package provenance, signing-key protection,
kernel-held descriptor execution, remount resistance, production task
isolation, remote issuer deployment, or capability enablement.

## Rollback

Revert commit `1bedb5d`. No installed service, policy, signing key, or
credential store was changed.
