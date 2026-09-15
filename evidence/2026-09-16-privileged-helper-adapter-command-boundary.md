# Privileged Helper Adapter Command Boundary Evidence

- Source revision: `60fe9ec`
- Working tree: clean before this evidence-only documentation update
- Captured: `2026-09-15T19:39:50Z`
- Host: Darwin `25.2.0`, arm64; macOS `26.2` build `25C56`
- Boundary: `AllowlistedPrivilegedHelper` now validates the complete command
  envelope (including exact fields, operation and target allowlists, payload
  schema, and payload digest binding) before selecting or invoking a handler.
- Source artifact SHA-256:
  - `packages/broker/src/privileged-helper.ts`:
    `cf453f630b28624ff4bf82e6b9449305b7be709ded53c98094c5230ac819df60`
  - `packages/broker/src/privileged-helper.test.ts`:
    `ee2d3ecd49ad50f8cc66800e29f9fda18b9efc98bde1681baeb716ec2a976df9`

## Verification

```text
npm run build
node --test packages/broker/dist/privileged-helper.test.js \
  packages/broker/dist/privileged-helper-executor.test.js
tests 27
pass 27
fail 0

npm run typecheck
npm run lint
git diff --check

MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 \
  node --test --test-concurrency=1 <all dist tests except the three
  pre-existing long-running suites>
tests 670
pass 665
fail 0
skipped 5
```

The five skips are explicit descriptor-capability real-sandbox probes. The
three pre-existing long-running suites were excluded and left untouched:
`broker.test.js`, `persistence.test.js`, and
`privileged-helper-authority-ipc.test.js`.

## Remaining gate

This closes direct handler invocation with an unbound or malformed command
only. It does not prove authenticated helper transport, privileged host
deployment, installed provenance, or capability enablement.

## Rollback

Revert commit `60fe9ec`. No installed service, policy, signing key, or
credential store was changed.
