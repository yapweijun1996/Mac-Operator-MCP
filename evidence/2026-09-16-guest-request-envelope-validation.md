# Guest Request Envelope Validation Evidence

- Source revision: `19099e4`
- Working tree: clean before this evidence-only documentation update
- Captured: `2026-09-15T19:29:17Z`
- Host: Darwin `25.2.0`, arm64; macOS `26.2` build `25C56`
- Boundary: the virtualization guest executor snapshots caller data and then
  invokes the canonical strict transport validator. The profile registry also
  invokes that validator for direct callers, so no executor entry can bypass
  version, kind, identifier, guest identity, operation, or resource-limit
  checks before profile resolution or adapter execution.
- Source artifact SHA-256:
  - `packages/broker/src/virtualization-guest-executor.ts`:
    `f5b511a117d6e0a96a311148111ed5e81951f214aa8aea0d46fdc17bdf231c7a`
  - `packages/broker/src/virtualization-guest-executor.test.ts`:
    `42b46f9423fb4aaea1ef859c1e97a7f9dc32109851f2957799ca834eed43accf`

## Verification

```text
npm run build
node --test packages/broker/dist/virtualization-guest-executor.test.js
tests 12
pass 12
fail 0

node --test packages/broker/dist/virtualization-guest-agent.test.js \
  packages/broker/dist/virtualization-guest-attestation-keyring.test.js \
  packages/broker/dist/virtualization-guest-attestation.test.js \
  packages/broker/dist/virtualization-guest-bootstrap.test.js \
  packages/broker/dist/virtualization-guest-channel.test.js \
  packages/broker/dist/virtualization-guest-executor.test.js \
  packages/broker/dist/virtualization-guest-image.test.js \
  packages/broker/dist/virtualization-guest-lifecycle.test.js \
  packages/broker/dist/virtualization-guest-native.test.js \
  packages/broker/dist/virtualization-guest-startup.test.js \
  packages/broker/dist/virtualization-guest-transport.test.js \
  packages/broker/dist/virtualization-guest-vm-native.test.js
tests 78
pass 78
fail 0

npm run typecheck
npm run lint
git diff --check

MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 \
  node --test --test-concurrency=1 <all dist tests except the three
  pre-existing long-running suites>
tests 668
pass 663
fail 0
skipped 5
```

The five skips are explicit descriptor-capability real-sandbox probes. The
three pre-existing long-running suites were excluded and left untouched:
`broker.test.js`, `persistence.test.js`, and
`privileged-helper-authority-ipc.test.js`.

## Remaining gate

This closes strict request-envelope validation at the in-process guest
executor boundary only. It does not prove authenticated remote admission,
native descriptor execution, immutable executable selection, VM isolation,
production credential/process isolation, installed provenance, or
`mac_task_run` enablement.

## Rollback

Revert commit `19099e4`. No installed service, policy, signing key, or
credential store was changed.
