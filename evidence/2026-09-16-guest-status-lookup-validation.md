# Guest Status Lookup Validation Evidence

- Source revision: `6ad2046`
- Working tree: clean before this evidence-only documentation update
- Captured: `2026-09-15T19:31:44Z`
- Host: Darwin `25.2.0`, arm64; macOS `26.2` build `25C56`
- Boundary: `VirtualizationGuestProfileExecutor.lookup()` now snapshots a
  validated status request before reading the bounded execution ledger or
  constructing a status response. Direct in-process callers therefore cannot
  bypass the versioned status kind, identifiers, guest identity, operation,
  or output/time limits.
- Source artifact SHA-256:
  - `packages/broker/src/virtualization-guest-executor.ts`:
    `c5c20a6e72f679230e55e1a6e3d65b693db4df2cca7ec396f3dbb2b0210f7c9e`
  - `packages/broker/src/virtualization-guest-executor.test.ts`:
    `912e264a4a2691b44e672a8b325af9548cb8adb43d904c9a18a7fd2f7cb58c19`

## Verification

```text
npm run build
node --test packages/broker/dist/virtualization-guest-executor.test.js \
  packages/broker/dist/virtualization-guest-agent.test.js \
  packages/broker/dist/virtualization-guest-transport.test.js
tests 32
pass 32
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

This closes direct in-process status-envelope bypass only. It does not prove
authenticated remote admission, native descriptor execution, immutable
executable selection, VM isolation, production credential/process isolation,
installed provenance, or `mac_task_run` enablement.

## Rollback

Revert commit `6ad2046`. No installed service, policy, signing key, or
credential store was changed.
