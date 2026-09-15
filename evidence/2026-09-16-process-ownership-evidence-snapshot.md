# Process Ownership Evidence Snapshot

Date: 2026-09-16
Status: implemented and locally verified; production task execution remains gated by native descriptor and isolation evidence
Source revision: `17aa71eff88d04beb66d45a870bdd8596518e81e`

## Boundary

`ProcessSupervisor` now recursively freezes every process ownership snapshot
before invoking `onStarted` or `onOwnershipChanged`. A persistence callback
cannot rewrite the PID, process-group ID, start-time identity, descendant list,
or no-fork proof that the Broker records for cancellation and restart recovery.

This protects the in-process evidence handoff only. It does not claim kernel
descriptor execution, process-tree isolation, or production task enablement.

## Host and source evidence

- Host: macOS Darwin 25.2.0 arm64, macOS 26.2 build 25C56.
- Source SHA-256: `16922b9c7415bb6e380c5cdc89891a0c63b62285ed1c071818ea094e30f751a5` (`packages/broker/src/process-supervisor.ts`).
- Test SHA-256: `3b4c309ca4b4b013857ff2d3745347167ac3cc032747d7e2c2338d5324ad04ff` (`packages/broker/src/process-supervisor.test.ts`).
- Working tree was clean after the source commit before this evidence addendum.

## Verification

Focused supervisor suite:

```text
node --test packages/broker/dist/process-supervisor.test.js
39 tests, 39 passed, 0 failed, 0 skipped
```

The recovery test confirms the callback receives frozen top-level, identity,
and descendant snapshots, and that a runtime PID mutation raises `TypeError`.

Repository checks:

```text
npm run build
npm run typecheck
npm run lint
git diff --check
```

All passed. The serial physical regression (with the three pre-existing
long-running suites excluded and left untouched) passed:

```text
MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 \
node --test --test-concurrency=1 $(find packages -path '*/dist/*.test.js' \
  ! -name 'broker.test.js' ! -name 'persistence.test.js' \
  ! -name 'privileged-helper-authority-ipc.test.js' | sort)
671 tests, 666 passed, 0 failed, 5 skipped
```

The five skips are the explicit descriptor-capability tests already documented
as unavailable without the native launcher boundary.

## Rollback

Revert source revision `17aa71e` to restore the previous callback handoff, then
rerun the focused supervisor suite and serial regression. No host files, Job
state, credentials, or capability enablement were changed.
