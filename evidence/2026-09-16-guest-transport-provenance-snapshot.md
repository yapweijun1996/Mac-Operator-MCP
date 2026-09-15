# Guest Transport Provenance Snapshot Evidence

Date: 2026-09-16
Status: implemented and locally verified; virtualization capability remains disabled unless the existing host gates and native evidence are enabled
Source revision: `6241e24cfa0e61324efed241dbbb0f51f0cfa160`

## Boundary

`VirtualizationGuestTransportExecutor` now retains recursively frozen copies of
the validated guest identity and unsigned attestation. The nested identity is
also frozen. Later callers cannot rewrite image/runtime identity or attestation
claims after constructor validation and before a subsequent task exchange or
provenance check.

This is an in-process provenance-snapshot boundary. It does not claim native
Virtualization.framework isolation, production guest enablement, or signed
attestation verification when no verifier is configured.

## Host and source evidence

- Host: macOS Darwin 25.2.0 arm64, macOS 26.2 build 25C56.
- Source SHA-256: `9de4ec83ff759325c874bfdad20695a915a2633485d9a8fa04ce5d06a8cbc0ad` (`packages/broker/src/task-runner.ts`).
- Test SHA-256: `a30e4d0a4a91a0b5ea275263b8c0fe4fb30ee11d9278030070fab3302920cc74` (`packages/broker/src/task-runner.test.ts`).
- Working tree was clean after the source commit before this evidence addendum.

## Verification

Focused Guest/Runner/Agent/Transport suites:

```text
node --test packages/broker/dist/task-runner.test.js \
  packages/broker/dist/virtualization-guest-agent.test.js
33 tests, 33 passed, 0 failed, 0 skipped
```

The focused suite proves the executor exposes frozen identity and attestation
snapshots and rejects runtime mutation attempts with `TypeError`; exchange,
status recovery, response binding, and verification behavior remain intact.

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

Revert source revision `6241e24` to restore the previous mutable executor
fields, then rerun the focused Guest suites and serial regression. No host
files, policy state, credentials, or virtualization capability enablement were
changed.
