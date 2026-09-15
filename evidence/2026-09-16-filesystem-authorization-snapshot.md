# Filesystem Authorization Snapshot Evidence

Date: 2026-09-16
Status: implemented and locally verified; production capability remains governed by the existing policy and host gates
Source revision: `29abdd0d85dce1363f61270e425f11dbfe43dabe`

## Boundary

`FilesystemInspector` now copies and recursively freezes every normalized
filesystem root policy. `planPath()` also recursively freezes the complete
authorization plan, including the requested target, root policy, and captured
volume/device/inode identity. A later caller cannot replace a target, widen a
root, alter deny zones, or substitute the volume identity before an asynchronous
worker or adapter consumes the plan.

This is an in-process authorization-snapshot boundary. It does not claim native
descriptor execution, production sandbox enablement, or privileged capability
enablement.

## Host and source evidence

- Host: macOS Darwin 25.2.0 arm64, macOS 26.2 build 25C56.
- Source SHA-256: `cb1e3c1a4f3df1f002bbd24394edade876a6d132a1fa5180dfd587e0900450e6` (`packages/broker/src/filesystem-inspector.ts`).
- Test SHA-256: `9725385e67fb99646073752bbede9725dab9f3c2ed79ee85ba436a4353070c1e` (`packages/broker/src/filesystem-inspector.test.ts`).
- Working tree was clean after the source commit before this evidence addendum.

## Verification

Focused filesystem boundary:

```text
node --test packages/broker/dist/filesystem-inspector.test.js
38 tests, 38 passed, 0 failed, 0 skipped
```

The focused suite includes runtime mutation attempts against the plan, nested
root policy, deny-zone array, and captured volume identity; each attempt fails
with `TypeError` while the original snapshot remains usable.

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

Revert source revision `29abdd0` to restore the previous mutable in-process
plan behavior, then rerun the focused filesystem suite and the serial regression.
No host files, policy state, credentials, or capability enablement were changed.
