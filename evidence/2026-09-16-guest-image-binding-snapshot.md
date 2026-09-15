# Guest Image Binding Snapshot Evidence

- Date: 2026-09-16
- Status: implemented and locally verified; virtualization remains disabled unless
  host gates, native isolation, and provenance evidence are independently closed.
- Source revision: `e613a5a5c63556f98b89004737dd2cd20728a9b9`
- Host: Darwin 25.2.0, arm64; macOS 26.2 (25C56)

## Boundary

`VirtualizationTaskRunner` now copies and recursively freezes the loaded guest
image binding before retaining it across asynchronous dispatch and recovery.
The immutable snapshot covers the canonical image path, validated guest
identity, publication class, and captured device/inode/size metadata. Later
caller-side mutation therefore cannot replace the image path, digest, identity,
or binding metadata used by `assertGuestImageStable`.

This is an in-process post-constructor binding boundary. It does not prove
kernel-level descriptor pinning, remount resistance, signed provenance, guest
isolation, or production virtualization enablement.

## Verification

Focused command:

```text
node --test packages/broker/dist/task-runner.test.js
```

Result: 13 tests passed, 0 failed, 0 skipped.

Additional checks passed:

- `npm run build`
- `npm run typecheck`
- `npm run lint`
- `git diff --check`

Serial physical regression (concurrency 1):

```text
MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 \
node --test --test-concurrency=1 $(find packages -path '*/dist/*.test.js' \
  ! -name 'broker.test.js' ! -name 'persistence.test.js' \
  ! -name 'privileged-helper-authority-ipc.test.js' | sort)
```

Result: 671 tests, 666 passed, 0 failed, 5 explicit descriptor-capability
skips. The three pre-existing long-running suites were excluded and left
untouched.

SHA-256 source readback:

```text
e8cd24b38ba01366bf01a6ea8afea565d0d77b1153eb9f5d0c0ca968b929f2c6  packages/broker/src/task-runner.ts
08fb967dd8902edbe52899748bf1a02c3b22083842b149bc408d2121435e2c16  packages/broker/src/task-runner.test.ts
```

## Rollback

Revert commit `e613a5a5c63556f98b89004737dd2cd20728a9b9` with
`git revert e613a5a` if this boundary must be withdrawn. No host policy,
credential, key, or virtualization enablement state was changed.
