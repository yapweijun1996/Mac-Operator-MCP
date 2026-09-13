# Atomic write storage-error evidence

Status: PASS for deterministic write-error cleanup and preservation of the
pre-existing target; physical disk-full, remount, and kernel-level I/O error
evidence remain OPEN.

- Date: 2026-09-13 (Asia/Kuala_Lumpur)
- Host profile: macOS 26.2, arm64
- Node: v25.5.0
- Source commit: `0ac3e1555ccdb230f50030daacb7551cb3a801ac`
- Working tree before this evidence document: clean after the source commit
- Contract version: `0.1`
- Host mutation: disposable temporary regular files only; no physical volume was filled or remounted

## Boundary exercised

The fault-test-only native module injects `ENOSPC` at the temporary-file write
and temporary-file `fsync` boundaries. The fixture covers create and replace
operations. Each failure exits non-zero without a signal, leaves a pre-existing
target unchanged (or leaves a new target absent), and removes the exact
temporary artifact. The production native module does not export or enable the
fault injection hook.

This is deterministic error-path evidence, not a claim that a real disk-full
condition or filesystem remount was reproduced.

## Verification

- Focused filesystem suite: `node --test packages/broker/dist/filesystem-inspector.test.js` — 31/31 passed.
- Default full suite: `npm test` — 370 tests, 368 passed, 2 opt-in real-sandbox tests skipped.
- Opt-in host suite: `MOPS_REAL_SANDBOX=1 npm test` — 368 passed, 2 opt-in real-sandbox tests skipped.
- Type/build: `npm run build` and `npm run typecheck -- --pretty false` — passed.
- Contract validation: `npm run verify:contracts` — 44 unique contracts validated.
- Dependency audit: `npm audit --omit=dev --audit-level=high` — 0 vulnerabilities.
- Boundary check: `git diff --check` — passed.

## Source hashes

```text
0d2abbd9392745108b3beb56993497536dce29e7e03d64218b7ea9523f2a8ebb  packages/broker/native/peer_credentials.cc
1a0c74ba5f53786287f684f42aeec8998bc9912fe0da13176220baa731496eba  packages/broker/src/filesystem-inspector.test.ts
```

## Remaining limits

The fault point is compiled only by `build:native:fault-test`; it does not
prove physical disk capacity behavior, delayed I/O errors, remount identity,
kernel-blocked cancellation, or crash/restart recovery under storage pressure.
No capability was enabled.
