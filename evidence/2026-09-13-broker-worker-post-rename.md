# Broker real-worker post-rename failure evidence

Status: PASS for the real worker post-rename ambiguous-outcome boundary;
physical disk-full, remount, and worker restart ownership remain OPEN.

- Date: 2026-09-13 (Asia/Kuala_Lumpur)
- Host profile: macOS 26.2, arm64 Mac mini
- Source commit: `42268d2b04b498fe7abe35508567bdba1d8acaa9`
- Working tree before this evidence document: clean after the source commit
- Contract version: `0.1`
- Host mutation: one disposable temporary directory and atomic test file

## Boundary exercised

The Broker test explicitly selects a test-only worker URL and fault native
adapter; no MCP argument can select either. The worker performs the real
descriptor-relative write and injects `ENOSPC` after atomic rename but before
the parent-directory `fsync`. The worker returns a failure, while the target
already contains the requested bytes and the temporary artifact is gone.

Broker preserves the Job as `UNKNOWN`, does not publish success, and a later
`mac_job_status` request reads `matches / remains_unknown`. The production
`WorkerFilesystemExecutor` default still uses the fixed
`filesystem-worker.js`, and the production native adapter still loads through
the protected artifact validator.

## Verification

- Focused Broker suite: `node --test packages/broker/dist/broker.test.js` — 62/62 passed.
- Default full suite: `npm test` — 372 tests, 370 passed, 2 opt-in real-sandbox tests skipped.
- Opt-in host suite: `MOPS_REAL_SANDBOX=1 npm test` — 372/372 passed.
- Type/build: `npm run build` and `npm run typecheck -- --pretty false` — passed.
- Contract validation: `npm run verify:contracts` — 44 unique contracts validated.
- Dependency audit: `npm audit --omit=dev --audit-level=high` — 0 vulnerabilities.
- Boundary check: `git diff --check` — passed.

## Source hashes

```text
31fb5bba5432171395da13cf59279e459c07550c364a23cfd6b15d4f5e4f8f50  packages/broker/src/filesystem-executor.ts
96d03c0de00edc03fbc1129aec58884127ef4a13cec7a30c64e6872468a04a12  packages/broker/src/filesystem-inspector.ts
e2a1c6076874e11692131068cd95a51ef7e06c3ed21e19751d82b81894a9bd51  packages/broker/src/filesystem-fault-worker.ts
28ac90227c1b12680c815c52b8a21df2935074fb4be4a37776379b4b267230da  packages/broker/src/broker.test.ts
```

## Remaining limits

The fault worker is compiled and selected only by the controlled test. It does
not prove physical storage exhaustion, delayed filesystem errors, remount
identity, kernel-blocked cancellation, or worker crash/restart recovery. The
default production worker path remains unchanged and no capability was enabled.
