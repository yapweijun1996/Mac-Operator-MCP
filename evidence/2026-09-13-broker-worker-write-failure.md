# Broker real-worker write-failure evidence

Status: PASS for real filesystem-worker failure admission and UNKNOWN Job
recovery; post-rename failure through the real worker, physical disk-full, and
restart/volume recovery remain OPEN.

- Date: 2026-09-13 (Asia/Kuala_Lumpur)
- Host profile: macOS 26.2, arm64 Mac mini
- Source commit: `2371eba5ca4b3d54dfcadd31e0e5584ec3cf4a97`
- Working tree before this evidence document: clean after the source commit
- Contract version: `0.1`
- Host mutation: one disposable temporary directory; its mode was changed to read-only and restored

## Boundary exercised

The Broker uses a real `WorkerFilesystemExecutor`, not a fake executor. Policy
authorization and filesystem plan capture succeed against a metadata-readable,
write-authorized root. The worker then attempts the atomic write while its
parent directory is mode `0500`; temporary-file creation fails closed. The
Broker returns a stable failure, persists the mutation Job as `UNKNOWN`, leaves
the target absent, and exposes `mac_job_status` recovery as
`unavailable / remains_unknown`.

No capability was enabled and no service, credential, or protected content was
touched.

## Verification

- Focused Broker suite: `node --test packages/broker/dist/broker.test.js` — 61/61 passed.
- Default full suite: `npm test` — 371 tests, 369 passed, 2 opt-in real-sandbox tests skipped.
- Opt-in host suite: `MOPS_REAL_SANDBOX=1 npm test` — 371/371 passed.
- Type/build: `npm run build` and `npm run typecheck -- --pretty false` — passed.
- Contract validation: `npm run verify:contracts` — 44 unique contracts validated.
- Dependency audit: `npm audit --omit=dev --audit-level=high` — 0 vulnerabilities.
- Boundary check: `git diff --check` — passed.

## Source hash

```text
e403bdbdc12fffcb49854dca2aed6f546a8aca073a867b13a58f9de49167d2e5  packages/broker/src/broker.test.ts
```

## Remaining limits

This proves a real worker failure before temporary-file creation, not a real
worker failure after rename. The deterministic native fault-test covers that
post-commit window separately, while Broker integration currently uses a
controlled executor for the same UNKNOWN invariant. Physical disk exhaustion,
kernel-blocked I/O, worker crash/restart ownership, and remount behavior remain
release-gate work.
