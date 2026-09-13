# Filesystem worker concurrency and cancellation evidence

Status: PASS for bounded multi-root worker dispatch and cancellation-capacity
recovery; production-scale exhaustion, kernel-blocked I/O interruption, and
restart recovery remain OPEN.

- Date: 2026-09-13 (Asia/Kuala_Lumpur)
- Host profile: macOS 26.2, arm64
- Node: v25.5.0
- Source commit: `df4ba85bb72ff436aa3e119af6f439890e2840a8`
- Working tree before this evidence document: clean after the source commit
- Contract version: `0.1`
- Host mutation: two disposable temporary roots and two regular files were created and removed

## Boundary exercised

The real `WorkerFilesystemExecutor` fixture authorizes two independent roots,
searches both roots in one bounded worker request, and verifies both canonical
matches. A concurrency cap of one rejects an overlapping request with stable
`CONFLICT`; after the first worker exits, a later request succeeds.

The `BoundedWorkerExecutor` fixture cancels an active worker, verifies that the
cancelled promise returns `CANCELLED` while capacity remains occupied, waits
for worker termination, and proves that the released slot accepts new work.
This records the intentional rule that cancellation publication and capacity
release are separate events.

No service was started, no capability or policy was enabled, and no protected
content was read.

## Verification

- Focused filesystem/worker suites: `node --test packages/broker/dist/filesystem-inspector.test.js packages/broker/dist/filesystem-executor.test.js packages/broker/dist/worker-executor.test.js` — 36/36 passed.
- Default full suite: `npm test` — 369 tests, 367 passed, 2 opt-in real-sandbox tests skipped.
- Opt-in host suite: `MOPS_REAL_SANDBOX=1 npm test` — 367 passed, 2 opt-in real-sandbox tests skipped.
- Type/build: `npm run build` and `npm run typecheck -- --pretty false` — passed.
- Contract validation: `npm run verify:contracts` — 44 unique contracts validated.
- Dependency audit: `npm audit --omit=dev --audit-level=high` — 0 vulnerabilities.
- Boundary check: `git diff --check` — passed.

## Source hashes

```text
317dbe078ed935a1275d49a9e8b6fac2df0dbbb10385027a7375c966f3e4c666  packages/broker/src/worker-executor.test.ts
f89559ff4d9e33140e4d3d6f2a61d75ad469353d7841d941510a31ac22c9ed4f  packages/broker/src/filesystem-executor.test.ts
```

## Remaining limits

The fixtures do not prove 50,000-entry production-scale traversal, disk-full or
other I/O error injection, cancellation of a kernel-blocked syscall, worker
restart/recovery after host crash, or process-level sandbox isolation. The
worker remains a bounded thread boundary with empty environment/arguments and
V8 memory/stack limits, not a macOS sandbox or privileged boundary.
