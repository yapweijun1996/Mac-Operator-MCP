# Bounded patch write evidence

Date: 2026-09-14
Host: Darwin arm64 development Mac
Scope: `mac_apply_patch` Broker/native prototype

## Evidence

- `npm run typecheck` passed.
- `node --test packages/broker/dist/broker.test.js packages/broker/dist/filesystem-patch.test.js` passed 73/73 after the native adapter build, including injected second-write rollback and rollback-failure `UNKNOWN_OUTCOME` cases.
- `MOPS_REAL_SANDBOX=1 node --test --test-concurrency=1 packages/*/dist/**/*.test.js` passed 434 tests with one explicit non-sandbox skip, including the real sandbox checks and new patch tests.
- The default parallel `MOPS_REAL_SANDBOX=1 npm test` run exercised the new tests successfully but retained one unrelated flaky `process-supervisor` detached-descendant failure under full parallel load; the same suite passes sequentially.
- `npm run lint`, `npm run verify:contracts`, `npm audit --audit-level=high`, and `git diff --check` passed.

## Boundary covered

The implementation accepts only a bounded textual patch envelope under an
authorized project root. It rejects traversal, absolute or symlink targets,
unsupported delete operations, duplicate files, secret-shaped content,
oversized input/output, and mismatched expected base hashes. All target files
are read before mutation, each write is bound to the observed descriptor
identity, and already-applied files are rolled back on a later write failure.
The Broker records approval, intent, Job, completion, and structured hash
readback; unresolved execution remains `UNKNOWN`.

## Not established

The capability is disabled by default. This evidence does not establish
physical remount durability, crash actor attribution for multi-file patches,
production policy enablement, or final release-gate closure.
