# Filesystem pressure-budget evidence

Status: PASS for bounded directory/search pressure fixtures; production-scale
resource-exhaustion and kernel I/O interruption evidence remain OPEN.

- Date: 2026-09-13 (Asia/Kuala_Lumpur)
- Host profile: macOS 26.2, arm64
- Node: v25.5.0
- Source commit: `9d6d6b066df78a785884925cfc080fa49e4c7bc3`
- Working tree before this evidence document: clean after the source commit
- Contract version: `0.1`
- Host mutation: only 600 temporary regular files were created and removed

## Boundary exercised

The bounded pressure fixture creates 600 files containing synthetic `needle`
text, then verifies:

- directory listing caps output at 500 entries and returns a continuation
  cursor;
- directory tree caps output at 128 entries and reports truncation;
- metadata search caps output at 100 matches and reports truncation;
- text search caps output at 100 matches and reports truncation; and
- oversized list/tree/search arguments are rejected before traversal.

The test uses fixed temporary roots and no protected or host data. It does not
claim that the fixed budgets are sufficient for all production workloads.

## Verification

- Focused filesystem suite: `node --test packages/broker/dist/filesystem-inspector.test.js` — 30/30 passed.
- Default full suite: `npm test` — 367 tests, 365 passed, 2 opt-in real-sandbox tests skipped.
- Opt-in host suite: `MOPS_REAL_SANDBOX=1 npm test` — 367/367 passed, 0 skipped.
- Type/build: `npm run build` and `npm run typecheck -- --pretty false` — passed.
- Contract validation: `npm run verify:contracts` — 44 unique contracts validated.
- Dependency audit: `npm audit --omit=dev --audit-level=high` — 0 vulnerabilities.
- Boundary check: `git diff --check` — passed.

## Source hash

```text
82799f530d7080ed910afa66b0c59077d734bf647bc66795d90a0d6d97fbc709  packages/broker/src/filesystem-inspector.test.ts
```

## Remaining limits

50,000-entry-scale traversal, concurrent multi-root pressure, disk-full/error
injection, worker cancellation during kernel-blocked I/O, and restart/recovery
under resource exhaustion require separate evidence. No capability was enabled.
