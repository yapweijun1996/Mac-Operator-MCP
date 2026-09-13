# Generic special-file boundary evidence

Status: PASS for the Unix-domain-socket negative boundary; the broader
special-file matrix and release gate remain OPEN.

- Date: 2026-09-13 (Asia/Kuala_Lumpur)
- Host profile: macOS 26.2, arm64
- Node: v25.5.0
- Source commit: `cd744205679f8c734bc4b51da0b6126eea5c356c`
- Working tree before this evidence document: clean after the source commit
- Contract version: `0.1`
- Host mutation: one temporary Unix-domain socket was created and removed; no
  system or credential surface was opened

## Boundary exercised

The adversarial filesystem test creates a disposable Unix-domain socket inside
an authorized temporary root. Metadata-only directory listing represents the
entry as `other`, while generic content read, hash, and atomic write attempts
fail closed. The test never connects to the socket or reads from it, and all
cleanup occurs after the listener closes.

This keeps generic filesystem tools from treating a socket as a regular file
or as a write target. It does not add a new capability or change the default
policy that special files require a dedicated adapter.

## Verification

- Focused filesystem suite: `node --test packages/broker/dist/filesystem-inspector.test.js` — 28/28 passed.
- Default full suite: `npm test` — 365 tests, 363 passed, 2 opt-in real-sandbox tests skipped.
- Opt-in host suite: `MOPS_REAL_SANDBOX=1 npm test` — 365/365 passed, 0 skipped.
- Type/build: `npm run build` and `npm run typecheck -- --pretty false` — passed.
- Contract validation: `npm run verify:contracts` — 44 unique contracts validated.
- Dependency audit: `npm audit --omit=dev --audit-level=high` — 0 vulnerabilities.
- Boundary check: `git diff --check` — passed.

## Source hash

```text
ccdfd4c192172d992efa34080a937d20d7b4b203952f7d32a325405f06102aa3  packages/broker/src/filesystem-inspector.test.ts
```

## Remaining limits

FIFO, character/block devices, pseudo-filesystems, mount-point traversal,
special-file target swaps, and a complete F0/F1 corpus still require separate
coverage. No production adapter was enabled.
