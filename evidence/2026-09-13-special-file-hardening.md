# Special-file blocking and pseudo-device hardening evidence

Status: PASS for the FIFO/non-blocking and pseudo-device fail-closed slice;
the complete special-file matrix and release gate remain OPEN.

- Date: 2026-09-13 (Asia/Kuala_Lumpur)
- Host profile: macOS 26.2, arm64
- Node: v25.5.0
- Source commit: `7a136ef36a208563140028b89013e817aab88d63`
- Working tree before this evidence document: clean after the source commit
- Contract version: `0.1`
- Host mutation: one disposable FIFO was created and removed; no volume or
  pseudo-filesystem was changed

## Boundary changes

Native metadata, content-read, and hash opens now include `O_NONBLOCK`, so an
untrusted FIFO without a writer cannot stall the Broker thread or worker.
The FIFO is returned only as bounded `other` metadata; generic content read,
hash, and atomic write attempts fail closed. The fixture also verifies that
`/dev/null` and `/dev` cannot cross the authorized local root volume boundary.

The test creates the FIFO through an explicit `/usr/bin/mkfifo` invocation with
an absolute path, `/`-independent working directory, minimal `PATH`, and no
captured output. It does not open the FIFO for data and removes the temporary
directory in a `finally` block.

## Verification

- Focused filesystem suite: `node --test packages/broker/dist/filesystem-inspector.test.js` — 29/29 passed.
- Default full suite: `npm test` — 366 tests, 364 passed, 2 opt-in real-sandbox tests skipped.
- Opt-in host suite: `MOPS_REAL_SANDBOX=1 npm test` — 366/366 passed, 0 skipped.
- Type/build: `npm run build` and `npm run typecheck -- --pretty false` — passed.
- Contract validation: `npm run verify:contracts` — 44 unique contracts validated.
- Dependency audit: `npm audit --omit=dev --audit-level=high` — 0 vulnerabilities.
- Boundary check: `git diff --check` — passed.

## Source hashes

```text
64e5f79b33ea24dd1a7428167170e491f306cecdded0736398d460d3505189d0  packages/broker/native/peer_credentials.cc
cdb47b80dc5ef674d1ca30852cbf62ddab0440f6a1169cffe7b500fff33a70f4  packages/broker/src/filesystem-inspector.test.ts
```

## Remaining limits

Character/block-device coverage beyond `/dev/null`, pseudo-filesystem mount
revalidation, FIFO/socket target swaps, removable-volume remounts, and kernel
syscall interruption under hostile I/O remain open. No capability was enabled.
