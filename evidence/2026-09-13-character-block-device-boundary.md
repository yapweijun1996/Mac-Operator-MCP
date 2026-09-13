# Character and block device boundary evidence

Status: PASS for the observed character/block-device denial slice; complete
device and pseudo-filesystem coverage remains OPEN.

- Date: 2026-09-13 (Asia/Kuala_Lumpur)
- Host profile: macOS 26.2, arm64
- Node: v25.5.0
- Source commit: `8fbd148057da246f52e37a2748806fa23740eb8d`
- Working tree before this evidence document: clean after the source commit
- Contract version: `0.1`
- Host mutation: none; `/dev` nodes were opened only through bounded read-only
  authorization checks and no device bytes were read

## Boundary exercised

The real-host negative fixture checks `/dev/null`, `/dev/tty`, and
`/dev/random` as character-device targets. When `/dev/disk0` exists, it also
checks that block-device metadata cannot cross the authorized local volume
identity. Each target is rejected with the stable filesystem escape/volume
policy boundary; no content or device data is returned.

The test tolerates hosts without `/dev/disk0` and does not infer coverage for a
missing device. It complements the disposable FIFO/socket tests and the
native `O_NONBLOCK` hardening.

## Verification

- Focused filesystem suite: `node --test packages/broker/dist/filesystem-inspector.test.js` — 29/29 passed.
- Default full suite: `npm test` — 366 tests, 364 passed, 2 opt-in real-sandbox tests skipped.
- Opt-in host suite: `MOPS_REAL_SANDBOX=1 npm test` — 366/366 passed, 0 skipped.
- Type/build: `npm run build` and `npm run typecheck -- --pretty false` — passed.
- Contract validation: `npm run verify:contracts` — 44 unique contracts validated.
- Dependency audit: `npm audit --omit=dev --audit-level=high` — 0 vulnerabilities.
- Boundary check: `git diff --check` — passed.

## Source hash

```text
4f551ae4465ef63e869b11d3001b6ae6aa8a367c9d0a7284d2978e89cbccb36a  packages/broker/src/filesystem-inspector.test.ts
```

## Remaining limits

Other character/block devices, dynamic pseudo-filesystems, device target swaps,
physical remount behavior, and kernel-level I/O interruption remain open. No
capability was enabled.
