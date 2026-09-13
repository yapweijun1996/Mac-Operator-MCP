# Atomic write post-commit error evidence

Status: PASS for the post-rename error boundary; physical disk-full,
directory-remount, and host restart evidence remain OPEN.

- Date: 2026-09-13 (Asia/Kuala_Lumpur)
- Host profile: macOS 26.2, arm64
- Node: v25.5.0
- Source commit: `93eeaf862f24a57da5982eac4f7e29748eebc13a`
- Working tree before this evidence document: clean after the source commit
- Contract version: `0.1`
- Host mutation: disposable temporary regular files only; no physical volume was filled or remounted

## Boundary exercised

The fault-test-only native module injects `ENOSPC` immediately after atomic
rename and before the parent-directory `fsync`. The fixture confirms that the
target contains the new bytes, the temporary name is absent, and the native
call still returns a non-zero failure. This models the ambiguous window where
the mutation may have committed but durable completion/readback was not
confirmed; the Broker must preserve the Job as `UNKNOWN` rather than publish
success or silently retry.

The production native module does not export or enable the injection hook.
This is deterministic boundary evidence, not a physical disk-full or remount
reproduction.

## Verification

- Focused filesystem suite: `node --test packages/broker/dist/filesystem-inspector.test.js` — 31/31 passed.
- Default full suite: `npm test` — 370 tests, 368 passed, 2 opt-in real-sandbox tests skipped.
- Opt-in host suite: `MOPS_REAL_SANDBOX=1 npm test` — 370/370 passed.
- Type/build: `npm run build` and `npm run typecheck -- --pretty false` — passed.
- Contract validation: `npm run verify:contracts` — 44 unique contracts validated.
- Dependency audit: `npm audit --omit=dev --audit-level=high` — 0 vulnerabilities.
- Boundary check: `git diff --check` — passed.

## Source hashes

```text
9331384d17f60b5e2f484aacd0eb63f5032861df87bc368231df5124b866bdd8  packages/broker/native/peer_credentials.cc
a66f77e19760bdec4f9a442efef4128697027eff986fb42124a75dac81677b5d  packages/broker/src/filesystem-inspector.test.ts
```

## Remaining limits

The fixture does not prove physical storage exhaustion, delayed filesystem
errors, remount identity, kernel-blocked cancellation, or restart recovery.
The corresponding Broker integration already marks a worker write failure as
`UNKNOWN`; this fixture strengthens the native post-rename evidence but does
not close the broader mutation release gate.
