# L0/L1 real macOS readback evidence

Status: PASS for the bounded, metadata-only host observation slice; not a
release-gate closure for the complete filesystem/secret boundary.

- Date: 2026-09-13 (Asia/Kuala_Lumpur)
- Host profile: macOS 26.2, arm64
- Node: v25.5.0
- Source commit: `a8fc40c1fe62855a5bc73131a77b16bc26199665`
- Working tree before this evidence document: clean after the source commit
- Contract version: `0.1`
- Policy state: no capability enablement or policy mutation performed

## Readback scope

`packages/broker/src/l0-l1-host-readback.test.ts` performs one read-only host
probe on macOS:

- system summary reads bounded OS/architecture/CPU/memory/uptime/load facts;
- network status observes interface metadata with `includeListeners=false`,
  returns no listener inventory, and verifies the explicit “no active network
  probe” warning;
- process inventory reads at most 16 bounded records and inspects only the
  current test process, asserting redacted `uid:<number>` ownership and no
  argv/environment fields;
- filesystem metadata uses the canonical `/System/Library` root, reads only
  directory metadata, lists at most eight entries, and builds a depth-one tree
  capped at 24 entries. Content reads are disabled and protected relative
  zones are denied.

The test does not open credential stores, read file contents, perform network
probes, launch children, mutate files, change policy, or install services.

## Verification

- Focused host test: `node --test packages/broker/dist/l0-l1-host-readback.test.js` — 1/1 passed.
- Default full suite after the new boundary: 362 tests, 360 passed, 2 opt-in real-sandbox tests skipped.
- Opt-in host suite: `MOPS_REAL_SANDBOX=1 npm test` — 362/362 passed, 0 skipped.
- Type/build: `npm run typecheck -- --pretty false` and `npm run build` — passed.
- Contract validation: `npm run verify:contracts` — 44 unique contracts validated.
- Dependency audit: `npm audit --omit=dev --audit-level=high` — 0 vulnerabilities.
- Boundary check: `git diff --check` — passed.

## Source hashes

```text
dcd04fad955d5da4df3312d1efe3219c980ca053f26668a0370b64e2367a6b24  packages/broker/src/l0-l1-host-readback.test.ts
9e4e5e6746434dbcedae4a1d67f11346f4bda9acb9b0cae2797dd868c5115331  packages/edge/src/jwt-verifier.test.ts
```

The JWT test adjustment fixes a one-second assertion race by binding the
expected expiration second to the signed token input. It does not weaken JWT
validation.

## Remaining limits

This evidence covers a narrow read-only host slice. Full L0/L1 release evidence
still needs broader secret corpus review, Unicode/case and remount identity
coverage, special-file and resource-exhaustion cases, listener ABI pinning,
real-volume race evidence, and final policy/readback review. No production
service or remote endpoint was changed.
