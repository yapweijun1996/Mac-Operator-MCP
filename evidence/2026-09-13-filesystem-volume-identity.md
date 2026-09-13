# Filesystem volume identity binding evidence

Status: PASS for the plan/native volume-identity guard; physical remount and
removable-volume release evidence remain OPEN.

- Date: 2026-09-13 (Asia/Kuala_Lumpur)
- Host profile: macOS 26.2, arm64
- Node: v25.5.0
- Source commit: `1807ebc77634e5ea44a87ad39511831de7fcff97`
- Working tree before this evidence document: clean after the source commit
- Contract version: `0.1`
- Host mutation: none; no volume was unmounted, mounted, or repartitioned

## Boundary changes

`FilesystemPathPlan` now captures the native canonical root path and volume ID
at authorization time. The ID includes the device and filesystem ID reported
by macOS. Every metadata, read, hash, list, write, and unlink operation checks
that identity before and after the native operation; storage analysis applies
the same check to each analysis root.

The native adapter additionally compares `f_fsid` and filesystem type for the
opened target or parent descriptor, not only `st_dev`. This prevents a target
or parent on a different mounted filesystem from passing a device-number-only
check.

The focused adversarial test forges a changed plan identity and verifies the
stable `POLICY_DENIED` failure before target metadata is returned. It creates
and removes only a temporary regular file; it does not simulate an actual
unmount or mount operation.

## Verification

- Focused filesystem and native peer suites: `node --test packages/broker/dist/filesystem-inspector.test.js packages/broker/dist/peer-credentials.test.js` — 33/33 passed.
- Default full suite: `npm test` — 364 tests, 362 passed, 2 opt-in real-sandbox tests skipped.
- Opt-in host suite: `MOPS_REAL_SANDBOX=1 npm test` — 364/364 passed, 0 skipped.
- Type/build: `npm run build` and `npm run typecheck -- --pretty false` — passed.
- Contract validation: `npm run verify:contracts` — 44 unique contracts validated.
- Dependency audit: `npm audit --omit=dev --audit-level=high` — 0 vulnerabilities.
- Boundary check: `git diff --check` — passed.

## Source hashes

```text
2fa1ef75433fabe15eb227a6c5f960657893a6146f44b8583e4f6781cf7a120b  packages/broker/src/filesystem-inspector.ts
1543d9e4b01ef4f22d2ac7e94fc9a7cc9b18b1598ecae492469267570e44192d  packages/broker/src/filesystem-inspector.test.ts
057f3abfd68aad167bbc855ace39c888c6c2b58cd5e2962541c43e1a880dc81f  packages/broker/native/peer_credentials.cc
```

## Remaining limits

The guard is a fail-closed control, not proof that every macOS filesystem
preserves a distinct identity across an unmount/remount cycle. A privileged or
physical removable-volume remount test, crash/restart persistence, directory
create/rename races, special-file policy, and resource-exhaustion evidence
remain outside this read-only run. No capability was enabled.
