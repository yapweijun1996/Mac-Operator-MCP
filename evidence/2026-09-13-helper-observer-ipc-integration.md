# Privileged Helper Observer IPC Integration Evidence

Date: 2026-09-13
Source commits: `3b24604`, `a1bd63c`
Host: macOS 26.2 (25C56), arm64
Runtime: Node.js v25.5.0

## Implemented boundary

`createPrivilegedHelperPackageHostObserver` now accepts an explicit
`helperStatusClient` containing the canonical helper socket and authentication
key. When that source is selected, the observer calls
`readPrivilegedHelperStatus`, which authenticates the helper-owned status
envelope and fences socket device/inode identity before returning runtime
metadata. The older `readRuntime` callback remains available for controlled
test/host adapters; the observer rejects construction when neither source is
provided.

This prevents package readiness from depending on a caller-assembled runtime
object. Launchd, process identity, plist, signature, and helper status remain
independent readback sources composed only after their exact plan checks.

## Verification

- Focused helper package suite: 13 passed, 0 failed.
- The integration test runs a real local helper IPC server, signs a status
  request, authenticates the response, and feeds the result through the
  production-shaped package observer.
- A key-manager integration test proves an already-created helper server
  rejects status reads immediately after its helper key is revoked.
- Latest default full suite: 400 tests, 397 passed, 0 failed, 3 opt-in sandbox
  tests skipped.
- `npm run typecheck`: passed.

No root helper was installed and no launchd mutation was attempted.

## Source hashes

- `347f1af5fbc58f7eff7efe02ae855e051e7606b354bd7c1ecb3bef6c5d154be1` `packages/broker/src/privileged-helper-package.ts`
- `a8004df0ac9aaa5e8a6a65c2b0a930ea68b3086fbd540a21ab5853f65d19d510` `packages/broker/src/privileged-helper-package.test.ts`
- `30b39b528332a74f6d0cdc43245eec6267a93280fc3eb45bce034ab9c74e1548` `packages/broker/src/privileged-helper-keyring.test.ts`
