# Owner-only socket parent-chain boundary

- Source revision: `working-tree` (dirty; no commit created)
- Captured: 2026-09-22, Asia/Kuala_Lumpur
- Host profile: macOS Darwin arm64, owner UID 501
- Result: PASS for the code-level boundary; production service enablement remains OPEN

## Boundary

`validateOwnerSocketParentChain` now checks every directory traversed before an
owner-only Unix socket. The immediate parent must be owned by the expected
owner and have no group/other permissions. Ancestors must be directories and
must not be writable by group/other users unless sticky protection applies.
Symlinked ancestors are rejected, except for the fixed macOS `/var` and `/tmp`
aliases when their link targets are exactly `/private/var` and `/private/tmp`.

The shared validator is used by the base Broker IPC listener, Authority
Control, Broker Status, Approval IPC, Virtualization guest transport, and the
Authority LaunchAgent socket readback. Socket consumers still perform their
own type, owner, mode, and device/inode identity checks and revalidation.

## Verification

```text
npm run typecheck
node --test packages/broker/dist/ipc-server.test.js packages/broker/dist/owner-socket-path.test.js packages/broker/dist/privileged-helper-runtime.test.js packages/broker/dist/privileged-helper-authority-ipc.test.js packages/broker/dist/privileged-helper-executor.test.js packages/broker/dist/privileged-service-control.test.js
npm test
```

Observed results:

- focused IPC/helper regression: 42/42 passed;
- full repository regression: 1,125 total, 1,110 passed, 15 skipped, 0 failed;
- lint, documentation, verification matrix, process-boundary, dependency audit,
  and diff checks passed;
- no live service, launchd job, Keychain item, root helper, R1 process, or MCP
  capability was installed, enabled, restarted, or removed.

This evidence proves the local code and test boundary only. It does not prove
Developer ID signing, root-domain installation, persistent service lifecycle,
or production acceptance.
