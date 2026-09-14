# Authority Control Key Lifecycle Evidence

Date: 2026-09-15
Source commit: `94ce4fd`
Host: physical Darwin arm64 development host

## Implemented boundary

`AuthorityControlIpcClient` now copies the supplied HMAC key into client-owned
memory and exposes an explicit `dispose()` boundary that wipes the copy and
rejects further requests with the stable `CANCELLED` error. The caller-owned
key remains available to its own lifecycle owner, while the client cannot
retain authority after disposal. Authority Control and Privileged Helper
servers also wipe their copied keys when socket detachment, server close, or
native transport cleanup fails.

The focused regression disposes a client, proves post-disposal rejection, and
continues a separate authenticated restart check with the caller-owned key.

## Verification

- Focused Authority Control IPC tests: 2/2 pass.
- Privileged Helper IPC tests: 9/9 pass.
- Full physical-Darwin regression with install, sandbox, and Keychain gates:
  573/573 pass, 0 skipped, 0 failed.
- `npm run build`, `npm run typecheck`, `npm run lint`,
  `npm run verify:contracts`, and `git diff --check` pass.

## Remaining boundary

This closes local client/server HMAC key lifetime handling for these channels.
It does not establish production operator key distribution, installed
launchd identity, or active process-tree termination and recovery.

## Rollback

Revert commit `94ce4fd`; the prior authenticated IPC protocol and replay
boundaries remain unchanged.
