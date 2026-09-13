# Privileged Helper Command Client Evidence

Date: 2026-09-13
Source commit: `6d6087d`
Host: macOS 26.2 (25C56), arm64
Runtime: Node.js v25.5.0

## Implemented boundary

`executePrivilegedHelperCommand` is the Broker-side bounded client for one
already-signed helper command. It validates the full signed command locally,
requires a canonical helper socket and protected key, caps request/response
bytes, applies a timeout, authenticates the complete response, and checks the
socket device/inode before and after the exchange. It cannot create authority;
`BrokerPrivilegedHelperCommandFactory` remains the only signer and still binds
approval, Job, target, policy, principal/session, revocation, and kill-switch
identity.

An authenticated helper failure is returned as a stable failure envelope. A
transport timeout, socket close, or transport error is mapped to retryable
`UNKNOWN_OUTCOME`; the client never infers privileged success or a safe failure
from a broken connection. Socket replacement maps to retryable `CONFLICT`.

## Verification

- Focused helper IPC suite: 8 passed, 0 failed.
- The client completes a signed local command, authenticates the success
  response, and receives durable `REPLAY_DENIED` on replay of the same command.
- Default full suite: 400 tests, 397 passed, 0 failed, 3 opt-in sandbox tests
  skipped.
- `npm run typecheck`: passed.

No privileged adapter, root helper, or launchd mutation was enabled.

## Source hashes

- `61a8454b40fd3c2c2975cf24db6bab099c1b9c31ac656403ba05134ffb9b2038` `packages/broker/src/privileged-helper.ts`
- `07289066f5aaf7be168a0286b2f99b60eea232b505afb00a66a4d9c67494ae5c` `packages/broker/src/privileged-helper.test.ts`
