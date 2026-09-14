# Local IPC Framing Hardening Evidence

Date: 2026-09-15
Source commits: `0dee251`, `64954e0`
Host: physical Darwin arm64 development host

## Implemented boundary

The privileged helper, policy-signer, and Broker status Unix-socket servers
now authenticate the first newline-delimited frame and reject any subsequent
non-ASCII-whitespace bytes before replay admission, status readback, mutation,
or helper dispatch. Their response clients apply the same single-frame rule
and fail closed on appended response data. A rejected trailing frame does not
consume the valid request nonce, so a clean retry is still governed by the
normal durable replay boundary. The Policy Signer server copies its HMAC key
and wipes the copy on every close path, including native-transport cleanup.

## Verification

- Privileged helper, policy-signer, and Broker status IPC framing tests pass.
- The helper regression covers command and status frames and proves that
  trailing data cannot dispatch or consume replay state.
- Full physical-Darwin regression with install, sandbox, and Keychain gates:
  573/573 pass, 0 skipped, 0 failed.
- `npm run build`, `npm run typecheck`, `npm run lint`,
  `npm run verify:contracts`, and `git diff --check` pass.

## Remaining boundary

This closes newline framing and pipelining ambiguity on these local channels.
It does not establish production root/helper installation, operator identity
distribution, or active process-tree termination.

## Rollback

Revert commits `0dee251` and `64954e0`; the existing authentication and replay
domains remain unchanged.
