# Authority Control CLI Evidence

Date: 2026-09-15
Source commits: `447e4aa`, `f359360`, `5962efc`, `032bf8f`
Host: physical Darwin arm64 development host

## Implemented boundary

The Broker package now exposes a bounded `mac-operator-authority` entrypoint
for the owner-only Authority Control channel. It supports only switch
readback, switch changes, and identity revocation. Database, socket, and key
configuration paths must be canonical owner-only paths; the active HMAC key is
restored through `AuthorityControlKeyManager`, never supplied on the command
line. Mutations require an expected prior state and an exact confirmation
token, then perform authenticated readback before returning `verified: true`.
The allowlist includes guest-attestation key revocation. No command, executable,
raw key, capability grant, or MCP-facing operation is representable.

The IPC server now recovers a structurally valid unsigned command solely to
bind stable failure responses. An expired or replayed signed command can
therefore be verified as `AUTH_EXPIRED` or `REPLAY_DENIED` by the caller,
while freshness and replay checks still happen before admission or execution.
Malformed envelopes, including unknown fields, continue to use the
invalid-command fallback proof.

## Verification

- Authority CLI tests: 4/4 pass, including a protected-file and authenticated
  IPC round trip.
- Authority Control IPC tests: 3/3 pass, including authenticated expiry
  readback with no mutation or audit side effect.
- Full physical-Darwin regression with install, sandbox, and Keychain gates:
  581/581 pass, 0 skipped, 0 failed.
- `npm run build`, `npm run typecheck`, `npm run lint`,
  `npm run verify:contracts`, and `git diff --check` pass.
- `--help` prints only the three bounded operation forms; malformed or
  unconfirmed inputs fail with stable `PRECONDITION_FAILED` output.

## Remaining boundary

This is a source-level operator path. It does not prove installed launchd
ownership, protected production key distribution, active process-tree
termination, or production capability enablement. Re-enable remains unsafe
until active and `UNKNOWN` Jobs have separate authenticated readback.

## Rollback

Revert commits `447e4aa`, `f359360`, `5962efc`, and `032bf8f`; the underlying owner-only
Authority Control IPC and its replay/audit semantics remain unchanged.
