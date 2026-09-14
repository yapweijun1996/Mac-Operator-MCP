# Authority Control IPC Framing Evidence

Date: 2026-09-15
Source commit: `b265873`
Host: physical Darwin arm64 development host

## Implemented boundary

The owner-only Authority Control IPC now rejects any non-whitespace bytes
after the first newline-delimited JSON command. The command is authenticated
before this framing check, but replay admission, authority mutation, and audit
are skipped when trailing data is present. The response remains bound to the
authenticated command and reports stable `PRECONDITION_FAILED`.

## Verification

- Focused Authority Control IPC tests: 2/2 pass.
- The test confirms a pipelined trailing frame cannot change switch state.
- Full physical-Darwin regression: 571/571 pass, 0 skipped.
- `npm run build`, `npm run typecheck`, `npm run lint`, and `git diff --check`
  pass.

## Remaining boundary

This is strict local framing evidence only. Installed operator identity,
active process-tree termination, production key distribution, and safe
re-enable procedures remain open.

## Rollback

Revert the trailing-data check and its test assertion; the command schema and
authentication domains remain unchanged.
