# Authority Control Restart Readback Evidence

Date: 2026-09-15
Source commit: `e48898d`
Host: physical Darwin arm64 development host

## Implemented boundary

The owner-only Authority Control IPC now has a regression that closes and
reopens the BrokerStore and server, then reads back persisted global/process
switch state and session/Edge revocation state through a freshly authenticated
client. The test also confirms that the earlier `set_switch` request remains a
replay after restart.

This verifies local persistence and authenticated readback of the authority
state. It does not expose the channel through MCP and does not imply that an
installed operator can safely distribute keys, terminate every active process,
or perform a production uninstall.

## Verification

- Focused Authority Control IPC tests: 2/2 pass.
- Full physical-Darwin regression after the test: 571/571 pass, 0 skipped.
- `npm run build`, `npm run typecheck`, `npm run lint`, and `git diff --check`
  pass.

## Remaining gates

Installed launchd/operator identity, active process-tree termination proof,
safe re-enable workflow, production key distribution, and final host
readback remain open.

## Rollback

Revert the restart readback assertions and this evidence file; the Authority
Control protocol and persistence implementation remain unchanged.
