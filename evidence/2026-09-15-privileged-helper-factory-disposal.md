# Privileged Helper Command Factory Disposal Evidence

Date: 2026-09-15
Source commit: `0055632`
Host: physical Darwin arm64 development host

## Implemented boundary

`BrokerPrivilegedHelperCommandFactory` now has a one-way disposal boundary.
The factory keeps its defensive authentication-key copy only until
`dispose()`, wipes it exactly once, and rejects every later `issue()` call
with the stable `CANCELLED` error. Repeated disposal is harmless. This keeps a
disposed factory from signing commands with a wiped key and prevents stale
references from being mistaken for usable helper authority.

## Verification

- Focused privileged-helper suite: 9/9 pass.
- The regression covers disposal, post-disposal issuance rejection, and
  idempotent repeated disposal.
- Full physical-Darwin regression with install, sandbox, and Keychain gates:
  576/576 pass, 0 skipped, 0 failed.
- `npm run build`, `npm run typecheck`, `npm run lint`,
  `npm run verify:contracts`, and `git diff --check` pass.

## Remaining boundary

This closes command-factory credential lifetime for the current Broker
process. It does not establish production operator-key distribution,
Developer ID signing, root-domain helper installation, real privileged
adapter execution, or final kill-switch readback on a deployed host.

## Rollback

Revert commit `0055632`; helper command issuance and authentication remain
otherwise unchanged.
