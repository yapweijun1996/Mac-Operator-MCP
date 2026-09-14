# Capability Kill-Switch Readback Evidence

Date: 2026-09-15
Source commit: `be1384e`
Host: physical Darwin arm64 development host

## Implemented boundary

`mac_capabilities` now evaluates the Broker-owned persisted runtime switch and
the signed policy kill-switch for every enabled capability family before it
advertises the capability. A process capability is reported with the stable
reason `disabled_by_kill_switch` when either authority source disables the
family. Tool execution remains independently fail-closed through the normal
authorization path.

## Verification

- Focused capability kill-switch regression: pass.
- The regression covers both persisted `process` switch state and policy
  `process` kill-switch state.
- Full physical-Darwin regression with install, sandbox, and Keychain gates:
  572/572 pass, 0 skipped, 0 failed.
- `npm run typecheck`, `npm run lint`, `npm run verify:contracts`, and
  `git diff --check` pass.

## Remaining boundary

This closes capability-state readback consistency only. Installed operator
identity, active process-tree termination, production key distribution, safe
re-enable procedures, and real Guest VM isolation remain open.

## Rollback

Revert commit `be1384e`; capability execution authorization and kill-switch
state storage remain otherwise unchanged.
