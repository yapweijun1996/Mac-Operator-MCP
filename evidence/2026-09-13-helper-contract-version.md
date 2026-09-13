# Privileged helper contract-version binding evidence

Status: PARTIAL compatibility-boundary evidence for MOP-060 / VT-COMP-01

Source commit: `ee6d37b` (`security: bind helper commands to contract version`)
Working tree: clean before verification commands
Scope: separately authenticated helper command envelope; helper remains disabled

## Boundary implemented

The Broker-generated privileged-helper command now carries both the shared MCP
protocol version and the shared tool contract version. The HMAC command proof
already covers the complete canonical command, so the contract version is
cryptographically bound to the helper request and response proof. The helper
parser rejects unknown fields, missing contract version, protocol mismatch, or
contract version mismatch before replay admission or dispatch. The Broker
factory takes the version from the approved contract binding and the fixed
validator fails closed for stale versions.

This is a compatibility check only. It does not grant authority, expose raw
arguments, enable a privileged operation, or bypass the existing OS-peer,
replay, approval, kill-switch, target, and postcondition checks.

## Verification

- Focused privileged-helper suite: 7 passed, 0 failed, 0 skipped.
- Full `npm test`: 328 tests, 326 passed, 0 failed, 2 opt-in real-sandbox
  tests skipped.
- Negative coverage rejects a signed command with contract version `9.9`.
- Broker factory readback confirms the emitted command carries `0.1`.
- `npm run typecheck -- --pretty false`: PASS.
- `npm run verify:contracts`: PASS, 44 unique contracts.
- `npm audit --omit=dev --audit-level=high`: PASS, 0 vulnerabilities.
- `git diff --check`: PASS.

No helper socket, root process, privileged adapter, package installation,
service mutation, power action, or production enablement was run. Caller
identity packaging, cross-runtime/remote negotiation, upgrade rollback, and
independent L5 review remain open; VT-PRIV-01 stays `BLOCKED` and VT-COMP-01
stays `OPEN`.
