# Tool Contract Approval-Policy Boundary

Date: 2026-09-23

Status: `PASS` for the source and staging contract boundary; production
capability enablement remains gated by the physical-host release audit.

Source state: shared working tree with pre-existing uncommitted project
changes; no commit or unrelated change was discarded.

## Decision

Approval policy is a closed contract vocabulary. The canonical JSON Schema,
the build-time contract verifier, and the Edge runtime registry must reject
unknown policy values before a contract can be loaded or used for MCP
registration. Every non-read-only contract must use an approval policy other
than `trusted_read`; privileged contracts additionally require
`explicit_privileged_policy`, the `privileged` audit class, and a required
postcondition.

## Implemented controls

- `packages/contracts/src/contract-invariants.ts` owns the shared approval
  vocabulary and cross-field safety checks.
- `tool-contracts/tool-contract.schema.json` encodes the closed enum and
  privileged/mutation relationships for build-time validation.
- `packages/edge/src/contract-registry.ts` applies the same enum and invariant
  checks at the runtime file-loading boundary.
- Edge tests cover unknown approval policies and destructive contracts that try
  to use trusted-read approval.

## Verification

- Edge contract-registry suite: 16 passed, 0 failed.
- Full repository regression: 1,151 total; 1,136 passed, 15 skipped, 0 failed.
- `npm run verify:contracts`: 45 unique contracts validated.
- `npm run typecheck`, `npm run lint`, `npm run verify:docs`,
  `npm run verify:matrix`, `npm run verify:process-boundaries`, high-severity
  dependency audit, and `git diff --check`: all passed.
- `npm run verify:completion`: intentionally remains `partial`, fail-closed,
  at 92% because the current host has no Developer ID identity, Accessibility
  permission is denied, target production services are absent, and the
  production acceptance record is absent.

## Host boundary

This change modifies only source contracts, validation, tests, and evidence.
It does not install services, change launchd state, grant Accessibility, read
secrets, provision Keychain material, install packages, reboot, shut down, or
enable a privileged MCP capability.

## Rollback

Revert the shared approval-policy enum/invariant, the Edge registry check, the
focused negative cases, and this evidence record together. No host rollback is
required because no host state changed.
