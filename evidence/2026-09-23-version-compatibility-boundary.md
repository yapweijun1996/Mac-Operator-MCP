# Version Compatibility Boundary

Date: 2026-09-23

Status: `PASS` for the local source and staging compatibility boundary;
production packaging, upgrade/rollback, and cross-runtime release evidence
remain open.

Source state: shared working tree with pre-existing uncommitted project
changes; no commit or unrelated change was discarded.

## Decision

Wire versions are accepted by explicit domain, not by independently repeated
string literals. The current release supports exactly protocol `0.1` and
contract `0.1`. Adding a future version requires changing the shared matrix
and its negative/positive compatibility tests before any boundary accepts it.

## Implemented controls

`packages/contracts/src/compatibility.ts` defines the exact matrix for:

- Edge↔Broker authenticated requests and responses;
- Broker↔privileged Helper commands, status, and readback;
- Authority Control, which carries protocol version but no MCP contract version;
- Broker capability discovery consumed by the MCP Edge.

The Broker request parser, Edge response parser and capability loader,
Authority Control parser, and privileged Helper validators now consult the
shared matrix. Unknown protocol versions, unknown contract versions, and
contract versions supplied to the protocol-only Authority domain fail closed
before trust-boundary handoff or capability publication.

## Verification

- Focused cross-boundary regression: 40 passed, 0 failed, 0 skipped.
- Full repository regression: 1,151 total; 1,136 passed, 15 skipped, 0 failed.
- `npm run build`: passed.
- `npm run typecheck`, `npm run lint`, `npm run verify:docs`,
  `npm run verify:matrix`, `npm run verify:process-boundaries`, high-severity
  dependency audit, and `git diff --check`: passed.
- `npm run verify:contracts`: 45 unique contracts validated.

## Release limits

The matrix proves local parser and runtime compatibility behavior. It does not
prove that separately packaged production Edge, Broker, Helper, or Authority
artifacts were upgraded and rolled back across independent processes. Those
host and release gates remain fail-closed.

## Rollback

Revert `packages/contracts/src/compatibility.ts`, its export and tests, the
runtime imports/checks, and this evidence record together. No host state was
changed by this boundary work.
