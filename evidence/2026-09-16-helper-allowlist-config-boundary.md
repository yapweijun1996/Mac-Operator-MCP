# Privileged Helper allowlist configuration boundary evidence

Date: 2026-09-16
Source revision: `a1acb3c`
Host: physical Darwin arm64 (`yaps-Mac-mini.local`, Darwin 25.2.0)
Node: `v25.5.0`

## Decision

The privileged Helper executor treats startup configuration as a security
boundary. The `enabled` flag must be a real boolean, and the operation
allowlist must be a bounded dense data array with no symbols, hidden fields,
sparse slots, or accessor descriptors. The supported operation set is frozen
before it is exposed. Values are checked against the fixed operation enum and
duplicates are rejected before the executor stores its internal set.

This prevents malformed host configuration from changing Helper capability
projection or invoking code through array accessors. The default remains
disabled, and an enabled executor still requires command authority, transport,
and at least one explicitly allowlisted operation.

## Verification

- Helper executor suite: 11/11 passed, 0 skipped, 0 failed.
- Added negatives cover a non-boolean enable flag, a sparse allowlist, and an
  accessor-backed allowlist element; all fail during construction.
- `npm run build`, `npm run typecheck`, and `npm run lint` passed.
- Existing full regression evidence remains valid at the prior source
  revision; no production Helper or privileged operation was enabled.

## Remaining gate

This closes malformed startup allowlist data handling only. It does not
provide production Helper signing/notarization, installation, descriptor-backed
task execution, VM/guest isolation, or real-Mac privileged capability evidence.
