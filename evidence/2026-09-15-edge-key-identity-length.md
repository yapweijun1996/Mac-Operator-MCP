# Edge-key identity length boundary — 2026-09-15

## Scope

Source revision `6fdc725` aligns the maximum identity bound across request
admission, Job provenance, and operator revocation. Edge and key IDs each allow
up to 128 bounded characters; their delimiter-separated composite is therefore
257 characters. The previous 256-character revocation/readback guard could
reject an otherwise valid identity, making that key impossible to revoke.

The shared keyring predicates and composite identity pattern now preserve this
full bounded value. Authority Control IPC/CLI and BrokerStore revocation accept
the same maximum subject length; unrelated audit request IDs retain their
existing tighter bound.

## Verification

- `npm run typecheck` — passed.
- `npm run lint` — passed (`566` tracked files).
- `npm run verify:contracts` — passed (`44` contracts plus ledger schema).
- Focused Edge-keyring and Authority Control tests — `10/10` passed.
- Non-overlapping package regression — `549` tests (`543` passed, `6` skipped,
  `0` failed).
- `git diff --check` — passed.

## Remaining limits

This closes a local bounded-identity compatibility gap only. Production key
distribution, Developer ID provenance, cross-process rotation, and installed
service evidence remain open.
