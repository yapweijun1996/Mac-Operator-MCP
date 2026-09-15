# Edge keyring identity boundary — 2026-09-15

## Scope

Source revision `a2580e0` closes a constructor-versus-loader validation drift
for Edge authentication identities. `EdgeKeyring.add` is a direct authority
loading boundary and now rejects malformed, traversal-shaped, empty, and
overlong Edge/key identifiers before inserting key material.

The canonical bounded Edge identity predicate is reused by:

- Edge key configuration validation;
- persisted Broker Job Edge provenance creation and readback; and
- `Broker.revokeEdge` input validation.

Key bytes and validity windows remain validated independently. The keyring does
not expose key material through results or audit evidence.

## Verification

- `npm run build` — passed.
- `npm run typecheck` — passed.
- `npm run lint` — passed (`565` tracked files).
- `npm run verify:contracts` — passed (`44` contracts plus ledger schema).
- Focused Edge keyring/config tests — `9/9` passed.
- Non-overlapping package regression — `547` tests (`541` passed, `6` skipped,
  `0` failed).
- `git diff --check` — passed.

The long-lived persistence test process was already active, so persistence
tests were not launched concurrently. Existing temporary schema/readback smoke
and the focused keyring/config suite provide the available local evidence.

## Remaining limits

This is constructor/loader consistency evidence only. Developer ID signing,
protected production key distribution, installed-service lifecycle, and real
cross-process rotation evidence remain open.
