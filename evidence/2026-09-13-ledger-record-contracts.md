# Versioned ledger record contracts

## Scope

`schemas/ledger-records.schema.json` is the versioned machine-readable
contract for Broker persistence envelopes. It covers Request, Approval, Job,
and Audit records with strict field sets, bounded identifiers/text/timestamps,
explicit lifecycle enums, nullable linkage fields, typed write/process metadata,
and the allowlisted privileged helper payload union. Unknown authority fields
such as `executable` are rejected by schema validation.

The schema is compiled by `npm run verify:contracts` in addition to the 44 MCP
tool contracts. `packages/contracts/src/ledger-contract.test.ts` validates one
bounded example of each record type and negative cases for raw helper authority,
wrong schema versions, and malformed audit evidence. Runtime persistence
validation remains authoritative for cross-field invariants such as target and
payload-digest binding; this schema does not claim to replace those checks.

## Verification

- `node --test packages/contracts/dist/ledger-contract.test.js`: 2/2
- `npm run typecheck`: pass
- `npm run verify:contracts`: pass; reports 44 MCP contracts and the versioned ledger-record schema
- `git diff --check`: pass

## Remaining boundary

The schema does not close SQLite backend acceptance. Crash/disk-pressure,
backup/restore, retention, corruption recovery, cross-runtime canonicalization,
stronger audit anchoring, and protected access roles remain open under
ADR-0005. It also does not enable any previously disabled tool or helper
operation.

## Rollback

Remove the schema, its verifier compile step, and the focused contract test.
Runtime Broker behavior remains unchanged because the schema is a validation
contract and the existing persistence validators remain in force.
