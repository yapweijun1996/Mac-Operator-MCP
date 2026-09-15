# Safe integer canonicalization evidence

Date: 2026-09-15
Host: physical Mac mini (Darwin arm64)

## Boundary

Inbound strict canonical JSON parsing rejects plain decimal integer tokens
outside JavaScript's safe-integer range. This prevents a request or audit
digest verifier from accepting a value that another runtime may preserve as a
different arbitrary-precision integer. The canonicalizer's locked
ECMAScript `JSON.stringify` output is unchanged; scientific notation remains
part of the versioned wire profile and is constrained by each field contract.

## Verification

Commands:

```text
npm run build
node --test packages/contracts/dist/canonical-json.test.js packages/contracts/dist/auth.test.js
npm run verify:contracts
npm run lint
git diff --check
```

Results:

- canonical JSON and authentication tests: 10 passed, 0 failed;
- contract verification: 44 unique tool contracts and the versioned
  ledger-record schema validated;
- dependency-free style check: 673 tracked files passed;
- diff check: passed.

Covered vectors include rejection of `9007199254740992` and
`100000000000000000000` as plain decimal input, preservation of the existing
`1e20` and `1e21` scientific-notation profile behavior, and unchanged fixed
canonical JSON hashes.

## Limits

This is a parser and digest-boundary guarantee, not a substitute for
field-specific numeric limits. Every authority-bearing timestamp, budget,
PID, port, revision, and counter must continue to use explicit safe-integer
validation at its owning contract boundary.
