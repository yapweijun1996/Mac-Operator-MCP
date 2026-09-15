# Tool contract schema identity boundary

Date: 2026-09-16
Source revision: `f7cd4fe`
Host: Darwin 25.2.0, arm64, Node v25.5.0

## Boundary

Every materialized tool contract must include the explicit top-level
`$schema` identity `./tool-contract.schema.json`. The Edge
`ToolContractRegistry` rejects missing or substituted identities at startup,
and the versioned JSON Schema enforces the same exact value, so machine
validation and runtime loading cannot silently disagree about the contract
envelope.

## Verification

```text
node --test packages/edge/dist/contract-registry.test.js
tests 10
pass 10
fail 0

npm run verify:contracts
Validated 44 unique tool contracts and the versioned ledger-record schema.

npm run build
npm run typecheck
npm run lint
npm run verify:docs
npm run verify:matrix
```

The focused negative cases remove `$schema` or substitute another schema path;
both are rejected before a contract is exposed. No tool is enabled or
disabled by this change, and no runtime or host configuration was modified.

## Remaining gate

This closes schema-identity consistency only. It does not prove runtime
authorization, target safety, host isolation, or release enablement for any
tool.

## Rollback

Revert commit `70302e0`; no installed service or host state needs restoration.
