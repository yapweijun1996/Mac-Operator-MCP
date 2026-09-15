# Tool contract schema identity boundary

Date: 2026-09-16
Source revision: `70302e0`
Host: Darwin 25.2.0, arm64, Node v25.5.0

## Boundary

Every materialized tool contract must include the explicit top-level
`$schema` identity. The Edge `ToolContractRegistry` already rejected missing
or unknown authority metadata at startup; the versioned JSON Schema now
requires the same field, so machine validation and runtime loading cannot
silently disagree about the contract envelope.

## Verification

```text
node --test packages/edge/dist/contract-registry.test.js
tests 9
pass 9
fail 0

npm run verify:contracts
Validated 44 unique tool contracts and the versioned ledger-record schema.

npm run build
npm run typecheck
npm run lint
npm run verify:docs
npm run verify:matrix
```

The focused negative case removes `$schema` and is rejected before a contract
is exposed. No tool is enabled or disabled by this change, and no runtime or
host configuration was modified.

## Remaining gate

This closes schema-identity consistency only. It does not prove runtime
authorization, target safety, host isolation, or release enablement for any
tool.

## Rollback

Revert commit `70302e0`; no installed service or host state needs restoration.
