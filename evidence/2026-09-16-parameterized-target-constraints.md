# Parameterized Target Constraint Evidence

Date: 2026-09-16
Source revision: `1ea5ab4`
Dirty state: clean after commit
Policy schema: `policy-document-v0.1.json`
Policy version: runtime `policy-0.1`; signed documents retain schema version `0.1`
Target host: local development host; no physical resource readback claimed

## Boundary

Signed target rules may now carry an optional `target_constraint` with
`mode: "finite_set"` and at most 64 references. The rule target supplies the
typed target kind and its anchor reference must be a member of the set. Every
member is validated with the same kind-specific canonical grammar, must be
unique and lexically sorted, and cannot contain a wildcard or prefix pattern.
The Broker matches only the normalized target reference against that finite
set; no caller argument can add a reference or change the target kind.

## Verification

The JSON Schema accepts the versioned constraint shape and the policy loader
materializes it into the immutable Broker policy. Runtime validation rejects
duplicates, unsorted references, a missing anchor, wildcard-shaped values, and
cross-kind values before authorization. Deny-over-allow and default-deny
semantics remain unchanged.

Focused command:

```text
npx tsc -b --pretty false
node --test packages/broker/dist/policy.test.js packages/broker/dist/policy-loader.test.js packages/broker/dist/policy-target-authority.test.js packages/broker/dist/policy-query-target.test.js
```

Result: 33/33 tests passed. `npm run lint` and `git diff --check` also passed.

## Limitations and rollback

This is local schema/runtime and authorization evidence only. It does not prove
physical mount/remount resistance, live app/Docker identity readback, remote
issuer behavior, native transport, or release enablement. Rollback is the
parent revision `36a3c0b`; removing the optional field restores exact-only
matching without changing the signed bundle version.
