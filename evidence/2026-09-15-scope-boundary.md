# Scope-list authority boundary evidence

Date: 2026-09-15
Source revision: `cb704af`

The Broker request parser now accepts principal scopes only when the value is
a dense data array of known scopes, with no duplicates and no more entries
than the registered scope set. The exported `authorizeTool` boundary applies
the same validation before reading the active policy or checking required
scopes. Malformed lists fail with the stable `AUTH_INVALID` class.

Focused verification:

```text
npm run build
node --test packages/broker/dist/policy.test.js packages/broker/dist/security-fuzz.test.js
15 passed, 0 failed
```

This closes a local representation-consistency gap only. It does not prove
production Edge/JWT scope issuance, cross-process identity packaging, or
capability enablement.
