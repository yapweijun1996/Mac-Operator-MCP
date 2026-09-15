# Target-grant authority boundary evidence

Date: 2026-09-15
Source revision: `d785eb0`

`authorizeTarget` now requires an existing enabled principal grant and verifies
that every requested scope is present in that grant before matching target
rules. Disabled grants fail with `POLICY_DENIED`; scopes outside the grant fail
with `SCOPE_DENIED`. This check is independent of the earlier request-principal
projection step, so direct target authorization and policy reload paths retain
the same default-deny behavior.

Focused verification:

```text
npm run build
node --test packages/broker/dist/policy.test.js packages/broker/dist/security-fuzz.test.js
16 passed, 0 failed
```

The non-overlapping package regression passes 546 total tests (540 passed,
6 skipped, 0 failed). Production policy distribution and capability enablement
remain open.
