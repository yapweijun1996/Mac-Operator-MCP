# Process descendant fixture stability evidence

- Date: 2026-09-16
- Scope: Darwin process ownership regression fixture

The persisted-descendant recovery test previously used a 50ms child lifetime,
which allowed a busy test host to miss the descendant before its first native
sample. The fixture now keeps the child alive until its PID/start-time identity
has been observed, then terminates that test-owned child explicitly before
terminating the root. The assertion remains conservative: after the persisted
descendant disappears, root recovery must stay `UNKNOWN_OUTCOME`.

Verification:

```text
node --test --test-name-pattern='process supervisor keeps a dead root unresolved after persisted descendants disappear' packages/broker/dist/process-supervisor.test.js
3/3 isolated runs passed
npm test --silent
870 tests: 856 passed, 14 skipped, 0 failed
```

No production process-control behavior or host service was changed.

Rollback is to revert the fixture-only test change and this evidence file.
