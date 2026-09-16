# Process-supervisor concurrency regression

- Date: 2026-09-16
- Source revision: `a04f628`
- Host: physical macOS Darwin arm64 development host
- Boundary: Broker-owned child-process cancellation and persisted recovery tests

## Change

The detached-descendant recovery test now treats native observer uncertainty
as `UNKNOWN` rather than asserting a false `drained` result. It still requires
`terminationObserved: true` only for a verified `drained` outcome. The test
also closes the supervisor before awaiting the worker so unresolved detached
children are terminated through the Broker-owned identity path.

The active-cancellation test waits for `ProcessSupervisor.activeCount()` before
requesting cancellation. A fixed delay could expire while the full Edge and
Broker suites were doing path-identity checks, causing a pre-spawn cancellation
to be mistaken for an active-process cancellation test.

## Verification

```text
npm run build --silent
npm test --silent
  860 tests, 846 passed, 14 skipped, 0 failed
```

The focused detached-descendant recovery test and the serial full-suite run
also pass. No production process policy was relaxed; observer uncertainty
remains fail-closed as `UNKNOWN_OUTCOME`.
