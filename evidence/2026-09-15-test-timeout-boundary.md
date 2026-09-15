# Test Timeout Boundary Evidence

Date: 2026-09-15

Source revision: `94bd182`

## Change

The root `npm test` command now invokes Node's test runner with a fixed
`--test-timeout=120000` per-test-case limit. The limit bounds verification
itself so a leaked listener, unresolved promise, or child-process handle
cannot keep a release run alive indefinitely. Broker task budgets remain
defined by the versioned tool contracts and are unaffected.

## Verification

- `npm run lint`: passed for 610 tracked files.
- `npm run typecheck`: passed.
- `node --test --test-timeout=120000 packages/contracts/dist/*.test.js`:
  11 passed, 0 failed, 0 skipped.
- The existing `broker.test.js`/`persistence.test.js` process was not
  terminated or restarted, so the root `npm test` command was not run in this
  checkpoint.

This hardens the local verification boundary only. It does not prove the
remaining physical crash, installed-service, isolation, remote deployment,
or independent P0/P1 release gates.
