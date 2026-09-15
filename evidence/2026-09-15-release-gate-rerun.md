# Release Gate Rerun Evidence

Date: 2026-09-15

Source revision: `7e0cc43`

## Commands and results

- `npm run verify:contracts` — 44 unique tool contracts and the versioned
  ledger-record schema validated.
- `npm run verify:canonical:native` — `jcs-utf8-v1`, 5/5 vectors passed.
- `npm audit --audit-level=high` — 0 vulnerabilities.
- `npm run lint` — passed for 611 tracked files.
- `npm run typecheck` — passed.
- `git diff --check` — passed.

The repository CI workflow also has a 15-minute job timeout, while the root
test command bounds each individual test case at 120 seconds.

The old `broker.test.js`/`persistence.test.js` process remains undisturbed,
so this rerun does not claim their complete result. It also does not close
physical crash/remount durability, persistent production installation,
Developer ID provenance, real isolation, external issuer/deployment, or
independent P0/P1 review.
