# Task Profile Budget Enforcement Evidence

- Source commit: `a78c1b33a6910d65bb5e662b03bc641b9eed4b70`
- Capture state: clean implementation revision before this evidence addendum
- Captured: 2026-09-13 (Asia/Kuala_Lumpur)
- Contract version: `0.1`
- Policy version used by tests: `policy-0.1`

## Verification

- `npm test` — 200 tests passed, 0 failed
- `git diff --check` — pass

## Observed invariant

The Broker now treats the resolved profile's timeout and output cap as authoritative even when an injected runner reports a successful, verified result. A runner result exceeding the profile output budget is persisted as a failed Job and returned as stable `OUTPUT_LIMIT`; it is never published as a successful task result. Reported truncation also blocks success.

This is a Broker-side result-boundary test. It does not claim that an OS sandbox, process supervisor, or runner implementation enforces the profile budget before output is generated; those controls and credential-isolation evidence remain required before enablement.
