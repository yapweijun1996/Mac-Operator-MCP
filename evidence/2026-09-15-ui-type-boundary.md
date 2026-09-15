# `mac_ui_type` boundary evidence

Date: 2026-09-15
Source revision: `adf9fd8`

## Decision

Implement the L4 `mac_ui_type` contract as a disabled-by-default Broker Job
slice. The capability accepts only bounded text (10,000 characters) and nine
allowlisted key names. It can target only an owned, unexpired Accessibility
snapshot whose parent app-window target is independently authorized.

## Security boundary

- Text is sent to the fixed Broker-owned JXA adapter through a bounded
  ProcessSupervisor stdin payload. It is not placed in argv, environment, audit
  evidence, or persisted Job stdout.
- Secret-like text is rejected by the shared secret-content policy before a
  child process starts. Secure or redacted Accessibility snapshots are denied.
- The adapter rejects non-text controls, sensitive app/window identities,
  stale index/role/label identities, missing Accessibility permission, and
  malformed input metadata.
- Broker authority is rechecked before dispatch, during execution polling, and
  after the adapter returns. Success requires exact target identity, accepted
  character/key counts, `focus_confirmed`, and `secure: false` readback.
- Job cancellation, revocation, approval expiry, and adapter uncertainty use
  the existing queued/running/unknown mutation paths; no late success is
  published after authority loss.

## Verification

- `npm run build`
- `npm run typecheck`
- `npm run verify:contracts` — 44 contracts and the ledger schema validated
- `npm run lint` — 567 tracked files
- `git diff --check`
- Focused UI, policy-loader, and ProcessSupervisor tests: 60/60 passed
- Non-overlapping package regression: 553 total, 547 passed, 6 skipped, 0
  failed
- Integration test confirms the Broker Job completes and contains no input
  text in persisted stdout.

## Remaining evidence

This is local code/test evidence only. The capability remains disabled until a
real macOS host proves Accessibility permission-granted behavior, focus-race
handling, revocation during active input, and adversarial-app readback. Human
approval UI/channel and production service installation evidence remain open.
