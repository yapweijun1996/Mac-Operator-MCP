# Request State Invariants Evidence

Date: 2026-09-15

Source revision: `f607f41`

The Broker persistence boundary now validates stored Request rows before they
enter authorization, dispatch, or restart-recovery logic. The validator checks
state/result-class agreement for admission, authorization, intent, running,
success, denial, failure, cancellation, timeout, verification failure, and
unknown outcomes. It also checks monotonic lifecycle timestamps, nonnegative
revisions, bounded result/target text, bounded approval and Job identifiers, and prevents mutation links
from being attached to a non-mutation request.

Focused tests:

- `packages/broker/src/request-state-invariants.test.ts`: 3/3 passed.
- Corrupted state/result rows and timestamp rollback both fail closed as
  `AUDIT_UNAVAILABLE`.

Regression:

- Build and typecheck passed.
- Lint passed for 571 tracked files.
- Contract verification passed for 44 tool contracts and the ledger schema.
- Non-overlapping package regression: 558 total, 552 passed, 6 skipped, 0
  failed. The existing long-lived broker/persistence test process was left
  untouched.

Remaining host evidence includes production Keychain/code-signing identity,
disk exhaustion, and final ADR acceptance.
