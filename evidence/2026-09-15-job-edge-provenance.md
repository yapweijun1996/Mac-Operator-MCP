# Job Edge provenance evidence

Date: 2026-09-15
Source revisions: `e0b9db8`, `66688ec`, `9a52c59`, `8dbbd67`

## Decision

Queued Job cancellation on Edge revocation must be scoped to the Edge that
admitted the Job. Jobs created before this field existed have no trustworthy
provenance and therefore remain conservative: an Edge revocation cancels them.
Malformed stored provenance is an audit-integrity failure and is rejected on
readback.

## Implementation

- BrokerStore schema versions `10` and `11` add nullable `jobs.owner_edge_id`
  and `jobs.owner_edge_key_id`.
- The migrations are forward-only and add both columns to legacy Job ledgers
  with `NULL` provenance.
- Every Broker-owned mutation Job admission passes the authenticated request
  Edge and Edge-key identity. Atomic and ordinary idempotent reuse reject a
  different authority identity.
- Restarted guest-task recovery rechecks the persisted Job Edge before making a
  status lookup, so a revoked Edge cannot close an unknown Job as success.
- Edge and Edge-key revocation cancel matching queued Jobs, plus legacy/null or
  malformed provenance; non-matching, valid identities remain queued.
- The public `BrokerJob` result does not expose Edge identity; it remains
  Broker-owned authority evidence.

## Verification

Passed:

- `npm run build`
- `npm run typecheck`
- `npm run lint` (`Style check passed for 565 tracked files.`)
- `git diff --check`
- Non-overlapping package regression: 546 tests, 540 passed, 6 skipped, 0
  failed.
- Temporary BrokerStore smoke: schema `11`; Edge-key identities read back as
  `edge-1:key-old`, `edge-1:key-new`, and `NULL`; revoking `edge-1:key-old`
  produced states `cancelled`, `queued`, `cancelled`; both provenance columns
  read back as nullable `TEXT`; malformed key provenance returned
  `AUDIT_UNAVAILABLE`.

The persistence test file already had a long-lived test process running, so the
new focused persistence tests were not launched concurrently. Their cases are
also covered by the temporary SQLite readback/revocation smoke above; the
malformed-provenance assertion remains scheduled for the next isolated
persistence run.

## Remaining risk

Active process termination and production installed-service evidence remain
open. Other upstream authority kinds without persisted Job provenance still use
conservative queued-Job cancellation.
