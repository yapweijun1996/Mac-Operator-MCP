# Request/Job idempotency and lifecycle fence

## Decision

Atomic approved-Job admission may mark an idempotent replay as `SUCCEEDED`
only when the existing Job already has a successful terminal outcome. The
existing Job must also belong to the requesting session; an otherwise
identical cross-session replay conflicts transactionally and leaves no new
Request row. The general Job-creation idempotency path also binds reuse to the
same session. New Request-to-Job links require an exact Edge identity; legacy
Job rows without persisted Edge provenance remain readable at startup but
cannot be attached to a new Request. The general Job-creation path likewise
refuses to reuse an active queued or running Job, so a second request cannot
execute the same active work. A queued, running, failed, cancelled, or unknown
Job is not a successful replay; the atomic admission is rejected
transactionally and leaves no new Request row.
Startup integrity validation also fails closed when a persisted successful
Request points at a non-terminal or non-successful Job.

## Evidence

- `BrokerStore.admitApprovedJob` rejects reuse of a queued Job and preserves
  the original Request/Job state.
- Atomic idempotency reuse rejects a different owner session even when
  principal, payload, tool, target, policy, and key otherwise match.
- General Job idempotency reuse also rejects a different session.
- Request-to-Job linkage rejects another Edge identity and missing Edge
  provenance on newly created Jobs; startup remains compatible with legacy
  rows whose Edge provenance predates the schema field.
- The cross-session regression test passes and confirms no Request row is
  persisted for the rejected retry.
- `BrokerStore.createJob` rejects reuse of queued or running Jobs, while
  completed terminal Jobs remain idempotently readable.
- A completed successful Job remains reusable and produces the expected
  `SUCCEEDED` / `IDEMPOTENT_REUSE` Request record.
- Startup rejects a tampered `SUCCEEDED` Request linked to a queued Job before
  reconciliation can act on the ledger.
- Focused persistence and Request/Job linkage coverage: 66 passed, 0 failed,
  0 skipped.
- Full repository regression on macOS 26.2 arm64, UID 501: 1,180 total,
  1,165 passed, 15 skipped, 0 failed.
- `npm run build` passed. No host LaunchAgent, privilege, permission, or
  service state was changed.

## Limits

This closes the successful idempotency replay and persisted Request/Job
cross-ledger slice. It does not prove physical process termination,
descendants created after the last snapshot, disk-full/remount durability,
external actor attribution, broader partial-mutation recovery, installed
service recovery, or production acceptance.
