# Persistence and Reliability Model

Status: Proposed contract; backend selection remains open
Version: 0.1

## Owned records

| Record | Stable key | Purpose | Initial retention direction |
|---|---|---|---|
| Principal | `principal_id` | Identity and grant status | While active plus audit retention |
| Session | `session_id` | Bound principal/scopes/expiry | Expiry plus replay window |
| Nonce | `(edge_id, session_id, nonce)` | Replay rejection | Maximum request age plus clock-skew margin |
| Request | `request_id` | Lifecycle and payload identity | Operational retention; exact value open |
| Idempotency | `(principal_id, tool, idempotency_key)` | Retry reconciliation | At least maximum client retry horizon |
| Approval | `approval_id` | Bound authorization evidence | TTL plus audit retention |
| Job | `job_id` | Broker-owned process state | Operational retention plus evidence reference |
| Audit event | `(request_id, sequence)` | Append-oriented intent/result history | Policy-defined; value open |
| Policy version | `policy_version` | Reproducible decision input | Current plus rollback and evidence history |

## Required uniqueness

- `request_id` is globally unique within one deployment identity.
- A nonce is accepted once within its replay domain.
- An idempotency key maps to one canonical payload digest; reuse with another digest returns `CONFLICT`.
- Job IDs cannot identify arbitrary host processes.
- Audit sequence is monotonic within a request.

## Request lifecycle

`RECEIVED -> AUTHORIZED | DENIED -> INTENT_RECORDED -> RUNNING -> SUCCEEDED | FAILED | CANCELLED | TIMED_OUT | VERIFICATION_FAILED | UNKNOWN`

Read-only requests may omit `INTENT_RECORDED` only if the approved audit-outage policy allows it. Mutating and privileged requests require durable intent before dispatch.

## Transaction boundaries

The final backend must define atomic boundaries for nonce acceptance, request admission, approval consumption, idempotency reservation, audit intent, and job creation. No design may claim exactly-once external mutation. The contract provides at-most-one admitted payload per idempotency key plus postcondition reconciliation.

## Crash windows

| Window | Required recovery |
|---|---|
| Before authorization persisted | Request may be retried as new after replay rules |
| After nonce acceptance, before decision | Resume or return stable internal failure; never re-admit nonce silently |
| After intent, before dispatch | Mark cancelled/failed after proving no mutation started |
| During mutation | Reconcile postcondition; return verified terminal state or `UNKNOWN` |
| After mutation, before completion event | Reconcile and append recovered completion evidence |
| During job execution | Recover process ownership or terminate and reconcile |

## Concurrency

The policy must define target-level conflict keys. Concurrent writes to the same file, Git index/repository, service, application target, package, or host power state require serialization or explicit conflict failure. Read/write interactions use preconditions and target identity checks. Backend locking mechanics remain open.

## UNKNOWN reconciliation

An `UNKNOWN` result is not success. Reconciliation loads the original principal, tool, payload digest, normalized target, policy version, precondition, intended end state, and available audit evidence; then runs a tool-specific observation that cannot repeat the mutation. It records `SUCCEEDED_RECOVERED`, `FAILED_RECOVERED`, or remains `UNKNOWN` with operator action.

## Retention and privacy

Exact durations remain open. Retention must cover replay defense, client retries, incident investigation, rollback, and release evidence while minimizing personal data. Outputs are bounded and redacted before persistence. Secret content is never retained as evidence.

## Open backend decision

The backend must support transactional uniqueness, durable append, crash recovery, bounded cleanup, backup/restore, integrity checks, and least-privilege access for Edge, Broker, operator, and helper roles. Selection is tracked by the audit-persistence ADR.
