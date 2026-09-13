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

## Current Request and Job Ledger prototype

Authenticated requests are admitted by one SQLite transaction that reserves the Edge nonce and globally unique request ID while creating a payload-bound `RECEIVED` record. Policy and target decisions atomically advance that record with their hash-linked audit event. Mutations then atomically persist `INTENT_RECORDED` with redacted evidence before `RUNNING`; successful completion is returned only after the `SUCCEEDED` state and completion evidence commit together. State changes use monotonic timestamps and revision preconditions.

On startup, interrupted `RECEIVED`, `AUTHORIZED`, `INTENT_RECORDED`, and read-only `RUNNING` records become `FAILED`. A mutation already marked `RUNNING` becomes `UNKNOWN`, because process restart alone cannot prove whether an external effect occurred. Recovery transitions append audit evidence and never infer success. Authenticated stale-policy and authorization denials remain replay-reserved and queryable; unauthenticated input is not admitted.

Approval records bind the approver and requesting principals, tool and contract version, normalized target kind/reference, canonical arguments digest, policy version, approval class, attended/unattended mode, issue time, expiry, and use limit. The current prototype accepts only `use_limit = 1`; batch approval semantics remain deliberately unavailable. A separate `ApprovalAuthority` verifies an issuer/key identity, signed canonical issuance payload, bounded preview digest, issuer validity window, durable issuance nonce, and unattended-profile policy before atomically persisting the approval plus decision/completion provenance. Mutation intent selects an exact unexpired, unrevoked match and consumes it in the same transaction that stores the request's approval link and hash-linked intent evidence. Missing, expired, revoked, exhausted, replayed, cross-principal, altered-payload, altered-target, altered-policy, altered-contract, altered-class, and attended/unattended mismatches fail closed. Revocation between intent and `RUNNING` prevents dispatch.

The local SQLite prototype persists Broker-generated job identity, owner principal/session, source tool, normalized target, policy version, canonical payload digest, principal-scoped idempotency key, revisioned state, timestamps, terminal result, bounded output, and cancellation state. Reusing an idempotency key with the same payload returns the existing job; a different payload returns `CONFLICT`. State transitions require the expected revision and enforce monotonic timestamps plus compatible terminal state/result pairs.

Job output is bounded before persistence and secret-shaped output is replaced rather than stored. On BrokerStore startup, queued records that cannot be safely resumed become `cancelled`; running records whose external outcome cannot be proven become `unknown`. Each recovery transition appends hash-linked audit evidence. `mac_job_status` and `mac_job_cancel` expose only jobs owned by the authenticated principal through the Broker-resolved `job:owned` policy target.

Authority changes now share one SQLite transaction with queued-job reconciliation:
disabling `global` or `mutations` cancels all queued Jobs, while `process` and
`network` cancel only queued `mac_task_run` rows. Principal/session revocation
cancels matching ownership; upstream edge/key/approval/policy-signer revocation
conservatively cancels all queued rows because their provenance is not yet
stored. Broker dispatch rechecks current authority immediately before a queued
Job transitions to `RUNNING`. These rules cover the current catalog; durable
worker leases, active process ownership, and restart-safe external termination
remain open.

The disabled `mac_write_file_atomic` prototype uses this Job Ledger directly: its explicit idempotency key binds one canonical payload and target, the returned `job_id` provides status lookup, and a running write that cannot be read back after restart remains `UNKNOWN` rather than being retried automatically. The Job Ledger persists only a bounded, non-secret write descriptor so `mac_job_status` can probe the current digest/size postcondition after restart. A matching postcondition is reported as evidence but never transitions the job to success, because the actor in the crash window cannot be proven.

This prototype does not yet persist an executable task descriptor, process-tree/lease identity, or a recovered-completion workflow. Approval issuance now has a separately authenticated signed issuer prototype plus a separate owner-only local IPC channel with durable replay nonce and provenance audit. Issuer key files use owner-only non-symlink `0600` loading/provisioning and revoke-before-retire deletion with a separate durable `approval_key` revocation kind. A versioned owner-only metadata config atomically writes and reloads key paths and validity metadata with canonical digest readback while keeping key bytes in separate files. BrokerStore persists activation history and audit intent/completion; the key manager rejects revision rollback and startup restore requires the exact persisted revision/digest. This is a cross-process activation guard, not Keychain-backed secret distribution or installed-service identity. Protected Keychain storage, human approval UI/channel, human-readable preview delivery, and unattended-profile ownership are not implemented. The `admitApprovedJob` primitive now binds approval consumption, request intent, idempotency reservation and new-job creation in one transaction; a default-off test-only fault hook verifies rollback and restart readback at each admission boundary. A disabled `ProcessSupervisor` prototype now provides explicit cwd/environment/stdio, bounded output, process-group cancellation and descendant cleanup, but actual task execution still needs a proven sandbox profile, credential isolation, a task descriptor and process lease recovery. Cancellation of a queued job is verified immediately; cancellation of a running job is recorded as accepted until an isolated executor observes termination. The SQLite backend, general schema migration strategy, retention, backup, corruption and multi-process ownership decisions remain open under ADR-0005.
