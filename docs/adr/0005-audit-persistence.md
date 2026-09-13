# ADR-0005: Audit and Operational Persistence

Status: Proposed
Date: 2026-09-12
Tasks: MOP-015, MOP-017, MOP-083

## Context

Request, nonce, idempotency, approval, job, policy-version, and audit records need transactional uniqueness and crash recovery. Audit data also requires integrity, privacy, retention, and least-privilege access.

## Required decision

Select the storage backend and process ownership. Define transaction boundaries, uniqueness constraints, append integrity, encryption or OS protection, backup/restore, retention cleanup, disk limits, migration, corruption handling, and access roles.

## Constraints

- Mutation and privileged intent is durable before dispatch.
- No claim of exactly-once external mutation.
- Idempotency keys bind one canonical payload.
- `UNKNOWN` never maps to success without observation-based reconciliation.
- Secret content is removed before persistence.
- Edge, Broker, helper, and operator access remain least privilege.

## Candidate baseline

An embedded transactional database owned by the Broker is the initial candidate for request/job/idempotency state and append events. Acceptance depends on crash-injection, lock/concurrency, integrity, backup, and migration tests.

## Prototype evidence

The Broker prototype owns a SQLite database with full synchronous WAL mode, atomic nonce-plus-request admission, revisioned request lifecycle records, single-use approvals, persisted jobs, revocations and kill switches, and append-oriented audit events linked by SHA-256 hashes. Exact approval consumption, request linkage, mutation intent, idempotency reservation and new-job creation commit together for the `admitApprovedJob` primitive; the `admitApprovedJobAfterDecision` primitive provides the same atomic boundary after an authorization decision for active task dispatch, binding owner, target, payload and timestamp preconditions. Decision and completion state changes also commit with their matching audit event. Generic switch and revocation changes now commit a redacted `intent`/`completion` audit pair in the same transaction as the authority update and queued-job cancellation. The separate Authority Control IPC durably admits its request/nonce before applying only allowlisted switch/revocation operations and reuses the command request ID for the audit pair. Startup reconciliation maps interrupted reads and pre-dispatch mutations to `FAILED`, and dispatched mutations with unproven outcomes to `UNKNOWN`; it never infers success. Audit evidence is recursively redacted before serialization and hashing, and authority reason text is reduced to a digest. Restart replay/reconciliation, approval competition/revocation, atomic new-job conflict rollback, injected failure rollback for both admission paths with restart readback, audit append, authority-audit ordering, revocation, switch persistence primitives, and redaction tests pass.

The Broker verifies the complete audit hash chain at startup and refuses a database whose stored event content no longer matches the chain. An atomic migration preserves legacy revocations while adding `edge_key` support. These checks detect accidental or unsophisticated modification; an unkeyed local chain is not proof against an attacker who can rewrite the database and recompute every hash.

The persistence boundary also publishes `schemas/ledger-records.schema.json`,
a versioned envelope contract for Request, Approval, Job, and Audit records.
The verifier compiles it with the MCP contracts, while focused tests reject
malformed lifecycle values and raw helper authority fields. This is a schema
and compatibility guard; BrokerStore's runtime validators remain authoritative
for cross-field target, digest, approval, and state-transition invariants.

The Broker now has a host-only backup/recovery slice. `BrokerStore.backupTo`
uses SQLite's backup API, publishes an owner-only `0600` file through a
same-directory temporary rename, verifies `quick_check`, recomputes the audit
hash chain, and returns a bounded SHA-256 manifest. `restoreBackup` validates
the source again, copies to a protected temporary file, rechecks source
device/inode/size/mtime, refuses an existing destination, and performs final
integrity readback. `pruneBackups` accepts only the exact generated filename
shape, retains the newest numeric timestamps, and refuses symlinks, foreign
owners, unsafe modes, oversized files, and target swaps. These are not MCP
tools and do not enable backup automation or external storage.

`node:sqlite` remains an experimental Node feature on the verified runtime. Backend acceptance is deferred until broader concurrent-access and crash tests, stronger integrity or external anchoring, general versioned migrations, encrypted/Keychain-protected backup storage, access control, disk-quota/exhaustion behavior, and an operator rollback/runbook decision are implemented and tested.
