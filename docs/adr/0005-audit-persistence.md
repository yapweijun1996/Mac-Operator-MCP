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

The Broker prototype owns a SQLite database with full synchronous WAL mode, atomic nonce-plus-request admission, revisioned request lifecycle records, single-use approvals, persisted jobs, revocations and kill switches, and append-oriented audit events linked by SHA-256 hashes. Exact approval consumption, request linkage, mutation intent, idempotency reservation and new-job creation commit together for the `admitApprovedJob` primitive; decision and completion state changes also commit with their matching audit event. Startup reconciliation maps interrupted reads and pre-dispatch mutations to `FAILED`, and dispatched mutations with unproven outcomes to `UNKNOWN`; it never infers success. Audit evidence is recursively redacted before serialization and hashing. Restart replay/reconciliation, approval competition/revocation, atomic new-job conflict rollback, injected failure rollback with restart readback, audit append, revocation, switch persistence primitives, and redaction tests pass.

The Broker verifies the complete audit hash chain at startup and refuses a database whose stored event content no longer matches the chain. An atomic migration preserves legacy revocations while adding `edge_key` support. These checks detect accidental or unsophisticated modification; an unkeyed local chain is not proof against an attacker who can rewrite the database and recompute every hash.

`node:sqlite` remains an experimental Node feature on the verified runtime. Backend acceptance is deferred until broader concurrent access tests, stronger integrity or external anchoring, general versioned migrations, backup/restore, retention, access control, and disk exhaustion are implemented and tested.
