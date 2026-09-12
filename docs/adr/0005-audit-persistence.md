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
