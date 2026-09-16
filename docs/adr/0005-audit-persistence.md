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

## Availability decision

When the keyed audit tail cannot be published or verified, every MCP request
admission fails closed, including read-only tools. The Broker may remain
inspectable through authenticated host recovery/readback procedures, but it
must be restarted with a verified tail before accepting new requests. This
avoids an unrecorded read side channel at the cost of availability during an
audit outage.

## Candidate baseline

An embedded transactional database owned by the Broker is the initial candidate for request/job/idempotency state and append events. Acceptance depends on crash-injection, lock/concurrency, integrity, backup, and migration tests.

## Prototype evidence

The Broker prototype owns a SQLite database with full synchronous WAL mode, atomic nonce-plus-request admission, revisioned request lifecycle records, single-use approvals, persisted jobs, revocations and kill switches, and append-oriented audit events linked by SHA-256 hashes. Exact approval consumption, request linkage, mutation intent, idempotency reservation and new-job creation commit together for the `admitApprovedJob` primitive; the `admitApprovedJobAfterDecision` primitive provides the same atomic boundary after an authorization decision for active task dispatch, binding owner, target, payload and timestamp preconditions. Decision and completion state changes also commit with their matching audit event. Generic switch and revocation changes now commit a redacted `intent`/`completion` audit pair in the same transaction as the authority update and queued-job cancellation. The separate Authority Control IPC durably admits its request/nonce before applying only allowlisted switch/revocation operations and reuses the command request ID for the audit pair. Startup reconciliation maps interrupted reads and pre-dispatch mutations to `FAILED`, and dispatched mutations with unproven outcomes to `UNKNOWN`; it never infers success. Audit evidence is recursively redacted before serialization and hashing, and authority reason text is reduced to a digest. Restart replay/reconciliation, approval competition/revocation, atomic new-job conflict rollback, injected failure rollback for both admission paths with restart readback, audit append, authority-audit ordering, revocation, switch persistence primitives, and redaction tests pass.

Durable replay ledgers reclaim entries whose expiry is exactly the current
admission time before enforcing capacity. This follows the strict validity
rule `expires_at_ms > now`, avoids an avoidable boundary-denial condition, and
does not weaken single-use replay checks for entries that remain valid.

Broker shutdown now preserves the same fail-closed recovery rule at the
resource boundary. Commit `505d28a` keeps the request admission fence active
after cleanup starts, clears a rejected aggregate close Promise, and permits an
explicit retry without reopening the Broker. A close failure therefore cannot
be mistaken for a completed shutdown or leave the host lifecycle permanently
unable to drain owned resources.

The Broker verifies the complete audit hash chain at startup and refuses a database whose stored event content no longer matches the chain. An atomic migration preserves legacy revocations while adding `edge_key` support. These checks detect accidental or unsophisticated modification; an unkeyed local chain is not proof against an attacker who can rewrite the database and recompute every hash.

An optional keyed audit-tail boundary is now implemented for host startup. The
Broker can receive an explicit memory-only HMAC key source and publish the
latest SQLite sequence/event hash to a separate owner-only `0600` sidecar after
each committing transaction. Startup verifies the sidecar against the SQLite
tail and fails closed on absence, staleness, key identity change, or forged
content. Publication is deliberately after the SQLite commit: a sidecar write
failure leaves the database ahead and therefore unresolved on the next start,
never falsely verified. This is stronger than an unkeyed local chain but is not
an external immutable log. Packaged Broker startup now requires the
Keychain-backed anchor configuration and fails closed when the item or sidecar
cannot be verified. Production Keychain provisioning/rotation, cross-process
sidecar locking, and a rollback-resistant external anchor remain acceptance
gates.

The persistence boundary also publishes `schemas/ledger-records.schema.json`,
a versioned envelope contract for Request, Approval, Job, and Audit records.
The verifier compiles it with the MCP contracts, while focused tests reject
malformed lifecycle values and raw helper authority fields. This is a schema
and compatibility guard; BrokerStore's runtime validators remain authoritative
for cross-field target, digest, approval, and state-transition invariants.

The Broker now has a host-only backup/recovery slice. `BrokerStore.backupTo`
uses SQLite's backup API, streams the snapshot through a Broker-owned
AES-256-GCM envelope, publishes an owner-only `0600` `.sqlite.enc` file through
a same-directory temporary rename, verifies `quick_check`, recomputes the
audit hash chain, and returns a bounded SHA-256 manifest. `restoreBackup`
authenticates and decrypts the source into a protected temporary file,
rechecks source device/inode/size/mtime, refuses an existing destination, and
performs final integrity readback. `pruneBackups` accepts only the exact
encrypted filename shape, retains the newest numeric timestamps, and refuses
legacy plaintext names, symlinks, foreign owners, unsafe modes, oversized
files, and target swaps. These are not MCP tools and do not enable backup
automation or external storage. SQLite backup WAL/SHM/journal sidecars are
removed with the temporary base. A hard-crashed backup child is covered by a
recovery test: stale hidden temporary artifacts and sidecars are removed only
after an age threshold and identity recheck.
Broker SQLite connections use a bounded busy timeout, and two independent
process writers have been verified to preserve the audit hash chain under
`BEGIN IMMEDIATE`. A simulated `ENOSPC` at publication maps to retryable
`AUDIT_UNAVAILABLE` and leaves no temporary artifacts.
Before the copy begins, the source page count/size and destination-volume
`statfs` available bytes are checked with bounded headroom for sidecars; an
insufficient-capacity preflight fails before creating a temporary file.

Backups are now encrypted by default with a Broker-owned AES-256-GCM key
source. The on-disk `.sqlite.enc` envelope binds a version, key identity, nonce,
ciphertext, and authentication tag; creation decrypts a verification copy before
atomic publication, and restore authenticates/decrypts before SQLite and audit
readback. Keys are loaded only through an injected source, with a dedicated
Keychain-backed source factory available for macOS startup; missing, malformed,
mismatched, or tampered keys/files fail closed. Legacy plaintext backup names
are refused by retention until an explicit migration is performed.

The macOS Keychain source now targets the file-based Keychain model required for
launchd daemons. Provisioning binds a `SecAccess` read ACL to one canonical,
protected Broker executable, and native read/retirement checks the exact
trusted-application ACL before touching secret bytes. Retirement requires the
expected 32-byte digest and deletes the item reference found by an exact
service/account search. Real host evidence covers provisioning, ACL readback,
wrong-executable denial, digest precondition failure, and cleanup; no MCP route
can choose the Keychain coordinates or executable identity. Data-protection
Keychain entitlements and production code-signing provenance remain packaging
gates rather than runtime fallbacks.

The audit-tail sidecar now takes an owner-only atomically-created sibling lock
for every read and publication. The lock spans validation, atomic rename, and
directory `fsync`; release rechecks device/inode identity, and a pre-existing
lock fails closed rather than being reclaimed by PID or age. This closes the
same-target cross-process sidecar race while leaving crash recovery to an
authenticated operator procedure.

The persistence constructor now enforces a monotonic SQLite `user_version`
gate. Fresh and legacy databases are upgraded through a versioned forward-only
registry of idempotent revocation, request, and Job migrations inside one
`BEGIN IMMEDIATE` transaction. Each migration records its version and stable
identity in `schema_migrations`; gaps, identity changes, malformed rows, and a
database marked with a newer version are rejected before any Broker authority
or recovery work. The marker advances to version `5` only after every known
step and registry record commit. Version 5 also creates a singleton persisted
Broker runtime fence. Packaged service startup claims the next generation and
fresh token before recovery; each write transaction verifies that pair so a
later service instance invalidates stale writers. Down-migrations are intentionally unsupported:
rollback requires stopping the Broker and restoring an authenticated encrypted
backup into a fresh destination, followed by a separately reviewed operator
cutover. The focused migration suite covers fresh initialization, legacy
preservation, future-version refusal, and registry-integrity refusal.

`node:sqlite` remains an experimental Node feature on the verified runtime. Backend acceptance is deferred until broader concurrent-access and crash tests, production Keychain anchor provisioning, explicit single-owner service policy, access control, disk-quota/exhaustion behavior, a documented operator cutover and stale-lock recovery runbook, production code-signing/Keychain identity review, an external rollback-resistant anchor, and final ADR acceptance are implemented and tested. Encrypted backup storage, the schema-version gate, the forward-only migration registry, the keyed local anchor boundary with cross-process locking, and the development-host Keychain ACL boundary are implemented; production rollback execution remains host-only.

The chosen audit-outage policy is covered by `audit-anchor-readonly.test.ts`:
after a committed tail cannot publish, a subsequent read-only Broker
admission returns `AUDIT_UNAVAILABLE` without creating a Request row. The
frozen SQLite tail remains available to the host recovery path.

BrokerStore now also validates persisted Job state/result/timestamp/lease/cancellation invariants before exposing a row, and a durable cancellation revision prevents a late active-Job success. This closes a local mutation-state consistency gap but does not satisfy the remaining disk-exhaustion, production identity, rollback, or ADR acceptance gates.

BrokerStore also validates persisted Request state/result/timestamp/approval/Job-link invariants before exposing a row. This prevents malformed or partially migrated request rows from influencing authorization or restart recovery, while preserving the existing forward-only migration and fail-closed `AUDIT_UNAVAILABLE` behavior.
